//! The comparison with Docker's default seccomp profile (ADR-007, D2):
//! the profile vendored from moby/profiles (`moby/default.json`, pinned in
//! `moby/README.md`), the names it does not allow unconditionally per
//! architecture (`docker-denied-<arch>.txt`, derived here), and the ADR's
//! table of the names among them that this policy allows.
//!
//! The derivation reads the profile with `boneli-json` and fails on any
//! key, action or comparison it does not know, so a later pin cannot be
//! misread in silence.

use std::collections::BTreeSet;

use boneli_json::{Limits, Value};
use boneli_sys::seccomp::Arch;

use super::{CENSUS, Extract, Verdict, entry, extract};

/// The vendored profile: moby/profiles `seccomp/default.json` at commit
/// 9ee3204f0d0cfa19ca2c6a7b0fcf5a2b353954ae.
pub const PROFILE: &[u8] = include_bytes!("moby/default.json");
/// Its size and FNV-1a 64 digest, recorded at the pin.
const PROFILE_LEN: usize = 18_182;
const PROFILE_FNV1A: u64 = 0x31fb_b8eb_3b62_1736;

/// The derived lists, reviewed as data.
const LIST_X86_64: &str = include_str!("docker-denied-x86_64.txt");
const LIST_AARCH64: &str = include_str!("docker-denied-aarch64.txt");

/// Docker's default capabilities (moby/moby
/// `daemon/pkg/oci/caps/defaults.go` at
/// 06db1734267bf7770914b417bff6556d835bf8cc).
pub const DOCKER_CAPS: [&str; 14] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FSETID",
    "CAP_FOWNER",
    "CAP_MKNOD",
    "CAP_NET_RAW",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETFCAP",
    "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT",
    "CAP_KILL",
    "CAP_AUDIT_WRITE",
];

/// The kernel floor (ADR-007 D3, raised to Linux 6.1 by ADR-044 D1 and D4):
/// rules with a higher `minKernel` do not apply.
pub const FLOOR: (u32, u32) = (6, 1);

/// Names that Docker allows only for some arguments and this policy for
/// more, but only in bits the kernel ignores: `domain` is an `int`, Docker
/// compares all 64 bits and the policy the low word, and every domain the
/// policy allows Docker allows too (ADR-007 D2, the comparison rule).
pub const IGNORED_BITS: [&str; 2] = ["socket", "socketpair"];

/// Limits for the profile: 65,536 bytes is 3.6 times the file, depth 8
/// against the 5 it uses, 4,096 values against its 980.
fn limits() -> Limits {
    Limits::new(65_536, 8, 4_096).expect("valid limits")
}

/// One argument comparison of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg {
    /// The argument, 0 to 5.
    pub index: u64,
    /// `eq`, `lt` or `masked_eq`.
    pub op: &'static str,
    /// The value (for `masked_eq` the mask).
    pub value: u64,
    /// The second value (for `masked_eq` the datum), 0 when absent.
    pub value_two: u64,
}

/// `includes` or `excludes` of a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cond {
    /// Architectures (`amd64`, `arm64`, ...).
    pub arches: Vec<String>,
    /// Capabilities.
    pub caps: Vec<String>,
    /// The lowest kernel, as (major, minor).
    pub min_kernel: Option<(u32, u32)>,
}

/// One rule of the profile's `syscalls` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The syscall names.
    pub names: Vec<String>,
    /// Whether the action is `SCMP_ACT_ALLOW` (else `SCMP_ACT_ERRNO`).
    pub allow: bool,
    /// The comparisons, all of which must hold.
    pub args: Vec<Arg>,
    /// When the rule applies.
    pub includes: Cond,
    /// When it does not.
    pub excludes: Cond,
}

/// A parsed profile.
#[derive(Debug)]
pub struct Profile {
    /// The rules in file order.
    pub rules: Vec<Rule>,
}

fn keys_known(v: &Value, what: &str, known: &[&str]) -> Result<(), String> {
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{what} is not an object"))?;
    for k in obj.keys() {
        if !known.contains(&k) {
            return Err(format!("unknown key {what}.{k}"));
        }
    }
    Ok(())
}

fn strings(v: Option<&Value>, what: &str) -> Result<Vec<String>, String> {
    let Some(v) = v else {
        return Ok(Vec::new());
    };
    if v.is_null() {
        return Ok(Vec::new());
    }
    v.as_array()
        .ok_or_else(|| format!("{what} is not an array"))?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("{what} holds a non-string"))
        })
        .collect()
}

fn number(v: Option<&Value>, what: &str) -> Result<u64, String> {
    v.and_then(Value::as_number)
        .and_then(|n| n.as_u64())
        .ok_or_else(|| format!("{what} is not an unsigned integer"))
}

/// Parses `minKernel`: two decimal numbers, `major.minor`.
pub fn parse_kernel(s: &str) -> Result<(u32, u32), String> {
    let bad = || format!("minKernel {s:?} is not <major>.<minor>");
    let (major, minor) = s.split_once('.').ok_or_else(bad)?;
    let num = |p: &str| -> Result<u32, String> {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        p.parse().map_err(|_| bad())
    };
    Ok((num(major)?, num(minor)?))
}

fn cond(v: Option<&Value>, what: &str) -> Result<Cond, String> {
    let Some(v) = v else {
        return Ok(Cond::default());
    };
    keys_known(v, what, &["arches", "caps", "minKernel"])?;
    let min_kernel = match v.get("minKernel") {
        None => None,
        Some(k) => {
            Some(parse_kernel(k.as_str().ok_or_else(|| {
                format!("{what}.minKernel is not a string")
            })?)?)
        }
    };
    Ok(Cond {
        arches: strings(v.get("arches"), &format!("{what}.arches"))?,
        caps: strings(v.get("caps"), &format!("{what}.caps"))?,
        min_kernel,
    })
}

/// Parses a profile; any key, action or comparison outside the known set
/// is an error that names it.
pub fn parse_profile(bytes: &[u8]) -> Result<Profile, String> {
    let root = boneli_json::parse(bytes, &limits()).map_err(|e| format!("JSON: {e}"))?;
    keys_known(
        &root,
        "profile",
        &["archMap", "defaultAction", "defaultErrnoRet", "syscalls"],
    )?;
    match root.get("defaultAction").and_then(Value::as_str) {
        Some("SCMP_ACT_ERRNO") => {}
        other => return Err(format!("defaultAction {other:?} is not SCMP_ACT_ERRNO")),
    }
    if let Some(map) = root.get("archMap") {
        for (i, a) in map
            .as_array()
            .ok_or("archMap is not an array")?
            .iter()
            .enumerate()
        {
            keys_known(
                a,
                &format!("archMap[{i}]"),
                &["architecture", "subArchitectures"],
            )?;
        }
    }
    let mut rules = Vec::new();
    for (i, r) in root
        .get("syscalls")
        .and_then(Value::as_array)
        .ok_or("syscalls is not an array")?
        .iter()
        .enumerate()
    {
        let what = format!("syscalls[{i}]");
        keys_known(
            r,
            &what,
            &[
                "action", "args", "comment", "errnoRet", "excludes", "includes", "names",
            ],
        )?;
        let allow = match r.get("action").and_then(Value::as_str) {
            Some("SCMP_ACT_ALLOW") => true,
            Some("SCMP_ACT_ERRNO") => false,
            other => return Err(format!("{what}: unknown action {other:?}")),
        };
        let mut args = Vec::new();
        if let Some(list) = r.get("args").filter(|v| !v.is_null()) {
            for (j, a) in list
                .as_array()
                .ok_or_else(|| format!("{what}.args is not an array"))?
                .iter()
                .enumerate()
            {
                let at = format!("{what}.args[{j}]");
                keys_known(a, &at, &["index", "op", "value", "valueTwo"])?;
                let op = match a.get("op").and_then(Value::as_str) {
                    Some("SCMP_CMP_EQ") => "eq",
                    Some("SCMP_CMP_LT") => "lt",
                    Some("SCMP_CMP_MASKED_EQ") => "masked_eq",
                    other => return Err(format!("{at}: unknown op {other:?}")),
                };
                let index = number(a.get("index"), &format!("{at}.index"))?;
                if index > 5 {
                    return Err(format!("{at}: index {index}"));
                }
                let value_two = match a.get("valueTwo") {
                    None => 0,
                    v => number(v, &format!("{at}.valueTwo"))?,
                };
                args.push(Arg {
                    index,
                    op,
                    value: number(a.get("value"), &format!("{at}.value"))?,
                    value_two,
                });
            }
        }
        rules.push(Rule {
            names: strings(r.get("names"), &format!("{what}.names"))?,
            allow,
            args,
            includes: cond(r.get("includes"), &format!("{what}.includes"))?,
            excludes: cond(r.get("excludes"), &format!("{what}.excludes"))?,
        });
    }
    Ok(Profile { rules })
}

/// Docker's name of `arch` in `includes.arches`.
pub fn docker_arch(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => "amd64",
        Arch::Aarch64 => "arm64",
    }
}

/// Whether `rule` applies with Docker's default capabilities on `arch` at
/// the kernel floor.
pub fn applies(rule: &Rule, arch: &str) -> bool {
    let i = &rule.includes;
    let e = &rule.excludes;
    i.caps.iter().all(|c| DOCKER_CAPS.contains(&c.as_str()))
        && (i.arches.is_empty() || i.arches.iter().any(|a| a == arch))
        && i.min_kernel.is_none_or(|k| k <= FLOOR)
        && !e.caps.iter().any(|c| DOCKER_CAPS.contains(&c.as_str()))
        && !e.arches.iter().any(|a| a == arch)
}

/// The list lines for `arch`: every name of the extract, in its order,
/// that no applying allow rule allows without arguments, as
/// `<name> denied` or `<name> partial <rule> | <rule>`.
pub fn derive(profile: &Profile, table: &Extract, arch: &str) -> Vec<String> {
    let mut full = BTreeSet::new();
    let mut partial: Vec<(String, Vec<String>)> = Vec::new();
    for r in profile.rules.iter().filter(|r| r.allow && applies(r, arch)) {
        for n in &r.names {
            if r.args.is_empty() {
                full.insert(n.clone());
            } else {
                let text = r
                    .args
                    .iter()
                    .map(|a| {
                        let two = if a.op == "masked_eq" {
                            format!(" {}", a.value_two)
                        } else {
                            String::new()
                        };
                        format!("arg{} {} {}{two}", a.index, a.op, a.value)
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                match partial.iter_mut().find(|(p, _)| p == n) {
                    Some((_, rules)) => rules.push(text),
                    None => partial.push((n.clone(), vec![text])),
                }
            }
        }
    }
    table
        .records
        .iter()
        .map(|(_, n)| n)
        .filter(|n| !full.contains(*n))
        .map(|n| match partial.iter().find(|(p, _)| p == n) {
            Some((_, rules)) => format!("{n} partial {}", rules.join(" | ")),
            None => format!("{n} denied"),
        })
        .collect()
}

/// The body lines of a list file (its header is `#` lines).
fn list_lines(text: &str) -> Vec<&str> {
    text.lines().filter(|l| !l.starts_with('#')).collect()
}

/// The list file of `arch`.
pub fn list(arch: Arch) -> &'static str {
    match arch {
        Arch::X86_64 => LIST_X86_64,
        Arch::Aarch64 => LIST_AARCH64,
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

#[test]
fn docker_profile_bytes_pinned() {
    assert_eq!(PROFILE.len(), PROFILE_LEN);
    assert_eq!(fnv1a(PROFILE), PROFILE_FNV1A);
    // One changed byte changes the digest.
    let mut changed = PROFILE.to_vec();
    changed[PROFILE_LEN / 2] ^= 1;
    assert_ne!(fnv1a(&changed), PROFILE_FNV1A);
}

#[test]
fn docker_profile_shape_known() {
    assert!(parse_profile(PROFILE).is_ok());
    let rule = |extra: &str| {
        format!(
            r#"{{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{{"names":["read"],"action":"SCMP_ACT_ALLOW"{extra}}}]}}"#
        )
    };
    for (bad, names) in [
        (
            r#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[],"listenerPath":""}"#.to_string(),
            "profile.listenerPath",
        ),
        (rule(r#","foo":1"#), "syscalls[0].foo"),
        (rule(r#","includes":{"foo":[]}"#), "syscalls[0].includes.foo"),
        (
            r#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_LOG"}]}"#
                .to_string(),
            "SCMP_ACT_LOG",
        ),
        (
            rule(r#","args":[{"index":0,"op":"SCMP_CMP_GE","value":1}]"#),
            "SCMP_CMP_GE",
        ),
        (
            r#"{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[]}"#.to_string(),
            "SCMP_ACT_ALLOW",
        ),
    ] {
        let err = parse_profile(bad.as_bytes()).expect_err(&bad);
        assert!(err.contains(names), "{bad}: {err:?} does not name {names}");
    }
}

#[test]
fn docker_rule_applicability() {
    // minKernel: two numbers, not strings.
    assert_eq!(parse_kernel("5.19"), Ok((5, 19)));
    assert_eq!(parse_kernel("5.2"), Ok((5, 2)));
    for bad in ["5", "5.19.1", "", "5.x", ".19", "5.", "+5.19", "5.1\u{663}"] {
        assert!(parse_kernel(bad).is_err(), "{bad:?}");
    }
    let base = Rule {
        names: vec!["n".to_string()],
        allow: true,
        args: Vec::new(),
        includes: Cond::default(),
        excludes: Cond::default(),
    };
    let with = |f: &dyn Fn(&mut Rule)| {
        let mut r = base.clone();
        f(&mut r);
        r
    };
    let kernel = |k: &str| with(&|r| r.includes.min_kernel = Some(parse_kernel(k).expect(k)));
    // Against the floor 6.1 (ADR-044 D1): 5.20 < 6.1 because 5 < 6, and
    // 6.10 > 6.1 because 10 > 1, where a string compare gets both wrong.
    for k in ["4.8", "5.2", "5.19", "5.20", "6.0", "6.1"] {
        assert!(applies(&kernel(k), "amd64"), "minKernel {k}");
    }
    for k in ["6.2", "6.10", "7.0"] {
        assert!(!applies(&kernel(k), "amd64"), "minKernel {k}");
    }
    // Capabilities: included ones must all be defaults, excluded ones none.
    let inc = |c: &str| with(&|r| r.includes.caps = vec![c.to_string()]);
    let exc = |c: &str| with(&|r| r.excludes.caps = vec![c.to_string()]);
    assert!(!applies(&inc("CAP_SYS_ADMIN"), "amd64"));
    assert!(applies(&inc("CAP_CHOWN"), "amd64"));
    assert!(!applies(&exc("CAP_CHOWN"), "amd64"));
    assert!(applies(&exc("CAP_SYS_ADMIN"), "amd64"));
    // Architectures.
    let arches = with(&|r| r.includes.arches = vec!["amd64".to_string(), "x32".to_string()]);
    assert!(applies(&arches, "amd64"));
    assert!(!applies(&arches, "arm64"));
    let not_arm = with(&|r| r.excludes.arches = vec!["arm64".to_string()]);
    assert!(!applies(&not_arm, "arm64"));
    assert!(applies(&not_arm, "amd64"));
    // A name with a full and a partial allow is full; a name no rule
    // allows is denied (the default action is an errno).
    let partial = with(&|r| {
        r.args = vec![Arg {
            index: 0,
            op: "eq",
            value: 1,
            value_two: 0,
        }]
    });
    let table = Extract {
        header: Vec::new(),
        records: vec![(0, "n".to_string()), (1, "m".to_string())],
    };
    let both = Profile {
        rules: vec![partial.clone(), base.clone()],
    };
    assert_eq!(derive(&both, &table, "amd64"), ["m denied"]);
    let only = Profile {
        rules: vec![partial],
    };
    assert_eq!(
        derive(&only, &table, "amd64"),
        ["n partial arg0 eq 1", "m denied"]
    );
    // An errno rule allows nothing.
    let errno = Profile {
        rules: vec![with(&|r| r.allow = false)],
    };
    assert_eq!(derive(&errno, &table, "amd64"), ["n denied", "m denied"]);
}

#[test]
fn docker_lists_derive_from_profile() {
    let profile = parse_profile(PROFILE).expect("the pinned profile");
    for (arch, total, partial) in [(Arch::X86_64, 80, 4), (Arch::Aarch64, 64, 4)] {
        let derived = derive(&profile, &extract(arch), docker_arch(arch));
        let file = list_lines(list(arch));
        assert_eq!(file, derived, "docker-denied-{}.txt", arch.name());
        assert_eq!(derived.len(), total, "{}", arch.name());
        let partials: Vec<&str> = derived
            .iter()
            .filter(|l| l.contains(" partial "))
            .map(|l| l.split(' ').next().unwrap_or(""))
            .collect();
        assert_eq!(partials.len(), partial, "{}: {partials:?}", arch.name());
        let mut sorted = partials.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            ["clone", "personality", "socket", "socketpair"],
            "{}",
            arch.name()
        );
        // The header is prose: it names the pin and the test, and holds no
        // program.
        let header: Vec<&str> = list(arch)
            .lines()
            .take_while(|l| l.starts_with('#'))
            .collect();
        let text = header.join("\n");
        assert!(text.contains("9ee3204f0d0cfa19ca2c6a7b0fcf5a2b353954ae"));
        assert!(text.contains("docker_lists_derive_from_profile"));
    }
}

/// The ADR the table lives in.
fn adr_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/007-sandbox-runtime-id-mapping-and-seccomp-policy.md")
}

const BEGIN: &str = "<!-- docker-table:begin -->";
const END: &str = "<!-- docker-table:end -->";

/// The rows of the table between the markers: one marker pair, comments
/// removed, a row per line that starts with `` | ` ``; each row split into
/// its cells.
pub fn table_rows(adr: &str) -> Result<Vec<Vec<String>>, String> {
    if adr.matches(BEGIN).count() != 1 || adr.matches(END).count() != 1 {
        return Err("the ADR needs exactly one docker-table marker pair".to_string());
    }
    let start = adr.find(BEGIN).map(|i| i + BEGIN.len()).unwrap_or(0);
    let end = adr.find(END).unwrap_or(0);
    if end < start {
        return Err("the end marker comes first".to_string());
    }
    let mut body = adr[start..end].to_string();
    while let Some(open) = body.find("<!--") {
        let close = body[open..]
            .find("-->")
            .map(|c| open + c + 3)
            .ok_or("an unclosed comment in the table")?;
        body.replace_range(open..close, "");
    }
    Ok(body
        .lines()
        .filter(|l| l.starts_with("| `"))
        .map(|l| {
            l.trim_matches('|')
                .split(" | ")
                .map(|c| c.trim().to_string())
                .collect()
        })
        .collect())
}

/// The verdict cell of a census entry.
fn verdict_cell(v: &Verdict) -> String {
    match v {
        Verdict::Own => "Own".to_string(),
        Verdict::NeedsCap { cap, .. } => format!("NeedsCap `{cap}`"),
        Verdict::Row { rows, .. } => format!(
            "Row {}",
            rows.iter()
                .map(|r| format!("`{r:?}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Verdict::NotImplemented => "NotImplemented".to_string(),
    }
}

/// Docker's cell from a list line.
fn docker_cell(line: &str) -> String {
    match line.split_once(" partial ") {
        // A pipe inside a table cell is escaped, also in a code span.
        Some((_, rules)) => format!("partial: `{}`", rules.replace(" | ", " \\| ")),
        None => "denied".to_string(),
    }
}

/// The expected table: one row per x86_64 list name that the census does
/// not deny in every form and that differs in more than ignored bits.
pub fn expected_rows() -> Vec<Vec<String>> {
    let x86 = extract(Arch::X86_64);
    let arm = extract(Arch::Aarch64);
    let arm_list = list_lines(LIST_AARCH64);
    let mut rows = Vec::new();
    for line in list_lines(LIST_X86_64) {
        let name = line.split(' ').next().unwrap_or("");
        let e = entry(name).unwrap_or_else(|| panic!("{name} is not in the census"));
        if let Verdict::Row { rows: r, .. } = &e.verdict
            && r.iter().all(|row| row.denies_every_form())
        {
            continue;
        }
        if IGNORED_BITS.contains(&name) {
            continue;
        }
        let arm_cell = match arm.number(name) {
            Some(nr) => {
                // Docker's answer is the same on both architectures where
                // both have the name.
                let arm_line = arm_list
                    .iter()
                    .find(|l| l.split(' ').next() == Some(name))
                    .unwrap_or_else(|| panic!("{name} is missing from the aarch64 list"));
                assert_eq!(*arm_line, line, "{name}: Docker differs per architecture");
                nr.to_string()
            }
            None => "-".to_string(),
        };
        rows.push(vec![
            format!("`{name}`"),
            x86.number(name).map(|n| n.to_string()).unwrap_or_default(),
            arm_cell,
            docker_cell(line),
            verdict_cell(&e.verdict),
            e.reason.to_string(),
        ]);
    }
    rows
}

#[test]
fn docker_diff_rows_complete() {
    let adr = std::fs::read_to_string(adr_path()).expect("read ADR-007");
    let rows = table_rows(&adr).expect("the Docker table");
    let names: Vec<&String> = rows.iter().map(|r| &r[0]).collect();
    let set: BTreeSet<&String> = names.iter().copied().collect();
    assert_eq!(names.len(), set.len(), "a repeated row");
    let expected = expected_rows();
    assert_eq!(rows.len(), 67);
    assert_eq!(rows.iter().filter(|r| r[2] != "-").count(), 51);
    for (got, want) in rows.iter().zip(&expected) {
        assert_eq!(got, want, "ADR-007's Docker table");
    }
    assert_eq!(rows.len(), expected.len());
    // The two names left out differ only in ignored bits, and every name
    // the census denies in every form is in both lists.
    for name in IGNORED_BITS {
        assert!(
            list_lines(LIST_X86_64)
                .iter()
                .any(|l| l.starts_with(&format!("{name} partial ")))
        );
    }
    let every_form: Vec<&str> = CENSUS
        .iter()
        .filter(|e| matches!(&e.verdict, Verdict::Row { rows, .. } if rows.iter().all(|r| r.denies_every_form())))
        .map(|e| e.name)
        .collect();
    assert_eq!(every_form.len(), 11, "{every_form:?}");
    for arch in Arch::ALL {
        let lines = list_lines(list(arch));
        for name in &every_form {
            assert!(
                lines.contains(&format!("{name} denied").as_str()),
                "{}: {name}",
                arch.name()
            );
        }
    }

    // The table reader itself.
    let row = "| `a` | 1 | 2 | denied | Own | r |";
    let pair = |body: &str| format!("x\n{BEGIN}\n{body}\n{END}\n");
    assert_eq!(table_rows(&pair(row)).expect("one row").len(), 1);
    assert!(table_rows(row).is_err(), "no markers");
    assert!(
        table_rows(&format!("{}{}", pair(row), pair(row))).is_err(),
        "two pairs"
    );
    assert_eq!(
        table_rows(&pair(&format!("<!--\n{row}\n-->")))
            .expect("commented")
            .len(),
        0
    );
    let twice = table_rows(&pair(&format!("{row}\n{row}"))).expect("two rows");
    assert_eq!(twice.len(), 2);
    assert_ne!(
        twice.iter().map(|r| &r[0]).collect::<BTreeSet<_>>().len(),
        twice.len(),
        "a repeated row is seen"
    );
}
