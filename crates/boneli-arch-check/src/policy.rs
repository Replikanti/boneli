//! `tools/architecture.toml`: validation of the policy and the ADR rules
//! that approve strict edges and build scripts (ADR-001, ADR-005).

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use boneli_toml::{Table, Value};

use crate::check::POLICY;
use crate::fs::{read_text, rel};
use crate::rules::{Report, Rule, ToolError};
use crate::text::{show, split_space, strip};

/// The validated policy.
#[derive(Debug, Default)]
pub(crate) struct Policy {
    pub(crate) core: Vec<String>,
    pub(crate) support: Vec<String>,
    pub(crate) roots: Vec<String>,
    pub(crate) unsafe_crates: Vec<String>,
    pub(crate) build_script: Vec<String>,
    pub(crate) platforms: Vec<String>,
    pub(crate) no_std_target: String,
    /// The lints of `check.unsafe-lints` as (tool, name); `None` when the
    /// array is malformed, which policy-format reports.
    pub(crate) unsafe_lints: Option<Vec<(String, String)>>,
    /// Recorded edges (parent, crate).
    pub(crate) edges: BTreeSet<(String, String)>,
    /// External crates whose build script an accepted ADR approves.
    pub(crate) build_scripts: BTreeMap<String, String>,
}

/// A TOML value as TOML syntax, for messages: a string as itself, other
/// values as they would be written (`true`, `5`, `["a"]`,
/// `{ level = "x" }`).
pub(crate) fn toml_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => toml_inline(other),
    }
}

fn toml_inline(value: &Value) -> String {
    match value {
        Value::String(s) => toml_string(s),
        Value::Integer(i) => i.to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(toml_inline).collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Table(t) if t.is_empty() => "{}".to_owned(),
        Value::Table(t) => {
            let inner: Vec<String> = t
                .iter()
                .map(|(k, v)| format!("{} = {}", toml_key(k), toml_inline(v)))
                .collect();
            format!("{{ {} }}", inner.join(", "))
        }
    }
}

/// A basic TOML string.
pub(crate) fn toml_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn toml_key(k: &str) -> String {
    let bare = !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if bare { k.to_owned() } else { toml_string(k) }
}

/// An optional value as text: `nothing` when it is missing.
pub(crate) fn text_or_nothing(value: Option<&Value>) -> String {
    value.map_or_else(|| "nothing".to_owned(), toml_text)
}

/// `[A-Za-z0-9_-]+`.
pub(crate) fn is_policy_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The number of an `ADR-NNN` reference.
pub(crate) fn adr_number(s: &str) -> Option<&str> {
    let digits = s.strip_prefix("ADR-")?;
    (digits.len() == 3 && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// `rust.<lint>` or `clippy.<lint>` with a lint of `[a-z0-9_]+`.
fn lint_name(s: &str) -> Option<(String, String)> {
    let (tool, name) = s.split_once('.')?;
    let ok = matches!(tool, "rust" | "clippy")
        && !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    ok.then(|| (tool.to_owned(), name.to_owned()))
}

/// The ADR files `docs/adr/<number>-*.md` (symlinks to files count),
/// sorted.
pub(crate) fn adr_files(root: &Path, number: &str) -> Result<Vec<PathBuf>, ToolError> {
    let dir = root.join("docs").join("adr");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(&dir).map_err(|e| {
        ToolError::new(
            rel(root, &dir),
            format!("cannot read directory: {}", crate::fs::strerror(&e)),
        )
    })?;
    let prefix = format!("{number}-");
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            ToolError::new(
                rel(root, &dir),
                format!("cannot read directory: {}", crate::fs::strerror(&e)),
            )
        })?;
        let name = entry.file_name();
        let bytes = name.as_bytes();
        if bytes.len() >= prefix.len() + 3
            && bytes.starts_with(prefix.as_bytes())
            && bytes.ends_with(b".md")
            && entry.path().is_file()
        {
            found.push(entry.path());
        }
    }
    found.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
    Ok(found)
}

/// The text without HTML comments: each `<!--` up to the next `-->`
/// after it is removed, and an unterminated `<!--` cuts the rest.
pub(crate) fn strip_html_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    while let Some(i) = text[pos..].find("<!--").map(|i| pos + i) {
        match text[i + 4..].find("-->") {
            Some(j) => {
                out.push_str(&text[pos..i]);
                pos = i + 4 + j + 3;
            }
            None => break,
        }
    }
    out.push_str(&text[pos..]);
    match out.find("<!--") {
        Some(cut) => out[..cut].to_owned(),
        None => out,
    }
}

/// Whether the first status line of an ADR (comments stripped) is
/// accepted.
pub(crate) fn adr_accepted(text: &str) -> bool {
    text.split('\n')
        .find(|l| l.starts_with("- Status:"))
        .is_some_and(|l| l.trim_end_matches('\r') == "- Status: accepted")
}

/// Whether an ADR (comments stripped) says `<crate>'s build script is
/// approved`, with the crate name not glued to a longer name and line
/// breaks inside the phrase read as spaces.
pub(crate) fn names_build_script(text: &str, krate: &str) -> bool {
    let flat = split_space(text).collect::<Vec<_>>().join(" ");
    let needle = format!("{krate}'s build script is approved");
    let bytes = flat.as_bytes();
    let mut from = 0;
    while let Some(i) = flat[from..].find(&needle).map(|i| from + i) {
        let glued = i > 0 && {
            let b = bytes[i - 1];
            b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
        };
        if !glued {
            return true;
        }
        from = i + flat[i..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Validates the policy. `None` when roles or check are unusable.
pub(crate) fn check_policy(
    data: &Table,
    root: &Path,
    rep: &mut Report,
) -> Result<Option<Policy>, ToolError> {
    let mut p = Checker {
        root,
        rep,
        resolved: BTreeMap::new(),
    };
    p.run(data)
}

struct Checker<'a> {
    root: &'a Path,
    rep: &'a mut Report,
    resolved: BTreeMap<String, Vec<PathBuf>>,
}

impl Checker<'_> {
    fn bad(&mut self, message: String) {
        self.rep.fail(Rule::PolicyFormat, POLICY, message, None);
    }

    fn names(&mut self, value: Option<&Value>, at: &str) -> Option<Vec<String>> {
        let list: Option<Vec<String>> = value.and_then(Value::as_array).and_then(|items| {
            items
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect()
        });
        let Some(list) = list else {
            self.bad(format!("{at} must be an array of strings"));
            return None;
        };
        for v in &list {
            if !is_policy_name(v) {
                self.bad(format!("{at}: name {} is not [A-Za-z0-9_-]+", show(v)));
            }
        }
        Some(list)
    }

    /// Whether `reference` is ADR-NNN with exactly one file
    /// `docs/adr/NNN-*.md`.
    fn resolves(&mut self, reference: &str) -> Result<bool, ToolError> {
        let Some(number) = adr_number(reference) else {
            return Ok(false);
        };
        if !self.resolved.contains_key(reference) {
            let files = adr_files(self.root, number)?;
            self.resolved.insert(reference.to_owned(), files);
        }
        Ok(self.resolved.get(reference).is_some_and(|f| f.len() == 1))
    }

    fn adr_file(&self, reference: &str) -> Option<PathBuf> {
        self.resolved
            .get(reference)
            .and_then(|f| f.first())
            .cloned()
    }

    fn decision(&mut self, value: Option<&Value>, at: &str) -> Result<(), ToolError> {
        match value.and_then(Value::as_str) {
            None | Some("") => self.bad(format!("{at}: missing or empty `decision`")),
            Some("ARCHITECTURE") => {}
            Some(v) if adr_number(v).is_none() => self.bad(format!(
                "{at}: decision {} is neither ARCHITECTURE nor ADR-NNN",
                show(v)
            )),
            Some(v) => {
                if !self.resolves(v)? {
                    self.bad(format!(
                        "{at}: {v} does not resolve to exactly one docs/adr/NNN-*.md"
                    ));
                }
            }
        }
        Ok(())
    }

    fn reason(&mut self, value: Option<&Value>, at: &str) {
        if value
            .and_then(Value::as_str)
            .is_none_or(|v| strip(v).is_empty())
        {
            self.bad(format!("{at}: missing or empty `reason`"));
        }
    }

    fn adr_text(&self, adr: &Path) -> Result<String, ToolError> {
        Ok(strip_html_comments(&read_text(adr, self.root)?))
    }

    fn run(&mut self, data: &Table) -> Result<Option<Policy>, ToolError> {
        for key in data.keys() {
            if !matches!(key, "roles" | "check" | "external") {
                self.bad(format!("unknown top-level table [{}]", show(key)));
            }
        }
        let mut pol = Policy::default();
        let mut usable = true;
        match data.get("roles").and_then(Value::as_table) {
            None => {
                self.bad("missing [roles]".to_owned());
                usable = false;
            }
            Some(roles) => {
                const ROLE_KEYS: [&str; 5] =
                    ["core", "support", "roots", "\x75nsafe", "build-script"];
                for key in roles.keys() {
                    if !ROLE_KEYS.contains(&key) {
                        self.bad(format!("unknown key roles.{}", show(key)));
                    }
                }
                for key in ROLE_KEYS {
                    let value = self.names(roles.get(key), &format!("roles.{key}"));
                    if value.is_none() {
                        usable = false;
                    }
                    let value = value.unwrap_or_default();
                    match key {
                        "core" => pol.core = value,
                        "support" => pol.support = value,
                        "roots" => pol.roots = value,
                        "build-script" => pol.build_script = value,
                        _ => pol.unsafe_crates = value,
                    }
                }
            }
        }
        match data.get("check").and_then(Value::as_table) {
            None => {
                self.bad("missing [check]".to_owned());
                usable = false;
            }
            Some(check) => {
                for key in check.keys() {
                    if !matches!(key, "platforms" | "no-std-target" | "\x75nsafe-lints") {
                        self.bad(format!("unknown key check.{}", show(key)));
                    }
                }
                let platforms: Option<Vec<String>> = check
                    .get("platforms")
                    .and_then(Value::as_array)
                    .filter(|items| !items.is_empty())
                    .and_then(|items| {
                        items
                            .iter()
                            .map(|v| v.as_str().filter(|s| !s.is_empty()).map(str::to_owned))
                            .collect()
                    });
                match platforms {
                    Some(list) => pol.platforms = list,
                    None => {
                        self.bad("check.platforms must be a non-empty array of strings".to_owned());
                        usable = false;
                    }
                }
                match check.get("no-std-target").and_then(Value::as_str) {
                    Some(t) if !t.is_empty() => pol.no_std_target = t.to_owned(),
                    _ => {
                        self.bad("check.no-std-target must be a string".to_owned());
                        usable = false;
                    }
                }
                // Required, so that deleting the line cannot switch the
                // lints of rule sys-lints off (ADR-007, D6). A malformed
                // array leaves the rule without its list; policy-format
                // fails the run.
                let lints: Option<Vec<(String, String)>> = check
                    .get("\x75nsafe-lints")
                    .and_then(Value::as_array)
                    .filter(|items| !items.is_empty())
                    .and_then(|items| {
                        items
                            .iter()
                            .map(|v| v.as_str().and_then(lint_name))
                            .collect()
                    });
                match lints {
                    None => self.bad(
                        "check.\x75nsafe-lints must be a non-empty array of \"rust.<lint>\" or \"clippy.<lint>\" strings"
                            .to_owned(),
                    ),
                    Some(list) => {
                        let distinct: BTreeSet<&(String, String)> = list.iter().collect();
                        if distinct.len() != list.len() {
                            self.bad("check.\x75nsafe-lints names a lint twice".to_owned());
                        } else {
                            pol.unsafe_lints = Some(list);
                        }
                    }
                }
            }
        }
        if !usable {
            return Ok(None);
        }

        let groups = [
            ("core", pol.core.clone()),
            ("support", pol.support.clone()),
            ("roots", pol.roots.clone()),
        ];
        let mut seen: BTreeMap<String, &str> = BTreeMap::new();
        for (group, members) in &groups {
            for name in members {
                if let Some(&first) = seen.get(name) {
                    if first != *group {
                        self.bad(format!("{name} is in both roles.{first} and roles.{group}"));
                    }
                } else {
                    seen.insert(name.clone(), group);
                }
            }
        }
        for name in &pol.unsafe_crates {
            if pol.core.contains(name) {
                self.bad(format!("{name} is in both roles.core and roles.\x75nsafe"));
            }
        }
        for name in &pol.build_script {
            if pol.core.contains(name) {
                self.bad(format!(
                    "{name} is in both roles.core and roles.build-script"
                ));
            }
        }

        let empty = Table::new();
        let external = match data.get("external") {
            None => &empty,
            Some(Value::Table(t)) => t,
            Some(_) => {
                self.bad("[external] must be a table".to_owned());
                &empty
            }
        };
        let mut strict: Vec<String> = Vec::new();
        for (krate, table) in external.iter() {
            let at = format!("[external.{}]", show(krate));
            if !is_policy_name(krate) {
                self.bad(format!("{at}: name is not [A-Za-z0-9_-]+"));
            }
            let Some(table) = table.as_table() else {
                self.bad(format!("{at} must be a table"));
                continue;
            };
            for key in table.keys() {
                if !matches!(
                    key,
                    "reason" | "decision" | "strict" | "build-script" | "pulled-by"
                ) {
                    self.bad(format!("{at}: unknown key {}", show(key)));
                }
            }
            self.reason(table.get("reason"), &at);
            self.decision(table.get("decision"), &at)?;
            if let Some(marker) = table.get("strict") {
                // Any strict key makes the crate strict, a malformed one
                // included.
                strict.push(krate.to_owned());
                match marker.as_str().filter(|m| adr_number(m).is_some()) {
                    None => self.bad(format!("{at}: strict must be \"ADR-NNN\"")),
                    Some(m) => {
                        if !self.resolves(m)? {
                            self.bad(format!(
                                "{at}: strict {m} does not resolve to exactly one docs/adr/NNN-*.md"
                            ));
                        }
                    }
                }
            }
            if let Some(reference) = table.get("build-script") {
                // Only a well-formed key citing an accepted ADR that names
                // the crate approves the build script, as for strict edges.
                match reference.as_str().filter(|r| adr_number(r).is_some()) {
                    None => self.bad(format!("{at}: build-script must be \"ADR-NNN\"")),
                    Some(r) => {
                        if !self.resolves(r)? {
                            self.bad(format!(
                                "{at}: build-script {r} does not resolve to exactly one docs/adr/NNN-*.md"
                            ));
                        } else if let Some(adr) = self.adr_file(r) {
                            let text = self.adr_text(&adr)?;
                            let adr_path = rel(self.root, &adr);
                            let mut approved = true;
                            if !adr_accepted(&text) {
                                self.rep.fail(
                                    Rule::PolicyFormat,
                                    adr_path.clone(),
                                    format!("{r} is not accepted (cited by {at} build-script)"),
                                    None,
                                );
                                approved = false;
                            }
                            if !names_build_script(&text, krate) {
                                self.rep.fail(
                                    Rule::PolicyFormat,
                                    adr_path,
                                    format!(
                                        "{r} does not say \"{krate}'s build script is approved\" (cited by {at} build-script)"
                                    ),
                                    None,
                                );
                                approved = false;
                            }
                            if approved {
                                pol.build_scripts.insert(krate.to_owned(), r.to_owned());
                            }
                        }
                    }
                }
            }
            let parents = table
                .get("pulled-by")
                .and_then(Value::as_table)
                .filter(|t| !t.is_empty());
            let Some(parents) = parents else {
                self.bad(format!(
                    "{at}: no edge record [external.{}.pulled-by.<parent>]",
                    show(krate)
                ));
                continue;
            };
            for (parent, record) in parents.iter() {
                let eat = format!("[external.{}.pulled-by.{}]", show(krate), show(parent));
                if !is_policy_name(parent) {
                    self.bad(format!("{eat}: name is not [A-Za-z0-9_-]+"));
                }
                if pol.core.iter().any(|c| c == parent) {
                    self.bad(format!("{eat}: core crates take no external dependencies"));
                }
                let Some(record) = record.as_table() else {
                    self.bad(format!("{eat} must be a table"));
                    continue;
                };
                for key in record.keys() {
                    if !matches!(key, "reason" | "decision") {
                        self.bad(format!("{eat}: unknown key {}", show(key)));
                    }
                }
                self.reason(record.get("reason"), &eat);
                self.decision(record.get("decision"), &eat)?;
                pol.edges.insert((parent.to_owned(), krate.to_owned()));
            }
        }

        // Strict crates: every edge cites its own accepted ADR that names it.
        for krate in &strict {
            let Some(parents) = external
                .get(krate)
                .and_then(Value::as_table)
                .and_then(|t| t.get("pulled-by"))
                .and_then(Value::as_table)
            else {
                continue;
            };
            for (parent, record) in parents.iter() {
                let eat = format!("[external.{}.pulled-by.{}]", show(krate), show(parent));
                let reference = record.as_table().and_then(|r| r.get("decision"));
                let edge = format!("`{parent} -> {krate}`");
                let Some(r) = reference
                    .and_then(Value::as_str)
                    .filter(|r| adr_number(r).is_some())
                else {
                    self.rep.fail(
                        Rule::PolicyStrict,
                        POLICY,
                        format!(
                            "{eat}: {krate} is strict, so this edge needs its own accepted ADR, not {}",
                            show(&text_or_nothing(reference))
                        ),
                        None,
                    );
                    continue;
                };
                if !self.resolves(r)? {
                    self.rep.fail(
                        Rule::PolicyStrict,
                        POLICY,
                        format!("{eat}: {r} does not resolve to exactly one ADR file"),
                        None,
                    );
                    continue;
                }
                let Some(adr) = self.adr_file(r) else {
                    continue;
                };
                let text = self.adr_text(&adr)?;
                let adr_path = rel(self.root, &adr);
                if !adr_accepted(&text) {
                    self.rep.fail(
                        Rule::PolicyStrict,
                        adr_path.clone(),
                        format!("{r} is not accepted (cited by {eat})"),
                        None,
                    );
                }
                if !text.contains(&edge) {
                    self.rep.fail(
                        Rule::PolicyStrict,
                        adr_path,
                        format!("{r} does not name the edge {edge} (cited by {eat})"),
                        None,
                    );
                }
            }
        }
        Ok(Some(pol))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Policy, adr_accepted, adr_files, check_policy, names_build_script, strip_html_comments,
        toml_text,
    };
    use crate::py_vectors;
    use crate::rules::Report;
    use crate::tmp::TempDir;

    #[test]
    fn strip_html_comments_matches_python() {
        for &(input, want) in py_vectors::STRIP_HTML_COMMENTS {
            assert_eq!(strip_html_comments(input), want, "{input:?}");
        }
    }

    #[test]
    fn names_build_script_matches_python() {
        for &(text, krate, want) in py_vectors::NAMES_BUILD_SCRIPT {
            assert_eq!(names_build_script(text, krate), want, "{text:?} {krate:?}");
        }
    }

    /// A symlink to an ADR file counts as the file; two files with the
    /// same number resolve to neither; a directory does not count.
    #[test]
    fn policy_adr_files_follow_symlinks() {
        let tmp = TempDir::new("adr-files");
        let dir = tmp.path().join("docs/adr");
        std::fs::create_dir_all(dir.join("003-dir.md")).expect("dirs");
        std::fs::write(tmp.path().join("real.md"), "- Status: accepted\n").expect("adr");
        std::os::unix::fs::symlink("../../real.md", dir.join("001-link.md")).expect("link");
        std::fs::write(dir.join("002-a.md"), "").expect("adr");
        std::fs::write(dir.join("002-b.md"), "").expect("adr");
        std::fs::write(dir.join("001.md"), "").expect("no dash");
        let names = |n: &str| -> Vec<String> {
            adr_files(tmp.path(), n)
                .expect("lists")
                .iter()
                .map(|p| p.file_name().expect("name").to_string_lossy().into_owned())
                .collect()
        };
        assert_eq!(names("001"), ["001-link.md"]);
        assert_eq!(names("002"), ["002-a.md", "002-b.md"]);
        assert!(names("003").is_empty());
    }

    #[test]
    fn policy_adr_status_lines() {
        assert!(adr_accepted("# x\n- Status: accepted\r\r\n"));
        assert!(!adr_accepted("- Status: proposed\n- Status: accepted\n"));
        assert!(!adr_accepted(" - Status: accepted"));
        assert!(!adr_accepted("- Status: accepted (2026)"));
        assert!(!adr_accepted(""));
    }

    #[test]
    fn toml_values_in_messages() {
        let t = boneli_toml::parse(
            b"a = 5\nb = true\nc = [\"x\", 1]\nd = { level = \"x\", \"k k\" = [] }\ne = \"s\"\nf = {}",
            &boneli_toml::Limits::new(1024, 8).expect("limits"),
        )
        .expect("parses");
        let got: Vec<String> = ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|k| toml_text(t.get(k).expect("key")))
            .collect();
        assert_eq!(
            got,
            [
                "5",
                "true",
                "[\"x\", 1]",
                "{ level = \"x\", \"k k\" = [] }",
                "s",
                "{}"
            ]
        );
    }

    /// The policy of the workspace with `extra` appended, checked against
    /// a root whose `docs/adr` holds `adrs`.
    fn checked(
        extra: &str,
        adrs: &[(&str, &str)],
    ) -> (Option<Policy>, Vec<(String, String, String)>) {
        let tmp = TempDir::new("policy");
        let dir = tmp.path().join("docs/adr");
        std::fs::create_dir_all(&dir).expect("adr dir");
        for (name, text) in adrs {
            std::fs::write(dir.join(name), text).expect("adr");
        }
        let text = format!(
            "[roles]\ncore = [\"boneli-domain\"]\nsupport = []\nroots = []\n\x75nsafe = []\nbuild-script = []\n\
             [check]\nplatforms = [\"x\"]\nno-std-target = \"y\"\n\x75nsafe-lints = [\"rust.a\"]\n{extra}"
        );
        let data = boneli_toml::parse(
            text.as_bytes(),
            &boneli_toml::Limits::new(1 << 20, 128).expect("limits"),
        )
        .expect("policy parses");
        let mut rep = Report::default();
        let pol = check_policy(&data, tmp.path(), &mut rep).expect("no tool error");
        let items = rep
            .items
            .iter()
            .map(|i| {
                (
                    i.rule.id().to_owned(),
                    i.path.to_string_lossy().into_owned(),
                    i.message.clone(),
                )
            })
            .collect();
        (pol, items)
    }

    /// A reason of U+001C or of U+3000 only is empty, as for the reference
    /// checker's `strip()`; `str::trim` would keep U+001C.
    #[test]
    fn policy_reason_python_whitespace_is_empty() {
        for blank in ["\\u001C", "\u{3000}", "\\u001F\\u3000 "] {
            let (_, items) = checked(
                &format!(
                    "[external.x]\nreason = \"{blank}\"\ndecision = \"ARCHITECTURE\"\n\
                     [external.x.pulled-by.boneli-app]\nreason = \"r\"\ndecision = \"ARCHITECTURE\"\n"
                ),
                &[],
            );
            assert_eq!(
                items,
                [(
                    "policy-format".to_owned(),
                    "tools/architecture.toml".to_owned(),
                    "[external.x]: missing or empty `reason`".to_owned()
                )],
                "{blank:?}"
            );
        }
    }

    #[test]
    fn policy_branches_without_a_fixture() {
        let (pol, items) = checked(
            "[external]\nx = 1\n[external.\"a.b\"]\nreason = \"r\"\ndecision = \"ADR-1\"\nstrict = 5\nbuild-script = \"ADR-009\"\n\
             [external.\"a.b\".pulled-by]\np = 1\n\"q q\" = { reason = \"r\", decision = \"ADR-007\", extra = 1 }\n",
            &[
                ("009-x.md", "- Status: accepted\n"),
                ("007-y.md", "- Status: proposed\n"),
            ],
        );
        let pol = pol.expect("usable");
        let messages: Vec<&str> = items.iter().map(|i| i.2.as_str()).collect();
        assert_eq!(
            messages,
            [
                "[external.x] must be a table",
                "[external.a.b]: name is not [A-Za-z0-9_-]+",
                "[external.a.b]: decision ADR-1 is neither ARCHITECTURE nor ADR-NNN",
                "[external.a.b]: strict must be \"ADR-NNN\"",
                "ADR-009 does not say \"a.b's build script is approved\" (cited by [external.a.b] build-script)",
                "[external.a.b.pulled-by.p] must be a table",
                "[external.a.b.pulled-by.q q]: name is not [A-Za-z0-9_-]+",
                "[external.a.b.pulled-by.q q]: unknown key extra",
                "[external.a.b.pulled-by.p]: a.b is strict, so this edge needs its own accepted ADR, not nothing",
                "ADR-007 is not accepted (cited by [external.a.b.pulled-by.q q])",
                "ADR-007 does not name the edge `q q -> a.b` (cited by [external.a.b.pulled-by.q q])",
            ]
        );
        assert_eq!(items[4].1, "docs/adr/009-x.md");
        assert!(pol.edges.contains(&("q q".to_owned(), "a.b".to_owned())));
        assert!(pol.build_scripts.is_empty());
    }

    #[test]
    fn policy_lints_and_roles() {
        let (pol, items) = checked("", &[]);
        assert!(items.is_empty(), "{items:?}");
        let pol = pol.expect("usable");
        assert_eq!(
            pol.unsafe_lints,
            Some(vec![("rust".to_owned(), "a".to_owned())])
        );
        // A duplicate lint and an overlap are reported; the policy stays
        // usable without the lints.
        let tmp = TempDir::new("policy-lints");
        let data = boneli_toml::parse(
            b"[roles]\ncore = [\"a\"]\nsupport = [\"a\", \"\xc3\xa9\"]\nroots = []\n\x75nsafe = [\"a\"]\nbuild-script = 1\nx = 2\n\
              [check]\nplatforms = [\"\"]\nno-std-target = 1\n\x75nsafe-lints = [\"rust.a\", \"rust.a\"]\n",
            &boneli_toml::Limits::new(1 << 20, 128).expect("limits"),
        )
        .expect("parses");
        let mut rep = Report::default();
        let pol = check_policy(&data, tmp.path(), &mut rep).expect("no tool error");
        assert!(pol.is_none());
        let messages: Vec<&str> = rep.items.iter().map(|i| i.message.as_str()).collect();
        assert_eq!(
            messages,
            [
                "unknown key roles.x",
                "roles.support: name \\u{e9} is not [A-Za-z0-9_-]+",
                "roles.build-script must be an array of strings",
                "check.platforms must be a non-empty array of strings",
                "check.no-std-target must be a string",
                "check.\x75nsafe-lints names a lint twice",
            ]
        );
    }
}
