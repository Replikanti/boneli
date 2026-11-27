//! The census of every syscall (ADR-007, D2): the two syscall extracts,
//! the verdict of each name ([`entries::CENSUS`]), the forms the policy's
//! rows deny, and the pure tests that tie them to the policy. The Docker
//! comparison is in [`docker`].
//!
//! The extracts list every number up to [`CEILING`] of the Linux 7.2.4 uapi
//! tables as `<nr> <name>`, after a header of `#` lines that names the
//! command that produced them. Their format is strict ([`parse`]), and
//! [`render`] gives back the file byte for byte.

pub mod docker;
mod entries;

use std::collections::{BTreeMap, BTreeSet};

use boneli_sys::seccomp::{Arch, CEILING, Policy, Row};

use crate::support::bpf::{ALLOW, Data, program, run};
pub use entries::CENSUS;

/// The x86_64 extract (`arch/x86/include/uapi/asm/unistd_64.h`, 7.2.4).
pub const SYSCALLS_X86_64: &str = include_str!("syscalls-x86_64.txt");
/// The aarch64 extract (`include/uapi/asm-generic/unistd.h` as arm64
/// builds it, 7.2.4).
pub const SYSCALLS_AARCH64: &str = include_str!("syscalls-aarch64.txt");

/// The verdict counts ADR-007 D2 records; a changed verdict updates both.
pub const OWN: usize = 267;
/// `NeedsCap` entries.
pub const NEEDS_CAP: usize = 83;
/// `Row` entries.
pub const ROW: usize = 21;
/// `NotImplemented` entries.
pub const NOT_IMPLEMENTED: usize = 14;

/// One syscall name and its verdict.
#[derive(Debug)]
pub struct Entry {
    /// The name, as both extracts write it.
    pub name: &'static str,
    /// Why the sandbox may or may not make the call.
    pub verdict: Verdict,
    /// One line: what the call reaches and why that verdict holds.
    pub reason: &'static str,
}

/// The verdict of a census entry.
#[derive(Debug)]
pub enum Verdict {
    /// The call acts only on the caller's own processes, memory,
    /// descriptors, files or namespaces, or reads values the sandbox's
    /// `/proc` shows anyway.
    Own,
    /// Policy rows decide it: every row on the name is listed, and the
    /// forms the rows leave allowed that a capability gates are `extra`.
    Row {
        /// The rows that match this syscall, in table order.
        rows: &'static [Row],
        /// Capability-gated forms the rows allow, probed like `NeedsCap`.
        extra: &'static [Form],
    },
    /// The call, or the form of it that reaches beyond the caller, needs a
    /// capability, which the sandbox lacks in every namespace (D9).
    NeedsCap {
        /// The capability.
        cap: &'static str,
        /// The kernel function that holds the check (Linux 7.2).
        check: &'static str,
        /// How `capability_gated_calls_fail` shows it.
        probe: Probe,
        /// The release (major, minor) that removed the syscall, which then
        /// answers ENOSYS.
        removed_in: Option<(u32, u32)>,
    },
    /// `sys_ni_syscall` in every release from 5.19 to 7.2.
    NotImplemented,
}

/// One gated form of a call: what the probe tries and what it must get.
#[derive(Debug)]
pub struct Form {
    /// The probe's name of the form (`cap:<name>:<form>`).
    pub form: &'static str,
    /// The errno the kernel returns for a caller without the capability.
    pub errno: i32,
    /// The kernel function that returns it (Linux 7.2).
    pub returned_by: &'static str,
}

/// How a `NeedsCap` entry is shown on a host.
#[derive(Debug)]
pub enum Probe {
    /// The gated forms the probe calls.
    Forms(&'static [Form]),
    /// No call can reach the check inside the sandbox; the reason is
    /// printed outside libtest's capture on every run.
    Unproven(&'static str),
}

/// The argument form each row denies, written out from ADR-007 D2 rather
/// than taken from `seccomp::table`: the six arguments of a call that the
/// row must refuse. `None` for the two rows no census entry lists, which
/// match on the architecture or the number alone.
pub fn denied_form(row: Row) -> Option<[u64; 6]> {
    let mut args = [0u64; 6];
    match row {
        Row::ForeignArch | Row::Ceiling => return None,
        // Every form: zeroed arguments.
        Row::IoUring | Row::BpfUserfaultfdPerf | Row::Keyring | Row::Syslog | Row::Clone3 => {}
        // CLONE_NEWUSER in arg 0.
        Row::NewUserNamespace => args[0] = 0x1000_0000,
        // AF_VSOCK.
        Row::SocketFamily => args[0] = 40,
        // AF_INET, SOCK_PACKET.
        Row::SockPacket => {
            args[0] = 2;
            args[1] = 10;
        }
        // AF_NETLINK, NETLINK_NETFILTER.
        Row::NetlinkProtocol => {
            args[0] = 16;
            args[2] = 12;
        }
        // AF_INET, SOCK_STREAM, SCTP.
        Row::InetProtocol => {
            args[0] = 2;
            args[1] = 1;
            args[2] = 132;
        }
        // socketpair(AF_INET).
        Row::Socketpair => args[0] = 2,
        // MAP_HUGETLB in arg 3, SHM_HUGETLB in arg 2, MFD_HUGETLB in arg 1.
        Row::HugetlbMmap => args[3] = 0x4_0000,
        Row::HugetlbShmget => args[2] = 0o4000,
        Row::HugetlbMemfd => args[1] = 0x4,
        // TIOCSETD, SIOCGIFBR.
        Row::LineDiscipline => args[1] = 0x5423,
        Row::ModuleIoctl => args[1] = 0x8940,
        // SOL_TLS with TLS_TX.
        Row::Ktls => {
            args[1] = 282;
            args[2] = 1;
        }
        // IPPROTO_TCP with TCP_AO_ADD_KEY.
        Row::TcpSignature => {
            args[1] = 6;
            args[2] = 38;
        }
        // IPPROTO_IP with BPFILTER_IPT_SO_SET_REPLACE.
        Row::Bpfilter => {
            args[1] = 0;
            args[2] = 64;
        }
        // FS_IOC_ADD_ENCRYPTION_KEY.
        Row::FsCryptoIoctl => args[1] = 0xc050_6617,
    }
    Some(args)
}

/// A parsed extract: its header lines (without the newline) and its
/// records in file order.
#[derive(Debug, PartialEq, Eq)]
pub struct Extract {
    /// The `#` lines at the top.
    pub header: Vec<String>,
    /// `(nr, name)` per record.
    pub records: Vec<(u32, String)>,
}

impl Extract {
    /// The number of `name`, if the extract has it.
    pub fn number(&self, name: &str) -> Option<u32> {
        self.records
            .iter()
            .find(|(_, n)| n == name)
            .map(|(nr, _)| *nr)
    }

    /// The names, as a set.
    pub fn names(&self) -> BTreeSet<&str> {
        self.records.iter().map(|(_, n)| n.as_str()).collect()
    }
}

/// Parses an extract. Strict: every line ends in `\n` (no `\r`), the
/// header is a run of lines that start with `#` at the top, and every
/// other line is `<nr> <name>` with one space, a decimal number without a
/// sign or leading zero, a name of ASCII lower-case letters, digits and
/// `_`, numbers rising, no name twice. Errors name the line.
pub fn parse(text: &str) -> Result<Extract, String> {
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| "the file does not end in a newline".to_string())?;
    let mut header = Vec::new();
    let mut records: Vec<(u32, String)> = Vec::new();
    let mut names = BTreeSet::new();
    for (i, line) in body.split('\n').enumerate() {
        let at = i + 1;
        if line.contains('\r') {
            return Err(format!("line {at}: carriage return"));
        }
        if line.starts_with('#') {
            if !records.is_empty() {
                return Err(format!("line {at}: a comment after the first record"));
            }
            header.push(line.to_string());
            continue;
        }
        let (nr, name) = line
            .split_once(' ')
            .ok_or_else(|| format!("line {at}: not \"<nr> <name>\": {line:?}"))?;
        let digits = !nr.is_empty() && nr.bytes().all(|b| b.is_ascii_digit());
        if !digits || (nr.len() > 1 && nr.starts_with('0')) {
            return Err(format!("line {at}: bad number {nr:?}"));
        }
        let nr: u32 = nr
            .parse()
            .map_err(|_| format!("line {at}: number {nr:?} out of range"))?;
        let name_ok = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !name_ok {
            return Err(format!("line {at}: bad name {name:?}"));
        }
        if let Some((last, _)) = records.last()
            && nr <= *last
        {
            return Err(format!("line {at}: number {nr} after {last}"));
        }
        if !names.insert(name.to_string()) {
            return Err(format!("line {at}: name {name} twice"));
        }
        records.push((nr, name.to_string()));
    }
    Ok(Extract { header, records })
}

/// Renders an extract as [`parse`] reads it.
pub fn render(extract: &Extract) -> String {
    let mut out = String::new();
    for line in &extract.header {
        out.push_str(line);
        out.push('\n');
    }
    for (nr, name) in &extract.records {
        out.push_str(&format!("{nr} {name}\n"));
    }
    out
}

/// The extract of `arch`, parsed.
pub fn extract(arch: Arch) -> Extract {
    let text = match arch {
        Arch::X86_64 => SYSCALLS_X86_64,
        Arch::Aarch64 => SYSCALLS_AARCH64,
    };
    parse(text).unwrap_or_else(|e| panic!("syscalls-{}.txt: {e}", arch.name()))
}

/// The census entry of `name`.
pub fn entry(name: &str) -> Option<&'static Entry> {
    CENSUS.iter().find(|e| e.name == name)
}

/// Every gated form the census names, by syscall: the forms of `NeedsCap`
/// entries and the extra forms of `Row` entries.
pub fn gated_forms() -> Vec<(&'static str, &'static Form)> {
    let mut out = Vec::new();
    for e in CENSUS {
        let forms: &[Form] = match &e.verdict {
            Verdict::NeedsCap {
                probe: Probe::Forms(forms),
                ..
            } => forms,
            Verdict::Row { extra, .. } => extra,
            _ => &[],
        };
        out.extend(forms.iter().map(|f| (e.name, f)));
    }
    out
}

#[test]
fn census_covers_every_syscall() {
    let x86 = extract(Arch::X86_64);
    let arm = extract(Arch::Aarch64);
    let names: Vec<&str> = CENSUS.iter().map(|e| e.name).collect();
    let set: BTreeSet<&str> = names.iter().copied().collect();
    // A repeated entry fails here, not only a missing or invented one.
    assert_eq!(names.len(), set.len(), "a census name is listed twice");
    assert_eq!(set, x86.names(), "census names against syscalls-x86_64.txt");
    assert_eq!(set.len(), 385);
    assert_eq!(x86.records.len(), 385);
    assert_eq!(arm.records.len(), 327);
    let missing: Vec<&str> = arm.names().difference(&set).copied().collect();
    assert!(
        missing.is_empty(),
        "aarch64 names outside the census: {missing:?}"
    );
    // The census is in x86_64 number order.
    let order: Vec<&str> = x86.records.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(names, order, "census order against syscalls-x86_64.txt");
    // The ceiling is the highest number of both tables.
    let max = |e: &Extract| e.records.last().map(|(nr, _)| *nr).expect("records");
    assert_eq!(CEILING, 471);
    assert_eq!(max(&x86).max(max(&arm)), CEILING);
    assert_eq!(x86.records.first(), Some(&(0, "read".to_string())));
    assert_eq!(arm.number("read"), Some(63));
    assert_eq!(x86.number("rseq_slice_yield"), Some(471));
    assert_eq!(arm.number("rseq_slice_yield"), Some(471));
    // The verdict counts ADR-007 D2 records.
    let mut counts = BTreeMap::new();
    for e in CENSUS {
        let kind = match e.verdict {
            Verdict::Own => "own",
            Verdict::Row { .. } => "row",
            Verdict::NeedsCap { .. } => "needs-cap",
            Verdict::NotImplemented => "not-implemented",
        };
        *counts.entry(kind).or_insert(0usize) += 1;
    }
    assert_eq!(counts.get("own"), Some(&OWN), "{counts:?}");
    assert_eq!(counts.get("needs-cap"), Some(&NEEDS_CAP), "{counts:?}");
    assert_eq!(counts.get("row"), Some(&ROW), "{counts:?}");
    assert_eq!(
        counts.get("not-implemented"),
        Some(&NOT_IMPLEMENTED),
        "{counts:?}"
    );
    assert_eq!(OWN + NEEDS_CAP + ROW + NOT_IMPLEMENTED, 385);
    // Every entry gives a reason.
    for e in CENSUS {
        assert!(!e.reason.trim().is_empty(), "{}: no reason", e.name);
    }
}

#[test]
fn census_extract_format() {
    let good = "# header\n0 read\n1 write\n";
    assert_eq!(
        parse(good),
        Ok(Extract {
            header: vec!["# header".to_string()],
            records: vec![(0, "read".to_string()), (1, "write".to_string())],
        })
    );
    // Each bad form names the line it is on.
    for (bad, line) in [
        ("# h\n0\tread\n", 2),
        ("# h\n0  read\n", 2),
        ("# h\n0 read\r\n", 2),
        ("# h\n0 read \n", 2),
        ("# h\n0 read\n\n1 write\n", 3),
        ("# h\n00 read\n", 2),
        ("# h\n01 read\n", 2),
        ("# h\n+1 read\n", 2),
        ("# h\n\u{663} read\n", 2),
        ("# h\n0 r\u{435}ad\n", 2),
        ("# h\n0 re\u{200b}ad\n", 2),
        ("# h\n0 read\n0 write\n", 3),
        ("# h\n1 read\n0 write\n", 3),
        ("# h\n0 read\n1 read\n", 3),
        ("# h\n0 read\n# late\n", 3),
        ("# h\n0 Read\n", 2),
        ("# h\nread\n", 2),
    ] {
        let err = parse(bad).expect_err(bad);
        assert!(
            err.starts_with(&format!("line {line}:")),
            "{bad:?} gave {err:?}, expected line {line}"
        );
    }
    assert!(parse("# h\n0 read").is_err(), "no final newline");
}

#[test]
fn census_extracts_round_trip() {
    for (arch, text) in [
        (Arch::X86_64, SYSCALLS_X86_64),
        (Arch::Aarch64, SYSCALLS_AARCH64),
    ] {
        let parsed = extract(arch);
        assert!(!parsed.header.is_empty(), "{}: no header", arch.name());
        assert_eq!(render(&parsed), text, "{}", arch.name());
    }
}

#[test]
fn census_matches_policy() {
    for arch in Arch::ALL {
        let prog = program(arch);
        let audit = arch.audit_arch();
        let table = extract(arch);
        let mut listed = BTreeSet::new();
        for e in CENSUS {
            let Some(nr) = table.number(e.name) else {
                continue;
            };
            let call = |args: [u64; 6]| {
                run(
                    &prog,
                    &Data {
                        nr,
                        arch: audit,
                        args,
                    },
                )
            };
            match &e.verdict {
                Verdict::Row { rows, .. } => {
                    assert!(!rows.is_empty(), "{}: a Row entry without rows", e.name);
                    for &row in rows.iter() {
                        let form = denied_form(row)
                            .unwrap_or_else(|| panic!("{}: row {row:?} has no form", e.name));
                        assert_eq!(
                            call(form),
                            row.action(),
                            "{}: {} gives another answer than row {row:?}",
                            arch.name(),
                            e.name
                        );
                        listed.insert(row);
                    }
                }
                _ => {
                    assert_eq!(call([0; 6]), ALLOW, "{}: {}", arch.name(), e.name);
                    for row in Row::ALL {
                        if let Some(form) = denied_form(row) {
                            assert_eq!(
                                call(form),
                                ALLOW,
                                "{}: {} is not a Row entry, but the form of {row:?} is refused",
                                arch.name(),
                                e.name
                            );
                        }
                    }
                }
            }
        }
        // Every row a name can select is listed on each architecture.
        let unlisted: Vec<Row> = Row::ALL
            .into_iter()
            .filter(|r| denied_form(*r).is_some() && !listed.contains(r))
            .collect();
        assert!(
            unlisted.is_empty(),
            "{}: rows no entry lists: {unlisted:?}",
            arch.name()
        );
        assert_eq!(listed.len(), Row::ALL.len() - 2, "{}", arch.name());
    }
    assert_eq!(Row::ALL.len(), 22);
    // The program the interpreter runs is the one spawn installs.
    assert!(Policy::sandbox().program(Arch::NATIVE).is_ok());
}

#[test]
fn census_needs_cap_have_probes() {
    let mut seen = BTreeSet::new();
    for e in CENSUS {
        match &e.verdict {
            Verdict::NeedsCap {
                cap, check, probe, ..
            } => {
                assert!(cap.starts_with("CAP_"), "{}: {cap}", e.name);
                assert!(!check.is_empty(), "{}: no check", e.name);
                match probe {
                    Probe::Forms(forms) => assert!(!forms.is_empty(), "{}: no form", e.name),
                    Probe::Unproven(why) => assert!(!why.trim().is_empty(), "{}", e.name),
                }
            }
            Verdict::Row { .. } | Verdict::Own | Verdict::NotImplemented => {}
        }
    }
    for (name, form) in gated_forms() {
        assert!(!form.form.is_empty(), "{name}: a form without a name");
        assert!(form.errno > 0, "{name}:{}: errno {}", form.form, form.errno);
        assert!(!form.returned_by.is_empty(), "{name}:{}", form.form);
        assert!(
            seen.insert((name, form.form)),
            "{name}:{} is listed twice",
            form.form
        );
    }
    // The probe has exactly these forms: every probe names a census form,
    // and every census form has a probe.
    let probes: BTreeSet<(&str, &str)> = crate::support::gated::GATED_FORMS
        .iter()
        .map(|(name, form, _)| (*name, *form))
        .collect();
    assert_eq!(
        probes.len(),
        crate::support::gated::GATED_FORMS.len(),
        "a probe form is listed twice"
    );
    let missing: Vec<_> = seen.difference(&probes).collect();
    let extra: Vec<_> = probes.difference(&seen).collect();
    assert!(
        missing.is_empty(),
        "census forms without a probe: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "probe forms outside the census: {extra:?}"
    );
    // The four entries no probe can reach are the ones ADR-007 D2 names.
    let unproven: Vec<&str> = CENSUS
        .iter()
        .filter(|e| {
            matches!(
                e.verdict,
                Verdict::NeedsCap {
                    probe: Probe::Unproven(_),
                    ..
                }
            )
        })
        .map(|e| e.name)
        .collect();
    assert_eq!(
        unproven,
        ["quotactl", "migrate_pages", "fsconfig", "quotactl_fd"]
    );
}
