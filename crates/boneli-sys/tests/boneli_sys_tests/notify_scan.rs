//! The no-continue pin (ADR-043, D5): no file of boneli-sys names the
//! reply flag that lets a notified call run, the descriptor-injection
//! ioctl, its flags and struct, or the flag-setting ioctl, in code, a
//! comment or a string, after `libc::` or renamed with `use ... as`; the
//! ioctl that sends a reply and the reply struct appear only in
//! `src/seccomp/notify.rs`; the send ioctl's number appears only there and
//! the injection ioctl's number nowhere, in any base, hex case or with `_`
//! separators. Rust cannot build an identifier without a proc macro,
//! which rule `proc-macro` bans, so a name has to be written to be used.
//! A number computed in the crate (through `ioc()`, say) is left to
//! review, which every boneli-sys change gets.
//!
//! This file builds the names from pieces and the numbers from their
//! fields, so that it passes its own scan.

use std::path::{Path, PathBuf};

/// The one file allowed to name the reply.
const NOTIFY_RS: &str = "src/seccomp/notify.rs";

fn banned_names() -> Vec<String> {
    [
        ["SECCOMP_USER_NOTIF_FLAG_", "CONTINUE"],
        ["SECCOMP_IOCTL_NOTIF_", "ADDFD"],
        ["SECCOMP_ADDFD_FLAG_", "SEND"],
        ["SECCOMP_ADDFD_FLAG_", "SETFD"],
        ["seccomp_notif_", "addfd"],
        ["SECCOMP_IOCTL_NOTIF_", "SET_FLAGS"],
    ]
    .iter()
    .map(|p| p.concat())
    .collect()
}

fn reply_names() -> Vec<String> {
    [["SECCOMP_IOCTL_NOTIF_", "SEND"], ["seccomp_notif_", "resp"]]
        .iter()
        .map(|p| p.concat())
        .collect()
}

/// The send ioctl is `_IOWR('!', 1, <the 24-byte reply struct>)` and the
/// injection ioctl `_IOW('!', 3, <its 24-byte struct>)`, in the encoding of
/// `include/uapi/asm-generic/ioctl.h`.
const fn ioctl_number(dir: u128, nr: u128) -> u128 {
    (dir << 30) | (24 << 16) | (0x21 << 8) | nr
}
const SEND_NUMBER: u128 = ioctl_number(3, 1);
const ADDFD_NUMBER: u128 = ioctl_number(1, 3);

/// One hit of the scan.
#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    /// The file, relative to the crate.
    pub file: String,
    /// The 1-based line.
    pub line: usize,
    /// What was found.
    pub what: String,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The value of a numeric literal token: `_` removed, an optional
/// `0x`/`0o`/`0b` prefix in either case, an optional integer suffix.
fn literal_value(token: &[u8]) -> Option<u128> {
    let t: Vec<u8> = token
        .iter()
        .filter(|b| **b != b'_')
        .map(u8::to_ascii_lowercase)
        .collect();
    let (radix, digits) = match t.get(..2) {
        Some(b"0x") => (16, &t[2..]),
        Some(b"0o") => (8, &t[2..]),
        Some(b"0b") => (2, &t[2..]),
        _ => (10, &t[..]),
    };
    let end = digits
        .iter()
        .position(|b| !char::from(*b).is_digit(radix))
        .unwrap_or(digits.len());
    let suffix = &digits[end..];
    let suffixes: [&[u8]; 13] = [
        b"", b"u8", b"u16", b"u32", b"u64", b"u128", b"usize", b"i8", b"i16", b"i32", b"i64",
        b"i128", b"isize",
    ];
    if end == 0 || !suffixes.contains(&suffix) {
        return None;
    }
    u128::from_str_radix(std::str::from_utf8(&digits[..end]).ok()?, radix).ok()
}

/// Scans one file's bytes; `file` is its path relative to the crate.
pub fn scan(file: &str, bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let in_notify = file == NOTIFY_RS;
    let line_of = |at: usize| bytes[..at].iter().filter(|b| **b == b'\n').count() + 1;
    let mut find = |needle: &str, what: &str| {
        let n = needle.as_bytes();
        let starts = bytes.windows(n.len()).enumerate().filter(|(_, w)| *w == n);
        for (at, _) in starts {
            out.push(Finding {
                file: file.to_string(),
                line: line_of(at),
                what: format!("{what} {needle}"),
            });
        }
    };
    for name in banned_names() {
        find(&name, "banned name");
    }
    if !in_notify {
        for name in reply_names() {
            find(&name, "reply name outside notify.rs");
        }
    }
    let mut i = 0usize;
    while i < bytes.len() {
        let starts = bytes[i].is_ascii_digit() && (i == 0 || !is_ident(bytes[i - 1]));
        if !starts {
            i += 1;
            continue;
        }
        let end = bytes[i..]
            .iter()
            .position(|b| !is_ident(*b))
            .map_or(bytes.len(), |n| i + n);
        let value = literal_value(&bytes[i..end]);
        if value == Some(ADDFD_NUMBER) || (value == Some(SEND_NUMBER) && !in_notify) {
            out.push(Finding {
                file: file.to_string(),
                line: line_of(i),
                what: format!("ioctl number {}", String::from_utf8_lossy(&bytes[i..end])),
            });
        }
        i = end;
    }
    out
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("a directory entry").path())
        .collect();
    entries.sort();
    for p in entries {
        let meta = std::fs::symlink_metadata(&p).expect("metadata");
        if meta.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn no_continue_reply_in_boneli_sys() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut all = Vec::new();
    for sub in ["src", "tests"] {
        files(&root.join(sub), &mut all);
    }
    let mut findings = Vec::new();
    let mut rel_names = Vec::new();
    for path in &all {
        let rel = path
            .strip_prefix(root)
            .expect("under the crate")
            .to_string_lossy()
            .into_owned();
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{rel}: {e}"));
        findings.extend(scan(&rel, &bytes));
        rel_names.push(rel);
    }
    // Not vacuous: the scan saw the crate, notify.rs and this file.
    for must in [
        NOTIFY_RS,
        "src/lib.rs",
        "tests/boneli_sys_tests/notify_scan.rs",
    ] {
        assert!(
            rel_names.iter().any(|r| r == must),
            "{must} was not scanned"
        );
    }
    assert!(rel_names.len() > 30, "only {} files", rel_names.len());
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn continue_scan_catches_every_form() {
    // The uapi values, written in pieces.
    assert_eq!(format!("{SEND_NUMBER:#x}"), ["0xc018", "2101"].concat());
    assert_eq!(format!("{ADDFD_NUMBER:#x}"), ["0x4018", "2103"].concat());
    let banned = banned_names();
    let reply = reply_names();
    let other = "src/spawn.rs";
    let hits = |file: &str, text: &str| scan(file, text.as_bytes()).len();
    for name in &banned {
        for form in [
            format!("let f = libc::{name};"),
            format!("use libc::{name} as Allowed;"),
            format!("use libc::{{{name}, ioctl}};"),
            format!("// reply with {name} here"),
            format!("let s = \"{name}\";"),
            format!("x{name}y"),
        ] {
            assert_eq!(hits(other, &form), 1, "{form}");
            assert_eq!(hits(NOTIFY_RS, &form), 1, "in notify.rs too: {form}");
        }
    }
    for name in &reply {
        let form = format!("let r: libc::{name};");
        assert_eq!(hits(other, &form), 1, "{form}");
        assert_eq!(hits(NOTIFY_RS, &form), 0, "allowed in notify.rs: {form}");
    }
    // The numbers in every spelling.
    let spell = |v: u128| {
        let hex = format!("{v:x}");
        let (hi, lo) = hex.split_at(4);
        vec![
            format!("0x{hex}"),
            format!("0x{}", hex.to_uppercase()),
            format!("0X{hex}"),
            format!("0x{hi}_{lo}"),
            format!("0x{hex}u32"),
            format!("0x{hex}_u64"),
            format!("{v}"),
            format!("{}_{}", v / 1_000_000, format_args!("{:06}", v % 1_000_000)),
            format!("{v}u32"),
            format!("0o{v:o}"),
            format!("0b{v:b}"),
        ]
    };
    for s in spell(ADDFD_NUMBER) {
        for file in [other, NOTIFY_RS] {
            assert_eq!(
                hits(file, &format!("ioctl(fd, {s} as _, p)")),
                1,
                "{file}: {s}"
            );
            assert_eq!(hits(file, &format!("// {s}")), 1, "{file}: {s}");
        }
    }
    for s in spell(SEND_NUMBER) {
        assert_eq!(hits(other, &format!("ioctl(fd, {s}, p)")), 1, "{s}");
        assert_eq!(hits(NOTIFY_RS, &format!("ioctl(fd, {s}, p)")), 0, "{s}");
    }
    // Neighbours and other ioctls pass; so do identifiers ending in digits.
    for clean in [
        format!("0x{:x}", SEND_NUMBER + 1),
        format!("{}", ADDFD_NUMBER - 1),
        format!("1{ADDFD_NUMBER}"),
        format!("x{ADDFD_NUMBER}"),
        "libc::SECCOMP_IOCTL_NOTIF_RECV".to_string(),
        "libc::seccomp_notif_sizes".to_string(),
        "1.5e10".to_string(),
    ] {
        assert_eq!(hits(other, &clean), 0, "{clean}");
    }
    // Line numbers point at the hit.
    let text = format!("a\nb\n// {}\n", banned[0]);
    assert_eq!(scan(other, text.as_bytes())[0].line, 3);
}
