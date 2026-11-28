//! The no-continue pin (ADR-043, D5): no file of boneli-sys names the
//! reply flag that lets a notified call run, the descriptor-injection
//! ioctl, its flags and struct, or the flag-setting ioctl, in code, a
//! comment or a string, after `libc::` or renamed with `use ... as`; the
//! ioctl that sends a reply and the reply struct appear only in
//! `src/seccomp/notify.rs`. Number literals are folded to the 32 bits the
//! kernel reads (`cmd` is an `unsigned int`), in any base, hex case, with
//! `_` separators and a suffix, and also negated and complemented when a
//! `-` or `!` comes before them. The send ioctl's number may then appear
//! only in notify.rs (the kernel matches it exactly), and no literal
//! anywhere may carry the injection ioctl's type and number bits
//! (`'!'`, 3), whatever its direction and size bits: the kernel
//! dispatches that ioctl on `EA_IOCTL(cmd)`, which masks them
//! (`seccomp_notify_ioctl`, `kernel/seccomp.c:1726` in 5.19, `:1846` in
//! 7.2). Rust cannot build an identifier without a proc macro,
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
const fn ioctl_number(dir: u32, nr: u32) -> u32 {
    (dir << 30) | (24 << 16) | (0x21 << 8) | nr
}
const SEND_NUMBER: u32 = ioctl_number(3, 1);
const ADDFD_NUMBER: u32 = ioctl_number(1, 3);

/// The bits `EA_IOCTL` keeps: type and number. The direction (bits 30 and
/// 31) and the size (bits 16 to 29) are masked before the injection
/// ioctl's `case`.
const TYPE_AND_NR: u32 = 0xffff;

/// Whether a 32-bit request reaches the injection ioctl, or the send
/// ioctl outside notify.rs.
fn dangerous(cmd: u32, in_notify: bool) -> Option<&'static str> {
    if cmd & TYPE_AND_NR == ADDFD_NUMBER & TYPE_AND_NR {
        Some("injection ioctl")
    } else if cmd == SEND_NUMBER && !in_notify {
        Some("send ioctl outside notify.rs")
    } else {
        None
    }
}

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

/// The value of a numeric literal token modulo 2^32, the part of an ioctl
/// request the kernel reads: `_` removed, an optional `0x`/`0o`/`0b`
/// prefix in either case, an optional integer suffix. Any length folds,
/// so a 64-bit or longer literal gives its low word.
fn literal_value(token: &[u8]) -> Option<u32> {
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
    let mut v: u32 = 0;
    for b in &digits[..end] {
        let d = char::from(*b).to_digit(radix)?;
        v = v.wrapping_mul(radix).wrapping_add(d);
    }
    Some(v)
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
        if let Some(v) = literal_value(&bytes[i..end]) {
            // A `-` or `!` before the literal (spaces between allowed):
            // check the negated or complemented value too.
            let before = bytes[..i]
                .iter()
                .rev()
                .find(|b| !b.is_ascii_whitespace())
                .copied();
            let forms = match before {
                Some(b'-') => [v, v.wrapping_neg()],
                Some(b'!') => [v, !v],
                _ => [v, v],
            };
            if let Some(what) = forms.iter().find_map(|cmd| dangerous(*cmd, in_notify)) {
                out.push(Finding {
                    file: file.to_string(),
                    line: line_of(i),
                    what: format!("{what}: {}", String::from_utf8_lossy(&bytes[i..end])),
                });
            }
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
    let spell = |v: u64| {
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
    // Every request the kernel dispatches to the injection ioctl: any
    // direction, any size (EA_IOCTL masks both), a 64-bit literal whose
    // low word it is (`cmd` is an unsigned int), and the negated and
    // complemented forms. The reviewer's C probe on 7.2.10 dispatched each
    // of the direction, size and 64-bit forms.
    let addfd = u64::from(ADDFD_NUMBER);
    let with_dir = |v: u64, dir: u64| (v & !(3 << 30)) | (dir << 30);
    let with_size = |v: u64, size: u64| (v & !(0x3fff << 16)) | (size << 16);
    let mut addfd_forms = Vec::new();
    for v in [
        with_dir(addfd, 0),
        with_dir(addfd, 1),
        with_dir(addfd, 2),
        with_dir(addfd, 3),
        with_size(addfd, 32),
        with_size(addfd, 0),
        (0xdead_beef << 32) | addfd,
        (1 << 32) | with_dir(addfd, 3),
    ] {
        addfd_forms.extend(spell(v));
    }
    let neg = ADDFD_NUMBER.wrapping_neg();
    let not = !ADDFD_NUMBER;
    addfd_forms.extend([
        format!("-{neg}"),
        format!("- {neg}"),
        format!("-{neg:#x}"),
        format!("!{not:#x}"),
        format!("! {not}"),
    ]);
    for s in &addfd_forms {
        for file in [other, NOTIFY_RS] {
            let call = format!("ioctl(fd, {s} as _, p)");
            assert_eq!(hits(file, &call), 1, "{file}: {call}");
            assert_eq!(hits(file, &format!("// {s}")), 1, "{file}: {s}");
        }
    }
    // The send ioctl, which the kernel matches exactly on its low word:
    // the number, a 64-bit literal with that low word, and the negated
    // and complemented forms; only notify.rs may hold it.
    let send = u64::from(SEND_NUMBER);
    let mut send_forms = Vec::new();
    for v in [send, (1 << 32) | send, (0xffff_ffff << 32) | send] {
        send_forms.extend(spell(v));
    }
    let neg = SEND_NUMBER.wrapping_neg();
    let not = !SEND_NUMBER;
    send_forms.extend([format!("-{neg}"), format!("- {neg}"), format!("!{not:#x}")]);
    for s in &send_forms {
        let call = format!("ioctl(fd, {s}, p)");
        assert_eq!(hits(other, &call), 1, "{call}");
        assert_eq!(hits(NOTIFY_RS, &call), 0, "{call}");
    }
    // Neighbours and other ioctls pass: the send ioctl with another size
    // (EINVAL in the probe), the injection ioctl's type with another
    // number, the send number with the injection ioctl's direction (both
    // EINVAL), and identifiers ending in digits.
    for clean in [
        format!("{:#x}", with_size(send, 32)),
        format!("{:#x}", addfd + 2),
        format!("{:#x}", addfd - 2),
        format!("0x{:x}", send + 1),
        format!("{}", addfd - 1),
        format!("-{}", addfd - 1),
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
