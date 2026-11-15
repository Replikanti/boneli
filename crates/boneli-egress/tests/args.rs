//! Command-line arguments (ADR-006, D1): `--flag value` only, one socket,
//! the allowlist entries and NAT64 prefixes as given.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use boneli_egress::address::Nat64Prefix;
use boneli_egress::{Args, UsageError};

fn parse(args: &[&str]) -> Result<Args, UsageError> {
    Args::parse(args.iter().map(OsString::from))
}

#[test]
fn args_accept_the_documented_form() {
    let args = parse(&[
        "--socket",
        "~/run/egress.sock",
        "--allow",
        "registry.npmjs.org:443",
        "--nat64-prefix",
        "2a00:1:2::/96",
        "--allow",
        "pypi.org:443",
        "--nat64-prefix",
        "64:ff9b::/96",
    ])
    .expect("valid");
    // The path is taken as given, with no `~` expansion.
    assert_eq!(args.socket, PathBuf::from("~/run/egress.sock"));
    assert_eq!(args.allow, ["registry.npmjs.org:443", "pypi.org:443"]);
    let expected: Vec<Nat64Prefix> = ["2a00:1:2::/96", "64:ff9b::/96"]
        .iter()
        .map(|p| Nat64Prefix::parse(p).expect("prefix"))
        .collect();
    assert_eq!(args.nat64.iter().copied().collect::<Vec<_>>(), {
        let mut sorted = expected;
        sorted.sort();
        sorted
    });
}

#[test]
fn args_allow_list_may_be_empty_here() {
    // The allowlist itself refuses an empty list (exit 2 in the binary).
    let args = parse(&["--socket", "s"]).expect("valid");
    assert!(args.allow.is_empty());
    assert!(args.nat64.is_empty());
}

#[test]
fn args_socket_path_may_be_any_bytes() {
    let path = OsString::from_vec(vec![b's', 0xff, b'k']);
    let args = Args::parse([OsString::from("--socket"), path.clone()]).expect("valid");
    assert_eq!(args.socket.as_os_str(), path);
}

#[test]
fn args_usage_errors() {
    let cases: &[(&[&str], UsageError)] = &[
        (&[], UsageError::MissingSocket),
        (&["--allow", "a.example:443"], UsageError::MissingSocket),
        (
            &["--socket", "a", "--socket", "b"],
            UsageError::RepeatedSocket,
        ),
        (&["--socket"], UsageError::MissingValue { flag: "--socket" }),
        (
            &["--socket", "s", "--allow"],
            UsageError::MissingValue { flag: "--allow" },
        ),
        (
            &["--socket", "s", "--nat64-prefix"],
            UsageError::MissingValue {
                flag: "--nat64-prefix",
            },
        ),
        (&["--socket=s"], UsageError::EqualsForm),
        (
            &["--socket", "s", "--allow=a.example:443"],
            UsageError::EqualsForm,
        ),
        (
            &["--socket", "s", "--frobnicate"],
            UsageError::UnknownArgument,
        ),
        (&["--socket", "s", "-a", "x"], UsageError::UnknownArgument),
        (&["--socket", "s", "stray"], UsageError::UnknownArgument),
        (
            &["--socket", "s", "--nat64-prefix", "2a00:1:2::/95"],
            UsageError::InvalidNat64Prefix,
        ),
        (
            &["--socket", "s", "--nat64-prefix", "2a00:1:2:0::/96"],
            UsageError::InvalidNat64Prefix,
        ),
        (
            &[
                "--socket",
                "s",
                "--nat64-prefix",
                "2a00:1:2::/96",
                "--nat64-prefix",
                "2a00:1:2::/96",
            ],
            UsageError::RepeatedNat64Prefix,
        ),
    ];
    for (args, expected) in cases {
        assert_eq!(parse(args).err(), Some(*expected), "{args:?}");
    }
}

#[test]
fn args_non_utf8_values_are_usage_errors() {
    let bad = OsString::from_vec(vec![b'a', 0xff, b':', b'4', b'4', b'3']);
    for flag in ["--allow", "--nat64-prefix"] {
        let args = [
            OsString::from("--socket"),
            OsString::from("s"),
            OsString::from(flag),
            bad.clone(),
        ];
        let expected = if flag == "--allow" {
            UsageError::NotUtf8 { flag: "--allow" }
        } else {
            UsageError::NotUtf8 {
                flag: "--nat64-prefix",
            }
        };
        assert_eq!(Args::parse(args).err(), Some(expected));
    }
    // A flag that is not UTF-8 is unknown.
    let args = [OsString::from_vec(vec![b'-', b'-', 0xff])];
    assert_eq!(Args::parse(args).err(), Some(UsageError::UnknownArgument));
}

#[test]
fn usage_errors_never_echo_the_value() {
    let err = parse(&["--socket", "s", "--nat64-prefix", "secret-value"]).expect_err("bad");
    assert!(!err.to_string().contains("secret-value"), "{err}");
}
