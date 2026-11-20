//! The command line of the checker binary (ADR-015, D3).

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_boneli-arch-check");

fn run(args: &[&OsStr], cwd: &Path) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("the checker runs")
}

/// A scratch directory for one test, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("boneli arch cli {name} {}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A root whose policy has neither `[roles]` nor `[check]`, so the check
/// reports two policy-format lines without running cargo.
fn unusable_root(dir: &Path) {
    std::fs::create_dir_all(dir.join("tools")).expect("tools");
    std::fs::write(dir.join("tools/architecture.toml"), "").expect("policy");
    std::fs::write(dir.join("Cargo.toml"), "").expect("manifest");
}

const UNUSABLE: &str = "FAIL [policy-format] tools/architecture.toml: missing [roles]\n\
    FAIL [policy-format] tools/architecture.toml: missing [check]\n2 violation(s)\n";

#[test]
fn list_rules_prints_32_ids() {
    let out = run(&[OsStr::new("--list-rules")], Path::new("/"));
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).expect("ASCII");
    let ids: Vec<&str> = text.lines().collect();
    assert_eq!(ids.len(), 32);
    assert_eq!(ids[0], "tool-error");
    assert_eq!(ids[31], "policy-strict");
}

#[test]
fn usage_errors_exit_2_without_stdout() {
    for args in [
        &["--root"][..],
        &["--root", "a", "b"],
        &["--bogus"],
        &["--fixtures", "x"],
        &["--list-rules", "x"],
    ] {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        let out = run(&args, Path::new("/"));
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).starts_with("usage: "));
    }
}

#[test]
fn missing_root_is_tool_error() {
    let scratch = Scratch::new("missing");
    let out = run(
        &[OsStr::new("--root"), scratch.0.join("nope").as_os_str()],
        Path::new("/"),
    );
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(out.stdout).expect("ASCII"),
        "FAIL [tool-error] tools/architecture.toml: cannot read: No such file or directory\n1 violation(s)\n"
    );
}

/// A relative root resolves against the caller's working directory, a
/// symlinked root is canonicalized and paths are printed relative to it.
#[test]
fn root_forms_resolve_like_python() {
    let scratch = Scratch::new("forms");
    let root = scratch.0.join("a root");
    unusable_root(&root);
    std::os::unix::fs::symlink("a root", scratch.0.join("link")).expect("link");
    let cases: [(&OsStr, PathBuf); 4] = [
        (OsStr::new("a root"), scratch.0.clone()),
        (OsStr::new("link"), scratch.0.clone()),
        (OsStr::new("../../a root/./"), root.join("tools")),
        (root.as_os_str(), PathBuf::from("/")),
    ];
    for (arg, cwd) in &cases {
        let out = run(&[OsStr::new("--root"), arg], cwd);
        assert_eq!(out.status.code(), Some(1), "{arg:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), UNUSABLE, "{arg:?}");
    }
}

#[test]
fn non_utf8_root_is_accepted() {
    let scratch = Scratch::new("bytes");
    let root = scratch.0.join(OsStr::from_bytes(b"r\xff\xfe"));
    unusable_root(&root);
    let out = run(&[OsStr::new("--root"), root.as_os_str()], Path::new("/"));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&out.stdout), UNUSABLE);
}

/// A write error on stdout is exit 2, not a panic (101).
#[test]
fn stdout_write_error_exits_2() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full");
    let status = Command::new(BIN)
        .arg("--list-rules")
        .stdout(Stdio::from(full))
        .status()
        .expect("runs");
    assert_eq!(status.code(), Some(2));
    let scratch = Scratch::new("full");
    unusable_root(&scratch.0);
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full");
    let status = Command::new(BIN)
        .arg("--root")
        .arg(&scratch.0)
        .stdout(Stdio::from(full))
        .status()
        .expect("runs");
    assert_eq!(status.code(), Some(2));
}
