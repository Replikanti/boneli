//! The host-setup block in `CLAUDE.md`, the one source CI and users run to
//! prepare a host (ADR-007, D5). Pure: the block runs against a fake
//! `sudo` that records its arguments and input and executes nothing.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::support::TempDir;

const BEGIN: &str = "<!-- host-setup:begin -->";
const END: &str = "<!-- host-setup:end -->";

fn claude_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../CLAUDE.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The lines inside the one ```` ```sh ```` fence between the markers, as
/// the workflow's awk extracts them.
fn block(doc: &str) -> String {
    let lines: Vec<&str> = doc.lines().collect();
    let begins: Vec<usize> = (0..lines.len()).filter(|&i| lines[i] == BEGIN).collect();
    let ends: Vec<usize> = (0..lines.len()).filter(|&i| lines[i] == END).collect();
    assert_eq!(begins.len(), 1, "exactly one {BEGIN} line in CLAUDE.md");
    assert_eq!(ends.len(), 1, "exactly one {END} line in CLAUDE.md");
    let inner = &lines[begins[0] + 1..ends[0].max(begins[0] + 1)];
    assert!(begins[0] < ends[0], "{BEGIN} comes before {END}");
    let opens: Vec<usize> = (0..inner.len()).filter(|&i| inner[i] == "```sh").collect();
    let fences: Vec<usize> = (0..inner.len())
        .filter(|&i| inner[i].starts_with("```"))
        .collect();
    assert_eq!(
        opens.len(),
        1,
        "exactly one ```sh fence between the markers"
    );
    assert_eq!(
        fences.len(),
        2,
        "one fence opens and one closes between the markers"
    );
    assert_eq!(fences[0], opens[0], "the ```sh fence opens first");
    assert_eq!(inner[fences[1]], "```", "a bare ``` closes the fence");
    let body = &inner[fences[0] + 1..fences[1]];
    assert!(
        body.iter().any(|l| !l.trim().is_empty()),
        "the block is not empty"
    );
    let mut text = body.join("\n");
    text.push('\n');
    text
}

#[test]
fn block_is_unique() {
    let text = block(&claude_md());
    let dir = TempDir::new("host-setup-syntax");
    let file = dir.path().join("block.sh");
    std::fs::write(&file, &text).expect("write the block");
    let out = Command::new("sh")
        .arg("-n")
        .arg(&file)
        .output()
        .expect("run sh -n");
    assert!(
        out.status.success(),
        "sh -n rejects the block: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// One run of the block against the fake sudo.
struct Run {
    ok: bool,
    stderr: String,
    /// Each sudo call: its arguments and its standard input.
    calls: Vec<(Vec<String>, String)>,
}

struct Harness {
    dir: TempDir,
    script: PathBuf,
    fakebin: PathBuf,
}

const FAKE_SUDO: &str = r#"#!/bin/sh
set -eu
c=$(cat "$FAKE_SUDO_DIR/count" 2>/dev/null || echo 0)
c=$((c + 1))
echo "$c" > "$FAKE_SUDO_DIR/count"
for a in "$@"; do printf '%s\n' "$a"; done > "$FAKE_SUDO_DIR/$c.argv"
cat > "$FAKE_SUDO_DIR/$c.stdin"
"#;

impl Harness {
    fn new() -> Harness {
        let dir = TempDir::new("host-setup");
        let script = dir.path().join("block.sh");
        std::fs::write(&script, block(&claude_md())).expect("write the block");
        let fakebin = dir.path().join("fakebin");
        std::fs::create_dir(&fakebin).expect("mkdir fakebin");
        let sudo = fakebin.join("sudo");
        std::fs::write(&sudo, FAKE_SUDO).expect("write the fake sudo");
        std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755))
            .expect("chmod the fake sudo");
        Harness {
            dir,
            script,
            fakebin,
        }
    }

    fn base(&self) -> &Path {
        self.dir.path()
    }

    /// Runs the block with `TARGET_DIR` set to `target` (unset for None),
    /// from the harness directory.
    fn run(&self, target: Option<&OsStr>) -> Run {
        let log = TempDir::new("host-setup-log");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut full = OsString::from(&self.fakebin);
        full.push(":");
        full.push(path);
        let mut cmd = Command::new("sh");
        cmd.arg("-eu")
            .arg(&self.script)
            .current_dir(self.base())
            .stdin(Stdio::null())
            .env("PATH", full)
            .env("APPARMOR_USERNS", "1")
            .env("FAKE_SUDO_DIR", log.path())
            .env_remove("TARGET_DIR")
            .env_remove("ENABLE_LINGER")
            .env_remove("RUN_USER");
        if let Some(t) = target {
            cmd.env("TARGET_DIR", t);
        }
        let out = cmd.output().expect("run the block");
        let mut calls = Vec::new();
        for n in 1.. {
            let argv = log.path().join(format!("{n}.argv"));
            if !argv.exists() {
                break;
            }
            let args = std::fs::read_to_string(&argv)
                .expect("read argv")
                .lines()
                .map(String::from)
                .collect();
            let stdin =
                std::fs::read_to_string(log.path().join(format!("{n}.stdin"))).expect("read stdin");
            calls.push((args, stdin));
        }
        Run {
            ok: out.status.success(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            calls,
        }
    }
}

fn golden_profile(target: &Path) -> String {
    format!(
        "abi <abi/4.0>,\ninclude <tunables/global>\nprofile boneli-sys-tests {}/*/deps/boneli_sys{{,_tests}}-[0-9a-f]* flags=(unconfined) {{\n  userns,\n}}\n",
        target.display()
    )
}

fn assert_accepted(run: &Run, canonical: &Path, case: &str) {
    assert!(run.ok, "{case}: the block failed: {}", run.stderr);
    let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let want = vec![
        (
            argv(&["tee", "/etc/apparmor.d/boneli-sys-tests"]),
            golden_profile(canonical),
        ),
        (
            argv(&["apparmor_parser", "-r", "/etc/apparmor.d/boneli-sys-tests"]),
            String::new(),
        ),
        (
            argv(&["mkdir", "-p", "/etc/systemd/system/user@.service.d"]),
            String::new(),
        ),
        (
            argv(&[
                "tee",
                "/etc/systemd/system/user@.service.d/boneli-delegate.conf",
            ]),
            "[Service]\nDelegate=cpu io memory pids\n".to_string(),
        ),
        (argv(&["systemctl", "daemon-reload"]), String::new()),
    ];
    assert_eq!(run.calls, want, "{case}: sudo calls");
}

#[test]
fn resolves_and_rejects_target_dirs() {
    let h = Harness::new();
    let base = h.base().canonicalize().expect("canonical harness dir");
    let real = base.join("real").join("target");
    std::fs::create_dir_all(&real).expect("mkdir real/target");

    // A relative path renders the canonical absolute one.
    let run = h.run(Some(OsStr::new("real/target")));
    assert_accepted(&run, &real, "relative TARGET_DIR");

    // So does a symlink: AppArmor matches the resolved exec path.
    std::os::unix::fs::symlink(&real, base.join("link")).expect("symlink");
    let run = h.run(Some(base.join("link").as_os_str()));
    assert_accepted(&run, &real, "symlinked TARGET_DIR");

    // Rejected before any sudo call.
    let mut rejected: Vec<(String, Option<OsString>)> = vec![
        ("unset".into(), None),
        ("empty".into(), Some(OsString::new())),
        (
            "nonexistent".into(),
            Some(base.join("missing").into_os_string()),
        ),
        ("/".into(), Some(OsString::from("/"))),
    ];
    // Each exists, so the character check, not realpath, rejects it.
    let names: &[(&str, &[u8])] = &[
        ("space", b"a b"),
        ("star", b"a*b"),
        ("brace", b"a{b"),
        ("quote", b"a\"b"),
        ("newline", b"a\nb"),
        ("trailing newline", b"t\n"),
        ("e acute", "caf\u{e9}".as_bytes()),
        ("Cyrillic a", "t\u{430}rget".as_bytes()),
        ("zero-width space", "a\u{200b}b".as_bytes()),
    ];
    // The trailing-newline case: `t` also exists, so a check that only
    // looked at realpath's output (whose newline the shell strips) would
    // accept `t` instead of rejecting `t\n`.
    std::fs::create_dir_all(base.join("t")).expect("mkdir t");
    for (case, name) in names {
        let dir = base.join(OsStr::from_bytes(name));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("mkdir {case}: {e}"));
        rejected.push((case.to_string(), Some(dir.into_os_string())));
    }
    // A literal `~/target` (the shell does not expand a tilde in a
    // variable), relative to the working directory, where it exists.
    std::fs::create_dir_all(base.join("~/target")).expect("mkdir ~/target");
    rejected.push(("literal ~/target".into(), Some(OsString::from("~/target"))));
    // A clean name that resolves to an unclean path.
    std::os::unix::fs::symlink(base.join("a b"), base.join("clean-link")).expect("symlink");
    rejected.push((
        "clean symlink to a path with a space".into(),
        Some(base.join("clean-link").into_os_string()),
    ));

    for (case, target) in &rejected {
        let run = h.run(target.as_deref());
        assert!(!run.ok, "{case}: the block accepted it");
        assert!(
            run.calls.is_empty(),
            "{case}: sudo was called: {:?}",
            run.calls
        );
    }
}
