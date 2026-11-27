//! Landlock on a host process (ADR-007, D10): the probe restricts itself
//! with `boneli_sys::Ruleset` and tries each access. The shim (#9) applies
//! the same API to itself as PID 1; here it runs on the host so the rows
//! need no sandbox.

use crate::support::{TempDir, report, run_probe_host};

/// The cases: probe key, the ABI that brought the right, the result.
fn cases() -> [(&'static str, u32, i32); 14] {
    [
        ("read_r", 1, 0),
        ("write_r", 1, libc::EACCES),
        ("read_outside", 1, libc::EACCES),
        ("create_w", 1, 0),
        ("rename_w", 2, 0),
        // R lacks remove_file, which Landlock checks before refer: EACCES,
        // not EXDEV (measured on the dev host, ABI 10).
        ("rename_r_to_w", 2, libc::EACCES),
        ("truncate_r", 3, libc::EACCES),
        ("exec_outside", 1, libc::EACCES),
        ("tcp_allowed", 4, 0),
        ("tcp_denied", 4, libc::EACCES),
        ("kill_outside", 6, libc::EPERM),
        ("abstract_outside", 6, libc::EPERM),
        ("unix_outside", 9, libc::EACCES),
        ("unix_allowed", 9, 0),
    ]
}

#[test]
#[ignore = "host: Landlock ABI 2"]
fn landlock_rights_hold() {
    let dir = TempDir::new("landlock");
    let base = dir.path();
    for d in ["r", "w/a", "w/b", "outside", "u1", "u2"] {
        std::fs::create_dir_all(base.join(d)).expect("mkdir");
    }
    for f in ["r/f", "r/g", "w/a/x", "outside/f"] {
        std::fs::write(base.join(f), b"boneli").expect("write a fixture file");
    }
    let p = run_probe_host(
        "landlock",
        &[("BONELI_PROBE_DIR", base.to_str().expect("a UTF-8 temp dir"))],
    );
    p.assert_ok();
    let abi: u32 = p.get("abi").parse().expect("abi");
    assert!(abi >= 2, "{}", p.raw);
    let mut failures = Vec::new();
    for (key, since, want) in cases() {
        let got = p.get(key);
        if abi < since {
            if got != "n/a" {
                failures.push(format!("{key}: {got} on ABI {abi}, expected n/a"));
            }
            report(&format!(
                "landlock_rights_hold: {key} n/a (ABI {abi}, needs {since})"
            ));
        } else if got != want.to_string() {
            failures.push(format!("{key}: got {got}, want {want}"));
        }
    }
    assert!(failures.is_empty(), "{}\n{}", failures.join("\n"), p.raw);
    assert_eq!(p.get("no_new_privs"), "1", "{}", p.raw);
    // The denied writes left R as it was.
    assert_eq!(
        std::fs::read(base.join("r/f")).expect("read r/f"),
        b"boneli"
    );
    assert!(base.join("r/g").exists());
    assert!(base.join("w/b/x").exists() || abi < 2);
}
