//! The privilege drop of the sandbox (ADR-007, D9), observed from inside:
//! no capability in any set, `no_new_privs`, the filter, locked
//! securebits.

use crate::support::{ids, run_probe};

const NONE: &str = "0000000000000000";
const CAP_SETS: [&str; 5] = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp filters"]
fn privileges_all_dropped() {
    for inside in [0, 999] {
        let p = run_probe("caps", ids(inside, inside), &[]);
        p.assert_ok();
        for set in CAP_SETS {
            assert_eq!(p.get(set), NONE, "inside id {inside}, {set}: {}", p.raw);
        }
        assert_eq!(p.get("NoNewPrivs"), "1", "inside id {inside}: {}", p.raw);
        // 2 is SECCOMP_MODE_FILTER; exactly the policy's filter.
        assert_eq!(p.get("Seccomp"), "2", "inside id {inside}: {}", p.raw);
        assert_eq!(
            p.get("Seccomp_filters"),
            "1",
            "inside id {inside}: {}",
            p.raw
        );
    }
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp filters"]
fn root_inside_gains_nothing_on_exec() {
    // Uid 0 inside execs a program: without SECBIT_NOROOT and the empty
    // bounding set, execve would give root every capability of the user
    // namespace again.
    let p = run_probe("caps", ids(0, 0), &[("BONELI_PROBE_EXEC", "1")]);
    p.assert_ok();
    assert_eq!(p.get("exec_status"), "Some(0)", "{}", p.raw);
    for set in CAP_SETS {
        assert_eq!(
            p.get(&format!("exec_{set}")),
            NONE,
            "after exec, {set}: {}",
            p.raw
        );
    }
    assert_eq!(p.get("exec_NoNewPrivs"), "1", "{}", p.raw);
    assert_eq!(p.get("exec_Seccomp"), "2", "{}", p.raw);
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp filters"]
fn securebits_locked() {
    for inside in [0, 999] {
        let p = run_probe("securebits", ids(inside, inside), &[]);
        p.assert_ok();
        assert_eq!(
            p.get("securebits"),
            boneli_sys::SECUREBITS.to_string(),
            "inside id {inside}: {}",
            p.raw
        );
        assert_eq!(p.get("securebits"), "239", "{}", p.raw);
        assert_eq!(p.get("set_errno"), libc::EPERM.to_string(), "{}", p.raw);
    }
}
