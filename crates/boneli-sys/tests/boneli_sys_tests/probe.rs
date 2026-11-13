//! `Features::probe` on the real host, and the narrowness of the AppArmor
//! profile of the host-setup block (ADR-007, D5).

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use boneli_sys::{Features, MissingId};

use crate::support::{self, Output, TempDir, parse_probe, report};

/// The ids the host is expected to lack, from `BONELI_SYS_EXPECT_MISSING`.
fn expected_missing() -> BTreeSet<MissingId> {
    let raw = std::env::var("BONELI_SYS_EXPECT_MISSING").unwrap_or_default();
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            MissingId::from_name(s)
                .unwrap_or_else(|| panic!("BONELI_SYS_EXPECT_MISSING names an unknown id {s:?}"))
        })
        .collect()
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, Linux 5.19"]
fn reports_expected_missing() {
    let want = expected_missing();
    let got: BTreeSet<MissingId> = match Features::probe() {
        Ok(()) => BTreeSet::new(),
        Err(missing) => {
            for m in &missing {
                report(&format!("probe: missing {}: {m}", m.id().as_str()));
            }
            missing.iter().map(|m| m.id()).collect()
        }
    };
    // Unset or empty: the host must have everything. Set: exactly that set,
    // so an extra id and a missing one both fail.
    assert_eq!(
        got, want,
        "Features::probe reported {got:?}, BONELI_SYS_EXPECT_MISSING says {want:?}"
    );
}

#[test]
#[ignore = "host: user namespaces, AppArmor where it restricts them"]
fn apparmor_profile_is_narrow() {
    let sysctl =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").ok();
    if sysctl.as_deref().map(str::trim) != Some("1") {
        report(
            "apparmor_profile_is_narrow: n/a (kernel.apparmor_restrict_unprivileged_userns is not 1)",
        );
        return;
    }
    // This binary sits under the profile's path: no AppArmor restriction.
    if let Err(missing) = Features::probe() {
        assert!(
            !missing.iter().any(|m| m.id() == MissingId::UsernsApparmor),
            "the test binary itself is restricted: is the host-setup profile loaded? {missing:?}"
        );
    }
    // A copy outside the profile's glob keeps the restriction.
    let dir = TempDir::new("narrow");
    let copy = dir.path().join("probe-copy");
    std::fs::copy(std::env::current_exe().expect("current_exe"), &copy)
        .expect("copy the test binary");
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the copy");
    let out = Command::new(&copy)
        .args(["--exact", "probe", "--nocapture", "--quiet"])
        .env_clear()
        .env(support::probe::ACTION_VAR, "features")
        .output()
        .expect("run the copy");
    let p = parse_probe(Output {
        status: match out.status.code() {
            Some(code) => boneli_sys::ExitStatus::Exited(code),
            None => boneli_sys::ExitStatus::Signaled(
                std::os::unix::process::ExitStatusExt::signal(&out.status).unwrap_or(0),
            ),
        },
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    });
    p.assert_ok();
    let ids: Vec<&str> = p.get("missing").split(',').collect();
    assert!(
        ids.contains(&"userns-apparmor"),
        "a copy outside the profile's path is not restricted, so the profile is too wide: {}",
        p.raw
    );
}

#[test]
#[ignore = "host: names the host's unobservable rows"]
fn host_gaps_are_known() {
    // Ids of rows a host may be unable to observe. None exist before the
    // seccomp rows land (PR 4 of #6), so any value is a mistake.
    const KNOWN: &[&str] = &[];
    let raw = std::env::var("BONELI_SYS_HOST_GAPS").unwrap_or_default();
    for id in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        assert!(
            KNOWN.contains(&id),
            "BONELI_SYS_HOST_GAPS names an unknown row {id:?}"
        );
    }
}
