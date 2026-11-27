//! `Features::probe` on the real host, and the narrowness of the AppArmor
//! profile of the host-setup block (ADR-007, D5).

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use boneli_sys::{Features, MissingId};

use crate::support::{self, Output, TempDir, parse_probe, report, run_probe_host};

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
#[ignore = "host: user namespaces, cgroup v2 delegation, Linux 5.19"]
fn refuses_host_without_keyrings() {
    // A kernel without CONFIG_KEYS, as the probe sees it: keyctl gives
    // ENOSYS (a filter of the probe process's own). The host is refused up
    // front instead of failing every spawn at the keyring join (ADR-007,
    // D3).
    let p = run_probe_host("features-no-keyrings", &[]);
    p.assert_ok();
    assert!(
        p.get("missing").split(',').any(|id| id == "keyrings"),
        "keyrings not reported: {}",
        p.raw
    );
    assert_eq!(
        p.get("keyrings"),
        format!("keyctl:{}", libc::ENOSYS),
        "{}",
        p.raw
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
    // This binary sits under the profile's path: the profile is attached
    // and lifts the restriction.
    let label = support::probe::apparmor_label();
    assert!(
        label.starts_with("boneli-sys-tests"),
        "the test binary runs as {label:?}, not under the host-setup profile: is it loaded?"
    );
    if let Err(missing) = Features::probe() {
        assert!(
            !missing.iter().any(|m| m.id() == MissingId::UsernsApparmor),
            "the test binary itself is restricted: {missing:?}"
        );
    }
    // A copy outside the profile's glob keeps the restriction. It must not
    // be started from here: a program this profile execs stays in it (a
    // copy started directly was not restricted on the CI runners), so the
    // user manager, which is unconfined, starts it, and AppArmor finds a
    // profile for it by its path alone.
    let dir = TempDir::new("narrow");
    let copy = dir.path().join("probe-copy");
    std::fs::copy(std::env::current_exe().expect("current_exe"), &copy)
        .expect("copy the test binary");
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the copy");
    let out = Command::new("systemd-run")
        .args(["--user", "--wait", "--pipe", "--quiet", "--collect"])
        .arg(format!("--setenv={}=features", support::probe::ACTION_VAR))
        .arg(&copy)
        .args(["--exact", "probe", "--nocapture", "--quiet"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the copy through systemd-run --user");
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
    assert!(
        !p.get("label").starts_with("boneli-sys-tests"),
        "the copy runs under the test profile, so the profile is too wide: {}",
        p.raw
    );
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
    // Exact: every listed id is known (support::KNOWN_GAPS), and the tests
    // that use one fail when a listed gap turns out observable
    // (seccomp::seccomp_rows, mounts::hugetlbfs_source_refused).
    let gaps = support::host_gaps();
    report(&format!("host gaps: {gaps:?}"));
}

#[test]
fn gap_ids_are_exact() {
    let all = support::parse_gaps(
        " syslog,shmget-hugetlb , hugetlbfs-mount,ioctl-siocgifbr,socket-inet-packet,\
         setsockopt-tls,setsockopt-tcp-ao,setsockopt-tcp-md5,nosys-statmount,alarm-rtc",
    )
    .expect("known ids");
    assert_eq!(all.len(), 10);
    assert_eq!(support::parse_gaps("").expect("empty"), Default::default());
    // `nosys-` takes NeedsCap census names only, byte for byte: not an Own
    // entry (read), not a Row entry (setsockopt), not an empty or unknown
    // name, not another case, a Cyrillic look-alike or a zero-width space.
    for bad in [
        "bogus",
        "syslog,bogus",
        "nosys-read",
        "nosys-setsockopt",
        "nosys-",
        "nosys-bogus",
        "NOSYS-statmount",
        "nosys-\u{455}tatmount",
        "nosys-statmount\u{200b}",
        "SYSLOG",
        "io-uring-setup",
    ] {
        assert!(support::parse_gaps(bad).is_err(), "{bad:?} was accepted");
    }
}
