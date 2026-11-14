//! The single id mapping (ADR-007, D1), observed from inside.

use std::os::unix::fs::MetadataExt;

use crate::support::rootfs::Fixture;
use crate::support::{host_ids, ids, read_number, run_probe, run_probe_on};

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn inside_ids_match_single_mapping() {
    let (host_uid, host_gid) = host_ids();
    for inside in [0, 999] {
        let p = run_probe("ids", ids(inside, inside), &[]);
        p.assert_ok();
        assert_eq!(p.get("uid"), inside.to_string(), "{}", p.raw);
        assert_eq!(p.get("gid"), inside.to_string(), "{}", p.raw);
        // Exactly one line each, compared after parsing.
        assert_eq!(
            p.get("uid_map"),
            format!("{inside} {host_uid} 1"),
            "{}",
            p.raw
        );
        assert_eq!(
            p.get("gid_map"),
            format!("{inside} {host_gid} 1"),
            "{}",
            p.raw
        );
        assert_eq!(p.get("setgroups"), "deny", "{}", p.raw);
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn other_ids_unusable() {
    // A host file owned by the host user, at /workspace/f inside.
    let fixture = Fixture::new("other-ids");
    std::fs::write(fixture.workspace.join("f"), b"x").expect("create the file");
    let file = "/workspace/f";

    let p = run_probe("setuid", ids(0, 0), &[("BONELI_PROBE_ID", "12345")]);
    p.assert_ok();
    assert_eq!(
        p.get("errno"),
        libc::EINVAL.to_string(),
        "setuid(12345) as inside 0: {}",
        p.raw
    );

    let p = run_probe_on(
        "chown",
        ids(0, 0),
        &[("BONELI_PROBE_ID", "12345"), ("BONELI_PROBE_FILE", file)],
        fixture.root(),
    );
    p.assert_ok();
    assert_eq!(
        p.get("errno"),
        libc::EINVAL.to_string(),
        "chown(f, 12345) as inside 0: {}",
        p.raw
    );

    // With inside 999, 0 is not mapped either: the kernel rejects the
    // unmapped id (EINVAL) before it checks capabilities (EPERM), so root
    // is out of reach the same way as any other id (measured).
    let p = run_probe("setuid", ids(999, 999), &[("BONELI_PROBE_ID", "0")]);
    p.assert_ok();
    assert_eq!(
        p.get("errno"),
        libc::EINVAL.to_string(),
        "setuid(0) as inside 999: {}",
        p.raw
    );
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn ownership_maps_through_single_line() {
    let (host_uid, host_gid) = host_ids();
    let overflow_uid = read_number("/proc/sys/kernel/overflowuid");
    let overflow_gid = read_number("/proc/sys/kernel/overflowgid");
    for inside in [0, 999] {
        // The probe creates /workspace/created-inside, a host directory
        // behind a writable bind, and stats /usr, the host's, owned by an
        // id that is not mapped. (The root itself belongs to the host user,
        // so it shows as the inside id.)
        let fixture = Fixture::new("ownership");
        let file = fixture.workspace.join("created-inside");
        let p = run_probe_on(
            "create-file",
            ids(inside, inside),
            &[
                ("BONELI_PROBE_FILE", "/workspace/created-inside"),
                ("BONELI_PROBE_STAT", "/usr"),
            ],
            fixture.root(),
        );
        p.assert_ok();
        let meta = std::fs::metadata(&file).expect("the probe's file exists on the host");
        assert_eq!(
            (meta.uid(), meta.gid()),
            (host_uid, host_gid),
            "owner on the host, inside {inside}"
        );
        assert_eq!(
            p.get("root_uid"),
            overflow_uid.to_string(),
            "/usr seen from inside {inside}: {}",
            p.raw
        );
        assert_eq!(
            p.get("root_gid"),
            overflow_gid.to_string(),
            "/usr seen from inside {inside}: {}",
            p.raw
        );
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn supplementary_groups_stay_unmapped() {
    let mut host = [0 as libc::gid_t; 1024];
    // SAFETY: host holds 1024 entries and the size passed says so.
    let n = unsafe { libc::getgroups(host.len() as i32, host.as_mut_ptr()) };
    assert!(n >= 0, "getgroups: {}", std::io::Error::last_os_error());
    let overflow_gid = read_number("/proc/sys/kernel/overflowgid").to_string();
    for inside in [0, 999] {
        let p = run_probe("groups", ids(inside, inside), &[]);
        p.assert_ok();
        let groups: Vec<&str> = p
            .get("groups")
            .split(',')
            .filter(|g| !g.is_empty())
            .collect();
        assert_eq!(
            groups.len(),
            n as usize,
            "as many groups inside as on the host: {}",
            p.raw
        );
        for g in &groups {
            assert!(
                *g == inside.to_string() || *g == overflow_gid,
                "group {g} inside is neither {inside} nor overflowgid: {}",
                p.raw
            );
        }
        assert_eq!(
            p.get("setgroups_errno"),
            libc::EPERM.to_string(),
            "setgroups is denied: {}",
            p.raw
        );
    }
}
