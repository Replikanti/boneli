//! The single id mapping (ADR-007, D1), observed from inside.

use std::os::unix::fs::MetadataExt;

use crate::support::{TempDir, host_ids, ids, read_number, run_probe};

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
    let dir = TempDir::new("other-ids");
    let file = dir.path().join("f");
    std::fs::write(&file, b"x").expect("create the file");
    let file = file.to_str().expect("UTF-8 temp path");

    let p = run_probe("setuid", ids(0, 0), &[("BONELI_PROBE_ID", "12345")]);
    p.assert_ok();
    assert_eq!(
        p.get("errno"),
        libc::EINVAL.to_string(),
        "setuid(12345) as inside 0: {}",
        p.raw
    );

    let p = run_probe(
        "chown",
        ids(0, 0),
        &[("BONELI_PROBE_ID", "12345"), ("BONELI_PROBE_FILE", file)],
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
        let dir = TempDir::new("ownership");
        let file = dir.path().join("created-inside");
        let p = run_probe(
            "create-file",
            ids(inside, inside),
            &[("BONELI_PROBE_FILE", file.to_str().expect("UTF-8 temp path"))],
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
            "/ seen from inside {inside}: {}",
            p.raw
        );
        assert_eq!(
            p.get("root_gid"),
            overflow_gid.to_string(),
            "/ seen from inside {inside}: {}",
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
