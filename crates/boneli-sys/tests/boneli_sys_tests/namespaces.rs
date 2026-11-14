//! The PID, network, IPC, UTS and cgroup namespaces (ADR-007, D7),
//! observed from inside.

use crate::support::rootfs::HOSTNAME;
use crate::support::{ids, run_probe};

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn pid_namespace_probe_is_pid_1() {
    let p = run_probe("pid", ids(0, 0), &[]);
    p.assert_ok();
    assert_eq!(p.get("pid"), "1", "{}", p.raw);
    // Only the probe's own process is visible in the sandbox's /proc.
    assert_eq!(p.get("proc_pids"), "1", "{}", p.raw);
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn network_namespace_loopback_only() {
    let p = run_probe("net", ids(0, 0), &[]);
    p.assert_ok();
    assert_eq!(p.get("interfaces"), "lo", "{}", p.raw);
    assert_eq!(p.get("lo_up"), "true", "{}", p.raw);
    assert_eq!(p.get("tcp_loopback"), "0", "TCP over 127.0.0.1: {}", p.raw);
    // TEST-NET-1 (RFC 5737): no route without a default one.
    assert_eq!(
        p.get("test_net_errno"),
        libc::ENETUNREACH.to_string(),
        "{}",
        p.raw
    );
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn ipc_namespace_isolated() {
    static N: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(1);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let key = ((std::process::id() as i32) << 8) | (n & 0xff);
    // SAFETY: shmget takes plain integers.
    let id = unsafe { libc::shmget(key, 4096, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) };
    assert!(id >= 0, "shmget: {}", std::io::Error::last_os_error());
    let p = run_probe("shm", ids(0, 0), &[("BONELI_PROBE_KEY", &key.to_string())]);
    // SAFETY: id is the segment created above; IPC_RMID takes no buffer.
    unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
    p.assert_ok();
    assert_eq!(
        p.get("errno"),
        libc::ENOENT.to_string(),
        "the host's segment is visible inside: {}",
        p.raw
    );
}

fn host_name() -> String {
    // SAFETY: an all-zero utsname is valid storage for uname.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: u is valid storage.
    assert_eq!(unsafe { libc::uname(&mut u) }, 0);
    let bytes: Vec<u8> = u
        .nodename
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn uts_namespace_hostname() {
    let before = host_name();
    let p = run_probe("uname", ids(0, 0), &[]);
    p.assert_ok();
    assert_eq!(p.get("nodename"), HOSTNAME, "{}", p.raw);
    assert_eq!(host_name(), before, "the host's name changed");
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn cgroup_namespace_created() {
    let p = run_probe("cgroup", ids(0, 0), &[]);
    p.assert_ok();
    assert_eq!(
        p.get("cgroup"),
        "0::/",
        "the sandbox sees its cgroup as the root: {}",
        p.raw
    );
}
