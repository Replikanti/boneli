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

/// `KEYCTL_JOIN_SESSION_KEYRING`, `include/uapi/linux/keyctl.h`.
const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;

/// The usage count `/proc/keys` on the host shows for the key `serial`
/// (eight hex digits), or `None` when the file does not list it.
fn host_key_usage(serial: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/proc/keys").expect("read the host's /proc/keys");
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next() != Some(serial) {
            return None;
        }
        fields.nth(1).and_then(|u| u.parse().ok())
    })
}

/// Waits until the key's usage count satisfies `want`: a credential drops
/// its keyring references after an RCU grace period, so the count settles
/// a moment after the change. 10 s is a hang bound.
fn await_key_usage(serial: &str, want: impl Fn(u32) -> bool, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = host_key_usage(serial);
        if got.is_some_and(&want) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{what}: keyring {serial} has usage {got:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp filters"]
fn runner_keyring_hidden() {
    // In a thread of its own: KEYCTL_JOIN_SESSION_KEYRING replaces the
    // session keyring of the calling thread's credentials only, so the
    // runner's real keyrings are never touched, no key is added to any of
    // them, and the anonymous keyring goes with this thread on every path,
    // a panic included.
    let run = std::thread::spawn(runner_keyring_hidden_in_own_thread);
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

fn runner_keyring_hidden_in_own_thread() {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    use crate::support::{self, Output, parse_probe, pipe, probe, rootfs};

    // SAFETY: a NULL name makes the kernel create an anonymous keyring.
    let id = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<libc::c_char>(),
        )
    };
    assert!(
        id > 0,
        "join a session keyring: {}",
        std::io::Error::last_os_error()
    );
    let serial = format!("{:08x}", id as u32);
    let base = host_key_usage(&serial).expect("the host's /proc/keys lists the new keyring");
    let _runs = support::shared();

    // The control: a child on the host inherits the keyring, so its usage
    // goes up while the child lives, and it can read the files.
    let mut host = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "probe", "--nocapture", "--quiet"])
        .env_clear()
        .env(probe::ACTION_VAR, "keys")
        .env("BONELI_PROBE_SERIAL", &serial)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start the host probe");
    // One reference per credential of the child, at least one.
    await_key_usage(&serial, |u| u > base, "a host child holds the keyring");
    drop(host.stdin.take());
    let out = host.wait_with_output().expect("wait for the host probe");
    let p = parse_probe(Output {
        status: boneli_sys::ExitStatus::Exited(out.status.code().unwrap_or(-1)),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    });
    p.assert_ok();
    assert_eq!(p.get("keys_lists_serial"), "1", "{}", p.raw);
    assert_ne!(p.get("key_users_len"), "0", "{}", p.raw);
    await_key_usage(&serial, |u| u == base, "after the host child");

    for inside in [0, 999] {
        let fixture = rootfs::Fixture::new("keys");
        let cg = support::cgroup::sandbox("keys");
        let (in_r, in_w) = pipe();
        let (out_r, out_w) = pipe();
        let (err_r, err_w) = pipe();
        let spec = boneli_sys::Spec {
            program: std::path::PathBuf::from(rootfs::PROBE),
            args: ["--exact", "probe", "--nocapture", "--quiet"]
                .map(std::ffi::OsString::from)
                .to_vec(),
            env: vec![
                (probe::ACTION_VAR.into(), "keys".into()),
                ("BONELI_PROBE_SERIAL".into(), serial.clone().into()),
            ],
            stdio: boneli_sys::Stdio {
                stdin: in_r,
                stdout: out_w,
                stderr: err_w,
            },
            ids: ids(inside, inside),
            setup_timeout: support::SETUP_TIMEOUT,
            root: fixture.root(),
            cgroup: &cg,
        };
        let mut child = boneli_sys::spawn(&spec).expect("spawn the keys probe");
        drop(spec);
        // The sandbox joined a keyring of its own before its filter, so
        // it holds no reference to this one, though it is alive.
        await_key_usage(
            &serial,
            |u| u == base,
            &format!("inside id {inside}: the sandbox still holds the keyring"),
        );
        let mut pfd = libc::pollfd {
            fd: child.pidfd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is one valid pollfd for the call's duration.
        let alive = unsafe { libc::poll(&mut pfd, 1, 0) } == 0;
        assert!(alive, "inside id {inside}: the probe ended before EOF");
        drop(in_w);
        let mut stdout = String::new();
        std::fs::File::from(out_r)
            .read_to_string(&mut stdout)
            .expect("read the probe's stdout");
        let mut stderr = String::new();
        std::fs::File::from(err_r)
            .read_to_string(&mut stderr)
            .expect("read the probe's stderr");
        let status = support::wait_bounded(&mut child, support::PROBE_HANG_BOUND);
        cg.destroy().expect("destroy the probe's cgroup");
        let p = parse_probe(Output {
            status,
            stdout,
            stderr,
        });
        p.assert_ok();
        // Both files are masked: empty, so neither the runner's keys nor
        // its quota line show.
        assert_eq!(p.get("keys_len"), "0", "inside id {inside}: {}", p.raw);
        assert_eq!(p.get("keys_lists_serial"), "0", "{}", p.raw);
        assert_eq!(p.get("key_users_len"), "0", "inside id {inside}: {}", p.raw);
    }
}
