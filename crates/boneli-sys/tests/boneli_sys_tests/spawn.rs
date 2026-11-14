//! The spawn model (ADR-007, D4): what reaches the child, signals, session,
//! exec errors, threads and the pidfd.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use boneli_sys::{Cgroup, Error, ExitStatus, Spec, Stdio, Step, spawn};

use crate::support::rootfs::Fixture;
use crate::support::{self, dev_null, ids, run, run_probe, wait_bounded};

/// A spec on `fixture`'s default root in `cgroup`.
fn spec<'a>(fixture: &Fixture, cgroup: &'a Cgroup, program: &str, args: &[&str]) -> Spec<'a> {
    Spec {
        program: PathBuf::from(program),
        args: args.iter().map(OsString::from).collect(),
        env: Vec::new(),
        stdio: Stdio {
            stdin: dev_null(),
            stdout: dev_null(),
            stderr: dev_null(),
        },
        ids: ids(0, 0),
        setup_timeout: support::SETUP_TIMEOUT,
        root: fixture.root(),
        cgroup,
    }
}

/// Sets `BONELI_SECRET_PROBE=1` in this process once.
fn set_secret_marker() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: std serializes its own environment reads and writes with a
        // lock, and the threads of this test binary read the environment
        // only through std; nothing here calls libc's getenv concurrently.
        unsafe { std::env::set_var("BONELI_SECRET_PROBE", "1") };
    });
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn only_stdio_and_given_env_reach_the_child() {
    // CVE-2024-21626 class: a host descriptor leaking into the sandbox.
    set_secret_marker();
    // SAFETY: the path is a valid C string; the fd is closed below.
    let leaked = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    assert!(
        leaked >= 0,
        "open / without O_CLOEXEC: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: leaked is a valid descriptor this test owns.
    let flags = unsafe { libc::fcntl(leaked, libc::F_GETFD) };
    assert_eq!(
        flags & libc::FD_CLOEXEC,
        0,
        "the leak candidate is inheritable"
    );

    let p = run_probe("fds-env", ids(0, 0), &[("BONELI_TEST_GIVEN", "yes")]);
    // SAFETY: leaked is still open and owned by this test.
    unsafe { libc::close(leaked) };
    p.assert_ok();
    assert_eq!(p.get("fds"), "0,1,2", "open descriptors inside: {}", p.raw);
    let env: BTreeSet<&str> = p
        .lines
        .iter()
        .filter(|(k, _)| k == "env")
        .map(|(_, v)| v.as_str())
        .collect();
    let want: BTreeSet<&str> = ["BONELI_SYS_PROBE=fds-env", "BONELI_TEST_GIVEN=yes"]
        .into_iter()
        .collect();
    assert_eq!(
        env, want,
        "the environment inside is exactly the spec's: {}",
        p.raw
    );
}

fn status_mask(status: &str, key: &str) -> u64 {
    let line = status
        .lines()
        .find(|l| l.starts_with(&format!("{key}:")))
        .unwrap_or_else(|| panic!("no {key} in:\n{status}"));
    u64::from_str_radix(line[key.len() + 1..].trim(), 16).unwrap_or_else(|e| panic!("{line}: {e}"))
}

fn sig_bit(sig: i32) -> u64 {
    1 << (sig - 1)
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn signal_state_reset() {
    // SAFETY: an empty sigset_t is valid storage for sigemptyset.
    let mut block: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: block is valid storage; sigemptyset and sigaddset only write it.
    unsafe { libc::sigemptyset(&mut block) };
    // SAFETY: as above; SIGUSR1 is a valid signal.
    unsafe { libc::sigaddset(&mut block, libc::SIGUSR1) };
    // SAFETY: old is valid storage for the previous mask.
    let mut old: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: both sets are valid; this changes only this test thread's mask.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &block, &mut old) };
    assert_eq!(rc, 0);

    let mine = std::fs::read_to_string("/proc/thread-self/status").expect("own status");
    assert_ne!(
        status_mask(&mine, "SigBlk") & sig_bit(libc::SIGUSR1),
        0,
        "SIGUSR1 is blocked here"
    );
    assert_ne!(
        status_mask(&mine, "SigIgn") & sig_bit(libc::SIGPIPE),
        0,
        "Rust ignores SIGPIPE here"
    );

    // cat changes no signal state, so it shows what execve handed it; a
    // Rust probe would ignore SIGPIPE again on its own.
    let out = run(
        Path::new("/bin/cat"),
        &["/proc/self/status"],
        ids(0, 0),
        &[],
    );
    // SAFETY: old holds the mask saved above.
    let rc = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    assert_eq!(out.status, ExitStatus::Exited(0), "{}", out.stderr);
    assert_eq!(
        status_mask(&out.stdout, "SigBlk"),
        0,
        "blocked signals inside:\n{}",
        out.stdout
    );
    assert_eq!(
        status_mask(&out.stdout, "SigIgn"),
        0,
        "ignored signals inside:\n{}",
        out.stdout
    );
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn new_session_without_terminal() {
    let p = run_probe("session", ids(0, 0), &[]);
    p.assert_ok();
    assert_eq!(
        p.get("sid"),
        p.get("pid"),
        "the probe leads its own session: {}",
        p.raw
    );
    assert_eq!(
        p.get("tty_errno"),
        libc::ENXIO.to_string(),
        "no controlling terminal: {}",
        p.raw
    );
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn exec_errors() {
    let fixture = Fixture::new("exec-errors");
    let cg = support::cgroup::sandbox("exec-errors");
    match spawn(&spec(&fixture, &cg, "/nonexistent/boneli-sys-probe", &[])) {
        Err(Error::Setup {
            step: Step::Exec,
            errno,
            ..
        }) => assert_eq!(errno, libc::ENOENT),
        other => panic!("missing program: {other:?}"),
    }
    // Rejected while preparing, before any clone.
    match spawn(&spec(&fixture, &cg, "bin/true", &[])) {
        Err(Error::RelativeProgram(p)) => assert_eq!(p, PathBuf::from("bin/true")),
        other => panic!("relative program: {other:?}"),
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn concurrent_spawns_from_threads() {
    // Hang bound per spawn and wait: /bin/true takes milliseconds.
    const BOUND: Duration = Duration::from_secs(10);
    // The churn thread loads the host: keep the timing tests out.
    let _runs = support::shared();
    let stop = Arc::new(AtomicBool::new(false));
    let churn = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let v: Vec<u64> = (0..64).collect();
                n = n.wrapping_add(v.iter().sum::<u64>());
            }
            n
        })
    };
    let fixture = Arc::new(Fixture::new("concurrent"));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let fixture = Arc::clone(&fixture);
            std::thread::spawn(move || {
                for _ in 0..8 {
                    let cg = support::cgroup::sandbox("concurrent");
                    let mut s = spec(&fixture, &cg, "/bin/true", &[]);
                    s.setup_timeout = BOUND;
                    let mut child = spawn(&s).expect("spawn /bin/true");
                    assert_eq!(wait_bounded(&mut child, BOUND), ExitStatus::Exited(0));
                    drop(s);
                    cg.destroy().expect("destroy");
                }
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|w| w.join()).collect();
    stop.store(true, Ordering::Relaxed);
    churn.join().expect("allocating thread");
    for r in results {
        r.expect("a worker failed");
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn wait_and_kill_by_pidfd() {
    let fixture = Fixture::new("kill");
    let cg = support::cgroup::sandbox("kill");
    let mut child = spawn(&spec(&fixture, &cg, "/bin/sleep", &["30"])).expect("spawn sleep");
    child.kill().expect("kill through the pidfd");
    assert_eq!(
        wait_bounded(&mut child, Duration::from_secs(10)),
        ExitStatus::Signaled(libc::SIGKILL)
    );
    assert!(
        matches!(child.wait(), Err(Error::AlreadyWaited)),
        "a second wait is an error"
    );
}

#[test]
#[ignore = "host: unprivileged user namespaces"]
fn report_survives_closed_stdio() {
    // A runner with 0-2 closed (daemonized): pipe2 would hand out 0 and 1
    // for the report pipe, and the child's stdio dup2 would replace its
    // write end, so the exec failure below would read as a success.
    let dir = support::TempDir::new("closed-stdio");
    let file = dir.path().join("result");
    let fixture = Fixture::new("closed-stdio");
    let out = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "probe", "--nocapture", "--quiet"])
        .env(support::probe::ACTION_VAR, "closed-stdio-spawn")
        .env("BONELI_PROBE_FILE", &file)
        .env("BONELI_PROBE_LAYER", &fixture.layer)
        .env(
            "BONELI_PROBE_STAGING",
            fixture.tree().path().join("staging"),
        )
        .output()
        .expect("run the probe");
    let got = std::fs::read_to_string(&file).unwrap_or_default();
    assert_eq!(
        out.status.code(),
        Some(0),
        "spawn with 0-2 closed did not report Setup {{ Exec, ENOENT }}: {got}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
