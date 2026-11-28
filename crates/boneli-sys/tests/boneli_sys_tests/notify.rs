//! The seccomp supervisor in the kernel (ADR-043): every notifying row
//! answers as the plain filter does, the record names the call, its pid
//! inside and its comm, every notification is answered, the workload's own
//! filters never get a call allowed, the supervisor ends with its sandbox,
//! and what a denied call costs. The tests that need a seam of the
//! supervisor (a lost supervisor, a killed caller, signals around the
//! receive) are unit tests in `src/seccomp/notify.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Instant;

use boneli_sys::seccomp::{Arch, Data, Decision, Denials, Key, Policy, Row, Selector, decide};
use boneli_sys::{ExitStatus, Spec, Stdio, spawn};

use crate::support::probe::{
    CEILING_FORMS, CHILD_COMM, COST_CALLS, MODULE_BRIDGE_VAR, MODULE_IOCTL_FORMS,
    MODULE_PACKET_VAR, PLAIN_FILTER_VAR, PREFIX, TCP_MD5SIG_EXT, UNTRIED, bpfilter_forms,
};
use crate::support::{
    self, Probe, cgroup, dev_null, ids, pipe, report, rootfs, run_probe, run_probe_host,
};

/// The name of the supervisor thread (ADR-043, D4).
const THREAD: &str = "seccomp-notify";

/// The call a probe form makes, as the filter sees it: the number and the
/// arguments the rows test (descriptors and pointers do not matter).
fn form_call(id: &str) -> Option<(u32, [u64; 6])> {
    let n = Arch::NATIVE.syscalls();
    let c = |v: i32| v as u32 as u64;
    let cloexec = c(libc::SOCK_CLOEXEC);
    let two_mib = 2u64 << 20;
    let call = match id {
        "io-uring-setup" => (n.io_uring_setup, [1, 0, 0, 0, 0, 0]),
        "bpf" => (n.bpf, [0; 6]),
        "userfaultfd" => (n.userfaultfd, [0; 6]),
        "perf-event-open" => (n.perf_event_open, [0; 6]),
        "keyctl" => (n.keyctl, [0; 6]),
        "add-key" => (n.add_key, [0; 6]),
        "request-key" => (n.request_key, [0; 6]),
        "syslog" => (n.syslog, [10, 0, 0, 0, 0, 0]),
        "unshare-newuser" => (n.unshare, [c(libc::CLONE_NEWUSER), 0, 0, 0, 0, 0]),
        "unshare-newuser-high" => (
            n.unshare,
            [(1 << 32) | c(libc::CLONE_NEWUSER), 0, 0, 0, 0, 0],
        ),
        "clone-newuser" => (
            n.clone,
            [c(libc::CLONE_NEWUSER | libc::SIGCHLD), 0, 0, 0, 0, 0],
        ),
        "clone3" => (n.clone3, [0; 6]),
        "socket-vsock" => (
            n.socket,
            [
                c(libc::AF_VSOCK),
                c(libc::SOCK_STREAM) | cloexec,
                0,
                0,
                0,
                0,
            ],
        ),
        // The allowed forms among the kernel rows.
        "socket-unix" => (
            n.socket,
            [c(libc::AF_UNIX), c(libc::SOCK_STREAM) | cloexec, 0, 0, 0, 0],
        ),
        "socket-inet-tcp" => (
            n.socket,
            [
                c(libc::AF_INET),
                c(libc::SOCK_STREAM) | cloexec,
                c(libc::IPPROTO_TCP),
                0,
                0,
                0,
            ],
        ),
        "socket-inet6-udp" => (
            n.socket,
            [
                c(libc::AF_INET6),
                c(libc::SOCK_DGRAM) | cloexec,
                c(libc::IPPROTO_UDP),
                0,
                0,
                0,
            ],
        ),
        "netlink-route" => (
            n.socket,
            [
                c(libc::AF_NETLINK),
                c(libc::SOCK_RAW) | cloexec,
                c(libc::NETLINK_ROUTE),
                0,
                0,
                0,
            ],
        ),
        "socket-inet-raw-protocol" => (
            n.socket,
            [
                c(libc::AF_INET),
                c(libc::SOCK_RAW) | cloexec,
                c(libc::IPPROTO_RAW),
                0,
                0,
                0,
            ],
        ),
        "socket-inet6-raw-protocol" => (
            n.socket,
            [
                c(libc::AF_INET6),
                c(libc::SOCK_RAW) | cloexec,
                c(libc::IPPROTO_RAW),
                0,
                0,
                0,
            ],
        ),
        "ioctl-tiocsetd" => (n.ioctl, [0, c(libc::TIOCSETD as i32), 0, 0, 0, 0]),
        "ioctl-siocgifbr" => (n.ioctl, [0, c(libc::SIOCGIFBR as i32), 0, 0, 0, 0]),
        // SOCK_PACKET (10), which libc lacks for Linux.
        "socket-inet-packet" => (n.socket, [c(libc::AF_INET), 10 | cloexec, 0, 0, 0, 0]),
        "netlink-netfilter" => (
            n.socket,
            [
                c(libc::AF_NETLINK),
                c(libc::SOCK_RAW) | cloexec,
                c(libc::NETLINK_NETFILTER),
                0,
                0,
                0,
            ],
        ),
        "socketpair-inet" => (
            n.socketpair,
            [c(libc::AF_INET), c(libc::SOCK_STREAM), 0, 0, 0, 0],
        ),
        "mmap-hugetlb" => (
            n.mmap,
            [
                0,
                two_mib,
                c(libc::PROT_READ | libc::PROT_WRITE),
                c(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB),
                u64::MAX,
                0,
            ],
        ),
        "memfd-hugetlb" => (
            n.memfd_create,
            [
                0,
                (libc::MFD_HUGETLB | libc::MFD_CLOEXEC) as u64,
                0,
                0,
                0,
                0,
            ],
        ),
        "shmget-hugetlb" => (
            n.shmget,
            [
                0,
                two_mib,
                c(libc::IPC_CREAT | libc::SHM_HUGETLB | 0o600),
                0,
                0,
                0,
            ],
        ),
        "setsockopt-tls" => (n.setsockopt, [0, c(libc::SOL_TLS), 1, 0, 0, 0]),
        "setsockopt-tcp-ao" => (n.setsockopt, [0, c(libc::IPPROTO_TCP), 38, 0, 0, 0]),
        "setsockopt-tcp-md5" => (
            n.setsockopt,
            [0, c(libc::IPPROTO_TCP), c(libc::TCP_MD5SIG), 0, 0, 0],
        ),
        "setsockopt-tcp-md5-ext" => (
            n.setsockopt,
            [0, c(libc::IPPROTO_TCP), c(TCP_MD5SIG_EXT), 0, 0, 0],
        ),
        "ioctl-fscrypt-add-key" => (n.ioctl, [0, 0xc050_6617, 0, 0, 0, 0]),
        "ioctl-fscrypt-set-policy" => (n.ioctl, [0, 0x800c_6613, 0, 0, 0, 0]),
        "ioctl-fsverity-enable" => (n.ioctl, [0, 0x4080_6685, 0, 0, 0, 0]),
        _ => {
            if let Some((_, cmd)) = MODULE_IOCTL_FORMS.iter().find(|(f, _)| *f == id) {
                (n.ioctl, [0, u64::from(*cmd), 0, 0, 0, 0])
            } else if let Some((_, nr)) = CEILING_FORMS.iter().find(|(f, _)| *f == id) {
                (*nr as u32, [0; 6])
            } else if let Some((_, get, level, opt)) =
                bpfilter_forms().into_iter().find(|(f, ..)| f == id)
            {
                let nr = if get { n.getsockopt } else { n.setsockopt };
                (nr, [0, c(level), c(opt), 0, 0, 0])
            } else {
                return None;
            }
        }
    };
    Some(call)
}

/// What the plain program answers a form: its row's errno and the key the
/// record must hold, or `None` for an allowed form.
fn expected(id: &str) -> Option<(i32, Key)> {
    let (nr, args) = form_call(id).unwrap_or_else(|| panic!("no call for form {id}"));
    let plain = Policy::sandbox().program(Arch::NATIVE).expect("plain");
    let data = Data {
        nr,
        arch: Arch::NATIVE.audit_arch(),
        instruction_pointer: 0,
        args,
    };
    match decide(Arch::NATIVE, &plain, &data) {
        Decision::Deny { errno, key, .. } => Some((errno, key)),
        Decision::Inconsistent { .. } => None,
    }
}

fn rows_of(p: &Probe) -> BTreeMap<String, String> {
    p.lines
        .iter()
        .filter_map(|(k, v)| k.strip_prefix("row:").map(|id| (id.to_string(), v.clone())))
        .collect()
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
fn notified_rows_answer_as_plain_filter() {
    // AC2: the same forms under the plain program on the host (no
    // listener) and in the sandbox under the notifying program (the
    // supervisor answers), for inside ids 0 and 999. The module rows are
    // tried only where the host has the module, as in seccomp_rows.
    let mut env = Vec::new();
    let mut untried = BTreeSet::new();
    for (id, var, shows) in [
        ("socket-inet-packet", MODULE_PACKET_VAR, "/proc/net/packet"),
        ("ioctl-siocgifbr", MODULE_BRIDGE_VAR, "/sys/module/bridge"),
    ] {
        if std::path::Path::new(shows).exists() {
            env.push((var, "1"));
        } else {
            report(&format!(
                "notified_rows_answer_as_plain_filter: {id} not tried ({shows} absent)"
            ));
            untried.insert(id);
        }
    }
    let mut host_env = env.clone();
    host_env.push((PLAIN_FILTER_VAR, "1"));
    let plain = run_probe_host("notify-forms", &host_env);
    plain.assert_ok();
    let plain_rows = rows_of(&plain);
    let mut failures = Vec::new();
    for inside in [0, 999] {
        let notified = run_probe("notify-forms", ids(inside, inside), &env);
        notified.assert_ok();
        let rows = rows_of(&notified);
        assert_eq!(
            rows.keys().collect::<Vec<_>>(),
            plain_rows.keys().collect::<Vec<_>>(),
            "the same forms"
        );
        let mut covered = BTreeSet::new();
        for (id, got) in &rows {
            let base = &plain_rows[id];
            if got != base {
                failures.push(format!(
                    "inside {inside}: {id}: {got} with the listener, {base} without"
                ));
            }
            if got == UNTRIED {
                assert!(untried.contains(id.as_str()), "{id} untried");
                continue;
            }
            match expected(id) {
                None => assert_eq!(got, "0", "{id}: an allowed form"),
                Some((errno, key)) => {
                    if got != &errno.to_string() {
                        failures.push(format!(
                            "inside {inside}: {id}: {got}, the row says {errno}"
                        ));
                    }
                    if !notified.denials.entries().iter().any(|d| d.key == key) {
                        failures.push(format!("inside {inside}: {id}: no record entry {key:?}"));
                    }
                    covered.insert(key.row());
                }
            }
        }
        // Every notifying row has a form (SockPacket only where af_packet
        // is there).
        let mut want: BTreeSet<Row> = Row::ALL.into_iter().filter(|r| r.notifies()).collect();
        if untried.contains("socket-inet-packet") {
            want.remove(&Row::SockPacket);
        }
        assert_eq!(covered, want, "inside {inside}: rows with a form");
        assert_eq!(notified.denials.failed(), None, "inside {inside}");
        assert_eq!(notified.denials.unanswered(), 0, "inside {inside}");
        for d in notified.denials.entries() {
            report(&format!(
                "notified_rows_answer_as_plain_filter inside {inside}: {}",
                d.render(Arch::NATIVE)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
fn record_names_the_inside_pid_and_comm() {
    let p = run_probe("notify-child", ids(0, 0), &[]);
    p.assert_ok();
    assert_eq!(
        p.get("child_errno"),
        libc::EAFNOSUPPORT.to_string(),
        "{}",
        p.raw
    );
    let child: u32 = p.get("child_pid").parse().expect("a pid");
    assert_ne!(p.get("pid"), p.get("child_pid"));
    assert_ne!(child, 1, "a nested process, not the sandbox's init");
    let entry = p
        .denials
        .entries()
        .iter()
        .find(|d| {
            d.row == Row::SocketFamily && d.key.selector() == Selector::Value(libc::AF_ALG as u32)
        })
        .unwrap_or_else(|| panic!("no AF_ALG entry: {:?}", p.denials));
    assert_eq!(entry.count, 1);
    let call = &entry.first.call;
    assert_eq!(call.pid, Some(child), "the pid inside, not the host's");
    let mut comm = [0u8; 16];
    comm[..CHILD_COMM.len()].copy_from_slice(CHILD_COMM.as_bytes());
    assert_eq!(call.comm, Some(comm));
    assert_eq!(call.errno, libc::EAFNOSUPPORT);
    report(&format!(
        "record_names_the_inside_pid_and_comm: {}",
        entry.render(Arch::NATIVE)
    ));
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
fn every_notification_is_answered() {
    let p = run_probe("notify-threads", ids(0, 0), &[]);
    p.assert_ok();
    assert_eq!(
        p.get("wrong"),
        "0",
        "every call got EAFNOSUPPORT: {}",
        p.raw
    );
    let d = &p.denials;
    assert_eq!(d.failed(), None);
    assert_eq!(d.unanswered(), 0);
    let vsock: Vec<_> = d
        .entries()
        .iter()
        .filter(|e| e.key.selector() == Selector::Value(libc::AF_VSOCK as u32))
        .collect();
    assert_eq!(vsock.len(), 1, "{d:?}");
    assert_eq!(vsock[0].count, 8 * 1000, "{d:?}");
    // The threads' start: glibc tries clone3 and falls back to clone.
    let clone3: Vec<_> = d
        .entries()
        .iter()
        .filter(|e| e.row == Row::Clone3)
        .collect();
    assert_eq!(clone3.len(), 1, "{d:?}");
    report(&format!(
        "every_notification_is_answered: {}",
        clone3[0].render(Arch::NATIVE)
    ));
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
fn stacked_filters_never_allow() {
    for inside in [0, 999] {
        let p = run_probe("notify-stack", ids(inside, inside), &[]);
        p.assert_ok();
        // A task has one listener at most.
        assert_eq!(
            p.get("listener_errno"),
            libc::EBUSY.to_string(),
            "{}",
            p.raw
        );
        assert_eq!(p.get("errno_install"), "0", "{}", p.raw);
        assert_eq!(p.get("notify_install"), "0", "{}", p.raw);
        // The workload's ERRNO outranks the sandbox's notification, and its
        // listener-less USER_NOTIF, the newer filter, wins the tie: both
        // calls fail, neither is notified.
        assert_eq!(p.get("vsock"), libc::EACCES.to_string(), "{}", p.raw);
        assert_eq!(p.get("keyctl"), libc::ENOSYS.to_string(), "{}", p.raw);
        let d = &p.denials;
        assert!(
            !d.entries().iter().any(|e| {
                e.row == Row::Keyring || e.key.selector() == Selector::Value(libc::AF_VSOCK as u32)
            }),
            "{d:?}"
        );
        assert_eq!(d.failed(), None);
    }
}

/// The threads of this process named [`THREAD`].
fn supervisor_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("list /proc/self/task")
        .flatten()
        .filter(|t| {
            std::fs::read_to_string(t.path().join("comm")).is_ok_and(|c| c.trim_end() == THREAD)
        })
        .count()
}

/// Waits until [`supervisor_threads`] is `n`, within the hang bound. The
/// supervisor is joined when `wait` or the drop returns, but glibc's join
/// returns when the kernel clears the thread's tid, before the exiting
/// task leaves `/proc/self/task`, so the count catches up a moment later
/// (2 of 20 runs saw the old count at once in review, 9 of 50 under load).
/// A supervisor that does not end fails here after the bound.
fn await_supervisor_threads(n: usize, when: &str) {
    let deadline = Instant::now() + support::PROBE_HANG_BOUND;
    loop {
        let got = supervisor_threads();
        if got == n {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{when}: {got} supervisor threads, want {n}"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// A probe started in a sandbox with its stdin a pipe the test closes.
struct Held {
    child: boneli_sys::Child,
    stdin: Option<std::os::fd::OwnedFd>,
    out: BufReader<std::fs::File>,
    cg: Option<boneli_sys::Cgroup>,
    _fixture: rootfs::Fixture,
}

fn start_held(action: &str, program: &str, args: &[&str]) -> Held {
    let fixture = rootfs::Fixture::new("held");
    let cg = cgroup::sandbox("held");
    let (in_r, in_w) = pipe();
    let (out_r, out_w) = pipe();
    let spec = Spec {
        program: PathBuf::from(program),
        args: args.iter().map(OsString::from).collect(),
        env: vec![(
            OsString::from(crate::support::probe::ACTION_VAR),
            OsString::from(action),
        )],
        stdio: Stdio {
            stdin: in_r,
            stdout: out_w,
            stderr: dev_null(),
        },
        ids: ids(0, 0),
        setup_timeout: support::SETUP_TIMEOUT,
        root: fixture.root(),
        cgroup: &cg,
    };
    let child = spawn(&spec).expect("spawn");
    drop(spec);
    Held {
        child,
        stdin: Some(in_w),
        out: BufReader::new(std::fs::File::from(out_r)),
        cg: Some(cg),
        _fixture: fixture,
    }
}

impl Held {
    fn finish(mut self) -> (ExitStatus, Denials) {
        drop(self.stdin.take());
        let status = support::wait_bounded(&mut self.child, support::PROBE_HANG_BOUND);
        let denials = self.child.denials();
        if let Some(cg) = self.cg.take() {
            drop(self.child);
            cg.destroy().expect("destroy the cgroup");
        }
        (status, denials)
    }
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
fn supervisor_ends_with_the_sandbox() {
    // No other sandbox of this binary runs meanwhile, so every supervisor
    // thread counted is this test's.
    let _only = support::exclusive();
    // An earlier test's supervisor may still be leaving /proc.
    await_supervisor_threads(0, "before");
    // Running: one thread each, at once: `spawn` returns after the
    // supervisor has named itself. Waited or dropped: none.
    let held = start_held("ids", "/usr/bin/sleep", &["30"]);
    assert_eq!(supervisor_threads(), 1, "while the sandbox runs");
    let fixture = rootfs::Fixture::new("ends");
    let cg = cgroup::sandbox("ends");
    let mut child = spawn(&Spec {
        program: PathBuf::from("/usr/bin/sleep"),
        args: vec![OsString::from("30")],
        env: Vec::new(),
        stdio: Stdio {
            stdin: dev_null(),
            stdout: dev_null(),
            stderr: dev_null(),
        },
        ids: ids(0, 0),
        setup_timeout: support::SETUP_TIMEOUT,
        root: fixture.root(),
        cgroup: &cg,
    })
    .expect("spawn");
    assert_eq!(supervisor_threads(), 2, "two sandboxes");
    child.kill().expect("kill");
    child.wait().expect("wait");
    await_supervisor_threads(1, "after wait");
    // Dropped without a wait: killed, reaped, the supervisor joined.
    drop(held.child);
    await_supervisor_threads(0, "after dropping an unwaited child");
    drop(child);
    for c in [cg, held.cg.expect("cgroup")] {
        c.destroy().expect("destroy");
    }
}

/// The supervisor thread's time on the CPU so far, in nanoseconds
/// (`/proc/<pid>/task/<tid>/schedstat`, first field); `None` without
/// schedstat.
fn supervisor_cpu_ns() -> Option<u64> {
    std::fs::read_dir("/proc/self/task")
        .ok()?
        .flatten()
        .find(|t| {
            std::fs::read_to_string(t.path().join("comm")).is_ok_and(|c| c.trim_end() == THREAD)
        })
        .and_then(|t| std::fs::read_to_string(t.path().join("schedstat")).ok())
        .and_then(|s| s.split_whitespace().next()?.parse().ok())
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
fn notification_cost() {
    // Printed for ADR-043 D8, asserted on nothing but the answers: a
    // denied call's latency without and with the listener, and the
    // supervisor's CPU time per notification.
    let _only = support::exclusive();
    let plain = run_probe_host("notify-cost", &[(PLAIN_FILTER_VAR, "1")]);
    plain.assert_ok();
    assert_eq!(plain.get("wrong"), "0");
    let mut held = start_held(
        "notify-cost",
        rootfs::PROBE,
        &["--exact", "probe", "--nocapture", "--quiet"],
    );
    let mut values = BTreeMap::new();
    let started = Instant::now();
    let mut line = String::new();
    while !values.contains_key("done") {
        line.clear();
        let n = held.out.read_line(&mut line).expect("read the probe");
        assert!(n > 0, "the probe ended early: {values:?}");
        assert!(
            started.elapsed() < support::PROBE_HANG_BOUND,
            "the probe still runs after {:?}",
            support::PROBE_HANG_BOUND
        );
        if let Some((k, v)) = line
            .split_once(PREFIX)
            .and_then(|(_, kv)| kv.trim_end().split_once('='))
        {
            values.insert(k.to_string(), v.to_string());
        }
    }
    let cpu = supervisor_cpu_ns();
    let (status, denials) = held.finish();
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(values["wrong"], "0");
    assert_eq!(denials.failed(), None);
    let notified: u64 = denials.entries().iter().map(|d| d.count).sum();
    assert!(notified >= COST_CALLS as u64, "{denials:?}");
    let per = cpu.map_or_else(
        || "n/a (no schedstat)".to_string(),
        |ns| format!("{} ns", ns / notified),
    );
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "boneli-sys test: notification_cost on {}: plain p50 {} ns p99 {} ns; \
         notified p50 {} ns p99 {} ns; supervisor CPU per notification {per} \
         over {notified} notifications",
        Arch::NATIVE.name(),
        plain.get("p50_ns"),
        plain.get("p99_ns"),
        values["p50_ns"],
        values["p99_ns"],
    );
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
fn set_id_calls_run_while_a_sandbox_runs() {
    // glibc's and musl's setgid, setuid and setgroups signal every thread
    // of the process and wait for each one's handler (SIGSETXID, 33 in
    // glibc), so a supervisor that blocked that signal would hang them,
    // every later thread start and its own exit. setgid to the current
    // group needs no privilege. The bound turns a hang into a failure: a
    // hung call holds glibc's thread-stack lock, so unwinding (which joins
    // the supervisor) would hang too, and the test aborts instead.
    let held = start_held("ids", "/usr/bin/sleep", &["30"]);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // SAFETY: getgid has no preconditions and cannot fail.
        let gid = unsafe { libc::getgid() };
        // SAFETY: setgid to the current real group changes nothing.
        let rc = unsafe { libc::setgid(gid) };
        let _ = tx.send(rc);
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(rc) => assert_eq!(rc, 0, "setgid(getgid())"),
        Err(e) => {
            let _ = held.child.kill();
            let _ = writeln!(
                std::io::stderr(),
                "set_id_calls_run_while_a_sandbox_runs: setgid with a running sandbox did not \
                 return within 10 s ({e}); aborting, since unwinding would join the hung \
                 supervisor"
            );
            std::process::abort();
        }
    }
    // A thread starts as before, and the sandbox ends.
    std::thread::spawn(|| ()).join().expect("a thread starts");
    held.child.kill().expect("kill");
    let (status, denials) = held.finish();
    assert_eq!(status, ExitStatus::Signaled(libc::SIGKILL));
    assert_eq!(denials.failed(), None);
}
