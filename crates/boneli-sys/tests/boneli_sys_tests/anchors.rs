//! A pod's anchors and the commands joined to them (ADR-042, D3), seen
//! from the runner and from inside.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use boneli_sys::{
    Anchor, AnchorSpec, Cgroup, Error, ExecSpec, ExitStatus, Hostname, InsidePath, Stdio, Step,
};

use crate::support::rootfs::{self, Fixture, inside};
use crate::support::{self, cgroup, dev_null, ids, pipe, probe, report, wait_bounded};

/// The port of the loopback tests: PostgreSQL's, which a pod's first
/// service listens on; each pod has a network namespace of its own.
const PORT: &str = "5432";

/// An anchor spec on `fixture` with the anchor mounts, every mount before
/// the fill point.
fn anchor_spec<'a>(
    fixture: &Fixture,
    cg: &'a Cgroup,
    hostname: &str,
    pins: Vec<OwnedFd>,
) -> AnchorSpec<'a> {
    let mut root = fixture.root_with(vec![fixture.layer.clone()], fixture.anchor_mounts());
    root.hostname = Hostname::new(hostname).expect("hostname");
    let fill_at = root.mounts.len();
    AnchorSpec {
        ids: ids(0, 0),
        root,
        fill_at,
        pins,
        cgroup: cg,
        setup_timeout: support::SETUP_TIMEOUT,
    }
}

/// A pod's first anchor, filled with nothing and resumed.
fn pod(fixture: &Fixture, cg: &Cgroup, hostname: &str, pins: Vec<OwnedFd>) -> Anchor {
    let spec = anchor_spec(fixture, cg, hostname, pins);
    let mut anchor = Anchor::create(&spec).unwrap_or_else(|e| panic!("create: {e}"));
    anchor
        .fill()
        .expect("at the fill point")
        .resume()
        .unwrap_or_else(|e| panic!("resume: {e}"));
    anchor
}

/// A later anchor of `first`'s pod, resumed.
fn joined(first: &Anchor, fixture: &Fixture, cg: &Cgroup, hostname: &str) -> Anchor {
    let spec = anchor_spec(fixture, cg, hostname, Vec::new());
    let mut anchor = first.join(&spec).unwrap_or_else(|e| panic!("join: {e}"));
    let fill = anchor.fill().expect("at the fill point");
    // The runner reaches a later anchor's root as the first one's: the
    // join set it dumpable again.
    fill.open(&inside("/workspace"))
        .unwrap_or_else(|e| panic!("open the joined anchor's workspace: {e}"));
    fill.resume()
        .unwrap_or_else(|e| panic!("resume the joined anchor: {e}"));
    anchor
}

fn exec_spec(program: &str, args: &[&str], env: &[(&str, &str)]) -> ExecSpec {
    ExecSpec {
        program: PathBuf::from(program),
        args: args.iter().map(OsString::from).collect(),
        env: env
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect(),
        cwd: InsidePath::root(),
        setup_timeout: support::SETUP_TIMEOUT,
    }
}

fn read_all(fd: OwnedFd) -> String {
    let mut buf = Vec::new();
    File::from(fd)
        .read_to_end(&mut buf)
        .expect("read a pipe from the exec");
    String::from_utf8_lossy(&buf).into_owned()
}

/// Runs a program in `anchor`'s container and collects its output.
fn run(anchor: &Anchor, program: &str, args: &[&str], env: &[(&str, &str)]) -> support::Output {
    let _runs = support::shared();
    let (out_r, out_w) = pipe();
    let (err_r, err_w) = pipe();
    let stdio = Stdio {
        stdin: dev_null(),
        stdout: out_w,
        stderr: err_w,
    };
    let mut child = anchor
        .exec(&exec_spec(program, args, env), stdio)
        .unwrap_or_else(|e| panic!("exec {program}: {e}"));
    let err_reader = std::thread::spawn(move || read_all(err_r));
    let stdout = read_all(out_r);
    let status = wait_bounded(&mut child, support::PROBE_HANG_BOUND);
    let stderr = err_reader.join().expect("stderr reader");
    support::Output {
        status,
        stdout,
        stderr,
        denials: child.denials(),
    }
}

/// `/bin/sh -c script` in `anchor`'s container; fails the test unless it
/// exits 0.
fn sh(anchor: &Anchor, script: &str) -> String {
    let out = run(anchor, "/bin/sh", &["-c", script], &[]);
    assert_eq!(
        out.status,
        ExitStatus::Exited(0),
        "{script}\n--- stdout\n{}--- stderr\n{}",
        out.stdout,
        out.stderr
    );
    out.stdout
}

/// This test binary as a probe for `action` in `anchor`'s container.
fn probe_in(anchor: &Anchor, action: &str, env: &[(&str, &str)]) -> support::Probe {
    let mut full = vec![(probe::ACTION_VAR, action)];
    full.extend_from_slice(env);
    support::parse_probe(run(
        anchor,
        rootfs::PROBE,
        &["--exact", "probe", "--nocapture", "--quiet"],
        &full,
    ))
}

/// Whether the read end of a pipe sees its last writer gone within `bound`.
fn hung_up(read: &OwnedFd, bound: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd: read.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd is one valid pollfd for the call's duration.
    let rc = unsafe { libc::poll(&mut pfd, 1, bound.as_millis() as i32) };
    rc > 0 && pfd.revents & libc::POLLHUP != 0
}

/// Whether a process with this pid exists (`kill(pid, 0)`).
fn alive(pid: i32) -> bool {
    // SAFETY: a signal of 0 only checks for the process.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// `(st_dev, st_ino)` of a descriptor.
fn identity(fd: BorrowedFd<'_>) -> (u64, u64) {
    // SAFETY: an all-zero stat is valid storage for fstat to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: st is valid storage; fd is open.
    assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) }, 0);
    (st.st_dev as u64, st.st_ino as u64)
}

/// A field of `/proc/<pid>/status`, whitespace trimmed.
fn status_field(pid: i32, key: &str) -> String {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
        .unwrap_or_else(|| panic!("no {key} in {text}"))
        .trim()
        .to_string()
}

/// `Anonymous` of `/proc/<pid>/smaps_rollup` in KiB.
fn anonymous_kib(pid: &str) -> u64 {
    let text =
        std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).expect("read smaps_rollup");
    text.lines()
        .find_map(|l| l.strip_prefix("Anonymous:"))
        .and_then(|v| v.trim().strip_suffix("kB"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| panic!("no Anonymous in {text}"))
}

/// The runner of `anchor_pins_outlive_the_runner`: a probe on the host
/// that creates a pod whose anchor pins its standard input, prints where
/// it is, and waits to be killed.
pub fn runner() -> ! {
    let fixture = Fixture::new("anchor-runner");
    let cg = cgroup::sandbox("anchor-runner");
    // SAFETY: F_DUPFD_CLOEXEC takes a descriptor and a minimum number.
    let pin = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(pin >= 0, "dup the pin");
    // SAFETY: fcntl returned a new descriptor that nothing else owns.
    let pin = unsafe { OwnedFd::from_raw_fd(pin) };
    let anchor = pod(&fixture, &cg, "runner", vec![pin]);
    let mut out = std::io::stdout();
    let put = |out: &mut std::io::Stdout, k: &str, v: &str| {
        let _ = writeln!(out, "{}{k}={v}", probe::PREFIX);
        let _ = out.flush();
    };
    put(&mut out, "cgroup", &cg.path().display().to_string());
    put(
        &mut out,
        "tree",
        &fixture.tree().path().display().to_string(),
    );
    put(&mut out, "anchor", &anchor.pid().to_string());
    put(&mut out, "ready", "1");
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn anchor_pins_outlive_the_runner() {
    let (pin_r, pin_w) = pipe();
    // The runner gets the pipe's write end as its standard input, the only
    // copy outside the test, and its anchor pins it.
    let mut runner = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "probe", "--nocapture", "--quiet"])
        .env_clear()
        .env(probe::ACTION_VAR, "anchor-runner")
        .env(cgroup::TEST_CGROUP_VAR, "self")
        .stdin(std::process::Stdio::from(pin_w))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start the runner");
    let mut values = std::collections::BTreeMap::new();
    for line in BufReader::new(runner.stdout.take().expect("stdout")).lines() {
        let line = line.expect("a line from the runner");
        if let Some((k, v)) = line
            .find(probe::PREFIX)
            .and_then(|p| line[p + probe::PREFIX.len()..].split_once('='))
        {
            values.insert(k.to_string(), v.to_string());
            if k == "ready" {
                break;
            }
        }
    }
    assert!(
        values.contains_key("ready"),
        "the runner failed: {values:?}"
    );
    let anchor: i32 = values["anchor"].parse().expect("a pid");
    let cg = PathBuf::from(&values["cgroup"]);
    runner.kill().expect("SIGKILL the runner");
    runner.wait().expect("reap the runner");

    // The runner is gone; its anchor and the pin are not.
    assert!(alive(anchor), "the anchor {anchor} died with the runner");
    assert!(
        !hung_up(&pin_r, Duration::from_millis(200)),
        "the pin was released with the runner"
    );
    // Until the pod's cgroup is killed (#33 sweeps such pods after a crash).
    std::fs::write(cg.join("cgroup.kill"), "1").expect("cgroup.kill");
    assert!(
        hung_up(&pin_r, Duration::from_secs(10)),
        "the pin outlived cgroup.kill"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::fs::remove_dir(&cg).is_err() {
        assert!(
            Instant::now() < deadline,
            "{} stays populated",
            cg.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = std::fs::remove_dir_all(&values["tree"]);
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn anchor_invisible_to_exec() {
    let fixture = Fixture::new("anchor-invisible");
    let cg = cgroup::sandbox("anchor-invisible");
    let anchor = pod(&fixture, &cg, "invisible", Vec::new());
    // Shell builtins only, so no child shows up in /proc. The anchor's host
    // pid names no process in the exec's PID namespace.
    let script = format!(
        "set -- /proc/[0-9]*; echo \"procs=$*\"; \
         printf 'cgroup='; while read p; do printf '%s,' \"$p\"; done < /sys/fs/cgroup/cgroup.procs; echo; \
         kill -0 {} 2>/dev/null; echo kill=$?",
        anchor.pid()
    );
    let out = sh(&anchor, &script);
    let field = |k: &str| -> String {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("no {k} in {out}"))
            .to_string()
    };
    assert_eq!(field("procs"), "/proc/1", "only itself in its /proc: {out}");
    // The pod's cgroup holds the anchor and the exec; a task outside the
    // reader's PID namespace reads as 0.
    let cgroup = field("cgroup");
    let procs: BTreeSet<&str> = cgroup.split(',').filter(|s| !s.is_empty()).collect();
    assert_eq!(procs, BTreeSet::from(["0", "1"]), "{out}");
    assert_eq!(field("kill"), "1", "kill -0 of the anchor's pid: {out}");
    drop(anchor);
    cg.destroy().expect("destroy the cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn exec_is_pid1_and_takes_its_children() {
    let fixture = Fixture::new("anchor-pid1");
    let cg = cgroup::sandbox("anchor-pid1");
    let anchor = pod(&fixture, &cg, "pid1", Vec::new());
    // The inner shell starts a sleep and exits, so the sleep is orphaned;
    // its parent is then the exec, PID 1 of the exec's namespace.
    let out = sh(
        &anchor,
        "echo pid=$$; bg=$(sh -c 'sleep 30 >/dev/null 2>&1 & echo $!'); \
         while read k v; do [ \"$k\" = PPid: ] && echo ppid=$v; done < /proc/$bg/status; true",
    );
    assert!(out.contains("pid=1\n"), "{out}");
    assert!(out.contains("ppid=1\n"), "the orphan's parent: {out}");
    // The exec ended, and its PID namespace with it: only the anchor is
    // left in the pod's cgroup.
    let procs = cgroup::read(&cg, "cgroup.procs");
    assert_eq!(
        procs.split_whitespace().collect::<Vec<_>>(),
        [anchor.pid().to_string()],
        "the orphaned sleep outlived its exec"
    );
    drop(anchor);
    cg.destroy().expect("destroy the cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn execs_of_a_pod_share_loopback() {
    let fixture = Fixture::new("anchor-loopback");
    let cg = cgroup::sandbox("anchor-loopback");
    let first = pod(&fixture, &cg, "db", Vec::new());
    assert!(first.families().ipv4, "{:?}", first.families());
    let second = joined(&first, &fixture, &cg, "app");
    assert_eq!(second.families(), first.families(), "one network namespace");
    // The families the anchor found are what lo has inside.
    let inet6 = sh(&first, "cat /proc/net/if_inet6 2>/dev/null; true");
    let has_v6 = inet6
        .lines()
        .any(|l| l.starts_with("00000000000000000000000000000001") && l.ends_with(" lo"));
    assert_eq!(first.families().ipv6, has_v6, "{inet6}");
    // Each container has its own UTS namespace.
    assert_eq!(
        sh(&first, "read h < /proc/sys/kernel/hostname; echo $h"),
        "db\n"
    );
    assert_eq!(
        sh(&second, "read h < /proc/sys/kernel/hostname; echo $h"),
        "app\n"
    );

    // A server in the first container, clients in both.
    for client in [&first, &second] {
        let (out_r, out_w) = pipe();
        let stdio = Stdio {
            stdin: dev_null(),
            stdout: out_w,
            stderr: dev_null(),
        };
        let spec = exec_spec(
            rootfs::PROBE,
            &["--exact", "probe", "--nocapture", "--quiet"],
            &[
                (probe::ACTION_VAR, "tcp-serve"),
                ("BONELI_PROBE_PORT", PORT),
            ],
        );
        let mut server = first.exec(&spec, stdio).expect("start the server");
        let mut lines = BufReader::new(File::from(out_r)).lines();
        assert!(
            lines.any(|l| l.is_ok_and(|l| l.contains("listening=1"))),
            "the server did not listen"
        );
        let p = probe_in(client, "tcp-connect", &[("BONELI_PROBE_PORT", PORT)]);
        p.assert_ok();
        assert_eq!(p.get("connect_errno"), "0", "{}", p.raw);
        assert_eq!(p.get("byte"), "k", "{}", p.raw);
        assert_eq!(
            wait_bounded(&mut server, support::PROBE_HANG_BOUND),
            ExitStatus::Exited(0)
        );
    }
    drop(second);
    drop(first);
    cg.destroy().expect("destroy the cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn pods_do_not_share_loopback() {
    let fixture = Fixture::new("anchor-pods");
    let cg_a = cgroup::sandbox("anchor-pod-a");
    let cg_b = cgroup::sandbox("anchor-pod-b");
    let a = pod(&fixture, &cg_a, "a", Vec::new());
    let b = pod(&fixture, &cg_b, "b", Vec::new());
    let (out_r, out_w) = pipe();
    let stdio = Stdio {
        stdin: dev_null(),
        stdout: out_w,
        stderr: dev_null(),
    };
    let spec = exec_spec(
        rootfs::PROBE,
        &["--exact", "probe", "--nocapture", "--quiet"],
        &[
            (probe::ACTION_VAR, "tcp-serve"),
            ("BONELI_PROBE_PORT", PORT),
        ],
    );
    let mut server = a.exec(&spec, stdio).expect("start the server");
    let mut lines = BufReader::new(File::from(out_r)).lines();
    assert!(
        lines.any(|l| l.is_ok_and(|l| l.contains("listening=1"))),
        "the server did not listen"
    );
    let p = probe_in(&b, "tcp-connect", &[("BONELI_PROBE_PORT", PORT)]);
    p.assert_ok();
    assert_eq!(
        p.get("connect_errno"),
        libc::ECONNREFUSED.to_string(),
        "another pod reached the server: {}",
        p.raw
    );
    // The control: the server's own pod reaches it.
    let own = probe_in(&a, "tcp-connect", &[("BONELI_PROBE_PORT", PORT)]);
    assert_eq!(own.get("connect_errno"), "0", "{}", own.raw);
    wait_bounded(&mut server, support::PROBE_HANG_BOUND);
    drop((a, b));
    cg_a.destroy().expect("destroy pod a");
    cg_b.destroy().expect("destroy pod b");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn execs_share_the_container_tmpfs() {
    let fixture = Fixture::new("anchor-tmpfs");
    let cg = cgroup::sandbox("anchor-tmpfs");
    let spec = anchor_spec(&fixture, &cg, "tmpfs", Vec::new());
    let mut anchor = Anchor::create(&spec).expect("create");
    {
        // The runner writes into the workspace tmpfs at the fill point.
        let fill = anchor.fill().expect("at the fill point");
        let ws = fill.open(&inside("/workspace")).expect("open /workspace");
        // SAFETY: the name is NUL-terminated; ws is an open directory.
        let fd = unsafe {
            libc::openat(
                ws.as_raw_fd(),
                c"seed".as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
                0o644 as libc::c_uint,
            )
        };
        assert!(fd >= 0, "create seed: {}", std::io::Error::last_os_error());
        // SAFETY: openat returned a new descriptor that nothing else owns.
        File::from(unsafe { OwnedFd::from_raw_fd(fd) })
            .write_all(b"filled\n")
            .expect("write seed");
        fill.resume().expect("resume");
    }
    let first = sh(
        &anchor,
        "cat /workspace/seed; echo one > /workspace/a; echo two > /tmp/b; \
         stat -f -c inodes=%c /workspace",
    );
    assert!(first.starts_with("filled\n"), "{first}");
    assert!(
        first.contains(&format!("inodes={}\n", rootfs::WORKSPACE_INODES)),
        "the workspace's nr_inodes: {first}"
    );
    assert_eq!(sh(&anchor, "cat /workspace/a /tmp/b"), "one\ntwo\n");
    drop(anchor);
    drop(spec);
    cg.destroy().expect("destroy the cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn fill_follows_no_symlink() {
    let fixture = Fixture::new("anchor-fill-link");
    // A hostile image: a symlink to the host's root, which the runner
    // would follow as the runner user.
    std::os::unix::fs::symlink("/", fixture.layer.join("escape")).expect("symlink");
    let cg = cgroup::sandbox("anchor-fill-link");
    let spec = anchor_spec(&fixture, &cg, "link", Vec::new());
    let mut anchor = Anchor::create(&spec).expect("create");
    let fill = anchor.fill().expect("at the fill point");
    for path in ["/escape", "/escape/etc"] {
        match fill.open(&inside(path)) {
            Err(Error::Sys { errno, .. }) => assert_eq!(errno, libc::ELOOP, "{path}"),
            other => panic!("{path}: {other:?}"),
        }
    }
    assert!(fill.open(&inside("/workspace")).is_ok());
    fill.resume().expect("resume");
    drop(anchor);
    drop(spec);
    cg.destroy().expect("destroy the cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn anchor_descriptors_are_its_pins() {
    let fixture = Fixture::new("anchor-fds");
    let cg = cgroup::sandbox("anchor-fds");
    let (_read, write) = pipe();
    let exe: OwnedFd = File::open(std::env::current_exe().expect("current_exe"))
        .expect("open the test binary")
        .into();
    let pins = vec![write, dev_null(), exe];
    let mut want: Vec<(u64, u64)> = pins.iter().map(|p| identity(p.as_fd())).collect();
    want.sort_unstable();
    let anchor = pod(&fixture, &cg, "fds", pins);
    let mut held: Vec<(u64, u64)> = std::fs::read_dir(format!("/proc/{}/fd", anchor.pid()))
        .expect("list the anchor's descriptors")
        .map(|e| {
            let path = e.expect("an fd entry").path();
            let st = std::fs::metadata(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            use std::os::unix::fs::MetadataExt;
            (st.dev(), st.ino())
        })
        .collect();
    held.sort_unstable();
    assert_eq!(held, want, "exactly the pins, nothing else");
    drop(anchor);
    cg.destroy().expect("destroy the cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn anchors_at_the_fill_point_hold_no_runner_descriptor() {
    // While one anchor waits at its fill point, the runner sets up other
    // pods: a copy of their report pipes in the waiting anchor would hold
    // those setups until its own fill ends. The pipe stands for one.
    let fixture = Fixture::new("anchor-fill-fds");
    let cg = cgroup::sandbox("anchor-fill-fds");
    let cg_other = cgroup::sandbox("anchor-fill-fds-other");
    let pod_anchor = pod(&fixture, &cg, "fill-fds", Vec::new());
    let (read, write) = pipe();
    let spec_first = anchor_spec(&fixture, &cg_other, "fill-a", Vec::new());
    let first = Anchor::create(&spec_first).expect("create, waiting at the fill point");
    let spec_joined = anchor_spec(&fixture, &cg, "fill-b", Vec::new());
    let joined = pod_anchor
        .join(&spec_joined)
        .expect("join, waiting at the fill point");
    drop(write);
    assert!(
        hung_up(&read, Duration::from_secs(1)),
        "an anchor at its fill point holds a copy of the runner's pipe"
    );
    // At the fill point each holds its report pipe, its resume socket and
    // its new root, the staging directory, for the mounts after the fill.
    let staging = spec_first.root.staging.display().to_string();
    for anchor in [&first, &joined] {
        let mut kinds: Vec<String> = std::fs::read_dir(format!("/proc/{}/fd", anchor.pid()))
            .expect("list the descriptors")
            .map(|e| {
                let link = std::fs::read_link(e.expect("an fd entry").path()).expect("readlink");
                let link = link.display().to_string();
                match link.split_once(':') {
                    Some((kind, _)) if kind == "pipe" || kind == "socket" => kind.to_string(),
                    _ => link,
                }
            })
            .collect();
        kinds.sort();
        assert_eq!(
            kinds,
            [staging.clone(), "pipe".to_string(), "socket".to_string()],
            "{}",
            anchor.pid()
        );
    }
    drop((first, joined, pod_anchor));
    cg.destroy().expect("destroy the cgroup");
    cg_other.destroy().expect("destroy the other cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn anchor_holds_no_privileges() {
    let fixture = Fixture::new("anchor-privs");
    let cg = cgroup::sandbox("anchor-privs");
    let first = pod(&fixture, &cg, "privs", Vec::new());
    let second = joined(&first, &fixture, &cg, "privs2");
    // SAFETY: getpid has no preconditions and cannot fail.
    let runner = unsafe { libc::getpid() };
    for anchor in [&first, &second] {
        let pid = anchor.pid();
        // Both are the runner's children, the joined one through
        // CLONE_PARENT, so only the runner reaps them.
        assert_eq!(status_field(pid, "PPid"), runner.to_string(), "{pid}");
        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            assert_eq!(status_field(pid, key), "0000000000000000", "{pid} {key}");
        }
        assert_eq!(status_field(pid, "NoNewPrivs"), "1", "{pid}");
        assert_eq!(status_field(pid, "Seccomp"), "2", "{pid}: a filter");
        // Every signal blocked but SIGKILL and SIGSTOP, which the kernel
        // never blocks: only SIGKILL ends it.
        assert_eq!(status_field(pid, "SigBlk"), "fffffffffffbfeff", "{pid}");
    }
    drop((second, first));
    cg.destroy().expect("destroy the cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn anchor_releases_runner_memory() {
    // 256 MiB of dirty heap in the runner before the clone: without the
    // release the anchor keeps it, copy-on-write, for the pod's life.
    const DIRTY: usize = 268_435_456;
    const BOUND_KIB: u64 = 64 << 10;
    let mut heap = vec![0u8; DIRTY];
    for i in (0..DIRTY).step_by(4096) {
        heap[i] = 1;
    }
    let runner_kib = anonymous_kib("self");
    assert!(
        runner_kib >= (DIRTY as u64 >> 10),
        "the buffer is not counted: {runner_kib} kB"
    );
    let fixture = Fixture::new("anchor-memory");
    let cg = cgroup::sandbox("anchor-memory");
    let first = pod(&fixture, &cg, "memory", Vec::new());
    let second = joined(&first, &fixture, &cg, "memory2");
    std::hint::black_box(&heap);
    for (kind, anchor) in [("first", &first), ("joined", &second)] {
        let kib = anonymous_kib(&anchor.pid().to_string());
        report(&format!(
            "anchor_releases_runner_memory: {kind} anchor Anonymous {kib} kB \
             after the release; the runner holds {runner_kib} kB"
        ));
        assert!(
            kib < BOUND_KIB,
            "the {kind} anchor keeps {kib} kB of the runner's memory"
        );
    }
    drop(heap);
    drop((second, first));
    cg.destroy().expect("destroy the cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn join_to_dead_anchor_fails() {
    let fixture = Fixture::new("anchor-dead");
    let cg = cgroup::sandbox("anchor-dead");
    let anchor = pod(&fixture, &cg, "dead", Vec::new());
    // SAFETY: pidfd_send_signal takes a descriptor, a signal and no info.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            anchor.pidfd().as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    assert_eq!(rc, 0, "kill the anchor");
    let mut pfd = libc::pollfd {
        fd: anchor.pidfd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pfd is one valid pollfd for the call's duration.
    let rc = unsafe { libc::poll(&mut pfd, 1, 10_000) };
    assert_eq!(rc, 1, "the anchor died");
    let start = Instant::now();
    let exec = anchor
        .exec(&exec_spec("/bin/true", &[], &[]), {
            Stdio {
                stdin: dev_null(),
                stdout: dev_null(),
                stderr: dev_null(),
            }
        })
        .map(|_| ());
    let join = anchor
        .join(&anchor_spec(&fixture, &cg, "dead2", Vec::new()))
        .map(|_| ());
    for (what, result) in [("exec", exec), ("join", join)] {
        match result {
            Err(Error::Setup {
                step: Step::Setns,
                errno,
                ..
            }) => assert_eq!(errno, libc::ESRCH, "{what}"),
            other => panic!("{what}: {other:?}"),
        }
    }
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "not prompt: {:?}",
        start.elapsed()
    );
    drop(anchor);
    cg.destroy().expect("destroy the cgroup");
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn exec_refuses_nul_and_relative() {
    let fixture = Fixture::new("anchor-nul");
    let cg = cgroup::sandbox("anchor-nul");
    let anchor = pod(&fixture, &cg, "nul", Vec::new());
    let null = || Stdio {
        stdin: dev_null(),
        stdout: dev_null(),
        stderr: dev_null(),
    };
    let relative = anchor.exec(&exec_spec("bin/true", &[], &[]), null());
    assert!(
        matches!(relative, Err(Error::RelativeProgram(_))),
        "{relative:?}"
    );
    let arg = anchor.exec(&exec_spec("/bin/true", &["a\0b"], &[]), null());
    assert!(matches!(arg, Err(Error::Nul("an argument"))), "{arg:?}");
    let env = anchor.exec(&exec_spec("/bin/true", &[], &[("A", "x\0y")]), null());
    assert!(
        matches!(env, Err(Error::Nul("an environment entry"))),
        "{env:?}"
    );
    let program = anchor.exec(&exec_spec("/bin/tr\0ue", &[], &[]), null());
    assert!(
        matches!(program, Err(Error::Nul("the program path"))),
        "{program:?}"
    );
    drop(anchor);
    cg.destroy().expect("destroy the cgroup");
}

/// Prints the setup times ADR-042 D8's hang bounds are derived from: 50
/// runs of each kind, min, median, p95 and max.
#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn setup_timing_report() {
    const RUNS: usize = 50;
    let _exclusive = support::exclusive();
    let fixture = Fixture::new("anchor-timing");
    let cg = cgroup::sandbox("anchor-timing");
    let summary = |kind: &str, mut times: Vec<Duration>| {
        times.sort_unstable();
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        report(&format!(
            "setup_timing_report: {kind} over {RUNS} runs: min {:.1} ms, median {:.1} ms, \
             p95 {:.1} ms, max {:.1} ms",
            ms(times[0]),
            ms(times[RUNS / 2]),
            ms(times[RUNS * 95 / 100]),
            ms(times[RUNS - 1]),
        ));
    };
    let mut creates = Vec::new();
    for _ in 0..RUNS {
        let start = Instant::now();
        let anchor = pod(&fixture, &cg, "timing", Vec::new());
        creates.push(start.elapsed());
        drop(anchor);
    }
    summary("create + resume of a first anchor", creates);
    let first = pod(&fixture, &cg, "timing", Vec::new());
    let mut joins = Vec::new();
    for _ in 0..RUNS {
        let start = Instant::now();
        let anchor = joined(&first, &fixture, &cg, "timing2");
        joins.push(start.elapsed());
        drop(anchor);
    }
    summary("join + resume of a later anchor", joins);
    let mut execs = Vec::new();
    for _ in 0..RUNS {
        let null = Stdio {
            stdin: dev_null(),
            stdout: dev_null(),
            stderr: dev_null(),
        };
        let start = Instant::now();
        let mut child = first
            .exec(&exec_spec("/bin/true", &[], &[]), null)
            .expect("exec");
        execs.push(start.elapsed());
        assert_eq!(child.wait().expect("wait"), ExitStatus::Exited(0));
    }
    summary("exec to the program", execs);
    drop(first);
    cg.destroy().expect("destroy the cgroup");
}

/// `(start, end)` of every mapping of `pid`.
fn ranges_of(pid: &str) -> Vec<(usize, usize)> {
    std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .expect("read maps")
        .lines()
        .filter_map(|l| {
            let (s, e) = l.split_whitespace().next()?.split_once('-')?;
            Some((
                usize::from_str_radix(s, 16).ok()?,
                usize::from_str_radix(e, 16).ok()?,
            ))
        })
        .collect()
}

/// Whether `pid` maps `addr`, and if so whether `want` reads back there
/// through `/proc/<pid>/mem`.
fn holds(pid: &str, addr: usize, want: &[u8]) -> (bool, bool) {
    use std::io::{Seek, SeekFrom};
    let mapped = ranges_of(pid).iter().any(|&(s, e)| s <= addr && addr < e);
    if !mapped {
        return (false, false);
    }
    let mut mem = File::open(format!("/proc/{pid}/mem")).expect("open mem");
    mem.seek(SeekFrom::Start(addr as u64)).expect("seek");
    let mut got = vec![0u8; want.len()];
    let read = mem.read_exact(&mut got).is_ok() && got == want;
    (true, read)
}

/// A secret marker no test writes elsewhere.
const SECRET: &[u8] = b"boneli-anchor-secret-marker-7f3a5c91e0d2";

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn runner_buffers_next_to_named_mappings_are_released() {
    // Review run 1: a runner buffer that starts where a named mapping
    // ends, a shared anonymous page (the pid page of a concurrent join)
    // or a private file mapping, is runner heap, not an ELF object's
    // `.bss`, and goes with the release.
    const LEN: usize = 32 << 20;
    let fixture = Fixture::new("anchor-adjacent");
    let exe = File::open(std::env::current_exe().expect("current_exe")).expect("open the binary");
    for below in ["shared page", "file mapping"] {
        // SAFETY: an anonymous private mapping with no address hint.
        let buf = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(buf, libc::MAP_FAILED);
        // SAFETY: buf is LEN writable bytes, used only here.
        let slice = unsafe { std::slice::from_raw_parts_mut(buf.cast::<u8>(), LEN) };
        for i in (0..LEN).step_by(4096) {
            slice[i] = 1;
        }
        slice[8192..8192 + SECRET.len()].copy_from_slice(SECRET);
        let (flags, fd, prot) = if below == "shared page" {
            (
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } else {
            (libc::MAP_PRIVATE, exe.as_raw_fd(), libc::PROT_READ)
        };
        // SAFETY: one page right below the buffer, refused if anything is
        // mapped there.
        let page = unsafe {
            libc::mmap(
                (buf as usize - 4096) as *mut libc::c_void,
                4096,
                prot,
                flags | libc::MAP_FIXED_NOREPLACE,
                fd,
                0,
            )
        };
        assert_eq!(
            page as usize,
            buf as usize - 4096,
            "{below} right below the buffer"
        );
        let cg = cgroup::sandbox("anchor-adjacent");
        let anchor = pod(&fixture, &cg, "adjacent", Vec::new());
        // The runner is done with the secret: it zeroes and unmaps both.
        slice[8192..8192 + SECRET.len()].fill(0);
        // SAFETY: both were mapped above with these lengths.
        unsafe { libc::munmap(buf, LEN) };
        // SAFETY: as above.
        unsafe { libc::munmap(page, 4096) };
        let pid = anchor.pid().to_string();
        let (mapped, readable) = holds(&pid, buf as usize + 8192, SECRET);
        let kib = anonymous_kib(&pid);
        report(&format!(
            "runner_buffers_next_to_named_mappings_are_released: after a {below}: \
             buffer mapped {mapped}, secret readable {readable}, anchor Anonymous {kib} kB"
        ));
        assert!(
            !mapped,
            "the anchor keeps the runner's buffer after a {below}"
        );
        drop(anchor);
        cg.destroy().expect("destroy the cgroup");
    }
}

/// Set when the test below re-executes this binary: the constructor then
/// creates a pod on the process's main thread, before libtest's `main`.
const MAIN_ANCHOR_VAR: &str = "BONELI_SYS_MAIN_ANCHOR";

/// The environment variable whose value the main-thread runner holds on
/// its `[stack]`, as a token in a runner's environment would be.
const MAIN_SECRET_VAR: &str = "BONELI_SYS_MAIN_SECRET";

// Runs on the main thread before `main` (ELF `.init_array`), where libtest
// would never run a test: the only way to clone an anchor from the
// runner's main thread, whose `[stack]` holds `envp` and `argv`.
#[used]
#[unsafe(link_section = ".init_array")]
static MAIN_ANCHOR: extern "C" fn() = main_anchor;

/// Fills a deep stack frame with the secret and returns its address:
/// stale data far below the frame that creates the anchor.
#[inline(never)]
fn stale_secret() -> usize {
    let mut frame = [0u8; 1 << 20];
    frame[..SECRET.len()].copy_from_slice(SECRET);
    std::hint::black_box(&mut frame);
    frame.as_ptr() as usize
}

extern "C" fn main_anchor() {
    if std::env::var_os(MAIN_ANCHOR_VAR).is_none() {
        return;
    }
    // SAFETY: the name is NUL-terminated; getenv returns a pointer into the
    // environment block on the main thread's stack, or null.
    let env = unsafe { libc::getenv(c"BONELI_SYS_MAIN_SECRET".as_ptr()) } as usize;
    let stale = stale_secret();
    let fixture = Fixture::new("anchor-main");
    let cg = cgroup::sandbox("anchor-main");
    let anchor = pod(&fixture, &cg, "main", Vec::new());
    let mut out = std::io::stdout();
    let _ = writeln!(out, "anchor={} env={env} stale={stale}", anchor.pid());
    let _ = out.flush();
    // Holds the pod until the test closes stdin.
    let mut rest = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut rest);
    drop(anchor);
    let code = i32::from(cg.destroy().is_err());
    let _ = out.flush();
    // SAFETY: _exit ends the process before libtest's main runs.
    unsafe { libc::_exit(code) }
}

#[test]
#[ignore = "host: unprivileged user namespaces, cgroup v2 delegation"]
fn main_thread_anchor_keeps_no_runner_stack() {
    // Review run 1: an anchor cloned on the runner's main thread kept that
    // thread's whole `[stack]`: the environment block at its top and the
    // stale frames below.
    let secret = std::str::from_utf8(SECRET).expect("ascii");
    let mut runner = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "probe", "--quiet"])
        .env_clear()
        .env(MAIN_ANCHOR_VAR, "1")
        .env(MAIN_SECRET_VAR, secret)
        .env(cgroup::TEST_CGROUP_VAR, "self")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start the main-thread runner");
    let mut line = String::new();
    BufReader::new(runner.stdout.take().expect("stdout"))
        .read_line(&mut line)
        .expect("the runner's line");
    let field = |k: &str| -> usize {
        line.split_whitespace()
            .find_map(|f| f.strip_prefix(&format!("{k}=")))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("no {k} in {line:?}"))
    };
    let (anchor, env, stale) = (field("anchor").to_string(), field("env"), field("stale"));
    let runner_pid = runner.id().to_string();
    // The control: both secrets are where the runner says.
    assert_eq!(
        holds(&runner_pid, env, SECRET),
        (true, true),
        "env in the runner"
    );
    assert_eq!(
        holds(&runner_pid, stale, SECRET),
        (true, true),
        "stale frame in the runner"
    );
    let in_env = holds(&anchor, env, SECRET);
    let in_stale = holds(&anchor, stale, SECRET);
    let kib = anonymous_kib(&anchor);
    report(&format!(
        "main_thread_anchor_keeps_no_runner_stack: env {in_env:?}, stale frame {in_stale:?}, \
         anchor Anonymous {kib} kB"
    ));
    drop(runner.stdin.take());
    let status = runner.wait().expect("reap the runner");
    assert!(status.success(), "the runner's teardown: {status:?}");
    assert_eq!(
        in_env,
        (false, false),
        "the anchor keeps the runner's environment"
    );
    assert_eq!(
        in_stale,
        (false, false),
        "the anchor keeps a stale runner frame"
    );
}
