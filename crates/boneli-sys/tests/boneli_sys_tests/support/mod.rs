//! Test harness: temp dirs, pipes, a reporter libtest does not capture,
//! bounded waits and the probe runner (ADR-007, D5).

pub mod alloc_guard;
pub mod cgroup;
pub mod probe;
pub mod rootfs;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use boneli_sys::{Cgroup, Child, ExitStatus, Ids, Root, Spec, Stdio, spawn};

/// Hang bound of one probe run. A probe is this test binary started inside
/// the sandbox; on a loaded CI host it starts in well under a second, so
/// reaching 30 s means it hangs.
pub const PROBE_HANG_BOUND: Duration = Duration::from_secs(30);

/// Setup timeout of the spawns in the host tests: a hang bound for the
/// child's setup, which takes milliseconds.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Writes one line to the test's stderr directly. libtest captures the
/// `print!` family, not writes to the stream itself, so the line shows in
/// every run (used for `n/a` and leniency notes, ADR-007, D5).
pub fn report(line: &str) {
    let mut err = std::io::stderr();
    // A failed write to stderr leaves nothing to report to.
    let _ = writeln!(err, "boneli-sys test: {line}");
}

/// A directory under `CARGO_TARGET_TMPDIR`, unique per process and call,
/// removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates `<CARGO_TARGET_TMPDIR>/<tag>-<pid>-<counter>`.
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create the test's temp dir");
        TempDir { path }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A pipe, both ends close-on-exec: `(read, write)`.
pub fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: fds is a valid array of two ints for pipe2 to fill.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2: {}", std::io::Error::last_os_error());
    // SAFETY: pipe2 succeeded, so both fds are open and owned by nobody else.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: as above, for the write end.
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    (read, write)
}

/// `/dev/null` opened for reading and writing.
pub fn dev_null() -> OwnedFd {
    File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null")
        .into()
}

/// Waits for the child, failing the test after `bound` (a hang bound).
pub fn wait_bounded(child: &mut Child, bound: Duration) -> ExitStatus {
    let deadline = Instant::now() + bound;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "child {} still running after {bound:?}",
            child.pid()
        );
        let mut pfd = libc::pollfd {
            fd: child.pidfd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = left.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: pfd is one valid pollfd for the duration of the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms.max(1)) };
        if rc > 0 {
            return child.wait().expect("wait for the child");
        }
        assert!(
            rc == 0 || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted,
            "poll on the pidfd failed"
        );
    }
}

/// The output of one program run in a sandbox.
pub struct Output {
    /// How the program ended.
    pub status: ExitStatus,
    /// Everything it wrote to stdout.
    pub stdout: String,
    /// Everything it wrote to stderr.
    pub stderr: String,
}

/// Runs `program` (a path inside the sandbox) in a sandbox on a default
/// fixture root with the given ids and environment and collects its
/// output.
pub fn run(program: &Path, args: &[&str], ids: Ids, env: &[(&str, &str)]) -> Output {
    let fixture = rootfs::Fixture::new("run");
    run_on(program, args, ids, env, fixture.root())
}

/// [`run`] on the given root, in a cgroup with the harness's default
/// limits ([`cgroup::default_limits`]) that is removed afterwards.
pub fn run_on(program: &Path, args: &[&str], ids: Ids, env: &[(&str, &str)], root: Root) -> Output {
    let cg = cgroup::sandbox("run");
    let out = run_in(program, args, ids, env, root, &cg);
    cg.destroy().expect("destroy the run's cgroup");
    out
}

/// Every sandbox run takes this lock shared, and so do the tests that
/// load the host between runs (a swap thread, a churn thread); the timing
/// tests take it exclusively ([`exclusive`]), so their limits are measured
/// without the rest of this binary competing for the CPU and the disk.
static RUNS: std::sync::RwLock<()> = std::sync::RwLock::new(());

std::thread_local! {
    /// Whether this thread holds [`RUNS`], shared or exclusively, so its
    /// own runs do not take it again (a second read lock behind a waiting
    /// writer would deadlock).
    static HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Holds [`RUNS`] until dropped.
pub struct RunsGuard {
    _shared: Option<std::sync::RwLockReadGuard<'static, ()>>,
    _exclusive: Option<std::sync::RwLockWriteGuard<'static, ()>>,
}

impl Drop for RunsGuard {
    fn drop(&mut self) {
        HELD.with(|h| h.set(false));
    }
}

/// Waits until no other sandbox run of this binary is in progress and
/// keeps new ones out until the guard drops; this thread's own runs go
/// ahead.
pub fn exclusive() -> RunsGuard {
    let guard = RUNS.write().unwrap_or_else(|p| p.into_inner());
    HELD.with(|h| h.set(true));
    RunsGuard {
        _shared: None,
        _exclusive: Some(guard),
    }
}

/// Holds [`RUNS`] shared for a whole test that loads the host between its
/// runs; `None` if this thread holds it already.
pub fn shared() -> Option<RunsGuard> {
    if HELD.with(std::cell::Cell::get) {
        return None;
    }
    let guard = RUNS.read().unwrap_or_else(|p| p.into_inner());
    HELD.with(|h| h.set(true));
    Some(RunsGuard {
        _shared: Some(guard),
        _exclusive: None,
    })
}

/// [`run_on`] in the given cgroup, which stays.
pub fn run_in(
    program: &Path,
    args: &[&str],
    ids: Ids,
    env: &[(&str, &str)],
    root: Root,
    cgroup: &Cgroup,
) -> Output {
    let _runs = shared();
    let (out_r, out_w) = pipe();
    let (err_r, err_w) = pipe();
    let spec = Spec {
        program: program.to_path_buf(),
        args: args.iter().map(OsString::from).collect(),
        env: env
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect(),
        stdio: Stdio {
            stdin: dev_null(),
            stdout: out_w,
            stderr: err_w,
        },
        ids,
        setup_timeout: SETUP_TIMEOUT,
        root,
        cgroup,
    };
    let mut child = spawn(&spec).unwrap_or_else(|e| panic!("spawn {}: {e}", program.display()));
    // The write ends live in the spec; dropping it leaves the child as the
    // only writer, so the reads below end when it exits.
    drop(spec);
    let err_reader = std::thread::spawn(move || read_all(err_r));
    let stdout = read_all(out_r);
    let status = wait_bounded(&mut child, PROBE_HANG_BOUND);
    let stderr = err_reader.join().expect("stderr reader");
    Output {
        status,
        stdout,
        stderr,
    }
}

fn read_all(fd: OwnedFd) -> String {
    let mut buf = Vec::new();
    File::from(fd)
        .read_to_end(&mut buf)
        .expect("read a pipe from the child");
    String::from_utf8_lossy(&buf).into_owned()
}

/// The parsed result of a probe run.
pub struct Probe {
    /// How the probe ended.
    pub status: ExitStatus,
    /// Its `BONELI_PROBE key=value` lines; a repeated key keeps the last.
    pub values: BTreeMap<String, String>,
    /// Every such line in order.
    pub lines: Vec<(String, String)>,
    /// Raw output, for failure messages.
    pub raw: String,
}

impl Probe {
    /// The value of `key`, failing the test when the probe did not print it.
    pub fn get(&self, key: &str) -> &str {
        match self.values.get(key) {
            Some(v) => v,
            None => panic!("probe printed no {key}; output:\n{}", self.raw),
        }
    }

    /// Fails the test unless the probe exited 0.
    pub fn assert_ok(&self) {
        assert_eq!(
            self.status,
            ExitStatus::Exited(0),
            "probe failed; output:\n{}",
            self.raw
        );
    }
}

/// Re-executes this test binary inside a sandbox on a default fixture
/// root as a probe for `action` with the given ids. `env` is added to the
/// probe's environment, which otherwise holds only the action.
pub fn run_probe(action: &str, ids: Ids, env: &[(&str, &str)]) -> Probe {
    let fixture = rootfs::Fixture::new("probe");
    run_probe_on(action, ids, env, fixture.root())
}

/// [`run_probe`] on the given root, which must bind this test binary at
/// [`rootfs::PROBE`] (as [`rootfs::Fixture::mounts`] does).
pub fn run_probe_on(action: &str, ids: Ids, env: &[(&str, &str)], root: Root) -> Probe {
    let cg = cgroup::sandbox("probe");
    let p = run_probe_in(action, ids, env, root, &cg);
    cg.destroy().expect("destroy the probe's cgroup");
    p
}

/// [`run_probe_on`] in the given cgroup, which stays.
pub fn run_probe_in(
    action: &str,
    ids: Ids,
    env: &[(&str, &str)],
    root: Root,
    cgroup: &Cgroup,
) -> Probe {
    let mut full = vec![(probe::ACTION_VAR, action)];
    full.extend_from_slice(env);
    let out = run_in(
        Path::new(rootfs::PROBE),
        &["--exact", "probe", "--nocapture", "--quiet"],
        ids,
        &full,
        root,
        cgroup,
    );
    parse_probe(out)
}

/// Parses `BONELI_PROBE key=value` lines anywhere in stdout: libtest may
/// print its own text on the same line.
pub fn parse_probe(out: Output) -> Probe {
    let mut values = BTreeMap::new();
    let mut lines = Vec::new();
    for line in out.stdout.lines() {
        if let Some(pos) = line.find(probe::PREFIX) {
            let rest = &line[pos + probe::PREFIX.len()..];
            if let Some((k, v)) = rest.split_once('=') {
                values.insert(k.to_string(), v.to_string());
                lines.push((k.to_string(), v.to_string()));
            }
        }
    }
    let raw = format!(
        "status {:?}\n--- stdout\n{}--- stderr\n{}",
        out.status, out.stdout, out.stderr
    );
    Probe {
        status: out.status,
        values,
        lines,
        raw,
    }
}

/// Ids for a test, failing on an invalid id.
pub fn ids(uid: u32, gid: u32) -> Ids {
    Ids::new(uid, gid).expect("valid test ids")
}

/// The caller's effective uid and gid.
pub fn host_ids() -> (u32, u32) {
    // SAFETY: geteuid and getegid have no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: as above.
    let gid = unsafe { libc::getegid() };
    (uid, gid)
}

/// Reads a number from a `/proc` or `/sys` file.
pub fn read_number(path: &str) -> u64 {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    text.trim()
        .parse()
        .unwrap_or_else(|e| panic!("parse {path} ({text:?}): {e}"))
}
