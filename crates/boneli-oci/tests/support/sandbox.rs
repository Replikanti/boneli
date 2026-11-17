//! The sandbox harness of the `boneli-oci` host tests, after
//! `boneli-sys`'s (ADR-007, D5): a delegated cgroup parent under
//! `BONELI_SYS_TEST_CGROUP=self`, a base layer with the mount points, and
//! runs of a program or of this test binary as a probe. Std and the
//! `boneli-sys` API only: this crate forbids `unsafe`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use boneli_sys::{
    Cgroup, CpuMax, ExitStatus, Hostname, Ids, InsidePath, IoLimits, Limits, Mount, Parent, Root,
    Spec, Stdio, spawn,
};

/// Set to `self` when the run has a delegated scope of its own (CLAUDE.md,
/// "Host tests"); the same variable as `boneli-sys`'s harness.
pub const TEST_CGROUP_VAR: &str = "BONELI_SYS_TEST_CGROUP";

/// The probe action of a re-executed test binary.
pub const ACTION_VAR: &str = "BONELI_OCI_PROBE";

/// The paths a `stat` probe reports, comma-separated.
pub const PATHS_VAR: &str = "BONELI_OCI_PROBE_PATHS";

/// The prefix of a probe's output lines.
pub const PREFIX: &str = "BONELI_PROBE ";

/// Where this test binary appears inside the sandbox.
pub const PROBE: &str = "/probe";

/// The name `Parent::vacate_and_delegate` moves the scope's processes to.
const LEAF: &str = "leaf";

/// Hang bound of one run: a probe starts in well under a second and
/// `node --version` in about one, so 120 s means it hangs (a cold CI disk
/// pages the image in on first use).
pub const HANG_BOUND: Duration = Duration::from_secs(120);

/// Setup timeout of a spawn: a hang bound for the child's setup, which
/// takes milliseconds.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// The memory limit of a test sandbox: node and postgres print their
/// version in well under 256 MiB.
pub const MEMORY_MAX: u64 = 256 << 20;

/// The task limit: the program, libtest's threads, node's worker threads.
pub const PIDS_MAX: u64 = 64;

/// The run's own cgroup, from `/proc/self/cgroup`.
fn own_cgroup() -> PathBuf {
    let text = std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
    let own = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .expect("a cgroup v2 line in /proc/self/cgroup");
    Path::new("/sys/fs/cgroup").join(own.trim_start_matches('/'))
}

/// The delegated parent of every test sandbox's cgroup, as in
/// `boneli-sys`'s harness: only with `BONELI_SYS_TEST_CGROUP=self`.
pub fn parent() -> &'static Parent {
    static PARENT: OnceLock<Parent> = OnceLock::new();
    PARENT.get_or_init(|| {
        let mode = std::env::var(TEST_CGROUP_VAR).unwrap_or_default();
        assert_eq!(
            mode, "self",
            "host tests need {TEST_CGROUP_VAR}=self in a delegated scope of their own \
             (systemd-run --user --scope -p Delegate=yes, CLAUDE.md \"Host tests\")"
        );
        let own = own_cgroup();
        if own.file_name().is_some_and(|n| n == LEAF) {
            let up = own.parent().expect("leaf/ has a parent");
            if let Ok(parent) = Parent::open(up) {
                return parent;
            }
        }
        Parent::vacate_and_delegate(&own)
            .unwrap_or_else(|e| panic!("delegate {}: {e}", own.display()))
    })
}

/// A cgroup for one run, with the limits above, one CPU and no IO limit.
pub fn cgroup(tag: &str) -> Cgroup {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("oci-{tag}-{}-{n}", std::process::id());
    let limits = Limits {
        memory_max: MEMORY_MAX,
        memory_swap_max: 0,
        pids_max: PIDS_MAX,
        cpu: CpuMax {
            quota_us: 100_000,
            period_us: 100_000,
        },
        io: IoLimits::none(),
    };
    Cgroup::create(parent(), &name, &limits).unwrap_or_else(|e| panic!("cgroup {name}: {e}"))
}

/// An inside path, failing the test on a bad one.
pub fn inside(path: &str) -> InsidePath {
    InsidePath::new(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The directories of the base layer: the mount points.
const DIRS: [&str; 5] = ["usr", "proc", "dev", "tmp", "etc"];

/// Creates the base layer at `layer`: the mount points, the probe's file,
/// `etc/ld.so.cache` from the host, and `bin`, `lib`, `lib64`, `sbin` as
/// the symlinks they are on the host, or as mount points where they are
/// directories. Returns the mounts the probe needs: the host's `/usr` and
/// those directories read-only, this binary at [`PROBE`], `/proc`, `/dev`
/// and a tmpfs `/tmp`.
pub fn base_layer(layer: &Path) -> Vec<Mount> {
    for d in DIRS {
        std::fs::create_dir_all(layer.join(d)).expect("a base layer dir");
    }
    std::fs::write(layer.join("probe"), b"").expect("the probe's mount point");
    if let Ok(cache) = std::fs::read("/etc/ld.so.cache") {
        std::fs::write(layer.join("etc/ld.so.cache"), cache).expect("copy ld.so.cache");
    }
    let mut mounts = vec![Mount::Bind {
        source: PathBuf::from("/usr"),
        target: inside("/usr"),
        writable: false,
    }];
    for top in ["bin", "lib", "lib64", "sbin"] {
        let host = Path::new("/").join(top);
        match std::fs::read_link(&host) {
            Ok(to) => std::os::unix::fs::symlink(to, layer.join(top)).expect("symlink"),
            Err(_) if host.is_dir() => {
                std::fs::create_dir_all(layer.join(top)).expect("mount point");
                mounts.push(Mount::Bind {
                    source: host,
                    target: inside(&format!("/{top}")),
                    writable: false,
                });
            }
            Err(_) => {}
        }
    }
    let exe = std::env::current_exe()
        .expect("current_exe")
        .canonicalize()
        .expect("canonicalize current_exe");
    mounts.push(Mount::Bind {
        source: exe,
        target: inside(PROBE),
        writable: false,
    });
    mounts.extend(image_mounts());
    mounts
}

/// The mounts every image gets: `/proc`, `/dev` and a 64 MiB tmpfs `/tmp`.
pub fn image_mounts() -> Vec<Mount> {
    vec![
        Mount::Tmpfs {
            target: inside("/tmp"),
            size_bytes: 64 << 20,
            mode: 0o1777,
        },
        Mount::Proc {
            target: inside("/proc"),
        },
        Mount::Dev {
            target: inside("/dev"),
            shm_size_bytes: 16 << 20,
        },
    ]
}

/// A root over `layers` (bottom first) with `mounts`, staged at `staging`.
pub fn root(layers: Vec<PathBuf>, staging: &Path, mounts: Vec<Mount>) -> Root {
    Root {
        layers,
        staging: staging.to_path_buf(),
        mounts,
        hostname: Hostname::new("boneli-oci-test").expect("hostname"),
        cwd: InsidePath::root(),
    }
}

/// The output of one program run in a sandbox.
#[derive(Debug)]
pub struct Output {
    /// How the program ended.
    pub status: ExitStatus,
    /// Its stdout.
    pub stdout: String,
    /// Its stderr.
    pub stderr: String,
}

fn read_all(fd: OwnedFd) -> String {
    let mut buf = Vec::new();
    File::from(fd)
        .read_to_end(&mut buf)
        .expect("read a pipe from the child");
    String::from_utf8_lossy(&buf).into_owned()
}

/// Whether `pid` has exited (a zombie, or gone).
fn exited(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat
            .rfind(')')
            .and_then(|i| stat.get(i + 1..))
            .and_then(|rest| rest.split_whitespace().next())
            .is_none_or(|state| state == "Z" || state == "X"),
        Err(_) => true,
    }
}

/// Runs `program` (a path inside the sandbox) with `args` and exactly
/// `env` as `ids` on `root`, in a cgroup of its own that is removed
/// afterwards, and collects its output. The wait is bounded by
/// [`HANG_BOUND`]: the child is polled through `/proc` until it exits.
pub fn run(program: &str, args: &[&str], env: &[(&str, &str)], ids: Ids, root: Root) -> Output {
    let cg = cgroup("run");
    let (out_r, out_w) = std::io::pipe().expect("pipe");
    let (err_r, err_w) = std::io::pipe().expect("pipe");
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .expect("/dev/null");
    let spec = Spec {
        program: PathBuf::from(program),
        args: args.iter().map(OsString::from).collect(),
        env: env
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect(),
        stdio: Stdio {
            stdin: OwnedFd::from(null),
            stdout: OwnedFd::from(out_w),
            stderr: OwnedFd::from(err_w),
        },
        ids,
        setup_timeout: SETUP_TIMEOUT,
        root,
        cgroup: &cg,
    };
    let mut child = spawn(&spec).unwrap_or_else(|e| panic!("spawn {program}: {e}"));
    // The spec holds the write ends; dropping it leaves the child as the
    // only writer, so the reads end when it exits.
    drop(spec);
    let err_reader = std::thread::spawn(move || read_all(OwnedFd::from(err_r)));
    let out_reader = std::thread::spawn(move || read_all(OwnedFd::from(out_r)));
    let deadline = Instant::now() + HANG_BOUND;
    while !exited(child.pid()) {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{program} still running after {HANG_BOUND:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = child.wait().expect("wait for the child");
    let stdout = out_reader.join().expect("stdout reader");
    let stderr = err_reader.join().expect("stderr reader");
    cg.destroy().expect("destroy the run's cgroup");
    Output {
        status,
        stdout,
        stderr,
    }
}

/// Runs this test binary inside the sandbox as a probe for `action`, with
/// `env` added, and returns its `BONELI_PROBE key=value` lines.
pub fn probe(action: &str, env: &[(&str, &str)], ids: Ids, root: Root) -> BTreeMap<String, String> {
    let mut full = vec![(ACTION_VAR, action)];
    full.extend_from_slice(env);
    let out = run(
        PROBE,
        &["--exact", "probe", "--nocapture", "--quiet"],
        &full,
        ids,
        root,
    );
    assert_eq!(out.status, ExitStatus::Exited(0), "probe failed: {out:?}");
    let mut values = BTreeMap::new();
    for line in out.stdout.lines() {
        if let Some(pos) = line.find(PREFIX)
            && let Some((k, v)) = line
                .get(pos + PREFIX.len()..)
                .and_then(|r| r.split_once('='))
        {
            values.insert(k.to_owned(), v.to_owned());
        }
    }
    values
}

/// The probe side: for `stat`, one line per path of [`PATHS_VAR`] with
/// what the path is, its mode, inode, link count and, for a file, its
/// contents. Paths are never followed.
pub fn probe_main(action: &str) {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    assert_eq!(action, "stat", "unknown probe action {action}");
    let paths = std::env::var(PATHS_VAR).unwrap_or_default();
    for path in paths.split(',').filter(|p| !p.is_empty()) {
        let line = match std::fs::symlink_metadata(path) {
            Err(e) => format!("missing errno={}", e.raw_os_error().unwrap_or(0)),
            Ok(m) => {
                let t = m.file_type();
                let kind = if t.is_dir() {
                    "dir".to_owned()
                } else if t.is_symlink() {
                    format!(
                        "symlink->{}",
                        std::fs::read_link(path).expect("link").display()
                    )
                } else if t.is_char_device() {
                    format!("char:{}", m.rdev())
                } else if t.is_fifo() {
                    "fifo".to_owned()
                } else if t.is_file() {
                    format!(
                        "file:{}",
                        std::fs::read_to_string(path).unwrap_or_else(|e| format!("<{e}>"))
                    )
                } else {
                    "other".to_owned()
                };
                format!(
                    "{kind} mode={:o} ino={} nlink={}",
                    m.permissions().mode() & 0o7777,
                    m.ino(),
                    m.nlink()
                )
            }
        };
        println!("{PREFIX}{path}={}", line.replace('\n', "\\n"));
    }
}

/// Ids for a test.
pub fn ids(uid: u32, gid: u32) -> Ids {
    Ids::new(uid, gid).expect("valid test ids")
}
