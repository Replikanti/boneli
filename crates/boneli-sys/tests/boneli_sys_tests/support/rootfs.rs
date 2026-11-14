//! Fixture roots for the host tests (ADR-007, D7): a base layer with the
//! mount points the tests use, the host's `/usr` and this test binary bound
//! read-only, a writable `/workspace`, a tmpfs `/tmp`, `/proc` and `/dev`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use boneli_sys::{Hostname, InsidePath, Mount, Root};

/// Where this test binary appears inside the sandbox; the probe runs from
/// there.
pub const PROBE: &str = "/probe";

/// The hostname of fixture sandboxes.
pub const HOSTNAME: &str = "boneli-test";

/// Size of the fixture's `/tmp`: room for the probes' files.
pub const TMP_SIZE: u64 = 64 << 20;

/// Size of the fixture's `/dev/shm`.
pub const SHM_SIZE: u64 = 16 << 20;

/// The directories of the base layer, mount points included.
const DIRS: [&str; 11] = [
    "usr",
    "proc",
    "dev",
    "tmp",
    "workspace",
    "work2",
    "shm-ro",
    "sys/fs/cgroup",
    "etc",
    "run/boneli",
    "empty",
];

/// The empty files of the base layer: the probe's and the egress socket's
/// mount points (ADR-006: a broker socket is bound onto a file).
const FILES: [&str; 2] = ["probe", "run/boneli/egress.sock"];

/// An inside path, failing the test on a bad one.
pub fn inside(path: &str) -> InsidePath {
    InsidePath::new(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A tree under `CARGO_TARGET_TMPDIR`, unique per process and call, with
/// symlinks resolved (bind sources are resolved without following any),
/// removed on drop after every directory in it was made writable again:
/// overlay creates `work/work` with mode 0.
pub struct Tree {
    path: PathBuf,
}

impl Tree {
    /// Creates `<CARGO_TARGET_TMPDIR>/<tag>-<pid>-<counter>`.
    pub fn new(tag: &str) -> Tree {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create the fixture dir");
        let path = path.canonicalize().expect("canonicalize the fixture dir");
        Tree { path }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates a directory in the tree and returns its path.
    pub fn dir(&self, rel: &str) -> PathBuf {
        let p = self.path.join(rel);
        std::fs::create_dir_all(&p).unwrap_or_else(|e| panic!("mkdir {}: {e}", p.display()));
        p
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        fn open_up(dir: &Path) {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    open_up(&entry.path());
                }
            }
        }
        open_up(&self.path);
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Creates the base layer at `layer`: the mount points, `etc/ld.so.cache`
/// copied from the host (the dynamic loader's search list on Debian-style
/// hosts), and `bin`, `lib`, `lib64`, `sbin` as the symlinks they are on
/// the host, or as mount points where they are directories. Returns the
/// binds those directories need.
pub fn base_layer(layer: &Path) -> Vec<Mount> {
    for d in DIRS {
        std::fs::create_dir_all(layer.join(d)).expect("create a layer dir");
    }
    for f in FILES {
        std::fs::write(layer.join(f), b"").expect("create a layer file");
    }
    if let Ok(cache) = std::fs::read("/etc/ld.so.cache") {
        std::fs::write(layer.join("etc/ld.so.cache"), cache).expect("copy ld.so.cache");
    }
    let mut binds = Vec::new();
    for top in ["bin", "lib", "lib64", "sbin"] {
        let host = Path::new("/").join(top);
        match std::fs::read_link(&host) {
            Ok(to) => std::os::unix::fs::symlink(to, layer.join(top)).expect("symlink"),
            Err(_) if host.is_dir() => {
                std::fs::create_dir_all(layer.join(top)).expect("mount point");
                binds.push(Mount::Bind {
                    source: host,
                    target: inside(&format!("/{top}")),
                    writable: false,
                });
            }
            Err(_) => {}
        }
    }
    binds
}

/// A fixture root: the base layer, its staging directory and the host
/// directory behind `/workspace`.
pub struct Fixture {
    tree: Tree,
    /// The base layer.
    pub layer: PathBuf,
    /// The host directory bound writable at `/workspace`.
    pub workspace: PathBuf,
    host_binds: Vec<Mount>,
}

impl Fixture {
    /// Creates the fixture.
    pub fn new(tag: &str) -> Fixture {
        let tree = Tree::new(tag);
        let layer = tree.dir("layers/base");
        let host_binds = base_layer(&layer);
        let workspace = tree.dir("workspace");
        tree.dir("staging");
        Fixture {
            tree,
            layer,
            workspace,
            host_binds,
        }
    }

    /// The fixture's tree, for extra layers and directories.
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// The default mounts: `/usr` (and any non-symlink `bin`, `lib`,
    /// `lib64`, `sbin`) and the probe read-only, `/workspace` writable, a
    /// tmpfs `/tmp`, `/proc` and `/dev`.
    pub fn mounts(&self) -> Vec<Mount> {
        let exe = std::env::current_exe()
            .expect("current_exe")
            .canonicalize()
            .expect("canonicalize current_exe");
        let mut mounts = vec![Mount::Bind {
            source: PathBuf::from("/usr"),
            target: inside("/usr"),
            writable: false,
        }];
        mounts.extend(self.host_binds.iter().cloned());
        mounts.extend([
            Mount::Bind {
                source: exe,
                target: inside(PROBE),
                writable: false,
            },
            Mount::Bind {
                source: self.workspace.clone(),
                target: inside("/workspace"),
                writable: true,
            },
            Mount::Tmpfs {
                target: inside("/tmp"),
                size_bytes: TMP_SIZE,
                mode: 0o1777,
            },
            Mount::Proc {
                target: inside("/proc"),
            },
            Mount::Dev {
                target: inside("/dev"),
                shm_size_bytes: SHM_SIZE,
            },
        ]);
        mounts
    }

    /// The default root: the base layer and [`Fixture::mounts`].
    pub fn root(&self) -> Root {
        self.root_with(vec![self.layer.clone()], self.mounts())
    }

    /// A root with other layers or mounts on this fixture's staging
    /// directory.
    pub fn root_with(&self, layers: Vec<PathBuf>, mounts: Vec<Mount>) -> Root {
        Root {
            layers,
            staging: self.tree.path().join("staging"),
            mounts,
            hostname: Hostname::new(HOSTNAME).expect("hostname"),
            cwd: InsidePath::root(),
        }
    }
}
