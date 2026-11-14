//! The allocation guard of the unit tests, the same as the integration
//! tests' `support::alloc_guard` (ADR-007, D4): the cloned child must not
//! allocate, so an allocation from a pid other than the recorded one exits
//! at once with 97, a code no setup step or probe uses, instead of risking
//! a deadlock on a lock another thread held at the clone.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI32, Ordering};

/// Exit code of a child that allocated.
pub const EXIT_ALLOCATED: i32 = 97;

static OWNER: AtomicI32 = AtomicI32::new(0);

fn check() {
    // SAFETY: getpid has no preconditions and cannot fail.
    let me = unsafe { libc::getpid() };
    match OWNER.compare_exchange(0, me, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => {}
        Err(owner) if owner == me => {}
        Err(_) => {
            // SAFETY: _exit ends the process without running any user code;
            // it is async-signal-safe and allocates nothing.
            unsafe { libc::_exit(EXIT_ALLOCATED) }
        }
    }
}

/// The system allocator behind the pid check.
pub struct Guard;

// SAFETY: every method checks the pid and then forwards its arguments
// unchanged to the system allocator, which upholds the GlobalAlloc contract.
unsafe impl GlobalAlloc for Guard {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        check();
        // SAFETY: the caller's layout contract is forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        check();
        // SAFETY: the caller's layout contract is forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        check();
        // SAFETY: ptr was allocated by System through this allocator with
        // this layout (the caller's contract).
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        check();
        // SAFETY: the caller's contract for ptr, layout and new_size is
        // forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// Serializes the unit tests that start children: they count this
/// process's descriptors and find their child among its children.
static HOST: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes the host test lock; a test that failed while holding it does not
/// fail the others.
pub fn host_lock() -> std::sync::MutexGuard<'static, ()> {
    HOST.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The pids of this process's children, from every thread's list.
pub fn children() -> Vec<i32> {
    let mut pids = Vec::new();
    for task in std::fs::read_dir("/proc/self/task")
        .into_iter()
        .flatten()
        .flatten()
    {
        let list = std::fs::read_to_string(task.path().join("children")).unwrap_or_default();
        pids.extend(
            list.split_whitespace()
                .filter_map(|p| p.parse::<i32>().ok()),
        );
    }
    pids
}

/// The first child that appears within `bound` (a hang bound).
pub fn wait_for_child(bound: std::time::Duration) -> i32 {
    let deadline = std::time::Instant::now() + bound;
    loop {
        if let Some(&pid) = children().first() {
            return pid;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no child appeared within {bound:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// A sandbox root for the unit tests, with one mount of every kind so that
/// a fault at any step is reached; removed on drop. It lives next to the
/// test binary (on the target directory's file system), because overlay
/// needs an upper directory with `user.*` xattrs.
pub struct UnitRoot {
    dir: std::path::PathBuf,
    /// The root.
    pub root: crate::Root,
}

impl UnitRoot {
    /// Creates the layer, the staging directory and the overlay's
    /// directories.
    pub fn new() -> UnitRoot {
        use crate::{Hostname, InsidePath, Mount};
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let exe = std::env::current_exe().expect("current_exe");
        let dir = exe
            .parent()
            .expect("the test binary's directory")
            .join(format!("boneli-sys-unit-{}-{n}", std::process::id()));
        let layer = dir.join("layer");
        for d in ["usr", "proc", "dev", "tmp", "work2"] {
            std::fs::create_dir_all(layer.join(d)).expect("create a mount point");
        }
        let mut mounts = vec![Mount::Bind {
            source: "/usr".into(),
            target: InsidePath::new("/usr").expect("path"),
            writable: false,
        }];
        for top in ["bin", "lib", "lib64", "sbin"] {
            let host = std::path::Path::new("/").join(top);
            match std::fs::read_link(&host) {
                Ok(to) => std::os::unix::fs::symlink(to, layer.join(top)).expect("symlink"),
                Err(_) if host.is_dir() => {
                    std::fs::create_dir_all(layer.join(top)).expect("mount point");
                    mounts.push(Mount::Bind {
                        source: host,
                        target: InsidePath::new(&format!("/{top}")).expect("path"),
                        writable: false,
                    });
                }
                Err(_) => {}
            }
        }
        for d in ["staging", "lower", "upper", "work"] {
            std::fs::create_dir_all(dir.join(d)).expect("create a directory");
        }
        mounts.extend([
            Mount::Tmpfs {
                target: InsidePath::new("/tmp").expect("path"),
                size_bytes: 1 << 20,
                mode: 0o1777,
            },
            Mount::Overlay {
                lower: dir.join("lower"),
                upper: dir.join("upper"),
                work: dir.join("work"),
                target: InsidePath::new("/work2").expect("path"),
            },
            Mount::Proc {
                target: InsidePath::new("/proc").expect("path"),
            },
            Mount::Dev {
                target: InsidePath::new("/dev").expect("path"),
                shm_size_bytes: 1 << 20,
            },
        ]);
        let root = crate::Root {
            layers: vec![layer],
            staging: dir.join("staging"),
            mounts,
            hostname: Hostname::new("boneli-unit").expect("hostname"),
            cwd: InsidePath::root(),
        };
        UnitRoot { dir, root }
    }
}

impl Drop for UnitRoot {
    fn drop(&mut self) {
        remove_tree(&self.dir);
    }
}

/// Removes a tree after making every directory in it writable: overlay
/// creates its `work/work` directory with mode 0.
pub fn remove_tree(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fn open_up(dir: &std::path::Path) {
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                open_up(&entry.path());
            }
        }
    }
    open_up(dir);
    let _ = std::fs::remove_dir_all(dir);
}
