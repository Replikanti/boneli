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
