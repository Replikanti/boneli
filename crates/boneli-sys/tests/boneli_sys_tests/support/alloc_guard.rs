//! The allocation guard every host test relies on (ADR-007, D4).
//!
//! The cloned child of `boneli_sys::spawn` must not allocate: it is a copy
//! of one thread of a multithreaded process, and another thread may have
//! held the allocator's lock at the moment of the clone. This allocator
//! records the pid of the process on its first call; a call from another
//! pid (the cloned child, which shares the copied record) exits at once
//! with 97, a code no probe uses (probes exit 0-3), instead of risking a
//! deadlock that would look like a hang.

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
