//! Ending the main thread alone (#35, ADR-015 D10): what a test needs to
//! observe a process whose thread-group leader has exited while another
//! thread runs, which std cannot produce.

use std::convert::Infallible;

use crate::error::{Error, Result};

/// Ends the calling thread, which must be the process's main thread, with
/// `SYS_exit`, not `exit_group`: only that thread ends, the process keeps
/// running until its last thread ends, and meanwhile the kernel shows the
/// thread-group leader as a zombie (`Z` in `/proc/<pid>/stat`).
///
/// On any other thread it returns [`Error::NotMainThread`] and changes
/// nothing. It never returns `Ok`; if the syscall ever returned, the
/// process aborts.
///
/// # Why a safe function is sound
///
/// Only the main thread can end itself this way, and that is checked
/// before any effect. Its stack is the process's initial stack, which
/// stays mapped while any thread runs, so a reference another thread holds
/// into it stays valid; and no thread can join the main thread, so nothing
/// waits on a handle it would never complete. Its destructors and
/// thread-local destructors do not run, which is a leak, and safe Rust
/// allows leaks (`mem::forget`). A lock it holds stays held, which is a
/// deadlock, not undefined behaviour.
///
/// Output that std still buffers for the main thread (stdout is line
/// buffered) is lost: flush it before the call.
pub fn exit_main_thread() -> Result<Infallible> {
    // SAFETY: gettid has no preconditions and cannot fail.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    if tid != libc::c_long::from(std::process::id().cast_signed()) {
        return Err(Error::NotMainThread);
    }
    // SAFETY: SYS_exit ends the calling thread, here the main thread
    // (checked above); see the soundness argument in the doc comment.
    unsafe { libc::syscall(libc::SYS_exit, 0) };
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::exit_main_thread;
    use crate::error::Error;

    /// libtest runs every test on a spawned thread, never the main thread:
    /// the call refuses and the thread and the process go on.
    #[test]
    fn exit_main_thread_refuses_other_threads() {
        assert!(matches!(exit_main_thread(), Err(Error::NotMainThread)));
        let other = std::thread::spawn(exit_main_thread).join().expect("joins");
        assert!(matches!(other, Err(Error::NotMainThread)));
        assert_eq!(
            Error::NotMainThread.to_string(),
            "exit_main_thread was called on a thread that is not the main thread"
        );
    }
}
