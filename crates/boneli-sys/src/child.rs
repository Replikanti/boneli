//! The cloned child's setup sequence (ADR-007, D4).
//!
//! The child is a copy of one thread of a possibly multithreaded process,
//! made by a raw `clone3`. Another thread may have held a lock (the
//! allocator's, stdio's, the environment's) at that moment, and the copy
//! of that lock stays held forever. So this code allocates nothing, takes
//! no lock and calls only syscalls on memory the parent prepared. A failed
//! step writes a 12-byte report to a close-on-exec pipe and exits 127; a
//! successful `execve` closes the pipe, which the parent reads as success.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

use crate::error::errno;
use crate::ffi;
use crate::report;

/// A step of the child's setup sequence, in order. The codes are the wire
/// format of the setup report (ADR-007, D4).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `deny` to `/proc/self/setgroups`, which the kernel requires before
    /// an unprivileged gid map.
    SetGroups = 1,
    /// The single line of `/proc/self/gid_map`.
    GidMap = 2,
    /// The single line of `/proc/self/uid_map`.
    UidMap = 3,
    /// `setsid`: a new session without a controlling terminal.
    Setsid = 4,
    /// Every signal disposition to `SIG_DFL` and an empty signal mask; the
    /// item is the signal number.
    Signals = 5,
    /// `dup2` of the three stdio descriptors; the item is the target fd.
    Stdio = 6,
    /// `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`.
    CloseFds = 7,
    /// `execve` of the program.
    Exec = 8,
}

impl Step {
    /// Every step, in sequence order.
    pub const ALL: [Step; 8] = [
        Step::SetGroups,
        Step::GidMap,
        Step::UidMap,
        Step::Setsid,
        Step::Signals,
        Step::Stdio,
        Step::CloseFds,
        Step::Exec,
    ];

    /// The step's code in the setup report.
    pub fn code(self) -> u32 {
        self as u32
    }

    /// The step with this report code.
    pub fn from_code(code: u32) -> Option<Step> {
        Step::ALL.into_iter().find(|s| s.code() == code)
    }

    /// The step's name in error messages.
    pub fn name(self) -> &'static str {
        match self {
            Step::SetGroups => "setgroups",
            Step::GidMap => "gid-map",
            Step::UidMap => "uid-map",
            Step::Setsid => "setsid",
            Step::Signals => "signals",
            Step::Stdio => "stdio",
            Step::CloseFds => "close-fds",
            Step::Exec => "exec",
        }
    }
}

/// What the child execs once the ids are mapped. Every pointer refers to
/// memory the parent prepared before the clone.
pub(crate) struct ExecPlan<'a> {
    pub program: &'a CStr,
    /// NULL-terminated.
    pub argv: &'a [*const c_char],
    /// NULL-terminated.
    pub envp: &'a [*const c_char],
    /// Descriptors >= 3 that become 0, 1 and 2.
    pub stdio: [c_int; 3],
}

/// The child's whole input.
pub(crate) struct ChildPlan<'a> {
    pub gid_line: &'a [u8],
    pub uid_line: &'a [u8],
    /// None: the host probe, which exits 0 after the id maps.
    pub exec: Option<ExecPlan<'a>>,
    /// The write end of the report pipe (close-on-exec).
    pub report_fd: c_int,
    pub fault: Fault,
}

/// A failed step, as it goes into the report.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Failure {
    pub step: Step,
    pub index: u32,
    pub errno: i32,
}

/// Every failure, injected ones included, is built here, so a change that
/// made failures allocate shows in the fault tests.
fn fail(step: Step, index: u32, errno: i32) -> Failure {
    Failure { step, index, errno }
}

/// Fault injection of the unit tests (ADR-007, D5).
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Fault {
    None,
    /// The step fails with EIO.
    Fail(Step),
    /// The child sleeps forever at the step.
    Hang(Step),
    /// The child allocates at the step (the allocation guard ends it).
    Allocate(Step),
}

/// Without tests there is nothing to inject.
#[cfg(not(test))]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Fault {
    None,
}

#[cfg(test)]
fn inject(fault: Fault, step: Step) -> Result<(), Failure> {
    match fault {
        Fault::Fail(s) if s == step => Err(fail(step, 0, libc::EIO)),
        Fault::Hang(s) if s == step => loop {
            // SAFETY: pause only waits for a signal.
            unsafe { libc::pause() };
        },
        Fault::Allocate(s) if s == step => {
            std::hint::black_box(Box::new(step));
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(not(test))]
#[inline(always)]
fn inject(_fault: Fault, _step: Step) -> Result<(), Failure> {
    Ok(())
}

/// Runs the setup sequence and execs, or reports the failed step and exits
/// 127. In probe mode (no exec plan) it exits 0 after the id maps.
///
/// # Safety
///
/// Call only in the child of a `clone3` without `CLONE_VM`, right after the
/// clone, with a plan whose memory was prepared before the clone.
pub(crate) unsafe fn run(plan: &ChildPlan<'_>) -> ! {
    let code = match steps(plan) {
        Ok(()) => 0,
        Err(f) => {
            let bytes = report::encode(f.step, f.index, f.errno);
            write_all(plan.report_fd, &bytes);
            127
        }
    };
    // SAFETY: _exit ends the child without running atexit handlers or
    // destructors that belong to the parent's copy of the process.
    unsafe { libc::_exit(code) }
}

/// Writes all bytes, retrying on EINTR. A failed report write leaves the
/// pipe empty, which the parent reads as an exec; the child's exit code
/// (127) still tells the story.
fn write_all(fd: c_int, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: bytes is valid for its length; fd is the report pipe.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return;
        }
        bytes = &bytes[n as usize..];
    }
}

/// Writes `data` to a `/proc` file in one `write`, as the id map files
/// require.
fn write_proc(path: &CStr, data: &[u8], step: Step) -> Result<(), Failure> {
    // SAFETY: path is a valid NUL-terminated string.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(fail(step, 0, errno()));
    }
    // SAFETY: data is valid for its length; fd was just opened.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    let result = if n < 0 {
        Err(fail(step, 0, errno()))
    } else if n as usize != data.len() {
        // A short write leaves a partial map; there is no errno for it.
        Err(fail(step, 0, libc::EIO))
    } else {
        Ok(())
    };
    // SAFETY: fd is open and owned by this function.
    unsafe { libc::close(fd) };
    result
}

fn steps(plan: &ChildPlan<'_>) -> Result<(), Failure> {
    let fault = plan.fault;

    inject(fault, Step::SetGroups)?;
    write_proc(c"/proc/self/setgroups", b"deny", Step::SetGroups)?;
    inject(fault, Step::GidMap)?;
    write_proc(c"/proc/self/gid_map", plan.gid_line, Step::GidMap)?;
    inject(fault, Step::UidMap)?;
    write_proc(c"/proc/self/uid_map", plan.uid_line, Step::UidMap)?;

    let Some(exec) = &plan.exec else {
        return Ok(());
    };

    inject(fault, Step::Setsid)?;
    // SAFETY: setsid has no memory arguments.
    if unsafe { libc::setsid() } < 0 {
        return Err(fail(Step::Setsid, 0, errno()));
    }

    // Dispositions first, then the mask: unblocking first could run one of
    // the parent's handlers in this child. An ignored disposition survives
    // execve (std ignores SIGPIPE), so every signal goes back to SIG_DFL.
    inject(fault, Step::Signals)?;
    let default = ffi::KernelSigaction {
        handler: libc::SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    for sig in 1..=ffi::NSIG {
        if sig == libc::SIGKILL || sig == libc::SIGSTOP {
            continue;
        }
        // SAFETY: default is a valid kernel sigaction for the call's
        // duration; no old action is requested.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_rt_sigaction,
                sig,
                &default as *const ffi::KernelSigaction,
                0usize,
                ffi::SIGSET_SIZE,
            )
        };
        if rc < 0 {
            return Err(fail(Step::Signals, sig as u32, errno()));
        }
    }
    let empty: u64 = 0;
    // SAFETY: empty is a valid kernel signal set for the call's duration.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            &empty as *const u64,
            0usize,
            ffi::SIGSET_SIZE,
        )
    };
    if rc < 0 {
        return Err(fail(Step::Signals, 0, errno()));
    }

    // The sources are >= 3 (prepared by the parent), so no dup2 overwrites
    // a source a later one needs, and dup2 clears close-on-exec on 0-2.
    inject(fault, Step::Stdio)?;
    for (target, &source) in exec.stdio.iter().enumerate() {
        // SAFETY: dup2 takes plain descriptor numbers.
        if unsafe { libc::dup2(source, target as c_int) } < 0 {
            return Err(fail(Step::Stdio, target as u32, errno()));
        }
    }

    // Every other descriptor, inherited or leaked by another thread, closes
    // at exec (CVE-2024-21626 class). CLOEXEC instead of closing keeps the
    // report pipe open until the exec itself.
    inject(fault, Step::CloseFds)?;
    // SAFETY: close_range takes plain integers.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if rc < 0 {
        return Err(fail(Step::CloseFds, 0, errno()));
    }

    inject(fault, Step::Exec)?;
    // SAFETY: program is NUL-terminated and argv and envp are
    // NULL-terminated arrays of pointers into memory prepared before the
    // clone; execve returns only on failure.
    unsafe {
        libc::execve(
            exec.program.as_ptr(),
            exec.argv.as_ptr(),
            exec.envp.as_ptr(),
        )
    };
    Err(fail(Step::Exec, 0, errno()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_codes_round_trip() {
        let mut names = std::collections::BTreeSet::new();
        for (i, step) in Step::ALL.into_iter().enumerate() {
            assert_eq!(step.code(), i as u32 + 1, "codes follow the sequence");
            assert_eq!(Step::from_code(step.code()), Some(step));
            assert_eq!(
                Step::from_code(step.code()).map(Step::code),
                Some(step.code())
            );
            assert!(names.insert(step.name()), "names are unique");
        }
        assert_eq!(Step::from_code(0), None);
        assert_eq!(Step::from_code(9), None);
        assert_eq!(Step::from_code(9999), None);
    }
}
