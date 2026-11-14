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
use crate::mount::{self, Op};
use crate::report;

/// A step of the child's setup sequence. The codes are the wire format of
/// the setup report (ADR-007, D4); they are stable, so the steps added by
/// later parts of #6 got new codes instead of renumbering. The order the
/// child runs them in is [`Step::SEQUENCE`].
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
    /// `PR_SET_NO_NEW_PRIVS` and a seccomp filter. Only the host probe's
    /// filter child runs it so far, with an allow-all filter, to prove the
    /// kernel installs filters at all (ADR-007, D3); `spawn` gets it before
    /// `Exec` with the policy of ADR-007 D2 in a later part of #6.
    Seccomp = 9,
    /// `unshare(CLONE_NEWCGROUP)`: the cgroup namespace, created in the
    /// child and not by `clone3` (ADR-007, D7).
    CgroupNs = 10,
    /// `mount("/", MS_REC | MS_PRIVATE)`.
    MakePrivate = 11,
    /// The read-only root on the staging directory: a bind of the one
    /// layer or an overlay of several.
    Root = 12,
    /// Opening a mount target beneath the new root without following any
    /// symlink; the item is the mount's index in `Root::mounts`.
    MountTarget = 13,
    /// A bind mount; the item is the mount's index.
    Bind = 14,
    /// A tmpfs mount; the item is the mount's index.
    Tmpfs = 15,
    /// A writable overlay mount; the item is the mount's index.
    Overlay = 16,
    /// A procfs mount; the item is the mount's index.
    Proc = 17,
    /// The minimal `/dev`; the item is the mount's index.
    Dev = 18,
    /// `pivot_root` onto the new root, the old root detached, and the
    /// working directory.
    Pivot = 19,
    /// `sethostname` in the new UTS namespace.
    Hostname = 20,
    /// `lo` up in the new network namespace.
    Loopback = 21,
}

impl Step {
    /// Every step, by code.
    pub const ALL: [Step; 21] = [
        Step::SetGroups,
        Step::GidMap,
        Step::UidMap,
        Step::Setsid,
        Step::Signals,
        Step::Stdio,
        Step::CloseFds,
        Step::Exec,
        Step::Seccomp,
        Step::CgroupNs,
        Step::MakePrivate,
        Step::Root,
        Step::MountTarget,
        Step::Bind,
        Step::Tmpfs,
        Step::Overlay,
        Step::Proc,
        Step::Dev,
        Step::Pivot,
        Step::Hostname,
        Step::Loopback,
    ];

    /// The steps of `spawn` in the order the child runs them.
    /// [`Step::MountTarget`] precedes each mount; [`Step::Seccomp`] is the
    /// probe's only (see there).
    pub const SEQUENCE: [Step; 20] = [
        Step::SetGroups,
        Step::GidMap,
        Step::UidMap,
        Step::CgroupNs,
        Step::MakePrivate,
        Step::Root,
        Step::MountTarget,
        Step::Bind,
        Step::Tmpfs,
        Step::Overlay,
        Step::Proc,
        Step::Dev,
        Step::Pivot,
        Step::Hostname,
        Step::Loopback,
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
            Step::Seccomp => "seccomp",
            Step::CgroupNs => "cgroup-ns",
            Step::MakePrivate => "make-private",
            Step::Root => "root",
            Step::MountTarget => "mount-target",
            Step::Bind => "bind",
            Step::Tmpfs => "tmpfs",
            Step::Overlay => "overlay",
            Step::Proc => "proc",
            Step::Dev => "dev",
            Step::Pivot => "pivot",
            Step::Hostname => "hostname",
            Step::Loopback => "loopback",
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
    /// The root, mounts, hostname and loopback (ADR-007, D7).
    pub ops: &'a [Op],
}

/// What the child does.
pub(crate) enum Action<'a> {
    /// The id maps and the whole sequence, then `execve` (`spawn`).
    Exec(ExecPlan<'a>),
    /// The host probe's user-namespace child: the id maps, then exit 0.
    ProbeIds,
    /// The host probe's filter child, cloned without a new user namespace
    /// so that it does not depend on one: an allow-all seccomp filter, then
    /// exit 0. A separate child, so that a host lacking both reports both.
    ProbeFilter,
}

/// The child's whole input.
pub(crate) struct ChildPlan<'a> {
    pub gid_line: &'a [u8],
    pub uid_line: &'a [u8],
    pub action: Action<'a>,
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
pub(crate) fn fail(step: Step, index: u32, errno: i32) -> Failure {
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
pub(crate) fn inject(fault: Fault, step: Step) -> Result<(), Failure> {
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
pub(crate) fn inject(_fault: Fault, _step: Step) -> Result<(), Failure> {
    Ok(())
}

/// Runs the setup sequence and execs, or reports the failed step and exits
/// 127. The probe's children exit 0 after their part (see [`Action`]).
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

/// `PR_SET_NO_NEW_PRIVS`, then a one-instruction filter that allows every
/// syscall: a kernel with `CONFIG_SECCOMP` but without
/// `CONFIG_SECCOMP_FILTER` knows the action values but refuses this.
fn allow_all_filter() -> Result<(), Failure> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes plain integers.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(fail(Step::Seccomp, 0, errno()));
    }
    let allow = [libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let prog = libc::sock_fprog {
        len: allow.len() as u16,
        filter: allow.as_ptr().cast_mut(),
    };
    // SAFETY: prog points at one valid instruction for the call's duration;
    // the kernel copies the program.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            &prog as *const libc::sock_fprog,
        )
    };
    if rc < 0 {
        return Err(fail(Step::Seccomp, 1, errno()));
    }
    Ok(())
}

fn steps(plan: &ChildPlan<'_>) -> Result<(), Failure> {
    let fault = plan.fault;

    if let Action::ProbeFilter = plan.action {
        allow_all_filter()?;
        // After the install, so that a test hanging here sees the filter.
        inject(fault, Step::Seccomp)?;
        return Ok(());
    }

    inject(fault, Step::SetGroups)?;
    write_proc(c"/proc/self/setgroups", b"deny", Step::SetGroups)?;
    inject(fault, Step::GidMap)?;
    write_proc(c"/proc/self/gid_map", plan.gid_line, Step::GidMap)?;
    inject(fault, Step::UidMap)?;
    write_proc(c"/proc/self/uid_map", plan.uid_line, Step::UidMap)?;

    let Action::Exec(exec) = &plan.action else {
        return Ok(());
    };

    // The cgroup namespace is created here, not by clone3: copy_process
    // creates namespaces before it moves the child into its target cgroup,
    // so a namespace from clone3 would be rooted at the parent's cgroup
    // (ADR-007, D7).
    inject(fault, Step::CgroupNs)?;
    // SAFETY: unshare takes plain flags.
    if unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } < 0 {
        return Err(fail(Step::CgroupNs, 0, errno()));
    }

    // The root, the mounts, pivot_root, the hostname and lo.
    mount::run(exec.ops, fault)?;

    inject(fault, Step::Setsid)?;
    // SAFETY: setsid has no memory arguments.
    if unsafe { libc::setsid() } < 0 {
        return Err(fail(Step::Setsid, 0, errno()));
    }

    // The parent blocked every signal around the clone (spawn::launch), so
    // no handler of the parent can have run here. Dispositions first, while
    // everything is still blocked, then the empty mask, as glibc's
    // posix_spawn does. An ignored disposition survives execve (std ignores
    // SIGPIPE), so every signal goes back to SIG_DFL.
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
            assert_eq!(step.code(), i as u32 + 1, "codes follow Step::ALL");
            assert_eq!(Step::from_code(step.code()), Some(step));
            assert_eq!(
                Step::from_code(step.code()).map(Step::code),
                Some(step.code())
            );
            assert!(names.insert(step.name()), "names are unique");
        }
        assert_eq!(Step::from_code(0), None);
        assert_eq!(Step::from_code(Step::ALL.len() as u32 + 1), None);
        // The sequence holds every step but the probe's Seccomp, once.
        let mut seen: Vec<Step> = Step::SEQUENCE.to_vec();
        seen.push(Step::Seccomp);
        seen.sort_by_key(|s| s.code());
        assert_eq!(seen, Step::ALL);
        assert_eq!(Step::from_code(9999), None);
    }
}
