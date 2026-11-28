//! The cloned child's setup sequence (ADR-007, D4).
//!
//! The child is a copy o one thread of a possibly multithreaded process,
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
use crate::privileges::{self, PrivilegeDrop};
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
    /// `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)`. For an anchor and a
    /// join (ADR-042, D3): item 0 every descriptor but the kept ones closed
    /// right after the clone, item 1 an anchor's close down to its pins
    /// and report pipe before the release, item 2 a later anchor's close
    /// down to its own after the inner clone.
    CloseFds = 7,
    /// `execve` of the program.
    Exec = 8,
    /// The seccomp filter, the last step but the listener hand-off before
    /// `Exec`: in `spawn` the notifying program of ADR-043 D2 with a
    /// listener (item 0, after [`Step::NoNewPrivs`], ADR-007 D9); in the
    /// host probe's filter child `PR_SET_NO_NEW_PRIVS` (item 0), an
    /// allow-all filter (item 1), which prove the kernel installs filters
    /// at all (ADR-007 D3), and the same filter with the notifying
    /// program's flags (item 2, ADR-043 D7).
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
    /// A read-only cgroup2 mount of the sandbox's own cgroup; the item is
    /// the mount's index.
    Cgroup2 = 22,
    /// `/proc/self/oom_score_adj` raised to 0 if the inherited value is
    /// negative, never lowered: a runner at `-1000` would otherwise make
    /// every sandbox task unkillable by the OOM killer and void
    /// `memory.oom.group` (ADR-007, D8).
    OomScoreAdj = 23,
    /// `PR_SET_SECUREBITS` to 0xEF: no capabilities for uid 0 at `execve`,
    /// no setuid fixup, no ambient raise, all locked (ADR-007, D9).
    Securebits = 24,
    /// `PR_CAPBSET_DROP` of every capability up to `cap_last_cap`; the item
    /// is the capability number.
    CapBoundingSet = 25,
    /// `PR_CAP_AMBIENT_CLEAR_ALL`.
    CapAmbient = 26,
    /// `capset` with empty effective, permitted and inheritable sets.
    Capset = 27,
    /// `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivs = 28,
    /// `keyctl(KEYCTL_JOIN_SESSION_KEYRING, NULL)`: a new anonymous session
    /// keyring, so the program holds no reference to the runner's (ADR-007,
    /// D2).
    SessionKeyring = 29,
    /// The notifying filter's listener sent to the parent over the
    /// listener socket and closed (ADR-043, D3); item 0 the send, item 1
    /// the close.
    Listener = 30,
    /// `setns` of the first stage of a join (an exec, or a pod's later
    /// anchor) into an anchor's namespaces through its pidfd (ADR-042,
    /// D3).
    Setns = 31,
    /// `unshare` of the first stage's new namespaces: mount and PID for an
    /// exec, also UTS and IPC for an anchor (ADR-042, D3).
    Unshare = 32,
    /// The first stage's `clone3(CLONE_PARENT | CLONE_PARENT_SETTID)` of
    /// the second stage, item 0; item 1 the gate pipe that holds the second
    /// stage back until the first has recorded its pid, item 2 the second
    /// stage's wait at it, item 3 its unmap of the runner's pid page
    /// (ADR-042, D3).
    InnerClone = 33,
    /// The first stage's record of the second stage's pid: a progress
    /// record, the pid as the item and errno 0. As a failure the item is
    /// that pid too, so the runner reaps the second stage, its child.
    Forked = 34,
    /// An anchor's fill point: a progress record with the loopback
    /// families as the item (bit 0 IPv4, bit 1 IPv6). As a failure, item 0
    /// the families' probe, item 1 the record's write, item 2 the wait for
    /// the runner's resume (ECANCELED when the runner went away).
    Fill = 35,
    /// An anchor's memory release and hold: a progress record once only
    /// its pins are left. As a failure, item 0 opening its maps, 1 reading
    /// them, 2 a line it cannot parse, 3 an `munmap`, 4 a release that has
    /// not ended within its passes, 5 the signal mask, 6 the kept ranges
    /// (more `.bss` ranges than it holds, a bad page size or caller frame)
    /// (ADR-042, D3).
    Release = 36,
}

impl Step {
    /// Every step, by code.
    pub const ALL: [Step; 36] = [
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
        Step::Cgroup2,
        Step::OomScoreAdj,
        Step::Securebits,
        Step::CapBoundingSet,
        Step::CapAmbient,
        Step::Capset,
        Step::NoNewPrivs,
        Step::SessionKeyring,
        Step::Listener,
        Step::Setns,
        Step::Unshare,
        Step::InnerClone,
        Step::Forked,
        Step::Fill,
        Step::Release,
    ];

    /// The steps of `spawn` in the order the child runs them.
    /// [`Step::MountTarget`] precedes each mount.
    pub const SEQUENCE: [Step; 30] = [
        Step::SetGroups,
        Step::GidMap,
        Step::UidMap,
        Step::SessionKeyring,
        Step::OomScoreAdj,
        Step::CgroupNs,
        Step::MakePrivate,
        Step::Root,
        Step::MountTarget,
        Step::Bind,
        Step::Tmpfs,
        Step::Overlay,
        Step::Proc,
        Step::Dev,
        Step::Cgroup2,
        Step::Pivot,
        Step::Hostname,
        Step::Loopback,
        Step::Setsid,
        Step::Signals,
        Step::Stdio,
        Step::CloseFds,
        Step::Securebits,
        Step::CapBoundingSet,
        Step::CapAmbient,
        Step::Capset,
        Step::NoNewPrivs,
        Step::Seccomp,
        Step::Listener,
        Step::Exec,
    ];

    /// The steps of a pod's first anchor in order (`Anchor::create`,
    /// ADR-042 D3): the descriptors it does not keep closed first, `lo`
    /// before the root, the fill point between the mounts, and the memory
    /// release last. [`Step::MountTarget`] precedes each mount.
    pub const ANCHOR_SEQUENCE: [Step; 28] = [
        Step::CloseFds,
        Step::SetGroups,
        Step::GidMap,
        Step::UidMap,
        Step::SessionKeyring,
        Step::OomScoreAdj,
        Step::CgroupNs,
        Step::Loopback,
        Step::MakePrivate,
        Step::Root,
        Step::MountTarget,
        Step::Bind,
        Step::Tmpfs,
        Step::Overlay,
        Step::Proc,
        Step::Dev,
        Step::Cgroup2,
        Step::Fill,
        Step::Pivot,
        Step::Hostname,
        Step::Setsid,
        Step::Securebits,
        Step::CapBoundingSet,
        Step::CapAmbient,
        Step::Capset,
        Step::NoNewPrivs,
        Step::Seccomp,
        Step::Release,
    ];

    /// The steps of a pod's later anchor in order (`Anchor::join`): the
    /// first stage up to [`Step::Forked`], then the second, the anchor.
    pub const JOIN_SEQUENCE: [Step; 27] = [
        Step::CloseFds,
        Step::OomScoreAdj,
        Step::Setns,
        Step::SessionKeyring,
        Step::Unshare,
        Step::InnerClone,
        Step::Forked,
        Step::MakePrivate,
        Step::Root,
        Step::MountTarget,
        Step::Bind,
        Step::Tmpfs,
        Step::Overlay,
        Step::Proc,
        Step::Dev,
        Step::Cgroup2,
        Step::Fill,
        Step::Pivot,
        Step::Hostname,
        Step::Setsid,
        Step::Securebits,
        Step::CapBoundingSet,
        Step::CapAmbient,
        Step::Capset,
        Step::NoNewPrivs,
        Step::Seccomp,
        Step::Release,
    ];

    /// The steps of an exec joined to an anchor in order (`Anchor::exec`):
    /// the first stage up to [`Step::Forked`], then the second, which
    /// mounts its own procfs ([`Step::Root`] opens its current root,
    /// [`Step::Pivot`] item 4 is the working directory) and goes on as
    /// `spawn` does from `setsid` to `execve`.
    pub const EXEC_SEQUENCE: [Step; 21] = [
        Step::CloseFds,
        Step::OomScoreAdj,
        Step::Setns,
        Step::SessionKeyring,
        Step::Unshare,
        Step::InnerClone,
        Step::Forked,
        Step::Root,
        Step::MountTarget,
        Step::Proc,
        Step::Setsid,
        Step::Signals,
        Step::Stdio,
        Step::Securebits,
        Step::CapBoundingSet,
        Step::CapAmbient,
        Step::Capset,
        Step::NoNewPrivs,
        Step::Seccomp,
        Step::Listener,
        Step::Exec,
    ];

    /// Whether a record of this step with errno 0 is a progress record
    /// (ADR-042, D3); every other record is a failure.
    pub(crate) fn is_progress(self) -> bool {
        matches!(self, Step::Forked | Step::Fill | Step::Release)
    }

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
            Step::Cgroup2 => "cgroup2",
            Step::OomScoreAdj => "oom-score-adj",
            Step::Securebits => "securebits",
            Step::CapBoundingSet => "cap-bounding-set",
            Step::CapAmbient => "cap-ambient",
            Step::Capset => "capset",
            Step::NoNewPrivs => "no-new-privs",
            Step::SessionKeyring => "session-keyring",
            Step::Listener => "listener",
            Step::Setns => "setns",
            Step::Unshare => "unshare",
            Step::InnerClone => "inner-clone",
            Step::Forked => "forked",
            Step::Fill => "fill",
            Step::Release => "release",
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
    /// The directory descriptor of the cgroup `clone3` places the child in
    /// (`CLONE_INTO_CGROUP`, ADR-007 D8).
    pub cgroup: c_int,
    /// The privilege drop and the seccomp filter (ADR-007, D9 and D2).
    pub privileges: PrivilegeDrop<'a>,
    /// The child's end of the listener socket (close-on-exec, >= 3): the
    /// notifying filter's listener goes to the parent through it
    /// (ADR-043, D3).
    pub listener_sock: c_int,
}

/// What an anchor runs (ADR-042, D3). Every pointer refers to memory the
/// parent prepared before the clone.
pub(crate) struct AnchorPlan<'a> {
    /// `lo` (the first anchor only), the root, the mounts, `pivot_root`
    /// and the hostname ([`crate::mount::plan_anchor`]).
    pub ops: &'a [Op],
    /// The index in `ops` of the first operation after the fill point.
    pub fill_at: usize,
    /// The anchor's end of the resume socket: the runner sends one byte once the
    /// fill is done, and closes it without one when it gives up.
    pub resume: c_int,
    /// Every descriptor the anchor keeps from the clone, ascending: the
    /// report pipe, the resume socket and the pins.
    pub keep: &'a [c_int],
    /// The descriptors left once it pivoted, ascending: the report pipe
    /// and the pins.
    pub hold: &'a [c_int],
    /// The privilege drop and the plain seccomp program, without a
    /// listener: the anchor runs no workload, so it has no denied call to
    /// record (ADR-042, D3; ADR-043).
    pub privileges: PrivilegeDrop<'a>,
    /// `<procfs>/self/maps` in its own root, which the release reads.
    pub maps: &'a CStr,
    /// The `.bss` ranges of the runner's ELF objects, page-aligned, which
    /// the release keeps (ADR-042, D3).
    pub bss: &'a [(usize, usize)],
    /// The page size.
    pub page: usize,
    /// The pod's cgroup, for `CLONE_INTO_CGROUP`.
    pub cgroup: c_int,
}

/// The first stage of a join (ADR-042, D3): a process cloned into the
/// pod's cgroup with no new namespace that joins an anchor's namespaces,
/// creates its own and clones the second stage as the runner's child.
pub(crate) struct JoinPlan<'a> {
    /// The anchor's pidfd.
    pub anchor: c_int,
    /// The `CLONE_NEW*` flags of the anchor's namespaces it joins.
    pub setns: c_int,
    /// The namespaces it creates.
    pub unshare: c_int,
    /// Every descriptor both stages keep, ascending.
    pub keep: &'a [c_int],
    /// The pod's cgroup, for `CLONE_INTO_CGROUP`.
    pub cgroup: c_int,
    /// The start of a page the runner mapped shared before the clone: the
    /// inner clone writes the second stage's pid there itself
    /// (`CLONE_PARENT_SETTID`), so the runner learns it even when the first
    /// stage dies before its record (ADR-042, D3).
    pub tid: usize,
    /// What the second stage runs.
    pub then: Joined<'a>,
}

/// The length of the runner's pid page ([`JoinPlan::tid`]): one page on
/// every supported kernel (4 KiB, or more on arm64, which `mmap` rounds up
/// to).
pub(crate) const TID_PAGE: usize = 4096;

/// The second stage of a join.
pub(crate) enum Joined<'a> {
    /// A pod's later anchor.
    Anchor(AnchorPlan<'a>),
    /// A program in an anchor's container: its procfs, then the sequence
    /// of `spawn` from `setsid` to `execve`.
    Exec(ExecPlan<'a>),
}

/// What the child does.
pub(crate) enum Action<'a> {
    /// The id maps and the whole sequence, then `execve` (`spawn`).
    Exec(ExecPlan<'a>),
    /// A pod's first anchor: the id maps, its sequence up to the fill
    /// point, the rest, the release and the hold (`Anchor::create`).
    Anchor(AnchorPlan<'a>),
    /// The first stage of a join (`Anchor::join`, `Anchor::exec`).
    Join(JoinPlan<'a>),
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
    // A record with errno 0 is a progress record for some steps (ADR-042,
    // D3), so a failure never carries 0, even if the call left none.
    let errno = if errno == 0 { libc::EIO } else { errno };
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
    /// The child sends no listener message.
    NoListener,
    /// The listener message carries no descriptor.
    ListenerWithoutFd,
    /// The listener message carries the listener twice.
    TwoListeners,
    /// The listener message has no payload byte.
    EmptyListener,
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
/// `CONFIG_SECCOMP_FILTER` knows the action values but refuses this. Then
/// the same filter once more with the notifying filter's flags (item 2).
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
    // The same filter with a listener and the wait-killable receive
    // (ADR-043, D7): EINVAL on a kernel below 5.19, EBUSY where this
    // process already sits under a filter with a listener. No call is
    // ever notified; the listener is closed at once.
    // SAFETY: as above.
    let listener = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            crate::seccomp::notify::LISTENER_FLAGS,
            &prog as *const libc::sock_fprog,
        )
    };
    if listener < 0 {
        return Err(fail(Step::Seccomp, 2, errno()));
    }
    // SAFETY: the install returned a new descriptor that only this
    // function uses.
    unsafe { libc::close(listener as c_int) };
    Ok(())
}

/// The payload length and the descriptor count of the listener message:
/// one byte and the listener (ADR-043, D3); the fault tests change both.
#[cfg(test)]
fn listener_message(fault: Fault) -> Option<(usize, usize)> {
    match fault {
        Fault::NoListener => None,
        Fault::ListenerWithoutFd => Some((1, 0)),
        Fault::TwoListeners => Some((1, 2)),
        Fault::EmptyListener => Some((0, 1)),
        _ => Some((1, 1)),
    }
}

#[cfg(not(test))]
#[inline(always)]
fn listener_message(_fault: Fault) -> Option<(usize, usize)> {
    Some((1, 1))
}

/// The step [`Step::Listener`]: sends `listener` to the parent as one byte
/// with one `SCM_RIGHTS` descriptor, from stack memory, then closes it, so
/// the program never holds it (it is close-on-exec as well, 5.19 `:1876`).
fn send_listener(sock: c_int, listener: c_int, fault: Fault) -> Result<(), Failure> {
    let step = Step::Listener;
    if let Some((len, count)) = listener_message(fault) {
        let byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_ptr().cast_mut().cast(),
            iov_len: len,
        };
        // SAFETY: cmsghdr is plain integers (and private padding on musl),
        // for which all zeroes is a valid value.
        let mut control: ffi::FdMessage = unsafe { std::mem::zeroed() };
        control.hdr.cmsg_level = libc::SOL_SOCKET;
        control.hdr.cmsg_type = libc::SCM_RIGHTS;
        control.hdr.cmsg_len = (ffi::CMSG_LEN_0 + 4 * count) as _;
        control.fds = [listener; 2];
        // SAFETY: msghdr is plain integers and pointers (and private
        // padding on musl), for which all zeroes is a valid value.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if count > 0 {
            msg.msg_control = (&mut control as *mut ffi::FdMessage).cast();
            // CMSG_SPACE of the data: 24 bytes for one or two descriptors.
            msg.msg_controllen = (ffi::CMSG_LEN_0 + 4 * count).next_multiple_of(8) as _;
        }
        let sent = loop {
            // SAFETY: msg, iov, byte and control are valid for the call's
            // duration; MSG_NOSIGNAL keeps a closed peer from raising
            // SIGPIPE, which has its default disposition by now.
            let n = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
            if n < 0 && errno() == libc::EINTR {
                continue;
            }
            break n;
        };
        if sent < 0 {
            return Err(fail(step, 0, errno()));
        }
        if sent as usize != len {
            return Err(fail(step, 0, libc::EIO));
        }
    }
    // SAFETY: listener is the descriptor the filter install returned, which
    // only this function uses.
    if unsafe { libc::close(listener) } < 0 && errno() != libc::EINTR {
        return Err(fail(step, 1, errno()));
    }
    Ok(())
}

/// Parses an `oom_score_adj` value as the kernel prints it: an optional
/// `-`, decimal digits, an optional newline. No allocation.
pub(crate) fn parse_oom_score_adj(bytes: &[u8]) -> Option<i32> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let (negative, digits) = match bytes.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, bytes),
    };
    if digits.is_empty() || digits.len() > 4 {
        return None;
    }
    let mut n: i32 = 0;
    for &d in digits {
        if !d.is_ascii_digit() {
            return None;
        }
        n = n * 10 + i32::from(d - b'0');
    }
    Some(if negative { -n } else { n })
}

/// What to write to `oom_score_adj` for an inherited value: `0` when it
/// is negative, nothing otherwise, so the value is raised to at least 0
/// and never lowered (raising needs no privilege, lowering does).
pub(crate) fn oom_score_adj_raise(current: i32) -> Option<&'static [u8]> {
    if current < 0 { Some(b"0") } else { None }
}

/// The step [`Step::OomScoreAdj`]: reads the inherited value into a stack
/// buffer and raises it to 0 if it is negative.
fn raise_oom_score_adj() -> Result<(), Failure> {
    let step = Step::OomScoreAdj;
    // SAFETY: the path is NUL-terminated.
    let fd = unsafe {
        libc::open(
            c"/proc/self/oom_score_adj".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(fail(step, 0, errno()));
    }
    let mut buf = [0u8; 16];
    // SAFETY: buf is valid writable memory of the length passed.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    let result = if n < 0 {
        Err(fail(step, 1, errno()))
    } else {
        match parse_oom_score_adj(&buf[..n as usize]) {
            None => Err(fail(step, 1, libc::EINVAL)),
            Some(current) => match oom_score_adj_raise(current) {
                None => Ok(()),
                Some(value) => {
                    // SAFETY: value is valid for its length; fd is open.
                    let w = unsafe { libc::pwrite(fd, value.as_ptr().cast(), value.len(), 0) };
                    if w < 0 {
                        Err(fail(step, 2, errno()))
                    } else if w as usize != value.len() {
                        Err(fail(step, 2, libc::EIO))
                    } else {
                        Ok(())
                    }
                }
            },
        }
    };
    // SAFETY: fd is open and owned by this function.
    unsafe { libc::close(fd) };
    result
}

/// Closes every descriptor but `keep` (ascending, each >= 0) with
/// `close_range` over the gaps.
pub(crate) fn close_except(keep: &[c_int]) -> Result<(), i32> {
    let mut from: u32 = 0;
    for &fd in keep {
        let fd = fd as u32;
        if fd > from {
            close_gap(from, fd - 1)?;
        }
        // fd is at most i32::MAX, so this cannot overflow.
        from = fd + 1;
    }
    close_gap(from, u32::MAX)
}

fn close_gap(first: u32, last: u32) -> Result<(), i32> {
    // SAFETY: close_range takes plain integers.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) };
    if rc < 0 { Err(errno()) } else { Ok(()) }
}

/// The step [`Step::SessionKeyring`].
fn join_session_keyring(fault: Fault) -> Result<(), Failure> {
    // A new session keyring of its own: the clone copied the runner's, and
    // the keyring is not namespaced. Before the mounts: joined after them,
    // the runner's keyring kept a reference for as long as the sandbox ran
    // (measured, ADR-007 D2), so something the mount steps create holds
    // the credentials of that moment. Before the filter, which denies
    // keyctl.
    inject(fault, Step::SessionKeyring)?;
    // SAFETY: a NULL name makes the kernel create an anonymous keyring; no
    // memory is passed.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            ffi::KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<c_char>(),
        )
    };
    if rc < 0 {
        return Err(fail(Step::SessionKeyring, 0, errno()));
    }
    Ok(())
}

/// The step [`Step::CgroupNs`].
fn new_cgroup_namespace(fault: Fault) -> Result<(), Failure> {
    // The cgroup namespace is created here, by a process CLONE_INTO_CGROUP
    // has already placed in its sandbox cgroup, so it is rooted there.
    // copy_process creates clone3's namespaces before the move, but since
    // Linux 5.7 (commit ef2c41cf38a7, which added CLONE_INTO_CGROUP)
    // cgroup_post_fork() re-roots a new cgroup namespace at the target
    // css_set, so CLONE_NEWCGROUP in clone3 would be equivalent on every
    // kernel above the 5.19 floor; the step is kept as the simpler reading
    // (ADR-007, D7 and D8).
    inject(fault, Step::CgroupNs)?;
    // SAFETY: unshare takes plain flags.
    if unsafe { libc::unshare(libc::CLONE_NEWCGROUP) } < 0 {
        return Err(fail(Step::CgroupNs, 0, errno()));
    }
    Ok(())
}

fn steps(plan: &ChildPlan<'_>) -> Result<(), Failure> {
    let fault = plan.fault;

    match &plan.action {
        Action::ProbeFilter => {
            allow_all_filter()?;
            // After the install, so that a test hanging here sees the filter.
            inject(fault, Step::Seccomp)?;
            return Ok(());
        }
        Action::Join(join) => return join_steps(join, plan.report_fd, fault),
        Action::Anchor(anchor) => {
            // First of all: the clone copied every descriptor of the runner,
            // among them the report pipes of other setups, whose end this
            // copy would hold open while the anchor waits at its fill point
            // (ADR-042, D3).
            inject(fault, Step::CloseFds)?;
            close_except(anchor.keep).map_err(|e| fail(Step::CloseFds, 0, e))?;
        }
        Action::Exec(_) | Action::ProbeIds => {}
    }

    inject(fault, Step::SetGroups)?;
    write_proc(c"/proc/self/setgroups", b"deny", Step::SetGroups)?;
    inject(fault, Step::GidMap)?;
    write_proc(c"/proc/self/gid_map", plan.gid_line, Step::GidMap)?;
    inject(fault, Step::UidMap)?;
    write_proc(c"/proc/self/uid_map", plan.uid_line, Step::UidMap)?;

    match &plan.action {
        Action::Exec(exec) => {
            join_session_keyring(fault)?;
            inject(fault, Step::OomScoreAdj)?;
            raise_oom_score_adj()?;
            new_cgroup_namespace(fault)?;
            // The root, the mounts, pivot_root, the hostname and lo.
            mount::run(exec.ops, fault)?;
            exec_tail(exec, fault)
        }
        Action::Anchor(anchor) => {
            join_session_keyring(fault)?;
            inject(fault, Step::OomScoreAdj)?;
            raise_oom_score_adj()?;
            new_cgroup_namespace(fault)?;
            anchor_steps(anchor, plan.report_fd, fault)
        }
        Action::ProbeIds | Action::ProbeFilter | Action::Join(_) => Ok(()),
    }
}

/// Writes one progress record (ADR-042, D3) in one `write`: a pipe write
/// of 12 bytes is atomic (below `PIPE_BUF`), so records of two writers
/// never interleave.
fn write_progress(fd: c_int, step: Step, value: u32) -> Result<(), i32> {
    let bytes = report::encode(step, value, 0);
    loop {
        // SAFETY: bytes is valid for its length; fd is the report pipe.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(errno());
        }
        return if n as usize == bytes.len() {
            Ok(())
        } else {
            Err(libc::EIO)
        };
    }
}

/// Reads one byte from `fd`, retrying on EINTR: `Ok(true)` for the byte,
/// `Ok(false)` at EOF.
fn read_byte(fd: c_int) -> Result<bool, i32> {
    let mut b = [0u8; 1];
    loop {
        // SAFETY: b is valid writable memory of the length passed.
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 1) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(errno());
        }
        return Ok(n == 1);
    }
}

/// Whether `lo` holds the loopback address of `family`: a datagram socket
/// binds to it (ADR-042, D3; `/etc/hosts` lists `::1` only where it does).
/// A family the kernel lacks (EAFNOSUPPORT) or an address `lo` lacks
/// (EADDRNOTAVAIL) is absent; any other error fails the step.
fn has_loopback(family: c_int) -> Result<bool, i32> {
    // SAFETY: socket takes plain integers.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return match errno() {
            libc::EAFNOSUPPORT => Ok(false),
            e => Err(e),
        };
    }
    let rc = if family == libc::AF_INET {
        // SAFETY: an all-zero sockaddr_in is valid; the fields are set below.
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        // SAFETY: addr is a valid sockaddr_in of the length passed.
        unsafe {
            libc::bind(
                fd,
                (&addr as *const libc::sockaddr_in).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
    } else {
        // SAFETY: an all-zero sockaddr_in6 is valid; the fields are set below.
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        addr.sin6_addr.s6_addr[15] = 1;
        // SAFETY: addr is a valid sockaddr_in6 of the length passed.
        unsafe {
            libc::bind(
                fd,
                (&addr as *const libc::sockaddr_in6).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };
    let result = if rc == 0 {
        Ok(true)
    } else {
        match errno() {
            libc::EADDRNOTAVAIL => Ok(false),
            e => Err(e),
        }
    };
    // SAFETY: fd was opened above and is closed once.
    unsafe { libc::close(fd) };
    result
}

/// The loopback families of the anchor's network namespace as the bits of
/// [`FAMILY_IPV4`] and [`FAMILY_IPV6`].
fn loopback_families() -> Result<u32, i32> {
    let mut bits = 0;
    if has_loopback(libc::AF_INET)? {
        bits |= FAMILY_IPV4;
    }
    if has_loopback(libc::AF_INET6)? {
        bits |= FAMILY_IPV6;
    }
    Ok(bits)
}

/// The bit of a fill point's progress record for `127.0.0.1` on `lo`.
pub(crate) const FAMILY_IPV4: u32 = 1;
/// The bit for `::1` on `lo`.
pub(crate) const FAMILY_IPV6: u32 = 2;

/// An anchor's sequence after its namespaces exist (ADR-042, D3): the
/// operations up to the fill point, the fill point, the rest, `setsid`,
/// the privilege drop and the plain filter, every descriptor but the
/// report pipe and the pins closed, then the memory release and the hold,
/// which never return. Returns only a failure.
fn anchor_steps(a: &AnchorPlan<'_>, report_fd: c_int, fault: Fault) -> Result<(), Failure> {
    let (Some(before), Some(after)) = (a.ops.get(..a.fill_at), a.ops.get(a.fill_at..)) else {
        return Err(fail(Step::Fill, 0, libc::EINVAL));
    };
    let mut state = mount::State::new();
    mount::run_with(before, fault, &mut state)?;

    // The fill point: the runner copies the workspace in and creates the
    // mount points of the binds after it, through /proc/<pid>/root, while
    // this process waits for one byte on the resume socket.
    inject(fault, Step::Fill)?;
    let families = loopback_families().map_err(|e| fail(Step::Fill, 0, e))?;
    write_progress(report_fd, Step::Fill, families).map_err(|e| fail(Step::Fill, 1, e))?;
    match read_byte(a.resume) {
        Ok(true) => {}
        Ok(false) => return Err(fail(Step::Fill, 2, libc::ECANCELED)),
        Err(e) => return Err(fail(Step::Fill, 2, e)),
    }
    // The binds onto the new mount points, pivot_root and the hostname.
    mount::run_with(after, fault, &mut state)?;
    // The root's descriptor; closed now, before the close below counts.
    drop(state);

    inject(fault, Step::Setsid)?;
    // SAFETY: setsid has no memory arguments.
    if unsafe { libc::setsid() } < 0 {
        return Err(fail(Step::Setsid, 0, errno()));
    }

    // The plain program, no listener: nothing is notified (ADR-043).
    privileges::drop_all(&a.privileges, fault)?;

    // The resume socket goes here, and anything opened since the first
    // close; the pins stay, and the report pipe until the hold.
    close_except(a.hold).map_err(|e| fail(Step::CloseFds, 1, e))?;

    inject(fault, Step::Release)?;
    // SAFETY: maps is NUL-terminated and prepared before the clone.
    let maps = unsafe { libc::open(a.maps.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if maps < 0 {
        return Err(fail(Step::Release, 0, errno()));
    }
    // A local of this frame: the release keeps the stack up to it and no
    // further, since nothing above is ever returned to. Its address
    // escapes into the call, so the call is no tail call and this frame
    // stays above the release's.
    let frame = 0u8;
    let caller = std::hint::black_box(&frame) as *const u8 as usize;
    crate::release::release_and_hold(maps, report_fd, a.bss, a.page, caller)
}

/// The first stage of a join (ADR-042, D3), then, in the second stage it
/// clones, the anchor or the exec. Returns in the first stage once it
/// recorded the second's pid; in the second only a failure.
fn join_steps(join: &JoinPlan<'_>, report_fd: c_int, fault: Fault) -> Result<(), Failure> {
    // As for an anchor: the runner's other report pipes must not stay
    // open here (ADR-042, D3).
    inject(fault, Step::CloseFds)?;
    close_except(join.keep).map_err(|e| fail(Step::CloseFds, 0, e))?;

    // Before setns: once in the anchor's mount namespace, /proc is the
    // anchor's, which does not show this process.
    inject(fault, Step::OomScoreAdj)?;
    raise_oom_score_adj()?;

    inject(fault, Step::Setns)?;
    // SAFETY: setns takes a descriptor and plain flags.
    if unsafe { libc::setns(join.anchor, join.setns) } < 0 {
        return Err(fail(Step::Setns, 0, errno()));
    }
    // setns leaves the process dumpable: commit_creds counts the runner's
    // credentials, the owner's in the parent namespace, as a superset of
    // the ones setns gives, so the runner still opens /proc/<pid>/root of
    // a later anchor at its fill point (measured; the tests' later anchors
    // are filled through it).

    join_session_keyring(fault)?;

    inject(fault, Step::Unshare)?;
    // SAFETY: unshare takes plain flags.
    if unsafe { libc::unshare(join.unshare) } < 0 {
        return Err(fail(Step::Unshare, 0, errno()));
    }

    inject(fault, Step::InnerClone)?;
    // The gate: the second stage waits for EOF or a byte on it, so its own
    // records never come before the first stage's pid record.
    let mut gate = [0 as c_int; 2];
    // SAFETY: gate is a valid array of two ints for pipe2 to fill.
    if unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(fail(Step::InnerClone, 1, errno()));
    }
    let args = libc::clone_args {
        flags: crate::spawn::inner_clone_flags(),
        pidfd: 0,
        child_tid: 0,
        parent_tid: join.tid as u64,
        // clone3 refuses CLONE_PARENT with an exit signal; the child gets
        // this process's, SIGCHLD to the runner.
        exit_signal: 0,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    // SAFETY: args is a valid clone_args of the size passed. Without
    // CLONE_VM the child gets a copy of this address space, as with fork,
    // and continues on its copy of this stack.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const libc::clone_args,
            std::mem::size_of::<libc::clone_args>(),
        )
    };
    if pid < 0 {
        let e = errno();
        // SAFETY: both ends were opened above and are closed once.
        unsafe { libc::close(gate[0]) };
        // SAFETY: as above.
        unsafe { libc::close(gate[1]) };
        return Err(fail(Step::InnerClone, 0, e));
    }
    if pid == 0 {
        // The second stage: PID 1 of the new PID namespace.
        // SAFETY: the write end is this copy's; closed once.
        unsafe { libc::close(gate[1]) };
        let opened = read_byte(gate[0]);
        // SAFETY: the read end is this copy's; closed once.
        unsafe { libc::close(gate[0]) };
        match opened {
            Ok(true) => {}
            Ok(false) => {
                // The first stage died or failed after the clone; the
                // runner knows this pid from its page and reaps this
                // process. No second report.
                // SAFETY: _exit ends this process without running anything
                // of the runner's copy.
                unsafe { libc::_exit(127) }
            }
            Err(e) => return Err(fail(Step::InnerClone, 2, e)),
        }
        // The runner's pid page goes; an anchor would keep it for good.
        // SAFETY: the page was mapped by the runner before the clone, at
        // this address and of this length; nothing here refers to it.
        if unsafe { libc::munmap(join.tid as *mut libc::c_void, TID_PAGE) } < 0 {
            return Err(fail(Step::InnerClone, 3, errno()));
        }
        return match &join.then {
            Joined::Anchor(a) => {
                // Down to the anchor's own: the first stage kept the pidfd
                // of the anchor it joined, which this one does not need.
                close_except(a.keep).map_err(|e| fail(Step::CloseFds, 2, e))?;
                anchor_steps(a, report_fd, fault)
            }
            Joined::Exec(exec) => {
                mount::run(exec.ops, fault)?;
                exec_tail(exec, fault)
            }
        };
    }
    // The first stage. Every failure from here carries the pid, so the
    // runner reaps the second stage, which the closed gate ends.
    let pid = pid as u32;
    // SAFETY: the read end is this copy's; closed once.
    unsafe { libc::close(gate[0]) };
    inject(fault, Step::Forked).map_err(|f| fail(f.step, pid, f.errno))?;
    write_progress(report_fd, Step::Forked, pid).map_err(|e| fail(Step::Forked, pid, e))?;
    let one = [1u8; 1];
    // SAFETY: one is valid for its length; gate[1] is the write end.
    let n = unsafe { libc::write(gate[1], one.as_ptr().cast(), 1) };
    if n != 1 {
        return Err(fail(Step::Forked, pid, errno()));
    }
    // SAFETY: the write end is this copy's; closed once.
    unsafe { libc::close(gate[1]) };
    Ok(())
}

/// The sequence of `spawn` from `setsid` to `execve` (ADR-007, D4), also
/// the second stage of an exec joined to an anchor. Returns only a
/// failure.
fn exec_tail(exec: &ExecPlan<'_>, fault: Fault) -> Result<(), Failure> {
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

    // Capabilities, no_new_privs and the seccomp filter last, so that only
    // the listener hand-off and execve run under the filter before the
    // program (ADR-007 D9, ADR-043 D3).
    let listener = privileges::drop_all(&exec.privileges, fault)?;

    inject(fault, Step::Listener)?;
    send_listener(exec.listener_sock, listener, fault)?;

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
    fn oom_score_adj_raised_never_lowered() {
        for (text, value) in [
            (&b"0\n"[..], 0),
            (b"200\n", 200),
            (b"1000", 1000),
            (b"-1\n", -1),
            (b"-1000\n", -1000),
        ] {
            assert_eq!(parse_oom_score_adj(text), Some(value), "{text:?}");
        }
        for bad in [
            &b""[..],
            b"\n",
            b"-",
            b"1a",
            b"+5",
            b" 5",
            b"10000",
            b"-10000",
        ] {
            assert_eq!(parse_oom_score_adj(bad), None, "{bad:?}");
        }
        // Negative values are raised to 0; 0 and above stay as they are.
        assert_eq!(oom_score_adj_raise(-1000), Some(&b"0"[..]));
        assert_eq!(oom_score_adj_raise(-1), Some(&b"0"[..]));
        assert_eq!(oom_score_adj_raise(0), None);
        assert_eq!(oom_score_adj_raise(200), None);
        assert_eq!(oom_score_adj_raise(1000), None);
    }

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
        // The sequence holds every step once; the filter comes after
        // no_new_privs (ADR-007, D9), and only the listener hand-off sits
        // between it and the exec (ADR-043, D3); the listener's code is 30.
        // spawn's sequence holds the 30 steps it had before the anchors;
        // each sequence holds a step at most once, and together they hold
        // every step (ADR-042, D3).
        let mut seen: Vec<Step> = Step::SEQUENCE.to_vec();
        seen.sort_by_key(|s| s.code());
        assert_eq!(seen, Step::ALL[..30]);
        let mut union = std::collections::BTreeSet::new();
        for sequence in [
            &Step::SEQUENCE[..],
            &Step::ANCHOR_SEQUENCE,
            &Step::JOIN_SEQUENCE,
            &Step::EXEC_SEQUENCE,
        ] {
            let codes: std::collections::BTreeSet<u32> =
                sequence.iter().map(|s| s.code()).collect();
            assert_eq!(codes.len(), sequence.len(), "no step twice: {sequence:?}");
            union.extend(codes);
        }
        assert_eq!(union.len(), Step::ALL.len(), "every step in a sequence");
        // The anchors end in the release, after the filter; the joins
        // record the second stage's pid right after the inner clone.
        assert_eq!(Step::ANCHOR_SEQUENCE[27], Step::Release);
        assert_eq!(Step::ANCHOR_SEQUENCE[26], Step::Seccomp);
        assert_eq!(Step::JOIN_SEQUENCE[26], Step::Release);
        for joined in [&Step::JOIN_SEQUENCE[..], &Step::EXEC_SEQUENCE] {
            assert_eq!(joined[5..7], [Step::InnerClone, Step::Forked]);
        }
        assert_eq!(Step::EXEC_SEQUENCE[20], Step::Exec);
        assert_eq!(Step::Release.code(), 36);
        let n = Step::SEQUENCE.len();
        assert_eq!(
            Step::SEQUENCE[n - 9..],
            [
                Step::CloseFds,
                Step::Securebits,
                Step::CapBoundingSet,
                Step::CapAmbient,
                Step::Capset,
                Step::NoNewPrivs,
                Step::Seccomp,
                Step::Listener,
                Step::Exec
            ]
        );
        assert_eq!(Step::Listener.code(), 30);
        assert_eq!(Step::Listener.name(), "listener");
        assert_eq!(Step::from_code(9999), None);
    }
}
