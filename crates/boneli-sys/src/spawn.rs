//! Starting a program in new namespaces with its own root (ADR-007, D1, D4
//! and D7).

use std::ffi::{CString, OsString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::cgroup::Cgroup;
use crate::child::{self, Action, ChildPlan, ExecPlan, Fault};
use crate::error::{Error, Result, errno};
use crate::ffi;
use crate::ids::Ids;
use crate::mount::{self, Op, Root};
use crate::report;

/// The three standard descriptors of the program. They are duplicated
/// while spawning; the spec keeps owning them, so dropping the spec after
/// [`spawn`] closes the caller's copies (and with them, for a pipe, the
/// last writer besides the child).
#[derive(Debug)]
pub struct Stdio {
    /// Becomes descriptor 0.
    pub stdin: OwnedFd,
    /// Becomes descriptor 1.
    pub stdout: OwnedFd,
    /// Becomes descriptor 2.
    pub stderr: OwnedFd,
}

/// What to run and how.
#[derive(Debug)]
pub struct Spec<'a> {
    /// Absolute path of the program inside the sandbox, resolved after
    /// `pivot_root`; there is no `PATH` search.
    pub program: PathBuf,
    /// Arguments after `argv[0]`, which is the program path.
    pub args: Vec<OsString>,
    /// The program's whole environment: nothing is inherited.
    pub env: Vec<(OsString, OsString)>,
    /// Descriptors 0, 1 and 2; no other descriptor reaches the program.
    pub stdio: Stdio,
    /// The ids inside.
    pub ids: Ids,
    /// The root, mounts, hostname and working directory (ADR-007, D7).
    pub root: Root,
    /// The cgroup the child is placed in at the clone, so it never runs
    /// outside its limits (ADR-007, D8).
    pub cgroup: &'a Cgroup,
    /// How long the child may take from the clone to the exec before it is
    /// killed. No default: the caller sizes it, and zero is rejected.
    pub setup_timeout: Duration,
}

/// How a child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// It exited with this code.
    Exited(i32),
    /// A signal with this number killed it.
    Signaled(i32),
}

/// A running child, addressed by its pidfd so a recycled pid is never hit.
/// Dropping a child that was not waited for kills and reaps it.
#[derive(Debug)]
pub struct Child {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    waited: bool,
}

impl Child {
    pub(crate) fn from_launched(launched: Launched) -> Child {
        Child {
            pid: launched.pid,
            pidfd: launched.pidfd,
            waited: false,
        }
    }

    /// The child's pid in the caller's pid namespace.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The pidfd; it becomes readable when the child exits.
    pub fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// Waits for the child to exit and reaps it. A second call is
    /// [`Error::AlreadyWaited`].
    pub fn wait(&mut self) -> Result<ExitStatus> {
        if self.waited {
            return Err(Error::AlreadyWaited);
        }
        let status = reap(&self.pidfd)?;
        self.waited = true;
        Ok(status)
    }

    /// Sends SIGKILL through the pidfd.
    pub fn kill(&self) -> Result<()> {
        if self.waited {
            return Err(Error::AlreadyWaited);
        }
        send_kill(&self.pidfd)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.waited {
            let _ = send_kill(&self.pidfd);
            let _ = reap(&self.pidfd);
        }
    }
}

fn send_kill(pidfd: &OwnedFd) -> Result<()> {
    // SAFETY: pidfd_send_signal takes a descriptor, a signal number, a null
    // siginfo (the kernel fills a default one) and no flags.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if rc < 0 {
        Err(Error::last("pidfd_send_signal"))
    } else {
        Ok(())
    }
}

/// Blocks until the child behind `pidfd` exits and reaps it.
fn reap(pidfd: &OwnedFd) -> Result<ExitStatus> {
    loop {
        // SAFETY: an all-zero siginfo_t is valid storage for waitid to fill.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: info is valid storage; P_PIDFD takes the descriptor as id.
        let rc = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED,
            )
        };
        if rc < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(Error::last("waitid"));
        }
        // SAFETY: waitid filled info for an exited child, so the SIGCHLD
        // member of the union, which holds si_status, is the active one.
        let status = unsafe { info.si_status() };
        return Ok(if info.si_code == libc::CLD_EXITED {
            ExitStatus::Exited(status)
        } else {
            ExitStatus::Signaled(status)
        });
    }
}

/// The caller's identity check (ADR-007, D1): a root caller would map the
/// sandbox onto host root, and a setuid or setgid caller would map it onto
/// an id the real user does not own.
pub(crate) fn check_caller(ruid: u32, euid: u32, rgid: u32, egid: u32) -> Result<()> {
    if ruid != euid || rgid != egid {
        return Err(Error::SetuidCaller);
    }
    if euid == 0 || egid == 0 {
        return Err(Error::RunningAsRoot);
    }
    Ok(())
}

fn caller() -> (u32, u32, u32, u32) {
    // SAFETY: the four id getters have no preconditions and cannot fail.
    let ruid = unsafe { libc::getuid() };
    // SAFETY: as above.
    let euid = unsafe { libc::geteuid() };
    // SAFETY: as above.
    let rgid = unsafe { libc::getgid() };
    // SAFETY: as above.
    let egid = unsafe { libc::getegid() };
    (ruid, euid, rgid, egid)
}

fn c_string(bytes: Vec<u8>, what: &'static str) -> Result<CString> {
    CString::new(bytes).map_err(|_| Error::Nul(what))
}

/// A descriptor duplicated to >= 3 with close-on-exec, so the child's dup2
/// onto 0-2 never overwrites another source.
fn dup_high(fd: &OwnedFd) -> Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC takes a descriptor and a minimum number.
    let new = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if new < 0 {
        return Err(Error::last("fcntl(F_DUPFD_CLOEXEC)"));
    }
    // SAFETY: fcntl returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// Every byte the child needs, prepared before the clone.
struct Prepared {
    program: CString,
    _strings: Vec<CString>,
    argv: Vec<*const c_char>,
    envp: Vec<*const c_char>,
    uid_line: Vec<u8>,
    gid_line: Vec<u8>,
    stdio: [OwnedFd; 3],
    ops: Vec<Op>,
}

fn prepare(spec: &Spec<'_>) -> Result<Prepared> {
    if spec.setup_timeout.is_zero() {
        return Err(Error::ZeroSetupTimeout);
    }
    if !spec.program.is_absolute() {
        return Err(Error::RelativeProgram(spec.program.clone()));
    }
    let (ruid, euid, rgid, egid) = caller();
    check_caller(ruid, euid, rgid, egid)?;
    let ops = mount::plan(&spec.root)?;

    let program = c_string(
        spec.program.as_os_str().as_bytes().to_vec(),
        "the program path",
    )?;
    let mut strings = Vec::with_capacity(spec.args.len() + spec.env.len() + 1);
    strings.push(program.clone());
    for arg in &spec.args {
        strings.push(c_string(arg.clone().into_vec(), "an argument")?);
    }
    let argc = strings.len();
    for (name, value) in &spec.env {
        let name = name.as_bytes();
        if name.is_empty() || name.contains(&b'=') {
            return Err(Error::InvalidEnvName(OsString::from_vec(name.to_vec())));
        }
        let mut entry = name.to_vec();
        entry.push(b'=');
        entry.extend_from_slice(value.as_bytes());
        strings.push(c_string(entry, "an environment entry")?);
    }
    // The CStrings' heap buffers do not move when `strings` is moved into
    // Prepared, so these pointers stay valid as long as it lives.
    let mut argv: Vec<*const c_char> = strings[..argc].iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const c_char> = strings[argc..].iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    let stdio = [
        dup_high(&spec.stdio.stdin)?,
        dup_high(&spec.stdio.stdout)?,
        dup_high(&spec.stdio.stderr)?,
    ];
    Ok(Prepared {
        program,
        _strings: strings,
        argv,
        envp,
        uid_line: spec.ids.uid_map_line(euid).into_bytes(),
        gid_line: spec.ids.gid_map_line(egid).into_bytes(),
        stdio,
        ops,
    })
}

/// A cloned child before its report was read.
pub(crate) struct Launched {
    pub pid: libc::pid_t,
    pub pidfd: OwnedFd,
}

/// The close-on-exec report pipe: `(read, write)`. The write end is moved to
/// a descriptor >= 3: a caller with 0-2 closed would get it there, and the
/// child's `dup2` onto 0-2 would then replace it, so a later failed step
/// would write its report into the program's stdio instead.
pub(crate) fn report_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds is a valid array of two ints for pipe2 to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(Error::last("pipe2"));
    }
    // SAFETY: pipe2 succeeded, so fds[0] is open and owned by nobody else.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: as above, for the write end.
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    let write = dup_high(&write)?;
    Ok((read, write))
}

/// Sets the calling thread's signal mask with the raw syscall, which also
/// covers the signals glibc reserves; returns the previous mask.
fn set_signal_mask(mask: u64) -> Result<u64> {
    let mut old: u64 = 0;
    // SAFETY: both sets are valid kernel signal sets of the size passed.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            &mask as *const u64,
            &mut old as *mut u64,
            crate::ffi::SIGSET_SIZE,
        )
    };
    if rc < 0 {
        Err(Error::last("rt_sigprocmask"))
    } else {
        Ok(old)
    }
}

/// The namespaces `clone3` creates for `spawn`: user, mount, PID, network,
/// IPC and UTS. The cgroup namespace comes later, from the child itself
/// (`Step::CgroupNs`), once `CLONE_INTO_CGROUP` has placed it in its
/// cgroup, so the namespace is rooted there (ADR-007, D7 and D8).
pub(crate) const SPAWN_NAMESPACES: u64 = (libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS) as u64;

/// Clones a child that runs `plan`: in the namespaces of
/// [`SPAWN_NAMESPACES`] for `spawn`, in a new user namespace only for the
/// probe's id child, and in none for its filter child. Returns in the
/// parent only; the child never returns from here.
pub(crate) fn launch(plan: &ChildPlan<'_>) -> Result<Launched> {
    let mut pidfd: c_int = -1;
    let (flags, cgroup) = match &plan.action {
        // The probe's filter child must not depend on user namespaces.
        Action::ProbeFilter => (libc::CLONE_PIDFD as u64, 0),
        Action::ProbeIds => ((libc::CLONE_NEWUSER | libc::CLONE_PIDFD) as u64, 0),
        // Into its cgroup at the clone: the child never runs outside its
        // limits, not even for its setup (ADR-007, D8).
        Action::Exec(exec) => (
            SPAWN_NAMESPACES | libc::CLONE_PIDFD as u64 | ffi::CLONE_INTO_CGROUP,
            exec.cgroup as u64,
        ),
    };
    let args = libc::clone_args {
        flags,
        pidfd: &mut pidfd as *mut c_int as u64,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        // No stack: like fork, the child continues on its copy of this one.
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup,
    };
    // Every signal stays blocked from the clone until the child has reset
    // its dispositions (Step::Signals), so no handler of this process runs
    // in the child; this thread's mask is restored right after the clone,
    // as glibc's posix_spawn does (ADR-007, D4).
    let old_mask = set_signal_mask(!0)?;
    // SAFETY: args is a valid clone_args of the size passed. Without
    // CLONE_VM the child gets a copy of this address space, as with fork.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const libc::clone_args,
            std::mem::size_of::<libc::clone_args>(),
        )
    };
    if pid == 0 {
        // SAFETY: this is the child of the clone3 above, without CLONE_VM,
        // and plan refers to memory prepared before it.
        unsafe { child::run(plan) }
    }
    let clone_errno = errno();
    let restored = set_signal_mask(old_mask);
    if pid < 0 {
        return Err(Error::Sys {
            call: "clone3",
            errno: clone_errno,
        });
    }
    if let Err(e) = restored {
        // SAFETY: clone3 stored a descriptor in pidfd that nothing owns yet.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
        let _ = send_kill(&pidfd);
        let _ = reap(&pidfd);
        return Err(e);
    }
    // SAFETY: clone3 with CLONE_PIDFD stored a new descriptor in pidfd that
    // nothing else owns.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    Ok(Launched {
        pid: pid as libc::pid_t,
        pidfd,
    })
}

/// Reads the report until EOF or the deadline. On anything but success the
/// child is killed (if it may still run) and reaped.
pub(crate) fn await_report(read: &OwnedFd, launched: &Launched, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    // One byte more than a report, to see an overlong one.
    let mut buf = [0u8; report::LEN + 1];
    let mut len = 0;
    let outcome = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break Err(Error::SetupTimeout(timeout));
        }
        let mut pfd = libc::pollfd {
            fd: read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Round up, so a remaining 0.4 ms does not poll with 0 and spin.
        let ms = left.as_micros().div_ceil(1000).min(c_int::MAX as u128) as c_int;
        // SAFETY: pfd is one valid pollfd for the call's duration.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            break Err(Error::last("poll"));
        }
        if rc == 0 {
            continue;
        }
        // SAFETY: buf[len..] is valid writable memory of the length passed.
        let n = unsafe {
            libc::read(
                read.as_raw_fd(),
                buf[len..].as_mut_ptr().cast(),
                buf.len() - len,
            )
        };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            break Err(Error::last("read"));
        }
        if n == 0 {
            break report::decode(&buf[..len]);
        }
        len += n as usize;
        if len > report::LEN {
            break report::decode(&buf[..len]);
        }
    };
    match outcome {
        Ok(()) => Ok(()),
        Err(e) => {
            // A failed step exits on its own; anything else may still run.
            if !matches!(e, Error::Setup { .. }) {
                let _ = send_kill(&launched.pidfd);
            }
            let _ = reap(&launched.pidfd);
            Err(e)
        }
    }
}

/// Starts `spec.program` in `spec.cgroup` (placed there at the clone,
/// ADR-007 D8) and in new user, mount, PID, network, IPC, UTS and cgroup
/// namespaces with the single id mapping of `spec.ids` (ADR-007,
/// D1), the read-only root and mounts of `spec.root`, its hostname and `lo`
/// up (ADR-007, D7), a new session, default signal dispositions, an empty
/// signal mask and only descriptors 0-2 (ADR-007, D4). Returns once the
/// program was exec'd.
///
/// Errors before the clone: [`Error::ZeroSetupTimeout`],
/// [`Error::RelativeProgram`], [`Error::RunningAsRoot`],
/// [`Error::SetuidCaller`], [`Error::Nul`], [`Error::InvalidEnvName`], and
/// for the root [`Error::InvalidRoot`], [`Error::InvalidMount`] and
/// [`Error::MountOptionsTooLong`].
/// After it: [`Error::Setup`] with the failed step, or
/// [`Error::SetupTimeout`] and [`Error::Protocol`], after which the child
/// was killed; in every error case it was reaped.
pub fn spawn(spec: &Spec<'_>) -> Result<Child> {
    let mut pid = 0;
    spawn_inner(spec, Fault::None, &mut pid)
}

/// [`spawn`] with a fault for the unit tests; `pid` receives the cloned
/// child's pid, so tests can check that it was reaped.
pub(crate) fn spawn_inner(spec: &Spec<'_>, fault: Fault, pid: &mut libc::pid_t) -> Result<Child> {
    let prepared = prepare(spec)?;
    let (read, write) = report_pipe()?;
    let stdio: [RawFd; 3] = [
        prepared.stdio[0].as_raw_fd(),
        prepared.stdio[1].as_raw_fd(),
        prepared.stdio[2].as_raw_fd(),
    ];
    let plan = ChildPlan {
        gid_line: &prepared.gid_line,
        uid_line: &prepared.uid_line,
        action: Action::Exec(ExecPlan {
            program: &prepared.program,
            argv: &prepared.argv,
            envp: &prepared.envp,
            stdio,
            ops: &prepared.ops,
            cgroup: spec.cgroup.dir_fd(),
        }),
        report_fd: write.as_raw_fd(),
        fault,
    };
    let launched = launch(&plan)?;
    *pid = launched.pid;
    // The child holds the only other write end now; EOF comes at its exec
    // or exit.
    drop(write);
    await_report(&read, &launched, spec.setup_timeout)?;
    Ok(Child::from_launched(launched))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::child::Step;

    fn null() -> OwnedFd {
        std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null")
            .into()
    }

    /// A spec on `root` in `cgroup`; the pure tests pass a root that is
    /// never mounted and a cgroup that never was one.
    fn spec_on<'a>(
        program: &str,
        timeout: Duration,
        root: &crate::Root,
        cgroup: &'a Cgroup,
    ) -> Spec<'a> {
        Spec {
            program: PathBuf::from(program),
            args: Vec::new(),
            env: Vec::new(),
            stdio: Stdio {
                stdin: null(),
                stdout: null(),
                stderr: null(),
            },
            ids: Ids::new(0, 0).expect("valid ids"),
            setup_timeout: timeout,
            root: root.clone(),
            cgroup,
        }
    }

    fn unmounted_root() -> crate::Root {
        crate::Root {
            layers: vec![PathBuf::from("/nonexistent/layer")],
            staging: PathBuf::from("/nonexistent/staging"),
            mounts: Vec::new(),
            hostname: crate::Hostname::new("unit").expect("hostname"),
            cwd: crate::InsidePath::root(),
        }
    }

    fn spec<'a>(program: &str, timeout: Duration, cgroup: &'a Cgroup) -> Spec<'a> {
        spec_on(program, timeout, &unmounted_root(), cgroup)
    }

    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("list /proc/self/fd")
            .count()
    }

    fn reaped(pid: libc::pid_t) -> bool {
        !std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    #[test]
    fn caller_identity_checks() {
        assert!(check_caller(1000, 1000, 1000, 1000).is_ok());
        assert!(matches!(
            check_caller(0, 0, 1000, 1000),
            Err(Error::RunningAsRoot)
        ));
        assert!(matches!(
            check_caller(1000, 1000, 0, 0),
            Err(Error::RunningAsRoot)
        ));
        assert!(matches!(
            check_caller(1000, 0, 1000, 1000),
            Err(Error::SetuidCaller)
        ));
        assert!(matches!(
            check_caller(0, 1000, 1000, 1000),
            Err(Error::SetuidCaller)
        ));
        assert!(matches!(
            check_caller(1000, 1000, 1000, 0),
            Err(Error::SetuidCaller)
        ));
        assert!(matches!(
            check_caller(1000, 1000, 0, 1000),
            Err(Error::SetuidCaller)
        ));
    }

    #[test]
    fn spawn_clone_flags() {
        // The cgroup namespace is the child's own step, after
        // CLONE_INTO_CGROUP placed it (ADR-007, D8).
        assert_eq!(SPAWN_NAMESPACES & libc::CLONE_NEWCGROUP as u64, 0);
        assert_eq!(ffi::CLONE_INTO_CGROUP, 1 << 33);
    }

    #[test]
    fn zero_setup_timeout_rejected() {
        let cg = Cgroup::unplaced();
        assert!(matches!(
            spawn(&spec("/bin/true", Duration::ZERO, &cg)),
            Err(Error::ZeroSetupTimeout)
        ));
    }

    #[test]
    fn nul_and_env_names_rejected() {
        let cg = Cgroup::unplaced();
        let mut s = spec("/bin/true", Duration::from_secs(1), &cg);
        s.args.push(OsString::from_vec(b"a\0b".to_vec()));
        assert!(matches!(spawn(&s), Err(Error::Nul("an argument"))));
        for name in ["", "A=B"] {
            let mut s = spec("/bin/true", Duration::from_secs(1), &cg);
            s.env.push((OsString::from(name), OsString::from("v")));
            assert!(
                matches!(spawn(&s), Err(Error::InvalidEnvName(_))),
                "{name:?}"
            );
        }
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn every_step_failure_is_reported() {
        let _host = crate::test_guard::host_lock();
        // Step::Seccomp is not part of spawn's sequence yet (only the probe
        // runs it; host::tests covers it there). The root has a mount of
        // every kind, so every mount step is reached.
        let unit = crate::test_guard::UnitRoot::new();
        for step in Step::SEQUENCE {
            let before = open_fds();
            let mut pid = 0;
            let cg = crate::test_guard::sandbox_cgroup("every-step");
            let s = spec_on("/bin/true", Duration::from_secs(10), &unit.root, &cg);
            match spawn_inner(&s, Fault::Fail(step), &mut pid) {
                Err(Error::Setup {
                    step: got,
                    index: 0,
                    errno,
                }) => {
                    assert_eq!(got, step);
                    assert_eq!(errno, libc::EIO, "{step:?}");
                }
                other => panic!("{step:?}: {other:?}"),
            }
            drop(s);
            cg.destroy().expect("destroy the cgroup");
            assert!(pid > 0 && reaped(pid), "{step:?}: child {pid} reaped");
            assert_eq!(open_fds(), before, "{step:?}: no descriptor leaked");
        }
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn setup_timeout_kills_hung_child() {
        let _host = crate::test_guard::host_lock();
        let unit = crate::test_guard::UnitRoot::new();
        let cg = crate::test_guard::sandbox_cgroup("timeout");
        let before = open_fds();
        let s = spec_on("/bin/true", Duration::from_millis(200), &unit.root, &cg);
        let mut pid = 0;
        let start = Instant::now();
        let result = spawn_inner(&s, Fault::Hang(Step::Setsid), &mut pid);
        let took = start.elapsed();
        assert!(
            matches!(result, Err(Error::SetupTimeout(t)) if t == Duration::from_millis(200)),
            "{result:?}"
        );
        assert!(
            took >= Duration::from_millis(200),
            "returned after {took:?}"
        );
        assert!(took < Duration::from_secs(5), "returned after {took:?}");
        drop(s);
        assert!(pid > 0 && reaped(pid), "child {pid} reaped");
        assert_eq!(open_fds(), before, "no descriptor leaked");
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn allocation_guard_catches_child_allocation() {
        let _host = crate::test_guard::host_lock();
        let unit = crate::test_guard::UnitRoot::new();
        let cg = crate::test_guard::sandbox_cgroup("alloc");
        let s = spec_on("/bin/true", Duration::from_secs(10), &unit.root, &cg);
        let mut pid = 0;
        // The guard ends the child before it reaches exec or writes a
        // report; the parent cannot tell that EOF from an exec, so the
        // exit code is what shows it.
        let mut child =
            spawn_inner(&s, Fault::Allocate(Step::Setsid), &mut pid).expect("EOF without a report");
        assert_eq!(
            child.wait().expect("wait"),
            ExitStatus::Exited(crate::test_guard::EXIT_ALLOCATED)
        );
    }

    static HANDLER_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

    extern "C" fn record_pid(_sig: libc::c_int) {
        // SAFETY: getpid is async-signal-safe and cannot fail.
        let pid = unsafe { libc::getpid() }.to_ne_bytes();
        let fd = HANDLER_FD.load(std::sync::atomic::Ordering::Relaxed);
        // SAFETY: write is async-signal-safe; pid is a local array.
        unsafe { libc::write(fd, pid.as_ptr().cast(), pid.len()) };
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn parent_handlers_never_run_in_the_child() {
        let _host = crate::test_guard::host_lock();
        let (read, write) = report_pipe().expect("pipe");
        // SAFETY: O_NONBLOCK on our own read end only changes how reads wait.
        unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        HANDLER_FD.store(write.as_raw_fd(), std::sync::atomic::Ordering::Relaxed);
        // SAFETY: an all-zero sigaction is valid storage for both actions.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = record_pid as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = libc::SA_RESTART;
        // SAFETY: as above.
        let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            // SAFETY: both actions are valid; the handler is async-signal-safe.
            unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut old) },
            0
        );

        // The child hangs after its id maps, before Step::Signals: the window
        // in which it still has the parent's handlers.
        let unit = crate::test_guard::UnitRoot::new();
        let root = unit.root.clone();
        let worker = std::thread::spawn(move || {
            let cg = crate::test_guard::sandbox_cgroup("handlers");
            let s = spec_on("/bin/true", Duration::from_millis(1500), &root, &cg);
            let mut pid = 0;
            let result = spawn_inner(&s, Fault::Hang(Step::Setsid), &mut pid);
            (result.map(|_| ()), pid)
        });
        let child = crate::test_guard::wait_for_child(Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(200));
        // SAFETY: kill takes plain integers; the child is ours and alive
        // until the setup timeout.
        assert_eq!(unsafe { libc::kill(child, libc::SIGUSR1) }, 0);
        // Control: the handler works in this process.
        // SAFETY: as above, for this process.
        let parent = unsafe { libc::getpid() };
        // SAFETY: as above.
        assert_eq!(unsafe { libc::kill(parent, libc::SIGUSR1) }, 0);
        let (result, pid) = worker.join().expect("spawning thread");
        assert!(matches!(result, Err(Error::SetupTimeout(_))), "{result:?}");
        assert_eq!(pid, child);

        // SAFETY: old holds the previous action.
        unsafe { libc::sigaction(libc::SIGUSR1, &old, std::ptr::null_mut()) };
        let mut ran_in = Vec::new();
        let mut buf = [0u8; 4];
        // SAFETY: buf is valid for 4 bytes; the read end is non-blocking.
        while unsafe { libc::read(read.as_raw_fd(), buf.as_mut_ptr().cast(), 4) } == 4 {
            ran_in.push(i32::from_ne_bytes(buf));
        }
        assert!(
            ran_in.contains(&parent),
            "the handler ran in the parent: {ran_in:?}"
        );
        assert!(
            !ran_in.contains(&child),
            "a parent handler ran in the child {child}: {ran_in:?}"
        );
    }
}
