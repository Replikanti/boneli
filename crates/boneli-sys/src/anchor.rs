//! A pod's anchors and the commands joined to them (ADR-042, D3).
//!
//! A pod is one user namespace with the single id mapping of ADR-007 (D1)
//! and one network namespace with only `lo`. Each container of a pod has
//! an **anchor**: a clone of the runner that never execs, PID 1 of a PID
//! namespace no workload sees, which owns the container's mount, UTS and
//! IPC namespaces and holds its layer pins (ADR-025, D2) for as long as the
//! pod lives. Every command joins an anchor in two stages, so it gets a PID
//! namespace and a copy of the mount namespace of its own and is PID 1 of
//! it, as a `spawn`ed program is.
//!
//! The runner is the parent of every anchor and every program
//! (`CLONE_PARENT`), and reaps each through its own pidfd. Code in the
//! same process that reaps with `waitpid(-1)` or sets `SIGCHLD` to
//! `SIG_IGN` would take those exits; std does neither.

use std::ffi::{CString, OsString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

use crate::cgroup::Cgroup;
use crate::child::{
    Action, AnchorPlan, ChildPlan, ExecPlan, FAMILY_IPV4, FAMILY_IPV6, Fault, JoinPlan, Joined,
    Step,
};
use crate::error::{Error, ProtocolError, Result, errno};
use crate::ffi;
use crate::ids::Ids;
use crate::mount::{self, InsidePath, Mount, Op, Root};
use crate::privileges::PrivilegeDrop;
use crate::release;
use crate::report::{self, Record};
use crate::seccomp::notify::Seam;
use crate::spawn::{
    self, ANCHOR_SETNS, ANCHOR_UNSHARE, Child, EXEC_SETNS, EXEC_UNSHARE, Filters, Launched, Stdio,
    caller, check_caller, dup_high, launch, listener_socket, reap, report_pipe, send_kill,
};

/// What an anchor is made of.
#[derive(Debug)]
pub struct AnchorSpec<'a> {
    /// The ids inside. A pod has one mapping: [`Anchor::join`] refuses
    /// ids other than its pod's.
    pub ids: Ids,
    /// The container's root, mounts and hostname (ADR-007, D7). It needs
    /// a [`Mount::Proc`], which the release reads and every exec mounts its
    /// own procfs over, and a [`Mount::Dev`], whose `null` covers the
    /// `keys` files of that procfs. `cwd` is unused: an exec has its own.
    pub root: Root,
    /// How many of `root.mounts` come before the fill point; the rest come
    /// after it, once the runner has created their mount points
    /// ([`Anchor::fill`]).
    pub fill_at: usize,
    /// The descriptors the anchor holds for the pod's life: the layer pins
    /// of ADR-025 (D2). The spec keeps owning them; dropping it closes the
    /// runner's copies, and the anchor's stay open until it dies.
    pub pins: Vec<OwnedFd>,
    /// The pod's cgroup, which every process of the pod is placed in at
    /// its clone (ADR-007, D8).
    pub cgroup: &'a Cgroup,
    /// How long the anchor may take from the clone to its fill point, and
    /// from the resume to its hold, before it is killed. No default, zero
    /// is refused. The fill itself is not counted.
    pub setup_timeout: Duration,
}

/// What to run in an anchor's container.
#[derive(Debug)]
pub struct ExecSpec {
    /// Absolute path of the program inside the container; no `PATH`
    /// search.
    pub program: PathBuf,
    /// Arguments after `argv[0]`, which is the program path.
    pub args: Vec<OsString>,
    /// The program's whole environment.
    pub env: Vec<(OsString, OsString)>,
    /// The working directory inside the container.
    pub cwd: InsidePath,
    /// How long the two stages may take from the clone to the exec. No
    /// default, zero is refused.
    pub setup_timeout: Duration,
}

/// The loopback addresses `lo` holds in the pod's network namespace, as an
/// anchor found them at its fill point: `/etc/hosts` lists `::1` only where
/// it exists (ADR-042, D7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Families {
    /// `127.0.0.1`.
    pub ipv4: bool,
    /// `::1`.
    pub ipv6: bool,
}

impl Families {
    fn from_bits(bits: u32) -> Option<Families> {
        if bits & !(FAMILY_IPV4 | FAMILY_IPV6) != 0 {
            return None;
        }
        Some(Families {
            ipv4: bits & FAMILY_IPV4 != 0,
            ipv6: bits & FAMILY_IPV6 != 0,
        })
    }
}

#[derive(Debug)]
enum State {
    /// Waiting at its fill point: the report pipe and the resume socket.
    Filling { report: OwnedFd, resume: OwnedFd },
    /// Pivoted, released and holding.
    Holding,
    /// Its setup failed or was abandoned; it was killed.
    Failed,
}

/// An anchor (ADR-042, D3), addressed by its pidfd. Dropping it kills and
/// reaps it; killing the pod's cgroup kills every anchor at once.
#[derive(Debug)]
pub struct Anchor {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    reaped: bool,
    ids: Ids,
    /// A descriptor of the pod's cgroup, for the joins.
    cgroup: OwnedFd,
    /// The staging directory without its leading `/`, beneath which the
    /// fill opens paths.
    staging: CString,
    /// The root, for the procfs mounts of an exec.
    root: Root,
    families: Families,
    setup_timeout: Duration,
    state: State,
}

/// Everything an anchor's child needs, prepared before the clone.
struct Prepared {
    ops: Vec<Op>,
    fill_at: usize,
    maps: CString,
    filters: Filters,
    bss: Vec<(usize, usize)>,
    page: usize,
}

fn prepare(spec: &AnchorSpec<'_>, loopback: bool) -> Result<Prepared> {
    if spec.setup_timeout.is_zero() {
        return Err(Error::ZeroSetupTimeout);
    }
    let (ruid, euid, rgid, egid) = caller();
    check_caller(ruid, euid, rgid, egid)?;
    let Some(proc) = spec.root.mounts.iter().find_map(|m| match m {
        Mount::Proc { target } => Some(target),
        _ => None,
    }) else {
        return Err(Error::InvalidAnchor(
            "the root has no procfs mount, which the release reads and every exec covers",
        ));
    };
    if !spec
        .root
        .mounts
        .iter()
        .any(|m| matches!(m, Mount::Dev { .. }))
    {
        return Err(Error::InvalidAnchor(
            "the root has no minimal /dev, whose null covers an exec's procfs keys",
        ));
    }
    let (ops, fill_at) = mount::plan_anchor(&spec.root, spec.fill_at, loopback)?;
    mount::refuse_hugetlbfs(&spec.root)?;
    let maps = spawn::c_string(
        format!("{}/self/maps", proc.as_str()).into_bytes(),
        "the procfs path",
    )?;
    let page = crate::cgroup::page_size() as usize;
    Ok(Prepared {
        ops,
        fill_at,
        maps,
        filters: spawn::prepare_filters()?,
        bss: bss_ranges(page)?,
        page,
    })
}

/// The `.bss` of every ELF object loaded in this process, page-aligned:
/// for each `PT_LOAD` whose memory size exceeds its file size, the pages
/// from the end of its file part, rounded up, to the end of its memory,
/// rounded up. The loader maps exactly these as anonymous memory; the
/// partial page before them is part of the file mapping. An anchor keeps
/// them through its release (ADR-042, D3), and only them: an unnamed
/// mapping next to a named one is no evidence of a `.bss`. More than
/// [`release::BSS_MAX`] is [`Error::InvalidAnchor`].
fn bss_ranges(page: usize) -> Result<Vec<(usize, usize)>> {
    unsafe extern "C" fn each(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> c_int {
        // SAFETY: data is the Vec passed to dl_iterate_phdr below, which
        // outlives the iteration and is used by nothing else meanwhile.
        let out = unsafe { &mut *data.cast::<Vec<(usize, usize, usize)>>() };
        // SAFETY: the loader passes a valid dl_phdr_info for the call.
        let info = unsafe { &*info };
        for i in 0..usize::from(info.dlpi_phnum) {
            // SAFETY: dlpi_phdr points at dlpi_phnum program headers, so the
            // i-th lies inside that array.
            let at = unsafe { info.dlpi_phdr.add(i) };
            // SAFETY: as above; the header is valid for reads.
            let ph = unsafe { &*at };
            if ph.p_type == libc::PT_LOAD && ph.p_memsz > ph.p_filesz {
                let at = info.dlpi_addr as usize + ph.p_vaddr as usize;
                out.push((at, ph.p_filesz as usize, ph.p_memsz as usize));
            }
        }
        0
    }
    let mut segments: Vec<(usize, usize, usize)> = Vec::new();
    // SAFETY: the callback only reads the headers the loader passes and
    // writes to the Vec behind data.
    unsafe {
        libc::dl_iterate_phdr(
            Some(each),
            (&mut segments as *mut Vec<(usize, usize, usize)>).cast(),
        )
    };
    let up = |a: usize| a.saturating_add(page - 1) & !(page - 1);
    let bss: Vec<(usize, usize)> = segments
        .into_iter()
        .map(|(at, file, mem)| (up(at.saturating_add(file)), up(at.saturating_add(mem))))
        .filter(|(start, end)| end > start)
        .collect();
    if bss.len() > release::BSS_MAX {
        return Err(Error::InvalidAnchor(
            "more ELF objects with a .bss than an anchor's release keeps",
        ));
    }
    Ok(bss)
}

/// The resume socket of an anchor's fill point, `(runner, anchor)`, both
/// ends close-on-exec. A stream pair rather than a pipe, so the runner's
/// write to an anchor that died is EPIPE through `MSG_NOSIGNAL`, never a
/// SIGPIPE in a process that did not ignore it.
fn resume_socket() -> Result<(OwnedFd, OwnedFd)> {
    listener_socket()
}

/// The descriptors in ascending order, without duplicates.
fn sorted(fds: &[RawFd]) -> Vec<RawFd> {
    let mut v = fds.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

/// `pidfd_open(pid, 0)`.
fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd> {
    // SAFETY: pidfd_open takes plain integers.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        return Err(Error::last("pidfd_open"));
    }
    // SAFETY: pidfd_open returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
}

/// Kills and reaps a child known by its pid only, the runner's own (the
/// second stage of a join whose pidfd could not be opened).
fn kill_pid(pid: libc::pid_t) {
    // SAFETY: kill takes plain integers; the pid is an unreaped child of
    // this process, so it names no other process.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut status = 0;
    // SAFETY: status is valid storage; the pid is this process's child.
    while unsafe { libc::waitpid(pid, &mut status, 0) } < 0 && errno() == libc::EINTR {}
}

fn kill_and_reap(launched: &Launched) {
    let _ = send_kill(&launched.pidfd);
    let _ = reap(&launched.pidfd);
}

/// The size of the stack an anchor is cloned on (ADR-042, D3): the clone
/// continues on a copy of the calling thread's stack and holds its TLS, so
/// an anchor is cloned from a thread of its own, on a stack mapped for it
/// alone ([`FreshStack`]). The thread's start, the clone and the child's
/// whole setup ran with every test passing on a 128 KiB stack and failed
/// on 64 KiB (measured, unoptimized, review run 2 of part 3); 1 MiB is
/// eight times what was enough.
const ANCHOR_STACK: usize = 1 << 20;

/// The stack an anchor is cloned on (ADR-042, D3): [`ANCHOR_STACK`] bytes
/// of a fresh anonymous mapping with a `PROT_NONE` guard page at each end.
/// The guard under it turns an overflow into a SIGSEGV that fails the
/// setup. The guard above it keeps its read-write part from ever merging
/// with a runner mapping right above it into one mapping, whose runner
/// part the release would then take for this stack (review of part 3, run
/// 3: 64 KiB of a neighbouring buffer were kept). The release also clips
/// its windows to [`FreshStack::bounds`], so a merge it did not foresee
/// keeps nothing either.
struct FreshStack {
    base: *mut libc::c_void,
    len: usize,
    page: usize,
}

impl FreshStack {
    fn new() -> Result<FreshStack> {
        let page = crate::cgroup::page_size() as usize;
        let len = ANCHOR_STACK + 2 * page;
        // SAFETY: an anonymous private mapping takes no file and no address.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(Error::last("mmap(anchor stack)"));
        }
        let stack = FreshStack { base, len, page };
        #[cfg(test)]
        FRESH.with(|f| f.set((base as usize, 0)));
        let top = base.cast::<u8>().wrapping_add(len - page).cast();
        for guard in [base, top] {
            // SAFETY: a page of the mapping made above.
            if unsafe { libc::mprotect(guard, page, libc::PROT_NONE) } < 0 {
                // The drop unmaps the whole mapping.
                return Err(Error::last("mprotect(anchor stack guard)"));
            }
        }
        Ok(stack)
    }

    /// The read-write part, `[start, end)`, between the guard pages.
    fn bounds(&self) -> (usize, usize) {
        let start = self.base as usize + self.page;
        (start, start + ANCHOR_STACK)
    }

    /// [`launch`] on a new thread on this stack (`pthread_attr_setstack`),
    /// joined before this returns; the mapping is unmapped after the join.
    /// The clone copies that thread only: its stack holds nothing but this
    /// crate's own frames, and the C library puts the thread's TLS and
    /// control block at the top of a stack it was given, so they are fresh
    /// too. Not `std::thread`: glibc caches the stacks of exited threads
    /// and hands them out again with their contents (review of part 3, run
    /// 2). A join that fails, which only a bug causes, still ends with the
    /// mapping unmapped: [`run_on`] returns only once the thread is gone
    /// (part 4, STOP 2 of part 3).
    fn launch(self, plan: &ChildPlan<'_>) -> Result<Launched> {
        run_on(plan, self.base, self.page)
    }
}

impl Drop for FreshStack {
    fn drop(&mut self) {
        // SAFETY: the mapping was made by new() with this length, and no
        // thread runs on it any more: `run_on` returns only after its
        // thread was joined or is gone; an anchor holds its own copy.
        unsafe { libc::munmap(self.base, self.len) };
        #[cfg(test)]
        FRESH.with(|f| f.set((f.get().0, self.base as usize)));
    }
}

#[cfg(test)]
std::thread_local! {
    /// The base of the last fresh stack this thread mapped and of the last
    /// one it unmapped, for `failed_join_unmaps_the_fresh_stack`.
    static FRESH: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// How often [`run_on`] looks whether a thread whose join failed is gone.
/// The thread runs only [`launch`], a clone and a few descriptor calls that
/// wait for nothing, so it ends within microseconds of its start.
const GONE_POLL: Duration = Duration::from_millis(1);

/// [`FreshStack::launch`]: the launch's result once the thread was joined.
///
/// If the join fails, the thread may still run, on the fresh stack and
/// writing into this frame, so this does not return before it is gone:
/// it recorded its kernel thread id first, and `tgkill(pid, tid, 0)`
/// answers ESRCH once the kernel has released it, which is after the
/// last write it makes to user memory (the clear of its tid word at its
/// exit included). For a positive tid of this process the only other
/// answer is success. Then the thread is detached, which frees the C
/// library's record of a joinable thread that has ended (glibc keeps it
/// in a list on the fresh stack itself until a join or a detach), and
/// what it launched is killed and reaped, so the error leaves neither a
/// mapping nor a process behind. A tid is reused only once the kernel's
/// cyclic allocation has gone round all of `pid_max`, so the wait cannot
/// mistake a new thread for this one in that time.
fn run_on(plan: &ChildPlan<'_>, base: *mut libc::c_void, page: usize) -> Result<Launched> {
    let mut result: Option<Result<Launched>> = None;
    let tid = AtomicI32::new(0);
    let done = AtomicBool::new(false);
    let mut job = || {
        // SAFETY: gettid has no preconditions and cannot fail.
        let me = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
        tid.store(me, Ordering::Release);
        result = Some(launch(plan));
        done.store(true, Ordering::Release);
    };
    let mut job: &mut dyn FnMut() = &mut job;
    extern "C" fn run(arg: *mut libc::c_void) -> *mut libc::c_void {
        // SAFETY: arg is the `&mut dyn FnMut()` below, which outlives the
        // thread: the caller joins it, or waits until it is gone, before
        // the closure goes out of scope.
        let job = unsafe { &mut *arg.cast::<&mut dyn FnMut()>() };
        job();
        std::ptr::null_mut()
    }
    // SAFETY: an all-zero pthread_attr_t is valid storage for init to fill.
    let mut attr: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
    // SAFETY: attr is valid storage.
    let rc = unsafe { libc::pthread_attr_init(&mut attr) };
    if rc != 0 {
        return Err(Error::Sys {
            call: "pthread_attr_init",
            errno: rc,
        });
    }
    // SAFETY: the stack is the mapping between its guard pages, ANCHOR_STACK
    // bytes, page-aligned and used by nothing else.
    let rc = unsafe {
        libc::pthread_attr_setstack(
            &mut attr,
            base.cast::<u8>().wrapping_add(page).cast(),
            ANCHOR_STACK,
        )
    };
    // SAFETY: pthread_t is an integer on glibc and a pointer on musl; all
    // zeroes is a valid placeholder for pthread_create to overwrite.
    let mut thread: libc::pthread_t = unsafe { std::mem::zeroed() };
    let rc = if rc == 0 {
        // SAFETY: attr is initialized; run takes the job pointer, which
        // stays valid until the join below.
        unsafe {
            libc::pthread_create(
                &mut thread,
                &attr,
                run,
                (&mut job as *mut &mut dyn FnMut()).cast(),
            )
        }
    } else {
        rc
    };
    // SAFETY: attr was initialized above and is destroyed once.
    unsafe { libc::pthread_attr_destroy(&mut attr) };
    if rc != 0 {
        return Err(Error::Sys {
            call: "pthread_create(anchor stack)",
            errno: rc,
        });
    }
    #[cfg(test)]
    let skip = matches!(plan.fault, Fault::JoinFails);
    #[cfg(not(test))]
    let skip = false;
    let rc = if skip {
        libc::EINVAL
    } else {
        // SAFETY: thread was created above and is joined once.
        unsafe { libc::pthread_join(thread, std::ptr::null_mut()) }
    };
    if rc != 0 {
        wait_gone(&tid);
        // SAFETY: the thread was created joinable above and has ended; a
        // detach frees what the C library keeps of it. If the failed join
        // already freed or detached it, the call fails and changes nothing.
        unsafe { libc::pthread_detach(thread) };
        if done.load(Ordering::Acquire)
            && let Some(Ok(launched)) = result.take()
        {
            kill_and_reap(&launched);
        }
        return Err(Error::Sys {
            call: "pthread_join(anchor stack)",
            errno: rc,
        });
    }
    let finished = done.load(Ordering::Acquire);
    match result {
        Some(r) if finished => r,
        _ => Err(Error::Sys {
            call: "pthread_create(anchor stack)",
            errno: libc::EIO,
        }),
    }
}

/// Waits until the thread that stored its kernel thread id in `tid` (or
/// will: it does so first) is gone, polling every [`GONE_POLL`].
fn wait_gone(tid: &AtomicI32) {
    // SAFETY: getpid has no preconditions and cannot fail.
    let pid = unsafe { libc::getpid() };
    loop {
        let t = tid.load(Ordering::Acquire);
        if t > 0 {
            // SAFETY: tgkill with signal 0 sends nothing; it only looks the
            // thread up in this process.
            let rc = unsafe { libc::syscall(libc::SYS_tgkill, pid, t, 0) };
            if rc < 0 && errno() == libc::ESRCH {
                return;
            }
        }
        std::thread::sleep(GONE_POLL);
    }
}

/// Whether `fd` became readable before `deadline`: a pidfd once its
/// process exited, a pipe once it holds data or its writers are gone.
fn ready_by(pidfd: &OwnedFd, deadline: Instant) -> Result<bool> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let mut pfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = left.as_micros().div_ceil(1000).min(c_int::MAX as u128) as c_int;
        // SAFETY: pfd is one valid pollfd for the call's duration.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(Error::last("poll"));
        }
        if rc > 0 {
            return Ok(true);
        }
        if left.is_zero() {
            return Ok(false);
        }
    }
}

/// Reads the records of one setup (ADR-042, D3) until a deadline.
struct Reports<'a> {
    fd: &'a OwnedFd,
    deadline: Instant,
    timeout: Duration,
}

impl Reports<'_> {
    /// The next record, or `None` at EOF. Never reads past a record, so a
    /// later one stays in the pipe.
    fn next(&mut self) -> Result<Option<[u8; report::LEN]>> {
        let mut buf = [0u8; report::LEN];
        let mut len = 0;
        loop {
            if !ready_by(self.fd, self.deadline)? {
                return Err(Error::SetupTimeout(self.timeout));
            }
            // SAFETY: buf[len..] is valid writable memory of the length passed.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf[len..].as_mut_ptr().cast(),
                    report::LEN - len,
                )
            };
            if n < 0 {
                if errno() == libc::EINTR {
                    continue;
                }
                return Err(Error::last("read"));
            }
            if n == 0 {
                return if len == 0 {
                    Ok(None)
                } else {
                    Err(Error::Protocol(ProtocolError::Length(len)))
                };
            }
            len += n as usize;
            if len == report::LEN {
                return Ok(Some(buf));
            }
        }
    }

    /// The next record, decoded; `None` at EOF.
    fn record(&mut self) -> Result<Option<Record>> {
        match self.next()? {
            None => Ok(None),
            Some(raw) => report::decode_record(&raw)
                .map(Some)
                .map_err(Error::Protocol),
        }
    }

    /// The value of the next record, which must be the progress record of
    /// `step`.
    fn progress(&mut self, step: Step) -> Result<u32> {
        match self.record()? {
            None => Err(Error::Protocol(ProtocolError::Ended(step))),
            Some(Record::Failed(e)) => Err(e),
            Some(Record::Progress { step: s, value }) if s == step => Ok(value),
            Some(Record::Progress { step: s, .. }) => {
                Err(Error::Protocol(ProtocolError::Unexpected(s)))
            }
        }
    }

    /// EOF, or the failure the next record names.
    fn end(&mut self) -> Result<()> {
        match self.record()? {
            None => Ok(()),
            Some(Record::Failed(e)) => Err(e),
            Some(Record::Progress { step, .. }) => {
                Err(Error::Protocol(ProtocolError::Unexpected(step)))
            }
        }
    }
}

/// A page mapped shared before a join's first clone: the inner clone's
/// `CLONE_PARENT_SETTID` writes the second stage's pid into it during the
/// clone, in the runner's PID namespace (ADR-042, D3). So the runner knows
/// its second child even when the first stage dies before its record, and
/// can check the record against it.
struct TidPage {
    ptr: *mut libc::c_void,
}

impl TidPage {
    fn new() -> Result<TidPage> {
        // SAFETY: an anonymous shared mapping takes no file and no address.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                crate::child::TID_PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(Error::last("mmap(pid page)"));
        }
        Ok(TidPage { ptr })
    }

    /// The page's address, for `clone_args.parent_tid`.
    fn addr(&self) -> usize {
        self.ptr as usize
    }

    /// The pid the kernel wrote, 0 before the inner clone.
    fn pid(&self) -> libc::pid_t {
        // SAFETY: the page is mapped, aligned and zero-filled at creation;
        // the kernel writes a pid_t at its start, which an atomic view
        // reads without a torn value.
        let slot = unsafe { &*(self.ptr as *const std::sync::atomic::AtomicI32) };
        slot.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for TidPage {
    fn drop(&mut self) {
        // SAFETY: the page was mapped by new() with this length and is
        // unmapped once; nothing refers to it after the drop.
        unsafe { libc::munmap(self.ptr, crate::child::TID_PAGE) };
    }
}

/// Reads the first stage's record of the second stage's pid, opens a
/// pidfd of the second stage and reaps the first once it has exited
/// (ADR-042, D3). On every error both stages are killed and reaped: the
/// second by the pid the kernel wrote into `tid`, if the inner clone ran.
fn second_stage(reports: &mut Reports<'_>, first: &Launched, tid: &TidPage) -> Result<Launched> {
    let record = reports.record();
    // The first stage exits right after its record, or has failed; once it
    // is gone, the page holds every pid the inner clone wrote.
    let pid = match record {
        Ok(Some(Record::Progress {
            step: Step::Forked,
            value,
        })) if value > 0 && value as libc::pid_t == tid.pid() => value as libc::pid_t,
        other => {
            let err = match other {
                Ok(None) => Error::Protocol(ProtocolError::Ended(Step::Forked)),
                Ok(Some(Record::Progress {
                    step: Step::Forked,
                    value,
                })) => Error::Protocol(ProtocolError::Value {
                    step: Step::Forked,
                    value,
                }),
                Ok(Some(Record::Progress { step, .. })) => {
                    Error::Protocol(ProtocolError::Unexpected(step))
                }
                Ok(Some(Record::Failed(e))) => e,
                Err(e) => e,
            };
            kill_and_reap(first);
            let pid = tid.pid();
            if pid > 0 {
                kill_pid(pid);
            }
            return Err(err);
        }
    };
    let pidfd = match pidfd_open(pid) {
        Ok(fd) => fd,
        Err(e) => {
            kill_pid(pid);
            kill_and_reap(first);
            return Err(e);
        }
    };
    let second = Launched { pid, pidfd };
    // The first stage opens the gate and exits right after its record; it
    // is not killed before, or the second stage would find the gate shut.
    match ready_by(&first.pidfd, reports.deadline) {
        Ok(true) => {
            let _ = reap(&first.pidfd);
            Ok(second)
        }
        Ok(false) => {
            kill_and_reap(first);
            kill_and_reap(&second);
            Err(Error::SetupTimeout(reports.timeout))
        }
        Err(e) => {
            kill_and_reap(first);
            kill_and_reap(&second);
            Err(e)
        }
    }
}

/// Whether two descriptors name the same file.
fn same_file(a: BorrowedFd<'_>, b: BorrowedFd<'_>) -> Result<bool> {
    let stat = |fd: BorrowedFd<'_>| -> Result<(u64, u64)> {
        // SAFETY: an all-zero stat is valid storage for fstat to fill.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: st is valid storage; fd is open.
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
            return Err(Error::last("fstat"));
        }
        Ok((st.st_dev as u64, st.st_ino as u64))
    };
    Ok(stat(a)? == stat(b)?)
}

impl Anchor {
    /// Creates a pod's first anchor in `spec.cgroup` (placed there at the
    /// clone) and in new user, mount, PID, network, IPC, UTS and cgroup
    /// namespaces with the single id mapping of `spec.ids`, as `spawn`
    /// creates a sandbox, but with `lo` up before the root (ADR-042, D3),
    /// cloned from a thread of its own on a freshly mapped stack, joined
    /// before this returns.
    /// Returns once the anchor waits at its fill point: the caller fills
    /// through [`Anchor::fill`] and resumes it, after which it finishes its
    /// mounts, pivots, sets its hostname, drops every privilege, loads the
    /// plain seccomp program, closes every descriptor but its pins,
    /// releases the runner's memory and holds.
    ///
    /// Errors before the clone: [`Error::ZeroSetupTimeout`],
    /// [`Error::RunningAsRoot`], [`Error::SetuidCaller`],
    /// [`Error::InvalidAnchor`], the root's errors of `spawn`,
    /// [`Error::CapLastCap`] and [`Error::NotifySizes`]. After it:
    /// [`Error::Setup`], [`Error::SetupTimeout`] or [`Error::Protocol`];
    /// the anchor was killed and reaped.
    pub fn create(spec: &AnchorSpec<'_>) -> Result<Anchor> {
        Anchor::create_inner(spec, Fault::None)
    }

    pub(crate) fn create_inner(spec: &AnchorSpec<'_>, fault: Fault) -> Result<Anchor> {
        let prepared = prepare(spec, true)?;
        let stack = FreshStack::new()?;
        let staging = staging_of(&spec.root)?;
        let (_, euid, _, egid) = caller();
        let uid_line = spec.ids.uid_map_line(euid).into_bytes();
        let gid_line = spec.ids.gid_map_line(egid).into_bytes();
        let cgroup = dup_cgroup(spec.cgroup)?;
        let (read, write) = report_pipe()?;
        let (resume, resume_child) = resume_socket()?;
        let pins: Vec<RawFd> = spec.pins.iter().map(AsRawFd::as_raw_fd).collect();
        let mut keep = pins.clone();
        keep.extend([write.as_raw_fd(), resume_child.as_raw_fd()]);
        let keep = sorted(&keep);
        let mut hold = pins;
        hold.push(write.as_raw_fd());
        let hold = sorted(&hold);
        let plan = ChildPlan {
            gid_line: &gid_line,
            uid_line: &uid_line,
            action: Action::Anchor(anchor_plan(
                &prepared,
                resume_child.as_raw_fd(),
                &keep,
                &hold,
                spec.cgroup.dir_fd(),
                stack.bounds(),
            )),
            report_fd: write.as_raw_fd(),
            fault,
        };
        let launched = stack.launch(&plan)?;
        drop(write);
        drop(resume_child);
        let anchor = Anchor {
            pid: launched.pid,
            pidfd: launched.pidfd,
            reaped: false,
            ids: spec.ids,
            cgroup,
            staging,
            root: spec.root.clone(),
            families: Families {
                ipv4: false,
                ipv6: false,
            },
            setup_timeout: spec.setup_timeout,
            state: State::Failed,
        };
        anchor.at_fill_point(read, resume, Instant::now() + spec.setup_timeout)
    }

    /// Reads the fill point's record by `deadline`; from here a drop
    /// kills and reaps.
    fn at_fill_point(
        mut self,
        read: OwnedFd,
        resume: OwnedFd,
        deadline: Instant,
    ) -> Result<Anchor> {
        let mut reports = Reports {
            fd: &read,
            deadline,
            timeout: self.setup_timeout,
        };
        let bits = reports.progress(Step::Fill)?;
        self.families = Families::from_bits(bits).ok_or(Error::Protocol(ProtocolError::Value {
            step: Step::Fill,
            value: bits,
        }))?;
        self.state = State::Filling {
            report: read,
            resume,
        };
        Ok(self)
    }

    /// Creates a later anchor of this anchor's pod: a first stage cloned
    /// into the pod's cgroup joins this anchor's user, network and cgroup
    /// namespaces, creates mount, PID, UTS and IPC namespaces of its own
    /// and clones the anchor as the runner's child (ADR-042, D3), which
    /// then runs as [`Anchor::create`]'s does from its root on. `spec.ids`
    /// must be this pod's, `spec.cgroup` its cgroup, and this anchor must
    /// hold.
    pub fn join(&self, spec: &AnchorSpec<'_>) -> Result<Anchor> {
        self.join_inner(spec, Fault::None)
    }

    pub(crate) fn join_inner(&self, spec: &AnchorSpec<'_>, fault: Fault) -> Result<Anchor> {
        self.holding()?;
        if spec.ids != self.ids {
            return Err(Error::InvalidAnchor(
                "a later anchor has other ids than its pod",
            ));
        }
        // SAFETY: dir_fd is the cgroup's open directory, which outlives this
        // borrow.
        let theirs = unsafe { BorrowedFd::borrow_raw(spec.cgroup.dir_fd()) };
        if !same_file(theirs, self.cgroup.as_fd())? {
            return Err(Error::InvalidAnchor(
                "a later anchor is placed in another cgroup than its pod's",
            ));
        }
        let prepared = prepare(spec, false)?;
        let stack = FreshStack::new()?;
        let tid = TidPage::new()?;
        let staging = staging_of(&spec.root)?;
        let cgroup = dup_raw(self.cgroup.as_raw_fd())?;
        let (read, write) = report_pipe()?;
        let (resume, resume_child) = resume_socket()?;
        let pins: Vec<RawFd> = spec.pins.iter().map(AsRawFd::as_raw_fd).collect();
        let mut keep = pins.clone();
        keep.extend([write.as_raw_fd(), resume_child.as_raw_fd()]);
        let mut first_keep = keep.clone();
        first_keep.push(self.pidfd.as_raw_fd());
        let keep = sorted(&keep);
        let first_keep = sorted(&first_keep);
        let mut hold = pins;
        hold.push(write.as_raw_fd());
        let hold = sorted(&hold);
        let plan = ChildPlan {
            gid_line: &[],
            uid_line: &[],
            action: Action::Join(JoinPlan {
                anchor: self.pidfd.as_raw_fd(),
                setns: ANCHOR_SETNS,
                unshare: ANCHOR_UNSHARE,
                keep: &first_keep,
                cgroup: self.cgroup.as_raw_fd(),
                tid: tid.addr(),
                then: Joined::Anchor(anchor_plan(
                    &prepared,
                    resume_child.as_raw_fd(),
                    &keep,
                    &hold,
                    self.cgroup.as_raw_fd(),
                    stack.bounds(),
                )),
            }),
            report_fd: write.as_raw_fd(),
            fault,
        };
        let first = stack.launch(&plan)?;
        drop(write);
        drop(resume_child);
        let mut reports = Reports {
            fd: &read,
            deadline: Instant::now() + spec.setup_timeout,
            timeout: spec.setup_timeout,
        };
        let second = second_stage(&mut reports, &first, &tid)?;
        // The deadline runs on from the clone: one setup bound up to the
        // fill point, as for the first anchor.
        let deadline = reports.deadline;
        let anchor = Anchor {
            pid: second.pid,
            pidfd: second.pidfd,
            reaped: false,
            ids: self.ids,
            cgroup,
            staging,
            root: spec.root.clone(),
            families: Families {
                ipv4: false,
                ipv6: false,
            },
            setup_timeout: spec.setup_timeout,
            state: State::Failed,
        };
        anchor.at_fill_point(read, resume, deadline)
    }

    /// The anchor's fill point, while it waits there.
    pub fn fill(&mut self) -> Result<Fill<'_>> {
        match self.state {
            State::Filling { .. } => Ok(Fill {
                anchor: self,
                resumed: false,
            }),
            State::Holding => Err(Error::InvalidAnchor("the anchor was resumed already")),
            State::Failed => Err(Error::InvalidAnchor("the anchor failed")),
        }
    }

    /// Runs a program in this anchor's container (ADR-042, D3): a first
    /// stage cloned into the pod's cgroup joins the anchor's user,
    /// network, cgroup, mount, UTS and IPC namespaces, creates a PID
    /// namespace and a copy of the mount namespace and clones the second
    /// stage as the runner's child. That one mounts a procfs of its PID
    /// namespace over each of the container's (so it never sees the
    /// anchor) and goes on as `spawn`'s child does from `setsid` to
    /// `execve`, under the seccomp policy whose denials a supervisor of
    /// this process records ([`Child::denials`], ADR-043). The program is
    /// PID 1 of its namespace and takes its orphans; it ends with them.
    ///
    /// Errors as `spawn`'s, and [`Error::InvalidAnchor`] unless the anchor
    /// holds.
    pub fn exec(&self, spec: &ExecSpec, stdio: Stdio) -> Result<Child> {
        self.exec_inner(spec, stdio, Fault::None, Seam::None)
    }

    /// A service (ADR-042, D2): [`Anchor::exec`] with `/dev/null` as its
    /// three standard descriptors, since its output is discarded. The
    /// caller keeps the [`Child`] and watches its pidfd; dropping it kills
    /// the service.
    pub fn start(&self, spec: &ExecSpec) -> Result<Child> {
        let null = || -> Result<OwnedFd> {
            std::fs::File::options()
                .read(true)
                .write(true)
                .open("/dev/null")
                .map(OwnedFd::from)
                .map_err(|e| Error::Sys {
                    call: "open(/dev/null)",
                    errno: e.raw_os_error().unwrap_or(libc::EIO),
                })
        };
        let stdio = Stdio {
            stdin: null()?,
            stdout: null()?,
            stderr: null()?,
        };
        self.exec(spec, stdio)
    }

    pub(crate) fn exec_inner(
        &self,
        spec: &ExecSpec,
        stdio: Stdio,
        fault: Fault,
        seam: Seam,
    ) -> Result<Child> {
        let started = Instant::now();
        self.holding()?;
        if spec.setup_timeout.is_zero() {
            return Err(Error::ZeroSetupTimeout);
        }
        let command = spawn::prepare_command(&spec.program, &spec.args, &spec.env)?;
        let ops = mount::plan_joined(&self.root, &spec.cwd)?;
        let filters = spawn::prepare_filters()?;
        let tid = TidPage::new()?;
        let sources = [
            dup_high(&stdio.stdin)?,
            dup_high(&stdio.stdout)?,
            dup_high(&stdio.stderr)?,
        ];
        drop(stdio);
        let (read, write) = report_pipe()?;
        let (sock, sock_child) = listener_socket()?;
        let raw_stdio = [
            sources[0].as_raw_fd(),
            sources[1].as_raw_fd(),
            sources[2].as_raw_fd(),
        ];
        let keep = sorted(&[
            write.as_raw_fd(),
            sock_child.as_raw_fd(),
            self.pidfd.as_raw_fd(),
            raw_stdio[0],
            raw_stdio[1],
            raw_stdio[2],
        ]);
        let plan = ChildPlan {
            gid_line: &[],
            uid_line: &[],
            action: Action::Join(JoinPlan {
                anchor: self.pidfd.as_raw_fd(),
                setns: EXEC_SETNS,
                unshare: EXEC_UNSHARE,
                keep: &keep,
                cgroup: self.cgroup.as_raw_fd(),
                tid: tid.addr(),
                then: Joined::Exec(ExecPlan {
                    program: &command.program,
                    argv: &command.argv,
                    envp: &command.envp,
                    stdio: raw_stdio,
                    ops: &ops,
                    cgroup: self.cgroup.as_raw_fd(),
                    privileges: PrivilegeDrop {
                        cap_last_cap: filters.cap_last_cap,
                        filter: filters.filter.instructions(),
                        listener: true,
                    },
                    listener_sock: sock_child.as_raw_fd(),
                }),
            }),
            report_fd: write.as_raw_fd(),
            fault,
        };
        let first = launch(&plan)?;
        // The stages hold the only other write ends now.
        drop(write);
        drop(sock_child);
        drop(sources);
        let mut reports = Reports {
            fd: &read,
            deadline: Instant::now() + spec.setup_timeout,
            timeout: spec.setup_timeout,
        };
        let second = second_stage(&mut reports, &first, &tid)?;
        if let Err(e) = reports.end() {
            kill_and_reap(&second);
            return Err(e);
        }
        spawn::supervise(second, sock, filters, started, seam)
    }

    fn holding(&self) -> Result<()> {
        match self.state {
            State::Holding => Ok(()),
            State::Filling { .. } => Err(Error::InvalidAnchor(
                "the anchor waits at its fill point; resume it first",
            )),
            State::Failed => Err(Error::InvalidAnchor("the anchor failed")),
        }
    }

    /// Kills and reaps the anchor, which is then failed.
    fn abandon(&mut self) {
        self.state = State::Failed;
        if !self.reaped {
            let _ = send_kill(&self.pidfd);
            let _ = reap(&self.pidfd);
            self.reaped = true;
        }
    }

    /// The anchor's pid in the runner's PID namespace.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The pidfd; it becomes readable when the anchor dies, which fails
    /// its pod (ADR-042, D8).
    pub fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// The loopback families of the pod's network namespace.
    pub fn families(&self) -> Families {
        self.families
    }
}

impl Drop for Anchor {
    fn drop(&mut self) {
        self.abandon();
    }
}

fn anchor_plan<'a>(
    prepared: &'a Prepared,
    resume: RawFd,
    keep: &'a [RawFd],
    hold: &'a [RawFd],
    cgroup: RawFd,
    stack: (usize, usize),
) -> AnchorPlan<'a> {
    AnchorPlan {
        ops: &prepared.ops,
        fill_at: prepared.fill_at,
        resume,
        keep,
        hold,
        privileges: PrivilegeDrop {
            cap_last_cap: prepared.filters.cap_last_cap,
            filter: prepared.filters.plain.instructions(),
            listener: false,
        },
        maps: &prepared.maps,
        bss: &prepared.bss,
        page: prepared.page,
        stack,
        cgroup,
    }
}

fn dup_raw(fd: RawFd) -> Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC takes a descriptor and a minimum number.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if new < 0 {
        return Err(Error::last("fcntl(F_DUPFD_CLOEXEC)"));
    }
    // SAFETY: fcntl returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

fn dup_cgroup(cgroup: &Cgroup) -> Result<OwnedFd> {
    dup_raw(cgroup.dir_fd())
}

fn staging_of(root: &Root) -> Result<CString> {
    let bytes = root.staging.as_os_str().as_bytes();
    let rel = bytes.strip_prefix(b"/").unwrap_or(bytes);
    spawn::c_string(rel.to_vec(), "the staging path")
}

/// An anchor at its fill point (ADR-042, D3). The runner copies the
/// workspace in and creates the mount points of the mounts after the fill
/// point through it, then resumes the anchor. Dropping it without
/// [`Fill::resume`] kills the anchor.
#[derive(Debug)]
pub struct Fill<'a> {
    anchor: &'a mut Anchor,
    resumed: bool,
}

impl Fill<'_> {
    /// Opens a directory of the container beneath its new root, through
    /// `/proc/<pid>/root` of the anchor, which has not pivoted yet: every
    /// component resolved beneath the root and without following any
    /// symlink, so a hostile image cannot point the runner at a host path.
    /// The pidfd is checked after `/proc/<pid>/root` is opened, so the
    /// descriptor is the anchor's root and no recycled pid's.
    pub fn open(&self, path: &InsidePath) -> Result<OwnedFd> {
        let proc_root = spawn::c_string(
            format!("/proc/{}/root", self.anchor.pid).into_bytes(),
            "the anchor's root path",
        )?;
        // SAFETY: proc_root is NUL-terminated; the magic link is followed
        // on purpose, into the anchor's mount namespace.
        let root = unsafe {
            libc::open(
                proc_root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root < 0 {
            return Err(Error::last("open(/proc/<pid>/root)"));
        }
        // SAFETY: open returned a new descriptor that nothing else owns.
        let root = unsafe { OwnedFd::from_raw_fd(root) };
        // SAFETY: a signal of 0 only checks that the process exists; no
        // siginfo is passed.
        let alive = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.anchor.pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if alive < 0 {
            return Err(Error::last("pidfd_send_signal(0)"));
        }
        let mut rel = self.anchor.staging.as_bytes().to_vec();
        rel.push(b'/');
        rel.extend_from_slice(path.relative().as_bytes());
        let rel = spawn::c_string(rel, "the fill path")?;
        let how = ffi::OpenHow {
            flags: (libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: libc::RESOLVE_IN_ROOT
                | libc::RESOLVE_NO_SYMLINKS
                | libc::RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: rel is NUL-terminated and how is a valid open_how of the
        // size passed, both for the call's duration.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                rel.as_ptr(),
                &how as *const ffi::OpenHow,
                std::mem::size_of::<ffi::OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(Error::last("openat2(fill path)"));
        }
        // SAFETY: openat2 returned a new descriptor that nothing else owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
    }

    /// The loopback families the anchor found at its fill point.
    pub fn loopback(&self) -> Families {
        self.anchor.families
    }

    /// Resumes the anchor and waits, within its setup timeout, until it
    /// holds: its last mounts, `pivot_root`, the privilege drop, the
    /// filter, the closed descriptors and the memory release (ADR-042,
    /// D3). On any error the anchor was killed and reaped.
    pub fn resume(mut self) -> Result<()> {
        self.resumed = true;
        let result = self.resume_inner();
        if result.is_err() {
            self.anchor.abandon();
        }
        result
    }

    fn resume_inner(&mut self) -> Result<()> {
        let State::Filling { report, resume } =
            std::mem::replace(&mut self.anchor.state, State::Failed)
        else {
            return Err(Error::InvalidAnchor("the anchor is not at its fill point"));
        };
        let one = [1u8; 1];
        // SAFETY: one is valid for its length; MSG_NOSIGNAL turns a dead
        // peer into EPIPE instead of SIGPIPE.
        let n = unsafe {
            libc::send(
                resume.as_raw_fd(),
                one.as_ptr().cast(),
                1,
                libc::MSG_NOSIGNAL,
            )
        };
        if n != 1 {
            return Err(Error::last("send(resume)"));
        }
        drop(resume);
        let mut reports = Reports {
            fd: &report,
            deadline: Instant::now() + self.anchor.setup_timeout,
            timeout: self.anchor.setup_timeout,
        };
        let value = reports.progress(Step::Release)?;
        if value != 0 {
            return Err(Error::Protocol(ProtocolError::Value {
                step: Step::Release,
                value,
            }));
        }
        reports.end()?;
        self.anchor.state = State::Holding;
        Ok(())
    }
}

impl Drop for Fill<'_> {
    fn drop(&mut self) {
        if !self.resumed {
            self.anchor.abandon();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_guard::{UnitRoot, cgroup_parent, children, host_lock, sandbox_cgroup};

    fn null() -> OwnedFd {
        std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null")
            .into()
    }

    fn stdio() -> Stdio {
        Stdio {
            stdin: null(),
            stdout: null(),
            stderr: null(),
        }
    }

    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("list /proc/self/fd")
            .count()
    }

    /// An anchor spec on the unit root, every mount before the fill point.
    fn spec<'a>(unit: &UnitRoot, cgroup: &'a Cgroup, timeout: Duration) -> AnchorSpec<'a> {
        AnchorSpec {
            ids: Ids::new(0, 0).expect("ids"),
            root: unit.root.clone(),
            fill_at: unit.root.mounts.len(),
            pins: Vec::new(),
            cgroup,
            setup_timeout: timeout,
        }
    }

    fn exec_spec(program: &str, timeout: Duration) -> ExecSpec {
        ExecSpec {
            program: PathBuf::from(program),
            args: Vec::new(),
            env: Vec::new(),
            cwd: InsidePath::root(),
            setup_timeout: timeout,
        }
    }

    /// A first anchor, filled with nothing and resumed.
    fn holding(spec: &AnchorSpec<'_>) -> Anchor {
        let mut anchor = Anchor::create(spec).expect("create the anchor");
        anchor
            .fill()
            .expect("at the fill point")
            .resume()
            .expect("resume");
        anchor
    }

    fn expect_setup(result: Result<()>, step: Step) {
        match result {
            Err(Error::Setup {
                step: got,
                errno,
                index,
            }) => {
                assert_eq!(got, step);
                assert_eq!(errno, libc::EIO, "{step:?}");
                if step == Step::Forked {
                    // The failure carries the second stage's pid.
                    assert!(index > 0, "{step:?}: {index}");
                } else {
                    assert_eq!(index, 0, "{step:?}");
                }
            }
            other => panic!("{step:?}: {other:?}"),
        }
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn every_anchor_step_failure_is_reported() {
        let _host = host_lock();
        let unit = UnitRoot::new();
        cgroup_parent();
        for step in Step::ANCHOR_SEQUENCE {
            let before = open_fds();
            let cg = sandbox_cgroup("anchor-step");
            let s = spec(&unit, &cg, Duration::from_secs(10));
            let result = match Anchor::create_inner(&s, Fault::Fail(step)) {
                Err(e) => Err(e),
                Ok(mut anchor) => anchor.fill().expect("at the fill point").resume(),
            };
            expect_setup(result, step);
            assert_eq!(children(), Vec::<i32>::new(), "{step:?}: reaped");
            drop(s);
            cg.destroy().expect("destroy the cgroup");
            assert_eq!(open_fds(), before, "{step:?}: no descriptor leaked");
        }
    }

    /// Part 4 (STOP 2 of part 3): when `pthread_join` fails, the fresh
    /// stack is still unmapped, once the thread is gone, and what the
    /// thread launched is killed and reaped; for a first anchor and for a
    /// later one. The seam skips the join and reports EINVAL, so the
    /// thread may still run when the failure path starts.
    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn failed_join_unmaps_the_fresh_stack() {
        let _host = host_lock();
        let unit = UnitRoot::new();
        cgroup_parent();
        let before = open_fds();
        let cg = sandbox_cgroup("join-fails");
        let s = spec(&unit, &cg, Duration::from_secs(10));
        let pod = holding(&s);
        for later in [false, true] {
            FRESH.with(|f| f.set((0, 0)));
            let result = if later {
                pod.join_inner(&s, Fault::JoinFails).map(|_| ())
            } else {
                Anchor::create_inner(&s, Fault::JoinFails).map(|_| ())
            };
            match result {
                Err(Error::Sys {
                    call: "pthread_join(anchor stack)",
                    errno: libc::EINVAL,
                }) => {}
                other => panic!("later {later}: {other:?}"),
            }
            let (mapped, unmapped) = FRESH.with(std::cell::Cell::get);
            assert_ne!(mapped, 0, "later {later}: a fresh stack was mapped");
            assert_eq!(unmapped, mapped, "later {later}: and unmapped");
            assert_eq!(children(), vec![pod.pid()], "later {later}: reaped");
        }
        drop(pod);
        drop(s);
        cg.destroy().expect("destroy the cgroup");
        assert_eq!(children(), Vec::<i32>::new());
        assert_eq!(open_fds(), before, "no descriptor leaked");
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn every_join_step_failure_is_reported() {
        let _host = host_lock();
        let unit = UnitRoot::new();
        let cg = sandbox_cgroup("join-step");
        let pod = holding(&spec(&unit, &cg, Duration::from_secs(10)));
        for step in Step::JOIN_SEQUENCE {
            let before = open_fds();
            let s = spec(&unit, &cg, Duration::from_secs(10));
            let result = match pod.join_inner(&s, Fault::Fail(step)) {
                Err(e) => Err(e),
                Ok(mut anchor) => anchor.fill().expect("at the fill point").resume(),
            };
            expect_setup(result, step);
            assert_eq!(children(), vec![pod.pid()], "{step:?}: both stages reaped");
            drop(s);
            assert_eq!(open_fds(), before, "{step:?}: no descriptor leaked");
        }
        drop(pod);
        cg.destroy().expect("destroy the cgroup");
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn every_exec_step_failure_is_reported() {
        let _host = host_lock();
        let unit = UnitRoot::new();
        let cg = sandbox_cgroup("exec-step");
        let pod = holding(&spec(&unit, &cg, Duration::from_secs(10)));
        for step in Step::EXEC_SEQUENCE {
            let before = open_fds();
            let e = exec_spec("/bin/true", Duration::from_secs(10));
            let result = pod
                .exec_inner(&e, stdio(), Fault::Fail(step), Seam::None)
                .map(|_| ());
            expect_setup(result, step);
            assert_eq!(children(), vec![pod.pid()], "{step:?}: both stages reaped");
            assert_eq!(open_fds(), before, "{step:?}: no descriptor leaked");
        }
        // And a run that fails nothing.
        let mut child = pod
            .exec(&exec_spec("/bin/true", Duration::from_secs(10)), stdio())
            .expect("exec /bin/true");
        assert_eq!(child.wait().expect("wait"), spawn::ExitStatus::Exited(0));
        assert_eq!(child.denials().failed(), None);
        drop(pod);
        cg.destroy().expect("destroy the cgroup");
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn hung_stages_time_out() {
        let _host = host_lock();
        let unit = UnitRoot::new();
        let cg = sandbox_cgroup("anchor-hang");
        let bound = Duration::from_millis(300);
        // Before the fill point, and after the resume.
        for step in [Step::Fill, Step::Release] {
            let s = spec(&unit, &cg, bound);
            let start = Instant::now();
            let result = match Anchor::create_inner(&s, Fault::Hang(step)) {
                Err(e) => Err(e),
                Ok(mut anchor) => anchor.fill().expect("at the fill point").resume(),
            };
            assert!(
                matches!(result, Err(Error::SetupTimeout(t)) if t == bound),
                "{step:?}: {result:?}"
            );
            assert!(start.elapsed() < Duration::from_secs(5), "{step:?}");
            assert_eq!(children(), Vec::<i32>::new(), "{step:?}: reaped");
        }
        // An exec whose second stage hangs: both stages are reaped.
        let pod = holding(&spec(&unit, &cg, Duration::from_secs(10)));
        let result = pod
            .exec_inner(
                &exec_spec("/bin/true", bound),
                stdio(),
                Fault::Hang(Step::Setsid),
                Seam::None,
            )
            .map(|_| ());
        assert!(
            matches!(result, Err(Error::SetupTimeout(t)) if t == bound),
            "{result:?}"
        );
        assert_eq!(children(), vec![pod.pid()], "both stages reaped");
        drop(pod);
        cg.destroy().expect("destroy the cgroup");
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn lost_first_stage_leaves_no_second() {
        // The first stage hangs after its inner clone, before it records
        // the second stage's pid, and is killed at the setup timeout: the
        // runner still learns the pid (CLONE_PARENT_SETTID) and reaps the
        // second stage, its child, which the shut gate ends.
        let _host = host_lock();
        let unit = UnitRoot::new();
        let cg = sandbox_cgroup("lost-first");
        let pod = holding(&spec(&unit, &cg, Duration::from_secs(10)));
        let bound = Duration::from_millis(300);
        let exec = pod
            .exec_inner(
                &exec_spec("/bin/true", bound),
                stdio(),
                Fault::Hang(Step::Forked),
                Seam::None,
            )
            .map(|_| ());
        assert!(
            matches!(exec, Err(Error::SetupTimeout(t)) if t == bound),
            "{exec:?}"
        );
        assert_eq!(children(), vec![pod.pid()], "exec: both stages reaped");
        let join = pod
            .join_inner(&spec(&unit, &cg, bound), Fault::Hang(Step::Forked))
            .map(|_| ());
        assert!(
            matches!(join, Err(Error::SetupTimeout(t)) if t == bound),
            "{join:?}"
        );
        assert_eq!(children(), vec![pod.pid()], "join: both stages reaped");
        drop(pod);
        cg.destroy().expect("destroy the cgroup");
    }

    /// Every address in `pid`'s readable memory where the stale marker of
    /// `Fault::Stale` starts.
    fn stale_hits(pid: i32) -> Vec<usize> {
        use std::io::{Read, Seek, SeekFrom};
        let mut want = crate::child::STALE_MARKER;
        for b in &mut want {
            *b ^= 0xa5;
        }
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("maps");
        let mut mem = std::fs::File::open(format!("/proc/{pid}/mem")).expect("mem");
        let mut hits = Vec::new();
        for line in maps.lines() {
            let Some((s, e)) = line
                .split_whitespace()
                .next()
                .and_then(|r| r.split_once('-'))
            else {
                continue;
            };
            let (s, e) = (
                usize::from_str_radix(s, 16).expect("hex"),
                usize::from_str_radix(e, 16).expect("hex"),
            );
            if s >= 0xffff_ffff_ff60_0000 {
                continue;
            }
            let mut data = vec![0u8; e - s];
            for (k, page) in data.chunks_mut(4096).enumerate() {
                let read = mem
                    .seek(SeekFrom::Start((s + k * 4096) as u64))
                    .and_then(|_| mem.read_exact(page));
                if read.is_err() {
                    page.fill(0);
                }
            }
            for (i, w) in data.windows(want.len()).enumerate() {
                if w == want {
                    hits.push(s + i);
                }
            }
        }
        hits
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn release_zeroes_stale_frames_under_it() {
        // Review run 2: the stack the release keeps under its frame held
        // what deeper calls had left there. The anchor leaves 40 KiB of
        // markers in a frame it returned from right before the release, under
        // the release's own frame and the margin it keeps.
        let _host = host_lock();
        let unit = UnitRoot::new();
        let cg = sandbox_cgroup("stale");
        let mut anchor = Anchor::create_inner(
            &spec(&unit, &cg, Duration::from_secs(10)),
            Fault::Stale(Step::Release),
        )
        .expect("create");
        anchor
            .fill()
            .expect("at the fill point")
            .resume()
            .expect("resume");
        let hits = stale_hits(anchor.pid());
        drop(anchor);
        cg.destroy().expect("destroy the cgroup");
        assert_eq!(hits.len(), 0, "stale markers kept under the release frame");
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn concurrent_setup_pid_page_is_released() {
        // Review run 1: while an exec waits for its second stage, its pid
        // page is mapped shared in the runner. A pod created meanwhile
        // must not keep it, nor the mapping above it.
        let _host = host_lock();
        let unit = UnitRoot::new();
        let cg = sandbox_cgroup("tid-page");
        let cg_other = sandbox_cgroup("tid-page-other");
        let pod = holding(&spec(&unit, &cg, Duration::from_secs(10)));
        let (maps, exec) = std::thread::scope(|s| {
            let exec = s.spawn(|| {
                pod.exec_inner(
                    &exec_spec("/bin/true", Duration::from_secs(3)),
                    stdio(),
                    Fault::Hang(Step::Setsid),
                    Seam::None,
                )
                .map(|_| ())
            });
            let deadline = Instant::now() + Duration::from_secs(2);
            while children().len() < 2 {
                assert!(Instant::now() < deadline, "no second stage");
                std::thread::sleep(Duration::from_millis(5));
            }
            let other = holding(&spec(&unit, &cg_other, Duration::from_secs(10)));
            let maps = std::fs::read_to_string(format!("/proc/{}/maps", other.pid()))
                .expect("the other anchor's maps");
            drop(other);
            (maps, exec.join().expect("the exec thread"))
        });
        assert!(matches!(exec, Err(Error::SetupTimeout(_))), "{exec:?}");
        drop(pod);
        cg.destroy().expect("destroy the cgroup");
        cg_other.destroy().expect("destroy the other cgroup");
        assert!(
            !maps
                .lines()
                .any(|l| l.contains("/dev/zero") || l.contains(" rw-s ")),
            "a concurrent setup's shared pid page is kept:\n{maps}"
        );
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn join_stages_hold_no_runner_descriptor() {
        // A pipe of the runner's, standing for another setup's report
        // pipe, open while an exec's two stages are cloned. The second
        // stage hangs before its exec; the pipe must still see its last
        // writer go when the runner closes it.
        let _host = host_lock();
        let unit = UnitRoot::new();
        let cg = sandbox_cgroup("join-fds");
        let pod = holding(&spec(&unit, &cg, Duration::from_secs(10)));
        let mut fds = [0 as c_int; 2];
        // SAFETY: fds is a valid array of two ints for pipe2 to fill.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: pipe2 succeeded, so fds[0] is open and owned once.
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: as above, for the write end.
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let bound = Duration::from_secs(3);
        let result = std::thread::scope(|s| {
            let exec = s.spawn(|| {
                pod.exec_inner(
                    &exec_spec("/bin/true", bound),
                    stdio(),
                    Fault::Hang(Step::Setsid),
                    Seam::None,
                )
                .map(|_| ())
            });
            // Until the second stage hangs: the first exits at once.
            let deadline = Instant::now() + Duration::from_secs(2);
            while children().len() < 2 {
                assert!(Instant::now() < deadline, "no second stage");
                std::thread::sleep(Duration::from_millis(5));
            }
            drop(write);
            let mut pfd = libc::pollfd {
                fd: read.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd is one valid pollfd for the call's duration.
            let rc = unsafe { libc::poll(&mut pfd, 1, 1000) };
            let hung_up = rc > 0 && pfd.revents & libc::POLLHUP != 0;
            (hung_up, exec.join().expect("the exec thread"))
        });
        assert!(result.0, "a join's stage holds a copy of the runner's pipe");
        assert!(
            matches!(result.1, Err(Error::SetupTimeout(t)) if t == bound),
            "{:?}",
            result.1
        );
        drop(pod);
        cg.destroy().expect("destroy the cgroup");
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces"]
    fn allocation_guard_covers_anchors_and_second_stages() {
        let _host = host_lock();
        let unit = UnitRoot::new();
        let cg = sandbox_cgroup("anchor-alloc");
        // The anchor allocates before its fill record: the guard ends it,
        // and the report ends without the record.
        let s = spec(&unit, &cg, Duration::from_secs(10));
        let result = Anchor::create_inner(&s, Fault::Allocate(Step::Fill)).map(|_| ());
        assert!(
            matches!(
                result,
                Err(Error::Protocol(ProtocolError::Ended(Step::Fill)))
            ),
            "{result:?}"
        );
        // A joined exec's second stage allocates at its last step: EOF
        // without a report, so the exit code shows it.
        let pod = holding(&spec(&unit, &cg, Duration::from_secs(10)));
        let mut child = pod
            .exec_inner(
                &exec_spec("/bin/true", Duration::from_secs(10)),
                stdio(),
                Fault::Allocate(Step::Exec),
                Seam::None,
            )
            .expect("EOF without a report");
        assert_eq!(
            child.wait().expect("wait"),
            spawn::ExitStatus::Exited(crate::test_guard::EXIT_ALLOCATED)
        );
        drop(pod);
        cg.destroy().expect("destroy the cgroup");
    }

    #[test]
    fn anchor_requests_checked_before_the_clone() {
        let cg = Cgroup::unplaced();
        let unit_root = || Root {
            layers: vec![PathBuf::from("/nonexistent/layer")],
            staging: PathBuf::from("/nonexistent/staging"),
            mounts: vec![
                Mount::Proc {
                    target: InsidePath::new("/proc").expect("path"),
                },
                Mount::Dev {
                    target: InsidePath::new("/dev").expect("path"),
                    shm_size_bytes: 1 << 20,
                },
            ],
            hostname: mount::Hostname::new("unit").expect("hostname"),
            cwd: InsidePath::root(),
        };
        let spec_with = |root: Root, fill_at, timeout| AnchorSpec {
            ids: Ids::new(0, 0).expect("ids"),
            root,
            fill_at,
            pins: Vec::new(),
            cgroup: &cg,
            setup_timeout: timeout,
        };
        let second = Duration::from_secs(1);
        assert!(matches!(
            Anchor::create(&spec_with(unit_root(), 0, Duration::ZERO)),
            Err(Error::ZeroSetupTimeout)
        ));
        assert!(matches!(
            Anchor::create(&spec_with(unit_root(), 3, second)),
            Err(Error::InvalidAnchor(_))
        ));
        for keep in [0, 1] {
            let mut root = unit_root();
            root.mounts.remove(keep);
            assert!(
                matches!(
                    Anchor::create(&spec_with(root, 0, second)),
                    Err(Error::InvalidAnchor(_))
                ),
                "without mount {keep}"
            );
        }
        assert_eq!(
            Families::from_bits(0),
            Some(Families {
                ipv4: false,
                ipv6: false
            })
        );
        assert_eq!(
            Families::from_bits(3),
            Some(Families {
                ipv4: true,
                ipv6: true
            })
        );
        assert_eq!(
            Families::from_bits(2),
            Some(Families {
                ipv4: false,
                ipv6: true
            })
        );
        assert_eq!(Families::from_bits(4), None);
        assert_eq!(sorted(&[5, 3, 5, 4]), [3, 4, 5]);
    }
}
