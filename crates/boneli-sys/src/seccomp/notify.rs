//! The seccomp supervisor (ADR-043, D3 to D5): the one reply it can send,
//! the buffers it receives into and replies from, how it derives the
//! answer to a notified call from the plain program, the listener with its
//! three requests, and the thread that answers and records every notified
//! call of one sandbox.
//!
//! This is the only file of the crate that may name the kernel's reply
//! struct and the ioctl that sends it; the self-scan
//! (`tests/boneli_sys_tests/notify_scan.rs`) holds every other file to
//! that, and bans the names of the flag that would let a call run and of
//! the descriptor-injection ioctl everywhere.

use std::os::fd::{AsRawFd, OwnedFd};

use super::bpf::{self, Data};
use super::policy::{Program, Row, errno_action};
use super::record::{Call, Key, Record, STATUS_MAX, Status, SupervisorFailure, parse_status};
use super::table::Arch;
use crate::error::Error;

/// The highest errno a reply may carry (ADR-043, D5): one below
/// `ERESTARTSYS` (512, `include/linux/errno.h`). From 512 up the kernel
/// keeps its own codes, "never seen by user programs": a pending signal
/// turns `ERESTARTSYS`, `ERESTARTNOINTR` or `ERESTARTNOHAND` into a
/// restart of the call, and `ERESTART_RESTARTBLOCK` runs the task's
/// restart block, another syscall. Every errno user space knows lies below:
/// the highest in the uapi headers of both architectures is `EHWPOISON`
/// (133, `include/uapi/asm-generic/errno.h`). The kernel's own bound,
/// `MAX_ERRNO` (4095, `include/linux/err.h`), is where a return value
/// stops being an error at all; a reply with `error` 0 makes the call
/// return `val`, a success.
pub const MAX_REPLY_ERRNO: i32 = 511;

const _: () = assert!(MAX_REPLY_ERRNO < 512);
const _: () = assert!(libc::EHWPOISON <= MAX_REPLY_ERRNO);

const _: () = assert!(core::mem::size_of::<libc::seccomp_notif>() == NOTIF_SIZE);
const _: () = assert!(core::mem::size_of::<libc::seccomp_notif_resp>() == RESP_SIZE);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_notif, id) == 0);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_notif, pid) == 8);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_notif, flags) == 12);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_notif, data) == 16);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_notif_resp, id) == 0);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_notif_resp, val) == 8);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_notif_resp, error) == 16);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_notif_resp, flags) == 20);

/// The size of `struct seccomp_notif` this crate is built against.
pub const NOTIF_SIZE: usize = 80;
/// The size of `struct seccomp_notif_resp` this crate is built against.
pub const RESP_SIZE: usize = 24;

/// A reply that denies a notified call with an errno (ADR-043, D5). It is
/// the only reply this crate can build: `flags` and `val` are always 0, so
/// the call never runs and never returns a value.
pub struct Deny(libc::seccomp_notif_resp);

impl Deny {
    /// The reply to notification `id` with `errno`, which must be 1 to
    /// [`MAX_REPLY_ERRNO`].
    pub fn new(id: u64, errno: i32) -> Option<Deny> {
        if !(1..=MAX_REPLY_ERRNO).contains(&errno) {
            return None;
        }
        Some(Deny(libc::seccomp_notif_resp {
            id,
            val: 0,
            error: -errno,
            flags: 0,
        }))
    }

    /// The notification it answers.
    pub fn id(&self) -> u64 {
        self.0.id
    }

    /// The return value: always 0.
    pub fn val(&self) -> i64 {
        self.0.val
    }

    /// The negated errno.
    pub fn error(&self) -> i32 {
        self.0.error
    }

    /// The reply flags: always 0.
    pub fn flags(&self) -> u32 {
        self.0.flags
    }
}

impl core::fmt::Debug for Deny {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Deny")
            .field("id", &self.0.id)
            .field("error", &self.0.error)
            .finish()
    }
}

/// A received notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notification {
    /// Its id, which the reply names.
    pub id: u64,
    /// The calling thread, in the supervisor's PID namespace.
    pub pid: u32,
    /// The kernel's notification flags.
    pub flags: u32,
    /// The call.
    pub data: Data,
}

/// The receive and reply buffers of one supervisor: zeroed, 8-aligned
/// (they are `u64` words) and as large as the kernel's structs, which
/// `SECCOMP_GET_NOTIF_SIZES` reports. The kernel requires a zeroed
/// receive buffer and may be newer than the structs this crate knows, so
/// both are sized by the kernel and this crate reads and writes only its
/// own prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buffers {
    recv: Vec<u64>,
    recv_len: usize,
    reply: Vec<u64>,
    reply_len: usize,
}

fn words(len: usize) -> Vec<u64> {
    vec![0; len.div_ceil(8)]
}

impl Buffers {
    /// Buffers for the kernel's `sizes`; [`Error::NotifySizes`] when any
    /// of them is smaller than this crate's struct (80, 24 and 64 bytes),
    /// which only a kernel this crate does not support reports.
    pub fn for_sizes(sizes: libc::seccomp_notif_sizes) -> Result<Buffers, Error> {
        let (notif, resp, data) = (
            usize::from(sizes.seccomp_notif),
            usize::from(sizes.seccomp_notif_resp),
            usize::from(sizes.seccomp_data),
        );
        if notif < NOTIF_SIZE || resp < RESP_SIZE || data < Data::SIZE {
            return Err(Error::NotifySizes {
                notif: sizes.seccomp_notif,
                resp: sizes.seccomp_notif_resp,
                data: sizes.seccomp_data,
            });
        }
        Ok(Buffers {
            recv: words(notif),
            recv_len: notif,
            reply: words(resp),
            reply_len: resp,
        })
    }

    /// The kernel's size of the receive buffer, in bytes.
    pub fn recv_len(&self) -> usize {
        self.recv_len
    }

    /// The kernel's size of the reply buffer, in bytes.
    pub fn reply_len(&self) -> usize {
        self.reply_len
    }

    /// The receive buffer, zeroed, for the next receive.
    pub fn recv_zeroed(&mut self) -> &mut [u64] {
        self.recv.fill(0);
        &mut self.recv
    }

    /// The receive buffer as it stands.
    pub fn recv(&self) -> &[u64] {
        &self.recv
    }

    /// The notification in the receive buffer: `id` at 0, `pid` at 8,
    /// `flags` at 12 and `data` at 16, little-endian.
    pub fn notification(&self) -> Notification {
        let mut data = [0u8; Data::SIZE];
        for (i, word) in self.recv[2..2 + Data::SIZE / 8].iter().enumerate() {
            data[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
        }
        Notification {
            id: self.recv[0],
            pid: self.recv[1] as u32,
            flags: (self.recv[1] >> 32) as u32,
            data: Data::from_bytes(&data),
        }
    }

    /// Writes `deny` into the zeroed reply buffer: `id` at 0, `val` at 8,
    /// `error` at 16 and `flags` at 20, little-endian; the kernel's
    /// trailing bytes stay zero.
    pub fn write_reply(&mut self, deny: &Deny) -> &[u64] {
        self.reply.fill(0);
        self.reply[0] = deny.id();
        self.reply[1] = deny.val() as u64;
        self.reply[2] = u64::from(deny.error() as u32) | (u64::from(deny.flags()) << 32);
        &self.reply
    }

    /// The reply buffer as it stands.
    pub fn reply(&self) -> &[u64] {
        &self.reply
    }
}

/// The answer to a notified call, derived from the plain program
/// (ADR-043, D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The plain program denies the call with `errno` at `row`'s return.
    Deny {
        /// The row.
        row: Row,
        /// Its errno.
        errno: i32,
        /// The record key of the call.
        key: Key,
    },
    /// The plain program allows or kills the call, or its answer names no
    /// row or another errno than the row's: a forged or inconsistent
    /// notification. The supervisor replies ENOSYS, never lets the call
    /// run, and stops as failed.
    Inconsistent {
        /// What the plain program returned.
        action: u32,
    },
}

impl Decision {
    /// The errno of the reply: the row's, or ENOSYS for an inconsistent
    /// call. Never 0.
    pub fn errno(&self) -> i32 {
        match self {
            Decision::Deny { errno, .. } => *errno,
            Decision::Inconsistent { .. } => libc::ENOSYS,
        }
    }

    /// Whether the supervisor stops as failed after replying.
    pub fn fails_supervisor(&self) -> bool {
        matches!(self, Decision::Inconsistent { .. })
    }
}

/// Evaluates the plain program on a notified call and derives the
/// answer. The notifying program differs from `plain` only in its errno
/// returns (ADR-043, D2), so a call it notified hits an errno return of
/// `plain`.
pub fn decide(arch: Arch, plain: &Program, data: &Data) -> Decision {
    let out = bpf::evaluate(plain.instructions(), data);
    let inconsistent = Decision::Inconsistent { action: out.action };
    let Some(row) = out.at.and_then(|at| plain.row_at(at)) else {
        return inconsistent;
    };
    let Some(errno) = row.errno() else {
        return inconsistent;
    };
    if out.action != errno_action(errno) {
        return inconsistent;
    }
    match Key::of(arch, row, data) {
        Some(key) => Decision::Deny { row, errno, key },
        None => inconsistent,
    }
}

/// A `seccomp_notif_sizes` for the unit tests, so that the reply
/// struct's name stays in this file.
#[cfg(test)]
pub(crate) fn sizes(notif: u16, resp: u16, data: u16) -> libc::seccomp_notif_sizes {
    libc::seccomp_notif_sizes {
        seccomp_notif: notif,
        seccomp_notif_resp: resp,
        seccomp_data: data,
    }
}

// The kernel side (ADR-043, D3 and D4): the listener, the three ioctls
// on it, and the supervisor thread.

/// The flags the notifying filter is installed with (ADR-043, D3 and D4):
/// a listener for the supervisor, and a receive after which a non-fatal
/// signal can no longer interrupt the call. Both are in Linux 5.19
/// (`kernel/seccomp.c:900`, `:1866`; D7).
pub(crate) const LISTENER_FLAGS: libc::c_ulong =
    libc::SECCOMP_FILTER_FLAG_NEW_LISTENER | libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

/// The kernel's sizes of the notification structs
/// (`SECCOMP_GET_NOTIF_SIZES`, Linux 5.0); the errno when the call fails.
pub(crate) fn kernel_sizes() -> std::result::Result<libc::seccomp_notif_sizes, i32> {
    let mut sizes = libc::seccomp_notif_sizes {
        seccomp_notif: 0,
        seccomp_notif_resp: 0,
        seccomp_data: 0,
    };
    // SAFETY: SECCOMP_GET_NOTIF_SIZES writes one seccomp_notif_sizes
    // through the pointer, which is valid for the call's duration.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0u32,
            &mut sizes as *mut libc::seccomp_notif_sizes,
        )
    };
    if rc < 0 {
        Err(crate::error::errno())
    } else {
        Ok(sizes)
    }
}

/// The listener of a sandbox's notifying filter, received from its child
/// (ADR-043, D3). The descriptor is private: the type has no `AsFd`,
/// `AsRawFd` or `IntoRawFd`, so the only requests made on it are the
/// three below, and the only reply is a [`Deny`]. Dropping it closes it,
/// and the kernel then answers every pending and every later notified
/// call of the sandbox with ENOSYS (`seccomp_notify_detach`, 5.19
/// `:1413`; no listener, `:1107`), so a lost supervisor leaves calls
/// denied, not hung (D4).
pub(crate) struct Listener(OwnedFd);

impl Listener {
    /// Takes the descriptor the child sent.
    pub(crate) fn new(fd: OwnedFd) -> Listener {
        Listener(fd)
    }

    /// `SECCOMP_IOCTL_NOTIF_RECV` into `buf`, which must be zeroed and at
    /// least the kernel's `seccomp_notif` size ([`Buffers`]).
    fn recv(&self, buf: &mut [u64]) -> std::result::Result<(), i32> {
        // SAFETY: buf is valid writable memory of at least the kernel's
        // seccomp_notif size (Buffers::for_sizes), all the kernel writes;
        // 8-aligned, as the struct needs.
        let rc = unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                buf.as_mut_ptr(),
            )
        };
        if rc < 0 {
            Err(crate::error::errno())
        } else {
            Ok(())
        }
    }

    /// `SECCOMP_IOCTL_NOTIF_ID_VALID`: whether notification `id` is still
    /// pending, so its caller is still the task the notification named.
    /// Retried on EINTR: the thread blocks every signal but the C
    /// library's own, and those (glibc's `SIGSETXID` from a set*id call in
    /// the runner) can still interrupt the request; a lost answer would
    /// drop a key's pid and comm.
    fn id_valid(&self, id: u64) -> bool {
        loop {
            match self.id_valid_once(id) {
                Ok(()) => return true,
                Err(libc::EINTR) => continue,
                Err(_) => return false,
            }
        }
    }

    fn id_valid_once(&self, id: u64) -> std::result::Result<(), i32> {
        #[cfg(test)]
        if ID_VALID_EINTR_ONCE.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(libc::EINTR);
        }
        // SAFETY: the kernel reads one u64 through the pointer, valid for
        // the call's duration.
        let rc = unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_ID_VALID,
                &id as *const u64,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(crate::error::errno())
        }
    }

    /// `SECCOMP_IOCTL_NOTIF_SEND` of `deny`, written into the reply buffer
    /// of `buffers`. The reply buffer is the only memory the kernel reads,
    /// and [`Buffers::write_reply`] fills it from a [`Deny`] alone, so the
    /// kernel only ever reads `flags` 0 and a negative errno.
    fn send(&self, buffers: &mut Buffers, deny: &Deny) -> std::result::Result<(), i32> {
        let reply = buffers.write_reply(deny);
        loop {
            // SAFETY: reply is at least the kernel's seccomp_notif_resp size
            // (Buffers::for_sizes) and 8-aligned; the kernel only reads it.
            let rc = unsafe {
                libc::ioctl(
                    self.0.as_raw_fd(),
                    libc::SECCOMP_IOCTL_NOTIF_SEND,
                    reply.as_ptr(),
                )
            };
            if rc == 0 {
                return Ok(());
            }
            // The kernel takes its notify lock interruptibly.
            match crate::error::errno() {
                libc::EINTR => continue,
                errno => return Err(errno),
            }
        }
    }
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Listener")
    }
}

/// The unit tests' way to interrupt the next ID_VALID request once with
/// EINTR, as a C library signal would. The host unit tests are serialized
/// by `test_guard::host_lock`, so one flag serves them.
#[cfg(test)]
pub(crate) static ID_VALID_EINTR_ONCE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// What the supervisor needs besides the listener, prepared before the
/// clone.
pub(crate) struct SupervisorPlan {
    /// The architecture of the calls.
    pub arch: Arch,
    /// The plain program, whose answer the supervisor replies with (D2).
    pub plain: Program,
    /// The receive and reply buffers in the kernel's sizes.
    pub buffers: Buffers,
    /// When the spawn started, for each call's time since spawn.
    pub started: std::time::Instant,
}

/// The name of the supervisor thread, as `/proc/<pid>/task/*/comm` shows
/// it.
pub const THREAD_NAME: &str = "seccomp-notify";

type Shared = std::sync::Arc<std::sync::Mutex<Record>>;

fn lock(record: &std::sync::Mutex<Record>) -> std::sync::MutexGuard<'_, Record> {
    record
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One sandbox's supervisor (ADR-043, D4): a thread in the process that
/// called `spawn` that answers every notified call of the sandbox with the
/// plain program's errno and records it. Stopping it (or dropping it)
/// ends the thread and closes the listener.
pub(crate) struct Supervisor {
    record: Shared,
    /// The write end of the stop pipe: closing it wakes the thread.
    stop: Option<OwnedFd>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl core::fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Supervisor")
            .field("running", &self.thread.is_some())
            .finish()
    }
}

impl Supervisor {
    /// Starts the thread. The listener is dropped, and so closed, if the
    /// thread cannot start.
    pub(crate) fn start(
        listener: Listener,
        plan: SupervisorPlan,
        seam: Seam,
    ) -> crate::error::Result<Supervisor> {
        let (stop_read, stop_write) = crate::spawn::report_pipe()?;
        let record: Shared = Default::default();
        let shared = record.clone();
        let (ready_tx, ready) = std::sync::mpsc::channel();
        let thread = std::thread::Builder::new()
            .name(THREAD_NAME.to_string())
            .spawn(move || supervise(listener, stop_read, plan, &shared, seam, ready_tx))
            .map_err(|e| Error::Supervisor {
                errno: e.raw_os_error().unwrap_or(libc::EAGAIN),
            })?;
        // The thread is named and its signal mask set before it says so,
        // so once `spawn` returns `/proc` shows the supervisor by its name.
        // It cannot end without sending or dropping the sender, and either
        // wakes this receive.
        let _ = ready.recv();
        Ok(Supervisor {
            record,
            stop: Some(stop_write),
            thread: Some(thread),
        })
    }

    /// A copy of the record as it stands.
    pub(crate) fn denials(&self) -> super::record::Denials {
        lock(&self.record).snapshot()
    }

    /// Stops the thread and waits for it. Called once the sandbox's PID
    /// namespace is reaped, when no task is left that could be notified;
    /// a second call does nothing.
    pub(crate) fn finish(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            // supervise() catches the loop's panics; this is the rest.
            lock(&self.record).fail(SupervisorFailure::Panicked);
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.finish();
    }
}

/// The supervisor thread's body: the loop under `catch_unwind`, then the
/// failure recorded, then the listener closed, in that order. Every path
/// that ends the loop with a failure records it before any call is
/// answered ENOSYS for it (the inconsistent path records it before its
/// own ENOSYS reply, in `serve`), so a reader that sees a call answered
/// ENOSYS can see why even before `wait`. No test can pin this order
/// (the window is microseconds); it is kept by review, and the record is
/// complete once `wait` returned (ADR-043, D4).
fn supervise(
    listener: Listener,
    stop: OwnedFd,
    mut plan: SupervisorPlan,
    record: &Shared,
    seam: Seam,
    ready: std::sync::mpsc::Sender<()>,
) {
    block_signals();
    let _ = ready.send(());
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        serve(&listener, &stop, &mut plan, record, seam)
    }));
    let failure = match outcome {
        Ok(Ok(())) => None,
        Ok(Err(failure)) => Some(failure),
        Err(_) => Some(SupervisorFailure::Panicked),
    };
    if let Some(failure) = failure {
        lock(record).fail(failure);
    }
    drop(listener);
}

/// Blocks every signal of the calling thread but the ones the C library
/// reserves for itself, so a process-directed signal goes to another
/// thread and the loop's waits are never interrupted. `sigfillset` leaves
/// the reserved ones out (glibc: 32 `SIGCANCEL` and 33 `SIGSETXID`; musl:
/// 32 to 34), and glibc's `pthread_sigmask` clears them again. They must
/// stay deliverable: `setuid`, `setgid` or `setgroups` in the runner sends
/// `SIGSETXID` to every thread and waits for each handler, so a thread
/// that blocked it would hang that call, every later thread start and
/// this thread's own exit (review of #45 PR 2).
fn block_signals() {
    // SAFETY: an all-zero sigset_t is valid storage for sigfillset.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: set is valid storage of the right type.
    unsafe { libc::sigfillset(&mut set) };
    // SAFETY: set is a valid signal set; no old mask is requested.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) };
}

/// What woke the supervisor.
enum Wake {
    /// A notification is pending.
    Notification,
    /// The stop pipe closed.
    Stop,
    /// No task uses the filter any more (`EPOLLHUP`, 5.19 `:1759`).
    Hangup,
}

fn wait(listener: &Listener, stop: &OwnedFd) -> std::result::Result<Wake, SupervisorFailure> {
    loop {
        let mut fds = [
            libc::pollfd {
                fd: listener.0.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: fds is two valid pollfds for the call's duration.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            match crate::error::errno() {
                libc::EINTR => continue,
                errno => {
                    return Err(SupervisorFailure::Sys {
                        call: "poll",
                        errno,
                    });
                }
            }
        }
        if fds[1].revents != 0 {
            return Ok(Wake::Stop);
        }
        let revents = fds[0].revents;
        if revents & libc::POLLIN != 0 {
            return Ok(Wake::Notification);
        }
        if revents & libc::POLLHUP != 0 {
            return Ok(Wake::Hangup);
        }
        if revents != 0 {
            // The listener's poll sets nothing else (5.19 `:1735`-`1762`).
            return Err(SupervisorFailure::Sys {
                call: "poll",
                errno: libc::EIO,
            });
        }
    }
}

/// Reads the inside pid and the comm of the task the notification named
/// (ADR-043, D6), then checks that the notification is still pending, so
/// the status read belongs to its caller and not to a task that took the
/// number after it was gone.
fn caller(listener: &Listener, id: u64, pid: u32) -> Status {
    use std::io::Read;
    let mut bytes = Vec::with_capacity(2048);
    if let Ok(file) = std::fs::File::open(format!("/proc/{pid}/status")) {
        let _ = file.take(STATUS_MAX as u64).read_to_end(&mut bytes);
    }
    let status = parse_status(&bytes, pid);
    if listener.id_valid(id) {
        status
    } else {
        Status::default()
    }
}

/// The loop (ADR-043, D4): wait, receive, decide, note, reply. `Ok` when
/// it ended because the sandbox is gone or it was stopped; `Err` with the
/// reason it stopped answering otherwise.
fn serve(
    listener: &Listener,
    stop: &OwnedFd,
    plan: &mut SupervisorPlan,
    record: &Shared,
    seam: Seam,
) -> std::result::Result<(), SupervisorFailure> {
    loop {
        match wait(listener, stop)? {
            Wake::Stop | Wake::Hangup => return Ok(()),
            Wake::Notification => {}
        }
        seam_before_recv(seam);
        match listener.recv(plan.buffers.recv_zeroed()) {
            Ok(()) => {}
            // The caller was killed after the poll, or a signal came.
            Err(libc::ENOENT | libc::EINTR) => continue,
            Err(errno) => {
                return Err(SupervisorFailure::Sys {
                    call: "notif-recv",
                    errno,
                });
            }
        }
        let mut n = plan.buffers.notification();
        seam_after_recv(seam, &mut n);
        let decision = decide(plan.arch, &plan.plain, &n.data);
        if let Decision::Deny { key, errno, .. } = decision {
            let first = !lock(record).contains(&key);
            // Only a key's first call reads /proc: a flood of one key costs
            // receive, decide and reply only (D8).
            let status = if first {
                caller(listener, n.id, n.pid)
            } else {
                Status::default()
            };
            let call = Call {
                since_spawn: plan.started.elapsed(),
                nr: n.data.nr,
                args: n.data.args,
                errno,
                pid: status.pid,
                comm: status.comm,
            };
            lock(record).note(key, call);
        }
        seam_before_send(seam, listener, stop, &n)?;
        // An inconsistent call is answered ENOSYS and ends the loop as
        // failed; the failure is recorded first, so a reader that sees the
        // ENOSYS can see why (D4; the order is kept by review, no test
        // pins it).
        if let Decision::Inconsistent { action } = decision {
            lock(record).fail(SupervisorFailure::Inconsistent {
                nr: n.data.nr,
                action,
            });
        }
        let Some(deny) = Deny::new(n.id, decision.errno()) else {
            // decision.errno() is a row's errno or ENOSYS; nothing else.
            return Err(SupervisorFailure::Inconsistent {
                nr: n.data.nr,
                action: 0,
            });
        };
        match listener.send(&mut plan.buffers, &deny) {
            Ok(()) => {}
            // The caller is gone: killed while it waited.
            Err(libc::ENOENT) => lock(record).note_unanswered(),
            Err(errno) => {
                return Err(SupervisorFailure::Sys {
                    call: "notif-send",
                    errno,
                });
            }
        }
        if let Decision::Inconsistent { action } = decision {
            return Err(SupervisorFailure::Inconsistent {
                nr: n.data.nr,
                action,
            });
        }
    }
}

/// Test seams of the supervisor (ADR-043 PR 2's host tests). Each one
/// acts only on notifications of syscall `nr`, so the calls a test
/// process makes on its own (libtest's thread start notifies `clone3`)
/// are answered as usual.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Seam {
    /// No seam.
    None,
    /// Notes the call and holds it unanswered until the supervisor is
    /// stopped, which then ends as [`SupervisorFailure::Stopped`].
    Hold { nr: u32 },
    /// Notes the call and holds it until its caller is gone, then
    /// replies (the kernel's ENOENT).
    HoldUntilGone { nr: u32 },
    /// Panics right after the receive.
    PanicAfterRecv { nr: u32 },
    /// Sleeps this long before every receive.
    DelayRecv(std::time::Duration),
    /// Rewrites the received call's number to `to`, as a forged or
    /// inconsistent notification would read: one the plain program allows.
    Forge { nr: u32, to: u32 },
    /// After the receive, sends `SIGUSR1` to the caller's thread group
    /// (the caller is single-threaded) and replies `hold` later.
    SignalAfterRecv { nr: u32, hold: std::time::Duration },
}

/// Without tests there are no seams.
#[cfg(not(test))]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Seam {
    None,
}

#[cfg(test)]
fn seam_before_recv(seam: Seam) {
    if let Seam::DelayRecv(d) = seam {
        std::thread::sleep(d);
    }
}

#[cfg(test)]
fn seam_after_recv(seam: Seam, n: &mut Notification) {
    match seam {
        Seam::Forge { nr, to } if nr == n.data.nr => n.data.nr = to,
        Seam::PanicAfterRecv { nr } if nr == n.data.nr => {
            panic!("the PanicAfterRecv seam, at a notification of {nr}");
        }
        Seam::SignalAfterRecv { nr, hold } if nr == n.data.nr => {
            // SAFETY: kill takes plain integers; the caller is a
            // single-threaded process, so its thread id is its pid.
            unsafe { libc::kill(n.pid as libc::pid_t, libc::SIGUSR1) };
            std::thread::sleep(hold);
        }
        _ => {}
    }
}

#[cfg(test)]
fn seam_before_send(
    seam: Seam,
    listener: &Listener,
    stop: &OwnedFd,
    n: &Notification,
) -> std::result::Result<(), SupervisorFailure> {
    match seam {
        Seam::Hold { nr } if nr == n.data.nr => {
            let mut pfd = libc::pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd is one valid pollfd for the call's duration.
            while unsafe { libc::poll(&mut pfd, 1, -1) } <= 0 {}
            Err(SupervisorFailure::Stopped)
        }
        Seam::HoldUntilGone { nr } if nr == n.data.nr => {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while listener.id_valid(n.id) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the held caller is still there after 30 s"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(not(test))]
#[inline(always)]
fn seam_before_recv(_seam: Seam) {}

#[cfg(not(test))]
#[inline(always)]
fn seam_after_recv(_seam: Seam, _n: &mut Notification) {}

#[cfg(not(test))]
#[inline(always)]
fn seam_before_send(
    _seam: Seam,
    _listener: &Listener,
    _stop: &OwnedFd,
    _n: &Notification,
) -> std::result::Result<(), SupervisorFailure> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_reply_encoding() {
        for errno in [
            1,
            libc::EPERM,
            libc::ENOSYS,
            libc::EHWPOISON,
            MAX_REPLY_ERRNO,
        ] {
            let d = Deny::new(7, errno).expect("in range");
            assert_eq!(
                (d.id(), d.val(), d.error(), d.flags()),
                (7, 0, -errno, 0),
                "errno {errno}"
            );
        }
        // 0 is a success; 512 to 531 are the kernel's internal codes
        // (ERESTARTSYS, ERESTARTNOINTR, ERESTARTNOHAND, ENOIOCTLCMD,
        // ERESTART_RESTARTBLOCK, ..., ENOGRACE); 4095 is MAX_ERRNO.
        let internal = 512..=531;
        for errno in [0, -1, i32::MIN, i32::MAX, 4095, 4096]
            .into_iter()
            .chain(internal)
        {
            assert!(Deny::new(7, errno).is_none(), "errno {errno}");
        }
        let d = Deny::new(u64::MAX, libc::EPERM).expect("in range");
        assert_eq!(d.id(), u64::MAX);
        // The bytes the kernel reads: id, val, error, flags.
        let mut b = Buffers::for_sizes(sizes(80, 24, 64)).expect("our sizes");
        let words = b.write_reply(&d).to_vec();
        assert_eq!(words, vec![u64::MAX, 0, u64::from((-libc::EPERM) as u32)]);
        let mut bytes = Vec::new();
        for w in &words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        assert_eq!(&bytes[16..20], &(-libc::EPERM).to_le_bytes());
        assert_eq!(&bytes[20..24], &[0, 0, 0, 0]);
        assert_eq!(&bytes[8..16], &[0; 8]);
    }

    #[test]
    fn notif_buffers_follow_kernel_sizes() {
        // Our sizes: exactly our layout.
        let b = Buffers::for_sizes(sizes(80, 24, 64)).expect("our sizes");
        assert_eq!((b.recv_len(), b.reply_len()), (80, 24));
        assert_eq!((b.recv().len(), b.reply().len()), (10, 3));
        assert!(b.recv().iter().chain(b.reply()).all(|w| *w == 0));
        // A newer kernel: its sizes, zeroed, our prefix.
        let mut b = Buffers::for_sizes(sizes(96, 32, 72)).expect("larger sizes");
        assert_eq!((b.recv_len(), b.reply_len()), (96, 32));
        assert_eq!((b.recv().len(), b.reply().len()), (12, 4));
        assert!(b.recv().iter().chain(b.reply()).all(|w| *w == 0));
        let d = Deny::new(3, libc::EAFNOSUPPORT).expect("in range");
        let reply = b.write_reply(&d).to_vec();
        assert_eq!(reply[0], 3);
        assert_eq!(reply[3], 0, "the kernel's trailing bytes stay zero");
        // A received notification is read from our prefix.
        let data = Data {
            nr: 41,
            arch: Arch::X86_64.audit_arch(),
            instruction_pointer: 0x1122_3344_5566_7788,
            args: [40, 1, 0, 0, 0, u64::MAX],
        };
        let recv = b.recv_zeroed();
        recv[0] = 9;
        recv[1] = 4711 | (5u64 << 32);
        for (i, chunk) in data.to_bytes().chunks(8).enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(chunk);
            recv[2 + i] = u64::from_le_bytes(w);
        }
        recv[11] = u64::MAX;
        assert_eq!(
            b.notification(),
            Notification {
                id: 9,
                pid: 4711,
                flags: 5,
                data
            }
        );
        assert!(b.recv_zeroed().iter().all(|w| *w == 0), "zeroed again");
        // Any size below ours is refused, with the kernel's numbers.
        for (n, r, d) in [(79, 24, 64), (80, 23, 64), (80, 24, 63), (79, 23, 63)] {
            match Buffers::for_sizes(sizes(n, r, d)) {
                Err(Error::NotifySizes { notif, resp, data }) => {
                    assert_eq!((notif, resp, data), (n, r, d));
                }
                other => panic!("{n}/{r}/{d}: {other:?}"),
            }
        }
    }
}

/// The supervisor's host tests that need a seam (ADR-043, D4): a lost
/// supervisor, a killed caller and signals around the receive. Each runs
/// this unit-test binary in a sandbox as a probe ([`host::unit_probe`]),
/// which makes `socket(AF_VSOCK)` calls, denied by the SocketFamily row
/// with EAFNOSUPPORT, and prints `BONELI_UNIT key=value` lines. No test
/// asserts a duration: the measured times are printed, and 30 s is a hang
/// bound (ADR-043, D8).
#[cfg(test)]
mod host {
    use super::*;
    use crate::child::Fault;
    use crate::spawn::{Child, ExitStatus, Spec, Stdio, spawn_with};
    use crate::test_guard::{UNIT_PROBE, UnitRoot, host_lock, sandbox_cgroup};
    use std::collections::BTreeMap;
    use std::io::{BufRead, Read, Write};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    const PROBE_VAR: &str = "BONELI_SYS_UNIT_PROBE";
    const RESTART_VAR: &str = "BONELI_SYS_UNIT_RESTART";
    const PREFIX: &str = "BONELI_UNIT ";
    /// The hang bound of one probe run (ADR-043, D8).
    const HANG_BOUND: Duration = Duration::from_secs(30);
    /// Set in a forked child's exit code when its signal handler ran.
    const HANDLED: i32 = 0x80;
    /// A forked child's exit code when its timer fired before its call.
    const EARLY: i32 = 0x7f;

    fn socket_nr() -> u32 {
        Arch::NATIVE.syscalls().socket
    }

    fn put(key: &str, value: &str) {
        let mut out = std::io::stdout();
        let _ = writeln!(out, "{PREFIX}{key}={value}");
        let _ = out.flush();
    }

    fn errno() -> i32 {
        crate::error::errno()
    }

    /// `socket(AF_VSOCK, SOCK_STREAM, 0)`: its errno, 0 if it succeeded
    /// (closed at once).
    fn vsock() -> i32 {
        // SAFETY: socket takes plain integers.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd >= 0 {
            // SAFETY: the call returned a new descriptor that nothing owns.
            unsafe { libc::close(fd) };
            return 0;
        }
        errno()
    }

    static FIRED: AtomicBool = AtomicBool::new(false);
    /// Read from [`RESTART_VAR`] before the fork: the forked child must not
    /// allocate, and reading the environment does.
    static RESTART: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_signal(_sig: libc::c_int) {
        FIRED.store(true, Ordering::SeqCst);
    }

    /// Installs [`on_signal`] for `sig`, with `SA_RESTART` if asked.
    fn handle(sig: libc::c_int, restart: bool) {
        // SAFETY: an all-zero sigaction is valid storage.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = if restart { libc::SA_RESTART } else { 0 };
        // SAFETY: action is valid; the handler only stores to an atomic.
        unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) };
    }

    /// Runs `body` in a forked, single-threaded child and returns its exit
    /// code (255 if it did not exit). `body` must not allocate: the child
    /// is a copy of one thread (the allocation guard ends it with 97).
    fn in_fork(body: fn() -> i32) -> i32 {
        // SAFETY: the child runs only `body` and _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: errno {}", errno());
        if pid == 0 {
            let code = body();
            // SAFETY: _exit ends the forked child without running anything.
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        // SAFETY: status is valid storage; pid is this process's child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            255
        }
    }

    /// A denied call after a signal handler was installed: the exit code
    /// is the call's errno, plus [`HANDLED`] if the handler ran by the time
    /// the call returned.
    fn signalled_call() -> i32 {
        handle(libc::SIGUSR1, false);
        let e = vsock();
        e | if FIRED.load(Ordering::SeqCst) {
            HANDLED
        } else {
            0
        }
    }

    /// A denied call with a 100 ms timer running: [`EARLY`] if the timer
    /// fired before the call started, else as [`signalled_call`].
    fn timed_call() -> i32 {
        handle(libc::SIGALRM, RESTART.load(Ordering::SeqCst));
        let timer = libc::itimerval {
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: libc::timeval {
                tv_sec: 0,
                tv_usec: 100_000,
            },
        };
        // SAFETY: timer is valid for the call's duration; no old value.
        unsafe { libc::setitimer(libc::ITIMER_REAL, &timer, std::ptr::null_mut()) };
        if FIRED.load(Ordering::SeqCst) {
            return EARLY;
        }
        let e = vsock();
        e | if FIRED.load(Ordering::SeqCst) {
            HANDLED
        } else {
            0
        }
    }

    /// The probe mode: does nothing without [`PROBE_VAR`].
    #[test]
    fn unit_probe() {
        let Some(action) = std::env::var_os(PROBE_VAR) else {
            return;
        };
        RESTART.store(std::env::var_os(RESTART_VAR).is_some(), Ordering::SeqCst);
        match action.to_str() {
            // Two calls, each with its errno and time.
            Some("vsock-twice") => {
                for i in 0..2 {
                    let t = Instant::now();
                    let e = vsock();
                    put(&format!("errno{i}"), &e.to_string());
                    put(&format!("ms{i}"), &t.elapsed().as_millis().to_string());
                }
            }
            // One call, then wait for stdin to end, so the test can read
            // the record while the sandbox still runs.
            Some("vsock-wait") => {
                put("errno0", &vsock().to_string());
                let mut rest = Vec::new();
                let _ = std::io::stdin().read_to_end(&mut rest);
            }
            Some("signal-after") => put("code", &in_fork(signalled_call).to_string()),
            Some("signal-before") => put("code", &in_fork(timed_call).to_string()),
            _ => put("unknown", "1"),
        }
        let _ = std::io::stdout().flush();
        // SAFETY: _exit ends the probe at once; nothing is left to run.
        unsafe { libc::_exit(0) };
    }

    /// A probe running in a sandbox under `seam`.
    struct Running {
        child: Child,
        /// The probe's stdout, line by line.
        out: std::sync::mpsc::Receiver<String>,
        /// The probe's stdin; `vsock-wait` waits for its end.
        stdin: Option<std::io::PipeWriter>,
        _cgroup: crate::Cgroup,
        _unit: UnitRoot,
    }

    fn start(action: &str, env: &[(&str, &str)], seam: Seam) -> Running {
        let unit = UnitRoot::with_probe();
        let cg = sandbox_cgroup("notify");
        let (out_r, out_w) = std::io::pipe().expect("pipe");
        let (in_r, in_w) = std::io::pipe().expect("pipe");
        let null = || -> OwnedFd {
            std::fs::File::options()
                .read(true)
                .write(true)
                .open("/dev/null")
                .expect("open /dev/null")
                .into()
        };
        let mut vars = vec![(PROBE_VAR.into(), action.into())];
        vars.extend(env.iter().map(|(k, v)| ((*k).into(), (*v).into())));
        let spec = Spec {
            program: UNIT_PROBE.into(),
            args: [
                "--exact",
                "seccomp::notify::host::unit_probe",
                "--nocapture",
                "--quiet",
                "--test-threads=1",
            ]
            .iter()
            .map(Into::into)
            .collect(),
            env: vars,
            stdio: Stdio {
                stdin: in_r.into(),
                stdout: out_w.into(),
                stderr: null(),
            },
            ids: crate::Ids::new(0, 0).expect("ids"),
            root: unit.root.clone(),
            cgroup: &cg,
            setup_timeout: Duration::from_secs(10),
        };
        let mut pid = 0;
        let child = spawn_with(&spec, Fault::None, seam, &mut pid).expect("spawn the probe");
        drop(spec);
        let (lines, out) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(out_r).lines().map_while(Result::ok) {
                let _ = lines.send(line);
            }
        });
        Running {
            child,
            out,
            stdin: Some(in_w),
            _cgroup: cg,
            _unit: unit,
        }
    }

    impl Running {
        /// The value of the probe's next line with `key`, within the hang
        /// bound.
        fn await_line(&self, key: &str) -> String {
            let deadline = Instant::now() + HANG_BOUND;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let line = self
                    .out
                    .recv_timeout(left)
                    .unwrap_or_else(|e| panic!("no {key} line within {HANG_BOUND:?}: {e}"));
                if let Some((k, v)) = line
                    .split_once(PREFIX)
                    .and_then(|(_, kv)| kv.split_once('='))
                    && k == key
                {
                    return v.to_string();
                }
            }
        }

        /// Polls the record until it holds an entry, within the hang bound.
        fn await_entry(&self) {
            let deadline = Instant::now() + HANG_BOUND;
            while self
                .child
                .denials()
                .entries()
                .iter()
                .all(|d| d.row != Row::SocketFamily)
            {
                assert!(Instant::now() < deadline, "no entry within {HANG_BOUND:?}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        /// Waits for the probe within the hang bound and parses its lines.
        fn finish(
            mut self,
        ) -> (
            ExitStatus,
            BTreeMap<String, String>,
            super::super::record::Denials,
        ) {
            drop(self.stdin.take());
            let deadline = Instant::now() + HANG_BOUND;
            loop {
                let mut pfd = libc::pollfd {
                    fd: self.child.pidfd().as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: pfd is one valid pollfd for the call's duration.
                if unsafe { libc::poll(&mut pfd, 1, 50) } > 0 {
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = self.child.kill();
                    panic!("the probe still runs after {HANG_BOUND:?}");
                }
            }
            let status = self.child.wait().expect("wait");
            let values = self
                .out
                .iter()
                .filter_map(|l| {
                    l.split_once(PREFIX)
                        .and_then(|(_, kv)| kv.split_once('='))
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                })
                .collect();
            let denials = self.child.denials();
            let _ = self._cgroup.destroy();
            (status, values, denials)
        }
    }

    fn report(line: &str) {
        let _ = writeln!(std::io::stderr(), "boneli-sys unit test: {line}");
    }

    fn vsock_count(d: &super::super::record::Denials) -> u64 {
        d.entries()
            .iter()
            .filter(|e| e.row == Row::SocketFamily)
            .map(|e| e.count)
            .sum()
    }

    fn get<'a>(v: &'a BTreeMap<String, String>, key: &str) -> &'a str {
        v.get(key)
            .unwrap_or_else(|| panic!("the probe printed no {key}: {v:?}"))
    }

    #[test]
    #[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
    fn stopped_supervisor_leaves_calls_denied() {
        let _host = host_lock();
        let mut run = start("vsock-twice", &[], Seam::Hold { nr: socket_nr() });
        // The first call is noted and held unanswered; then the supervisor
        // goes, and the kernel answers the held call and the next one.
        run.await_entry();
        run.child.stop_supervisor();
        let (status, v, denials) = run.finish();
        assert_eq!(status, ExitStatus::Exited(0), "{v:?}");
        let enosys = libc::ENOSYS.to_string();
        assert_eq!(get(&v, "errno0"), enosys, "the held call");
        assert_eq!(get(&v, "errno1"), enosys, "a call after the stop");
        assert_eq!(denials.failed(), Some(&SupervisorFailure::Stopped));
        assert_eq!(vsock_count(&denials), 1, "the held call is in the record");
        report(&format!(
            "stopped_supervisor_leaves_calls_denied: held call {} ms, next call {} ms",
            get(&v, "ms0"),
            get(&v, "ms1")
        ));
    }

    #[test]
    #[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
    fn panicked_supervisor_leaves_calls_denied() {
        let _host = host_lock();
        let run = start("vsock-twice", &[], Seam::PanicAfterRecv { nr: socket_nr() });
        let (status, v, denials) = run.finish();
        assert_eq!(status, ExitStatus::Exited(0), "{v:?}");
        let enosys = libc::ENOSYS.to_string();
        assert_eq!(get(&v, "errno0"), enosys, "the received call");
        assert_eq!(get(&v, "errno1"), enosys, "a call after the panic");
        assert_eq!(denials.failed(), Some(&SupervisorFailure::Panicked));
        assert_eq!(vsock_count(&denials), 0, "it panicked before the note");
        report(&format!(
            "panicked_supervisor_leaves_calls_denied: received call {} ms, next call {} ms",
            get(&v, "ms0"),
            get(&v, "ms1")
        ));
        // While the sandbox still runs, once the caller has its ENOSYS, a
        // read finds the panic in the common case. This does not pin the
        // order of record and close (D4): the window is microseconds.
        let run = start("vsock-wait", &[], Seam::PanicAfterRecv { nr: socket_nr() });
        assert_eq!(run.await_line("errno0"), enosys);
        assert_eq!(
            run.child.denials().failed(),
            Some(&SupervisorFailure::Panicked)
        );
        let (status, _, _) = run.finish();
        assert_eq!(status, ExitStatus::Exited(0));
    }

    #[test]
    #[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
    fn inconsistent_notification_is_denied_and_fails() {
        let _host = host_lock();
        // The first socket call reads as getpid, which the plain program
        // allows: an inconsistent notification. It is answered ENOSYS,
        // never let through, and the supervisor stops as failed; the
        // kernel answers the second call ENOSYS without it.
        let getpid = if cfg!(target_arch = "x86_64") {
            39
        } else {
            172
        };
        let seam = Seam::Forge {
            nr: socket_nr(),
            to: getpid,
        };
        let run = start("vsock-twice", &[], seam);
        let (status, v, denials) = run.finish();
        assert_eq!(status, ExitStatus::Exited(0), "{v:?}");
        let enosys = libc::ENOSYS.to_string();
        assert_eq!(get(&v, "errno0"), enosys, "the inconsistent call");
        assert_eq!(get(&v, "errno1"), enosys, "a call after the failure");
        assert_eq!(
            denials.failed(),
            Some(&SupervisorFailure::Inconsistent {
                nr: getpid,
                action: libc::SECCOMP_RET_ALLOW,
            })
        );
        assert_eq!(vsock_count(&denials), 0);
        // While the sandbox still runs, once the caller has its ENOSYS, a
        // read finds the failure in the common case. This does not pin the
        // order of record and reply (D4): the window is microseconds.
        let run = start("vsock-wait", &[], seam);
        assert_eq!(run.await_line("errno0"), enosys);
        assert_eq!(
            run.child.denials().failed(),
            Some(&SupervisorFailure::Inconsistent {
                nr: getpid,
                action: libc::SECCOMP_RET_ALLOW,
            }),
            "a read once the call returned"
        );
        let (status, _, _) = run.finish();
        assert_eq!(status, ExitStatus::Exited(0));
    }

    #[test]
    #[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
    fn interrupted_id_check_is_retried() {
        let _host = host_lock();
        // The first key's ID_VALID request is interrupted once, as a C
        // library signal (glibc's SIGSETXID) can do: it is retried, so the
        // key keeps the pid and comm it read. Without the retry that entry
        // would have neither.
        ID_VALID_EINTR_ONCE.store(true, Ordering::SeqCst);
        let run = start("vsock-twice", &[], Seam::None);
        let (status, v, denials) = run.finish();
        assert_eq!(status, ExitStatus::Exited(0), "{v:?}");
        assert!(
            !ID_VALID_EINTR_ONCE.load(Ordering::SeqCst),
            "the interruption was taken"
        );
        assert!(!denials.entries().is_empty(), "{denials:?}");
        for d in denials.entries() {
            assert!(
                d.first.call.pid.is_some() && d.first.call.comm.is_some(),
                "{d:?}"
            );
        }
        assert_eq!(denials.failed(), None);
    }

    #[test]
    #[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
    fn killed_caller_is_not_a_failure() {
        let _host = host_lock();
        let run = start("vsock-twice", &[], Seam::HoldUntilGone { nr: socket_nr() });
        run.await_entry();
        run.child.kill().expect("kill the sandbox");
        let (status, _, denials) = run.finish();
        assert_eq!(status, ExitStatus::Signaled(libc::SIGKILL));
        assert_eq!(denials.unanswered(), 1, "the reply found its caller gone");
        assert_eq!(denials.failed(), None);
        assert_eq!(vsock_count(&denials), 1);
    }

    #[test]
    #[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
    fn signal_after_receive_keeps_the_errno() {
        let _host = host_lock();
        // The supervisor signals the caller after the receive and answers
        // 200 ms later: the wait is killable only, so the handler runs
        // after the call returned, with the row's errno, not EINTR.
        let seam = Seam::SignalAfterRecv {
            nr: socket_nr(),
            hold: Duration::from_millis(200),
        };
        let run = start("signal-after", &[], seam);
        let (status, v, denials) = run.finish();
        assert_eq!(status, ExitStatus::Exited(0), "{v:?}");
        assert_eq!(
            get(&v, "code"),
            (libc::EAFNOSUPPORT | HANDLED).to_string(),
            "the row's errno, and the handler ran"
        );
        assert_eq!(vsock_count(&denials), 1);
        assert_eq!(denials.failed(), None);
    }

    #[test]
    #[ignore = "host: user namespaces, cgroup v2 delegation, seccomp user notification"]
    fn signal_before_receive_restarts_or_interrupts() {
        let _host = host_lock();
        // Every receive waits 1 s, and a 100 ms timer interrupts the call
        // before it: without SA_RESTART the call fails with EINTR, with it
        // the call restarts and is denied. Never allowed. The interrupted
        // notification is withdrawn before any receive (5.19
        // `seccomp_do_user_notification`, `list_del` on the interrupted
        // path), so the record holds no entry for the EINTR call and one
        // for the restarted one: an interrupted call is missed, never
        // counted twice.
        for (restart, want, entries) in [(false, libc::EINTR, 0), (true, libc::EAFNOSUPPORT, 1)] {
            let env: &[(&str, &str)] = if restart { &[(RESTART_VAR, "1")] } else { &[] };
            let mut tries = 0;
            let (code, denials) = loop {
                tries += 1;
                let run = start(
                    "signal-before",
                    env,
                    Seam::DelayRecv(Duration::from_secs(1)),
                );
                let (status, v, denials) = run.finish();
                assert_eq!(status, ExitStatus::Exited(0), "{v:?}");
                let code: i32 = get(&v, "code").parse().expect("a number");
                // The timer fired before the call: try again.
                if code == EARLY && tries < 3 {
                    continue;
                }
                break (code, denials);
            };
            assert_eq!(code, want | HANDLED, "SA_RESTART {restart}");
            assert_eq!(vsock_count(&denials), entries, "SA_RESTART {restart}");
            assert_eq!(denials.failed(), None);
            report(&format!(
                "signal_before_receive_restarts_or_interrupts: SA_RESTART {restart}: \
                 errno {}, {} record entries for the call",
                code & !HANDLED,
                vsock_count(&denials)
            ));
        }
    }
}
