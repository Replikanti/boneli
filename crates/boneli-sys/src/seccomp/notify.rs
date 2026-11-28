//! The pure part of the seccomp supervisor (ADR-043, D4 and D5): the one
//! reply it can send, the buffers it receives into and replies from, and
//! how it derives the answer to a notified call from the plain program.
//!
//! This is the only file of the crate that may name the kernel's reply
//! struct and the ioctl that sends it; the self-scan
//! (`tests/boneli_sys_tests/notify_scan.rs`) holds every other file to
//! that, and bans the names of the flag that would let a call run and of
//! the descriptor-injection ioctl everywhere.

use super::bpf::{self, Data};
use super::policy::{Program, Row, errno_action};
use super::record::Key;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sizes(notif: u16, resp: u16, data: u16) -> libc::seccomp_notif_sizes {
        libc::seccomp_notif_sizes {
            seccomp_notif: notif,
            seccomp_notif_resp: resp,
            seccomp_data: data,
        }
    }

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
