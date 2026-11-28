//! The record of denied calls (ADR-043, D6): one entry per key, a key per
//! row and selector value, the first occurrence of each key kept in full,
//! and the decoding that renders an entry as one ASCII line.
//!
//! Everything here is pure: the supervisor (ADR-043, D4) feeds it the
//! notification's `seccomp_data`, the inside pid and the comm it read
//! from `/proc/<pid>/status`, and the time since spawn. No workload
//! memory is read; pointer arguments stay raw values.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use super::bpf::Data;
use super::policy::Row;
use super::table::{
    AF_INET, AF_INET6, AF_NETLINK, AF_UNIX, Arch, BPFILTER_OPTIONS, CEILING, CLONE_NEWUSER,
    ENOPROTOOPT, FS_CRYPTO_IOCTLS, FS_IOC_ADD_ENCRYPTION_KEY, FS_IOC_ENABLE_VERITY,
    FS_IOC_SET_ENCRYPTION_POLICY, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IP, IPPROTO_TCP,
    IPPROTO_UDP, MAP_HUGETLB, MFD_HUGETLB, MODULE_IOCTLS, NETLINK_ROUTE, SHM_HUGETLB, SIOCBRADDBR,
    SIOCBRADDIF, SIOCBRDELBR, SIOCBRDELIF, SIOCGIFBR, SIOCGIFVLAN, SIOCSIFBR, SIOCSIFVLAN,
    SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_PACKET, SOCK_PACKET_TYPES, SOL_SOCKET, SOL_TLS, Syscalls,
    TCP_AO_ADD_KEY, TCP_MD5SIG, TCP_MD5SIG_EXT, TCP_SIGNATURE_OPTIONS, TIOCSETD,
};

/// The highest syscall number above [`CEILING`] with a key of its own;
/// higher numbers, x32 numbers and −1 share one. 472 to 511 are 40
/// numbers: Linux added 48 (424 in 5.1 to 471 in 7.2) in about seven
/// years, so the window covers about five to six years of new syscalls
/// (ADR-043, D8).
pub const CEILING_KEYS_LAST: u32 = 511;

/// `AF_MAX` in Linux 7.2 (`include/linux/socket.h`): families 0 to 45
/// have keys of their own, higher ones share one. The kernel answers
/// EAFNOSUPPORT for those itself.
pub const FAMILY_KEYS: u32 = 46;

/// `MAX_LINKS` (`include/uapi/linux/netlink.h`): netlink protocols 1 to
/// 31 have keys of their own, higher ones share one, which
/// `netlink_create` refuses itself.
pub const NETLINK_KEYS: u32 = 32;

/// `IPPROTO_MPTCP`, the highest IP protocol in the Linux 7.2 uapi
/// (`include/uapi/linux/in.h`): protocols up to it have keys of their
/// own, higher ones share one per family, which `inet_create` refuses
/// with EINVAL itself.
pub const INET_PROTOCOL_LAST: u32 = 262;

/// The number of keys [`Key::all`] gives on each architecture: the bound
/// on a record's entries (ADR-043, D6 and D8).
pub const KEY_SPACE: usize = 723;

/// The bytes of `/proc/<pid>/status` that [`parse_status`] reads: the dev
/// host's longest status file was 1,542 bytes, so this is a 5.3× margin,
/// and a longer one (a long `Groups:` line pushes `NStgid:` past it)
/// costs only the pid (ADR-043, D8).
pub const STATUS_MAX: usize = 8192;

const _: () = assert!(INET_PROTOCOL_LAST == libc::IPPROTO_MPTCP as u32);

/// The selector of a key: which value of the row's field the call had.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Selector {
    /// The row has one key.
    Only,
    /// One value of the row's field: a syscall number, a family, a
    /// protocol, an ioctl number or an option.
    Value(u32),
    /// Two values: an IP family and a protocol, or a call and an option.
    Pair(u32, u32),
    /// Every value above the field's table.
    Other,
    /// Every value above the field's table for this family.
    OtherOf(u32),
}

/// What a record entry counts: a row and a selector (ADR-043, D6). The
/// key space is finite ([`KEY_SPACE`]), so every denied call is counted
/// in some entry and none is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    row: Row,
    selector: Selector,
}

fn low(args: &[u64; 6], i: usize) -> u32 {
    args[i] as u32
}

/// The syscalls a row keys by number.
fn whole_syscalls(row: Row) -> &'static [fn(&Syscalls) -> u32] {
    match row {
        Row::IoUring => &[
            |n| n.io_uring_setup,
            |n| n.io_uring_enter,
            |n| n.io_uring_register,
        ],
        Row::BpfUserfaultfdPerf => &[|n| n.bpf, |n| n.userfaultfd, |n| n.perf_event_open],
        Row::Keyring => &[|n| n.keyctl, |n| n.add_key, |n| n.request_key],
        Row::Syslog => &[|n| n.syslog],
        Row::NewUserNamespace => &[|n| n.clone, |n| n.unshare],
        _ => &[],
    }
}

fn inet_allowed(family: u32, protocol: u32) -> bool {
    matches!(protocol, IPPROTO_IP | IPPROTO_TCP | IPPROTO_UDP)
        || (family == AF_INET && protocol == IPPROTO_ICMP)
        || (family == AF_INET6 && protocol == IPPROTO_ICMPV6)
}

fn family_allowed(family: u32) -> bool {
    matches!(family, AF_UNIX | AF_INET | AF_INET6 | AF_NETLINK)
}

impl Key {
    /// The row.
    pub fn row(&self) -> Row {
        self.row
    }

    /// The selector.
    pub fn selector(&self) -> Selector {
        self.selector
    }

    /// The key of a call that `row` denied on `arch`. `None` when the
    /// call is not one the row denies, which the plain program's answer
    /// rules out; the supervisor then treats the evaluation as
    /// inconsistent (ADR-043, D4).
    pub fn of(arch: Arch, row: Row, data: &Data) -> Option<Key> {
        let n = arch.syscalls();
        let a = &data.args;
        let selector = match row {
            Row::ForeignArch => return None,
            Row::Ceiling => match data.nr {
                nr if nr <= CEILING => return None,
                nr if nr <= CEILING_KEYS_LAST => Selector::Value(nr),
                _ => Selector::Other,
            },
            Row::IoUring | Row::BpfUserfaultfdPerf | Row::Keyring | Row::Syslog => {
                whole_syscalls(row)
                    .iter()
                    .any(|f| f(n) == data.nr)
                    .then_some(Selector::Value(data.nr))?
            }
            Row::NewUserNamespace => {
                let named = whole_syscalls(row).iter().any(|f| f(n) == data.nr);
                (named && low(a, 0) & CLONE_NEWUSER != 0).then_some(Selector::Value(data.nr))?
            }
            Row::Clone3 => (data.nr == n.clone3).then_some(Selector::Only)?,
            Row::SocketFamily => {
                let f = low(a, 0);
                if data.nr != n.socket || family_allowed(f) {
                    return None;
                }
                if f < FAMILY_KEYS {
                    Selector::Value(f)
                } else {
                    Selector::Other
                }
            }
            Row::SockPacket => (data.nr == n.socket
                && low(a, 0) == AF_INET
                && SOCK_PACKET_TYPES.contains(&low(a, 1)))
            .then_some(Selector::Only)?,
            Row::NetlinkProtocol => {
                let p = low(a, 2);
                if data.nr != n.socket || low(a, 0) != AF_NETLINK || p == NETLINK_ROUTE {
                    return None;
                }
                if p < NETLINK_KEYS {
                    Selector::Value(p)
                } else {
                    Selector::Other
                }
            }
            Row::InetProtocol => {
                let (f, p) = (low(a, 0), low(a, 2));
                if data.nr != n.socket || !matches!(f, AF_INET | AF_INET6) || inet_allowed(f, p) {
                    return None;
                }
                if p <= INET_PROTOCOL_LAST {
                    Selector::Pair(f, p)
                } else {
                    Selector::OtherOf(f)
                }
            }
            Row::Socketpair => {
                let f = low(a, 0);
                if data.nr != n.socketpair || f == AF_UNIX {
                    return None;
                }
                if f < FAMILY_KEYS {
                    Selector::Value(f)
                } else {
                    Selector::Other
                }
            }
            Row::HugetlbMmap => {
                (data.nr == n.mmap && low(a, 3) & MAP_HUGETLB != 0).then_some(Selector::Only)?
            }
            Row::HugetlbShmget => {
                (data.nr == n.shmget && low(a, 2) & SHM_HUGETLB != 0).then_some(Selector::Only)?
            }
            Row::HugetlbMemfd => (data.nr == n.memfd_create && low(a, 1) & MFD_HUGETLB != 0)
                .then_some(Selector::Only)?,
            Row::LineDiscipline => {
                (data.nr == n.ioctl && low(a, 1) == TIOCSETD).then_some(Selector::Only)?
            }
            Row::ModuleIoctl => (data.nr == n.ioctl && MODULE_IOCTLS.contains(&low(a, 1)))
                .then_some(Selector::Value(low(a, 1)))?,
            Row::FsCryptoIoctl => (data.nr == n.ioctl && FS_CRYPTO_IOCTLS.contains(&low(a, 1)))
                .then_some(Selector::Value(low(a, 1)))?,
            Row::Ktls => {
                (data.nr == n.setsockopt && low(a, 1) == SOL_TLS).then_some(Selector::Only)?
            }
            Row::TcpSignature => (data.nr == n.setsockopt
                && low(a, 1) == IPPROTO_TCP
                && TCP_SIGNATURE_OPTIONS.contains(&low(a, 2)))
            .then_some(Selector::Value(low(a, 2)))?,
            Row::Bpfilter => {
                let (level, opt) = (low(a, 1), low(a, 2));
                let call = (data.nr == n.setsockopt && level == IPPROTO_IP)
                    || (data.nr == n.getsockopt && level != SOL_SOCKET);
                (call && (BPFILTER_OPTIONS.0..=BPFILTER_OPTIONS.1).contains(&opt))
                    .then_some(Selector::Pair(data.nr, opt))?
            }
        };
        Some(Key { row, selector })
    }

    /// Every key on `arch`, in table order: [`KEY_SPACE`] of them.
    pub fn all(arch: Arch) -> Vec<Key> {
        let n = arch.syscalls();
        let mut keys = Vec::with_capacity(KEY_SPACE);
        let mut push = |row: Row, selector: Selector| keys.push(Key { row, selector });
        for row in Row::ALL {
            match row {
                Row::ForeignArch => {}
                Row::Ceiling => {
                    for nr in CEILING + 1..=CEILING_KEYS_LAST {
                        push(row, Selector::Value(nr));
                    }
                    push(row, Selector::Other);
                }
                Row::IoUring
                | Row::BpfUserfaultfdPerf
                | Row::Keyring
                | Row::Syslog
                | Row::NewUserNamespace => {
                    for f in whole_syscalls(row) {
                        push(row, Selector::Value(f(n)));
                    }
                }
                Row::SocketFamily | Row::Socketpair => {
                    for f in 0..FAMILY_KEYS {
                        let allowed = match row {
                            Row::SocketFamily => family_allowed(f),
                            _ => f == AF_UNIX,
                        };
                        if !allowed {
                            push(row, Selector::Value(f));
                        }
                    }
                    push(row, Selector::Other);
                }
                Row::NetlinkProtocol => {
                    for p in NETLINK_ROUTE + 1..NETLINK_KEYS {
                        push(row, Selector::Value(p));
                    }
                    push(row, Selector::Other);
                }
                Row::InetProtocol => {
                    for f in [AF_INET, AF_INET6] {
                        for p in 0..=INET_PROTOCOL_LAST {
                            if !inet_allowed(f, p) {
                                push(row, Selector::Pair(f, p));
                            }
                        }
                        push(row, Selector::OtherOf(f));
                    }
                }
                Row::ModuleIoctl => {
                    for cmd in MODULE_IOCTLS {
                        push(row, Selector::Value(cmd));
                    }
                }
                Row::FsCryptoIoctl => {
                    for cmd in FS_CRYPTO_IOCTLS {
                        push(row, Selector::Value(cmd));
                    }
                }
                Row::TcpSignature => {
                    for opt in TCP_SIGNATURE_OPTIONS {
                        push(row, Selector::Value(opt));
                    }
                }
                Row::Bpfilter => {
                    for call in [n.setsockopt, n.getsockopt] {
                        for opt in BPFILTER_OPTIONS.0..=BPFILTER_OPTIONS.1 {
                            push(row, Selector::Pair(call, opt));
                        }
                    }
                }
                Row::Clone3
                | Row::SockPacket
                | Row::HugetlbMmap
                | Row::HugetlbShmget
                | Row::HugetlbMemfd
                | Row::LineDiscipline
                | Row::Ktls => push(row, Selector::Only),
            }
        }
        keys
    }
}

/// Why the supervisor stopped answering before its sandbox ended
/// (ADR-043, D4). The kernel then answers every pending and later
/// notified call with ENOSYS, so the calls stay denied; the record is
/// incomplete from that point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorFailure {
    /// The plain program did not deny a call the notifying program
    /// notified, or its answer named no row: the supervisor replied
    /// ENOSYS and stopped.
    Inconsistent {
        /// The syscall number.
        nr: u32,
        /// What the plain program returned.
        action: u32,
    },
    /// It was stopped while it held a call it had not answered.
    Stopped,
    /// It panicked.
    Panicked,
    /// A call on the listener failed other than the kernel's ENOENT for
    /// a caller that is gone.
    Sys {
        /// The call.
        call: &'static str,
        /// Its errno.
        errno: i32,
    },
}

/// One denied call as the supervisor saw it, before the record numbers
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    /// The time since spawn.
    pub since_spawn: Duration,
    /// The syscall number, raw.
    pub nr: u32,
    /// The six arguments, raw.
    pub args: [u64; 6],
    /// The errno the reply carried.
    pub errno: i32,
    /// The pid inside the sandbox, if `/proc` gave it.
    pub pid: Option<u32>,
    /// The comm, NUL-padded, if `/proc` gave it.
    pub comm: Option<[u8; 16]>,
}

/// The first occurrence of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Occurrence {
    /// Its number among every call the record noted, from 0.
    pub seq: u64,
    /// The call.
    pub call: Call,
}

/// One entry of the record: a key, how often it was denied and its first
/// occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denial {
    /// The row.
    pub row: Row,
    /// The key.
    pub key: Key,
    /// How many calls had this key, saturating at `u64::MAX`.
    pub count: u64,
    /// The first of them.
    pub first: Occurrence,
}

/// A snapshot of a sandbox's record (`Child::denials()`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Denials {
    entries: Vec<Denial>,
    unanswered: u64,
    failed: Option<SupervisorFailure>,
}

impl Denials {
    /// The entries, in the order their keys were first seen.
    pub fn entries(&self) -> &[Denial] {
        &self.entries
    }

    /// Notified calls whose caller was gone before the reply (the kernel's
    /// ENOENT on send): killed while blocked, not a failure.
    pub fn unanswered(&self) -> u64 {
        self.unanswered
    }

    /// Why the supervisor stopped early, if it did; a caller that needs the
    /// record complete treats `Some` as a failed run.
    pub fn failed(&self) -> Option<&SupervisorFailure> {
        self.failed.as_ref()
    }
}

/// The record a supervisor fills.
#[derive(Debug, Clone, Default)]
pub struct Record {
    entries: Vec<Denial>,
    index: BTreeMap<Key, usize>,
    next_seq: u64,
    unanswered: u64,
    failed: Option<SupervisorFailure>,
}

impl Record {
    /// An empty record.
    pub fn new() -> Record {
        Record::default()
    }

    /// Whether `key` has an entry already; the supervisor reads `/proc`
    /// only for a key's first occurrence.
    pub fn contains(&self, key: &Key) -> bool {
        self.index.contains_key(key)
    }

    /// Counts one denied call under `key`; the first call of a key is kept
    /// in full.
    pub fn note(&mut self, key: Key, call: Call) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        match self.index.get(&key) {
            Some(&i) => {
                let entry = &mut self.entries[i];
                entry.count = entry.count.saturating_add(1);
            }
            None => {
                self.index.insert(key, self.entries.len());
                self.entries.push(Denial {
                    row: key.row,
                    key,
                    count: 1,
                    first: Occurrence { seq, call },
                });
            }
        }
    }

    /// Counts a call whose caller was gone before the reply.
    pub fn note_unanswered(&mut self) {
        self.unanswered = self.unanswered.saturating_add(1);
    }

    /// Records why the supervisor stopped; the first failure is kept.
    pub fn fail(&mut self, failure: SupervisorFailure) {
        if self.failed.is_none() {
            self.failed = Some(failure);
        }
    }

    /// A copy of the record as it stands.
    pub fn snapshot(&self) -> Denials {
        Denials {
            entries: self.entries.clone(),
            unanswered: self.unanswered,
            failed: self.failed.clone(),
        }
    }
}

/// What [`parse_status`] read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Status {
    /// The last `NStgid:` field: the thread group id in the innermost PID
    /// namespace, which is what the caller's `getpid()` returns.
    pub pid: Option<u32>,
    /// The comm, the kernel's escaping undone, NUL-padded.
    pub comm: Option<[u8; 16]>,
}

/// Reads the inside pid and the comm from `/proc/<notif_pid>/status`
/// (ADR-043, D6). Only the first [`STATUS_MAX`] bytes count, and only
/// lines that end within them. Nothing is taken unless the file's `Pid:`
/// field equals `notif_pid`, so a procfs that shows another namespace's
/// process under that number gives nothing. The kernel escapes only `\n`
/// and `\` in `Name:` (`proc_task_name`, `fs/proc/array.c` in 5.19 and
/// 7.2), so no comm moves a line; any other escape, or a comm longer
/// than 15 bytes, gives no comm.
pub fn parse_status(bytes: &[u8], notif_pid: u32) -> Status {
    let window = &bytes[..bytes.len().min(STATUS_MAX)];
    let mut name = None;
    let mut pid_field = None;
    let mut nstgid = None;
    let mut rest = window;
    while let Some(end) = rest.iter().position(|b| *b == b'\n') {
        let line = &rest[..end];
        rest = &rest[end + 1..];
        if let Some(v) = line.strip_prefix(b"Name:\t") {
            name.get_or_insert(v);
        } else if let Some(v) = line.strip_prefix(b"Pid:\t") {
            pid_field.get_or_insert(v);
        } else if let Some(v) = line.strip_prefix(b"NStgid:\t") {
            nstgid.get_or_insert(v);
        }
    }
    if pid_field.and_then(decimal) != Some(notif_pid) {
        return Status::default();
    }
    Status {
        pid: nstgid.and_then(|v| v.split(|b| *b == b'\t').next_back().and_then(decimal)),
        comm: name.and_then(unescape_name),
    }
}

fn decimal(v: &[u8]) -> Option<u32> {
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

fn unescape_name(v: &[u8]) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut n = 0usize;
    let mut i = 0usize;
    while i < v.len() {
        let b = match (v[i], v.get(i + 1)) {
            (b'\\', Some(b'n')) => {
                i += 1;
                b'\n'
            }
            (b'\\', Some(b'\\')) => {
                i += 1;
                b'\\'
            }
            (b'\\', _) | (0, _) => return None,
            (b, _) => b,
        };
        i += 1;
        // TASK_COMM_LEN is 16 with the NUL.
        if n == 15 {
            return None;
        }
        out[n] = b;
        n += 1;
    }
    Some(out)
}

/// The bytes of a NUL-padded comm.
pub fn comm_bytes(comm: &[u8; 16]) -> &[u8] {
    let end = comm.iter().position(|b| *b == 0).unwrap_or(comm.len());
    &comm[..end]
}

/// Renders a comm as printable ASCII: every byte outside 0x20 to 0x7e,
/// and `\` and `"`, as `\xHH`, so a workload cannot put a line break, a
/// terminal escape or a bidirectional override into the report.
pub fn escape_comm(comm: &[u8]) -> String {
    let mut s = String::with_capacity(comm.len());
    for &b in comm {
        if (0x20..=0x7e).contains(&b) && b != b'\\' && b != b'"' {
            s.push(char::from(b));
        } else {
            let _ = write!(s, "\\x{b:02x}");
        }
    }
    s
}

// Decode tables. Each value the rows test is pinned to libc where libc
// has it and cites its uapi header otherwise (as `table.rs` does).

/// The socket families of Linux 7.2 (`include/linux/socket.h`), by
/// number.
const FAMILIES: [&str; FAMILY_KEYS as usize] = [
    "AF_UNSPEC",
    "AF_UNIX",
    "AF_INET",
    "AF_AX25",
    "AF_IPX",
    "AF_APPLETALK",
    "AF_NETROM",
    "AF_BRIDGE",
    "AF_ATMPVC",
    "AF_X25",
    "AF_INET6",
    "AF_ROSE",
    "AF_DECnet",
    "AF_NETBEUI",
    "AF_SECURITY",
    "AF_KEY",
    "AF_NETLINK",
    "AF_PACKET",
    "AF_ASH",
    "AF_ECONET",
    "AF_ATMSVC",
    "AF_RDS",
    "AF_SNA",
    "AF_IRDA",
    "AF_PPPOX",
    "AF_WANPIPE",
    "AF_LLC",
    "AF_IB",
    "AF_MPLS",
    "AF_CAN",
    "AF_TIPC",
    "AF_BLUETOOTH",
    "AF_IUCV",
    "AF_RXRPC",
    "AF_ISDN",
    "AF_PHONET",
    "AF_IEEE802154",
    "AF_CAIF",
    "AF_ALG",
    "AF_NFC",
    "AF_VSOCK",
    "AF_KCM",
    "AF_QIPCRTR",
    "AF_SMC",
    "AF_XDP",
    "AF_MCTP",
];

macro_rules! pin_families {
    ($($name:ident),* $(,)?) => {
        $(const _: () = assert!(
            konst_eq(FAMILIES[libc::$name as usize], stringify!($name))
        );)*
    };
}

const fn konst_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// libc 0.2.191 lacks AF_SMC (43) and AF_MCTP (45) and, for gnu
// targets, AF_KCM (41) and AF_QIPCRTR (42), and AF_MAX: the table
// cites the 7.2 header for them.
pin_families!(
    AF_UNSPEC,
    AF_UNIX,
    AF_INET,
    AF_AX25,
    AF_IPX,
    AF_APPLETALK,
    AF_NETROM,
    AF_BRIDGE,
    AF_ATMPVC,
    AF_X25,
    AF_INET6,
    AF_ROSE,
    AF_DECnet,
    AF_NETBEUI,
    AF_SECURITY,
    AF_KEY,
    AF_NETLINK,
    AF_PACKET,
    AF_ASH,
    AF_ECONET,
    AF_ATMSVC,
    AF_RDS,
    AF_SNA,
    AF_IRDA,
    AF_PPPOX,
    AF_WANPIPE,
    AF_LLC,
    AF_IB,
    AF_MPLS,
    AF_CAN,
    AF_TIPC,
    AF_BLUETOOTH,
    AF_IUCV,
    AF_RXRPC,
    AF_ISDN,
    AF_PHONET,
    AF_IEEE802154,
    AF_CAIF,
    AF_ALG,
    AF_NFC,
    AF_VSOCK,
    AF_XDP,
);

/// The socket types (`include/linux/net.h`); `SOCK_PACKET` is the one
/// the SockPacket row tests.
const SOCK_TYPES: [(u32, &str); 7] = [
    (1, "SOCK_STREAM"),
    (2, "SOCK_DGRAM"),
    (3, "SOCK_RAW"),
    (4, "SOCK_RDM"),
    (5, "SOCK_SEQPACKET"),
    (6, "SOCK_DCCP"),
    (SOCK_PACKET, "SOCK_PACKET"),
];

const _: () = assert!(SOCK_TYPES[0].0 == libc::SOCK_STREAM as u32);
const _: () = assert!(SOCK_TYPES[1].0 == libc::SOCK_DGRAM as u32);
const _: () = assert!(SOCK_TYPES[2].0 == libc::SOCK_RAW as u32);
const _: () = assert!(SOCK_TYPES[3].0 == libc::SOCK_RDM as u32);
const _: () = assert!(SOCK_TYPES[4].0 == libc::SOCK_SEQPACKET as u32);
const _: () = assert!(SOCK_TYPES[5].0 == libc::SOCK_DCCP as u32);

/// The namespace flags of `clone` and `unshare`
/// (`include/uapi/linux/sched.h`), highest first; `CLONE_NEWUSER` is the
/// one the NewUserNamespace row tests. `CLONE_NEWTIME` (0x80) is left to
/// the hex remainder: for `clone` that bit is part of the exit signal.
const CLONE_NAMESPACES: [(u64, &str); 7] = [
    (libc::CLONE_NEWNET as u64, "CLONE_NEWNET"),
    (libc::CLONE_NEWPID as u64, "CLONE_NEWPID"),
    (libc::CLONE_NEWUSER as u64, "CLONE_NEWUSER"),
    (libc::CLONE_NEWIPC as u64, "CLONE_NEWIPC"),
    (libc::CLONE_NEWUTS as u64, "CLONE_NEWUTS"),
    (libc::CLONE_NEWCGROUP as u64, "CLONE_NEWCGROUP"),
    (libc::CLONE_NEWNS as u64, "CLONE_NEWNS"),
];

/// The huge page size field shared by `mmap`, `shmget` and
/// `memfd_create` (`include/uapi/asm-generic/hugetlb_encode.h`): log2 of
/// the size in bits 26 to 31. libc lacks `SHM_HUGE_SHIFT`; all three are
/// `HUGETLB_FLAG_ENCODE_SHIFT`.
const HUGE_SHIFT: u32 = 26;
const HUGE_MASK: u64 = 0x3f;

const _: () = assert!(HUGE_SHIFT == libc::MAP_HUGE_SHIFT as u32);
const _: () = assert!(HUGE_SHIFT == libc::MFD_HUGE_SHIFT);
const _: () = assert!((21 << HUGE_SHIFT) == libc::MAP_HUGE_2MB as u32);

/// The ioctl numbers the rows test.
const IOCTLS: [(u32, &str); 12] = [
    (TIOCSETD, "TIOCSETD"),
    (SIOCGIFBR, "SIOCGIFBR"),
    (SIOCSIFBR, "SIOCSIFBR"),
    (SIOCGIFVLAN, "SIOCGIFVLAN"),
    (SIOCSIFVLAN, "SIOCSIFVLAN"),
    (SIOCBRADDBR, "SIOCBRADDBR"),
    (SIOCBRDELBR, "SIOCBRDELBR"),
    (SIOCBRADDIF, "SIOCBRADDIF"),
    (SIOCBRDELIF, "SIOCBRDELIF"),
    (FS_IOC_ADD_ENCRYPTION_KEY, "FS_IOC_ADD_ENCRYPTION_KEY"),
    (FS_IOC_SET_ENCRYPTION_POLICY, "FS_IOC_SET_ENCRYPTION_POLICY"),
    (FS_IOC_ENABLE_VERITY, "FS_IOC_ENABLE_VERITY"),
];

/// Socket option levels: the ones the rows test (`SOL_SOCKET`,
/// `IPPROTO_IP`, `IPPROTO_TCP`, `SOL_TLS`) and the IP levels that reach
/// the getsockopt half of the Bpfilter row (`ip_getsockopt`).
const LEVELS: [(u32, &str); 6] = [
    (0, "SOL_IP"),
    (1, "SOL_SOCKET"),
    (6, "SOL_TCP"),
    (17, "SOL_UDP"),
    (41, "SOL_IPV6"),
    (SOL_TLS, "SOL_TLS"),
];

const _: () = assert!(LEVELS[0].0 == libc::SOL_IP as u32);
const _: () = assert!(LEVELS[1].0 == libc::SOL_SOCKET as u32);
const _: () = assert!(LEVELS[2].0 == libc::SOL_TCP as u32);
const _: () = assert!(LEVELS[3].0 == libc::SOL_UDP as u32);
const _: () = assert!(LEVELS[4].0 == libc::SOL_IPV6 as u32);

/// `SOL_TLS` options (`include/uapi/linux/tls.h`, 7.2); libc 0.2.191
/// lacks them.
const TLS_OPTIONS: [(u32, &str); 5] = [
    (1, "TLS_TX"),
    (2, "TLS_RX"),
    (3, "TLS_TX_ZEROCOPY_RO"),
    (4, "TLS_RX_EXPECT_NO_PAD"),
    (5, "TLS_TX_MAX_PAYLOAD_LEN"),
];

/// The TCP signature options.
const TCP_OPTIONS: [(u32, &str); 3] = [
    (TCP_MD5SIG, "TCP_MD5SIG"),
    (TCP_MD5SIG_EXT, "TCP_MD5SIG_EXT"),
    (TCP_AO_ADD_KEY, "TCP_AO_ADD_KEY"),
];

/// Options 64 to 67 at `SOL_IPV6` (ip6tables' two queries,
/// `include/uapi/linux/netfilter_ipv6/ip6_tables.h`, and the traffic
/// class pair, `include/uapi/linux/in6.h`).
const IPV6_OPTIONS: [&str; 4] = [
    "IP6T_SO_GET_INFO",
    "IP6T_SO_GET_ENTRIES",
    "IPV6_RECVTCLASS",
    "IPV6_TCLASS",
];

const _: () = assert!(libc::IPV6_RECVTCLASS == 66);
const _: () = assert!(libc::IPV6_TCLASS == 67);

/// Options 64 to 67 elsewhere, as bpfilter names them
/// (`include/uapi/linux/bpfilter.h` in 5.19): the setsockopt pair and the
/// four getsockopt queries.
const BPFILTER_SET: [&str; 2] = [
    "BPFILTER_IPT_SO_SET_REPLACE",
    "BPFILTER_IPT_SO_SET_ADD_COUNTERS",
];
const BPFILTER_GET: [&str; 4] = [
    "BPFILTER_IPT_SO_GET_INFO",
    "BPFILTER_IPT_SO_GET_ENTRIES",
    "BPFILTER_IPT_SO_GET_REVISION_MATCH",
    "BPFILTER_IPT_SO_GET_REVISION_TARGET",
];

/// The errno names of the rows.
fn errno_name(errno: i32) -> String {
    match errno {
        libc::EPERM => "EPERM".into(),
        libc::ENOSYS => "ENOSYS".into(),
        libc::EAFNOSUPPORT => "EAFNOSUPPORT".into(),
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT".into(),
        ENOPROTOOPT => "ENOPROTOOPT".into(),
        other => format!("errno {other}"),
    }
}

fn lookup(table: &[(u32, &'static str)], v: u32) -> Option<&'static str> {
    table.iter().find(|(k, _)| *k == v).map(|(_, name)| *name)
}

/// An int argument: its name from `table`, else the low word as a signed
/// number (the kernel reads an `int`).
fn int_arg(table: &[(u32, &'static str)], v: u32) -> String {
    lookup(table, v).map_or_else(|| (v as i32).to_string(), str::to_string)
}

fn family(v: u32) -> String {
    FAMILIES
        .get(v as usize)
        .map_or_else(|| (v as i32).to_string(), |s| (*s).to_string())
}

/// Flags: the named bits, then the huge page size if `huge` is set and
/// the field holds one, then the rest in hex; `0` when nothing is set.
fn flags(value: u64, named: &[(u64, &str)], huge: Option<(u64, &str)>) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut rest = value;
    for (bit, name) in named {
        if rest & bit != 0 {
            parts.push((*name).to_string());
            rest &= !bit;
        }
    }
    if let Some((huge_bit, prefix)) = huge
        && value & huge_bit != 0
    {
        let log2 = (rest >> HUGE_SHIFT) & HUGE_MASK;
        if log2 != 0 {
            let (scale, unit) = match log2 {
                30.. => (log2 - 30, "GB"),
                20.. => (log2 - 20, "MB"),
                10.. => (log2 - 10, "KB"),
                _ => (log2, "B"),
            };
            parts.push(format!("{prefix}_HUGE_{}{unit}", 1u64 << scale));
            rest &= !(HUGE_MASK << HUGE_SHIFT);
        }
    }
    if rest != 0 || parts.is_empty() {
        parts.push(format!("{rest:#x}"));
    }
    parts.join("|")
}

fn socket_type(v: u32) -> String {
    let named = lookup(&SOCK_TYPES, v & 0xf);
    let mut parts: Vec<String> = Vec::new();
    let mut rest = v;
    if let Some(name) = named {
        parts.push(name.to_string());
        rest &= !0xf;
    }
    for (bit, name) in [
        (SOCK_NONBLOCK, "SOCK_NONBLOCK"),
        (SOCK_CLOEXEC, "SOCK_CLOEXEC"),
    ] {
        if rest & bit != 0 {
            parts.push(name.to_string());
            rest &= !bit;
        }
    }
    if rest != 0 || parts.is_empty() {
        parts.push(format!("{rest:#x}"));
    }
    parts.join("|")
}

fn option(level: u32, opt: u32, setsockopt: bool) -> String {
    let in_range = (BPFILTER_OPTIONS.0..=BPFILTER_OPTIONS.1).contains(&opt);
    let i = opt.wrapping_sub(BPFILTER_OPTIONS.0) as usize;
    let name = match level {
        SOL_TLS => lookup(&TLS_OPTIONS, opt),
        IPPROTO_TCP if setsockopt => lookup(&TCP_OPTIONS, opt),
        41 if in_range => IPV6_OPTIONS.get(i).copied(),
        _ if in_range && setsockopt => BPFILTER_SET.get(i).copied(),
        _ if in_range => BPFILTER_GET.get(i).copied(),
        _ => None,
    };
    name.map_or_else(|| (opt as i32).to_string(), str::to_string)
}

/// The name of a syscall the rows name, by number.
pub fn syscall_name(arch: Arch, nr: u32) -> Option<&'static str> {
    let n = arch.syscalls();
    let names: [(u32, &'static str); 21] = [
        (n.io_uring_setup, "io_uring_setup"),
        (n.io_uring_enter, "io_uring_enter"),
        (n.io_uring_register, "io_uring_register"),
        (n.bpf, "bpf"),
        (n.userfaultfd, "userfaultfd"),
        (n.perf_event_open, "perf_event_open"),
        (n.add_key, "add_key"),
        (n.request_key, "request_key"),
        (n.keyctl, "keyctl"),
        (n.syslog, "syslog"),
        (n.clone, "clone"),
        (n.unshare, "unshare"),
        (n.clone3, "clone3"),
        (n.socket, "socket"),
        (n.socketpair, "socketpair"),
        (n.mmap, "mmap"),
        (n.shmget, "shmget"),
        (n.memfd_create, "memfd_create"),
        (n.ioctl, "ioctl"),
        (n.setsockopt, "setsockopt"),
        (n.getsockopt, "getsockopt"),
    ];
    lookup(&names, nr)
}

/// The call with the arguments `row` tests, decoded: names from the
/// tables above, other values as numbers, flags with the unknown
/// remainder in hex. Pointer arguments are never shown or read.
pub fn describe_call(arch: Arch, row: Row, nr: u32, args: &[u64; 6]) -> String {
    let name = syscall_name(arch, nr).unwrap_or("syscall");
    let a = |i: usize| low(args, i);
    match row {
        Row::ForeignArch | Row::Ceiling => format!("syscall(nr={})", nr as i32),
        Row::IoUring | Row::BpfUserfaultfdPerf | Row::Keyring | Row::Syslog | Row::Clone3 => {
            format!("{name}()")
        }
        Row::NewUserNamespace => {
            format!("{name}(flags={})", flags(args[0], &CLONE_NAMESPACES, None))
        }
        Row::SocketFamily
        | Row::SockPacket
        | Row::NetlinkProtocol
        | Row::InetProtocol
        | Row::Socketpair => format!(
            "{name}(domain={}, type={}, protocol={})",
            family(a(0)),
            socket_type(a(1)),
            a(2) as i32
        ),
        Row::HugetlbMmap => format!(
            "{name}(flags={})",
            flags(
                args[3],
                &[(MAP_HUGETLB.into(), "MAP_HUGETLB")],
                Some((MAP_HUGETLB.into(), "MAP"))
            )
        ),
        Row::HugetlbShmget => format!(
            "{name}(shmflg={})",
            flags(
                args[2],
                &[(SHM_HUGETLB.into(), "SHM_HUGETLB")],
                Some((SHM_HUGETLB.into(), "SHM"))
            )
        ),
        Row::HugetlbMemfd => format!(
            "{name}(flags={})",
            flags(
                args[1],
                &[(MFD_HUGETLB.into(), "MFD_HUGETLB")],
                Some((MFD_HUGETLB.into(), "MFD"))
            )
        ),
        Row::LineDiscipline | Row::ModuleIoctl | Row::FsCryptoIoctl => {
            let cmd = a(1);
            let cmd = lookup(&IOCTLS, cmd).map_or_else(|| format!("{cmd:#x}"), str::to_string);
            format!("{name}(cmd={cmd})")
        }
        Row::Ktls | Row::TcpSignature | Row::Bpfilter => {
            let setsockopt = nr == arch.syscalls().setsockopt;
            format!(
                "{name}(level={}, optname={})",
                int_arg(&LEVELS, a(1)),
                option(a(1), a(2), setsockopt)
            )
        }
    }
}

impl Denial {
    /// One ASCII line: the call, the errno and row, the count, and the
    /// first occurrence's time, pid and comm (`?` where unknown).
    pub fn render(&self, arch: Arch) -> String {
        let call = &self.first.call;
        let t = call.since_spawn;
        let pid = call.pid.map_or_else(|| "?".to_string(), |p| p.to_string());
        let comm = call.comm.as_ref().map_or_else(
            || "?".to_string(),
            |c| format!("\"{}\"", escape_comm(comm_bytes(c))),
        );
        let mut line = format!(
            "{} -> {}, row {:?}, {} call{}, first at +{}.{:03}s, pid {pid}, comm {comm}",
            describe_call(arch, self.row, call.nr, &call.args),
            errno_name(call.errno),
            self.row,
            self.count,
            if self.count == 1 { "" } else { "s" },
            t.as_secs(),
            t.subsec_millis(),
        );
        if self.row == Row::Clone3 {
            line.push_str(
                "; libc falls back to clone, where the NewUserNamespace row sees the flags",
            );
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_saturates() {
        let key = Key {
            row: Row::Clone3,
            selector: Selector::Only,
        };
        let call = Call {
            since_spawn: Duration::ZERO,
            nr: 435,
            args: [0; 6],
            errno: libc::ENOSYS,
            pid: None,
            comm: None,
        };
        let mut r = Record::new();
        r.note(key, call);
        r.entries[0].count = u64::MAX - 1;
        r.note(key, call);
        r.note(key, call);
        assert_eq!(r.snapshot().entries()[0].count, u64::MAX);
        r.next_seq = u64::MAX;
        r.note(key, call);
        assert_eq!(r.next_seq, u64::MAX);
    }
}
