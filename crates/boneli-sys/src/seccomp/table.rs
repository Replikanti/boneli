//! The syscall numbers and argument flags the seccomp policy names, per
//! architecture (ADR-007, D2), from the Linux 7.2.4 uapi headers
//! (`arch/x86/include/uapi/asm/unistd_64.h` for x86_64, the generic table
//! `include/uapi/asm-generic/unistd.h` as arm64 builds it for aarch64).
//! Every number is pinned to `libc::SYS_*` at compile time for the build's
//! own architecture; CI's `cargo check` for `aarch64-unknown-linux-musl`
//! evaluates the aarch64 assertions.

/// The highest syscall number in the reviewed tables (`rseq_slice_yield`,
/// 471 on both architectures). Larger numbers fail with ENOSYS.
pub const CEILING: u32 = 471;

/// `AUDIT_ARCH_X86_64`, `include/uapi/linux/audit.h`: `EM_X86_64` (62) |
/// `__AUDIT_ARCH_64BIT` | `__AUDIT_ARCH_LE`.
pub const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;

/// `AUDIT_ARCH_AARCH64`, `include/uapi/linux/audit.h`: `EM_AARCH64` (183)
/// | `__AUDIT_ARCH_64BIT` | `__AUDIT_ARCH_LE`.
pub const AUDIT_ARCH_AARCH64: u32 = 183 | 0x8000_0000 | 0x4000_0000;

/// `MAP_HUGETLB`, the same on both architectures
/// (`include/uapi/asm-generic/mman-common.h` via `mman.h`, and x86's).
pub const MAP_HUGETLB: u32 = 0x4_0000;
/// `SHM_HUGETLB`, `include/uapi/linux/shm.h` (octal 04000).
pub const SHM_HUGETLB: u32 = 0o4000;
/// `MFD_HUGETLB`, `include/uapi/linux/memfd.h`.
pub const MFD_HUGETLB: u32 = 0x4;
/// `CLONE_NEWUSER`, `include/uapi/linux/sched.h`.
pub const CLONE_NEWUSER: u32 = 0x1000_0000;
/// The socket families the policy allows (`include/linux/socket.h`):
/// `AF_UNIX`, `AF_INET`, `AF_INET6`, `AF_NETLINK`.
pub const AF_UNIX: u32 = 1;
/// `AF_INET`.
pub const AF_INET: u32 = 2;
/// `AF_INET6`.
pub const AF_INET6: u32 = 10;
/// `AF_NETLINK`.
pub const AF_NETLINK: u32 = 16;
/// `NETLINK_ROUTE`, `include/uapi/linux/netlink.h`: the one netlink
/// protocol the policy allows.
pub const NETLINK_ROUTE: u32 = 0;
/// The IP protocols the policy allows for `AF_INET` and `AF_INET6`
/// (`include/uapi/linux/in.h`, `in6.h`): `IPPROTO_IP` (0, the type's
/// default), `IPPROTO_TCP`, `IPPROTO_UDP`, and each family's ICMP for
/// unprivileged ping sockets.
pub const IPPROTO_IP: u32 = 0;
/// `IPPROTO_ICMP`, IPv4 only.
pub const IPPROTO_ICMP: u32 = 1;
/// `IPPROTO_TCP`.
pub const IPPROTO_TCP: u32 = 6;
/// `IPPROTO_UDP`.
pub const IPPROTO_UDP: u32 = 17;
/// `IPPROTO_ICMPV6`, IPv6 only.
pub const IPPROTO_ICMPV6: u32 = 58;
/// `TIOCSETD`, `include/uapi/asm-generic/ioctls.h` (x86 and arm64 both
/// use the generic numbers): sets a tty's line discipline.
pub const TIOCSETD: u32 = 0x5423;

const _: () = assert!(MAP_HUGETLB == libc::MAP_HUGETLB as u32);
const _: () = assert!(SHM_HUGETLB == libc::SHM_HUGETLB as u32);
const _: () = assert!(MFD_HUGETLB == libc::MFD_HUGETLB);
const _: () = assert!(CLONE_NEWUSER == libc::CLONE_NEWUSER as u32);
const _: () = assert!(AF_UNIX == libc::AF_UNIX as u32);
const _: () = assert!(AF_INET == libc::AF_INET as u32);
const _: () = assert!(AF_INET6 == libc::AF_INET6 as u32);
const _: () = assert!(AF_NETLINK == libc::AF_NETLINK as u32);
const _: () = assert!(NETLINK_ROUTE == libc::NETLINK_ROUTE as u32);
const _: () = assert!(IPPROTO_IP == libc::IPPROTO_IP as u32);
const _: () = assert!(IPPROTO_ICMP == libc::IPPROTO_ICMP as u32);
const _: () = assert!(IPPROTO_TCP == libc::IPPROTO_TCP as u32);
const _: () = assert!(IPPROTO_UDP == libc::IPPROTO_UDP as u32);
const _: () = assert!(IPPROTO_ICMPV6 == libc::IPPROTO_ICMPV6 as u32);
const _: () = assert!(TIOCSETD == libc::TIOCSETD as u32);

/// An architecture the policy has a table for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// x86_64 (not x32, not i386).
    X86_64,
    /// aarch64 (not AArch32).
    Aarch64,
}

impl Arch {
    /// Both architectures.
    pub const ALL: [Arch; 2] = [Arch::X86_64, Arch::Aarch64];

    /// The architecture this crate is built for.
    #[cfg(target_arch = "x86_64")]
    pub const NATIVE: Arch = Arch::X86_64;
    /// The architecture this crate is built for.
    #[cfg(target_arch = "aarch64")]
    pub const NATIVE: Arch = Arch::Aarch64;

    /// The value of `seccomp_data.arch` for this architecture.
    pub fn audit_arch(self) -> u32 {
        match self {
            Arch::X86_64 => AUDIT_ARCH_X86_64,
            Arch::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    /// The numbers of the syscalls the policy names.
    pub fn syscalls(self) -> &'static Syscalls {
        match self {
            Arch::X86_64 => &X86_64,
            Arch::Aarch64 => &AARCH64,
        }
    }

    /// The name used in messages and in the census file names.
    pub fn name(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }
}

/// The numbers of the syscalls the policy's rows name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Syscalls {
    /// `io_uring_setup`.
    pub io_uring_setup: u32,
    /// `io_uring_enter`.
    pub io_uring_enter: u32,
    /// `io_uring_register`.
    pub io_uring_register: u32,
    /// `bpf`.
    pub bpf: u32,
    /// `userfaultfd`.
    pub userfaultfd: u32,
    /// `perf_event_open`.
    pub perf_event_open: u32,
    /// `add_key`.
    pub add_key: u32,
    /// `request_key`.
    pub request_key: u32,
    /// `keyctl`.
    pub keyctl: u32,
    /// `syslog`.
    pub syslog: u32,
    /// `clone`.
    pub clone: u32,
    /// `unshare`.
    pub unshare: u32,
    /// `clone3`.
    pub clone3: u32,
    /// `socket`.
    pub socket: u32,
    /// `socketpair`.
    pub socketpair: u32,
    /// `mmap`.
    pub mmap: u32,
    /// `shmget`.
    pub shmget: u32,
    /// `memfd_create`.
    pub memfd_create: u32,
    /// `ioctl`.
    pub ioctl: u32,
}

/// x86_64, `arch/x86/include/uapi/asm/unistd_64.h` (7.2.4).
pub const X86_64: Syscalls = Syscalls {
    io_uring_setup: 425,
    io_uring_enter: 426,
    io_uring_register: 427,
    bpf: 321,
    userfaultfd: 323,
    perf_event_open: 298,
    add_key: 248,
    request_key: 249,
    keyctl: 250,
    syslog: 103,
    clone: 56,
    unshare: 272,
    clone3: 435,
    socket: 41,
    socketpair: 53,
    mmap: 9,
    shmget: 29,
    memfd_create: 319,
    ioctl: 16,
};

/// aarch64, `include/uapi/asm-generic/unistd.h` as arm64 builds it (7.2.4).
pub const AARCH64: Syscalls = Syscalls {
    io_uring_setup: 425,
    io_uring_enter: 426,
    io_uring_register: 427,
    bpf: 280,
    userfaultfd: 282,
    perf_event_open: 241,
    add_key: 217,
    request_key: 218,
    keyctl: 219,
    syslog: 116,
    clone: 220,
    unshare: 97,
    clone3: 435,
    socket: 198,
    socketpair: 199,
    mmap: 222,
    shmget: 194,
    memfd_create: 279,
    ioctl: 29,
};

/// The build's own table.
#[cfg(target_arch = "x86_64")]
const NATIVE: Syscalls = X86_64;
/// The build's own table.
#[cfg(target_arch = "aarch64")]
const NATIVE: Syscalls = AARCH64;

macro_rules! pin {
    ($($field:ident => $sys:ident),* $(,)?) => {
        $(const _: () = assert!(NATIVE.$field as libc::c_long == libc::$sys);)*
    };
}

pin! {
    io_uring_setup => SYS_io_uring_setup,
    io_uring_enter => SYS_io_uring_enter,
    io_uring_register => SYS_io_uring_register,
    bpf => SYS_bpf,
    userfaultfd => SYS_userfaultfd,
    perf_event_open => SYS_perf_event_open,
    add_key => SYS_add_key,
    request_key => SYS_request_key,
    keyctl => SYS_keyctl,
    syslog => SYS_syslog,
    clone => SYS_clone,
    unshare => SYS_unshare,
    clone3 => SYS_clone3,
    socket => SYS_socket,
    socketpair => SYS_socketpair,
    mmap => SYS_mmap,
    shmget => SYS_shmget,
    memfd_create => SYS_memfd_create,
    ioctl => SYS_ioctl,
}
