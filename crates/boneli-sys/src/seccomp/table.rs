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
/// The socket ioctls whose handler asks for a module by name
/// (`include/uapi/linux/sockios.h`, the same on both architectures):
/// `SIOCGIFBR`, `SIOCSIFBR`, `SIOCBRADDBR`, `SIOCBRDELBR`, `SIOCBRADDIF`
/// and `SIOCBRDELIF` reach `br_ioctl_call`, which loads `bridge`;
/// `SIOCGIFVLAN` and `SIOCSIFVLAN` load `8021q` (`sock_ioctl`,
/// `net/socket.c` in Linux 7.2).
pub const MODULE_IOCTLS: [u32; 8] = [
    SIOCGIFBR,
    SIOCSIFBR,
    SIOCGIFVLAN,
    SIOCSIFVLAN,
    SIOCBRADDBR,
    SIOCBRDELBR,
    SIOCBRADDIF,
    SIOCBRDELIF,
];
/// `SIOCGIFBR`.
pub const SIOCGIFBR: u32 = 0x8940;
/// `SIOCSIFBR`.
pub const SIOCSIFBR: u32 = 0x8941;
/// `SIOCGIFVLAN`; libc 0.2.191 defines it for Android only.
pub const SIOCGIFVLAN: u32 = 0x8982;
/// `SIOCSIFVLAN`, likewise.
pub const SIOCSIFVLAN: u32 = 0x8983;
/// `SIOCBRADDBR`, likewise.
pub const SIOCBRADDBR: u32 = 0x89a0;
/// `SIOCBRDELBR`, likewise.
pub const SIOCBRDELBR: u32 = 0x89a1;
/// `SIOCBRADDIF`, likewise.
pub const SIOCBRADDIF: u32 = 0x89a2;
/// `SIOCBRDELIF`, likewise.
pub const SIOCBRDELIF: u32 = 0x89a3;
/// `SOCK_PACKET` (`include/linux/net.h`): `__sock_create` turns
/// `socket(AF_INET, SOCK_PACKET, ...)` into a `PF_PACKET` socket. libc
/// 0.2.191 defines it for Android and uclibc only.
pub const SOCK_PACKET: u32 = 10;
/// `SOCK_NONBLOCK` and `SOCK_CLOEXEC`, the only flags `socket` accepts
/// beside the type (`__sys_socket_create`); `O_NONBLOCK` and `O_CLOEXEC`
/// on both architectures.
pub const SOCK_NONBLOCK: u32 = 0x800;
/// `SOCK_CLOEXEC`.
pub const SOCK_CLOEXEC: u32 = 0x8_0000;
/// Every `type` argument `socket` accepts as `SOCK_PACKET`: the type with
/// each combination of the two flags. Any other value with type 10 in its
/// low four bits fails with EINVAL before the family is looked at.
pub const SOCK_PACKET_TYPES: [u32; 4] = [
    SOCK_PACKET,
    SOCK_PACKET | SOCK_NONBLOCK,
    SOCK_PACKET | SOCK_CLOEXEC,
    SOCK_PACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
];

/// `ENOPROTOOPT`, `include/uapi/asm-generic/errno.h` (the same on both
/// architectures): what a socket answers for a level or option it lacks,
/// and the answer of the kTLS and TCP signature rows.
pub const ENOPROTOOPT: i32 = 92;
/// `SOL_TLS`, `include/linux/socket.h`: the socket level of kTLS.
pub const SOL_TLS: u32 = 282;
/// `TCP_MD5SIG`, `include/uapi/linux/tcp.h`: an RFC 2385 key.
pub const TCP_MD5SIG: u32 = 14;
/// `TCP_MD5SIG_EXT`, likewise, with prefix and interface.
pub const TCP_MD5SIG_EXT: u32 = 32;
/// `TCP_AO_ADD_KEY`, `include/uapi/linux/tcp.h` (7.2.4): an RFC 5925
/// key, with the algorithm named by the caller. libc 0.2.191 lacks it.
pub const TCP_AO_ADD_KEY: u32 = 38;
/// The first and last option numbers at `IPPROTO_IP` (`SOL_IP`) that
/// kernels from 5.19 until bpfilter's removal (it is gone in 6.12) hand
/// to bpfilter before any capability check
/// (`ip_setsockopt` and `ip_getsockopt` with `CONFIG_BPFILTER_UMH`:
/// `BPFILTER_IPT_SO_SET_REPLACE` 64 to `BPFILTER_IPT_SO_GET_REVISION_TARGET`
/// 67, `include/uapi/linux/bpfilter.h` in 5.19), which loads the
/// `bpfilter` module; iptables uses the same numbers.
pub const BPFILTER_OPTIONS: (u32, u32) = (64, 67);
/// The TCP options that set a signature key.
pub const TCP_SIGNATURE_OPTIONS: [u32; 3] = [TCP_MD5SIG, TCP_MD5SIG_EXT, TCP_AO_ADD_KEY];
/// `FS_IOC_ADD_ENCRYPTION_KEY`, `include/uapi/linux/fscrypt.h`:
/// `_IOWR('f', 23, struct fscrypt_add_key_arg)`, 80 bytes. libc 0.2.191
/// lacks it, as it lacks the two below.
pub const FS_IOC_ADD_ENCRYPTION_KEY: u32 = ioc(3, b'f' as u32, 23, 80);
/// `FS_IOC_SET_ENCRYPTION_POLICY`, likewise: `_IOR('f', 19, struct
/// fscrypt_policy_v1)`, 12 bytes (the uapi header's direction).
pub const FS_IOC_SET_ENCRYPTION_POLICY: u32 = ioc(2, b'f' as u32, 19, 12);
/// `FS_IOC_ENABLE_VERITY`, `include/uapi/linux/fsverity.h`: `_IOW('f',
/// 133, struct fsverity_enable_arg)`, 128 bytes.
pub const FS_IOC_ENABLE_VERITY: u32 = ioc(1, b'f' as u32, 133, 128);
/// The file-system crypto ioctls the policy refuses.
pub const FS_CRYPTO_IOCTLS: [u32; 3] = [
    FS_IOC_ADD_ENCRYPTION_KEY,
    FS_IOC_SET_ENCRYPTION_POLICY,
    FS_IOC_ENABLE_VERITY,
];

/// An ioctl number in the encoding x86 and arm64 share
/// (`include/uapi/asm-generic/ioctl.h`): the direction in bits 30-31
/// (`_IOC_WRITE` 1, `_IOC_READ` 2), the argument size in bits 16-29, the
/// type in bits 8-15 and the number in bits 0-7.
pub const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | (ty << 8) | nr
}

const _: () = assert!(FS_IOC_ADD_ENCRYPTION_KEY == 0xc050_6617);
const _: () = assert!(FS_IOC_SET_ENCRYPTION_POLICY == 0x800c_6613);
const _: () = assert!(FS_IOC_ENABLE_VERITY == 0x4080_6685);
const _: () = assert!(ENOPROTOOPT == libc::ENOPROTOOPT);
const _: () = assert!(SOL_TLS == libc::SOL_TLS as u32);
const _: () = assert!(TCP_MD5SIG == libc::TCP_MD5SIG as u32);
const _: () = assert!(TCP_MD5SIG_EXT == libc::TCP_MD5SIG_EXT as u32);
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
const _: () = assert!(SIOCGIFBR == libc::SIOCGIFBR as u32);
const _: () = assert!(SIOCSIFBR == libc::SIOCSIFBR as u32);
const _: () = assert!(SOCK_NONBLOCK == libc::SOCK_NONBLOCK as u32);
const _: () = assert!(SOCK_CLOEXEC == libc::SOCK_CLOEXEC as u32);

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
    /// `setsockopt`.
    pub setsockopt: u32,
    /// `getsockopt`.
    pub getsockopt: u32,
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
    setsockopt: 54,
    getsockopt: 55,
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
    setsockopt: 208,
    getsockopt: 209,
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
    setsockopt => SYS_setsockopt,
    getsockopt => SYS_getsockopt,
}
