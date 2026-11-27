//! The sandbox's seccomp policy (ADR-007, D2): one fixed table of deny
//! rows over an allow default, assembled into a classic BPF program in the
//! parent before the clone.

use super::bpf::{self, AsmError, Insn, Label, Op, Target};
use super::table::{
    AF_INET, AF_INET6, AF_NETLINK, AF_UNIX, Arch, BPFILTER_OPTIONS, CEILING, CLONE_NEWUSER,
    ENOPROTOOPT as ENOPROTOOPT_ERRNO, FS_CRYPTO_IOCTLS, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IP,
    IPPROTO_TCP, IPPROTO_UDP, MAP_HUGETLB, MFD_HUGETLB, MODULE_IOCTLS, NETLINK_ROUTE, SHM_HUGETLB,
    SOCK_PACKET_TYPES, SOL_TLS, TCP_SIGNATURE_OPTIONS, TIOCSETD,
};

/// Offsets into `struct seccomp_data` (`include/uapi/linux/seccomp.h`):
/// `nr` at 0, `arch` at 4, `instruction_pointer` at 8, `args[i]` at
/// 16 + 8·i. On little-endian the low 32-bit word of an argument comes
/// first.
const NR: u32 = 0;
const ARCH: u32 = 4;
const fn arg_low(i: u32) -> u32 {
    16 + 8 * i
}

const _: () = assert!(core::mem::offset_of!(libc::seccomp_data, nr) == NR as usize);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_data, arch) == ARCH as usize);
const _: () = assert!(core::mem::offset_of!(libc::seccomp_data, args) == arg_low(0) as usize);

/// `SECCOMP_RET_ERRNO` with an errno in its data bits.
pub const fn errno_action(errno: i32) -> u32 {
    libc::SECCOMP_RET_ERRNO | (errno as u32 & libc::SECCOMP_RET_DATA)
}

/// A row of the policy table, top to bottom (ADR-007, D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Row {
    /// `arch` is not the build's: `SECCOMP_RET_KILL_PROCESS`.
    ForeignArch,
    /// The number is above [`CEILING`]: ENOSYS.
    Ceiling,
    /// `io_uring_setup`, `io_uring_enter`, `io_uring_register`: EPERM.
    IoUring,
    /// `bpf`, `userfaultfd`, `perf_event_open`: EPERM.
    BpfUserfaultfdPerf,
    /// `keyctl`, `add_key`, `request_key`: EPERM.
    Keyring,
    /// `syslog`: EPERM.
    Syslog,
    /// `clone` or `unshare` with `CLONE_NEWUSER` in the low word of arg 0:
    /// EPERM.
    NewUserNamespace,
    /// `clone3`: ENOSYS.
    Clone3,
    /// `socket` with a family other than Unix, IPv4, IPv6 and netlink:
    /// EAFNOSUPPORT.
    SocketFamily,
    /// `socket` of family IPv4 with type `SOCK_PACKET` (10, with or
    /// without `SOCK_NONBLOCK` and `SOCK_CLOEXEC`) in the low word of
    /// arg 1, which the kernel turns into a packet socket: EAFNOSUPPORT.
    SockPacket,
    /// `socket` of family netlink with a protocol other than
    /// `NETLINK_ROUTE`: EPROTONOSUPPORT.
    NetlinkProtocol,
    /// `socket` of family IPv4 or IPv6 with a protocol other than 0, TCP,
    /// UDP and the family's ICMP: EPROTONOSUPPORT.
    InetProtocol,
    /// `socketpair` with a family other than Unix: EAFNOSUPPORT.
    Socketpair,
    /// `mmap` with `MAP_HUGETLB` in the low word of arg 3: EPERM.
    HugetlbMmap,
    /// `shmget` with `SHM_HUGETLB` in the low word of arg 2: EPERM.
    HugetlbShmget,
    /// `memfd_create` with `MFD_HUGETLB` in the low word of arg 1: EPERM.
    HugetlbMemfd,
    /// `ioctl` with `TIOCSETD` in the low word of arg 1: EPERM.
    LineDiscipline,
    /// `ioctl` with one of the eight socket ioctls whose handler loads
    /// `bridge` or `8021q` in the low word of arg 1: EPERM.
    ModuleIoctl,
    /// `setsockopt` with `SOL_TLS` in the low word of arg 1 (the level):
    /// ENOPROTOOPT.
    Ktls,
    /// `setsockopt` with `IPPROTO_TCP` in the low word of arg 1 and
    /// `TCP_MD5SIG`, `TCP_MD5SIG_EXT` or `TCP_AO_ADD_KEY` in the low word
    /// of arg 2: ENOPROTOOPT.
    TcpSignature,
    /// `setsockopt` or `getsockopt` with `IPPROTO_IP` in the low word of
    /// arg 1 and 64 to 67 in the low word of arg 2, the options kernels
    /// from 5.19 until bpfilter's removal hand to bpfilter: ENOPROTOOPT.
    Bpfilter,
    /// `ioctl` with `FS_IOC_ADD_ENCRYPTION_KEY`,
    /// `FS_IOC_SET_ENCRYPTION_POLICY` or `FS_IOC_ENABLE_VERITY` in the low
    /// word of arg 1: EPERM.
    FsCryptoIoctl,
}

impl Row {
    /// Every row, in table order.
    pub const ALL: [Row; 22] = [
        Row::ForeignArch,
        Row::Ceiling,
        Row::IoUring,
        Row::BpfUserfaultfdPerf,
        Row::Keyring,
        Row::Syslog,
        Row::NewUserNamespace,
        Row::Clone3,
        Row::SocketFamily,
        Row::SockPacket,
        Row::NetlinkProtocol,
        Row::InetProtocol,
        Row::Socketpair,
        Row::HugetlbMmap,
        Row::HugetlbShmget,
        Row::HugetlbMemfd,
        Row::LineDiscipline,
        Row::ModuleIoctl,
        Row::Ktls,
        Row::TcpSignature,
        Row::Bpfilter,
        Row::FsCryptoIoctl,
    ];

    /// The seccomp action of the row.
    pub fn action(self) -> u32 {
        match self {
            Row::ForeignArch => libc::SECCOMP_RET_KILL_PROCESS,
            Row::Ceiling | Row::Clone3 => errno_action(libc::ENOSYS),
            Row::IoUring
            | Row::BpfUserfaultfdPerf
            | Row::Keyring
            | Row::Syslog
            | Row::NewUserNamespace
            | Row::HugetlbMmap
            | Row::HugetlbShmget
            | Row::HugetlbMemfd
            | Row::LineDiscipline
            | Row::ModuleIoctl
            | Row::FsCryptoIoctl => errno_action(libc::EPERM),
            Row::SocketFamily | Row::SockPacket | Row::Socketpair => {
                errno_action(libc::EAFNOSUPPORT)
            }
            Row::NetlinkProtocol | Row::InetProtocol => errno_action(libc::EPROTONOSUPPORT),
            Row::Ktls | Row::TcpSignature | Row::Bpfilter => errno_action(ENOPROTOOPT_ERRNO),
        }
    }

    /// Whether the row denies every call of its syscalls, whatever the
    /// arguments (the others look at one argument).
    pub fn denies_every_form(self) -> bool {
        matches!(
            self,
            Row::IoUring | Row::BpfUserfaultfdPerf | Row::Keyring | Row::Syslog | Row::Clone3
        )
    }
}

/// An assembled program, ready for `seccomp(SECCOMP_SET_MODE_FILTER)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program(Vec<Insn>);

impl Program {
    /// The instructions.
    pub fn instructions(&self) -> &[Insn] {
        &self.0
    }
}

/// The seccomp policy. There is one, without configuration (ADR-007, D2).
#[derive(Debug, Clone, Copy)]
pub struct Policy(());

// The labels of the program.
const KILL: Label = Label(1);
const ALLOW: Label = Label(2);
const EPERM: Label = Label(3);
const ENOSYS: Label = Label(4);
const EAFNOSUPPORT: Label = Label(5);
const EPROTONOSUPPORT: Label = Label(6);
const CLONE_FLAGS: Label = Label(7);
const SOCKET: Label = Label(8);
const NETLINK: Label = Label(9);
const SOCKETPAIR: Label = Label(10);
const MMAP: Label = Label(11);
const SHMGET: Label = Label(12);
const MEMFD: Label = Label(13);
const INET: Label = Label(14);
const INET6: Label = Label(15);
const IP_PROTOCOL: Label = Label(16);
const IOCTL: Label = Label(17);
const SETSOCKOPT: Label = Label(18);
const ENOPROTOOPT: Label = Label(19);
const GETSOCKOPT: Label = Label(20);
const IP_OPTION: Label = Label(21);

fn to(label: Label) -> Target {
    Target::Label(label)
}

const NEXT: Target = Target::Next;

impl Policy {
    /// The sandbox policy of ADR-007, D2.
    pub fn sandbox() -> Policy {
        Policy(())
    }

    /// The program for `arch`.
    pub fn program(&self, arch: Arch) -> Result<Program, AsmError> {
        bpf::assemble(&self.source(arch)).map(Program)
    }

    fn source(&self, arch: Arch) -> Vec<Op> {
        let nr = arch.syscalls();
        let mut ops = vec![
            // Row ForeignArch: another syscall table (i386, AArch32, or
            // the other 64-bit architecture).
            Op::Load(ARCH),
            Op::Jeq(arch.audit_arch(), NEXT, to(KILL)),
            Op::Load(NR),
            // Row Ceiling, unsigned: also x32 numbers (bit 30) and -1.
            Op::Jgt(CEILING, to(ENOSYS), NEXT),
        ];
        // Rows that deny every call of a syscall.
        for whole in [
            nr.io_uring_setup,
            nr.io_uring_enter,
            nr.io_uring_register,
            nr.bpf,
            nr.userfaultfd,
            nr.perf_event_open,
            nr.keyctl,
            nr.add_key,
            nr.request_key,
            nr.syslog,
        ] {
            ops.push(Op::Jeq(whole, to(EPERM), NEXT));
        }
        ops.extend([
            Op::Jeq(nr.clone3, to(ENOSYS), NEXT),
            // Rows that look at one argument.
            Op::Jeq(nr.clone, to(CLONE_FLAGS), NEXT),
            Op::Jeq(nr.unshare, to(CLONE_FLAGS), NEXT),
            Op::Jeq(nr.socket, to(SOCKET), NEXT),
            Op::Jeq(nr.socketpair, to(SOCKETPAIR), NEXT),
            Op::Jeq(nr.mmap, to(MMAP), NEXT),
            Op::Jeq(nr.shmget, to(SHMGET), NEXT),
            Op::Jeq(nr.memfd_create, to(MEMFD), NEXT),
            Op::Jeq(nr.ioctl, to(IOCTL), NEXT),
            Op::Jeq(nr.setsockopt, to(SETSOCKOPT), NEXT),
            Op::Jeq(nr.getsockopt, to(GETSOCKOPT), NEXT),
            Op::Ret(libc::SECCOMP_RET_ALLOW),
            // Row NewUserNamespace: clone uses only the low word of its
            // flags, unshare rejects unknown upper bits.
            Op::Mark(CLONE_FLAGS),
            Op::Load(arg_low(0)),
            Op::Jset(CLONE_NEWUSER, to(EPERM), to(ALLOW)),
            // Rows SocketFamily, NetlinkProtocol and InetProtocol: `domain`
            // and `protocol` are ints.
            Op::Mark(SOCKET),
            Op::Load(arg_low(0)),
            Op::Jeq(AF_UNIX, to(ALLOW), NEXT),
            Op::Jeq(AF_INET, to(INET), NEXT),
            Op::Jeq(AF_INET6, to(INET6), NEXT),
            Op::Jeq(AF_NETLINK, to(NETLINK), to(EAFNOSUPPORT)),
            Op::Mark(NETLINK),
            Op::Load(arg_low(2)),
            Op::Jeq(NETLINK_ROUTE, to(ALLOW), to(EPROTONOSUPPORT)),
            // Row SockPacket, IPv4 only (`__sock_create` rewrites only
            // PF_INET): `type` is an int, and the kernel accepts no other
            // value with type 10 in it.
            Op::Mark(INET),
            Op::Load(arg_low(1)),
            Op::Jeq(SOCK_PACKET_TYPES[0], to(EAFNOSUPPORT), NEXT),
            Op::Jeq(SOCK_PACKET_TYPES[1], to(EAFNOSUPPORT), NEXT),
            Op::Jeq(SOCK_PACKET_TYPES[2], to(EAFNOSUPPORT), NEXT),
            Op::Jeq(SOCK_PACKET_TYPES[3], to(EAFNOSUPPORT), NEXT),
            // Each family's ICMP, then the protocols both share.
            Op::Load(arg_low(2)),
            Op::Jeq(IPPROTO_ICMP, to(ALLOW), to(IP_PROTOCOL)),
            Op::Mark(INET6),
            Op::Load(arg_low(2)),
            Op::Jeq(IPPROTO_ICMPV6, to(ALLOW), NEXT),
            Op::Mark(IP_PROTOCOL),
            Op::Jeq(IPPROTO_IP, to(ALLOW), NEXT),
            Op::Jeq(IPPROTO_TCP, to(ALLOW), NEXT),
            Op::Jeq(IPPROTO_UDP, to(ALLOW), to(EPROTONOSUPPORT)),
            // Row Socketpair.
            Op::Mark(SOCKETPAIR),
            Op::Load(arg_low(0)),
            Op::Jeq(AF_UNIX, to(ALLOW), to(EAFNOSUPPORT)),
            // Huge page rows: the kernel tests only these bits, which lie
            // in the low words.
            Op::Mark(MMAP),
            Op::Load(arg_low(3)),
            Op::Jset(MAP_HUGETLB, to(EPERM), to(ALLOW)),
            Op::Mark(SHMGET),
            Op::Load(arg_low(2)),
            Op::Jset(SHM_HUGETLB, to(EPERM), to(ALLOW)),
            Op::Mark(MEMFD),
            Op::Load(arg_low(1)),
            Op::Jset(MFD_HUGETLB, to(EPERM), to(ALLOW)),
            // Rows LineDiscipline, ModuleIoctl and FsCryptoIoctl: `cmd` is
            // an unsigned int.
            Op::Mark(IOCTL),
            Op::Load(arg_low(1)),
            Op::Jeq(TIOCSETD, to(EPERM), NEXT),
            Op::Jeq(MODULE_IOCTLS[0], to(EPERM), NEXT),
            Op::Jeq(MODULE_IOCTLS[1], to(EPERM), NEXT),
            Op::Jeq(MODULE_IOCTLS[2], to(EPERM), NEXT),
            Op::Jeq(MODULE_IOCTLS[3], to(EPERM), NEXT),
            Op::Jeq(MODULE_IOCTLS[4], to(EPERM), NEXT),
            Op::Jeq(MODULE_IOCTLS[5], to(EPERM), NEXT),
            Op::Jeq(MODULE_IOCTLS[6], to(EPERM), NEXT),
            Op::Jeq(MODULE_IOCTLS[7], to(EPERM), NEXT),
            Op::Jeq(FS_CRYPTO_IOCTLS[0], to(EPERM), NEXT),
            Op::Jeq(FS_CRYPTO_IOCTLS[1], to(EPERM), NEXT),
            Op::Jeq(FS_CRYPTO_IOCTLS[2], to(EPERM), to(ALLOW)),
            // Rows Ktls, TcpSignature and Bpfilter: `level` and `optname`
            // are ints. Every other level and option is judged by the
            // kernel.
            Op::Mark(SETSOCKOPT),
            Op::Load(arg_low(1)),
            Op::Jeq(SOL_TLS, to(ENOPROTOOPT), NEXT),
            Op::Jeq(IPPROTO_IP, to(IP_OPTION), NEXT),
            Op::Jeq(IPPROTO_TCP, NEXT, to(ALLOW)),
            Op::Load(arg_low(2)),
            Op::Jeq(TCP_SIGNATURE_OPTIONS[0], to(ENOPROTOOPT), NEXT),
            Op::Jeq(TCP_SIGNATURE_OPTIONS[1], to(ENOPROTOOPT), NEXT),
            Op::Jeq(TCP_SIGNATURE_OPTIONS[2], to(ENOPROTOOPT), to(ALLOW)),
            // Row Bpfilter for getsockopt, then the option range both
            // calls share, unsigned: 64 to 67.
            Op::Mark(GETSOCKOPT),
            Op::Load(arg_low(1)),
            Op::Jeq(IPPROTO_IP, NEXT, to(ALLOW)),
            Op::Mark(IP_OPTION),
            Op::Load(arg_low(2)),
            Op::Jgt(BPFILTER_OPTIONS.1, to(ALLOW), NEXT),
            Op::Jgt(BPFILTER_OPTIONS.0 - 1, to(ENOPROTOOPT), to(ALLOW)),
            // The returns.
            Op::Mark(ALLOW),
            Op::Ret(libc::SECCOMP_RET_ALLOW),
            Op::Mark(EPERM),
            Op::Ret(errno_action(libc::EPERM)),
            Op::Mark(ENOSYS),
            Op::Ret(errno_action(libc::ENOSYS)),
            Op::Mark(EAFNOSUPPORT),
            Op::Ret(errno_action(libc::EAFNOSUPPORT)),
            Op::Mark(EPROTONOSUPPORT),
            Op::Ret(errno_action(libc::EPROTONOSUPPORT)),
            Op::Mark(ENOPROTOOPT),
            Op::Ret(errno_action(ENOPROTOOPT_ERRNO)),
            Op::Mark(KILL),
            Op::Ret(libc::SECCOMP_RET_KILL_PROCESS),
        ]);
        ops
    }
}
