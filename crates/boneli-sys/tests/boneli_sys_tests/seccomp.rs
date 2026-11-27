//! The seccomp policy (ADR-007, D2): the program the assembler builds,
//! run through the test interpreter (`support::bpf`) for both
//! architectures, and the real program in the kernel (`seccomp_rows`).
//!
//! The pure tests take their syscall numbers from the uapi 7.2.4 table in
//! ADR-007 D2, written out here, not from `boneli_sys::seccomp::table`, so
//! a wrong number in the library fails them instead of moving with them.

use boneli_sys::seccomp::{Arch, CEILING, Policy, errno_action};

use crate::support::bpf::{ALLOW, Data, program, run};
use crate::support::probe::{MODULE_BRIDGE_VAR, MODULE_PACKET_VAR, UNTRIED};
use crate::support::{self, ids, report, run_probe, run_probe_host};

const EPERM: u32 = errno_action(libc::EPERM);
const ENOSYS: u32 = errno_action(libc::ENOSYS);
const EAFNOSUPPORT: u32 = errno_action(libc::EAFNOSUPPORT);
const EPROTONOSUPPORT: u32 = errno_action(libc::EPROTONOSUPPORT);
const ENOPROTOOPT: u32 = errno_action(libc::ENOPROTOOPT);
const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;

/// The numbers the rows name, per architecture (ADR-007 D2 and the huge
/// page rows), as the ADR's table writes them.
struct Numbers {
    deny_eperm: [u32; 10],
    clone: u32,
    unshare: u32,
    clone3: u32,
    socket: u32,
    socketpair: u32,
    mmap: u32,
    shmget: u32,
    memfd_create: u32,
    ioctl: u32,
    setsockopt: u32,
    getsockopt: u32,
}

/// x86_64: io_uring_setup/enter/register, bpf, userfaultfd,
/// perf_event_open, add_key, request_key, keyctl, syslog.
const X86_64: Numbers = Numbers {
    deny_eperm: [425, 426, 427, 321, 323, 298, 248, 249, 250, 103],
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

/// aarch64, in the same order.
const AARCH64: Numbers = Numbers {
    deny_eperm: [425, 426, 427, 280, 282, 241, 217, 218, 219, 116],
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

fn numbers(arch: Arch) -> &'static Numbers {
    match arch {
        Arch::X86_64 => &X86_64,
        Arch::Aarch64 => &AARCH64,
    }
}

/// `AUDIT_ARCH_I386` and `AUDIT_ARCH_ARM`, `include/uapi/linux/audit.h`.
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
const AUDIT_ARCH_ARM: u32 = 0x4000_0028;

/// What the policy must answer for `nr` with zeroed arguments.
fn expected_zeroed(arch: Arch, nr: u32) -> u32 {
    let n = numbers(arch);
    if nr > 471 {
        ENOSYS
    } else if n.deny_eperm.contains(&nr) {
        EPERM
    } else if nr == n.clone3 {
        ENOSYS
    } else if nr == n.socket || nr == n.socketpair {
        // Family 0 (AF_UNSPEC) is none of the allowed ones.
        EAFNOSUPPORT
    } else {
        // clone and unshare without CLONE_NEWUSER, mmap, shmget and
        // memfd_create without their huge page flag.
        ALLOW
    }
}

fn policy_decisions(arch: Arch) {
    let prog = program(arch);
    let audit = arch.audit_arch();
    assert_eq!(CEILING, 471);
    // Every number up to and past the ceiling: a superset of the numbers
    // the 7.2 table defines on this architecture.
    for nr in 0..=CEILING + 8 {
        let got = run(&prog, &Data::call(audit, nr));
        assert_eq!(
            got,
            expected_zeroed(arch, nr),
            "{}: nr {nr} gave {got:#x}",
            arch.name()
        );
    }
    assert_eq!(run(&prog, &Data::call(audit, 471)), ALLOW);
    assert_eq!(run(&prog, &Data::call(audit, 472)), ENOSYS);
    // x32 `read` (bit 30) and nr = -1.
    assert_eq!(run(&prog, &Data::call(audit, 0x4000_0000)), ENOSYS);
    assert_eq!(run(&prog, &Data::call(audit, 0xFFFF_FFFF)), ENOSYS);
    // Another syscall table is killed, whatever the number: i386, AArch32
    // and the other 64-bit architecture.
    let other = match arch {
        Arch::X86_64 => Arch::Aarch64.audit_arch(),
        Arch::Aarch64 => Arch::X86_64.audit_arch(),
    };
    for foreign in [AUDIT_ARCH_I386, AUDIT_ARCH_ARM, other, 0] {
        for nr in [0, 1, 20, 102, 471, 472, 0xFFFF_FFFF] {
            assert_eq!(
                run(&prog, &Data::call(foreign, nr)),
                KILL,
                "{}: arch {foreign:#x} nr {nr}",
                arch.name()
            );
        }
    }
}

#[test]
fn policy_decisions_x86_64() {
    policy_decisions(Arch::X86_64);
}

#[test]
fn policy_decisions_aarch64() {
    policy_decisions(Arch::Aarch64);
}

#[test]
fn user_namespace_rows() {
    const NEWUSER: u64 = libc::CLONE_NEWUSER as u64;
    const NEWNS: u64 = libc::CLONE_NEWNS as u64;
    let cases: [(u64, u32); 6] = [
        (0, ALLOW),
        (NEWNS, ALLOW),
        (NEWUSER, EPERM),
        (NEWUSER | NEWNS, EPERM),
        // Bits above the low word: clone ignores them and unshare refuses
        // them with EINVAL, so they never select a user namespace.
        (1 << 32, ALLOW),
        ((1 << 32) | NEWUSER, EPERM),
    ];
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        for nr in [n.clone, n.unshare] {
            for (flags, want) in cases {
                let data = Data::call(arch.audit_arch(), nr).arg(0, flags);
                assert_eq!(
                    run(&prog, &data),
                    want,
                    "{}: nr {nr} flags {flags:#x}",
                    arch.name()
                );
            }
        }
    }
}

#[test]
fn socket_family_rows() {
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        for domain in 0u64..=63 {
            let want = if [1, 2, 10, 16].contains(&domain) {
                ALLOW
            } else {
                EAFNOSUPPORT
            };
            let data = Data::call(audit, n.socket).arg(0, domain);
            assert_eq!(run(&prog, &data), want, "{}: socket {domain}", arch.name());
            let want = if domain == 1 { ALLOW } else { EAFNOSUPPORT };
            let data = Data::call(audit, n.socketpair).arg(0, domain);
            assert_eq!(
                run(&prog, &data),
                want,
                "{}: socketpair {domain}",
                arch.name()
            );
        }
        // `domain` is an int: the high word is not part of it.
        let data = Data::call(audit, n.socket).arg(0, (1 << 32) | 1);
        assert_eq!(run(&prog, &data), ALLOW, "{}", arch.name());
        let data = Data::call(audit, n.socketpair).arg(0, (1 << 32) | 1);
        assert_eq!(run(&prog, &data), ALLOW, "{}", arch.name());
        // The type argument plays no part.
        let data = Data::call(audit, n.socket)
            .arg(0, libc::AF_VSOCK as u64)
            .arg(1, libc::SOCK_STREAM as u64);
        assert_eq!(run(&prog, &data), EAFNOSUPPORT, "{}", arch.name());
    }
}

#[test]
fn netlink_protocol_rows() {
    const MAX_LINKS: u64 = 32;
    let netlink = libc::AF_NETLINK as u64;
    let raw = libc::SOCK_RAW as u64;
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let socket = |family: u64, protocol: u64| {
            run(
                &prog,
                &Data::call(audit, n.socket)
                    .arg(0, family)
                    .arg(1, raw)
                    .arg(2, protocol),
            )
        };
        assert_eq!(socket(netlink, 0), ALLOW, "{}", arch.name());
        for p in 1..=MAX_LINKS {
            assert_eq!(
                socket(netlink, p),
                EPROTONOSUPPORT,
                "{}: protocol {p}",
                arch.name()
            );
        }
        // `protocol` is an int.
        assert_eq!(socket(netlink, 1 << 32), ALLOW, "{}", arch.name());
        assert_eq!(
            socket(netlink, (1 << 32) | 12),
            EPROTONOSUPPORT,
            "{}",
            arch.name()
        );
        assert_eq!(socket(netlink, 0xFFFF_FFFF), EPROTONOSUPPORT);
        // The protocol of a Unix socket is the kernel's to judge; IPv4 has
        // its own protocol row (`inet_protocol_rows`).
        assert_eq!(socket(libc::AF_UNIX as u64, 12), ALLOW, "{}", arch.name());
        assert_eq!(
            socket(libc::AF_INET as u64, 12),
            EPROTONOSUPPORT,
            "{}",
            arch.name()
        );
    }
}

/// The IP protocols each family allows (ADR-007 D2): 0, TCP and UDP, and
/// the family's own ICMP for unprivileged ping sockets.
const INET_ALLOWED: [u64; 4] = [0, 1, 6, 17];
const INET6_ALLOWED: [u64; 4] = [0, 6, 17, 58];

#[test]
fn inet_protocol_rows() {
    let inet = libc::AF_INET as u64;
    let inet6 = libc::AF_INET6 as u64;
    let stream = libc::SOCK_STREAM as u64;
    let raw = libc::SOCK_RAW as u64;
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let name = arch.name();
        let socket = |family: u64, ty: u64, protocol: u64| {
            run(
                &prog,
                &Data::call(audit, n.socket)
                    .arg(0, family)
                    .arg(1, ty)
                    .arg(2, protocol),
            )
        };
        // Every protocol up to past IPPROTO_MAX (263), the module ones
        // among them: L2TP 115, SCTP 132, UDP-Lite 136, SMC 256, MPTCP 262,
        // DCCP 33, raw 255.
        for p in 0u64..=300 {
            for (family, allowed) in [(inet, INET_ALLOWED), (inet6, INET6_ALLOWED)] {
                let want = if allowed.contains(&p) {
                    ALLOW
                } else {
                    EPROTONOSUPPORT
                };
                for ty in [stream, libc::SOCK_DGRAM as u64, raw] {
                    assert_eq!(
                        socket(family, ty, p),
                        want,
                        "{name}: family {family} type {ty} protocol {p}"
                    );
                }
            }
        }
        // Each family's ICMP is not the other's.
        assert_eq!(socket(inet, raw, 58), EPROTONOSUPPORT, "{name}");
        assert_eq!(socket(inet6, raw, 1), EPROTONOSUPPORT, "{name}");
        // `protocol` is an int: the high word is not part of it, and -1 is
        // no protocol.
        for family in [inet, inet6] {
            assert_eq!(socket(family, stream, (1 << 32) | 6), ALLOW, "{name}");
            assert_eq!(socket(family, stream, 1 << 32), ALLOW, "{name}");
            assert_eq!(
                socket(family, stream, (1 << 32) | 132),
                EPROTONOSUPPORT,
                "{name}"
            );
            assert_eq!(socket(family, stream, 0xFFFF_FFFF), EPROTONOSUPPORT);
            assert_eq!(
                socket(family, stream, 0xFFFF_FFFF_0000_0006),
                ALLOW,
                "{name}"
            );
        }
        // The flags in the type argument play no part.
        let flags = (libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u64;
        assert_eq!(socket(inet, stream | flags, 6), ALLOW, "{name}");
        assert_eq!(socket(inet6, stream | flags, 132), EPROTONOSUPPORT);
        // The other families keep their own rows: Unix takes any protocol,
        // netlink only routing, the rest no family at all.
        assert_eq!(socket(libc::AF_UNIX as u64, stream, 132), ALLOW, "{name}");
        assert_eq!(
            socket(libc::AF_NETLINK as u64, raw, 6),
            EPROTONOSUPPORT,
            "{name}"
        );
        assert_eq!(socket(libc::AF_VSOCK as u64, stream, 6), EAFNOSUPPORT);
    }
    // MPTCP and UDP-Lite stay refused (ADR-007 D2, the census verdict),
    // named: both families, stream and datagram.
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        for protocol in [libc::IPPROTO_MPTCP, libc::IPPROTO_UDPLITE] {
            for family in [libc::AF_INET, libc::AF_INET6] {
                for ty in [libc::SOCK_STREAM, libc::SOCK_DGRAM] {
                    let got = run(
                        &prog,
                        &Data::call(audit, n.socket)
                            .arg(0, family as u64)
                            .arg(1, ty as u64)
                            .arg(2, protocol as u64),
                    );
                    assert_eq!(
                        got,
                        EPROTONOSUPPORT,
                        "{}: family {family} type {ty} protocol {protocol}",
                        arch.name()
                    );
                }
            }
        }
    }
    assert_eq!(libc::IPPROTO_MPTCP, 262);
    assert_eq!(libc::IPPROTO_UDPLITE, 136);
    assert_eq!(libc::IPPROTO_ICMP, 1);
    assert_eq!(libc::IPPROTO_TCP, 6);
    assert_eq!(libc::IPPROTO_UDP, 17);
    assert_eq!(libc::IPPROTO_ICMPV6, 58);
}

#[test]
fn tty_line_discipline_row() {
    // The numbers are written out, like the syscall numbers above; they are
    // the same on both architectures (asm-generic ioctls.h, which x86 and
    // arm64 both use).
    const TIOCSETD: u64 = 0x5423;
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let name = arch.name();
        let ioctl = |fd: u64, cmd: u64, arg: u64| {
            run(
                &prog,
                &Data::call(audit, n.ioctl)
                    .arg(0, fd)
                    .arg(1, cmd)
                    .arg(2, arg),
            )
        };
        for fd in [0, 3, 0xFFFF_FFFF] {
            assert_eq!(ioctl(fd, TIOCSETD, 0), EPERM, "{name}: fd {fd}");
            assert_eq!(ioctl(fd, TIOCSETD, 0x7ffd_0000), EPERM, "{name}");
        }
        // `cmd` is an unsigned int: the high word is not part of it.
        assert_eq!(ioctl(3, (1 << 32) | TIOCSETD, 0), EPERM, "{name}");
        assert_eq!(ioctl(3, 1 << 32, 0), ALLOW, "{name}");
        // The neighbours and the other tty ioctls stay allowed: TIOCNOTTY,
        // TIOCGETD (reads the discipline), TIOCGPTPEER, TIOCSPTLCK, TCGETS.
        for cmd in [
            0,
            TIOCSETD - 1,
            TIOCSETD + 1,
            0x5424,      // TIOCGETD
            0x5441,      // TIOCGPTPEER
            0x4004_5431, // TIOCSPTLCK
            0x5401,      // TCGETS
        ] {
            assert_eq!(ioctl(3, cmd, 0), ALLOW, "{name}: cmd {cmd:#x}");
        }
        // The number in another argument selects nothing.
        assert_eq!(ioctl(TIOCSETD, 0, TIOCSETD), ALLOW, "{name}");
    }
}

#[test]
fn sock_packet_row() {
    // Written out: SOCK_PACKET is 10, SOCK_NONBLOCK 0x800 and SOCK_CLOEXEC
    // 0x80000 on both architectures.
    const PACKET: u64 = 10;
    const NONBLOCK: u64 = 0x800;
    const CLOEXEC: u64 = 0x8_0000;
    let inet = libc::AF_INET as u64;
    let inet6 = libc::AF_INET6 as u64;
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let name = arch.name();
        let socket = |family: u64, ty: u64, protocol: u64| {
            run(
                &prog,
                &Data::call(audit, n.socket)
                    .arg(0, family)
                    .arg(1, ty)
                    .arg(2, protocol),
            )
        };
        // Every form the kernel accepts as SOCK_PACKET, with the protocols
        // a packet socket takes (ETH_P_ALL 0x0300 in network order among
        // them) and ones the protocol row would allow.
        for ty in [
            PACKET,
            PACKET | NONBLOCK,
            PACKET | CLOEXEC,
            PACKET | NONBLOCK | CLOEXEC,
        ] {
            for protocol in [0, 1, 6, 17, 0x0300, 0x0003, 132] {
                assert_eq!(
                    socket(inet, ty, protocol),
                    EAFNOSUPPORT,
                    "{name}: type {ty:#x} protocol {protocol:#x}"
                );
            }
            // `type` is an int: the high word is not part of it.
            assert_eq!(socket(inet, (1 << 32) | ty, 0), EAFNOSUPPORT, "{name}");
            assert_eq!(
                socket(inet, 0xFFFF_FFFF_0000_0000 | ty, 6),
                EAFNOSUPPORT,
                "{name}"
            );
            // The kernel rewrites only PF_INET, so IPv6 keeps its protocol
            // row, and the other families their own.
            assert_eq!(socket(inet6, ty, 0), ALLOW, "{name}: inet6 {ty:#x}");
            assert_eq!(socket(inet6, ty, 132), EPROTONOSUPPORT, "{name}");
            assert_eq!(socket(libc::AF_UNIX as u64, ty, 0), ALLOW, "{name}");
            assert_eq!(socket(libc::AF_PACKET as u64, ty, 0), EAFNOSUPPORT);
        }
        // The neighbouring types and other flag bits keep the protocol row:
        // the kernel refuses unknown flags with EINVAL itself.
        for ty in [
            9,
            11,
            PACKET | 0x10,
            PACKET | 0x40,
            PACKET | 0x8_0800 | 0x1000,
            libc::SOCK_STREAM as u64,
            libc::SOCK_DGRAM as u64 | NONBLOCK,
            libc::SOCK_RAW as u64 | CLOEXEC,
        ] {
            assert_eq!(socket(inet, ty, 6), ALLOW, "{name}: type {ty:#x}");
            assert_eq!(socket(inet, ty, 132), EPROTONOSUPPORT, "{name}");
        }
        // ICMP still selects the IPv4 ping socket after the type check.
        assert_eq!(socket(inet, libc::SOCK_DGRAM as u64, 1), ALLOW, "{name}");
        // The type in another argument selects nothing: as a protocol, 10
        // meets the protocol row.
        assert_eq!(socket(inet, 0, PACKET), EPROTONOSUPPORT, "{name}");
    }
    assert_eq!(NONBLOCK, libc::SOCK_NONBLOCK as u64);
    assert_eq!(CLOEXEC, libc::SOCK_CLOEXEC as u64);
}

#[test]
fn module_ioctl_rows() {
    // The socket ioctls whose handler asks for a module (sockios.h), the
    // same on both architectures: SIOCGIFBR, SIOCSIFBR and SIOCBRADDBR to
    // SIOCBRDELIF load bridge, SIOCGIFVLAN and SIOCSIFVLAN load 8021q.
    const MODULE: [u64; 8] = [
        0x8940, 0x8941, 0x8982, 0x8983, 0x89a0, 0x89a1, 0x89a2, 0x89a3,
    ];
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let name = arch.name();
        let ioctl = |fd: u64, cmd: u64, arg: u64| {
            run(
                &prog,
                &Data::call(audit, n.ioctl)
                    .arg(0, fd)
                    .arg(1, cmd)
                    .arg(2, arg),
            )
        };
        for cmd in MODULE {
            // On every descriptor: the kernel reaches the module branch from
            // any socket, a Unix one included.
            for fd in [0, 3, 0xFFFF_FFFF] {
                assert_eq!(ioctl(fd, cmd, 0), EPERM, "{name}: cmd {cmd:#x}");
            }
            // `cmd` is an unsigned int.
            assert_eq!(ioctl(3, (1 << 32) | cmd, 0), EPERM, "{name}");
            assert_eq!(ioctl(3, 0xFFFF_FFFF_0000_0000 | cmd, 7), EPERM);
            // The number in another argument selects nothing.
            assert_eq!(ioctl(cmd, 0, cmd), ALLOW, "{name}: cmd {cmd:#x}");
        }
        // The neighbours and the socket ioctls programs use stay allowed:
        // SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFINDEX, SIOCGIFADDR, SIOCGIFMTU,
        // SIOCGIFHWADDR, SIOCGIFNAME, SIOCETHTOOL, SIOCGSTAMP, FIONREAD,
        // SIOCOUTQ, SIOCINQ's alias and SIOCGIFBRDADDR.
        for cmd in [
            0x893f, 0x8942, 0x8981, 0x8984, 0x899f, 0x89a4, 0x8912, 0x8913, 0x8933, 0x8915, 0x8921,
            0x8927, 0x8910, 0x8946, 0x8906, 0x541b, 0x5411, 0x8919,
        ] {
            assert_eq!(ioctl(3, cmd, 0), ALLOW, "{name}: cmd {cmd:#x}");
        }
        // The TIOCSETD row still answers before them.
        assert_eq!(ioctl(3, 0x5423, 0), EPERM, "{name}");
    }
    assert_eq!(MODULE[0], libc::SIOCGIFBR);
    assert_eq!(MODULE[1], libc::SIOCSIFBR);
}

#[test]
fn hugetlb_flag_rows() {
    const HUGE_SHIFT: u64 = libc::MAP_HUGE_SHIFT as u64;
    let private_anon = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
    let hugetlb = libc::MAP_HUGETLB as u64;
    let shm_hugetlb = libc::SHM_HUGETLB as u64;
    let creat = libc::IPC_CREAT as u64;
    let mfd_hugetlb = u64::from(libc::MFD_HUGETLB);
    let mfd_cloexec = u64::from(libc::MFD_CLOEXEC);
    let mfd_sealing = u64::from(libc::MFD_ALLOW_SEALING);
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let call = |nr: u32, i: usize, v: u64| run(&prog, &Data::call(audit, nr).arg(i, v));
        let name = arch.name();
        // mmap, arg 3 (flags).
        for v in [
            private_anon | hugetlb,
            private_anon | hugetlb | (21 << HUGE_SHIFT),
            (1 << 32) | hugetlb,
        ] {
            assert_eq!(call(n.mmap, 3, v), EPERM, "{name}: mmap flags {v:#x}");
        }
        for v in [
            private_anon,
            private_anon | (21 << HUGE_SHIFT),
            private_anon | 0x2_0000,
            private_anon | 0x8_0000,
            1 << 32,
        ] {
            assert_eq!(call(n.mmap, 3, v), ALLOW, "{name}: mmap flags {v:#x}");
        }
        // The flag in another argument (prot) selects nothing.
        assert_eq!(call(n.mmap, 2, hugetlb), ALLOW, "{name}");
        // shmget, arg 2 (shmflg).
        assert_eq!(
            call(n.shmget, 2, creat | shm_hugetlb | 0o600),
            EPERM,
            "{name}"
        );
        assert_eq!(call(n.shmget, 2, creat | 0o600), ALLOW, "{name}");
        assert_eq!(
            call(n.shmget, 2, libc::SHM_NORESERVE as u64),
            ALLOW,
            "{name}"
        );
        assert_eq!(call(n.shmget, 1, shm_hugetlb), ALLOW, "{name}");
        // memfd_create, arg 1 (flags).
        assert_eq!(call(n.memfd_create, 1, mfd_hugetlb), EPERM, "{name}");
        assert_eq!(
            call(n.memfd_create, 1, mfd_cloexec | mfd_hugetlb),
            EPERM,
            "{name}"
        );
        assert_eq!(call(n.memfd_create, 1, mfd_cloexec), ALLOW, "{name}");
        assert_eq!(call(n.memfd_create, 1, mfd_sealing), ALLOW, "{name}");
    }
    // The values the rows test are the uapi ones.
    assert_eq!(hugetlb, 0x4_0000);
    assert_eq!(shm_hugetlb, 0o4000);
    assert_eq!(mfd_hugetlb, 0x4);
}

#[test]
fn ktls_row() {
    // Written out: SOL_TLS is 282 (`include/linux/socket.h`), TCP_ULP 31.
    const SOL_TLS: u64 = 282;
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let name = arch.name();
        let setsockopt = |fd: u64, level: u64, optname: u64| {
            run(
                &prog,
                &Data::call(audit, n.setsockopt)
                    .arg(0, fd)
                    .arg(1, level)
                    .arg(2, optname),
            )
        };
        // Every option at this level: TLS_TX 1, TLS_RX 2, TLS_TX_ZEROCOPY_RO
        // 3, TLS_RX_EXPECT_NO_PAD 4, TLS_TX_MAX_PAYLOAD_LEN 5, and values
        // the kernel does not define.
        for optname in [1, 2, 3, 4, 5, 0, 0xFFFF_FFFF] {
            assert_eq!(
                setsockopt(3, SOL_TLS, optname),
                ENOPROTOOPT,
                "{name}: optname {optname:#x}"
            );
        }
        // `level` is an int: the high word is not part of it.
        assert_eq!(setsockopt(3, (1 << 32) | SOL_TLS, 1), ENOPROTOOPT, "{name}");
        assert_eq!(
            setsockopt(3, 0xFFFF_FFFF_0000_011A, 1),
            ENOPROTOOPT,
            "{name}"
        );
        // The other levels, the neighbours among them: SOL_IP 0, SOL_SOCKET
        // 1, SOL_IPV6 41.
        for level in [0, 1, 41, 281, 283, 0xFFFF_FFFF] {
            assert_eq!(setsockopt(3, level, 1), ALLOW, "{name}: level {level}");
        }
        // Attaching the ULP stays allowed: its autoload is capable()-gated.
        assert_eq!(setsockopt(3, 6, 31), ALLOW, "{name}: TCP_ULP");
        // The level is arg 1, not arg 2 or arg 0.
        assert_eq!(setsockopt(3, 1, SOL_TLS), ALLOW, "{name}");
        assert_eq!(setsockopt(SOL_TLS, 1, 1), ALLOW, "{name}");
        // Reading the options allocates nothing.
        assert_eq!(
            run(
                &prog,
                &Data::call(audit, n.getsockopt)
                    .arg(0, 3)
                    .arg(1, SOL_TLS)
                    .arg(2, 1)
            ),
            ALLOW,
            "{name}: getsockopt"
        );
    }
    assert_eq!(SOL_TLS, libc::SOL_TLS as u64);
    assert_eq!(libc::TCP_ULP, 31);
}

#[test]
fn tcp_signature_rows() {
    // Written out: TCP_MD5SIG 14, TCP_MD5SIG_EXT 32 and TCP_AO_ADD_KEY 38
    // (`include/uapi/linux/tcp.h`), at level IPPROTO_TCP 6.
    const TCP: u64 = 6;
    const SIGNED: [u64; 3] = [14, 32, 38];
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let name = arch.name();
        let setsockopt = |level: u64, optname: u64| {
            run(
                &prog,
                &Data::call(audit, n.setsockopt)
                    .arg(0, 3)
                    .arg(1, level)
                    .arg(2, optname),
            )
        };
        for optname in SIGNED {
            assert_eq!(
                setsockopt(TCP, optname),
                ENOPROTOOPT,
                "{name}: optname {optname}"
            );
        }
        // `level` and `optname` are ints.
        assert_eq!(setsockopt((1 << 32) | TCP, 38), ENOPROTOOPT, "{name}");
        assert_eq!(setsockopt(TCP, (1 << 32) | 38), ENOPROTOOPT, "{name}");
        // The neighbours and the other TCP-AO options, which allocate
        // nothing without a key: TCP_AO_DEL_KEY 39, TCP_AO_INFO 40,
        // TCP_AO_GET_KEYS 41, TCP_AO_REPAIR 42.
        for optname in [13, 15, 31, 33, 37, 39, 40, 41, 42] {
            assert_eq!(setsockopt(TCP, optname), ALLOW, "{name}: optname {optname}");
        }
        // The same numbers name other options at other levels.
        for level in [0, 1, 17, 41] {
            for optname in SIGNED {
                assert_eq!(
                    setsockopt(level, optname),
                    ALLOW,
                    "{name}: level {level} optname {optname}"
                );
            }
        }
    }
    assert_eq!(SIGNED[0], libc::TCP_MD5SIG as u64);
    assert_eq!(SIGNED[1], libc::TCP_MD5SIG_EXT as u64);
}

#[test]
fn bpfilter_row() {
    // Written out: IPPROTO_IP (SOL_IP) is 0, and the bpfilter range is
    // BPFILTER_IPT_SO_SET_REPLACE 64 to BPFILTER_IPT_SO_GET_REVISION_TARGET
    // 67 (`include/uapi/linux/bpfilter.h` in 5.19), the iptables numbers.
    const SOL_IP: u64 = 0;
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let name = arch.name();
        for nr in [n.setsockopt, n.getsockopt] {
            let call = |level: u64, optname: u64| {
                run(
                    &prog,
                    &Data::call(audit, nr)
                        .arg(0, 3)
                        .arg(1, level)
                        .arg(2, optname),
                )
            };
            for optname in 64..=67 {
                assert_eq!(
                    call(SOL_IP, optname),
                    ENOPROTOOPT,
                    "{name}: nr {nr} optname {optname}"
                );
                // `level` and `optname` are ints.
                assert_eq!(call(1 << 32, optname), ENOPROTOOPT, "{name}: nr {nr}");
                assert_eq!(call(SOL_IP, (1 << 32) | optname), ENOPROTOOPT, "{name}");
            }
            // The neighbours and the IP options programs use: IP_TOS 1,
            // IP_TTL 2, IP_MULTICAST_IF 32, IP_RECVERR 11, MCAST_JOIN_GROUP
            // 42, IP_LOCAL_PORT_RANGE 51, IP_PROTOCOL 52, and 63, 68, 96
            // (ARPT_SO_SET_REPLACE, judged by the kernel).
            for optname in [0, 1, 2, 11, 32, 42, 51, 52, 63, 68, 96, 0xFFFF_FFFF] {
                assert_eq!(call(SOL_IP, optname), ALLOW, "{name}: nr {nr} {optname}");
            }
            // The same numbers at other levels: SOL_SOCKET, IPPROTO_TCP,
            // IPPROTO_UDP, SOL_IPV6 (whose 64-67 are ip6tables, which need
            // CAP_NET_ADMIN and load no module).
            for level in [1, 6, 17, 41] {
                for optname in 64..=67 {
                    assert_eq!(call(level, optname), ALLOW, "{name}: {level} {optname}");
                }
            }
        }
        // getsockopt keeps no other row.
        let get = |level: u64, optname: u64| {
            run(
                &prog,
                &Data::call(audit, n.getsockopt)
                    .arg(1, level)
                    .arg(2, optname),
            )
        };
        assert_eq!(get(6, 38), ALLOW, "{name}: getsockopt TCP_AO_ADD_KEY");
        assert_eq!(get(282, 1), ALLOW, "{name}: getsockopt SOL_TLS");
    }
}

#[test]
fn fs_crypto_ioctl_rows() {
    // Written out, from the 7.2.4 uapi headers (`linux/fscrypt.h`,
    // `linux/fsverity.h`): FS_IOC_ADD_ENCRYPTION_KEY,
    // FS_IOC_SET_ENCRYPTION_POLICY, FS_IOC_ENABLE_VERITY.
    const REFUSED: [u64; 3] = [0xc050_6617, 0x800c_6613, 0x4080_6685];
    for arch in Arch::ALL {
        let prog = program(arch);
        let n = numbers(arch);
        let audit = arch.audit_arch();
        let name = arch.name();
        let ioctl = |fd: u64, cmd: u64, arg: u64| {
            run(
                &prog,
                &Data::call(audit, n.ioctl)
                    .arg(0, fd)
                    .arg(1, cmd)
                    .arg(2, arg),
            )
        };
        for cmd in REFUSED {
            assert_eq!(ioctl(3, cmd, 0), EPERM, "{name}: cmd {cmd:#x}");
            // `cmd` is an unsigned int.
            assert_eq!(ioctl(3, (1 << 32) | cmd, 0), EPERM, "{name}: {cmd:#x}");
            // The number in another argument selects nothing.
            assert_eq!(ioctl(3, 0, cmd), ALLOW, "{name}: {cmd:#x} in arg 2");
        }
        // The other fscrypt and fs-verity ioctls: FS_IOC_GET_ENCRYPTION_PWSALT
        // 0x40106614, FS_IOC_GET_ENCRYPTION_POLICY 0x400c6615,
        // FS_IOC_GET_ENCRYPTION_POLICY_EX 0xc0096616,
        // FS_IOC_REMOVE_ENCRYPTION_KEY 0xc0406618, its _ALL_USERS twin
        // 0xc0406619, FS_IOC_GET_ENCRYPTION_KEY_STATUS 0xc080661a,
        // FS_IOC_GET_ENCRYPTION_NONCE 0x8010661b, FS_IOC_MEASURE_VERITY
        // 0xc0046686, FS_IOC_READ_VERITY_METADATA 0xc0286687; the add-key
        // number with its size off by one either way; FS_IOC_SETFLAGS,
        // which the kernel judges.
        for cmd in [
            0x4010_6614,
            0x400c_6615,
            0xc009_6616,
            0xc040_6618,
            0xc040_6619,
            0xc080_661a,
            0x8010_661b,
            0xc004_6686,
            0xc028_6687,
            0xc051_6617,
            0xc04f_6617,
            0x4008_6602,
        ] {
            assert_eq!(ioctl(3, cmd, 0), ALLOW, "{name}: cmd {cmd:#x}");
        }
        // The rows before them keep their answers.
        assert_eq!(ioctl(3, 0x5423, 0), EPERM, "{name}: TIOCSETD");
        assert_eq!(ioctl(3, 0x8940, 0), EPERM, "{name}: SIOCGIFBR");
        assert_eq!(ioctl(3, 0x89a3, 0), EPERM, "{name}: SIOCBRDELIF");
    }
    // The library builds the numbers with the asm-generic encoding.
    use boneli_sys::seccomp::table::ioc;
    assert_eq!(u64::from(ioc(3, 0x66, 23, 80)), REFUSED[0]);
    assert_eq!(u64::from(ioc(2, 0x66, 19, 12)), REFUSED[1]);
    assert_eq!(u64::from(ioc(1, 0x66, 133, 128)), REFUSED[2]);
}

#[test]
fn program_shape() {
    for arch in Arch::ALL {
        let prog = program(arch);
        let len = prog.len();
        assert!(len <= 4096, "{}: {len} instructions", arch.name());
        let last = prog.last().expect("an empty program");
        assert_eq!(last.code, 0x06, "{}: does not end in RET", arch.name());
        for (at, insn) in prog.iter().enumerate() {
            match insn.code {
                // Jumps: both targets inside the program.
                0x15 | 0x25 | 0x45 => {
                    for off in [insn.jt, insn.jf] {
                        let to = at + 1 + usize::from(off);
                        assert!(to < len, "{}: jump at {at} past the end", arch.name());
                    }
                }
                0x20 | 0x06 => assert_eq!((insn.jt, insn.jf), (0, 0), "{}", arch.name()),
                other => panic!("{}: opcode {other:#x} at {at}", arch.name()),
            }
        }
        // The count ADR-007 D2 records; a change to the rows updates both.
        assert_eq!(
            len,
            PROGRAM_LEN,
            "{}: the ADR records {PROGRAM_LEN}",
            arch.name()
        );
    }
    // One policy, the same program every time.
    assert_eq!(
        Policy::sandbox().program(Arch::NATIVE),
        Policy::sandbox().program(Arch::NATIVE)
    );
}

/// The assembler's instruction count, recorded in ADR-007 D2.
const PROGRAM_LEN: usize = 88;

/// The kernel rows (ADR-007, D2): the probe's id for each call and the
/// result the policy must give inside, an errno or 0 for an allowed call.
const KERNEL_ROWS: &[(&str, i32)] = &[
    ("io-uring-setup", libc::EPERM),
    ("bpf", libc::EPERM),
    ("userfaultfd", libc::EPERM),
    ("perf-event-open", libc::EPERM),
    ("keyctl", libc::EPERM),
    ("add-key", libc::EPERM),
    ("request-key", libc::EPERM),
    ("syslog", libc::EPERM),
    ("unshare-newuser", libc::EPERM),
    ("unshare-newuser-high", libc::EPERM),
    ("clone-newuser", libc::EPERM),
    ("clone3", libc::ENOSYS),
    ("socket-vsock", libc::EAFNOSUPPORT),
    ("socket-unix", 0),
    ("socket-inet-tcp", 0),
    ("socket-inet6-udp", 0),
    ("socket-inet-raw-protocol", libc::EPROTONOSUPPORT),
    ("socket-inet6-raw-protocol", libc::EPROTONOSUPPORT),
    ("ioctl-tiocsetd", libc::EPERM),
    ("ioctl-siocgifbr", libc::EPERM),
    ("socket-inet-packet", libc::EAFNOSUPPORT),
    ("netlink-netfilter", libc::EPROTONOSUPPORT),
    ("netlink-route", 0),
    ("socketpair-inet", libc::EAFNOSUPPORT),
    ("mmap-hugetlb", libc::EPERM),
    ("memfd-hugetlb", libc::EPERM),
    ("shmget-hugetlb", libc::EPERM),
    ("setsockopt-tls", libc::ENOPROTOOPT),
    ("setsockopt-tcp-ao", libc::ENOPROTOOPT),
    ("setsockopt-tcp-md5", libc::ENOPROTOOPT),
    ("ioctl-fscrypt-add-key", libc::EPERM),
    ("ioctl-fscrypt-set-policy", libc::EPERM),
    ("ioctl-fsverity-enable", libc::EPERM),
];

/// What one kernel row showed on this host.
#[derive(Debug, PartialEq, Eq)]
enum RowOutcome {
    /// The filter changed the result: the row is observed.
    Observed,
    /// The host gives the filtered result already, and the row is listed in
    /// `BONELI_SYS_HOST_GAPS`.
    Gap,
    /// An allowed call that the filter passed.
    Allowed,
}

/// Classifies one row from its baseline (no filter) and filtered results.
/// Exact both ways: an unobservable row must be listed, and a listed row
/// must be unobservable.
fn classify_row(
    id: &str,
    want: i32,
    baseline: i32,
    filtered: i32,
    listed: bool,
) -> Result<RowOutcome, String> {
    if filtered != want {
        return Err(format!(
            "{id}: the sandbox gave {filtered}, the policy says {want}"
        ));
    }
    if want == 0 {
        return if listed {
            Err(format!("{id}: an allowed call cannot be a host gap"))
        } else {
            Ok(RowOutcome::Allowed)
        };
    }
    match (baseline == filtered, listed) {
        (false, false) => Ok(RowOutcome::Observed),
        (true, true) => Ok(RowOutcome::Gap),
        (true, false) => Err(format!(
            "{id}: the host gives {baseline} without the filter too, so the row is \
             unobservable here; list it in BONELI_SYS_HOST_GAPS"
        )),
        (false, true) => Err(format!(
            "{id}: listed in BONELI_SYS_HOST_GAPS, but the host gives {baseline} \
             without the filter, so the row is observable"
        )),
    }
}

#[test]
fn kernel_row_classification() {
    let (eperm, enomem) = (libc::EPERM, libc::ENOMEM);
    assert_eq!(
        classify_row("r", eperm, 0, eperm, false),
        Ok(RowOutcome::Observed)
    );
    assert_eq!(
        classify_row("r", eperm, enomem, eperm, false),
        Ok(RowOutcome::Observed)
    );
    assert_eq!(
        classify_row("r", eperm, eperm, eperm, true),
        Ok(RowOutcome::Gap)
    );
    assert_eq!(classify_row("r", 0, 0, 0, false), Ok(RowOutcome::Allowed));
    // Unobservable but unlisted, listed but observable, a wrong filtered
    // result, and an allowed call listed as a gap.
    assert!(classify_row("r", eperm, eperm, eperm, false).is_err());
    assert!(classify_row("r", eperm, 0, eperm, true).is_err());
    assert!(classify_row("r", eperm, 0, 0, false).is_err());
    assert!(classify_row("r", eperm, eperm, libc::ENOSYS, true).is_err());
    assert!(classify_row("r", 0, 0, 0, true).is_err());
    assert!(classify_row("r", 0, 0, eperm, false).is_err());
    // Every gap id of the kernel rows is a row, the module rows included.
    for gap in [
        "syslog",
        "shmget-hugetlb",
        "ioctl-siocgifbr",
        "socket-inet-packet",
        "setsockopt-tcp-ao",
        "setsockopt-tcp-md5",
    ] {
        assert!(KERNEL_ROWS.iter().any(|(id, _)| *id == gap), "{gap}");
    }
}

/// Where the kernel lists the TCP upper-layer protocols it has
/// registered: `tls` is there when the `tls` module is loaded or built in.
const TCP_ULPS: &str = "/proc/sys/net/ipv4/tcp_available_ulp";

/// The kTLS kernel row, decided by the host's `tcp_available_ulp`, not by
/// a gap id: whether the `tls` module is loaded differs between runners of
/// one CI image (present on one x86_64 runner, absent on the next, PR 5's
/// first two runs), so no reviewed list can name it. With the ULP the row
/// must be observed; without it the host answers ENOPROTOOPT at `SOL_TLS`
/// already, and the baseline must say so. Exact both ways.
fn tls_row_outcome(available: bool, baseline: i32, filtered: i32) -> Result<RowOutcome, String> {
    let want = libc::ENOPROTOOPT;
    if filtered != want {
        return Err(format!(
            "setsockopt-tls: the sandbox gave {filtered}, the policy says {want}"
        ));
    }
    match (available, baseline == want) {
        (true, false) => Ok(RowOutcome::Observed),
        (false, true) => Ok(RowOutcome::Gap),
        (true, true) => Err(format!(
            "setsockopt-tls: {TCP_ULPS} lists tls, but the host gives {baseline} without the \
             filter, so the ULP did not attach"
        )),
        (false, false) => Err(format!(
            "setsockopt-tls: {TCP_ULPS} does not list tls, but the host gives {baseline} \
             without the filter"
        )),
    }
}

#[test]
fn tls_row_classification() {
    let (enoprotoopt, einval) = (libc::ENOPROTOOPT, libc::EINVAL);
    assert_eq!(
        tls_row_outcome(true, einval, enoprotoopt),
        Ok(RowOutcome::Observed)
    );
    assert_eq!(
        tls_row_outcome(false, enoprotoopt, enoprotoopt),
        Ok(RowOutcome::Gap)
    );
    assert!(tls_row_outcome(true, enoprotoopt, enoprotoopt).is_err());
    assert!(tls_row_outcome(false, einval, enoprotoopt).is_err());
    assert!(tls_row_outcome(true, einval, einval).is_err());
    assert!(tls_row_outcome(false, enoprotoopt, libc::EPERM).is_err());
    // Not a gap id: a list cannot name it.
    assert!(!support::KNOWN_GAPS.contains(&"setsockopt-tls"));
    assert!(KERNEL_ROWS.iter().any(|(id, _)| *id == "setsockopt-tls"));
}

/// The kernel rows that are tried only where the host has the module the
/// call would otherwise ask for (ADR-007 D2, "Module autoload"), with the
/// file that shows it: the probe never loads a module, on the host or
/// inside. Where the module is absent the row is untried and must be listed
/// in `BONELI_SYS_HOST_GAPS`; where it is present it must not be.
const MODULE_ROWS: [(&str, &str, &str); 2] = [
    ("socket-inet-packet", MODULE_PACKET_VAR, "/proc/net/packet"),
    ("ioctl-siocgifbr", MODULE_BRIDGE_VAR, "/sys/module/bridge"),
];

/// What a module row may do on this host: tried when its module is there.
fn module_row_untried(present: bool, listed: bool, id: &str) -> Result<bool, String> {
    match (present, listed) {
        (true, false) => Ok(false),
        (false, true) => Ok(true),
        (true, true) => Err(format!(
            "{id}: listed in BONELI_SYS_HOST_GAPS, but the host has the module, so the row is observable"
        )),
        (false, false) => Err(format!(
            "{id}: the host lacks the module the baseline would load, so the row is not tried; \
             list it in BONELI_SYS_HOST_GAPS"
        )),
    }
}

#[test]
fn module_row_classification() {
    assert_eq!(module_row_untried(true, false, "r"), Ok(false));
    assert_eq!(module_row_untried(false, true, "r"), Ok(true));
    assert!(module_row_untried(true, true, "r").is_err());
    assert!(module_row_untried(false, false, "r").is_err());
    for (id, _, _) in MODULE_ROWS {
        assert!(KERNEL_ROWS.iter().any(|(row, _)| *row == id), "{id}");
        assert!(support::KNOWN_GAPS.contains(&id), "{id}");
    }
}

fn row_value(p: &crate::support::Probe, id: &str) -> i32 {
    p.get(&format!("row:{id}"))
        .parse()
        .unwrap_or_else(|_| panic!("row {id} is not a number: {}", p.raw))
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp filters"]
fn seccomp_rows() {
    let gaps = support::host_gaps();
    let mut failures = Vec::new();
    // The module rows: tried in both runs only where the host has the
    // module, decided here on the host (the sandbox has no /sys).
    let mut env = Vec::new();
    let mut untried = Vec::new();
    for (id, var, shows) in MODULE_ROWS {
        let present = std::path::Path::new(shows).exists();
        match module_row_untried(present, gaps.contains(id), id) {
            Ok(true) => {
                report(&format!(
                    "seccomp_rows: {id} not tried ({shows} absent), listed in BONELI_SYS_HOST_GAPS"
                ));
                untried.push(id);
            }
            Ok(false) => env.push((var, "1")),
            // Not tried either: the failure says why.
            Err(e) => {
                failures.push(e);
                untried.push(id);
            }
        }
    }
    // The kTLS row: decided by the kernel's own ULP list, read here on the
    // host (the list is global, not per network namespace).
    let tls_ulp = std::fs::read_to_string(TCP_ULPS)
        .map(|t| t.split_whitespace().any(|u| u == "tls"))
        .unwrap_or(false);
    report(&format!("seccomp_rows: tls ULP available: {tls_ulp}"));
    // The baseline: the same calls on the host, without a filter, as the
    // unprivileged host user the sandbox maps to.
    let baseline = run_probe_host("seccomp-rows", &env);
    baseline.assert_ok();
    for inside in [0, 999] {
        let filtered = run_probe("seccomp-rows", ids(inside, inside), &env);
        filtered.assert_ok();
        for &(id, want) in KERNEL_ROWS {
            if untried.contains(&id) {
                for p in [&baseline, &filtered] {
                    if p.get(&format!("row:{id}")) != UNTRIED {
                        failures.push(format!("{id}: tried although its module is absent"));
                    }
                }
                continue;
            }
            let base = row_value(&baseline, id);
            let got = row_value(&filtered, id);
            let outcome = if id == "setsockopt-tls" {
                tls_row_outcome(tls_ulp, base, got)
            } else {
                classify_row(id, want, base, got, gaps.contains(id))
            };
            match outcome {
                Ok(RowOutcome::Gap) if id == "setsockopt-tls" => report(&format!(
                    "seccomp_rows: setsockopt-tls unobservable on this host (baseline {base}): \
                     {TCP_ULPS} does not list tls"
                )),
                Ok(RowOutcome::Gap) => report(&format!(
                    "seccomp_rows: {id} unobservable on this host (baseline {base}), \
                     listed in BONELI_SYS_HOST_GAPS"
                )),
                Ok(_) => {}
                Err(e) => failures.push(format!("inside id {inside}: {e}")),
            }
        }
    }
    // The arch row: an i386 call from a 64-bit process.
    if cfg!(target_arch = "x86_64") {
        let base = run_probe_host("int80", &[]);
        base.assert_ok();
        report(&format!(
            "seccomp_rows: int 0x80 getpid without the filter gave {}",
            base.get("int80")
        ));
        let p = run_probe("int80", ids(0, 0), &[]);
        if p.status != boneli_sys::ExitStatus::Signaled(libc::SIGSYS) {
            failures.push(format!(
                "int 0x80 inside was not killed with SIGSYS:\n{}",
                p.raw
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp filters"]
fn filter_covers_threads_children_and_stacking() {
    for inside in [0, 999] {
        let p = run_probe("filter-reach", ids(inside, inside), &[]);
        p.assert_ok();
        let eperm = libc::EPERM.to_string();
        assert_eq!(p.get("thread"), eperm, "a new thread: {}", p.raw);
        assert_eq!(p.get("fork"), eperm, "a forked child: {}", p.raw);
        // A filter of the workload's own goes on top; the strictest result
        // of all filters wins.
        assert_eq!(p.get("stack_errno"), "0", "{}", p.raw);
        assert_eq!(
            p.get("stacked"),
            eperm,
            "under an allow-all filter: {}",
            p.raw
        );
    }
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp filters"]
fn clone3_fallback_starts_threads() {
    // The probe itself runs in a libtest thread, started after the filter
    // was installed; the action starts one more.
    let p = run_probe("clone3-fallback", ids(0, 0), &[]);
    p.assert_ok();
    assert_eq!(p.get("clone3_errno"), libc::ENOSYS.to_string(), "{}", p.raw);
    assert_eq!(p.get("thread"), "0", "{}", p.raw);
}
