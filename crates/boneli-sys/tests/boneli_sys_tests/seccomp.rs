//! The seccomp policy (ADR-007, D2): the program the assembler builds,
//! run through the test interpreter (`support::bpf`) for both
//! architectures, and the real program in the kernel (`seccomp_rows`).
//!
//! The pure tests take their syscall numbers from the uapi 7.2.4 table in
//! ADR-007 D2, written out here, not from `boneli_sys::seccomp::table`, so
//! a wrong number in the library fails them instead of moving with them.

use boneli_sys::seccomp::{Arch, CEILING, Policy, errno_action};

use crate::support::bpf::{ALLOW, Data, program, run};
use crate::support::{self, ids, report, run_probe, run_probe_host};

const EPERM: u32 = errno_action(libc::EPERM);
const ENOSYS: u32 = errno_action(libc::ENOSYS);
const EAFNOSUPPORT: u32 = errno_action(libc::EAFNOSUPPORT);
const EPROTONOSUPPORT: u32 = errno_action(libc::EPROTONOSUPPORT);
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
const PROGRAM_LEN: usize = 56;

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
    ("netlink-netfilter", libc::EPROTONOSUPPORT),
    ("netlink-route", 0),
    ("socketpair-inet", libc::EAFNOSUPPORT),
    ("mmap-hugetlb", libc::EPERM),
    ("memfd-hugetlb", libc::EPERM),
    ("shmget-hugetlb", libc::EPERM),
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
    // Every gap id of the kernel rows is a row.
    for gap in ["syslog", "shmget-hugetlb"] {
        assert!(KERNEL_ROWS.iter().any(|(id, _)| *id == gap), "{gap}");
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
    // The baseline: the same calls on the host, without a filter, as the
    // unprivileged host user the sandbox maps to.
    let baseline = run_probe_host("seccomp-rows", &[]);
    baseline.assert_ok();
    let mut failures = Vec::new();
    for inside in [0, 999] {
        let filtered = run_probe("seccomp-rows", ids(inside, inside), &[]);
        filtered.assert_ok();
        for &(id, want) in KERNEL_ROWS {
            let base = row_value(&baseline, id);
            let got = row_value(&filtered, id);
            match classify_row(id, want, base, got, gaps.contains(id)) {
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
