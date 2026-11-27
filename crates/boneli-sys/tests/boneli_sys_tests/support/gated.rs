//! The probe side of the census's host tests (ADR-007, D2): every gated
//! form of a `NeedsCap` entry, and of the `Row` entries' extra forms, as a
//! call the sandbox must fail without a capability (`caps-gated`), and the
//! `NotImplemented` entries (`nosys`).
//!
//! Each form makes its call with arguments that reach the capability check
//! and are harmless if the check passed: the current time for a clock, an
//! empty image for a module, the current hostname, a file of the probe's
//! own under `/tmp/cap`, the probe's own memory and namespaces. Syscalls
//! are made by number from the census extract of the build's architecture,
//! so a name the architecture lacks is skipped, and a call goes to the
//! kernel even where libc has no wrapper.

use std::ffi::CStr;
use std::sync::OnceLock;

use boneli_sys::seccomp::Arch;

use super::probe::{errno, fail, put};
use crate::census::{CENSUS, Verdict, extract, gated_forms};

/// The variable through which the test passes the host's mount namespace
/// id, which `statmount` and `listmount` name.
pub const HOST_MNTNS_VAR: &str = "BONELI_PROBE_HOST_MNTNS";

/// The probe's directory for its own files.
const DIR: &CStr = c"/tmp/cap";
/// A file of mode 0000 that the probe owns.
const MODE0: &CStr = c"/tmp/cap/m0";
/// A regular file of mode 0600 that the probe owns.
const FILE: &CStr = c"/tmp/cap/f";
/// An empty file, the image of `finit_module`.
const EMPTY: &CStr = c"/tmp/cap/empty";
/// An empty directory, the target of the mount forms.
const MNT: &CStr = c"/tmp/cap/mnt";
/// A character device node the probe tries to create.
const CHR: &CStr = c"/tmp/cap/chr";
/// The name of the capability xattr.
const CAPS_XATTR: &CStr = c"security.capability";

/// The numbers of the build's architecture, by name.
fn table() -> &'static crate::census::Extract {
    static TABLE: OnceLock<crate::census::Extract> = OnceLock::new();
    TABLE.get_or_init(|| extract(Arch::NATIVE))
}

/// Whether the build's architecture has the syscall `name`.
pub fn has(name: &str) -> bool {
    table().number(name).is_some()
}

/// A pointer or integer argument as the syscall ABI passes it.
fn p<T>(ptr: *const T) -> libc::c_long {
    ptr as libc::c_long
}

/// A pointer the kernel writes through, as the syscall ABI passes it.
fn pm<T>(ptr: *mut T) -> libc::c_long {
    ptr as libc::c_long
}

/// `syscall(<name>, args...)` with the native number: its errno, 0 when
/// it succeeded. A descriptor it returns is left open; the probe exits
/// right after its forms.
fn sc(name: &str, args: &[libc::c_long]) -> i32 {
    let nr = table()
        .number(name)
        .unwrap_or_else(|| fail(2, &format!("{name} is not in this architecture's table")));
    let mut a = [0 as libc::c_long; 6];
    a[..args.len()].copy_from_slice(args);
    // SAFETY: every form passes plain integers or pointers to memory it
    // owns, of the size the call reads or writes, for the call's duration.
    let rc = unsafe { libc::syscall(libc::c_long::from(nr), a[0], a[1], a[2], a[3], a[4], a[5]) };
    if rc < 0 { errno() } else { 0 }
}

/// A raw syscall by libc number that must succeed: its result.
fn must(what: &str, rc: libc::c_long) -> libc::c_long {
    if rc < 0 {
        fail(3, &format!("{what}: errno {}", errno()));
    }
    rc
}

/// An open descriptor of `path`.
fn open(path: &CStr, flags: libc::c_int) -> libc::c_long {
    // SAFETY: the path is NUL-terminated.
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
    must("open", libc::c_long::from(fd))
}

/// One anonymous page of the probe's own, mapped read-write.
fn page() -> libc::c_long {
    // SAFETY: an anonymous mapping with no address hint.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        fail(3, &format!("mmap: errno {}", errno()));
    }
    addr as libc::c_long
}

/// A `/proc/sys` number.
fn sysctl(path: &str) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or_else(|| fail(3, &format!("read {path}")))
}

/// Lowers a limit to 0, soft and hard: allowed without a capability, and
/// what the `rlimit-0`, `SHM_LOCK`, `MAP_LOCKED`, `raise-hard`,
/// `lower-nice` and `SCHED_FIFO` forms rely on, so a host's limits cannot
/// let a form pass without its capability.
fn zero_limit(resource: libc::c_long) {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: zero is a valid rlimit for the call's duration; no old limit
    // is read back.
    let rc = unsafe { libc::syscall(libc::SYS_prlimit64, 0, resource, &zero, 0) };
    if rc != 0 {
        fail(3, &format!("prlimit64({resource}, 0): errno {}", errno()));
    }
}

/// The files and limits the forms use.
fn prepare() {
    for (path, mode) in [(DIR, 0o700), (MNT, 0o700)] {
        // SAFETY: the path is NUL-terminated.
        let rc = unsafe { libc::mkdir(path.as_ptr(), mode) };
        if rc != 0 && errno() != libc::EEXIST {
            fail(3, &format!("mkdir {path:?}: errno {}", errno()));
        }
    }
    for path in [MODE0, FILE, EMPTY] {
        // SAFETY: the path is NUL-terminated.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
                0o600,
            )
        };
        must("create a probe file", libc::c_long::from(fd));
        // SAFETY: fd was opened here and nothing else owns it.
        unsafe { libc::close(fd) };
    }
    // SAFETY: the path is NUL-terminated.
    must(
        "chmod m0",
        libc::c_long::from(unsafe { libc::chmod(MODE0.as_ptr(), 0) }),
    );
    for r in [
        libc::RLIMIT_MEMLOCK,
        libc::RLIMIT_NICE,
        libc::RLIMIT_RTPRIO,
        libc::RLIMIT_CORE,
    ] {
        zero_limit(r as libc::c_long);
    }
}

/// A raw clone with `flags | SIGCHLD` and no stack, like fork; the child
/// exits at once. Its errno.
fn clone_flags(flags: libc::c_int) -> i32 {
    // SAFETY: without CLONE_VM the child runs on a copy of this stack and
    // only calls _exit.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::c_long::from(flags | libc::SIGCHLD),
            0,
            0,
            0,
            0,
        )
    };
    if pid == 0 {
        // SAFETY: _exit ends the cloned child without running anything.
        unsafe { libc::_exit(0) };
    }
    if pid > 0 {
        let mut st = 0;
        // SAFETY: st is valid storage; pid is this process's child.
        unsafe { libc::waitpid(pid as i32, &mut st, 0) };
        return 0;
    }
    errno()
}

/// `unshare(CLONE_NEWNS)` in a forked child (the probe runs in libtest's
/// thread): its errno.
fn unshare_newns() -> i32 {
    super::probe::in_fork(|| {
        // SAFETY: unshare takes plain flags.
        let rc = unsafe { libc::syscall(libc::SYS_unshare, libc::c_long::from(libc::CLONE_NEWNS)) };
        if rc < 0 { errno() } else { 0 }
    })
}

/// `sendmsg` (or `sendmmsg`) of one byte on a Unix datagram pair with
/// `SCM_CREDENTIALS` naming a pid other than the caller's.
fn send_credentials(mmsg: bool) -> i32 {
    let mut pair = [-1; 2];
    // SAFETY: pair is storage for two descriptors.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    };
    must("socketpair", libc::c_long::from(rc));
    // SAFETY: getpid, getuid and getgid cannot fail.
    let me = unsafe { libc::getpid() };
    let cred = libc::ucred {
        pid: if me == 1 { 2 } else { 1 },
        // SAFETY: as above.
        uid: unsafe { libc::getuid() },
        // SAFETY: as above.
        gid: unsafe { libc::getgid() },
    };
    // A cmsghdr (len, level, type) followed by the ucred, 8-byte aligned.
    let mut control = [0u64; 4];
    let hdr = std::mem::size_of::<libc::cmsghdr>();
    let len = hdr + std::mem::size_of::<libc::ucred>();
    let bytes: &mut [u8; 32] = bytemuck(&mut control);
    bytes[..std::mem::size_of::<usize>()].copy_from_slice(&len.to_ne_bytes());
    bytes[8..12].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
    bytes[12..16].copy_from_slice(&libc::SCM_CREDENTIALS.to_ne_bytes());
    bytes[hdr..hdr + 4].copy_from_slice(&cred.pid.to_ne_bytes());
    bytes[hdr + 4..hdr + 8].copy_from_slice(&cred.uid.to_ne_bytes());
    bytes[hdr + 8..hdr + 12].copy_from_slice(&cred.gid.to_ne_bytes());
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: an all-zero msghdr is a valid empty one.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = len as _;
    if mmsg {
        let mut m = libc::mmsghdr {
            msg_hdr: msg,
            msg_len: 0,
        };
        sc("sendmmsg", &[libc::c_long::from(pair[0]), pm(&mut m), 1, 0])
    } else {
        sc("sendmsg", &[libc::c_long::from(pair[0]), p(&msg), 0])
    }
}

/// The control buffer as bytes.
fn bytemuck(words: &mut [u64; 4]) -> &mut [u8; 32] {
    // SAFETY: [u64; 4] and [u8; 32] have the same size, u8 has no
    // alignment requirement and every byte pattern is a valid u8.
    unsafe { &mut *(words as *mut [u64; 4]).cast::<[u8; 32]>() }
}

/// A new socket that must succeed.
fn socket(family: libc::c_int, ty: libc::c_int) -> libc::c_long {
    // SAFETY: socket takes plain integers.
    let fd = unsafe { libc::socket(family, ty | libc::SOCK_CLOEXEC, 0) };
    must("socket", libc::c_long::from(fd))
}

fn bind_port_80() -> i32 {
    let fd = socket(libc::AF_INET, libc::SOCK_STREAM);
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 80u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([127, 0, 0, 1]).to_be(),
        },
        sin_zero: [0; 8],
    };
    sc(
        "bind",
        &[
            fd,
            p(&addr),
            std::mem::size_of::<libc::sockaddr_in>() as libc::c_long,
        ],
    )
}

fn so_mark() -> i32 {
    let fd = socket(libc::AF_INET, libc::SOCK_DGRAM);
    let one: libc::c_int = 1;
    sc(
        "setsockopt",
        &[
            fd,
            libc::c_long::from(libc::SOL_SOCKET),
            libc::c_long::from(libc::SO_MARK),
            p(&one),
            4,
        ],
    )
}

fn shm_lock() -> i32 {
    // SAFETY: shmget takes plain integers.
    let id = unsafe { libc::shmget(libc::IPC_PRIVATE, 4096, libc::IPC_CREAT | 0o600) };
    must("shmget", libc::c_long::from(id));
    let r = sc(
        "shmctl",
        &[
            libc::c_long::from(id),
            libc::c_long::from(libc::SHM_LOCK),
            0,
        ],
    );
    // SAFETY: id is the segment created above; IPC_RMID takes no buffer.
    unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
    r
}

fn msg_qbytes() -> i32 {
    // SAFETY: msgget takes plain integers.
    let id = unsafe { libc::msgget(libc::IPC_PRIVATE, libc::IPC_CREAT | 0o600) };
    must("msgget", libc::c_long::from(id));
    // SAFETY: an all-zero msqid_ds is valid storage for IPC_STAT.
    let mut ds: libc::msqid_ds = unsafe { std::mem::zeroed() };
    // SAFETY: ds is valid storage for IPC_STAT.
    must(
        "msgctl IPC_STAT",
        libc::c_long::from(unsafe { libc::msgctl(id, libc::IPC_STAT, &mut ds) }),
    );
    ds.msg_qbytes = (sysctl("/proc/sys/kernel/msgmnb") + 1) as _;
    let r = sc(
        "msgctl",
        &[
            libc::c_long::from(id),
            libc::c_long::from(libc::IPC_SET),
            p(&ds),
        ],
    );
    // SAFETY: id is the queue created above; IPC_RMID takes no buffer.
    unsafe { libc::msgctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
    r
}

fn pipe_size() -> i32 {
    let mut fds = [-1; 2];
    // SAFETY: fds is storage for two descriptors.
    must(
        "pipe2",
        libc::c_long::from(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }),
    );
    let over = 2 * sysctl("/proc/sys/fs/pipe-max-size");
    sc(
        "fcntl",
        &[
            libc::c_long::from(fds[0]),
            libc::c_long::from(libc::F_SETPIPE_SZ),
            over as libc::c_long,
        ],
    )
}

fn capset_inheritable() -> i32 {
    // _LINUX_CAPABILITY_VERSION_3 and pid 0, then two data words: the
    // inheritable set gains CAP_CHOWN beyond the empty permitted set.
    let header: [u32; 2] = [0x2008_0522, 0];
    let data: [u32; 6] = [0, 0, 1, 0, 0, 0];
    sc("capset", &[p(&header), p(&data)])
}

/// `makedev(1, 3)`, the number of `/dev/null`.
const NULL_DEV: libc::c_long = (1 << 8) | 3;

fn lower_nice() -> i32 {
    // Raising the nice value needs nothing; lowering it again does.
    // SAFETY: setpriority takes plain integers.
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 5) };
    must("setpriority(5)", libc::c_long::from(rc));
    sc(
        "setpriority",
        &[libc::c_long::from(libc::PRIO_PROCESS), 0, 4],
    )
}

fn sched_fifo() -> i32 {
    let param: libc::c_int = 1;
    sc(
        "sched_setscheduler",
        &[0, libc::c_long::from(libc::SCHED_FIFO), p(&param)],
    )
}

fn sched_attr_fifo() -> i32 {
    // struct sched_attr, SCHED_ATTR_SIZE_VER0 (48 bytes): size, policy,
    // flags (u64), nice, priority, runtime, deadline, period.
    let mut attr = [0u32; 12];
    attr[0] = 48;
    attr[1] = libc::SCHED_FIFO as u32;
    attr[5] = 1;
    sc("sched_setattr", &[0, p(&attr), 0])
}

fn map_locked() -> i32 {
    // SAFETY: an anonymous mapping with no address hint.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_LOCKED,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED { errno() } else { 0 }
}

fn set_tick(name: &str) -> i32 {
    // SAFETY: an all-zero timex reads the clock state (modes 0).
    let mut t: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: t is valid storage for the call's duration.
    must(
        "adjtimex(0)",
        libc::c_long::from(unsafe { libc::adjtimex(&mut t) }),
    );
    t.modes = libc::ADJ_TICK;
    if name == "adjtimex" {
        sc("adjtimex", &[p(&t)])
    } else {
        sc(
            "clock_adjtime",
            &[libc::c_long::from(libc::CLOCK_REALTIME), p(&t)],
        )
    }
}

fn raise_hard(name: &str) -> i32 {
    // RLIMIT_CORE was set to 0/0 by `prepare`.
    let one = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 1,
    };
    let core = libc::RLIMIT_CORE as libc::c_long;
    if name == "setrlimit" {
        sc("setrlimit", &[core, p(&one)])
    } else {
        sc("prlimit64", &[0, core, p(&one), 0])
    }
}

fn set_now(name: &str) -> i32 {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: tv is valid storage; no timezone.
    must(
        "gettimeofday",
        libc::c_long::from(unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) }),
    );
    if name == "settimeofday" {
        return sc("settimeofday", &[p(&tv), 0]);
    }
    let ts = libc::timespec {
        tv_sec: tv.tv_sec,
        tv_nsec: tv.tv_usec * 1000,
    };
    sc(
        "clock_settime",
        &[libc::c_long::from(libc::CLOCK_REALTIME), p(&ts)],
    )
}

fn same_name(name: &str) -> i32 {
    // SAFETY: an all-zero utsname is valid storage for uname.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: u is valid storage for the call's duration.
    must("uname", libc::c_long::from(unsafe { libc::uname(&mut u) }));
    let field = if name == "sethostname" {
        &u.nodename
    } else {
        &u.domainname
    };
    let len = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    sc(name, &[p(field.as_ptr()), len as libc::c_long])
}

fn finit_empty() -> i32 {
    let fd = open(EMPTY, libc::O_RDONLY);
    sc("finit_module", &[fd, p(c"".as_ptr()), 0])
}

/// `struct vfs_cap_data` of revision 2 with empty sets, 20 bytes.
const CAP_V2: [u32; 5] = [0x0200_0000, 0, 0, 0, 0];

fn set_caps_xattr(name: &str) -> i32 {
    let value = p(CAP_V2.as_ptr());
    let name_p = p(CAPS_XATTR.as_ptr());
    match name {
        "setxattr" | "lsetxattr" => sc(name, &[p(FILE.as_ptr()), name_p, value, 20, 0]),
        "fsetxattr" => sc(name, &[open(FILE, libc::O_RDONLY), name_p, value, 20, 0]),
        // struct xattr_args: value (u64), size (u32), flags (u32).
        _ => {
            let args: [u64; 2] = [CAP_V2.as_ptr() as u64, 20];
            sc(
                "setxattrat",
                &[
                    libc::c_long::from(libc::AT_FDCWD),
                    p(FILE.as_ptr()),
                    0,
                    name_p,
                    p(&args),
                    16,
                ],
            )
        }
    }
}

fn remove_caps_xattr(name: &str) -> i32 {
    let name_p = p(CAPS_XATTR.as_ptr());
    match name {
        "removexattr" | "lremovexattr" => sc(name, &[p(FILE.as_ptr()), name_p]),
        "fremovexattr" => sc(name, &[open(FILE, libc::O_RDONLY), name_p]),
        _ => sc(
            "removexattrat",
            &[
                libc::c_long::from(libc::AT_FDCWD),
                p(FILE.as_ptr()),
                0,
                name_p,
            ],
        ),
    }
}

/// `CLOCK_REALTIME_ALARM`.
const REALTIME_ALARM: libc::c_long = 8;

fn alarm_clock(name: &str) -> i32 {
    match name {
        "timer_create" => {
            let mut id: libc::c_int = 0;
            sc("timer_create", &[REALTIME_ALARM, 0, pm(&mut id)])
        }
        "clock_nanosleep" => {
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 1,
            };
            sc("clock_nanosleep", &[REALTIME_ALARM, 0, p(&ts), 0])
        }
        _ => sc(
            "timerfd_create",
            &[REALTIME_ALARM, libc::c_long::from(libc::TFD_CLOEXEC)],
        ),
    }
}

/// `MPOL_MF_MOVE_ALL`, `include/uapi/linux/mempolicy.h`.
const MPOL_MF_MOVE_ALL: libc::c_long = 1 << 2;

fn mq_maxmsg() -> i32 {
    // struct mq_attr: flags, maxmsg, msgsize, curmsgs, four reserved longs.
    let attr: [libc::c_long; 8] = [
        0,
        (sysctl("/proc/sys/fs/mqueue/msg_max") + 1) as libc::c_long,
        8,
        0,
        0,
        0,
        0,
        0,
    ];
    sc(
        "mq_open",
        &[
            p(c"boneli-cap".as_ptr()),
            libc::c_long::from(libc::O_CREAT | libc::O_RDWR),
            0o600,
            p(&attr),
        ],
    )
}

fn fanotify_mount_mark() -> i32 {
    // An unprivileged group, which must report file ids, then a mount
    // mark, which needs CAP_SYS_ADMIN over the group's user namespace.
    const FAN_REPORT_FID: libc::c_uint = 0x200;
    const FAN_MARK_ADD: libc::c_uint = 0x1;
    const FAN_MARK_MOUNT: libc::c_uint = 0x10;
    const FAN_MODIFY: u64 = 0x2;
    // SAFETY: fanotify_init takes plain flags.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            libc::c_long::from(FAN_REPORT_FID),
            libc::c_long::from(libc::O_RDONLY),
        )
    };
    must("fanotify_init(FAN_REPORT_FID)", fd);
    sc(
        "fanotify_mark",
        &[
            fd,
            libc::c_long::from(FAN_MARK_ADD | FAN_MARK_MOUNT),
            FAN_MODIFY as libc::c_long,
            libc::c_long::from(libc::AT_FDCWD),
            p(DIR.as_ptr()),
        ],
    )
}

fn open_dir_handle() -> i32 {
    // struct file_handle: handle_bytes (u32), handle_type (i32), then the
    // handle; 128 bytes of handle (MAX_HANDLE_SZ).
    let mut handle = [0u32; 34];
    handle[0] = 128;
    let mut mount_id: libc::c_int = 0;
    let rc = sc(
        "name_to_handle_at",
        &[
            libc::c_long::from(libc::AT_FDCWD),
            p(DIR.as_ptr()),
            p(handle.as_mut_ptr()),
            pm(&mut mount_id),
            0,
        ],
    );
    if rc != 0 {
        fail(3, &format!("name_to_handle_at: errno {rc}"));
    }
    let mfd = open(DIR, libc::O_RDONLY | libc::O_DIRECTORY);
    sc(
        "open_by_handle_at",
        &[
            mfd,
            p(handle.as_ptr()),
            libc::c_long::from(libc::O_RDONLY | libc::O_DIRECTORY),
        ],
    )
}

fn setns_own_net() -> i32 {
    let fd = open(c"/proc/self/ns/net", libc::O_RDONLY);
    sc("setns", &[fd, libc::c_long::from(libc::CLONE_NEWNET)])
}

fn madvise_other() -> i32 {
    let addr = page();
    // SAFETY: fork has no memory arguments; the child only pauses until
    // it is killed.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        loop {
            // SAFETY: pause takes no arguments.
            unsafe { libc::pause() };
        }
    }
    must("fork", libc::c_long::from(pid));
    // SAFETY: pidfd_open takes plain integers.
    let pidfd = must("pidfd_open", unsafe {
        libc::syscall(libc::SYS_pidfd_open, pid, 0)
    });
    let iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: 4096,
    };
    let r = sc(
        "process_madvise",
        &[pidfd, p(&iov), 1, libc::c_long::from(libc::MADV_COLD), 0],
    );
    // SAFETY: pid is this process's child.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut st = 0;
    // SAFETY: st is valid storage; pid is this process's child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    r
}

/// The host's mount namespace id, passed in by the test.
fn host_mntns() -> u64 {
    std::env::var(HOST_MNTNS_VAR)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| fail(2, &format!("{HOST_MNTNS_VAR} is not a number")))
}

fn foreign_mounts(name: &str) -> i32 {
    // struct mnt_id_req, MNT_ID_REQ_SIZE_VER1 (32 bytes): size, mnt_ns_fd,
    // mnt_id, param, mnt_ns_id.
    const LSMT_ROOT: u64 = u64::MAX;
    let req: [u64; 4] = [
        32,
        LSMT_ROOT,
        if name == "statmount" { 1 } else { 0 },
        host_mntns(),
    ];
    let mut buf = [0u64; 512];
    let size = if name == "statmount" { 4096 } else { 512 };
    sc(name, &[p(&req), p(buf.as_mut_ptr()), size, 0])
}

fn clear_rdonly_root() -> i32 {
    // struct mount_attr: attr_set, attr_clr, propagation, userns_fd.
    let attr: [u64; 4] = [0, libc::MOUNT_ATTR_RDONLY, 0, 0];
    sc(
        "mount_setattr",
        &[
            libc::c_long::from(libc::AT_FDCWD),
            p(c"/".as_ptr()),
            0,
            p(&attr),
            32,
        ],
    )
}

fn file_setattr_immutable() -> i32 {
    // struct file_attr, FILE_ATTR_SIZE_VER0 (24 bytes): fa_xflags (u64,
    // FS_XFLAG_IMMUTABLE 0x8), extsize, nextents, projid, cowextsize.
    let attr: [u64; 3] = [0x8, 0, 0];
    sc(
        "file_setattr",
        &[
            libc::c_long::from(libc::AT_FDCWD),
            p(FILE.as_ptr()),
            p(&attr),
            24,
            0,
        ],
    )
}

fn setflags_immutable() -> i32 {
    const FS_IOC_SETFLAGS: libc::c_long = 0x4008_6602;
    const FS_IMMUTABLE_FL: libc::c_int = 0x10;
    let fd = open(FILE, libc::O_RDONLY);
    sc("ioctl", &[fd, FS_IOC_SETFLAGS, p(&FS_IMMUTABLE_FL)])
}

fn hwpoison() -> i32 {
    // A page that was mapped and is not any more: if the check passed,
    // the call would fail on the address.
    let addr = page();
    // SAFETY: addr is the page mapped above, of that size.
    unsafe { libc::munmap(addr as *mut libc::c_void, 4096) };
    const MADV_HWPOISON: libc::c_long = 100;
    sc("madvise", &[addr, 4096, MADV_HWPOISON])
}

fn at(path: &CStr) -> [libc::c_long; 2] {
    [libc::c_long::from(libc::AT_FDCWD), p(path.as_ptr())]
}

/// A form of the census and the call that shows it.
pub type GatedForm = (&'static str, &'static str, fn() -> i32);

/// Every gated form, by census name and form name; `census_needs_cap_have_probes`
/// requires this list to equal the census's forms.
pub const GATED_FORMS: &[GatedForm] = &[
    ("open", "mode-0000", || {
        sc(
            "open",
            &[p(MODE0.as_ptr()), libc::c_long::from(libc::O_RDONLY)],
        )
    }),
    ("mmap", "MAP_LOCKED", map_locked),
    ("ioctl", "FS_IOC_SETFLAGS-immutable", setflags_immutable),
    ("access", "mode-0000", || {
        sc(
            "access",
            &[p(MODE0.as_ptr()), libc::c_long::from(libc::R_OK)],
        )
    }),
    ("madvise", "MADV_HWPOISON", hwpoison),
    ("shmctl", "SHM_LOCK", shm_lock),
    ("socket", "SOCK_RAW", || {
        sc(
            "socket",
            &[
                libc::c_long::from(libc::AF_INET),
                libc::c_long::from(libc::SOCK_RAW | libc::SOCK_CLOEXEC),
                libc::c_long::from(libc::IPPROTO_TCP),
            ],
        )
    }),
    ("sendmsg", "SCM_CREDENTIALS", || send_credentials(false)),
    ("bind", "port-80", bind_port_80),
    ("setsockopt", "SO_MARK", so_mark),
    ("clone", "CLONE_NEWNS", || clone_flags(libc::CLONE_NEWNS)),
    ("msgctl", "IPC_SET-qbytes", msg_qbytes),
    ("fcntl", "F_SETPIPE_SZ", pipe_size),
    ("creat", "mode-0000", || {
        sc("creat", &[p(MODE0.as_ptr()), 0o600])
    }),
    ("capset", "raise-inheritable", capset_inheritable),
    ("mknod", "char-device", || {
        sc(
            "mknod",
            &[
                p(CHR.as_ptr()),
                libc::c_long::from(libc::S_IFCHR | 0o600),
                NULL_DEV,
            ],
        )
    }),
    ("setpriority", "lower-nice", lower_nice),
    ("sched_setscheduler", "SCHED_FIFO", sched_fifo),
    ("mlock", "rlimit-0", || sc("mlock", &[page(), 4096])),
    ("mlockall", "rlimit-0", || {
        sc("mlockall", &[libc::c_long::from(libc::MCL_CURRENT)])
    }),
    ("vhangup", "self", || sc("vhangup", &[])),
    ("pivot_root", "dot", || {
        sc("pivot_root", &[p(c".".as_ptr()), p(c".".as_ptr())])
    }),
    ("prctl", "PR_CAPBSET_DROP", || {
        sc("prctl", &[libc::c_long::from(libc::PR_CAPBSET_DROP), 0])
    }),
    ("adjtimex", "set-tick", || set_tick("adjtimex")),
    ("setrlimit", "raise-hard", || raise_hard("setrlimit")),
    ("chroot", "slash", || sc("chroot", &[p(c"/".as_ptr())])),
    ("acct", "off", || sc("acct", &[0])),
    ("settimeofday", "now", || set_now("settimeofday")),
    ("mount", "tmpfs", || {
        sc(
            "mount",
            &[
                p(c"none".as_ptr()),
                p(MNT.as_ptr()),
                p(c"tmpfs".as_ptr()),
                0,
                0,
            ],
        )
    }),
    ("mount", "remount-root-rw", || {
        sc(
            "mount",
            &[
                0,
                p(c"/".as_ptr()),
                0,
                (libc::MS_REMOUNT | libc::MS_BIND) as libc::c_long,
                0,
            ],
        )
    }),
    ("umount2", "proc", || {
        sc("umount2", &[p(c"/proc".as_ptr()), 0])
    }),
    ("swapon", "file", || sc("swapon", &[p(FILE.as_ptr()), 0])),
    ("swapoff", "file", || sc("swapoff", &[p(FILE.as_ptr())])),
    ("reboot", "cad-off", || {
        sc(
            "reboot",
            &[
                libc::c_long::from(libc::LINUX_REBOOT_MAGIC1),
                libc::c_long::from(libc::LINUX_REBOOT_MAGIC2),
                libc::c_long::from(libc::LINUX_REBOOT_CMD_CAD_OFF),
                0,
            ],
        )
    }),
    ("sethostname", "same", || same_name("sethostname")),
    ("setdomainname", "same", || same_name("setdomainname")),
    ("iopl", "3", || sc("iopl", &[3])),
    ("ioperm", "port-0x80", || sc("ioperm", &[0x80, 1, 1])),
    ("init_module", "empty", || {
        let image = [0u8; 1];
        sc("init_module", &[p(image.as_ptr()), 0, p(c"".as_ptr())])
    }),
    ("delete_module", "none", || {
        sc(
            "delete_module",
            &[
                p(c"boneli_none".as_ptr()),
                libc::c_long::from(libc::O_NONBLOCK),
            ],
        )
    }),
    ("setxattr", "security.capability", || {
        set_caps_xattr("setxattr")
    }),
    ("lsetxattr", "security.capability", || {
        set_caps_xattr("lsetxattr")
    }),
    ("fsetxattr", "security.capability", || {
        set_caps_xattr("fsetxattr")
    }),
    ("removexattr", "security.capability", || {
        remove_caps_xattr("removexattr")
    }),
    ("lremovexattr", "security.capability", || {
        remove_caps_xattr("lremovexattr")
    }),
    ("fremovexattr", "security.capability", || {
        remove_caps_xattr("fremovexattr")
    }),
    ("lookup_dcookie", "null", || {
        sc("lookup_dcookie", &[0, 0, 0])
    }),
    ("timer_create", "CLOCK_REALTIME_ALARM", || {
        alarm_clock("timer_create")
    }),
    ("clock_settime", "now", || set_now("clock_settime")),
    ("clock_nanosleep", "CLOCK_REALTIME_ALARM", || {
        alarm_clock("clock_nanosleep")
    }),
    ("mbind", "MPOL_MF_MOVE_ALL", || {
        sc("mbind", &[page(), 4096, 0, 0, 0, MPOL_MF_MOVE_ALL])
    }),
    ("mq_open", "maxmsg", mq_maxmsg),
    ("kexec_load", "zero-segments", || {
        sc("kexec_load", &[0, 0, 0, 0])
    }),
    ("ioprio_set", "RT", || sc("ioprio_set", &[1, 0, 1 << 13])),
    ("openat", "mode-0000", || {
        let [d, f] = at(MODE0);
        sc("openat", &[d, f, libc::c_long::from(libc::O_RDONLY)])
    }),
    ("mknodat", "char-device", || {
        let [d, f] = at(CHR);
        sc(
            "mknodat",
            &[d, f, libc::c_long::from(libc::S_IFCHR | 0o600), NULL_DEV],
        )
    }),
    ("faccessat", "mode-0000", || {
        let [d, f] = at(MODE0);
        sc("faccessat", &[d, f, libc::c_long::from(libc::R_OK)])
    }),
    ("unshare", "CLONE_NEWNS", unshare_newns),
    ("move_pages", "MPOL_MF_MOVE_ALL", || {
        sc("move_pages", &[0, 0, 0, 0, 0, MPOL_MF_MOVE_ALL])
    }),
    ("timerfd_create", "CLOCK_REALTIME_ALARM", || {
        alarm_clock("timerfd_create")
    }),
    ("fanotify_init", "FAN_CLASS_CONTENT", || {
        sc("fanotify_init", &[0x4, libc::c_long::from(libc::O_RDONLY)])
    }),
    ("fanotify_mark", "FAN_MARK_MOUNT", fanotify_mount_mark),
    ("prlimit64", "raise-hard", || raise_hard("prlimit64")),
    ("open_by_handle_at", "dir-handle", open_dir_handle),
    ("clock_adjtime", "set-tick", || set_tick("clock_adjtime")),
    ("sendmmsg", "SCM_CREDENTIALS", || send_credentials(true)),
    ("setns", "own-netns", setns_own_net),
    ("finit_module", "empty", finit_empty),
    ("sched_setattr", "SCHED_FIFO", sched_attr_fifo),
    ("kexec_file_load", "unload", || {
        sc("kexec_file_load", &[-1, -1, 0, 0, 1])
    }),
    ("mlock2", "rlimit-0", || sc("mlock2", &[page(), 4096, 0])),
    ("open_tree", "OPEN_TREE_CLONE", || {
        let [d, f] = at(c"/tmp");
        sc(
            "open_tree",
            &[d, f, 1 | libc::c_long::from(libc::O_CLOEXEC)],
        )
    }),
    ("move_mount", "tmp", || {
        let [d, from] = at(c"/tmp");
        sc("move_mount", &[d, from, d, p(MNT.as_ptr()), 0])
    }),
    ("fsopen", "tmpfs", || {
        sc("fsopen", &[p(c"tmpfs".as_ptr()), 0])
    }),
    ("fsmount", "no-context", || sc("fsmount", &[-1, 0, 0])),
    ("fspick", "root", || {
        let [d, f] = at(c"/");
        sc("fspick", &[d, f, 0])
    }),
    ("openat2", "mode-0000", || {
        // struct open_how: flags, mode, resolve.
        let how: [u64; 3] = [libc::O_RDONLY as u64, 0, 0];
        let [d, f] = at(MODE0);
        sc("openat2", &[d, f, p(&how), 24])
    }),
    ("faccessat2", "mode-0000", || {
        let [d, f] = at(MODE0);
        sc("faccessat2", &[d, f, libc::c_long::from(libc::R_OK), 0])
    }),
    ("process_madvise", "other-process", madvise_other),
    ("mount_setattr", "root-clear-rdonly", clear_rdonly_root),
    ("statmount", "host-namespace", || {
        foreign_mounts("statmount")
    }),
    ("listmount", "host-namespace", || {
        foreign_mounts("listmount")
    }),
    ("setxattrat", "security.capability", || {
        set_caps_xattr("setxattrat")
    }),
    ("removexattrat", "security.capability", || {
        remove_caps_xattr("removexattrat")
    }),
    ("open_tree_attr", "OPEN_TREE_CLONE", || {
        let [d, f] = at(c"/tmp");
        sc("open_tree_attr", &[d, f, 1, 0, 0])
    }),
    ("file_setattr", "immutable", file_setattr_immutable),
];

/// `caps-gated`: every gated form of the census whose syscall this
/// architecture has, as `cap:<name>:<form>=<errno>` in census order.
pub fn caps_gated() {
    prepare();
    for (name, form) in gated_forms() {
        if !has(name) {
            continue;
        }
        let call = GATED_FORMS
            .iter()
            .find(|(n, f, _)| *n == name && *f == form.form)
            .map(|(_, _, call)| *call)
            .unwrap_or_else(|| fail(2, &format!("no probe for {name}:{}", form.form)));
        put(&format!("cap:{name}:{}", form.form), &call().to_string());
    }
}

/// `nosys`: every `NotImplemented` entry this architecture has, called with
/// zeroed arguments, as `nosys:<name>=<errno>`.
pub fn nosys() {
    for e in CENSUS {
        if matches!(e.verdict, Verdict::NotImplemented) && has(e.name) {
            put(&format!("nosys:{}", e.name), &sc(e.name, &[]).to_string());
        }
    }
}
