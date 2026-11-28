//! Kernel interface items that libc 0.2.191 does not carry, each citing
//! its uapi header (Linux 7.2.4 headers). Where libc has the same name, a
//! compile-time assertion pins the two together.

/// `LANDLOCK_CREATE_RULESET_VERSION`, `include/uapi/linux/landlock.h`:
/// `landlock_create_ruleset(NULL, 0, this)` returns the ABI version.
pub(crate) const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

/// The highest signal number, `_NSIG` in `include/uapi/asm-generic/signal.h`
/// and `arch/x86/include/uapi/asm/signal.h` (both 64).
pub(crate) const NSIG: i32 = 64;

/// The kernel's signal set size in bytes, `_NSIG / 8`; `rt_sigaction` and
/// `rt_sigprocmask` reject any other `sigsetsize`.
pub(crate) const SIGSET_SIZE: usize = (NSIG / 8) as usize;

/// The kernel's `struct sigaction` for `rt_sigaction`: handler, flags,
/// restorer, mask (`include/uapi/asm-generic/signal.h` with `SA_RESTORER`,
/// which arm64 defines in `arch/arm64/include/uapi/asm/signal.h`;
/// `arch/x86/include/uapi/asm/signal.h` for x86_64). glibc's
/// `struct sigaction` has another layout, and its wrapper refuses the
/// signals it reserves (32 and 33), so the raw call is used.
#[repr(C)]
pub(crate) struct KernelSigaction {
    pub handler: usize,
    pub flags: u64,
    pub restorer: usize,
    pub mask: u64,
}

const _: () = assert!(SIGSET_SIZE == core::mem::size_of::<u64>());
const _: () = assert!(core::mem::size_of::<KernelSigaction>() == 32);
// libc's SIG_DFL is the handler value 0 the kernel expects.
const _: () = assert!(libc::SIG_DFL == 0);

/// `KEYCTL_JOIN_SESSION_KEYRING`, `include/uapi/linux/keyctl.h`: with a
/// NULL name, a new anonymous session keyring for the caller.
pub(crate) const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;

/// `OPEN_TREE_CLONE`, `include/uapi/linux/mount.h`: `open_tree` returns a
/// detached copy of the mount instead of the mount itself.
pub(crate) const OPEN_TREE_CLONE: u32 = 1 << 0;

/// `OPEN_TREE_CLOEXEC`, `include/uapi/linux/mount.h`: defined as `O_CLOEXEC`.
pub(crate) const OPEN_TREE_CLOEXEC: u32 = libc::O_CLOEXEC as u32;

/// `MOVE_MOUNT_F_EMPTY_PATH`, `include/uapi/linux/mount.h`: the source is
/// the descriptor itself.
pub(crate) const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x0000_0004;

/// `MOVE_MOUNT_T_EMPTY_PATH`, `include/uapi/linux/mount.h`: the target is
/// the descriptor itself.
pub(crate) const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x0000_0040;

/// `MOUNT_ATTR_RDONLY`, `include/uapi/linux/mount.h`.
pub(crate) const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
/// `MOUNT_ATTR_NOSUID`, `include/uapi/linux/mount.h`.
pub(crate) const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
/// `MOUNT_ATTR_NODEV`, `include/uapi/linux/mount.h`.
pub(crate) const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
/// `MOUNT_ATTR_NOEXEC`, `include/uapi/linux/mount.h`.
pub(crate) const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;

/// `struct mount_attr`, `include/uapi/linux/mount.h`, as first published
/// (`MOUNT_ATTR_SIZE_VER0`, 32 bytes).
#[repr(C)]
pub(crate) struct MountAttr {
    pub attr_set: u64,
    pub attr_clr: u64,
    pub propagation: u64,
    pub userns_fd: u64,
}

/// `MOUNT_ATTR_SIZE_VER0`, `include/uapi/linux/mount.h`.
pub(crate) const MOUNT_ATTR_SIZE_VER0: usize = 32;

/// `struct open_how`, `include/uapi/linux/openat2.h`. libc 0.2.191 has it,
/// but `#[non_exhaustive]`, so it cannot be built outside libc.
#[repr(C)]
pub(crate) struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}

const _: () = assert!(core::mem::size_of::<MountAttr>() == MOUNT_ATTR_SIZE_VER0);
const _: () = assert!(core::mem::size_of::<OpenHow>() == core::mem::size_of::<libc::open_how>());
const _: () = assert!(core::mem::size_of::<OpenHow>() == 24);

/// `CLONE_INTO_CGROUP`, `include/uapi/linux/sched.h`
/// (`0x200000000ULL`): `clone3` places the child in the cgroup whose
/// directory descriptor is `clone_args.cgroup`. libc 0.2.191 has it only
/// for glibc and as a `c_int`, which cannot hold it (deprecated there as
/// overflowing).
pub(crate) const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// `_LINUX_CAPABILITY_VERSION_3`, `include/uapi/linux/capability.h`: the
/// `capset` header version with two 32-bit data elements.
pub(crate) const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// `struct __user_cap_header_struct`, `include/uapi/linux/capability.h`.
#[repr(C)]
pub(crate) struct CapHeader {
    pub version: u32,
    pub pid: i32,
}

/// `struct __user_cap_data_struct`, `include/uapi/linux/capability.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CapData {
    pub effective: u32,
    pub permitted: u32,
    pub inheritable: u32,
}

const _: () = assert!(core::mem::size_of::<CapHeader>() == 8);
const _: () = assert!(core::mem::size_of::<CapData>() == 12);

/// `HUGETLBFS_MAGIC`, `include/uapi/linux/magic.h`: `f_type` of hugetlbfs.
pub(crate) const HUGETLBFS_MAGIC: u32 = 0x9584_58f6;

const _: () = assert!(libc::HUGETLBFS_MAGIC as u32 == HUGETLBFS_MAGIC);

/// `LANDLOCK_RULE_PATH_BENEATH`, `include/uapi/linux/landlock.h`.
pub(crate) const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
/// `LANDLOCK_RULE_NET_PORT`, `include/uapi/linux/landlock.h`.
pub(crate) const LANDLOCK_RULE_NET_PORT: u32 = 2;

/// `struct landlock_ruleset_attr`, `include/uapi/linux/landlock.h`, up to
/// `scoped` (ABI 6). The kernel accepts a struct of this size from ABI 1
/// on as long as the fields it does not know are zero.
#[repr(C)]
pub(crate) struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

/// `struct landlock_path_beneath_attr`, `include/uapi/linux/landlock.h`,
/// packed.
#[repr(C, packed)]
pub(crate) struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

/// `struct landlock_net_port_attr`, `include/uapi/linux/landlock.h`.
#[repr(C)]
pub(crate) struct LandlockNetPortAttr {
    pub allowed_access: u64,
    pub port: u64,
}

const _: () = assert!(core::mem::size_of::<LandlockRulesetAttr>() == 24);
const _: () = assert!(core::mem::size_of::<LandlockPathBeneathAttr>() == 12);
const _: () = assert!(core::mem::size_of::<LandlockNetPortAttr>() == 16);

/// The ancillary data of the listener message (ADR-043, D3): one
/// `struct cmsghdr` and room for two descriptors, laid out as `CMSG_DATA`
/// expects (`include/linux/socket.h`: the data starts at
/// `CMSG_ALIGN(sizeof(struct cmsghdr))`, 16 bytes on both architectures
/// and libcs). The child sends one descriptor; the parent receives into
/// room for two, so a message with more than one is seen, not cut to one.
#[repr(C, align(8))]
pub(crate) struct FdMessage {
    pub hdr: libc::cmsghdr,
    pub fds: [libc::c_int; 2],
}

/// `CMSG_LEN(0)`: the header without data.
// SAFETY: CMSG_LEN is pure arithmetic on its argument.
pub(crate) const CMSG_LEN_0: usize = unsafe { libc::CMSG_LEN(0) } as usize;
/// `CMSG_LEN(sizeof(int))`: the header with one descriptor.
// SAFETY: as above.
pub(crate) const CMSG_LEN_1: usize = unsafe { libc::CMSG_LEN(4) } as usize;
/// `CMSG_SPACE(sizeof(int))`: one descriptor's message with its padding.
// SAFETY: CMSG_SPACE is pure arithmetic on its argument.
pub(crate) const CMSG_SPACE_1: usize = unsafe { libc::CMSG_SPACE(4) } as usize;

const _: () = assert!(core::mem::offset_of!(FdMessage, fds) == CMSG_LEN_0);
const _: () = assert!(CMSG_LEN_0 == 16 && CMSG_LEN_1 == 20 && CMSG_SPACE_1 == 24);
// SAFETY: as above.
const _: () = assert!(core::mem::size_of::<FdMessage>() == unsafe { libc::CMSG_SPACE(8) } as usize);
