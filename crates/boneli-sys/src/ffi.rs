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
