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
