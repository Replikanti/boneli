//! Boneli support crate: the syscalls of the sandbox runtime and the only
//! crate with `unsafe` code (ADR-001, ADR-007).
//!
//! Generic plumbing without domain knowledge: it starts a program in a new
//! user namespace with a single id mapping ([`Ids`], ADR-007 D1), through a
//! raw `clone3` whose child runs a fixed setup sequence that allocates
//! nothing ([`spawn`], ADR-007 D4) and gives it new mount, PID, network,
//! IPC, UTS and cgroup namespaces with a read-only root ([`Root`], ADR-007
//! D7) inside a cgroup whose limits are in place before it starts
//! ([`Cgroup`], ADR-007 D8) and whose own thread keeps its memory
//! statistics fresh, so that a buffered writer is slowed rather than
//! OOM-killed ([`STATS_KEEPER_PERIOD`], ADR-007 D8), without any
//! capability, with `no_new_privs` and under a seccomp-bpf policy it
//! assembles itself ([`seccomp`], ADR-007 D2 and D9), whose denied calls a
//! supervisor thread of the caller answers and records
//! ([`Child::denials`], ADR-043). For a pod of several containers it
//! creates an [`Anchor`] per container, a no-exec clone that owns the
//! container's namespaces and holds its layer pins, and runs commands
//! joined to it, each PID 1 of a PID namespace of its own (ADR-042, D3);
//! the runner is the parent of all of them, so nothing else in its
//! process may reap with `waitpid(-1)` or ignore `SIGCHLD`. It applies
//! Landlock to the calling process ([`Ruleset`], ADR-007 D10), and it
//! checks that a host has what the runtime needs ([`Features::probe`],
//! ADR-007 D3, the floor Linux 6.1 by ADR-044). For tests that need a
//! process whose main thread has exited while another thread runs, it
//! can end the main thread alone
//! ([`exit_main_thread`], ADR-015 D10). The kernel is reached through `libc` only.
//!
//! The crate builds only for little-endian Linux on x86_64 and aarch64:
//! the syscall tables and the `seccomp_data` layout the runtime relies on
//! (ADR-007, D2) exist only for those.

#[cfg(not(all(
    target_os = "linux",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("boneli-sys supports only little-endian Linux on x86_64 and aarch64 (ADR-007)");

mod anchor;
mod cgroup;
mod child;
mod error;
mod ffi;
pub mod fs;
mod host;
mod ids;
mod keeper;
mod landlock;
mod layer;
mod mount;
mod privileges;
mod release;
mod report;
pub mod seccomp;
mod spawn;
mod thread;

pub use anchor::{Anchor, AnchorSpec, ExecSpec, Families, Fill};
pub use cgroup::{
    Cgroup, CpuMax, DeviceNumber, Frozen, IoLimits, IoMax, Limits, Parent, block_device_of,
    leaked_cgroups,
};
pub use child::Step;
pub use error::{Error, ListenerError, ProtocolError, Result};
pub use host::{Features, Missing, MissingId, NotifyGap};
pub use ids::Ids;
pub use keeper::{KeeperReport, STATS_KEEPER_PERIOD};
pub use landlock::{ABI_KNOWN, ABI_REQUIRED, Abi, AccessFs, AccessNet, Ruleset, Scope};
pub use layer::{make_fifo, make_whiteout, mark_opaque, sync_filesystem, user_xattr};
pub use mount::{DEV_ENTRIES, Hostname, InsidePath, Mount, OPTIONS_MAX, Root};
pub use privileges::SECUREBITS;
pub use spawn::{Child, ExitStatus, Spec, Stdio, spawn};
pub use thread::exit_main_thread;

#[cfg(test)]
mod test_guard;

#[cfg(test)]
#[global_allocator]
static GUARD: test_guard::Guard = test_guard::Guard;
