//! Boneli support crate: the syscalls of the sandbox runtime and the only
//! crate with `unsafe` code (ADR-001, ADR-007).
//!
//! Generic plumbing without domain knowledge: it starts a program in a new
//! user namespace with a single id mapping ([`Ids`], ADR-007 D1), through a
//! raw `clone3` whose child runs a fixed setup sequence that allocates
//! nothing ([`spawn`], ADR-007 D4), and it checks that a host has what the
//! runtime needs ([`Features::probe`], ADR-007 D3). The kernel is reached
//! through `libc` only.
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

mod child;
mod error;
mod ffi;
mod host;
mod ids;
mod report;
mod spawn;

pub use child::Step;
pub use error::{Error, ProtocolError, Result};
pub use host::{Features, Missing, MissingId};
pub use ids::Ids;
pub use spawn::{Child, ExitStatus, Spec, Stdio, spawn};

#[cfg(test)]
mod test_guard;

#[cfg(test)]
#[global_allocator]
static GUARD: test_guard::Guard = test_guard::Guard;
