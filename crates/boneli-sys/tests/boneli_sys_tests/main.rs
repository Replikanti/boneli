//! Tests of `boneli-sys` (ADR-007, D5).
//!
//! One integration test target, so that the AppArmor profile of the
//! host-setup block in `CLAUDE.md` names exactly two binaries: the unit
//! tests (`boneli_sys-<hash>`) and this one (`boneli_sys_tests-<hash>`).
//!
//! Tests that create a user namespace are `#[ignore = "host: ..."]` and run
//! with `cargo test -p boneli-sys -- --ignored`; a missing host feature fails
//! them with the probe's message, never skips them. The pure tests run in
//! every `cargo test`.
//!
//! The test `probe` is this binary's probe mode: the host tests re-execute
//! the binary inside the sandbox with `--exact probe --nocapture` and
//! `BONELI_SYS_PROBE=<action>`, and it prints `BONELI_PROBE key=value`
//! lines. Without that variable it does nothing.

mod cgroups;
mod host_setup;
mod mounts;
mod namespaces;
mod probe;
mod spawn;
mod support;
mod userns;

#[global_allocator]
static GUARD: support::alloc_guard::Guard = support::alloc_guard::Guard;

/// The probe mode (see the crate docs); a no-op in a normal test run.
#[test]
fn probe() {
    if let Some(action) = std::env::var_os(support::probe::ACTION_VAR) {
        support::probe::main(&action.to_string_lossy());
    }
}
