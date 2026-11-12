//! Boneli domain.
//!
//! Types, run and case state machines, policies, gates and budget accounting.
//! Pure functions: no I/O, no wall clock, no threads, no async and no
//! external dependencies. The domain takes an event and returns a new state
//! and a list of commands; the application executes them through ports.
//!
//! The crate is `#![no_std]` with `alloc` (ADR-001): the architecture check
//! builds it for a target without `std`.
//!
//! Design: `docs/ARCHITECTURE.md`, sections "Code architecture" and
//! "Debugging line".
//!
//! # Doctests in this crate cannot use `unsafe` (ADR-001)
//!
//! The workspace lints do not reach doctests, so the crate root forbids
//! `unsafe` in them. This example must not compile:
//!
//! ```compile_fail
//! let x = 0u8;
//! let p = &x as *const u8;
//! let _ = unsafe { *p };
//! ```
#![no_std]
#![doc(test(attr(forbid(unsafe_code))))]
