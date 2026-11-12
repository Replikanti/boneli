//! Boneli application layer.
//!
//! Use cases (`BuildEnvironment`, `OnboardRepo`, `DebugTicket`, `BuildCase`,
//! `RunBench`) and the ports they drive, as synchronous traits. Depends only
//! on `boneli-domain`; adapters implement the ports in their own crates.
//! The crate is `#![no_std]` with `alloc` (ADR-001).
//!
//! Design: `docs/ARCHITECTURE.md`, section "Code architecture".
#![no_std]
#![doc(test(attr(forbid(unsafe_code))))]
