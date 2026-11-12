//! Boneli application layer.
//!
//! Use cases (`BuildEnvironment`, `OnboardRepo`, `DebugTicket`, `BuildCase`,
//! `RunBench`) and the ports they drive, as synchronous traits. Depends only
//! on `boneli-domain`; adapters implement the ports in their own crates.
//!
//! Design: `docs/ARCHITECTURE.md`, section "Code architecture".
