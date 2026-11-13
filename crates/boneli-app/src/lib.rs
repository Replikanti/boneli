//! Boneli application layer.
//!
//! Use cases (`BuildEnvironment`, `OnboardRepo`, `DebugTicket`, `BuildCase`,
//! `RunBench`) and the ports they drive, as synchronous traits. Depends only
//! on `boneli-domain`; adapters implement the ports in their own crates.
//! The crate is `#![no_std]` with `alloc` (ADR-001).
//!
//! Design: `docs/ARCHITECTURE.md`, section "Code architecture"; the ports,
//! the contract suites and `DebugTicket` are fixed in ADR-004
//! (`docs/adr/004-ports-in-memory-adapters-and-debug-ticket.md`).
//!
//! The ports are object-safe traits with `&self` methods, one module each:
//! [`Agent`], [`Verifier`], [`Forge`], [`EventStore`], [`Evidence`],
//! [`Clock`] and [`Ids`]. [`DebugTicket`] drives one run through them.
//! [`contract`] holds the suites every adapter of a port must pass; the
//! in-memory adapters live in the `boneli-memory` crate.
#![no_std]
#![doc(test(attr(forbid(unsafe_code))))]

extern crate alloc;

pub mod agent;
pub mod clock;
pub mod contract;
pub mod debug_ticket;
pub mod evidence;
pub mod forge;
pub mod ids;
pub mod job;
pub mod store;
pub mod verifier;

pub use agent::{
    Agent, FixRequest, PreviousTriage, ReproductionRequest, RootCauseReport, RootCauseRequest,
    TriageReport, TriageRequest, Written,
};
pub use clock::Clock;
pub use debug_ticket::{
    DebugReport, DebugRequest, DebugTicket, DebugTicketError, PreviousRunError,
};
pub use evidence::{Evidence, EvidenceError};
pub use forge::{Attached, Forge, ForgeRef, PullRequest};
pub use ids::Ids;
pub use job::JobFailure;
pub use store::{EventStore, RunLog, RunStart, StoreError, replay};
pub use verifier::Verifier;
