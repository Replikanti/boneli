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
//! "Debugging line"; the run model, budget units and gates are fixed in
//! ADR-002 (`docs/adr/002-run-state-machine-and-replay-gate.md`).
//!
//! The entry point is [`Run`]: [`Run::handle`] takes a [`RunEvent`] and
//! returns the next run and its [`RunCommand`]s. [`scenarios`] is the event
//! corpus the unit tests and the two-process replay gate fold.
//!
//! [`patch_policy`] judges a fix diff before it is verified: size,
//! forbidden paths, binaries, symlinks and disabled tests (ADR-013). The
//! run asks for it with `CheckPatch` after `FixWritten` and gates on the
//! `PatchChecked` result (ADR-023).
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

extern crate alloc;

pub mod budget;
pub mod command;
pub mod error;
pub mod event;
pub mod gate;
pub mod line_diff;
pub mod patch;
pub mod patch_corpus;
pub mod patch_js;
pub mod patch_path;
pub mod run;
pub mod scenarios;
pub mod values;

pub use budget::{Budget, BudgetDimension, Overrun, Usage};
pub use command::RunCommand;
pub use error::DomainError;
pub use event::{EventKind, RunEvent, TriageVerdict};
pub use gate::{
    CheckStatus, CitationProblem, CitationStatus, FixCheck, FixChecks, GateFailure, GateOutcome,
    PatchCheck, TestStatus,
};
pub use patch::{
    BaseLink, Change, ChangeProblem, Entry, EntryKind, LinkProblem, NotText, Patch, PatchLimits,
    PatchVerdict, PatchViolation, TestDisabling, UnreadablePath, patch_policy,
};
pub use patch_js::Marker;
pub use patch_path::ForbiddenClass;
pub use run::{AgentOutputProblem, Outcome, Run, Stage};
pub use values::{Citation, CommitSha, EvidenceRef, RunId, Ticket, TicketField, TicketSource};
