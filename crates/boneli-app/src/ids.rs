//! The `Ids` port (ADR-004, D1).
//!
//! Run identifiers come from outside the core, so a run replays with the
//! same id it was recorded with.

use boneli_domain::RunId;

/// The source of run identifiers.
pub trait Ids {
    /// A new run identifier: not blank and never issued before by this
    /// adapter.
    fn run_id(&self) -> RunId;
}
