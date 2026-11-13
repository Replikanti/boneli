//! The `EventStore` port and replay (ADR-004, D1, D6).
//!
//! Every run has an append-only log: how it started and the events it
//! accepted, in order. Replaying the log through `Run::handle` gives the run
//! back (`docs/ARCHITECTURE.md`, "Code architecture": functional core,
//! imperative shell). The log format and its versioning belong to the real
//! adapter (#4).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use boneli_domain::{Budget, DomainError, Run, RunCommand, RunEvent, RunId};

/// How a run started: what `Run::new` took, plus the run it continues.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunStart {
    /// The run's limits.
    pub budget: Budget,
    /// The run whose triage questions this run answers (ADR-004, D6).
    pub previous: Option<RunId>,
}

/// A run's stored log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunLog {
    /// How the run started.
    pub start: RunStart,
    /// The events the run accepted, in order.
    pub events: Vec<RunEvent>,
}

/// Why the event store did not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// No run with this id was created.
    UnknownRun,
    /// A run with this id was already created.
    AlreadyExists,
    /// The store cannot hold a run under this id (for example, a file store
    /// that would have to leave its directory).
    InvalidRunId,
    /// The store could not be reached or written.
    Unavailable {
        /// What went wrong, as the store reports it.
        detail: String,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::UnknownRun => f.write_str("unknown run"),
            StoreError::AlreadyExists => f.write_str("the run already exists"),
            StoreError::InvalidRunId => f.write_str("the store cannot hold a run under this id"),
            StoreError::Unavailable { detail } => {
                write!(f, "the event store is unavailable: {detail}")
            }
        }
    }
}

impl core::error::Error for StoreError {}

/// The append-only log of every run.
pub trait EventStore {
    /// Creates the log of a new run.
    fn create(&self, id: &RunId, start: &RunStart) -> Result<(), StoreError>;

    /// Appends one accepted event to a run's log. Appending the same event
    /// twice keeps both copies.
    fn append(&self, id: &RunId, event: &RunEvent) -> Result<(), StoreError>;

    /// The run's log as stored.
    fn load(&self, id: &RunId) -> Result<RunLog, StoreError>;
}

/// Replays a stored log: `Run::new` with the logged budget, then every event
/// through `Run::handle`. Returns the run and every command it emitted, in
/// order, or the first error; a log written by `DebugTicket` always
/// replays, because only accepted events are appended.
pub fn replay(id: &RunId, log: &RunLog) -> Result<(Run, Vec<RunCommand>), DomainError> {
    let mut run = Run::new(id.clone(), log.start.budget)?;
    let mut commands = Vec::new();
    for event in &log.events {
        let (next, more) = run.handle(event.clone())?;
        run = next;
        commands.extend(more);
    }
    Ok((run, commands))
}
