//! In-memory adapters of the Boneli ports (ADR-004, D2).
//!
//! One adapter crate holds the in-memory adapter of every port: there is no
//! dependency, `unsafe` or I/O boundary between them that separate crates
//! would protect, and every consumer needs several. The job adapters
//! ([`MemoryAgent`], [`MemoryVerifier`], [`MemoryForge`]) answer from a
//! script of plain data and record every request; the stores keep their
//! data in a `BTreeMap`. Each adapter passes its port's contract suite in
//! `boneli_app::contract` (`tests/contract.rs`), and `tests/mutants.rs`
//! shows that every clause of those suites can fail.
//!
//! State sits behind a `std::sync::Mutex`, so the adapters are `Sync` and a
//! root can share them across threads. A poisoned lock is recovered with
//! `PoisonError::into_inner` (ADR-004, D8): every critical section is one
//! push, pop, insert or increment, which a panic cannot leave half done.
#![doc(test(attr(forbid(unsafe_code))))]

mod agent;
mod clock;
mod evidence;
mod forge;
mod store;
mod verifier;

use std::sync::{Mutex, MutexGuard, PoisonError};

use boneli_app::JobFailure;

pub use agent::{AgentRequest, AgentScript, MemoryAgent};
pub use clock::{SequentialIds, StepClock};
pub use evidence::MemoryEvidence;
pub use forge::{ForgeRequest, ForgeScript, MemoryForge};
pub use store::MemoryEventStore;
pub use verifier::{MemoryVerifier, VerifierRequest, VerifierScript};

/// A scripted job failure: what [`JobFailure::new`] gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptedFailure {
    /// The job's error output.
    pub error_output: String,
    /// The job's status, for example `exit status 3`.
    pub status: String,
    /// What the job cost before it failed, in micro-USD.
    pub cost_micro_usd: u64,
}

impl ScriptedFailure {
    /// The failure as the port reports it.
    pub fn to_failure(&self) -> JobFailure {
        JobFailure::new(&self.error_output, &self.status, self.cost_micro_usd)
    }
}

/// One scripted answer of a job adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response<T> {
    /// The operation succeeds with this value.
    Answer(T),
    /// The operation fails.
    Fail(ScriptedFailure),
}

/// The answer when an operation's script is used up: a failure that names
/// the operation, never a panic.
fn exhausted(operation: &str) -> JobFailure {
    JobFailure::new(&format!("no scripted response for {operation}"), "", 0)
}

/// Pops the next scripted response of an operation and turns it into the
/// port's result.
fn next<T>(
    queue: &Mutex<std::collections::VecDeque<Response<T>>>,
    operation: &str,
) -> Result<T, JobFailure> {
    match lock(queue).pop_front() {
        Some(Response::Answer(value)) => Ok(value),
        Some(Response::Fail(failure)) => Err(failure.to_failure()),
        None => Err(exhausted(operation)),
    }
}

/// Locks a mutex, recovering a poisoned one (ADR-004, D8).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
