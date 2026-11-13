//! Errors: input the run cannot accept (ADR-002).
//!
//! A [`DomainError`] means the caller sent something wrong: an event out of
//! sequence, invalid intake input, a blank forge reference, job failure detail
//! or evidence reference, an invalid budget or a malformed SHA. The
//! run does not advance. Bad agent output is not an error; it ends the run
//! with an outcome (fail closed, `docs/ARCHITECTURE.md`, "Debugging line").

use core::fmt;

use crate::budget::BudgetDimension;
use crate::event::EventKind;
use crate::values::TicketField;

/// Input the run cannot accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainError {
    /// The event is not legal in the run's current state.
    UnexpectedEvent {
        /// The event kind the run waits for; `None` once the run is done.
        expected: Option<EventKind>,
        /// The event kind that arrived.
        got: EventKind,
    },
    /// A required ticket field is blank.
    InvalidTicket(TicketField),
    /// An event carries a blank required text (see
    /// [`crate::values::is_blank`]): the forge reference of
    /// `QuestionsPosted` or `PullRequestOpened`, or the detail of
    /// `JobFailed`. The kind names the field; a finished run would point at
    /// no evidence.
    BlankEventField(EventKind),
    /// A blank evidence reference (see [`crate::values::is_blank`]).
    BlankEvidenceRef,
    /// A budget limit is zero.
    InvalidBudget(BudgetDimension),
    /// Not a full lowercase SHA-1 or SHA-256 object name.
    InvalidCommitSha,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::UnexpectedEvent {
                expected: Some(expected),
                got,
            } => write!(
                f,
                "unexpected event {got:?}, the run waits for {expected:?}"
            ),
            DomainError::UnexpectedEvent {
                expected: None,
                got,
            } => write!(f, "unexpected event {got:?}, the run is done"),
            DomainError::InvalidTicket(field) => write!(f, "ticket field {field:?} is blank"),
            DomainError::BlankEventField(kind) => {
                write!(f, "{kind:?} carries a blank required text")
            }
            DomainError::BlankEvidenceRef => f.write_str("blank evidence reference"),
            DomainError::InvalidBudget(dimension) => {
                write!(f, "budget limit {dimension:?} is zero")
            }
            DomainError::InvalidCommitSha => {
                f.write_str("not a full lowercase SHA-1 or SHA-256 object name")
            }
        }
    }
}

impl core::error::Error for DomainError {}
