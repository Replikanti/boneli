//! Events: what the application reports back to a run (ADR-002).
//!
//! Every job result carries the job's [`Usage`]; the two forge results
//! (`QuestionsPosted`, `PullRequestOpened`) and the ticket spend no agent
//! budget and carry none.

use alloc::string::String;
use alloc::vec::Vec;

use crate::budget::Usage;
use crate::gate::{CitationStatus, FixChecks, TestStatus};
use crate::values::{Citation, CommitSha, EvidenceRef, Ticket};

/// The result of triage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TriageVerdict {
    /// The ticket has enough information to start.
    Ready,
    /// Information is missing; the run posts these questions and ends.
    NeedsInformation {
        /// The questions for the reporter, at least one, none blank.
        questions: Vec<String>,
    },
}

/// One input to [`crate::Run::handle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEvent {
    /// Intake: the ticket and the base commit the run works on.
    TicketReceived {
        /// The bug report.
        ticket: Ticket,
        /// The commit everything is reproduced and verified against.
        base: CommitSha,
    },
    /// The triage job finished.
    TriageFinished {
        /// Its verdict.
        verdict: TriageVerdict,
        /// What the job consumed.
        usage: Usage,
    },
    /// The forge posted the triage questions.
    QuestionsPosted {
        /// The forge's reference to the comment; must not be blank.
        reference: String,
    },
    /// The agent wrote a reproduction test.
    ReproductionWritten {
        /// The stored test.
        test: EvidenceRef,
        /// What the job consumed.
        usage: Usage,
    },
    /// The reproduction test ran on the base SHA.
    ReproductionChecked {
        /// How it ended.
        status: TestStatus,
        /// What the job consumed.
        usage: Usage,
    },
    /// The agent proposed a root cause.
    RootCauseProposed {
        /// The stored analysis.
        analysis: EvidenceRef,
        /// Its citations.
        citations: Vec<Citation>,
        /// What the job consumed.
        usage: Usage,
    },
    /// The citations were verified against the base SHA.
    CitationsChecked {
        /// One result per citation, in citation order.
        results: Vec<CitationStatus>,
        /// What the job consumed.
        usage: Usage,
    },
    /// The agent wrote a fix.
    FixWritten {
        /// The stored diff.
        diff: EvidenceRef,
        /// What the job consumed.
        usage: Usage,
    },
    /// The fix was checked in a clean sandbox.
    FixVerified {
        /// The observations of the fix gate.
        checks: FixChecks,
        /// What the job consumed.
        usage: Usage,
    },
    /// The forge opened the pull request.
    PullRequestOpened {
        /// The forge's reference to the pull request; must not be blank.
        reference: String,
    },
    /// The job or forge call the run waits for failed.
    JobFailed {
        /// What went wrong, as reported; must not be blank, because it is
        /// the only evidence of why the run ended.
        detail: String,
        /// What the job consumed before it failed.
        usage: Usage,
    },
}

/// The kind of a [`RunEvent`], without its data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventKind {
    /// [`RunEvent::TicketReceived`].
    TicketReceived,
    /// [`RunEvent::TriageFinished`].
    TriageFinished,
    /// [`RunEvent::QuestionsPosted`].
    QuestionsPosted,
    /// [`RunEvent::ReproductionWritten`].
    ReproductionWritten,
    /// [`RunEvent::ReproductionChecked`].
    ReproductionChecked,
    /// [`RunEvent::RootCauseProposed`].
    RootCauseProposed,
    /// [`RunEvent::CitationsChecked`].
    CitationsChecked,
    /// [`RunEvent::FixWritten`].
    FixWritten,
    /// [`RunEvent::FixVerified`].
    FixVerified,
    /// [`RunEvent::PullRequestOpened`].
    PullRequestOpened,
    /// [`RunEvent::JobFailed`].
    JobFailed,
}

impl EventKind {
    /// Every kind, in declaration order.
    pub const ALL: [EventKind; 11] = [
        EventKind::TicketReceived,
        EventKind::TriageFinished,
        EventKind::QuestionsPosted,
        EventKind::ReproductionWritten,
        EventKind::ReproductionChecked,
        EventKind::RootCauseProposed,
        EventKind::CitationsChecked,
        EventKind::FixWritten,
        EventKind::FixVerified,
        EventKind::PullRequestOpened,
        EventKind::JobFailed,
    ];
}

impl RunEvent {
    /// The event's kind.
    pub fn kind(&self) -> EventKind {
        match self {
            RunEvent::TicketReceived { .. } => EventKind::TicketReceived,
            RunEvent::TriageFinished { .. } => EventKind::TriageFinished,
            RunEvent::QuestionsPosted { .. } => EventKind::QuestionsPosted,
            RunEvent::ReproductionWritten { .. } => EventKind::ReproductionWritten,
            RunEvent::ReproductionChecked { .. } => EventKind::ReproductionChecked,
            RunEvent::RootCauseProposed { .. } => EventKind::RootCauseProposed,
            RunEvent::CitationsChecked { .. } => EventKind::CitationsChecked,
            RunEvent::FixWritten { .. } => EventKind::FixWritten,
            RunEvent::FixVerified { .. } => EventKind::FixVerified,
            RunEvent::PullRequestOpened { .. } => EventKind::PullRequestOpened,
            RunEvent::JobFailed { .. } => EventKind::JobFailed,
        }
    }

    /// The usage the event carries; `None` for intake and forge results.
    pub fn usage(&self) -> Option<Usage> {
        match self {
            RunEvent::TicketReceived { .. }
            | RunEvent::QuestionsPosted { .. }
            | RunEvent::PullRequestOpened { .. } => None,
            RunEvent::TriageFinished { usage, .. }
            | RunEvent::ReproductionWritten { usage, .. }
            | RunEvent::ReproductionChecked { usage, .. }
            | RunEvent::RootCauseProposed { usage, .. }
            | RunEvent::CitationsChecked { usage, .. }
            | RunEvent::FixWritten { usage, .. }
            | RunEvent::FixVerified { usage, .. }
            | RunEvent::JobFailed { usage, .. } => Some(*usage),
        }
    }
}
