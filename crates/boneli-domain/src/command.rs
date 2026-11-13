//! Commands: what a run asks the application to do next (ADR-002).
//!
//! The application executes each command through its ports and reports the
//! result as the next [`crate::RunEvent`].

use alloc::string::String;
use alloc::vec::Vec;

use crate::budget::{Overrun, Usage};
use crate::gate::FixChecks;
use crate::values::{Citation, CommitSha, EvidenceRef, Ticket};

/// One command of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunCommand {
    /// Run the triage job.
    Triage {
        /// The bug report.
        ticket: Ticket,
        /// The base commit.
        base: CommitSha,
    },
    /// Post the triage questions on the ticket.
    PostQuestions {
        /// The bug report.
        ticket: Ticket,
        /// The questions, none blank.
        questions: Vec<String>,
    },
    /// Run the job that writes a reproduction test.
    WriteReproduction {
        /// The bug report.
        ticket: Ticket,
        /// The base commit.
        base: CommitSha,
    },
    /// Run the reproduction test on the base commit.
    CheckReproduction {
        /// The base commit.
        base: CommitSha,
        /// The test.
        test: EvidenceRef,
    },
    /// Run the root-cause analysis job.
    AnalyzeRootCause {
        /// The bug report.
        ticket: Ticket,
        /// The base commit.
        base: CommitSha,
        /// The reproduction test that passed its gate.
        test: EvidenceRef,
    },
    /// Verify the citations against the base commit.
    VerifyCitations {
        /// The base commit.
        base: CommitSha,
        /// The citations, all well formed.
        citations: Vec<Citation>,
    },
    /// Run the job that writes the fix.
    WriteFix {
        /// The bug report.
        ticket: Ticket,
        /// The base commit.
        base: CommitSha,
        /// The reproduction test.
        test: EvidenceRef,
        /// The analysis that passed its gate.
        analysis: EvidenceRef,
    },
    /// Check the fix in a clean sandbox from the base commit and the diff
    /// only (invariant 6); the test reference lets the verifier confirm the
    /// test is unchanged.
    VerifyFix {
        /// The base commit.
        base: CommitSha,
        /// The fix.
        diff: EvidenceRef,
        /// The reproduction test.
        test: EvidenceRef,
    },
    /// Open the pull request. A human always merges.
    OpenPullRequest {
        /// The bug report.
        ticket: Ticket,
        /// The base commit.
        base: CommitSha,
        /// The verified fix.
        diff: EvidenceRef,
        /// The reproduction test.
        test: EvidenceRef,
        /// The verified analysis.
        analysis: EvidenceRef,
        /// The fix gate's observations, for the before and after results.
        checks: FixChecks,
        /// The run's total consumption.
        spent: Usage,
        /// Set when the verify job's usage crossed a limit (ADR-002); the
        /// pull request states it.
        overrun: Option<Overrun>,
    },
}
