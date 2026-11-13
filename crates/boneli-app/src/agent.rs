//! The `Agent` port: the jobs a model does (ADR-004, D1).
//!
//! Triage, the reproduction test, the root-cause analysis and the fix. The
//! requests carry the evidence bytes `DebugTicket` loaded from the
//! `Evidence` port, and the reports carry the bytes the agent produced and
//! the provider cost of the job in micro-USD (ADR-002, D3). The duration is
//! measured by `DebugTicket` with the `Clock` port, not reported here.

use alloc::string::String;
use alloc::vec::Vec;

use boneli_domain::{Citation, CommitSha, Outcome, RunId, Ticket, TriageVerdict};

use crate::job::JobFailure;

/// What the previous run of the same ticket asked, when the reporter's
/// answer started this run (ADR-004, D6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviousTriage {
    /// The previous run.
    pub run: RunId,
    /// How it ended: always `NeedsInformation`, with the forge's reference
    /// to the questions comment.
    pub outcome: Outcome,
    /// The questions it posted, as logged in its `TriageFinished` event.
    pub questions: Vec<String>,
}

/// Input of the triage job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriageRequest {
    /// The bug report.
    pub ticket: Ticket,
    /// The base commit.
    pub base: CommitSha,
    /// The previous run's questions, for a re-run after them.
    pub previous: Option<PreviousTriage>,
}

/// Output of the triage job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriageReport {
    /// The verdict.
    pub verdict: TriageVerdict,
    /// What the job cost, in micro-USD.
    pub cost_micro_usd: u64,
}

/// Input of the job that writes the reproduction test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReproductionRequest {
    /// The bug report.
    pub ticket: Ticket,
    /// The base commit.
    pub base: CommitSha,
}

/// Output of a job that writes a file: the reproduction test or the fix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    /// The bytes written: the test, or the fix as a diff.
    pub content: Vec<u8>,
    /// What the job cost, in micro-USD.
    pub cost_micro_usd: u64,
}

/// Input of the root-cause analysis job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootCauseRequest {
    /// The bug report.
    pub ticket: Ticket,
    /// The base commit.
    pub base: CommitSha,
    /// The reproduction test that passed its gate.
    pub test: Vec<u8>,
}

/// Output of the root-cause analysis job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootCauseReport {
    /// The analysis as written.
    pub analysis: Vec<u8>,
    /// Its citations, which the domain checks before the verifier sees them.
    pub citations: Vec<Citation>,
    /// What the job cost, in micro-USD.
    pub cost_micro_usd: u64,
}

/// Input of the job that writes the fix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixRequest {
    /// The bug report.
    pub ticket: Ticket,
    /// The base commit.
    pub base: CommitSha,
    /// The reproduction test.
    pub test: Vec<u8>,
    /// The analysis that passed its gate.
    pub analysis: Vec<u8>,
}

/// The model side of the debugging line. Every failure is a [`JobFailure`]
/// with the cost the job ran up; its detail is never blank.
pub trait Agent {
    /// Decides whether the ticket has enough information to start.
    fn triage(&self, request: &TriageRequest) -> Result<TriageReport, JobFailure>;

    /// Writes a test that reproduces the bug on the base commit.
    fn write_reproduction(&self, request: &ReproductionRequest) -> Result<Written, JobFailure>;

    /// Finds the root cause, with citations into the base commit.
    fn analyze_root_cause(&self, request: &RootCauseRequest)
    -> Result<RootCauseReport, JobFailure>;

    /// Writes the fix as a diff against the base commit.
    fn write_fix(&self, request: &FixRequest) -> Result<Written, JobFailure>;
}
