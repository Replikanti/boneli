//! The `Verifier` port: the deterministic checks of the debugging line
//! (ADR-004, D3).
//!
//! It runs the reproduction test on the base commit, verifies citations
//! against the base commit and checks the fix in a clean sandbox from the
//! base commit and the diff only (invariant 6). The observations it returns
//! are what the domain's gates decide on (ADR-002, D2). The real adapter
//! (#17) runs on `Sandbox` and `Git` and classifies test results per stack.
//! A verifier spends no provider budget: its jobs cost 0 µUSD, and only
//! their duration is measured.

use alloc::vec::Vec;

use boneli_domain::{Citation, CitationStatus, CommitSha, FixChecks, TestStatus};

use crate::job::JobFailure;

/// The checks of the debugging line. A failure means the check could not
/// run at all; a check that ran reports its observation, `Unknown`
/// included. Every failure is a [`JobFailure`] whose detail is never blank.
pub trait Verifier {
    /// Runs the reproduction test on the base commit.
    fn check_reproduction(&self, base: &CommitSha, test: &[u8]) -> Result<TestStatus, JobFailure>;

    /// Verifies every citation against the base commit: one status per
    /// citation, in citation order.
    fn verify_citations(
        &self,
        base: &CommitSha,
        citations: &[Citation],
    ) -> Result<Vec<CitationStatus>, JobFailure>;

    /// Checks the fix in a clean sandbox from the base commit and the diff;
    /// the test lets the verifier confirm it is unchanged.
    fn verify_fix(
        &self,
        base: &CommitSha,
        diff: &[u8],
        test: &[u8],
    ) -> Result<FixChecks, JobFailure>;
}
