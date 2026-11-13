//! [`MemoryVerifier`]: the `Verifier` port from a script.

use std::collections::VecDeque;
use std::sync::Mutex;

use boneli_app::{JobFailure, Verifier};
use boneli_domain::{Citation, CitationStatus, CommitSha, FixChecks, TestStatus};

use crate::{Response, lock, next};

/// The scripted answers of a [`MemoryVerifier`], one queue per operation,
/// used front to back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifierScript {
    /// Answers of `check_reproduction`.
    pub check_reproduction: Vec<Response<TestStatus>>,
    /// Answers of `verify_citations`.
    pub verify_citations: Vec<Response<Vec<CitationStatus>>>,
    /// Answers of `verify_fix`.
    pub verify_fix: Vec<Response<FixChecks>>,
}

/// One request a [`MemoryVerifier`] received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifierRequest {
    /// A `check_reproduction` call.
    CheckReproduction {
        /// The base commit.
        base: CommitSha,
        /// The test.
        test: Vec<u8>,
    },
    /// A `verify_citations` call.
    VerifyCitations {
        /// The base commit.
        base: CommitSha,
        /// The citations.
        citations: Vec<Citation>,
    },
    /// A `verify_fix` call.
    VerifyFix {
        /// The base commit.
        base: CommitSha,
        /// The diff.
        diff: Vec<u8>,
        /// The test.
        test: Vec<u8>,
    },
}

/// A `Verifier` that answers from a [`VerifierScript`] and records every
/// request. An operation whose queue is used up fails with
/// `no scripted response for <operation>`.
#[derive(Debug, Default)]
pub struct MemoryVerifier {
    check_reproduction: Mutex<VecDeque<Response<TestStatus>>>,
    verify_citations: Mutex<VecDeque<Response<Vec<CitationStatus>>>>,
    verify_fix: Mutex<VecDeque<Response<FixChecks>>>,
    requests: Mutex<Vec<VerifierRequest>>,
}

impl MemoryVerifier {
    /// A verifier that answers from `script`.
    pub fn new(script: VerifierScript) -> MemoryVerifier {
        MemoryVerifier {
            check_reproduction: Mutex::new(script.check_reproduction.into()),
            verify_citations: Mutex::new(script.verify_citations.into()),
            verify_fix: Mutex::new(script.verify_fix.into()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<VerifierRequest> {
        lock(&self.requests).clone()
    }

    fn record(&self, request: VerifierRequest) {
        lock(&self.requests).push(request);
    }
}

impl Verifier for MemoryVerifier {
    fn check_reproduction(&self, base: &CommitSha, test: &[u8]) -> Result<TestStatus, JobFailure> {
        self.record(VerifierRequest::CheckReproduction {
            base: base.clone(),
            test: test.to_vec(),
        });
        next(&self.check_reproduction, "check_reproduction")
    }

    fn verify_citations(
        &self,
        base: &CommitSha,
        citations: &[Citation],
    ) -> Result<Vec<CitationStatus>, JobFailure> {
        self.record(VerifierRequest::VerifyCitations {
            base: base.clone(),
            citations: citations.to_vec(),
        });
        next(&self.verify_citations, "verify_citations")
    }

    fn verify_fix(
        &self,
        base: &CommitSha,
        diff: &[u8],
        test: &[u8],
    ) -> Result<FixChecks, JobFailure> {
        self.record(VerifierRequest::VerifyFix {
            base: base.clone(),
            diff: diff.to_vec(),
            test: test.to_vec(),
        });
        next(&self.verify_fix, "verify_fix")
    }
}
