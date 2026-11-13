//! [`MemoryAgent`]: the `Agent` port from a script.

use std::collections::VecDeque;
use std::sync::Mutex;

use boneli_app::{
    Agent, FixRequest, JobFailure, ReproductionRequest, RootCauseReport, RootCauseRequest,
    TriageReport, TriageRequest, Written,
};

use crate::{Response, lock, next};

/// The scripted answers of a [`MemoryAgent`], one queue per operation, used
/// front to back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentScript {
    /// Answers of `triage`.
    pub triage: Vec<Response<TriageReport>>,
    /// Answers of `write_reproduction`.
    pub write_reproduction: Vec<Response<Written>>,
    /// Answers of `analyze_root_cause`.
    pub analyze_root_cause: Vec<Response<RootCauseReport>>,
    /// Answers of `write_fix`.
    pub write_fix: Vec<Response<Written>>,
}

/// One request a [`MemoryAgent`] received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentRequest {
    /// A `triage` call.
    Triage(TriageRequest),
    /// A `write_reproduction` call.
    WriteReproduction(ReproductionRequest),
    /// An `analyze_root_cause` call.
    AnalyzeRootCause(RootCauseRequest),
    /// A `write_fix` call.
    WriteFix(FixRequest),
}

/// An `Agent` that answers from an [`AgentScript`] and records every
/// request. An operation whose queue is used up fails with
/// `no scripted response for <operation>`.
#[derive(Debug, Default)]
pub struct MemoryAgent {
    triage: Mutex<VecDeque<Response<TriageReport>>>,
    write_reproduction: Mutex<VecDeque<Response<Written>>>,
    analyze_root_cause: Mutex<VecDeque<Response<RootCauseReport>>>,
    write_fix: Mutex<VecDeque<Response<Written>>>,
    requests: Mutex<Vec<AgentRequest>>,
}

impl MemoryAgent {
    /// An agent that answers from `script`.
    pub fn new(script: AgentScript) -> MemoryAgent {
        MemoryAgent {
            triage: Mutex::new(script.triage.into()),
            write_reproduction: Mutex::new(script.write_reproduction.into()),
            analyze_root_cause: Mutex::new(script.analyze_root_cause.into()),
            write_fix: Mutex::new(script.write_fix.into()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<AgentRequest> {
        lock(&self.requests).clone()
    }

    fn record(&self, request: AgentRequest) {
        lock(&self.requests).push(request);
    }
}

impl Agent for MemoryAgent {
    fn triage(&self, request: &TriageRequest) -> Result<TriageReport, JobFailure> {
        self.record(AgentRequest::Triage(request.clone()));
        next(&self.triage, "triage")
    }

    fn write_reproduction(&self, request: &ReproductionRequest) -> Result<Written, JobFailure> {
        self.record(AgentRequest::WriteReproduction(request.clone()));
        next(&self.write_reproduction, "write_reproduction")
    }

    fn analyze_root_cause(
        &self,
        request: &RootCauseRequest,
    ) -> Result<RootCauseReport, JobFailure> {
        self.record(AgentRequest::AnalyzeRootCause(request.clone()));
        next(&self.analyze_root_cause, "analyze_root_cause")
    }

    fn write_fix(&self, request: &FixRequest) -> Result<Written, JobFailure> {
        self.record(AgentRequest::WriteFix(request.clone()));
        next(&self.write_fix, "write_fix")
    }
}
