//! The app scenario corpus: `DebugTicket` end to end on in-memory adapters
//! (ADR-004, D7).
//!
//! Every `DebugTicket` test runs through this corpus, so the two-process
//! replay sees every path those tests exercise. A scenario is plain data:
//! scripts for the in-memory agent, verifier and forge, a clock, an
//! optional injected [`Fault`] and the requests, in order. [`play`] runs it
//! with a fixed `Clock` and `SequentialIds` behind recording adapters and
//! returns everything that is compared: each request's result, every run
//! log, every recorded job request, every diff `Git::apply` got and every
//! port call. Every scenario runs on the same repository
//! ([`git_commits`]), which the patch check fetches and applies the
//! agent's diff to (ADR-023, D8).
//!
//! [`fault_scenarios`] derives the fault matrix from the hand-written
//! scenarios. [`ScriptedClock`] knowingly breaks the `Clock` contract, to
//! reach a backwards clock with given readings.

use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};

use std::num::NonZeroU32;

use boneli_app::{
    Agent, BranchName, CheckoutId, Clock, CommitInfo, DataError, DebugReport, DebugRequest,
    DebugTicket, DebugTicketError, EventStore, Evidence, EvidenceError, FixRequest, Forge,
    ForgeRef, Git, GitError, Ids, ImageError, JobFailure, PreviousRunError, PullRequest,
    RelativePath, RepoUrl, ReproductionRequest, RootCauseReport, RootCauseRequest, RunLog,
    RunStart, SandboxError, StoreError, TreePath, TriageReport, TriageRequest, Verifier, Written,
};
use boneli_app::{
    BrokerName, ContainerName, LayerRef, LimitProblem, NameProblem, SpecProblem, WorkspaceBytes,
};
use boneli_domain::{
    Budget, CheckStatus, Citation, CitationStatus, CommitSha, DomainError, EventKind, EvidenceRef,
    FixChecks, Patch, PatchLimits, RunEvent, RunId, Stage, TestStatus, Ticket, TicketSource,
    TriageVerdict, UnreadablePath,
};
use boneli_memory::{
    AgentRequest, AgentScript, ForgeRequest, ForgeScript, GitCommit, MemoryAgent, MemoryEventStore,
    MemoryEvidence, MemoryForge, MemoryGit, MemoryVerifier, Response, ScriptedFailure,
    SequentialIds, StepClock, Tree, VerifierRequest, VerifierScript, pack_diff,
};

/// The base commit of every scenario.
pub const BASE: &str = "0123456789abcdef0123456789abcdef01234567";

/// The budget of every scenario that does not test the budget: far above
/// the largest spend of one corpus run (4 000 µUSD, 8 000 ms).
pub const BUDGET: Budget = Budget {
    cost_micro_usd: 1_000_000,
    duration_ms: 600_000,
};

/// The cost of every agent job, in micro-USD.
pub const AGENT_COST: u64 = 1_000;

/// The step of the default clock: every measured job lasts 1 000 ms, so the
/// delivered path's 8 measured jobs take 8 000 ms.
pub const STEP_MS: u64 = 1_000;

/// The first reading of the default clock. Not 0, so a backwards fault
/// always has 1 ms to go back.
pub const CLOCK_START: u64 = 1_000;

/// The clock a scenario runs on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClockSetup {
    /// [`StepClock`]: `start`, then one step per reading.
    Step {
        /// The first reading.
        start: u64,
        /// The increment per reading.
        increment: u64,
    },
    /// [`ScriptedClock`]: these readings, then the last one again.
    Readings(Vec<u64>),
}

/// One named `DebugTicket` scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppScenario {
    /// Unique, `[a-z0-9-]+`.
    pub name: String,
    /// The agent's answers.
    pub agent: AgentScript,
    /// The verifier's answers.
    pub verifier: VerifierScript,
    /// The forge's failures.
    pub forge: ForgeScript,
    /// The clock.
    pub clock: ClockSetup,
    /// The injected fault, if any.
    pub fault: Option<Fault>,
    /// For a fault-matrix scenario, the hand-written scenario it varies.
    pub base: Option<String>,
    /// The requests, played in order on the same adapters.
    pub requests: Vec<DebugRequest>,
}

/// A port call as `play` records it: one variant per operation of every
/// port. The recording adapters around the in-memory ones implement every
/// port trait, so a new port operation does not compile until it records
/// a variant here, and [`Call::fault_kinds`] matches every variant, so the
/// variant does not compile without its fault kinds (ADR-004, D7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Call {
    /// `Agent::triage`.
    Triage,
    /// `Agent::write_reproduction`.
    WriteReproduction,
    /// `Agent::analyze_root_cause`.
    AnalyzeRootCause,
    /// `Agent::write_fix`.
    WriteFix,
    /// `Verifier::check_reproduction`.
    CheckReproduction,
    /// `Verifier::verify_citations`.
    VerifyCitations,
    /// `Verifier::verify_fix`.
    VerifyFix,
    /// `Forge::post_questions`.
    PostQuestions,
    /// `Forge::open_pull_request`.
    OpenPullRequest,
    /// `Git::fetch_base`.
    FetchBase,
    /// `Git::read`.
    Read,
    /// `Git::snapshot`.
    Snapshot,
    /// `Git::diff`.
    Diff,
    /// `Git::apply`.
    Apply,
    /// `Git::patch_between`.
    PatchBetween,
    /// `Git::push`.
    Push,
    /// `EventStore::create`.
    Create,
    /// `EventStore::append`.
    Append,
    /// `EventStore::load`.
    Load,
    /// `Evidence::put`.
    Put,
    /// `Evidence::get`.
    Get,
    /// `Clock::now_ms`.
    Now,
    /// `Ids::run_id`.
    RunId,
}

impl Call {
    /// The call's name in scenario names.
    pub fn name(self) -> &'static str {
        match self {
            Call::Triage => "triage",
            Call::WriteReproduction => "write-reproduction",
            Call::AnalyzeRootCause => "analyze-root-cause",
            Call::WriteFix => "write-fix",
            Call::CheckReproduction => "check-reproduction",
            Call::VerifyCitations => "verify-citations",
            Call::VerifyFix => "verify-fix",
            Call::PostQuestions => "post-questions",
            Call::OpenPullRequest => "open-pull-request",
            Call::FetchBase => "fetch-base",
            Call::Read => "read",
            Call::Snapshot => "snapshot",
            Call::Diff => "diff",
            Call::Apply => "apply",
            Call::PatchBetween => "patch-between",
            Call::Push => "push",
            Call::Create => "create",
            Call::Append => "append",
            Call::Load => "load",
            Call::Put => "put",
            Call::Get => "get",
            Call::Now => "now",
            Call::RunId => "run-id",
        }
    }

    /// Every way this call can fail: a job failure for the job ports, every
    /// `GitError` variant for git, every `StoreError` and `EvidenceError`
    /// variant for the stores, a backwards reading for the clock.
    /// `Ids::run_id` cannot fail.
    pub fn fault_kinds(self) -> Vec<FaultKind> {
        match self {
            Call::Triage
            | Call::WriteReproduction
            | Call::AnalyzeRootCause
            | Call::WriteFix
            | Call::CheckReproduction
            | Call::VerifyCitations
            | Call::VerifyFix
            | Call::PostQuestions
            | Call::OpenPullRequest => vec![FaultKind::Fails],
            Call::FetchBase
            | Call::Read
            | Call::Snapshot
            | Call::Diff
            | Call::Apply
            | Call::PatchBetween
            | Call::Push => every_git_error().into_iter().map(FaultKind::Git).collect(),
            Call::Create | Call::Append | Call::Load => every_store_error()
                .into_iter()
                .map(FaultKind::Store)
                .collect(),
            Call::Put | Call::Get => every_evidence_error()
                .into_iter()
                .map(FaultKind::Evidence)
                .collect(),
            Call::Now => vec![FaultKind::Backwards],
            Call::RunId => vec![],
        }
    }
}

/// Every `StoreError` variant. Each is listed by the variant before it, in
/// an exhaustive match, so a new variant does not compile until it is in
/// the chain.
pub fn every_store_error() -> Vec<StoreError> {
    let mut all = Vec::new();
    let mut next = Some(StoreError::UnknownRun);
    while let Some(error) = next {
        next = match &error {
            StoreError::UnknownRun => Some(StoreError::AlreadyExists),
            StoreError::AlreadyExists => Some(StoreError::InvalidRunId),
            StoreError::InvalidRunId => Some(StoreError::Unavailable {
                detail: String::from(FAULT),
            }),
            StoreError::Unavailable { .. } => None,
        };
        all.push(error);
    }
    all
}

/// Every `GitError` variant, chained the same way.
pub fn every_git_error() -> Vec<GitError> {
    let mut all = Vec::new();
    let mut next = Some(GitError::UnknownCommit);
    while let Some(error) = next {
        next = match &error {
            GitError::UnknownCommit => Some(GitError::UnknownCheckout),
            GitError::UnknownCheckout => Some(GitError::BranchExists),
            GitError::BranchExists => Some(GitError::Failed {
                detail: String::from(FAULT),
            }),
            GitError::Failed { .. } => None,
        };
        all.push(error);
    }
    all
}

/// Every `EvidenceError` variant, chained the same way.
pub fn every_evidence_error() -> Vec<EvidenceError> {
    let mut all = Vec::new();
    let mut next = Some(EvidenceError::NotFound);
    while let Some(error) = next {
        next = match &error {
            EvidenceError::NotFound => Some(EvidenceError::InvalidReference),
            EvidenceError::InvalidReference => Some(EvidenceError::Corrupted),
            EvidenceError::Corrupted => Some(EvidenceError::Unavailable {
                detail: String::from(FAULT),
            }),
            EvidenceError::Unavailable { .. } => None,
        };
        all.push(error);
    }
    all
}

/// How an injected fault fails a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// A job port fails with [`injected_failure`].
    Fails,
    /// An event-store call returns this error.
    Store(StoreError),
    /// An evidence call returns this error.
    Evidence(EvidenceError),
    /// A git call returns this error.
    Git(GitError),
    /// The clock reads 1 ms below its previous reading.
    Backwards,
}

impl FaultKind {
    /// The kind's name in scenario names.
    pub fn name(&self) -> &'static str {
        match self {
            FaultKind::Fails => "fails",
            FaultKind::Store(StoreError::UnknownRun) => "unknown-run",
            FaultKind::Store(StoreError::AlreadyExists) => "already-exists",
            FaultKind::Store(StoreError::InvalidRunId) => "invalid-run-id",
            FaultKind::Store(StoreError::Unavailable { .. })
            | FaultKind::Evidence(EvidenceError::Unavailable { .. }) => "unavailable",
            FaultKind::Evidence(EvidenceError::NotFound) => "not-found",
            FaultKind::Evidence(EvidenceError::InvalidReference) => "invalid-reference",
            FaultKind::Evidence(EvidenceError::Corrupted) => "corrupted",
            FaultKind::Git(GitError::UnknownCommit) => "unknown-commit",
            FaultKind::Git(GitError::UnknownCheckout) => "unknown-checkout",
            FaultKind::Git(GitError::BranchExists) => "branch-exists",
            FaultKind::Git(GitError::Failed { .. }) => "git-failed",
            FaultKind::Backwards => "backwards",
        }
    }
}

/// One injected fault: the `occurrence`-th call (from 1, over all requests
/// of the scenario) of `call` fails as `kind`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    /// The call.
    pub call: Call,
    /// Which of its calls.
    pub occurrence: usize,
    /// How it fails.
    pub kind: FaultKind,
}

/// The failure an injected `Fails` fault returns. Its 700 µUSD differ from
/// an agent job's 1 000, so charging it as a success or as zero changes the
/// total; a verifier's or forge's cost is not charged at all.
pub fn injected_failure() -> JobFailure {
    JobFailure::new("injected failure", "exit status 70", 700)
}

/// Everything a played scenario left behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Played {
    /// Each request's result, in order.
    pub results: Vec<Result<DebugReport, DebugTicketError>>,
    /// Every run log in the store, in `RunId` order.
    pub logs: Vec<(RunId, RunLog)>,
    /// The requests the agent received.
    pub agent: Vec<AgentRequest>,
    /// The requests the verifier received.
    pub verifier: Vec<VerifierRequest>,
    /// The requests the forge received.
    pub forge: Vec<ForgeRequest>,
    /// The diffs `Git::apply` received, in order: the bytes the patch
    /// check judged.
    pub applied: Vec<Vec<u8>>,
    /// Every port call, with the index of the request it belonged to.
    pub calls: Vec<(usize, Call)>,
}

/// The detail of every injected `Unavailable` error.
pub const FAULT: &str = "the disk is full";

/// A `Clock` that returns the given readings in order, then repeats the
/// last one (0 when there are none). It breaks the `Clock` contract when the
/// readings decrease, which is what it is for.
#[derive(Debug)]
pub struct ScriptedClock {
    readings: Vec<u64>,
    taken: Mutex<usize>,
}

impl ScriptedClock {
    /// A clock over `readings`.
    pub fn new(readings: Vec<u64>) -> ScriptedClock {
        ScriptedClock {
            readings,
            taken: Mutex::new(0),
        }
    }
}

impl Clock for ScriptedClock {
    fn now_ms(&self) -> u64 {
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        let k = (*taken).min(self.readings.len().saturating_sub(1));
        *taken += 1;
        self.readings.get(k).copied().unwrap_or(0)
    }
}

/// Records every port call and says when the scenario's fault hits.
#[derive(Debug, Default)]
struct Recorder {
    fault: Option<Fault>,
    request: Mutex<usize>,
    calls: Mutex<Vec<(usize, Call)>>,
    applied: Mutex<Vec<Vec<u8>>>,
}

impl Recorder {
    /// Records the call; the fault kind when this call is the faulted one.
    fn record(&self, call: Call) -> Option<FaultKind> {
        let request = *self.request.lock().unwrap_or_else(PoisonError::into_inner);
        let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
        calls.push((request, call));
        let occurrence = calls.iter().filter(|(_, c)| *c == call).count();
        self.fault
            .as_ref()
            .filter(|f| f.call == call && f.occurrence == occurrence)
            .map(|f| f.kind.clone())
    }
}

/// The adapters of one played scenario, each recording its calls in the
/// shared [`Recorder`] and failing where its fault says. A job port is
/// called before its fault replaces the result, so its script and request
/// record advance as for a real failure; a store or the clock fails
/// instead of being called.
struct Recording<'a, P> {
    inner: P,
    recorder: &'a Recorder,
}

impl<P> Recording<'_, P> {
    fn job<T>(&self, call: Call, result: Result<T, JobFailure>) -> Result<T, JobFailure> {
        match self.recorder.record(call) {
            Some(_) => Err(injected_failure()),
            None => result,
        }
    }

    fn store<T>(
        &self,
        call: Call,
        run: impl FnOnce() -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        match self.recorder.record(call) {
            Some(FaultKind::Store(error)) => Err(error),
            _ => run(),
        }
    }

    fn evidence<T>(
        &self,
        call: Call,
        run: impl FnOnce() -> Result<T, EvidenceError>,
    ) -> Result<T, EvidenceError> {
        match self.recorder.record(call) {
            Some(FaultKind::Evidence(error)) => Err(error),
            _ => run(),
        }
    }

    fn git<T>(&self, call: Call, run: impl FnOnce() -> Result<T, GitError>) -> Result<T, GitError> {
        match self.recorder.record(call) {
            Some(FaultKind::Git(error)) => Err(error),
            _ => run(),
        }
    }
}

impl Agent for Recording<'_, MemoryAgent> {
    fn triage(&self, request: &TriageRequest) -> Result<TriageReport, JobFailure> {
        let result = self.inner.triage(request);
        self.job(Call::Triage, result)
    }
    fn write_reproduction(&self, request: &ReproductionRequest) -> Result<Written, JobFailure> {
        let result = self.inner.write_reproduction(request);
        self.job(Call::WriteReproduction, result)
    }
    fn analyze_root_cause(
        &self,
        request: &RootCauseRequest,
    ) -> Result<RootCauseReport, JobFailure> {
        let result = self.inner.analyze_root_cause(request);
        self.job(Call::AnalyzeRootCause, result)
    }
    fn write_fix(&self, request: &FixRequest) -> Result<Written, JobFailure> {
        let result = self.inner.write_fix(request);
        self.job(Call::WriteFix, result)
    }
}

impl Verifier for Recording<'_, MemoryVerifier> {
    fn check_reproduction(&self, base: &CommitSha, test: &[u8]) -> Result<TestStatus, JobFailure> {
        let result = self.inner.check_reproduction(base, test);
        self.job(Call::CheckReproduction, result)
    }
    fn verify_citations(
        &self,
        base: &CommitSha,
        citations: &[Citation],
    ) -> Result<Vec<CitationStatus>, JobFailure> {
        let result = self.inner.verify_citations(base, citations);
        self.job(Call::VerifyCitations, result)
    }
    fn verify_fix(
        &self,
        base: &CommitSha,
        diff: &[u8],
        test: &[u8],
    ) -> Result<FixChecks, JobFailure> {
        let result = self.inner.verify_fix(base, diff, test);
        self.job(Call::VerifyFix, result)
    }
}

impl Forge for Recording<'_, MemoryForge> {
    fn post_questions(
        &self,
        ticket: &Ticket,
        questions: &[String],
    ) -> Result<ForgeRef, JobFailure> {
        let result = self.inner.post_questions(ticket, questions);
        self.job(Call::PostQuestions, result)
    }
    fn open_pull_request(&self, request: &PullRequest) -> Result<ForgeRef, JobFailure> {
        let result = self.inner.open_pull_request(request);
        self.job(Call::OpenPullRequest, result)
    }
}

impl EventStore for Recording<'_, MemoryEventStore> {
    fn create(&self, id: &RunId, start: &RunStart) -> Result<(), StoreError> {
        self.store(Call::Create, || self.inner.create(id, start))
    }
    fn append(&self, id: &RunId, event: &RunEvent) -> Result<(), StoreError> {
        self.store(Call::Append, || self.inner.append(id, event))
    }
    fn load(&self, id: &RunId) -> Result<RunLog, StoreError> {
        self.store(Call::Load, || self.inner.load(id))
    }
}

impl Evidence for Recording<'_, MemoryEvidence> {
    fn put(&self, content: &[u8]) -> Result<EvidenceRef, EvidenceError> {
        self.evidence(Call::Put, || self.inner.put(content))
    }
    fn get(&self, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError> {
        self.evidence(Call::Get, || self.inner.get(reference))
    }
}

impl Git for Recording<'_, MemoryGit> {
    fn fetch_base(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError> {
        self.git(Call::FetchBase, || self.inner.fetch_base(repo, base))
    }
    fn read(
        &self,
        checkout: &CheckoutId,
        path: &RelativePath,
    ) -> Result<Option<Vec<u8>>, GitError> {
        self.git(Call::Read, || self.inner.read(checkout, path))
    }
    fn snapshot(&self, checkout: &CheckoutId) -> Result<Vec<u8>, GitError> {
        self.git(Call::Snapshot, || self.inner.snapshot(checkout))
    }
    fn diff(&self, checkout: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError> {
        self.git(Call::Diff, || self.inner.diff(checkout, workspace))
    }
    fn apply(&self, checkout: &CheckoutId, diff: &[u8]) -> Result<CheckoutId, GitError> {
        self.recorder
            .applied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(diff.to_vec());
        self.git(Call::Apply, || self.inner.apply(checkout, diff))
    }
    fn patch_between(
        &self,
        base: &CheckoutId,
        after: &CheckoutId,
    ) -> Result<Result<Patch, UnreadablePath>, GitError> {
        self.git(Call::PatchBetween, || self.inner.patch_between(base, after))
    }
    fn push(
        &self,
        checkout: &CheckoutId,
        branch: &BranchName,
        commit: &CommitInfo,
    ) -> Result<CommitSha, GitError> {
        self.git(Call::Push, || self.inner.push(checkout, branch, commit))
    }
}

/// The scenario's clock, recording its readings; a `Backwards` fault reads
/// 1 ms below the reading before it.
struct RecordingClock<'a> {
    inner: Box<dyn Clock>,
    recorder: &'a Recorder,
    last: Mutex<Option<u64>>,
}

impl Clock for RecordingClock<'_> {
    fn now_ms(&self) -> u64 {
        let reading = self.inner.now_ms();
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let now = match (self.recorder.record(Call::Now), *last) {
            (Some(FaultKind::Backwards), Some(previous)) => previous.saturating_sub(1),
            _ => reading,
        };
        *last = Some(now);
        now
    }
}

impl Ids for Recording<'_, SequentialIds> {
    fn run_id(&self) -> RunId {
        let _ = self.recorder.record(Call::RunId);
        self.inner.run_id()
    }
}

/// Plays one scenario on fresh adapters.
pub fn play(scenario: &AppScenario) -> Played {
    let recorder = Recorder {
        fault: scenario.fault.clone(),
        ..Recorder::default()
    };
    let wrap = |inner| Recording {
        inner,
        recorder: &recorder,
    };
    let agent = wrap(MemoryAgent::new(scenario.agent.clone()));
    let verifier = Recording {
        inner: MemoryVerifier::new(scenario.verifier.clone()),
        recorder: &recorder,
    };
    let forge = Recording {
        inner: MemoryForge::scripted(scenario.forge.clone()),
        recorder: &recorder,
    };
    let git = Recording {
        inner: MemoryGit::new(git_commits()),
        recorder: &recorder,
    };
    let events = Recording {
        inner: MemoryEventStore::new(),
        recorder: &recorder,
    };
    let evidence = Recording {
        inner: MemoryEvidence::new(),
        recorder: &recorder,
    };
    let ids = Recording {
        inner: SequentialIds::new(),
        recorder: &recorder,
    };
    let inner: Box<dyn Clock> = match &scenario.clock {
        ClockSetup::Step { start, increment } => Box::new(StepClock::new(*start, *increment)),
        ClockSetup::Readings(readings) => Box::new(ScriptedClock::new(readings.clone())),
    };
    let clock = RecordingClock {
        inner,
        recorder: &recorder,
        last: Mutex::new(None),
    };
    let use_case = DebugTicket {
        agent: &agent,
        verifier: &verifier,
        forge: &forge,
        git: &git,
        events: &events,
        evidence: &evidence,
        clock: &clock,
        ids: &ids,
    };
    let mut results = Vec::new();
    for (k, request) in scenario.requests.iter().enumerate() {
        *recorder
            .request
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = k;
        results.push(use_case.run(request.clone()));
    }
    let calls = recorder
        .calls
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let applied = recorder
        .applied
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    Played {
        results,
        logs: events.inner.logs(),
        agent: agent.inner.requests(),
        verifier: verifier.inner.requests(),
        forge: forge.inner.requests(),
        applied,
        calls,
    }
}

/// For each scenario, in order: `app-scenario <name>`, the pretty `Debug`
/// of [`play`]'s result, then `display <k>: <error>` for every request `k`
/// that returned an error.
pub fn render_app(scenarios: &[AppScenario]) -> String {
    let mut out = String::new();
    for scenario in scenarios {
        let played = play(scenario);
        // Writing to a String cannot fail.
        let _ = write!(out, "app-scenario {}\n{played:#?}\n", scenario.name);
        for (k, result) in played.results.iter().enumerate() {
            if let Err(error) = result {
                let _ = writeln!(out, "display {k}: {error}");
            }
        }
    }
    out
}

/// The `Display` and `Debug` of every variant of every `boneli-app` type
/// with a hand-written `Display`, and the hand-written `Debug` of
/// `TreePath`, so the replay compares them too.
pub fn render_app_errors() -> String {
    let unavailable = || String::from(FAULT);
    let store = [
        StoreError::UnknownRun,
        StoreError::AlreadyExists,
        StoreError::InvalidRunId,
        StoreError::Unavailable {
            detail: unavailable(),
        },
    ];
    let evidence = [
        EvidenceError::NotFound,
        EvidenceError::InvalidReference,
        EvidenceError::Corrupted,
        EvidenceError::Unavailable {
            detail: unavailable(),
        },
    ];
    let debug_ticket = [
        DebugTicketError::Domain(DomainError::InvalidCommitSha),
        DebugTicketError::PreviousRun(PreviousRunError::Unknown),
        DebugTicketError::PreviousRun(PreviousRunError::Unreplayable(
            DomainError::BlankEvidenceRef,
        )),
        DebugTicketError::PreviousRun(PreviousRunError::NotNeedsInformation(Stage::Reproduce)),
        DebugTicketError::PreviousRun(PreviousRunError::DifferentTicket),
        DebugTicketError::Store(StoreError::UnknownRun),
        DebugTicketError::Stalled(EventKind::FixVerified),
    ];
    let sandbox = [
        SandboxError::UnknownSandbox,
        SandboxError::NotFound,
        SandboxError::Failed {
            detail: unavailable(),
        },
    ];
    let git = [
        GitError::UnknownCommit,
        GitError::UnknownCheckout,
        GitError::Failed {
            detail: unavailable(),
        },
    ];
    let image = [
        ImageError::NotFound,
        ImageError::Failed {
            detail: unavailable(),
        },
    ];
    let data = [
        DataError::UnknownSnapshot,
        DataError::UnknownCopy,
        DataError::InvalidRunId,
        DataError::Failed {
            detail: unavailable(),
        },
    ];
    let mut out = String::new();
    for error in store {
        let _ = writeln!(out, "display app: {error}\n{error:?}");
    }
    for error in evidence {
        let _ = writeln!(out, "display app: {error}\n{error:?}");
    }
    for error in debug_ticket {
        let _ = writeln!(out, "display app: {error}\n{error:?}");
    }
    for error in sandbox {
        let _ = writeln!(out, "display app: {error}\n{error:?}");
    }
    for error in git {
        let _ = writeln!(out, "display app: {error}\n{error:?}");
    }
    for error in image {
        let _ = writeln!(out, "display app: {error}\n{error:?}");
    }
    for error in data {
        let _ = writeln!(out, "display app: {error}\n{error:?}");
    }
    // The pod spec problems of ADR-042 (D2), every variant.
    let names = [
        NameProblem::Empty,
        NameProblem::TooLong {
            length: 64,
            max: 63,
        },
        NameProblem::Character { offset: 2 },
        NameProblem::Reserved,
    ];
    for problem in names {
        let _ = writeln!(out, "display app: {problem}\n{problem:?}");
    }
    let limits = [
        LimitProblem::NoContainers,
        LimitProblem::Zero { field: "tmp_bytes" },
        LimitProblem::MemoryBelowStorage {
            storage: Some(2_348_810_240),
            memory: 2_147_483_648,
        },
        LimitProblem::MemoryBelowStorage {
            storage: None,
            memory: 1,
        },
        LimitProblem::TooFewProcesses {
            needed: 4,
            processes: 3,
        },
        LimitProblem::CpuBelowFloor { cpu_millis: 9 },
    ];
    for problem in limits {
        let _ = writeln!(out, "display app: {problem}\n{problem:?}");
    }
    let container = ContainerName::parse("app");
    let broker = BrokerName::parse("sql");
    if let (Ok(container), Ok(broker)) = (container, broker) {
        let specs = [
            SpecProblem::Limits(LimitProblem::NoContainers),
            SpecProblem::DuplicateContainer(container),
            SpecProblem::DuplicateBroker(broker.clone()),
            SpecProblem::DuplicateDependency(LayerRef::new(String::from("layer-1"))),
            SpecProblem::BrokerSocket(broker),
            SpecProblem::VerifyWithBrokers,
            SpecProblem::User,
        ];
        for problem in specs {
            let _ = writeln!(out, "display app: {problem}\n{problem:?}");
        }
    }
    let workspace = WorkspaceBytes::new(b"fn main() {}".to_vec());
    let _ = writeln!(out, "debug app: {workspace:?}");
    // `TreePath`'s `Debug` (ADR-018): a UTF-8 path and one that is not.
    for bytes in [&b"src/a\\b.rs"[..], b"x\xff\"\\"] {
        if let Ok(path) = TreePath::parse(bytes) {
            let _ = writeln!(out, "debug app: {path:?}");
        }
    }
    out
}

// ------------------------------------------------------------------ Corpus

fn base() -> CommitSha {
    CommitSha::parse(BASE).expect("BASE is 40 lowercase hex digits")
}

/// The repository every scenario's base is fetched from.
pub const REPO: &str = "https://git.example/invoices.git";

/// The code the fix changes, with the bug on line 2. Short, because every
/// diff is printed byte by byte in the replay output.
pub const INVOICE: &str = "fn total(a: u64) -> u64 {\n    a + 1\n}\n";

/// The fixed code: line 2 without the extra cent.
pub const INVOICE_FIXED: &str = "fn total(a: u64) -> u64 {\n    a\n}\n";

/// A test file of the base, so a fix can disable a test.
pub const INVOICE_TEST: &str = "import { total } from \"../src/invoice\";

test(\"three lines\", () => {
  expect(total([1, 2, 3])).toBe(6);
});
";

/// CI configuration of the base, a forbidden path (ADR-013, D4).
pub const CI: &str = "on: push\njobs: {}\n";

fn tree_path(path: &[u8]) -> TreePath {
    TreePath::parse(path).expect("a corpus path is a tree path")
}

/// The repository's one commit, at [`BASE`].
pub fn git_commits() -> Vec<GitCommit> {
    let files: Tree = [
        ("src/invoice.rs", INVOICE),
        ("tests/invoice.test.ts", INVOICE_TEST),
        (".github/workflows/ci.yml", CI),
    ]
    .into_iter()
    .map(|(path, content)| (tree_path(path.as_bytes()), content.as_bytes().to_vec()))
    .collect();
    vec![GitCommit {
        repo: RepoUrl::new(String::from(REPO)),
        sha: base(),
        files,
    }]
}

/// A diff in `MemoryGit`'s format: each path with its new content, or
/// `None` for a removal.
pub fn diff_of(changes: &[(&[u8], Option<&str>)]) -> Vec<u8> {
    let changes: Vec<(TreePath, Option<Vec<u8>>)> = changes
        .iter()
        .map(|(path, content)| (tree_path(path), content.map(|c| c.as_bytes().to_vec())))
        .collect();
    pack_diff(&changes)
}

/// The delivering agent's fix: one line of `src/invoice.rs` changed, so
/// the policy passes it as one file and two lines.
pub fn fix_diff() -> Vec<u8> {
    diff_of(&[(b"src/invoice.rs", Some(INVOICE_FIXED))])
}

/// The ticket of every scenario.
pub fn ticket() -> Ticket {
    Ticket {
        source: TicketSource::GitHub,
        key: String::from("BUG-17"),
        title: String::from("Invoice total is one cent too high"),
        body: String::from("Three-line invoices are one cent off."),
    }
}

/// The questions of the first triage that needs information.
pub fn questions() -> Vec<String> {
    vec![
        String::from("Which record?"),
        String::from("Which version?"),
    ]
}

/// The questions of the second one, in a chain.
pub fn second_questions() -> Vec<String> {
    vec![String::from("Which invoice number?")]
}

fn citation(path: &str, line: u32) -> Citation {
    Citation {
        path: String::from(path),
        line,
        sha: base(),
        quote: String::from("total += line.amount + 1;"),
    }
}

fn citations() -> Vec<Citation> {
    vec![
        citation("src/invoice.rs", 42),
        citation("src/invoice.rs", 7),
    ]
}

fn passing_checks() -> FixChecks {
    FixChecks {
        reproduction_test: TestStatus::Passed,
        reproduction_test_unchanged: CheckStatus::Passed,
        previously_green_tests: CheckStatus::Passed,
        lint: CheckStatus::Passed,
        typecheck: CheckStatus::Passed,
    }
}

fn request() -> DebugRequest {
    DebugRequest {
        ticket: ticket(),
        base: base(),
        repo: RepoUrl::new(String::from(REPO)),
        budget: BUDGET,
        patch_limits: PatchLimits::DEFAULT,
        previous: None,
    }
}

/// The default request with a file limit of `files`.
fn file_limit(files: u32) -> DebugRequest {
    let files = NonZeroU32::new(files).expect("a corpus limit is not 0");
    DebugRequest {
        patch_limits: PatchLimits {
            max_changed_files: files,
            ..PatchLimits::DEFAULT
        },
        ..request()
    }
}

fn after(previous: &str) -> DebugRequest {
    DebugRequest {
        previous: Some(RunId::new(String::from(previous))),
        ..request()
    }
}

fn limited(cost_micro_usd: u64, duration_ms: u64) -> DebugRequest {
    DebugRequest {
        budget: Budget {
            cost_micro_usd,
            duration_ms,
        },
        ..request()
    }
}

fn failure(error_output: &str, status: &str, cost_micro_usd: u64) -> ScriptedFailure {
    ScriptedFailure {
        error_output: String::from(error_output),
        status: String::from(status),
        cost_micro_usd,
    }
}

fn ready() -> Response<TriageReport> {
    Response::Answer(TriageReport {
        verdict: TriageVerdict::Ready,
        cost_micro_usd: AGENT_COST,
    })
}

fn needs(questions: Vec<String>) -> Response<TriageReport> {
    Response::Answer(TriageReport {
        verdict: TriageVerdict::NeedsInformation { questions },
        cost_micro_usd: AGENT_COST,
    })
}

fn written(content: &[u8]) -> Response<Written> {
    Response::Answer(Written {
        content: content.to_vec(),
        cost_micro_usd: AGENT_COST,
    })
}

fn analyzed(citations: Vec<Citation>) -> Response<RootCauseReport> {
    Response::Answer(RootCauseReport {
        analysis: b"cause".to_vec(),
        citations,
        cost_micro_usd: AGENT_COST,
    })
}

/// The agent of one delivered run after the given triage answers.
fn agent_after(triage: Vec<Response<TriageReport>>) -> AgentScript {
    AgentScript {
        triage,
        write_reproduction: vec![written(b"test")],
        analyze_root_cause: vec![analyzed(citations())],
        write_fix: vec![written(&fix_diff())],
    }
}

/// The delivering agent with another fix.
fn fixing(diff: Vec<u8>) -> AgentScript {
    AgentScript {
        write_fix: vec![written(&diff)],
        ..delivering_agent()
    }
}

fn delivering_agent() -> AgentScript {
    agent_after(vec![ready()])
}

fn delivering_verifier() -> VerifierScript {
    VerifierScript {
        check_reproduction: vec![Response::Answer(TestStatus::FailedOnAssertion)],
        verify_citations: vec![Response::Answer(vec![CitationStatus::Verified; 2])],
        verify_fix: vec![Response::Answer(passing_checks())],
    }
}

/// A scenario on the delivering scripts, the default clock and no faults.
fn scenario(name: &str, requests: Vec<DebugRequest>) -> AppScenario {
    AppScenario {
        name: String::from(name),
        agent: delivering_agent(),
        verifier: delivering_verifier(),
        forge: ForgeScript::default(),
        clock: ClockSetup::Step {
            start: CLOCK_START,
            increment: STEP_MS,
        },
        fault: None,
        base: None,
        requests,
    }
}

/// The corpus, in a fixed order: the hand-written scenarios, then the
/// fault matrix.
pub fn scenarios() -> Vec<AppScenario> {
    let mut all = hand_written();
    all.extend(fault_scenarios());
    all
}

/// The fault matrix (ADR-004, D7): every hand-written scenario without a
/// fault of its own is played once as a base, and for every port call it
/// made there is one scenario per fault kind of that call
/// ([`Call::fault_kinds`]) that fails exactly that call. The first clock
/// reading of a request is no fault point: no earlier reading of the run
/// exists to go back from.
///
/// A branch added to `DebugTicket` later adds port calls to some base, so
/// its fault scenarios appear here without anyone writing them, and the
/// replay plays them.
pub fn fault_scenarios() -> Vec<AppScenario> {
    let mut all = Vec::new();
    for base in hand_written().into_iter().filter(|s| s.fault.is_none()) {
        let played = play(&base);
        let mut seen: Vec<Call> = Vec::new();
        let mut timed: Vec<usize> = Vec::new();
        for &(request, call) in &played.calls {
            seen.push(call);
            let occurrence = seen.iter().filter(|c| **c == call).count();
            if call == Call::Now && !timed.contains(&request) {
                timed.push(request);
                continue;
            }
            for kind in call.fault_kinds() {
                all.push(AppScenario {
                    name: format!(
                        "fault-{}-{}-{occurrence}-{}",
                        base.name,
                        call.name(),
                        kind.name()
                    ),
                    base: Some(base.name.clone()),
                    fault: Some(Fault {
                        call,
                        occurrence,
                        kind,
                    }),
                    ..base.clone()
                });
            }
        }
    }
    all
}

/// The hand-written scenarios, in a fixed order.
pub fn hand_written() -> Vec<AppScenario> {
    vec![
        scenario("delivered", vec![request()]),
        scenario("delivered-at-limits", vec![limited(4_000, 8_000)]),
        scenario("delivered-over-duration", vec![limited(1_000_000, 7_999)]),
        scenario("cost-exceeded-at-triage", vec![limited(999, 600_000)]),
        scenario("both-limits-crossed", vec![limited(999, 999)]),
        AppScenario {
            agent: AgentScript {
                triage: vec![Response::Fail(failure(
                    "model refused",
                    "exit status 2",
                    AGENT_COST,
                ))],
                ..AgentScript::default()
            },
            ..scenario("failed-job-over-budget", vec![limited(999, 600_000)])
        },
        AppScenario {
            clock: ClockSetup::Step {
                start: CLOCK_START,
                increment: 0,
            },
            ..scenario("equal-clock-readings", vec![request()])
        },
        AppScenario {
            clock: ClockSetup::Readings(vec![5_000, 4_000]),
            ..scenario("clock-backwards", vec![request()])
        },
        AppScenario {
            agent: agent_after(vec![needs(questions()), ready()]),
            ..scenario("rerun-after-questions", vec![request(), after("run-1")])
        },
        AppScenario {
            agent: agent_after(vec![needs(questions()), needs(second_questions()), ready()]),
            ..scenario(
                "rerun-chain",
                vec![request(), after("run-1"), after("run-2")],
            )
        },
        scenario("rerun-unknown-previous", vec![after("run-9"), request()]),
        AppScenario {
            agent: agent_after(vec![needs(questions()), ready()]),
            ..scenario(
                "rerun-hostile-previous-id",
                vec![
                    request(),
                    after("../run-1"),
                    after("run-1\u{200B}"),
                    after(""),
                    after("run-1"),
                ],
            )
        },
        scenario("rerun-previous-delivered", vec![request(), after("run-1")]),
        AppScenario {
            fault: Some(Fault {
                call: Call::Append,
                occurrence: 3,
                kind: FaultKind::Store(StoreError::Unavailable {
                    detail: String::from(FAULT),
                }),
            }),
            ..scenario("rerun-previous-unfinished", vec![request(), after("run-1")])
        },
        AppScenario {
            agent: agent_after(vec![needs(questions())]),
            ..scenario(
                "rerun-different-ticket",
                vec![
                    request(),
                    DebugRequest {
                        ticket: Ticket {
                            source: TicketSource::GitLab,
                            ..ticket()
                        },
                        ..after("run-1")
                    },
                    DebugRequest {
                        ticket: Ticket {
                            key: String::from("BUG-17 "),
                            ..ticket()
                        },
                        ..after("run-1")
                    },
                    DebugRequest {
                        ticket: Ticket {
                            key: String::from("\u{0412}UG-17"),
                            ..ticket()
                        },
                        ..after("run-1")
                    },
                ],
            )
        },
        AppScenario {
            agent: agent_after(vec![needs(questions()), ready()]),
            ..scenario(
                "rerun-title-changed",
                vec![
                    request(),
                    DebugRequest {
                        ticket: Ticket {
                            title: String::from("Invoice total is off by one cent"),
                            ..ticket()
                        },
                        ..after("run-1")
                    },
                ],
            )
        },
        AppScenario {
            agent: AgentScript {
                triage: vec![Response::Fail(failure("", "exit status 3", 500))],
                ..AgentScript::default()
            },
            ..scenario("agent-silent-failure", vec![request()])
        },
        AppScenario {
            verifier: VerifierScript {
                // A verifier spends no provider budget: its reported cost is
                // not charged.
                check_reproduction: vec![Response::Fail(failure(
                    "runner crashed",
                    "exit status 1",
                    5,
                ))],
                ..VerifierScript::default()
            },
            ..scenario("verifier-failure", vec![request()])
        },
        AppScenario {
            agent: agent_after(vec![needs(questions())]),
            forge: ForgeScript {
                post_questions: vec![Response::Fail(failure("rate limited", "HTTP 429", 9))],
                open_pull_request: vec![],
            },
            ..scenario("forge-questions-failure", vec![request()])
        },
        AppScenario {
            forge: ForgeScript {
                post_questions: vec![],
                open_pull_request: vec![Response::Fail(failure("", "HTTP 502", 9))],
            },
            ..scenario("forge-pull-request-failure", vec![request()])
        },
        AppScenario {
            agent: AgentScript::default(),
            ..scenario("agent-script-exhausted", vec![request()])
        },
        AppScenario {
            fault: Some(Fault {
                call: Call::Append,
                occurrence: 3,
                kind: FaultKind::Store(StoreError::Unavailable {
                    detail: String::from(FAULT),
                }),
            }),
            ..scenario("event-store-append-fails", vec![request()])
        },
        AppScenario {
            fault: Some(Fault {
                call: Call::Put,
                occurrence: 1,
                kind: FaultKind::Evidence(EvidenceError::Unavailable {
                    detail: String::from(FAULT),
                }),
            }),
            ..scenario("evidence-store-fails", vec![request()])
        },
        AppScenario {
            fault: Some(Fault {
                call: Call::Get,
                occurrence: 1,
                kind: FaultKind::Evidence(EvidenceError::Unavailable {
                    detail: String::from(FAULT),
                }),
            }),
            ..scenario("evidence-load-fails", vec![request()])
        },
        scenario(
            "invalid-ticket-zero-width-key",
            vec![DebugRequest {
                ticket: Ticket {
                    key: String::from("\u{200B}"),
                    ..ticket()
                },
                ..request()
            }],
        ),
        scenario("invalid-budget-zero", vec![limited(0, 600_000)]),
        AppScenario {
            verifier: VerifierScript {
                check_reproduction: vec![Response::Answer(TestStatus::Passed)],
                ..delivering_verifier()
            },
            ..scenario("gate-failed-reproduction", vec![request()])
        },
        AppScenario {
            agent: AgentScript {
                analyze_root_cause: vec![analyzed(vec![])],
                ..delivering_agent()
            },
            ..scenario("gate-failed-no-citations", vec![request()])
        },
        AppScenario {
            verifier: VerifierScript {
                verify_citations: vec![Response::Answer(vec![
                    CitationStatus::Verified,
                    CitationStatus::Unverifiable,
                ])],
                ..delivering_verifier()
            },
            ..scenario("gate-failed-citations", vec![request()])
        },
        AppScenario {
            verifier: VerifierScript {
                verify_fix: vec![Response::Answer(FixChecks {
                    lint: CheckStatus::Failed,
                    ..passing_checks()
                })],
                ..delivering_verifier()
            },
            ..scenario("gate-failed-fix", vec![request()])
        },
        AppScenario {
            agent: agent_after(vec![needs(vec![
                String::from("Which record?"),
                String::from(" "),
            ])]),
            ..scenario("blank-question", vec![request()])
        },
        // The patch check (ADR-023, D8).
        AppScenario {
            agent: fixing(forbidden_fix()),
            ..scenario("patch-forbidden-path", vec![request()])
        },
        AppScenario {
            agent: fixing(diff_of(&[
                (b"src/invoice.rs", Some(INVOICE_FIXED)),
                (
                    b"tests/invoice.test.ts",
                    Some(&INVOICE_TEST.replace("test(", "test.skip(")),
                ),
            ])),
            ..scenario("patch-disables-test", vec![request()])
        },
        AppScenario {
            agent: fixing(two_file_fix()),
            ..scenario("patch-over-file-limit", vec![file_limit(1)])
        },
        AppScenario {
            agent: fixing(two_file_fix()),
            ..scenario("patch-at-file-limit", vec![file_limit(2)])
        },
        AppScenario {
            agent: fixing(Vec::new()),
            ..scenario("patch-empty-fix", vec![request()])
        },
        AppScenario {
            agent: fixing(diff_of(&[
                (b"src/invoice.rs", Some(INVOICE_FIXED)),
                (b"src/inv\xffoice.rs", Some(INVOICE_FIXED)),
            ])),
            ..scenario("patch-unreadable-path", vec![request()])
        },
        AppScenario {
            agent: fixing(diff_of(&[(b"src/missing.rs", None)])),
            ..scenario("patch-diff-does-not-apply", vec![request()])
        },
        scenario("patch-check-over-duration", vec![limited(1_000_000, 6_999)]),
        AppScenario {
            agent: fixing(forbidden_fix()),
            ..scenario(
                "patch-refused-over-duration",
                vec![limited(1_000_000, 6_999)],
            )
        },
    ]
}

/// The fix plus an edit of the CI configuration.
fn forbidden_fix() -> Vec<u8> {
    diff_of(&[
        (
            b".github/workflows/ci.yml",
            Some("on: push\njobs: {}\n# ok\n"),
        ),
        (b"src/invoice.rs", Some(INVOICE_FIXED)),
    ])
}

/// The fix plus a new file: two changed files.
fn two_file_fix() -> Vec<u8> {
    diff_of(&[
        (b"src/invoice.rs", Some(INVOICE_FIXED)),
        (b"src/rounding.rs", Some("pub const CENT: u64 = 1;\n")),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_clock_repeats_its_last_reading() {
        let clock = ScriptedClock::new(vec![3, 1]);
        let readings: Vec<u64> = (0..4).map(|_| clock.now_ms()).collect();
        assert_eq!(readings, [3, 1, 1, 1]);
        assert_eq!(ScriptedClock::new(vec![]).now_ms(), 0);
    }
}
