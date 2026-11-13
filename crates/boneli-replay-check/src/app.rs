//! The app scenario corpus: `DebugTicket` end to end on in-memory adapters
//! (ADR-004, D7).
//!
//! Every `DebugTicket` test runs through this corpus, so the two-process
//! replay sees every path those tests exercise. A scenario is plain data:
//! scripts for the in-memory agent, verifier and forge, a clock, optional
//! store faults and the requests, in order. [`play`] runs it with a fixed
//! `Clock` and `SequentialIds` and returns everything that is compared:
//! each request's result, every run log and every recorded job request.
//!
//! Three fault doubles here knowingly break their port's contract, to drive
//! paths no contract-abiding adapter reaches: [`ScriptedClock`] goes
//! backwards, [`FailingEvidence`] and [`FailingEventStore`] fail one call.

use std::fmt::Write as _;
use std::sync::{Mutex, PoisonError};

use boneli_app::{
    Clock, DebugReport, DebugRequest, DebugTicket, DebugTicketError, EventStore, Evidence,
    EvidenceError, PreviousRunError, RootCauseReport, RunLog, RunStart, StoreError, TriageReport,
    Written,
};
use boneli_domain::{
    Budget, CheckStatus, Citation, CitationStatus, CommitSha, DomainError, EventKind, EvidenceRef,
    FixChecks, RunEvent, RunId, Stage, TestStatus, Ticket, TicketSource, TriageVerdict,
};
use boneli_memory::{
    AgentRequest, AgentScript, ForgeRequest, ForgeScript, MemoryAgent, MemoryEventStore,
    MemoryEvidence, MemoryForge, MemoryVerifier, Response, ScriptedFailure, SequentialIds,
    StepClock, VerifierRequest, VerifierScript,
};

/// The base commit of every scenario.
pub const BASE: &str = "0123456789abcdef0123456789abcdef01234567";

/// The budget of every scenario that does not test the budget: far above
/// the largest spend of one corpus run (4 000 µUSD, 7 000 ms).
pub const BUDGET: Budget = Budget {
    cost_micro_usd: 1_000_000,
    duration_ms: 600_000,
};

/// The cost of every agent job, in micro-USD.
pub const AGENT_COST: u64 = 1_000;

/// The step of the default clock: every measured job lasts 1 000 ms, so the
/// delivered path's 7 measured jobs take 7 000 ms.
pub const STEP_MS: u64 = 1_000;

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
    /// Store faults.
    pub faults: Faults,
    /// The requests, played in order on the same adapters.
    pub requests: Vec<DebugRequest>,
}

/// Store faults of a scenario. Calls are counted from 1, over all requests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Faults {
    /// The evidence `put` that fails as unavailable.
    pub evidence_put: Option<usize>,
    /// The evidence `get` that fails as unavailable.
    pub evidence_get: Option<usize>,
    /// The evidence `get` before which the stored content is overwritten
    /// behind the store's back (ADR-004, D9).
    pub evidence_tamper: Option<usize>,
    /// Whether every event-store `create` fails as unavailable.
    pub event_create: bool,
    /// The event-store `append` that fails as unavailable.
    pub event_append: Option<usize>,
}

/// How often each fallible port was called while a scenario played. The
/// fault matrix ([`fault_scenarios`]) injects a fault at each of these
/// calls of the delivered run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Calls {
    /// Evidence `put` calls.
    pub evidence_put: usize,
    /// Evidence `get` calls.
    pub evidence_get: usize,
    /// Event-store `create` calls.
    pub event_create: usize,
    /// Event-store `append` calls.
    pub event_append: usize,
    /// `Clock` readings.
    pub clock: usize,
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
    /// How often the stores and the clock were called.
    pub calls: Calls,
}

/// The detail every fault double reports.
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

/// The bytes a tamper fault writes over the stored content.
pub const TAMPERED: &[u8] = b"tampered";

/// [`MemoryEvidence`] with the evidence faults of [`Faults`]: one `put` or
/// `get` fails as unavailable, or the content under one `get`'s reference
/// is overwritten just before it, which the store must reject.
#[derive(Debug, Default)]
pub struct FailingEvidence {
    inner: MemoryEvidence,
    fail_put: Option<usize>,
    fail_get: Option<usize>,
    tamper_get: Option<usize>,
    puts: Mutex<usize>,
    gets: Mutex<usize>,
}

impl FailingEvidence {
    /// A store with the evidence faults of `faults`.
    pub fn new(faults: &Faults) -> FailingEvidence {
        FailingEvidence {
            fail_put: faults.evidence_put,
            fail_get: faults.evidence_get,
            tamper_get: faults.evidence_tamper,
            ..FailingEvidence::default()
        }
    }

    fn count(calls: &Mutex<usize>) -> usize {
        let mut calls = calls.lock().unwrap_or_else(PoisonError::into_inner);
        *calls += 1;
        *calls
    }
}

impl Evidence for FailingEvidence {
    fn put(&self, content: &[u8]) -> Result<EvidenceRef, EvidenceError> {
        if Some(FailingEvidence::count(&self.puts)) == self.fail_put {
            return Err(EvidenceError::Unavailable {
                detail: String::from(FAULT),
            });
        }
        self.inner.put(content)
    }

    fn get(&self, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError> {
        let n = Some(FailingEvidence::count(&self.gets));
        if n == self.fail_get {
            return Err(EvidenceError::Unavailable {
                detail: String::from(FAULT),
            });
        }
        if n == self.tamper_get {
            self.inner.tamper(reference, TAMPERED);
        }
        self.inner.get(reference)
    }
}

/// [`MemoryEventStore`] with the event-store faults of [`Faults`].
#[derive(Debug, Default)]
pub struct FailingEventStore {
    inner: MemoryEventStore,
    fail_create: bool,
    fail_append: Option<usize>,
    creates: Mutex<usize>,
    appends: Mutex<usize>,
}

impl FailingEventStore {
    /// A store with the event-store faults of `faults`.
    pub fn new(faults: &Faults) -> FailingEventStore {
        FailingEventStore {
            fail_create: faults.event_create,
            fail_append: faults.event_append,
            ..FailingEventStore::default()
        }
    }

    /// Every log, in `RunId` order.
    pub fn logs(&self) -> Vec<(RunId, RunLog)> {
        self.inner.logs()
    }
}

impl EventStore for FailingEventStore {
    fn create(&self, id: &RunId, start: &RunStart) -> Result<(), StoreError> {
        FailingEvidence::count(&self.creates);
        if self.fail_create {
            return Err(StoreError::Unavailable {
                detail: String::from(FAULT),
            });
        }
        self.inner.create(id, start)
    }

    fn append(&self, id: &RunId, event: &RunEvent) -> Result<(), StoreError> {
        if Some(FailingEvidence::count(&self.appends)) == self.fail_append {
            return Err(StoreError::Unavailable {
                detail: String::from(FAULT),
            });
        }
        self.inner.append(id, event)
    }

    fn load(&self, id: &RunId) -> Result<RunLog, StoreError> {
        self.inner.load(id)
    }
}

/// Counts the readings of the clock it wraps.
struct CountingClock<'a> {
    inner: &'a dyn Clock,
    readings: Mutex<usize>,
}

impl Clock for CountingClock<'_> {
    fn now_ms(&self) -> u64 {
        FailingEvidence::count(&self.readings);
        self.inner.now_ms()
    }
}

fn taken(calls: &Mutex<usize>) -> usize {
    *calls.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Plays one scenario on fresh adapters.
pub fn play(scenario: &AppScenario) -> Played {
    let agent = MemoryAgent::new(scenario.agent.clone());
    let verifier = MemoryVerifier::new(scenario.verifier.clone());
    let forge = MemoryForge::scripted(scenario.forge.clone());
    let events = FailingEventStore::new(&scenario.faults);
    let evidence = FailingEvidence::new(&scenario.faults);
    let ids = SequentialIds::new();
    let step;
    let scripted;
    let inner: &dyn Clock = match &scenario.clock {
        ClockSetup::Step { start, increment } => {
            step = StepClock::new(*start, *increment);
            &step
        }
        ClockSetup::Readings(readings) => {
            scripted = ScriptedClock::new(readings.clone());
            &scripted
        }
    };
    let clock = CountingClock {
        inner,
        readings: Mutex::new(0),
    };
    let use_case = DebugTicket {
        agent: &agent,
        verifier: &verifier,
        forge: &forge,
        events: &events,
        evidence: &evidence,
        clock: &clock,
        ids: &ids,
    };
    let results = scenario
        .requests
        .iter()
        .map(|request| use_case.run(request.clone()))
        .collect();
    Played {
        results,
        logs: events.logs(),
        agent: agent.requests(),
        verifier: verifier.requests(),
        forge: forge.requests(),
        calls: Calls {
            evidence_put: taken(&evidence.puts),
            evidence_get: taken(&evidence.gets),
            event_create: taken(&events.creates),
            event_append: taken(&events.appends),
            clock: taken(&clock.readings),
        },
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
/// with a hand-written `Display`, so the replay compares them too.
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
    out
}

// ------------------------------------------------------------------ Corpus

fn base() -> CommitSha {
    CommitSha::parse(BASE).expect("BASE is 40 lowercase hex digits")
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
        budget: BUDGET,
        previous: None,
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
        write_fix: vec![written(b"diff")],
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
            start: 0,
            increment: STEP_MS,
        },
        faults: Faults::default(),
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

/// The failure every agent fault returns: it ran up provider cost.
pub fn agent_fault() -> ScriptedFailure {
    failure("agent crashed", "exit status 2", 700)
}

/// The failure every verifier fault returns; its cost is not charged.
pub fn verifier_fault() -> ScriptedFailure {
    failure("runner crashed", "exit status 1", 5)
}

/// The failure every forge fault returns; forge calls carry no usage.
pub fn forge_fault() -> ScriptedFailure {
    failure("bad gateway", "HTTP 502", 9)
}

/// The first reading of the clock in the clock-backwards faults: above
/// 5 000 ms, so a guard that only checks early readings is caught too.
pub const BACKWARDS_START: u64 = 10_000;

/// The script with its `occurrence`-th response (from 1) failing.
fn fail_at<T: Clone>(
    script: &[Response<T>],
    occurrence: usize,
    fault: ScriptedFailure,
) -> Vec<Response<T>> {
    let mut script = script.to_vec();
    let failing = Response::Fail(fault);
    match script.get_mut(occurrence - 1) {
        Some(slot) => *slot = failing,
        None => script.push(failing),
    }
    script
}

/// The occurrence (from 1) of each element among those with the same key.
fn occurrences<K: PartialEq>(keys: &[K]) -> Vec<usize> {
    keys.iter()
        .enumerate()
        .map(|(k, key)| keys[..=k].iter().filter(|other| *other == key).count())
        .collect()
}

/// The fault matrix (ADR-004, D7): the delivered run is played once, and
/// for every call it made to a port that can fail there is one scenario
/// that fails exactly that call, per failure kind:
///
/// - every agent, verifier and forge call fails with a scripted failure;
/// - every evidence `put` and `get` fails as unavailable, and every `get`
///   also meets content overwritten behind the store's back;
/// - the event-store `create` and every `append` fail as unavailable;
/// - the clock goes back 1 ms at the second reading of every measured job.
///   The first reading of a job is not a fault point: `DebugTicket` only
///   compares the two readings of one job.
///
/// A branch added to `DebugTicket` later adds port calls, so its scenarios
/// appear here without anyone writing them, and the replay plays them.
pub fn fault_scenarios() -> Vec<AppScenario> {
    let happy = scenario("delivered", vec![request()]);
    let played = play(&happy);
    let calls = played.calls;
    let mut all = Vec::new();
    let fault = |name: String, faults: Faults| AppScenario {
        name,
        faults,
        ..happy.clone()
    };

    let agent_ops: Vec<&str> = played.agent.iter().map(agent_operation).collect();
    for (op, occurrence) in agent_ops.iter().zip(occurrences(&agent_ops)) {
        let mut agent = happy.agent.clone();
        let f = agent_fault();
        match *op {
            "triage" => agent.triage = fail_at(&agent.triage, occurrence, f),
            "write_reproduction" => {
                agent.write_reproduction = fail_at(&agent.write_reproduction, occurrence, f);
            }
            "analyze_root_cause" => {
                agent.analyze_root_cause = fail_at(&agent.analyze_root_cause, occurrence, f);
            }
            _ => agent.write_fix = fail_at(&agent.write_fix, occurrence, f),
        }
        all.push(AppScenario {
            name: format!("fault-agent-{}-{occurrence}", op.replace('_', "-")),
            agent,
            ..happy.clone()
        });
    }
    let verifier_ops: Vec<&str> = played.verifier.iter().map(verifier_operation).collect();
    for (op, occurrence) in verifier_ops.iter().zip(occurrences(&verifier_ops)) {
        let mut verifier = happy.verifier.clone();
        let f = verifier_fault();
        match *op {
            "check_reproduction" => {
                verifier.check_reproduction = fail_at(&verifier.check_reproduction, occurrence, f);
            }
            "verify_citations" => {
                verifier.verify_citations = fail_at(&verifier.verify_citations, occurrence, f);
            }
            _ => verifier.verify_fix = fail_at(&verifier.verify_fix, occurrence, f),
        }
        all.push(AppScenario {
            name: format!("fault-verifier-{}-{occurrence}", op.replace('_', "-")),
            verifier,
            ..happy.clone()
        });
    }
    let forge_ops: Vec<&str> = played.forge.iter().map(forge_operation).collect();
    for (op, occurrence) in forge_ops.iter().zip(occurrences(&forge_ops)) {
        let mut forge = happy.forge.clone();
        let failing = |script: &[Response<()>]| fail_at(script, occurrence, forge_fault());
        match *op {
            "post_questions" => forge.post_questions = failing(&forge.post_questions),
            _ => forge.open_pull_request = failing(&forge.open_pull_request),
        }
        all.push(AppScenario {
            name: format!("fault-forge-{}-{occurrence}", op.replace('_', "-")),
            forge,
            ..happy.clone()
        });
    }
    for n in 1..=calls.evidence_put {
        let faults = Faults {
            evidence_put: Some(n),
            ..Faults::default()
        };
        all.push(fault(format!("fault-evidence-put-{n}"), faults));
    }
    for n in 1..=calls.evidence_get {
        let faults = Faults {
            evidence_get: Some(n),
            ..Faults::default()
        };
        all.push(fault(format!("fault-evidence-get-{n}"), faults));
        let faults = Faults {
            evidence_tamper: Some(n),
            ..Faults::default()
        };
        all.push(fault(format!("fault-evidence-tamper-{n}"), faults));
    }
    if calls.event_create > 0 {
        let faults = Faults {
            event_create: true,
            ..Faults::default()
        };
        all.push(fault(String::from("fault-event-create"), faults));
    }
    for n in 1..=calls.event_append {
        let faults = Faults {
            event_append: Some(n),
            ..Faults::default()
        };
        all.push(fault(format!("fault-event-append-{n}"), faults));
    }
    for job in 1..=calls.clock / 2 {
        let before = (1..2 * job).map(|k| BACKWARDS_START + STEP_MS * (k as u64 - 1));
        let mut readings: Vec<u64> = before.collect();
        let last = readings.last().copied().unwrap_or(BACKWARDS_START);
        readings.push(last - 1);
        all.push(AppScenario {
            name: format!("fault-clock-backwards-{job}"),
            clock: ClockSetup::Readings(readings),
            ..happy.clone()
        });
    }
    all
}

/// The operation an agent request was for.
pub fn agent_operation(request: &AgentRequest) -> &'static str {
    match request {
        AgentRequest::Triage(_) => "triage",
        AgentRequest::WriteReproduction(_) => "write_reproduction",
        AgentRequest::AnalyzeRootCause(_) => "analyze_root_cause",
        AgentRequest::WriteFix(_) => "write_fix",
    }
}

/// The operation a verifier request was for.
pub fn verifier_operation(request: &VerifierRequest) -> &'static str {
    match request {
        VerifierRequest::CheckReproduction { .. } => "check_reproduction",
        VerifierRequest::VerifyCitations { .. } => "verify_citations",
        VerifierRequest::VerifyFix { .. } => "verify_fix",
    }
}

/// The operation a forge request was for.
pub fn forge_operation(request: &ForgeRequest) -> &'static str {
    match request {
        ForgeRequest::PostQuestions { .. } => "post_questions",
        ForgeRequest::OpenPullRequest(_) => "open_pull_request",
    }
}

fn hand_written() -> Vec<AppScenario> {
    vec![
        scenario("delivered", vec![request()]),
        scenario("delivered-at-limits", vec![limited(4_000, 7_000)]),
        scenario("delivered-over-duration", vec![limited(1_000_000, 6_999)]),
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
                start: 0,
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
            faults: Faults {
                event_append: Some(3),
                ..Faults::default()
            },
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
            faults: Faults {
                event_append: Some(3),
                ..Faults::default()
            },
            ..scenario("event-store-append-fails", vec![request()])
        },
        AppScenario {
            faults: Faults {
                evidence_put: Some(1),
                ..Faults::default()
            },
            ..scenario("evidence-store-fails", vec![request()])
        },
        AppScenario {
            faults: Faults {
                evidence_get: Some(1),
                ..Faults::default()
            },
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
    ]
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
