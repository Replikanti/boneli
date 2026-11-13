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
    pub name: &'static str,
    /// The agent's answers.
    pub agent: AgentScript,
    /// The verifier's answers.
    pub verifier: VerifierScript,
    /// The forge's failures.
    pub forge: ForgeScript,
    /// The clock.
    pub clock: ClockSetup,
    /// The 1-based number of the evidence `put` that fails, if any.
    pub fail_evidence_put: Option<usize>,
    /// The 1-based number of the evidence `get` that fails, if any.
    pub fail_evidence_get: Option<usize>,
    /// The 1-based number of the event-store `append` that fails, if any.
    pub fail_event_append: Option<usize>,
    /// The requests, played in order on the same adapters.
    pub requests: Vec<DebugRequest>,
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

/// Counts calls and says whether this one is the `fail`-th.
fn hits(calls: &Mutex<usize>, fail: Option<usize>) -> bool {
    let mut calls = calls.lock().unwrap_or_else(PoisonError::into_inner);
    *calls += 1;
    fail == Some(*calls)
}

/// [`MemoryEvidence`] whose `fail_put`-th `put` and `fail_get`-th `get`
/// fail as unavailable.
#[derive(Debug, Default)]
pub struct FailingEvidence {
    inner: MemoryEvidence,
    fail_put: Option<usize>,
    fail_get: Option<usize>,
    puts: Mutex<usize>,
    gets: Mutex<usize>,
}

impl FailingEvidence {
    /// A store that fails the given calls, counted from 1.
    pub fn new(fail_put: Option<usize>, fail_get: Option<usize>) -> FailingEvidence {
        FailingEvidence {
            fail_put,
            fail_get,
            ..FailingEvidence::default()
        }
    }
}

impl Evidence for FailingEvidence {
    fn put(&self, content: &[u8]) -> Result<EvidenceRef, EvidenceError> {
        if hits(&self.puts, self.fail_put) {
            return Err(EvidenceError::Unavailable {
                detail: String::from(FAULT),
            });
        }
        self.inner.put(content)
    }

    fn get(&self, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError> {
        if hits(&self.gets, self.fail_get) {
            return Err(EvidenceError::Unavailable {
                detail: String::from(FAULT),
            });
        }
        self.inner.get(reference)
    }
}

/// [`MemoryEventStore`] whose `fail_append`-th `append` fails as
/// unavailable.
#[derive(Debug, Default)]
pub struct FailingEventStore {
    inner: MemoryEventStore,
    fail_append: Option<usize>,
    appends: Mutex<usize>,
}

impl FailingEventStore {
    /// A store that fails the given append, counted from 1.
    pub fn new(fail_append: Option<usize>) -> FailingEventStore {
        FailingEventStore {
            fail_append,
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
        self.inner.create(id, start)
    }

    fn append(&self, id: &RunId, event: &RunEvent) -> Result<(), StoreError> {
        if hits(&self.appends, self.fail_append) {
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

/// Plays one scenario on fresh adapters.
pub fn play(scenario: &AppScenario) -> Played {
    let agent = MemoryAgent::new(scenario.agent.clone());
    let verifier = MemoryVerifier::new(scenario.verifier.clone());
    let forge = MemoryForge::scripted(scenario.forge.clone());
    let events = FailingEventStore::new(scenario.fail_event_append);
    let evidence = FailingEvidence::new(scenario.fail_evidence_put, scenario.fail_evidence_get);
    let ids = SequentialIds::new();
    let step;
    let scripted;
    let clock: &dyn Clock = match &scenario.clock {
        ClockSetup::Step { start, increment } => {
            step = StepClock::new(*start, *increment);
            &step
        }
        ClockSetup::Readings(readings) => {
            scripted = ScriptedClock::new(readings.clone());
            &scripted
        }
    };
    let use_case = DebugTicket {
        agent: &agent,
        verifier: &verifier,
        forge: &forge,
        events: &events,
        evidence: &evidence,
        clock,
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
fn scenario(name: &'static str, requests: Vec<DebugRequest>) -> AppScenario {
    AppScenario {
        name,
        agent: delivering_agent(),
        verifier: delivering_verifier(),
        forge: ForgeScript::default(),
        clock: ClockSetup::Step {
            start: 0,
            increment: STEP_MS,
        },
        fail_evidence_put: None,
        fail_evidence_get: None,
        fail_event_append: None,
        requests,
    }
}

/// The corpus, in a fixed order.
pub fn scenarios() -> Vec<AppScenario> {
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
            fail_event_append: Some(3),
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
            fail_event_append: Some(3),
            ..scenario("event-store-append-fails", vec![request()])
        },
        AppScenario {
            fail_evidence_put: Some(1),
            ..scenario("evidence-store-fails", vec![request()])
        },
        AppScenario {
            fail_evidence_get: Some(1),
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
