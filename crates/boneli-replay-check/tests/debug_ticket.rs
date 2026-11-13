//! `DebugTicket` end to end on in-memory adapters (ADR-004, D5-D7).
//!
//! Every test plays scenarios of the app corpus, so the two-process replay
//! sees every path these tests exercise; the bijection test makes a
//! scenario without an expectation fail.

use std::collections::BTreeSet;

use boneli_app::{
    DebugTicketError, EvidenceError, PreviousRunError, PreviousTriage, StoreError, replay,
};
use boneli_domain::{
    AgentOutputProblem, Budget, BudgetDimension, DomainError, EventKind, FixCheck, GateFailure,
    Outcome, Overrun, RunId, Stage, TicketField, Usage,
};
use boneli_memory::{AgentRequest, ForgeRequest, VerifierRequest};
use boneli_replay_check::app::{
    AppScenario, CLOCK_START, Call, FAULT, Fault, FaultKind, Played, STEP_MS, play, questions,
    scenarios, second_questions,
};

type Want = Result<(Stage, Usage), DebugTicketError>;

struct Expectation {
    name: String,
    /// Each request's final stage and spending, or its error.
    results: Vec<Want>,
    agent: usize,
    verifier: usize,
    forge: usize,
}

fn usage(cost_micro_usd: u64, duration_ms: u64) -> Usage {
    Usage {
        cost_micro_usd,
        duration_ms,
    }
}

fn budget(cost_micro_usd: u64, duration_ms: u64) -> Budget {
    Budget {
        cost_micro_usd,
        duration_ms,
    }
}

fn done(outcome: Outcome, spent: Usage) -> Want {
    Ok((Stage::Done(outcome), spent))
}

fn delivered(pull_request: &str) -> Outcome {
    Outcome::Delivered {
        pull_request: String::from(pull_request),
        overrun: None,
    }
}

fn asked(comment: &str) -> Outcome {
    Outcome::NeedsInformation {
        comment: String::from(comment),
    }
}

fn job_failed(awaiting: EventKind, detail: &str) -> Outcome {
    Outcome::JobFailed {
        awaiting,
        detail: String::from(detail),
    }
}

fn over(dimension: BudgetDimension, spent: Usage, budget: Budget) -> Outcome {
    Outcome::BudgetExceeded(Overrun {
        dimension,
        spent,
        budget,
    })
}

fn previous(error: PreviousRunError) -> Want {
    Err(DebugTicketError::PreviousRun(error))
}

fn unavailable() -> Want {
    Err(DebugTicketError::Store(StoreError::Unavailable {
        detail: String::from(FAULT),
    }))
}

fn expect(
    name: &'static str,
    results: Vec<Want>,
    (agent, verifier, forge): (usize, usize, usize),
) -> Expectation {
    Expectation {
        name: String::from(name),
        results,
        agent,
        verifier,
        forge,
    }
}

/// The full delivered path: 4 agent jobs of 1 000 µUSD and 7 measured jobs
/// of 1 000 ms.
const FULL: Usage = Usage {
    cost_micro_usd: 4_000,
    duration_ms: 7_000,
};
const TRIAGE: Usage = Usage {
    cost_micro_usd: 1_000,
    duration_ms: 1_000,
};

fn expectations() -> Vec<Expectation> {
    let mut all = hand_written_expectations();
    all.extend(fault_expectations());
    all
}

fn hand_written_expectations() -> Vec<Expectation> {
    let stored = "the evidence store is unavailable: the disk is full";
    vec![
        expect(
            "delivered",
            vec![done(delivered("pull-1"), FULL)],
            (4, 3, 1),
        ),
        expect(
            "delivered-at-limits",
            vec![done(delivered("pull-1"), FULL)],
            (4, 3, 1),
        ),
        expect(
            "delivered-over-duration",
            vec![done(
                Outcome::Delivered {
                    pull_request: String::from("pull-1"),
                    overrun: Some(Overrun {
                        dimension: BudgetDimension::Duration,
                        spent: FULL,
                        budget: budget(1_000_000, 6_999),
                    }),
                },
                FULL,
            )],
            (4, 3, 1),
        ),
        expect(
            "cost-exceeded-at-triage",
            vec![done(
                over(BudgetDimension::Cost, TRIAGE, budget(999, 600_000)),
                TRIAGE,
            )],
            (1, 0, 0),
        ),
        expect(
            "both-limits-crossed",
            vec![done(
                over(BudgetDimension::Cost, TRIAGE, budget(999, 999)),
                TRIAGE,
            )],
            (1, 0, 0),
        ),
        expect(
            "failed-job-over-budget",
            vec![done(
                over(BudgetDimension::Cost, TRIAGE, budget(999, 600_000)),
                TRIAGE,
            )],
            (1, 0, 0),
        ),
        expect(
            "equal-clock-readings",
            vec![done(delivered("pull-1"), usage(4_000, 0))],
            (4, 3, 1),
        ),
        expect(
            "clock-backwards",
            vec![done(
                job_failed(
                    EventKind::TriageFinished,
                    "the clock went backwards: 5000 ms, then 4000 ms",
                ),
                usage(1_000, 0),
            )],
            (1, 0, 0),
        ),
        expect(
            "rerun-after-questions",
            vec![
                done(asked("comment-1"), TRIAGE),
                done(delivered("pull-2"), FULL),
            ],
            (5, 3, 2),
        ),
        expect(
            "rerun-chain",
            vec![
                done(asked("comment-1"), TRIAGE),
                done(asked("comment-2"), TRIAGE),
                done(delivered("pull-3"), FULL),
            ],
            (6, 3, 3),
        ),
        expect(
            "rerun-unknown-previous",
            vec![
                previous(PreviousRunError::Unknown),
                done(delivered("pull-1"), FULL),
            ],
            (4, 3, 1),
        ),
        expect(
            "rerun-hostile-previous-id",
            vec![
                done(asked("comment-1"), TRIAGE),
                previous(PreviousRunError::Unknown),
                previous(PreviousRunError::Unknown),
                previous(PreviousRunError::Unknown),
                done(delivered("pull-2"), FULL),
            ],
            (5, 3, 2),
        ),
        expect(
            "rerun-previous-delivered",
            vec![
                done(delivered("pull-1"), FULL),
                previous(PreviousRunError::NotNeedsInformation(Stage::Done(
                    delivered("pull-1"),
                ))),
            ],
            (4, 3, 1),
        ),
        expect(
            "rerun-previous-unfinished",
            vec![
                unavailable(),
                previous(PreviousRunError::NotNeedsInformation(Stage::Reproduce)),
            ],
            (2, 0, 0),
        ),
        expect(
            "rerun-different-ticket",
            vec![
                done(asked("comment-1"), TRIAGE),
                previous(PreviousRunError::DifferentTicket),
                previous(PreviousRunError::DifferentTicket),
                previous(PreviousRunError::DifferentTicket),
            ],
            (1, 0, 1),
        ),
        expect(
            "rerun-title-changed",
            vec![
                done(asked("comment-1"), TRIAGE),
                done(delivered("pull-2"), FULL),
            ],
            (5, 3, 2),
        ),
        expect(
            "agent-silent-failure",
            vec![done(
                job_failed(EventKind::TriageFinished, "exit status 3, no error output"),
                usage(500, 1_000),
            )],
            (1, 0, 0),
        ),
        expect(
            "verifier-failure",
            vec![done(
                job_failed(
                    EventKind::ReproductionChecked,
                    "exit status 1: runner crashed",
                ),
                usage(2_000, 3_000),
            )],
            (2, 1, 0),
        ),
        expect(
            "forge-questions-failure",
            vec![done(
                job_failed(EventKind::QuestionsPosted, "HTTP 429: rate limited"),
                TRIAGE,
            )],
            (1, 0, 1),
        ),
        expect(
            "forge-pull-request-failure",
            vec![done(
                job_failed(EventKind::PullRequestOpened, "HTTP 502, no error output"),
                FULL,
            )],
            (4, 3, 1),
        ),
        expect(
            "agent-script-exhausted",
            vec![done(
                job_failed(EventKind::TriageFinished, "no scripted response for triage"),
                usage(0, 1_000),
            )],
            (1, 0, 0),
        ),
        expect("event-store-append-fails", vec![unavailable()], (2, 0, 0)),
        expect(
            "evidence-store-fails",
            vec![done(
                job_failed(
                    EventKind::ReproductionWritten,
                    &format!("storing the reproduction test failed: {stored}"),
                ),
                usage(2_000, 2_000),
            )],
            (2, 0, 0),
        ),
        expect(
            "evidence-load-fails",
            vec![done(
                job_failed(
                    EventKind::ReproductionChecked,
                    &format!("loading the reproduction test failed: {stored}"),
                ),
                usage(2_000, 3_000),
            )],
            (2, 0, 0),
        ),
        expect(
            "invalid-ticket-zero-width-key",
            vec![Err(DebugTicketError::Domain(DomainError::InvalidTicket(
                TicketField::Key,
            )))],
            (0, 0, 0),
        ),
        expect(
            "invalid-budget-zero",
            vec![Err(DebugTicketError::Domain(DomainError::InvalidBudget(
                BudgetDimension::Cost,
            )))],
            (0, 0, 0),
        ),
        expect(
            "gate-failed-reproduction",
            vec![done(
                Outcome::GateFailed(GateFailure::ReproductionPassedOnBase),
                usage(2_000, 3_000),
            )],
            (2, 1, 0),
        ),
        expect(
            "gate-failed-no-citations",
            vec![done(
                Outcome::GateFailed(GateFailure::NoCitations),
                usage(3_000, 4_000),
            )],
            (3, 1, 0),
        ),
        expect(
            "gate-failed-citations",
            vec![done(
                Outcome::GateFailed(GateFailure::CitationsNotVerified { indices: vec![1] }),
                usage(3_000, 5_000),
            )],
            (3, 2, 0),
        ),
        expect(
            "gate-failed-fix",
            vec![done(
                Outcome::GateFailed(GateFailure::FixCheckFailed(FixCheck::Lint)),
                FULL,
            )],
            (4, 3, 0),
        ),
        expect(
            "blank-question",
            vec![done(
                Outcome::InvalidAgentOutput {
                    awaiting: EventKind::TriageFinished,
                    problem: AgentOutputProblem::BlankQuestion { index: 1 },
                },
                TRIAGE,
            )],
            (1, 0, 0),
        ),
    ]
}

// --------------------------------------------------------- The fault model

/// One job of the delivered run, written out independently of
/// `DebugTicket`: the evidence it loads, the port it calls and the evidence
/// it stores, in that order. The expectations of the delivered run's fault
/// scenarios are derived from this table, not from `DebugTicket`, so a
/// change in what `DebugTicket` calls or charges shows up as a mismatch.
struct Job {
    awaiting: EventKind,
    loads: &'static [&'static str],
    call: Call,
    agent: bool,
    stores: Option<&'static str>,
    measured: bool,
}

const TEST: &str = "reproduction test";

const DELIVERED_RUN: [Job; 8] = [
    Job {
        awaiting: EventKind::TriageFinished,
        loads: &[],
        call: Call::Triage,
        agent: true,
        stores: None,
        measured: true,
    },
    Job {
        awaiting: EventKind::ReproductionWritten,
        loads: &[],
        call: Call::WriteReproduction,
        agent: true,
        stores: Some(TEST),
        measured: true,
    },
    Job {
        awaiting: EventKind::ReproductionChecked,
        loads: &[TEST],
        call: Call::CheckReproduction,
        agent: false,
        stores: None,
        measured: true,
    },
    Job {
        awaiting: EventKind::RootCauseProposed,
        loads: &[TEST],
        call: Call::AnalyzeRootCause,
        agent: true,
        stores: Some("analysis"),
        measured: true,
    },
    Job {
        awaiting: EventKind::CitationsChecked,
        loads: &[],
        call: Call::VerifyCitations,
        agent: false,
        stores: None,
        measured: true,
    },
    Job {
        awaiting: EventKind::FixWritten,
        loads: &[TEST, "analysis"],
        call: Call::WriteFix,
        agent: true,
        stores: Some("diff"),
        measured: true,
    },
    Job {
        awaiting: EventKind::FixVerified,
        loads: &["diff", TEST],
        call: Call::VerifyFix,
        agent: false,
        stores: None,
        measured: true,
    },
    Job {
        awaiting: EventKind::PullRequestOpened,
        loads: &["diff", TEST, "analysis"],
        call: Call::OpenPullRequest,
        agent: false,
        stores: None,
        measured: false,
    },
];

/// The model's run of the delivered scenario under one fault (or none):
/// every call it makes, and what it ends with.
struct Model<'a> {
    fault: Option<&'a Fault>,
    calls: Vec<Call>,
}

impl Model<'_> {
    /// Records a call; the fault kind when this call is the faulted one.
    fn hit(&mut self, call: Call) -> Option<FaultKind> {
        self.calls.push(call);
        let occurrence = self.calls.iter().filter(|c| **c == call).count();
        self.fault
            .filter(|f| f.call == call && f.occurrence == occurrence)
            .map(|f| f.kind.clone())
    }

    /// The `r`-th reading of the step clock, 1 ms below the one before when
    /// the fault hits it.
    fn now(&mut self, previous: Option<u64>) -> u64 {
        let reading =
            CLOCK_START + STEP_MS * self.calls.iter().filter(|c| **c == Call::Now).count() as u64;
        match (self.hit(Call::Now), previous) {
            (Some(FaultKind::Backwards), Some(previous)) => previous - 1,
            _ => reading,
        }
    }

    /// The result and the agent, verifier and forge calls. Agent jobs cost
    /// 1 000 µUSD and 700 µUSD when they fail, measured jobs last 1 000 ms,
    /// verifier and forge failures charge no cost, a backwards reading
    /// within a job charges the job's cost with 0 ms, and a backwards first
    /// reading ends the run before the job runs.
    fn run(&mut self) -> (Want, (usize, usize, usize)) {
        let mut counts = (0, 0, 0);
        let _ = self.hit(Call::RunId);
        if let Some(FaultKind::Store(error)) = self.hit(Call::Create) {
            return (Err(DebugTicketError::Store(error)), counts);
        }
        if let Some(FaultKind::Store(error)) = self.hit(Call::Append) {
            return (Err(DebugTicketError::Store(error)), counts);
        }
        let mut spent = Usage::default();
        let mut last: Option<u64> = None;
        let mut previous: Option<u64> = None;
        for job in &DELIVERED_RUN {
            let backwards =
                |a: u64, b: u64| format!("the clock went backwards: {a} ms, then {b} ms");
            let mut before = 0;
            if job.measured {
                before = self.now(previous);
                previous = Some(before);
                if let Some(last) = last.filter(|last| before < *last) {
                    let outcome = job_failed(job.awaiting, &backwards(last, before));
                    return (done(outcome, spent), counts);
                }
            }
            let mut cost = 0;
            let mut failed: Option<String> = None;
            for what in job.loads {
                if let Some(FaultKind::Evidence(error)) = self.hit(Call::Get) {
                    failed = Some(format!("loading the {what} failed: {error}"));
                    break;
                }
            }
            if failed.is_none() {
                let hit = self.hit(job.call);
                match job.call {
                    Call::OpenPullRequest => counts.2 += 1,
                    _ if job.agent => counts.0 += 1,
                    _ => counts.1 += 1,
                }
                if hit.is_some() {
                    failed = Some(String::from("exit status 70: injected failure"));
                    cost = if job.agent { 700 } else { 0 };
                } else if job.agent {
                    cost = 1_000;
                }
            }
            if let (None, Some(what)) = (&failed, job.stores) {
                if let Some(FaultKind::Evidence(error)) = self.hit(Call::Put) {
                    failed = Some(format!("storing the {what} failed: {error}"));
                }
            }
            let mut duration = 0;
            if job.measured {
                let after = self.now(previous);
                previous = Some(after);
                last = Some(after);
                match after.checked_sub(before) {
                    Some(elapsed) => duration = elapsed,
                    None => failed = Some(backwards(before, after)),
                }
            }
            spent = usage(spent.cost_micro_usd + cost, spent.duration_ms + duration);
            if let Some(detail) = failed {
                return (done(job_failed(job.awaiting, &detail), spent), counts);
            }
            if let Some(FaultKind::Store(error)) = self.hit(Call::Append) {
                return (Err(DebugTicketError::Store(error)), counts);
            }
        }
        (done(delivered("pull-1"), spent), counts)
    }
}

fn model(fault: &Fault) -> (Want, (usize, usize, usize)) {
    Model {
        fault: Some(fault),
        calls: Vec::new(),
    }
    .run()
}

/// Every fault point of the delivered run by the model: its call sequence
/// without a fault, each call with every fault kind, except the first
/// clock reading. Names as the fault matrix must give them.
fn delivered_fault_points() -> Vec<(String, Fault)> {
    let mut clean = Model {
        fault: None,
        calls: Vec::new(),
    };
    let _ = clean.run();
    let mut points = Vec::new();
    for (k, &call) in clean.calls.iter().enumerate() {
        let occurrence = clean.calls[..=k].iter().filter(|c| **c == call).count();
        if call == Call::Now && occurrence == 1 {
            continue;
        }
        for kind in call.fault_kinds() {
            let name = format!(
                "fault-delivered-{}-{occurrence}-{}",
                call.name(),
                kind.name()
            );
            points.push((
                name,
                Fault {
                    call,
                    occurrence,
                    kind,
                },
            ));
        }
    }
    points
}

fn fault_expectations() -> Vec<Expectation> {
    delivered_fault_points()
        .into_iter()
        .map(|(name, fault)| {
            let (want, (agent, verifier, forge)) = model(&fault);
            Expectation {
                name,
                results: vec![want],
                agent,
                verifier,
                forge,
            }
        })
        .collect()
}

fn fault(call: Call, occurrence: usize, kind: FaultKind) -> Fault {
    Fault {
        call,
        occurrence,
        kind,
    }
}

/// Spot checks of the model against numbers worked out by hand, so a model
/// bug cannot silently agree with a `DebugTicket` bug.
#[test]
fn fault_model_spot_checks() {
    let failed = |awaiting, detail: &str, spent| done(job_failed(awaiting, detail), spent);
    let unavailable_evidence = FaultKind::Evidence(EvidenceError::Unavailable {
        detail: String::from(FAULT),
    });
    // A failed write_fix charges the 700 µUSD it ran up (review mutant C).
    assert_eq!(
        model(&fault(Call::WriteFix, 1, FaultKind::Fails)),
        (
            failed(
                EventKind::FixWritten,
                "exit status 70: injected failure",
                usage(3_700, 6_000)
            ),
            (4, 2, 0)
        )
    );
    // A failed verify_fix charges no cost, only its duration.
    assert_eq!(
        model(&fault(Call::VerifyFix, 1, FaultKind::Fails)).0,
        failed(
            EventKind::FixVerified,
            "exit status 70: injected failure",
            FULL
        )
    );
    // The 5th load is the diff in VerifyFix (review mutant B), the 7th the
    // diff for the pull request (review mutant A).
    assert_eq!(
        model(&fault(Call::Get, 5, unavailable_evidence)),
        (
            failed(
                EventKind::FixVerified,
                "loading the diff failed: the evidence store is unavailable: the disk is full",
                FULL
            ),
            (4, 2, 0)
        )
    );
    assert_eq!(
        model(&fault(
            Call::Get,
            7,
            FaultKind::Evidence(EvidenceError::Corrupted)
        )),
        (
            failed(
                EventKind::PullRequestOpened,
                "loading the diff failed: the stored content does not match its reference",
                FULL
            ),
            (4, 3, 0)
        )
    );
    // Readings are 1 000, 2 000, ... The 12th is write_fix's second.
    assert_eq!(
        model(&fault(Call::Now, 12, FaultKind::Backwards)).0,
        failed(
            EventKind::FixWritten,
            "the clock went backwards: 11000 ms, then 10999 ms",
            usage(4_000, 5_000)
        )
    );
    // The 3rd is write_reproduction's first: the job never runs.
    assert_eq!(
        model(&fault(Call::Now, 3, FaultKind::Backwards)),
        (
            failed(
                EventKind::ReproductionWritten,
                "the clock went backwards: 2000 ms, then 1999 ms",
                usage(1_000, 1_000)
            ),
            (1, 0, 0)
        )
    );
    assert_eq!(
        model(&fault(
            Call::Append,
            9,
            FaultKind::Store(StoreError::InvalidRunId)
        )),
        (
            Err(DebugTicketError::Store(StoreError::InvalidRunId)),
            (4, 3, 1)
        )
    );
}

/// The base request a fault hits: the request in which the base scenario
/// made the faulted call.
fn faulted_request(base: &Played, fault: &Fault) -> usize {
    base.calls
        .iter()
        .filter(|(_, call)| *call == fault.call)
        .nth(fault.occurrence - 1)
        .map(|(request, _)| *request)
        .expect("the fault hits a call the base made")
}

fn job_event(call: Call) -> Option<EventKind> {
    match call {
        Call::Triage => Some(EventKind::TriageFinished),
        Call::WriteReproduction => Some(EventKind::ReproductionWritten),
        Call::AnalyzeRootCause => Some(EventKind::RootCauseProposed),
        Call::WriteFix => Some(EventKind::FixWritten),
        Call::CheckReproduction => Some(EventKind::ReproductionChecked),
        Call::VerifyCitations => Some(EventKind::CitationsChecked),
        Call::VerifyFix => Some(EventKind::FixVerified),
        Call::PostQuestions => Some(EventKind::QuestionsPosted),
        Call::OpenPullRequest => Some(EventKind::PullRequestOpened),
        Call::Create
        | Call::Append
        | Call::Load
        | Call::Put
        | Call::Get
        | Call::Now
        | Call::RunId => None,
    }
}

/// Every fault scenario fails closed at the faulted call: the requests
/// before it end as in the base scenario, and the faulted request ends with
/// the outcome or error the fault calls for, never as if the call had
/// succeeded. A job outcome may instead be `BudgetExceeded` when the
/// failing job's usage crosses a limit (ADR-002 D1, step 3), or a
/// backwards clock in the same job.
#[test]
fn every_fault_fails_closed() {
    let scenarios = scenarios();
    let mut checked = 0;
    for scenario in scenarios.iter().filter(|s| s.fault.is_some()) {
        let Some(base_name) = &scenario.base else {
            continue;
        };
        let fault = scenario.fault.as_ref().expect("a fault scenario");
        let base = scenarios
            .iter()
            .find(|s| &s.name == base_name)
            .expect("the base exists");
        let (base, got) = (play(base), play(scenario));
        let k = faulted_request(&base, fault);
        assert_eq!(got.results[..k], base.results[..k], "{}", scenario.name);
        let result = &got.results[k];
        let stage = result.as_ref().map(|report| report.run.stage());
        // A backwards clock in the same job takes precedence over the job's
        // own failure (ADR-004, D5); the base `clock-backwards` meets that.
        let clock = |detail: &str| detail.starts_with("the clock went backwards: ");
        let job_ended = |check: &dyn Fn(EventKind, &str) -> bool| match &stage {
            Ok(Stage::Done(Outcome::JobFailed { awaiting, detail })) => {
                check(*awaiting, detail) || clock(detail)
            }
            Ok(Stage::Done(Outcome::BudgetExceeded(_))) => true,
            _ => false,
        };
        let ok = match (&fault.kind, fault.call) {
            (FaultKind::Fails, call) => job_ended(&|awaiting, detail| {
                Some(awaiting) == job_event(call) && detail == "exit status 70: injected failure"
            }),
            (FaultKind::Evidence(error), Call::Put) => job_ended(&|_, detail| {
                detail.starts_with("storing the ") && detail.ends_with(&format!(" failed: {error}"))
            }),
            (FaultKind::Evidence(error), _) => job_ended(&|_, detail| {
                detail.starts_with("loading the ") && detail.ends_with(&format!(" failed: {error}"))
            }),
            (FaultKind::Store(StoreError::UnknownRun | StoreError::InvalidRunId), Call::Load) => {
                *result == Err(DebugTicketError::PreviousRun(PreviousRunError::Unknown))
            }
            (FaultKind::Store(error), _) => *result == Err(DebugTicketError::Store(error.clone())),
            (FaultKind::Backwards, _) => job_ended(&|_, detail| clock(detail)),
        };
        assert!(ok, "{} ended as {result:?}", scenario.name);
        checked += 1;
    }
    assert_eq!(
        checked,
        scenarios.iter().filter(|s| s.base.is_some()).count()
    );
    println!("fault scenarios checked: {checked}");
}

/// A store failure leaves the log as the prefix of accepted events: when
/// the faulted request is the scenario's last, the store holds exactly the
/// runs and events the base had created and appended before the fault.
#[test]
fn every_event_store_fault_leaves_the_accepted_prefix() {
    let scenarios = scenarios();
    for scenario in scenarios.iter().filter(|s| s.base.is_some()) {
        let fault = scenario.fault.as_ref().expect("a fault scenario");
        if !matches!(fault.call, Call::Create | Call::Append | Call::Load) {
            continue;
        }
        let base_scenario = scenarios
            .iter()
            .find(|s| Some(&s.name) == scenario.base.as_ref())
            .expect("the base exists");
        let base = play(base_scenario);
        if faulted_request(&base, fault) + 1 != scenario.requests.len() {
            continue;
        }
        let position = base
            .calls
            .iter()
            .enumerate()
            .filter(|(_, (_, call))| *call == fault.call)
            .nth(fault.occurrence - 1)
            .map(|(k, _)| k)
            .expect("the faulted call");
        let before = &base.calls[..position];
        let count = |call| before.iter().filter(|(_, c)| *c == call).count();
        let got = play(scenario);
        let events: usize = got.logs.iter().map(|(_, log)| log.events.len()).sum();
        assert_eq!(got.logs.len(), count(Call::Create), "{}", scenario.name);
        assert_eq!(events, count(Call::Append), "{}", scenario.name);
    }
}

/// A store failure while loading the previous run fails closed (review
/// mutant G): no re-run without the previous questions, no new run.
#[test]
fn previous_run_load_failure_fails_closed() {
    let got = played("fault-rerun-after-questions-load-1-unavailable");
    assert_eq!(got.results.len(), 2);
    assert_eq!(
        got.results[1],
        Err(DebugTicketError::Store(StoreError::Unavailable {
            detail: String::from(FAULT),
        }))
    );
    assert_eq!(log_ids(&got), ["run-1"]);
    assert_eq!(got.agent.len(), 1);
    let unknown = played("fault-rerun-after-questions-load-1-unknown-run");
    assert_eq!(
        unknown.results[1],
        Err(DebugTicketError::PreviousRun(PreviousRunError::Unknown))
    );
}

/// Wherever the forge got a pull request, it carries exactly the diff and
/// test bytes the verifier checked in that run's `VerifyFix` (ADR-004, D9).
#[test]
fn forge_gets_the_bytes_the_verifier_checked() {
    let mut opened = 0;
    for scenario in scenarios() {
        let played = play(&scenario);
        let checked: Vec<(&Vec<u8>, &Vec<u8>)> = played
            .verifier
            .iter()
            .filter_map(|request| match request {
                VerifierRequest::VerifyFix { diff, test, .. } => Some((diff, test)),
                _ => None,
            })
            .collect();
        let requests = played.forge.iter().filter_map(|request| match request {
            ForgeRequest::OpenPullRequest(request) => Some(request),
            ForgeRequest::PostQuestions { .. } => None,
        });
        for (k, request) in requests.enumerate() {
            opened += 1;
            let (diff, test) = checked[k];
            assert_eq!(&request.diff.content, diff, "{}", scenario.name);
            assert_eq!(&request.test.content, test, "{}", scenario.name);
        }
    }
    assert!(opened > 0);
}

fn played(name: &str) -> Played {
    let scenario: AppScenario = scenarios()
        .into_iter()
        .find(|s| s.name == name)
        .expect("the scenario exists");
    play(&scenario)
}

fn log_ids(played: &Played) -> Vec<&str> {
    played.logs.iter().map(|(id, _)| id.as_str()).collect()
}

#[test]
fn delivered_end_to_end() {
    let played = played("delivered");
    let [Ok(report)] = played.results.as_slice() else {
        panic!("one delivered report expected: {:?}", played.results);
    };
    assert_eq!(
        report.run.stage(),
        Stage::Done(Outcome::Delivered {
            pull_request: String::from("pull-1"),
            overrun: None,
        })
    );
    assert_eq!(report.run.spent(), FULL);
    assert_eq!(
        (
            played.agent.len(),
            played.verifier.len(),
            played.forge.len()
        ),
        (4, 3, 1)
    );
    // The pull request carries the stored evidence, loaded back.
    let [ForgeRequest::OpenPullRequest(request)] = played.forge.as_slice() else {
        panic!("one pull request expected: {:?}", played.forge);
    };
    assert_eq!(request.run.as_str(), "run-1");
    assert_eq!(request.test.content, b"test");
    assert_eq!(request.analysis.content, b"cause");
    assert_eq!(request.diff.content, b"diff");
    assert_eq!(request.spent, FULL);
    assert_eq!(request.overrun, None);
    // The verifier saw the stored bytes, and the fix with the same test.
    assert_eq!(
        played.verifier.last(),
        Some(&VerifierRequest::VerifyFix {
            base: request.base.clone(),
            diff: b"diff".to_vec(),
            test: b"test".to_vec(),
        })
    );
    assert_eq!(log_ids(&played), ["run-1"]);
}

#[test]
fn scenario_expectations_match() {
    let expectations = expectations();
    for scenario in scenarios() {
        let Some(want) = expectations.iter().find(|e| e.name == scenario.name) else {
            // Fault scenarios of other bases are checked by
            // `every_fault_fails_closed`.
            assert!(
                scenario
                    .base
                    .as_deref()
                    .is_some_and(|base| base != "delivered"),
                "{} has no expectation",
                scenario.name
            );
            continue;
        };
        let played = play(&scenario);
        let got: Vec<Want> = played
            .results
            .iter()
            .map(|result| {
                result
                    .as_ref()
                    .map(|report| (report.run.stage(), report.run.spent()))
                    .map_err(Clone::clone)
            })
            .collect();
        assert_eq!(got, want.results, "{}", scenario.name);
        assert_eq!(
            (
                played.agent.len(),
                played.verifier.len(),
                played.forge.len()
            ),
            (want.agent, want.verifier, want.forge),
            "{}: agent, verifier and forge calls",
            scenario.name
        );
    }
}

#[test]
fn expectations_and_scenarios_are_a_bijection() {
    let all = scenarios();
    let names: Vec<&str> = all.iter().map(|s| s.name.as_str()).collect();
    let unique: BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(unique.len(), names.len(), "scenario names repeat");
    for name in &names {
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "{name:?}"
        );
    }
    let wanted = expectations();
    let expected: Vec<&str> = wanted.iter().map(|e| e.name.as_str()).collect();
    let expected_unique: BTreeSet<&str> = expected.iter().copied().collect();
    assert_eq!(expected_unique.len(), expected.len(), "expectations repeat");
    // Every hand-written scenario and every fault scenario of the delivered
    // run has an exact expectation; the other fault scenarios are checked
    // by property.
    let exact: BTreeSet<&str> = all
        .iter()
        .filter(|s| s.base.as_deref().is_none_or(|base| base == "delivered"))
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(exact, expected_unique);
    let generated = all.iter().filter(|s| s.base.is_some()).count();
    let bases: BTreeSet<&str> = all.iter().filter_map(|s| s.base.as_deref()).collect();
    println!(
        "app corpus: {} scenarios, {} hand-written, {} bases, {generated} fault scenarios, \
         {} with exact expectations",
        all.len(),
        all.len() - generated,
        bases.len(),
        expected.len()
    );
}

#[test]
fn replayed_run_equals_reported_run() {
    for scenario in scenarios() {
        let played = play(&scenario);
        for (id, log) in &played.logs {
            assert!(
                replay(id, log).is_ok(),
                "{}: the log of {id:?} does not replay",
                scenario.name
            );
        }
        for report in played.results.iter().flatten() {
            let id = report.run.id();
            let (_, log) = played
                .logs
                .iter()
                .find(|(logged, _)| logged == id)
                .expect("a reported run is logged");
            let (run, commands) = replay(id, log).expect("the log replays");
            assert_eq!(run, report.run, "{}: {id:?}", scenario.name);
            assert_eq!(commands, report.commands, "{}: {id:?}", scenario.name);
        }
    }
}

#[test]
fn no_event_is_rejected_blank() {
    for scenario in scenarios() {
        for result in play(&scenario).results {
            if let Err(DebugTicketError::Domain(error)) = result {
                assert!(
                    matches!(
                        error,
                        DomainError::InvalidTicket(_) | DomainError::InvalidBudget(_)
                    ),
                    "{}: a job result was rejected: {error:?}",
                    scenario.name
                );
            }
        }
    }
}

fn triage_previous(played: &Played) -> Vec<Option<PreviousTriage>> {
    played
        .agent
        .iter()
        .filter_map(|request| match request {
            AgentRequest::Triage(triage) => Some(triage.previous.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn rerun_hands_triage_the_previous_questions() {
    let played = played("rerun-after-questions");
    assert_eq!(
        triage_previous(&played),
        [
            None,
            Some(PreviousTriage {
                run: RunId::new(String::from("run-1")),
                outcome: asked("comment-1"),
                questions: questions(),
            }),
        ]
    );
    let starts: Vec<Option<&str>> = played
        .logs
        .iter()
        .map(|(_, log)| log.start.previous.as_ref().map(RunId::as_str))
        .collect();
    assert_eq!(starts, [None, Some("run-1")]);
}

#[test]
fn rerun_chain_passes_only_the_immediate_predecessor() {
    let played = played("rerun-chain");
    let previous = triage_previous(&played);
    assert_eq!(previous.len(), 3);
    assert_eq!(
        previous[2],
        Some(PreviousTriage {
            run: RunId::new(String::from("run-2")),
            outcome: asked("comment-2"),
            questions: second_questions(),
        })
    );
}

#[test]
fn rejected_input_uses_no_id_and_stores_nothing() {
    for (name, logged) in [
        ("rerun-unknown-previous", vec!["run-1"]),
        ("rerun-hostile-previous-id", vec!["run-1", "run-2"]),
        ("rerun-different-ticket", vec!["run-1"]),
        ("rerun-previous-delivered", vec!["run-1"]),
        ("invalid-ticket-zero-width-key", vec![]),
        ("invalid-budget-zero", vec![]),
    ] {
        assert_eq!(log_ids(&played(name)), logged, "{name}");
    }
    // The run after the rejected request got the first id.
    let played = played("rerun-unknown-previous");
    let Some(Ok(report)) = played.results.last() else {
        panic!("the second request delivers");
    };
    assert_eq!(report.run.id().as_str(), "run-1");
}

#[test]
fn overrun_reaches_the_forge_unchanged() {
    let played = played("delivered-over-duration");
    let [ForgeRequest::OpenPullRequest(request)] = played.forge.as_slice() else {
        panic!("one pull request expected");
    };
    let overrun = Some(Overrun {
        dimension: BudgetDimension::Duration,
        spent: FULL,
        budget: budget(1_000_000, 6_999),
    });
    assert_eq!(request.overrun, overrun);
    assert_eq!(request.spent, FULL);
}

#[test]
fn store_failure_leaves_the_accepted_prefix() {
    let played = played("event-store-append-fails");
    let [(id, log)] = played.logs.as_slice() else {
        panic!("one run logged");
    };
    let kinds: Vec<EventKind> = log.events.iter().map(|e| e.kind()).collect();
    assert_eq!(
        kinds,
        [EventKind::TicketReceived, EventKind::TriageFinished]
    );
    let (run, _) = replay(id, log).expect("the prefix replays");
    assert_eq!(run.expects(), Some(EventKind::ReproductionWritten));
}
