//! `DebugTicket` end to end on in-memory adapters (ADR-004, D5-D7).
//!
//! Every test plays scenarios of the app corpus, so the two-process replay
//! sees every path these tests exercise; the bijection test makes a
//! scenario without an expectation fail.

use std::collections::BTreeSet;

use boneli_app::{DebugTicketError, PreviousRunError, PreviousTriage, StoreError, replay};
use boneli_domain::{
    AgentOutputProblem, Budget, BudgetDimension, DomainError, EventKind, FixCheck, GateFailure,
    Outcome, Overrun, RunId, Stage, TicketField, Usage,
};
use boneli_memory::{AgentRequest, ForgeRequest, VerifierRequest};
use boneli_replay_check::app::{
    AppScenario, FAULT, Played, play, questions, scenarios, second_questions,
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
/// it stores, in that order. The fault expectations are derived from this
/// table, not from the scenarios, so a change in what `DebugTicket` calls
/// shows up as a mismatch.
struct Job {
    awaiting: EventKind,
    loads: &'static [&'static str],
    agent: Option<&'static str>,
    verifier: Option<&'static str>,
    forge: Option<&'static str>,
    stores: Option<&'static str>,
}

const TEST: &str = "reproduction test";

const DELIVERED_RUN: [Job; 8] = [
    Job {
        awaiting: EventKind::TriageFinished,
        loads: &[],
        agent: Some("triage"),
        verifier: None,
        forge: None,
        stores: None,
    },
    Job {
        awaiting: EventKind::ReproductionWritten,
        loads: &[],
        agent: Some("write_reproduction"),
        verifier: None,
        forge: None,
        stores: Some(TEST),
    },
    Job {
        awaiting: EventKind::ReproductionChecked,
        loads: &[TEST],
        agent: None,
        verifier: Some("check_reproduction"),
        forge: None,
        stores: None,
    },
    Job {
        awaiting: EventKind::RootCauseProposed,
        loads: &[TEST],
        agent: Some("analyze_root_cause"),
        verifier: None,
        forge: None,
        stores: Some("analysis"),
    },
    Job {
        awaiting: EventKind::CitationsChecked,
        loads: &[],
        agent: None,
        verifier: Some("verify_citations"),
        forge: None,
        stores: None,
    },
    Job {
        awaiting: EventKind::FixWritten,
        loads: &[TEST, "analysis"],
        agent: Some("write_fix"),
        verifier: None,
        forge: None,
        stores: Some("diff"),
    },
    Job {
        awaiting: EventKind::FixVerified,
        loads: &["diff", TEST],
        agent: None,
        verifier: Some("verify_fix"),
        forge: None,
        stores: None,
    },
    Job {
        awaiting: EventKind::PullRequestOpened,
        loads: &["diff", TEST, "analysis"],
        agent: None,
        verifier: None,
        forge: Some("open_pull_request"),
        stores: None,
    },
];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    Agent(&'static str),
    Verifier(&'static str),
    Forge(&'static str),
    Put(usize),
    Get(usize),
    Tamper(usize),
    Create,
    Append(usize),
    ClockBackwards(usize),
}

/// What the delivered run does under one fault, by the model: the result,
/// and the agent, verifier and forge calls. Agent jobs cost 1 000 µUSD
/// (700 when they fail), measured jobs last 1 000 ms, a verifier's failure
/// cost and every forge call are free, and a backwards clock charges the
/// job's cost with 0 ms.
fn model(fault: Fault) -> (Want, (usize, usize, usize)) {
    const UNAVAILABLE: &str = "the evidence store is unavailable: the disk is full";
    const CORRUPTED: &str = "the stored content does not match its reference";
    let mut calls = (0, 0, 0);
    if fault == Fault::Create {
        return (unavailable(), calls);
    }
    let (mut puts, mut gets, mut appends, mut measured) = (0, 0, 1, 0);
    if fault == Fault::Append(1) {
        return (unavailable(), calls);
    }
    let mut spent = Usage::default();
    for job in &DELIVERED_RUN {
        let is_measured = job.forge.is_none();
        measured += usize::from(is_measured);
        let mut cost = 0;
        let mut failed: Option<String> = None;
        for what in job.loads {
            gets += 1;
            if fault == Fault::Get(gets) {
                failed = Some(format!("loading the {what} failed: {UNAVAILABLE}"));
            } else if fault == Fault::Tamper(gets) {
                failed = Some(format!("loading the {what} failed: {CORRUPTED}"));
            }
            if failed.is_some() {
                break;
            }
        }
        if failed.is_none() {
            if let Some(op) = job.agent {
                calls.0 += 1;
                if fault == Fault::Agent(op) {
                    cost = 700;
                    failed = Some(String::from("exit status 2: agent crashed"));
                } else {
                    cost = 1_000;
                }
            }
            if let Some(op) = job.verifier {
                calls.1 += 1;
                if fault == Fault::Verifier(op) {
                    failed = Some(String::from("exit status 1: runner crashed"));
                }
            }
            if let Some(op) = job.forge {
                calls.2 += 1;
                if fault == Fault::Forge(op) {
                    failed = Some(String::from("HTTP 502: bad gateway"));
                }
            }
        }
        if let (None, Some(what)) = (&failed, job.stores) {
            puts += 1;
            if fault == Fault::Put(puts) {
                failed = Some(format!("storing the {what} failed: {UNAVAILABLE}"));
            }
        }
        let mut duration = if is_measured { 1_000 } else { 0 };
        if is_measured && fault == Fault::ClockBackwards(measured) {
            let before = 10_000 + 1_000 * (2 * measured as u64 - 2);
            let after = before - 1;
            failed = Some(format!(
                "the clock went backwards: {before} ms, then {after} ms"
            ));
            duration = 0;
        }
        spent = usage(spent.cost_micro_usd + cost, spent.duration_ms + duration);
        if let Some(detail) = failed {
            return (done(job_failed(job.awaiting, &detail), spent), calls);
        }
        appends += 1;
        if fault == Fault::Append(appends) {
            return (unavailable(), calls);
        }
    }
    (done(delivered("pull-1"), spent), calls)
}

/// Every fault point of the model, with the scenario name the fault matrix
/// must give it.
fn fault_points() -> Vec<(String, Fault)> {
    let mut points = Vec::new();
    for op in DELIVERED_RUN.iter().filter_map(|j| j.agent) {
        points.push((format!("fault-agent-{}-1", kebab(op)), Fault::Agent(op)));
    }
    for op in DELIVERED_RUN.iter().filter_map(|j| j.verifier) {
        points.push((
            format!("fault-verifier-{}-1", kebab(op)),
            Fault::Verifier(op),
        ));
    }
    for op in DELIVERED_RUN.iter().filter_map(|j| j.forge) {
        points.push((format!("fault-forge-{}-1", kebab(op)), Fault::Forge(op)));
    }
    let puts = DELIVERED_RUN.iter().filter(|j| j.stores.is_some()).count();
    for n in 1..=puts {
        points.push((format!("fault-evidence-put-{n}"), Fault::Put(n)));
    }
    let gets: usize = DELIVERED_RUN.iter().map(|j| j.loads.len()).sum();
    for n in 1..=gets {
        points.push((format!("fault-evidence-get-{n}"), Fault::Get(n)));
        points.push((format!("fault-evidence-tamper-{n}"), Fault::Tamper(n)));
    }
    points.push((String::from("fault-event-create"), Fault::Create));
    // TicketReceived, then one event per job.
    for n in 1..=DELIVERED_RUN.len() + 1 {
        points.push((format!("fault-event-append-{n}"), Fault::Append(n)));
    }
    let measured = DELIVERED_RUN.iter().filter(|j| j.forge.is_none()).count();
    for job in 1..=measured {
        points.push((
            format!("fault-clock-backwards-{job}"),
            Fault::ClockBackwards(job),
        ));
    }
    points
}

fn kebab(operation: &str) -> String {
    operation.replace('_', "-")
}

fn fault_expectations() -> Vec<Expectation> {
    fault_points()
        .into_iter()
        .map(|(name, fault)| {
            let (want, (agent, verifier, forge)) = model(fault);
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

/// Spot checks of the model against numbers worked out by hand, so a model
/// bug cannot silently agree with a `DebugTicket` bug.
#[test]
fn fault_model_spot_checks() {
    let failed = |awaiting, detail: &str, spent| done(job_failed(awaiting, detail), spent);
    // A failed write_fix charges the 700 µUSD it ran up (review mutant C).
    assert_eq!(
        model(Fault::Agent("write_fix")),
        (
            failed(
                EventKind::FixWritten,
                "exit status 2: agent crashed",
                usage(3_700, 6_000)
            ),
            (4, 2, 0)
        )
    );
    // A failed verify_fix charges no cost, only its duration.
    assert_eq!(
        model(Fault::Verifier("verify_fix")).0,
        failed(
            EventKind::FixVerified,
            "exit status 1: runner crashed",
            FULL
        )
    );
    // The 5th load is the diff in VerifyFix (review mutant B), the 7th the
    // diff for the pull request (review mutant A).
    assert_eq!(
        model(Fault::Get(5)),
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
        model(Fault::Tamper(7)),
        (
            failed(
                EventKind::PullRequestOpened,
                "loading the diff failed: the stored content does not match its reference",
                FULL
            ),
            (4, 3, 0)
        )
    );
    // The clock goes back in the 6th measured job, write_fix.
    assert_eq!(
        model(Fault::ClockBackwards(6)).0,
        failed(
            EventKind::FixWritten,
            "the clock went backwards: 20000 ms, then 19999 ms",
            usage(4_000, 5_000)
        )
    );
    assert_eq!(model(Fault::Append(9)), (unavailable(), (4, 3, 1)));
    assert_eq!(fault_points().len(), 46);
}

/// A store failure leaves the log as the prefix of accepted events: the
/// n-th append failing leaves n - 1 events, and a failed create none.
#[test]
fn every_event_store_fault_leaves_the_accepted_prefix() {
    for scenario in scenarios() {
        let played = play(&scenario);
        if scenario.faults.event_create {
            assert!(played.logs.is_empty(), "{}", scenario.name);
        }
        if let Some(n) = scenario.faults.event_append {
            let events = played.logs.first().map_or(0, |(_, log)| log.events.len());
            assert_eq!(events, n - 1, "{}", scenario.name);
        }
    }
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
        let want = expectations
            .iter()
            .find(|e| e.name == scenario.name)
            .expect("an expectation per scenario");
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
    assert_eq!(unique, expected_unique);
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
