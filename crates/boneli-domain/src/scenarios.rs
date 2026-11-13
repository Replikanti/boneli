//! The event corpus of the run state machine (ADR-002).
//!
//! This module is test data, compiled into the library because core crates
//! declare no features (ADR-001). The domain's unit tests fold every
//! scenario through [`fold`] and compare it with a test-only table of
//! expected results; the `boneli-replay-check` harness folds the same list in
//! two child processes and in its own, and compares the `Debug` output byte
//! for byte. That comparison is the gate for address leaks from the domain
//! (ADR-001, decision D1), so the corpus runs every error path: every
//! rejected (state, event) pair, every gate failure, every outcome, and an
//! overrun both set and unset.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::budget::{Budget, Usage};
use crate::command::RunCommand;
use crate::error::DomainError;
use crate::event::{EventKind, RunEvent, TriageVerdict};
use crate::gate::{CheckStatus, CitationStatus, FixChecks, TestStatus};
use crate::run::{Run, Stage};
use crate::values::{Citation, CommitSha, EvidenceRef, RunId, Ticket, TicketSource};

/// One named event sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scenario {
    /// Unique, `[a-z0-9-]+`.
    pub name: &'static str,
    /// The run's limits.
    pub budget: Budget,
    /// The events, in order.
    pub events: Vec<RunEvent>,
}

/// The result of folding one scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    /// One entry per event.
    pub entries: Vec<TraceEntry>,
    /// The run after the last event.
    pub run: Run,
}

/// What one event did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEntry {
    /// What the run waited for before the event.
    pub expected: Option<EventKind>,
    /// The event's kind.
    pub got: EventKind,
    /// The commands, or the error; on an error the run stays as it was.
    pub result: Result<Vec<RunCommand>, DomainError>,
    /// The stage after the event.
    pub stage: Stage,
}

/// Folds a scenario: a new run with the scenario's budget, then every event
/// through [`Run::handle`]. An error is recorded in the trace and the run
/// keeps its state; only [`Run::new`] can fail the fold.
pub fn fold(scenario: &Scenario) -> Result<Trace, DomainError> {
    let mut run = Run::new(RunId::new(String::from(scenario.name)), scenario.budget)?;
    let mut entries = Vec::with_capacity(scenario.events.len());
    for event in &scenario.events {
        let expected = run.expects();
        let got = event.kind();
        let result = match run.clone().handle(event.clone()) {
            Ok((next, commands)) => {
                run = next;
                Ok(commands)
            }
            Err(error) => Err(error),
        };
        entries.push(TraceEntry {
            expected,
            got,
            result,
            stage: run.stage(),
        });
    }
    Ok(Trace { entries, run })
}

pub(crate) const BASE: &str = "0123456789abcdef0123456789abcdef01234567";
pub(crate) const OTHER_SHA: &str = "fedcba9876543210fedcba9876543210fedcba98";

/// The budget of every scenario that does not test the budget.
pub(crate) const BUDGET: Budget = Budget {
    cost_micro_usd: 1_000_000,
    duration_ms: 1_000_000,
};

/// The usage of every job in scenarios that do not test the budget.
pub(crate) const JOB: Usage = Usage {
    cost_micro_usd: 1_000,
    duration_ms: 100,
};

pub(crate) const PULL_REQUEST: &str = "pull/101";
pub(crate) const COMMENT: &str = "issue-comment/55";
pub(crate) const FAILURE: &str = "sandbox exited with status 137";

pub(crate) fn usage(cost_micro_usd: u64, duration_ms: u64) -> Usage {
    Usage {
        cost_micro_usd,
        duration_ms,
    }
}

pub(crate) fn base() -> CommitSha {
    CommitSha::from_corpus(BASE)
}

pub(crate) fn ticket() -> Ticket {
    Ticket {
        source: TicketSource::GitHub,
        key: String::from("BUG-17"),
        title: String::from("Invoice total is one cent too high"),
        body: String::from("Invoices with three lines show a total one cent above the sum."),
    }
}

pub(crate) fn test_ref() -> EvidenceRef {
    EvidenceRef::from_corpus("evidence/reproduction-test")
}

pub(crate) fn analysis_ref() -> EvidenceRef {
    EvidenceRef::from_corpus("evidence/analysis")
}

pub(crate) fn diff_ref() -> EvidenceRef {
    EvidenceRef::from_corpus("evidence/fix-diff")
}

pub(crate) fn citation(path: &str, line: u32) -> Citation {
    Citation {
        path: String::from(path),
        line,
        sha: base(),
        quote: String::from("total += line.amount + 1;"),
    }
}

pub(crate) fn citations() -> Vec<Citation> {
    vec![
        citation("src/invoice.rs", 42),
        citation("src/invoice.rs", 7),
    ]
}

pub(crate) fn passing_checks() -> FixChecks {
    FixChecks {
        reproduction_test: TestStatus::Passed,
        reproduction_test_unchanged: CheckStatus::Passed,
        previously_green_tests: CheckStatus::Passed,
        lint: CheckStatus::Passed,
        typecheck: CheckStatus::Passed,
    }
}

pub(crate) fn questions() -> Vec<String> {
    vec![
        String::from("Which invoice shows the wrong total?"),
        String::from("Which version runs in production?"),
    ]
}

fn received() -> RunEvent {
    RunEvent::TicketReceived {
        ticket: ticket(),
        base: base(),
    }
}

fn received_with(key: &str, title: &str) -> RunEvent {
    RunEvent::TicketReceived {
        ticket: Ticket {
            key: String::from(key),
            title: String::from(title),
            ..ticket()
        },
        base: base(),
    }
}

fn ready(usage: Usage) -> RunEvent {
    RunEvent::TriageFinished {
        verdict: TriageVerdict::Ready,
        usage,
    }
}

fn needs(questions: Vec<String>, usage: Usage) -> RunEvent {
    RunEvent::TriageFinished {
        verdict: TriageVerdict::NeedsInformation { questions },
        usage,
    }
}

fn posted() -> RunEvent {
    posted_as(COMMENT)
}

fn posted_as(reference: &str) -> RunEvent {
    RunEvent::QuestionsPosted {
        reference: String::from(reference),
    }
}

fn written(usage: Usage) -> RunEvent {
    RunEvent::ReproductionWritten {
        test: test_ref(),
        usage,
    }
}

fn checked(status: TestStatus, usage: Usage) -> RunEvent {
    RunEvent::ReproductionChecked { status, usage }
}

fn proposed(citations: Vec<Citation>, usage: Usage) -> RunEvent {
    RunEvent::RootCauseProposed {
        analysis: analysis_ref(),
        citations,
        usage,
    }
}

fn cited(results: Vec<CitationStatus>, usage: Usage) -> RunEvent {
    RunEvent::CitationsChecked { results, usage }
}

fn fixed(usage: Usage) -> RunEvent {
    RunEvent::FixWritten {
        diff: diff_ref(),
        usage,
    }
}

fn verified(checks: FixChecks, usage: Usage) -> RunEvent {
    RunEvent::FixVerified { checks, usage }
}

fn opened() -> RunEvent {
    opened_as(PULL_REQUEST)
}

fn opened_as(reference: &str) -> RunEvent {
    RunEvent::PullRequestOpened {
        reference: String::from(reference),
    }
}

fn failed(usage: Usage) -> RunEvent {
    failed_with(FAILURE, usage)
}

fn failed_with(detail: &str, usage: Usage) -> RunEvent {
    RunEvent::JobFailed {
        detail: String::from(detail),
        usage,
    }
}

/// The full path to `Delivered`, every job spending `each`; the verify job
/// spends `verify`.
fn path(each: Usage, verify: Usage) -> Vec<RunEvent> {
    vec![
        received(),
        ready(each),
        written(each),
        checked(TestStatus::FailedOnAssertion, each),
        proposed(citations(), each),
        cited(
            vec![CitationStatus::Verified, CitationStatus::Verified],
            each,
        ),
        fixed(each),
        verified(passing_checks(), verify),
        opened(),
    ]
}

/// The first `n` events of the default path.
fn head(n: usize) -> Vec<RunEvent> {
    let mut events = path(JOB, JOB);
    events.truncate(n);
    events
}

fn with(mut events: Vec<RunEvent>, more: Vec<RunEvent>) -> Vec<RunEvent> {
    events.extend(more);
    events
}

/// One event of each kind, used where the run must reject it.
fn sample(kind: EventKind) -> RunEvent {
    match kind {
        EventKind::TicketReceived => received(),
        EventKind::TriageFinished => ready(JOB),
        EventKind::QuestionsPosted => posted(),
        EventKind::ReproductionWritten => written(JOB),
        EventKind::ReproductionChecked => checked(TestStatus::FailedOnAssertion, JOB),
        EventKind::RootCauseProposed => proposed(citations(), JOB),
        EventKind::CitationsChecked => cited(vec![CitationStatus::Verified], JOB),
        EventKind::FixWritten => fixed(JOB),
        EventKind::FixVerified => verified(passing_checks(), JOB),
        EventKind::PullRequestOpened => opened(),
        EventKind::JobFailed => failed(JOB),
    }
}

/// `prefix`, then one event of every kind the state after it rejects, in
/// [`EventKind::ALL`] order. `waits_for` is what that state expects.
fn rejections(prefix: Vec<RunEvent>, waits_for: Option<EventKind>) -> Vec<RunEvent> {
    let accepted = |kind: EventKind| match waits_for {
        None => false,
        Some(EventKind::TicketReceived) => kind == EventKind::TicketReceived,
        Some(expected) => kind == expected || kind == EventKind::JobFailed,
    };
    let illegal = EventKind::ALL.into_iter().filter(|&k| !accepted(k));
    with(prefix, illegal.map(sample).collect())
}

fn fix_checks(change: impl FnOnce(&mut FixChecks)) -> FixChecks {
    let mut checks = passing_checks();
    change(&mut checks);
    checks
}

fn scenario(name: &'static str, events: Vec<RunEvent>) -> Scenario {
    Scenario {
        name,
        budget: BUDGET,
        events,
    }
}

fn limited(name: &'static str, budget: Budget, events: Vec<RunEvent>) -> Scenario {
    Scenario {
        name,
        budget,
        events,
    }
}

/// The budget of the fix-gate exception scenarios: cost far above what they
/// spend, 10 000 ms of job time.
pub(crate) const EXCEPTION_BUDGET: Budget = Budget {
    cost_micro_usd: 1_000_000,
    duration_ms: 10_000,
};

/// Each of the six jobs before verify in the exception scenarios.
pub(crate) const SIX_JOBS_EACH: Usage = Usage {
    cost_micro_usd: 10_000,
    duration_ms: 1_500,
};

/// The exception scenarios up to `FixWritten`: 60 000 µUSD and 9 000 ms.
fn exception_head() -> Vec<RunEvent> {
    let mut events = path(SIX_JOBS_EACH, SIX_JOBS_EACH);
    events.truncate(7);
    events
}

/// The budget of the scenarios that cross on one event late in the run.
pub(crate) const LATE_BUDGET: Budget = Budget {
    cost_micro_usd: 10_000,
    duration_ms: 1_000_000,
};

/// Every scenario, in a fixed order.
pub fn all() -> Vec<Scenario> {
    use CitationStatus::{Mismatch, Unverifiable, Verified};
    use EventKind as K;
    let max = Budget {
        cost_micro_usd: u64::MAX,
        duration_ms: u64::MAX,
    };
    let hundred = Budget {
        cost_micro_usd: 100,
        duration_ms: 1_000_000,
    };
    let short = Budget {
        cost_micro_usd: 1_000_000,
        duration_ms: 100,
    };
    let small = Budget {
        cost_micro_usd: 100,
        duration_ms: 100,
    };
    let after_triage = || with(head(1), vec![needs(questions(), JOB)]);
    vec![
        scenario("delivered", head(9)),
        // Every (state, event) pair the run rejects.
        scenario(
            "reject-in-intake",
            rejections(vec![], Some(K::TicketReceived)),
        ),
        scenario(
            "reject-in-triage",
            rejections(head(1), Some(K::TriageFinished)),
        ),
        scenario(
            "reject-in-questions",
            rejections(after_triage(), Some(K::QuestionsPosted)),
        ),
        scenario(
            "reject-in-reproduction-writing",
            rejections(head(2), Some(K::ReproductionWritten)),
        ),
        scenario(
            "reject-in-reproduction-check",
            rejections(head(3), Some(K::ReproductionChecked)),
        ),
        scenario(
            "reject-in-root-cause",
            rejections(head(4), Some(K::RootCauseProposed)),
        ),
        scenario(
            "reject-in-citation-check",
            rejections(head(5), Some(K::CitationsChecked)),
        ),
        scenario("reject-in-fix", rejections(head(6), Some(K::FixWritten))),
        scenario(
            "reject-in-verify",
            rejections(head(7), Some(K::FixVerified)),
        ),
        scenario(
            "reject-in-deliver",
            rejections(head(8), Some(K::PullRequestOpened)),
        ),
        scenario(
            "reject-in-done",
            rejections(with(head(1), vec![failed(JOB)]), None),
        ),
        // Triage.
        scenario("needs-information", with(after_triage(), vec![posted()])),
        scenario(
            "triage-no-questions",
            with(head(1), vec![needs(vec![], JOB)]),
        ),
        scenario(
            "triage-blank-question",
            with(
                head(1),
                vec![needs(
                    vec![
                        String::from("What total do you expect?"),
                        String::from("\u{200B}"),
                        String::from("\u{3000}"),
                        String::from("\u{3164}"),
                    ],
                    JOB,
                )],
            ),
        ),
        // A failed job in every waiting state.
        scenario("job-failed-triage", with(head(1), vec![failed(JOB)])),
        scenario(
            "job-failed-questions",
            with(after_triage(), vec![failed(JOB)]),
        ),
        scenario(
            "job-failed-reproduction-writing",
            with(head(2), vec![failed(JOB)]),
        ),
        scenario(
            "job-failed-reproduction-check",
            with(head(3), vec![failed(JOB)]),
        ),
        scenario("job-failed-root-cause", with(head(4), vec![failed(JOB)])),
        scenario(
            "job-failed-citation-check",
            with(head(5), vec![failed(JOB)]),
        ),
        scenario("job-failed-fix", with(head(6), vec![failed(JOB)])),
        scenario("job-failed-verify", with(head(7), vec![failed(JOB)])),
        scenario("job-failed-pull-request", with(head(8), vec![failed(JOB)])),
        // Intake validation: rejected, then accepted.
        scenario(
            "ticket-blank-title",
            vec![
                received_with("BUG-17", "  \t"),
                received_with("BUG-17", "\u{FEFF}"),
                received(),
            ],
        ),
        scenario(
            "ticket-blank-key",
            vec![received_with("", "Invoice total"), received()],
        ),
        // Forge validation: a blank reference is rejected, then accepted.
        scenario(
            "reference-blank-questions",
            with(
                after_triage(),
                vec![posted_as(""), posted_as("\u{200B}"), posted()],
            ),
        ),
        scenario(
            "reference-blank-pull-request",
            with(head(8), vec![opened_as(""), opened_as(" \t"), opened()]),
        ),
        scenario(
            "job-failed-blank-detail",
            with(
                head(3),
                vec![
                    failed_with("", JOB),
                    failed_with("\u{3000}", JOB),
                    failed(JOB),
                ],
            ),
        ),
        // Reproduction gate.
        scenario(
            "reproduction-passes-on-base",
            with(head(3), vec![checked(TestStatus::Passed, JOB)]),
        ),
        scenario(
            "reproduction-fails-to-build",
            with(head(3), vec![checked(TestStatus::FailedToBuild, JOB)]),
        ),
        scenario(
            "reproduction-errors",
            with(head(3), vec![checked(TestStatus::Errored, JOB)]),
        ),
        scenario(
            "reproduction-times-out",
            with(head(3), vec![checked(TestStatus::TimedOut, JOB)]),
        ),
        scenario(
            "reproduction-unknown",
            with(head(3), vec![checked(TestStatus::Unknown, JOB)]),
        ),
        // Root-cause precheck and gate.
        scenario(
            "root-cause-no-citations",
            with(head(4), vec![proposed(vec![], JOB)]),
        ),
        scenario(
            "root-cause-off-base",
            with(
                head(4),
                vec![proposed(
                    vec![Citation {
                        sha: CommitSha::from_corpus(OTHER_SHA),
                        ..citation("src/invoice.rs", 42)
                    }],
                    JOB,
                )],
            ),
        ),
        scenario(
            "root-cause-line-zero",
            with(
                head(4),
                vec![proposed(vec![citation("src/invoice.rs", 0)], JOB)],
            ),
        ),
        scenario(
            "root-cause-malformed-path",
            with(
                head(4),
                vec![proposed(
                    vec![
                        citation("src/invoice.rs", 42),
                        citation("src/../invoice.rs", 42),
                        citation("/src/invoice.rs", 42),
                    ],
                    JOB,
                )],
            ),
        ),
        scenario(
            "root-cause-mismatch",
            with(head(5), vec![cited(vec![Mismatch, Verified], JOB)]),
        ),
        scenario(
            "root-cause-unverifiable",
            with(head(5), vec![cited(vec![Unverifiable, Mismatch], JOB)]),
        ),
        scenario(
            "root-cause-fewer-results",
            with(head(5), vec![cited(vec![Verified], JOB)]),
        ),
        scenario(
            "root-cause-more-results",
            with(
                head(5),
                vec![cited(vec![Verified, Verified, Verified], JOB)],
            ),
        ),
        // Fix gate.
        scenario(
            "fix-reproduction-still-fails",
            with(
                head(7),
                vec![verified(
                    fix_checks(|c| c.reproduction_test = TestStatus::FailedOnAssertion),
                    JOB,
                )],
            ),
        ),
        scenario(
            "fix-test-changed",
            with(
                head(7),
                vec![verified(
                    fix_checks(|c| c.reproduction_test_unchanged = CheckStatus::Failed),
                    JOB,
                )],
            ),
        ),
        scenario(
            "fix-regression",
            with(
                head(7),
                vec![verified(
                    fix_checks(|c| c.previously_green_tests = CheckStatus::Failed),
                    JOB,
                )],
            ),
        ),
        scenario(
            "fix-lint-fails",
            with(
                head(7),
                vec![verified(fix_checks(|c| c.lint = CheckStatus::Failed), JOB)],
            ),
        ),
        scenario(
            "fix-typecheck-fails",
            with(
                head(7),
                vec![verified(
                    fix_checks(|c| c.typecheck = CheckStatus::Failed),
                    JOB,
                )],
            ),
        ),
        scenario(
            "fix-check-unknown",
            with(
                head(7),
                vec![verified(
                    fix_checks(|c| c.previously_green_tests = CheckStatus::Unknown),
                    JOB,
                )],
            ),
        ),
        scenario(
            "fix-required-not-configured",
            with(
                head(7),
                vec![verified(
                    fix_checks(|c| c.reproduction_test_unchanged = CheckStatus::NotConfigured),
                    JOB,
                )],
            ),
        ),
        scenario(
            "fix-lint-not-configured",
            with(
                head(7),
                vec![verified(
                    fix_checks(|c| c.lint = CheckStatus::NotConfigured),
                    JOB,
                )],
            ),
        ),
        // Budget, the general rule: every usage-carrying kind crosses once.
        limited(
            "budget-exactly-spent",
            hundred,
            vec![received(), ready(usage(60, 10)), written(usage(40, 10))],
        ),
        limited(
            "budget-cost-exceeded",
            hundred,
            vec![received(), ready(usage(60, 10)), written(usage(41, 10))],
        ),
        limited(
            "budget-duration-exceeded",
            short,
            vec![received(), ready(usage(0, 101))],
        ),
        limited(
            "budget-both-exceeded",
            small,
            vec![
                received(),
                ready(usage(1, 1)),
                written(usage(1, 1)),
                checked(TestStatus::FailedOnAssertion, usage(200, 200)),
            ],
        ),
        limited(
            "budget-overflow",
            max,
            vec![
                received(),
                ready(usage(u64::MAX - 1, 1)),
                written(usage(0, 1)),
                checked(TestStatus::FailedOnAssertion, usage(0, 1)),
                proposed(citations(), usage(2, 1)),
            ],
        ),
        limited(
            "budget-stops-citations-gate-pass",
            LATE_BUDGET,
            with(
                head(5),
                vec![cited(vec![Verified, Verified], usage(6_001, 100))],
            ),
        ),
        limited(
            "budget-stops-fix-written",
            LATE_BUDGET,
            with(head(6), vec![fixed(usage(5_001, 100))]),
        ),
        limited(
            "budget-beats-job-failed",
            LATE_BUDGET,
            vec![received(), failed(usage(10_001, 100))],
        ),
        // Budget, the fix-gate exception (ADR-002).
        limited(
            "budget-over-fix-passes",
            EXCEPTION_BUDGET,
            with(
                exception_head(),
                vec![verified(passing_checks(), usage(0, 1_001)), opened()],
            ),
        ),
        limited(
            "budget-fix-at-limit",
            EXCEPTION_BUDGET,
            with(
                exception_head(),
                vec![verified(passing_checks(), usage(0, 1_000)), opened()],
            ),
        ),
        limited(
            "budget-over-fix-fails",
            EXCEPTION_BUDGET,
            with(
                exception_head(),
                vec![verified(
                    fix_checks(|c| c.previously_green_tests = CheckStatus::Failed),
                    usage(0, 1_001),
                )],
            ),
        ),
        limited(
            "budget-over-then-forge-fails",
            EXCEPTION_BUDGET,
            with(
                exception_head(),
                vec![
                    verified(passing_checks(), usage(0, 1_001)),
                    failed(usage(0, 0)),
                ],
            ),
        ),
        // The verify job overflows a u64::MAX cost limit: the saturated total
        // equals the limit, and the crossing must still stick.
        limited(
            "budget-overflow-fix-then-forge-fails",
            Budget {
                cost_micro_usd: u64::MAX,
                duration_ms: 1_000_000,
            },
            vec![
                received(),
                ready(usage(u64::MAX - 1, 1)),
                written(usage(0, 1)),
                checked(TestStatus::FailedOnAssertion, usage(0, 1)),
                proposed(citations(), usage(0, 1)),
                cited(vec![Verified, Verified], usage(0, 1)),
                fixed(usage(0, 1)),
                verified(passing_checks(), usage(2, 1)),
                failed(usage(0, 0)),
            ],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{BudgetDimension, Overrun};
    use crate::gate::{CitationProblem, FixCheck, GateFailure};
    use crate::run::{AgentOutputProblem, Outcome, Record};
    use crate::values::TicketField;
    use alloc::collections::{BTreeMap, BTreeSet};

    /// What one event must do: its result and the stage after it.
    struct Want {
        result: Result<Vec<RunCommand>, DomainError>,
        stage: Stage,
    }

    struct Expectation {
        name: &'static str,
        wants: Vec<Want>,
        spent: Usage,
    }

    fn ok(commands: Vec<RunCommand>, stage: Stage) -> Want {
        Want {
            result: Ok(commands),
            stage,
        }
    }

    fn ends(outcome: Outcome) -> Want {
        Want {
            result: Ok(vec![]),
            stage: Stage::Done(outcome),
        }
    }

    fn refused(error: DomainError, stage: Stage) -> Want {
        Want {
            result: Err(error),
            stage,
        }
    }

    fn gate_failed(failure: GateFailure) -> Want {
        ends(Outcome::GateFailed(failure))
    }

    fn job_failed(awaiting: EventKind) -> Want {
        ends(Outcome::JobFailed {
            awaiting,
            detail: String::from(FAILURE),
        })
    }

    fn over(dimension: BudgetDimension, spent: Usage, budget: Budget) -> Overrun {
        Overrun {
            dimension,
            spent,
            budget,
        }
    }

    fn times(each: Usage, n: u64) -> Usage {
        usage(each.cost_micro_usd * n, each.duration_ms * n)
    }

    fn c_triage() -> RunCommand {
        RunCommand::Triage {
            ticket: ticket(),
            base: base(),
        }
    }

    fn c_post() -> RunCommand {
        RunCommand::PostQuestions {
            ticket: ticket(),
            questions: questions(),
        }
    }

    fn c_write_reproduction() -> RunCommand {
        RunCommand::WriteReproduction {
            ticket: ticket(),
            base: base(),
        }
    }

    fn c_check() -> RunCommand {
        RunCommand::CheckReproduction {
            base: base(),
            test: test_ref(),
        }
    }

    fn c_analyze() -> RunCommand {
        RunCommand::AnalyzeRootCause {
            ticket: ticket(),
            base: base(),
            test: test_ref(),
        }
    }

    fn c_verify_citations() -> RunCommand {
        RunCommand::VerifyCitations {
            base: base(),
            citations: citations(),
        }
    }

    fn c_write_fix() -> RunCommand {
        RunCommand::WriteFix {
            ticket: ticket(),
            base: base(),
            test: test_ref(),
            analysis: analysis_ref(),
        }
    }

    fn c_verify_fix() -> RunCommand {
        RunCommand::VerifyFix {
            base: base(),
            diff: diff_ref(),
            test: test_ref(),
        }
    }

    fn c_open(checks: FixChecks, spent: Usage, overrun: Option<Overrun>) -> RunCommand {
        RunCommand::OpenPullRequest {
            ticket: ticket(),
            base: base(),
            diff: diff_ref(),
            test: test_ref(),
            analysis: analysis_ref(),
            checks,
            spent,
            overrun,
        }
    }

    /// The first `n` wants of the default path (`head(n)`).
    fn head_wants(n: usize) -> Vec<Want> {
        let mut wants = vec![
            ok(vec![c_triage()], Stage::Triage),
            ok(vec![c_write_reproduction()], Stage::Reproduce),
            ok(vec![c_check()], Stage::Reproduce),
            ok(vec![c_analyze()], Stage::RootCause),
            ok(vec![c_verify_citations()], Stage::RootCause),
            ok(vec![c_write_fix()], Stage::Fix),
            ok(vec![c_verify_fix()], Stage::Verify),
            ok(
                vec![c_open(passing_checks(), times(JOB, 7), None)],
                Stage::Deliver,
            ),
            ends(Outcome::Delivered {
                pull_request: String::from(PULL_REQUEST),
                overrun: None,
            }),
        ];
        wants.truncate(n);
        wants
    }

    /// The independent legality rule: the expected kind, plus `JobFailed` in
    /// the nine waiting states.
    fn legal(expected: Option<EventKind>, got: EventKind) -> bool {
        match expected {
            None => false,
            Some(EventKind::TicketReceived) => got == EventKind::TicketReceived,
            Some(kind) => got == kind || got == EventKind::JobFailed,
        }
    }

    fn rejected_all(expected: Option<EventKind>, stage: Stage) -> Vec<Want> {
        EventKind::ALL
            .into_iter()
            .filter(|&got| !legal(expected, got))
            .map(|got| {
                refused(
                    DomainError::UnexpectedEvent { expected, got },
                    stage.clone(),
                )
            })
            .collect()
    }

    fn join(mut first: Vec<Want>, rest: Vec<Want>) -> Vec<Want> {
        first.extend(rest);
        first
    }

    fn x(name: &'static str, wants: Vec<Want>, spent: Usage) -> Expectation {
        Expectation { name, wants, spent }
    }

    fn expectations() -> Vec<Expectation> {
        use EventKind as K;
        let j = |n| times(JOB, n);
        let asked = || join(head_wants(1), vec![ok(vec![c_post()], Stage::Triage)]);
        let failed_triage = Outcome::JobFailed {
            awaiting: K::TriageFinished,
            detail: String::from(FAILURE),
        };
        let hundred = Budget {
            cost_micro_usd: 100,
            duration_ms: 1_000_000,
        };
        let short = Budget {
            cost_micro_usd: 1_000_000,
            duration_ms: 100,
        };
        let small = Budget {
            cost_micro_usd: 100,
            duration_ms: 100,
        };
        let max = Budget {
            cost_micro_usd: u64::MAX,
            duration_ms: u64::MAX,
        };
        let budget_ends = |o: Overrun| ends(Outcome::BudgetExceeded(o));
        let late = over(
            BudgetDimension::Duration,
            usage(60_000, 10_001),
            EXCEPTION_BUDGET,
        );
        let saturated = over(
            BudgetDimension::Cost,
            usage(u64::MAX, 7),
            Budget {
                cost_micro_usd: u64::MAX,
                duration_ms: 1_000_000,
            },
        );
        let fix_fails = |check| {
            join(
                head_wants(7),
                vec![gate_failed(GateFailure::FixCheckFailed(check))],
            )
        };
        let fix_unsure = |check| {
            join(
                head_wants(7),
                vec![gate_failed(GateFailure::FixCheckInconclusive(check))],
            )
        };
        let malformed = |index, problem| {
            join(
                head_wants(4),
                vec![gate_failed(GateFailure::CitationMalformed {
                    index,
                    problem,
                })],
            )
        };
        let reproduction = |failure| join(head_wants(3), vec![gate_failed(failure)]);
        let not_verified = |indices: Vec<usize>| {
            join(
                head_wants(5),
                vec![gate_failed(GateFailure::CitationsNotVerified { indices })],
            )
        };
        let result_count = |results| {
            join(
                head_wants(5),
                vec![gate_failed(GateFailure::CitationResultsMismatch {
                    citations: 2,
                    results,
                })],
            )
        };
        vec![
            x("delivered", head_wants(9), j(7)),
            x(
                "reject-in-intake",
                rejected_all(Some(K::TicketReceived), Stage::Intake),
                j(0),
            ),
            x(
                "reject-in-triage",
                join(
                    head_wants(1),
                    rejected_all(Some(K::TriageFinished), Stage::Triage),
                ),
                j(0),
            ),
            x(
                "reject-in-questions",
                join(
                    asked(),
                    rejected_all(Some(K::QuestionsPosted), Stage::Triage),
                ),
                j(1),
            ),
            x(
                "reject-in-reproduction-writing",
                join(
                    head_wants(2),
                    rejected_all(Some(K::ReproductionWritten), Stage::Reproduce),
                ),
                j(1),
            ),
            x(
                "reject-in-reproduction-check",
                join(
                    head_wants(3),
                    rejected_all(Some(K::ReproductionChecked), Stage::Reproduce),
                ),
                j(2),
            ),
            x(
                "reject-in-root-cause",
                join(
                    head_wants(4),
                    rejected_all(Some(K::RootCauseProposed), Stage::RootCause),
                ),
                j(3),
            ),
            x(
                "reject-in-citation-check",
                join(
                    head_wants(5),
                    rejected_all(Some(K::CitationsChecked), Stage::RootCause),
                ),
                j(4),
            ),
            x(
                "reject-in-fix",
                join(head_wants(6), rejected_all(Some(K::FixWritten), Stage::Fix)),
                j(5),
            ),
            x(
                "reject-in-verify",
                join(
                    head_wants(7),
                    rejected_all(Some(K::FixVerified), Stage::Verify),
                ),
                j(6),
            ),
            x(
                "reject-in-deliver",
                join(
                    head_wants(8),
                    rejected_all(Some(K::PullRequestOpened), Stage::Deliver),
                ),
                j(7),
            ),
            x(
                "reject-in-done",
                join(
                    join(head_wants(1), vec![ends(failed_triage.clone())]),
                    rejected_all(None, Stage::Done(failed_triage.clone())),
                ),
                j(1),
            ),
            x(
                "needs-information",
                join(
                    asked(),
                    vec![ends(Outcome::NeedsInformation {
                        comment: String::from(COMMENT),
                    })],
                ),
                j(1),
            ),
            x(
                "triage-no-questions",
                join(
                    head_wants(1),
                    vec![ends(Outcome::InvalidAgentOutput {
                        awaiting: K::TriageFinished,
                        problem: AgentOutputProblem::NoQuestions,
                    })],
                ),
                j(1),
            ),
            x(
                "triage-blank-question",
                join(
                    head_wants(1),
                    vec![ends(Outcome::InvalidAgentOutput {
                        awaiting: K::TriageFinished,
                        problem: AgentOutputProblem::BlankQuestion { index: 1 },
                    })],
                ),
                j(1),
            ),
            x(
                "job-failed-triage",
                join(head_wants(1), vec![job_failed(K::TriageFinished)]),
                j(1),
            ),
            x(
                "job-failed-questions",
                join(asked(), vec![job_failed(K::QuestionsPosted)]),
                j(2),
            ),
            x(
                "job-failed-reproduction-writing",
                join(head_wants(2), vec![job_failed(K::ReproductionWritten)]),
                j(2),
            ),
            x(
                "job-failed-reproduction-check",
                join(head_wants(3), vec![job_failed(K::ReproductionChecked)]),
                j(3),
            ),
            x(
                "job-failed-root-cause",
                join(head_wants(4), vec![job_failed(K::RootCauseProposed)]),
                j(4),
            ),
            x(
                "job-failed-citation-check",
                join(head_wants(5), vec![job_failed(K::CitationsChecked)]),
                j(5),
            ),
            x(
                "job-failed-fix",
                join(head_wants(6), vec![job_failed(K::FixWritten)]),
                j(6),
            ),
            x(
                "job-failed-verify",
                join(head_wants(7), vec![job_failed(K::FixVerified)]),
                j(7),
            ),
            x(
                "job-failed-pull-request",
                join(head_wants(8), vec![job_failed(K::PullRequestOpened)]),
                j(8),
            ),
            x(
                "ticket-blank-title",
                vec![
                    refused(
                        DomainError::InvalidTicket(TicketField::Title),
                        Stage::Intake,
                    ),
                    refused(
                        DomainError::InvalidTicket(TicketField::Title),
                        Stage::Intake,
                    ),
                    ok(vec![c_triage()], Stage::Triage),
                ],
                j(0),
            ),
            x(
                "ticket-blank-key",
                vec![
                    refused(DomainError::InvalidTicket(TicketField::Key), Stage::Intake),
                    ok(vec![c_triage()], Stage::Triage),
                ],
                j(0),
            ),
            x(
                "reference-blank-questions",
                join(
                    asked(),
                    vec![
                        refused(
                            DomainError::BlankEventField(K::QuestionsPosted),
                            Stage::Triage,
                        ),
                        refused(
                            DomainError::BlankEventField(K::QuestionsPosted),
                            Stage::Triage,
                        ),
                        ends(Outcome::NeedsInformation {
                            comment: String::from(COMMENT),
                        }),
                    ],
                ),
                j(1),
            ),
            x(
                "reference-blank-pull-request",
                join(
                    head_wants(8),
                    join(
                        vec![
                            refused(
                                DomainError::BlankEventField(K::PullRequestOpened),
                                Stage::Deliver,
                            ),
                            refused(
                                DomainError::BlankEventField(K::PullRequestOpened),
                                Stage::Deliver,
                            ),
                        ],
                        head_wants(9).split_off(8),
                    ),
                ),
                j(7),
            ),
            x(
                "job-failed-blank-detail",
                join(
                    head_wants(3),
                    vec![
                        refused(DomainError::BlankEventField(K::JobFailed), Stage::Reproduce),
                        refused(DomainError::BlankEventField(K::JobFailed), Stage::Reproduce),
                        job_failed(K::ReproductionChecked),
                    ],
                ),
                j(3),
            ),
            x(
                "reproduction-passes-on-base",
                reproduction(GateFailure::ReproductionPassedOnBase),
                j(3),
            ),
            x(
                "reproduction-fails-to-build",
                reproduction(GateFailure::ReproductionNotAnAssertion(
                    TestStatus::FailedToBuild,
                )),
                j(3),
            ),
            x(
                "reproduction-errors",
                reproduction(GateFailure::ReproductionNotAnAssertion(TestStatus::Errored)),
                j(3),
            ),
            x(
                "reproduction-times-out",
                reproduction(GateFailure::ReproductionNotAnAssertion(
                    TestStatus::TimedOut,
                )),
                j(3),
            ),
            x(
                "reproduction-unknown",
                reproduction(GateFailure::ReproductionInconclusive),
                j(3),
            ),
            x(
                "root-cause-no-citations",
                join(head_wants(4), vec![gate_failed(GateFailure::NoCitations)]),
                j(4),
            ),
            x(
                "root-cause-off-base",
                malformed(0, CitationProblem::NotOnBase),
                j(4),
            ),
            x(
                "root-cause-line-zero",
                malformed(0, CitationProblem::LineZero),
                j(4),
            ),
            x(
                "root-cause-malformed-path",
                malformed(1, CitationProblem::ParentComponent),
                j(4),
            ),
            x("root-cause-mismatch", not_verified(vec![0]), j(5)),
            x("root-cause-unverifiable", not_verified(vec![0, 1]), j(5)),
            x("root-cause-fewer-results", result_count(1), j(5)),
            x("root-cause-more-results", result_count(3), j(5)),
            x(
                "fix-reproduction-still-fails",
                fix_fails(FixCheck::ReproductionTest),
                j(7),
            ),
            x(
                "fix-test-changed",
                fix_fails(FixCheck::ReproductionTestUnchanged),
                j(7),
            ),
            x(
                "fix-regression",
                fix_fails(FixCheck::PreviouslyGreenTests),
                j(7),
            ),
            x("fix-lint-fails", fix_fails(FixCheck::Lint), j(7)),
            x("fix-typecheck-fails", fix_fails(FixCheck::Typecheck), j(7)),
            x(
                "fix-check-unknown",
                fix_unsure(FixCheck::PreviouslyGreenTests),
                j(7),
            ),
            x(
                "fix-required-not-configured",
                fix_unsure(FixCheck::ReproductionTestUnchanged),
                j(7),
            ),
            x(
                "fix-lint-not-configured",
                join(
                    head_wants(7),
                    vec![ok(
                        vec![c_open(
                            fix_checks(|c| c.lint = CheckStatus::NotConfigured),
                            j(7),
                            None,
                        )],
                        Stage::Deliver,
                    )],
                ),
                j(7),
            ),
            x("budget-exactly-spent", head_wants(3), usage(100, 20)),
            x(
                "budget-cost-exceeded",
                join(
                    head_wants(2),
                    vec![budget_ends(over(
                        BudgetDimension::Cost,
                        usage(101, 20),
                        hundred,
                    ))],
                ),
                usage(101, 20),
            ),
            x(
                "budget-duration-exceeded",
                join(
                    head_wants(1),
                    vec![budget_ends(over(
                        BudgetDimension::Duration,
                        usage(0, 101),
                        short,
                    ))],
                ),
                usage(0, 101),
            ),
            x(
                "budget-both-exceeded",
                join(
                    head_wants(3),
                    vec![budget_ends(over(
                        BudgetDimension::Cost,
                        usage(202, 202),
                        small,
                    ))],
                ),
                usage(202, 202),
            ),
            x(
                "budget-overflow",
                join(
                    head_wants(4),
                    vec![budget_ends(over(
                        BudgetDimension::Cost,
                        usage(u64::MAX, 4),
                        max,
                    ))],
                ),
                usage(u64::MAX, 4),
            ),
            x(
                "budget-stops-citations-gate-pass",
                join(
                    head_wants(5),
                    vec![budget_ends(over(
                        BudgetDimension::Cost,
                        usage(10_001, 500),
                        LATE_BUDGET,
                    ))],
                ),
                usage(10_001, 500),
            ),
            x(
                "budget-stops-fix-written",
                join(
                    head_wants(6),
                    vec![budget_ends(over(
                        BudgetDimension::Cost,
                        usage(10_001, 600),
                        LATE_BUDGET,
                    ))],
                ),
                usage(10_001, 600),
            ),
            x(
                "budget-beats-job-failed",
                join(
                    head_wants(1),
                    vec![budget_ends(over(
                        BudgetDimension::Cost,
                        usage(10_001, 100),
                        LATE_BUDGET,
                    ))],
                ),
                usage(10_001, 100),
            ),
            x(
                "budget-over-fix-passes",
                join(
                    head_wants(7),
                    vec![
                        ok(
                            vec![c_open(passing_checks(), usage(60_000, 10_001), Some(late))],
                            Stage::Deliver,
                        ),
                        ends(Outcome::Delivered {
                            pull_request: String::from(PULL_REQUEST),
                            overrun: Some(late),
                        }),
                    ],
                ),
                usage(60_000, 10_001),
            ),
            x(
                "budget-fix-at-limit",
                join(
                    head_wants(7),
                    vec![
                        ok(
                            vec![c_open(passing_checks(), usage(60_000, 10_000), None)],
                            Stage::Deliver,
                        ),
                        ends(Outcome::Delivered {
                            pull_request: String::from(PULL_REQUEST),
                            overrun: None,
                        }),
                    ],
                ),
                usage(60_000, 10_000),
            ),
            x(
                "budget-over-fix-fails",
                join(head_wants(7), vec![budget_ends(late)]),
                usage(60_000, 10_001),
            ),
            x(
                "budget-over-then-forge-fails",
                join(
                    head_wants(7),
                    vec![
                        ok(
                            vec![c_open(passing_checks(), usage(60_000, 10_001), Some(late))],
                            Stage::Deliver,
                        ),
                        budget_ends(late),
                    ],
                ),
                usage(60_000, 10_001),
            ),
            x(
                "budget-overflow-fix-then-forge-fails",
                join(
                    head_wants(7),
                    vec![
                        ok(
                            vec![c_open(
                                passing_checks(),
                                usage(u64::MAX, 7),
                                Some(saturated),
                            )],
                            Stage::Deliver,
                        ),
                        budget_ends(saturated),
                    ],
                ),
                usage(u64::MAX, 7),
            ),
        ]
    }

    fn traces() -> Vec<(Scenario, Trace)> {
        all()
            .into_iter()
            .map(|s| {
                let trace = fold(&s).expect("every corpus budget is valid");
                (s, trace)
            })
            .collect()
    }

    #[test]
    fn every_scenario_matches_its_expectation() {
        let expected: BTreeMap<&str, Expectation> =
            expectations().into_iter().map(|e| (e.name, e)).collect();
        for (scenario, trace) in traces() {
            let name = scenario.name;
            let want = expected
                .get(name)
                .expect("every scenario has an expectation");
            assert_eq!(trace.entries.len(), scenario.events.len(), "{name}");
            assert_eq!(
                trace.entries.len(),
                want.wants.len(),
                "{name}: number of events"
            );
            for (k, (entry, w)) in trace.entries.iter().zip(&want.wants).enumerate() {
                assert_eq!(entry.got, scenario.events[k].kind(), "{name} event {k}");
                assert_eq!(entry.result, w.result, "{name} event {k}: result");
                assert_eq!(entry.stage, w.stage, "{name} event {k}: stage");
            }
            let last = want.wants.last().map_or(Stage::Intake, |w| w.stage.clone());
            assert_eq!(trace.run.stage(), last, "{name}: final stage");
            assert_eq!(trace.run.spent(), want.spent, "{name}: spent");
            assert_eq!(trace.run.budget(), scenario.budget, "{name}: budget");
        }
    }

    #[test]
    fn expectations_and_scenarios_are_a_bijection() {
        let scenarios: Vec<&str> = all().iter().map(|s| s.name).collect();
        let expected: Vec<&str> = expectations().iter().map(|e| e.name).collect();
        assert_eq!(scenarios.len(), 63);
        assert_eq!(scenarios.len(), expected.len());
        let a: BTreeSet<&str> = scenarios.into_iter().collect();
        let b: BTreeSet<&str> = expected.into_iter().collect();
        assert_eq!(a.len(), 63, "scenario names are unique");
        assert_eq!(a, b);
    }

    #[test]
    fn scenario_names_are_unique_and_kebab_case() {
        let mut names = BTreeSet::new();
        for s in all() {
            assert!(!s.name.is_empty());
            assert!(
                s.name
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-')),
                "{}",
                s.name
            );
            assert!(names.insert(s.name), "duplicate {}", s.name);
        }
    }

    #[test]
    fn corpus_evidence_refs_parse() {
        for r in [test_ref(), analysis_ref(), diff_ref()] {
            assert_eq!(EvidenceRef::parse(r.as_str()), Ok(r.clone()));
        }
    }

    #[test]
    fn corpus_shas_parse() {
        assert_eq!(CommitSha::parse(BASE), Ok(base()));
        assert_eq!(
            CommitSha::parse(OTHER_SHA),
            Ok(CommitSha::from_corpus(OTHER_SHA))
        );
    }

    #[test]
    fn every_state_event_pair_is_exercised() {
        // A state is identified by what it expects: Intake, the nine
        // waiting states (each expects another kind) and Done (None).
        let states: Vec<Option<EventKind>> = core::iter::once(None)
            .chain(
                EventKind::ALL
                    .into_iter()
                    .filter(|&k| k != EventKind::JobFailed)
                    .map(Some),
            )
            .collect();
        assert_eq!(states.len(), 11);
        let mut seen = BTreeSet::new();
        let mut accepted = BTreeSet::new();
        for (_, trace) in traces() {
            for e in trace.entries {
                seen.insert((e.expected, e.got));
                if legal(e.expected, e.got) {
                    if e.result.is_ok() {
                        accepted.insert((e.expected, e.got));
                    }
                    assert!(
                        !matches!(e.result, Err(DomainError::UnexpectedEvent { .. })),
                        "legal pair rejected: {:?}",
                        (e.expected, e.got)
                    );
                } else {
                    assert_eq!(
                        e.result,
                        Err(DomainError::UnexpectedEvent {
                            expected: e.expected,
                            got: e.got,
                        })
                    );
                }
            }
        }
        let mut legal_pairs = 0;
        for &state in &states {
            for got in EventKind::ALL {
                assert!(
                    seen.contains(&(state, got)),
                    "not exercised: {:?}",
                    (state, got)
                );
                if legal(state, got) {
                    legal_pairs += 1;
                    assert!(
                        accepted.contains(&(state, got)),
                        "never accepted: {:?}",
                        (state, got)
                    );
                }
            }
        }
        assert_eq!(seen.len(), 121);
        assert_eq!(legal_pairs, 19);
        assert_eq!(accepted.len(), 19);
    }

    #[test]
    fn budget_rule_covers_every_usage_event() {
        let no_usage = [
            EventKind::TicketReceived,
            EventKind::QuestionsPosted,
            EventKind::PullRequestOpened,
        ];
        let usage_kinds: Vec<EventKind> = EventKind::ALL
            .into_iter()
            .filter(|k| !no_usage.contains(k))
            .collect();
        assert_eq!(usage_kinds.len(), 8);
        let traces = traces();
        for kind in usage_kinds {
            let crossed = traces.iter().any(|(_, t)| {
                t.entries.iter().any(|e| {
                    e.got == kind
                        && e.result.is_ok()
                        && matches!(e.stage, Stage::Done(Outcome::BudgetExceeded(_)))
                })
            });
            assert!(crossed, "no scenario crosses the budget on {kind:?}");
        }
        let delivered_over = traces.iter().any(|(_, t)| {
            let carried = t.entries.iter().find_map(|e| match (&e.got, &e.result) {
                (EventKind::FixVerified, Ok(commands)) => match commands.as_slice() {
                    [
                        RunCommand::OpenPullRequest {
                            overrun: Some(o), ..
                        },
                    ] => Some(*o),
                    _ => None,
                },
                _ => None,
            });
            let delivered = match t.run.stage() {
                Stage::Done(Outcome::Delivered {
                    overrun: Some(o), ..
                }) => Some(o),
                _ => None,
            };
            carried.is_some() && carried == delivered
        });
        assert!(
            delivered_over,
            "no over-budget fix is delivered with its overrun"
        );
    }

    #[test]
    fn new_rejects_zero_limits() {
        let id = || RunId::new(String::from("run-1"));
        assert_eq!(
            Run::new(id(), usage_budget(0, 1)),
            Err(DomainError::InvalidBudget(BudgetDimension::Cost))
        );
        assert_eq!(
            Run::new(id(), usage_budget(1, 0)),
            Err(DomainError::InvalidBudget(BudgetDimension::Duration))
        );
        assert_eq!(
            Run::new(id(), usage_budget(0, 0)),
            Err(DomainError::InvalidBudget(BudgetDimension::Cost))
        );
        let run = Run::new(id(), usage_budget(1, 1)).expect("1 and 1 are valid limits");
        assert_eq!(run.stage(), Stage::Intake);
        assert_eq!(run.expects(), Some(EventKind::TicketReceived));
        assert_eq!(run.spent(), Usage::default());
        assert_eq!(run.id().as_str(), "run-1");
    }

    fn usage_budget(cost_micro_usd: u64, duration_ms: u64) -> Budget {
        Budget {
            cost_micro_usd,
            duration_ms,
        }
    }

    fn final_record(name: &str) -> Record {
        let scenario = all()
            .into_iter()
            .find(|s| s.name == name)
            .expect("scenario exists");
        let trace = fold(&scenario).expect("valid budget");
        trace.run.record().expect("the run is past intake")
    }

    fn scenario_named(name: &str) -> Scenario {
        all()
            .into_iter()
            .find(|s| s.name == name)
            .expect("scenario exists")
    }

    #[test]
    fn blank_event_fields_leave_the_run_unchanged() {
        // Folding the events up to the first blank text and folding the same
        // events plus the two rejected ones must give the same run: nothing
        // advances and nothing is charged (the rejected JobFailed events
        // carry usage).
        for name in [
            "reference-blank-questions",
            "reference-blank-pull-request",
            "job-failed-blank-detail",
        ] {
            let full = scenario_named(name);
            let n = full.events.len();
            let before = Scenario {
                events: full.events[..n - 3].to_vec(),
                ..full.clone()
            };
            let rejected = Scenario {
                events: full.events[..n - 1].to_vec(),
                ..full.clone()
            };
            let a = fold(&before).expect("valid budget");
            let b = fold(&rejected).expect("valid budget");
            assert_eq!(a.run, b.run, "{name}");
            for entry in &b.entries[n - 3..] {
                assert_eq!(
                    entry.result,
                    Err(DomainError::BlankEventField(entry.got)),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn finished_runs_keep_their_evidence() {
        // Over budget with a failing fix gate: the failing checks stay.
        match final_record("budget-over-fix-fails") {
            Record::Verified(v) => {
                assert_eq!(v.checks.previously_green_tests, CheckStatus::Failed);
                assert_eq!(v.overrun, None);
            }
            other => panic!("unexpected record {other:?}"),
        }
        // Over budget, then the forge fails: the verified diff stays.
        match final_record("budget-over-then-forge-fails") {
            Record::Verified(v) => {
                assert_eq!(v.fixed.diff, diff_ref());
                assert!(v.overrun.is_some());
            }
            other => panic!("unexpected record {other:?}"),
        }
        // A failed root-cause gate keeps the analysis and its citations.
        match final_record("root-cause-mismatch") {
            Record::Analyzed(a) => {
                assert_eq!(a.analysis, analysis_ref());
                assert_eq!(a.citations, citations());
            }
            other => panic!("unexpected record {other:?}"),
        }
        // A failed reproduction gate keeps the test.
        match final_record("reproduction-unknown") {
            Record::Reproduced(r) => assert_eq!(r.test, test_ref()),
            other => panic!("unexpected record {other:?}"),
        }
    }
}
