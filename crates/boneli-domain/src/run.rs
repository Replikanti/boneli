//! The run state machine (`docs/ARCHITECTURE.md`, "Debugging line" and
//! "Code architecture"; ADR-002).
//!
//! A run waits for exactly one event kind at a time ([`Run::expects`]).
//! [`Run::handle`] takes that event and returns the next run and the commands
//! for the application. `JobFailed` is accepted in every waiting state; every
//! other event out of sequence is an [`DomainError::UnexpectedEvent`].

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::budget::{Budget, BudgetDimension, Overrun, Usage, charge};
use crate::command::RunCommand;
use crate::error::DomainError;
use crate::event::{EventKind, RunEvent, TriageVerdict};
use crate::gate::{
    FixCheck, FixChecks, GateFailure, GateOutcome, fix_gate, reproduction_gate, root_cause_gate,
    root_cause_precheck,
};
use crate::values::{Citation, CommitSha, EvidenceRef, RunId, Ticket, is_blank};

/// Where a run is (`docs/ARCHITECTURE.md`, "Debugging line").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Waiting for the ticket.
    Intake,
    /// Triage, and posting its questions.
    Triage,
    /// Writing and checking the reproduction test.
    Reproduce,
    /// Root-cause analysis and citation verification.
    RootCause,
    /// Writing the fix.
    Fix,
    /// Verifying the fix in a clean sandbox.
    Verify,
    /// Opening the pull request.
    Deliver,
    /// Finished; no event is accepted.
    Done(Outcome),
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The pull request is open.
    Delivered {
        /// The forge's reference to it.
        pull_request: String,
        /// Set when the verify job crossed a limit; the run still delivered
        /// and says so (ADR-002).
        overrun: Option<Overrun>,
    },
    /// Triage asked the reporter; an answer starts a new run.
    NeedsInformation {
        /// The forge's reference to the questions comment.
        comment: String,
    },
    /// A gate did not pass.
    GateFailed(GateFailure),
    /// A budget limit was crossed.
    BudgetExceeded(Overrun),
    /// The job or forge call the run waited for failed.
    JobFailed {
        /// The event kind the run waited for.
        awaiting: EventKind,
        /// What went wrong, as reported.
        detail: String,
    },
    /// The agent's output cannot be used.
    InvalidAgentOutput {
        /// The event kind that carried it.
        awaiting: EventKind,
        /// What is wrong with it.
        problem: AgentOutputProblem,
    },
}

/// Why agent output cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentOutputProblem {
    /// Triage needs information but asks no question.
    NoQuestions,
    /// A triage question is blank; the first one is reported.
    BlankQuestion {
        /// Its index.
        index: usize,
    },
}

/// The ticket and base, known after intake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Opened {
    pub(crate) ticket: Ticket,
    pub(crate) base: CommitSha,
}

/// Plus the reproduction test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reproduced {
    pub(crate) opened: Opened,
    pub(crate) test: EvidenceRef,
}

/// Plus the analysis and its citations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Analyzed {
    pub(crate) reproduced: Reproduced,
    pub(crate) analysis: EvidenceRef,
    pub(crate) citations: Vec<Citation>,
}

/// Plus the diff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Fixed {
    pub(crate) analyzed: Analyzed,
    pub(crate) diff: EvidenceRef,
}

/// Plus the fix checks, and the overrun of an over-budget `FixVerified`
/// that passed the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Verified {
    pub(crate) fixed: Fixed,
    pub(crate) checks: FixChecks,
    pub(crate) overrun: Option<Overrun>,
}

/// The evidence a finished run points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Record {
    Opened(Opened),
    Reproduced(Reproduced),
    Analyzed(Analyzed),
    Fixed(Fixed),
    Verified(Verified),
}

/// The nine states that wait for a job or forge result.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Waiting {
    Triage(Opened),
    Questions(Opened),
    ReproductionWriting(Opened),
    ReproductionCheck(Reproduced),
    RootCause(Reproduced),
    CitationCheck(Analyzed),
    FixWriting(Analyzed),
    Verify(Fixed),
    Deliver(Verified),
}

impl Waiting {
    fn expects(&self) -> EventKind {
        match self {
            Waiting::Triage(_) => EventKind::TriageFinished,
            Waiting::Questions(_) => EventKind::QuestionsPosted,
            Waiting::ReproductionWriting(_) => EventKind::ReproductionWritten,
            Waiting::ReproductionCheck(_) => EventKind::ReproductionChecked,
            Waiting::RootCause(_) => EventKind::RootCauseProposed,
            Waiting::CitationCheck(_) => EventKind::CitationsChecked,
            Waiting::FixWriting(_) => EventKind::FixWritten,
            Waiting::Verify(_) => EventKind::FixVerified,
            Waiting::Deliver(_) => EventKind::PullRequestOpened,
        }
    }

    fn stage(&self) -> Stage {
        match self {
            Waiting::Triage(_) | Waiting::Questions(_) => Stage::Triage,
            Waiting::ReproductionWriting(_) | Waiting::ReproductionCheck(_) => Stage::Reproduce,
            Waiting::RootCause(_) | Waiting::CitationCheck(_) => Stage::RootCause,
            Waiting::FixWriting(_) => Stage::Fix,
            Waiting::Verify(_) => Stage::Verify,
            Waiting::Deliver(_) => Stage::Deliver,
        }
    }

    fn into_record(self) -> Record {
        match self {
            Waiting::Triage(o) | Waiting::Questions(o) | Waiting::ReproductionWriting(o) => {
                Record::Opened(o)
            }
            Waiting::ReproductionCheck(r) | Waiting::RootCause(r) => Record::Reproduced(r),
            Waiting::CitationCheck(a) | Waiting::FixWriting(a) => Record::Analyzed(a),
            Waiting::Verify(f) => Record::Fixed(f),
            Waiting::Deliver(v) => Record::Verified(v),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Intake,
    Waiting(Waiting),
    Done { outcome: Outcome, record: Record },
}

impl State {
    fn done(outcome: Outcome, record: Record) -> State {
        State::Done { outcome, record }
    }
}

/// One debugging run: its limits, what it has spent, where it is and the
/// evidence it has collected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    id: RunId,
    budget: Budget,
    spent: Usage,
    state: State,
}

impl Run {
    /// A run in [`Stage::Intake`]. A zero limit is a missing value, not a
    /// budget, and is rejected.
    pub fn new(id: RunId, budget: Budget) -> Result<Run, DomainError> {
        if budget.cost_micro_usd == 0 {
            return Err(DomainError::InvalidBudget(BudgetDimension::Cost));
        }
        if budget.duration_ms == 0 {
            return Err(DomainError::InvalidBudget(BudgetDimension::Duration));
        }
        Ok(Run {
            id,
            budget,
            spent: Usage::default(),
            state: State::Intake,
        })
    }

    /// The run's identifier.
    pub fn id(&self) -> &RunId {
        &self.id
    }

    /// The run's limits.
    pub fn budget(&self) -> Budget {
        self.budget
    }

    /// The total consumption so far, saturated at `u64::MAX`.
    pub fn spent(&self) -> Usage {
        self.spent
    }

    /// Where the run is.
    pub fn stage(&self) -> Stage {
        match &self.state {
            State::Intake => Stage::Intake,
            State::Waiting(w) => w.stage(),
            State::Done { outcome, .. } => Stage::Done(outcome.clone()),
        }
    }

    /// The event kind the run waits for; `None` once it is done. `JobFailed`
    /// is also accepted whenever this is neither `None` nor `TicketReceived`.
    pub fn expects(&self) -> Option<EventKind> {
        match &self.state {
            State::Intake => Some(EventKind::TicketReceived),
            State::Waiting(w) => Some(w.expects()),
            State::Done { .. } => None,
        }
    }

    /// The evidence of a run past intake.
    #[cfg(test)]
    pub(crate) fn record(&self) -> Option<Record> {
        match &self.state {
            State::Intake => None,
            State::Waiting(w) => Some(w.clone().into_record()),
            State::Done { record, .. } => Some(record.clone()),
        }
    }

    /// Takes one event and returns the next run and the commands to execute.
    ///
    /// The order decides the ties (ADR-002):
    /// 1. An event the state does not accept is an
    ///    [`DomainError::UnexpectedEvent`], and it is never charged.
    /// 2. A ticket with a blank key or title is a
    ///    [`DomainError::InvalidTicket`]; the run stays in intake.
    /// 3. The event's usage is charged. A total over a limit ends the run as
    ///    [`Outcome::BudgetExceeded`] with no command, whatever the event
    ///    says, with one exception: a `FixVerified` whose fix gate passes
    ///    goes on and carries the overrun into `OpenPullRequest` and
    ///    `Delivered` (opening the pull request spends no agent budget).
    /// 4. The event's own rule: gate, validation, transition.
    pub fn handle(self, event: RunEvent) -> Result<(Run, Vec<RunCommand>), DomainError> {
        let Run {
            id,
            budget,
            spent,
            state,
        } = self;
        let (waiting, event) = match (state, event) {
            (State::Intake, RunEvent::TicketReceived { ticket, base }) => {
                if let Some(field) = ticket.blank_field() {
                    return Err(DomainError::InvalidTicket(field));
                }
                let command = RunCommand::Triage {
                    ticket: ticket.clone(),
                    base: base.clone(),
                };
                let run = Run {
                    id,
                    budget,
                    spent,
                    state: State::Waiting(Waiting::Triage(Opened { ticket, base })),
                };
                return Ok((run, vec![command]));
            }
            (State::Waiting(waiting), event) if accepts(&waiting, event.kind()) => (waiting, event),
            (state, event) => {
                let expected = Run {
                    id,
                    budget,
                    spent,
                    state,
                }
                .expects();
                return Err(DomainError::UnexpectedEvent {
                    expected,
                    got: event.kind(),
                });
            }
        };

        let fix = match &event {
            RunEvent::FixVerified { checks, .. } => Some(fix_gate(checks)),
            _ => None,
        };
        let (spent, overrun) = match event.usage().map(|usage| charge(spent, usage, &budget)) {
            None => (spent, None),
            Some(Ok(total)) => (total, None),
            Some(Err(overrun)) => (overrun.spent, Some(overrun)),
        };
        // The one budget exception (ADR-002): a FixVerified whose fix gate
        // passes goes on with the overrun. Every other crossing ends the run.
        let exception = matches!(fix, Some(GateOutcome::Pass));
        let (carried, stop) = match overrun {
            Some(o) if exception => (Some(o), None),
            other => (None, other),
        };

        // Step 4 runs first so that a stopped run keeps the evidence this
        // event brought (the failing checks of a FixVerified, for example);
        // a stop then replaces its outcome and drops its commands. `advance`
        // never returns Intake, so the last arm sees no stop.
        let (state, commands) = advance(waiting, event, fix, carried, spent);
        let (state, commands) = match (stop, state) {
            (Some(o), State::Waiting(w)) => (
                State::done(Outcome::BudgetExceeded(o), w.into_record()),
                vec![],
            ),
            (Some(o), State::Done { record, .. }) => {
                (State::done(Outcome::BudgetExceeded(o), record), vec![])
            }
            (_, state) => (state, commands),
        };
        let run = Run {
            id,
            budget,
            spent,
            state,
        };
        Ok((run, commands))
    }
}

/// Whether a waiting state accepts an event kind: the one it expects, or
/// `JobFailed`.
fn accepts(waiting: &Waiting, got: EventKind) -> bool {
    got == waiting.expects() || got == EventKind::JobFailed
}

/// Step 4 of [`Run::handle`]: the event's own rule in a waiting state that
/// accepts it. `fix` is the fix gate's result on `FixVerified`, `overrun` the
/// overrun the exception carries, and `spent` the total after this event.
fn advance(
    waiting: Waiting,
    event: RunEvent,
    fix: Option<GateOutcome>,
    overrun: Option<Overrun>,
    spent: Usage,
) -> (State, Vec<RunCommand>) {
    let awaiting = waiting.expects();
    match (waiting, event) {
        (waiting, RunEvent::JobFailed { detail, .. }) => {
            let outcome = Outcome::JobFailed { awaiting, detail };
            (State::done(outcome, waiting.into_record()), vec![])
        }
        (Waiting::Triage(o), RunEvent::TriageFinished { verdict, .. }) => match verdict {
            TriageVerdict::Ready => {
                let command = RunCommand::WriteReproduction {
                    ticket: o.ticket.clone(),
                    base: o.base.clone(),
                };
                (
                    State::Waiting(Waiting::ReproductionWriting(o)),
                    vec![command],
                )
            }
            TriageVerdict::NeedsInformation { questions } => {
                let problem = if questions.is_empty() {
                    Some(AgentOutputProblem::NoQuestions)
                } else {
                    questions
                        .iter()
                        .position(|q| is_blank(q))
                        .map(|index| AgentOutputProblem::BlankQuestion { index })
                };
                match problem {
                    Some(problem) => {
                        let outcome = Outcome::InvalidAgentOutput { awaiting, problem };
                        (State::done(outcome, Record::Opened(o)), vec![])
                    }
                    None => {
                        let command = RunCommand::PostQuestions {
                            ticket: o.ticket.clone(),
                            questions,
                        };
                        (State::Waiting(Waiting::Questions(o)), vec![command])
                    }
                }
            }
        },
        (Waiting::Questions(o), RunEvent::QuestionsPosted { reference }) => {
            let outcome = Outcome::NeedsInformation { comment: reference };
            (State::done(outcome, Record::Opened(o)), vec![])
        }
        (Waiting::ReproductionWriting(o), RunEvent::ReproductionWritten { test, .. }) => {
            let command = RunCommand::CheckReproduction {
                base: o.base.clone(),
                test: test.clone(),
            };
            let r = Reproduced { opened: o, test };
            (State::Waiting(Waiting::ReproductionCheck(r)), vec![command])
        }
        (Waiting::ReproductionCheck(r), RunEvent::ReproductionChecked { status, .. }) => {
            match reproduction_gate(status) {
                GateOutcome::Pass => {
                    let command = RunCommand::AnalyzeRootCause {
                        ticket: r.opened.ticket.clone(),
                        base: r.opened.base.clone(),
                        test: r.test.clone(),
                    };
                    (State::Waiting(Waiting::RootCause(r)), vec![command])
                }
                GateOutcome::Fail(failure) => gate_failed(failure, Record::Reproduced(r)),
            }
        }
        (
            Waiting::RootCause(r),
            RunEvent::RootCauseProposed {
                analysis,
                citations,
                ..
            },
        ) => {
            let outcome = root_cause_precheck(&citations, &r.opened.base);
            let a = Analyzed {
                reproduced: r,
                analysis,
                citations,
            };
            match outcome {
                GateOutcome::Pass => {
                    let command = RunCommand::VerifyCitations {
                        base: a.reproduced.opened.base.clone(),
                        citations: a.citations.clone(),
                    };
                    (State::Waiting(Waiting::CitationCheck(a)), vec![command])
                }
                GateOutcome::Fail(failure) => gate_failed(failure, Record::Analyzed(a)),
            }
        }
        (Waiting::CitationCheck(a), RunEvent::CitationsChecked { results, .. }) => {
            match root_cause_gate(&a.citations, &results) {
                GateOutcome::Pass => {
                    let command = RunCommand::WriteFix {
                        ticket: a.reproduced.opened.ticket.clone(),
                        base: a.reproduced.opened.base.clone(),
                        test: a.reproduced.test.clone(),
                        analysis: a.analysis.clone(),
                    };
                    (State::Waiting(Waiting::FixWriting(a)), vec![command])
                }
                GateOutcome::Fail(failure) => gate_failed(failure, Record::Analyzed(a)),
            }
        }
        (Waiting::FixWriting(a), RunEvent::FixWritten { diff, .. }) => {
            let command = RunCommand::VerifyFix {
                base: a.reproduced.opened.base.clone(),
                diff: diff.clone(),
                test: a.reproduced.test.clone(),
            };
            let f = Fixed { analyzed: a, diff };
            (State::Waiting(Waiting::Verify(f)), vec![command])
        }
        (Waiting::Verify(f), RunEvent::FixVerified { checks, .. }) => {
            let v = Verified {
                fixed: f,
                checks,
                overrun,
            };
            match fix {
                Some(GateOutcome::Pass) => {
                    let a = &v.fixed.analyzed;
                    let command = RunCommand::OpenPullRequest {
                        ticket: a.reproduced.opened.ticket.clone(),
                        base: a.reproduced.opened.base.clone(),
                        diff: v.fixed.diff.clone(),
                        test: a.reproduced.test.clone(),
                        analysis: a.analysis.clone(),
                        checks,
                        spent,
                        overrun,
                    };
                    (State::Waiting(Waiting::Deliver(v)), vec![command])
                }
                Some(GateOutcome::Fail(failure)) => gate_failed(failure, Record::Verified(v)),
                // `handle` evaluates the fix gate for every FixVerified; a
                // missing result fails closed.
                None => gate_failed(
                    GateFailure::FixCheckInconclusive(FixCheck::ReproductionTest),
                    Record::Verified(v),
                ),
            }
        }
        (Waiting::Deliver(v), RunEvent::PullRequestOpened { reference }) => {
            let outcome = Outcome::Delivered {
                pull_request: reference,
                overrun: v.overrun,
            };
            (State::done(outcome, Record::Verified(v)), vec![])
        }
        // Unreachable: `handle` admits only accepted kinds, and every
        // accepted (state, kind) pair has an arm above. Fail closed anyway:
        // the run stays where it was and emits nothing.
        (waiting, _) => (State::Waiting(waiting), vec![]),
    }
}

fn gate_failed(failure: GateFailure, record: Record) -> (State, Vec<RunCommand>) {
    (State::done(Outcome::GateFailed(failure), record), vec![])
}
