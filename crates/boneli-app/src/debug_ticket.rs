//! The `DebugTicket` use case (`docs/ARCHITECTURE.md`, "Debugging line";
//! ADR-004, D5 and D6).
//!
//! It drives one run from the ticket to its outcome: the domain's
//! [`Run::handle`] decides, and `DebugTicket` executes each command as one
//! job through the ports and feeds the job's result back as the next event.
//! Commands run one at a time, in the order the run emits them. An event is
//! appended to the log only after the run accepted it, so every stored log
//! replays ([`crate::store::replay`]).
//!
//! The patch check between `FixWritten` and `VerifyFix` is a job of the
//! application, not of an adapter: it fetches the base through `Git`,
//! applies the stored diff, describes the change with
//! [`Git::patch_between`] and judges it with the domain's
//! [`patch_policy`] under the request's limits (ADR-023, D3).
//!
//! A failure inside a job (the agent, the verifier, the forge, git, or
//! loading or storing evidence) ends the run with a recorded `JobFailed`
//! outcome, its detail capped at [`MAX_DETAIL_BYTES`](crate::MAX_DETAIL_BYTES)
//! so the event fits a log line (ADR-023, D2). A
//! failure of the event store itself returns [`DebugTicketError::Store`] at
//! once, and the log stays the prefix of accepted events.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;
use core::fmt;

use boneli_domain::{
    Budget, Citation, CitationStatus, CommitSha, DomainError, EventKind, EvidenceRef, FixChecks,
    Outcome, PatchCheck, PatchLimits, Run, RunCommand, RunEvent, RunId, Stage, TestStatus, Ticket,
    TriageVerdict, Usage, patch_policy,
};

use crate::agent::{
    Agent, FixRequest, PreviousTriage, ReproductionRequest, RootCauseRequest, TriageRequest,
};
use crate::clock::Clock;
use crate::evidence::Evidence;
use crate::forge::{Attached, Forge, PullRequest};
use crate::git::{Git, GitError, RepoUrl};
use crate::ids::Ids;
use crate::job::{JobFailure, cap_detail};
use crate::store::{EventStore, RunStart, StoreError, replay};
use crate::verifier::Verifier;

/// The ports one run drives. The use case borrows them for the run; a root
/// that shares adapters across threads holds them behind its own bounds
/// (ADR-004, D1).
pub struct DebugTicket<'a> {
    /// Triage, reproduction, root cause and fix.
    pub agent: &'a dyn Agent,
    /// The checks behind the gates.
    pub verifier: &'a dyn Verifier,
    /// Questions and the pull request.
    pub forge: &'a dyn Forge,
    /// The base and the diff applied to it, for the patch check.
    pub git: &'a dyn Git,
    /// The run logs.
    pub events: &'a dyn EventStore,
    /// The test, the analysis and the diff.
    pub evidence: &'a dyn Evidence,
    /// Measures each job's duration.
    pub clock: &'a dyn Clock,
    /// Issues the run's id.
    pub ids: &'a dyn Ids,
}

/// One ticket to debug.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugRequest {
    /// The bug report.
    pub ticket: Ticket,
    /// The commit everything is reproduced and verified against.
    pub base: CommitSha,
    /// The repository `base` is fetched from for the patch check. The
    /// forge pushes to the repository it was configured with, so the
    /// composition root builds both from one value (ADR-023, D3).
    pub repo: RepoUrl,
    /// The run's limits.
    pub budget: Budget,
    /// The patch policy's limits, run input like the budget (ADR-023,
    /// D5). Not logged: the `PatchChecked` event records the limits the
    /// policy judged against.
    pub patch_limits: PatchLimits,
    /// The run that asked the questions this request answers, if any
    /// (ADR-004, D6).
    pub previous: Option<RunId>,
}

/// A finished run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugReport {
    /// The run, in `Stage::Done`.
    pub run: Run,
    /// Every command the run emitted, in order.
    pub commands: Vec<RunCommand>,
}

/// Why `DebugRequest::previous` cannot be continued (ADR-004, D6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviousRunError {
    /// The event store has no such run, or cannot hold its id.
    Unknown,
    /// The stored log does not replay.
    Unreplayable(DomainError),
    /// The run did not end with triage questions; its stage is given.
    NotNeedsInformation(Stage),
    /// The run is about another ticket: its source or key differs.
    DifferentTicket,
}

/// Why `DebugTicket` returned without a finished run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DebugTicketError {
    /// The run rejected the request: an invalid ticket or budget, or (never
    /// on today's ports) an event.
    Domain(DomainError),
    /// The previous run cannot be continued; nothing was stored.
    PreviousRun(PreviousRunError),
    /// The event store failed; the log holds the events accepted so far.
    Store(StoreError),
    /// No command is left, but the run still waits for this event kind. It
    /// cannot happen under ADR-002's table; it fails closed if a later
    /// domain change makes it possible (ADR-004, D5).
    Stalled(EventKind),
}

impl fmt::Display for DebugTicketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DebugTicketError::Domain(error) => write!(f, "the run rejected the input: {error}"),
            DebugTicketError::PreviousRun(PreviousRunError::Unknown) => {
                f.write_str("the previous run is unknown")
            }
            DebugTicketError::PreviousRun(PreviousRunError::Unreplayable(error)) => {
                write!(f, "the log of the previous run does not replay: {error}")
            }
            DebugTicketError::PreviousRun(PreviousRunError::NotNeedsInformation(stage)) => write!(
                f,
                "the previous run did not end with triage questions, it is at {stage:?}"
            ),
            DebugTicketError::PreviousRun(PreviousRunError::DifferentTicket) => {
                f.write_str("the previous run is about another ticket")
            }
            DebugTicketError::Store(error) => write!(f, "the event store failed: {error}"),
            DebugTicketError::Stalled(kind) => {
                write!(f, "the run waits for {kind:?} with no command left to run")
            }
        }
    }
}

impl core::error::Error for DebugTicketError {}

/// What a measured job produced, before its usage is known.
enum Produced {
    Triage(TriageVerdict),
    Reproduction(EvidenceRef),
    ReproductionStatus(TestStatus),
    RootCause(EvidenceRef, Vec<Citation>),
    Citations(Vec<CitationStatus>),
    Fix(EvidenceRef),
    Patch(PatchCheck),
    Checks(FixChecks),
}

impl Produced {
    fn into_event(self, usage: Usage) -> RunEvent {
        match self {
            Produced::Triage(verdict) => RunEvent::TriageFinished { verdict, usage },
            Produced::Reproduction(test) => RunEvent::ReproductionWritten { test, usage },
            Produced::ReproductionStatus(status) => RunEvent::ReproductionChecked { status, usage },
            Produced::RootCause(analysis, citations) => RunEvent::RootCauseProposed {
                analysis,
                citations,
                usage,
            },
            Produced::Citations(results) => RunEvent::CitationsChecked { results, usage },
            Produced::Fix(diff) => RunEvent::FixWritten { diff, usage },
            Produced::Patch(check) => RunEvent::PatchChecked { check, usage },
            Produced::Checks(checks) => RunEvent::FixVerified { checks, usage },
        }
    }
}

/// The end of a measured job: its provider cost, and what it produced or
/// the failure detail.
struct Job {
    cost_micro_usd: u64,
    result: Result<Produced, String>,
}

impl Job {
    fn done(cost_micro_usd: u64, produced: Produced) -> Job {
        Job {
            cost_micro_usd,
            result: Ok(produced),
        }
    }

    fn failed(cost_micro_usd: u64, detail: String) -> Job {
        Job {
            cost_micro_usd,
            result: Err(detail),
        }
    }

    /// An agent failure charges the cost the agent ran up.
    fn agent_failed(failure: JobFailure) -> Job {
        Job::failed(failure.cost_micro_usd(), String::from(failure.detail()))
    }

    /// A verifier spends no provider budget (ADR-004, D5).
    fn verifier_failed(failure: &JobFailure) -> Job {
        Job::failed(0, String::from(failure.detail()))
    }
}

/// The run input that is not the run's own state: what the patch check
/// needs besides the command.
struct Input {
    repo: RepoUrl,
    patch_limits: PatchLimits,
}

/// A forge failure carries no usage (ADR-002, D3). Its detail is capped
/// like every `JobFailed` detail ([`cap_detail`]).
fn forge_failed(detail: String) -> RunEvent {
    RunEvent::JobFailed {
        detail: cap_detail(detail),
        usage: Usage::default(),
    }
}

impl DebugTicket<'_> {
    /// Runs one ticket to its outcome.
    ///
    /// Start order (ADR-004, D5): resolve `previous`, take an id from
    /// `Ids`, `Run::new`, `TicketReceived` through `Run::handle`, and only
    /// then create the log and append `TicketReceived`. A failure before the
    /// log is created stores nothing, and a rejected `previous` uses up no
    /// id.
    pub fn run(&self, request: DebugRequest) -> Result<DebugReport, DebugTicketError> {
        let DebugRequest {
            ticket,
            base,
            repo,
            budget,
            patch_limits,
            previous,
        } = request;
        let input = Input { repo, patch_limits };
        let context = match &previous {
            Some(id) => Some(self.previous_triage(id, &ticket)?),
            None => None,
        };
        let id = self.ids.run_id();
        let run = Run::new(id.clone(), budget).map_err(DebugTicketError::Domain)?;
        let received = RunEvent::TicketReceived { ticket, base };
        let (mut run, first) = run
            .handle(received.clone())
            .map_err(DebugTicketError::Domain)?;
        let start = RunStart { budget, previous };
        self.events
            .create(&id, &start)
            .map_err(DebugTicketError::Store)?;
        self.events
            .append(&id, &received)
            .map_err(DebugTicketError::Store)?;

        let mut commands = first.clone();
        let mut queue = VecDeque::from(first);
        // The run's latest `Clock` reading: every reading is checked against
        // the one before it, within a job and across jobs (ADR-004, D5).
        let last = Cell::new(None);
        while let Some(command) = queue.pop_front() {
            let event = self.execute(&id, command, &input, context.as_ref(), &last);
            let (next, more) = run
                .handle(event.clone())
                .map_err(DebugTicketError::Domain)?;
            self.events
                .append(&id, &event)
                .map_err(DebugTicketError::Store)?;
            run = next;
            commands.extend(more.iter().cloned());
            queue.extend(more);
        }
        match run.expects() {
            None => Ok(DebugReport { run, commands }),
            Some(kind) => Err(DebugTicketError::Stalled(kind)),
        }
    }

    /// The previous run's questions (ADR-004, D6): it exists, its log
    /// replays, it ended as `NeedsInformation`, and it is about the same
    /// ticket (source and key compared exactly; title and body may change).
    fn previous_triage(
        &self,
        id: &RunId,
        ticket: &Ticket,
    ) -> Result<PreviousTriage, DebugTicketError> {
        let previous = |error| DebugTicketError::PreviousRun(error);
        let log = match self.events.load(id) {
            Ok(log) => log,
            Err(StoreError::UnknownRun | StoreError::InvalidRunId) => {
                return Err(previous(PreviousRunError::Unknown));
            }
            Err(error) => return Err(DebugTicketError::Store(error)),
        };
        let (run, _) =
            replay(id, &log).map_err(|error| previous(PreviousRunError::Unreplayable(error)))?;
        let outcome = match run.stage() {
            Stage::Done(outcome @ Outcome::NeedsInformation { .. }) => outcome,
            stage => return Err(previous(PreviousRunError::NotNeedsInformation(stage))),
        };
        let mut asked = None;
        let mut questions = None;
        for event in log.events {
            match event {
                RunEvent::TicketReceived { ticket, .. } => asked = Some(ticket),
                RunEvent::TriageFinished {
                    verdict: TriageVerdict::NeedsInformation { questions: q },
                    ..
                } => questions = Some(q),
                _ => {}
            }
        }
        // A log that replays to NeedsInformation holds both events; fail
        // closed if it ever does not.
        let (Some(asked), Some(questions)) = (asked, questions) else {
            return Err(previous(PreviousRunError::NotNeedsInformation(run.stage())));
        };
        if asked.source != ticket.source || asked.key != ticket.key {
            return Err(previous(PreviousRunError::DifferentTicket));
        }
        Ok(PreviousTriage {
            run: id.clone(),
            outcome,
            questions,
        })
    }

    /// Executes one command as one job and returns the event it produced.
    fn execute(
        &self,
        id: &RunId,
        command: RunCommand,
        input: &Input,
        previous: Option<&PreviousTriage>,
        last: &Cell<Option<u64>>,
    ) -> RunEvent {
        match command {
            RunCommand::Triage { ticket, base } => self.measured(last, || {
                let request = TriageRequest {
                    ticket,
                    base,
                    previous: previous.cloned(),
                };
                match self.agent.triage(&request) {
                    Ok(report) => {
                        Job::done(report.cost_micro_usd, Produced::Triage(report.verdict))
                    }
                    Err(failure) => Job::agent_failed(failure),
                }
            }),
            RunCommand::PostQuestions { ticket, questions } => {
                match self.forge.post_questions(&ticket, &questions) {
                    Ok(reference) => RunEvent::QuestionsPosted {
                        reference: String::from(reference.as_str()),
                    },
                    Err(failure) => forge_failed(String::from(failure.detail())),
                }
            }
            RunCommand::WriteReproduction { ticket, base } => self.measured(last, || {
                let request = ReproductionRequest { ticket, base };
                match self.agent.write_reproduction(&request) {
                    Ok(written) => Job {
                        cost_micro_usd: written.cost_micro_usd,
                        result: self
                            .store("reproduction test", &written.content)
                            .map(Produced::Reproduction),
                    },
                    Err(failure) => Job::agent_failed(failure),
                }
            }),
            RunCommand::CheckReproduction { base, test } => self.measured(last, || {
                let test = match self.load("reproduction test", &test) {
                    Ok(test) => test,
                    Err(detail) => return Job::failed(0, detail),
                };
                match self.verifier.check_reproduction(&base, &test) {
                    Ok(status) => Job::done(0, Produced::ReproductionStatus(status)),
                    Err(failure) => Job::verifier_failed(&failure),
                }
            }),
            RunCommand::AnalyzeRootCause { ticket, base, test } => self.measured(last, || {
                let test = match self.load("reproduction test", &test) {
                    Ok(test) => test,
                    Err(detail) => return Job::failed(0, detail),
                };
                let request = RootCauseRequest { ticket, base, test };
                match self.agent.analyze_root_cause(&request) {
                    Ok(report) => Job {
                        cost_micro_usd: report.cost_micro_usd,
                        result: self
                            .store("analysis", &report.analysis)
                            .map(|analysis| Produced::RootCause(analysis, report.citations)),
                    },
                    Err(failure) => Job::agent_failed(failure),
                }
            }),
            RunCommand::VerifyCitations { base, citations } => self.measured(last, || {
                match self.verifier.verify_citations(&base, &citations) {
                    Ok(results) => Job::done(0, Produced::Citations(results)),
                    Err(failure) => Job::verifier_failed(&failure),
                }
            }),
            RunCommand::WriteFix {
                ticket,
                base,
                test,
                analysis,
            } => self.measured(last, || {
                let inputs = self
                    .load("reproduction test", &test)
                    .and_then(|test| Ok((test, self.load("analysis", &analysis)?)));
                let (test, analysis) = match inputs {
                    Ok(inputs) => inputs,
                    Err(detail) => return Job::failed(0, detail),
                };
                let request = FixRequest {
                    ticket,
                    base,
                    test,
                    analysis,
                };
                match self.agent.write_fix(&request) {
                    Ok(written) => Job {
                        cost_micro_usd: written.cost_micro_usd,
                        result: self.store("diff", &written.content).map(Produced::Fix),
                    },
                    Err(failure) => Job::agent_failed(failure),
                }
            }),
            RunCommand::CheckPatch { base, diff } => self.measured(last, || {
                let diff = match self.load("diff", &diff) {
                    Ok(diff) => diff,
                    Err(detail) => return Job::failed(0, detail),
                };
                match self.check_patch(input, &base, &diff) {
                    Ok(check) => Job::done(0, Produced::Patch(check)),
                    Err(detail) => Job::failed(0, detail),
                }
            }),
            RunCommand::VerifyFix { base, diff, test } => self.measured(last, || {
                let inputs = self
                    .load("diff", &diff)
                    .and_then(|diff| Ok((diff, self.load("reproduction test", &test)?)));
                let (diff, test) = match inputs {
                    Ok(inputs) => inputs,
                    Err(detail) => return Job::failed(0, detail),
                };
                match self.verifier.verify_fix(&base, &diff, &test) {
                    Ok(checks) => Job::done(0, Produced::Checks(checks)),
                    Err(failure) => Job::verifier_failed(&failure),
                }
            }),
            RunCommand::OpenPullRequest {
                ticket,
                base,
                diff,
                test,
                analysis,
                citations,
                checks,
                spent,
                overrun,
            } => {
                let attached = self.attach("diff", diff).and_then(|diff| {
                    let test = self.attach("reproduction test", test)?;
                    Ok((diff, test, self.attach("analysis", analysis)?))
                });
                let (diff, test, analysis) = match attached {
                    Ok(attached) => attached,
                    Err(detail) => return forge_failed(detail),
                };
                let request = PullRequest {
                    run: id.clone(),
                    ticket,
                    base,
                    diff,
                    test,
                    analysis,
                    citations,
                    checks,
                    spent,
                    overrun,
                };
                match self.forge.open_pull_request(&request) {
                    Ok(reference) => RunEvent::PullRequestOpened {
                        reference: String::from(reference.as_str()),
                    },
                    Err(failure) => forge_failed(String::from(failure.detail())),
                }
            }
        }
    }

    /// The patch check (ADR-023, D3): the base, the diff applied to it by
    /// the same `Git::apply` the forge pushes from (ADR-014), the change
    /// between the two, and the policy's verdict under the request's
    /// limits. A git error names the step; a diff that does not apply is
    /// one, so it ends the run as a failed job (ADR-023, D2).
    fn check_patch(
        &self,
        input: &Input,
        base: &CommitSha,
        diff: &[u8],
    ) -> Result<PatchCheck, String> {
        let failed = |step: &str, error: GitError| format!("{step} failed: {error}");
        let checkout = self
            .git
            .fetch_base(&input.repo, base)
            .map_err(|e| failed("fetching the base", e))?;
        let applied = self
            .git
            .apply(&checkout, diff)
            .map_err(|e| failed("applying the diff", e))?;
        let patch = self
            .git
            .patch_between(&checkout, &applied)
            .map_err(|e| failed("describing the patch", e))?;
        let limits = input.patch_limits;
        Ok(match patch {
            Ok(patch) => PatchCheck::Judged {
                limits,
                verdict: patch_policy(&patch, &limits),
            },
            Err(path) => PatchCheck::Unreadable(path),
        })
    }

    /// Loads stored evidence for the pull request.
    fn attach(&self, what: &str, reference: EvidenceRef) -> Result<Attached, String> {
        self.load(what, &reference)
            .map(|content| Attached { reference, content })
    }

    /// Runs a job between two `Clock` readings and turns its end into the
    /// event: the job's cost and the difference of the readings as its
    /// usage (ADR-002, D3). Every reading is checked against the one before
    /// it in the run (ADR-004, D5). A first reading lower than the run's
    /// previous one ends the job as `JobFailed` before it runs, with zero
    /// usage; a second reading lower than the first ends it with duration 0
    /// and the job's cost. A clock that goes backwards would under-charge
    /// the duration budget, and ending the run stops all further spending.
    fn measured(&self, last: &Cell<Option<u64>>, job: impl FnOnce() -> Job) -> RunEvent {
        let before = self.clock.now_ms();
        if let Some(previous) = last.get().filter(|previous| before < *previous) {
            return RunEvent::JobFailed {
                detail: format!("the clock went backwards: {previous} ms, then {before} ms"),
                usage: Usage::default(),
            };
        }
        let Job {
            cost_micro_usd,
            result,
        } = job();
        let after = self.clock.now_ms();
        last.set(Some(after));
        let Some(duration_ms) = after.checked_sub(before) else {
            return RunEvent::JobFailed {
                detail: format!("the clock went backwards: {before} ms, then {after} ms"),
                usage: Usage {
                    cost_micro_usd,
                    duration_ms: 0,
                },
            };
        };
        let usage = Usage {
            cost_micro_usd,
            duration_ms,
        };
        match result {
            Ok(produced) => produced.into_event(usage),
            Err(detail) => RunEvent::JobFailed {
                detail: cap_detail(detail),
                usage,
            },
        }
    }

    fn load(&self, what: &str, reference: &EvidenceRef) -> Result<Vec<u8>, String> {
        self.evidence
            .get(reference)
            .map_err(|error| format!("loading the {what} failed: {error}"))
    }

    fn store(&self, what: &str, content: &[u8]) -> Result<EvidenceRef, String> {
        self.evidence
            .put(content)
            .map_err(|error| format!("storing the {what} failed: {error}"))
    }
}
