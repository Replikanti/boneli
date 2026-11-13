//! Mutant adapters: every contract clause can fail (ADR-004, D2).
//!
//! One mutant adapter per clause case wraps an in-memory adapter and breaks
//! exactly that case; `tests/mutants.rs` checks that its suite returns a
//! violation naming it, and that mutants and clause cases are a bijection.
//! A clause that no mutant breaks would be a vacuous check.
//!
//! The table lives in this test-only library, not in `boneli-memory`'s
//! tests, so that the replay binary can render the violation of every
//! mutant in two processes and compare them (ADR-004, D10): a violation
//! detail that held an address or other nondeterministic text would fail
//! the replay like run data does.

use std::fmt::Write as _;
use std::sync::Mutex;

use boneli_app::contract::{self, SilentFailure, Violation};
use boneli_app::{
    Agent, Clock, EventStore, Evidence, EvidenceError, FixRequest, Forge, ForgeRef, Ids,
    JobFailure, PullRequest, ReproductionRequest, RootCauseReport, RootCauseRequest, RunLog,
    RunStart, StoreError, TriageReport, TriageRequest, Verifier, Written,
};
use boneli_domain::{
    Budget, Citation, CitationStatus, CommitSha, EvidenceRef, FixChecks, RunEvent, RunId,
    TestStatus, Ticket,
};
use boneli_memory::{
    AgentScript, ForgeScript, MemoryAgent, MemoryEventStore, MemoryEvidence, MemoryForge,
    MemoryVerifier, Response, ScriptedFailure, SequentialIds, StepClock, VerifierScript,
};

const STATUS: &str = "exit status 3";
const BASE: &str = "0123456789abcdef0123456789abcdef01234567";

fn fails<T>() -> Vec<Response<T>> {
    vec![Response::Fail(silent())]
}

fn silent() -> ScriptedFailure {
    ScriptedFailure {
        error_output: String::new(),
        status: String::from(STATUS),
        cost_micro_usd: 10,
    }
}

/// The failure a mutant reports instead: the status is dropped.
fn without_status(failure: JobFailure) -> JobFailure {
    JobFailure::new("", "", failure.cost_micro_usd())
}

// ---------------------------------------------------------------- EventStore

/// Which `EventStore` clause the mutant breaks.
#[derive(Clone, Copy, Debug)]
enum StoreBug {
    /// `create` stores nothing; the first append creates the run.
    LazyCreate,
    /// `load` returns the events in reverse.
    Reversed,
    /// `append` drops an event equal to the last one.
    DropsDuplicates,
    /// Every run shares the log of the first run created.
    SharedLog,
    /// `load` of an unknown run is an empty log, and `append` creates it.
    UnknownIsEmpty,
    /// A second `create` of the same id claims success.
    CreateTwiceOk,
    /// Text stops at NUL, like a store built on C strings.
    StripsNul,
    /// The id is cut to its last `/` component, like a careless file store.
    LastComponent,
}

struct StoreMutant {
    bug: StoreBug,
    inner: MemoryEventStore,
    first: Mutex<Option<RunId>>,
}

fn store_mutant(bug: StoreBug) -> impl Fn() -> StoreMutant {
    move || StoreMutant {
        bug,
        inner: MemoryEventStore::new(),
        first: Mutex::new(None),
    }
}

fn some_start() -> RunStart {
    RunStart {
        budget: Budget {
            cost_micro_usd: 1,
            duration_ms: 1,
        },
        previous: None,
    }
}

impl StoreMutant {
    fn key(&self, id: &RunId) -> RunId {
        match self.bug {
            StoreBug::LastComponent => {
                let last = id.as_str().rsplit('/').next().unwrap_or_default();
                RunId::new(last.to_owned())
            }
            StoreBug::SharedLog => {
                let mut first = self.first.lock().expect("not poisoned");
                first.get_or_insert_with(|| id.clone()).clone()
            }
            _ => id.clone(),
        }
    }

    fn ensure_created(&self, key: &RunId) -> Result<(), StoreError> {
        if self.inner.load(key).is_err() {
            self.inner.create(key, &some_start())?;
        }
        Ok(())
    }
}

impl EventStore for StoreMutant {
    fn create(&self, id: &RunId, start: &RunStart) -> Result<(), StoreError> {
        let key = self.key(id);
        match self.bug {
            StoreBug::LazyCreate => Ok(()),
            StoreBug::CreateTwiceOk | StoreBug::SharedLog => match self.inner.create(&key, start) {
                Err(StoreError::AlreadyExists) => Ok(()),
                other => other,
            },
            _ => self.inner.create(&key, start),
        }
    }

    fn append(&self, id: &RunId, event: &RunEvent) -> Result<(), StoreError> {
        let key = self.key(id);
        match self.bug {
            StoreBug::LazyCreate | StoreBug::UnknownIsEmpty => {
                self.ensure_created(&key)?;
                self.inner.append(&key, event)
            }
            StoreBug::DropsDuplicates => {
                let last = self.inner.load(&key)?.events.last().cloned();
                if last.as_ref() == Some(event) {
                    Ok(())
                } else {
                    self.inner.append(&key, event)
                }
            }
            StoreBug::StripsNul => match event {
                RunEvent::TicketReceived { ticket, base } => {
                    let mut ticket = ticket.clone();
                    ticket.body = ticket.body.replace('\0', "");
                    let base = base.clone();
                    self.inner
                        .append(&key, &RunEvent::TicketReceived { ticket, base })
                }
                _ => self.inner.append(&key, event),
            },
            _ => self.inner.append(&key, event),
        }
    }

    fn load(&self, id: &RunId) -> Result<RunLog, StoreError> {
        let key = self.key(id);
        match self.bug {
            StoreBug::Reversed => self.inner.load(&key).map(|mut log| {
                log.events.reverse();
                log
            }),
            StoreBug::UnknownIsEmpty => Ok(self.inner.load(&key).unwrap_or(RunLog {
                start: some_start(),
                events: vec![],
            })),
            _ => self.inner.load(&key),
        }
    }
}

// ------------------------------------------------------------------ Evidence

/// Which `Evidence` clause the mutant breaks.
#[derive(Clone, Copy, Debug)]
enum EvidenceBug {
    /// Blobs are cut at the 64 KiB pipe buffer.
    Truncates,
    /// Every put issues a new reference.
    NoDedup,
    /// The reference is derived from the length only.
    KeyedByLength,
    /// An unknown reference reads as empty.
    UnknownIsEmpty,
    /// A reference is cut to its last `/` component.
    LastComponent,
    /// `get` returns what is on disk without checking it against the
    /// reference.
    SkipsIntegrity,
    /// References come from a counter, as in a store that keeps a checksum
    /// beside each blob instead of naming blobs by their digest.
    CounterReferences,
}

struct EvidenceMutant {
    bug: EvidenceBug,
    inner: MemoryEvidence,
    by_length: Mutex<Vec<(usize, EvidenceRef)>>,
    puts: Mutex<u64>,
    /// What `tamper` wrote.
    on_disk: Mutex<Vec<(EvidenceRef, Vec<u8>)>>,
    /// Counter references and the content-derived ones behind them.
    aliases: Mutex<Vec<(EvidenceRef, EvidenceRef)>>,
}

impl EvidenceMutant {
    fn overwritten(&self, reference: &EvidenceRef) -> Option<Vec<u8>> {
        let on_disk = self.on_disk.lock().expect("not poisoned");
        on_disk
            .iter()
            .rev()
            .find(|(r, _)| r == reference)
            .map(|(_, content)| content.clone())
    }
}

fn evidence_mutant(bug: EvidenceBug) -> impl Fn() -> EvidenceMutant {
    move || EvidenceMutant {
        bug,
        inner: MemoryEvidence::new(),
        by_length: Mutex::new(Vec::new()),
        puts: Mutex::new(0),
        on_disk: Mutex::new(Vec::new()),
        aliases: Mutex::new(Vec::new()),
    }
}

/// The tamper hook of every evidence mutant.
/// The tamper hook of every evidence mutant: it records the overwrite, and
/// every mutant but `SkipsIntegrity` then rejects that reference as
/// `Corrupted`, as `MemoryEvidence` does after re-deriving the reference.
fn tamper_mutant(store: &EvidenceMutant, reference: &EvidenceRef, content: &[u8]) {
    store
        .on_disk
        .lock()
        .expect("not poisoned")
        .push((reference.clone(), content.to_vec()));
}

fn evidence_suite(bug: EvidenceBug) -> Result<(), Violation> {
    contract::evidence::run(evidence_mutant(bug), tamper_mutant)
}

impl Evidence for EvidenceMutant {
    fn put(&self, content: &[u8]) -> Result<EvidenceRef, EvidenceError> {
        match self.bug {
            EvidenceBug::Truncates => self.inner.put(&content[..content.len().min(1 << 16)]),
            EvidenceBug::NoDedup => {
                // Salt every put, then strip the salt again on get.
                let mut puts = self.puts.lock().expect("not poisoned");
                *puts += 1;
                let mut salted = puts.to_be_bytes().to_vec();
                salted.extend_from_slice(content);
                self.inner.put(&salted)
            }
            EvidenceBug::KeyedByLength => {
                let mut seen = self.by_length.lock().expect("not poisoned");
                if let Some((_, reference)) = seen.iter().find(|(len, _)| *len == content.len()) {
                    return Ok(reference.clone());
                }
                let reference = self.inner.put(content)?;
                seen.push((content.len(), reference.clone()));
                Ok(reference)
            }
            EvidenceBug::CounterReferences => {
                let inner = self.inner.put(content)?;
                let mut aliases = self.aliases.lock().expect("not poisoned");
                if let Some((alias, _)) = aliases.iter().find(|(_, i)| *i == inner) {
                    return Ok(alias.clone());
                }
                let n = aliases.len() + 1;
                let alias = EvidenceRef::parse(&format!("blob-{n}")).expect("not blank");
                aliases.push((alias.clone(), inner));
                Ok(alias)
            }
            _ => self.inner.put(content),
        }
    }

    fn get(&self, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError> {
        match self.bug {
            EvidenceBug::NoDedup => self.inner.get(reference).map(|salted| salted[8..].to_vec()),
            EvidenceBug::UnknownIsEmpty => Ok(self.inner.get(reference).unwrap_or_default()),
            EvidenceBug::LastComponent => {
                let last = reference.as_str().rsplit('/').next().unwrap_or_default();
                match EvidenceRef::parse(last) {
                    Ok(cut) => self.inner.get(&cut),
                    Err(_) => Err(EvidenceError::NotFound),
                }
            }
            _ if self.overwritten(reference).is_some() => {
                match (self.bug, self.overwritten(reference)) {
                    (EvidenceBug::SkipsIntegrity, Some(content)) => Ok(content),
                    _ => Err(EvidenceError::Corrupted),
                }
            }
            EvidenceBug::CounterReferences => {
                let aliases = self.aliases.lock().expect("not poisoned");
                match aliases.iter().find(|(alias, _)| alias == reference) {
                    Some((_, inner)) => self.inner.get(inner),
                    None => Err(EvidenceError::NotFound),
                }
            }
            _ => self.inner.get(reference),
        }
    }
}

// ------------------------------------------------------------- Clock and Ids

/// Goes back by 1 ms once, at reading 500.
struct BackwardsClock {
    inner: StepClock,
    readings: Mutex<u64>,
}

impl Clock for BackwardsClock {
    fn now_ms(&self) -> u64 {
        let mut readings = self.readings.lock().expect("not poisoned");
        *readings += 1;
        let now = self.inner.now_ms();
        if *readings == 500 { now - 1_001 } else { now }
    }
}

/// Issues a blank id once, as its second id.
struct BlankOnceIds {
    inner: SequentialIds,
    issued: Mutex<u64>,
}

impl Ids for BlankOnceIds {
    fn run_id(&self) -> RunId {
        let mut issued = self.issued.lock().expect("not poisoned");
        *issued += 1;
        if *issued == 2 {
            RunId::new(String::from("\u{200B}"))
        } else {
            self.inner.run_id()
        }
    }
}

/// A 16-bit counter: wraps after 65 536 ids.
struct SixteenBitIds {
    next: Mutex<u16>,
}

impl Ids for SixteenBitIds {
    fn run_id(&self) -> RunId {
        let mut next = self.next.lock().expect("not poisoned");
        let n = *next;
        *next = n.wrapping_add(1);
        RunId::new(format!("run-{n}"))
    }
}

// ------------------------------------------------------- Agent, Verifier, Forge

/// Drops the status from the failures of one operation only, so the
/// suite's check of that operation is shown to bite.
struct StatusDroppingAgent(&'static str, MemoryAgent);

impl StatusDroppingAgent {
    fn failure(&self, operation: &str, failure: JobFailure) -> JobFailure {
        if self.0 == operation {
            without_status(failure)
        } else {
            failure
        }
    }
}

impl Agent for StatusDroppingAgent {
    fn triage(&self, request: &TriageRequest) -> Result<TriageReport, JobFailure> {
        self.1
            .triage(request)
            .map_err(|f| self.failure("triage", f))
    }
    fn write_reproduction(&self, request: &ReproductionRequest) -> Result<Written, JobFailure> {
        let result = self.1.write_reproduction(request);
        result.map_err(|f| self.failure("write_reproduction", f))
    }
    fn analyze_root_cause(
        &self,
        request: &RootCauseRequest,
    ) -> Result<RootCauseReport, JobFailure> {
        let result = self.1.analyze_root_cause(request);
        result.map_err(|f| self.failure("analyze_root_cause", f))
    }
    fn write_fix(&self, request: &FixRequest) -> Result<Written, JobFailure> {
        self.1
            .write_fix(request)
            .map_err(|f| self.failure("write_fix", f))
    }
}

fn silent_agent() -> MemoryAgent {
    MemoryAgent::new(AgentScript {
        triage: fails(),
        write_reproduction: fails(),
        analyze_root_cause: fails(),
        write_fix: fails(),
    })
}

#[derive(Clone, Copy, Debug)]
enum VerifierBug {
    /// Drops the last citation status.
    DropsStatus,
    /// Drops the status from the failures of this operation only.
    DropsFailureStatusOn(&'static str),
}

struct VerifierMutant(VerifierBug, MemoryVerifier);

impl Verifier for VerifierMutant {
    fn check_reproduction(&self, base: &CommitSha, test: &[u8]) -> Result<TestStatus, JobFailure> {
        self.1
            .check_reproduction(base, test)
            .map_err(|f| self.failure("check_reproduction", f))
    }
    fn verify_citations(
        &self,
        base: &CommitSha,
        citations: &[Citation],
    ) -> Result<Vec<CitationStatus>, JobFailure> {
        let mut statuses = self
            .1
            .verify_citations(base, citations)
            .map_err(|f| self.failure("verify_citations", f))?;
        if matches!(self.0, VerifierBug::DropsStatus) {
            statuses.pop();
        }
        Ok(statuses)
    }
    fn verify_fix(
        &self,
        base: &CommitSha,
        diff: &[u8],
        test: &[u8],
    ) -> Result<FixChecks, JobFailure> {
        self.1
            .verify_fix(base, diff, test)
            .map_err(|f| self.failure("verify_fix", f))
    }
}

impl VerifierMutant {
    fn failure(&self, operation: &str, failure: JobFailure) -> JobFailure {
        match self.0 {
            VerifierBug::DropsFailureStatusOn(op) if op == operation => without_status(failure),
            _ => failure,
        }
    }
}

fn verifier_fixtures(
    bug: VerifierBug,
) -> (
    impl Fn() -> contract::verifier::Answering<VerifierMutant>,
    impl Fn() -> SilentFailure<VerifierMutant>,
) {
    let answering = move || {
        let base = CommitSha::parse(BASE).expect("valid SHA");
        let citations = contract::verifier::sample(&base);
        let statuses = vec![CitationStatus::Verified; citations.len()];
        let script = VerifierScript {
            verify_citations: vec![Response::Answer(statuses)],
            ..VerifierScript::default()
        };
        contract::verifier::Answering {
            adapter: VerifierMutant(bug, MemoryVerifier::new(script)),
            base,
            citations,
        }
    };
    let silent = move || SilentFailure {
        adapter: VerifierMutant(
            bug,
            MemoryVerifier::new(VerifierScript {
                check_reproduction: vec![Response::Fail(silent())],
                verify_citations: vec![Response::Fail(silent())],
                verify_fix: vec![Response::Fail(silent())],
            }),
        ),
        status: String::from(STATUS),
    };
    (answering, silent)
}

#[derive(Clone, Copy, Debug)]
enum ForgeBug {
    /// Every call returns the same reference.
    SameReference,
    /// Drops the status from the failures of this operation only.
    DropsFailureStatusOn(&'static str),
}

struct ForgeMutant(ForgeBug, MemoryForge);

impl ForgeMutant {
    fn answer(
        &self,
        operation: &str,
        result: Result<ForgeRef, JobFailure>,
    ) -> Result<ForgeRef, JobFailure> {
        match self.0 {
            ForgeBug::SameReference => {
                result.map(|_| ForgeRef::parse("pull-1").expect("not blank"))
            }
            ForgeBug::DropsFailureStatusOn(op) if op == operation => result.map_err(without_status),
            ForgeBug::DropsFailureStatusOn(_) => result,
        }
    }
}

impl Forge for ForgeMutant {
    fn post_questions(
        &self,
        ticket: &Ticket,
        questions: &[String],
    ) -> Result<ForgeRef, JobFailure> {
        self.answer("post_questions", self.1.post_questions(ticket, questions))
    }
    fn open_pull_request(&self, request: &PullRequest) -> Result<ForgeRef, JobFailure> {
        self.answer("open_pull_request", self.1.open_pull_request(request))
    }
}

fn silent_forge() -> MemoryForge {
    MemoryForge::scripted(ForgeScript {
        post_questions: vec![Response::Fail(silent())],
        open_pull_request: vec![Response::Fail(silent())],
    })
}

// --------------------------------------------------------------------- Table

/// One mutant: the port and clause it breaks, the operation whose check it
/// targets (empty for clauses without operations), and the suite run on it.
pub struct Mutant {
    /// The port, as in [`Violation::port`].
    pub port: &'static str,
    /// The clause it breaks.
    pub clause: &'static str,
    /// For `silent-failure-detail`, the one operation it breaks.
    pub operation: &'static str,
    /// Runs the port's suite on the mutant.
    pub run: Box<dyn Fn() -> Result<(), Violation>>,
}

fn mutant(
    port: &'static str,
    clause: &'static str,
    run: impl Fn() -> Result<(), Violation> + 'static,
) -> Mutant {
    Mutant {
        port,
        clause,
        operation: "",
        run: Box::new(run),
    }
}

fn silent_mutant(
    port: &'static str,
    operation: &'static str,
    run: impl Fn() -> Result<(), Violation> + 'static,
) -> Mutant {
    Mutant {
        port,
        clause: "silent-failure-detail",
        operation,
        run: Box::new(run),
    }
}

/// The mutant table, in a fixed order.
pub fn mutants() -> Vec<Mutant> {
    let store = |clause, bug| {
        mutant("EventStore", clause, move || {
            contract::event_store::run(store_mutant(bug))
        })
    };
    let evidence = |clause, bug| mutant("Evidence", clause, move || evidence_suite(bug));
    let mut all = vec![
        store("create-then-load", StoreBug::LazyCreate),
        store("append-order", StoreBug::Reversed),
        store("duplicates-kept", StoreBug::DropsDuplicates),
        store("runs-isolated", StoreBug::SharedLog),
        store("unknown-run", StoreBug::UnknownIsEmpty),
        store("create-twice", StoreBug::CreateTwiceOk),
        store("round-trip", StoreBug::StripsNul),
        store("hostile-run-ids", StoreBug::LastComponent),
        evidence("round-trip", EvidenceBug::Truncates),
        evidence("content-addressed", EvidenceBug::NoDedup),
        evidence("distinct-content", EvidenceBug::KeyedByLength),
        evidence("reference-from-content", EvidenceBug::CounterReferences),
        evidence("unknown-reference", EvidenceBug::UnknownIsEmpty),
        evidence("hostile-references", EvidenceBug::LastComponent),
        evidence("tampered-content-rejected", EvidenceBug::SkipsIntegrity),
        mutant("Clock", "non-decreasing", || {
            contract::clock::run(&BackwardsClock {
                inner: StepClock::new(5_000, 1),
                readings: Mutex::new(0),
            })
        }),
        mutant("Ids", "not-blank", || {
            contract::ids::run(&BlankOnceIds {
                inner: SequentialIds::new(),
                issued: Mutex::new(0),
            })
        }),
        mutant("Ids", "distinct", || {
            contract::ids::run(&SixteenBitIds {
                next: Mutex::new(0),
            })
        }),
        mutant("Verifier", "one-status-per-citation", || {
            let (answering, silent) = verifier_fixtures(VerifierBug::DropsStatus);
            contract::verifier::run(answering, silent)
        }),
        mutant("Forge", "distinct-references", || {
            contract::forge::run(
                || ForgeMutant(ForgeBug::SameReference, MemoryForge::new()),
                || SilentFailure {
                    adapter: ForgeMutant(ForgeBug::SameReference, silent_forge()),
                    status: String::from(STATUS),
                },
            )
        }),
    ];
    for &operation in contract::agent::OPERATIONS {
        all.push(silent_mutant("Agent", operation, move || {
            contract::agent::run(|| SilentFailure {
                adapter: StatusDroppingAgent(operation, silent_agent()),
                status: String::from(STATUS),
            })
        }));
    }
    for &operation in contract::verifier::OPERATIONS {
        all.push(silent_mutant("Verifier", operation, move || {
            let bug = VerifierBug::DropsFailureStatusOn(operation);
            let (answering, silent) = verifier_fixtures(bug);
            contract::verifier::run(answering, silent)
        }));
    }
    for &operation in contract::forge::OPERATIONS {
        all.push(silent_mutant("Forge", operation, move || {
            let bug = ForgeBug::DropsFailureStatusOn(operation);
            contract::forge::run(
                move || ForgeMutant(bug, MemoryForge::new()),
                move || SilentFailure {
                    adapter: ForgeMutant(bug, silent_forge()),
                    status: String::from(STATUS),
                },
            )
        }));
    }
    all
}

/// The violations of fixtures with a blank status, one per job-port
/// suite: the suite rejects the fixture instead of passing vacuously.
pub fn blank_status_violations() -> Vec<(&'static str, Result<(), Violation>)> {
    let blank = |status: &str| ScriptedFailure {
        status: String::from(status),
        ..silent()
    };
    let agent = contract::agent::run(|| SilentFailure {
        adapter: silent_agent(),
        status: String::new(),
    });
    let verifier = contract::verifier::run(
        || {
            let base = CommitSha::parse(BASE).expect("valid SHA");
            let citations = contract::verifier::sample(&base);
            let statuses = vec![CitationStatus::Verified; citations.len()];
            contract::verifier::Answering {
                adapter: MemoryVerifier::new(VerifierScript {
                    verify_citations: vec![Response::Answer(statuses)],
                    ..VerifierScript::default()
                }),
                base,
                citations,
            }
        },
        || SilentFailure {
            adapter: MemoryVerifier::new(VerifierScript {
                check_reproduction: vec![Response::Fail(blank("\u{200B}"))],
                ..VerifierScript::default()
            }),
            status: String::from("\u{200B}"),
        },
    );
    let forge = contract::forge::run(MemoryForge::new, || SilentFailure {
        adapter: MemoryForge::scripted(ForgeScript {
            post_questions: vec![Response::Fail(blank(" "))],
            open_pull_request: vec![Response::Fail(blank(" "))],
        }),
        status: String::from(" "),
    });
    vec![("Agent", agent), ("Verifier", verifier), ("Forge", forge)]
}

/// For each mutant: `mutant <port> <clause> <operation>` and the pretty
/// `Debug` of its suite's result; then the blank-status violations.
pub fn render_violations() -> String {
    let mut out = String::new();
    for m in mutants() {
        // Writing to a String cannot fail.
        let _ = write!(
            out,
            "mutant {} {} {}\n{:#?}\n",
            m.port,
            m.clause,
            m.operation,
            (m.run)()
        );
    }
    for (port, result) in blank_status_violations() {
        let _ = write!(out, "blank-status {port}\n{result:#?}\n");
    }
    out
}
