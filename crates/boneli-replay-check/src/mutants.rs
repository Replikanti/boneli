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
    Agent, CheckoutId, Clock, Command as SandboxCommand, DataError, DataSnapshot, DatabaseCopy,
    EventStore, Evidence, EvidenceError, ExecResult, ExitStatus, FixRequest, Forge, ForgeRef, Git,
    GitError, Ids, ImageError, ImageRef, ImageStore, JobFailure, Limits, Phase, PullRequest,
    RelativePath, RepoUrl, ReproductionRequest, RootCauseReport, RootCauseRequest, RootfsRef,
    RunLog, RunStart, Sandbox, SandboxError, SandboxId, SandboxSpec, SnapshotId, SnapshotSource,
    StoreError, TriageReport, TriageRequest, Verifier, Written,
};
use boneli_domain::{
    Budget, Citation, CitationStatus, CommitSha, EvidenceRef, FixChecks, RunEvent, RunId,
    TestStatus, Ticket,
};
use boneli_memory::{
    AgentScript, ForgeScript, GitCommit, MemoryAgent, MemoryDataSnapshot, MemoryEventStore,
    MemoryEvidence, MemoryForge, MemoryGit, MemoryImageStore, MemorySandbox, MemoryVerifier,
    Program, Response, ScriptedFailure, SequentialIds, StepClock, Tree, VerifierScript, pack_tree,
    unpack_tree,
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

// ------------------------------------------------------------------ Sandbox

/// Which `Sandbox` clause the mutant breaks.
#[derive(Clone, Copy, Debug)]
enum SandboxBug {
    /// Every `create` returns the first handle it issued.
    SameId,
    /// `copy_out` drops the last byte.
    Truncates,
    /// A file never written reads as empty.
    MissingIsEmpty,
    /// `copy_out` falls back to the other sandboxes' workspaces.
    SharedWorkspace,
    /// Every command reports `Code(0)`.
    ReportsSuccess,
    /// `destroy` does nothing.
    DestroyIgnored,
}

struct SandboxMutant {
    bug: SandboxBug,
    inner: MemorySandbox,
    issued: Mutex<Vec<SandboxId>>,
}

impl Sandbox for SandboxMutant {
    fn create(&self, spec: &SandboxSpec) -> Result<SandboxId, SandboxError> {
        let id = self.inner.create(spec)?;
        let mut issued = self.issued.lock().expect("not poisoned");
        issued.push(id.clone());
        match self.bug {
            SandboxBug::SameId => Ok(issued[0].clone()),
            _ => Ok(id),
        }
    }

    fn exec(
        &self,
        id: &SandboxId,
        command: &SandboxCommand,
        limits: &Limits,
    ) -> Result<ExecResult, SandboxError> {
        let mut result = self.inner.exec(id, command, limits)?;
        if matches!(self.bug, SandboxBug::ReportsSuccess) {
            result.status = ExitStatus::Code(0);
        }
        Ok(result)
    }

    fn copy_out(&self, id: &SandboxId, path: &RelativePath) -> Result<Vec<u8>, SandboxError> {
        let got = self.inner.copy_out(id, path);
        match (self.bug, got) {
            (SandboxBug::Truncates, Ok(mut content)) => {
                content.pop();
                Ok(content)
            }
            (SandboxBug::MissingIsEmpty, Err(SandboxError::NotFound)) => Ok(Vec::new()),
            (SandboxBug::SharedWorkspace, Err(SandboxError::NotFound)) => {
                let issued = self.issued.lock().expect("not poisoned").clone();
                issued
                    .iter()
                    .find_map(|other| self.inner.copy_out(other, path).ok())
                    .ok_or(SandboxError::NotFound)
            }
            (_, got) => got,
        }
    }

    fn destroy(&self, id: &SandboxId) -> Result<(), SandboxError> {
        match self.bug {
            SandboxBug::DestroyIgnored => Ok(()),
            _ => self.inner.destroy(id),
        }
    }
}

/// Pools workspaces: a destroyed sandbox's workspace goes, unwiped, to the
/// next `create` under a fresh handle.
struct PooledSandbox {
    inner: MemorySandbox,
    issued: Mutex<u64>,
    /// Handed-out handles and the inner sandboxes behind them.
    live: Mutex<Vec<(SandboxId, SandboxId)>>,
    pool: Mutex<Vec<SandboxId>>,
}

impl PooledSandbox {
    fn inner_of(&self, id: &SandboxId) -> Result<SandboxId, SandboxError> {
        let live = self.live.lock().expect("not poisoned");
        live.iter()
            .find(|(outer, _)| outer == id)
            .map(|(_, inner)| inner.clone())
            .ok_or(SandboxError::UnknownSandbox)
    }
}

impl Sandbox for PooledSandbox {
    fn create(&self, spec: &SandboxSpec) -> Result<SandboxId, SandboxError> {
        let pooled = self.pool.lock().expect("not poisoned").pop();
        let inner = match pooled {
            Some(inner) => inner,
            None => self.inner.create(spec)?,
        };
        let mut issued = self.issued.lock().expect("not poisoned");
        *issued += 1;
        let outer = SandboxId::new(format!("pooled-{issued}"));
        let mut live = self.live.lock().expect("not poisoned");
        live.push((outer.clone(), inner));
        Ok(outer)
    }

    fn exec(
        &self,
        id: &SandboxId,
        command: &SandboxCommand,
        limits: &Limits,
    ) -> Result<ExecResult, SandboxError> {
        self.inner.exec(&self.inner_of(id)?, command, limits)
    }

    fn copy_out(&self, id: &SandboxId, path: &RelativePath) -> Result<Vec<u8>, SandboxError> {
        self.inner.copy_out(&self.inner_of(id)?, path)
    }

    fn destroy(&self, id: &SandboxId) -> Result<(), SandboxError> {
        let inner = self.inner_of(id)?;
        self.live
            .lock()
            .expect("not poisoned")
            .retain(|(outer, _)| outer != id);
        self.pool.lock().expect("not poisoned").push(inner);
        Ok(())
    }
}

fn sandbox_command(program: &str) -> SandboxCommand {
    SandboxCommand {
        program: String::from(program),
        args: vec![],
        environment: vec![],
    }
}

fn path(text: &str) -> RelativePath {
    RelativePath::parse(text).expect("a valid path")
}

/// The sandbox fixture around `adapter`, built from the scripted programs.
fn sandbox_fixture<S>(make: impl FnOnce(MemorySandbox) -> S) -> contract::sandbox::Workspace<S> {
    let done = |code| ExecResult {
        status: ExitStatus::Code(code),
        stdout: vec![],
        stderr: vec![],
    };
    let inner = MemorySandbox::new(vec![
        Program {
            name: String::from("write"),
            result: done(0),
            writes: vec![(path("out/result.txt"), b"written".to_vec())],
        },
        Program {
            name: String::from("exit-3"),
            result: done(3),
            writes: vec![],
        },
    ]);
    contract::sandbox::Workspace {
        adapter: make(inner),
        spec: SandboxSpec {
            phase: Phase::Verify,
            rootfs: RootfsRef::new(String::from("rootfs-1")),
        },
        limits: Limits {
            wall_ms: 1_000,
            memory_bytes: 1 << 20,
            processes: 1,
        },
        write: sandbox_command("write"),
        path: path("out/result.txt"),
        content: b"written".to_vec(),
        exit: sandbox_command("exit-3"),
        status: ExitStatus::Code(3),
    }
}

fn sandbox_workspace(bug: SandboxBug) -> contract::sandbox::Workspace<SandboxMutant> {
    sandbox_fixture(|inner| SandboxMutant {
        bug,
        inner,
        issued: Mutex::new(Vec::new()),
    })
}

fn pooled_workspace() -> contract::sandbox::Workspace<PooledSandbox> {
    sandbox_fixture(|inner| PooledSandbox {
        inner,
        issued: Mutex::new(0),
        live: Mutex::new(Vec::new()),
        pool: Mutex::new(Vec::new()),
    })
}

// ---------------------------------------------------------------------- Git

/// Which `Git` clause the mutant breaks.
#[derive(Clone, Copy, Debug)]
enum GitBug {
    /// `read` drops the last byte.
    Truncates,
    /// A missing file reads as empty.
    MissingIsEmpty,
    /// An unknown commit checks out anyway.
    UnknownIsOk,
    /// `apply` ignores the diff.
    IgnoresDiff,
    /// `apply` changes the checkout it was given, as a working tree would.
    InPlace,
    /// Every diff starts with a header, even an empty one.
    Header,
    /// `apply` writes into a per-commit cache, so a later `fetch_base` of
    /// the same base returns the applied tree.
    PoisonsBase,
    /// `diff` drops files the base does not have, as `git diff` does for
    /// untracked files.
    DropsNewFiles,
    /// `diff` drops removed files.
    DropsRemovals,
    /// A diff that does not apply is ignored instead of refused: `apply`
    /// returns the checkout it was given.
    ToleratesMismatch,
}

const HEADER: &[u8] = b"diff\n";

struct GitMutant {
    bug: GitBug,
    inner: MemoryGit,
    /// Checkouts that now read as another one (`InPlace`).
    moved: Mutex<Vec<(CheckoutId, CheckoutId)>>,
    /// The last diff applied (`PoisonsBase`).
    last_diff: Mutex<Option<Vec<u8>>>,
}

impl GitMutant {
    fn resolve(&self, checkout: &CheckoutId) -> CheckoutId {
        let moved = self.moved.lock().expect("not poisoned");
        moved
            .iter()
            .rev()
            .find(|(from, _)| from == checkout)
            .map_or_else(|| checkout.clone(), |(_, to)| to.clone())
    }
}

impl Git for GitMutant {
    fn fetch_base(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError> {
        if let GitBug::PoisonsBase = self.bug {
            let fetched = self.inner.fetch_base(repo, base)?;
            let last = self.last_diff.lock().expect("not poisoned").clone();
            return match last {
                Some(diff) => self.inner.apply(&fetched, &diff),
                None => Ok(fetched),
            };
        }
        match (self.bug, self.inner.fetch_base(repo, base)) {
            (GitBug::UnknownIsOk, Err(GitError::UnknownCommit)) => {
                Ok(CheckoutId::new(String::from("checkout-0")))
            }
            (_, got) => got,
        }
    }

    fn read(
        &self,
        checkout: &CheckoutId,
        path: &RelativePath,
    ) -> Result<Option<Vec<u8>>, GitError> {
        let got = self.inner.read(&self.resolve(checkout), path)?;
        Ok(match (self.bug, got) {
            (GitBug::Truncates, Some(mut content)) => {
                content.pop();
                Some(content)
            }
            (GitBug::MissingIsEmpty, None) => Some(Vec::new()),
            (_, got) => got,
        })
    }

    fn snapshot(&self, checkout: &CheckoutId) -> Result<Vec<u8>, GitError> {
        self.inner.snapshot(&self.resolve(checkout))
    }

    fn diff(&self, checkout: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError> {
        let from = self.resolve(checkout);
        let base = unpack_tree(&self.inner.snapshot(&from)?).unwrap_or_default();
        let mut tree = unpack_tree(workspace).unwrap_or_default();
        match self.bug {
            GitBug::DropsNewFiles => tree.retain(|path, _| base.contains_key(path)),
            GitBug::DropsRemovals => {
                for (path, content) in base {
                    tree.entry(path).or_insert(content);
                }
            }
            _ => {}
        }
        let diff = match self.bug {
            GitBug::DropsNewFiles | GitBug::DropsRemovals => {
                self.inner.diff(&from, &pack_tree(&tree))?
            }
            _ => self.inner.diff(&from, workspace)?,
        };
        Ok(match self.bug {
            GitBug::Header => [HEADER, &diff].concat(),
            _ => diff,
        })
    }

    fn apply(&self, checkout: &CheckoutId, diff: &[u8]) -> Result<CheckoutId, GitError> {
        *self.last_diff.lock().expect("not poisoned") = Some(diff.to_vec());
        let from = self.resolve(checkout);
        match self.bug {
            GitBug::IgnoresDiff => self.inner.apply(&from, &[]),
            GitBug::Header => self
                .inner
                .apply(&from, diff.strip_prefix(HEADER).unwrap_or(diff)),
            GitBug::ToleratesMismatch => match self.inner.apply(&from, diff) {
                Err(GitError::Failed { .. }) => Ok(checkout.clone()),
                other => other,
            },
            GitBug::InPlace => {
                let applied = self.inner.apply(&from, diff)?;
                let mut moved = self.moved.lock().expect("not poisoned");
                moved.push((checkout.clone(), applied));
                Ok(checkout.clone())
            }
            _ => self.inner.apply(&from, diff),
        }
    }
}

const OTHER: &str = "89abcdef0123456789abcdef0123456789abcdef";

fn git_repository(bug: GitBug) -> contract::git::Repository<GitMutant> {
    let repo = RepoUrl::new(String::from("https://example.invalid/app.git"));
    let base = CommitSha::parse(BASE).expect("valid SHA");
    let files: Tree = [(path("src/lib.rs"), b"fn total() {}\n".to_vec())]
        .into_iter()
        .collect();
    let inner = MemoryGit::new(vec![GitCommit {
        repo: repo.clone(),
        sha: base.clone(),
        files,
    }]);
    contract::git::Repository {
        adapter: GitMutant {
            bug,
            inner,
            moved: Mutex::new(Vec::new()),
            last_diff: Mutex::new(None),
        },
        repo,
        base,
        path: path("src/lib.rs"),
        content: b"fn total() {}\n".to_vec(),
        missing: path("src/missing.rs"),
        unknown: CommitSha::parse(OTHER).expect("valid SHA"),
        edited: b"fn total() { 1 }\n".to_vec(),
    }
}

fn git_edit(workspace: &[u8], file: &RelativePath, content: Option<&[u8]>) -> Vec<u8> {
    let mut tree = unpack_tree(workspace).unwrap_or_default();
    match content {
        Some(content) => tree.insert(file.clone(), content.to_vec()),
        None => tree.remove(file),
    };
    pack_tree(&tree)
}

// --------------------------------------------------------------- ImageStore

/// Which `ImageStore` clause the mutant breaks.
#[derive(Clone, Copy, Debug)]
enum ImageBug {
    /// Every pull unpacks again under a new handle.
    NewRootfsPerPull,
    /// A missing image pulls as an empty root filesystem.
    MissingIsEmpty,
    /// Images resolve by name alone; digest and platform are ignored.
    ByName,
    /// Images resolve by name and digest; the platform is ignored.
    IgnoresPlatform,
}

struct ImageMutant {
    bug: ImageBug,
    inner: MemoryImageStore,
    pulls: Mutex<u64>,
    /// The images the inner store has.
    known: Vec<ImageRef>,
}

impl ImageStore for ImageMutant {
    fn pull(&self, image: &ImageRef) -> Result<RootfsRef, ImageError> {
        let resolved = self.known.iter().find(|k| match self.bug {
            ImageBug::ByName => k.name == image.name,
            ImageBug::IgnoresPlatform => k.name == image.name && k.digest == image.digest,
            _ => *k == image,
        });
        let image = resolved.unwrap_or(image);
        match (self.bug, self.inner.pull(image)) {
            (ImageBug::NewRootfsPerPull, Ok(rootfs)) => {
                let mut pulls = self.pulls.lock().expect("not poisoned");
                *pulls += 1;
                Ok(RootfsRef::new(format!("{}-{pulls}", rootfs.as_str())))
            }
            (ImageBug::MissingIsEmpty, Err(ImageError::NotFound)) => {
                Ok(RootfsRef::new(String::from("rootfs-empty")))
            }
            (_, got) => got,
        }
    }
}

fn image_ref(name: &str, digest: &str, platform: &str) -> ImageRef {
    ImageRef {
        name: String::from(name),
        digest: String::from(digest),
        platform: String::from(platform),
    }
}

fn images(bug: ImageBug) -> contract::image::Images<ImageMutant> {
    let present = image_ref("library/postgres", "sha256:aa", "linux/amd64");
    contract::image::Images {
        adapter: ImageMutant {
            bug,
            inner: MemoryImageStore::new(vec![present.clone()]),
            pulls: Mutex::new(0),
            known: vec![present.clone()],
        },
        present,
        missing: image_ref("library/node", "sha256:aa", "linux/amd64"),
        other_digest: image_ref("library/postgres", "sha256:bb", "linux/amd64"),
        other_platform: image_ref("library/postgres", "sha256:aa", "linux/arm64"),
    }
}

// ------------------------------------------------------------- DataSnapshot

/// Which `DataSnapshot` clause the mutant breaks.
#[derive(Clone, Copy, Debug)]
enum DataBug {
    /// Every run of a snapshot gets the same copy.
    SameCopy,
    /// Every copy shares the data of the first one.
    SharedData,
    /// `remove_copy` does nothing.
    RemoveIgnored,
    /// A copy is named after the run id's last `/` component, so `../x`
    /// gets the copy of run `x`.
    LastComponent,
}

struct DataMutant {
    bug: DataBug,
    inner: MemoryDataSnapshot,
    first: Mutex<Option<DatabaseCopy>>,
    /// Copies by the last component of their run id (`LastComponent`).
    named: Mutex<Vec<(String, DatabaseCopy)>>,
}

impl DataMutant {
    /// The copy whose data a handle reaches.
    fn data_of(&self, copy: &DatabaseCopy) -> DatabaseCopy {
        match self.bug {
            DataBug::SharedData => self
                .first
                .lock()
                .expect("not poisoned")
                .clone()
                .unwrap_or_else(|| copy.clone()),
            _ => copy.clone(),
        }
    }
}

impl DataSnapshot for DataMutant {
    fn load(&self, sandbox: &SandboxId, source: &SnapshotSource) -> Result<SnapshotId, DataError> {
        self.inner.load(sandbox, source)
    }

    fn copy(&self, snapshot: &SnapshotId, run: &RunId) -> Result<DatabaseCopy, DataError> {
        if let DataBug::LastComponent = self.bug {
            let last = run
                .as_str()
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_owned();
            let mut named = self.named.lock().expect("not poisoned");
            if let Some((_, copy)) = named.iter().find(|(name, _)| *name == last) {
                return Ok(copy.clone());
            }
            let copy = self.inner.copy(snapshot, run)?;
            named.push((last, copy.clone()));
            return Ok(copy);
        }
        let copy = self.inner.copy(snapshot, run)?;
        let mut first = self.first.lock().expect("not poisoned");
        let first = first.get_or_insert_with(|| copy.clone()).clone();
        match self.bug {
            DataBug::SameCopy => Ok(first),
            _ => Ok(copy),
        }
    }

    fn remove_copy(&self, copy: &DatabaseCopy) -> Result<(), DataError> {
        match self.bug {
            DataBug::RemoveIgnored => Ok(()),
            _ => self.inner.remove_copy(copy),
        }
    }
}

/// Inserts a row and looks for it, through the handle's data.
struct RowProbe;

impl contract::data::Probe<DataMutant> for RowProbe {
    fn change(&self, adapter: &DataMutant, copy: &DatabaseCopy) -> Result<(), String> {
        let data = adapter.data_of(copy);
        adapter
            .inner
            .insert(&data, "changed")
            .map_err(|e| e.to_string())
    }

    fn changed(&self, adapter: &DataMutant, copy: &DatabaseCopy) -> Result<bool, String> {
        let data = adapter.data_of(copy);
        let rows = adapter.inner.rows(&data).map_err(|e| e.to_string())?;
        Ok(rows.iter().any(|row| row == "changed"))
    }
}

fn database(bug: DataBug) -> contract::data::Database<DataMutant> {
    let source = SnapshotSource::new(String::from("seed.sql"));
    contract::data::Database {
        adapter: DataMutant {
            bug,
            inner: MemoryDataSnapshot::new(vec![(source.clone(), vec![String::from("seed")])]),
            first: Mutex::new(None),
            named: Mutex::new(Vec::new()),
        },
        sandbox: SandboxId::new(String::from("sandbox-1")),
        source,
    }
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
    let sandbox = |clause, bug| {
        mutant("Sandbox", clause, move || {
            contract::sandbox::run(|| sandbox_workspace(bug))
        })
    };
    let git = |clause, bug| {
        mutant("Git", clause, move || {
            contract::git::run(|| git_repository(bug), git_edit)
        })
    };
    let image = |clause, bug| {
        mutant("ImageStore", clause, move || {
            contract::image::run(|| images(bug))
        })
    };
    let data = |clause, bug| {
        mutant("DataSnapshot", clause, move || {
            contract::data::run(|| database(bug), &RowProbe)
        })
    };
    all.extend([
        sandbox("distinct-ids", SandboxBug::SameId),
        sandbox("copy-out-after-write", SandboxBug::Truncates),
        sandbox("copy-out-missing", SandboxBug::MissingIsEmpty),
        sandbox("isolated", SandboxBug::SharedWorkspace),
        mutant("Sandbox", "fresh-after-destroy", || {
            contract::sandbox::run(pooled_workspace)
        }),
        sandbox("exit-status", SandboxBug::ReportsSuccess),
        sandbox("destroyed-is-unknown", SandboxBug::DestroyIgnored),
        git("read-at-base", GitBug::Truncates),
        git("read-missing", GitBug::MissingIsEmpty),
        git("unknown-commit", GitBug::UnknownIsOk),
        git("apply-then-read", GitBug::IgnoresDiff),
        git("apply-leaves-base", GitBug::InPlace),
        git("base-refetch-unchanged", GitBug::PoisonsBase),
        git("unchanged-snapshot-empty-diff", GitBug::Header),
        git("added-file", GitBug::DropsNewFiles),
        git("removed-file", GitBug::DropsRemovals),
        git("apply-mismatch-fails", GitBug::ToleratesMismatch),
        image("pull-idempotent", ImageBug::NewRootfsPerPull),
        image("missing-image", ImageBug::MissingIsEmpty),
        image("digest-pinned", ImageBug::ByName),
        image("platform-pinned", ImageBug::IgnoresPlatform),
        data("distinct-copies", DataBug::SameCopy),
        data("copies-independent", DataBug::SharedData),
        data("removed-copy-unknown", DataBug::RemoveIgnored),
        data("hostile-run-ids", DataBug::LastComponent),
    ]);
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
