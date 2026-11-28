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
    Agent, BranchName, Broker, BrokerName, CheckoutId, Clock, Command as SandboxCommand,
    CommitInfo, ContainerName, ContainerSpec, DataError, DataSnapshot, DatabaseCopy, EventStore,
    Evidence, EvidenceError, ExecResult, ExitStatus, FixRequest, Forge, ForgeRef, Git, GitError,
    Ids, ImageError, ImageExemption, ImageOrigin, ImageRef, ImageStore, JobFailure, LayerRef,
    Limits, Phase, PodLimits, PullRequest, Pulled, RelativePath, RepoUrl, ReproductionRequest,
    RootCauseReport, RootCauseRequest, RootfsRef, RunLog, RunStart, Sandbox, SandboxError,
    SandboxId, SandboxSpec, SnapshotId, SnapshotSource, StoreError, TreePath, TriageReport,
    TriageRequest, Verifier, WorkspaceBytes, Written,
};
use boneli_domain::{
    Budget, Change, Citation, CitationStatus, CommitSha, Entry, EntryKind, EvidenceRef, FixChecks,
    Patch, RunEvent, RunId, TestStatus, Ticket, UnreadablePath,
};
use boneli_memory::{
    AgentScript, ForgeScript, GitCommit, MemoryAgent, MemoryDataSnapshot, MemoryEventStore,
    MemoryEvidence, MemoryForge, MemoryGit, MemoryImageStore, MemorySandbox, MemoryVerifier,
    Program, Response, ScriptedFailure, SequentialIds, StepClock, Tree, VerifierScript, WORKSPACE,
    Write, pack_tree, tree_patch, unpack_tree,
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
                let mut first = Mutex::lock(&self.first).expect("not poisoned");
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
        let on_disk = Mutex::lock(&self.on_disk).expect("not poisoned");
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
    Mutex::lock(&store.on_disk)
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
                let mut puts = Mutex::lock(&self.puts).expect("not poisoned");
                *puts += 1;
                let mut salted = puts.to_be_bytes().to_vec();
                salted.extend_from_slice(content);
                self.inner.put(&salted)
            }
            EvidenceBug::KeyedByLength => {
                let mut seen = Mutex::lock(&self.by_length).expect("not poisoned");
                if let Some((_, reference)) = seen.iter().find(|(len, _)| *len == content.len()) {
                    return Ok(reference.clone());
                }
                let reference = self.inner.put(content)?;
                seen.push((content.len(), reference.clone()));
                Ok(reference)
            }
            EvidenceBug::CounterReferences => {
                let inner = self.inner.put(content)?;
                let mut aliases = Mutex::lock(&self.aliases).expect("not poisoned");
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
                let aliases = Mutex::lock(&self.aliases).expect("not poisoned");
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
        let mut readings = Mutex::lock(&self.readings).expect("not poisoned");
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
        let mut issued = Mutex::lock(&self.issued).expect("not poisoned");
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
        let mut next = Mutex::lock(&self.next).expect("not poisoned");
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// A command in a container the pod does not have runs in the first.
    IgnoresContainer,
    /// `create` replaces the pod limits with generous ones, as an adapter
    /// that never calls `PodLimits::check` would run them.
    UncheckedLimits,
    /// `export` returns an empty workspace.
    ExportEmpty,
    /// `export` returns the workspace the sandbox was created from.
    ExportStale,
    /// `copy_out` follows a symlink at the path or at a parent.
    FollowsLinks,
    /// A verify spec with brokers is created as an agent sandbox.
    VerifyKeepsBrokers,
    /// Every sandbox is created as a prepare sandbox, after the core check
    /// of its own phase, so any of them can be sealed.
    SealsAnyPhase,
    /// `create` drops the dependencies.
    DependencyNotMounted,
    /// Every `seal` returns the first layer handle it issued.
    ReusesLayer,
    /// `release` reports success and keeps the layer.
    ReleaseIgnored,
    /// `release` of a layer a live sandbox mounts reports success.
    ReleasesInUse,
}

/// Limits with room for anything the suite builds.
fn generous() -> PodLimits {
    PodLimits {
        memory_bytes: 1 << 40,
        processes: 1 << 20,
        cpu_millis: 1_000,
        workspace_bytes: 1 << 30,
        workspace_inodes: 1 << 30,
        tmp_bytes: 1 << 30,
        shm_bytes: 1 << 30,
    }
}

struct SandboxMutant {
    bug: SandboxBug,
    inner: MemorySandbox,
    issued: Mutex<Vec<SandboxId>>,
    /// The spec of every live handle, as given.
    specs: Mutex<Vec<(SandboxId, SandboxSpec)>>,
    layers: Mutex<Vec<LayerRef>>,
}

impl SandboxMutant {
    fn spec_of(&self, id: &SandboxId) -> Option<SandboxSpec> {
        let specs = Mutex::lock(&self.specs).expect("not poisoned");
        specs.iter().find(|(i, _)| i == id).map(|(_, s)| s.clone())
    }

    /// `path` read through the symlinks the inner sandbox holds, as an
    /// adapter that opens it with symlinks followed would.
    fn follow(&self, id: &SandboxId, path: &RelativePath) -> Option<Vec<u8>> {
        let components: Vec<&str> = path.as_str().split('/').collect();
        for k in 1..=components.len() {
            let prefix = components[..k].join("/");
            if let Some(Write::Symlink(target)) =
                self.inner.entry(id, &format!("{WORKSPACE}/{prefix}"))
            {
                let target = String::from_utf8(target).ok()?;
                let rest = components[k..].join("/");
                let resolved = if rest.is_empty() {
                    target
                } else {
                    format!("{target}/{rest}")
                };
                return match self.inner.entry(id, &resolved) {
                    Some(Write::File(content)) => Some(content),
                    _ => None,
                };
            }
        }
        None
    }
}

impl Sandbox for SandboxMutant {
    fn create(&self, spec: &SandboxSpec) -> Result<SandboxId, SandboxError> {
        let mut given = spec.clone();
        match self.bug {
            SandboxBug::UncheckedLimits => given.limits = generous(),
            SandboxBug::VerifyKeepsBrokers
                if spec.phase == Phase::Verify && !spec.brokers.is_empty() =>
            {
                given.phase = Phase::Agent;
            }
            SandboxBug::SealsAnyPhase => {
                spec.check().map_err(|problem| SandboxError::Failed {
                    detail: format!("{problem}"),
                })?;
                given.phase = Phase::Prepare;
            }
            SandboxBug::DependencyNotMounted => given.dependencies.clear(),
            _ => {}
        }
        let id = self.inner.create(&given)?;
        Mutex::lock(&self.specs)
            .expect("not poisoned")
            .push((id.clone(), spec.clone()));
        let mut issued = Mutex::lock(&self.issued).expect("not poisoned");
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
        let mut command = command.clone();
        if self.bug == SandboxBug::IgnoresContainer
            && let Some(spec) = self.spec_of(id)
            && spec.containers.iter().all(|c| c.name != command.container)
        {
            command.container = spec.containers[0].name.clone();
        }
        let mut result = self.inner.exec(id, &command, limits)?;
        if matches!(self.bug, SandboxBug::ReportsSuccess) {
            result.status = ExitStatus::Code(0);
        }
        Ok(result)
    }

    fn start(&self, id: &SandboxId, command: &SandboxCommand) -> Result<(), SandboxError> {
        self.inner.start(id, command)
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
                let issued = Mutex::lock(&self.issued).expect("not poisoned").clone();
                issued
                    .iter()
                    .find_map(|other| self.inner.copy_out(other, path).ok())
                    .ok_or(SandboxError::NotFound)
            }
            (SandboxBug::FollowsLinks, Err(error)) => self.follow(id, path).ok_or(error),
            (_, got) => got,
        }
    }

    fn export(&self, id: &SandboxId) -> Result<Vec<u8>, SandboxError> {
        let got = self.inner.export(id)?;
        match self.bug {
            SandboxBug::ExportEmpty => Ok(Vec::new()),
            SandboxBug::ExportStale => Ok(self
                .spec_of(id)
                .map(|s| s.workspace.as_bytes().to_vec())
                .unwrap_or_default()),
            _ => Ok(got),
        }
    }

    fn seal(&self, id: &SandboxId, paths: &[RelativePath]) -> Result<LayerRef, SandboxError> {
        let layer = self.inner.seal(id, paths)?;
        let mut layers = Mutex::lock(&self.layers).expect("not poisoned");
        layers.push(layer.clone());
        match self.bug {
            SandboxBug::ReusesLayer => Ok(layers[0].clone()),
            _ => Ok(layer),
        }
    }

    fn release(&self, layer: &LayerRef) -> Result<(), SandboxError> {
        match self.bug {
            SandboxBug::ReleaseIgnored => Ok(()),
            SandboxBug::ReleasesInUse => {
                let in_use = Mutex::lock(&self.specs)
                    .expect("not poisoned")
                    .iter()
                    .any(|(_, spec)| spec.dependencies.contains(layer));
                if in_use {
                    Ok(())
                } else {
                    self.inner.release(layer)
                }
            }
            _ => self.inner.release(layer),
        }
    }

    fn destroy(&self, id: &SandboxId) -> Result<(), SandboxError> {
        match self.bug {
            SandboxBug::DestroyIgnored => Ok(()),
            _ => {
                self.inner.destroy(id)?;
                Mutex::lock(&self.specs)
                    .expect("not poisoned")
                    .retain(|(i, _)| i != id);
                Ok(())
            }
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
        let live = Mutex::lock(&self.live).expect("not poisoned");
        live.iter()
            .find(|(outer, _)| outer == id)
            .map(|(_, inner)| inner.clone())
            .ok_or(SandboxError::UnknownSandbox)
    }
}

impl Sandbox for PooledSandbox {
    fn create(&self, spec: &SandboxSpec) -> Result<SandboxId, SandboxError> {
        let pooled = Mutex::lock(&self.pool).expect("not poisoned").pop();
        let inner = match pooled {
            Some(inner) => inner,
            None => self.inner.create(spec)?,
        };
        let mut issued = Mutex::lock(&self.issued).expect("not poisoned");
        *issued += 1;
        let outer = SandboxId::new(format!("pooled-{issued}"));
        let mut live = Mutex::lock(&self.live).expect("not poisoned");
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

    fn start(&self, id: &SandboxId, command: &SandboxCommand) -> Result<(), SandboxError> {
        self.inner.start(&self.inner_of(id)?, command)
    }

    fn copy_out(&self, id: &SandboxId, path: &RelativePath) -> Result<Vec<u8>, SandboxError> {
        self.inner.copy_out(&self.inner_of(id)?, path)
    }

    fn export(&self, id: &SandboxId) -> Result<Vec<u8>, SandboxError> {
        self.inner.export(&self.inner_of(id)?)
    }

    fn seal(&self, id: &SandboxId, paths: &[RelativePath]) -> Result<LayerRef, SandboxError> {
        self.inner.seal(&self.inner_of(id)?, paths)
    }

    fn release(&self, layer: &LayerRef) -> Result<(), SandboxError> {
        self.inner.release(layer)
    }

    fn destroy(&self, id: &SandboxId) -> Result<(), SandboxError> {
        let inner = self.inner_of(id)?;
        Mutex::lock(&self.live)
            .expect("not poisoned")
            .retain(|(outer, _)| outer != id);
        Mutex::lock(&self.pool).expect("not poisoned").push(inner);
        Ok(())
    }
}

fn app() -> ContainerName {
    ContainerName::parse("app").expect("a valid name")
}

fn sandbox_command(program: &str) -> SandboxCommand {
    SandboxCommand {
        container: app(),
        program: String::from(program),
        args: vec![],
        environment: vec![],
    }
}

fn path(text: &str) -> RelativePath {
    RelativePath::parse(text).expect("a valid path")
}

fn tpath(bytes: &[u8]) -> TreePath {
    TreePath::parse(bytes).expect("a valid tree path")
}

/// A scripted program that ends with `code` and changes nothing.
fn sandbox_program(name: &str, code: i32) -> Program {
    Program {
        name: String::from(name),
        result: ExecResult {
            status: ExitStatus::Code(code),
            stdout: vec![],
            stderr: vec![],
        },
        writes: vec![],
        outside: vec![],
        copies: vec![],
    }
}

/// The sandbox fixture around `adapter`, built from the scripted programs:
/// the ones of `boneli-memory`'s own contract test.
fn sandbox_fixture<S>(make: impl FnOnce(MemorySandbox) -> S) -> contract::sandbox::Workspace<S> {
    let inner = MemorySandbox::new(vec![
        Program {
            writes: vec![(path("out/result.txt"), Write::File(b"written".to_vec()))],
            ..sandbox_program("write", 0)
        },
        sandbox_program("exit-3", 3),
        Program {
            outside: vec![(String::from("/tmp/planted/result.txt"), b"outside".to_vec())],
            ..sandbox_program("plant", 0)
        },
        Program {
            writes: vec![(
                path("out/result.txt"),
                Write::Symlink(b"/tmp/planted/result.txt".to_vec()),
            )],
            ..sandbox_program("link", 0)
        },
        Program {
            writes: vec![(path("out"), Write::Symlink(b"/tmp/planted".to_vec()))],
            ..sandbox_program("through", 0)
        },
        Program {
            copies: vec![(format!("{WORKSPACE}/out/result.txt"), path("copied.txt"))],
            ..sandbox_program("read", 0)
        },
    ]);
    contract::sandbox::Workspace {
        adapter: make(inner),
        spec: SandboxSpec {
            phase: Phase::Verify,
            containers: vec![ContainerSpec {
                name: app(),
                rootfs: RootfsRef::new(String::from("rootfs-1")),
            }],
            workspace: WorkspaceBytes::new(vec![]),
            dependencies: vec![],
            brokers: vec![],
            limits: PodLimits {
                memory_bytes: 1 << 30,
                processes: 16,
                cpu_millis: 1_000,
                workspace_bytes: 1 << 20,
                workspace_inodes: 1_000,
                tmp_bytes: 1 << 20,
                shm_bytes: 1 << 20,
            },
            user: 1000,
        },
        limits: Limits {
            wall_ms: 1_000,
            output_bytes: 1 << 20,
        },
        write: sandbox_command("write"),
        path: path("out/result.txt"),
        content: b"written".to_vec(),
        exit: sandbox_command("exit-3"),
        status: ExitStatus::Code(3),
        container: ContainerSpec {
            name: ContainerName::parse("db").expect("a valid name"),
            rootfs: RootfsRef::new(String::from("rootfs-2")),
        },
        plant: sandbox_command("plant"),
        outside: b"outside".to_vec(),
        link: sandbox_command("link"),
        through: sandbox_command("through"),
        broker: Broker {
            name: BrokerName::parse("sql").expect("a valid name"),
            socket: String::from("/run/brokers/sql.sock"),
        },
        dependency: path("out"),
        read: sandbox_command("read"),
        copied: path("copied.txt"),
    }
}

fn sandbox_workspace(bug: SandboxBug) -> contract::sandbox::Workspace<SandboxMutant> {
    sandbox_fixture(|inner| SandboxMutant {
        bug,
        inner,
        issued: Mutex::new(Vec::new()),
        specs: Mutex::new(Vec::new()),
        layers: Mutex::new(Vec::new()),
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
    /// A correct diff that runs a hook it finds in the workspace, as a git
    /// that discovers the workspace's `.git` would (#30).
    RunsMetadata,
    /// `diff` encodes repository metadata as content.
    MetadataIsContent,
    /// After a diff that saw repository metadata, every later diff starts
    /// with a header, as a store that adopted the workspace's config would.
    AdoptsMetadata,
    /// Adoption into the store of the checkout whose diff saw metadata:
    /// later diffs of that checkout start with a header (review of #61).
    AdoptsPerCheckout,
    /// Adoption that shows only in a non-empty diff, as a planted
    /// `diff.noprefix` would (review of #61).
    AdoptsOnChanges,
    /// A hook that runs only when the same checkout is diffed again
    /// (review of #61).
    RunsOnRediff,
    /// Adoption into what new checkouts start from, as a shared template
    /// or global config would: diffs of checkouts fetched after a diff saw
    /// metadata start with a header.
    AdoptsIntoNewCheckouts,
    /// After a diff that saw metadata, `apply` also writes a file, as an
    /// adopted hook would.
    AdoptsOnApply,
    /// `apply` accepts a diff that writes repository metadata, leaving the
    /// tree as it was instead of refusing it.
    AppliesMetadata,
    /// `apply` refuses a diff that writes repository metadata, but only
    /// after writing into the checkout it was given.
    WritesThenRefuses,
    /// `diff` drops only the top-level `.git` and encodes nested
    /// repository metadata as content (review round 2 of #61).
    NestedIsContent,
    /// `push` commits the base's tree instead of the checkout's, as an
    /// adapter that commits the store's base would.
    PushesBase,
    /// `push` creates a commit with no parent, as `commit-tree` without
    /// `-p` would.
    PushesOrphan,
    /// `push` to an existing branch moves it to the new commit, as a
    /// forced push would.
    Overwrites,
    /// `push` from an unknown checkout is `Failed`.
    UnknownCheckoutFails,
    /// `snapshot` leaves out the paths the citation rule refuses, and
    /// `diff` keeps the base's file where the workspace has none there:
    /// the design that drops such files (ADR-018, alternatives).
    HidesUncitable,
    /// `diff` keeps the base's content of an uncitable path the workspace
    /// changed.
    IgnoresUncitableEdits,
    /// `diff` keeps an uncitable path the workspace removed.
    KeepsUncitableRemovals,
    /// `diff` drops an uncitable path the base does not have.
    DropsNewUncitable,
    /// `snapshot` refuses a tree with an uncitable path, as `GitCli` did
    /// before ADR-018.
    RefusesUncitableSnapshot,
    /// `apply` refuses a result with an uncitable path, as `GitCli` did
    /// before ADR-018.
    RefusesUncitableTrees,
    /// `snapshot` renders a path that is not UTF-8 through U+FFFD, and
    /// `diff` reads the rendered name back as the base's.
    LossyUncitable,
    /// `patch_between` reports a change with equal sides when the trees
    /// are equal, which the policy would refuse as malformed.
    PatchSpurious,
    /// `patch_between` drops every before side, so an edit looks like an
    /// add and the base's test declarations are hidden.
    PatchDropsBefore,
    /// `patch_between` leaves out changes with no after side, which hides
    /// a deleted test file.
    PatchDropsRemovals,
    /// `patch_between` of an unknown handle is an empty patch.
    PatchUnknownEmpty,
    /// `patch_between` leaves out a change at a path the citation rule
    /// refuses.
    PatchDropsUncitable,
    /// `patch_between` renders paths through U+FFFD, so a path that is not
    /// UTF-8 reaches the policy as one it accepts.
    PatchLossyPaths,
}

const HEADER: &[u8] = b"diff\n";

/// Repository metadata below the top level, such as `sub/.git/config`.
fn is_nested_metadata(path: &TreePath) -> bool {
    path.is_repository_metadata() && !path.as_bytes().starts_with(b".git/")
}

/// Whether some component of the path is `.git` and the next is `hooks`.
fn is_hook(path: &TreePath) -> bool {
    let components: Vec<&[u8]> = path.as_bytes().split(|b| *b == b'/').collect();
    components
        .windows(2)
        .any(|pair| pair[0] == b".git" && pair[1] == b"hooks")
}

/// Whether the citation rule refuses the path.
fn is_uncitable(path: &TreePath) -> bool {
    path.citable().is_err()
}

/// The path with its bytes read as UTF-8 through U+FFFD.
fn lossy(path: &TreePath) -> TreePath {
    TreePath::parse(String::from_utf8_lossy(path.as_bytes()).as_bytes())
        .unwrap_or_else(|_| path.clone())
}

/// The metadata entries of a workspace in `MemoryGit`'s diff format: each
/// path, `1` and the content, as an adapter that does not drop them would
/// write them.
fn metadata_as_changes(workspace: &Tree) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, content) in workspace {
        if path.is_repository_metadata() {
            put_field(&mut out, path.as_bytes());
            out.push(1);
            put_field(&mut out, content);
        }
    }
    out
}

/// One field of `MemoryGit`'s formats: its length in 8 big-endian bytes,
/// then the bytes.
fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Reads one field; `None` when it runs past the end.
fn take_field<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = rest.get(..8)?;
    let n = usize::try_from(u64::from_be_bytes(length.try_into().ok()?)).ok()?;
    let bytes = rest.get(8..8usize.checked_add(n)?)?;
    *rest = &rest[8 + n..];
    Some(bytes)
}

struct GitMutant {
    bug: GitBug,
    inner: MemoryGit,
    /// Checkouts that now read as another one (`InPlace`).
    moved: Mutex<Vec<(CheckoutId, CheckoutId)>>,
    /// The last diff applied (`PoisonsBase`).
    last_diff: Mutex<Option<Vec<u8>>>,
    /// Whether a hook ran (`RunsMetadata`); [`MutantTripwire`] reads it.
    ran: Mutex<bool>,
    /// Whether a diff saw repository metadata (`AdoptsMetadata`).
    adopted: Mutex<bool>,
    /// Checkouts whose diff saw metadata (`AdoptsPerCheckout`,
    /// `RunsOnRediff`) or that were fetched after one did
    /// (`AdoptsIntoNewCheckouts`).
    tainted: Mutex<Vec<CheckoutId>>,
    /// The repository and base of every checkout issued (`PushesBase`).
    origins: Mutex<Vec<(CheckoutId, RepoUrl, CommitSha)>>,
    /// What the remote shows for a branch instead of `MemoryGit`'s state:
    /// the tip and its parents that `PushesOrphan` and `Overwrites` left.
    remote: Mutex<Vec<ShownBranch>>,
}

/// A branch as a mutant's remote shows it: repository, name, tip and the
/// tip's parents.
type ShownBranch = (RepoUrl, BranchName, CommitSha, Vec<CommitSha>);

/// Reads a mutant's remote: what its push left in place of `MemoryGit`'s
/// own state, or that state.
struct MutantRemote;

impl contract::git::Remote<GitMutant> for MutantRemote {
    fn branch(
        &self,
        adapter: &GitMutant,
        repo: &RepoUrl,
        branch: &BranchName,
    ) -> Result<Option<(CommitSha, Vec<CommitSha>)>, String> {
        let remote = Mutex::lock(&adapter.remote).expect("not poisoned");
        let shown = remote
            .iter()
            .rev()
            .find(|(r, b, _, _)| r == repo && b == branch)
            .map(|(_, _, tip, parents)| (tip.clone(), parents.clone()));
        Ok(shown.or_else(|| adapter.inner.branch(repo, branch)))
    }
}

/// Reports a hook run that [`GitBug::RunsMetadata`] recorded.
struct MutantTripwire;

impl contract::git::Tripwire<GitMutant> for MutantTripwire {
    fn tripped(&self, adapter: &GitMutant) -> Result<Vec<String>, String> {
        let ran = *Mutex::lock(&adapter.ran).expect("not poisoned");
        Ok(if ran {
            vec![String::from("a hook from the workspace")]
        } else {
            vec![]
        })
    }
}

impl GitMutant {
    /// The repository and base a checkout was fetched from.
    fn origin(&self, checkout: &CheckoutId) -> Option<(RepoUrl, CommitSha)> {
        let origins = Mutex::lock(&self.origins).expect("not poisoned");
        origins
            .iter()
            .find(|(c, _, _)| c == checkout)
            .map(|(_, repo, base)| (repo.clone(), base.clone()))
    }

    /// Notes that `checkout` came from `repo` at `base`.
    fn record(&self, checkout: &CheckoutId, repo: RepoUrl, base: CommitSha) {
        let mut origins = Mutex::lock(&self.origins).expect("not poisoned");
        origins.push((checkout.clone(), repo, base));
    }

    /// What the remote shows for `branch` instead of `MemoryGit`'s state.
    fn show(&self, repo: RepoUrl, branch: &BranchName, tip: CommitSha, parents: Vec<CommitSha>) {
        let mut remote = Mutex::lock(&self.remote).expect("not poisoned");
        remote.push((repo, branch.clone(), tip, parents));
    }

    /// `fetch_base` with the bugs that change it.
    fn fetch(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError> {
        if let GitBug::PoisonsBase = self.bug {
            let fetched = self.inner.fetch_base(repo, base)?;
            let last = Mutex::lock(&self.last_diff).expect("not poisoned").clone();
            return match last {
                Some(diff) => self.inner.apply(&fetched, &diff),
                None => Ok(fetched),
            };
        }
        let adopted = *Mutex::lock(&self.adopted).expect("not poisoned");
        match (self.bug, self.inner.fetch_base(repo, base)) {
            (GitBug::UnknownIsOk, Err(GitError::UnknownCommit)) => {
                Ok(CheckoutId::new(String::from("checkout-0")))
            }
            (GitBug::AdoptsIntoNewCheckouts, Ok(fetched)) if adopted => {
                let mut tainted = Mutex::lock(&self.tainted).expect("not poisoned");
                tainted.push(fetched.clone());
                Ok(fetched)
            }
            (_, got) => got,
        }
    }

    fn resolve(&self, checkout: &CheckoutId) -> CheckoutId {
        let moved = Mutex::lock(&self.moved).expect("not poisoned");
        moved
            .iter()
            .rev()
            .find(|(from, _)| from == checkout)
            .map_or_else(|| checkout.clone(), |(_, to)| to.clone())
    }
}

impl Git for GitMutant {
    fn fetch_base(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError> {
        let fetched = self.fetch(repo, base)?;
        self.record(&fetched, repo.clone(), base.clone());
        Ok(fetched)
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
        let packed = self.inner.snapshot(&self.resolve(checkout))?;
        let tree = || unpack_tree(&packed).unwrap_or_default();
        Ok(match self.bug {
            GitBug::HidesUncitable => {
                let mut tree = tree();
                tree.retain(|path, _| !is_uncitable(path));
                pack_tree(&tree)
            }
            GitBug::RefusesUncitableSnapshot if tree().keys().any(is_uncitable) => {
                return Err(GitError::Failed {
                    detail: String::from("the tree has a path a workspace cannot carry"),
                });
            }
            GitBug::LossyUncitable => {
                pack_tree(&tree().into_iter().map(|(p, c)| (lossy(&p), c)).collect())
            }
            _ => packed,
        })
    }

    fn diff(&self, checkout: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError> {
        let from = self.resolve(checkout);
        let base = unpack_tree(&self.inner.snapshot(&from)?).unwrap_or_default();
        let mut tree = unpack_tree(workspace).unwrap_or_default();
        let sees_metadata = tree.keys().any(TreePath::is_repository_metadata);
        let mut changed = true;
        match self.bug {
            GitBug::RunsMetadata if tree.keys().any(is_hook) => {
                *Mutex::lock(&self.ran).expect("not poisoned") = true;
            }
            GitBug::DropsNewFiles => tree.retain(|path, _| base.contains_key(path)),
            GitBug::DropsRemovals => {
                for (path, content) in base {
                    tree.entry(path).or_insert(content);
                }
            }
            GitBug::HidesUncitable | GitBug::KeepsUncitableRemovals => {
                for (path, content) in base.into_iter().filter(|(p, _)| is_uncitable(p)) {
                    tree.entry(path).or_insert(content);
                }
            }
            GitBug::IgnoresUncitableEdits => {
                for (path, content) in base.into_iter().filter(|(p, _)| is_uncitable(p)) {
                    if let Some(now) = tree.get_mut(&path) {
                        *now = content;
                    }
                }
            }
            GitBug::DropsNewUncitable => {
                tree.retain(|path, _| !is_uncitable(path) || base.contains_key(path));
            }
            GitBug::LossyUncitable => {
                for path in base.keys().filter(|p| lossy(p) != **p) {
                    if !tree.contains_key(path)
                        && let Some(content) = tree.remove(&lossy(path))
                    {
                        tree.insert(path.clone(), content);
                    }
                }
            }
            _ => changed = false,
        }
        let diff = if changed {
            self.inner.diff(&from, &pack_tree(&tree))?
        } else {
            self.inner.diff(&from, workspace)?
        };
        let adopted = {
            let mut adopted = Mutex::lock(&self.adopted).expect("not poisoned");
            let before = *adopted;
            *adopted |= sees_metadata;
            before
        };
        let tainted = {
            let mut tainted = Mutex::lock(&self.tainted).expect("not poisoned");
            let before = tainted.contains(checkout);
            let per_checkout = matches!(self.bug, GitBug::AdoptsPerCheckout | GitBug::RunsOnRediff);
            if per_checkout && sees_metadata && !before {
                tainted.push(checkout.clone());
            }
            before
        };
        if let (GitBug::RunsOnRediff, true) = (self.bug, tainted) {
            *Mutex::lock(&self.ran).expect("not poisoned") = true;
        }
        Ok(match self.bug {
            GitBug::Header => [HEADER, &diff].concat(),
            GitBug::MetadataIsContent => [diff, metadata_as_changes(&tree)].concat(),
            GitBug::NestedIsContent => {
                let mut nested = tree.clone();
                nested.retain(|path, _| !path.as_bytes().starts_with(b".git/"));
                [diff, metadata_as_changes(&nested)].concat()
            }
            GitBug::AdoptsMetadata if adopted => [HEADER, &diff].concat(),
            GitBug::AdoptsOnChanges if adopted && !diff.is_empty() => [HEADER, &diff].concat(),
            GitBug::AdoptsPerCheckout | GitBug::AdoptsIntoNewCheckouts if tainted => {
                [HEADER, &diff].concat()
            }
            _ => diff,
        })
    }

    fn apply(&self, checkout: &CheckoutId, diff: &[u8]) -> Result<CheckoutId, GitError> {
        let applied = self.apply_with_bug(checkout, diff)?;
        if let Some((repo, base)) = self.origin(checkout) {
            self.record(&applied, repo, base);
        }
        Ok(applied)
    }

    fn patch_between(
        &self,
        base: &CheckoutId,
        after: &CheckoutId,
    ) -> Result<Result<Patch, UnreadablePath>, GitError> {
        let (from, to) = (self.resolve(base), self.resolve(after));
        let got = match self.bug {
            GitBug::PatchUnknownEmpty => match self.inner.patch_between(&from, &to) {
                Err(GitError::UnknownCheckout) => {
                    return Ok(Ok(Patch {
                        changes: Vec::new(),
                        base_links: Vec::new(),
                    }));
                }
                other => other?,
            },
            GitBug::PatchLossyPaths => {
                let lossy_tree = |c: &CheckoutId| -> Result<Tree, GitError> {
                    let tree = unpack_tree(&self.inner.snapshot(c)?).unwrap_or_default();
                    Ok(tree.into_iter().map(|(p, d)| (lossy(&p), d)).collect())
                };
                tree_patch(&lossy_tree(&from)?, &lossy_tree(&to)?)
            }
            _ => self.inner.patch_between(&from, &to)?,
        };
        let Ok(mut patch) = got else {
            return Ok(got);
        };
        match self.bug {
            GitBug::PatchSpurious if patch.changes.is_empty() => {
                let tree = unpack_tree(&self.inner.snapshot(&from)?).unwrap_or_default();
                let first = tree
                    .iter()
                    .find_map(|(p, d)| Some((std::str::from_utf8(p.as_bytes()).ok()?, d)));
                if let Some((path, data)) = first {
                    let side = Some(Entry {
                        kind: EntryKind::File,
                        data: data.clone(),
                    });
                    patch.changes.push(Change {
                        path: path.to_owned(),
                        before: side.clone(),
                        after: side,
                    });
                }
            }
            GitBug::PatchDropsBefore => {
                for change in &mut patch.changes {
                    change.before = None;
                }
            }
            GitBug::PatchDropsRemovals => patch.changes.retain(|c| c.after.is_some()),
            GitBug::PatchDropsUncitable => patch
                .changes
                .retain(|c| !TreePath::parse(c.path.as_bytes()).is_ok_and(|p| is_uncitable(&p))),
            _ => {}
        }
        Ok(Ok(patch))
    }

    fn push(
        &self,
        checkout: &CheckoutId,
        branch: &BranchName,
        commit: &CommitInfo,
    ) -> Result<CommitSha, GitError> {
        let from = self.resolve(checkout);
        match self.bug {
            GitBug::PushesBase => {
                let (repo, base) = self.origin(checkout).ok_or(GitError::UnknownCheckout)?;
                let fresh = self.inner.fetch_base(&repo, &base)?;
                self.inner.push(&fresh, branch, commit)
            }
            GitBug::PushesOrphan => {
                let sha = self.inner.push(&from, branch, commit)?;
                let (repo, _) = self.origin(checkout).ok_or(GitError::UnknownCheckout)?;
                self.show(repo, branch, sha.clone(), Vec::new());
                Ok(sha)
            }
            GitBug::Overwrites => match self.inner.push(&from, branch, commit) {
                Err(GitError::BranchExists) => {
                    // The new commit, made on a branch of its own, then
                    // shown as the tip of the one it overwrote.
                    let (repo, base) = self.origin(checkout).ok_or(GitError::UnknownCheckout)?;
                    let name = format!("{}-overwrite", branch.as_str());
                    let side = BranchName::parse(&name).ok_or(GitError::BranchExists)?;
                    let sha = self.inner.push(&from, &side, commit)?;
                    self.show(repo, branch, sha.clone(), vec![base]);
                    Ok(sha)
                }
                other => other,
            },
            GitBug::UnknownCheckoutFails => match self.inner.push(&from, branch, commit) {
                Err(GitError::UnknownCheckout) => Err(GitError::Failed {
                    detail: String::from("no such checkout"),
                }),
                other => other,
            },
            _ => self.inner.push(&from, branch, commit),
        }
    }
}

impl GitMutant {
    /// `apply` with the bugs that change it.
    fn apply_with_bug(&self, checkout: &CheckoutId, diff: &[u8]) -> Result<CheckoutId, GitError> {
        *Mutex::lock(&self.last_diff).expect("not poisoned") = Some(diff.to_vec());
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
            GitBug::AppliesMetadata => match self.inner.apply(&from, diff) {
                Err(GitError::Failed { .. }) if diff.windows(4).any(|w| w == b".git") => {
                    self.inner.apply(&from, &[])
                }
                other => other,
            },
            GitBug::WritesThenRefuses => match self.inner.apply(&from, diff) {
                Err(error) if diff.windows(4).any(|w| w == b".git") => {
                    let mut extra = Vec::new();
                    put_field(&mut extra, b"written");
                    extra.push(1);
                    put_field(&mut extra, b"before the refusal");
                    let written = self.inner.apply(&from, &extra)?;
                    let mut moved = Mutex::lock(&self.moved).expect("not poisoned");
                    moved.push((checkout.clone(), written));
                    Err(error)
                }
                other => other,
            },
            GitBug::AdoptsOnApply if *Mutex::lock(&self.adopted).expect("not poisoned") => {
                let mut extra = Vec::new();
                put_field(&mut extra, b"adopted");
                extra.push(1);
                put_field(&mut extra, b"by a hook");
                self.inner.apply(&from, &[diff, &extra].concat())
            }
            GitBug::InPlace => {
                let applied = self.inner.apply(&from, diff)?;
                let mut moved = Mutex::lock(&self.moved).expect("not poisoned");
                moved.push((checkout.clone(), applied));
                Ok(checkout.clone())
            }
            GitBug::RefusesUncitableTrees => {
                let applied = self.inner.apply(&from, diff)?;
                let tree = unpack_tree(&self.inner.snapshot(&applied)?).unwrap_or_default();
                if tree.keys().any(is_uncitable) {
                    return Err(GitError::Failed {
                        detail: String::from("the diff leaves a path a workspace cannot carry"),
                    });
                }
                Ok(applied)
            }
            _ => self.inner.apply(&from, diff),
        }
    }
}

const OTHER: &str = "89abcdef0123456789abcdef0123456789abcdef";

/// The base's files whose paths the citation rule refuses, one of each
/// class (ADR-018, D6).
fn git_uncitable() -> Vec<(TreePath, Vec<u8>)> {
    vec![
        (tpath(b"dir\\file"), b"backslash\n".to_vec()),
        (tpath(b" "), b"blank\n".to_vec()),
        (tpath(b"x\xff"), b"not UTF-8\n".to_vec()),
    ]
}

fn git_repository(bug: GitBug) -> contract::git::Repository<GitMutant> {
    git_repository_with(bug, git_uncitable(), None)
}

/// [`git_repository`] with another list of uncitable paths and,
/// optionally, one more file at the base.
fn git_repository_with(
    bug: GitBug,
    uncitable: Vec<(TreePath, Vec<u8>)>,
    extra: Option<(TreePath, Vec<u8>)>,
) -> contract::git::Repository<GitMutant> {
    let repo = RepoUrl::new(String::from("https://example.invalid/app.git"));
    let base = CommitSha::parse(BASE).expect("valid SHA");
    let mut files: Tree = [(tpath(b"src/lib.rs"), b"fn total() {}\n".to_vec())]
        .into_iter()
        .collect();
    files.extend(git_uncitable());
    files.extend(extra);
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
            ran: Mutex::new(false),
            adopted: Mutex::new(false),
            tainted: Mutex::new(Vec::new()),
            origins: Mutex::new(Vec::new()),
            remote: Mutex::new(Vec::new()),
        },
        repo,
        base,
        path: path("src/lib.rs"),
        content: b"fn total() {}\n".to_vec(),
        missing: path("src/missing.rs"),
        unknown: CommitSha::parse(OTHER).expect("valid SHA"),
        edited: b"fn total() { 1 }\n".to_vec(),
        // A fixed sentinel: nothing runs it here, and the replay gate
        // compares the rendered lengths of `same-diff` across processes, so
        // it must not vary. A real adapter's test uses a unique one per
        // fixture (`contract::git::Tripwire`).
        metadata: vec![
            (
                path(".git/config"),
                b"[core]\n\tfsmonitor = touch /tmp/boneli-tripwire/tripped\n\thooksPath = .git/hooks\n".to_vec(),
            ),
            (
                path(".git/hooks/post-index-change"),
                b"#!/bin/sh\ntouch /tmp/boneli-tripwire/tripped\n".to_vec(),
            ),
            (
                path("sub/.git/config"),
                b"[core]\n\tfsmonitor = touch /tmp/boneli-tripwire/tripped\n".to_vec(),
            ),
        ],
        uncitable,
    }
}

/// Moves every change of `from` in a diff of `MemoryGit`'s format to
/// `to`; a malformed diff comes back as it was.
fn git_retarget(diff: &[u8], from: &RelativePath, to: &RelativePath) -> Vec<u8> {
    let mut rest = diff;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let Some(path) = take_field(&mut rest) else {
            return diff.to_vec();
        };
        let path = if path == from.as_str().as_bytes() {
            to.as_str().as_bytes()
        } else {
            path
        };
        put_field(&mut out, path);
        let Some((&tag, tail)) = rest.split_first() else {
            return diff.to_vec();
        };
        rest = tail;
        out.push(tag);
        if tag == 1 {
            let Some(content) = take_field(&mut rest) else {
                return diff.to_vec();
            };
            put_field(&mut out, content);
        }
    }
    out
}

fn git_edit(workspace: &[u8], file: &TreePath, content: Option<&[u8]>) -> Vec<u8> {
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
    /// Bytes that do not match their digest are accepted.
    AcceptsTampered,
    /// The first pull of a tampered image fails, but what it fetched is
    /// kept and handed out by the second.
    CachesTampered,
    /// Every reference is pulled as the operator's: the origin is
    /// dropped (ADR-032).
    IgnoresOrigin,
    /// The exemption that admitted an agent's image is not reported.
    DropsExemption,
    /// A pull of a reference the operator chose reports an exemption.
    ExemptsOperator,
}

struct ImageMutant {
    bug: ImageBug,
    inner: MemoryImageStore,
    pulls: Mutex<u64>,
    /// The images the inner store has.
    known: Vec<ImageRef>,
}

impl ImageStore for ImageMutant {
    fn pull(&self, image: &ImageRef) -> Result<Pulled, ImageError> {
        let resolved = self.known.iter().find(|k| match self.bug {
            ImageBug::ByName => k.name == image.name,
            ImageBug::IgnoresPlatform => k.name == image.name && k.digest == image.digest,
            _ => *k == image,
        });
        let image = resolved.unwrap_or(image);
        let as_operator = ImageRef {
            origin: ImageOrigin::Operator,
            ..image.clone()
        };
        let pulled = match self.bug {
            ImageBug::IgnoresOrigin => self.inner.pull(&as_operator),
            _ => self.inner.pull(image),
        };
        let tampered = || {
            Ok(Pulled {
                rootfs: RootfsRef::new(String::from("rootfs-tampered")),
                exemption: None,
            })
        };
        match (self.bug, pulled) {
            (ImageBug::AcceptsTampered, Err(ImageError::Failed { .. })) => tampered(),
            (ImageBug::CachesTampered, Err(ImageError::Failed { detail })) => {
                let mut pulls = Mutex::lock(&self.pulls).expect("not poisoned");
                *pulls += 1;
                if *pulls == 1 {
                    Err(ImageError::Failed { detail })
                } else {
                    tampered()
                }
            }
            (ImageBug::NewRootfsPerPull, Ok(p)) => {
                let mut pulls = Mutex::lock(&self.pulls).expect("not poisoned");
                *pulls += 1;
                Ok(Pulled {
                    rootfs: RootfsRef::new(format!("{}-{pulls}", p.rootfs.as_str())),
                    ..p
                })
            }
            (ImageBug::MissingIsEmpty, Err(ImageError::NotFound)) => Ok(Pulled {
                rootfs: RootfsRef::new(String::from("rootfs-empty")),
                exemption: None,
            }),
            (ImageBug::DropsExemption, Ok(p)) => Ok(Pulled {
                exemption: None,
                ..p
            }),
            (ImageBug::ExemptsOperator, Ok(p)) if image.origin == ImageOrigin::Operator => {
                Ok(Pulled {
                    exemption: Some(exemption()),
                    ..p
                })
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
        origin: ImageOrigin::Operator,
    }
}

fn agent_ref(name: &str) -> ImageRef {
    ImageRef {
        origin: ImageOrigin::Agent,
        ..image_ref(name, "sha256:dd", "linux/amd64")
    }
}

fn exemption() -> ImageExemption {
    ImageExemption {
        registry: String::from("docker.io"),
        scope: String::from("library/"),
    }
}

fn images(bug: ImageBug) -> contract::image::Images<ImageMutant> {
    let present = image_ref("library/postgres", "sha256:aa", "linux/amd64");
    let tampered = image_ref("library/redis", "sha256:cc", "linux/amd64");
    let agent_refused = agent_ref("acme/app");
    let agent_exempted = agent_ref("library/mailcatcher");
    let stocked = vec![
        present.clone(),
        agent_refused.clone(),
        agent_exempted.clone(),
    ];
    contract::image::Images {
        adapter: ImageMutant {
            bug,
            inner: MemoryImageStore::new(stocked.clone())
                .with_tampered(vec![tampered.clone()])
                .with_agent_exemptions(vec![(agent_exempted.name.clone(), exemption())]),
            pulls: Mutex::new(0),
            known: stocked,
        },
        present,
        missing: image_ref("library/node", "sha256:aa", "linux/amd64"),
        other_digest: image_ref("library/postgres", "sha256:bb", "linux/amd64"),
        other_platform: image_ref("library/postgres", "sha256:aa", "linux/arm64"),
        tampered,
        agent_refused,
        agent_exempted,
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
            DataBug::SharedData => Mutex::lock(&self.first)
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
            let mut named = Mutex::lock(&self.named).expect("not poisoned");
            if let Some((_, copy)) = named.iter().find(|(name, _)| *name == last) {
                return Ok(copy.clone());
            }
            let copy = self.inner.copy(snapshot, run)?;
            named.push((last, copy.clone()));
            return Ok(copy);
        }
        let copy = self.inner.copy(snapshot, run)?;
        let mut first = Mutex::lock(&self.first).expect("not poisoned");
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

/// A mutant that breaks one sub-check (`operation`) of a clause that
/// checks several; its violation detail starts with `<operation>:`.
fn sub_mutant(
    port: &'static str,
    clause: &'static str,
    operation: &'static str,
    run: impl Fn() -> Result<(), Violation> + 'static,
) -> Mutant {
    Mutant {
        port,
        clause,
        operation,
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
                &contract::sample_ticket(),
            )
        }),
    ];
    let sandbox = |clause, bug| {
        mutant("Sandbox", clause, move || {
            contract::sandbox::run(|| sandbox_workspace(bug), git_edit)
        })
    };
    let git = |clause, bug| mutant("Git", clause, move || git_suite(bug));
    let git_metadata = |sub, bug| {
        sub_mutant("Git", "workspace-metadata-inert", sub, move || {
            git_suite(bug)
        })
    };
    let git_uncitable = |sub, bug| {
        sub_mutant("Git", "uncitable-paths-carried", sub, move || {
            git_suite(bug)
        })
    };
    let git_patch_uncitable =
        |sub, bug| sub_mutant("Git", "patch-uncitable-paths", sub, move || git_suite(bug));
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
            contract::sandbox::run(pooled_workspace, git_edit)
        }),
        sandbox("exit-status", SandboxBug::ReportsSuccess),
        sandbox("destroyed-is-unknown", SandboxBug::DestroyIgnored),
        sandbox("unknown-container", SandboxBug::IgnoresContainer),
        sandbox("limits-checked", SandboxBug::UncheckedLimits),
        sandbox("export-round-trip", SandboxBug::ExportEmpty),
        sandbox("export-sees-write", SandboxBug::ExportStale),
        sandbox("copy-out-no-symlink", SandboxBug::FollowsLinks),
        sandbox("verify-without-brokers", SandboxBug::VerifyKeepsBrokers),
        sandbox("seal-prepare-only", SandboxBug::SealsAnyPhase),
        sandbox("sealed-layer-mounted", SandboxBug::DependencyNotMounted),
        sandbox("distinct-layers", SandboxBug::ReusesLayer),
        sandbox("released-layer-unknown", SandboxBug::ReleaseIgnored),
        sandbox("layer-in-use-kept", SandboxBug::ReleasesInUse),
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
        git_metadata("nothing-ran", GitBug::RunsMetadata),
        git_metadata("same-diff", GitBug::MetadataIsContent),
        git_metadata("same-checkout", GitBug::AdoptsPerCheckout),
        git_metadata("fresh-checkout", GitBug::AdoptsIntoNewCheckouts),
        git_metadata("same-apply", GitBug::AdoptsOnApply),
        git_metadata("apply-refuses", GitBug::AppliesMetadata),
        git("push-reads-back", GitBug::PushesBase),
        git("push-parent-is-base", GitBug::PushesOrphan),
        git("push-never-overwrites", GitBug::Overwrites),
        git("push-unknown-checkout", GitBug::UnknownCheckoutFails),
        git_uncitable("snapshot-carries", GitBug::HidesUncitable),
        git_uncitable("edit-round-trip", GitBug::IgnoresUncitableEdits),
        git_uncitable("remove-round-trip", GitBug::KeepsUncitableRemovals),
        git_uncitable("add-round-trip", GitBug::DropsNewUncitable),
        git("patch-unchanged-empty", GitBug::PatchSpurious),
        git("patch-full-sides", GitBug::PatchDropsBefore),
        git("patch-added-removed", GitBug::PatchDropsRemovals),
        git("patch-unknown-checkout", GitBug::PatchUnknownEmpty),
        git_patch_uncitable("uncitable-carried", GitBug::PatchDropsUncitable),
        git_patch_uncitable("unreadable-refused", GitBug::PatchLossyPaths),
        image("pull-idempotent", ImageBug::NewRootfsPerPull),
        image("missing-image", ImageBug::MissingIsEmpty),
        image("digest-pinned", ImageBug::ByName),
        image("platform-pinned", ImageBug::IgnoresPlatform),
        sub_mutant("ImageStore", "tampered-refused", "first-pull", || {
            contract::image::run(|| images(ImageBug::AcceptsTampered))
        }),
        sub_mutant("ImageStore", "tampered-refused", "second-pull", || {
            contract::image::run(|| images(ImageBug::CachesTampered))
        }),
        image("agent-origin-refused", ImageBug::IgnoresOrigin),
        sub_mutant("ImageStore", "exemption-reported", "agent-pull", || {
            contract::image::run(|| images(ImageBug::DropsExemption))
        }),
        sub_mutant("ImageStore", "exemption-reported", "operator-pull", || {
            contract::image::run(|| images(ImageBug::ExemptsOperator))
        }),
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
                &contract::sample_ticket(),
            )
        }));
    }
    all
}

fn git_suite(bug: GitBug) -> Result<(), Violation> {
    contract::git::run(
        || git_repository(bug),
        git_edit,
        git_retarget,
        &MutantTripwire,
        &MutantRemote,
    )
}

/// Mutants that review found passing an earlier version of a suite, and
/// mutants for a second check site of a case. Each is caught by a clause
/// case that already has its own mutant in [`mutants`], so they stay out
/// of that table, which is a bijection; they are checked and rendered the
/// same way.
pub fn regression_mutants() -> Vec<Mutant> {
    let git_metadata = |sub, bug| {
        sub_mutant("Git", "workspace-metadata-inert", sub, move || {
            git_suite(bug)
        })
    };
    vec![
        // Review of #61: adoption that every later diff shows; it was the
        // `later-diff` mutant before that sub-check was split.
        git_metadata("same-checkout", GitBug::AdoptsMetadata),
        // Review of #61: adoption that shows only in a non-empty diff.
        git_metadata("same-checkout", GitBug::AdoptsOnChanges),
        // Review of #61: a hook that runs only on a second diff of the same
        // checkout.
        git_metadata("nothing-ran", GitBug::RunsOnRediff),
        // The second site of `apply-refuses`: the refused checkout is
        // unchanged.
        git_metadata("apply-refuses", GitBug::WritesThenRefuses),
        // Review round 2 of #61: nested metadata treated as content.
        git_metadata("same-diff", GitBug::NestedIsContent),
        // #64: `GitCli` before ADR-018, whose `snapshot` and `apply`
        // refused uncitable paths; `apply-then-read` is the first clause
        // that snapshots and applies.
        mutant("Git", "apply-then-read", || {
            git_suite(GitBug::RefusesUncitableSnapshot)
        }),
        mutant("Git", "apply-then-read", || {
            git_suite(GitBug::RefusesUncitableTrees)
        }),
        // #64: a snapshot that renders a path that is not UTF-8 lossily.
        sub_mutant("Git", "uncitable-paths-carried", "snapshot-carries", || {
            git_suite(GitBug::LossyUncitable)
        }),
    ]
}

/// An `edit` fixture hook of the `Git` suite.
type EditHook = dyn Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>;

/// The violations of `workspace-metadata-inert` with fixture hooks that
/// review of #61 showed making it vacuous, each on a mutant it let
/// through: an `edit` that never writes metadata (round 1), one that skips
/// or later drops the nested entry, and a `retarget` that breaks diffs
/// pointed at metadata (round 2). Then the same for
/// `uncitable-paths-carried` (#64): an `edit` that skips uncitable paths,
/// a list without one class and a base that has a twin. The suite rejects
/// the fixture; each row names the clause it must reject it at.
pub fn vacuous_fixture_violations() -> Vec<(&'static str, &'static str, Result<(), Violation>)> {
    let skipping = |w: &[u8], p: &TreePath, c: Option<&[u8]>| {
        if p.is_repository_metadata() {
            w.to_vec()
        } else {
            git_edit(w, p, c)
        }
    };
    let run = |bug| {
        contract::git::run(
            || git_repository(bug),
            skipping,
            git_retarget,
            &MutantTripwire,
            &MutantRemote,
        )
    };
    // Review round 2 of #61: an `edit` that skips only the nested entry,
    // or drops it once the top-level `.git` is there.
    let skip_nested = |w: &[u8], p: &TreePath, c: Option<&[u8]>| {
        if is_nested_metadata(p) {
            w.to_vec()
        } else {
            git_edit(w, p, c)
        }
    };
    let drop_nested_later = |w: &[u8], p: &TreePath, c: Option<&[u8]>| {
        let top = unpack_tree(w)
            .unwrap_or_default()
            .keys()
            .any(|k| k.as_bytes().starts_with(b".git/"));
        if top && is_nested_metadata(p) {
            w.to_vec()
        } else {
            git_edit(w, p, c)
        }
    };
    let nested = |edit: &EditHook| {
        contract::git::run(
            || git_repository(GitBug::NestedIsContent),
            edit,
            git_retarget,
            &MutantTripwire,
            &MutantRemote,
        )
    };
    // Review round 2 of #61: a `retarget` that breaks diffs pointed at
    // metadata, so any `apply` refuses them.
    let garbles_metadata = |d: &[u8], from: &RelativePath, to: &RelativePath| {
        if to.is_repository_metadata() {
            b"garbage".to_vec()
        } else {
            git_retarget(d, from, to)
        }
    };
    // #64: an `edit` that skips uncitable paths, so a snapshot that
    // leaves them out looks complete.
    let skips_uncitable = |w: &[u8], p: &TreePath, c: Option<&[u8]>| {
        if is_uncitable(p) {
            w.to_vec()
        } else {
            git_edit(w, p, c)
        }
    };
    let uncitable_run = |make: &dyn Fn() -> contract::git::Repository<GitMutant>,
                         edit: &EditHook| {
        contract::git::run(make, edit, git_retarget, &MutantTripwire, &MutantRemote)
    };
    // A list without the non-UTF-8 path lets the lossy snapshot through,
    // and a twin at the base lets the mutant that drops new uncitable
    // paths through: adding the twin is then an edit.
    let without_non_utf8 = || {
        let mut list = git_uncitable();
        list.retain(|(p, _)| p.citable() != Err(boneli_app::Uncitable::NotUtf8));
        git_repository_with(GitBug::LossyUncitable, list, None)
    };
    let twin_at_base = || {
        let twin = tpath("dir\\file\u{200B}".as_bytes());
        git_repository_with(
            GitBug::DropsNewUncitable,
            git_uncitable(),
            Some((twin, b"twin\n".to_vec())),
        )
    };
    const METADATA: &str = "workspace-metadata-inert";
    const UNCITABLE: &str = "uncitable-paths-carried";
    vec![
        ("RunsMetadata", METADATA, run(GitBug::RunsMetadata)),
        (
            "MetadataIsContent",
            METADATA,
            run(GitBug::MetadataIsContent),
        ),
        ("NestedIsContent skipped", METADATA, nested(&skip_nested)),
        (
            "NestedIsContent dropped later",
            METADATA,
            nested(&drop_nested_later),
        ),
        (
            "AppliesMetadata garbled",
            METADATA,
            contract::git::run(
                || git_repository(GitBug::AppliesMetadata),
                git_edit,
                garbles_metadata,
                &MutantTripwire,
                &MutantRemote,
            ),
        ),
        (
            "HidesUncitable skipped",
            UNCITABLE,
            uncitable_run(&|| git_repository(GitBug::HidesUncitable), &skips_uncitable),
        ),
        (
            "LossyUncitable without the non-UTF-8 class",
            UNCITABLE,
            uncitable_run(&without_non_utf8, &git_edit),
        ),
        (
            "DropsNewUncitable with a twin at the base",
            UNCITABLE,
            uncitable_run(&twin_at_base, &git_edit),
        ),
    ]
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
    let forge = contract::forge::run(
        MemoryForge::new,
        || SilentFailure {
            adapter: MemoryForge::scripted(ForgeScript {
                post_questions: vec![Response::Fail(blank(" "))],
                open_pull_request: vec![Response::Fail(blank(" "))],
            }),
            status: String::from(" "),
        },
        &contract::sample_ticket(),
    );
    vec![("Agent", agent), ("Verifier", verifier), ("Forge", forge)]
}

/// For each mutant: `mutant <port> <clause> <operation>` and the pretty
/// `Debug` of its suite's result; the same for each regression mutant
/// (`regression ...`); then the blank-status and vacuous-fixture
/// violations.
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
    for m in regression_mutants() {
        let _ = write!(
            out,
            "regression {} {} {}\n{:#?}\n",
            m.port,
            m.clause,
            m.operation,
            (m.run)()
        );
    }
    for (port, result) in blank_status_violations() {
        let _ = write!(out, "blank-status {port}\n{result:#?}\n");
    }
    for (name, _, result) in vacuous_fixture_violations() {
        let _ = write!(out, "vacuous-fixture Git {name}\n{result:#?}\n");
    }
    out
}
