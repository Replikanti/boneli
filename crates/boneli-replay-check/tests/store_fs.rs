//! `DebugTicket` on the file store (#4, ADR-012): the acceptance "a
//! replayed run reaches the same state as the original" on the real
//! adapter, with the in-memory job adapters of the app corpus.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use boneli_app::{
    BranchName, CheckoutId, Clock, CommitInfo, DebugRequest, DebugTicket, DebugTicketError,
    EventStore, Evidence, Git, GitError, MAX_DETAIL_BYTES, RelativePath, RepoUrl, replay,
};
use boneli_domain::{
    CommitSha, EventKind, EvidenceRef, Outcome, Patch, RunEvent, RunId, Stage, UnreadablePath,
};
use boneli_memory::{
    AgentRequest, ForgeRequest, MemoryAgent, MemoryEvidence, MemoryForge, MemoryGit,
    MemoryVerifier, SequentialIds, StepClock, VerifierRequest,
};
use boneli_replay_check::app::{
    AppScenario, ClockSetup, ScriptedClock, git_commits, hand_written, play, questions,
};
use boneli_store_fs::FsStore;

/// A directory under `CARGO_TARGET_TMPDIR`, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("store-fs-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create the test's temp dir");
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The job adapters, clock and ids of one scenario; they outlive a store
/// restart, as a runner's would.
struct Jobs {
    agent: MemoryAgent,
    verifier: MemoryVerifier,
    forge: MemoryForge,
    git: MemoryGit,
    clock: Box<dyn Clock>,
    ids: SequentialIds,
}

impl Jobs {
    fn of(scenario: &AppScenario) -> Jobs {
        let clock: Box<dyn Clock> = match &scenario.clock {
            ClockSetup::Step { start, increment } => Box::new(StepClock::new(*start, *increment)),
            ClockSetup::Readings(readings) => Box::new(ScriptedClock::new(readings.clone())),
        };
        Jobs {
            agent: MemoryAgent::new(scenario.agent.clone()),
            verifier: MemoryVerifier::new(scenario.verifier.clone()),
            forge: MemoryForge::scripted(scenario.forge.clone()),
            git: MemoryGit::new(git_commits()),
            clock,
            ids: SequentialIds::new(),
        }
    }

    fn run(
        &self,
        store: &FsStore,
        request: DebugRequest,
    ) -> Result<boneli_app::DebugReport, DebugTicketError> {
        DebugTicket {
            agent: &self.agent,
            verifier: &self.verifier,
            forge: &self.forge,
            git: &self.git,
            events: store,
            evidence: store,
            clock: self.clock.as_ref(),
            ids: &self.ids,
        }
        .run(request)
    }
}

/// The `Debug` form of `value` with every `sha256:` reference of `store`
/// replaced by the reference `MemoryEvidence` gives the same bytes, so a
/// run on the file store compares with the same run on the in-memory one.
fn as_in_memory(store: &FsStore, value: &impl std::fmt::Debug) -> String {
    let text = format!("{value:?}");
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find("sha256:") {
        out.push_str(&rest[..at]);
        let end = at + "sha256:".len() + 64;
        let reference = EvidenceRef::parse(&rest[at..end]).expect("a reference");
        let content = store.get(&reference).expect("a stored blob");
        let memory = MemoryEvidence::new().put(&content).expect("put");
        out.push_str(memory.as_str());
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Every fault-free hand-written scenario through `DebugTicket` on
/// `FsStore`. Each request gives what it gives on the in-memory stores,
/// up to the form of the evidence references; after a reopen every run
/// loads to the log the in-memory store holds, and every finished run
/// replays to its `DebugReport`.
#[test]
fn debug_ticket_on_fs_store_replays() {
    let mut played = 0;
    let mut finished = 0;
    for scenario in hand_written().into_iter().filter(|s| s.fault.is_none()) {
        let tmp = TempDir::new("debug-ticket");
        let root = tmp.0.join("store");
        let jobs = Jobs::of(&scenario);
        let results: Vec<_> = {
            let store = FsStore::open(&root).expect("open");
            scenario
                .requests
                .iter()
                .map(|request| jobs.run(&store, request.clone()))
                .collect()
        };
        let in_memory = play(&scenario);
        let store = FsStore::open(&root).expect("reopen");
        let name = &scenario.name;
        assert_eq!(
            as_in_memory(&store, &results),
            format!("{:?}", in_memory.results),
            "{name}"
        );
        assert_eq!(
            as_in_memory(&store, &jobs.agent.requests()),
            format!("{:?}", in_memory.agent),
            "{name}"
        );
        assert_eq!(
            as_in_memory(&store, &jobs.forge.requests()),
            format!("{:?}", in_memory.forge),
            "{name}"
        );
        let mut logs = Vec::new();
        for (run, _) in &in_memory.logs {
            logs.push((run.clone(), store.load(run).expect("load")));
        }
        assert_eq!(
            as_in_memory(&store, &logs),
            format!("{:?}", in_memory.logs),
            "{name}"
        );
        for report in results.iter().flatten() {
            let log = store.load(report.run.id()).expect("load");
            let (run, commands) = replay(report.run.id(), &log).expect("replays");
            assert_eq!(run, report.run, "{name}");
            assert_eq!(commands, report.commands, "{name}");
            finished += 1;
        }
        played += 1;
    }
    println!("{played} scenarios, {finished} finished runs replayed from disk");
    assert!(played >= 10 && finished >= 10, "{played} {finished}");
}

/// A run that ends with questions, a restart of the store, then the re-run
/// (ADR-004, D6): its triage request carries the questions as the reopened
/// store logged them.
#[test]
fn rerun_after_restart_reads_questions_from_disk() {
    let scenario = hand_written()
        .into_iter()
        .find(|s| s.name == "rerun-after-questions")
        .expect("the scenario");
    let tmp = TempDir::new("rerun");
    let root = tmp.0.join("store");
    let jobs = Jobs::of(&scenario);
    let first = {
        let store = FsStore::open(&root).expect("open");
        jobs.run(&store, scenario.requests[0].clone())
            .expect("the first run")
    };
    let store = FsStore::open(&root).expect("reopen");
    let second = jobs
        .run(&store, scenario.requests[1].clone())
        .expect("the re-run");
    assert_eq!(scenario.requests[1].previous, Some(first.run.id().clone()));
    let triages: Vec<_> = jobs
        .agent
        .requests()
        .into_iter()
        .filter_map(|r| match r {
            AgentRequest::Triage(t) => Some(t),
            _ => None,
        })
        .collect();
    let previous = triages[1].previous.as_ref().expect("the previous triage");
    assert_eq!(previous.run, RunId::new(String::from("run-1")));
    assert_eq!(previous.questions, questions());
    assert_eq!(second.run.id(), &RunId::new(String::from("run-2")));
}

/// A run logged in version 1 that ended with questions still answers a
/// re-run (ADR-023, D7): its header is rewritten to version 1 before the
/// store reopens, and the re-run's triage gets the questions from it.
#[test]
fn rerun_reads_questions_from_a_version_1_log() {
    let scenario = hand_written()
        .into_iter()
        .find(|s| s.name == "rerun-after-questions")
        .expect("the scenario");
    let tmp = TempDir::new("rerun-v1");
    let root = tmp.0.join("store");
    let jobs = Jobs::of(&scenario);
    {
        let store = FsStore::open(&root).expect("open");
        jobs.run(&store, scenario.requests[0].clone())
            .expect("the first run");
    }
    let logs: Vec<PathBuf> = std::fs::read_dir(root.join("runs"))
        .expect("list the logs")
        .map(|e| e.expect("entry").path())
        .collect();
    let [log] = logs.as_slice() else {
        panic!("one log expected: {logs:?}");
    };
    let text = std::fs::read_to_string(log).expect("read");
    assert!(text.starts_with("{\"format\":\"boneli-run-log\",\"version\":2,"));
    let text = text.replacen("\"version\":2,", "\"version\":1,", 1);
    std::fs::write(log, text).expect("write");
    let store = FsStore::open(&root).expect("reopen");
    let second = jobs
        .run(&store, scenario.requests[1].clone())
        .expect("the re-run");
    assert_eq!(second.run.id(), &RunId::new(String::from("run-2")));
    let previous = jobs
        .agent
        .requests()
        .into_iter()
        .filter_map(|r| match r {
            AgentRequest::Triage(t) => t.previous,
            _ => None,
        })
        .next()
        .expect("the re-run's triage names the previous run");
    assert_eq!(previous.questions, questions());
}

/// The forge gets the bytes the verifier checked (ADR-004, D9), read back
/// from disk.
#[test]
fn forge_gets_verified_bytes_on_fs_store() {
    let scenario = hand_written()
        .into_iter()
        .find(|s| s.name == "delivered")
        .expect("the scenario");
    let tmp = TempDir::new("forge-bytes");
    let jobs = Jobs::of(&scenario);
    let store = FsStore::open(&tmp.0.join("store")).expect("open");
    jobs.run(&store, scenario.requests[0].clone())
        .expect("delivered");
    let verified = jobs
        .verifier
        .requests()
        .into_iter()
        .find_map(|r| match r {
            VerifierRequest::VerifyFix { diff, test, .. } => Some((diff, test)),
            _ => None,
        })
        .expect("the fix was verified");
    let opened = jobs
        .forge
        .requests()
        .into_iter()
        .find_map(|r| match r {
            ForgeRequest::OpenPullRequest(pr) => Some(pr),
            _ => None,
        })
        .expect("a pull request was opened");
    assert_eq!(opened.diff.content, verified.0);
    assert_eq!(opened.test.content, verified.1);
    assert_eq!(store.get(&opened.diff.reference), Ok(verified.0));
    assert!(opened.diff.reference.as_str().starts_with("sha256:"));
}

/// `MemoryGit`, except that `apply` fails with a detail larger than a log
/// line, as `GitCli` does for a diff of many patches that do not apply:
/// one stderr line per patch. Control characters escape to 6 bytes each
/// in JSON, the worst case of the cap's derivation (ADR-023, D2).
struct OversizedApply(MemoryGit);

/// The size the review measured for a 35 MB diff that does not apply.
const OVERSIZED: usize = 9_588_938;

impl Git for OversizedApply {
    fn fetch_base(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError> {
        self.0.fetch_base(repo, base)
    }
    fn read(
        &self,
        checkout: &CheckoutId,
        path: &RelativePath,
    ) -> Result<Option<Vec<u8>>, GitError> {
        self.0.read(checkout, path)
    }
    fn snapshot(&self, checkout: &CheckoutId) -> Result<Vec<u8>, GitError> {
        self.0.snapshot(checkout)
    }
    fn diff(&self, checkout: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError> {
        self.0.diff(checkout, workspace)
    }
    fn apply(&self, _checkout: &CheckoutId, _diff: &[u8]) -> Result<CheckoutId, GitError> {
        Err(GitError::Failed {
            detail: "\u{1}".repeat(OVERSIZED),
        })
    }
    fn patch_between(
        &self,
        base: &CheckoutId,
        after: &CheckoutId,
    ) -> Result<Result<Patch, UnreadablePath>, GitError> {
        self.0.patch_between(base, after)
    }
    fn push(
        &self,
        checkout: &CheckoutId,
        branch: &BranchName,
        commit: &CommitInfo,
    ) -> Result<CommitSha, GitError> {
        self.0.push(checkout, branch, commit)
    }
}

/// A git error over the log-line limit still ends the run with a recorded
/// `JobFailed` (ADR-023, D2): the detail is capped, the append succeeds on
/// the file store, and the stored log replays to the reported run.
#[test]
fn oversized_git_error_is_recorded() {
    let scenario = hand_written()
        .into_iter()
        .find(|s| s.name == "delivered")
        .expect("the scenario");
    let tmp = TempDir::new("oversized-detail");
    let jobs = Jobs::of(&scenario);
    let git = OversizedApply(MemoryGit::new(git_commits()));
    let store = FsStore::open(&tmp.0.join("store")).expect("open");
    let report = DebugTicket {
        agent: &jobs.agent,
        verifier: &jobs.verifier,
        forge: &jobs.forge,
        git: &git,
        events: &store,
        evidence: &store,
        clock: jobs.clock.as_ref(),
        ids: &jobs.ids,
    }
    .run(scenario.requests[0].clone())
    .expect("the run ends with a recorded outcome");
    let Stage::Done(Outcome::JobFailed { awaiting, detail }) = report.run.stage() else {
        panic!("a failed job expected: {:?}", report.run.stage());
    };
    assert_eq!(awaiting, EventKind::PatchChecked);
    assert!(detail.len() <= MAX_DETAIL_BYTES, "{}", detail.len());
    assert!(detail.starts_with("applying the diff failed: git failed: \u{1}"));
    let total = "applying the diff failed: git failed: ".len() + OVERSIZED;
    assert!(
        detail.ends_with(&format!(" [truncated, {total} bytes in all]")),
        "{}",
        &detail[detail.len() - 60..]
    );
    let log = store.load(report.run.id()).expect("load");
    assert!(matches!(
        log.events.last(),
        Some(RunEvent::JobFailed { detail: logged, .. }) if *logged == detail
    ));
    let (run, _) = replay(report.run.id(), &log).expect("replays");
    assert_eq!(run, report.run);
    assert_eq!(
        jobs.verifier.requests().len(),
        2,
        "the fix is never verified"
    );
}
