//! `DebugTicket` on the file store (#4, ADR-012): the acceptance "a
//! replayed run reaches the same state as the original" on the real
//! adapter, with the in-memory job adapters of the app corpus.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use boneli_app::{
    Clock, DebugRequest, DebugTicket, DebugTicketError, EventStore, Evidence, replay,
};
use boneli_domain::{EvidenceRef, RunId};
use boneli_memory::{
    AgentRequest, ForgeRequest, MemoryAgent, MemoryEvidence, MemoryForge, MemoryVerifier,
    SequentialIds, StepClock, VerifierRequest,
};
use boneli_replay_check::app::{
    AppScenario, ClockSetup, ScriptedClock, hand_written, play, questions,
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
