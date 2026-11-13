//! Every in-memory adapter passes its port's contract suite (ADR-004, D2).

use boneli_app::contract::{self, SilentFailure};
use boneli_app::{
    Command, DatabaseCopy, ExecResult, ExitStatus, ImageRef, Limits, Phase, RelativePath, RepoUrl,
    RootCauseReport, RootfsRef, SandboxId, SandboxSpec, SnapshotSource, TriageReport, Written,
};
use boneli_domain::{CitationStatus, CommitSha, FixChecks, TriageVerdict};
use boneli_memory::{
    AgentScript, ForgeScript, GitCommit, MemoryAgent, MemoryDataSnapshot, MemoryEventStore,
    MemoryForge, MemoryGit, MemoryImageStore, MemorySandbox, MemoryVerifier, Program, Response,
    ScriptedFailure, SequentialIds, StepClock, Tree, VerifierScript, pack_tree, unpack_tree,
};

/// The status the silent-failure fixtures report.
pub const STATUS: &str = "exit status 3";

/// Every operation fails silently.
pub fn fails<T>() -> Vec<Response<T>> {
    vec![Response::Fail(silent())]
}

/// A failure with no error output and the status [`STATUS`].
pub fn silent() -> ScriptedFailure {
    ScriptedFailure {
        error_output: String::new(),
        status: String::from(STATUS),
        cost_micro_usd: 10,
    }
}

/// An agent whose every operation fails silently.
pub fn silent_agent() -> SilentFailure<MemoryAgent> {
    SilentFailure {
        adapter: MemoryAgent::new(AgentScript {
            triage: fails(),
            write_reproduction: fails(),
            analyze_root_cause: fails(),
            write_fix: fails(),
        }),
        status: String::from(STATUS),
    }
}

/// A verifier whose every operation fails silently.
pub fn silent_verifier() -> SilentFailure<MemoryVerifier> {
    SilentFailure {
        adapter: MemoryVerifier::new(VerifierScript {
            check_reproduction: vec![Response::Fail(silent())],
            verify_citations: vec![Response::Fail(silent())],
            verify_fix: vec![Response::Fail(silent())],
        }),
        status: String::from(STATUS),
    }
}

/// A verifier that answers the suite's sample citations.
pub fn answering_verifier() -> contract::verifier::Answering<MemoryVerifier> {
    let base = CommitSha::parse("0123456789abcdef0123456789abcdef01234567").expect("valid SHA");
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
}

/// A forge whose every operation fails silently.
pub fn silent_forge() -> SilentFailure<MemoryForge> {
    SilentFailure {
        adapter: MemoryForge::scripted(ForgeScript {
            post_questions: vec![Response::Fail(silent())],
            open_pull_request: vec![Response::Fail(silent())],
        }),
        status: String::from(STATUS),
    }
}

#[test]
fn in_memory_event_store_passes_contract() {
    assert_eq!(contract::event_store::run(MemoryEventStore::new), Ok(()));
}

// The Evidence suite runs in the unit tests of `src/evidence.rs`: its
// `tampered-content-rejected` clause writes behind the store, which only
// test code inside the crate may do (ADR-004, D9).

#[test]
fn in_memory_clock_passes_contract() {
    assert_eq!(contract::clock::run(&StepClock::new(0, 1_000)), Ok(()));
    assert_eq!(contract::clock::run(&StepClock::new(7, 0)), Ok(()));
    // Saturates instead of wrapping.
    assert_eq!(
        contract::clock::run(&StepClock::new(u64::MAX - 1, 1)),
        Ok(())
    );
}

#[test]
fn in_memory_ids_passes_contract() {
    assert_eq!(contract::ids::run(&SequentialIds::new()), Ok(()));
}

#[test]
fn in_memory_agent_passes_contract() {
    assert_eq!(contract::agent::run(silent_agent), Ok(()));
}

#[test]
fn in_memory_verifier_passes_contract() {
    assert_eq!(
        contract::verifier::run(answering_verifier, silent_verifier),
        Ok(())
    );
}

#[test]
fn in_memory_forge_passes_contract() {
    assert_eq!(contract::forge::run(MemoryForge::new, silent_forge), Ok(()));
}

/// The scripts answer in order and an exhausted queue fails with the
/// operation's name instead of panicking.
#[test]
fn scripts_answer_in_order_then_fail_by_name() {
    use boneli_app::{Agent, TriageRequest, Verifier};
    let agent = MemoryAgent::new(AgentScript {
        triage: vec![
            Response::Answer(TriageReport {
                verdict: TriageVerdict::Ready,
                cost_micro_usd: 1,
            }),
            Response::Fail(silent()),
        ],
        write_reproduction: vec![Response::Answer(Written {
            content: b"t".to_vec(),
            cost_micro_usd: 2,
        })],
        analyze_root_cause: vec![Response::Answer(RootCauseReport {
            analysis: b"a".to_vec(),
            citations: vec![],
            cost_micro_usd: 3,
        })],
        write_fix: vec![],
    });
    let base = CommitSha::parse("0123456789abcdef0123456789abcdef01234567").expect("valid SHA");
    let request = TriageRequest {
        ticket: boneli_domain::Ticket {
            source: boneli_domain::TicketSource::Jira,
            key: String::from("K-1"),
            title: String::from("t"),
            body: String::new(),
        },
        base: base.clone(),
        previous: None,
    };
    assert_eq!(agent.triage(&request).map(|r| r.cost_micro_usd), Ok(1));
    let failed = agent.triage(&request).expect_err("scripted failure");
    assert_eq!(failed.detail(), "exit status 3, no error output");
    assert_eq!(failed.cost_micro_usd(), 10);
    let exhausted = agent.triage(&request).expect_err("script used up");
    assert_eq!(exhausted.detail(), "no scripted response for triage");
    assert_eq!(exhausted.cost_micro_usd(), 0);
    assert_eq!(agent.requests().len(), 3);

    let verifier = MemoryVerifier::new(VerifierScript::default());
    let checks = verifier.verify_fix(&base, b"d", b"t");
    assert_eq!(
        checks.map_err(|f| f.detail().to_owned()),
        Err::<FixChecks, _>(String::from("no scripted response for verify_fix"))
    );
}

fn path(text: &str) -> RelativePath {
    RelativePath::parse(text).expect("a valid path")
}

fn command(program: &str) -> Command {
    Command {
        program: String::from(program),
        args: vec![],
        environment: vec![],
    }
}

/// A sandbox with a program that writes a file and one that exits 3.
pub fn workspace() -> contract::sandbox::Workspace<MemorySandbox> {
    let done = |code| ExecResult {
        status: ExitStatus::Code(code),
        stdout: vec![],
        stderr: vec![],
    };
    contract::sandbox::Workspace {
        adapter: MemorySandbox::new(vec![
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
        ]),
        spec: SandboxSpec {
            phase: Phase::Verify,
            rootfs: RootfsRef::new(String::from("rootfs-1")),
        },
        limits: Limits {
            wall_ms: 1_000,
            memory_bytes: 1 << 20,
            processes: 1,
        },
        write: command("write"),
        path: path("out/result.txt"),
        content: b"written".to_vec(),
        exit: command("exit-3"),
        status: ExitStatus::Code(3),
    }
}

#[test]
fn in_memory_sandbox_passes_contract() {
    assert_eq!(contract::sandbox::run(workspace), Ok(()));
}

const BASE: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER: &str = "89abcdef0123456789abcdef0123456789abcdef";

/// A repository with one commit holding two files.
pub fn repository() -> contract::git::Repository<MemoryGit> {
    let repo = RepoUrl::new(String::from("https://example.invalid/app.git"));
    let base = CommitSha::parse(BASE).expect("valid SHA");
    let files: Tree = [
        (path("src/lib.rs"), b"fn total() {}\n".to_vec()),
        (path("README"), b"app".to_vec()),
    ]
    .into_iter()
    .collect();
    contract::git::Repository {
        adapter: MemoryGit::new(vec![GitCommit {
            repo: repo.clone(),
            sha: base.clone(),
            files,
        }]),
        repo,
        base,
        path: path("src/lib.rs"),
        content: b"fn total() {}\n".to_vec(),
        missing: path("src/missing.rs"),
        unknown: CommitSha::parse(OTHER).expect("valid SHA"),
        edited: b"fn total() { 1 }\n".to_vec(),
    }
}

/// Sets a file in a workspace of `MemoryGit`'s snapshot format.
pub fn edit(workspace: &[u8], file: &RelativePath, content: &[u8]) -> Vec<u8> {
    let mut tree = unpack_tree(workspace).expect("the adapter's own snapshot");
    tree.insert(file.clone(), content.to_vec());
    pack_tree(&tree)
}

#[test]
fn in_memory_git_passes_contract() {
    assert_eq!(contract::git::run(repository, edit), Ok(()));
}

fn image(name: &str) -> ImageRef {
    ImageRef {
        name: String::from(name),
        digest: format!("sha256:{name}"),
        platform: String::from("linux/amd64"),
    }
}

/// A store with one image.
pub fn images() -> contract::image::Images<MemoryImageStore> {
    contract::image::Images {
        adapter: MemoryImageStore::new(vec![image("library/postgres")]),
        present: image("library/postgres"),
        missing: image("library/node"),
    }
}

#[test]
fn in_memory_image_store_passes_contract() {
    assert_eq!(contract::image::run(images), Ok(()));
}

/// An adapter that can load one source with one row.
pub fn database() -> contract::data::Database<MemoryDataSnapshot> {
    let source = SnapshotSource::new(String::from("seed.sql"));
    contract::data::Database {
        adapter: MemoryDataSnapshot::new(vec![(source.clone(), vec![String::from("seed")])]),
        sandbox: SandboxId::new(String::from("sandbox-1")),
        source,
    }
}

/// Changes a copy by inserting a row and looks for that row.
pub struct RowProbe;

impl contract::data::Probe<MemoryDataSnapshot> for RowProbe {
    fn change(&self, adapter: &MemoryDataSnapshot, copy: &DatabaseCopy) -> Result<(), String> {
        adapter.insert(copy, "changed").map_err(|e| e.to_string())
    }

    fn changed(&self, adapter: &MemoryDataSnapshot, copy: &DatabaseCopy) -> Result<bool, String> {
        let rows = adapter.rows(copy).map_err(|e| e.to_string())?;
        Ok(rows.iter().any(|row| row == "changed"))
    }
}

#[test]
fn in_memory_data_snapshot_passes_contract() {
    assert_eq!(contract::data::run(database, &RowProbe), Ok(()));
}

/// A fixture cannot make a clause vacuous: content that an empty file would
/// match, a success status, unchanged content or a base that is its own
/// unknown commit is a violation, not a pass.
#[test]
fn vacuous_fixtures_are_violations() {
    let clause =
        |result: Result<(), contract::Violation>| result.map(|()| "").unwrap_or_else(|v| v.clause);
    let empty = || contract::sandbox::Workspace {
        content: vec![],
        ..workspace()
    };
    assert_eq!(
        clause(contract::sandbox::run(empty)),
        "copy-out-after-write"
    );
    let success = || contract::sandbox::Workspace {
        status: ExitStatus::Code(0),
        ..workspace()
    };
    assert_eq!(clause(contract::sandbox::run(success)), "exit-status");
    let unchanged = || {
        let r = repository();
        contract::git::Repository {
            edited: r.content.clone(),
            ..r
        }
    };
    assert_eq!(
        clause(contract::git::run(unchanged, edit)),
        "apply-then-read"
    );
    let own_base = || {
        let r = repository();
        contract::git::Repository {
            unknown: r.base.clone(),
            ..r
        }
    };
    assert_eq!(clause(contract::git::run(own_base, edit)), "unknown-commit");
}

/// The in-memory sandbox answers an unknown program as a shell does, and a
/// workspace from the sandbox cannot name a path outside the tree.
#[test]
fn unknown_program_and_hostile_workspace() {
    use boneli_app::{Git, Sandbox};
    let w = workspace();
    let id = w.adapter.create(&w.spec).expect("created");
    let ran = w.adapter.exec(&id, &command("make"), &w.limits);
    assert_eq!(
        ran,
        Ok(ExecResult {
            status: ExitStatus::Code(127),
            stdout: vec![],
            stderr: b"program not found".to_vec(),
        })
    );
    assert_eq!(w.adapter.commands().len(), 1);

    let r = repository();
    let base = r.adapter.fetch_base(&r.repo, &r.base).expect("fetched");
    // A workspace that names `../x`, packed by hand.
    let mut hostile = Vec::new();
    for field in [&b"../x"[..], b"payload"] {
        hostile.extend_from_slice(&(field.len() as u64).to_be_bytes());
        hostile.extend_from_slice(field);
    }
    assert!(matches!(
        r.adapter.diff(&base, &hostile),
        Err(boneli_app::GitError::Failed { .. })
    ));
    // A length past the end is an error, not a panic.
    let truncated = u64::MAX.to_be_bytes();
    assert!(matches!(
        r.adapter.diff(&base, &truncated),
        Err(boneli_app::GitError::Failed { .. })
    ));
    // A removed file round-trips through diff and apply.
    let mut tree = unpack_tree(&r.adapter.snapshot(&base).expect("snapshot")).expect("unpacked");
    tree.remove(&path("README"));
    let diff = r.adapter.diff(&base, &pack_tree(&tree)).expect("diff");
    let after = r.adapter.apply(&base, &diff).expect("applied");
    assert_eq!(r.adapter.read(&after, &path("README")), Ok(None));
    assert_eq!(
        r.adapter.read(&base, &path("README")),
        Ok(Some(b"app".to_vec()))
    );
}
