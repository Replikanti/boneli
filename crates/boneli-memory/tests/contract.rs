//! Every in-memory adapter passes its port's contract suite (ADR-004, D2).

use std::sync::atomic::{AtomicU64, Ordering};

use boneli_app::contract::{self, SilentFailure};
use boneli_app::{
    BranchName, Broker, BrokerName, Command, ContainerName, ContainerSpec, DatabaseCopy,
    ExecResult, ExitStatus, ImageExemption, ImageOrigin, ImageRef, Limits, Phase, PodLimits,
    RelativePath, RepoUrl, RootCauseReport, RootfsRef, SandboxId, SandboxSpec, SnapshotSource,
    TreePath, TriageReport, WorkspaceBytes, Written,
};
use boneli_domain::{CitationStatus, CommitSha, FixChecks, TriageVerdict};
use boneli_memory::{
    AgentScript, ForgeScript, GitCommit, MemoryAgent, MemoryDataSnapshot, MemoryEventStore,
    MemoryForge, MemoryGit, MemoryImageStore, MemorySandbox, MemoryVerifier, Program, Response,
    ScriptedFailure, SequentialIds, StepClock, Tree, VerifierScript, WORKSPACE, Write, pack_tree,
    unpack_tree,
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
    assert_eq!(
        contract::forge::run(MemoryForge::new, silent_forge, &contract::sample_ticket()),
        Ok(())
    );
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

/// A tree path, of any bytes.
fn tpath(bytes: &[u8]) -> TreePath {
    TreePath::parse(bytes).expect("a valid tree path")
}

/// The base's files whose paths the citation rule refuses, one of each
/// class: a backslash, a blank name, a name that is not UTF-8 (ADR-018).
pub fn uncitable() -> Vec<(TreePath, Vec<u8>)> {
    vec![
        (tpath(b"dir\\file"), b"backslash\n".to_vec()),
        (tpath(b" "), b"blank\n".to_vec()),
        (tpath(b"x\xff"), b"not UTF-8\n".to_vec()),
    ]
}

/// The base commit's files: two content files and [`uncitable`].
pub fn base_files() -> Tree {
    let mut files: Tree = [
        (tpath(b"src/lib.rs"), b"fn total() {}\n".to_vec()),
        (tpath(b"README"), b"app".to_vec()),
    ]
    .into_iter()
    .collect();
    files.extend(uncitable());
    files
}

/// The first container of the sandbox fixture.
fn app() -> ContainerName {
    ContainerName::parse("app").expect("a valid name")
}

fn command(program: &str) -> Command {
    Command {
        container: app(),
        program: String::from(program),
        args: vec![],
        environment: vec![],
    }
}

/// Pod limits that fit every spec the sandbox suite builds.
pub fn pod_limits() -> PodLimits {
    PodLimits {
        memory_bytes: 1 << 30,
        processes: 16,
        cpu_millis: 1_000,
        workspace_bytes: 1 << 20,
        workspace_inodes: 1_000,
        tmp_bytes: 1 << 20,
        shm_bytes: 1 << 20,
    }
}

/// A scripted program that ends with `code`.
fn program(name: &str, code: i32) -> Program {
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

/// The programs of the sandbox fixture: `write` writes `out/result.txt`,
/// `exit-3` exits 3, `plant` writes `/tmp/planted/result.txt` outside the
/// workspace, `link` makes `out/result.txt` a symlink to it, `through`
/// makes `out` a symlink to its directory, `read` copies `out/result.txt`
/// to `copied.txt`, `overwrite` writes `out/result.txt` again, `relative`
/// links it to `../sentinel.txt`, which it writes, `print` prints
/// `printed`, `serve` writes like `write` as a service, and `settle` does
/// nothing, because a scripted service has written when `start` returns.
pub fn sandbox_programs() -> Vec<Program> {
    vec![
        Program {
            writes: vec![(path("out/result.txt"), Write::File(b"written".to_vec()))],
            ..program("write", 0)
        },
        program("exit-3", 3),
        Program {
            outside: vec![(String::from("/tmp/planted/result.txt"), b"outside".to_vec())],
            ..program("plant", 0)
        },
        Program {
            writes: vec![(
                path("out/result.txt"),
                Write::Symlink(b"/tmp/planted/result.txt".to_vec()),
            )],
            ..program("link", 0)
        },
        Program {
            writes: vec![(path("out"), Write::Symlink(b"/tmp/planted".to_vec()))],
            ..program("through", 0)
        },
        Program {
            copies: vec![(format!("{WORKSPACE}/out/result.txt"), path("copied.txt"))],
            ..program("read", 0)
        },
        Program {
            writes: vec![(path("out/result.txt"), Write::File(b"overwritten".to_vec()))],
            ..program("overwrite", 0)
        },
        Program {
            writes: vec![
                (path("sentinel.txt"), Write::File(b"outside".to_vec())),
                (
                    path("out/result.txt"),
                    Write::Symlink(b"../sentinel.txt".to_vec()),
                ),
            ],
            ..program("relative", 0)
        },
        Program {
            result: ExecResult {
                status: ExitStatus::Code(0),
                stdout: b"printed".to_vec(),
                stderr: vec![],
            },
            ..program("print", 0)
        },
        Program {
            writes: vec![(path("out/result.txt"), Write::File(b"written".to_vec()))],
            ..program("serve", 0)
        },
        program("settle", 0),
    ]
}

/// A sandbox with the programs of [`sandbox_programs`].
pub fn workspace() -> contract::sandbox::Workspace<MemorySandbox> {
    contract::sandbox::Workspace {
        adapter: MemorySandbox::new(sandbox_programs()),
        spec: SandboxSpec {
            phase: Phase::Verify,
            containers: vec![ContainerSpec {
                name: app(),
                rootfs: RootfsRef::new(String::from("rootfs-1")),
            }],
            workspace: WorkspaceBytes::new(vec![]),
            dependencies: vec![],
            brokers: vec![],
            limits: pod_limits(),
            user: 1000,
        },
        limits: Limits {
            wall_ms: 1_000,
            output_bytes: 1 << 20,
        },
        write: command("write"),
        path: path("out/result.txt"),
        content: b"written".to_vec(),
        exit: command("exit-3"),
        status: ExitStatus::Code(3),
        container: ContainerSpec {
            name: ContainerName::parse("db").expect("a valid name"),
            rootfs: RootfsRef::new(String::from("rootfs-2")),
        },
        plant: command("plant"),
        outside: b"outside".to_vec(),
        link: command("link"),
        through: command("through"),
        broker: Broker {
            name: BrokerName::parse("sql").expect("a valid name"),
            socket: String::from("/run/brokers/sql.sock"),
        },
        dependency: path("out"),
        read: command("read"),
        copied: path("copied.txt"),
        overwrite: command("overwrite"),
        overwritten: b"overwritten".to_vec(),
        relative: command("relative"),
        print: command("print"),
        printed: b"printed".to_vec(),
        service: command("serve"),
        settle: command("settle"),
    }
}

#[test]
fn in_memory_sandbox_passes_contract() {
    assert_eq!(contract::sandbox::run(workspace, edit), Ok(()));
}

const BASE: &str = "0123456789abcdef0123456789abcdef01234567";
const OTHER: &str = "89abcdef0123456789abcdef0123456789abcdef";

/// A repository with one commit holding two files and one uncitable file
/// of each class.
pub fn repository() -> contract::git::Repository<MemoryGit> {
    let repo = RepoUrl::new(String::from("https://example.invalid/app.git"));
    let base = CommitSha::parse(BASE).expect("valid SHA");
    let files = base_files();
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
        metadata: metadata(),
        uncitable: uncitable(),
    }
}

/// Repository metadata an agent could leave in a workspace: a config that
/// names a command for `core.fsmonitor` and a hooks directory, a hook git
/// runs when it writes an index, and the config of a nested repository.
/// The sentinel is an absolute path outside anything an adapter creates or
/// removes, unique to each fixture, as `Tripwire` requires; `MemoryGit`
/// runs nothing, so here it is only an example and is never created.
pub fn metadata() -> Vec<(RelativePath, Vec<u8>)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let sentinel = std::env::temp_dir()
        .join(format!("boneli-tripwire-{}-{n}", std::process::id()))
        .join("tripped");
    let touch = format!("touch {}", sentinel.display());
    vec![
        (
            path(".git/config"),
            format!("[core]\n\tfsmonitor = {touch}\n\thooksPath = .git/hooks\n").into_bytes(),
        ),
        (
            path(".git/hooks/post-index-change"),
            format!("#!/bin/sh\n{touch}\n").into_bytes(),
        ),
        (
            path("sub/.git/config"),
            format!("[core]\n\tfsmonitor = {touch}\n").into_bytes(),
        ),
    ]
}

/// `MemoryGit` runs nothing, so nothing it does can trip.
pub struct NothingRuns;

impl contract::git::Tripwire<MemoryGit> for NothingRuns {
    fn tripped(&self, _adapter: &MemoryGit) -> Result<Vec<String>, String> {
        Ok(vec![])
    }
}

/// The remote of `MemoryGit` is its own state.
pub struct MemoryRemote;

impl contract::git::Remote<MemoryGit> for MemoryRemote {
    fn branch(
        &self,
        adapter: &MemoryGit,
        repo: &RepoUrl,
        branch: &BranchName,
    ) -> Result<Option<(CommitSha, Vec<CommitSha>)>, String> {
        Ok(adapter.branch(repo, branch))
    }
}

/// One field of `MemoryGit`'s formats; `None` when it runs past the end.
fn take_field<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length: [u8; 8] = rest.get(..8)?.try_into().ok()?;
    let n = usize::try_from(u64::from_be_bytes(length)).ok()?;
    let bytes = rest.get(8..8usize.checked_add(n)?)?;
    *rest = &rest[8 + n..];
    Some(bytes)
}

fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Moves every change of `from` in a diff of `MemoryGit`'s format to `to`;
/// a malformed diff comes back as it was.
pub fn retarget(diff: &[u8], from: &RelativePath, to: &RelativePath) -> Vec<u8> {
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

/// Sets or removes a file in a workspace of `MemoryGit`'s snapshot format.
pub fn edit(workspace: &[u8], file: &TreePath, content: Option<&[u8]>) -> Vec<u8> {
    let mut tree = unpack_tree(workspace).expect("the adapter's own snapshot");
    match content {
        Some(content) => tree.insert(file.clone(), content.to_vec()),
        None => tree.remove(file),
    };
    pack_tree(&tree)
}

#[test]
fn in_memory_git_passes_contract() {
    assert_eq!(
        contract::git::run(repository, edit, retarget, &NothingRuns, &MemoryRemote),
        Ok(())
    );
}

fn git_clause(result: Result<(), contract::Violation>) -> (&'static str, String) {
    match result {
        Ok(()) => ("", String::new()),
        Err(v) => (v.clause, v.detail),
    }
}

/// A metadata fixture that holds a content path would let an adapter that
/// treats metadata as content pass `same-diff` on that entry alone.
#[test]
fn metadata_fixture_must_be_metadata() {
    let content = || {
        let mut r = repository();
        r.metadata.push((path("src/x.rs"), b"fn x() {}\n".to_vec()));
        r
    };
    let (clause, detail) = git_clause(contract::git::run(
        content,
        edit,
        retarget,
        &NothingRuns,
        &MemoryRemote,
    ));
    assert_eq!(clause, "workspace-metadata-inert", "{detail}");
    assert!(detail.starts_with("fixture:"), "{detail}");
    assert!(detail.contains("src/x.rs"), "{detail}");
}

/// An `edit` that never writes metadata into the workspace makes the
/// clause vacuous: the adapter never sees any (review of #61).
#[test]
fn metadata_fixture_must_reach_the_workspace() {
    let skipping = |w: &[u8], p: &TreePath, c: Option<&[u8]>| {
        if p.is_repository_metadata() {
            w.to_vec()
        } else {
            edit(w, p, c)
        }
    };
    let (clause, detail) = git_clause(contract::git::run(
        repository,
        skipping,
        retarget,
        &NothingRuns,
        &MemoryRemote,
    ));
    assert_eq!(clause, "workspace-metadata-inert", "{detail}");
    assert!(detail.starts_with("fixture:"), "{detail}");
}

/// `apply-refuses` is only as good as the diff it applies: a `retarget`
/// that makes garbage, or ignores its target, is a violation, and so is a
/// base that already has the twin path.
#[test]
fn retarget_must_make_a_diff_that_applies() {
    let garbage = |_: &[u8], _: &RelativePath, _: &RelativePath| b"garbage".to_vec();
    let ignores = |d: &[u8], _: &RelativePath, _: &RelativePath| d.to_vec();
    for result in [
        contract::git::run(repository, edit, garbage, &NothingRuns, &MemoryRemote),
        contract::git::run(repository, edit, ignores, &NothingRuns, &MemoryRemote),
    ] {
        let (clause, detail) = git_clause(result);
        assert_eq!(clause, "workspace-metadata-inert", "{detail}");
        assert!(detail.starts_with("fixture:"), "{detail}");
        assert!(detail.contains("retarget"), "{detail}");
    }
    let twin_exists = || {
        let r = repository();
        let mut files = base_files();
        files.insert(tpath(b"src/missing.rs.twin"), b"here".to_vec());
        contract::git::Repository {
            adapter: MemoryGit::new(vec![GitCommit {
                repo: r.repo.clone(),
                sha: r.base.clone(),
                files,
            }]),
            ..r
        }
    };
    let (clause, detail) = git_clause(contract::git::run(
        twin_exists,
        edit,
        retarget,
        &NothingRuns,
        &MemoryRemote,
    ));
    assert_eq!(clause, "workspace-metadata-inert", "{detail}");
    assert!(detail.starts_with("fixture:"), "{detail}");
    assert!(detail.contains("twin"), "{detail}");
}

/// Every metadata entry must reach the workspace on its own and in the
/// full set: an `edit` that skips the nested entry, or drops it once the
/// top-level `.git` is there, would let an adapter that drops only the
/// top-level `.git` pass (review round 2 of #61).
#[test]
fn metadata_fixture_entries_each_reach_the_workspace() {
    let skip_nested = |w: &[u8], p: &TreePath, c: Option<&[u8]>| {
        if p.is_repository_metadata() && !p.as_bytes().starts_with(b".git/") {
            w.to_vec()
        } else {
            edit(w, p, c)
        }
    };
    let drop_nested_later = |w: &[u8], p: &TreePath, c: Option<&[u8]>| {
        let top = unpack_tree(w)
            .expect("a workspace")
            .keys()
            .any(|k| k.as_bytes().starts_with(b".git/"));
        if top && p.is_repository_metadata() && !p.as_bytes().starts_with(b".git/") {
            w.to_vec()
        } else {
            edit(w, p, c)
        }
    };
    for result in [
        contract::git::run(
            repository,
            skip_nested,
            retarget,
            &NothingRuns,
            &MemoryRemote,
        ),
        contract::git::run(
            repository,
            drop_nested_later,
            retarget,
            &NothingRuns,
            &MemoryRemote,
        ),
    ] {
        let (clause, detail) = git_clause(result);
        assert_eq!(clause, "workspace-metadata-inert", "{detail}");
        assert!(detail.starts_with("fixture:"), "{detail}");
        assert!(detail.contains("sub/.git/config"), "{detail}");
    }
}

/// The refusal must come from the metadata rule, not from a diff that
/// `retarget` broke for metadata targets: a diff retargeted to each
/// metadata path and back must apply (review round 2 of #61).
#[test]
fn retarget_must_round_trip_through_metadata_paths() {
    let garbles_metadata = |d: &[u8], from: &RelativePath, to: &RelativePath| {
        if to.is_repository_metadata() {
            b"garbage".to_vec()
        } else {
            retarget(d, from, to)
        }
    };
    let (clause, detail) = git_clause(contract::git::run(
        repository,
        edit,
        garbles_metadata,
        &NothingRuns,
        &MemoryRemote,
    ));
    assert_eq!(clause, "workspace-metadata-inert", "{detail}");
    assert!(detail.starts_with("fixture:"), "{detail}");
    assert!(detail.contains(".git/config"), "{detail}");
}

/// Each fixture gets its own sentinel, so tests that run in parallel cannot
/// clear each other's (review round 2 of #61).
#[test]
fn fixture_sentinels_are_unique() {
    assert_ne!(repository().metadata, repository().metadata);
}

/// No metadata: every adapter would pass, so it is a violation.
#[test]
fn metadata_fixture_must_not_be_empty() {
    let empty = || contract::git::Repository {
        metadata: vec![],
        ..repository()
    };
    let (clause, detail) = git_clause(contract::git::run(
        empty,
        edit,
        retarget,
        &NothingRuns,
        &MemoryRemote,
    ));
    assert_eq!(clause, "workspace-metadata-inert", "{detail}");
    assert!(detail.starts_with("fixture:"), "{detail}");
}

/// Fixtures that would make `uncitable-paths-carried` vacuous are
/// violations, not passes (ADR-018, D6): an empty list, a list without a
/// class, a citable or metadata path in it, an `edit` that skips
/// uncitable paths, and a base that has a twin.
#[test]
fn uncitable_fixture_guards() {
    let with = |list: Vec<(TreePath, Vec<u8>)>| {
        move || contract::git::Repository {
            uncitable: list.clone(),
            ..repository()
        }
    };
    let without = |k: usize| {
        let mut list = uncitable();
        list.remove(k);
        list
    };
    let plus = |p: &[u8]| {
        let mut list = uncitable();
        list.push((tpath(p), b"x".to_vec()));
        list
    };
    let skipping = |w: &[u8], p: &TreePath, c: Option<&[u8]>| {
        if p.citable().is_err() {
            w.to_vec()
        } else {
            edit(w, p, c)
        }
    };
    let twin_at_base = || {
        let r = repository();
        let mut files = base_files();
        files.insert(tpath(" \u{200B}".as_bytes()), b"twin".to_vec());
        contract::git::Repository {
            adapter: MemoryGit::new(vec![GitCommit {
                repo: r.repo.clone(),
                sha: r.base.clone(),
                files,
            }]),
            ..r
        }
    };
    let run = |make: &dyn Fn() -> contract::git::Repository<MemoryGit>| {
        contract::git::run(make, edit, retarget, &NothingRuns, &MemoryRemote)
    };
    let cases: Vec<(&str, Result<(), contract::Violation>, &str)> = vec![
        ("empty", run(&with(vec![])), "no uncitable paths"),
        ("no backslash", run(&with(without(0))), "a backslash"),
        ("no blank", run(&with(without(1))), "blank"),
        ("no non-UTF-8", run(&with(without(2))), "not UTF-8"),
        (
            "citable",
            run(&with(plus(b"src/lib.rs"))),
            "path 3 is citable",
        ),
        (
            "metadata",
            run(&with(plus(b".git/x\\y"))),
            "path 3 is repository metadata",
        ),
        (
            "skipping edit",
            contract::git::run(repository, skipping, retarget, &NothingRuns, &MemoryRemote),
            "does not write path 0",
        ),
        ("twin at the base", run(&twin_at_base), "twin of path 1"),
    ];
    for (name, result, words) in cases {
        let (clause, detail) = git_clause(result);
        assert_eq!(clause, "uncitable-paths-carried", "{name}: {detail}");
        assert!(detail.starts_with("fixture:"), "{name}: {detail}");
        assert!(detail.contains(words), "{name}: {detail}");
    }
}

/// `MemoryGit` carries uncitable paths through its formats: unpacking
/// takes the tree path rule, so a backslash, a blank name and a name that
/// is not UTF-8 round-trip, and `..` is still refused.
#[test]
fn memory_formats_carry_uncitable_paths() {
    let tree = base_files();
    assert_eq!(unpack_tree(&pack_tree(&tree)), Ok(tree));
    let mut packed = Vec::new();
    for field in [&b"a/../b"[..], b"x"] {
        packed.extend_from_slice(&(field.len() as u64).to_be_bytes());
        packed.extend_from_slice(field);
    }
    assert!(unpack_tree(&packed).is_err());
}

/// A tripwire that is already tripped cannot tell what the clause caused.
#[test]
fn tripped_before_the_clause_is_a_violation() {
    struct AlwaysTripped;
    impl contract::git::Tripwire<MemoryGit> for AlwaysTripped {
        fn tripped(&self, _adapter: &MemoryGit) -> Result<Vec<String>, String> {
            Ok(vec![String::from("left over from an earlier run")])
        }
    }
    let (clause, detail) = git_clause(contract::git::run(
        repository,
        edit,
        retarget,
        &AlwaysTripped,
        &MemoryRemote,
    ));
    assert_eq!(clause, "workspace-metadata-inert", "{detail}");
    assert!(detail.starts_with("fixture:"), "{detail}");
    // A tripwire that cannot look is a violation too, not a pass.
    struct Blind;
    impl contract::git::Tripwire<MemoryGit> for Blind {
        fn tripped(&self, _adapter: &MemoryGit) -> Result<Vec<String>, String> {
            Err(String::from("cannot read the sentinel directory"))
        }
    }
    let (clause, detail) = git_clause(contract::git::run(
        repository,
        edit,
        retarget,
        &Blind,
        &MemoryRemote,
    ));
    assert_eq!(clause, "workspace-metadata-inert", "{detail}");
    assert!(detail.contains("cannot read"), "{detail}");
}

/// Repository metadata in a workspace is not content: the diff is the one
/// of the same workspace without it.
#[test]
fn memory_diff_drops_repository_metadata() {
    use boneli_app::Git;
    let r = repository();
    let base = r.adapter.fetch_base(&r.repo, &r.base).expect("fetched");
    let snapshot = r.adapter.snapshot(&base).expect("snapshot");
    let plain = edit(&snapshot, &TreePath::from(&r.path), Some(&r.edited));
    let mut hostile = plain.clone();
    for (file, content) in [
        (
            ".git/config",
            &b"[core]\n\tfsmonitor = touch /tmp/boneli-tripwire/tripped\n"[..],
        ),
        ("sub/.git/HEAD", b"ref: refs/heads/main\n"),
    ] {
        hostile = edit(&hostile, &tpath(file.as_bytes()), Some(content));
    }
    let expected = r.adapter.diff(&base, &plain).expect("diff");
    assert!(!expected.is_empty());
    assert_eq!(r.adapter.diff(&base, &hostile), Ok(expected));
    // Metadata alone is an unchanged workspace.
    let only = edit(&snapshot, &tpath(b".git/config"), Some(b"[core]\n"));
    assert_eq!(r.adapter.diff(&base, &only), Ok(vec![]));
}

/// A diff that writes or removes a metadata path does not apply, as
/// `git apply` refuses it with "invalid path".
#[test]
fn memory_apply_refuses_metadata_paths() {
    use boneli_app::Git;
    let r = repository();
    let base = r.adapter.fetch_base(&r.repo, &r.base).expect("fetched");
    let field = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    // Sets `.git/config`, packed by hand in `MemoryGit`'s diff format.
    let mut sets = Vec::new();
    field(&mut sets, b".git/config");
    sets.push(1);
    field(&mut sets, b"[core]\n");
    // Removes `sub/.git`.
    let mut removes = Vec::new();
    field(&mut removes, b"sub/.git");
    removes.push(0);
    for diff in [sets, removes] {
        assert!(matches!(
            r.adapter.apply(&base, &diff),
            Err(boneli_app::GitError::Failed { .. })
        ));
    }
    // Nothing was created: the next checkout is the second one.
    let next = r.adapter.fetch_base(&r.repo, &r.base).expect("fetched");
    assert_eq!(next.as_str(), "checkout-2");
}

fn image(name: &str, digest: &str, platform: &str) -> ImageRef {
    ImageRef {
        name: String::from(name),
        digest: String::from(digest),
        platform: String::from(platform),
        origin: ImageOrigin::Operator,
    }
}

fn agent(image: ImageRef) -> ImageRef {
    ImageRef {
        origin: ImageOrigin::Agent,
        ..image
    }
}

/// A store with one image, refs that differ from it in one field, and
/// two images for the agent, one of them exempted by name.
pub fn images() -> contract::image::Images<MemoryImageStore> {
    let present = image("library/postgres", "sha256:aa", "linux/amd64");
    let agent_refused = agent(image("acme/app", "sha256:dd", "linux/amd64"));
    let agent_exempted = agent(image("library/mailhog", "sha256:ee", "linux/amd64"));
    let exemption = ImageExemption {
        registry: String::from("docker.io"),
        scope: String::from("library/"),
    };
    contract::image::Images {
        adapter: MemoryImageStore::new(vec![
            present.clone(),
            agent_refused.clone(),
            agent_exempted.clone(),
        ])
        .with_tampered(vec![image("library/redis", "sha256:cc", "linux/amd64")])
        .with_agent_exemptions(vec![(agent_exempted.name.clone(), exemption)]),
        present,
        missing: image("library/node", "sha256:aa", "linux/amd64"),
        other_digest: image("library/postgres", "sha256:bb", "linux/amd64"),
        other_platform: image("library/postgres", "sha256:aa", "linux/arm64"),
        tampered: image("library/redis", "sha256:cc", "linux/amd64"),
        agent_refused,
        agent_exempted,
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
        clause(contract::sandbox::run(empty, edit)),
        "copy-out-after-write"
    );
    let success = || contract::sandbox::Workspace {
        status: ExitStatus::Code(0),
        ..workspace()
    };
    assert_eq!(clause(contract::sandbox::run(success, edit)), "exit-status");
    let unplanted = || contract::sandbox::Workspace {
        outside: vec![],
        ..workspace()
    };
    assert_eq!(
        clause(contract::sandbox::run(unplanted, edit)),
        "copy-out-no-symlink"
    );
    let elsewhere = || contract::sandbox::Workspace {
        dependency: path("vendor"),
        ..workspace()
    };
    assert_eq!(
        clause(contract::sandbox::run(elsewhere, edit)),
        "seal-prepare-only"
    );
    let into_dependency = || contract::sandbox::Workspace {
        copied: path("out/copy.txt"),
        ..workspace()
    };
    assert_eq!(
        clause(contract::sandbox::run(into_dependency, edit)),
        "seal-prepare-only"
    );
    let no_edit = |w: &[u8], _: &TreePath, _: Option<&[u8]>| w.to_vec();
    assert_eq!(
        clause(contract::sandbox::run(workspace, no_edit)),
        "export-round-trip"
    );
    let same_overwrite = || contract::sandbox::Workspace {
        overwritten: b"written".to_vec(),
        ..workspace()
    };
    assert_eq!(
        clause(contract::sandbox::run(same_overwrite, edit)),
        "seal-prepare-only"
    );
    let silent = || contract::sandbox::Workspace {
        printed: vec![],
        ..workspace()
    };
    assert_eq!(clause(contract::sandbox::run(silent, edit)), "output-cap");
    // Review run 1 of #147: a workspace that already holds the copy
    // target would let an adapter pass without mounting the layer.
    let preseeded = || {
        let mut w = workspace();
        let bytes = edit(
            w.spec.workspace.as_bytes(),
            &TreePath::from(&w.copied),
            Some(&w.content),
        );
        w.spec.workspace = WorkspaceBytes::new(bytes);
        w
    };
    assert_eq!(
        clause(contract::sandbox::run(preseeded, edit)),
        "sealed-layer-mounted"
    );
    let taken = || {
        let w = workspace();
        contract::sandbox::Workspace {
            container: w.spec.containers[0].clone(),
            ..w
        }
    };
    assert_eq!(
        clause(contract::sandbox::run(taken, edit)),
        "unknown-container"
    );
    let unchanged = || {
        let r = repository();
        contract::git::Repository {
            edited: r.content.clone(),
            ..r
        }
    };
    assert_eq!(
        clause(contract::git::run(
            unchanged,
            edit,
            retarget,
            &NothingRuns,
            &MemoryRemote
        )),
        "apply-then-read"
    );
    let own_base = || {
        let r = repository();
        contract::git::Repository {
            unknown: r.base.clone(),
            ..r
        }
    };
    assert_eq!(
        clause(contract::git::run(
            own_base,
            edit,
            retarget,
            &NothingRuns,
            &MemoryRemote
        )),
        "unknown-commit"
    );
    let same_digest = || contract::image::Images {
        other_digest: images().present,
        ..images()
    };
    assert_eq!(clause(contract::image::run(same_digest)), "digest-pinned");
    let other_name = || {
        let i = images();
        contract::image::Images {
            other_platform: ImageRef {
                name: String::from("library/node"),
                ..i.other_platform.clone()
            },
            ..i
        }
    };
    assert_eq!(clause(contract::image::run(other_name)), "platform-pinned");
    // The agent clauses check their fixture too: an agent image that says
    // `Operator`, and one the operator cannot pull either, are fixture
    // violations, not passes (ADR-032).
    let fixture = |result: Result<(), contract::Violation>, name: &str| {
        let violation = result.expect_err("a vacuous fixture must not pass");
        assert_eq!(violation.clause, name);
        assert!(violation.detail.starts_with("fixture:"), "{violation:?}");
    };
    let operator_refused = || {
        let i = images();
        contract::image::Images {
            agent_refused: ImageRef {
                origin: ImageOrigin::Operator,
                ..i.agent_refused.clone()
            },
            ..i
        }
    };
    fixture(
        contract::image::run(operator_refused),
        "agent-origin-refused",
    );
    let unknown_refused = || {
        let i = images();
        contract::image::Images {
            agent_refused: agent(image("acme/none", "sha256:dd", "linux/amd64")),
            ..i
        }
    };
    fixture(
        contract::image::run(unknown_refused),
        "agent-origin-refused",
    );
    let operator_exempted = || {
        let i = images();
        contract::image::Images {
            agent_exempted: ImageRef {
                origin: ImageOrigin::Operator,
                ..i.agent_exempted.clone()
            },
            ..i
        }
    };
    fixture(
        contract::image::run(operator_exempted),
        "exemption-reported",
    );
}

/// The origin never changes the root filesystem: an agent's exempted pull
/// and the operator's pull of the same image get the same handle, and
/// only the agent's reports the exemption (ADR-032).
#[test]
fn memory_image_origin_keeps_the_rootfs() {
    use boneli_app::ImageStore;
    let i = images();
    let by_agent = i.adapter.pull(&i.agent_exempted).expect("agent pull");
    let by_operator = i
        .adapter
        .pull(&ImageRef {
            origin: ImageOrigin::Operator,
            ..i.agent_exempted.clone()
        })
        .expect("operator pull");
    assert_eq!(by_agent.rootfs, by_operator.rootfs);
    assert!(by_agent.exemption.is_some());
    assert_eq!(by_operator.exemption, None);
    // Refused first: an agent's image outside the set is Failed, not
    // NotFound.
    match i
        .adapter
        .pull(&agent(image("acme/none", "sha256:dd", "linux/amd64")))
    {
        Err(boneli_app::ImageError::Failed { detail }) => {
            assert!(detail.contains("not exempted"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
}

/// The four infra ports stay object-safe: roots hold them as `&dyn`
/// (ADR-004, D1), and a generic method would break that only when a
/// consumer lands.
#[test]
fn infra_ports_are_object_safe() {
    use boneli_app::{DataSnapshot, Git, ImageStore, Sandbox};
    let sandbox = workspace().adapter;
    let git = repository().adapter;
    let images = images().adapter;
    let data = database().adapter;
    let ports: (&dyn Sandbox, &dyn Git, &dyn ImageStore, &dyn DataSnapshot) =
        (&sandbox, &git, &images, &data);
    let spec = workspace().spec;
    assert!(ports.0.create(&spec).is_ok());
    assert_eq!(
        ports
            .1
            .fetch_base(&repository().repo, &repository().unknown),
        Err(boneli_app::GitError::UnknownCommit)
    );
    assert_eq!(
        ports
            .2
            .pull(&image("library/node", "sha256:aa", "linux/amd64")),
        Err(boneli_app::ImageError::NotFound)
    );
    assert_eq!(
        ports
            .3
            .remove_copy(&DatabaseCopy::new(String::from("copy-9"))),
        Err(boneli_app::DataError::UnknownCopy)
    );
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
    // A path given twice is an error, not a silent overwrite.
    let mut twice = Vec::new();
    for field in [&b"src/lib.rs"[..], b"one", b"src/lib.rs", b"two"] {
        twice.extend_from_slice(&(field.len() as u64).to_be_bytes());
        twice.extend_from_slice(field);
    }
    assert!(unpack_tree(&twice).is_err());
    assert!(matches!(
        r.adapter.diff(&base, &twice),
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
    tree.remove(&tpath(b"README"));
    let diff = r.adapter.diff(&base, &pack_tree(&tree)).expect("diff");
    let after = r.adapter.apply(&base, &diff).expect("applied");
    assert_eq!(r.adapter.read(&after, &path("README")), Ok(None));
    assert_eq!(
        r.adapter.read(&base, &path("README")),
        Ok(Some(b"app".to_vec()))
    );
}

/// Pushed commit ids come from a counter, as long as the base's id, so a
/// replayed run gets the same ids; an id that a fixed commit of the
/// repository already has is refused rather than shadowed.
#[test]
fn memory_git_push_ids() {
    use boneli_app::{BranchName, CommitInfo, Git, GitError};
    let taken = format!("{:040x}", 2);
    let mut r = repository();
    let tree = unpack_tree(
        &r.adapter
            .snapshot(&r.adapter.fetch_base(&r.repo, &r.base).expect("fetch"))
            .expect("snapshot"),
    )
    .expect("tree");
    r.adapter = MemoryGit::new(vec![
        GitCommit {
            repo: r.repo.clone(),
            sha: r.base.clone(),
            files: tree.clone(),
        },
        GitCommit {
            repo: r.repo.clone(),
            sha: CommitSha::parse(&taken).expect("valid SHA"),
            files: tree,
        },
    ]);
    let info = CommitInfo::new("t", "t@example.invalid", "m").expect("valid");
    let branch = |n: &str| BranchName::parse(n).expect("valid");
    let c = r.adapter.fetch_base(&r.repo, &r.base).expect("fetch");
    let first = r
        .adapter
        .push(&c, &branch("boneli/a"), &info)
        .expect("push");
    assert_eq!(first.as_str(), format!("{:040x}", 1));
    let got = r.adapter.push(&c, &branch("boneli/b"), &info);
    assert!(
        matches!(&got, Err(GitError::Failed { detail }) if detail.contains("taken")),
        "{got:?}"
    );
    assert_eq!(r.adapter.branch(&r.repo, &branch("boneli/b")), None);
    assert_eq!(
        r.adapter.branch(&r.repo, &branch("boneli/a")),
        Some((first, vec![r.base.clone()]))
    );
}

// ------------------------------------------------- MemorySandbox edge cases

/// A sandbox fixture spec with this workspace, phase and dependencies.
fn pod(tree: &Tree, phase: Phase, dependencies: Vec<boneli_app::LayerRef>) -> SandboxSpec {
    SandboxSpec {
        phase,
        workspace: WorkspaceBytes::new(pack_tree(tree)),
        dependencies,
        ..workspace().spec
    }
}

/// A layer sealed at `out` with `out/result.txt` in it.
fn out_layer(adapter: &MemorySandbox) -> boneli_app::LayerRef {
    use boneli_app::Sandbox;
    let p = adapter
        .create(&pod(&Tree::new(), Phase::Prepare, vec![]))
        .expect("created");
    adapter
        .exec(&p, &command("write"), &workspace().limits)
        .expect("ran");
    adapter.seal(&p, &[path("out")]).expect("sealed")
}

fn is_failed<T>(result: &Result<T, boneli_app::SandboxError>) -> bool {
    matches!(result, Err(boneli_app::SandboxError::Failed { .. }))
}

#[test]
fn empty_workspace_round_trips() {
    use boneli_app::Sandbox;
    let w = workspace();
    let id = w.adapter.create(&w.spec).expect("created");
    assert_eq!(w.adapter.export(&id), Ok(vec![]));
}

#[test]
fn seal_needs_paths() {
    use boneli_app::Sandbox;
    let w = workspace();
    let p = w
        .adapter
        .create(&pod(&Tree::new(), Phase::Prepare, vec![]))
        .expect("created");
    w.adapter.exec(&p, &w.write, &w.limits).expect("ran");
    assert!(is_failed(&w.adapter.seal(&p, &[])));
    // A path with nothing beneath it, and a file, are no directory.
    assert!(is_failed(&w.adapter.seal(&p, &[path("vendor")])));
    assert!(is_failed(&w.adapter.seal(&p, &[path("out/result.txt")])));
    assert!(w.adapter.seal(&p, &[path("out")]).is_ok());
}

#[test]
fn copy_out_empty_file() {
    use boneli_app::Sandbox;
    let adapter = MemorySandbox::new(vec![Program {
        writes: vec![(path("empty"), Write::File(vec![]))],
        ..program("touch", 0)
    }]);
    let id = adapter.create(&workspace().spec).expect("created");
    adapter
        .exec(&id, &command("touch"), &workspace().limits)
        .expect("ran");
    assert_eq!(adapter.copy_out(&id, &path("empty")), Ok(vec![]));
}

#[test]
fn workspace_inodes_cover_snapshot() {
    use boneli_app::Sandbox;
    let w = workspace();
    let fill = Program {
        writes: vec![(path("node_modules/x"), Write::File(b"x".to_vec()))],
        ..program("install", 0)
    };
    let adapter = MemorySandbox::new(vec![fill]);
    let p = adapter
        .create(&pod(&Tree::new(), Phase::Prepare, vec![]))
        .expect("created");
    adapter
        .exec(&p, &command("install"), &w.limits)
        .expect("ran");
    let layer = adapter.seal(&p, &[path("node_modules")]).expect("sealed");
    // 10 nodes: the directory `src` and 9 files in it.
    let tree: Tree = (0..9)
        .map(|k| (tpath(format!("src/a{k}").as_bytes()), b"a".to_vec()))
        .collect();
    let with = |inodes| {
        let mut spec = pod(&tree, Phase::Agent, vec![layer.clone()]);
        spec.limits.workspace_inodes = inodes;
        spec
    };
    // 10 nodes + the root + the mount point.
    assert!(adapter.create(&with(12)).is_ok());
    let got = adapter.create(&with(11));
    assert!(
        matches!(&got, Err(boneli_app::SandboxError::Failed { detail }) if detail.contains("12 inodes")),
        "{got:?}"
    );
}

#[test]
fn output_cap_inclusive() {
    use boneli_app::Sandbox;
    let noisy = |name: &str, stdout: &[u8], stderr: &[u8]| Program {
        result: ExecResult {
            status: ExitStatus::Code(0),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        },
        ..program(name, 0)
    };
    let adapter = MemorySandbox::new(vec![
        noisy("out", b"12345678", b""),
        noisy("err", b"", b"12345678"),
    ]);
    let id = adapter.create(&workspace().spec).expect("created");
    for name in ["out", "err"] {
        let at = |output_bytes| Limits {
            wall_ms: 1_000,
            output_bytes,
        };
        assert!(adapter.exec(&id, &command(name), &at(8)).is_ok(), "{name}");
        assert!(
            is_failed(&adapter.exec(&id, &command(name), &at(7))),
            "{name}"
        );
    }
}

#[test]
fn dependency_over_tracked_files_refused() {
    use boneli_app::Sandbox;
    let w = workspace();
    let layer = out_layer(&w.adapter);
    for tracked in [&b"out/old.txt"[..], b"out", b"out/a/b"] {
        let tree: Tree = [(tpath(tracked), b"x".to_vec())].into_iter().collect();
        let got = w
            .adapter
            .create(&pod(&tree, Phase::Agent, vec![layer.clone()]));
        assert!(is_failed(&got), "{tracked:?}: {got:?}");
    }
    // A sibling with a shared prefix is not beneath the mount.
    let tree: Tree = [(tpath(b"outer.txt"), b"x".to_vec())].into_iter().collect();
    assert!(
        w.adapter
            .create(&pod(&tree, Phase::Agent, vec![layer]))
            .is_ok()
    );
}

#[test]
fn dependency_paths_overlap_refused() {
    use boneli_app::Sandbox;
    let w = workspace();
    let both = Program {
        writes: vec![
            (path("out/result.txt"), Write::File(b"r".to_vec())),
            (path("out/x/y"), Write::File(b"y".to_vec())),
        ],
        ..program("both", 0)
    };
    let adapter = MemorySandbox::new(vec![both]);
    let p = adapter
        .create(&pod(&Tree::new(), Phase::Prepare, vec![]))
        .expect("created");
    adapter.exec(&p, &command("both"), &w.limits).expect("ran");
    // Nested in either order, and equal: refused as an overlap, not by
    // another check.
    for paths in [
        [path("out"), path("out/x")],
        [path("out/x"), path("out")],
        [path("out"), path("out")],
    ] {
        let got = adapter.seal(&p, &paths);
        assert!(
            matches!(&got, Err(boneli_app::SandboxError::Failed { detail }) if detail.contains("overlap")),
            "{paths:?}: {got:?}"
        );
    }
    // Two layers whose paths overlap cannot be mounted together.
    let outer = adapter.seal(&p, &[path("out")]).expect("sealed");
    let inner = adapter.seal(&p, &[path("out/x")]).expect("sealed");
    let got = adapter.create(&pod(&Tree::new(), Phase::Agent, vec![outer, inner]));
    assert!(is_failed(&got), "{got:?}");
}

#[test]
fn create_refuses_malformed_workspace() {
    use boneli_app::Sandbox;
    let w = workspace();
    let field = |bytes: &[u8]| {
        let mut out = (bytes.len() as u64).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    };
    let good = [field(b"a"), field(b"x")].concat();
    let mut partial = good.clone();
    partial.extend_from_slice(&field(b"b"));
    partial.extend_from_slice(&3u64.to_be_bytes());
    partial.push(b'y');
    let malformed = [
        u64::MAX.to_be_bytes().to_vec(),
        good[..good.len() - 1].to_vec(),
        [field(b"../x"), field(b"x")].concat(),
        [field(b"/abs"), field(b"x")].concat(),
        [good.clone(), good.clone()].concat(),
        partial,
    ];
    for bytes in malformed {
        let spec = SandboxSpec {
            workspace: WorkspaceBytes::new(bytes),
            ..w.spec.clone()
        };
        assert!(is_failed(&w.adapter.create(&spec)), "{spec:?}");
    }
    // Nothing was created: the first handle is still the first.
    let id = w.adapter.create(&w.spec).expect("created");
    assert_eq!(id.as_str(), "sandbox-1");
}

#[test]
fn hostile_names_round_trip() {
    use boneli_app::Sandbox;
    let w = workspace();
    let tree: Tree = uncitable().into_iter().collect();
    let id = w
        .adapter
        .create(&pod(&tree, Phase::Agent, vec![]))
        .expect("created");
    assert_eq!(w.adapter.export(&id), Ok(pack_tree(&tree)));
}

#[test]
fn workspace_metadata_carried() {
    use boneli_app::Sandbox;
    let w = workspace();
    let tree: Tree = [
        (tpath(b".git/HEAD"), b"ref: refs/heads/main\n".to_vec()),
        (tpath(b"README"), b"app".to_vec()),
    ]
    .into_iter()
    .collect();
    let id = w
        .adapter
        .create(&pod(&tree, Phase::Agent, vec![]))
        .expect("created");
    assert_eq!(w.adapter.export(&id), Ok(pack_tree(&tree)));
    assert_eq!(
        w.adapter.copy_out(&id, &path(".git/HEAD")),
        Ok(b"ref: refs/heads/main\n".to_vec())
    );
}

#[test]
fn export_skips_dependency_mounts() {
    use boneli_app::Sandbox;
    let w = workspace();
    let layer = out_layer(&w.adapter);
    let id = w
        .adapter
        .create(&pod(&Tree::new(), Phase::Agent, vec![layer]))
        .expect("created");
    w.adapter.exec(&id, &w.read, &w.limits).expect("ran");
    assert_eq!(w.adapter.copy_out(&id, &w.copied), Ok(b"written".to_vec()));
    // The mount is read-only: a write beneath it is dropped.
    w.adapter.exec(&id, &w.write, &w.limits).expect("ran");
    let only_copy: Tree = [(tpath(b"copied.txt"), b"written".to_vec())]
        .into_iter()
        .collect();
    assert_eq!(w.adapter.export(&id), Ok(pack_tree(&only_copy)));
    assert!(is_failed(&w.adapter.copy_out(&id, &w.path)));
}

#[test]
fn second_container_has_its_own_root() {
    use boneli_app::Sandbox;
    let w = workspace();
    let mut spec = w.spec.clone();
    spec.containers.push(w.container.clone());
    let id = w.adapter.create(&spec).expect("created");
    let in_db = |program: &str| Command {
        container: w.container.name.clone(),
        ..command(program)
    };
    w.adapter
        .exec(&id, &in_db("write"), &w.limits)
        .expect("ran");
    w.adapter
        .exec(&id, &in_db("plant"), &w.limits)
        .expect("ran");
    assert_eq!(
        w.adapter.copy_out(&id, &w.path),
        Err(boneli_app::SandboxError::NotFound)
    );
    // The planted file is the second container's, not the first's.
    assert_eq!(w.adapter.entry(&id, "/tmp/planted/result.txt"), None);
    assert_eq!(w.adapter.start(&id, &in_db("plant")), Ok(()));
    assert!(is_failed(&w.adapter.start(&id, &command("make"))));
}

#[test]
fn export_refuses_symlinks() {
    use boneli_app::Sandbox;
    let w = workspace();
    let id = w.adapter.create(&w.spec).expect("created");
    w.adapter.exec(&id, &w.link, &w.limits).expect("ran");
    assert!(is_failed(&w.adapter.export(&id)));
    assert_eq!(
        w.adapter.entry(&id, "/workspace/out/result.txt"),
        Some(Write::Symlink(b"/tmp/planted/result.txt".to_vec()))
    );
}

/// Every failure detail of the in-memory sandbox is not blank (ADR-004,
/// D4).
#[test]
fn sandbox_failure_details_are_never_blank() {
    use boneli_app::{LayerRef, Sandbox, SandboxError};
    let w = workspace();
    let layer = out_layer(&w.adapter);
    let id = w.adapter.create(&w.spec).expect("created");
    let tight = Limits {
        wall_ms: 1,
        output_bytes: 0,
    };
    let noisy = MemorySandbox::new(vec![Program {
        result: ExecResult {
            status: ExitStatus::Code(0),
            stdout: b"x".to_vec(),
            stderr: vec![],
        },
        ..program("noisy", 0)
    }]);
    let noisy_id = noisy.create(&w.spec).expect("created");
    let elsewhere = Command {
        container: ContainerName::parse("nowhere").expect("valid"),
        ..command("exit-3")
    };
    w.adapter.exec(&id, &w.link, &w.limits).expect("ran");
    let mut errors: Vec<SandboxError> = vec![
        w.adapter
            .create(&SandboxSpec {
                containers: vec![],
                ..w.spec.clone()
            })
            .expect_err("refused"),
        w.adapter
            .create(&SandboxSpec {
                workspace: WorkspaceBytes::new(vec![1]),
                ..w.spec.clone()
            })
            .expect_err("refused"),
        w.adapter
            .create(&SandboxSpec {
                dependencies: vec![LayerRef::new(String::from("layer-99"))],
                ..w.spec.clone()
            })
            .expect_err("refused"),
        w.adapter
            .exec(&id, &elsewhere, &w.limits)
            .expect_err("refused"),
        w.adapter.start(&id, &command("make")).expect_err("refused"),
        noisy
            .exec(&noisy_id, &command("noisy"), &tight)
            .expect_err("refused"),
        w.adapter.copy_out(&id, &w.path).expect_err("refused"),
        w.adapter.export(&id).expect_err("refused"),
        w.adapter.seal(&id, &[path("out")]).expect_err("refused"),
        w.adapter
            .release(&LayerRef::new(String::from("layer-99")))
            .expect_err("refused"),
    ];
    let user = w
        .adapter
        .create(&pod(&Tree::new(), Phase::Agent, vec![layer.clone()]))
        .expect("created");
    errors.push(w.adapter.release(&layer).expect_err("refused"));
    errors.push(w.adapter.copy_out(&user, &w.path).expect_err("refused"));
    for error in errors {
        match error {
            SandboxError::Failed { detail } => {
                assert!(!boneli_domain::values::is_blank(&detail), "{detail:?}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
