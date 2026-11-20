//! The `Git` contract (ADR-004, ADR-010) on `GitCli` over a fixture
//! repository, and the proof that its `workspace-metadata-inert` fixture
//! is not vacuous on real git.

use std::process::Command;

use boneli_app::contract::{self, git::run};
use boneli_app::{BranchName, CheckoutId, CommitInfo, Git, GitError, RelativePath, RepoUrl};
use boneli_domain::CommitSha;
use boneli_git_cli::GitCli;

use crate::support::{
    HostRemote, Source, TempDir, Trip, cli, contract_source, decode, edit, encode, host_git,
    repository, retarget, unpack_all,
};

#[test]
fn git_cli_passes_contract() {
    let tmp = TempDir::new("contract");
    let (source, base) = contract_source(&tmp);
    let trip = Trip::new(&tmp);
    let make = || repository(cli(&tmp), &source, &base, trip.metadata());
    assert_eq!(run(make, edit, retarget, &trip, &HostRemote), Ok(()));
    assert_eq!(trip.tripped(), Vec::<String>::new());
}

/// A `GitCli` whose `diff` first does what the steering bug does: it
/// unpacks the whole workspace, repository metadata included, runs
/// `git add -A` there with discovery on, and deletes that directory, as
/// the adapter deletes its scratch directory. Only the sentinel can show
/// what ran.
struct Discovering {
    inner: GitCli,
    tmp: std::path::PathBuf,
}

impl Git for Discovering {
    fn fetch_base(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError> {
        self.inner.fetch_base(repo, base)
    }
    fn read(&self, c: &CheckoutId, p: &RelativePath) -> Result<Option<Vec<u8>>, GitError> {
        self.inner.read(c, p)
    }
    fn snapshot(&self, c: &CheckoutId) -> Result<Vec<u8>, GitError> {
        self.inner.snapshot(c)
    }
    fn diff(&self, c: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError> {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = self.tmp.join(format!("discovering-{n}"));
        std::fs::create_dir(&dir).expect("unpack dir");
        unpack_all(workspace, &dir);
        // The exit status does not matter: a hook or fsmonitor runs, or it
        // does not, and the tripwire tells.
        let _ = Command::new(host_git())
            .args(["add", "-A"])
            .current_dir(&dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("run the discovering git");
        std::fs::remove_dir_all(&dir).expect("remove the unpacked workspace");
        self.inner.diff(c, workspace)
    }
    fn apply(&self, c: &CheckoutId, d: &[u8]) -> Result<CheckoutId, GitError> {
        self.inner.apply(c, d)
    }
    fn push(&self, c: &CheckoutId, b: &BranchName, i: &CommitInfo) -> Result<CommitSha, GitError> {
        self.inner.push(c, b, i)
    }
}

/// Which metadata a case plants.
type Planted = fn(&Trip) -> Vec<(RelativePath, Vec<u8>)>;

/// The fixture's `core.fsmonitor` and `post-index-change` hook really fire
/// on a git that discovers the workspace's repository, each on its own, so
/// the clause is not vacuous on git (ADR-010, "Accept when"). The full
/// fixture trips too.
#[test]
fn metadata_fixture_trips_a_discovering_git() {
    let tmp = TempDir::new("discovering");
    let (source, base) = contract_source(&tmp);
    let fixtures: [(&str, Planted); 3] = [
        ("hook only", |t| vec![t.hook()]),
        ("fsmonitor only", |t| vec![t.fsmonitor_config()]),
        ("all", Trip::metadata),
    ];
    for (which, metadata) in fixtures {
        let case = TempDir::new("discovering-case");
        let trip = Trip::new(&case);
        let make = || {
            let inner = cli(&case);
            repository(
                Discovering {
                    inner,
                    tmp: case.path().to_path_buf(),
                },
                &source,
                &base,
                metadata(&trip),
            )
        };
        let got = run(make, edit, retarget, &trip, &HostRemote);
        let Err(contract::Violation { clause, detail, .. }) = got else {
            panic!("{which}: the discovering git passed: {got:?}");
        };
        assert_eq!(clause, "workspace-metadata-inert", "{which}: {detail}");
        assert!(detail.starts_with("nothing-ran:"), "{which}: {detail}");
        assert!(!trip.tripped().is_empty(), "{which}");
    }
}

/// An adapter that drops only the top-level `.git` and keeps the nested
/// `sub/.git` as content fails at `same-diff`. git itself never adds a
/// path with a `.git` component, so the wrapper writes the nested entries
/// into the diff itself, as an adapter with its own unpacking would.
#[test]
fn nested_metadata_is_dropped() {
    struct TopLevelOnly(GitCli);
    impl Git for TopLevelOnly {
        fn fetch_base(&self, r: &RepoUrl, b: &CommitSha) -> Result<CheckoutId, GitError> {
            self.0.fetch_base(r, b)
        }
        fn read(&self, c: &CheckoutId, p: &RelativePath) -> Result<Option<Vec<u8>>, GitError> {
            self.0.read(c, p)
        }
        fn snapshot(&self, c: &CheckoutId) -> Result<Vec<u8>, GitError> {
            self.0.snapshot(c)
        }
        fn diff(&self, c: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError> {
            let mut diff = self.0.diff(c, workspace)?;
            for (p, _, data) in decode(workspace).iter() {
                if p.is_repository_metadata() && !p.as_bytes().starts_with(b".git/") {
                    let shown = String::from_utf8_lossy(p.as_bytes());
                    diff.extend_from_slice(format!("nested {shown} {}\n", data.len()).as_bytes());
                }
            }
            Ok(diff)
        }
        fn apply(&self, c: &CheckoutId, d: &[u8]) -> Result<CheckoutId, GitError> {
            self.0.apply(c, d)
        }
        fn push(
            &self,
            c: &CheckoutId,
            b: &BranchName,
            i: &CommitInfo,
        ) -> Result<CommitSha, GitError> {
            self.0.push(c, b, i)
        }
    }
    let tmp = TempDir::new("nested");
    let (source, base) = contract_source(&tmp);
    let trip = Trip::new(&tmp);
    let make = || repository(TopLevelOnly(cli(&tmp)), &source, &base, trip.metadata());
    let got = run(make, edit, retarget, &trip, &HostRemote);
    let Err(contract::Violation { clause, detail, .. }) = got else {
        panic!("the top-level-only adapter passed: {got:?}");
    };
    assert_eq!(clause, "workspace-metadata-inert", "{detail}");
    assert!(detail.starts_with("same-diff:"), "{detail}");
}

/// The `edit` hook writes a planted hook executable, as the proof above
/// needs, and keeps the kind of an existing file.
#[test]
fn edit_hook_keeps_kinds() {
    let tmp = TempDir::new("edit-hook");
    let source = Source::new(&tmp, "src", false);
    source.write("run.sh", b"#!/bin/sh\n", true);
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git
        .fetch_base(&source.url(), &crate::support::sha(&base))
        .expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    let trip = Trip::new(&tmp);
    let (hook, script) = trip.hook();
    let hook = boneli_app::TreePath::from(hook);
    let w = edit(&snapshot, &hook, Some(&script));
    let w = edit(
        &w,
        &crate::support::tpath("run.sh"),
        Some(b"#!/bin/sh\nexit 0\n"),
    );
    let d = decode(&w);
    assert_eq!(
        d.get(&hook).map(|(k, _)| k),
        Some(boneli_git_cli::Kind::Executable)
    );
    assert_eq!(
        d.get(&crate::support::tpath("run.sh")).map(|(k, _)| k),
        Some(boneli_git_cli::Kind::Executable)
    );
    // `encode` keeps what it is given.
    let list = d
        .iter()
        .map(|(p, k, data)| (p.clone(), k, data.to_vec()))
        .collect();
    assert_eq!(encode(list), w);
}
