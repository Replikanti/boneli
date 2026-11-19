//! Fetches this repository from GitHub over https (ignored; QA runs it
//! once): the SHA fetch, the https transport without `PATH`, and the fixed
//! environment against a real forge.

use boneli_app::{Git, GitError, RepoUrl};
use boneli_git_cli::{DEFAULT_MAX_NODES, GitCli, GitCliConfig, Transports};

use crate::support::{TempDir, host_git, path, sha};

/// A commit on this repository's `main` (#7 part 3).
const COMMIT: &str = "58e8013e248e1f5cbb91431a23d03c00272f663a";

#[test]
#[ignore = "network: fetches from github.com"]
fn fetches_this_repository() {
    let tmp = TempDir::new("network");
    let git = GitCli::open(GitCliConfig {
        git: host_git(),
        root: tmp.path().join("root"),
        transports: Transports::Https,
        max_workspace_nodes: DEFAULT_MAX_NODES,
        credentials: None,
    })
    .expect("open");
    let repo = RepoUrl::new("https://github.com/Replikanti/boneli.git".to_owned());
    let c = git.fetch_base(&repo, &sha(COMMIT)).expect("fetch");
    let manifest = git
        .read(&c, &path("Cargo.toml"))
        .expect("read")
        .expect("a Cargo.toml");
    assert!(String::from_utf8_lossy(&manifest).contains("[workspace]"));
    // This tree holds an architecture-checker fixture whose name has a
    // backslash, which the workspace path rule refuses (ADR-010, D2), so
    // its snapshot fails closed and names the path.
    let detail = match git.snapshot(&c) {
        Err(GitError::Failed { detail }) => detail,
        other => panic!("expected the backslash path to be refused: {other:?}"),
    };
    assert!(detail.contains("Backslash"), "{detail}");
}
