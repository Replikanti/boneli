//! `push`: create-only branches on the repository the base came from,
//! with the base as the only parent (ADR-014, D1 and D2).

use boneli_app::{BranchName, CheckoutId, CommitInfo, Git, GitError};
use boneli_git_cli::GitCli;

use crate::support::{
    EDITED, LIB, Source, TempDir, branch_at, cli, contract_source, edit, fgit, host_git, open,
    path, sha, write_executable,
};

fn branch(name: &str) -> BranchName {
    BranchName::parse(name).expect("a valid branch name")
}

fn info() -> CommitInfo {
    CommitInfo::new(
        "boneli-test[bot]",
        "1+boneli-test[bot]@users.noreply.github.com",
        "boneli: fix for GitHub ticket 7\n\nRun r-1\n",
    )
    .expect("a valid identity")
}

/// The base checkout and one with `src/lib.rs` edited, applied from a
/// diff as a run does.
fn edited(git: &GitCli, source: &Source, base: &str) -> (CheckoutId, CheckoutId) {
    let c = git.fetch_base(&source.url(), &sha(base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    let workspace = edit(&snapshot, &path("src/lib.rs"), Some(EDITED));
    let diff = git.diff(&c, &workspace).expect("diff");
    let after = git.apply(&c, &diff).expect("apply");
    (c, after)
}

/// The object count of a repository: loose objects plus packed ones.
fn objects(dir: &std::path::Path) -> u64 {
    let out = fgit(dir, &["count-objects", "-v"]);
    out.lines()
        .filter_map(|line| line.split_once(": "))
        .filter(|(key, _)| *key == "count" || *key == "in-pack")
        .map(|(_, n)| n.parse::<u64>().expect("a number"))
        .sum()
}

#[test]
fn push_creates_a_branch_with_the_applied_tree() {
    let tmp = TempDir::new("push-creates");
    let (source, base) = contract_source(&tmp);
    let git = cli(&tmp);
    let (_, after) = edited(&git, &source, &base);
    let sha = git
        .push(&after, &branch("boneli/run-1-0123abcd"), &info())
        .expect("push");
    let (tip, _) = branch_at(&source.dir, "boneli/run-1-0123abcd").expect("the branch");
    assert_eq!(tip, sha.as_str());
    let at = |p: &str| fgit(&source.dir, &["show", &format!("{tip}:{p}")]);
    assert_eq!(format!("{}\n", at("src/lib.rs")).as_bytes(), EDITED);
    assert_eq!(at("README"), "app");
    // The identity and the message as given, author and committer alike.
    let meta = fgit(
        &source.dir,
        &["log", "-1", "--format=%an|%ae|%cn|%ce%n%B", &tip],
    );
    let want = format!(
        "{n}|{e}|{n}|{e}\n{m}",
        n = info().name(),
        e = info().email(),
        m = info().message().trim_end()
    );
    assert_eq!(meta, want);
    // `main` did not move.
    assert_eq!(fgit(&source.dir, &["rev-parse", "main"]), base);
}

#[test]
fn push_parent_is_the_base() {
    let tmp = TempDir::new("push-parent");
    let (source, base) = contract_source(&tmp);
    let git = cli(&tmp);
    let (_, after) = edited(&git, &source, &base);
    git.push(&after, &branch("boneli/parent"), &info())
        .expect("push");
    let (_, parents) = branch_at(&source.dir, "boneli/parent").expect("the branch");
    assert_eq!(parents, vec![base]);
}

#[test]
fn push_refuses_existing_branch() {
    let tmp = TempDir::new("push-exists");
    let (source, base) = contract_source(&tmp);
    let git = cli(&tmp);
    let (c, after) = edited(&git, &source, &base);
    let name = branch("boneli/twice");
    let first = git.push(&after, &name, &info()).expect("push");
    for from in [&after, &c] {
        assert_eq!(git.push(from, &name, &info()), Err(GitError::BranchExists));
    }
    let (tip, _) = branch_at(&source.dir, "boneli/twice").expect("the branch");
    assert_eq!(tip, first.as_str());
}

/// A branch that already points at the base: the new commit would be a
/// fast-forward of it, and the push still refuses and leaves it alone.
#[test]
fn push_refuses_fast_forward_of_existing_branch() {
    let tmp = TempDir::new("push-ff");
    let (source, base) = contract_source(&tmp);
    fgit(&source.dir, &["branch", "boneli/ff", &base]);
    let git = cli(&tmp);
    let (_, after) = edited(&git, &source, &base);
    assert_eq!(
        git.push(&after, &branch("boneli/ff"), &info()),
        Err(GitError::BranchExists)
    );
    let (tip, _) = branch_at(&source.dir, "boneli/ff").expect("the branch");
    assert_eq!(tip, base);
}

/// The race `ls-remote` cannot close: the branch appears after the check.
/// A git whose first `ls-remote` answers that the remote has no refs
/// stands in for it; the push's empty lease is refused by the remote, the
/// lookup after the refusal finds the branch, and the result is
/// `BranchExists` with the tip unchanged.
#[test]
fn push_lease_refuses_a_branch_created_after_the_check() {
    let tmp = TempDir::new("push-race");
    let (source, base) = contract_source(&tmp);
    fgit(&source.dir, &["branch", "boneli/race", &base]);
    let marker = tmp.path().join("first-ls-remote-done");
    let racing = tmp.path().join("racing-git");
    write_executable(
        &racing,
        format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do\n\
             if [ \"$a\" = ls-remote ] && [ ! -e '{marker}' ]; then : > '{marker}'; exit 0; fi\n\
             done\n\
             exec '{real}' \"$@\"\n",
            marker = marker.display(),
            real = host_git().display()
        )
        .as_bytes(),
    );
    let git = open(&tmp, &racing, boneli_git_cli::DEFAULT_MAX_NODES);
    let (_, after) = edited(&git, &source, &base);
    assert_eq!(
        git.push(&after, &branch("boneli/race"), &info()),
        Err(GitError::BranchExists)
    );
    assert!(marker.exists(), "the first ls-remote was not faked");
    let (tip, _) = branch_at(&source.dir, "boneli/race").expect("the branch");
    assert_eq!(tip, base);
}

/// The store holds the base at depth 1 and nothing older; the push
/// still lands with the base as its parent.
#[test]
fn push_from_depth_one_store() {
    let tmp = TempDir::new("push-shallow");
    let source = Source::new(&tmp, "src", false);
    source.write("src/lib.rs", b"fn old() {}\n", false);
    source.write("README", b"app", false);
    source.commit("old");
    source.write("src/lib.rs", LIB, false);
    let base = source.commit("base");
    let git = cli(&tmp);
    let (_, after) = edited(&git, &source, &base);
    let stores: Vec<_> = std::fs::read_dir(git.root().join("stores"))
        .expect("stores")
        .map(|e| e.expect("entry").path())
        .collect();
    assert_eq!(stores.len(), 1);
    assert_eq!(
        std::fs::read_to_string(stores[0].join("shallow")).expect("a shallow store"),
        format!("{base}\n")
    );
    git.push(&after, &branch("boneli/shallow"), &info())
        .expect("push");
    let (_, parents) = branch_at(&source.dir, "boneli/shallow").expect("the branch");
    assert_eq!(parents, vec![base]);
}

/// The remote's `main` moved past the base after the fetch; a one-file
/// change still sends 4 objects: the commit, the root and `src` trees and
/// the blob (ADR-014, D2).
#[test]
fn push_sends_only_new_objects_when_main_moved() {
    let tmp = TempDir::new("push-objects");
    let (source, base) = contract_source(&tmp);
    let git = cli(&tmp);
    let (_, after) = edited(&git, &source, &base);
    source.write("docs/later.md", b"later\n", false);
    source.commit("later");
    let before = objects(&source.dir);
    git.push(&after, &branch("boneli/objects"), &info())
        .expect("push");
    assert_eq!(objects(&source.dir) - before, 4);
}

#[test]
fn push_unknown_checkout() {
    let tmp = TempDir::new("push-unknown");
    let (source, base) = contract_source(&tmp);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let unknown = CheckoutId::new(format!("{}-unknown", c.as_str()));
    assert_eq!(
        git.push(&unknown, &branch("boneli/unknown"), &info()),
        Err(GitError::UnknownCheckout)
    );
    assert_eq!(branch_at(&source.dir, "boneli/unknown"), None);
}

/// Every form `BranchName` accepts at its edges is a branch name git
/// accepts unchanged (`git check-ref-format --branch`).
#[test]
fn every_branch_name_passes_check_ref_format() {
    let tmp = TempDir::new("push-refname");
    let longest = format!("boneli/a{}", "b".repeat(99));
    let slug = format!("boneli/{}-0123abcd", "r".repeat(40));
    let samples = [
        "boneli/a",
        "boneli/0",
        "boneli/run-1-0123abcd",
        "boneli/run-7-ffffffff",
        "boneli/run-0f1e2d3c",
        "boneli/a.b_c-d",
        "boneli/a.lockx",
        "boneli/a-.-b",
        "boneli/a_-_b",
        slug.as_str(),
        longest.as_str(),
    ];
    for name in samples {
        let parsed = branch(name);
        assert_eq!(
            fgit(
                tmp.path(),
                &["check-ref-format", "--branch", parsed.as_str()]
            ),
            name
        );
    }
}
