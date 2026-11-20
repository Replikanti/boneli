//! `push`: create-only branches on the repository the base came from,
//! with the base as the only parent (ADR-014, D1 and D2).

use std::collections::BTreeSet;

use boneli_app::{BranchName, CheckoutId, CommitInfo, Git, GitError};
use boneli_git_cli::GitCli;

use crate::support::{
    EDITED, LIB, Source, TempDir, branch_at, cli, contract_source, edit, fgit, host_git, open, sha,
    tpath, tracing_git, write_executable,
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
    let workspace = edit(&snapshot, &tpath("src/lib.rs"), Some(EDITED));
    let diff = git.diff(&c, &workspace).expect("diff");
    let after = git.apply(&c, &diff).expect("apply");
    (c, after)
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

/// Every object id of the repository at `dir`.
fn all_objects(dir: &std::path::Path) -> BTreeSet<String> {
    fgit(
        dir,
        &[
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
        ],
    )
    .lines()
    .map(str::to_owned)
    .collect()
}

/// The pack indexes under `<dir>/.git/objects/pack`.
fn packs(dir: &std::path::Path) -> BTreeSet<std::path::PathBuf> {
    std::fs::read_dir(dir.join(".git/objects/pack"))
        .map(|entries| {
            entries
                .map(|e| e.expect("entry").path())
                .filter(|p| p.extension().is_some_and(|x| x == "idx"))
                .collect()
        })
        .unwrap_or_default()
}

/// The objects of the pack whose index is `idx`, from `verify-pack -v`.
fn pack_objects(dir: &std::path::Path, idx: &std::path::Path) -> BTreeSet<String> {
    let idx = idx.to_str().expect("a UTF-8 path");
    fgit(dir, &["verify-pack", "-v", idx])
        .lines()
        .filter_map(|line| line.split(' ').next())
        .filter(|id| id.len() == 40 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned)
        .collect()
}

/// The values of the trace2 data event `pack-objects` / `key` in a
/// `GIT_TRACE2_EVENT` file, in order.
fn trace2_data(trace: &std::path::Path, key: &str) -> Vec<u64> {
    let needle = format!("\"category\":\"pack-objects\",\"key\":\"{key}\",\"value\":\"");
    std::fs::read_to_string(trace)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let rest = &line[line.find(&needle)? + needle.len()..];
            rest[..rest.find('"')?].parse().ok()
        })
        .collect()
}

/// What a push sends (ADR-014, D2). The base has 300 more files beside
/// the edited one, and the store holds the base at depth 1 with no refs,
/// so without push negotiation git cannot tell what the remote has and
/// sends the base commit and its whole tree; with it, a one-file change
/// sends 4 objects: the commit, the root and `src` trees and the blob.
/// Checked with `main` still at the base and with `main` moved past it,
/// where no advertised tip is a commit the store has. Measured twice:
/// what the push's `pack-objects` wrote (trace2), and the pack the
/// remote kept (`receive.unpackLimit=1`), which also holds the delta
/// bases the remote appends to complete a thin pack
/// (`index-pack --fix-thin`), objects it had already.
#[test]
fn push_sends_only_new_objects() {
    for moved in [false, true] {
        let tmp = TempDir::new("push-objects");
        let source = Source::new(&tmp, "src", false);
        source.write("src/lib.rs", LIB, false);
        for n in 0..300 {
            source.write(
                &format!("src/data/f{n}"),
                format!("{n}\n").as_bytes(),
                false,
            );
        }
        let base = source.commit("base");
        for (key, value) in [
            ("receive.unpackLimit", "1"),
            ("receive.autogc", "false"),
            ("gc.auto", "0"),
        ] {
            fgit(&source.dir, &["config", key, value]);
        }
        let trace = tmp.path().join("trace2.json");
        let git = open(
            &tmp,
            &tracing_git(&tmp, &trace),
            boneli_git_cli::DEFAULT_MAX_NODES,
        );
        let (_, after) = edited(&git, &source, &base);
        if moved {
            source.write("docs/later.md", b"later\n", false);
            source.commit("later");
        }
        let had = all_objects(&source.dir);
        let old_packs = packs(&source.dir);
        let _ = std::fs::remove_file(&trace);
        git.push(&after, &branch("boneli/objects"), &info())
            .expect("push");
        assert_eq!(
            trace2_data(&trace, "write_pack_file/wrote"),
            vec![4],
            "moved: {moved}"
        );
        let deltas: u64 = trace2_data(&trace, "written/delta").iter().sum();
        let new_packs: Vec<_> = packs(&source.dir).difference(&old_packs).cloned().collect();
        assert_eq!(new_packs.len(), 1, "moved: {moved}");
        let kept = pack_objects(&source.dir, &new_packs[0]);
        let fresh: Vec<&String> = kept.iter().filter(|id| !had.contains(*id)).collect();
        assert_eq!(fresh.len(), 4, "moved: {moved}");
        let appended = (kept.len() - fresh.len()) as u64;
        assert!(appended <= deltas, "moved: {moved}: {appended} > {deltas}");
    }
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
