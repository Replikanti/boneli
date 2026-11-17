//! `diff`: ignore rules, attributes, modes, metadata, look-alikes, the node
//! cap and the scratch directory (ADR-010, D6).

use boneli_app::{CheckoutId, Git};
use boneli_git_cli::{GitCli, Kind, Workspace};

use crate::support::{
    Source, TempDir, Trip, cli, decode, edit, edit_kind, failed, host_git, listing, open, path, sha,
};

fn fetched(tmp: &TempDir, source: &Source, base: &str) -> (GitCli, CheckoutId, Vec<u8>) {
    let git = cli(tmp);
    let c = git.fetch_base(&source.url(), &sha(base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    (git, c, snapshot)
}

fn scratch_is_empty(git: &GitCli) {
    assert_eq!(listing(&git.root().join("scratch")), Vec::<String>::new());
    assert_eq!(listing(&git.root().join("tmp")), Vec::<String>::new());
}

#[test]
fn diff_follows_gitignore() {
    let tmp = TempDir::new("gitignore");
    let source = Source::new(&tmp, "src", false);
    source.write(".gitignore", b"dist/\n*.log\n", false);
    source.write("tracked.log", b"one\n", false);
    let base = {
        // Tracked although ignored: added with force.
        crate::support::fgit(&source.dir, &["add", "-f", "tracked.log"]);
        source.commit("base")
    };
    let (git, c, snapshot) = fetched(&tmp, &source, &base);
    let w = edit(&snapshot, &path("dist/out.js"), Some(b"built"));
    assert_eq!(git.diff(&c, &w), Ok(vec![]));
    let w = edit(&w, &path("tracked.log"), Some(b"two\n"));
    let diff = String::from_utf8(git.diff(&c, &w).expect("diff")).expect("utf8");
    assert!(diff.contains("b/tracked.log"), "{diff}");
    assert!(!diff.contains("dist/out.js"), "{diff}");
    scratch_is_empty(&git);
}

#[test]
fn attributes_do_not_convert_content() {
    let tmp = TempDir::new("attributes");
    let source = Source::new(&tmp, "src", false);
    // CRLF committed before the attribute exists, as in a repository that
    // added `text=auto` later.
    source.write("crlf.txt", b"x\r\ny\r\n", false);
    source.commit("crlf");
    source.write(".gitattributes", b"* text=auto\n", false);
    let base = source.commit("base");
    let (git, c, snapshot) = fetched(&tmp, &source, &base);
    assert_eq!(git.diff(&c, &snapshot), Ok(vec![]));
    let w = edit(
        &snapshot,
        &path(".gitattributes"),
        Some(b"* text=auto\n*.txt text eol=crlf\n"),
    );
    let w = edit(&w, &path("a.txt"), Some(b"lf\n"));
    let w = edit(&w, &path("b.txt"), Some(b"crlf\r\n"));
    let diff = git.diff(&c, &w).expect("diff");
    let after = git.apply(&c, &diff).expect("apply");
    assert_eq!(git.read(&after, &path("a.txt")), Ok(Some(b"lf\n".to_vec())));
    assert_eq!(
        git.read(&after, &path("b.txt")),
        Ok(Some(b"crlf\r\n".to_vec()))
    );
    assert_eq!(
        git.read(&after, &path("crlf.txt")),
        Ok(Some(b"x\r\ny\r\n".to_vec()))
    );
}

#[test]
fn mode_change_round_trip() {
    let tmp = TempDir::new("mode-change");
    let source = Source::new(&tmp, "src", false);
    source.write("run.sh", b"#!/bin/sh\n", false);
    let base = source.commit("base");
    let (git, c, snapshot) = fetched(&tmp, &source, &base);
    let w = edit_kind(
        &snapshot,
        &path("run.sh"),
        Some((Kind::Executable, b"#!/bin/sh\n")),
    );
    let diff = git.diff(&c, &w).expect("diff");
    assert!(!diff.is_empty());
    let after = git.apply(&c, &diff).expect("apply");
    let applied = decode(&git.snapshot(&after).expect("snapshot"));
    assert_eq!(
        applied.get(&path("run.sh")).map(|(k, _)| k),
        Some(Kind::Executable)
    );
}

/// Top-level `.git`, nested `sub/.git`, `.git` as a file and as a symlink:
/// all dropped, the same diff as without them.
#[test]
fn metadata_forms_are_dropped() {
    let tmp = TempDir::new("metadata-forms");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    let base = source.commit("base");
    let (git, c, snapshot) = fetched(&tmp, &source, &base);
    let plain = edit(&snapshot, &path("a"), Some(b"b"));
    let want = git.diff(&c, &plain).expect("diff");
    assert!(!want.is_empty());
    let trip = Trip::new(&tmp);
    let without_git: Vec<(boneli_app::RelativePath, Kind, Vec<u8>)> = decode(&plain)
        .iter()
        .filter(|(p, _, _)| !p.is_repository_metadata())
        .map(|(p, k, d)| (p.clone(), k, d.to_vec()))
        .collect();
    let forms: Vec<Vec<u8>> = vec![
        edit(
            &plain,
            &trip.fsmonitor_config().0,
            Some(&trip.fsmonitor_config().1),
        ),
        edit(&plain, &trip.nested().0, Some(&trip.nested().1)),
        {
            let mut list = without_git.clone();
            list.push((path(".git"), Kind::File, b"gitdir: /elsewhere\n".to_vec()));
            crate::support::encode(list)
        },
        {
            let mut list = without_git.clone();
            list.push((path(".git"), Kind::Symlink, b"/".to_vec()));
            crate::support::encode(list)
        },
        {
            let mut list = without_git.clone();
            list.push((path("sub/.git"), Kind::Symlink, b"../..".to_vec()));
            crate::support::encode(list)
        },
    ];
    for (k, w) in forms.iter().enumerate() {
        assert_eq!(git.diff(&c, w).as_ref(), Ok(&want), "form {k}");
    }
    assert_eq!(trip.tripped(), Vec::<String>::new());
    scratch_is_empty(&git);
}

/// Names that are `.git` on a case-insensitive or Windows file system fail
/// through git's own path checks, and leave the scratch directory empty.
#[test]
fn lookalikes_are_refused() {
    let tmp = TempDir::new("lookalikes");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    let base = source.commit("base");
    let (git, c, snapshot) = fetched(&tmp, &source, &base);
    for p in [
        ".GIT/config",
        ".Git/hooks/x",
        "git~1/x",
        "GIT~1/x",
        ".git./x",
        ".git /x",
        ".g\u{200C}it/x",
    ] {
        let w = edit(&snapshot, &path(p), Some(b"[core]\n"));
        failed(git.diff(&c, &w));
        scratch_is_empty(&git);
    }
}

/// The cap counts the decoded workspace's nodes: the snapshot's own count
/// passes, one more fails.
#[test]
fn workspace_entry_cap() {
    let tmp = TempDir::new("cap");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    source.write("d/b", b"b", false);
    let base = source.commit("base");
    let (_, _, snapshot) = fetched(&tmp, &source, &base);
    let k = decode(&snapshot).nodes();
    let git = open(&tmp, &host_git(), k);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let own = git.snapshot(&c).expect("snapshot at the cap");
    assert_eq!(own, snapshot);
    assert_eq!(git.diff(&c, &own), Ok(vec![]));
    let one_more = edit(&own, &path("z"), Some(b"z"));
    assert_eq!(decode(&one_more).nodes(), k + 1);
    let detail = failed(git.diff(&c, &one_more));
    assert!(detail.contains(&k.to_string()), "{detail}");
    scratch_is_empty(&git);
}

#[test]
fn diff_cleans_scratch() {
    let tmp = TempDir::new("clean");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    let base = source.commit("base");
    let (git, c, snapshot) = fetched(&tmp, &source, &base);
    for bad in [b"garbage".to_vec(), Vec::new(), {
        let mut b = snapshot.clone();
        b.push(b'f');
        b
    }] {
        failed(git.diff(&c, &bad));
        scratch_is_empty(&git);
    }
    // And after a good diff.
    git.diff(&c, &edit(&snapshot, &path("a"), Some(b"b")))
        .expect("diff");
    scratch_is_empty(&git);
    assert_eq!(Workspace::new().encode().len(), boneli_git_cli::MAGIC.len());
}

#[test]
fn concurrent_diffs_do_not_share_scratch() {
    let tmp = TempDir::new("concurrent");
    let source = Source::new(&tmp, "src", false);
    for k in 0..50 {
        source.write(&format!("f{k}"), b"x\n", false);
    }
    let base = source.commit("base");
    let (git, c, snapshot) = fetched(&tmp, &source, &base);
    let w = edit(&snapshot, &path("f7"), Some(b"y\n"));
    let (one, two) = std::thread::scope(|s| {
        let a = s.spawn(|| git.diff(&c, &w));
        let b = s.spawn(|| git.diff(&c, &w));
        (a.join().expect("thread"), b.join().expect("thread"))
    });
    let one = one.expect("diff");
    assert!(!one.is_empty());
    assert_eq!(two, Ok(one));
    scratch_is_empty(&git);
}
