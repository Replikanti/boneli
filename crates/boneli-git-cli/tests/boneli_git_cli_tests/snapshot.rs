//! `snapshot`: the files and the generated `.git` (ADR-010, D6).

use boneli_app::{Git, GitError};
use boneli_git_cli::Kind;

use crate::support::{
    Source, TempDir, bpath, cli, decode, edit, entries, failed, fgit, listing, sha, tpath,
};

const ALLOWLIST: &[&str] = &[
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/refs/heads/main",
    ".git/shallow",
];

/// The fixed config text of a SHA-1 snapshot.
const CONFIG: &str = "[core]\n\
                      \trepositoryformatversion = 0\n\
                      \tfilemode = true\n\
                      \tbare = false\n\
                      \tlogallrefupdates = true\n";

#[test]
fn snapshot_is_deterministic() {
    let tmp = TempDir::new("deterministic");
    let source = Source::new(&tmp, "src", false);
    for k in 0..20 {
        source.write(
            &format!("f{k}"),
            format!("line {k}\n").repeat(50).as_bytes(),
            false,
        );
    }
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let one = git.snapshot(&c).expect("snapshot");
    let two = git.snapshot(&c).expect("snapshot");
    assert_eq!(one, two);
    // A second fetch into a new store gives the same bytes too.
    let other = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    assert_eq!(git.snapshot(&other).expect("snapshot"), one);
}

#[test]
fn snapshot_keeps_modes() {
    let tmp = TempDir::new("modes");
    let source = Source::new(&tmp, "src", false);
    source.write("plain", b"p", false);
    source.write("run.sh", b"#!/bin/sh\n", true);
    source.link("link", "../outside");
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let w = decode(&git.snapshot(&c).expect("snapshot"));
    assert_eq!(w.get(&tpath("plain")), Some((Kind::File, &b"p"[..])));
    assert_eq!(
        w.get(&tpath("run.sh")),
        Some((Kind::Executable, &b"#!/bin/sh\n"[..]))
    );
    assert_eq!(
        w.get(&tpath("link")),
        Some((Kind::Symlink, &b"../outside"[..]))
    );
}

/// A base tree with paths the citation rule refuses snapshots, each with
/// its kind and content: a backslash, blank names, a name that is not
/// UTF-8, a backslash directory, an executable and a symlink whose target
/// is not UTF-8 (ADR-018, D4). This replaces the refusal of ADR-010.
#[test]
fn snapshot_carries_uncitable_paths() {
    let tmp = TempDir::new("uncitable");
    let source = Source::new(&tmp, "src", false);
    source.write("ok", b"ok", false);
    let files: [(&[u8], &[u8]); 6] = [
        (b"a\\b", b"1"),
        (b" ", b"2"),
        ("\u{200B}".as_bytes(), b"3"),
        (b"\t", b"4"),
        (b"x\xff", b"5"),
        (b"d\\e/f", b"6"),
    ];
    for (p, data) in files {
        source.write_bytes(p, data, false);
    }
    source.write_bytes(b"run\\x.sh", b"#!/bin/sh\n", true);
    source.link_bytes(b"l\\x", b"x\xff");
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    let w = decode(&snapshot);
    for (p, data) in files {
        assert_eq!(w.get(&bpath(p)), Some((Kind::File, data)), "{p:?}");
    }
    assert_eq!(
        w.get(&bpath(b"run\\x.sh")),
        Some((Kind::Executable, &b"#!/bin/sh\n"[..]))
    );
    assert_eq!(w.get(&bpath(b"l\\x")), Some((Kind::Symlink, &b"x\xff"[..])));
    // The snapshot is the workspace `diff` takes back unchanged.
    assert_eq!(git.diff(&c, &snapshot), Ok(vec![]));
}

/// Tree entries that sort before the generated `.git/` block (tab, space,
/// `-`) and after it (0xFF) merge with it in byte order, so `from_sorted`
/// sees no `Unsorted`.
#[test]
fn snapshot_merges_wide_paths_around_generated_git() {
    let tmp = TempDir::new("merge-order");
    let source = Source::new(&tmp, "src", false);
    for p in [&b"\t"[..], b" ", b"-", b"\xff"] {
        source.write_bytes(p, p, false);
    }
    let base = source.commit("base");
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let w = decode(&git.snapshot(&c).expect("snapshot"));
    let order: Vec<Vec<u8>> = w.iter().map(|(p, _, _)| p.as_bytes().to_vec()).collect();
    let first_git = order
        .iter()
        .position(|p| p.starts_with(b".git/"))
        .expect("the generated .git");
    assert_eq!(
        &order[..first_git],
        [b"\t".to_vec(), b" ".to_vec(), b"-".to_vec()]
    );
    assert_eq!(order.last(), Some(&b"\xff".to_vec()));
    let mut sorted = order.clone();
    sorted.sort();
    assert_eq!(order, sorted);
}

/// A base path with a component that is `.git` on another file system
/// once `\\` splits it, as git's NTFS check splits it, or once bytes that
/// are not UTF-8 are read, never snapshots (ADR-018, D3). The forms git
/// refuses itself (`x\\.git`, `.git\\config`, `x\\GIT~1`, `.git\\x/y`)
/// fail at the fetch, whose fsck reports `hasDotgit`; the forms git
/// accepts (`x\\.g<U+200B>it`, `.g<0xFF>it`) are fetched, and `snapshot`
/// refuses them, naming the path.
#[test]
fn snapshot_refuses_backslash_lookalikes() {
    let cases: [(&[u8], Option<&str>); 6] = [
        (b"x\\.git", None),
        (b".git\\config", None),
        (b"x\\GIT~1", None),
        (b".git\\x/y", None),
        ("x\\.g\u{200B}it".as_bytes(), Some("\"x\\\\.g\\u{200b}it\"")),
        (b"a/.g\xffit", Some("\"a/.g\\xffit\"")),
    ];
    for (p, shown) in cases {
        let tmp = TempDir::new("backslash-lookalike");
        let source = Source::new(&tmp, "src", false);
        source.write("ok", b"ok", false);
        source.write_bytes(p, b"x", false);
        let base = source.commit("base");
        let git = cli(&tmp);
        let fetched = git.fetch_base(&source.url(), &sha(&base));
        let Some(shown) = shown else {
            let detail = failed(fetched);
            assert!(detail.contains("hasDotgit"), "{p:?}: {detail}");
            continue;
        };
        let c = fetched.expect("git accepts this name");
        let detail = failed(git.snapshot(&c));
        assert!(
            detail.contains(".git on another file system"),
            "{p:?}: {detail}"
        );
        assert!(detail.contains(shown), "{p:?}: {detail}");
        assert_eq!(listing(&git.root().join("tmp")), Vec::<String>::new());
    }
}

/// A base tree that holds repository metadata (git only warns about a
/// `.git` tree entry) is refused, so it cannot merge into the generated
/// `.git`.
#[test]
fn snapshot_refuses_base_metadata() {
    let tmp = TempDir::new("base-metadata");
    let source = Source::new(&tmp, "src", false);
    source.write("ok", b"ok", false);
    source.commit("first");
    let blob = fgit(&source.dir, &["hash-object", "-w", "ok"]);
    let inner = std::process::Command::new(crate::support::host_git())
        .args(["mktree"])
        .current_dir(&source.dir)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(format!("100644 blob {blob}\tconfig\n").as_bytes())?;
            child.wait_with_output()
        })
        .expect("mktree");
    let inner = String::from_utf8(inner.stdout).expect("utf8");
    let mut child = std::process::Command::new(crate::support::host_git())
        .args(["mktree"])
        .current_dir(&source.dir)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("mktree");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(
                format!(
                    "040000 tree {}\t.git\n100644 blob {blob}\tok\n",
                    inner.trim()
                )
                .as_bytes(),
            )
            .expect("write");
    }
    let top = child.wait_with_output().expect("mktree");
    let top = String::from_utf8(top.stdout).expect("utf8");
    let commit = fgit(&source.dir, &["commit-tree", top.trim(), "-m", "hostile"]);
    fgit(&source.dir, &["update-ref", "refs/heads/hostile", &commit]);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&commit));
    let detail = match c {
        Ok(c) => failed(git.snapshot(&c)),
        // A git whose fsck refuses the tree refuses it at the fetch.
        Err(e) => {
            assert!(
                matches!(e, GitError::UnknownCommit | GitError::Failed { .. }),
                "{e:?}"
            );
            return;
        }
    };
    assert!(detail.contains("repository metadata"), "{detail}");
}

/// A base tree path with a component that is `.git` on another file system
/// is refused by `snapshot`, as `diff` would refuse it, before anything is
/// written: git and its fsck accept these names, so they pass `fetch_base`,
/// and without the check every later `diff` (a file) or `apply` (a
/// gitlink) of the run would fail.
#[test]
fn snapshot_refuses_base_lookalikes() {
    for p in ["sub/.g\u{200B}it/x", ".g\u{2060}it/x", "a/\u{00AD}.GIT"] {
        let tmp = TempDir::new("base-lookalike");
        let source = Source::new(&tmp, "src", false);
        source.write("ok", b"ok", false);
        source.write(p, b"x", false);
        let base = source.commit("base");
        let git = cli(&tmp);
        let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
        let detail = failed(git.snapshot(&c));
        assert!(detail.contains(&format!("{p:?}")), "{p:?}: {detail}");
        assert_eq!(listing(&git.root().join("tmp")), Vec::<String>::new());
    }
    // A gitlink is not in the snapshot, but `apply` checks every path of
    // its result, gitlinks included, so a gitlink at such a name would
    // fail the apply of the run's own diff.
    for p in ["sub/.g\u{200B}it", ".g\u{2060}it"] {
        let tmp = TempDir::new("base-lookalike-gitlink");
        let source = Source::new(&tmp, "src", false);
        source.write("ok", b"ok", false);
        source.gitlink(p, "1234567890123456789012345678901234567890");
        let base = source.commit("base");
        let git = cli(&tmp);
        let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
        let detail = failed(git.snapshot(&c));
        assert!(detail.contains(&format!("{p:?}")), "{p:?}: {detail}");
        assert_eq!(listing(&git.root().join("tmp")), Vec::<String>::new());
    }
}

/// The source repository's config has a remote, a credential helper and a
/// hook; the snapshot's `.git` has exactly the generated entries.
#[test]
fn snapshot_has_no_remote_hook_or_credential() {
    let tmp = TempDir::new("no-remote");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    let base = source.commit("base");
    fgit(
        &source.dir,
        &["remote", "add", "origin", "https://example.invalid/o/r.git"],
    );
    fgit(&source.dir, &["config", "credential.helper", "store"]);
    source.write(".git/hooks/post-checkout", b"#!/bin/sh\nexit 0\n", true);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    let metadata: Vec<(String, Kind, Vec<u8>)> = entries(&snapshot)
        .into_iter()
        .filter(|(p, _, _)| p.starts_with(".git/"))
        .collect();
    let mut names: Vec<&str> = metadata
        .iter()
        .map(|(p, _, _)| p.as_str())
        .filter(|p| !p.starts_with(".git/objects/pack/"))
        .collect();
    names.sort();
    assert_eq!(names, ALLOWLIST);
    let packs: Vec<&str> = metadata
        .iter()
        .map(|(p, _, _)| p.as_str())
        .filter(|p| p.starts_with(".git/objects/pack/"))
        .collect();
    assert_eq!(packs.len(), 2, "{packs:?}");
    let stem = packs[0].strip_suffix(".idx").expect("idx first");
    assert!(stem.starts_with(".git/objects/pack/pack-"), "{stem}");
    assert_eq!(packs[1], format!("{stem}.pack"));
    let get = |p: &str| {
        metadata
            .iter()
            .find(|(n, _, _)| n == p)
            .map(|(_, _, d)| String::from_utf8_lossy(d).into_owned())
            .expect("entry")
    };
    assert_eq!(get(".git/config"), CONFIG);
    assert_eq!(get(".git/HEAD"), "ref: refs/heads/main\n");
    assert_eq!(get(".git/refs/heads/main"), format!("{base}\n"));
    assert_eq!(get(".git/shallow"), format!("{base}\n"));
    assert!(metadata.iter().all(|(p, _, _)| !p.contains("/hooks/")));
    for word in [
        "remote",
        "credential",
        "url",
        "http",
        "include",
        "hooksPath",
    ] {
        assert!(!get(".git/config").contains(word), "{word}");
    }
}

/// A gitlink is omitted from the snapshot, kept by `diff`, and an entry
/// under it is refused.
#[test]
fn gitlinks_are_kept_and_closed() {
    let tmp = TempDir::new("gitlinks");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    source.gitlink("mod", "1234567890123456789012345678901234567890");
    let base = source.commit("base");
    assert!(fgit(&source.dir, &["ls-tree", "HEAD", "mod"]).starts_with("160000 commit "));
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    assert!(
        entries(&snapshot)
            .iter()
            .all(|(p, _, _)| p != "mod" && !p.starts_with("mod/"))
    );
    assert_eq!(git.diff(&c, &snapshot), Ok(vec![]));
    let edited = edit(&snapshot, &tpath("a"), Some(b"b"));
    let diff = git.diff(&c, &edited).expect("diff");
    assert!(!String::from_utf8_lossy(&diff).contains("mod"));
    let under = edit(&snapshot, &tpath("mod/x"), Some(b"x"));
    failed(git.diff(&c, &under));
    let at = edit(&snapshot, &tpath("mod"), Some(b"x"));
    failed(git.diff(&c, &at));
    assert_eq!(
        crate::support::listing(&git.root().join("scratch")),
        Vec::<String>::new()
    );
}
