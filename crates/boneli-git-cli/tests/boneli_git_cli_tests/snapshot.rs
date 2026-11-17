//! `snapshot`: the files and the generated `.git` (ADR-010, D6).

use boneli_app::{Git, GitError};
use boneli_git_cli::Kind;

use crate::support::{Source, TempDir, cli, decode, edit, entries, failed, fgit, path, sha};

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
    assert_eq!(w.get(&path("plain")), Some((Kind::File, &b"p"[..])));
    assert_eq!(
        w.get(&path("run.sh")),
        Some((Kind::Executable, &b"#!/bin/sh\n"[..]))
    );
    assert_eq!(
        w.get(&path("link")),
        Some((Kind::Symlink, &b"../outside"[..]))
    );
}

#[test]
fn snapshot_refuses_unrepresentable_paths() {
    for (name, bad) in [("backslash", "a\\b"), ("blank", " ")] {
        let tmp = TempDir::new("unrepresentable");
        let source = Source::new(&tmp, "src", false);
        source.write("ok", b"ok", false);
        source.write(bad, b"x", false);
        let base = source.commit("base");
        let git = cli(&tmp);
        let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
        let detail = failed(git.snapshot(&c));
        assert!(detail.contains(&format!("{bad:?}")), "{name}: {detail}");
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
    let edited = edit(&snapshot, &path("a"), Some(b"b"));
    let diff = git.diff(&c, &edited).expect("diff");
    assert!(!String::from_utf8_lossy(&diff).contains("mod"));
    let under = edit(&snapshot, &path("mod/x"), Some(b"x"));
    failed(git.diff(&c, &under));
    let at = edit(&snapshot, &path("mod"), Some(b"x"));
    failed(git.diff(&c, &at));
    assert_eq!(
        crate::support::listing(&git.root().join("scratch")),
        Vec::<String>::new()
    );
}
