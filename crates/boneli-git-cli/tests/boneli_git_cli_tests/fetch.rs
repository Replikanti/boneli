//! `fetch_base`: the transports, failure classification, SHA-256
//! repositories and what a rebuilt repository holds (ADR-010, D5 and D6).

use std::path::Path;

use boneli_app::{Git, GitError, RepoUrl};
use boneli_git_cli::{DEFAULT_MAX_NODES, GitCli, GitCliConfig, Transports};

use crate::support::record::Recorder;
use crate::support::{
    Source, TempDir, cli, decode, edit, failed, fgit, listing, open, path, sha, unpack_all,
};

/// Every refused URL is refused by the pure check and by `fetch_base`
/// before any git runs, and the root is unchanged.
#[test]
fn url_policy() {
    let https_refused = [
        "http://h/r",
        "ssh://h/r",
        "git://h/r",
        "ext::sh -c x",
        "file:///tmp/r",
        "https://user:tok@h/r",
        "https://h/r\n",
        "https://",
        " https://h/r",
        "HTTPS://h/r",
        "-https://h/r",
        "https:///r",
        "https://h",
        "https://h/r\0",
        "https://h/a b",
        "https://h/r\u{7f}",
        "",
    ];
    let https_accepted = [
        "https://github.com/o/r.git",
        "https://h:443/r",
        "https://[::1]/r",
    ];
    let file_refused = [
        "file://host/p",
        "file://rel",
        "file:///a/../b",
        "file:///a/./b",
        "file:///",
        "/abs",
        "file:///a b",
    ];
    for url in https_refused {
        assert!(Transports::Https.check(url).is_err(), "{url:?}");
        assert!(
            Transports::HttpsAndFile.check(url).is_err() || url == "file:///tmp/r",
            "{url:?}"
        );
    }
    for url in https_accepted {
        assert_eq!(Transports::Https.check(url), Ok(()), "{url:?}");
        assert_eq!(Transports::HttpsAndFile.check(url), Ok(()), "{url:?}");
    }
    assert_eq!(Transports::HttpsAndFile.check("file:///abs"), Ok(()));
    assert_eq!(Transports::HttpsAndFile.check("file:///tmp/r"), Ok(()));
    for url in file_refused {
        assert!(Transports::HttpsAndFile.check(url).is_err(), "{url:?}");
        assert!(Transports::Https.check(url).is_err(), "{url:?}");
    }

    // Through the adapter: no git runs and the root does not change.
    let tmp = TempDir::new("url-policy");
    let recorder = Recorder::new(&tmp);
    let root = tmp.path().join("root");
    let git = GitCli::open(GitCliConfig {
        git: recorder.git.clone(),
        root: root.clone(),
        transports: Transports::Https,
        max_workspace_nodes: DEFAULT_MAX_NODES,
    })
    .expect("open");
    recorder.clear();
    let before = tree(&root);
    let base = sha("0123456789abcdef0123456789abcdef01234567");
    for url in https_refused.iter().chain(file_refused.iter()) {
        let detail = failed(git.fetch_base(&RepoUrl::new((*url).to_owned()), &base));
        assert!(!detail.trim().is_empty(), "{url:?}");
    }
    assert!(recorder.calls().is_empty(), "{:?}", recorder.calls());
    assert_eq!(tree(&root), before);
}

/// Every path under `dir`, recursively.
fn tree(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for name in listing(&d) {
            let p = d.join(&name);
            out.push(p.strip_prefix(dir).expect("under").display().to_string());
            if p.symlink_metadata().expect("meta").is_dir() {
                stack.push(p);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn fetch_classification() {
    let tmp = TempDir::new("classify");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    let base = source.commit("base");
    let tree_id = fgit(&source.dir, &["rev-parse", "HEAD^{tree}"]);
    let git = cli(&tmp);
    let stores = || listing(&git.root().join("stores"));
    let cases = [
        ("absent", "1111111111111111111111111111111111111111"),
        ("tree", tree_id.as_str()),
        (
            "sha256 against sha1",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ),
    ];
    for (which, id) in cases {
        assert_eq!(
            git.fetch_base(&source.url(), &sha(id)),
            Err(GitError::UnknownCommit),
            "{which}"
        );
        assert_eq!(stores(), Vec::<String>::new(), "{which}");
    }
    let missing = RepoUrl::new(format!("file://{}/missing", tmp.path().display()));
    let detail = failed(git.fetch_base(&missing, &sha(&base)));
    assert!(!detail.trim().is_empty());
    assert_eq!(stores(), Vec::<String>::new());
    // And a good fetch keeps its store.
    git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    assert_eq!(stores().len(), 1);
}

/// `len` bytes no compressor shrinks: a xorshift stream.
fn incompressible(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[3]
        })
        .collect()
}

/// A git that cannot write a file past 256 KiB (`ulimit -f 512`, in
/// 512-byte blocks): a stand-in for a full disk under the root.
fn write_limited_git(tmp: &TempDir) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let git = tmp.path().join("limited-git");
    std::fs::write(
        &git,
        format!(
            "#!/bin/sh\nulimit -f 512\nexec '{}' \"$@\"\n",
            crate::support::host_git().display()
        ),
    )
    .expect("write the wrapper");
    std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755)).expect("mode");
    git
}

/// The remote advertises the commit, so a failed fetch of it is the fetch's
/// failure, never `UnknownCommit`: a local write failure and a remote that
/// lost an object (ADR-010, D6). The store is removed either way.
#[test]
fn advertised_commit_fetch_failure_is_failed() {
    let tmp = TempDir::new("advertised-failure");
    // A local write failure while the pack arrives.
    let big = Source::new(&tmp, "big", false);
    big.write("blob", &incompressible(2 << 20), false);
    let tip = big.commit("big");
    let git = open(&tmp, &write_limited_git(&tmp), DEFAULT_MAX_NODES);
    let detail = failed(git.fetch_base(&big.url(), &sha(&tip)));
    assert!(!detail.trim().is_empty());
    assert_eq!(listing(&git.root().join("stores")), Vec::<String>::new());

    // A remote that lost a blob of its advertised HEAD.
    let broken = Source::new(&tmp, "broken", false);
    broken.write("a", b"lost blob\n", false);
    let head = broken.commit("base");
    let blob = fgit(&broken.dir, &["rev-parse", "HEAD:a"]);
    std::fs::remove_file(
        broken
            .dir
            .join(".git/objects")
            .join(&blob[..2])
            .join(&blob[2..]),
    )
    .expect("remove the loose blob");
    let git = cli(&tmp);
    let detail = failed(git.fetch_base(&broken.url(), &sha(&head)));
    assert!(!detail.trim().is_empty());
    assert_eq!(listing(&git.root().join("stores")), Vec::<String>::new());
}

#[test]
fn sha256_repository_round_trip() {
    let tmp = TempDir::new("sha256");
    let source = Source::new(&tmp, "src", true);
    source.write("src/lib.rs", b"fn a() {}\n", false);
    source.write("run.sh", b"#!/bin/sh\n", true);
    let base = source.commit("base");
    assert_eq!(base.len(), 64);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    assert_eq!(
        git.read(&c, &path("src/lib.rs")),
        Ok(Some(b"fn a() {}\n".to_vec()))
    );
    let snapshot = git.snapshot(&c).expect("snapshot");
    let config = decode(&snapshot)
        .get(&path(".git/config"))
        .map(|(_, d)| String::from_utf8_lossy(d).into_owned())
        .expect("a config");
    assert!(config.contains("objectformat = sha256"), "{config}");
    let edited = edit(&snapshot, &path("src/lib.rs"), Some(b"fn a() { 1 }\n"));
    let diff = git.diff(&c, &edited).expect("diff");
    assert!(!diff.is_empty());
    let after = git.apply(&c, &diff).expect("apply");
    assert_eq!(
        git.read(&after, &path("src/lib.rs")),
        Ok(Some(b"fn a() { 1 }\n".to_vec()))
    );
    assert_eq!(git.diff(&c, &snapshot), Ok(vec![]));
    // The generated `.git` is a working SHA-256 repository.
    let dir = tmp.path().join("unpacked");
    std::fs::create_dir(&dir).expect("dir");
    unpack_all(&snapshot, &dir);
    assert_eq!(fgit(&dir, &["rev-parse", "HEAD"]), base);
    assert_eq!(fgit(&dir, &["status", "--porcelain"]), "");
}

/// The source has base A, a child B on `main`, a tag and a branch at B.
/// The store and the snapshot's `.git` hold A only.
#[test]
fn rebuild_has_no_later_commit() {
    let tmp = TempDir::new("rebuild");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    let a = source.commit("A");
    source.write("b", b"b", false);
    let b = source.commit("B");
    fgit(&source.dir, &["tag", "t1"]);
    fgit(&source.dir, &["branch", "side"]);
    let git = cli(&tmp);
    let c = git.fetch_base(&source.url(), &sha(&a)).expect("fetch");
    let stores = listing(&git.root().join("stores"));
    assert_eq!(stores.len(), 1);
    let store = git.root().join("stores").join(&stores[0]);
    let in_store = std::process::Command::new(crate::support::host_git())
        .arg(format!("--git-dir={}", store.display()))
        .args(["cat-file", "-e", &b])
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .expect("cat-file");
    assert!(!in_store.success(), "B is in the store");

    let snapshot = git.snapshot(&c).expect("snapshot");
    let dir = tmp.path().join("unpacked");
    std::fs::create_dir(&dir).expect("dir");
    unpack_all(&snapshot, &dir);
    let probe = std::process::Command::new(crate::support::host_git())
        .args(["cat-file", "-e", &b])
        .current_dir(&dir)
        .env_clear()
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .expect("cat-file");
    assert!(!probe.success(), "B is in the snapshot");
    assert_eq!(
        fgit(&dir, &["for-each-ref", "--format=%(refname)"]),
        "refs/heads/main"
    );
    assert_eq!(fgit(&dir, &["rev-list", "--all"]), a);
    assert_eq!(fgit(&dir, &["status", "--porcelain"]), "");
}
