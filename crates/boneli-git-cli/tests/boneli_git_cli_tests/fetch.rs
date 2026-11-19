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
        credentials: None,
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
    let git = tmp.path().join("limited-git");
    crate::support::write_executable(
        &git,
        format!(
            "#!/bin/sh\nulimit -f 512\nexec '{}' \"$@\"\n",
            crate::support::host_git().display()
        )
        .as_bytes(),
    );
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

/// A source whose commit A is not a tip: A holds 2 MiB no compressor
/// shrinks, and its child B, the only tip, drops it. `filter` lets the
/// remote's upload-pack serve `--filter` requests.
fn non_tip_source(tmp: &TempDir, name: &str, filter: bool) -> (Source, String, String) {
    let source = Source::new(tmp, name, false);
    source.write("blob", &incompressible(2 << 20), false);
    let a = source.commit("A");
    std::fs::remove_file(source.dir.join("blob")).expect("drop the blob");
    source.write("small", b"small\n", false);
    let b = source.commit("B");
    if filter {
        fgit(&source.dir, &["config", "uploadpack.allowFilter", "true"]);
    }
    (source, a, b)
}

/// Every path under `dir` with its size.
fn sized(dir: &Path) -> Vec<(String, u64)> {
    tree(dir)
        .into_iter()
        .map(|p| {
            let len = dir.join(&p).symlink_metadata().expect("meta").len();
            (p, len)
        })
        .collect()
}

/// The probes among the recorded calls: fetches with `--filter=tree:0`,
/// as the `--git-dir` each ran on.
fn probes(recorder: &Recorder) -> Vec<String> {
    recorder
        .calls()
        .into_iter()
        .filter(|c| {
            c.subcommand() == Some("fetch") && c.args.iter().any(|a| a == "--filter=tree:0")
        })
        .map(|c| {
            c.args
                .iter()
                .find_map(|a| a.strip_prefix("--git-dir="))
                .expect("a --git-dir")
                .to_owned()
        })
        .collect()
}

/// A base that is not an advertised tip and whose fetch fails while the
/// remote answers is `Failed` once a fetch of the commit alone proves the
/// commit exists; ids that are no commit stay `UnknownCommit` although the
/// probe gets a tree. Each probe runs in its own repository under
/// `<root>/tmp`, which is removed, so no store changes (ADR-010, D6).
#[test]
fn non_tip_fetch_failure_is_failed() {
    let tmp = TempDir::new("non-tip");
    let (source, a, b) = non_tip_source(&tmp, "src", true);
    let recorder = Recorder::wrapping(&tmp, &write_limited_git(&tmp));
    let git = open(&tmp, &recorder.git, DEFAULT_MAX_NODES);
    let good = git
        .fetch_base(&source.url(), &sha(&b))
        .expect("the tip fits");
    let stores = listing(&git.root().join("stores"));
    assert_eq!(stores.len(), 1);
    let store = git.root().join("stores").join(&stores[0]);
    let before = sized(&store);
    let in_tmp = |dir: &String| Path::new(dir).starts_with(git.root().join("tmp"));

    // The full fetch of A breaks on the file size limit, a stand-in for a
    // full disk; the probe's pack holds one commit and fits.
    recorder.clear();
    let detail = failed(git.fetch_base(&source.url(), &sha(&a)));
    assert!(!detail.trim().is_empty());
    let ran = probes(&recorder);
    assert_eq!(ran.len(), 1, "{ran:?}");
    assert!(ran.iter().all(in_tmp), "{ran:?}");

    // A's tree does not fit either, but the probe of a tree id gets just
    // the tree: not a commit, so still the input's fault.
    let tree_id = fgit(&source.dir, &["rev-parse", &format!("{a}^{{tree}}")]);
    for id in [tree_id.as_str(), "1111111111111111111111111111111111111111"] {
        recorder.clear();
        assert_eq!(
            git.fetch_base(&source.url(), &sha(id)),
            Err(GitError::UnknownCommit),
            "{id}"
        );
        let ran = probes(&recorder);
        assert_eq!(ran.len(), 1, "{id}: {ran:?}");
        assert!(ran.iter().all(in_tmp), "{id}: {ran:?}");
    }

    assert_eq!(listing(&git.root().join("stores")), stores);
    assert_eq!(sized(&store), before);
    assert_eq!(listing(&git.root().join("tmp")), Vec::<String>::new());
    assert_eq!(
        git.read(&good, &path("small")),
        Ok(Some(b"small\n".to_vec()))
    );
}

/// A remote that does not serve `--filter` ignores it (git warns), so the
/// probe is a full depth-1 fetch of the same commit: no larger than the
/// fetch that failed, and it fails the same way. The result is the
/// residual of ADR-010's Consequences, `UnknownCommit`, and nothing is
/// left behind.
#[test]
fn probe_without_filter_support_stays_bounded() {
    let tmp = TempDir::new("non-tip-unfiltered");
    let (source, a, _) = non_tip_source(&tmp, "src", false);
    let git = open(&tmp, &write_limited_git(&tmp), DEFAULT_MAX_NODES);
    assert_eq!(
        git.fetch_base(&source.url(), &sha(&a)),
        Err(GitError::UnknownCommit)
    );
    assert_eq!(listing(&git.root().join("stores")), Vec::<String>::new());
    assert_eq!(listing(&git.root().join("tmp")), Vec::<String>::new());
}

/// A probe that cannot even start (its `init` fails) is no evidence that
/// the commit is missing: the fetch's own failure stands, as `Failed`.
#[test]
fn probe_that_cannot_start_is_failed() {
    let tmp = TempDir::new("probe-init");
    let (source, a, _) = non_tip_source(&tmp, "src", true);
    let git = tmp.path().join("second-init-fails");
    let marker = tmp.path().join("init-seen");
    crate::support::write_executable(
        &git,
        format!(
            "#!/bin/sh\n\
             ulimit -f 512\n\
             for a in \"$@\"; do\n\
             if [ \"$a\" = init ]; then\n\
             if [ -e '{marker}' ]; then exit 1; fi\n\
             : > '{marker}'\n\
             fi\n\
             done\n\
             exec '{real}' \"$@\"\n",
            marker = marker.display(),
            real = crate::support::host_git().display(),
        )
        .as_bytes(),
    );
    let cli = open(&tmp, &git, DEFAULT_MAX_NODES);
    let detail = failed(cli.fetch_base(&source.url(), &sha(&a)));
    assert!(!detail.trim().is_empty());
    assert!(marker.exists());
    assert_eq!(listing(&cli.root().join("stores")), Vec::<String>::new());
    assert_eq!(listing(&cli.root().join("tmp")), Vec::<String>::new());
}

/// A probe step that gives no answer from git is no evidence either way:
/// a fetch or `cat-file` that cannot start (the wrapper makes itself
/// unexecutable, EACCES, the stand-in for EAGAIN or ENOMEM on fork) and a
/// fetch killed by a signal give the first fetch's `Failed`, never
/// `UnknownCommit` (ADR-010, D6).
#[test]
fn probe_step_without_an_answer_is_failed() {
    // What the wrapper does around the probe; `{real}` runs the call.
    let cases = [
        // The probe's `init` runs, then its fetch cannot start.
        (
            "fetch-cannot-start",
            "init",
            "'{real}' \"$@\"; rc=$?; chmod 000 '{git}'; exit $rc",
        ),
        // The probe's fetch runs, then its `cat-file` cannot start.
        (
            "cat-file-cannot-start",
            "--filter=tree:0",
            "'{real}' \"$@\"; rc=$?; chmod 000 '{git}'; exit $rc",
        ),
        // The probe's fetch dies by a signal.
        ("fetch-killed", "--filter=tree:0", "kill -KILL $$"),
    ];
    for (name, trigger, action) in cases {
        let tmp = TempDir::new(name);
        let (source, a, _) = non_tip_source(&tmp, "src", true);
        let git = tmp.path().join("probe-without-answer");
        let marker = tmp.path().join("init-seen");
        let real = crate::support::host_git();
        let action = action
            .replace("{real}", &real.display().to_string())
            .replace("{git}", &git.display().to_string());
        // The main fetch breaks on the file size limit; the second `init`
        // is the probe's.
        let script = format!(
            "#!/bin/sh\n\
             ulimit -f 512\n\
             probe=no\n\
             for a in \"$@\"; do\n\
             if [ \"$a\" = init ]; then\n\
             if [ -e '{marker}' ]; then probe=yes; fi\n\
             : > '{marker}'\n\
             fi\n\
             if [ \"$a\" = --filter=tree:0 ]; then probe=yes; fi\n\
             done\n\
             if [ $probe = yes ]; then\n\
             for a in \"$@\"; do\n\
             if [ \"$a\" = '{trigger}' ]; then {action}; fi\n\
             done\n\
             fi\n\
             exec '{real}' \"$@\"\n",
            marker = marker.display(),
            real = real.display(),
        );
        crate::support::write_executable(&git, script.as_bytes());
        let cli = open(&tmp, &git, DEFAULT_MAX_NODES);
        let detail = failed(cli.fetch_base(&source.url(), &sha(&a)));
        assert!(!detail.trim().is_empty(), "{name}");
        assert_eq!(
            listing(&cli.root().join("stores")),
            Vec::<String>::new(),
            "{name}"
        );
        assert_eq!(
            listing(&cli.root().join("tmp")),
            Vec::<String>::new(),
            "{name}"
        );
        if name != "fetch-killed" {
            // The step that could not start was the wrapper's own exec.
            let mode = std::fs::metadata(&git).expect("wrapper").permissions();
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
                0,
                "{name}"
            );
        }
    }
}
