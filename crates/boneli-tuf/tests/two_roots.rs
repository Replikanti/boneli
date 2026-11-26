//! Two trust roots side by side (ADR-041): Sigstore's and GitHub's, each
//! in its own ADR-033 trust directory, refreshed from fixture
//! repositories. A refresh of one never touches the other's directory:
//! a directory belongs to the pin in its `tuf/pin` (R1), and no trust
//! directory is, or lies inside, a directory named `tuf` (R2). The checks
//! of ADR-033 (rollback, expiry, snapshot version, pin, lock and inode
//! re-check) hold for the second root as for the first.

mod support;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use boneli_tuf::{Error, Outcome, Step};
use support::real;
use support::repo::{MetaSpec, RootBuilder, SnapshotBuilder, TimestampBuilder};
use support::server::{
    Entry, Reply, Scratch, Server, fixture, github_fixture, github_root_v1, pinned, publish, run,
    tree,
};

/// The two trust directories, siblings in a fresh scratch directory.
fn siblings(tag: &str) -> (Scratch, PathBuf, PathBuf) {
    let scratch = Scratch::new(tag);
    let sigstore = scratch.0.join("sigstore");
    let github = scratch.0.join("github");
    (scratch, sigstore, github)
}

/// The Sigstore directory refreshed once from its fixture, and its tree.
fn sigstore_set_up(dir: &Path) -> BTreeMap<PathBuf, Entry> {
    let (server, initial, _) = fixture();
    run(&server, dir, &initial).expect("the Sigstore fixture");
    tree(dir)
}

/// The installed file's entry in `dir`.
fn installed(dir: &Path) -> Entry {
    tree(dir)
        .remove(Path::new("trusted_root.json"))
        .expect("an installed trusted_root.json")
}

/// A GitHub fixture server whose `2.root.json` arrives over about 1.8 s,
/// so a refresh against it is still in its root chain while the test
/// works on the directories.
fn slow_github() -> Server {
    let server = Server::new();
    publish(&server, 1, real::GITHUB_TRUSTED_ROOT);
    let mut v2 = RootBuilder::new(2);
    v2.expires = "2030-01-02T00:00:00Z".to_string();
    let v2 = v2.bytes();
    let chunks = v2.chunks(v2.len() / 5 + 1).map(<[u8]>::to_vec).collect();
    server.answer(
        "2.root.json",
        Reply::Trickle {
            head: format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", v2.len()).into_bytes(),
            chunks,
            delay: Duration::from_millis(300),
        },
    );
    server
}

/// `name` created as a private directory.
fn private_dir(path: &Path) {
    fs::create_dir(path).expect("dir");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod");
}

// ---------------------------------------------------------------------
// ADR-033's checks on the second root (AC 3)
// ---------------------------------------------------------------------

#[test]
fn github_timestamp_rollback_refused() {
    let (_scratch, sigstore, github) = siblings("gh-rollback");
    let sigstore_before = sigstore_set_up(&sigstore);
    let (server, initial, _) = github_fixture();
    publish(&server, 5, real::GITHUB_TRUSTED_ROOT);
    run(&server, &github, &initial).expect("v5");
    let file = installed(&github);

    publish(&server, 4, real::GITHUB_TRUSTED_ROOT);
    let err = run(&server, &github, &initial).expect_err("rollback");
    assert_eq!(err.step, Step::Timestamp, "{err}");
    let rollback = Error::Rollback {
        role: "timestamp",
        trusted: 5,
        found: 4,
    };
    assert_eq!(err.detail, rollback.to_string());
    assert_eq!(installed(&github), file);
    assert_eq!(tree(&sigstore), sigstore_before);

    // The equal version again is no rollback.
    publish(&server, 5, real::GITHUB_TRUSTED_ROOT);
    let again = run(&server, &github, &initial).expect("equal version");
    assert!(matches!(again, Outcome::Unchanged(_)), "{again:?}");
}

#[test]
fn github_expired_timestamp_refused() {
    let (_scratch, sigstore, github) = siblings("gh-expired");
    let sigstore_before = sigstore_set_up(&sigstore);
    let (server, initial, _) = github_fixture();
    // `run` starts at 2026-11-24T00:00:00Z: a timestamp that expires at
    // that second has expired, one that expires a second later has not.
    let timestamp = |expires: &str| {
        let mut ts = TimestampBuilder::new(1, MetaSpec::version(1));
        ts.expires = expires.to_string();
        ts.bytes()
    };
    let expired = timestamp("2026-11-24T00:00:00Z");
    server.put("timestamp.json", &expired);
    let err = run(&server, &github, &initial).expect_err("expired");
    assert_eq!(err.step, Step::Timestamp, "{err}");
    assert_eq!(err.detail, Error::Expired { role: "timestamp" }.to_string());
    assert!(!github.join("trusted_root.json").exists());

    server.put("timestamp.json", &timestamp("2026-11-24T00:00:01Z"));
    let outcome = run(&server, &github, &initial).expect("a second before expiry");
    assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
    let file = installed(&github);

    server.put("timestamp.json", &expired);
    let err = run(&server, &github, &initial).expect_err("expired again");
    assert_eq!(err.step, Step::Timestamp, "{err}");
    assert_eq!(installed(&github), file);
    assert_eq!(tree(&sigstore), sigstore_before);
}

#[test]
fn github_snapshot_mismatch_refused() {
    let (_scratch, sigstore, github) = siblings("gh-snapshot");
    let sigstore_before = sigstore_set_up(&sigstore);
    let (server, initial, _) = github_fixture();
    run(&server, &github, &initial).expect("v1");
    let file = installed(&github);
    // The timestamp names snapshot 6; `6.snapshot.json` says version 5.
    server.put(
        "timestamp.json",
        &TimestampBuilder::new(6, MetaSpec::version(6)).bytes(),
    );
    server.put(
        "6.snapshot.json",
        &SnapshotBuilder::new(5, MetaSpec::version(1)).bytes(),
    );
    let err = run(&server, &github, &initial).expect_err("version mismatch");
    assert_eq!(err.step, Step::Snapshot(6), "{err}");
    let mismatch = Error::VersionMismatch {
        role: "snapshot",
        expected: 6,
        found: 5,
    };
    assert_eq!(err.detail, mismatch.to_string());
    assert_eq!(installed(&github), file);
    assert_eq!(tree(&sigstore), sigstore_before);
}

#[test]
fn github_changed_pin_refused() {
    let (_scratch, sigstore, github) = siblings("gh-pin");
    let sigstore_before = sigstore_set_up(&sigstore);
    let (server, initial, _) = github_fixture();
    run(&server, &github, &initial).expect("the GitHub pin");
    let github_before = tree(&github);
    let (_, sigstore_initial, _) = fixture();
    assert_ne!(sigstore_initial.sha256_hex(), initial.sha256_hex());
    server.clear_log();
    let err = run(&server, &github, &sigstore_initial).expect_err("another pin");
    assert_eq!(err.step, Step::InitialRoot, "{err}");
    assert!(
        err.detail
            .contains("the trust directory was set up from another initial root (tuf/pin)"),
        "{err}"
    );
    assert!(server.requested().is_empty());
    assert_eq!(tree(&github), github_before);
    assert_eq!(tree(&sigstore), sigstore_before);
}

// ---------------------------------------------------------------------
// The lock and the inode re-check per root (AC 4)
// ---------------------------------------------------------------------

/// A GitHub refresh in progress makes a second GitHub refresh busy, while
/// a Sigstore refresh in the sibling directory completes in the same
/// window: each root has its own lock.
#[test]
fn github_lock_is_its_own() {
    let (_scratch, sigstore, github) = siblings("gh-lock");
    let slow = slow_github();
    let root = github_root_v1();
    let a = {
        let (github, slow, initial) = (github.clone(), slow.clone(), pinned(&root));
        thread::spawn(move || run(&slow, &github, &initial))
    };
    thread::sleep(Duration::from_millis(400));
    let fast = Server::new();
    publish(&fast, 1, real::GITHUB_TRUSTED_ROOT);
    let busy = run(&fast, &github, &pinned(&root)).expect_err("A holds GitHub's lock");
    assert_eq!(busy.step, Step::Lock);
    assert!(busy.detail.contains("busy"), "{busy}");
    assert!(fast.requested().is_empty());

    let (server, initial, _) = fixture();
    let outcome = run(&server, &sigstore, &initial).expect("Sigstore's own lock");
    assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
    assert!(
        !a.is_finished(),
        "A still runs while Sigstore's refresh ends"
    );
    let a = a.join().expect("join").expect("A ends");
    assert_eq!(a.report().root_version, 2);
}

/// GitHub's `tuf/` removed during a GitHub refresh: that refresh stops
/// at `Lock` and writes nothing more, the next one bootstraps a clean
/// chain, and Sigstore's directory is untouched throughout.
#[test]
fn github_tuf_removed_during_refresh() {
    let (_scratch, sigstore, github) = siblings("gh-race");
    let sigstore_before = sigstore_set_up(&sigstore);
    let slow = slow_github();
    let root = github_root_v1();
    let a = {
        let (github, slow, initial) = (github.clone(), slow.clone(), pinned(&root));
        thread::spawn(move || run(&slow, &github, &initial))
    };
    thread::sleep(Duration::from_millis(400));
    fs::remove_dir_all(github.join("tuf")).expect("remove GitHub's tuf/");
    let a = a
        .join()
        .expect("join")
        .expect_err("tuf/ was removed under A");
    assert_eq!(a.step, Step::Lock, "{a}");
    assert!(!github.join("tuf").exists(), "A wrote nothing more");

    let fast = Server::new();
    publish(&fast, 1, real::GITHUB_TRUSTED_ROOT);
    let outcome = run(&fast, &github, &pinned(&root)).expect("bootstrap again");
    assert_eq!(outcome.report().root_version, 1);
    assert_eq!(fs::read(github.join("tuf/root.json")).expect("root"), root);
    assert_eq!(tree(&sigstore), sigstore_before);
}

// ---------------------------------------------------------------------
// R1: one directory per pin
// ---------------------------------------------------------------------

/// Both roots pointed at one directory, in both orders: the second
/// refresh fails at `InitialRoot` before any request, and every entry,
/// a crashed run's temporary files included, keeps its bytes, inode and
/// mtime (the sweep runs only after the pin check).
#[test]
fn one_directory_per_pin() {
    for sigstore_first in [true, false] {
        let scratch = Scratch::new(&format!("one-dir-{sigstore_first}"));
        let dir = scratch.0.join("shared");
        let (s_server, s_initial, _) = fixture();
        let (g_server, g_initial, _) = github_fixture();
        let (first, second) = if sigstore_first {
            ((&s_server, &s_initial), (&g_server, &g_initial))
        } else {
            ((&g_server, &g_initial), (&s_server, &s_initial))
        };
        run(first.0, &dir, first.1).expect("the first root");
        for stale in [".tmp-trusted_root.json", "tuf/.tmp-root.json"] {
            fs::write(dir.join(stale), b"left by a crashed run").expect("plant");
        }
        let before = tree(&dir);
        let err = run(second.0, &dir, second.1).expect_err("the other root");
        assert_eq!(err.step, Step::InitialRoot, "{err}");
        assert!(second.0.requested().is_empty());
        assert_eq!(tree(&dir), before, "sigstore first: {sigstore_first}");
    }
}

/// Siblings, one after the other, concurrently, and one nested beside the
/// other's `tuf/`: no refresh changes the other directory.
#[test]
fn sibling_roots_touch_only_their_own() {
    let (s_server, s_initial, _) = fixture();
    let (g_server, g_initial, _) = github_fixture();

    let (_scratch, sigstore, github) = siblings("siblings");
    run(&s_server, &sigstore, &s_initial).expect("Sigstore");
    let s1 = tree(&sigstore);
    run(&g_server, &github, &g_initial).expect("GitHub");
    assert_eq!(tree(&sigstore), s1);
    for stale in [".tmp-x", "tuf/.tmp-x"] {
        fs::write(github.join(stale), b"GitHub's").expect("plant");
    }
    let g1 = tree(&github);
    let again = run(&s_server, &sigstore, &s_initial).expect("Sigstore again");
    assert!(matches!(again, Outcome::Unchanged(_)), "{again:?}");
    assert_eq!(tree(&github), g1);

    let (_scratch, sigstore, github) = siblings("siblings-parallel");
    let threads = [
        (s_server.clone(), s_initial.clone(), sigstore),
        (g_server.clone(), g_initial.clone(), github),
    ]
    .map(|(server, initial, dir)| thread::spawn(move || run(&server, &dir, &initial)));
    for t in threads {
        let outcome = t.join().expect("join").expect("no Busy between siblings");
        assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
    }

    // GitHub's directory inside Sigstore's, beside its tuf/.
    let scratch = Scratch::new("siblings-nested");
    let sigstore = scratch.0.join("sigstore");
    let github = sigstore.join("github");
    let outside_github = |dir: &Path| {
        let mut t = tree(dir);
        t.retain(|path, _| !path.starts_with("github"));
        t
    };
    run(&s_server, &sigstore, &s_initial).expect("Sigstore");
    let outcome = run(&g_server, &github, &g_initial).expect("nested beside tuf/");
    assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
    fs::write(github.join(".tmp-x"), b"GitHub's").expect("plant");
    let g = tree(&github);
    run(&s_server, &sigstore, &s_initial).expect("Sigstore again");
    assert_eq!(tree(&github), g);
    let s = outside_github(&sigstore);
    run(&g_server, &github, &g_initial).expect("GitHub again");
    assert_eq!(outside_github(&sigstore), s);
}

// ---------------------------------------------------------------------
// R2: no trust directory at or under a `tuf` entry
// ---------------------------------------------------------------------

/// The refusal of R2: `Lock`, naming the rule, with no request.
fn refused(server: &Server, dir: &Path, initial: &boneli_tuf::InitialRoot) {
    let err = run(server, dir, initial).expect_err("R2");
    assert_eq!(err.step, Step::Lock, "{}: {err}", dir.display());
    assert!(
        err.detail.contains("directory named tuf"),
        "{}: {err}",
        dir.display()
    );
    assert!(server.requested().is_empty());
}

/// One root's directory set to the other's `tuf/`, both ways round: no
/// `lock` and no `tuf/` appear in it.
#[test]
fn trust_dir_is_tuf_refused() {
    let (g_server, g_initial, _) = github_fixture();
    let (_scratch, sigstore, _) = siblings("is-tuf");
    let before = sigstore_set_up(&sigstore);
    refused(&g_server, &sigstore.join("tuf"), &g_initial);
    assert_eq!(tree(&sigstore), before);

    let (s_server, s_initial, _) = fixture();
    let (_scratch, _, github) = siblings("is-tuf-reverse");
    run(&g_server, &github, &g_initial).expect("GitHub");
    let before = tree(&github);
    refused(&s_server, &github.join("tuf"), &s_initial);
    assert_eq!(tree(&github), before);
}

/// A missing directory below the other's `tuf/` is not created.
#[test]
fn trust_dir_below_tuf_refused() {
    let (g_server, g_initial, _) = github_fixture();
    let (_scratch, sigstore, _) = siblings("below-tuf");
    let before = sigstore_set_up(&sigstore);
    for dir in [sigstore.join("tuf/github"), sigstore.join("tuf/a/github")] {
        refused(&g_server, &dir, &g_initial);
        assert!(!dir.exists(), "{}", dir.display());
    }
    assert_eq!(tree(&sigstore), before);
}

/// `tuf` in any ASCII case, existing or missing, as the trust directory
/// or an ancestor of it.
#[test]
fn trust_dir_case_variant_refused() {
    let (server, initial, _) = github_fixture();
    let scratch = Scratch::new("case-tuf");
    for name in ["TUF", "Tuf", "tUf", "tuF"] {
        let missing = scratch.0.join(format!("missing-{name}")).join(name);
        refused(&server, &missing, &initial);
        assert!(!missing.exists(), "{}", missing.display());
        let existing = scratch.0.join(name);
        private_dir(&existing);
        refused(&server, &existing, &initial);
        refused(&server, &existing.join("github"), &initial);
        assert_eq!(
            fs::read_dir(&existing).expect("list").count(),
            0,
            "{}",
            existing.display()
        );
    }
}

/// A symlink to the other root's `tuf/`: refused once resolved, and a
/// missing directory under it is not created.
#[test]
fn trust_dir_symlink_into_tuf_refused() {
    let (g_server, g_initial, _) = github_fixture();
    let (scratch, sigstore, _) = siblings("link-tuf");
    let before = sigstore_set_up(&sigstore);
    let link = scratch.0.join("link");
    symlink(sigstore.join("tuf"), &link).expect("link");
    refused(&g_server, &link, &g_initial);
    refused(&g_server, &link.join("github"), &g_initial);
    assert!(!sigstore.join("tuf/github").exists());
    assert_eq!(tree(&sigstore), before);
}

/// Names that are other directories on the test filesystem are allowed:
/// only `tuf` in ASCII case, or what the filesystem resolves to the
/// parent's `tuf` entry, is refused.
#[test]
fn trust_dir_look_alike_names_allowed() {
    let (server, initial, _) = github_fixture();
    let scratch = Scratch::new("look-alike");
    private_dir(&scratch.0.join("tuf"));
    for name in [
        OsStr::new("tuf\u{200b}"),
        OsStr::new("\u{ff54}\u{ff55}\u{ff46}"),
        OsStr::new("tuf.d"),
        OsStr::new(".tuf"),
        OsStr::new("tuff"),
        OsStr::new("tu"),
        OsStr::from_bytes(b"tu\xff"),
    ] {
        let dir = scratch.0.join(name);
        let outcome =
            run(&server, &dir, &initial).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
    }
}

// ---------------------------------------------------------------------
// R2 by content: another root's state reached through an alias
// ---------------------------------------------------------------------

/// A refusal at `Lock` whose detail holds `needle`, with no request.
fn refused_with(server: &Server, dir: &Path, initial: &boneli_tuf::InitialRoot, needle: &str) {
    let err = run(server, dir, initial).expect_err("refused by content");
    assert_eq!(err.step, Step::Lock, "{}: {err}", dir.display());
    assert!(err.detail.contains(needle), "{}: {err}", dir.display());
    assert!(server.requested().is_empty());
}

/// Review run 1 of #137: another root's `tuf/` reached through an alias
/// (a bind mount, a volume mapped one level too deep) passes every path
/// rule. A trust directory that holds a trust directory's TUF state is
/// refused before anything is written there, so the other root's
/// in-flight temporary file survives. A bind mount needs root, so the
/// alias is a copy of the entries: the rule reads the directory's
/// contents, which are the same either way.
#[test]
fn trust_dir_holding_tuf_state_refused() {
    let (g_server, g_initial, _) = github_fixture();
    let (scratch, sigstore, _) = siblings("holds-state");
    sigstore_set_up(&sigstore);
    let alias = scratch.0.join("alias");
    private_dir(&alias);
    for entry in fs::read_dir(sigstore.join("tuf")).expect("list") {
        let entry = entry.expect("entry");
        fs::copy(entry.path(), alias.join(entry.file_name())).expect("copy");
    }
    fs::write(alias.join(".tmp-root.json"), b"Sigstore's, in flight").expect("plant");
    let before = tree(&alias);
    refused_with(&g_server, &alias, &g_initial, "TUF state");
    assert_eq!(tree(&alias), before);

    // Each state name alone, in its final and its temporary form.
    for name in [
        "pin",
        "root.json",
        "timestamp.json",
        "snapshot.json",
        ".tmp-pin",
        ".tmp-root.json",
        ".tmp-timestamp.json",
        ".tmp-snapshot.json",
    ] {
        let dir = scratch.0.join(format!("one{name}"));
        private_dir(&dir);
        fs::write(dir.join(name), b"another root's").expect("plant");
        let before = tree(&dir);
        refused_with(&g_server, &dir, &g_initial, "TUF state");
        assert_eq!(tree(&dir), before, "{name}");
    }
}

/// The other way round: another root's trust directory reached as this
/// one's `tuf/`. A `tuf/` that holds a trust directory's own entries is
/// refused before anything is written, in this directory or in it.
#[test]
fn trust_dir_whose_tuf_is_a_trust_dir_refused() {
    let (g_server, g_initial, _) = github_fixture();
    let scratch = Scratch::new("tuf-is-dir");
    for name in ["lock", "trusted_root.json", ".tmp-trusted_root.json", "tuf"] {
        let github = scratch.0.join(format!("github{name}"));
        private_dir(&github);
        private_dir(&github.join("tuf"));
        if name == "tuf" {
            private_dir(&github.join("tuf/tuf"));
        } else {
            fs::write(github.join("tuf").join(name), b"another root's").expect("plant");
        }
        fs::write(github.join("tuf/.tmp-root.json"), b"in flight").expect("plant");
        let before = tree(&github);
        refused_with(&g_server, &github, &g_initial, "holds a trust directory");
        assert_eq!(tree(&github), before, "{name}");
    }
}

/// A trust directory set up by this client passes the content rule on
/// every later run, a crashed run's temporary files included.
#[test]
fn own_state_passes_the_content_rule() {
    let (g_server, g_initial, _) = github_fixture();
    let (_scratch, _, github) = siblings("own-state");
    run(&g_server, &github, &g_initial).expect("first run");
    for stale in [
        ".tmp-trusted_root.json",
        "tuf/.tmp-pin",
        "tuf/.tmp-root.json",
    ] {
        fs::write(github.join(stale), b"left by a crashed run").expect("plant");
    }
    let again = run(&g_server, &github, &g_initial).expect("own state");
    assert!(matches!(again, Outcome::Unchanged(_)), "{again:?}");
}
