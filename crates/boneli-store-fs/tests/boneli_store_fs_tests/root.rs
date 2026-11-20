//! The store root and the lock (ADR-012, D1). The root matrix is the one
//! `boneli-oci` pins for the same rules (`crates/boneli-oci/tests/store.rs`,
//! ADR-009 D8), minus the overlay separators, which this store does not
//! hand to a mount; the rules live in `boneli-private-dir` (ADR-021).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use boneli_app::Evidence;
use boneli_store_fs::{FsStore, OpenError};

use crate::support::{TempDir, names_in};

fn assert_root_refused(root: &Path, why: &str) {
    match FsStore::open(root) {
        Err(OpenError::Root { .. }) => {}
        other => panic!("{why}: {root:?} gave {other:?}"),
    }
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod")
}

/// A relative root, `~/x` (relative, never expanded), `file:///x` or
/// `./x` is refused. A symlinked root is resolved, and the store reports
/// the resolved root. `,`, `:` and `\` are accepted: no mount option is
/// built from this root.
#[test]
fn root_path_forms() {
    let tmp = TempDir::new("root-forms");
    for relative in ["store", "~/store", "file:///store", "./store"] {
        assert_root_refused(Path::new(relative), "relative");
    }
    let clean = tmp.path().join("clean");
    std::fs::create_dir(&clean).expect("dir");
    chmod(&clean, 0o700);
    let link = tmp.path().join("link-to-clean");
    std::os::unix::fs::symlink(&clean, &link).expect("symlink");
    let store = FsStore::open(&link).expect("a clean link");
    assert_eq!(store.root(), clean.canonicalize().expect("resolve"));
    drop(store);
    for name in ["a,b", "a:b", "a\\b"] {
        FsStore::open(&tmp.path().join(name)).expect(name);
    }
}

/// A missing root is created `0o700`; an existing one with a group or
/// other bit, or a file, is refused; `0o700` is accepted.
#[test]
fn root_mode_rules() {
    let tmp = TempDir::new("root-mode");
    let fresh = tmp.path().join("fresh");
    drop(FsStore::open(&fresh).expect("open"));
    let mode = std::fs::metadata(&fresh)
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o700);
    for sub in ["runs", "evidence", "evidence/sha256"] {
        let mode = std::fs::metadata(fresh.join(sub))
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o700, "{sub}");
    }
    let lock = std::fs::metadata(fresh.join("lock")).expect("lock");
    assert_eq!(lock.permissions().mode() & 0o7777, 0o600);
    for refused in [0o750, 0o701, 0o710, 0o707] {
        let root = tmp.path().join(format!("m{refused:o}"));
        std::fs::create_dir(&root).expect("dir");
        chmod(&root, refused);
        assert_root_refused(&root, "group or other bits");
        assert!(names_in(&root).is_empty(), "{refused:o}: wrote into it");
    }
    let file = tmp.path().join("file");
    std::fs::write(&file, b"").expect("file");
    chmod(&file, 0o600);
    assert_root_refused(&file, "not a directory");
    let ok = tmp.path().join("ok");
    std::fs::create_dir(&ok).expect("dir");
    chmod(&ok, 0o700);
    FsStore::open(&ok).expect("a private root");
}

/// The ancestors of the root follow sshd's `StrictModes`: a parent or
/// grandparent writable by its group or by others, and not sticky, is
/// refused, whether the root exists or `open` would create it, and nothing
/// is created or written; sticky `1777` and `1775` parents, `0o755` and
/// `0o700` are accepted.
#[test]
fn root_ancestor_rules() {
    let tmp = TempDir::new("root-ancestors");
    for (i, mode) in [0o777, 0o775, 0o757, 0o770, 0o707].into_iter().enumerate() {
        let shared = tmp.path().join(format!("shared{i}"));
        std::fs::create_dir(&shared).expect("dir");
        chmod(&shared, mode);
        let missing = shared.join("store");
        assert_root_refused(&missing, "a writable parent, missing root");
        assert!(!missing.exists(), "{mode:o}: the root was created");
        std::fs::create_dir(&missing).expect("dir");
        chmod(&missing, 0o700);
        assert_root_refused(&missing, "a writable parent");
        assert!(
            names_in(&missing).is_empty(),
            "{mode:o}: wrote into the root"
        );
        let deep = shared.join("mid");
        std::fs::create_dir(&deep).expect("dir");
        chmod(&deep, 0o755);
        assert_root_refused(&deep.join("store"), "a writable grandparent");
        assert!(
            !deep.join("store").exists(),
            "{mode:o}: the deep root was created"
        );
    }
    match FsStore::open(&tmp.path().join("shared0").join("store")) {
        Err(OpenError::Root { path, reason }) => {
            assert_eq!(
                path,
                tmp.path().join("shared0").canonicalize().expect("resolve")
            );
            assert!(reason.contains("ancestor"), "{reason}");
        }
        other => panic!("a 0o777 parent gave {other:?}"),
    }
    for (i, mode) in [0o1777, 0o1775, 0o755, 0o700].into_iter().enumerate() {
        let parent = tmp.path().join(format!("ok{i}"));
        std::fs::create_dir(&parent).expect("dir");
        chmod(&parent, mode);
        FsStore::open(&parent.join("store")).expect("an accepted parent");
    }
}

/// A root with a `.` or `..` component is refused on its text, before
/// `open` checks or creates anything, whether the directory it names would
/// pass or not. Without the rule, `<d>/missing/../gw/store` checks `<d>`,
/// the existing ancestor of the text, and creating it makes `<d>/missing`
/// and `<d>/gw/store` under a group-writable `gw` before the check of the
/// resolved root refuses it (review of #67).
#[test]
fn root_dot_components_refused() {
    let tmp = TempDir::new("root-dots");
    let gw = tmp.path().join("gw");
    std::fs::create_dir(&gw).expect("dir");
    chmod(&gw, 0o777);
    let ok = tmp.path().join("ok");
    std::fs::create_dir(&ok).expect("dir");
    chmod(&ok, 0o700);
    for dotted in [
        "missing/../gw/store",
        "missing/./../gw/store",
        "ok/../ok/store",
        "ok/./store",
        "ok/store/.",
        "ok/store/..",
        "ok/store/../store",
        "./ok/store",
    ] {
        let root = tmp.path().join(dotted);
        match FsStore::open(&root) {
            Err(OpenError::Root { path, reason }) => {
                assert_eq!(path, root, "{dotted}");
                assert!(reason.contains("`..`"), "{dotted}: {reason}");
            }
            other => panic!("{dotted}: {root:?} gave {other:?}"),
        }
        assert_eq!(names_in(tmp.path()), vec!["gw", "ok"], "{dotted}");
        assert!(names_in(&gw).is_empty(), "{dotted}: created under gw");
        assert!(names_in(&ok).is_empty(), "{dotted}: created under ok");
    }
    // The same roots without the dots open.
    FsStore::open(&ok.join("store")).expect("the plain root");
}

/// A root owned by someone else is refused before anything is written:
/// `/usr`, which is root's on every Linux host and CI runner. A run as root
/// would own it, so the check does not apply there.
#[test]
fn root_owned_by_another_user_refused() {
    let usr = Path::new("/usr");
    let me = std::fs::metadata("/proc/self").expect("self").uid();
    let owner = std::fs::metadata(usr).expect("/usr").uid();
    if me == 0 || owner == me {
        println!("skipped: this process owns /usr");
        return;
    }
    let before = names_in(usr);
    match FsStore::open(usr) {
        Err(OpenError::Root { path, reason }) => {
            assert_eq!(path, usr.canonicalize().expect("resolve"));
            assert_eq!(reason, "must be owned by the caller");
        }
        other => panic!("/usr gave {other:?}"),
    }
    assert_eq!(names_in(usr), before, "open wrote into /usr");
}

/// The root rules live in `boneli-private-dir` (ADR-021), and its errors
/// map back to this crate's: a rule to `OpenError::Root` with the same
/// text, a filesystem failure (here a NUL byte in the root) to
/// `OpenError::Io`.
#[test]
fn root_errors_keep_their_variants_and_text() {
    match FsStore::open(Path::new("store")) {
        Err(e @ OpenError::Root { .. }) => {
            assert_eq!(e.to_string(), "store root store: must be an absolute path")
        }
        other => panic!("a relative root gave {other:?}"),
    }
    let tmp = TempDir::new("root-errors");
    let nul = {
        use std::os::unix::ffi::OsStrExt;
        tmp.path().join(std::ffi::OsStr::from_bytes(b"a\0b"))
    };
    match FsStore::open(&nul) {
        Err(OpenError::Io { source, .. }) => {
            assert_eq!(source.kind(), std::io::ErrorKind::InvalidInput, "{source}")
        }
        other => panic!("a NUL byte gave {other:?}"),
    }
    assert!(names_in(tmp.path()).is_empty(), "created something");
}

/// One store per root: a second `open` while the first store lives is
/// `InUse`, also from the same process; after the first is dropped the
/// root opens again.
#[test]
fn second_open_is_refused_while_held() {
    let tmp = TempDir::new("lock");
    let root = tmp.path().join("store");
    let first = FsStore::open(&root).expect("open");
    match FsStore::open(&root) {
        Err(OpenError::InUse { path }) => assert_eq!(path, first.root().join("lock")),
        other => panic!("a second open gave {other:?}"),
    }
    let second = std::thread::spawn({
        let root = root.clone();
        move || FsStore::open(&root).map(|_| ())
    })
    .join()
    .expect("thread");
    assert!(matches!(second, Err(OpenError::InUse { .. })), "{second:?}");
    drop(first);
    FsStore::open(&root).expect("reopen after the drop");
}

/// `open` removes every `.tmp-*` file in `runs/` and `evidence/sha256/`,
/// keeps every other name, and a `.tmp-` entry it cannot remove (here a
/// directory) does not fail it.
#[test]
fn temp_leftovers_swept_on_open() {
    let tmp = TempDir::new("sweep");
    let root = tmp.path().join("store");
    drop(FsStore::open(&root).expect("open"));
    let runs = root.join("runs");
    let blobs = root.join("evidence").join("sha256");
    for dir in [&runs, &blobs] {
        for name in [".tmp-0", ".tmp-17", ".tmp-x"] {
            std::fs::write(dir.join(name), b"partial").expect("plant");
        }
        std::fs::create_dir(dir.join(".tmp-dir")).expect("plant dir");
        for name in [".tmpx", "keep", ".keep", "tmp-0"] {
            std::fs::write(dir.join(name), b"other").expect("plant");
        }
    }
    let store = FsStore::open(&root).expect("reopen with leftovers");
    for dir in [&runs, &blobs] {
        assert_eq!(
            names_in(dir),
            vec![".keep", ".tmp-dir", ".tmpx", "keep", "tmp-0"],
            "{dir:?}"
        );
    }
    drop(store);
}

/// A reopen does not fail while another thread of the process spawns
/// processes: a child holds a copy of every descriptor from fork to exec,
/// the lock's included, and the drop must release the lock anyway (#94,
/// ADR-026). Probabilistic before the fix; the deterministic pin is the
/// unit test `unlock_on_drop_releases_while_a_child_holds_a_copy`.
#[test]
fn reopen_survives_concurrent_spawns() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const CYCLES: usize = 300;
    let tmp = TempDir::new("reopen-spawns");
    let root = tmp.path().join("store");
    let stop = Arc::new(AtomicBool::new(false));
    let spawner = std::thread::spawn({
        let stop = Arc::clone(&stop);
        move || {
            let mut spawned = 0u64;
            loop {
                std::process::Command::new("true")
                    .status()
                    .expect("spawn true");
                spawned += 1;
                if stop.load(Ordering::Relaxed) {
                    return spawned;
                }
            }
        }
    });
    let mut failure = None;
    for cycle in 0..CYCLES {
        match FsStore::open(&root) {
            Ok(store) => {
                store.put(format!("cycle {cycle}").as_bytes()).expect("put");
            }
            Err(e) => {
                failure = Some((cycle, e));
                break;
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    let spawned = spawner.join().expect("spawner");
    if let Some((cycle, e)) = failure {
        panic!("open failed at cycle {cycle} of {CYCLES}, {spawned} spawns: {e}");
    }
}
