//! The store-root rules (ADR-021): the root matrix both consumers pinned
//! before the rules moved here (ADR-009 D8, ADR-012 D1), one test per
//! edge case of the #66 plan, and the new root of the git adapter
//! (`create_new_root`, ADR-024).

use std::cell::RefCell;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier};

use boneli_private_dir::{Error, create_new_root, prepare_root};

/// A directory under `CARGO_TARGET_TMPDIR`, unique per process and call,
/// removed on drop even when a test left directories without `u+w`.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates `<CARGO_TARGET_TMPDIR>/private-dir-<tag>-<pid>-<counter>`
    /// and returns it resolved: a relative `CARGO_TARGET_DIR` such as
    /// `../target` puts `..` into `CARGO_TARGET_TMPDIR`, and the rules
    /// refuse a root with dot components.
    fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("private-dir-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create the test's temp dir");
        let path = path.canonicalize().expect("resolve the test's temp dir");
        TempDir { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// A `0o700` directory `name` under the temp dir.
    fn private(&self, name: &str) -> PathBuf {
        let dir = self.path.join(name);
        std::fs::create_dir(&dir).expect("dir");
        chmod(&dir, 0o700);
        dir
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        make_writable(&self.path);
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Gives every directory under `path` (not following symlinks) `u+rwx`, so
/// a test can remove it.
fn make_writable(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let mode = meta.permissions().mode() | 0o700;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            make_writable(&entry.path());
        }
    }
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod")
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// The text rule of a consumer with none (`boneli-store-fs`).
fn any(_: &Path) -> Result<(), &'static str> {
    Ok(())
}

fn my_uid() -> u32 {
    std::fs::metadata("/proc/self").expect("self").uid()
}

/// Expects `Rule` and returns its path and reason.
fn rule(root: &Path, result: Result<PathBuf, Error>) -> (PathBuf, &'static str) {
    match result {
        Err(Error::Rule { path, reason }) => (path, reason),
        other => panic!("{root:?} gave {other:?}"),
    }
}

/// Expects `Io` and returns its path and error.
fn io(root: &Path, result: Result<PathBuf, Error>) -> (PathBuf, std::io::Error) {
    match result {
        Err(Error::Io { path, source }) => (path, source),
        other => panic!("{root:?} gave {other:?}"),
    }
}

const ANCESTOR_OWNER: &str = "an ancestor of the root must be owned by root or the caller";
const ANCESTOR_MODE: &str =
    "an ancestor of the root must not be writable by its group or others unless it is sticky";

// ---- The matrix both consumers pinned (ADR-009 D8, ADR-012 D1). ----

/// A relative root, `~/x` (relative, never expanded), `file:///x` or
/// `./x` is refused. A symlinked root is resolved, and the resolved root is
/// returned. `,`, `:` and `\` are plain bytes here: refusing them is the
/// overlay consumer's text rule, not the shared one.
#[test]
fn root_path_forms() {
    let tmp = TempDir::new("root-forms");
    for relative in ["store", "~/store", "file:///store", "./store"] {
        let (path, reason) = rule(Path::new(relative), prepare_root(Path::new(relative), &any));
        assert_eq!(path, Path::new(relative));
        assert_eq!(reason, "must be an absolute path");
    }
    let clean = tmp.private("clean");
    let link = tmp.path().join("link-to-clean");
    std::os::unix::fs::symlink(&clean, &link).expect("symlink");
    let resolved = prepare_root(&link, &any).expect("a clean link");
    assert_eq!(resolved, clean.canonicalize().expect("resolve"));
    for name in ["a,b", "a:b", "a\\b"] {
        let root = tmp.path().join(name);
        assert_eq!(prepare_root(&root, &any).expect(name), root);
    }
}

/// A missing root is created `0o700`; an existing one with a group or
/// other bit, or a file, is refused and nothing is written into it;
/// `0o700` and sticky `0o1700` are accepted.
#[test]
fn root_mode_rules() {
    let tmp = TempDir::new("root-mode");
    let fresh = tmp.path().join("fresh");
    prepare_root(&fresh, &any).expect("a fresh root");
    assert_eq!(mode_of(&fresh), 0o700);
    for refused in [0o750, 0o701, 0o710, 0o707] {
        let root = tmp.path().join(format!("m{refused:o}"));
        std::fs::create_dir(&root).expect("dir");
        chmod(&root, refused);
        let (path, reason) = rule(&root, prepare_root(&root, &any));
        assert_eq!(path, root, "{refused:o}");
        assert_eq!(reason, "must have no group or other permission bits");
        assert!(names_in(&root).is_empty(), "{refused:o}: wrote into it");
    }
    let file = tmp.path().join("file");
    std::fs::write(&file, b"").expect("file");
    chmod(&file, 0o600);
    let (path, reason) = rule(&file, prepare_root(&file, &any));
    assert_eq!(path, file);
    assert_eq!(reason, "must be a directory");
    for accepted in [0o700, 0o1700] {
        let root = tmp.path().join(format!("ok{accepted:o}"));
        std::fs::create_dir(&root).expect("dir");
        chmod(&root, accepted);
        assert_eq!(prepare_root(&root, &any).expect("a private root"), root);
    }
}

/// The ancestors of the root follow sshd's `StrictModes`: a parent or
/// grandparent writable by its group or by others, and not sticky, is
/// refused, whether the root exists or would be created, and nothing is
/// created or written; the reported path is the deepest offending
/// ancestor. Sticky `1777`, `1775` and `1757` parents, `0o755`, `0o711` and
/// `0o700` are accepted.
#[test]
fn root_ancestor_rules() {
    let tmp = TempDir::new("root-ancestors");
    for (i, mode) in [0o777, 0o775, 0o757, 0o770, 0o707].into_iter().enumerate() {
        let shared = tmp.path().join(format!("shared{i}"));
        std::fs::create_dir(&shared).expect("dir");
        chmod(&shared, mode);
        let missing = shared.join("store");
        let (path, reason) = rule(&missing, prepare_root(&missing, &any));
        assert_eq!((path.as_path(), reason), (shared.as_path(), ANCESTOR_MODE));
        assert!(!missing.exists(), "{mode:o}: the root was created");
        std::fs::create_dir(&missing).expect("dir");
        chmod(&missing, 0o700);
        let (path, reason) = rule(&missing, prepare_root(&missing, &any));
        assert_eq!((path.as_path(), reason), (shared.as_path(), ANCESTOR_MODE));
        assert!(
            names_in(&missing).is_empty(),
            "{mode:o}: wrote into the root"
        );
        let deep = shared.join("mid");
        std::fs::create_dir(&deep).expect("dir");
        chmod(&deep, 0o755);
        let root = deep.join("store");
        let (path, reason) = rule(&root, prepare_root(&root, &any));
        assert_eq!((path.as_path(), reason), (shared.as_path(), ANCESTOR_MODE));
        assert!(!root.exists(), "{mode:o}: the deep root was created");
        // Two offending ancestors: the deeper one is reported.
        chmod(&deep, mode);
        let (path, _) = rule(&root, prepare_root(&root, &any));
        assert_eq!(path, deep, "{mode:o}: not the deepest offender");
        assert!(!root.exists(), "{mode:o}: the deep root was created");
    }
    for (i, mode) in [0o1777, 0o1775, 0o1757, 0o755, 0o711, 0o700]
        .into_iter()
        .enumerate()
    {
        let parent = tmp.path().join(format!("ok{i}"));
        std::fs::create_dir(&parent).expect("dir");
        chmod(&parent, mode);
        let root = parent.join("store");
        assert_eq!(prepare_root(&root, &any).expect("an accepted parent"), root);
        assert_eq!(mode_of(&root), 0o700, "{mode:o}");
    }
}

/// A root with a `.` or `..` component is refused on its text, before
/// anything is checked or created, whether the directory it names would
/// pass or not. Without the rule, `<d>/missing/../gw/store` checks `<d>`,
/// the existing ancestor of the text, and creating it makes `<d>/missing`
/// and `<d>/gw/store` under a group-writable `gw` (review of #67).
#[test]
fn root_dot_components_refused() {
    let tmp = TempDir::new("root-dots");
    let gw = tmp.path().join("gw");
    std::fs::create_dir(&gw).expect("dir");
    chmod(&gw, 0o777);
    let ok = tmp.private("ok");
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
        let (path, reason) = rule(&root, prepare_root(&root, &any));
        assert_eq!(path, root, "{dotted}");
        assert_eq!(reason, "must not have a `.` or `..` component", "{dotted}");
        assert_eq!(names_in(tmp.path()), vec!["gw", "ok"], "{dotted}");
        assert!(names_in(&gw).is_empty(), "{dotted}: created under gw");
        assert!(names_in(&ok).is_empty(), "{dotted}: created under ok");
    }
    prepare_root(&ok.join("store"), &any).expect("the plain root");
}

/// A root owned by someone else is refused before anything is written:
/// `/usr`, which is root's on every Linux host and CI runner. A run as root
/// would own it, so the check does not apply there.
#[test]
fn root_owned_by_another_user_refused() {
    let usr = Path::new("/usr");
    let me = my_uid();
    let owner = std::fs::metadata(usr).expect("/usr").uid();
    if me == 0 || owner == me {
        println!("skipped: this process owns /usr");
        return;
    }
    let before = names_in(usr);
    let (path, reason) = rule(usr, prepare_root(usr, &any));
    assert_eq!(path, usr.canonicalize().expect("resolve"));
    assert_eq!(reason, "must be owned by the caller");
    assert_eq!(names_in(usr), before, "wrote into /usr");
}

// ---- Edge cases of the #66 plan. ----

/// The empty path and relative forms are refused as given, before the
/// text rule runs or anything is touched.
#[test]
fn relative_and_empty_roots_refused() {
    let cwd = std::env::current_dir().expect("cwd");
    let before = names_in(&cwd);
    let calls = RefCell::new(0);
    let counting = |_: &Path| {
        *calls.borrow_mut() += 1;
        Ok(())
    };
    for relative in ["", "store", "~/store", "file:///store", "./store"] {
        let root = Path::new(relative);
        let (path, reason) = rule(root, prepare_root(root, &counting));
        assert_eq!(path, root, "{relative:?}");
        assert_eq!(reason, "must be an absolute path", "{relative:?}");
    }
    assert_eq!(*calls.borrow(), 0, "the text rule ran on a relative root");
    assert_eq!(names_in(&cwd), before, "created something in the cwd");
}

/// `/` and `//` are refused: as non-root for the owner, as root for the
/// mode (`/` is `0o755` or `0o555`, both with group and other bits).
#[test]
fn filesystem_root_refused() {
    let expected = if my_uid() == 0 {
        "must have no group or other permission bits"
    } else {
        "must be owned by the caller"
    };
    for given in ["/", "//"] {
        let root = Path::new(given);
        let (path, reason) = rule(root, prepare_root(root, &any));
        assert_eq!(path, Path::new("/"), "{given}");
        assert_eq!(reason, expected, "{given}");
    }
}

/// `<tmp>/ok//store/` is the same root as `<tmp>/ok/store`.
#[test]
fn trailing_and_doubled_slashes() {
    let tmp = TempDir::new("slashes");
    let ok = tmp.private("ok");
    let given = PathBuf::from(format!("{}//store/", ok.display()));
    let resolved = prepare_root(&given, &any).expect("doubled and trailing slashes");
    assert_eq!(resolved, ok.join("store").canonicalize().expect("resolve"));
    assert_eq!(mode_of(&resolved), 0o700);
}

/// Names that look like `.` or `..` but are not are plain names: the root
/// opens under `ok`, keeps the name byte for byte, and nothing escapes.
#[test]
fn dot_lookalikes_are_plain_names() {
    let tmp = TempDir::new("lookalikes");
    let ok = tmp.private("ok");
    for name in [
        "...",
        ".store",
        "..store",
        "\u{2024}",
        "\u{2025}",
        "\u{FF0E}\u{FF0E}",
        ".\u{200B}",
        "..\u{200B}",
        " ..",
        ".. ",
        "%2e%2e",
        "..\\x",
    ] {
        let root = ok.join(name).join("store");
        let resolved = prepare_root(&root, &any).expect(name);
        assert!(resolved.starts_with(&ok), "{name:?}: {resolved:?}");
        assert_eq!(resolved, root, "{name:?}");
        assert_eq!(
            resolved
                .parent()
                .and_then(Path::file_name)
                .map(OsStr::as_bytes),
            Some(name.as_bytes()),
            "{name:?}"
        );
    }
    assert_eq!(names_in(tmp.path()), vec!["ok"]);
}

/// Blank, control and zero-width names are plain names, kept byte for
/// byte with no trimming; a name that is not UTF-8 is a plain name too
/// under a rule that allows it (the overlay rule of `boneli-oci` does not).
#[test]
fn blank_and_non_utf8_names_are_plain() {
    let tmp = TempDir::new("blank");
    let ok = tmp.private("ok");
    let names: [&[u8]; 5] = [b" ", b"\t", b"\n", "\u{200B}".as_bytes(), b"caf\xe9"];
    for name in names {
        let root = ok.join(OsStr::from_bytes(name));
        let resolved = prepare_root(&root, &any).expect("a plain name");
        assert_eq!(resolved, root, "{name:?}");
        assert_eq!(
            resolved.file_name().map(OsStr::as_bytes),
            Some(name),
            "{name:?}"
        );
        assert_eq!(mode_of(&resolved), 0o700, "{name:?}");
    }
}

/// A NUL byte is an `Io` error (`InvalidInput`) and a name of 256 bytes is
/// one too (`ENAMETOOLONG`, `NAME_MAX` is 255); neither creates anything
/// or panics. A name of 255 bytes opens.
#[test]
fn nul_byte_and_overlong_names_are_io_errors() {
    let tmp = TempDir::new("nul-long");
    let ok = tmp.private("ok");
    let nul = ok.join(OsStr::from_bytes(b"a\0b")).join("store");
    let (_, e) = io(&nul, prepare_root(&nul, &any));
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
    let long = ok.join("x".repeat(256));
    let (path, e) = io(&long, prepare_root(&long, &any));
    assert_eq!(path, long);
    assert_eq!(e.raw_os_error(), Some(36), "ENAMETOOLONG: {e}");
    assert!(names_in(&ok).is_empty(), "created {:?}", names_in(&ok));
    let longest = ok.join("x".repeat(255));
    assert_eq!(prepare_root(&longest, &any).expect("255 bytes"), longest);
}

/// A symlinked root resolves, and its resolution is a fixed point.
#[test]
fn resolved_root_round_trips() {
    let tmp = TempDir::new("round-trip");
    let real = tmp.private("real");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let once = prepare_root(&link, &any).expect("once");
    assert_eq!(once, real);
    assert_eq!(prepare_root(&once, &any).expect("twice"), once);
}

/// A dangling root is an `Io` error at the root; a dangling ancestor of a
/// missing root is one at the link. Nothing is created at either target.
#[test]
fn dangling_symlinks_are_io_errors() {
    let tmp = TempDir::new("dangling");
    let ok = tmp.private("ok");
    let nowhere = ok.join("nowhere");
    let root = ok.join("dangling-root");
    std::os::unix::fs::symlink(&nowhere, &root).expect("symlink");
    let (path, _) = io(&root, prepare_root(&root, &any));
    assert_eq!(path, root);
    let link = ok.join("dangling-ancestor");
    std::os::unix::fs::symlink(&nowhere, &link).expect("symlink");
    let missing = link.join("store");
    let (path, _) = io(&missing, prepare_root(&missing, &any));
    assert_eq!(path, link);
    assert!(!nowhere.exists(), "created the target");
    assert_eq!(names_in(&ok), vec!["dangling-ancestor", "dangling-root"]);
}

/// An ancestor that is a symlink is checked where it points: to a `0o777`
/// directory it is refused at that directory's canonical path and nothing
/// is created there; to a private directory the root is created under the
/// target.
#[test]
fn symlinked_ancestor_checked_after_resolution() {
    let tmp = TempDir::new("linked-ancestor");
    let ok = tmp.private("ok");
    let gw = tmp.path().join("gw");
    std::fs::create_dir(&gw).expect("dir");
    chmod(&gw, 0o777);
    let to_gw = ok.join("to-gw");
    std::os::unix::fs::symlink(&gw, &to_gw).expect("symlink");
    let root = to_gw.join("store");
    let (path, reason) = rule(&root, prepare_root(&root, &any));
    assert_eq!((path.as_path(), reason), (gw.as_path(), ANCESTOR_MODE));
    assert!(names_in(&gw).is_empty(), "created under gw");

    let private = tmp.private("private");
    let to_private = ok.join("to-private");
    std::os::unix::fs::symlink(&private, &to_private).expect("symlink");
    let root = to_private.join("store");
    assert_eq!(
        prepare_root(&root, &any).expect("a private target"),
        private.join("store")
    );
}

/// A regular file as an ancestor is refused at the file.
#[test]
fn file_ancestor_refused() {
    let tmp = TempDir::new("file-ancestor");
    let ok = tmp.private("ok");
    let file = ok.join("file");
    std::fs::write(&file, b"").expect("file");
    let root = file.join("store");
    let (path, reason) = rule(&root, prepare_root(&root, &any));
    assert_eq!(path, file);
    assert_eq!(reason, "an ancestor of the root must be a directory");
}

/// A parent the caller cannot search (`0o600`) is an `Io` error, not a
/// panic. Root bypasses the permission check, so the case needs non-root.
#[test]
fn unsearchable_parent_is_io_error() {
    if my_uid() == 0 {
        println!("skipped: root searches every directory");
        return;
    }
    let tmp = TempDir::new("unsearchable");
    let parent = tmp.private("parent");
    chmod(&parent, 0o600);
    let root = parent.join("store");
    let (_, e) = io(&root, prepare_root(&root, &any));
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
    chmod(&parent, 0o700);
    assert!(names_in(&parent).is_empty(), "created under it");
}

/// The text rule sees the given root, then the root as it will be created
/// (when it is missing), then the resolved root; the prospective path is
/// the resolved one.
#[test]
fn text_rule_sees_given_then_prospective_then_resolved() {
    let tmp = TempDir::new("rule-order");
    let real = tmp.private("real");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let seen = RefCell::new(Vec::new());
    let recording = |p: &Path| {
        seen.borrow_mut().push(p.to_path_buf());
        Ok(())
    };

    let missing = link.join("store");
    let resolved = prepare_root(&missing, &recording).expect("missing");
    assert_eq!(resolved, real.join("store"));
    assert_eq!(
        *seen.borrow(),
        vec![missing.clone(), resolved.clone(), resolved.clone()],
        "a missing root"
    );

    seen.borrow_mut().clear();
    let again = prepare_root(&missing, &recording).expect("existing");
    assert_eq!(again, resolved);
    assert_eq!(*seen.borrow(), vec![missing, resolved], "an existing root");
}

/// A text rule that refuses the given root reports it and creates nothing.
/// One that refuses only where a symlinked ancestor points reports the
/// root under the target, and the target stays empty: the root is not
/// created first and refused afterwards (ADR-021, D3).
#[test]
fn text_rule_refusal_creates_nothing() {
    let tmp = TempDir::new("rule-refusal");
    let ok = tmp.private("ok");
    let root = ok.join("store");
    let refuse_all = |_: &Path| Err("refused by the rule");
    let (path, reason) = rule(&root, prepare_root(&root, &refuse_all));
    assert_eq!(
        (path.as_path(), reason),
        (root.as_path(), "refused by the rule")
    );
    assert!(names_in(&ok).is_empty(), "created under ok");

    let target = tmp.private("target");
    let link = ok.join("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let root = link.join("store");
    let refuse_target = |p: &Path| {
        if p.starts_with(&target) {
            Err("refused under the target")
        } else {
            Ok(())
        }
    };
    let (path, reason) = rule(&root, prepare_root(&root, &refuse_target));
    assert_eq!(path, target.join("store"));
    assert_eq!(reason, "refused under the target");
    assert!(names_in(&target).is_empty(), "created under the target");
}

/// The root is created at the path the checks passed, not through the
/// given path again: a rule that re-points `<d>/link` from `a` to `b` when
/// it sees the prospective root finds `a/store` created and `b` empty, and
/// the given path, which now resolves into `b`, fails to resolve (ADR-021,
/// D3).
#[test]
fn creation_uses_the_checked_path() {
    let tmp = TempDir::new("repoint");
    let a = tmp.private("a");
    let b = tmp.private("b");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&a, &link).expect("symlink");
    let repointed = RefCell::new(false);
    let repoint = |p: &Path| {
        if p.starts_with(&a) && !*repointed.borrow() {
            std::fs::remove_file(&link).expect("unlink");
            std::os::unix::fs::symlink(&b, &link).expect("re-point");
            *repointed.borrow_mut() = true;
        }
        Ok(())
    };
    let root = link.join("store");
    let (path, _) = io(&root, prepare_root(&root, &repoint));
    assert!(
        *repointed.borrow(),
        "the rule never saw the prospective root"
    );
    assert_eq!(path, root);
    assert!(a.join("store").is_dir(), "the checked root was not created");
    assert!(
        names_in(&b).is_empty(),
        "created through the re-pointed link"
    );
}

/// `a`, `b` and `store` of a missing `<ok>/a/b/store` are each created
/// `0o700`.
#[test]
fn missing_intermediates_created_private() {
    let tmp = TempDir::new("intermediates");
    let ok = tmp.private("ok");
    let root = ok.join("a").join("b").join("store");
    assert_eq!(prepare_root(&root, &any).expect("open"), root);
    for dir in [ok.join("a"), ok.join("a").join("b"), root] {
        assert_eq!(mode_of(&dir), 0o700, "{dir:?}");
    }
}

/// Eight threads preparing the same missing root all succeed with the same
/// path: creating a directory that exists is not an error.
#[test]
fn concurrent_first_open_agrees() {
    let tmp = TempDir::new("concurrent");
    let ok = tmp.private("ok");
    let root = Arc::new(ok.join("a").join("store"));
    let start = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let root = Arc::clone(&root);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                prepare_root(&root, &any).map_err(|e| e.to_string())
            })
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().expect("thread"), Ok(root.as_ref().clone()));
    }
}

/// An ancestor owned by another user, neither root nor the caller, is
/// refused for its owner: `/proc/<pid>` of a visible process of another
/// user, mode `0o555`, so only the owner rule can refuse it. Skipped when
/// no such process is visible (`hidepid`, a lone CI user).
#[test]
fn ancestor_owned_by_another_user_refused() {
    let me = my_uid();
    for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let name = entry.file_name();
        if !name.as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let dir = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        if meta.uid() == 0 || meta.uid() == me || meta.mode() & 0o022 != 0 {
            continue;
        }
        let root = dir.join("store");
        match prepare_root(&root, &any) {
            Err(Error::Rule { path, reason }) => {
                assert_eq!(path, dir);
                assert_eq!(reason, ANCESTOR_OWNER);
                return;
            }
            // The process exited between the listing and the check.
            Err(Error::Io { .. }) if !dir.exists() => continue,
            other => panic!("{root:?} gave {other:?}"),
        }
    }
    println!("skipped: no process of another user is visible");
}

/// An ACL that grants another user write on an ancestor puts its mask into
/// the group bits (`0o755` reads `0o775`), so the mode rule refuses it
/// although it cannot see the ACL entries. Skipped without `setfacl` or a
/// filesystem that takes ACLs.
#[test]
fn acl_write_grant_refused() {
    let tmp = TempDir::new("acl");
    let parent = tmp.path().join("parent");
    std::fs::create_dir(&parent).expect("dir");
    chmod(&parent, 0o755);
    let other = if my_uid() == 65534 { 65533 } else { 65534 };
    let granted = Command::new("setfacl")
        .arg("-m")
        .arg(format!("u:{other}:rwx"))
        .arg(&parent)
        .output()
        .is_ok_and(|o| o.status.success());
    if !granted || mode_of(&parent) & 0o020 == 0 {
        println!("skipped: setfacl is missing or the filesystem takes no ACLs");
        return;
    }
    let root = parent.join("store");
    let (path, reason) = rule(&root, prepare_root(&root, &any));
    assert_eq!((path.as_path(), reason), (parent.as_path(), ANCESTOR_MODE));
    assert!(!root.exists(), "the root was created");
}

// ---- create_new_root (ADR-024): the git adapter's root, which must not
// exist and is made by one non-recursive `mkdir`. ----

/// Expects `Io` with kind `AlreadyExists` at `at`.
fn exists_at(root: &Path, at: &Path, result: Result<PathBuf, Error>) {
    let (path, e) = io(root, result);
    assert_eq!(path, at, "{root:?}");
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{root:?}: {e}");
}

/// A parent writable by its group or by others and not sticky is refused
/// at that parent, whether the root exists or not, and nothing is created
/// or written; with two offenders the deeper one is reported, with only
/// the grandparent offending it is reported. Sticky `1777`, `1775` and
/// `1757` parents and `0o755`, `0o711` and `0o700` ones are accepted, and
/// the root gets mode `0o700` exactly.
#[test]
fn create_new_root_ancestor_rules() {
    let tmp = TempDir::new("new-ancestors");
    for (i, mode) in [0o777, 0o775, 0o757, 0o770, 0o707].into_iter().enumerate() {
        let shared = tmp.path().join(format!("shared{i}"));
        std::fs::create_dir(&shared).expect("dir");
        chmod(&shared, mode);
        let root = shared.join("root");
        let (path, reason) = rule(&root, create_new_root(&root, &any));
        assert_eq!((path.as_path(), reason), (shared.as_path(), ANCESTOR_MODE));
        assert!(!root.exists(), "{mode:o}: the root was created");
        // An existing root: the rule, not `AlreadyExists`, because the
        // check comes before `mkdir`.
        std::fs::create_dir(&root).expect("dir");
        chmod(&root, 0o700);
        let (path, reason) = rule(&root, create_new_root(&root, &any));
        assert_eq!((path.as_path(), reason), (shared.as_path(), ANCESTOR_MODE));
        assert!(names_in(&root).is_empty(), "{mode:o}: wrote into the root");
        // Only the grandparent offends.
        let mid = shared.join("mid");
        std::fs::create_dir(&mid).expect("dir");
        chmod(&mid, 0o755);
        let deep = mid.join("root");
        let (path, reason) = rule(&deep, create_new_root(&deep, &any));
        assert_eq!((path.as_path(), reason), (shared.as_path(), ANCESTOR_MODE));
        assert!(!deep.exists(), "{mode:o}: the deep root was created");
        // Both offend: the parent is reported.
        chmod(&mid, mode);
        let (path, _) = rule(&deep, create_new_root(&deep, &any));
        assert_eq!(path, mid, "{mode:o}: not the deepest offender");
        assert!(!deep.exists(), "{mode:o}: the deep root was created");
    }
    for (i, mode) in [0o1777, 0o1775, 0o1757, 0o755, 0o711, 0o700]
        .into_iter()
        .enumerate()
    {
        let parent = tmp.path().join(format!("ok{i}"));
        std::fs::create_dir(&parent).expect("dir");
        chmod(&parent, mode);
        let root = parent.join("root");
        assert_eq!(create_new_root(&root, &any).expect("accepted"), root);
        assert_eq!(mode_of(&root), 0o700, "{mode:o}");
    }
}

/// A root that exists in any form is `AlreadyExists` at that path, and a
/// link's target is left alone: a directory, a symlink to a directory, a
/// dangling symlink, a regular file. `/` and `//` are `AlreadyExists` at
/// `/`. Creating the returned root again is `AlreadyExists` too.
#[test]
fn create_new_root_refuses_an_existing_root() {
    let tmp = TempDir::new("new-exists");
    let ok = tmp.private("ok");
    let dir = ok.join("dir");
    std::fs::create_dir(&dir).expect("dir");
    exists_at(&dir, &dir, create_new_root(&dir, &any));
    assert!(names_in(&dir).is_empty(), "wrote into the directory");

    let target = tmp.private("target");
    let to_dir = ok.join("to-dir");
    std::os::unix::fs::symlink(&target, &to_dir).expect("symlink");
    exists_at(&to_dir, &to_dir, create_new_root(&to_dir, &any));
    assert!(names_in(&target).is_empty(), "wrote into the link's target");

    let nowhere = ok.join("nowhere");
    let dangling = ok.join("dangling");
    std::os::unix::fs::symlink(&nowhere, &dangling).expect("symlink");
    exists_at(&dangling, &dangling, create_new_root(&dangling, &any));
    assert!(!nowhere.exists(), "created the dangling link's target");

    let file = ok.join("file");
    std::fs::write(&file, b"kept").expect("file");
    exists_at(&file, &file, create_new_root(&file, &any));
    assert_eq!(std::fs::read(&file).expect("read"), b"kept");

    for given in ["/", "//"] {
        let root = Path::new(given);
        exists_at(root, Path::new("/"), create_new_root(root, &any));
    }

    let made = create_new_root(&ok.join("root"), &any).expect("new");
    exists_at(&made, &made, create_new_root(&made, &any));
    assert_eq!(
        names_in(&ok),
        vec!["dangling", "dir", "file", "root", "to-dir"]
    );
}

/// Eight threads creating one missing root: exactly one succeeds, the
/// others get `AlreadyExists`. This holds for any interleaving; eight
/// only make overlapping `mkdir`s likely.
#[test]
fn create_new_root_is_exclusive() {
    let tmp = TempDir::new("new-exclusive");
    let ok = tmp.private("ok");
    let root = Arc::new(ok.join("root"));
    let start = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let root = Arc::clone(&root);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                create_new_root(&root, &any)
            })
        })
        .collect();
    let (mut created, mut exists) = (0, 0);
    for t in threads {
        match t.join().expect("thread") {
            Ok(path) => {
                assert_eq!(path, *root);
                created += 1;
            }
            Err(Error::Io { path, source })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                assert_eq!(path, *root);
                exists += 1;
            }
            Err(other) => panic!("{other:?}"),
        }
    }
    assert_eq!((created, exists), (1, 7));
}

/// The root is created at the path the check passed, not through the
/// given path again: a text rule that re-points `<d>/link` from `a` to `b`
/// when it sees the prospective root finds `a/root` created and returned,
/// and `b` empty (ADR-021, D3; ADR-024, D2).
#[test]
fn create_new_root_creates_at_the_checked_path() {
    let tmp = TempDir::new("new-repoint");
    let a = tmp.private("a");
    let b = tmp.private("b");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&a, &link).expect("symlink");
    let repointed = RefCell::new(false);
    let repoint = |p: &Path| {
        if p.starts_with(&a) && !*repointed.borrow() {
            std::fs::remove_file(&link).expect("unlink");
            std::os::unix::fs::symlink(&b, &link).expect("re-point");
            *repointed.borrow_mut() = true;
        }
        Ok(())
    };
    let root = link.join("root");
    let made = create_new_root(&root, &repoint).expect("created");
    assert!(
        *repointed.borrow(),
        "the rule never saw the prospective root"
    );
    assert_eq!(made, a.join("root"));
    assert!(made.is_dir(), "the checked root was not created");
    assert!(
        names_in(&b).is_empty(),
        "created through the re-pointed link"
    );
}

/// The text rule sees the given root, then the prospective one, in that
/// order. A rule that refuses the given root creates nothing; one that
/// refuses only under a link's target reports the root there and leaves
/// the target empty.
#[test]
fn create_new_root_text_rule_sees_given_then_prospective() {
    let tmp = TempDir::new("new-rule-order");
    let real = tmp.private("real");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let seen = RefCell::new(Vec::new());
    let recording = |p: &Path| {
        seen.borrow_mut().push(p.to_path_buf());
        Ok(())
    };
    let root = link.join("root");
    let made = create_new_root(&root, &recording).expect("created");
    assert_eq!(made, real.join("root"));
    assert_eq!(*seen.borrow(), vec![root, made]);

    let ok = tmp.private("ok");
    let root = ok.join("root");
    let refuse_given = |p: &Path| {
        if p == root {
            Err("refused as given")
        } else {
            Ok(())
        }
    };
    let (path, reason) = rule(&root, create_new_root(&root, &refuse_given));
    assert_eq!(
        (path.as_path(), reason),
        (root.as_path(), "refused as given")
    );
    assert!(names_in(&ok).is_empty(), "created under ok");

    let target = tmp.private("target");
    let to_target = ok.join("to-target");
    std::os::unix::fs::symlink(&target, &to_target).expect("symlink");
    let root = to_target.join("root");
    let refuse_target = |p: &Path| {
        if p.starts_with(&target) {
            Err("refused under the target")
        } else {
            Ok(())
        }
    };
    let (path, reason) = rule(&root, create_new_root(&root, &refuse_target));
    assert_eq!(path, target.join("root"));
    assert_eq!(reason, "refused under the target");
    assert!(names_in(&target).is_empty(), "created under the target");
}

/// A root with a `.` or `..` component is refused on its text before
/// anything is checked or created. Without the rule `ok/../ok/root`,
/// `ok/./root` and `./ok/root` would create a root.
#[test]
fn create_new_root_dot_components_refused() {
    let tmp = TempDir::new("new-dots");
    let ok = tmp.private("ok");
    for dotted in [
        "ok/../ok/root",
        "ok/./root",
        "ok/root/.",
        "ok/root/..",
        "./ok/root",
    ] {
        let root = tmp.path().join(dotted);
        let (path, reason) = rule(&root, create_new_root(&root, &any));
        assert_eq!(path, root, "{dotted}");
        assert_eq!(reason, "must not have a `.` or `..` component", "{dotted}");
        assert_eq!(names_in(tmp.path()), vec!["ok"], "{dotted}");
        assert!(names_in(&ok).is_empty(), "{dotted}: created under ok");
    }
    create_new_root(&ok.join("root"), &any).expect("the plain root");
}

/// Relative and empty roots are refused as given, before the text rule
/// runs; doubled and trailing slashes name the plain root; dot look-alikes,
/// blank and non-UTF-8 names are plain names kept byte for byte; a NUL byte
/// is `InvalidInput`; a 256-byte name is `ENAMETOOLONG` and creates
/// nothing, a 255-byte one opens.
#[test]
fn create_new_root_path_forms() {
    let calls = RefCell::new(0);
    let counting = |_: &Path| {
        *calls.borrow_mut() += 1;
        Ok(())
    };
    for relative in ["", "root", "~/root", "file:///root"] {
        let root = Path::new(relative);
        let (path, reason) = rule(root, create_new_root(root, &counting));
        assert_eq!(path, root, "{relative:?}");
        assert_eq!(reason, "must be an absolute path", "{relative:?}");
    }
    assert_eq!(*calls.borrow(), 0, "the text rule ran on a relative root");

    let tmp = TempDir::new("new-forms");
    let ok = tmp.private("ok");
    let given = PathBuf::from(format!("{}//root/", ok.display()));
    assert_eq!(
        create_new_root(&given, &any).expect("slashes"),
        ok.join("root")
    );

    let names: [&[u8]; 8] = [
        "\u{2024}".as_bytes(),
        "\u{FF0E}\u{FF0E}".as_bytes(),
        ".\u{200B}".as_bytes(),
        b" ..",
        b"%2e%2e",
        b" ",
        b"\t",
        b"caf\xe9",
    ];
    for name in names {
        let root = ok.join(OsStr::from_bytes(name));
        let made = create_new_root(&root, &any).expect("a plain name");
        assert_eq!(made, root, "{name:?}");
        assert_eq!(
            made.file_name().map(OsStr::as_bytes),
            Some(name),
            "{name:?}"
        );
        assert_eq!(mode_of(&made), 0o700, "{name:?}");
    }

    let plain = tmp.private("plain");
    let nul = plain.join(OsStr::from_bytes(b"a\0b"));
    let (_, e) = io(&nul, create_new_root(&nul, &any));
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
    let long = plain.join("x".repeat(256));
    let (path, e) = io(&long, create_new_root(&long, &any));
    assert_eq!(path, long);
    assert_eq!(e.raw_os_error(), Some(36), "ENAMETOOLONG: {e}");
    assert!(
        names_in(&plain).is_empty(),
        "created {:?}",
        names_in(&plain)
    );
    let longest = plain.join("x".repeat(255));
    assert_eq!(create_new_root(&longest, &any).expect("255 bytes"), longest);
}

/// The parent is never created: a missing one is `NotFound` at the
/// parent, a dangling link `NotFound` at the link, a link loop `ELOOP`; a
/// regular file is refused by the ancestor rule; a parent the caller cannot
/// write (`0o600`) is `PermissionDenied`, not a panic.
#[test]
fn create_new_root_parent_errors() {
    let tmp = TempDir::new("new-parents");
    let ok = tmp.private("ok");
    let missing = ok.join("missing");
    let root = missing.join("root");
    let (path, e) = io(&root, create_new_root(&root, &any));
    assert_eq!(path, missing);
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    assert!(names_in(&ok).is_empty(), "created the parent");

    let nowhere = ok.join("nowhere");
    let dangling = ok.join("dangling");
    std::os::unix::fs::symlink(&nowhere, &dangling).expect("symlink");
    let root = dangling.join("root");
    let (path, e) = io(&root, create_new_root(&root, &any));
    assert_eq!(path, dangling);
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
    assert!(!nowhere.exists(), "created the link's target");

    let l1 = ok.join("l1");
    let l2 = ok.join("l2");
    std::os::unix::fs::symlink(&l2, &l1).expect("symlink");
    std::os::unix::fs::symlink(&l1, &l2).expect("symlink");
    let root = l1.join("root");
    let (path, e) = io(&root, create_new_root(&root, &any));
    assert_eq!(path, l1);
    assert_eq!(e.raw_os_error(), Some(40), "ELOOP: {e}");

    let file = ok.join("file");
    std::fs::write(&file, b"").expect("file");
    let root = file.join("root");
    let (path, reason) = rule(&root, create_new_root(&root, &any));
    assert_eq!(path, file);
    assert_eq!(reason, "an ancestor of the root must be a directory");

    if my_uid() == 0 {
        println!("skipped: root writes every directory");
        return;
    }
    let closed = tmp.private("closed");
    chmod(&closed, 0o600);
    let root = closed.join("root");
    let (_, e) = io(&root, create_new_root(&root, &any));
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
    chmod(&closed, 0o700);
    assert!(names_in(&closed).is_empty(), "created under it");
}

/// A symlinked parent is checked and used where it points: to a private
/// directory the root is created under the target and the returned path is
/// resolved; to a `0o777` directory it is refused at the target and nothing
/// is created there; a link that sits in a `0o777` directory but points to
/// a private one is fine, because the root is made under the target.
#[test]
fn create_new_root_symlinked_ancestors() {
    let tmp = TempDir::new("new-links");
    let ok = tmp.private("ok");
    let private = tmp.private("private");
    let to_private = ok.join("to-private");
    std::os::unix::fs::symlink(&private, &to_private).expect("symlink");
    let made = create_new_root(&to_private.join("root"), &any).expect("private target");
    assert_eq!(made, private.join("root"));
    assert_eq!(made.canonicalize().expect("resolve"), made);

    let gw = tmp.path().join("gw");
    std::fs::create_dir(&gw).expect("dir");
    chmod(&gw, 0o777);
    let to_gw = ok.join("to-gw");
    std::os::unix::fs::symlink(&gw, &to_gw).expect("symlink");
    let root = to_gw.join("root");
    let (path, reason) = rule(&root, create_new_root(&root, &any));
    assert_eq!((path.as_path(), reason), (gw.as_path(), ANCESTOR_MODE));
    assert!(names_in(&gw).is_empty(), "created under gw");

    let other = tmp.private("other");
    let in_gw = gw.join("to-other");
    std::os::unix::fs::symlink(&other, &in_gw).expect("symlink");
    let made = create_new_root(&in_gw.join("root"), &any).expect("a link in gw");
    assert_eq!(made, other.join("root"));
}

/// An ancestor owned by another user, neither root nor the caller, is
/// refused for its owner: `/proc/<pid>` of a visible process of another
/// user, mode `0o555`, so only the owner rule can refuse it. Skipped when
/// no such process is visible.
#[test]
fn create_new_root_owner_rule() {
    let me = my_uid();
    for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let name = entry.file_name();
        if !name.as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let dir = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        if meta.uid() == 0 || meta.uid() == me || meta.mode() & 0o022 != 0 {
            continue;
        }
        let root = dir.join("root");
        match create_new_root(&root, &any) {
            Err(Error::Rule { path, reason }) => {
                assert_eq!(path, dir);
                assert_eq!(reason, ANCESTOR_OWNER);
                return;
            }
            // The process exited between the listing and the check.
            Err(Error::Io { .. }) if !dir.exists() => continue,
            other => panic!("{root:?} gave {other:?}"),
        }
    }
    println!("skipped: no process of another user is visible");
}

const UMASK_CHILD: &str = "BONELI_PRIVATE_DIR_UMASK_CHILD";

/// The root is `0o700` whatever the umask: a child under `umask 277`,
/// which clears the only bits `0o700` asks for, first sees a plain
/// `create_dir` give `0o500`, then gets `0o700` from `create_new_root`.
#[test]
fn create_new_root_mode_ignores_umask() {
    if std::env::var_os(UMASK_CHILD).is_some() {
        let tmp = TempDir::new("new-umask");
        // The temp dir itself was made under the umask: `0o500`.
        chmod(tmp.path(), 0o700);
        let probe = tmp.path().join("probe");
        std::fs::create_dir(&probe).expect("probe");
        assert_eq!(mode_of(&probe), 0o500, "umask 277");
        let made = create_new_root(&tmp.path().join("root"), &any).expect("created");
        assert_eq!(mode_of(&made), 0o700);
        return;
    }
    let exe = std::env::current_exe().expect("the test binary");
    let output = Command::new("sh")
        .arg("-c")
        .arg("umask 277 && exec \"$0\" \"$@\"")
        .arg(exe)
        .args([
            "--exact",
            "create_new_root_mode_ignores_umask",
            "--test-threads",
            "1",
        ])
        .env(UMASK_CHILD, "1")
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 passed"),
        "the child ran no test: {stdout}"
    );
}
