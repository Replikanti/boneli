//! `GitCli::open`: the git path, the root and the version floor (ADR-010,
//! D7), and the rules on the root and its ancestors (ADR-024).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use boneli_app::Git;
use boneli_git_cli::{DEFAULT_MAX_NODES, GitCli, GitCliConfig, OpenError, Transports};

use crate::support::record::{Recorder, version_only};
use crate::support::{Source, TempDir, edit, host_git, listing, sha, tpath};

fn config(git: PathBuf, root: PathBuf) -> GitCliConfig {
    GitCliConfig {
        git,
        root,
        transports: Transports::Https,
        max_workspace_nodes: DEFAULT_MAX_NODES,
        credentials: None,
    }
}

#[test]
fn open_refuses() {
    let tmp = TempDir::new("open");
    let relative = GitCli::open(config(PathBuf::from("git"), tmp.path().join("a")));
    assert!(
        matches!(relative, Err(OpenError::GitNotAbsolute)),
        "{relative:?}"
    );
    assert!(!tmp.path().join("a").exists());

    let exists = tmp.path().join("exists");
    std::fs::create_dir(&exists).expect("dir");
    let got = GitCli::open(config(host_git(), exists.clone()));
    assert!(matches!(got, Err(OpenError::RootExists)), "{got:?}");
    assert_eq!(listing(&exists), Vec::<String>::new());

    for (k, answer) in [
        "git version 2.39.0",
        "",
        "git version x",
        "git version 2.38.9.vfs.1",
    ]
    .into_iter()
    .enumerate()
    {
        let git = version_only(&tmp, &format!("old-{k}"), answer);
        let root = tmp.path().join(format!("old-root-{k}"));
        let got = GitCli::open(config(git, root.clone()));
        assert!(
            matches!(got, Err(OpenError::Version { .. })),
            "{answer:?}: {got:?}"
        );
        assert!(!root.exists(), "{answer:?}: the root stays behind");
    }
    for (k, answer) in [
        "git version 2.39.1",
        "git version 2.40.0",
        "git version 2.100.0",
        "git version 3.0.0",
        "git version 2.43.0.windows.1",
    ]
    .into_iter()
    .enumerate()
    {
        let git = version_only(&tmp, &format!("new-{k}"), answer);
        let root = tmp.path().join(format!("new-root-{k}"));
        GitCli::open(config(git, root.clone())).unwrap_or_else(|e| panic!("{answer:?}: {e:?}"));
        let mode = std::fs::metadata(&root).expect("root").permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "{answer:?}");
    }
}

/// A relative root is refused before anything is created: git runs with
/// the store as its working directory and `--git-dir`, so a relative root
/// would name another directory in every call after `open`.
#[test]
fn open_refuses_a_relative_root() {
    let tmp = TempDir::new("open-relative");
    let target = tmp.path().join("relroot");
    // The same directory, relative to the test's working directory.
    let cwd = std::env::current_dir().expect("cwd");
    let mut relative = PathBuf::new();
    for _ in cwd.components().skip(1) {
        relative.push("..");
    }
    relative.push(target.strip_prefix("/").expect("absolute"));
    assert!(relative.is_relative());
    let got = GitCli::open(config(host_git(), relative));
    assert!(matches!(got, Err(OpenError::RootNotAbsolute)), "{got:?}");
    assert!(!target.exists());
}

/// Fake gits are written by a child process, so the test process never
/// holds a write descriptor to one: a process another test thread forks
/// cannot inherit such a descriptor, and exec of a script written a moment
/// earlier never fails with "Text file busy" (ETXTBSY). Here 16 threads
/// spawn processes without pause while scripts are written and started.
/// With the scripts written in-process, 35 of 400 opens failed with
/// ETXTBSY; through `write_executable`, none. About a minute under a
/// 3-CPU cap, so it is not in the default run:
/// `cargo test -p boneli-git-cli --test boneli_git_cli_tests -- --ignored open::fresh_executables`
#[test]
#[ignore = "stress: about a minute of concurrent process spawning"]
fn fresh_executables_start_under_concurrent_spawns() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const OPENS: usize = 400;
    let tmp = TempDir::new("etxtbsy");
    let stop = Arc::new(AtomicBool::new(false));
    let spawners: Vec<_> = (0..16)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = std::process::Command::new("true").status();
                }
            })
        })
        .collect();
    let mut failures = Vec::new();
    for k in 0..OPENS {
        let git = version_only(&tmp, &format!("busy-{k}"), "git version 2.56.0");
        if let Err(e) = GitCli::open(config(git, tmp.path().join(format!("busy-root-{k}")))) {
            failures.push(format!("{k}: {e}"));
        }
    }
    stop.store(true, Ordering::Relaxed);
    for spawner in spawners {
        spawner.join().expect("spawner");
    }
    assert!(
        failures.is_empty(),
        "{} of {OPENS} opens failed: {failures:?}",
        failures.len()
    );
}

// ---- The root's ancestors (ADR-024): wiring tests over
// `boneli_private_dir::create_new_root`. Each refusal also shows that no
// git ran. ----

const ANCESTOR_MODE: &str =
    "an ancestor of the root must not be writable by its group or others unless it is sticky";
const ANCESTOR_OWNER: &str = "an ancestor of the root must be owned by root or the caller";

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
}

fn uid_of(path: &Path) -> u32 {
    std::fs::metadata(path).expect("stat").uid()
}

/// A `0o700` directory `name` under the temp dir.
fn private(tmp: &TempDir, name: &str) -> PathBuf {
    let dir = tmp.path().join(name);
    std::fs::create_dir(&dir).expect("dir");
    chmod(&dir, 0o700);
    dir
}

/// Expects `OpenError::Root` and returns its path and reason.
fn refused(result: Result<GitCli, OpenError>) -> (PathBuf, &'static str) {
    match result {
        Err(OpenError::Root { path, reason }) => (path, reason),
        other => panic!("expected Root, got {other:?}"),
    }
}

/// A parent writable by its group or by others and not sticky is refused
/// at the parent; the root is not created and git does not run.
#[test]
fn open_refuses_a_root_under_a_shared_ancestor() {
    let tmp = TempDir::new("open-shared");
    let recorder = Recorder::new(&tmp);
    for (i, mode) in [0o777, 0o775, 0o757, 0o770, 0o707].into_iter().enumerate() {
        let shared = tmp.path().join(format!("shared{i}"));
        std::fs::create_dir(&shared).expect("dir");
        chmod(&shared, mode);
        let root = shared.join("root");
        let (path, reason) = refused(GitCli::open(config(recorder.git.clone(), root.clone())));
        assert_eq!((path.as_path(), reason), (shared.as_path(), ANCESTOR_MODE));
        assert!(!root.exists(), "{mode:o}: the root was created");
    }
    assert!(recorder.calls().is_empty(), "git ran");
}

/// Sticky and private parents are accepted; the root is `0o700`.
#[test]
fn open_accepts_sticky_and_private_parents() {
    let tmp = TempDir::new("open-sticky");
    for (i, mode) in [0o1777, 0o1775, 0o1757, 0o755, 0o711, 0o700]
        .into_iter()
        .enumerate()
    {
        let parent = tmp.path().join(format!("ok{i}"));
        std::fs::create_dir(&parent).expect("dir");
        chmod(&parent, mode);
        let root = parent.join("root");
        let git = GitCli::open(config(host_git(), root.clone()))
            .unwrap_or_else(|e| panic!("{mode:o}: {e}"));
        assert_eq!(git.root(), root);
        assert_eq!(mode_of(&root), 0o700, "{mode:o}");
    }
}

/// An ancestor owned by another user (`/proc/<pid>` of a process of
/// another user, mode `0o555`) is refused for its owner and git does not
/// run. Skipped when no such process is visible.
#[test]
fn open_refuses_a_foreign_owned_ancestor() {
    let tmp = TempDir::new("open-foreign");
    let recorder = Recorder::new(&tmp);
    let me = uid_of(Path::new("/proc/self"));
    for entry in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let dir = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&dir) else {
            continue;
        };
        if meta.uid() == 0 || meta.uid() == me || meta.mode() & 0o022 != 0 {
            continue;
        }
        match GitCli::open(config(recorder.git.clone(), dir.join("root"))) {
            Err(OpenError::Root { path, reason }) => {
                assert_eq!((path.as_path(), reason), (dir.as_path(), ANCESTOR_OWNER));
                assert!(recorder.calls().is_empty(), "git ran");
                return;
            }
            // The process exited between the listing and the check.
            Err(OpenError::Io(_)) if !dir.exists() => continue,
            other => panic!("{dir:?} gave {other:?}"),
        }
    }
    println!("skipped: no process of another user is visible");
}

/// A symlinked parent is resolved once, in `open`: the root is created
/// under the link's target, `root()` returns that path, and re-pointing the
/// link afterwards changes nothing the adapter writes. A link that points
/// to a `0o777` directory is refused there, and git does not run.
#[test]
fn open_resolves_a_symlinked_parent() {
    let tmp = TempDir::new("open-linked");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    let base = source.commit("base");
    let gw = tmp.path().join("gw");
    std::fs::create_dir(&gw).expect("dir");
    chmod(&gw, 0o777);
    let first = private(&tmp, "first");
    let second = private(&tmp, "second");
    // The link sits in a shared directory; what counts is where it points.
    let link = gw.join("link");
    std::os::unix::fs::symlink(&first, &link).expect("symlink");
    let mut cfg = config(host_git(), link.join("root"));
    cfg.transports = Transports::HttpsAndFile;
    let git = GitCli::open(cfg).expect("open");
    assert_eq!(git.root(), first.join("root"));
    std::fs::remove_file(&link).expect("unlink");
    std::os::unix::fs::symlink(&second, &link).expect("re-point");
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    git.diff(&c, &edit(&snapshot, &tpath("a"), Some(b"b")))
        .expect("diff");
    assert_eq!(listing(&second), Vec::<String>::new());
    assert!(!listing(&first.join("root").join("stores")).is_empty());

    let recorder = Recorder::new(&tmp);
    let to_gw = first.join("to-gw");
    std::os::unix::fs::symlink(&gw, &to_gw).expect("symlink");
    let (path, reason) = refused(GitCli::open(config(
        recorder.git.clone(),
        to_gw.join("root"),
    )));
    assert_eq!((path.as_path(), reason), (gw.as_path(), ANCESTOR_MODE));
    assert_eq!(listing(&gw), vec!["link"]);
    assert!(recorder.calls().is_empty(), "git ran");
}

/// A root with a `.` or `..` component is refused on its text; nothing is
/// created and git does not run.
#[test]
fn open_refuses_dot_components() {
    let tmp = TempDir::new("open-dots");
    let recorder = Recorder::new(&tmp);
    let ok = private(&tmp, "ok");
    for dotted in [
        "ok/../ok/root",
        "ok/./root",
        "ok/root/.",
        "ok/root/..",
        "./ok/root",
    ] {
        let root = tmp.path().join(dotted);
        let (path, reason) = refused(GitCli::open(config(recorder.git.clone(), root.clone())));
        assert_eq!(path, root, "{dotted}");
        assert_eq!(reason, "must not have a `.` or `..` component", "{dotted}");
        assert_eq!(listing(&ok), Vec::<String>::new(), "{dotted}");
    }
    assert!(recorder.calls().is_empty(), "git ran");
}

/// A root that exists in any form is `RootExists`, with link targets left
/// alone: a directory, a symlink to a directory, a dangling symlink, a
/// regular file, `/` and `//`. Git does not run.
#[test]
fn open_existing_root_forms() {
    let tmp = TempDir::new("open-exists");
    let recorder = Recorder::new(&tmp);
    let ok = private(&tmp, "ok");
    let target = private(&tmp, "target");
    std::fs::create_dir(ok.join("dir")).expect("dir");
    std::os::unix::fs::symlink(&target, ok.join("to-dir")).expect("symlink");
    std::os::unix::fs::symlink(ok.join("nowhere"), ok.join("dangling")).expect("symlink");
    std::fs::write(ok.join("file"), b"kept").expect("file");
    let mut roots: Vec<PathBuf> = ["dir", "to-dir", "dangling", "file"]
        .iter()
        .map(|name| ok.join(name))
        .collect();
    roots.push(PathBuf::from("/"));
    roots.push(PathBuf::from("//"));
    for root in roots {
        let got = GitCli::open(config(recorder.git.clone(), root.clone()));
        assert!(
            matches!(got, Err(OpenError::RootExists)),
            "{root:?}: {got:?}"
        );
    }
    assert_eq!(listing(&target), Vec::<String>::new());
    assert_eq!(listing(&ok.join("dir")), Vec::<String>::new());
    assert!(!ok.join("nowhere").exists());
    assert_eq!(std::fs::read(ok.join("file")).expect("read"), b"kept");
    assert!(recorder.calls().is_empty(), "git ran");
}

/// The mapping of the support crate's errors: a rule is `Root` and its
/// `Display` names the path and the rule; an `Io` error keeps its kind and
/// its `Display` names the path. Git does not run.
#[test]
fn open_maps_root_errors() {
    let tmp = TempDir::new("open-errors");
    let recorder = Recorder::new(&tmp);
    let ok = private(&tmp, "ok");
    let open = |root: PathBuf| GitCli::open(config(recorder.git.clone(), root));

    let file = ok.join("file");
    std::fs::write(&file, b"").expect("file");
    let got = open(file.join("root"));
    let shown = got
        .as_ref()
        .map(|_| ())
        .expect_err("a file parent")
        .to_string();
    let (path, reason) = refused(got);
    assert_eq!(path, file);
    assert_eq!(reason, "an ancestor of the root must be a directory");
    assert_eq!(shown, format!("adapter root {}: {reason}", file.display()));

    let missing = ok.join("missing");
    match open(missing.join("root")) {
        Err(OpenError::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
            assert!(e.to_string().contains(&*missing.to_string_lossy()), "{e}");
        }
        other => panic!("a missing parent gave {other:?}"),
    }
    assert_eq!(listing(&ok), vec!["file"]);

    let loop1 = ok.join("l1");
    std::os::unix::fs::symlink(ok.join("l2"), &loop1).expect("symlink");
    std::os::unix::fs::symlink(&loop1, ok.join("l2")).expect("symlink");
    match open(loop1.join("root")) {
        Err(OpenError::Io(e)) => {
            assert!(e.to_string().contains(&*loop1.to_string_lossy()), "{e}");
        }
        other => panic!("a link loop gave {other:?}"),
    }

    if uid_of(Path::new("/proc/self")) != 0 {
        let closed = private(&tmp, "closed");
        chmod(&closed, 0o600);
        let root = closed.join("root");
        match open(root.clone()) {
            Err(OpenError::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
                assert!(e.to_string().contains(&*root.to_string_lossy()), "{e}");
            }
            other => panic!("a closed parent gave {other:?}"),
        }
        chmod(&closed, 0o700);
    }
    assert!(recorder.calls().is_empty(), "git ran");
}
