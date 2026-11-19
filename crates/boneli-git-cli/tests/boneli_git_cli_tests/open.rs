//! `GitCli::open`: the git path, the root and the version floor (ADR-010,
//! D7).

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use boneli_git_cli::{DEFAULT_MAX_NODES, GitCli, GitCliConfig, OpenError, Transports};

use crate::support::record::version_only;
use crate::support::{TempDir, host_git, listing};

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
