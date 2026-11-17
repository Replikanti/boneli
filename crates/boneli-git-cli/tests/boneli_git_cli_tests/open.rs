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
