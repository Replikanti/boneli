//! Writes a workspace onto the host (ADR-010, D3).
//!
//! [`materialize`] runs as the runner user on agent-written entries, so it
//! never trusts what is already on disk and never follows a symlink:
//!
//! - The target must be a new, empty directory with mode 0700, checked
//!   without following a symlink.
//! - Everything is checked before anything is written: repository metadata
//!   (ADR-010, D1) is refused as defense in depth, although `diff` drops it
//!   first, and so is an entry at or under a gitlink and a gitlink beneath
//!   an entry or in repository metadata.
//! - Parents are made one component at a time with `create_dir`; one that
//!   already exists must be a real directory by `symlink_metadata`, so a
//!   symlink the workspace planted is never a parent. The workspace keeps
//!   every entry off the paths beneath another entry, so this check fires
//!   only on a case or normalization alias of a name already written.
//! - The workspace's files, symlinks and implied directories plus the
//!   gitlinks' directories must fit `max_nodes`, checked before the first
//!   write.
//! - Files are opened with `create_new`, which also refuses a symlink at
//!   the final name, and get their mode through the open file, so the
//!   umask does not matter. A directory gets 0755 by a `chmod` of its path
//!   right after `create_dir` made it, so the umask does not matter there
//!   either.
//! - Each directory is created once, in path order, so the work is linear
//!   in the number of nodes; every path-based call walks at most
//!   `PATH_MAX` bytes.
//! - Symlinks are created with their target as raw bytes and never
//!   resolved.
//! - Each gitlink becomes an empty directory, so `git add -A` keeps it.
//!
//! On an error the directory may hold part of the workspace; the caller
//! removes it.
//!
//! Paths reach the kernel as raw bytes (`OsStr::from_bytes`), and only `/`
//! splits them: a backslash, a blank name and bytes that are not UTF-8
//! are name bytes, so `..\x` or an overlong `..` is one entry inside the
//! target (ADR-018, D2).
//!
//! The calls are path-based, so the kernel follows a symlink in an
//! intermediate component. Within the private 0700 target only a process
//! of the runner's own uid could plant one while the write runs, and such
//! a process already holds everything the runner holds, so no permission
//! boundary is crossed.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::Path;

use boneli_app::TreePath;

use crate::workspace::{Workspace, common_prefix, slashes};

/// Why the target directory is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryProblem {
    /// It is missing, a symlink or not a directory.
    NotADirectory,
    /// Its permission bits are not 0700.
    Mode(u32),
    /// It holds something.
    NotEmpty,
}

/// The item an error is about: a workspace entry or a gitlink, by index in
/// path order or in the order given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    /// The n-th workspace entry.
    Entry(usize),
    /// The n-th gitlink.
    Gitlink(usize),
}

impl fmt::Display for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Item::Entry(n) => write!(f, "entry {n}"),
            Item::Gitlink(n) => write!(f, "gitlink {n}"),
        }
    }
}

/// Why a workspace was not written. A detail quotes indexes, never the
/// agent-written paths.
#[derive(Debug)]
pub enum MaterializeError {
    /// The target directory is refused.
    Directory(DirectoryProblem),
    /// The item is repository metadata.
    Metadata(Item),
    /// The entry is at or under a gitlink.
    AtGitlink(Item),
    /// The gitlink lies beneath a file or symlink entry.
    GitlinkBeneathEntry(Item),
    /// The workspace and the gitlinks make more files, symlinks and
    /// directories than the cap.
    TooManyNodes {
        /// The cap.
        max: usize,
    },
    /// A parent of the item exists and is not a real directory.
    NotADirectory(Item),
    /// The file system refused a write.
    Io(Option<Item>, std::io::Error),
}

impl fmt::Display for MaterializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaterializeError::Directory(DirectoryProblem::NotADirectory) => {
                write!(f, "the target is not a directory")
            }
            MaterializeError::Directory(DirectoryProblem::Mode(mode)) => {
                write!(f, "the target has mode {mode:o}, not 700")
            }
            MaterializeError::Directory(DirectoryProblem::NotEmpty) => {
                write!(f, "the target is not empty")
            }
            MaterializeError::Metadata(item) => write!(f, "{item} is repository metadata"),
            MaterializeError::AtGitlink(item) => write!(f, "{item} is at or under a gitlink"),
            MaterializeError::GitlinkBeneathEntry(item) => {
                write!(f, "{item} lies beneath a workspace entry")
            }
            MaterializeError::TooManyNodes { max } => write!(
                f,
                "more than {max} files, symlinks and directories (the node cap)"
            ),
            MaterializeError::NotADirectory(item) => {
                write!(f, "a parent of {item} exists and is not a directory")
            }
            MaterializeError::Io(Some(item), error) => write!(f, "{item}: {error}"),
            MaterializeError::Io(None, error) => write!(f, "the target: {error}"),
        }
    }
}

impl std::error::Error for MaterializeError {}

/// Writes `workspace` into `dir`, a new, empty directory with mode 0700,
/// and an empty directory at each of `gitlinks`, unless that makes more
/// than `max_nodes` files, symlinks and directories. A decoded workspace
/// already holds its own cap ([`Workspace::decode`]); this one also
/// counts the gitlinks and holds for a workspace built in code.
pub fn materialize(
    workspace: &Workspace,
    dir: &Path,
    gitlinks: &[TreePath],
    max_nodes: usize,
) -> Result<(), MaterializeError> {
    check_target(dir)?;
    check_items(workspace, gitlinks, max_nodes)?;
    write_entries(workspace, dir)?;
    for (n, gitlink) in gitlinks.iter().enumerate() {
        let item = Item::Gitlink(n);
        create_parents(dir, gitlink.as_bytes(), 0, item)?;
        create_directory(dir, gitlink.as_bytes(), item)?;
    }
    Ok(())
}

/// `dir` is a real directory (not a symlink to one), mode 0700, empty.
fn check_target(dir: &Path) -> Result<(), MaterializeError> {
    let refused = |problem| Err(MaterializeError::Directory(problem));
    let meta = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return refused(DirectoryProblem::NotADirectory);
        }
        Err(e) => return Err(MaterializeError::Io(None, e)),
    };
    if !meta.file_type().is_dir() {
        return refused(DirectoryProblem::NotADirectory);
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode != 0o700 {
        return refused(DirectoryProblem::Mode(mode));
    }
    let mut listing = fs::read_dir(dir).map_err(|e| MaterializeError::Io(None, e))?;
    if listing.next().is_some() {
        return refused(DirectoryProblem::NotEmpty);
    }
    Ok(())
}

/// Everything that can be refused without touching the disk.
fn check_items(
    workspace: &Workspace,
    gitlinks: &[TreePath],
    max_nodes: usize,
) -> Result<(), MaterializeError> {
    let links: BTreeSet<&[u8]> = gitlinks.iter().map(TreePath::as_bytes).collect();
    // No ancestor longer than the longest gitlink can be one, so a deep
    // agent-written path costs at most that many bytes of lookups.
    let longest = links.iter().map(|g| g.len()).max().unwrap_or(0);
    for (n, (path, _, _)) in workspace.iter().enumerate() {
        if path.is_repository_metadata() {
            return Err(MaterializeError::Metadata(Item::Entry(n)));
        }
        let text = path.as_bytes();
        let at = text.len() <= longest && links.contains(text);
        let under = slashes(text)
            .take_while(|i| *i <= longest)
            .any(|i| links.contains(&text[..i]));
        if at || under {
            return Err(MaterializeError::AtGitlink(Item::Entry(n)));
        }
    }
    // An entry at a gitlink's own path was refused above.
    for (n, gitlink) in gitlinks.iter().enumerate() {
        if gitlink.is_repository_metadata() {
            return Err(MaterializeError::Metadata(Item::Gitlink(n)));
        }
        let text = gitlink.as_bytes();
        let beneath = slashes(text).any(|i| {
            // A proper ancestor of a tree path always parses; were it
            // refused, it would be no entry's path.
            TreePath::parse(&text[..i]).is_ok_and(|p| workspace.get(&p).is_some())
        });
        if beneath {
            return Err(MaterializeError::GitlinkBeneathEntry(Item::Gitlink(n)));
        }
    }
    // The directories the gitlinks add: each gitlink and its parents,
    // once, unless an entry already implies them. Gitlinks come from the
    // base tree, so this set stays small.
    let mut gitlink_directories = BTreeSet::new();
    for gitlink in gitlinks {
        let text = gitlink.as_bytes();
        let parents = slashes(text).map(|i| &text[..i]);
        gitlink_directories.extend(parents.chain([text]));
    }
    let added = gitlink_directories
        .iter()
        .filter(|d| !workspace.implies_directory(d))
        .count();
    if workspace.nodes().saturating_add(added) > max_nodes {
        return Err(MaterializeError::TooManyNodes { max: max_nodes });
    }
    Ok(())
}

/// Writes every entry in path order. The workspace keeps every entry off
/// the paths beneath another, so no entry is written through a symlink
/// written before it; `create_parents` and `create_new` check it anyway.
///
/// Each directory is created once: the parents an entry shares with the
/// previous entry lie inside their common prefix and were made for that
/// entry (`workspace::new_directories`), so only the rest are created.
/// Creating every parent again for every entry cost O(depth^2) path
/// lookups per entry: 500 entries under one chain of 1,900 directories
/// took 150 s (review of part 2).
fn write_entries(workspace: &Workspace, dir: &Path) -> Result<(), MaterializeError> {
    let mut previous: Option<&[u8]> = None;
    for (n, (path, kind, data)) in workspace.iter().enumerate() {
        let item = Item::Entry(n);
        let io = |e| MaterializeError::Io(Some(item), e);
        let text = path.as_bytes();
        let shared = previous.map_or(0, |p| common_prefix(p, text));
        create_parents(dir, text, shared, item)?;
        previous = Some(text);
        let target = dir.join(OsStr::from_bytes(text));
        match kind.mode() {
            Some(mode) => {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&target)
                    .map_err(io)?;
                file.write_all(data).map_err(io)?;
                file.set_permissions(fs::Permissions::from_mode(mode))
                    .map_err(io)?;
            }
            None => symlink(OsStr::from_bytes(data), &target).map_err(io)?,
        }
    }
    Ok(())
}

/// Creates the parents of `rel` inside `dir` whose `/` lies at or past
/// byte `from`, one component at a time; an existing one must be a real
/// directory.
fn create_parents(dir: &Path, rel: &[u8], from: usize, item: Item) -> Result<(), MaterializeError> {
    for i in slashes(rel).filter(|i| *i >= from) {
        create_directory(dir, &rel[..i], item)?;
    }
    Ok(())
}

/// Creates the directory `rel` inside `dir` with mode 0755, or accepts an
/// existing real directory there.
fn create_directory(dir: &Path, rel: &[u8], item: Item) -> Result<(), MaterializeError> {
    let target = dir.join(OsStr::from_bytes(rel));
    match fs::create_dir(&target) {
        Ok(()) => fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .map_err(|e| MaterializeError::Io(Some(item), e)),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => match fs::symlink_metadata(&target) {
            Ok(meta) if meta.file_type().is_dir() => Ok(()),
            Ok(_) => Err(MaterializeError::NotADirectory(item)),
            Err(e) => Err(MaterializeError::Io(Some(item), e)),
        },
        Err(e) => Err(MaterializeError::Io(Some(item), e)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;
    use crate::scratch::ScratchDir;
    use crate::workspace::{DEFAULT_MAX_NODES, Kind};

    fn path(text: &str) -> TreePath {
        TreePath::parse(text.as_bytes()).expect("a valid path")
    }

    fn workspace(entries: &[(&str, Kind, &[u8])]) -> Workspace {
        let mut w = Workspace::new();
        for (p, kind, data) in entries {
            w.insert(path(p), *kind, data.to_vec()).expect("valid");
        }
        w
    }

    /// A scratch dir holding `target`, a new 0700 directory, and
    /// `outside`, an empty directory next to it.
    fn target(tag: &str) -> (ScratchDir, PathBuf, PathBuf) {
        let scratch = ScratchDir::new(tag);
        let dir = scratch.path().join("target");
        fs::create_dir(&dir).expect("target");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        let outside = scratch.path().join("outside");
        fs::create_dir(&outside).expect("outside");
        (scratch, dir, outside)
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p)
            .expect("exists")
            .permissions()
            .mode()
            & 0o7777
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in fs::read_dir(&d).expect("read_dir") {
                let p = entry.expect("entry").path();
                let rel = p.strip_prefix(dir).expect("inside");
                out.push(rel.to_string_lossy().into_owned());
                if fs::symlink_metadata(&p).expect("meta").is_dir() {
                    stack.push(p);
                }
            }
        }
        out.sort();
        out
    }

    /// Set in the child that re-runs the modes test under `umask 077`.
    const UMASK_CHILD: &str = "BONELI_GIT_CLI_UMASK_CHILD";

    /// The modes do not depend on the umask: the test runs here and again
    /// in a child under `umask 077`, where a directory left to the umask
    /// would be 0700 and a file 0600. The crate cannot call `umask` itself
    /// (no `unsafe`), so the child is this test binary started by `sh`.
    #[test]
    fn materialize_sets_explicit_modes() {
        if std::env::var_os(UMASK_CHILD).is_some() {
            // The umask really is 077 here: a plain `create_dir` gives 0700.
            let probe = ScratchDir::new("umask-probe");
            fs::create_dir(probe.path().join("d")).expect("probe");
            assert_eq!(mode(&probe.path().join("d")), 0o700, "umask 077");
            explicit_modes();
            return;
        }
        explicit_modes();
        let exe = std::env::current_exe().expect("the test binary");
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg("umask 077 && exec \"$0\" \"$@\"")
            .arg(exe)
            .args([
                "--exact",
                "materialize::tests::materialize_sets_explicit_modes",
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

    fn explicit_modes() {
        let (_scratch, dir, _) = target("modes");
        let w = workspace(&[
            ("a/plain.txt", Kind::File, b"plain"),
            ("a/run.sh", Kind::Executable, b"#!/bin/sh\n"),
            ("a\nb", Kind::File, b""),
        ]);
        materialize(&w, &dir, &[path("g/sub")], DEFAULT_MAX_NODES).expect("written");
        assert_eq!(mode(&dir.join("a/plain.txt")), 0o644);
        assert_eq!(mode(&dir.join("a/run.sh")), 0o755);
        for d in ["a", "g", "g/sub"] {
            assert_eq!(mode(&dir.join(d)), 0o755, "{d}");
        }
        assert_eq!(fs::read(dir.join("a/plain.txt")).expect("read"), b"plain");
        assert_eq!(
            fs::read(dir.join("a/run.sh")).expect("read"),
            b"#!/bin/sh\n"
        );
        assert_eq!(fs::read(dir.join("a\nb")).expect("read"), b"");
        // Byte order: `\n` sorts before `/`.
        assert_eq!(
            listing(&dir),
            ["a", "a\nb", "a/plain.txt", "a/run.sh", "g", "g/sub"]
        );
    }

    /// The node cap counts implied directories and gitlink directories,
    /// and holds before anything is written.
    #[test]
    fn materialize_refuses_past_the_node_cap() {
        let deep = "a/".repeat(10) + "f";
        let w = workspace(&[(deep.as_str(), Kind::File, b"")]);
        let (_scratch, dir, _) = target("node-cap");
        let refused = materialize(&w, &dir, &[], 10);
        assert!(
            matches!(refused, Err(MaterializeError::TooManyNodes { max: 10 })),
            "{refused:?}"
        );
        assert!(listing(&dir).is_empty());
        materialize(&w, &dir, &[], 11).expect("written");
        assert_eq!(listing(&dir).len(), 11);

        // `v`, `v/r`, plus `v/lib` for the gitlink; `x` and `x/y` for the
        // second.
        let w = workspace(&[("v/r", Kind::File, b"")]);
        let (_scratch, dir, _) = target("node-cap-gitlink");
        let refused = materialize(&w, &dir, &[path("v/lib")], 2);
        assert!(
            matches!(refused, Err(MaterializeError::TooManyNodes { max: 2 })),
            "{refused:?}"
        );
        assert!(listing(&dir).is_empty());
        let gitlinks = [path("v/lib"), path("x/y")];
        let refused = materialize(&w, &dir, &gitlinks, 4);
        assert!(
            matches!(refused, Err(MaterializeError::TooManyNodes { max: 4 })),
            "{refused:?}"
        );
        materialize(&w, &dir, &gitlinks, 5).expect("written");
        assert_eq!(listing(&dir).len(), 5);
    }

    /// What `materialize` creates is exactly what the cap counted.
    #[test]
    fn materialize_creates_exactly_its_nodes() {
        let w = workspace(&[
            ("Z", Kind::File, b""),
            ("a b/c", Kind::File, b""),
            ("a.txt", Kind::File, b""),
            ("a/b/c/d", Kind::File, b""),
            ("a/b/c/e", Kind::Symlink, b"/"),
            ("a/b/x", Kind::Executable, b""),
            ("a/bc/y", Kind::File, b""),
            ("a/c", Kind::File, b""),
            ("b/a/b/c", Kind::File, b""),
        ]);
        let (_scratch, dir, _) = target("exact-nodes");
        // `a/b/sub` adds itself; `q` and `q/r` add two.
        let gitlinks = [path("a/b/sub"), path("q/r")];
        materialize(&w, &dir, &gitlinks, w.nodes() + 3).expect("written");
        assert_eq!(listing(&dir).len(), w.nodes() + 3);
        let (_scratch, dir, _) = target("exact-nodes-short");
        let refused = materialize(&w, &dir, &gitlinks, w.nodes() + 2);
        assert!(
            matches!(refused, Err(MaterializeError::TooManyNodes { .. })),
            "{refused:?}"
        );
    }

    /// The review's shape: 500 entries under one chain of 1,900
    /// directories. Creating every parent for every entry took 150 s in a
    /// release build; creating each directory once takes well under a
    /// second. The bound leaves a wide margin both ways.
    #[test]
    fn materialize_is_linear_in_path_depth() {
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
        let chain = "a/".repeat(1900);
        let names: Vec<String> = (0..500).map(|n| format!("{chain}f{n:05}")).collect();
        // Built through `decode`, which is linear; `insert` looks every
        // ancestor up and is meant for short paths.
        let mut bytes = crate::workspace::MAGIC.to_vec();
        for name in &names {
            bytes.push(b'f');
            bytes.extend_from_slice(&(name.len() as u64).to_be_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(&1u64.to_be_bytes());
            bytes.push(b'x');
        }
        let w = Workspace::decode(&bytes, DEFAULT_MAX_NODES).expect("decodes");
        let (_scratch, dir, _) = target("linear");
        let start = std::time::Instant::now();
        materialize(&w, &dir, &[], DEFAULT_MAX_NODES).expect("written");
        assert!(start.elapsed() < DEADLINE, "{:?}", start.elapsed());
        assert_eq!(w.nodes(), 1900 + 500);
        let last = dir.join(&names[499]);
        assert_eq!(fs::read(last).expect("the last file"), b"x");
    }

    #[test]
    fn materialize_creates_symlinks_without_following_them() {
        let (_scratch, dir, outside) = target("symlink");
        let raw_target: Vec<u8> = (1..=255u8).filter(|b| *b != b'/').collect();
        let out_target = outside.as_os_str().as_bytes().to_vec();
        let w = workspace(&[
            ("k", Kind::File, b"k"),
            ("root", Kind::Symlink, b"/"),
            ("out", Kind::Symlink, &out_target),
            ("raw", Kind::Symlink, &raw_target),
            ("z", Kind::File, b"z"),
        ]);
        materialize(&w, &dir, &[], DEFAULT_MAX_NODES).expect("written");
        let link = |name: &str| fs::read_link(dir.join(name)).expect("a symlink");
        assert_eq!(link("root"), PathBuf::from("/"));
        assert_eq!(link("out").as_os_str().as_bytes(), out_target.as_slice());
        assert_eq!(link("raw").as_os_str().as_bytes(), raw_target.as_slice());
        assert!(fs::read_dir(&outside).expect("outside").next().is_none());

        // A gitlink beneath a symlink entry is refused before anything is
        // written, so nothing appears outside.
        let (_scratch, dir, outside) = target("symlink-gitlink");
        let w = workspace(&[("out", Kind::Symlink, &out_target)]);
        let refused = materialize(&w, &dir, &[path("out/sub")], DEFAULT_MAX_NODES);
        assert!(
            matches!(
                refused,
                Err(MaterializeError::GitlinkBeneathEntry(Item::Gitlink(0)))
            ),
            "{refused:?}"
        );
        assert!(listing(&dir).is_empty());
        assert!(fs::read_dir(&outside).expect("outside").next().is_none());
    }

    /// The parent check on its own: a symlink already at a parent's name is
    /// never written through, whatever planted it.
    #[test]
    fn materialize_never_writes_through_a_planted_parent() {
        let (_scratch, dir, outside) = target("planted");
        std::os::unix::fs::symlink(&outside, dir.join("p")).expect("plant");
        let refused = create_parents(&dir, b"p/x", 0, Item::Entry(0));
        assert!(
            matches!(
                refused,
                Err(MaterializeError::NotADirectory(Item::Entry(0)))
            ),
            "{refused:?}"
        );
        fs::write(dir.join("f"), b"").expect("plant a file");
        let refused = create_parents(&dir, b"f/x", 0, Item::Entry(1));
        assert!(
            matches!(
                refused,
                Err(MaterializeError::NotADirectory(Item::Entry(1)))
            ),
            "{refused:?}"
        );
        assert!(fs::read_dir(&outside).expect("outside").next().is_none());
        // A symlink at a file's own name is not opened through either: the
        // file it points to keeps its content.
        let victim = outside.join("victim");
        fs::write(&victim, b"keep").expect("victim");
        std::os::unix::fs::symlink(&victim, dir.join("q")).expect("plant");
        let w = workspace(&[("q", Kind::File, b"overwritten")]);
        let refused = write_entries(&w, &dir);
        assert!(
            matches!(refused, Err(MaterializeError::Io(Some(Item::Entry(0)), _))),
            "{refused:?}"
        );
        assert_eq!(fs::read(&victim).expect("victim"), b"keep");
        assert_eq!(mode(&victim) & 0o111, 0, "its mode is untouched too");
    }

    #[test]
    fn materialize_refuses_a_target_that_is_not_new() {
        let w = workspace(&[("a", Kind::File, b"x")]);

        let (_scratch, dir, _) = target("non-empty");
        fs::write(dir.join("old"), b"").expect("plant");
        let refused = materialize(&w, &dir, &[], DEFAULT_MAX_NODES);
        assert!(
            matches!(
                refused,
                Err(MaterializeError::Directory(DirectoryProblem::NotEmpty))
            ),
            "{refused:?}"
        );
        assert_eq!(listing(&dir), ["old"]);

        let (_scratch, dir, _) = target("mode");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod");
        let refused = materialize(&w, &dir, &[], DEFAULT_MAX_NODES);
        assert!(
            matches!(
                refused,
                Err(MaterializeError::Directory(DirectoryProblem::Mode(0o755)))
            ),
            "{refused:?}"
        );

        let (scratch, dir, _) = target("link");
        let link = scratch.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).expect("link");
        let refused = materialize(&w, &link, &[], DEFAULT_MAX_NODES);
        assert!(
            matches!(
                refused,
                Err(MaterializeError::Directory(DirectoryProblem::NotADirectory))
            ),
            "{refused:?}"
        );
        assert!(listing(&dir).is_empty());

        let refused = materialize(&w, &scratch.path().join("missing"), &[], DEFAULT_MAX_NODES);
        assert!(
            matches!(
                refused,
                Err(MaterializeError::Directory(DirectoryProblem::NotADirectory))
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn materialize_creates_gitlink_placeholders() {
        let (_scratch, dir, _) = target("gitlink");
        let w = workspace(&[("vendor/README", Kind::File, b"r")]);
        materialize(
            &w,
            &dir,
            &[path("vendor/lib"), path("deep/er/mod")],
            DEFAULT_MAX_NODES,
        )
        .expect("written");
        for g in ["vendor/lib", "deep/er/mod"] {
            let meta = fs::symlink_metadata(dir.join(g)).expect("exists");
            assert!(meta.is_dir(), "{g}");
            assert!(fs::read_dir(dir.join(g)).expect("dir").next().is_none());
            assert_eq!(mode(&dir.join(g)), 0o755);
        }
        assert_eq!(
            listing(&dir),
            [
                "deep",
                "deep/er",
                "deep/er/mod",
                "vendor",
                "vendor/README",
                "vendor/lib"
            ]
        );
    }

    #[test]
    fn materialize_refuses_an_entry_at_or_under_a_gitlink() {
        let gitlinks = [path("other"), path("vendor/lib")];
        let cases = ["vendor/lib", "vendor/lib/x", "other/a/b"];
        for entry in cases {
            let (_scratch, dir, _) = target("under-gitlink");
            let w = workspace(&[("a", Kind::File, b"a"), (entry, Kind::File, b"x")]);
            let refused = materialize(&w, &dir, &gitlinks, DEFAULT_MAX_NODES);
            assert!(
                matches!(refused, Err(MaterializeError::AtGitlink(Item::Entry(1)))),
                "{entry}: {refused:?}"
            );
            assert!(listing(&dir).is_empty(), "{entry}: nothing is written");
        }
        // A sibling that only shares a prefix is not under the gitlink.
        let (_scratch, dir, _) = target("gitlink-sibling");
        let w = workspace(&[("vendor/lib.rs", Kind::File, b"x")]);
        materialize(&w, &dir, &gitlinks, DEFAULT_MAX_NODES).expect("written");
        // A gitlink beneath a file entry is refused too.
        let (_scratch, dir, _) = target("gitlink-under-file");
        let w = workspace(&[("vendor", Kind::File, b"x")]);
        let refused = materialize(&w, &dir, &gitlinks, DEFAULT_MAX_NODES);
        assert!(
            matches!(
                refused,
                Err(MaterializeError::GitlinkBeneathEntry(Item::Gitlink(1)))
            ),
            "{refused:?}"
        );
        assert!(listing(&dir).is_empty());
    }

    /// Backslash traversal, overlong `/` and `..`, blank and non-UTF-8
    /// names are name bytes: each becomes one entry inside the target, with
    /// its bytes as written, and nothing appears outside (ADR-018, D2).
    #[test]
    fn materialize_writes_uncitable_names_literally() {
        let (_scratch, dir, outside) = target("uncitable");
        let names: [&[u8]; 8] = [
            b" ",
            b"..\\x",
            b"\xc0\xae\xc0\xae",
            b"\xc0\xaf",
            b"a\\..\\b",
            "\u{200B}".as_bytes(),
            b"d\\e",
            b"x\xff",
        ];
        let mut w = Workspace::new();
        for name in names.iter().filter(|n| **n != b"d\\e") {
            let p = TreePath::parse(name).expect("a tree path");
            w.insert(p, Kind::File, name.to_vec()).expect("valid");
        }
        let link = TreePath::parse(b"l\\x").expect("a tree path");
        w.insert(link, Kind::Symlink, b"x\xff".to_vec())
            .expect("valid");
        let nested = TreePath::parse(b"d\\e/f").expect("a tree path");
        w.insert(nested, Kind::Executable, b"f".to_vec())
            .expect("valid");
        materialize(&w, &dir, &[], w.nodes()).expect("written");
        let mut top: Vec<Vec<u8>> = fs::read_dir(&dir)
            .expect("the target")
            .map(|e| e.expect("entry").file_name().as_bytes().to_vec())
            .collect();
        top.sort();
        let mut want: Vec<Vec<u8>> = names.iter().map(|n| n.to_vec()).collect();
        want.push(b"l\\x".to_vec());
        want.sort();
        assert_eq!(top, want);
        for name in names.iter().filter(|n| **n != b"d\\e") {
            let file = dir.join(OsStr::from_bytes(name));
            assert_eq!(fs::read(&file).expect("a file"), *name, "{name:?}");
        }
        let link = fs::read_link(dir.join(OsStr::from_bytes(b"l\\x"))).expect("a symlink");
        assert_eq!(link.as_os_str().as_bytes(), b"x\xff");
        let nested = dir.join(OsStr::from_bytes(b"d\\e")).join("f");
        assert_eq!(mode(&nested), 0o755);
        assert_eq!(w.nodes(), 10);
        assert!(fs::read_dir(&outside).expect("outside").next().is_none());
        assert!(
            fs::read_dir(dir.parent().expect("the scratch"))
                .expect("scratch")
                .count()
                == 2
        );
    }

    #[test]
    fn materialize_refuses_metadata() {
        let entries: [&[(&str, Kind, &[u8])]; 3] = [
            &[(".git/config", Kind::File, b"[core]")],
            &[("a", Kind::File, b""), ("sub/.git", Kind::Symlink, b"/")],
            &[(".git", Kind::File, b"gitdir: /x")],
        ];
        for entries in entries {
            let (_scratch, dir, _) = target("metadata");
            let w = workspace(entries);
            let refused = materialize(&w, &dir, &[], DEFAULT_MAX_NODES);
            assert!(
                matches!(refused, Err(MaterializeError::Metadata(Item::Entry(_)))),
                "{entries:?}: {refused:?}"
            );
            assert!(listing(&dir).is_empty(), "{entries:?}");
        }
        let (_scratch, dir, _) = target("metadata-gitlink");
        let refused = materialize(
            &Workspace::new(),
            &dir,
            &[path("sub/.git/x")],
            DEFAULT_MAX_NODES,
        );
        assert!(
            matches!(refused, Err(MaterializeError::Metadata(Item::Gitlink(0)))),
            "{refused:?}"
        );
        assert!(listing(&dir).is_empty());
    }
}
