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
//! - Files are opened with `create_new`, which also refuses a symlink at
//!   the final name, and get their mode through the open file, so the
//!   umask does not matter. Directories get 0755 the same way.
//! - Symlinks are created with their target as raw bytes and never
//!   resolved.
//! - Each gitlink becomes an empty directory, so `git add -A` keeps it.
//!
//! On an error the directory may hold part of the workspace; the caller
//! removes it.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::Path;

use boneli_app::RelativePath;

use crate::workspace::Workspace;

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
/// and an empty directory at each of `gitlinks`.
pub fn materialize(
    workspace: &Workspace,
    dir: &Path,
    gitlinks: &[RelativePath],
) -> Result<(), MaterializeError> {
    check_target(dir)?;
    check_items(workspace, gitlinks)?;
    write_entries(workspace, dir)?;
    for (n, gitlink) in gitlinks.iter().enumerate() {
        let item = Item::Gitlink(n);
        create_parents(dir, gitlink.as_str(), item)?;
        create_directory(dir, gitlink.as_str(), item)?;
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
fn check_items(workspace: &Workspace, gitlinks: &[RelativePath]) -> Result<(), MaterializeError> {
    let links: BTreeSet<&str> = gitlinks.iter().map(RelativePath::as_str).collect();
    // No ancestor longer than the longest gitlink can be one, so a deep
    // agent-written path costs at most that many bytes of lookups.
    let longest = links.iter().map(|g| g.len()).max().unwrap_or(0);
    for (n, (path, _, _)) in workspace.iter().enumerate() {
        if path.is_repository_metadata() {
            return Err(MaterializeError::Metadata(Item::Entry(n)));
        }
        let text = path.as_str();
        let at = text.len() <= longest && links.contains(text);
        let under = text
            .match_indices('/')
            .take_while(|(i, _)| *i <= longest)
            .any(|(i, _)| links.contains(&text[..i]));
        if at || under {
            return Err(MaterializeError::AtGitlink(Item::Entry(n)));
        }
    }
    // An entry at a gitlink's own path was refused above.
    for (n, gitlink) in gitlinks.iter().enumerate() {
        if gitlink.is_repository_metadata() {
            return Err(MaterializeError::Metadata(Item::Gitlink(n)));
        }
        let text = gitlink.as_str();
        let beneath = text.match_indices('/').any(|(i, _)| {
            // An ancestor that does not parse (a blank first component)
            // is no entry's path.
            RelativePath::parse(&text[..i]).is_ok_and(|p| workspace.get(&p).is_some())
        });
        if beneath {
            return Err(MaterializeError::GitlinkBeneathEntry(Item::Gitlink(n)));
        }
    }
    Ok(())
}

/// Writes every entry in path order. The workspace keeps every entry off
/// the paths beneath another, so no entry is written through a symlink
/// written before it; `create_parents` and `create_new` check it anyway.
fn write_entries(workspace: &Workspace, dir: &Path) -> Result<(), MaterializeError> {
    for (n, (path, kind, data)) in workspace.iter().enumerate() {
        let item = Item::Entry(n);
        let io = |e| MaterializeError::Io(Some(item), e);
        create_parents(dir, path.as_str(), item)?;
        let target = dir.join(path.as_str());
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

/// Creates every missing parent of `rel` inside `dir`, one component at a
/// time; an existing one must be a real directory.
fn create_parents(dir: &Path, rel: &str, item: Item) -> Result<(), MaterializeError> {
    for (i, _) in rel.match_indices('/') {
        create_directory(dir, &rel[..i], item)?;
    }
    Ok(())
}

/// Creates the directory `rel` inside `dir` with mode 0755, or accepts an
/// existing real directory there.
fn create_directory(dir: &Path, rel: &str, item: Item) -> Result<(), MaterializeError> {
    let target = dir.join(rel);
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
    use crate::workspace::Kind;

    fn path(text: &str) -> RelativePath {
        RelativePath::parse(text).expect("a valid path")
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

    #[test]
    fn materialize_sets_explicit_modes() {
        let (_scratch, dir, _) = target("modes");
        let w = workspace(&[
            ("a/plain.txt", Kind::File, b"plain"),
            ("a/run.sh", Kind::Executable, b"#!/bin/sh\n"),
            ("a\nb", Kind::File, b""),
        ]);
        materialize(&w, &dir, &[]).expect("written");
        assert_eq!(mode(&dir.join("a/plain.txt")), 0o644);
        assert_eq!(mode(&dir.join("a/run.sh")), 0o755);
        assert_eq!(mode(&dir.join("a")), 0o755);
        assert_eq!(fs::read(dir.join("a/plain.txt")).expect("read"), b"plain");
        assert_eq!(
            fs::read(dir.join("a/run.sh")).expect("read"),
            b"#!/bin/sh\n"
        );
        assert_eq!(fs::read(dir.join("a\nb")).expect("read"), b"");
        // Byte order: `\n` sorts before `/`.
        assert_eq!(listing(&dir), ["a", "a\nb", "a/plain.txt", "a/run.sh"]);
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
        materialize(&w, &dir, &[]).expect("written");
        let link = |name: &str| fs::read_link(dir.join(name)).expect("a symlink");
        assert_eq!(link("root"), PathBuf::from("/"));
        assert_eq!(link("out").as_os_str().as_bytes(), out_target.as_slice());
        assert_eq!(link("raw").as_os_str().as_bytes(), raw_target.as_slice());
        assert!(fs::read_dir(&outside).expect("outside").next().is_none());

        // A gitlink beneath a symlink entry is refused before anything is
        // written, so nothing appears outside.
        let (_scratch, dir, outside) = target("symlink-gitlink");
        let w = workspace(&[("out", Kind::Symlink, &out_target)]);
        let refused = materialize(&w, &dir, &[path("out/sub")]);
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
        let refused = create_parents(&dir, "p/x", Item::Entry(0));
        assert!(
            matches!(
                refused,
                Err(MaterializeError::NotADirectory(Item::Entry(0)))
            ),
            "{refused:?}"
        );
        fs::write(dir.join("f"), b"").expect("plant a file");
        let refused = create_parents(&dir, "f/x", Item::Entry(1));
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
        let refused = materialize(&w, &dir, &[]);
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
        let refused = materialize(&w, &dir, &[]);
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
        let refused = materialize(&w, &link, &[]);
        assert!(
            matches!(
                refused,
                Err(MaterializeError::Directory(DirectoryProblem::NotADirectory))
            ),
            "{refused:?}"
        );
        assert!(listing(&dir).is_empty());

        let refused = materialize(&w, &scratch.path().join("missing"), &[]);
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
        materialize(&w, &dir, &[path("vendor/lib"), path("deep/er/mod")]).expect("written");
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
            let refused = materialize(&w, &dir, &gitlinks);
            assert!(
                matches!(refused, Err(MaterializeError::AtGitlink(Item::Entry(1)))),
                "{entry}: {refused:?}"
            );
            assert!(listing(&dir).is_empty(), "{entry}: nothing is written");
        }
        // A sibling that only shares a prefix is not under the gitlink.
        let (_scratch, dir, _) = target("gitlink-sibling");
        let w = workspace(&[("vendor/lib.rs", Kind::File, b"x")]);
        materialize(&w, &dir, &gitlinks).expect("written");
        // A gitlink beneath a file entry is refused too.
        let (_scratch, dir, _) = target("gitlink-under-file");
        let w = workspace(&[("vendor", Kind::File, b"x")]);
        let refused = materialize(&w, &dir, &gitlinks);
        assert!(
            matches!(
                refused,
                Err(MaterializeError::GitlinkBeneathEntry(Item::Gitlink(1)))
            ),
            "{refused:?}"
        );
        assert!(listing(&dir).is_empty());
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
            let refused = materialize(&w, &dir, &[]);
            assert!(
                matches!(refused, Err(MaterializeError::Metadata(Item::Entry(_)))),
                "{entries:?}: {refused:?}"
            );
            assert!(listing(&dir).is_empty(), "{entries:?}");
        }
        let (_scratch, dir, _) = target("metadata-gitlink");
        let refused = materialize(&Workspace::new(), &dir, &[path("sub/.git/x")]);
        assert!(
            matches!(refused, Err(MaterializeError::Metadata(Item::Gitlink(0)))),
            "{refused:?}"
        );
        assert!(listing(&dir).is_empty());
    }
}
