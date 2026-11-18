//! The patch policy's input from two workspaces (ADR-013, D1).
//!
//! [`patch_between`] describes the change from a base workspace to the
//! workspace a fix produced as a `boneli_domain::Patch`, without loss: every
//! changed path with both full sides, and every symlink of the base. The
//! domain then computes sizes, classes and link walks itself. Nothing calls
//! it yet; wiring the policy into the run is #68.

use std::cmp::Ordering;
use std::iter::Peekable;

use boneli_app::RelativePath;
use boneli_domain::{BaseLink, Change, Entry, EntryKind, Patch};

use crate::workspace::{Kind, Workspace};

fn entry(kind: Kind, data: &[u8]) -> Entry {
    let kind = match kind {
        Kind::File => EntryKind::File,
        Kind::Executable => EntryKind::Executable,
        Kind::Symlink => EntryKind::Symlink,
    };
    Entry {
        kind,
        data: data.to_vec(),
    }
}

/// The workspace's entries in path order, without repository metadata,
/// which `diff` drops too (ADR-010, D1).
fn content(
    workspace: &Workspace,
) -> Peekable<impl Iterator<Item = (&RelativePath, Kind, &[u8])> + '_> {
    workspace
        .iter()
        .filter(|(path, _, _)| !path.is_repository_metadata())
        .peekable()
}

/// The patch from `base` to `after`: a merge join over both workspaces in
/// path order (the byte order of the paths, which the policy requires),
/// skipping repository metadata on both sides. `base_links` are every
/// symlink of `base`, metadata included, so the policy's walks see every
/// link a checkout of the base can hold. A workspace holds no gitlinks
/// (ADR-010, D3), so the patch never has one.
pub fn patch_between(base: &Workspace, after: &Workspace) -> Patch {
    let mut left = content(base);
    let mut right = content(after);
    let mut changes = Vec::new();
    loop {
        let order = match (left.peek(), right.peek()) {
            (None, None) => break,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some((a, _, _)), Some((b, _, _))) => a.as_str().cmp(b.as_str()),
        };
        let (path, before, now) = match order {
            Ordering::Less => {
                let Some((path, kind, data)) = left.next() else {
                    break;
                };
                (path, Some(entry(kind, data)), None)
            }
            Ordering::Greater => {
                let Some((path, kind, data)) = right.next() else {
                    break;
                };
                (path, None, Some(entry(kind, data)))
            }
            Ordering::Equal => {
                let (Some((path, kind, data)), Some((_, kind2, data2))) =
                    (left.next(), right.next())
                else {
                    break;
                };
                if kind == kind2 && data == data2 {
                    continue;
                }
                (path, Some(entry(kind, data)), Some(entry(kind2, data2)))
            }
        };
        changes.push(Change {
            path: path.as_str().to_owned(),
            before,
            after: now,
        });
    }
    let base_links = base
        .iter()
        .filter(|(_, kind, _)| *kind == Kind::Symlink)
        .map(|(path, _, target)| BaseLink {
            path: path.as_str().to_owned(),
            target: target.to_vec(),
        })
        .collect();
    Patch {
        changes,
        base_links,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boneli_domain::{PatchLimits, PatchVerdict, PatchViolation, patch_policy};

    fn path(text: &str) -> RelativePath {
        RelativePath::parse(text).expect("a valid path")
    }

    fn workspace(entries: &[(&str, Kind, &[u8])]) -> Workspace {
        let mut out = Workspace::new();
        for (p, kind, data) in entries {
            out.insert(path(p), *kind, data.to_vec())
                .expect("a valid entry");
        }
        out
    }

    fn kind_of(kind: EntryKind) -> Kind {
        match kind {
            EntryKind::File => Kind::File,
            EntryKind::Executable => Kind::Executable,
            EntryKind::Symlink => Kind::Symlink,
            EntryKind::Gitlink => panic!("a workspace patch has no gitlink"),
        }
    }

    /// The base without metadata with every change's after side applied:
    /// removals first, so a file can become a directory.
    fn apply(base: &Workspace, patch: &Patch) -> Workspace {
        let mut out = base.clone().without_metadata();
        for change in &patch.changes {
            out.remove(&path(&change.path));
        }
        for change in &patch.changes {
            if let Some(after) = &change.after {
                out.insert(path(&change.path), kind_of(after.kind), after.data.clone())
                    .expect("the after side fits");
            }
        }
        out
    }

    fn pairs() -> Vec<(Workspace, Workspace)> {
        use Kind::*;
        let base = workspace(&[
            (".git/config", File, b"[core]\n"),
            ("a.ts", File, b"a\n"),
            ("bin/run", File, b"echo\n"),
            ("docs/link", Symlink, b"../a.ts"),
            ("gone.txt", File, b"x\n"),
            ("lib/.git", Symlink, b"elsewhere"),
            ("same.txt", File, b"same\n"),
            ("to-link", File, b"target\n"),
            ("to-file", Symlink, b"a.ts"),
            ("file-to-dir", File, b"x\n"),
        ]);
        let after = workspace(&[
            (".git/HEAD", File, b"ref\n"),
            ("a.ts", File, b"b\n"),
            ("bin/run", Executable, b"echo\n"),
            ("docs/link", Symlink, b"../same.txt"),
            ("file-to-dir/x", File, b"y\n"),
            ("new.ts", File, b"new\n"),
            ("same.txt", File, b"same\n"),
            ("sub/.git/x", File, b"meta\n"),
            ("to-file", File, b"now a file\n"),
            ("to-link", Symlink, b"a.ts"),
        ]);
        vec![
            (base.clone(), after.clone()),
            (after.clone(), base.clone()),
            (Workspace::new(), after),
            (base, Workspace::new()),
        ]
    }

    #[test]
    fn patch_between_round_trips() {
        for (base, after) in pairs() {
            let patch = patch_between(&base, &after);
            assert_eq!(apply(&base, &patch), after.clone().without_metadata());
            for change in &patch.changes {
                assert!(!path(&change.path).is_repository_metadata(), "{change:?}");
                assert_ne!(change.before, change.after);
            }
        }
        let (base, after) = pairs().remove(0);
        let changed: Vec<String> = patch_between(&base, &after)
            .changes
            .into_iter()
            .map(|c| c.path)
            .collect();
        assert_eq!(
            changed,
            [
                "a.ts",
                "bin/run",
                "docs/link",
                "file-to-dir",
                "file-to-dir/x",
                "gone.txt",
                "new.ts",
                "to-file",
                "to-link",
            ]
        );
    }

    #[test]
    fn patch_between_of_equal_workspaces_is_empty() {
        for (base, _) in pairs() {
            let patch = patch_between(&base, &base.clone());
            assert!(patch.changes.is_empty());
        }
        let (base, _) = pairs().remove(0);
        let links: Vec<(String, Vec<u8>)> = patch_between(&base, &base)
            .base_links
            .into_iter()
            .map(|l| (l.path, l.target))
            .collect();
        assert_eq!(
            links,
            [
                ("docs/link".to_owned(), b"../a.ts".to_vec()),
                ("lib/.git".to_owned(), b"elsewhere".to_vec()),
                ("to-file".to_owned(), b"a.ts".to_vec()),
            ]
        );
    }

    #[test]
    fn patch_between_is_valid_policy_input() {
        for (base, after) in pairs() {
            let patch = patch_between(&base, &after);
            let verdict = patch_policy(&patch, &PatchLimits::DEFAULT);
            if let PatchVerdict::Reject(violations) = &verdict {
                for violation in violations {
                    assert!(
                        !matches!(
                            violation,
                            PatchViolation::Malformed { .. }
                                | PatchViolation::BaseLinkMalformed { .. }
                        ),
                        "{violation:?}"
                    );
                }
            }
        }
        // The first pair is an ordinary fix and passes.
        let (base, after) = pairs().remove(0);
        assert_eq!(
            patch_policy(&patch_between(&base, &after), &PatchLimits::DEFAULT),
            PatchVerdict::Pass {
                files: 9,
                lines: 12
            }
        );
    }
}
