//! The patch policy's input from two workspaces (ADR-013, D1).
//!
//! [`patch_between`] describes the change from a base workspace to the
//! workspace a fix produced as a `boneli_domain::Patch`, without loss: every
//! changed path with both full sides, and every symlink of the base. The
//! domain then computes sizes, classes and link walks itself. Nothing calls
//! it in the run: `GitCli::patch_between` builds the policy's input from
//! two checkouts' trees (ADR-023, D4), and this function stays as the
//! differential oracle of its tests.
//!
//! The policy's paths are text and follow the citation rule (ADR-013,
//! ADR-018 D5). A changed path or a base link with a backslash or a blank
//! name reaches the policy as written, and the policy refuses the fix
//! (`Malformed`, `BaseLinkMalformed`). One that is not UTF-8 has no text
//! form, so it is an [`UnreadablePath`] here (ADR-023, D6).

use std::cmp::Ordering;
use std::iter::Peekable;

use boneli_app::TreePath;
use boneli_domain::{BaseLink, Change, Entry, EntryKind, Patch, UnreadablePath};

use crate::workspace::{Kind, Workspace};

/// The path as the policy's text, if it is UTF-8.
fn text(path: &TreePath) -> Option<String> {
    std::str::from_utf8(path.as_bytes()).ok().map(str::to_owned)
}

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
fn content(workspace: &Workspace) -> Peekable<impl Iterator<Item = (&TreePath, Kind, &[u8])> + '_> {
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
/// (ADR-010, D3), so the patch never has one. A changed path or a base
/// link path that is not UTF-8 is an [`UnreadablePath`]; an unchanged
/// file at such a path is no part of the patch.
pub fn patch_between(base: &Workspace, after: &Workspace) -> Result<Patch, UnreadablePath> {
    let mut left = content(base);
    let mut right = content(after);
    let mut changes = Vec::new();
    loop {
        let order = match (left.peek(), right.peek()) {
            (None, None) => break,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some((a, _, _)), Some((b, _, _))) => a.cmp(b),
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
        let change = changes.len();
        changes.push(Change {
            path: text(path).ok_or(UnreadablePath::Change { index: change })?,
            before,
            after: now,
        });
    }
    let base_links = base
        .iter()
        .filter(|(_, kind, _)| *kind == Kind::Symlink)
        .enumerate()
        .map(|(link, (path, _, target))| {
            Ok(BaseLink {
                path: text(path).ok_or(UnreadablePath::BaseLink { index: link })?,
                target: target.to_vec(),
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(Patch {
        changes,
        base_links,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boneli_domain::{PatchLimits, PatchVerdict, PatchViolation, patch_policy};

    fn path(text: &str) -> TreePath {
        bpath(text.as_bytes())
    }

    fn bpath(bytes: &[u8]) -> TreePath {
        TreePath::parse(bytes).expect("a valid path")
    }

    fn patch(base: &Workspace, after: &Workspace) -> Patch {
        patch_between(base, after).expect("UTF-8 paths")
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
            let patch = patch(&base, &after);
            assert_eq!(apply(&base, &patch), after.clone().without_metadata());
            for change in &patch.changes {
                assert!(!path(&change.path).is_repository_metadata(), "{change:?}");
                assert_ne!(change.before, change.after);
            }
        }
        let (base, after) = pairs().remove(0);
        let changed: Vec<String> = patch(&base, &after)
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
            let patch = patch(&base, &base.clone());
            assert!(patch.changes.is_empty());
        }
        let (base, _) = pairs().remove(0);
        let links: Vec<(String, Vec<u8>)> = patch(&base, &base)
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
            let patch = patch(&base, &after);
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
            patch_policy(&patch(&base, &after), &PatchLimits::DEFAULT),
            PatchVerdict::Pass {
                files: 9,
                lines: 12
            }
        );
    }

    /// Paths the citation rule refuses reach the policy as written and
    /// are refused there; one that is not UTF-8 is an input error naming
    /// its index; an unchanged file at such a path passes (ADR-018, D5).
    #[test]
    fn patch_between_with_uncitable_paths() {
        use Kind::*;
        use boneli_domain::CitationProblem;
        let mut base = workspace(&[("a.ts", File, b"a\n"), ("z.ts", File, b"z\n")]);
        for (p, kind, data) in [
            (&b"dir\\file"[..], File, &b"x\n"[..]),
            (b" ", File, b"y\n"),
            (b"x\xff", File, b"z\n"),
        ] {
            base.insert(bpath(p), kind, data.to_vec()).expect("valid");
        }
        let with = |w: &Workspace, p: &[u8], kind: Kind, data: &[u8]| {
            let mut w = w.clone();
            w.insert(bpath(p), kind, data.to_vec()).expect("valid");
            w
        };
        let malformed = |problem| PatchViolation::Malformed {
            index: 0,
            problem: boneli_domain::ChangeProblem::Path(problem),
        };
        let rejects = |base: &Workspace, after: &Workspace, want: &PatchViolation| {
            let verdict = patch_policy(&patch(base, after), &PatchLimits::DEFAULT);
            match verdict {
                PatchVerdict::Reject(violations) => {
                    assert!(violations.contains(want), "{violations:?}");
                }
                other => panic!("{want:?}: {other:?}"),
            }
        };
        // A backslash change and a blank change are malformed for the
        // policy.
        rejects(
            &base,
            &with(&base, b"dir\\file", File, b"changed\n"),
            &malformed(CitationProblem::Backslash),
        );
        rejects(
            &base,
            &with(&base, b" ", File, b"changed\n"),
            &malformed(CitationProblem::BlankPath),
        );
        // A non-UTF-8 change is an input error with the change's index:
        // `a.ts` is change 0, the non-UTF-8 path sorts last.
        let mut after = with(&base, b"a.ts", File, b"b\n");
        after = with(&after, b"x\xff", File, b"changed\n");
        assert_eq!(
            patch_between(&base, &after),
            Err(UnreadablePath::Change { index: 1 })
        );
        let mut removed = base.clone();
        removed.remove(&bpath(b"x\xff"));
        assert_eq!(
            patch_between(&base, &removed),
            Err(UnreadablePath::Change { index: 0 })
        );
        // A base symlink at a backslash path makes every fix malformed; at
        // a non-UTF-8 path it is an input error.
        let linked = with(&base, b"l\\x", Symlink, b"a.ts");
        let fix = with(&linked, b"a.ts", File, b"b\n");
        let verdict = patch_policy(&patch(&linked, &fix), &PatchLimits::DEFAULT);
        assert!(
            matches!(
                &verdict,
                PatchVerdict::Reject(v) if v.iter().any(|v| matches!(
                    v,
                    PatchViolation::BaseLinkMalformed { .. }
                ))
            ),
            "{verdict:?}"
        );
        let linked = with(&base, b"l\xff", Symlink, b"a.ts");
        let fix = with(&linked, b"a.ts", File, b"b\n");
        assert_eq!(
            patch_between(&linked, &fix),
            Err(UnreadablePath::BaseLink { index: 0 })
        );
        // Unchanged uncitable files and an edit elsewhere: this
        // repository's case, an ordinary fix.
        let fix = with(&base, b"a.ts", File, b"b\n");
        assert_eq!(
            patch_policy(&patch(&base, &fix), &PatchLimits::DEFAULT),
            PatchVerdict::Pass { files: 1, lines: 2 }
        );
    }
}
