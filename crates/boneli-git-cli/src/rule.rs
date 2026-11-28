//! The path rule this adapter passes to `boneli-workspace` (ADR-042, D1):
//! the tree path rule of ADR-018, by delegation, so a workspace path here
//! is a `TreePath` and repository metadata is what
//! `TreePath::is_repository_metadata` says.

use boneli_app::{TreePath, TreePathProblem};
use boneli_workspace::PathRule;

/// The tree path rule: [`TreePath::parse`] and
/// [`TreePath::is_repository_metadata`].
#[derive(Clone, Copy, Debug)]
pub struct TreeRule;

impl PathRule for TreeRule {
    type Path = TreePath;
    type Problem = TreePathProblem;

    fn check(path: &[u8]) -> Result<TreePath, TreePathProblem> {
        TreePath::parse(path)
    }

    fn is_metadata(path: &[u8]) -> bool {
        // A path the rule refuses is no entry's path; were it asked, it
        // counts as metadata, which fails closed for every caller.
        TreePath::parse(path).map_or(true, |p| p.is_repository_metadata())
    }

    fn bytes(path: &TreePath) -> &[u8] {
        path.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule is `TreePath`'s, byte string by byte string: what it
    /// accepts and refuses with which problem, which paths are metadata,
    /// and the bytes it keeps (ADR-042, D1).
    #[test]
    fn git_cli_rule_is_tree_path() {
        let cases: [&[u8]; 30] = [
            b"",
            b"/",
            b"/abs",
            b"a",
            b"a/b",
            b"a//b",
            b"a/",
            b"./a",
            b"a/./b",
            b"../a",
            b"a/..",
            b"a\0b",
            b"a\\b",
            b"..\\x",
            b" ",
            b"\t",
            b"x\xff",
            b"\xc0\xae\xc0\xae",
            b".git",
            b".git/config",
            b"sub/.git",
            b"sub/.git/HEAD",
            b".gitignore",
            b".github/workflows/ci.yml",
            b".GIT",
            b".git\\x",
            b"a.git",
            b"git",
            "\u{17E}/\u{200B}".as_bytes(),
            b"~/x",
        ];
        for bytes in cases {
            let ours = TreeRule::check(bytes);
            assert_eq!(ours, TreePath::parse(bytes), "{bytes:?}");
            if let Ok(path) = ours {
                assert_eq!(TreeRule::bytes(&path), bytes, "{bytes:?}");
                assert_eq!(
                    TreeRule::is_metadata(bytes),
                    path.is_repository_metadata(),
                    "{bytes:?}"
                );
            } else {
                assert!(TreeRule::is_metadata(bytes), "{bytes:?} fails closed");
            }
        }
        // Metadata in both directions, so neither answer passes alone.
        assert!(TreeRule::is_metadata(b"sub/.git/HEAD"));
        assert!(!TreeRule::is_metadata(b".gitignore"));
    }
}
