//! Paths that ports take (ADR-004, D1).
//!
//! A path inside a repository or a sandbox workspace is a [`RelativePath`]:
//! the citation path rule of ADR-002 (D2) through the one shared function,
//! `boneli_domain::gate::path_problem`. So a sandbox or git path cannot
//! leave the tree by a route the citation precheck would reject, and a
//! path that is hostile as written (absolute, `..`, backslash, NUL) is
//! refused by the type before it reaches a port.
//!
//! The rule is lexical. It does not resolve symlinks, and it accepts
//! `.git/config`: a symlink planted in a workspace is the real adapter's to
//! refuse (ADR-004, D11), and a path into the repository's own metadata is
//! dropped from a workspace by every `Git` adapter
//! ([`RelativePath::is_repository_metadata`], ADR-010).
//!
//! Two path types, because two things are bound (ADR-018, D1). A
//! [`RelativePath`] is what an agent or a port argument names: a citation,
//! `Git::read`, `Sandbox::copy_out`, a change the patch policy judges. A
//! [`TreePath`] is what a tree holds: the paths of a workspace, a snapshot
//! and a diff. A repository may hold a file whose name has a backslash, is
//! blank or is not UTF-8, and the replica must hold it too, so the tree
//! rule keeps only what protects the host and what git itself refuses.
//! Every `RelativePath` is a `TreePath`; [`TreePath::citable`] is the way
//! back, and it refuses exactly what the citation rule refuses, so such a
//! file can be carried but not cited.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use boneli_domain::CitationProblem;
use boneli_domain::gate::path_problem;

/// A path relative to the root of a repository or a sandbox workspace,
/// canonical in the sense of the citation precheck: not blank, not
/// absolute, no backslash or NUL, no empty, `.` or `..` component. Only `/`
/// and ASCII `.` are structural, so `~/x` or `file:x` is a literal file name
/// (ADR-002, D2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelativePath(String);

impl RelativePath {
    /// Accepts exactly the paths `path_problem` accepts, kept as written;
    /// otherwise its problem.
    pub fn parse(path: &str) -> Result<RelativePath, CitationProblem> {
        match path_problem(path) {
            Some(problem) => Err(problem),
            None => Ok(RelativePath(String::from(path))),
        }
    }

    /// The path as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the path is repository metadata: some component is exactly
    /// `.git`, the top-level repository's or a nested one's. The one rule
    /// for the `Git` suite, `MemoryGit` and the real adapter (#30, ADR-010
    /// D1). Look-alikes (`.GIT`, `git~1`, `.git.`) are content here; the
    /// real adapter refuses them before it writes a workspace (ADR-010 D6).
    pub fn is_repository_metadata(&self) -> bool {
        self.0.split('/').any(|component| component == ".git")
    }
}

/// Why bytes are not a [`TreePath`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreePathProblem {
    /// No bytes.
    Empty,
    /// The path starts with `/`.
    Absolute,
    /// The path contains NUL.
    Nul,
    /// A component is empty (`a//b`, `a/`).
    EmptyComponent,
    /// A component is `.`.
    DotComponent,
    /// A component is `..`.
    ParentComponent,
}

/// Why a [`TreePath`] is not a [`RelativePath`]: what the citation rule
/// refuses in it (ADR-018, D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uncitable {
    /// The path is not UTF-8.
    NotUtf8,
    /// The citation rule's reason (ADR-002, D2).
    Citation(CitationProblem),
}

/// A path as a tree holds it, relative to the tree's root (ADR-018, D1):
/// not empty, not absolute, no NUL, and no empty, `.` or `..` component,
/// where only `/` splits components. Every other byte is a name byte, so a
/// backslash, a blank name and bytes that are not UTF-8 are kept as
/// written. Its order is byte order, which on UTF-8 paths is
/// [`RelativePath`]'s.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TreePath(Vec<u8>);

impl TreePath {
    /// Accepts the bytes the rule accepts, kept as written; otherwise the
    /// first problem, checked in the order of [`TreePathProblem`].
    pub fn parse(path: &[u8]) -> Result<TreePath, TreePathProblem> {
        if path.is_empty() {
            return Err(TreePathProblem::Empty);
        }
        if path[0] == b'/' {
            return Err(TreePathProblem::Absolute);
        }
        if path.contains(&0) {
            return Err(TreePathProblem::Nul);
        }
        for component in path.split(|b| *b == b'/') {
            match component {
                b"" => return Err(TreePathProblem::EmptyComponent),
                b"." => return Err(TreePathProblem::DotComponent),
                b".." => return Err(TreePathProblem::ParentComponent),
                _ => {}
            }
        }
        Ok(TreePath(path.to_vec()))
    }

    /// The path as written.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether the path is repository metadata: some `/`-component is
    /// exactly `.git`, the rule of [`RelativePath::is_repository_metadata`]
    /// on bytes. `.git\x` is one name, so it is not; the real adapter
    /// refuses it as a look-alike (ADR-018, D3).
    pub fn is_repository_metadata(&self) -> bool {
        self.0
            .split(|b| *b == b'/')
            .any(|component| component == b".git")
    }

    /// The path as a [`RelativePath`], which an agent may cite, or what
    /// the citation rule refuses in it; UTF-8 is checked first.
    pub fn citable(&self) -> Result<RelativePath, Uncitable> {
        let text = core::str::from_utf8(&self.0).map_err(|_| Uncitable::NotUtf8)?;
        RelativePath::parse(text).map_err(Uncitable::Citation)
    }
}

impl From<RelativePath> for TreePath {
    fn from(path: RelativePath) -> TreePath {
        TreePath(path.0.into_bytes())
    }
}

impl From<&RelativePath> for TreePath {
    fn from(path: &RelativePath) -> TreePath {
        TreePath(path.0.as_bytes().to_vec())
    }
}

/// A UTF-8 path as a string, any other as escaped ASCII; both lossless.
impl fmt::Debug for TreePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match core::str::from_utf8(&self.0) {
            Ok(text) => write!(f, "TreePath({text:?})"),
            Err(_) => write!(f, "TreePath(b\"{}\")", self.0.escape_ascii()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use boneli_domain::gate::citation_problem;
    use boneli_domain::{Citation, CommitSha};

    const BASE: &str = "0123456789abcdef0123456789abcdef01234567";

    /// What the citation precheck says about the path of a citation that is
    /// otherwise valid.
    fn as_citation(path: &str) -> Option<CitationProblem> {
        let base = CommitSha::parse(BASE).expect("a valid SHA");
        let citation = Citation {
            path: String::from(path),
            line: 1,
            sha: base.clone(),
            quote: String::from("let x = 1;"),
        };
        citation_problem(&citation, &base)
    }

    #[test]
    fn path_problem_matches_citation_rule() {
        let rejected = [
            ("/a", CitationProblem::AbsolutePath),
            ("a\\b", CitationProblem::Backslash),
            ("a\u{0}b", CitationProblem::Nul),
            ("", CitationProblem::BlankPath),
            (" ", CitationProblem::BlankPath),
            ("\u{200B}", CitationProblem::BlankPath),
            ("a//b", CitationProblem::EmptyComponent),
            ("a/", CitationProblem::EmptyComponent),
            ("./a", CitationProblem::DotComponent),
            ("a/.", CitationProblem::DotComponent),
            ("a/..", CitationProblem::ParentComponent),
            ("../x", CitationProblem::ParentComponent),
            ("..", CitationProblem::ParentComponent),
        ];
        for (path, problem) in rejected {
            assert_eq!(RelativePath::parse(path), Err(problem), "{path:?}");
        }
        // Only `/` and ASCII `.` are structural, so these are literal paths
        // (ADR-002, D2).
        let accepted = [
            "src/lib.rs",
            "~/x",
            "file:x",
            "a/\u{2024}\u{2024}",
            "a\u{200B}",
            " a ",
            "...",
        ];
        for path in accepted {
            let parsed = RelativePath::parse(path).map(|p| String::from(p.as_str()));
            assert_eq!(parsed, Ok(String::from(path)), "{path:?}");
        }
        // One rule: the type, the shared function and the citation precheck
        // agree on every sample.
        for (path, _) in rejected {
            assert_eq!(path_problem(path), as_citation(path), "{path:?}");
            assert_eq!(RelativePath::parse(path).err(), path_problem(path));
        }
        for path in accepted {
            assert_eq!(path_problem(path), None, "{path:?}");
            assert_eq!(as_citation(path), None, "{path:?}");
        }
    }

    /// Only a component that is exactly `.git` is repository metadata;
    /// look-alikes are content as far as the core is concerned (#30).
    #[test]
    fn repository_metadata_is_an_exact_git_component() {
        let metadata = [".git", ".git/config", "a/.git", "a/.git/b"];
        for text in metadata {
            let path = RelativePath::parse(text).expect("a valid path");
            assert!(path.is_repository_metadata(), "{text:?}");
        }
        let content = [
            ".github/x",
            ".gitignore",
            ".git-blame-ignore-revs",
            "a.git/x",
            ".gitx",
            "git/x",
            ".GIT/config",
            ".git /x",
            ".git./x",
            ".g\u{200C}it/x",
            "git~1/x",
        ];
        for text in content {
            let path = RelativePath::parse(text).expect("a valid path");
            assert!(!path.is_repository_metadata(), "{text:?}");
        }
    }

    fn tree(bytes: &[u8]) -> TreePath {
        TreePath::parse(bytes).expect("a valid tree path")
    }

    /// The tree path rule keeps only what git and the kernel refuse or
    /// resolve; a backslash, a blank name and bytes that are not UTF-8 are
    /// name bytes (ADR-018, D1).
    #[test]
    fn tree_path_rule() {
        let refused: [(&[u8], TreePathProblem); 13] = [
            (b"", TreePathProblem::Empty),
            (b"/", TreePathProblem::Absolute),
            (b"/a", TreePathProblem::Absolute),
            (b"a\0b", TreePathProblem::Nul),
            (b"\0", TreePathProblem::Nul),
            (b"a//b", TreePathProblem::EmptyComponent),
            (b"a/", TreePathProblem::EmptyComponent),
            (b".", TreePathProblem::DotComponent),
            (b"a/./b", TreePathProblem::DotComponent),
            (b"..", TreePathProblem::ParentComponent),
            (b"../x", TreePathProblem::ParentComponent),
            (b"a/..", TreePathProblem::ParentComponent),
            // The first problem in the order of the checks wins.
            (b"/a\0", TreePathProblem::Absolute),
        ];
        for (bytes, problem) in refused {
            assert_eq!(TreePath::parse(bytes), Err(problem), "{bytes:?}");
        }
        let accepted: [&[u8]; 16] = [
            b"a\\b",
            b"d\\e/f",
            b" ",
            b"\t",
            "\u{3000}".as_bytes(),
            "\u{200B}".as_bytes(),
            b"x\xff",
            b"\xff",
            // Overlong `/`, overlong `..` and backslash traversal are one
            // name each: only `/` splits, and only ASCII `.` is a dot.
            b"\xc0\xaf",
            b"\xc0\xae\xc0\xae",
            b"..\\x",
            b"a\\..\\b",
            b"...",
            b"~/x",
            b"file:x",
            b".git/config",
        ];
        for bytes in accepted {
            assert_eq!(
                TreePath::parse(bytes).map(|p| p.as_bytes().to_vec()),
                Ok(bytes.to_vec()),
                "{bytes:?}"
            );
        }
    }

    /// The reference of `tree_path_parse_total`, written as the rule reads
    /// for inputs of one or two bytes.
    fn reference(bytes: &[u8]) -> Result<(), TreePathProblem> {
        match bytes {
            [] => Err(TreePathProblem::Empty),
            [b'/', ..] => Err(TreePathProblem::Absolute),
            _ if bytes.contains(&0) => Err(TreePathProblem::Nul),
            [b'.'] | [b'.', b'/'] => Err(TreePathProblem::DotComponent),
            [b'.', b'.'] => Err(TreePathProblem::ParentComponent),
            [_, b'/'] => Err(TreePathProblem::EmptyComponent),
            _ => Ok(()),
        }
    }

    /// Every input of one or two bytes, 65,792 in all: no panic, and the
    /// result the reference gives.
    #[test]
    fn tree_path_parse_total() {
        let mut checked = 0usize;
        for a in 0..=255u8 {
            let one = [a];
            assert_eq!(
                TreePath::parse(&one).map(|_| ()),
                reference(&one),
                "{one:?}"
            );
            checked += 1;
            for b in 0..=255u8 {
                let two = [a, b];
                assert_eq!(
                    TreePath::parse(&two).map(|_| ()),
                    reference(&two),
                    "{two:?}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 65_792);
    }

    /// Blank means the whole path; UTF-8 is checked before the citation
    /// rule, so a path in two classes is `NotUtf8`.
    #[test]
    fn citable_classifies() {
        let rows: [(&[u8], Result<(), Uncitable>); 12] = [
            (
                b"a\\b",
                Err(Uncitable::Citation(CitationProblem::Backslash)),
            ),
            (b" ", Err(Uncitable::Citation(CitationProblem::BlankPath))),
            (b"\t", Err(Uncitable::Citation(CitationProblem::BlankPath))),
            (
                "\u{3000}".as_bytes(),
                Err(Uncitable::Citation(CitationProblem::BlankPath)),
            ),
            (
                "\u{200B}".as_bytes(),
                Err(Uncitable::Citation(CitationProblem::BlankPath)),
            ),
            (b"x\xff", Err(Uncitable::NotUtf8)),
            (b"\xff\\", Err(Uncitable::NotUtf8)),
            (b"\xc0\xaf", Err(Uncitable::NotUtf8)),
            (b" /x", Ok(())),
            (b"a/ ", Ok(())),
            (b"src/lib.rs", Ok(())),
            (b".git/config", Ok(())),
        ];
        for (bytes, want) in rows {
            let got = tree(bytes).citable();
            assert_eq!(
                got.as_ref().map(|_| ()),
                want.as_ref().map(|_| ()),
                "{bytes:?}"
            );
            if let Ok(cited) = got {
                assert_eq!(cited.as_str().as_bytes(), bytes);
            }
        }
    }

    /// Every path the citation rule accepts is a tree path that `citable`
    /// gives back unchanged, and a tree path refused as `Citation(p)` is
    /// refused by `path_problem` with `p`: the citation rule did not move
    /// (ADR-002, D2).
    #[test]
    fn every_relative_path_is_a_tree_path() {
        let accepted = [
            "src/lib.rs",
            "~/x",
            "file:x",
            "a/\u{2024}\u{2024}",
            "a\u{200B}",
            " a ",
            "...",
            ".git/config",
            ".GIT/config",
            "a\nb",
            "-rf",
        ];
        for text in accepted {
            let relative = RelativePath::parse(text).expect("a valid path");
            let tree_path = TreePath::from(&relative);
            assert_eq!(tree_path.as_bytes(), text.as_bytes());
            assert_eq!(TreePath::parse(text.as_bytes()), Ok(tree_path.clone()));
            assert_eq!(tree_path.citable(), Ok(relative.clone()));
            assert_eq!(TreePath::from(relative), tree_path);
        }
        let refused = [
            "a\\b", " ", "\u{200B}", "\t", "\u{3000}", "d\\e/f", "a\\..\\b",
        ];
        for text in refused {
            let tree_path = tree(text.as_bytes());
            match tree_path.citable() {
                Err(Uncitable::Citation(problem)) => {
                    assert_eq!(path_problem(text), Some(problem), "{text:?}");
                }
                other => panic!("{text:?}: {other:?}"),
            }
        }
    }

    /// Only a `/`-component that is exactly `.git` is repository metadata;
    /// `.git\x` is one name, so it is not (the adapter refuses it as a
    /// look-alike, ADR-018 D3).
    #[test]
    fn tree_path_metadata_is_exact_git_component() {
        let metadata: [&[u8]; 5] = [
            b".git",
            b".git/config",
            b"a/.git",
            b"a/.git/b",
            b"x\xff/.git",
        ];
        for bytes in metadata {
            assert!(tree(bytes).is_repository_metadata(), "{bytes:?}");
        }
        let content: [&[u8]; 6] = [
            b".git\\x",
            b"x\\.git",
            b".git\xff",
            b".gitx",
            b".GIT/x",
            b"a\\.git\\b",
        ];
        for bytes in content {
            assert!(!tree(bytes).is_repository_metadata(), "{bytes:?}");
        }
        // The same rule as `RelativePath`'s on every citable path.
        for text in [".git", "a/.git/b", ".github/x", ".git /x"] {
            let relative = RelativePath::parse(text).expect("a valid path");
            assert_eq!(
                TreePath::from(&relative).is_repository_metadata(),
                relative.is_repository_metadata(),
                "{text:?}"
            );
        }
    }

    /// Tree path order is byte order, and agrees with `RelativePath`'s on
    /// citable paths.
    #[test]
    fn tree_path_order_is_byte_order() {
        let sorted: [&[u8]; 8] = [
            b"\t",
            b" ",
            b".git/HEAD",
            b"a.b",
            b"a/x",
            b"a\\b",
            "\u{17E}".as_bytes(),
            b"\xff",
        ];
        for pair in sorted.windows(2) {
            assert!(tree(pair[0]) < tree(pair[1]), "{pair:?}");
        }
        let (a, b) = ("a.b", "a/x");
        let relative = |t: &str| RelativePath::parse(t).expect("valid");
        assert_eq!(
            relative(a).cmp(&relative(b)),
            TreePath::from(relative(a)).cmp(&TreePath::from(relative(b)))
        );
    }

    /// `Debug` shows a UTF-8 path as a string and any other as escaped
    /// ASCII, both lossless.
    #[test]
    fn tree_path_debug_is_lossless() {
        assert_eq!(
            alloc::format!("{:?}", tree(b"a\\b")),
            "TreePath(\"a\\\\b\")"
        );
        assert_eq!(
            alloc::format!("{:?}", tree(b"x\xff")),
            "TreePath(b\"x\\xff\")"
        );
    }
}
