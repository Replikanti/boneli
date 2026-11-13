//! Paths that ports take (ADR-004, D1).
//!
//! A path inside a repository or a sandbox workspace is a [`RelativePath`]:
//! the citation path rule of ADR-002 (D2) through the one shared function,
//! `boneli_domain::gate::path_problem`. So a sandbox or git path cannot
//! leave the tree by a route the citation precheck would reject, and a
//! hostile path is refused by the type before it reaches a port.

use alloc::string::String;

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
}
