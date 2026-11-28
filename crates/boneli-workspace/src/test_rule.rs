//! The path rule of the unit tests: the tree path rule of ADR-018 (D2),
//! written out here because a support crate cannot depend on the core
//! crate that holds it (ADR-042, D1). Each adapter pins its own rule to
//! the core one in its own tests.

use crate::PathRule;

/// A path the test rule accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TestPath(Vec<u8>);

impl TestPath {
    /// Accepts what the rule accepts, or the first problem.
    pub(crate) fn parse(path: &[u8]) -> Result<TestPath, TestProblem> {
        TestRule::check(path)
    }

    /// The path as written.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Why the test rule refuses bytes, in the order it checks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestProblem {
    /// No bytes.
    Empty,
    /// The path starts with `/`.
    Absolute,
    /// The path contains NUL.
    Nul,
    /// A component is empty.
    EmptyComponent,
    /// A component is `.`.
    DotComponent,
    /// A component is `..`.
    ParentComponent,
}

/// The tree path rule: not empty, not absolute, no NUL, no empty, `.` or
/// `..` component between `/` bytes; metadata is a component that is
/// exactly `.git`.
pub(crate) struct TestRule;

impl PathRule for TestRule {
    type Path = TestPath;
    type Problem = TestProblem;

    fn check(path: &[u8]) -> Result<TestPath, TestProblem> {
        if path.is_empty() {
            return Err(TestProblem::Empty);
        }
        if path[0] == b'/' {
            return Err(TestProblem::Absolute);
        }
        if path.contains(&0) {
            return Err(TestProblem::Nul);
        }
        for component in path.split(|b| *b == b'/') {
            match component {
                b"" => return Err(TestProblem::EmptyComponent),
                b"." => return Err(TestProblem::DotComponent),
                b".." => return Err(TestProblem::ParentComponent),
                _ => {}
            }
        }
        Ok(TestPath(path.to_vec()))
    }

    fn is_metadata(path: &[u8]) -> bool {
        path.split(|b| *b == b'/')
            .any(|component| component == b".git")
    }

    fn bytes(path: &TestPath) -> &[u8] {
        &path.0
    }
}
