//! Gates as pure functions over observation values (`docs/ARCHITECTURE.md`,
//! "Debugging line"; ADR-002).
//!
//! Every gate is deterministic and fails closed: when the observations do
//! not prove a pass, it does not pass. The domain only decides; running the
//! tests, checking citations against git and verifying the fix in a clean
//! sandbox belong to the application and its adapters (#17).

use alloc::vec::Vec;

use crate::values::{Citation, CommitSha, is_blank};

/// The result of one test run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestStatus {
    /// The test ran and passed.
    Passed,
    /// The test ran and failed on an assertion.
    FailedOnAssertion,
    /// The test did not compile or build.
    FailedToBuild,
    /// The test ran and failed otherwise (panic, crash, setup error).
    Errored,
    /// The test hit its time limit.
    TimedOut,
    /// The runner could not tell.
    Unknown,
}

/// The result of one fix check other than the reproduction test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckStatus {
    /// The check ran and passed.
    Passed,
    /// The check ran and failed.
    Failed,
    /// The repository configures no such check.
    NotConfigured,
    /// The runner could not tell.
    Unknown,
}

/// The result of verifying one citation against the base SHA.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CitationStatus {
    /// The quoted text is at that path and line at the base SHA.
    Verified,
    /// The path and line exist, but the text differs.
    Mismatch,
    /// The citation could not be checked (for example, no such path).
    Unverifiable,
}

/// The observations of the fix gate, checked in field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixChecks {
    /// The reproduction test on base plus the diff.
    pub reproduction_test: TestStatus,
    /// Whether the reproduction test is byte for byte the one that was
    /// checked on the base.
    pub reproduction_test_unchanged: CheckStatus,
    /// Whether the tests that passed on the base still pass.
    pub previously_green_tests: CheckStatus,
    /// The repository's linter.
    pub lint: CheckStatus,
    /// The repository's type checker.
    pub typecheck: CheckStatus,
}

/// One field of [`FixChecks`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FixCheck {
    /// [`FixChecks::reproduction_test`].
    ReproductionTest,
    /// [`FixChecks::reproduction_test_unchanged`].
    ReproductionTestUnchanged,
    /// [`FixChecks::previously_green_tests`].
    PreviouslyGreenTests,
    /// [`FixChecks::lint`].
    Lint,
    /// [`FixChecks::typecheck`].
    Typecheck,
}

/// Why a citation is malformed, found before any verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CitationProblem {
    /// The path is blank.
    BlankPath,
    /// The path starts with `/`.
    AbsolutePath,
    /// The path contains `\`.
    Backslash,
    /// The path contains NUL.
    Nul,
    /// The path has an empty component (`a//b`, `a/`).
    EmptyComponent,
    /// The path has a `.` component.
    DotComponent,
    /// The path has a `..` component.
    ParentComponent,
    /// The line number is 0; lines are 1-based.
    LineZero,
    /// The quote is blank.
    BlankQuote,
    /// The citation names another commit than the run's base.
    NotOnBase,
}

/// Why a gate did not pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateFailure {
    /// The reproduction test passed on the base, so it does not reproduce.
    ReproductionPassedOnBase,
    /// The reproduction test failed, but not on an assertion.
    ReproductionNotAnAssertion(TestStatus),
    /// The runner could not tell how the reproduction test ended.
    ReproductionInconclusive,
    /// The analysis cites nothing.
    NoCitations,
    /// A citation is malformed; the first one is reported.
    CitationMalformed {
        /// Its index in the analysis.
        index: usize,
        /// What is wrong with it.
        problem: CitationProblem,
    },
    /// The verifier returned another number of results than there are
    /// citations (inconclusive).
    CitationResultsMismatch {
        /// Number of citations.
        citations: usize,
        /// Number of results.
        results: usize,
    },
    /// Citations that are not verified, every flagged index in ascending
    /// order.
    CitationsNotVerified {
        /// Indices of the citations that are not `Verified`.
        indices: Vec<usize>,
    },
    /// A fix check failed; the first in field order is reported.
    FixCheckFailed(FixCheck),
    /// A fix check is unknown, or a required one is not configured.
    FixCheckInconclusive(FixCheck),
}

/// The decision of one gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateOutcome {
    /// The gate passes.
    Pass,
    /// The gate does not pass.
    Fail(GateFailure),
}

/// Reproduction gate: on the base SHA the test runs and fails on an
/// assertion, not on compilation (`docs/ARCHITECTURE.md`, "Debugging line",
/// step 3).
pub fn reproduction_gate(status: TestStatus) -> GateOutcome {
    let failure = match status {
        TestStatus::FailedOnAssertion => return GateOutcome::Pass,
        TestStatus::Passed => GateFailure::ReproductionPassedOnBase,
        TestStatus::FailedToBuild | TestStatus::Errored | TestStatus::TimedOut => {
            GateFailure::ReproductionNotAnAssertion(status)
        }
        TestStatus::Unknown => GateFailure::ReproductionInconclusive,
    };
    GateOutcome::Fail(failure)
}

/// The first problem of one citation, checked before verification: the path
/// is relative and canonical, the line is 1-based, the quote is not blank
/// and the SHA is the run's base.
///
/// Only `/` and ASCII `.` are structural in a git path, so `~/x`, `file:x`
/// and look-alike dots are literal repository paths; verification against
/// the tree (#17) reports them `Unverifiable` when they are absent.
pub fn citation_problem(citation: &Citation, base: &CommitSha) -> Option<CitationProblem> {
    let problem = if let Some(problem) = path_problem(&citation.path) {
        problem
    } else if citation.line == 0 {
        CitationProblem::LineZero
    } else if is_blank(&citation.quote) {
        CitationProblem::BlankQuote
    } else if citation.sha != *base {
        CitationProblem::NotOnBase
    } else {
        return None;
    };
    Some(problem)
}

/// The first problem of a path inside a repository or a workspace: blank,
/// absolute, a backslash, NUL, or an empty, `.` or `..` component. The one
/// path rule of the citation precheck, shared with the paths that ports
/// take (ADR-004, D1), so a port path cannot leave the tree by a route a
/// citation could not.
pub fn path_problem(path: &str) -> Option<CitationProblem> {
    if is_blank(path) {
        Some(CitationProblem::BlankPath)
    } else if path.starts_with('/') {
        Some(CitationProblem::AbsolutePath)
    } else if path.contains('\\') {
        Some(CitationProblem::Backslash)
    } else if path.contains('\0') {
        Some(CitationProblem::Nul)
    } else {
        path.split('/').find_map(component_problem)
    }
}

fn component_problem(component: &str) -> Option<CitationProblem> {
    match component {
        "" => Some(CitationProblem::EmptyComponent),
        "." => Some(CitationProblem::DotComponent),
        ".." => Some(CitationProblem::ParentComponent),
        _ => None,
    }
}

/// Root-cause precheck on `RootCauseProposed`: at least one citation, none
/// malformed; the first malformed one is reported.
pub(crate) fn root_cause_precheck(citations: &[Citation], base: &CommitSha) -> GateOutcome {
    if citations.is_empty() {
        return GateOutcome::Fail(GateFailure::NoCitations);
    }
    let first = citations
        .iter()
        .enumerate()
        .find_map(|(index, c)| citation_problem(c, base).map(|problem| (index, problem)));
    match first {
        Some((index, problem)) => {
            GateOutcome::Fail(GateFailure::CitationMalformed { index, problem })
        }
        None => GateOutcome::Pass,
    }
}

/// Root-cause gate: one result per citation, all `Verified`. Unverifiable
/// citations are flagged, and a flagged citation fails the gate. No
/// citations at all never passes (the precheck stops that case earlier).
pub fn root_cause_gate(citations: &[Citation], results: &[CitationStatus]) -> GateOutcome {
    if citations.len() != results.len() {
        return GateOutcome::Fail(GateFailure::CitationResultsMismatch {
            citations: citations.len(),
            results: results.len(),
        });
    }
    if citations.is_empty() {
        return GateOutcome::Fail(GateFailure::NoCitations);
    }
    let indices: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, status)| **status != CitationStatus::Verified)
        .map(|(index, _)| index)
        .collect();
    if indices.is_empty() {
        GateOutcome::Pass
    } else {
        GateOutcome::Fail(GateFailure::CitationsNotVerified { indices })
    }
}

/// Fix gate: the reproduction test passes, it is unchanged, previously green
/// tests stay green, and lint and typecheck pass where configured
/// (`docs/ARCHITECTURE.md`, "Debugging line", step 5). The first field in
/// that order that does not pass is reported.
pub fn fix_gate(checks: &FixChecks) -> GateOutcome {
    let test = match checks.reproduction_test {
        TestStatus::Passed => None,
        TestStatus::Unknown => Some(GateFailure::FixCheckInconclusive(
            FixCheck::ReproductionTest,
        )),
        _ => Some(GateFailure::FixCheckFailed(FixCheck::ReproductionTest)),
    };
    let fields = [
        (
            FixCheck::ReproductionTestUnchanged,
            checks.reproduction_test_unchanged,
            true,
        ),
        (
            FixCheck::PreviouslyGreenTests,
            checks.previously_green_tests,
            true,
        ),
        (FixCheck::Lint, checks.lint, false),
        (FixCheck::Typecheck, checks.typecheck, false),
    ];
    let failure = test.or_else(|| {
        fields
            .into_iter()
            .find_map(|(field, status, required)| check_failure(field, status, required))
    });
    match failure {
        Some(failure) => GateOutcome::Fail(failure),
        None => GateOutcome::Pass,
    }
}

fn check_failure(field: FixCheck, status: CheckStatus, required: bool) -> Option<GateFailure> {
    match status {
        CheckStatus::Passed => None,
        CheckStatus::NotConfigured if !required => None,
        CheckStatus::Failed => Some(GateFailure::FixCheckFailed(field)),
        CheckStatus::NotConfigured | CheckStatus::Unknown => {
            Some(GateFailure::FixCheckInconclusive(field))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec;

    const BASE: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER: &str = "fedcba9876543210fedcba9876543210fedcba98";

    fn sha(hex: &str) -> CommitSha {
        CommitSha::parse(hex).expect("test SHA is valid")
    }

    fn citation(path: &str, line: u32) -> Citation {
        Citation {
            path: String::from(path),
            line,
            sha: sha(BASE),
            quote: String::from("total += 1;"),
        }
    }

    #[test]
    fn reproduction_gate_passes_only_on_assertion() {
        use TestStatus::*;
        assert_eq!(reproduction_gate(FailedOnAssertion), GateOutcome::Pass);
        assert_eq!(
            reproduction_gate(Passed),
            GateOutcome::Fail(GateFailure::ReproductionPassedOnBase)
        );
        for status in [FailedToBuild, Errored, TimedOut] {
            assert_eq!(
                reproduction_gate(status),
                GateOutcome::Fail(GateFailure::ReproductionNotAnAssertion(status))
            );
        }
        assert_eq!(
            reproduction_gate(Unknown),
            GateOutcome::Fail(GateFailure::ReproductionInconclusive)
        );
    }

    #[test]
    fn citation_problem_path_forms() {
        let base = sha(BASE);
        let rejected = [
            ("/abs", CitationProblem::AbsolutePath),
            ("..", CitationProblem::ParentComponent),
            ("a/../b", CitationProblem::ParentComponent),
            ("a\\b", CitationProblem::Backslash),
            ("a//b", CitationProblem::EmptyComponent),
            ("./a", CitationProblem::DotComponent),
            ("a/", CitationProblem::EmptyComponent),
            ("", CitationProblem::BlankPath),
            ("\u{200B}", CitationProblem::BlankPath),
            ("a\0b", CitationProblem::Nul),
        ];
        for (path, problem) in rejected {
            assert_eq!(
                citation_problem(&citation(path, 1), &base),
                Some(problem),
                "{path:?}"
            );
        }
        for path in ["src/lib.rs", "~/x", "file:x", "\u{2024}\u{2024}/x"] {
            assert_eq!(
                citation_problem(&citation(path, 1), &base),
                None,
                "{path:?}"
            );
        }
        assert_eq!(
            citation_problem(&citation("src/lib.rs", 0), &base),
            Some(CitationProblem::LineZero)
        );
        assert_eq!(
            citation_problem(&citation("src/lib.rs", u32::MAX), &base),
            None
        );
        let mut blank_quote = citation("src/lib.rs", 3);
        blank_quote.quote = String::from(" \u{FEFF}");
        assert_eq!(
            citation_problem(&blank_quote, &base),
            Some(CitationProblem::BlankQuote)
        );
        let mut off_base = citation("src/lib.rs", 3);
        off_base.sha = sha(OTHER);
        assert_eq!(
            citation_problem(&off_base, &base),
            Some(CitationProblem::NotOnBase)
        );
    }

    #[test]
    fn root_cause_precheck_reports_the_first_bad_citation() {
        let base = sha(BASE);
        assert_eq!(
            root_cause_precheck(&[], &base),
            GateOutcome::Fail(GateFailure::NoCitations)
        );
        let citations = [citation("a", 1), citation("/b", 1), citation("c", 0)];
        assert_eq!(
            root_cause_precheck(&citations, &base),
            GateOutcome::Fail(GateFailure::CitationMalformed {
                index: 1,
                problem: CitationProblem::AbsolutePath,
            })
        );
        assert_eq!(
            root_cause_precheck(&citations[..1], &base),
            GateOutcome::Pass
        );
    }

    #[test]
    fn root_cause_gate_flags_and_counts() {
        use CitationStatus::*;
        let two = [citation("a", 1), citation("b", 2)];
        assert_eq!(
            root_cause_gate(&two, &[Verified, Verified]),
            GateOutcome::Pass
        );
        assert_eq!(
            root_cause_gate(&two, &[Unverifiable, Mismatch]),
            GateOutcome::Fail(GateFailure::CitationsNotVerified {
                indices: vec![0, 1]
            })
        );
        assert_eq!(
            root_cause_gate(&two, &[Verified]),
            GateOutcome::Fail(GateFailure::CitationResultsMismatch {
                citations: 2,
                results: 1,
            })
        );
        assert_eq!(
            root_cause_gate(&two, &[Verified, Verified, Verified]),
            GateOutcome::Fail(GateFailure::CitationResultsMismatch {
                citations: 2,
                results: 3,
            })
        );
        assert_eq!(
            root_cause_gate(&[], &[]),
            GateOutcome::Fail(GateFailure::NoCitations)
        );
    }

    const ALL_CHECKS: [CheckStatus; 4] = [
        CheckStatus::Passed,
        CheckStatus::Failed,
        CheckStatus::NotConfigured,
        CheckStatus::Unknown,
    ];
    const ALL_TESTS: [TestStatus; 6] = [
        TestStatus::Passed,
        TestStatus::FailedOnAssertion,
        TestStatus::FailedToBuild,
        TestStatus::Errored,
        TestStatus::TimedOut,
        TestStatus::Unknown,
    ];

    fn passing() -> FixChecks {
        FixChecks {
            reproduction_test: TestStatus::Passed,
            reproduction_test_unchanged: CheckStatus::Passed,
            previously_green_tests: CheckStatus::Passed,
            lint: CheckStatus::Passed,
            typecheck: CheckStatus::Passed,
        }
    }

    // The rule per field, written out independently of fix_gate.
    fn expected_for_check(field: FixCheck, status: CheckStatus) -> Option<GateFailure> {
        let optional = matches!(field, FixCheck::Lint | FixCheck::Typecheck);
        match status {
            CheckStatus::Passed => None,
            CheckStatus::NotConfigured if optional => None,
            CheckStatus::Failed => Some(GateFailure::FixCheckFailed(field)),
            CheckStatus::NotConfigured | CheckStatus::Unknown => {
                Some(GateFailure::FixCheckInconclusive(field))
            }
        }
    }

    fn set(checks: &mut FixChecks, field: FixCheck, status: CheckStatus) {
        match field {
            FixCheck::ReproductionTest => {}
            FixCheck::ReproductionTestUnchanged => checks.reproduction_test_unchanged = status,
            FixCheck::PreviouslyGreenTests => checks.previously_green_tests = status,
            FixCheck::Lint => checks.lint = status,
            FixCheck::Typecheck => checks.typecheck = status,
        }
    }

    #[test]
    fn fix_gate_table() {
        assert_eq!(fix_gate(&passing()), GateOutcome::Pass);
        for status in ALL_TESTS {
            let checks = FixChecks {
                reproduction_test: status,
                ..passing()
            };
            let expected = match status {
                TestStatus::Passed => GateOutcome::Pass,
                TestStatus::Unknown => GateOutcome::Fail(GateFailure::FixCheckInconclusive(
                    FixCheck::ReproductionTest,
                )),
                _ => GateOutcome::Fail(GateFailure::FixCheckFailed(FixCheck::ReproductionTest)),
            };
            assert_eq!(fix_gate(&checks), expected, "{status:?}");
        }
        let fields = [
            FixCheck::ReproductionTestUnchanged,
            FixCheck::PreviouslyGreenTests,
            FixCheck::Lint,
            FixCheck::Typecheck,
        ];
        for field in fields {
            for status in ALL_CHECKS {
                let mut checks = passing();
                set(&mut checks, field, status);
                let expected = match expected_for_check(field, status) {
                    None => GateOutcome::Pass,
                    Some(failure) => GateOutcome::Fail(failure),
                };
                assert_eq!(fix_gate(&checks), expected, "{field:?} {status:?}");
            }
        }
        // Two failing fields: the first in field order is reported.
        for (k, first) in fields.iter().enumerate() {
            for later in &fields[k + 1..] {
                let mut checks = passing();
                set(&mut checks, *later, CheckStatus::Failed);
                set(&mut checks, *first, CheckStatus::Unknown);
                assert_eq!(
                    fix_gate(&checks),
                    GateOutcome::Fail(GateFailure::FixCheckInconclusive(*first)),
                    "{first:?} before {later:?}"
                );
            }
        }
        let both = FixChecks {
            reproduction_test: TestStatus::TimedOut,
            typecheck: CheckStatus::Failed,
            ..passing()
        };
        assert_eq!(
            fix_gate(&both),
            GateOutcome::Fail(GateFailure::FixCheckFailed(FixCheck::ReproductionTest))
        );
    }
}
