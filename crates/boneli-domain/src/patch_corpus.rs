//! The patch corpus of the patch policy (ADR-013).
//!
//! Test data compiled into the library, for the reason the scenarios are
//! (ADR-002, D4): the domain's unit tests judge every case and compare the
//! verdict with a test-only table, and the `boneli-replay-check` harness
//! renders every verdict in two child processes and in its own and
//! compares the `Debug` output byte for byte. The cases together reach
//! every [`PatchViolation`](crate::patch::PatchViolation) variant and every
//! reason variant, so every violation the policy can return passes the
//! address-leak gate.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use crate::patch::{BaseLink, Change, Entry, EntryKind, Patch, PatchLimits};

/// One named patch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchCase {
    /// Unique, `[a-z0-9-]+`.
    pub name: &'static str,
    /// The patch.
    pub patch: Patch,
    /// The limits it is judged with.
    pub limits: PatchLimits,
}

fn entry(kind: EntryKind, data: &[u8]) -> Option<Entry> {
    Some(Entry {
        kind,
        data: data.to_vec(),
    })
}

fn file(text: &str) -> Option<Entry> {
    entry(EntryKind::File, text.as_bytes())
}

fn link(target: &str) -> Option<Entry> {
    entry(EntryKind::Symlink, target.as_bytes())
}

fn change(path: &str, before: Option<Entry>, after: Option<Entry>) -> Change {
    Change {
        path: String::from(path),
        before,
        after,
    }
}

fn add(path: &str, after: Option<Entry>) -> Change {
    change(path, None, after)
}

fn base_link(path: &str, target: &str) -> BaseLink {
    BaseLink {
        path: String::from(path),
        target: target.as_bytes().to_vec(),
    }
}

fn case(name: &'static str, changes: Vec<Change>, base_links: Vec<BaseLink>) -> PatchCase {
    PatchCase {
        name,
        patch: Patch {
            changes,
            base_links,
        },
        limits: PatchLimits::DEFAULT,
    }
}

/// A test file with two tests, the base of the disabled-test cases.
pub(crate) const SUITE: &str = "describe('totals', () => {\n  it('adds', () => {\n    expect(sum(1, 2)).toBe(3)\n  })\n  it('rounds', () => {\n    expect(sum(0.1, 0.2)).toBeCloseTo(0.3)\n  })\n})\n";

/// One line per marker, in marker order.
const MARKER_LINES: &str = "it.skip('a', f)\nit.only('b', f)\nit.todo('c')\ntest.fixme('d', f)\nit.skipIf(c)('e', f)\nit.runIf(c)('f', f)\nit.fails('g', f)\ntest.failing('h', f)\ntest.fail('i', f)\nxit('j', f)\nxtest('k', f)\nxdescribe('l', f)\nxcontext('m', f)\nxspecify('n', f)\nfit('o', f)\nfdescribe('p', f)\nfcontext('q', f)\n";

/// Every case, in a fixed order.
pub fn cases() -> Vec<PatchCase> {
    let gitlink = entry(
        EntryKind::Gitlink,
        b"0123456789abcdef0123456789abcdef01234567",
    );
    let lines = |count: usize| -> String { (0..count).map(|k| format!("line {k}\n")).collect() };
    let rounds = "  it('rounds', () => {\n    expect(sum(0.1, 0.2)).toBeCloseTo(0.3)\n  })\n";
    let mut tight = case(
        "tight-limits",
        vec![add("a.ts", file("a\nb\n")), add("b.ts", file("c\n"))],
        Vec::new(),
    );
    tight.limits = PatchLimits {
        max_changed_files: NonZeroU32::MIN,
        max_changed_lines: NonZeroU32::MIN,
    };
    vec![
        case(
            "pass-one-line-fix",
            vec![change(
                "src/totals.ts",
                file("return a + b + 1\n"),
                file("return a + b\n"),
            )],
            Vec::new(),
        ),
        case(
            "pass-new-reproduction-test",
            vec![
                add("src/totals.test.ts", file(SUITE)),
                change("src/totals.ts", file("x\n"), file("y\n")),
            ],
            Vec::new(),
        ),
        case(
            "pass-links-and-modes",
            vec![
                change(
                    "bin/run",
                    file("echo\n"),
                    entry(EntryKind::Executable, b"echo\n"),
                ),
                add("docs/README.md", link("../README.md")),
                change("logo.png", entry(EntryKind::File, b"\x89PNG\0"), None),
                change("old", link("/etc"), None),
            ],
            vec![base_link("old", "/etc"), base_link("outward", "/etc")],
        ),
        case(
            "too-many-files",
            (0..26)
                .map(|k| add(&format!("f{k:02}.ts"), file("x\n")))
                .collect(),
            Vec::new(),
        ),
        tight,
        case("empty", Vec::new(), vec![base_link("l", "a")]),
        case(
            "malformed-order",
            vec![
                add("b", file("x\n")),
                add("a", file("x\n")),
                add("a", file("y\n")),
            ],
            Vec::new(),
        ),
        case(
            "malformed-paths",
            vec![
                add("", file("x\n")),
                add("/a", file("x\n")),
                add("a\0b", file("x\n")),
                add("a/../b", file("x\n")),
                add("a/./b", file("x\n")),
                add("a//b", file("x\n")),
                add("a\\b", file("x\n")),
            ],
            Vec::new(),
        ),
        case(
            "malformed-sides",
            vec![
                change("a", file("x\n"), file("x\n")),
                add("b", link("")),
                add("c", link("c\0")),
                change("d", link("x"), None),
                add("e", file("x\n")),
            ],
            vec![base_link("e", "x")],
        ),
        case(
            "base-link-malformed",
            vec![add("src/a.ts", file("x\n"))],
            vec![
                base_link("b", "x"),
                base_link("a", ""),
                base_link("a/../c", "x\0"),
            ],
        ),
        case(
            "too-many-lines",
            vec![add("a.ts", file(&lines(1001)))],
            Vec::new(),
        ),
        case(
            "forbidden-classes",
            vec![
                add(".git/config", file("x\n")),
                add(".github/workflows/ci.yml", file("x\n")),
                add(".gitmodules", file("x\n")),
                add("CODEOWNERS", file("x\n")),
                add("Dockerfile", file("x\n")),
                add("package.json", file("x\n")),
            ],
            Vec::new(),
        ),
        case(
            "gitlink-and-binaries",
            vec![
                add("a.bin", entry(EntryKind::File, b"a\0")),
                add("b.txt", entry(EntryKind::Executable, b"\xFF")),
                add("c.ts", file("x\u{202E}\n")),
                add("vendor/lib", gitlink),
            ],
            Vec::new(),
        ),
        case(
            "link-problems",
            vec![
                add("a", entry(EntryKind::Symlink, b"\xFF")),
                add("b", link(&"a/".repeat(2048))),
                add("c", link("/etc/passwd")),
                add("d", link("..\\x")),
                add("e", link("../x")),
                add("f", link("z/x")),
                add("h", link(".github/workflows")),
                add("z/w.ts", file("x\n")),
            ],
            vec![base_link("z", "y")],
        ),
        case(
            "markers",
            vec![change(
                "src/totals.test.ts",
                file(SUITE),
                file(&format!("{SUITE}{MARKER_LINES}")),
            )],
            Vec::new(),
        ),
        case(
            "tests-deleted-removed-config",
            vec![
                change("a.test.ts", file(SUITE), None),
                change("b.spec.ts", file(SUITE), file(&SUITE.replace(rounds, ""))),
                change("jest.config.ts", file("a\n"), file("b\n")),
                change(
                    "vite.config.ts",
                    file("export default { test: {} }\n"),
                    file("export default {}\n"),
                ),
            ],
            Vec::new(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::CitationProblem;
    use crate::patch::{
        ChangeProblem, LinkProblem, NotText, PatchVerdict, PatchViolation, TestDisabling,
        patch_policy,
    };
    use crate::patch_js::Marker;
    use crate::patch_path::ForbiddenClass;
    use alloc::collections::BTreeSet;

    fn malformed(index: usize, problem: ChangeProblem) -> PatchViolation {
        PatchViolation::Malformed { index, problem }
    }

    fn path(index: usize, problem: CitationProblem) -> PatchViolation {
        malformed(index, ChangeProblem::Path(problem))
    }

    fn base(index: usize, problem: ChangeProblem) -> PatchViolation {
        PatchViolation::BaseLinkMalformed { index, problem }
    }

    fn forbidden(index: usize, class: ForbiddenClass) -> PatchViolation {
        PatchViolation::Forbidden { index, class }
    }

    fn link(index: usize, problem: LinkProblem) -> PatchViolation {
        PatchViolation::Link { index, problem }
    }

    fn disables(index: usize, reason: TestDisabling) -> PatchViolation {
        PatchViolation::DisablesTests { index, reason }
    }

    fn reject(violations: Vec<PatchViolation>) -> PatchVerdict {
        PatchVerdict::Reject(violations)
    }

    /// The expected verdict of every case, by name, written out
    /// independently of the policy.
    fn expectations() -> Vec<(&'static str, PatchVerdict)> {
        use ChangeProblem::*;
        use CitationProblem::*;
        use ForbiddenClass::*;
        vec![
            (
                "pass-one-line-fix",
                PatchVerdict::Pass { files: 1, lines: 2 },
            ),
            (
                "pass-new-reproduction-test",
                PatchVerdict::Pass {
                    files: 2,
                    lines: 10,
                },
            ),
            (
                "pass-links-and-modes",
                PatchVerdict::Pass { files: 4, lines: 2 },
            ),
            (
                "too-many-files",
                reject(vec![PatchViolation::TooManyFiles {
                    files: 26,
                    limit: 25,
                }]),
            ),
            (
                "tight-limits",
                reject(vec![PatchViolation::TooManyFiles { files: 2, limit: 1 }]),
            ),
            ("empty", reject(vec![PatchViolation::Empty])),
            (
                "malformed-order",
                reject(vec![malformed(1, OutOfOrder), malformed(2, OutOfOrder)]),
            ),
            (
                "malformed-paths",
                reject(vec![
                    path(0, BlankPath),
                    path(1, AbsolutePath),
                    path(2, Nul),
                    path(3, ParentComponent),
                    path(4, DotComponent),
                    path(5, EmptyComponent),
                    path(6, Backslash),
                ]),
            ),
            (
                "malformed-sides",
                reject(vec![
                    malformed(0, NoChange),
                    malformed(1, EmptyLinkTarget),
                    malformed(2, NulInLinkTarget),
                    malformed(3, BaseLinkMismatch),
                    malformed(4, BaseLinkMismatch),
                ]),
            ),
            (
                "base-link-malformed",
                reject(vec![
                    base(1, OutOfOrder),
                    base(1, EmptyLinkTarget),
                    base(2, Path(ParentComponent)),
                    base(2, NulInLinkTarget),
                ]),
            ),
            (
                "too-many-lines",
                reject(vec![PatchViolation::TooManyLines { limit: 1000 }]),
            ),
            (
                "forbidden-classes",
                reject(vec![
                    forbidden(0, RepositoryMetadata),
                    forbidden(1, Ci),
                    forbidden(2, GitConfig),
                    forbidden(3, CodeOwners),
                    forbidden(4, ContainerBuild),
                    forbidden(5, Dependencies),
                ]),
            ),
            (
                "gitlink-and-binaries",
                reject(vec![
                    PatchViolation::NotText {
                        index: 0,
                        reason: NotText::Nul,
                    },
                    PatchViolation::NotText {
                        index: 1,
                        reason: NotText::NotUtf8,
                    },
                    PatchViolation::NotText {
                        index: 2,
                        reason: NotText::BidiControl,
                    },
                    PatchViolation::Gitlink { index: 3 },
                ]),
            ),
            (
                "link-problems",
                reject(vec![
                    link(0, LinkProblem::NotUtf8),
                    link(1, LinkProblem::TooLong),
                    link(2, LinkProblem::Absolute),
                    link(3, LinkProblem::WindowsForm),
                    link(4, LinkProblem::Escapes),
                    link(5, LinkProblem::ThroughLink),
                    link(6, LinkProblem::Into(Ci)),
                    link(7, LinkProblem::ThroughLink),
                ]),
            ),
            (
                "markers",
                reject(
                    Marker::ALL
                        .into_iter()
                        .map(|m| disables(0, TestDisabling::Marker(m)))
                        .collect(),
                ),
            ),
            (
                "tests-deleted-removed-config",
                reject(vec![
                    disables(0, TestDisabling::DeletedTestFile),
                    disables(1, TestDisabling::TestsRemoved),
                    disables(2, TestDisabling::TestConfigChanged),
                    disables(3, TestDisabling::TestConfigChanged),
                ]),
            ),
        ]
    }

    #[test]
    fn corpus_matches_expectations() {
        let all = cases();
        let expected = expectations();
        let names: Vec<&str> = all.iter().map(|c| c.name).collect();
        let expected_names: Vec<&str> = expected.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, expected_names, "one expectation per case, in order");
        for (case, (_, want)) in all.iter().zip(&expected) {
            assert_eq!(
                &patch_policy(&case.patch, &case.limits),
                want,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn case_names_are_unique_and_kebab() {
        let all = cases();
        let names: BTreeSet<&str> = all.iter().map(|c| c.name).collect();
        assert_eq!(names.len(), all.len());
        for name in names {
            assert!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-')),
                "{name:?}"
            );
        }
    }

    /// Every variant and every reason variant a violation can carry, as a
    /// label. The match has no wildcard: a new variant does not compile
    /// until it gets a label here, and its label goes into `EVERY_LABEL`
    /// (markers come from `Marker::ALL`), which the corpus must then cover.
    fn labels(violation: &PatchViolation) -> Vec<&'static str> {
        let problem = |p: &ChangeProblem| match p {
            ChangeProblem::OutOfOrder => "out-of-order",
            ChangeProblem::Path(_) => "path",
            ChangeProblem::NoChange => "no-change",
            ChangeProblem::EmptyLinkTarget => "empty-link-target",
            ChangeProblem::NulInLinkTarget => "nul-in-link-target",
            ChangeProblem::BaseLinkMismatch => "base-link-mismatch",
        };
        let class = |c: &ForbiddenClass| match c {
            ForbiddenClass::RepositoryMetadata => "repository-metadata",
            ForbiddenClass::Ci => "ci",
            ForbiddenClass::ContainerBuild => "container-build",
            ForbiddenClass::CodeOwners => "code-owners",
            ForbiddenClass::GitConfig => "git-config",
            ForbiddenClass::Dependencies => "dependencies",
        };
        match violation {
            PatchViolation::TooManyFiles { .. } => vec!["too-many-files"],
            PatchViolation::Empty => vec!["empty"],
            PatchViolation::Malformed { problem: p, .. } => vec!["malformed", problem(p)],
            PatchViolation::BaseLinkMalformed { problem: p, .. } => {
                vec!["base-link-malformed", problem(p)]
            }
            PatchViolation::TooManyLines { .. } => vec!["too-many-lines"],
            PatchViolation::Forbidden { class: c, .. } => vec!["forbidden", class(c)],
            PatchViolation::Gitlink { .. } => vec!["gitlink"],
            PatchViolation::NotText { reason, .. } => vec![
                "not-text",
                match reason {
                    NotText::Nul => "nul",
                    NotText::NotUtf8 => "not-utf8",
                    NotText::BidiControl => "bidi-control",
                },
            ],
            PatchViolation::Link { problem, .. } => vec![
                "link",
                match problem {
                    LinkProblem::NotUtf8 => "link-not-utf8",
                    LinkProblem::TooLong => "too-long",
                    LinkProblem::Absolute => "absolute",
                    LinkProblem::WindowsForm => "windows-form",
                    LinkProblem::Escapes => "escapes",
                    LinkProblem::ThroughLink => "through-link",
                    LinkProblem::Into(_) => "into",
                },
            ],
            PatchViolation::DisablesTests { reason, .. } => vec![
                "disables-tests",
                match reason {
                    TestDisabling::Marker(m) => m.name(),
                    TestDisabling::DeletedTestFile => "deleted-test-file",
                    TestDisabling::TestsRemoved => "tests-removed",
                    TestDisabling::TestConfigChanged => "test-config-changed",
                },
            ],
        }
    }

    const EVERY_LABEL: [&str; 35] = [
        "too-many-files",
        "empty",
        "malformed",
        "base-link-malformed",
        "out-of-order",
        "path",
        "no-change",
        "empty-link-target",
        "nul-in-link-target",
        "base-link-mismatch",
        "too-many-lines",
        "forbidden",
        "repository-metadata",
        "ci",
        "container-build",
        "code-owners",
        "git-config",
        "dependencies",
        "gitlink",
        "not-text",
        "nul",
        "not-utf8",
        "bidi-control",
        "link",
        "link-not-utf8",
        "too-long",
        "absolute",
        "windows-form",
        "escapes",
        "through-link",
        "into",
        "disables-tests",
        "deleted-test-file",
        "tests-removed",
        "test-config-changed",
    ];

    #[test]
    fn corpus_covers_every_variant() {
        let mut seen = BTreeSet::new();
        let mut passes = 0;
        for case in cases() {
            match patch_policy(&case.patch, &case.limits) {
                PatchVerdict::Pass { .. } => passes += 1,
                PatchVerdict::Reject(violations) => {
                    for violation in &violations {
                        seen.extend(labels(violation));
                    }
                }
            }
        }
        assert!(passes >= 3, "passing cases too");
        let mut every: BTreeSet<&str> = EVERY_LABEL.into_iter().collect();
        every.extend(Marker::ALL.iter().map(|m| m.name()));
        assert_eq!(
            every.len(),
            EVERY_LABEL.len() + Marker::ALL.len(),
            "labels are distinct"
        );
        assert_eq!(seen, every);
    }
}
