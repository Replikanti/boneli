//! Rule ids and the report (ADR-001; output contract in ADR-015, D3).

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt as _;

use crate::text::{show, show_bytes};

/// A rule id. The order is the order of `--list-rules`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    ToolError,
    MemberName,
    CoreMissing,
    GraphDomain,
    GraphApp,
    GraphSupport,
    GraphAdapter,
    GraphRootLeaf,
    LintsInherit,
    LintsUnsafe,
    SysLints,
    CargoConfig,
    ClippyConfig,
    ToolchainFile,
    DoctestUnsafe,
    UnsafeToken,
    SysMacroExport,
    ProcMacro,
    BuildScript,
    SourceRedirect,
    Symlink,
    CoreNoStdAttr,
    CoreNoStdBuild,
    CoreTargets,
    CoreFeatures,
    CoreToken,
    ManifestRedirect,
    DepSource,
    DepEdge,
    DepBuildScript,
    PolicyFormat,
    PolicyStrict,
}

/// Every rule, in the order of `--list-rules`.
pub(crate) const RULES: [Rule; 32] = [
    Rule::ToolError,
    Rule::MemberName,
    Rule::CoreMissing,
    Rule::GraphDomain,
    Rule::GraphApp,
    Rule::GraphSupport,
    Rule::GraphAdapter,
    Rule::GraphRootLeaf,
    Rule::LintsInherit,
    Rule::LintsUnsafe,
    Rule::SysLints,
    Rule::CargoConfig,
    Rule::ClippyConfig,
    Rule::ToolchainFile,
    Rule::DoctestUnsafe,
    Rule::UnsafeToken,
    Rule::SysMacroExport,
    Rule::ProcMacro,
    Rule::BuildScript,
    Rule::SourceRedirect,
    Rule::Symlink,
    Rule::CoreNoStdAttr,
    Rule::CoreNoStdBuild,
    Rule::CoreTargets,
    Rule::CoreFeatures,
    Rule::CoreToken,
    Rule::ManifestRedirect,
    Rule::DepSource,
    Rule::DepEdge,
    Rule::DepBuildScript,
    Rule::PolicyFormat,
    Rule::PolicyStrict,
];

/// The ids, indexed by `Rule as usize`.
const IDS: [&str; 32] = [
    "tool-error",
    "member-name",
    "core-missing",
    "graph-domain",
    "graph-app",
    "graph-support",
    "graph-adapter",
    "graph-root-leaf",
    "lints-inherit",
    "lints-\x75nsafe",
    "sys-lints",
    "cargo-config",
    "clippy-config",
    "toolchain-file",
    "doctest-\x75nsafe",
    "\x75nsafe-token",
    "sys-macro-export",
    "proc-macro",
    "build-script",
    "source-redirect",
    "symlink",
    "core-no-std-attr",
    "core-no-std-build",
    "core-targets",
    "core-features",
    "core-token",
    "manifest-redirect",
    "dep-source",
    "dep-edge",
    "dep-build-script",
    "policy-format",
    "policy-strict",
];

impl Rule {
    /// The id as printed in a FAIL line.
    pub(crate) fn id(self) -> &'static str {
        IDS[self as usize]
    }

    /// The rule with id `id`.
    pub(crate) fn from_id(id: &str) -> Option<Rule> {
        RULES.iter().copied().find(|r| r.id() == id)
    }
}

/// One violation. The path is relative to the root, as raw bytes, so that
/// a file name outside UTF-8 is kept exactly until it is printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Item {
    pub(crate) rule: Rule,
    pub(crate) path: OsString,
    pub(crate) line: Option<usize>,
    pub(crate) message: String,
}

/// Violations in the order they were found, each (rule, path, line,
/// message) at most once.
#[derive(Debug, Default)]
pub(crate) struct Report {
    pub(crate) items: Vec<Item>,
}

impl Report {
    /// Records a violation unless the same one is already recorded.
    pub(crate) fn fail(
        &mut self,
        rule: Rule,
        path: impl Into<OsString>,
        message: impl Into<String>,
        line: Option<usize>,
    ) {
        let item = Item {
            rule,
            path: path.into(),
            line,
            message: message.into(),
        };
        if !self.items.contains(&item) {
            self.items.push(item);
        }
    }
}

/// A failure that stops the check: one `tool-error` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolError {
    pub(crate) path: OsString,
    pub(crate) message: String,
}

impl ToolError {
    pub(crate) fn new(path: impl Into<OsString>, message: impl Into<String>) -> ToolError {
        ToolError {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// What the check ended with.
pub(crate) enum Outcome {
    /// The check ran; the report may be empty.
    Report(Report),
    /// A tool error stopped it.
    Tool(ToolError),
    /// The check panicked or could not start: an internal error.
    Internal(String),
}

/// The text after `OK: ` when nothing failed.
pub(crate) const OK_LINE: &str =
    "OK: crate graph, lints, \x75nsafe containment, core purity, sources and dependency edges";

/// The path that names the checker in an internal error.
pub(crate) const SELF_PATH: &str = "crates/boneli-arch-check";

/// One FAIL line, escaped: paths and messages go through [`show`], so a
/// control character or a line break in a file name cannot forge a line.
pub(crate) fn fail_line(rule: Rule, path: &[u8], line: Option<usize>, message: &str) -> String {
    let mut out = format!("FAIL [{}] {}", rule.id(), show_bytes(path));
    if let Some(line) = line {
        out.push_str(&format!(":{line}"));
    }
    out.push_str(": ");
    out.push_str(&show(message));
    out
}

/// Writes the outcome and returns the exit code: 0 OK, 1 violations, 2 a
/// tool or internal error. A write error is exit 2 too.
pub(crate) fn emit(outcome: &Outcome, out: &mut dyn Write) -> u8 {
    let (code, written) = match outcome {
        Outcome::Report(rep) if rep.items.is_empty() => (0, writeln!(out, "{OK_LINE}")),
        Outcome::Report(rep) => (1, write_items(rep, out)),
        Outcome::Tool(err) => (
            2,
            single(
                out,
                &fail_line(Rule::ToolError, err.path.as_bytes(), None, &err.message),
            ),
        ),
        Outcome::Internal(what) => (
            2,
            single(
                out,
                &fail_line(
                    Rule::ToolError,
                    SELF_PATH.as_bytes(),
                    None,
                    &format!("internal error: {what}"),
                ),
            ),
        ),
    };
    match written.and_then(|()| out.flush()) {
        Ok(()) => code,
        Err(_) => 2,
    }
}

fn write_items(rep: &Report, out: &mut dyn Write) -> io::Result<()> {
    for item in &rep.items {
        let line = fail_line(item.rule, item.path.as_bytes(), item.line, &item.message);
        writeln!(out, "{line}")?;
    }
    writeln!(out, "{} violation(s)", rep.items.len())
}

fn single(out: &mut dyn Write, line: &str) -> io::Result<()> {
    writeln!(out, "{line}")?;
    writeln!(out, "1 violation(s)")
}

#[cfg(test)]
mod tests {
    use super::{Outcome, RULES, Report, Rule, ToolError, emit, fail_line};

    /// The ids and their order as the reference checker listed them.
    const PYTHON_ORDER: &str = "tool-error member-name core-missing graph-domain graph-app \
        graph-support graph-adapter graph-root-leaf lints-inherit lints-\x75nsafe sys-lints \
        cargo-config clippy-config toolchain-file doctest-\x75nsafe \x75nsafe-token \
        sys-macro-export proc-macro build-script source-redirect symlink core-no-std-attr \
        core-no-std-build core-targets core-features core-token manifest-redirect dep-source \
        dep-edge dep-build-script policy-format policy-strict";

    #[test]
    fn rules_in_python_order() {
        let ids: Vec<&str> = RULES.iter().map(|r| r.id()).collect();
        assert_eq!(ids, PYTHON_ORDER.split(' ').collect::<Vec<_>>());
        assert_eq!(RULES.len(), 32);
        for r in RULES {
            assert_eq!(Rule::from_id(r.id()), Some(r));
        }
    }

    #[test]
    fn report_dedups_and_keeps_order() {
        let mut rep = Report::default();
        rep.fail(
            Rule::CoreToken,
            "a.rs",
            "banned in core crates: std",
            Some(3),
        );
        rep.fail(Rule::Symlink, "b", "x", None);
        rep.fail(
            Rule::CoreToken,
            "a.rs",
            "banned in core crates: std",
            Some(3),
        );
        rep.fail(
            Rule::CoreToken,
            "a.rs",
            "banned in core crates: arch",
            Some(3),
        );
        rep.fail(
            Rule::CoreToken,
            "a.rs",
            "banned in core crates: std",
            Some(4),
        );
        let got: Vec<(&str, Option<usize>, &str)> = rep
            .items
            .iter()
            .map(|i| (i.rule.id(), i.line, i.message.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                ("core-token", Some(3), "banned in core crates: std"),
                ("symlink", None, "x"),
                ("core-token", Some(3), "banned in core crates: arch"),
                ("core-token", Some(4), "banned in core crates: std"),
            ]
        );
    }

    /// A newline or another control character in a file name stays inside
    /// one FAIL line, and the line parses back to its rule, path and line.
    #[test]
    fn output_lines_parse_back() {
        let mut rep = Report::default();
        rep.fail(Rule::Symlink, "src/a\nFAIL [x] y: z", "m\r\n", None);
        rep.fail(Rule::CoreToken, "src/\u{1b}[2Jb.rs", "t", Some(7));
        let mut out = Vec::new();
        assert_eq!(emit(&Outcome::Report(rep), &mut out), 1);
        let text = String::from_utf8(out).expect("ASCII");
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert_eq!(
            lines[0],
            "FAIL [symlink] src/a\\u{a}FAIL [x] y: z: m\\u{d}\\u{a}"
        );
        assert_eq!(lines[1], "FAIL [core-token] src/\\u{1b}[2Jb.rs:7: t");
        assert_eq!(lines[2], "2 violation(s)");
        assert!(
            lines
                .iter()
                .all(|l| l.bytes().all(|b| (b' '..=b'~').contains(&b)))
        );
        assert_eq!(
            fail_line(Rule::ToolError, b"a\xff", Some(1), "x"),
            "FAIL [tool-error] a\\u{dcff}:1: x"
        );
    }

    #[test]
    fn tool_and_internal_errors_exit_2() {
        let mut out = Vec::new();
        let err = ToolError::new("Cargo.toml", "bad");
        assert_eq!(emit(&Outcome::Tool(err), &mut out), 2);
        assert_eq!(out, b"FAIL [tool-error] Cargo.toml: bad\n1 violation(s)\n");
        out.clear();
        assert_eq!(emit(&Outcome::Internal("boom".into()), &mut out), 2);
        assert_eq!(
            out,
            b"FAIL [tool-error] crates/boneli-arch-check: internal error: boom\n1 violation(s)\n"
        );
        out.clear();
        assert_eq!(emit(&Outcome::Report(Report::default()), &mut out), 0);
        assert!(out.starts_with(b"OK: crate graph"));
    }

    struct Broken;

    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_error_exits_2() {
        assert_eq!(emit(&Outcome::Report(Report::default()), &mut Broken), 2);
        let mut rep = Report::default();
        rep.fail(Rule::Symlink, "a", "b", None);
        assert_eq!(emit(&Outcome::Report(rep), &mut Broken), 2);
    }
}
