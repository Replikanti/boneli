#![doc(test(attr(forbid(unsafe_code))))]
//! Architecture and dependency rules of the boneli workspace, and the
//! runner of their fixtures.
//!
//! Why every rule exists: docs/adr/001-core-purity-and-dependency-allowlist.md;
//! why the checker is this crate: docs/adr/015-architecture-checker-in-rust.md.
//! Policy data: tools/architecture.toml. Entry point:
//! tools/check-architecture.sh, which builds this crate and runs it.
//!
//! Output contract (ADR-015, D3): one line per violation,
//! `FAIL [<rule-id>] <path>[:<line>]: <message>`, then `OK: ...` or
//! `N violation(s)`. Exit 0 means OK, 1 violations, 2 a tool error, a
//! usage error or an internal error; never 101. Diagnostics from cargo
//! and rustc go to stderr.
//!
//! Flags: `--root <dir>` (default: the repository root), `--list-rules`,
//! `--fixtures` (runs tools/fixtures/arch/cases).

mod cfg;
mod check;
mod fixtures;
mod fs;
mod metadata;
mod policy;
mod rules;
mod scan;
mod text;
mod tmp;

#[cfg(test)]
mod py_vectors;

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::rules::{Outcome, RULES, emit};

/// The stack of the thread the check runs on: the smallest power of two
/// on which its deepest operation uses at most 75% in the test profile
/// (ADR-015, D4).
pub(crate) const CHECK_STACK: usize = 1 << 19;

const USAGE: &str = "usage: check-architecture.sh [--root <dir> | --list-rules | --fixtures]\n";

/// The repository this checker was built from.
pub(crate) fn repo_root() -> PathBuf {
    fs::resolve(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

/// Runs `f` on a thread with [`CHECK_STACK`]; a panic or a thread that
/// cannot start is an internal error.
pub(crate) fn guarded<F>(f: F) -> Outcome
where
    F: FnOnce() -> Result<rules::Report, rules::ToolError> + Send + 'static,
{
    let spawned = std::thread::Builder::new()
        .name("arch-check".to_owned())
        .stack_size(CHECK_STACK)
        .spawn(f);
    match spawned {
        Err(err) => Outcome::Internal(format!("cannot start the check thread: {err}")),
        Ok(handle) => match handle.join() {
            Ok(Ok(rep)) => Outcome::Report(rep),
            Ok(Err(err)) => Outcome::Tool(err),
            Err(payload) => {
                let what = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown payload".to_owned());
                Outcome::Internal(format!("panic: {what}"))
            }
        },
    }
}

/// Runs the checker with the arguments after the program name and returns
/// the exit code.
pub fn run(args: Vec<OsString>) -> u8 {
    let mut out = std::io::stdout().lock();
    if args == ["--list-rules"] {
        let mut text = String::new();
        for r in RULES {
            text.push_str(r.id());
            text.push('\n');
        }
        return match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
            Ok(()) => 0,
            Err(_) => 2,
        };
    }
    if args == ["--fixtures"] {
        return fixtures::run_fixtures(&repo_root(), &mut out);
    }
    let root = match args.as_slice() {
        [] => repo_root(),
        [flag, dir] if flag == "--root" => fs::resolve(Path::new(dir)),
        _ => {
            let _ = std::io::stderr().write_all(USAGE.as_bytes());
            return 2;
        }
    };
    let outcome = guarded(move || check::check(&root));
    emit(&outcome, &mut out)
}

#[cfg(test)]
mod tests {
    use super::{CHECK_STACK, guarded};
    use crate::rules::{Outcome, Report, ToolError, emit};

    /// The deepest inputs each parser accepts, read the way the check
    /// reads them: TOML at depth 128 by every route (header chains,
    /// dotted keys, inline tables, arrays), printed as a message would
    /// print it; `cargo metadata` JSON at depth 128 (objects and arrays);
    /// a cfg 32 levels deep, parsed and evaluated.
    fn deepest_workload() {
        workload(None);
    }

    /// One operation of the workload, or all of them.
    fn workload(only: Option<&str>) {
        let run = |op: &str| only.is_none_or(|o| o == op);
        let limits =
            boneli_toml::Limits::new(crate::check::TOML_MAX_BYTES, crate::check::TOML_MAX_DEPTH)
                .expect("limits");
        let chain = |n: usize| vec!["k"; n].join(".");
        let inline = format!("a = {}1{}", "{ a = ".repeat(127), " }".repeat(127));
        let arrays = format!("a = {}{}", "[".repeat(127), "]".repeat(127));
        let header = format!("[{}]\n", chain(127));
        let dotted = format!("{} = 1\n", chain(128));
        for (op, input) in [
            ("toml-header", header),
            ("toml-dotted", dotted),
            ("toml-inline", inline),
            ("toml-arrays", arrays),
        ] {
            if !run(op) {
                continue;
            }
            let table = boneli_toml::parse(input.as_bytes(), &limits).expect("depth 128 parses");
            for (_, value) in table.iter() {
                assert!(!crate::policy::toml_text(value).is_empty());
            }
        }
        let objects = format!("{}0{}", "{\"a\":".repeat(128), "}".repeat(128));
        let arrays = format!("{}{}", "[".repeat(128), "]".repeat(128));
        for (op, input) in [("json-objects", objects), ("json-arrays", arrays)] {
            if !run(op) {
                continue;
            }
            let err = crate::metadata::parse(input.as_bytes()).expect_err("not metadata");
            assert!(err.message.contains("unexpected JSON"), "{}", err.message);
        }
        if run("cfg") {
            let cfg = format!("{}unix{}", "any(not(".repeat(16), "))".repeat(16));
            let tree = crate::cfg::parse_cfg(&cfg).expect("32 levels");
            let _ = crate::cfg::eval_cfg(&tree, &crate::cfg::CfgSet::new());
        }
    }

    /// The deepest inputs fit the check thread (ADR-015, D4).
    #[test]
    fn deepest_inputs_fit_check_stack() {
        let outcome = guarded(|| {
            deepest_workload();
            Ok(Report::default())
        });
        assert!(matches!(outcome, Outcome::Report(_)));
        assert_eq!(CHECK_STACK.count_ones(), 1);
    }

    /// Measurement aid for ADR-015 D4: parses the file named by
    /// `BONELI_ARCH_JSON` as `cargo metadata` output (peak RSS).
    #[test]
    #[ignore = "measurement"]
    fn memory_probe() {
        let data = std::fs::read(std::env::var("BONELI_ARCH_JSON").expect("file")).expect("read");
        let _ = crate::metadata::parse(&data);
    }

    /// Measurement aid for ADR-015 D4: runs the workload on a thread of
    /// `BONELI_ARCH_STACK` bytes (an overflow aborts the process).
    #[test]
    #[ignore = "measurement"]
    fn stack_probe() {
        let size: usize = std::env::var("BONELI_ARCH_STACK")
            .expect("size")
            .parse()
            .expect("number");
        std::thread::Builder::new()
            .stack_size(size)
            .spawn(|| workload(std::env::var("BONELI_ARCH_STACK_OP").ok().as_deref()))
            .expect("spawn")
            .join()
            .expect("no panic");
    }

    #[test]
    fn panic_in_check_is_tool_error() {
        let outcome = guarded(|| -> Result<Report, ToolError> { panic!("boom") });
        let mut out = Vec::new();
        assert_eq!(emit(&outcome, &mut out), 2);
        assert_eq!(
            String::from_utf8(out).expect("ASCII"),
            "FAIL [tool-error] crates/boneli-arch-check: internal error: panic: boom\n1 violation(s)\n"
        );
        let outcome = guarded(|| Err(ToolError::new("x", "y")));
        assert!(matches!(outcome, Outcome::Tool(_)));
    }
}
