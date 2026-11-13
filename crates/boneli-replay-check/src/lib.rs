//! Two-process replay gate for the domain (ADR-002; ADR-001, decision D1).
//!
//! The binary prints a probe line with a heap and a code address, then the
//! pretty `Debug` output of every domain scenario folded through
//! [`boneli_domain::scenarios::fold`]. The integration test runs the binary
//! twice, checks that the two probes differ (address randomization is on, so
//! a leaked address would differ too), and compares the rest of both outputs
//! byte for byte with each other and with the test process's own rendering.
//! Equal output across three processes means the domain's output holds no
//! heap or code address.
//!
//! The harness cannot live in `boneli-domain`: the core token scan covers
//! every file of a core package, tests included, and bans `std`. It is a
//! test-only root, so no production crate can depend on it.
#![doc(test(attr(forbid(unsafe_code))))]

use std::fmt::Write as _;

use boneli_domain::scenarios::{Scenario, all, fold};
use boneli_domain::{
    Budget, CommitSha, DomainError, EvidenceRef, Run, RunCommand, RunEvent, RunId,
};

/// The first line of the binary's output.
pub const PROBE_PREFIX: &str = "probe ";

/// The heap and code addresses one process reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    /// Address of a fresh heap allocation.
    pub heap: usize,
    /// Address of `boneli_domain::Run::handle`.
    pub code: usize,
}

type Handle = fn(Run, RunEvent) -> Result<(Run, Vec<RunCommand>), DomainError>;

/// `probe heap=<hex> code=<hex>\n` for this process: a fresh `Box<u64>` (heap
/// randomization) and the domain's `Run::handle` (the executable's load
/// bias). Both must differ between processes, or a leak of that kind would
/// compare equal.
pub fn probe() -> String {
    let boxed = Box::new(0u64);
    let heap = (&raw const *boxed).addr();
    let code = Run::handle as Handle as usize;
    format!("{PROBE_PREFIX}heap={heap:x} code={code:x}\n")
}

fn hex(text: &str) -> Option<usize> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(text, 16).ok()
}

/// Reads a probe line (without its newline) back; `None` unless it has
/// exactly the form [`probe`] prints.
pub fn parse_probe(line: &str) -> Option<Probe> {
    let rest = line.strip_prefix(PROBE_PREFIX)?;
    let mut fields = rest.split(' ');
    let heap = hex(fields.next()?.strip_prefix("heap=")?)?;
    let code = hex(fields.next()?.strip_prefix("code=")?)?;
    if fields.next().is_some() {
        return None;
    }
    Some(Probe { heap, code })
}

/// For each scenario, in the given order: `scenario <name>`, the trace's
/// pretty `Debug`, then `display <k>: <error>` for every entry `k` whose
/// result is an error.
///
/// `Debug` is derived everywhere in `boneli-domain` except where a type has
/// a hand-written formatting impl. Those impls are rendered too, or a leak in
/// them would pass the comparison: today the only one is `DomainError`'s
/// `Display`, and `every_hand_written_fmt_impl_is_rendered` fails when the
/// domain gains another.
pub fn render_scenarios(scenarios: &[Scenario]) -> Result<String, DomainError> {
    let mut out = String::new();
    for scenario in scenarios {
        let trace = fold(scenario)?;
        // Writing to a String cannot fail.
        let _ = write!(out, "scenario {}\n{trace:#?}\n", scenario.name);
        for (k, entry) in trace.entries.iter().enumerate() {
            if let Err(error) = &entry.result {
                let _ = writeln!(out, "display {k}: {error}");
            }
        }
    }
    // The errors no trace can hold, from the real constructors.
    for error in constructor_errors() {
        let _ = writeln!(out, "display constructor: {error}\n{error:?}");
    }
    Ok(out)
}

/// The `DomainError` variants that only constructors return:
/// `Run::new` with a zero limit, `CommitSha::parse` of a malformed name and
/// `EvidenceRef::parse` of a blank reference.
fn constructor_errors() -> Vec<DomainError> {
    let id = || RunId::new(String::from("replay-check"));
    let zero_cost = Budget {
        cost_micro_usd: 0,
        duration_ms: 1,
    };
    let zero_duration = Budget {
        cost_micro_usd: 1,
        duration_ms: 0,
    };
    [
        Run::new(id(), zero_cost).err(),
        Run::new(id(), zero_duration).err(),
        CommitSha::parse("not a sha").err(),
        EvidenceRef::parse("\u{200B}").err(),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The hand-written formatting impls of `boneli-domain` that
/// [`render_scenarios`] renders, as their `impl` lines.
pub const RENDERED_FMT_IMPLS: &[&str] = &["impl fmt::Display for DomainError {"];

/// [`render_scenarios`] over the whole corpus, in [`all`] order.
pub fn render() -> Result<String, DomainError> {
    render_scenarios(&all())
}

/// The first line where `a` and `b` differ: its 1-based number and both
/// versions (`None` past the end of one of them). `None` when equal.
pub fn first_difference<'a>(
    a: &'a str,
    b: &'a str,
) -> Option<(usize, Option<&'a str>, Option<&'a str>)> {
    let mut left = a.lines();
    let mut right = b.lines();
    let mut number = 0;
    loop {
        number += 1;
        match (left.next(), right.next()) {
            (None, None) => {
                return if a == b {
                    None
                } else {
                    Some((number, None, None))
                };
            }
            (l, r) if l != r => return Some((number, l, r)),
            _ => {}
        }
    }
}
