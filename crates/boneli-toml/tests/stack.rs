//! The depth ceiling fits the gate thread (ADR-011, D6): every route that
//! nests, at depth `MAX_DEPTH`, is parsed, cloned, compared, formatted and
//! dropped on a thread of `GATE` bytes, and one level more is `TooDeep`.
//!
//! Its own test binary: a stack overflow aborts the whole process instead
//! of failing one test.

mod common;

use std::fmt::{self, Write as _};

use boneli_toml::{ErrorKind, Limits, MAX_DEPTH, parse};
use common::depth;

/// The smallest power of two on which the deepest operation in the test
/// profile uses at most 75% (ADR-011, D6); a consumer's thread needs it too.
const GATE: usize = 256 * 1024;

/// A `fmt::Write` that only counts, so that formatting a deep value does
/// not hold its output.
struct Count(usize);

impl fmt::Write for Count {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

/// Documents whose root holds `n` nested containers, one per route: inline
/// arrays, inline tables, both alternating, a header, a dotted key, and
/// arrays of tables with a table below the last one.
fn routes(n: usize) -> Vec<(&'static str, String)> {
    let mut mixed_open = String::new();
    let mut mixed_close = String::new();
    for i in 0..n {
        if i.is_multiple_of(2) {
            mixed_open.push('[');
            mixed_close.insert(0, ']');
        } else {
            mixed_open.push_str("{b = ");
            mixed_close.insert(0, '}');
        }
    }
    let innermost = if n.is_multiple_of(2) { "1" } else { "" };
    let mut aot = String::new();
    for level in 1..=(n - 1) / 2 {
        aot.push_str(&format!("[[{}]]\n", vec!["k"; level].join(".")));
    }
    let mut path = vec!["k"; (n - 1) / 2];
    if !n.is_multiple_of(2) {
        path.push("t");
    } else {
        path.push("t.u");
    }
    aot.push_str(&format!("[{}]\n", path.join(".")));
    vec![
        ("arrays", format!("a = {}{}", "[".repeat(n), "]".repeat(n))),
        (
            "inline tables",
            format!("a = {}{{}}{}", "{b = ".repeat(n - 1), "}".repeat(n - 1)),
        ),
        (
            "alternating",
            format!("a = {mixed_open}{innermost}{mixed_close}"),
        ),
        ("header", format!("[{}]", vec!["k"; n].join("."))),
        ("dotted", format!("{} = 1", vec!["k"; n + 1].join("."))),
        ("arrays of tables", aot),
    ]
}

fn exercise(name: &str, input: &str, lim: &Limits) {
    let t = parse(input.as_bytes(), lim).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(depth(&t), MAX_DEPTH, "{name}");
    let copy = t.clone();
    assert!(copy == t);
    let mut sink = Count(0);
    write!(sink, "{t:?}").expect("debug");
    write!(sink, "{t:#?}").expect("pretty debug");
    assert!(sink.0 > 0);
    drop(copy);
    drop(t);
}

#[test]
fn ceiling_fits_the_gate_thread() {
    let worker = std::thread::Builder::new()
        .stack_size(GATE)
        .spawn(|| {
            let lim = Limits::new(1 << 20, MAX_DEPTH).expect("limits");
            for (name, input) in routes(MAX_DEPTH - 1) {
                exercise(name, &input, &lim);
            }
            for (name, input) in routes(MAX_DEPTH) {
                let e = parse(input.as_bytes(), &lim).expect_err(name);
                assert_eq!(e.kind(), ErrorKind::TooDeep, "{name}");
            }
        })
        .expect("spawn");
    worker.join().expect("worker finished");
}
