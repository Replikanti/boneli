//! The depth ceiling fits half of a default thread stack (ADR-008, D6).
//!
//! Its own test binary: a stack overflow aborts the whole process instead
//! of failing one test.

mod common;

use std::fmt::{self, Write as _};

use boneli_json::{ErrorKind, Limits, MAX_DEPTH, parse, to_vec};
use common::{built_arrays, built_objects, nested_arrays, nested_objects};

/// Half of the 2 MiB that std gives a spawned thread by default; the other
/// half belongs to the frames below and above the JSON code (ADR-008, D6).
const BUDGET: usize = 1 << 20;

/// A `fmt::Write` that only counts, so that formatting a deep value does
/// not hold its output.
struct Count(usize);

impl fmt::Write for Count {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0 += s.len();
        Ok(())
    }
}

fn exercise(input: &[u8], lim: &Limits) {
    let v = parse(input, lim).expect("depth 512 parses");
    let bytes = to_vec(&v).expect("depth 512 serializes");
    assert_eq!(bytes, input);
    let copy = v.clone();
    assert!(copy == v);
    let mut sink = Count(0);
    write!(sink, "{v:?}").expect("debug");
    write!(sink, "{v:#?}").expect("pretty debug");
    assert!(sink.0 > input.len());
    drop(copy);
    drop(v);
}

#[test]
fn ceiling_fits_half_default_stack() {
    let worker = std::thread::Builder::new()
        .stack_size(BUDGET)
        .spawn(|| {
            let lim = Limits::new(1 << 20, MAX_DEPTH, 1 << 20).expect("limits");
            exercise(&nested_arrays(MAX_DEPTH), &lim);
            exercise(&nested_objects(MAX_DEPTH), &lim);
            for input in [nested_arrays(MAX_DEPTH + 1), nested_objects(MAX_DEPTH + 1)] {
                let e = parse(&input, &lim).expect_err("depth 513");
                assert_eq!(e.kind(), ErrorKind::TooDeep);
            }
            for v in [built_arrays(MAX_DEPTH + 1), built_objects(MAX_DEPTH + 1)] {
                assert_eq!(
                    to_vec(&v).expect_err("depth 513").kind(),
                    ErrorKind::TooDeep
                );
            }
        })
        .expect("spawn");
    worker.join().expect("worker finished");
}
