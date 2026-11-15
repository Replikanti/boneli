//! A deterministic mutation sweep over the JSONTestSuite files in place of
//! a fuzzer (ADR-008): no mutant panics, and every mutant that parses
//! respects the limits and round-trips.

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use boneli_json::{Limits, parse, to_vec};
use common::{corpus, harness_limits, limits, shape};

/// Bytes the replacements and insertions use: NUL, the four whitespace
/// bytes, a quote, a comma, a minus, a digit, a colon, the brackets and
/// braces, a backslash and a byte that is never valid UTF-8.
const BYTES: [u8; 16] = [
    0x00, 0x09, 0x0a, 0x0d, 0x20, 0x22, 0x2c, 0x2d, 0x30, 0x3a, 0x5b, 0x5c, 0x5d, 0x7b, 0x7d, 0xff,
];

/// Every file is cut to this many bytes. Only the two deep `n_` files are
/// longer, and both are rejected before byte 2,048 (at offsets 1,280 and
/// 512), so the cut drops nothing the parser reads.
const CUT: usize = 2_048;

fn check(input: &[u8], lim: &Limits, file: &str, op: &str, at: usize, byte: u8) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if let Ok(v) = parse(input, lim) {
            let (depth, values) = shape(&v);
            assert!(depth <= lim.max_depth(), "depth {depth}");
            assert!(values <= lim.max_values(), "{values} values");
            let bytes = to_vec(&v).expect("a parsed value serializes");
            let back = parse(&bytes, &harness_limits()).expect("serialized output parses");
            assert_eq!(back, v);
            assert_eq!(to_vec(&back).expect("serializes"), bytes);
        }
    }));
    assert!(
        outcome.is_ok(),
        "panic: file {file}, {op} at {at}, byte {byte:#04x}, limits {lim:?}"
    );
}

#[test]
fn mutation_sweep_never_panics() {
    let started = Instant::now();
    let sets = [harness_limits(), limits(64, 4, 16)];
    let mut mutants = 0usize;
    let mut cut_bytes = 0usize;
    let files = corpus();
    for (name, full) in &files {
        let original = &full[..full.len().min(CUT)];
        cut_bytes += original.len();
        let len = original.len();
        let mut run = |input: &[u8], op: &str, at: usize, byte: u8| {
            for lim in &sets {
                check(input, lim, name, op, at, byte);
            }
            mutants += 1;
        };
        for at in 0..len {
            run(&original[..at], "truncate", at, 0);
            let mut deleted = original.to_vec();
            deleted.remove(at);
            run(&deleted, "delete", at, 0);
            for byte in BYTES {
                let mut replaced = original.to_vec();
                replaced[at] = byte;
                run(&replaced, "replace", at, byte);
            }
            for mask in [0x01u8, 0x20, 0x80] {
                let mut flipped = original.to_vec();
                flipped[at] ^= mask;
                run(&flipped, "flip", at, mask);
            }
        }
        for at in 0..=len {
            for byte in BYTES {
                let mut inserted = original.to_vec();
                inserted.insert(at, byte);
                run(&inserted, "insert", at, byte);
            }
        }
    }
    assert_eq!(files.len(), 318);
    assert_eq!(cut_bytes, 8_119);
    assert_eq!(mutants, 8_119 * 21 + 16 * (8_119 + 318));
    assert_eq!(mutants, 305_491);
    eprintln!(
        "mutation sweep: {mutants} mutants, {} parses, {:?}",
        mutants * sets.len(),
        started.elapsed()
    );
}
