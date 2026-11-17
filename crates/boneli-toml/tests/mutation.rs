//! A deterministic mutation sweep in place of a fuzzer (ADR-011, D10): the
//! toml-test files and the workspace's own manifests and policies are
//! truncated, cut, overwritten, extended and bit-flipped at up to `CAP`
//! offsets each. No mutant panics, every error offset lies inside the
//! input, and every mutant that parses respects the depth limit and
//! round-trips through the test writer.

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::Instant;

use boneli_toml::{Limits, parse};
use common::{corpus_toml, depth, harness_limits, limits, styles, write};

/// The bytes the replacements and insertions use: the delimiters of every
/// TOML construct, the newline and the escape character.
const BYTES: [u8; 12] = *b"\"'[]{}=.,#\n\\";

/// Offsets per seed; a longer seed is sampled with a fixed stride.
const CAP: usize = 128;

/// The workspace files the sweep starts from besides the corpus: the
/// manifests and the two policy files, the inputs the Rust architecture
/// checker of #35 will read.
fn workspace_seeds() -> Vec<(String, Vec<u8>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut names = vec![
        "Cargo.toml".to_owned(),
        "deny.toml".to_owned(),
        "tools/architecture.toml".to_owned(),
    ];
    for entry in std::fs::read_dir(root.join("crates")).expect("crates") {
        let entry = entry.expect("entry");
        let name = entry.file_name().into_string().expect("UTF-8 name");
        if entry.path().join("Cargo.toml").is_file() {
            names.push(format!("crates/{name}/Cargo.toml"));
        }
    }
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let bytes = std::fs::read(root.join(&name)).expect("seed");
            (name, bytes)
        })
        .collect()
}

/// Parses `input` under the harness limits and the tight ones. A value
/// the tight limits accept is the harness value, since limits only
/// reject, so only the harness value is written back and parsed again.
fn check(input: &[u8], tight: &Limits, seed: &str, op: &str, at: usize, style: usize) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let full = parse(input, &harness_limits());
        match &full {
            Ok(t) => {
                let style = styles()[style];
                let text = write(t, style);
                let back =
                    parse(text.as_bytes(), &harness_limits()).expect("written output parses");
                assert!(back == *t, "{style:?} changed the value");
            }
            Err(e) => assert!(
                e.offset() <= input.len(),
                "offset {} of {}",
                e.offset(),
                input.len()
            ),
        }
        match parse(input, tight) {
            Ok(t) => {
                assert!(depth(&t) <= tight.max_depth(), "depth {}", depth(&t));
                assert!(
                    full.as_ref().is_ok_and(|f| *f == t),
                    "the limits changed the value"
                );
            }
            Err(e) => assert!(
                e.offset() <= input.len(),
                "offset {} of {}",
                e.offset(),
                input.len()
            ),
        }
    }));
    assert!(outcome.is_ok(), "panic: seed {seed}, {op} at {at}");
}

#[test]
fn mutation_sweep_never_panics() {
    let started = Instant::now();
    let tight = limits(64, 3);
    let corpus = corpus_toml();
    let workspace = workspace_seeds();
    let corpus_seeds = corpus.len();
    let corpus_bytes: usize = corpus.iter().map(|(_, b)| b.len()).sum();
    let mut offsets = 0usize;
    let mut corpus_offsets = 0usize;
    let mut mutants = 0usize;
    let styles_len = styles().len();
    for (index, (name, seed)) in corpus.iter().chain(workspace.iter()).enumerate() {
        let len = seed.len();
        let stride = len.div_ceil(CAP).max(1);
        for at in (0..len).step_by(stride) {
            offsets += 1;
            if index < corpus_seeds {
                corpus_offsets += 1;
            }
            let mut run = |input: &[u8], op: &str| {
                check(input, &tight, name, op, at, mutants % styles_len);
                mutants += 1;
            };
            run(&seed[..at], "truncate");
            let mut deleted = seed.clone();
            deleted.remove(at);
            run(&deleted, "delete");
            for byte in BYTES {
                let mut replaced = seed.clone();
                replaced[at] = byte;
                run(&replaced, "replace");
                let mut inserted = seed.clone();
                inserted.insert(at, byte);
                run(&inserted, "insert");
            }
            let mut flipped = seed.clone();
            flipped[at] ^= 1 << (at % 8);
            run(&flipped, "flip");
        }
    }
    assert_eq!(corpus_seeds, 717);
    assert_eq!(corpus_bytes, 45_191);
    assert_eq!(corpus_offsets, CORPUS_OFFSETS);
    assert!(workspace.len() >= 15, "{} workspace seeds", workspace.len());
    assert_eq!(mutants, offsets * 27);
    eprintln!(
        "mutation sweep: {} seeds, {offsets} offsets ({corpus_offsets} in the corpus), {mutants} mutants, {} parses, {:?}",
        corpus_seeds + workspace.len(),
        mutants * 2,
        started.elapsed()
    );
}

/// The corpus offsets at `CAP`, pinned so that a change to the corpus or
/// the cap shows; the workspace part grows with the workspace.
const CORPUS_OFFSETS: usize = 30_574;
