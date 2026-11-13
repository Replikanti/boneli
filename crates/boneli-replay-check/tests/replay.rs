//! The address-leak gate for `boneli-domain` (ADR-001 decision D1, ADR-002).

use std::process::Command;

use boneli_domain::scenarios::all;
use boneli_replay_check::{Probe, RENDERED_FMT_IMPLS, first_difference, parse_probe, render};

/// Runs the harness binary and returns its probe and the rest of its output.
fn run_child() -> (Probe, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_boneli-replay-check"))
        .output()
        .expect("the harness binary starts");
    assert!(
        output.status.success(),
        "the harness binary failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("the output is UTF-8");
    let (line, rest) = text.split_once('\n').expect("the output has a probe line");
    let probe = parse_probe(line).expect("the probe line is well formed");
    (probe, rest.to_owned())
}

fn assert_same(what: &str, a: &str, b: &str) {
    if let Some((line, left, right)) = first_difference(a, b) {
        panic!("{what} differ at line {line}:\n  {left:?}\n  {right:?}");
    }
}

#[test]
fn two_processes_produce_identical_debug_output() {
    let (probe_a, out_a) = run_child();
    let (probe_b, out_b) = run_child();
    assert!(
        probe_a.heap != probe_b.heap && probe_a.code != probe_b.code,
        "address randomization is off ({probe_a:?} vs {probe_b:?}): equal output would \
         prove nothing, so the replay gate fails"
    );
    assert_same("the two child outputs", &out_a, &out_b);
    let own = render().expect("every corpus budget is valid");
    assert_same("the child and the parent outputs", &out_a, &own);

    // Coverage: every scenario is rendered, in corpus order.
    let headers: Vec<&str> = out_a
        .lines()
        .filter_map(|line| line.strip_prefix("scenario "))
        .collect();
    let names: Vec<&str> = all().iter().map(|s| s.name).collect();
    assert_eq!(headers, names, "the harness skipped or reordered scenarios");
}

#[test]
fn parse_probe_rejects_malformed_lines() {
    assert_eq!(
        parse_probe("probe heap=7f00a0 code=55aa10"),
        Some(Probe {
            heap: 0x7f00a0,
            code: 0x55aa10,
        })
    );
    for line in [
        "",
        "probe",
        "probe heap=7f00a0",
        "probe code=55aa10",
        "probe heap= code=55aa10",
        "probe heap=7f00a0 code=55ag10",
        "probe heap=+7f00a0 code=55aa10",
        "probe heap=0x7f00a0 code=55aa10",
        "probe heap=7f00a0 code=55aa10 extra=1",
        "probe heap=7f00a0 code=55aa10 ",
        "probe  heap=7f00a0 code=55aa10",
        "heap=7f00a0 code=55aa10",
    ] {
        assert_eq!(parse_probe(line), None, "{line:?}");
    }
}

#[test]
fn first_difference_reports_the_line() {
    assert_eq!(first_difference("a\nb\n", "a\nb\n"), None);
    assert_eq!(
        first_difference("a\nb\n", "a\nc\n"),
        Some((2, Some("b"), Some("c")))
    );
    assert_eq!(
        first_difference("a\n", "a\nb\n"),
        Some((2, None, Some("b")))
    );
    assert_eq!(first_difference("a", "a\n"), Some((2, None, None)));
}

/// Tripwire: every hand-written formatting impl in `boneli-domain` must be
/// rendered by the harness, because the replay compares only what it prints.
/// A new `impl ... Display/Debug/...` there fails this test until
/// `render_scenarios` prints it and `RENDERED_FMT_IMPLS` lists it.
#[test]
fn every_hand_written_fmt_impl_is_rendered() {
    const TRAITS: [&str; 10] = [
        "fmt::", "Display", "Debug", "Write", "LowerHex", "UpperHex", "Binary", "Octal",
        "LowerExp", "UpperExp",
    ];
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../boneli-domain/src");
    let mut found = Vec::new();
    let mut files: Vec<_> = std::fs::read_dir(&src)
        .expect("the domain sources are readable")
        .map(|entry| entry.expect("a directory entry").path())
        .collect();
    files.sort();
    assert!(
        files.len() >= 9,
        "domain sources not found in {}",
        src.display()
    );
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a domain source is UTF-8");
        for line in text.lines() {
            let line = line.trim();
            let is_impl = line.starts_with("impl ") || line.starts_with("impl<");
            if is_impl && TRAITS.iter().any(|t| line.contains(t)) {
                found.push(line.to_owned());
            }
        }
    }
    assert_eq!(
        found, RENDERED_FMT_IMPLS,
        "render these in render_scenarios"
    );
}
