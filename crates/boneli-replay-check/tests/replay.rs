//! The address-leak gate for `boneli-domain` and `boneli-app` (ADR-001
//! decision D1, ADR-002, ADR-004).

use std::process::Command;

use boneli_domain::scenarios::all;
use boneli_replay_check::{
    Probe, RENDERED_APP_FMT_IMPLS, RENDERED_FMT_IMPLS, app, first_difference, parse_probe, render,
};

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
    let app_headers: Vec<&str> = out_a
        .lines()
        .filter_map(|line| line.strip_prefix("app-scenario "))
        .collect();
    let app_names: Vec<&str> = app::scenarios().iter().map(|s| s.name).collect();
    assert_eq!(
        app_headers, app_names,
        "the harness skipped or reordered app scenarios"
    );
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

/// Tripwire: every hand-written formatting impl in `boneli-domain` and
/// `boneli-app` must be rendered by the harness, because the replay compares only what it prints.
///
/// It counts `fn fmt` definitions, not trait names: every formatting trait
/// names its method `fmt`, so a renamed import (`use core::fmt::Display as
/// Show;`) cannot hide one. Whitespace is ignored, so `fn` and `fmt` on
/// separate lines still count, and so does a raw `r#fmt`. A `macro_rules!`
/// could build the name from a fragment, so any macro definition fails too.
/// Each definition is listed by file and the `impl` line above it; a new one
/// fails until the harness prints it and `RENDERED_FMT_IMPLS` (domain) or
/// `RENDERED_APP_FMT_IMPLS` (app) lists it.
#[test]
fn every_hand_written_fmt_impl_is_rendered() {
    assert_eq!(
        hand_written_fmt_impls("boneli-domain", 9),
        RENDERED_FMT_IMPLS,
        "a hand-written formatting impl in boneli-domain is not rendered by the replay \
         harness: print it in render_scenarios and list it in RENDERED_FMT_IMPLS"
    );
    assert_eq!(
        hand_written_fmt_impls("boneli-app", 11),
        RENDERED_APP_FMT_IMPLS,
        "a hand-written formatting impl in boneli-app is not rendered by the replay \
         harness: print it in app::render_app_errors and list it in RENDERED_APP_FMT_IMPLS"
    );
}

/// The core sources the tripwire reads, sorted; at least `min_files`.
fn core_sources(krate: &str, min_files: usize) -> Vec<std::path::PathBuf> {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(krate)
        .join("src");
    let mut files: Vec<_> = std::fs::read_dir(&src)
        .expect("the core sources are readable")
        .map(|entry| entry.expect("a directory entry").path())
        .collect();
    files.sort();
    assert!(
        files.len() >= min_files,
        "{krate} sources not found in {}",
        src.display()
    );
    files
}

/// `read_dir` does not recurse, so a module in a subdirectory would be
/// invisible to the tripwire: the core sources stay flat.
#[test]
fn app_sources_are_flat() {
    for (krate, min_files) in [("boneli-domain", 9), ("boneli-app", 11)] {
        for file in core_sources(krate, min_files) {
            assert!(
                file.is_file(),
                "{} is not a plain file; the replay tripwire reads only the top level",
                file.display()
            );
        }
    }
}

/// Every `fn fmt` definition in a core crate, as its file and the `impl`
/// line above it.
fn hand_written_fmt_impls(krate: &str, min_files: usize) -> Vec<String> {
    const DEFINITIONS: [&str; 3] = ["fnfmt(", "fnfmt<", "fnr#fmt"];
    let files = core_sources(krate, min_files);
    let compact = |text: &str| -> String { text.chars().filter(|c| !c.is_whitespace()).collect() };
    let mut found = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a core source is UTF-8");
        let name = file
            .file_name()
            .expect("a file name")
            .to_string_lossy()
            .into_owned();
        let whole = compact(&text);
        let total: usize = DEFINITIONS.iter().map(|d| whole.matches(d).count()).sum();
        let mut on_lines = 0;
        let mut last_impl = "<no impl line above>";
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("impl ") || trimmed.starts_with("impl<") {
                last_impl = trimmed;
            }
            let line_compact = compact(line);
            let here: usize = DEFINITIONS
                .iter()
                .map(|d| line_compact.matches(d).count())
                .sum();
            for _ in 0..here {
                found.push(format!("{name}: {last_impl}"));
            }
            on_lines += here;
        }
        // A definition split across lines is seen only in the whole text.
        for _ in on_lines..total {
            found.push(format!("{name}: fn fmt split across lines"));
        }
        if whole.contains("macro_rules!") {
            found.push(format!("{name}: macro_rules! (can define fn fmt)"));
        }
    }
    found
}
