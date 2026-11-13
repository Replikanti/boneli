//! The address-leak gate for `boneli-domain` and `boneli-app` (ADR-001
//! decision D1, ADR-002, ADR-004).

use std::process::Command;

use boneli_domain::scenarios::all;
use boneli_replay_check::{
    Probe, RENDERED_APP_FMT_IMPLS, RENDERED_FMT_IMPLS, app, first_difference, mutants, parse_probe,
    render,
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
    let app_scenarios = app::scenarios();
    let app_names: Vec<&str> = app_scenarios.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        app_headers, app_names,
        "the harness skipped or reordered app scenarios"
    );
    // Every contract mutant's violation is rendered and compared too
    // (ADR-004, D10).
    let mutant_headers = out_a.lines().filter(|l| l.starts_with("mutant ")).count();
    assert_eq!(mutant_headers, mutants::mutants().len());
    assert_eq!(
        out_a
            .lines()
            .filter(|l| l.starts_with("blank-status "))
            .count(),
        3
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

/// The tokens of Rust source that the tripwire needs: identifiers and the
/// punctuation `; { } : # [ ] ( )`. Comments (nested block comments too),
/// string, byte-string, raw-string and character literals are removed, so
/// text inside them can neither hide code nor end the scan early.
fn tokens(code: &str) -> Vec<String> {
    let chars: Vec<char> = code.chars().collect();
    let mut out = Vec::new();
    let mut k = 0;
    while k < chars.len() {
        let c = chars[k];
        let next = chars.get(k + 1).copied();
        if c == '/' && next == Some('/') {
            while k < chars.len() && chars[k] != '\n' {
                k += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0usize;
            while k < chars.len() {
                if chars[k] == '/' && chars.get(k + 1) == Some(&'*') {
                    depth += 1;
                    k += 2;
                } else if chars[k] == '*' && chars.get(k + 1) == Some(&'/') {
                    depth -= 1;
                    k += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    k += 1;
                }
            }
        } else if let Some(end) = raw_string_end(&chars, k) {
            k = end;
        } else if c == '"' {
            k = quoted_end(&chars, k, '"');
        } else if c == '\'' {
            // A character literal, or the quote of a lifetime or label.
            if next == Some('\\') {
                k = quoted_end(&chars, k, '\'');
            } else if chars.get(k + 2) == Some(&'\'') {
                k += 3;
            } else {
                k += 1;
            }
        } else if c.is_alphabetic() || c == '_' {
            let start = k;
            while k < chars.len() && (chars[k].is_alphanumeric() || chars[k] == '_') {
                k += 1;
            }
            out.push(chars[start..k].iter().collect());
        } else {
            if matches!(c, ';' | '{' | '}' | ':' | '#' | '[' | ']' | '(' | ')') {
                out.push(c.to_string());
            }
            k += 1;
        }
    }
    out
}

/// The end of the quoted literal that opens at `k`, honouring escapes.
fn quoted_end(chars: &[char], k: usize, quote: char) -> usize {
    let mut j = k + 1;
    while j < chars.len() && chars[j] != quote {
        j += if chars[j] == '\\' { 2 } else { 1 };
    }
    j + 1
}

/// The end of the raw string literal (`r"…"`, `r#"…"#`, `br#"…"#`) that
/// opens at `k`, if one opens there. `r#name` is a raw identifier, not a
/// literal, and yields `None`.
fn raw_string_end(chars: &[char], k: usize) -> Option<usize> {
    let mut j = k;
    if chars.get(j) == Some(&'b') {
        j += 1;
    }
    if chars.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let hashes = chars[j..].iter().take_while(|c| **c == '#').count();
    j += hashes;
    if chars.get(j) != Some(&'"') {
        return None;
    }
    j += 1;
    while j < chars.len() {
        let closes = chars[j] == '"'
            && chars
                .get(j + 1..j + 1 + hashes)
                .is_some_and(|tail| tail.iter().all(|c| *c == '#'));
        if closes {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    Some(chars.len())
}

/// The tokens with every item under a `#[cfg(test)]` attribute removed: the
/// attribute, then the item through its first `;` or its first balanced
/// `{ … }` block, whichever comes first. A skip never runs past the item it
/// belongs to, so library code after a test module is still scanned; a
/// skip that stops early only scans more.
fn without_test_items(tokens: &[String]) -> Vec<String> {
    const ATTRIBUTE: [&str; 7] = ["#", "[", "cfg", "(", "test", ")", "]"];
    let mut kept = Vec::new();
    let mut k = 0;
    while k < tokens.len() {
        let attribute = tokens
            .get(k..k + ATTRIBUTE.len())
            .is_some_and(|window| window.iter().zip(ATTRIBUTE).all(|(t, a)| t == a));
        if !attribute {
            kept.push(tokens[k].clone());
            k += 1;
            continue;
        }
        k += ATTRIBUTE.len();
        while k < tokens.len() && tokens[k] != ";" && tokens[k] != "{" {
            k += 1;
        }
        if tokens.get(k).map(String::as_str) == Some("{") {
            let mut depth = 0usize;
            while k < tokens.len() {
                match tokens[k].as_str() {
                    "{" => depth += 1,
                    "}" => depth -= 1,
                    _ => {}
                }
                k += 1;
                if depth == 0 {
                    break;
                }
            }
        } else {
            k += 1;
        }
    }
    kept
}

/// The tripwire must see through comments, literals and renames, and must
/// not stop at text that only looks like a test attribute.
#[test]
fn tripwire_tokens_are_not_fooled() {
    let flagged = |code: &str| {
        without_test_items(&tokens(code))
            .iter()
            .any(|t| t == "contract" || t == "Violation")
    };
    let bypasses = [
        // Review round 3 (N4): the attribute text inside a comment.
        "// #[cfg(test)]\nuse crate::{contract as suites};",
        "/* #[cfg(test)] */ use crate::{contract as suites};",
        "/* /* nested */ #[cfg(test)] */ use crate::contract;",
        // Review round 2: a brace group with a rename.
        "use crate::{contract as suites};",
        // A quote in a character literal must not open a string.
        "const Q: char = '\"'; use crate::contract; const E: &str = \"\";",
        // Raw strings that contain quotes or the attribute text.
        "const R: &str = r#\"\" #[cfg(test)]\"#; use crate::contract;",
        "const B: &[u8] = br\"#[cfg(test)]\"; use crate::contract;",
        // A raw identifier and a macro argument.
        "use crate::r#contract;",
        "m!(contract);",
        // Library code after a test module is still library code.
        "#[cfg(test)] mod t { use crate::contract; }\nfn f() -> Violation { todo!() }",
        "#[cfg(test)] use x::{y};\nuse crate::contract;",
    ];
    for code in bypasses {
        assert!(flagged(code), "not flagged: {code}");
    }
    let clean = [
        "#[cfg(test)] mod tests { use boneli_app::contract; }",
        "#[cfg(test)] use crate::contract;",
        "/// Runs the contract suites.\nfn f<'a>(x: &'a str) -> char { 'c' }",
        "const S: &str = \"contract Violation\";",
    ];
    for code in clean {
        assert!(!flagged(code), "flagged: {code}");
    }
}

/// Tripwire behind ADR-004 D10: outside the `contract` module and outside
/// items under `#[cfg(test)]`, no source of `boneli-domain`, `boneli-app`
/// or `boneli-memory` has the identifier `contract` or `Violation` anywhere: not in a `use`
/// tree, a path, a rename, a raw identifier or a macro argument. Comments
/// and literals are removed first (`tokens`), and only a real attribute
/// removes test code (`without_test_items`). The gate for what violation
/// text holds is the replay of every mutant's violation, not this scan.
#[test]
fn contract_suites_stay_out_of_library_code() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut scanned = 0;
    // The domain is scanned too: a `macro_rules!` there could emit the
    // path in a use case, and core, alloc and std are the only other
    // macro sources these crates see.
    for krate in ["boneli-domain", "boneli-app", "boneli-memory"] {
        for file in std::fs::read_dir(root.join(krate).join("src")).expect("sources") {
            let path = file.expect("a directory entry").path();
            let name = path
                .file_name()
                .expect("a file name")
                .to_string_lossy()
                .into_owned();
            if krate == "boneli-app" && name == "contract.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("UTF-8 source");
            let words = without_test_items(&tokens(&text));
            scanned += 1;
            for (k, word) in words.iter().enumerate() {
                let named = word == "Violation" || word == "contract";
                let declaration = krate == "boneli-app"
                    && name == "lib.rs"
                    && word == "contract"
                    && k > 1
                    && words[k - 1] == "mod"
                    && words[k - 2] == "pub";
                assert!(
                    !named || declaration,
                    "{krate}/{name} names the contract suites outside tests"
                );
            }
        }
    }
    assert!(scanned >= 26, "too few sources scanned: {scanned}");
}
