//! toml-test (`tests/toml-test/`, the TOML 1.0.0 file list vendored at a
//! pinned commit, see its README): every file has a pinned outcome, a
//! valid file is accepted with the expected value or fails with
//! `Unsupported`, and no invalid file is accepted (ADR-011, D9).

mod common;

use std::collections::BTreeMap;

use boneli_toml::{ErrorKind, parse};
use common::{
    FNV_OFFSET, corpus_dir, corpus_toml, files_below, fnv1a, harness_limits, listed_files, tagged,
    tagged_eq,
};

/// Files next to the corpus that are not part of upstream's list.
const OWN_FILES: [&str; 3] = ["LICENSE", "README.md", "files-toml-1.0.0"];

#[test]
fn corpus_is_pinned() {
    let mut listed = listed_files();
    listed.sort();
    let on_disk: Vec<String> = files_below(&corpus_dir())
        .into_iter()
        .filter(|name| !OWN_FILES.contains(&name.as_str()))
        .collect();
    assert_eq!(
        on_disk, listed,
        "the vendored files are exactly upstream's list"
    );

    let mut totals = BTreeMap::new();
    let mut bytes_total = 0;
    let mut digest = FNV_OFFSET;
    for name in &listed {
        let bytes = std::fs::read(corpus_dir().join(name)).expect("corpus file");
        let class = match (name.starts_with("valid/"), name.ends_with(".toml")) {
            (true, true) => "valid toml",
            (true, false) => "valid json",
            (false, _) => "invalid toml",
        };
        *totals.entry(class).or_insert(0usize) += 1;
        bytes_total += bytes.len();
        digest = fnv1a(digest, name.as_bytes());
        digest = fnv1a(digest, &[0]);
        digest = fnv1a(digest, &(bytes.len() as u64).to_le_bytes());
        digest = fnv1a(digest, &bytes);
    }
    let expected: BTreeMap<&str, usize> = [
        ("valid toml", 208),
        ("valid json", 208),
        ("invalid toml", 509),
    ]
    .into_iter()
    .collect();
    assert_eq!(totals, expected);
    assert_eq!(bytes_total, 103_336);
    assert_eq!(digest, 0x7642_9c6f_74dc_945b, "vendored bytes changed");
}

/// The outcome of one corpus file: `ok`, `unsupported:<feature>` or
/// `error:<kind>`.
fn outcome(name: &str, bytes: &[u8]) -> String {
    match parse(bytes, &harness_limits()) {
        Ok(table) => {
            if name.starts_with("valid/") {
                let json_name = format!("{}.json", name.trim_end_matches(".toml"));
                let json = std::fs::read(corpus_dir().join(&json_name)).expect("expected JSON");
                let lim = boneli_json::Limits::new(1 << 20, 512, 1 << 20).expect("limits");
                let expected = boneli_json::parse(&json, &lim).expect("expected JSON parses");
                let got = tagged(&table);
                assert!(
                    tagged_eq(&got, &expected),
                    "{name}: value differs\n got {}\nwant {}",
                    boneli_json::to_string(&got).expect("serializes"),
                    String::from_utf8_lossy(&json)
                );
            }
            "ok".to_owned()
        }
        Err(e) => match e.kind() {
            ErrorKind::Unsupported(feature) => format!("unsupported:{feature:?}"),
            kind => format!("error:{kind:?}"),
        },
    }
}

#[test]
fn outcomes_are_pinned() {
    let mut computed = String::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (name, bytes) in corpus_toml() {
        let got = outcome(&name, &bytes);
        let class = name.split('/').next().expect("class").to_owned();
        let summary = got.split(':').next().expect("outcome").to_owned();
        *counts.entry(format!("{class} {summary}")).or_insert(0) += 1;
        if class == "valid" {
            assert!(!got.starts_with("error:"), "{name}: {got}");
        } else {
            assert_ne!(got, "ok", "{name} is invalid TOML and was accepted");
            assert!(
                !got.contains("TooLarge") && !got.contains("TooDeep"),
                "{name}: {got}"
            );
        }
        computed.push_str(&format!("{name} {got}\n"));
    }
    let pinned = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/toml_test_outcomes.txt"),
    )
    .unwrap_or_default();
    if pinned != computed {
        eprintln!("computed outcomes:\n{computed}");
        panic!("outcomes differ from tests/toml_test_outcomes.txt; counts {counts:?}");
    }
    eprintln!("{counts:?}");
}
