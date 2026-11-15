//! JSONTestSuite (`tests/jsontestsuite/`, vendored at a pinned commit, see
//! its README): every `y_` file is accepted except the two duplicate-key
//! files, every `n_` file is rejected, and every `i_` file has a pinned
//! outcome (ADR-008).

mod common;

use std::collections::BTreeMap;

use boneli_json::{ErrorKind, parse};
use common::{FNV_OFFSET, corpus, corpus_with, fnv1a, harness_limits};

/// The `y_` files that are rejected because duplicate keys are (ADR-008,
/// D4; decided at STOP 1 of #29).
const REJECTED_Y: [&str; 2] = [
    "y_object_duplicated_key.json",
    "y_object_duplicated_key_and_value.json",
];

#[test]
fn corpus_is_pinned() {
    let mut totals = BTreeMap::new();
    let mut digest = FNV_OFFSET;
    for (name, bytes) in corpus() {
        let class = name.split('_').next().expect("prefix").to_owned();
        let entry = totals.entry(class).or_insert((0usize, 0usize));
        entry.0 += 1;
        entry.1 += bytes.len();
        digest = fnv1a(digest, name.as_bytes());
        digest = fnv1a(digest, &[0]);
        digest = fnv1a(digest, &(bytes.len() as u64).to_le_bytes());
        digest = fnv1a(digest, &bytes);
    }
    let expected: BTreeMap<String, (usize, usize)> = [
        ("i".to_owned(), (35, 1_562)),
        ("n".to_owned(), (188, 351_272)),
        ("y".to_owned(), (95, 1_190)),
    ]
    .into_iter()
    .collect();
    assert_eq!(totals, expected);
    assert_eq!(digest, 0xadeb_e70c_8b75_1705, "vendored bytes changed");
}

#[test]
fn y_files_accepted() {
    let limits = harness_limits();
    let mut accepted = 0;
    let mut rejected = Vec::new();
    for (name, bytes) in corpus_with("y_") {
        match parse(&bytes, &limits) {
            Ok(_) => accepted += 1,
            Err(e) => {
                assert_eq!(e.kind(), ErrorKind::DuplicateKey, "{name}: {e}");
                rejected.push(name);
            }
        }
    }
    assert_eq!(rejected, REJECTED_Y);
    assert_eq!(accepted, 93);
}

#[test]
fn n_files_rejected() {
    let limits = harness_limits();
    let mut rejected = 0;
    for (name, bytes) in corpus_with("n_") {
        let e = parse(&bytes, &limits).expect_err(&name);
        assert_ne!(e.kind(), ErrorKind::TooLarge, "{name}");
        match name.as_str() {
            "n_structure_open_array_object.json" => {
                assert_eq!((e.kind(), e.offset()), (ErrorKind::TooDeep, 1_280));
            }
            "n_structure_100000_opening_arrays.json" => {
                assert_eq!((e.kind(), e.offset()), (ErrorKind::TooDeep, 512));
            }
            _ => {}
        }
        rejected += 1;
    }
    assert_eq!(rejected, 188);
}

/// The outcome of every `i_` file: `None` for accepted, the error kind for
/// rejected.
fn i_table() -> BTreeMap<&'static str, Option<ErrorKind>> {
    use ErrorKind::{InvalidUtf8, LoneSurrogate, UnexpectedByte};
    [
        ("i_number_double_huge_neg_exp.json", None),
        ("i_number_huge_exp.json", None),
        ("i_number_neg_int_huge_exp.json", None),
        ("i_number_pos_double_huge_exp.json", None),
        ("i_number_real_neg_overflow.json", None),
        ("i_number_real_pos_overflow.json", None),
        ("i_number_real_underflow.json", None),
        ("i_number_too_big_neg_int.json", None),
        ("i_number_too_big_pos_int.json", None),
        ("i_number_very_big_negative_int.json", None),
        ("i_object_key_lone_2nd_surrogate.json", Some(LoneSurrogate)),
        (
            "i_string_1st_surrogate_but_2nd_missing.json",
            Some(LoneSurrogate),
        ),
        (
            "i_string_1st_valid_surrogate_2nd_invalid.json",
            Some(LoneSurrogate),
        ),
        ("i_string_UTF-16LE_with_BOM.json", Some(InvalidUtf8)),
        ("i_string_UTF-8_invalid_sequence.json", Some(InvalidUtf8)),
        ("i_string_UTF8_surrogate_U+D800.json", Some(InvalidUtf8)),
        (
            "i_string_incomplete_surrogate_and_escape_valid.json",
            Some(LoneSurrogate),
        ),
        (
            "i_string_incomplete_surrogate_pair.json",
            Some(LoneSurrogate),
        ),
        (
            "i_string_incomplete_surrogates_escape_valid.json",
            Some(LoneSurrogate),
        ),
        (
            "i_string_invalid_lonely_surrogate.json",
            Some(LoneSurrogate),
        ),
        ("i_string_invalid_surrogate.json", Some(LoneSurrogate)),
        ("i_string_invalid_utf-8.json", Some(InvalidUtf8)),
        (
            "i_string_inverted_surrogates_U+1D11E.json",
            Some(LoneSurrogate),
        ),
        ("i_string_iso_latin_1.json", Some(InvalidUtf8)),
        ("i_string_lone_second_surrogate.json", Some(LoneSurrogate)),
        (
            "i_string_lone_utf8_continuation_byte.json",
            Some(InvalidUtf8),
        ),
        ("i_string_not_in_unicode_range.json", Some(InvalidUtf8)),
        ("i_string_overlong_sequence_2_bytes.json", Some(InvalidUtf8)),
        ("i_string_overlong_sequence_6_bytes.json", Some(InvalidUtf8)),
        (
            "i_string_overlong_sequence_6_bytes_null.json",
            Some(InvalidUtf8),
        ),
        ("i_string_truncated-utf-8.json", Some(InvalidUtf8)),
        ("i_string_utf16BE_no_BOM.json", Some(InvalidUtf8)),
        ("i_string_utf16LE_no_BOM.json", Some(InvalidUtf8)),
        ("i_structure_500_nested_arrays.json", None),
        (
            "i_structure_UTF-8_BOM_empty_object.json",
            Some(UnexpectedByte),
        ),
    ]
    .into_iter()
    .collect()
}

#[test]
fn i_files_pinned() {
    let limits = harness_limits();
    let table = i_table();
    assert_eq!(table.len(), 35);
    let files = corpus_with("i_");
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    let listed: Vec<&str> = table.keys().copied().collect();
    let mut sorted_names = names.clone();
    sorted_names.sort_unstable();
    assert_eq!(sorted_names, listed, "table and corpus differ");

    let mut accepted = 0;
    for (name, bytes) in &files {
        let outcome = parse(bytes, &limits);
        match table[name.as_str()] {
            None => {
                outcome.as_ref().expect(name);
                accepted += 1;
            }
            Some(kind) => {
                let e = outcome.as_ref().expect_err(name);
                assert_eq!(e.kind(), kind, "{name}");
                if name == "i_structure_UTF-8_BOM_empty_object.json" {
                    assert_eq!(e.offset(), 0);
                }
            }
        }
    }
    assert_eq!(accepted, 11);

    let number = |name: &str| {
        let (_, bytes) = files
            .iter()
            .find(|(n, _)| n == name)
            .expect("file in corpus");
        let value = parse(bytes, &limits).expect(name);
        value.as_array().expect("array")[0]
            .as_number()
            .expect("number")
            .clone()
    };
    let too_big = number("i_number_too_big_pos_int.json");
    assert_eq!((too_big.as_u64(), too_big.as_i64()), (None, None));
    assert!(too_big.as_f64().is_some_and(f64::is_finite));
    let too_small = number("i_number_too_big_neg_int.json");
    assert_eq!((too_small.as_u64(), too_small.as_i64()), (None, None));
    assert_eq!(number("i_number_real_pos_overflow.json").as_f64(), None);
    assert_eq!(number("i_number_real_neg_overflow.json").as_f64(), None);
    assert_eq!(number("i_number_real_underflow.json").as_f64(), Some(0.0));
    assert_eq!(number("i_number_huge_exp.json").as_f64(), None);
    assert_eq!(
        number("i_number_double_huge_neg_exp.json").as_f64(),
        Some(0.0)
    );
}
