//! The three limits and their bounds: every limit is inclusive, and every
//! violation is an error at a pinned offset (ADR-008, D5 and D6).

mod common;

use boneli_json::{ErrorKind, Limits, MAX_DEPTH, Value, parse};
use common::{corpus_with, limits};

fn kind_at(input: &[u8], lim: &Limits) -> (ErrorKind, usize) {
    let e = parse(input, lim).expect_err("rejected");
    (e.kind(), e.offset())
}

#[test]
fn limits_new_rejects_zero_and_above_ceiling() {
    for (bytes, depth, values) in [(0, 1, 1), (1, 0, 1), (1, 1, 0), (0, 0, 0)] {
        let e = Limits::new(bytes, depth, values).expect_err("zero");
        assert_eq!(e.kind(), ErrorKind::InvalidLimit);
    }
    let e = Limits::new(1, MAX_DEPTH + 1, 1).expect_err("above the ceiling");
    assert_eq!(e.kind(), ErrorKind::InvalidLimit);
    assert_eq!(MAX_DEPTH, 512);
    let lim = Limits::new(usize::MAX, MAX_DEPTH, usize::MAX).expect("at the ceiling");
    assert_eq!(
        (lim.max_bytes(), lim.max_depth(), lim.max_values()),
        (usize::MAX, 512, usize::MAX)
    );
}

#[test]
fn max_bytes_inclusive() {
    let lim = limits(8, 4, 16);
    assert_eq!(
        parse(b"[1,2,33]", &lim)
            .expect("8 bytes")
            .as_array()
            .map(<[Value]>::len),
        Some(3)
    );
    assert_eq!(kind_at(b"[1,2,333]", &lim), (ErrorKind::TooLarge, 8));
    // The size check runs before the UTF-8 check and before any parsing.
    assert_eq!(
        kind_at(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff", &lim),
        (ErrorKind::TooLarge, 8)
    );
    assert_eq!(kind_at(b"[1,2,33]\xff", &lim), (ErrorKind::TooLarge, 8));
    assert_eq!(kind_at(b"\xff", &lim), (ErrorKind::InvalidUtf8, 0));
    assert_eq!(kind_at(b"        1", &lim), (ErrorKind::TooLarge, 8));
    let one = limits(1, 1, 1);
    assert_eq!(parse(b"1", &one).expect("1 byte"), Value::from(1i64));
    assert_eq!(kind_at(b"12", &one), (ErrorKind::TooLarge, 1));
}

#[test]
fn max_depth_inclusive_arrays_and_objects() {
    let lim = limits(64, 2, 64);
    for input in [
        &b"[[]]"[..],
        b"[{}]",
        b"{\"a\":{}}",
        b"[[1],[2]]",
        b"{\"a\":[1]}",
    ] {
        parse(input, &lim).expect("depth 2");
    }
    assert_eq!(kind_at(b"[[[]]]", &lim), (ErrorKind::TooDeep, 2));
    assert_eq!(kind_at(b"{\"a\":[{}]}", &lim), (ErrorKind::TooDeep, 6));
    assert_eq!(kind_at(b"[[], [[]]]", &lim), (ErrorKind::TooDeep, 6));
    // The check runs before the parser descends, so what follows the
    // offending bracket is never read.
    assert_eq!(kind_at(b"[[[\xff", &lim), (ErrorKind::InvalidUtf8, 3));
    assert_eq!(kind_at(b"[[[x", &lim), (ErrorKind::TooDeep, 2));
    let flat = limits(64, 1, 64);
    parse(b"[1,2]", &flat).expect("depth 1");
    assert_eq!(kind_at(b"[[]]", &flat), (ErrorKind::TooDeep, 1));
    assert_eq!(kind_at(b"{\"a\":{}}", &flat), (ErrorKind::TooDeep, 5));
}

#[test]
fn suite_500_nested_boundary() {
    let files = corpus_with("i_structure_500_nested_arrays");
    let (_, bytes) = files.first().expect("suite file");
    assert_eq!(bytes.len(), 1_000);
    assert_eq!(
        kind_at(bytes, &limits(1_000, 499, 1_000)),
        (ErrorKind::TooDeep, 499)
    );
    parse(bytes, &limits(1_000, 500, 500)).expect("depth 500");
    assert_eq!(
        kind_at(bytes, &limits(1_000, 500, 499)),
        (ErrorKind::TooManyValues, 499)
    );
}

#[test]
fn max_values_inclusive() {
    let lim = limits(64, 4, 3);
    parse(b"[1,2]", &lim).expect("3 values");
    assert_eq!(kind_at(b"[1,2,3]", &lim), (ErrorKind::TooManyValues, 5));
    parse(b"{\"a\":1}", &limits(64, 4, 2)).expect("2 values");
    assert_eq!(
        kind_at(b"{\"a\":1,\"b\":2}", &limits(64, 4, 2)),
        (ErrorKind::TooManyValues, 11)
    );
    parse(b"[[],{}]", &lim).expect("3 values");
    assert_eq!(
        kind_at(b"[[],{},\"\"]", &lim),
        (ErrorKind::TooManyValues, 7)
    );
    let single = limits(64, 4, 1);
    parse(b"\"x\"", &single).expect("1 value");
    parse(b"[]", &single).expect("1 value");
    assert_eq!(kind_at(b"[0]", &single), (ErrorKind::TooManyValues, 1));
}
