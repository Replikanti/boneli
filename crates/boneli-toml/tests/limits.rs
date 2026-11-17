//! The two limits and the depth arithmetic: both limits are inclusive, the
//! root table is depth 1 and every table or array below it adds 1, on
//! every route that creates one (ADR-011, D5 and D6).

mod common;

use boneli_toml::{ErrorKind, Limits, MAX_DEPTH, Value, parse};
use common::{depth, limits};

fn kind_at(input: &str, lim: &Limits) -> (ErrorKind, usize) {
    let e = parse(input.as_bytes(), lim).expect_err("rejected");
    (e.kind(), e.offset())
}

fn accepts(input: &str, lim: &Limits) -> bool {
    parse(input.as_bytes(), lim).is_ok()
}

#[test]
fn limits_reject_zero_and_above_ceiling() {
    for (bytes, depth) in [
        (0, 1),
        (1, 0),
        (1, MAX_DEPTH + 1),
        (0, 0),
        (usize::MAX, usize::MAX),
    ] {
        let e = Limits::new(bytes, depth).expect_err("invalid");
        assert_eq!(
            (e.kind(), e.offset()),
            (ErrorKind::InvalidLimit, 0),
            "{bytes} {depth}"
        );
    }
    assert_eq!(MAX_DEPTH, 128);
    let lim = Limits::new(1, MAX_DEPTH).expect("at the ceiling");
    assert_eq!((lim.max_bytes(), lim.max_depth()), (1, 128));
    let lim = Limits::new(usize::MAX, 1).expect("one level");
    assert_eq!((lim.max_bytes(), lim.max_depth()), (usize::MAX, 1));
}

#[test]
fn max_bytes_is_inclusive() {
    let lim = limits(5, 2);
    assert_eq!(
        parse(b"a = 1", &lim).expect("5 bytes").get("a"),
        Some(&Value::Integer(1))
    );
    assert_eq!(kind_at("a = 12", &lim), (ErrorKind::TooLarge, 5));
    // The size check runs before the UTF-8 check and before any parsing.
    let e = parse(b"\xff\xff\xff\xff\xff\xff", &lim).expect_err("too large");
    assert_eq!((e.kind(), e.offset()), (ErrorKind::TooLarge, 5));
    let e = parse(b"\xff", &lim).expect_err("invalid UTF-8");
    assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidUtf8, 0));
    assert_eq!(kind_at("      ", &lim), (ErrorKind::TooLarge, 5));
    let one = limits(1, 1);
    assert!(parse(b"\n", &one).expect("1 byte").is_empty());
    assert_eq!(kind_at("\n\n", &one), (ErrorKind::TooLarge, 1));
}

#[test]
fn depth_counts_every_route() {
    let two = limits(64, 2);
    assert!(accepts("a.b = 1", &two));
    assert_eq!(kind_at("a.b.c = 1", &two), (ErrorKind::TooDeep, 2));
    assert!(accepts("a = [1]", &two));
    assert!(accepts("a = {}", &two));
    assert!(accepts("[a]", &two));
    assert_eq!(kind_at("a = [[1]]", &two), (ErrorKind::TooDeep, 5));
    assert_eq!(kind_at("a = [{}]", &two), (ErrorKind::TooDeep, 5));
    assert_eq!(kind_at("a = {b = {}}", &two), (ErrorKind::TooDeep, 9));
    assert_eq!(kind_at("a = {b.c = 1}", &two), (ErrorKind::TooDeep, 5));
    assert_eq!(kind_at("[[t]]", &two), (ErrorKind::TooDeep, 2));
    assert_eq!(kind_at("[a.b]", &two), (ErrorKind::TooDeep, 3));
    let one = limits(64, 1);
    assert!(accepts("a = 1\nb = 'x'", &one));
    assert_eq!(kind_at("[a]", &one), (ErrorKind::TooDeep, 1));
    assert_eq!(kind_at("a = []", &one), (ErrorKind::TooDeep, 4));
    assert_eq!(kind_at("a = {}", &one), (ErrorKind::TooDeep, 4));
    assert_eq!(kind_at("a.b = 1", &one), (ErrorKind::TooDeep, 0));
    // A header through an array of tables passes the array and its last
    // element: [[a]] is 3 deep, [a.b] below it 4.
    let three = limits(64, 3);
    assert!(accepts("[[a]]", &three));
    assert_eq!(kind_at("[[a]]\n[a.b]", &three), (ErrorKind::TooDeep, 9));
    assert_eq!(kind_at("[[a]]\nb = []", &three), (ErrorKind::TooDeep, 10));
    let four = limits(64, 4);
    assert!(accepts("[[a]]\n[a.b]", &four));
}

#[test]
fn depth_adds_header_dotted_and_inline() {
    let input = "[a.b]\nc.d = [{e = 1}]";
    let t = parse(input.as_bytes(), &limits(64, 6)).expect("depth 6");
    assert_eq!(depth(&t), 6);
    assert_eq!(kind_at(input, &limits(64, 5)), (ErrorKind::TooDeep, 13));
    assert_eq!(kind_at(input, &limits(64, 4)), (ErrorKind::TooDeep, 12));
    assert_eq!(kind_at(input, &limits(64, 3)), (ErrorKind::TooDeep, 6));
    assert_eq!(kind_at(input, &limits(64, 2)), (ErrorKind::TooDeep, 3));
}

#[test]
fn max_depth_ceiling_arithmetic() {
    let lim = limits(1 << 16, MAX_DEPTH);
    let deepest = format!("a = {}{}", "[".repeat(127), "]".repeat(127));
    let t = parse(deepest.as_bytes(), &lim).expect("127 arrays below the root");
    assert_eq!(depth(&t), MAX_DEPTH);
    let open = format!("a = {}", "[".repeat(128));
    assert_eq!(kind_at(&open, &lim), (ErrorKind::TooDeep, 131));
    // The same ceiling for headers, dotted keys and inline tables.
    let header = format!("[{}]", vec!["k"; 127].join("."));
    assert_eq!(
        depth(&parse(header.as_bytes(), &lim).expect("header")),
        MAX_DEPTH
    );
    let header = format!("[{}]", vec!["k"; 128].join("."));
    assert_eq!(kind_at(&header, &lim), (ErrorKind::TooDeep, 255));
    let dotted = format!("{} = 1", vec!["k"; 128].join("."));
    assert_eq!(
        depth(&parse(dotted.as_bytes(), &lim).expect("dotted")),
        MAX_DEPTH
    );
    let dotted = format!("{} = 1", vec!["k"; 129].join("."));
    assert_eq!(kind_at(&dotted, &lim), (ErrorKind::TooDeep, 254));
    let inline = format!("a = {}{}", "{b = ".repeat(127), "}".repeat(127));
    assert!(parse(inline.as_bytes(), &lim).is_err(), "no value inside");
    let inline = format!("a = {}1{}", "{b = ".repeat(126), "}".repeat(126));
    assert_eq!(
        depth(&parse(inline.as_bytes(), &lim).expect("inline")),
        MAX_DEPTH - 1
    );
    let inline = format!("a = {}{{}}{}", "{b = ".repeat(126), "}".repeat(126));
    assert_eq!(
        depth(&parse(inline.as_bytes(), &lim).expect("inline")),
        MAX_DEPTH
    );
    let inline = format!("a = {}{{}}{}", "{b = ".repeat(127), "}".repeat(127));
    assert_eq!(kind_at(&inline, &lim), (ErrorKind::TooDeep, 4 + 5 * 127));
}
