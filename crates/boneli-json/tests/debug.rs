//! `Debug` of values is compact, ignores the alternate flag and costs
//! time linear in its output, so `{:#?}` of a deep hostile value is as
//! cheap as `{:?}` (ADR-008, D9).

mod common;

use std::time::{Duration, Instant};

use boneli_json::{MAX_DEPTH, Number, Object, Value, parse};
use common::{built_arrays, built_objects, harness_limits, nested_arrays, nested_objects};

#[test]
fn debug_format_pinned() {
    let v = parse(
        br#"{"s":"a\"\n","n":-1.5e3,"b":[true,false,null],"o":{},"a":[]}"#,
        &harness_limits(),
    )
    .expect("parses");
    let want = r#"Object {"s": String("a\"\n"), "n": Number(-1.5e3), "b": Array [Bool(true), Bool(false), Null], "o": Object {}, "a": Array []}"#;
    assert_eq!(format!("{v:?}"), want);
    assert_eq!(format!("{v:#?}"), want);
    let n = Number::from_lexeme("12").expect("number");
    assert_eq!(format!("{n:?} {n:#?}"), "Number(12) Number(12)");
    let o: Object = [("k".to_owned(), Value::Null)].into_iter().collect();
    assert_eq!(format!("{o:?} {o:#?}"), r#"{"k": Null} {"k": Null}"#);
    assert_eq!(format!("{:?}", Object::new()), "{}");
}

/// The only timing bound in this binary. The derived pretty `Debug` took
/// 6.7 s (arrays) and 61 s (objects) in release on these values, cubic in
/// the depth, and 26 s for the arrays in the test profile on a loaded
/// laptop (ADR-008, D9). The compact form writes at most 14 bytes per
/// level once: 87 µs and 186 µs in the test profile. 2 s leaves more than
/// 10 times the margin below the old cost and about 10,000 times above
/// the new one.
#[test]
fn pretty_debug_of_deep_values_is_fast() {
    for input in [nested_arrays(MAX_DEPTH), nested_objects(MAX_DEPTH)] {
        let v = parse(&input, &harness_limits()).expect("depth 512");
        let started = Instant::now();
        let pretty = format!("{v:#?}");
        let took = started.elapsed();
        assert!(took < Duration::from_secs(2), "took {took:?}");
        assert_eq!(pretty, format!("{v:?}"));
        assert!(pretty.len() < 20 * input.len(), "{} bytes", pretty.len());
        eprintln!("{{:#?}} of {} input bytes in {took:?}", input.len());
    }
}

/// A built value deeper than `MAX_DEPTH` prints its first `MAX_DEPTH`
/// levels and elides the rest, so `Debug` recurses no deeper than for a
/// parsed value (ADR-008, D6).
#[test]
fn debug_stops_at_max_depth() {
    let arrays = format!("{:?}", built_arrays(MAX_DEPTH + 2));
    assert_eq!(arrays.matches("Array [").count(), MAX_DEPTH + 1);
    assert!(arrays.contains("Array [Array [..]]"), "{}", &arrays[..64]);
    let objects = format!("{:#?}", built_objects(MAX_DEPTH + 2));
    assert_eq!(objects.matches("Object {").count(), MAX_DEPTH + 1);
    assert!(objects.contains(r#"Object {"k": Object {..}}"#));
    // Exactly at the ceiling nothing is elided.
    let full = format!("{:?}", built_arrays(MAX_DEPTH));
    assert!(!full.contains(".."));
    assert_eq!(full.matches("Array [").count(), MAX_DEPTH);
}
