//! `Debug` of values is compact, ignores the alternate flag, costs time
//! linear in its output and elides containers inside `MAX_DEPTH` others
//! (ADR-011, D8, the reasoning of ADR-008, D9).

mod common;

use std::time::{Duration, Instant};

use boneli_toml::{MAX_DEPTH, Table, Value};
use common::{deepest_tables, ok};

#[test]
fn debug_format_pinned() {
    let t = ok("s = \"a\\\"\\n\"\nn = -15\nb = [true, false]\nt = {}\na = []\n[u]\nx = 'y'");
    let want = r#"{"s": String("a\"\n"), "n": Integer(-15), "b": Array [Boolean(true), Boolean(false)], "t": Table {}, "a": Array [], "u": Table {"x": String("y")}}"#;
    assert_eq!(format!("{t:?}"), want);
    assert_eq!(format!("{t:#?}"), want);
    let v = Value::Integer(1);
    assert_eq!(format!("{v:?} {v:#?}"), "Integer(1) Integer(1)");
    assert_eq!(format!("{:?}", Table::new()), "{}");
    assert_eq!(format!("{:?}", Value::Table(Table::new())), "Table {}");
}

/// The derived pretty `Debug` is cubic in the depth (ADR-008, D9); the
/// hand-written form writes a few bytes per level. 2 s is the same bound
/// as boneli-json's, at a quarter of its depth.
#[test]
fn pretty_debug_matches_compact_and_is_fast() {
    let mut deep = deepest_tables();
    deep.push(ok(&format!("a = {}{}", "[".repeat(127), "]".repeat(127))));
    for t in deep {
        let started = Instant::now();
        let pretty = format!("{t:#?}");
        let took = started.elapsed();
        assert!(took < Duration::from_secs(2), "took {took:?}");
        assert_eq!(pretty, format!("{t:?}"));
        assert!(
            !pretty.contains(".."),
            "a parsed depth is never elided: {}",
            &pretty[pretty.len().saturating_sub(300)..]
        );
        eprintln!(
            "{{:#?}} of depth {MAX_DEPTH} in {took:?}, {} bytes",
            pretty.len()
        );
    }
}

/// A built value deeper than `MAX_DEPTH` prints its first levels and
/// elides the rest, so `Debug` recurses no deeper than for a parsed value.
#[test]
fn debug_stops_at_max_depth() {
    let mut v = Value::Integer(1);
    for _ in 0..MAX_DEPTH + 2 {
        let mut t = Table::new();
        t.insert("k", v);
        v = Value::Table(t);
    }
    let mut root = Table::new();
    root.insert("k", v);
    let shown = format!("{root:?}");
    assert_eq!(shown.matches("Table {").count(), MAX_DEPTH);
    assert!(
        shown.contains(r#"Table {"k": Table {..}}"#),
        "{}",
        &shown[shown.len() - 64..]
    );
    let mut v = Value::Array(Vec::new());
    for _ in 0..MAX_DEPTH + 2 {
        v = Value::Array(vec![v]);
    }
    let shown = format!("{v:#?}");
    assert_eq!(shown.matches("Array [").count(), MAX_DEPTH + 1);
    assert!(shown.contains("Array [Array [..]]"));
}
