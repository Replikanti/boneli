//! Serializer output: compact, ordered, deterministic, and escaping exactly
//! `"`, `\` and U+0000-U+001F (ADR-008, D7).

mod common;

use boneli_json::{ErrorKind, MAX_DEPTH, Number, Object, Value, to_string, to_vec};
use common::{built_arrays, built_objects};

#[test]
fn escapes_exact_bytes() {
    let named = [
        (0x08, "\\b"),
        (0x09, "\\t"),
        (0x0a, "\\n"),
        (0x0c, "\\f"),
        (0x0d, "\\r"),
    ];
    for c in 0u8..0x20 {
        let expected = match named.iter().find(|(b, _)| *b == c) {
            Some((_, short)) => (*short).to_owned(),
            None => format!("\\u{c:04x}"),
        };
        let out = to_string(&Value::String(char::from(c).to_string())).expect("string");
        assert_eq!(out, format!("\"{expected}\""), "{c:#04x}");
    }
    let cases = [
        ("\"", "\"\\\"\""),
        ("\\", "\"\\\\\""),
        ("/", "\"/\""),
        ("\u{7f}", "\"\u{7f}\""),
        ("\u{2028}", "\"\u{2028}\""),
        ("\u{2029}", "\"\u{2029}\""),
        ("\u{feff}", "\"\u{feff}\""),
        ("\u{1f600}", "\"\u{1f600}\""),
        ("a\u{1f}b\"c", "\"a\\u001fb\\\"c\""),
        ("", "\"\""),
    ];
    for (input, expected) in cases {
        assert_eq!(
            to_string(&Value::from(input)).expect("string"),
            expected,
            "{input:?}"
        );
    }
    assert_eq!(
        to_vec(&Value::from("\u{1b}")).expect("string"),
        b"\"\\u001b\""
    );
}

#[test]
fn compact_and_ordered() {
    let mut inner = Object::new();
    inner.insert(
        "b",
        Value::Array(vec![Value::from(1i64), Value::Object(Object::new())]),
    );
    inner.insert("a", Value::Null);
    let v = Value::Object(inner);
    assert_eq!(to_vec(&v).expect("value"), br#"{"b":[1,{}],"a":null}"#);
    assert_eq!(
        to_string(&v).expect("value"),
        to_string(&v.clone()).expect("value")
    );
    let scalars = Value::Array(vec![
        Value::Bool(true),
        Value::Bool(false),
        Value::Null,
        Value::Number(Number::from_lexeme("-0.5e+3").expect("number")),
        Value::from(u64::MAX),
        Value::Array(Vec::new()),
        Value::from("k"),
    ]);
    assert_eq!(
        to_string(&scalars).expect("value"),
        r#"[true,false,null,-0.5e+3,18446744073709551615,[],"k"]"#
    );
    let mut keyed = Object::new();
    keyed.insert("\n\"", 1i64);
    assert_eq!(
        to_string(&Value::Object(keyed)).expect("value"),
        r#"{"\n\"":1}"#
    );
}

#[test]
fn serialize_depth_ceiling() {
    for build in [built_arrays, built_objects] {
        let at = build(MAX_DEPTH);
        to_vec(&at).expect("depth 512");
        let over = build(MAX_DEPTH + 1);
        let e = to_vec(&over).expect_err("depth 513");
        assert_eq!(e.kind(), ErrorKind::TooDeep);
        assert_eq!(
            to_string(&over).expect_err("depth 513").kind(),
            ErrorKind::TooDeep
        );
    }
    let mut wide = vec![built_arrays(MAX_DEPTH - 1); 3];
    wide.push(built_arrays(MAX_DEPTH));
    let e = to_vec(&Value::Array(wide)).expect_err("depth 513 in the last element");
    assert_eq!(e.kind(), ErrorKind::TooDeep);
}
