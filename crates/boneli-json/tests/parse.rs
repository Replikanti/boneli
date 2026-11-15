//! Parser edge cases: the grammar, escapes, surrogates, UTF-8, duplicate
//! keys, numbers, member order and errors (ADR-008, D1-D4 and D9).

mod common;

use std::time::{Duration, Instant};

use boneli_json::{Error, ErrorKind, Number, Object, Value, parse};
use common::{harness_limits, limits};

fn ok(input: &[u8]) -> Value {
    parse(input, &harness_limits()).unwrap_or_else(|e| panic!("{:?}: {e}", show(input)))
}

fn err(input: &[u8]) -> Error {
    match parse(input, &harness_limits()) {
        Ok(v) => panic!("{:?} parsed as {v:?}", show(input)),
        Err(e) => e,
    }
}

fn kind_at(input: &[u8]) -> (ErrorKind, usize) {
    let e = err(input);
    (e.kind(), e.offset())
}

fn show(input: &[u8]) -> String {
    String::from_utf8_lossy(input).into_owned()
}

/// `input` with every `%` replaced by a backslash, so that escapes in the
/// tests stay readable as escapes.
fn esc(input: &str) -> String {
    input.replace('%', "\\")
}

fn string(input: &str) -> String {
    match ok(input.as_bytes()) {
        Value::String(s) => s,
        other => panic!("{input:?} is {other:?}"),
    }
}

#[test]
fn empty_and_whitespace_only_input() {
    for input in ["", " ", "\t\n\r ", "\n"] {
        assert_eq!(
            kind_at(input.as_bytes()),
            (ErrorKind::UnexpectedEnd, input.len()),
            "{input:?}"
        );
    }
}

#[test]
fn single_scalar_top_level() {
    let shallow = limits(16, 1, 1);
    assert_eq!(parse(b"null", &shallow).expect("null"), Value::Null);
    assert_eq!(parse(b"true", &shallow).expect("true"), Value::Bool(true));
    assert_eq!(parse(b"0", &shallow).expect("0"), Value::from(0i64));
    assert_eq!(parse(b"\"x\"", &shallow).expect("x"), Value::from("x"));
    assert_eq!(
        parse(b" false ", &shallow).expect("false"),
        Value::Bool(false)
    );
}

#[test]
fn whitespace_set_is_exactly_four() {
    assert_eq!(
        ok(b" \t\n\r[ \t\n\r1 \t\n\r] \t\n\r"),
        Value::Array(vec![Value::from(1i64)])
    );
    for ws in [
        "\u{c}", "\u{b}", "\u{a0}", "\u{2060}", "\u{feff}", "\u{3000}", "\u{200b}",
    ] {
        for input in [format!("{ws}1"), format!("[{ws}1]"), format!("[1{ws}]")] {
            let e = err(input.as_bytes());
            assert!(
                matches!(
                    e.kind(),
                    ErrorKind::UnexpectedByte | ErrorKind::TrailingData
                ),
                "{input:?}: {e}"
            );
        }
        let e = err(format!("1{ws}").as_bytes());
        assert_eq!(
            (e.kind(), e.offset()),
            (ErrorKind::TrailingData, 1),
            "{ws:?}"
        );
    }
}

#[test]
fn bom_rejected() {
    assert_eq!(kind_at(b"\xef\xbb\xbf{}"), (ErrorKind::UnexpectedByte, 0));
    assert_eq!(
        kind_at(b"\xef\xbb\xbf\"x\""),
        (ErrorKind::UnexpectedByte, 0)
    );
}

#[test]
fn trailing_data_rejected() {
    assert_eq!(kind_at(b"1 2"), (ErrorKind::TrailingData, 2));
    assert_eq!(kind_at(b"[]]"), (ErrorKind::TrailingData, 2));
    assert_eq!(kind_at(b"{}x"), (ErrorKind::TrailingData, 2));
    assert_eq!(kind_at(b"[] //"), (ErrorKind::TrailingData, 3));
    assert_eq!(kind_at(b"[1,]"), (ErrorKind::UnexpectedByte, 3));
    assert_eq!(kind_at(b"{\"a\":1,}"), (ErrorKind::UnexpectedByte, 7));
    assert_eq!(kind_at(b"['a']"), (ErrorKind::UnexpectedByte, 1));
    assert_eq!(kind_at(b"[1 /* c */]"), (ErrorKind::UnexpectedByte, 3));
}

#[test]
fn literal_prefixes_and_case() {
    assert_eq!(kind_at(b"tru"), (ErrorKind::UnexpectedEnd, 3));
    assert_eq!(kind_at(b"nul"), (ErrorKind::UnexpectedEnd, 3));
    assert_eq!(kind_at(b"[fals"), (ErrorKind::UnexpectedEnd, 5));
    assert_eq!(kind_at(b"truex"), (ErrorKind::TrailingData, 4));
    assert_eq!(kind_at(b"trUe"), (ErrorKind::UnexpectedByte, 2));
    for input in ["True", "NULL", "NaN", "Infinity", "False"] {
        assert_eq!(
            kind_at(input.as_bytes()),
            (ErrorKind::UnexpectedByte, 0),
            "{input}"
        );
    }
    assert_eq!(kind_at(b"-Infinity"), (ErrorKind::InvalidNumber, 1));
}

#[test]
fn number_grammar_table() {
    for input in [
        "0",
        "-0",
        "0.0",
        "1e05",
        "1E+5",
        "-0.0e-0",
        "123456789012345678901234567890",
        "1.5e-3",
        "-12",
    ] {
        let v = ok(input.as_bytes());
        assert_eq!(v.as_number().expect("number").as_str(), input);
        assert_eq!(Number::from_lexeme(input).expect(input).as_str(), input);
    }
    for input in [
        "-", "00", "01", "-01", "1.", ".1", "1e", "1e+", "+1", "0x1", "1_000", "\u{ff11}", "1.e1",
        "-.1", "1e1.5", "1E", "- 1", "01.5",
    ] {
        let e = err(input.as_bytes());
        assert!(
            matches!(
                e.kind(),
                ErrorKind::InvalidNumber | ErrorKind::UnexpectedByte | ErrorKind::TrailingData
            ),
            "{input:?}: {e}"
        );
        assert!(Number::from_lexeme(input).is_err(), "{input:?}");
    }
    assert_eq!(kind_at(b"-"), (ErrorKind::InvalidNumber, 1));
    assert_eq!(kind_at(b"01"), (ErrorKind::InvalidNumber, 1));
    assert_eq!(kind_at(b"[1.]"), (ErrorKind::InvalidNumber, 3));
    assert_eq!(kind_at(b"1e+"), (ErrorKind::InvalidNumber, 3));
    assert_eq!(kind_at(b".1"), (ErrorKind::UnexpectedByte, 0));
    assert_eq!(kind_at(b"+1"), (ErrorKind::UnexpectedByte, 0));
    assert_eq!(kind_at(b"0x1"), (ErrorKind::TrailingData, 1));
    assert_eq!(kind_at(b"1_000"), (ErrorKind::TrailingData, 1));
    assert!(Number::from_lexeme("").is_err());
    assert!(Number::from_lexeme(" 1").is_err());
    assert!(Number::from_lexeme("1 ").is_err());
}

#[test]
fn number_accessors() {
    let n = |s: &str| Number::from_lexeme(s).expect(s);
    assert_eq!(n("-9223372036854775808").as_i64(), Some(i64::MIN));
    assert_eq!(n("-9223372036854775809").as_i64(), None);
    assert_eq!(n("9223372036854775807").as_i64(), Some(i64::MAX));
    assert_eq!(n("9223372036854775808").as_i64(), None);
    assert_eq!(n("18446744073709551615").as_u64(), Some(u64::MAX));
    assert_eq!(n("18446744073709551616").as_u64(), None);
    assert_eq!(n("-1").as_u64(), None);
    assert_eq!(n("-0").as_i64(), Some(0));
    assert_eq!(n("-0").as_u64(), None);
    assert_eq!(n("1.0").as_i64(), None);
    assert_eq!(n("1e2").as_i64(), None);
    assert_eq!(n("1e2").as_u64(), None);
    assert!(n("12").is_integer());
    assert!(n("-0").is_integer());
    assert!(!n("1.0").is_integer());
    assert!(!n("1E2").is_integer());
    let big = n("9007199254740993");
    assert_eq!(big.as_u64(), Some(9_007_199_254_740_993));
    assert_eq!(big.as_f64(), Some(9_007_199_254_740_992.0));
    assert_eq!(n("1e400").as_f64(), None);
    assert_eq!(n("-1e400").as_f64(), None);
    assert_eq!(n("1e-400").as_f64(), Some(0.0));
    assert_eq!(n("1.5").as_f64(), Some(1.5));
    let long = "9".repeat(100_000);
    assert_eq!(n(&long).as_u64(), None);
    assert_eq!(n(&long).as_i64(), None);
    assert_eq!(n(&long).as_f64(), None);
    assert_eq!(Number::from(i64::MIN).as_str(), "-9223372036854775808");
    assert_eq!(Number::from(u64::MAX).as_str(), "18446744073709551615");
}

#[test]
fn number_from_f64() {
    for f in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(Number::from_f64(f), None);
    }
    for f in [
        -0.0,
        0.0,
        5e-324,
        f64::MIN_POSITIVE,
        f64::MAX,
        f64::MIN,
        0.1,
        1e21,
        1e-7,
        1.0,
        -2.5,
        123_456_789.0,
    ] {
        let n = Number::from_f64(f).expect("finite");
        let back = n.as_f64().expect("finite");
        assert_eq!(back.to_bits(), f.to_bits(), "{f:?} -> {}", n.as_str());
        assert_eq!(Number::from_lexeme(n.as_str()).expect("grammar"), n);
        assert!(!n.is_integer(), "{f:?} gives an integer lexeme");
    }
}

#[test]
fn number_lexeme_equality() {
    let one = ok(b"1");
    assert_ne!(one, ok(b"1.0"));
    assert_ne!(one, ok(b"1e0"));
    assert_ne!(ok(b"1.0"), ok(b"1e0"));
    assert_ne!(ok(b"-0"), ok(b"0"));
    assert_eq!(one, Value::from(1i64));
    assert_eq!(Value::from(1u64), Value::from(1i64));
}

#[test]
fn escapes_table() {
    assert_eq!(string(r#""\"\\\/\b\f\n\r\t""#), "\"\\/\u{8}\u{c}\n\r\t");
    assert_eq!(
        string(&esc(r#""%u0041%u00e9%u00E9%uABCD%uabcd""#)),
        "A\u{e9}\u{e9}\u{abcd}\u{abcd}"
    );
    assert_eq!(string(r#""a\u0000b""#), "a\u{0}b");
    for (input, at) in [
        (r#""\U0041""#, 1),
        (r#""\x41""#, 1),
        (r#""\'""#, 1),
        (r#""\0""#, 1),
        (r#""ab\u12"x""#, 3),
        (r#""\u12G4""#, 1),
        (r#""\a""#, 1),
        ("\"\\\u{e9}\"", 1),
    ] {
        assert_eq!(
            kind_at(input.as_bytes()),
            (ErrorKind::InvalidEscape, at),
            "{input}"
        );
    }
    assert_eq!(kind_at(b"\"\\"), (ErrorKind::UnexpectedEnd, 2));
    assert_eq!(kind_at(b"\"\\u12"), (ErrorKind::UnexpectedEnd, 5));
    assert_eq!(kind_at(b"\"abc"), (ErrorKind::UnexpectedEnd, 4));
    for c in 0u8..0x20 {
        let input = [b'"', b'a', c, b'"'];
        assert_eq!(
            kind_at(&input),
            (ErrorKind::ControlCharacter, 2),
            "{c:#04x}"
        );
        let key = [b'{', b'"', c, b'"', b':', b'1', b'}'];
        assert_eq!(
            kind_at(&key),
            (ErrorKind::ControlCharacter, 2),
            "{c:#04x} in a key"
        );
    }
    assert_eq!(
        string("\"\u{7f}\u{2028}\u{2029}\""),
        "\u{7f}\u{2028}\u{2029}"
    );
}

#[test]
fn surrogate_boundaries() {
    assert_eq!(string(&esc(r#""%uD7FF""#)), "\u{d7ff}");
    assert_eq!(string(&esc(r#""%uE000""#)), "\u{e000}");
    assert_eq!(string(&esc(r#""%uD800%uDC00""#)), "\u{10000}");
    assert_eq!(string(&esc(r#""%udbff%udfff""#)), "\u{10ffff}");
    assert_eq!(string(&esc(r#""%uD83D%uDE00x""#)), "\u{1f600}x");
    for (input, at) in [
        (r#""\uD800""#, 1),
        (r#""\uDFFF""#, 1),
        (r#""\uDC00\uD800""#, 1),
        (r#""\uD800A""#, 1),
        (r#""\uD800x""#, 1),
        (r#""\uD800\n""#, 1),
        (r#""ab\uD800\uD800""#, 3),
        (r#""\uD800%u0041""#, 1),
        (r#""\uD800%uE000""#, 1),
        (r#""\uDBFF""#, 1),
        (r#""\uDC00""#, 1),
    ] {
        assert_eq!(
            kind_at(esc(input).as_bytes()),
            (ErrorKind::LoneSurrogate, at),
            "{input}"
        );
    }
    assert_eq!(kind_at(br#"{"\uD800":1}"#), (ErrorKind::LoneSurrogate, 2));
    assert_eq!(kind_at(br#""\uD800"#), (ErrorKind::LoneSurrogate, 1));
    assert_eq!(kind_at(br#""\uD800\u12G4""#), (ErrorKind::InvalidEscape, 7));
}

#[test]
fn invalid_utf8_forms() {
    for (input, at) in [
        (&b"\"\xc0\x80\""[..], 1),
        (b"\"\xed\xa0\x80\"", 1),
        (b"\"\xf4\x90\x80\x80\"", 1),
        (b"\"\x80\"", 1),
        (b"\"ab\xe2\x82", 3),
        (b"{\"k\xff\":1}", 3),
        (b"[1,\xff]", 3),
        (b"\xfe", 0),
        (b"\"\xc3\"", 1),
    ] {
        assert_eq!(kind_at(input), (ErrorKind::InvalidUtf8, at), "{input:?}");
    }
    assert_eq!(
        string("\"\u{ffff}\u{fffe}\u{fdd0}\u{10ffff}\""),
        "\u{ffff}\u{fffe}\u{fdd0}\u{10ffff}"
    );
}

#[test]
fn duplicate_keys() {
    assert_eq!(kind_at(br#"{"a":1,"a":2}"#), (ErrorKind::DuplicateKey, 7));
    assert_eq!(
        kind_at(esc(r#"{"a":1,"%u0061":2}"#).as_bytes()),
        (ErrorKind::DuplicateKey, 7)
    );
    assert_eq!(kind_at(br#"{"a":1,"a":1}"#), (ErrorKind::DuplicateKey, 7));
    assert_eq!(kind_at(br#"{"":1,"":1}"#), (ErrorKind::DuplicateKey, 6));
    // The second occurrence that comes first in the input is reported.
    assert_eq!(
        kind_at(br#"{"b":1,"a":2,"c":3,"a":4,"b":5}"#),
        (ErrorKind::DuplicateKey, 19)
    );
    // A duplicate in a nested object is found when that object closes.
    assert_eq!(
        kind_at(br#"[{"x":{"k":1,"k":2}}]"#),
        (ErrorKind::DuplicateKey, 13)
    );
    let distinct = ok("{\"\u{e9}\":1,\"e\u{301}\":2}".as_bytes());
    assert_eq!(distinct.as_object().expect("object").len(), 2);
    let invisible = ok("{\"model\":1,\"model\u{200b}\":2}".as_bytes());
    assert_eq!(invisible.as_object().expect("object").len(), 2);
    let escaped = ok(esc(r#"{"%u00e9":1,"e%u0301":2}"#).as_bytes());
    assert_eq!(escaped.as_object().expect("object").len(), 2);
    let nested = ok(br#"{"a":{"a":1},"b":{"a":2},"c":[{"a":3},{"a":4}]}"#);
    assert_eq!(nested.as_object().expect("object").len(), 3);
}

/// The only test that depends on timing. 2^18 keys need about 4.7 * 10^6
/// key comparisons in O(m log m), and about 3.4 * 10^10 in a quadratic
/// check: at least 34 s even at 1 ns per comparison. The parse measured
/// 1 to 3 s in the test profile on a loaded laptop, so 30 s leaves about
/// 10 times the margin both ways (ADR-008, D4).
#[test]
fn duplicate_check_not_quadratic() {
    let keys = 1usize << 18;
    let mut input = Vec::with_capacity(keys * 12);
    input.push(b'{');
    for i in 0..keys {
        if i > 0 {
            input.push(b',');
        }
        input.extend_from_slice(format!("\"k{i}\":0").as_bytes());
    }
    input.push(b'}');
    let lim = limits(input.len(), 2, keys + 1);
    let started = Instant::now();
    let v = parse(&input, &lim).expect("distinct keys");
    let took = started.elapsed();
    assert_eq!(v.as_object().expect("object").len(), keys);
    assert!(took < Duration::from_secs(30), "took {took:?}");
    eprintln!("{keys} distinct keys parsed in {took:?}");

    // The same object with its last key repeated is rejected at that key.
    let at = input.len() - 1;
    input.truncate(at);
    input.extend_from_slice(b",\"k0\":1}");
    let lim = limits(input.len(), 2, keys + 2);
    let e = parse(&input, &lim).expect_err("duplicate");
    assert_eq!((e.kind(), e.offset()), (ErrorKind::DuplicateKey, at + 1));
}

/// A decoded string or key never reserves more than its encoding, so the
/// strings of a parse fit in `max_bytes` (ADR-008, D5). The first input is
/// the one that used to double: one escape after a long run.
#[test]
fn string_capacity_within_encoding() {
    let mut long = b"\"".to_vec();
    long.resize(1 + (1 << 20), b'a');
    long.extend_from_slice(b"\\/b\"");
    let mut all_escapes = b"\"".to_vec();
    for _ in 0..4096 {
        all_escapes.extend_from_slice(b"\\u0041");
    }
    all_escapes.push(b'"');
    // An escaped quote first: the reservation must reach past it to the
    // closing quote.
    let mut quote_first = b"\"\\\"".to_vec();
    quote_first.resize(3 + 1000, b'a');
    quote_first.extend_from_slice(b"\\/b\"");
    let inputs: Vec<Vec<u8>> = vec![
        long,
        quote_first,
        all_escapes,
        b"\"\\/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"".to_vec(),
        b"\"a\"".to_vec(),
        b"\"abc\\n\"".to_vec(),
        b"\"\\ud83d\\ude00x\"".to_vec(),
        "\"\u{e9}\u{1f600}\\t\"".as_bytes().to_vec(),
    ];
    let lim = limits(4 << 20, 4, 4);
    for input in inputs {
        let encoded = input.len();
        let Value::String(s) = parse(&input, &lim).expect("string") else {
            panic!("not a string");
        };
        assert!(
            s.capacity() <= encoded,
            "encoded {encoded}, len {}, capacity {}",
            s.len(),
            s.capacity()
        );
        // The same string as a key.
        let mut object = b"{".to_vec();
        object.extend_from_slice(&input);
        object.extend_from_slice(b":0}");
        let Value::Object(o) = parse(&object, &lim).expect("object") else {
            panic!("not an object");
        };
        let (key, _) = o.into_iter().next().expect("one member");
        assert_eq!(key, s);
        assert!(key.capacity() <= encoded, "key capacity {}", key.capacity());
    }
}

#[test]
fn object_order_preserved() {
    let v = ok(br#"{"b":1,"a":2,"c":{"z":0,"y":0}}"#);
    let keys: Vec<&str> = v.as_object().expect("object").keys().collect();
    assert_eq!(keys, ["b", "a", "c"]);
    let inner: Vec<&str> = v
        .get("c")
        .and_then(Value::as_object)
        .expect("c")
        .keys()
        .collect();
    assert_eq!(inner, ["z", "y"]);
    assert_ne!(ok(br#"{"b":1,"a":2}"#), ok(br#"{"a":2,"b":1}"#));
    assert_eq!(v.get("a"), Some(&Value::from(2i64)));
    assert_eq!(v.get("missing"), None);
    assert_eq!(Value::Null.get("a"), None);
}

#[test]
fn object_insert_replaces_in_place() {
    let mut o = Object::new();
    assert_eq!(o.insert("a", 1i64), None);
    assert_eq!(o.insert("b", 2i64), None);
    assert_eq!(o.insert("c", 3i64), None);
    assert_eq!(o.insert("a", "x"), Some(Value::from(1i64)));
    let pairs: Vec<(&str, &Value)> = o.iter().collect();
    assert_eq!(
        pairs,
        [
            ("a", &Value::from("x")),
            ("b", &Value::from(2i64)),
            ("c", &Value::from(3i64))
        ]
    );
    assert_eq!(o.len(), 3);
    assert!(o.contains_key("b"));
    assert!(!o.contains_key("d"));
    if let Some(v) = o.get_mut("b") {
        *v = Value::Null;
    }
    assert_eq!(o.get("b"), Some(&Value::Null));
}

#[test]
fn object_from_iter_duplicates() {
    let o: Object = [
        ("a".to_owned(), Value::from(1i64)),
        ("b".to_owned(), Value::from(2i64)),
        ("a".to_owned(), Value::from(3i64)),
        ("c".to_owned(), Value::from(4i64)),
        ("b".to_owned(), Value::from(5i64)),
        ("a".to_owned(), Value::from(6i64)),
    ]
    .into_iter()
    .collect();
    let pairs: Vec<(String, Value)> = o.into_iter().collect();
    assert_eq!(
        pairs,
        [
            ("a".to_owned(), Value::from(6i64)),
            ("b".to_owned(), Value::from(5i64)),
            ("c".to_owned(), Value::from(4i64)),
        ]
    );
    let empty: Object = std::iter::empty().collect();
    assert!(empty.is_empty());
}

#[test]
fn object_remove_keeps_order() {
    let mut o: Object = ["a", "b", "c", "d"]
        .into_iter()
        .map(|k| (k.to_owned(), Value::from(k)))
        .collect();
    assert_eq!(o.remove("b"), Some(Value::from("b")));
    assert_eq!(o.remove("b"), None);
    let keys: Vec<&str> = o.keys().collect();
    assert_eq!(keys, ["a", "c", "d"]);
}

#[test]
fn value_is_32_bytes() {
    if cfg!(target_pointer_width = "64") {
        assert_eq!(size_of::<Value>(), 32);
    }
}

#[test]
fn error_display_has_no_input_bytes() {
    let marker = "MARKER7f3a9c";
    for input in [
        format!(r#"{{"key":"sk-{marker}"#),
        format!(r#"{{"key":"sk-{marker}\q"}}"#),
        format!(r#"["sk-{marker}" x]"#),
        format!(r#"{{"sk-{marker}":1,"sk-{marker}":2}}"#),
        format!("sk-{marker}"),
    ] {
        let e = err(input.as_bytes());
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(marker), "{shown}");
        assert!(!shown.contains("sk-"), "{shown}");
    }
}

#[test]
fn value_accessors() {
    let v = ok(br#"{"s":"x","b":true,"n":5,"a":[null],"o":{}}"#);
    assert_eq!(v.get("s").and_then(Value::as_str), Some("x"));
    assert_eq!(v.get("b").and_then(Value::as_bool), Some(true));
    assert_eq!(
        v.get("n")
            .and_then(Value::as_number)
            .and_then(Number::as_i64),
        Some(5)
    );
    assert_eq!(
        v.get("a").and_then(Value::as_array).map(<[Value]>::len),
        Some(1)
    );
    assert!(v.get("a").and_then(Value::as_array).expect("a")[0].is_null());
    assert!(
        v.get("o")
            .and_then(Value::as_object)
            .is_some_and(Object::is_empty)
    );
    assert_eq!(v.get("s").and_then(Value::as_bool), None);
    assert_eq!(Value::from(String::from("y")), Value::from("y"));
    assert_eq!(Value::from(Number::from(7u64)), Value::from(7u64));
    assert_eq!(Value::from(vec![Value::Null]), ok(b"[null]"));
    assert_eq!(Value::from(Object::with_capacity(4)), ok(b"{}"));
    assert_eq!(Value::from(false), ok(b"false"));
}
