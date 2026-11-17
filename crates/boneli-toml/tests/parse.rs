//! The grammar: documents, strings, integers, whitespace, newlines,
//! control characters, encodings and the unsupported features
//! (ADR-011, D1 and D2).

mod common;

use boneli_toml::{ErrorKind, Feature, Value, parse};
use common::{err, harness_limits, kind_at, lookup, ok};

fn string_of(input: &str, key: &str) -> String {
    match ok(input).get(key) {
        Some(Value::String(s)) => s.clone(),
        other => panic!("{input:?}: {key} is {other:?}"),
    }
}

#[test]
fn empty_and_blank_inputs() {
    for input in [
        "",
        " ",
        "\t \t",
        "\n\n",
        "# a comment",
        "# one\n# two\n",
        "\r\n",
        "\r\n\r\n  \r\n",
    ] {
        assert!(ok(input).is_empty(), "{input:?}");
    }
}

#[test]
fn document_edges() {
    assert_eq!(ok("a = 1").get("a"), Some(&Value::Integer(1)));
    assert_eq!(ok("a = 1 # end").get("a"), Some(&Value::Integer(1)));
    assert_eq!(ok("a = 1\n# end").len(), 1);
    assert!(
        ok("[t]")
            .get("t")
            .and_then(Value::as_table)
            .is_some_and(|t| t.is_empty())
    );
    assert!(
        ok("[[t]]")
            .get("t")
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() == 1)
    );
    assert_eq!(kind_at("a="), (ErrorKind::UnexpectedEnd, 2));
    assert_eq!(kind_at("a"), (ErrorKind::UnexpectedEnd, 1));
    assert_eq!(kind_at("a ="), (ErrorKind::UnexpectedEnd, 3));
    assert_eq!(kind_at("[t"), (ErrorKind::UnexpectedEnd, 2));
    assert_eq!(kind_at("[[t]"), (ErrorKind::UnexpectedEnd, 4));
    assert_eq!(kind_at("a = \"x"), (ErrorKind::UnexpectedEnd, 6));
    assert_eq!(kind_at("a = [1,"), (ErrorKind::UnexpectedEnd, 7));
    assert_eq!(kind_at("a = {b = 1"), (ErrorKind::UnexpectedEnd, 10));
    // Exactly one pair per line, and nothing but a comment after it.
    assert_eq!(kind_at("a = 1 b = 2"), (ErrorKind::UnexpectedByte, 6));
    assert_eq!(kind_at("[t] x = 1"), (ErrorKind::UnexpectedByte, 4));
    assert_eq!(kind_at("a = 1\n= 2"), (ErrorKind::UnexpectedByte, 6));
    assert_eq!(kind_at("a\n= 1"), (ErrorKind::UnexpectedByte, 1));
    assert_eq!(kind_at("a =\n1"), (ErrorKind::UnexpectedByte, 3));
    assert_eq!(kind_at("[ [t]]"), (ErrorKind::UnexpectedByte, 2));
    assert_eq!(kind_at("[[t] ]"), (ErrorKind::UnexpectedByte, 4));
}

#[test]
fn empty_forms() {
    let t = ok("a = []\nb = {}\nc = \"\"\nd = ''\ne = \"\"\"\"\"\"\nf = ''''''\n\"\" = 1");
    assert_eq!(t.get("a"), Some(&Value::Array(Vec::new())));
    assert!(
        t.get("b")
            .and_then(Value::as_table)
            .is_some_and(|t| t.is_empty())
    );
    for key in ["c", "d", "e", "f"] {
        assert_eq!(t.get(key).and_then(Value::as_str), Some(""), "{key}");
    }
    // "" and '' are the same empty key, so the dotted key is a duplicate
    // of the scalar.
    assert_eq!(kind_at("\"\" = 1\n''.x = 2"), (ErrorKind::NotExtensible, 7));
    assert_eq!(kind_at("\"\" = 1\n['']"), (ErrorKind::DuplicateTable, 8));
    assert_eq!(
        lookup(&ok("[''.'']"), &["", ""])
            .and_then(Value::as_table)
            .map(|t| t.len()),
        Some(0)
    );
    assert_eq!(kind_at("[]"), (ErrorKind::UnexpectedByte, 1));
    assert_eq!(kind_at("= 1"), (ErrorKind::UnexpectedByte, 0));
}

#[test]
fn integer_bounds_and_underscores() {
    for (input, want) in [
        ("9223372036854775807", i64::MAX),
        ("-9223372036854775808", i64::MIN),
        ("9_223_372_036_854_775_807", i64::MAX),
        ("+9223372036854775807", i64::MAX),
        ("+0", 0),
        ("-0", 0),
        ("0", 0),
        ("1_0", 10),
        ("-1_2_3", -123),
    ] {
        let t = ok(&format!("a = {input}"));
        assert_eq!(t.get("a"), Some(&Value::Integer(want)), "{input}");
    }
    for input in [
        "9223372036854775808",
        "-9223372036854775809",
        "99999999999999999999999",
    ] {
        assert_eq!(
            kind_at(&format!("a = {input}")),
            (ErrorKind::IntegerOutOfRange, 4),
            "{input}"
        );
    }
    for input in [
        "00", "01", "0_1", "1_", "1__0", "+_1", "-01", "+", "-", "1a", "--1", "+-1", "1+",
    ] {
        assert_eq!(
            kind_at(&format!("a = {input}")),
            (ErrorKind::InvalidInteger, 4),
            "{input}"
        );
    }
}

#[test]
fn escape_bounds() {
    assert_eq!(string_of(r#"a = "\U0010FFFF""#, "a"), "\u{10ffff}");
    assert_eq!(string_of(r#"a = "\u0000""#, "a"), "\0");
    assert_eq!(
        string_of(r#"a = "\b\t\n\f\r\"\\\u00e9\U0001F600""#, "a"),
        "\u{8}\t\n\u{c}\r\"\\\u{e9}\u{1f600}"
    );
    for esc in [
        r"\U00110000",
        r"\uD800",
        r"\uDFFF",
        r"\e",
        r"\x41",
        r"\ x",
        r"\u12",
        r"\u12G4",
        r"\a",
        r"\/",
        r"\'",
    ] {
        assert_eq!(
            kind_at(&format!("a = \"{esc}\"")),
            (ErrorKind::InvalidEscape, 5),
            "{esc}"
        );
        assert_eq!(
            kind_at(&format!("a = \"\"\"{esc}\"\"\"")),
            (ErrorKind::InvalidEscape, 7),
            "{esc}"
        );
    }
    assert_eq!(kind_at("a = \"\\"), (ErrorKind::UnexpectedEnd, 6));
    assert_eq!(kind_at("a = \"\\u00"), (ErrorKind::UnexpectedEnd, 9));
}

#[test]
fn multiline_delimiter_runs() {
    assert_eq!(string_of("a = \"\"\"a\"\"\"\"", "a"), "a\"");
    assert_eq!(string_of("a = \"\"\"a\"\"\"\"\"", "a"), "a\"\"");
    assert_eq!(
        kind_at("a = \"\"\"a\"\"\"\"\"\""),
        (ErrorKind::UnexpectedByte, 13)
    );
    assert_eq!(string_of("a = '''a''''", "a"), "a'");
    assert_eq!(string_of("a = '''a'''''", "a"), "a''");
    assert_eq!(kind_at("a = '''a''''''"), (ErrorKind::UnexpectedByte, 13));
    assert_eq!(string_of("a = \"\"\"\"\"a\"\"\"", "a"), "\"\"a");
    assert_eq!(string_of("a = \"\"\"\nx\"\"\"", "a"), "x");
    assert_eq!(string_of("a = \"\"\"\r\nx\"\"\"", "a"), "x");
    assert_eq!(string_of("a = '''\nx'''", "a"), "x");
    assert_eq!(string_of("a = '''\r\nx'''", "a"), "x");
    // Only the first newline is trimmed.
    assert_eq!(string_of("a = \"\"\"\n\nx\"\"\"", "a"), "\nx");
    assert_eq!(string_of("a = '''\n\nx'''", "a"), "\nx");
    assert_eq!(string_of("a = \"\"\"a\\\"\"\"\"\"", "a"), "a\"\"");
    assert_eq!(string_of("a = \"\"\"a\\\"\"\"\"\"\"", "a"), "a\"\"\"");
}

#[test]
fn byte_order_mark_rejected() {
    assert_eq!(kind_at("\u{feff}a = 1"), (ErrorKind::UnexpectedByte, 0));
    assert_eq!(kind_at("\u{feff}"), (ErrorKind::UnexpectedByte, 0));
    assert_eq!(
        kind_at("a = 1\n\u{feff}b = 2"),
        (ErrorKind::UnexpectedByte, 6)
    );
    assert_eq!(kind_at("a =\u{feff}1"), (ErrorKind::UnexpectedByte, 3));
    // Inside a string it is a character like any other.
    assert_eq!(string_of("a = \"\u{feff}\"", "a"), "\u{feff}");
}

#[test]
fn only_space_and_tab_are_whitespace() {
    assert_eq!(ok("\ta\t=\t1\t").get("a"), Some(&Value::Integer(1)));
    for ws in ["\u{a0}", "\u{3000}", "\u{b}", "\u{c}", "\u{2028}", "\u{85}"] {
        assert_eq!(
            kind_at(&format!("a{ws}= 1")),
            (ErrorKind::UnexpectedByte, 1),
            "{ws:?}"
        );
        assert_eq!(
            kind_at(&format!("a ={ws}1")),
            (ErrorKind::UnexpectedByte, 3),
            "{ws:?}"
        );
        assert_eq!(
            kind_at(&format!("{ws}a = 1")),
            (ErrorKind::UnexpectedByte, 0),
            "{ws:?}"
        );
        assert_eq!(
            kind_at(&format!("a = [1,{ws}2]")),
            (ErrorKind::UnexpectedByte, 7),
            "{ws:?}"
        );
    }
}

#[test]
fn newline_forms() {
    let t = ok("a = 1\r\nb = [\r\n1,\r\n2]\r\n[t]\r\nc = 3\r\n");
    assert_eq!(lookup(&t, &["t", "c"]), Some(&Value::Integer(3)));
    assert_eq!(string_of("a = \"\"\"x\r\ny\r\n\"\"\"", "a"), "x\ny\n");
    assert_eq!(string_of("a = '''x\r\ny'''", "a"), "x\ny");
    assert_eq!(string_of("a = \"\"\"x\\\r\n  y\"\"\"", "a"), "xy");
    for input in [
        "a = 1\rb = 2",
        "\r",
        "a = 1\r",
        "a\r= 1",
        "# c\r",
        "# c\rd = 1\n",
        "a = \"x\ry\"",
        "a = 'x\ry'",
        "a = \"\"\"x\ry\"\"\"",
        "a = '''x\ry'''",
        "a = [1,\r2]",
        "[t]\r",
        "a = \"\"\"x\\\ry\"\"\"",
    ] {
        assert!(
            parse(input.as_bytes(), &harness_limits()).is_err(),
            "{input:?}"
        );
    }
    assert_eq!(kind_at("a = 1\rb = 2"), (ErrorKind::UnexpectedByte, 5));
    assert_eq!(kind_at("a = \"x\ry\""), (ErrorKind::ControlCharacter, 6));
    assert_eq!(kind_at("# c\r"), (ErrorKind::ControlCharacter, 3));
    // A newline ends a single-line string too early.
    assert_eq!(kind_at("a = \"x\ny\""), (ErrorKind::ControlCharacter, 6));
    assert_eq!(kind_at("a = 'x\ny'"), (ErrorKind::ControlCharacter, 6));
}

#[test]
fn control_characters_by_context() {
    let controls = (0u8..0x20)
        .filter(|&b| b != b'\t' && b != b'\n' && b != b'\r')
        .chain([0x7f]);
    for b in controls {
        let c = char::from(b);
        for (input, at) in [
            (format!("a = \"x{c}\""), 6),
            (format!("a = 'x{c}'"), 6),
            (format!("a = \"\"\"x{c}\"\"\""), 8),
            (format!("a = '''x{c}'''"), 8),
            (format!("# x{c}\n"), 3),
            (format!("a = 1 # x{c}"), 9),
            (format!("\"k{c}\" = 1"), 2),
            (format!("'k{c}' = 1"), 2),
        ] {
            assert_eq!(
                kind_at(&input),
                (ErrorKind::ControlCharacter, at),
                "{input:?}"
            );
        }
        assert_eq!(
            kind_at(&format!("a = 1{c}")),
            (ErrorKind::UnexpectedByte, 5),
            "{b:#x}"
        );
    }
    let t = ok("a = \"\tx\"\nb = '\t'\nc = \"\"\"\t\"\"\"\nd = '''\t'''\n# \t\n\"\tk\" = 1");
    assert_eq!(t.get("a").and_then(Value::as_str), Some("\tx"));
    assert_eq!(t.get("\tk"), Some(&Value::Integer(1)));
    // C1 controls are not control characters for TOML 1.0.
    assert_eq!(
        string_of("a = \"\u{80}\u{9f}\" # \u{85}", "a"),
        "\u{80}\u{9f}"
    );
}

#[test]
fn bare_tokens_are_ascii_only() {
    for (input, at) in [
        ("l\u{131}nts = 1", 1),
        ("lint\u{455} = 1", 4),
        ("l\u{435}nts = 1", 1),
        ("\u{ff4c}ints = 1", 0),
        ("\u{e9} = 1", 0),
        ("a = True", 4),
        ("a = TRUE", 4),
        ("a = tru", 4),
        ("a = truex", 4),
        ("a = falsey", 4),
        ("a = t\u{2d0}ue", 4),
        ("a = \u{ff11}", 4),
        ("a = nul", 4),
        ("[\u{131}]", 1),
    ] {
        assert_eq!(kind_at(input), (ErrorKind::UnexpectedByte, at), "{input:?}");
    }
    let t = ok("a = true\nb = false\nAZaz09_- = 1");
    assert_eq!(t.get("a"), Some(&Value::Boolean(true)));
    assert_eq!(t.get("b"), Some(&Value::Boolean(false)));
    assert_eq!(t.get("AZaz09_-"), Some(&Value::Integer(1)));
}

#[test]
fn invalid_utf8_positions() {
    for (input, at) in [
        (&b"a = \"\xc0\x80\""[..], 5),
        (b"a = \"\xed\xa0\x80\"", 5),
        (b"a = \"\xf4\x90\x80\x80\"", 5),
        (b"a = \"\xe2\x82", 5),
        (b"\xff", 0),
        (b"# \xfe\n", 2),
        (b"a = 1\n\x80", 6),
    ] {
        let e = parse(input, &harness_limits()).expect_err("invalid UTF-8");
        assert_eq!(
            (e.kind(), e.offset()),
            (ErrorKind::InvalidUtf8, at),
            "{input:?}"
        );
    }
}

#[test]
fn toml_1_1_syntax_is_an_error() {
    assert_eq!(kind_at("a = {\nb = 1}"), (ErrorKind::UnexpectedByte, 5));
    assert_eq!(kind_at("a = {b = 1\n}"), (ErrorKind::UnexpectedByte, 10));
    assert_eq!(kind_at("a = {b = 1,}"), (ErrorKind::UnexpectedByte, 11));
    assert_eq!(kind_at("a = {b = 1, }"), (ErrorKind::UnexpectedByte, 12));
    assert_eq!(
        kind_at("a = {b = 1 # c\n}"),
        (ErrorKind::UnexpectedByte, 11)
    );
    assert_eq!(kind_at("a = \"\\e\""), (ErrorKind::InvalidEscape, 5));
    assert_eq!(kind_at("a = \"\\x41\""), (ErrorKind::InvalidEscape, 5));
    // Arrays inside inline tables may span lines in TOML 1.0.
    let t = ok("a = {b = [\n1,\n2,\n]}");
    assert_eq!(
        lookup(&t, &["a", "b"])
            .and_then(Value::as_array)
            .map(<[Value]>::len),
        Some(2)
    );
}

#[test]
fn markup_inside_strings_and_comments_is_inert() {
    let t = ok(concat!(
        "a = \"\"\"\n[lints]\nx = 1\n# no\n\"\"\"\n",
        "b = '''\n[[t]]\ny = {}\n'''\n",
        "c = \"# not a comment\" # a comment\n",
        "\"#k\" = 'x # y'\n",
        "# [lints]\n# z = 1\n",
        "d = [ # [e]\n  1, # f = 2\n]\n",
    ));
    assert_eq!(t.keys().collect::<Vec<_>>(), ["a", "b", "c", "#k", "d"]);
    assert_eq!(
        t.get("a").and_then(Value::as_str),
        Some("[lints]\nx = 1\n# no\n")
    );
    assert_eq!(t.get("b").and_then(Value::as_str), Some("[[t]]\ny = {}\n"));
    assert_eq!(t.get("c").and_then(Value::as_str), Some("# not a comment"));
    assert_eq!(t.get("#k").and_then(Value::as_str), Some("x # y"));
    assert_eq!(t.get("d"), Some(&Value::Array(vec![Value::Integer(1)])));
}

#[test]
fn backslash_by_string_form() {
    let t = ok("['cfg(target_os = \"li\\nux\")'.dependencies]\nx = 1");
    assert!(t.get("cfg(target_os = \"li\\nux\")").is_some());
    assert_eq!(string_of("a = 'C:\\path\\n'", "a"), "C:\\path\\n");
    assert_eq!(string_of("a = \"\"\"a \\\n   \n  b\"\"\"", "a"), "a b");
    assert_eq!(string_of("a = \"\"\"a \\  \t\n  b\"\"\"", "a"), "a b");
    assert_eq!(string_of("a = \"\"\"a\\\n\"\"\"", "a"), "a");
    assert_eq!(string_of("a = '''a \\\nb'''", "a"), "a \\\nb");
    assert_eq!(kind_at("a = \"a \\\nb\""), (ErrorKind::InvalidEscape, 7));
    assert_eq!(
        kind_at("a = \"\"\"a\\ b\"\"\""),
        (ErrorKind::InvalidEscape, 8)
    );
}

#[test]
fn unsupported_features_are_named() {
    for (value, feature) in [
        ("1.5", Feature::Float),
        ("-1.5", Feature::Float),
        ("1e3", Feature::Float),
        ("1E3", Feature::Float),
        ("1_000.0", Feature::Float),
        ("0e0", Feature::Float),
        ("inf", Feature::Float),
        ("+inf", Feature::Float),
        ("-inf", Feature::Float),
        ("nan", Feature::Float),
        ("+nan", Feature::Float),
        ("1979-05-27T07:32:00Z", Feature::OffsetDateTime),
        ("1979-05-27T07:32:00-07:00", Feature::OffsetDateTime),
        ("1979-05-27 07:32:00+01:00", Feature::OffsetDateTime),
        ("1979-05-27T07:32:00", Feature::LocalDateTime),
        ("1979-05-27t07:32:00.999", Feature::LocalDateTime),
        ("1979-05-27 07:32:00", Feature::LocalDateTime),
        ("1979-05-27", Feature::LocalDate),
        ("07:32:00", Feature::LocalTime),
        ("0x1F", Feature::HexInteger),
        ("0o17", Feature::OctalInteger),
        ("0b1", Feature::BinaryInteger),
    ] {
        for (input, at) in [
            (format!("a = {value}"), 4),
            (format!("a = [1, {value}]"), 8),
            (format!("a = {{b = {value}}}"), 9),
        ] {
            let e = err(&input);
            assert_eq!(
                (e.kind(), e.offset()),
                (ErrorKind::Unsupported(feature), at),
                "{input:?}"
            );
        }
    }
}

#[test]
fn number_like_keys_are_keys() {
    let t = ok("2001-02-03 = 1\n1.2 = 3\n0x1 = 4\ninf = 5\n-1 = 6");
    assert_eq!(t.get("2001-02-03"), Some(&Value::Integer(1)));
    assert_eq!(lookup(&t, &["1", "2"]), Some(&Value::Integer(3)));
    assert_eq!(t.get("0x1"), Some(&Value::Integer(4)));
    assert_eq!(t.get("inf"), Some(&Value::Integer(5)));
    assert_eq!(t.get("-1"), Some(&Value::Integer(6)));
    assert_eq!(kind_at("+1 = 7"), (ErrorKind::UnexpectedByte, 0));
}

#[test]
fn string_capacity_within_encoding() {
    let long = "a".repeat(1000);
    for body in [
        format!("\"{long}\""),
        format!("\"{long}\\n\""),
        format!("\"\\n{long}\""),
        format!("\"{}\"", "\\u0041".repeat(200)),
        format!("\"{}\"", "\\U0001F600".repeat(200)),
        format!("\"\"\"\n{long}\\\n     \n   {long}\"\"\""),
        format!("\"\"\"{long}\r\n{long}\r\n\"\"\""),
        format!("'''\r\n{long}\r\n'''"),
        format!("\"\"\"{long}\"\"\"\"\""),
        format!("'{long}'"),
    ] {
        let input = format!("a = {body}");
        match ok(&input).get("a") {
            Some(Value::String(s)) => assert!(
                s.capacity() <= body.len(),
                "capacity {} for {} encoded bytes",
                s.capacity(),
                body.len()
            ),
            other => panic!("{other:?}"),
        }
    }
}
