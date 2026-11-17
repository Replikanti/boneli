//! Errors carry a kind and a position, never input bytes (ADR-011, D8).

mod common;

use boneli_toml::{ErrorKind, Feature, Limits, parse};
use common::{err, limits};

const MARKER: &str = "s3cr3t-M4RK3R";

#[test]
fn errors_never_show_input() {
    let m = MARKER;
    let cases = [
        format!("{m} = 1\n{m} = 2"),
        format!("\"{m}\" = 1\n'{m}' = 2"),
        format!("[{m}]\n[{m}]"),
        format!("{m}.x = 1\n[{m}]"),
        format!("{m} = 1\n{m}.x = 2"),
        format!("a = \"{m}\\q\""),
        format!("a = \"{m}\u{1}\""),
        format!("# {m}\u{1}"),
        format!("a = '{m}"),
        format!("a = {m}"),
        format!("a = 1.{m}"),
        format!("a = 0x{m}"),
        format!("a = 1{m}"),
        format!("a = 99999999999999999999{m}"),
        format!("a = 99999999999999999999 # {m}"),
        format!("{m} = [[[1]]]"),
        format!("a = \"{m}\" {m}"),
        format!("a = \"{m}\"\u{0}"),
    ];
    let lim = limits(1 << 16, 3);
    let mut kinds = Vec::new();
    for input in &cases {
        let e = parse(input.as_bytes(), &lim).expect_err(input);
        for shown in [
            e.to_string(),
            format!("{e:?}"),
            format!("{e:#?}"),
            format!("{:?}", e.kind()),
        ] {
            assert!(!shown.contains(m), "{input:?} shows {shown:?}");
            assert!(!shown.contains("M4RK"), "{input:?} shows {shown:?}");
        }
        kinds.push(e.kind());
    }
    let mut bytes = MARKER.as_bytes().to_vec();
    bytes.push(0xff);
    let e = parse(&bytes, &lim).expect_err("invalid UTF-8");
    assert!(!e.to_string().contains(m) && !format!("{e:?}").contains(m));
    let e = parse(MARKER.as_bytes(), &limits(4, 1)).expect_err("too large");
    assert!(!e.to_string().contains(m) && !format!("{e:?}").contains(m));
    kinds.sort_by_key(|k| format!("{k:?}"));
    kinds.dedup();
    assert!(kinds.len() >= 10, "{kinds:?}");
}

#[test]
fn display_names_kind_and_position() {
    let e = err("a = 1\n\"a\" = 2");
    assert_eq!(e.to_string(), "duplicate key at line 2, column 1 (byte 6)");
    let e = err("x = 1\r\ny = 1.5");
    assert_eq!((e.line(), e.column(), e.offset()), (2, 5, 11));
    assert_eq!(e.kind(), ErrorKind::Unsupported(Feature::Float));
    assert_eq!(
        e.to_string(),
        "unsupported TOML feature: float at line 2, column 5 (byte 11)"
    );
    // Columns count bytes, not characters.
    let e = err("\"\u{e9}\u{e9}\" = [1.5]");
    assert_eq!((e.line(), e.column(), e.offset()), (1, 11, 10));
}

#[test]
fn every_feature_and_kind_has_a_name() {
    for (feature, name) in [
        (Feature::Float, "float"),
        (Feature::OffsetDateTime, "offset date-time"),
        (Feature::LocalDateTime, "local date-time"),
        (Feature::LocalDate, "local date"),
        (Feature::LocalTime, "local time"),
        (Feature::HexInteger, "hexadecimal integer"),
        (Feature::OctalInteger, "octal integer"),
        (Feature::BinaryInteger, "binary integer"),
    ] {
        assert_eq!(feature.name(), name);
    }
    let e = Limits::new(0, 1).expect_err("zero");
    assert_eq!(e.to_string(), "invalid limit");
    assert_eq!((e.line(), e.column(), e.offset()), (1, 1, 0));
    let e = parse(b"a = 1", &limits(2, 1)).expect_err("too large");
    assert_eq!(
        e.to_string(),
        "input too large at line 1, column 3 (byte 2)"
    );
    let src: &dyn std::error::Error = &e;
    assert!(src.source().is_none());
}
