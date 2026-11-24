//! The canonical form (ADR-033, item 4): sorted keys, no whitespace, only
//! `\` and `"` escaped, control characters raw, integers only. The real
//! Sigstore signatures are the known answers: they verify over our bytes
//! only if every rule matches the one the repository signed with.

mod support;

use boneli_https::PublicKey;
use boneli_json::{Limits, Object, Value};
use boneli_tuf::{Error, canonical};
use support::real;
use support::repo::{RootBuilder, START, obj, s, set, signed_by};

fn parse(bytes: &[u8]) -> Value {
    let limits = Limits::new(1 << 20, 64, 1 << 16).expect("limits");
    boneli_json::parse(bytes, &limits).expect("JSON")
}

fn canon(text: &str) -> Result<Vec<u8>, Error> {
    canonical(&parse(text.as_bytes()))
}

/// Every real root from v5 to v16: at least the root threshold (3) of the
/// signatures over our canonical bytes verify under the root's own keys,
/// checked here with `PublicKey` directly, not through the crate's
/// threshold code. The PEM keys hold line feeds, so this proves control
/// characters are written raw.
#[test]
fn canonical_matches_sigstore_signatures() {
    for version in 5..=16 {
        let doc = parse(real::root(version));
        let signed = doc.get("signed").expect("signed");
        let bytes = canonical(signed).expect("canonical");
        let keys = signed.get("keys").and_then(Value::as_object).expect("keys");
        let mut verified = 0;
        for sig in doc
            .get("signatures")
            .and_then(Value::as_array)
            .expect("sigs")
        {
            let id = sig.get("keyid").and_then(Value::as_str).expect("keyid");
            let hex = sig.get("sig").and_then(Value::as_str).expect("sig");
            let Some(entry) = keys.get(id) else { continue };
            let pem = entry
                .get("keyval")
                .and_then(|k| k.get("public"))
                .and_then(Value::as_str)
                .expect("public");
            let key = PublicKey::from_pem(pem.as_bytes()).expect("P-256 PEM");
            let sig: Vec<u8> = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
                .collect();
            if key.verify(&bytes, &sig).is_ok() {
                verified += 1;
            }
        }
        assert!(verified >= 3, "v{version}: {verified} signatures verify");
        // The PEM line feeds are in the signed bytes as raw 0x0A.
        assert!(bytes.contains(&b'\n'), "v{version}");
        assert!(!bytes.windows(2).any(|w| w == b"\\n"), "v{version}");
    }
}

/// Keys sort by code point. Rust's `str` order is UTF-8 byte order, which
/// is code point order; UTF-16 order would put U+1F600 (a surrogate pair,
/// 0xD83D...) before U+FF61.
#[test]
fn canonical_sorts_by_code_point() {
    let mut o = Object::new();
    for key in ["\u{1F600}", "\u{FF61}", "a", "B", "", "aa", "\u{e9}"] {
        o.insert(key, Value::from(1i64));
    }
    let bytes = canonical(&Value::Object(o)).expect("canonical");
    assert_eq!(
        String::from_utf8(bytes).expect("UTF-8"),
        "{\"\":1,\"B\":1,\"a\":1,\"aa\":1,\"\u{e9}\":1,\"\u{FF61}\":1,\"\u{1F600}\":1}"
    );
}

/// Exact bytes for each rule: no whitespace, nested objects sorted, only
/// `"` and `\` escaped, `/`, control characters and non-ASCII raw.
#[test]
fn canonical_exact_bytes() {
    let cases: [(&str, &[u8]); 7] = [
        (
            r#" { "b" : [ 1 , true , null , false ] , "a" : { "z" : {} , "y" : [] } } "#,
            br#"{"a":{"y":[],"z":{}},"b":[1,true,null,false]}"#,
        ),
        (r#""x\"y\\z""#, br#""x\"y\\z""#),
        (r#""a\/b""#, b"\"a/b\""),
        (r#""\n\t\r\b\f\u0000\u001f""#, b"\"\n\t\r\x08\x0c\x00\x1f\""),
        (
            r#""\u00e9\u20ac\ud83d\ude00""#,
            "\"\u{e9}\u{20ac}\u{1F600}\"".as_bytes(),
        ),
        ("-9223372036854775808", b"-9223372036854775808"),
        ("[0,-1,9223372036854775807]", b"[0,-1,9223372036854775807]"),
    ];
    for (input, want) in cases {
        assert_eq!(canon(input).expect(input), want, "{input}");
    }
}

/// Fractions, exponents, `-0` and integers outside `i64` refuse the
/// document, wherever they sit, and so does a root that carries one in
/// `signed`.
#[test]
fn canonical_refuses_non_integers() {
    for input in [
        "1.0",
        "1e3",
        "1E3",
        "0.5",
        "-0",
        "1e-1",
        "9223372036854775808",
        "-9223372036854775809",
        "[1,2,{\"a\":[3.5]}]",
        "{\"a\":{\"b\":-0}}",
    ] {
        assert_eq!(canon(input), Err(Error::NotCanonical), "{input}");
    }
    for extra in ["1.0", "1e3", "-0"] {
        let mut signed = RootBuilder::new(1).signed();
        set(&mut signed, "x-extra", parse(extra.as_bytes()));
        // The signer cannot even form the bytes; build the envelope from
        // a signature over the document without the member.
        let mut plain = signed.clone();
        support::repo::remove(&mut plain, "x-extra");
        let sigs = [1, 2, 3]
            .iter()
            .map(|n| support::repo::signature(*n, &plain))
            .collect();
        let bytes = support::repo::envelope(&signed, sigs);
        assert_eq!(
            boneli_tuf::TrustedSet::new(&bytes, START).err(),
            Some(Error::NotCanonical),
            "{extra}"
        );
    }
    // An integer extra member is signed like any other field.
    let mut signed = RootBuilder::new(1).signed();
    set(&mut signed, "x-extra", Value::from(-5i64));
    let bytes = signed_by(&signed, &[1, 2, 3]);
    assert!(boneli_tuf::TrustedSet::new(&bytes, START).is_ok());
}

/// The output is never longer than the JSON it came from: escapes shrink
/// or stay, whitespace goes, numbers keep their lexeme.
#[test]
fn canonical_no_amplification() {
    let mut inputs: Vec<Vec<u8>> = (5..=16)
        .map(|v| {
            let doc = parse(real::root(v));
            boneli_json::to_vec(doc.get("signed").expect("signed")).expect("serialize")
        })
        .collect();
    inputs.extend(
        [
            r#"{"a":"\u00e9\n\/\"\\","b":[1,-2,"\u0000"]}"#,
            r#""\"\"\"\"\\\\""#,
            r#"[[],{},"",0]"#,
        ]
        .map(|s| s.as_bytes().to_vec()),
    );
    for input in inputs {
        let out = canonical(&parse(&input)).expect("canonical");
        assert!(out.len() <= input.len(), "{} > {}", out.len(), input.len());
    }
}

/// For strings without control characters the canonical form is JSON
/// again, and canonical of canonical gives equal bytes.
#[test]
fn canonical_idempotent() {
    let value = obj([
        ("zeta", s("x\"y\\z/\u{e9}\u{1F600}")),
        ("alpha", Value::Array(vec![Value::from(0i64), Value::Null])),
        ("mid", obj([("b", Value::Bool(true)), ("a", obj([]))])),
    ]);
    let once = canonical(&value).expect("canonical");
    let reparsed = parse(&once);
    let twice = canonical(&reparsed).expect("canonical");
    assert_eq!(once, twice);
    // Sigstore's v16 without its PEM line feeds (keys dropped).
    let mut signed = parse(real::root(16)).get("signed").expect("signed").clone();
    set(&mut signed, "keys", obj([]));
    let once = canonical(&signed).expect("canonical");
    assert_eq!(canonical(&parse(&once)).expect("canonical"), once);
}

/// A hand-built value deeper than the JSON crate's ceiling is refused
/// instead of overflowing the stack.
#[test]
fn canonical_refuses_values_too_deep() {
    let mut value = Value::Null;
    for _ in 0..boneli_json::MAX_DEPTH {
        value = Value::Array(vec![value]);
    }
    assert!(canonical(&value).is_ok(), "at the ceiling");
    let deeper = Value::Array(vec![value]);
    assert_eq!(canonical(&deeper), Err(Error::NotCanonical));
}
