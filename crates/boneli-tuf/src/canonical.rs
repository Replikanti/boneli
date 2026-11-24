//! The canonical form TUF metadata is signed over (ADR-033, item 4), as
//! securesystemslib's `encode_canonical` writes it and Sigstore's
//! repository signs it:
//!
//! - object keys sorted by code point (Rust's `str` order, which is UTF-8
//!   byte order and so code point order), no whitespace anywhere;
//! - strings with only `\` and `"` escaped, every other character written
//!   raw, control characters (the line feeds of PEM keys) included;
//! - integers as their lexemes; a fraction, an exponent or `-0` has no
//!   canonical form and is refused, and so is an integer outside `i64`.
//!
//! The output is never longer than the JSON the value was parsed from:
//! escapes only shrink, whitespace goes and lexemes stay.

use boneli_json::{MAX_DEPTH, Number, Value};

use crate::Error;

/// The canonical bytes of `value`, or [`Error::NotCanonical`] when it holds
/// a number that is not a canonical integer within `i64` or nests deeper
/// than `boneli_json::MAX_DEPTH`, which keeps a hand-built value inside
/// the stack.
pub fn canonical(value: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    write(value, &mut out, 0)?;
    Ok(out)
}

/// Whether `n` is a canonical integer: the lexeme is `0` or
/// `-?[1-9][0-9]*` (the JSON grammar already refuses leading zeros and a
/// `+`), not `-0`, and within `i64`.
pub(crate) fn is_canonical_integer(n: &Number) -> bool {
    n.is_integer() && n.as_str() != "-0" && n.as_i64().is_some()
}

fn write(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), Error> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if !is_canonical_integer(n) {
                return Err(Error::NotCanonical);
            }
            out.extend_from_slice(n.as_str().as_bytes());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            if depth >= MAX_DEPTH {
                return Err(Error::NotCanonical);
            }
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(item, out, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(o) => {
            if depth >= MAX_DEPTH {
                return Err(Error::NotCanonical);
            }
            let mut members: Vec<(&str, &Value)> = o.iter().collect();
            // Keys of an `Object` are distinct, so the order is total.
            members.sort_unstable_by(|a, b| a.0.cmp(b.0));
            out.push(b'{');
            for (i, (key, member)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write(member, out, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for &b in s.as_bytes() {
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out.push(b'"');
}
