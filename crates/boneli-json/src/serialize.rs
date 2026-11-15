//! A compact, deterministic serializer (ADR-008, D7).

use crate::error::{Error, ErrorKind};
use crate::limits::MAX_DEPTH;
use crate::value::Value;

/// Serializes `value` as compact JSON: no whitespace, object members in
/// their stored order, numbers as their lexemes, so the same value always
/// gives the same bytes.
///
/// Strings escape exactly `"`, `\` and U+0000 to U+001F (`\b \f \n \r \t`
/// where they exist, lowercase `\u00xx` otherwise) and keep every other
/// character as UTF-8, so the output never contains a raw line feed. A
/// value that nests deeper than `MAX_DEPTH` is `TooDeep`, checked before
/// the serializer descends.
pub fn to_string(value: &Value) -> Result<String, Error> {
    let mut out = String::new();
    write_value(&mut out, value, 0)?;
    Ok(out)
}

/// `to_string` as bytes.
pub fn to_vec(value: &Value) -> Result<Vec<u8>, Error> {
    to_string(value).map(String::into_bytes)
}

fn write_value(out: &mut String, value: &Value, depth: usize) -> Result<(), Error> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(n.as_str()),
        Value::String(s) => write_str(out, s),
        Value::Array(items) => {
            if depth >= MAX_DEPTH {
                return Err(Error::new(ErrorKind::TooDeep, out.len()));
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            if depth >= MAX_DEPTH {
                return Err(Error::new(ErrorKind::TooDeep, out.len()));
            }
            out.push('{');
            for (i, (key, item)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(out, key);
                out.push(':');
                write_value(out, item, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[inline(never)]
fn write_str(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    let mut run = 0;
    for (i, b) in s.bytes().enumerate() {
        let short = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            0x08 => "\\b",
            0x09 => "\\t",
            0x0a => "\\n",
            0x0c => "\\f",
            0x0d => "\\r",
            0x00..=0x1f => "",
            _ => continue,
        };
        out.push_str(&s[run..i]);
        if short.is_empty() {
            out.push_str("\\u00");
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0xf)]));
        } else {
            out.push_str(short);
        }
        run = i + 1;
    }
    out.push_str(&s[run..]);
    out.push('"');
}
