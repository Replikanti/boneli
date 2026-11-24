//! Typed reads from `boneli-json` values. A missing member and a member
//! of the wrong type are the same: `None`, which every caller turns into
//! its own fixed refusal.

use boneli_json::{Limits, Value};

use crate::{MAX_JSON_DEPTH, MAX_JSON_VALUES};

/// Parses `bytes` as one JSON value of at most `max_bytes`, with the
/// crate's depth and value limits.
pub(crate) fn parse(bytes: &[u8], max_bytes: usize) -> Option<Value> {
    let limits = Limits::new(max_bytes, MAX_JSON_DEPTH, MAX_JSON_VALUES).ok()?;
    boneli_json::parse(bytes, &limits).ok()
}

/// The object member `key` if it is an object.
pub(crate) fn object<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get(key).filter(|v| v.as_object().is_some())
}

/// The object member `key` if it is a string.
pub(crate) fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key)?.as_str()
}

/// The object member `key` if it is an array.
pub(crate) fn array<'a>(value: &'a Value, key: &str) -> Option<&'a [Value]> {
    value.get(key)?.as_array()
}

/// The object member `key` as canonical base64, decoded.
pub(crate) fn base64(value: &Value, key: &str) -> Option<Vec<u8>> {
    crate::base64::decode(string(value, key)?.as_bytes())
}

/// The object member `key` as a JSON integer from 0 to `i64::MAX`.
pub(crate) fn integer(value: &Value, key: &str) -> Option<u64> {
    let n = value.get(key)?.as_number()?.as_u64()?;
    (n <= i64::MAX as u64).then_some(n)
}

/// The object member `key` as protobuf JSON's int64 string: canonical
/// decimal digits (no sign, no leading zero), from 0 to `i64::MAX`.
pub(crate) fn decimal(value: &Value, key: &str) -> Option<u64> {
    let text = string(value, key)?;
    let b = text.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
        return None;
    }
    let n: u64 = text.parse().ok()?;
    (n <= i64::MAX as u64).then_some(n)
}
