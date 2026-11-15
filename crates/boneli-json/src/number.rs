//! Numbers keep their validated source text (ADR-008, D3).

use crate::error::{Error, ErrorKind};

/// A JSON number, stored as its lexeme.
///
/// Nothing is lost when a parsed number is serialized again: integers
/// above 2^53 and decimals with more digits than an `f64` holds come back
/// byte for byte. The accessors convert on demand.
///
/// Equality compares lexemes, so `1`, `1.0` and `1e0` are different
/// numbers, and so are `-0` and `0`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Number(Box<str>);

impl Number {
    /// A number from its text, which must match the RFC 8259 grammar
    /// exactly (no sign `+`, no leading zeros, no surrounding whitespace).
    /// The error is `InvalidNumber` at the offset of the first byte that
    /// does not fit.
    pub fn from_lexeme(lexeme: &str) -> Result<Number, Error> {
        match scan(lexeme.as_bytes(), 0) {
            Ok(end) if end == lexeme.len() => Ok(Number(lexeme.into())),
            Ok(end) | Err(end) => Err(Error::new(ErrorKind::InvalidNumber, end)),
        }
    }

    /// A lexeme the parser has already matched with `scan`.
    pub(crate) fn from_lexeme_unchecked(lexeme: &str) -> Number {
        Number(lexeme.into())
    }

    /// The shortest decimal form of a finite `f64` that reads back as the
    /// same bits, or `None` for NaN and the infinities.
    pub fn from_f64(value: f64) -> Option<Number> {
        if !value.is_finite() {
            return None;
        }
        let text = format!("{value:?}");
        let number = Number::from_lexeme(&text).ok()?;
        let back = number.as_f64()?;
        (back.to_bits() == value.to_bits()).then_some(number)
    }

    /// The lexeme.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the lexeme is an integer: no fraction and no exponent.
    pub fn is_integer(&self) -> bool {
        !self.0.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'))
    }

    /// The value as an `i64`, if the lexeme is an integer in range. `-0`
    /// gives 0; `1.0` and `1e2` give `None`.
    pub fn as_i64(&self) -> Option<i64> {
        if !self.is_integer() {
            return None;
        }
        self.0.parse().ok()
    }

    /// The value as a `u64`, if the lexeme is a non-negative integer in
    /// range. `-0` gives `None`.
    pub fn as_u64(&self) -> Option<u64> {
        if !self.is_integer() || self.0.starts_with('-') {
            return None;
        }
        self.0.parse().ok()
    }

    /// The nearest `f64`, if it is finite: `1e400` gives `None`, `1e-400`
    /// gives `Some(0.0)`.
    pub fn as_f64(&self) -> Option<f64> {
        let value: f64 = self.0.parse().ok()?;
        value.is_finite().then_some(value)
    }
}

impl From<i64> for Number {
    fn from(value: i64) -> Number {
        Number(value.to_string().into())
    }
}

impl From<u64> for Number {
    fn from(value: u64) -> Number {
        Number(value.to_string().into())
    }
}

/// Matches the RFC 8259 number grammar at `start`:
/// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
///
/// Returns the offset after the number, or the offset of the first byte
/// that cannot continue it (which may be `bytes.len()`). A digit after a
/// leading `0` is an error here rather than the start of trailing data.
pub(crate) fn scan(bytes: &[u8], start: usize) -> Result<usize, usize> {
    let at = |i: usize| bytes.get(i).copied();
    let digits = |mut i: usize| {
        while at(i).is_some_and(|b| b.is_ascii_digit()) {
            i += 1;
        }
        i
    };
    let mut i = start;
    if at(i) == Some(b'-') {
        i += 1;
    }
    match at(i) {
        Some(b'0') => {
            i += 1;
            if at(i).is_some_and(|b| b.is_ascii_digit()) {
                return Err(i);
            }
        }
        Some(b'1'..=b'9') => i = digits(i + 1),
        _ => return Err(i),
    }
    if at(i) == Some(b'.') {
        i += 1;
        if !at(i).is_some_and(|b| b.is_ascii_digit()) {
            return Err(i);
        }
        i = digits(i);
    }
    if matches!(at(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(at(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if !at(i).is_some_and(|b| b.is_ascii_digit()) {
            return Err(i);
        }
        i = digits(i);
    }
    Ok(i)
}
