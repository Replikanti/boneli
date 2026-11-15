//! A strict RFC 8259 recursive-descent parser over bytes (ADR-008, D1-D5).

use crate::error::{Error, ErrorKind};
use crate::limits::Limits;
use crate::number::{Number, scan};
use crate::value::{Object, Value, by_key_then_index};

/// Parses one JSON value from `input`.
///
/// In this order: the input is at most `limits.max_bytes()` long
/// (`TooLarge` at offset `max_bytes`), it is UTF-8 (`InvalidUtf8` at the
/// first bad byte), and then it is one value with optional whitespace (SP,
/// HT, LF, CR) around it. Depth and value count are checked before each
/// value is read. Duplicate keys, lone surrogate escapes and a leading BOM
/// are errors; nothing is repaired.
pub fn parse(input: &[u8], limits: &Limits) -> Result<Value, Error> {
    if input.len() > limits.max_bytes() {
        return Err(Error::new(ErrorKind::TooLarge, limits.max_bytes()));
    }
    let text = match std::str::from_utf8(input) {
        Ok(text) => text,
        Err(e) => return Err(Error::new(ErrorKind::InvalidUtf8, e.valid_up_to())),
    };
    let mut p = Parser {
        text,
        bytes: input,
        pos: 0,
        max_depth: limits.max_depth(),
        values_left: limits.max_values(),
        key_offsets: Vec::new(),
        order: Vec::new(),
    };
    p.skip_ws();
    let value = p.value(0)?;
    p.skip_ws();
    if p.pos != input.len() {
        return Err(Error::new(ErrorKind::TrailingData, p.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    max_depth: usize,
    values_left: usize,
    /// The offset of every key of the objects being read, innermost last.
    key_offsets: Vec<usize>,
    /// Scratch space of the duplicate check.
    order: Vec<usize>,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn fail<T>(&self, kind: ErrorKind, at: usize) -> Result<T, Error> {
        Err(Error::new(kind, at))
    }

    /// `UnexpectedEnd` at the end of the input, `UnexpectedByte` elsewhere.
    fn unexpected<T>(&self) -> Result<T, Error> {
        match self.peek() {
            None => self.fail(ErrorKind::UnexpectedEnd, self.pos),
            Some(_) => self.fail(ErrorKind::UnexpectedByte, self.pos),
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// One value at `pos` (whitespace already skipped) inside containers
    /// nested `depth` deep.
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        let at = self.pos;
        let Some(first) = self.peek() else {
            return self.fail(ErrorKind::UnexpectedEnd, at);
        };
        if self.values_left == 0 {
            return self.fail(ErrorKind::TooManyValues, at);
        }
        self.values_left -= 1;
        match first {
            b'[' | b'{' => {
                if depth >= self.max_depth {
                    return self.fail(ErrorKind::TooDeep, at);
                }
                if first == b'[' {
                    self.array(depth + 1)
                } else {
                    self.object(depth + 1)
                }
            }
            b'"' => self.string().map(Value::String),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.number().map(Value::Number),
            _ => self.fail(ErrorKind::UnexpectedByte, at),
        }
    }

    #[inline(never)]
    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, Error> {
        for &expected in word {
            match self.peek() {
                Some(b) if b == expected => self.pos += 1,
                _ => return self.unexpected(),
            }
        }
        Ok(value)
    }

    #[inline(never)]
    fn number(&mut self) -> Result<Number, Error> {
        let start = self.pos;
        match scan(self.bytes, start) {
            Ok(end) => {
                self.pos = end;
                Ok(Number::from_lexeme_unchecked(&self.text[start..end]))
            }
            Err(at) => self.fail(ErrorKind::InvalidNumber, at),
        }
    }

    /// The elements of an array at `pos`, which nests `depth` deep.
    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b']') => {
                    self.pos += 1;
                    items.shrink_to_fit();
                    return Ok(Value::Array(items));
                }
                _ => return self.unexpected(),
            }
        }
    }

    /// The members of an object at `pos`, which nests `depth` deep.
    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        self.pos += 1;
        let base = self.key_offsets.len();
        let mut members = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(Object::new()));
        }
        loop {
            if self.peek() != Some(b'"') {
                return self.unexpected();
            }
            let key_at = self.pos;
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return self.unexpected();
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.value(depth)?;
            self.key_offsets.push(key_at);
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return self.unexpected(),
            }
        }
        self.check_duplicates(&members, base)?;
        self.key_offsets.truncate(base);
        members.shrink_to_fit();
        Ok(Value::Object(Object::from_distinct(members)))
    }

    /// `DuplicateKey` at the earliest key that repeats an earlier one, in
    /// O(m log m) comparisons: the member indices are sorted by key and
    /// position, so equal keys end up adjacent (ADR-008, D4).
    #[inline(never)]
    fn check_duplicates(&mut self, members: &[(String, Value)], base: usize) -> Result<(), Error> {
        if members.len() < 2 {
            return Ok(());
        }
        self.order.clear();
        self.order.extend(0..members.len());
        self.order
            .sort_unstable_by(|&a, &b| by_key_then_index(members, a, b));
        let second = self
            .order
            .windows(2)
            .filter(|pair| members[pair[0]].0 == members[pair[1]].0)
            .map(|pair| pair[1])
            .min();
        match second {
            Some(index) => self.fail(ErrorKind::DuplicateKey, self.key_offsets[base + index]),
            None => Ok(()),
        }
    }

    /// A string at `pos` (on its opening quote), unescaped.
    ///
    /// Its capacity never exceeds its encoding: a string without escapes
    /// is copied once at its exact length, and at the first escape the
    /// buffer reserves exactly the encoded length up to the closing quote,
    /// which the decoded string never outgrows (ADR-008, D5).
    #[inline(never)]
    fn string(&mut self) -> Result<String, Error> {
        let mut out = String::new();
        let mut i = self.pos + 1;
        let mut run = i;
        loop {
            match self.bytes.get(i) {
                None => return self.fail(ErrorKind::UnexpectedEnd, i),
                Some(b'"') => {
                    let tail = &self.text[run..i];
                    self.pos = i + 1;
                    if out.capacity() == 0 {
                        return Ok(tail.to_owned());
                    }
                    out.push_str(tail);
                    return Ok(out);
                }
                Some(b'\\') => {
                    if out.capacity() == 0 {
                        out.reserve_exact(self.closing_quote(i) - run);
                    }
                    out.push_str(&self.text[run..i]);
                    i = self.escape(i, &mut out)?;
                    run = i;
                }
                Some(0x00..=0x1f) => return self.fail(ErrorKind::ControlCharacter, i),
                Some(_) => i += 1,
            }
        }
    }

    /// The offset of the first unescaped quote at or after `from`, or the
    /// end of the input. It skips the byte after every backslash, and a
    /// UTF-8 continuation byte is never a quote or a backslash, so for a
    /// valid string this is the quote `string` stops at. For an invalid
    /// one `string` returns its error and drops the reservation, which the
    /// input's length bounds.
    fn closing_quote(&self, from: usize) -> usize {
        let mut i = from;
        while let Some(&b) = self.bytes.get(i) {
            match b {
                b'"' => return i,
                b'\\' => i += 2,
                _ => i += 1,
            }
        }
        self.bytes.len()
    }

    /// The escape whose backslash is at `at`; returns the offset after it.
    fn escape(&self, at: usize, out: &mut String) -> Result<usize, Error> {
        let short = match self.bytes.get(at + 1) {
            None => return self.fail(ErrorKind::UnexpectedEnd, at + 1),
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let unit = self.hex4(at)?;
                let c = match unit {
                    0xd800..=0xdbff => {
                        let next = at + 6;
                        if self.bytes.get(next..next + 2) != Some(b"\\u") {
                            return self.fail(ErrorKind::LoneSurrogate, at);
                        }
                        let low = self.hex4(next)?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return self.fail(ErrorKind::LoneSurrogate, at);
                        }
                        let code = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                        out.push(self.char_of(code, at)?);
                        return Ok(at + 12);
                    }
                    0xdc00..=0xdfff => return self.fail(ErrorKind::LoneSurrogate, at),
                    _ => self.char_of(unit, at)?,
                };
                out.push(c);
                return Ok(at + 6);
            }
            Some(_) => return self.fail(ErrorKind::InvalidEscape, at),
        };
        out.push(short);
        Ok(at + 2)
    }

    /// The four hex digits of the `\u` escape whose backslash is at `at`.
    fn hex4(&self, at: usize) -> Result<u32, Error> {
        let mut unit = 0;
        for i in at + 2..at + 6 {
            let digit = match self.bytes.get(i) {
                None => return self.fail(ErrorKind::UnexpectedEnd, i),
                Some(&b) => char::from(b).to_digit(16),
            };
            match digit {
                Some(d) => unit = unit * 16 + d,
                None => return self.fail(ErrorKind::InvalidEscape, at),
            }
        }
        Ok(unit)
    }

    /// The character `code`; every caller passes a scalar value, so the
    /// error is unreachable.
    fn char_of(&self, code: u32, at: usize) -> Result<char, Error> {
        match char::from_u32(code) {
            Some(c) => Ok(c),
            None => self.fail(ErrorKind::LoneSurrogate, at),
        }
    }
}
