//! A single-pass parser over bytes for the TOML 1.0 subset (ADR-011,
//! D1-D7). Strings and scalars are read here; which table a key or header
//! may create or extend is decided in `document`.

use std::borrow::Cow;

use crate::document::{Builder, Document, Fail, Origin, Segment};
use crate::error::{Error, ErrorKind, Feature};
use crate::limits::Limits;
use crate::value::{Table, Value};

/// Parses one TOML document from `input`.
///
/// In this order: the input is at most `limits.max_bytes()` long
/// (`TooLarge` at offset `max_bytes`), it is UTF-8 (`InvalidUtf8` at the
/// first bad byte), and then it is read in one pass. Depth is checked
/// before every table or array is created, so nothing is built past
/// `max_depth`. An over-deep bracket stops the read at that bracket. A
/// key is read whole first (a header up to its closing `]`), so a syntax
/// error later in an over-deep dotted key is reported instead of
/// `TooDeep`; a well-formed one is `TooDeep` at the offending segment.
/// A value of a type outside the subset is `Unsupported` at its first
/// byte.
pub fn parse(input: &[u8], limits: &Limits) -> Result<Table, Error> {
    if input.len() > limits.max_bytes() {
        return Err(Error::at(ErrorKind::TooLarge, limits.max_bytes(), input));
    }
    let text = match std::str::from_utf8(input) {
        Ok(text) => text,
        Err(e) => return Err(Error::at(ErrorKind::InvalidUtf8, e.valid_up_to(), input)),
    };
    let mut p = Parser {
        text,
        bytes: input,
        pos: 0,
        max_depth: limits.max_depth(),
    };
    let mut doc = Document::new();
    match p.document(&mut doc) {
        Ok(()) => Ok(doc.finish()),
        Err((kind, at)) => Err(Error::at(kind, at, input)),
    }
}

/// A control character for TOML 1.0: U+0000 to U+001F except tab, and
/// U+007F. Every one of them is a single byte in UTF-8.
fn is_control(b: u8) -> bool {
    (b < 0x20 && b != b'\t') || b == 0x7f
}

fn is_bare(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// The bytes a scalar token (integer, boolean, or an unsupported number or
/// date) may consist of.
fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-' | b'.' | b':')
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    max_depth: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn at(&self, i: usize) -> Option<u8> {
        self.bytes.get(i).copied()
    }

    /// `UnexpectedEnd` at the end of the input, `UnexpectedByte` elsewhere.
    fn unexpected<T>(&self, at: usize) -> Result<T, Fail> {
        match self.at(at) {
            None => Err((ErrorKind::UnexpectedEnd, at)),
            Some(_) => Err((ErrorKind::UnexpectedByte, at)),
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), Fail> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            self.unexpected(self.pos)
        }
    }

    /// The text from `from` to `to`; both are offsets of ASCII delimiters
    /// or the end of the input, so they are character boundaries.
    fn slice(&self, from: usize, to: usize) -> Result<&'a str, Fail> {
        match self.text.get(from..to) {
            Some(s) => Ok(s),
            None => Err((ErrorKind::InvalidUtf8, from)),
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    /// A newline at `i`: LF is 1 byte, CRLF 2, anything else 0.
    fn newline_at(&self, i: usize) -> usize {
        match (self.at(i), self.at(i + 1)) {
            (Some(b'\n'), _) => 1,
            (Some(b'\r'), Some(b'\n')) => 2,
            _ => 0,
        }
    }

    /// A comment at `pos` (on its `#`), up to but not including the
    /// newline that ends it.
    fn comment(&mut self) -> Result<(), Fail> {
        let mut i = self.pos + 1;
        while let Some(b) = self.at(i) {
            if b == b'\n' || self.newline_at(i) == 2 {
                break;
            }
            if is_control(b) {
                return Err((ErrorKind::ControlCharacter, i));
            }
            i += 1;
        }
        self.pos = i;
        Ok(())
    }

    /// Optional whitespace and a comment, then a newline or the end.
    fn line_end(&mut self) -> Result<(), Fail> {
        self.skip_ws();
        if self.peek() == Some(b'#') {
            self.comment()?;
        }
        if self.peek().is_none() {
            return Ok(());
        }
        match self.newline_at(self.pos) {
            0 => Err((ErrorKind::UnexpectedByte, self.pos)),
            n => {
                self.pos += n;
                Ok(())
            }
        }
    }

    /// Whitespace, comments and newlines, as between array elements.
    fn skip_blank(&mut self) -> Result<(), Fail> {
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b'#') => self.comment()?,
                Some(b'\n' | b'\r') => match self.newline_at(self.pos) {
                    0 => return Err((ErrorKind::UnexpectedByte, self.pos)),
                    n => self.pos += n,
                },
                _ => return Ok(()),
            }
        }
    }

    fn document(&mut self, doc: &mut Document<'a>) -> Result<(), Fail> {
        loop {
            self.skip_ws();
            match self.peek() {
                None => return Ok(()),
                Some(b'#' | b'\n' | b'\r') => {}
                Some(b'[') => self.header(doc)?,
                Some(_) => {
                    let (keys, parent) = self.key_eq(doc.current_depth())?;
                    let value = self.value(parent)?;
                    doc.current_table()?.insert_dotted(keys, value)?;
                }
            }
            self.line_end()?;
        }
    }

    /// `[key]` or `[[key]]` at `pos`.
    fn header(&mut self, doc: &mut Document<'a>) -> Result<(), Fail> {
        self.pos += 1;
        let array = self.peek() == Some(b'[');
        if array {
            self.pos += 1;
        }
        self.skip_ws();
        let keys = self.key()?;
        self.expect(b']')?;
        if array {
            self.expect(b']')?;
        }
        doc.header(keys, array, self.max_depth)
    }

    /// A dotted key at `pos`, and the whitespace after it.
    fn key(&mut self) -> Result<Vec<Segment<'a>>, Fail> {
        let mut keys = Vec::new();
        loop {
            let at = self.pos;
            let key = match self.peek() {
                Some(b'"') => self.basic_string()?,
                Some(b'\'') => self.literal_string()?,
                _ => {
                    let mut end = at;
                    while self.at(end).is_some_and(is_bare) {
                        end += 1;
                    }
                    if end == at {
                        return self.unexpected(at);
                    }
                    self.pos = end;
                    Cow::Borrowed(self.slice(at, end)?)
                }
            };
            keys.push((key, at));
            self.skip_ws();
            if self.peek() != Some(b'.') {
                return Ok(keys);
            }
            self.pos += 1;
            self.skip_ws();
        }
    }

    /// `key =` at `pos` and the whitespace after it, for a table `depth`
    /// deep; returns the key and the depth of the table that holds its
    /// value. The tables the dotted key passes are checked against
    /// `max_depth` before the value is read: segment i (from 0) of n is a
    /// table at `depth + 1 + i`, so the value's own containers start at
    /// `depth + n`. Out of line, so that its locals stay out of the frames
    /// that recurse through inline tables (ADR-011, D6).
    #[inline(never)]
    fn key_eq(&mut self, depth: usize) -> Result<(Vec<Segment<'a>>, usize), Fail> {
        let keys = self.key()?;
        let tables = keys.len().saturating_sub(1);
        for (i, (_, at)) in keys.iter().take(tables).enumerate() {
            if depth + 1 + i > self.max_depth {
                return Err((ErrorKind::TooDeep, *at));
            }
        }
        self.expect(b'=')?;
        self.skip_ws();
        Ok((keys, depth + tables))
    }

    /// One value at `pos` in a table or array `parent` deep.
    fn value(&mut self, parent: usize) -> Result<Value, Fail> {
        let at = self.pos;
        match self.peek() {
            None => Err((ErrorKind::UnexpectedEnd, at)),
            Some(b'"') => {
                if self.bytes[at..].starts_with(b"\"\"\"") {
                    self.multiline_basic()
                        .map(|s| Value::String(s.into_owned()))
                } else {
                    self.basic_string().map(|s| Value::String(s.into_owned()))
                }
            }
            Some(b'\'') => {
                if self.bytes[at..].starts_with(b"'''") {
                    self.multiline_literal()
                        .map(|s| Value::String(s.into_owned()))
                } else {
                    self.literal_string().map(|s| Value::String(s.into_owned()))
                }
            }
            Some(open @ (b'[' | b'{')) => {
                if parent >= self.max_depth {
                    return Err((ErrorKind::TooDeep, at));
                }
                if open == b'[' {
                    self.array(parent + 1)
                } else {
                    self.inline_table(parent + 1)
                }
            }
            Some(_) => self.scalar(),
        }
    }

    /// An array at `pos`, which is `depth` deep.
    fn array(&mut self, depth: usize) -> Result<Value, Fail> {
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_blank()?;
            if self.peek() == Some(b']') {
                self.pos += 1;
                break;
            }
            items.push(self.value(depth)?);
            self.skip_blank()?;
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return self.unexpected(self.pos),
            }
        }
        items.shrink_to_fit();
        Ok(Value::Array(items))
    }

    /// An inline table at `pos`, which is `depth` deep: one line, no
    /// trailing comma, closed for good at its `}`.
    fn inline_table(&mut self, depth: usize) -> Result<Value, Fail> {
        self.pos += 1;
        self.skip_ws();
        let mut table: Builder<'a> = Builder::new(Origin::Dotted);
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Table(Table::new()));
        }
        loop {
            let (keys, parent) = self.key_eq(depth)?;
            let value = self.value(parent)?;
            table.insert_dotted(keys, value)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Table(table.finish()));
                }
                _ => return self.unexpected(self.pos),
            }
        }
    }

    /// An integer or boolean at `pos`, or the `Unsupported` error of a
    /// float, date, time or radix integer. The token is classified as a
    /// whole before any of it is read as an integer (ADR-011, D1).
    #[inline(never)]
    fn scalar(&mut self) -> Result<Value, Fail> {
        let start = self.pos;
        let mut end = start;
        while self.at(end).is_some_and(is_token) {
            end += 1;
        }
        let tok = &self.bytes[start..end];
        let unsupported = |f| Err((ErrorKind::Unsupported(f), start));
        let (signed, body) = match tok.split_first() {
            None => return self.unexpected(start),
            Some((b'+' | b'-', rest)) => (true, rest),
            Some(_) => (false, tok),
        };
        if tok == b"true" || tok == b"false" {
            self.pos = end;
            return Ok(Value::Boolean(tok == b"true"));
        }
        if body == b"inf" || body == b"nan" {
            return unsupported(Feature::Float);
        }
        if !signed {
            match tok {
                [b'0', b'x', ..] => return unsupported(Feature::HexInteger),
                [b'0', b'o', ..] => return unsupported(Feature::OctalInteger),
                [b'0', b'b', ..] => return unsupported(Feature::BinaryInteger),
                [a, b, c, d, b'-', ..] if [a, b, c, d].iter().all(|x| x.is_ascii_digit()) => {
                    return unsupported(self.date_feature(tok, end));
                }
                [a, b, b':', ..] if a.is_ascii_digit() && b.is_ascii_digit() => {
                    return unsupported(Feature::LocalTime);
                }
                _ => {}
            }
        }
        let numeric = body.first().is_some_and(u8::is_ascii_digit);
        if numeric && body.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) {
            return unsupported(Feature::Float);
        }
        if !numeric && !signed {
            return Err((ErrorKind::UnexpectedByte, start));
        }
        let value = integer(tok).map_err(|kind| (kind, start))?;
        self.pos = end;
        Ok(Value::Integer(value))
    }

    /// Which date or time type the token `tok`, which starts with
    /// `DDDD-` and ends at `end`, would be: a time after `T`, `t` or a
    /// space makes it a date-time, and a `Z`, `z`, `+` or `-` in the time
    /// gives it an offset.
    fn date_feature(&self, tok: &[u8], end: usize) -> Feature {
        let time = match tok.get(10) {
            Some(b'T' | b't') => &tok[11..],
            None if self.at(end) == Some(b' ')
                && self.at(end + 1).is_some_and(|b| b.is_ascii_digit())
                && self.at(end + 2).is_some_and(|b| b.is_ascii_digit())
                && self.at(end + 3) == Some(b':') =>
            {
                let mut stop = end + 1;
                while self.at(stop).is_some_and(is_token) {
                    stop += 1;
                }
                &self.bytes[end + 1..stop]
            }
            _ => return Feature::LocalDate,
        };
        if time.iter().any(|b| matches!(b, b'Z' | b'z' | b'+' | b'-')) {
            Feature::OffsetDateTime
        } else {
            Feature::LocalDateTime
        }
    }

    /// A basic string at `pos` (on its opening quote), unescaped.
    ///
    /// Its capacity never exceeds its encoding: a string without escapes is
    /// copied once at its exact length, and at the first escape the buffer
    /// reserves exactly the encoded length up to the closing quote, which
    /// the decoded string never outgrows (ADR-011, D5).
    #[inline(never)]
    fn basic_string(&mut self) -> Result<Cow<'a, str>, Fail> {
        let mut out = String::new();
        let mut i = self.pos + 1;
        let mut run = i;
        loop {
            match self.at(i) {
                None => return Err((ErrorKind::UnexpectedEnd, i)),
                Some(b'"') => {
                    let tail = self.slice(run, i)?;
                    self.pos = i + 1;
                    return Ok(finish(out, tail));
                }
                Some(b'\\') => {
                    if out.capacity() == 0 {
                        out.reserve_exact(self.closing(i, b'"', false) - run);
                    }
                    out.push_str(self.slice(run, i)?);
                    i = self.escape(i, &mut out)?;
                    run = i;
                }
                Some(b) if is_control(b) => return Err((ErrorKind::ControlCharacter, i)),
                Some(_) => i += 1,
            }
        }
    }

    /// A multi-line basic string at `pos` (on its first quote).
    #[inline(never)]
    fn multiline_basic(&mut self) -> Result<Cow<'a, str>, Fail> {
        let mut out = String::new();
        let mut i = self.pos + 3;
        i += self.newline_at(i);
        let mut run = i;
        loop {
            match self.at(i) {
                None => return Err((ErrorKind::UnexpectedEnd, i)),
                Some(b'"') => {
                    let quotes = self.run_of(i, b'"');
                    if quotes >= 3 {
                        // Up to two quotes before the closing delimiter
                        // belong to the string; a sixth is left over.
                        let end = i + quotes.min(5) - 3;
                        let tail = self.slice(run, end)?;
                        self.pos = end + 3;
                        return Ok(finish(out, tail));
                    }
                    i += quotes;
                }
                Some(b'\\') => {
                    if out.capacity() == 0 {
                        out.reserve_exact(self.closing(i, b'"', true) - run);
                    }
                    out.push_str(self.slice(run, i)?);
                    let mut j = i + 1;
                    while matches!(self.at(j), Some(b' ' | b'\t')) {
                        j += 1;
                    }
                    if self.newline_at(j) > 0 {
                        // A line-ending backslash: drop it and every
                        // space, tab and newline after it.
                        loop {
                            match self.at(j) {
                                Some(b' ' | b'\t' | b'\n') => j += 1,
                                Some(b'\r') if self.newline_at(j) == 2 => j += 2,
                                _ => break,
                            }
                        }
                        i = j;
                    } else {
                        i = self.escape(i, &mut out)?;
                    }
                    run = i;
                }
                Some(b'\r') => {
                    i = self.crlf(i, run, &mut out, b'"')?;
                    run = i;
                }
                Some(b'\n') => i += 1,
                Some(b) if is_control(b) => return Err((ErrorKind::ControlCharacter, i)),
                Some(_) => i += 1,
            }
        }
    }

    /// A literal string at `pos` (on its opening quote).
    #[inline(never)]
    fn literal_string(&mut self) -> Result<Cow<'a, str>, Fail> {
        let start = self.pos + 1;
        let mut i = start;
        loop {
            match self.at(i) {
                None => return Err((ErrorKind::UnexpectedEnd, i)),
                Some(b'\'') => {
                    self.pos = i + 1;
                    return Ok(Cow::Borrowed(self.slice(start, i)?));
                }
                Some(b) if is_control(b) => return Err((ErrorKind::ControlCharacter, i)),
                Some(_) => i += 1,
            }
        }
    }

    /// A multi-line literal string at `pos` (on its first quote).
    #[inline(never)]
    fn multiline_literal(&mut self) -> Result<Cow<'a, str>, Fail> {
        let mut out = String::new();
        let mut i = self.pos + 3;
        i += self.newline_at(i);
        let mut run = i;
        loop {
            match self.at(i) {
                None => return Err((ErrorKind::UnexpectedEnd, i)),
                Some(b'\'') => {
                    let quotes = self.run_of(i, b'\'');
                    if quotes >= 3 {
                        let end = i + quotes.min(5) - 3;
                        let tail = self.slice(run, end)?;
                        self.pos = end + 3;
                        return Ok(finish(out, tail));
                    }
                    i += quotes;
                }
                Some(b'\r') => {
                    i = self.crlf(i, run, &mut out, b'\'')?;
                    run = i;
                }
                Some(b'\n') => i += 1,
                Some(b) if is_control(b) => return Err((ErrorKind::ControlCharacter, i)),
                Some(_) => i += 1,
            }
        }
    }

    /// The CRLF at `i` in a multi-line string read since `run`: it reads as
    /// LF, so the text before it is copied and an LF appended. A CR without
    /// LF is a control character. Returns the offset after the CRLF.
    fn crlf(&self, i: usize, run: usize, out: &mut String, quote: u8) -> Result<usize, Fail> {
        if self.newline_at(i) != 2 {
            return Err((ErrorKind::ControlCharacter, i));
        }
        if out.capacity() == 0 {
            out.reserve_exact(self.closing(i, quote, true) - run);
        }
        out.push_str(self.slice(run, i)?);
        out.push('\n');
        Ok(i + 2)
    }

    /// The escape whose backslash is at `at`; returns the offset after it.
    /// TOML 1.0 has the short forms `\b \t \n \f \r \" \\`, `\uXXXX` and
    /// `\UXXXXXXXX` for Unicode scalar values only (ADR-011, D1).
    fn escape(&self, at: usize, out: &mut String) -> Result<usize, Fail> {
        let short = match self.at(at + 1) {
            None => return Err((ErrorKind::UnexpectedEnd, at + 1)),
            Some(b'b') => '\u{8}',
            Some(b't') => '\t',
            Some(b'n') => '\n',
            Some(b'f') => '\u{c}',
            Some(b'r') => '\r',
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'u') => return self.unicode(at, 4, out),
            Some(b'U') => return self.unicode(at, 8, out),
            Some(_) => return Err((ErrorKind::InvalidEscape, at)),
        };
        out.push(short);
        Ok(at + 2)
    }

    /// The `digits` hex digits of the `\u` or `\U` escape at `at`.
    fn unicode(&self, at: usize, digits: usize, out: &mut String) -> Result<usize, Fail> {
        let mut code: u32 = 0;
        for i in at + 2..at + 2 + digits {
            let digit = match self.at(i) {
                None => return Err((ErrorKind::UnexpectedEnd, i)),
                Some(b) => char::from(b).to_digit(16),
            };
            match digit {
                Some(d) => code = (code << 4) | d,
                None => return Err((ErrorKind::InvalidEscape, at)),
            }
        }
        match char::from_u32(code) {
            Some(c) => {
                out.push(c);
                Ok(at + 2 + digits)
            }
            None => Err((ErrorKind::InvalidEscape, at)),
        }
    }

    /// How many `quote` bytes follow one another from `i`.
    fn run_of(&self, i: usize, quote: u8) -> usize {
        self.bytes[i..].iter().take_while(|&&b| b == quote).count()
    }

    /// An upper bound for the end of the content of the string delimited
    /// by `quote` that `from` is in: the first closing quote of a
    /// single-line string, or two bytes after the first `"""` or `'''` of a
    /// multi-line one (which may close two content quotes later), at most
    /// the end of the input. In basic strings it skips the byte after every
    /// backslash as the decoder does, and a UTF-8 continuation byte is
    /// never a quote or a backslash, so a valid string's content ends at or
    /// before it. For an invalid one the decoder returns its error and
    /// drops the reservation, which the input's length bounds.
    fn closing(&self, from: usize, quote: u8, multiline: bool) -> usize {
        let len = self.bytes.len();
        let mut i = from;
        while let Some(b) = self.at(i) {
            if b == b'\\' && quote == b'"' {
                i += 2;
            } else if b == quote && !multiline {
                return i;
            } else if b == quote && self.run_of(i, quote) >= 3 {
                return (i + 2).min(len);
            } else {
                i += 1;
            }
        }
        len
    }
}

/// The decoded string: `tail`, borrowed, if nothing was decoded before
/// it, so a copy made later has its exact length.
fn finish(mut out: String, tail: &str) -> Cow<'_, str> {
    if out.capacity() == 0 {
        return Cow::Borrowed(tail);
    }
    out.push_str(tail);
    Cow::Owned(out)
}

/// A decimal integer token: an optional sign, then `0` or a digit other
/// than `0` followed by digits with single underscores between them. The
/// value is accumulated negatively, so `i64::MIN` fits (ADR-011, D7).
fn integer(tok: &[u8]) -> Result<i64, ErrorKind> {
    let (negative, digits) = match tok.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, tok),
    };
    if digits.len() > 1 && digits[0] == b'0' {
        return Err(ErrorKind::InvalidInteger);
    }
    let mut after_digit = false;
    let mut acc: Option<i64> = Some(0);
    for &b in digits {
        match b {
            b'0'..=b'9' => {
                after_digit = true;
                acc = acc
                    .and_then(|a| a.checked_mul(10))
                    .and_then(|a| a.checked_sub(i64::from(b - b'0')));
            }
            b'_' if after_digit => after_digit = false,
            _ => return Err(ErrorKind::InvalidInteger),
        }
    }
    if !after_digit {
        return Err(ErrorKind::InvalidInteger);
    }
    match acc {
        Some(a) if negative => Ok(a),
        Some(a) => a.checked_neg().ok_or(ErrorKind::IntegerOutOfRange),
        None => Err(ErrorKind::IntegerOutOfRange),
    }
}
