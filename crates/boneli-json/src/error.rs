//! The one error type of the crate.
//!
//! An error carries its kind and position, never input bytes: request bodies
//! hold secrets, and errors get logged (ADR-008, D9).

use std::fmt;
use std::io;

/// What went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The input is longer than `Limits::max_bytes`.
    TooLarge,
    /// Arrays and objects nest deeper than `Limits::max_depth`, or a value
    /// to serialize nests deeper than `MAX_DEPTH`.
    TooDeep,
    /// The input holds more values than `Limits::max_values`.
    TooManyValues,
    /// The input ended inside a value, or holds no value.
    UnexpectedEnd,
    /// A byte that cannot start or continue a value here.
    UnexpectedByte,
    /// Something other than whitespace follows the value.
    TrailingData,
    /// The input is not UTF-8.
    InvalidUtf8,
    /// A backslash escape outside the eight short forms and `\uXXXX`.
    InvalidEscape,
    /// A `\u` escape of a surrogate that is not half of a high-low pair.
    LoneSurrogate,
    /// An unescaped U+0000 to U+001F inside a string.
    ControlCharacter,
    /// A number outside the RFC 8259 grammar.
    InvalidNumber,
    /// A key that already occurred in the same object.
    DuplicateKey,
    /// An NDJSON line is longer than `Limits::max_bytes`.
    LineTooLong,
    /// An NDJSON stream ended inside a line.
    UnterminatedLine,
    /// The underlying stream failed; `Error::source` holds its error.
    Io,
    /// A limit passed to `Limits::new` is zero, or `max_depth` is above
    /// `MAX_DEPTH`.
    InvalidLimit,
}

impl ErrorKind {
    fn describe(self) -> &'static str {
        match self {
            ErrorKind::TooLarge => "input too large",
            ErrorKind::TooDeep => "nesting too deep",
            ErrorKind::TooManyValues => "too many values",
            ErrorKind::UnexpectedEnd => "unexpected end of input",
            ErrorKind::UnexpectedByte => "unexpected byte",
            ErrorKind::TrailingData => "trailing data after the value",
            ErrorKind::InvalidUtf8 => "invalid UTF-8",
            ErrorKind::InvalidEscape => "invalid escape",
            ErrorKind::LoneSurrogate => "lone surrogate escape",
            ErrorKind::ControlCharacter => "unescaped control character in a string",
            ErrorKind::InvalidNumber => "invalid number",
            ErrorKind::DuplicateKey => "duplicate key",
            ErrorKind::LineTooLong => "line too long",
            ErrorKind::UnterminatedLine => "unterminated last line",
            ErrorKind::Io => "I/O error",
            ErrorKind::InvalidLimit => "invalid limit",
        }
    }
}

/// An error and where it was found.
///
/// `offset` is a byte offset into the input of `parse`, into the line for
/// NDJSON, into the lexeme for `Number::from_lexeme`, or into the output
/// written so far for the serializer; it is 0 for `InvalidLimit` and `Io`.
/// `line` is the 1-based line number for errors from `ndjson::Reader` and
/// `None` everywhere else.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    offset: usize,
    line: Option<u64>,
    io: Option<io::Error>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, offset: usize) -> Error {
        Error {
            kind,
            offset,
            line: None,
            io: None,
        }
    }

    pub(crate) fn io(e: io::Error) -> Error {
        Error {
            kind: ErrorKind::Io,
            offset: 0,
            line: None,
            io: Some(e),
        }
    }

    pub(crate) fn on_line(mut self, line: u64) -> Error {
        self.line = Some(line);
        self
    }

    /// What went wrong.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The byte offset (see the type's documentation).
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The 1-based NDJSON line, if the error came from `ndjson::Reader`.
    pub fn line(&self) -> Option<u64> {
        self.line
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.describe())?;
        if let Some(line) = self.line {
            write!(f, " on line {line}")?;
        }
        match &self.io {
            Some(e) => write!(f, ": {e}"),
            None if self.kind == ErrorKind::InvalidLimit => Ok(()),
            None => write!(f, " at byte {}", self.offset),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.io {
            Some(e) => Some(e),
            None => None,
        }
    }
}
