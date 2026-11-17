//! The one error type of the crate.
//!
//! An error carries its kind and position, never input bytes: configuration
//! can hold credentials, and errors get logged (ADR-011, D8).

use std::fmt;

/// A TOML 1.0 feature outside the subset (ADR-011, D1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Feature {
    /// A float, `inf` and `nan` included.
    Float,
    /// A date and time with an offset, `1979-05-27T07:32:00Z`.
    OffsetDateTime,
    /// A date and time without an offset, `1979-05-27T07:32:00`.
    LocalDateTime,
    /// A date, `1979-05-27`.
    LocalDate,
    /// A time of day, `07:32:00`.
    LocalTime,
    /// An integer with the `0x` prefix.
    HexInteger,
    /// An integer with the `0o` prefix.
    OctalInteger,
    /// An integer with the `0b` prefix.
    BinaryInteger,
}

impl Feature {
    /// The feature's name in lower case, as `Display` of an error shows it.
    pub fn name(self) -> &'static str {
        match self {
            Feature::Float => "float",
            Feature::OffsetDateTime => "offset date-time",
            Feature::LocalDateTime => "local date-time",
            Feature::LocalDate => "local date",
            Feature::LocalTime => "local time",
            Feature::HexInteger => "hexadecimal integer",
            Feature::OctalInteger => "octal integer",
            Feature::BinaryInteger => "binary integer",
        }
    }
}

/// What went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The input is longer than `Limits::max_bytes`.
    TooLarge,
    /// Tables and arrays nest deeper than `Limits::max_depth`.
    TooDeep,
    /// A limit passed to `Limits::new` is zero, or `max_depth` is above
    /// `MAX_DEPTH`.
    InvalidLimit,
    /// The input is not UTF-8.
    InvalidUtf8,
    /// A byte that cannot start or continue anything here.
    UnexpectedByte,
    /// The input ended inside a key, a value, a header or a string.
    UnexpectedEnd,
    /// A control character other than tab inside a string or a comment, or
    /// a newline inside a single-line string.
    ControlCharacter,
    /// A backslash escape outside the TOML 1.0 forms, or one that names a
    /// surrogate or a code point above U+10FFFF.
    InvalidEscape,
    /// A decimal integer with a leading zero, a misplaced underscore or a
    /// character that is not a digit.
    InvalidInteger,
    /// A decimal integer outside the range of `i64`.
    IntegerOutOfRange,
    /// A key that already holds a value in the same table.
    DuplicateKey,
    /// A header for a table or array of tables that is already defined,
    /// or for a key that holds another kind of value.
    DuplicateTable,
    /// A header or dotted key that would add to a value that cannot take
    /// members: a scalar, an inline table, a static array, or a table
    /// that the other form of definition owns.
    NotExtensible,
    /// A value of a TOML 1.0 type outside the subset.
    Unsupported(Feature),
}

impl ErrorKind {
    fn describe(self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            ErrorKind::TooLarge => "input too large",
            ErrorKind::TooDeep => "nesting too deep",
            ErrorKind::InvalidLimit => "invalid limit",
            ErrorKind::InvalidUtf8 => "invalid UTF-8",
            ErrorKind::UnexpectedByte => "unexpected byte",
            ErrorKind::UnexpectedEnd => "unexpected end of input",
            ErrorKind::ControlCharacter => "control character",
            ErrorKind::InvalidEscape => "invalid escape",
            ErrorKind::InvalidInteger => "invalid integer",
            ErrorKind::IntegerOutOfRange => "integer out of range",
            ErrorKind::DuplicateKey => "duplicate key",
            ErrorKind::DuplicateTable => "table defined twice",
            ErrorKind::NotExtensible => "value cannot be extended",
            ErrorKind::Unsupported(feature) => {
                f.write_str("unsupported TOML feature: ")?;
                feature.name()
            }
        };
        f.write_str(text)
    }
}

/// An error and where it was found.
///
/// `offset` is the byte offset into the input of `parse`, `line` the
/// 1-based line (lines end at LF) and `column` the 1-based byte offset in
/// that line. `InvalidLimit` has offset 0, line 1 and column 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    offset: usize,
    line: usize,
    column: usize,
}

impl Error {
    /// An error at `offset` of `input`, with its line and column.
    pub(crate) fn at(kind: ErrorKind, offset: usize, input: &[u8]) -> Error {
        let before = &input[..offset.min(input.len())];
        let line_start = before
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        Error {
            kind,
            offset,
            line: 1 + before.iter().filter(|&&b| b == b'\n').count(),
            column: 1 + offset - line_start,
        }
    }

    pub(crate) fn without_input(kind: ErrorKind) -> Error {
        Error {
            kind,
            offset: 0,
            line: 1,
            column: 1,
        }
    }

    /// What went wrong.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The byte offset into the input.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The 1-based line.
    pub fn line(&self) -> usize {
        self.line
    }

    /// The 1-based byte column.
    pub fn column(&self) -> usize {
        self.column
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.describe(f)?;
        if self.kind == ErrorKind::InvalidLimit {
            return Ok(());
        }
        write!(
            f,
            " at line {}, column {} (byte {})",
            self.line, self.column, self.offset
        )
    }
}

impl std::error::Error for Error {}
