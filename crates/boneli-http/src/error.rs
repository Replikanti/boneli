//! The one error type of the crate and the status the server answers with.

use std::fmt;
use std::io;

/// Everything that can go wrong while reading, writing or serving HTTP.
#[derive(Debug)]
pub enum Error {
    /// The underlying stream failed.
    Io(io::Error),
    /// The peer sent bytes outside the accepted subset (ADR-003).
    Malformed(&'static str),
    /// A head (or a trailer section) is longer than `Limits::max_head_bytes`.
    HeadTooLarge,
    /// A head (or a trailer section) has more fields than
    /// `Limits::max_headers`.
    TooManyHeaders,
    /// A body is longer than `Limits::max_body_bytes`.
    BodyTooLarge,
    /// A transfer coding other than a single `chunked`.
    UnsupportedTransferCoding,
    /// An HTTP version other than 1.1.
    UnsupportedVersion,
    /// An `Expect` field other than `100-continue`.
    ExpectationFailed,
    /// A read did not complete before its deadline.
    Timeout,
    /// The stream ended inside a head or a body.
    UnexpectedEof,
    /// The caller passed something this crate refuses to send or use: a
    /// zero limit, a header it owns, a byte that would break framing, or a
    /// call in the wrong state. Nothing has been written when it is
    /// returned.
    InvalidInput(&'static str),
    /// The peer answered with a status the operation cannot continue
    /// from, such as a refused CONNECT or `101 Switching Protocols`.
    Status(u16),
}

impl Error {
    /// The status the server answers with before it closes the connection,
    /// or `None` when it closes without an answer.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Malformed(_) => Some(400),
            Error::Timeout => Some(408),
            Error::BodyTooLarge => Some(413),
            Error::ExpectationFailed => Some(417),
            Error::HeadTooLarge | Error::TooManyHeaders => Some(431),
            Error::UnsupportedTransferCoding => Some(501),
            Error::UnsupportedVersion => Some(505),
            Error::Io(_) | Error::UnexpectedEof | Error::InvalidInput(_) | Error::Status(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Malformed(what) => write!(f, "malformed message: {what}"),
            Error::HeadTooLarge => f.write_str("head too large"),
            Error::TooManyHeaders => f.write_str("too many header fields"),
            Error::BodyTooLarge => f.write_str("body too large"),
            Error::UnsupportedTransferCoding => f.write_str("unsupported transfer coding"),
            Error::UnsupportedVersion => f.write_str("unsupported HTTP version"),
            Error::ExpectationFailed => f.write_str("unsupported expectation"),
            Error::Timeout => f.write_str("timed out"),
            Error::UnexpectedEof => f.write_str("unexpected end of stream"),
            Error::InvalidInput(what) => write!(f, "invalid input: {what}"),
            Error::Status(status) => write!(f, "unexpected status {status}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    /// Unwraps an `Error` that crossed `io::Read` or `io::Write`, and maps
    /// timeouts and early ends of the stream to their own variants.
    fn from(e: io::Error) -> Self {
        if e.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            if let Some(inner) = e.into_inner() {
                if let Ok(ours) = inner.downcast::<Error>() {
                    return *ours;
                }
            }
            return Error::Malformed("lost error");
        }
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Error::Timeout,
            io::ErrorKind::UnexpectedEof => Error::UnexpectedEof,
            _ => Error::Io(e),
        }
    }
}

impl From<Error> for io::Error {
    /// Carries an `Error` through `io::Read` and `io::Write`, with the kind
    /// that matches it, so that `From<io::Error>` can recover it.
    fn from(e: Error) -> Self {
        let kind = match &e {
            Error::Io(_) => None,
            Error::Timeout => Some(io::ErrorKind::TimedOut),
            Error::UnexpectedEof => Some(io::ErrorKind::UnexpectedEof),
            Error::InvalidInput(_) => Some(io::ErrorKind::InvalidInput),
            _ => Some(io::ErrorKind::InvalidData),
        };
        match (e, kind) {
            (Error::Io(inner), _) => inner,
            (other, Some(kind)) => io::Error::new(kind, other),
            (other, None) => io::Error::other(other),
        }
    }
}

/// `Result` with this crate's `Error`.
pub type Result<T> = std::result::Result<T, Error>;
