//! Newline-delimited JSON: one value per line, each line ended by `\n`
//! (ADR-008, D8).

use std::io::{self, BufRead, Write};

use crate::error::{Error, ErrorKind};
use crate::limits::Limits;
use crate::parse::parse;
use crate::serialize::to_vec;
use crate::value::Value;

/// Reads one value per line from a `BufRead`.
///
/// Every item is the value of one line or an error that names the 1-based
/// line; after an error in one line the next item is the next line, so the
/// consumer decides whether to stop or skip. Error offsets count from the
/// start of the line. A line is at most `limits.max_bytes()` long without
/// its `\n` (a `\r` before it is whitespace and counts), and an over-long
/// line is reported as `LineTooLong` as soon as its byte `max_bytes + 1`
/// arrives; the rest of it is skipped without being buffered. So the reader
/// holds at most `max_bytes` plus the `BufRead` buffer.
///
/// An empty line is an error (`UnexpectedEnd`), and so is a last line
/// without `\n` (`UnterminatedLine`), even when it parses: a truncated
/// `12345` would otherwise read as `123`. `Interrupted` is retried; any
/// other I/O error is returned once, as `Io`, and then the reader ends.
#[derive(Debug)]
pub struct Reader<R> {
    inner: R,
    limits: Limits,
    line: u64,
    buf: Vec<u8>,
    skipping: bool,
    done: bool,
}

impl<R: BufRead> Reader<R> {
    /// A reader over `inner` with `limits` for each line.
    pub fn new(inner: R, limits: Limits) -> Reader<R> {
        Reader {
            inner,
            limits,
            line: 1,
            buf: Vec::new(),
            skipping: false,
            done: false,
        }
    }

    /// The reader this one reads from.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: BufRead> Iterator for Reader<R> {
    type Item = Result<Value, Error>;

    fn next(&mut self) -> Option<Result<Value, Error>> {
        let max = self.limits.max_bytes();
        while !self.done {
            let data = match self.inner.fill_buf() {
                Ok(data) => data,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.done = true;
                    return Some(Err(Error::io(e).on_line(self.line)));
                }
            };
            if data.is_empty() {
                self.done = true;
                if self.skipping || self.buf.is_empty() {
                    return None;
                }
                let e = Error::new(ErrorKind::UnterminatedLine, self.buf.len());
                return Some(Err(e.on_line(self.line)));
            }
            let newline = data.iter().position(|&b| b == b'\n');
            if self.skipping {
                match newline {
                    Some(i) => {
                        self.inner.consume(i + 1);
                        self.skipping = false;
                        self.line += 1;
                    }
                    None => {
                        let n = data.len();
                        self.inner.consume(n);
                    }
                }
                continue;
            }
            let content = newline.unwrap_or(data.len());
            if content > max - self.buf.len() {
                let line = self.line;
                self.buf.clear();
                match newline {
                    Some(i) => {
                        self.inner.consume(i + 1);
                        self.line += 1;
                    }
                    None => {
                        let n = data.len();
                        self.inner.consume(n);
                        self.skipping = true;
                    }
                }
                return Some(Err(Error::new(ErrorKind::LineTooLong, max).on_line(line)));
            }
            self.buf.extend_from_slice(&data[..content]);
            match newline {
                Some(i) => {
                    self.inner.consume(i + 1);
                    let line = self.line;
                    self.line += 1;
                    let item = parse(&self.buf, &self.limits).map_err(|e| e.on_line(line));
                    self.buf.clear();
                    return Some(item);
                }
                None => {
                    let n = data.len();
                    self.inner.consume(n);
                }
            }
        }
        None
    }
}

/// Writes `value` as one compact line ending in `\n`, in a single
/// `write_all`. The compact form escapes every line feed, so the only raw
/// `\n` is the last byte. A value too deep to serialize writes nothing.
pub fn write_line<W: Write + ?Sized>(out: &mut W, value: &Value) -> Result<(), Error> {
    let mut line = to_vec(value)?;
    line.push(b'\n');
    out.write_all(&line).map_err(Error::io)
}
