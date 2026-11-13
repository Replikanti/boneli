//! Message bodies: the reader for every framing, our own chunk-line parser,
//! the length and chunked writers, and `pass_through` for event streams
//! (ADR-003).

use std::io::{self, Read, Write};

use crate::error::{Error, Result};
use crate::head::Framing;
use crate::limits::Limits;
use crate::wire::{HeadScan, READ_CHUNK, Wire};

/// Where a body reader stands. Kept in the connection, so that it knows
/// after the reader is gone whether the body was read to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyState {
    /// The body has been read to its end (or there is none).
    Done,
    /// A body read failed; the connection cannot be reused.
    Failed,
    /// Content-Length body: bytes left.
    Length(u64),
    /// Chunked body, expecting a chunk-size line; `received` data bytes so far.
    ChunkSize { received: u64 },
    /// Chunked body, inside a chunk's data.
    ChunkData { left: u64, received: u64 },
    /// Chunked body, expecting the CRLF after a chunk's data.
    ChunkEnd { received: u64 },
    /// Chunked body, expecting the trailer section.
    Trailers,
    /// Close-delimited body (responses only); `received` bytes so far.
    UntilClose { received: u64 },
}

impl BodyState {
    pub(crate) fn from_framing(framing: Framing) -> BodyState {
        match framing {
            Framing::None | Framing::Length(0) => BodyState::Done,
            Framing::Length(n) => BodyState::Length(n),
            Framing::Chunked => BodyState::ChunkSize { received: 0 },
        }
    }
}

/// Reads one body off a connection. Implements `Read`; errors travel inside
/// `io::Error` and convert back with `Error::from`. Each `read` returns as
/// soon as one read of the stream has yielded body bytes, so event streams
/// pass through unbuffered.
pub struct BodyReader<'a, S> {
    wire: &'a mut Wire<S>,
    state: &'a mut BodyState,
    limits: Limits,
}

impl<'a, S: Read> BodyReader<'a, S> {
    pub(crate) fn new(
        wire: &'a mut Wire<S>,
        state: &'a mut BodyState,
        limits: Limits,
    ) -> BodyReader<'a, S> {
        BodyReader {
            wire,
            state,
            limits,
        }
    }

    /// Whether the body has been read to its end.
    pub fn is_done(&self) -> bool {
        *self.state == BodyState::Done
    }

    /// Copies buffered bytes, reading the stream once if none are buffered.
    /// End of stream is an error: the framing promised more.
    fn take(&mut self, buf: &mut [u8], left: u64) -> Result<usize> {
        if self.wire.available().is_empty() && self.wire.fill()? == 0 {
            return Err(Error::UnexpectedEof);
        }
        let avail = self.wire.available();
        let n = avail
            .len()
            .min(buf.len())
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        buf[..n].copy_from_slice(&avail[..n]);
        self.wire.consume(n);
        Ok(n)
    }

    fn step(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            match *self.state {
                BodyState::Done => return Ok(0),
                BodyState::Failed => return Err(Error::Malformed("the body failed earlier")),
                BodyState::Length(left) => {
                    let n = self.take(buf, left)?;
                    let left = left - n as u64;
                    *self.state = if left == 0 {
                        BodyState::Done
                    } else {
                        BodyState::Length(left)
                    };
                    return Ok(n);
                }
                BodyState::ChunkSize { received } => {
                    let line = self.wire.read_line(self.limits.max_head_bytes())?;
                    let size = parse_chunk_line(&line)?;
                    let total = received.checked_add(size).ok_or(Error::BodyTooLarge)?;
                    if total > self.limits.max_body_bytes() {
                        return Err(Error::BodyTooLarge);
                    }
                    *self.state = if size == 0 {
                        BodyState::Trailers
                    } else {
                        BodyState::ChunkData {
                            left: size,
                            received: total,
                        }
                    };
                }
                BodyState::ChunkData { left, received } => {
                    let n = self.take(buf, left)?;
                    let left = left - n as u64;
                    *self.state = if left == 0 {
                        BodyState::ChunkEnd { received }
                    } else {
                        BodyState::ChunkData { left, received }
                    };
                    return Ok(n);
                }
                BodyState::ChunkEnd { received } => {
                    self.wire.require(2)?;
                    if &self.wire.available()[..2] != b"\r\n" {
                        return Err(Error::Malformed("chunk data does not end with CRLF"));
                    }
                    self.wire.consume(2);
                    *self.state = BodyState::ChunkSize { received };
                }
                BodyState::Trailers => {
                    self.read_trailers()?;
                    *self.state = BodyState::Done;
                    return Ok(0);
                }
                BodyState::UntilClose { received } => {
                    if self.wire.available().is_empty() && self.wire.fill()? == 0 {
                        *self.state = BodyState::Done;
                        return Ok(0);
                    }
                    let avail = self.wire.available();
                    let n = avail.len().min(buf.len());
                    let total = received + n as u64;
                    if total > self.limits.max_body_bytes() {
                        return Err(Error::BodyTooLarge);
                    }
                    buf[..n].copy_from_slice(&avail[..n]);
                    self.wire.consume(n);
                    *self.state = BodyState::UntilClose { received: total };
                    return Ok(n);
                }
            }
        }
    }

    /// Reads and discards the trailer section, held to the head limits:
    /// CRLF lines only, at most `max_head_bytes` including the final empty
    /// line, at most `max_headers` fields, each one a valid field line.
    fn read_trailers(&mut self) -> Result<()> {
        let max = self.limits.max_head_bytes();
        // The section is either one empty line or fields and an empty line;
        // the head scanner does not allow a leading empty line to end it.
        self.wire.require(1)?;
        if self.wire.available()[0] == b'\r' {
            self.wire.require(2)?;
            if &self.wire.available()[..2] != b"\r\n" {
                return Err(Error::Malformed("CR without LF"));
            }
            self.wire.consume(2);
            return Ok(());
        }
        let mut scan = HeadScan::default();
        let end = loop {
            if let Some(end) = scan.advance(self.wire.available(), max)? {
                break end;
            }
            if self.wire.fill()? == 0 {
                return Err(Error::UnexpectedEof);
            }
        };
        let section = self.wire.available()[..end].to_vec();
        self.wire.consume(end);
        let cap = self.limits.max_headers().min(max / 4 + 1);
        let mut slots = vec![httparse::EMPTY_HEADER; cap];
        match httparse::parse_headers(&section, &mut slots) {
            Ok(httparse::Status::Complete((n, _))) if n == section.len() => Ok(()),
            Err(httparse::Error::TooManyHeaders) => Err(Error::TooManyHeaders),
            _ => Err(Error::Malformed("invalid trailer section")),
        }
    }
}

impl<S: Read> Read for BodyReader<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.step(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                *self.state = BodyState::Failed;
                Err(e.into())
            }
        }
    }
}

/// Parses one chunk-size line including its CRLF: 1 to 16 hex digits (16
/// digits are the most a `u64` holds), then optional SP or HTAB before
/// `;` extensions, which are ignored. No control character other than HTAB
/// anywhere. httparse's `parse_chunk_size` accepts a bare LF after an
/// extension, so it is not used (ADR-003).
pub(crate) fn parse_chunk_line(line: &[u8]) -> Result<u64> {
    let bad = Error::Malformed("invalid chunk-size line");
    let content = line
        .strip_suffix(b"\r\n")
        .ok_or(Error::Malformed("chunk-size line does not end with CRLF"))?;
    if !content
        .iter()
        .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f))
    {
        return Err(bad);
    }
    let digits = content.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 || digits > 16 {
        return Err(bad);
    }
    let rest = &content[digits..];
    let after_ws = rest
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(rest.len());
    if after_ws < rest.len() && rest[after_ws] != b';' {
        return Err(bad);
    }
    if after_ws == rest.len() && !rest.is_empty() {
        // Whitespace without an extension after it.
        return Err(bad);
    }
    let mut size: u64 = 0;
    for &d in &content[..digits] {
        let v = (d as char)
            .to_digit(16)
            .ok_or(Error::Malformed("invalid chunk-size line"))?;
        size = (size << 4) | u64::from(v);
    }
    Ok(size)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Length(u64),
    Chunked,
    /// The response to a HEAD request: bytes are accepted and dropped.
    Discard,
}

/// Writes one body: either exactly a declared length, or chunked. Call
/// `finish` at the end; a writer dropped without it leaves the body
/// unterminated, which the peer sees as a truncated message.
pub struct BodyWriter<'a, W: Write> {
    out: W,
    mode: Mode,
    finished: Option<&'a mut bool>,
}

impl<W: Write> BodyWriter<'static, W> {
    /// A writer for a body of exactly `len` bytes.
    pub fn length(out: W, len: u64) -> BodyWriter<'static, W> {
        BodyWriter {
            out,
            mode: Mode::Length(len),
            finished: None,
        }
    }

    /// A writer for a chunked body.
    pub fn chunked(out: W) -> BodyWriter<'static, W> {
        BodyWriter {
            out,
            mode: Mode::Chunked,
            finished: None,
        }
    }
}

impl<'a, W: Write> BodyWriter<'a, W> {
    /// The server's writer: `finished` is set once `finish` succeeds.
    pub(crate) fn with_flag(
        out: W,
        framing: Framing,
        discard: bool,
        finished: &'a mut bool,
    ) -> BodyWriter<'a, W> {
        let mode = match (discard, framing) {
            (true, _) => Mode::Discard,
            (false, Framing::Length(n)) => Mode::Length(n),
            (false, _) => Mode::Chunked,
        };
        BodyWriter {
            out,
            mode,
            finished: Some(finished),
        }
    }

    /// Ends the body: checks that a declared length was written in full, or
    /// writes the last chunk, then flushes.
    pub fn finish(mut self) -> io::Result<()> {
        match self.mode {
            Mode::Length(0) | Mode::Discard => {}
            Mode::Length(_) => {
                return Err(Error::InvalidInput("body shorter than its declared length").into());
            }
            Mode::Chunked => self.out.write_all(b"0\r\n\r\n")?,
        }
        self.out.flush()?;
        if let Some(flag) = self.finished.take() {
            *flag = true;
        }
        Ok(())
    }
}

impl<W: Write> Write for BodyWriter<'_, W> {
    /// Writes all of `buf` or nothing of it. An empty write sends nothing:
    /// in chunked mode an empty chunk would end the body.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.mode {
            Mode::Discard => {}
            Mode::Length(left) => {
                if buf.len() as u64 > left {
                    return Err(Error::InvalidInput("body longer than its declared length").into());
                }
                self.out.write_all(buf)?;
                self.mode = Mode::Length(left - buf.len() as u64);
            }
            Mode::Chunked => {
                let mut chunk = Vec::with_capacity(buf.len() + 20);
                chunk.extend_from_slice(format!("{:x}\r\n", buf.len()).as_bytes());
                chunk.extend_from_slice(buf);
                chunk.extend_from_slice(b"\r\n");
                self.out.write_all(&chunk)?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Copies `src` into `dst`, writing and flushing after every read, so each
/// event of a stream reaches the peer as it arrives. At the end of `src` it
/// finishes `dst`. On a read or write error it returns the error without
/// finishing, so a truncated upstream stays a truncated body downstream.
/// Returns the number of bytes copied.
pub fn pass_through<R: Read + ?Sized, W: Write>(
    src: &mut R,
    mut dst: BodyWriter<'_, W>,
) -> io::Result<u64> {
    let mut buf = vec![0u8; READ_CHUNK];
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        dst.write_all(&buf[..n])?;
        dst.flush()?;
        total += n as u64;
    }
    dst.finish()?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_lines() {
        for (line, size) in [
            (&b"a\r\n"[..], 10u64),
            (b"A\r\n", 10),
            (b"a;x=1\r\n", 10),
            (b"a ;x\r\n", 10),
            (b"a\t;x\r\n", 10),
            (b"0\r\n", 0),
            (b"000a\r\n", 10),
            (b"ffffffffffffffff\r\n", u64::MAX),
            (b"a;x=\"q s\"\r\n", 10),
        ] {
            assert_eq!(parse_chunk_line(line).expect("valid"), size, "{line:?}");
        }
        for line in [
            &b"0xa\r\n"[..],
            b"+a\r\n",
            b" a\r\n",
            b"a \r\n",
            b"a\n",
            b"a;x\n",
            b"a;x\rz\r\n",
            b"10000000000000000\r\n",
            b"0000000000000000000a\r\n",
            b"\r\n",
            b"g\r\n",
            b"a;x\x00\r\n",
            b"a\r\r\n",
            b"a;\x7f\r\n",
        ] {
            assert!(parse_chunk_line(line).is_err(), "{line:?}");
        }
    }
}
