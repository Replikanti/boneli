//! The buffered read side of a connection: reads in 8 KiB steps, keeps
//! bytes past the current message for the next one, finds the end of a
//! head in one pass, and applies the server's deadline to every read.

use std::io::{self, Read};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Bytes asked for per read. The same as `std::io::BufReader`'s default; it
/// only trades system calls for memory (ADR-003).
pub(crate) const READ_CHUNK: usize = 8 * 1024;

/// Sets a read timeout on a stream (`Transport::set_read_timeout`).
pub(crate) type SetTimeout<S> = fn(&S, Option<Duration>) -> io::Result<()>;

pub(crate) struct Wire<S> {
    pub(crate) stream: S,
    buf: Vec<u8>,
    start: usize,
    /// When set, every read must finish before this instant.
    pub(crate) deadline: Option<Instant>,
    set_timeout: Option<SetTimeout<S>>,
}

/// A head read off the wire: `bytes[content..]` is the head without the
/// leading empty lines.
pub(crate) struct RawHead {
    pub(crate) bytes: Vec<u8>,
    pub(crate) content: usize,
}

impl<S: Read> Wire<S> {
    pub(crate) fn new(stream: S, set_timeout: Option<SetTimeout<S>>) -> Wire<S> {
        Wire {
            stream,
            buf: Vec::new(),
            start: 0,
            deadline: None,
            set_timeout,
        }
    }

    /// The bytes read but not consumed yet.
    pub(crate) fn available(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    pub(crate) fn consume(&mut self, n: usize) {
        self.start += n;
        debug_assert!(self.start <= self.buf.len());
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// Takes every buffered byte.
    pub(crate) fn take_buffered(&mut self) -> Vec<u8> {
        let rest = self.buf.split_off(self.start);
        self.buf.clear();
        self.start = 0;
        rest
    }

    /// Reads once from the stream into the buffer. Returns the number of
    /// new bytes; zero means end of stream.
    pub(crate) fn fill(&mut self) -> Result<usize> {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        loop {
            if let Some(set) = self.set_timeout {
                let timeout = match self.deadline {
                    Some(deadline) => {
                        let left = deadline.saturating_duration_since(Instant::now());
                        if left.is_zero() {
                            return Err(Error::Timeout);
                        }
                        Some(left)
                    }
                    None => None,
                };
                set(&self.stream, timeout)?;
            }
            let len = self.buf.len();
            self.buf.resize(len + READ_CHUNK, 0);
            let read = self.stream.read(&mut self.buf[len..]);
            self.buf.truncate(len + *read.as_ref().unwrap_or(&0));
            match read {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // A timeout that fires before the deadline (the kernel may
                // round) reads again with what is left.
                Err(e) if is_timeout(&e) && self.deadline.is_some_and(|d| Instant::now() < d) => {
                    continue;
                }
                Err(e) => return Err(Error::from(e)),
            }
        }
    }

    /// Reads one head of at most `max` bytes. Leading empty lines are
    /// skipped but counted. Returns `None` when the stream ends before any
    /// other byte. Every line must end with CRLF: a bare LF or CR is
    /// rejected here, because httparse accepts a bare LF (ADR-003). The end
    /// is found in one pass over the bytes, so a trickled head costs linear
    /// time.
    pub(crate) fn read_head(&mut self, max: usize) -> Result<Option<RawHead>> {
        let mut scan = HeadScan::default();
        loop {
            if let Some(end) = scan.advance(self.available(), max)? {
                let bytes = self.available()[..end].to_vec();
                self.consume(end);
                let content = scan.content.unwrap_or(0);
                return Ok(Some(RawHead { bytes, content }));
            }
            if self.fill()? == 0 {
                if scan.content.is_none() {
                    let leading = self.available().len();
                    self.consume(leading);
                    return Ok(None);
                }
                return Err(Error::UnexpectedEof);
            }
        }
    }

    /// Reads one line through its LF, at most `max` bytes. The line is
    /// returned with its ending; the caller checks it.
    pub(crate) fn read_line(&mut self, max: usize) -> Result<Vec<u8>> {
        let mut searched = 0;
        loop {
            let avail = self.available();
            let window = avail.len().min(max);
            if let Some(at) = avail[searched..window].iter().position(|&b| b == b'\n') {
                let line = avail[..searched + at + 1].to_vec();
                self.consume(line.len());
                return Ok(line);
            }
            if window >= max {
                return Err(Error::Malformed("line too long"));
            }
            searched = window;
            if self.fill()? == 0 {
                return Err(Error::UnexpectedEof);
            }
        }
    }

    /// Makes at least `n` bytes available, or fails with `UnexpectedEof`.
    pub(crate) fn require(&mut self, n: usize) -> Result<()> {
        while self.available().len() < n {
            if self.fill()? == 0 {
                return Err(Error::UnexpectedEof);
            }
        }
        Ok(())
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// The one-pass head scanner. It keeps its position across reads.
#[derive(Default)]
pub(crate) struct HeadScan {
    pos: usize,
    seen_cr: bool,
    line_len: usize,
    /// Where the first line that is not empty starts.
    pub(crate) content: Option<usize>,
}

impl HeadScan {
    /// Scans `data` from where the last call stopped. Returns the length of
    /// the head when its empty last line has been seen.
    pub(crate) fn advance(&mut self, data: &[u8], max: usize) -> Result<Option<usize>> {
        while self.pos < data.len() && self.pos < max {
            let b = data[self.pos];
            self.pos += 1;
            if self.seen_cr {
                if b != b'\n' {
                    return Err(Error::Malformed("CR without LF"));
                }
                self.seen_cr = false;
                if self.line_len == 0 && self.content.is_some() {
                    return Ok(Some(self.pos));
                }
                self.line_len = 0;
                continue;
            }
            match b {
                b'\r' => self.seen_cr = true,
                b'\n' => return Err(Error::Malformed("LF without CR")),
                _ => {
                    if self.content.is_none() {
                        self.content = Some(self.pos - 1);
                    }
                    self.line_len += 1;
                }
            }
        }
        if self.pos >= max {
            return Err(Error::HeadTooLarge);
        }
        Ok(None)
    }
}
