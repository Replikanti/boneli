//! An RFC 1952 gzip reader over `miniz_oxide`'s raw deflate (ADR-009, D5).
//!
//! The framing is ours: `FEXTRA`, `FNAME`, `FCOMMENT` and `FHCRC` are
//! skipped, reserved `FLG` bits and any `CM` but 8 are refused, and `ISIZE`
//! is checked. Several members decode as one stream, and like Go's reader
//! (which Docker and containerd use) any byte after the last member that
//! does not start another member is refused. CRC-32 is not computed: the
//! diff_id check covers every decoded byte.

use std::io::{self, Read};

use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

use crate::error::{Error, carry};

const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;
const RESERVED: u8 = 0xe0;

/// The input buffer: 64 KiB, about one network read.
const INPUT: usize = 64 * 1024;

enum Phase {
    /// Before a member header; `first` until the first member began.
    Header { first: bool },
    /// Inside a member's deflate data.
    Body,
    /// After the last member.
    Done,
}

/// Decodes a gzip stream from `R`.
pub(crate) struct GzipReader<R> {
    source: R,
    buf: Box<[u8]>,
    pos: usize,
    len: usize,
    eof: bool,
    state: Box<InflateState>,
    phase: Phase,
    /// Bytes of the current member, for ISIZE (its size modulo 2^32).
    member_out: u64,
}

fn bad(what: &'static str) -> io::Error {
    carry(Error::Gzip(what))
}

impl<R: Read> GzipReader<R> {
    pub(crate) fn new(source: R) -> GzipReader<R> {
        GzipReader {
            source,
            buf: vec![0u8; INPUT].into_boxed_slice(),
            pos: 0,
            len: 0,
            eof: false,
            state: InflateState::new_boxed(DataFormat::Raw),
            phase: Phase::Header { first: true },
            member_out: 0,
        }
    }

    /// Moves the unread input to the front and reads more after it.
    /// Returns whether new bytes arrived.
    fn fill(&mut self) -> io::Result<bool> {
        if self.eof {
            return Ok(false);
        }
        self.buf.copy_within(self.pos..self.len, 0);
        self.len -= self.pos;
        self.pos = 0;
        if self.len == self.buf.len() {
            return Ok(true);
        }
        loop {
            match self.source.read(&mut self.buf[self.len..]) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(false);
                }
                Ok(n) => {
                    self.len += n;
                    return Ok(true);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// The next input byte, `None` at the end of the source.
    fn byte(&mut self) -> io::Result<Option<u8>> {
        if self.pos == self.len && !self.fill()? {
            return Ok(None);
        }
        let b = self.buf.get(self.pos).copied();
        self.pos += 1;
        Ok(b)
    }

    /// The next input byte; the end of the source is a truncated member.
    fn need(&mut self) -> io::Result<u8> {
        self.byte()?.ok_or_else(|| bad("truncated member"))
    }

    fn skip(&mut self, mut n: usize) -> io::Result<()> {
        while n > 0 {
            self.need()?;
            n -= 1;
        }
        Ok(())
    }

    fn skip_zero_terminated(&mut self) -> io::Result<()> {
        while self.need()? != 0 {}
        Ok(())
    }

    /// Reads a member header. `Ok(false)` at a clean end after a member.
    fn header(&mut self, first: bool) -> io::Result<bool> {
        let id1 = match self.byte()? {
            Some(b) => b,
            None if first => return Err(bad("empty stream")),
            None => return Ok(false),
        };
        if id1 != 0x1f || self.need()? != 0x8b {
            return Err(bad(if first {
                "not a gzip stream"
            } else {
                "data after the last member"
            }));
        }
        if self.need()? != 8 {
            return Err(bad("compression method is not deflate"));
        }
        let flg = self.need()?;
        if flg & RESERVED != 0 {
            return Err(bad("reserved flag bits set"));
        }
        // MTIME, XFL, OS.
        self.skip(6)?;
        if flg & FEXTRA != 0 {
            let lo = self.need()?;
            let hi = self.need()?;
            self.skip(usize::from(u16::from_le_bytes([lo, hi])))?;
        }
        if flg & FNAME != 0 {
            self.skip_zero_terminated()?;
        }
        if flg & FCOMMENT != 0 {
            self.skip_zero_terminated()?;
        }
        if flg & FHCRC != 0 {
            self.skip(2)?;
        }
        self.state.reset(DataFormat::Raw);
        self.member_out = 0;
        Ok(true)
    }

    /// Reads the CRC-32 (not checked) and ISIZE of a member.
    fn trailer(&mut self) -> io::Result<()> {
        self.skip(4)?;
        let mut isize = [0u8; 4];
        for b in &mut isize {
            *b = self.need()?;
        }
        // ISIZE is the member's size modulo 2^32.
        if u32::from_le_bytes(isize) != self.member_out as u32 {
            return Err(bad("ISIZE does not match the decoded size"));
        }
        Ok(())
    }
}

impl<R: Read> Read for GzipReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match self.phase {
                Phase::Done => return Ok(0),
                Phase::Header { first } => {
                    if self.header(first)? {
                        self.phase = Phase::Body;
                    } else {
                        self.phase = Phase::Done;
                    }
                }
                Phase::Body => {
                    if self.pos == self.len {
                        self.fill()?;
                    }
                    let r = inflate(
                        &mut self.state,
                        &self.buf[self.pos..self.len],
                        out,
                        MZFlush::None,
                    );
                    self.pos += r.bytes_consumed;
                    self.member_out = self
                        .member_out
                        .wrapping_add(u64::try_from(r.bytes_written).unwrap_or(u64::MAX));
                    match r.status {
                        Ok(MZStatus::StreamEnd) => {
                            self.trailer()?;
                            self.phase = Phase::Header { first: false };
                        }
                        Ok(_) => {}
                        Err(MZError::Buf) => {
                            // No progress without more input.
                            if r.bytes_written == 0 && r.bytes_consumed == 0 && !self.fill()? {
                                return Err(bad("truncated member"));
                            }
                        }
                        Err(_) => return Err(bad("corrupt deflate data")),
                    }
                    if r.bytes_written > 0 {
                        return Ok(r.bytes_written);
                    }
                    if r.bytes_consumed == 0 && self.pos == self.len && self.eof {
                        return Err(bad("truncated member"));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::GzipReader;
    use crate::error::{Error, from_io};

    fn member_with(flg: u8, extra: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x1f, 0x8b, 8, flg, 1, 2, 3, 4, 0, 3];
        out.extend_from_slice(extra);
        out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(data, 6));
        out.extend_from_slice(&[0, 0, 0, 0]);
        let isize = u32::try_from(data.len()).expect("small");
        out.extend_from_slice(&isize.to_le_bytes());
        out
    }

    fn member(data: &[u8]) -> Vec<u8> {
        member_with(0, &[], data)
    }

    /// Reads with a 3-byte source and a 5-byte output, so every state sees
    /// short reads.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(3).min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn decode(bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        GzipReader::new(bytes)
            .read_to_end(&mut out)
            .map_err(from_io)?;
        let mut small = Vec::new();
        let mut reader = GzipReader::new(Trickle(bytes));
        let mut chunk = [0u8; 5];
        loop {
            let n = reader.read(&mut chunk).map_err(from_io)?;
            if n == 0 {
                break;
            }
            small.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(out, small, "chunking changes nothing");
        Ok(out)
    }

    fn data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8 ^ (i / 251) as u8).collect()
    }

    #[test]
    fn gzip_multi_member() {
        let (a, b, c) = (data(70_000), data(5), Vec::new());
        let mut stream = member(&a);
        stream.extend_from_slice(&member(&b));
        stream.extend_from_slice(&member(&c));
        let mut expected = a;
        expected.extend_from_slice(&b);
        assert_eq!(decode(&stream).expect("decodes"), expected);
    }

    #[test]
    fn gzip_trailing_garbage_refused() {
        let good = member(b"layer");
        for tail in [
            &[0u8][..],
            &[0, 0, 0, 0],
            b"x",
            &[0x1f],
            &[0x1f, 0x8b],
            &[0x1f, 0x8c, 8],
        ] {
            let mut stream = good.clone();
            stream.extend_from_slice(tail);
            assert!(
                matches!(decode(&stream), Err(Error::Gzip(_))),
                "{tail:?} after the last member"
            );
        }
        assert!(matches!(decode(&[]), Err(Error::Gzip("empty stream"))));
    }

    #[test]
    fn gzip_header_rules() {
        // Every optional field is skipped.
        let mut extra = vec![3, 0, b'a', b'b', b'c'];
        extra.extend_from_slice(b"name.tar\0");
        extra.extend_from_slice(b"a comment\0");
        extra.extend_from_slice(&[0xaa, 0xbb]);
        let all = member_with(0x02 | 0x04 | 0x08 | 0x10, &extra, b"payload");
        assert_eq!(decode(&all).expect("decodes"), b"payload");
        // FTEXT is bit 0 and only a hint.
        assert_eq!(decode(&member_with(0x01, &[], b"t")).expect("ftext"), b"t");

        for flg in [0x20u8, 0x40, 0x80, 0xe0] {
            let m = member_with(flg, &[], b"x");
            assert!(
                matches!(decode(&m), Err(Error::Gzip("reserved flag bits set"))),
                "{flg:#x}"
            );
        }
        let mut cm = member(b"x");
        cm[2] = 7;
        assert!(matches!(decode(&cm), Err(Error::Gzip(_))));
        let mut magic = member(b"x");
        magic[1] = 0x8c;
        assert!(matches!(decode(&magic), Err(Error::Gzip(_))));
    }

    #[test]
    fn gzip_isize_mismatch_refused() {
        let mut m = member(b"twelve bytes");
        let at = m.len() - 4;
        m[at] ^= 1;
        assert!(matches!(
            decode(&m),
            Err(Error::Gzip("ISIZE does not match the decoded size"))
        ));
    }

    #[test]
    fn gzip_truncated_or_corrupt() {
        let m = member(&data(3000));
        for cut in 0..m.len() {
            assert!(decode(&m[..cut]).is_err(), "cut at {cut}");
        }
        // A deflate block of a reserved type (BTYPE 11).
        let mut bad = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0x07];
        bad.extend_from_slice(&[0; 8]);
        assert!(matches!(
            decode(&bad),
            Err(Error::Gzip("corrupt deflate data"))
        ));
    }
}
