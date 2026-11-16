//! zstd frames through `ruzstd`'s `FrameDecoder` (ADR-009, D5).
//!
//! Frames follow each other; skippable frames (`0x184D2A50..=0x184D2A5F`)
//! are skipped, and anything after the last frame that is not another frame
//! is refused. The decoder refuses a window above 100 MiB
//! (`set_max_window_size`), for the first frame, later frames and
//! single-segment frames alike, before it allocates anything. The reserved
//! bit of the frame header descriptor must be 0 (RFC 8878, 3.1.1.1.1),
//! which ruzstd does not check. Content checksums are read but not
//! verified (no `hash` feature): the diff_id check covers every decoded
//! byte.

use std::io::{self, Read};

use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

use crate::error::{Error, carry};

/// The largest window a frame may declare, inclusive: 100 MiB.
pub(crate) const MAX_WINDOW: u64 = 100 * 1024 * 1024;

const MAGIC: u32 = 0xfd2f_b528;
const SKIPPABLE: std::ops::RangeInclusive<u32> = 0x184d_2a50..=0x184d_2a5f;

/// Decoded bytes per `decode_blocks` call before they are drained.
const STEP: usize = 128 * 1024;

fn bad(what: impl Into<String>) -> io::Error {
    carry(Error::Zstd(what.into()))
}

/// Decodes a zstd stream from `R`.
pub(crate) struct ZstdReader<R> {
    source: R,
    decoder: FrameDecoder,
    in_frame: bool,
    seen_frame: bool,
}

impl<R: Read> ZstdReader<R> {
    pub(crate) fn new(source: R) -> ZstdReader<R> {
        let mut decoder = FrameDecoder::new();
        decoder.set_max_window_size(MAX_WINDOW);
        ZstdReader {
            source,
            decoder,
            in_frame: false,
            seen_frame: false,
        }
    }

    /// Fills `buf`; `Ok(false)` if the source ended before the first byte.
    fn read_exact_or_end(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        let mut got = 0;
        while got < buf.len() {
            match self.source.read(&mut buf[got..]) {
                Ok(0) if got == 0 => return Ok(false),
                Ok(0) => return Err(bad("truncated frame header")),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() || self.read_exact_or_end(buf)? {
            Ok(())
        } else {
            Err(bad("truncated frame header"))
        }
    }

    /// Starts the next frame, skipping skippable ones. `Ok(false)` at a
    /// clean end of the stream after at least one frame.
    fn next_frame(&mut self) -> io::Result<bool> {
        loop {
            let mut magic = [0u8; 4];
            if !self.read_exact_or_end(&mut magic)? {
                return if self.seen_frame {
                    Ok(false)
                } else {
                    Err(bad("empty stream"))
                };
            }
            self.seen_frame = true;
            let value = u32::from_le_bytes(magic);
            if SKIPPABLE.contains(&value) {
                let mut len = [0u8; 4];
                self.read_exact(&mut len)?;
                let len = u64::from(u32::from_le_bytes(len));
                let skipped = io::copy(&mut (&mut self.source).take(len), &mut io::sink())?;
                if skipped != len {
                    return Err(bad("truncated skippable frame"));
                }
                continue;
            }
            if value != MAGIC {
                return Err(bad(format!("bad frame magic {value:#010x}")));
            }
            let mut fhd = [0u8; 1];
            self.read_exact(&mut fhd)?;
            if fhd[0] & 0x08 != 0 {
                return Err(bad("reserved frame header bit set"));
            }
            // ruzstd reads the header again from the bytes already taken,
            // then from the source; it checks the window there.
            let head = [magic[0], magic[1], magic[2], magic[3], fhd[0]];
            self.decoder
                .init((&head[..]).chain(&mut self.source))
                .map_err(|e| bad(e.to_string()))?;
            return Ok(true);
        }
    }
}

impl<R: Read> Read for ZstdReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.in_frame {
                if !self.next_frame()? {
                    return Ok(0);
                }
                self.in_frame = true;
            }
            let n = self.decoder.read(out)?;
            if n > 0 {
                return Ok(n);
            }
            if self.decoder.is_finished() {
                self.in_frame = false;
                continue;
            }
            self.decoder
                .decode_blocks(&mut self.source, BlockDecodingStrategy::UptoBytes(STEP))
                .map_err(|e| bad(e.to_string()))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::{MAX_WINDOW, ZstdReader};
    use crate::error::{Error, from_io};

    fn decode(bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        ZstdReader::new(bytes)
            .read_to_end(&mut out)
            .map_err(from_io)?;
        Ok(out)
    }

    fn frame(data: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
    }

    /// A single-segment frame with one raw block and a content checksum
    /// that is not verified.
    fn raw_frame_with_checksum(data: &[u8]) -> Vec<u8> {
        assert!(data.len() < 256);
        let mut out = 0xfd2f_b528u32.to_le_bytes().to_vec();
        out.push(0x20 | 0x04); // single segment, checksum flag
        out.push(u8::try_from(data.len()).expect("small"));
        let block = (u32::try_from(data.len()).expect("small") << 3) | 1; // raw, last
        out.extend_from_slice(&block.to_le_bytes()[..3]);
        out.extend_from_slice(data);
        out.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        out
    }

    fn skippable(n: u8, len: u32) -> Vec<u8> {
        let mut out = (0x184d_2a50u32 + u32::from(n)).to_le_bytes().to_vec();
        out.extend_from_slice(&len.to_le_bytes());
        out.extend(std::iter::repeat_n(
            0xaau8,
            usize::try_from(len).expect("fits"),
        ));
        out
    }

    #[test]
    fn zstd_frames() {
        let a: Vec<u8> = (0..300_000u32).map(|i| (i % 7) as u8).collect();
        let mut stream = skippable(0, 5);
        stream.extend_from_slice(&frame(&a));
        stream.extend_from_slice(&skippable(15, 0));
        stream.extend_from_slice(&raw_frame_with_checksum(b"checksummed"));
        stream.extend_from_slice(&frame(b""));
        stream.extend_from_slice(&frame(b"tail"));
        stream.extend_from_slice(&skippable(3, 2));
        let mut expected = a;
        expected.extend_from_slice(b"checksummed");
        expected.extend_from_slice(b"tail");
        assert_eq!(decode(&stream).expect("decodes"), expected);

        assert!(matches!(decode(&[]), Err(Error::Zstd(_))), "no frame");
        let mut trailing = frame(b"x");
        trailing.push(0);
        assert!(matches!(decode(&trailing), Err(Error::Zstd(_))));
        let truncated_skip = &skippable(1, 10)[..12];
        let mut s = frame(b"x");
        s.extend_from_slice(truncated_skip);
        assert!(matches!(decode(&s), Err(Error::Zstd(_))));
    }

    #[test]
    fn zstd_window_above_100mib_refused() {
        // Window descriptor: 2^(10 + exponent) plus mantissa eighths.
        // 64 MiB + 5/8 = 104 MiB and 128 MiB are above the cap; so is a
        // single-segment frame whose content size, its window, is 100 MiB
        // plus one byte.
        let wd = |exp: u8, mantissa: u8| (exp << 3) | mantissa;
        let mut single = vec![0xe0];
        single.extend_from_slice(&(MAX_WINDOW + 1).to_le_bytes());
        for header in [vec![0x00, wd(16, 5)], vec![0x00, wd(17, 0)], single] {
            // Refused for the first frame and for a later one, before any
            // block is read.
            let mut first = 0xfd2f_b528u32.to_le_bytes().to_vec();
            first.extend_from_slice(&header);
            let e = decode(&first).expect_err("window above the cap");
            assert!(e.to_string().contains("window_size is too big"), "{e}");
            let mut second = frame(b"ok");
            second.extend_from_slice(&first);
            let e = decode(&second).expect_err("window above the cap");
            assert!(e.to_string().contains("window_size is too big"), "{e}");
        }
        // Exactly 100 MiB passes the window check, as a window descriptor
        // (64 MiB + 4/8 = 96 MiB is the largest below it) and as a
        // single-segment content size; the frames then end early.
        let mut exact = vec![0xe0];
        exact.extend_from_slice(&MAX_WINDOW.to_le_bytes());
        for header in [vec![0x00, wd(16, 4)], exact] {
            let mut f = 0xfd2f_b528u32.to_le_bytes().to_vec();
            f.extend_from_slice(&header);
            let e = decode(&f).expect_err("no blocks");
            assert!(!e.to_string().contains("too big"), "{e}");
        }
    }

    #[test]
    fn zstd_truncated_or_corrupt() {
        let f = frame(&(0..5000u32).map(|i| (i % 13) as u8).collect::<Vec<_>>());
        for cut in 0..f.len() {
            assert!(decode(&f[..cut]).is_err(), "cut at {cut}");
        }
        let mut reserved = f.clone();
        reserved[4] |= 0x08;
        assert!(decode(&reserved).is_err());
    }
}
