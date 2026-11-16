//! The tar reader (ADR-009, D4): the subset that Go's `archive/tar` reads
//! and Docker and containerd write, because those are the readers and
//! writers of the images we pull.
//!
//! - Headers with ustar or GNU magic; V7 and other formats are refused.
//!   The checksum may be the unsigned or the signed sum.
//! - Numbers in octal or base-256; a negative base-256 number is refused.
//! - PAX `x` headers (`path`, `linkpath`, `size`, `mtime`; other keys,
//!   `SCHILY.xattr.*` among them, are ignored), PAX `g` headers (framing
//!   checked, contents ignored, as Docker does), GNU `L` and `K`.
//! - Entry types `0`, NUL and `7` (regular file; NUL with a trailing `/` is
//!   a directory), `1`, `2`, `3`, `4`, `5`, `6`. Sparse files (`S`,
//!   `GNU.sparse.*`) and every other type are refused.
//! - The end of the archive follows Go: EOF at a header boundary, or one
//!   zero block followed by EOF or by a second zero block. A zero block
//!   followed by anything else is refused. What follows the end is left to
//!   the caller, which hashes it but extracts nothing.

use std::io::{self, Read};

use crate::error::{Error, from_io};

/// The tar block size.
pub(crate) const BLOCK: usize = 512;

/// The type of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    HardLink,
    Symlink,
    Char,
    Block,
    Dir,
    Fifo,
}

/// A modification time: seconds and nanoseconds since the epoch, the
/// nanoseconds always in `0..1_000_000_000`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mtime {
    pub(crate) secs: i64,
    pub(crate) nanos: u32,
}

/// One entry's header, with PAX and GNU extensions applied.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) path: Vec<u8>,
    pub(crate) link: Vec<u8>,
    pub(crate) kind: Kind,
    pub(crate) mode: u32,
    pub(crate) mtime: Mtime,
    pub(crate) size: u64,
    pub(crate) devmajor: u64,
    pub(crate) devminor: u64,
}

/// Reads entries from `R`.
pub(crate) struct Reader<R> {
    source: R,
    max_special: u64,
    /// Body bytes of the current entry not yet read.
    remaining: u64,
    /// Padding after the current entry's body.
    pad: u64,
    done: bool,
}

#[derive(Default)]
struct Pax {
    path: Option<Vec<u8>>,
    link: Option<Vec<u8>>,
    size: Option<u64>,
    mtime: Option<Mtime>,
}

fn tar(what: &'static str) -> Error {
    Error::Tar(what)
}

impl<R: Read> Reader<R> {
    pub(crate) fn new(source: R, max_special: u64) -> Reader<R> {
        Reader {
            source,
            max_special,
            remaining: 0,
            pad: 0,
            done: false,
        }
    }

    /// The source, for the bytes after the end of the archive.
    pub(crate) fn into_inner(self) -> R {
        self.source
    }

    /// Reads exactly `buf.len()` bytes, or none at all (`Ok(false)`).
    fn block_or_end(&mut self, buf: &mut [u8; BLOCK]) -> Result<bool, Error> {
        let mut got = 0;
        while got < BLOCK {
            match self.source.read(&mut buf[got..]) {
                Ok(0) if got == 0 => return Ok(false),
                Ok(0) => return Err(tar("truncated archive")),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(from_io(e)),
            }
        }
        Ok(true)
    }

    fn skip(&mut self, n: u64) -> Result<(), Error> {
        let skipped =
            io::copy(&mut (&mut self.source).take(n), &mut io::sink()).map_err(from_io)?;
        if skipped == n {
            Ok(())
        } else {
            Err(tar("truncated archive"))
        }
    }

    /// Skips what is left of the current entry's body and its padding.
    fn finish_entry(&mut self) -> Result<(), Error> {
        let n = self.remaining + self.pad;
        self.remaining = 0;
        self.pad = 0;
        self.skip(n)
    }

    /// A special body (PAX or GNU), at most `max_special` bytes.
    fn special(&mut self, size: u64) -> Result<Vec<u8>, Error> {
        if size > self.max_special {
            return Err(Error::Limit {
                what: "PAX or GNU extension header size",
                max: self.max_special,
            });
        }
        let len = usize::try_from(size).map_err(|_| tar("extension header too large"))?;
        let mut body = vec![0u8; len];
        self.source.read_exact(&mut body).map_err(from_io)?;
        self.skip(padding(size))?;
        Ok(body)
    }

    /// The next entry, or `None` at the end of the archive. The body of the
    /// previous entry is skipped if the caller did not read it.
    pub(crate) fn next_entry(&mut self) -> Result<Option<Entry>, Error> {
        if self.done {
            return Ok(None);
        }
        self.finish_entry()?;
        let mut pax = Pax::default();
        let mut long_name: Option<Vec<u8>> = None;
        let mut long_link: Option<Vec<u8>> = None;
        let mut pending = false;
        let mut block = [0u8; BLOCK];
        loop {
            if !self.block_or_end(&mut block)? {
                return self.end(pending);
            }
            if block.iter().all(|&b| b == 0) {
                if self.block_or_end(&mut block)? && block.iter().any(|&b| b != 0) {
                    return Err(tar("a zero block followed by data"));
                }
                return self.end(pending);
            }
            let h = parse_header(&block)?;
            match h.typeflag {
                b'x' => {
                    let body = self.special(h.size)?;
                    parse_pax(&body, Some(&mut pax))?;
                    pending = true;
                }
                b'g' => {
                    let body = self.special(h.size)?;
                    parse_pax(&body, None)?;
                }
                b'L' | b'K' => {
                    let body = self.special(h.size)?;
                    let value = until_nul(&body).to_vec();
                    if h.typeflag == b'L' {
                        long_name = Some(value);
                    } else {
                        long_link = Some(value);
                    }
                    pending = true;
                }
                b'S' => return Err(tar("sparse files are not supported")),
                t => {
                    let mut path = long_name.take().unwrap_or(h.name);
                    if let Some(p) = pax.path.take() {
                        path = p;
                    }
                    let mut link = long_link.take().unwrap_or(h.linkname);
                    if let Some(l) = pax.link.take() {
                        link = l;
                    }
                    let kind = match t {
                        b'0' | b'7' => Kind::File,
                        0 if path.ends_with(b"/") => Kind::Dir,
                        0 => Kind::File,
                        b'1' => Kind::HardLink,
                        b'2' => Kind::Symlink,
                        b'3' => Kind::Char,
                        b'4' => Kind::Block,
                        b'5' => Kind::Dir,
                        b'6' => Kind::Fifo,
                        _ => return Err(tar("unsupported entry type")),
                    };
                    let size = pax.size.unwrap_or(h.size);
                    // Header-only types carry no data, whatever the size
                    // field says (Go's reader).
                    let size = if kind == Kind::File { size } else { 0 };
                    self.remaining = size;
                    self.pad = padding(size);
                    return Ok(Some(Entry {
                        path,
                        link,
                        kind,
                        mode: h.mode,
                        mtime: pax.mtime.unwrap_or(Mtime {
                            secs: h.mtime,
                            nanos: 0,
                        }),
                        size,
                        devmajor: h.devmajor,
                        devminor: h.devminor,
                    }));
                }
            }
        }
    }

    fn end(&mut self, pending: bool) -> Result<Option<Entry>, Error> {
        if pending {
            return Err(tar("an extension header without an entry"));
        }
        self.done = true;
        Ok(None)
    }

    /// Reads from the current entry's body.
    pub(crate) fn read_body(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(self.remaining).map_or(buf.len(), |r| r.min(buf.len()));
        let n = loop {
            match self.source.read(&mut buf[..want]) {
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(from_io(e)),
            }
        };
        if n == 0 {
            return Err(tar("truncated archive"));
        }
        self.remaining -= u64::try_from(n).unwrap_or(u64::MAX);
        Ok(n)
    }
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

fn until_nul(b: &[u8]) -> &[u8] {
    b.iter().position(|&c| c == 0).map_or(b, |i| &b[..i])
}

struct Raw {
    name: Vec<u8>,
    linkname: Vec<u8>,
    typeflag: u8,
    mode: u32,
    size: u64,
    mtime: i64,
    devmajor: u64,
    devminor: u64,
}

fn field(block: &[u8; BLOCK], start: usize, end: usize) -> &[u8] {
    block.get(start..end).unwrap_or(&[])
}

fn parse_header(block: &[u8; BLOCK]) -> Result<Raw, Error> {
    let stored =
        parse_octal(field(block, 148, 156)).map_err(|_| tar("unreadable header checksum"))?;
    let mut unsigned: i64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in block.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += i64::from(b);
        signed += i64::from(b as i8);
    }
    let stored = i64::try_from(stored).unwrap_or(-1);
    if stored != unsigned && stored != signed {
        return Err(tar("header checksum mismatch"));
    }
    let magic = field(block, 257, 263);
    let version = field(block, 263, 265);
    let ustar = magic == b"ustar\0" && version == b"00";
    let gnu = magic == b"ustar " && version == b" \0";
    if !ustar && !gnu {
        return Err(tar("not a ustar or GNU header"));
    }
    let mut name = until_nul(field(block, 0, 100)).to_vec();
    if ustar {
        let prefix = until_nul(field(block, 345, 500));
        if !prefix.is_empty() {
            let mut joined = prefix.to_vec();
            joined.push(b'/');
            joined.extend_from_slice(&name);
            name = joined;
        }
    }
    let mode = parse_numeric(field(block, 100, 108))?;
    let size = parse_numeric(field(block, 124, 136))?;
    let mtime = parse_numeric(field(block, 136, 148))?;
    let devmajor = parse_numeric(field(block, 329, 337))?;
    let devminor = parse_numeric(field(block, 337, 345))?;
    Ok(Raw {
        name,
        linkname: until_nul(field(block, 157, 257)).to_vec(),
        typeflag: block[156],
        mode: u32::try_from(mode & 0o7777).unwrap_or(0),
        size: u64::try_from(size).map_err(|_| tar("negative size"))?,
        mtime,
        devmajor: u64::try_from(devmajor).map_err(|_| tar("negative device number"))?,
        devminor: u64::try_from(devminor).map_err(|_| tar("negative device number"))?,
    })
}

/// An octal field: leading and trailing spaces and NULs are trimmed (Go's
/// `parseOctal`), an empty field is 0.
fn parse_octal(b: &[u8]) -> Result<u64, Error> {
    let trim = |c: &u8| *c == b' ' || *c == 0;
    let start = b.iter().position(|c| !trim(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !trim(c)).map_or(start, |i| i + 1);
    let mut value: u64 = 0;
    for &c in b.get(start..end).unwrap_or(&[]) {
        if !(b'0'..=b'7').contains(&c) {
            return Err(tar("invalid octal number"));
        }
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
            .ok_or(tar("number out of range"))?;
    }
    Ok(value)
}

/// A numeric field in octal or base-256 (first byte with bit 0x80). A
/// negative base-256 number (bit 0x40 also set) is refused; the value must
/// fit an `i64`, as in Go.
fn parse_numeric(b: &[u8]) -> Result<i64, Error> {
    let Some((&first, rest)) = b.split_first() else {
        return Ok(0);
    };
    let value = if first & 0x80 != 0 {
        if first & 0x40 != 0 {
            return Err(tar("negative base-256 number"));
        }
        let mut v = u64::from(first & 0x3f);
        for &c in rest {
            if v >> 56 != 0 {
                return Err(tar("number out of range"));
            }
            v = (v << 8) | u64::from(c);
        }
        v
    } else {
        parse_octal(b)?
    };
    i64::try_from(value).map_err(|_| tar("number out of range"))
}

/// Unsigned decimal digits, at most `i64::MAX` (Go's `ParseInt` range).
fn parse_decimal(b: &[u8]) -> Option<u64> {
    if b.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    (v <= i64::MAX as u64).then_some(v)
}

/// A PAX time, `[+-]secs[.fraction]` (Go's `parsePAXTime`): at most nine
/// fraction digits count, the rest are dropped; a leading `-` makes the
/// fraction negative too.
fn parse_pax_time(v: &[u8]) -> Result<Mtime, Error> {
    let bad = || tar("invalid PAX mtime");
    let (ss, sn) = match v.iter().position(|&c| c == b'.') {
        Some(i) => (&v[..i], &v[i + 1..]),
        None => (v, &[][..]),
    };
    let (negative, digits) = match ss.split_first() {
        Some((b'-', d)) => (true, d),
        Some((b'+', d)) => (false, d),
        _ => (false, ss),
    };
    let magnitude = parse_decimal(digits).ok_or_else(bad)?;
    let secs = i64::try_from(magnitude).map_err(|_| bad())?;
    let secs = if negative { -secs } else { secs };
    if !sn.iter().all(u8::is_ascii_digit) {
        return Err(bad());
    }
    let mut nanos: u32 = 0;
    for i in 0..9 {
        let d = sn.get(i).map_or(0, |c| u32::from(c - b'0'));
        nanos = nanos * 10 + d;
    }
    if negative && nanos > 0 {
        let secs = secs.checked_sub(1).ok_or_else(bad)?;
        return Ok(Mtime {
            secs,
            nanos: 1_000_000_000 - nanos,
        });
    }
    Ok(Mtime { secs, nanos })
}

/// Parses PAX records (`"<len> <key>=<value>\n"`, Go's `parsePAXRecord`)
/// into `into`, later keys winning; `None` checks the framing only (a `g`
/// header).
fn parse_pax(mut body: &[u8], mut into: Option<&mut Pax>) -> Result<(), Error> {
    let bad = || tar("malformed PAX record");
    while !body.is_empty() {
        let space = body.iter().position(|&c| c == b' ').ok_or_else(bad)?;
        let n = parse_decimal(&body[..space]).ok_or_else(bad)?;
        let n = usize::try_from(n).map_err(|_| bad())?;
        if n < 5 || n > body.len() || space + 1 > n - 1 {
            return Err(bad());
        }
        let (record, rest) = body.split_at(n);
        if record.last() != Some(&b'\n') {
            return Err(bad());
        }
        let kv = &record[space + 1..n - 1];
        let eq = kv.iter().position(|&c| c == b'=').ok_or_else(bad)?;
        let (key, value) = (&kv[..eq], &kv[eq + 1..]);
        if key.is_empty() || key.contains(&0) {
            return Err(bad());
        }
        if let Some(pax) = into.as_deref_mut() {
            match key {
                b"path" | b"linkpath" if value.contains(&0) => {
                    return Err(tar("NUL in a PAX path"));
                }
                b"path" => pax.path = Some(value.to_vec()),
                b"linkpath" => pax.link = Some(value.to_vec()),
                b"size" => pax.size = Some(parse_decimal(value).ok_or(tar("invalid PAX size"))?),
                b"mtime" => pax.mtime = Some(parse_pax_time(value)?),
                k if k.starts_with(b"GNU.sparse.") => {
                    return Err(tar("sparse files are not supported"));
                }
                _ => {}
            }
        }
        body = rest;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Mtime, parse_decimal, parse_numeric, parse_octal, parse_pax_time};

    #[test]
    fn octal_fields() {
        assert_eq!(parse_octal(b"0000644\0").expect("ok"), 0o644);
        assert_eq!(parse_octal(b"  644 \0").expect("ok"), 0o644);
        assert_eq!(parse_octal(b"\0\0\0\0").expect("ok"), 0);
        assert_eq!(parse_octal(b"").expect("ok"), 0);
        assert!(parse_octal(b"0008").is_err());
        assert!(parse_octal(b"6 4").is_err());
        assert!(parse_octal(b"7777777777777777777777").is_err());
    }

    #[test]
    fn numeric_fields() {
        let mut b = [0u8; 12];
        b[0] = 0x80;
        b[11] = 5;
        assert_eq!(parse_numeric(&b).expect("base-256"), 5);
        b[0] = 0xff;
        assert!(parse_numeric(&b).is_err(), "negative");
        let mut max = [0xffu8; 12];
        max[0] = 0x80;
        max[1..4].fill(0);
        max[4] = 0x7f;
        assert_eq!(parse_numeric(&max).expect("i64::MAX"), i64::MAX);
        max[4] = 0x80;
        assert!(parse_numeric(&max).is_err(), "above i64");
    }

    #[test]
    fn decimal_and_time() {
        assert_eq!(parse_decimal(b"9223372036854775807"), Some(i64::MAX as u64));
        assert_eq!(parse_decimal(b"9223372036854775808"), None);
        assert_eq!(parse_decimal(b"+1"), None);
        assert_eq!(
            parse_pax_time(b"-1.5").expect("ok"),
            Mtime {
                secs: -2,
                nanos: 500_000_000
            }
        );
        assert_eq!(
            parse_pax_time(b"-9223372036854775807.5").expect("ok"),
            Mtime {
                secs: i64::MIN,
                nanos: 500_000_000
            }
        );
        assert!(parse_pax_time(b"-").is_err());
        assert!(parse_pax_time(b".5").is_err());
    }
}
