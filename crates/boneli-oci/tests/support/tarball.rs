//! A test-only tar writer: ustar, GNU long names and PAX, plus the knobs the
//! framing tests need (checksum forms, base-256 numbers, raw headers), and
//! gzip and zstd encoders for the fixtures.

/// The tar block size.
pub const BLOCK: usize = 512;

/// The magic and version fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Magic {
    /// `ustar\0` `00` (POSIX ustar, also what PAX archives use).
    Ustar,
    /// `ustar ` ` \0` (GNU).
    Gnu,
    /// All zeros (V7), which the reader refuses.
    V7,
}

/// How the header checksum is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Checksum {
    /// The sum of the bytes as unsigned values (POSIX).
    Unsigned,
    /// The sum of the bytes as signed values (old Sun and GNU tar).
    Signed,
    /// The unsigned sum plus one.
    Wrong,
}

/// One header block, field by field.
#[derive(Clone, Debug)]
pub struct Header {
    /// The name field (at most 100 bytes are written).
    pub name: Vec<u8>,
    /// The ustar prefix field (at most 155 bytes are written).
    pub prefix: Vec<u8>,
    /// The mode field.
    pub mode: u32,
    /// The uid field.
    pub uid: u64,
    /// The gid field.
    pub gid: u64,
    /// The size field.
    pub size: u64,
    /// The mtime field; a negative value is written in base-256.
    pub mtime: i64,
    /// The type flag.
    pub typeflag: u8,
    /// The linkname field (at most 100 bytes are written).
    pub linkname: Vec<u8>,
    /// The magic and version fields.
    pub magic: Magic,
    /// The device major number.
    pub devmajor: u32,
    /// The device minor number.
    pub devminor: u32,
    /// How the checksum is written.
    pub checksum: Checksum,
    /// The size field in base-256 instead of octal.
    pub size_base256: bool,
    /// A raw size field that overrides `size` (for negative base-256).
    pub raw_size: Option<[u8; 12]>,
    /// Raw bytes written at an offset before the checksum is computed.
    pub patches: Vec<(usize, Vec<u8>)>,
}

/// The mtime every helper writes unless a test sets its own.
pub const MTIME: i64 = 1_700_000_000;

impl Header {
    /// A ustar header with mode 0o644 and [`MTIME`].
    pub fn new(name: &[u8], typeflag: u8) -> Header {
        Header {
            name: name.to_vec(),
            prefix: Vec::new(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: MTIME,
            typeflag,
            linkname: Vec::new(),
            magic: Magic::Ustar,
            devmajor: 0,
            devminor: 0,
            checksum: Checksum::Unsigned,
            size_base256: false,
            raw_size: None,
            patches: Vec::new(),
        }
    }

    /// The 512-byte block.
    pub fn encode(&self) -> [u8; BLOCK] {
        let mut b = [0u8; BLOCK];
        put_bytes(&mut b[0..100], &self.name);
        put_octal(&mut b[100..108], u64::from(self.mode));
        put_octal(&mut b[108..116], self.uid);
        put_octal(&mut b[116..124], self.gid);
        if let Some(raw) = self.raw_size {
            b[124..136].copy_from_slice(&raw);
        } else if self.size_base256 {
            put_base256(&mut b[124..136], i128::from(self.size));
        } else {
            put_octal(&mut b[124..136], self.size);
        }
        if self.mtime < 0 {
            put_base256(&mut b[136..148], i128::from(self.mtime));
        } else {
            put_octal(
                &mut b[136..148],
                u64::try_from(self.mtime).expect("non-negative"),
            );
        }
        b[156] = self.typeflag;
        put_bytes(&mut b[157..257], &self.linkname);
        match self.magic {
            Magic::Ustar => {
                b[257..263].copy_from_slice(b"ustar\0");
                b[263..265].copy_from_slice(b"00");
            }
            Magic::Gnu => {
                b[257..263].copy_from_slice(b"ustar ");
                b[263..265].copy_from_slice(b" \0");
            }
            Magic::V7 => {}
        }
        if self.magic != Magic::V7 {
            put_octal(&mut b[329..337], u64::from(self.devmajor));
            put_octal(&mut b[337..345], u64::from(self.devminor));
        }
        if self.magic == Magic::Ustar {
            put_bytes(&mut b[345..500], &self.prefix);
        }
        for (at, bytes) in &self.patches {
            b[*at..*at + bytes.len()].copy_from_slice(bytes);
        }
        b[148..156].copy_from_slice(b"        ");
        let sum: i64 = match self.checksum {
            Checksum::Unsigned | Checksum::Wrong => b.iter().map(|&x| i64::from(x)).sum(),
            Checksum::Signed => b.iter().map(|&x| i64::from(x as i8)).sum(),
        };
        let sum = if self.checksum == Checksum::Wrong {
            sum + 1
        } else {
            sum
        };
        // Six octal digits, NUL, space; a negative signed sum is written as
        // its 18-bit two's complement, as old tars do.
        let sum = u64::try_from(sum.rem_euclid(1 << 18)).expect("in range");
        let text = format!("{sum:06o}\0 ");
        b[148..156].copy_from_slice(text.as_bytes());
        b
    }
}

fn put_bytes(field: &mut [u8], value: &[u8]) {
    let n = value.len().min(field.len());
    field[..n].copy_from_slice(&value[..n]);
}

fn put_octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    assert!(
        text.len() <= digits,
        "{value} does not fit {digits} octal digits"
    );
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
}

fn put_base256(field: &mut [u8], value: i128) {
    let bytes = value.to_be_bytes();
    let n = field.len();
    // Sign-extend into the field, then mark it base-256.
    for (i, slot) in field.iter_mut().enumerate() {
        let from = bytes.len() - n + i;
        *slot = bytes[from];
    }
    field[0] = if value < 0 { 0xff } else { 0x80 };
}

/// One PAX record, `"<len> <key>=<value>\n"`, with its length computed.
pub fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let body = key.len() + value.len() + 3; // space, '=', newline
    let mut len = body + 1;
    while len.to_string().len() + body != len {
        len = len.to_string().len() + body;
    }
    let mut out = format!("{len} {key}=").into_bytes();
    out.extend_from_slice(value);
    out.push(b'\n');
    assert_eq!(out.len(), len);
    out
}

/// An archive under construction.
#[derive(Default)]
pub struct Tar {
    /// The bytes so far.
    pub bytes: Vec<u8>,
}

impl Tar {
    /// An empty archive.
    pub fn new() -> Tar {
        Tar::default()
    }

    /// A header with `size` set to `data.len()` unless the header carries a
    /// raw size, then the data and its padding.
    pub fn entry(&mut self, header: &Header, data: &[u8]) -> &mut Tar {
        let mut h = header.clone();
        if h.raw_size.is_none() {
            h.size = u64::try_from(data.len()).expect("fits");
        }
        self.raw(&h, data)
    }

    /// The header exactly as given, then the data and its padding.
    pub fn raw(&mut self, header: &Header, data: &[u8]) -> &mut Tar {
        self.bytes.extend_from_slice(&header.encode());
        self.data(data)
    }

    /// Data plus zero padding to the next block.
    pub fn data(&mut self, data: &[u8]) -> &mut Tar {
        self.bytes.extend_from_slice(data);
        let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
        self.bytes.extend(std::iter::repeat_n(0u8, pad));
        self
    }

    /// A regular file.
    pub fn file(&mut self, name: &str, mode: u32, data: &[u8]) -> &mut Tar {
        let mut h = Header::new(name.as_bytes(), b'0');
        h.mode = mode;
        self.entry(&h, data)
    }

    /// A regular file with an mtime.
    pub fn file_at(&mut self, name: &str, mode: u32, data: &[u8], mtime: i64) -> &mut Tar {
        let mut h = Header::new(name.as_bytes(), b'0');
        h.mode = mode;
        h.mtime = mtime;
        self.entry(&h, data)
    }

    /// A directory.
    pub fn dir(&mut self, name: &str, mode: u32) -> &mut Tar {
        let mut h = Header::new(name.as_bytes(), b'5');
        h.mode = mode;
        self.entry(&h, &[])
    }

    /// A directory with an mtime.
    pub fn dir_at(&mut self, name: &str, mode: u32, mtime: i64) -> &mut Tar {
        let mut h = Header::new(name.as_bytes(), b'5');
        h.mode = mode;
        h.mtime = mtime;
        self.entry(&h, &[])
    }

    /// A symbolic link.
    pub fn symlink(&mut self, name: &str, target: &str) -> &mut Tar {
        let mut h = Header::new(name.as_bytes(), b'2');
        h.mode = 0o777;
        h.linkname = target.as_bytes().to_vec();
        self.entry(&h, &[])
    }

    /// A hard link.
    pub fn hardlink(&mut self, name: &str, target: &str) -> &mut Tar {
        let mut h = Header::new(name.as_bytes(), b'1');
        h.linkname = target.as_bytes().to_vec();
        self.entry(&h, &[])
    }

    /// A character (`b'3'`) or block (`b'4'`) device.
    pub fn device(&mut self, name: &str, typeflag: u8, major: u32, minor: u32) -> &mut Tar {
        let mut h = Header::new(name.as_bytes(), typeflag);
        h.devmajor = major;
        h.devminor = minor;
        self.entry(&h, &[])
    }

    /// A FIFO.
    pub fn fifo(&mut self, name: &str, mode: u32) -> &mut Tar {
        let mut h = Header::new(name.as_bytes(), b'6');
        h.mode = mode;
        self.entry(&h, &[])
    }

    /// A PAX extended header (`x`) for the next entry.
    pub fn pax(&mut self, records: &[(&str, &[u8])]) -> &mut Tar {
        self.pax_typed(b'x', records)
    }

    /// A PAX global header (`g`).
    pub fn pax_global(&mut self, records: &[(&str, &[u8])]) -> &mut Tar {
        self.pax_typed(b'g', records)
    }

    fn pax_typed(&mut self, typeflag: u8, records: &[(&str, &[u8])]) -> &mut Tar {
        let mut body = Vec::new();
        for (k, v) in records {
            body.extend_from_slice(&pax_record(k, v));
        }
        let h = Header::new(b"././@PaxHeader", typeflag);
        self.entry(&h, &body)
    }

    /// A GNU long name (`L`) or long link name (`K`) for the next entry,
    /// NUL-terminated as GNU tar writes it.
    pub fn gnu_long(&mut self, typeflag: u8, value: &[u8]) -> &mut Tar {
        let mut h = Header::new(b"././@LongLink", typeflag);
        h.magic = Magic::Gnu;
        let mut body = value.to_vec();
        body.push(0);
        self.entry(&h, &body)
    }

    /// `n` zero blocks.
    pub fn zero_blocks(&mut self, n: usize) -> &mut Tar {
        self.bytes.extend(std::iter::repeat_n(0u8, n * BLOCK));
        self
    }

    /// The archive with the two zero blocks of a normal end.
    pub fn finish(&mut self) -> Vec<u8> {
        self.zero_blocks(2);
        std::mem::take(&mut self.bytes)
    }

    /// The archive without an end marker.
    pub fn unterminated(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

/// CRC-32 (IEEE), so the gzip fixtures are real gzip files, even though the
/// reader does not check it (ADR-009, D5).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// One gzip member: a 10-byte header, raw deflate, CRC-32 and ISIZE.
pub fn gzip_member(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(data, 6));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    let isize = u32::try_from(data.len() % (1 << 32)).expect("fits");
    out.extend_from_slice(&isize.to_le_bytes());
    out
}

/// A gzip stream with one member.
pub fn gzip(data: &[u8]) -> Vec<u8> {
    gzip_member(data)
}

/// A zstd stream with one frame, from ruzstd's encoder.
pub fn zstd(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
}
