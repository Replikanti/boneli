//! The DNS messages of the stub resolver (ADR-022, D4): a query for one
//! name and type with recursion desired, and the reader of the answer.
//!
//! The reader takes hostile input: whoever can send a datagram to the
//! resolver's port from the name server's address. Every index is checked,
//! so no input panics; a message is either ignored (it does not get as far
//! as matching the id and question of an outstanding query), an answer, or
//! a malformed answer to a matched query. Only the answer section is read;
//! the authority and additional sections never are, so a record a name
//! server adds there cannot place an address.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The fixed header of every DNS message (RFC 1035, 4.1.1).
pub(crate) const HEADER_BYTES: usize = 12;

/// The longest name on the wire, length octets and the root's zero
/// included (RFC 1035, 2.3.4).
pub(crate) const MAX_WIRE_NAME: usize = 255;

/// The longest label (RFC 1035, 2.3.4): the two high bits of a length
/// octet are the label type, so 63 is also the format's own limit.
const MAX_LABEL: usize = 63;

/// The most compression pointers one name may follow (ADR-022, Numbers).
/// A name has at most 127 labels (255 octets, each label at least 2), and
/// a pointer that saves space leads to at least one label, because a
/// pointer to a bare root octet or to another pointer is no shorter than
/// what it replaces; so no space-saving encoding needs more jumps. Without
/// a cap, a TCP answer of 65,532 bytes whose 4,096 owner names follow one
/// chain of 8,169 pointers took about 145 ms to parse (release build,
/// development host); at the cap the heaviest such answer, 5,436 owner
/// names of 127 jumps, takes 3 to 5 ms.
const MAX_POINTER_JUMPS: usize = 127;

const CLASS_IN: u16 = 1;
const TYPE_CNAME: u16 = 5;
const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;

/// The rcode of a name error (NXDOMAIN, RFC 1035, 4.1.1).
pub(crate) const RCODE_NXDOMAIN: u8 = 3;

/// The two record types the resolver asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QType {
    /// An IPv4 address (RFC 1035).
    A,
    /// An IPv6 address (RFC 3596).
    Aaaa,
}

impl QType {
    fn code(self) -> u16 {
        match self {
            QType::A => 1,
            QType::Aaaa => 28,
        }
    }
}

/// A query in flight: its id, type and name in lowercase wire form. An
/// answer counts only when its id, question name (case-insensitively),
/// type and class IN match one of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Outstanding {
    pub(crate) id: u16,
    pub(crate) qtype: QType,
    pub(crate) name: Vec<u8>,
}

/// What a received message is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    /// Not an answer to an outstanding query: shorter than the header, a
    /// query (QR=0), another opcode, another id, a question that does not
    /// parse, or another question. The wait goes on, as glibc's `send_dg`
    /// drops such datagrams, so a sender who does not know the id cannot
    /// fail the server.
    Ignored,
    /// The answer to the outstanding query `(id, qtype)`.
    Answer(Answer),
    /// The answer to the outstanding query `(id, qtype)`, but not one the
    /// format allows: that query failed.
    Malformed { id: u16, qtype: QType },
}

/// An answer to an outstanding query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) id: u16,
    pub(crate) qtype: QType,
    /// 0 is an answer or NODATA, 3 is NXDOMAIN, anything else a failure.
    pub(crate) rcode: u8,
    /// TC=1: the answer did not fit, ask again over TCP. Its records are
    /// not read.
    pub(crate) truncated: bool,
    /// The addresses of the query's type owned by the last name of the
    /// CNAME chain, in message order; empty unless rcode is 0.
    pub(crate) addrs: Vec<IpAddr>,
}

/// `name` (dotted, no trailing dot) in lowercase wire form, or `None` when
/// it is not a name the resolver asks for: an empty label, a label over 63
/// bytes, more than 255 octets on the wire, or a byte that is not printable
/// ASCII. A search domain from resolv.conf passes through here too, so
/// such a candidate is skipped instead of sent.
pub(crate) fn wire_name(name: &str) -> Option<Vec<u8>> {
    let mut wire = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_LABEL || !bytes.iter().all(u8::is_ascii_graphic) {
            return None;
        }
        wire.push(u8::try_from(bytes.len()).ok()?);
        wire.extend(bytes.iter().map(u8::to_ascii_lowercase));
    }
    wire.push(0);
    (wire.len() <= MAX_WIRE_NAME).then_some(wire)
}

/// The query for `name` (lowercase wire form, from [`wire_name`]) and
/// `qtype`: RD=1, one question of class IN, no EDNS record, so the answer
/// over UDP is at most 512 bytes (RFC 1035, 4.2.1).
pub(crate) fn encode_query(id: u16, name: &[u8], qtype: QType) -> Vec<u8> {
    let mut query = Vec::with_capacity(HEADER_BYTES + name.len() + 4);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&FLAG_RD.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[0; 6]);
    query.extend_from_slice(name);
    query.extend_from_slice(&qtype.code().to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());
    query
}

/// Reads `msg` as the answer to one of `outstanding`. Anything before the
/// (id, question) match is ignored; only a matched answer can be malformed.
pub(crate) fn parse_response(msg: &[u8], outstanding: &[Outstanding]) -> Parsed {
    let Some(header) = Header::read(msg) else {
        return Parsed::Ignored;
    };
    if header.flags & FLAG_QR == 0 || (header.flags >> 11) & 0xF != 0 || header.qdcount != 1 {
        return Parsed::Ignored;
    }
    let Some((qname, pos)) = read_name(msg, HEADER_BYTES) else {
        return Parsed::Ignored;
    };
    let (Some(qtype), Some(qclass)) = (be16(msg, pos), be16(msg, pos + 2)) else {
        return Parsed::Ignored;
    };
    let Some(query) = outstanding.iter().find(|o| {
        o.id == header.id && o.qtype.code() == qtype && qclass == CLASS_IN && o.name == qname
    }) else {
        return Parsed::Ignored;
    };
    let rcode = u8::try_from(header.flags & 0xF).unwrap_or(u8::MAX);
    let truncated = header.flags & FLAG_TC != 0;
    let mut answer = Answer {
        id: query.id,
        qtype: query.qtype,
        rcode,
        truncated,
        addrs: Vec::new(),
    };
    if truncated || rcode != 0 {
        return Parsed::Answer(answer);
    }
    match read_answers(msg, pos + 4, header.ancount, &qname, query.qtype) {
        Some(addrs) => {
            answer.addrs = addrs;
            Parsed::Answer(answer)
        }
        None => Parsed::Malformed {
            id: query.id,
            qtype: query.qtype,
        },
    }
}

struct Header {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
}

impl Header {
    fn read(msg: &[u8]) -> Option<Header> {
        if msg.len() < HEADER_BYTES {
            return None;
        }
        Some(Header {
            id: be16(msg, 0)?,
            flags: be16(msg, 2)?,
            qdcount: be16(msg, 4)?,
            ancount: be16(msg, 6)?,
        })
    }
}

/// What the answer section says, as far as the resolver reads it.
enum Record {
    Address { owner: Vec<u8>, ip: IpAddr },
    Cname { owner: Vec<u8>, target: Vec<u8> },
}

/// The addresses of `qtype` for `qname` from the `ancount` records at
/// `pos`, through the CNAME chain, or `None` when the section is
/// malformed. Records of another class or type are skipped; an A or AAAA
/// record of class IN must have the address's length, and a CNAME's name
/// must fill its RDATA exactly.
fn read_answers(
    msg: &[u8],
    mut pos: usize,
    ancount: u16,
    qname: &[u8],
    qtype: QType,
) -> Option<Vec<IpAddr>> {
    let mut records = Vec::new();
    for _ in 0..ancount {
        let (owner, after) = read_name(msg, pos)?;
        let rtype = be16(msg, after)?;
        let rclass = be16(msg, after + 2)?;
        let rdlength = usize::from(be16(msg, after + 8)?);
        let start = after + 10;
        let end = start.checked_add(rdlength)?;
        let rdata = msg.get(start..end)?;
        if rclass == CLASS_IN {
            if rtype == QType::A.code() {
                let octets: [u8; 4] = rdata.try_into().ok()?;
                let ip = IpAddr::V4(Ipv4Addr::from(octets));
                records.push((rtype, Record::Address { owner, ip }));
            } else if rtype == QType::Aaaa.code() {
                let octets: [u8; 16] = rdata.try_into().ok()?;
                let ip = IpAddr::V6(Ipv6Addr::from(octets));
                records.push((rtype, Record::Address { owner, ip }));
            } else if rtype == TYPE_CNAME {
                let (target, name_end) = read_name(msg, start)?;
                if name_end != end {
                    return None;
                }
                records.push((rtype, Record::Cname { owner, target }));
            }
        }
        pos = end;
    }
    // The chain: the first CNAME of each owner, followed from the question
    // name at most `ancount` steps; a name met twice is a loop.
    let mut cnames: BTreeMap<&[u8], &[u8]> = BTreeMap::new();
    for (_, record) in &records {
        if let Record::Cname { owner, target } = record {
            cnames.entry(owner.as_slice()).or_insert(target.as_slice());
        }
    }
    let mut current = qname;
    let mut seen = BTreeSet::from([qname]);
    for _ in 0..ancount {
        let Some(&target) = cnames.get(current) else {
            break;
        };
        if !seen.insert(target) {
            return None;
        }
        current = target;
    }
    Some(
        records
            .iter()
            .filter_map(|(rtype, record)| match record {
                Record::Address { owner, ip } if *rtype == qtype.code() && owner == current => {
                    Some(*ip)
                }
                _ => None,
            })
            .collect(),
    )
}

/// The name at `start` in lowercase wire form, and the offset just past
/// it where it sits (after its first compression pointer, if any). `None`
/// when malformed: a label type 0x40 or 0x80 (RFC 6891 and the retired
/// binary labels), a label or pointer cut by the end of the message, more
/// than 255 octets, a compression pointer that does not point strictly
/// before the labels it ends, or more than [`MAX_POINTER_JUMPS`] pointers.
/// Each pointer must point before the previous target, so reading always
/// ends; the cap bounds the work.
fn read_name(msg: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut name = Vec::new();
    let mut pos = start;
    let mut limit = start;
    let mut end = None;
    let mut jumps = 0usize;
    loop {
        let len = *msg.get(pos)?;
        match len & 0xC0 {
            0x00 if len == 0 => {
                name.push(0);
                if name.len() > MAX_WIRE_NAME {
                    return None;
                }
                return Some((name, end.unwrap_or(pos + 1)));
            }
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(len))?;
                name.push(len);
                name.extend(label.iter().map(u8::to_ascii_lowercase));
                if name.len() >= MAX_WIRE_NAME {
                    return None;
                }
                pos += 1 + usize::from(len);
            }
            0xC0 => {
                let low = *msg.get(pos + 1)?;
                let target = (usize::from(len & 0x3F) << 8) | usize::from(low);
                jumps += 1;
                if target >= limit || jumps > MAX_POINTER_JUMPS {
                    return None;
                }
                end.get_or_insert(pos + 2);
                limit = target;
                pos = target;
            }
            _ => return None,
        }
    }
}

fn be16(msg: &[u8], at: usize) -> Option<u16> {
    let bytes = msg.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::IpAddr;

    use super::{
        HEADER_BYTES, MAX_POINTER_JUMPS, MAX_WIRE_NAME, Outstanding, Parsed, QType, encode_query,
        parse_response, read_name, wire_name,
    };

    const ID: u16 = 0x1234;

    /// A response builder for the tests: header flags, the question of
    /// the outstanding query, then raw records.
    pub(crate) struct Msg {
        pub(crate) bytes: Vec<u8>,
    }

    impl Msg {
        /// QR=1, RD=1, RA=1, rcode, one question `name`/`qtype`, `ancount`.
        pub(crate) fn answer(id: u16, name: &str, qtype: QType, rcode: u8, ancount: u16) -> Msg {
            let mut bytes = encode_query(id, &wire(name), qtype);
            let flags = 0x8180u16 | u16::from(rcode);
            bytes[2..4].copy_from_slice(&flags.to_be_bytes());
            bytes[6..8].copy_from_slice(&ancount.to_be_bytes());
            Msg { bytes }
        }

        /// A record with `owner` given as raw wire bytes.
        pub(crate) fn record_raw(
            mut self,
            owner: &[u8],
            rtype: u16,
            class: u16,
            rdata: &[u8],
        ) -> Msg {
            self.bytes.extend_from_slice(owner);
            self.bytes.extend_from_slice(&rtype.to_be_bytes());
            self.bytes.extend_from_slice(&class.to_be_bytes());
            self.bytes.extend_from_slice(&300u32.to_be_bytes());
            let len = u16::try_from(rdata.len()).expect("rdata length");
            self.bytes.extend_from_slice(&len.to_be_bytes());
            self.bytes.extend_from_slice(rdata);
            self
        }

        /// A record owned by the question name (a pointer to offset 12).
        pub(crate) fn record(self, rtype: u16, class: u16, rdata: &[u8]) -> Msg {
            self.record_raw(&[0xC0, 12], rtype, class, rdata)
        }
    }

    pub(crate) fn wire(name: &str) -> Vec<u8> {
        wire_name(name).expect("test name")
    }

    fn pending(qtype: QType) -> Vec<Outstanding> {
        vec![Outstanding {
            id: ID,
            qtype,
            name: wire("git.example"),
        }]
    }

    fn addrs(parsed: Parsed) -> Vec<IpAddr> {
        match parsed {
            Parsed::Answer(answer) => answer.addrs,
            other => panic!("expected an answer, got {other:?}"),
        }
    }

    /// The matched A query `ID`, malformed.
    fn malformed_a() -> Parsed {
        Parsed::Malformed {
            id: ID,
            qtype: QType::A,
        }
    }

    /// A valid answer with two A records for `git.example`.
    fn two_records() -> Vec<u8> {
        Msg::answer(ID, "git.example", QType::A, 0, 2)
            .record(1, 1, &[192, 0, 2, 1])
            .record(1, 1, &[192, 0, 2, 2])
            .bytes
    }

    #[test]
    fn query_parses_back_to_its_question() {
        let name = wire("git.Example");
        let query = encode_query(ID, &name, QType::Aaaa);
        assert_eq!(&query[0..2], &ID.to_be_bytes());
        // RD=1, QR=0, opcode 0, one question, no other records.
        assert_eq!(&query[2..4], &[0x01, 0x00]);
        assert_eq!(&query[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
        let (read, pos) = read_name(&query, HEADER_BYTES).expect("question name");
        assert_eq!(read, wire("git.example"));
        assert_eq!(&query[pos..], &[0, 28, 0, 1]);
        assert_eq!(pos + 4, query.len());
        // The same bytes with QR=1 answer the query.
        let mut answer = query.clone();
        answer[2] |= 0x80;
        let outstanding = [Outstanding {
            id: ID,
            qtype: QType::Aaaa,
            name,
        }];
        assert_eq!(
            addrs(parse_response(&answer, &outstanding)),
            Vec::<IpAddr>::new()
        );
    }

    #[test]
    fn wire_name_of_255_octets_passes_and_256_fails() {
        let label = |n: usize| "a".repeat(n);
        let name = |last: usize| format!("{0}.{0}.{0}.{1}", label(63), label(last));
        // 3 x (1 + 63) + (1 + 61) + 1 = 255.
        let ok = wire_name(&name(61)).expect("255 octets");
        assert_eq!(ok.len(), MAX_WIRE_NAME);
        assert_eq!(wire_name(&name(62)), None);
        assert_eq!(wire_name(&label(64)), None);
        assert_eq!(wire_name("a..b"), None);
        assert_eq!(wire_name("a b"), None);

        // The same bounds on a name read from a message.
        let mut msg = vec![0; HEADER_BYTES];
        msg.extend_from_slice(&ok);
        assert_eq!(read_name(&msg, HEADER_BYTES).map(|(n, _)| n), Some(ok));
        let mut long = vec![0; HEADER_BYTES];
        for len in [63u8, 63, 63, 62] {
            long.push(len);
            long.extend(std::iter::repeat_n(b'a', usize::from(len)));
        }
        long.push(0);
        assert_eq!(long.len() - HEADER_BYTES, 256);
        assert_eq!(read_name(&long, HEADER_BYTES), None);
    }

    #[test]
    fn compression_pointer_must_point_backwards() {
        // A name `example` at offset 12, then names at 21 built from it.
        let mut msg = vec![0; HEADER_BYTES];
        msg.extend_from_slice(&wire("example"));
        let at = msg.len();
        // `git` + pointer back to 12: passes.
        msg.extend_from_slice(&[3, b'g', b'i', b't', 0xC0, 12]);
        let (name, end) = read_name(&msg, at).expect("backward pointer");
        assert_eq!(name, wire("git.example"));
        assert_eq!(end, msg.len());
        // A pointer to itself.
        let mut own = msg.clone();
        let p = own.len();
        own.extend_from_slice(&[0xC0, u8::try_from(p).expect("offset")]);
        assert_eq!(read_name(&own, p), None);
        // A forward pointer, and one out of bounds.
        let mut fwd = msg.clone();
        let p = fwd.len();
        fwd.extend_from_slice(&[0xC0, u8::try_from(p + 2).expect("offset"), 0]);
        assert_eq!(read_name(&fwd, p), None);
        let mut out = msg.clone();
        let p = out.len();
        out.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(read_name(&out, p), None);
        // A pointer into its own labels: a loop.
        let mut lp = msg.clone();
        let p = lp.len();
        lp.extend_from_slice(&[1, b'a', 0xC0, u8::try_from(p).expect("offset")]);
        assert_eq!(read_name(&lp, p), None);
        // A pointer cut after its first byte.
        let mut cut = msg;
        let p = cut.len();
        cut.push(0xC0);
        assert_eq!(read_name(&cut, p), None);
    }

    #[test]
    fn extended_label_types_are_malformed() {
        for kind in [0x40u8, 0x80] {
            let mut msg = vec![0; HEADER_BYTES];
            msg.extend_from_slice(&[kind | 1, b'a', 0]);
            assert_eq!(read_name(&msg, HEADER_BYTES), None, "{kind:#x}");
        }
        // In an answer record's owner name too.
        let msg = Msg::answer(ID, "git.example", QType::A, 0, 1)
            .record_raw(&[0x41, b'a', 0], 1, 1, &[192, 0, 2, 1])
            .bytes;
        assert_eq!(parse_response(&msg, &pending(QType::A)), malformed_a());
    }

    #[test]
    fn wrong_rdata_length_is_malformed() {
        for (qtype, rtype, len) in [
            (QType::A, 1u16, 3usize),
            (QType::A, 1, 5),
            (QType::Aaaa, 28, 15),
            (QType::Aaaa, 28, 17),
        ] {
            let msg = Msg::answer(ID, "git.example", qtype, 0, 1)
                .record(rtype, 1, &vec![1; len])
                .bytes;
            assert_eq!(
                parse_response(&msg, &pending(qtype)),
                Parsed::Malformed { id: ID, qtype },
                "type {rtype} length {len}"
            );
        }
        let aaaa = Msg::answer(ID, "git.example", QType::Aaaa, 0, 1)
            .record(
                28,
                1,
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            )
            .bytes;
        assert_eq!(
            addrs(parse_response(&aaaa, &pending(QType::Aaaa))),
            vec!["2001:db8::1".parse::<IpAddr>().expect("ip")]
        );
    }

    #[test]
    fn rdata_ending_at_the_last_byte_passes_and_one_short_fails() {
        let msg = two_records();
        assert_eq!(
            addrs(parse_response(&msg, &pending(QType::A))),
            vec![
                "192.0.2.1".parse::<IpAddr>().expect("ip"),
                "192.0.2.2".parse().expect("ip")
            ]
        );
        let short = &msg[..msg.len() - 1];
        assert_eq!(parse_response(short, &pending(QType::A)), malformed_a());
    }

    #[test]
    fn cname_loop_is_malformed() {
        let a = wire("a.example");
        let b = wire("b.example");
        let msg = Msg::answer(ID, "a.example", QType::A, 0, 3)
            .record_raw(&a, 5, 1, &b)
            .record_raw(&b, 5, 1, &a)
            .record_raw(&b, 1, 1, &[192, 0, 2, 1])
            .bytes;
        let outstanding = [Outstanding {
            id: ID,
            qtype: QType::A,
            name: a.clone(),
        }];
        assert_eq!(parse_response(&msg, &outstanding), malformed_a());

        // A chain a -> b -> c: only c's addresses count.
        let c = wire("c.example");
        let msg = Msg::answer(ID, "a.example", QType::A, 0, 5)
            .record_raw(&a, 1, 1, &[192, 0, 2, 9])
            .record_raw(&b, 5, 1, &c)
            .record_raw(&a, 5, 1, &b)
            .record_raw(&b, 1, 1, &[192, 0, 2, 8])
            .record_raw(&c, 1, 1, &[192, 0, 2, 3])
            .bytes;
        assert_eq!(
            addrs(parse_response(&msg, &outstanding)),
            vec!["192.0.2.3".parse::<IpAddr>().expect("ip")]
        );
        // A CNAME whose name does not fill its RDATA.
        let mut padded = b.clone();
        padded.push(0);
        let msg = Msg::answer(ID, "a.example", QType::A, 0, 1)
            .record_raw(&a, 5, 1, &padded)
            .bytes;
        assert_eq!(parse_response(&msg, &outstanding), malformed_a());
    }

    #[test]
    fn records_of_other_owners_are_ignored() {
        let msg = Msg::answer(ID, "git.example", QType::A, 0, 2)
            .record_raw(&wire("evil.example"), 1, 1, &[203, 0, 113, 1])
            .record(1, 1, &[192, 0, 2, 1])
            .bytes;
        assert_eq!(
            addrs(parse_response(&msg, &pending(QType::A))),
            vec!["192.0.2.1".parse::<IpAddr>().expect("ip")]
        );
    }

    #[test]
    fn additional_section_addresses_are_ignored() {
        // ANCOUNT 0, NSCOUNT 1, ARCOUNT 1, both holding A records of the
        // question name.
        let mut msg = Msg::answer(ID, "git.example", QType::A, 0, 0)
            .record(1, 1, &[203, 0, 113, 1])
            .record(1, 1, &[203, 0, 113, 2])
            .bytes;
        msg[8..10].copy_from_slice(&1u16.to_be_bytes());
        msg[10..12].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            addrs(parse_response(&msg, &pending(QType::A))),
            Vec::<IpAddr>::new()
        );
    }

    #[test]
    fn other_class_and_unknown_types_are_skipped() {
        let msg = Msg::answer(ID, "git.example", QType::A, 0, 4)
            // Class CH, with a length no A record has.
            .record(1, 3, &[1, 2, 3])
            // TXT and an unassigned type.
            .record(16, 1, b"\x05hello")
            .record(65280, 1, &[0; 7])
            .record(1, 1, &[192, 0, 2, 1])
            .bytes;
        assert_eq!(
            addrs(parse_response(&msg, &pending(QType::A))),
            vec!["192.0.2.1".parse::<IpAddr>().expect("ip")]
        );
        // An AAAA record in an A answer is read but does not count.
        let msg = Msg::answer(ID, "git.example", QType::A, 0, 1)
            .record(28, 1, &[0; 16])
            .bytes;
        assert_eq!(
            addrs(parse_response(&msg, &pending(QType::A))),
            Vec::<IpAddr>::new()
        );
    }

    #[test]
    fn unmatched_short_or_broken_messages_are_ignored() {
        // Shorter than the header, or cut inside the question: no (id,
        // question) match, so ignored, as glibc's `send_dg` drops them.
        let msg = two_records();
        let question_end = HEADER_BYTES + wire("git.example").len() + 4;
        for len in 0..question_end {
            assert_eq!(
                parse_response(&msg[..len], &pending(QType::A)),
                Parsed::Ignored,
                "{len}"
            );
        }
        // A question name with an extended label type, or a pointer.
        let mut label = msg.clone();
        label[HEADER_BYTES] = 0x41;
        let mut pointer = msg;
        pointer[HEADER_BYTES..HEADER_BYTES + 2].copy_from_slice(&[0xC0, 12]);
        for bytes in [label, pointer] {
            assert_eq!(parse_response(&bytes, &pending(QType::A)), Parsed::Ignored);
        }
    }

    #[test]
    fn counts_beyond_the_matched_message_are_malformed() {
        let msg = two_records();
        let mut more = msg.clone();
        more[6..8].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(parse_response(&more, &pending(QType::A)), malformed_a());
        let mut huge = msg;
        huge[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(parse_response(&huge, &pending(QType::A)), malformed_a());
    }

    #[test]
    fn mismatched_id_question_or_qr_is_ignored_not_malformed() {
        let msg = two_records();
        let mut query = msg.clone();
        query[2] &= 0x7F;
        let mut other_id = msg.clone();
        other_id[0] ^= 1;
        let other_name = Msg::answer(ID, "gitx.example", QType::A, 0, 0).bytes;
        let other_type = Msg::answer(ID, "git.example", QType::Aaaa, 0, 0).bytes;
        let mut other_class = msg.clone();
        let class_at = HEADER_BYTES + wire("git.example").len() + 2;
        other_class[class_at..class_at + 2].copy_from_slice(&3u16.to_be_bytes());
        let mut opcode = msg.clone();
        opcode[2] |= 0x10;
        let mut two_questions = msg;
        two_questions[4..6].copy_from_slice(&2u16.to_be_bytes());
        for (what, bytes) in [
            ("QR=0", query),
            ("id", other_id),
            ("name", other_name),
            ("type", other_type),
            ("class", other_class),
            ("opcode", opcode),
            ("QDCOUNT", two_questions),
        ] {
            assert_eq!(
                parse_response(&bytes, &pending(QType::A)),
                Parsed::Ignored,
                "{what}"
            );
        }
    }

    #[test]
    fn question_name_matches_case_insensitively() {
        let mut msg = two_records();
        let name_at = HEADER_BYTES + 1;
        msg[name_at..name_at + 3].copy_from_slice(b"GiT");
        assert_eq!(addrs(parse_response(&msg, &pending(QType::A))).len(), 2);
    }

    #[test]
    fn truncated_and_failed_answers_carry_no_records() {
        let mut tc = two_records();
        tc[2] |= 0x02;
        match parse_response(&tc, &pending(QType::A)) {
            Parsed::Answer(answer) => {
                assert!(answer.truncated);
                assert_eq!(answer.addrs, Vec::<IpAddr>::new());
            }
            other => panic!("{other:?}"),
        }
        let servfail = Msg::answer(ID, "git.example", QType::A, 2, 0).bytes;
        match parse_response(&servfail, &pending(QType::A)) {
            Parsed::Answer(answer) => assert_eq!(answer.rcode, 2),
            other => panic!("{other:?}"),
        }
    }

    /// A message whose name at the returned offset is `jumps` compression
    /// pointers, each pointing at the one before, ending at `a` (offset 12).
    fn pointer_chain(jumps: usize) -> (Vec<u8>, usize) {
        let mut msg = vec![0; HEADER_BYTES];
        msg.extend_from_slice(&[1, b'a', 0]);
        let mut last = HEADER_BYTES;
        for _ in 0..jumps {
            let at = msg.len();
            let pointer = u16::try_from(last).expect("offset") | 0xC000;
            msg.extend_from_slice(&pointer.to_be_bytes());
            last = at;
        }
        (msg, last)
    }

    #[test]
    fn pointer_jumps_per_name_are_capped() {
        let (msg, at) = pointer_chain(MAX_POINTER_JUMPS);
        assert_eq!(read_name(&msg, at), Some((wire("a"), at + 2)));
        let (msg, at) = pointer_chain(MAX_POINTER_JUMPS + 1);
        assert_eq!(read_name(&msg, at), None);
    }

    /// The most pointer work one message can ask for: an unknown record
    /// whose RDATA holds a chain of `chain` pointers, then as many records
    /// as fit in 65,535 bytes whose owner is the chain's head.
    fn pointer_heavy_message(chain: usize) -> (Vec<u8>, u16) {
        let mut msg = Msg::answer(ID, "git.example", QType::A, 0, 0).bytes;
        msg.extend_from_slice(&[0xC0, 12, 0xFF, 0x00, 0, 1, 0, 0, 0, 0]);
        let len_at = msg.len();
        msg.extend_from_slice(&[0, 0]);
        let start = msg.len();
        msg.push(0);
        let mut last = start;
        for _ in 0..chain {
            let at = msg.len();
            let pointer = u16::try_from(last).expect("offset") | 0xC000;
            msg.extend_from_slice(&pointer.to_be_bytes());
            last = at;
        }
        let rdlength = u16::try_from(msg.len() - start).expect("rdlength");
        msg[len_at..len_at + 2].copy_from_slice(&rdlength.to_be_bytes());
        let owner = (u16::try_from(last).expect("offset") | 0xC000).to_be_bytes();
        let mut count: u16 = 1;
        while msg.len() + 12 <= usize::from(u16::MAX) {
            msg.extend_from_slice(&owner);
            msg.extend_from_slice(&[0xFF, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
            count += 1;
        }
        msg[6..8].copy_from_slice(&count.to_be_bytes());
        (msg, count)
    }

    #[test]
    fn pointer_chain_beyond_the_cap_is_malformed() {
        // The review's message: a chain of 8,169 pointers that every
        // owner name points at.
        let (msg, _) = pointer_heavy_message(8_169);
        assert_eq!(
            parse_response(&msg, &pending(QType::A)),
            Parsed::Malformed {
                id: ID,
                qtype: QType::A
            }
        );
        // At the cap (the owner pointer is the first jump) the message is
        // read; the time is ADR-022's number.
        let (msg, count) = pointer_heavy_message(MAX_POINTER_JUMPS - 1);
        let start = std::time::Instant::now();
        let parsed = parse_response(&msg, &pending(QType::A));
        eprintln!(
            "{} bytes, {count} records, {MAX_POINTER_JUMPS} jumps each: {:?}",
            msg.len(),
            start.elapsed()
        );
        assert_eq!(addrs(parsed), Vec::<IpAddr>::new());
    }

    #[test]
    fn every_truncation_and_byte_flip_parses_without_panic() {
        let msg = two_records();
        let outstanding = pending(QType::A);
        let mut answers = 0;
        for len in 0..msg.len() {
            if let Parsed::Answer(_) = parse_response(&msg[..len], &outstanding) {
                answers += 1;
            }
        }
        for at in 0..msg.len() {
            let mut flipped = msg.clone();
            flipped[at] ^= 0xFF;
            if let Parsed::Answer(_) = parse_response(&flipped, &outstanding) {
                answers += 1;
            }
        }
        // Some flips (the TTL, the address bytes) leave an answer.
        assert!(answers > 0);
    }
}
