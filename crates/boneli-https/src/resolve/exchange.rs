//! One try of the resolver against one name server (ADR-022, D4 and D5):
//! the A and AAAA queries over one connected UDP socket, an answer with
//! TC=1 asked again over TCP, or both over TCP under `use-vc`. Every wait
//! is bounded by the end of the try, which is never past the request's
//! deadline, and the try runs on the caller's thread.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use super::DNS_UDP_MESSAGE_BYTES;
use super::message::{Outstanding, Parsed, QType, RCODE_NXDOMAIN, encode_query, parse_response};
use crate::dial::{DeadlineSocket, time_left};
use crate::random::fill_random;

/// Where a query stands within one try.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Slot {
    /// Asked, not answered yet.
    Pending,
    /// Answered with rcode 0 (addresses or NODATA) or NXDOMAIN.
    Settled { addrs: Vec<IpAddr> },
    /// Answered with TC=1: ask again over TCP.
    Truncated,
    /// Answered with a failing rcode or a malformed answer. The other
    /// query is still waited for (ADR-022, D5), as glibc's `send_dg` does.
    Failed,
}

/// Why a server failed a try.
#[derive(Debug)]
pub(crate) enum Fail {
    /// The server's port is closed (ICMP port unreachable, or a TCP reset).
    Refused,
    /// An rcode other than 0 and 3: SERVFAIL, NOTIMP, REFUSED and the rest.
    Rcode(u8),
    /// A matched answer the format does not allow, a truncated answer over
    /// TCP, or a TCP frame of length 0.
    Malformed,
    /// A socket error.
    Io(io::Error),
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fail::Refused => f.write_str("connection refused"),
            Fail::Rcode(rcode) => write!(f, "rcode {rcode}"),
            Fail::Malformed => f.write_str("malformed answer"),
            Fail::Io(e) => write!(f, "{e}"),
        }
    }
}

/// What a received message did to the slots.
#[derive(Debug)]
pub(crate) enum Event {
    /// Not an answer to a pending query, or a second answer to one: the
    /// wait goes on.
    Ignored,
    /// A pending query is answered.
    Settled,
    /// A pending query needs TCP.
    Truncated,
    /// A pending query failed (its slot is `Failed`).
    Failed(Fail),
}

/// The outcome of one try.
#[derive(Debug)]
pub(crate) enum TryResult {
    /// Addresses for either type, A first.
    Found(Vec<IpAddr>),
    /// NODATA or NXDOMAIN for both types.
    NoName,
    /// The server failed.
    Failed(Fail),
    /// The try's wait ended before both types were settled.
    TimedOut,
}

/// Applies `parsed` to the slot of the outstanding query it answers,
/// matched by id and question type, so an A and an AAAA query with the
/// same id are told apart. An answer to a slot that is no longer pending
/// (a duplicate datagram) is ignored. A failing rcode or a malformed
/// answer fails that slot only.
pub(crate) fn match_response(
    parsed: Parsed,
    outstanding: &[Outstanding],
    slots: &mut [Slot],
) -> Event {
    let (id, qtype) = match &parsed {
        Parsed::Ignored => return Event::Ignored,
        Parsed::Malformed { id, qtype } => (*id, *qtype),
        Parsed::Answer(answer) => (answer.id, answer.qtype),
    };
    let Some(index) = outstanding
        .iter()
        .position(|o| o.id == id && o.qtype == qtype)
    else {
        return Event::Ignored;
    };
    let Some(slot) = slots.get_mut(index) else {
        return Event::Ignored;
    };
    if *slot != Slot::Pending {
        return Event::Ignored;
    }
    let answer = match parsed {
        Parsed::Answer(answer) => answer,
        _ => {
            *slot = Slot::Failed;
            return Event::Failed(Fail::Malformed);
        }
    };
    if answer.truncated {
        *slot = Slot::Truncated;
        return Event::Truncated;
    }
    if answer.rcode != 0 && answer.rcode != RCODE_NXDOMAIN {
        *slot = Slot::Failed;
        return Event::Failed(Fail::Rcode(answer.rcode));
    }
    *slot = Slot::Settled {
        addrs: answer.addrs,
    };
    Event::Settled
}

/// One try of `name` (lowercase wire form) against `server`, ending by
/// `try_end`. A TCP retry after TC=1 gets its own window of `try_timeout`,
/// bounded by `deadline`. `Err` only when the random source fails: the ids
/// are never predictable.
pub(crate) fn try_server(
    server: SocketAddr,
    name: &[u8],
    use_vc: bool,
    try_timeout: Duration,
    try_end: Instant,
    deadline: Instant,
) -> io::Result<TryResult> {
    let mut ids = [0u8; 4];
    fill_random(&mut ids).map_err(io::Error::other)?;
    let outstanding = [
        Outstanding {
            id: u16::from_be_bytes([ids[0], ids[1]]),
            qtype: QType::A,
            name: name.to_vec(),
        },
        Outstanding {
            id: u16::from_be_bytes([ids[2], ids[3]]),
            qtype: QType::Aaaa,
            name: name.to_vec(),
        },
    ];
    let mut slots = [Slot::Pending, Slot::Pending];
    let failure = if use_vc {
        tcp_phase(server, &outstanding, &mut slots, try_end)
    } else {
        match udp_phase(server, &outstanding, &mut slots, try_end) {
            Err(fail) => Some(fail),
            Ok(failed) if slots.contains(&Slot::Truncated) => {
                let window = Instant::now()
                    .checked_add(try_timeout)
                    .map_or(deadline, |end| end.min(deadline));
                tcp_phase(server, &outstanding, &mut slots, window).or(failed)
            }
            Ok(failed) => failed,
        }
    };
    Ok(evaluate(&slots, failure))
}

/// Addresses for either type win, even beside a failure or a silence;
/// then a failure (of a query or of the server); then NODATA or NXDOMAIN
/// for both; else the wait ended.
fn evaluate(slots: &[Slot], failure: Option<Fail>) -> TryResult {
    let addrs: Vec<IpAddr> = slots
        .iter()
        .flat_map(|slot| match slot {
            Slot::Settled { addrs } => addrs.clone(),
            _ => Vec::new(),
        })
        .collect();
    if !addrs.is_empty() {
        return TryResult::Found(addrs);
    }
    if let Some(fail) = failure {
        return TryResult::Failed(fail);
    }
    if slots.iter().all(|s| matches!(s, Slot::Settled { .. })) {
        TryResult::NoName
    } else {
        TryResult::TimedOut
    }
}

/// Both queries over one connected UDP socket, then answers until both
/// slots leave `Pending` or `try_end` comes. `Ok` carries the failure of a
/// query, if one failed: the phase waits on for the other (ADR-022, D5).
/// `Err` is a socket error, which ends the phase at once. A datagram
/// longer than 512 bytes is read as truncated (the kernel cut it), so its
/// type is asked again over TCP.
fn udp_phase(
    server: SocketAddr,
    outstanding: &[Outstanding],
    slots: &mut [Slot],
    try_end: Instant,
) -> Result<Option<Fail>, Fail> {
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind::<::std::net::SocketAddr>(local)
        .and_then(|s| s.connect::<::std::net::SocketAddr>(server).map(|()| s))
        .map_err(io_fail)?;
    for query in outstanding {
        socket
            .send(&encode_query(query.id, &query.name, query.qtype))
            .map_err(io_fail)?;
    }
    let mut failed = None;
    let mut buf = [0u8; DNS_UDP_MESSAGE_BYTES + 1];
    while slots.contains(&Slot::Pending) {
        let left = try_end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        socket.set_read_timeout(Some(left)).map_err(Fail::Io)?;
        let len = match socket.recv(&mut buf) {
            Ok(len) => len,
            Err(e) if is_wait_over(&e) || e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_fail(e)),
        };
        if len > DNS_UDP_MESSAGE_BYTES
            && let Some(flags) = buf.get_mut(2)
        {
            *flags |= 0x02;
        }
        let msg = buf
            .get(..len.min(DNS_UDP_MESSAGE_BYTES))
            .unwrap_or_default();
        if let Event::Failed(fail) =
            match_response(parse_response(msg, outstanding), outstanding, slots)
        {
            failed = Some(fail);
        }
    }
    Ok(failed)
}

/// Every pending or truncated query over TCP, one connection each, in
/// slot order, until `window_end`. A query still pending at the end of
/// the window stays pending: the try timed out. A failed query does not
/// stop the next one (ADR-022, D5); a connection error ends the phase.
fn tcp_phase(
    server: SocketAddr,
    outstanding: &[Outstanding],
    slots: &mut [Slot],
    window_end: Instant,
) -> Option<Fail> {
    let mut failed = None;
    for index in 0..slots.len() {
        let Some(slot) = slots.get_mut(index) else {
            continue;
        };
        if !matches!(slot, Slot::Pending | Slot::Truncated) {
            continue;
        }
        *slot = Slot::Pending;
        let Some(query) = outstanding.get(index) else {
            continue;
        };
        match tcp_query(server, outstanding, slots, query, window_end) {
            Ok(()) => {}
            Err(TcpEnd::WaitOver) => return failed,
            Err(TcpEnd::Answer(fail)) => {
                if let Some(slot) = slots.get_mut(index) {
                    *slot = Slot::Failed;
                }
                failed = Some(fail);
            }
            Err(TcpEnd::Fail(fail)) => return Some(fail),
        }
    }
    failed
}

enum TcpEnd {
    /// The window ended.
    WaitOver,
    /// The answer to the query failed it: the next query is still asked.
    Answer(Fail),
    /// The connection failed.
    Fail(Fail),
}

impl From<io::Error> for TcpEnd {
    fn from(e: io::Error) -> TcpEnd {
        if is_wait_over(&e) {
            TcpEnd::WaitOver
        } else {
            TcpEnd::Fail(io_fail(e))
        }
    }
}

/// One query over its own TCP connection, framed by a two-byte length
/// (RFC 1035, 4.2.2), every read and write under `window_end`. Messages
/// that do not answer it are skipped; a zero length or an answer with
/// TC=1 is malformed.
fn tcp_query(
    server: SocketAddr,
    outstanding: &[Outstanding],
    slots: &mut [Slot],
    query: &Outstanding,
    window_end: Instant,
) -> Result<(), TcpEnd> {
    let tcp = TcpStream::connect_timeout(&server, time_left(window_end)?)?;
    let mut socket = DeadlineSocket::new(tcp, window_end);
    let body = encode_query(query.id, &query.name, query.qtype);
    let len = u16::try_from(body.len()).map_err(|_| TcpEnd::Fail(Fail::Malformed))?;
    let mut frame = len.to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    socket.write_all(&frame)?;
    loop {
        let mut prefix = [0u8; 2];
        socket.read_exact(&mut prefix)?;
        let len = usize::from(u16::from_be_bytes(prefix));
        if len == 0 {
            return Err(TcpEnd::Fail(Fail::Malformed));
        }
        let mut msg = vec![0u8; len];
        socket.read_exact(&mut msg)?;
        match match_response(parse_response(&msg, outstanding), outstanding, slots) {
            Event::Ignored => {}
            Event::Settled => return Ok(()),
            Event::Truncated => return Err(TcpEnd::Answer(Fail::Malformed)),
            Event::Failed(fail) => return Err(TcpEnd::Answer(fail)),
        }
    }
}

/// A timeout of a socket wait (`WouldBlock` on Linux) or of the deadline.
fn is_wait_over(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn io_fail(e: io::Error) -> Fail {
    if e.kind() == io::ErrorKind::ConnectionRefused {
        Fail::Refused
    } else {
        Fail::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{Event, Slot, match_response};
    use crate::resolve::message::tests::{Msg, wire};
    use crate::resolve::message::{Outstanding, QType, parse_response};

    fn both(id_a: u16, id_aaaa: u16) -> [Outstanding; 2] {
        [
            Outstanding {
                id: id_a,
                qtype: QType::A,
                name: wire("git.example"),
            },
            Outstanding {
                id: id_aaaa,
                qtype: QType::Aaaa,
                name: wire("git.example"),
            },
        ]
    }

    fn settled(ip: &str) -> Slot {
        Slot::Settled {
            addrs: vec![ip.parse::<IpAddr>().expect("ip")],
        }
    }

    #[test]
    fn equal_ids_are_told_apart_by_question_type() {
        let outstanding = both(7, 7);
        let mut slots = [Slot::Pending, Slot::Pending];
        let aaaa = Msg::answer(7, "git.example", QType::Aaaa, 0, 1)
            .record(
                28,
                1,
                &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            )
            .bytes;
        let event = match_response(
            parse_response(&aaaa, &outstanding),
            &outstanding,
            &mut slots,
        );
        assert!(matches!(event, Event::Settled), "{event:?}");
        assert_eq!(slots, [Slot::Pending, settled("2001:db8::1")]);
        let a = Msg::answer(7, "git.example", QType::A, 0, 1)
            .record(1, 1, &[192, 0, 2, 1])
            .bytes;
        let event = match_response(parse_response(&a, &outstanding), &outstanding, &mut slots);
        assert!(matches!(event, Event::Settled), "{event:?}");
        assert_eq!(slots, [settled("192.0.2.1"), settled("2001:db8::1")]);
    }

    #[test]
    fn duplicate_answers_leave_the_first_in_place() {
        let outstanding = both(1, 2);
        let mut slots = [Slot::Pending, Slot::Pending];
        let first = Msg::answer(1, "git.example", QType::A, 0, 1)
            .record(1, 1, &[192, 0, 2, 1])
            .bytes;
        let second = Msg::answer(1, "git.example", QType::A, 0, 1)
            .record(1, 1, &[192, 0, 2, 2])
            .bytes;
        for msg in [&first, &second] {
            match_response(parse_response(msg, &outstanding), &outstanding, &mut slots);
        }
        assert_eq!(slots[0], settled("192.0.2.1"));
        // A SERVFAIL after the answer changes nothing either.
        let servfail = Msg::answer(1, "git.example", QType::A, 2, 0).bytes;
        let event = match_response(
            parse_response(&servfail, &outstanding),
            &outstanding,
            &mut slots,
        );
        assert!(matches!(event, Event::Ignored), "{event:?}");
    }

    #[test]
    fn rcodes_settle_truncate_or_fail() {
        let outstanding = both(1, 2);
        for (rcode, want) in [
            (0u8, "settled"),
            (3, "settled"),
            (2, "failed"),
            (5, "failed"),
            (4, "failed"),
        ] {
            let mut slots = [Slot::Pending, Slot::Pending];
            let msg = Msg::answer(1, "git.example", QType::A, rcode, 0).bytes;
            let event =
                match_response(parse_response(&msg, &outstanding), &outstanding, &mut slots);
            let got = match event {
                Event::Settled => "settled",
                Event::Failed(_) => "failed",
                other => panic!("{other:?}"),
            };
            assert_eq!(got, want, "rcode {rcode}");
        }
        // A failure fails its own slot only; the other still settles, and a
        // later answer to the failed one is ignored.
        let mut slots = [Slot::Pending, Slot::Pending];
        let servfail = Msg::answer(2, "git.example", QType::Aaaa, 2, 0).bytes;
        let event = match_response(
            parse_response(&servfail, &outstanding),
            &outstanding,
            &mut slots,
        );
        assert!(matches!(event, Event::Failed(_)), "{event:?}");
        assert_eq!(slots, [Slot::Pending, Slot::Failed]);
        let mut cut = Msg::answer(1, "git.example", QType::A, 0, 1)
            .record(1, 1, &[192, 0, 2, 1])
            .bytes;
        cut.pop();
        let event = match_response(parse_response(&cut, &outstanding), &outstanding, &mut slots);
        assert!(matches!(event, Event::Failed(_)), "{event:?}");
        assert_eq!(slots, [Slot::Failed, Slot::Failed]);
        let late = Msg::answer(2, "git.example", QType::Aaaa, 0, 0).bytes;
        let event = match_response(
            parse_response(&late, &outstanding),
            &outstanding,
            &mut slots,
        );
        assert!(matches!(event, Event::Ignored), "{event:?}");

        let mut slots = [Slot::Pending, Slot::Pending];
        let mut tc = Msg::answer(2, "git.example", QType::Aaaa, 0, 0).bytes;
        tc[2] |= 0x02;
        let event = match_response(parse_response(&tc, &outstanding), &outstanding, &mut slots);
        assert!(matches!(event, Event::Truncated), "{event:?}");
        assert_eq!(slots, [Slot::Pending, Slot::Truncated]);
    }
}
