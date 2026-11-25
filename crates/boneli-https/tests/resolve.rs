//! The resolver of ADR-022 against fake name servers on 127.0.0.1: the
//! schedule over servers and candidates, the deadline, TCP after a
//! truncated answer, and what it never sends. Each fake server answers
//! over UDP and TCP on one port, as scripted per query, and records when
//! each query arrived.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use boneli_https::{Resolver, ResolverConfig};

/// How often the fake server's threads look at the stop flag.
const POLL: Duration = Duration::from_millis(5);

/// A deadline no test reaches, so only the try timeouts count.
const FAR: Duration = Duration::from_secs(30);

const A: u16 = 1;
const AAAA: u16 = 28;

/// One query the fake server received.
#[derive(Clone, Debug)]
struct Arrival {
    at: Instant,
    name: String,
    qtype: u16,
    tcp: bool,
}

/// What the fake server does with one query.
#[derive(Clone, Debug)]
enum Reply {
    /// rcode 0 with these addresses (those of the query's type).
    Answer(Vec<IpAddr>),
    /// The same answer after a delay.
    Later(Duration, Vec<IpAddr>),
    /// rcode 0 without records.
    NoData,
    NxDomain,
    ServFail,
    /// TC=1, no records.
    Truncated,
    /// Nothing; over TCP the connection stays open and silent.
    Silence,
    /// Raw datagrams, each sent as given (the query's id is patched in
    /// where the second element says so).
    Raw(Vec<(Vec<u8>, bool)>),
}

type Script = dyn Fn(&str, u16, bool) -> Reply + Send + Sync;

struct Fake {
    addr: SocketAddr,
    log: Arc<Mutex<Vec<Arrival>>>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Fake {
    /// A name server on UDP and TCP of one loopback port, answering as
    /// `script(name, qtype, over_tcp)` says.
    fn start(script: impl Fn(&str, u16, bool) -> Reply + Send + Sync + 'static) -> Fake {
        let script: Arc<Script> = Arc::new(script);
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").expect("udp bind");
            let port = udp.local_addr().expect("addr").port();
            // The same port for TCP; if another socket holds it, rebind.
            if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)) {
                break (udp, tcp);
            }
        };
        let addr = udp.local_addr().expect("addr");
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let threads = vec![
            spawn_udp(
                udp,
                Arc::clone(&script),
                Arc::clone(&log),
                Arc::clone(&stop),
            ),
            spawn_tcp(tcp, script, Arc::clone(&log), Arc::clone(&stop)),
        ];
        Fake {
            addr,
            log,
            stop,
            threads,
        }
    }

    fn arrivals(&self) -> Vec<Arrival> {
        self.log.lock().expect("log").clone()
    }

    fn count(&self) -> usize {
        self.arrivals().len()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// The query's id, lowercase dotted name and type; queries carry no
/// compression.
fn decode_query(msg: &[u8]) -> Option<(u16, String, u16)> {
    let id = u16::from_be_bytes([*msg.first()?, *msg.get(1)?]);
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*msg.get(pos)?);
        if len == 0 {
            break;
        }
        labels.push(String::from_utf8_lossy(msg.get(pos + 1..pos + 1 + len)?).into_owned());
        pos += 1 + len;
    }
    let qtype = u16::from_be_bytes([*msg.get(pos + 1)?, *msg.get(pos + 2)?]);
    Some((id, labels.join("."), qtype))
}

/// The response to `query` (its header and question copied) with
/// `flags` low bits as rcode and TC, and one record per address of the
/// query's type.
fn respond(query: &[u8], rcode: u8, truncated: bool, addrs: &[IpAddr]) -> Vec<u8> {
    let (_, name, qtype) = decode_query(query).expect("query");
    let question_end = 12 + name.len() + 2 + 4;
    let mut msg = query[..question_end].to_vec();
    let mut flags = 0x8180u16 | u16::from(rcode);
    if truncated {
        flags |= 0x0200;
    }
    msg[2..4].copy_from_slice(&flags.to_be_bytes());
    let records: Vec<Vec<u8>> = addrs
        .iter()
        .filter_map(|ip| match (ip, qtype) {
            (IpAddr::V4(v4), A) => Some(v4.octets().to_vec()),
            (IpAddr::V6(v6), AAAA) => Some(v6.octets().to_vec()),
            _ => None,
        })
        .collect();
    let count = u16::try_from(records.len()).expect("count");
    msg[6..8].copy_from_slice(&count.to_be_bytes());
    for rdata in records {
        msg.extend_from_slice(&[0xC0, 12]);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&u16::try_from(rdata.len()).expect("len").to_be_bytes());
        msg.extend_from_slice(&rdata);
    }
    msg
}

/// The datagrams `reply` sends for `query`, each with the time to send it.
fn render(query: &[u8], reply: &Reply, now: Instant) -> Vec<(Instant, Vec<u8>)> {
    match reply {
        Reply::Answer(addrs) => vec![(now, respond(query, 0, false, addrs))],
        Reply::Later(delay, addrs) => vec![(now + *delay, respond(query, 0, false, addrs))],
        Reply::NoData => vec![(now, respond(query, 0, false, &[]))],
        Reply::NxDomain => vec![(now, respond(query, 3, false, &[]))],
        Reply::ServFail => vec![(now, respond(query, 2, false, &[]))],
        Reply::Truncated => vec![(now, respond(query, 0, true, &[]))],
        Reply::Silence => Vec::new(),
        Reply::Raw(list) => list
            .iter()
            .map(|(bytes, patch_id)| {
                let mut bytes = bytes.clone();
                if *patch_id && bytes.len() >= 2 {
                    bytes[..2].copy_from_slice(&query[..2]);
                }
                (now, bytes)
            })
            .collect(),
    }
}

fn spawn_udp(
    udp: UdpSocket,
    script: Arc<Script>,
    log: Arc<Mutex<Vec<Arrival>>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        udp.set_read_timeout(Some(POLL)).expect("timeout");
        let mut due: Vec<(Instant, Vec<u8>, SocketAddr)> = Vec::new();
        let mut buf = [0u8; 1024];
        while !stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            due.retain(|(at, bytes, peer)| {
                if *at <= now {
                    let _ = udp.send_to(bytes, peer);
                    false
                } else {
                    true
                }
            });
            let (len, peer) = match udp.recv_from(&mut buf) {
                Ok(got) => got,
                Err(_) => continue,
            };
            let query = &buf[..len];
            let Some((_, name, qtype)) = decode_query(query) else {
                continue;
            };
            let at = Instant::now();
            log.lock().expect("log").push(Arrival {
                at,
                name: name.clone(),
                qtype,
                tcp: false,
            });
            for (when, bytes) in render(query, &script(&name, qtype, false), at) {
                if when <= at {
                    let _ = udp.send_to(&bytes, peer);
                } else {
                    due.push((when, bytes, peer));
                }
            }
        }
    })
}

fn spawn_tcp(
    tcp: TcpListener,
    script: Arc<Script>,
    log: Arc<Mutex<Vec<Arrival>>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        tcp.set_nonblocking(true).expect("nonblocking");
        let mut conns = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            match tcp.accept() {
                Ok((stream, _)) => {
                    let (script, log, stop) =
                        (Arc::clone(&script), Arc::clone(&log), Arc::clone(&stop));
                    conns.push(thread::spawn(move || {
                        serve_tcp(stream, &*script, &log, &stop)
                    }));
                }
                Err(_) => thread::sleep(POLL),
            }
        }
        for conn in conns {
            let _ = conn.join();
        }
    })
}

fn serve_tcp(mut stream: TcpStream, script: &Script, log: &Mutex<Vec<Arrival>>, stop: &AtomicBool) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(POLL));
    let mut pending = Vec::new();
    let mut buf = [0u8; 1024];
    while !stop.load(Ordering::SeqCst) {
        match stream.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue;
            }
            Err(_) => return,
        }
        while pending.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([pending[0], pending[1]]));
            if pending.len() < 2 + len {
                break;
            }
            let query: Vec<u8> = pending.drain(..2 + len).skip(2).collect();
            let Some((_, name, qtype)) = decode_query(&query) else {
                return;
            };
            let at = Instant::now();
            log.lock().expect("log").push(Arrival {
                at,
                name: name.clone(),
                qtype,
                tcp: true,
            });
            for (_, bytes) in render(&query, &script(&name, qtype, true), at) {
                let mut frame = u16::try_from(bytes.len())
                    .expect("len")
                    .to_be_bytes()
                    .to_vec();
                frame.extend_from_slice(&bytes);
                if stream.write_all(&frame).is_err() {
                    return;
                }
            }
        }
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip")
}

/// The usual answer: one A and one AAAA address.
fn both(_: &str, qtype: u16, _: bool) -> Reply {
    match qtype {
        A => Reply::Answer(vec![ip("192.0.2.1")]),
        _ => Reply::Answer(vec![ip("2001:db8::1")]),
    }
}

fn config(servers: &[&Fake], try_timeout: Duration, attempts: u8) -> ResolverConfig {
    ResolverConfig::new(
        servers.iter().map(|f| f.addr).collect(),
        try_timeout,
        attempts,
    )
    .expect("config")
}

fn lookup(resolver: &Resolver, host: &str, within: Duration) -> io::Result<Vec<SocketAddr>> {
    resolver.lookup(host, 443, Instant::now() + within)
}

fn addrs(list: &[&str]) -> Vec<SocketAddr> {
    list.iter().map(|s| SocketAddr::new(ip(s), 443)).collect()
}

#[test]
fn answers_resolve_ipv6_first() {
    let fake = Fake::start(both);
    let resolver = Resolver::fixed(config(&[&fake], FAR, 1));
    let got = lookup(&resolver, "git.example", FAR).expect("lookup");
    assert_eq!(got, addrs(&["2001:db8::1", "192.0.2.1"]));
    let arrivals = fake.arrivals();
    let mut types: Vec<u16> = arrivals.iter().map(|a| a.qtype).collect();
    types.sort_unstable();
    assert_eq!(types, [A, AAAA]);
    assert!(arrivals.iter().all(|a| a.name == "git.example" && !a.tcp));
}

#[test]
fn invalid_names_send_no_query() {
    let fake = Fake::start(both);
    let resolver = Resolver::fixed(config(&[&fake], FAR, 1));
    for bad in [
        "",
        "g\u{043E}t.example",
        "git\u{200B}.example",
        "git\u{00A0}.example",
        "git\u{FF0E}example",
        "127.1",
        "0x7f000001",
        "2130706433",
        "10.1",
        "a..b",
        "git.example.",
        "-a.example",
        "[::1]",
        "fe80::1%lo",
        "under_score.example",
        "git example",
    ] {
        let err = lookup(&resolver, bad, FAR).expect_err(bad);
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "{bad:?}");
    }
    let err = resolver
        .lookup("git.example", 0, Instant::now() + FAR)
        .expect_err("port 0");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(fake.count(), 0);
}

#[test]
fn name_length_bounds() {
    let fake = Fake::start(|_, _, _| Reply::NxDomain);
    let resolver = Resolver::fixed(config(&[&fake], FAR, 1));
    let label = |n: usize| "a".repeat(n);
    // A label of 63 bytes is asked; 64 is refused.
    let err = lookup(&resolver, &format!("{}.example", label(63)), FAR).expect_err("nxdomain");
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert_eq!(fake.count(), 2);
    let err = lookup(&resolver, &format!("{}.example", label(64)), FAR).expect_err("64");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    // A name of 253 bytes is asked; 254 is refused.
    let name = |last: usize| format!("{0}.{0}.{0}.{1}", label(63), label(last));
    assert_eq!(name(61).len(), 253);
    let err = lookup(&resolver, &name(61), FAR).expect_err("nxdomain");
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert_eq!(fake.count(), 4);
    let err = lookup(&resolver, &name(62), FAR).expect_err("254");
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert_eq!(fake.count(), 4);
}

#[test]
fn localhost_names_are_loopback_without_a_query() {
    let fake = Fake::start(both);
    let resolver = Resolver::fixed(config(&[&fake], FAR, 1));
    for name in [
        "localhost",
        "LOCALHOST",
        "registry.localhost",
        "A.B.Localhost",
    ] {
        assert_eq!(
            lookup(&resolver, name, FAR).expect(name),
            addrs(&["::1", "127.0.0.1"]),
            "{name}"
        );
    }
    // IP literals come back as they are.
    assert_eq!(
        lookup(&resolver, "192.0.2.7", FAR).expect("v4"),
        addrs(&["192.0.2.7"])
    );
    assert_eq!(
        lookup(&resolver, "2001:DB8::7", FAR).expect("v6"),
        addrs(&["2001:db8::7"])
    );
    assert_eq!(fake.count(), 0);
}

#[test]
fn deadline_passed_sends_nothing() {
    let fake = Fake::start(both);
    let resolver = Resolver::fixed(config(&[&fake], FAR, 1));
    let err = resolver
        .lookup("git.example", 443, Instant::now())
        .expect_err("deadline");
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(fake.count(), 0);
}

#[test]
fn hosts_entry_wins_over_dns() {
    let fake = Fake::start(both);
    let resolver = Resolver::fixed(
        config(&[&fake], FAR, 1)
            .with_hosts("192.0.2.9 git.example\n192.0.2.9 Git.Example\n".into()),
    );
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("hosts"),
        addrs(&["192.0.2.9"])
    );
    assert_eq!(fake.count(), 0);
}

#[test]
fn duplicate_addresses_are_tried_once() {
    let fake = Fake::start(|_, qtype, _| match qtype {
        A => Reply::Answer(vec![ip("192.0.2.1"), ip("192.0.2.1"), ip("192.0.2.2")]),
        _ => Reply::NoData,
    });
    let resolver = Resolver::fixed(config(&[&fake], FAR, 1));
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("lookup"),
        addrs(&["192.0.2.1", "192.0.2.2"])
    );
}

#[test]
fn arrival_order_does_not_change_the_result() {
    let late = Duration::from_millis(100);
    let a_late = Fake::start(move |_, qtype, _| match qtype {
        A => Reply::Later(late, vec![ip("192.0.2.1")]),
        _ => Reply::Answer(vec![ip("2001:db8::1")]),
    });
    let aaaa_late = Fake::start(move |_, qtype, _| match qtype {
        A => Reply::Answer(vec![ip("192.0.2.1")]),
        _ => Reply::Later(late, vec![ip("2001:db8::1")]),
    });
    let one = lookup(
        &Resolver::fixed(config(&[&a_late], FAR, 1)),
        "git.example",
        FAR,
    );
    let two = lookup(
        &Resolver::fixed(config(&[&aaaa_late], FAR, 1)),
        "git.example",
        FAR,
    );
    assert_eq!(one.expect("a late"), addrs(&["2001:db8::1", "192.0.2.1"]));
    assert_eq!(
        two.expect("aaaa late"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
}

#[test]
fn nodata_moves_to_the_next_candidate() {
    let fake = Fake::start(|name, qtype, _| match (name, qtype) {
        ("git.corp.example", _) => Reply::NoData,
        ("git.example", A) => Reply::Answer(vec![ip("192.0.2.1")]),
        _ => Reply::NoData,
    });
    let resolver = Resolver::fixed(
        config(&[&fake], FAR, 1).with_search(vec!["corp.example".into(), "example".into()]),
    );
    assert_eq!(
        lookup(&resolver, "git", FAR).expect("second candidate"),
        addrs(&["192.0.2.1"])
    );
    let names: Vec<String> = fake.arrivals().into_iter().map(|a| a.name).collect();
    assert_eq!(names.len(), 4);
    assert!(
        names[..2].iter().all(|n| n == "git.corp.example"),
        "{names:?}"
    );
    assert!(names[2..].iter().all(|n| n == "git.example"), "{names:?}");
}

#[test]
fn nxdomain_moves_to_the_next_candidate_not_server() {
    let first = Fake::start(|name, qtype, _| match (name, qtype) {
        ("git.example", A) => Reply::Answer(vec![ip("192.0.2.1")]),
        ("git.example", _) => Reply::NoData,
        _ => Reply::NxDomain,
    });
    let second = Fake::start(both);
    let resolver = Resolver::fixed(
        config(&[&first, &second], FAR, 2)
            .with_search(vec!["corp.example".into(), "example".into()]),
    );
    assert_eq!(
        lookup(&resolver, "git", FAR).expect("lookup"),
        addrs(&["192.0.2.1"])
    );
    assert_eq!(second.count(), 0);
    // Every candidate NXDOMAIN: NotFound, after one try each.
    let none = Fake::start(|_, _, _| Reply::NxDomain);
    let resolver =
        Resolver::fixed(config(&[&none, &second], FAR, 2).with_search(vec!["corp.example".into()]));
    let err = lookup(&resolver, "git", FAR).expect_err("no name");
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert_eq!(none.count(), 4);
    assert_eq!(second.count(), 0);
}

#[test]
fn servfail_moves_to_the_next_server() {
    let first = Fake::start(|_, _, _| Reply::ServFail);
    let second = Fake::start(both);
    let resolver = Resolver::fixed(config(&[&first, &second], FAR, 1));
    let start = Instant::now();
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("second server"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(second.count(), 2);
    // Only failing servers: an error that is neither NotFound nor TimedOut.
    let other = Fake::start(|_, _, _| Reply::ServFail);
    let resolver = Resolver::fixed(config(&[&first, &other], FAR, 2));
    let err = lookup(&resolver, "git.example", FAR).expect_err("servfail");
    assert_eq!(err.kind(), ErrorKind::Other, "{err}");
    assert!(err.to_string().contains("rcode 2"), "{err}");
}

#[test]
fn refused_server_moves_to_the_next_at_once() {
    // A port that was just bound and closed again: ICMP port unreachable.
    let closed = UdpSocket::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr");
    let second = Fake::start(both);
    let resolver = Resolver::fixed(
        ResolverConfig::new(vec![closed, second.addr], Duration::from_secs(5), 1).expect("config"),
    );
    let start = Instant::now();
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("second server"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[test]
fn timeout_on_every_server_ends_the_lookup() {
    let one = Fake::start(|_, _, _| Reply::Silence);
    let two = Fake::start(|_, _, _| Reply::Silence);
    let resolver = Resolver::fixed(
        config(&[&one, &two], Duration::from_millis(100), 1)
            .with_search(vec!["corp.example".into()]),
    );
    let err = lookup(&resolver, "git", FAR).expect_err("timeout");
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    for fake in [&one, &two] {
        let names: Vec<String> = fake.arrivals().into_iter().map(|a| a.name).collect();
        assert_eq!(names, ["git.corp.example", "git.corp.example"]);
    }
}

#[test]
fn schedule_is_attempts_times_servers_times_try_timeout() {
    let one = Fake::start(|_, _, _| Reply::Silence);
    let two = Fake::start(|_, _, _| Reply::Silence);
    let resolver = Resolver::fixed(config(&[&one, &two], Duration::from_millis(200), 2));
    let start = Instant::now();
    let err = lookup(&resolver, "git.example", FAR).expect_err("timeout");
    let elapsed = start.elapsed();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(elapsed >= Duration::from_millis(800), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
    // Each server got 2 tries of 2 datagrams, in the order s1, s2, s1, s2.
    let (a, b) = (one.arrivals(), two.arrivals());
    assert_eq!((a.len(), b.len()), (4, 4));
    let first = |list: &[Arrival], at: usize| list[at].at;
    assert!(first(&a, 0) < first(&b, 0));
    assert!(first(&b, 1) < first(&a, 2));
    assert!(first(&a, 3) < first(&b, 2));
    let since = |t: Instant| t.duration_since(start);
    assert!(since(first(&b, 0)) >= Duration::from_millis(200));
    assert!(since(first(&a, 2)) >= Duration::from_millis(400));
    assert!(since(first(&b, 2)) >= Duration::from_millis(600));
}

#[test]
fn stalled_server_times_out_at_the_deadline() {
    let fake = Fake::start(|_, _, _| Reply::Silence);
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_secs(10), 2));
    let start = Instant::now();
    let err = lookup(&resolver, "git.example", Duration::from_millis(300)).expect_err("deadline");
    let elapsed = start.elapsed();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    assert_eq!(fake.count(), 2);
}

/// Nothing outlives the call (#81, second criterion): with a 200 ms try
/// timeout, 5 attempts and a 500 ms deadline, tries start at 0, 200 and
/// 400 ms and the third ends at the deadline, so no fourth starts. Every
/// query arrived before `lookup` returned, and none comes later.
#[test]
fn no_query_after_the_lookup_returns() {
    let fake = Fake::start(|_, _, _| Reply::Silence);
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_millis(200), 5));
    let start = Instant::now();
    let err = lookup(&resolver, "git.example", Duration::from_millis(500)).expect_err("deadline");
    let returned = Instant::now();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(
        returned - start < Duration::from_secs(1),
        "{:?}",
        returned - start
    );
    let arrivals = fake.arrivals();
    // 3 tries of an A and an AAAA query; fewer when CI is slow.
    assert!(
        arrivals.len().is_multiple_of(2) && (2..=6).contains(&arrivals.len()),
        "{arrivals:?}"
    );
    assert!(arrivals.iter().all(|a| a.at < returned), "{arrivals:?}");
    thread::sleep(Duration::from_millis(600));
    assert_eq!(fake.count(), arrivals.len(), "a query after the return");
}

#[test]
fn partial_answer_after_the_try_timeout() {
    let fake = Fake::start(|_, qtype, _| match qtype {
        A => Reply::Answer(vec![ip("192.0.2.1")]),
        _ => Reply::Silence,
    });
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_millis(300), 2));
    let start = Instant::now();
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("partial"),
        addrs(&["192.0.2.1"])
    );
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    // One try, no retry.
    assert_eq!(fake.count(), 2);
}

#[test]
fn spoofed_and_duplicate_datagrams_are_ignored() {
    let fake = Fake::start(|name, qtype, _| {
        let answer = |addr: &str| {
            let mut query = Vec::new();
            query.extend_from_slice(&[0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            for label in name.split('.') {
                query.push(u8::try_from(label.len()).expect("label"));
                query.extend_from_slice(label.as_bytes());
            }
            query.push(0);
            query.extend_from_slice(&qtype.to_be_bytes());
            query.extend_from_slice(&1u16.to_be_bytes());
            respond(&query, 0, false, &[ip(addr)])
        };
        match qtype {
            A => {
                // Another id first, then the answer, then a second answer
                // with another address.
                let mut wrong = answer("203.0.113.66");
                wrong[0] = 0xAB;
                wrong[1] = 0xCD;
                Reply::Raw(vec![
                    (wrong, false),
                    (answer("192.0.2.1"), true),
                    (answer("192.0.2.2"), true),
                ])
            }
            _ => Reply::Later(Duration::from_millis(100), vec![ip("2001:db8::1")]),
        }
    });
    let resolver = Resolver::fixed(config(&[&fake], FAR, 1));
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("lookup"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
}

#[test]
fn mismatched_id_question_or_qr_is_ignored_not_malformed() {
    let fake = Fake::start(|name, qtype, _| {
        let mut query = vec![0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(u8::try_from(label.len()).expect("label"));
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        let good = respond(&query, 0, false, &[ip("192.0.2.1"), ip("2001:db8::1")]);
        // The query echoed back (QR=0), and an answer for another name.
        let echo = query.clone();
        let mut other = query.clone();
        other[13] = b'x';
        let other = respond(&other, 0, false, &[ip("203.0.113.1")]);
        Reply::Raw(vec![(echo, true), (other, true), (good, true)])
    });
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_secs(5), 1));
    let start = Instant::now();
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("lookup"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
    assert!(start.elapsed() < Duration::from_secs(1));
}

/// The query a resolver sends for `name` and `qtype`, id 0.
fn query_for(name: &str, qtype: u16) -> Vec<u8> {
    let mut query = vec![0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).expect("label"));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

/// The usual address of `qtype`.
fn usual(qtype: u16) -> IpAddr {
    if qtype == A {
        ip("192.0.2.1")
    } else {
        ip("2001:db8::1")
    }
}

#[test]
fn unmatched_garbage_is_ignored_not_a_failure() {
    // Before any answer, from the server's address: datagrams shorter than
    // the header, a header with the right id and a broken question, and a
    // header with the right id and the question cut off. None of them
    // matches (id, question), so none fails the server (ADR-022, D4).
    let fake = Fake::start(|name, qtype, _| {
        let good = respond(&query_for(name, qtype), 0, false, &[usual(qtype)]);
        let mut broken = good.clone();
        broken[12] = 0x41;
        let cut = good[..14].to_vec();
        Reply::Raw(vec![
            (vec![0xAB, 0xCD, 0x80], false),
            (vec![0xFF; 7], false),
            (broken, true),
            (cut, true),
            (good, true),
        ])
    });
    let second = Fake::start(both);
    let resolver = Resolver::fixed(config(&[&fake, &second], Duration::from_secs(5), 1));
    let start = Instant::now();
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("the only server's answer"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(second.count(), 0);
}

#[test]
fn malformed_matched_answer_fails_its_type_only() {
    // A: the matched answer cut inside its record, so malformed. AAAA:
    // the address 50 ms later, which still counts (ADR-022, D5).
    let fake = Fake::start(|name, qtype, _| match qtype {
        A => {
            let mut bad = respond(&query_for(name, qtype), 0, false, &[usual(qtype)]);
            bad.pop();
            Reply::Raw(vec![(bad, true)])
        }
        _ => Reply::Later(Duration::from_millis(50), vec![usual(qtype)]),
    });
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_secs(2), 1));
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("aaaa"),
        addrs(&["2001:db8::1"])
    );
    // Malformed for both types: the server failed, the next one is asked.
    let bad = Fake::start(|name, qtype, _| {
        let mut bad = respond(&query_for(name, qtype), 0, false, &[usual(qtype)]);
        bad.pop();
        Reply::Raw(vec![(bad, true)])
    });
    let second = Fake::start(both);
    let resolver = Resolver::fixed(config(&[&bad, &second], Duration::from_secs(5), 1));
    let start = Instant::now();
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("second server"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    let only = Resolver::fixed(config(&[&bad], Duration::from_secs(5), 1));
    let err = lookup(&only, "git.example", FAR).expect_err("malformed");
    assert_eq!(err.kind(), ErrorKind::Other, "{err}");
    assert!(err.to_string().contains("malformed answer"), "{err}");
}

#[test]
fn failure_of_one_type_does_not_lose_the_other_in_either_order() {
    // ADR-022, D5: addresses for either type mean Found even when the
    // other type fails, whichever arrives first.
    // SERVFAIL, NOTIMP and REFUSED.
    for rcode in [2u8, 4, 5] {
        let failed = move |name: &str, qtype: u16| {
            Reply::Raw(vec![(
                respond(&query_for(name, qtype), rcode, false, &[]),
                true,
            )])
        };
        // AAAA fails at once, A answers 50 ms later.
        let fail_first = Fake::start(move |name, qtype, _| match qtype {
            A => Reply::Later(Duration::from_millis(50), vec![usual(qtype)]),
            _ => failed(name, qtype),
        });
        let resolver = Resolver::fixed(config(&[&fail_first], Duration::from_secs(2), 2));
        assert_eq!(
            lookup(&resolver, "git.example", FAR).expect("failure first"),
            addrs(&["192.0.2.1"]),
            "rcode {rcode}"
        );
        assert_eq!(fail_first.count(), 2, "one try");
        // A fails at once, AAAA answers 50 ms later.
        let a_fails = Fake::start(move |name, qtype, _| match qtype {
            A => failed(name, qtype),
            _ => Reply::Later(Duration::from_millis(50), vec![usual(qtype)]),
        });
        let resolver = Resolver::fixed(config(&[&a_fails], Duration::from_secs(2), 2));
        assert_eq!(
            lookup(&resolver, "git.example", FAR).expect("a fails"),
            addrs(&["2001:db8::1"]),
            "rcode {rcode}"
        );
        // A answers at once, then AAAA fails.
        let answer_first = Fake::start(move |name, qtype, _| match qtype {
            A => Reply::Answer(vec![usual(qtype)]),
            _ => failed(name, qtype),
        });
        let resolver = Resolver::fixed(config(&[&answer_first], Duration::from_secs(2), 2));
        assert_eq!(
            lookup(&resolver, "git.example", FAR).expect("answer first"),
            addrs(&["192.0.2.1"]),
            "rcode {rcode}"
        );
    }
}

#[test]
fn failure_of_one_type_waits_for_the_other_until_the_try_ends() {
    // AAAA fails, A stays silent: the try waits for A until its end, then
    // the server counts as failed and the next one is asked.
    let first = Fake::start(|_, qtype, _| match qtype {
        A => Reply::Silence,
        _ => Reply::ServFail,
    });
    let second = Fake::start(both);
    let resolver = Resolver::fixed(config(&[&first, &second], Duration::from_millis(200), 1));
    let start = Instant::now();
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("second server"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    assert_eq!(second.count(), 2);
}

#[test]
fn use_vc_failure_of_one_type_still_asks_the_other() {
    let fake = Fake::start(|_, qtype, _| match qtype {
        A => Reply::ServFail,
        _ => Reply::Answer(vec![usual(qtype)]),
    });
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_secs(2), 1).with_use_vc(true));
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("aaaa over tcp"),
        addrs(&["2001:db8::1"])
    );
    let arrivals = fake.arrivals();
    assert_eq!(arrivals.len(), 2, "{arrivals:?}");
    assert!(arrivals.iter().all(|a| a.tcp), "{arrivals:?}");
}

#[test]
fn truncated_type_goes_to_tcp_beside_a_failed_one() {
    // A truncated over UDP, AAAA SERVFAIL: A is asked over TCP and found.
    let fake = Fake::start(|_, qtype, tcp| match (qtype, tcp) {
        (A, false) => Reply::Truncated,
        (A, true) => Reply::Answer(vec![usual(qtype)]),
        _ => Reply::ServFail,
    });
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_secs(2), 1));
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("a over tcp"),
        addrs(&["192.0.2.1"])
    );
    let tcp: Vec<u16> = fake
        .arrivals()
        .into_iter()
        .filter(|a| a.tcp)
        .map(|a| a.qtype)
        .collect();
    assert_eq!(tcp, [A]);
}

#[test]
fn only_unusable_name_servers_fail_closed_not_on_loopback() {
    // ADR-022, D3: resolv.conf lists name servers, none usable (a zone, a
    // word that is not an address): the lookup fails naming the first,
    // instead of asking 127.0.0.1:53, which nobody configured.
    let resolver = Resolver::fixed(ResolverConfig::parse(
        "nameserver fe80::1%eth0\nnameserver fe80::2%eth1\n",
    ));
    let err = lookup(&resolver, "git.example", FAR).expect_err("no usable server");
    assert_eq!(err.kind(), ErrorKind::Unsupported, "{err}");
    assert!(err.to_string().contains("fe80::1%eth0"), "{err}");
    assert!(!err.to_string().contains("127.0.0.1"), "{err}");
    // IP literals and hosts entries need no name server.
    let resolver = Resolver::fixed(
        ResolverConfig::parse("nameserver fe80::1%eth0\n").with_hosts("192.0.2.9 git\n".into()),
    );
    assert_eq!(
        lookup(&resolver, "git", FAR).expect("hosts"),
        addrs(&["192.0.2.9"])
    );
}

#[test]
fn truncated_answer_retries_over_tcp() {
    let fake = Fake::start(|_, qtype, tcp| match (qtype, tcp) {
        (A, false) => Reply::Truncated,
        (A, true) => Reply::Answer(vec![ip("192.0.2.1")]),
        (_, false) => Reply::Answer(vec![ip("2001:db8::1")]),
        (_, true) => Reply::ServFail,
    });
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_secs(5), 1));
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("lookup"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
    let tcp: Vec<u16> = fake
        .arrivals()
        .into_iter()
        .filter(|a| a.tcp)
        .map(|a| a.qtype)
        .collect();
    assert_eq!(tcp, [A]);
}

#[test]
fn stalled_tcp_fallback_stops_at_the_deadline() {
    let fake = Fake::start(|_, _, tcp| {
        if tcp {
            Reply::Silence
        } else {
            Reply::Truncated
        }
    });
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_secs(10), 2));
    let start = Instant::now();
    let err = lookup(&resolver, "git.example", Duration::from_millis(300)).expect_err("deadline");
    let elapsed = start.elapsed();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    assert!(fake.arrivals().iter().any(|a| a.tcp));
}

#[test]
fn use_vc_queries_over_tcp_only() {
    let fake = Fake::start(both);
    let resolver = Resolver::fixed(config(&[&fake], Duration::from_secs(5), 1).with_use_vc(true));
    assert_eq!(
        lookup(&resolver, "git.example", FAR).expect("lookup"),
        addrs(&["2001:db8::1", "192.0.2.1"])
    );
    let arrivals = fake.arrivals();
    assert_eq!(arrivals.len(), 2);
    assert!(arrivals.iter().all(|a| a.tcp), "{arrivals:?}");
}

/// Every `.rs` file under `dir`, recursively.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn resolver_module_spawns_nothing_and_uses_no_std_lookup() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/resolve");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(files.len() >= 5, "{files:?}");
    let forbidden = [
        "thread::spawn",
        "thread::Builder",
        "Command::new",
        "to_socket_addrs",
        "ToSocketAddrs",
    ];
    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("source");
        for (number, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for token in forbidden {
                if line.contains(token) {
                    hits.push(format!("{}:{}: {token}", file.display(), number + 1));
                }
            }
        }
    }
    assert!(hits.is_empty(), "{hits:#?}");
}

/// The names of the std functions that take `impl ToSocketAddrs`:
/// `TcpStream::connect`, `TcpListener::bind`, `UdpSocket::bind`,
/// `UdpSocket::connect` and `UdpSocket::send_to`. Given a name, each runs
/// `getaddrinfo`, without a deadline. The scan keys on the name, not on
/// the path in front of it: a method call, a turbofish, a qualified path
/// (`<TcpStream>::connect`) and an alias (`use ... as T`, `type T = ...`)
/// all end in the same identifier. `connect_timeout` takes a
/// `&SocketAddr` and is another identifier.
const STD_LOOKUP_NAMES: [&str; 3] = ["connect", "send_to", "bind"];

/// The turbofish that lets the compiler check a std lookup's argument:
/// `bind::<::std::net::SocketAddr>(local)` does not compile with a
/// string. The leading `::` matters: a file-local `type SocketAddr =
/// String` or `use ... as SocketAddr` cannot stand in for the type.
const SOCKET_ADDR_TURBOFISH: [&str; 9] =
    ["::", "<", "::", "std", "::", "net", "::", "SocketAddr", ">"];

/// The number of socket-address calls in each file under `src/` that has
/// any, exactly as the tree holds them: the resolver's bind and connect
/// (`SOCKET_ADDR_TURBOFISH`), and the test servers' binds to
/// `127.0.0.1:0`. A new call changes the count and fails.
const SOCKET_ADDR_CALLS: [(&str, usize); 2] =
    [("resolve/exchange.rs", 2), ("revocation/http.rs", 8)];

/// One token of a Rust source file. Comments are dropped and each
/// literal is one token, so a name or a `)` inside them is not seen.
#[derive(Debug)]
enum Tok {
    /// An identifier or a keyword; `raw` for `r#name`.
    Ident { name: String, raw: bool },
    /// A string literal, `"..."` or `r#"..."#`: its text between the
    /// quotes as written, escapes not decoded.
    Str(String),
    /// Any other literal (number, character, byte, byte or C string) or a
    /// lifetime.
    Lit,
    /// `::`, or any other punctuation character.
    Punct(String),
}

#[derive(Debug)]
struct Token {
    tok: Tok,
    /// The line of the token's first character, from 1.
    line: usize,
}

// Identifiers are ASCII here: a non-ASCII character outside comments and
// literals is a lex error. rustc's identifiers also take characters that
// are not alphanumeric (a combining mark glues `X` and `crate` into one
// name), and it skips some that `char::is_whitespace` does not (U+200E),
// so a lexer that guessed at them could split or join names differently.
fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_ascii_alphabetic()
}

fn is_ident_continue(c: char) -> bool {
    c == '_' || c.is_ascii_alphanumeric()
}

/// The lexer's position in a source file.
struct Lexer {
    chars: Vec<char>,
    at: usize,
    line: usize,
}

impl Lexer {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.at += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn word(&mut self) -> String {
        let mut word = String::new();
        while let Some(c) = self.peek(0).filter(|&c| is_ident_continue(c)) {
            word.push(c);
            self.at += 1;
        }
        word
    }

    /// The rest of a string literal with escapes, after its `"`.
    fn quoted(&mut self, start: usize) -> Result<String, String> {
        let mut text = String::new();
        loop {
            match self.bump() {
                Some('"') => return Ok(text),
                Some('\\') => {
                    text.push('\\');
                    text.extend(self.bump());
                }
                Some(c) => text.push(c),
                None => return Err(format!("{start}: unterminated string literal")),
            }
        }
    }

    /// The rest of a raw string literal with `hashes` `#`, after its `"`.
    fn raw_quoted(&mut self, hashes: usize, start: usize) -> Result<String, String> {
        let mut text = String::new();
        loop {
            match self.bump() {
                Some('"') if (0..hashes).all(|k| self.peek(k) == Some('#')) => {
                    self.at += hashes;
                    return Ok(text);
                }
                Some(c) => text.push(c),
                None => return Err(format!("{start}: unterminated raw string literal")),
            }
        }
    }

    /// The rest of a character literal, after its `'`.
    fn char_literal(&mut self, start: usize) -> Result<(), String> {
        if self.bump() == Some('\\') {
            self.bump();
        }
        loop {
            match self.bump() {
                Some('\'') => return Ok(()),
                Some('\n') | None => {
                    return Err(format!("{start}: unterminated character literal"));
                }
                Some(_) => {}
            }
        }
    }
}

/// The tokens of a Rust source file. An unterminated literal or block
/// comment, a non-ASCII character outside comments and literals, or a
/// file that starts with `#!` but not with `#![`, is an error, so the
/// scan fails closed instead of skipping the rest of the file. rustc
/// drops the first line of a file as a shebang when the first token
/// after `#!` (doc comments count, other comments do not) is not `[`,
/// so `#! /*` would hide the file behind a comment only the scan sees.
fn lex(text: &str) -> Result<Vec<Token>, String> {
    if text.starts_with("#!") && !text.starts_with("#![") {
        return Err("1: `#!` not followed by `[` (a shebang line to rustc)".to_string());
    }
    let mut lx = Lexer {
        chars: text.chars().collect(),
        at: 0,
        line: 1,
    };
    let mut out = Vec::new();
    while let Some(c) = lx.peek(0) {
        let line = lx.line;
        let tok = if !c.is_ascii() {
            return Err(format!(
                "{line}: non-ASCII character U+{:04X} outside a comment or literal",
                u32::from(c)
            ));
        } else if c.is_whitespace() {
            lx.bump();
            continue;
        } else if c == '/' && lx.peek(1) == Some('/') {
            while lx.peek(0).is_some_and(|c| c != '\n') {
                lx.bump();
            }
            continue;
        } else if c == '/' && lx.peek(1) == Some('*') {
            lx.at += 2;
            let mut depth = 1;
            while depth > 0 {
                match (lx.peek(0), lx.peek(1)) {
                    (Some('/'), Some('*')) => {
                        lx.at += 2;
                        depth += 1;
                    }
                    (Some('*'), Some('/')) => {
                        lx.at += 2;
                        depth -= 1;
                    }
                    (Some(_), _) => {
                        lx.bump();
                    }
                    (None, _) => return Err(format!("{line}: unterminated block comment")),
                }
            }
            continue;
        } else if c == '"' {
            lx.bump();
            Tok::Str(lx.quoted(line)?)
        } else if c == '\'' {
            if lx.peek(1) == Some('\\') || lx.peek(1).is_some() && lx.peek(2) == Some('\'') {
                lx.bump();
                lx.char_literal(line)?;
            } else if lx.peek(1).is_some_and(is_ident_start) {
                lx.bump();
                lx.word();
            } else {
                return Err(format!("{line}: unterminated character literal"));
            }
            Tok::Lit
        } else if c.is_ascii_digit() {
            lx.word();
            while lx.peek(0) == Some('.') && lx.peek(1).is_some_and(|c| c.is_ascii_digit()) {
                lx.at += 1;
                lx.word();
            }
            Tok::Lit
        } else if is_ident_start(c) {
            let word = lx.word();
            let hashes = (0..).take_while(|&k| lx.peek(k) == Some('#')).count();
            if matches!(word.as_str(), "b" | "c") && lx.peek(0) == Some('"') {
                lx.bump();
                lx.quoted(line)?;
                Tok::Lit
            } else if word == "b" && lx.peek(0) == Some('\'') {
                lx.bump();
                lx.char_literal(line)?;
                Tok::Lit
            } else if matches!(word.as_str(), "r" | "br" | "cr") && lx.peek(hashes) == Some('"') {
                lx.at += hashes + 1;
                let text = lx.raw_quoted(hashes, line)?;
                if word == "r" {
                    Tok::Str(text)
                } else {
                    Tok::Lit
                }
            } else if word == "r" && hashes == 1 && lx.peek(1).is_some_and(is_ident_start) {
                lx.at += 1;
                Tok::Ident {
                    name: lx.word(),
                    raw: true,
                }
            } else {
                Tok::Ident {
                    name: word,
                    raw: false,
                }
            }
        } else if c == ':' && lx.peek(1) == Some(':') {
            lx.at += 2;
            Tok::Punct("::".to_string())
        } else {
            lx.bump();
            Tok::Punct(c.to_string())
        };
        out.push(Token { tok, line });
    }
    Ok(out)
}

/// Tokens as text for a hit message, at most 12 of them.
fn tokens_text(toks: &[Token]) -> String {
    let mut parts: Vec<String> = toks
        .iter()
        .take(12)
        .map(|t| match &t.tok {
            Tok::Ident { name, raw: true } => format!("r#{name}"),
            Tok::Ident { name, raw: false } => name.clone(),
            Tok::Str(text) => format!("{text:?}"),
            Tok::Lit => "<literal>".to_string(),
            Tok::Punct(p) => p.clone(),
        })
        .collect();
    if toks.len() > 12 {
        parts.push("...".to_string());
    }
    parts.join(" ")
}

/// The std lookups in the source `text` of `file` (relative to `src/`):
/// the ones that may take a name, as `file:line: what`, and the count of
/// calls whose argument is a socket address. A hit is:
///
/// - `to_socket_addrs` or `ToSocketAddrs`, by any mention;
/// - code the scan cannot read: `macro_rules` (a macro body can build a
///   call from its arguments), `include` (another file, also through an
///   alias of the macro) and a `path = ...` attribute (a module file
///   anywhere);
/// - a name of `STD_LOOKUP_NAMES`, unless it is defined there (`fn`
///   before it) or is the crate's own `connect` (`crate::` before it;
///   `crate` cannot be shadowed), or it is called with one argument
///   token: right after the name, either `(` and a string literal
///   parsing as a socket address (std parses it before it would look
///   anything up), or `SOCKET_ADDR_TURBOFISH`, `(` and an identifier,
///   whose type the compiler then checks. A UFCS call holds the socket
///   in its argument too and never passes; any other turbofish or the
///   function as a value has no `(` after the name.
///
/// Source the lexer refuses (see `lex`) is one hit.
fn std_lookup_hits(file: &str, text: &str) -> (Vec<String>, usize) {
    let toks = match lex(text) {
        Ok(toks) => toks,
        Err(err) => return (vec![format!("{file}:{err}")], 0),
    };
    let ident = |at: usize| match toks.get(at).map(|t| &t.tok) {
        Some(Tok::Ident { name, raw }) => Some((name.as_str(), *raw)),
        _ => None,
    };
    let punct =
        |at: usize, p: &str| matches!(toks.get(at).map(|t| &t.tok), Some(Tok::Punct(q)) if q == p);
    let mut hits = Vec::new();
    let mut allowed = 0;
    for (i, token) in toks.iter().enumerate() {
        let Tok::Ident { name, .. } = &token.tok else {
            continue;
        };
        let at = format!("{file}:{}", token.line);
        let after = || tokens_text(&toks[i + 1..]);
        match name.as_str() {
            "to_socket_addrs" | "ToSocketAddrs" => hits.push(format!("{at}: {name}")),
            "macro_rules" | "include" => hits.push(format!("{at}: {name} {}", after())),
            "path"
                if punct(i + 1, "=")
                    && i.checked_sub(1)
                        .is_some_and(|b| punct(b, "[") || punct(b, ",") || punct(b, "(")) =>
            {
                hits.push(format!("{at}: {name} {}", after()));
            }
            name if STD_LOOKUP_NAMES.contains(&name) => {
                let definition = i.checked_sub(1).and_then(ident) == Some(("fn", false));
                let crate_own =
                    i >= 2 && punct(i - 1, "::") && ident(i - 2) == Some(("crate", false));
                if definition || crate_own {
                    continue;
                }
                let n = SOCKET_ADDR_TURBOFISH.len();
                let typed = SOCKET_ADDR_TURBOFISH.iter().enumerate().all(|(k, text)| {
                    punct(i + 1 + k, text) || ident(i + 1 + k) == Some((*text, false))
                }) && punct(i + 1 + n, "(")
                    && ident(i + 2 + n).is_some()
                    && punct(i + 3 + n, ")");
                if typed {
                    allowed += 1;
                    continue;
                }
                if !punct(i + 1, "(") {
                    hits.push(format!("{at}: {name} {}", after()));
                    continue;
                }
                let mut depth = 0usize;
                let close = (i + 1..toks.len()).find(|&j| {
                    if punct(j, "(") {
                        depth += 1;
                    } else if punct(j, ")") {
                        depth -= 1;
                    }
                    depth == 0
                });
                let Some(close) = close else {
                    hits.push(format!("{at}: {name} {}", after()));
                    continue;
                };
                let argument = &toks[i + 2..close];
                let socket_addr = match argument {
                    [
                        Token {
                            tok: Tok::Str(text),
                            ..
                        },
                    ] => text.parse::<SocketAddr>().is_ok(),
                    _ => false,
                };
                if socket_addr {
                    allowed += 1;
                } else {
                    hits.push(format!("{at}: {name}({})", tokens_text(argument)));
                }
            }
            _ => {}
        }
    }
    (hits, allowed)
}

/// The hits of `std_lookup_hits` in the source of `file` under `src/`,
/// and, once there are none, one more when its count of socket-address
/// calls differs from `SOCKET_ADDR_CALLS` (0 for a file not listed).
fn crate_file_hits(file: &str, text: &str) -> Vec<String> {
    let (mut hits, allowed) = std_lookup_hits(file, text);
    let expected = SOCKET_ADDR_CALLS
        .iter()
        .find(|(f, _)| *f == file)
        .map_or(0, |(_, n)| *n);
    if hits.is_empty() && allowed != expected {
        hits.push(format!(
            "{file}: {allowed} socket-address calls, SOCKET_ADDR_CALLS says {expected}"
        ));
    }
    hits
}

/// No call site of the crate resolves with std any more (ADR-022, D7):
/// `TlsDial`, `connect` and the CRL and OCSP fetches go through
/// `Resolver`, so no `getaddrinfo` runs outside a deadline. Neither
/// `ToSocketAddrs` nor a std function that takes it may appear, in any
/// form, except in the calls whose argument is a socket address that
/// `SOCKET_ADDR_CALLS` counts (`crate_file_hits`). The scan reads
/// tokens, so comments and string literals may name them.
#[test]
fn crate_has_no_std_lookup() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(files.len() >= 15, "{files:?}");
    let mut hits = Vec::new();
    let mut seen = Vec::new();
    for file in &files {
        let relative = file.strip_prefix(&root).expect("under src");
        let relative = relative.to_str().expect("UTF-8 path");
        let text = std::fs::read_to_string(file).expect("source");
        hits.extend(crate_file_hits(relative, &text));
        seen.push(relative.to_string());
    }
    assert!(hits.is_empty(), "{hits:#?}");
    // Every file the count pins is there, so its calls were counted.
    for (file, _) in SOCKET_ADDR_CALLS {
        assert!(seen.iter().any(|s| s == file), "{file} not under src");
    }
}

/// The scan's rule on the forms it must catch and the ones it must let
/// through. Each caught text is one hit and no allowed call.
#[test]
fn std_lookup_scan_rule() {
    let caught = [
        (
            "revocation/http.rs",
            "TcpStream::connect((url.host(), url.port()))",
        ),
        (
            "revocation/http.rs",
            "TcpStream::connect(format!(\"{host}:{port}\"))",
        ),
        ("dial.rs", "UdpSocket::bind(host)"),
        ("dial.rs", "socket.send_to(&query, (name, 53))"),
        ("dial.rs", "socket.connect(server)"),
        ("resolve/exchange.rs", "UdpSocket::bind(\"localhost:0\")"),
        // UFCS: the socket is the first argument.
        (
            "revocation/http.rs",
            "std::net::UdpSocket::connect(s, (url.host(), url.port()))",
        ),
        ("revocation/http.rs", "UdpSocket::send_to(&s, buf, host)"),
        ("resolve/exchange.rs", "UdpSocket::connect(&socket, server)"),
        ("dial.rs", "UdpSocket::connect(&s, server)"),
        // The function as a value.
        ("revocation/http.rs", ".map(TcpStream::connect)"),
        ("revocation/http.rs", "addrs.map(UdpSocket::bind)"),
        ("dial.rs", "let f = T::connect;"),
        // Turbofish, on the path and on the method, also spaced.
        ("revocation/http.rs", "TcpStream::connect::<&str>(host)"),
        ("dial.rs", "socket.connect::<&str>(host)"),
        ("dial.rs", "socket.send_to::<&str>(buf, host)"),
        ("dial.rs", "socket.connect :: < &str > (host)"),
        ("revocation/http.rs", "TcpStream::connect (host)"),
        // Qualified paths.
        ("dial.rs", "<TcpStream>::connect(host)"),
        ("dial.rs", "<std::net::TcpStream>::connect(host)"),
        // Aliases: the `use` and the `type` lines are clean, the call
        // is the hit.
        ("dial.rs", "use std::net::TcpStream as T; T::connect(host)"),
        ("dial.rs", "type T = TcpStream; T::connect(host)"),
        // Split over lines.
        ("dial.rs", "TcpStream\n::connect\n(host)"),
        ("dial.rs", "socket\n.connect(\nhost)"),
        // A raw identifier is the same name.
        ("dial.rs", "r#connect(host)"),
        // Arguments that are not one socket-address token.
        ("dial.rs", "TcpListener::bind(\"localhost:0\")"),
        ("dial.rs", "TcpListener::bind(\"127.0.0.1:0\".to_string())"),
        ("dial.rs", "UdpSocket::bind(local)"),
        // Only the absolute `SocketAddr` turbofish lets an identifier
        // through: the compiler checks its type.
        ("resolve/exchange.rs", "UdpSocket::bind(local)"),
        ("resolve/exchange.rs", "s.connect(server)"),
        ("resolve/exchange.rs", "s.connect::<SocketAddr>(server)"),
        (
            "resolve/exchange.rs",
            "s.connect::<std::net::SocketAddr>(server)",
        ),
        (
            "resolve/exchange.rs",
            "s.connect::<::std::net::SocketAddrV4>(server)",
        ),
        (
            "resolve/exchange.rs",
            "s.connect::<::std::net::SocketAddr>(server.0)",
        ),
        (
            "resolve/exchange.rs",
            "s.connect::<::std::net::SocketAddr>(\"localhost:53\")",
        ),
        // Only the crate path is the crate's own `connect`.
        ("dial.rs", "use crate::connect; connect(host)"),
        // The trait, by any mention.
        ("dial.rs", "use std::net::ToSocketAddrs;"),
        ("dial.rs", "let a = (host, 443).to_socket_addrs();"),
        // Code the scan cannot read: a macro body, an included file, a
        // module file named by `#[path]`.
        ("dial.rs", "macro_rules! m { () => {}; }"),
        ("dial.rs", "include!(\"x.rs\");"),
        ("dial.rs", "use std::include as inc; inc!(\"x.rs\");"),
        ("dial.rs", "#[path = \"../x.rs\"] mod x;"),
        ("dial.rs", "#[cfg_attr(unix, path = \"../x.rs\")] mod x;"),
    ];
    for (file, text) in caught {
        let (hits, allowed) = std_lookup_hits(file, text);
        assert_eq!((hits.len(), allowed), (1, 0), "{file}: {text}: {hits:?}");
    }
    let through = [
        (
            "resolve/exchange.rs",
            "let socket = UdpSocket::bind::<::std::net::SocketAddr>(local)",
            1,
        ),
        (
            "resolve/exchange.rs",
            ".and_then(|s| s.connect::<::std::net::SocketAddr>(server))",
            1,
        ),
        ("dial.rs", "s.send_to::<::std::net::SocketAddr>(addr)", 1),
        (
            "revocation/http.rs",
            "TcpListener::bind(\"127.0.0.1:0\")",
            1,
        ),
        ("dial.rs", "UdpSocket::bind(\"[::1]:443\")", 1),
        ("dial.rs", "TcpListener::bind(r#\"127.0.0.1:0\"#)", 1),
        ("dial.rs", "TcpStream::connect_timeout(&addr, left)", 0),
        ("lib.rs", "pub fn connect(host: &str) {}", 0),
        (
            "revocation/ocsp/live.rs",
            "crate::connect(host, 443, &plain, &options())",
            0,
        ),
        ("dial.rs", "reconnect(host); bind_all(host)", 0),
        ("dial.rs", "let path = \"../x.rs\";", 0),
        // Non-ASCII in comments and literals.
        (
            "dial.rs",
            "// conn\u{435}ct\n/* \u{200E} */ let s = \"\u{e9}\"; let c = '\u{e9}';",
            0,
        ),
    ];
    for (file, text, calls) in through {
        let (hits, allowed) = std_lookup_hits(file, text);
        assert!(hits.is_empty(), "{file}: {text}: {hits:?}");
        assert_eq!(allowed, calls, "{file}: {text}");
    }
}

/// The lexer drops comments and keeps each literal one token, so names
/// inside them are no hits and a `)` inside them ends no argument.
#[test]
fn lex_ignores_comments_and_literals() {
    let idents = |text: &str| -> Vec<String> {
        lex(text)
            .expect("lex")
            .into_iter()
            .filter_map(|t| match t.tok {
                Tok::Ident { name, .. } => Some(name),
                _ => None,
            })
            .collect()
    };
    assert_eq!(idents("// connect(host)\nlet a = 1;"), ["let", "a"]);
    assert_eq!(idents("/* a /* connect */ bind */ x"), ["x"]);
    assert_eq!(idents("/// send_to(host)\n//! bind\nx"), ["x"]);
    assert_eq!(idents("\"lookup file bind\" x"), ["x"]);
    assert_eq!(idents("\"a \\\" connect(\" x"), ["x"]);
    assert_eq!(idents("r#\"a ) \" connect\"# x"), ["x"]);
    assert_eq!(idents("r\"connect\" x"), ["x"]);
    assert_eq!(idents("b\"bind\" b'x' c\"connect\" br#\"bind\"# x"), ["x"]);
    assert_eq!(idents("'a' '\\'' '\\u{29}' ')' x"), ["x"]);
    assert_eq!(idents("1.0e5 0x1F_u8 t.0.1 x"), ["t", "x"]);
    assert_eq!(idents("fn f<'a>(x: &'a str) {}"), ["fn", "f", "x", "str"]);
    assert_eq!(idents("'outer: loop {}"), ["loop"]);
    assert_eq!(idents("r#connect r#fn"), ["connect", "fn"]);
    assert_eq!(idents("#![allow(x)]\ny"), ["allow", "x", "y"]);
    let toks = lex("r#fn fn").expect("lex");
    assert!(matches!(&toks[0].tok, Tok::Ident { raw: true, .. }));
    assert!(matches!(&toks[1].tok, Tok::Ident { raw: false, .. }));
    assert_eq!(lex("a\n/* b\n */\nc").expect("lex")[1].line, 4);
    // A `)` in a literal or a lifetime in an argument does not move the
    // argument's end: the bind after the call is still seen.
    for text in [
        "s.connect(f(')')); TcpListener::bind(\"127.0.0.1:0\")",
        "s.connect(\")\"); TcpListener::bind(\"127.0.0.1:0\")",
        "s.connect(g::<'a>(x)); TcpListener::bind(\"127.0.0.1:0\")",
        "s.connect(r#\")\"#); TcpListener::bind(\"127.0.0.1:0\")",
    ] {
        let (hits, allowed) = std_lookup_hits("dial.rs", text);
        assert_eq!((hits.len(), allowed), (1, 1), "{text}: {hits:?}");
    }
}

/// Input the lexer cannot end is an error, and the scan counts it as a
/// hit: nothing after it is read, so nothing after it may pass.
#[test]
fn lex_fails_closed_on_unterminated_input() {
    for text in [
        "\"abc",
        "\"abc\\\"",
        "/* x",
        "/* /* x */",
        "r#\"abc\"",
        "r#\"abc",
        "b\"abc",
        "'\\n",
        "'",
        // Non-ASCII outside comments and literals: a combining mark that
        // rustc reads as part of `X\u{301}crate`, a left-to-right mark
        // it reads as whitespace, a Cyrillic look-alike, a lifetime.
        "X\u{301}crate::connect(host)",
        "#[path\u{200E}= \"../x.rs\"] mod m;",
        "conn\u{435}ct(host)",
        "fn f<'\u{e9}>() {}",
        // A first line rustc drops as a shebang: anything but `#![`.
        "#! /*\nTcpStream::connect(host)\n// */",
        "#! /** */ [ /*\nTcpStream::connect(host)\n// */",
        "#!/usr/bin/env rustc\nx",
        "#! [allow(x)]",
    ] {
        assert!(lex(text).is_err(), "{text:?}");
        let (hits, allowed) = std_lookup_hits("dial.rs", text);
        assert_eq!((hits.len(), allowed), (1, 0), "{text:?}: {hits:?}");
    }
}

/// A mutant per form in a real source file: the resolver's exchange,
/// with one function or item appended, fails the scan with exactly one
/// more hit. The file as it is passes, with its two socket-address calls.
#[test]
fn std_lookup_scan_catches_each_form_in_real_sources() {
    let file = "resolve/exchange.rs";
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(file);
    let text = std::fs::read_to_string(path).expect("source");
    let hits = crate_file_hits(file, &text);
    assert!(hits.is_empty(), "{hits:#?}");
    let mutants = [
        // Method turbofish.
        "fn mutant(s: &UdpSocket, host: &str) -> io::Result<()> {\n    s.connect::<&str>(host)\n}",
        "fn mutant(s: &UdpSocket, host: &str) -> io::Result<usize> {\n    s.send_to::<&str>(&[], host)\n}",
        // Qualified path.
        "fn mutant(host: &str) -> io::Result<std::net::TcpStream> {\n    <std::net::TcpStream>::connect(host)\n}",
        // Aliases.
        "use std::net::TcpStream as T;\nfn mutant(host: &str) -> io::Result<T> {\n    T::connect(host)\n}",
        "type T = std::net::TcpStream;\nfn mutant(host: &str) -> io::Result<T> {\n    T::connect(host)\n}",
        // Macros.
        "macro_rules! dial {\n    ($($t:tt)*) => { $($t)* };\n}",
        "include!(\"../../mutant.rs\");",
        "#[path = \"../../mutant.rs\"]\nmod mutant;",
        // A combining mark that makes `X\u{301}crate` one name to rustc,
        // and a left-to-right mark it reads as whitespace.
        "use std::net::TcpStream as X\u{301}crate;\nfn mutant(host: &str) -> io::Result<X\u{301}crate> {\n    X\u{301}crate::connect(host)\n}",
        "#[rustfmt::skip]\n#[path\u{200E}= \"../../mutant.rs\"]\nmod mutant;",
        // A call with an identifier and no turbofish.
        "fn mutant(server: &str) -> io::Result<std::net::TcpStream> {\n    std::net::TcpStream::connect(server)\n}",
        // A typed call more than the count.
        "fn mutant(s: &UdpSocket, a: SocketAddr) -> io::Result<()> {\n    s.connect::<::std::net::SocketAddr>(a)\n}",
    ];
    for mutant in mutants {
        let hits = crate_file_hits(file, &format!("{text}\n{mutant}\n"));
        assert_eq!(hits.len(), 1, "{mutant}: {hits:#?}");
    }
    // A first line rustc drops as a shebang, which would hide the file
    // from the scan behind a block comment that its last line ends. The
    // hit is the shebang, not the count: a file without counted calls
    // would have no count to miss.
    for prefix in ["#! /*\n", "#! /** */ [ /*\n"] {
        let hits = crate_file_hits(file, &format!("{prefix}{text}\n// */\n"));
        assert_eq!(hits.len(), 1, "{prefix:?}: {hits:#?}");
        assert!(hits[0].contains("`#!`"), "{prefix:?}: {hits:#?}");
    }
    // The counted calls edited in place.Without its turbofish a call is
    // a hit. With it, rebinding `server` to a `String` in front of the
    // call does not compile (E0308), so a rebinding mutant that compiles
    // drops the turbofish too.
    let connect = "s.connect::<::std::net::SocketAddr>(server)";
    let bind = "let socket = UdpSocket::bind::<::std::net::SocketAddr>(local)";
    let rebind =
        "let server = std::env::var(\"BONELI_DNS_RELAY\").unwrap_or_else(|_| server.to_string());";
    for (from, to) in [
        (connect, "s.connect(server)".to_string()),
        (bind, "let socket = UdpSocket::bind(local)".to_string()),
        (connect, format!("{{ {rebind} s.connect(server) }}")),
    ] {
        assert!(text.contains(from), "{from}");
        let hits = crate_file_hits(file, &text.replacen(from, &to, 1));
        assert_eq!(hits.len(), 1, "{to}: {hits:#?}");
    }
}
