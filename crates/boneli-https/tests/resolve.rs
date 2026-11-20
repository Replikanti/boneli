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

/// The std calls that take `impl ToSocketAddrs`: given a name, each runs
/// `getaddrinfo`, without a deadline. `TcpStream::connect_timeout` takes a
/// `&SocketAddr` and is not one of them.
const STD_LOOKUP_CALLS: [&str; 5] = [
    "TcpStream::connect(",
    "TcpListener::bind(",
    "UdpSocket::bind(",
    ".connect(",
    ".send_to(",
];

/// Call sites of `STD_LOOKUP_CALLS` whose argument is a `SocketAddr`
/// variable: the file under `src/` and the argument. The resolver's UDP
/// socket binds the unspecified address of the server's family and
/// connects to the server.
const SOCKET_ADDR_ARGS: [(&str, &str); 2] = [
    ("resolve/exchange.rs", "local"),
    ("resolve/exchange.rs", "server"),
];

/// The argument text of a call whose `(` ends `rest`'s prefix: up to the
/// matching `)` on the line, or the rest of the line.
fn call_argument(rest: &str) -> &str {
    let mut depth = 0usize;
    for (at, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return &rest[..at],
            ')' => depth -= 1,
            _ => {}
        }
    }
    rest
}

/// Whether a `STD_LOOKUP_CALLS` argument cannot be a name: a string
/// literal that parses as a socket address (std parses it before it would
/// look anything up), or a `SocketAddr` variable of `SOCKET_ADDR_ARGS`.
fn is_socket_addr(file: &str, argument: &str) -> bool {
    let argument = argument.trim();
    let literal = argument
        .strip_prefix('"')
        .and_then(|a| a.strip_suffix('"'))
        .is_some_and(|a| a.parse::<SocketAddr>().is_ok());
    literal || SOCKET_ADDR_ARGS.contains(&(file, argument))
}

/// No call site of the crate resolves with std any more (ADR-022, D7):
/// `TlsDial`, `connect` and the CRL and OCSP fetches go through
/// `Resolver`, so no `getaddrinfo` runs outside a deadline. Neither
/// `ToSocketAddrs` nor a std call that takes it may appear, unless its
/// argument is a socket address. Comment lines may name them.
#[test]
fn crate_has_no_std_lookup() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(files.len() >= 15, "{files:?}");
    let mut hits = Vec::new();
    let mut allowed = 0;
    for file in &files {
        let relative = file.strip_prefix(&root).expect("under src");
        let relative = relative.to_str().expect("UTF-8 path");
        let text = std::fs::read_to_string(file).expect("source");
        for (number, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            let at = format!("{relative}:{}", number + 1);
            for token in ["to_socket_addrs", "ToSocketAddrs"] {
                if line.contains(token) {
                    hits.push(format!("{at}: {token}"));
                }
            }
            for call in STD_LOOKUP_CALLS {
                for (start, _) in line.match_indices(call) {
                    let argument = call_argument(&line[start + call.len()..]);
                    if is_socket_addr(relative, argument) {
                        allowed += 1;
                    } else {
                        hits.push(format!("{at}: {call}{argument})"));
                    }
                }
            }
        }
    }
    assert!(hits.is_empty(), "{hits:#?}");
    // The scan sees the calls that are there: the resolver's bind and
    // connect, and the test servers' binds to 127.0.0.1:0.
    assert!(allowed >= 3, "{allowed} socket-address calls");
}

/// The scan's rule on the forms it must catch and the ones it must let
/// through.
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
    ];
    for (file, line) in caught {
        let call = STD_LOOKUP_CALLS
            .into_iter()
            .find(|c| line.contains(c))
            .expect("a call");
        let start = line.find(call).expect("call") + call.len();
        assert!(
            !is_socket_addr(file, call_argument(&line[start..])),
            "{file}: {line}"
        );
    }
    for (file, argument) in [
        ("resolve/exchange.rs", "local"),
        ("resolve/exchange.rs", " server"),
        ("revocation/http.rs", "\"127.0.0.1:0\""),
        ("dial.rs", "\"[::1]:443\""),
    ] {
        assert!(is_socket_addr(file, argument), "{file}: {argument}");
    }
    assert_eq!(call_argument("(a, b)).expect(\"x\")"), "(a, b)");
}
