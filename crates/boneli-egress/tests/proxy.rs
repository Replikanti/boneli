//! The proxy over a real Unix socket: decisions and their answers, the
//! write-ahead order of the log, the connect order and budget, hostile
//! heads, the connection cap and the production limits (ADR-006, D3 to
//! D10).

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use boneli_egress::Settings;
use boneli_egress::log::{End, FailReason, Record, RejectedStatus};
use common::{
    Call, Connect, DEADLINE, FakeUpstream, MemSink, connect_head, join, kinds, next_origin, of,
    read_head, read_to_close, send, server_limits, spawn_proxy, spawn_proxy_nat64, status,
    test_settings,
};

const NPM: &str = "registry.npmjs.org:443";
const NPM_ADDR: &str = "104.16.0.34:443";

fn sock(s: &str) -> SocketAddr {
    s.parse().expect(s)
}

/// A fake that resolves the npm registry to one global address.
fn npm_upstream() -> (FakeUpstream, mpsc::Receiver<std::os::unix::net::UnixStream>) {
    let (fake, origins) = FakeUpstream::new();
    (fake.answer("registry.npmjs.org", &[NPM_ADDR]), origins)
}

/// The terminal record of connection `id`.
fn terminal(records: &[Record], id: u64) -> Record {
    let mut found: Vec<Record> = of(records, id)
        .into_iter()
        .filter(Record::is_terminal)
        .collect();
    assert_eq!(found.len(), 1, "one terminal record for {id}: {records:?}");
    found.remove(0)
}

fn failed(records: &[Record], id: u64) -> (FailReason, Option<SocketAddr>) {
    match terminal(records, id) {
        Record::Failed { reason, addr, .. } => (reason, addr),
        other => panic!("expected failed, got {other:?}"),
    }
}

fn close(records: &[Record], id: u64) -> (u64, u64, End) {
    match terminal(records, id) {
        Record::Close { up, down, end, .. } => (up, down, end),
        other => panic!("expected close, got {other:?}"),
    }
}

/// Sends `head`, reads the answer head and the rest until the close.
fn exchange(client: &mut std::os::unix::net::UnixStream, head: &[u8]) -> (String, Vec<u8>) {
    send(client, head);
    let answer = read_head(client);
    let rest = read_to_close(client);
    (answer, rest)
}

#[test]
fn allowed_host_tunnels_bytes_both_ways() {
    let (fake, origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    let mut client = proxy.client();
    send(&mut client, &connect_head(NPM));
    assert_eq!(read_head(&mut client), "HTTP/1.1 200 OK\r\n\r\n");
    let mut origin = next_origin(&origins);

    send(&mut client, b"hello upstream");
    let mut got = [0u8; 14];
    origin.read_exact(&mut got).expect("request at the origin");
    assert_eq!(&got, b"hello upstream");
    send(&mut origin, b"hello sandbox, longer");
    let mut got = [0u8; 21];
    client.read_exact(&mut got).expect("response at the client");
    assert_eq!(&got, b"hello sandbox, longer");

    client.shutdown(Shutdown::Write).expect("half-close");
    assert!(
        read_to_close(&mut origin).is_empty(),
        "EOF reaches the origin"
    );
    drop(origin);
    assert!(
        read_to_close(&mut client).is_empty(),
        "EOF reaches the client"
    );

    let records = proxy.sink.wait_terminal(1);
    assert_eq!(kinds(&records, 1), ["allowed", "open", "close"]);
    assert_eq!(close(&records, 1), (14, 21, End::Eof));
    match &of(&records, 1)[1] {
        Record::Open { addr, .. } => assert_eq!(*addr, sock(NPM_ADDR)),
        other => panic!("{other:?}"),
    }
    match &of(&records, 1)[0] {
        Record::Allowed { endpoint, .. } => {
            assert_eq!(
                (endpoint.host(), endpoint.port()),
                ("registry.npmjs.org", 443)
            )
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn bytes_sent_with_the_connect_head_reach_upstream_first() {
    let (fake, origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    let mut client = proxy.client();
    // A TLS ClientHello-like record in the same write as the head.
    let early = [0x16u8, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];
    let mut first = connect_head(NPM);
    first.extend_from_slice(&early);
    send(&mut client, &first);
    assert_eq!(read_head(&mut client), "HTTP/1.1 200 OK\r\n\r\n");
    send(&mut client, b"later");
    client.shutdown(Shutdown::Write).expect("half-close");

    let mut origin = next_origin(&origins);
    let got = read_to_close(&mut origin);
    let mut expected = early.to_vec();
    expected.extend_from_slice(b"later");
    assert_eq!(got, expected, "early bytes first, then the rest");
    drop(origin);
    assert!(read_to_close(&mut client).is_empty());

    let records = proxy.sink.wait_terminal(1);
    assert_eq!(close(&records, 1), (15, 0, End::Eof));
}

#[test]
fn refused_host_gets_403_and_is_never_resolved() {
    let (fake, _origins) = FakeUpstream::new();
    let fake = fake.answer("evil.example", &[NPM_ADDR]);
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    let mut client = proxy.client();
    let (answer, rest) = exchange(&mut client, &connect_head("evil.example:443"));
    assert_eq!(status(&answer), 403);
    assert!(answer.contains("Content-Length: 0\r\n"), "{answer}");
    assert!(answer.contains("Connection: close\r\n"), "{answer}");
    assert!(rest.is_empty());

    let records = proxy.sink.wait_terminal(1);
    assert_eq!(kinds(&records, 1), ["refused"]);
    match terminal(&records, 1) {
        Record::Refused { endpoint, .. } => {
            assert_eq!((endpoint.host(), endpoint.port()), ("evil.example", 443))
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        proxy.upstream.resolves(),
        0,
        "a refused name is never resolved"
    );
}

#[test]
fn decision_record_precedes_every_effect() {
    let (fake, origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    proxy.upstream.witness(proxy.sink.clone());
    let mut client = proxy.client();
    send(&mut client, &connect_head(NPM));
    assert_eq!(status(&read_head(&mut client)), 200);
    drop(next_origin(&origins));
    drop(client);
    proxy.sink.wait_terminal(1);

    let calls = proxy.upstream.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    match &calls[0] {
        Call::Resolve { log, .. } => {
            assert_eq!(log.len(), 1, "{log:?}");
            assert!(log[0].starts_with("allowed "), "{log:?}");
        }
        other => panic!("{other:?}"),
    }
    match &calls[1] {
        Call::Connect { log, .. } => {
            assert!(
                log.iter().all(|l| !l.starts_with("open ")),
                "no open before the connect: {log:?}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn forbidden_address_is_refused_before_any_connect() {
    let (fake, _origins) = FakeUpstream::new();
    let fake = fake.answer(
        "registry.npmjs.org",
        &["104.16.0.34:443", "169.254.169.254:443"],
    );
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    let mut client = proxy.client();
    let (answer, rest) = exchange(&mut client, &connect_head(NPM));
    assert_eq!(status(&answer), 403);
    assert!(rest.is_empty());

    let records = proxy.sink.wait_terminal(1);
    assert_eq!(kinds(&records, 1), ["allowed", "failed"]);
    assert_eq!(
        failed(&records, 1),
        (
            FailReason::ForbiddenAddress,
            Some(sock("169.254.169.254:443"))
        )
    );
    assert!(proxy.upstream.connect_calls().is_empty());
}

/// A network-specific NAT64 prefix in effect reaches the address check: an
/// address that embeds metadata space is refused, the same address without
/// the prefix would be global.
#[test]
fn nat64_prefixes_reach_the_address_check() {
    let synthesized = "[2a00:1:2::a9fe:a9fe]:443";
    for (prefixes, expected) in [(&["2a00:1:2::/96"][..], 403), (&[][..], 200)] {
        let (fake, origins) = FakeUpstream::new();
        let fake = fake.answer("registry.npmjs.org", &[synthesized]);
        let proxy = spawn_proxy_nat64(&[NPM], prefixes, fake, MemSink::new(), test_settings());
        let mut client = proxy.client();
        send(&mut client, &connect_head(NPM));
        assert_eq!(status(&read_head(&mut client)), expected, "{prefixes:?}");
        if expected == 200 {
            drop(next_origin(&origins));
        }
        drop(client);
        let records = proxy.sink.wait_terminal(1);
        if expected == 403 {
            assert_eq!(
                failed(&records, 1),
                (FailReason::ForbiddenAddress, Some(sock(synthesized)))
            );
        }
    }
}

#[test]
fn undici_host_without_port_is_allowed() {
    let (fake, origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    let mut client = proxy.client();
    send(
        &mut client,
        b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n",
    );
    assert_eq!(status(&read_head(&mut client)), 200);
    drop(next_origin(&origins));
    drop(client);
    let records = proxy.sink.wait_terminal(1);
    assert_eq!(kinds(&records, 1), ["allowed", "open", "close"]);
}

#[test]
fn target_is_canonicalized_before_matching() {
    let (fake, origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    let mut client = proxy.client();
    send(&mut client, &connect_head("REGISTRY.NPMJS.ORG:0443"));
    assert_eq!(status(&read_head(&mut client)), 200);
    drop(next_origin(&origins));
    drop(client);
    let records = proxy.sink.wait_terminal(1);
    let lines = proxy.sink.lines();
    assert!(
        lines[0].ends_with(" id=1 host=registry.npmjs.org port=443\n"),
        "{lines:?}"
    );
    assert_eq!(kinds(&records, 1), ["allowed", "open", "close"]);
    match &proxy.upstream.calls()[0] {
        Call::Resolve { host, port, .. } => {
            assert_eq!((host.as_str(), *port), ("registry.npmjs.org", 443))
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn hostile_heads_are_rejected_and_logged() {
    let heads: Vec<Vec<u8>> = vec![
        b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n".to_vec(),
        b"CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"GET http://registry.npmjs.org/ HTTP/1.1\r\nHost: registry.npmjs.org\r\n\r\n".to_vec(),
        b"connect registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n".to_vec(),
        connect_head("user@registry.npmjs.org:443"),
        connect_head("registry%2Enpmjs.org:443"),
        connect_head("registry.npmjs.org.:443"),
        connect_head("127.1:443"),
        // Cyrillic U+0435 in place of the Latin `e`.
        connect_head("r\u{435}gistry.npmjs.org:443"),
        // A zero-width space inside the name.
        connect_head("registry\u{200b}.npmjs.org:443"),
        b"CONNECT registry.npmjs.org:443 HTTP/1.1\nHost: registry.npmjs.org:443\n\n".to_vec(),
    ];
    let (fake, _origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    for (k, head) in heads.iter().enumerate() {
        let mut client = proxy.client();
        let (answer, _) = exchange(&mut client, head);
        assert_eq!(status(&answer), 400, "head {k}");
        let records = proxy.sink.wait_terminal(k + 1);
        let id = (k + 1) as u64;
        assert_eq!(kinds(&records, id), ["rejected"], "head {k}");
        assert!(matches!(
            terminal(&records, id),
            Record::Rejected {
                status: RejectedStatus::BadRequest,
                ..
            }
        ));
    }
    assert_eq!(proxy.upstream.resolves(), 0);
}

#[test]
fn non_connect_method_gets_405_with_allow() {
    let (fake, _origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    let mut client = proxy.client();
    let (answer, rest) = exchange(&mut client, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(status(&answer), 405);
    assert!(answer.contains("\r\nAllow: CONNECT\r\n"), "{answer}");
    assert!(answer.contains("\r\nConnection: close\r\n"), "{answer}");
    assert!(answer.contains("\r\nContent-Length: 0\r\n"), "{answer}");
    assert!(rest.is_empty(), "the connection closes after the answer");
    let records = proxy.sink.wait_terminal(1);
    assert_eq!(kinds(&records, 1), ["method"]);
    assert_eq!(proxy.upstream.resolves(), 0);
}

#[test]
fn pipelined_request_after_refusal_is_never_served() {
    let (fake, _origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    let mut both = connect_head("evil.example:443");
    both.extend_from_slice(&connect_head(NPM));
    let mut client = proxy.client();
    let (answer, rest) = exchange(&mut client, &both);
    assert_eq!(status(&answer), 403);
    assert!(rest.is_empty(), "no second answer: {rest:?}");
    proxy.sink.wait_terminal(1);
    thread::sleep(Duration::from_millis(200));
    let records = proxy.sink.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(kinds(&records, 1), ["refused"]);
    assert_eq!(proxy.upstream.resolves(), 0);
}

#[test]
fn resolve_and_connect_failures_are_502() {
    let (fake, _origins) = FakeUpstream::new();
    let fake = fake
        .answer_error("a.example", ErrorKind::NotFound)
        .answer("b.example", &[])
        .answer("c.example", &["104.16.0.1:443", "104.16.0.2:443"])
        .connect_as("104.16.0.1:443", Connect::Refuse)
        .connect_as("104.16.0.2:443", Connect::Refuse);
    let allow = ["a.example:443", "b.example:443", "c.example:443"];
    let proxy = spawn_proxy(&allow, fake, MemSink::new(), test_settings());
    for (k, target) in allow.iter().enumerate() {
        let mut client = proxy.client();
        let (answer, rest) = exchange(&mut client, &connect_head(target));
        assert_eq!(status(&answer), 502, "{target}");
        assert!(rest.is_empty());
        proxy.sink.wait_terminal(k + 1);
    }
    let records = proxy.sink.records();
    assert_eq!(failed(&records, 1), (FailReason::Resolve, None));
    assert_eq!(failed(&records, 2), (FailReason::Resolve, None));
    assert_eq!(
        failed(&records, 3),
        (FailReason::Connect, Some(sock("104.16.0.2:443")))
    );
    assert_eq!(proxy.upstream.connect_calls().len(), 2);
}

#[test]
fn connect_budget_exhaustion_is_504() {
    let addrs = [
        "104.16.0.1:443",
        "104.16.0.2:443",
        "104.16.0.3:443",
        "104.16.0.4:443",
    ];
    let (fake, _origins) = FakeUpstream::new();
    let mut fake = fake.answer("d.example", &addrs);
    for addr in addrs {
        fake = fake.connect_as(addr, Connect::Blackhole);
    }
    let settings = Settings::new(
        server_limits(4, DEADLINE),
        Duration::from_millis(200),
        Duration::from_millis(500),
        DEADLINE,
        16 * 1024,
    )
    .expect("settings");
    let proxy = spawn_proxy(&["d.example:443"], fake, MemSink::new(), settings);
    let mut client = proxy.client();
    let (answer, _) = exchange(&mut client, &connect_head("d.example:443"));
    assert_eq!(status(&answer), 504);
    let records = proxy.sink.wait_terminal(1);
    assert_eq!(
        failed(&records, 1),
        (FailReason::ConnectTimeout, Some(sock(addrs[2])))
    );
    let timeouts: Vec<Duration> = proxy
        .upstream
        .connect_calls()
        .into_iter()
        .map(|(_, t)| t)
        .collect();
    // The budget is wall time: the third attempt gets what is left of the
    // 500 ms after two full 200 ms attempts, at most 100 ms, and then no
    // fourth attempt is made. The slack below 100 ms is the test's
    // tolerance for a loaded machine.
    let ms = Duration::from_millis;
    assert_eq!(timeouts.len(), 3, "{timeouts:?}");
    assert_eq!(timeouts[..2], [ms(200), ms(200)]);
    assert!(
        timeouts[2] > Duration::ZERO && timeouts[2] <= ms(100),
        "{timeouts:?}"
    );
}

#[test]
fn blackholed_family_falls_back_to_the_other() {
    let (fake, origins) = FakeUpstream::new();
    let fake = fake
        .answer(
            "registry.npmjs.org",
            &[
                "[2606:4700::1]:443",
                "[2606:4700::2]:443",
                "104.16.0.1:443",
                "104.16.0.2:443",
            ],
        )
        .connect_as("[2606:4700::1]:443", Connect::TimedOutNow)
        .connect_as("[2606:4700::2]:443", Connect::TimedOutNow);
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), test_settings());
    let mut client = proxy.client();
    send(&mut client, &connect_head(NPM));
    assert_eq!(status(&read_head(&mut client)), 200);
    drop(next_origin(&origins));
    drop(client);
    let records = proxy.sink.wait_terminal(1);
    let tried: Vec<SocketAddr> = proxy
        .upstream
        .connect_calls()
        .into_iter()
        .map(|(a, _)| a)
        .collect();
    assert_eq!(tried, [sock("[2606:4700::1]:443"), sock("104.16.0.1:443")]);
    match &of(&records, 1)[1] {
        Record::Open { addr, .. } => assert_eq!(*addr, sock("104.16.0.1:443")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn no_request_aborted_and_timeout_are_logged() {
    let (fake, _origins) = npm_upstream();
    let settings = Settings::new(
        server_limits(4, Duration::from_millis(300)),
        Duration::from_secs(1),
        Duration::from_secs(3),
        DEADLINE,
        16 * 1024,
    )
    .expect("settings");
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), settings);

    drop(proxy.client());
    let records = proxy.sink.wait_terminal(1);
    assert!(matches!(terminal(&records, 1), Record::NoRequest { .. }));

    let mut partial = proxy.client();
    send(&mut partial, b"CONNECT regis");
    drop(partial);
    let records = proxy.sink.wait_terminal(2);
    assert!(matches!(terminal(&records, 2), Record::Aborted { .. }));

    let mut silent = proxy.client();
    send(&mut silent, b"CONNECT regis");
    let answer = read_head(&mut silent);
    assert_eq!(status(&answer), 408);
    let records = proxy.sink.wait_terminal(3);
    assert!(matches!(
        terminal(&records, 3),
        Record::Rejected {
            status: RejectedStatus::RequestTimeout,
            ..
        }
    ));
    assert_eq!(proxy.upstream.resolves(), 0);
}

#[test]
fn every_connection_has_exactly_one_terminal_record() {
    let (fake, origins) = FakeUpstream::new();
    let fake = fake
        .answer("registry.npmjs.org", &[NPM_ADDR])
        .answer("pypi.org", &["10.0.0.1:443"]);
    let proxy = spawn_proxy(
        &[NPM, "pypi.org:443"],
        fake,
        MemSink::new(),
        test_settings(),
    );
    // Echo origins: read the request to its end, send it back, close.
    let echo = thread::spawn(move || {
        // Three of the sixteen clients open a tunnel.
        for _ in 0..3 {
            let mut origin = next_origin(&origins);
            thread::spawn(move || {
                let got = read_to_close(&mut origin);
                let _ = origin.write_all(&got);
            });
        }
    });

    let clients: Vec<_> = (0..16)
        .map(|k| {
            let path = proxy.socket.0.clone();
            thread::spawn(move || {
                let mut client = std::os::unix::net::UnixStream::connect(&path).expect("connect");
                client.set_read_timeout(Some(DEADLINE)).expect("timeout");
                match k % 6 {
                    0 => {
                        send(&mut client, &connect_head(NPM));
                        assert_eq!(status(&read_head(&mut client)), 200);
                        send(&mut client, b"ping");
                        client.shutdown(Shutdown::Write).expect("half-close");
                        assert_eq!(read_to_close(&mut client), b"ping");
                    }
                    1 => {
                        let (answer, _) = exchange(&mut client, &connect_head("evil.example:443"));
                        assert_eq!(status(&answer), 403);
                    }
                    2 => {
                        let (answer, _) =
                            exchange(&mut client, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
                        assert_eq!(status(&answer), 405);
                    }
                    3 => {
                        let (answer, _) = exchange(&mut client, &connect_head("127.1:443"));
                        assert_eq!(status(&answer), 400);
                    }
                    4 => drop(client),
                    _ => {
                        let (answer, _) = exchange(&mut client, &connect_head("pypi.org:443"));
                        assert_eq!(status(&answer), 403);
                    }
                }
            })
        })
        .collect();
    for client in clients {
        join(client);
    }
    let records = proxy.sink.wait_terminal(16);
    let ids: std::collections::BTreeSet<u64> = records.iter().filter_map(Record::id).collect();
    assert_eq!(ids, (1..=16).collect(), "ids 1 to 16");
    for id in ids {
        let mine = of(&records, id);
        let terminal: Vec<_> = mine.iter().filter(|r| r.is_terminal()).collect();
        assert_eq!(terminal.len(), 1, "{mine:?}");
        assert!(mine.last().is_some_and(Record::is_terminal), "{mine:?}");
        let k: Vec<&str> = mine.iter().map(Record::kind).collect();
        match k.as_slice() {
            ["allowed", "open", "close"]
            | ["allowed", "failed"]
            | ["refused"]
            | ["method"]
            | ["rejected"]
            | ["no-request"] => {}
            other => panic!("unexpected sequence {other:?}"),
        }
    }
    let count = |kind: &str| records.iter().filter(|r| r.kind() == kind).count();
    assert_eq!(count("close"), 3);
    assert_eq!(count("failed"), 2);
    assert_eq!(count("refused"), 3);
    assert_eq!(count("method"), 3);
    assert_eq!(count("rejected"), 3);
    assert_eq!(count("no-request"), 2);
    drop(proxy);
    join(echo);
}

#[test]
fn log_failure_stops_before_any_effect() {
    // The `allowed` record fails: no resolution, no connect, no answer.
    let (fake, _origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::failing_at(1), test_settings());
    let mut client = proxy.client();
    send(&mut client, &connect_head(NPM));
    assert!(read_to_close(&mut client).is_empty(), "no answer");
    assert_eq!(proxy.upstream.calls().len(), 0);
    assert_eq!(proxy.log_failures.load(Ordering::SeqCst), 1);

    // The `open` record fails: the upstream is dropped and no 200 is sent.
    let (fake, origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::failing_at(2), test_settings());
    let mut client = proxy.client();
    send(&mut client, &connect_head(NPM));
    assert!(read_to_close(&mut client).is_empty(), "no 200");
    let mut origin = next_origin(&origins);
    assert!(
        read_to_close(&mut origin).is_empty(),
        "the upstream is dropped"
    );
    assert_eq!(proxy.log_failures.load(Ordering::SeqCst), 1);
    assert_eq!(proxy.sink.lines().len(), 1, "only `allowed` was kept");

    // A refusal whose record fails gets no answer either.
    let (fake, _origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::failing_at(1), test_settings());
    let mut client = proxy.client();
    send(&mut client, &connect_head("evil.example:443"));
    assert!(read_to_close(&mut client).is_empty(), "no 403");
    assert_eq!(proxy.log_failures.load(Ordering::SeqCst), 1);
}

#[test]
fn open_always_gets_a_close() {
    let (gate, gate_rx) = mpsc::channel();
    let (fake, origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake.gated(gate_rx), MemSink::new(), test_settings());
    let mut client = proxy.client();
    send(&mut client, &connect_head(NPM));
    // Wait until the egress is inside the connect, then let the client go.
    let start = std::time::Instant::now();
    while proxy.upstream.connect_calls().is_empty() {
        assert!(start.elapsed() < DEADLINE, "no connect");
        thread::sleep(Duration::from_millis(5));
    }
    drop(client);
    gate.send(()).expect("gate");
    let mut origin = next_origin(&origins);
    let records = proxy.sink.wait_terminal(1);
    assert_eq!(kinds(&records, 1), ["allowed", "open", "close"]);
    assert_eq!(close(&records, 1), (0, 0, End::Error));
    assert!(
        read_to_close(&mut origin).is_empty(),
        "the upstream is closed"
    );
}

#[test]
fn two_servers_keep_their_own_allowlists() {
    let make = |allow: &str| {
        let (fake, origins) = FakeUpstream::new();
        let fake = fake
            .answer("a.example", &["104.16.0.1:443"])
            .answer("b.example", &["104.16.0.2:443"]);
        (
            spawn_proxy(&[allow], fake, MemSink::new(), test_settings()),
            origins,
        )
    };
    let (a, a_origins) = make("a.example:443");
    let (b, _b_origins) = make("b.example:443");
    let mut client = a.client();
    assert_eq!(
        status(&exchange(&mut client, &connect_head("b.example:443")).0),
        403
    );
    let mut client = b.client();
    assert_eq!(
        status(&exchange(&mut client, &connect_head("a.example:443")).0),
        403
    );
    let mut client = a.client();
    send(&mut client, &connect_head("a.example:443"));
    assert_eq!(status(&read_head(&mut client)), 200);
    drop(next_origin(&a_origins));
    assert_eq!(b.upstream.resolves(), 0);
}

#[test]
fn connection_cap_holds_the_second_client() {
    let (fake, origins) = npm_upstream();
    let settings = Settings::new(
        server_limits(1, DEADLINE),
        Duration::from_secs(1),
        Duration::from_secs(3),
        DEADLINE,
        16 * 1024,
    )
    .expect("settings");
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), settings);
    let mut first = proxy.client();
    send(&mut first, &connect_head(NPM));
    assert_eq!(status(&read_head(&mut first)), 200);
    let origin = next_origin(&origins);

    let mut second = proxy.client();
    send(&mut second, &connect_head(NPM));
    second
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");
    let mut byte = [0u8; 1];
    let err = second.read(&mut byte).expect_err("held in the backlog");
    assert!(
        matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        "{err:?}"
    );

    drop(first);
    drop(origin);
    second.set_read_timeout(Some(DEADLINE)).expect("timeout");
    assert_eq!(status(&read_head(&mut second)), 200);
    drop(next_origin(&origins));
}

/// A head of `len` bytes: a CONNECT to the registry with one padding
/// field.
fn head_of_len(len: usize) -> Vec<u8> {
    let base = format!("CONNECT {NPM} HTTP/1.1\r\nHost: {NPM}\r\nX-Pad: \r\n\r\n");
    let pad = "p".repeat(len - base.len());
    format!("CONNECT {NPM} HTTP/1.1\r\nHost: {NPM}\r\nX-Pad: {pad}\r\n\r\n").into_bytes()
}

/// A head with `fields` header fields, `Host` included.
fn head_with_fields(fields: usize) -> Vec<u8> {
    let mut head = format!("CONNECT {NPM} HTTP/1.1\r\nHost: {NPM}\r\n");
    for k in 1..fields {
        head.push_str(&format!("X-F{k}: v\r\n"));
    }
    head.push_str("\r\n");
    head.into_bytes()
}

#[test]
fn production_head_limits_are_wired() {
    let (fake, origins) = npm_upstream();
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), Settings::production());
    let cases: [(Vec<u8>, u16); 4] = [
        (head_of_len(8192), 200),
        (head_of_len(8193), 431),
        (head_with_fields(32), 200),
        (head_with_fields(33), 431),
    ];
    assert_eq!(cases[0].0.len(), 8192);
    assert_eq!(cases[1].0.len(), 8193);
    for (k, (head, expected)) in cases.iter().enumerate() {
        let mut client = proxy.client();
        send(&mut client, head);
        assert_eq!(status(&read_head(&mut client)), *expected, "case {k}");
        if *expected == 200 {
            drop(next_origin(&origins));
        }
        drop(client);
        let records = proxy.sink.wait_terminal(k + 1);
        if *expected == 431 {
            assert!(matches!(
                terminal(&records, (k + 1) as u64),
                Record::Rejected {
                    status: RejectedStatus::HeaderFieldsTooLarge,
                    ..
                }
            ));
        }
    }
}
