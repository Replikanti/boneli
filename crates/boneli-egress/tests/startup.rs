//! Startup: NAT64 discovery through `ipv4only.arpa` merged with the
//! prefixes the runner passes, the `start` record, and the exits before
//! the socket accepts (ADR-006, D1 and D4).

mod common;

use std::collections::BTreeSet;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;

use boneli_egress::address::Nat64Prefix;
use boneli_egress::log::Record;
use boneli_egress::{Allowlist, Config, DISCOVERY_NAME, LaunchError, LogSink, Upstream, launch};
use boneli_memory::StepClock;
use common::{
    Call, DEADLINE, FakeUpstream, MemSink, SocketFile, connect_head, join, read_head,
    read_to_close, send, socket_path, status, test_settings,
};

const NPM: &str = "registry.npmjs.org:443";
const UNIX_MS: u64 = 1_763_000_000_000;

struct Launched {
    socket: SocketFile,
    sink: Arc<MemSink>,
    upstream: Arc<FakeUpstream>,
    handle: thread::JoinHandle<LaunchError>,
}

/// Binds a fresh socket and runs `launch` in a thread.
fn start(fake: FakeUpstream, sink: MemSink, passed: &[&str]) -> Launched {
    let socket = socket_path();
    let listener = UnixListener::bind(&socket.0).expect("bind");
    start_on(socket, listener, fake, sink, passed)
}

fn start_on(
    socket: SocketFile,
    listener: UnixListener,
    fake: FakeUpstream,
    sink: MemSink,
    passed: &[&str],
) -> Launched {
    let sink = Arc::new(sink);
    let upstream = Arc::new(fake);
    let config = Config {
        allowlist: Allowlist::parse(&[NPM]).expect("list"),
        nat64: passed
            .iter()
            .map(|p| Nat64Prefix::parse(p).expect("prefix"))
            .collect(),
        upstream: Arc::clone(&upstream) as Arc<dyn Upstream>,
        sink: Arc::clone(&sink) as Arc<dyn LogSink>,
        clock: Box::new(StepClock::new(7, 1)),
        settings: test_settings(),
        on_log_failure: Box::new(|| {}),
    };
    let handle = thread::spawn(move || launch(listener, config, || UNIX_MS));
    Launched {
        socket,
        sink,
        upstream,
        handle,
    }
}

fn prefixes(list: &[&str]) -> BTreeSet<Nat64Prefix> {
    list.iter()
        .map(|p| Nat64Prefix::parse(p).expect("prefix"))
        .collect()
}

/// Waits for the `start` record and returns its NAT64 prefixes.
fn start_nat64(launched: &Launched) -> BTreeSet<Nat64Prefix> {
    let records = launched
        .sink
        .wait_for("the start record", |records| !records.is_empty());
    match &records[0] {
        Record::Start {
            t,
            unix_ms,
            nat64,
            allow,
        } => {
            assert_eq!((*t, *unix_ms), (7, UNIX_MS));
            assert_eq!(allow, &Allowlist::parse(&[NPM]).expect("list"));
            nat64.clone()
        }
        other => panic!("the first record is start: {other:?}"),
    }
}

fn a_only() -> FakeUpstream {
    let (fake, _origins) = FakeUpstream::new();
    fake.answer(DISCOVERY_NAME, &["192.0.0.170:0", "192.0.0.171:0"])
        .answer("registry.npmjs.org", &["104.16.0.34:443"])
}

#[test]
fn a_only_discovery_starts_with_no_prefix() {
    let launched = start(a_only(), MemSink::new(), &[]);
    assert!(start_nat64(&launched).is_empty());
    assert!(launched.sink.lines()[0].ends_with(" nat64=-\n"));
    match &launched.upstream.calls()[0] {
        Call::Resolve { host, .. } => assert_eq!(host, "ipv4only.arpa"),
        other => panic!("{other:?}"),
    }
    // The egress accepts after the start record.
    let mut client = UnixStream::connect(&launched.socket.0).expect("connect");
    client.set_read_timeout(Some(DEADLINE)).expect("timeout");
    send(&mut client, &connect_head("evil.example:443"));
    assert_eq!(status(&read_head(&mut client)), 403);
}

#[test]
fn discovery_without_an_answer_exits_1_before_accepting() {
    let (empty, _o) = FakeUpstream::new();
    let empty = empty.answer(DISCOVERY_NAME, &[]);
    let (error, _o) = FakeUpstream::new();
    let error = error.answer_error(DISCOVERY_NAME, std::io::ErrorKind::NotFound);
    for fake in [empty, error] {
        let socket = socket_path();
        let listener = UnixListener::bind(&socket.0).expect("bind");
        // A client already waiting in the backlog is never served.
        let mut client = UnixStream::connect(&socket.0).expect("connect");
        client.set_read_timeout(Some(DEADLINE)).expect("timeout");
        send(&mut client, &connect_head(NPM));
        let launched = start_on(socket, listener, fake, MemSink::new(), &[]);
        let error = join(launched.handle);
        assert_eq!(error.exit_code(), 1, "{error}");
        assert!(launched.sink.lines().is_empty(), "no start record");
        assert!(read_to_close(&mut client).is_empty(), "never answered");
    }
}

#[test]
fn passed_prefix_reaches_the_start_record_when_discovery_hides_it() {
    let launched = start(a_only(), MemSink::new(), &["2a00:1:2::/96"]);
    assert_eq!(start_nat64(&launched), prefixes(&["2a00:1:2::/96"]));
}

#[test]
fn discovered_and_passed_prefixes_merge() {
    let (fake, _origins) = FakeUpstream::new();
    // 192.0.0.170 is c000:00aa at bits 96 to 127 of a /96.
    let fake = fake.answer(DISCOVERY_NAME, &["192.0.0.170:0", "[2a00:aa::c000:aa]:0"]);
    let launched = start(fake, MemSink::new(), &["2a00:1:2::/96"]);
    assert_eq!(
        start_nat64(&launched),
        prefixes(&["2a00:1:2::/96", "2a00:aa::/96"])
    );
}

#[test]
fn unwritable_start_record_exits_3() {
    let launched = start(a_only(), MemSink::failing_at(1), &[]);
    let error = join(launched.handle);
    assert_eq!(error.exit_code(), 3, "{error}");
}
