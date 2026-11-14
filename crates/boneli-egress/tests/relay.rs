//! The relay through the proxy: half-close in both directions, a full
//! close after the request, the shared idle timeout (a peer that stops
//! reading included), and traffic in one direction keeping a tunnel open
//! (ADR-006, D7).

mod common;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::{Duration, Instant};

use boneli_egress::log::{End, Record};
use boneli_egress::{RelayStream, Settings};
use common::{
    DEADLINE, FakeUpstream, MemSink, Proxy, connect_head, join, kinds, next_origin, read_head,
    read_to_close, send, server_limits, spawn_proxy, status,
};

const NPM: &str = "registry.npmjs.org:443";

fn settings(idle: Duration) -> Settings {
    Settings::new(
        server_limits(8, DEADLINE),
        Duration::from_secs(1),
        Duration::from_secs(3),
        idle,
        16 * 1024,
    )
    .expect("settings")
}

/// A proxy with an open tunnel: the client after its `200`, and the origin.
fn tunnel(idle: Duration) -> (Proxy, UnixStream, UnixStream, Receiver<UnixStream>) {
    let (fake, origins) = FakeUpstream::new();
    let fake = fake.answer("registry.npmjs.org", &["104.16.0.34:443"]);
    let proxy = spawn_proxy(&[NPM], fake, MemSink::new(), settings(idle));
    let mut client = proxy.client();
    send(&mut client, &connect_head(NPM));
    assert_eq!(status(&read_head(&mut client)), 200);
    let origin = next_origin(&origins);
    (proxy, client, origin, origins)
}

fn close(proxy: &Proxy) -> (u64, u64, End) {
    let records = proxy.sink.wait_terminal(1);
    assert_eq!(kinds(&records, 1), ["allowed", "open", "close"]);
    match records.last() {
        Some(Record::Close { up, down, end, .. }) => (*up, *down, *end),
        other => panic!("{other:?}"),
    }
}

#[test]
fn client_half_close_still_delivers_the_response() {
    let (proxy, mut client, mut origin, _origins) = tunnel(DEADLINE);
    send(&mut client, b"request");
    client.shutdown(Shutdown::Write).expect("half-close");
    assert_eq!(read_to_close(&mut origin), b"request");
    send(&mut origin, b"response");
    drop(origin);
    assert_eq!(read_to_close(&mut client), b"response");
    assert_eq!(close(&proxy), (7, 8, End::Eof));
}

#[test]
fn upstream_half_close_still_delivers_the_request() {
    let (proxy, mut client, mut origin, _origins) = tunnel(DEADLINE);
    send(&mut origin, b"greeting");
    origin.shutdown(Shutdown::Write).expect("half-close");
    assert_eq!(read_to_close(&mut client), b"greeting");
    send(&mut client, b"request");
    client.shutdown(Shutdown::Write).expect("half-close");
    assert_eq!(read_to_close(&mut origin), b"request");
    assert_eq!(close(&proxy), (7, 8, End::Eof));
}

/// A client that closes its socket after its request, while the origin
/// still answers the end of the upload (a TLS `close_notify`): the bytes
/// cannot be delivered, a Unix socket refuses them with `EPIPE`, and the
/// tunnel still ends as `eof`, not as an error.
#[test]
fn client_full_close_after_the_request_ends_eof() {
    let (proxy, mut client, mut origin, _origins) = tunnel(DEADLINE);
    send(&mut client, b"request");
    drop(client);
    assert_eq!(read_to_close(&mut origin), b"request");
    send(&mut origin, b"close_notify");
    drop(origin);
    assert_eq!(close(&proxy), (7, 0, End::Eof));
}

/// A client that half-closes its upload and then stops reading while the
/// origin pushes more than the socket buffers hold: the blocked write runs
/// out the idle window, and the tunnel ends as `idle`.
#[test]
fn client_that_stops_reading_ends_idle() {
    let start = Instant::now();
    let (proxy, client, mut origin, _origins) = tunnel(Duration::from_millis(300));
    client.shutdown(Shutdown::Write).expect("half-close");
    origin.set_write_timeout(Some(DEADLINE)).expect("timeout");
    let writer = thread::spawn(move || {
        // Fails once the relay stops the tunnel; that is the point.
        let _ = origin.write_all(&vec![b'x'; 8 << 20]);
    });
    let (up, _down, end) = close(&proxy);
    assert_eq!((up, end), (0, End::Idle));
    assert!(start.elapsed() < DEADLINE, "{:?}", start.elapsed());
    join(writer);
    drop(client);
}

#[test]
fn idle_tunnel_closes_after_the_idle_timeout() {
    let start = Instant::now();
    let (proxy, mut client, mut origin, _origins) = tunnel(Duration::from_millis(300));
    assert!(read_to_close(&mut client).is_empty());
    assert!(read_to_close(&mut origin).is_empty());
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < DEADLINE, "{elapsed:?}");
    assert_eq!(close(&proxy), (0, 0, End::Idle));
}

#[test]
fn traffic_in_one_direction_keeps_the_tunnel_open() {
    let (proxy, mut client, mut origin, _origins) = tunnel(Duration::from_secs(1));
    let start = Instant::now();
    let writer = thread::spawn(move || {
        for _ in 0..25 {
            origin.write_all(b"x").expect("byte to the client");
            thread::sleep(Duration::from_millis(100));
        }
    });
    let got = read_to_close(&mut client);
    join(writer);
    assert_eq!(got, vec![b'x'; 25], "every byte, then the origin's EOF");
    assert!(start.elapsed() >= Duration::from_millis(2400));
    drop(client);
    assert_eq!(close(&proxy), (0, 25, End::Eof));
}

/// A stream whose writes always fail with the given kind.
struct FailingWrites(UnixStream, std::io::ErrorKind);

impl std::io::Read for FailingWrites {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for FailingWrites {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(self.1, "write failure on purpose"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl RelayStream for FailingWrites {
    fn try_clone_box(&self) -> std::io::Result<Box<dyn RelayStream>> {
        Ok(Box::new(FailingWrites(self.0.try_clone()?, self.1)))
    }

    fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        self.0.shutdown(how)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.0.set_write_timeout(timeout)
    }
}

/// A failed write in the upload direction ends the download direction too,
/// while it is blocked reading a silent origin: the tunnel ends long
/// before its 60 s idle timeout, with `end=error`, and both peers see the
/// end of their stream.
#[test]
fn a_failed_direction_stops_the_other() {
    let (sandbox, mut client) = UnixStream::pair().expect("pair");
    let (upstream, mut origin) = UnixStream::pair().expect("pair");
    client.set_read_timeout(Some(DEADLINE)).expect("timeout");
    origin.set_read_timeout(Some(DEADLINE)).expect("timeout");
    let settings = settings(Duration::from_secs(60));
    let start = Instant::now();
    let relay = thread::spawn(move || {
        boneli_egress::relay(
            Box::new(sandbox),
            Vec::new(),
            Box::new(FailingWrites(upstream, std::io::ErrorKind::Other)),
            &settings,
        )
    });
    send(&mut client, b"x");
    let outcome = join(relay);
    assert!(start.elapsed() < DEADLINE, "{:?}", start.elapsed());
    assert_eq!(outcome.end, End::Error);
    assert_eq!((outcome.up, outcome.down), (0, 0));
    assert!(read_to_close(&mut client).is_empty());
    assert!(read_to_close(&mut origin).is_empty());
}

/// Both peers gone: each direction reads a byte and finds the peer it
/// writes to gone, so neither saw the end of a stream, and the tunnel
/// ends as `error`, not as `eof`.
#[test]
fn both_peers_gone_ends_error() {
    let (sandbox, mut client) = UnixStream::pair().expect("pair");
    let (upstream, mut origin) = UnixStream::pair().expect("pair");
    send(&mut client, b"x");
    send(&mut origin, b"y");
    let settings = settings(Duration::from_secs(60));
    let start = Instant::now();
    let relay = thread::spawn(move || {
        boneli_egress::relay(
            Box::new(FailingWrites(sandbox, std::io::ErrorKind::BrokenPipe)),
            Vec::new(),
            Box::new(FailingWrites(upstream, std::io::ErrorKind::BrokenPipe)),
            &settings,
        )
    });
    let outcome = join(relay);
    assert!(start.elapsed() < DEADLINE, "{:?}", start.elapsed());
    assert_eq!((outcome.up, outcome.down, outcome.end), (0, 0, End::Error));
}

/// A reset is not a peer that is gone after its stream: the upload's write
/// meets the reset first, the origin's end of stream follows, and the
/// tunnel still ends as `error`, not as `eof`.
#[test]
fn reset_on_upload_write_ends_error() {
    let (sandbox, mut client) = UnixStream::pair().expect("pair");
    let (upstream, origin) = UnixStream::pair().expect("pair");
    client.set_read_timeout(Some(DEADLINE)).expect("timeout");
    let settings = settings(Duration::from_secs(60));
    let relay = thread::spawn(move || {
        boneli_egress::relay(
            Box::new(sandbox),
            Vec::new(),
            Box::new(FailingWrites(upstream, std::io::ErrorKind::ConnectionReset)),
            &settings,
        )
    });
    send(&mut client, b"x");
    origin.shutdown(Shutdown::Write).expect("half-close");
    let outcome = join(relay);
    assert_eq!((outcome.up, outcome.down, outcome.end), (0, 0, End::Error));
    assert!(read_to_close(&mut client).is_empty());
}

/// A real TCP reset in the middle of a download (the origin closes with
/// unread upload bytes, so Linux sends a reset instead of a FIN): the
/// tunnel ends as `error` with the bytes that made it through.
#[test]
fn tcp_reset_mid_download_ends_error() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let upstream = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let (mut origin, _) = listener.accept().expect("accept");
    let (sandbox, mut client) = UnixStream::pair().expect("pair");
    client.set_read_timeout(Some(DEADLINE)).expect("timeout");
    origin.set_read_timeout(Some(DEADLINE)).expect("timeout");
    let settings = settings(Duration::from_secs(60));
    let start = Instant::now();
    let relay = thread::spawn(move || {
        boneli_egress::relay(Box::new(sandbox), Vec::new(), Box::new(upstream), &settings)
    });
    send(&mut client, b"x");
    // The upload byte sits unread in the origin's receive queue.
    let mut byte = [0u8; 1];
    assert_eq!(origin.peek(&mut byte).expect("peek"), 1);
    send(&mut origin, b"partial");
    let mut got = [0u8; 7];
    client.read_exact(&mut got).expect("partial download");
    assert_eq!(&got, b"partial");
    drop(origin);
    let outcome = join(relay);
    assert!(start.elapsed() < DEADLINE, "{:?}", start.elapsed());
    assert_eq!((outcome.up, outcome.down, outcome.end), (1, 7, End::Error));
}
