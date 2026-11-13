//! Server-sent events: every event reaches the reader before the next one
//! is produced, directly and through `pass_through` (ADR-003).
//!
//! The producer sends event 2 only after the consumer has read event 1
//! (a channel handshake), so buffering anywhere turns into a wait. The
//! 10 s socket read timeouts and channel waits turn that wait into a test
//! failure instead of a hang; they are far above any local delivery time
//! and only bound a deadlock.

mod common;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use boneli_http::{
    Connection, Error, Exchange, Headers, Method, RequestBody, RequestHead, Target, pass_through,
};
use common::wide;

const DEADLOCK_BOUND: Duration = Duration::from_secs(10);
const EVENT_1: &[u8] = b"data: 1\n\n";
const EVENT_2: &[u8] = b"data: 2\n\n";

fn get_events() -> RequestHead {
    RequestHead::new(
        Method::new("GET").expect("method"),
        Target::Origin("/events".into()),
    )
}

/// Serves one connection whose handler streams event 1, waits for the
/// signal, then streams event 2.
fn spawn_producer(read_one: Receiver<()>) -> UnixStream {
    let (client, server) = UnixStream::pair().expect("pair");
    let read_one = Mutex::new(read_one);
    let limits = common::server_limits(wide());
    thread::spawn(move || {
        boneli_http::serve_connection(server, &limits, &|ex: Exchange<'_, UnixStream>| {
            let mut headers = Headers::new();
            headers.append("Content-Type", "text/event-stream");
            let mut writer = ex.respond_streaming(200, &headers)?;
            writer.write_all(EVENT_1)?;
            writer.flush()?;
            read_one
                .lock()
                .expect("lock")
                .recv_timeout(DEADLOCK_BOUND)
                .map_err(|_| Error::Timeout)?;
            writer.write_all(EVENT_2)?;
            writer.finish()?;
            Ok(())
        })
    });
    client
        .set_read_timeout(Some(DEADLOCK_BOUND))
        .expect("timeout");
    client
}

/// Reads from `body` until `expected` has arrived in full.
fn read_exactly(body: &mut impl Read, expected: &[u8]) {
    let mut got = vec![0u8; expected.len()];
    body.read_exact(&mut got)
        .expect("event arrives without the next one");
    assert_eq!(got, expected);
}

#[test]
fn sse_events_arrive_unbuffered() {
    let (signal, read_one) = mpsc::channel();
    let stream = spawn_producer(read_one);
    let mut conn = Connection::new(stream, "localhost", wide()).expect("connection");
    let mut response = conn
        .request(&get_events(), RequestBody::None)
        .expect("response");
    assert_eq!(response.head.status, 200);
    read_exactly(&mut response, EVENT_1);
    signal.send(()).expect("signal");
    let mut rest = Vec::new();
    response.read_to_end(&mut rest).expect("rest");
    assert_eq!(rest, EVENT_2);
    drop(response);
    assert!(conn.is_reusable());
}

/// Serves one connection whose handler fetches `/events` from `upstream`
/// and forwards the body with `pass_through`.
fn spawn_middle(upstream: UnixStream) -> UnixStream {
    let (client, server) = UnixStream::pair().expect("pair");
    let upstream = Mutex::new(Some(upstream));
    let limits = common::server_limits(wide());
    thread::spawn(move || {
        boneli_http::serve_connection(server, &limits, &|ex: Exchange<'_, UnixStream>| {
            let stream = upstream.lock().expect("lock").take().expect("one request");
            let mut conn = Connection::new(stream, "upstream", wide())?;
            let mut response = conn.request(&get_events(), RequestBody::None)?;
            // The server owns the framing headers; forward the rest.
            let mut headers = Headers::new();
            for (name, value) in response.head.headers.iter() {
                let framing = ["transfer-encoding", "content-length", "connection"];
                if !framing.iter().any(|f| name.eq_ignore_ascii_case(f)) {
                    headers.append(name, value);
                }
            }
            let writer = ex.respond_streaming(response.head.status, &headers)?;
            pass_through(&mut response, writer)?;
            Ok(())
        })
    });
    client
        .set_read_timeout(Some(DEADLOCK_BOUND))
        .expect("timeout");
    client
}

#[test]
fn pass_through_forwards_each_read() {
    let (signal, read_one) = mpsc::channel();
    let upstream = spawn_producer(read_one);
    let middle = spawn_middle(upstream);
    let mut conn = Connection::new(middle, "localhost", wide()).expect("connection");
    let mut response = conn
        .request(&get_events(), RequestBody::None)
        .expect("response");
    assert_eq!(
        response.head.headers.get("content-type"),
        Some(&b"text/event-stream"[..])
    );
    read_exactly(&mut response, EVENT_1);
    signal.send(()).expect("signal");
    let mut rest = Vec::new();
    response.read_to_end(&mut rest).expect("rest");
    assert_eq!(rest, EVENT_2);
}

#[test]
fn pass_through_truncation_stays_visible() {
    let (upstream, mut raw) = UnixStream::pair().expect("pair");
    let middle = spawn_middle(upstream);
    let feeder = thread::spawn(move || {
        raw.set_read_timeout(Some(DEADLOCK_BOUND)).expect("timeout");
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            assert_eq!(raw.read(&mut byte).expect("request"), 1);
            request.push(byte[0]);
        }
        raw.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata: 1\n\n\r\n")
            .expect("event 1");
        // The upstream dies mid-stream: no terminating chunk.
    });

    let mut conn = Connection::new(middle, "localhost", wide()).expect("connection");
    let mut response = conn
        .request(&get_events(), RequestBody::None)
        .expect("response");
    read_exactly(&mut response, EVENT_1);
    feeder.join().expect("feeder");
    let mut rest = Vec::new();
    let err = response
        .read_to_end(&mut rest)
        .expect_err("truncation is visible");
    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    assert!(rest.is_empty());
    drop(response);
    assert!(!conn.is_reusable());
}
