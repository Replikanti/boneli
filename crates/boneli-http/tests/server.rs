//! The server: what handlers may send, keep-alive, the connection cap and
//! the timeouts (ADR-003).

mod common;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::{Duration, Instant};

use boneli_http::{Error, Exchange, Headers, Limits, ServerLimits};
use common::{MemStream, SocketFile, run_server, wide};

const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";

/// Runs one handler over in-memory input and returns what it wrote.
fn serve_mem<H>(input: &[u8], handler: H) -> (Vec<u8>, Result<(), Error>)
where
    H: Fn(Exchange<'_, MemStream>) -> Result<(), Error>,
{
    let (stream, output) = MemStream::new(input, 4096);
    let result = boneli_http::serve_connection(stream, &common::server_limits(wide()), &handler);
    let written = output.borrow().clone();
    (written, result)
}

/// Reads from `stream` until a full response head has arrived (bodies in
/// these tests are empty).
fn read_head(stream: &mut UnixStream) -> String {
    let mut got = Vec::new();
    let mut byte = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).expect("read response");
        assert_ne!(n, 0, "closed after {:?}", String::from_utf8_lossy(&got));
        got.push(byte[0]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// Asserts that the peer closes `stream` (reads end of file).
fn assert_closed(stream: &mut UnixStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).expect("closed");
}

fn timeouts(idle: Duration, request: Duration) -> ServerLimits {
    ServerLimits::new(wide(), 4, idle, request, Duration::from_secs(5)).expect("limits")
}

#[test]
fn response_header_injection_rejected() {
    let bad: [(&str, &[u8]); 6] = [
        ("X", b"a\r\nInjected: 1"),
        ("X", b"a\nb"),
        ("Content-Length", b"0"),
        ("transfer-encoding", b"chunked"),
        ("CONNECTION", b"close"),
        ("X Y", b"1"),
    ];
    for (name, value) in bad {
        for propagate in [false, true] {
            let mut headers = Headers::new();
            headers.append(name, value);
            let (written, _) = serve_mem(GET, |ex| {
                let result = ex.respond(200, &headers, b"body");
                assert!(matches!(result, Err(Error::InvalidInput(_))), "{name:?}");
                if propagate { result } else { Ok(()) }
            });
            assert!(
                written.is_empty(),
                "{name:?}: nothing written, got {:?}",
                String::from_utf8_lossy(&written)
            );

            let mut headers = Headers::new();
            headers.append(name, value);
            let (written, _) = serve_mem(GET, |ex| {
                let result = ex.respond_streaming(200, &headers).map(drop);
                assert!(result.is_err(), "{name:?}");
                Ok(())
            });
            assert!(
                written.is_empty(),
                "{name:?}: nothing written when streaming"
            );
        }
    }
}

#[test]
fn server_head_omits_body() {
    let head = b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n";
    let (written, result) = serve_mem(head, |ex| ex.respond(200, &Headers::new(), b"abc"));
    result.expect("served");
    assert_eq!(written, b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n");

    let (written, result) = serve_mem(head, |ex| {
        let mut writer = ex.respond_streaming(200, &Headers::new())?;
        writer.write_all(b"abc")?;
        writer.finish()?;
        Ok(())
    });
    result.expect("served");
    assert_eq!(
        written,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
}

#[test]
fn server_bodyless_statuses() {
    for status in [204u16, 304] {
        let (written, _) = serve_mem(GET, |ex| {
            assert!(matches!(
                ex.respond(status, &Headers::new(), b"x"),
                Err(Error::InvalidInput(_))
            ));
            Ok(())
        });
        assert!(written.is_empty());
        let (written, _) = serve_mem(GET, |ex| {
            assert!(ex.respond_streaming(status, &Headers::new()).is_err());
            Ok(())
        });
        assert!(written.is_empty());
        let (written, result) = serve_mem(GET, |ex| ex.respond(status, &Headers::new(), b""));
        result.expect("served");
        let text = String::from_utf8_lossy(&written).into_owned();
        assert!(text.starts_with(&format!("HTTP/1.1 {status} ")), "{text}");
        assert!(
            !text.to_ascii_lowercase().contains("content-length"),
            "{text}"
        );
    }
    for status in [100u16, 101, 103, 199, 99, 1000] {
        let (written, _) = serve_mem(GET, |ex| {
            assert!(
                ex.respond(status, &Headers::new(), b"").is_err(),
                "status {status}"
            );
            Ok(())
        });
        assert!(written.is_empty(), "status {status}");
    }
}

#[test]
fn pipelined_requests_answered_in_order() {
    let input = b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nPOST /2 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhiGET /3 HTTP/1.1\r\nHost: a\r\n\r\n";
    let out = run_server(input, input.len(), wide());
    assert_eq!(out.statuses(), vec![200, 200, 200]);
    let targets: Vec<_> = out
        .requests
        .iter()
        .map(|(head, _)| format!("{:?}", head.target))
        .collect();
    assert_eq!(targets.len(), 3);
    assert!(
        targets[0].contains("/1") && targets[1].contains("/2") && targets[2].contains("/3"),
        "{targets:?}"
    );
    assert_eq!(out.requests[1].1, Ok(b"hi".to_vec()));
    assert!(!out.text().contains("Connection: close"));
}

#[test]
fn unread_body_closes_connection() {
    let mut input = b"POST /1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello".to_vec();
    input.extend_from_slice(b"GET /2 HTTP/1.1\r\nHost: a\r\n\r\n");
    let (written, result) = serve_mem(&input, |ex| ex.respond(200, &Headers::new(), b""));
    result.expect("served");
    assert_eq!(
        common::statuses(&written),
        vec![200],
        "the second request is never read"
    );
    assert!(String::from_utf8_lossy(&written).contains("Connection: close"));

    // `close_after` closes the same way.
    let (written, _) = serve_mem(&GET.repeat(2), |mut ex| {
        ex.close_after();
        ex.respond(200, &Headers::new(), b"")
    });
    assert_eq!(common::statuses(&written), vec![200]);
    assert!(String::from_utf8_lossy(&written).contains("Connection: close"));
}

/// Starts `serve` on a fresh socket with one connection slot.
fn serve_one_slot<H>(handler: H) -> SocketFile
where
    H: Fn(Exchange<'_, UnixStream>) -> Result<(), Error> + Send + Sync + 'static,
{
    let path = common::socket_path();
    let listener = UnixListener::bind(&path).expect("bind");
    let five = Duration::from_secs(5);
    let limits = ServerLimits::new(wide(), 1, five, five, five).expect("limits");
    thread::spawn(move || boneli_http::serve(listener, limits, handler));
    SocketFile(path)
}

#[test]
fn handler_panic_releases_slot() {
    let socket = serve_one_slot(|ex| {
        if format!("{:?}", ex.head().target).contains("/panic") {
            panic!("handler panic on purpose");
        }
        ex.respond(200, &Headers::new(), b"")
    });

    let mut first = UnixStream::connect(&socket.0).expect("connect");
    first
        .write_all(b"GET /panic HTTP/1.1\r\nHost: a\r\n\r\n")
        .expect("send");
    assert_closed(&mut first);

    let mut second = UnixStream::connect(&socket.0).expect("connect");
    second
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    second.write_all(GET).expect("send");
    assert!(read_head(&mut second).starts_with("HTTP/1.1 200 "));
}

#[test]
fn connection_cap_backpressure() {
    let socket = serve_one_slot(|ex| ex.respond(200, &Headers::new(), b""));

    let mut first = UnixStream::connect(&socket.0).expect("connect");
    first
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    first.write_all(GET).expect("send");
    assert!(read_head(&mut first).starts_with("HTTP/1.1 200 "));

    // The first connection is idle but open, so it holds the only slot.
    let mut second = UnixStream::connect(&socket.0).expect("the kernel backlog accepts");
    second.write_all(GET).expect("send");
    second
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");
    let mut byte = [0u8; 1];
    let err = second
        .read(&mut byte)
        .expect_err("no response while the slot is held");
    assert!(
        matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        "{err:?}"
    );

    drop(first);
    second
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    assert!(read_head(&mut second).starts_with("HTTP/1.1 200 "));
}

/// Runs `serve_connection` on one end of a socket pair in a thread.
fn spawn_connection<H>(
    limits: ServerLimits,
    handler: H,
) -> (UnixStream, thread::JoinHandle<Result<(), Error>>)
where
    H: Fn(Exchange<'_, UnixStream>) -> Result<(), Error> + Send + 'static,
{
    let (client, server) = UnixStream::pair().expect("pair");
    let handle = thread::spawn(move || boneli_http::serve_connection(server, &limits, &handler));
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    (client, handle)
}

/// Writes `bytes` one per 20 ms until the peer stops reading.
fn trickle(mut stream: UnixStream, bytes: Vec<u8>) {
    thread::spawn(move || {
        for byte in bytes {
            if stream.write_all(&[byte]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
}

#[test]
fn request_timeout_bounds_trickled_head() {
    let (mut client, handle) = spawn_connection(
        timeouts(Duration::from_secs(5), Duration::from_millis(200)),
        |ex| ex.respond(200, &Headers::new(), b""),
    );
    let mut head = b"GET / HTTP/1.1\r\nHost: a\r\nX: ".to_vec();
    head.extend(std::iter::repeat_n(b'a', 1000));
    let start = Instant::now();
    trickle(client.try_clone().expect("clone"), head);

    assert!(read_head(&mut client).starts_with("HTTP/1.1 408 "));
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    assert_closed(&mut client);
    assert!(matches!(
        handle.join().expect("no panic"),
        Err(Error::Timeout)
    ));
}

#[test]
fn request_timeout_covers_body() {
    let (mut client, handle) = spawn_connection(
        timeouts(Duration::from_secs(5), Duration::from_millis(200)),
        |mut ex| {
            let mut body = Vec::new();
            ex.body().read_to_end(&mut body)?;
            ex.respond(200, &Headers::new(), b"")
        },
    );
    let start = Instant::now();
    client
        .write_all(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\n\r\n")
        .expect("head");
    trickle(client.try_clone().expect("clone"), vec![b'a'; 1000]);

    assert!(read_head(&mut client).starts_with("HTTP/1.1 408 "));
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(200), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    assert_closed(&mut client);
    assert!(handle.join().expect("no panic").is_err());
}

#[test]
fn idle_keepalive_timeout() {
    let (mut client, handle) = spawn_connection(
        timeouts(Duration::from_millis(100), Duration::from_secs(5)),
        |ex| ex.respond(200, &Headers::new(), b""),
    );
    client.write_all(GET).expect("send");
    let start = Instant::now();
    assert!(read_head(&mut client).starts_with("HTTP/1.1 200 "));
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).expect("closed by the server");
    let elapsed = start.elapsed();
    assert!(rest.is_empty());
    assert!(elapsed >= Duration::from_millis(100), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    handle
        .join()
        .expect("no panic")
        .expect("an idle close is not an error");
}

#[test]
fn empty_connection_closes_quietly() {
    let (written, result) = serve_mem(b"", |_| panic!("no request"));
    result.expect("no error");
    assert!(written.is_empty());

    let (client, handle) =
        spawn_connection(common::server_limits(wide()), |_| panic!("no request"));
    drop(client);
    handle.join().expect("no panic").expect("no error");
}

#[test]
fn zero_limits_rejected() {
    assert!(Limits::new(0, 1, 1).is_err());
    assert!(Limits::new(1, 0, 1).is_err());
    assert!(Limits::new(1, 1, 0).is_err());
    assert!(Limits::new(1, 1, 1).is_ok());

    let one = Duration::from_millis(1);
    let zero = Duration::ZERO;
    assert!(ServerLimits::new(wide(), 0, one, one, one).is_err());
    assert!(ServerLimits::new(wide(), 1, zero, one, one).is_err());
    assert!(ServerLimits::new(wide(), 1, one, zero, one).is_err());
    assert!(ServerLimits::new(wide(), 1, one, one, zero).is_err());
    assert!(ServerLimits::new(wide(), 1, one, one, one).is_ok());
}
