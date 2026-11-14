//! The server: what handlers may send, keep-alive, the connection cap and
//! the timeouts (ADR-003).

mod common;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Mutex, PoisonError, mpsc};
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

/// Asserts that the peer writes exactly `expected` more and closes
/// `stream`: end of file, or a reset when the peer closed with input of
/// ours still unread (a Unix socket reports that as `ConnectionReset` after
/// the queued bytes; the trickle tests race with it).
fn assert_closed(stream: &mut UnixStream, expected: &[u8]) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut rest = Vec::new();
    match stream.read_to_end(&mut rest) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
        Err(e) => panic!("closed: {e:?}"),
    }
    assert_eq!(
        String::from_utf8_lossy(&rest),
        String::from_utf8_lossy(expected),
        "bytes before the close"
    );
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
            // Nothing of the response is written. A handler that returns
            // the error closes without an answer (no explicit status); one
            // that returns `Ok` gets the server's 500.
            let expected: &[u8] = if propagate { b"" } else { INTERNAL_ERROR };
            let (written, _) = serve_mem(GET, |ex| {
                let result = ex.respond(200, &headers, b"body");
                assert!(matches!(result, Err(Error::InvalidInput(_))), "{name:?}");
                if propagate { result } else { Ok(()) }
            });
            assert_eq!(
                written,
                expected,
                "{name:?}: got {:?}",
                String::from_utf8_lossy(&written)
            );

            let mut headers = Headers::new();
            headers.append(name, value);
            let (written, _) = serve_mem(GET, |ex| {
                let result = ex.respond_streaming(200, &headers).map(drop);
                assert!(result.is_err(), "{name:?}");
                if propagate { result } else { Ok(()) }
            });
            assert_eq!(written, expected, "{name:?}: streaming");
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
        assert_eq!(written, INTERNAL_ERROR);
        let (written, _) = serve_mem(GET, |ex| {
            assert!(ex.respond_streaming(status, &Headers::new()).is_err());
            Ok(())
        });
        assert_eq!(written, INTERNAL_ERROR);
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
        assert_eq!(written, INTERNAL_ERROR, "status {status}");
    }
}

/// The answer to a handler that returned `Ok` without a byte of a
/// response on the wire (ADR-003, item 11).
const INTERNAL_ERROR: &[u8] =
    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Serves `input` (read in one piece) and counts the handler's calls.
fn serve_counted<H>(input: &[u8], handler: H) -> (Vec<u8>, Result<(), Error>, usize)
where
    H: Fn(Exchange<'_, MemStream>) -> Result<(), Error>,
{
    let calls = std::cell::Cell::new(0);
    let (written, result) = serve_mem(input, |ex| {
        calls.set(calls.get() + 1);
        handler(ex)
    });
    (written, result, calls.get())
}

#[test]
fn handler_without_answer_gets_500() {
    let (written, result, calls) = serve_counted(&GET.repeat(2), |_| Ok(()));
    result.expect("served");
    assert_eq!(
        written,
        INTERNAL_ERROR,
        "{:?}",
        String::from_utf8_lossy(&written)
    );
    assert_eq!(calls, 1, "the connection closes after the 500");
}

#[test]
fn failed_respond_validation_gets_500() {
    // A gateway forwards an upstream value with CR in it, ignores the error
    // and returns `Ok`: nothing reached the wire, so the client gets 500
    // instead of a silent close.
    let mut headers = Headers::new();
    headers.append("X-Up", "a\r\nb");
    let (written, result, calls) = serve_counted(&GET.repeat(2), |ex| {
        assert!(ex.respond(200, &headers, b"").is_err());
        Ok(())
    });
    result.expect("served");
    assert_eq!(written, INTERNAL_ERROR);
    assert_eq!(calls, 1);

    // The same for `accept_tunnel` on a request that is not CONNECT.
    let (written, _, calls) = serve_counted(&GET.repeat(2), |ex| {
        assert!(ex.accept_tunnel().is_err());
        Ok(())
    });
    assert_eq!(written, INTERNAL_ERROR);
    assert_eq!(calls, 1);
}

#[test]
fn unfinished_stream_closes_connection() {
    let (written, result, calls) = serve_counted(&GET.repeat(2), |ex| {
        let mut writer = ex.respond_streaming(200, &Headers::new())?;
        writer.write_all(b"abc")?;
        Ok(())
    });
    result.expect("served");
    assert_eq!(
        written, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
        "no last chunk and no 500 after bytes reached the wire"
    );
    assert_eq!(calls, 1, "the connection closes");
}

/// A stream that reads its input and accepts `room` bytes of writes, then
/// fails every write: a response that reached the wire in part.
struct ShortWrites {
    input: common::Pieces,
    written: std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
    room: usize,
}

impl Read for ShortWrites {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for ShortWrites {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = self.written.borrow_mut();
        let n = buf.len().min(self.room - written.len());
        if n == 0 {
            return Err(ErrorKind::BrokenPipe.into());
        }
        written.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl boneli_http::Transport for ShortWrites {
    fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn failed_respond_write_closes_connection() {
    let written = std::rc::Rc::default();
    let stream = ShortWrites {
        input: common::pieces(&GET.repeat(2), 4096),
        written: std::rc::Rc::clone(&written),
        room: 5,
    };
    let calls = std::cell::Cell::new(0);
    let result =
        boneli_http::serve_connection(stream, &common::server_limits(wide()), &|ex: Exchange<
            '_,
            ShortWrites,
        >| {
            calls.set(calls.get() + 1);
            assert!(ex.respond(200, &Headers::new(), b"").is_err());
            Ok(())
        });
    result.expect("served");
    assert_eq!(
        &written.borrow()[..],
        b"HTTP/",
        "no 500 after a partial response"
    );
    assert_eq!(calls.get(), 1, "the connection closes");
}

#[test]
fn returned_tunnel_closes_connection() {
    let connect = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    let mut input = connect.to_vec();
    input.extend_from_slice(GET);
    // The CONNECT arrives alone, so the request after it is still unread
    // when the tunnel is accepted.
    let (stream, output) = MemStream::from_pieces(common::split_at(&input, &[connect.len()]));
    let calls = std::cell::Cell::new(0);
    let result =
        boneli_http::serve_connection(stream, &common::server_limits(wide()), &|ex: Exchange<
            '_,
            MemStream,
        >| {
            calls.set(calls.get() + 1);
            drop(ex.accept_tunnel()?);
            Ok(())
        });
    result.expect("served");
    assert_eq!(&output.borrow()[..], b"HTTP/1.1 200 OK\r\n\r\n");
    assert_eq!(calls.get(), 1, "the connection closes with the tunnel");
}

#[test]
fn handler_error_without_status_closes() {
    // Errors a handler returns get a status only through `Error::Status`:
    // an upstream timeout or malformed upstream answer is not the client's
    // fault, so it is not answered with 408, 400 or 413.
    for error in [
        || Error::Timeout,
        || Error::Malformed("upstream"),
        || Error::BodyTooLarge,
        || Error::HeadTooLarge,
        || Error::UnsupportedVersion,
        || Error::UnexpectedEof,
        || Error::Io(ErrorKind::ConnectionReset.into()),
    ] {
        let (written, result, calls) = serve_counted(&GET.repeat(2), |_| Err(error()));
        assert!(
            written.is_empty(),
            "{:?}",
            String::from_utf8_lossy(&written)
        );
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }
}

#[test]
fn handler_error_status_answered() {
    for status in [400u16, 403, 502, 504, 599] {
        let (written, result, calls) =
            serve_counted(&GET.repeat(2), |_| Err(Error::Status(status)));
        assert!(matches!(result, Err(Error::Status(s)) if s == status));
        assert_eq!(common::statuses(&written), vec![status]);
        assert!(String::from_utf8_lossy(&written).contains("Connection: close"));
        assert_eq!(calls, 1);
    }
    // Only final error statuses: anything else closes without an answer.
    for status in [0u16, 101, 200, 302, 399, 600, 1000] {
        let (written, _, _) = serve_counted(GET, |_| Err(Error::Status(status)));
        assert!(written.is_empty(), "status {status}");
    }
}

#[test]
fn body_error_status_survives_handler_error() {
    // The server's own reading of the body failed (413); the handler then
    // returns some other error. The client still learns why.
    let input = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n800\r\n";
    let (stream, output) = MemStream::new(input, 4096);
    let limits = common::server_limits(common::limits(1024, 8, 10));
    let result =
        boneli_http::serve_connection(stream, &limits, &|mut ex: Exchange<'_, MemStream>| {
            let mut body = Vec::new();
            assert!(ex.body().read_to_end(&mut body).is_err());
            Err(Error::UnexpectedEof)
        });
    assert!(result.is_err());
    assert_eq!(common::statuses(&output.borrow()), vec![413]);
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
    // A panic is not an answer: the connection closes without a byte.
    assert_closed(&mut first, b"");

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

/// `accept_loop` (ADR-006, D10): every accepted stream reaches the
/// callback, the cap holds the next client in the backlog until a slot is
/// freed, and a panicking callback frees its slot.
#[test]
fn accept_loop_holds_the_cap_and_frees_on_panic() {
    let path = common::socket_path();
    let socket = SocketFile(path.clone());
    let listener = UnixListener::bind(&path).expect("bind");
    let five = Duration::from_secs(5);
    let limits = ServerLimits::new(wide(), 1, five, five, five).expect("limits");
    let (handed, received) = mpsc::channel::<UnixStream>();
    let handed = Mutex::new(handed);
    thread::spawn(move || {
        boneli_http::accept_loop(listener, &limits, move |mut stream: UnixStream| {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).expect("first byte");
            if byte[0] == b'p' {
                panic!("callback panic on purpose");
            }
            let clone = stream.try_clone().expect("clone");
            handed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .send(clone)
                .expect("test alive");
            // Hold the slot until the client closes.
            let mut rest = Vec::new();
            let _ = stream.read_to_end(&mut rest);
        })
    });

    let connect = |first: &[u8]| {
        let mut client = UnixStream::connect(&socket.0).expect("connect");
        client.write_all(first).expect("send");
        client
    };
    // The stream the callback got is the client's: a byte written to it
    // arrives at the client.
    let check = |client: &mut UnixStream, mut handed: UnixStream| {
        handed.write_all(b"x").expect("write to the handed stream");
        client.set_read_timeout(Some(five)).expect("timeout");
        let mut byte = [0u8; 1];
        client
            .read_exact(&mut byte)
            .expect("byte from the callback");
        assert_eq!(&byte, b"x");
    };

    let mut first = connect(b"h");
    let stream = received
        .recv_timeout(five)
        .expect("first stream handed over");
    check(&mut first, stream);

    let mut second = connect(b"h");
    assert!(
        received.recv_timeout(Duration::from_millis(200)).is_err(),
        "the second client waits while the only slot is held"
    );
    drop(first);
    let stream = received
        .recv_timeout(five)
        .expect("second stream after the slot is freed");
    check(&mut second, stream);

    drop(second);
    let panicking = connect(b"p");
    let mut fourth = connect(b"h");
    let stream = received
        .recv_timeout(five)
        .expect("a panicking callback frees its slot");
    check(&mut fourth, stream);
    drop(panicking);
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
    assert_closed(&mut client, b"");
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
    assert_closed(&mut client, b"");
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
