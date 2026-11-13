//! The client: response framing, connection reuse and the headers it owns
//! (ADR-003).

mod common;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use boneli_http::{
    Connection, Error, Headers, IdleCheck, Method, RequestBody, RequestHead, Target,
};
use common::{MemStream, Pieces, limits, pieces, wide};

/// A stream with all input loaded up front cannot tell what arrived after
/// a response, so a connection over it serves one request.
impl IdleCheck for MemStream {
    fn is_idle(&mut self) -> io::Result<bool> {
        Ok(false)
    }
}

/// A peer that answers each request with the next queued response: the
/// response becomes readable when the client flushes its request.
struct Replies {
    queue: VecDeque<Vec<u8>>,
    current: Pieces,
    output: Rc<RefCell<Vec<u8>>>,
}

impl Read for Replies {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.current.read(buf)
    }
}

impl Write for Replies {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.current.is_empty() {
            if let Some(next) = self.queue.pop_front() {
                self.current = pieces(&next, 7);
            }
        }
        Ok(())
    }
}

impl IdleCheck for Replies {
    fn is_idle(&mut self) -> io::Result<bool> {
        Ok(self.current.is_empty())
    }
}

/// A connection whose peer answers request N with `responses[N]`.
fn replies(responses: &[&[u8]]) -> (Connection<Replies>, Rc<RefCell<Vec<u8>>>) {
    let output = Rc::new(RefCell::new(Vec::new()));
    let stream = Replies {
        queue: responses.iter().map(|r| r.to_vec()).collect(),
        current: pieces(b"", 1),
        output: Rc::clone(&output),
    };
    (
        Connection::new(stream, "example.test", wide()).expect("connection"),
        output,
    )
}

fn get(path: &str) -> RequestHead {
    RequestHead::new(
        Method::new("GET").expect("method"),
        Target::Origin(path.into()),
    )
}

fn with_method(method: &str, path: &str) -> RequestHead {
    RequestHead::new(
        Method::new(method).expect("method"),
        Target::Origin(path.into()),
    )
}

/// A connection whose peer answers with `responses`.
fn connection(
    responses: &[u8],
) -> (
    Connection<MemStream>,
    std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
) {
    connection_with(responses, wide())
}

fn connection_with(
    responses: &[u8],
    limits: boneli_http::Limits,
) -> (
    Connection<MemStream>,
    std::rc::Rc<std::cell::RefCell<Vec<u8>>>,
) {
    let (stream, written) = MemStream::new(responses, 7);
    (
        Connection::new(stream, "example.test", limits).expect("connection"),
        written,
    )
}

/// Sends `head` without a body and reads the whole response body.
fn fetch<S: Read + Write + IdleCheck>(
    conn: &mut Connection<S>,
    head: &RequestHead,
) -> Result<(u16, Vec<u8>), Error> {
    let mut response = conn.request(head, RequestBody::None)?;
    let mut body = Vec::new();
    response.read_to_end(&mut body)?;
    Ok((response.head.status, body))
}

#[test]
fn client_writes_request_and_framing() {
    let ok: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let (mut conn, written) = replies(&[ok, ok, ok]);
    let mut head = get("/p?q=1");
    head.headers.append("X-Test", "1");
    fetch(&mut conn, &head).expect("get");
    assert_eq!(
        &written.borrow()[..],
        b"GET /p?q=1 HTTP/1.1\r\nHost: example.test\r\nX-Test: 1\r\n\r\n"
    );

    written.borrow_mut().clear();
    let post = with_method("POST", "/up");
    conn.request(&post, RequestBody::Bytes(b"abc"))
        .expect("post");
    assert_eq!(
        &written.borrow()[..],
        b"POST /up HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc"
    );

    written.borrow_mut().clear();
    let mut source: &[u8] = b"hello";
    conn.request(
        &post,
        RequestBody::Reader {
            reader: &mut source,
            length: None,
        },
    )
    .expect("streamed post");
    assert_eq!(
        &written.borrow()[..],
        b"POST /up HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    );
}

#[test]
fn head_response_has_no_body() {
    let (mut conn, _) = replies(&[
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
    ]);
    let (status, body) = fetch(&mut conn, &with_method("HEAD", "/")).expect("head");
    assert_eq!((status, body), (200, Vec::new()));
    assert!(conn.is_reusable());
    let (status, body) = fetch(&mut conn, &get("/")).expect("get");
    assert_eq!((status, body), (200, b"hi".to_vec()));
    assert!(conn.is_reusable());
}

#[test]
fn interim_responses_skipped_and_bounded() {
    let (mut conn, _) = connection(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
    );
    assert_eq!(
        fetch(&mut conn, &get("/")).expect("get"),
        (200, b"hi".to_vec())
    );

    for status in ["204 No Content", "304 Not Modified"] {
        let (mut conn, _) = replies(&[
            format!("HTTP/1.1 {status}\r\nContent-Length: 5\r\n\r\n").as_bytes(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        ]);
        assert_eq!(
            fetch(&mut conn, &get("/")).expect("bodyless").1,
            Vec::<u8>::new()
        );
        assert!(conn.is_reusable());
        assert_eq!(
            fetch(&mut conn, &get("/")).expect("next"),
            (200, b"hi".to_vec())
        );
    }

    // 25 + 28 = 53 bytes of heads fit 64.
    let (mut conn, _) = connection_with(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        limits(64, 8, 10),
    );
    assert_eq!(fetch(&mut conn, &get("/")).expect("fits").0, 204);

    // An endless 1xx stream fails once the heads together pass 64 bytes.
    let endless = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(100);
    let (mut conn, _) = connection_with(&endless, limits(64, 8, 10));
    assert!(matches!(
        fetch(&mut conn, &get("/")),
        Err(Error::HeadTooLarge)
    ));
    assert!(!conn.is_reusable());
}

#[test]
fn switching_protocols_rejected() {
    let (mut conn, _) = connection(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\nConnection: upgrade\r\n\r\n",
    );
    assert!(matches!(
        fetch(&mut conn, &get("/")),
        Err(Error::Status(101))
    ));
    assert!(!conn.is_reusable());
}

#[test]
fn close_delimited_response() {
    let (mut conn, _) = connection(b"HTTP/1.1 200 OK\r\n\r\nabc");
    assert_eq!(
        fetch(&mut conn, &get("/")).expect("get"),
        (200, b"abc".to_vec())
    );
    assert!(!conn.is_reusable());

    // The body limit holds for close-delimited bodies too.
    let (mut conn, _) = connection_with(b"HTTP/1.1 200 OK\r\n\r\n0123456789a", limits(1024, 8, 10));
    assert!(matches!(
        fetch(&mut conn, &get("/")),
        Err(Error::BodyTooLarge)
    ));
}

#[test]
fn response_version_and_status_checked() {
    let (mut conn, _) = connection(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    assert!(matches!(
        fetch(&mut conn, &get("/")),
        Err(Error::UnsupportedVersion)
    ));
    for input in [
        &b"HTTP/1.1 099 Low\r\nContent-Length: 0\r\n\r\n"[..],
        b"HTTP/1.1 1000 High\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 20 Short\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    ] {
        let (mut conn, _) = connection(input);
        assert!(
            fetch(&mut conn, &get("/")).is_err(),
            "input {:?}",
            String::from_utf8_lossy(input)
        );
        assert!(!conn.is_reusable());
    }
    let (mut conn, _) = connection(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n");
    assert!(matches!(
        fetch(&mut conn, &get("/")),
        Err(Error::UnsupportedTransferCoding)
    ));
}

#[test]
fn connection_close_token_in_list() {
    let (mut conn, _) = connection(
        b"HTTP/1.1 200 OK\r\nConnection: keep-alive, Close\r\nContent-Length: 0\r\n\r\n",
    );
    fetch(&mut conn, &get("/")).expect("get");
    assert!(!conn.is_reusable());

    let (mut conn, _) =
        connection(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n");
    fetch(&mut conn, &get("/")).expect("get");
    assert!(conn.is_reusable());
}

#[test]
fn partially_read_response_not_reusable() {
    let (mut conn, _) = connection(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    {
        let mut response = conn.request(&get("/"), RequestBody::None).expect("get");
        let mut two = [0u8; 2];
        response.read_exact(&mut two).expect("two bytes");
    }
    assert!(!conn.is_reusable());
    assert!(matches!(
        conn.request(&get("/"), RequestBody::None),
        Err(Error::InvalidInput(_))
    ));

    // A chunked body over the limit after part of it was read: the read
    // fails and the connection is not reused.
    let (mut conn, _) = connection_with(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n0123\r\n7\r\n456789a\r\n0\r\n\r\n",
        limits(1024, 8, 10),
    );
    assert!(matches!(
        fetch(&mut conn, &get("/")),
        Err(Error::BodyTooLarge)
    ));
    assert!(!conn.is_reusable());
}

#[test]
fn client_rejects_numeric_hosts() {
    for host in [
        "0xa9fea9fe",
        "2130706433",
        "127.1",
        "0177.0.0.1",
        "10.1",
        "1.0x1",
        "127.1:80",
        "0x7f000001:8080",
        "a_b",
        "-a.example",
        "a..b",
    ] {
        assert!(
            matches!(
                Connection::new(MemStream::new(b"", 1).0, host, wide()),
                Err(Error::InvalidInput(_))
            ),
            "{host}"
        );
    }
    for host in ["127.0.0.1", "127.0.0.1:80", "a-1.example", "[::1]:80"] {
        Connection::new(MemStream::new(b"", 1).0, host, wide()).expect(host);
    }
}

#[test]
fn client_not_reused_with_buffered_bytes() {
    // An unsolicited second response arrives in the same read as the first:
    // it must not become the answer to the next request.
    let input =
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nEVIL";
    let (stream, written) = MemStream::new(input, 4096);
    let mut conn = Connection::new(stream, "example.test", wide()).expect("connection");
    assert_eq!(fetch(&mut conn, &get("/")).expect("first").0, 200);
    assert!(!conn.is_reusable());
    let sent = written.borrow().len();
    assert!(conn.request(&get("/"), RequestBody::None).is_err());
    assert_eq!(written.borrow().len(), sent, "nothing more written");
}

/// A client over a Unix socket, and the server end the test drives.
fn unix_pair() -> (Connection<UnixStream>, UnixStream) {
    let (client, server) = UnixStream::pair().expect("pair");
    for end in [&client, &server] {
        end.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
    }
    (
        Connection::new(client, "example.test", wide()).expect("connection"),
        server,
    )
}

/// Reads one request head (these requests have no body).
fn read_request(server: &mut UnixStream) -> Vec<u8> {
    let mut got = Vec::new();
    let mut byte = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        assert_eq!(server.read(&mut byte).expect("read request"), 1);
        got.push(byte[0]);
    }
    got
}

/// Whether bytes are waiting on `server`, without blocking.
fn pending(server: &mut UnixStream) -> bool {
    server.set_nonblocking(true).expect("nonblocking");
    let mut byte = [0u8; 1];
    let read = server.read(&mut byte);
    server.set_nonblocking(false).expect("blocking");
    match read {
        Ok(n) => n > 0,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
        Err(e) => panic!("{e}"),
    }
}

const EMPTY_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

#[test]
fn client_reuses_quiet_unix_connection() {
    let (mut conn, mut server) = unix_pair();
    let peer = thread::spawn(move || {
        for _ in 0..3 {
            read_request(&mut server);
            server.write_all(EMPTY_OK).expect("answer");
        }
        server
    });
    for _ in 0..3 {
        assert_eq!(fetch(&mut conn, &get("/")).expect("fetch").0, 200);
        assert!(conn.is_reusable());
    }
    peer.join().expect("peer");
}

#[test]
fn client_discards_connection_with_unsolicited_bytes() {
    let (mut conn, mut server) = unix_pair();
    server.write_all(EMPTY_OK).expect("first answer");
    assert_eq!(fetch(&mut conn, &get("/")).expect("first").0, 200);
    read_request(&mut server);
    // The peer sends a response nobody asked for while the connection is
    // idle; the next request must not be answered by it.
    server
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nEVIL")
        .expect("unsolicited");
    assert!(conn.request(&get("/"), RequestBody::None).is_err());
    assert!(!conn.is_reusable());
    assert!(!pending(&mut server), "the request was not sent");
}

#[test]
fn client_discards_connection_after_peer_close() {
    let (mut conn, mut server) = unix_pair();
    server.write_all(EMPTY_OK).expect("first answer");
    assert_eq!(fetch(&mut conn, &get("/")).expect("first").0, 200);
    read_request(&mut server);
    server
        .shutdown(std::net::Shutdown::Write)
        .expect("peer closes");
    assert!(conn.request(&get("/"), RequestBody::None).is_err());
    assert!(!conn.is_reusable());
    assert!(!pending(&mut server), "the request was not sent");
}

#[test]
fn client_over_memstream_serves_one_request() {
    // A stream that cannot tell whether bytes arrived while idle is never
    // reused.
    let (mut conn, written) = connection(EMPTY_OK);
    fetch(&mut conn, &get("/")).expect("first");
    let sent = written.borrow().len();
    assert!(conn.request(&get("/"), RequestBody::None).is_err());
    assert_eq!(written.borrow().len(), sent);
}

#[test]
fn client_owns_framing_headers() {
    for name in ["host", "Content-Length", "TRANSFER-ENCODING", "Connection"] {
        let (mut conn, written) = connection(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let mut head = get("/");
        head.headers.append(name, "1");
        assert!(
            matches!(
                conn.request(&head, RequestBody::None),
                Err(Error::InvalidInput(_))
            ),
            "name {name}"
        );
        assert!(
            written.borrow().is_empty(),
            "name {name}: zero bytes written"
        );
    }

    // CONNECT and non-origin targets go through `connect_tunnel` only.
    let (mut conn, written) = connection(b"");
    let connect = RequestHead::new(
        Method::new("CONNECT").expect("method"),
        Target::Authority {
            host: "example.com".into(),
            port: 443,
        },
    );
    assert!(conn.request(&connect, RequestBody::None).is_err());
    assert!(written.borrow().is_empty());
}

#[test]
fn client_header_injection_rejected() {
    let bad: [(&str, &[u8]); 9] = [
        ("X", b"a\r\nInjected: 1"),
        ("X", b"a\nb"),
        ("X", b"a\rb"),
        ("X", b"a\x00b"),
        ("X", b"a\x7fb"),
        ("Content\u{2011}Length", b"1"),
        ("X Y", b"1"),
        ("X:Y", b"1"),
        ("", b"1"),
    ];
    for (name, value) in bad {
        let (mut conn, written) = connection(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let mut head = get("/");
        head.headers.append("Accept", "*/*");
        head.headers.append(name, value);
        assert!(
            conn.request(&head, RequestBody::None).is_err(),
            "{name:?}: {value:?}"
        );
        assert!(written.borrow().is_empty(), "{name:?}: zero bytes written");
    }

    // Targets are checked the same way.
    for target in ["/a b", "/a\r\nX: y", "noslash", "/caf\u{e9}"] {
        let (mut conn, written) = connection(b"");
        assert!(
            conn.request(&get(target), RequestBody::None).is_err(),
            "target {target:?}"
        );
        assert!(written.borrow().is_empty());
    }
    assert!(Method::new("GE T").is_err());
    assert!(Connection::new(MemStream::new(b"", 1).0, "a\r\nb", wide()).is_err());

    // An obs-text value byte is allowed; HTAB too.
    let mut headers = Headers::new();
    headers.append("X", &b"a\tb\xffc"[..]);
    let (mut conn, _) = connection(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let mut head = get("/");
    head.headers = headers;
    fetch(&mut conn, &head).expect("valid value");
}
