//! CONNECT on both sides: the server hands over the stream, the client
//! opens a tunnel (ADR-003).

mod common;

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use boneli_http::{
    Connection, Error, Exchange, Headers, IdleCheck, Method, RequestBody, RequestHead, Target,
    connect_tunnel,
};
use common::{MemStream, wide};

/// Copies `from` into `to` until end of file, then shuts down `to` for
/// writing so the far side sees the end too.
fn relay(mut from: impl Read, mut to: UnixStream) -> io::Result<u64> {
    let copied = io::copy(&mut from, &mut to)?;
    to.shutdown(Shutdown::Write)?;
    Ok(copied)
}

#[test]
fn connect_tunnel_relays_and_keeps_early_bytes() {
    let (mut client, server) = UnixStream::pair().expect("pair");
    let (upstream_near, mut upstream_far) = UnixStream::pair().expect("pair");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    upstream_far
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");

    let limits = common::server_limits(wide());
    let handle = thread::spawn(move || {
        boneli_http::serve_connection(server, &limits, &|ex: Exchange<'_, UnixStream>| {
            assert_eq!(
                ex.head().target,
                Target::Authority {
                    host: "example.com".into(),
                    port: 443
                }
            );
            let tunnel = ex.accept_tunnel()?;
            let (early, stream) = tunnel.into_parts();
            let back = stream.try_clone()?;
            let up_write = upstream_near.try_clone()?;
            let up_read = upstream_near.try_clone()?;
            // Both directions at once: early bytes first, then the stream.
            thread::scope(|scope| {
                let out = scope.spawn(move || relay(early.as_slice().chain(back), up_write));
                let down = relay(up_read, stream.try_clone()?);
                out.join().expect("relay thread")?;
                down.map(drop)
            })?;
            Ok(())
        })
    });

    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nEARLY")
        .expect("send");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(client.read(&mut byte).expect("read"), 1);
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200 "),
        "{:?}",
        String::from_utf8_lossy(&head)
    );

    let mut early = [0u8; 5];
    upstream_far.read_exact(&mut early).expect("early bytes");
    assert_eq!(&early, b"EARLY");

    client.write_all(b"more").expect("send");
    let mut more = [0u8; 4];
    upstream_far.read_exact(&mut more).expect("relayed");
    assert_eq!(&more, b"more");

    upstream_far.write_all(b"back").expect("send");
    let mut back = [0u8; 4];
    client.read_exact(&mut back).expect("relayed back");
    assert_eq!(&back, b"back");

    client.shutdown(Shutdown::Write).expect("shutdown");
    let mut rest = Vec::new();
    upstream_far.read_to_end(&mut rest).expect("end relayed");
    assert!(rest.is_empty());
    drop(upstream_far);
    let mut rest = Vec::new();
    client.read_to_end(&mut rest).expect("tunnel closed");
    handle.join().expect("no panic").expect("served");
}

#[test]
fn client_tunnel_keeps_bytes_after_head() {
    let (stream, written) = MemStream::new(b"HTTP/1.1 200 Connection established\r\n\r\nHELLO", 3);
    let mut tunnel = connect_tunnel(stream, "Example.com", 443, &wide()).expect("tunnel");
    assert_eq!(
        &written.borrow()[..],
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    );
    let mut got = Vec::new();
    tunnel.read_to_end(&mut got).expect("read");
    assert_eq!(got, b"HELLO");
    tunnel.write_all(b"up").expect("write");
    assert!(written.borrow().ends_with(b"\r\n\r\nup"));

    let (stream, written) = MemStream::new(b"HTTP/1.1 200 OK\r\n\r\n", 64);
    connect_tunnel(stream, "::1", 8443, &wide()).expect("tunnel");
    assert!(
        written
            .borrow()
            .starts_with(b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n")
    );

    for (host, port) in [
        ("a b", 443u16),
        ("u@h", 443),
        ("h", 0),
        ("", 443),
        ("h:1", 443),
        ("a_b", 443),
        ("[::1]", 443),
    ] {
        let (stream, written) = MemStream::new(b"HTTP/1.1 200 OK\r\n\r\n", 64);
        assert!(
            connect_tunnel(stream, host, port, &wide()).is_err(),
            "{host:?}:{port}"
        );
        assert!(written.borrow().is_empty());
    }
}

#[test]
fn client_tunnel_rejects_numeric_hosts() {
    // inet_aton forms that are not canonical IPv4 addresses (ADR-003):
    // nothing is sent for them.
    for host in [
        "0xa9fea9fe",
        "2130706433",
        "127.1",
        "0177.0.0.1",
        "10.1",
        "1.0x1",
    ] {
        let (stream, written) = MemStream::new(b"HTTP/1.1 200 OK\r\n\r\n", 64);
        assert!(
            matches!(
                connect_tunnel(stream, host, 80, &wide()),
                Err(Error::InvalidInput(_))
            ),
            "{host}"
        );
        assert!(written.borrow().is_empty(), "{host}");
    }
    let (stream, written) = MemStream::new(b"HTTP/1.1 200 OK\r\n\r\n", 64);
    connect_tunnel(stream, "169.254.169.254", 80, &wide()).expect("canonical IPv4");
    assert!(
        written
            .borrow()
            .starts_with(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n")
    );
}

#[test]
fn tunnel_idle_check() {
    // HTTP over a tunnel reuses connections too: early bytes not read yet
    // count as input that arrived.
    let (client, mut server) = UnixStream::pair().expect("pair");
    server
        .write_all(b"HTTP/1.1 200 OK\r\n\r\nX")
        .expect("answer");
    let mut tunnel = connect_tunnel(client, "example.com", 443, &wide()).expect("tunnel");
    assert_eq!(tunnel.is_idle().expect("check"), Some(false));
    let mut byte = [0u8; 1];
    tunnel.read_exact(&mut byte).expect("early byte");
    assert_eq!(tunnel.is_idle().expect("check"), Some(true));
    server.write_all(b"Y").expect("unsolicited");
    assert_eq!(tunnel.is_idle().expect("check"), Some(false));
}

/// Reads one head (these requests have no body) from `stream`.
fn read_head(stream: &mut UnixStream) -> Vec<u8> {
    let mut got = Vec::new();
    let mut byte = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).expect("read head"), 1);
        got.push(byte[0]);
    }
    got
}

fn get_root() -> RequestHead {
    RequestHead::new(
        Method::new("GET").expect("method"),
        Target::Origin("/".into()),
    )
}

#[test]
fn client_tunnel_first_request_refuses_early_response() {
    // The proxy answers the CONNECT and, in the same write, a response the
    // origin never sent. The first request over the tunnel must not get it.
    let (client, mut proxy) = UnixStream::pair().expect("pair");
    proxy
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    proxy
        .write_all(b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nEVIL")
        .expect("answer");
    let tunnel = connect_tunnel(client, "origin.example", 80, &wide()).expect("tunnel");
    assert_eq!(tunnel.early().len(), 42);
    read_head(&mut proxy);
    let mut conn = Connection::new(tunnel, "origin.example", wide()).expect("connection");
    assert!(conn.request(&get_root(), RequestBody::None).is_err());
    assert!(!conn.is_reusable());
    proxy.set_nonblocking(true).expect("nonblocking");
    let mut byte = [0u8; 1];
    assert!(
        matches!(proxy.read(&mut byte), Err(e) if e.kind() == io::ErrorKind::WouldBlock),
        "the request was not sent"
    );
}

#[test]
fn client_tunnel_first_request_without_early_bytes() {
    // A quiet tunnel serves its first request and stays reusable.
    let (client, mut proxy) = UnixStream::pair().expect("pair");
    proxy
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    proxy.write_all(b"HTTP/1.1 200 OK\r\n\r\n").expect("answer");
    let tunnel = connect_tunnel(client, "origin.example", 80, &wide()).expect("tunnel");
    assert!(tunnel.early().is_empty());
    read_head(&mut proxy);
    let origin = thread::spawn(move || {
        let request = read_head(&mut proxy);
        proxy
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .expect("response");
        request
    });
    let mut conn = Connection::new(tunnel, "origin.example", wide()).expect("connection");
    let mut response = conn.request(&get_root(), RequestBody::None).expect("first");
    let mut body = Vec::new();
    response.read_to_end(&mut body).expect("body");
    assert_eq!((response.head.status, &body[..]), (200, &b"ok"[..]));
    assert!(conn.is_reusable());
    let request = origin.join().expect("origin");
    assert!(request.starts_with(b"GET / HTTP/1.1\r\nHost: origin.example\r\n"));
}

#[test]
fn client_tunnel_refused() {
    let (stream, _) = MemStream::new(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 64);
    assert!(matches!(
        connect_tunnel(stream, "example.com", 443, &wide()),
        Err(Error::Status(403))
    ));

    // The server side: a handler that refuses answers with its status, and
    // the connection closes (bytes after a refused CONNECT are not a request).
    let input = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n";
    let (stream, output) = MemStream::new(input, 4096);
    let limits = common::server_limits(wide());
    boneli_http::serve_connection(stream, &limits, &|ex: Exchange<'_, MemStream>| {
        // A 2xx without `accept_tunnel` would promise a tunnel.
        ex.respond(403, &Headers::new(), b"")
    })
    .expect("served");
    assert_eq!(common::statuses(&output.borrow()), vec![403]);

    // A 2xx through `respond` is refused before any byte is written; the
    // handler that then returns `Ok` has not answered, so the server sends
    // 500 and closes (ADR-003, item 11).
    let (stream, output) = MemStream::new(input, 4096);
    boneli_http::serve_connection(stream, &limits, &|ex: Exchange<'_, MemStream>| {
        assert!(matches!(
            ex.respond(200, &Headers::new(), b""),
            Err(Error::InvalidInput(_))
        ));
        Ok(())
    })
    .expect("served");
    assert_eq!(common::statuses(&output.borrow()), vec![500]);
    assert!(String::from_utf8_lossy(&output.borrow()).contains("Connection: close"));
}
