//! The TLS client against a local rustls server on 127.0.0.1 (ADR-005):
//! verification, protocol versions, ALPN, truncation, timeouts, trust
//! roots, the idle check of a reused connection, and HTTPS through a
//! CONNECT tunnel of `boneli-http`.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use boneli_http::{
    Connection, Exchange, Headers, IdleCheck, Limits, Method, RequestBody, RequestHead,
    ServerLimits, Target, Transport, connect_tunnel,
};
use boneli_https::{ConnectOptions, Error, Roots, TlsConfig, TlsStream, connect, connect_over};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{CertificateError, ServerConfig, ServerConnection, StreamOwned};

const CA: &[u8] = include_bytes!("data/ca.pem");
const LEAF: &[u8] = include_bytes!("data/leaf.pem");
const LEAF_KEY: &[u8] = include_bytes!("data/leaf.key");
const EXPIRED: &[u8] = include_bytes!("data/expired.pem");
const EXPIRED_KEY: &[u8] = include_bytes!("data/expired.key");
const OTHER_CA: &[u8] = include_bytes!("data/other-ca.pem");
const OTHER_LEAF: &[u8] = include_bytes!("data/other-leaf.pem");
const OTHER_LEAF_KEY: &[u8] = include_bytes!("data/other-leaf.key");

/// Bounds every blocking read in these tests, so that a bug ends in a
/// failure instead of a hang; far above any local delivery time.
const GUARD: Duration = Duration::from_secs(10);

// ------------------------------------------------------------- helpers

/// The test CA as the only root.
fn test_roots() -> Roots {
    let mut roots = Roots::empty();
    assert_eq!(roots.add_pem(CA).expect("test CA"), 1);
    roots
}

fn config(roots: Roots) -> TlsConfig {
    TlsConfig::new(roots).expect("valid config")
}

fn options() -> ConnectOptions {
    ConnectOptions::new(GUARD, GUARD, GUARD).expect("valid options")
}

fn wide() -> Limits {
    Limits::new(16 * 1024, 64, 1024 * 1024).expect("valid limits")
}

fn get_root() -> RequestHead {
    RequestHead::new(
        Method::new("GET").expect("method"),
        Target::Origin("/".into()),
    )
}

/// A server config for `cert` and `key` with the given versions and ALPN.
fn server_config(
    cert: &[u8],
    key: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: bool,
) -> Arc<ServerConfig> {
    let chain = CertificateDer::pem_slice_iter(cert)
        .collect::<Result<Vec<_>, _>>()
        .expect("cert PEM");
    let key = PrivateKeyDer::from_pem_slice(key).expect("key PEM");
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server cert");
    if alpn {
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }
    Arc::new(config)
}

fn default_server() -> Arc<ServerConfig> {
    server_config(
        LEAF,
        LEAF_KEY,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        true,
    )
}

/// The server side of a TLS connection, as a `boneli-http` transport.
struct ServerTls(StreamOwned<ServerConnection, TcpStream>);

impl Read for ServerTls {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for ServerTls {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Transport for ServerTls {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.sock.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.sock.set_write_timeout(timeout)
    }
}

/// Accepts one TCP connection and completes the server handshake. The
/// handshake is done when this returns, so a TLS 1.3 server has written
/// its session tickets.
fn accept_tls(
    listener: &TcpListener,
    config: Arc<ServerConfig>,
) -> io::Result<StreamOwned<ServerConnection, TcpStream>> {
    let (mut tcp, _) = listener.accept()?;
    tcp.set_read_timeout(Some(GUARD))?;
    tcp.set_write_timeout(Some(GUARD))?;
    let mut conn = ServerConnection::new(config).map_err(io::Error::other)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)?;
    }
    Ok(StreamOwned::new(conn, tcp))
}

/// Listens on 127.0.0.1 and runs `serve` on one accepted TLS connection in
/// a thread.
fn tls_server<T: Send + 'static>(
    config: Arc<ServerConfig>,
    serve: impl FnOnce(StreamOwned<ServerConnection, TcpStream>) -> T + Send + 'static,
) -> (SocketAddr, thread::JoinHandle<io::Result<T>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = thread::spawn(move || Ok(serve(accept_tls(&listener, config)?)));
    (addr, handle)
}

/// A `boneli-http` server over TLS that answers every request with `200`
/// and the body `hello`.
fn http_server(config: Arc<ServerConfig>) -> (SocketAddr, thread::JoinHandle<io::Result<()>>) {
    tls_server(config, |stream| {
        let five = Duration::from_secs(5);
        let limits = ServerLimits::new(wide(), 4, five, five, five).expect("server limits");
        // The client may drop the connection without close_notify; that
        // ends the loop with an error the tests do not look at.
        let _ = boneli_http::serve_connection(ServerTls(stream), &limits, &hello);
    })
}

/// Answers every request with `200` and the body `hello`.
fn hello(ex: Exchange<'_, ServerTls>) -> boneli_http::Result<()> {
    ex.respond(200, &Headers::new(), b"hello")
}

/// One GET over `conn`: status and body.
fn get<S: Read + Write + IdleCheck>(conn: &mut Connection<S>) -> (u16, Vec<u8>) {
    let mut response = conn
        .request(&get_root(), RequestBody::None)
        .expect("request");
    let mut body = Vec::new();
    response.read_to_end(&mut body).expect("body");
    (response.head.status, body)
}

/// The certificate error inside a TLS error, or a panic.
fn certificate_error(err: Error) -> CertificateError {
    match err {
        Error::Tls(rustls::Error::InvalidCertificate(e)) => e,
        other => panic!("expected a certificate error, got {other:?}"),
    }
}

/// A stream that counts every read, write and timeout change and has no
/// data.
#[derive(Default)]
struct Untouched {
    calls: Cell<usize>,
}

impl Untouched {
    fn call(&self) {
        self.calls.set(self.calls.get() + 1);
    }
}

impl Read for Untouched {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        self.call();
        Ok(0)
    }
}

impl Write for Untouched {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.call();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.call();
        Ok(())
    }
}

impl Transport for &mut Untouched {
    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        self.call();
        Ok(())
    }

    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        self.call();
        Ok(())
    }
}

/// Reads one plaintext request head (up to the empty line) from `stream`.
fn read_request_head(stream: &mut impl Read) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).expect("request byte"), 1);
        head.push(byte[0]);
    }
    head
}

// ------------------------------------------------------- verification

#[test]
fn get_over_tls_localhost() {
    let (addr, server) = http_server(default_server());
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options())
        .expect("handshake inside connect");
    assert!(tls.protocol_version().is_some(), "handshake completed");
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
    drop(conn);
    server.join().expect("server thread").expect("server");
}

#[test]
fn ip_server_name() {
    let (addr, _server) = http_server(default_server());
    let tls = connect("127.0.0.1", addr.port(), &config(test_roots()), &options())
        .expect("IP SAN matches");
    let mut conn = Connection::new(tls, "127.0.0.1", wide()).expect("connection");
    assert_eq!(get(&mut conn).0, 200);
}

#[test]
fn server_name_case_insensitive() {
    let (addr, _server) = http_server(default_server());
    let tls = connect("LOCALHOST", addr.port(), &config(test_roots()), &options())
        .expect("names compare case-insensitively");
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn).0, 200);
}

#[test]
fn wrong_name_rejected() {
    let (addr, _server) = http_server(default_server());
    let tcp = TcpStream::connect(addr).expect("tcp");
    tcp.set_read_timeout(Some(GUARD)).expect("timeout");
    let err = connect_over(tcp, "other.test", &config(test_roots()), &options())
        .expect_err("a name the certificate does not carry");
    let cert = certificate_error(err);
    assert!(
        matches!(
            cert,
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
        ),
        "{cert:?}"
    );
}

#[test]
fn invalid_server_names_rejected() {
    // Cyrillic `о`, empty, a bracketed address, and numeric forms that
    // `getaddrinfo` would read as IPv4 addresses (ADR-003, item 3).
    for name in [
        "l\u{43e}calhost",
        "",
        "[::1]",
        "2130706433",
        "127.1",
        "0x7f000001",
        "0177.0.0.1",
        "10.1",
    ] {
        let mut stream = Untouched::default();
        let err = connect_over(&mut stream, name, &config(test_roots()), &options())
            .expect_err("invalid name");
        assert!(matches!(err, Error::InvalidServerName), "{name:?}: {err:?}");
        assert_eq!(
            stream.calls.get(),
            0,
            "{name:?}: no I/O before the name check"
        );

        // `connect` refuses before it resolves or dials.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let err = connect(name, port, &config(test_roots()), &options()).expect_err("invalid name");
        assert!(matches!(err, Error::InvalidServerName), "{name:?}: {err:?}");
        assert_eq!(
            listener.accept().err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock),
            "{name:?}: nothing dialed"
        );
    }
}

#[test]
fn untrusted_issuer_rejected() {
    let server = server_config(
        OTHER_LEAF,
        OTHER_LEAF_KEY,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        true,
    );
    let (addr, _server) = http_server(server);
    let err = connect("localhost", addr.port(), &config(test_roots()), &options())
        .expect_err("leaf of an untrusted CA");
    assert_eq!(certificate_error(err), CertificateError::UnknownIssuer);
}

#[test]
fn expired_certificate_rejected() {
    let server = server_config(
        EXPIRED,
        EXPIRED_KEY,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        true,
    );
    let (addr, _server) = http_server(server);
    let err = connect("localhost", addr.port(), &config(test_roots()), &options())
        .expect_err("expired leaf");
    let cert = certificate_error(err);
    assert!(
        matches!(
            cert,
            CertificateError::Expired | CertificateError::ExpiredContext { .. }
        ),
        "{cert:?}"
    );
}

#[test]
fn mozilla_roots_reject_test_ca() {
    let (addr, _server) = http_server(default_server());
    let roots = Roots::mozilla();
    assert!(roots.len() > 100, "webpki-roots ships Mozilla's roots");
    let err = connect("localhost", addr.port(), &config(roots), &options())
        .expect_err("the test CA is not a Mozilla root");
    assert_eq!(certificate_error(err), CertificateError::UnknownIssuer);
}

// ------------------------------------------------- versions and ALPN

#[test]
fn tls12_and_tls13_negotiate() {
    let tls12 = server_config(LEAF, LEAF_KEY, &[&rustls::version::TLS12], true);
    let (addr, _server) = http_server(tls12);
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options()).expect("1.2");
    assert_eq!(
        tls.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn).0, 200);

    let (addr, _server) = http_server(default_server());
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options()).expect("1.3");
    assert_eq!(
        tls.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

#[test]
fn alpn_http11() {
    let (addr, _server) = http_server(default_server());
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
    assert_eq!(tls.alpn_protocol(), Some(&b"http/1.1"[..]));
}

// ------------------------------------------------ closing and timeouts

#[test]
fn close_notify_vs_truncation() {
    for clean in [true, false] {
        let (addr, server) = tls_server(default_server(), move |mut stream| {
            read_request_head(&mut stream);
            // No framing field: the body runs until the stream ends.
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nall of it")
                .expect("response");
            if clean {
                stream.conn.send_close_notify();
            }
            stream.flush().expect("flush");
            stream.sock.shutdown(Shutdown::Both).expect("shutdown");
        });
        let tls =
            connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
        let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
        let mut response = conn
            .request(&get_root(), RequestBody::None)
            .expect("request");
        let mut body = Vec::new();
        let result = response.read_to_end(&mut body);
        if clean {
            result.expect("close_notify ends the body");
            assert_eq!(body, b"all of it");
        } else {
            let err = result.expect_err("a TCP close without close_notify");
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err:?}");
        }
        server.join().expect("server thread").expect("server");
    }
}

#[test]
fn client_close_sends_close_notify() {
    let (addr, server) = tls_server(default_server(), |mut stream| {
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).map(|_| rest)
    });
    let mut tls =
        connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
    tls.close().expect("close_notify");
    let rest = server
        .join()
        .expect("server thread")
        .expect("server")
        .expect("a clean end of the stream, not UnexpectedEof");
    assert!(rest.is_empty());
}

#[test]
fn handshake_timeout() {
    // Accepts and never answers the ClientHello.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let silent = thread::spawn(move || listener.accept().map(|(stream, _)| stream));
    let io_timeout = Duration::from_millis(200);
    let options = ConnectOptions::new(GUARD, GUARD, io_timeout).expect("options");
    let start = Instant::now();
    let err =
        connect("127.0.0.1", port, &config(test_roots()), &options).expect_err("no ServerHello");
    let elapsed = start.elapsed();
    assert!(
        matches!(&err, Error::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)),
        "{err:?}"
    );
    assert!(elapsed >= io_timeout, "{elapsed:?}");
    // 25 times the timeout: room for a loaded CI runner.
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    drop(silent.join().expect("silent thread"));
}

/// A server that reads the ClientHello and then sends its first flight
/// one byte every 150 ms, which would take minutes, until the client goes
/// away.
fn trickle_server() -> (SocketAddr, thread::JoinHandle<io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = thread::spawn(move || -> io::Result<()> {
        let (mut tcp, _) = listener.accept()?;
        tcp.set_read_timeout(Some(GUARD))?;
        let mut conn = ServerConnection::new(default_server()).map_err(io::Error::other)?;
        while !conn.wants_write() {
            conn.read_tls(&mut tcp)?;
            conn.process_new_packets().map_err(io::Error::other)?;
        }
        let mut flight = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut flight)?;
        }
        assert!(flight.len() > 500, "{} bytes", flight.len());
        for byte in flight {
            if tcp.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(150));
        }
        Ok(())
    });
    (addr, handle)
}

/// Runs `handshake` on a thread and asserts that it fails with the
/// handshake deadline's `TimedOut` after `handshake_timeout` and well
/// before the trickle would end.
fn assert_deadline<T: Send + 'static>(
    handshake_timeout: Duration,
    handshake: impl FnOnce() -> Result<T, Error> + Send + 'static,
) {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let start = Instant::now();
        let result = handshake().map(|_| ());
        let _ = tx.send((start.elapsed(), result));
    });
    // 25 times the deadline: room for a loaded CI runner.
    let (elapsed, result) = rx
        .recv_timeout(handshake_timeout * 25)
        .expect("the handshake ended at its deadline");
    let err = result.expect_err("a trickled handshake times out");
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::TimedOut),
        "{err:?}"
    );
    assert!(elapsed >= handshake_timeout, "{elapsed:?}");
}

#[test]
fn handshake_deadline_bounds_trickled_connect() {
    // Review of PR B, finding 3: each byte arrives within `io_timeout`, so
    // only the total deadline ends the handshake.
    let (addr, _server) = trickle_server();
    let handshake_timeout = Duration::from_millis(800);
    let options =
        ConnectOptions::new(GUARD, handshake_timeout, Duration::from_millis(200)).expect("options");
    assert_deadline(handshake_timeout, move || {
        connect("localhost", addr.port(), &config(test_roots()), &options)
    });
}

#[test]
fn handshake_deadline_bounds_trickled_connect_over() {
    let (addr, _server) = trickle_server();
    let handshake_timeout = Duration::from_millis(800);
    let options =
        ConnectOptions::new(GUARD, handshake_timeout, Duration::from_millis(200)).expect("options");
    assert_deadline(handshake_timeout, move || {
        let tcp = TcpStream::connect(addr).map_err(Error::Io)?;
        connect_over(tcp, "localhost", &config(test_roots()), &options)
    });
}

#[test]
fn handshake_deadline_shortens_a_read() {
    // A silent server and an `io_timeout` far beyond the deadline: the
    // read waits only for what is left of the deadline.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let silent = thread::spawn(move || listener.accept().map(|(stream, _)| stream));
    let handshake_timeout = Duration::from_millis(300);
    let options = ConnectOptions::new(GUARD, handshake_timeout, GUARD).expect("options");
    let start = Instant::now();
    let err =
        connect("127.0.0.1", port, &config(test_roots()), &options).expect_err("no ServerHello");
    let elapsed = start.elapsed();
    assert!(
        matches!(&err, Error::Io(e) if e.kind() == io::ErrorKind::TimedOut),
        "{err:?}"
    );
    assert!(elapsed >= handshake_timeout, "{elapsed:?}");
    assert!(elapsed < GUARD / 2, "{elapsed:?}");
    drop(silent.join().expect("silent thread"));
}

#[test]
fn handshake_sets_io_timeout_after_deadline() {
    // During the handshake the timeouts follow the deadline (here below
    // `io_timeout`); afterwards both are `io_timeout`.
    let io_timeout = Duration::from_secs(9);
    let options = ConnectOptions::new(GUARD, Duration::from_secs(8), io_timeout).expect("options");
    let (addr, _server) = http_server(default_server());
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options).expect("tls");
    assert_eq!(
        tls.get_ref().read_timeout().expect("read"),
        Some(io_timeout)
    );
    assert_eq!(
        tls.get_ref().write_timeout().expect("write"),
        Some(io_timeout)
    );

    let (addr, _server) = http_server(default_server());
    let tcp = TcpStream::connect(addr).expect("tcp");
    let tls = connect_over(tcp, "localhost", &config(test_roots()), &options).expect("tls");
    assert_eq!(
        tls.get_ref().read_timeout().expect("read"),
        Some(io_timeout)
    );
    assert_eq!(
        tls.get_ref().write_timeout().expect("write"),
        Some(io_timeout)
    );
}

// ---------------------------------------------------- configuration

#[test]
fn roots_input_forms() {
    let mut roots = test_roots();
    assert_eq!(roots.len(), 1);

    // Empty input, or a file with a key and no certificate.
    for input in [&b""[..], LEAF_KEY, b"not PEM at all\n"] {
        let err = roots.add_pem(input).expect_err("no certificate");
        assert!(matches!(err, Error::NoCertificates), "{err:?}");
        assert_eq!(roots.len(), 1, "store unchanged");
    }

    // A good block followed by a corrupt one: nothing is added.
    let mut corrupt = OTHER_CA.to_vec();
    corrupt.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n");
    let err = roots.add_pem(&corrupt).expect_err("corrupt block");
    assert!(matches!(err, Error::Pem(_)), "{err:?}");
    assert_eq!(roots.len(), 1, "store unchanged");

    // A block whose DER is not a certificate: nothing is added.
    let mut bad_der = OTHER_CA.to_vec();
    bad_der.extend_from_slice(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    let err = roots.add_pem(&bad_der).expect_err("not a certificate");
    assert!(matches!(err, Error::Tls(_)), "{err:?}");
    assert_eq!(roots.len(), 1, "store unchanged");

    // DER that is not a certificate.
    let err = roots
        .add_der(b"\x30\x03\x02\x01\x01")
        .expect_err("not a certificate");
    assert!(matches!(err, Error::Tls(_)), "{err:?}");
    assert_eq!(roots.len(), 1);

    // Two good blocks at once, and DER.
    let mut two = OTHER_CA.to_vec();
    two.extend_from_slice(CA);
    assert_eq!(roots.add_pem(&two).expect("two certificates"), 2);
    assert_eq!(roots.len(), 3);
    let der = CertificateDer::from_pem_slice(OTHER_CA).expect("DER");
    roots.add_der(&der).expect("DER certificate");
    assert_eq!(roots.len(), 4);
}

#[test]
fn empty_roots_rejected() {
    // An empty store refuses every server: a configuration mistake.
    let err = TlsConfig::new(Roots::empty()).expect_err("empty roots");
    assert!(matches!(err, Error::NoCertificates), "{err:?}");
}

#[test]
fn zero_options_rejected() {
    let one = Duration::from_secs(1);
    let zero = Duration::ZERO;
    for (connect_timeout, handshake_timeout, io_timeout) in
        [(zero, one, one), (one, zero, one), (one, one, zero)]
    {
        let err = ConnectOptions::new(connect_timeout, handshake_timeout, io_timeout)
            .expect_err("zero timeout");
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    }
    let err = connect("localhost", 0, &config(test_roots()), &options()).expect_err("port zero");
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
}

// ------------------------------------------------- idle check (ADR-003)

#[test]
fn tls_connection_is_reused() {
    let (addr, _server) = http_server(default_server());
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    for _ in 0..3 {
        assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
        assert!(conn.is_reusable());
    }
}

#[test]
fn session_tickets_do_not_fail_first_request() {
    // A TLS 1.3 server sends session tickets after the handshake. They are
    // TLS records without application data, so the stream is still idle.
    let (ready_tx, ready_rx) = mpsc::channel();
    let (addr, server) = tls_server(default_server(), move |stream| {
        // `accept_tls` returned, so the tickets are on the wire.
        ready_tx.send(()).expect("signal");
        let five = Duration::from_secs(5);
        let limits = ServerLimits::new(wide(), 4, five, five, five).expect("server limits");
        let _ = boneli_http::serve_connection(ServerTls(stream), &limits, &hello);
    });
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
    assert_eq!(
        tls.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    ready_rx.recv_timeout(GUARD).expect("server ready");
    // Give the tickets time to reach the client's socket buffer.
    thread::sleep(Duration::from_millis(50));
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
    drop(conn);
    server.join().expect("server thread").expect("server");
}

#[test]
fn tls_idle_check_states() {
    // step 1: nothing but tickets arrived; step 2: two records of
    // application data arrived and the client reads only part of them;
    // step 3: close_notify arrived.
    let (to_server, from_client) = mpsc::channel::<u8>();
    let (to_client, from_server) = mpsc::channel::<u8>();
    let (addr, server) = tls_server(default_server(), move |mut stream| -> io::Result<()> {
        to_client.send(1).map_err(io::Error::other)?;
        from_client.recv().map_err(io::Error::other)?;
        // Two writes, two records.
        stream.write_all(b"abc")?;
        stream.flush()?;
        stream.write_all(b"EVIL")?;
        stream.flush()?;
        to_client.send(2).map_err(io::Error::other)?;
        from_client.recv().map_err(io::Error::other)?;
        stream.conn.send_close_notify();
        stream.flush()?;
        to_client.send(3).map_err(io::Error::other)?;
        from_client.recv().map_err(io::Error::other)?;
        Ok(())
    });
    let mut tls =
        connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");

    assert_eq!(from_server.recv_timeout(GUARD).expect("step 1"), 1);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(tls.is_idle().expect("check"), Some(true), "tickets only");
    assert_eq!(tls.is_idle().expect("check"), Some(true), "still idle");

    to_server.send(0).expect("go");
    assert_eq!(from_server.recv_timeout(GUARD).expect("step 2"), 2);
    thread::sleep(Duration::from_millis(50));
    let mut three = [0u8; 3];
    tls.read_exact(&mut three).expect("first record");
    assert_eq!(&three, b"abc");
    assert_eq!(
        tls.is_idle().expect("check"),
        Some(false),
        "plaintext that rustls holds is input that arrived"
    );
    let mut four = [0u8; 4];
    tls.read_exact(&mut four).expect("second record");
    assert_eq!(&four, b"EVIL");
    assert_eq!(tls.is_idle().expect("check"), Some(true), "all read");

    to_server.send(0).expect("go");
    assert_eq!(from_server.recv_timeout(GUARD).expect("step 3"), 3);
    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        tls.is_idle().expect("check"),
        Some(false),
        "close_notify is the end of the stream"
    );
    to_server.send(0).expect("done");
    server
        .join()
        .expect("server thread")
        .expect("server")
        .expect("served");
}

#[test]
fn unsolicited_response_inside_tls_fails_next_request() {
    let (to_server, from_client) = mpsc::channel::<()>();
    let (to_client, from_server) = mpsc::channel::<()>();
    let (addr, server) = tls_server(default_server(), move |mut stream| -> io::Result<Vec<u8>> {
        read_request_head(&mut stream);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
        stream.flush()?;
        from_client.recv().map_err(io::Error::other)?;
        // An answer to a request the client has not sent.
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nEVIL")?;
        stream.flush()?;
        to_client.send(()).map_err(io::Error::other)?;
        // Whatever the client sends from here on.
        let mut rest = Vec::new();
        match stream.read_to_end(&mut rest) {
            Ok(_) => Ok(rest),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(rest),
            Err(e) => Err(e),
        }
    });
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"ok".to_vec()));
    assert!(conn.is_reusable());
    to_server.send(()).expect("go");
    from_server
        .recv_timeout(GUARD)
        .expect("unsolicited response sent");
    thread::sleep(Duration::from_millis(50));

    let err = conn
        .request(&get_root(), RequestBody::None)
        .map(|response| response.head.status)
        .expect_err("the stream had input before the request");
    assert!(matches!(err, boneli_http::Error::Malformed(_)), "{err:?}");
    assert!(!conn.is_reusable());
    drop(conn);
    let rest = server
        .join()
        .expect("server thread")
        .expect("server")
        .expect("read");
    assert!(
        rest.is_empty(),
        "nothing written after the unsolicited response: {:?}",
        String::from_utf8_lossy(&rest)
    );
}

#[test]
fn peer_close_while_idle_fails_next_request() {
    let (to_server, from_client) = mpsc::channel::<()>();
    let (to_client, from_server) = mpsc::channel::<()>();
    let (addr, _server) = tls_server(default_server(), move |mut stream| -> io::Result<()> {
        read_request_head(&mut stream);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
        stream.flush()?;
        from_client.recv().map_err(io::Error::other)?;
        stream.conn.send_close_notify();
        stream.flush()?;
        to_client.send(()).map_err(io::Error::other)?;
        Ok(())
    });
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"ok".to_vec()));
    to_server.send(()).expect("go");
    from_server.recv_timeout(GUARD).expect("closed");
    thread::sleep(Duration::from_millis(50));
    let err = conn
        .request(&get_root(), RequestBody::None)
        .map(|response| response.head.status)
        .expect_err("the peer closed");
    assert!(matches!(err, boneli_http::Error::Malformed(_)), "{err:?}");
}

/// Encrypts `plaintext` on the server as TLS records, without sending
/// them: the bytes go to the caller, who decides what reaches the wire.
fn encrypt(stream: &mut StreamOwned<ServerConnection, TcpStream>, plaintext: &[u8]) -> Vec<u8> {
    stream
        .conn
        .writer()
        .write_all(plaintext)
        .expect("plaintext");
    let mut raw = Vec::new();
    while stream.conn.wants_write() {
        stream.conn.write_tls(&mut raw).expect("records");
    }
    raw
}

/// What the client sent until it went away; the client drops connections
/// without `close_notify`.
fn read_rest(stream: &mut StreamOwned<ServerConnection, TcpStream>) -> io::Result<Vec<u8>> {
    let mut rest = Vec::new();
    match stream.read_to_end(&mut rest) {
        Ok(_) => Ok(rest),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(rest),
        Err(e) => Err(e),
    }
}

#[test]
fn partial_record_while_idle_is_not_idle() {
    // Review of PR B, finding 1: all but the last byte of an application
    // data record have arrived. rustls has no complete record and so no
    // plaintext, but the bytes are input that arrived.
    let (to_server, from_client) = mpsc::channel::<()>();
    let (to_client, from_server) = mpsc::channel::<()>();
    let (addr, server) = tls_server(default_server(), move |mut stream| -> io::Result<()> {
        let raw = encrypt(
            &mut stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nEVIL",
        );
        stream.sock.write_all(&raw[..raw.len() - 1])?;
        to_client.send(()).map_err(io::Error::other)?;
        from_client.recv().map_err(io::Error::other)?;
        Ok(())
    });
    let mut tls =
        connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
    from_server
        .recv_timeout(GUARD)
        .expect("partial record sent");
    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        tls.is_idle().expect("check"),
        Some(false),
        "a record that has partly arrived is input"
    );
    assert_eq!(tls.is_idle().expect("check"), Some(false), "still partial");
    to_server.send(()).expect("done");
    server
        .join()
        .expect("server thread")
        .expect("server")
        .expect("served");
}

#[test]
fn partial_unsolicited_response_fails_next_request() {
    // Review of PR B, finding 1: only the first 20 bytes of an unsolicited
    // response's record arrive before the next request. Sending the
    // request would make the rest of that record its answer.
    let (to_server, from_client) = mpsc::channel::<()>();
    let (to_client, from_server) = mpsc::channel::<()>();
    let (addr, server) = tls_server(default_server(), move |mut stream| -> io::Result<Vec<u8>> {
        read_request_head(&mut stream);
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
        stream.flush()?;
        from_client.recv().map_err(io::Error::other)?;
        let raw = encrypt(
            &mut stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nEVIL",
        );
        stream.sock.write_all(&raw[..20])?;
        to_client.send(()).map_err(io::Error::other)?;
        read_rest(&mut stream)
    });
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"ok".to_vec()));
    to_server.send(()).expect("go");
    from_server
        .recv_timeout(GUARD)
        .expect("partial record sent");
    thread::sleep(Duration::from_millis(50));

    let err = conn
        .request(&get_root(), RequestBody::None)
        .map(|response| response.head.status)
        .expect_err("part of a record had arrived before the request");
    assert!(matches!(err, boneli_http::Error::Malformed(_)), "{err:?}");
    assert!(!conn.is_reusable());
    drop(conn);
    let rest = server
        .join()
        .expect("server thread")
        .expect("server")
        .expect("read");
    assert!(
        rest.is_empty(),
        "no request sent: {:?}",
        String::from_utf8_lossy(&rest)
    );
}

#[test]
fn partial_record_after_response_fails_next_request() {
    // Review of PR B, finding 1: the head of an unsolicited record arrives
    // in the same segment as the end of a response, so rustls takes it in
    // while the client reads that response, before any idle check.
    let (addr, server) = tls_server(default_server(), move |mut stream| -> io::Result<Vec<u8>> {
        read_request_head(&mut stream);
        let mut raw = encrypt(
            &mut stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        );
        let evil = encrypt(
            &mut stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nEVIL",
        );
        raw.extend_from_slice(&evil[..20]);
        stream.sock.write_all(&raw)?;
        read_rest(&mut stream)
    });
    let tls = connect("localhost", addr.port(), &config(test_roots()), &options()).expect("tls");
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"ok".to_vec()));
    thread::sleep(Duration::from_millis(50));

    let err = conn
        .request(&get_root(), RequestBody::None)
        .map(|response| response.head.status)
        .expect_err("part of a record had arrived before the request");
    assert!(matches!(err, boneli_http::Error::Malformed(_)), "{err:?}");
    drop(conn);
    let rest = server
        .join()
        .expect("server thread")
        .expect("server")
        .expect("read");
    assert!(
        rest.is_empty(),
        "no request sent: {:?}",
        String::from_utf8_lossy(&rest)
    );
}

#[test]
fn session_ticket_split_across_reads_stays_idle() {
    // The TLS 1.3 session tickets reach the client in three pieces: the
    // first ends inside a record header, the second inside a record body.
    // While a ticket record is incomplete the check fails closed; once it
    // is complete the connection is idle again and serves a request.
    let (to_server, from_client) = mpsc::channel::<()>();
    let (to_client, from_server) = mpsc::channel::<()>();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut tcp, _) = listener.accept()?;
        tcp.set_read_timeout(Some(GUARD))?;
        tcp.set_write_timeout(Some(GUARD))?;
        let mut conn = ServerConnection::new(default_server()).map_err(io::Error::other)?;
        while conn.is_handshaking() {
            if conn.wants_write() {
                conn.write_tls(&mut tcp)?;
            } else {
                conn.read_tls(&mut tcp)?;
                conn.process_new_packets().map_err(io::Error::other)?;
            }
        }
        // The handshake is over and the tickets are still queued.
        let mut tickets = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut tickets)?;
        }
        assert!(tickets.len() > 5, "a TLS 1.3 server sends tickets");
        let body_split = 5
            + (tickets.len() - 5).min(usize::from(u16::from_be_bytes([tickets[3], tickets[4]])))
                / 2;
        for piece in [
            &tickets[..3],
            &tickets[3..body_split],
            &tickets[body_split..],
        ] {
            tcp.write_all(piece)?;
            to_client.send(()).map_err(io::Error::other)?;
            from_client.recv().map_err(io::Error::other)?;
        }
        let five = Duration::from_secs(5);
        let limits = ServerLimits::new(wide(), 4, five, five, five).expect("server limits");
        let _ =
            boneli_http::serve_connection(ServerTls(StreamOwned::new(conn, tcp)), &limits, &hello);
        Ok(())
    });
    let mut tls = connect("localhost", port, &config(test_roots()), &options()).expect("tls");
    assert_eq!(
        tls.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    for (piece, idle) in [("header", false), ("body", false), ("rest", true)] {
        from_server.recv_timeout(GUARD).expect(piece);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(tls.is_idle().expect("check"), Some(idle), "after {piece}");
        to_server.send(()).expect("next");
    }
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
    drop(conn);
    server.join().expect("server thread").expect("server");
}

// --------------------------------------------------- CONNECT tunnels

/// Copies `from` into `to` until the end of the stream, then shuts down
/// `to` for writing so that the far side sees the end too.
fn relay(mut from: impl Read, mut to: impl Write, shutdown: impl FnOnce() -> io::Result<()>) {
    let _ = io::copy(&mut from, &mut to);
    let _ = shutdown();
}

#[test]
fn https_through_connect_tunnel() {
    let (tls_addr, _server) = http_server(default_server());
    let (client_side, proxy_side) = UnixStream::pair().expect("pair");
    client_side.set_read_timeout(Some(GUARD)).expect("timeout");
    let five = Duration::from_secs(5);
    let limits = ServerLimits::new(wide(), 4, five, five, five).expect("server limits");
    let proxy = thread::spawn(move || {
        boneli_http::serve_connection(proxy_side, &limits, &|ex: Exchange<'_, UnixStream>| {
            let port = match &ex.head().target {
                Target::Authority { host, port } if host == "localhost" => *port,
                _ => return Err(boneli_http::Error::Status(403)),
            };
            let upstream = TcpStream::connect(("127.0.0.1", port))?;
            let tunnel = ex.accept_tunnel()?;
            let (early, stream) = tunnel.into_parts();
            let down_read = upstream.try_clone()?;
            let down_write = stream.try_clone()?;
            let up_read = stream.try_clone()?;
            let up_shutdown = upstream.try_clone()?;
            thread::scope(|scope| {
                scope.spawn(move || {
                    relay(early.as_slice().chain(up_read), &upstream, || {
                        up_shutdown.shutdown(Shutdown::Write)
                    })
                });
                let back = down_write.try_clone();
                relay(down_read, &down_write, move || {
                    back.and_then(|s| s.shutdown(Shutdown::Write))
                });
            });
            Ok(())
        })
    });

    let tunnel =
        connect_tunnel(client_side, "localhost", tls_addr.port(), &wide()).expect("tunnel");
    let tls = connect_over(tunnel, "localhost", &config(test_roots()), &options())
        .expect("TLS over the tunnel");
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
    assert_eq!(
        get(&mut conn),
        (200, b"hello".to_vec()),
        "reused through the tunnel"
    );
    drop(conn);
    proxy.join().expect("proxy thread").expect("proxy");
}

/// `TlsStream` is a `boneli-http` transport when its stream is one.
#[test]
fn tls_stream_is_a_transport() {
    fn assert_transport<T: Transport>() {}
    assert_transport::<TlsStream<TcpStream>>();
    assert_transport::<TlsStream<UnixStream>>();
}
