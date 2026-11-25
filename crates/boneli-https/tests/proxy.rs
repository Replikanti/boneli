//! The proxy route (ADR-039): `TlsDial` and the revocation fetches of a
//! `TlsConfig::with_proxy` configuration against a fake HTTP proxy on
//! 127.0.0.1 that records every request head it receives, tunnels
//! `CONNECT` to local rustls servers that record what they receive, and
//! answers absolute-form `GET`s from a table. The CRL and OCSP points of
//! the test leaves are under `boneli.test`, a name that never resolves, so
//! a fetch that bypassed the proxy would fail.

mod common;

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use boneli_https::{
    BasicCredentials, ConnectOptions, CrlFetchError, CrlSource, CrlUrl, Dial, Error,
    PROXY_MAX_HEAD_BYTES, PROXY_MAX_HEADERS, Proxy, Resolver, ResolverConfig,
    RevocationFailureKind, RevocationStatus, Roots, Stream, Timed, TlsConfig, TlsDial, connect,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

const CA: &[u8] = include_bytes!("data/ca.pem");
const LEAF: &[u8] = include_bytes!("data/leaf.pem");
const LEAF_KEY: &[u8] = include_bytes!("data/leaf.key");
const OTHER_LEAF: &[u8] = include_bytes!("data/other-leaf.pem");
const OTHER_LEAF_KEY: &[u8] = include_bytes!("data/other-leaf.key");
const CRL_CA: &[u8] = include_bytes!("data/crl-ca.pem");
const CRL_LEAF_KEY: &[u8] = include_bytes!("data/crl-leaf.key");
const CRL_GOOD: &[u8] = include_bytes!("data/crl-good.pem");
const CRL_FRESH: &[u8] = include_bytes!("data/crl-ca-fresh.crl");
const OCSP_CA: &[u8] = include_bytes!("data/ocsp-ca.pem");
const OCSP_GOOD: &[u8] = include_bytes!("data/ocsp-good.pem");
const OCSP_GOOD_RESP: &[u8] = include_bytes!("data/ocsp-good.resp");
const CHAIN_ROOT: &[u8] = include_bytes!("data/chain-root.pem");
const CHAIN_CA1: &[u8] = include_bytes!("data/chain-ca1.pem");
const CHAIN_LEAF_NONE: &[u8] = include_bytes!("data/chain-leaf-none-ca1.pem");
const CHAIN_ROOT_EMPTY: &[u8] = include_bytes!("data/chain-root-empty.crl");

const CRL_URL: &str = "http://crl.boneli.test/ca.crl";
const OCSP_URL: &str = "http://ocsp.boneli.test/";
const ROOT_CRL_URL: &str = "http://crl1.boneli.test/root.crl";

/// A distinctive 24-character username and 40-character password, so a
/// scan for them cannot match by chance.
const USER: &str = "pRx-u5Er9q8RzT3vW1xY7kLm";
const PASS: &str = "pRx-pA55w0rD9xK2mN7qR4tV6yZ8bC1dF3gH5jL7";

/// Bounds every blocking call of the fakes, so that a bug ends in a
/// failure instead of a hang; far above any local delivery time.
const GUARD: Duration = Duration::from_secs(10);

// ------------------------------------------------------------- servers

fn server_config(chain_pem: &[&[u8]], key: &[u8]) -> Arc<ServerConfig> {
    let chain = chain_pem
        .iter()
        .flat_map(|pem| CertificateDer::pem_slice_iter(pem))
        .collect::<Result<Vec<_>, _>>()
        .expect("cert PEM");
    let key = PrivateKeyDer::from_pem_slice(key).expect("key PEM");
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server cert");
    config.send_tls13_tickets = 0;
    Arc::new(config)
}

/// Reads a head through its empty line, at most 64 KiB.
fn read_head(stream: &mut impl Read) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 65_536 {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    head
}

/// A TLS origin on 127.0.0.1: for every connection it completes the
/// handshake, records the request head it receives and answers
/// `200 hello`. A failed handshake records nothing.
struct Origin {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Origin {
    fn start(config: Arc<ServerConfig>) -> Origin {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&heads);
        thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { continue };
                let config = Arc::clone(&config);
                let record = Arc::clone(&record);
                thread::spawn(move || serve_tls(tcp, config, &record));
            }
        });
        Origin { addr, heads }
    }

    fn trusted() -> Origin {
        Origin::start(server_config(&[LEAF], LEAF_KEY))
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("heads").clone()
    }
}

/// One TLS connection: handshake, the request head recorded, `200 hello`.
fn serve_tls(tcp: TcpStream, config: Arc<ServerConfig>, record: &Mutex<Vec<String>>) {
    let _ = tcp.set_read_timeout(Some(GUARD));
    let _ = tcp.set_write_timeout(Some(GUARD));
    let Ok(conn) = ServerConnection::new(config) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, tcp);
    let head = read_head(&mut tls);
    if head.is_empty() {
        return;
    }
    record
        .lock()
        .expect("record")
        .push(String::from_utf8_lossy(&head).into_owned());
    let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// What the fake proxy does with a `CONNECT`.
#[derive(Clone)]
enum OnConnect {
    /// `200`, then relays bytes to and from this address.
    Tunnel(SocketAddr),
    /// `200`, then serves TLS itself with this configuration.
    Terminate(Arc<ServerConfig>),
    /// These bytes, then close.
    Answer(Vec<u8>),
    /// Never answers; holds the connection until the client closes it.
    Silent,
}

/// A fake HTTP proxy on 127.0.0.1. Every connection counts and every
/// request head is recorded; `CONNECT` goes as `on_connect` says, and an
/// absolute-form `GET` gets the answer of the first entry of `gets` whose
/// prefix its target starts with, or `502`. A proxy started with
/// `requiring` answers `407` to any request without that
/// `Proxy-Authorization` value, as an authenticating proxy does.
struct FakeProxy {
    addr: SocketAddr,
    heads: Arc<Mutex<Vec<String>>>,
    connections: Arc<AtomicUsize>,
}

impl FakeProxy {
    fn start(on_connect: OnConnect, gets: Vec<(String, Vec<u8>)>) -> FakeProxy {
        FakeProxy::requiring(on_connect, gets, None)
    }

    fn requiring(
        on_connect: OnConnect,
        gets: Vec<(String, Vec<u8>)>,
        auth: Option<String>,
    ) -> FakeProxy {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (record, count) = (Arc::clone(&heads), Arc::clone(&connections));
        let gets = Arc::new(gets);
        let auth = Arc::new(auth);
        thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { continue };
                count.fetch_add(1, Ordering::SeqCst);
                let (record, on_connect, gets, auth) = (
                    Arc::clone(&record),
                    on_connect.clone(),
                    Arc::clone(&gets),
                    Arc::clone(&auth),
                );
                thread::spawn(move || {
                    proxy_connection(tcp, &record, &on_connect, &gets, auth.as_deref())
                });
            }
        });
        FakeProxy {
            addr,
            heads,
            connections,
        }
    }

    fn proxy(&self) -> Proxy {
        Proxy::new("127.0.0.1", self.addr.port()).expect("proxy")
    }

    fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("heads").clone()
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// The request lines received, in order.
    fn lines(&self) -> Vec<String> {
        self.heads()
            .iter()
            .map(|h| h.split("\r\n").next().unwrap_or_default().to_owned())
            .collect()
    }
}

fn proxy_connection(
    mut client: TcpStream,
    record: &Mutex<Vec<String>>,
    on_connect: &OnConnect,
    gets: &[(String, Vec<u8>)],
    auth: Option<&str>,
) {
    let _ = client.set_read_timeout(Some(GUARD));
    let _ = client.set_write_timeout(Some(GUARD));
    let head = String::from_utf8_lossy(&read_head(&mut client)).into_owned();
    record.lock().expect("record").push(head.clone());
    if let Some(auth) = auth
        && !head.contains(&format!("\r\nProxy-Authorization: {auth}\r\n"))
    {
        let _ = client.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n",
        );
        return;
    }
    if head.starts_with("CONNECT ") {
        match on_connect {
            OnConnect::Tunnel(origin) => {
                let Ok(upstream) = TcpStream::connect(origin) else {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                    return;
                };
                let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                relay(client, upstream);
            }
            OnConnect::Terminate(config) => {
                let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                serve_tls(client, Arc::clone(config), record);
            }
            OnConnect::Answer(bytes) => {
                let _ = client.write_all(bytes);
            }
            OnConnect::Silent => {
                let mut sink = [0u8; 1];
                let _ = client.set_read_timeout(Some(GUARD));
                let _ = client.read(&mut sink);
            }
        }
        return;
    }
    let target = head.split(' ').nth(1).unwrap_or_default();
    let answer = gets
        .iter()
        .find(|(prefix, _)| target.starts_with(prefix.as_str()))
        .map_or_else(
            || b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_vec(),
            |(_, answer)| answer.clone(),
        );
    let _ = client.write_all(&answer);
}

/// Copies both ways until either side ends.
fn relay(client: TcpStream, upstream: TcpStream) {
    let (Ok(mut client_read), Ok(mut upstream_read)) = (client.try_clone(), upstream.try_clone())
    else {
        return;
    };
    let (mut client_write, mut upstream_write) = (client, upstream);
    let up = thread::spawn(move || {
        let _ = io::copy(&mut client_read, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut upstream_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = up.join();
}

fn ok_with(body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

// ------------------------------------------------------------- clients

fn roots(pem: &[u8]) -> Roots {
    let mut roots = Roots::empty();
    roots.add_pem(pem).expect("test CA");
    roots
}

fn options() -> ConnectOptions {
    ConnectOptions::new(GUARD, GUARD, GUARD).expect("options")
}

/// A resolver whose only names are the `hosts` entries and whose one name
/// server never answers, so any other name fails at the deadline.
fn hosts_resolver(hosts: &str) -> (Resolver, common::Stalled) {
    let stalled = common::Stalled::start();
    let config = ResolverConfig::new(vec![stalled.addr()], Duration::from_millis(200), 1)
        .expect("config")
        .with_hosts(hosts.to_owned());
    (Resolver::fixed(config), stalled)
}

fn dial(config: TlsConfig) -> TlsDial {
    TlsDial::new(config, options())
}

/// Sends `GET /` over a dialed stream and returns the body.
fn get_root(stream: Box<dyn Stream>) -> Vec<u8> {
    let limits = boneli_http::Limits::new(16_384, 64, 1_024).expect("limits");
    let stream = Timed::new(stream, Instant::now() + GUARD, GUARD);
    let mut conn = boneli_http::Connection::new(stream, "localhost", limits).expect("connection");
    let head = boneli_http::RequestHead::new(
        boneli_http::Method::new("GET").expect("method"),
        boneli_http::Target::Origin("/".into()),
    );
    let mut response = conn
        .request(&head, boneli_http::RequestBody::None)
        .expect("request");
    let mut body = Vec::new();
    response.read_to_end(&mut body).expect("body");
    body
}

/// The `boneli_https::Error` inside a dial error.
fn inner(err: &io::Error) -> &Error {
    err.get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .unwrap_or_else(|| panic!("not the TLS client's error: {err:?}"))
}

fn dial_err(dial: &TlsDial, host: &str, port: u16, deadline: Instant) -> io::Error {
    match dial.dial(host, port, deadline) {
        Ok(_) => panic!("{host}:{port} dialed"),
        Err(e) => e,
    }
}

/// Every 16-byte window of `secret`, or `secret` itself when shorter.
fn windows(secret: &str) -> Vec<String> {
    let bytes = secret.as_bytes();
    if bytes.len() <= 16 {
        return vec![secret.to_owned()];
    }
    bytes
        .windows(16)
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .collect()
}

fn credentials() -> BasicCredentials {
    BasicCredentials::new(USER, PASS).expect("credentials")
}

/// `base64(USER:PASS)`, the secret on the wire.
fn encoded() -> String {
    credentials()
        .header_value()
        .strip_prefix("Basic ")
        .expect("scheme")
        .to_owned()
}

fn assert_no_secret(text: &str) {
    let encoded = encoded();
    for secret in [USER, PASS, encoded.as_str()] {
        for window in windows(secret) {
            assert!(!text.contains(&window), "{window:?} in {text:?}");
        }
    }
}

// ------------------------------------------------------------- the dial

/// The trusted leaf behind the proxy: one `CONNECT localhost:<port>` with
/// `Host` only, then TLS end to end and the request inside the tunnel.
#[test]
fn trusted_leaf_through_the_proxy() {
    let origin = Origin::trusted();
    let proxy = FakeProxy::start(OnConnect::Tunnel(origin.addr), vec![]);
    let config = TlsConfig::new(roots(CA))
        .expect("config")
        .with_proxy(proxy.proxy());
    let port = origin.addr.port();
    let stream = dial(config)
        .dial("localhost", port, Instant::now() + GUARD)
        .expect("dial");
    assert_eq!(get_root(stream), b"hello");
    assert_eq!(
        proxy.heads(),
        [format!(
            "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
        )]
    );
    let heads = origin.heads();
    assert_eq!(heads.len(), 1);
    assert!(heads[0].starts_with("GET / HTTP/1.1\r\nHost: localhost\r\n"));
}

/// A target outside ADR-003's grammar is refused before the proxy is
/// dialed: the proxy sees no connection.
#[test]
fn invalid_target_refused_before_the_proxy() {
    let proxy = FakeProxy::start(OnConnect::Silent, vec![]);
    let config = TlsConfig::new(roots(CA))
        .expect("config")
        .with_proxy(proxy.proxy());
    let dial = dial(config);
    for (host, port) in [
        ("127.1", 443u16),
        ("LOCALHOST", 443),
        ("0x7f000001", 443),
        ("a_b.example", 443),
        ("[::1]", 443),
        ("localhost", 0),
    ] {
        let err = dial_err(&dial, host, port, Instant::now() + GUARD);
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{host}: {err:?}");
    }
    thread::sleep(Duration::from_millis(100));
    assert_eq!(proxy.connections(), 0);
}

/// The target's name is never resolved locally: only the proxy's name is
/// in the resolver, the proxy sees `CONNECT registry.boneli.test:443`, and
/// the dial fails on the certificate's name, not on resolution.
#[test]
fn target_never_resolved_locally() {
    let origin = Origin::trusted();
    let proxy = FakeProxy::start(OnConnect::Tunnel(origin.addr), vec![]);
    let (resolver, stalled) = hosts_resolver("127.0.0.1 proxy.boneli.test\n");
    let config = TlsConfig::new(roots(CA))
        .expect("config")
        .with_resolver(resolver)
        .with_proxy(Proxy::new("proxy.boneli.test", proxy.addr.port()).expect("proxy"));
    let err = dial_err(
        &dial(config),
        "registry.boneli.test",
        443,
        Instant::now() + GUARD,
    );
    assert!(
        matches!(
            inner(&err),
            Error::Tls(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                    | rustls::CertificateError::NotValidForNameContext { .. }
            ))
        ),
        "{err:?}"
    );
    assert_eq!(proxy.lines(), ["CONNECT registry.boneli.test:443 HTTP/1.1"]);
    assert_eq!(stalled.take(), 0, "a name server was asked");
}

/// The proxy's addresses are tried in turn: 127.0.0.2 refuses the
/// connection, 127.0.0.1 is the proxy.
#[test]
fn proxy_addresses_tried_in_turn() {
    let origin = Origin::trusted();
    let proxy = FakeProxy::start(OnConnect::Tunnel(origin.addr), vec![]);
    let (resolver, _stalled) =
        hosts_resolver("127.0.0.2 proxy.boneli.test\n127.0.0.1 proxy.boneli.test\n");
    let config = TlsConfig::new(roots(CA))
        .expect("config")
        .with_proxy(Proxy::new("proxy.boneli.test", proxy.addr.port()).expect("proxy"))
        .with_resolver(resolver);
    let stream = dial(config)
        .dial("localhost", origin.addr.port(), Instant::now() + GUARD)
        .expect("dial through the second address");
    assert_eq!(get_root(stream), b"hello");
    assert_eq!(proxy.connections(), 1);
}

/// A certificate the runner does not trust is refused behind the proxy,
/// from an origin behind a tunnel and from a proxy that terminates TLS
/// itself; the origin records no request.
#[test]
fn untrusted_certificate_refused_behind_the_proxy() {
    let other = || server_config(&[OTHER_LEAF], OTHER_LEAF_KEY);
    let origin = Origin::start(other());
    for on_connect in [
        OnConnect::Tunnel(origin.addr),
        OnConnect::Terminate(other()),
    ] {
        let proxy = FakeProxy::start(on_connect, vec![]);
        let config = TlsConfig::new(roots(CA))
            .expect("config")
            .with_proxy(proxy.proxy());
        let err = dial_err(
            &dial(config),
            "localhost",
            origin.addr.port(),
            Instant::now() + GUARD,
        );
        assert!(
            matches!(
                inner(&err),
                Error::Tls(rustls::Error::InvalidCertificate(_))
            ),
            "{err:?}"
        );
        // Only the CONNECT head: the terminating proxy recorded no request.
        thread::sleep(Duration::from_millis(100));
        assert_eq!(proxy.heads().len(), 1, "{:?}", proxy.heads());
    }
    thread::sleep(Duration::from_millis(100));
    assert!(origin.heads().is_empty(), "{:?}", origin.heads());
}

/// `Proxy-Authorization` is on the `CONNECT` and nowhere inside the
/// tunnel; the origin never sees the proxy's base64.
#[test]
fn proxy_credentials_only_on_connect() {
    let origin = Origin::trusted();
    let proxy = FakeProxy::start(OnConnect::Tunnel(origin.addr), vec![]);
    let config = TlsConfig::new(roots(CA))
        .expect("config")
        .with_proxy(proxy.proxy().with_credentials(credentials()));
    let port = origin.addr.port();
    let stream = dial(config)
        .dial("localhost", port, Instant::now() + GUARD)
        .expect("dial");
    assert_eq!(get_root(stream), b"hello");
    assert_eq!(
        proxy.heads(),
        [format!(
            "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\
Proxy-Authorization: Basic {}\r\n\r\n",
            encoded()
        )]
    );
    let heads = origin.heads();
    assert_eq!(heads.len(), 1);
    assert!(
        !heads[0].to_ascii_lowercase().contains("authorization"),
        "{heads:?}"
    );
    assert_no_secret(&heads[0]);
}

/// Without credentials no `Proxy-Authorization` is sent, on `CONNECT` or
/// on a proxied `GET`.
#[test]
fn no_proxy_credentials_without_configuration() {
    let origin = Origin::start(server_config(&[CRL_GOOD], CRL_LEAF_KEY));
    let proxy = FakeProxy::start(
        OnConnect::Tunnel(origin.addr),
        vec![(CRL_URL.into(), ok_with(CRL_FRESH))],
    );
    let config = TlsConfig::new(roots(CRL_CA))
        .expect("config")
        .with_proxy(proxy.proxy());
    let stream = dial(config)
        .dial("localhost", origin.addr.port(), Instant::now() + GUARD)
        .expect("dial");
    drop(stream);
    let heads = proxy.heads();
    assert_eq!(heads.len(), 2, "{heads:?}");
    for head in heads {
        assert!(
            !head.to_ascii_lowercase().contains("authorization"),
            "{head:?}"
        );
    }
}

/// `407`, `403` and `502` to `CONNECT` are `Error::Proxy` with the status;
/// neither the error nor its `Debug` holds the credentials.
#[test]
fn proxy_refusals_are_errors_without_secrets() {
    for status in [407u16, 403, 502] {
        let proxy = FakeProxy::start(
            OnConnect::Answer(
                format!("HTTP/1.1 {status} No\r\nProxy-Authenticate: Basic realm=\"x\"\r\n\r\n")
                    .into_bytes(),
            ),
            vec![],
        );
        let config = TlsConfig::new(roots(CA))
            .expect("config")
            .with_proxy(proxy.proxy().with_credentials(credentials()));
        let err = dial_err(&dial(config), "localhost", 443, Instant::now() + GUARD);
        let Error::Proxy {
            proxy: name,
            target,
            status: got,
        } = inner(&err)
        else {
            panic!("{err:?}");
        };
        assert_eq!(
            (name.as_str(), target.as_str(), *got),
            (
                format!("127.0.0.1:{}", proxy.addr.port()).as_str(),
                "localhost:443",
                status
            )
        );
        let text = err.to_string();
        assert!(text.contains(&format!("answered {status}")), "{text}");
        assert_no_secret(&text);
        assert_no_secret(&format!("{err:?}"));
    }
}

/// A `CONNECT` answer head of `PROXY_MAX_HEAD_BYTES` and of
/// `PROXY_MAX_HEADERS` fields opens the tunnel; one byte or one field more
/// is refused.
#[test]
fn proxy_head_limits_inclusive() {
    /// A 200 head of `fields` fields, padded with one `X-Pad` field to
    /// `total` bytes when given.
    fn head(fields: usize, total: Option<usize>) -> Vec<u8> {
        let mut head = String::from("HTTP/1.1 200 Connection established\r\n");
        let own = usize::from(total.is_some());
        for i in 0..fields - own {
            head.push_str(&format!("X-F{i}: a\r\n"));
        }
        if let Some(total) = total {
            let pad = total - head.len() - "X-Pad: \r\n\r\n".len();
            head.push_str(&format!("X-Pad: {}\r\n", "a".repeat(pad)));
        }
        head.push_str("\r\n");
        if let Some(total) = total {
            assert_eq!(head.len(), total);
        }
        head.into_bytes()
    }
    let origin = Origin::trusted();
    let try_head = |bytes: Vec<u8>| -> io::Result<()> {
        // The head, then a tunnel: the proxy relays after its own answer.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let origin_addr = origin.addr;
        thread::spawn(move || {
            let Ok((mut client, _)) = listener.accept() else {
                return;
            };
            let _ = client.set_read_timeout(Some(GUARD));
            read_head(&mut client);
            let _ = client.write_all(&bytes);
            if let Ok(upstream) = TcpStream::connect(origin_addr) {
                relay(client, upstream);
            }
        });
        let config = TlsConfig::new(roots(CA))
            .expect("config")
            .with_proxy(Proxy::new("127.0.0.1", port).expect("proxy"));
        dial(config)
            .dial("localhost", origin.addr.port(), Instant::now() + GUARD)
            .map(drop)
    };
    try_head(head(1, Some(PROXY_MAX_HEAD_BYTES))).expect("16,384 B");
    try_head(head(PROXY_MAX_HEADERS, None)).expect("64 fields");
    for (what, bytes) in [
        ("16,385 B", head(1, Some(PROXY_MAX_HEAD_BYTES + 1))),
        ("65 fields", head(PROXY_MAX_HEADERS + 1, None)),
    ] {
        let err = try_head(bytes).expect_err(what);
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{what}: {err:?}");
        assert!(err.to_string().contains("through the proxy"), "{err}");
    }
}

/// A proxy that accepts and never answers fails the dial at the request
/// deadline, within one `io` of it, not at `io` alone; a deadline already
/// past dials nothing.
#[test]
fn proxy_silent_after_accept_fails_at_the_deadline() {
    let proxy = FakeProxy::start(OnConnect::Silent, vec![]);
    let config = TlsConfig::new(roots(CA))
        .expect("config")
        .with_proxy(proxy.proxy());
    // `io` far above the deadline: only the deadline can end the wait.
    let dial = TlsDial::new(
        config,
        ConnectOptions::new(GUARD, GUARD, Duration::from_secs(30)).expect("options"),
    );
    let start = Instant::now();
    let err = dial_err(&dial, "localhost", 443, start + Duration::from_millis(300));
    let elapsed = start.elapsed();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err:?}");
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    assert_eq!(proxy.connections(), 1);

    let err = dial_err(&dial, "localhost", 443, Instant::now());
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err:?}");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(proxy.connections(), 1, "dialed past the deadline");
}

// ------------------------------------------------------------- revocation

/// The leaf's `http` CRL point is an absolute-form `GET` to the proxy,
/// and the list it answers settles the leaf. Against a proxy that asks for
/// credentials, the `GET` carries them only on its retry after `407`.
#[test]
fn crl_fetch_goes_through_the_proxy() {
    let origin = Origin::start(server_config(&[CRL_GOOD], CRL_LEAF_KEY));
    let proxy = FakeProxy::requiring(
        OnConnect::Tunnel(origin.addr),
        vec![(CRL_URL.into(), ok_with(CRL_FRESH))],
        Some(credentials().header_value()),
    );
    let config = TlsConfig::new(roots(CRL_CA))
        .expect("config")
        .with_proxy(proxy.proxy().with_credentials(credentials()));
    let stream = dial(config)
        .dial("localhost", origin.addr.port(), Instant::now() + GUARD)
        .expect("dial");
    drop(stream);
    // The CONNECT carries the credentials up front; the GET goes without
    // them first and again with them after the proxy's 407 (ADR-039, D8).
    let port = origin.addr.port();
    assert_eq!(
        proxy.heads(),
        [
            format!(
                "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\
Proxy-Authorization: Basic {}\r\n\r\n",
                encoded()
            ),
            format!("GET {CRL_URL} HTTP/1.1\r\nHost: crl.boneli.test\r\n\r\n"),
            format!(
                "GET {CRL_URL} HTTP/1.1\r\nHost: crl.boneli.test\r\n\
Proxy-Authorization: Basic {}\r\n\r\n",
                encoded()
            ),
        ]
    );
}

/// The status a `TlsStream` reports, through the proxy.
fn dialed_status(config: TlsConfig, origin: &Origin) -> (RevocationStatus, Vec<RevocationStatus>) {
    // `Dial` returns a boxed stream; the status needs the `TlsStream`, so
    // tunnel by hand the way `TlsDial` does and hand it to `connect_over`.
    let proxy = config.proxy().expect("proxy").clone();
    let tcp = TcpStream::connect((proxy.host(), proxy.port())).expect("proxy");
    tcp.set_read_timeout(Some(GUARD)).expect("timeout");
    let mut tunnel = tcp;
    tunnel
        .write_all(
            format!(
                "CONNECT localhost:{0} HTTP/1.1\r\nHost: localhost:{0}\r\n\r\n",
                origin.addr.port()
            )
            .as_bytes(),
        )
        .expect("CONNECT");
    let answer = read_head(&mut tunnel);
    assert!(answer.starts_with(b"HTTP/1.1 200"), "{answer:?}");
    let tls = boneli_https::connect_over(tunnel, "localhost", &config, &options()).expect("TLS");
    (
        tls.revocation().clone(),
        tls.intermediate_revocation().to_vec(),
    )
}

/// The same through `connect_over`, which reports the status: the leaf is
/// `Checked` by the list the proxy served.
#[test]
fn crl_status_through_the_proxy() {
    let origin = Origin::start(server_config(&[CRL_GOOD], CRL_LEAF_KEY));
    let proxy = FakeProxy::start(
        OnConnect::Tunnel(origin.addr),
        vec![(CRL_URL.into(), ok_with(CRL_FRESH))],
    );
    let config = TlsConfig::new(roots(CRL_CA))
        .expect("config")
        .with_proxy(proxy.proxy());
    let (leaf, _) = dialed_status(config, &origin);
    assert_eq!(
        leaf,
        RevocationStatus::Checked {
            url: CRL_URL.into()
        }
    );
    assert!(
        proxy.lines().contains(&format!("GET {CRL_URL} HTTP/1.1")),
        "{:?}",
        proxy.lines()
    );
}

/// An OCSP responder is an absolute-form `GET` through the proxy, and its
/// answer settles the leaf.
#[test]
fn ocsp_fetch_goes_through_the_proxy() {
    let origin = Origin::start(server_config(&[OCSP_GOOD], CRL_LEAF_KEY));
    let proxy = FakeProxy::start(
        OnConnect::Tunnel(origin.addr),
        vec![(OCSP_URL.into(), ok_with(OCSP_GOOD_RESP))],
    );
    let config = TlsConfig::new(roots(OCSP_CA))
        .expect("config")
        .with_proxy(proxy.proxy());
    let (leaf, _) = dialed_status(config.clone(), &origin);
    assert_eq!(
        leaf,
        RevocationStatus::OcspChecked {
            url: OCSP_URL.into()
        }
    );
    let gets: Vec<String> = proxy
        .lines()
        .into_iter()
        .filter(|l| l.starts_with("GET "))
        .collect();
    assert_eq!(gets.len(), 1, "{gets:?}");
    assert!(
        gets[0].starts_with("GET http://ocsp.boneli.test/MEIw"),
        "{gets:?}"
    );
    // And through `TlsDial`.
    let origin = Origin::start(server_config(&[OCSP_GOOD], CRL_LEAF_KEY));
    let proxy = FakeProxy::start(
        OnConnect::Tunnel(origin.addr),
        vec![(OCSP_URL.into(), ok_with(OCSP_GOOD_RESP))],
    );
    let config = TlsConfig::new(roots(OCSP_CA))
        .expect("config")
        .with_proxy(proxy.proxy());
    dial(config)
        .dial("localhost", origin.addr.port(), Instant::now() + GUARD)
        .expect("dial");
}

/// An intermediate's CA list (ADR-027) is fetched through the proxy too.
#[test]
fn ca_list_fetch_goes_through_the_proxy() {
    let origin = Origin::start(server_config(&[CHAIN_LEAF_NONE, CHAIN_CA1], CRL_LEAF_KEY));
    let proxy = FakeProxy::start(
        OnConnect::Tunnel(origin.addr),
        vec![(ROOT_CRL_URL.into(), ok_with(CHAIN_ROOT_EMPTY))],
    );
    let config = TlsConfig::new(roots(CHAIN_ROOT))
        .expect("config")
        .with_proxy(proxy.proxy());
    let (leaf, intermediates) = dialed_status(config, &origin);
    assert_eq!(leaf, RevocationStatus::NoRevocationSource);
    assert_eq!(
        intermediates,
        [RevocationStatus::Checked {
            url: ROOT_CRL_URL.into()
        }]
    );
    assert!(
        proxy
            .lines()
            .contains(&format!("GET {ROOT_CRL_URL} HTTP/1.1")),
        "{:?}",
        proxy.lines()
    );
}

/// The proxy refuses the fetch with `403`: the check fails closed with
/// `RevocationUnknown`, for the dial and for the leaf's point.
#[test]
fn revocation_unknown_when_the_proxy_refuses_the_fetch() {
    let origin = Origin::start(server_config(&[CRL_GOOD], CRL_LEAF_KEY));
    let proxy = FakeProxy::start(
        OnConnect::Tunnel(origin.addr),
        vec![(
            CRL_URL.into(),
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec(),
        )],
    );
    let config = TlsConfig::new(roots(CRL_CA))
        .expect("config")
        .with_proxy(proxy.proxy().with_credentials(credentials()));
    let err = dial_err(
        &dial(config),
        "localhost",
        origin.addr.port(),
        Instant::now() + GUARD,
    );
    let Error::RevocationUnknown(failures) = inner(&err) else {
        panic!("{err:?}");
    };
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0].url.as_deref(), Some(CRL_URL));
    assert_eq!(failures[0].kind, RevocationFailureKind::Status);
    assert_no_secret(&err.to_string());
    assert_no_secret(&format!("{err:?}"));
}

// ------------------------------------------------------------- configuration

/// A `CrlSource` that records the URLs it is asked for and has no list.
#[derive(Default)]
struct Recording(Mutex<Vec<String>>);

impl CrlSource for Recording {
    fn fetch(&self, url: &CrlUrl, _deadline: Instant) -> Result<Vec<u8>, CrlFetchError> {
        self.0.lock().expect("record").push(url.to_string());
        Err(CrlFetchError::Unreachable("recording".into()))
    }
}

/// `with_proxy` and `with_resolver` in either order route both the dial
/// and the CRL fetch through the proxy; a second `with_proxy` wins.
#[test]
fn proxy_and_resolver_commute() {
    let origin = Origin::start(server_config(&[CRL_GOOD], CRL_LEAF_KEY));
    let first = FakeProxy::start(
        OnConnect::Answer(b"HTTP/1.1 403 No\r\n\r\n".to_vec()),
        vec![],
    );
    let proxy = FakeProxy::start(
        OnConnect::Tunnel(origin.addr),
        vec![(CRL_URL.into(), ok_with(CRL_FRESH))],
    );
    let hosts = "127.0.0.1 proxy.boneli.test\n";
    let named = || Proxy::new("proxy.boneli.test", proxy.addr.port()).expect("proxy");
    let base = TlsConfig::new(roots(CRL_CA)).expect("config");
    for order in 0..3 {
        let (resolver, _stalled) = hosts_resolver(hosts);
        let config = match order {
            0 => base.with_proxy(named()).with_resolver(resolver),
            1 => base.with_resolver(resolver).with_proxy(named()),
            _ => base
                .with_resolver(resolver)
                .with_proxy(first.proxy())
                .with_proxy(named()),
        };
        let before = proxy.heads().len();
        dial(config)
            .dial("localhost", origin.addr.port(), Instant::now() + GUARD)
            .unwrap_or_else(|e| panic!("order {order}: {e:?}"));
        let new: Vec<String> = proxy.lines()[before..].to_vec();
        assert_eq!(new.len(), 2, "order {order}: {new:?}");
        assert!(new.iter().any(|l| l.starts_with("CONNECT localhost:")));
        assert!(new.contains(&format!("GET {CRL_URL} HTTP/1.1")));
    }
    assert_eq!(first.connections(), 0, "the replaced proxy was used");
}

/// A `CrlSource` set after `with_proxy` is kept: the proxy carries the
/// dial, the source the list.
#[test]
fn custom_sources_after_with_proxy_are_kept() {
    let origin = Origin::start(server_config(&[CRL_GOOD], CRL_LEAF_KEY));
    let proxy = FakeProxy::start(OnConnect::Tunnel(origin.addr), vec![]);
    let recording = Arc::new(Recording::default());
    let config = TlsConfig::new(roots(CRL_CA))
        .expect("config")
        .with_proxy(proxy.proxy())
        .with_crl_source(Arc::clone(&recording) as Arc<dyn CrlSource>);
    assert!(
        config.proxy().is_some(),
        "with_crl_source dropped the proxy"
    );
    let err = dial_err(
        &dial(config),
        "localhost",
        origin.addr.port(),
        Instant::now() + GUARD,
    );
    assert!(
        matches!(inner(&err), Error::RevocationUnknown(_)),
        "{err:?}"
    );
    assert_eq!(*recording.0.lock().expect("record"), [CRL_URL]);
    assert_eq!(proxy.lines().len(), 1, "{:?}", proxy.lines());
}

/// `connect` refuses a proxied configuration before any lookup.
#[test]
fn connect_refuses_a_proxied_config() {
    let (resolver, stalled) = hosts_resolver("");
    let config = TlsConfig::new(roots(CA))
        .expect("config")
        .with_resolver(resolver)
        .with_proxy(Proxy::new("127.0.0.1", 3128).expect("proxy"));
    let start = Instant::now();
    let err = connect("registry.boneli.test", 443, &config, &options()).expect_err("refused");
    assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
    assert!(err.to_string().contains("TlsDial"), "{err}");
    assert!(start.elapsed() < Duration::from_millis(100));
    assert_eq!(stalled.take(), 0, "a name server was asked");
}

/// `Debug` of `Proxy`, `TlsConfig` and `TlsDial` holds no secret window.
#[test]
fn debug_output_redacts_credentials() {
    let proxy = Proxy::new("proxy.corp.example", 3128)
        .expect("proxy")
        .with_credentials(credentials());
    let config = TlsConfig::new(roots(CA))
        .expect("config")
        .with_proxy(proxy.clone());
    let dial = dial(config.clone());
    for text in [
        format!("{proxy:?}"),
        format!("{proxy:#?}"),
        format!("{config:?}"),
        format!("{config:#?}"),
        format!("{dial:?}"),
        format!("{:?}", credentials()),
    ] {
        assert_no_secret(&text);
    }
    assert!(format!("{config:?}").contains("[redacted]"));
}
