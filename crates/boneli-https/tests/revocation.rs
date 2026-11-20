//! Certificate revocation by CRL (ADR-017) in real handshakes against
//! local rustls servers on 127.0.0.1, with CRLs from a fake `CrlSource`:
//! revoked and good leaves, every way a list can fail to settle a leaf,
//! the order and number of distribution points, leaves without one,
//! resumed sessions, CONNECT tunnels, `TlsDial`'s deadline and the
//! default source.
//!
//! The fixtures are openssl 3.5 certificates and CRLs of the "Boneli CRL
//! test CA" (`tests/data/README.md`). These tests do not prove
//! interoperability with real CAs; `tests/network.rs` does, by hand.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use boneli_http::{
    Connection, Exchange, Headers, Limits, Method, RequestBody, RequestHead, ServerLimits, Target,
    Transport, connect_tunnel,
};
use boneli_https::{
    ConnectOptions, CrlFailureKind, CrlFetchError, CrlSource, CrlUrl, Dial, Error,
    RevocationStatus, Roots, TlsConfig, TlsDial, TlsStream, connect, connect_over,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{HandshakeKind, ServerConfig, ServerConnection, StreamOwned};

const CRL_CA: &[u8] = include_bytes!("data/crl-ca.pem");
const CRL_LEAF_KEY: &[u8] = include_bytes!("data/crl-leaf.key");
const GOOD: &[u8] = include_bytes!("data/crl-good.pem");
const REVOKED: &[u8] = include_bytes!("data/crl-revoked.pem");
const REVOKED_FIRST: &[u8] = include_bytes!("data/crl-revoked-first.pem");
const TWO_DP: &[u8] = include_bytes!("data/crl-two-dp.pem");
const FIVE_URLS: &[u8] = include_bytes!("data/crl-five-urls.pem");
const LDAP_ONLY: &[u8] = include_bytes!("data/crl-ldap-only.pem");
const REASONS_ONLY: &[u8] = include_bytes!("data/crl-reasons-only.pem");
const STRAY: &[u8] = include_bytes!("data/crl-stray.pem");
const FRESH: &[u8] = include_bytes!("data/crl-ca-fresh.crl");
const FRESH_PEM: &[u8] = include_bytes!("data/crl-ca-fresh.pem");
const EMPTY: &[u8] = include_bytes!("data/crl-ca-empty.crl");
const WEEK1: &[u8] = include_bytes!("data/crl-ca-week1.crl");
const IDP: &[u8] = include_bytes!("data/crl-ca-idp.crl");
const OTHER_SHARD: &[u8] = include_bytes!("data/crl-ca-other-shard.crl");
const V1: &[u8] = include_bytes!("data/crl-ca-v1.crl");
const FORGED: &[u8] = include_bytes!("data/crl-ca-forged.crl");
const CA: &[u8] = include_bytes!("data/ca.pem");
const LEAF: &[u8] = include_bytes!("data/leaf.pem");
const LEAF_KEY: &[u8] = include_bytes!("data/leaf.key");

const URL: &str = "http://crl.boneli.test/ca.crl";

/// Bounds every blocking read in these tests, so that a bug ends in a
/// failure instead of a hang; far above any local delivery time.
const GUARD: Duration = Duration::from_secs(10);

// ------------------------------------------------------------- helpers

/// Both test CAs as roots: the CRL CA and the CA of `leaf.pem`.
fn roots() -> Roots {
    let mut roots = Roots::empty();
    roots.add_pem(CRL_CA).expect("CRL test CA");
    roots.add_pem(CA).expect("test CA");
    roots
}

fn options() -> ConnectOptions {
    ConnectOptions::new(GUARD, GUARD, GUARD).expect("valid options")
}

fn wide() -> Limits {
    Limits::new(16 * 1024, 64, 1024 * 1024).expect("valid limits")
}

type Reply = Result<Vec<u8>, CrlFetchError>;

/// A source with a fixed answer per URL (unreachable for any other) that
/// records every URL it is asked for.
#[derive(Default)]
struct Fake {
    answers: BTreeMap<String, Reply>,
    asked: Mutex<Vec<String>>,
}

impl Fake {
    fn new(answers: &[(&str, Reply)]) -> Arc<Fake> {
        Arc::new(Fake {
            answers: answers
                .iter()
                .map(|(url, reply)| ((*url).to_owned(), reply.clone()))
                .collect(),
            asked: Mutex::new(Vec::new()),
        })
    }

    /// `URL` answers with `crl`.
    fn serving(crl: &[u8]) -> Arc<Fake> {
        Fake::new(&[(URL, ok(crl))])
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }
}

impl CrlSource for Fake {
    fn fetch(&self, url: &CrlUrl, _deadline: Instant) -> Reply {
        self.asked
            .lock()
            .expect("asked")
            .push(url.as_str().to_owned());
        self.answers
            .get(url.as_str())
            .cloned()
            .unwrap_or_else(|| Err(CrlFetchError::Unreachable("not served".into())))
    }
}

fn ok(crl: &[u8]) -> Reply {
    Ok(crl.to_vec())
}

fn unreachable() -> Reply {
    Err(CrlFetchError::Unreachable("refused".into()))
}

fn config(source: Arc<Fake>) -> TlsConfig {
    TlsConfig::new(roots())
        .expect("config")
        .with_crl_source(source)
}

fn server_config(
    chain_pem: &[&[u8]],
    key: &[u8],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ServerConfig> {
    let chain = chain_pem
        .iter()
        .flat_map(|pem| CertificateDer::pem_slice_iter(pem))
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
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn both() -> [&'static rustls::SupportedProtocolVersion; 2] {
    [&rustls::version::TLS13, &rustls::version::TLS12]
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

/// Answers every request with `200 hello`.
fn hello(ex: Exchange<'_, ServerTls>) -> boneli_http::Result<()> {
    ex.respond(200, &Headers::new(), b"hello")
}

/// Listens on 127.0.0.1 and serves `count` TLS connections one after the
/// other with `200 hello` until the client goes away. Returns the
/// handshake kind of each, `None` where the handshake failed.
fn server(
    config: Arc<ServerConfig>,
    count: usize,
) -> (SocketAddr, thread::JoinHandle<Vec<Option<HandshakeKind>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = thread::spawn(move || {
        let mut kinds = Vec::new();
        for _ in 0..count {
            let Ok((mut tcp, _)) = listener.accept() else {
                kinds.push(None);
                continue;
            };
            let _ = tcp.set_read_timeout(Some(GUARD));
            let _ = tcp.set_write_timeout(Some(GUARD));
            let mut conn = ServerConnection::new(Arc::clone(&config)).expect("server");
            let mut failed = false;
            while conn.is_handshaking() {
                if conn.complete_io(&mut tcp).is_err() {
                    failed = true;
                    break;
                }
            }
            if failed {
                kinds.push(None);
                continue;
            }
            kinds.push(conn.handshake_kind());
            let five = Duration::from_secs(5);
            let limits = ServerLimits::new(wide(), 4, five, five, five).expect("server limits");
            // The client may drop the connection without close_notify.
            let _ = boneli_http::serve_connection(
                ServerTls(StreamOwned::new(conn, tcp)),
                &limits,
                &hello,
            );
        }
        kinds
    });
    (addr, handle)
}

/// A server for one connection presenting `leaf` (with the CRL leaf key).
fn serve(leaf: &[u8]) -> SocketAddr {
    server(server_config(&[leaf], CRL_LEAF_KEY, &both()), 1).0
}

fn connect_to(addr: SocketAddr, config: &TlsConfig) -> boneli_https::Result<TlsStream<TcpStream>> {
    connect("localhost", addr.port(), config, &options())
}

/// One GET over a fresh connection to `addr`: what the revocation check
/// found, after a request that went through.
fn status_of(leaf: &[u8], source: Arc<Fake>) -> boneli_https::Result<RevocationStatus> {
    let addr = serve(leaf);
    let tls = connect_to(addr, &config(source))?;
    let status = tls.revocation().clone();
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
    Ok(status)
}

fn get<S: Read + Write + boneli_http::IdleCheck>(conn: &mut Connection<S>) -> (u16, Vec<u8>) {
    let head = RequestHead::new(
        Method::new("GET").expect("method"),
        Target::Origin("/".into()),
    );
    let mut response = conn.request(&head, RequestBody::None).expect("request");
    let mut body = Vec::new();
    response.read_to_end(&mut body).expect("body");
    (response.head.status, body)
}

fn checked(url: &str) -> RevocationStatus {
    RevocationStatus::Checked { url: url.into() }
}

fn assert_revoked<T: std::fmt::Debug>(result: boneli_https::Result<T>) {
    match result {
        Err(Error::Revoked { url }) => assert_eq!(url, URL),
        other => panic!("expected Revoked, got {other:?}"),
    }
}

/// The failure kinds of a `RevocationUnknown`, each with its URL.
fn failures<T: std::fmt::Debug>(
    result: boneli_https::Result<T>,
) -> Vec<(Option<String>, CrlFailureKind)> {
    match result {
        Err(Error::RevocationUnknown(failures)) => {
            failures.into_iter().map(|f| (f.url, f.kind)).collect()
        }
        other => panic!("expected RevocationUnknown, got {other:?}"),
    }
}

fn one(kind: CrlFailureKind) -> Vec<(Option<String>, CrlFailureKind)> {
    vec![(Some(URL.to_owned()), kind)]
}

// ----------------------------------------------------- the criteria

#[test]
fn revoked_leaf_is_refused() {
    let source = Fake::serving(FRESH);
    assert_revoked(connect_to(serve(REVOKED), &config(source.clone())));
    assert_eq!(source.asked(), [URL]);
}

#[test]
fn revoked_first_entry_is_refused() {
    assert_revoked(connect_to(
        serve(REVOKED_FIRST),
        &config(Fake::serving(FRESH)),
    ));
}

#[test]
fn good_leaf_same_ca_passes() {
    assert_eq!(
        status_of(GOOD, Fake::serving(FRESH)).expect("connect"),
        checked(URL)
    );
}

#[test]
fn empty_crl_passes() {
    assert_eq!(
        status_of(REVOKED, Fake::serving(EMPTY)).expect("connect"),
        checked(URL)
    );
}

#[test]
fn unreachable_crl_fails_closed() {
    let source = Fake::new(&[(URL, unreachable())]);
    assert_eq!(
        failures(connect_to(serve(GOOD), &config(source))),
        one(CrlFailureKind::Unreachable)
    );
    let error = connect_to(serve(GOOD), &config(Fake::new(&[]))).expect_err("unknown");
    let text = error.to_string();
    assert!(text.contains(URL) && text.contains("unreachable"), "{text}");
}

#[test]
fn malformed_crl_fails_closed() {
    let mut trailing = FRESH.to_vec();
    trailing.push(0);
    let html = b"<html><body>Not a CRL</body></html>".to_vec();
    for (what, bytes) in [
        ("truncated", FRESH[..FRESH.len() - 1].to_vec()),
        ("trailing byte", trailing),
        ("PEM", FRESH_PEM.to_vec()),
        ("HTML", html),
        ("version 1", V1.to_vec()),
    ] {
        let source = Fake::new(&[(URL, Ok(bytes))]);
        assert_eq!(
            failures(connect_to(serve(GOOD), &config(source))),
            one(CrlFailureKind::Malformed),
            "{what}"
        );
    }
}

#[test]
fn expired_crl_fails_closed_and_is_not_cached() {
    // Week1 expired on 2026-01-08; these tests run later.
    let source = Fake::serving(WEEK1);
    let config = config(source.clone());
    for _ in 0..2 {
        assert_eq!(
            failures(connect_to(serve(GOOD), &config)),
            one(CrlFailureKind::Expired)
        );
    }
    assert_eq!(source.asked(), [URL, URL], "asked again: not cached");
}

// ------------------------------------------ issuers, shards, signatures

#[test]
fn other_shard_fails_closed() {
    assert_eq!(
        failures(connect_to(
            serve(REVOKED),
            &config(Fake::serving(OTHER_SHARD))
        )),
        one(CrlFailureKind::NotSettled)
    );
}

#[test]
fn matching_idp_is_used() {
    assert_revoked(connect_to(serve(REVOKED), &config(Fake::serving(IDP))));
    assert_eq!(
        status_of(GOOD, Fake::serving(IDP)).expect("connect"),
        checked(URL)
    );
}

#[test]
fn forged_issuer_fails_closed() {
    assert_eq!(
        failures(connect_to(serve(GOOD), &config(Fake::serving(FORGED)))),
        one(CrlFailureKind::NotSettled)
    );
}

// --------------------------------------------- distribution points

const CRL1: &str = "http://crl1.boneli.test/ca.crl";
const CRL2: &str = "http://crl2.boneli.test/ca.crl";
const CRL3: &str = "http://crl3.boneli.test/ca.crl";
const CRL4: &str = "http://crl4.boneli.test/ca.crl";
const CRL5: &str = "http://crl5.boneli.test/ca.crl";

#[test]
fn revoked_on_first_url_stops() {
    // crl-two-dp.pem's serial is listed in the fresh list; the mirror
    // serves the empty list and is never asked to overrule it.
    let source = Fake::new(&[(CRL1, ok(FRESH)), (CRL2, ok(EMPTY))]);
    match connect_to(serve(TWO_DP), &config(source.clone())) {
        Err(Error::Revoked { url }) => assert_eq!(url, CRL1),
        other => panic!("expected Revoked, got {other:?}"),
    }
    assert_eq!(source.asked(), [CRL1]);
}

#[test]
fn second_url_used_when_first_fails() {
    let source = Fake::new(&[(CRL1, unreachable()), (CRL2, ok(EMPTY))]);
    assert_eq!(
        status_of(TWO_DP, source.clone()).expect("connect"),
        checked(CRL2)
    );
    assert_eq!(source.asked(), [CRL1, CRL2]);
}

#[test]
fn fourth_url_is_tried() {
    let source = Fake::new(&[(CRL4, ok(EMPTY))]);
    assert_eq!(
        status_of(FIVE_URLS, source.clone()).expect("connect"),
        checked(CRL4)
    );
    assert_eq!(source.asked(), [CRL1, CRL2, CRL3, CRL4]);
}

#[test]
fn fifth_url_is_never_tried() {
    let source = Fake::new(&[(CRL5, ok(EMPTY))]);
    let found = failures(connect_to(serve(FIVE_URLS), &config(source.clone())));
    assert_eq!(found.len(), 4);
    assert!(found.iter().all(|(_, k)| *k == CrlFailureKind::Unreachable));
    assert_eq!(source.asked(), [CRL1, CRL2, CRL3, CRL4]);
}

#[test]
fn extra_certificate_points_are_never_fetched() {
    let source = Fake::serving(EMPTY);
    let config_server = server_config(&[GOOD, STRAY], CRL_LEAF_KEY, &both());
    let (addr, _server) = server(config_server, 1);
    let tls = connect_to(addr, &config(source.clone())).expect("connect");
    assert_eq!(tls.revocation(), &checked(URL));
    assert_eq!(source.asked(), [URL]);
}

#[test]
fn ldap_only_passes_unchecked() {
    let source = Fake::new(&[]);
    assert_eq!(
        status_of(LDAP_ONLY, source.clone()).expect("connect"),
        RevocationStatus::NoDistributionPoint
    );
    assert!(source.asked().is_empty());
}

#[test]
fn reasons_only_passes_unchecked() {
    let source = Fake::new(&[]);
    assert_eq!(
        status_of(REASONS_ONLY, source.clone()).expect("connect"),
        RevocationStatus::NoDistributionPoint
    );
    assert!(source.asked().is_empty());
}

#[test]
fn no_distribution_point_passes_unchecked() {
    let source = Fake::new(&[]);
    let (addr, _server) = server(server_config(&[LEAF], LEAF_KEY, &both()), 1);
    let tls = connect_to(addr, &config(source.clone())).expect("connect");
    assert_eq!(tls.revocation(), &RevocationStatus::NoDistributionPoint);
    assert!(source.asked().is_empty());
}

// -------------------------------------------------------- resumption

#[test]
fn resumed_tls12_session_is_refused_again() {
    let (addr, server) = server(
        server_config(&[REVOKED], CRL_LEAF_KEY, &[&rustls::version::TLS12]),
        2,
    );
    let config = config(Fake::serving(FRESH));
    assert_revoked(connect_to(addr, &config));
    assert_revoked(connect_to(addr, &config));
    let kinds = server.join().expect("server");
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
    );
}

#[test]
fn resumed_tls13_session_is_checked_again() {
    let (addr, server) = server(
        server_config(&[GOOD], CRL_LEAF_KEY, &[&rustls::version::TLS13]),
        2,
    );
    let source = Fake::serving(EMPTY);
    let config = config(source.clone());
    for _ in 0..2 {
        // The GET reads the session tickets that arrive before the
        // response.
        let tls = connect_to(addr, &config).expect("connect");
        assert_eq!(tls.revocation(), &checked(URL));
        let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
        assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
    }
    let kinds = server.join().expect("server");
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
    );
    // The second check used the cached list.
    assert_eq!(source.asked(), [URL]);
}

// ------------------------------------------------------ CONNECT tunnels

/// Copies `from` into `to` until the end of the stream, then shuts down
/// `to` for writing so that the far side sees the end too.
fn relay(mut from: impl Read, mut to: impl Write, shutdown: impl FnOnce() -> io::Result<()>) {
    let _ = io::copy(&mut from, &mut to);
    let _ = shutdown();
}

#[test]
fn connect_over_tunnel_checks() {
    let tls_addr = serve(REVOKED);
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
    assert_revoked(connect_over(
        tunnel,
        "localhost",
        &config(Fake::serving(FRESH)),
        &options(),
    ));
    let _ = proxy.join();
}

// ------------------------------------------------- deadlines, defaults

/// A source that records the deadline it was given and waits for it.
struct Waiting {
    deadlines: Mutex<Vec<Instant>>,
}

impl CrlSource for Waiting {
    fn fetch(&self, _url: &CrlUrl, deadline: Instant) -> Reply {
        self.deadlines.lock().expect("deadlines").push(deadline);
        thread::sleep(deadline.saturating_duration_since(Instant::now()));
        Err(CrlFetchError::TimedOut)
    }
}

#[test]
fn tls_dial_clamps_fetch_to_request_deadline() {
    let source = Arc::new(Waiting {
        deadlines: Mutex::new(Vec::new()),
    });
    let config = TlsConfig::new(roots())
        .expect("config")
        .with_crl_source(source.clone());
    let addr = serve(GOOD);
    let dial = TlsDial::new(config, options());
    let start = Instant::now();
    let deadline = start + Duration::from_millis(300);
    let error = match dial.dial("localhost", addr.port(), deadline) {
        Ok(_) => panic!("the dial passed"),
        Err(e) => e,
    };
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
    let inner = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .expect("the TLS client's error");
    assert!(matches!(inner, Error::RevocationUnknown(_)), "{inner:?}");
    let seen = source.deadlines.lock().expect("deadlines").clone();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|d| *d <= deadline), "{seen:?}");
}

#[test]
fn default_config_checks_revocation() {
    // The real source: `crl.boneli.test` does not resolve. The kind is not
    // asserted, because some resolvers answer every name.
    let config = TlsConfig::new(roots()).expect("config");
    let error = connect_to(serve(GOOD), &config).expect_err("unknown");
    assert!(matches!(error, Error::RevocationUnknown(_)), "{error:?}");
}

#[test]
fn classical_config_checks_revocation() {
    let config = TlsConfig::classical(roots()).expect("config");
    let error = connect_to(serve(GOOD), &config).expect_err("unknown");
    assert!(matches!(error, Error::RevocationUnknown(_)), "{error:?}");
}

#[test]
fn tls_config_is_send_sync_and_clones_share_cache() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<TlsConfig>();
    let source = Fake::serving(EMPTY);
    let config = config(source.clone());
    let clone = config.clone();
    let (addr, _server) = server(server_config(&[GOOD], CRL_LEAF_KEY, &both()), 2);
    connect_to(addr, &config).expect("first");
    connect_to(addr, &clone).expect("second");
    assert_eq!(source.asked(), [URL], "one fetch for both");
    // `with_crl_source` starts a cache of its own.
    let other = config.with_crl_source(source.clone());
    connect_to(serve(GOOD), &other).expect("third");
    assert_eq!(source.asked(), [URL, URL]);
}
