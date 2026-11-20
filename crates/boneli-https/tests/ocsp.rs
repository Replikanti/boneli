//! Certificate revocation by OCSP (ADR-020) in real handshakes against
//! local rustls servers on 127.0.0.1, with answers from a fake
//! `OcspSource`: good, revoked and unknown leaves, every way an answer can
//! fail to settle a leaf, resumed sessions, CONNECT tunnels, `TlsDial`'s
//! deadline, clones, stapling, the default source and its name
//! resolution (ADR-022).
//!
//! The fixtures are openssl 3.5 certificates of the "Boneli OCSP test CA"
//! and answers of `openssl ocsp -index` (`tests/data/README.md`). These
//! tests do not prove interoperability with real responders;
//! `tests/network.rs` and the crate's `ocsp::live` tests do, by hand.

mod common;

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
    ConnectOptions, CrlFetchError, CrlSource, CrlUrl, Dial, Error, OcspSource,
    RevocationFailureKind, RevocationStatus, Roots, TlsConfig, TlsDial, TlsStream, connect,
    connect_over,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{HandshakeKind, ServerConfig, ServerConnection, StreamOwned};

const OCSP_CA: &[u8] = include_bytes!("data/ocsp-ca.pem");
const LEAF_KEY: &[u8] = include_bytes!("data/crl-leaf.key");
const GOOD: &[u8] = include_bytes!("data/ocsp-good.pem");
const REVOKED: &[u8] = include_bytes!("data/ocsp-revoked.pem");
const BOTH: &[u8] = include_bytes!("data/ocsp-and-crl.pem");
const GOOD_RESP: &[u8] = include_bytes!("data/ocsp-good.resp");
const GOOD_BYKEY_RESP: &[u8] = include_bytes!("data/ocsp-good-bykey.resp");
const REVOKED_RESP: &[u8] = include_bytes!("data/ocsp-revoked.resp");
const UNKNOWN_RESP: &[u8] = include_bytes!("data/ocsp-unknown.resp");
const DELEGATED_RESP: &[u8] = include_bytes!("data/ocsp-delegated.resp");
const EXPIRED_RESP: &[u8] = include_bytes!("data/ocsp-expired.resp");
const GOOD_REQ: &[u8] = include_bytes!("data/ocsp-good.req");

const URL: &str = "http://ocsp.boneli.test/";

/// Bounds every blocking read in these tests, so that a bug ends in a
/// failure instead of a hang; far above any local delivery time.
const GUARD: Duration = Duration::from_secs(10);

// ------------------------------------------------------------- helpers

fn roots() -> Roots {
    let mut roots = Roots::empty();
    roots.add_pem(OCSP_CA).expect("OCSP test CA");
    roots
}

fn options() -> ConnectOptions {
    ConnectOptions::new(GUARD, GUARD, GUARD).expect("valid options")
}

fn wide() -> Limits {
    Limits::new(16 * 1024, 64, 1024 * 1024).expect("valid limits")
}

type Reply = Result<Vec<u8>, CrlFetchError>;

/// A source with a fixed answer per responder (unreachable for any other)
/// that records every responder and request it is asked for.
#[derive(Default)]
struct Fake {
    answers: BTreeMap<String, Reply>,
    asked: Mutex<Vec<(String, Vec<u8>)>>,
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

    /// `URL` answers with `response`.
    fn serving(response: &[u8]) -> Arc<Fake> {
        Fake::new(&[(URL, Ok(response.to_vec()))])
    }

    fn asked(&self) -> Vec<String> {
        self.asked
            .lock()
            .expect("asked")
            .iter()
            .map(|(url, _)| url.clone())
            .collect()
    }
}

impl OcspSource for Fake {
    fn fetch(&self, responder: &CrlUrl, request: &[u8], _deadline: Instant) -> Reply {
        self.asked
            .lock()
            .expect("asked")
            .push((responder.as_str().to_owned(), request.to_vec()));
        self.answers
            .get(responder.as_str())
            .cloned()
            .unwrap_or_else(|| Err(CrlFetchError::Unreachable("not served".into())))
    }
}

/// A CRL source that records what it is asked for and serves nothing.
#[derive(Default)]
struct NoCrl(Mutex<Vec<String>>);

impl CrlSource for NoCrl {
    fn fetch(&self, url: &CrlUrl, _deadline: Instant) -> Reply {
        self.0.lock().expect("asked").push(url.as_str().to_owned());
        Err(CrlFetchError::Unreachable("no CRL here".into()))
    }
}

fn config(source: Arc<Fake>) -> TlsConfig {
    TlsConfig::new(roots())
        .expect("config")
        .with_ocsp_source(source)
}

fn server_config(
    chain_pem: &[&[u8]],
    versions: &[&'static rustls::SupportedProtocolVersion],
    staple: Option<&[u8]>,
) -> Arc<ServerConfig> {
    let chain = chain_pem
        .iter()
        .flat_map(|pem| CertificateDer::pem_slice_iter(pem))
        .collect::<Result<Vec<_>, _>>()
        .expect("cert PEM");
    let key = PrivateKeyDer::from_pem_slice(LEAF_KEY).expect("key PEM");
    let builder =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .expect("versions")
            .with_no_client_auth();
    let mut config = match staple {
        Some(staple) => builder.with_single_cert_with_ocsp(chain, key, staple.to_vec()),
        None => builder.with_single_cert(chain, key),
    }
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

fn serve(leaf: &[u8]) -> SocketAddr {
    server(server_config(&[leaf], &both(), None), 1).0
}

fn connect_to(addr: SocketAddr, config: &TlsConfig) -> boneli_https::Result<TlsStream<TcpStream>> {
    connect("localhost", addr.port(), config, &options())
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

/// One GET over a fresh connection: what the revocation check found,
/// after a request that went through.
fn status_of(leaf: &[u8], source: Arc<Fake>) -> boneli_https::Result<RevocationStatus> {
    let tls = connect_to(serve(leaf), &config(source))?;
    let status = tls.revocation().clone();
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
    Ok(status)
}

fn checked() -> RevocationStatus {
    RevocationStatus::OcspChecked { url: URL.into() }
}

fn assert_revoked<T: std::fmt::Debug>(result: boneli_https::Result<T>) {
    match result {
        Err(Error::Revoked { url }) => assert_eq!(url, URL),
        other => panic!("expected Revoked, got {other:?}"),
    }
}

fn kinds<T: std::fmt::Debug>(result: boneli_https::Result<T>) -> Vec<RevocationFailureKind> {
    match result {
        Err(Error::RevocationUnknown(failures)) => {
            for f in &failures {
                assert_eq!(f.url.as_deref(), Some(URL), "{f}");
            }
            failures.into_iter().map(|f| f.kind).collect()
        }
        other => panic!("expected RevocationUnknown, got {other:?}"),
    }
}

// ----------------------------------------------------- the criteria

#[test]
fn ocsp_good_leaf_passes() {
    let source = Fake::serving(GOOD_RESP);
    assert_eq!(status_of(GOOD, source.clone()).expect("connect"), checked());
    let asked = source.asked.lock().expect("asked").clone();
    assert_eq!(asked, [(URL.to_owned(), GOOD_REQ.to_vec())]);
    // The same answer with the responder named by key hash.
    assert_eq!(
        status_of(GOOD, Fake::serving(GOOD_BYKEY_RESP)).expect("connect"),
        checked()
    );
}

#[test]
fn ocsp_revoked_leaf_is_refused() {
    let source = Fake::serving(REVOKED_RESP);
    assert_revoked(connect_to(serve(REVOKED), &config(source.clone())));
    assert_eq!(source.asked(), [URL]);
    let error = connect_to(serve(REVOKED), &config(source)).expect_err("revoked");
    assert_eq!(
        error.to_string(),
        "the certificate is revoked (http://ocsp.boneli.test/)"
    );
}

#[test]
fn delegated_responder_passes() {
    assert_eq!(
        status_of(GOOD, Fake::serving(DELEGATED_RESP)).expect("connect"),
        checked()
    );
}

#[test]
fn unknown_status_fails_closed() {
    assert_eq!(
        kinds(connect_to(
            serve(GOOD),
            &config(Fake::serving(UNKNOWN_RESP))
        )),
        [RevocationFailureKind::UnknownCertificate]
    );
}

#[test]
fn expired_response_fails_closed() {
    // Generated with `-nmin 1`: it expired a minute after it was made.
    assert_eq!(
        kinds(connect_to(
            serve(GOOD),
            &config(Fake::serving(EXPIRED_RESP))
        )),
        [RevocationFailureKind::Expired]
    );
}

#[test]
fn answer_for_another_leaf_does_not_settle() {
    assert_eq!(
        kinds(connect_to(
            serve(GOOD),
            &config(Fake::serving(REVOKED_RESP))
        )),
        [RevocationFailureKind::NotSettled]
    );
}

#[test]
fn unreachable_responder_fails_closed() {
    for (reply, kind) in [
        (
            Err(CrlFetchError::Unreachable("refused".into())),
            RevocationFailureKind::Unreachable,
        ),
        (
            Err(CrlFetchError::TimedOut),
            RevocationFailureKind::TimedOut,
        ),
        (
            Err(CrlFetchError::Status(503)),
            RevocationFailureKind::Status,
        ),
    ] {
        let source = Fake::new(&[(URL, reply)]);
        assert_eq!(kinds(connect_to(serve(GOOD), &config(source))), [kind]);
    }
    let error = connect_to(serve(GOOD), &config(Fake::new(&[]))).expect_err("unknown");
    let text = error.to_string();
    assert!(text.contains(URL) && text.contains("unreachable"), "{text}");
}

#[test]
fn malformed_response_fails_closed() {
    let mut trailing = GOOD_RESP.to_vec();
    trailing.push(0);
    for (what, bytes) in [
        ("truncated", GOOD_RESP[..GOOD_RESP.len() - 1].to_vec()),
        ("trailing byte", trailing),
        ("HTML", b"<html><body>Not OCSP</body></html>".to_vec()),
        ("empty", Vec::new()),
    ] {
        let source = Fake::new(&[(URL, Ok(bytes))]);
        assert_eq!(
            kinds(connect_to(serve(GOOD), &config(source))),
            [RevocationFailureKind::Malformed],
            "{what}"
        );
    }
}

// ------------------------------------------------------------- routing

#[test]
fn crl_point_wins_over_ocsp() {
    let crl = Arc::new(NoCrl::default());
    let ocsp = Fake::serving(GOOD_RESP);
    let config = TlsConfig::new(roots())
        .expect("config")
        .with_crl_source(crl.clone())
        .with_ocsp_source(ocsp.clone());
    let error = connect_to(serve(BOTH), &config).expect_err("CRL unreachable");
    assert!(matches!(error, Error::RevocationUnknown(_)), "{error:?}");
    assert_eq!(
        *crl.0.lock().expect("asked"),
        ["http://crl.boneli.test/ocsp-ca.crl"]
    );
    assert!(ocsp.asked().is_empty());
}

#[test]
fn sources_are_kept_by_the_other_setter() {
    // `with_ocsp_source` after `with_crl_source` keeps the CRL source, and
    // the other way round.
    let crl = Arc::new(NoCrl::default());
    let ocsp = Fake::serving(GOOD_RESP);
    let config = TlsConfig::new(roots())
        .expect("config")
        .with_ocsp_source(ocsp.clone())
        .with_crl_source(crl.clone());
    assert_eq!(
        connect_to(serve(GOOD), &config).expect("ocsp").revocation(),
        &checked()
    );
    connect_to(serve(BOTH), &config).expect_err("CRL unreachable");
    assert_eq!(crl.0.lock().expect("asked").len(), 1);
}

// -------------------------------------------------------- resumption

#[test]
fn ocsp_resumed_tls12_session_is_refused_again() {
    let (addr, server) = server(
        server_config(&[REVOKED], &[&rustls::version::TLS12], None),
        2,
    );
    let config = config(Fake::serving(REVOKED_RESP));
    assert_revoked(connect_to(addr, &config));
    assert_revoked(connect_to(addr, &config));
    let kinds = server.join().expect("server");
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
    );
}

#[test]
fn ocsp_resumed_tls13_session_is_checked_again() {
    let (addr, server) = server(server_config(&[GOOD], &[&rustls::version::TLS13], None), 2);
    let source = Fake::serving(GOOD_RESP);
    let config = config(source.clone());
    for _ in 0..2 {
        let tls = connect_to(addr, &config).expect("connect");
        assert_eq!(tls.revocation(), &checked());
        let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
        assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
    }
    let kinds = server.join().expect("server");
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
    );
    // The second check used the cached answer.
    assert_eq!(source.asked(), [URL]);
}

// ------------------------------------------------------ CONNECT tunnels

fn relay(mut from: impl Read, mut to: impl Write, shutdown: impl FnOnce() -> io::Result<()>) {
    let _ = io::copy(&mut from, &mut to);
    let _ = shutdown();
}

#[test]
fn ocsp_check_over_connect_tunnel() {
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
        &config(Fake::serving(REVOKED_RESP)),
        &options(),
    ));
    let _ = proxy.join();
}

// ------------------------------------------------- deadlines, defaults

/// A source that records the deadline it was given and waits for it.
struct Waiting {
    deadlines: Mutex<Vec<Instant>>,
}

impl OcspSource for Waiting {
    fn fetch(&self, _responder: &CrlUrl, _request: &[u8], deadline: Instant) -> Reply {
        self.deadlines.lock().expect("deadlines").push(deadline);
        thread::sleep(deadline.saturating_duration_since(Instant::now()));
        Err(CrlFetchError::TimedOut)
    }
}

#[test]
fn tls_dial_deadline_bounds_ocsp_fetch() {
    let source = Arc::new(Waiting {
        deadlines: Mutex::new(Vec::new()),
    });
    let config = TlsConfig::new(roots())
        .expect("config")
        .with_ocsp_source(source.clone());
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
fn default_config_checks_ocsp() {
    // The real source: `ocsp.boneli.test` does not resolve. The kind is
    // not asserted, because some resolvers answer every name.
    let config = TlsConfig::new(roots()).expect("config");
    let error = connect_to(serve(GOOD), &config).expect_err("unknown");
    assert!(matches!(error, Error::RevocationUnknown(_)), "{error:?}");
}

/// The real source resolves the responder's host through the
/// configuration's resolver under the request's deadline: against a name
/// server that never answers, `TlsDial` fails at its 300 ms deadline with
/// a timed-out fetch, not after the resolver's 3.75 s of tries, and no
/// query is sent once it returned: a lookup left running would send one
/// at 500 ms (`Stalled::call_site_resolver`).
#[test]
fn ocsp_lookup_stops_at_the_request_deadline() {
    let stalled = common::Stalled::start();
    let config = TlsConfig::new(roots())
        .expect("config")
        .with_resolver(stalled.call_site_resolver());
    let addr = serve(GOOD);
    let dial = TlsDial::new(config, options());
    let start = Instant::now();
    let error = match dial.dial("localhost", addr.port(), start + Duration::from_millis(300)) {
        Ok(_) => panic!("the dial passed"),
        Err(e) => e,
    };
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
    let inner = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .expect("the TLS client's error");
    match inner {
        Error::RevocationUnknown(list) => {
            let found: Vec<_> = list.iter().map(|f| (f.url.as_deref(), f.kind)).collect();
            assert_eq!(found, [(Some(URL), RevocationFailureKind::TimedOut)]);
        }
        other => panic!("expected RevocationUnknown, got {other:?}"),
    }
    let sent = stalled.take();
    assert!(
        sent.is_multiple_of(2) && (2..=6).contains(&sent),
        "{sent} queries"
    );
    thread::sleep(Duration::from_millis(600));
    assert_eq!(stalled.take(), 0, "a query after the dial returned");
}

#[test]
fn clones_share_ocsp_cache() {
    let source = Fake::serving(GOOD_RESP);
    let config = config(source.clone());
    let clone = config.clone();
    let (addr, _server) = server(server_config(&[GOOD], &both(), None), 2);
    connect_to(addr, &config).expect("first");
    connect_to(addr, &clone).expect("second");
    assert_eq!(source.asked(), [URL], "one fetch for both");
    // `with_ocsp_source` starts a cache of its own.
    let other = config.with_ocsp_source(source.clone());
    connect_to(serve(GOOD), &other).expect("third");
    assert_eq!(source.asked(), [URL, URL]);
}

#[test]
fn stapled_response_is_ignored() {
    // A garbage staple changes nothing: the source decides.
    let (addr, _server) = server(server_config(&[GOOD], &both(), Some(b"garbage")), 1);
    let source = Fake::serving(GOOD_RESP);
    let tls = connect_to(addr, &config(source.clone())).expect("connect");
    assert_eq!(tls.revocation(), &checked());
    assert_eq!(source.asked(), [URL]);
    // A valid good staple for a leaf the source reports revoked: refused.
    let (addr, _server) = server(server_config(&[REVOKED], &both(), Some(GOOD_RESP)), 1);
    assert_revoked(connect_to(addr, &config(Fake::serving(REVOKED_RESP))));
}
