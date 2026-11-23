//! Revocation of intermediate certificates (ADR-027) in real handshakes
//! against local rustls servers on 127.0.0.1, with CRLs from a fake
//! `CrlSource`: revoked and good intermediates above revoked and good
//! leaves, every way a CA list can fail to settle one, the order and
//! number of fetches, the budget, the cache, intermediates without a
//! point, OCSP-route and sourceless leaves, resumed sessions, CONNECT
//! tunnels and `TlsDial`'s deadline.
//!
//! The fixtures are the openssl 3.5 certificates of the "Boneli chain
//! test root" (`tests/data/README.md`): a root, six CAs in a line, each
//! naming its issuer's list at `crl1` and `crl2`, and leaves. The lists
//! are built and signed here at test time with the kept test keys. These
//! tests do not prove interoperability with real CAs; the real captures
//! of `src/revocation/ca_list.rs` and `tests/network.rs` do.

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boneli_http::{
    Connection, Exchange, Headers, Limits, Method, RequestBody, RequestHead, ServerLimits, Target,
    Transport, connect_tunnel,
};
use boneli_https::{
    ConnectOptions, CrlFetchError, CrlSource, CrlUrl, Dial, Error, MAX_CA_CRL_BYTES,
    MAX_CA_CRL_FETCHES, OcspSource, RevocationFailureKind, RevocationStatus, Roots, TlsConfig,
    TlsDial, TlsStream, connect, connect_over,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{HandshakeKind, ServerConfig, ServerConnection, SignatureScheme, StreamOwned};

const ROOT: &[u8] = include_bytes!("data/chain-root.pem");
const ROOT_KEY: &[u8] = include_bytes!("data/test-only-chain-root.key");
const CA_KEY: &[u8] = include_bytes!("data/test-only-chain-ca.key");
const LEAF_KEY: &[u8] = include_bytes!("data/crl-leaf.key");
const CA: [&[u8]; 6] = [
    include_bytes!("data/chain-ca1.pem"),
    include_bytes!("data/chain-ca2.pem"),
    include_bytes!("data/chain-ca3.pem"),
    include_bytes!("data/chain-ca4.pem"),
    include_bytes!("data/chain-ca5.pem"),
    include_bytes!("data/chain-ca6.pem"),
];
const CA1_NO_POINT: &[u8] = include_bytes!("data/chain-ca1-no-point.pem");
const CA1_LDAP: &[u8] = include_bytes!("data/chain-ca1-ldap.pem");
const CA1_FIVE: &[u8] = include_bytes!("data/chain-ca1-five-urls.pem");
const STRAY_CA: &[u8] = include_bytes!("data/chain-stray-ca.pem");
const LEAF_CA1: &[u8] = include_bytes!("data/chain-leaf-ca1.pem");
const LEAF_CA2: &[u8] = include_bytes!("data/chain-leaf-ca2.pem");
const LEAF_CA5: &[u8] = include_bytes!("data/chain-leaf-ca5.pem");
const LEAF_CA6: &[u8] = include_bytes!("data/chain-leaf-ca6.pem");
const LEAF_OCSP: &[u8] = include_bytes!("data/chain-leaf-ocsp-ca1.pem");
const LEAF_NONE: &[u8] = include_bytes!("data/chain-leaf-none-ca1.pem");
const ROOT_EMPTY: &[u8] = include_bytes!("data/chain-root-empty.crl");
const ROOT_LISTS_CA1: &[u8] = include_bytes!("data/chain-root-lists-ca1.crl");

/// The serials of CA 1 to CA 6.
const CA_SERIAL: [u8; 6] = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16];

/// Bounds every blocking read in these tests, so that a bug ends in a
/// failure instead of a hang; far above any local delivery time.
const GUARD: Duration = Duration::from_secs(10);

// ------------------------------------------------------------- lists

/// `crl1` or `crl2`'s URL of `issuer`'s list (`root`, `ca1` ... `ca6`).
fn url(n: u8, issuer: &str) -> String {
    format!("http://crl{n}.boneli.test/{issuer}.crl")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// One DER element: `tag`, the minimal length, `value`.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(value);
    out
}

/// A GeneralizedTime, whole, for Unix seconds (proleptic Gregorian).
fn gtime(secs: u64) -> Vec<u8> {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    // Days to a civil date (H. Hinnant's algorithm), from 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let text = format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
        rest / 3_600,
        rest / 60 % 60,
        rest % 60
    );
    tlv(0x18, text.as_bytes())
}

/// The subject Name of a certificate, whole.
fn subject(pem: &[u8]) -> Vec<u8> {
    let der = CertificateDer::from_pem_slice(pem).expect("PEM");
    let cert = webpki::EndEntityCert::try_from(&der).expect("certificate");
    tlv(0x30, cert.subject())
}

/// A version 2 list, ecdsa-with-SHA256, from `this_update` to
/// `next_update`, with a cRLNumber, listing `serials`, signed by `key`
/// under the subject name of `issuer`.
fn list_at(
    issuer: &[u8],
    key: &[u8],
    this_update: u64,
    next_update: u64,
    serials: &[u8],
) -> Vec<u8> {
    const ECDSA_SHA256: &[u8] = &[
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
    ];
    let mut tbs = tlv(0x02, &[1]);
    tbs.extend_from_slice(ECDSA_SHA256);
    tbs.extend(subject(issuer));
    tbs.extend(gtime(this_update));
    tbs.extend(gtime(next_update));
    if !serials.is_empty() {
        let entries: Vec<u8> = serials
            .iter()
            .flat_map(|s| {
                let mut entry = tlv(0x02, &[*s]);
                entry.extend(gtime(this_update));
                tlv(0x30, &entry)
            })
            .collect();
        tbs.extend(tlv(0x30, &entries));
    }
    let mut number = tlv(0x06, &[0x55, 0x1D, 0x14]);
    number.extend(tlv(0x04, &tlv(0x02, &[1])));
    tbs.extend(tlv(0xA0, &tlv(0x30, &tlv(0x30, &number))));
    let tbs = tlv(0x30, &tbs);
    let key = PrivateKeyDer::from_pem_slice(key).expect("key PEM");
    let key = rustls::crypto::ring::sign::any_ecdsa_type(&key).expect("ECDSA key");
    let signature = key
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .expect("P-256")
        .sign(&tbs)
        .expect("sign");
    let mut bits = vec![0];
    bits.extend(signature);
    let mut body = tbs;
    body.extend_from_slice(ECDSA_SHA256);
    body.extend(tlv(0x03, &bits));
    tlv(0x30, &body)
}

/// A list valid from an hour ago for a week.
fn list(issuer: &[u8], key: &[u8], serials: &[u8]) -> Vec<u8> {
    let now = now();
    list_at(issuer, key, now - 3_600, now + 7 * 86_400, serials)
}

/// The root's list.
fn root_list(serials: &[u8]) -> Vec<u8> {
    list(ROOT, ROOT_KEY, serials)
}

/// CA `n`'s list (1 to 6).
fn ca_list(n: usize, serials: &[u8]) -> Vec<u8> {
    list(CA[n - 1], CA_KEY, serials)
}

// ------------------------------------------------------------ helpers

type Reply = Result<Vec<u8>, CrlFetchError>;

/// A source with a queue of answers per URL (the last one repeats;
/// unreachable for any other URL) that records every URL it is asked
/// for.
#[derive(Default)]
struct Fake {
    answers: Mutex<BTreeMap<String, VecDeque<Reply>>>,
    asked: Mutex<Vec<String>>,
}

impl Fake {
    fn new(answers: &[(&str, Reply)]) -> Arc<Fake> {
        let fake = Fake::default();
        for (url, reply) in answers {
            fake.push(url, reply.clone());
        }
        Arc::new(fake)
    }

    /// Queues `reply` after the answers `url` has.
    fn push(&self, url: &str, reply: Reply) {
        self.answers
            .lock()
            .expect("answers")
            .entry(url.to_owned())
            .or_default()
            .push_back(reply);
    }

    /// `url` answers `reply` from now on.
    fn set(&self, url: &str, reply: Reply) {
        self.answers
            .lock()
            .expect("answers")
            .insert(url.to_owned(), VecDeque::from([reply]));
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("asked").clone()
    }

    fn clear(&self) {
        self.asked.lock().expect("asked").clear();
    }
}

impl CrlSource for Fake {
    fn fetch(&self, url: &CrlUrl, _deadline: Instant) -> Reply {
        self.asked
            .lock()
            .expect("asked")
            .push(url.as_str().to_owned());
        let mut answers = self.answers.lock().expect("answers");
        match answers.get_mut(url.as_str()) {
            Some(queue) if queue.len() > 1 => queue.pop_front().expect("queued"),
            Some(queue) => queue.front().cloned().expect("queued"),
            None => Err(CrlFetchError::Unreachable("not served".into())),
        }
    }
}

fn ok(der: &[u8]) -> Reply {
    Ok(der.to_vec())
}

fn unreachable() -> Reply {
    Err(CrlFetchError::Unreachable("refused".into()))
}

/// An OCSP source that must never be asked.
struct NoOcsp;

impl OcspSource for NoOcsp {
    fn fetch(&self, url: &CrlUrl, _request: &[u8], _deadline: Instant) -> Reply {
        panic!("OCSP fetch of {url}")
    }
}

fn roots() -> Roots {
    let mut roots = Roots::empty();
    roots.add_pem(ROOT).expect("chain test root");
    roots
}

fn options() -> ConnectOptions {
    ConnectOptions::new(GUARD, GUARD, GUARD).expect("valid options")
}

fn wide() -> Limits {
    Limits::new(16 * 1024, 64, 1024 * 1024).expect("valid limits")
}

fn config(source: Arc<Fake>) -> TlsConfig {
    TlsConfig::new(roots())
        .expect("config")
        .with_crl_source(source)
        .with_ocsp_source(Arc::new(NoOcsp))
}

fn server_config(
    chain: &[&[u8]],
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ServerConfig> {
    let chain = chain
        .iter()
        .flat_map(|pem| CertificateDer::pem_slice_iter(pem))
        .collect::<Result<Vec<_>, _>>()
        .expect("cert PEM");
    let key = PrivateKeyDer::from_pem_slice(LEAF_KEY).expect("key PEM");
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

fn hello(ex: Exchange<'_, ServerTls>) -> boneli_http::Result<()> {
    ex.respond(200, &Headers::new(), b"hello")
}

/// Listens on 127.0.0.1 and serves `count` TLS connections one after the
/// other with `200 hello`. Returns the handshake kind of each, `None`
/// where the handshake failed.
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

/// A server for one connection presenting `chain` (leaf first).
fn serve(chain: &[&[u8]]) -> SocketAddr {
    server(server_config(chain, &both()), 1).0
}

fn connect_to(addr: SocketAddr, config: &TlsConfig) -> boneli_https::Result<TlsStream<TcpStream>> {
    connect("localhost", addr.port(), config, &options())
}

/// One connection presenting `chain` and a GET over it: both statuses.
fn statuses(
    chain: &[&[u8]],
    config: &TlsConfig,
) -> boneli_https::Result<(RevocationStatus, Vec<RevocationStatus>)> {
    let tls = connect_to(serve(chain), config)?;
    let found = (
        tls.revocation().clone(),
        tls.intermediate_revocation().to_vec(),
    );
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    let head = RequestHead::new(
        Method::new("GET").expect("method"),
        Target::Origin("/".into()),
    );
    let mut response = conn.request(&head, RequestBody::None).expect("request");
    let mut body = Vec::new();
    response.read_to_end(&mut body).expect("body");
    assert_eq!((response.head.status, body), (200, b"hello".to_vec()));
    Ok(found)
}

fn checked(url: &str) -> RevocationStatus {
    RevocationStatus::Checked { url: url.into() }
}

fn revoked_by<T: std::fmt::Debug>(result: boneli_https::Result<T>) -> String {
    match result {
        Err(Error::Revoked { url }) => url,
        other => panic!("expected Revoked, got {other:?}"),
    }
}

/// The failure kinds of a `RevocationUnknown`, each with its URL.
fn failures<T: std::fmt::Debug>(
    result: boneli_https::Result<T>,
) -> Vec<(Option<String>, RevocationFailureKind)> {
    match result {
        Err(Error::RevocationUnknown(failures)) => {
            failures.into_iter().map(|f| (f.url, f.kind)).collect()
        }
        other => panic!("expected RevocationUnknown, got {other:?}"),
    }
}

/// The chain of the leaf under CA `n`, leaf first: `leaf`, CA `n` ... CA 1.
fn chain_of(leaf: &'static [u8], n: usize) -> Vec<&'static [u8]> {
    let mut chain = vec![leaf];
    chain.extend(CA[..n].iter().rev());
    chain
}

/// Every list of a chain under CA `n` served good: the root's at both
/// URLs, CA 1's to CA `n`'s at both.
fn all_good(n: usize) -> Vec<(String, Reply)> {
    let mut answers = Vec::new();
    for m in 1..=2 {
        answers.push((url(m, "root"), ok(&root_list(&[]))));
        for ca in 1..=n {
            answers.push((url(m, &format!("ca{ca}")), ok(&ca_list(ca, &[]))));
        }
    }
    answers
}

fn fake(answers: &[(String, Reply)]) -> Arc<Fake> {
    let pairs: Vec<(&str, Reply)> = answers
        .iter()
        .map(|(u, r)| (u.as_str(), r.clone()))
        .collect();
    Fake::new(&pairs)
}

// ----------------------------------------------------- the criteria

#[test]
fn root_issued_leaf_fetches_no_ca_list() {
    // A leaf of the CRL test CA, issued by a root: no intermediate.
    let source = Fake::new(&[(
        "http://crl.boneli.test/ca.crl",
        ok(include_bytes!("data/crl-ca-empty.crl")),
    )]);
    let mut roots = roots();
    roots
        .add_pem(include_bytes!("data/crl-ca.pem"))
        .expect("CRL CA");
    let config = TlsConfig::new(roots)
        .expect("config")
        .with_crl_source(source.clone());
    let (leaf, intermediates) =
        statuses(&[include_bytes!("data/crl-good.pem")], &config).expect("connect");
    assert_eq!(leaf, checked("http://crl.boneli.test/ca.crl"));
    assert!(intermediates.is_empty());
    assert_eq!(source.asked(), ["http://crl.boneli.test/ca.crl"]);
}

#[test]
fn root_sent_by_server_is_never_fetched() {
    // The self-signed root is sent too; it is the anchor, not on the path.
    let source = fake(&all_good(1));
    let mut chain = chain_of(LEAF_CA1, 1);
    chain.push(ROOT);
    let (leaf, intermediates) = statuses(&chain, &config(source.clone())).expect("connect");
    assert_eq!(leaf, checked(&url(1, "ca1")));
    assert_eq!(intermediates, [checked(&url(1, "root"))]);
    assert_eq!(source.asked(), [url(1, "root"), url(1, "ca1")]);
}

#[test]
fn stray_ca_certificate_is_never_fetched() {
    let source = fake(&all_good(1));
    let mut chain = chain_of(LEAF_CA1, 1);
    chain.push(STRAY_CA);
    statuses(&chain, &config(source.clone())).expect("connect");
    assert!(
        !source.asked().iter().any(|u| u.contains("169.254.169.254")),
        "{:?}",
        source.asked()
    );
    assert_eq!(source.asked(), [url(1, "root"), url(1, "ca1")]);
}

#[test]
fn revoked_issuing_ca_never_fetches_leaf_url() {
    // Acceptance 1: CA 1 is listed in the root's list; the leaf is not
    // listed in CA 1's, which is never asked for.
    let source = Fake::new(&[
        (&url(1, "root"), ok(&root_list(&[CA_SERIAL[0]]))),
        (&url(1, "ca1"), ok(&ca_list(1, &[]))),
    ]);
    assert_eq!(
        revoked_by(connect_to(
            serve(&chain_of(LEAF_CA1, 1)),
            &config(source.clone())
        )),
        url(1, "root")
    );
    assert_eq!(source.asked(), [url(1, "root")]);
}

#[test]
fn revoked_upper_ca_stops_before_lower_urls() {
    let mut answers = all_good(2);
    answers.insert(0, (url(1, "root"), ok(&root_list(&[CA_SERIAL[0]]))));
    let source = fake(&answers);
    assert_eq!(
        revoked_by(connect_to(
            serve(&chain_of(LEAF_CA2, 2)),
            &config(source.clone())
        )),
        url(1, "root")
    );
    assert_eq!(source.asked(), [url(1, "root")]);
}

#[test]
fn revoked_lower_ca_is_refused() {
    let mut answers = all_good(2);
    answers.insert(0, (url(1, "ca1"), ok(&ca_list(1, &[CA_SERIAL[1]]))));
    let source = fake(&answers);
    assert_eq!(
        revoked_by(connect_to(
            serve(&chain_of(LEAF_CA2, 2)),
            &config(source.clone())
        )),
        url(1, "ca1")
    );
    assert_eq!(source.asked(), [url(1, "root"), url(1, "ca1")]);
}

#[test]
fn unlisted_chain_passes_with_statuses() {
    // Acceptance 2.
    let source = fake(&all_good(2));
    let (leaf, intermediates) =
        statuses(&chain_of(LEAF_CA2, 2), &config(source.clone())).expect("connect");
    assert_eq!(leaf, checked(&url(1, "ca2")));
    assert_eq!(
        intermediates,
        [checked(&url(1, "ca1")), checked(&url(1, "root"))]
    );
    assert_eq!(
        source.asked(),
        [url(1, "root"), url(1, "ca1"), url(1, "ca2")]
    );
}

#[test]
fn openssl_lists_settle_ca1() {
    // Lists from an encoder independent of this file's.
    let source = Fake::new(&[
        (&url(1, "root"), ok(ROOT_EMPTY)),
        (&url(1, "ca1"), ok(&ca_list(1, &[]))),
    ]);
    let (_, intermediates) = statuses(&chain_of(LEAF_CA1, 1), &config(source)).expect("connect");
    assert_eq!(intermediates, [checked(&url(1, "root"))]);
    // The nameless onlyContainsCACerts form, listing CA 1.
    let source = Fake::new(&[(&url(1, "root"), ok(ROOT_LISTS_CA1))]);
    assert_eq!(
        revoked_by(connect_to(serve(&chain_of(LEAF_CA1, 1)), &config(source))),
        url(1, "root")
    );
}

#[test]
fn intermediate_without_point_passes_unchecked() {
    // D2: CA 1 without a point, the leaf checked as usual.
    let source = fake(&all_good(1));
    let (leaf, intermediates) =
        statuses(&[LEAF_CA1, CA1_NO_POINT], &config(source.clone())).expect("connect");
    assert_eq!(leaf, checked(&url(1, "ca1")));
    assert_eq!(intermediates, [RevocationStatus::NoRevocationSource]);
    assert_eq!(source.asked(), [url(1, "ca1")]);
}

#[test]
fn intermediate_with_ldap_point_only_passes_unchecked() {
    let source = fake(&all_good(1));
    let (_, intermediates) =
        statuses(&[LEAF_CA1, CA1_LDAP], &config(source.clone())).expect("connect");
    assert_eq!(intermediates, [RevocationStatus::NoRevocationSource]);
    assert_eq!(source.asked(), [url(1, "ca1")]);
}

#[test]
fn intermediate_tries_at_most_four_urls() {
    let source = Fake::new(&[
        ("http://crl5.boneli.test/root.crl", ok(&root_list(&[]))),
        (&url(1, "ca1"), ok(&ca_list(1, &[]))),
    ]);
    let found = failures(connect_to(
        serve(&[LEAF_CA1, CA1_FIVE]),
        &config(source.clone()),
    ));
    assert_eq!(found.len(), 4);
    assert!(
        found
            .iter()
            .all(|(_, k)| *k == RevocationFailureKind::Unreachable)
    );
    let expected: Vec<String> = (1..=4).map(|n| url(n, "root")).collect();
    assert_eq!(source.asked(), expected);
    // The fourth URL settles it.
    let source = Fake::new(&[
        ("http://crl4.boneli.test/root.crl", ok(&root_list(&[]))),
        (&url(1, "ca1"), ok(&ca_list(1, &[]))),
    ]);
    let (_, intermediates) = statuses(&[LEAF_CA1, CA1_FIVE], &config(source)).expect("connect");
    assert_eq!(intermediates, [checked("http://crl4.boneli.test/root.crl")]);
}

#[test]
fn ocsp_leaf_under_revoked_ca_is_refused() {
    // NoOcsp panics if the leaf's OCSP check ran.
    let source = Fake::new(&[(&url(1, "root"), ok(&root_list(&[CA_SERIAL[0]])))]);
    assert_eq!(
        revoked_by(connect_to(serve(&chain_of(LEAF_OCSP, 1)), &config(source))),
        url(1, "root")
    );
}

#[test]
fn sourceless_leaf_under_revoked_ca_is_refused() {
    let source = Fake::new(&[(&url(1, "root"), ok(&root_list(&[CA_SERIAL[0]])))]);
    assert_eq!(
        revoked_by(connect_to(serve(&chain_of(LEAF_NONE, 1)), &config(source))),
        url(1, "root")
    );
    // Unlisted: the intermediate is checked, the leaf passes unchecked.
    let source = Fake::new(&[(&url(1, "root"), ok(&root_list(&[])))]);
    let (leaf, intermediates) =
        statuses(&chain_of(LEAF_NONE, 1), &config(source)).expect("connect");
    assert_eq!(leaf, RevocationStatus::NoRevocationSource);
    assert_eq!(intermediates, [checked(&url(1, "root"))]);
}

// ------------------------------------------------------------- budget

#[test]
fn six_intermediates_pass_within_budget() {
    let source = fake(&all_good(6));
    let (leaf, intermediates) =
        statuses(&chain_of(LEAF_CA6, 6), &config(source.clone())).expect("connect");
    assert_eq!(leaf, checked(&url(1, "ca6")));
    let expected: Vec<RevocationStatus> = (1..=5)
        .rev()
        .map(|n| checked(&url(1, &format!("ca{n}"))))
        .chain([checked(&url(1, "root"))])
        .collect();
    assert_eq!(intermediates, expected);
    // Six CA lists, then the leaf's: 6 <= MAX_CA_CRL_FETCHES.
    assert_eq!(source.asked().len(), 7);
    const { assert!(6 <= MAX_CA_CRL_FETCHES) };
}

/// Five intermediates whose first URLs all fail and whose mirrors answer.
fn five_with_failing_first_urls() -> Arc<Fake> {
    let mut answers = vec![(url(2, "root"), ok(&root_list(&[])))];
    for ca in 1..=5 {
        answers.push((url(2, &format!("ca{ca}")), ok(&ca_list(ca, &[]))));
    }
    // The leaf's list.
    answers.push((url(1, "ca5"), ok(&ca_list(5, &[]))));
    fake(&answers)
}

#[test]
fn ninth_ca_fetch_fails_closed() {
    // Acceptance 3. From the anchor side down, CA 1 to CA 4 take two
    // fetches each (fetches 1 to 8); both URLs of CA 5, the leaf's issuer,
    // find the budget spent and fail closed without a fetch.
    let source = five_with_failing_first_urls();
    let result = connect_to(serve(&chain_of(LEAF_CA5, 5)), &config(source.clone()));
    let error = match result {
        Err(e) => e,
        Ok(_) => panic!("passed"),
    };
    let text = error.to_string();
    assert!(text.contains("intermediate 1 of 5"), "{text}");
    assert_eq!(
        failures::<()>(Err(error)),
        [
            (Some(url(1, "ca4")), RevocationFailureKind::LimitReached),
            (Some(url(2, "ca4")), RevocationFailureKind::LimitReached),
        ]
    );
    assert_eq!(source.asked().len(), MAX_CA_CRL_FETCHES);
    assert_eq!(MAX_CA_CRL_FETCHES, 8);
}

#[test]
fn five_intermediates_cold_cache_pass() {
    let source = fake(&all_good(5));
    let (_, intermediates) =
        statuses(&chain_of(LEAF_CA5, 5), &config(source.clone())).expect("connect");
    assert_eq!(intermediates.len(), 5);
    // Five CA lists and the leaf's.
    assert_eq!(source.asked().len(), 6);
}

#[test]
fn leaf_fetches_do_not_count_against_the_budget() {
    // CA 1 to CA 3 fail their first URL (six fetches), CA 4 and CA 5 pass
    // on theirs (two more): the budget is spent, and the leaf's own list
    // is still fetched, a ninth fetch.
    let answers = vec![
        (url(2, "root"), ok(&root_list(&[]))),
        (url(2, "ca1"), ok(&ca_list(1, &[]))),
        (url(2, "ca2"), ok(&ca_list(2, &[]))),
        (url(1, "ca3"), ok(&ca_list(3, &[]))),
        (url(1, "ca4"), ok(&ca_list(4, &[]))),
        (url(1, "ca5"), ok(&ca_list(5, &[]))),
    ];
    let source = fake(&answers);
    let (leaf, intermediates) =
        statuses(&chain_of(LEAF_CA5, 5), &config(source.clone())).expect("connect");
    assert_eq!(leaf, checked(&url(1, "ca5")));
    assert_eq!(intermediates.len(), 5);
    assert_eq!(source.asked().len(), MAX_CA_CRL_FETCHES + 1);
}

// --------------------------------------------- failures of one list

#[test]
fn ca_list_size_cap_is_inclusive() {
    for (len, kind) in [
        (MAX_CA_CRL_BYTES, RevocationFailureKind::Malformed),
        (MAX_CA_CRL_BYTES + 1, RevocationFailureKind::TooLarge),
    ] {
        let source = Fake::new(&[
            (&url(1, "root"), Ok(vec![0; len])),
            (&url(2, "root"), Ok(vec![0; len])),
        ]);
        assert_eq!(
            failures(connect_to(serve(&chain_of(LEAF_CA1, 1)), &config(source))),
            [(Some(url(1, "root")), kind), (Some(url(2, "root")), kind)],
            "{len}"
        );
    }
    assert_eq!(MAX_CA_CRL_BYTES, 1_048_576);
}

#[test]
fn ca_list_unreachable_fails_closed() {
    // Acceptance 4, each case through both URLs.
    let source = Fake::new(&[(&url(1, "ca1"), ok(&ca_list(1, &[])))]);
    let result = connect_to(serve(&chain_of(LEAF_CA1, 1)), &config(source));
    assert_eq!(
        failures(result),
        [
            (Some(url(1, "root")), RevocationFailureKind::Unreachable),
            (Some(url(2, "root")), RevocationFailureKind::Unreachable),
        ]
    );
}

#[test]
fn ca_list_malformed_fails_closed() {
    let good = root_list(&[]);
    let mut trailing = good.clone();
    trailing.push(0);
    for (what, bytes) in [
        ("truncated", good[..good.len() - 1].to_vec()),
        ("trailing byte", trailing),
        ("HTML", b"<html><body>Not a CRL</body></html>".to_vec()),
    ] {
        let source = Fake::new(&[
            (&url(1, "root"), Ok(bytes.clone())),
            (&url(2, "root"), Ok(bytes)),
        ]);
        assert_eq!(
            failures(connect_to(serve(&chain_of(LEAF_CA1, 1)), &config(source))),
            [
                (Some(url(1, "root")), RevocationFailureKind::Malformed),
                (Some(url(2, "root")), RevocationFailureKind::Malformed),
            ],
            "{what}"
        );
    }
}

#[test]
fn ca_list_expired_fails_closed() {
    // 2026-01-01 to 2026-01-08, long past.
    let expired = list_at(ROOT, ROOT_KEY, 1_767_225_600, 1_767_830_400, &[]);
    let source = Fake::new(&[
        (&url(1, "root"), ok(&expired)),
        (&url(2, "root"), ok(&expired)),
    ]);
    let config = config(source.clone());
    for _ in 0..2 {
        assert_eq!(
            failures(connect_to(serve(&chain_of(LEAF_CA1, 1)), &config)),
            [
                (Some(url(1, "root")), RevocationFailureKind::Expired),
                (Some(url(2, "root")), RevocationFailureKind::Expired),
            ]
        );
    }
    // Asked again each time: not cached.
    assert_eq!(source.asked().len(), 4);
}

#[test]
fn ca_list_of_another_issuer_and_forged_fail_closed() {
    // CA 1's list where the root's belongs, and the root's name under the
    // CA key.
    for bytes in [ca_list(1, &[]), list(ROOT, CA_KEY, &[])] {
        let source = Fake::new(&[(&url(1, "root"), ok(&bytes)), (&url(2, "root"), ok(&bytes))]);
        assert_eq!(
            failures(connect_to(serve(&chain_of(LEAF_CA1, 1)), &config(source))),
            [
                (Some(url(1, "root")), RevocationFailureKind::NotSettled),
                (Some(url(2, "root")), RevocationFailureKind::NotSettled),
            ]
        );
    }
}

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
fn tls_dial_deadline_cuts_ca_fetches() {
    let source = Arc::new(Waiting {
        deadlines: Mutex::new(Vec::new()),
    });
    let config = TlsConfig::new(roots())
        .expect("config")
        .with_crl_source(source.clone());
    let addr = serve(&chain_of(LEAF_CA2, 2));
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

// ------------------------------------------------------------- cache

#[test]
fn ca_revocation_is_not_overruled_by_mirror() {
    let source = Fake::new(&[
        (&url(1, "root"), ok(&root_list(&[CA_SERIAL[0]]))),
        (&url(2, "root"), ok(&root_list(&[]))),
    ]);
    assert_eq!(
        revoked_by(connect_to(
            serve(&chain_of(LEAF_CA1, 1)),
            &config(source.clone())
        )),
        url(1, "root")
    );
    assert_eq!(source.asked(), [url(1, "root")]);
}

#[test]
fn cached_ca_revocation_wins_over_other_point() {
    // First: crl1 unreachable, crl2 revokes CA 1. Then crl1 serves an
    // older list without it, which must not undo the cached revocation.
    let now = now();
    let older = list_at(ROOT, ROOT_KEY, now - 7_200, now + 86_400, &[]);
    let source = Fake::new(&[
        (&url(1, "root"), unreachable()),
        (&url(2, "root"), ok(&root_list(&[CA_SERIAL[0]]))),
    ]);
    let config = config(source.clone());
    assert_eq!(
        revoked_by(connect_to(serve(&chain_of(LEAF_CA1, 1)), &config)),
        url(2, "root")
    );
    source.set(&url(1, "root"), ok(&older));
    assert_eq!(
        revoked_by(connect_to(serve(&chain_of(LEAF_CA1, 1)), &config)),
        url(2, "root")
    );
    assert_eq!(
        source.asked(),
        [url(1, "root"), url(2, "root"), url(1, "root")]
    );
}

#[test]
fn ca_list_is_cached_per_url() {
    let source = fake(&all_good(2));
    let config = config(source.clone());
    let (addr, _server) = server(server_config(&chain_of(LEAF_CA2, 2), &both()), 2);
    let first = connect_to(addr, &config).expect("first");
    assert_eq!(first.intermediate_revocation().len(), 2);
    drop(first);
    source.clear();
    let second = connect_to(addr, &config).expect("second");
    assert_eq!(
        second.intermediate_revocation(),
        [checked(&url(1, "ca1")), checked(&url(1, "root"))]
    );
    assert!(source.asked().is_empty(), "{:?}", source.asked());
}

#[test]
fn url_shared_by_leaf_and_ca_points() {
    // crl1/ca1.crl is CA 2's point and the point of the leaf under CA 1:
    // the two caches keep the list apart, so each check fetches it once.
    let source = fake(&all_good(2));
    let config = config(source.clone());
    statuses(&chain_of(LEAF_CA2, 2), &config).expect("leaf under CA 2");
    source.clear();
    let (leaf, intermediates) = statuses(&chain_of(LEAF_CA1, 1), &config).expect("leaf under CA 1");
    assert_eq!(leaf, checked(&url(1, "ca1")));
    assert_eq!(intermediates, [checked(&url(1, "root"))]);
    // The root's list came from the CA cache; CA 1's list was fetched
    // again for the leaf cache.
    assert_eq!(source.asked(), [url(1, "ca1")]);
}

// -------------------------------------------------------- resumption

#[test]
fn resumed_tls12_session_with_revoked_ca_is_refused_again() {
    let (addr, server) = server(
        server_config(&chain_of(LEAF_CA1, 1), &[&rustls::version::TLS12]),
        2,
    );
    let source = Fake::new(&[(&url(1, "root"), ok(&root_list(&[CA_SERIAL[0]])))]);
    let config = config(source);
    assert_eq!(revoked_by(connect_to(addr, &config)), url(1, "root"));
    assert_eq!(revoked_by(connect_to(addr, &config)), url(1, "root"));
    let kinds = server.join().expect("server");
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
    );
}

#[test]
fn resumed_tls13_session_checks_intermediates_again() {
    let (addr, server) = server(
        server_config(&chain_of(LEAF_CA2, 2), &[&rustls::version::TLS13]),
        2,
    );
    let source = fake(&all_good(2));
    let config = config(source.clone());
    for _ in 0..2 {
        // The GET reads the session tickets that arrive before the
        // response.
        let tls = connect_to(addr, &config).expect("connect");
        assert_eq!(
            tls.intermediate_revocation(),
            [checked(&url(1, "ca1")), checked(&url(1, "root"))]
        );
        let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
        let head = RequestHead::new(
            Method::new("GET").expect("method"),
            Target::Origin("/".into()),
        );
        let mut response = conn.request(&head, RequestBody::None).expect("request");
        let mut body = Vec::new();
        response.read_to_end(&mut body).expect("body");
    }
    let kinds = server.join().expect("server");
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
    );
    // The second check used the cached lists.
    assert_eq!(
        source.asked(),
        [url(1, "root"), url(1, "ca1"), url(1, "ca2")]
    );
}

// ------------------------------------------------------ CONNECT tunnels

/// Copies `from` into `to` until the end of the stream, then shuts down
/// `to` for writing so that the far side sees the end too.
fn relay(mut from: impl Read, mut to: impl Write, shutdown: impl FnOnce() -> io::Result<()>) {
    let _ = io::copy(&mut from, &mut to);
    let _ = shutdown();
}

#[test]
fn tunnel_checks_intermediates() {
    let tls_addr = serve(&chain_of(LEAF_CA1, 1));
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
    let source = Fake::new(&[(&url(1, "root"), ok(&root_list(&[CA_SERIAL[0]])))]);
    assert_eq!(
        revoked_by(connect_over(
            tunnel,
            "localhost",
            &config(source),
            &options()
        )),
        url(1, "root")
    );
    let _ = proxy.join();
}
