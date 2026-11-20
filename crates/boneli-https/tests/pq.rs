//! The hybrid post-quantum key exchange X25519MLKEM768 (RFC 10024;
//! ADR-016) against local rustls servers on 127.0.0.1: the group is
//! negotiated where the server offers it, X25519 is picked without a
//! retry where it does not, the retry, TLS 1.2 and resumption paths, the
//! ClientHello on the wire, `TlsConfig::classical`, and servers that send
//! a malformed hybrid share.
//!
//! The server half of the hybrid here (`ServerHybrid`) is written from the
//! same reading of RFC 10024 as the client, so these tests prove the
//! integration with rustls, not interoperability; `tests/interop.rs`
//! checks the reading against OpenSSL.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use boneli_http::{
    Connection, Exchange, Headers, IdleCheck, Limits, Method, RequestBody, RequestHead,
    ServerLimits, Target, Transport, connect_tunnel,
};
use boneli_https::{ConnectOptions, Error, Roots, TlsConfig, connect, connect_over, fill_random};
use ml_kem::EncapsulationKey768;
use ml_kem::array::Array;
use rustls::crypto::ring::kx_group;
use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{
    AlertDescription, HandshakeKind, NamedGroup, PeerMisbehaved, ProtocolVersion, ServerConfig,
    ServerConnection, StreamOwned,
};

const CA: &[u8] = include_bytes!("data/ca.pem");
const LEAF: &[u8] = include_bytes!("data/leaf.pem");
const LEAF_KEY: &[u8] = include_bytes!("data/leaf.key");

/// Bounds every blocking read in these tests, so that a bug ends in a
/// failure instead of a hang; far above any local delivery time.
const GUARD: Duration = Duration::from_secs(10);

// ------------------------------------------------------------- helpers
// Copied from tests/tls.rs, with the server's provider as a parameter.

fn test_roots() -> Roots {
    let mut roots = Roots::empty();
    assert_eq!(roots.add_pem(CA).expect("test CA"), 1);
    roots
}

fn hybrid_config() -> TlsConfig {
    TlsConfig::new(test_roots()).expect("valid config")
}

fn classical_config() -> TlsConfig {
    TlsConfig::classical(test_roots()).expect("valid config")
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

/// A server config for the test leaf with the given key exchange groups
/// and versions.
fn server_config(
    groups: Vec<&'static dyn SupportedKxGroup>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Arc<ServerConfig> {
    let chain = CertificateDer::pem_slice_iter(LEAF)
        .collect::<Result<Vec<_>, _>>()
        .expect("cert PEM");
    let key = PrivateKeyDer::from_pem_slice(LEAF_KEY).expect("key PEM");
    let provider = CryptoProvider {
        kx_groups: groups,
        ..rustls::crypto::ring::default_provider()
    };
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server cert");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn tls13_server(groups: Vec<&'static dyn SupportedKxGroup>) -> Arc<ServerConfig> {
    server_config(groups, &[&rustls::version::TLS13])
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

/// Accepts one TCP connection and completes the server handshake.
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

/// What the server saw of one handshake.
#[derive(Debug, PartialEq)]
struct Seen {
    kind: Option<HandshakeKind>,
    group: Option<NamedGroup>,
    version: Option<ProtocolVersion>,
}

/// Listens on 127.0.0.1 and serves `count` TLS connections one after the
/// other, each with a `boneli-http` server that answers `200 hello`, until
/// the client goes away. Returns what the server saw of each handshake.
fn http_server(
    config: Arc<ServerConfig>,
    count: usize,
) -> (SocketAddr, thread::JoinHandle<io::Result<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..count {
            let stream = accept_tls(&listener, Arc::clone(&config))?;
            seen.push(Seen {
                kind: stream.conn.handshake_kind(),
                group: stream
                    .conn
                    .negotiated_key_exchange_group()
                    .map(|g| g.name()),
                version: stream.conn.protocol_version(),
            });
            let five = Duration::from_secs(5);
            let limits = ServerLimits::new(wide(), 4, five, five, five).expect("server limits");
            // The client drops the connection without close_notify; that
            // ends the loop with an error the tests do not look at.
            let _ = boneli_http::serve_connection(ServerTls(stream), &limits, &hello);
        }
        Ok(seen)
    });
    (addr, handle)
}

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

/// Connects to `addr` as `localhost`, checks the group the client
/// reports, runs one GET and drops the connection.
fn handshake_and_get(addr: SocketAddr, config: &TlsConfig, group: NamedGroup) {
    let tls = connect("localhost", addr.port(), config, &options()).expect("handshake");
    assert_eq!(tls.key_exchange_group(), Some(group), "client side");
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
}

fn seen(handle: thread::JoinHandle<io::Result<Vec<Seen>>>) -> Vec<Seen> {
    handle.join().expect("server thread").expect("server")
}

fn full_13(group: NamedGroup) -> Seen {
    Seen {
        kind: Some(HandshakeKind::Full),
        group: Some(group),
        version: Some(ProtocolVersion::TLSv1_3),
    }
}

// ---------------------------------------- the server half of the hybrid

/// What a hostile server does to its hybrid share.
#[derive(Clone, Copy, Debug)]
enum Mutation {
    None,
    /// 1119 bytes: the last byte dropped.
    Short,
    /// 1121 bytes: one byte appended.
    Long,
    /// An all-zero X25519 part.
    ZeroX25519,
    /// X25519 first, then the ciphertext.
    Reversed,
    /// One bit of the ciphertext flipped after encapsulation.
    TamperCiphertext,
}

/// The server side of X25519MLKEM768 (RFC 10024, sections 4.1 to 4.3),
/// test-only: it splits the client's 1216-byte share, checks the
/// encapsulation key (FIPS 203, section 7.2) and encapsulates to it, runs
/// ring's X25519 on the rest, and applies `mutation` to its share.
#[derive(Debug)]
struct ServerHybrid {
    mutation: Mutation,
}

static SERVER_HYBRID: ServerHybrid = ServerHybrid {
    mutation: Mutation::None,
};
static SHORT: ServerHybrid = ServerHybrid {
    mutation: Mutation::Short,
};
static LONG: ServerHybrid = ServerHybrid {
    mutation: Mutation::Long,
};
static ZERO_X25519: ServerHybrid = ServerHybrid {
    mutation: Mutation::ZeroX25519,
};
static REVERSED: ServerHybrid = ServerHybrid {
    mutation: Mutation::Reversed,
};
static TAMPERED: ServerHybrid = ServerHybrid {
    mutation: Mutation::TamperCiphertext,
};

impl SupportedKxGroup for ServerHybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        Err(rustls::Error::General(
            "test server: server role only".into(),
        ))
    }

    fn start_and_complete(
        &self,
        client_share: &[u8],
    ) -> Result<CompletedKeyExchange, rustls::Error> {
        let invalid = || rustls::Error::from(PeerMisbehaved::InvalidKeyShare);
        if client_share.len() != 1216 {
            return Err(invalid());
        }
        let (ek, x25519) = client_share.split_at(1184);
        let ek = EncapsulationKey768::new(&Array::try_from(ek).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let mut m = [0u8; 32];
        fill_random(&mut m).map_err(|_| rustls::Error::FailedToGetRandomBytes)?;
        let (ct, k) = ek.encapsulate_deterministic(&Array::from(m));
        let classical = kx_group::X25519.start_and_complete(x25519)?;
        let mut share = [&ct[..], &classical.pub_key[..]].concat();
        match self.mutation {
            Mutation::None => {}
            Mutation::Short => {
                share.pop();
            }
            Mutation::Long => share.push(0),
            Mutation::ZeroX25519 => share[1088..].fill(0),
            Mutation::Reversed => share = [&classical.pub_key[..], &ct[..]].concat(),
            Mutation::TamperCiphertext => share[0] ^= 1,
        }
        let secret = [&k[..], classical.secret.secret_bytes()].concat();
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key: share,
            secret: SharedSecret::from(secret),
        })
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

// ------------------------------------------------ negotiation (AC 1, 2)

#[test]
fn hybrid_negotiated_when_server_offers_it() {
    let (addr, server) = http_server(tls13_server(vec![&SERVER_HYBRID, kx_group::X25519]), 1);
    handshake_and_get(addr, &hybrid_config(), NamedGroup::X25519MLKEM768);
    assert_eq!(seen(server), [full_13(NamedGroup::X25519MLKEM768)]);
}

#[test]
fn falls_back_to_x25519_without_retry() {
    // ring's defaults: X25519, P-256, P-384. `Full`, not
    // `FullWithHelloRetryRequest`: the second key share was used.
    let defaults = rustls::crypto::ring::default_provider().kx_groups;
    let (addr, server) = http_server(tls13_server(defaults), 1);
    handshake_and_get(addr, &hybrid_config(), NamedGroup::X25519);
    assert_eq!(seen(server), [full_13(NamedGroup::X25519)]);
}

#[test]
fn p256_only_server_retries_and_completes() {
    let (addr, server) = http_server(tls13_server(vec![kx_group::SECP256R1]), 1);
    handshake_and_get(addr, &hybrid_config(), NamedGroup::secp256r1);
    assert_eq!(
        seen(server),
        [Seen {
            kind: Some(HandshakeKind::FullWithHelloRetryRequest),
            group: Some(NamedGroup::secp256r1),
            version: Some(ProtocolVersion::TLSv1_3),
        }]
    );
}

#[test]
fn tls12_server_gets_x25519() {
    let defaults = rustls::crypto::ring::default_provider().kx_groups;
    let (addr, server) = http_server(server_config(defaults, &[&rustls::version::TLS12]), 1);
    let tls = connect("localhost", addr.port(), &hybrid_config(), &options()).expect("1.2");
    assert_eq!(tls.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    assert_eq!(tls.key_exchange_group(), Some(NamedGroup::X25519));
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn).0, 200);
    drop(conn);
    let seen = seen(server);
    assert_eq!(seen[0].group, Some(NamedGroup::X25519));
    assert_eq!(seen[0].version, Some(ProtocolVersion::TLSv1_2));
}

#[test]
fn resumption_keeps_hybrid() {
    let (addr, server) = http_server(tls13_server(vec![&SERVER_HYBRID, kx_group::X25519]), 2);
    let config = hybrid_config();
    // The GET reads the session tickets that arrive before the response.
    handshake_and_get(addr, &config, NamedGroup::X25519MLKEM768);
    handshake_and_get(addr, &config, NamedGroup::X25519MLKEM768);
    let seen = seen(server);
    assert_eq!(seen[0], full_13(NamedGroup::X25519MLKEM768));
    assert_eq!(
        seen[1],
        Seen {
            kind: Some(HandshakeKind::Resumed),
            group: Some(NamedGroup::X25519MLKEM768),
            version: Some(ProtocolVersion::TLSv1_3),
        }
    );
}

#[test]
fn hrr_into_hybrid_after_x25519_hint() {
    // The first server picks X25519, so rustls remembers X25519 for
    // `localhost` and the next ClientHello carries only an X25519 share.
    // A hybrid-only server under the same name then asks for a retry,
    // and the client starts the hybrid again.
    let config = hybrid_config();
    let (first, first_server) = http_server(tls13_server(vec![kx_group::X25519]), 1);
    handshake_and_get(first, &config, NamedGroup::X25519);
    assert_eq!(seen(first_server), [full_13(NamedGroup::X25519)]);

    let (second, second_server) = http_server(tls13_server(vec![&SERVER_HYBRID]), 1);
    handshake_and_get(second, &config, NamedGroup::X25519MLKEM768);
    assert_eq!(
        seen(second_server),
        [Seen {
            kind: Some(HandshakeKind::FullWithHelloRetryRequest),
            group: Some(NamedGroup::X25519MLKEM768),
            version: Some(ProtocolVersion::TLSv1_3),
        }]
    );
}

// ------------------------------------------------ TlsConfig::classical

#[test]
fn classical_negotiates_x25519_with_hybrid_server() {
    let (addr, server) = http_server(tls13_server(vec![&SERVER_HYBRID, kx_group::X25519]), 1);
    handshake_and_get(addr, &classical_config(), NamedGroup::X25519);
    assert_eq!(seen(server), [full_13(NamedGroup::X25519)]);
}

// ------------------------------------------------- ClientHello on the wire

/// What a ClientHello offers.
#[derive(Debug)]
struct Hello {
    /// The length of the handshake message, header included.
    handshake_len: usize,
    /// `supported_groups` (0x000a).
    groups: Vec<u16>,
    /// `key_share` (0x0033): group and key exchange bytes.
    shares: Vec<(u16, Vec<u8>)>,
}

/// A cursor over bytes that panics, naming the field, when one runs past
/// the end.
struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &str) -> &'a [u8] {
        assert!(self.bytes.len() >= n, "ClientHello ends inside {what}");
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        head
    }

    fn u8(&mut self, what: &str) -> usize {
        usize::from(self.take(1, what)[0])
    }

    fn u16(&mut self, what: &str) -> usize {
        let b = self.take(2, what);
        usize::from(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self, what: &str) -> usize {
        let b = self.take(3, what);
        (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
    }

    fn vec8(&mut self, what: &str) -> &'a [u8] {
        let n = self.u8(what);
        self.take(n, what)
    }

    fn vec16(&mut self, what: &str) -> &'a [u8] {
        let n = self.u16(what);
        self.take(n, what)
    }
}

/// Parses one TLS record that holds a whole ClientHello (RFC 8446,
/// sections 5.1 and 4.1.2) down to its supported groups and key shares.
fn parse_client_hello(record: &[u8]) -> Hello {
    let mut c = Cursor { bytes: record };
    assert_eq!(c.u8("record type"), 22, "a handshake record");
    c.take(2, "record version");
    let record_len = c.u16("record length");
    assert_eq!(record_len, c.bytes.len(), "one record, read whole");
    let handshake_len = c.bytes.len();
    assert_eq!(c.u8("handshake type"), 1, "a ClientHello");
    assert_eq!(c.u24("handshake length") + 4, handshake_len, "one message");
    c.take(2, "legacy_version");
    c.take(32, "random");
    c.vec8("legacy_session_id");
    c.vec16("cipher_suites");
    c.vec8("legacy_compression_methods");
    let mut exts = Cursor {
        bytes: c.vec16("extensions"),
    };
    assert!(c.bytes.is_empty(), "nothing after the extensions");
    let (mut groups, mut shares) = (None, None);
    while !exts.bytes.is_empty() {
        let kind = exts.u16("extension type");
        let mut body = Cursor {
            bytes: exts.vec16("extension body"),
        };
        match kind {
            0x000a => {
                let mut list = Cursor {
                    bytes: body.vec16("named_group_list"),
                };
                let mut found = Vec::new();
                while !list.bytes.is_empty() {
                    found.push(u16::try_from(list.u16("named group")).expect("u16"));
                }
                assert!(groups.replace(found).is_none(), "one supported_groups");
            }
            0x0033 => {
                let mut list = Cursor {
                    bytes: body.vec16("client_shares"),
                };
                let mut found = Vec::new();
                while !list.bytes.is_empty() {
                    let group = u16::try_from(list.u16("share group")).expect("u16");
                    found.push((group, list.vec16("key_exchange").to_vec()));
                }
                assert!(shares.replace(found).is_none(), "one key_share");
            }
            _ => {}
        }
    }
    Hello {
        handshake_len,
        groups: groups.expect("supported_groups"),
        shares: shares.expect("key_share"),
    }
}

/// Connects with `config` to a TCP listener that reads the client's first
/// record whole and then closes, and parses it.
fn client_hello(config: &TlsConfig) -> Hello {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let reader = thread::spawn(move || -> io::Result<Vec<u8>> {
        let (mut tcp, _) = listener.accept()?;
        tcp.set_read_timeout(Some(GUARD))?;
        let mut record = vec![0u8; 5];
        tcp.read_exact(&mut record)?;
        let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
        record.resize(5 + len, 0);
        tcp.read_exact(&mut record[5..])?;
        tcp.shutdown(Shutdown::Both)?;
        Ok(record)
    });
    let result = connect("127.0.0.1", port, config, &options());
    assert!(result.is_err(), "the listener sends no ServerHello");
    parse_client_hello(&reader.join().expect("reader thread").expect("record"))
}

#[test]
fn client_hello_offers_hybrid_then_x25519_shares() {
    let hello = client_hello(&hybrid_config());
    assert_eq!(hello.groups, [0x11ec, 0x001d, 0x0017, 0x0018]);
    let shares: Vec<(u16, usize)> = hello.shares.iter().map(|(g, k)| (*g, k.len())).collect();
    assert_eq!(shares, [(0x11ec, 1216), (0x001d, 32)]);
    assert_eq!(
        &hello.shares[0].1[1184..],
        &hello.shares[1].1[..],
        "the hybrid share ends in the X25519 share"
    );
}

#[test]
fn classical_client_hello_offers_no_hybrid() {
    let classical = client_hello(&classical_config());
    assert_eq!(classical.groups, [0x001d, 0x0017, 0x0018]);
    let shares: Vec<(u16, usize)> = classical
        .shares
        .iter()
        .map(|(g, k)| (*g, k.len()))
        .collect();
    assert_eq!(shares, [(0x001d, 32)]);
    assert!(!classical.groups.contains(&0x11ec));
    assert!(classical.shares.iter().all(|(g, _)| *g != 0x11ec));
    // 1216 bytes of share, 4 of its entry header and 2 for the group in
    // `supported_groups`. Both configs are fresh: no resumption ticket.
    let hybrid = client_hello(&hybrid_config());
    assert_eq!(hybrid.handshake_len - classical.handshake_len, 1222);
}

// --------------------------------------------------- CONNECT tunnels

/// Copies `from` into `to` until the end of the stream, then shuts down
/// `to` for writing so that the far side sees the end too.
fn relay(mut from: impl Read, mut to: impl Write, shutdown: impl FnOnce() -> io::Result<()>) {
    let _ = io::copy(&mut from, &mut to);
    let _ = shutdown();
}

#[test]
fn hybrid_through_connect_tunnel() {
    // The ClientHello is larger than one TCP segment of a typical path
    // (about 1460 bytes) and crosses the proxy as several reads.
    let (tls_addr, server) = http_server(tls13_server(vec![&SERVER_HYBRID, kx_group::X25519]), 1);
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
    let tls = connect_over(tunnel, "localhost", &hybrid_config(), &options())
        .expect("TLS over the tunnel");
    assert_eq!(tls.key_exchange_group(), Some(NamedGroup::X25519MLKEM768));
    let mut conn = Connection::new(tls, "localhost", wide()).expect("connection");
    assert_eq!(get(&mut conn), (200, b"hello".to_vec()));
    drop(conn);
    proxy.join().expect("proxy thread").expect("proxy");
    assert_eq!(seen(server), [full_13(NamedGroup::X25519MLKEM768)]);
}

// ------------------------------------------------------ hostile servers

/// Runs a hybrid-only server whose share `group` mutates, connects, and
/// returns the client's error and the server's error. Afterwards no
/// further connection may be waiting: the client does not retry without
/// the hybrid.
fn hostile(group: &'static ServerHybrid) -> (Error, io::Error) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let config = tls13_server(vec![group]);
    let server = thread::spawn(move || {
        let result = accept_tls(&listener, config).map(|_| ());
        (result, listener)
    });
    let client = connect("127.0.0.1", port, &hybrid_config(), &options())
        .expect_err("a malformed hybrid share");
    let (result, listener) = server.join().expect("server thread");
    let server_err = result.expect_err("the server sees the handshake fail");
    listener.set_nonblocking(true).expect("nonblocking");
    assert_eq!(
        listener.accept().err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock),
        "exactly one connection: no retry"
    );
    (client, server_err)
}

/// The rustls error inside an `io::Error` of the server side.
fn tls_error(err: &io::Error) -> Option<&rustls::Error> {
    err.get_ref()?.downcast_ref::<rustls::Error>()
}

fn assert_illegal_parameter(group: &'static ServerHybrid) {
    let (client, server) = hostile(group);
    assert!(
        matches!(
            client,
            Error::Tls(rustls::Error::PeerMisbehaved(
                PeerMisbehaved::InvalidKeyShare
            ))
        ),
        "{group:?}: {client:?}"
    );
    assert!(
        matches!(
            tls_error(&server),
            Some(rustls::Error::AlertReceived(
                AlertDescription::IllegalParameter
            ))
        ),
        "{group:?}: {server:?}"
    );
}

#[test]
fn short_server_share_is_illegal_parameter() {
    assert_illegal_parameter(&SHORT);
}

#[test]
fn long_server_share_is_illegal_parameter() {
    assert_illegal_parameter(&LONG);
}

#[test]
fn zero_x25519_server_share_is_illegal_parameter() {
    assert_illegal_parameter(&ZERO_X25519);
}

#[test]
fn reversed_server_share_fails_handshake() {
    // The halves land in the wrong places: the client derives a key the
    // server does not have and cannot decrypt the server's flight. A
    // `DecryptError`, so the hybrid was negotiated and then failed; a
    // client without the hybrid would get the server's handshake_failure.
    let (client, _server) = hostile(&REVERSED);
    assert!(
        matches!(client, Error::Tls(rustls::Error::DecryptError)),
        "{client:?}"
    );
}

#[test]
fn tampered_ciphertext_fails_handshake() {
    // Implicit rejection: the client derives a key the server does not
    // have, so the server's encrypted flight does not decrypt.
    let (client, _server) = hostile(&TAMPERED);
    assert!(
        matches!(client, Error::Tls(rustls::Error::DecryptError)),
        "{client:?}"
    );
}
