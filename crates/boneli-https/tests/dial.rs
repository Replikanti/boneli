//! `TlsDial` against a local rustls server on 127.0.0.1 (ADR-009, D10 and
//! D12; moved here from boneli-oci by ADR-014, D4): the request deadline
//! holds below TLS, and a host outside the ADR-003 grammar is refused
//! before anything is resolved or dialed. The server and its certificates
//! are this crate's TLS test fixtures.

use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use boneli_https::{ConnectOptions, Dial, Roots, TlsConfig, TlsDial};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};

const CA: &[u8] = include_bytes!("data/ca.pem");
const LEAF: &[u8] = include_bytes!("data/leaf.pem");
const LEAF_KEY: &[u8] = include_bytes!("data/leaf.key");

/// Bounds every blocking call of the server, so that a bug ends in a
/// failure instead of a hang; far above any local delivery time.
const GUARD: Duration = Duration::from_secs(10);

/// A dial that trusts the test CA only, with `io` as its read and write
/// timeout and connect and handshake timeouts that never fire first.
fn dial(io: Duration) -> TlsDial {
    let mut roots = Roots::empty();
    assert_eq!(roots.add_pem(CA).expect("test CA"), 1);
    let config = TlsConfig::new(roots).expect("config");
    TlsDial::new(
        config,
        ConnectOptions::new(GUARD, GUARD, io).expect("options"),
    )
}

/// The `localhost` leaf, TLS 1.3 and 1.2, no session tickets, so the only
/// record after the handshake is the one the test writes.
fn server_config() -> Arc<ServerConfig> {
    let chain = CertificateDer::pem_slice_iter(LEAF)
        .collect::<Result<Vec<_>, _>>()
        .expect("cert PEM");
    let key = PrivateKeyDer::from_pem_slice(LEAF_KEY).expect("key PEM");
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

/// Accepts one connection, completes the handshake, then sends one
/// application data record of 16,000 B one byte every `every`, for at most
/// `budget`, and closes. Returns how many bytes of the record it sent.
fn drip_server(
    listener: TcpListener,
    every: Duration,
    budget: Duration,
) -> thread::JoinHandle<io::Result<usize>> {
    thread::spawn(move || {
        let (mut tcp, _) = listener.accept()?;
        tcp.set_read_timeout(Some(GUARD))?;
        tcp.set_write_timeout(Some(GUARD))?;
        let mut conn = ServerConnection::new(server_config()).map_err(io::Error::other)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut tcp)?;
        }
        conn.writer().write_all(&[b'x'; 16_000])?;
        let mut record = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut record)?;
        }
        let start = Instant::now();
        let mut sent = 0;
        for byte in &record {
            if start.elapsed() > budget || tcp.write_all(std::slice::from_ref(byte)).is_err() {
                break;
            }
            sent += 1;
            thread::sleep(every);
        }
        Ok(sent)
    })
}

/// A peer that sends one TLS record a byte at a time, each byte well within
/// the io timeout: the read above TLS waits for the whole record, so only
/// the deadline on the socket below TLS ends it, close to the deadline.
#[test]
fn tls_read_stops_at_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    // Without the deadline below TLS the read would last until the server
    // gives up after 4 s, far past the bound below.
    let server = drip_server(listener, Duration::from_millis(100), Duration::from_secs(4));

    let io = Duration::from_millis(500);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(1);
    let mut stream = dial(io).dial("localhost", port, deadline).expect("dial");
    let mut buf = [0u8; 1024];
    let err = stream
        .read(&mut buf)
        .expect_err("the deadline passed mid-record");
    let elapsed = start.elapsed();
    assert!(
        matches!(
            err.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ),
        "{err:?}"
    );
    assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(1) + io, "{elapsed:?}");
    drop(stream);
    let sent = server.join().expect("server thread").expect("server");
    assert!(sent > 1 && sent < 16_000, "{sent} bytes of the record sent");
}

/// Hosts outside the ADR-003 grammar, among them numeric forms that
/// `getaddrinfo` reads as IPv4 addresses, are refused before any name is
/// resolved or any connection made (ADR-003, item 3).
#[test]
fn invalid_hosts_rejected_before_dialing() {
    let dial = dial(GUARD);
    for host in [
        "l\u{43e}calhost",
        "",
        "[::1]",
        "2130706433",
        "127.1",
        "0x7f000001",
        "0177.0.0.1",
        "10.1",
        "LOCALHOST",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let err = match dial.dial(host, port, Instant::now() + GUARD) {
            Ok(_) => panic!("{host:?}: dialed"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{host:?}: {err:?}");
        assert_eq!(
            listener.accept().err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock),
            "{host:?}: nothing dialed"
        );
    }
    // Port zero is refused the same way.
    let err = match dial.dial("localhost", 0, Instant::now() + GUARD) {
        Ok(_) => panic!("port 0: dialed"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err:?}");
}
