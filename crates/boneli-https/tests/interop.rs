//! X25519MLKEM768 against an independent implementation (ADR-016): an
//! `openssl s_server` of OpenSSL 3.5 or newer on 127.0.0.1. The local
//! rustls tests use a server half written from the same reading of RFC
//! 10024 as the client, so a layout error mirrored on both sides passes
//! them; OpenSSL's ML-KEM and hybrid code derive the same 64-byte secret
//! only if the reading is right, since otherwise the server's Finished does
//! not verify and no response comes back.
//!
//! Ignored by default because it needs `openssl` on PATH; CI runs it on
//! every PR (`.github/workflows/ci.yml`). A missing `openssl`, or one
//! without the group, fails the test instead of skipping it:
//!
//! ```sh
//! cargo test -p boneli-https --test interop -- --ignored
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use boneli_https::{ConnectOptions, Roots, TlsConfig, connect};
use rustls::NamedGroup;

const CA: &[u8] = include_bytes!("data/ca.pem");
const LEAF: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/leaf.pem");
const LEAF_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/leaf.key");

/// Bounds every wait on the server, so that a bug ends in a failure
/// instead of a hang; far above any local delivery time.
const GUARD: Duration = Duration::from_secs(10);

/// One handshake samples one key pair; 32 catch a fault that hits 10% of
/// key pairs with probability 1 - 0.9^32, about 0.97 (ADR-016, item 10).
const HANDSHAKES: usize = 32;

/// A running `openssl s_server`, killed and reaped on drop.
struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Fails, with the reason, unless `openssl` runs and lists X25519MLKEM768
/// among its TLS 1.3 groups.
fn require_openssl() {
    let out = Command::new("openssl")
        .args(["list", "-tls1_3", "-tls-groups"])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("interop needs openssl 3.5 or newer on PATH: {e}"));
    let groups = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success()
            && groups
                .split(|c: char| c == ':' || c.is_whitespace())
                .any(|g| g == "X25519MLKEM768"),
        "interop needs openssl 3.5 or newer with X25519MLKEM768; `openssl list -tls1_3 -tls-groups` said: {groups}"
    );
}

/// Starts `openssl s_server` with the test leaf, TLS 1.3 only and the
/// given groups, and reads its port from the `ACCEPT 127.0.0.1:<port>`
/// line.
fn s_server(groups: &str) -> Server {
    require_openssl();
    let mut child = Command::new("openssl")
        .args([
            "s_server",
            "-accept",
            "127.0.0.1:0",
            "-tls1_3",
            "-www",
            "-groups",
            groups,
        ])
        .args(["-cert", LEAF, "-key", LEAF_KEY])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start openssl s_server: {e}"));
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            if let Some(port) = line.strip_prefix("ACCEPT 127.0.0.1:") {
                let _ = tx.send(port.trim().parse::<u16>());
            }
        }
    });
    let mut server = Server { child, port: 0 };
    server.port = rx
        .recv_timeout(GUARD)
        .expect("s_server printed no ACCEPT line in time")
        .expect("a port in the ACCEPT line");
    server
}

/// One handshake with a fresh configuration (no resumption, no key share
/// hint) and one HTTP/1.0 request; returns the negotiated group.
fn handshake(port: u16) -> Option<NamedGroup> {
    let mut roots = Roots::empty();
    roots.add_pem(CA).expect("test CA");
    let config = TlsConfig::new(roots).expect("config");
    let options = ConnectOptions::new(GUARD, GUARD, GUARD).expect("options");
    let mut tls = connect("127.0.0.1", port, &config, &options).expect("handshake with OpenSSL");
    let group = tls.key_exchange_group();
    tls.write_all(b"GET / HTTP/1.0\r\n\r\n").expect("request");
    tls.flush().expect("flush");
    // The status line; `-www` answers with a status page.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n") {
        assert_eq!(tls.read(&mut byte).expect("response byte"), 1);
        head.push(byte[0]);
    }
    assert_eq!(head, b"HTTP/1.0 200 ok\r\n");
    group
}

#[test]
#[ignore = "interop: needs openssl 3.5 or newer on PATH"]
fn openssl_hybrid_only_server_32_handshakes() {
    let server = s_server("X25519MLKEM768");
    for i in 0..HANDSHAKES {
        assert_eq!(
            handshake(server.port),
            Some(NamedGroup::X25519MLKEM768),
            "handshake {i}"
        );
    }
}

#[test]
#[ignore = "interop: needs openssl 3.5 or newer on PATH"]
fn openssl_x25519_only_server_falls_back() {
    let server = s_server("X25519");
    assert_eq!(handshake(server.port), Some(NamedGroup::X25519));
}
