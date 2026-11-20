//! X25519MLKEM768 against a production server (ADR-016, item 10):
//! pq.cloudflareresearch.com reports the key exchange it negotiated in
//! `/cdn-cgi/trace`, so a second independent stack confirms the group
//! from the server side, over a real network path that carries the larger
//! ClientHello.
//!
//! Ignored by default because it depends on a third party; run it by hand
//! before a change to `src/pq.rs` or to the group lists merges:
//!
//! ```sh
//! cargo test -p boneli-https --test network -- --ignored --nocapture
//! ```

use std::io::Read;
use std::time::Duration;

use boneli_http::{Connection, Limits, Method, RequestBody, RequestHead, Target};
use boneli_https::{ConnectOptions, Roots, TlsConfig, connect};
use rustls::NamedGroup;

const HOST: &str = "pq.cloudflareresearch.com";

#[test]
#[ignore = "network: reaches pq.cloudflareresearch.com"]
fn cloudflare_confirms_x25519mlkem768() {
    let config = TlsConfig::new(Roots::mozilla()).expect("config");
    let ten = Duration::from_secs(10);
    let options = ConnectOptions::new(ten, ten, ten).expect("options");
    let tls = connect(HOST, 443, &config, &options).expect("handshake");
    assert_eq!(tls.key_exchange_group(), Some(NamedGroup::X25519MLKEM768));
    let limits = Limits::new(16 * 1024, 64, 64 * 1024).expect("limits");
    let mut conn = Connection::new(tls, HOST, limits).expect("connection");
    let head = RequestHead::new(
        Method::new("GET").expect("method"),
        Target::Origin("/cdn-cgi/trace".into()),
    );
    let mut response = conn.request(&head, RequestBody::None).expect("request");
    assert_eq!(response.head.status, 200);
    let mut body = String::new();
    response.read_to_string(&mut body).expect("body");
    // Only the protocol lines: the trace also holds the client's address.
    let reported: Vec<&str> = body
        .lines()
        .filter(|line| line.starts_with("tls=") || line.starts_with("kex="))
        .collect();
    println!("{}", reported.join("\n"));
    assert!(
        reported.contains(&"kex=X25519MLKEM768"),
        "the server reports another key exchange: {reported:?}"
    );
}
