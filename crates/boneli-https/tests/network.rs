//! Live tests against production servers, ignored by default because they
//! depend on third parties.
//!
//! X25519MLKEM768 (ADR-016, item 10): pq.cloudflareresearch.com reports
//! the key exchange it negotiated in `/cdn-cgi/trace`, so a second
//! independent stack confirms the group from the server side, over a real
//! network path that carries the larger ClientHello. Run it by hand
//! before a change to `src/pq.rs` or to the group lists merges.
//!
//! Revocation by CRL (ADR-017, item 12): Let's Encrypt's test sites serve
//! a revoked and a valid leaf whose CRLs come from a real CA over the
//! real network path, which no loopback test reaches. Revocation by OCSP
//! (ADR-020, item 12): the six forge hosts whose leaves name only an OCSP
//! responder must be checked by Sectigo's. Run them by hand before a
//! change under `src/revocation/` merges:
//!
//! ```sh
//! cargo test -p boneli-https --test network -- --ignored --nocapture
//! ```

use std::io::Read;
use std::time::Duration;

use boneli_http::{Connection, Limits, Method, RequestBody, RequestHead, Target};
use boneli_https::{ConnectOptions, Error, RevocationStatus, Roots, TlsConfig, connect};
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

fn live_options() -> ConnectOptions {
    let ten = Duration::from_secs(10);
    ConnectOptions::new(ten, ten, ten).expect("options")
}

#[test]
#[ignore = "network: reaches revoked-isrgrootx1.letsencrypt.org and its CRL"]
fn lets_encrypt_revoked_test_site_is_refused() {
    let config = TlsConfig::new(Roots::mozilla()).expect("config");
    match connect(
        "revoked-isrgrootx1.letsencrypt.org",
        443,
        &config,
        &live_options(),
    ) {
        Err(Error::Revoked { url }) => {
            println!("revoked by {url}");
            assert!(url.starts_with("http://"), "{url}");
        }
        other => panic!("expected Error::Revoked, got {other:?}"),
    }
}

#[test]
#[ignore = "network: reaches valid-isrgrootx1.letsencrypt.org and its CRL"]
fn lets_encrypt_valid_test_site_is_checked() {
    let config = TlsConfig::new(Roots::mozilla()).expect("config");
    let tls = connect(
        "valid-isrgrootx1.letsencrypt.org",
        443,
        &config,
        &live_options(),
    )
    .expect("handshake");
    println!("{:?}", tls.revocation());
    assert!(
        matches!(tls.revocation(), RevocationStatus::Checked { .. }),
        "{:?}",
        tls.revocation()
    );
}

#[test]
#[ignore = "network: reaches the runner's hosts and their CRLs"]
fn runner_hosts_revocation_status() {
    let config = TlsConfig::new(Roots::mozilla()).expect("config");
    for host in [
        "api.github.com",
        "registry-1.docker.io",
        "api.anthropic.com",
    ] {
        let tls = connect(host, 443, &config, &live_options()).expect(host);
        println!("{host}: {:?}", tls.revocation());
    }
}

/// The forge hosts whose leaves name no CRL point and one OCSP responder,
/// Sectigo's (ADR-020, Context).
const OCSP_HOSTS: [&str; 6] = [
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "ghcr.io",
    "gitlab.com",
    "registry.gitlab.com",
];

#[test]
#[ignore = "network: reaches GitHub, GHCR, GitLab and ocsp.sectigo.com"]
fn forge_hosts_checked_by_ocsp() {
    let config = TlsConfig::new(Roots::mozilla()).expect("config");
    let mut wrong = Vec::new();
    for host in OCSP_HOSTS {
        let status =
            connect(host, 443, &config, &live_options()).map(|tls| tls.revocation().clone());
        println!("{host}: {status:?}");
        let expected = RevocationStatus::OcspChecked {
            url: "http://ocsp.sectigo.com/".into(),
        };
        if !matches!(&status, Ok(s) if *s == expected) {
            wrong.push(host);
        }
    }
    assert!(
        wrong.is_empty(),
        "not checked by Sectigo's responder: {wrong:?}"
    );
}
