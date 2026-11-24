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
//! responder must be checked by Sectigo's. Intermediates (ADR-027): each
//! one on the verified path of Let's Encrypt's, GitHub's and the runner's
//! hosts must be checked against its issuer's list. Name resolution
//! (ADR-022): the own resolver must agree with the system's on the
//! runner's hosts. Run
//! them by hand before a change under `src/revocation/` or `src/resolve/`
//! merges:
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

/// ADR-027, item 12: the intermediates of real chains are checked against
/// their issuers' lists over the real network path.
#[test]
#[ignore = "network: reaches Let's Encrypt, GitHub, the runner's hosts and their CA lists"]
fn intermediates_checked_live() {
    let config = TlsConfig::new(Roots::mozilla()).expect("config");
    let checked = |status: &RevocationStatus, host: &str| match status {
        RevocationStatus::Checked { url } => url.contains(host),
        _ => false,
    };

    let tls = connect(
        "valid-isrgrootx1.letsencrypt.org",
        443,
        &config,
        &live_options(),
    )
    .expect("valid-isrgrootx1");
    println!(
        "valid-isrgrootx1: leaf {:?}, intermediates {:?}",
        tls.revocation(),
        tls.intermediate_revocation()
    );
    let found = tls.intermediate_revocation();
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(checked(&found[0], "yr.c.lencr.org"), "{found:?}");
    assert!(checked(&found[1], "x1.c.lencr.org"), "{found:?}");
    assert!(
        matches!(tls.revocation(), RevocationStatus::Checked { .. }),
        "{:?}",
        tls.revocation()
    );

    // The intermediates pass, then the leaf is refused by its own list.
    match connect(
        "revoked-isrgrootx1.letsencrypt.org",
        443,
        &config,
        &live_options(),
    ) {
        Err(Error::Revoked { url }) => {
            println!("revoked-isrgrootx1: revoked by {url}");
            assert!(
                !url.contains("x1.c.lencr.org") && !url.contains("yr.c.lencr.org"),
                "{url}"
            );
        }
        other => panic!("expected Error::Revoked, got {other:?}"),
    }

    let tls = connect("github.com", 443, &config, &live_options()).expect("github.com");
    println!(
        "github.com: leaf {:?}, intermediates {:?}",
        tls.revocation(),
        tls.intermediate_revocation()
    );
    assert!(
        matches!(tls.intermediate_revocation(), [s] if checked(s, "crl.sectigo.com")),
        "{:?}",
        tls.intermediate_revocation()
    );
    assert!(
        matches!(tls.revocation(), RevocationStatus::OcspChecked { .. }),
        "{:?}",
        tls.revocation()
    );

    let mut wrong = Vec::new();
    for host in [
        "api.github.com",
        "ghcr.io",
        "gitlab.com",
        "registry-1.docker.io",
        "auth.docker.io",
        "production.cloudflare.docker.com",
        "docker-images-prod.s3.dualstack.us-east-1.amazonaws.com",
        "pkg-containers.githubusercontent.com",
        "api.anthropic.com",
    ] {
        match connect(host, 443, &config, &live_options()) {
            Ok(tls) => {
                println!(
                    "{host}: leaf {:?}, intermediates {:?}",
                    tls.revocation(),
                    tls.intermediate_revocation()
                );
                let all_checked = tls
                    .intermediate_revocation()
                    .iter()
                    .all(|s| matches!(s, RevocationStatus::Checked { .. }));
                if tls.intermediate_revocation().is_empty() || !all_checked {
                    wrong.push(host);
                }
            }
            Err(e) => {
                println!("{host}: {e}");
                wrong.push(host);
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "not every intermediate checked: {wrong:?}"
    );
}

/// The hosts the runner reaches today, measured when ADR-022 was planned:
/// forges, registries, the model API, and the CRL and OCSP hosts their
/// leaves name.
const RESOLVER_HOSTS: [&str; 14] = [
    "api.anthropic.com",
    "api.github.com",
    "codeload.github.com",
    "ghcr.io",
    "github.com",
    "gitlab.com",
    "registry-1.docker.io",
    "registry.gitlab.com",
    "auth.docker.io",
    "production.cloudflare.docker.com",
    "pkg-containers.githubusercontent.com",
    "ocsp.sectigo.com",
    "x1.c.lencr.org",
    "crl3.digicert.com",
];

/// ADR-022: the own resolver (resolv.conf and hosts only) finds an
/// address of each host that the system's `getaddrinfo` (all of NSS) also
/// finds. Run it by hand before a change under `src/resolve/` merges;
/// the times it prints are the lookup times ADR-022 records.
#[test]
#[ignore = "network: resolves the runner's hosts through the host's name servers"]
fn own_resolver_agrees_with_the_system() {
    use std::collections::BTreeSet;
    use std::net::ToSocketAddrs;
    use std::time::Instant;

    let resolver = boneli_https::Resolver::system();
    let mut wrong = Vec::new();
    for host in RESOLVER_HOSTS {
        let start = Instant::now();
        let own = resolver.lookup(host, 443, start + Duration::from_secs(10));
        let own_time = start.elapsed();
        let start = Instant::now();
        let system: BTreeSet<_> = (host, 443)
            .to_socket_addrs()
            .map(Iterator::collect)
            .unwrap_or_default();
        let system_time = start.elapsed();
        let own: BTreeSet<_> = match own {
            Ok(list) => list.into_iter().collect(),
            Err(e) => {
                println!("{host}: own resolver failed: {e}");
                wrong.push(host);
                continue;
            }
        };
        println!(
            "{host}: own {} addresses in {own_time:.1?}, system {} in {system_time:.1?}, {} shared",
            own.len(),
            system.len(),
            own.intersection(&system).count()
        );
        if own.is_empty() || own.is_disjoint(&system) {
            wrong.push(host);
        }
    }
    assert!(
        wrong.is_empty(),
        "the own resolver disagrees with the system on {wrong:?}"
    );
}
