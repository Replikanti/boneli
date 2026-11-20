//! Live tests of the OCSP check against real responders, ignored by
//! default because they depend on third parties (ADR-019, item 12). They
//! call the check directly, so leaves that also name a CRL point, which
//! the handshake would check by CRL, go through OCSP here: SSL.com's
//! revoked test leaves (a revoked answer by name, signed by the CA), and
//! `pypi.org` and `www.microsoft.com`, whose responders delegate. The six
//! forge hosts are checked through the public API in `tests/network.rs`.
//!
//! ```sh
//! cargo test -p boneli-https --lib -- --ignored ocsp::live
//! ```

use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use super::super::{HttpSource, Leaf, RevocationStatus, der};
use super::{Context, OcspCache, candidates, check};
use crate::{ConnectOptions, Error, Roots, TlsConfig};

fn options() -> ConnectOptions {
    let ten = Duration::from_secs(10);
    ConnectOptions::new(ten, ten, ten).expect("options")
}

/// The OCSP status of `host`'s leaf, through the real HTTP source.
fn ocsp_status(host: &str) -> crate::Result<RevocationStatus> {
    let config = TlsConfig::new(Roots::mozilla()).expect("config");
    let plain = config.without_revocation();
    let tls = crate::connect(host, 443, &plain, &options()).expect(host);
    let chain: Vec<CertificateDer<'static>> = tls
        .stream
        .conn
        .peer_certificates()
        .expect("chain")
        .iter()
        .map(|c| c.clone().into_owned())
        .collect();
    let source = HttpSource::new(plain);
    let cache = Mutex::new(OcspCache::new());
    let ctx = Context {
        roots: &config.roots,
        algorithms: config
            .client
            .crypto_provider()
            .signature_verification_algorithms
            .all,
        source: &source,
        cache: &cache,
    };
    let name = ServerName::try_from(host.to_owned()).expect("name");
    let now = UnixTime::now();
    let leaf = Leaf {
        cert: &chain[0],
        intermediates: &chain[1..],
        name: &name,
        now,
        secs: now.as_secs(),
        deadline: Instant::now() + super::OCSP_CHECK_DEADLINE,
    };
    let uris = der::ocsp_responder_uris(chain[0].as_ref()).expect("AIA");
    let found = candidates(&uris);
    assert!(!found.is_empty(), "{host} names no responder");
    check(&ctx, &leaf, &found)
}

#[test]
#[ignore = "network: reaches revoked-rsa-dv.ssl.com, revoked-ecc-dv.ssl.com and ocsps.ssl.com"]
fn ssl_com_revoked_leaves_are_revoked() {
    for host in ["revoked-rsa-dv.ssl.com", "revoked-ecc-dv.ssl.com"] {
        match ocsp_status(host) {
            Err(Error::Revoked { url }) => println!("{host}: revoked ({url})"),
            other => panic!("{host}: expected Error::Revoked, got {other:?}"),
        }
    }
}

#[test]
#[ignore = "network: reaches pypi.org, www.microsoft.com and their delegated responders"]
fn delegated_responders_answer_good() {
    for host in ["pypi.org", "www.microsoft.com"] {
        let status = ocsp_status(host);
        println!("{host}: {status:?}");
        assert!(
            matches!(status, Ok(RevocationStatus::OcspChecked { .. })),
            "{host}: {status:?}"
        );
    }
}
