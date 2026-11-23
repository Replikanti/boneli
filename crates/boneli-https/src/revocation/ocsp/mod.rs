//! Certificate revocation by OCSP (ADR-020), for leaves that name an OCSP
//! responder and no fetchable CRL distribution point.
//!
//! The check re-verifies the chain with webpki for the leaf's issuer on
//! the verified path, builds a SHA-1 CertID, asks the cache, and otherwise
//! sends one GET per responder URL (RFC 6960, A.1) through an
//! [`OcspSource`], verifies the answer (`response`) and caches it. A
//! revoked answer fails the connection with `Error::Revoked`; every
//! outcome that does not settle the leaf fails it with
//! `Error::RevocationUnknown` (D1: fail closed, no opt-out).

mod cache;
mod request;
mod response;

#[cfg(test)]
mod live;
#[cfg(test)]
pub(crate) mod testing;

pub(crate) use cache::OcspCache;
pub(crate) use request::get_path;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustls::RootCertStore;
use rustls::pki_types::SignatureVerificationAlgorithm;

use super::url::{self, Candidate, CrlUrl};
use super::{
    CRL_CONNECT_TIMEOUT, CRL_HANDSHAKE_TIMEOUT, CRL_IO_TIMEOUT, CRL_MIN_RATE, CrlFetchError, Leaf,
    RevocationFailure, RevocationFailureKind, RevocationStatus, der, lock,
};
use crate::Error;
use cache::{Entry, Lookup};
use request::CertId;
use response::{Issuer, Status};

/// The most responder URLs tried for one leaf: twice the measured maximum
/// of 1 (ADR-020, item 7).
pub const MAX_OCSP_URLS: usize = 2;

/// The largest OCSP response accepted, in bytes: 28 times the largest
/// measured answer (2,341 B). A `Content-Length` above it fails before
/// the body is read.
pub const MAX_OCSP_RESPONSE_BYTES: usize = 65_536;

/// The most certificates an OCSP response may carry: delegation is one
/// level deep (RFC 6960, 4.2.2.2), and every measured answer carries at
/// most 1.
pub const MAX_OCSP_RESPONSE_CERTS: usize = 4;

/// The deadline of one OCSP check, shared by its URLs: connect, TLS (an
/// `https` responder only), the response (BR 4.10.2: 10 s), and
/// `MAX_OCSP_RESPONSE_BYTES` at `CRL_MIN_RATE` rounded up to a second; 31
/// s. A `TlsDial` request's own deadline cuts it shorter.
pub const OCSP_CHECK_DEADLINE: Duration = Duration::from_secs(
    CRL_CONNECT_TIMEOUT.as_secs()
        + CRL_HANDSHAKE_TIMEOUT.as_secs()
        + CRL_IO_TIMEOUT.as_secs()
        + (MAX_OCSP_RESPONSE_BYTES as u64).div_ceil(CRL_MIN_RATE),
);

/// The answers one `TlsConfig`'s cache holds at most, least recently used
/// out first.
pub const OCSP_CACHE_MAX_ENTRIES: usize = 1_024;

/// How long a cached answer is used without a fetch after a fetch last
/// returned it (24 h; D2, as ADR-017's `CRL_MAX_AGE_SECS`). Never past
/// its `nextUpdate`.
pub const OCSP_MAX_AGE_SECS: u64 = 86_400;

/// The wait after a failed refresh before the next one (1 h; D2);
/// meanwhile the cached answer decides until its `nextUpdate`.
pub const OCSP_REFRESH_RETRY_SECS: u64 = 3_600;

/// Where OCSP responses come from. Not a verifier hook: whatever a source
/// returns is verified against the leaf's issuer on the verified path,
/// the leaf's CertID and the system clock (ADR-020, item 11). A source can
/// make a connection fail, hand over an older answer the issuer signed
/// that is still before its `nextUpdate` on a cold cache, or keep a cached
/// good answer in use until its `nextUpdate` by failing every refresh,
/// and nothing else. The transport types (`CrlUrl`, `CrlFetchError`) are
/// shared with `CrlSource`.
pub trait OcspSource: Send + Sync {
    /// The response of `responder` to the DER `request`, fetched by
    /// `deadline`.
    fn fetch(
        &self,
        responder: &CrlUrl,
        request: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, CrlFetchError>;
}

/// What one OCSP check works with: the handshake's roots and algorithms,
/// the source and the cache of its `TlsConfig`.
pub(crate) struct Context<'a> {
    pub(crate) roots: &'a RootCertStore,
    pub(crate) algorithms: &'a [&'static dyn SignatureVerificationAlgorithm],
    pub(crate) source: &'a dyn OcspSource,
    pub(crate) cache: &'a Mutex<OcspCache>,
}

/// The responder URLs to try, from the certificate's `id-ad-ocsp`
/// locations: ADR-017's grammar (`url::classify`), with a query refused,
/// because the request is appended to the path; other schemes skipped;
/// at most `MAX_OCSP_URLS`, refused ones counted.
pub(crate) fn candidates(uris: &[&[u8]]) -> Vec<Candidate> {
    uris.iter()
        .map(|uri| match url::classify(uri) {
            Candidate::Fetch(url) if url.path().contains('?') => {
                Candidate::Bad("responder URL with a query")
            }
            other => other,
        })
        .filter(|c| *c != Candidate::Skip)
        .take(MAX_OCSP_URLS)
        .collect()
}

/// The check of `leaf` against `candidates` (not empty, from
/// `candidates`), in the order of ADR-017 item 4 (ADR-020, item 5).
pub(crate) fn check(
    ctx: &Context<'_>,
    leaf: &Leaf<'_>,
    candidates: &[Candidate],
) -> crate::Result<RevocationStatus> {
    let (issuer, id) = issuer_of(ctx, leaf).map_err(|detail| {
        Error::RevocationUnknown(vec![RevocationFailure::new(
            None,
            RevocationFailureKind::NotSettled,
            detail,
        )])
    })?;
    let lookup = lock(ctx.cache).lookup(&id.der, leaf.secs);
    match lookup {
        Lookup::Fresh(entry) => Ok(decided(&entry, false)?),
        Lookup::Stale(entry) => Ok(decided(&entry, true)?),
        Lookup::Refresh(cached) => {
            // A refresh succeeds with an answer that verifies and is not
            // older than the cached one; a revocation always counts. Any
            // other outcome leaves the decision to the cached answer.
            for url in fetchable(candidates) {
                let Ok(entry) = fetch(ctx, leaf, url, &id, &issuer) else {
                    continue;
                };
                if entry.status == Status::Good && entry.this_update < cached.this_update {
                    continue;
                }
                let stored = lock(ctx.cache).insert(&id.der, entry, leaf.secs);
                return decided(&stored, false);
            }
            decided(&cached, true)
        }
        Lookup::Missing => {
            let mut failures = Vec::new();
            for candidate in candidates {
                let url = match candidate {
                    Candidate::Fetch(url) => url,
                    Candidate::Bad(why) => {
                        failures.push(RevocationFailure::new(
                            None,
                            RevocationFailureKind::BadUrl,
                            *why,
                        ));
                        continue;
                    }
                    Candidate::Skip => continue,
                };
                match fetch(ctx, leaf, url, &id, &issuer) {
                    // The stored entry decides: a revocation another
                    // connection cached meanwhile wins over this pass.
                    Ok(entry) => {
                        return decided(&lock(ctx.cache).insert(&id.der, entry, leaf.secs), false);
                    }
                    Err(failure) => failures.push(failure),
                }
            }
            Err(Error::RevocationUnknown(failures))
        }
    }
}

fn fetchable(candidates: &[Candidate]) -> impl Iterator<Item = &CrlUrl> {
    candidates.iter().filter_map(|c| match c {
        Candidate::Fetch(url) => Some(url),
        _ => None,
    })
}

/// The status an entry decides; `stale` when a good answer past its
/// maximum age decides it.
fn decided(entry: &Entry, stale: bool) -> crate::Result<RevocationStatus> {
    let url = entry.url.clone();
    match (entry.status, stale) {
        (Status::Revoked, _) => Err(Error::Revoked { url }),
        (Status::Good, false) => Ok(RevocationStatus::OcspChecked { url }),
        (Status::Good, true) => Ok(RevocationStatus::OcspCheckedStale { url }),
    }
}

/// One responder: request, size check, verification; the entry to store.
fn fetch(
    ctx: &Context<'_>,
    leaf: &Leaf<'_>,
    url: &CrlUrl,
    id: &CertId,
    issuer: &Issuer,
) -> Result<Entry, RevocationFailure> {
    let request = request::encode_request(id);
    let bytes = ctx
        .source
        .fetch(url, &request, leaf.deadline)
        .map_err(|e| RevocationFailure::from_fetch(url, e))?;
    // Any source, not only the HTTP one, is held to the cap.
    if bytes.len() > MAX_OCSP_RESPONSE_BYTES {
        return Err(RevocationFailure::new(
            Some(url),
            RevocationFailureKind::TooLarge,
            format!("{} bytes", bytes.len()),
        ));
    }
    let answer = response::verify(&bytes, id, issuer, ctx.algorithms, leaf.now)
        .map_err(|refusal| RevocationFailure::new(Some(url), refusal.kind, refusal.detail))?;
    Ok(Entry::new(
        answer.status,
        answer.this_update,
        answer.next_update,
        url.as_str(),
        leaf.secs,
    ))
}

/// The leaf's issuer on the path webpki verifies with the handshake's
/// roots and algorithms at the check's `now`, and the leaf's CertID under
/// it (ADR-020, item 2). The issuer is the path's first intermediate, or
/// its anchor when a root issued the leaf. webpki picks the same kind of
/// path rustls did; a different path could only change the issuer's key,
/// which no answer then matches, so the check fails closed.
fn issuer_of(ctx: &Context<'_>, leaf: &Leaf<'_>) -> Result<(Issuer, CertId), String> {
    let cert = webpki::EndEntityCert::try_from(leaf.cert)
        .map_err(|e| format!("the certificate cannot be parsed: {e}"))?;
    let path = cert
        .verify_for_usage(
            ctx.algorithms,
            &ctx.roots.roots,
            leaf.intermediates,
            leaf.now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| format!("the chain does not verify for the OCSP check: {e}"))?;
    let issuer = match path.intermediate_certificates().next() {
        Some(intermediate) => {
            let der = intermediate.der();
            let anchor = webpki::anchor_from_trusted_cert(&der)
                .map_err(|e| format!("the issuer cannot be an anchor: {e}"))?
                .to_owned();
            Issuer {
                spki: intermediate.subject_public_key_info().as_ref().to_vec(),
                anchor,
            }
        }
        None => Issuer {
            spki: webpki::spki_for_anchor(path.anchor()).as_ref().to_vec(),
            anchor: path.anchor().to_owned(),
        },
    };
    let (_, key) = der::spki_parts(&issuer.spki)
        .map_err(|e| format!("the issuer's key cannot be read: {e}"))?;
    let id = CertId::new(cert.issuer(), key, cert.serial());
    Ok((issuer, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::mpsc;
    use std::sync::{Arc, OnceLock};
    use std::thread;

    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};

    use super::super::{CrlSource, Revocation};
    use super::testing::{self, Response, SingleSpec, T};

    const GOOD: &[u8] = include_bytes!("../../../tests/data/ocsp-good.pem");
    const REVOKED: &[u8] = include_bytes!("../../../tests/data/ocsp-revoked.pem");
    const THREE: &[u8] = include_bytes!("../../../tests/data/ocsp-three-urls.pem");
    const LDAP_ONLY: &[u8] = include_bytes!("../../../tests/data/ocsp-ldap-only.pem");
    const QUERY: &[u8] = include_bytes!("../../../tests/data/ocsp-query.pem");
    const BOTH: &[u8] = include_bytes!("../../../tests/data/ocsp-and-crl.pem");
    const LDAP_CRL: &[u8] = include_bytes!("../../../tests/data/ocsp-ldap-crl.pem");
    const DECOY: &[u8] = include_bytes!("../../../tests/data/ocsp-decoy-ca.pem");

    const URL: &str = "http://ocsp.boneli.test/";
    const URL1: &str = "http://ocsp1.boneli.test/";
    const URL2: &str = "http://ocsp2.boneli.test/";

    const GUARD: Duration = Duration::from_secs(10);

    fn roots() -> Arc<RootCertStore> {
        static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
        Arc::clone(ROOTS.get_or_init(|| {
            let mut store = RootCertStore::empty();
            store
                .add(CertificateDer::from(testing::pem_der(testing::CA)))
                .expect("CA");
            Arc::new(store)
        }))
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn chain(pem: &[u8]) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("PEM")
    }

    fn name() -> ServerName<'static> {
        ServerName::try_from("localhost").expect("name")
    }

    type Reply = Result<Vec<u8>, CrlFetchError>;

    /// A source that answers from a script and records each responder.
    #[derive(Default)]
    struct Script {
        replies: Mutex<VecDeque<Reply>>,
        asked: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl Script {
        fn new(replies: Vec<Reply>) -> Arc<Script> {
            Arc::new(Script {
                replies: Mutex::new(replies.into()),
                asked: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> usize {
            self.asked.lock().expect("asked").len()
        }

        fn urls(&self) -> Vec<String> {
            self.asked
                .lock()
                .expect("asked")
                .iter()
                .map(|(u, _)| u.clone())
                .collect()
        }
    }

    impl OcspSource for Script {
        fn fetch(&self, responder: &CrlUrl, request: &[u8], _deadline: Instant) -> Reply {
            self.asked
                .lock()
                .expect("asked")
                .push((responder.as_str().to_owned(), request.to_vec()));
            self.replies
                .lock()
                .expect("replies")
                .pop_front()
                .unwrap_or_else(|| Err(CrlFetchError::Unreachable("script ended".into())))
        }
    }

    /// A CRL source that must never be asked.
    struct NoCrl;

    impl CrlSource for NoCrl {
        fn fetch(&self, url: &CrlUrl, _deadline: Instant) -> Reply {
            panic!("CRL fetch of {url}")
        }
    }

    /// A CRL source that answers nothing and counts.
    #[derive(Default)]
    struct CountingCrl(Mutex<usize>);

    impl CrlSource for CountingCrl {
        fn fetch(&self, _url: &CrlUrl, _deadline: Instant) -> Reply {
            *self.0.lock().expect("count") += 1;
            Err(CrlFetchError::Unreachable("no CRL".into()))
        }
    }

    fn revocation(source: Arc<dyn OcspSource>) -> Revocation {
        Revocation::on(roots(), provider(), Arc::new(NoCrl), source)
    }

    fn check_at(r: &Revocation, leaf: &[u8], secs: u64) -> crate::Result<RevocationStatus> {
        r.check_at(&chain(leaf), &name(), None, testing::time(secs))
    }

    fn kinds(result: crate::Result<RevocationStatus>) -> Vec<RevocationFailureKind> {
        match result {
            Err(Error::RevocationUnknown(failures)) => failures.iter().map(|f| f.kind).collect(),
            other => panic!("expected RevocationUnknown, got {other:?}"),
        }
    }

    fn revoked_by(result: crate::Result<RevocationStatus>) -> String {
        match result {
            Err(Error::Revoked { url }) => url,
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    fn checked(url: &str) -> RevocationStatus {
        RevocationStatus::OcspChecked { url: url.into() }
    }

    fn stale(url: &str) -> RevocationStatus {
        RevocationStatus::OcspCheckedStale { url: url.into() }
    }

    /// A response for `leaf` with `status`, valid from `this` to `next`.
    fn answer(leaf: &[u8], status: Vec<u8>, this: u64, next: u64) -> Reply {
        let id = testing::id_of(leaf);
        let single = SingleSpec {
            status,
            this_update: this,
            next_update: Some(next),
            ..SingleSpec::good(&id.der)
        };
        Ok(Response::new(vec![single]).build())
    }

    const NEXT: u64 = T + 7 * 86_400;

    fn good_of(leaf: &[u8]) -> Reply {
        answer(leaf, testing::good(), T - 3_600, NEXT)
    }

    fn revoked_of(leaf: &[u8]) -> Reply {
        answer(leaf, testing::revoked(T - 7_200), T - 3_600, NEXT)
    }

    fn unreachable() -> Reply {
        Err(CrlFetchError::Unreachable("refused".into()))
    }

    // ------------------------------------------------------------ routing

    #[test]
    fn crl_point_wins_over_ocsp() {
        let crl = Arc::new(CountingCrl::default());
        let ocsp = Script::new(vec![good_of(BOTH)]);
        let r = Revocation::on(roots(), provider(), crl.clone(), ocsp.clone());
        assert_eq!(
            kinds(check_at(&r, BOTH, T)),
            [RevocationFailureKind::Unreachable]
        );
        assert_eq!(*crl.0.lock().expect("count"), 1);
        assert_eq!(ocsp.calls(), 0, "the OCSP source is never asked");
    }

    #[test]
    fn ldap_only_point_falls_to_ocsp() {
        let script = Script::new(vec![good_of(LDAP_CRL)]);
        let r = revocation(script.clone());
        assert_eq!(check_at(&r, LDAP_CRL, T).expect("check"), checked(URL));
        assert_eq!(script.calls(), 1);
    }

    #[test]
    fn ocsp_ldap_only_passes_unchecked() {
        let script = Script::new(vec![]);
        let r = revocation(script.clone());
        assert_eq!(
            check_at(&r, LDAP_ONLY, T).expect("check"),
            RevocationStatus::NoRevocationSource
        );
        assert_eq!(script.calls(), 0);
    }

    // ---------------------------------------------------------- URL forms

    fn classified(uri: &[u8]) -> Vec<Candidate> {
        candidates(&[uri])
    }

    fn is_bad(uri: &[u8]) -> bool {
        matches!(classified(uri).as_slice(), [Candidate::Bad(_)])
    }

    #[test]
    fn bad_ocsp_url_fails_closed() {
        for uri in [
            b"http://user@ocsp.example.com".as_slice(),
            b"http://127.1/",
            b"http://ocsp.example.com:0/",
            b"ocsp.example.com",
        ] {
            assert!(is_bad(uri), "{:?}", String::from_utf8_lossy(uri));
        }
    }

    #[test]
    fn ocsp_url_non_ascii_is_bad() {
        assert!(is_bad(b"http://ocsp.example\xE2\x80\x8B.com/"));
        assert!(is_bad(b"http://ocsp.example.com/\xC2\xA0"));
    }

    #[test]
    fn ocsp_url_scheme_case_insensitive() {
        match classified(b"HTTP://OCSP.Example.COM").as_slice() {
            [Candidate::Fetch(url)] => assert_eq!(url.as_str(), "http://ocsp.example.com/"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn ocsp_url_with_query_is_bad() {
        assert!(is_bad(b"http://ocsp.example.com/?a=b"));
        let script = Script::new(vec![good_of(QUERY)]);
        let r = revocation(script.clone());
        assert_eq!(
            kinds(check_at(&r, QUERY, T)),
            [RevocationFailureKind::BadUrl]
        );
        assert_eq!(script.calls(), 0);
    }

    #[test]
    fn other_schemes_are_skipped_and_not_counted() {
        let found = candidates(&[
            b"ldap://ldap.example.com/x".as_slice(),
            b"http://a.example/",
            b"file:///etc/passwd",
            b"http://b.example/",
            b"http://c.example/",
        ]);
        let urls: Vec<&str> = found
            .iter()
            .map(|c| match c {
                Candidate::Fetch(url) => url.as_str(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(urls, ["http://a.example/", "http://b.example/"]);
    }

    // -------------------------------------------------- URL count, order

    #[test]
    fn third_ocsp_url_is_never_tried() {
        let script = Script::new(vec![unreachable(), unreachable(), good_of(THREE)]);
        let r = revocation(script.clone());
        assert_eq!(
            kinds(check_at(&r, THREE, T)),
            [
                RevocationFailureKind::Unreachable,
                RevocationFailureKind::Unreachable
            ]
        );
        assert_eq!(script.urls(), [URL1, URL2]);
    }

    #[test]
    fn second_ocsp_url_used_when_first_fails() {
        let script = Script::new(vec![unreachable(), good_of(THREE)]);
        let r = revocation(script.clone());
        assert_eq!(check_at(&r, THREE, T).expect("check"), checked(URL2));
        assert_eq!(script.urls(), [URL1, URL2]);
    }

    #[test]
    fn revoked_on_first_ocsp_url_stops() {
        let script = Script::new(vec![revoked_of(THREE), good_of(THREE)]);
        let r = revocation(script.clone());
        assert_eq!(revoked_by(check_at(&r, THREE, T)), URL1);
        assert_eq!(script.urls(), [URL1]);
    }

    #[test]
    fn request_is_the_leafs_cert_id() {
        let script = Script::new(vec![good_of(GOOD)]);
        let r = revocation(script.clone());
        check_at(&r, GOOD, T).expect("check");
        let asked = script.asked.lock().expect("asked").clone();
        assert_eq!(
            asked,
            [(URL.to_owned(), request::encode_request(&testing::good_id()))]
        );
        assert_eq!(
            asked[0].1,
            include_bytes!("../../../tests/data/ocsp-good.req")
        );
    }

    // ------------------------------------------------- answers, D1 cases

    #[test]
    fn ocsp_good_leaf_passes() {
        let r = revocation(Script::new(vec![good_of(GOOD)]));
        assert_eq!(check_at(&r, GOOD, T).expect("check"), checked(URL));
    }

    #[test]
    fn ocsp_revoked_leaf_is_refused() {
        let r = revocation(Script::new(vec![revoked_of(REVOKED)]));
        assert_eq!(revoked_by(check_at(&r, REVOKED, T)), URL);
    }

    #[test]
    fn unreachable_responder_fails_closed() {
        for (reply, kind) in [
            (unreachable(), RevocationFailureKind::Unreachable),
            (
                Err(CrlFetchError::TimedOut),
                RevocationFailureKind::TimedOut,
            ),
            (
                Err(CrlFetchError::Status(404)),
                RevocationFailureKind::Status,
            ),
            (
                Err(CrlFetchError::Status(301)),
                RevocationFailureKind::Status,
            ),
            (
                Err(CrlFetchError::TooLarge),
                RevocationFailureKind::TooLarge,
            ),
            (
                Err(CrlFetchError::Malformed("gzip".into())),
                RevocationFailureKind::Malformed,
            ),
        ] {
            let r = revocation(Script::new(vec![reply]));
            assert_eq!(kinds(check_at(&r, GOOD, T)), [kind]);
        }
    }

    #[test]
    fn oversized_source_bytes_refused() {
        let r = revocation(Script::new(vec![Ok(vec![0; MAX_OCSP_RESPONSE_BYTES + 1])]));
        assert_eq!(
            kinds(check_at(&r, GOOD, T)),
            [RevocationFailureKind::TooLarge]
        );
        let r = revocation(Script::new(vec![Ok(vec![0; MAX_OCSP_RESPONSE_BYTES])]));
        assert_eq!(
            kinds(check_at(&r, GOOD, T)),
            [RevocationFailureKind::Malformed]
        );
    }

    #[test]
    fn unknown_status_fails_closed() {
        let r = revocation(Script::new(vec![answer(
            GOOD,
            testing::unknown(),
            T - 3_600,
            NEXT,
        )]));
        assert_eq!(
            kinds(check_at(&r, GOOD, T)),
            [RevocationFailureKind::UnknownCertificate]
        );
    }

    #[test]
    fn answer_for_another_leaf_does_not_settle() {
        let r = revocation(Script::new(vec![good_of(REVOKED)]));
        assert_eq!(
            kinds(check_at(&r, GOOD, T)),
            [RevocationFailureKind::NotSettled]
        );
    }

    // -------------------------------------------------------------- cache

    fn entry(r: &Revocation, leaf: &[u8]) -> Option<Entry> {
        let super::super::Mode::On { ocsp_cache, .. } = &r.mode else {
            panic!("off")
        };
        lock(ocsp_cache).get(&testing::id_of(leaf).der).cloned()
    }

    #[test]
    fn ocsp_fresh_within_max_age_is_not_fetched() {
        let script = Script::new(vec![good_of(GOOD)]);
        let r = revocation(script.clone());
        assert_eq!(check_at(&r, GOOD, T).expect("check"), checked(URL));
        assert_eq!(check_at(&r, GOOD, T + 86_399).expect("check"), checked(URL));
        assert_eq!(script.calls(), 1);
    }

    #[test]
    fn ocsp_stale_entry_is_asked_again() {
        let newer = answer(GOOD, testing::good(), T + 80_000, NEXT + 86_400);
        let script = Script::new(vec![good_of(GOOD), newer]);
        let r = revocation(script.clone());
        check_at(&r, GOOD, T).expect("check");
        assert_eq!(check_at(&r, GOOD, T + 86_400).expect("check"), checked(URL));
        assert_eq!(script.calls(), 2);
        let e = entry(&r, GOOD).expect("entry");
        assert_eq!((e.this_update, e.confirmed_at), (T + 80_000, T + 86_400));
    }

    #[test]
    fn ocsp_refresh_failure_keeps_cached_until_retry() {
        let script = Script::new(vec![good_of(GOOD), unreachable(), unreachable()]);
        let r = revocation(script.clone());
        check_at(&r, GOOD, T).expect("check");
        assert_eq!(check_at(&r, GOOD, T + 86_400).expect("check"), stale(URL));
        assert_eq!(script.calls(), 2);
        assert_eq!(check_at(&r, GOOD, T + 89_999).expect("check"), stale(URL));
        assert_eq!(script.calls(), 2);
        assert_eq!(check_at(&r, GOOD, T + 90_000).expect("check"), stale(URL));
        assert_eq!(script.calls(), 3);
    }

    #[test]
    fn ocsp_cached_answer_expires_at_next_update() {
        let script = Script::new(vec![good_of(GOOD), unreachable(), unreachable()]);
        let r = revocation(script.clone());
        check_at(&r, GOOD, T).expect("check");
        assert_eq!(check_at(&r, GOOD, NEXT - 1).expect("check"), stale(URL));
        assert_eq!(script.calls(), 2);
        // Inside the retry wait, but at `nextUpdate`: fetched, and the
        // failure fails closed.
        assert_eq!(
            kinds(check_at(&r, GOOD, NEXT)),
            [RevocationFailureKind::Unreachable]
        );
        assert_eq!(script.calls(), 3);
        assert!(entry(&r, GOOD).is_none());
    }

    #[test]
    fn ocsp_older_response_on_refresh_keeps_newer() {
        let older = answer(GOOD, testing::good(), T - 7_200, NEXT);
        let script = Script::new(vec![good_of(GOOD), older]);
        let r = revocation(script.clone());
        check_at(&r, GOOD, T).expect("check");
        assert_eq!(check_at(&r, GOOD, T + 86_400).expect("check"), stale(URL));
        let e = entry(&r, GOOD).expect("entry");
        assert_eq!(
            (e.this_update, e.confirmed_at, e.claimed_at),
            (T - 3_600, T, Some(T + 86_400))
        );
        assert_eq!(check_at(&r, GOOD, T + 89_999).expect("check"), stale(URL));
        assert_eq!(script.calls(), 2);
    }

    #[test]
    fn ocsp_equal_response_confirms_entry() {
        let script = Script::new(vec![good_of(GOOD), good_of(GOOD)]);
        let r = revocation(script.clone());
        check_at(&r, GOOD, T).expect("check");
        assert_eq!(check_at(&r, GOOD, T + 86_400).expect("check"), checked(URL));
        let e = entry(&r, GOOD).expect("entry");
        assert_eq!((e.confirmed_at, e.claimed_at), (T + 86_400, None));
        assert_eq!(
            check_at(&r, GOOD, T + 172_799).expect("check"),
            checked(URL)
        );
        assert_eq!(script.calls(), 2);
    }

    #[test]
    fn ocsp_refresh_sees_new_revocation() {
        let later = answer(
            GOOD,
            testing::revoked(T + 50_000),
            T + 60_000,
            NEXT + 86_400,
        );
        let script = Script::new(vec![good_of(GOOD), later]);
        let r = revocation(script.clone());
        check_at(&r, GOOD, T).expect("check");
        assert_eq!(revoked_by(check_at(&r, GOOD, T + 86_400)), URL);
        // Cached: refused again without a fetch, past the maximum age too.
        assert_eq!(revoked_by(check_at(&r, GOOD, T + 3 * 86_400)), URL);
        assert_eq!(script.calls(), 2);
    }

    #[test]
    fn ocsp_mirror_revocation_is_not_undone() {
        // URL 1 unreachable, URL 2 revokes; the next check would get a
        // good answer from URL 1, but the cache decides first.
        let script = Script::new(vec![unreachable(), revoked_of(THREE), good_of(THREE)]);
        let r = revocation(script.clone());
        assert_eq!(revoked_by(check_at(&r, THREE, T)), URL2);
        assert_eq!(revoked_by(check_at(&r, THREE, T + 3_600)), URL2);
        assert_eq!(script.urls(), [URL1, URL2]);
    }

    #[test]
    fn ocsp_failed_answer_is_not_cached() {
        let wrong = good_of(REVOKED);
        let script = Script::new(vec![wrong.clone(), wrong]);
        let r = revocation(script.clone());
        assert_eq!(
            kinds(check_at(&r, GOOD, T)),
            [RevocationFailureKind::NotSettled]
        );
        assert!(entry(&r, GOOD).is_none());
        assert_eq!(
            kinds(check_at(&r, GOOD, T)),
            [RevocationFailureKind::NotSettled]
        );
        assert_eq!(script.calls(), 2);
    }

    /// A source that runs a closure.
    struct FnSource<F>(F);

    impl<F: Fn() -> Reply + Send + Sync> OcspSource for FnSource<F> {
        fn fetch(&self, _: &CrlUrl, _: &[u8], _: Instant) -> Reply {
            (self.0)()
        }
    }

    #[test]
    fn ocsp_stale_refresh_is_claimed_by_one_connection() {
        let (entered_tx, entered) = mpsc::channel::<()>();
        let (release, release_rx) = mpsc::channel::<()>();
        let entered_tx = Mutex::new(entered_tx);
        let release_rx = Mutex::new(release_rx);
        let calls = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&calls);
        let source = FnSource(move || {
            let n = {
                let mut calls = counter.lock().expect("calls");
                *calls += 1;
                *calls
            };
            if n == 1 {
                return good_of(GOOD);
            }
            let _ = entered_tx.lock().expect("tx").send(());
            let _ = release_rx.lock().expect("rx").recv_timeout(GUARD);
            unreachable()
        });
        let r = Arc::new(revocation(Arc::new(source)));
        check_at(&r, GOOD, T).expect("check");
        let a = {
            let r = Arc::clone(&r);
            thread::spawn(move || check_at(&r, GOOD, T + 86_400))
        };
        entered.recv_timeout(GUARD).expect("A is refreshing");
        assert_eq!(check_at(&r, GOOD, T + 86_400).expect("B"), stale(URL));
        assert_eq!(*calls.lock().expect("calls"), 2, "B did not fetch");
        release.send(()).expect("release");
        assert_eq!(a.join().expect("A").expect("A"), stale(URL));
        assert_eq!(*calls.lock().expect("calls"), 2);
    }

    #[test]
    fn ocsp_poisoned_cache_recovers() {
        let script = Script::new(vec![good_of(GOOD), good_of(GOOD)]);
        let r = Arc::new(revocation(script.clone()));
        check_at(&r, GOOD, T).expect("check");
        {
            let r = Arc::clone(&r);
            let _ = thread::spawn(move || {
                let super::super::Mode::On { ocsp_cache, .. } = &r.mode else {
                    return;
                };
                let _guard = ocsp_cache.lock();
                panic!("poison the cache");
            })
            .join();
        }
        let super::super::Mode::On { ocsp_cache, .. } = &r.mode else {
            panic!("off")
        };
        assert!(ocsp_cache.is_poisoned());
        assert_eq!(check_at(&r, GOOD, T).expect("check"), checked(URL));
        assert_eq!(script.calls(), 2, "the cache was cleared");
        assert!(!ocsp_cache.is_poisoned());
        assert_eq!(check_at(&r, GOOD, T).expect("check"), checked(URL));
        assert_eq!(script.calls(), 2);
    }

    // ------------------------------------------------------------- issuer

    #[test]
    fn leaf_issued_by_root_is_checked() {
        // The test CA is a root: the anchor's key names the leaf.
        let r = revocation(Script::new(vec![good_of(GOOD)]));
        assert_eq!(check_at(&r, GOOD, T).expect("check"), checked(URL));
    }

    #[test]
    fn decoy_intermediate_does_not_change_issuer() {
        // The server sends a CA with the issuer's name and another key
        // first; the CertID still names the root that verified the leaf.
        let script = Script::new(vec![good_of(GOOD)]);
        let r = revocation(script.clone());
        let mut sent = chain(GOOD);
        sent.extend(chain(DECOY));
        let status = r
            .check_at(&sent, &name(), None, testing::time(T))
            .expect("check");
        assert_eq!(status, checked(URL));
        let asked = script.asked.lock().expect("asked").clone();
        assert_eq!(asked[0].1, request::encode_request(&testing::good_id()));
    }

    #[test]
    fn unverifiable_chain_fails_closed_before_any_fetch() {
        let script = Script::new(vec![good_of(GOOD)]);
        let r = Revocation::on(
            Arc::new(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            }),
            provider(),
            Arc::new(NoCrl),
            script.clone(),
        );
        assert_eq!(
            kinds(check_at(&r, GOOD, T)),
            [RevocationFailureKind::NotSettled]
        );
        assert_eq!(script.calls(), 0);
    }

    // ------------------------------------------------------ real captures

    const E36: &[u8] = include_bytes!("../../../tests/data/capture-e36-chain.pem");
    const E36_RESP: &[u8] = include_bytes!("../../../tests/data/capture-e36.resp");
    const R36: &[u8] = include_bytes!("../../../tests/data/capture-r36-chain.pem");
    const R36_RESP: &[u8] = include_bytes!("../../../tests/data/capture-r36.resp");
    const GLOBALSIGN: &[u8] = include_bytes!("../../../tests/data/capture-globalsign-chain.pem");
    const GLOBALSIGN_RESP: &[u8] = include_bytes!("../../../tests/data/capture-globalsign.resp");
    const SSL_COM: &[u8] = include_bytes!("../../../tests/data/capture-sslcom-revoked-chain.pem");
    const SSL_COM_RESP: &[u8] = include_bytes!("../../../tests/data/capture-sslcom-revoked.resp");

    /// Fetch times of the captures, 2026-11-20 UTC (`tests/data/README.md`).
    const SECTIGO_AT: u64 = 1_795_181_189;
    const GLOBALSIGN_AT: u64 = 1_795_181_238;
    const SSL_COM_AT: u64 = 1_795_181_340;

    /// The `nextUpdate` of each capture, from `openssl ocsp -resp_text`.
    const E36_NEXT: u64 = 1_795_657_048; // 2026-11-26 01:37:28
    const R36_NEXT: u64 = 1_795_506_514; // 2026-11-24 07:48:34
    const GLOBALSIGN_NEXT: u64 = 1_795_514_738; // 2026-11-24 10:05:38
    const SSL_COM_NEXT: u64 = 1_795_775_100; // 2026-11-27 10:25:00

    /// The answer of a capture for its chain at `now`, through the check
    /// with Mozilla's roots and a source that serves `response`.
    fn capture(pem: &[u8], response: &[u8], now: u64) -> crate::Result<RevocationStatus> {
        let mozilla = Arc::new(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
        let source = Script::new(vec![Ok(response.to_vec())]);
        let r = Revocation::on(mozilla, provider(), Arc::new(NoCrl), source);
        let chain = chain(pem);
        // The CRL path would win for the GlobalSign and SSL.com leaves;
        // the OCSP check is called directly.
        let super::super::Mode::On {
            roots,
            provider,
            ocsp_source,
            ocsp_cache,
            ..
        } = &r.mode
        else {
            panic!("off")
        };
        let ctx = Context {
            roots,
            algorithms: provider.signature_verification_algorithms.all,
            source: ocsp_source.as_ref(),
            cache: ocsp_cache,
        };
        let name = name();
        let leaf = Leaf {
            cert: &chain[0],
            intermediates: &chain[1..],
            name: &name,
            now: testing::time(now),
            secs: now,
            deadline: Instant::now() + GUARD,
        };
        let uris = der::ocsp_responder_uris(chain[0].as_ref()).expect("AIA");
        check(&ctx, &leaf, &candidates(&uris))
    }

    #[test]
    fn sectigo_e36_capture_is_good() {
        assert_eq!(
            capture(E36, E36_RESP, SECTIGO_AT).expect("good"),
            checked("http://ocsp.sectigo.com/")
        );
    }

    #[test]
    fn sectigo_r36_capture_is_good() {
        assert_eq!(
            capture(R36, R36_RESP, SECTIGO_AT).expect("good"),
            checked("http://ocsp.sectigo.com/")
        );
    }

    #[test]
    fn globalsign_delegated_capture_is_good() {
        assert_eq!(
            capture(GLOBALSIGN, GLOBALSIGN_RESP, GLOBALSIGN_AT).expect("good"),
            checked("http://ocsp.globalsign.com/gsgccr46evtlsca2025")
        );
    }

    #[test]
    fn ssl_com_revoked_capture_is_revoked() {
        assert_eq!(
            revoked_by(capture(SSL_COM, SSL_COM_RESP, SSL_COM_AT)),
            "http://ocsps.ssl.com/"
        );
    }

    #[test]
    fn captures_expire_at_next_update() {
        for (pem, response, next) in [
            (E36, E36_RESP, E36_NEXT),
            (R36, R36_RESP, R36_NEXT),
            (GLOBALSIGN, GLOBALSIGN_RESP, GLOBALSIGN_NEXT),
            (SSL_COM, SSL_COM_RESP, SSL_COM_NEXT),
        ] {
            assert!(
                !matches!(
                    capture(pem, response, next - 1),
                    Err(Error::RevocationUnknown(_))
                ),
                "valid at nextUpdate - 1"
            );
            assert_eq!(
                kinds(capture(pem, response, next)),
                [RevocationFailureKind::Expired]
            );
        }
    }

    #[test]
    fn check_deadline_is_31_seconds() {
        assert_eq!(OCSP_CHECK_DEADLINE, Duration::from_secs(31));
    }
}
