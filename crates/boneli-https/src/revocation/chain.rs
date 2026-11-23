//! The intermediates of the verified path and their check against their
//! issuers' CRLs (ADR-027, items 1 to 7).
//!
//! The path is webpki's (`EndEntityCert::verify_for_usage` with the
//! handshake's roots and algorithms, as for OCSP in ADR-020 item 2), so
//! the anchor and the certificates the server sent beside the path are
//! never read. The intermediates are checked from the anchor side down,
//! before the leaf: a URL is fetched only from a certificate whose issuers
//! have passed. Each takes the leaf's algorithm of ADR-017 item 4 with the
//! CA cache, `ca_list`'s decision and the connection's fetch budget.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};

use super::ca_list::{self, IssuerKey, Subject, Verdict};
use super::cache::{CrlCache, Entry, Lookup};
use super::url::{self, Candidate, CrlUrl};
use super::{
    CrlSource, MAX_CA_CRL_BYTES, MAX_CRL_URLS, RevocationFailure, RevocationFailureKind,
    RevocationStatus, lock, revoked,
};
use crate::Error;
use crate::der::{self, KeyUsage};

/// A CA list as the cache keeps it: its DER, decided again for every
/// certificate it is used for, against that certificate's issuer key.
#[derive(Debug)]
pub(crate) struct CaList {
    pub(crate) der: Vec<u8>,
}

/// The cache of the intermediates' lists.
pub(crate) type CaCache = CrlCache<Arc<CaList>>;

/// One intermediate on the path, with what its check reads.
#[derive(Clone, Debug)]
pub(crate) struct Link {
    pub(crate) der: Vec<u8>,
    /// Its issuer Name and serial, as webpki reads them.
    issuer: Vec<u8>,
    serial: Vec<u8>,
    /// Its issuer's whole `SubjectPublicKeyInfo`: the next intermediate's,
    /// or the anchor's for the top one.
    issuer_spki: Vec<u8>,
    /// Its issuer's keyUsage, when the issuer is an intermediate that has
    /// one; never read for the anchor.
    issuer_key_usage: Option<KeyUsage>,
}

/// The intermediates of the verified path, the leaf's issuer first; empty
/// when a root issued the leaf.
#[derive(Clone, Debug)]
pub(crate) struct Path {
    pub(crate) links: Vec<Link>,
}

/// The path webpki verifies for `leaf` with `intermediates` (what the
/// server sent beside it), `roots` and `algorithms` at `now`, for
/// `serverAuth` and without revocation: the call ADR-020's `issuer_of`
/// makes. A certificate the server sent that is not on the path is never
/// read.
pub(crate) fn verified_path(
    roots: &RootCertStore,
    algorithms: &[&'static dyn SignatureVerificationAlgorithm],
    leaf: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
) -> Result<Path, String> {
    let cert = webpki::EndEntityCert::try_from(leaf)
        .map_err(|e| format!("the certificate cannot be parsed: {e}"))?;
    let path = cert
        .verify_for_usage(
            algorithms,
            &roots.roots,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| format!("the chain does not verify for the revocation check: {e}"))?;
    let certs: Vec<&webpki::Cert<'_>> = path.intermediate_certificates().collect();
    let mut links = Vec::with_capacity(certs.len());
    for (i, cert) in certs.iter().enumerate() {
        let (issuer_spki, issuer_key_usage) = match certs.get(i + 1) {
            Some(issuer) => {
                let usage = der::key_usage(issuer.der().as_ref())
                    .map_err(|e| format!("an issuer's keyUsage cannot be read: {e}"))?;
                (issuer.subject_public_key_info().as_ref().to_vec(), usage)
            }
            None => (
                webpki::spki_for_anchor(path.anchor()).as_ref().to_vec(),
                None,
            ),
        };
        links.push(Link {
            der: cert.der().as_ref().to_vec(),
            issuer: cert.issuer().to_vec(),
            serial: cert.serial().to_vec(),
            issuer_spki,
            issuer_key_usage,
        });
    }
    Ok(Path { links })
}

/// What one check of the intermediates works with: the handshake's
/// algorithms, the source and the CA cache of its `TlsConfig`.
pub(crate) struct Context<'a> {
    pub(crate) algorithms: &'a [&'static dyn SignatureVerificationAlgorithm],
    pub(crate) source: &'a dyn CrlSource,
    pub(crate) cache: &'a Mutex<CaCache>,
}

/// What one distribution point gave.
enum Outcome {
    /// Not revoked, by these lists.
    Settled(RevocationStatus, Vec<Arc<CaList>>),
    Failed(RevocationFailure),
}

/// One intermediate and the time of the check.
struct Cert<'a> {
    subject: Subject<'a>,
    issuer: IssuerKey<'a>,
    secs: u64,
    deadline: Instant,
}

/// Checks every intermediate of `path` at `secs` (Unix seconds), from the
/// anchor side down, under one `deadline` and at most `budget` fetches.
/// The statuses come back in path order, the leaf's issuer's first. A
/// revoked intermediate is `Error::Revoked` with its issuer's list, at
/// once; one that no list settles is `Error::RevocationUnknown`, each
/// failure's detail prefixed with `intermediate k of n` (k = 1 is the
/// leaf's issuer).
pub(crate) fn check_intermediates(
    ctx: &Context<'_>,
    path: &Path,
    budget: usize,
    deadline: Instant,
    secs: u64,
) -> crate::Result<Vec<RevocationStatus>> {
    let n = path.links.len();
    let mut fetches_left = budget;
    let mut statuses = Vec::with_capacity(n);
    for (i, link) in path.links.iter().enumerate().rev() {
        let status =
            check_link(ctx, link, &mut fetches_left, deadline, secs).map_err(|e| match e {
                Error::RevocationUnknown(failures) => Error::RevocationUnknown(
                    failures
                        .into_iter()
                        .map(|f| RevocationFailure {
                            detail: format!("intermediate {} of {n}: {}", i + 1, f.detail),
                            ..f
                        })
                        .collect(),
                ),
                other => other,
            })?;
        statuses.push(status);
    }
    statuses.reverse();
    Ok(statuses)
}

/// One intermediate: its points by the leaf's rules (ADR-017, item 3),
/// then each in order (ADR-017, item 4).
fn check_link(
    ctx: &Context<'_>,
    link: &Link,
    fetches_left: &mut usize,
    deadline: Instant,
    secs: u64,
) -> crate::Result<RevocationStatus> {
    let uris = der::distribution_point_uris(&link.der).map_err(|e| {
        Error::RevocationUnknown(vec![RevocationFailure::new(
            None,
            RevocationFailureKind::BadUrl,
            format!("the certificate's CRL distribution points cannot be read: {e}"),
        )])
    })?;
    let candidates: Vec<Candidate> = uris
        .iter()
        .map(|uri| url::classify(uri))
        .filter(|c| *c != Candidate::Skip)
        .take(MAX_CRL_URLS)
        .collect();
    // D2: no `http` or `https` point, nothing to check against.
    if candidates.is_empty() {
        return Ok(RevocationStatus::NoRevocationSource);
    }
    let cert = Cert {
        subject: Subject {
            issuer: &link.issuer,
            serial: &link.serial,
            points: &uris,
        },
        issuer: IssuerKey {
            spki: &link.issuer_spki,
            key_usage: link.issuer_key_usage,
        },
        secs,
        deadline,
    };
    let urls: Vec<&CrlUrl> = candidates
        .iter()
        .filter_map(|c| match c {
            Candidate::Fetch(url) => Some(url),
            _ => None,
        })
        .collect();
    let mut failures = Vec::new();
    for candidate in &candidates {
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
        match check_url(ctx, url, &cert, fetches_left)? {
            Outcome::Settled(status, used) => {
                cached_revocation(ctx, &urls, &used, &cert)?;
                return Ok(status);
            }
            Outcome::Failed(failure) => failures.push(failure),
        }
    }
    Err(Error::RevocationUnknown(failures))
}

/// A revocation the CA cache holds for any of the certificate's points
/// wins over the list that just passed it, as for the leaf (ADR-017, item
/// 8): every cached list of those points still before its `nextUpdate`
/// is decided for this certificate.
fn cached_revocation(
    ctx: &Context<'_>,
    urls: &[&CrlUrl],
    used: &[Arc<CaList>],
    cert: &Cert<'_>,
) -> crate::Result<()> {
    // Collected under the lock, decided outside it.
    let cached: Vec<(&CrlUrl, Arc<CaList>)> = {
        let cache = lock(ctx.cache);
        urls.iter()
            .flat_map(|url| {
                cache
                    .peek(url.as_str(), cert.secs)
                    .into_iter()
                    .map(move |list| (*url, list))
            })
            .collect()
    };
    for (url, list) in cached {
        if used.iter().any(|u| Arc::ptr_eq(u, &list)) {
            continue;
        }
        if decide(ctx, &list, cert) == Verdict::Revoked {
            return Err(revoked(url));
        }
    }
    Ok(())
}

/// Takes one fetch from the budget; whether there was one.
fn take(fetches_left: &mut usize) -> bool {
    match fetches_left.checked_sub(1) {
        Some(left) => {
            *fetches_left = left;
            true
        }
        None => false,
    }
}

/// One distribution point: the cache, then a fetch where it says so and
/// the budget allows. `Revoked` is an error at once.
fn check_url(
    ctx: &Context<'_>,
    url: &CrlUrl,
    cert: &Cert<'_>,
    fetches_left: &mut usize,
) -> crate::Result<Outcome> {
    let lookup = lock(ctx.cache).lookup(url.as_str(), cert.secs);
    match lookup {
        Lookup::Fresh(lists) => decide_cached(ctx, url, lists, cert, false),
        Lookup::Stale(lists) => decide_cached(ctx, url, lists, cert, true),
        Lookup::Refresh(lists, cached_this_update) => {
            // The lookup claimed the refresh. With the budget spent it is
            // left to the cached list and counts as a failed refresh, so
            // the next one waits `CRL_REFRESH_RETRY_SECS`.
            if take(fetches_left)
                && let Ok(fetched) = fetch(ctx, url, cert)
                && fetched.this_update >= cached_this_update
            {
                match fetched.verdict {
                    Verdict::Good => {
                        let used = vec![Arc::clone(&fetched.list)];
                        store(ctx, url, fetched, cert.secs);
                        return Ok(Outcome::Settled(checked(url), used));
                    }
                    Verdict::Revoked => {
                        store(ctx, url, fetched, cert.secs);
                        return Err(revoked(url));
                    }
                    Verdict::Expired(_) | Verdict::NotSettled(_) | Verdict::Malformed(_) => {}
                }
            }
            decide_cached(ctx, url, lists, cert, true)
        }
        Lookup::Missing => {
            if !take(fetches_left) {
                return Ok(Outcome::Failed(RevocationFailure::new(
                    Some(url),
                    RevocationFailureKind::LimitReached,
                    "the connection's fetches of CA lists are spent",
                )));
            }
            let fetched = match fetch(ctx, url, cert) {
                Ok(fetched) => fetched,
                Err(failure) => return Ok(Outcome::Failed(failure)),
            };
            let failed = |kind, detail| {
                Ok(Outcome::Failed(RevocationFailure::new(
                    Some(url),
                    kind,
                    detail,
                )))
            };
            match fetched.verdict.clone() {
                Verdict::Good => {
                    let used = vec![Arc::clone(&fetched.list)];
                    store(ctx, url, fetched, cert.secs);
                    Ok(Outcome::Settled(checked(url), used))
                }
                Verdict::Revoked => {
                    store(ctx, url, fetched, cert.secs);
                    Err(revoked(url))
                }
                Verdict::Expired(detail) => failed(RevocationFailureKind::Expired, detail),
                Verdict::NotSettled(detail) => failed(RevocationFailureKind::NotSettled, detail),
                Verdict::Malformed(detail) => failed(RevocationFailureKind::Malformed, detail),
            }
        }
    }
}

fn checked(url: &CrlUrl) -> RevocationStatus {
    RevocationStatus::Checked {
        url: url.as_str().to_owned(),
    }
}

/// A list fetched, size-checked and parsed, with its verdict on the
/// certificate it was fetched for.
struct Fetched {
    list: Arc<CaList>,
    digest: [u8; 32],
    this_update: u64,
    next_update: u64,
    verdict: Verdict,
}

/// Fetches the list at `url` under `MAX_CA_CRL_BYTES` and decides it.
fn fetch(ctx: &Context<'_>, url: &CrlUrl, cert: &Cert<'_>) -> Result<Fetched, RevocationFailure> {
    let bytes = ctx
        .source
        .fetch_limited(url, MAX_CA_CRL_BYTES, cert.deadline)
        .map_err(|e| RevocationFailure::from_fetch(url, e))?;
    // Any source, not only the HTTP one, is held to the cap.
    if bytes.len() > MAX_CA_CRL_BYTES {
        return Err(RevocationFailure::new(
            Some(url),
            RevocationFailureKind::TooLarge,
            format!("{} bytes", bytes.len()),
        ));
    }
    let (this_update, next_update, verdict) = {
        let parsed = ca_list::parse(&bytes).map_err(|e| {
            RevocationFailure::new(Some(url), RevocationFailureKind::Malformed, e.0)
        })?;
        let verdict = parsed.decide(&cert.subject, &cert.issuer, ctx.algorithms, cert.secs);
        (parsed.this_update, parsed.next_update, verdict)
    };
    Ok(Fetched {
        digest: crate::Sha256::digest(&bytes),
        list: Arc::new(CaList { der: bytes }),
        this_update,
        next_update,
        verdict,
    })
}

/// Caches a list that settled a certificate.
fn store(ctx: &Context<'_>, url: &CrlUrl, fetched: Fetched, now: u64) {
    let der_len = fetched.list.der.len();
    let entry = Entry::new(
        fetched.list,
        fetched.digest,
        fetched.this_update,
        fetched.next_update,
        der_len,
        now,
    );
    lock(ctx.cache).insert(url.as_str(), entry, now);
}

fn decide(ctx: &Context<'_>, list: &CaList, cert: &Cert<'_>) -> Verdict {
    ca_list::decide(
        &list.der,
        &cert.subject,
        &cert.issuer,
        ctx.algorithms,
        cert.secs,
    )
}

/// The answer of a URL's cached lists, each decided for this certificate;
/// `stale` when they are past their maximum age. Any list that revokes it
/// wins; otherwise it passes when at least one list settles it.
fn decide_cached(
    ctx: &Context<'_>,
    url: &CrlUrl,
    lists: Vec<Arc<CaList>>,
    cert: &Cert<'_>,
    stale: bool,
) -> crate::Result<Outcome> {
    let mut good = Vec::new();
    let mut failure = None;
    for list in lists {
        match decide(ctx, &list, cert) {
            Verdict::Revoked => return Err(revoked(url)),
            Verdict::Good => good.push(list),
            Verdict::Expired(detail) => {
                failure.get_or_insert((RevocationFailureKind::Expired, detail));
            }
            Verdict::NotSettled(detail) => {
                failure.get_or_insert((RevocationFailureKind::NotSettled, detail));
            }
            Verdict::Malformed(detail) => {
                failure.get_or_insert((RevocationFailureKind::Malformed, detail));
            }
        }
    }
    if good.is_empty() {
        let (kind, detail) = failure.unwrap_or((
            RevocationFailureKind::NotSettled,
            "no cached list".to_owned(),
        ));
        return Ok(Outcome::Failed(RevocationFailure::new(
            Some(url),
            kind,
            detail,
        )));
    }
    let url = url.as_str().to_owned();
    let status = if stale {
        RevocationStatus::CheckedStale { url }
    } else {
        RevocationStatus::Checked { url }
    };
    Ok(Outcome::Settled(status, good))
}

#[cfg(test)]
impl Link {
    /// The verdict of the list `der` on this intermediate at `now`.
    pub(crate) fn verdict(
        &self,
        der: &[u8],
        algorithms: &[&dyn SignatureVerificationAlgorithm],
        now: u64,
    ) -> Verdict {
        let points = der::distribution_point_uris(&self.der).expect("points");
        let subject = Subject {
            issuer: &self.issuer,
            serial: &self.serial,
            points: &points,
        };
        let issuer = IssuerKey {
            spki: &self.issuer_spki,
            key_usage: self.issuer_key_usage,
        };
        ca_list::decide(der, &subject, &issuer, algorithms, now)
    }

    /// The serial, the content of the INTEGER.
    pub(crate) fn serial(&self) -> &[u8] {
        &self.serial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::time::Duration;

    use super::super::ca_list::testing::{
        self, CA1, CA1_NO_CRL_SIGN, CA2, ListSpec, ROOT, T0, WEEK1_END,
    };
    use super::super::{
        CA_CRL_CACHE_MAX_BYTES, CRL_MAX_AGE_SECS, CRL_REFRESH_RETRY_SECS, CrlFetchError,
        MAX_CA_CRL_FETCHES,
    };

    const LEAF_CA1: &[u8] = include_bytes!("../../tests/data/chain-leaf-ca1.pem");
    const LEAF_CA2: &[u8] = include_bytes!("../../tests/data/chain-leaf-ca2.pem");
    const STRAY: &[u8] = include_bytes!("../../tests/data/chain-stray-ca.pem");

    const ROOT_CRL1: &str = "http://crl1.boneli.test/root.crl";
    const ROOT_CRL2: &str = "http://crl2.boneli.test/root.crl";
    const CA1_CRL1: &str = "http://crl1.boneli.test/ca1.crl";

    fn algorithms() -> &'static [&'static dyn SignatureVerificationAlgorithm] {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .all
    }

    fn time(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    fn roots() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(testing::pem_der(ROOT)))
            .expect("root");
        roots
    }

    fn der(pem: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(testing::pem_der(pem))
    }

    fn path(leaf: &[u8], sent: &[&[u8]]) -> Path {
        let sent: Vec<CertificateDer<'static>> = sent.iter().map(|pem| der(pem)).collect();
        verified_path(&roots(), algorithms(), &der(leaf), &sent, time(T0 + 3_600)).expect("path")
    }

    type Reply = Result<Vec<u8>, CrlFetchError>;

    /// A source that answers from a script and records each URL.
    #[derive(Default)]
    struct Script {
        replies: Mutex<VecDeque<Reply>>,
        asked: Mutex<Vec<String>>,
    }

    impl Script {
        fn new(replies: Vec<Reply>) -> Script {
            Script {
                replies: Mutex::new(replies.into()),
                asked: Mutex::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().expect("asked").clone()
        }
    }

    impl CrlSource for Script {
        fn fetch(&self, url: &CrlUrl, _deadline: Instant) -> Reply {
            self.asked
                .lock()
                .expect("asked")
                .push(url.as_str().to_owned());
            self.replies
                .lock()
                .expect("replies")
                .pop_front()
                .unwrap_or_else(|| Err(CrlFetchError::Unreachable("script ended".into())))
        }
    }

    fn check(
        source: &Script,
        cache: &Mutex<CaCache>,
        path: &Path,
        budget: usize,
        secs: u64,
    ) -> crate::Result<Vec<RevocationStatus>> {
        let ctx = Context {
            algorithms: algorithms(),
            source,
            cache,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        check_intermediates(&ctx, path, budget, deadline, secs)
    }

    fn cache() -> Mutex<CaCache> {
        Mutex::new(CaCache::new(CA_CRL_CACHE_MAX_BYTES))
    }

    fn checked(url: &str) -> RevocationStatus {
        RevocationStatus::Checked { url: url.into() }
    }

    fn stale(url: &str) -> RevocationStatus {
        RevocationStatus::CheckedStale { url: url.into() }
    }

    fn kinds(result: crate::Result<Vec<RevocationStatus>>) -> Vec<RevocationFailureKind> {
        match result {
            Err(Error::RevocationUnknown(failures)) => failures.iter().map(|f| f.kind).collect(),
            other => panic!("expected RevocationUnknown, got {other:?}"),
        }
    }

    #[test]
    fn path_holds_the_intermediates_leaf_issuer_first() {
        let one = path(LEAF_CA1, &[CA1]);
        assert_eq!(one.links.len(), 1);
        let link = &one.links[0];
        assert_eq!(link.der, testing::pem_der(CA1));
        assert_eq!(link.serial, [0x11]);
        assert_eq!(
            crate::der::encode(crate::der::SEQUENCE, &link.issuer),
            testing::subject_name(ROOT)
        );
        // The anchor is the top one's issuer; its key usage is not read.
        assert_eq!(link.issuer_key_usage, None);

        let two = path(LEAF_CA2, &[CA2, CA1]);
        assert_eq!(two.links.len(), 2);
        assert_eq!(two.links[0].der, testing::pem_der(CA2));
        assert_eq!(two.links[1].der, testing::pem_der(CA1));
        // CA 2's issuer is CA 1: its key and its keyUsage.
        let ca1_der = der(CA1);
        let ca1 = webpki::EndEntityCert::try_from(&ca1_der).expect("CA 1");
        assert_eq!(
            two.links[0].issuer_spki,
            ca1.subject_public_key_info().as_ref()
        );
        assert!(two.links[0].issuer_key_usage.expect("keyUsage").crl_sign());
        assert_eq!(
            two.links[1].issuer_spki,
            two.links[1].issuer_spki_of_anchor()
        );
    }

    impl Link {
        fn issuer_spki_of_anchor(&self) -> Vec<u8> {
            let root = der(ROOT);
            let anchor = webpki::anchor_from_trusted_cert(&root).expect("anchor");
            webpki::spki_for_anchor(&anchor).as_ref().to_vec()
        }
    }

    #[test]
    fn certificates_off_the_path_are_never_read() {
        // The root itself and a stray CA beside the path.
        let path = path(LEAF_CA1, &[CA1, ROOT, STRAY]);
        assert_eq!(path.links.len(), 1);
        assert_eq!(path.links[0].der, testing::pem_der(CA1));
        let path = verified_path(
            &roots(),
            algorithms(),
            &der(LEAF_CA1),
            &[der(ROOT)],
            time(T0),
        );
        assert!(path.is_err(), "CA 1 is missing: no path");
    }

    #[test]
    fn no_crl_sign_issuer_is_carried_to_the_decision() {
        let path = path(LEAF_CA2, &[CA2, CA1_NO_CRL_SIGN]);
        assert!(!path.links[0].issuer_key_usage.expect("keyUsage").crl_sign());
        let source = Script::new(vec![
            Ok(ListSpec::root().build()),
            Ok(ListSpec::ca1().build()),
            Ok(ListSpec::ca1().build()),
        ]);
        assert_eq!(
            kinds(check(&source, &cache(), &path, 8, T0 + 3_600)),
            [
                RevocationFailureKind::NotSettled,
                RevocationFailureKind::NotSettled
            ]
        );
    }

    #[test]
    fn statuses_come_back_leaf_issuer_first() {
        let path = path(LEAF_CA2, &[CA2, CA1]);
        let source = Script::new(vec![
            Ok(ListSpec::root().build()),
            Ok(ListSpec::ca1().build()),
        ]);
        assert_eq!(
            check(&source, &cache(), &path, 8, T0 + 3_600).expect("check"),
            [checked(CA1_CRL1), checked(ROOT_CRL1)]
        );
        // The anchor side first.
        assert_eq!(source.asked(), [ROOT_CRL1, CA1_CRL1]);
    }

    #[test]
    fn spent_budget_leaves_refresh_to_cached_list() {
        let path = path(LEAF_CA1, &[CA1]);
        let cache = cache();
        let source = Script::new(vec![
            Ok(ListSpec::root().build()),
            Ok(ListSpec::root().build()),
        ]);
        assert_eq!(
            check(&source, &cache, &path, MAX_CA_CRL_FETCHES, T0).expect("warm"),
            [checked(ROOT_CRL1)]
        );
        // The refresh is due, the budget spent: the cached list decides,
        // nothing is fetched, and the claim counts as a failed refresh.
        let due = T0 + CRL_MAX_AGE_SECS;
        assert_eq!(
            check(&source, &cache, &path, 0, due).expect("stale"),
            [stale(ROOT_CRL1)]
        );
        assert_eq!(source.asked(), [ROOT_CRL1]);
        assert_eq!(
            check(
                &source,
                &cache,
                &path,
                MAX_CA_CRL_FETCHES,
                due + CRL_REFRESH_RETRY_SECS - 1
            )
            .expect("waiting"),
            [stale(ROOT_CRL1)]
        );
        assert_eq!(source.asked(), [ROOT_CRL1]);
        assert_eq!(
            check(
                &source,
                &cache,
                &path,
                MAX_CA_CRL_FETCHES,
                due + CRL_REFRESH_RETRY_SECS
            )
            .expect("refreshed"),
            [checked(ROOT_CRL1)]
        );
        assert_eq!(source.asked(), [ROOT_CRL1, ROOT_CRL1]);
    }

    #[test]
    fn spent_budget_refuses_a_missing_list_without_a_fetch() {
        let path = path(LEAF_CA1, &[CA1]);
        let source = Script::new(vec![Ok(ListSpec::root().build())]);
        assert_eq!(
            kinds(check(&source, &cache(), &path, 0, T0)),
            [
                RevocationFailureKind::LimitReached,
                RevocationFailureKind::LimitReached
            ]
        );
        assert!(source.asked().is_empty());
        // One fetch left: the first URL takes it.
        let source = Script::new(vec![Err(CrlFetchError::TimedOut)]);
        assert_eq!(
            kinds(check(&source, &cache(), &path, 1, T0)),
            [
                RevocationFailureKind::TimedOut,
                RevocationFailureKind::LimitReached
            ]
        );
        assert_eq!(source.asked(), [ROOT_CRL1]);
    }

    #[test]
    fn cached_ca_list_is_reverified_per_issuer() {
        let path = path(LEAF_CA1, &[CA1]);
        let cache = cache();
        let source = Script::new(vec![Ok(ListSpec::root().build())]);
        check(&source, &cache, &path, 8, T0).expect("warm");
        // Certificates that name the root's URLs and are not the root's:
        // one under CA 1's name, one under the root's name with CA 1's
        // key. The cached root list is decided again for each and settles
        // neither; nothing is fetched for crl1, which is fresh.
        let ca2 = self::path(LEAF_CA2, &[CA2, CA1]).links[0].clone();
        let other_name = Link {
            der: testing::pem_der(CA1),
            ..ca2.clone()
        };
        let other_key = Link {
            issuer_spki: ca2.issuer_spki.clone(),
            ..path.links[0].clone()
        };
        for link in [other_name, other_key] {
            let source = Script::new(vec![]);
            let found = kinds(check(
                &source,
                &cache,
                &Path { links: vec![link] },
                8,
                T0 + 1,
            ));
            assert_eq!(
                found,
                [
                    RevocationFailureKind::NotSettled,
                    RevocationFailureKind::Unreachable
                ]
            );
            assert_eq!(source.asked(), [ROOT_CRL2]);
        }
        // The certificate it was cached for still passes from the cache.
        let source = Script::new(vec![]);
        assert_eq!(
            check(&source, &cache, &path, 8, T0 + 1).expect("cached"),
            [checked(ROOT_CRL1)]
        );
    }

    #[test]
    fn revocation_cached_for_other_point_wins() {
        // crl1 unreachable, crl2 revokes; then crl1 passes with an older
        // list, and the cached revocation at crl2 still decides.
        let path = path(LEAF_CA1, &[CA1]);
        let cache = cache();
        let revoking = ListSpec::window(
            testing::subject_name(ROOT),
            testing::ROOT_KEY,
            T0,
            WEEK1_END,
        )
        .listing(&[&[0x11]])
        .build();
        let older = ListSpec::window(
            testing::subject_name(ROOT),
            testing::ROOT_KEY,
            T0 - 60,
            WEEK1_END,
        )
        .build();
        let source = Script::new(vec![
            Err(CrlFetchError::Unreachable("down".into())),
            Ok(revoking),
            Ok(older),
        ]);
        for _ in 0..2 {
            match check(&source, &cache, &path, 8, T0 + 60) {
                Err(Error::Revoked { url }) => assert_eq!(url, ROOT_CRL2),
                other => panic!("expected Revoked, got {other:?}"),
            }
        }
        assert_eq!(source.asked(), [ROOT_CRL1, ROOT_CRL2, ROOT_CRL1]);
    }

    #[test]
    fn failure_details_name_the_intermediate() {
        let path = path(LEAF_CA2, &[CA2, CA1]);
        let source = Script::new(vec![Ok(ListSpec::root().build())]);
        match check(&source, &cache(), &path, 8, T0) {
            Err(Error::RevocationUnknown(failures)) => {
                assert_eq!(failures.len(), 2);
                for f in failures {
                    assert!(
                        f.detail.starts_with("intermediate 1 of 2: "),
                        "{}",
                        f.detail
                    );
                }
            }
            other => panic!("expected RevocationUnknown, got {other:?}"),
        }
    }
}
