//! Certificate revocation by CRL (ADR-017) and OCSP (ADR-020), of the
//! leaf and of the intermediates on its verified path (ADR-027).
//!
//! After rustls has verified the chain in the handshake, the check reads
//! the CRL distribution points of the verified leaf, fetches each CRL
//! through a [`CrlSource`], caches it, and verifies the chain a second
//! time with rustls' `WebPkiServerVerifier` built with that list: leaf
//! only, unknown status is an error, an expired list is an error. A leaf
//! listed in a list fails the connection with `Error::Revoked`; a leaf that
//! names a point no list settles fails it with `Error::RevocationUnknown`
//! (D1: fail closed, no opt-out). A leaf that names no fetchable point
//! but an OCSP responder is checked by OCSP instead (`ocsp`, ADR-020),
//! with the same outcomes; a leaf with neither passes unchecked (ADR-017,
//! D2).
//!
//! Before the leaf, every intermediate on the path webpki verifies is
//! checked against its issuer's CRL (`chain`, ADR-027), from the anchor
//! side down, with a strict list parser of its own (`ca_list`), a cache of
//! its own and a fetch budget per connection; a listed intermediate fails
//! the connection with `Error::Revoked`, one whose points no list settles
//! with `Error::RevocationUnknown`, and one without an `http` or `https`
//! point passes unchecked (D2). The anchor is never checked.
//!
//! The check runs on `peer_certificates()` after the handshake, not in a
//! verifier inside it, because rustls skips the verifier on resumed
//! sessions but restores the peer chain from them (ADR-017, item 1).

mod ca_list;
mod cache;
mod chain;
mod der;
mod http;
mod ocsp;
mod signature;
mod url;

pub use ocsp::{
    MAX_OCSP_RESPONSE_BYTES, MAX_OCSP_RESPONSE_CERTS, MAX_OCSP_URLS, OCSP_CACHE_MAX_ENTRIES,
    OCSP_CHECK_DEADLINE, OCSP_MAX_AGE_SECS, OCSP_REFRESH_RETRY_SECS, OcspSource,
};
pub use url::{CrlScheme, CrlUrl};

pub(crate) use http::HttpSource;

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
use rustls::{CertificateError, RootCertStore};

use crate::Error;
use cache::{CrlCache, Entry, Lookup};
use chain::CaCache;
use ocsp::OcspCache;
use url::Candidate;

/// The largest CRL accepted, in bytes (32 MiB; D4): 3.05 times the largest
/// list measured for ADR-017 (11,005,110 B). A `Content-Length` above it
/// fails before the body is read.
pub const MAX_CRL_BYTES: usize = 33_554_432;

/// The DER bytes one `TlsConfig`'s cache holds at most (64 MiB; D4): two
/// lists at `MAX_CRL_BYTES`, and 3.5 times all leaf lists measured for
/// ADR-017. Least recently used lists go first.
pub const CRL_CACHE_MAX_BYTES: usize = 67_108_864;

/// How long a cached list is used without a fetch after a fetch last
/// returned it (24 h; D5, ADR-017 item 8). Never past its `nextUpdate`.
pub const CRL_MAX_AGE_SECS: u64 = 86_400;

/// The wait after a failed refresh before the next one (1 h; ADR-017
/// item 8); meanwhile the cached list decides until its `nextUpdate`.
pub const CRL_REFRESH_RETRY_SECS: u64 = 3_600;

/// The most URLs tried for one leaf: twice the measured maximum of 2.
pub const MAX_CRL_URLS: usize = 4;

/// The longest distribution point URL accepted, in bytes.
pub const MAX_CRL_URL_BYTES: usize = 1_024;

/// Each TCP connection attempt of a fetch: lets three SYN
/// retransmissions through (1, 3 and 7 s).
pub const CRL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The TLS handshake of an `https` point.
pub const CRL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Each read and write of a fetch: three lost segments in a row (1 + 2 +
/// 4 s) still pass.
pub const CRL_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// What a fetch needs before its body: connect, handshake and a round
/// trip with the server's time.
pub const CRL_SETUP_TIME: Duration = Duration::from_secs(30);

/// The slowest transfer rate a fetch of a list at `MAX_CRL_BYTES` is
/// given time for, in bytes per second.
pub const CRL_MIN_RATE: u64 = 1_048_576;

/// The deadline of one check, shared by all its URLs: the setup time plus
/// `MAX_CRL_BYTES` at `CRL_MIN_RATE`, 62 s. A `TlsDial` request's own
/// deadline cuts it shorter.
pub const CRL_CHECK_DEADLINE: Duration =
    Duration::from_secs(CRL_SETUP_TIME.as_secs() + MAX_CRL_BYTES as u64 / CRL_MIN_RATE);

/// The largest response head of a fetch, in bytes. Shared by CRL and
/// OCSP fetches, as are the timeouts above (ADR-020, item 7).
pub const CRL_MAX_HEAD_BYTES: usize = 16_384;

/// The most header fields in the response head of a fetch.
pub const CRL_MAX_HEADERS: usize = 64;

/// The largest CA list accepted, in bytes (1 MiB; ADR-027, D3): 486 times
/// the largest measured list of an intermediate's issuer (2,157 B). A
/// `Content-Length` above it fails before the body is read.
pub const MAX_CA_CRL_BYTES: usize = 1_048_576;

/// The most CA list fetches of one connection, refreshes included
/// (ADR-027, D3): twice the measured cold-cache worst case of 4 (two
/// intermediates, two URLs each), and room for webpki's maximum of six
/// intermediates with one working URL each. Past it, a missing list fails
/// closed with `RevocationFailureKind::LimitReached` and a due refresh is
/// left to the cached list. The leaf's fetches do not count.
pub const MAX_CA_CRL_FETCHES: usize = 8;

/// The deadline of the intermediates' check of one connection, shared by
/// all their URLs: the setup time plus `MAX_CA_CRL_FETCHES` lists at
/// `MAX_CA_CRL_BYTES` at `CRL_MIN_RATE`, 38 s (ADR-027, D3). The leaf's
/// check follows with its own deadline; a `TlsDial` request's deadline
/// cuts both shorter.
pub const CA_CRL_CHECK_DEADLINE: Duration = Duration::from_secs(
    CRL_SETUP_TIME.as_secs() + (MAX_CA_CRL_FETCHES * MAX_CA_CRL_BYTES) as u64 / CRL_MIN_RATE,
);

/// The DER bytes one `TlsConfig`'s CA cache holds at most (16 MiB;
/// ADR-027, D3): 16 lists at `MAX_CA_CRL_BYTES`. Least recently used
/// lists go first.
pub const CA_CRL_CACHE_MAX_BYTES: usize = 16_777_216;

/// Where CRLs come from. Not a verifier hook: whatever a source returns is
/// verified against the roots, the certificate's issuer and point, and
/// the system clock: by webpki for a leaf (ADR-017, item 10), by
/// `ca_list` for an intermediate (ADR-027). A source can make a
/// connection fail, hand over an older CA-signed list that is still
/// before its `nextUpdate` on a cold cache, or keep a cached list in use
/// until its `nextUpdate` by failing every refresh, and nothing else.
pub trait CrlSource: Send + Sync {
    /// The DER bytes at `url`, fetched by `deadline`.
    fn fetch(&self, url: &CrlUrl, deadline: Instant) -> Result<Vec<u8>, CrlFetchError>;

    /// The DER bytes at `url`, fetched by `deadline`, where a body above
    /// `cap` bytes may fail early as `CrlFetchError::TooLarge`: the fetch
    /// of an intermediate's list (`MAX_CA_CRL_BYTES`, ADR-027). The
    /// default is `fetch`; whatever a source returns is held to the cap
    /// after the fetch anyway.
    fn fetch_limited(
        &self,
        url: &CrlUrl,
        cap: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, CrlFetchError> {
        let _ = cap;
        self.fetch(url, deadline)
    }
}

/// Why a source returned no list or response; shared by `CrlSource` and
/// `OcspSource`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrlFetchError {
    /// No connection, or the connection failed.
    Unreachable(String),
    /// A read, write or connection attempt, or the deadline, ran out.
    TimedOut,
    /// A status other than 200; redirects are not followed.
    Status(u16),
    /// More than `MAX_CRL_BYTES`, `MAX_CA_CRL_BYTES` for an
    /// intermediate's list, or `MAX_OCSP_RESPONSE_BYTES` for OCSP.
    TooLarge,
    /// A response this client does not accept, such as a content coding
    /// or a head over its limits.
    Malformed(String),
}

impl fmt::Display for CrlFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrlFetchError::Unreachable(why) => write!(f, "unreachable: {why}"),
            CrlFetchError::TimedOut => f.write_str("timed out"),
            CrlFetchError::Status(status) => write!(f, "status {status}"),
            CrlFetchError::TooLarge => f.write_str("larger than the size cap"),
            CrlFetchError::Malformed(why) => write!(f, "malformed response: {why}"),
        }
    }
}

impl std::error::Error for CrlFetchError {}

/// What the revocation check of one certificate of a connection found:
/// the leaf (`TlsStream::revocation`) or an intermediate
/// (`TlsStream::intermediate_revocation`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The list at `url` settled the certificate as not revoked.
    Checked {
        /// The canonical URL of the list.
        url: String,
    },
    /// A cached list past its maximum age settled the certificate, because its
    /// refresh is failing or another connection is running it. The list is
    /// still before its `nextUpdate`; from then on the check fails closed.
    CheckedStale {
        /// The canonical URL of the list.
        url: String,
    },
    /// The OCSP responder at `url` settled the leaf as not revoked
    /// (ADR-020).
    OcspChecked {
        /// The canonical URL of the responder.
        url: String,
    },
    /// A cached OCSP answer past its maximum age settled the leaf, because
    /// its refresh is failing or another connection is running it. The
    /// answer is still before its `nextUpdate`; from then on the check
    /// fails closed.
    OcspCheckedStale {
        /// The canonical URL of the responder.
        url: String,
    },
    /// The certificate names neither an `http` or `https` CRL
    /// distribution point nor, for a leaf, such an OCSP responder, so it
    /// passes unchecked (ADR-017, D2; ADR-027, D2 for an intermediate).
    NoRevocationSource,
}

/// Why one distribution point or OCSP responder did not settle a
/// certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationFailureKind {
    /// Not a URL this client fetches, or the extension cannot be read.
    BadUrl,
    /// No connection, or it failed.
    Unreachable,
    /// The fetch ran out of time.
    TimedOut,
    /// A status other than 200.
    Status,
    /// More than `MAX_CRL_BYTES`, `MAX_CA_CRL_BYTES` or
    /// `MAX_OCSP_RESPONSE_BYTES`.
    TooLarge,
    /// Not a CRL webpki accepts (a leaf's) or `ca_list` accepts (an
    /// intermediate's), or an OCSP response this client parses, or its
    /// dates are reversed or missing.
    Malformed,
    /// At or past its `nextUpdate`.
    Expired,
    /// A valid list that does not cover the certificate (another issuer,
    /// another shard or scope, a bad signature), or an OCSP response that
    /// names another certificate.
    NotSettled,
    /// An OCSP responder answered with an error status: `malformedRequest`,
    /// `internalError`, `tryLater`, `sigRequired` or `unauthorized`.
    ResponderError,
    /// An OCSP responder does not know the certificate (`unknown`).
    UnknownCertificate,
    /// An OCSP response not signed by the leaf's issuer or a responder
    /// it authorized.
    BadSignature,
    /// The connection's `MAX_CA_CRL_FETCHES` fetches of intermediates'
    /// lists were spent before this one (ADR-027); nothing was fetched.
    LimitReached,
}

impl fmt::Display for RevocationFailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RevocationFailureKind::BadUrl => "bad URL",
            RevocationFailureKind::Unreachable => "unreachable",
            RevocationFailureKind::TimedOut => "timed out",
            RevocationFailureKind::Status => "unexpected status",
            RevocationFailureKind::TooLarge => "too large",
            RevocationFailureKind::Malformed => "malformed",
            RevocationFailureKind::Expired => "expired",
            RevocationFailureKind::NotSettled => "does not settle the certificate",
            RevocationFailureKind::ResponderError => "responder error",
            RevocationFailureKind::UnknownCertificate => "unknown certificate",
            RevocationFailureKind::BadSignature => "bad signature",
            RevocationFailureKind::LimitReached => "fetch limit reached",
        })
    }
}

/// One distribution point or OCSP responder that did not settle a
/// certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationFailure {
    /// The canonical URL, when the point or responder was one.
    pub url: Option<String>,
    /// What went wrong.
    pub kind: RevocationFailureKind,
    /// The details, for logs.
    pub detail: String,
}

impl RevocationFailure {
    fn new(
        url: Option<&CrlUrl>,
        kind: RevocationFailureKind,
        detail: impl Into<String>,
    ) -> RevocationFailure {
        RevocationFailure {
            url: url.map(|u| u.as_str().to_owned()),
            kind,
            detail: detail.into(),
        }
    }

    fn from_fetch(url: &CrlUrl, e: CrlFetchError) -> RevocationFailure {
        let kind = match e {
            CrlFetchError::Unreachable(_) => RevocationFailureKind::Unreachable,
            CrlFetchError::TimedOut => RevocationFailureKind::TimedOut,
            CrlFetchError::Status(_) => RevocationFailureKind::Status,
            CrlFetchError::TooLarge => RevocationFailureKind::TooLarge,
            CrlFetchError::Malformed(_) => RevocationFailureKind::Malformed,
        };
        RevocationFailure::new(Some(url), kind, e.to_string())
    }
}

impl fmt::Display for RevocationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.url {
            Some(url) => write!(f, "{url}: {} ({})", self.kind, self.detail),
            None => write!(f, "{} ({})", self.kind, self.detail),
        }
    }
}

/// The revocation check of one `TlsConfig`.
pub(crate) struct Revocation {
    mode: Mode,
}

enum Mode {
    /// Only the crate-private configuration of an `https` CRL or OCSP
    /// fetch (ADR-017, item 6); no public constructor builds it.
    Off,
    On {
        roots: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
        source: Arc<dyn CrlSource>,
        cache: Mutex<LeafCache>,
        /// The intermediates' lists (ADR-027): their own cache, so that a
        /// URL that is a leaf's point and an intermediate's keeps both.
        ca_cache: Mutex<CaCache>,
        ocsp_source: Arc<dyn OcspSource>,
        ocsp_cache: Mutex<OcspCache>,
    },
}

/// The cache of the leaves' lists, each kept as the webpki verifier built
/// with it.
type LeafCache = CrlCache<Arc<WebPkiServerVerifier>>;

/// What the check of a connection found: the leaf's status and each
/// intermediate's, the leaf's issuer first; no intermediate when a root
/// issued the leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChainStatus {
    pub(crate) leaf: RevocationStatus,
    pub(crate) intermediates: Vec<RevocationStatus>,
}

impl fmt::Debug for Revocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let on = matches!(self.mode, Mode::On { .. });
        f.debug_struct("Revocation").field("on", &on).finish()
    }
}

/// A list fetched and parsed, before it settled anything.
struct Fetched {
    verifier: Arc<WebPkiServerVerifier>,
    /// SHA-256 of the DER, which tells two lists with the same
    /// `thisUpdate` apart in the cache.
    digest: [u8; 32],
    this_update: u64,
    next_update: u64,
    der_len: usize,
}

/// What one list says about the leaf.
enum Verdict {
    Good,
    Revoked,
    Expired(String),
    NotSettled(String),
}

/// What one distribution point gave.
enum Outcome {
    /// Not revoked, by these lists.
    Settled(RevocationStatus, Vec<Arc<WebPkiServerVerifier>>),
    Failed(RevocationFailure),
}

/// The leaf and the time of one check.
struct Leaf<'a> {
    cert: &'a CertificateDer<'a>,
    intermediates: &'a [CertificateDer<'a>],
    name: &'a ServerName<'a>,
    now: UnixTime,
    secs: u64,
    deadline: Instant,
}

/// `started + limit`, never past `outer`.
fn deadline(limit: Duration, outer: Option<Instant>) -> Instant {
    let started = Instant::now();
    let deadline = started.checked_add(limit).unwrap_or(started);
    match outer {
        Some(outer) => deadline.min(outer),
        None => deadline,
    }
}

impl Revocation {
    /// Checks revocation with lists from `source` and OCSP responses from
    /// `ocsp_source`, verified against `roots` with `provider`'s
    /// algorithms: those of the handshake. All three caches start empty.
    pub(crate) fn on(
        roots: Arc<RootCertStore>,
        provider: Arc<CryptoProvider>,
        source: Arc<dyn CrlSource>,
        ocsp_source: Arc<dyn OcspSource>,
    ) -> Revocation {
        Revocation {
            mode: Mode::On {
                roots,
                provider,
                source,
                cache: Mutex::new(CrlCache::new(CRL_CACHE_MAX_BYTES)),
                ca_cache: Mutex::new(CrlCache::new(CA_CRL_CACHE_MAX_BYTES)),
                ocsp_source,
                ocsp_cache: Mutex::new(OcspCache::new()),
            },
        }
    }

    /// No check, for the connection of an `https` CRL or OCSP fetch only.
    pub(crate) fn off() -> Revocation {
        Revocation { mode: Mode::Off }
    }

    /// The same check with `crl` or `ocsp` in place of its sources, where
    /// given, and all caches empty. A check that is off stays off.
    pub(crate) fn with_sources(
        &self,
        crl: Option<Arc<dyn CrlSource>>,
        ocsp: Option<Arc<dyn OcspSource>>,
    ) -> Revocation {
        match &self.mode {
            Mode::Off => Revocation::off(),
            Mode::On {
                roots,
                provider,
                source,
                ocsp_source,
                ..
            } => Revocation::on(
                Arc::clone(roots),
                Arc::clone(provider),
                crl.unwrap_or_else(|| Arc::clone(source)),
                ocsp.unwrap_or_else(|| Arc::clone(ocsp_source)),
            ),
        }
    }

    /// The check at the system clock's time.
    pub(crate) fn check(
        &self,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        outer: Option<Instant>,
    ) -> crate::Result<ChainStatus> {
        self.check_chain_at(chain, name, outer, UnixTime::now())
    }

    /// The leaf's status only, for the tests of the leaf's rules.
    #[cfg(test)]
    pub(crate) fn check_at(
        &self,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        outer: Option<Instant>,
        now: UnixTime,
    ) -> crate::Result<RevocationStatus> {
        self.check_chain_at(chain, name, outer, now)
            .map(|status| status.leaf)
    }

    /// The check of a verified `chain` (leaf first) for `name` at `now`,
    /// which is used throughout: the caches, the validity of each list or
    /// answer and the path. First the intermediates on the path webpki
    /// verifies, from the anchor side down, under `CA_CRL_CHECK_DEADLINE`
    /// (ADR-027, item 1); then the leaf under its own deadline. `outer`
    /// cuts both deadlines shorter. A chain of the leaf alone has no
    /// intermediate to check: rustls verified it, so a root issued it.
    pub(crate) fn check_chain_at(
        &self,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        outer: Option<Instant>,
        now: UnixTime,
    ) -> crate::Result<ChainStatus> {
        let Mode::On {
            roots,
            provider,
            source,
            ca_cache,
            ..
        } = &self.mode
        else {
            // Never reaches a caller: only the connection of an `https`
            // CRL or OCSP fetch runs without a check.
            return Ok(ChainStatus {
                leaf: RevocationStatus::NoRevocationSource,
                intermediates: Vec::new(),
            });
        };
        let intermediates = match chain.split_first() {
            Some((cert, sent)) if !sent.is_empty() => {
                let algorithms = provider.signature_verification_algorithms.all;
                let path =
                    chain::verified_path(roots, algorithms, cert, sent, now).map_err(|detail| {
                        Error::RevocationUnknown(vec![RevocationFailure::new(
                            None,
                            RevocationFailureKind::NotSettled,
                            detail,
                        )])
                    })?;
                let ctx = chain::Context {
                    algorithms,
                    source: source.as_ref(),
                    cache: ca_cache,
                };
                chain::check_intermediates(
                    &ctx,
                    &path,
                    MAX_CA_CRL_FETCHES,
                    deadline(CA_CRL_CHECK_DEADLINE, outer),
                    now.as_secs(),
                )?
            }
            _ => Vec::new(),
        };
        let leaf = self.check_leaf(chain, name, outer, now)?;
        Ok(ChainStatus {
            leaf,
            intermediates,
        })
    }

    /// The leaf's check (ADR-017, ADR-020). A leaf with an `http` or
    /// `https` CRL point takes the CRL path only; a leaf without one and
    /// with such an OCSP responder takes the OCSP path (ADR-020, item 1).
    fn check_leaf(
        &self,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        outer: Option<Instant>,
        now: UnixTime,
    ) -> crate::Result<RevocationStatus> {
        let Mode::On {
            roots,
            provider,
            ocsp_source,
            ocsp_cache,
            ..
        } = &self.mode
        else {
            // Never reaches a caller: only the connection of an `https`
            // CRL or OCSP fetch runs without a check.
            return Ok(RevocationStatus::NoRevocationSource);
        };
        let Some((cert, intermediates)) = chain.split_first() else {
            return Err(Error::RevocationUnknown(vec![RevocationFailure::new(
                None,
                RevocationFailureKind::NotSettled,
                "the server sent no certificate",
            )]));
        };
        // rustls verified this leaf in the handshake: the reader reads
        // only bytes webpki has accepted (ADR-017, item 9).
        let uris = der::distribution_point_uris(cert.as_ref()).map_err(|e| {
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
        if candidates.is_empty() {
            let responders = der::ocsp_responder_uris(cert.as_ref()).map_err(|e| {
                Error::RevocationUnknown(vec![RevocationFailure::new(
                    None,
                    RevocationFailureKind::BadUrl,
                    format!("the certificate's OCSP responders cannot be read: {e}"),
                )])
            })?;
            let candidates = ocsp::candidates(&responders);
            if candidates.is_empty() {
                return Ok(RevocationStatus::NoRevocationSource);
            }
            let leaf = Leaf {
                cert,
                intermediates,
                name,
                now,
                secs: now.as_secs(),
                deadline: deadline(OCSP_CHECK_DEADLINE, outer),
            };
            let ctx = ocsp::Context {
                roots,
                algorithms: provider.signature_verification_algorithms.all,
                source: ocsp_source.as_ref(),
                cache: ocsp_cache,
            };
            return ocsp::check(&ctx, &leaf, &candidates);
        }
        let leaf = Leaf {
            cert,
            intermediates,
            name,
            now,
            secs: now.as_secs(),
            deadline: deadline(CRL_CHECK_DEADLINE, outer),
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
            match self.check_url(url, &leaf)? {
                Outcome::Settled(status, used) => {
                    self.cached_revocation(&urls, &used, &leaf)?;
                    return Ok(status);
                }
                Outcome::Failed(failure) => failures.push(failure),
            }
        }
        Err(Error::RevocationUnknown(failures))
    }

    /// A revocation the cache holds for any of the leaf's points wins over
    /// the list that just passed it (ADR-017, item 8): every cached list
    /// of those points still before its `nextUpdate`, fresh or stale, is
    /// consulted, so neither an older list from a mirror nor a list with
    /// the same `thisUpdate` can undo a revocation already seen.
    fn cached_revocation(
        &self,
        urls: &[&CrlUrl],
        used: &[Arc<WebPkiServerVerifier>],
        leaf: &Leaf<'_>,
    ) -> crate::Result<()> {
        let Mode::On { cache, .. } = &self.mode else {
            return Ok(());
        };
        // Collected under the lock, verified outside it.
        let cached: Vec<(&CrlUrl, Arc<WebPkiServerVerifier>)> = {
            let cache = lock(cache);
            urls.iter()
                .flat_map(|url| {
                    cache
                        .peek(url.as_str(), leaf.secs)
                        .into_iter()
                        .map(move |v| (*url, v))
                })
                .collect()
        };
        for (url, verifier) in cached {
            if used.iter().any(|u| Arc::ptr_eq(u, &verifier)) {
                continue;
            }
            if let Verdict::Revoked = verify(&verifier, leaf) {
                return Err(revoked(url));
            }
        }
        Ok(())
    }

    /// One distribution point: the cache, then a fetch where it says so
    /// (ADR-017, items 4 and 8). `Revoked` is an error at once.
    fn check_url(&self, url: &CrlUrl, leaf: &Leaf<'_>) -> crate::Result<Outcome> {
        let Mode::On { cache, .. } = &self.mode else {
            return Ok(Outcome::Failed(RevocationFailure::new(
                Some(url),
                RevocationFailureKind::NotSettled,
                "no revocation check",
            )));
        };
        let lookup = lock(cache).lookup(url.as_str(), leaf.secs);
        match lookup {
            Lookup::Fresh(verifiers) => decide(url, verifiers, leaf, false),
            Lookup::Stale(verifiers) => decide(url, verifiers, leaf, true),
            Lookup::Refresh(verifiers, cached_this_update) => {
                // A refresh succeeds only with a list that passes every
                // check, settles the leaf and is not older than the cached
                // one; anything else leaves the decision to the cached list.
                if let Ok(fetched) = self.fetch(url, leaf)
                    && fetched.this_update >= cached_this_update
                {
                    match verify(&fetched.verifier, leaf) {
                        Verdict::Good => {
                            let used = vec![Arc::clone(&fetched.verifier)];
                            self.store(url, fetched, leaf.secs);
                            return Ok(Outcome::Settled(
                                RevocationStatus::Checked {
                                    url: url.as_str().to_owned(),
                                },
                                used,
                            ));
                        }
                        Verdict::Revoked => {
                            self.store(url, fetched, leaf.secs);
                            return Err(revoked(url));
                        }
                        Verdict::Expired(_) | Verdict::NotSettled(_) => {}
                    }
                }
                decide(url, verifiers, leaf, true)
            }
            Lookup::Missing => {
                let fetched = match self.fetch(url, leaf) {
                    Ok(fetched) => fetched,
                    Err(failure) => return Ok(Outcome::Failed(failure)),
                };
                match verify(&fetched.verifier, leaf) {
                    Verdict::Good => {
                        let used = vec![Arc::clone(&fetched.verifier)];
                        self.store(url, fetched, leaf.secs);
                        Ok(Outcome::Settled(
                            RevocationStatus::Checked {
                                url: url.as_str().to_owned(),
                            },
                            used,
                        ))
                    }
                    Verdict::Revoked => {
                        self.store(url, fetched, leaf.secs);
                        Err(revoked(url))
                    }
                    Verdict::Expired(detail) => Ok(Outcome::Failed(RevocationFailure::new(
                        Some(url),
                        RevocationFailureKind::Expired,
                        detail,
                    ))),
                    Verdict::NotSettled(detail) => Ok(Outcome::Failed(RevocationFailure::new(
                        Some(url),
                        RevocationFailureKind::NotSettled,
                        detail,
                    ))),
                }
            }
        }
    }

    /// Fetches, size-checks, parses and date-checks the list at `url`.
    fn fetch(&self, url: &CrlUrl, leaf: &Leaf<'_>) -> Result<Fetched, RevocationFailure> {
        let Mode::On {
            roots,
            provider,
            source,
            ..
        } = &self.mode
        else {
            return Err(RevocationFailure::new(
                Some(url),
                RevocationFailureKind::NotSettled,
                "off",
            ));
        };
        let bytes = source
            .fetch(url, leaf.deadline)
            .map_err(|e| RevocationFailure::from_fetch(url, e))?;
        // Any source, not only the HTTP one, is held to the cap.
        if bytes.len() > MAX_CRL_BYTES {
            return Err(RevocationFailure::new(
                Some(url),
                RevocationFailureKind::TooLarge,
                format!("{} bytes", bytes.len()),
            ));
        }
        let der_len = bytes.len();
        let digest = crate::Sha256::digest(&bytes);
        // Read here because `build()` takes the bytes, and looked at only
        // once `build()` has accepted them: the reader's result counts
        // only for bytes webpki parsed (ADR-017, item 9).
        let validity = der::crl_validity(&bytes);
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::clone(roots), Arc::clone(provider))
                .with_crls([CertificateRevocationListDer::from(bytes)])
                .only_check_end_entity_revocation()
                .enforce_revocation_expiration()
                .build()
                .map_err(|e| {
                    RevocationFailure::new(
                        Some(url),
                        RevocationFailureKind::Malformed,
                        e.to_string(),
                    )
                })?;
        let (this_update, next_update) = validity.map_err(|e| {
            RevocationFailure::new(Some(url), RevocationFailureKind::Malformed, e.to_string())
        })?;
        if let Some((kind, detail)) = validity_failure(this_update, next_update, leaf.secs) {
            return Err(RevocationFailure::new(Some(url), kind, detail));
        }
        Ok(Fetched {
            verifier,
            digest,
            this_update,
            next_update,
            der_len,
        })
    }

    /// Caches a list that settled the leaf.
    fn store(&self, url: &CrlUrl, fetched: Fetched, now: u64) {
        if let Mode::On { cache, .. } = &self.mode {
            let entry = Entry::new(
                fetched.verifier,
                fetched.digest,
                fetched.this_update,
                fetched.next_update,
                fetched.der_len,
                now,
            );
            lock(cache).insert(url.as_str(), entry, now);
        }
    }
}

/// Reversed dates are `Malformed`; a list at or past its `nextUpdate` is
/// `Expired`.
fn validity_failure(
    this_update: u64,
    next_update: u64,
    now: u64,
) -> Option<(RevocationFailureKind, &'static str)> {
    if next_update < this_update {
        return Some((
            RevocationFailureKind::Malformed,
            "nextUpdate is before thisUpdate",
        ));
    }
    if next_update <= now {
        return Some((
            RevocationFailureKind::Expired,
            "the list is at or past its nextUpdate",
        ));
    }
    None
}

/// The answer of a URL's cached lists; `stale` when they are past their
/// maximum age. Any list that revokes the leaf wins; otherwise the leaf
/// passes when at least one list settles it.
fn decide(
    url: &CrlUrl,
    verifiers: Vec<Arc<WebPkiServerVerifier>>,
    leaf: &Leaf<'_>,
    stale: bool,
) -> crate::Result<Outcome> {
    let mut good = Vec::new();
    let mut failure = None;
    for verifier in verifiers {
        match verify(&verifier, leaf) {
            Verdict::Revoked => return Err(revoked(url)),
            Verdict::Good => good.push(verifier),
            Verdict::Expired(detail) => {
                failure.get_or_insert((RevocationFailureKind::Expired, detail));
            }
            Verdict::NotSettled(detail) => {
                failure.get_or_insert((RevocationFailureKind::NotSettled, detail));
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

/// webpki's verification of the chain with one list: leaf only, unknown
/// status and an expired list are errors.
fn verify(verifier: &WebPkiServerVerifier, leaf: &Leaf<'_>) -> Verdict {
    match verifier.verify_server_cert(leaf.cert, leaf.intermediates, leaf.name, &[], leaf.now) {
        Ok(_) => Verdict::Good,
        Err(rustls::Error::InvalidCertificate(CertificateError::Revoked)) => Verdict::Revoked,
        Err(
            e @ rustls::Error::InvalidCertificate(
                CertificateError::ExpiredRevocationList
                | CertificateError::ExpiredRevocationListContext { .. },
            ),
        ) => Verdict::Expired(e.to_string()),
        Err(e) => Verdict::NotSettled(e.to_string()),
    }
}

pub(crate) fn revoked(url: &CrlUrl) -> Error {
    Error::Revoked {
        url: url.as_str().to_owned(),
    }
}

/// A cache that a poisoned lock clears.
trait Clear {
    fn clear(&mut self);
}

impl<V: Clone> Clear for CrlCache<V> {
    fn clear(&mut self) {
        CrlCache::clear(self);
    }
}

impl Clear for OcspCache {
    fn clear(&mut self) {
        OcspCache::clear(self);
    }
}

/// A cache's lock. A poisoned one is recovered and the cache cleared:
/// the cache only saves fetches.
fn lock<T: Clear>(cache: &Mutex<T>) -> MutexGuard<'_, T> {
    match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            guard.clear();
            cache.clear_poison();
            guard
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::mpsc;
    use std::sync::{Barrier, OnceLock};
    use std::thread;

    use rustls::pki_types::pem::PemObject;

    const CA: &[u8] = include_bytes!("../../tests/data/crl-ca.pem");
    const GOOD: &[u8] = include_bytes!("../../tests/data/crl-good.pem");
    const REVOKED: &[u8] = include_bytes!("../../tests/data/crl-revoked.pem");
    const TWO_DP: &[u8] = include_bytes!("../../tests/data/crl-two-dp.pem");
    const FRESH: &[u8] = include_bytes!("../../tests/data/crl-ca-fresh.crl");
    const EMPTY: &[u8] = include_bytes!("../../tests/data/crl-ca-empty.crl");
    const WEEK1: &[u8] = include_bytes!("../../tests/data/crl-ca-week1.crl");
    const DAY2: &[u8] = include_bytes!("../../tests/data/crl-ca-day2.crl");
    const IDP: &[u8] = include_bytes!("../../tests/data/crl-ca-idp.crl");
    const OTHER_SHARD: &[u8] = include_bytes!("../../tests/data/crl-ca-other-shard.crl");
    const REVERSED: &[u8] = include_bytes!("../../tests/data/crl-ca-reversed.crl");
    const FORGED: &[u8] = include_bytes!("../../tests/data/crl-ca-forged.crl");

    const T0: u64 = 1_767_225_600;
    const WEEK1_END: u64 = 1_767_830_400;
    const DAY2_END: u64 = 1_767_916_800;
    const URL: &str = "http://crl.boneli.test/ca.crl";

    /// Bounds every wait on another thread, so that a bug fails a test
    /// instead of hanging it.
    const GUARD: Duration = Duration::from_secs(10);

    fn roots() -> Arc<RootCertStore> {
        static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
        Arc::clone(ROOTS.get_or_init(|| {
            let mut store = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(CA) {
                store.add(cert.expect("CA PEM")).expect("CA");
            }
            Arc::new(store)
        }))
    }

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// A verifier built with `crl`, as the check builds it.
    pub(crate) fn verifier_for(crl: &[u8]) -> Arc<WebPkiServerVerifier> {
        WebPkiServerVerifier::builder_with_provider(roots(), provider())
            .with_crls([CertificateRevocationListDer::from(crl.to_vec())])
            .only_check_end_entity_revocation()
            .enforce_revocation_expiration()
            .build()
            .expect("CRL")
    }

    fn chain(pem: &[u8]) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("PEM")
    }

    fn name() -> ServerName<'static> {
        ServerName::try_from("localhost").expect("name")
    }

    fn time(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    type Reply = Result<Vec<u8>, CrlFetchError>;

    /// A source that answers from a script and counts its calls.
    #[derive(Default)]
    struct Script {
        replies: Mutex<VecDeque<Reply>>,
        asked: Mutex<Vec<String>>,
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

    /// A source that runs a closure.
    struct FnSource<F>(F);

    impl<F: Fn(&CrlUrl) -> Reply + Send + Sync> CrlSource for FnSource<F> {
        fn fetch(&self, url: &CrlUrl, _deadline: Instant) -> Reply {
            (self.0)(url)
        }
    }

    fn ok(crl: &[u8]) -> Reply {
        Ok(crl.to_vec())
    }

    fn unreachable() -> Reply {
        Err(CrlFetchError::Unreachable("refused".into()))
    }

    /// An OCSP source that must never be asked: no CRL fixture names a
    /// responder.
    struct NoOcsp;

    impl OcspSource for NoOcsp {
        fn fetch(&self, url: &CrlUrl, _request: &[u8], _deadline: Instant) -> Reply {
            panic!("OCSP fetch of {url}")
        }
    }

    fn revocation(source: Arc<dyn CrlSource>) -> Revocation {
        Revocation::on(roots(), provider(), source, Arc::new(NoOcsp))
    }

    fn check(r: &Revocation, leaf: &[u8], secs: u64) -> crate::Result<RevocationStatus> {
        r.check_at(&chain(leaf), &name(), None, time(secs))
    }

    fn checked() -> RevocationStatus {
        RevocationStatus::Checked { url: URL.into() }
    }

    fn stale() -> RevocationStatus {
        RevocationStatus::CheckedStale { url: URL.into() }
    }

    fn kinds(result: crate::Result<RevocationStatus>) -> Vec<RevocationFailureKind> {
        match result {
            Err(Error::RevocationUnknown(failures)) => failures.iter().map(|f| f.kind).collect(),
            other => panic!("expected RevocationUnknown, got {other:?}"),
        }
    }

    fn assert_revoked(result: crate::Result<RevocationStatus>) {
        match result {
            Err(Error::Revoked { url }) => assert_eq!(url, URL),
            other => panic!("expected Revoked, got {other:?}"),
        }
    }

    fn entry(r: &Revocation) -> Option<Entry<Arc<WebPkiServerVerifier>>> {
        let Mode::On { cache, .. } = &r.mode else {
            panic!("off")
        };
        lock(cache).get(URL).cloned()
    }

    #[test]
    fn check_deadline_is_62_seconds() {
        assert_eq!(
            CRL_CHECK_DEADLINE,
            CRL_SETUP_TIME + Duration::from_secs(MAX_CRL_BYTES as u64 / CRL_MIN_RATE)
        );
        assert_eq!(CRL_CHECK_DEADLINE, Duration::from_secs(62));
    }

    #[test]
    fn ca_check_deadline_is_38_seconds() {
        assert_eq!(
            CA_CRL_CHECK_DEADLINE,
            CRL_SETUP_TIME
                + Duration::from_secs(
                    (MAX_CA_CRL_FETCHES * MAX_CA_CRL_BYTES) as u64 / CRL_MIN_RATE
                )
        );
        assert_eq!(CA_CRL_CHECK_DEADLINE, Duration::from_secs(38));
        assert_eq!(
            (MAX_CA_CRL_BYTES, MAX_CA_CRL_FETCHES, CA_CRL_CACHE_MAX_BYTES),
            (1_048_576, 8, 16_777_216)
        );
    }

    #[test]
    fn cache_refetches_at_next_update_and_not_before() {
        let script = Script::new(vec![ok(WEEK1), ok(DAY2)]);
        let r = revocation(script.clone());
        assert_eq!(check(&r, GOOD, 1_767_787_200).expect("check"), checked());
        assert_eq!(script.calls(), 1);
        assert_eq!(check(&r, GOOD, WEEK1_END - 1).expect("check"), checked());
        assert_eq!(script.calls(), 1);
        assert_eq!(check(&r, GOOD, WEEK1_END).expect("check"), checked());
        assert_eq!(script.calls(), 2);
        assert_eq!(check(&r, GOOD, WEEK1_END + 1).expect("check"), checked());
        assert_eq!(script.calls(), 2);
    }

    #[test]
    fn expired_list_is_refetched_and_not_cached() {
        let script = Script::new(vec![ok(WEEK1), ok(DAY2), ok(DAY2), ok(DAY2)]);
        let r = revocation(script.clone());
        check(&r, GOOD, 1_767_787_200).expect("week1");
        check(&r, GOOD, WEEK1_END).expect("day2");
        assert_eq!(script.calls(), 2);
        // Day2's `nextUpdate`, and exactly its maximum age.
        assert_eq!(
            kinds(check(&r, GOOD, DAY2_END)),
            [RevocationFailureKind::Expired]
        );
        assert_eq!(script.calls(), 3);
        assert!(entry(&r).is_none(), "not cached");
        assert_eq!(
            kinds(check(&r, GOOD, DAY2_END)),
            [RevocationFailureKind::Expired]
        );
        assert_eq!(script.calls(), 4);
    }

    #[test]
    fn fresh_within_max_age_is_not_fetched() {
        let script = Script::new(vec![ok(WEEK1)]);
        let r = revocation(script.clone());
        assert_eq!(check(&r, GOOD, T0).expect("check"), checked());
        assert_eq!(check(&r, GOOD, T0 + 86_399).expect("check"), checked());
        assert_eq!(script.calls(), 1);
    }

    #[test]
    fn refresh_after_max_age_sees_new_revocation() {
        let script = Script::new(vec![ok(WEEK1), ok(DAY2)]);
        let r = revocation(script.clone());
        assert_eq!(check(&r, REVOKED, T0).expect("check"), checked());
        assert_eq!(check(&r, REVOKED, T0 + 86_399).expect("check"), checked());
        assert_eq!(script.calls(), 1);
        assert_revoked(check(&r, REVOKED, T0 + 86_400));
        assert_eq!(script.calls(), 2);
    }

    #[test]
    fn refresh_restarts_max_age() {
        let script = Script::new(vec![ok(WEEK1), ok(DAY2), ok(DAY2)]);
        let r = revocation(script.clone());
        check(&r, GOOD, T0).expect("check");
        assert_eq!(check(&r, GOOD, T0 + 86_400).expect("check"), checked());
        assert_eq!(script.calls(), 2);
        assert_eq!(check(&r, GOOD, T0 + 172_799).expect("check"), checked());
        assert_eq!(script.calls(), 2);
        assert_eq!(check(&r, GOOD, T0 + 172_800).expect("check"), checked());
        assert_eq!(script.calls(), 3);
        assert_eq!(check(&r, GOOD, T0 + 172_801).expect("check"), checked());
        assert_eq!(script.calls(), 3);
    }

    #[test]
    fn equal_list_on_refresh_confirms_entry() {
        let script = Script::new(vec![ok(DAY2), ok(DAY2)]);
        let r = revocation(script.clone());
        check(&r, GOOD, T0 + 86_400).expect("check");
        let before = entry(&r).expect("entry");
        assert_eq!(check(&r, GOOD, T0 + 172_800).expect("check"), checked());
        assert_eq!(script.calls(), 2);
        let after = entry(&r).expect("entry");
        assert_eq!(after.lists.len(), 1);
        assert!(Arc::ptr_eq(&before.lists[0].value, &after.lists[0].value));
        assert_eq!((after.confirmed_at, after.claimed_at), (T0 + 172_800, None));
    }

    #[test]
    fn refresh_failure_before_next_update_keeps_cached_list() {
        let script = Script::new(vec![ok(WEEK1), unreachable(), unreachable()]);
        let r = revocation(script.clone());
        check(&r, GOOD, T0).expect("check");
        assert_eq!(check(&r, GOOD, T0 + 86_400).expect("check"), stale());
        assert_eq!(script.calls(), 2);
        assert_eq!(check(&r, GOOD, T0 + 86_401).expect("check"), stale());
        assert_eq!(check(&r, GOOD, T0 + 89_999).expect("check"), stale());
        assert_eq!(script.calls(), 2);
        assert_eq!(check(&r, GOOD, T0 + 90_000).expect("check"), stale());
        assert_eq!(script.calls(), 3);
    }

    #[test]
    fn every_refresh_failure_keeps_cached_list() {
        let failures: Vec<Reply> = vec![
            unreachable(),
            Err(CrlFetchError::TimedOut),
            Err(CrlFetchError::Status(503)),
            Ok(vec![0; MAX_CRL_BYTES + 1]),
            Ok(WEEK1[..WEEK1.len() - 1].to_vec()),
            ok(REVERSED),
            ok(OTHER_SHARD),
            ok(FORGED),
        ];
        for (i, failure) in failures.into_iter().enumerate() {
            let script = Script::new(vec![ok(WEEK1), failure]);
            let r = revocation(script.clone());
            check(&r, GOOD, T0).expect("check");
            let before = entry(&r).expect("entry");
            assert_eq!(check(&r, GOOD, T0 + 86_400).expect("check"), stale(), "{i}");
            assert_eq!(script.calls(), 2, "{i}");
            let after = entry(&r).expect("entry");
            assert_eq!(after.lists.len(), 1, "{i}");
            assert!(
                Arc::ptr_eq(&before.lists[0].value, &after.lists[0].value),
                "{i}"
            );
            assert_eq!((after.this_update, after.confirmed_at), (T0, T0), "{i}");
        }
    }

    #[test]
    fn refresh_failure_past_next_update_fails_closed() {
        let script = Script::new(vec![ok(WEEK1), unreachable(), unreachable(), unreachable()]);
        let r = revocation(script.clone());
        check(&r, GOOD, T0).expect("check");
        assert_eq!(check(&r, GOOD, WEEK1_END - 1).expect("check"), stale());
        assert_eq!(script.calls(), 2);
        // Inside the retry wait, but the list has expired: fetched anyway.
        assert_eq!(
            kinds(check(&r, GOOD, WEEK1_END)),
            [RevocationFailureKind::Unreachable]
        );
        assert_eq!(script.calls(), 3);
        assert_eq!(
            kinds(check(&r, GOOD, WEEK1_END)),
            [RevocationFailureKind::Unreachable]
        );
        assert_eq!(script.calls(), 4);
    }

    #[test]
    fn next_update_wins_over_stale_at_the_same_second() {
        let script = Script::new(vec![ok(DAY2), unreachable()]);
        let r = revocation(script.clone());
        check(&r, GOOD, WEEK1_END).expect("check");
        assert_eq!(
            kinds(check(&r, GOOD, DAY2_END)),
            [RevocationFailureKind::Unreachable]
        );
    }

    #[test]
    fn older_list_on_refresh_keeps_newer() {
        let script = Script::new(vec![ok(DAY2), ok(WEEK1), unreachable()]);
        let r = revocation(script.clone());
        check(&r, GOOD, T0 + 86_400).expect("check");
        assert_eq!(check(&r, GOOD, T0 + 172_800).expect("check"), stale());
        assert_eq!(script.calls(), 2);
        let kept = entry(&r).expect("entry");
        assert_eq!(kept.this_update, T0 + 86_400);
        assert_eq!(kept.claimed_at, Some(T0 + 172_800));
        assert_eq!(check(&r, GOOD, T0 + 176_399).expect("check"), stale());
        assert_eq!(script.calls(), 2);
        assert_eq!(check(&r, GOOD, T0 + 176_400).expect("check"), stale());
        assert_eq!(script.calls(), 3);
    }

    #[test]
    fn replayed_older_list_cannot_unrevoke() {
        let script = Script::new(vec![ok(DAY2), ok(WEEK1)]);
        let r = revocation(script.clone());
        assert_revoked(check(&r, REVOKED, T0 + 86_400));
        assert_revoked(check(&r, REVOKED, T0 + 172_800));
        assert_eq!(script.calls(), 2);
    }

    #[test]
    fn stale_refresh_is_claimed_by_one_connection() {
        let (entered_tx, entered) = mpsc::channel::<()>();
        let (release, release_rx) = mpsc::channel::<()>();
        let entered_tx = Mutex::new(entered_tx);
        let release_rx = Mutex::new(release_rx);
        let calls = Arc::new(Mutex::new(0usize));
        let counter = Arc::clone(&calls);
        let source = FnSource(move |_: &CrlUrl| {
            let n = {
                let mut calls = counter.lock().expect("calls");
                *calls += 1;
                *calls
            };
            if n == 1 {
                return ok(WEEK1);
            }
            let _ = entered_tx.lock().expect("tx").send(());
            // Bounded, so that a wrong second caller fails the test
            // instead of hanging it.
            let _ = release_rx.lock().expect("rx").recv_timeout(GUARD);
            unreachable()
        });
        let r = Arc::new(revocation(Arc::new(source)));
        check(&r, GOOD, T0).expect("check");
        let a = {
            let r = Arc::clone(&r);
            thread::spawn(move || check(&r, GOOD, T0 + 86_400))
        };
        entered.recv_timeout(GUARD).expect("A is refreshing");
        assert_eq!(check(&r, GOOD, T0 + 86_400).expect("B"), stale());
        assert_eq!(*calls.lock().expect("calls"), 2, "B did not fetch");
        release.send(()).expect("release");
        assert_eq!(a.join().expect("A").expect("A"), stale());
        assert_eq!(*calls.lock().expect("calls"), 2);
    }

    #[test]
    fn unsettling_list_is_not_cached() {
        let script = Script::new(vec![ok(OTHER_SHARD), ok(OTHER_SHARD)]);
        let r = revocation(script.clone());
        assert_eq!(
            kinds(check(&r, GOOD, T0)),
            [RevocationFailureKind::NotSettled]
        );
        assert!(entry(&r).is_none());
        assert_eq!(
            kinds(check(&r, GOOD, T0)),
            [RevocationFailureKind::NotSettled]
        );
        assert_eq!(script.calls(), 2);
    }

    #[test]
    fn concurrent_cold_fetches_leave_one_entry() {
        let barrier = Barrier::new(2);
        let calls = Mutex::new(0usize);
        let source = FnSource(move |_: &CrlUrl| {
            let n = {
                let mut calls = calls.lock().expect("calls");
                *calls += 1;
                *calls
            };
            barrier.wait();
            if n == 1 { ok(WEEK1) } else { ok(DAY2) }
        });
        let r = Arc::new(revocation(Arc::new(source)));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let r = Arc::clone(&r);
                thread::spawn(move || check(&r, GOOD, T0 + 86_401))
            })
            .collect();
        for t in threads {
            assert_eq!(t.join().expect("thread").expect("check"), checked());
        }
        assert_eq!(entry(&r).expect("entry").this_update, T0 + 86_400);
        let Mode::On { cache, .. } = &r.mode else {
            panic!("off")
        };
        assert_eq!(lock(cache).len(), 1);
    }

    #[test]
    fn next_update_agrees_with_webpki() {
        for crl in [FRESH, EMPTY, WEEK1, DAY2, IDP, REVERSED] {
            let (_, next) = der::crl_validity(crl).expect("validity");
            let verifier = verifier_for(crl);
            let cert = &chain(GOOD)[0];
            verifier
                .verify_server_cert(cert, &[], &name(), &[], time(next - 1))
                .expect("before nextUpdate");
            let err = verifier
                .verify_server_cert(cert, &[], &name(), &[], time(next))
                .expect_err("at nextUpdate");
            match err {
                rustls::Error::InvalidCertificate(
                    CertificateError::ExpiredRevocationListContext { next_update, .. },
                ) => assert_eq!(next_update, time(next)),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn zero_length_validity_is_expired() {
        assert_eq!(
            validity_failure(T0, T0, T0).map(|(kind, _)| kind),
            Some(RevocationFailureKind::Expired)
        );
        assert_eq!(validity_failure(T0, T0 + 1, T0), None);
    }

    #[test]
    fn reversed_validity_is_malformed() {
        assert_eq!(
            validity_failure(T0 + 1, T0, T0 - 5).map(|(kind, _)| kind),
            Some(RevocationFailureKind::Malformed)
        );
        let script = Script::new(vec![ok(REVERSED)]);
        let r = revocation(script);
        assert_eq!(
            kinds(check(&r, GOOD, T0)),
            [RevocationFailureKind::Malformed]
        );
    }

    #[test]
    fn oversized_source_bytes_refused() {
        let script = Script::new(vec![
            Ok(vec![0; MAX_CRL_BYTES + 1]),
            Ok(vec![0; MAX_CRL_BYTES]),
        ]);
        let r = revocation(script);
        assert_eq!(
            kinds(check(&r, GOOD, T0)),
            [RevocationFailureKind::TooLarge]
        );
        // At the cap the size check passes and webpki refuses the bytes.
        assert_eq!(
            kinds(check(&r, GOOD, T0)),
            [RevocationFailureKind::Malformed]
        );
    }

    #[test]
    fn missing_peer_chain_fails_closed() {
        let script = Script::new(vec![]);
        let r = revocation(script.clone());
        let result = r.check_at(&[], &name(), None, time(T0));
        assert_eq!(kinds(result), [RevocationFailureKind::NotSettled]);
        assert_eq!(script.calls(), 0);
    }

    #[test]
    fn poisoned_cache_recovers() {
        let script = Script::new(vec![ok(EMPTY), ok(EMPTY)]);
        let r = Arc::new(revocation(script.clone()));
        check(&r, GOOD, T0).expect("check");
        {
            let r = Arc::clone(&r);
            let _ = thread::spawn(move || {
                let Mode::On { cache, .. } = &r.mode else {
                    return;
                };
                let _guard = cache.lock();
                panic!("poison the cache");
            })
            .join();
        }
        let Mode::On { cache, .. } = &r.mode else {
            panic!("off")
        };
        assert!(cache.is_poisoned());
        assert_eq!(check(&r, GOOD, T0).expect("check"), checked());
        assert_eq!(script.calls(), 2, "the cache was cleared");
        assert!(!cache.is_poisoned());
        assert_eq!(check(&r, GOOD, T0).expect("check"), checked());
        assert_eq!(script.calls(), 2);
    }

    #[test]
    fn no_lock_across_fetch() {
        let (entered_tx, entered) = mpsc::channel::<()>();
        let (release, release_rx) = mpsc::channel::<()>();
        let entered_tx = Mutex::new(entered_tx);
        let release_rx = Mutex::new(release_rx);
        let source = FnSource(move |url: &CrlUrl| {
            if url.host() == "crl1.boneli.test" {
                let _ = entered_tx.lock().expect("tx").send(());
                let _ = release_rx.lock().expect("rx").recv_timeout(GUARD);
            }
            ok(EMPTY)
        });
        let r = Arc::new(revocation(Arc::new(source)));
        let a = {
            let r = Arc::clone(&r);
            thread::spawn(move || check(&r, TWO_DP, T0))
        };
        entered.recv_timeout(GUARD).expect("A is fetching");
        assert_eq!(check(&r, GOOD, T0).expect("B"), checked());
        release.send(()).expect("release");
        assert_eq!(
            a.join().expect("A").expect("A"),
            RevocationStatus::Checked {
                url: "http://crl1.boneli.test/ca.crl".into()
            }
        );
    }

    #[test]
    fn off_checks_nothing() {
        let r = Revocation::off();
        assert_eq!(
            check(&r, GOOD, T0).expect("off"),
            RevocationStatus::NoRevocationSource
        );
    }

    #[test]
    fn bad_and_skipped_uris_count_as_specified() {
        // crl-dps.pem: http, ldap (skipped), http; every fetch fails.
        let script = Script::new(vec![]);
        let r = revocation(script.clone());
        let dps = include_bytes!("../../tests/data/crl-dps.pem");
        assert_eq!(
            kinds(check(&r, dps, T0)),
            [
                RevocationFailureKind::Unreachable,
                RevocationFailureKind::Unreachable
            ]
        );
        assert_eq!(
            script.asked(),
            [
                "http://crl.boneli.test/a.crl",
                "http://crl.boneli.test/e.crl"
            ]
        );
    }

    // A CA can sign two different lists with the same `thisUpdate`
    // (`crl-ca-empty.crl` and `crl-ca-fresh.crl` share their dates; the
    // fresh one lists 0x01, 0x20, 0x40 and 0x80). A revocation seen in
    // either must stick (ADR-017, item 8).

    #[test]
    fn equal_this_update_revoking_list_replaces_cached() {
        let script = Script::new(vec![ok(EMPTY), ok(FRESH)]);
        let r = revocation(script.clone());
        assert_eq!(check(&r, REVOKED, T0).expect("check"), checked());
        assert_revoked(check(&r, REVOKED, T0 + 86_400));
        assert_revoked(check(&r, REVOKED, T0 + 86_401));
        assert_revoked(check(&r, REVOKED, T0 + 172_000));
        assert_eq!(script.calls(), 2, "the revoking list is cached");
    }

    #[test]
    fn equal_this_update_list_cannot_unrevoke_cached() {
        let script = Script::new(vec![ok(FRESH), ok(EMPTY)]);
        let r = revocation(script.clone());
        assert_revoked(check(&r, REVOKED, T0));
        // The refresh returns a list with the same `thisUpdate` that does
        // not list the leaf: the cached revocation still decides.
        assert_revoked(check(&r, REVOKED, T0 + 86_400));
        assert_revoked(check(&r, REVOKED, T0 + 86_401));
        assert_eq!(script.calls(), 2);
    }

    const CRL1: &str = "http://crl1.boneli.test/ca.crl";
    const CRL2: &str = "http://crl2.boneli.test/ca.crl";

    fn assert_revoked_by(result: crate::Result<RevocationStatus>, url: &str) {
        match result {
            Err(Error::Revoked { url: by }) => assert_eq!(by, url),
            other => panic!("expected Revoked by {url}, got {other:?}"),
        }
    }

    #[test]
    fn mirror_revocation_is_not_undone_by_first_url() {
        // crl-two-dp.pem (0x40), points crl1 then crl2. The first check
        // finds crl1 unreachable and crl2's list revoking the leaf; the
        // next gets an older list without it from crl1.
        let script = Script::new(vec![unreachable(), ok(FRESH), ok(WEEK1)]);
        let r = revocation(script.clone());
        assert_revoked_by(check(&r, TWO_DP, T0 + 3_600), CRL2);
        assert_revoked_by(check(&r, TWO_DP, T0 + 7_200), CRL2);
        assert_eq!(script.asked(), [CRL1, CRL2, CRL1]);
    }

    #[test]
    fn stale_mirror_revocation_still_wins() {
        // The revocation sits in crl2's list past its maximum age, while
        // crl1 serves a list without it: the cached revocation decides.
        let script = Script::new(vec![unreachable(), ok(FRESH), ok(WEEK1), ok(WEEK1)]);
        let r = revocation(script.clone());
        assert_revoked_by(check(&r, TWO_DP, T0 + 3_600), CRL2);
        assert_revoked_by(check(&r, TWO_DP, T0 + 3_600 + 86_400), CRL2);
        assert_revoked_by(check(&r, TWO_DP, T0 + 3_600 + 86_401), CRL2);
    }

    // The cache is shared by every leaf that names a URL. At a tie, a list
    // that revokes the leaf being checked must not push out a list that
    // revokes another leaf: `crl-ca-fresh.crl` lists 0x01, 0x20, 0x40 and
    // 0x80, `crl-ca-idp.crl` has the same dates and lists only 0x80.

    const REVOKED_FIRST: &[u8] = include_bytes!("../../tests/data/crl-revoked-first.pem");

    #[test]
    fn tie_for_one_leaf_keeps_revocations_of_another() {
        let script = Script::new(vec![ok(FRESH), ok(IDP)]);
        let r = revocation(script.clone());
        assert_revoked(check(&r, REVOKED_FIRST, T0));
        // 0x80 triggers the refresh, which returns the shorter list.
        assert_revoked(check(&r, REVOKED, T0 + 86_400));
        assert_revoked(check(&r, REVOKED_FIRST, T0 + 86_401));
        assert_revoked(check(&r, REVOKED, T0 + 86_401));
        assert_eq!(script.calls(), 2);
        assert_eq!(entry(&r).expect("entry").lists.len(), 2);
    }

    #[test]
    fn tie_for_one_leaf_keeps_revocations_of_another_reversed() {
        let script = Script::new(vec![ok(IDP), ok(FRESH)]);
        let r = revocation(script.clone());
        assert_revoked(check(&r, REVOKED, T0));
        assert_revoked(check(&r, REVOKED_FIRST, T0 + 86_400));
        assert_revoked(check(&r, REVOKED, T0 + 86_401));
        assert_revoked(check(&r, REVOKED_FIRST, T0 + 86_401));
        // The good leaf passes both lists.
        assert_eq!(check(&r, GOOD, T0 + 86_401).expect("check"), checked());
        assert_eq!(script.calls(), 2);
    }
}
