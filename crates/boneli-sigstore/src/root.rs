//! `trusted_root.json`, the operator's statement of which Sigstore
//! instance to trust (ADR-029, S2): the Rekor logs whose promises count,
//! the Fulcio certificate authorities that issue signing certificates,
//! and the CT logs whose SCTs count, each with a validity window.
//!
//! It is read strictly, because a wrong reading would trust the wrong
//! key: the media type byte for byte; every log ID recomputed from its key
//! and compared with the file's `logId.keyId`; `keyDetails` naming the
//! key's own kind (the algorithm still follows from the key alone,
//! `boneli_https::PublicKey`); `hashAlgorithm` `SHA2_256`, the only hash
//! RFC 6962 and Rekor v1 use; no log ID twice across the Rekor and CT
//! logs; no window that ends before it starts. A field this crate does
//! not use is not read: `baseUrl`, `uri`, `subject`, and the whole of
//! `timestampAuthorities` (TSA time is out of scope, ADR-029 S2).
//!
//! A CT log whose `keyId` is not the SHA-256 of its key refuses the file
//! (RFC 6962 defines the log ID so). A Rekor log whose `keyId` is not is
//! read and checked like the others, then left out: that is how a Rekor
//! v2 log names itself (by its signed-note key ID; `log2025-1` in the
//! public-good root, measured), and a v2 log issues no SET, so it can
//! vouch for nothing here (Rekor v2 is out of scope, S2). Entries are
//! looked up by the SHA-256 of the key either way, never by the file's
//! `keyId`.
//!
//! A key of a kind `PublicKey` does not support refuses the whole file,
//! as does every other defect: the operator keeps the file that worked
//! until the next one reads (fails closed).

use std::fmt;

use boneli_https::{CtLog, KeyKind, PublicKey};
use boneli_json::Value;

use crate::error::ConfigError;
use crate::{MAX_TRUSTED_ROOT_BYTES, json, time};

/// The one media type accepted, byte for byte.
pub const TRUSTED_ROOT_MEDIA_TYPE: &str =
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1";

/// A validity window in milliseconds since the Unix epoch, inclusive at
/// both ends; `end_ms` `None` has no end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    pub(crate) start_ms: u64,
    pub(crate) end_ms: Option<u64>,
}

impl Window {
    pub(crate) fn contains(&self, ms: u64) -> bool {
        self.start_ms <= ms && self.end_ms.is_none_or(|end| ms <= end)
    }
}

/// A Rekor log: its key and the window of integrated times it vouches
/// for.
#[derive(Clone, Debug)]
pub(crate) struct Tlog {
    pub(crate) key: PublicKey,
    pub(crate) window: Window,
}

/// A Fulcio certificate authority: its chain, the anchor last, and the
/// window of integrated times in which it issued.
#[derive(Clone, Debug)]
pub(crate) struct Authority {
    pub(crate) intermediates: Vec<Vec<u8>>,
    pub(crate) root: Vec<u8>,
    pub(crate) window: Window,
}

/// A parsed `trusted_root.json`.
///
/// `Debug` shows how many logs and authorities it holds.
#[derive(Clone)]
pub struct TrustedRoot {
    pub(crate) tlogs: Vec<Tlog>,
    pub(crate) authorities: Vec<Authority>,
    pub(crate) ctlogs: Vec<CtLog>,
}

impl fmt::Debug for TrustedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedRoot")
            .field("tlogs", &self.tlogs.len())
            .field("authorities", &self.authorities.len())
            .field("ctlogs", &self.ctlogs.len())
            .finish()
    }
}

impl TrustedRoot {
    /// Reads `trusted_root.json` of at most [`MAX_TRUSTED_ROOT_BYTES`]
    /// (module doc). `tlogs`, `certificateAuthorities` and `ctlogs` may be
    /// absent, as protobuf JSON omits empty lists; a keyless signature
    /// then finds no log or authority and is refused.
    pub fn from_json(bytes: &[u8]) -> Result<TrustedRoot, ConfigError> {
        if bytes.len() > MAX_TRUSTED_ROOT_BYTES {
            return Err(ConfigError::RootTooLarge);
        }
        let root = json::parse(bytes, MAX_TRUSTED_ROOT_BYTES).ok_or(ConfigError::RootMalformed)?;
        if root.as_object().is_none() {
            return Err(ConfigError::RootMalformed);
        }
        if json::string(&root, "mediaType") != Some(TRUSTED_ROOT_MEDIA_TYPE) {
            return Err(ConfigError::RootMediaType);
        }
        // A Rekor v2 log names itself by its signed-note key ID, not by
        // the SHA-256 of its key (`log2025-1` in the public-good root), and
        // never issues a SET: it is read like the others and left out.
        let mut tlogs = Vec::new();
        for value in list(&root, "tlogs")? {
            let (key, window, v1) = log(value)?;
            if v1 {
                tlogs.push(Tlog { key, window });
            }
        }
        let ctlogs = list(&root, "ctlogs")?
            .iter()
            .map(|v| {
                let (key, window, v1) = log(v)?;
                if !v1 {
                    return Err(ConfigError::RootLogId);
                }
                Ok(CtLog {
                    key,
                    valid_from_ms: window.start_ms,
                    valid_to_ms: window.end_ms,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authorities = list(&root, "certificateAuthorities")?
            .iter()
            .map(authority)
            .collect::<Result<Vec<_>, _>>()?;
        let mut ids: Vec<[u8; 32]> = tlogs
            .iter()
            .map(|l| l.key.key_id())
            .chain(ctlogs.iter().map(|l| l.key.key_id()))
            .collect();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ConfigError::RootDuplicateLogId);
        }
        Ok(TrustedRoot {
            tlogs,
            authorities,
            ctlogs,
        })
    }

    /// How many Rekor v1 logs the root holds (v2 logs are left out).
    pub fn tlog_count(&self) -> usize {
        self.tlogs.len()
    }

    /// How many Fulcio certificate authorities the root holds.
    pub fn authority_count(&self) -> usize {
        self.authorities.len()
    }

    /// How many CT logs the root holds.
    pub fn ctlog_count(&self) -> usize {
        self.ctlogs.len()
    }
}

/// The array member `key`, empty when absent.
fn list<'a>(root: &'a Value, key: &str) -> Result<&'a [Value], ConfigError> {
    match root.get(key) {
        None => Ok(&[]),
        Some(v) => v.as_array().ok_or(ConfigError::RootMalformed),
    }
}

/// A `TransparencyLogInstance`: the key, checked against `keyDetails`
/// and `hashAlgorithm`, its window, and whether `logId.keyId` is the
/// SHA-256 of the key (RFC 6962's log ID, which CT logs and Rekor v1 use).
/// A `keyId` that is not 32 bytes of base64 refuses the file.
fn log(value: &Value) -> Result<(PublicKey, Window, bool), ConfigError> {
    if json::string(value, "hashAlgorithm") != Some("SHA2_256") {
        return Err(ConfigError::RootHashAlgorithm);
    }
    let public = json::object(value, "publicKey").ok_or(ConfigError::RootMalformed)?;
    let der = json::base64(public, "rawBytes").ok_or(ConfigError::RootKey)?;
    let key = PublicKey::from_spki_der(&der).map_err(|_| ConfigError::RootKey)?;
    let details = json::string(public, "keyDetails").ok_or(ConfigError::RootKeyDetails)?;
    if !details_match(details, key.kind()) {
        return Err(ConfigError::RootKeyDetails);
    }
    let window = window(public)?;
    let log_id = json::object(value, "logId").ok_or(ConfigError::RootMalformed)?;
    let id: [u8; 32] = json::base64(log_id, "keyId")
        .and_then(|id| id.try_into().ok())
        .ok_or(ConfigError::RootLogId)?;
    let v1 = id == key.key_id();
    Ok((key, window, v1))
}

/// Whether `keyDetails` (protobuf's `PublicKeyDetails`) names `kind`.
fn details_match(details: &str, kind: KeyKind) -> bool {
    match kind {
        KeyKind::EcdsaP256 => details == "PKIX_ECDSA_P256_SHA_256",
        KeyKind::EcdsaP384 => details == "PKIX_ECDSA_P384_SHA_384",
        KeyKind::Ed25519 => details == "PKIX_ED25519",
        KeyKind::Rsa { bits } => {
            matches!(
                (details, bits),
                ("PKIX_RSA_PKCS1V15_2048_SHA256", 2_048)
                    | ("PKIX_RSA_PKCS1V15_3072_SHA256", 3_072)
                    | ("PKIX_RSA_PKCS1V15_4096_SHA256", 4_096)
            )
        }
    }
}

/// A `CertificateAuthority`: its chain and window.
fn authority(value: &Value) -> Result<Authority, ConfigError> {
    let chain = json::object(value, "certChain").ok_or(ConfigError::RootCertificate)?;
    let certificates = json::array(chain, "certificates").ok_or(ConfigError::RootCertificate)?;
    let mut ders = certificates
        .iter()
        .map(|c| json::base64(c, "rawBytes").filter(|d| !d.is_empty()))
        .collect::<Option<Vec<_>>>()
        .ok_or(ConfigError::RootCertificate)?;
    let root = ders.pop().ok_or(ConfigError::RootCertificate)?;
    Ok(Authority {
        intermediates: ders,
        root,
        window: window(value)?,
    })
}

/// The `validFor` member of `value`: `start` required, `end` optional.
fn window(value: &Value) -> Result<Window, ConfigError> {
    let valid = json::object(value, "validFor").ok_or(ConfigError::RootTime)?;
    let start = json::string(valid, "start")
        .and_then(time::parse)
        .ok_or(ConfigError::RootTime)?
        .start_ms();
    let end = match valid.get("end") {
        None => None,
        Some(v) => Some(
            v.as_str()
                .and_then(time::parse)
                .ok_or(ConfigError::RootTime)?
                .end_ms(),
        ),
    };
    if end.is_some_and(|end| end < start) {
        return Err(ConfigError::RootReversedWindow);
    }
    Ok(Window {
        start_ms: start,
        end_ms: end,
    })
}
