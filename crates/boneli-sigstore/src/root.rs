//! `trusted_root.json`, the operator's statement of which Sigstore
//! instance to trust (ADR-029, S2): the Rekor v1 logs whose promises
//! count, the Rekor v2 logs whose checkpoints count (ADR-038, D6),
//! the Fulcio certificate authorities that issue signing certificates,
//! the CT logs whose SCTs count, and the timestamp authorities whose RFC
//! 3161 tokens count as a time (ADR-038, D4), each with a validity window.
//!
//! It is read strictly, because a wrong reading would trust the wrong
//! key: the media type byte for byte; every log ID recomputed from its key
//! and compared with the file's `logId.keyId` (a Rekor v2 log's from each
//! checkpoint's origin); `keyDetails` naming the key's own kind (the
//! algorithm still follows from the key alone, `boneli_https::PublicKey`);
//! `hashAlgorithm` `SHA2_256`, the only hash RFC 6962 and both Rekor
//! versions use; no log ID twice across the Rekor and CT
//! logs; no window that ends before it starts. A field this crate does
//! not use is not read: `baseUrl`, `uri` and `subject`. A timestamp
//! authority's chain is read with its leaf first and its anchor last; one
//! of a single certificate can anchor no token and is skipped, and one
//! whose first certificate is a CA stays listed but no token verifies
//! through it (ADR-038, D4).
//!
//! A CT log whose `keyId` is not the SHA-256 of its key refuses the file
//! (RFC 6962 defines the log ID so). A Rekor log whose `keyId` is not is
//! read and checked like the others: that is how a Rekor v2 log names
//! itself, by its signed-note key ID, SHA-256(origin ‖ `\n` ‖ 0x01 ‖ raw
//! key) (`log2025-1` in the public-good root, measured). With an Ed25519
//! key it is kept as a v2 log under that key ID, which the checkpoint's
//! origin must hash to (ADR-038, D6), so `baseUrl` is never needed; with
//! another key it is left out, since a signed note of Rekor v2 is signed
//! with Ed25519 only. Its key still counts as a duplicate of any other
//! log with the same key. Rekor v1 entries are looked up by the SHA-256
//! of the key, never by the file's `keyId`; v2 entries by the key ID the
//! checkpoint then proves.
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

/// A Rekor v2 log (ADR-038, D6): its Ed25519 key, its signed-note key ID
/// as the root states it, and the window of verified times it vouches
/// for.
#[derive(Clone, Debug)]
pub(crate) struct NoteLog {
    pub(crate) key: PublicKey,
    pub(crate) key_id: [u8; 32],
    pub(crate) window: Window,
}

/// A timestamp authority (ADR-038, D4): its leaf, the certificates between
/// the leaf and the anchor, the anchor, and the window of genTimes it
/// vouches for.
#[derive(Clone, Debug)]
pub(crate) struct Tsa {
    pub(crate) leaf: Vec<u8>,
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
    pub(crate) note_logs: Vec<NoteLog>,
    pub(crate) authorities: Vec<Authority>,
    pub(crate) ctlogs: Vec<CtLog>,
    pub(crate) tsas: Vec<Tsa>,
    /// Every log the file lists: each `tlogs` entry, kept as Rekor v1 or
    /// v2 or left out, and each `ctlogs` entry (ADR-040, D1).
    pub(crate) listed_logs: usize,
}

impl fmt::Debug for TrustedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedRoot")
            .field("tlogs", &self.tlogs.len())
            .field("note_logs", &self.note_logs.len())
            .field("authorities", &self.authorities.len())
            .field("ctlogs", &self.ctlogs.len())
            .field("tsas", &self.tsas.len())
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
        // the SHA-256 of its key (`log2025-1` in the public-good root): it
        // is read like the others and kept apart when its key is Ed25519,
        // left out otherwise. Its key still counts for the duplicate check
        // below, so the same key twice is refused like any duplicate.
        let mut ids = Vec::new();
        let mut tlogs = Vec::new();
        let mut note_logs = Vec::new();
        for value in list(&root, "tlogs")? {
            let (key, window, id) = log(value)?;
            ids.push(key.key_id());
            if id == key.key_id() {
                tlogs.push(Tlog { key, window });
            } else if key.kind() == KeyKind::Ed25519 {
                note_logs.push(NoteLog {
                    key,
                    key_id: id,
                    window,
                });
            }
        }
        let ctlogs = list(&root, "ctlogs")?
            .iter()
            .map(|v| {
                let (key, window, id) = log(v)?;
                if id != key.key_id() {
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
        let tsas = list(&root, "timestampAuthorities")?
            .iter()
            .map(tsa)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        ids.extend(ctlogs.iter().map(|l| l.key.key_id()));
        // One ID per listed log, left-out Rekor logs included: the count
        // before the duplicate check below.
        let listed_logs = ids.len();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ConfigError::RootDuplicateLogId);
        }
        Ok(TrustedRoot {
            tlogs,
            note_logs,
            authorities,
            ctlogs,
            tsas,
            listed_logs,
        })
    }

    /// Whether the file lists any Rekor log (v1, v2 or one left out) or
    /// CT log: a root that does cannot carry the no-log opt-in (ADR-040,
    /// D1), so the opt-in never weakens a logged instance.
    pub(crate) fn lists_logs(&self) -> bool {
        self.listed_logs > 0
    }

    /// How many Rekor v1 logs the root holds (v2 logs are counted apart).
    pub fn tlog_count(&self) -> usize {
        self.tlogs.len()
    }

    /// How many Rekor v2 logs the root holds (ADR-038, D6).
    pub fn note_log_count(&self) -> usize {
        self.note_logs.len()
    }

    /// How many Fulcio certificate authorities the root holds.
    pub fn authority_count(&self) -> usize {
        self.authorities.len()
    }

    /// How many CT logs the root holds.
    pub fn ctlog_count(&self) -> usize {
        self.ctlogs.len()
    }

    /// How many timestamp authorities the root holds (ADR-038).
    pub fn tsa_count(&self) -> usize {
        self.tsas.len()
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
/// and `hashAlgorithm`, its window, and `logId.keyId`: the SHA-256 of the
/// key for CT logs and Rekor v1 (RFC 6962's log ID), the signed-note key
/// ID for Rekor v2. A `keyId` that is not 32 bytes of base64 refuses the
/// file.
fn log(value: &Value) -> Result<(PublicKey, Window, [u8; 32]), ConfigError> {
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
    Ok((key, window, id))
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
    let mut ders = chain(value)?;
    let root = ders.pop().ok_or(ConfigError::RootCertificate)?;
    Ok(Authority {
        intermediates: ders,
        root,
        window: window(value)?,
    })
}

/// The DER certificates of `certChain.certificates`, each non-empty
/// canonical base64.
fn chain(value: &Value) -> Result<Vec<Vec<u8>>, ConfigError> {
    let chain = json::object(value, "certChain").ok_or(ConfigError::RootCertificate)?;
    let certificates = json::array(chain, "certificates").ok_or(ConfigError::RootCertificate)?;
    certificates
        .iter()
        .map(|c| json::base64(c, "rawBytes").filter(|d| !d.is_empty()))
        .collect::<Option<Vec<_>>>()
        .ok_or(ConfigError::RootCertificate)
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

/// A `timestampAuthorities` entry (ADR-038, D4): `certChain.certificates`
/// with the TSA's leaf first and the anchor last, and `validFor` with
/// `start` required. `subject` and `uri` are not read; an empty chain
/// refuses the file. An entry whose chain is one certificate is read as
/// strictly and then skipped (`None`): webpki cannot verify a certificate
/// that is itself the anchor, so the entry anchors no token, and refusing
/// the whole file would also refuse every Rekor v1 bundle under it. A
/// chain whose first certificate is a CA is kept; no token verifies
/// through it, since its "leaf" is refused as a CA or as not the signer.
fn tsa(value: &Value) -> Result<Option<Tsa>, ConfigError> {
    let mut ders = chain(value)?;
    let window = window(value)?;
    if ders.len() == 1 {
        return Ok(None);
    }
    let root = ders.pop().ok_or(ConfigError::RootCertificate)?;
    let leaf = ders.remove(0);
    Ok(Some(Tsa {
        leaf,
        intermediates: ders,
        root,
        window,
    }))
}
