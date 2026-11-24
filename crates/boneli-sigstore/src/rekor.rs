//! Rekor v1 entries and their inclusion promises (ADR-029, S2).
//!
//! A Signed Entry Timestamp (SET) is Rekor's signature over the JSON
//! Canonicalization Scheme (RFC 8785) form of
//! `{"body":…,"integratedTime":…,"logID":…,"logIndex":…}`: the entry body
//! in base64, the integrated time in Unix seconds, the log ID in
//! lower-case hex and the log index. We build those bytes ourselves from
//! validated parts (canonical base64, lower-case hex, integers), so
//! nothing needs escaping and the keys are already in JCS order; a mistake
//! here can only refuse a valid promise, because the bytes feed a
//! signature check, and the real Kubernetes, Chainguard and cosign entries
//! are known answers (`tests/rekor.rs`).
//!
//! The promise vouches for the body; the body has to vouch for the
//! signature. As sigstore-go's `VerifyTlogEntry` compares them for Rekor
//! v1, a `hashedrekord` 0.0.1 body must carry the SHA-256 of the payload,
//! the signature bytes and the signing certificate, and a `dsse` 0.0.1
//! body the SHA-256 of the DSSE payload and exactly one signature with
//! its certificate as verifier. The `dsse` body's `envelopeHash` is not
//! checked: Rekor hashed the envelope as cosign submitted it, and the
//! bundle carries no copy of those bytes (cosign writes the envelope
//! again), so no input could reproduce it.

use boneli_https::Sha256;
use boneli_json::Value;

use crate::error::Refusal;
use crate::root::TrustedRoot;
use crate::{MAX_BUNDLE_BYTES, base64, hex, json, pem};

/// One transparency log entry, as the evidence carries it.
#[derive(Clone, Debug)]
pub(crate) struct TlogEntry {
    /// The canonicalized entry body Rekor signed.
    pub(crate) body: Vec<u8>,
    pub(crate) integrated_time: u64,
    pub(crate) log_index: u64,
    pub(crate) log_id: [u8; 32],
    /// The SET, if the entry carries an inclusion promise.
    pub(crate) set: Option<Vec<u8>>,
}

/// What the entry body must say.
pub(crate) enum Expected<'a> {
    /// A `hashedrekord` 0.0.1 over a cosign simple-signing payload.
    HashedRekord {
        payload: &'a [u8],
        signature: &'a [u8],
        certificate: &'a [u8],
    },
    /// A `dsse` 0.0.1 over a DSSE envelope with one signature.
    Dsse {
        payload: &'a [u8],
        signature: &'a [u8],
        certificate: &'a [u8],
    },
}

/// The bytes a SET signs (module doc).
pub(crate) fn set_message(entry: &TlogEntry) -> Vec<u8> {
    format!(
        "{{\"body\":\"{}\",\"integratedTime\":{},\"logID\":\"{}\",\"logIndex\":{}}}",
        base64::encode(&entry.body),
        entry.integrated_time,
        hex::encode(&entry.log_id),
        entry.log_index,
    )
    .into_bytes()
}

/// Checks `entry` against the Rekor logs of `root` at `at_ms`, its
/// integrated time in milliseconds: a known log whose window holds the
/// time, a SET that verifies under that log's key, and a body that says
/// what `expected` says.
pub(crate) fn check(
    entry: &TlogEntry,
    root: &TrustedRoot,
    at_ms: u64,
    expected: &Expected<'_>,
) -> Result<(), Refusal> {
    let set = entry.set.as_deref().ok_or(Refusal::TlogEntries)?;
    let log = root
        .tlogs
        .iter()
        .find(|log| log.key.key_id() == entry.log_id)
        .ok_or(Refusal::UnknownLog)?;
    if !log.window.contains(at_ms) {
        return Err(Refusal::LogOutsideWindow);
    }
    log.key
        .verify(&set_message(entry), set)
        .map_err(|_| Refusal::SetInvalid)?;
    let body = json::parse(&entry.body, MAX_BUNDLE_BYTES).ok_or(Refusal::BodyMismatch)?;
    body_matches(&body, expected)
}

/// Whether a parsed entry body says what `expected` says.
fn body_matches(body: &Value, expected: &Expected<'_>) -> Result<(), Refusal> {
    let kind = json::string(body, "kind");
    let version = json::string(body, "apiVersion");
    let spec = json::object(body, "spec");
    match expected {
        Expected::HashedRekord {
            payload,
            signature,
            certificate,
        } => {
            if (kind, version) != (Some("hashedrekord"), Some("0.0.1")) {
                return Err(Refusal::EntryKind);
            }
            let spec = spec.ok_or(Refusal::BodyMismatch)?;
            let hash = json::object(spec, "data")
                .and_then(|d| json::object(d, "hash"))
                .ok_or(Refusal::BodyMismatch)?;
            let sig = json::object(spec, "signature").ok_or(Refusal::BodyMismatch)?;
            let key = json::object(sig, "publicKey").ok_or(Refusal::BodyMismatch)?;
            let ok = hash_matches(hash, payload)
                && json::base64(sig, "content").as_deref() == Some(*signature)
                && pem_certificate(key, "content").as_deref() == Some(*certificate);
            ok.then_some(()).ok_or(Refusal::BodyMismatch)
        }
        Expected::Dsse {
            payload,
            signature,
            certificate,
        } => {
            if (kind, version) != (Some("dsse"), Some("0.0.1")) {
                return Err(Refusal::EntryKind);
            }
            let spec = spec.ok_or(Refusal::BodyMismatch)?;
            let hash = json::object(spec, "payloadHash").ok_or(Refusal::BodyMismatch)?;
            let [one] = json::array(spec, "signatures").ok_or(Refusal::BodyMismatch)? else {
                return Err(Refusal::BodyMismatch);
            };
            let ok = hash_matches(hash, payload)
                && json::base64(one, "signature").as_deref() == Some(*signature)
                && pem_certificate(one, "verifier").as_deref() == Some(*certificate);
            ok.then_some(()).ok_or(Refusal::BodyMismatch)
        }
    }
}

/// Whether `{"algorithm":"sha256","value":<hex>}` is the SHA-256 of
/// `data`.
fn hash_matches(hash: &Value, data: &[u8]) -> bool {
    json::string(hash, "algorithm") == Some("sha256")
        && json::string(hash, "value") == Some(hex::encode(&Sha256::digest(data)).as_str())
}

/// The DER of the PEM certificate that the member `key` holds in base64.
fn pem_certificate(value: &Value, key: &str) -> Option<Vec<u8>> {
    pem::certificate(&json::base64(value, key)?)
}
