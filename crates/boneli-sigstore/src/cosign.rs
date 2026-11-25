//! cosign's legacy signatures (ADR-029, S1): one layer of the `.sig`
//! manifest, media type [`SIMPLE_SIGNING_MEDIA_TYPE`], whose blob is the
//! signed simple-signing payload and whose annotations carry the rest.
//!
//! - [`SIGNATURE_ANNOTATION`]: the signature over the payload's bytes, in
//!   base64. Required.
//! - [`CERTIFICATE_ANNOTATION`]: the Fulcio leaf in PEM, for a keyless
//!   signature. Absent (or empty) for a keyed one.
//! - [`BUNDLE_ANNOTATION`]: the Rekor entry with its SET, as JSON
//!   `{"SignedEntryTimestamp":…,"Payload":{"body":…,"integratedTime":…,"logIndex":…,"logID":…}}`.
//! - `dev.sigstore.cosign/chain` is never read: intermediates come only
//!   from the trusted root, so a chain an attacker attaches changes
//!   nothing.
//!
//! The payload is read strictly where it decides: `critical.type` must be
//! `cosign container image signature` byte for byte, and
//! `critical.image.docker-manifest-digest` must be `sha256:` and 64
//! lower-case hex digits. `critical.identity.docker-reference` and
//! `optional` are ignored: the digest binds the bytes, and a mirror under
//! another name is legitimate.

use crate::error::Refusal;
use crate::rekor::TlogEntry;
use crate::verify::{Evidence, Form};
use crate::{MAX_BUNDLE_BYTES, MAX_PAYLOAD_BYTES, base64, hex, json, pem};

/// The media type of a simple-signing layer.
pub const SIMPLE_SIGNING_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
/// The annotation holding the signature.
pub const SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
/// The annotation holding the signing certificate.
pub const CERTIFICATE_ANNOTATION: &str = "dev.sigstore.cosign/certificate";
/// The annotation holding the Rekor entry and its promise.
pub const BUNDLE_ANNOTATION: &str = "dev.sigstore.cosign/bundle";
/// `critical.type` of an image signature.
pub const SIMPLE_SIGNING_TYPE: &str = "cosign container image signature";

impl Evidence {
    /// The evidence of one simple-signing layer: its `annotations` and
    /// its blob `payload` (module doc). A key the reader uses that occurs
    /// twice refuses the layer; unknown keys are ignored.
    pub fn from_cosign_layer(
        annotations: &[(&str, &str)],
        payload: &[u8],
    ) -> Result<Evidence, Refusal> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Refusal::PayloadTooLarge);
        }
        let one = |key: &str| annotation(annotations, key);
        let signature = one(SIGNATURE_ANNOTATION)?.ok_or(Refusal::MalformedAnnotations)?;
        let signature = base64::decode(signature.as_bytes()).ok_or(Refusal::MalformedSignature)?;
        let certificate = match one(CERTIFICATE_ANNOTATION)? {
            None | Some("") => None,
            Some(text) => {
                Some(pem::certificate(text.as_bytes()).ok_or(Refusal::MalformedCertificate)?)
            }
        };
        let tlog = match one(BUNDLE_ANNOTATION)? {
            None => None,
            Some(text) => Some(legacy_entry(text.as_bytes()).ok_or(Refusal::MalformedTlogEntry)?),
        };
        let digest = signed_digest(payload)?;
        Ok(Evidence {
            form: Form::Cosign {
                payload: payload.to_vec(),
                digest,
                signature,
                certificate,
                tlog,
            },
        })
    }
}

/// The value of `key` among `annotations`, if any; a key that occurs
/// twice refuses (`MalformedAnnotations`), so the layer has one reading.
pub(crate) fn annotation<'a>(
    annotations: &[(&str, &'a str)],
    key: &str,
) -> Result<Option<&'a str>, Refusal> {
    let mut values = annotations.iter().filter(|(k, _)| *k == key);
    let first = values.next().map(|(_, v)| *v);
    match values.next() {
        Some(_) => Err(Refusal::MalformedAnnotations),
        None => Ok(first),
    }
}

/// The digest a simple-signing payload names (module doc).
fn signed_digest(payload: &[u8]) -> Result<[u8; 32], Refusal> {
    let value = json::parse(payload, MAX_PAYLOAD_BYTES).ok_or(Refusal::MalformedPayload)?;
    let critical = json::object(&value, "critical").ok_or(Refusal::MalformedPayload)?;
    let kind = json::string(critical, "type").ok_or(Refusal::MalformedPayload)?;
    if kind != SIMPLE_SIGNING_TYPE {
        return Err(Refusal::PayloadType);
    }
    let image = json::object(critical, "image").ok_or(Refusal::MalformedPayload)?;
    let digest = json::string(image, "docker-manifest-digest").ok_or(Refusal::MalformedPayload)?;
    hex::sha256_digest(digest).ok_or(Refusal::MalformedDigest)
}

/// The Rekor entry of a [`BUNDLE_ANNOTATION`].
pub(crate) fn legacy_entry(text: &[u8]) -> Option<TlogEntry> {
    let value = json::parse(text, MAX_BUNDLE_BYTES)?;
    let set = json::base64(&value, "SignedEntryTimestamp")?;
    let payload = json::object(&value, "Payload")?;
    Some(TlogEntry {
        body: json::base64(payload, "body")?,
        integrated_time: Some(json::integer(payload, "integratedTime")?),
        log_index: json::integer(payload, "logIndex")?,
        log_id: hex::decode_32(json::string(payload, "logID")?)?,
        set: Some(set),
        proof: None,
    })
}
