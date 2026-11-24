//! Sigstore bundles v0.3 with a DSSE envelope (ADR-029, S1), as cosign
//! attaches them to an image as OCI 1.1 referrers.
//!
//! Accepted is media type [`BUNDLE_V03_MEDIA_TYPE`] only, with:
//!
//! - `dsseEnvelope`: `payload` and `payloadType` (in-toto's, `dsse`), and
//!   exactly one signature. A `messageSignature` bundle is refused: it
//!   signs a digest without saying what the digest is of.
//! - `verificationMaterial`: exactly one of `certificate` (a Fulcio leaf,
//!   DER) and `publicKey` (a key hint, which is not read: the trust's keys
//!   are tried, so a hint cannot pick one). `x509CertificateChain`, the
//!   v0.1/v0.2 field, is refused as a version mismatch, so a chain an
//!   attacker sends along is never even parsed; intermediates come from
//!   the trusted root only.
//! - `tlogEntries`: each with `logIndex`, `logId.keyId`, `kindVersion`,
//!   `integratedTime`, `canonicalizedBody` and, if present,
//!   `inclusionPromise.signedEntryTimestamp`. A `kindVersion` that does
//!   not name the body's kind and version is a malformed entry, as
//!   sigstore-go treats it. `inclusionProof` and
//!   `timestampVerificationData` are not read (out of scope, ADR-029).
//!
//! Integers are protobuf JSON's int64 strings; bytes are canonical
//! base64.

use boneli_json::Value;

use crate::dsse::{self, IN_TOTO_PAYLOAD_TYPE};
use crate::error::Refusal;
use crate::rekor::TlogEntry;
use crate::verify::{Dsse, Evidence, Form};
use crate::{MAX_BUNDLE_BYTES, json};

/// The one bundle media type accepted.
pub const BUNDLE_V03_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

impl Evidence {
    /// The evidence of one bundle of at most [`MAX_BUNDLE_BYTES`] (module
    /// doc).
    pub fn from_bundle(bytes: &[u8]) -> Result<Evidence, Refusal> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(Refusal::BundleTooLarge);
        }
        let bundle = json::parse(bytes, MAX_BUNDLE_BYTES).ok_or(Refusal::MalformedBundle)?;
        if bundle.as_object().is_none() {
            return Err(Refusal::MalformedBundle);
        }
        if json::string(&bundle, "mediaType") != Some(BUNDLE_V03_MEDIA_TYPE) {
            return Err(Refusal::BundleVersion);
        }
        if bundle.get("messageSignature").is_some() {
            return Err(Refusal::MessageSignature);
        }
        let material =
            json::object(&bundle, "verificationMaterial").ok_or(Refusal::MalformedBundle)?;
        if material.get("x509CertificateChain").is_some() {
            return Err(Refusal::BundleVersion);
        }
        let certificate = match (material.get("certificate"), material.get("publicKey")) {
            (Some(cert), None) => Some(
                json::base64(cert, "rawBytes")
                    .filter(|der| !der.is_empty())
                    .ok_or(Refusal::MalformedCertificate)?,
            ),
            (None, Some(hint)) if hint.as_object().is_some() => None,
            _ => return Err(Refusal::MalformedBundle),
        };
        let tlogs = match material.get("tlogEntries") {
            None => Vec::new(),
            Some(list) => list
                .as_array()
                .ok_or(Refusal::MalformedTlogEntry)?
                .iter()
                .map(|e| entry(e).ok_or(Refusal::MalformedTlogEntry))
                .collect::<Result<Vec<_>, _>>()?,
        };

        let envelope = json::object(&bundle, "dsseEnvelope").ok_or(Refusal::MalformedBundle)?;
        let payload = json::base64(envelope, "payload").ok_or(Refusal::MalformedBundle)?;
        let payload_type = json::string(envelope, "payloadType").ok_or(Refusal::MalformedBundle)?;
        if payload_type != IN_TOTO_PAYLOAD_TYPE {
            return Err(Refusal::DsseShape);
        }
        let [one] = json::array(envelope, "signatures").ok_or(Refusal::MalformedBundle)? else {
            return Err(Refusal::DsseShape);
        };
        let signature = json::base64(one, "sig").ok_or(Refusal::MalformedSignature)?;
        let statement = dsse::statement(&payload, &[dsse::STATEMENT_V1])?;
        Ok(Evidence {
            form: Form::Bundle(Dsse {
                message: dsse::pae(payload_type.as_bytes(), &payload),
                payload,
                signature,
                certificate,
                statement,
                tlogs,
            }),
        })
    }
}

/// One `TransparencyLogEntry`.
fn entry(value: &Value) -> Option<TlogEntry> {
    let body = json::base64(value, "canonicalizedBody")?;
    let kind_version = json::object(value, "kindVersion")?;
    let parsed = json::parse(&body, MAX_BUNDLE_BYTES)?;
    if json::string(kind_version, "kind")? != json::string(&parsed, "kind")?
        || json::string(kind_version, "version")? != json::string(&parsed, "apiVersion")?
    {
        return None;
    }
    let log_id: [u8; 32] = json::base64(json::object(value, "logId")?, "keyId")?
        .try_into()
        .ok()?;
    let set = match value.get("inclusionPromise") {
        None => None,
        Some(promise) => Some(json::base64(promise, "signedEntryTimestamp")?),
    };
    Some(TlogEntry {
        body,
        integrated_time: json::decimal(value, "integratedTime")?,
        log_index: json::decimal(value, "logIndex")?,
        log_id,
        set,
    })
}
