//! cosign's attestations (ADR-036): one layer of the `.att` manifest,
//! media type [`DSSE_ENVELOPE_MEDIA_TYPE`], whose blob is a DSSE envelope
//! over an in-toto statement and whose annotations carry the rest, as on a
//! `.sig` layer (`cosign`).
//!
//! - [`CERTIFICATE_ANNOTATION`](crate::CERTIFICATE_ANNOTATION): the Fulcio
//!   leaf in PEM for a keyless attestation; absent or empty for a keyed
//!   one.
//! - [`BUNDLE_ANNOTATION`](crate::BUNDLE_ANNOTATION): the Rekor entry with
//!   its SET, in the `.sig` layer's form. Optional; a keyless attestation
//!   needs it in [`verify`](crate::verify).
//! - The signature annotation (always empty here: the signature is in the
//!   envelope), `dev.sigstore.cosign/chain` and
//!   [`PREDICATE_TYPE_ANNOTATION`] are never read. The predicate type that
//!   counts is the signed statement's; the annotation only lets
//!   `boneli-oci` skip layers it would not fetch.
//!
//! The envelope is read strictly: a JSON object whose `payloadType` is
//! in-toto's, whose `payload` is canonical base64 and whose `signatures`
//! hold exactly one entry with a canonical base64 `sig`; `keyid` and other
//! members are not read. The statement is in-toto Statement v0.1 or v1
//! (every measured `.att` is v0.1). The result is checked as a bundle is
//! (`verify`): PAE is the signed text, and a keyless one needs its one
//! Rekor `dsse` 0.0.1 entry. The entry body's `envelopeHash` is not
//! checked, as for a bundle (ADR-029 item 8): the signature over PAE, the
//! payload hash and the verifier already bind everything the verdict
//! reads.

use crate::cosign::{self, annotation};
use crate::dsse::{self, IN_TOTO_PAYLOAD_TYPE, STATEMENT_V01, STATEMENT_V1};
use crate::error::Refusal;
use crate::verify::{Dsse, Evidence, Form};
use crate::{BUNDLE_ANNOTATION, CERTIFICATE_ANNOTATION, MAX_BUNDLE_BYTES, json, pem};

/// The media type of an `.att` layer.
pub const DSSE_ENVELOPE_MEDIA_TYPE: &str = "application/vnd.dsse.envelope.v1+json";
/// The annotation of an `.att` layer that names its predicate type, as
/// cosign writes it.
pub const PREDICATE_TYPE_ANNOTATION: &str = "predicateType";

impl Evidence {
    /// The evidence of one `.att` layer: its `annotations` and its blob
    /// `envelope` of at most [`MAX_BUNDLE_BYTES`] (module doc). A key the
    /// reader uses that occurs twice refuses the layer; unknown keys are
    /// ignored.
    pub fn from_cosign_attestation(
        annotations: &[(&str, &str)],
        envelope: &[u8],
    ) -> Result<Evidence, Refusal> {
        if envelope.len() > MAX_BUNDLE_BYTES {
            return Err(Refusal::EnvelopeTooLarge);
        }
        let certificate = match annotation(annotations, CERTIFICATE_ANNOTATION)? {
            None | Some("") => None,
            Some(text) => {
                Some(pem::certificate(text.as_bytes()).ok_or(Refusal::MalformedCertificate)?)
            }
        };
        let tlog = match annotation(annotations, BUNDLE_ANNOTATION)? {
            None => None,
            Some(text) => {
                Some(cosign::legacy_entry(text.as_bytes()).ok_or(Refusal::MalformedTlogEntry)?)
            }
        };

        // A value that is not an object has no members, so it fails at
        // `payloadType` as `MalformedEnvelope`.
        let envelope = json::parse(envelope, MAX_BUNDLE_BYTES).ok_or(Refusal::MalformedEnvelope)?;
        let payload_type =
            json::string(&envelope, "payloadType").ok_or(Refusal::MalformedEnvelope)?;
        if payload_type != IN_TOTO_PAYLOAD_TYPE {
            return Err(Refusal::DsseShape);
        }
        let payload = json::base64(&envelope, "payload").ok_or(Refusal::MalformedEnvelope)?;
        let signatures = json::array(&envelope, "signatures").ok_or(Refusal::MalformedEnvelope)?;
        let [one] = signatures else {
            return Err(Refusal::DsseShape);
        };
        let signature = json::base64(one, "sig").ok_or(Refusal::MalformedSignature)?;
        let statement = dsse::statement(&payload, &[STATEMENT_V01, STATEMENT_V1])?;
        Ok(Evidence {
            form: Form::Attestation(Dsse {
                message: dsse::pae(payload_type.as_bytes(), &payload),
                payload,
                signature,
                certificate,
                statement,
                tlogs: tlog.into_iter().collect(),
            }),
        })
    }
}
