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
//! Rekor entry, of one of two kinds:
//!
//! - `dsse` 0.0.1 (ADR-036), as for a bundle. The body's `envelopeHash` is
//!   not checked (ADR-029 item 8): the signature over PAE, the payload
//!   hash and the verifier already bind everything the verdict reads.
//! - `intoto` 0.0.1 (ADR-037), as slsa-github-generator before v2 logged
//!   its attestations. Its body holds no signature, so the binding runs
//!   through the envelope bytes: the SET covers the body, the body's
//!   `content.hash` is the SHA-256 of the exact blob this reader took (the
//!   layer digest `boneli-oci` checked on fetch), and with those bytes the
//!   signature and payload are fixed; `content.payloadHash` names the
//!   decoded payload and `publicKey` the leaf, which the chain then
//!   verifies. The digest is taken over the input before any parse, never
//!   over a re-serialization.
//!
//! Only `.att` takes an `intoto` entry: a bundle does not carry the bytes
//! Rekor hashed, and a `.sig` layer is a `hashedrekord` (ADR-029 S2).

use boneli_https::Sha256;

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
        // Over the input as received, before any parse: an `intoto` entry
        // names these bytes, and a re-serialization would differ.
        let digest = Sha256::digest(envelope);
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
            form: Form::Attestation(
                Dsse {
                    message: dsse::pae(payload_type.as_bytes(), &payload),
                    payload,
                    signature,
                    certificate,
                    statement,
                    tlogs: tlog.into_iter().collect(),
                    timestamps: Vec::new(),
                },
                digest,
            ),
        })
    }
}
