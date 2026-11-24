//! DSSE's pre-authentication encoding and the in-toto Statement v1 it
//! carries (ADR-029, S5).
//!
//! A DSSE signature is over `PAE(payloadType, payload)`, so the payload
//! type is signed too: `DSSEv1 <len> <type> <len> <payload>`, lengths in
//! bytes as ASCII decimal. Only `application/vnd.in-toto+json` is
//! accepted, and the payload must be a Statement v1 (`_type` byte for
//! byte). What it signs is its `subject` list: a subject matches by
//! `digest.sha256`, 64 lower-case hex digits compared byte for byte, and
//! other algorithms or forms never match. Its `predicateType` must be on
//! the trust's list; the predicate itself is not evaluated (SLSA claim
//! checks are a follow-up).

use boneli_json::Value;

use crate::error::Refusal;
use crate::{MAX_BUNDLE_BYTES, hex, json};

/// The one DSSE payload type accepted.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// The one statement type accepted.
pub const STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

/// `PAE(payload_type, payload)` of the DSSE specification.
pub fn pae(payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// What a statement signs.
#[derive(Clone, Debug)]
pub(crate) struct Statement {
    /// The SHA-256 digests of the subjects that name one in the accepted
    /// form.
    pub(crate) subjects: Vec<[u8; 32]>,
    pub(crate) predicate_type: String,
}

/// Reads an in-toto Statement v1.
pub(crate) fn statement(payload: &[u8]) -> Result<Statement, Refusal> {
    let value = json::parse(payload, MAX_BUNDLE_BYTES).ok_or(Refusal::MalformedStatement)?;
    if value.as_object().is_none() {
        return Err(Refusal::MalformedStatement);
    }
    if json::string(&value, "_type") != Some(STATEMENT_V1) {
        return Err(Refusal::StatementType);
    }
    let subjects = json::array(&value, "subject").ok_or(Refusal::MalformedStatement)?;
    let predicate_type =
        json::string(&value, "predicateType").ok_or(Refusal::MalformedStatement)?;
    Ok(Statement {
        subjects: subjects.iter().filter_map(subject_digest).collect(),
        predicate_type: predicate_type.to_owned(),
    })
}

/// The SHA-256 a subject names in the accepted form, or `None`.
fn subject_digest(subject: &Value) -> Option<[u8; 32]> {
    hex::decode_32(json::string(json::object(subject, "digest")?, "sha256")?)
}
