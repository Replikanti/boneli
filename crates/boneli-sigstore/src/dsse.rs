//! DSSE's pre-authentication encoding and the in-toto statement it carries
//! (ADR-029, S5; ADR-036).
//!
//! A DSSE signature is over `PAE(payloadType, payload)`, so the payload
//! type is signed too: `DSSEv1 <len> <type> <len> <payload>`, lengths in
//! bytes as ASCII decimal. Only `application/vnd.in-toto+json` is
//! accepted, and the statement's `_type` must be one the caller admits,
//! byte for byte: Statement v1 in a bundle, v0.1 or v1 in a cosign `.att`
//! (ADR-036: every measured `.att` is v0.1, no measured bundle is). What
//! it signs is its `subject` list: a subject matches by
//! `digest.sha256`, 64 lower-case hex digits compared byte for byte, and
//! other algorithms or forms never match. Its `predicateType` must be on
//! the trust's list; the predicate itself is evaluated only under a trust
//! with claims (`provenance`, ADR-031).

use boneli_json::Value;

use crate::error::Refusal;
use crate::{MAX_BUNDLE_BYTES, hex, json};

/// The one DSSE payload type accepted.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// in-toto Statement v1, the one statement type a bundle may carry.
pub const STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
/// in-toto Statement v0.1, admitted in a cosign `.att` only (ADR-036).
pub const STATEMENT_V01: &str = "https://in-toto.io/Statement/v0.1";

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

/// Reads an in-toto statement whose `_type` is one of `types`.
pub(crate) fn statement(payload: &[u8], types: &[&str]) -> Result<Statement, Refusal> {
    let value = json::parse(payload, MAX_BUNDLE_BYTES).ok_or(Refusal::MalformedStatement)?;
    if value.as_object().is_none() {
        return Err(Refusal::MalformedStatement);
    }
    if !json::string(&value, "_type").is_some_and(|t| types.contains(&t)) {
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
