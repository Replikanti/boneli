//! Rekor v1 entries and their inclusion promises (ADR-029, S2), and
//! Rekor v2 entries and their inclusion proofs (ADR-038, D7).
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
//!
//! A cosign `.att` layer (ADR-037) may also be logged as `intoto` 0.0.1,
//! as slsa-github-generator before v2 did. That body has no signature
//! member: it names the SHA-256 of the envelope bytes (`content.hash`),
//! the SHA-256 of the decoded payload (`content.payloadHash`) and the
//! signing certificate (`publicKey`). Here the layer blob is the exact
//! envelope Rekor hashed, so the content hash binds the signature and the
//! payload, and the public key the leaf; that is the pair cosign's
//! `VerifyBundle` compares. The payload hash is checked as well, and
//! required: Rekor indexes attestations by it, so it ties the statement
//! log monitors see to the one we read. sigstore-go reads no `intoto`
//! 0.0.1 entry; bundles and `.sig` layers never take one here.
//!
//! A Rekor v2 entry (ADR-038) carries no time and no promise; it is
//! transparency evidence only, and its time comes from RFC 3161 tokens.
//! [`check_v2`] reads the one kind a bundle may log there,
//! `hashedrekord` 0.0.2, by rebuilding its body from the bundle, as
//! sigstore-go's `reconstructV2EntryHash` does: Rekor v2 writes it with
//! sorted keys and no whitespace, the SHA-256 of the DSSE PAE as the
//! digest, the signature and the leaf, all in base64, so nothing needs
//! escaping. The rebuilt bytes must equal `canonicalizedBody` byte for
//! byte (3 of 3 real entries do), so the inclusion proof commits to
//! exactly what we derived, never to a body read field by field. The leaf
//! must be P-256, the only key kind the body names here (12 of 12
//! measured leaves). The RFC 9162 (section 2.1.3.2) path from
//! SHA-256(0x00 ‖ body) must reach the root of a checkpoint the log's key
//! signed (`checkpoint`), and the log's window must hold every verified
//! time. No consistency proof is checked: an offline verifier holds no
//! earlier checkpoint (D8).

use boneli_https::{KeyKind, Sha256};
use boneli_json::Value;

use crate::checkpoint;
use crate::error::Refusal;
use crate::root::{NoteLog, TrustedRoot};
use crate::{MAX_BUNDLE_BYTES, base64, hex, json, pem};

/// One transparency log entry, as the evidence carries it: a Rekor v1
/// entry has its SET and integrated time, a Rekor v2 entry its proof.
#[derive(Clone, Debug)]
pub(crate) struct TlogEntry {
    /// The canonicalized entry body Rekor signed.
    pub(crate) body: Vec<u8>,
    /// The integrated time, read only with an inclusion promise.
    pub(crate) integrated_time: Option<u64>,
    pub(crate) log_index: u64,
    pub(crate) log_id: [u8; 32],
    /// The SET, if the entry carries an inclusion promise.
    pub(crate) set: Option<Vec<u8>>,
    /// The inclusion proof of an entry without a promise (Rekor v2).
    pub(crate) proof: Option<InclusionProof>,
}

/// A Rekor v2 entry's inclusion proof and its checkpoint, unparsed.
#[derive(Clone, Debug)]
pub(crate) struct InclusionProof {
    pub(crate) log_index: u64,
    pub(crate) tree_size: u64,
    pub(crate) root_hash: [u8; 32],
    pub(crate) hashes: Vec<[u8; 32]>,
    pub(crate) checkpoint: String,
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
    /// The entry of a cosign `.att` layer: a `dsse` 0.0.1 as [`Expected::Dsse`],
    /// or an `intoto` 0.0.1 over the envelope whose SHA-256 is `envelope`
    /// (ADR-037).
    Attestation {
        payload: &'a [u8],
        signature: &'a [u8],
        certificate: &'a [u8],
        envelope: &'a [u8; 32],
    },
}

/// The bytes a SET signs (module doc), at `integrated_time`.
pub(crate) fn set_message(entry: &TlogEntry, integrated_time: u64) -> Vec<u8> {
    format!(
        "{{\"body\":\"{}\",\"integratedTime\":{},\"logID\":\"{}\",\"logIndex\":{}}}",
        base64::encode(&entry.body),
        integrated_time,
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
    let (Some(set), Some(integrated_time)) = (entry.set.as_deref(), entry.integrated_time) else {
        return Err(Refusal::TlogEntries);
    };
    let log = root
        .tlogs
        .iter()
        .find(|log| log.key.key_id() == entry.log_id)
        .ok_or(Refusal::UnknownLog)?;
    if !log.window.contains(at_ms) {
        return Err(Refusal::LogOutsideWindow);
    }
    log.key
        .verify(&set_message(entry, integrated_time), set)
        .map_err(|_| Refusal::SetInvalid)?;
    let body = json::parse(&entry.body, MAX_BUNDLE_BYTES).ok_or(Refusal::BodyMismatch)?;
    body_matches(&body, expected)
}

/// Checks a Rekor v2 entry of `log` (module doc): a P-256 leaf
/// (`leaf_kind`, of the leaf webpki verified), a `hashedrekord` 0.0.2 body
/// equal to the one rebuilt from `message` (the PAE), `signature` and
/// `certificate`, the proof's index the entry's and inside the tree, a
/// checkpoint of the log over the proof's tree, the path from the body
/// to its root, and the log's window around every one of `times` (Unix
/// seconds).
pub(crate) fn check_v2(
    entry: &TlogEntry,
    log: &NoteLog,
    times: &[u64],
    leaf_kind: KeyKind,
    message: &[u8],
    signature: &[u8],
    certificate: &[u8],
) -> Result<(), Refusal> {
    if leaf_kind != KeyKind::EcdsaP256 {
        return Err(Refusal::EntryKeyKind);
    }
    let body = json::parse(&entry.body, MAX_BUNDLE_BYTES).ok_or(Refusal::BodyMismatch)?;
    if (
        json::string(&body, "kind"),
        json::string(&body, "apiVersion"),
    ) != (Some("hashedrekord"), Some("0.0.2"))
    {
        return Err(Refusal::EntryKind);
    }
    if hashedrekord_v2(message, signature, certificate) != entry.body {
        return Err(Refusal::BodyMismatch);
    }
    // Every entry without a promise has its proof (the bundle reader).
    let proof = entry.proof.as_ref().ok_or(Refusal::TlogEntries)?;
    if proof.log_index != entry.log_index || proof.log_index >= proof.tree_size {
        return Err(Refusal::InclusionProof);
    }
    checkpoint::verify(&proof.checkpoint, log, proof.tree_size, &proof.root_hash)?;
    if !included(
        &leaf_hash(&entry.body),
        proof.log_index,
        proof.tree_size,
        &proof.hashes,
        &proof.root_hash,
    ) {
        return Err(Refusal::InclusionProof);
    }
    if !times
        .iter()
        .all(|at| log.window.contains(at.saturating_mul(1_000)))
    {
        return Err(Refusal::LogOutsideWindow);
    }
    Ok(())
}

/// The `hashedrekord` 0.0.2 body Rekor v2 writes for a DSSE signature by
/// a P-256 leaf (module doc): sorted keys, no whitespace.
fn hashedrekord_v2(message: &[u8], signature: &[u8], certificate: &[u8]) -> Vec<u8> {
    format!(
        "{{\"apiVersion\":\"0.0.2\",\"kind\":\"hashedrekord\",\"spec\":{{\"hashedRekordV002\":{{\
         \"data\":{{\"algorithm\":\"SHA2_256\",\"digest\":\"{}\"}},\
         \"signature\":{{\"content\":\"{}\",\"verifier\":{{\"keyDetails\":\"PKIX_ECDSA_P256_SHA_256\",\
         \"x509Certificate\":{{\"rawBytes\":\"{}\"}}}}}}}}}}}}",
        base64::encode(&Sha256::digest(message)),
        base64::encode(signature),
        base64::encode(certificate),
    )
    .into_bytes()
}

/// RFC 6962's leaf hash, SHA-256(0x00 ‖ data).
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(data.len() + 1);
    bytes.push(0x00);
    bytes.extend_from_slice(data);
    Sha256::digest(&bytes)
}

/// RFC 6962's interior node, SHA-256(0x01 ‖ left ‖ right).
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 65];
    bytes[0] = 0x01;
    bytes[1..33].copy_from_slice(left);
    bytes[33..].copy_from_slice(right);
    Sha256::digest(&bytes)
}

/// Whether `hashes` lead from `leaf` at `index` of a tree of `size` to
/// `root`: RFC 9162, section 2.1.3.2, step by step. A hash past the path
/// (`sn` already 0) or a path cut short (`sn` not 0 at the end) fails, so
/// the path has exactly the length the position fixes, at most 63 hashes
/// for a tree of `i64::MAX` leaves; there is no other cap (ADR-038,
/// limits). The caller has checked `index < size`.
fn included(leaf: &[u8; 32], index: u64, size: u64, hashes: &[[u8; 32]], root: &[u8; 32]) -> bool {
    let mut fn_ = index;
    let mut sn = size.saturating_sub(1);
    let mut r = *leaf;
    for p in hashes {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
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
            let ok = sha256_is(hash, &Sha256::digest(payload))
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
            dsse_matches(spec, payload, signature, certificate)
        }
        Expected::Attestation {
            payload,
            signature,
            certificate,
            envelope,
        } => match (kind, version) {
            (Some("dsse"), Some("0.0.1")) => dsse_matches(spec, payload, signature, certificate),
            (Some("intoto"), Some("0.0.1")) => intoto_matches(spec, payload, certificate, envelope),
            _ => Err(Refusal::EntryKind),
        },
    }
}

/// Whether a `dsse` 0.0.1 `spec` names the SHA-256 of `payload` and
/// exactly one signature, `signature`, with `certificate` as verifier.
fn dsse_matches(
    spec: Option<&Value>,
    payload: &[u8],
    signature: &[u8],
    certificate: &[u8],
) -> Result<(), Refusal> {
    let spec = spec.ok_or(Refusal::BodyMismatch)?;
    let hash = json::object(spec, "payloadHash").ok_or(Refusal::BodyMismatch)?;
    let [one] = json::array(spec, "signatures").ok_or(Refusal::BodyMismatch)? else {
        return Err(Refusal::BodyMismatch);
    };
    let ok = sha256_is(hash, &Sha256::digest(payload))
        && json::base64(one, "signature").as_deref() == Some(signature)
        && pem_certificate(one, "verifier").as_deref() == Some(certificate);
    ok.then_some(()).ok_or(Refusal::BodyMismatch)
}

/// Whether an `intoto` 0.0.1 `spec` names the envelope whose SHA-256 is
/// `envelope` (`content.hash`), the SHA-256 of the decoded `payload`
/// (`content.payloadHash`) and `certificate` (`publicKey`). All three are
/// required (ADR-037, D2); `content.envelope` and other members are not
/// read.
fn intoto_matches(
    spec: Option<&Value>,
    payload: &[u8],
    certificate: &[u8],
    envelope: &[u8; 32],
) -> Result<(), Refusal> {
    let spec = spec.ok_or(Refusal::BodyMismatch)?;
    let content = json::object(spec, "content").ok_or(Refusal::BodyMismatch)?;
    let hash = json::object(content, "hash").ok_or(Refusal::BodyMismatch)?;
    let payload_hash = json::object(content, "payloadHash").ok_or(Refusal::BodyMismatch)?;
    let ok = sha256_is(hash, envelope)
        && sha256_is(payload_hash, &Sha256::digest(payload))
        && pem_certificate(spec, "publicKey").as_deref() == Some(certificate);
    ok.then_some(()).ok_or(Refusal::BodyMismatch)
}

/// Whether `hash` is `{"algorithm":"sha256","value":<hex>}` with `digest`
/// in lower-case hex.
fn sha256_is(hash: &Value, digest: &[u8; 32]) -> bool {
    json::string(hash, "algorithm") == Some("sha256")
        && json::string(hash, "value") == Some(hex::encode(digest).as_str())
}

/// The DER of the PEM certificate that the member `key` holds in base64.
fn pem_certificate(value: &Value, key: &str) -> Option<Vec<u8>> {
    pem::certificate(&json::base64(value, key)?)
}
