//! The OCSP response (RFC 6960, 4.2; ADR-020, item 4): a strict parser
//! and the verifier whose result decides.
//!
//! Unlike the CRL reader (ADR-017, item 9), nothing behind this module
//! re-checks what it accepts, so it is strict: definite minimal lengths,
//! no trailing bytes at any level, a known structure only. The signature
//! is checked over the raw `tbsResponseData` bytes as they arrived, with
//! the handshake's algorithms and webpki's matching rule. The signer is
//! the leaf's issuer, or a certificate in the response that webpki
//! verifies as issued by that issuer for `id-kp-OCSPSigning`; the
//! responder ID only has to be well formed and never picks the signer.
//! Every `SingleResponse` that names the leaf's CertID exactly counts, and
//! any revocation among them wins.

use std::slice;

use rustls::pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};

use super::super::{RevocationFailureKind, signature};
use super::MAX_OCSP_RESPONSE_CERTS;
use super::request::CertId;
use crate::der::{
    self, BIT_STRING, BOOLEAN, CONTEXT_0, CONTEXT_1, CONTEXT_2, DerError, ENUMERATED,
    GENERALIZED_TIME, INTEGER, NULL, OCTET_STRING, OID, Reader, SEQUENCE,
};

/// id-pkix-ocsp-basic, 1.3.6.1.5.5.7.48.1.1.
const OCSP_BASIC: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// id-sha1, 1.3.14.3.2.26.
const SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
/// id-sha256, 2.16.840.1.101.3.4.2.1.
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// id-kp-OCSPSigning, 1.3.6.1.5.5.7.3.9, as webpki's `KeyUsage` takes it.
const OCSP_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
/// `good [0] IMPLICIT NULL`.
const GOOD: u8 = 0x80;
/// `unknown [2] IMPLICIT UnknownInfo` (a NULL).
const UNKNOWN: u8 = 0x82;

/// What a verified response says about the leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Good,
    Revoked,
}

/// A verified answer: the leaf's status and the window of the matching
/// responses (the latest `thisUpdate`, the earliest `nextUpdate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Answer {
    pub(crate) status: Status,
    pub(crate) this_update: u64,
    pub(crate) next_update: u64,
}

/// Why a response settled nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) kind: RevocationFailureKind,
    pub(crate) detail: String,
}

fn refuse(kind: RevocationFailureKind, detail: impl Into<String>) -> Refusal {
    Refusal {
        kind,
        detail: detail.into(),
    }
}

fn malformed(e: DerError) -> Refusal {
    refuse(RevocationFailureKind::Malformed, e.0)
}

/// The leaf's issuer on the verified path: its whole
/// `SubjectPublicKeyInfo`, and itself as the one trust anchor a delegated
/// responder certificate must chain to.
#[derive(Clone, Debug)]
pub(crate) struct Issuer {
    pub(crate) spki: Vec<u8>,
    pub(crate) anchor: TrustAnchor<'static>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    /// Another algorithm, or SHA-1 or SHA-256 with parameters other than
    /// NULL: never matches.
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CertStatus {
    Good,
    Revoked,
    Unknown,
}

struct Single<'a> {
    hash: Hash,
    name_hash: &'a [u8],
    key_hash: &'a [u8],
    serial: &'a [u8],
    status: CertStatus,
    this_update: u64,
    next_update: Option<u64>,
}

struct Basic<'a> {
    /// `tbsResponseData`, whole: what the signature covers.
    tbs: &'a [u8],
    /// The content of `signatureAlgorithm`.
    signature_algorithm: &'a [u8],
    signature: &'a [u8],
    /// The certificates, each whole.
    certs: Vec<&'a [u8]>,
    singles: Vec<Single<'a>>,
}

/// Verifies `response` for the certificate `id` issued by `issuer` at
/// `now`, with `algorithms` (the handshake's). `Ok` only for a response
/// that parses, is signed by an authorized signer, names `id` and is
/// inside its validity window: `Revoked` when any matching response says
/// so, `Good` when all of them do. Every other outcome is a refusal of
/// the kind the check reports (D1: all of them fail closed).
pub(crate) fn verify(
    response: &[u8],
    id: &CertId,
    issuer: &Issuer,
    algorithms: &[&dyn SignatureVerificationAlgorithm],
    now: UnixTime,
) -> Result<Answer, Refusal> {
    let basic = parse(response)?;
    if !signed_by_authorized(&basic, issuer, algorithms, now) {
        return Err(refuse(
            RevocationFailureKind::BadSignature,
            "not signed by the issuer or a responder it authorized",
        ));
    }
    decide(&basic, id, now.as_secs())
}

/// The status of the matching responses, after their windows.
fn decide(basic: &Basic<'_>, id: &CertId, now: u64) -> Result<Answer, Refusal> {
    let matches: Vec<&Single<'_>> = basic.singles.iter().filter(|s| names(s, id)).collect();
    if matches.is_empty() {
        return Err(refuse(
            RevocationFailureKind::NotSettled,
            "no response names the certificate",
        ));
    }
    let mut this_update = 0;
    let mut next_update = u64::MAX;
    for single in &matches {
        let Some(next) = single.next_update else {
            return Err(refuse(
                RevocationFailureKind::Malformed,
                "a response without nextUpdate",
            ));
        };
        if next < single.this_update {
            return Err(refuse(
                RevocationFailureKind::Malformed,
                "nextUpdate is before thisUpdate",
            ));
        }
        // Exclusive, as webpki's for a CRL. A `thisUpdate` in the future is
        // not refused, as webpki does not refuse one for a CRL.
        if next <= now {
            return Err(refuse(
                RevocationFailureKind::Expired,
                "the response is at or past its nextUpdate",
            ));
        }
        this_update = this_update.max(single.this_update);
        next_update = next_update.min(next);
    }
    let status = if matches.iter().any(|s| s.status == CertStatus::Revoked) {
        Status::Revoked
    } else if matches.iter().any(|s| s.status == CertStatus::Unknown) {
        return Err(refuse(
            RevocationFailureKind::UnknownCertificate,
            "the responder does not know the certificate",
        ));
    } else {
        Status::Good
    };
    Ok(Answer {
        status,
        this_update,
        next_update,
    })
}

/// Whether `single` names exactly the certificate of `id`: a known hash
/// with NULL or absent parameters, both hashes and the serial's content
/// bytes equal.
fn names(single: &Single<'_>, id: &CertId) -> bool {
    let (name, key): (&[u8], &[u8]) = match single.hash {
        Hash::Sha1 => (&id.sha1_name, &id.sha1_key),
        Hash::Sha256 => (&id.sha256_name, &id.sha256_key),
        Hash::Other => return false,
    };
    single.name_hash == name && single.key_hash == key && single.serial == id.serial.as_slice()
}

/// The issuer's key first, then each certificate of the response that
/// webpki verifies as issued by the issuer, directly, for
/// `id-kp-OCSPSigning` at `now` (RFC 6960, 4.2.2.2; BR 7.1.2.8).
fn signed_by_authorized(
    basic: &Basic<'_>,
    issuer: &Issuer,
    algorithms: &[&dyn SignatureVerificationAlgorithm],
    now: UnixTime,
) -> bool {
    if signed_by(&issuer.spki, basic, algorithms) {
        return true;
    }
    basic.certs.iter().any(|cert| {
        let der = CertificateDer::from(*cert);
        let Ok(responder) = webpki::EndEntityCert::try_from(&der) else {
            return false;
        };
        let authorized = responder
            .verify_for_usage(
                algorithms,
                slice::from_ref(&issuer.anchor),
                &[],
                now,
                webpki::KeyUsage::required(OCSP_SIGNING),
                None,
                None,
            )
            .is_ok();
        authorized
            && signed_by(
                responder.subject_public_key_info().as_ref(),
                basic,
                algorithms,
            )
    })
}

/// Whether the key of `spki` signed the response, by the rule of
/// `signature::verified`.
fn signed_by(
    spki: &[u8],
    basic: &Basic<'_>,
    algorithms: &[&dyn SignatureVerificationAlgorithm],
) -> bool {
    signature::verified(
        spki,
        basic.signature_algorithm,
        basic.tbs,
        basic.signature,
        algorithms,
    )
}

/// `OCSPResponse` down to the `BasicOCSPResponse`.
fn parse(response: &[u8]) -> Result<Basic<'_>, Refusal> {
    let mut outer = Reader::new(response);
    let mut body = Reader::new(outer.expect(SEQUENCE).map_err(malformed)?);
    outer.finish().map_err(malformed)?;
    let status = body.expect(ENUMERATED).map_err(malformed)?;
    match status {
        [0] => {}
        [code @ (1 | 2 | 3 | 5 | 6)] => {
            return Err(refuse(
                RevocationFailureKind::ResponderError,
                format!("responseStatus {code}"),
            ));
        }
        _ => {
            return Err(refuse(
                RevocationFailureKind::Malformed,
                "an unknown responseStatus",
            ));
        }
    }
    let mut bytes = Reader::new(body.expect(CONTEXT_0).map_err(malformed)?);
    body.finish().map_err(malformed)?;
    let mut bytes_seq = Reader::new(bytes.expect(SEQUENCE).map_err(malformed)?);
    bytes.finish().map_err(malformed)?;
    let kind = bytes_seq.expect(OID).map_err(malformed)?;
    let basic = bytes_seq.expect(OCTET_STRING).map_err(malformed)?;
    bytes_seq.finish().map_err(malformed)?;
    if kind != OCSP_BASIC {
        return Err(refuse(
            RevocationFailureKind::Malformed,
            "not a basic OCSP response",
        ));
    }
    basic_response(basic).map_err(malformed)
}

/// `BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm,
/// signature, certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }`.
fn basic_response(basic: &[u8]) -> Result<Basic<'_>, DerError> {
    let mut outer = Reader::new(basic);
    let mut body = Reader::new(outer.expect(SEQUENCE)?);
    outer.finish()?;
    let tbs = body.expect_tlv(SEQUENCE)?;
    let signature_algorithm = body.expect(SEQUENCE)?;
    let signature = match body.expect(BIT_STRING)?.split_first() {
        Some((0, signature)) => signature,
        _ => return Err(DerError("a signature with unused bits")),
    };
    let mut certs = Vec::new();
    if let Some(wrapper) = body.optional(CONTEXT_0)? {
        let mut wrapper = Reader::new(wrapper);
        let mut list = Reader::new(wrapper.expect(SEQUENCE)?);
        wrapper.finish()?;
        while !list.is_empty() {
            if certs.len() == MAX_OCSP_RESPONSE_CERTS {
                return Err(DerError("too many certificates"));
            }
            certs.push(list.expect_tlv(SEQUENCE)?);
        }
    }
    body.finish()?;
    let singles = response_data(tbs)?;
    Ok(Basic {
        tbs,
        signature_algorithm,
        signature,
        certs,
        singles,
    })
}

/// `ResponseData ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1,
/// responderID, producedAt, responses, responseExtensions [1] OPTIONAL }`.
fn response_data(tbs: &[u8]) -> Result<Vec<Single<'_>>, DerError> {
    let mut outer = Reader::new(tbs);
    let mut data = Reader::new(outer.expect(SEQUENCE)?);
    outer.finish()?;
    if let Some(version) = data.optional(CONTEXT_0)? {
        // Only v1, which DER leaves out; written out, it must be 0.
        let mut version = Reader::new(version);
        if version.expect(INTEGER)? != [0] {
            return Err(DerError("an unknown version"));
        }
        version.finish()?;
    }
    // ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }:
    // checked for form only, never used to pick the signer.
    let (tag, id) = data.read()?;
    let mut id = Reader::new(id);
    match tag {
        CONTEXT_1 => id.expect(SEQUENCE)?,
        CONTEXT_2 => id.expect(OCTET_STRING)?,
        _ => return Err(DerError("not a responder ID")),
    };
    id.finish()?;
    der::generalized_time(data.expect(GENERALIZED_TIME)?)?; // producedAt
    let mut responses = Reader::new(data.expect(SEQUENCE)?);
    if let Some(extensions) = data.optional(CONTEXT_1)? {
        check_extensions(extensions)?;
    }
    data.finish()?;
    let mut singles = Vec::new();
    while !responses.is_empty() {
        singles.push(single_response(responses.expect(SEQUENCE)?)?);
    }
    if singles.is_empty() {
        return Err(DerError("no responses"));
    }
    Ok(singles)
}

/// `SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate,
/// nextUpdate [0] EXPLICIT OPTIONAL, singleExtensions [1] OPTIONAL }`.
fn single_response(single: &[u8]) -> Result<Single<'_>, DerError> {
    let mut single = Reader::new(single);
    let mut cert_id = Reader::new(single.expect(SEQUENCE)?);
    let hash = hash_algorithm(cert_id.expect(SEQUENCE)?)?;
    let name_hash = cert_id.expect(OCTET_STRING)?;
    let key_hash = cert_id.expect(OCTET_STRING)?;
    let serial = cert_id.expect(INTEGER)?;
    cert_id.finish()?;
    let status = match single.read()? {
        (GOOD, []) => CertStatus::Good,
        (UNKNOWN, []) => CertStatus::Unknown,
        // RevokedInfo ::= SEQUENCE { revocationTime, revocationReason [0]
        // EXPLICIT CRLReason OPTIONAL }, implicitly tagged [1].
        (CONTEXT_1, info) => {
            let mut info = Reader::new(info);
            der::generalized_time(info.expect(GENERALIZED_TIME)?)?;
            if let Some(reason) = info.optional(CONTEXT_0)? {
                let mut reason = Reader::new(reason);
                reason.expect(ENUMERATED)?;
                reason.finish()?;
            }
            info.finish()?;
            CertStatus::Revoked
        }
        _ => return Err(DerError("not a certificate status")),
    };
    let this_update = der::generalized_time(single.expect(GENERALIZED_TIME)?)?;
    let next_update = match single.optional(CONTEXT_0)? {
        Some(next) => {
            let mut next = Reader::new(next);
            let time = der::generalized_time(next.expect(GENERALIZED_TIME)?)?;
            next.finish()?;
            Some(time)
        }
        None => None,
    };
    if let Some(extensions) = single.optional(CONTEXT_1)? {
        check_extensions(extensions)?;
    }
    single.finish()?;
    Ok(Single {
        hash,
        name_hash,
        key_hash,
        serial,
        status,
        this_update,
        next_update,
    })
}

/// The hash of a CertID: SHA-1 or SHA-256 with NULL or absent parameters,
/// anything else `Other`.
fn hash_algorithm(algorithm: &[u8]) -> Result<Hash, DerError> {
    let mut algorithm = Reader::new(algorithm);
    let oid = algorithm.expect(OID)?;
    let plain = match algorithm.read() {
        Err(_) if algorithm.is_empty() => true,
        Err(e) => return Err(e),
        Ok((NULL, [])) => algorithm.is_empty(),
        Ok(_) => false,
    };
    if !plain {
        return Ok(Hash::Other);
    }
    Ok(match oid {
        SHA1 => Hash::Sha1,
        SHA256 => Hash::Sha256,
        _ => Hash::Other,
    })
}

/// `[1] EXPLICIT Extensions`: well formed, and none marked critical. A
/// critical extension is one this client would have to understand, and
/// it understands none, so the response is refused; a non-critical one,
/// such as a nonce, is ignored.
fn check_extensions(wrapper: &[u8]) -> Result<(), DerError> {
    let mut wrapper = Reader::new(wrapper);
    let mut extensions = Reader::new(wrapper.expect(SEQUENCE)?);
    wrapper.finish()?;
    while !extensions.is_empty() {
        let mut extension = Reader::new(extensions.expect(SEQUENCE)?);
        extension.expect(OID)?;
        match extension.optional(BOOLEAN)? {
            None | Some([0x00]) => {}
            Some([0xFF]) => return Err(DerError("a critical extension")),
            Some(_) => return Err(DerError("a malformed critical flag")),
        }
        extension.expect(OCTET_STRING)?;
        extension.finish()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::testing::{
        self, FORGER_KEY, RESPONDER_KEY, Response, SingleSpec, T, ext, gtime,
    };
    use crate::revocation::RevocationFailureKind as Kind;

    const RESPONDER: &[u8] = include_bytes!("../../../tests/data/ocsp-responder.pem");
    const RESPONDER_NO_EKU: &[u8] = include_bytes!("../../../tests/data/ocsp-responder-no-eku.pem");
    const RESPONDER_OTHER_CA: &[u8] =
        include_bytes!("../../../tests/data/ocsp-responder-other-ca.pem");
    const RESPONDER_EXPIRED: &[u8] =
        include_bytes!("../../../tests/data/ocsp-responder-expired.pem");
    const RESPONDER_CA: &[u8] = include_bytes!("../../../tests/data/ocsp-responder-ca.pem");

    fn check(response: &[u8]) -> Result<Answer, Refusal> {
        check_at(response, T)
    }

    fn check_at(response: &[u8], now: u64) -> Result<Answer, Refusal> {
        verify(
            response,
            &testing::good_id(),
            &testing::issuer(),
            testing::algorithms(),
            testing::time(now),
        )
    }

    fn kind(result: Result<Answer, Refusal>) -> Kind {
        match result {
            Err(refusal) => refusal.kind,
            Ok(answer) => panic!("expected a refusal, got {answer:?}"),
        }
    }

    fn good_response() -> Response {
        Response::new(vec![SingleSpec::good(&testing::good_id().der)])
    }

    #[test]
    fn good_response_signed_by_issuer_passes() {
        let answer = check(&good_response().build()).expect("good");
        assert_eq!(answer.status, Status::Good);
        assert_eq!(answer.this_update, T - 3_600);
        assert_eq!(answer.next_update, T + 7 * 86_400);
    }

    #[test]
    fn revoked_response_refuses() {
        let mut response = good_response();
        response.singles[0].status = testing::revoked(T - 7_200);
        assert_eq!(
            check(&response.build()).expect("answer").status,
            Status::Revoked
        );
        // With a reason code.
        let mut reason = gtime(T - 7_200);
        reason.extend(der::encode(CONTEXT_0, &der::encode(ENUMERATED, &[1])));
        response.singles[0].status = der::encode(CONTEXT_1, &reason);
        assert_eq!(
            check(&response.build()).expect("answer").status,
            Status::Revoked
        );
    }

    #[test]
    fn unknown_status_fails_closed() {
        let mut response = good_response();
        response.singles[0].status = testing::unknown();
        assert_eq!(kind(check(&response.build())), Kind::UnknownCertificate);
    }

    #[test]
    fn flipped_signature_bit_fails() {
        let response = good_response();
        let tbs = response.tbs();
        let signature = response.sign(&tbs);
        for i in 0..signature.len() {
            let mut flipped = signature.clone();
            flipped[i] ^= 0x01;
            assert_eq!(
                kind(check(&response.assemble(&tbs, &flipped))),
                Kind::BadSignature,
                "byte {i}"
            );
        }
        assert!(check(&response.assemble(&tbs, &signature)).is_ok());
    }

    #[test]
    fn flipped_tbs_byte_fails() {
        // The responder ID's key hash: still a well-formed response.
        let response = good_response();
        let tbs = response.tbs();
        let signature = response.sign(&tbs);
        let at = tbs
            .windows(2)
            .position(|w| w == [0x04, 0x14])
            .expect("key hash")
            + 2;
        let mut flipped = tbs.clone();
        flipped[at] ^= 0x01;
        assert_eq!(
            kind(check(&response.assemble(&flipped, &signature))),
            Kind::BadSignature
        );
    }

    #[test]
    fn response_signed_by_other_ca_fails() {
        let mut response = good_response();
        response.key = FORGER_KEY;
        assert_eq!(kind(check(&response.build())), Kind::BadSignature);
    }

    #[test]
    fn other_serial_does_not_settle() {
        let other = testing::cert_id_with_serial(&[0x11]);
        let response = Response::new(vec![SingleSpec::good(&other.der)]);
        assert_eq!(kind(check(&response.build())), Kind::NotSettled);
    }

    #[test]
    fn serial_encoding_must_match_exactly() {
        // 0x10 with a redundant leading zero: the same value, not the same
        // encoding.
        let padded = testing::cert_id_with_serial(&[0x00, 0x10]);
        let response = Response::new(vec![SingleSpec::good(&padded.der)]);
        assert_eq!(kind(check(&response.build())), Kind::NotSettled);
        // And the other way round: the leaf 0x80 is `00 80`.
        let id = testing::id_of(testing::REVOKED_LEAF);
        assert_eq!(id.serial, [0x00, 0x80]);
        let short = testing::cert_id_with_serial(&[0x80]);
        let response = Response::new(vec![SingleSpec::good(&short.der)]);
        let result = verify(
            &response.build(),
            &id,
            &testing::issuer(),
            testing::algorithms(),
            testing::time(T),
        );
        assert_eq!(kind(result), Kind::NotSettled);
    }

    #[test]
    fn other_issuer_hash_does_not_settle() {
        let id = testing::good_id();
        for (name, key) in [
            (testing::flip_last(&id.sha1_name), id.sha1_key.to_vec()),
            (id.sha1_name.to_vec(), testing::flip_last(&id.sha1_key)),
        ] {
            let cert_id = testing::cert_id(testing::SHA1_NULL, &name, &key, &id.serial);
            let response = Response::new(vec![SingleSpec::good(&cert_id)]);
            assert_eq!(kind(check(&response.build())), Kind::NotSettled);
        }
    }

    #[test]
    fn sha256_cert_id_matches() {
        let id = testing::good_id();
        let sha256 = [&[0x30, 0x0D, 0x06, 0x09][..], SHA256, &[0x05, 0x00]].concat();
        let cert_id = testing::cert_id(&sha256, &id.sha256_name, &id.sha256_key, &id.serial);
        let response = Response::new(vec![SingleSpec::good(&cert_id)]);
        assert_eq!(check(&response.build()).expect("good").status, Status::Good);
        // SHA-256 hashes under the SHA-1 id do not match.
        let crossed = testing::cert_id(
            testing::SHA1_NULL,
            &id.sha256_name,
            &id.sha256_key,
            &id.serial,
        );
        let response = Response::new(vec![SingleSpec::good(&crossed)]);
        assert_eq!(kind(check(&response.build())), Kind::NotSettled);
    }

    #[test]
    fn sha1_params_absent_or_null_match() {
        let id = testing::good_id();
        let absent = [&[0x30, 0x07, 0x06, 0x05][..], SHA1].concat();
        for algorithm in [testing::SHA1_NULL, absent.as_slice()] {
            let cert_id = testing::cert_id(algorithm, &id.sha1_name, &id.sha1_key, &id.serial);
            let response = Response::new(vec![SingleSpec::good(&cert_id)]);
            assert_eq!(check(&response.build()).expect("good").status, Status::Good);
        }
        // Other parameters do not.
        let odd = [&[0x30, 0x09, 0x06, 0x05][..], SHA1, &[0x04, 0x00]].concat();
        let cert_id = testing::cert_id(&odd, &id.sha1_name, &id.sha1_key, &id.serial);
        let response = Response::new(vec![SingleSpec::good(&cert_id)]);
        assert_eq!(kind(check(&response.build())), Kind::NotSettled);
    }

    #[test]
    fn unknown_cert_id_hash_does_not_settle() {
        // id-md5 with the SHA-1 hashes.
        let md5 = [
            0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00,
        ];
        let id = testing::good_id();
        let cert_id = testing::cert_id(&md5, &id.sha1_name, &id.sha1_key, &id.serial);
        let response = Response::new(vec![SingleSpec::good(&cert_id)]);
        assert_eq!(kind(check(&response.build())), Kind::NotSettled);
    }

    fn with_window(this_update: u64, next_update: Option<u64>) -> Vec<u8> {
        let mut response = good_response();
        response.singles[0].this_update = this_update;
        response.singles[0].next_update = next_update;
        response.build()
    }

    #[test]
    fn next_update_bound_is_exclusive() {
        let response = with_window(T - 10, Some(T + 10));
        assert!(check_at(&response, T + 9).is_ok());
        assert_eq!(kind(check_at(&response, T + 10)), Kind::Expired);
    }

    #[test]
    fn reversed_window_is_malformed() {
        assert_eq!(
            kind(check(&with_window(T + 20, Some(T + 10)))),
            Kind::Malformed
        );
    }

    #[test]
    fn zero_length_window_is_expired() {
        assert_eq!(kind(check(&with_window(T, Some(T)))), Kind::Expired);
    }

    #[test]
    fn future_this_update_is_accepted() {
        let answer = check(&with_window(T + 3_600, Some(T + 86_400))).expect("good");
        assert_eq!(answer.this_update, T + 3_600);
    }

    #[test]
    fn missing_next_update_fails_closed() {
        assert_eq!(kind(check(&with_window(T - 10, None))), Kind::Malformed);
    }

    #[test]
    fn expired_response_fails_closed() {
        assert_eq!(
            kind(check(&with_window(T - 86_400, Some(T - 1)))),
            Kind::Expired
        );
    }

    #[test]
    fn responder_error_statuses_fail_closed() {
        for code in [1u8, 2, 3, 5, 6] {
            let bare = der::encode(SEQUENCE, &der::encode(ENUMERATED, &[code]));
            assert_eq!(kind(check(&bare)), Kind::ResponderError, "{code}");
        }
        for code in [4u8, 7, 0x80] {
            let bare = der::encode(SEQUENCE, &der::encode(ENUMERATED, &[code]));
            assert_eq!(kind(check(&bare)), Kind::Malformed, "{code}");
        }
        // Successful without responseBytes.
        let bare = der::encode(SEQUENCE, &der::encode(ENUMERATED, &[0]));
        assert_eq!(kind(check(&bare)), Kind::Malformed);
        // A two-byte status.
        let wide = der::encode(SEQUENCE, &der::encode(ENUMERATED, &[0, 0]));
        assert_eq!(kind(check(&wide)), Kind::Malformed);
    }

    #[test]
    fn malformed_response_fails_closed() {
        let good = good_response().build();
        let mut pem = b"-----BEGIN OCSP RESPONSE-----\n".to_vec();
        pem.extend_from_slice(&good);
        let mut unused = good_response();
        unused.unused_bits = 1;
        let mut version_one = good_response();
        version_one.version = Some(der::encode(CONTEXT_0, &der::encode(INTEGER, &[1])));
        let mut no_singles = good_response();
        no_singles.singles.clear();
        for (what, bytes) in [
            ("not DER", b"\x30\x80\x00\x00".to_vec()),
            ("empty", Vec::new()),
            ("PEM", pem),
            ("HTML", b"<html><body>Not OCSP</body></html>".to_vec()),
            ("unused bits", unused.build()),
            ("version 1", version_one.build()),
            ("no SingleResponse", no_singles.build()),
        ] {
            assert_eq!(kind(check(&bytes)), Kind::Malformed, "{what}");
        }
        // Version 0 written out is accepted.
        let mut version_zero = good_response();
        version_zero.version = Some(der::encode(CONTEXT_0, &der::encode(INTEGER, &[0])));
        assert!(check(&version_zero.build()).is_ok());
    }

    #[test]
    fn trailing_byte_is_malformed() {
        let mut outer = good_response().build();
        outer.push(0);
        assert_eq!(kind(check(&outer)), Kind::Malformed);
        // Inside the signed data: a byte after the responses.
        let response = good_response();
        let mut tbs = response.tbs();
        tbs = testing::append_inside(&tbs, &[0x05, 0x00]);
        let signature = response.sign(&tbs);
        assert_eq!(
            kind(check(&response.assemble(&tbs, &signature))),
            Kind::Malformed
        );
    }

    #[test]
    fn wrong_response_type_is_malformed() {
        let mut response = good_response();
        // id-pkix-ocsp-nonce instead of basic.
        response.response_type = vec![0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
        assert_eq!(kind(check(&response.build())), Kind::Malformed);
    }

    #[test]
    fn every_truncation_is_malformed() {
        let mut delegated = good_response();
        delegated.key = RESPONDER_KEY;
        delegated.certs = Some(vec![testing::pem_der(RESPONDER)]);
        for response in [good_response().build(), delegated.build()] {
            assert!(check(&response).is_ok());
            for len in 0..response.len() {
                assert_eq!(
                    kind(check(&response[..len])),
                    Kind::Malformed,
                    "prefix of {len} bytes"
                );
            }
        }
    }

    #[test]
    fn every_byte_flip_returns() {
        let mut delegated = good_response();
        delegated.key = RESPONDER_KEY;
        delegated.certs = Some(vec![testing::pem_der(RESPONDER)]);
        for response in [good_response().build(), delegated.build()] {
            for i in 0..response.len() {
                for bit in 0..8 {
                    let mut flipped = response.clone();
                    flipped[i] ^= 1 << bit;
                    // Any outcome, without a panic.
                    let _ = check(&flipped);
                }
            }
        }
    }

    const NONCE: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

    #[test]
    fn critical_extension_is_refused() {
        let critical = testing::extensions(&[ext(NONCE, Some(0xFF), &[0x04, 0x02, 1, 2])]);
        let mut response = good_response();
        response.extensions = Some(critical.clone());
        assert_eq!(kind(check(&response.build())), Kind::Malformed);
        let mut response = good_response();
        response.singles[0].extensions = Some(critical);
        assert_eq!(kind(check(&response.build())), Kind::Malformed);
        // A critical flag that is neither TRUE nor FALSE.
        let odd = testing::extensions(&[ext(NONCE, Some(0x01), &[0x04, 0x00])]);
        let mut response = good_response();
        response.extensions = Some(odd);
        assert_eq!(kind(check(&response.build())), Kind::Malformed);
    }

    #[test]
    fn noncritical_nonce_is_ignored() {
        for flag in [None, Some(0x00)] {
            let nonce = testing::extensions(&[ext(NONCE, flag, &[0x04, 0x02, 1, 2])]);
            let mut response = good_response();
            response.extensions = Some(nonce.clone());
            response.singles[0].extensions = Some(nonce);
            assert!(check(&response.build()).is_ok());
        }
    }

    #[test]
    fn revoked_single_response_wins() {
        let id = testing::good_id();
        let other = testing::cert_id_with_serial(&[0x11]);
        let revoked = SingleSpec {
            status: testing::revoked(T - 60),
            ..SingleSpec::good(&id.der)
        };
        for singles in [
            vec![SingleSpec::good(&other.der), revoked.clone()],
            vec![SingleSpec::good(&id.der), revoked.clone()],
            vec![revoked.clone(), SingleSpec::good(&id.der)],
        ] {
            let response = Response::new(singles);
            assert_eq!(
                check(&response.build()).expect("answer").status,
                Status::Revoked
            );
        }
    }

    #[test]
    fn unknown_beats_good_for_same_cert() {
        let id = testing::good_id();
        let unknown = SingleSpec {
            status: testing::unknown(),
            ..SingleSpec::good(&id.der)
        };
        let response = Response::new(vec![SingleSpec::good(&id.der), unknown]);
        assert_eq!(kind(check(&response.build())), Kind::UnknownCertificate);
    }

    fn delegated(cert: &[u8], key: &'static [u8]) -> Vec<u8> {
        let mut response = good_response();
        response.key = key;
        response.certs = Some(vec![testing::pem_der(cert)]);
        response.build()
    }

    #[test]
    fn delegated_responder_passes() {
        let answer = check(&delegated(RESPONDER, RESPONDER_KEY)).expect("delegated");
        assert_eq!(answer.status, Status::Good);
        // Without its certificate, the responder's key is nobody's.
        let mut bare = good_response();
        bare.key = RESPONDER_KEY;
        assert_eq!(kind(check(&bare.build())), Kind::BadSignature);
    }

    #[test]
    fn responder_without_ocsp_signing_fails() {
        assert_eq!(
            kind(check(&delegated(RESPONDER_NO_EKU, RESPONDER_KEY))),
            Kind::BadSignature
        );
    }

    #[test]
    fn responder_from_other_ca_fails() {
        // Issued by the decoy, which carries the CA's name under another
        // key.
        assert_eq!(
            kind(check(&delegated(RESPONDER_OTHER_CA, RESPONDER_KEY))),
            Kind::BadSignature
        );
    }

    #[test]
    fn expired_responder_fails() {
        // Valid 2026-01-01 to 2026-01-02 only; T is later.
        assert_eq!(
            kind(check(&delegated(RESPONDER_EXPIRED, RESPONDER_KEY))),
            Kind::BadSignature
        );
        // Inside its validity it is a responder like the others.
        assert!(check_at(&delegated(RESPONDER_EXPIRED, RESPONDER_KEY), 1_767_240_000).is_ok());
    }

    #[test]
    fn ca_responder_fails() {
        assert_eq!(
            kind(check(&delegated(RESPONDER_CA, RESPONDER_KEY))),
            Kind::BadSignature
        );
    }

    #[test]
    fn issuer_signature_with_extra_certs_passes() {
        let mut response = good_response();
        response.certs = Some(vec![
            testing::pem_der(RESPONDER_NO_EKU),
            testing::pem_der(testing::CA),
        ]);
        assert!(check(&response.build()).is_ok());
    }

    #[test]
    fn too_many_certs_is_malformed() {
        let cert = testing::pem_der(RESPONDER);
        let mut response = good_response();
        response.certs = Some(vec![cert.clone(); MAX_OCSP_RESPONSE_CERTS]);
        assert!(check(&response.build()).is_ok());
        response.certs = Some(vec![cert; MAX_OCSP_RESPONSE_CERTS + 1]);
        assert_eq!(kind(check(&response.build())), Kind::Malformed);
    }

    #[test]
    fn responder_id_is_not_trusted_for_selection() {
        // The ID names the delegated responder by name; the issuer signed.
        let mut response = good_response();
        response.responder_id = der::encode(
            CONTEXT_1,
            &der::encode(SEQUENCE, &der::encode(0x31, &[0x30, 0x00])),
        );
        assert!(check(&response.build()).is_ok());
        // An ID of neither form is malformed.
        response.responder_id = der::encode(0xA3, &der::encode(OCTET_STRING, &[0; 20]));
        assert_eq!(kind(check(&response.build())), Kind::Malformed);
    }

    #[test]
    fn algorithm_key_mismatch_fails() {
        // sha256WithRSAEncryption claimed over the CA's ECDSA key.
        let mut response = good_response();
        response.signature_algorithm = vec![
            0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
            0x00,
        ];
        assert_eq!(kind(check(&response.build())), Kind::BadSignature);
    }

    #[test]
    fn sha1_signature_is_refused() {
        // sha1WithRSAEncryption and ecdsa-with-SHA1: no algorithm of the
        // handshake has either id.
        for id in [
            vec![
                0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05,
                0x00,
            ],
            vec![
                0x30, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01,
            ],
        ] {
            let mut response = good_response();
            response.signature_algorithm = id;
            assert_eq!(kind(check(&response.build())), Kind::BadSignature);
        }
    }

    #[test]
    fn openssl_fixtures_verify() {
        // `openssl ocsp -index` answers, at a time inside their 100 years.
        let now = 1_830_000_000;
        let good = include_bytes!("../../../tests/data/ocsp-good.resp");
        let bykey = include_bytes!("../../../tests/data/ocsp-good-bykey.resp");
        let delegated = include_bytes!("../../../tests/data/ocsp-delegated.resp");
        let unknown = include_bytes!("../../../tests/data/ocsp-unknown.resp");
        let expired = include_bytes!("../../../tests/data/ocsp-expired.resp");
        for response in [&good[..], &bykey[..], &delegated[..]] {
            assert_eq!(check_at(response, now).expect("good").status, Status::Good);
        }
        assert_eq!(kind(check_at(unknown, now)), Kind::UnknownCertificate);
        assert_eq!(kind(check_at(expired, now)), Kind::Expired);
        let revoked = include_bytes!("../../../tests/data/ocsp-revoked.resp");
        let result = verify(
            revoked,
            &testing::id_of(testing::REVOKED_LEAF),
            &testing::issuer(),
            testing::algorithms(),
            testing::time(now),
        );
        assert_eq!(result.expect("revoked").status, Status::Revoked);
    }
}
