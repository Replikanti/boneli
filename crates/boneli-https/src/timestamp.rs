//! RFC 3161 timestamp tokens, as Sigstore bundles carry them in
//! `timestampVerificationData` (ADR-038, D3): a time authority's (TSA's)
//! CMS signature over a time and the SHA-256 of a message, which for a
//! bundle is the bytes of the DSSE signature.
//!
//! The parse decides, so it is strict ([`der::Reader`]): the whole
//! `TimeStampResp` with status 0 or 1 and nothing after it; a ContentInfo
//! of signed data over a TSTInfo; **exactly one** SignerInfo with digest
//! SHA-256 and signature `ecdsa-with-SHA256`; signed attributes with
//! contentType, messageDigest and signingCertificateV2 each exactly once;
//! a TSTInfo of version 1, a SHA-256 imprint and a genTime in whole
//! seconds. `certificates [0]` and `crls [1]` are skipped unread: the
//! signer's chain comes only from the caller (the operator's trusted
//! root), never from the token, so a certificate an attacker puts there is
//! never parsed. The signer is bound by the ESSCertIDv2 hash of its
//! certificate, so `sid` is read for form only, and so are the fields
//! nothing here decides on: policy, serial number, accuracy, ordering,
//! nonce, the TSA name, the signing time.
//!
//! [`TimestampToken::verify`] checks, cheapest first: the imprint against
//! the message, the ESSCertIDv2 hash against the leaf, the leaf's EKU
//! (critical and exactly `id-kp-timeStamping`, RFC 3161 2.3) and keyUsage,
//! the chain by webpki at genTime with the anchor itself valid then
//! (`codesign::verify_chain`), the messageDigest against the TSTInfo
//! bytes, and the leaf's signature over
//! the signed attributes. Every refusal is a fixed [`TimestampError`].

use std::fmt;

use rustls::pki_types::{SignatureVerificationAlgorithm, alg_id};

use crate::codesign::{self, CertError};
use crate::der::{
    self, BOOLEAN, CONTEXT_0, DerError, GENERALIZED_TIME, INTEGER, NULL, OCTET_STRING, OID, Reader,
    SEQUENCE,
};
use crate::revocation::signature;
use crate::sha256::Sha256;

#[cfg(test)]
mod testing;

/// id-signedData, 1.2.840.113549.1.7.2.
const ID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// id-ct-TSTInfo, 1.2.840.113549.1.9.16.1.4.
const ID_CT_TST_INFO: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];
/// The contentType attribute, 1.2.840.113549.1.9.3.
const CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
/// The messageDigest attribute, 1.2.840.113549.1.9.4.
const MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
/// id-aa-signingCertificateV2, 1.2.840.113549.1.9.16.2.47.
const SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];
/// id-sha256, 2.16.840.1.101.3.4.2.1.
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// id-kp-timeStamping, 1.3.6.1.5.5.7.3.8.
const ID_KP_TIME_STAMPING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
/// id-ce-extKeyUsage, 2.5.29.37.
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
/// `[1]` constructed: `crls` of SignedData, `unsignedAttrs` of a
/// SignerInfo, the extensions of a TSTInfo.
const CONTEXT_1: u8 = 0xA1;
/// `[0]` primitive: a SignerInfo's `subjectKeyIdentifier`.
const CONTEXT_0_PRIMITIVE: u8 = 0x80;
/// The SET tag the signed attributes are signed under (RFC 5652, 5.4).
const SET: u8 = 0x31;

/// Why a timestamp token was refused. Every variant is a fixed rule, so
/// no message carries token or certificate text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampError {
    /// The token is not DER of the shape read here.
    Malformed,
    /// The response's status is neither granted (0) nor granted with
    /// modifications (1).
    Status,
    /// The content is not signed data over a TSTInfo, or the contentType
    /// attribute names another type.
    ContentType,
    /// The signed data holds no SignerInfo or more than one.
    SignerCount,
    /// The digest is not SHA-256, or the signature not `ecdsa-with-SHA256`.
    Algorithm,
    /// The signed attributes are missing, or contentType or messageDigest
    /// is missing, present twice or not one value.
    SignedAttributes,
    /// messageDigest is not the SHA-256 of the TSTInfo.
    MessageDigest,
    /// signingCertificateV2 is missing, present twice, not over SHA-256,
    /// or does not name the leaf.
    SigningCertificate,
    /// The message imprint is not SHA-256.
    ImprintAlgorithm,
    /// genTime is not `YYYYMMDDHHMMSSZ` of a real time from 1970 on.
    Time,
    /// The TSTInfo has an extension marked critical.
    CriticalExtension,
    /// The imprint is not the SHA-256 of the message.
    Imprint,
    /// The leaf's extended key usage is not critical and exactly
    /// `id-kp-timeStamping`, or an intermediate lacks it.
    NotTimestamping,
    /// The leaf's keyUsage allows neither digitalSignature nor
    /// nonRepudiation.
    KeyUsage,
    /// The TSA's chain does not verify at genTime.
    Chain(CertError),
    /// The leaf's key does not verify the signature.
    Signature,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TimestampError::Malformed => "the timestamp token is malformed",
            TimestampError::Status => "the timestamp response was not granted",
            TimestampError::ContentType => "the timestamp token is not signed data over a TSTInfo",
            TimestampError::SignerCount => "the timestamp token has not exactly one signer",
            TimestampError::Algorithm => {
                "the timestamp token's digest or signature algorithm is not accepted"
            }
            TimestampError::SignedAttributes => {
                "the timestamp token's signed attributes are malformed"
            }
            TimestampError::MessageDigest => {
                "the timestamp token's message digest does not match its TSTInfo"
            }
            TimestampError::SigningCertificate => {
                "the timestamp token does not name the authority's certificate"
            }
            TimestampError::ImprintAlgorithm => "the timestamp's message imprint is not SHA-256",
            TimestampError::Time => "the timestamp's time is not a whole-second UTC time",
            TimestampError::CriticalExtension => "the timestamp has a critical extension",
            TimestampError::Imprint => "the timestamp is not over the signature",
            TimestampError::NotTimestamping => {
                "the authority's certificate is not valid for timestamping"
            }
            TimestampError::KeyUsage => "the authority's key may not sign timestamps",
            TimestampError::Chain(_) => "the authority's certificate does not verify",
            TimestampError::Signature => "the timestamp's signature does not verify",
        })?;
        match self {
            TimestampError::Chain(e) => write!(f, ": {e}"),
            _ => Ok(()),
        }
    }
}

impl std::error::Error for TimestampError {}

/// A parsed RFC 3161 timestamp token (module doc).
///
/// `Debug` shows the genTime only.
#[derive(Clone)]
pub struct TimestampToken {
    gen_time: u64,
    imprint: [u8; 32],
    /// The TSTInfo DER, the eContent octets.
    tst_info: Vec<u8>,
    message_digest: [u8; 32],
    cert_hash: [u8; 32],
    /// The signed attributes re-tagged as a SET: the signed bytes.
    signed_attributes: Vec<u8>,
    signature: Vec<u8>,
}

impl fmt::Debug for TimestampToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimestampToken")
            .field("gen_time", &self.gen_time)
            .finish_non_exhaustive()
    }
}

impl TimestampToken {
    /// Reads a whole DER `TimeStampResp` (RFC 3161, 2.4.2), as a bundle's
    /// `signedTimestamp` holds it (module doc).
    pub fn from_response_der(der: &[u8]) -> Result<TimestampToken, TimestampError> {
        let malformed = |_: DerError| TimestampError::Malformed;
        let mut outer = Reader::new(der);
        let mut response = Reader::new(outer.expect(SEQUENCE).map_err(malformed)?);
        outer.finish().map_err(malformed)?;
        status(response.expect(SEQUENCE).map_err(malformed)?)?;
        let content_info = response.expect(SEQUENCE).map_err(malformed)?;
        response.finish().map_err(malformed)?;

        let mut content_info = Reader::new(content_info);
        if content_info.expect(OID).map_err(malformed)? != ID_SIGNED_DATA {
            return Err(TimestampError::ContentType);
        }
        let mut wrapper = Reader::new(content_info.expect(CONTEXT_0).map_err(malformed)?);
        content_info.finish().map_err(malformed)?;
        let signed_data = wrapper.expect(SEQUENCE).map_err(malformed)?;
        wrapper.finish().map_err(malformed)?;

        let mut signed_data = Reader::new(signed_data);
        signed_data.expect(INTEGER).map_err(malformed)?; // version
        signed_data.expect(SET).map_err(malformed)?; // digestAlgorithms
        let mut encap = Reader::new(signed_data.expect(SEQUENCE).map_err(malformed)?);
        if encap.expect(OID).map_err(malformed)? != ID_CT_TST_INFO {
            return Err(TimestampError::ContentType);
        }
        let mut econtent = Reader::new(encap.expect(CONTEXT_0).map_err(malformed)?);
        encap.finish().map_err(malformed)?;
        let tst_info = econtent.expect(OCTET_STRING).map_err(malformed)?;
        econtent.finish().map_err(malformed)?;
        // Never parsed: the signer's chain comes from the caller only.
        signed_data.optional(CONTEXT_0).map_err(malformed)?; // certificates
        signed_data.optional(CONTEXT_1).map_err(malformed)?; // crls
        let mut signer_infos = Reader::new(signed_data.expect(SET).map_err(malformed)?);
        signed_data.finish().map_err(malformed)?;
        let mut signers = Vec::new();
        while !signer_infos.is_empty() {
            signers.push(signer_infos.expect(SEQUENCE).map_err(malformed)?);
        }
        let [signer] = signers[..] else {
            return Err(TimestampError::SignerCount);
        };
        let signer = signer_info(signer)?;
        let (gen_time, imprint) = tst(tst_info)?;
        Ok(TimestampToken {
            gen_time,
            imprint,
            tst_info: tst_info.to_vec(),
            message_digest: signer.message_digest,
            cert_hash: signer.cert_hash,
            signed_attributes: signer.signed_attributes,
            signature: signer.signature,
        })
    }

    /// genTime, Unix seconds.
    pub fn gen_time(&self) -> u64 {
        self.gen_time
    }

    /// The SHA-256 the token is over.
    pub fn message_imprint(&self) -> &[u8; 32] {
        &self.imprint
    }

    /// Whether the TSA whose leaf is `leaf` (DER), with `intermediates`
    /// and the anchor `root`, signed this token over `message` (module
    /// doc). Only the given certificates are path candidates.
    pub fn verify(
        &self,
        message: &[u8],
        leaf: &[u8],
        intermediates: &[&[u8]],
        root: &[u8],
    ) -> Result<(), TimestampError> {
        if Sha256::digest(message) != self.imprint {
            return Err(TimestampError::Imprint);
        }
        if Sha256::digest(leaf) != self.cert_hash {
            return Err(TimestampError::SigningCertificate);
        }
        let parsed =
            codesign::parse(leaf).map_err(|_| TimestampError::Chain(CertError::Malformed))?;
        let eku = codesign::find(&parsed.extensions, EXT_KEY_USAGE)
            .ok_or(TimestampError::NotTimestamping)?;
        if !eku.critical || !only_time_stamping(eku.value) {
            return Err(TimestampError::NotTimestamping);
        }
        match der::key_usage(leaf) {
            Ok(None) => {}
            Ok(Some(usage)) if usage.signs_content() => {}
            Ok(Some(_)) => return Err(TimestampError::KeyUsage),
            Err(_) => return Err(TimestampError::Chain(CertError::Malformed)),
        }
        codesign::verify_chain(
            leaf,
            intermediates,
            &[root],
            self.gen_time,
            ID_KP_TIME_STAMPING,
        )
        .map_err(|e| match e {
            CertError::NotCodeSigning => TimestampError::NotTimestamping,
            other => TimestampError::Chain(other),
        })?;
        if Sha256::digest(&self.tst_info) != self.message_digest {
            return Err(TimestampError::MessageDigest);
        }
        let algorithms: Vec<&dyn SignatureVerificationAlgorithm> =
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all
                .iter()
                .copied()
                .filter(|a| {
                    a.signature_alg_id() == alg_id::ECDSA_SHA256
                        && (a.public_key_alg_id() == alg_id::ECDSA_P256
                            || a.public_key_alg_id() == alg_id::ECDSA_P384)
                })
                .collect();
        let ok = signature::verified(
            parsed.spki,
            alg_id::ECDSA_SHA256.as_ref(),
            &self.signed_attributes,
            &self.signature,
            &algorithms,
        );
        ok.then_some(()).ok_or(TimestampError::Signature)
    }
}

/// `PKIStatusInfo`: granted (0) or granted with modifications (1);
/// `statusString` and `failInfo` are read for form only.
fn status(info: &[u8]) -> Result<(), TimestampError> {
    let malformed = |_: DerError| TimestampError::Malformed;
    let mut info = Reader::new(info);
    let value = info.expect(INTEGER).map_err(malformed)?;
    info.optional(SEQUENCE).map_err(malformed)?; // statusString
    info.optional(der::BIT_STRING).map_err(malformed)?; // failInfo
    info.finish().map_err(malformed)?;
    match value {
        [0] | [1] => Ok(()),
        _ => Err(TimestampError::Status),
    }
}

/// Whether an AlgorithmIdentifier's content is `oid` with absent or NULL
/// parameters.
fn is_algorithm(identifier: &[u8], oid: &[u8]) -> bool {
    let mut reader = Reader::new(identifier);
    if reader.expect(OID).ok() != Some(oid) {
        return false;
    }
    match reader.optional(NULL) {
        Ok(None) => reader.is_empty(),
        Ok(Some(params)) => params.is_empty() && reader.is_empty(),
        Err(_) => false,
    }
}

/// What the one SignerInfo holds.
struct Signer {
    message_digest: [u8; 32],
    cert_hash: [u8; 32],
    signed_attributes: Vec<u8>,
    signature: Vec<u8>,
}

fn signer_info(info: &[u8]) -> Result<Signer, TimestampError> {
    let malformed = |_: DerError| TimestampError::Malformed;
    let mut info = Reader::new(info);
    info.expect(INTEGER).map_err(malformed)?; // version
    // sid: issuerAndSerialNumber or subjectKeyIdentifier, for form only;
    // signingCertificateV2 binds the signer.
    match info.peek() {
        Some(SEQUENCE | CONTEXT_0_PRIMITIVE) => {
            info.read().map_err(malformed)?;
        }
        _ => return Err(TimestampError::Malformed),
    }
    if !is_algorithm(info.expect(SEQUENCE).map_err(malformed)?, SHA256) {
        return Err(TimestampError::Algorithm);
    }
    if info.peek() != Some(CONTEXT_0) {
        return Err(TimestampError::SignedAttributes);
    }
    let whole = info.expect_tlv(CONTEXT_0).map_err(malformed)?;
    let attributes = Reader::new(whole).expect(CONTEXT_0).map_err(malformed)?;
    let algorithm = info.expect(SEQUENCE).map_err(malformed)?;
    if algorithm != alg_id::ECDSA_SHA256.as_ref() {
        return Err(TimestampError::Algorithm);
    }
    let signature = info.expect(OCTET_STRING).map_err(malformed)?;
    info.optional(CONTEXT_1).map_err(malformed)?; // unsignedAttrs
    info.finish().map_err(malformed)?;

    let (message_digest, cert_hash) = attributes_of(attributes)?;
    // RFC 5652, 5.4: the signature is over the attributes' DER with the
    // SET tag in place of the `[0]`.
    let mut signed_attributes = whole.to_vec();
    if let Some(tag) = signed_attributes.first_mut() {
        *tag = SET;
    }
    Ok(Signer {
        message_digest,
        cert_hash,
        signed_attributes,
        signature: signature.to_vec(),
    })
}

/// The messageDigest and the first ESSCertIDv2 hash of the signed
/// attributes; contentType must name a TSTInfo.
fn attributes_of(attributes: &[u8]) -> Result<([u8; 32], [u8; 32]), TimestampError> {
    let bad = |_: DerError| TimestampError::SignedAttributes;
    let mut attributes = Reader::new(attributes);
    let mut content_type = None;
    let mut message_digest = None;
    let mut certificate = None;
    while !attributes.is_empty() {
        let mut attribute = Reader::new(attributes.expect(SEQUENCE).map_err(bad)?);
        let oid = attribute.expect(OID).map_err(bad)?;
        let values = attribute.expect(SET).map_err(bad)?;
        attribute.finish().map_err(bad)?;
        let slot = if oid == CONTENT_TYPE {
            &mut content_type
        } else if oid == MESSAGE_DIGEST {
            &mut message_digest
        } else if oid == SIGNING_CERTIFICATE_V2 {
            &mut certificate
        } else {
            continue;
        };
        if slot.is_some() {
            return Err(if oid == SIGNING_CERTIFICATE_V2 {
                TimestampError::SigningCertificate
            } else {
                TimestampError::SignedAttributes
            });
        }
        *slot = Some(values);
    }
    let one = |values: &[u8], tag: u8| -> Result<Vec<u8>, DerError> {
        let mut reader = Reader::new(values);
        let value = reader.expect(tag)?;
        reader.finish()?;
        Ok(value.to_vec())
    };
    let content_type = content_type.ok_or(TimestampError::SignedAttributes)?;
    if one(content_type, OID).map_err(bad)? != ID_CT_TST_INFO {
        return Err(TimestampError::ContentType);
    }
    let message_digest = message_digest.ok_or(TimestampError::SignedAttributes)?;
    let message_digest: [u8; 32] = one(message_digest, OCTET_STRING)
        .map_err(bad)?
        .try_into()
        .map_err(|_| TimestampError::SignedAttributes)?;
    let certificate = certificate.ok_or(TimestampError::SigningCertificate)?;
    let cert_hash = ess_cert_id_v2(certificate).ok_or(TimestampError::SigningCertificate)?;
    Ok((message_digest, cert_hash))
}

/// The certHash of the first ESSCertIDv2 of a signingCertificateV2 value
/// set (RFC 5035, 3), whose hashAlgorithm is absent (SHA-256 by default)
/// or SHA-256. `None` for any other shape.
fn ess_cert_id_v2(values: &[u8]) -> Option<[u8; 32]> {
    let mut values = Reader::new(values);
    let mut signing_certificate = Reader::new(values.expect(SEQUENCE).ok()?);
    values.finish().ok()?;
    let mut certs = Reader::new(signing_certificate.expect(SEQUENCE).ok()?);
    signing_certificate.optional(SEQUENCE).ok()?; // policies
    signing_certificate.finish().ok()?;
    let mut first = Reader::new(certs.expect(SEQUENCE).ok()?);
    while !certs.is_empty() {
        certs.expect(SEQUENCE).ok()?; // other certificates, for form
    }
    if first.peek() == Some(SEQUENCE) && !is_algorithm(first.expect(SEQUENCE).ok()?, SHA256) {
        return None;
    }
    let hash = first.expect(OCTET_STRING).ok()?.try_into().ok()?;
    first.optional(SEQUENCE).ok()?; // issuerSerial
    first.finish().ok()?;
    Some(hash)
}

/// genTime and the imprint of a TSTInfo (RFC 3161, 2.4.2).
fn tst(der: &[u8]) -> Result<(u64, [u8; 32]), TimestampError> {
    let malformed = |_: DerError| TimestampError::Malformed;
    let mut outer = Reader::new(der);
    let mut tst = Reader::new(outer.expect(SEQUENCE).map_err(malformed)?);
    outer.finish().map_err(malformed)?;
    if tst.expect(INTEGER).map_err(malformed)? != [1] {
        return Err(TimestampError::Malformed);
    }
    tst.expect(OID).map_err(malformed)?; // policy
    let mut imprint = Reader::new(tst.expect(SEQUENCE).map_err(malformed)?);
    if !is_algorithm(imprint.expect(SEQUENCE).map_err(malformed)?, SHA256) {
        return Err(TimestampError::ImprintAlgorithm);
    }
    let hashed: [u8; 32] = imprint
        .expect(OCTET_STRING)
        .map_err(malformed)?
        .try_into()
        .map_err(|_| TimestampError::Malformed)?;
    imprint.finish().map_err(malformed)?;
    tst.expect(INTEGER).map_err(malformed)?; // serialNumber
    let (tag, value) = tst.read().map_err(malformed)?;
    if tag != GENERALIZED_TIME {
        return Err(TimestampError::Time);
    }
    let gen_time = der::time(tag, value).map_err(|_| TimestampError::Time)?;
    tst.optional(SEQUENCE).map_err(malformed)?; // accuracy
    tst.optional(BOOLEAN).map_err(malformed)?; // ordering
    tst.optional(INTEGER).map_err(malformed)?; // nonce
    tst.optional(CONTEXT_0).map_err(malformed)?; // tsa
    if let Some(extensions) = tst.optional(CONTEXT_1).map_err(malformed)? {
        let mut extensions = Reader::new(extensions);
        while !extensions.is_empty() {
            let mut extension = Reader::new(extensions.expect(SEQUENCE).map_err(malformed)?);
            extension.expect(OID).map_err(malformed)?;
            match extension.optional(BOOLEAN).map_err(malformed)? {
                None => {}
                Some([0xFF]) => return Err(TimestampError::CriticalExtension),
                Some(_) => return Err(TimestampError::Malformed),
            }
            extension.expect(OCTET_STRING).map_err(malformed)?;
            extension.finish().map_err(malformed)?;
        }
    }
    tst.finish().map_err(malformed)?;
    Ok((gen_time, hashed))
}

/// Whether an EKU extension value is a SEQUENCE of exactly
/// `id-kp-timeStamping`.
fn only_time_stamping(value: &[u8]) -> bool {
    let mut outer = Reader::new(value);
    let Ok(purposes) = outer.expect(SEQUENCE) else {
        return false;
    };
    let mut purposes = Reader::new(purposes);
    outer.is_empty()
        && purposes.expect(OID).ok() == Some(ID_KP_TIME_STAMPING)
        && purposes.is_empty()
}

#[cfg(test)]
mod tests {
    use super::testing::{
        self, Attributes, LEAF_FROM, LEAF_TO, MESSAGE, T, TokenSpec, TsaLeafSpec, algorithm,
        anchor, ca_true, eku, key_usage,
    };
    use super::*;

    fn parse(spec: &TokenSpec) -> Result<TimestampToken, TimestampError> {
        TimestampToken::from_response_der(&spec.build())
    }

    /// Parses and verifies `spec` over `MESSAGE` with its own leaf.
    fn check(spec: &TokenSpec) -> Result<(), TimestampError> {
        parse(spec)?.verify(MESSAGE, &spec.leaf, &[], &anchor())
    }

    #[test]
    fn good_token_verifies() {
        let spec = TokenSpec::good();
        let token = parse(&spec).expect("parses");
        assert_eq!(token.gen_time(), T);
        assert_eq!(token.message_imprint(), &Sha256::digest(MESSAGE));
        assert_eq!(check(&spec), Ok(()));
        assert_eq!(
            format!("{token:?}"),
            format!("TimestampToken {{ gen_time: {T}, .. }}")
        );
    }

    #[test]
    fn token_structure() {
        let cases: Vec<(&str, TokenSpec, TimestampError)> = vec![
            (
                "status 2",
                TokenSpec {
                    status: vec![2],
                    ..TokenSpec::good()
                },
                TimestampError::Status,
            ),
            (
                "no signer",
                TokenSpec {
                    signer_infos: 0,
                    ..TokenSpec::good()
                },
                TimestampError::SignerCount,
            ),
            (
                "two signers",
                TokenSpec {
                    signer_infos: 2,
                    ..TokenSpec::good()
                },
                TimestampError::SignerCount,
            ),
            (
                "digest SHA-1",
                TokenSpec {
                    digest_algorithm: algorithm(testing::SHA1, false),
                    ..TokenSpec::good()
                },
                TimestampError::Algorithm,
            ),
            (
                "digest SHA-512",
                TokenSpec {
                    digest_algorithm: algorithm(testing::SHA512, true),
                    ..TokenSpec::good()
                },
                TimestampError::Algorithm,
            ),
            (
                "digest SHA-256 with other parameters",
                TokenSpec {
                    digest_algorithm: der::encode(
                        SEQUENCE,
                        &[der::encode(OID, SHA256), der::encode(SEQUENCE, &[])].concat(),
                    ),
                    ..TokenSpec::good()
                },
                TimestampError::Algorithm,
            ),
            (
                "ecdsa-with-SHA384",
                TokenSpec {
                    signature_algorithm: algorithm(testing::ECDSA_WITH_SHA384, false),
                    ..TokenSpec::good()
                },
                TimestampError::Algorithm,
            ),
            (
                "RSA",
                TokenSpec {
                    signature_algorithm: algorithm(testing::RSA_WITH_SHA256, true),
                    ..TokenSpec::good()
                },
                TimestampError::Algorithm,
            ),
            (
                "ecdsa-with-SHA256 with NULL",
                TokenSpec {
                    signature_algorithm: algorithm(testing::ECDSA_WITH_SHA256, true),
                    ..TokenSpec::good()
                },
                TimestampError::Algorithm,
            ),
            (
                "no signed attributes",
                TokenSpec {
                    attributes: Attributes::Absent,
                    ..TokenSpec::good()
                },
                TimestampError::SignedAttributes,
            ),
            (
                "messageDigest twice",
                TokenSpec {
                    attributes: Attributes::Edited(|list, _, _| {
                        let digest = list[2].clone();
                        list.push(digest);
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::SignedAttributes,
            ),
            (
                "contentType twice",
                TokenSpec {
                    attributes: Attributes::Edited(|list, _, _| {
                        let content_type = list[0].clone();
                        list.insert(1, content_type);
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::SignedAttributes,
            ),
            (
                "no messageDigest",
                TokenSpec {
                    attributes: Attributes::Edited(|list, _, _| {
                        list.remove(2);
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::SignedAttributes,
            ),
            (
                "no contentType",
                TokenSpec {
                    attributes: Attributes::Edited(|list, _, _| {
                        list.remove(0);
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::SignedAttributes,
            ),
            (
                "two messageDigest values",
                TokenSpec {
                    attributes: Attributes::Edited(|list, econtent, _| {
                        let digest = der::encode(OCTET_STRING, &Sha256::digest(econtent));
                        list[2] = testing::attribute(MESSAGE_DIGEST, &[digest.clone(), digest]);
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::SignedAttributes,
            ),
            (
                "eContentType id-data",
                TokenSpec {
                    e_content_type: testing::ID_DATA,
                    ..TokenSpec::good()
                },
                TimestampError::ContentType,
            ),
            (
                "contentType attribute id-data",
                TokenSpec {
                    attributes: Attributes::Edited(|list, _, _| {
                        list[0] =
                            testing::attribute(CONTENT_TYPE, &[der::encode(OID, testing::ID_DATA)]);
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::ContentType,
            ),
            (
                "ContentInfo id-data",
                TokenSpec {
                    content_type: testing::ID_DATA,
                    ..TokenSpec::good()
                },
                TimestampError::ContentType,
            ),
            (
                "no signingCertificateV2",
                TokenSpec {
                    attributes: Attributes::Edited(|list, _, _| {
                        list.remove(3);
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::SigningCertificate,
            ),
            (
                "only v1 signingCertificate",
                TokenSpec {
                    attributes: Attributes::Edited(|list, _, leaf| {
                        list[3] = testing::signing_certificate_v1(&Sha256::digest(leaf));
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::SigningCertificate,
            ),
            (
                "signingCertificateV2 over SHA-1",
                TokenSpec {
                    attributes: Attributes::Edited(|list, _, leaf| {
                        list[3] = testing::signing_certificate_v2(
                            Some(algorithm(testing::SHA1, true)),
                            &Sha256::digest(leaf),
                        );
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::SigningCertificate,
            ),
            (
                "signingCertificateV2 twice",
                TokenSpec {
                    attributes: Attributes::Edited(|list, _, _| {
                        let certificate = list[3].clone();
                        list.push(certificate);
                    }),
                    ..TokenSpec::good()
                },
                TimestampError::SigningCertificate,
            ),
            (
                "imprint SHA-384",
                TokenSpec {
                    tst: {
                        let mut tst = testing::TstSpec::over(MESSAGE, T);
                        tst.imprint_algorithm = algorithm(testing::SHA384, true);
                        tst
                    },
                    ..TokenSpec::good()
                },
                TimestampError::ImprintAlgorithm,
            ),
            (
                "imprint of 31 bytes",
                TokenSpec {
                    tst: {
                        let mut tst = testing::TstSpec::over(MESSAGE, T);
                        tst.imprint.pop();
                        tst
                    },
                    ..TokenSpec::good()
                },
                TimestampError::Malformed,
            ),
            (
                "TSTInfo version 2",
                TokenSpec {
                    tst: testing::TstSpec {
                        version: 2,
                        ..testing::TstSpec::over(MESSAGE, T)
                    },
                    ..TokenSpec::good()
                },
                TimestampError::Malformed,
            ),
            (
                "trailing byte",
                TokenSpec {
                    trailing: vec![0],
                    ..TokenSpec::good()
                },
                TimestampError::Malformed,
            ),
            (
                "constructed OCTET STRING",
                TokenSpec {
                    constructed_econtent: true,
                    ..TokenSpec::good()
                },
                TimestampError::Malformed,
            ),
        ];
        for (name, spec, error) in cases {
            assert_eq!(parse(&spec).err(), Some(error), "{name}");
        }
        // Status 1, granted with modifications, passes; so does a digest
        // with NULL parameters and a token without `certificates`.
        assert_eq!(
            check(&TokenSpec {
                status: vec![1],
                ..TokenSpec::good()
            }),
            Ok(())
        );
        assert_eq!(
            check(&TokenSpec {
                digest_algorithm: algorithm(SHA256, true),
                ..TokenSpec::good()
            }),
            Ok(())
        );
        assert_eq!(
            check(&TokenSpec {
                certificates: None,
                ..TokenSpec::good()
            }),
            Ok(())
        );
        // signingCertificateV2 with its hash algorithm spelled out.
        assert_eq!(
            check(&TokenSpec {
                attributes: Attributes::Edited(|list, _, leaf| {
                    list[3] = testing::signing_certificate_v2(
                        Some(algorithm(SHA256, false)),
                        &Sha256::digest(leaf),
                    );
                }),
                ..TokenSpec::good()
            }),
            Ok(())
        );
        // A non-minimal outer length.
        let good = TokenSpec::good().build();
        assert_eq!(good[1], 0x82, "a two-byte length");
        let mut long = vec![0x30, 0x83, 0x00];
        long.extend_from_slice(&good[2..]);
        assert_eq!(
            TimestampToken::from_response_der(&long).err(),
            Some(TimestampError::Malformed)
        );
        // Every truncation is refused.
        for n in 0..good.len() {
            assert!(
                TimestampToken::from_response_der(&good[..n]).is_err(),
                "{n}"
            );
        }
    }

    #[test]
    fn verify_rules() {
        // A wrong messageDigest.
        let spec = TokenSpec {
            attributes: Attributes::Edited(|list, _, _| {
                list[2] =
                    testing::attribute(MESSAGE_DIGEST, &[der::encode(OCTET_STRING, &[7; 32])]);
            }),
            ..TokenSpec::good()
        };
        assert_eq!(check(&spec), Err(TimestampError::MessageDigest));
        // One flipped signature byte.
        let spec = TokenSpec {
            corrupt: true,
            ..TokenSpec::good()
        };
        assert_eq!(check(&spec), Err(TimestampError::Signature));
        // ESSCertIDv2 over another certificate.
        let spec = TokenSpec::good();
        let token = parse(&spec).expect("parses");
        let other = TsaLeafSpec {
            serial: 10,
            ..TsaLeafSpec::good()
        }
        .build();
        assert_eq!(
            token.verify(MESSAGE, &other, &[], &anchor()),
            Err(TimestampError::SigningCertificate)
        );
        // The imprint is over the message, not anything near it.
        assert_eq!(
            token.verify(b"another message", &spec.leaf, &[], &anchor()),
            Err(TimestampError::Imprint)
        );
        // Another anchor.
        let root = testing::root();
        assert_eq!(
            token.verify(MESSAGE, &spec.leaf, &[], &root),
            Err(TimestampError::Chain(CertError::UnknownIssuer))
        );
    }

    #[test]
    fn gen_time_forms() {
        for text in [
            "20260921141320.5Z",
            "20260921141320+0000",
            "20260921141320",
            "19691231235959Z",
            "20260921141360Z",
            "20260230120000Z",
            "202609211413Z",
        ] {
            let mut spec = TokenSpec::good();
            spec.tst.gen_time_text(text);
            assert_eq!(parse(&spec).err(), Some(TimestampError::Time), "{text}");
        }
        // A UTCTime is not a genTime.
        let mut spec = TokenSpec::good();
        spec.tst.gen_time = der::encode(der::UTC_TIME, b"260921141320Z");
        assert_eq!(parse(&spec).err(), Some(TimestampError::Time));
        let mut spec = TokenSpec::good();
        spec.tst.gen_time_text("20260921141320Z");
        assert_eq!(parse(&spec).map(|t| t.gen_time()), Ok(T));
    }

    #[test]
    fn tstinfo_extensions() {
        let extension = |critical: Option<&[u8]>| {
            let mut body =
                der::encode(OID, &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x09]);
            if let Some(value) = critical {
                body.extend(der::encode(BOOLEAN, value));
            }
            body.extend(der::encode(OCTET_STRING, &[0x05, 0x00]));
            der::encode(CONTEXT_1, &der::encode(SEQUENCE, &body))
        };
        let with = |field| {
            let mut spec = TokenSpec::good();
            spec.tst.extensions = Some(field);
            spec
        };
        assert_eq!(
            parse(&with(extension(Some(&[0xFF])))).err(),
            Some(TimestampError::CriticalExtension)
        );
        assert_eq!(check(&with(extension(None))), Ok(()));
        // An explicit FALSE is not DER (DEFAULT FALSE is left out).
        assert_eq!(
            parse(&with(extension(Some(&[0x00])))).err(),
            Some(TimestampError::Malformed)
        );
    }

    #[test]
    fn tsa_leaf_rules() {
        let with_leaf = |leaf: TsaLeafSpec| TokenSpec {
            leaf: leaf.build(),
            ..TokenSpec::good()
        };
        let extensions = |extensions| TsaLeafSpec {
            extensions,
            ..TsaLeafSpec::good()
        };
        let cases = [
            (
                "EKU not critical",
                extensions(vec![key_usage(0x80), eku(false, &[ID_KP_TIME_STAMPING])]),
                TimestampError::NotTimestamping,
            ),
            (
                "EKU timeStamping and codeSigning",
                extensions(vec![
                    key_usage(0x80),
                    eku(true, &[ID_KP_TIME_STAMPING, testing::CODE_SIGNING]),
                ]),
                TimestampError::NotTimestamping,
            ),
            (
                "EKU codeSigning",
                extensions(vec![key_usage(0x80), eku(true, &[testing::CODE_SIGNING])]),
                TimestampError::NotTimestamping,
            ),
            (
                "no EKU",
                extensions(vec![key_usage(0x80)]),
                TimestampError::NotTimestamping,
            ),
            (
                "keyEncipherment only",
                extensions(vec![key_usage(0x20), eku(true, &[ID_KP_TIME_STAMPING])]),
                TimestampError::KeyUsage,
            ),
            (
                "a CA",
                extensions(vec![
                    key_usage(0x80),
                    eku(true, &[ID_KP_TIME_STAMPING]),
                    ca_true(),
                ]),
                TimestampError::Chain(CertError::IsCa),
            ),
            (
                "expired at genTime",
                TsaLeafSpec {
                    not_after: T - 1,
                    ..TsaLeafSpec::good()
                },
                TimestampError::Chain(CertError::OutsideValidity),
            ),
        ];
        for (name, leaf, error) in cases {
            assert_eq!(check(&with_leaf(leaf)), Err(error), "{name}");
        }
        // nonRepudiation alone, and no keyUsage at all, pass.
        assert_eq!(
            check(&with_leaf(extensions(vec![
                key_usage(0x40),
                eku(true, &[ID_KP_TIME_STAMPING])
            ]))),
            Ok(())
        );
        assert_eq!(
            check(&with_leaf(extensions(vec![eku(
                true,
                &[ID_KP_TIME_STAMPING]
            )]))),
            Ok(())
        );
    }

    /// webpki's validity is inclusive at both ends, at genTime.
    #[test]
    fn tsa_leaf_validity_bounds() {
        for (at, ok) in [
            (LEAF_FROM - 1, false),
            (LEAF_FROM, true),
            (LEAF_TO, true),
            (LEAF_TO + 1, false),
        ] {
            let spec = TokenSpec::over(MESSAGE, at);
            let result = check(&spec);
            if ok {
                assert_eq!(result, Ok(()), "{at}");
            } else {
                assert_eq!(
                    result,
                    Err(TimestampError::Chain(CertError::OutsideValidity)),
                    "{at}"
                );
            }
        }
    }

    /// The TSA's anchor must hold at genTime too, not only the leaf: the
    /// anchor (the test intermediate) is valid from 2026-01-01 to
    /// 2126-01-01, and each leaf here is valid around genTime (review of
    /// PR #132, run 1).
    #[test]
    fn anchor_validity_at_gen_time() {
        for (at, leaf_from, leaf_to) in [
            // genTime 2025-07-01 inside a leaf from 2025-06-01.
            (1_751_328_000, 1_748_736_000, LEAF_TO),
            // genTime one second after the anchor's notAfter.
            (4_922_899_201, LEAF_FROM, 4_922_899_300),
        ] {
            let leaf = TsaLeafSpec {
                not_before: leaf_from,
                not_after: leaf_to,
                ..TsaLeafSpec::good()
            }
            .build();
            let spec = TokenSpec {
                leaf: leaf.clone(),
                ..TokenSpec::over(MESSAGE, at)
            };
            assert_eq!(
                parse(&spec)
                    .expect("parses")
                    .verify(MESSAGE, &leaf, &[], &anchor()),
                Err(TimestampError::Chain(CertError::OutsideValidity)),
                "{at}"
            );
        }
    }

    #[test]
    fn errors_have_fixed_text() {
        assert_eq!(
            TimestampError::Chain(CertError::IsCa).to_string(),
            "the authority's certificate does not verify: the certificate is a CA certificate"
        );
        assert_eq!(
            TimestampError::Imprint.to_string(),
            "the timestamp is not over the signature"
        );
    }
}
