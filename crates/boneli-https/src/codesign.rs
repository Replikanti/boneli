//! Code-signing certificate chains and their embedded SCTs, for keyless
//! image signatures (ADR-029, S2): a Fulcio leaf is verified by webpki
//! for `id-kp-codeSigning` at a time the caller chooses (Rekor's
//! integrated time, never the wall clock: a Fulcio leaf lives 10
//! minutes), and its embedded Signed Certificate Timestamps are verified
//! by RFC 6962, section 3.2.
//!
//! webpki decides the chain: the signatures, the validity at `at_secs`
//! (inclusive at both ends) of the leaf and the intermediates, while the
//! trust anchor's own validity, which webpki never reads, is checked by
//! `verify_chain` (ADR-038, D3), the basic constraints (the leaf must not be
//! a CA), and the EKU, which `KeyUsage::required` demands of the leaf and
//! of every intermediate on the path, as Sigstore's public-good
//! intermediate carries it. Intermediates come only from the caller, so a
//! chain an attacker sends along is never read; there is no CRL, because
//! Fulcio publishes none and its leaves expire in minutes.
//!
//! The readers here decide too, so they are strict (`der`): the SANs and
//! extensions of a leaf webpki accepted, a second extension with the same
//! OID refuses the leaf, and so does an IA5String SAN that is not ASCII.
//! The SCT check rebuilds the precertificate's TBS, the leaf's TBS with
//! the SCT list extension removed and re-encoded; a mistake there can
//! only refuse a valid SCT, never accept a forged one, because the result
//! feeds a signature check (the real leaves are known answers in
//! `tests/codesign.rs`).

use std::fmt;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, UnixTime};

use crate::der::{
    self, BIT_STRING, BOOLEAN, CONTEXT_0, CONTEXT_1_PRIMITIVE, CONTEXT_2_PRIMITIVE, CONTEXT_3,
    DerError, INTEGER, OCTET_STRING, OID, Reader, SEQUENCE,
};
use crate::keys::{KeyKind, PublicKey};
use crate::sha256::Sha256;

#[cfg(test)]
pub(crate) mod testing;

/// id-kp-codeSigning, 1.3.6.1.5.5.7.3.3.
const ID_KP_CODE_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
/// id-ce-subjectAltName, 2.5.29.17.
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];
/// The embedded SCT list of RFC 6962, 3.3: 1.3.6.1.4.1.11129.2.4.2.
const SCT_LIST: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02];

/// GeneralName tags (RFC 5280, 4.2.1.6), implicitly tagged IA5Strings.
const RFC822_NAME: u8 = 0x81;
const DNS_NAME: u8 = 0x82;
const URI: u8 = 0x86;

/// RFC 6962's `HashAlgorithm.sha256` and `SignatureAlgorithm`s.
const TLS_SHA256: u8 = 4;
const TLS_RSA: u8 = 1;
const TLS_ECDSA: u8 = 3;

/// Why a code-signing certificate was refused. Every variant is a fixed
/// rule, so no message carries certificate text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertError {
    /// The leaf is not a certificate webpki or the strict reader can read.
    Malformed,
    /// A trust root is not a certificate webpki can use as an anchor.
    BadRoot,
    /// No path from the leaf through the given intermediates to a root.
    UnknownIssuer,
    /// The leaf, or an intermediate on the path, lacks the Code Signing
    /// EKU.
    NotCodeSigning,
    /// The leaf is a CA certificate.
    IsCa,
    /// The leaf, or a certificate on the path, is not valid at the time.
    OutsideValidity,
    /// The chain fails for another reason, a bad signature among them.
    Invalid,
    /// An `rfc822Name`, `dNSName` or `uniformResourceIdentifier` SAN holds
    /// a byte that is not ASCII.
    NonAsciiSan,
    /// The leaf's public key is of no [`KeyKind`].
    UnsupportedKey,
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CertError::Malformed => "the certificate is malformed",
            CertError::BadRoot => "a trust root is not a usable CA certificate",
            CertError::UnknownIssuer => "the certificate does not chain to a trust root",
            CertError::NotCodeSigning => "the certificate chain is not valid for code signing",
            CertError::IsCa => "the certificate is a CA certificate",
            CertError::OutsideValidity => "the certificate is not valid at the given time",
            CertError::Invalid => "the certificate chain does not verify",
            CertError::NonAsciiSan => "a subject alternative name is not ASCII",
            CertError::UnsupportedKey => "the certificate's public key is not supported",
        })
    }
}

impl std::error::Error for CertError {}

/// Why no embedded SCT was accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SctError {
    /// The leaf has no SCT list extension.
    Missing,
    /// The SCT list, or the leaf's TBS, cannot be read.
    Malformed,
    /// No v1 SCT from a listed log, inside that log's window, verifies.
    NoneVerified,
}

impl fmt::Display for SctError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SctError::Missing => "the certificate carries no embedded SCT list",
            SctError::Malformed => "the embedded SCT list is malformed",
            SctError::NoneVerified => "no embedded SCT from a trusted CT log verifies",
        })
    }
}

impl std::error::Error for SctError {}

/// A subject alternative name of a code-signing leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum San {
    /// An `rfc822Name`.
    Email(String),
    /// A `uniformResourceIdentifier`.
    Uri(String),
    /// Any other name type (a `dNSName`, an `otherName`, ...).
    Other,
}

/// A certificate transparency log an SCT may come from: its key and the
/// window, in milliseconds since the Unix epoch and inclusive at both
/// ends, in which its timestamps are accepted. `valid_to_ms` `None` is a
/// log without an end.
#[derive(Clone, Debug)]
pub struct CtLog {
    /// The log's key; its [`PublicKey::key_id`] is the log ID.
    pub key: PublicKey,
    /// The first accepted timestamp.
    pub valid_from_ms: u64,
    /// The last accepted timestamp, if the log has an end.
    pub valid_to_ms: Option<u64>,
}

/// A leaf that webpki verified for code signing, with what the identity
/// checks read from it.
///
/// `Debug` shows the validity, the key kind and the number of SANs, never
/// their text.
#[derive(Clone)]
pub struct CodeSigningCert {
    der: Vec<u8>,
    issuer_spki: Vec<u8>,
    sans: Vec<San>,
    extensions: Vec<(Vec<u8>, Vec<u8>)>,
    public_key: PublicKey,
    not_before: u64,
    not_after: u64,
}

/// Verifies `leaf` (DER) for code signing at `at_secs` (Unix seconds),
/// through `intermediates` to one of `roots` (each DER). Only the given
/// intermediates are path candidates. See the module doc for what webpki
/// checks; on top, the leaf must be readable by the strict reader and
/// carry a public key of a [`KeyKind`].
pub fn verify_code_signing(
    leaf: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    at_secs: u64,
) -> Result<CodeSigningCert, CertError> {
    let issuer_spki = verify_chain(leaf, intermediates, roots, at_secs, ID_KP_CODE_SIGNING)?;
    let parsed = parse(leaf).map_err(|_| CertError::Malformed)?;
    let sans = match find(&parsed.extensions, SUBJECT_ALT_NAME) {
        Some(extension) => sans(extension.value)?,
        None => Vec::new(),
    };
    let public_key =
        PublicKey::from_spki_der(parsed.spki).map_err(|_| CertError::UnsupportedKey)?;
    Ok(CodeSigningCert {
        der: leaf.to_vec(),
        issuer_spki,
        sans,
        extensions: parsed
            .extensions
            .iter()
            .map(|e| (e.oid.to_vec(), e.value.to_vec()))
            .collect(),
        public_key,
        not_before: parsed.not_before,
        not_after: parsed.not_after,
    })
}

/// Verifies `leaf` through `intermediates` to one of `roots` at `at_secs`
/// for the extended key usage `eku`, which webpki demands of the leaf and
/// of every intermediate on the path (module doc): the one webpki call of
/// code-signing chains and of timestamp authorities (`timestamp`). Gives
/// the SubjectPublicKeyInfo of the leaf's issuer on the verified path.
///
/// webpki checks the validity of the certificates on the path only, never
/// of the trust anchor (a `TrustAnchor` carries none), so the root that
/// ends a path must also be valid at `at_secs`, inclusive at both ends as
/// webpki's own check (ADR-038, D3). The check runs as webpki's path
/// callback, so a path to a root outside its validity is not taken and
/// path building goes on to the other roots. A root the strict reader
/// cannot read is refused as `BadRoot`, as one webpki cannot use.
pub(crate) fn verify_chain(
    leaf: &[u8],
    intermediates: &[&[u8]],
    roots: &[&[u8]],
    at_secs: u64,
    eku: &'static [u8],
) -> Result<Vec<u8>, CertError> {
    let validity = roots
        .iter()
        .map(|root| {
            parse(root)
                .map(|p| (p.not_before, p.not_after))
                .map_err(|_| CertError::BadRoot)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let roots: Vec<CertificateDer<'_>> = roots.iter().map(|r| CertificateDer::from(*r)).collect();
    let anchors = roots
        .iter()
        .map(|root| webpki::anchor_from_trusted_cert(root).map_err(|_| CertError::BadRoot))
        .collect::<Result<Vec<_>, _>>()?;
    let time = UnixTime::since_unix_epoch(Duration::from_secs(at_secs));
    let anchor_valid = |path: &webpki::VerifiedPath<'_>| -> Result<(), webpki::Error> {
        let index = anchors
            .iter()
            .position(|anchor| std::ptr::eq(anchor, path.anchor()))
            .ok_or(webpki::Error::UnknownIssuer)?;
        let (not_before, not_after) = validity[index];
        if at_secs < not_before {
            return Err(webpki::Error::CertNotValidYet {
                time,
                not_before: UnixTime::since_unix_epoch(Duration::from_secs(not_before)),
            });
        }
        if at_secs > not_after {
            return Err(webpki::Error::CertExpired {
                time,
                not_after: UnixTime::since_unix_epoch(Duration::from_secs(not_after)),
            });
        }
        Ok(())
    };
    let intermediates: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|c| CertificateDer::from(*c))
        .collect();
    let leaf_der = CertificateDer::from(leaf);
    let cert = webpki::EndEntityCert::try_from(&leaf_der).map_err(|_| CertError::Malformed)?;
    let path = cert
        .verify_for_usage(
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
            &anchors,
            &intermediates,
            time,
            webpki::KeyUsage::required(eku),
            None,
            Some(&anchor_valid),
        )
        .map_err(chain_error)?;
    Ok(path.issuer_spki().as_ref().to_vec())
}

/// The fixed reason for a webpki chain error.
fn chain_error(error: webpki::Error) -> CertError {
    match error {
        webpki::Error::RequiredEkuNotFoundContext(_) | webpki::Error::EmptyEkuExtension => {
            CertError::NotCodeSigning
        }
        webpki::Error::CaUsedAsEndEntity => CertError::IsCa,
        webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
            CertError::OutsideValidity
        }
        webpki::Error::UnknownIssuer => CertError::UnknownIssuer,
        _ => CertError::Invalid,
    }
}

impl CodeSigningCert {
    /// The subject alternative names, in certificate order; empty when the
    /// leaf has no SAN extension.
    pub fn sans(&self) -> &[San] {
        &self.sans
    }

    /// The raw `extnValue` contents of the extension `oid` (the content
    /// octets of its OBJECT IDENTIFIER), or `None`. Each OID occurs at
    /// most once: a leaf with two was refused.
    pub fn extension(&self, oid: &[u8]) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(id, _)| id == oid)
            .map(|(_, value)| value.as_slice())
    }

    /// The leaf's public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// `notBefore`, Unix seconds.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// `notAfter`, Unix seconds.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// The timestamp, in milliseconds, of the first embedded SCT that
    /// verifies (RFC 6962, 3.2): a v1 SCT whose log ID is the key ID of
    /// one of `logs`, whose timestamp lies in that log's window, whose
    /// algorithm is SHA-256 with the log key's kind, and whose signature
    /// verifies over the precertificate entry built from this leaf's TBS
    /// without the SCT list and the SHA-256 of its issuer's key on the
    /// path webpki verified. SCTs of other versions are skipped.
    pub fn verify_embedded_sct(&self, logs: &[CtLog]) -> Result<u64, SctError> {
        let value = self.extension(SCT_LIST).ok_or(SctError::Missing)?;
        let scts = sct_list(value).ok_or(SctError::Malformed)?;
        let tbs = precert_tbs(&self.der).map_err(|_| SctError::Malformed)?;
        let issuer_key_hash = Sha256::digest(&self.issuer_spki);
        for sct in scts {
            let Some(sct) = sct else { continue };
            let signed = sct
                .signed_data(&issuer_key_hash, &tbs)
                .ok_or(SctError::Malformed)?;
            let verified = logs.iter().any(|log| {
                log.key.key_id() == sct.log_id
                    && log.valid_from_ms <= sct.timestamp
                    && log.valid_to_ms.is_none_or(|to| sct.timestamp <= to)
                    && algorithm_matches(log.key.kind(), sct.hash, sct.signature_algorithm)
                    && log.key.verify(&signed, sct.signature).is_ok()
            });
            if verified {
                return Ok(sct.timestamp);
            }
        }
        Err(SctError::NoneVerified)
    }
}

impl fmt::Debug for CodeSigningCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeSigningCert")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("key", &self.public_key.kind())
            .field("sans", &self.sans.len())
            .finish()
    }
}

/// Whether an SCT's `DigitallySigned` algorithm is the one the log's key
/// verifies with: SHA-256, and ECDSA for a P-256 key or RSA for an RSA
/// key (RFC 6962, 2.1.4). Other key kinds verify with another hash
/// (`PublicKey::verify`), so their SCTs never verify.
fn algorithm_matches(kind: KeyKind, hash: u8, signature: u8) -> bool {
    hash == TLS_SHA256
        && match kind {
            KeyKind::EcdsaP256 => signature == TLS_ECDSA,
            KeyKind::Rsa { .. } => signature == TLS_RSA,
            KeyKind::EcdsaP384 | KeyKind::Ed25519 => false,
        }
}

/// What the strict reader takes from a certificate.
pub(crate) struct Parsed<'a> {
    /// The SubjectPublicKeyInfo, whole.
    pub(crate) spki: &'a [u8],
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    /// In certificate order, no OID twice.
    pub(crate) extensions: Vec<Extension<'a>>,
}

/// One extension of a certificate the strict reader read.
pub(crate) struct Extension<'a> {
    /// The content octets of its OBJECT IDENTIFIER.
    pub(crate) oid: &'a [u8],
    /// Whether it is marked critical (a BOOLEAN TRUE, `0xFF`).
    pub(crate) critical: bool,
    /// The contents of `extnValue`.
    pub(crate) value: &'a [u8],
}

/// The TBSCertificate of a certificate, as content octets.
fn tbs_of(cert: &[u8]) -> Result<&[u8], DerError> {
    let mut outer = Reader::new(cert);
    let mut certificate = Reader::new(outer.expect(SEQUENCE)?);
    outer.finish()?;
    let tbs = certificate.expect(SEQUENCE)?;
    certificate.expect(SEQUENCE)?; // signatureAlgorithm
    certificate.expect(BIT_STRING)?; // signatureValue
    certificate.finish()?;
    Ok(tbs)
}

pub(crate) fn parse(cert: &[u8]) -> Result<Parsed<'_>, DerError> {
    let mut tbs = Reader::new(tbs_of(cert)?);
    tbs.optional(CONTEXT_0)?; // version
    tbs.expect(INTEGER)?; // serialNumber
    tbs.expect(SEQUENCE)?; // signature
    tbs.expect(SEQUENCE)?; // issuer
    let mut validity = Reader::new(tbs.expect(SEQUENCE)?);
    let (tag, value) = validity.read()?;
    let not_before = der::time(tag, value)?;
    let (tag, value) = validity.read()?;
    let not_after = der::time(tag, value)?;
    validity.finish()?;
    tbs.expect(SEQUENCE)?; // subject
    let spki = tbs.expect_tlv(SEQUENCE)?;
    tbs.optional(CONTEXT_1_PRIMITIVE)?; // issuerUniqueID
    tbs.optional(CONTEXT_2_PRIMITIVE)?; // subjectUniqueID
    let mut extensions = Vec::new();
    if let Some(wrapper) = tbs.optional(CONTEXT_3)? {
        let mut wrapper = Reader::new(wrapper);
        let mut list = Reader::new(wrapper.expect(SEQUENCE)?);
        wrapper.finish()?;
        while !list.is_empty() {
            let mut extension = Reader::new(list.expect(SEQUENCE)?);
            let oid = extension.expect(OID)?;
            let critical = extension.optional(BOOLEAN)? == Some(&[0xFF]);
            let value = extension.expect(OCTET_STRING)?;
            extension.finish()?;
            if find(&extensions, oid).is_some() {
                return Err(DerError("two extensions with one OID"));
            }
            extensions.push(Extension {
                oid,
                critical,
                value,
            });
        }
    }
    tbs.finish()?;
    Ok(Parsed {
        spki,
        not_before,
        not_after,
        extensions,
    })
}

pub(crate) fn find<'e, 'a>(
    extensions: &'e [Extension<'a>],
    oid: &[u8],
) -> Option<&'e Extension<'a>> {
    extensions.iter().find(|e| e.oid == oid)
}

/// `GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName`, as [`San`]s.
fn sans(value: &[u8]) -> Result<Vec<San>, CertError> {
    let malformed = |_| CertError::Malformed;
    let mut wrapper = Reader::new(value);
    let mut names = Reader::new(wrapper.expect(SEQUENCE).map_err(malformed)?);
    wrapper.finish().map_err(malformed)?;
    let mut sans = Vec::new();
    while !names.is_empty() {
        let (tag, name) = names.read().map_err(malformed)?;
        let text = || {
            if name.is_ascii() {
                String::from_utf8(name.to_vec()).map_err(|_| CertError::NonAsciiSan)
            } else {
                Err(CertError::NonAsciiSan)
            }
        };
        sans.push(match tag {
            RFC822_NAME => San::Email(text()?),
            URI => San::Uri(text()?),
            DNS_NAME => {
                text()?;
                San::Other
            }
            _ => San::Other,
        });
    }
    Ok(sans)
}

/// The precertificate's TBSCertificate, whole (RFC 6962, 3.2): `cert`'s
/// TBS with the SCT list extension removed, every other field and
/// extension byte for byte, the lengths re-encoded. When the SCT list was
/// the only extension, the `[3]` field goes too, as in Go's
/// `x509.RemoveSCTList`.
fn precert_tbs(cert: &[u8]) -> Result<Vec<u8>, DerError> {
    let mut fields = Reader::new(tbs_of(cert)?);
    let mut out = Vec::new();
    while !fields.is_empty() {
        let field = fields.read_tlv()?;
        if field.first() != Some(&CONTEXT_3) {
            out.extend_from_slice(field);
            continue;
        }
        let mut wrapper = Reader::new(Reader::new(field).expect(CONTEXT_3)?);
        let mut list = Reader::new(wrapper.expect(SEQUENCE)?);
        wrapper.finish()?;
        let mut kept = Vec::new();
        while !list.is_empty() {
            let extension = list.read_tlv()?;
            let mut inner = Reader::new(Reader::new(extension).expect(SEQUENCE)?);
            if inner.expect(OID)? != SCT_LIST {
                kept.extend_from_slice(extension);
            }
        }
        if !kept.is_empty() {
            out.extend(der::encode(CONTEXT_3, &der::encode(SEQUENCE, &kept)));
        }
    }
    Ok(der::encode(SEQUENCE, &out))
}

/// One SCT of a list (RFC 6962, 3.2).
struct Sct<'a> {
    log_id: [u8; 32],
    timestamp: u64,
    extensions: &'a [u8],
    hash: u8,
    signature_algorithm: u8,
    signature: &'a [u8],
}

impl Sct<'_> {
    /// The `digitally-signed` struct of a precert entry: version v1,
    /// `certificate_timestamp`, the timestamp, `precert_entry`, the issuer
    /// key hash, the TBS (24-bit length) and the extensions (16-bit
    /// length). `None` when a length does not fit its field.
    fn signed_data(&self, issuer_key_hash: &[u8; 32], tbs: &[u8]) -> Option<Vec<u8>> {
        let tbs_len = u32::try_from(tbs.len()).ok().filter(|n| *n < 1 << 24)?;
        let extensions_len = u16::try_from(self.extensions.len()).ok()?;
        let mut out = Vec::with_capacity(48 + tbs.len() + self.extensions.len());
        out.push(0); // sct_version v1
        out.push(0); // signature_type certificate_timestamp
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // entry_type precert_entry
        out.extend_from_slice(issuer_key_hash);
        out.extend_from_slice(&tbs_len.to_be_bytes()[1..]);
        out.extend_from_slice(tbs);
        out.extend_from_slice(&extensions_len.to_be_bytes());
        out.extend_from_slice(self.extensions);
        Some(out)
    }
}

/// A cursor over TLS-encoded bytes (RFC 8446, 3).
struct Tls<'a>(&'a [u8]);

impl<'a> Tls<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
    }

    /// An `opaque<0..2^16-1>`.
    fn vector16(&mut self) -> Option<&'a [u8]> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }
}

/// The SCTs of the SCT list extension's value: an OCTET STRING holding a
/// `SignedCertificateTimestampList` (RFC 6962, 3.3). `None` when it is
/// malformed anywhere; an entry of another version than v1 is `Some(None)`
/// (skipped: its layout is unknown, its length is not).
fn sct_list(value: &[u8]) -> Option<Vec<Option<Sct<'_>>>> {
    let mut wrapper = Reader::new(value);
    let list = wrapper.expect(OCTET_STRING).ok()?;
    wrapper.finish().ok()?;
    let mut outer = Tls(list);
    let mut entries = Tls(outer.vector16()?);
    if !outer.0.is_empty() {
        return None;
    }
    let mut scts = Vec::new();
    while !entries.0.is_empty() {
        let mut sct = Tls(entries.vector16()?);
        if sct.u8()? != 0 {
            scts.push(None);
            continue;
        }
        let log_id: [u8; 32] = sct.take(32)?.try_into().ok()?;
        let timestamp = u64::from_be_bytes(sct.take(8)?.try_into().ok()?);
        let extensions = sct.vector16()?;
        let hash = sct.u8()?;
        let signature_algorithm = sct.u8()?;
        let signature = sct.vector16()?;
        if !sct.0.is_empty() {
            return None;
        }
        scts.push(Some(Sct {
            log_id,
            timestamp,
            extensions,
            hash,
            signature_algorithm,
            signature,
        }));
    }
    Some(scts)
}

#[cfg(test)]
mod tests {
    use super::testing::{
        self, CA, CA_NO_EKU, CODE_SIGNING, CT_PUBLIC, FULCIO_ISSUER, LIFETIME, LeafSpec, ROOT,
        SCT_MS, SERVER_AUTH, SctSpec, T, ca_true, eku, pem_der, san,
    };
    use super::*;

    fn verify(leaf: &[u8], issuer: &[u8], at: u64) -> Result<CodeSigningCert, CertError> {
        let intermediate = pem_der(issuer);
        let root = pem_der(ROOT);
        verify_code_signing(leaf, &[&intermediate], &[&root], at)
    }

    fn cert(spec: &LeafSpec) -> CodeSigningCert {
        verify(&spec.build(), spec.issuer, T).expect("chain")
    }

    fn test_log() -> CtLog {
        CtLog {
            key: PublicKey::from_pem(CT_PUBLIC).expect("CT key"),
            valid_from_ms: 0,
            valid_to_ms: None,
        }
    }

    fn sct(spec: &LeafSpec) -> Result<u64, SctError> {
        cert(spec).verify_embedded_sct(&[test_log()])
    }

    #[test]
    fn fulcio_shaped_leaf_verifies() {
        let spec = LeafSpec::fulcio(san(&[(
            0x86,
            b"https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1",
        )]));
        let cert = cert(&spec);
        assert_eq!(
            cert.sans(),
            &[San::Uri(
                "https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1".into()
            )]
        );
        assert_eq!(
            cert.extension(FULCIO_ISSUER),
            Some(&b"https://issuer.boneli.test"[..])
        );
        assert_eq!(cert.not_before(), T);
        assert_eq!(cert.not_after(), T + LIFETIME);
        assert_eq!(cert.public_key().kind(), KeyKind::EcdsaP256);
        assert_eq!(cert.verify_embedded_sct(&[test_log()]), Ok(SCT_MS));
        let email = self::cert(&LeafSpec::email());
        assert_eq!(email.sans(), &[San::Email("signer@boneli.test".into())]);
    }

    #[test]
    fn leaf_usage_cases() {
        let mut no_eku = LeafSpec::email();
        no_eku.extensions.remove(1);
        no_eku.sct_position = 3;
        assert_eq!(
            verify(&no_eku.build(), CA, T).expect_err("refused"),
            CertError::NotCodeSigning
        );
        let mut server_auth = LeafSpec::email();
        server_auth.extensions[1] = eku(&[SERVER_AUTH]);
        assert_eq!(
            verify(&server_auth.build(), CA, T).expect_err("refused"),
            CertError::NotCodeSigning
        );
        let mut both = LeafSpec::email();
        both.extensions[1] = eku(&[SERVER_AUTH, CODE_SIGNING]);
        assert!(verify(&both.build(), CA, T).is_ok());
        let mut ca = LeafSpec::email();
        ca.extensions.push(ca_true());
        assert_eq!(
            verify(&ca.build(), CA, T).expect_err("refused"),
            CertError::IsCa
        );
    }

    /// The intermediates are only those passed in, and webpki demands the
    /// Code Signing EKU of them too.
    #[test]
    fn intermediates_only_those_passed() {
        let leaf = LeafSpec::email().build();
        let root = pem_der(ROOT);
        assert_eq!(
            verify_code_signing(&leaf, &[], &[&root], T).expect_err("refused"),
            CertError::UnknownIssuer
        );
        let intermediate = pem_der(CA);
        assert_eq!(
            verify_code_signing(&leaf, &[&intermediate], &[], T).expect_err("refused"),
            CertError::UnknownIssuer
        );
        // The intermediate as the root: a trust anchor needs no EKU.
        assert!(verify_code_signing(&leaf, &[], &[&intermediate], T).is_ok());
        let mut under_no_eku = LeafSpec::email();
        under_no_eku.issuer = CA_NO_EKU;
        assert_eq!(
            verify(&under_no_eku.build(), CA_NO_EKU, T).expect_err("refused"),
            CertError::NotCodeSigning
        );
    }

    #[test]
    fn integrated_time_at_leaf_bounds() {
        let leaf = LeafSpec::email().build();
        assert!(verify(&leaf, CA, T).is_ok());
        assert!(verify(&leaf, CA, T + LIFETIME).is_ok());
        assert_eq!(
            verify(&leaf, CA, T - 1).expect_err("refused"),
            CertError::OutsideValidity
        );
        assert_eq!(
            verify(&leaf, CA, T + LIFETIME + 1).expect_err("refused"),
            CertError::OutsideValidity
        );
    }

    /// The trust anchor itself must be valid at the time, inclusive at
    /// both ends: webpki never checks an anchor's validity (ADR-038, D3).
    /// The intermediate is the anchor here (2026-01-01 to 2126-01-01), and
    /// the leaf is valid well around both of its bounds.
    #[test]
    fn anchor_validity_at_time() {
        const ANCHOR_FROM: u64 = 1_767_225_600;
        const ANCHOR_TO: u64 = 4_922_899_200;
        let anchor = pem_der(CA);
        let leaf = |at: u64| {
            LeafSpec {
                not_before: at - 86_400,
                not_after: at + 86_400,
                ..LeafSpec::email()
            }
            .build()
        };
        for (at, ok) in [
            (1_751_328_000, false),
            (ANCHOR_FROM - 1, false),
            (ANCHOR_FROM, true),
            (ANCHOR_TO, true),
            (ANCHOR_TO + 1, false),
        ] {
            let result = verify_code_signing(&leaf(at), &[], &[&anchor], at);
            if ok {
                assert!(result.is_ok(), "{at}");
            } else {
                assert_eq!(
                    result.expect_err("refused"),
                    CertError::OutsideValidity,
                    "{at}"
                );
            }
        }
    }

    #[test]
    fn two_sans_read_in_order() {
        let spec = LeafSpec::fulcio(san(&[
            (0x81, b"a@boneli.test"),
            (0x86, b"https://boneli.test/x"),
        ]));
        assert_eq!(
            cert(&spec).sans(),
            &[
                San::Email("a@boneli.test".into()),
                San::Uri("https://boneli.test/x".into())
            ]
        );
    }

    #[test]
    fn other_name_types_are_other() {
        let other_name = der::encode(
            OID,
            &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x07],
        );
        let mut other_name_value = other_name;
        other_name_value.extend(der::encode(0xA0, &der::encode(0x0C, b"user")));
        let spec = LeafSpec::fulcio(san(&[
            (DNS_NAME, b"boneli.test"),
            (0xA0, &other_name_value),
        ]));
        assert_eq!(cert(&spec).sans(), &[San::Other, San::Other]);
    }

    #[test]
    fn non_ascii_san_refused() {
        for tag in [RFC822_NAME, URI, DNS_NAME] {
            for name in ["sign\u{e9}r@boneli.test", "https://gith\u{430}b.com/x"] {
                let spec = LeafSpec::fulcio(san(&[(tag, name.as_bytes())]));
                assert_eq!(
                    verify(&spec.build(), CA, T).expect_err("refused"),
                    CertError::NonAsciiSan,
                    "tag {tag:#x} {name}"
                );
            }
        }
    }

    #[test]
    fn no_san_extension_gives_no_sans() {
        let mut spec = LeafSpec::email();
        spec.extensions.remove(2);
        spec.sct_position = 3;
        assert_eq!(cert(&spec).sans(), &[]);
    }

    #[test]
    fn extension_reader() {
        let cert = cert(&LeafSpec::email());
        assert_eq!(
            cert.extension(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x08]),
            None
        );
        // The raw extnValue contents: keyUsage's BIT STRING, whole.
        assert_eq!(
            cert.extension(&[0x55, 0x1D, 0x0F]),
            Some(&[0x03, 0x02, 0x07, 0x80][..])
        );
    }

    #[test]
    fn duplicate_extension_refused() {
        let mut spec = LeafSpec::email();
        spec.extensions
            .push(testing::fulcio_issuer(b"https://other.boneli.test"));
        assert_eq!(
            verify(&spec.build(), CA, T).expect_err("refused"),
            CertError::Malformed
        );
    }

    #[test]
    fn unsupported_leaf_key_refused() {
        let mut spec = LeafSpec::email();
        spec.key = testing::P521_KEY;
        assert_eq!(
            verify(&spec.build(), CA, T).expect_err("refused"),
            CertError::UnsupportedKey
        );
    }

    /// The precertificate TBS is rebuilt exactly: equal to the one built
    /// without the SCT list, wherever the list sits.
    #[test]
    fn precert_tbs_matches_the_one_built_without_the_list() {
        for position in 0..=4 {
            let mut spec = LeafSpec::email();
            spec.sct_position = position;
            let leaf = spec.build();
            assert_eq!(
                precert_tbs(&leaf),
                Ok(spec.precert_tbs()),
                "position {position}"
            );
            assert_eq!(sct(&spec), Ok(SCT_MS), "position {position}");
        }
    }

    /// A leaf whose only extension is the SCT list: the rebuilt TBS has
    /// no `[3]` field at all.
    #[test]
    fn precert_tbs_without_extensions() {
        let mut spec = LeafSpec::email();
        spec.extensions.clear();
        spec.sct_position = 0;
        let leaf = spec.build();
        assert_eq!(precert_tbs(&leaf), Ok(spec.precert_tbs()));
    }

    #[test]
    fn sct_cases() {
        // No SCT list.
        let mut none = LeafSpec::email();
        none.scts.clear();
        assert_eq!(sct(&none), Err(SctError::Missing));
        // Signed over another TBS.
        let mut other_tbs = LeafSpec::email();
        other_tbs.scts[0].over_other_tbs = true;
        assert_eq!(sct(&other_tbs), Err(SctError::NoneVerified));
        // Signed with another issuer key hash.
        let mut other_issuer = LeafSpec::email();
        other_issuer.scts[0].issuer_key_hash = Some(testing::key_hash(ROOT));
        assert_eq!(sct(&other_issuer), Err(SctError::NoneVerified));
        // A corrupt signature.
        let mut corrupt = LeafSpec::email();
        corrupt.scts[0].corrupt = true;
        assert_eq!(sct(&corrupt), Err(SctError::NoneVerified));
        // From an unknown log: the right key under another log ID, and the
        // test log's ID with no such log listed.
        let mut unknown = LeafSpec::email();
        unknown.scts[0].log_id = Some([0x42; 32]);
        assert_eq!(sct(&unknown), Err(SctError::NoneVerified));
        assert_eq!(
            cert(&LeafSpec::email()).verify_embedded_sct(&[]),
            Err(SctError::NoneVerified)
        );
        // Another hash or signature algorithm than SHA-256 with ECDSA, over
        // a valid ECDSA-SHA256 signature.
        for (hash, signature) in [(5, 3), (4, 1), (4, 7), (0, 3)] {
            let mut wrong = LeafSpec::email();
            wrong.scts[0].hash = hash;
            wrong.scts[0].signature_algorithm = signature;
            assert_eq!(
                sct(&wrong),
                Err(SctError::NoneVerified),
                "{hash} {signature}"
            );
        }
    }

    /// The log window is inclusive at both ends, in milliseconds.
    #[test]
    fn sct_log_window_bounds() {
        let cert = cert(&LeafSpec::email());
        let window = |from, to| CtLog {
            valid_from_ms: from,
            valid_to_ms: to,
            ..test_log()
        };
        assert_eq!(
            cert.verify_embedded_sct(&[window(SCT_MS, Some(SCT_MS))]),
            Ok(SCT_MS)
        );
        assert_eq!(
            cert.verify_embedded_sct(&[window(SCT_MS + 1, None)]),
            Err(SctError::NoneVerified)
        );
        assert_eq!(
            cert.verify_embedded_sct(&[window(0, Some(SCT_MS - 1))]),
            Err(SctError::NoneVerified)
        );
        // A second listing of the same log whose window holds the time.
        assert_eq!(
            cert.verify_embedded_sct(&[window(SCT_MS + 1, None), window(0, None)]),
            Ok(SCT_MS)
        );
    }

    /// At least one SCT must verify; which one does not matter, and a
    /// later version is skipped.
    #[test]
    fn one_good_sct_among_bad_ones() {
        let bad = SctSpec {
            corrupt: true,
            timestamp_ms: SCT_MS + 1,
            ..SctSpec::good()
        };
        let v2 = SctSpec {
            version: 1,
            timestamp_ms: SCT_MS + 2,
            ..SctSpec::good()
        };
        for scts in [
            vec![bad.clone(), SctSpec::good()],
            vec![SctSpec::good(), bad.clone()],
            vec![v2.clone(), SctSpec::good()],
        ] {
            let mut spec = LeafSpec::email();
            spec.scts = scts;
            assert_eq!(sct(&spec), Ok(SCT_MS));
        }
        let mut only_bad = LeafSpec::email();
        only_bad.scts = vec![bad, v2];
        assert_eq!(sct(&only_bad), Err(SctError::NoneVerified));
        // A v1 signature under another version label is not read as v1.
        let mut relabelled = LeafSpec::email();
        relabelled.scts[0].label_version = Some(1);
        assert_eq!(sct(&relabelled), Err(SctError::NoneVerified));
    }

    #[test]
    fn malformed_sct_lists() {
        let good = {
            let spec = LeafSpec::email();
            let cert = cert(&spec);
            cert.extension(SCT_LIST).expect("list").to_vec()
        };
        // The OCTET STRING's content: the TLS list.
        let tls = Reader::new(&good)
            .expect(OCTET_STRING)
            .expect("list")
            .to_vec();
        let mut lists = Vec::new();
        // Every truncation of the TLS list, with consistent DER around it.
        for n in 0..tls.len() {
            lists.push(der::encode(OCTET_STRING, &tls[..n]));
        }
        // A trailing byte after the list, and inside the one SCT.
        let mut trailing = tls.clone();
        trailing.push(0);
        lists.push(der::encode(OCTET_STRING, &trailing));
        let mut inner = tls.clone();
        let total = u16::from_be_bytes([inner[0], inner[1]]) + 1;
        let one = u16::from_be_bytes([inner[2], inner[3]]) + 1;
        inner[..2].copy_from_slice(&total.to_be_bytes());
        inner[2..4].copy_from_slice(&one.to_be_bytes());
        inner.push(0);
        lists.push(der::encode(OCTET_STRING, &inner));
        // Not an OCTET STRING: webpki itself refuses the leaf.
        let mut not_octets = LeafSpec::email();
        not_octets.raw_sct_list = Some(testing::ext(SCT_LIST, false, &der::encode(SEQUENCE, &tls)));
        assert_eq!(
            verify(&not_octets.build(), CA, T).expect_err("refused"),
            CertError::Malformed
        );
        for list in lists {
            let mut spec = LeafSpec::email();
            spec.raw_sct_list = Some(testing::ext(SCT_LIST, false, &list));
            let result = sct(&spec);
            // The empty list is well formed and holds nothing.
            if list == der::encode(OCTET_STRING, &[0, 0]) {
                assert_eq!(result, Err(SctError::NoneVerified));
            } else {
                assert_eq!(result, Err(SctError::Malformed), "{list:02x?}");
            }
        }
    }
}
