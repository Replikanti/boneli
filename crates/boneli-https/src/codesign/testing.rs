//! Test helpers: code-signing leaves built and signed at test time with
//! the kept test intermediate's key, and embedded SCTs signed with the
//! kept test CT log key (`tests/data/README.md`), as
//! `revocation/ocsp/testing.rs` builds OCSP responses.

use rustls::SignatureScheme;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::Sha256;
use crate::der::{self, BIT_STRING, BOOLEAN, CONTEXT_0, INTEGER, OCTET_STRING, OID, SEQUENCE};

use super::SCT_LIST;

pub(crate) const ROOT: &[u8] = include_bytes!("../../tests/data/codesign-root.pem");
pub(crate) const CA: &[u8] = include_bytes!("../../tests/data/codesign-intermediate.pem");
pub(crate) const CA_NO_EKU: &[u8] =
    include_bytes!("../../tests/data/codesign-intermediate-no-eku.pem");
/// The key of both intermediates.
const CA_KEY: &[u8] = include_bytes!("../../tests/data/test-only-codesign-ca.key");
const CT_KEY: &[u8] = include_bytes!("../../tests/data/test-only-ct-log.key");
pub(crate) const CT_PUBLIC: &[u8] = include_bytes!("../../tests/data/codesign-ct-log.pem");
/// The public key every built leaf carries.
pub(crate) const LEAF_KEY: &[u8] = include_bytes!("../../tests/data/pubkey-p256.pem");
pub(crate) const P521_KEY: &[u8] = include_bytes!("../../tests/data/pubkey-p521.pem");

/// 2026-09-21T14:13:20Z, inside the test CAs' validity: every built
/// leaf's `notBefore`.
pub(crate) const T: u64 = 1_790_000_000;
/// Fulcio's leaf lifetime, 10 minutes.
pub(crate) const LIFETIME: u64 = 600;
/// The default SCT timestamp, 5 ms after `T`.
pub(crate) const SCT_MS: u64 = T * 1_000 + 5;

pub(crate) const CODE_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
pub(crate) const SERVER_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// Fulcio's issuer extension 1.3.6.1.4.1.57264.1.1.
pub(crate) const FULCIO_ISSUER: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x01];
const KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];
/// `ecdsa-with-SHA384`, whole.
const ECDSA_SHA384: &[u8] = &[
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
];

pub(crate) fn pem_der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem)
        .expect("PEM")
        .as_ref()
        .to_vec()
}

/// The DER SubjectPublicKeyInfo of a `PUBLIC KEY` PEM.
pub(crate) fn spki(pem: &[u8]) -> Vec<u8> {
    rustls::pki_types::SubjectPublicKeyInfoDer::from_pem_slice(pem)
        .expect("public key PEM")
        .as_ref()
        .to_vec()
}

/// An `Extension`, whole: `value` goes into the OCTET STRING.
pub(crate) fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut body = der::encode(OID, oid);
    if critical {
        body.extend(der::encode(BOOLEAN, &[0xFF]));
    }
    body.extend(der::encode(OCTET_STRING, value));
    der::encode(SEQUENCE, &body)
}

/// A critical subjectAltName with `names`, each a GeneralName tag and
/// its content.
pub(crate) fn san(names: &[(u8, &[u8])]) -> Vec<u8> {
    let names: Vec<u8> = names
        .iter()
        .flat_map(|(tag, value)| der::encode(*tag, value))
        .collect();
    ext(SUBJECT_ALT_NAME, true, &der::encode(SEQUENCE, &names))
}

pub(crate) fn eku(purposes: &[&[u8]]) -> Vec<u8> {
    let oids: Vec<u8> = purposes.iter().flat_map(|p| der::encode(OID, p)).collect();
    ext(EXT_KEY_USAGE, false, &der::encode(SEQUENCE, &oids))
}

/// `keyUsage` critical, `digitalSignature`.
pub(crate) fn key_usage() -> Vec<u8> {
    ext(KEY_USAGE, true, &der::encode(BIT_STRING, &[0x07, 0x80]))
}

/// `basicConstraints` critical, `CA:TRUE`.
pub(crate) fn ca_true() -> Vec<u8> {
    ext(
        BASIC_CONSTRAINTS,
        true,
        &der::encode(SEQUENCE, &der::encode(BOOLEAN, &[0xFF])),
    )
}

pub(crate) fn fulcio_issuer(issuer: &[u8]) -> Vec<u8> {
    ext(FULCIO_ISSUER, false, issuer)
}

/// The SHA-256 of the SPKI of the CA certificate `pem`.
pub(crate) fn key_hash(pem: &[u8]) -> [u8; 32] {
    let der = CertificateDer::from(pem_der(pem));
    let cert = webpki::EndEntityCert::try_from(&der).expect("CA");
    Sha256::digest(cert.subject_public_key_info().as_ref())
}

fn subject(pem: &[u8]) -> Vec<u8> {
    let der = CertificateDer::from(pem_der(pem));
    let cert = webpki::EndEntityCert::try_from(&der).expect("CA");
    der::encode(SEQUENCE, cert.subject())
}

/// A DER ECDSA signature of `message` with the PKCS#8 key `pem` under
/// `scheme`.
fn sign(pem: &[u8], scheme: SignatureScheme, message: &[u8]) -> Vec<u8> {
    let key = PrivateKeyDer::from_pem_slice(pem).expect("key PEM");
    let key = rustls::crypto::ring::sign::any_ecdsa_type(&key).expect("ECDSA key");
    let signer = key.choose_scheme(&[scheme]).expect("scheme");
    signer.sign(message).expect("sign")
}

/// One embedded SCT, signed at build time with the test CT log key.
#[derive(Clone, Debug)]
pub(crate) struct SctSpec {
    pub(crate) version: u8,
    /// Label the serialized SCT with this version instead, signed as
    /// `version`.
    pub(crate) label_version: Option<u8>,
    pub(crate) timestamp_ms: u64,
    pub(crate) hash: u8,
    pub(crate) signature_algorithm: u8,
    /// Sign over the TBS of a leaf with another serial number.
    pub(crate) over_other_tbs: bool,
    /// Sign with this issuer key hash instead of the issuer's.
    pub(crate) issuer_key_hash: Option<[u8; 32]>,
    /// Carry this log ID instead of the test log's.
    pub(crate) log_id: Option<[u8; 32]>,
    /// Flip the last signature byte after signing.
    pub(crate) corrupt: bool,
}

impl SctSpec {
    /// v1, SHA-256 with ECDSA, at `SCT_MS`, from the test log.
    pub(crate) fn good() -> SctSpec {
        SctSpec {
            version: 0,
            label_version: None,
            timestamp_ms: SCT_MS,
            hash: 4,
            signature_algorithm: 3,
            over_other_tbs: false,
            issuer_key_hash: None,
            log_id: None,
            corrupt: false,
        }
    }

    fn encode(&self, issuer_key_hash: &[u8; 32], tbs: &[u8]) -> Vec<u8> {
        let log_id = self
            .log_id
            .unwrap_or_else(|| Sha256::digest(&spki(CT_PUBLIC)));
        let mut signed = vec![self.version, 0];
        signed.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        signed.extend_from_slice(&[0, 1]);
        signed.extend_from_slice(&self.issuer_key_hash.unwrap_or(*issuer_key_hash));
        signed.extend_from_slice(&(tbs.len() as u32).to_be_bytes()[1..]);
        signed.extend_from_slice(tbs);
        signed.extend_from_slice(&[0, 0]);
        let mut signature = sign(CT_KEY, SignatureScheme::ECDSA_NISTP256_SHA256, &signed);
        if self.corrupt {
            let last = signature.len() - 1;
            signature[last] ^= 0x01;
        }
        let mut sct = vec![self.label_version.unwrap_or(self.version)];
        sct.extend_from_slice(&log_id);
        sct.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        sct.extend_from_slice(&[0, 0]);
        sct.push(self.hash);
        sct.push(self.signature_algorithm);
        sct.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        sct.extend_from_slice(&signature);
        sct
    }
}

/// The SCT list extension around serialized SCTs.
pub(crate) fn sct_list(scts: &[Vec<u8>]) -> Vec<u8> {
    ext(SCT_LIST, false, &der::encode(OCTET_STRING, &tls_list(scts)))
}

/// A `SignedCertificateTimestampList`: 16-bit lengths around each SCT and
/// the whole.
pub(crate) fn tls_list(scts: &[Vec<u8>]) -> Vec<u8> {
    let mut entries = Vec::new();
    for sct in scts {
        entries.extend_from_slice(&(sct.len() as u16).to_be_bytes());
        entries.extend_from_slice(sct);
    }
    let mut list = (entries.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&entries);
    list
}

/// A code-signing leaf to build.
#[derive(Clone, Debug)]
pub(crate) struct LeafSpec {
    /// The intermediate (PEM) that issues it, with `CA_KEY`.
    pub(crate) issuer: &'static [u8],
    pub(crate) serial: u8,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    /// A `PUBLIC KEY` PEM.
    pub(crate) key: &'static [u8],
    /// Whole extensions, without the SCT list.
    pub(crate) extensions: Vec<Vec<u8>>,
    pub(crate) scts: Vec<SctSpec>,
    /// Where among `extensions` the SCT list goes.
    pub(crate) sct_position: usize,
    /// The whole SCT list extension, instead of one built from `scts`.
    pub(crate) raw_sct_list: Option<Vec<u8>>,
}

impl LeafSpec {
    /// Fulcio's shape: keyUsage, EKU codeSigning, the critical SAN, the
    /// issuer extension, then one good SCT; valid for 10 minutes from `T`.
    pub(crate) fn fulcio(san_ext: Vec<u8>) -> LeafSpec {
        LeafSpec {
            issuer: CA,
            serial: 7,
            not_before: T,
            not_after: T + LIFETIME,
            key: LEAF_KEY,
            extensions: vec![
                key_usage(),
                eku(&[CODE_SIGNING]),
                san_ext,
                fulcio_issuer(b"https://issuer.boneli.test"),
            ],
            scts: vec![SctSpec::good()],
            sct_position: 4,
            raw_sct_list: None,
        }
    }

    pub(crate) fn email() -> LeafSpec {
        LeafSpec::fulcio(san(&[(0x81, b"signer@boneli.test")]))
    }

    fn tbs(&self, serial: u8, extensions: &[Vec<u8>]) -> Vec<u8> {
        let mut body = der::encode(CONTEXT_0, &der::encode(INTEGER, &[2]));
        body.extend(der::encode(INTEGER, &[serial]));
        body.extend_from_slice(ECDSA_SHA384);
        body.extend(subject(self.issuer));
        let mut validity = der::encode_generalized_time(self.not_before);
        validity.extend(der::encode_generalized_time(self.not_after));
        body.extend(der::encode(SEQUENCE, &validity));
        body.extend(der::encode(SEQUENCE, &[])); // an empty subject, as Fulcio's
        body.extend(spki(self.key));
        if !extensions.is_empty() {
            body.extend(der::encode(
                0xA3,
                &der::encode(SEQUENCE, &extensions.concat()),
            ));
        }
        der::encode(SEQUENCE, &body)
    }

    /// The precertificate TBS the SCTs sign: the leaf's TBS without the SCT
    /// list, built directly, not by removing it.
    pub(crate) fn precert_tbs(&self) -> Vec<u8> {
        self.tbs(self.serial, &self.extensions)
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        let issuer_key_hash = key_hash(self.issuer);
        let precert = self.precert_tbs();
        let other = self.tbs(self.serial.wrapping_add(1), &self.extensions);
        let mut extensions = self.extensions.clone();
        let list = match &self.raw_sct_list {
            Some(raw) => Some(raw.clone()),
            None if self.scts.is_empty() => None,
            None => {
                let scts: Vec<Vec<u8>> = self
                    .scts
                    .iter()
                    .map(|s| {
                        let tbs = if s.over_other_tbs { &other } else { &precert };
                        s.encode(&issuer_key_hash, tbs)
                    })
                    .collect();
                Some(sct_list(&scts))
            }
        };
        if let Some(list) = list {
            extensions.insert(self.sct_position, list);
        }
        let tbs = self.tbs(self.serial, &extensions);
        let signature = sign(CA_KEY, SignatureScheme::ECDSA_NISTP384_SHA384, &tbs);
        let mut bits = vec![0];
        bits.extend_from_slice(&signature);
        let mut cert = tbs;
        cert.extend_from_slice(ECDSA_SHA384);
        cert.extend(der::encode(BIT_STRING, &bits));
        der::encode(SEQUENCE, &cert)
    }
}
