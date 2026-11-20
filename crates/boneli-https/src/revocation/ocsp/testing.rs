//! Test helpers: OCSP responses built and signed at test time with the
//! kept test keys (`tests/data/README.md`), and the CertIDs and issuer of
//! the "Boneli OCSP test CA" fixtures.

use std::sync::OnceLock;
use std::time::Duration;

use rustls::SignatureScheme;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, SignatureVerificationAlgorithm, UnixTime};

use super::super::der::{
    self, BIT_STRING, BOOLEAN, CONTEXT_0, CONTEXT_1, CONTEXT_2, ENUMERATED, GENERALIZED_TIME,
    INTEGER, OCTET_STRING, OID, Reader, SEQUENCE,
};
use super::request::CertId;
use super::response::Issuer;

pub(crate) const CA: &[u8] = include_bytes!("../../../tests/data/ocsp-ca.pem");
pub(crate) const CA_KEY: &[u8] = include_bytes!("../../../tests/data/test-only-ocsp-ca.key");
pub(crate) const RESPONDER_KEY: &[u8] =
    include_bytes!("../../../tests/data/test-only-ocsp-responder.key");
/// The key of the decoy CA, which carries the test CA's name.
pub(crate) const FORGER_KEY: &[u8] = include_bytes!("../../../tests/data/test-only-p256.key");
pub(crate) const GOOD_LEAF: &[u8] = include_bytes!("../../../tests/data/ocsp-good.pem");
pub(crate) const REVOKED_LEAF: &[u8] = include_bytes!("../../../tests/data/ocsp-revoked.pem");

/// 2026-08-29: inside every fixture's validity, after the expired
/// responder's.
pub(crate) const T: u64 = 1_788_000_000;

/// `AlgorithmIdentifier { id-sha1, NULL }`, whole.
pub(crate) const SHA1_NULL: &[u8] = &[
    0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
];

/// `ecdsa-with-SHA256`, whole.
const ECDSA_SHA256: &[u8] = &[
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
];

const OCSP_BASIC: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

pub(crate) fn time(secs: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(secs))
}

pub(crate) fn algorithms() -> &'static [&'static dyn SignatureVerificationAlgorithm] {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .all
}

pub(crate) fn pem_der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem)
        .expect("PEM")
        .as_ref()
        .to_vec()
}

/// The test CA as the issuer of its leaves.
pub(crate) fn issuer() -> Issuer {
    static ISSUER: OnceLock<Issuer> = OnceLock::new();
    ISSUER
        .get_or_init(|| {
            let ca = CertificateDer::from(pem_der(CA));
            let anchor = webpki::anchor_from_trusted_cert(&ca)
                .expect("anchor")
                .to_owned();
            let parsed = webpki::EndEntityCert::try_from(&ca).expect("CA");
            Issuer {
                spki: parsed.subject_public_key_info().as_ref().to_vec(),
                anchor,
            }
        })
        .clone()
}

/// The CertID of a leaf of the test CA.
pub(crate) fn id_of(leaf_pem: &[u8]) -> CertId {
    let leaf = CertificateDer::from(pem_der(leaf_pem));
    let leaf = webpki::EndEntityCert::try_from(&leaf).expect("leaf");
    cert_id_for(leaf.issuer(), leaf.serial())
}

pub(crate) fn good_id() -> CertId {
    id_of(GOOD_LEAF)
}

/// The CertID of serial `serial` (INTEGER content) from the test CA.
pub(crate) fn cert_id_with_serial(serial: &[u8]) -> CertId {
    let leaf = CertificateDer::from(pem_der(GOOD_LEAF));
    let leaf = webpki::EndEntityCert::try_from(&leaf).expect("leaf");
    cert_id_for(leaf.issuer(), serial)
}

fn cert_id_for(issuer_name: &[u8], serial: &[u8]) -> CertId {
    let spki = issuer().spki;
    let (_, key) = der::spki_parts(&spki).expect("SPKI");
    CertId::new(issuer_name, key, serial)
}

/// A CertID, whole, with any algorithm, hashes and serial.
pub(crate) fn cert_id(algorithm: &[u8], name: &[u8], key: &[u8], serial: &[u8]) -> Vec<u8> {
    let mut body = algorithm.to_vec();
    body.extend(der::encode(OCTET_STRING, name));
    body.extend(der::encode(OCTET_STRING, key));
    body.extend(der::encode(INTEGER, serial));
    der::encode(SEQUENCE, &body)
}

pub(crate) fn flip_last(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if let Some(last) = out.last_mut() {
        *last ^= 0x01;
    }
    out
}

/// A GeneralizedTime, whole, for Unix seconds (proleptic Gregorian).
pub(crate) fn gtime(secs: u64) -> Vec<u8> {
    let days = secs / 86_400;
    let rest = secs % 86_400;
    // Days to a civil date (H. Hinnant's algorithm), from 1970-01-01.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let text = format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",
        rest / 3_600,
        rest / 60 % 60,
        rest % 60
    );
    der::encode(GENERALIZED_TIME, text.as_bytes())
}

pub(crate) fn good() -> Vec<u8> {
    vec![0x80, 0x00]
}

pub(crate) fn revoked(at: u64) -> Vec<u8> {
    der::encode(CONTEXT_1, &gtime(at))
}

pub(crate) fn unknown() -> Vec<u8> {
    vec![0x82, 0x00]
}

/// An `Extension`, whole: `value` goes into the OCTET STRING.
pub(crate) fn ext(oid: &[u8], critical: Option<u8>, value: &[u8]) -> Vec<u8> {
    let mut body = der::encode(OID, oid);
    if let Some(flag) = critical {
        body.extend(der::encode(BOOLEAN, &[flag]));
    }
    body.extend(der::encode(OCTET_STRING, value));
    der::encode(SEQUENCE, &body)
}

/// `[1] EXPLICIT Extensions`, whole.
pub(crate) fn extensions(extensions: &[Vec<u8>]) -> Vec<u8> {
    der::encode(CONTEXT_1, &der::encode(SEQUENCE, &extensions.concat()))
}

/// `element` (a whole constructed TLV) with `extra` appended to its
/// content.
pub(crate) fn append_inside(element: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut reader = Reader::new(element);
    let (tag, content) = reader.read().expect("TLV");
    let mut content = content.to_vec();
    content.extend_from_slice(extra);
    der::encode(tag, &content)
}

/// One `SingleResponse`.
#[derive(Clone, Debug)]
pub(crate) struct SingleSpec {
    pub(crate) cert_id: Vec<u8>,
    pub(crate) status: Vec<u8>,
    pub(crate) this_update: u64,
    pub(crate) next_update: Option<u64>,
    pub(crate) extensions: Option<Vec<u8>>,
}

impl SingleSpec {
    /// Good for `cert_id`, from an hour before `T` to seven days after.
    pub(crate) fn good(cert_id: &[u8]) -> SingleSpec {
        SingleSpec {
            cert_id: cert_id.to_vec(),
            status: good(),
            this_update: T - 3_600,
            next_update: Some(T + 7 * 86_400),
            extensions: None,
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut body = self.cert_id.clone();
        body.extend_from_slice(&self.status);
        body.extend(gtime(self.this_update));
        if let Some(next) = self.next_update {
            body.extend(der::encode(CONTEXT_0, &gtime(next)));
        }
        if let Some(extensions) = &self.extensions {
            body.extend_from_slice(extensions);
        }
        der::encode(SEQUENCE, &body)
    }
}

/// An `OCSPResponse`, field by field.
#[derive(Clone, Debug)]
pub(crate) struct Response {
    pub(crate) status: u8,
    pub(crate) response_type: Vec<u8>,
    /// `[0]` whole, or absent.
    pub(crate) version: Option<Vec<u8>>,
    /// The `ResponderID`, whole.
    pub(crate) responder_id: Vec<u8>,
    pub(crate) produced_at: u64,
    pub(crate) singles: Vec<SingleSpec>,
    /// `[1]` whole, or absent.
    pub(crate) extensions: Option<Vec<u8>>,
    /// The `signatureAlgorithm`, whole.
    pub(crate) signature_algorithm: Vec<u8>,
    /// Certificates, each whole; `None` leaves `[0]` out.
    pub(crate) certs: Option<Vec<Vec<u8>>>,
    /// The PEM of the signing key (P-256, PKCS#8).
    pub(crate) key: &'static [u8],
    pub(crate) unused_bits: u8,
}

impl Response {
    /// Successful, basic, no version, by key, produced at `T - 3600`,
    /// signed ecdsa-with-SHA256 by the test CA, no certificates.
    pub(crate) fn new(singles: Vec<SingleSpec>) -> Response {
        Response {
            status: 0,
            response_type: OCSP_BASIC.to_vec(),
            version: None,
            responder_id: der::encode(CONTEXT_2, &der::encode(OCTET_STRING, &[0x5A; 20])),
            produced_at: T - 3_600,
            singles,
            extensions: None,
            signature_algorithm: ECDSA_SHA256.to_vec(),
            certs: None,
            key: CA_KEY,
            unused_bits: 0,
        }
    }

    /// `tbsResponseData`, whole.
    pub(crate) fn tbs(&self) -> Vec<u8> {
        let mut body = self.version.clone().unwrap_or_default();
        body.extend_from_slice(&self.responder_id);
        body.extend(gtime(self.produced_at));
        let singles: Vec<u8> = self.singles.iter().flat_map(SingleSpec::encode).collect();
        body.extend(der::encode(SEQUENCE, &singles));
        if let Some(extensions) = &self.extensions {
            body.extend_from_slice(extensions);
        }
        der::encode(SEQUENCE, &body)
    }

    /// An ECDSA P-256 SHA-256 signature of `tbs` with `self.key`.
    pub(crate) fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        let key = PrivateKeyDer::from_pem_slice(self.key).expect("key PEM");
        let key = rustls::crypto::ring::sign::any_ecdsa_type(&key).expect("ECDSA key");
        let signer = key
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("P-256");
        signer.sign(tbs).expect("sign")
    }

    /// The response around `tbs` and `signature`.
    pub(crate) fn assemble(&self, tbs: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut bits = vec![self.unused_bits];
        bits.extend_from_slice(signature);
        let mut basic = tbs.to_vec();
        basic.extend_from_slice(&self.signature_algorithm);
        basic.extend(der::encode(BIT_STRING, &bits));
        if let Some(certs) = &self.certs {
            basic.extend(der::encode(
                CONTEXT_0,
                &der::encode(SEQUENCE, &certs.concat()),
            ));
        }
        let basic = der::encode(SEQUENCE, &basic);
        let mut bytes = der::encode(OID, &self.response_type);
        bytes.extend(der::encode(OCTET_STRING, &basic));
        let mut body = der::encode(ENUMERATED, &[self.status]);
        body.extend(der::encode(CONTEXT_0, &der::encode(SEQUENCE, &bytes)));
        der::encode(SEQUENCE, &body)
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        let tbs = self.tbs();
        let signature = self.sign(&tbs);
        self.assemble(&tbs, &signature)
    }
}

#[test]
fn gtime_matches_the_reader() {
    for secs in [0, 951_825_600, 1_709_164_800, T, 4_922_899_200] {
        let tlv = gtime(secs);
        let mut reader = Reader::new(&tlv);
        let value = reader.expect(GENERALIZED_TIME).expect("time");
        assert_eq!(der::generalized_time(value), Ok(secs), "{secs}");
    }
}
