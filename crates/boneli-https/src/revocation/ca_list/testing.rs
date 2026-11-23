//! Test helpers: CA lists built and signed at test time with the kept
//! test keys of the "Boneli chain test root" fixtures
//! (`tests/data/README.md`), and the subjects and issuer keys of those
//! fixtures.

use rustls::SignatureScheme;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::super::ocsp::testing::gtime;
use crate::der::{
    self, BIT_STRING, BOOLEAN, CONTEXT_0, ENUMERATED, INTEGER, OCTET_STRING, OID, SEQUENCE,
};

pub(crate) const ROOT: &[u8] = include_bytes!("../../../tests/data/chain-root.pem");
pub(crate) const ROOT_KEY: &[u8] = include_bytes!("../../../tests/data/test-only-chain-root.key");
pub(crate) const CA_KEY: &[u8] = include_bytes!("../../../tests/data/test-only-chain-ca.key");
/// A key no fixture CA has: the forger's.
pub(crate) const FORGER_KEY: &[u8] = include_bytes!("../../../tests/data/test-only-p256.key");
pub(crate) const CA1: &[u8] = include_bytes!("../../../tests/data/chain-ca1.pem");
pub(crate) const CA2: &[u8] = include_bytes!("../../../tests/data/chain-ca2.pem");
pub(crate) const CA1_NO_CRL_SIGN: &[u8] =
    include_bytes!("../../../tests/data/chain-ca1-no-crl-sign.pem");

/// 2026-01-01 and 2026-01-08: the default `thisUpdate` and `nextUpdate`.
pub(crate) const T0: u64 = 1_767_225_600;
pub(crate) const WEEK1_END: u64 = 1_767_830_400;

/// `ecdsa-with-SHA256`, whole.
pub(crate) const ECDSA_SHA256: &[u8] = &[
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
];
/// `ecdsa-with-SHA1`, whole: no handshake algorithm has it.
pub(crate) const ECDSA_SHA1: &[u8] = &[
    0x30, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01,
];

pub(crate) const CRL_NUMBER: &[u8] = &[0x55, 0x1D, 0x14];
pub(crate) const REASON_CODE: &[u8] = &[0x55, 0x1D, 0x15];
pub(crate) const DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1D, 0x1B];
pub(crate) const IDP: &[u8] = &[0x55, 0x1D, 0x1C];
/// id-ce-freshestCRL, 2.5.29.46: understood by nobody here.
pub(crate) const FRESHEST_CRL: &[u8] = &[0x55, 0x1D, 0x2E];
/// id-ce-invalidityDate, 2.5.29.24.
pub(crate) const INVALIDITY_DATE: &[u8] = &[0x55, 0x1D, 0x18];

pub(crate) fn pem_der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem)
        .expect("PEM")
        .as_ref()
        .to_vec()
}

/// A certificate's subject Name, whole, as a list's issuer field.
pub(crate) fn subject_name(pem: &[u8]) -> Vec<u8> {
    let der = CertificateDer::from(pem_der(pem));
    let cert = webpki::EndEntityCert::try_from(&der).expect("certificate");
    der::encode(SEQUENCE, cert.subject())
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

/// A `reasonCode` entry extension, whole.
pub(crate) fn reason(code: u8) -> Vec<u8> {
    ext(REASON_CODE, None, &der::encode(ENUMERATED, &[code]))
}

/// One entry, whole: `serial` (INTEGER content), revoked at `T0`, with
/// `extensions` (each whole) when given.
pub(crate) fn entry(serial: &[u8], extensions: Option<Vec<Vec<u8>>>) -> Vec<u8> {
    let mut body = der::encode(INTEGER, serial);
    body.extend(gtime(T0));
    if let Some(extensions) = extensions {
        body.extend(der::encode(SEQUENCE, &extensions.concat()));
    }
    der::encode(SEQUENCE, &body)
}

/// An issuingDistributionPoint value: `[0]` with `full_name` (each a
/// whole GeneralName) when given, then each `(tag, value)` field as is.
pub(crate) fn idp_value(full_name: Option<&[Vec<u8>]>, fields: &[(u8, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    if let Some(names) = full_name {
        body.extend(der::encode(
            CONTEXT_0,
            &der::encode(CONTEXT_0, &names.concat()),
        ));
    }
    for (tag, value) in fields {
        body.extend(der::encode(*tag, value));
    }
    der::encode(SEQUENCE, &body)
}

/// A `uniformResourceIdentifier` GeneralName, whole.
pub(crate) fn uri(text: &str) -> Vec<u8> {
    der::encode(0x86, text.as_bytes())
}

/// A CertificateList, field by field.
#[derive(Clone, Debug)]
pub(crate) struct ListSpec {
    /// The version INTEGER, whole, or absent.
    pub(crate) version: Option<Vec<u8>>,
    /// The inner `signature` AlgorithmIdentifier, whole.
    pub(crate) inner_algorithm: Vec<u8>,
    /// The issuer Name, whole.
    pub(crate) issuer: Vec<u8>,
    /// `thisUpdate` and `nextUpdate`, whole times; `None` leaves the
    /// second out.
    pub(crate) this_update: Vec<u8>,
    pub(crate) next_update: Option<Vec<u8>>,
    /// The entries, each whole; `None` leaves `revokedCertificates` out,
    /// `Some(vec![])` writes an empty SEQUENCE.
    pub(crate) entries: Option<Vec<Vec<u8>>>,
    /// The list's extensions, each whole, inside `[0] SEQUENCE`; `None`
    /// leaves `[0]` out.
    pub(crate) extensions: Option<Vec<Vec<u8>>>,
    /// The outer `signatureAlgorithm`, whole.
    pub(crate) outer_algorithm: Vec<u8>,
    pub(crate) unused_bits: u8,
    /// The PEM of the signing key (P-256, PKCS#8).
    pub(crate) key: &'static [u8],
}

impl ListSpec {
    /// Version 2, ecdsa-with-SHA256, `T0` to `WEEK1_END`, no entries, a
    /// cRLNumber, signed by `key` under the name `issuer` (whole).
    pub(crate) fn new(issuer: Vec<u8>, key: &'static [u8]) -> ListSpec {
        ListSpec::window(issuer, key, T0, WEEK1_END)
    }

    /// The same from `this_update` to `next_update`.
    pub(crate) fn window(
        issuer: Vec<u8>,
        key: &'static [u8],
        this_update: u64,
        next_update: u64,
    ) -> ListSpec {
        ListSpec {
            version: Some(der::encode(INTEGER, &[1])),
            inner_algorithm: ECDSA_SHA256.to_vec(),
            issuer,
            this_update: gtime(this_update),
            next_update: Some(gtime(next_update)),
            entries: None,
            extensions: Some(vec![ext(CRL_NUMBER, None, &der::encode(INTEGER, &[1]))]),
            outer_algorithm: ECDSA_SHA256.to_vec(),
            unused_bits: 0,
            key,
        }
    }

    /// The root's list of its intermediates.
    pub(crate) fn root() -> ListSpec {
        ListSpec::new(subject_name(ROOT), ROOT_KEY)
    }

    /// CA 1's list of its intermediates.
    pub(crate) fn ca1() -> ListSpec {
        ListSpec::new(subject_name(CA1), CA_KEY)
    }

    /// This list with entries for `serials` (INTEGER content).
    pub(crate) fn listing(mut self, serials: &[&[u8]]) -> ListSpec {
        self.entries = Some(serials.iter().map(|s| entry(s, None)).collect());
        self
    }

    /// This list with `extension` (whole) added.
    pub(crate) fn with_extension(mut self, extension: Vec<u8>) -> ListSpec {
        self.extensions.get_or_insert_with(Vec::new).push(extension);
        self
    }

    /// `tbsCertList`, whole.
    pub(crate) fn tbs(&self) -> Vec<u8> {
        let mut body = self.version.clone().unwrap_or_default();
        body.extend_from_slice(&self.inner_algorithm);
        body.extend_from_slice(&self.issuer);
        body.extend_from_slice(&self.this_update);
        if let Some(next) = &self.next_update {
            body.extend_from_slice(next);
        }
        if let Some(entries) = &self.entries {
            body.extend(der::encode(SEQUENCE, &entries.concat()));
        }
        if let Some(extensions) = &self.extensions {
            body.extend(der::encode(
                CONTEXT_0,
                &der::encode(SEQUENCE, &extensions.concat()),
            ));
        }
        der::encode(SEQUENCE, &body)
    }

    /// The list around `tbs` and `signature`.
    pub(crate) fn assemble(&self, tbs: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut bits = vec![self.unused_bits];
        bits.extend_from_slice(signature);
        let mut body = tbs.to_vec();
        body.extend_from_slice(&self.outer_algorithm);
        body.extend(der::encode(BIT_STRING, &bits));
        der::encode(SEQUENCE, &body)
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        let tbs = self.tbs();
        self.assemble(&tbs, &sign(self.key, &tbs))
    }
}

/// An ECDSA P-256 SHA-256 signature of `tbs` with the PEM key `key`.
pub(crate) fn sign(key: &[u8], tbs: &[u8]) -> Vec<u8> {
    let key = PrivateKeyDer::from_pem_slice(key).expect("key PEM");
    let key = rustls::crypto::ring::sign::any_ecdsa_type(&key).expect("ECDSA key");
    let signer = key
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .expect("P-256");
    signer.sign(tbs).expect("sign")
}
