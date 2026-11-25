//! Test helpers: RFC 3161 tokens built and signed at test time, in the
//! field order of the public-good TSA's tokens (`tests/data/README.md`),
//! with the kept test TSA key `test-only-tsa.key` (P-256, through
//! [`EcdsaP256Key`]), and TSA leaves issued by the code-signing test
//! intermediate's key (`codesign/testing.rs`), which the tests use as the
//! anchor, as the public-good TSA chain is a leaf and its anchor.

use rustls::SignatureScheme;

use crate::codesign::testing::{CA, CA_KEY, ECDSA_SHA384, ROOT, pem_der, sign, spki, subject};
use crate::der::{
    self, BIT_STRING, BOOLEAN, CONTEXT_0, INTEGER, NULL, OCTET_STRING, OID, SEQUENCE,
};
use crate::{EcdsaP256Key, Sha256};

use super::{
    CONTENT_TYPE, EXT_KEY_USAGE, ID_CT_TST_INFO, ID_KP_TIME_STAMPING, ID_SIGNED_DATA,
    MESSAGE_DIGEST, SHA256, SIGNING_CERTIFICATE_V2,
};

/// The P-256 key of every built TSA leaf, and its public key.
pub(crate) const TSA_KEY: &[u8] = include_bytes!("../../tests/data/test-only-tsa.key");
pub(crate) const TSA_PUBLIC: &[u8] = include_bytes!("../../tests/data/test-only-tsa.pub.pem");

/// 2026-09-21T14:13:20Z, inside the test CA's validity: the default
/// genTime.
pub(crate) const T: u64 = 1_790_000_000;
/// The built TSA leaf's validity: 30 days on each side of `T`.
pub(crate) const LEAF_FROM: u64 = T - 30 * 86_400;
pub(crate) const LEAF_TO: u64 = T + 30 * 86_400;

/// The message every default token is over.
pub(crate) const MESSAGE: &[u8] = b"the DSSE signature bytes";

pub(crate) const ID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
pub(crate) const SIGNING_TIME: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];
pub(crate) const SIGNING_CERTIFICATE_V1: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0C,
];
pub(crate) const SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
pub(crate) const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
pub(crate) const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
pub(crate) const ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
pub(crate) const ECDSA_WITH_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
pub(crate) const RSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
pub(crate) const CODE_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
/// Sigstore's TSA policy, 1.3.6.1.4.1.57264.2.
const POLICY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x02];
const KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];

/// An AlgorithmIdentifier, whole: `oid` and, if `null`, NULL parameters.
pub(crate) fn algorithm(oid: &[u8], null: bool) -> Vec<u8> {
    let mut body = der::encode(OID, oid);
    if null {
        body.extend(der::encode(NULL, &[]));
    }
    der::encode(SEQUENCE, &body)
}

/// An `Extension`, whole.
pub(crate) fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    crate::codesign::testing::ext(oid, critical, value)
}

/// `extendedKeyUsage` with `purposes`.
pub(crate) fn eku(critical: bool, purposes: &[&[u8]]) -> Vec<u8> {
    let oids: Vec<u8> = purposes.iter().flat_map(|p| der::encode(OID, p)).collect();
    ext(EXT_KEY_USAGE, critical, &der::encode(SEQUENCE, &oids))
}

/// `keyUsage` critical with the first byte `bits` (0x80 digitalSignature,
/// 0x20 keyEncipherment).
pub(crate) fn key_usage(bits: u8) -> Vec<u8> {
    ext(KEY_USAGE, true, &der::encode(BIT_STRING, &[0x00, bits]))
}

/// `basicConstraints` critical, `CA:TRUE`.
pub(crate) fn ca_true() -> Vec<u8> {
    ext(
        BASIC_CONSTRAINTS,
        true,
        &der::encode(SEQUENCE, &der::encode(BOOLEAN, &[0xFF])),
    )
}

/// A `Name` with one commonName.
fn name(cn: &str) -> Vec<u8> {
    let attribute = der::encode(
        SEQUENCE,
        &[
            der::encode(OID, &[0x55, 0x04, 0x03]),
            der::encode(0x0C, cn.as_bytes()),
        ]
        .concat(),
    );
    der::encode(SEQUENCE, &der::encode(0x31, &attribute))
}

/// A TSA leaf to build, issued by the code-signing test intermediate.
#[derive(Clone, Debug)]
pub(crate) struct TsaLeafSpec {
    pub(crate) serial: u8,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
    pub(crate) extensions: Vec<Vec<u8>>,
}

impl TsaLeafSpec {
    /// The public-good TSA leaf's shape: keyUsage digitalSignature and the
    /// EKU timeStamping, both critical.
    pub(crate) fn good() -> TsaLeafSpec {
        TsaLeafSpec {
            serial: 9,
            not_before: LEAF_FROM,
            not_after: LEAF_TO,
            extensions: vec![key_usage(0x80), eku(true, &[ID_KP_TIME_STAMPING])],
        }
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        let mut body = der::encode(CONTEXT_0, &der::encode(INTEGER, &[2]));
        body.extend(der::encode(INTEGER, &[self.serial]));
        body.extend_from_slice(ECDSA_SHA384);
        body.extend(subject(CA));
        let mut validity = der::encode_generalized_time(self.not_before);
        validity.extend(der::encode_generalized_time(self.not_after));
        body.extend(der::encode(SEQUENCE, &validity));
        body.extend(name("Boneli test TSA"));
        body.extend(spki(TSA_PUBLIC));
        if !self.extensions.is_empty() {
            body.extend(der::encode(
                0xA3,
                &der::encode(SEQUENCE, &self.extensions.concat()),
            ));
        }
        let tbs = der::encode(SEQUENCE, &body);
        let signature = sign(CA_KEY, SignatureScheme::ECDSA_NISTP384_SHA384, &tbs);
        let mut bits = vec![0];
        bits.extend_from_slice(&signature);
        let mut cert = tbs;
        cert.extend_from_slice(ECDSA_SHA384);
        cert.extend(der::encode(BIT_STRING, &bits));
        der::encode(SEQUENCE, &cert)
    }
}

/// The anchor of every built TSA leaf: the code-signing test
/// intermediate, DER.
pub(crate) fn anchor() -> Vec<u8> {
    pem_der(CA)
}

/// The code-signing test root, DER: an anchor that did not issue the
/// built leaves.
pub(crate) fn root() -> Vec<u8> {
    pem_der(ROOT)
}

/// One signed attribute, whole: `oid` and a SET of `values`.
pub(crate) fn attribute(oid: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    der::encode(
        SEQUENCE,
        &[der::encode(OID, oid), der::encode(0x31, &values.concat())].concat(),
    )
}

/// `signingCertificateV2` naming `cert_hash`, with `hash_algorithm` (a
/// whole AlgorithmIdentifier) or the default, SHA-256, left out.
pub(crate) fn signing_certificate_v2(hash_algorithm: Option<Vec<u8>>, cert_hash: &[u8]) -> Vec<u8> {
    let mut id = hash_algorithm.unwrap_or_default();
    id.extend(der::encode(OCTET_STRING, cert_hash));
    let ids = der::encode(SEQUENCE, &der::encode(SEQUENCE, &id));
    attribute(SIGNING_CERTIFICATE_V2, &[der::encode(SEQUENCE, &ids)])
}

/// A TSTInfo to build.
#[derive(Clone, Debug)]
pub(crate) struct TstSpec {
    pub(crate) version: u8,
    /// The imprint's AlgorithmIdentifier, whole.
    pub(crate) imprint_algorithm: Vec<u8>,
    pub(crate) imprint: Vec<u8>,
    /// The genTime element, whole.
    pub(crate) gen_time: Vec<u8>,
    /// The `[1]` extensions field, whole, if any.
    pub(crate) extensions: Option<Vec<u8>>,
}

impl TstSpec {
    pub(crate) fn over(message: &[u8], gen_time: u64) -> TstSpec {
        TstSpec {
            version: 1,
            imprint_algorithm: algorithm(SHA256, true),
            imprint: Sha256::digest(message).to_vec(),
            gen_time: der::encode_generalized_time(gen_time),
            extensions: None,
        }
    }

    /// A genTime of the raw text `text`.
    pub(crate) fn gen_time_text(&mut self, text: &str) {
        self.gen_time = der::encode(0x18, text.as_bytes());
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        let mut body = der::encode(INTEGER, &[self.version]);
        body.extend(der::encode(OID, POLICY));
        body.extend(der::encode(
            SEQUENCE,
            &[
                self.imprint_algorithm.clone(),
                der::encode(OCTET_STRING, &self.imprint),
            ]
            .concat(),
        ));
        body.extend(der::encode(INTEGER, &[0x3A, 0x13, 0x54]));
        body.extend_from_slice(&self.gen_time);
        // accuracy: 1 second, as the public-good TSA writes it.
        body.extend(der::encode(SEQUENCE, &der::encode(INTEGER, &[1])));
        if let Some(extensions) = &self.extensions {
            body.extend_from_slice(extensions);
        }
        der::encode(SEQUENCE, &body)
    }
}

/// A token to build.
#[derive(Clone, Debug)]
pub(crate) struct TokenSpec {
    /// The PKIStatus value bytes.
    pub(crate) status: Vec<u8>,
    pub(crate) content_type: &'static [u8],
    pub(crate) e_content_type: &'static [u8],
    pub(crate) tst: TstSpec,
    /// Wrap eContent in a constructed OCTET STRING.
    pub(crate) constructed_econtent: bool,
    /// The content of `certificates [0]`, if present.
    pub(crate) certificates: Option<Vec<u8>>,
    /// How many copies of the SignerInfo go into the set.
    pub(crate) signer_infos: usize,
    /// The SignerInfo's digestAlgorithm, whole.
    pub(crate) digest_algorithm: Vec<u8>,
    /// The signed attributes, each whole; `None` leaves `[0]` out.
    /// `Default` builds the public-good order from `leaf`.
    pub(crate) attributes: Attributes,
    /// The signatureAlgorithm, whole.
    pub(crate) signature_algorithm: Vec<u8>,
    /// The leaf the default signingCertificateV2 names.
    pub(crate) leaf: Vec<u8>,
    /// Flip the last signature byte after signing.
    pub(crate) corrupt: bool,
    /// Bytes after the TimeStampResp.
    pub(crate) trailing: Vec<u8>,
}

/// The signed attributes of a token.
#[derive(Clone, Debug)]
pub(crate) enum Attributes {
    /// contentType, signingTime, messageDigest (of eContent) and
    /// signingCertificateV2 (of the leaf), as the public-good TSA writes
    /// them.
    Default,
    /// The default ones, edited by the function.
    Edited(fn(&mut Vec<Vec<u8>>, &[u8], &[u8])),
    /// None: no `[0]` field.
    Absent,
}

impl TokenSpec {
    /// A good token over `message` at `gen_time`, by the leaf of
    /// [`TsaLeafSpec::good`].
    pub(crate) fn over(message: &[u8], gen_time: u64) -> TokenSpec {
        TokenSpec {
            status: vec![0],
            content_type: ID_SIGNED_DATA,
            e_content_type: ID_CT_TST_INFO,
            tst: TstSpec::over(message, gen_time),
            constructed_econtent: false,
            certificates: Some(Vec::new()),
            signer_infos: 1,
            digest_algorithm: algorithm(SHA256, false),
            attributes: Attributes::Default,
            signature_algorithm: algorithm(ECDSA_WITH_SHA256, false),
            leaf: TsaLeafSpec::good().build(),
            corrupt: false,
            trailing: Vec::new(),
        }
    }

    pub(crate) fn good() -> TokenSpec {
        TokenSpec::over(MESSAGE, T)
    }

    /// The default signed attributes for `econtent`.
    pub(crate) fn default_attributes(econtent: &[u8], leaf: &[u8]) -> Vec<Vec<u8>> {
        vec![
            attribute(CONTENT_TYPE, &[der::encode(OID, ID_CT_TST_INFO)]),
            attribute(SIGNING_TIME, &[der::encode(0x17, b"260921141320Z")]),
            attribute(
                MESSAGE_DIGEST,
                &[der::encode(OCTET_STRING, &Sha256::digest(econtent))],
            ),
            signing_certificate_v2(None, &Sha256::digest(leaf)),
        ]
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        let econtent = self.tst.build();
        let attributes = match self.attributes {
            Attributes::Default => Some(Self::default_attributes(&econtent, &self.leaf)),
            Attributes::Edited(edit) => {
                let mut list = Self::default_attributes(&econtent, &self.leaf);
                edit(&mut list, &econtent, &self.leaf);
                Some(list)
            }
            Attributes::Absent => None,
        };
        let key = EcdsaP256Key::from_pem(&mut TSA_KEY.to_vec()).expect("test TSA key");
        let signed = der::encode(0x31, &attributes.clone().unwrap_or_default().concat());
        let mut signature = key.sign(&signed).expect("sign");
        if self.corrupt {
            let last = signature.len() - 1;
            signature[last] ^= 0x01;
        }
        // issuerAndSerialNumber: read for form only.
        let sid = der::encode(
            SEQUENCE,
            &[subject(CA), der::encode(INTEGER, &[9])].concat(),
        );
        let mut signer_info = der::encode(INTEGER, &[1]);
        signer_info.extend(sid);
        signer_info.extend_from_slice(&self.digest_algorithm);
        if let Some(list) = &attributes {
            signer_info.extend(der::encode(0xA0, &list.concat()));
        }
        signer_info.extend_from_slice(&self.signature_algorithm);
        signer_info.extend(der::encode(OCTET_STRING, &signature));
        let signer_info = der::encode(SEQUENCE, &signer_info);

        let econtent_field = if self.constructed_econtent {
            der::encode(0x24, &der::encode(OCTET_STRING, &econtent))
        } else {
            der::encode(OCTET_STRING, &econtent)
        };
        let mut signed_data = der::encode(INTEGER, &[3]);
        signed_data.extend(der::encode(0x31, &algorithm(SHA256, false)));
        signed_data.extend(der::encode(
            SEQUENCE,
            &[
                der::encode(OID, self.e_content_type),
                der::encode(0xA0, &econtent_field),
            ]
            .concat(),
        ));
        if let Some(certificates) = &self.certificates {
            signed_data.extend(der::encode(0xA0, certificates));
        }
        signed_data.extend(der::encode(
            0x31,
            &vec![signer_info; self.signer_infos].concat(),
        ));
        let content_info = der::encode(
            SEQUENCE,
            &[
                der::encode(OID, self.content_type),
                der::encode(0xA0, &der::encode(SEQUENCE, &signed_data)),
            ]
            .concat(),
        );
        let status = der::encode(SEQUENCE, &der::encode(INTEGER, &self.status));
        let mut out = der::encode(SEQUENCE, &[status, content_info].concat());
        out.extend_from_slice(&self.trailing);
        out
    }
}

/// v1 `signingCertificate` naming `cert_hash` (SHA-1 in real tokens; the
/// hash value is not read).
pub(crate) fn signing_certificate_v1(cert_hash: &[u8]) -> Vec<u8> {
    let id = der::encode(SEQUENCE, &der::encode(OCTET_STRING, cert_hash));
    let ids = der::encode(SEQUENCE, &id);
    attribute(SIGNING_CERTIFICATE_V1, &[der::encode(SEQUENCE, &ids)])
}
