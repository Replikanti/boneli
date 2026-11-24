//! A synthetic Sigstore instance built at test time (ADR-029, S3): an RSA
//! root and intermediate with the Code Signing EKU, Fulcio-shaped leaves
//! with issuer extensions and embedded SCTs, a test CT log and a test
//! Rekor whose SETs are signed over the JCS bytes, and `trusted_root.json`
//! around them, all with chosen times and contents.
//!
//! Every signature is `boneli_https::RsaSha256Key::sign` with an RSA test
//! key made by `openssl` (`tests/data/README.md`); certificates go through
//! the small DER writer below. The documents are `boneli_json` values, so
//! a negative test changes one member and serializes again.

use boneli_https::{PublicKey, RsaSha256Key, Sha256};
use boneli_json::{Object, Value};
use boneli_sigstore::{
    BUNDLE_ANNOTATION, BUNDLE_V03_MEDIA_TYPE, CERTIFICATE_ANNOTATION, COSIGN_SIGN_PREDICATE,
    IN_TOTO_PAYLOAD_TYPE, SIGNATURE_ANNOTATION, STATEMENT_V1, base64, pae,
};

/// 2026-09-21T14:13:20Z: every built leaf's `notBefore`.
pub const T: u64 = 1_790_000_000;
/// Fulcio's leaf lifetime, 10 minutes.
pub const LIFETIME: u64 = 600;
/// The default integrated time, 5 s into the leaf's life.
pub const INTEGRATED: u64 = T + 5;
/// The default SCT time, 5 ms after `T`.
pub const SCT_MS: u64 = T * 1_000 + 5;
/// The default log index.
pub const LOG_INDEX: u64 = 4_242;

pub const ISSUER: &str = "https://issuer.boneli.test";
pub const EMAIL: &str = "signer@boneli.test";
pub const URI: &str = "https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1.2.3";

/// The OIDs of the extensions the leaves carry, as content octets.
pub const CODE_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
pub const SERVER_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
pub const ISSUER_V1: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x01];
pub const ISSUER_V2: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x08];
const SCT_LIST: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02];
const KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `sha256WithRSAEncryption` with NULL parameters, whole.
const RSA_SHA256: &[u8] = &[
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
];

pub const RFC822_NAME: u8 = 0x81;
pub const URI_NAME: u8 = 0x86;

// ---- DER --------------------------------------------------------------

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

pub fn utf8(text: &[u8]) -> Vec<u8> {
    tlv(0x0C, text)
}

/// A Name with one CN.
pub fn name(cn: &str) -> Vec<u8> {
    let atv = seq(&[&tlv(0x06, COMMON_NAME), &utf8(cn.as_bytes())]);
    seq(&[&tlv(0x31, &atv)])
}

/// GeneralizedTime `YYYYMMDDHHMMSSZ` of Unix seconds.
pub fn generalized_time(secs: u64) -> Vec<u8> {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil(days as i64);
    let text = format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    );
    tlv(0x18, text.as_bytes())
}

/// Howard Hinnant's `civil_from_days`.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// An `Extension`.
pub fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![tlv(0x06, oid)];
    if critical {
        parts.push(tlv(0x01, &[0xFF]));
    }
    parts.push(tlv(0x04, value));
    tlv(0x30, &parts.concat())
}

pub fn basic_constraints_ca() -> Vec<u8> {
    ext(BASIC_CONSTRAINTS, true, &seq(&[&tlv(0x01, &[0xFF])]))
}

pub fn key_usage(bits: u8) -> Vec<u8> {
    ext(KEY_USAGE, true, &tlv(0x03, &[0x01, bits]))
}

pub fn eku(purposes: &[&[u8]]) -> Vec<u8> {
    let oids: Vec<u8> = purposes.iter().flat_map(|p| tlv(0x06, p)).collect();
    ext(EXT_KEY_USAGE, false, &tlv(0x30, &oids))
}

/// A critical subjectAltName of `(tag, value)` GeneralNames.
pub fn san(names: &[(u8, &[u8])]) -> Vec<u8> {
    let names: Vec<u8> = names.iter().flat_map(|(t, v)| tlv(*t, v)).collect();
    ext(SUBJECT_ALT_NAME, true, &tlv(0x30, &names))
}

// ---- Keys -------------------------------------------------------------

/// A test key pair: the signer and its public key.
pub struct Key {
    pub private: RsaSha256Key,
    pub public: PublicKey,
}

impl Key {
    fn load(private: &[u8], public: &[u8]) -> Key {
        Key {
            private: RsaSha256Key::from_pem(&mut private.to_vec()).expect("test key"),
            public: PublicKey::from_pem(public).expect("test public key"),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.private.sign(message).expect("sign")
    }

    pub fn spki(&self) -> Vec<u8> {
        self.public.spki_der().to_vec()
    }

    pub fn id(&self) -> [u8; 32] {
        self.public.key_id()
    }
}

/// The test instance: its keys and the CA certificates.
pub struct Pki {
    pub root_key: Key,
    pub intermediate_key: Key,
    pub attacker_key: Key,
    pub leaf_key: Key,
    pub ct_key: Key,
    pub rekor_key: Key,
    pub signer_key: Key,
    pub other_key: Key,
    pub root: Vec<u8>,
    pub intermediate: Vec<u8>,
    /// An intermediate an attacker made: same name as ours, own key,
    /// self-signed, so no root of the instance vouches for it.
    pub attacker_intermediate: Vec<u8>,
}

/// A certificate to build.
#[derive(Clone)]
pub struct CertSpec {
    pub serial: u8,
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub spki: Vec<u8>,
    pub extensions: Vec<Vec<u8>>,
}

impl CertSpec {
    pub fn tbs(&self) -> Vec<u8> {
        let mut parts = vec![
            tlv(0xA0, &tlv(0x02, &[2])),
            tlv(0x02, &[self.serial]),
            RSA_SHA256.to_vec(),
            self.issuer.clone(),
            seq(&[
                &generalized_time(self.not_before),
                &generalized_time(self.not_after),
            ]),
            self.subject.clone(),
            self.spki.clone(),
        ];
        if !self.extensions.is_empty() {
            parts.push(tlv(0xA3, &tlv(0x30, &self.extensions.concat())));
        }
        tlv(0x30, &parts.concat())
    }

    pub fn sign(&self, key: &Key) -> Vec<u8> {
        let tbs = self.tbs();
        let mut bits = vec![0];
        bits.extend(key.sign(&tbs));
        seq(&[&tbs, RSA_SHA256, &tlv(0x03, &bits)])
    }
}

pub const ROOT_NAME: &str = "Boneli sigstore test root";
pub const INTERMEDIATE_NAME: &str = "Boneli sigstore test intermediate";

impl Pki {
    pub fn new() -> Pki {
        let root_key = Key::load(
            include_bytes!("../data/test-only-root.key"),
            include_bytes!("../data/test-only-root.pub.pem"),
        );
        let intermediate_key = Key::load(
            include_bytes!("../data/test-only-intermediate.key"),
            include_bytes!("../data/test-only-intermediate.pub.pem"),
        );
        let attacker_key = Key::load(
            include_bytes!("../data/test-only-attacker-ca.key"),
            include_bytes!("../data/test-only-attacker-ca.pub.pem"),
        );
        let ca = |serial, issuer: &str, key: &Key, eku_on: bool| CertSpec {
            serial,
            issuer: name(issuer),
            subject: name(if serial == 1 {
                ROOT_NAME
            } else {
                INTERMEDIATE_NAME
            }),
            not_before: T - 365 * 86_400,
            not_after: T + 10 * 365 * 86_400,
            spki: key.spki(),
            extensions: {
                let mut e = vec![basic_constraints_ca(), key_usage(0x06)];
                if eku_on {
                    e.push(eku(&[CODE_SIGNING]));
                }
                e
            },
        };
        let root = ca(1, ROOT_NAME, &root_key, false).sign(&root_key);
        let intermediate = ca(2, ROOT_NAME, &intermediate_key, true).sign(&root_key);
        let attacker_intermediate =
            ca(3, INTERMEDIATE_NAME, &attacker_key, true).sign(&attacker_key);
        Pki {
            root_key,
            intermediate_key,
            attacker_key,
            leaf_key: Key::load(
                include_bytes!("../data/test-only-leaf.key"),
                include_bytes!("../data/test-only-leaf.pub.pem"),
            ),
            ct_key: Key::load(
                include_bytes!("../data/test-only-ct-log.key"),
                include_bytes!("../data/test-only-ct-log.pub.pem"),
            ),
            rekor_key: Key::load(
                include_bytes!("../data/test-only-rekor.key"),
                include_bytes!("../data/test-only-rekor.pub.pem"),
            ),
            signer_key: Key::load(
                include_bytes!("../data/test-only-signer.key"),
                include_bytes!("../data/test-only-signer.pub.pem"),
            ),
            other_key: Key::load(
                include_bytes!("../data/test-only-other.key"),
                include_bytes!("../data/test-only-other.pub.pem"),
            ),
            root,
            intermediate,
            attacker_intermediate,
        }
    }
}

// ---- Leaves and SCTs --------------------------------------------------

/// Who signs an SCT and over what.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SctSigner {
    /// The test CT log.
    Ct,
    /// A key the root does not list as a CT log.
    Other,
}

#[derive(Clone)]
pub struct SctSpec {
    pub timestamp_ms: u64,
    pub signer: SctSigner,
    /// Sign over the TBS of a leaf with another serial number.
    pub over_other_tbs: bool,
}

impl SctSpec {
    pub fn good() -> SctSpec {
        SctSpec {
            timestamp_ms: SCT_MS,
            signer: SctSigner::Ct,
            over_other_tbs: false,
        }
    }
}

/// Which CA issues a leaf.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LeafIssuer {
    Intermediate,
    Attacker,
}

/// A Fulcio-shaped leaf to build.
#[derive(Clone)]
pub struct LeafSpec {
    pub serial: u8,
    pub not_before: u64,
    pub not_after: u64,
    pub issuer: LeafIssuer,
    /// The SAN extension, whole; `None` leaves it out.
    pub san: Option<Vec<u8>>,
    /// The raw value of extension 1.1; `None` leaves it out.
    pub issuer_v1: Option<Vec<u8>>,
    /// The raw value (a whole TLV) of extension 1.8; `None` leaves it out.
    pub issuer_v2: Option<Vec<u8>>,
    /// EKU purposes; `None` leaves the extension out.
    pub eku: Option<Vec<&'static [u8]>>,
    pub ca: bool,
    pub scts: Vec<SctSpec>,
}

impl LeafSpec {
    /// An email SAN, both issuer extensions naming [`ISSUER`], one SCT.
    pub fn email() -> LeafSpec {
        LeafSpec {
            serial: 7,
            not_before: T,
            not_after: T + LIFETIME,
            issuer: LeafIssuer::Intermediate,
            san: Some(san(&[(RFC822_NAME, EMAIL.as_bytes())])),
            issuer_v1: Some(ISSUER.as_bytes().to_vec()),
            issuer_v2: Some(utf8(ISSUER.as_bytes())),
            eku: Some(vec![CODE_SIGNING]),
            ca: false,
            scts: vec![SctSpec::good()],
        }
    }

    /// A URI SAN, as GitHub Actions' leaves.
    pub fn uri(uri: &str) -> LeafSpec {
        LeafSpec {
            san: Some(san(&[(URI_NAME, uri.as_bytes())])),
            ..LeafSpec::email()
        }
    }

    fn spec(&self, pki: &Pki, serial: u8, extensions: Vec<Vec<u8>>) -> CertSpec {
        CertSpec {
            serial,
            issuer: name(INTERMEDIATE_NAME),
            subject: seq(&[]),
            not_before: self.not_before,
            not_after: self.not_after,
            spki: pki.leaf_key.spki(),
            extensions,
        }
    }

    fn extensions(&self) -> Vec<Vec<u8>> {
        let mut e = vec![key_usage(0x80)];
        if let Some(purposes) = &self.eku {
            e.push(eku(purposes));
        }
        if self.ca {
            e.push(basic_constraints_ca());
        }
        e.extend(self.san.clone());
        if let Some(v1) = &self.issuer_v1 {
            e.push(ext(ISSUER_V1, false, v1));
        }
        if let Some(v2) = &self.issuer_v2 {
            e.push(ext(ISSUER_V2, false, v2));
        }
        e
    }

    pub fn build(&self, pki: &Pki) -> Vec<u8> {
        let (ca_cert, ca_key) = match self.issuer {
            LeafIssuer::Intermediate => (&pki.intermediate, &pki.intermediate_key),
            LeafIssuer::Attacker => (&pki.attacker_intermediate, &pki.attacker_key),
        };
        let issuer_key_hash = Sha256::digest(&spki_of(ca_cert));
        let base = self.extensions();
        let precert = self.spec(pki, self.serial, base.clone()).tbs();
        let other = self
            .spec(pki, self.serial.wrapping_add(1), base.clone())
            .tbs();
        let mut extensions = base;
        if !self.scts.is_empty() {
            let scts: Vec<Vec<u8>> = self
                .scts
                .iter()
                .map(|s| {
                    let tbs = if s.over_other_tbs { &other } else { &precert };
                    let key = match s.signer {
                        SctSigner::Ct => &pki.ct_key,
                        SctSigner::Other => &pki.other_key,
                    };
                    sct(key, s.timestamp_ms, &issuer_key_hash, tbs)
                })
                .collect();
            extensions.push(ext(SCT_LIST, false, &tlv(0x04, &tls_list(&scts))));
        }
        self.spec(pki, self.serial, extensions).sign(ca_key)
    }
}

/// One v1 SCT over a precertificate entry, signed by `key` (RSA).
fn sct(key: &Key, timestamp_ms: u64, issuer_key_hash: &[u8; 32], tbs: &[u8]) -> Vec<u8> {
    let mut signed = vec![0, 0];
    signed.extend_from_slice(&timestamp_ms.to_be_bytes());
    signed.extend_from_slice(&[0, 1]);
    signed.extend_from_slice(issuer_key_hash);
    signed.extend_from_slice(&(tbs.len() as u32).to_be_bytes()[1..]);
    signed.extend_from_slice(tbs);
    signed.extend_from_slice(&[0, 0]);
    let signature = key.sign(&signed);
    let mut out = vec![0];
    out.extend_from_slice(&key.id());
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out.extend_from_slice(&[0, 0, 4, 1]);
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(&signature);
    out
}

fn tls_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut entries = Vec::new();
    for item in items {
        entries.extend_from_slice(&(item.len() as u16).to_be_bytes());
        entries.extend_from_slice(item);
    }
    let mut out = (entries.len() as u16).to_be_bytes().to_vec();
    out.extend(entries);
    out
}

/// The SubjectPublicKeyInfo of a certificate built here: the seventh
/// element of its TBS.
pub fn spki_of(cert: &[u8]) -> Vec<u8> {
    let tbs = elements(content(cert))[0].clone();
    elements(content(&tbs))[6].clone()
}

fn content(der: &[u8]) -> &[u8] {
    let (len, header) = length(&der[1..]);
    &der[1 + header..1 + header + len]
}

fn length(b: &[u8]) -> (usize, usize) {
    if b[0] < 0x80 {
        (usize::from(b[0]), 1)
    } else {
        let n = usize::from(b[0] & 0x7F);
        let len = b[1..=n].iter().fold(0, |acc, x| acc << 8 | usize::from(*x));
        (len, 1 + n)
    }
}

fn elements(mut der: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !der.is_empty() {
        let (len, header) = length(&der[1..]);
        let end = 1 + header + len;
        out.push(der[..end].to_vec());
        der = &der[end..];
    }
    out
}

/// Go's `pem.Encode` of a certificate.
pub fn pem(der: &[u8]) -> String {
    let b64 = base64::encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

// ---- trusted_root.json ------------------------------------------------

pub fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

pub fn s(text: &str) -> Value {
    Value::String(text.to_owned())
}

pub fn valid_for(start: &str, end: Option<&str>) -> Value {
    let mut members = vec![("start", s(start))];
    if let Some(end) = end {
        members.push(("end", s(end)));
    }
    obj(members)
}

/// A `TransparencyLogInstance` for an RSA-2048 test key.
pub fn log_instance(key: &Key, start: &str, end: Option<&str>) -> Value {
    obj(vec![
        ("baseUrl", s("https://log.boneli.test")),
        ("hashAlgorithm", s("SHA2_256")),
        (
            "publicKey",
            obj(vec![
                ("rawBytes", s(&base64::encode(&key.spki()))),
                ("keyDetails", s("PKIX_RSA_PKCS1V15_2048_SHA256")),
                ("validFor", valid_for(start, end)),
            ]),
        ),
        ("logId", obj(vec![("keyId", s(&base64::encode(&key.id())))])),
    ])
}

pub fn authority(chain: &[&[u8]], start: &str, end: Option<&str>) -> Value {
    let certificates = chain
        .iter()
        .map(|c| obj(vec![("rawBytes", s(&base64::encode(c)))]))
        .collect();
    obj(vec![
        ("subject", obj(vec![("commonName", s(ROOT_NAME))])),
        (
            "certChain",
            obj(vec![("certificates", Value::Array(certificates))]),
        ),
        ("validFor", valid_for(start, end)),
    ])
}

pub const EPOCH_2020: &str = "2020-01-01T00:00:00Z";

/// The trusted root of the test instance: the test Rekor, the
/// intermediate and root, and the test CT log, each valid from 2020 on.
pub fn root_value(pki: &Pki) -> Value {
    obj(vec![
        (
            "mediaType",
            s("application/vnd.dev.sigstore.trustedroot+json;version=0.1"),
        ),
        (
            "tlogs",
            Value::Array(vec![log_instance(&pki.rekor_key, EPOCH_2020, None)]),
        ),
        (
            "certificateAuthorities",
            Value::Array(vec![authority(
                &[&pki.intermediate, &pki.root],
                EPOCH_2020,
                None,
            )]),
        ),
        (
            "ctlogs",
            Value::Array(vec![log_instance(&pki.ct_key, EPOCH_2020, None)]),
        ),
    ])
}

pub fn to_bytes(value: &Value) -> Vec<u8> {
    boneli_json::to_vec(value).expect("serialize")
}

/// Sets `path` (object keys) in `value` to `new`.
pub fn set(value: &mut Value, path: &[&str], new: Value) {
    let (last, parents) = path.split_last().expect("path");
    let mut at = value;
    for key in parents {
        at = match at {
            Value::Object(o) => o.get_mut(key).expect("member"),
            _ => panic!("not an object"),
        };
    }
    match at {
        Value::Object(o) => {
            o.insert(*last, new);
        }
        _ => panic!("not an object"),
    }
}

/// Removes `path` from `value`.
pub fn remove(value: &mut Value, path: &[&str]) {
    let (last, parents) = path.split_last().expect("path");
    let mut at = value;
    for key in parents {
        at = match at {
            Value::Object(o) => o.get_mut(key).expect("member"),
            _ => panic!("not an object"),
        };
    }
    match at {
        Value::Object(o) => {
            o.remove(last);
        }
        _ => panic!("not an object"),
    }
}

// ---- Signatures -------------------------------------------------------

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The digest of the synthetic image every built signature names.
pub const IMAGE: [u8; 32] = [0xA5; 32];
/// Another image's digest.
pub const OTHER_IMAGE: [u8; 32] = [0x5A; 32];

/// A simple-signing payload naming `digest` (text after `sha256:`).
pub fn simple_signing(digest: &str, kind: &str) -> Vec<u8> {
    format!(
        "{{\"critical\":{{\"identity\":{{\"docker-reference\":\"registry.boneli.test/app\"}},\
         \"image\":{{\"docker-manifest-digest\":\"sha256:{digest}\"}},\"type\":\"{kind}\"}},\
         \"optional\":null}}"
    )
    .into_bytes()
}

pub fn payload_for(digest: &[u8; 32]) -> Vec<u8> {
    simple_signing(&hex(digest), "cosign container image signature")
}

/// A `hashedrekord` 0.0.1 body.
pub fn hashedrekord(payload: &[u8], signature: &[u8], certificate: &[u8]) -> Value {
    obj(vec![
        ("apiVersion", s("0.0.1")),
        ("kind", s("hashedrekord")),
        (
            "spec",
            obj(vec![
                (
                    "data",
                    obj(vec![(
                        "hash",
                        obj(vec![
                            ("algorithm", s("sha256")),
                            ("value", s(&hex(&Sha256::digest(payload)))),
                        ]),
                    )]),
                ),
                (
                    "signature",
                    obj(vec![
                        ("content", s(&base64::encode(signature))),
                        (
                            "publicKey",
                            obj(vec![(
                                "content",
                                s(&base64::encode(pem(certificate).as_bytes())),
                            )]),
                        ),
                    ]),
                ),
            ]),
        ),
    ])
}

/// A `dsse` 0.0.1 body.
pub fn dsse_body(payload: &[u8], signature: &[u8], certificate: &[u8]) -> Value {
    obj(vec![
        ("apiVersion", s("0.0.1")),
        ("kind", s("dsse")),
        (
            "spec",
            obj(vec![
                (
                    "envelopeHash",
                    obj(vec![
                        ("algorithm", s("sha256")),
                        ("value", s(&hex(&[0; 32]))),
                    ]),
                ),
                (
                    "payloadHash",
                    obj(vec![
                        ("algorithm", s("sha256")),
                        ("value", s(&hex(&Sha256::digest(payload)))),
                    ]),
                ),
                (
                    "signatures",
                    Value::Array(vec![obj(vec![
                        ("signature", s(&base64::encode(signature))),
                        ("verifier", s(&base64::encode(pem(certificate).as_bytes()))),
                    ])]),
                ),
            ]),
        ),
    ])
}

/// The JCS bytes a SET signs.
pub fn set_message(
    body: &[u8],
    integrated_time: u64,
    log_id: &[u8; 32],
    log_index: u64,
) -> Vec<u8> {
    format!(
        "{{\"body\":\"{}\",\"integratedTime\":{integrated_time},\"logID\":\"{}\",\"logIndex\":{log_index}}}",
        base64::encode(body),
        hex(log_id)
    )
    .into_bytes()
}

/// A log entry to build.
pub struct EntrySpec {
    pub body: Vec<u8>,
    pub integrated_time: u64,
    pub log_index: u64,
    pub log_id: [u8; 32],
    /// The SET; `None` signs it with the test Rekor key.
    pub set: Option<Vec<u8>>,
}

impl EntrySpec {
    pub fn new(pki: &Pki, body: &Value) -> EntrySpec {
        EntrySpec {
            body: to_bytes(body),
            integrated_time: INTEGRATED,
            log_index: LOG_INDEX,
            log_id: pki.rekor_key.id(),
            set: None,
        }
    }

    pub fn signed_set(&self, pki: &Pki) -> Vec<u8> {
        self.set.clone().unwrap_or_else(|| {
            pki.rekor_key.sign(&set_message(
                &self.body,
                self.integrated_time,
                &self.log_id,
                self.log_index,
            ))
        })
    }

    /// cosign's `dev.sigstore.cosign/bundle` annotation.
    pub fn cosign_annotation(&self, pki: &Pki) -> Value {
        obj(vec![
            (
                "SignedEntryTimestamp",
                s(&base64::encode(&self.signed_set(pki))),
            ),
            (
                "Payload",
                obj(vec![
                    ("body", s(&base64::encode(&self.body))),
                    ("integratedTime", Value::Number(self.integrated_time.into())),
                    ("logIndex", Value::Number(self.log_index.into())),
                    ("logID", s(&hex(&self.log_id))),
                ]),
            ),
        ])
    }

    /// A bundle's `TransparencyLogEntry`.
    pub fn bundle_entry(&self, pki: &Pki, kind: &str) -> Value {
        obj(vec![
            ("logIndex", s(&self.log_index.to_string())),
            (
                "logId",
                obj(vec![("keyId", s(&base64::encode(&self.log_id)))]),
            ),
            (
                "kindVersion",
                obj(vec![("kind", s(kind)), ("version", s("0.0.1"))]),
            ),
            ("integratedTime", s(&self.integrated_time.to_string())),
            (
                "inclusionPromise",
                obj(vec![(
                    "signedEntryTimestamp",
                    s(&base64::encode(&self.signed_set(pki))),
                )]),
            ),
            ("canonicalizedBody", s(&base64::encode(&self.body))),
        ])
    }
}

/// A keyless cosign layer: the leaf signs `payload`, the body and the SET
/// are the test Rekor's.
pub struct CosignLayer {
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub certificate: Vec<u8>,
    pub entry: EntrySpec,
}

impl CosignLayer {
    pub fn keyless(pki: &Pki, leaf: &LeafSpec, digest: &[u8; 32]) -> CosignLayer {
        let payload = payload_for(digest);
        let signature = pki.leaf_key.sign(&payload);
        let certificate = leaf.build(pki);
        let body = hashedrekord(&payload, &signature, &certificate);
        CosignLayer {
            entry: EntrySpec::new(pki, &body),
            payload,
            signature,
            certificate,
        }
    }

    pub fn annotations(&self, pki: &Pki) -> Vec<(String, String)> {
        vec![
            (
                SIGNATURE_ANNOTATION.to_owned(),
                base64::encode(&self.signature),
            ),
            (CERTIFICATE_ANNOTATION.to_owned(), pem(&self.certificate)),
            (
                BUNDLE_ANNOTATION.to_owned(),
                String::from_utf8(to_bytes(&self.entry.cosign_annotation(pki))).expect("UTF-8"),
            ),
        ]
    }

    pub fn evidence(
        &self,
        pki: &Pki,
    ) -> Result<boneli_sigstore::Evidence, boneli_sigstore::Refusal> {
        let owned = self.annotations(pki);
        let pairs: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        boneli_sigstore::Evidence::from_cosign_layer(&pairs, &self.payload)
    }
}

/// An in-toto statement over `subjects` (hex) with `predicate_type`.
pub fn statement(subjects: &[&str], predicate_type: &str) -> Vec<u8> {
    let subjects = subjects
        .iter()
        .map(|d| {
            obj(vec![
                ("name", s("registry.boneli.test/app")),
                ("digest", obj(vec![("sha256", s(d))])),
            ])
        })
        .collect();
    to_bytes(&obj(vec![
        ("_type", s(STATEMENT_V1)),
        ("subject", Value::Array(subjects)),
        ("predicateType", s(predicate_type)),
        ("predicate", obj(vec![])),
    ]))
}

/// A keyless DSSE bundle: the leaf signs the PAE of `statement`.
pub struct BundleSpec {
    pub statement: Vec<u8>,
    pub signature: Vec<u8>,
    pub certificate: Vec<u8>,
    pub entry: EntrySpec,
}

impl BundleSpec {
    pub fn keyless(pki: &Pki, leaf: &LeafSpec, digest: &[u8; 32]) -> BundleSpec {
        BundleSpec::keyless_statement(pki, leaf, statement(&[&hex(digest)], COSIGN_SIGN_PREDICATE))
    }

    pub fn keyless_statement(pki: &Pki, leaf: &LeafSpec, statement: Vec<u8>) -> BundleSpec {
        let signature = pki
            .leaf_key
            .sign(&pae(IN_TOTO_PAYLOAD_TYPE.as_bytes(), &statement));
        let certificate = leaf.build(pki);
        let body = dsse_body(&statement, &signature, &certificate);
        BundleSpec {
            entry: EntrySpec::new(pki, &body),
            statement,
            signature,
            certificate,
        }
    }

    pub fn value(&self, pki: &Pki) -> Value {
        obj(vec![
            ("mediaType", s(BUNDLE_V03_MEDIA_TYPE)),
            (
                "verificationMaterial",
                obj(vec![
                    (
                        "certificate",
                        obj(vec![("rawBytes", s(&base64::encode(&self.certificate)))]),
                    ),
                    (
                        "tlogEntries",
                        Value::Array(vec![self.entry.bundle_entry(pki, "dsse")]),
                    ),
                ]),
            ),
            (
                "dsseEnvelope",
                obj(vec![
                    ("payload", s(&base64::encode(&self.statement))),
                    ("payloadType", s(IN_TOTO_PAYLOAD_TYPE)),
                    (
                        "signatures",
                        Value::Array(vec![obj(vec![
                            ("sig", s(&base64::encode(&self.signature))),
                            ("keyid", s("")),
                        ])]),
                    ),
                ]),
            ),
        ])
    }

    pub fn bytes(&self, pki: &Pki) -> Vec<u8> {
        to_bytes(&self.value(pki))
    }
}

/// A keyed bundle: `key` signs the PAE of `statement`; no log entry.
pub fn keyed_bundle(key: &Key, statement: &[u8]) -> Value {
    let signature = key.sign(&pae(IN_TOTO_PAYLOAD_TYPE.as_bytes(), statement));
    obj(vec![
        ("mediaType", s(BUNDLE_V03_MEDIA_TYPE)),
        (
            "verificationMaterial",
            obj(vec![(
                "publicKey",
                obj(vec![("hint", s(&base64::encode(&key.id())))]),
            )]),
        ),
        (
            "dsseEnvelope",
            obj(vec![
                ("payload", s(&base64::encode(statement))),
                ("payloadType", s(IN_TOTO_PAYLOAD_TYPE)),
                (
                    "signatures",
                    Value::Array(vec![obj(vec![("sig", s(&base64::encode(&signature)))])]),
                ),
            ]),
        ),
    ])
}

/// Keyed cosign annotations: `key` signs `payload`.
pub fn keyed_layer(key: &Key, payload: &[u8]) -> Vec<(String, String)> {
    vec![(
        SIGNATURE_ANNOTATION.to_owned(),
        base64::encode(&key.sign(payload)),
    )]
}

// ---- Trusts -----------------------------------------------------------

pub fn trusted_root(value: &Value) -> std::sync::Arc<boneli_sigstore::TrustedRoot> {
    std::sync::Arc::new(boneli_sigstore::TrustedRoot::from_json(&to_bytes(value)).expect("root"))
}

/// A keyless trust in the test instance's root (`root_value`) for
/// `identities`, with the default predicate list.
pub fn keyless_trust(
    pki: &Pki,
    identities: Vec<boneli_sigstore::Identity>,
) -> boneli_sigstore::Trust {
    keyless_trust_in(&root_value(pki), identities)
}

pub fn keyless_trust_in(
    root: &Value,
    identities: Vec<boneli_sigstore::Identity>,
) -> boneli_sigstore::Trust {
    boneli_sigstore::Trust::new(
        Vec::new(),
        Some((trusted_root(root), identities)),
        vec![COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust")
}

pub fn email_identity() -> boneli_sigstore::Identity {
    boneli_sigstore::Identity::new(ISSUER, boneli_sigstore::SanRule::Email(EMAIL.to_owned()))
        .expect("identity")
}

/// Verifies a keyless cosign layer built from `leaf` over `IMAGE`.
pub fn verify_leaf(
    pki: &Pki,
    leaf: &LeafSpec,
    trust: &boneli_sigstore::Trust,
) -> Result<boneli_sigstore::Accepted, boneli_sigstore::Refusal> {
    let evidence = CosignLayer::keyless(pki, leaf, &IMAGE).evidence(pki)?;
    boneli_sigstore::verify(&evidence, &IMAGE, trust)
}

/// A keyed trust in the test signer's key, with `predicates`.
pub fn keyed_trust(pki: &Pki, predicates: &[&str]) -> boneli_sigstore::Trust {
    boneli_sigstore::Trust::new(
        vec![pki.signer_key.public.clone()],
        None,
        predicates.iter().map(|p| (*p).to_owned()).collect(),
    )
    .expect("trust")
}

impl CosignLayer {
    /// Logs the layer's current payload, signature and certificate again:
    /// a new body, signed by the test Rekor.
    pub fn relog(&mut self, pki: &Pki) {
        let body = hashedrekord(&self.payload, &self.signature, &self.certificate);
        self.entry = EntrySpec::new(pki, &body);
    }
}

/// Unix seconds as RFC 3339 with milliseconds.
pub fn rfc3339_ms(ms: u64) -> String {
    let secs = ms / 1_000;
    let (y, m, d) = civil((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60,
        ms % 1_000
    )
}
