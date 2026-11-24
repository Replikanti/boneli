//! A fixture-repository builder: metadata written as `boneli_json::Value`,
//! signed over `boneli_tuf::canonical(signed)` with `EcdsaP256Key`, the one
//! scheme production accepts (ADR-033, S4), with knobs for version,
//! expiry, threshold, signer set, `_type` and extra fields.
//!
//! Keys are numbered 1 to 7 (`tests/data/test-only-p256-N.key`). The
//! default root has root and targets keys 1 to 5 with threshold 3 and the
//! online key 6 for timestamp and snapshot with threshold 1, as Sigstore's
//! roots since v10; key 7 is spare for rotations.

use std::sync::OnceLock;

use boneli_https::{EcdsaP256Key, Sha256};
use boneli_json::{Object, Value};
use boneli_sigstore::base64;

/// An expiry far after every start time the tests use.
pub const FAR: &str = "2030-01-01T00:00:00Z";
/// 2030-01-01T00:00:00Z in seconds.
pub const FAR_SECS: u64 = 1_893_456_000;
/// A start time before `FAR`: 2026-11-24T00:00:00Z.
pub const START: u64 = 1_795_478_400;

const KEY_FILES: [&[u8]; 7] = [
    include_bytes!("../data/test-only-p256-1.key"),
    include_bytes!("../data/test-only-p256-2.key"),
    include_bytes!("../data/test-only-p256-3.key"),
    include_bytes!("../data/test-only-p256-4.key"),
    include_bytes!("../data/test-only-p256-5.key"),
    include_bytes!("../data/test-only-p256-6.key"),
    include_bytes!("../data/test-only-p256-7.key"),
];

/// Public keys of kinds the client never counts (copies of
/// `boneli-https`'s fixtures).
pub const P384_PEM: &str = include_str!("../data/pubkey-p384.pem");
pub const ED25519_PEM: &str = include_str!("../data/pubkey-ed25519.pem");
pub const RSA_PEM: &str = include_str!("../data/pubkey-rsa2048.pem");

/// Test key `n` (1 to 7), loaded once.
pub fn key(n: usize) -> &'static EcdsaP256Key {
    static KEYS: OnceLock<Vec<EcdsaP256Key>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        KEY_FILES
            .iter()
            .map(|pem| EcdsaP256Key::from_pem(&mut pem.to_vec()).expect("test key"))
            .collect()
    });
    &keys[n - 1]
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The key ID tests use for key `n`: the SHA-256 of its SPKI, in hex.
/// The client treats key IDs as opaque labels.
pub fn keyid(n: usize) -> String {
    hex(&Sha256::digest(key(n).public_key().spki_der()))
}

/// The `PUBLIC KEY` PEM of key `n`, with line feeds, as Sigstore writes
/// it.
pub fn pem(n: usize) -> String {
    let body = base64::encode(key(n).public_key().spki_der());
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END PUBLIC KEY-----\n");
    out
}

/// A key entry as Sigstore's roots write it since v9.
pub fn key_entry(keytype: &str, scheme: &str, public: &str) -> Value {
    obj([
        ("keytype", s(keytype)),
        ("scheme", s(scheme)),
        ("keyval", obj([("public", s(public))])),
    ])
}

/// The key entry of test key `n`.
pub fn p256_entry(n: usize) -> Value {
    key_entry("ecdsa", "ecdsa-sha2-nistp256", &pem(n))
}

pub fn s(text: &str) -> Value {
    Value::String(text.to_string())
}

pub fn obj<const N: usize>(members: [(&str, Value); N]) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::Object(o)
}

/// `value` with member `key` of its object set to `member`.
pub fn set(value: &mut Value, key: &str, member: Value) {
    match value {
        Value::Object(o) => {
            o.insert(key, member);
        }
        _ => panic!("not an object"),
    }
}

/// `value` with member `key` removed.
pub fn remove(value: &mut Value, key: &str) {
    match value {
        Value::Object(o) => {
            o.remove(key);
        }
        _ => panic!("not an object"),
    }
}

/// The member `path` of nested objects, mutably.
pub fn at<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
    let mut v = value;
    for key in path {
        v = match v {
            Value::Object(o) => o.get_mut(key).expect("member"),
            _ => panic!("not an object"),
        };
    }
    v
}

/// The signature entry of key `n` over `signed`, under its usual key ID.
pub fn signature(n: usize, signed: &Value) -> Value {
    signature_as(&keyid(n), n, signed)
}

/// The signature entry of key `n` over `signed`, under key ID `id`.
pub fn signature_as(id: &str, n: usize, signed: &Value) -> Value {
    let canonical = boneli_tuf::canonical(signed).expect("canonical");
    let sig = key(n).sign(&canonical).expect("sign");
    obj([("keyid", s(id)), ("sig", s(&hex(&sig)))])
}

/// The envelope bytes of `signed` with `signatures`, compact.
pub fn envelope(signed: &Value, signatures: Vec<Value>) -> Vec<u8> {
    let doc = obj([
        ("signed", signed.clone()),
        ("signatures", Value::Array(signatures)),
    ]);
    boneli_json::to_vec(&doc).expect("serialize")
}

/// `signed` signed by keys `signers`, each under its usual key ID.
pub fn signed_by(signed: &Value, signers: &[usize]) -> Vec<u8> {
    let sigs = signers.iter().map(|n| signature(*n, signed)).collect();
    envelope(signed, sigs)
}

/// One role of a root: its keys by test number and its threshold.
#[derive(Clone, Debug)]
pub struct RoleSpec {
    pub keys: Vec<usize>,
    pub threshold: i64,
}

/// A root under construction.
#[derive(Clone, Debug)]
pub struct RootBuilder {
    pub version: i64,
    pub expires: String,
    pub type_: String,
    pub spec_version: String,
    pub consistent_snapshot: bool,
    pub root: RoleSpec,
    pub timestamp: RoleSpec,
    pub snapshot: RoleSpec,
    pub targets: RoleSpec,
}

impl RootBuilder {
    /// The default root at `version`.
    pub fn new(version: i64) -> RootBuilder {
        let offline = RoleSpec {
            keys: vec![1, 2, 3, 4, 5],
            threshold: 3,
        };
        let online = RoleSpec {
            keys: vec![6],
            threshold: 1,
        };
        RootBuilder {
            version,
            expires: FAR.to_string(),
            type_: "root".to_string(),
            spec_version: "1.0".to_string(),
            consistent_snapshot: true,
            root: offline.clone(),
            timestamp: online.clone(),
            snapshot: online,
            targets: offline,
        }
    }

    /// The `signed` value: every key of every role in `keys`, under its
    /// usual key ID.
    pub fn signed(&self) -> Value {
        let mut keys = Object::new();
        for spec in [&self.root, &self.timestamp, &self.snapshot, &self.targets] {
            for n in &spec.keys {
                keys.insert(keyid(*n), p256_entry(*n));
            }
        }
        let role = |spec: &RoleSpec| {
            obj([
                (
                    "keyids",
                    Value::Array(spec.keys.iter().map(|n| s(&keyid(*n))).collect()),
                ),
                ("threshold", Value::from(spec.threshold)),
            ])
        };
        obj([
            ("_type", s(&self.type_)),
            ("spec_version", s(&self.spec_version)),
            ("version", Value::from(self.version)),
            ("expires", s(&self.expires)),
            ("consistent_snapshot", Value::Bool(self.consistent_snapshot)),
            ("keys", Value::Object(keys)),
            (
                "roles",
                obj([
                    ("root", role(&self.root)),
                    ("timestamp", role(&self.timestamp)),
                    ("snapshot", role(&self.snapshot)),
                    ("targets", role(&self.targets)),
                ]),
            ),
        ])
    }

    /// The root signed by keys `signers`.
    pub fn signed_by(&self, signers: &[usize]) -> Vec<u8> {
        signed_by(&self.signed(), signers)
    }

    /// The root signed by its own root keys.
    pub fn bytes(&self) -> Vec<u8> {
        let signers = self.root.keys.clone();
        self.signed_by(&signers)
    }
}
