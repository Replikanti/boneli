//! Key entries (ADR-033, item 3). One kind counts: key type `ecdsa` or
//! `ecdsa-sha2-nistp256` (Sigstore's roots use the second up to v8 and
//! the first from v9), scheme `ecdsa-sha2-nistp256`, and a `PUBLIC KEY`
//! PEM in `keyval.public` that `PublicKey::from_pem` reads as P-256.
//! Everything else, Sigstore's hex keys of v1 to v4 included, is `None`:
//! it counts zero towards a threshold and does not refuse the document,
//! so a root may list a key of another kind and still pass on the others.

use boneli_https::{KeyKind, PublicKey};
use boneli_json::Value;

/// The key of entry `entry`, if it is of the one kind that counts.
pub(crate) fn public_key(entry: &Value) -> Option<PublicKey> {
    let keytype = entry.get("keytype")?.as_str()?;
    if keytype != "ecdsa" && keytype != "ecdsa-sha2-nistp256" {
        return None;
    }
    if entry.get("scheme")?.as_str()? != "ecdsa-sha2-nistp256" {
        return None;
    }
    let pem = entry.get("keyval")?.get("public")?.as_str()?;
    let key = PublicKey::from_pem(pem.as_bytes()).ok()?;
    (key.kind() == KeyKind::EcdsaP256).then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boneli_json::Object;

    const P256: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEXsz3SZXFb8jMV42j6pJlyjbjR8K\nN3Bwocexq6LMIb5qsWKOQvLN16NUefLc4HswOoumRsVVaajSpQS6fobkRw==\n-----END PUBLIC KEY-----\n";
    const P384: &str = include_str!("../tests/data/pubkey-p384.pem");
    const ED25519: &str = include_str!("../tests/data/pubkey-ed25519.pem");
    const RSA: &str = include_str!("../tests/data/pubkey-rsa2048.pem");

    fn entry(keytype: &str, scheme: &str, public: &str) -> Value {
        let mut keyval = Object::new();
        keyval.insert("public", public);
        let mut o = Object::new();
        o.insert("keytype", keytype);
        o.insert("scheme", scheme);
        o.insert("keyval", Value::Object(keyval));
        Value::Object(o)
    }

    #[test]
    fn p256_under_both_key_types() {
        for keytype in ["ecdsa", "ecdsa-sha2-nistp256"] {
            let key = public_key(&entry(keytype, "ecdsa-sha2-nistp256", P256));
            assert_eq!(key.map(|k| k.kind()), Some(KeyKind::EcdsaP256));
        }
    }

    /// The kind check: a P-384, Ed25519 or RSA key under the accepted key
    /// type and scheme is `None`, so a valid signature of such a key can
    /// never count.
    #[test]
    fn other_kinds_under_the_accepted_labels() {
        for pem in [P384, ED25519, RSA] {
            assert!(public_key(&entry("ecdsa", "ecdsa-sha2-nistp256", pem)).is_none());
        }
    }

    #[test]
    fn labels_and_shapes() {
        for (keytype, scheme, pem) in [
            ("ecdsa", "ecdsa-sha2-nistp384", P256),
            ("ECDSA", "ecdsa-sha2-nistp256", P256),
            ("ed25519", "ecdsa-sha2-nistp256", P256),
            ("ecdsa", "ecdsa-sha2-nistp256 ", P256),
            ("ecdsa", "ecdsa-sha2-nistp256", "04ab"),
            ("ecdsa", "ecdsa-sha2-nistp256", ""),
        ] {
            assert!(
                public_key(&entry(keytype, scheme, pem)).is_none(),
                "{keytype} {scheme}"
            );
        }
        assert!(public_key(&Value::Null).is_none());
        let mut o = Object::new();
        o.insert("keytype", "ecdsa");
        o.insert("scheme", "ecdsa-sha2-nistp256");
        o.insert("keyval", P256);
        assert!(public_key(&Value::Object(o)).is_none());
    }
}
