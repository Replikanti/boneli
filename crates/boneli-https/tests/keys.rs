//! `PublicKey` (ADR-029, S2): every supported kind verifies a signature
//! OpenSSL made, the algorithm follows from the key alone, the refused
//! keys and PEM files are refused, and nothing prints key material. The
//! keys and signatures are fixtures (`tests/data/README.md`).

use boneli_https::{KeyKind, MAX_PUBLIC_KEY_PEM_LEN, PublicKey, PublicKeyError, Sha256};

const MESSAGE: &[u8] = include_bytes!("data/pubkey-message.txt");

const P256: &[u8] = include_bytes!("data/pubkey-p256.pem");
const P384: &[u8] = include_bytes!("data/pubkey-p384.pem");
const ED25519: &[u8] = include_bytes!("data/pubkey-ed25519.pem");
const RSA2048: &[u8] = include_bytes!("data/pubkey-rsa2048.pem");
const RSA8192: &[u8] = include_bytes!("data/pubkey-rsa8192.pem");
const P521: &[u8] = include_bytes!("data/pubkey-p521.pem");
const RSA1024: &[u8] = include_bytes!("data/pubkey-rsa1024.pem");
const DSA: &[u8] = include_bytes!("data/pubkey-dsa.pem");
const CT_LOG_2022: &[u8] = include_bytes!("data/sigstore-ctfe-2022.pem");
const CERT: &[u8] = include_bytes!("data/codesign-root.pem");
const PRIVATE: &[u8] = include_bytes!("data/test-only-ct-log.key");

const SIG_P256: &[u8] = include_bytes!("data/pubkey-p256.sig");
const SIG_P256_SHA384: &[u8] = include_bytes!("data/pubkey-p256-sha384.sig");
const SIG_P384: &[u8] = include_bytes!("data/pubkey-p384.sig");
const SIG_ED25519: &[u8] = include_bytes!("data/pubkey-ed25519.sig");
const SIG_RSA2048: &[u8] = include_bytes!("data/pubkey-rsa2048.sig");
const SIG_RSA8192: &[u8] = include_bytes!("data/pubkey-rsa8192.sig");

fn key(pem: &[u8]) -> PublicKey {
    PublicKey::from_pem(pem).expect("key")
}

/// Every kind, with the signature OpenSSL made with it.
fn cases() -> [(&'static [u8], KeyKind, &'static [u8]); 5] {
    [
        (P256, KeyKind::EcdsaP256, SIG_P256),
        (P384, KeyKind::EcdsaP384, SIG_P384),
        (ED25519, KeyKind::Ed25519, SIG_ED25519),
        (RSA2048, KeyKind::Rsa { bits: 2048 }, SIG_RSA2048),
        (RSA8192, KeyKind::Rsa { bits: 8192 }, SIG_RSA8192),
    ]
}

fn flip(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= 0x01;
    out
}

#[test]
fn each_kind_verifies_an_openssl_signature() {
    for (pem, kind, signature) in cases() {
        let key = key(pem);
        assert_eq!(key.kind(), kind);
        assert_eq!(key.verify(MESSAGE, signature), Ok(()), "{kind:?}");
    }
}

#[test]
fn a_flipped_byte_fails() {
    for (pem, kind, signature) in cases() {
        let key = key(pem);
        let last = signature.len() - 1;
        assert!(
            key.verify(MESSAGE, &flip(signature, last)).is_err(),
            "{kind:?} signature"
        );
        assert!(
            key.verify(&flip(MESSAGE, 0), signature).is_err(),
            "{kind:?} message"
        );
        assert!(key.verify(MESSAGE, &[]).is_err(), "{kind:?} empty");
    }
}

#[test]
fn another_key_fails() {
    for (pem, kind, _) in cases() {
        let key = key(pem);
        for (other_pem, other_kind, other_signature) in cases() {
            if other_pem == pem {
                continue;
            }
            assert!(
                key.verify(MESSAGE, other_signature).is_err(),
                "{kind:?} accepted {other_kind:?}'s signature"
            );
        }
    }
}

/// The key kind fixes the hash: a P-256 key verifies ECDSA with SHA-256
/// only, so OpenSSL's valid ECDSA-SHA384 signature with the same key does
/// not verify.
#[test]
fn the_algorithm_is_fixed_by_the_key_kind() {
    let key = key(P256);
    assert_eq!(key.verify(MESSAGE, SIG_P256), Ok(()));
    assert!(key.verify(MESSAGE, SIG_P256_SHA384).is_err());
}

#[test]
fn refused_keys() {
    assert_eq!(
        PublicKey::from_pem(P521).expect_err("refused"),
        PublicKeyError::UnsupportedAlgorithm
    );
    assert_eq!(
        PublicKey::from_pem(DSA).expect_err("refused"),
        PublicKeyError::UnsupportedAlgorithm
    );
    assert_eq!(
        PublicKey::from_pem(RSA1024).expect_err("refused"),
        PublicKeyError::RsaSize
    );
}

#[test]
fn refused_pem_files() {
    let mut two = P256.to_vec();
    two.extend_from_slice(P384);
    assert_eq!(
        PublicKey::from_pem(&two).expect_err("refused"),
        PublicKeyError::NotOneSection
    );
    let mut with_cert = P256.to_vec();
    with_cert.extend_from_slice(CERT);
    assert_eq!(
        PublicKey::from_pem(&with_cert).expect_err("refused"),
        PublicKeyError::NotOneSection
    );
    assert_eq!(
        PublicKey::from_pem(b"").expect_err("refused"),
        PublicKeyError::NotOneSection
    );
    assert_eq!(
        PublicKey::from_pem(CERT).expect_err("refused"),
        PublicKeyError::NotPublicKey
    );
    assert_eq!(
        PublicKey::from_pem(PRIVATE).expect_err("refused"),
        PublicKeyError::NotPublicKey
    );
    let rsa_label = String::from_utf8(RSA2048.to_vec())
        .expect("fixture")
        .replace("PUBLIC KEY", "RSA PUBLIC KEY");
    assert_eq!(
        PublicKey::from_pem(rsa_label.as_bytes()).expect_err("refused"),
        PublicKeyError::NotPublicKey
    );
    let corrupt = String::from_utf8(P256.to_vec())
        .expect("fixture")
        .replace('M', "*");
    assert_eq!(
        PublicKey::from_pem(corrupt.as_bytes()).expect_err("refused"),
        PublicKeyError::CorruptPem
    );
}

/// The size cap is inclusive: text around the section up to exactly
/// `MAX_PUBLIC_KEY_PEM_LEN` bytes is accepted, one byte more is refused
/// before anything is parsed.
#[test]
fn pem_size_cap_inclusive() {
    assert_eq!(MAX_PUBLIC_KEY_PEM_LEN, 8_192);
    let mut at_cap = vec![b'#'; MAX_PUBLIC_KEY_PEM_LEN - RSA8192.len() - 1];
    at_cap.push(b'\n');
    at_cap.extend_from_slice(RSA8192);
    assert_eq!(at_cap.len(), MAX_PUBLIC_KEY_PEM_LEN);
    assert_eq!(
        PublicKey::from_pem(&at_cap).expect("at the cap").kind(),
        KeyKind::Rsa { bits: 8192 }
    );
    let mut over = vec![b'#'];
    over.extend_from_slice(&at_cap);
    assert_eq!(
        PublicKey::from_pem(&over).expect_err("refused"),
        PublicKeyError::TooLarge
    );
}

#[test]
fn from_spki_der_round_trips() {
    for (pem, kind, signature) in cases() {
        let key = key(pem);
        let again = PublicKey::from_spki_der(key.spki_der()).expect("DER");
        assert_eq!(again.kind(), kind);
        assert_eq!(again.spki_der(), key.spki_der());
        assert_eq!(again.verify(MESSAGE, signature), Ok(()));
    }
}

#[test]
fn malformed_spki_refused() {
    let der = key(P256).spki_der().to_vec();
    let mut trailing = der.clone();
    trailing.push(0);
    assert_eq!(
        PublicKey::from_spki_der(&trailing).expect_err("refused"),
        PublicKeyError::Malformed
    );
    assert_eq!(
        PublicKey::from_spki_der(&[]).expect_err("refused"),
        PublicKeyError::Malformed
    );
    // A compressed P-256 point: ring verifies uncompressed points only.
    // `30 59`, the 21-byte AlgorithmIdentifier, `03 42 00 04` X Y.
    let algorithm = &der[2..23];
    let x = &der[27..59];
    let mut compressed = vec![0x30, 0x39];
    compressed.extend_from_slice(algorithm);
    compressed.extend_from_slice(&[0x03, 0x22, 0x00, 0x02]);
    compressed.extend_from_slice(x);
    assert_eq!(
        PublicKey::from_spki_der(&compressed).expect_err("refused"),
        PublicKeyError::Malformed
    );
}

/// Every prefix of every key file is an error or (the whole file) a key,
/// never a panic.
#[test]
fn truncated_keys_never_panic() {
    for (pem, _, _) in cases() {
        let der = key(pem).spki_der().to_vec();
        for n in 0..der.len() {
            assert!(
                PublicKey::from_spki_der(&der[..n]).is_err(),
                "DER prefix {n}"
            );
        }
        for n in 0..pem.len() {
            let _ = PublicKey::from_pem(&pem[..n]);
        }
    }
}

/// The key ID is the SHA-256 of the SPKI DER: RFC 6962's log ID. Known
/// answer: the `logId.keyId` of `ctfe.sigstore.dev/2022` in Sigstore's
/// public-good `trusted_root.json`.
#[test]
fn key_id_is_the_rfc_6962_log_id() {
    let ct = key(CT_LOG_2022);
    assert_eq!(ct.kind(), KeyKind::EcdsaP256);
    let expected = [
        0xdd, 0x3d, 0x30, 0x6a, 0xc6, 0xc7, 0x11, 0x32, 0x63, 0x19, 0x1e, 0x1c, 0x99, 0x67, 0x37,
        0x02, 0xa2, 0x4a, 0x5e, 0xb8, 0xde, 0x3c, 0xad, 0xff, 0x87, 0x8a, 0x72, 0x80, 0x2f, 0x29,
        0xee, 0x8e,
    ];
    assert_eq!(ct.key_id(), expected);
    assert_eq!(ct.key_id(), Sha256::digest(ct.spki_der()));
}

#[test]
fn debug_prints_the_kind_only() {
    let shown = format!("{:?}", key(RSA2048));
    assert_eq!(shown, "PublicKey { kind: Rsa { bits: 2048 } }");
}

#[test]
fn error_texts() {
    for (error, text) in [
        (
            PublicKeyError::TooLarge,
            "the public key file is larger than 8192 bytes",
        ),
        (
            PublicKeyError::NotOneSection,
            "the public key file must hold exactly one PEM section",
        ),
        (
            PublicKeyError::NotPublicKey,
            "the PEM section must be a PUBLIC KEY",
        ),
        (PublicKeyError::CorruptPem, "the PEM section is corrupt"),
        (PublicKeyError::Malformed, "the public key is malformed"),
        (
            PublicKeyError::UnsupportedAlgorithm,
            "the public key is not ECDSA P-256 or P-384, Ed25519 or RSA",
        ),
        (
            PublicKeyError::RsaSize,
            "the RSA key is not between 2048 and 8192 bits",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
    let failed = key(P256).verify(MESSAGE, &[]).expect_err("refused");
    assert_eq!(failed.to_string(), "the signature does not verify");
}

/// DER `tag`, minimal length, `value`.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(value);
    out
}

/// rsaEncryption with NULL parameters, whole.
const RSA_ENCRYPTION: &[u8] = &[
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// An RSA SubjectPublicKeyInfo with the modulus content `n` and e 65537.
fn rsa_spki(algorithm: &[u8], n: &[u8]) -> Vec<u8> {
    let mut key = tlv(0x02, n);
    key.extend(tlv(0x02, &[0x01, 0x00, 0x01]));
    let mut bits = vec![0];
    bits.extend(tlv(0x30, &key));
    let mut body = algorithm.to_vec();
    body.extend(tlv(0x03, &bits));
    tlv(0x30, &body)
}

fn modulus(top: &[u8], rest: usize) -> Vec<u8> {
    let mut n = top.to_vec();
    n.extend(std::iter::repeat_n(0x01, rest));
    n
}

/// The modulus length decides, at ring's bounds 2048 and 8192, inclusive;
/// the modulus must be a positive INTEGER in minimal DER.
#[test]
fn rsa_modulus_forms() {
    let kind = |n: &[u8]| PublicKey::from_spki_der(&rsa_spki(RSA_ENCRYPTION, n)).map(|k| k.kind());
    assert_eq!(
        kind(&modulus(&[0x00, 0xC0], 255)),
        Ok(KeyKind::Rsa { bits: 2048 })
    );
    assert_eq!(kind(&modulus(&[0x7F], 255)), Err(PublicKeyError::RsaSize));
    assert_eq!(
        kind(&modulus(&[0x00, 0x80], 1023)),
        Ok(KeyKind::Rsa { bits: 8192 })
    );
    assert_eq!(kind(&modulus(&[0x01], 1024)), Err(PublicKeyError::RsaSize));
    // Negative: the top bit set without a leading zero byte.
    assert_eq!(kind(&modulus(&[0xC0], 255)), Err(PublicKeyError::Malformed));
    // Not minimal: a leading zero byte before a byte below 0x80.
    assert_eq!(
        kind(&modulus(&[0x00, 0x7F], 255)),
        Err(PublicKeyError::Malformed)
    );
    assert_eq!(kind(&[]), Err(PublicKeyError::Malformed));
    assert_eq!(kind(&[0x00]), Err(PublicKeyError::Malformed));
    // rsaEncryption without its NULL parameters.
    let absent = &[
        0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ];
    assert_eq!(
        PublicKey::from_spki_der(&rsa_spki(absent, &modulus(&[0x00, 0xC0], 255)))
            .expect_err("refused"),
        PublicKeyError::UnsupportedAlgorithm
    );
}

/// An Ed25519 key is exactly 32 bytes.
#[test]
fn ed25519_key_length() {
    let der = key(ED25519).spki_der().to_vec();
    assert_eq!(der.len(), 44);
    let algorithm = &der[2..9];
    for len in [31, 33] {
        let mut bits = vec![0];
        bits.extend(std::iter::repeat_n(0x07, len));
        let mut body = algorithm.to_vec();
        body.extend(tlv(0x03, &bits));
        assert_eq!(
            PublicKey::from_spki_der(&tlv(0x30, &body)).expect_err("refused"),
            PublicKeyError::Malformed,
            "{len} bytes"
        );
    }
}
