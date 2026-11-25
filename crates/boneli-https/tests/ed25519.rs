//! `Ed25519Key` (ADR-038): Ed25519 signatures through the ring key
//! provider, checked against the public key OpenSSL derived from the same
//! key file, the key rules, the wiped input and output that never shows
//! key material. The keys are test-only fixtures (`tests/data/README.md`).

use boneli_https::{Ed25519Key, KeyError, KeyKind, PublicKey};

const ED25519: &[u8] = include_bytes!("data/test-only-ed25519.key");
const ED25519_PUB: &[u8] = include_bytes!("data/test-only-ed25519.pub.pem");
const P256: &[u8] = include_bytes!("data/test-only-p256.key");
const P256_SEC1: &[u8] = include_bytes!("data/test-only-p256-sec1.key");
const P384: &[u8] = include_bytes!("data/test-only-p384.key");
const RSA_PKCS8: &[u8] = include_bytes!("data/test-only-rsa-2048-pkcs8.key");
const RSA_PKCS1: &[u8] = include_bytes!("data/test-only-rsa-2048-pkcs1.key");
const CA: &[u8] = include_bytes!("data/ca.pem");

/// `from_pem` over a copy, because it wipes its input.
fn load(pem: &[u8]) -> Result<Ed25519Key, KeyError> {
    Ed25519Key::from_pem(&mut pem.to_vec())
}

/// The base64 lines between the PEM markers.
fn body_lines(pem: &[u8]) -> Vec<&[u8]> {
    pem.split(|b| *b == b'\n')
        .filter(|line| !line.is_empty() && !line.starts_with(b"-----"))
        .collect()
}

/// A PEM section labelled `label` around `lines`.
fn section(label: &str, lines: &[&[u8]]) -> Vec<u8> {
    let mut out = format!("-----BEGIN {label}-----\n").into_bytes();
    for line in lines {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    out
}

/// The public key is the one OpenSSL derives from the same file (`openssl
/// pkey -pubout`), and a signature verifies under that independent copy.
#[test]
fn signs_under_the_openssl_public_key() {
    let key = load(ED25519).expect("Ed25519 key");
    let openssl = PublicKey::from_pem(ED25519_PUB).expect("OpenSSL public key");
    assert_eq!(key.public_key(), &openssl);
    assert_eq!(key.public_key().kind(), KeyKind::Ed25519);
    let long = vec![0xA5u8; 1 << 20];
    for message in [&b"origin\n1\nroot\n"[..], b"", long.as_slice()] {
        let signature = key.sign(message).expect("sign");
        assert_eq!(signature.len(), 64);
        openssl
            .verify(message, &signature)
            .expect("verifies under OpenSSL's key");
    }
}

/// RFC 8032 signatures are deterministic: two signatures of one message
/// are the same bytes; neither verifies another message.
#[test]
fn signatures_are_deterministic_and_bound_to_the_message() {
    let key = load(ED25519).expect("Ed25519 key");
    let a = key.sign(b"message").expect("sign");
    let b = key.sign(b"message").expect("sign");
    assert_eq!(a, b);
    key.public_key().verify(b"message", &a).expect("verifies");
    assert!(key.public_key().verify(b"messagf", &a).is_err());
}

/// Exactly one PEM section, an unencrypted PKCS#8 `PRIVATE KEY` of
/// Ed25519; everything else is refused with the rule it broke.
#[test]
fn key_rules() {
    let encrypted_headers = {
        let mut with_headers: Vec<&[u8]> = vec![
            b"Proc-Type: 4,ENCRYPTED",
            b"DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF",
            b"",
        ];
        with_headers.extend(body_lines(ED25519));
        section("PRIVATE KEY", &with_headers)
    };
    let truncated = {
        let lines = body_lines(ED25519);
        let line = lines[0];
        section("PRIVATE KEY", &[&line[..line.len() / 2]])
    };
    let cases: Vec<(&str, Vec<u8>, KeyError)> = vec![
        ("empty", Vec::new(), KeyError::NotOneSection),
        ("text only", b"no key\n".to_vec(), KeyError::NotOneSection),
        (
            "two keys",
            [ED25519, ED25519].concat(),
            KeyError::NotOneSection,
        ),
        (
            "key and certificate",
            [ED25519, CA].concat(),
            KeyError::NotOneSection,
        ),
        ("P-256", P256.to_vec(), KeyError::NotEd25519),
        ("SEC1 P-256", P256_SEC1.to_vec(), KeyError::NotEd25519),
        ("P-384", P384.to_vec(), KeyError::NotEd25519),
        ("RSA PKCS#8", RSA_PKCS8.to_vec(), KeyError::NotEd25519),
        ("RSA PKCS#1", RSA_PKCS1.to_vec(), KeyError::NotEd25519),
        ("public key", ED25519_PUB.to_vec(), KeyError::NotEd25519),
        ("certificate", CA.to_vec(), KeyError::NotEd25519),
        (
            "encrypted PKCS#8 label",
            section("ENCRYPTED PRIVATE KEY", &body_lines(ED25519)),
            KeyError::NotEd25519,
        ),
        (
            "encryption headers",
            encrypted_headers,
            KeyError::NotEd25519,
        ),
        ("truncated DER", truncated, KeyError::NotEd25519),
        (
            "bad base64",
            section("PRIVATE KEY", &[b"!!!!"]),
            KeyError::CorruptPem,
        ),
    ];
    for (name, pem, want) in cases {
        match load(&pem) {
            Ok(_) => panic!("{name}: accepted"),
            Err(got) => assert_eq!(got, want, "{name}"),
        }
    }
    let annotated = [&b"checkpoint key, test only\n"[..], ED25519, b"\nnote\n"].concat();
    assert!(load(&annotated).is_ok(), "text around the section");
}

/// The input cap is inclusive; one byte over it is refused before any
/// parsing.
#[test]
fn pem_size_cap() {
    let cap = Ed25519Key::MAX_PEM_LEN;
    assert_eq!(cap, 16_384);
    let mut at_cap = vec![b'#'; cap - ED25519.len() - 1];
    at_cap.push(b'\n');
    at_cap.extend_from_slice(ED25519);
    assert_eq!(at_cap.len(), cap);
    assert!(load(&at_cap).is_ok(), "exactly the cap");
    let mut over = vec![b'#'; cap - ED25519.len()];
    over.push(b'\n');
    over.extend_from_slice(ED25519);
    assert_eq!(over.len(), cap + 1);
    assert_eq!(load(&over).err(), Some(KeyError::TooLarge));
}

/// `from_pem` wipes its input before it returns, on success and on every
/// refusal.
#[test]
fn input_is_wiped() {
    let mut over = vec![b'#'; Ed25519Key::MAX_PEM_LEN];
    over.extend_from_slice(ED25519);
    for (name, pem) in [
        ("Ed25519", ED25519.to_vec()),
        ("P-256", P256.to_vec()),
        ("RSA", RSA_PKCS8.to_vec()),
        ("two keys", [ED25519, ED25519].concat()),
        ("too large", over),
    ] {
        let mut buf = pem;
        let _ = Ed25519Key::from_pem(&mut buf);
        assert!(buf.iter().all(|b| *b == 0), "{name}: input not wiped");
    }
}

/// `Debug` of the key and of every error carries no key material.
#[test]
fn debug_has_no_key_material() {
    let key = load(ED25519).expect("Ed25519 key");
    assert_eq!(format!("{key:?}"), "Ed25519Key { .. }");
    let mut outputs = vec![format!("{key:?}"), format!("{key:#?}")];
    for pem in [P256, P384, RSA_PKCS8] {
        let err = load(pem).expect_err("refused");
        outputs.push(format!("{err:?}"));
        outputs.push(format!("{err}"));
    }
    for pem in [ED25519, P256, P384] {
        for line in body_lines(pem) {
            for window in line.windows(16) {
                let window = String::from_utf8_lossy(window);
                for output in &outputs {
                    assert!(!output.contains(window.as_ref()), "{output}");
                }
            }
        }
    }
}

#[test]
fn error_text() {
    assert_eq!(
        KeyError::NotEd25519.to_string(),
        "the PEM section must be an unencrypted PKCS#8 PRIVATE KEY of Ed25519"
    );
}
