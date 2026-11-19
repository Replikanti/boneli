//! `RsaSha256Key` and `fill_random` (ADR-014, D4): RS256 signatures through
//! the ring key provider, checked byte for byte against OpenSSL, the key
//! rules, the wiped input and output that never shows key material. The keys
//! are test-only fixtures (`tests/data/README.md`).

use boneli_https::{KeyError, RsaSha256Key, fill_random};

const PKCS1: &[u8] = include_bytes!("data/test-only-rsa-2048-pkcs1.key");
const PKCS8: &[u8] = include_bytes!("data/test-only-rsa-2048-pkcs8.key");
const RSA_1024: &[u8] = include_bytes!("data/test-only-rsa-1024.key");
const RSA_2304: &[u8] = include_bytes!("data/test-only-rsa-2304.key");
const P256: &[u8] = include_bytes!("data/test-only-p256.key");
const CA: &[u8] = include_bytes!("data/ca.pem");
const MESSAGE: &[u8] = include_bytes!("data/rs256-message.txt");
const SIGNATURE: &[u8] = include_bytes!("data/rs256-test-only.sig");

/// `from_pem` over a copy, because it wipes its input.
fn load(pem: &[u8]) -> Result<RsaSha256Key, KeyError> {
    RsaSha256Key::from_pem(&mut pem.to_vec())
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

/// `pem` with its markers swapped for `label`.
fn relabel(pem: &[u8], label: &str) -> Vec<u8> {
    section(label, &body_lines(pem))
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// The signature OpenSSL 3.5 made of a JWT signing input with the PKCS#1
/// key (`openssl dgst -sha256 -sign`, tests/data/README.md). RSASSA-PKCS1-v1_5
/// is deterministic, so a provider that picked another hash or padding, or
/// signed a copy of the wrong bytes, fails here.
#[test]
fn rs256_known_answer() {
    let key = load(PKCS1).expect("PKCS#1 key");
    let signature = key.sign(MESSAGE).expect("sign");
    assert_eq!(signature.len(), 256);
    assert_eq!(signature, SIGNATURE);
    assert_eq!(key.modulus_bits(), 2048);
}

/// The same key in PKCS#1 and PKCS#8 gives the same signatures, for an
/// empty and a long message too.
#[test]
fn pkcs1_and_pkcs8_sign_alike() {
    let pkcs1 = load(PKCS1).expect("PKCS#1 key");
    let pkcs8 = load(PKCS8).expect("PKCS#8 key");
    let long = vec![0xA5u8; 1 << 20];
    for message in [MESSAGE, b"", long.as_slice()] {
        assert_eq!(
            pkcs1.sign(message).expect("sign"),
            pkcs8.sign(message).expect("sign"),
            "{} bytes",
            message.len()
        );
    }
    assert_eq!(pkcs8.sign(MESSAGE).expect("sign"), SIGNATURE);
}

/// Exactly one PEM section, labelled `RSA PRIVATE KEY` or `PRIVATE KEY`,
/// holding an RSA key ring accepts (2048 to 4096 bits); everything else is
/// refused with the rule it broke.
#[test]
fn key_rules() {
    let pkcs1_body = body_lines(PKCS1).concat();
    // A base64 character in the middle of the body that decodes to other
    // bits: the DER no longer parses, or the key fails ring's checks.
    let mut flipped = PKCS1.to_vec();
    let middle = PKCS1
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .nth(12)
        .map(|(i, _)| i + 10)
        .expect("a 13th line");
    flipped[middle] = if flipped[middle] == b'A' { b'B' } else { b'A' };
    let truncated = {
        let lines = body_lines(PKCS1);
        section("RSA PRIVATE KEY", &lines[..lines.len() / 2])
    };
    let garbage = section("PRIVATE KEY", &[&b"QUFB".repeat(100)]);
    // OpenSSL's traditional encryption (`openssl genrsa -traditional
    // -aes128`) keeps the PKCS#1 label and adds RFC 1421 headers. The body
    // here is the plain key: the headers alone must refuse it.
    let traditional_encrypted = {
        let lines = body_lines(PKCS1);
        let mut with_headers: Vec<&[u8]> = vec![
            b"Proc-Type: 4,ENCRYPTED",
            b"DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF",
            b"",
        ];
        with_headers.extend(lines);
        section("RSA PRIVATE KEY", &with_headers)
    };
    let dek_info_only = {
        let mut with_header: Vec<&[u8]> =
            vec![b"DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF"];
        with_header.extend(body_lines(PKCS8));
        section("PRIVATE KEY", &with_header)
    };
    // A BEGIN marker with four trailing dashes instead of five.
    let short_marker = {
        let mut out = PKCS1.to_vec();
        let end = out.iter().position(|b| *b == b'\n').expect("a first line");
        out.remove(end - 1);
        out
    };
    let missing_end = PKCS1
        .split(|b| *b == b'\n')
        .filter(|line| !line.starts_with(b"-----END"))
        .collect::<Vec<_>>()
        .join(&b'\n');
    let cases: Vec<(&str, Vec<u8>, KeyError)> = vec![
        ("empty", Vec::new(), KeyError::NotOneSection),
        (
            "text only",
            b"not a key\n".to_vec(),
            KeyError::NotOneSection,
        ),
        ("bare base64", pkcs1_body.clone(), KeyError::NotOneSection),
        ("two keys", concat(&[PKCS1, PKCS8]), KeyError::NotOneSection),
        (
            "key and certificate",
            concat(&[PKCS1, CA]),
            KeyError::NotOneSection,
        ),
        (
            "certificate and key",
            concat(&[CA, PKCS8]),
            KeyError::NotOneSection,
        ),
        ("certificate", CA.to_vec(), KeyError::UnsupportedSection),
        (
            "encrypted",
            relabel(PKCS8, "ENCRYPTED PRIVATE KEY"),
            KeyError::UnsupportedSection,
        ),
        (
            "OpenSSH label",
            relabel(PKCS1, "OPENSSH PRIVATE KEY"),
            KeyError::UnsupportedSection,
        ),
        (
            "SEC1 label",
            relabel(PKCS1, "EC PRIVATE KEY"),
            KeyError::UnsupportedSection,
        ),
        (
            "public key",
            relabel(PKCS8, "PUBLIC KEY"),
            KeyError::UnsupportedSection,
        ),
        (
            "PKCS#8 under the PKCS#1 label",
            relabel(PKCS8, "RSA PRIVATE KEY"),
            KeyError::Rejected,
        ),
        (
            "PKCS#1 under the PKCS#8 label",
            relabel(PKCS1, "PRIVATE KEY"),
            KeyError::Rejected,
        ),
        (
            "traditional encrypted PKCS#1",
            traditional_encrypted,
            KeyError::UnsupportedSection,
        ),
        (
            "DEK-Info header",
            dek_info_only,
            KeyError::UnsupportedSection,
        ),
        ("1024-bit RSA", RSA_1024.to_vec(), KeyError::Rejected),
        // ring loads primes in multiples of 512 bits only, so a 2304-bit
        // key, between the accepted sizes, is refused.
        ("2304-bit RSA", RSA_2304.to_vec(), KeyError::Rejected),
        ("P-256", P256.to_vec(), KeyError::NotRsa),
        ("garbage DER", garbage, KeyError::Rejected),
        ("truncated DER", truncated, KeyError::Rejected),
        ("flipped base64", flipped, KeyError::Rejected),
        ("missing END", missing_end, KeyError::CorruptPem),
        (
            "bad base64",
            relabel(
                b"-----BEGIN X-----\n!!!!\n-----END X-----\n",
                "RSA PRIVATE KEY",
            ),
            KeyError::CorruptPem,
        ),
        ("short marker", short_marker, KeyError::CorruptPem),
    ];
    for (name, pem, want) in cases {
        match load(&pem) {
            Ok(_) => panic!("{name}: accepted"),
            Err(got) => assert_eq!(got, want, "{name}"),
        }
    }
    // Explanatory text around the one section is not a section.
    let annotated = concat(&[
        &b"GitHub App key, test only\n"[..],
        PKCS1,
        &b"\ntrailing note\n"[..],
    ]);
    assert!(load(&annotated).is_ok(), "text around the section");
    // CRLF line ends, as a key saved on Windows has them.
    let crlf: Vec<u8> = PKCS8
        .split(|b| *b == b'\n')
        .collect::<Vec<_>>()
        .join(&b"\r\n"[..]);
    assert!(load(&crlf).is_ok(), "CRLF");
}

/// The input cap holds a 4096-bit key with OpenSSL's text dump (about
/// 11,125 B); one byte over it is refused before any parsing.
#[test]
fn pem_size_cap() {
    let cap = RsaSha256Key::MAX_PEM_LEN;
    assert_eq!(cap, 16_384);
    let mut at_cap = vec![b'#'; cap - PKCS1.len() - 1];
    at_cap.push(b'\n');
    at_cap.extend_from_slice(PKCS1);
    assert_eq!(at_cap.len(), cap);
    assert!(load(&at_cap).is_ok(), "exactly the cap");
    let mut over = vec![b'#'; cap - PKCS1.len()];
    over.push(b'\n');
    over.extend_from_slice(PKCS1);
    assert_eq!(over.len(), cap + 1);
    assert_eq!(load(&over).err(), Some(KeyError::TooLarge));
    // A huge input is refused at the length, not after a scan.
    assert_eq!(load(&vec![b'A'; 1 << 20]).err(), Some(KeyError::TooLarge));
}

/// `from_pem` wipes its input before it returns, on success and on every
/// refusal.
#[test]
fn input_is_wiped() {
    let mut over = vec![b'#'; RsaSha256Key::MAX_PEM_LEN];
    over.extend_from_slice(PKCS1);
    for (name, pem) in [
        ("PKCS#1", PKCS1.to_vec()),
        ("PKCS#8", PKCS8.to_vec()),
        ("1024-bit", RSA_1024.to_vec()),
        ("P-256", P256.to_vec()),
        ("two keys", concat(&[PKCS1, PKCS8])),
        ("certificate", CA.to_vec()),
        ("SEC1 label", relabel(PKCS1, "EC PRIVATE KEY")),
        ("too large", over),
    ] {
        let mut buf = pem;
        let _ = RsaSha256Key::from_pem(&mut buf);
        assert!(buf.iter().all(|b| *b == 0), "{name}: input not wiped");
    }
}

/// `Debug` of the key, and `Debug` and `Display` of every error, carry no
/// key material: no 16-byte window of the key's base64 and no hex of it.
#[test]
fn debug_has_no_key_material() {
    let key = load(PKCS1).expect("PKCS#1 key");
    assert_eq!(format!("{key:?}"), "RsaSha256Key { modulus_bits: 2048 }");
    assert_eq!(format!("{key:#?}").matches("2048").count(), 1);

    let mut outputs = vec![format!("{key:?}"), format!("{key:#?}")];
    for pem in [
        RSA_1024.to_vec(),
        P256.to_vec(),
        concat(&[PKCS1, PKCS8]),
        relabel(PKCS1, "EC PRIVATE KEY"),
        relabel(PKCS8, "RSA PRIVATE KEY"),
    ] {
        let err = load(&pem).expect_err("refused");
        outputs.push(format!("{err:?}"));
        outputs.push(format!("{err}"));
        outputs.push(format!(
            "{:?}",
            std::error::Error::source(&err).map(ToString::to_string)
        ));
    }
    let mut windows = Vec::new();
    for pem in [PKCS1, PKCS8, RSA_1024, RSA_2304, P256] {
        let body = body_lines(pem).concat();
        for window in body.windows(16) {
            windows.push(String::from_utf8(window.to_vec()).expect("base64 is ASCII"));
        }
    }
    for output in &outputs {
        assert!(output.len() < 200, "{output}");
        for window in &windows {
            assert!(!output.contains(window.as_str()), "{output}");
        }
    }
}

/// `fill_random` fills every byte from the system's random source: two
/// 64-byte draws differ and neither is all zeros (each has probability
/// 2^-512 for a working source); an empty buffer is fine; a 1 MiB buffer
/// has no 4 KiB page left at zero.
#[test]
fn fill_random_fills() {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    fill_random(&mut a).expect("random");
    fill_random(&mut b).expect("random");
    assert_ne!(a, [0u8; 64]);
    assert_ne!(b, [0u8; 64]);
    assert_ne!(a, b);
    fill_random(&mut []).expect("empty");
    let mut big = vec![0u8; 1 << 20];
    fill_random(&mut big).expect("random");
    for page in big.chunks(4096) {
        assert!(page.iter().any(|b| *b != 0), "a page left at zero");
    }
}

/// The forge shares one key between threads (ADR-014, D4).
#[test]
fn key_is_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<RsaSha256Key>();
}

/// The refusal names the sizes ring loads: 2048, 3072 and 4096 bits (ring
/// 0.17 refuses primes that are not a multiple of 512 bits), not a range
/// that a refused 2304-bit key lies inside.
#[test]
fn rejected_names_the_accepted_sizes() {
    for pem in [RSA_1024, RSA_2304] {
        let err = load(pem).expect_err("refused");
        assert_eq!(err, KeyError::Rejected);
        assert_eq!(
            err.to_string(),
            "not an RSA private key of 2048, 3072 or 4096 bits"
        );
    }
}
