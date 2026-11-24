//! Strict base64 (RFC 4648, section 4): the encodings Sigstore writes
//! pass and round-trip, every other form is refused.

use boneli_sigstore::base64::{decode, encode};

/// RFC 4648, section 10.
const VECTORS: &[(&str, &str)] = &[
    ("", ""),
    ("f", "Zg=="),
    ("fo", "Zm8="),
    ("foo", "Zm9v"),
    ("foob", "Zm9vYg=="),
    ("fooba", "Zm9vYmE="),
    ("foobar", "Zm9vYmFy"),
];

#[test]
fn rfc_4648_vectors() {
    for (plain, encoded) in VECTORS {
        assert_eq!(
            decode(encoded.as_bytes()).as_deref(),
            Some(plain.as_bytes()),
            "{encoded}"
        );
        assert_eq!(encode(plain.as_bytes()), *encoded);
    }
}

#[test]
fn base64_round_trip() {
    // Every accepted vector, and every byte value in every position of a
    // quad and of both padded tails.
    for (_, encoded) in VECTORS {
        let decoded = decode(encoded.as_bytes()).expect("vector");
        assert_eq!(encode(&decoded), *encoded);
    }
    for len in 0..=6 {
        for byte in 0..=255u8 {
            let data: Vec<u8> = (0..len).map(|i| byte.wrapping_add(i as u8 * 37)).collect();
            let encoded = encode(&data);
            assert_eq!(decode(encoded.as_bytes()), Some(data.clone()));
            assert_eq!(encode(&decode(encoded.as_bytes()).expect("own")), encoded);
        }
    }
    assert_eq!(encode(&[0xFB, 0xFF]), "+/8=");
    assert_eq!(decode(b"+/8="), Some(vec![0xFB, 0xFF]));
}

#[test]
fn base64_strict_forms() {
    let refused: &[&[u8]] = &[
        // Non-canonical trailing bits.
        b"QR==",
        b"Zm9=",
        b"Zh==",
        // Missing or misplaced padding.
        b"Zg",
        b"Zg=",
        b"Zm8",
        b"Zg==Zg==",
        b"Z===",
        b"====",
        b"Zm=v",
        // The URL-safe alphabet.
        b"-_8=",
        b"Zm9v-w==",
        // Whitespace, ASCII and U+00A0.
        b"Zm9v\n",
        b"Zm9v Zm9v",
        b"Zm9v\r\nYmFy",
        b"Zm9v\tYmFy",
        "Zm9v\u{a0}YmFy".as_bytes(),
        // Other bytes.
        b"Zm9v*mFy",
        b"Zm9vYmF\0",
    ];
    for input in refused {
        assert_eq!(decode(input), None, "{:?}", String::from_utf8_lossy(input));
    }
}
