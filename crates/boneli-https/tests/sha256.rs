//! Known answers and split invariance of `boneli_https::Sha256`, the one
//! SHA-256 of the repository (ADR-009, D6).

use boneli_https::Sha256;

fn hex(digest: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    out
}

/// The FIPS 180-2 examples (appendix B) and the empty input. A wrapper that
/// picked another suite's hash (SHA-384 has 48 bytes of output), dropped an
/// update or copied the wrong bytes out fails here.
#[test]
fn sha256_fips_examples() {
    let cases: [(&[u8], &str); 3] = [
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(hex(Sha256::digest(input)), expected, "digest of {input:?}");
        let mut streamed = Sha256::new();
        streamed.update(input);
        assert_eq!(hex(streamed.finish()), expected, "streamed {input:?}");
    }

    // One million `a`, fed as 1,000 updates of 1,000 bytes.
    let block = [b'a'; 1000];
    let mut million = Sha256::default();
    for _ in 0..1000 {
        million.update(&block);
    }
    assert_eq!(
        hex(million.finish()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

/// Every two-part split of a 1,000-byte input, including an empty first and
/// an empty last part, and 1,000 one-byte updates, equal the one-shot
/// digest, which takes a separate path through ring (`Hash::hash`).
#[test]
fn sha256_split_invariance() {
    let input: Vec<u8> = (0..1000u32)
        .map(|i| u8::try_from(i.wrapping_mul(31) % 251).unwrap_or(0))
        .collect();
    let whole = Sha256::digest(&input);

    for split in 0..=input.len() {
        let (a, b) = input.split_at(split);
        let mut h = Sha256::new();
        h.update(a);
        h.update(b);
        assert_eq!(h.finish(), whole, "split at {split}");
    }

    let mut bytewise = Sha256::new();
    for byte in &input {
        bytewise.update(std::slice::from_ref(byte));
        bytewise.update(&[]);
    }
    assert_eq!(bytewise.finish(), whole, "one-byte updates");
}

/// The type crosses threads: the layer cache hashes on the pulling thread
/// and the store may hand a hasher to another.
#[test]
fn sha256_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Sha256>();
}
