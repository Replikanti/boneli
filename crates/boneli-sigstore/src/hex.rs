//! Lower-case hex, the form Rekor and the registries write digests and
//! log IDs in. Upper-case digits are refused, so one value has one form
//! and a byte-exact comparison is a value comparison.

/// The lower-case hex of `bytes`.
pub(crate) fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0F)]));
    }
    out
}

/// The 32 bytes of exactly 64 lower-case hex digits, or `None`.
pub(crate) fn decode_32(text: &str) -> Option<[u8; 32]> {
    let text = text.as_bytes();
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in text.as_chunks::<2>().0.iter().enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// The digest of `sha256:` followed by 64 lower-case hex digits, or
/// `None`: another algorithm, upper-case or fullwidth digits, or any
/// byte more.
pub(crate) fn sha256_digest(text: &str) -> Option<[u8; 32]> {
    decode_32(text.strip_prefix("sha256:")?)
}
