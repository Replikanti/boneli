//! Base64 with the standard alphabet of RFC 4648, section 4, read
//! strictly: padding is required, the unused bits of the last character
//! must be zero (section 3.5, so every byte string has exactly one
//! encoding), and nothing outside the alphabet and the final `=`s is
//! accepted, whitespace and the URL-safe alphabet included.
//!
//! Sigstore's formats carry signatures, certificates, keys and Rekor
//! bodies in this form (protobuf JSON and Go's `encoding/base64`
//! `StdEncoding`, which write exactly this). One encoding per value
//! matters for the SET: its signed bytes are rebuilt with [`encode`] from
//! what [`decode`] returned, so they equal the input only because the
//! input was canonical (ADR-029, item 8).

/// The standard alphabet, by value.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The value of one alphabet character, or `None`.
fn value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes `input`, or `None` when it is not the canonical padded
/// standard encoding of some byte string. The empty input is the empty
/// string.
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let quads = input.len() / 4;
    for (i, quad) in input.as_chunks::<4>().0.iter().enumerate() {
        let last = i + 1 == quads;
        let padding = match quad {
            [_, _, b'=', b'='] if last => 2,
            [_, _, _, b'='] if last => 1,
            _ => 0,
        };
        let mut bits: u32 = 0;
        for &c in &quad[..4 - padding] {
            bits = (bits << 6) | u32::from(value(c)?);
        }
        match padding {
            0 => out.extend_from_slice(&bits.to_be_bytes()[1..]),
            1 => {
                // 18 bits: 16 of data, the low 2 must be zero.
                if bits & 0b11 != 0 {
                    return None;
                }
                out.extend_from_slice(&(bits >> 2).to_be_bytes()[2..]);
            }
            _ => {
                // 12 bits: 8 of data, the low 4 must be zero.
                if bits & 0b1111 != 0 {
                    return None;
                }
                out.push((bits >> 4) as u8);
            }
        }
    }
    Some(out)
}

/// The padded standard encoding of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut word = [0u8; 3];
        word[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, word[0], word[1], word[2]]);
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                let index = (bits >> (18 - 6 * i)) & 0x3F;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}
