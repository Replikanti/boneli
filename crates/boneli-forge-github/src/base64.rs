//! Base64 encoding (RFC 4648): the standard alphabet with padding for the
//! git `Authorization` value, and the URL-safe alphabet without padding
//! for JWT segments (RFC 7515, section 2). Encoding only: the adapter never
//! decodes base64.

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// `bytes` in the standard alphabet, padded with `=` (RFC 4648, section 4).
pub fn standard(bytes: &[u8]) -> String {
    encode(bytes, STANDARD, true)
}

/// `bytes` in the URL-safe alphabet without padding (RFC 4648, section 5;
/// the JWT form of RFC 7515).
pub fn url_safe(bytes: &[u8]) -> String {
    encode(bytes, URL_SAFE, false)
}

fn encode(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let symbol = |index: u32| char::from(alphabet[(index & 0x3F) as usize]);
    for chunk in bytes.chunks(3) {
        let b = |k: usize| chunk.get(k).copied().map_or(0, u32::from);
        let triple = (b(0) << 16) | (b(1) << 8) | b(2);
        let symbols = chunk.len() + 1;
        for k in 0..4 {
            if k < symbols {
                out.push(symbol(triple >> (18 - 6 * k)));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}
