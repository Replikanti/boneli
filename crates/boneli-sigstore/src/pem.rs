//! The PEM certificates cosign writes into annotations and Rekor into
//! entry bodies (Go's `pem.Encode`): one `CERTIFICATE` block, `\n` line
//! ends, base64 lines of at most 64 characters, and nothing before the
//! block or after it but one final `\n`. The decoded DER is what the
//! verifier compares and verifies, so the strictness here only refuses
//! odd encodings; it decides nothing on its own.

use crate::base64;

const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----\n";
const END: &[u8] = b"-----END CERTIFICATE-----";

/// The longest base64 line Go's encoder writes.
const LINE: usize = 64;

/// The DER of the one certificate block of `text`, or `None`.
pub(crate) fn certificate(text: &[u8]) -> Option<Vec<u8>> {
    let body = text.strip_prefix(BEGIN)?;
    let body = body.strip_suffix(b"\n").unwrap_or(body);
    let body = body.strip_suffix(END)?;
    let body = body.strip_suffix(b"\n")?;
    let mut joined = Vec::with_capacity(body.len());
    for line in body.split(|b| *b == b'\n') {
        if line.is_empty() || line.len() > LINE {
            return None;
        }
        joined.extend_from_slice(line);
    }
    let der = base64::decode(&joined)?;
    (!der.is_empty()).then_some(der)
}
