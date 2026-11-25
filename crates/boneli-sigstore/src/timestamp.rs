//! RFC 3161 timestamps as a time source of keyless bundles (ADR-038, D1,
//! D5): which of a bundle's tokens give a verified time.
//!
//! A token counts when it parses and some timestamp authority of the
//! trusted root, whose window holds the token's genTime, verifies it over
//! the bundle's DSSE signature bytes (`boneli_https::TimestampToken`). A
//! token that does not count is no error by itself, as in sigstore-go's
//! `VerifySignedTimestamp`: a bundle may carry a token from a TSA the
//! operator's root does not list. The first failure is kept, so a bundle
//! with no time at all is refused with the reason of its first token.

use boneli_https::TimestampToken;

use crate::error::Refusal;
use crate::root::TrustedRoot;

/// The genTimes (Unix seconds) of the tokens of `tokens` that verify over
/// `signature` (module doc), in bundle order, and the first failure.
pub(crate) fn verified_times(
    tokens: &[Vec<u8>],
    signature: &[u8],
    root: &TrustedRoot,
) -> (Vec<u64>, Option<Refusal>) {
    let mut times = Vec::new();
    let mut first_failure = None;
    for token in tokens {
        match verified_time(token, signature, root) {
            Ok(time) => times.push(time),
            Err(refusal) => {
                first_failure.get_or_insert(refusal);
            }
        }
    }
    (times, first_failure)
}

/// The genTime of `token` if a TSA of `root` verifies it.
fn verified_time(token: &[u8], signature: &[u8], root: &TrustedRoot) -> Result<u64, Refusal> {
    let token = TimestampToken::from_response_der(token).map_err(Refusal::Timestamp)?;
    let at = token.gen_time();
    // genTime is at most 9999-12-31T23:59:59Z (the reader's range), so
    // the product fits; saturating keeps it panic-free all the same.
    let at_ms = at.saturating_mul(1_000);
    let mut error = Refusal::NoTsaAtTime;
    for tsa in root.tsas.iter().filter(|tsa| tsa.window.contains(at_ms)) {
        let intermediates: Vec<&[u8]> = tsa.intermediates.iter().map(Vec::as_slice).collect();
        match token.verify(signature, &tsa.leaf, &intermediates, &tsa.root) {
            Ok(()) => return Ok(at),
            Err(e) if error == Refusal::NoTsaAtTime => error = Refusal::Timestamp(e),
            Err(_) => {}
        }
    }
    Err(error)
}
