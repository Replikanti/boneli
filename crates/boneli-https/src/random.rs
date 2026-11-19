//! Random bytes from the system's source, through the ring provider's
//! `secure_random` (ADR-014, D4): the source rustls draws its handshake
//! randomness from, so the runner has one random source and no new crate.

use std::fmt;

/// The system's random source failed; `buf` holds no usable randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomFailed;

impl fmt::Display for RandomFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the system random source failed")
    }
}

impl std::error::Error for RandomFailed {}

/// Fills `buf` with random bytes from the system's source (`getrandom`),
/// or fails; it never falls back to a weaker source. An empty `buf` is
/// fine.
pub fn fill_random(buf: &mut [u8]) -> Result<(), RandomFailed> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(buf)
        .map_err(|_| RandomFailed)
}
