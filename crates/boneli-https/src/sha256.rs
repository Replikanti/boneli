//! SHA-256 for content addressing: ring's implementation through rustls'
//! public hash-provider API (ADR-009, D6).
//!
//! This is the one SHA-256 of the repository. ring is already linked for
//! TLS, where it hashes the transcript of every TLS 1.3 connection on a
//! SHA-256 suite; exporting it here adds no crate and no dependency edge,
//! and keeps ring confined to this crate (ADR-005).

use std::fmt;

use rustls::SupportedCipherSuite;
use rustls::crypto::hash::{Context, Hash};

/// The hash provider of `TLS13_AES_128_GCM_SHA256`, which in rustls 0.23
/// with the ring provider is ring's `digest::SHA256`.
/// `hash_provider_is_sha256` fails if an update swaps it.
fn provider() -> &'static dyn Hash {
    // Both arms carry a public `common`, and the enum is exhaustive, so
    // there is no `Option` and no panic path.
    match rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256 {
        SupportedCipherSuite::Tls12(suite) => suite.common.hash_provider,
        SupportedCipherSuite::Tls13(suite) => suite.common.hash_provider,
    }
}

/// A streaming SHA-256.
///
/// `new`, `update`, `finish` and `digest` cannot fail and do not panic. A
/// wrong provider would show up as a failed known-answer test and, in
/// production, as a digest mismatch, which fails closed.
pub struct Sha256(Box<dyn Context>);

impl Sha256 {
    /// An empty hash.
    pub fn new() -> Sha256 {
        Sha256(provider().start())
    }

    /// Feeds `data`. An empty slice changes nothing.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything fed so far.
    pub fn finish(self) -> [u8; 32] {
        copy_out(self.0.finish().as_ref())
    }

    /// The digest of `data` in one call (ring's one-shot path).
    pub fn digest(data: &[u8]) -> [u8; 32] {
        copy_out(provider().hash(data).as_ref())
    }
}

impl Default for Sha256 {
    fn default() -> Sha256 {
        Sha256::new()
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256")
    }
}

/// Copies the first 32 bytes without indexing; a shorter output (a wrong
/// provider) leaves zeros, which no known-answer test accepts.
fn copy_out(output: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    for (slot, byte) in digest.iter_mut().zip(output) {
        *slot = *byte;
    }
    digest
}

#[cfg(test)]
mod tests {
    use rustls::crypto::hash::HashAlgorithm;

    use super::provider;

    /// A rustls update that changes the suite's provider fails here, not
    /// in a pull.
    #[test]
    fn hash_provider_is_sha256() {
        assert_eq!(provider().algorithm(), HashAlgorithm::SHA256);
        assert_eq!(provider().output_len(), 32);
    }
}
