//! The one signature check of the parsers whose result decides: OCSP
//! responses (ADR-020, item 4) and CA lists (ADR-027).

use rustls::pki_types::SignatureVerificationAlgorithm;

use super::der;

/// Whether the key of the whole `SubjectPublicKeyInfo` `spki` signed
/// `signed` with `signature` under `signature_algorithm` (the content of
/// its AlgorithmIdentifier): webpki's rule, every algorithm whose
/// signature id equals `signature_algorithm` and whose key id equals the
/// key's is tried. None matching is a bad signature, so an algorithm the
/// handshake does not accept (SHA-1, BR SC-053) never verifies.
pub(crate) fn verified(
    spki: &[u8],
    signature_algorithm: &[u8],
    signed: &[u8],
    signature: &[u8],
    algorithms: &[&dyn SignatureVerificationAlgorithm],
) -> bool {
    let Ok((key_algorithm, key)) = der::spki_parts(spki) else {
        return false;
    };
    algorithms
        .iter()
        .filter(|a| {
            a.signature_alg_id().as_ref() == signature_algorithm
                && a.public_key_alg_id().as_ref() == key_algorithm
        })
        .any(|a| a.verify_signature(key, signed, signature).is_ok())
}
