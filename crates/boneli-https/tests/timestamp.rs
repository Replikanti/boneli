//! RFC 3161 timestamp tokens (ADR-038, D3), with the seven real tokens of
//! Sigstore's public-good TSA as known answers: each parses with its
//! measured genTime and verifies over the DSSE signature bytes of its
//! bundle against the public-good TSA chain (`tests/data/README.md`). The
//! synthetic cases, with tokens built at test time, are the unit tests of
//! `src/timestamp.rs`.

use boneli_https::{CertError, Sha256, TimestampError, TimestampToken};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

const TSA_LEAF: &[u8] = include_bytes!("data/tsa-sigstore-leaf.pem");
const TSA_ROOT: &[u8] = include_bytes!("data/tsa-sigstore-root.pem");
const OTHER_ROOT: &[u8] = include_bytes!("data/codesign-root.pem");

/// Name, token, signed bytes and the measured genTime (README).
const TOKENS: [(&str, &[u8], &[u8], u64); 7] = [
    (
        "aicr recipe catalog 1.3.0",
        include_bytes!("data/tsa-aicr-recipe-catalog-1.3.0.tsr"),
        include_bytes!("data/tsa-aicr-recipe-catalog-1.3.0.sig"),
        1_794_873_195,
    ),
    (
        "aicr SBOM 1.3.0",
        include_bytes!("data/tsa-aicr-sbom-1.3.0.tsr"),
        include_bytes!("data/tsa-aicr-sbom-1.3.0.sig"),
        1_794_873_249,
    ),
    (
        "aicr OpenVEX 858ab1e4",
        include_bytes!("data/tsa-aicr-openvex-858ab1e4.tsr"),
        include_bytes!("data/tsa-aicr-openvex-858ab1e4.sig"),
        1_793_656_382,
    ),
    (
        "aicr OpenVEX 1.3.0",
        include_bytes!("data/tsa-aicr-openvex-1.3.0.tsr"),
        include_bytes!("data/tsa-aicr-openvex-1.3.0.sig"),
        1_794_873_594,
    ),
    (
        "bex-cnb-run",
        include_bytes!("data/tsa-bex-cnb-run.tsr"),
        include_bytes!("data/tsa-bex-cnb-run.sig"),
        1_793_371_569,
    ),
    (
        "cosign latest",
        include_bytes!("data/tsa-cosign-latest.tsr"),
        include_bytes!("data/tsa-cosign-latest.sig"),
        1_792_519_726,
    ),
    (
        "trillian_log_server",
        include_bytes!("data/tsa-trillian-log-server.tsr"),
        include_bytes!("data/tsa-trillian-log-server.sig"),
        1_795_367_610,
    ),
];

fn der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem)
        .expect("PEM")
        .as_ref()
        .to_vec()
}

#[test]
fn real_tokens_verify() {
    let (leaf, root) = (der(TSA_LEAF), der(TSA_ROOT));
    for (name, token, signed, gen_time) in TOKENS {
        let parsed = TimestampToken::from_response_der(token).expect(name);
        assert_eq!(parsed.gen_time(), gen_time, "{name}");
        assert_eq!(parsed.message_imprint(), &Sha256::digest(signed), "{name}");
        assert_eq!(parsed.verify(signed, &leaf, &[], &root), Ok(()), "{name}");
    }
}

/// The real tokens fail closed on every input that is not theirs.
#[test]
fn real_tokens_refuse_other_inputs() {
    let (leaf, root) = (der(TSA_LEAF), der(TSA_ROOT));
    let (_, token, signed, _) = TOKENS[0];
    let (_, _, other_signed, _) = TOKENS[1];
    let parsed = TimestampToken::from_response_der(token).expect("token");
    assert_eq!(
        parsed.verify(other_signed, &leaf, &[], &root),
        Err(TimestampError::Imprint)
    );
    // The leaf's anchor as the leaf: the token does not name it.
    assert_eq!(
        parsed.verify(signed, &root, &[], &root),
        Err(TimestampError::SigningCertificate)
    );
    // Another anchor.
    assert_eq!(
        parsed.verify(signed, &leaf, &[], &der(OTHER_ROOT)),
        Err(TimestampError::Chain(CertError::UnknownIssuer))
    );
    // The leaf as its own anchor: webpki cannot verify a certificate that
    // is itself the anchor, so a chain of one certificate never verifies.
    assert!(parsed.verify(signed, &leaf, &[], &leaf).is_err());
    // A flipped byte anywhere in the token is refused or fails to verify.
    for i in 0..token.len() {
        let mut flipped = token.to_vec();
        flipped[i] ^= 0x01;
        let verdict = TimestampToken::from_response_der(&flipped)
            .and_then(|t| t.verify(signed, &leaf, &[], &root).map(|()| t.gen_time()));
        // Bytes that are read for form only (the serial number, the
        // signing time, the certificates field, the signer's name) may
        // change without changing the verdict, but never the time.
        if let Ok(time) = verdict {
            assert_eq!(time, TOKENS[0].3, "byte {i}");
        }
    }
}
