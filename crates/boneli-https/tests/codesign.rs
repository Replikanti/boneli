//! Code-signing chains and embedded SCTs (ADR-029, S2), with real
//! Sigstore certificates as known answers: the Fulcio leaves of the
//! Kubernetes `pause:3.10` and Chainguard `node` signatures verify
//! against the public-good Fulcio chain at their Rekor-integrated times,
//! their SANs and issuer extensions read as measured, and their SCTs
//! verify against the public-good CT log key (`tests/data/README.md`).
//! The synthetic cases, with leaves built at test time, are the unit
//! tests of `src/codesign.rs`.

use boneli_https::{CertError, CtLog, PublicKey, San, SctError, verify_code_signing};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

const KUBERNETES: &[u8] = include_bytes!("data/sigstore-leaf-kubernetes.pem");
const CHAINGUARD: &[u8] = include_bytes!("data/sigstore-leaf-chainguard.pem");
const FULCIO_INTERMEDIATE: &[u8] = include_bytes!("data/sigstore-fulcio-intermediate.pem");
const FULCIO_ROOT: &[u8] = include_bytes!("data/sigstore-fulcio-root.pem");
const CT_LOG_2022: &[u8] = include_bytes!("data/sigstore-ctfe-2022.pem");
const TEST_ROOT: &[u8] = include_bytes!("data/codesign-root.pem");
const TEST_CT_LOG: &[u8] = include_bytes!("data/codesign-ct-log.pem");

/// The Rekor `integratedTime` of each signature (README).
const KUBERNETES_INTEGRATED: u64 = 1_716_500_129;
const CHAINGUARD_INTEGRATED: u64 = 1_795_470_488;
/// The timestamps of their SCTs, in milliseconds.
const KUBERNETES_SCT_MS: u64 = 1_716_500_128_451;
const CHAINGUARD_SCT_MS: u64 = 1_795_470_485_986;
/// `ctfe.sigstore.dev/2022`'s `validFor.start`, 2022-10-20T00:00:00Z.
const CT_2022_START_MS: u64 = 1_666_224_000_000;

/// Fulcio's OIDC issuer extensions: 1.3.6.1.4.1.57264.1.1 (raw bytes) and
/// 1.3.6.1.4.1.57264.1.8 (a DER UTF8String).
const ISSUER_V1: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x01];
const ISSUER_V2: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x08];

fn der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem)
        .expect("PEM")
        .as_ref()
        .to_vec()
}

fn utf8_string(text: &str) -> Vec<u8> {
    let mut out = vec![0x0C, text.len() as u8];
    out.extend_from_slice(text.as_bytes());
    out
}

fn public_good_ct() -> CtLog {
    CtLog {
        key: PublicKey::from_pem(CT_LOG_2022).expect("CT key"),
        valid_from_ms: CT_2022_START_MS,
        valid_to_ms: None,
    }
}

fn verify(leaf: &[u8], at: u64) -> Result<boneli_https::CodeSigningCert, CertError> {
    let intermediate = der(FULCIO_INTERMEDIATE);
    let root = der(FULCIO_ROOT);
    verify_code_signing(&der(leaf), &[&intermediate], &[&root], at)
}

#[test]
fn kubernetes_leaf_known_answer() {
    let cert = verify(KUBERNETES, KUBERNETES_INTEGRATED).expect("chain");
    assert_eq!(
        cert.sans(),
        &[San::Email(
            "krel-trust@k8s-releng-prod.iam.gserviceaccount.com".into()
        )]
    );
    assert_eq!(
        cert.extension(ISSUER_V1),
        Some(&b"https://accounts.google.com"[..])
    );
    assert_eq!(
        cert.extension(ISSUER_V2),
        Some(&utf8_string("https://accounts.google.com")[..])
    );
    assert_eq!(cert.not_before(), 1_716_500_128);
    assert_eq!(cert.not_after(), 1_716_500_728);
    assert_eq!(cert.public_key().kind(), boneli_https::KeyKind::EcdsaP256);
    assert_eq!(
        cert.verify_embedded_sct(&[public_good_ct()]),
        Ok(KUBERNETES_SCT_MS)
    );
}

#[test]
fn chainguard_leaf_known_answer() {
    let cert = verify(CHAINGUARD, CHAINGUARD_INTEGRATED).expect("chain");
    assert_eq!(
        cert.sans(),
        &[San::Uri(
            "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main"
                .into()
        )]
    );
    assert_eq!(
        cert.extension(ISSUER_V1),
        Some(&b"https://token.actions.githubusercontent.com"[..])
    );
    assert_eq!(
        cert.extension(ISSUER_V2),
        Some(&utf8_string("https://token.actions.githubusercontent.com")[..])
    );
    assert_eq!(cert.not_before(), 1_795_470_485);
    assert_eq!(cert.not_after(), 1_795_471_085);
    assert_eq!(
        cert.verify_embedded_sct(&[public_good_ct()]),
        Ok(CHAINGUARD_SCT_MS)
    );
}

/// A Fulcio leaf lives 10 minutes: the chain verifies at its bounds,
/// inclusive, and not one second outside them, nor at the wall clock.
#[test]
fn real_leaf_only_inside_its_ten_minutes() {
    assert!(verify(KUBERNETES, 1_716_500_128).is_ok());
    assert!(verify(KUBERNETES, 1_716_500_728).is_ok());
    assert_eq!(
        verify(KUBERNETES, 1_716_500_127).expect_err("refused"),
        CertError::OutsideValidity
    );
    assert_eq!(
        verify(KUBERNETES, 1_716_500_729).expect_err("refused"),
        CertError::OutsideValidity
    );
    assert_eq!(
        verify(CHAINGUARD, 1_800_000_000).expect_err("refused"),
        CertError::OutsideValidity
    );
}

/// The intermediate comes only from the caller: the leaf does not chain
/// to the root without it, and not to another root.
#[test]
fn real_leaf_needs_the_intermediate_and_the_root() {
    let root = der(FULCIO_ROOT);
    let intermediate = der(FULCIO_INTERMEDIATE);
    let leaf = der(KUBERNETES);
    assert_eq!(
        verify_code_signing(&leaf, &[], &[&root], KUBERNETES_INTEGRATED).expect_err("refused"),
        CertError::UnknownIssuer
    );
    let other = der(TEST_ROOT);
    assert_eq!(
        verify_code_signing(&leaf, &[&intermediate], &[&other], KUBERNETES_INTEGRATED)
            .expect_err("refused"),
        CertError::UnknownIssuer
    );
    assert_eq!(
        verify_code_signing(&leaf, &[&intermediate], &[], KUBERNETES_INTEGRATED)
            .expect_err("refused"),
        CertError::UnknownIssuer
    );
}

#[test]
fn real_sct_needs_its_log() {
    let cert = verify(CHAINGUARD, CHAINGUARD_INTEGRATED).expect("chain");
    assert_eq!(cert.verify_embedded_sct(&[]), Err(SctError::NoneVerified));
    let other = CtLog {
        key: PublicKey::from_pem(TEST_CT_LOG).expect("key"),
        valid_from_ms: 0,
        valid_to_ms: None,
    };
    assert_eq!(
        cert.verify_embedded_sct(&[other]),
        Err(SctError::NoneVerified)
    );
    // The log's window must hold the SCT's time, inclusive at both ends.
    let window = |from, to| CtLog {
        key: PublicKey::from_pem(CT_LOG_2022).expect("key"),
        valid_from_ms: from,
        valid_to_ms: to,
    };
    let t = CHAINGUARD_SCT_MS;
    assert_eq!(cert.verify_embedded_sct(&[window(t, Some(t))]), Ok(t));
    assert_eq!(
        cert.verify_embedded_sct(&[window(t + 1, None)]),
        Err(SctError::NoneVerified)
    );
    assert_eq!(
        cert.verify_embedded_sct(&[window(0, Some(t - 1))]),
        Err(SctError::NoneVerified)
    );
}

#[test]
fn a_root_that_is_not_a_certificate_is_refused() {
    let leaf = der(KUBERNETES);
    let intermediate = der(FULCIO_INTERMEDIATE);
    assert_eq!(
        verify_code_signing(
            &leaf,
            &[&intermediate],
            &[b"not DER"],
            KUBERNETES_INTEGRATED
        )
        .expect_err("refused"),
        CertError::BadRoot
    );
}

/// Every prefix of a real leaf, and the leaf with any one byte flipped,
/// is an error, never a panic or a pass (a flip in the signature, the
/// TBS or the framing breaks the issuer's signature or the parse).
#[test]
fn damaged_real_leaves_never_pass() {
    let root = der(FULCIO_ROOT);
    let intermediate = der(FULCIO_INTERMEDIATE);
    let leaf = der(KUBERNETES);
    for n in 0..leaf.len() {
        assert!(
            verify_code_signing(
                &leaf[..n],
                &[&intermediate],
                &[&root],
                KUBERNETES_INTEGRATED
            )
            .is_err(),
            "prefix {n}"
        );
    }
    for i in 0..leaf.len() {
        let mut flipped = leaf.clone();
        flipped[i] ^= 0x01;
        assert!(
            verify_code_signing(&flipped, &[&intermediate], &[&root], KUBERNETES_INTEGRATED)
                .is_err(),
            "byte {i}"
        );
    }
}

#[test]
fn error_texts_are_fixed() {
    for (error, text) in [
        (CertError::Malformed, "the certificate is malformed"),
        (
            CertError::BadRoot,
            "a trust root is not a usable CA certificate",
        ),
        (
            CertError::UnknownIssuer,
            "the certificate does not chain to a trust root",
        ),
        (
            CertError::NotCodeSigning,
            "the certificate chain is not valid for code signing",
        ),
        (CertError::IsCa, "the certificate is a CA certificate"),
        (
            CertError::OutsideValidity,
            "the certificate is not valid at the given time",
        ),
        (CertError::Invalid, "the certificate chain does not verify"),
        (
            CertError::NonAsciiSan,
            "a subject alternative name is not ASCII",
        ),
        (
            CertError::UnsupportedKey,
            "the certificate's public key is not supported",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
    for (error, text) in [
        (
            SctError::Missing,
            "the certificate carries no embedded SCT list",
        ),
        (SctError::Malformed, "the embedded SCT list is malformed"),
        (
            SctError::NoneVerified,
            "no embedded SCT from a trusted CT log verifies",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
}

/// `Debug` shows neither SAN text nor certificate bytes.
#[test]
fn debug_hides_the_identity() {
    let cert = verify(KUBERNETES, KUBERNETES_INTEGRATED).expect("chain");
    let shown = format!("{cert:?}");
    assert!(!shown.contains("krel"), "{shown}");
    assert!(!shown.contains("google"), "{shown}");
}
