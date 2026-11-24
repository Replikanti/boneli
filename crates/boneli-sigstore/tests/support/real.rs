//! The real captures of `tests/data/README.md`: three image signatures
//! and Sigstore's public-good trusted root, as the tests read them.

use std::sync::Arc;

use boneli_json::{Limits, Value};
use boneli_sigstore::{COSIGN_SIGN_PREDICATE, Evidence, Identity, SanRule, Trust, TrustedRoot};

pub const TRUSTED_ROOT: &[u8] = include_bytes!("../data/sigstore-trusted-root.json");
pub const KUBERNETES_SIG: &[u8] = include_bytes!("../data/kubernetes-pause-3.10.sig.json");
pub const KUBERNETES_PAYLOAD: &[u8] = include_bytes!("../data/kubernetes-pause-3.10.payload.json");
pub const CHAINGUARD_SIG: &[u8] = include_bytes!("../data/chainguard-node.sig.json");
pub const CHAINGUARD_PAYLOAD: &[u8] = include_bytes!("../data/chainguard-node.payload.json");
pub const COSIGN_BUNDLE: &[u8] = include_bytes!("../data/cosign-latest.bundle.json");
pub const COSIGN_RELEASE_KEY: &[u8] = include_bytes!("../data/release-cosign.pub");

/// `registry.k8s.io/pause:3.10`'s index digest.
pub const KUBERNETES_DIGEST: [u8; 32] =
    hex32("ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a");
/// `chainguard/node`'s index digest.
pub const CHAINGUARD_DIGEST: [u8; 32] =
    hex32("3fb5318a58807dec0f2ece547efbe8d62c67b7b2fd91a16795b98651d6385dbe");
/// `ghcr.io/sigstore/cosign/cosign:latest`'s index digest (v3.1.4).
pub const COSIGN_DIGEST: [u8; 32] =
    hex32("0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d");

pub const GOOGLE: &str = "https://accounts.google.com";
pub const KUBERNETES_EMAIL: &str = "krel-trust@k8s-releng-prod.iam.gserviceaccount.com";
pub const GITHUB_ACTIONS: &str = "https://token.actions.githubusercontent.com";
pub const CHAINGUARD_WORKFLOW: &str =
    "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main";
pub const CHAINGUARD_PREFIX: &str =
    "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/";

/// The Rekor `integratedTime`s of the two keyless signatures.
pub const KUBERNETES_INTEGRATED: u64 = 1_716_500_129;
pub const CHAINGUARD_INTEGRATED: u64 = 1_795_470_488;

pub const fn hex32(text: &str) -> [u8; 32] {
    let b = text.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) << 4 | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}

pub fn json(bytes: &[u8]) -> Value {
    let limits = Limits::new(1 << 24, 64, 1 << 20).expect("limits");
    boneli_json::parse(bytes, &limits).expect("JSON")
}

/// The annotations of the first layer of a `.sig` manifest.
pub fn annotations(manifest: &[u8]) -> Vec<(String, String)> {
    let manifest = json(manifest);
    let layer = &manifest
        .get("layers")
        .and_then(Value::as_array)
        .expect("layers")[0];
    layer
        .get("annotations")
        .and_then(Value::as_object)
        .expect("annotations")
        .iter()
        .map(|(k, v)| (k.to_owned(), v.as_str().expect("string").to_owned()))
        .collect()
}

pub fn pairs(owned: &[(String, String)]) -> Vec<(&str, &str)> {
    owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// `annotations` with `key` set to `value` (added if missing).
pub fn with(owned: &[(String, String)], key: &str, value: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = owned.iter().filter(|(k, _)| k != key).cloned().collect();
    out.push((key.to_owned(), value.to_owned()));
    out
}

/// `annotations` without `key`.
pub fn without(owned: &[(String, String)], key: &str) -> Vec<(String, String)> {
    owned.iter().filter(|(k, _)| k != key).cloned().collect()
}

pub fn kubernetes() -> Evidence {
    Evidence::from_cosign_layer(&pairs(&annotations(KUBERNETES_SIG)), KUBERNETES_PAYLOAD)
        .expect("Kubernetes evidence")
}

pub fn chainguard() -> Evidence {
    Evidence::from_cosign_layer(&pairs(&annotations(CHAINGUARD_SIG)), CHAINGUARD_PAYLOAD)
        .expect("Chainguard evidence")
}

pub fn cosign() -> Evidence {
    Evidence::from_bundle(COSIGN_BUNDLE).expect("cosign bundle")
}

pub fn public_good() -> Arc<TrustedRoot> {
    Arc::new(TrustedRoot::from_json(TRUSTED_ROOT).expect("public-good root"))
}

pub fn keyless(identities: Vec<Identity>) -> Trust {
    Trust::new(
        Vec::new(),
        Some((public_good(), identities)),
        vec![COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust")
}

pub fn kubernetes_identity() -> Identity {
    Identity::new(GOOGLE, SanRule::Email(KUBERNETES_EMAIL.to_owned())).expect("identity")
}

pub fn chainguard_identity() -> Identity {
    Identity::new(GITHUB_ACTIONS, SanRule::Uri(CHAINGUARD_WORKFLOW.to_owned())).expect("identity")
}
