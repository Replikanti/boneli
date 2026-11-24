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

// ---- SLSA provenance v1 (ADR-031) ----------------------------------------

pub const RUNNER_BUNDLE: &[u8] = include_bytes!("../data/actions-runner.bundle.json");
pub const JQ_BUNDLE: &[u8] = include_bytes!("../data/jq-1.8.2.bundle.json");

/// The SHA-256 of the two captured bundles, as `tests/data/README.md`
/// lists them.
pub const RUNNER_BUNDLE_SHA256: [u8; 32] =
    hex32("3a9ba514996eb5d5573364af8c8854a14e429dd4fb5dd29bfe58715637124876");
pub const JQ_BUNDLE_SHA256: [u8; 32] =
    hex32("988609523bb7aa9f034ee3a65c297ce8c81eb29b4819af13bb2565b4703ed018");

/// `ghcr.io/actions/actions-runner`'s index digest, the statement's
/// subject.
pub const RUNNER_DIGEST: [u8; 32] =
    hex32("6d0b2d80d80f143f77dcb676e50920100bbb547e39e883454d57f45ab8c31300");
/// `ghcr.io/jqlang/jq:1.8.2`'s index digest.
pub const JQ_DIGEST: [u8; 32] =
    hex32("b9c68867e5766576263a222e91db3de422d802069c7af70440e667a95344e486");

/// The runner's workflow: its SAN and its statement's `builder.id`.
pub const RUNNER_WORKFLOW: &str =
    "https://github.com/actions/runner/.github/workflows/docker-publish.yml@refs/heads/main";
pub const RUNNER_REPOSITORY: &str = "https://github.com/actions/runner";
pub const RUNNER_REF: &str = "refs/heads/main";
pub const RUNNER_MATERIAL: &str = "git+https://github.com/actions/runner@refs/heads/main";
pub const RUNNER_COMMIT: &str = "8cfa1049f86781d141056082d73802d56cd2b433";
/// jq's tag-release workflow, as an identity prefix.
pub const JQ_PREFIX: &str = "https://github.com/jqlang/jq/.github/workflows/ci.yml@refs/tags/";
pub const JQ_REPOSITORY: &str = "https://github.com/jqlang/jq";
pub const JQ_MATERIAL: &str = "git+https://github.com/jqlang/jq@refs/tags/jq-1.8.2";
pub const JQ_COMMIT: &str = "34f7186b86743a083a589741b6cea95293524108";

/// Rekor's integrated time and log index of the two entries.
pub const RUNNER_INTEGRATED: u64 = 1_794_424_176;
pub const RUNNER_LOG_INDEX: u64 = 3_816_483_043;
pub const JQ_INTEGRATED: u64 = 1_781_962_736;
pub const JQ_LOG_INDEX: u64 = 1_884_124_456;

pub fn runner() -> Evidence {
    Evidence::from_bundle(RUNNER_BUNDLE).expect("runner bundle")
}

pub fn jq() -> Evidence {
    Evidence::from_bundle(JQ_BUNDLE).expect("jq bundle")
}

/// The in-toto statement the runner bundle signs, parsed.
pub fn runner_statement() -> Value {
    let bundle = json(RUNNER_BUNDLE);
    let payload = bundle
        .get("dsseEnvelope")
        .and_then(|e| e.get("payload"))
        .and_then(Value::as_str)
        .expect("payload");
    json(&boneli_sigstore::base64::decode(payload.as_bytes()).expect("base64"))
}

/// A keyless trust over the public-good root for `identity`, with the
/// SLSA v1 predicate type only.
pub fn slsa_keyless(identity: Identity) -> Trust {
    Trust::new(
        Vec::new(),
        Some((public_good(), vec![identity])),
        vec![boneli_sigstore::SLSA_PROVENANCE_V1_PREDICATE.to_owned()],
    )
    .expect("trust")
}

pub fn runner_identity() -> Identity {
    Identity::new(GITHUB_ACTIONS, SanRule::Uri(RUNNER_WORKFLOW.to_owned())).expect("identity")
}

pub fn jq_identity() -> Identity {
    Identity::new(GITHUB_ACTIONS, SanRule::UriPrefix(JQ_PREFIX.to_owned())).expect("identity")
}
