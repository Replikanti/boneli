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

// ---- Fulcio certificate claims (ADR-034) ---------------------------------

/// What Fulcio wrote into the three GitHub leaves: Source Repository URI
/// (1.12), Ref (1.14), Identifier (1.15) and Build Trigger (1.20). The
/// runner's repository and ref are `RUNNER_REPOSITORY` and `RUNNER_REF`,
/// jq's repository `JQ_REPOSITORY`.
pub const RUNNER_TRIGGER: &str = "workflow_dispatch";
pub const RUNNER_REPOSITORY_ID: &str = "184286875";
pub const JQ_REF: &str = "refs/tags/jq-1.8.2";
pub const JQ_TRIGGER: &str = "push";
pub const JQ_REPOSITORY_ID: &str = "5101141";
pub const CHAINGUARD_REPOSITORY: &str = "https://github.com/chainguard-images/images";
pub const CHAINGUARD_REF: &str = "refs/heads/main";
pub const CHAINGUARD_TRIGGER: &str = "push";
pub const CHAINGUARD_REPOSITORY_ID: &str = "563510952";

// ---- SLSA provenance v0.2 in cosign `.att` (ADR-036) ---------------------

pub const FLUX_ATT: &[u8] = include_bytes!("../data/flux-cli-2.4.0.att.json");
pub const FLUX_ENVELOPE: &[u8] = include_bytes!("../data/flux-cli-2.4.0.envelope.json");
pub const FLUX_273_ATT: &[u8] = include_bytes!("../data/flux-cli-2.7.3.att.json");
pub const FLUX_273_ENVELOPE: &[u8] = include_bytes!("../data/flux-cli-2.7.3.envelope.json");
pub const ARGOCD_ATT: &[u8] = include_bytes!("../data/argocd-2.10.0.att.json");
pub const ARGOCD_ENVELOPE: &[u8] = include_bytes!("../data/argocd-2.10.0.envelope.json");

/// The SHA-256 of the captured `.att` manifests and envelopes, as
/// `tests/data/README.md` lists them.
pub const FLUX_ATT_SHA256: [u8; 32] =
    hex32("467ee9c3451f2f8d7a9f0e9c34eaaf11798ecfa8061d985a828450185b9f7ac5");
pub const FLUX_ENVELOPE_SHA256: [u8; 32] =
    hex32("f12badd94a7463a534fb297d33d0d5c276a62efda34811b285f637a156be214b");
pub const FLUX_273_ATT_SHA256: [u8; 32] =
    hex32("c3da921964eaf4a7c0ef8904d58d227653a89a6e69bf43206a7f1e67ec8bffb7");
pub const FLUX_273_ENVELOPE_SHA256: [u8; 32] =
    hex32("fa11fca232195ae71e8388cc26fe9642746b39e992f2b36f9772e4b7b93f2d67");
pub const ARGOCD_ATT_SHA256: [u8; 32] =
    hex32("954ee0e643ac0c7a5e28b7297849469602c983f4de910766f8daace4c776d1b9");
pub const ARGOCD_ENVELOPE_SHA256: [u8; 32] =
    hex32("cd15fe3cca5f6b94aba70a1f60d710de838f83f9c136f34e4d4cf19622478294");

/// `ghcr.io/fluxcd/flux-cli` v2.4.0's and v2.7.3's index digests, and
/// `quay.io/argoproj/argocd` v2.10.0's: the statements' subjects.
pub const FLUX_DIGEST: [u8; 32] =
    hex32("a9cb966cddc1a0c56dc0d57dda485d9477dd397f8b45f222717b24663471fd1f");
pub const FLUX_273_DIGEST: [u8; 32] =
    hex32("334f73637220fe587fcc8439f35a841c92c44d4695895fd04c77731bd418f14e");
pub const ARGOCD_DIGEST: [u8; 32] =
    hex32("13cdc24e2218bb74fe6ec988c8045c7afc3043f24601e33b20ee78b787440baa");

/// slsa-github-generator's container workflow at v2.0.0: the SAN of the
/// flux-cli v2.4.0 certificate and its statement's `builder.id`.
pub const GENERATOR_V200: &str = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0";
/// The same workflow at any tag, as an identity prefix.
pub const GENERATOR_PREFIX: &str = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/";
pub const FLUX_REPOSITORY: &str = "https://github.com/fluxcd/flux2";
pub const FLUX_REF: &str = "refs/tags/v2.4.0";
pub const FLUX_MATERIAL: &str = "git+https://github.com/fluxcd/flux2@refs/tags/v2.4.0";
pub const FLUX_COMMIT: &str = "5350425cdcd5fa015337e09fa502153c0275bd4b";
pub const FLUX_273_MATERIAL: &str = "git+https://github.com/fluxcd/flux2@refs/tags/v2.7.3";
pub const FLUX_273_COMMIT: &str = "b6e76ca2534f76dcb8dd94fb057cdfa923c3b641";
pub const ARGOCD_REPOSITORY: &str = "https://github.com/argoproj/argo-cd";

/// Rekor's integrated time and log index of the two `dsse` entries.
pub const FLUX_INTEGRATED: u64 = 1_727_714_974;
pub const FLUX_LOG_INDEX: u64 = 135_502_222;
pub const FLUX_273_INTEGRATED: u64 = 1_761_669_969;
pub const FLUX_273_LOG_INDEX: u64 = 649_299_369;

/// The evidence of the first layer of an `.att` manifest and its envelope.
pub fn attestation(manifest: &[u8], envelope: &[u8]) -> Result<Evidence, boneli_sigstore::Refusal> {
    Evidence::from_cosign_attestation(&pairs(&annotations(manifest)), envelope)
}

pub fn flux() -> Evidence {
    attestation(FLUX_ATT, FLUX_ENVELOPE).expect("flux-cli v2.4.0 attestation")
}

pub fn flux_273() -> Evidence {
    attestation(FLUX_273_ATT, FLUX_273_ENVELOPE).expect("flux-cli v2.7.3 attestation")
}

pub fn argocd() -> Evidence {
    attestation(ARGOCD_ATT, ARGOCD_ENVELOPE).expect("argocd v2.10.0 attestation")
}

/// The in-toto statement flux-cli v2.4.0's envelope signs, parsed.
pub fn flux_statement() -> Value {
    let envelope = json(FLUX_ENVELOPE);
    let payload = envelope
        .get("payload")
        .and_then(Value::as_str)
        .expect("payload");
    json(&boneli_sigstore::base64::decode(payload.as_bytes()).expect("base64"))
}

/// A keyless trust over the public-good root for `identity`, with the
/// SLSA v0.2 predicate type only.
pub fn slsa_v02_keyless(identity: Identity) -> Trust {
    Trust::new(
        Vec::new(),
        Some((public_good(), vec![identity])),
        vec![boneli_sigstore::SLSA_PROVENANCE_V02_PREDICATE.to_owned()],
    )
    .expect("trust")
}

/// The generator's exact SAN at v2.0.0.
pub fn generator_identity() -> Identity {
    Identity::new(GITHUB_ACTIONS, SanRule::Uri(GENERATOR_V200.to_owned())).expect("identity")
}

/// The generator's SAN at any tag.
pub fn generator_prefix_identity() -> Identity {
    Identity::new(
        GITHUB_ACTIONS,
        SanRule::UriPrefix(GENERATOR_PREFIX.to_owned()),
    )
    .expect("identity")
}

// ---- Rekor `intoto` 0.0.1 entries for cosign `.att` (ADR-037) ------------

pub const KYVERNO_ATT: &[u8] = include_bytes!("../data/kyverno-1.11.0.att.json");
pub const KYVERNO_ENVELOPE: &[u8] = include_bytes!("../data/kyverno-1.11.0.envelope.json");

/// The SHA-256 of kyverno v1.11.0's `.att` manifest and envelope, as
/// `tests/data/README.md` lists them.
pub const KYVERNO_ATT_SHA256: [u8; 32] =
    hex32("81c56313cb6c8b8906489344965a12d44bca389f482d99a0d406c9923f9923a2");
pub const KYVERNO_ENVELOPE_SHA256: [u8; 32] =
    hex32("148c49ddc6f3099c00a75e6ac186ae003aba2c81c37458b6aa6c0e6f82837513");

/// `ghcr.io/kyverno/kyverno` v1.11.0's index digest, the statement's
/// subject.
pub const KYVERNO_DIGEST: [u8; 32] =
    hex32("4c30afa85d83f4a55ab14642b0630ba51fde573717ba712721edd1408ab39e3a");

/// slsa-github-generator's container workflow at v1.9.0: the SAN of the
/// argocd and kyverno certificates and their statements' `builder.id`.
pub const GENERATOR_V190: &str = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v1.9.0";

pub const ARGOCD_REF: &str = "refs/tags/v2.10.0";
pub const ARGOCD_MATERIAL: &str = "git+https://github.com/argoproj/argo-cd@refs/tags/v2.10.0";
pub const ARGOCD_COMMIT: &str = "2175939ed6156ddd743e60f427f7f48118c971bf";
pub const KYVERNO_REPOSITORY: &str = "https://github.com/kyverno/kyverno";
pub const KYVERNO_REF: &str = "refs/tags/v1.11.0";
pub const KYVERNO_MATERIAL: &str = "git+https://github.com/kyverno/kyverno@refs/tags/v1.11.0";
pub const KYVERNO_COMMIT: &str = "a411fe6377afc165f31f251d119ab526f56fcfb6";

/// Rekor's integrated time and log index of the two `intoto` entries.
/// Each integrated time equals its leaf's notBefore to the second.
pub const ARGOCD_INTEGRATED: u64 = 1_707_230_840;
pub const ARGOCD_LOG_INDEX: u64 = 69_491_963;
pub const KYVERNO_INTEGRATED: u64 = 1_699_611_421;
pub const KYVERNO_LOG_INDEX: u64 = 48_852_930;

pub fn kyverno() -> Evidence {
    attestation(KYVERNO_ATT, KYVERNO_ENVELOPE).expect("kyverno v1.11.0 attestation")
}

/// The generator's exact SAN at v1.9.0.
pub fn generator_v190_identity() -> Identity {
    Identity::new(GITHUB_ACTIONS, SanRule::Uri(GENERATOR_V190.to_owned())).expect("identity")
}

// ---- RFC 3161 timestamps (ADR-038) -------------------------------------

/// The keyless `cosign sign` bundle of
/// `ghcr.io/sigstore/scaffolding/trillian_log_server` v0.7.42: Rekor v1
/// `dsse` 0.0.1 with a SET, and one RFC 3161 token of the public-good TSA.
pub const TRILLIAN_BUNDLE: &[u8] = include_bytes!("../data/trillian-log-server.bundle.json");
/// The Rekor v2 bundles (`hashedrekord` 0.0.2 in `log2025-1`, no
/// integrated time, one token each, ADR-038 D6 and D7).
pub const BEX_BUNDLE: &[u8] = include_bytes!("../data/bex-cnb-run.bundle.json");
pub const AICR_RECIPE_BUNDLE: &[u8] =
    include_bytes!("../data/aicr-recipe-catalog-1.3.0.sigstore.json");
/// The third one: its statement is in-toto v0.1, which a bundle may not
/// carry (ADR-029 S1), so only its entry body is a known answer.
pub const AICR_SBOM_BUNDLE: &[u8] = include_bytes!("../data/aicr-sbom-1.3.0.sigstore.json");

/// bex-cnb-run's index (the statement's subject), the SAN of its leaf and
/// its entry's log index.
pub const BEX_DIGEST: [u8; 32] =
    hex32("b02a639bada113f1b64024c23d5dce1ecb12b67ef4c75b1650999f2bf1732df9");
pub const BEX_WORKFLOW: &str =
    "https://github.com/bex-co/bex/.github/workflows/native-base-image.yml@refs/heads/main";
pub const BEX_LOG_INDEX: u64 = 176_091_980;
/// The recipe catalog's subject, the SAN of both aicr leaves and the
/// catalog entry's log index. Its predicate is SLSA provenance v1.
pub const AICR_RECIPE_DIGEST: [u8; 32] =
    hex32("ffb5e1c293e7a6bb48a7a51862317f631eaaeaf39cb39a6c2a1d23946da1b87f");
pub const AICR_WORKFLOW: &str =
    "https://github.com/NVIDIA/aicr/.github/workflows/on-tag.yaml@refs/tags/v1.3.0";
pub const AICR_RECIPE_LOG_INDEX: u64 = 202_433_287;

pub fn bex() -> Evidence {
    Evidence::from_bundle(BEX_BUNDLE).expect("bex bundle")
}

pub fn bex_identity() -> Identity {
    Identity::new(GITHUB_ACTIONS, SanRule::Uri(BEX_WORKFLOW.to_owned())).expect("identity")
}

pub fn aicr_identity() -> Identity {
    Identity::new(GITHUB_ACTIONS, SanRule::Uri(AICR_WORKFLOW.to_owned())).expect("identity")
}

/// The image index the trillian bundle signs.
pub const TRILLIAN_DIGEST: [u8; 32] =
    hex32("ec7c9ee7a48ebdd4ca53ed68e493f1cb389fb7c899f60b9648ff72ab91504f1f");
pub const TRILLIAN_WORKFLOW: &str =
    "https://github.com/sigstore/scaffolding/.github/workflows/release.yaml@refs/tags/v0.7.42";
/// Its integrated time, which equals its token's genTime and its leaf's
/// notBefore (2026-11-22T17:13:30Z), and its log index.
pub const TRILLIAN_INTEGRATED: u64 = 1_795_367_610;
pub const TRILLIAN_LOG_INDEX: u64 = 4_047_157_521;

pub fn trillian() -> Evidence {
    Evidence::from_bundle(TRILLIAN_BUNDLE).expect("trillian bundle")
}

pub fn trillian_identity() -> Identity {
    Identity::new(GITHUB_ACTIONS, SanRule::Uri(TRILLIAN_WORKFLOW.to_owned())).expect("identity")
}
