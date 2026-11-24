//! Image signatures (ADR-029, PR 3 of #57) against the fake registry: the
//! acceptance of the issue on both carriers, keyed with test keys and
//! keyless with Chainguard's real `.sig`, and one test per `boneli-oci`
//! edge case of the plan. The format and crypto edge cases are
//! `boneli-sigstore`'s and `boneli-https`'s (PR 1 and PR 2).
//!
//! Keyed signatures are made at test time with `RsaSha256Key` and the RSA
//! test keys in `tests/data` (README there).

mod support;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use boneli_app::{ImageError, ImageExemption, ImageOrigin, ImageRef, ImageStore, Pulled};
use boneli_https::{PublicKey, RsaSha256Key};
use boneli_oci::{
    AgentExemption, Decision, Error, ExemptScope, MAX_SIGNATURES, OciImageStore, PolicyRule,
    Registry, RepoScope, Repository, Requirement, SignaturePolicy, StoreConfig, Timeouts,
};
use boneli_sigstore::{
    BUNDLE_V03_MEDIA_TYPE, COSIGN_SIGN_PREDICATE, CertificateClaims, ClaimMatch, Claims,
    IN_TOTO_PAYLOAD_TYPE, Identity, Material, SIGNATURE_ANNOTATION, SIMPLE_SIGNING_MEDIA_TYPE,
    SLSA_PROVENANCE_V1_PREDICATE, SanRule, Trust, TrustedRoot, base64, pae,
};

use support::TempDir;
use support::images::{Layer, Pushed, config, push};
use support::registry::{
    Fake, Hub, Referrers, Reply, Seen, challenge_for, descriptor, digest_of, entry, image, index,
    media,
};
use support::tarball::Tar;

const POLICY_OFF_REQUESTS: &str = include_str!("data/policy-off-requests.txt");
const SIGNER_KEY: &[u8] = include_bytes!("data/test-only-signer.key");
const SIGNER_PUB: &[u8] = include_bytes!("data/test-only-signer.pub.pem");
const OTHER_KEY: &[u8] = include_bytes!("data/test-only-other.key");
const OTHER_PUB: &[u8] = include_bytes!("data/test-only-other.pub.pem");
const TRUSTED_ROOT: &[u8] = include_bytes!("data/sigstore-trusted-root.json");
const CG_INDEX: &[u8] = include_bytes!("data/chainguard-node.index.json");
const CG_AMD64: &[u8] = include_bytes!("data/chainguard-node.amd64.json");
const CG_CONFIG: &[u8] = include_bytes!("data/chainguard-node.amd64-config.json");
const CG_SIG: &[u8] = include_bytes!("data/chainguard-node.sig.json");
const CG_PAYLOAD: &[u8] = include_bytes!("data/chainguard-node.payload.json");
const COSIGN_INDEX: &[u8] = include_bytes!("data/cosign.index.json");
const COSIGN_AMD64: &[u8] = include_bytes!("data/cosign.amd64.json");
const COSIGN_CONFIG: &[u8] = include_bytes!("data/cosign.amd64-config.json");
const COSIGN_REFERRERS: &[u8] = include_bytes!("data/cosign.referrers-tag.json");
const COSIGN_REFERRER: &[u8] = include_bytes!("data/cosign.referrer.json");
const COSIGN_BUNDLE: &[u8] = include_bytes!("data/cosign.bundle.json");
const COSIGN_RELEASE_KEY: &[u8] = include_bytes!("data/release-cosign.pub");
const JQ_INDEX: &[u8] = include_bytes!("data/jq.index.json");
const JQ_AMD64: &[u8] = include_bytes!("data/jq.amd64.json");
const JQ_CONFIG: &[u8] = include_bytes!("data/jq.amd64-config.json");
const JQ_REFERRERS: &[u8] = include_bytes!("data/jq.referrers-tag.json");
const JQ_REFERRER: &[u8] = include_bytes!("data/jq.referrer.json");
const JQ_BUNDLE: &[u8] = include_bytes!("data/jq.bundle.json");

const REPO: &str = "library/app";
const GITHUB_ACTIONS: &str = "https://token.actions.githubusercontent.com";
const CHAINGUARD_WORKFLOW: &str =
    "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main";
const SIG_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const EMPTY_CONFIG: &str = "application/vnd.oci.empty.v1+json";
const EMPTY_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

// ---------------------------------------------------------------------
// Signing and the artifacts the registry serves
// ---------------------------------------------------------------------

struct Signer {
    key: RsaSha256Key,
}

impl Signer {
    fn new(pem: &[u8]) -> Signer {
        Signer {
            key: RsaSha256Key::from_pem(&mut pem.to_vec()).expect("test key"),
        }
    }

    fn sign(&self, message: &[u8]) -> String {
        base64::encode(&self.key.sign(message).expect("sign"))
    }
}

fn signer() -> Signer {
    Signer::new(SIGNER_KEY)
}

fn other() -> Signer {
    Signer::new(OTHER_KEY)
}

/// A keyed trust over `keys` with the default predicate list.
fn keyed(keys: &[&[u8]]) -> Arc<Trust> {
    Arc::new(
        Trust::new(
            keys.iter()
                .map(|k| PublicKey::from_pem(k).expect("key"))
                .collect(),
            None,
            vec![COSIGN_SIGN_PREDICATE.to_owned()],
        )
        .expect("trust"),
    )
}

/// Chainguard's keyless trust over the public-good root, with `san`.
fn chainguard_trust(san: SanRule) -> Arc<Trust> {
    let root = Arc::new(TrustedRoot::from_json(TRUSTED_ROOT).expect("root"));
    let identity = Identity::new(GITHUB_ACTIONS, san).expect("identity");
    Arc::new(
        Trust::new(
            Vec::new(),
            Some((root, vec![identity])),
            vec![COSIGN_SIGN_PREDICATE.to_owned()],
        )
        .expect("trust"),
    )
}

fn rule(scope: RepoScope, requirement: Requirement) -> PolicyRule {
    PolicyRule {
        registry: "docker.io".to_owned(),
        scope,
        requirement,
    }
}

fn rules(rules: Vec<PolicyRule>) -> SignaturePolicy {
    SignaturePolicy::new(Requirement::Off, rules).expect("policy")
}

/// `Required` with `trust` for every repository of Docker Hub.
fn required(trust: Arc<Trust>) -> SignaturePolicy {
    rules(vec![rule(
        RepoScope::Registry,
        Requirement::Required(trust),
    )])
}

fn trusted() -> SignaturePolicy {
    required(keyed(&[SIGNER_PUB]))
}

fn repo(text: &str) -> Repository {
    Repository::parse(text).expect("repository")
}

/// `sha256:<hex>` as the tag schema writes it: `sha256-<hex>`.
fn tag_of(digest: &str) -> String {
    digest.replace(':', "-")
}

/// The digest in `json` after the first `"digest":"`, skipping `skip`.
fn nth_digest(json: &[u8], skip: usize) -> String {
    let text = std::str::from_utf8(json).expect("utf-8");
    text.split("\"digest\":\"").nth(skip + 1).expect("digest")[..71].to_owned()
}

/// A simple-signing payload naming `digest`.
fn payload(digest: &str) -> Vec<u8> {
    format!(
        "{{\"critical\":{{\"identity\":{{\"docker-reference\":\"index.docker.io/{REPO}\"}},\
         \"image\":{{\"docker-manifest-digest\":\"{digest}\"}},\
         \"type\":\"cosign container image signature\"}},\"optional\":null}}"
    )
    .into_bytes()
}

/// A `.sig` layer over `payload`, signed by `signer`, the payload added to
/// the hub.
fn sig_layer(hub: &mut Hub, signer: &Signer, payload: &[u8]) -> String {
    sig_layer_typed(hub, signer, payload, SIMPLE_SIGNING_MEDIA_TYPE)
}

fn sig_layer_typed(hub: &mut Hub, signer: &Signer, payload: &[u8], media_type: &str) -> String {
    let digest = hub.blob(REPO, payload);
    format!(
        r#"{{"mediaType":"{media_type}","digest":"{digest}","size":{},"annotations":{{"{SIGNATURE_ANNOTATION}":"{}"}}}}"#,
        payload.len(),
        signer.sign(payload)
    )
}

/// A `.sig` manifest over these layers.
fn sig_manifest(layers: &[String]) -> Vec<u8> {
    let config = br#"{"architecture":"","os":"","rootfs":{"type":"layers","diff_ids":[]}}"#;
    format!(
        r#"{{"schemaVersion":2,"mediaType":"{}","config":{},"layers":[{}]}}"#,
        media::MANIFEST,
        descriptor(SIG_CONFIG, &digest_of(config), config.len()),
        layers.join(",")
    )
    .into_bytes()
}

/// Tags `layers` as the `.sig` of `subject`.
fn sign_legacy(hub: &mut Hub, subject: &str, layers: &[String]) -> String {
    let tag = format!("{}.sig", tag_of(subject));
    hub.tag(REPO, &tag, media::MANIFEST, &sig_manifest(layers))
}

/// An in-toto statement v1 over `subjects` with `predicate`.
fn statement(subjects: &[&str], predicate: &str) -> Vec<u8> {
    statement_with_body(subjects, predicate, "{}")
}

/// An in-toto statement v1 over `subjects` with `predicate` and the
/// predicate body `body` (JSON).
fn statement_with_body(subjects: &[&str], predicate: &str, body: &str) -> Vec<u8> {
    let subjects: Vec<String> = subjects
        .iter()
        .map(|d| {
            format!(
                r#"{{"name":"index.docker.io/{REPO}","digest":{{"sha256":"{}"}}}}"#,
                d.trim_start_matches("sha256:")
            )
        })
        .collect();
    format!(
        r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[{}],"predicateType":"{predicate}","predicate":{body}}}"#,
        subjects.join(",")
    )
    .into_bytes()
}

/// A keyed bundle v0.3 with a DSSE envelope over `statement`.
fn bundle(signer: &Signer, statement: &[u8]) -> Vec<u8> {
    let sig = signer.sign(&pae(IN_TOTO_PAYLOAD_TYPE.as_bytes(), statement));
    format!(
        r#"{{"mediaType":"{BUNDLE_V03_MEDIA_TYPE}","verificationMaterial":{{"publicKey":{{"hint":"test"}}}},"dsseEnvelope":{{"payload":"{}","payloadType":"{IN_TOTO_PAYLOAD_TYPE}","signatures":[{{"sig":"{sig}"}}]}}}}"#,
        base64::encode(statement)
    )
    .into_bytes()
}

/// A bundle by `signer` whose statement names `subjects`.
fn bundle_over(signer: &Signer, subjects: &[&str]) -> Vec<u8> {
    bundle(signer, &statement(subjects, COSIGN_SIGN_PREDICATE))
}

/// A referrer manifest for `subject` holding `bundle` (added to the hub);
/// returns the listing entry for it.
fn referrer(hub: &mut Hub, subject: &str, bundle: &[u8]) -> String {
    referrer_with(
        hub,
        subject,
        bundle,
        BUNDLE_V03_MEDIA_TYPE,
        COSIGN_SIGN_PREDICATE,
    )
}

fn referrer_with(
    hub: &mut Hub,
    subject: &str,
    bundle: &[u8],
    artifact_type: &str,
    predicate: &str,
) -> String {
    let bundle_digest = hub.blob(REPO, bundle);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"{}","artifactType":"{BUNDLE_V03_MEDIA_TYPE}","config":{},"layers":[{}],"subject":{}}}"#,
        media::MANIFEST,
        descriptor(EMPTY_CONFIG, EMPTY_DIGEST, 2),
        descriptor(BUNDLE_V03_MEDIA_TYPE, &bundle_digest, bundle.len()),
        descriptor(media::INDEX, subject, 100),
    )
    .into_bytes();
    let digest = hub.document(REPO, media::MANIFEST, &manifest);
    listing_entry(&digest, manifest.len(), artifact_type, predicate)
}

fn listing_entry(digest: &str, size: usize, artifact_type: &str, predicate: &str) -> String {
    format!(
        r#"{{"mediaType":"{}","digest":"{digest}","size":{size},"artifactType":"{artifact_type}","annotations":{{"dev.sigstore.bundle.content":"dsse-envelope","dev.sigstore.bundle.predicateType":"{predicate}"}}}}"#,
        media::MANIFEST
    )
}

fn listing(entries: &[String]) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion":2,"mediaType":"{}","manifests":[{}]}}"#,
        media::INDEX,
        entries.join(",")
    )
    .into_bytes()
}

/// Lists `entries` as the referrers of `subject`.
fn list(hub: &mut Hub, subject: &str, entries: &[String]) {
    hub.referrers(REPO, subject, Referrers::Listing(listing(entries)));
}

/// A bundle signed by `signer` over `subject`, listed by the referrers
/// API.
fn sign_bundle(hub: &mut Hub, signer: &Signer, subject: &str) {
    let entry = referrer(hub, subject, &bundle_over(signer, &[subject]));
    list(hub, subject, &[entry]);
}

/// Signs `subject` through `carrier` (`legacy` or `bundle`).
fn sign(hub: &mut Hub, carrier: &str, signer: &Signer, subject: &str, over: &str) {
    if carrier == "legacy" {
        let layer = sig_layer(hub, signer, &payload(over));
        sign_legacy(hub, subject, &[layer]);
    } else {
        let entry = referrer(hub, subject, &bundle_over(signer, &[over]));
        list(hub, subject, &[entry]);
    }
}

/// One candidate over `over` attached to `subject` through `carrier`.
fn candidate(hub: &mut Hub, carrier: &str, signer: &Signer, subject: &str, over: &str) -> String {
    if carrier == "legacy" {
        sig_layer(hub, signer, &payload(over))
    } else {
        referrer(hub, subject, &bundle_over(signer, &[over]))
    }
}

/// Attaches `entries` to `subject` through `carrier`.
fn attach(hub: &mut Hub, carrier: &str, subject: &str, entries: &[String]) {
    if carrier == "legacy" {
        sign_legacy(hub, subject, entries);
    } else {
        list(hub, subject, entries);
    }
}

// ---------------------------------------------------------------------
// The image, the store and what the fake saw
// ---------------------------------------------------------------------

fn image_ref(name: &str, digest: &str) -> ImageRef {
    ImageRef {
        name: name.to_owned(),
        digest: digest.to_owned(),
        platform: "linux/amd64".to_owned(),
        origin: ImageOrigin::Operator,
    }
}

/// `library/app`: three layers, the middle one gzip, under an index.
fn app_hub() -> (Hub, Pushed) {
    let mut hub = Hub::default();
    let pushed = push(
        &mut hub,
        REPO,
        &[
            Layer::file("etc/base", b"base\n"),
            Layer::gzip(Tar::new().file("usr/bin/tool", 0o755, b"#!\n").finish()),
            Layer::file("etc/top", b"top\n"),
        ],
        r#"{"Cmd":["tool"]}"#,
    );
    (hub, pushed)
}

fn hub_fake(hub: Hub) -> Fake {
    Fake::new(move |s| hub.handle(s))
}

fn config_with(fake: &Fake, policy: SignaturePolicy) -> StoreConfig {
    let mut config = config(fake);
    config.signatures = policy;
    config
}

fn open_with(root: &Path, fake: &Fake, policy: SignaturePolicy) -> OciImageStore {
    OciImageStore::open(root, config_with(fake, policy)).expect("open")
}

/// Pulls `library/app` at `digest` into a fresh store under `policy`.
fn pull_once(
    fake: &Fake,
    policy: SignaturePolicy,
    digest: &str,
) -> (TempDir, Result<String, ImageError>) {
    let tmp = TempDir::new("sig");
    let store = open_with(&tmp.path().join("store"), fake, policy);
    let result = store
        .pull(&image_ref(REPO, digest))
        .map(|r| r.rootfs.as_str().to_owned());
    (tmp, result)
}

/// Every request as one line: the dialed host and port, the target and
/// every header field in order, so a comparison is byte for byte.
fn request_log(seen: &[Seen]) -> String {
    let mut out = String::new();
    for s in seen {
        out.push_str(&format!("{}:{} {}", s.host, s.port, s.target));
        for (name, value) in &s.headers {
            out.push_str(&format!(" | {name}: {value}"));
        }
        out.push('\n');
    }
    out
}

/// The targets of the requests that carried a token.
fn targets(seen: &[Seen]) -> Vec<String> {
    seen.iter()
        .filter(|s| s.header("authorization").is_some())
        .map(|s| s.target.clone())
        .collect()
}

/// Whether the fake saw a request for one of the image's layer blobs.
fn layer_requested(fake: &Fake, pushed: &Pushed) -> bool {
    fake.seen().iter().any(|s| {
        pushed
            .blobs
            .iter()
            .any(|b| s.target.ends_with(&format!("/blobs/{b}")))
    })
}

/// The committed layers and sidecars under the store in `tmp`.
fn layer_entries(tmp: &TempDir) -> Vec<String> {
    let dir = tmp.path().join("store/layers/sha256");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("layers")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    names.sort();
    names
}

/// The pull failed under the policy, before any layer was requested or
/// committed; returns the detail.
fn refused_before_layers(
    fake: &Fake,
    pushed: &Pushed,
    tmp: &TempDir,
    result: Result<String, ImageError>,
) -> String {
    let detail = match result {
        Err(ImageError::Failed { detail }) => detail,
        other => panic!("the pull must be refused: {other:?}"),
    };
    assert!(detail.starts_with("signature policy: "), "{detail}");
    assert!(
        !layer_requested(fake, pushed),
        "a layer was requested: {:?}",
        targets(&fake.seen())
    );
    assert!(layer_entries(tmp).is_empty(), "{:?}", layer_entries(tmp));
    detail
}

fn passed(result: Result<String, ImageError>, pushed: &Pushed) {
    assert_eq!(result.expect("the pull passes"), pushed.manifest);
}

// ---------------------------------------------------------------------
// The issue's acceptance, keyed, on both carriers
// ---------------------------------------------------------------------

/// A signature by the trusted key over the image's digest lets the pull
/// pass, through the `.sig` tag and through a bundle referrer alike; the
/// layers are unpacked.
#[test]
fn trusted_signature_pulls() {
    for carrier in ["legacy", "bundle"] {
        let (mut hub, pushed) = app_hub();
        sign(&mut hub, carrier, &signer(), &pushed.index, &pushed.index);
        let fake = hub_fake(hub);
        let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
        passed(result, &pushed);
        assert!(layer_requested(&fake, &pushed), "{carrier}");
        assert_eq!(layer_entries(&tmp).len(), 6, "{carrier}");
    }
}

/// An unsigned image is refused before any layer is requested; the detail
/// names both carriers for both subjects.
#[test]
fn unsigned_refused_before_any_layer_request() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    for subject in [&pushed.index, &pushed.manifest] {
        assert!(
            detail.contains(&format!("{subject}: .sig: none")),
            "{detail}"
        );
        assert!(
            detail.contains(&format!("{subject}: referrers: unsupported, tag: none")),
            "{detail}"
        );
    }
}

/// A valid signature by a key the rule does not trust is refused, on both
/// carriers, before any layer is requested.
#[test]
fn other_identity_refused_before_any_layer_request() {
    for carrier in ["legacy", "bundle"] {
        let (mut hub, pushed) = app_hub();
        sign(&mut hub, carrier, &other(), &pushed.index, &pushed.index);
        let fake = hub_fake(hub);
        let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
        let detail = refused_before_layers(&fake, &pushed, &tmp, result);
        assert!(
            detail.contains("no trusted key verifies the signature"),
            "{carrier}: {detail}"
        );
    }
}

/// The trusted key's signature over another digest is refused, on both
/// carriers, before any layer is requested.
#[test]
fn signature_over_other_digest_refused_before_any_layer_request() {
    let elsewhere = digest_of(b"another image");
    for carrier in ["legacy", "bundle"] {
        let (mut hub, pushed) = app_hub();
        sign(&mut hub, carrier, &signer(), &pushed.index, &elsewhere);
        let fake = hub_fake(hub);
        let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
        let detail = refused_before_layers(&fake, &pushed, &tmp, result);
        assert!(
            detail.contains("the signature is not over this digest"),
            "{carrier}: {detail}"
        );
    }
}

// ---------------------------------------------------------------------
// Keyless, offline, with Chainguard's real `.sig`
// ---------------------------------------------------------------------

const CG_REPO: &str = "chainguard/node";
const CG_DIGEST: &str = "sha256:3fb5318a58807dec0f2ece547efbe8d62c67b7b2fd91a16795b98651d6385dbe";

/// A hub with Chainguard's real index, amd64 manifest, config and `.sig`
/// (captured 2026-11-24) under `repo`, the `.sig` tagged for `sig_for`,
/// and no layer blob: a layer request is answered `404`.
fn chainguard_hub(repo: &str, sig_for: &str) -> Hub {
    let mut hub = Hub::default();
    hub.document(repo, media::INDEX, CG_INDEX);
    hub.document(repo, media::MANIFEST, CG_AMD64);
    hub.blob(repo, CG_CONFIG);
    hub.blob(repo, CG_PAYLOAD);
    hub.tag(
        repo,
        &format!("{}.sig", tag_of(sig_for)),
        media::MANIFEST,
        CG_SIG,
    );
    hub
}

fn chainguard_policy(san: SanRule) -> SignaturePolicy {
    rules(vec![rule(
        RepoScope::Prefix("chainguard/".to_owned()),
        Requirement::Required(chainguard_trust(san)),
    )])
}

/// The first layer of Chainguard's amd64 manifest (the config comes first).
fn chainguard_first_layer() -> String {
    nth_digest(CG_AMD64, 1)
}

/// Chainguard's keyless signature verifies against the public-good root
/// with its workflow identity, exactly and by the `@refs/heads/` prefix,
/// and the pull goes on to its first layer: the request is the proof (the
/// fake answers it `404`).
#[test]
fn keyless_real_signature_reaches_layers() {
    for san in [
        SanRule::Uri(CHAINGUARD_WORKFLOW.to_owned()),
        SanRule::UriPrefix(CHAINGUARD_WORKFLOW.trim_end_matches("main").to_owned()),
    ] {
        let fake = hub_fake(chainguard_hub(CG_REPO, CG_DIGEST));
        let tmp = TempDir::new("keyless");
        let store = open_with(&tmp.path().join("store"), &fake, chainguard_policy(san));
        let detail = match store.pull(&image_ref(CG_REPO, CG_DIGEST)) {
            Err(ImageError::Failed { detail }) => detail,
            other => panic!("the layer request must fail: {other:?}"),
        };
        assert!(detail.contains("404"), "{detail}");
        assert!(!detail.contains("signature policy"), "{detail}");
        let layer = chainguard_first_layer();
        assert!(
            targets(&fake.seen())
                .iter()
                .any(|t| t.ends_with(&format!("/blobs/{layer}"))),
            "no layer request"
        );
    }
}

/// The same real signature under another identity is refused before any
/// layer request.
#[test]
fn keyless_other_identity_refused_before_any_layer_request() {
    let fake = hub_fake(chainguard_hub(CG_REPO, CG_DIGEST));
    let tmp = TempDir::new("keyless-other");
    let other = SanRule::Uri(CHAINGUARD_WORKFLOW.replace("main", "dev"));
    let store = open_with(&tmp.path().join("store"), &fake, chainguard_policy(other));
    let detail = match store.pull(&image_ref(CG_REPO, CG_DIGEST)) {
        Err(ImageError::Failed { detail }) => detail,
        other => panic!("{other:?}"),
    };
    assert!(
        detail.contains("the signer is not a trusted identity"),
        "{detail}"
    );
    let layer = chainguard_first_layer();
    assert!(!targets(&fake.seen()).iter().any(|t| t.ends_with(&layer)));
}

/// The real `.sig` served for another image's digest is refused: its
/// payload names Chainguard's index.
#[test]
fn keyless_signature_for_other_image_refused() {
    let (mut hub, pushed) = app_hub();
    let chainguard = chainguard_hub(REPO, &pushed.index);
    hub.blobs.extend(chainguard.blobs);
    hub.tags = chainguard.tags;
    let fake = hub_fake(hub);
    let policy = required(chainguard_trust(SanRule::Uri(
        CHAINGUARD_WORKFLOW.to_owned(),
    )));
    let (tmp, result) = pull_once(&fake, policy, &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(
        detail.contains("the signature is not over this digest"),
        "{detail}"
    );
}

/// cosign's real keyed bundle as GHCR serves it (captured 2026-11-24): no
/// `.sig`, the referrers API answers `404`, the tag `sha256-<index hex>`
/// lists two bundle referrers. With cosign's release key the first one
/// verifies and the pull goes on to its first layer (answered `404`);
/// with another key it is refused before any layer request.
#[test]
fn keyed_real_bundle_through_fallback_tag() {
    let repo = "sigstore/cosign/cosign";
    let index = digest_of(COSIGN_INDEX);
    let mut hub = Hub::default();
    hub.document(repo, media::INDEX, COSIGN_INDEX);
    hub.document(repo, media::MANIFEST, COSIGN_AMD64);
    hub.document(repo, media::MANIFEST, COSIGN_REFERRER);
    hub.blob(repo, COSIGN_CONFIG);
    hub.blob(repo, COSIGN_BUNDLE);
    hub.tag(repo, &tag_of(&index), media::INDEX, COSIGN_REFERRERS);
    let first_layer = nth_digest(COSIGN_AMD64, 1);
    for (key, passes) in [(COSIGN_RELEASE_KEY, true), (SIGNER_PUB, false)] {
        let fake = hub_fake(hub.clone());
        let tmp = TempDir::new("cosign");
        let store = open_with(&tmp.path().join("store"), &fake, required(keyed(&[key])));
        let detail = match store.pull(&image_ref(repo, &index)) {
            Err(ImageError::Failed { detail }) => detail,
            other => panic!("{other:?}"),
        };
        let reached = targets(&fake.seen())
            .iter()
            .any(|t| t.ends_with(&format!("/blobs/{first_layer}")));
        assert_eq!(reached, passes, "{detail}");
        assert_eq!(detail.starts_with("signature policy"), !passes, "{detail}");
        if !passes {
            assert!(
                detail.contains("referrers tag: 2 listed, 2 candidates"),
                "{detail}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------

/// The requests of the pulls the log was recorded with before #57 PR 3:
/// a cold pull by index and a warm one, then a cold pull by manifest
/// through the CDN, each into a fresh store, under `config`.
fn logged_pulls(config: impl Fn(&Fake) -> StoreConfig) -> String {
    logged_pulls_as(ImageOrigin::Operator, config)
}

/// [`logged_pulls`] with references chosen by `origin` (ADR-032).
fn logged_pulls_as(origin: ImageOrigin, config: impl Fn(&Fake) -> StoreConfig) -> String {
    let mut log = String::new();
    for (cdn, by_manifest) in [(false, false), (true, true)] {
        let (mut hub, pushed) = app_hub();
        hub.cdn = cdn;
        let fake = hub_fake(hub);
        let tmp = TempDir::new("policy-off");
        let store = OciImageStore::open(&tmp.path().join("store"), config(&fake)).expect("open");
        let digest = if by_manifest {
            &pushed.manifest
        } else {
            &pushed.index
        };
        let image = ImageRef {
            origin,
            ..image_ref(REPO, digest)
        };
        store.pull(&image).expect("cold pull");
        store.pull(&image).expect("warm pull");
        log.push_str(&format!("# cdn={cdn} by_manifest={by_manifest}\n"));
        log.push_str(&request_log(&fake.seen()));
    }
    log
}

/// With no rule (the default policy), and with rules that do not apply
/// (an `Off` rule for the repository, `Required` for other repositories
/// and registries), a pull sends exactly the requests of #7, byte for
/// byte: the log recorded at the merge base, before this change.
#[test]
fn policy_off_requests_unchanged() {
    let log = logged_pulls(config);
    assert_eq!(log, POLICY_OFF_REQUESTS);
    for line in log.lines() {
        for marker in [".sig", "/referrers/", "sha256-"] {
            assert!(!line.contains(marker), "{line}");
        }
    }
    let unrelated = |fake: &Fake| {
        let trust = keyed(&[SIGNER_PUB]);
        let req = || Requirement::Required(Arc::clone(&trust));
        let mut ghcr = rule(RepoScope::Registry, req());
        ghcr.registry = "ghcr.io".to_owned();
        let policy = SignaturePolicy::new(
            Requirement::Off,
            vec![
                rule(RepoScope::Exact(repo(REPO)), Requirement::Off),
                rule(RepoScope::Prefix("library/app/".to_owned()), req()),
                rule(RepoScope::Exact(repo("library/apps")), req()),
                rule(RepoScope::Exact(repo("app")), req()),
                rule(RepoScope::Registry, req()),
                ghcr,
            ],
        )
        .expect("policy");
        let mut config = config_with(fake, policy);
        config.registries.push(
            Registry::new(
                "ghcr.io",
                "ghcr.io",
                &["ghcr.io"],
                &[".githubusercontent.com"],
            )
            .expect("registry"),
        );
        config
    };
    assert_eq!(logged_pulls(unrelated), POLICY_OFF_REQUESTS);
}

/// Two rules with the same registry and scope are refused; the same scope
/// under two registries, and an exact rule next to a prefix of the same
/// text, are fine.
#[test]
fn duplicate_rule_refused() {
    let trust = keyed(&[SIGNER_PUB]);
    let req = || Requirement::Required(Arc::clone(&trust));
    for scope in [
        RepoScope::Registry,
        RepoScope::Exact(repo(REPO)),
        RepoScope::Prefix("library/".to_owned()),
    ] {
        match SignaturePolicy::new(
            Requirement::Off,
            vec![rule(scope.clone(), req()), rule(scope, Requirement::Off)],
        ) {
            Err(Error::InvalidPolicy(_)) => {}
            other => panic!("{other:?}"),
        }
    }
    let mut ghcr = rule(RepoScope::Registry, req());
    ghcr.registry = "ghcr.io".to_owned();
    SignaturePolicy::new(
        Requirement::Off,
        vec![rule(RepoScope::Registry, req()), ghcr],
    )
    .expect("two registries");
    SignaturePolicy::new(
        Requirement::Off,
        vec![
            rule(RepoScope::Exact(repo("library")), req()),
            rule(RepoScope::Prefix("library/".to_owned()), req()),
        ],
    )
    .expect("an exact rule and a prefix with the same text");
}

/// A prefix must be repository components ending in `/`.
#[test]
fn prefix_without_boundary_refused() {
    let trust = keyed(&[SIGNER_PUB]);
    for prefix in [
        "acme",
        "acme//",
        "/",
        "",
        "Acme/",
        "acme /",
        "a\u{430}cme/",
        "acme/app",
        "acme/./",
    ] {
        match SignaturePolicy::new(
            Requirement::Off,
            vec![rule(
                RepoScope::Prefix(prefix.to_owned()),
                Requirement::Required(Arc::clone(&trust)),
            )],
        ) {
            Err(Error::InvalidPolicy(_)) => {}
            other => panic!("{prefix:?}: {other:?}"),
        }
    }
    SignaturePolicy::new(
        Requirement::Off,
        vec![rule(
            RepoScope::Prefix("acme/app/".to_owned()),
            Requirement::Required(trust),
        )],
    )
    .expect("a good prefix");
}

fn is_required(r: &Requirement) -> bool {
    matches!(r, Requirement::Required(_))
}

/// Rules `acme/` and `acme/app/` both apply to `acme/app/x`; the longer
/// one wins; an exact rule beats both; the registry-wide rule beats the
/// default; a rule of another registry never applies.
#[test]
fn most_specific_rule_wins() {
    let trust = keyed(&[SIGNER_PUB]);
    let req = || Requirement::Required(Arc::clone(&trust));
    let forward = vec![
        rule(RepoScope::Prefix("acme/".to_owned()), Requirement::Off),
        rule(RepoScope::Prefix("acme/app/".to_owned()), req()),
        rule(RepoScope::Exact(repo("acme/app/x")), Requirement::Off),
        rule(RepoScope::Registry, req()),
        rule(RepoScope::Prefix("acme/app/x/".to_owned()), req()),
    ];
    let mut backward = forward.clone();
    backward.reverse();
    for policy in [rules(forward), rules(backward)] {
        let at = |r: &str| is_required(policy.requirement("docker.io", &repo(r)));
        assert!(at("acme/app/y"));
        assert!(!at("acme/app/x"));
        assert!(at("acme/app/x/y"));
        assert!(!at("acme/other"));
        assert!(at("elsewhere"));
        assert!(!is_required(
            policy.requirement("ghcr.io", &repo("acme/app/y"))
        ));
    }
    // The default applies where no rule does.
    let strict = SignaturePolicy::new(
        req(),
        vec![rule(RepoScope::Exact(repo("x")), Requirement::Off)],
    )
    .expect("policy");
    assert!(is_required(strict.requirement("ghcr.io", &repo("y"))));
    assert!(is_required(strict.requirement("docker.io", &repo("y"))));
    assert!(!is_required(strict.requirement("docker.io", &repo("x"))));
    assert!(!is_required(
        SignaturePolicy::off().requirement("docker.io", &repo("x"))
    ));
}

/// A repository is matched as written: a rule for `library/node` does not
/// cover `node`, and one for `acme/` does not cover `acme-evil/x` or
/// `acme`; in a pull, a rule for `app` does not cover `library/app`.
#[test]
fn rule_matches_repository_as_written() {
    let trust = keyed(&[SIGNER_PUB]);
    let policy = rules(vec![
        rule(
            RepoScope::Exact(repo("library/node")),
            Requirement::Required(Arc::clone(&trust)),
        ),
        rule(
            RepoScope::Prefix("acme/".to_owned()),
            Requirement::Required(Arc::clone(&trust)),
        ),
    ]);
    assert!(is_required(
        policy.requirement("docker.io", &repo("library/node"))
    ));
    assert!(is_required(
        policy.requirement("docker.io", &repo("acme/x/y"))
    ));
    for r in [
        "node",
        "library/node/x",
        "library/nodes",
        "acme-evil/x",
        "acme",
    ] {
        assert!(
            !is_required(policy.requirement("docker.io", &repo(r))),
            "{r}"
        );
    }
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let short = rules(vec![rule(
        RepoScope::Exact(repo("app")),
        Requirement::Required(trust),
    )]);
    let (_tmp, result) = pull_once(&fake, short, &pushed.index);
    passed(result, &pushed);
}

/// A rule for a registry the store does not pull from fails `open`, before
/// anything is created; once the registry is listed, the store opens.
#[test]
fn rule_for_unknown_registry_refused() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("unknown-registry");
    let mut ghcr = rule(
        RepoScope::Registry,
        Requirement::Required(keyed(&[SIGNER_PUB])),
    );
    ghcr.registry = "ghcr.io".to_owned();
    let root = tmp.path().join("store");
    match OciImageStore::open(&root, config_with(&fake, rules(vec![ghcr.clone()]))) {
        Err(Error::InvalidPolicy(detail)) => assert!(detail.contains("ghcr.io"), "{detail}"),
        other => panic!("{other:?}"),
    }
    assert!(!root.exists(), "open created the root");
    let mut config = config_with(&fake, rules(vec![ghcr]));
    config.registries.push(
        Registry::new(
            "ghcr.io",
            "ghcr.io",
            &["ghcr.io"],
            &[".githubusercontent.com"],
        )
        .expect("registry"),
    );
    OciImageStore::open(&root, config).expect("a listed registry");
}

// ---------------------------------------------------------------------
// Listings and carriers
// ---------------------------------------------------------------------

/// A `.sig` with no layers and referrers `[]` are no candidate, and the
/// pull is refused.
#[test]
fn empty_listings_refuse() {
    let (mut hub, pushed) = app_hub();
    for subject in [&pushed.index, &pushed.manifest] {
        sign_legacy(&mut hub, subject, &[]);
        list(&mut hub, subject, &[]);
    }
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert_eq!(detail.matches(": 0 listed").count(), 4, "{detail}");
    assert_eq!(
        detail.matches("referrers: 0 listed, 0 candidates").count(),
        2,
        "{detail}"
    );
}

/// Referrers `null` (Artifact Registry's answer, measured) is an empty
/// listing, and after a `200` the fallback tag is not read.
#[test]
fn referrers_null_is_empty() {
    let (mut hub, pushed) = app_hub();
    let null = format!(
        r#"{{"schemaVersion":2,"mediaType":"{}","manifests":null}}"#,
        media::INDEX
    );
    for subject in [&pushed.index, &pushed.manifest] {
        hub.referrers(REPO, subject, Referrers::Listing(null.clone().into_bytes()));
    }
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert_eq!(
        detail.matches("referrers: 0 listed, 0 candidates").count(),
        2,
        "{detail}"
    );
    let tag = tag_of(&pushed.index);
    assert!(!targets(&fake.seen()).iter().any(|t| t.ends_with(&tag)));
}

/// A single valid signature passes, and an honest signed pull costs the
/// `.sig` and its payload only.
#[test]
fn single_signature_passes() {
    let (mut hub, pushed) = app_hub();
    sign(&mut hub, "legacy", &signer(), &pushed.index, &pushed.index);
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    passed(result, &pushed);
    let payload_digest = digest_of(&payload(&pushed.index));
    let extra: Vec<String> = targets(&fake.seen())
        .into_iter()
        .filter(|t| t.contains(".sig") || t.contains("/referrers/") || t.ends_with(&payload_digest))
        .collect();
    assert_eq!(extra.len(), 2, "{extra:?}");
}

/// The cap is inclusive: 16 listed with the valid one at position 16
/// passes; 17 are refused without fetching any of them, on both carriers.
#[test]
fn signature_cap_inclusive() {
    assert_eq!(MAX_SIGNATURES, 16);
    for carrier in ["legacy", "bundle"] {
        for listed in [16, 17] {
            let (mut hub, pushed) = app_hub();
            let mut entries: Vec<String> = (0..listed - 1)
                .map(|i| {
                    let wrong = digest_of(format!("other {i}").as_bytes());
                    candidate(&mut hub, carrier, &signer(), &pushed.index, &wrong)
                })
                .collect();
            entries.push(candidate(
                &mut hub,
                carrier,
                &signer(),
                &pushed.index,
                &pushed.index,
            ));
            attach(&mut hub, carrier, &pushed.index, &entries);
            let fake = hub_fake(hub);
            let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
            if listed == 16 {
                passed(result, &pushed);
                continue;
            }
            let detail = refused_before_layers(&fake, &pushed, &tmp, result);
            assert!(detail.contains("17 "), "{carrier}: {detail}");
            assert!(detail.contains("more than 16"), "{carrier}: {detail}");
            // Nothing listed was fetched: no blob, no manifest but the
            // image's own.
            for t in targets(&fake.seen()) {
                let image_doc = t.ends_with(&pushed.index)
                    || t.ends_with(&pushed.manifest)
                    || t.ends_with(&pushed.config);
                let listed_fetch =
                    (t.contains("/blobs/") || t.contains("/manifests/sha256:")) && !image_doc;
                assert!(!listed_fetch, "{carrier}: fetched {t}");
            }
        }
    }
}

/// An invalid candidate then a valid one passes, and the reverse order
/// too, on both carriers.
#[test]
fn candidate_order_irrelevant() {
    for carrier in ["legacy", "bundle"] {
        for valid_first in [true, false] {
            let (mut hub, pushed) = app_hub();
            let good = candidate(&mut hub, carrier, &signer(), &pushed.index, &pushed.index);
            let bad = candidate(&mut hub, carrier, &other(), &pushed.index, &pushed.index);
            let entries = if valid_first {
                [good, bad]
            } else {
                [bad, good]
            };
            attach(&mut hub, carrier, &pushed.index, &entries);
            let fake = hub_fake(hub);
            let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
            passed(result, &pushed);
        }
    }
}

/// The valid signature as the first or the last of three `.sig` layers,
/// or the first or last of three referrers, passes.
#[test]
fn valid_at_head_and_tail() {
    for carrier in ["legacy", "bundle"] {
        for at in [0, 2] {
            let (mut hub, pushed) = app_hub();
            let entries: Vec<String> = (0..3)
                .map(|i| {
                    let over = if i == at {
                        pushed.index.clone()
                    } else {
                        digest_of(format!("x{i}").as_bytes())
                    };
                    candidate(&mut hub, carrier, &signer(), &pushed.index, &over)
                })
                .collect();
            attach(&mut hub, carrier, &pushed.index, &entries);
            let fake = hub_fake(hub);
            let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
            passed(result, &pushed);
        }
    }
}

/// The same artifact listed twice is fetched once and counted twice: 9
/// copies of one referrer and 8 others are 17, over the cap; an untrusted
/// referrer listed three times before the valid one is fetched once; two
/// `.sig` layers over one payload fetch it once and both are verified.
#[test]
fn duplicate_entries_fetched_once_counted_raw() {
    let (mut hub, pushed) = app_hub();
    let one = candidate(&mut hub, "bundle", &signer(), &pushed.index, &pushed.index);
    let mut entries = vec![one; 9];
    for i in 0..8 {
        let wrong = digest_of(format!("{i}").as_bytes());
        entries.push(candidate(
            &mut hub,
            "bundle",
            &other(),
            &pushed.index,
            &wrong,
        ));
    }
    list(&mut hub, &pushed.index, &entries);
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(detail.contains("17 listed, more than 16"), "{detail}");

    // Verified once too: three copies of an untrusted referrer are one
    // candidate.
    let (mut hub, pushed) = app_hub();
    let bad = candidate(&mut hub, "bundle", &other(), &pushed.index, &pushed.index);
    list(&mut hub, &pushed.index, &[bad.clone(), bad.clone(), bad]);
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(
        detail.contains("3 listed, 1 candidates (entry 0: "),
        "{detail}"
    );

    let (mut hub, pushed) = app_hub();
    let bad = candidate(&mut hub, "bundle", &other(), &pushed.index, &pushed.index);
    let good = candidate(&mut hub, "bundle", &signer(), &pushed.index, &pushed.index);
    let bad_digest = nth_digest(bad.as_bytes(), 0);
    list(
        &mut hub,
        &pushed.index,
        &[bad.clone(), bad.clone(), bad, good],
    );
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    passed(result, &pushed);
    let fetched = targets(&fake.seen())
        .iter()
        .filter(|t| t.ends_with(&bad_digest))
        .count();
    assert_eq!(fetched, 1);

    let (mut hub, pushed) = app_hub();
    let p = payload(&pushed.index);
    let layers = [
        sig_layer(&mut hub, &other(), &p),
        sig_layer(&mut hub, &signer(), &p),
    ];
    sign_legacy(&mut hub, &pushed.index, &layers);
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    passed(result, &pushed);
    let fetched = targets(&fake.seen())
        .iter()
        .filter(|t| t.ends_with(&digest_of(&p)))
        .count();
    assert_eq!(fetched, 1);
}

/// When the reference names an index, a signature over the selected
/// platform manifest passes, on both carriers.
#[test]
fn platform_manifest_signature_passes() {
    for carrier in ["legacy", "bundle"] {
        let (mut hub, pushed) = app_hub();
        sign(
            &mut hub,
            carrier,
            &signer(),
            &pushed.manifest,
            &pushed.manifest,
        );
        let fake = hub_fake(hub);
        let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
        passed(result, &pushed);
    }
}

/// A signature over a sibling platform's manifest, or over the config, is
/// refused: neither is a subject, their tags are never read, and the same
/// signatures attached to a subject name the wrong digest.
#[test]
fn sibling_or_config_signature_refused() {
    let mut hub = Hub::default();
    let (amd64, amd64_size) = image(&mut hub, REPO, ("linux", "amd64", None), 1);
    let (arm64, arm64_size) = image(&mut hub, REPO, ("linux", "arm64", None), 1);
    let index_bytes = index(&[
        entry(
            media::MANIFEST,
            &amd64,
            amd64_size,
            Some(("linux", "amd64", None)),
        ),
        entry(
            media::MANIFEST,
            &arm64,
            arm64_size,
            Some(("linux", "arm64", None)),
        ),
    ]);
    let index_digest = hub.document(REPO, media::INDEX, &index_bytes);
    let config_digest = nth_digest(&hub.manifests[REPO][&amd64].1, 0);
    let mut layers = Vec::new();
    for target in [&arm64, &config_digest] {
        let layer = sig_layer(&mut hub, &signer(), &payload(target));
        sign_legacy(&mut hub, target, std::slice::from_ref(&layer));
        sign_bundle(&mut hub, &signer(), target);
        layers.push(layer);
    }
    sign_legacy(&mut hub, &amd64, &layers);
    sign_legacy(&mut hub, &index_digest, &layers);
    let fake = hub_fake(hub);
    let tmp = TempDir::new("sibling");
    let store = open_with(&tmp.path().join("store"), &fake, trusted());
    match store.pull(&image_ref(REPO, &index_digest)) {
        Err(ImageError::Failed { detail }) => {
            assert!(detail.starts_with("signature policy"), "{detail}");
            assert_eq!(
                detail
                    .matches("the signature is not over this digest")
                    .count(),
                4,
                "{detail}"
            );
        }
        other => panic!("{other:?}"),
    }
    for t in targets(&fake.seen()) {
        for other in [&arm64, &config_digest] {
            assert!(
                !t.contains(&tag_of(other)) && !t.ends_with(&format!("/referrers/{other}")),
                "{t}"
            );
        }
    }
}

/// A statement with several subjects, one of which is the image, passes
/// end to end.
#[test]
fn matching_second_subject_passes() {
    let (mut hub, pushed) = app_hub();
    let first = digest_of(b"first");
    let entry = referrer(
        &mut hub,
        &pushed.index,
        &bundle_over(&signer(), &[&first, &pushed.index]),
    );
    list(&mut hub, &pushed.index, &[entry]);
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    passed(result, &pushed);
}

/// Look-alike media and artifact types are not candidates: an
/// `artifactType` of `…+JSON` or with a parameter, a `.sig` layer of
/// `…+JSON` or with a parameter. Nothing of them is fetched.
#[test]
fn look_alike_media_types_skipped() {
    let (mut hub, pushed) = app_hub();
    let b = bundle_over(&signer(), &[&pushed.index]);
    let upper = BUNDLE_V03_MEDIA_TYPE.replace("+json", "+JSON");
    let param = format!("{BUNDLE_V03_MEDIA_TYPE}; charset=utf-8");
    let entries = [
        referrer_with(&mut hub, &pushed.index, &b, &upper, COSIGN_SIGN_PREDICATE),
        referrer_with(&mut hub, &pushed.index, &b, &param, COSIGN_SIGN_PREDICATE),
    ];
    list(&mut hub, &pushed.index, &entries);
    let p = payload(&pushed.index);
    let layers = [
        sig_layer_typed(
            &mut hub,
            &signer(),
            &p,
            &SIMPLE_SIGNING_MEDIA_TYPE.replace("+json", "+JSON"),
        ),
        sig_layer_typed(
            &mut hub,
            &signer(),
            &p,
            &format!("{SIMPLE_SIGNING_MEDIA_TYPE};v=1"),
        ),
    ];
    sign_legacy(&mut hub, &pushed.index, &layers);
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(detail.contains("2 listed, 0 candidates"), "{detail}");
    assert_eq!(
        detail.matches("not a simple-signing layer").count(),
        2,
        "{detail}"
    );
    let all = targets(&fake.seen());
    assert!(
        !all.iter()
            .any(|t| t.contains("/blobs/") && !t.ends_with(&pushed.config)),
        "{all:?}"
    );
}

/// A predicate-type annotation not on the list byte for byte (a trailing
/// space, `http://`, percent-encoding) is no candidate, and one listed
/// twice on an entry is none either.
#[test]
fn predicate_annotation_exact() {
    let (mut hub, pushed) = app_hub();
    let b = bundle_over(&signer(), &[&pushed.index]);
    let mut entries: Vec<String> = [
        format!("{COSIGN_SIGN_PREDICATE} "),
        COSIGN_SIGN_PREDICATE.replace("https", "http"),
        COSIGN_SIGN_PREDICATE.replace(".dev", "%2Edev"),
    ]
    .iter()
    .map(|p| referrer_with(&mut hub, &pushed.index, &b, BUNDLE_V03_MEDIA_TYPE, p))
    .collect();
    // No annotations at all.
    let bare = referrer(&mut hub, &pushed.index, &b);
    entries.push(
        bare.split(",\"annotations\"")
            .next()
            .expect("entry")
            .to_owned()
            + "}",
    );
    list(&mut hub, &pushed.index, &entries);
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(detail.contains("4 listed, 0 candidates"), "{detail}");
}

/// A listing annotation that lies (it says cosign sign, the statement is
/// an SBOM) is fetched as a candidate and refused by the verifier.
#[test]
fn predicate_annotation_lies() {
    let (mut hub, pushed) = app_hub();
    let b = bundle(
        &signer(),
        &statement(&[&pushed.index], "https://spdx.dev/Document"),
    );
    let entry = referrer(&mut hub, &pushed.index, &b);
    list(&mut hub, &pushed.index, &[entry]);
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(
        detail.contains("the predicate type is not trusted"),
        "{detail}"
    );
}

/// A `.sig` layer's payload of exactly `MAX_PAYLOAD_BYTES` (65,536) is a
/// candidate; one byte more is refused before it is requested.
#[test]
fn payload_cap_inclusive() {
    for (size, passes) in [(65_536, true), (65_537, false)] {
        let (mut hub, pushed) = app_hub();
        let mut p = payload(&pushed.index);
        // Padding inside `optional` keeps the payload valid JSON.
        let pad = size - p.len() - 4;
        let text = String::from_utf8(p).expect("utf-8").replace(
            "\"optional\":null",
            &format!("\"optional\":{{\"p\":\"{}\"}}", "x".repeat(pad)),
        );
        p = text.into_bytes();
        assert_eq!(p.len(), size);
        let layer = sig_layer(&mut hub, &signer(), &p);
        sign_legacy(&mut hub, &pushed.index, &[layer]);
        let fake = hub_fake(hub);
        let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
        let fetched = targets(&fake.seen())
            .iter()
            .any(|t| t.ends_with(&digest_of(&p)));
        assert_eq!(fetched, passes, "{size}");
        if passes {
            passed(result, &pushed);
        } else {
            let detail = refused_before_layers(&fake, &pushed, &tmp, result);
            assert!(detail.contains("more than the limit of 65536"), "{detail}");
        }
    }
}

/// A referrer listed as a bundle whose own manifest says otherwise is no
/// pass: another `artifactType`, none, two layers, a layer of another
/// media type. Each is skipped with a fixed reason, and its layers are
/// not fetched.
#[test]
fn referrer_manifest_shape_checked() {
    let (mut hub, pushed) = app_hub();
    let b = bundle_over(&signer(), &[&pushed.index]);
    let bundle_digest = hub.blob(REPO, &b);
    let layer = descriptor(BUNDLE_V03_MEDIA_TYPE, &bundle_digest, b.len());
    let subject = descriptor(media::INDEX, &pushed.index, 100);
    let shapes = [
        (
            r#","artifactType":"application/vnd.example+json""#.to_owned(),
            layer.clone(),
        ),
        (String::new(), layer.clone()),
        (
            format!(r#","artifactType":"{BUNDLE_V03_MEDIA_TYPE}""#),
            format!("{layer},{layer}"),
        ),
        (
            format!(r#","artifactType":"{BUNDLE_V03_MEDIA_TYPE}""#),
            descriptor("application/json", &bundle_digest, b.len()),
        ),
    ];
    let mut entries = Vec::new();
    for (artifact_type, layers) in shapes {
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"{}"{artifact_type},"config":{},"layers":[{layers}],"subject":{subject}}}"#,
            media::MANIFEST,
            descriptor(EMPTY_CONFIG, EMPTY_DIGEST, 2),
        );
        let digest = hub.document(REPO, media::MANIFEST, manifest.as_bytes());
        entries.push(listing_entry(
            &digest,
            manifest.len(),
            BUNDLE_V03_MEDIA_TYPE,
            COSIGN_SIGN_PREDICATE,
        ));
    }
    list(&mut hub, &pushed.index, &entries);
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(detail.contains("4 listed, 4 candidates"), "{detail}");
    assert_eq!(
        detail.matches("the referrer is not a bundle v0.3").count(),
        2,
        "{detail}"
    );
    assert_eq!(
        detail
            .matches("the referrer does not hold exactly one bundle layer")
            .count(),
        2,
        "{detail}"
    );
    assert!(
        !targets(&fake.seen())
            .iter()
            .any(|t| t.ends_with(&bundle_digest))
    );
}

/// A referrer whose manifest names no subject or another one is skipped
/// with a fixed reason, and a valid one after them passes.
#[test]
fn referrer_subject_mismatch_skipped() {
    let (mut hub, pushed) = app_hub();
    let b = bundle_over(&signer(), &[&pushed.index]);
    let other_subject = referrer(&mut hub, &digest_of(b"elsewhere"), &b);
    let bundle_digest = hub.blob(REPO, &b);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"{}","artifactType":"{BUNDLE_V03_MEDIA_TYPE}","config":{},"layers":[{}]}}"#,
        media::MANIFEST,
        descriptor(EMPTY_CONFIG, EMPTY_DIGEST, 2),
        descriptor(BUNDLE_V03_MEDIA_TYPE, &bundle_digest, b.len()),
    );
    let digest = hub.document(REPO, media::MANIFEST, manifest.as_bytes());
    let no_subject = listing_entry(
        &digest,
        manifest.len(),
        BUNDLE_V03_MEDIA_TYPE,
        COSIGN_SIGN_PREDICATE,
    );
    list(
        &mut hub,
        &pushed.index,
        &[other_subject.clone(), no_subject.clone()],
    );
    let fake = hub_fake(hub.clone());
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert_eq!(
        detail
            .matches("the referrer does not name this subject")
            .count(),
        2,
        "{detail}"
    );
    let good = referrer(&mut hub, &pushed.index, &b);
    list(&mut hub, &pushed.index, &[other_subject, no_subject, good]);
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    passed(result, &pushed);
}

/// GHCR answers the fallback tag with the image's own index where no
/// referrer exists (measured): no referrers, not an error, and nothing in
/// it is fetched. A referrers index under the tag is read.
#[test]
fn fallback_tag_answering_the_image() {
    let (mut hub, pushed) = app_hub();
    let index_bytes = hub.manifests[REPO][&pushed.index].1.clone();
    hub.tag(REPO, &tag_of(&pushed.index), media::INDEX, &index_bytes);
    let fake = hub_fake(hub.clone());
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(
        detail.contains(&format!(
            "{}: referrers: unsupported, tag answers with the subject",
            pushed.index
        )),
        "{detail}"
    );

    let entry = candidate(&mut hub, "bundle", &signer(), &pushed.index, &pushed.index);
    hub.tag(
        REPO,
        &tag_of(&pushed.index),
        media::INDEX,
        &listing(&[entry]),
    );
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    passed(result, &pushed);
}

/// Only a referrers `404` leads to the fallback tag: `405` (and every
/// other status) is an error of that carrier, and the tag is not read.
#[test]
fn referrers_only_404_falls_back() {
    let (mut hub, pushed) = app_hub();
    let entry = candidate(&mut hub, "bundle", &signer(), &pushed.index, &pushed.index);
    hub.tag(
        REPO,
        &tag_of(&pushed.index),
        media::INDEX,
        &listing(&[entry]),
    );
    for status in [405, 400, 500] {
        let mut hub = hub.clone();
        hub.referrers(REPO, &pushed.index, Referrers::Status(status));
        hub.referrers(REPO, &pushed.manifest, Referrers::Status(status));
        let fake = hub_fake(hub);
        let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
        let detail = refused_before_layers(&fake, &pushed, &tmp, result);
        assert!(detail.contains(&format!("answered {status}")), "{detail}");
        let tag = tag_of(&pushed.index);
        assert!(
            !targets(&fake.seen()).iter().any(|t| t.ends_with(&tag)),
            "{status}"
        );
    }
    // The control: on `404` the same tag lets the pull pass.
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    passed(result, &pushed);
}

type Breaker = fn(&Seen) -> Option<Reply>;

/// The faults of `discovery_errors_fail_closed`.
fn faults() -> [(&'static str, Breaker); 5] {
    [
        ("503", |_| Some(Reply::status(503))),
        ("429", |_| Some(Reply::status(429))),
        ("malformed", |_| {
            Some(Reply::http(
                200,
                &[("Content-Type", media::INDEX)],
                br#"{"schemaVersion":2,"manifests":{},"layers":7}"#,
            ))
        }),
        ("401 after authorization", |s| {
            s.header("authorization")
                .map(|_| Reply::http(401, &[("WWW-Authenticate", &challenge_for(REPO))], b""))
        }),
        ("deadline", |_| {
            Some(Reply::Trickle {
                head: b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".to_vec(),
                chunks: vec![b"x".to_vec(); 4],
                delay: Duration::from_millis(800),
            })
        }),
    ]
}

/// A fake over `base` whose requests to `broken` (a target suffix) get the
/// breaker's answer, with a 1 s deadline per fetch.
fn broken_store(base: Hub, broken: String, breaker: Breaker) -> (Fake, TempDir, OciImageStore) {
    let fake =
        Fake::new(
            move |s| match s.target.ends_with(&broken).then(|| breaker(s)).flatten() {
                Some(reply) => reply,
                None => base.handle(s),
            },
        );
    let mut config = config_with(&fake, trusted());
    config.timeouts =
        Timeouts::new(Duration::from_secs(5), Duration::from_secs(1), 1 << 30).expect("timeouts");
    let tmp = TempDir::new("errors");
    let store = OciImageStore::open(&tmp.path().join("store"), config).expect("open");
    (fake, tmp, store)
}

/// Discovery errors never pass the pull: `5xx`, `429`, a malformed
/// listing, a `401` after authorization, a deadline; whichever carrier
/// breaks, the other one may still produce the pass.
#[test]
fn discovery_errors_fail_closed() {
    let (mut hub, pushed) = app_hub();
    sign(&mut hub, "legacy", &signer(), &pushed.index, &pushed.index);
    sign(&mut hub, "bundle", &signer(), &pushed.index, &pushed.index);
    let sig = format!("{}.sig", tag_of(&pushed.index));
    let referrers = format!("/referrers/{}", pushed.index);
    for (name, breaker) in faults() {
        for (broken, other_carrier) in [(&sig, "bundle"), (&referrers, "legacy")] {
            // The broken carrier alone: refused.
            let mut alone = hub.clone();
            if other_carrier == "bundle" {
                alone.referrers.clear();
            } else {
                alone.tags.clear();
            }
            let (fake, tmp, store) = broken_store(alone, broken.clone(), breaker);
            let result = store
                .pull(&image_ref(REPO, &pushed.index))
                .map(|r| r.rootfs.as_str().to_owned());
            let detail = refused_before_layers(&fake, &pushed, &tmp, result);
            assert!(!detail.is_empty(), "{name}");
            // With the other carrier intact: it passes.
            let (_fake, _tmp, store) = broken_store(hub.clone(), broken.clone(), breaker);
            let pulled = store.pull(&image_ref(REPO, &pushed.index));
            assert_eq!(
                pulled
                    .unwrap_or_else(|e| panic!("{name} on {broken}: {e:?}"))
                    .rootfs
                    .as_str(),
                pushed.manifest
            );
        }
    }
}

/// A newline, an ANSI escape or a bidi control in what a registry sends
/// (a payload, a redirect target) never reaches the failure detail as it
/// is.
#[test]
fn refusal_detail_carries_no_untrusted_text() {
    let (mut hub, pushed) = app_hub();
    let evil = "line\\nbreak\\u001b[31mred\u{202e}rtl";
    let p = format!(
        "{{\"critical\":{{\"identity\":{{\"docker-reference\":\"{evil}\"}},\"image\":{{\"docker-manifest-digest\":\"{}\"}},\"type\":\"cosign container image signature\"}},\"optional\":{{\"note\":\"{evil}\"}}}}",
        pushed.index
    );
    let layer = sig_layer(&mut hub, &other(), p.as_bytes());
    sign_legacy(&mut hub, &pushed.index, &[layer]);
    let base = hub;
    let fake = Fake::new(move |s| {
        if s.target.contains("/referrers/") {
            Reply::Raw(
                "HTTP/1.1 302 Found\r\nLocation: /x\u{202e}rtl\r\nContent-Length: 0\r\n\r\n"
                    .as_bytes()
                    .to_vec(),
            )
        } else {
            base.handle(s)
        }
    });
    let (tmp, result) = pull_once(&fake, trusted(), &pushed.index);
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(
        detail.bytes().all(|b| (b' '..=b'~').contains(&b)),
        "{detail:?}"
    );
    for piece in ["line", "break", "31m", "\u{202e}"] {
        assert!(!detail.contains(piece), "{detail}");
    }
}

// ---------------------------------------------------------------------
// Kept evidence and warm pulls
// ---------------------------------------------------------------------

/// An image cached under `Off`, then pulled under `Required` without a
/// signature, is refused with no handle and no lease, though every layer
/// is cached.
#[test]
fn cached_unsigned_refused_under_required() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("cached-unsigned");
    let root = tmp.path().join("store");
    open_with(&root, &fake, SignaturePolicy::off())
        .pull(&image_ref(REPO, &pushed.index))
        .expect("off");
    let store = open_with(&root, &fake, trusted());
    match store.pull(&image_ref(REPO, &pushed.index)) {
        Err(ImageError::Failed { detail }) => {
            assert!(detail.starts_with("signature policy"), "{detail}")
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        store.pull_leased(&image_ref(REPO, &pushed.index)),
        Err(ImageError::Failed { .. })
    ));
}

/// A warm pull re-verifies the kept evidence and makes no request, on both
/// carriers, for an index signature and for a platform-manifest one; the
/// pointer names the carrier.
#[test]
fn warm_pull_offline() {
    for carrier in ["legacy", "bundle"] {
        for on_manifest in [false, true] {
            let (mut hub, pushed) = app_hub();
            let subject = if on_manifest {
                pushed.manifest.clone()
            } else {
                pushed.index.clone()
            };
            sign(&mut hub, carrier, &signer(), &subject, &subject);
            let fake = hub_fake(hub);
            let tmp = TempDir::new("warm");
            let root = tmp.path().join("store");
            open_with(&root, &fake, trusted())
                .pull(&image_ref(REPO, &pushed.index))
                .expect("cold");
            let pointer = std::fs::read_to_string(
                root.join("signatures/sha256")
                    .join(subject.trim_start_matches("sha256:")),
            )
            .expect("pointer");
            assert!(pointer.starts_with(carrier), "{pointer}");
            let before = fake.seen().len();
            let store = open_with(&root, &fake, trusted());
            assert_eq!(
                store
                    .pull(&image_ref(REPO, &pushed.index))
                    .expect("warm")
                    .rootfs
                    .as_str(),
                pushed.manifest
            );
            assert_eq!(
                fake.seen().len(),
                before,
                "{carrier}: {:?}",
                targets(&fake.seen()[before..])
            );
        }
    }
}

/// After a policy change the kept evidence fails, discovery runs again, and
/// the pull is refused; the detail names the kept evidence's reason.
#[test]
fn warm_pull_reverifies_under_current_policy() {
    for carrier in ["legacy", "bundle"] {
        let (mut hub, pushed) = app_hub();
        sign(&mut hub, carrier, &signer(), &pushed.index, &pushed.index);
        let fake = hub_fake(hub);
        let tmp = TempDir::new("reverify");
        let root = tmp.path().join("store");
        open_with(&root, &fake, trusted())
            .pull(&image_ref(REPO, &pushed.index))
            .expect("cold");
        let before = fake.seen().len();
        let store = open_with(&root, &fake, required(keyed(&[OTHER_PUB])));
        let detail = match store.pull(&image_ref(REPO, &pushed.index)) {
            Err(ImageError::Failed { detail }) => detail,
            other => panic!("{other:?}"),
        };
        assert!(
            detail.contains("kept evidence: no trusted key verifies the signature"),
            "{carrier}: {detail}"
        );
        assert!(
            fake.seen().len() > before,
            "{carrier}: discovery did not run"
        );
    }
}

/// A kept artifact changed on disk is removed and fetched again, and the
/// pull passes; so does one removed, and a pointer file that is garbage.
#[test]
fn corrupted_kept_evidence_refetched() {
    let (mut hub, pushed) = app_hub();
    let p = payload(&pushed.index);
    let layer = sig_layer(&mut hub, &signer(), &p);
    sign_legacy(&mut hub, &pushed.index, &[layer]);
    let fake = hub_fake(hub);
    let tmp = TempDir::new("corrupt-evidence");
    let root = tmp.path().join("store");
    open_with(&root, &fake, trusted())
        .pull(&image_ref(REPO, &pushed.index))
        .expect("cold");
    let kept = root
        .join("blobs/sha256")
        .join(digest_of(&p).trim_start_matches("sha256:"));
    let pointer = root
        .join("signatures/sha256")
        .join(pushed.index.trim_start_matches("sha256:"));
    for damage in ["flip", "remove", "pointer"] {
        match damage {
            "flip" => {
                let mut bytes = std::fs::read(&kept).expect("kept payload");
                bytes[0] ^= 1;
                std::fs::write(&kept, bytes).expect("corrupt");
            }
            "remove" => std::fs::remove_file(&kept).expect("remove"),
            _ => std::fs::write(&pointer, b"legacy nonsense\n").expect("garbage"),
        }
        let before = fake.seen().len();
        open_with(&root, &fake, trusted())
            .pull(&image_ref(REPO, &pushed.index))
            .expect(damage);
        let again = targets(&fake.seen()[before..]);
        assert!(
            again.iter().any(|t| t.ends_with(".sig")),
            "{damage}: {again:?}"
        );
        if damage != "pointer" {
            assert!(
                again.iter().any(|t| t.ends_with(&digest_of(&p))),
                "{damage}: {again:?}"
            );
        }
        assert_eq!(std::fs::read(&kept).expect("kept again"), p, "{damage}");
        assert!(
            std::fs::read_to_string(&pointer)
                .expect("pointer")
                .starts_with("legacy sha256:")
        );
    }
}

/// Warm and cold pulls reach the same verdict: for a trusted signature, an
/// untrusted one and none, a pull into a fresh store and a second pull
/// into it agree.
#[test]
fn warm_and_cold_same_verdict() {
    for case in ["trusted", "untrusted", "none"] {
        let (mut hub, pushed) = app_hub();
        match case {
            "trusted" => sign_bundle(&mut hub, &signer(), &pushed.index),
            "untrusted" => sign_bundle(&mut hub, &other(), &pushed.index),
            _ => {}
        }
        let fake = hub_fake(hub);
        let tmp = TempDir::new("same-verdict");
        let root = tmp.path().join("store");
        let cold = open_with(&root, &fake, trusted())
            .pull(&image_ref(REPO, &pushed.index))
            .is_ok();
        let warm = open_with(&root, &fake, trusted())
            .pull(&image_ref(REPO, &pushed.index))
            .is_ok();
        assert_eq!(cold, warm, "{case}");
        assert_eq!(cold, case == "trusted", "{case}");
    }
}

/// A trim keeps a pointer whose evidence is there and removes one whose
/// evidence is gone and a malformed one; the next pull discovers the
/// evidence again.
#[test]
fn trim_removes_dangling_pointers() {
    let (mut hub, pushed) = app_hub();
    sign_bundle(&mut hub, &signer(), &pushed.index);
    let fake = hub_fake(hub);
    let tmp = TempDir::new("dangling");
    let root = tmp.path().join("store");
    let store = open_with(&root, &fake, trusted());
    store.pull(&image_ref(REPO, &pushed.index)).expect("cold");
    let pointer = root
        .join("signatures/sha256")
        .join(pushed.index.trim_start_matches("sha256:"));
    store.trim().expect("trim");
    assert!(pointer.is_file(), "a complete pointer was removed");
    let text = std::fs::read_to_string(&pointer).expect("pointer");
    let bundle = text
        .trim_end()
        .rsplit(' ')
        .next()
        .expect("bundle")
        .to_owned();
    std::fs::remove_file(
        root.join("blobs/sha256")
            .join(bundle.trim_start_matches("sha256:")),
    )
    .expect("evict the bundle");
    let junk = root.join("signatures/sha256").join(format!("{:064x}", 1));
    std::fs::write(&junk, b"junk").expect("junk");
    store.trim().expect("trim");
    assert!(!pointer.exists(), "a dangling pointer stayed");
    assert!(!junk.exists(), "a malformed pointer stayed");
    store
        .pull(&image_ref(REPO, &pushed.index))
        .expect("discovered again");
    assert!(pointer.is_file());
}

/// Two `Required` rules with different trusts over one digest keep each
/// other's evidence: after a pull under the second rule, a warm pull under
/// the first still makes no request (S6, review of PR 3), and so does one
/// under the second; the pointer file holds both lines.
#[test]
fn kept_evidence_survives_another_rule() {
    let (mut hub, pushed) = app_hub();
    sign(&mut hub, "legacy", &signer(), &pushed.index, &pushed.index);
    sign(&mut hub, "bundle", &other(), &pushed.index, &pushed.index);
    let docs = hub.manifests[REPO].clone();
    hub.manifests.insert("library/app2".to_owned(), docs);
    let tags = hub.tags[REPO].clone();
    hub.tags.insert("library/app2".to_owned(), tags);
    let refs = hub.referrers[REPO].clone();
    hub.referrers.insert("library/app2".to_owned(), refs);
    let fake = hub_fake(hub);
    let policy = rules(vec![
        rule(
            RepoScope::Exact(repo(REPO)),
            Requirement::Required(keyed(&[SIGNER_PUB])),
        ),
        rule(
            RepoScope::Exact(repo("library/app2")),
            Requirement::Required(keyed(&[OTHER_PUB])),
        ),
    ]);
    let tmp = TempDir::new("two-rules");
    let root = tmp.path().join("store");
    let store = open_with(&root, &fake, policy);
    store
        .pull(&image_ref(REPO, &pushed.index))
        .expect("first rule, cold");
    store
        .pull(&image_ref("library/app2", &pushed.index))
        .expect("second rule, cold");
    let before = fake.seen().len();
    for name in [REPO, "library/app2", REPO] {
        store.pull(&image_ref(name, &pushed.index)).expect("warm");
    }
    assert_eq!(
        fake.seen().len(),
        before,
        "{:?}",
        targets(&fake.seen()[before..])
    );
    let pointer = std::fs::read_to_string(
        root.join("signatures/sha256")
            .join(pushed.index.trim_start_matches("sha256:")),
    )
    .expect("pointer");
    let kinds: Vec<&str> = pointer.lines().map(|l| &l[..6]).collect();
    assert_eq!(kinds, ["legacy", "bundle"], "{pointer}");
}

/// A `.sig` answer that is another image's document served with another
/// `Content-Type` never spoils that image: whether the image was pulled
/// before (its kept copy is not replaced) or after (the copy the
/// signature lookup left is fetched again from the image's own
/// repository), its pulls under `Off` work, and so do the ones after.
#[test]
fn sig_answer_never_spoils_a_document() {
    for victim_first in [false, true] {
        let (mut hub, victim) = app_hub();
        let evil = push(&mut hub, "evil/x", &[Layer::file("etc/evil", b"e\n")], "");
        let victim_index = hub.manifests[REPO][&victim.index].1.clone();
        hub.tag(
            "evil/x",
            &format!("{}.sig", tag_of(&evil.index)),
            media::MANIFEST,
            &victim_index,
        );
        let fake = hub_fake(hub);
        let policy = rules(vec![rule(
            RepoScope::Exact(repo("evil/x")),
            Requirement::Required(keyed(&[SIGNER_PUB])),
        )]);
        let tmp = TempDir::new("spoil");
        let root = tmp.path().join("store");
        let store = open_with(&root, &fake, policy);
        if victim_first {
            store
                .pull(&image_ref(REPO, &victim.index))
                .expect("victim first");
        }
        assert!(store.pull(&image_ref("evil/x", &evil.index)).is_err());
        let victim_blob = root
            .join("blobs/sha256")
            .join(victim.index.trim_start_matches("sha256:"));
        let before = fake.seen().len();
        if victim_first {
            // The kept copy was not touched: the victim's pull is offline.
            store.pull(&image_ref(REPO, &victim.index)).expect("victim");
            assert_eq!(fake.seen().len(), before, "the victim's copy was replaced");
        } else {
            // A `.sig` answer that is no artifact is never kept.
            assert!(!victim_blob.exists(), "an unparsed .sig answer was kept");
        }
        for round in 0..2 {
            store
                .pull(&image_ref(REPO, &victim.index))
                .unwrap_or_else(|e| panic!("victim_first={victim_first} round {round}: {e:?}"));
        }
        let kept_type = std::fs::read_to_string(root.join("blobs/sha256").join(format!(
            "{}.type",
            victim.index.trim_start_matches("sha256:")
        )))
        .expect("type");
        assert_eq!(kept_type, media::INDEX, "victim_first={victim_first}");
        // Once healed, the victim's pull makes no request.
        let before = fake.seen().len();
        store.pull(&image_ref(REPO, &victim.index)).expect("warm");
        assert_eq!(fake.seen().len(), before, "victim_first={victim_first}");
    }
}

/// The same poisoning through an image pull (ADR-009 D8's path): an index
/// in another repository that names the victim's index as its platform
/// manifest, served with the manifest type, fails its own pull and leaves
/// nothing kept that breaks the victim's.
#[test]
fn foreign_index_never_spoils_a_document() {
    let (mut hub, victim) = app_hub();
    let victim_index = hub.manifests[REPO][&victim.index].1.clone();
    let evil_index = index(&[entry(
        media::MANIFEST,
        &victim.index,
        victim_index.len(),
        Some(("linux", "amd64", None)),
    )]);
    let evil = hub.document("evil/x", media::INDEX, &evil_index);
    hub.manifests.get_mut("evil/x").expect("evil").insert(
        victim.index.clone(),
        (media::MANIFEST.to_owned(), victim_index),
    );
    let fake = hub_fake(hub);
    let tmp = TempDir::new("foreign-index");
    let store = open_with(&tmp.path().join("store"), &fake, SignaturePolicy::off());
    assert!(store.pull(&image_ref("evil/x", &evil)).is_err());
    store
        .pull(&image_ref(REPO, &victim.index))
        .expect("the victim pulls");
}

/// A line whose evidence is gone is dropped when the file is next
/// written, and a trim keeps a file with one complete line among dangling
/// ones.
#[test]
fn dangling_lines_dropped_and_trimmed() {
    let (mut hub, pushed) = app_hub();
    sign(&mut hub, "legacy", &signer(), &pushed.index, &pushed.index);
    sign(&mut hub, "bundle", &other(), &pushed.index, &pushed.index);
    let fake = hub_fake(hub);
    let tmp = TempDir::new("dangling-lines");
    let root = tmp.path().join("store");
    let pointer = root
        .join("signatures/sha256")
        .join(pushed.index.trim_start_matches("sha256:"));
    let blobs = root.join("blobs/sha256");
    let pull = |trust: &[u8]| {
        open_with(&root, &fake, required(keyed(&[trust])))
            .pull(&image_ref(REPO, &pushed.index))
            .expect("pull");
    };
    pull(SIGNER_PUB);
    pull(OTHER_PUB);
    let lines = std::fs::read_to_string(&pointer).expect("pointer");
    assert_eq!(lines.lines().count(), 2, "{lines}");
    // The legacy payload goes: a trim keeps the file for the bundle line.
    let payload = lines
        .lines()
        .next()
        .expect("legacy")
        .rsplit(' ')
        .next()
        .expect("payload");
    std::fs::remove_file(blobs.join(payload.trim_start_matches("sha256:"))).expect("evict");
    open_with(&root, &fake, trusted()).trim().expect("trim");
    assert_eq!(std::fs::read_to_string(&pointer).expect("kept"), lines);
    // The next write drops the dangling line.
    std::fs::remove_file(&pointer).expect("reset");
    std::fs::write(&pointer, &lines).expect("restore");
    pull(SIGNER_PUB);
    let after = std::fs::read_to_string(&pointer).expect("pointer");
    let kinds: Vec<&str> = after.lines().map(|l| &l[..6]).collect();
    assert_eq!(kinds, ["bundle", "legacy"], "{after}");
}

/// Discovery takes the artifacts it already kept from the store: with the
/// pointer gone, a pull fetches the listings again but neither the
/// referrer manifest nor the bundle.
#[test]
fn discovery_reuses_kept_artifacts() {
    let (mut hub, pushed) = app_hub();
    sign(&mut hub, "bundle", &signer(), &pushed.index, &pushed.index);
    let fake = hub_fake(hub);
    let tmp = TempDir::new("reuse");
    let root = tmp.path().join("store");
    open_with(&root, &fake, trusted())
        .pull(&image_ref(REPO, &pushed.index))
        .expect("cold");
    let pointer = root
        .join("signatures/sha256")
        .join(pushed.index.trim_start_matches("sha256:"));
    let line = std::fs::read_to_string(&pointer).expect("pointer");
    std::fs::remove_file(&pointer).expect("forget");
    let before = fake.seen().len();
    open_with(&root, &fake, trusted())
        .pull(&image_ref(REPO, &pushed.index))
        .expect("again");
    let again = targets(&fake.seen()[before..]);
    assert!(again.iter().any(|t| t.contains("/referrers/")), "{again:?}");
    for kept in line.trim_end().split(' ').skip(1) {
        assert!(
            !again.iter().any(|t| t.ends_with(kept)),
            "{kept}: {again:?}"
        );
    }
}

/// A manifest without a `mediaType` field takes its type from the
/// response, so two repositories may serve its bytes as Docker and as OCI.
/// Each pull takes the kept copy only when it is what its index says, and
/// otherwise fetches it again from its own repository: both images pull,
/// in turn, every time.
#[test]
fn kept_document_of_another_type_refetched() {
    let mut hub = Hub::default();
    let layer = Layer::file("etc/a", b"a\n");
    let diff = layer.diff_id.clone();
    let config = format!(
        r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":["{diff}"]}}}}"#
    );
    let mut repos = Vec::new();
    for (repo, media_type) in [
        ("library/docker", media::DOCKER_MANIFEST),
        ("library/oci", media::MANIFEST),
    ] {
        let blob = hub.blob(repo, &layer.blob);
        let config_digest = hub.blob(repo, config.as_bytes());
        let manifest = format!(
            r#"{{"schemaVersion":2,"config":{},"layers":[{}]}}"#,
            descriptor(
                "application/vnd.oci.image.config.v1+json",
                &config_digest,
                config.len()
            ),
            descriptor(layer.media_type, &blob, layer.blob.len()),
        );
        let digest = hub.document(repo, media_type, manifest.as_bytes());
        let index_bytes = index(&[entry(
            media_type,
            &digest,
            manifest.len(),
            Some(("linux", "amd64", None)),
        )]);
        repos.push((repo, hub.document(repo, media::INDEX, &index_bytes)));
    }
    // A third repository whose index says Docker but which serves the
    // manifest as OCI: its pull fails, and keeps nothing it cannot use.
    let docker_index = repos[0].1.clone();
    let docker_manifest = nth_digest(&hub.manifests["library/docker"][&docker_index].1, 0);
    let manifest_bytes = hub.manifests["library/docker"][&docker_manifest].1.clone();
    let liar_index = index(&[entry(
        media::DOCKER_MANIFEST,
        &docker_manifest,
        manifest_bytes.len(),
        Some(("linux", "amd64", None)),
    )]);
    let liar = hub.document("library/liar", media::INDEX, &liar_index);
    hub.document("library/liar", media::MANIFEST, &manifest_bytes);
    let fake = hub_fake(hub);
    let tmp = TempDir::new("two-types");
    let store = open_with(&tmp.path().join("store"), &fake, SignaturePolicy::off());
    for round in 0..2 {
        for (repo, index_digest) in &repos {
            store
                .pull(&image_ref(repo, index_digest))
                .unwrap_or_else(|e| panic!("{repo} round {round}: {e:?}"));
        }
    }
    // On a fresh store the liar's pull keeps nothing it could not use.
    let tmp = TempDir::new("liar");
    let root = tmp.path().join("store");
    let store = open_with(&root, &fake, SignaturePolicy::off());
    assert!(store.pull(&image_ref("library/liar", &liar)).is_err());
    assert!(
        !root
            .join("blobs/sha256")
            .join(docker_manifest.trim_start_matches("sha256:"))
            .exists(),
        "an unusable manifest was kept"
    );
}

/// A kept document whose `.type` makes it unreadable (left by a build
/// that kept what it could not parse) is fetched again and replaced, and
/// the pull after that is offline.
#[test]
fn unreadable_kept_document_fetched_again() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("unreadable");
    let root = tmp.path().join("store");
    let store = open_with(&root, &fake, SignaturePolicy::off());
    store.pull(&image_ref(REPO, &pushed.index)).expect("cold");
    let type_path = root.join("blobs/sha256").join(format!(
        "{}.type",
        pushed.index.trim_start_matches("sha256:")
    ));
    std::fs::write(&type_path, media::MANIFEST).expect("spoil");
    store.pull(&image_ref(REPO, &pushed.index)).expect("healed");
    assert_eq!(
        std::fs::read_to_string(&type_path).expect("type"),
        media::INDEX
    );
    let before = fake.seen().len();
    store.pull(&image_ref(REPO, &pushed.index)).expect("warm");
    assert_eq!(fake.seen().len(), before);
}

/// A `.sig` answer that parses as an artifact but is a manifest another
/// image keeps under another type (one without a `mediaType` field, kept
/// as Docker as its index says, served as OCI by the lookup) leaves the
/// kept copy as it is: the other image's pull stays offline.
#[test]
fn sig_answer_never_replaces_a_kept_manifest() {
    let mut hub = Hub::default();
    let layer = Layer::file("etc/a", b"a\n");
    let diff = layer.diff_id.clone();
    let config = format!(
        r#"{{"architecture":"amd64","os":"linux","rootfs":{{"type":"layers","diff_ids":["{diff}"]}}}}"#
    );
    let repo = "library/docker";
    let blob = hub.blob(repo, &layer.blob);
    let config_digest = hub.blob(repo, config.as_bytes());
    let manifest = format!(
        r#"{{"schemaVersion":2,"config":{},"layers":[{}]}}"#,
        descriptor(
            "application/vnd.oci.image.config.v1+json",
            &config_digest,
            config.len()
        ),
        descriptor(layer.media_type, &blob, layer.blob.len()),
    );
    let manifest_digest = hub.document(repo, media::DOCKER_MANIFEST, manifest.as_bytes());
    let index_bytes = index(&[entry(
        media::DOCKER_MANIFEST,
        &manifest_digest,
        manifest.len(),
        Some(("linux", "amd64", None)),
    )]);
    let digest = hub.document(repo, media::INDEX, &index_bytes);
    let evil = push(&mut hub, "evil/x", &[Layer::file("etc/evil", b"e\n")], "");
    hub.tag(
        "evil/x",
        &format!("{}.sig", tag_of(&evil.index)),
        media::MANIFEST,
        manifest.as_bytes(),
    );
    let fake = hub_fake(hub);
    let tmp = TempDir::new("sig-replace");
    let policy = rules(vec![rule(
        RepoScope::Exact(self::repo("evil/x")),
        Requirement::Required(keyed(&[SIGNER_PUB])),
    )]);
    let store = open_with(&tmp.path().join("store"), &fake, policy);
    store.pull(&image_ref(repo, &digest)).expect("docker image");
    let detail = match store.pull(&image_ref("evil/x", &evil.index)) {
        Err(ImageError::Failed { detail }) => detail,
        other => panic!("{other:?}"),
    };
    assert!(detail.contains("not a simple-signing layer"), "{detail}");
    let before = fake.seen().len();
    store.pull(&image_ref(repo, &digest)).expect("docker again");
    assert_eq!(fake.seen().len(), before, "the kept manifest was replaced");
}

// ---------------------------------------------------------------------
// SLSA provenance claims (ADR-031)
// ---------------------------------------------------------------------

const JQ_REPO: &str = "jqlang/jq";
const JQ_SAN_PREFIX: &str = "https://github.com/jqlang/jq/.github/workflows/ci.yml@refs/tags/";
const JQ_SOURCE: &str = "https://github.com/jqlang/jq";
const JQ_MATERIAL: &str = "git+https://github.com/jqlang/jq@refs/tags/jq-1.8.2";
const JQ_COMMIT: &str = "34f7186b86743a083a589741b6cea95293524108";
const ACME_SOURCE: &str = "https://github.com/acme/app";
const ACME_BUILDER: &str =
    "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main";

/// jq 1.8.2's real index (a Docker manifest list), amd64 manifest and
/// config, and GHCR's listing for the tag `sha256-<index hex>` with its
/// one SLSA referrer and bundle (captured 2026-11-24). No layer blob: a
/// layer request is answered `404`.
fn jq_hub() -> Hub {
    let mut hub = Hub::default();
    hub.document(JQ_REPO, media::DOCKER_LIST, JQ_INDEX);
    hub.document(JQ_REPO, media::DOCKER_MANIFEST, JQ_AMD64);
    hub.document(JQ_REPO, media::MANIFEST, JQ_REFERRER);
    hub.blob(JQ_REPO, JQ_CONFIG);
    hub.blob(JQ_REPO, JQ_BUNDLE);
    hub.tag(
        JQ_REPO,
        &tag_of(&digest_of(JQ_INDEX)),
        media::INDEX,
        JQ_REFERRERS,
    );
    hub
}

/// jq's keyless trust over the public-good root (its tag-release
/// workflow by SAN prefix), SLSA only, with the claims of the plan and
/// `repository` as the source-repository claim.
fn jq_trust(repository: &str) -> Arc<Trust> {
    let root = Arc::new(TrustedRoot::from_json(TRUSTED_ROOT).expect("root"));
    let identity =
        Identity::new(GITHUB_ACTIONS, SanRule::UriPrefix(JQ_SAN_PREFIX.to_owned())).expect("id");
    let claims = Claims::new(
        None,
        Some(ClaimMatch::Exact(repository.to_owned())),
        Some(ClaimMatch::Prefix("refs/tags/".to_owned())),
        vec![Material::new(JQ_MATERIAL, "gitCommit", JQ_COMMIT).expect("material")],
    )
    .expect("claims");
    Arc::new(
        Trust::new(
            Vec::new(),
            Some((root, vec![identity])),
            vec![SLSA_PROVENANCE_V1_PREDICATE.to_owned()],
        )
        .expect("trust")
        .with_claims(claims)
        .expect("with claims"),
    )
}

/// A GitHub-shaped SLSA v1 statement over `subject` whose source
/// repository is `repository`.
fn slsa_statement(subject: &str, repository: &str) -> Vec<u8> {
    let body = format!(
        r#"{{"buildDefinition":{{"buildType":"https://actions.github.io/buildtypes/workflow/v1","externalParameters":{{"workflow":{{"ref":"refs/heads/main","repository":"{repository}","path":".github/workflows/release.yml"}}}},"resolvedDependencies":[]}},"runDetails":{{"builder":{{"id":"{ACME_BUILDER}"}}}}}}"#
    );
    statement_with_body(&[subject], SLSA_PROVENANCE_V1_PREDICATE, &body)
}

/// A referrer of `subject` holding a keyed SLSA bundle by `signer` whose
/// source is `repository`; returns its listing entry.
fn slsa_referrer(hub: &mut Hub, signer: &Signer, subject: &str, repository: &str) -> String {
    let b = bundle(signer, &slsa_statement(subject, repository));
    referrer_with(
        hub,
        subject,
        &b,
        BUNDLE_V03_MEDIA_TYPE,
        SLSA_PROVENANCE_V1_PREDICATE,
    )
}

/// The test signer's key, SLSA only, with an exact source-repository
/// claim of `repository`; without claims if `None`.
fn slsa_keyed(repository: Option<&str>) -> Arc<Trust> {
    let trust = Trust::new(
        vec![PublicKey::from_pem(SIGNER_PUB).expect("key")],
        None,
        vec![SLSA_PROVENANCE_V1_PREDICATE.to_owned()],
    )
    .expect("trust");
    Arc::new(match repository {
        None => trust,
        Some(repository) => trust
            .with_claims(
                Claims::new(
                    None,
                    Some(ClaimMatch::Exact(repository.to_owned())),
                    None,
                    vec![],
                )
                .expect("claims"),
            )
            .expect("with claims"),
    })
}

/// Whether the fake saw a request for a `.sig` tag.
fn sig_requested(fake: &Fake) -> bool {
    fake.seen().iter().any(|s| s.target.ends_with(".sig"))
}

/// jq's real SLSA provenance through GHCR's tag schema: with claims it
/// meets, the pull goes on to its first layer (answered `404`); with a
/// source-repository claim it does not meet, it is refused before any
/// layer request and the detail names the claim. Neither asks for a
/// `.sig`.
#[test]
fn real_provenance_through_fallback_tag() {
    let index = digest_of(JQ_INDEX);
    // Pretty-printed, unlike the documents `nth_digest` reads.
    let compact: String = std::str::from_utf8(JQ_AMD64)
        .expect("utf-8")
        .split_whitespace()
        .collect();
    let first_layer = nth_digest(compact.as_bytes(), 1);
    for (repository, passes) in [
        (JQ_SOURCE, true),
        ("https://github.com/jqlang/other", false),
    ] {
        let fake = hub_fake(jq_hub());
        let tmp = TempDir::new("jq");
        let store = open_with(
            &tmp.path().join("store"),
            &fake,
            required(jq_trust(repository)),
        );
        let detail = match store.pull(&image_ref(JQ_REPO, &index)) {
            Err(ImageError::Failed { detail }) => detail,
            other => panic!("{other:?}"),
        };
        let reached = targets(&fake.seen())
            .iter()
            .any(|t| t.ends_with(&format!("/blobs/{first_layer}")));
        assert_eq!(reached, passes, "{detail}");
        assert!(!sig_requested(&fake), "{:?}", targets(&fake.seen()));
        if passes {
            assert!(!detail.contains("signature policy"), "{detail}");
        } else {
            assert!(detail.starts_with("signature policy: "), "{detail}");
            assert!(
                detail.contains(&format!(
                    "{index}: referrers tag: 1 listed, 1 candidates (entry 0: the provenance's source repository does not meet the rule)"
                )),
                "{detail}"
            );
        }
    }
}

/// Under a rule with claims, an image signed only by a trusted keyed
/// `.sig` is refused, the `.sig` tag never requested and the detail says
/// why; under the same trust without claims it passes as in #57.
#[test]
fn claims_rule_skips_sig_carrier() {
    for claims in [true, false] {
        let (mut hub, pushed) = app_hub();
        sign(&mut hub, "legacy", &signer(), &pushed.index, &pushed.index);
        let fake = hub_fake(hub);
        let trust = slsa_keyed(claims.then_some(ACME_SOURCE));
        let (tmp, result) = pull_once(&fake, required(trust), &pushed.index);
        if claims {
            let detail = refused_before_layers(&fake, &pushed, &tmp, result);
            assert!(
                detail.contains(&format!(
                    "{}: .sig: not examined, the rule has provenance claims",
                    pushed.index
                )),
                "{detail}"
            );
            assert!(!sig_requested(&fake), "{:?}", targets(&fake.seen()));
        } else {
            passed(result, &pushed);
            assert!(sig_requested(&fake));
        }
    }
}

/// Two SLSA referrers: the first fails the claims, the second meets them,
/// and the pull passes.
#[test]
fn claims_second_candidate_passes() {
    let (mut hub, pushed) = app_hub();
    let first = slsa_referrer(
        &mut hub,
        &signer(),
        &pushed.index,
        "https://github.com/acme/other",
    );
    let second = slsa_referrer(&mut hub, &signer(), &pushed.index, ACME_SOURCE);
    list(&mut hub, &pushed.index, &[first, second]);
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(
        &fake,
        required(slsa_keyed(Some(ACME_SOURCE))),
        &pushed.index,
    );
    passed(result, &pushed);
    // The first alone is refused.
    let (mut hub, pushed) = app_hub();
    let first = slsa_referrer(
        &mut hub,
        &signer(),
        &pushed.index,
        "https://github.com/acme/other",
    );
    list(&mut hub, &pushed.index, &[first]);
    let fake = hub_fake(hub);
    let (tmp, result) = pull_once(
        &fake,
        required(slsa_keyed(Some(ACME_SOURCE))),
        &pushed.index,
    );
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(
        detail.contains("the provenance's source repository does not meet the rule"),
        "{detail}"
    );
}

/// The kept evidence is checked against the current rule's claims: after
/// rule A's pass, rule B (another repository) on the same store is
/// refused and the detail names the claim for the kept evidence; rule A
/// again pulls warm with no request.
#[test]
fn warm_pull_rechecks_claims() {
    let (mut hub, pushed) = app_hub();
    let entry = slsa_referrer(&mut hub, &signer(), &pushed.index, ACME_SOURCE);
    list(&mut hub, &pushed.index, &[entry]);
    let fake = hub_fake(hub);
    let tmp = TempDir::new("warm-claims");
    let root = tmp.path().join("store");
    let a = || required(slsa_keyed(Some(ACME_SOURCE)));
    open_with(&root, &fake, a())
        .pull(&image_ref(REPO, &pushed.index))
        .expect("cold under A");
    let b = required(slsa_keyed(Some("https://github.com/acme/other")));
    let detail = match open_with(&root, &fake, b).pull(&image_ref(REPO, &pushed.index)) {
        Err(ImageError::Failed { detail }) => detail,
        other => panic!("{other:?}"),
    };
    assert!(
        detail.contains("kept evidence: the provenance's source repository does not meet the rule"),
        "{detail}"
    );
    let before = fake.seen().len();
    let store = open_with(&root, &fake, a());
    assert_eq!(
        store
            .pull(&image_ref(REPO, &pushed.index))
            .expect("warm under A")
            .rootfs
            .as_str(),
        pushed.manifest
    );
    assert_eq!(
        fake.seen().len(),
        before,
        "{:?}",
        targets(&fake.seen()[before..])
    );
}

// ---------------------------------------------------------------------
// Fulcio certificate claims (ADR-033)
// ---------------------------------------------------------------------

const CG_SOURCE: &str = "https://github.com/chainguard-images/images";

/// Chainguard's keyless trust (its workflow's exact SAN) with certificate
/// claims its real leaf meets but for `triggers`.
fn chainguard_certificate_trust(triggers: &[&str]) -> Arc<Trust> {
    let claims = CertificateClaims::new(
        Some(ClaimMatch::Exact(CG_SOURCE.to_owned())),
        Some(ClaimMatch::Exact("refs/heads/main".to_owned())),
        triggers.iter().map(|t| (*t).to_owned()).collect(),
    )
    .expect("certificate claims")
    .with_repository_id("563510952")
    .expect("repository id");
    let trust = chainguard_trust(SanRule::Uri(CHAINGUARD_WORKFLOW.to_owned()));
    Arc::new(
        Trust::clone(&trust)
            .with_certificate_claims(claims)
            .expect("with certificate claims"),
    )
}

fn chainguard_certificate_policy(triggers: &[&str]) -> SignaturePolicy {
    rules(vec![rule(
        RepoScope::Prefix("chainguard/".to_owned()),
        Requirement::Required(chainguard_certificate_trust(triggers)),
    )])
}

/// Whether the fake saw a request for Chainguard's first layer.
fn chainguard_layer_requested(fake: &Fake) -> bool {
    let layer = chainguard_first_layer();
    targets(&fake.seen())
        .iter()
        .any(|t| t.ends_with(&format!("/blobs/{layer}")))
}

const CG_TRIGGER_REFUSAL: &str =
    "the certificate's Fulcio Build Trigger (1.3.6.1.4.1.57264.1.20) does not meet the rule";

/// Certificate claims alone keep the `.sig` carrier: Chainguard's real
/// keyless `.sig` is requested and passes on to its first layer (answered
/// `404`); with the trigger list `[schedule]` it is refused before any
/// layer request, and the detail names the build trigger, not "not
/// examined".
#[test]
fn certificate_claims_examine_sig() {
    for (triggers, passes) in [(&["push"][..], true), (&["schedule"][..], false)] {
        let fake = hub_fake(chainguard_hub(CG_REPO, CG_DIGEST));
        let tmp = TempDir::new("certificate-claims");
        let store = open_with(
            &tmp.path().join("store"),
            &fake,
            chainguard_certificate_policy(triggers),
        );
        let detail = match store.pull(&image_ref(CG_REPO, CG_DIGEST)) {
            Err(ImageError::Failed { detail }) => detail,
            other => panic!("{other:?}"),
        };
        assert!(sig_requested(&fake), "{:?}", targets(&fake.seen()));
        assert_eq!(chainguard_layer_requested(&fake), passes, "{detail}");
        assert!(!detail.contains("not examined"), "{detail}");
        if passes {
            assert!(!detail.contains("signature policy"), "{detail}");
        } else {
            assert!(detail.starts_with("signature policy: "), "{detail}");
            assert!(
                detail.contains(&format!(": 1 listed (layer 0: {CG_TRIGGER_REFUSAL})")),
                "{detail}"
            );
        }
    }
}

/// The kept evidence is checked against the current rule's certificate
/// claims: after `[push]` passed, `[schedule]` on the same store is
/// refused, naming the build trigger for the kept evidence, before any
/// layer request; `[push]` again passes on the kept evidence with no
/// signature request.
#[test]
fn warm_pull_rechecks_certificate_claims() {
    let fake = hub_fake(chainguard_hub(CG_REPO, CG_DIGEST));
    let tmp = TempDir::new("warm-certificate-claims");
    let root = tmp.path().join("store");
    let pull =
        |triggers: &[&str]| match open_with(&root, &fake, chainguard_certificate_policy(triggers))
            .pull(&image_ref(CG_REPO, CG_DIGEST))
        {
            Err(ImageError::Failed { detail }) => detail,
            other => panic!("{other:?}"),
        };
    let detail = pull(&["push"]);
    assert!(!detail.contains("signature policy"), "{detail}");
    let before = fake.seen().len();
    let detail = pull(&["schedule"]);
    assert!(
        detail.contains(&format!("kept evidence: {CG_TRIGGER_REFUSAL}")),
        "{detail}"
    );
    let layer = chainguard_first_layer();
    assert!(
        !targets(&fake.seen()[before..])
            .iter()
            .any(|t| t.ends_with(&layer)),
        "a layer was requested under [schedule]"
    );
    let before = fake.seen().len();
    let detail = pull(&["push"]);
    assert!(!detail.contains("signature policy"), "{detail}");
    let seen = targets(&fake.seen()[before..]);
    assert!(!seen.iter().any(|t| t.ends_with(".sig")), "{seen:?}");
    assert!(
        seen.iter().any(|t| t.ends_with(&format!("/blobs/{layer}"))),
        "{seen:?}"
    );
}

/// jq's real attestation through GHCR's tag schema under #104's claims,
/// certificate claims and the statement agreement passes on to its first
/// layer (answered `404`); under the trigger list `[release]` it is
/// refused before any layer request, naming the build trigger.
#[test]
fn jq_agreement_through_fallback_tag() {
    let index = digest_of(JQ_INDEX);
    let compact: String = std::str::from_utf8(JQ_AMD64)
        .expect("utf-8")
        .split_whitespace()
        .collect();
    let first_layer = nth_digest(compact.as_bytes(), 1);
    for (triggers, passes) in [("push", true), ("release", false)] {
        let claims = CertificateClaims::new(
            Some(ClaimMatch::Exact(JQ_SOURCE.to_owned())),
            Some(ClaimMatch::Prefix("refs/tags/".to_owned())),
            vec![triggers.to_owned()],
        )
        .expect("certificate claims")
        .with_repository_id("5101141")
        .expect("repository id")
        .with_statement_agreement();
        let trust = Arc::new(
            Trust::clone(&jq_trust(JQ_SOURCE))
                .with_certificate_claims(claims)
                .expect("with certificate claims"),
        );
        let fake = hub_fake(jq_hub());
        let tmp = TempDir::new("jq-agreement");
        let store = open_with(&tmp.path().join("store"), &fake, required(trust));
        let detail = match store.pull(&image_ref(JQ_REPO, &index)) {
            Err(ImageError::Failed { detail }) => detail,
            other => panic!("{other:?}"),
        };
        let reached = targets(&fake.seen())
            .iter()
            .any(|t| t.ends_with(&format!("/blobs/{first_layer}")));
        assert_eq!(reached, passes, "{detail}");
        if !passes {
            assert!(
                detail.contains(&format!(
                    "{index}: referrers tag: 1 listed, 1 candidates (entry 0: {CG_TRIGGER_REFUSAL})"
                )),
                "{detail}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Origin (ADR-032)
// ---------------------------------------------------------------------

/// The detail of an agent reference refused before any request.
fn agent_refusal(registry: &str, repository: &str) -> String {
    format!(
        "signature policy: {registry}/{repository} was chosen by the agent, and no Required \
         rule or agent exemption covers it"
    )
}

fn agent_ref(name: &str, digest: &str) -> ImageRef {
    ImageRef {
        origin: ImageOrigin::Agent,
        ..image_ref(name, digest)
    }
}

fn exemption(registry: &str, scope: &str) -> AgentExemption {
    AgentExemption {
        registry: registry.to_owned(),
        scope: ExemptScope::parse(scope).expect("scope"),
    }
}

fn exempting(policy: SignaturePolicy, exemptions: Vec<AgentExemption>) -> SignaturePolicy {
    policy
        .with_agent_exemptions(exemptions)
        .expect("exemptions")
}

/// `Off` with the documented first-stack exemption, `docker.io` +
/// `library/`.
fn official() -> SignaturePolicy {
    exempting(
        SignaturePolicy::off(),
        vec![AgentExemption::docker_official_images()],
    )
}

fn recorded(registry: &str, scope: &str) -> Option<ImageExemption> {
    Some(ImageExemption {
        registry: registry.to_owned(),
        scope: scope.to_owned(),
    })
}

/// The store has nothing under `blobs/` and `layers/`.
fn store_empty(tmp: &TempDir) {
    let blobs: Vec<_> = std::fs::read_dir(tmp.path().join("store/blobs/sha256"))
        .expect("blobs")
        .collect();
    assert!(blobs.is_empty(), "{blobs:?}");
    assert!(layer_entries(tmp).is_empty(), "{:?}", layer_entries(tmp));
}

/// `image` is `Failed` with exactly `detail` and the fake saw no request
/// and no dial.
fn refused_unseen(fake: &Fake, got: Result<Pulled, ImageError>, detail: &str) {
    assert_eq!(
        got,
        Err(ImageError::Failed {
            detail: detail.to_owned()
        })
    );
    assert!(fake.seen().is_empty(), "{:?}", targets(&fake.seen()));
    assert!(fake.dials().is_empty(), "{:?}", fake.dials());
}

/// Requests for signature evidence that carried a token.
fn signature_requests(fake: &Fake) -> Vec<String> {
    targets(&fake.seen())
        .into_iter()
        .filter(|t| t.contains(".sig") || t.contains("/referrers/") || t.contains("sha256-"))
        .collect()
}

/// The hub of `app_hub` answering the referrers API with `[]` for both
/// subjects, as Docker Hub does (ADR-029).
fn docker_hub_like() -> (Hub, Pushed) {
    let (mut hub, pushed) = app_hub();
    for subject in [&pushed.index, &pushed.manifest] {
        list(&mut hub, subject, &[]);
    }
    (hub, pushed)
}

/// Under the default policy, with no exemption or an empty list, the
/// agent's unsigned `library/app` is refused with the exact detail before
/// any request, so no layer either, and the store keeps nothing.
#[test]
fn agent_unsigned_refused_without_any_request() {
    for policy in [
        SignaturePolicy::off(),
        exempting(SignaturePolicy::off(), Vec::new()),
    ] {
        let (hub, pushed) = app_hub();
        let fake = hub_fake(hub);
        let tmp = TempDir::new("agent-refused");
        let store = open_with(&tmp.path().join("store"), &fake, policy);
        let got = store.pull(&agent_ref(REPO, &pushed.index));
        refused_unseen(&fake, got, &agent_refusal("docker.io", REPO));
        store_empty(&tmp);
    }
}

/// An agent's reference under a `Required` rule is checked with that
/// rule's trust exactly as the operator's: signed, it passes, requests
/// its layers and reports no exemption; unsigned, it is refused after the
/// 4 signature requests of Docker Hub (`.sig` 404 and referrers `[]` for
/// the index and its platform manifest) and no layer request, and the
/// operator's pull sends the same requests.
#[test]
fn agent_ref_under_required_rule_checked() {
    let (mut hub, pushed) = app_hub();
    sign(&mut hub, "legacy", &signer(), &pushed.index, &pushed.index);
    let fake = hub_fake(hub);
    let tmp = TempDir::new("agent-required");
    let store = open_with(&tmp.path().join("store"), &fake, trusted());
    let got = store
        .pull(&agent_ref(REPO, &pushed.index))
        .expect("a signed agent image");
    assert_eq!(got.rootfs.as_str(), pushed.manifest);
    assert_eq!(got.exemption, None);
    assert!(layer_requested(&fake, &pushed));

    let mut logs = Vec::new();
    for origin in [ImageOrigin::Agent, ImageOrigin::Operator] {
        let (hub, pushed) = docker_hub_like();
        let fake = hub_fake(hub);
        let tmp = TempDir::new("agent-required-unsigned");
        let store = open_with(&tmp.path().join("store"), &fake, trusted());
        let result = store
            .pull(&ImageRef {
                origin,
                ..image_ref(REPO, &pushed.index)
            })
            .map(|p| p.rootfs.as_str().to_owned());
        let detail = refused_before_layers(&fake, &pushed, &tmp, result);
        assert!(detail.contains(".sig: none"), "{detail}");
        assert_eq!(signature_requests(&fake).len(), 4, "{origin:?}");
        logs.push(request_log(&fake.seen()));
    }
    assert_eq!(
        logs[0], logs[1],
        "the agent's check differs from the operator's"
    );
}

/// An exempted agent pull passes and reports `docker.io` + `library/`,
/// through the port and through the lease; the operator's pull of the
/// same image right after reports none, and neither does a lease of the
/// handle: the exemption belongs to the pull.
#[test]
fn exempted_agent_pull_reports_exemption() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("agent-exempted");
    let store = open_with(&tmp.path().join("store"), &fake, official());
    let agent = agent_ref(REPO, &pushed.index);
    let got = store.pull(&agent).expect("an exempted agent image");
    assert_eq!(got.rootfs.as_str(), pushed.manifest);
    assert_eq!(got.exemption, recorded("docker.io", "library/"));
    let lease = store.pull_leased(&agent).expect("leased");
    assert_eq!(
        lease.exemption().cloned(),
        recorded("docker.io", "library/")
    );
    drop(lease);
    let by_operator = store
        .pull(&image_ref(REPO, &pushed.index))
        .expect("operator");
    assert_eq!(by_operator.rootfs, got.rootfs);
    assert_eq!(by_operator.exemption, None);
    assert_eq!(
        store.lease(&got.rootfs).expect("lease").exemption(),
        None,
        "a lease is not a pull"
    );
}

/// Operator pulls with exemptions configured send exactly the requests of
/// #7, byte for byte. An exempted agent pull sends them too on a cold
/// store; a warm one fetches again only the document the reference names,
/// from the named repository (ADR-032, S6): the first three requests of
/// the cold pull (the manifest's `401`, the token, the manifest), and no
/// other.
#[test]
fn exempted_agent_requests_unchanged() {
    let with_exemptions = |fake: &Fake| {
        config_with(
            fake,
            exempting(
                SignaturePolicy::off(),
                vec![
                    AgentExemption::docker_official_images(),
                    exemption("docker.io", REPO),
                ],
            ),
        )
    };
    assert_eq!(logged_pulls(with_exemptions), POLICY_OFF_REQUESTS);
    let mut expected = String::new();
    for section in POLICY_OFF_REQUESTS.split_inclusive('\n').fold(
        Vec::<Vec<&str>>::new(),
        |mut sections, line| {
            if line.starts_with("# ") {
                sections.push(vec![line]);
            } else if let Some(last) = sections.last_mut() {
                last.push(line);
            }
            sections
        },
    ) {
        assert!(section[1].contains("/manifests/"), "{section:?}");
        assert!(
            section[2].starts_with("auth.docker.io:443 /token"),
            "{section:?}"
        );
        assert!(section[3].contains("/manifests/"), "{section:?}");
        expected.extend(section.iter().copied());
        expected.extend(section[1..4].iter().copied());
    }
    assert_eq!(
        logged_pulls_as(ImageOrigin::Agent, with_exemptions),
        expected
    );
}

/// An exemption never lifts a `Required` rule: under a registry-wide
/// rule, and under a `Required` default, the agent's unsigned image is
/// refused by the signature check of ADR-029, before any layer request.
#[test]
fn exemption_never_lifts_required_rule() {
    let trust = keyed(&[SIGNER_PUB]);
    let registry_wide = exempting(
        trusted(),
        vec![
            AgentExemption::docker_official_images(),
            exemption("docker.io", REPO),
        ],
    );
    let by_default = exempting(
        SignaturePolicy::new(Requirement::Required(trust), Vec::new()).expect("policy"),
        vec![AgentExemption::docker_official_images()],
    );
    for policy in [registry_wide, by_default] {
        let (hub, pushed) = docker_hub_like();
        let fake = hub_fake(hub);
        let tmp = TempDir::new("exemption-required");
        let store = open_with(&tmp.path().join("store"), &fake, policy);
        let result = store
            .pull(&agent_ref(REPO, &pushed.index))
            .map(|p| p.rootfs.as_str().to_owned());
        let detail = refused_before_layers(&fake, &pushed, &tmp, result);
        assert!(detail.contains(".sig: none"), "{detail}");
    }
}

/// An operator `Off` rule opens a repository to the operator's
/// references only. Under a registry-wide `Required` rule the operator's
/// pull passes unchecked, while the agent's is still checked under that
/// rule and refused by the signature check; with the `Off` rule alone, the
/// agent's is refused before any request.
#[test]
fn operator_off_rule_is_not_an_agent_exemption() {
    let policy = || {
        rules(vec![
            rule(
                RepoScope::Registry,
                Requirement::Required(keyed(&[SIGNER_PUB])),
            ),
            rule(RepoScope::Exact(repo(REPO)), Requirement::Off),
        ])
    };
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(&fake, policy(), &pushed.index);
    passed(result, &pushed);
    assert!(signature_requests(&fake).is_empty());

    let (hub, pushed) = docker_hub_like();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("off-not-exemption");
    let store = open_with(&tmp.path().join("store"), &fake, policy());
    let result = store
        .pull(&agent_ref(REPO, &pushed.index))
        .map(|p| p.rootfs.as_str().to_owned());
    let detail = refused_before_layers(&fake, &pushed, &tmp, result);
    assert!(detail.contains(".sig: none"), "{detail}");
    assert_eq!(signature_requests(&fake).len(), 4);

    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("off-alone");
    let off_alone = rules(vec![rule(RepoScope::Exact(repo(REPO)), Requirement::Off)]);
    let store = open_with(&tmp.path().join("store"), &fake, off_alone);
    let got = store.pull(&agent_ref(REPO, &pushed.index));
    refused_unseen(&fake, got, &agent_refusal("docker.io", REPO));
}

/// Review of PR #116: an operator `Off` rule never shadows a `Required`
/// rule for the agent, so it cannot turn on a broader exemption. With a
/// `Required` prefix `library/`, an exact `Off` rule for `library/app` and
/// the preset, the agent's unsigned `library/app` is checked under the
/// prefix's trust and refused after the 4 signature requests, not pulled
/// unchecked under `library/`; the operator's pull passes unchecked. Under
/// a `Required` default with an `Off` rule and no exemption, the agent's
/// reference is checked under the default.
#[test]
fn operator_off_rule_never_shadows_required_for_agent() {
    let trust = keyed(&[SIGNER_PUB]);
    let prefix_and_off = || {
        exempting(
            rules(vec![
                rule(
                    RepoScope::Prefix("library/".to_owned()),
                    Requirement::Required(Arc::clone(&trust)),
                ),
                rule(RepoScope::Exact(repo(REPO)), Requirement::Off),
            ]),
            vec![AgentExemption::docker_official_images()],
        )
    };
    let policy = prefix_and_off();
    for r in [REPO, "library/other"] {
        assert!(
            matches!(
                policy.decide("docker.io", &repo(r), ImageOrigin::Agent),
                Decision::Required(_)
            ),
            "{r}"
        );
    }
    assert!(matches!(
        policy.decide("docker.io", &repo(REPO), ImageOrigin::Operator),
        Decision::Unchecked
    ));
    let default_and_off = SignaturePolicy::new(
        Requirement::Required(Arc::clone(&trust)),
        vec![rule(RepoScope::Exact(repo(REPO)), Requirement::Off)],
    )
    .expect("policy");
    assert!(matches!(
        default_and_off.decide("docker.io", &repo(REPO), ImageOrigin::Agent),
        Decision::Required(_)
    ));

    for policy in [prefix_and_off(), default_and_off] {
        let (hub, pushed) = docker_hub_like();
        let fake = hub_fake(hub);
        let tmp = TempDir::new("off-shadow");
        let store = open_with(&tmp.path().join("store"), &fake, policy);
        let result = store
            .pull(&agent_ref(REPO, &pushed.index))
            .map(|p| p.rootfs.as_str().to_owned());
        let detail = refused_before_layers(&fake, &pushed, &tmp, result);
        assert!(detail.contains(".sig: none"), "{detail}");
        assert_eq!(signature_requests(&fake).len(), 4);
    }
    let (hub, pushed) = docker_hub_like();
    let fake = hub_fake(hub);
    let (_tmp, result) = pull_once(&fake, prefix_and_off(), &pushed.index);
    passed(result, &pushed);
    assert!(signature_requests(&fake).is_empty());
}

/// Review of PR #116: documents are kept by digest, so an agent's
/// reference must not be served a digest its named repository does not
/// hold. After the operator pulls `evil/miner@D`, the agent's
/// `library/node@D` is `NotFound`, as on a cold store, under the preset
/// and under a `Required` rule alike, and reports no exemption; the only
/// new requests are for the named document in `library/node`. An agent
/// pull of an image the named repository holds is served the kept layers
/// after that one document.
#[test]
fn agent_ref_never_served_another_repositorys_digest() {
    let required_library = || {
        rules(vec![rule(
            RepoScope::Prefix("library/".to_owned()),
            Requirement::Required(keyed(&[SIGNER_PUB])),
        )])
    };
    for policy in [official(), required_library()] {
        let mut hub = Hub::default();
        let evil = push(
            &mut hub,
            "evil/miner",
            &[Layer::file("etc/evil", b"evil\n")],
            "",
        );
        let fake = hub_fake(hub);
        let tmp = TempDir::new("agent-cross-repo");
        let store = open_with(&tmp.path().join("store"), &fake, policy);
        store
            .pull(&image_ref("evil/miner", &evil.index))
            .expect("operator");
        let before = fake.seen().len();
        let got = store.pull(&agent_ref("library/node", &evil.index));
        assert_eq!(got, Err(ImageError::NotFound));
        let new: Vec<String> = fake.seen()[before..]
            .iter()
            .map(|s| s.target.clone())
            .collect();
        assert!(!new.is_empty(), "the warm agent pull asked nothing");
        for target in &new {
            assert!(
                target.starts_with("/v2/library/node/manifests/") || target.starts_with("/token?"),
                "{target}"
            );
        }
    }

    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("agent-warm-own");
    let store = open_with(&tmp.path().join("store"), &fake, official());
    store
        .pull(&image_ref(REPO, &pushed.index))
        .expect("operator");
    let before = fake.seen().len();
    let got = store
        .pull(&agent_ref(REPO, &pushed.index))
        .expect("the named repository holds it");
    assert_eq!(got.rootfs.as_str(), pushed.manifest);
    assert_eq!(got.exemption, recorded("docker.io", "library/"));
    let authorized = targets(&fake.seen()[before..]);
    assert_eq!(
        authorized,
        [format!("/v2/{REPO}/manifests/{}", pushed.index)],
        "one manifest request for the named document"
    );
}

fn exempted_scope(decision: Decision<'_>) -> Option<String> {
    match decision {
        Decision::Exempted(e) => Some(format!("{} {}", e.registry, e.scope.as_str())),
        _ => None,
    }
}

/// The most specific exemption is the one recorded: an exact one over a
/// prefix, a longer prefix over a shorter one, in either order; a pull
/// records the exact one.
#[test]
fn most_specific_exemption_recorded() {
    let forward = vec![
        exemption("docker.io", "library/"),
        exemption("docker.io", REPO),
        exemption("docker.io", "a/"),
        exemption("docker.io", "a/b/"),
    ];
    let mut backward = forward.clone();
    backward.reverse();
    for list in [forward, backward] {
        let policy = exempting(SignaturePolicy::off(), list);
        let at = |r: &str| exempted_scope(policy.decide("docker.io", &repo(r), ImageOrigin::Agent));
        assert_eq!(at(REPO).as_deref(), Some("docker.io library/app"));
        assert_eq!(at("library/other").as_deref(), Some("docker.io library/"));
        assert_eq!(at("a/b/c").as_deref(), Some("docker.io a/b/"));
        assert_eq!(at("a/c").as_deref(), Some("docker.io a/"));
    }
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("exemption-specific");
    let policy = exempting(
        SignaturePolicy::off(),
        vec![
            AgentExemption::docker_official_images(),
            exemption("docker.io", REPO),
        ],
    );
    let store = open_with(&tmp.path().join("store"), &fake, policy);
    let got = store.pull(&agent_ref(REPO, &pushed.index)).expect("exempt");
    assert_eq!(got.exemption, recorded("docker.io", REPO));
}

/// A prefix ends on a component boundary: `library/` covers neither the
/// repository `library` nor `libraryx/app`, which are refused before any
/// request.
#[test]
fn exemption_prefix_on_component_boundary() {
    let policy = official();
    for r in ["library", "libraryx/app"] {
        assert!(
            matches!(
                policy.decide("docker.io", &repo(r), ImageOrigin::Agent),
                Decision::Refused
            ),
            "{r}"
        );
        let fake = hub_fake(Hub::default());
        let tmp = TempDir::new("exemption-boundary");
        let store = open_with(&tmp.path().join("store"), &fake, official());
        let got = store.pull(&agent_ref(r, &digest_of(b"anything")));
        refused_unseen(&fake, got, &agent_refusal("docker.io", r));
    }
}

/// An exemption is keyed by registry: `ghcr.io` + `library/` does not
/// cover `docker.io/library/app`.
#[test]
fn exemption_keyed_by_registry() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("exemption-registry");
    let mut config = config_with(
        &fake,
        exempting(
            SignaturePolicy::off(),
            vec![exemption("ghcr.io", "library/")],
        ),
    );
    config.registries.push(
        Registry::new(
            "ghcr.io",
            "ghcr.io",
            &["ghcr.io"],
            &[".githubusercontent.com"],
        )
        .expect("registry"),
    );
    let store = OciImageStore::open(&tmp.path().join("store"), config).expect("open");
    for name in [REPO, "docker.io/library/app"] {
        let got = store.pull(&agent_ref(name, &pushed.index));
        refused_unseen(&fake, got, &agent_refusal("docker.io", REPO));
    }
}

/// A name through Docker Hub's API host, with or without its port, is the
/// registry `docker.io`: exempt under the `docker.io` exemption and
/// recorded as `docker.io`, refused before any request without it.
#[test]
fn agent_ref_through_api_host_matches_registry_name() {
    let names = [
        "registry-1.docker.io/library/app",
        "registry-1.docker.io:443/library/app",
        "docker.io/library/app",
    ];
    for name in names {
        let (hub, pushed) = app_hub();
        let fake = hub_fake(hub);
        let tmp = TempDir::new("agent-api-host");
        let store = open_with(&tmp.path().join("store"), &fake, official());
        let got = store.pull(&agent_ref(name, &pushed.index)).expect(name);
        assert_eq!(got.exemption, recorded("docker.io", "library/"), "{name}");

        let (hub, pushed) = app_hub();
        let fake = hub_fake(hub);
        let tmp = TempDir::new("agent-api-host-refused");
        let store = open_with(&tmp.path().join("store"), &fake, SignaturePolicy::off());
        let got = store.pull(&agent_ref(name, &pushed.index));
        refused_unseen(&fake, got, &agent_refusal("docker.io", REPO));
    }
}

/// A bare name is read as written (D9): `app` is not `library/app`, so
/// `library/` does not cover it.
#[test]
fn exempted_prefix_does_not_cover_bare_name() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("agent-bare");
    let store = open_with(&tmp.path().join("store"), &fake, official());
    let got = store.pull(&agent_ref("app", &pushed.index));
    refused_unseen(&fake, got, &agent_refusal("docker.io", "app"));
}

/// Scope text that breaks the repository grammar of D9 is refused, by
/// `ExemptScope::parse` and, for a prefix built by hand, by
/// `with_agent_exemptions`; the longest valid prefix (255 bytes before the
/// `/`) is accepted and one byte more is not.
#[test]
fn exemption_grammar_checked() {
    let long_ok = format!("{}/", "a".repeat(255));
    let long_bad = format!("{}/", "a".repeat(256));
    let bad_prefixes = [
        "/",
        "//",
        "Library/",
        "l\u{456}brary/",
        "library\u{200b}/",
        "library /",
        " library/",
        "library/\t/",
        long_bad.as_str(),
    ];
    for text in bad_prefixes {
        match ExemptScope::parse(text) {
            Err(Error::InvalidPolicy(_)) => {}
            other => panic!("{text:?}: {other:?}"),
        }
        let by_hand = AgentExemption {
            registry: "docker.io".to_owned(),
            scope: ExemptScope::Prefix(text.to_owned()),
        };
        match SignaturePolicy::off().with_agent_exemptions(vec![by_hand]) {
            Err(Error::InvalidPolicy(_)) => {}
            other => panic!("{text:?}: {other:?}"),
        }
    }
    for text in [
        "",
        "library//app",
        "Library/app",
        "library/\t",
        "library/app ",
    ] {
        match ExemptScope::parse(text) {
            Err(Error::InvalidPolicy(_)) => {}
            other => panic!("{text:?}: {other:?}"),
        }
    }
    // A prefix built by hand without its `/` is refused, though parse
    // would have read the text as one repository.
    let no_slash = AgentExemption {
        registry: "docker.io".to_owned(),
        scope: ExemptScope::Prefix("library".to_owned()),
    };
    match SignaturePolicy::off().with_agent_exemptions(vec![no_slash]) {
        Err(Error::InvalidPolicy(detail)) => assert!(detail.contains("does not end in /")),
        other => panic!("{other:?}"),
    }
    assert_eq!(long_ok.len(), 256);
    assert_eq!(
        ExemptScope::parse(&long_ok).expect("255 bytes and the /"),
        ExemptScope::Prefix(long_ok.clone())
    );
    SignaturePolicy::off()
        .with_agent_exemptions(vec![exemption("docker.io", &long_ok)])
        .expect("the longest prefix");
}

/// The same registry and scope twice is refused; the same scope under two
/// registries, and a repository next to the prefix of the same text, are
/// fine.
#[test]
fn duplicate_exemption_refused() {
    for scope in [REPO, "library/"] {
        match SignaturePolicy::off().with_agent_exemptions(vec![
            exemption("docker.io", scope),
            exemption("docker.io", scope),
        ]) {
            Err(Error::InvalidPolicy(_)) => {}
            other => panic!("{scope}: {other:?}"),
        }
        SignaturePolicy::off()
            .with_agent_exemptions(vec![
                exemption("docker.io", scope),
                exemption("ghcr.io", scope),
            ])
            .expect("two registries");
    }
    SignaturePolicy::off()
        .with_agent_exemptions(vec![
            exemption("docker.io", "library"),
            exemption("docker.io", "library/"),
        ])
        .expect("a repository and a prefix of the same text");
}

/// An exemption for a registry the store does not pull from fails `open`
/// before the root exists.
#[test]
fn exemption_for_unknown_registry_refused() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("exemption-unknown-registry");
    let root = tmp.path().join("store");
    let policy = exempting(
        SignaturePolicy::off(),
        vec![exemption("ghcr.io", "library/")],
    );
    match OciImageStore::open(&root, config_with(&fake, policy)) {
        Err(Error::InvalidPolicy(detail)) => assert!(detail.contains("ghcr.io"), "{detail}"),
        other => panic!("{other:?}"),
    }
    assert!(!root.exists(), "open created the root");
}

/// A cached image is no exemption: after the operator's pull, the agent's
/// pull of the same image is refused with no new request; and a store
/// reopened on the same root without the exemption that admitted an
/// earlier agent pull refuses the agent's warm pull with no request.
#[test]
fn cached_image_refused_for_unexempted_agent() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("agent-cached");
    let root = tmp.path().join("store");
    let store = open_with(&root, &fake, SignaturePolicy::off());
    store
        .pull(&image_ref(REPO, &pushed.index))
        .expect("operator");
    let before = fake.seen().len();
    let got = store.pull(&agent_ref(REPO, &pushed.index));
    assert_eq!(
        got,
        Err(ImageError::Failed {
            detail: agent_refusal("docker.io", REPO)
        })
    );
    assert_eq!(fake.seen().len(), before);
    drop(store);

    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("agent-cached-reopen");
    let root = tmp.path().join("store");
    let store = open_with(&root, &fake, official());
    store
        .pull(&agent_ref(REPO, &pushed.index))
        .expect("exempted");
    drop(store);
    let cold = hub_fake(Hub::default());
    let store = open_with(&root, &cold, SignaturePolicy::off());
    let got = store.pull(&agent_ref(REPO, &pushed.index));
    refused_unseen(&cold, got, &agent_refusal("docker.io", REPO));
}

/// The refusal comes before the registry is asked, so an agent's
/// reference to a repository the registry does not have is `Failed`, not
/// `NotFound`; the operator's is `NotFound`.
#[test]
fn agent_refusal_is_failed_even_for_missing_image() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("agent-missing");
    let store = open_with(&tmp.path().join("store"), &fake, SignaturePolicy::off());
    let digest = digest_of(b"no such index");
    let got = store.pull(&agent_ref("library/missing", &digest));
    refused_unseen(&fake, got, &agent_refusal("docker.io", "library/missing"));
    assert_eq!(
        store.pull(&image_ref("library/missing", &digest)),
        Err(ImageError::NotFound)
    );
}

/// A look-alike name (Cyrillic, zero-width, upper case) is refused by the
/// reference grammar before any request, even under the exemption it
/// imitates.
#[test]
fn agent_lookalike_name_refused_before_any_request() {
    for name in ["l\u{456}brary/app", "library\u{200b}/app", "Library/app"] {
        let (hub, pushed) = app_hub();
        let fake = hub_fake(hub);
        let tmp = TempDir::new("agent-lookalike");
        let store = open_with(&tmp.path().join("store"), &fake, official());
        match store.pull(&agent_ref(name, &pushed.index)) {
            Err(ImageError::Failed { detail }) => assert!(!detail.is_empty()),
            other => panic!("{name:?}: {other:?}"),
        }
        assert!(fake.seen().is_empty(), "{name:?}");
        assert!(fake.dials().is_empty(), "{name:?}");
    }
}

/// A scope renders as it was parsed, and the text says which kind it is:
/// a repository never ends in `/`, a prefix always does.
#[test]
fn exemption_scope_round_trips() {
    for text in [REPO, "library", "library/", "a/b/", "a/b/c"] {
        let scope = ExemptScope::parse(text).expect(text);
        assert_eq!(scope.as_str(), text);
        assert_eq!(ExemptScope::parse(scope.as_str()).expect(text), scope);
        assert_eq!(
            matches!(scope, ExemptScope::Prefix(_)),
            text.ends_with('/'),
            "{text}"
        );
    }
}

/// The preset is `docker.io` + `library/`, and the agent's `library/node`
/// and `library/postgres` pull under it and record it (ADR-032 S4,
/// offline; the network test pulls the real ones).
#[test]
fn docker_official_images_preset() {
    assert_eq!(
        AgentExemption::docker_official_images(),
        AgentExemption {
            registry: "docker.io".to_owned(),
            scope: ExemptScope::Prefix("library/".to_owned()),
        }
    );
    let mut hub = Hub::default();
    let node = push(
        &mut hub,
        "library/node",
        &[Layer::file("usr/local/bin/node", b"node\n")],
        "",
    );
    let postgres = push(
        &mut hub,
        "library/postgres",
        &[Layer::file("usr/bin/postgres", b"postgres\n")],
        "",
    );
    let fake = hub_fake(hub);
    let tmp = TempDir::new("agent-preset");
    let store = open_with(&tmp.path().join("store"), &fake, official());
    for (name, pushed) in [("library/node", &node), ("library/postgres", &postgres)] {
        let got = store.pull(&agent_ref(name, &pushed.index)).expect(name);
        assert_eq!(got.rootfs.as_str(), pushed.manifest);
        assert_eq!(got.exemption, recorded("docker.io", "library/"), "{name}");
    }
}

/// For the agent, the `Required` rule that applies is the most specific
/// one of the reference's registry: an exact rule with the signer's key
/// wins over a prefix with another key, in either order, so the signed
/// image passes; a `Required` rule of another registry never applies, so
/// the preset still admits the agent's `docker.io` reference.
#[test]
fn agent_required_rule_most_specific_of_its_registry() {
    let exact = || {
        rule(
            RepoScope::Exact(repo(REPO)),
            Requirement::Required(keyed(&[SIGNER_PUB])),
        )
    };
    let prefix = || {
        rule(
            RepoScope::Prefix("library/".to_owned()),
            Requirement::Required(keyed(&[OTHER_PUB])),
        )
    };
    for list in [vec![exact(), prefix()], vec![prefix(), exact()]] {
        let (mut hub, pushed) = app_hub();
        sign(&mut hub, "legacy", &signer(), &pushed.index, &pushed.index);
        let fake = hub_fake(hub);
        let tmp = TempDir::new("agent-required-specific");
        let store = open_with(&tmp.path().join("store"), &fake, rules(list));
        let got = store
            .pull(&agent_ref(REPO, &pushed.index))
            .expect("checked under the exact rule");
        assert_eq!(got.exemption, None);
    }
    let mut ghcr = rule(
        RepoScope::Prefix("library/".to_owned()),
        Requirement::Required(keyed(&[SIGNER_PUB])),
    );
    ghcr.registry = "ghcr.io".to_owned();
    let policy = exempting(
        rules(vec![ghcr]),
        vec![AgentExemption::docker_official_images()],
    );
    assert_eq!(
        exempted_scope(policy.decide("docker.io", &repo(REPO), ImageOrigin::Agent)).as_deref(),
        Some("docker.io library/")
    );
}
