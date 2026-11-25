//! Keyless bundles without a transparency log (ADR-040): the opt-in
//! `Trust::with_no_log`, its configuration rules, and verification under
//! it. The known answers are two real bundles of GitHub's own Sigstore
//! instance, whose trusted root lists no Rekor and no CT log: K1, the
//! attest-demo bundle (CA and TSA window 0), and K2, GitHub's prober
//! (window 4), both MIT-sourced (`tests/data/README.md`). The synthetic
//! cases run over the instance of `support::pki` with its logs removed.

mod support;

use std::sync::Arc;

use boneli_https::{CertError, PublicKey, Sha256, TimestampError};
use boneli_json::Value;
use boneli_sigstore::{
    Accepted, COSIGN_SIGN_PREDICATE, CertificateClaims, CertificateRefusal, ClaimMatch, Claims,
    ConfigError, Evidence, Extension, GITHUB_ACTIONS_ISSUER, Identity, MAX_TIMESTAMPS, Refusal,
    SLSA_PROVENANCE_V1_PREDICATE, SanRule, Trust, TrustedRoot, base64, verify,
};
use support::pki::{
    self, AttestationSpec, BundleSpec, CODE_SIGNING, CertSpec, EMAIL, EPOCH_2020, IMAGE,
    INTERMEDIATE_NAME, ISSUER, LIFETIME, LeafSpec, NoteLog, Pki, ROOT_NAME, SERVER_AUTH, SctSigner,
    SctSpec, T, Tsa, URI, V2Spec, authority, basic_constraints_ca, eku, email_identity, hex,
    key_usage, keyless_trust_in, log_instance, name, obj, remove, root_value, s, set, to_bytes,
    valid_for, with_tokens, with_tsas,
};
use support::real;

// ---------------------------------------------------------------------
// Roots, trusts and evidence
// ---------------------------------------------------------------------

fn root_of(value: &Value) -> Arc<TrustedRoot> {
    Arc::new(TrustedRoot::from_json(&to_bytes(value)).expect("root"))
}

/// A keyless trust in `root` for `identities` with `predicates`, before
/// the opt-in.
fn plain(root: &Value, identities: Vec<Identity>, predicates: &[&str]) -> Trust {
    Trust::new(
        Vec::new(),
        Some((root_of(root), identities)),
        predicates.iter().map(|p| (*p).to_owned()).collect(),
    )
    .expect("trust")
}

/// [`plain`] with the opt-in.
fn no_log(root: &Value, identities: Vec<Identity>, predicates: &[&str]) -> Trust {
    plain(root, identities, predicates)
        .with_no_log()
        .expect("with no log")
}

/// A trust in GitHub's root for `identity`, SLSA v1, with the opt-in.
fn github(identity: Identity) -> Trust {
    no_log(
        &real::github_root_value(),
        vec![identity],
        &[SLSA_PROVENANCE_V1_PREDICATE],
    )
}

fn uri(text: &str) -> Identity {
    Identity::new(GITHUB_ACTIONS_ISSUER, SanRule::Uri(text.to_owned())).expect("identity")
}

fn uri_prefix(text: &str) -> Identity {
    Identity::new(GITHUB_ACTIONS_ISSUER, SanRule::UriPrefix(text.to_owned())).expect("identity")
}

/// `root` without the entries at `indices` of the array member `member`.
fn without(mut root: Value, member: &str, indices: &[usize]) -> Value {
    let Value::Object(object) = &mut root else {
        panic!("not an object");
    };
    let Some(Value::Array(list)) = object.get_mut(member) else {
        panic!("no array {member}");
    };
    let kept: Vec<Value> = std::mem::take(list)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !indices.contains(i))
        .map(|(_, v)| v)
        .collect();
    *list = kept;
    root
}

/// A real bundle with `edit` applied.
fn edited(bundle: &[u8], edit: impl FnOnce(&mut Value)) -> Result<Evidence, Refusal> {
    let mut value = real::json(bundle);
    edit(&mut value);
    Evidence::from_bundle(&to_bytes(&value))
}

const fn keyless_without_log(signed_timestamps: usize) -> Result<Accepted, Refusal> {
    Ok(Accepted::KeylessWithoutLog {
        signed_timestamps,
        identity: 0,
    })
}

/// The synthetic no-log root: the test instance's Fulcio chain and `tsa`,
/// no Rekor and no CT log, as GitHub's root.
fn no_log_root(pki: &Pki, tsa: &Tsa) -> Value {
    let mut root = with_tsas(root_value(pki), vec![tsa.authority(EPOCH_2020, None)]);
    remove(&mut root, &["tlogs"]);
    remove(&mut root, &["ctlogs"]);
    root
}

/// An email leaf without an SCT list, as GitHub's leaves.
fn leaf() -> LeafSpec {
    LeafSpec {
        scts: Vec::new(),
        ..LeafSpec::email()
    }
}

/// `spec`'s bundle without its log entry, carrying `tokens`.
fn bundle_value(pki: &Pki, spec: &BundleSpec, tokens: &[Vec<u8>]) -> Value {
    let mut value = with_tokens(spec.value(pki), tokens);
    remove(&mut value, &["verificationMaterial", "tlogEntries"]);
    value
}

fn bundle(pki: &Pki, spec: &BundleSpec, tokens: &[Vec<u8>]) -> Evidence {
    Evidence::from_bundle(&to_bytes(&bundle_value(pki, spec, tokens))).expect("bundle")
}

/// One synthetic world: the instance, its TSA, the no-log trust for the
/// email identity and the bundle spec of `leaf`.
struct World {
    pki: Pki,
    tsa: Tsa,
    trust: Trust,
    spec: BundleSpec,
}

impl World {
    fn new(leaf: &LeafSpec) -> World {
        let pki = Pki::new();
        let tsa = Tsa::new(&pki);
        let trust = no_log(
            &no_log_root(&pki, &tsa),
            vec![email_identity()],
            &[COSIGN_SIGN_PREDICATE],
        );
        let spec = BundleSpec::keyless(&pki, leaf, &IMAGE);
        World {
            pki,
            tsa,
            trust,
            spec,
        }
    }

    fn token(&self, at: u64) -> Vec<u8> {
        self.tsa.token(&self.spec.signature, at)
    }

    fn verify(&self, tokens: &[Vec<u8>]) -> Result<Accepted, Refusal> {
        verify(&bundle(&self.pki, &self.spec, tokens), &IMAGE, &self.trust)
    }
}

// ---------------------------------------------------------------------
// Configuration (D1)
// ---------------------------------------------------------------------

#[test]
fn no_log_config_rules() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let base = no_log_root(&pki, &tsa);
    let try_root = |root: &Value| {
        plain(root, vec![email_identity()], &[COSIGN_SIGN_PREDICATE])
            .with_no_log()
            .map(|_| ())
    };
    assert_eq!(try_root(&base), Ok(()));
    // The public-good root: Rekor v1, Rekor v2 and two CT logs.
    let public_good = Trust::new(
        Vec::new(),
        Some((real::public_good(), vec![real::chainguard_identity()])),
        vec![COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust");
    assert_eq!(
        public_good.with_no_log().map(|_| ()),
        Err(ConfigError::NoLogRootHasLogs)
    );

    // The no-log root plus exactly one log, of each kind the reader knows.
    let left_out = {
        let key = pki::p256_leaf_key();
        obj(vec![
            ("baseUrl", s("https://left-out.boneli.test")),
            ("hashAlgorithm", s("SHA2_256")),
            (
                "publicKey",
                obj(vec![
                    ("rawBytes", s(&base64::encode(key.public_key().spki_der()))),
                    ("keyDetails", s("PKIX_ECDSA_P256_SHA_256")),
                    ("validFor", valid_for(EPOCH_2020, None)),
                ]),
            ),
            (
                "logId",
                obj(vec![("keyId", s(&base64::encode(&[0x42; 32])))]),
            ),
        ])
    };
    let with_member = |member: &str, entry: Value| {
        let mut root = base.clone();
        set(&mut root, &[member], Value::Array(vec![entry]));
        root
    };
    let variants = [
        (
            "Rekor v1",
            with_member("tlogs", log_instance(&pki.rekor_key, EPOCH_2020, None)),
            (1, 0, 0),
        ),
        (
            "Rekor v2",
            with_member("tlogs", NoteLog::new().instance(EPOCH_2020, None)),
            (0, 1, 0),
        ),
        (
            "left-out P-256 Rekor",
            with_member("tlogs", left_out),
            (0, 0, 0),
        ),
        (
            "CT",
            with_member("ctlogs", log_instance(&pki.ct_key, EPOCH_2020, None)),
            (0, 0, 1),
        ),
    ];
    for (name, root, counts) in variants {
        let parsed = root_of(&root);
        assert_eq!(
            (
                parsed.tlog_count(),
                parsed.note_log_count(),
                parsed.ctlog_count()
            ),
            counts,
            "{name}"
        );
        assert_eq!(
            try_root(&root),
            Err(ConfigError::NoLogRootHasLogs),
            "{name}"
        );
    }

    // TSAs: none, one skipped one-certificate entry, one usable.
    let mut no_member = base.clone();
    remove(&mut no_member, &["timestampAuthorities"]);
    assert_eq!(try_root(&no_member), Err(ConfigError::NoLogRootWithoutTsa));
    let single = with_tsas(
        no_member.clone(),
        vec![authority(&[&tsa.leaf], EPOCH_2020, None)],
    );
    assert_eq!(root_of(&single).tsa_count(), 0);
    assert_eq!(try_root(&single), Err(ConfigError::NoLogRootWithoutTsa));
    assert_eq!(root_of(&base).tsa_count(), 1);

    // A keyless part is required; keys next to it are allowed.
    let key = pki.signer_key.public.clone();
    let keys_only = Trust::new(
        vec![key.clone()],
        None,
        vec![COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust");
    assert_eq!(
        keys_only.with_no_log().map(|_| ()),
        Err(ConfigError::NoLogWithoutKeyless)
    );
    let both = Trust::new(
        vec![key],
        Some((root_of(&base), vec![email_identity()])),
        vec![COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust");
    assert!(both.with_no_log().is_ok());

    // Identities: every one must name at least an owner.
    let with_ids = |ids: Vec<Identity>| {
        plain(&base, ids, &[COSIGN_SIGN_PREDICATE])
            .with_no_log()
            .map(|_| ())
    };
    let email = Identity::new(ISSUER, SanRule::Email(EMAIL.to_owned())).expect("identity");
    for passes in [
        uri(real::ATTEST_DEMO_WORKFLOW),
        email.clone(),
        uri_prefix("https://github.com/acme/"),
        uri_prefix("https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/"),
    ] {
        assert_eq!(with_ids(vec![passes.clone()]), Ok(()), "{passes:?}");
    }
    for refused in [
        "https://github.com/",
        "https://",
        "https://github.com//",
        "https://github.com/./",
        "https://github.com/../",
        "https:///acme/",
        "github.com/acme/",
    ] {
        assert_eq!(
            with_ids(vec![uri_prefix(refused)]),
            Err(ConfigError::NoLogIdentityWithoutOwner),
            "{refused}"
        );
    }
    // Every identity must pass, not any.
    assert_eq!(
        with_ids(vec![
            uri(real::ATTEST_DEMO_WORKFLOW),
            uri_prefix("https://github.com/")
        ]),
        Err(ConfigError::NoLogIdentityWithoutOwner)
    );
    assert_eq!(
        with_ids(vec![uri_prefix("https://github.com/"), email]),
        Err(ConfigError::NoLogIdentityWithoutOwner)
    );
    // Non-ASCII and zero-width text never reaches the check.
    assert_eq!(
        Identity::new(
            GITHUB_ACTIONS_ISSUER,
            SanRule::UriPrefix("https://github.com/\u{200b}/".to_owned())
        ),
        Err(ConfigError::IdentityNotAscii)
    );
}

#[test]
fn no_log_debug() {
    let root = real::github_root_value();
    let without = plain(
        &root,
        vec![uri(real::ATTEST_DEMO_WORKFLOW)],
        &[SLSA_PROVENANCE_V1_PREDICATE],
    );
    // Without the opt-in the trust reads as before ADR-040.
    assert_eq!(
        format!("{without:?}"),
        "Trust { keys: 0, identities: 1, predicate_types: 1 }"
    );
    assert!(!without.no_log());
    let with = without.clone().with_no_log().expect("no log");
    assert!(with.no_log());
    assert_eq!(
        format!("{with:?}"),
        "Trust { keys: 0, identities: 1, predicate_types: 1, no_log: true }"
    );
    let claims = CertificateClaims::new(None, None, vec![real::ATTEST_DEMO_TRIGGER.to_owned()])
        .expect("claims");
    let first = with
        .with_certificate_claims(claims.clone())
        .expect("claims after");
    let second = without
        .with_certificate_claims(claims)
        .expect("claims before")
        .with_no_log()
        .expect("no log after");
    assert_eq!(format!("{first:?}"), format!("{second:?}"));
    assert_eq!(
        format!("{first:?}"),
        "Trust { keys: 0, identities: 1, predicate_types: 1, certificate_claims: true, no_log: true }"
    );
    assert!(first.no_log() && second.no_log());
    assert!(first.certificate_claims().is_some() && second.certificate_claims().is_some());
}

#[test]
fn no_log_keeps_keyed() {
    let key = PublicKey::from_pem(real::COSIGN_RELEASE_KEY).expect("key");
    let trust = Trust::new(
        vec![key],
        Some((real::github_root(), vec![uri(real::ATTEST_DEMO_WORKFLOW)])),
        vec![COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust")
    .with_no_log()
    .expect("no log");
    assert_eq!(
        verify(&real::cosign(), &real::COSIGN_DIGEST, &trust),
        Ok(Accepted::Keyed { key: 0 })
    );
}

// ---------------------------------------------------------------------
// The real bundles (AC 2)
// ---------------------------------------------------------------------

#[test]
fn real_github_bundles_verify_under_no_log() {
    assert_eq!(Sha256::digest(real::GITHUB_ROOT), real::GITHUB_ROOT_SHA256);
    assert_eq!(
        Sha256::digest(real::ATTEST_DEMO_BUNDLE),
        real::ATTEST_DEMO_BUNDLE_SHA256
    );
    assert_eq!(
        Sha256::digest(real::PROBER_BUNDLE),
        real::PROBER_BUNDLE_SHA256
    );
    let root = real::github_root();
    assert_eq!(
        format!("{root:?}"),
        "TrustedRoot { tlogs: 0, note_logs: 0, authorities: 6, ctlogs: 0, tsas: 6 }"
    );
    assert_eq!(
        verify(
            &real::attest_demo(),
            &real::ATTEST_DEMO_DIGEST,
            &github(uri(real::ATTEST_DEMO_WORKFLOW))
        ),
        keyless_without_log(1)
    );
    assert_eq!(
        verify(
            &real::prober(),
            &real::PROBER_DIGEST,
            &github(uri(real::PROBER_WORKFLOW))
        ),
        keyless_without_log(1)
    );
    assert_eq!(
        verify(
            &real::prober(),
            &real::PROBER_DIGEST,
            &github(uri_prefix("https://github.com/actions/"))
        ),
        keyless_without_log(1)
    );
    // The first matching identity is named.
    let trust = no_log(
        &real::github_root_value(),
        vec![uri(real::ATTEST_DEMO_WORKFLOW), uri(real::PROBER_WORKFLOW)],
        &[SLSA_PROVENANCE_V1_PREDICATE],
    );
    assert_eq!(
        verify(&real::prober(), &real::PROBER_DIGEST, &trust),
        Ok(Accepted::KeylessWithoutLog {
            signed_timestamps: 1,
            identity: 1,
        })
    );
    // Each bundle signs only its own subject.
    assert_eq!(
        verify(
            &real::attest_demo(),
            &real::PROBER_DIGEST,
            &github(uri(real::ATTEST_DEMO_WORKFLOW))
        ),
        Err(Refusal::SubjectMismatch)
    );
}

#[test]
fn real_github_bundles_refused_without_opt_in() {
    let root = real::github_root_value();
    for (evidence, digest, identity) in [
        (
            real::attest_demo(),
            real::ATTEST_DEMO_DIGEST,
            real::ATTEST_DEMO_WORKFLOW,
        ),
        (real::prober(), real::PROBER_DIGEST, real::PROBER_WORKFLOW),
    ] {
        let trust = plain(&root, vec![uri(identity)], &[SLSA_PROVENANCE_V1_PREDICATE]);
        assert_eq!(
            verify(&evidence, &digest, &trust),
            Err(Refusal::TlogEntries),
            "{identity}"
        );
    }
}

// ---------------------------------------------------------------------
// Negative fixtures (AC 3)
// ---------------------------------------------------------------------

#[test]
fn no_log_bundle_under_public_good_root() {
    let trust = Trust::new(
        Vec::new(),
        Some((real::public_good(), vec![uri(real::ATTEST_DEMO_WORKFLOW)])),
        vec![SLSA_PROVENANCE_V1_PREDICATE.to_owned()],
    )
    .expect("trust");
    assert_eq!(
        trust.clone().with_no_log().map(|_| ()),
        Err(ConfigError::NoLogRootHasLogs)
    );
    assert_eq!(
        verify(&real::attest_demo(), &real::ATTEST_DEMO_DIGEST, &trust),
        Err(Refusal::TlogEntries)
    );
}

/// The downgrade: a public-good bundle with its log entry removed. It
/// still carries a public-good token, and without its entry it is refused,
/// while the bundle as captured passes.
#[test]
fn stripped_public_good_bundle_refused() {
    let trust = real::keyless(vec![real::trillian_identity()]);
    assert!(matches!(
        verify(&real::trillian(), &real::TRILLIAN_DIGEST, &trust),
        Ok(Accepted::Keyless {
            signed_timestamps: 1,
            ..
        })
    ));
    for edit in [
        |v: &mut Value| remove(v, &["verificationMaterial", "tlogEntries"]),
        |v: &mut Value| {
            set(
                v,
                &["verificationMaterial", "tlogEntries"],
                Value::Array(Vec::new()),
            )
        },
    ] {
        let stripped = edited(real::TRILLIAN_BUNDLE, edit).expect("bundle");
        assert_eq!(
            verify(&stripped, &real::TRILLIAN_DIGEST, &trust),
            Err(Refusal::TlogEntries)
        );
    }
}

#[test]
fn no_log_tsa_not_in_root() {
    // K1's genTime 1713807206 lies in TSA window 0 only (window 1 starts
    // 2024-05-13).
    let root = without(real::github_root_value(), "timestampAuthorities", &[0]);
    let trust = no_log(
        &root,
        vec![uri(real::ATTEST_DEMO_WORKFLOW)],
        &[SLSA_PROVENANCE_V1_PREDICATE],
    );
    assert_eq!(
        verify(&real::attest_demo(), &real::ATTEST_DEMO_DIGEST, &trust),
        Err(Refusal::NoTsaAtTime)
    );
    // Synthetic: a token with the right imprint from a TSA the root does
    // not list.
    let world = World::new(&leaf());
    let foreign = Tsa::attacker(&world.pki).token(&world.spec.signature, T + 10);
    assert_eq!(
        world.verify(&[foreign]),
        Err(Refusal::Timestamp(TimestampError::SigningCertificate))
    );
}

#[test]
fn no_log_needs_a_timestamp() {
    let trust = github(uri(real::ATTEST_DEMO_WORKFLOW));
    let shapes: [fn(&mut Value); 3] = [
        |v| remove(v, &["verificationMaterial", "timestampVerificationData"]),
        |v| {
            set(
                v,
                &["verificationMaterial", "timestampVerificationData"],
                obj(vec![]),
            )
        },
        |v| {
            set(
                v,
                &["verificationMaterial", "timestampVerificationData"],
                obj(vec![("rfc3161Timestamps", Value::Array(Vec::new()))]),
            )
        },
    ];
    for (i, shape) in shapes.into_iter().enumerate() {
        let evidence = edited(real::ATTEST_DEMO_BUNDLE, shape).expect("bundle");
        assert_eq!(
            verify(&evidence, &real::ATTEST_DEMO_DIGEST, &trust),
            Err(Refusal::NoTimeSource),
            "shape {i}"
        );
    }
}

/// A root captured before 2025-11-13 lacks CA and TSA windows 4 and 5:
/// TSA window 3 holds K2's time, but its leaf did not sign the token.
#[test]
fn no_log_stale_root() {
    let root = without(real::github_root_value(), "certificateAuthorities", &[4, 5]);
    let root = without(root, "timestampAuthorities", &[4, 5]);
    let trust = no_log(
        &root,
        vec![uri(real::PROBER_WORKFLOW)],
        &[SLSA_PROVENANCE_V1_PREDICATE],
    );
    assert_eq!(
        verify(&real::prober(), &real::PROBER_DIGEST, &trust),
        Err(Refusal::Timestamp(TimestampError::SigningCertificate))
    );
}

#[test]
fn no_log_ca_windows() {
    // K1's time lies in CA window 0 only.
    let root = without(real::github_root_value(), "certificateAuthorities", &[0]);
    let trust = no_log(
        &root,
        vec![uri(real::ATTEST_DEMO_WORKFLOW)],
        &[SLSA_PROVENANCE_V1_PREDICATE],
    );
    assert_eq!(
        verify(&real::attest_demo(), &real::ATTEST_DEMO_DIGEST, &trust),
        Err(Refusal::NoCaAtTime)
    );
    // K2's time lies in CA windows 3 and 4; window 3's l2 has the same
    // name and another key.
    let root = without(real::github_root_value(), "certificateAuthorities", &[4]);
    let trust = no_log(
        &root,
        vec![uri(real::PROBER_WORKFLOW)],
        &[SLSA_PROVENANCE_V1_PREDICATE],
    );
    assert_eq!(
        verify(&real::prober(), &real::PROBER_DIGEST, &trust),
        Err(Refusal::Certificate(CertError::Invalid))
    );
    // Only window 4 left: K2 passes through it alone.
    let root = without(
        real::github_root_value(),
        "certificateAuthorities",
        &[0, 1, 2, 3, 5],
    );
    let trust = no_log(
        &root,
        vec![uri(real::PROBER_WORKFLOW)],
        &[SLSA_PROVENANCE_V1_PREDICATE],
    );
    assert_eq!(
        verify(&real::prober(), &real::PROBER_DIGEST, &trust),
        keyless_without_log(1)
    );
}

// ---------------------------------------------------------------------
// Verification under the opt-in (D2)
// ---------------------------------------------------------------------

#[test]
fn no_log_token_rules() {
    let world = World::new(&leaf());
    let good = world.token(T + 10);
    // No token.
    assert_eq!(world.verify(&[]), Err(Refusal::NoTimeSource));
    // One valid and one garbage token: the garbage does not count.
    assert_eq!(
        world.verify(&[good.clone(), b"not a token".to_vec()]),
        keyless_without_log(1)
    );
    assert_eq!(
        world.verify(&[b"not a token".to_vec(), good.clone()]),
        keyless_without_log(1)
    );
    // Two valid tokens count two.
    assert_eq!(
        world.verify(&[good.clone(), world.token(T + 20)]),
        keyless_without_log(2)
    );
    // Every verified time is checked: the second one after the leaf's
    // notAfter refuses.
    assert_eq!(
        world.verify(&[good.clone(), world.token(T + LIFETIME + 1)]),
        Err(Refusal::Certificate(CertError::OutsideValidity))
    );
    assert_eq!(
        world.verify(&[world.token(T - 1)]),
        Err(Refusal::Certificate(CertError::OutsideValidity))
    );
    // The leaf's bounds are inclusive; the CA window is open-ended.
    assert_eq!(
        world.verify(&[world.token(T + LIFETIME)]),
        keyless_without_log(1)
    );
    assert_eq!(world.verify(&[world.token(T)]), keyless_without_log(1));
    // The existing cap: 32 tokens pass, 33 are refused when read.
    let all = vec![good; MAX_TIMESTAMPS];
    assert_eq!(world.verify(&all), keyless_without_log(MAX_TIMESTAMPS));
    let mut over = all;
    over.push(world.token(T + 30));
    assert_eq!(
        Evidence::from_bundle(&to_bytes(&bundle_value(&world.pki, &world.spec, &over))).err(),
        Some(Refusal::TooManyTimestamps)
    );
}

/// Under the opt-in a bundle must carry no log entry at all: a Rekor v1
/// entry with its SET, and a Rekor v2 entry, are refused.
#[test]
fn no_log_refuses_log_entries() {
    let world = World::new(&leaf());
    let with_entry = with_tokens(world.spec.value(&world.pki), &[world.token(T + 10)]);
    let evidence = Evidence::from_bundle(&to_bytes(&with_entry)).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &world.trust),
        Err(Refusal::TlogEntries)
    );
    let log = NoteLog::new();
    let v2 = V2Spec::new(&world.pki, &log, &IMAGE);
    let token = world.tsa.token(&v2.signature, T + 10);
    assert_eq!(
        verify(
            &v2.evidence(&[token]).expect("bundle"),
            &IMAGE,
            &world.trust
        ),
        Err(Refusal::TlogEntries)
    );
}

/// Cosign layers carry no token this crate reads (ADR-038), and the root
/// has no log whose SET could time them: refused before their entry.
#[test]
fn no_log_refuses_cosign_layers() {
    let trust = no_log(
        &real::github_root_value(),
        vec![real::chainguard_identity()],
        &[COSIGN_SIGN_PREDICATE],
    );
    assert_eq!(
        verify(&real::chainguard(), &real::CHAINGUARD_DIGEST, &trust),
        Err(Refusal::NoTimeSource)
    );
    // A keyless `.att` under claims.
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let statement = pki::statement(&[&hex(&IMAGE)], SLSA_PROVENANCE_V1_PREDICATE);
    let mut spec = AttestationSpec::keyless(&pki, &LeafSpec::uri(URI), statement);
    spec.predicate_type = SLSA_PROVENANCE_V1_PREDICATE.to_owned();
    let claims = Claims::new(
        None,
        Some(ClaimMatch::Exact("https://github.com/acme/app".to_owned())),
        None,
        Vec::new(),
    )
    .expect("claims");
    let trust = no_log(
        &no_log_root(&pki, &tsa),
        vec![Identity::new(ISSUER, SanRule::Uri(URI.to_owned())).expect("identity")],
        &[SLSA_PROVENANCE_V1_PREDICATE],
    )
    .with_claims(claims)
    .expect("claims");
    assert_eq!(
        verify(&spec.evidence(&pki).expect("attestation"), &IMAGE, &trust),
        Err(Refusal::NoTimeSource)
    );
}

/// The SCT list goes unread under the opt-in: an SCT from a log no root
/// lists passes there, and is refused under a logged root without it.
#[test]
fn no_log_sct_list_unread() {
    let foreign = LeafSpec {
        scts: vec![SctSpec {
            signer: SctSigner::Other,
            ..SctSpec::good()
        }],
        ..LeafSpec::email()
    };
    let world = World::new(&foreign);
    assert_eq!(world.verify(&[world.token(T + 10)]), keyless_without_log(1));
    let logged = keyless_trust_in(&root_value(&world.pki), vec![email_identity()]);
    let evidence = Evidence::from_bundle(&world.spec.bytes(&world.pki)).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &logged),
        Err(Refusal::Sct(boneli_https::SctError::NoneVerified))
    );
}

#[test]
fn no_log_identity_mismatch() {
    assert_eq!(
        verify(
            &real::attest_demo(),
            &real::ATTEST_DEMO_DIGEST,
            &github(uri(real::PROBER_WORKFLOW))
        ),
        Err(Refusal::IdentityMismatch)
    );
    assert_eq!(
        verify(
            &real::attest_demo(),
            &real::ATTEST_DEMO_DIGEST,
            &github(uri_prefix(
                "https://github.com/actions/attest-build-provenance/"
            ))
        ),
        Err(Refusal::IdentityMismatch)
    );
}

#[test]
fn no_log_with_certificate_claims() {
    let claims = |id: &str, trigger: &str| {
        CertificateClaims::new(
            Some(ClaimMatch::Exact(real::ATTEST_DEMO_REPOSITORY.to_owned())),
            None,
            vec![trigger.to_owned()],
        )
        .expect("claims")
        .with_repository_id(id)
        .expect("repository id")
    };
    let check = |id: &str, trigger: &str| {
        let trust = github(uri(real::ATTEST_DEMO_WORKFLOW))
            .with_certificate_claims(claims(id, trigger))
            .expect("certificate claims");
        verify(&real::attest_demo(), &real::ATTEST_DEMO_DIGEST, &trust)
    };
    assert_eq!(
        check(real::ATTEST_DEMO_REPOSITORY_ID, real::ATTEST_DEMO_TRIGGER),
        keyless_without_log(1)
    );
    assert_eq!(
        check(real::ATTEST_DEMO_REPOSITORY_ID, "push"),
        Err(Refusal::CertificateClaim(CertificateRefusal::Mismatch(
            Extension::BuildTrigger
        )))
    );
    assert_eq!(
        check("763287533", real::ATTEST_DEMO_TRIGGER),
        Err(Refusal::CertificateClaim(CertificateRefusal::Mismatch(
            Extension::SourceRepositoryIdentifier
        )))
    );
}

// ---------------------------------------------------------------------
// GitHub-shaped chains (D4)
// ---------------------------------------------------------------------

const L1_NAME: &str = "Boneli sigstore test l1";

/// A CA certificate of the synthetic GitHub-shaped chain.
fn ca(
    serial: u8,
    issuer: &str,
    subject: &str,
    spki: Vec<u8>,
    purposes: Option<&[&[u8]]>,
) -> CertSpec {
    let mut extensions = vec![basic_constraints_ca(), key_usage(0x06)];
    if let Some(purposes) = purposes {
        extensions.push(eku(purposes));
    }
    CertSpec {
        serial,
        issuer: name(issuer),
        subject: name(subject),
        not_before: T - 365 * 86_400,
        not_after: T + 10 * 365 * 86_400,
        spki,
        extensions,
    }
}

/// The synthetic root → l1 → l2 → leaf chain, as GitHub's: l1 (the other
/// key) with `l1_eku`, l2 (the intermediate's key and name, so the built
/// leaves chain to it) with `l2_eku`, and the no-log root over it.
fn github_shaped(
    pki: &Pki,
    tsa: &Tsa,
    l1_eku: Option<&[&[u8]]>,
    l2_eku: Option<&[&[u8]]>,
) -> Value {
    let l1 = ca(20, ROOT_NAME, L1_NAME, pki.other_key.spki(), l1_eku).sign(&pki.root_key);
    let l2 = ca(
        21,
        L1_NAME,
        INTERMEDIATE_NAME,
        pki.intermediate_key.spki(),
        l2_eku,
    )
    .sign(&pki.other_key);
    let mut root = no_log_root(pki, tsa);
    set(
        &mut root,
        &["certificateAuthorities"],
        Value::Array(vec![authority(&[&l2, &l1, &pki.root], EPOCH_2020, None)]),
    );
    root
}

#[test]
fn github_shaped_chain_rules() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let code_signing: &[&[u8]] = &[CODE_SIGNING];
    let server_auth: &[&[u8]] = &[SERVER_AUTH];
    let check = |root: &Value, leaf: &LeafSpec| {
        let trust = no_log(root, vec![email_identity()], &[COSIGN_SIGN_PREDICATE]);
        let spec = BundleSpec::keyless(&pki, leaf, &IMAGE);
        let token = tsa.token(&spec.signature, T + 10);
        verify(&bundle(&pki, &spec, &[token]), &IMAGE, &trust)
    };
    let github = github_shaped(&pki, &tsa, None, Some(code_signing));
    assert_eq!(check(&github, &leaf()), keyless_without_log(1));
    assert_eq!(
        check(
            &github_shaped(&pki, &tsa, Some(server_auth), Some(code_signing)),
            &leaf()
        ),
        Err(Refusal::Certificate(CertError::NotCodeSigning))
    );
    assert_eq!(
        check(
            &github_shaped(&pki, &tsa, Some(code_signing), Some(server_auth)),
            &leaf()
        ),
        Err(Refusal::Certificate(CertError::NotCodeSigning))
    );
    assert_eq!(
        check(&github_shaped(&pki, &tsa, None, None), &leaf()),
        keyless_without_log(1)
    );
    for (what, purposes) in [
        ("no EKU", None),
        ("an empty EKU", Some(Vec::new())),
        ("serverAuth only", Some(vec![SERVER_AUTH])),
    ] {
        let leaf = LeafSpec {
            eku: purposes,
            ..leaf()
        };
        assert_eq!(
            check(&github, &leaf),
            Err(Refusal::Certificate(CertError::NotCodeSigning)),
            "{what}"
        );
    }
}
