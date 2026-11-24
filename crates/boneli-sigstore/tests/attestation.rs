//! cosign `.att` attestations (ADR-036): the real flux-cli layers as known
//! answers, keyless under the public-good root, then one test per edge
//! case of the envelope reader over keyed envelopes signed with the test
//! signer of `support::pki`.

mod support;

use boneli_https::Sha256;
use boneli_json::Value;
use boneli_sigstore::{
    Accepted, BUNDLE_ANNOTATION, CERTIFICATE_ANNOTATION, COSIGN_SIGN_PREDICATE, ClaimMatch,
    ClaimRefusal, Claims, DSSE_ENVELOPE_MEDIA_TYPE, Evidence, IN_TOTO_PAYLOAD_TYPE,
    MAX_BUNDLE_BYTES, Material, PREDICATE_TYPE_ANNOTATION, Refusal, SIGNATURE_ANNOTATION,
    SLSA_PROVENANCE_V1_PREDICATE, SLSA_PROVENANCE_V02_PREDICATE, STATEMENT_V01, STATEMENT_V1,
    Trust, base64, verify,
};
use support::pki::{
    self, IMAGE, OTHER_IMAGE, Pki, hex, keyed_attestation_annotations, keyed_bundle,
    keyed_envelope, obj, remove, s, set, to_bytes,
};
use support::real;

// ---------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------

fn exact(text: &str) -> Option<ClaimMatch> {
    Some(ClaimMatch::Exact(text.to_owned()))
}

fn prefix(text: &str) -> Option<ClaimMatch> {
    Some(ClaimMatch::Prefix(text.to_owned()))
}

fn flux_material() -> Material {
    Material::new(real::FLUX_MATERIAL, "sha1", real::FLUX_COMMIT).expect("material")
}

/// The claims of the plan: the exact builder, the exact repository, the
/// ref prefix `refs/tags/` and the source commit.
fn flux_claims() -> Claims {
    Claims::new(
        Some(real::GENERATOR_V200),
        exact(real::FLUX_REPOSITORY),
        prefix("refs/tags/"),
        vec![flux_material()],
    )
    .expect("claims")
}

fn slsa(trust: Trust, claims: Claims) -> Trust {
    trust.with_claims(claims).expect("with claims")
}

fn flux_verify(trust: &Trust) -> Result<Accepted, Refusal> {
    verify(&real::flux(), &real::FLUX_DIGEST, trust)
}

const FLUX_ACCEPTED: Result<Accepted, Refusal> = Ok(Accepted::Keyless {
    integrated_time: real::FLUX_INTEGRATED,
    log_index: real::FLUX_LOG_INDEX,
    identity: 0,
});

const KEYED: Result<Accepted, Refusal> = Ok(Accepted::Keyed { key: 0 });

/// The real flux statement over the synthetic `IMAGE`, edited.
fn statement_with(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut st = real::flux_statement();
    set(
        &mut st,
        &["subject"],
        Value::Array(vec![obj(vec![
            ("name", s("registry.boneli.test/app")),
            ("digest", obj(vec![("sha256", s(&hex(&IMAGE)))])),
        ])]),
    );
    edit(&mut st);
    to_bytes(&st)
}

fn pairs(owned: &[(String, String)]) -> Vec<(&str, &str)> {
    owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// The keyed `.att` evidence of `envelope` with cosign's annotations.
fn keyed_evidence(envelope: &[u8]) -> Result<Evidence, Refusal> {
    let owned = keyed_attestation_annotations(SLSA_PROVENANCE_V02_PREDICATE);
    Evidence::from_cosign_attestation(&pairs(&owned), envelope)
}

/// A keyed trust in the test signer with `predicates` and the flux claims
/// with an exact ref.
fn keyed_claims(pki: &Pki, predicates: &[&str]) -> Trust {
    let claims = Claims::new(
        Some(real::GENERATOR_V200),
        exact(real::FLUX_REPOSITORY),
        exact(real::FLUX_REF),
        vec![flux_material()],
    )
    .expect("claims");
    slsa(pki::keyed_trust(pki, predicates), claims)
}

/// `statement` in a keyed envelope by the test signer, verified over
/// `IMAGE` under the keyed v0.2 trust with the flux claims.
fn keyed_verify(pki: &Pki, statement: &[u8]) -> Result<Accepted, Refusal> {
    let evidence = keyed_evidence(&to_bytes(&keyed_envelope(&pki.signer_key, statement)))?;
    verify(
        &evidence,
        &IMAGE,
        &keyed_claims(pki, &[SLSA_PROVENANCE_V02_PREDICATE]),
    )
}

/// The real flux envelope with `edit` applied to its JSON.
fn flux_envelope_with(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut envelope = real::json(real::FLUX_ENVELOPE);
    edit(&mut envelope);
    to_bytes(&envelope)
}

fn flux_annotations() -> Vec<(String, String)> {
    real::annotations(real::FLUX_ATT)
}

/// The real flux trust: the generator's exact SAN, v0.2 only, the plan's
/// claims.
fn flux_trust() -> Trust {
    slsa(
        real::slsa_v02_keyless(real::generator_identity()),
        flux_claims(),
    )
}

// ---------------------------------------------------------------------
// Known answers
// ---------------------------------------------------------------------

/// flux-cli v2.4.0's real `.att` (captured 2026-11-24) verifies against
/// the public-good root under the generator's exact SAN and under its tag
/// prefix, and meets the plan's claims. The manifest, envelope and index
/// digests are pinned.
#[test]
fn real_attestation_meets_its_claims() {
    assert_eq!(Sha256::digest(real::FLUX_ATT), real::FLUX_ATT_SHA256);
    assert_eq!(
        Sha256::digest(real::FLUX_ENVELOPE),
        real::FLUX_ENVELOPE_SHA256
    );
    assert_eq!(
        Sha256::digest(real::FLUX_273_ATT),
        real::FLUX_273_ATT_SHA256
    );
    assert_eq!(
        Sha256::digest(real::FLUX_273_ENVELOPE),
        real::FLUX_273_ENVELOPE_SHA256
    );
    assert_eq!(Sha256::digest(real::ARGOCD_ATT), real::ARGOCD_ATT_SHA256);
    assert_eq!(
        Sha256::digest(real::ARGOCD_ENVELOPE),
        real::ARGOCD_ENVELOPE_SHA256
    );
    // The layer of each manifest is the captured envelope.
    for (manifest, envelope) in [
        (real::FLUX_ATT, real::FLUX_ENVELOPE),
        (real::FLUX_273_ATT, real::FLUX_273_ENVELOPE),
        (real::ARGOCD_ATT, real::ARGOCD_ENVELOPE),
    ] {
        let manifest = real::json(manifest);
        let layer = &manifest
            .get("layers")
            .and_then(Value::as_array)
            .expect("layers")[0];
        assert_eq!(
            layer.get("mediaType").and_then(Value::as_str),
            Some(DSSE_ENVELOPE_MEDIA_TYPE)
        );
        assert_eq!(
            layer.get("digest").and_then(Value::as_str),
            Some(format!("sha256:{}", hex(&Sha256::digest(envelope))).as_str())
        );
    }
    assert_eq!(flux_verify(&flux_trust()), FLUX_ACCEPTED);
    let by_prefix = slsa(
        real::slsa_v02_keyless(real::generator_prefix_identity()),
        flux_claims(),
    );
    assert_eq!(flux_verify(&by_prefix), FLUX_ACCEPTED);
}

/// flux-cli v2.7.3, whose `invocation.parameters.vars` is a non-empty
/// object of strings, passes under D1 (b): `vars` is accepted unread.
#[test]
fn real_attestation_with_vars() {
    let statement = {
        let envelope = real::json(real::FLUX_273_ENVELOPE);
        let payload = envelope.get("payload").and_then(Value::as_str).expect("p");
        real::json(&base64::decode(payload.as_bytes()).expect("base64"))
    };
    let vars = statement
        .get("predicate")
        .and_then(|p| p.get("invocation"))
        .and_then(|i| i.get("parameters"))
        .and_then(|p| p.get("vars"))
        .and_then(Value::as_object)
        .expect("vars");
    assert!(!vars.is_empty());
    let claims = Claims::new(
        None,
        exact(real::FLUX_REPOSITORY),
        prefix("refs/tags/"),
        vec![Material::new(real::FLUX_273_MATERIAL, "sha1", real::FLUX_273_COMMIT).expect("m")],
    )
    .expect("claims");
    let trust = slsa(
        real::slsa_v02_keyless(real::generator_prefix_identity()),
        claims,
    );
    assert_eq!(
        verify(&real::flux_273(), &real::FLUX_273_DIGEST, &trust),
        Ok(Accepted::Keyless {
            integrated_time: real::FLUX_273_INTEGRATED,
            log_index: real::FLUX_273_LOG_INDEX,
            identity: 0
        })
    );
}

/// The issue's five negative fixtures over the real flux evidence, one
/// field of the rule changed each; another SAN and another digest.
#[test]
fn real_attestation_negative() {
    let other_builder = real::GENERATOR_V200.replace("v2.0.0", "v2.1.0");
    let cases: Vec<(Claims, ClaimRefusal)> = vec![
        (
            Claims::new(
                Some(&other_builder),
                exact(real::FLUX_REPOSITORY),
                prefix("refs/tags/"),
                vec![flux_material()],
            )
            .expect("claims"),
            ClaimRefusal::BuilderId,
        ),
        (
            Claims::new(
                Some(real::GENERATOR_V200),
                exact("https://github.com/fluxcd/other"),
                prefix("refs/tags/"),
                vec![flux_material()],
            )
            .expect("claims"),
            ClaimRefusal::SourceRepository,
        ),
        (
            Claims::new(
                Some(real::GENERATOR_V200),
                exact(real::FLUX_REPOSITORY),
                exact("refs/tags/v2.4.1"),
                vec![flux_material()],
            )
            .expect("claims"),
            ClaimRefusal::SourceRef,
        ),
        (
            Claims::new(
                Some(real::GENERATOR_V200),
                exact(real::FLUX_REPOSITORY),
                prefix("refs/tags/"),
                vec![
                    Material::new(
                        "git+https://github.com/fluxcd/flux2@refs/tags/v2.4.1",
                        "sha1",
                        real::FLUX_COMMIT,
                    )
                    .expect("material"),
                ],
            )
            .expect("claims"),
            ClaimRefusal::MaterialMissing(0),
        ),
        (
            Claims::new(
                Some(real::GENERATOR_V200),
                exact(real::FLUX_REPOSITORY),
                prefix("refs/tags/"),
                vec![
                    Material::new(
                        real::FLUX_MATERIAL,
                        "sha1",
                        "0000000000000000000000000000000000000000",
                    )
                    .expect("material"),
                ],
            )
            .expect("claims"),
            ClaimRefusal::MaterialDigest(0),
        ),
    ];
    for (claims, refusal) in cases {
        let trust = slsa(real::slsa_v02_keyless(real::generator_identity()), claims);
        assert_eq!(flux_verify(&trust), Err(Refusal::Claim(refusal)));
    }
    let other_san = boneli_sigstore::Identity::new(
        real::GITHUB_ACTIONS,
        boneli_sigstore::SanRule::Uri(
            "https://github.com/fluxcd/flux2/.github/workflows/release.yaml@refs/tags/v2.4.0"
                .to_owned(),
        ),
    )
    .expect("identity");
    let trust = slsa(real::slsa_v02_keyless(other_san), flux_claims());
    assert_eq!(flux_verify(&trust), Err(Refusal::IdentityMismatch));
    assert_eq!(
        verify(&real::flux(), &real::FLUX_273_DIGEST, &flux_trust()),
        Err(Refusal::SubjectMismatch)
    );
}

/// argocd v2.10.0's `.att` is logged as a Rekor `intoto` 0.0.1 entry,
/// which this crate does not read (D3): refused with `EntryKind`.
#[test]
fn real_intoto_entry_refused() {
    let claims = Claims::new(None, exact(real::ARGOCD_REPOSITORY), None, vec![]).expect("c");
    let trust = slsa(
        real::slsa_v02_keyless(real::generator_prefix_identity()),
        claims,
    );
    assert_eq!(
        verify(&real::argocd(), &real::ARGOCD_DIGEST, &trust),
        Err(Refusal::EntryKind)
    );
}

/// Under a trust without claims an attestation counts for nothing, keyed
/// or keyless, whatever its predicate list: `AttestationNeedsClaims`
/// before any other check, so a warm verdict equals the cold one.
#[test]
fn attestation_needs_claims() {
    let pki = Pki::new();
    let keyless = real::slsa_v02_keyless(real::generator_identity());
    assert_eq!(flux_verify(&keyless), Err(Refusal::AttestationNeedsClaims));
    // Even over another digest: the check comes first.
    assert_eq!(
        verify(&real::flux(), &OTHER_IMAGE, &keyless),
        Err(Refusal::AttestationNeedsClaims)
    );
    let envelope = to_bytes(&keyed_envelope(&pki.signer_key, &statement_with(|_| {})));
    let evidence = keyed_evidence(&envelope).expect("evidence");
    for list in [
        &[SLSA_PROVENANCE_V02_PREDICATE][..],
        &[SLSA_PROVENANCE_V1_PREDICATE, SLSA_PROVENANCE_V02_PREDICATE],
        &[COSIGN_SIGN_PREDICATE],
        &[],
    ] {
        assert_eq!(
            verify(&evidence, &IMAGE, &pki::keyed_trust(&pki, list)),
            Err(Refusal::AttestationNeedsClaims),
            "{list:?}"
        );
    }
    // The same envelope under claims passes.
    assert_eq!(
        verify(
            &evidence,
            &IMAGE,
            &keyed_claims(&pki, &[SLSA_PROVENANCE_V02_PREDICATE])
        ),
        KEYED
    );
}

// ---------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------

/// Flip one byte of the base64 text at `at` to another alphabet letter.
fn flip(text: &str, at: usize) -> String {
    let mut bytes = text.as_bytes().to_vec();
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).expect("ASCII")
}

#[test]
fn failing_envelope_refused() {
    let pki = Pki::new();
    let statement = statement_with(|_| {});
    let good = keyed_envelope(&pki.signer_key, &statement);
    assert_eq!(keyed_verify(&pki, &statement), KEYED);
    let trust = keyed_claims(&pki, &[SLSA_PROVENANCE_V02_PREDICATE]);
    let keyed_check = |envelope: &Value| {
        keyed_evidence(&to_bytes(envelope)).and_then(|e| verify(&e, &IMAGE, &trust))
    };

    // A flipped signature byte, a changed payload byte.
    let sig = good
        .get("signatures")
        .and_then(Value::as_array)
        .and_then(|a| a[0].get("sig"))
        .and_then(Value::as_str)
        .expect("sig")
        .to_owned();
    let mut flipped = good.clone();
    set(
        &mut flipped,
        &["signatures"],
        Value::Array(vec![obj(vec![
            ("keyid", s("")),
            ("sig", s(&flip(&sig, 10))),
        ])]),
    );
    assert_eq!(keyed_check(&flipped), Err(Refusal::NoTrustedKey));
    let changed = statement_with(|st| {
        set(
            st,
            &["predicate", "metadata", "buildInvocationID"],
            s("11110350185-2"),
        )
    });
    let mut swapped = good.clone();
    set(&mut swapped, &["payload"], s(&base64::encode(&changed)));
    assert_eq!(keyed_check(&swapped), Err(Refusal::NoTrustedKey));

    // The same on the real keyless evidence: the Rekor body no longer
    // matches the signature or the payload, the first failing check.
    let annotations = flux_annotations();
    let keyless_check = |envelope: &[u8]| {
        Evidence::from_cosign_attestation(&pairs(&annotations), envelope)
            .and_then(|e| verify(&e, &real::FLUX_DIGEST, &flux_trust()))
    };
    let real_sig = real::json(real::FLUX_ENVELOPE)
        .get("signatures")
        .and_then(Value::as_array)
        .and_then(|a| a[0].get("sig"))
        .and_then(Value::as_str)
        .expect("sig")
        .to_owned();
    let flipped = flux_envelope_with(|e| {
        set(
            e,
            &["signatures"],
            Value::Array(vec![obj(vec![
                ("keyid", s("")),
                ("sig", s(&flip(&real_sig, 20))),
            ])]),
        )
    });
    assert_eq!(keyless_check(&flipped), Err(Refusal::BodyMismatch));
    let mut real_statement = real::flux_statement();
    set(
        &mut real_statement,
        &["predicate", "metadata", "buildInvocationID"],
        s("11110350185-2"),
    );
    let changed = flux_envelope_with(|e| {
        set(
            e,
            &["payload"],
            s(&base64::encode(&to_bytes(&real_statement))),
        )
    });
    assert_eq!(keyless_check(&changed), Err(Refusal::BodyMismatch));

    // Shapes.
    for payload_type in [
        "application/vnd.in-toto+json ",
        "application/vnd.in-toto+json; charset=utf-8",
        "Application/vnd.in-toto+json",
        "application/vnd.dev.cosign.simplesigning.v1+json",
        "",
    ] {
        let mut e = good.clone();
        set(&mut e, &["payloadType"], s(payload_type));
        assert_eq!(
            keyed_check(&e).err(),
            Some(Refusal::DsseShape),
            "{payload_type:?}"
        );
    }
    let one = good
        .get("signatures")
        .and_then(Value::as_array)
        .expect("signatures")[0]
        .clone();
    for count in [0, 2] {
        let mut e = good.clone();
        set(
            &mut e,
            &["signatures"],
            Value::Array(vec![one.clone(); count]),
        );
        assert_eq!(keyed_check(&e).err(), Some(Refusal::DsseShape), "{count}");
    }
    let payload_b64 = base64::encode(&statement);
    let unpadded = payload_b64.trim_end_matches('=').to_owned();
    let mut malformed: Vec<Value> = Vec::new();
    for bad in [
        format!("{payload_b64}\n"),
        format!(" {payload_b64}"),
        format!("{payload_b64}AAAA="),
    ] {
        let mut e = good.clone();
        set(&mut e, &["payload"], s(&bad));
        malformed.push(e);
    }
    if unpadded != payload_b64 {
        let mut e = good.clone();
        set(&mut e, &["payload"], s(&unpadded));
        malformed.push(e);
    }
    for member in ["payload", "payloadType", "signatures"] {
        let mut e = good.clone();
        remove(&mut e, &[member]);
        malformed.push(e);
        let mut e = good.clone();
        set(&mut e, &[member], Value::Number(7u64.into()));
        malformed.push(e);
    }
    for e in &malformed {
        assert_eq!(
            keyed_check(e).err(),
            Some(Refusal::MalformedEnvelope),
            "{e:?}"
        );
    }
    for bad in [
        b"not JSON".to_vec(),
        b"[]".to_vec(),
        b"\"x\"".to_vec(),
        // A member twice: boneli-json refuses the document.
        {
            let text = String::from_utf8(to_bytes(&good)).expect("utf-8");
            text.replacen(
                "{\"payload\"",
                &format!("{{\"payloadType\":\"{IN_TOTO_PAYLOAD_TYPE}\",\"payload\""),
                1,
            )
            .into_bytes()
        },
    ] {
        assert_eq!(
            keyed_evidence(&bad).err(),
            Some(Refusal::MalformedEnvelope),
            "{:?}",
            String::from_utf8_lossy(&bad)
        );
    }
    // A signature that is not canonical base64.
    for bad_sig in [format!("{sig}\n"), format!(" {sig}"), format!("{sig}AAAA=")] {
        let mut e = good.clone();
        set(
            &mut e,
            &["signatures"],
            Value::Array(vec![obj(vec![("keyid", s("")), ("sig", s(&bad_sig))])]),
        );
        assert_eq!(
            keyed_check(&e).err(),
            Some(Refusal::MalformedSignature),
            "{bad_sig:?}"
        );
    }
    let mut e = good.clone();
    set(
        &mut e,
        &["signatures"],
        Value::Array(vec![obj(vec![("keyid", s(""))])]),
    );
    assert_eq!(keyed_check(&e).err(), Some(Refusal::MalformedSignature));

    // The size cap: one byte over refuses before the JSON step; at the cap
    // the JSON step decides.
    let over = vec![b' '; MAX_BUNDLE_BYTES + 1];
    assert_eq!(keyed_evidence(&over).err(), Some(Refusal::EnvelopeTooLarge));
    let at = vec![b' '; MAX_BUNDLE_BYTES];
    assert_eq!(keyed_evidence(&at).err(), Some(Refusal::MalformedEnvelope));
    // A valid envelope padded to exactly the cap is read.
    let mut padded = to_bytes(&good);
    padded.resize(MAX_BUNDLE_BYTES, b' ');
    assert_eq!(
        keyed_evidence(&padded).and_then(|e| verify(&e, &IMAGE, &trust)),
        KEYED
    );
}

/// The annotations: an empty certificate means keyed, a garbage one or a
/// garbage Rekor entry refuses, a key the reader uses twice refuses; the
/// signature, chain and `predicateType` annotations and `keyid` are never
/// read, and the statement's predicate type is what counts.
#[test]
fn attestation_annotations() {
    let pki = Pki::new();
    let statement = statement_with(|_| {});
    let envelope = to_bytes(&keyed_envelope(&pki.signer_key, &statement));
    let trust = keyed_claims(&pki, &[SLSA_PROVENANCE_V02_PREDICATE]);
    let check = |owned: &[(String, String)], envelope: &[u8]| {
        Evidence::from_cosign_attestation(&pairs(owned), envelope)
            .and_then(|e| verify(&e, &IMAGE, &trust))
    };
    let keyed = keyed_attestation_annotations(SLSA_PROVENANCE_V02_PREDICATE);
    assert_eq!(check(&keyed, &envelope), KEYED);
    assert_eq!(check(&[], &envelope), KEYED);
    let empty_cert = real::with(&keyed, CERTIFICATE_ANNOTATION, "");
    assert_eq!(check(&empty_cert, &envelope), KEYED);
    assert!(
        !Evidence::from_cosign_attestation(&pairs(&empty_cert), &envelope)
            .expect("evidence")
            .is_keyless()
    );
    let garbage_cert = real::with(
        &keyed,
        CERTIFICATE_ANNOTATION,
        "-----BEGIN CERTIFICATE-----",
    );
    assert_eq!(
        check(&garbage_cert, &envelope),
        Err(Refusal::MalformedCertificate)
    );
    let garbage_entry = real::with(&keyed, BUNDLE_ANNOTATION, "{}");
    assert_eq!(
        check(&garbage_entry, &envelope),
        Err(Refusal::MalformedTlogEntry)
    );
    for key in [CERTIFICATE_ANNOTATION, BUNDLE_ANNOTATION] {
        let mut twice = flux_annotations();
        let value = twice
            .iter()
            .find(|(k, _)| k == key)
            .expect("annotation")
            .1
            .clone();
        twice.push((key.to_owned(), value));
        assert_eq!(
            Evidence::from_cosign_attestation(&pairs(&twice), real::FLUX_ENVELOPE).err(),
            Some(Refusal::MalformedAnnotations),
            "{key}"
        );
    }
    // Junk in what is never read changes no verdict, keyed or keyless.
    let mut junk = real::with(&keyed, SIGNATURE_ANNOTATION, "junk!");
    junk.push((SIGNATURE_ANNOTATION.to_owned(), "twice".to_owned()));
    junk = real::with(&junk, "dev.sigstore.cosign/chain", "junk");
    junk = real::with(&junk, PREDICATE_TYPE_ANNOTATION, COSIGN_SIGN_PREDICATE);
    junk.push((PREDICATE_TYPE_ANNOTATION.to_owned(), "twice".to_owned()));
    assert_eq!(check(&junk, &envelope), KEYED);
    let mut junk_keyid = keyed_envelope(&pki.signer_key, &statement);
    let sig = junk_keyid
        .get("signatures")
        .and_then(Value::as_array)
        .and_then(|a| a[0].get("sig"))
        .cloned()
        .expect("sig");
    set(
        &mut junk_keyid,
        &["signatures"],
        Value::Array(vec![obj(vec![
            ("keyid", Value::Number(5u64.into())),
            ("sig", sig),
        ])]),
    );
    assert_eq!(check(&keyed, &to_bytes(&junk_keyid)), KEYED);
    let mut real_junk = flux_annotations();
    real_junk = real::with(&real_junk, SIGNATURE_ANNOTATION, "junk!");
    real_junk = real::with(&real_junk, "dev.sigstore.cosign/chain", "junk");
    real_junk = real::with(&real_junk, PREDICATE_TYPE_ANNOTATION, COSIGN_SIGN_PREDICATE);
    assert_eq!(
        Evidence::from_cosign_attestation(&pairs(&real_junk), real::FLUX_ENVELOPE)
            .and_then(|e| verify(&e, &real::FLUX_DIGEST, &flux_trust())),
        FLUX_ACCEPTED
    );

    // The statement decides the predicate type: a look-alike there is
    // refused whatever the annotation says, and so is a lying annotation
    // over a cosign/sign/v1 statement.
    for look_alike in [
        "https://slsa.dev/provenance/v0.2 ",
        "https://slsa.dev/provenance/V0.2",
        "https://slsa.dev/provenance/v0.2/",
        "https://slsa.dev/provenance/v0.1",
    ] {
        let st = statement_with(|st| set(st, &["predicateType"], s(look_alike)));
        let envelope = to_bytes(&keyed_envelope(&pki.signer_key, &st));
        assert_eq!(
            check(&keyed, &envelope),
            Err(Refusal::PredicateType),
            "{look_alike:?}"
        );
    }
    let st = pki::statement(&[&hex(&IMAGE)], COSIGN_SIGN_PREDICATE);
    let envelope = to_bytes(&keyed_envelope(&pki.signer_key, &st));
    assert_eq!(check(&keyed, &envelope), Err(Refusal::PredicateType));
}

/// Statement v0.1 and v1 are admitted in an attestation; another `_type`
/// is `StatementType`; a bundle still admits v1 only.
#[test]
fn attestation_statement_types() {
    let pki = Pki::new();
    for kind in [STATEMENT_V01, STATEMENT_V1] {
        let st = statement_with(|st| set(st, &["_type"], s(kind)));
        assert_eq!(keyed_verify(&pki, &st), KEYED, "{kind}");
    }
    for kind in [
        "https://in-toto.io/Statement/v0.2",
        "https://in-toto.io/Statement/v0.1 ",
        "https://in-toto.io/Statement/V0.1",
        "",
    ] {
        let st = statement_with(|st| set(st, &["_type"], s(kind)));
        assert_eq!(
            keyed_verify(&pki, &st),
            Err(Refusal::StatementType),
            "{kind:?}"
        );
    }
    let st = statement_with(|st| remove(st, &["_type"]));
    assert_eq!(keyed_verify(&pki, &st), Err(Refusal::StatementType));
    // A member twice in the statement: boneli-json refuses it.
    let text = String::from_utf8(statement_with(|_| {})).expect("utf-8");
    let twice = text.replacen(
        "{\"_type\"",
        &format!("{{\"predicateType\":\"{COSIGN_SIGN_PREDICATE}\",\"_type\""),
        1,
    );
    assert_ne!(twice, text);
    assert_eq!(
        keyed_verify(&pki, twice.as_bytes()),
        Err(Refusal::MalformedStatement)
    );
    // A bundle with Statement v0.1 is still refused (ADR-029 S5).
    let st = statement_with(|st| set(st, &["_type"], s(STATEMENT_V01)));
    assert_eq!(
        Evidence::from_bundle(&to_bytes(&keyed_bundle(&pki.signer_key, &st))).err(),
        Some(Refusal::StatementType)
    );
}

/// Every strict prefix of the real envelope is refused, never a panic.
#[test]
fn truncated_attestation_never_panics() {
    let annotations = flux_annotations();
    let envelope = real::FLUX_ENVELOPE;
    for n in 0..envelope.len() {
        assert!(
            Evidence::from_cosign_attestation(&pairs(&annotations), &envelope[..n]).is_err(),
            "prefix {n}"
        );
    }
}

/// `Debug` names the form and whether it is keyless, never the content.
#[test]
fn attestation_debug_shows_no_content() {
    let text = format!("{:?}", real::flux());
    assert_eq!(
        text, "Evidence { form: \"attestation\", keyless: true }",
        "{text}"
    );
    let pki = Pki::new();
    let envelope = to_bytes(&keyed_envelope(&pki.signer_key, &statement_with(|_| {})));
    let text = format!("{:?}", keyed_evidence(&envelope).expect("evidence"));
    assert_eq!(text, "Evidence { form: \"attestation\", keyless: false }");
    assert!(real::flux().is_keyless());
}

/// Every new refusal and configuration text is pinned.
#[test]
fn attestation_texts() {
    for (refusal, text) in [
        (Refusal::EnvelopeTooLarge, "the DSSE envelope is too large"),
        (Refusal::MalformedEnvelope, "the DSSE envelope is malformed"),
        (
            Refusal::AttestationNeedsClaims,
            "a cosign attestation counts only under a rule with provenance claims",
        ),
        (
            Refusal::WorkflowInputs,
            "the provenance records workflow inputs, which can change what was built",
        ),
        (
            Refusal::StatementType,
            "the payload is not an in-toto statement of an accepted type",
        ),
    ] {
        assert_eq!(refusal.to_string(), text);
    }
    assert_eq!(
        boneli_sigstore::ConfigError::ClaimsWithoutSource.to_string(),
        "a trust that lists SLSA provenance v0.2 needs an exact source repository, or a repository prefix or material that names an owner"
    );
}
