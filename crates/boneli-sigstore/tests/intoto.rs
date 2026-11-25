//! Rekor `intoto` 0.0.1 entries for cosign `.att` layers (ADR-037): the
//! real argocd and kyverno layers as known answers under the public-good
//! root, then one test per edge case of the body check over keyless
//! attestations of the synthetic instance of `support::pki`.

mod support;

use boneli_https::Sha256;
use boneli_json::Value;
use boneli_sigstore::{
    Accepted, BUNDLE_ANNOTATION, CERTIFICATE_ANNOTATION, CertificateClaims, CertificateRefusal,
    ClaimMatch, Claims, Evidence, Extension, Identity, Material, Refusal,
    SLSA_PROVENANCE_V02_PREDICATE, SanRule, Trust, base64, verify,
};
use support::pki::{
    self, AttestationSpec, BundleSpec, CosignLayer, EntrySpec, IMAGE, ISSUER, LeafSpec, Pki, URI,
    envelope_value, hashedrekord, hex, keyed_attestation_annotations, keyed_envelope, obj, remove,
    s, set, to_bytes,
};
use support::real;

// ---------------------------------------------------------------------
// Rules and helpers
// ---------------------------------------------------------------------

fn exact(text: &str) -> Option<ClaimMatch> {
    Some(ClaimMatch::Exact(text.to_owned()))
}

fn prefix(text: &str) -> Option<ClaimMatch> {
    Some(ClaimMatch::Prefix(text.to_owned()))
}

fn pairs(owned: &[(String, String)]) -> Vec<(&str, &str)> {
    owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// One real `intoto` capture with what its rule names.
struct Real {
    att: &'static [u8],
    envelope: &'static [u8],
    digest: [u8; 32],
    repository: &'static str,
    git_ref: &'static str,
    material: &'static str,
    commit: &'static str,
    accepted: Accepted,
}

const ARGOCD: Real = Real {
    att: real::ARGOCD_ATT,
    envelope: real::ARGOCD_ENVELOPE,
    digest: real::ARGOCD_DIGEST,
    repository: real::ARGOCD_REPOSITORY,
    git_ref: real::ARGOCD_REF,
    material: real::ARGOCD_MATERIAL,
    commit: real::ARGOCD_COMMIT,
    accepted: Accepted::Keyless {
        integrated_time: Some(1_707_230_840),
        signed_timestamps: 0,
        log_index: 69_491_963,
        identity: 0,
    },
};

const KYVERNO: Real = Real {
    att: real::KYVERNO_ATT,
    envelope: real::KYVERNO_ENVELOPE,
    digest: real::KYVERNO_DIGEST,
    repository: real::KYVERNO_REPOSITORY,
    git_ref: real::KYVERNO_REF,
    material: real::KYVERNO_MATERIAL,
    commit: real::KYVERNO_COMMIT,
    accepted: Accepted::Keyless {
        integrated_time: Some(1_699_611_421),
        signed_timestamps: 0,
        log_index: 48_852_930,
        identity: 0,
    },
};

impl Real {
    /// The exact builder, repository, ref and material of the capture.
    fn claims(&self) -> Claims {
        Claims::new(
            Some(real::GENERATOR_V190),
            exact(self.repository),
            exact(self.git_ref),
            vec![Material::new(self.material, "sha1", self.commit).expect("material")],
        )
        .expect("claims")
    }

    fn trust(&self, identity: Identity) -> Trust {
        real::slsa_v02_keyless(identity)
            .with_claims(self.claims())
            .expect("with claims")
    }

    fn annotations(&self) -> Vec<(String, String)> {
        real::annotations(self.att)
    }

    /// The verdict over `envelope` with `annotations`, under the exact
    /// generator SAN and the capture's claims.
    fn verify_with(
        &self,
        annotations: &[(String, String)],
        envelope: &[u8],
    ) -> Result<Accepted, Refusal> {
        let evidence = Evidence::from_cosign_attestation(&pairs(annotations), envelope)?;
        verify(
            &evidence,
            &self.digest,
            &self.trust(real::generator_v190_identity()),
        )
    }

    /// The Rekor body the capture's bundle annotation carries.
    fn body(&self) -> (Vec<u8>, Value) {
        let annotations = self.annotations();
        let text = &annotations
            .iter()
            .find(|(k, _)| k == BUNDLE_ANNOTATION)
            .expect("bundle")
            .1;
        let entry = real::json(text.as_bytes());
        let body = entry
            .get("Payload")
            .and_then(|p| p.get("body"))
            .and_then(Value::as_str)
            .expect("body");
        let bytes = base64::decode(body.as_bytes()).expect("base64");
        let value = real::json(&bytes);
        (bytes, value)
    }

    fn certificate(&self) -> String {
        self.annotations()
            .into_iter()
            .find(|(k, _)| k == CERTIFICATE_ANNOTATION)
            .expect("certificate")
            .1
    }
}

fn keys(value: &Value) -> Vec<&str> {
    value.as_object().expect("object").keys().collect()
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    let mut at = value;
    for key in path {
        at = at.get(key).expect(key);
    }
    at.as_str().expect("string")
}

/// The flux statement over the synthetic `IMAGE`.
fn statement() -> Vec<u8> {
    let mut st = real::flux_statement();
    set(
        &mut st,
        &["subject"],
        Value::Array(vec![obj(vec![
            ("name", s("registry.boneli.test/app")),
            ("digest", obj(vec![("sha256", s(&hex(&IMAGE)))])),
        ])]),
    );
    to_bytes(&st)
}

/// The flux claims of ADR-036's plan, over the synthetic statement.
fn flux_claims() -> Claims {
    Claims::new(
        Some(real::GENERATOR_V200),
        exact(real::FLUX_REPOSITORY),
        prefix("refs/tags/"),
        vec![Material::new(real::FLUX_MATERIAL, "sha1", real::FLUX_COMMIT).expect("material")],
    )
    .expect("claims")
}

fn uri_identity() -> Identity {
    Identity::new(ISSUER, SanRule::Uri(URI.to_owned())).expect("identity")
}

/// A keyless trust in the test root for the URI leaf, v0.2 only, with the
/// flux claims.
fn synthetic_trust(pki: &Pki) -> Trust {
    Trust::new(
        Vec::new(),
        Some((
            pki::trusted_root(&pki::root_value(pki)),
            vec![uri_identity()],
        )),
        vec![SLSA_PROVENANCE_V02_PREDICATE.to_owned()],
    )
    .expect("trust")
    .with_claims(flux_claims())
    .expect("with claims")
}

fn spec(pki: &Pki) -> AttestationSpec {
    AttestationSpec::keyless(pki, &LeafSpec::uri(URI), statement())
}

fn synthetic_verify(pki: &Pki, spec: &AttestationSpec) -> Result<Accepted, Refusal> {
    verify(&spec.evidence(pki)?, &IMAGE, &synthetic_trust(pki))
}

const SYNTHETIC: Result<Accepted, Refusal> = Ok(Accepted::Keyless {
    integrated_time: Some(pki::INTEGRATED),
    signed_timestamps: 0,
    log_index: pki::LOG_INDEX,
    identity: 0,
});

// ---------------------------------------------------------------------
// Known answers
// ---------------------------------------------------------------------

/// The facts of ADR-037's context, read from the captures: an `intoto`
/// 0.0.1 body of exactly `kind`, `apiVersion`, `spec.content.hash`,
/// `spec.content.payloadHash` and `spec.publicKey`; the content hash is the
/// layer digest and the SHA-256 of the envelope bytes; `payloadHash` is the
/// SHA-256 of the decoded payload, not of its base64 text; `publicKey` is
/// the certificate annotation byte for byte.
#[test]
fn real_intoto_entries_as_measured() {
    assert_eq!(Sha256::digest(real::ARGOCD_ATT), real::ARGOCD_ATT_SHA256);
    assert_eq!(
        Sha256::digest(real::ARGOCD_ENVELOPE),
        real::ARGOCD_ENVELOPE_SHA256
    );
    assert_eq!(Sha256::digest(real::KYVERNO_ATT), real::KYVERNO_ATT_SHA256);
    assert_eq!(
        Sha256::digest(real::KYVERNO_ENVELOPE),
        real::KYVERNO_ENVELOPE_SHA256
    );
    for (capture, length) in [(&ARGOCD, 3_615), (&KYVERNO, 3_583)] {
        let (bytes, body) = capture.body();
        assert_eq!(bytes.len(), length);
        assert_eq!(keys(&body), ["apiVersion", "kind", "spec"]);
        assert_eq!(str_at(&body, &["kind"]), "intoto");
        assert_eq!(str_at(&body, &["apiVersion"]), "0.0.1");
        let spec = body.get("spec").expect("spec");
        assert_eq!(keys(spec), ["content", "publicKey"]);
        assert_eq!(
            keys(spec.get("content").expect("content")),
            ["hash", "payloadHash"]
        );
        let envelope_hex = hex(&Sha256::digest(capture.envelope));
        assert_eq!(str_at(spec, &["content", "hash", "algorithm"]), "sha256");
        assert_eq!(str_at(spec, &["content", "hash", "value"]), envelope_hex);
        let manifest = real::json(capture.att);
        let layer = &manifest
            .get("layers")
            .and_then(Value::as_array)
            .expect("layers")[0];
        assert_eq!(
            layer.get("digest").and_then(Value::as_str),
            Some(format!("sha256:{envelope_hex}").as_str())
        );
        let envelope = real::json(capture.envelope);
        let payload_text = str_at(&envelope, &["payload"]);
        let payload = base64::decode(payload_text.as_bytes()).expect("base64");
        assert_eq!(
            str_at(spec, &["content", "payloadHash", "algorithm"]),
            "sha256"
        );
        assert_eq!(
            str_at(spec, &["content", "payloadHash", "value"]),
            hex(&Sha256::digest(&payload))
        );
        assert_ne!(
            str_at(spec, &["content", "payloadHash", "value"]),
            hex(&Sha256::digest(payload_text.as_bytes()))
        );
        let public_key = base64::decode(str_at(spec, &["publicKey"]).as_bytes()).expect("b64");
        assert_eq!(public_key, capture.certificate().as_bytes());
    }
}

/// Both real `intoto` attestations pass under the generator's exact v1.9.0
/// SAN and under its tag prefix, with an exact builder, repository, ref and
/// material claim. Both integrated times equal their leaf's notBefore, so
/// they pin webpki's inclusive bound.
#[test]
fn real_intoto_attestations_verify() {
    assert_eq!(
        ARGOCD.accepted,
        Accepted::Keyless {
            integrated_time: Some(real::ARGOCD_INTEGRATED),
            signed_timestamps: 0,
            log_index: real::ARGOCD_LOG_INDEX,
            identity: 0
        }
    );
    assert_eq!(
        KYVERNO.accepted,
        Accepted::Keyless {
            integrated_time: Some(real::KYVERNO_INTEGRATED),
            signed_timestamps: 0,
            log_index: real::KYVERNO_LOG_INDEX,
            identity: 0
        }
    );
    for (capture, evidence) in [(&ARGOCD, real::argocd()), (&KYVERNO, real::kyverno())] {
        for identity in [
            real::generator_v190_identity(),
            real::generator_prefix_identity(),
        ] {
            assert_eq!(
                verify(&evidence, &capture.digest, &capture.trust(identity)),
                Ok(capture.accepted)
            );
        }
    }
}

/// Replaces the first `from` in `bytes` with `to`.
fn replace_once(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = bytes
        .windows(from.len())
        .position(|w| w == from)
        .expect("present");
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(to);
    out.extend_from_slice(&bytes[at + from.len()..]);
    out
}

/// Every other byte string for a real envelope, kept under its real SET,
/// is `BodyMismatch`: the same JSON in other bytes, a flipped signature,
/// an edited statement, and certificates or envelopes swapped between the
/// two captures. The body check runs before the signature and the chain.
#[test]
fn real_intoto_envelope_bytes_bound() {
    for capture in [&ARGOCD, &KYVERNO] {
        let annotations = capture.annotations();
        assert_eq!(
            capture.verify_with(&annotations, capture.envelope),
            Ok(capture.accepted)
        );
        let value = real::json(capture.envelope);
        let reordered = to_bytes(&obj(vec![
            ("payload", value.get("payload").expect("payload").clone()),
            (
                "payloadType",
                value.get("payloadType").expect("type").clone(),
            ),
            (
                "signatures",
                value.get("signatures").expect("signatures").clone(),
            ),
        ]));
        assert_ne!(reordered, capture.envelope);
        let mut trailing = capture.envelope.to_vec();
        trailing.push(b'\n');
        let mut spaced = b"{ ".to_vec();
        spaced.extend_from_slice(&capture.envelope[1..]);
        // One signature character flipped, still canonical base64.
        let sig = str_at(
            &value
                .get("signatures")
                .and_then(Value::as_array)
                .expect("signatures")[0],
            &["sig"],
        );
        let mut flipped = sig.as_bytes().to_vec();
        flipped[10] = if flipped[10] == b'A' { b'B' } else { b'A' };
        let flipped = replace_once(capture.envelope, sig.as_bytes(), &flipped);
        // One statement field edited: the source commit.
        let payload_text = str_at(&value, &["payload"]);
        let payload = base64::decode(payload_text.as_bytes()).expect("base64");
        let edited = replace_once(&payload, capture.commit.as_bytes(), &[b'0'; 40]);
        let edited = replace_once(
            capture.envelope,
            payload_text.as_bytes(),
            base64::encode(&edited).as_bytes(),
        );
        for (i, envelope) in [reordered, trailing, spaced, flipped, edited]
            .iter()
            .enumerate()
        {
            assert_eq!(
                capture.verify_with(&annotations, envelope),
                Err(Refusal::BodyMismatch),
                "change {i}"
            );
        }
    }
    // The certificate annotations swapped: the body's `publicKey` no
    // longer names the leaf. Without that check kyverno's leaf would fail
    // the chain at argocd's time (it expired 7,618,819 s before).
    let swapped =
        |a: &Real, b: &Real| real::with(&a.annotations(), CERTIFICATE_ANNOTATION, &b.certificate());
    assert_eq!(
        ARGOCD.verify_with(&swapped(&ARGOCD, &KYVERNO), ARGOCD.envelope),
        Err(Refusal::BodyMismatch)
    );
    assert_eq!(
        KYVERNO.verify_with(&swapped(&KYVERNO, &ARGOCD), KYVERNO.envelope),
        Err(Refusal::BodyMismatch)
    );
    // argocd's annotations (its entry and leaf) over kyverno's envelope.
    assert_eq!(
        KYVERNO.verify_with(&ARGOCD.annotations(), KYVERNO.envelope),
        Err(Refusal::BodyMismatch)
    );
}

/// Fulcio certificate claims (ADR-034) apply to an `intoto`-logged leaf as
/// to every keyless carrier: argocd's leaf names its repository, its tag
/// ref, its release workflow and `push`. Another trigger is refused by the
/// leaf; the statement agreement is GitHub's v1 build type only.
#[test]
fn real_intoto_under_certificate_claims() {
    let certificate = |trigger: &str| {
        CertificateClaims::new(
            exact(real::ARGOCD_REPOSITORY),
            prefix("refs/tags/"),
            vec![trigger.to_owned()],
        )
        .expect("certificate claims")
        .with_workflow_path(".github/workflows/release.yaml")
        .expect("workflow path")
    };
    let with = |claims: CertificateClaims| {
        ARGOCD
            .trust(real::generator_v190_identity())
            .with_certificate_claims(claims)
            .expect("with certificate claims")
    };
    let evidence = real::argocd();
    assert_eq!(
        verify(&evidence, &ARGOCD.digest, &with(certificate("push"))),
        Ok(ARGOCD.accepted)
    );
    assert_eq!(
        verify(
            &evidence,
            &ARGOCD.digest,
            &with(certificate("workflow_dispatch"))
        ),
        Err(Refusal::CertificateClaim(CertificateRefusal::Mismatch(
            Extension::BuildTrigger
        )))
    );
    assert_eq!(
        verify(
            &evidence,
            &ARGOCD.digest,
            &with(certificate("push").with_statement_agreement())
        ),
        Err(Refusal::UnknownBuildType)
    );
}

// ---------------------------------------------------------------------
// The body check
// ---------------------------------------------------------------------

/// A `PUBLIC KEY` PEM in Go's form.
fn public_key_pem(spki: &[u8]) -> String {
    pki::pem(spki).replace("CERTIFICATE", "PUBLIC KEY")
}

/// The synthetic `intoto` body: correct passes, every edit refuses with
/// its named refusal, and an extra `content.envelope` is not read.
#[test]
fn intoto_body_checks() {
    let pki = Pki::new();
    let base = spec(&pki);
    assert_eq!(synthetic_verify(&pki, &base), SYNTHETIC);
    let good = base.intoto_body();
    let envelope_hex = hex(&Sha256::digest(&base.envelope));
    let pem_text = pki::pem(&base.certificate);
    let b64 = |text: &str| s(&base64::encode(text.as_bytes()));
    let other_leaf = LeafSpec {
        serial: 9,
        ..LeafSpec::uri(URI)
    }
    .build(&pki);
    let payload_text = base64::encode(&base.statement);
    // Non-canonical: a line break inside the base64 (Go's decoder skips it).
    let broken = {
        let text = base64::encode(pem_text.as_bytes());
        format!("{}\n{}", &text[..64], &text[64..])
    };
    let hash = ["spec", "content", "hash"];
    let value = ["spec", "content", "hash", "value"];
    let algorithm = ["spec", "content", "hash", "algorithm"];
    let payload_value = ["spec", "content", "payloadHash", "value"];
    let key = ["spec", "publicKey"];
    let mismatches: Vec<(&str, &[&str], Option<Value>)> = vec![
        ("zero hash", &value, Some(s(&hex(&[0; 32])))),
        (
            "upper-case hash",
            &value,
            Some(s(&envelope_hex.to_uppercase())),
        ),
        (
            "prefixed hash",
            &value,
            Some(s(&format!("sha256:{envelope_hex}"))),
        ),
        (
            "hash newline",
            &value,
            Some(s(&format!("{envelope_hex}\n"))),
        ),
        (
            "hash zero-width space",
            &value,
            Some(s(&format!("{envelope_hex}\u{200B}"))),
        ),
        ("63 digits", &value, Some(s(&envelope_hex[..63]))),
        ("sha512", &algorithm, Some(s("sha512"))),
        ("SHA256", &algorithm, Some(s("SHA256"))),
        ("sha256 space", &algorithm, Some(s("sha256 "))),
        ("hash missing", &hash, None),
        (
            "payloadHash over base64",
            &payload_value,
            Some(s(&hex(&Sha256::digest(payload_text.as_bytes())))),
        ),
        ("payloadHash zero", &payload_value, Some(s(&hex(&[0; 32])))),
        (
            "payloadHash missing",
            &["spec", "content", "payloadHash"],
            None,
        ),
        (
            "payloadHash algorithm",
            &["spec", "content", "payloadHash", "algorithm"],
            Some(s("sha512")),
        ),
        ("other leaf", &key, Some(b64(&pki::pem(&other_leaf)))),
        (
            "public key PEM",
            &key,
            Some(b64(&public_key_pem(&pki.leaf_key.spki()))),
        ),
        ("CRLF", &key, Some(b64(&pem_text.replace('\n', "\r\n")))),
        (
            "two blocks",
            &key,
            Some(b64(&format!("{pem_text}{pem_text}"))),
        ),
        ("non-canonical base64", &key, Some(s(&broken))),
        ("publicKey number", &key, Some(Value::Number(7u64.into()))),
        ("publicKey missing", &key, None),
        ("content missing", &["spec", "content"], None),
        ("content string", &["spec", "content"], Some(s("x"))),
        ("spec missing", &["spec"], None),
        ("spec string", &["spec"], Some(s("x"))),
    ];
    for (name, path, new) in mismatches {
        let mut body = good.clone();
        match new {
            Some(new) => set(&mut body, path, new),
            None => remove(&mut body, path),
        }
        let mut spec = spec(&pki);
        spec.log(&pki, &body);
        assert_eq!(
            synthetic_verify(&pki, &spec),
            Err(Refusal::BodyMismatch),
            "{name}"
        );
    }
    // A body that is not JSON.
    let mut not_json = spec(&pki);
    not_json.entry.body = b"intoto".to_vec();
    assert_eq!(
        synthetic_verify(&pki, &not_json),
        Err(Refusal::BodyMismatch)
    );
    // Kind and version look-alikes.
    let kinds: Vec<(&str, &[&str], Option<Value>)> = vec![
        ("0.0.2", &["apiVersion"], Some(s("0.0.2"))),
        ("0.0.1 space", &["apiVersion"], Some(s("0.0.1 "))),
        ("0.0.10", &["apiVersion"], Some(s("0.0.10"))),
        ("apiVersion missing", &["apiVersion"], None),
        ("inToto", &["kind"], Some(s("inToto"))),
        ("Cyrillic o", &["kind"], Some(s("int\u{043E}to"))),
        (
            "kind zero-width space",
            &["kind"],
            Some(s("intoto\u{200B}")),
        ),
        ("rekord", &["kind"], Some(s("rekord"))),
        ("hashedrekord", &["kind"], Some(s("hashedrekord"))),
        ("kind missing", &["kind"], None),
    ];
    for (name, path, new) in kinds {
        let mut body = good.clone();
        match new {
            Some(new) => set(&mut body, path, new),
            None => remove(&mut body, path),
        }
        let mut spec = spec(&pki);
        spec.log(&pki, &body);
        assert_eq!(
            synthetic_verify(&pki, &spec),
            Err(Refusal::EntryKind),
            "{name}"
        );
    }
    // `content.envelope` and unknown members are not read.
    let mut body = good.clone();
    set(
        &mut body,
        &["spec", "content", "envelope"],
        obj(vec![("payloadType", s("x"))]),
    );
    set(&mut body, &["spec", "unknown"], s("x"));
    let mut extra = spec(&pki);
    extra.log(&pki, &body);
    assert_eq!(synthetic_verify(&pki, &extra), SYNTHETIC);
    // A `dsse` 0.0.1 entry over the same `.att` still passes.
    let mut dsse = spec(&pki);
    let body = pki::dsse_body(&dsse.statement, &dsse.signature, &dsse.certificate);
    dsse.log(&pki, &body);
    assert_eq!(synthetic_verify(&pki, &dsse), SYNTHETIC);
    // A `hashedrekord` entry for an `.att` is another kind.
    let mut rekord = spec(&pki);
    let body = hashedrekord(&rekord.statement, &rekord.signature, &rekord.certificate);
    rekord.log(&pki, &body);
    assert_eq!(synthetic_verify(&pki, &rekord), Err(Refusal::EntryKind));
}

/// An envelope that is not compact, logged with its own exact bytes,
/// passes: the hash is over the input, never a re-serialization.
#[test]
fn intoto_whitespace_envelope_passes() {
    let pki = Pki::new();
    let mut spec = spec(&pki);
    let compact = spec.envelope.clone();
    let mut spaced = b"{ ".to_vec();
    spaced.extend_from_slice(&compact[1..]);
    spaced.push(b'\n');
    spec.envelope = spaced;
    spec.relog(&pki);
    assert_eq!(synthetic_verify(&pki, &spec), SYNTHETIC);
    // The compact envelope under the spaced entry is refused.
    spec.envelope = compact;
    assert_eq!(synthetic_verify(&pki, &spec), Err(Refusal::BodyMismatch));
}

/// A body with `hash` twice (Go keeps the last, which is right here) is
/// refused: boneli-json refuses duplicate keys.
#[test]
fn intoto_duplicate_key_body_refused() {
    let pki = Pki::new();
    let mut spec = spec(&pki);
    let body = to_bytes(&spec.intoto_body());
    let duplicated = replace_once(
        &body,
        b"\"content\":{",
        format!(
            "\"content\":{{\"hash\":{{\"algorithm\":\"sha256\",\"value\":\"{}\"}},",
            hex(&[0; 32])
        )
        .as_bytes(),
    );
    spec.entry = EntrySpec {
        body: duplicated,
        ..EntrySpec::new(&pki, &Value::Null)
    };
    assert_eq!(synthetic_verify(&pki, &spec), Err(Refusal::BodyMismatch));
}

/// `"kind":"\u0069ntoto"` is `intoto` after unescaping and passes, as a
/// `dsse` kind does: the SET binds the bytes, the kind compares as text.
#[test]
fn intoto_escaped_kind_passes() {
    let pki = Pki::new();
    let mut spec = spec(&pki);
    let body = to_bytes(&spec.intoto_body());
    let escaped = replace_once(&body, b"\"kind\":\"intoto\"", b"\"kind\":\"\\u0069ntoto\"");
    assert_ne!(escaped, body);
    spec.entry = EntrySpec {
        body: escaped,
        ..EntrySpec::new(&pki, &Value::Null)
    };
    assert_eq!(synthetic_verify(&pki, &spec), SYNTHETIC);
}

/// `intoto` is an `.att` entry only: a bundle or a `.sig` layer logged as
/// `intoto` 0.0.1 is `EntryKind`.
#[test]
fn intoto_only_for_attestations() {
    let pki = Pki::new();
    let trust = pki::keyless_trust(&pki, vec![pki::email_identity()]);
    let mut bundle = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let envelope = to_bytes(&envelope_value(&bundle.statement, &bundle.signature));
    let body = pki::intoto_body(&envelope, &bundle.statement, &bundle.certificate);
    bundle.entry = EntrySpec::new(&pki, &body);
    let mut value = bundle.value(&pki);
    set(
        &mut value,
        &["verificationMaterial", "tlogEntries"],
        Value::Array(vec![bundle.entry.bundle_entry(&pki, "intoto")]),
    );
    let evidence = Evidence::from_bundle(&to_bytes(&value)).expect("parses");
    assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::EntryKind));
    let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let body = pki::intoto_body(&layer.payload, &layer.payload, &layer.certificate);
    layer.entry = EntrySpec::new(&pki, &body);
    let evidence = layer.evidence(&pki).expect("parses");
    assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::EntryKind));
}

/// Nothing changes under a trust without claims: argocd counts for nothing
/// (`AttestationNeedsClaims`), and a keyed `.att` whose bundle annotation
/// holds an `intoto` entry stays on the keyed path, which never reads it.
#[test]
fn intoto_rules_without_claims_unchanged() {
    assert_eq!(
        verify(
            &real::argocd(),
            &ARGOCD.digest,
            &real::slsa_v02_keyless(real::generator_v190_identity())
        ),
        Err(Refusal::AttestationNeedsClaims)
    );
    let pki = Pki::new();
    let synthetic = spec(&pki);
    let envelope = to_bytes(&keyed_envelope(&pki.signer_key, &statement()));
    let mut owned = keyed_attestation_annotations(SLSA_PROVENANCE_V02_PREDICATE);
    owned.push((
        BUNDLE_ANNOTATION.to_owned(),
        String::from_utf8(to_bytes(&synthetic.entry.cosign_annotation(&pki))).expect("UTF-8"),
    ));
    let evidence = Evidence::from_cosign_attestation(&pairs(&owned), &envelope).expect("evidence");
    assert!(!evidence.is_keyless());
    let keyed = pki::keyed_trust(&pki, &[SLSA_PROVENANCE_V02_PREDICATE])
        .with_claims(flux_claims())
        .expect("with claims");
    assert_eq!(
        verify(&evidence, &IMAGE, &keyed),
        Ok(Accepted::Keyed { key: 0 })
    );
}

/// Every strict prefix of both real envelopes, and of a synthetic `intoto`
/// body under a freshly signed SET, is refused, never a panic.
#[test]
fn truncated_intoto_never_panics() {
    for capture in [&ARGOCD, &KYVERNO] {
        let annotations = capture.annotations();
        let trust = capture.trust(real::generator_v190_identity());
        for n in 0..capture.envelope.len() {
            let verdict =
                Evidence::from_cosign_attestation(&pairs(&annotations), &capture.envelope[..n])
                    .and_then(|e| verify(&e, &capture.digest, &trust));
            assert!(verdict.is_err(), "prefix {n}");
        }
    }
    let pki = Pki::new();
    let mut spec = spec(&pki);
    let body = to_bytes(&spec.intoto_body());
    let trust = synthetic_trust(&pki);
    for n in 0..body.len() {
        // A fresh SET over the prefix: `signed_set` signs when `set` is None.
        spec.entry = EntrySpec {
            body: body[..n].to_vec(),
            ..EntrySpec::new(&pki, &Value::Null)
        };
        let evidence = spec.evidence(&pki).expect("parses");
        assert!(verify(&evidence, &IMAGE, &trust).is_err(), "prefix {n}");
    }
}
