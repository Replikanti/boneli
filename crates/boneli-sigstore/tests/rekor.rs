//! Rekor v1 entries (ADR-029, S2): the SET over our JCS bytes, the log
//! lookup and window, and the body match.

mod support;

use boneli_https::PublicKey;
use boneli_json::Value;
use boneli_sigstore::{BUNDLE_ANNOTATION, Evidence, Refusal, base64, verify};
use support::pki::{
    self, BundleSpec, CosignLayer, EntrySpec, IMAGE, LeafSpec, OTHER_IMAGE, Pki, hashedrekord, hex,
    set_message, to_bytes,
};
use support::real::{self, pairs, with};

fn rekor_v1_key() -> PublicKey {
    let root = real::json(real::TRUSTED_ROOT);
    let raw = root.get("tlogs").and_then(Value::as_array).expect("tlogs")[0]
        .get("publicKey")
        .and_then(|k| k.get("rawBytes"))
        .and_then(Value::as_str)
        .expect("rawBytes")
        .to_owned();
    PublicKey::from_spki_der(&base64::decode(raw.as_bytes()).expect("b64")).expect("key")
}

fn cosign_bundle_annotation(sig: &[u8]) -> Value {
    let annotations = real::annotations(sig);
    let text = &annotations
        .iter()
        .find(|(k, _)| k == BUNDLE_ANNOTATION)
        .expect("bundle")
        .1;
    real::json(text.as_bytes())
}

#[test]
fn jcs_matches_rekor() {
    let key = rekor_v1_key();
    for sig in [real::KUBERNETES_SIG, real::CHAINGUARD_SIG] {
        let value = cosign_bundle_annotation(sig);
        let payload = value.get("Payload").expect("Payload");
        let body = base64::decode(
            payload
                .get("body")
                .and_then(Value::as_str)
                .expect("body")
                .as_bytes(),
        )
        .expect("body");
        let n = |k: &str| {
            payload
                .get(k)
                .and_then(Value::as_number)
                .and_then(|n| n.as_u64())
                .expect(k)
        };
        let id = payload.get("logID").and_then(Value::as_str).expect("logID");
        let id = real::hex32(id);
        let message = set_message(&body, n("integratedTime"), &id, n("logIndex"));
        let set = base64::decode(
            value
                .get("SignedEntryTimestamp")
                .and_then(Value::as_str)
                .expect("SET")
                .as_bytes(),
        )
        .expect("SET");
        assert!(key.verify(&message, &set).is_ok());
        assert_eq!(key.key_id(), id);
    }
    // The bundle form: integers as strings, the log ID in base64.
    let bundle = real::json(real::COSIGN_BUNDLE);
    let entry = &bundle
        .get("verificationMaterial")
        .and_then(|m| m.get("tlogEntries"))
        .and_then(Value::as_array)
        .expect("entries")[0];
    let str_of = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).expect(k).to_owned();
    let body = base64::decode(str_of(entry, "canonicalizedBody").as_bytes()).expect("body");
    let id: [u8; 32] =
        base64::decode(str_of(entry.get("logId").expect("logId"), "keyId").as_bytes())
            .expect("id")
            .try_into()
            .expect("32");
    let message = set_message(
        &body,
        str_of(entry, "integratedTime").parse().expect("int"),
        &id,
        str_of(entry, "logIndex").parse().expect("int"),
    );
    let set = base64::decode(
        str_of(
            entry.get("inclusionPromise").expect("promise"),
            "signedEntryTimestamp",
        )
        .as_bytes(),
    )
    .expect("SET");
    assert!(key.verify(&message, &set).is_ok());
}

#[test]
fn set_for_other_body_refused() {
    // Chainguard's SET with Kubernetes' body.
    let k8s = cosign_bundle_annotation(real::KUBERNETES_SIG);
    let mut cg = cosign_bundle_annotation(real::CHAINGUARD_SIG);
    pki::set(
        &mut cg,
        &["Payload", "body"],
        k8s.get("Payload")
            .and_then(|p| p.get("body"))
            .expect("body")
            .clone(),
    );
    let annotations = with(
        &real::annotations(real::KUBERNETES_SIG),
        BUNDLE_ANNOTATION,
        &String::from_utf8(to_bytes(&cg)).expect("utf-8"),
    );
    let evidence = Evidence::from_cosign_layer(&pairs(&annotations), real::KUBERNETES_PAYLOAD)
        .expect("parses");
    let trust = real::keyless(vec![real::kubernetes_identity()]);
    assert_eq!(
        verify(&evidence, &real::KUBERNETES_DIGEST, &trust),
        Err(Refusal::SetInvalid)
    );
    // Any changed field of the promised tuple.
    let pki = Pki::new();
    let trust = pki::keyless_trust(&pki, vec![pki::email_identity()]);
    for change in 0..3 {
        let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
        let set = layer.entry.signed_set(&pki);
        layer.entry.set = Some(set);
        match change {
            0 => layer.entry.integrated_time += 1,
            1 => layer.entry.log_index += 1,
            _ => layer.entry.body.push(b' '),
        }
        let evidence = layer.evidence(&pki).expect("parses");
        assert_eq!(
            verify(&evidence, &IMAGE, &trust),
            Err(Refusal::SetInvalid),
            "change {change}"
        );
    }
}

#[test]
fn body_mismatch_refused() {
    let pki = Pki::new();
    let trust = pki::keyless_trust(&pki, vec![pki::email_identity()]);
    let base = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let other_cert = LeafSpec {
        serial: 9,
        ..LeafSpec::email()
    }
    .build(&pki);
    let other_payload = pki::payload_for(&OTHER_IMAGE);
    let other_sig = pki.leaf_key.sign(&other_payload);
    // Each body is logged properly; it just says something else.
    let bodies = [
        hashedrekord(&base.payload, &other_sig, &base.certificate),
        hashedrekord(&other_payload, &base.signature, &base.certificate),
        hashedrekord(&base.payload, &base.signature, &other_cert),
    ];
    for (i, body) in bodies.iter().enumerate() {
        let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
        layer.entry = EntrySpec::new(&pki, body);
        let evidence = layer.evidence(&pki).expect("parses");
        assert_eq!(
            verify(&evidence, &IMAGE, &trust),
            Err(Refusal::BodyMismatch),
            "body {i}"
        );
    }
    // Field forms: another algorithm, upper-case hex, no publicKey.
    let good = hashedrekord(&base.payload, &base.signature, &base.certificate);
    let upper = hex(&boneli_https::Sha256::digest(&base.payload)).to_uppercase();
    for (path, new) in [
        (&["spec", "data", "hash", "algorithm"][..], pki::s("sha512")),
        (&["spec", "data", "hash", "value"][..], pki::s(&upper)),
        (&["spec", "signature", "publicKey"][..], pki::s("x")),
        (&["spec", "signature", "content"][..], pki::s("not base64")),
    ] {
        let mut body = good.clone();
        pki::set(&mut body, path, new);
        let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
        layer.entry = EntrySpec::new(&pki, &body);
        let evidence = layer.evidence(&pki).expect("parses");
        assert_eq!(
            verify(&evidence, &IMAGE, &trust),
            Err(Refusal::BodyMismatch),
            "{path:?}"
        );
    }
    // A body that is not JSON.
    let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    layer.entry.body = b"not json".to_vec();
    let evidence = layer.evidence(&pki).expect("parses");
    assert_eq!(
        verify(&evidence, &IMAGE, &trust),
        Err(Refusal::BodyMismatch)
    );
}

#[test]
fn entry_kind_must_fit_the_evidence() {
    let pki = Pki::new();
    let trust = pki::keyless_trust(&pki, vec![pki::email_identity()]);
    // A cosign layer logged as dsse.
    let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let body = pki::dsse_body(&layer.payload, &layer.signature, &layer.certificate);
    layer.entry = EntrySpec::new(&pki, &body);
    let evidence = layer.evidence(&pki).expect("parses");
    assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::EntryKind));
    // hashedrekord 0.0.2.
    let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let mut body = hashedrekord(&layer.payload, &layer.signature, &layer.certificate);
    pki::set(&mut body, &["apiVersion"], pki::s("0.0.2"));
    layer.entry = EntrySpec::new(&pki, &body);
    let evidence = layer.evidence(&pki).expect("parses");
    assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::EntryKind));
    // A bundle logged as hashedrekord (kindVersion following the body).
    let mut spec = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let body = hashedrekord(&spec.statement, &spec.signature, &spec.certificate);
    spec.entry = EntrySpec::new(&pki, &body);
    let mut value = spec.value(&pki);
    pki::set(
        &mut value,
        &["verificationMaterial", "tlogEntries"],
        Value::Array(vec![spec.entry.bundle_entry(&pki, "hashedrekord")]),
    );
    let evidence = Evidence::from_bundle(&to_bytes(&value)).expect("parses");
    assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::EntryKind));
}

#[test]
fn dsse_body_checks() {
    let pki = Pki::new();
    let trust = pki::keyless_trust(&pki, vec![pki::email_identity()]);
    let spec = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let good = pki::dsse_body(&spec.statement, &spec.signature, &spec.certificate);
    let other_cert = LeafSpec {
        serial: 9,
        ..LeafSpec::email()
    }
    .build(&pki);
    let one = good
        .get("spec")
        .and_then(|s| s.get("signatures"))
        .and_then(Value::as_array)
        .expect("signatures")[0]
        .clone();
    let changes: Vec<(&[&str], Value)> = vec![
        (&["spec", "payloadHash", "value"], pki::s(&hex(&[0; 32]))),
        (&["spec", "payloadHash", "algorithm"], pki::s("sha384")),
        (
            &["spec", "signatures"],
            Value::Array(vec![one.clone(), one.clone()]),
        ),
        (&["spec", "signatures"], Value::Array(vec![])),
        (
            &["spec", "signatures"],
            pki::dsse_body(&spec.statement, &spec.signature, &other_cert)
                .get("spec")
                .and_then(|s| s.get("signatures"))
                .expect("signatures")
                .clone(),
        ),
        (
            &["spec", "signatures"],
            pki::dsse_body(
                &spec.statement,
                &pki.leaf_key.sign(b"other"),
                &spec.certificate,
            )
            .get("spec")
            .and_then(|s| s.get("signatures"))
            .expect("signatures")
            .clone(),
        ),
    ];
    for (i, (path, new)) in changes.into_iter().enumerate() {
        let mut body = good.clone();
        pki::set(&mut body, path, new);
        let mut spec = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE);
        spec.entry = EntrySpec::new(&pki, &body);
        let evidence = Evidence::from_bundle(&spec.bytes(&pki)).expect("parses");
        assert_eq!(
            verify(&evidence, &IMAGE, &trust),
            Err(Refusal::BodyMismatch),
            "change {i}"
        );
    }
    // envelopeHash is not checked (the bundle has no copy of the bytes
    // Rekor hashed): the synthetic body carries zeros there and passes.
    let evidence = Evidence::from_bundle(&spec.bytes(&pki)).expect("parses");
    assert!(verify(&evidence, &IMAGE, &trust).is_ok());
}

#[test]
fn set_by_ctlog_key_refused() {
    let pki = Pki::new();
    let trust = pki::keyless_trust(&pki, vec![pki::email_identity()]);
    // Signed by the CT log and naming it: not a Rekor log of the root.
    let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    layer.entry.log_id = pki.ct_key.id();
    layer.entry.set = Some(pki.ct_key.sign(&set_message(
        &layer.entry.body,
        layer.entry.integrated_time,
        &layer.entry.log_id,
        layer.entry.log_index,
    )));
    let evidence = layer.evidence(&pki).expect("parses");
    assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::UnknownLog));
    // Signed by the CT log, naming Rekor.
    let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    layer.entry.set = Some(pki.ct_key.sign(&set_message(
        &layer.entry.body,
        layer.entry.integrated_time,
        &layer.entry.log_id,
        layer.entry.log_index,
    )));
    let evidence = layer.evidence(&pki).expect("parses");
    assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::SetInvalid));
}

#[test]
fn unknown_log_refused() {
    let pki = Pki::new();
    let trust = pki::keyless_trust(&pki, vec![pki::email_identity()]);
    let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    layer.entry.log_id = pki.other_key.id();
    layer.entry.set = Some(pki.other_key.sign(&set_message(
        &layer.entry.body,
        layer.entry.integrated_time,
        &layer.entry.log_id,
        layer.entry.log_index,
    )));
    let evidence = layer.evidence(&pki).expect("parses");
    assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::UnknownLog));
    // The Rekor v2 log of the public-good root is left out, so neither
    // the SHA-256 of its key nor its signed-note key ID is known.
    let trust = real::keyless(vec![real::kubernetes_identity()]);
    for id in [
        "b54813cb63d8859870a5e78500cc6adcfdf59723edae93ee8d25faf2475a0690",
        "cf1199155bddd051268d1f16ac5c0c75c009f6fb5a63f4177f8e18d7051e3fa0",
    ] {
        let mut real_value = cosign_bundle_annotation(real::KUBERNETES_SIG);
        pki::set(&mut real_value, &["Payload", "logID"], pki::s(id));
        let annotations = with(
            &real::annotations(real::KUBERNETES_SIG),
            BUNDLE_ANNOTATION,
            &String::from_utf8(to_bytes(&real_value)).expect("utf-8"),
        );
        let evidence = Evidence::from_cosign_layer(&pairs(&annotations), real::KUBERNETES_PAYLOAD)
            .expect("parses");
        assert_eq!(
            verify(&evidence, &real::KUBERNETES_DIGEST, &trust),
            Err(Refusal::UnknownLog)
        );
    }
}
