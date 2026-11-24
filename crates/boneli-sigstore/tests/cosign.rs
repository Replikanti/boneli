//! cosign simple-signing layers (ADR-029, S1): the annotations, the
//! payload's `critical` part, and keyed verification.

mod support;

use boneli_sigstore::{
    BUNDLE_ANNOTATION, CERTIFICATE_ANNOTATION, Evidence, MAX_PAYLOAD_BYTES, Refusal,
    SIGNATURE_ANNOTATION, verify,
};
use support::pki::{
    self, CosignLayer, IMAGE, LeafSpec, OTHER_IMAGE, Pki, hex, keyed_layer, keyed_trust,
    payload_for, simple_signing,
};
use support::real::{self, pairs, with, without};

fn layer(annotations: &[(String, String)], payload: &[u8]) -> Result<Evidence, Refusal> {
    Evidence::from_cosign_layer(&pairs(annotations), payload)
}

fn keyed(pki: &Pki, payload: &[u8]) -> Result<boneli_sigstore::Accepted, Refusal> {
    let evidence = layer(&keyed_layer(&pki.signer_key, payload), payload)?;
    verify(&evidence, &IMAGE, &keyed_trust(pki, &[]))
}

#[test]
fn keyed_layer_passes_and_other_key_fails() {
    let pki = Pki::new();
    assert_eq!(
        keyed(&pki, &payload_for(&IMAGE)),
        Ok(boneli_sigstore::Accepted::Keyed { key: 0 })
    );
    let payload = payload_for(&IMAGE);
    let evidence = layer(&keyed_layer(&pki.other_key, &payload), &payload).expect("parses");
    assert_eq!(
        verify(&evidence, &IMAGE, &keyed_trust(&pki, &[])),
        Err(Refusal::NoTrustedKey)
    );
    // A payload byte changed after signing, in a field nothing reads.
    let mut changed = payload.clone();
    let at = changed
        .windows(8)
        .position(|w| w == b"registry")
        .expect("reference");
    changed[at] = b"R"[0];
    let evidence = layer(&keyed_layer(&pki.signer_key, &payload), &changed).expect("parses");
    assert_eq!(
        verify(&evidence, &IMAGE, &keyed_trust(&pki, &[])),
        Err(Refusal::NoTrustedKey)
    );
    // The second trusted key is found too.
    let trust = boneli_sigstore::Trust::new(
        vec![pki.other_key.public.clone(), pki.signer_key.public.clone()],
        None,
        Vec::new(),
    )
    .expect("trust");
    let evidence = layer(&keyed_layer(&pki.signer_key, &payload), &payload).expect("parses");
    assert_eq!(
        verify(&evidence, &IMAGE, &trust),
        Ok(boneli_sigstore::Accepted::Keyed { key: 1 })
    );
}

#[test]
fn signature_over_other_digest_refused() {
    let pki = Pki::new();
    let payload = payload_for(&OTHER_IMAGE);
    let evidence = layer(&keyed_layer(&pki.signer_key, &payload), &payload).expect("parses");
    assert_eq!(
        verify(&evidence, &IMAGE, &keyed_trust(&pki, &[])),
        Err(Refusal::SubjectMismatch)
    );
    // The real Chainguard signature is not one of Kubernetes' image.
    let trust = real::keyless(vec![real::chainguard_identity()]);
    assert_eq!(
        verify(&real::chainguard(), &real::KUBERNETES_DIGEST, &trust),
        Err(Refusal::SubjectMismatch)
    );
}

#[test]
fn look_alike_type_refused() {
    let pki = Pki::new();
    for kind in [
        "cosign container image signature ",
        " cosign container image signature",
        "cosign container image signatur\u{0435}",
        "Cosign container image signature",
        "cosign  container image signature",
        "",
    ] {
        let payload = simple_signing(&hex(&IMAGE), kind);
        assert_eq!(keyed(&pki, &payload), Err(Refusal::PayloadType), "{kind:?}");
    }
}

#[test]
fn digest_forms_refused() {
    let pki = Pki::new();
    let lower = hex(&IMAGE);
    for digest in [
        lower.to_uppercase(),
        lower[..63].to_owned(),
        format!("{lower}0"),
        lower.replacen('5', "\u{ff15}", 1),
        format!("{lower}\u{200b}"),
        format!("\u{200b}{lower}"),
    ] {
        let payload = simple_signing(&digest, boneli_sigstore::SIMPLE_SIGNING_TYPE);
        assert_eq!(
            keyed(&pki, &payload),
            Err(Refusal::MalformedDigest),
            "{digest:?}"
        );
    }
    for whole in [
        format!("sha512:{lower}"),
        format!("SHA256:{lower}"),
        lower.clone(),
        format!("sha256 :{lower}"),
    ] {
        let payload = format!(
            "{{\"critical\":{{\"identity\":{{}},\"image\":{{\"docker-manifest-digest\":\"{whole}\"}},\"type\":\"cosign container image signature\"}}}}"
        );
        assert_eq!(
            keyed(&pki, payload.as_bytes()),
            Err(Refusal::MalformedDigest),
            "{whole}"
        );
    }
}

#[test]
fn payload_shape() {
    let pki = Pki::new();
    for payload in [
        &b"not json"[..],
        b"[]",
        b"{}",
        b"{\"critical\":[]}",
        b"{\"critical\":{\"type\":\"cosign container image signature\"}}",
        b"{\"critical\":{\"type\":\"cosign container image signature\",\"image\":{}}}",
        b"{\"critical\":{\"type\":1,\"image\":{\"docker-manifest-digest\":\"x\"}}}",
        b"{\"critical\":{\"type\":\"cosign container image signature\",\"type\":\"x\",\"image\":{}}}",
    ] {
        let result = keyed(&pki, payload);
        assert!(
            matches!(result, Err(Refusal::MalformedPayload)),
            "{}: {result:?}",
            String::from_utf8_lossy(payload)
        );
    }
    // `identity` and `optional` are not read.
    let payload = format!(
        "{{\"critical\":{{\"image\":{{\"docker-manifest-digest\":\"sha256:{}\"}},\"type\":\"cosign container image signature\"}},\"optional\":{{\"a\":[1,2]}}}}",
        hex(&IMAGE)
    );
    assert!(keyed(&pki, payload.as_bytes()).is_ok());
}

#[test]
fn payload_size_cap() {
    let pki = Pki::new();
    let mut payload = payload_for(&IMAGE);
    payload.resize(MAX_PAYLOAD_BYTES, b' ');
    assert!(keyed(&pki, &payload).is_ok(), "at the cap");
    payload.push(b' ');
    let annotations = keyed_layer(&pki.signer_key, &payload);
    assert_eq!(
        layer(&annotations, &payload).err(),
        Some(Refusal::PayloadTooLarge)
    );
}

#[test]
fn annotations_read_strictly() {
    let pki = Pki::new();
    let payload = payload_for(&IMAGE);
    let good = keyed_layer(&pki.signer_key, &payload);
    assert_eq!(
        layer(&[], &payload).err(),
        Some(Refusal::MalformedAnnotations)
    );
    let mut twice = good.clone();
    twice.extend(good.clone());
    assert_eq!(
        layer(&twice, &payload).err(),
        Some(Refusal::MalformedAnnotations)
    );
    let bad_sig = with(&good, SIGNATURE_ANNOTATION, "not base64!");
    assert_eq!(
        layer(&bad_sig, &payload).err(),
        Some(Refusal::MalformedSignature)
    );
    for cert in [
        "-----BEGIN CERTIFICATE-----\nAAAA\n",
        "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        "-----BEGIN CERTIFICATE-----\nA A=\n-----END CERTIFICATE-----\n",
        "x-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----\r\n",
        "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n",
    ] {
        let annotations = with(&good, CERTIFICATE_ANNOTATION, cert);
        assert_eq!(
            layer(&annotations, &payload).err(),
            Some(Refusal::MalformedCertificate),
            "{cert:?}"
        );
    }
    // A real certificate with its base64 on one line, or with a line of
    // 65 characters, is not the form Go writes.
    let real_cert = real::annotations(real::KUBERNETES_SIG)
        .into_iter()
        .find(|(k, _)| k == CERTIFICATE_ANNOTATION)
        .expect("certificate")
        .1;
    let body: String = real_cert
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let one_line = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");
    let wide = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n{}\n-----END CERTIFICATE-----\n",
        &body[..65],
        &body[65..]
    );
    for cert in [one_line, wide] {
        let annotations = with(&good, CERTIFICATE_ANNOTATION, &cert);
        assert_eq!(
            layer(&annotations, &payload).err(),
            Some(Refusal::MalformedCertificate)
        );
    }
    let twice_cert = {
        let mut a = with(&good, CERTIFICATE_ANNOTATION, "x");
        a.push((CERTIFICATE_ANNOTATION.to_owned(), "y".to_owned()));
        a
    };
    assert_eq!(
        layer(&twice_cert, &payload).err(),
        Some(Refusal::MalformedAnnotations)
    );
    // An empty certificate annotation is a keyed signature.
    let empty = with(&good, CERTIFICATE_ANNOTATION, "");
    let evidence = layer(&empty, &payload).expect("keyed");
    assert!(!evidence.is_keyless());
    // Unknown annotations are ignored.
    let extra = with(&good, "org.example/x", "y");
    assert!(layer(&extra, &payload).is_ok());
}

#[test]
fn bundle_annotation_shape() {
    let real_annotations = real::annotations(real::KUBERNETES_SIG);
    let bundle = real_annotations
        .iter()
        .find(|(k, _)| k == BUNDLE_ANNOTATION)
        .map(|(_, v)| v.clone())
        .expect("bundle");
    let mut value = real::json(bundle.as_bytes());
    let broken = |path: &[&str], new: boneli_json::Value, value: &boneli_json::Value| {
        let mut v = value.clone();
        pki::set(&mut v, path, new);
        let text = String::from_utf8(pki::to_bytes(&v)).expect("utf-8");
        layer(
            &with(&real_annotations, BUNDLE_ANNOTATION, &text),
            real::KUBERNETES_PAYLOAD,
        )
        .err()
    };
    use boneli_json::{Number, Value};
    let num = |n: &str| Value::Number(Number::from_lexeme(n).expect("number"));
    for (path, new) in [
        (&["Payload", "integratedTime"][..], num("-1")),
        (
            &["Payload", "integratedTime"][..],
            num("9223372036854775808"),
        ),
        (&["Payload", "integratedTime"][..], num("1.5")),
        (&["Payload", "integratedTime"][..], pki::s("1716500129")),
        (&["Payload", "logIndex"][..], num("-3")),
        (
            &["Payload", "logID"][..],
            pki::s("C0D23D6AD406973F9559F3BA2D1CA01F84147D8FFC5B8445C224F98B9591801D"),
        ),
        (&["Payload", "logID"][..], pki::s("c0d23d6a")),
        (&["Payload", "body"][..], pki::s("eyJ")),
        (&["SignedEntryTimestamp"][..], pki::s("MEY CIQ=")),
    ] {
        assert_eq!(
            broken(path, new.clone(), &value),
            Some(Refusal::MalformedTlogEntry),
            "{path:?} {new:?}"
        );
    }
    // i64::MAX itself parses; it cannot be compared in milliseconds.
    pki::set(
        &mut value,
        &["Payload", "integratedTime"],
        num("9223372036854775807"),
    );
    let text = String::from_utf8(pki::to_bytes(&value)).expect("utf-8");
    let evidence = layer(
        &with(&real_annotations, BUNDLE_ANNOTATION, &text),
        real::KUBERNETES_PAYLOAD,
    )
    .expect("parses");
    let trust = real::keyless(vec![real::kubernetes_identity()]);
    assert_eq!(
        verify(&evidence, &real::KUBERNETES_DIGEST, &trust),
        Err(Refusal::IntegratedTimeRange)
    );
}

#[test]
fn integrated_time_range() {
    // Synthetic: integrated times past what milliseconds can hold are
    // refused before anything is looked up; negative and above-i64 ones
    // do not parse (`bundle_annotation_shape`).
    let pki = Pki::new();
    let trust = pki::keyless_trust(&pki, vec![pki::email_identity()]);
    for at in [u64::MAX / 1_000 + 1, i64::MAX as u64] {
        let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
        layer.entry.integrated_time = at;
        let evidence = layer.evidence(&pki).expect("parses");
        assert_eq!(
            verify(&evidence, &IMAGE, &trust),
            Err(Refusal::IntegratedTimeRange),
            "{at}"
        );
    }
}

#[test]
fn keyless_layer_without_entry_refused() {
    let pki = Pki::new();
    let layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let annotations = without(&layer.annotations(&pki), BUNDLE_ANNOTATION);
    let evidence =
        Evidence::from_cosign_layer(&pairs(&annotations), &layer.payload).expect("parses");
    let trust = pki::keyless_trust(&pki, vec![pki::email_identity()]);
    assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::TlogEntries));
}
