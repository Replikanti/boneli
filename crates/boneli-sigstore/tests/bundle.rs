//! Sigstore bundles v0.3 (ADR-029, S1): versions, verification material,
//! log entries and size.

mod support;

use boneli_json::{Number, Value};
use boneli_sigstore::{COSIGN_SIGN_PREDICATE, Evidence, MAX_BUNDLE_BYTES, Refusal, base64, verify};
use support::pki::{
    self, BundleSpec, IMAGE, LeafSpec, Pki, hex, keyed_bundle, keyed_trust, obj, remove, s, set,
    statement, to_bytes,
};
use support::real;

fn parse(value: &Value) -> Result<Evidence, Refusal> {
    Evidence::from_bundle(&to_bytes(value))
}

fn keyless_trust(pki: &Pki) -> boneli_sigstore::Trust {
    pki::keyless_trust(pki, vec![pki::email_identity()])
}

#[test]
fn bundle_versions() {
    let pki = Pki::new();
    let good = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE).value(&pki);
    for media_type in [
        "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "application/vnd.dev.sigstore.bundle.v0.3+JSON",
        "application/vnd.dev.sigstore.bundle.v0.3+json; charset=utf-8",
        "application/vnd.dev.sigstore.bundle.v0.4+json",
    ] {
        let mut b = good.clone();
        set(&mut b, &["mediaType"], s(media_type));
        assert_eq!(
            parse(&b).err(),
            Some(Refusal::BundleVersion),
            "{media_type}"
        );
    }
    let mut b = good.clone();
    remove(&mut b, &["mediaType"]);
    assert_eq!(parse(&b).err(), Some(Refusal::BundleVersion));
    // A messageSignature bundle, with or without the envelope.
    let message = obj(vec![("signature", s("AAAA"))]);
    let mut b = good.clone();
    set(&mut b, &["messageSignature"], message.clone());
    assert_eq!(parse(&b).err(), Some(Refusal::MessageSignature));
    let mut b = good.clone();
    remove(&mut b, &["dsseEnvelope"]);
    set(&mut b, &["messageSignature"], message);
    assert_eq!(parse(&b).err(), Some(Refusal::MessageSignature));
    // The good one reads and passes.
    let evidence = parse(&good).expect("bundle");
    assert!(verify(&evidence, &IMAGE, &keyless_trust(&pki)).is_ok());
}

#[test]
fn bundle_chain_ignored() {
    let pki = Pki::new();
    // A bundle that brings a chain (the v0.1/v0.2 field) is refused
    // without reading it.
    let bundle = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let mut b = bundle.value(&pki);
    let chain = obj(vec![(
        "certificates",
        Value::Array(vec![
            obj(vec![("rawBytes", s(&base64::encode(&bundle.certificate)))]),
            obj(vec![(
                "rawBytes",
                s(&base64::encode(&pki.attacker_intermediate)),
            )]),
        ]),
    )]);
    set(
        &mut b,
        &["verificationMaterial", "x509CertificateChain"],
        chain,
    );
    assert_eq!(parse(&b).err(), Some(Refusal::BundleVersion));
    // A leaf issued by the attacker's intermediate fails even when the
    // cosign chain annotation carries that intermediate: intermediates
    // come only from the trusted root. It has our intermediate's name, so
    // webpki tries ours and the leaf's signature fails.
    let leaf = LeafSpec {
        issuer: pki::LeafIssuer::Attacker,
        ..LeafSpec::email()
    };
    let layer = pki::CosignLayer::keyless(&pki, &leaf, &IMAGE);
    let mut annotations = layer.annotations(&pki);
    annotations.push((
        "dev.sigstore.cosign/chain".to_owned(),
        format!(
            "{}{}",
            pki::pem(&pki.attacker_intermediate),
            pki::pem(&pki.root)
        ),
    ));
    let evidence =
        Evidence::from_cosign_layer(&real::pairs(&annotations), &layer.payload).expect("parses");
    assert_eq!(
        verify(&evidence, &IMAGE, &keyless_trust(&pki)),
        Err(Refusal::Certificate(boneli_https::CertError::Invalid))
    );
    // The same bundle form: an attacker-issued leaf in `certificate`.
    let bundle = BundleSpec::keyless(&pki, &leaf, &IMAGE);
    let evidence = parse(&bundle.value(&pki)).expect("parses");
    assert_eq!(
        verify(&evidence, &IMAGE, &keyless_trust(&pki)),
        Err(Refusal::Certificate(boneli_https::CertError::Invalid))
    );
}

#[test]
fn verification_material_shape() {
    let pki = Pki::new();
    let good = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE).value(&pki);
    // Both, or neither.
    let mut b = good.clone();
    set(
        &mut b,
        &["verificationMaterial", "publicKey"],
        obj(vec![("hint", s("AAAA"))]),
    );
    assert_eq!(parse(&b).err(), Some(Refusal::MalformedBundle));
    let mut b = good.clone();
    remove(&mut b, &["verificationMaterial", "certificate"]);
    assert_eq!(parse(&b).err(), Some(Refusal::MalformedBundle));
    for raw in [s(""), s("AA=A"), Value::Null] {
        let mut b = good.clone();
        set(
            &mut b,
            &["verificationMaterial", "certificate", "rawBytes"],
            raw,
        );
        assert_eq!(parse(&b).err(), Some(Refusal::MalformedCertificate));
    }
    let mut b = good.clone();
    set(&mut b, &["verificationMaterial", "publicKey"], s("hint"));
    remove(&mut b, &["verificationMaterial", "certificate"]);
    assert_eq!(parse(&b).err(), Some(Refusal::MalformedBundle));
    for b in [Value::Array(vec![]), s("x"), obj(vec![])] {
        assert!(matches!(
            parse(&b),
            Err(Refusal::MalformedBundle | Refusal::BundleVersion)
        ));
    }
}

#[test]
fn keyed_bundle_needs_no_entry_and_hint_is_not_read() {
    let pki = Pki::new();
    let st = statement(&[&hex(&IMAGE)], COSIGN_SIGN_PREDICATE);
    let mut b = keyed_bundle(&pki.signer_key, &st);
    // A hint naming another key changes nothing: every trusted key is
    // tried.
    set(
        &mut b,
        &["verificationMaterial", "publicKey", "hint"],
        s(&base64::encode(&pki.other_key.id())),
    );
    let evidence = parse(&b).expect("parses");
    assert!(!evidence.is_keyless());
    assert!(
        verify(
            &evidence,
            &IMAGE,
            &keyed_trust(&pki, &[COSIGN_SIGN_PREDICATE])
        )
        .is_ok()
    );
    // A keyed bundle under a keyless-only trust has no certificate.
    assert_eq!(
        verify(&evidence, &IMAGE, &keyless_trust(&pki)),
        Err(Refusal::NoCertificate)
    );
}

#[test]
fn tlog_entries_shape() {
    let pki = Pki::new();
    let spec = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let good = spec.value(&pki);
    let entry = spec.entry.bundle_entry(&pki, "dsse");
    let with_entry = |e: Value| {
        let mut b = good.clone();
        set(
            &mut b,
            &["verificationMaterial", "tlogEntries"],
            Value::Array(vec![e]),
        );
        parse(&b)
    };
    let num = |n: &str| Value::Number(Number::from_lexeme(n).expect("number"));
    for (path, new) in [
        (&["kindVersion", "kind"][..], s("hashedrekord")),
        (&["kindVersion", "version"][..], s("0.0.2")),
        (&["integratedTime"][..], num("1790000005")),
        (&["integratedTime"][..], s("01790000005")),
        (&["integratedTime"][..], s("+1790000005")),
        (&["integratedTime"][..], s("-1")),
        (&["integratedTime"][..], s("9223372036854775808")),
        (&["integratedTime"][..], s("")),
        (&["logIndex"][..], s("4 242")),
        (&["logId", "keyId"][..], s("AAAA")),
        (&["canonicalizedBody"][..], s("e30")),
        (&["inclusionPromise", "signedEntryTimestamp"][..], s("*")),
    ] {
        let mut e = entry.clone();
        set(&mut e, path, new.clone());
        assert_eq!(
            with_entry(e).err(),
            Some(Refusal::MalformedTlogEntry),
            "{path:?} {new:?}"
        );
    }
    let mut b = good.clone();
    set(&mut b, &["verificationMaterial", "tlogEntries"], s("x"));
    assert_eq!(parse(&b).err(), Some(Refusal::MalformedTlogEntry));
    // Zero or two: refused for keyless. One without a promise and without
    // a timestamp has no time source at all (ADR-038, D1).
    let trust = keyless_trust(&pki);
    for entries in [vec![], vec![entry.clone(), entry.clone()]] {
        let mut b = good.clone();
        set(
            &mut b,
            &["verificationMaterial", "tlogEntries"],
            Value::Array(entries),
        );
        let evidence = parse(&b).expect("parses");
        assert_eq!(verify(&evidence, &IMAGE, &trust), Err(Refusal::TlogEntries));
    }
    let mut e = entry.clone();
    remove(&mut e, &["inclusionPromise"]);
    let evidence = with_entry(e).expect("parses");
    assert_eq!(
        verify(&evidence, &IMAGE, &trust),
        Err(Refusal::NoTimeSource)
    );
}

#[test]
fn bundle_size_cap() {
    let pki = Pki::new();
    let mut bytes = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE).bytes(&pki);
    bytes.resize(MAX_BUNDLE_BYTES, b' ');
    assert!(Evidence::from_bundle(&bytes).is_ok(), "at the cap");
    bytes.push(b' ');
    assert_eq!(
        Evidence::from_bundle(&bytes).err(),
        Some(Refusal::BundleTooLarge)
    );
}

#[test]
fn real_bundle_reads() {
    let evidence = real::cosign();
    assert!(!evidence.is_keyless());
    assert_eq!(
        format!("{evidence:?}"),
        "Evidence { form: \"bundle\", keyless: false }"
    );
}
