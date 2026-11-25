//! RFC 3161 timestamps as a time source of keyless bundles (ADR-038, D1,
//! D3 to D5): the real trillian_log_server bundle (Rekor v1 SET and one
//! token) as a known answer, then the rules over the synthetic instance of
//! `support::pki` with its test TSA.
//!
//! A bundle entry without an inclusion promise is still refused with
//! `TlogEntries` once a time is found (Rekor v2 entries are PR 2 of
//! #102), so the cases without a SET tell the time sources apart by that
//! refusal: `TlogEntries` means a token counted, `NoTimeSource` or a
//! token refusal means none did.

mod support;

use boneli_https::{CertError, Sha256, TimestampError, TimestampToken};
use boneli_json::Value;
use boneli_sigstore::{
    Accepted, Evidence, IN_TOTO_PAYLOAD_TYPE, MAX_TIMESTAMPS, Refusal, Trust, TrustedRoot, base64,
    pae, verify,
};
use support::pki::{
    self, BundleSpec, EPOCH_2020, IMAGE, INTEGRATED, LIFETIME, LOG_INDEX, LeafSpec, Pki, T, Tsa,
    email_identity, keyless_trust_in, obj, remove, rfc3339_ms, root_value, s, set, to_bytes,
    with_tokens, with_tsas,
};
use support::real;

/// The test root with `tsa` valid from 2020 on.
fn tsa_root(pki: &Pki, tsa: &Tsa) -> Value {
    with_tsas(root_value(pki), vec![tsa.authority(EPOCH_2020, None)])
}

fn trusting(root: &Value) -> Trust {
    keyless_trust_in(root, vec![email_identity()])
}

/// A keyless bundle over `IMAGE` from the email leaf, its SET at
/// `INTEGRATED`, carrying `tokens`; without its promise if `!promise`.
fn bundle(pki: &Pki, spec: &BundleSpec, tokens: &[Vec<u8>], promise: bool) -> Evidence {
    let mut value = with_tokens(spec.value(pki), tokens);
    if !promise {
        let mut entry = spec.entry.bundle_entry(pki, "dsse");
        remove(&mut entry, &["inclusionPromise"]);
        set(
            &mut value,
            &["verificationMaterial", "tlogEntries"],
            Value::Array(vec![entry]),
        );
    }
    Evidence::from_bundle(&to_bytes(&value)).expect("bundle")
}

fn email_bundle(pki: &Pki) -> BundleSpec {
    BundleSpec::keyless(pki, &LeafSpec::email(), &IMAGE)
}

fn accepted(integrated_time: Option<u64>, signed_timestamps: usize) -> Result<Accepted, Refusal> {
    Ok(Accepted::Keyless {
        integrated_time,
        signed_timestamps,
        log_index: LOG_INDEX,
        identity: 0,
    })
}

#[test]
fn real_set_and_timestamp_verify() {
    let trust = real::keyless(vec![real::trillian_identity()]);
    assert_eq!(
        verify(&real::trillian(), &real::TRILLIAN_DIGEST, &trust),
        Ok(Accepted::Keyless {
            integrated_time: Some(real::TRILLIAN_INTEGRATED),
            signed_timestamps: 1,
            log_index: real::TRILLIAN_LOG_INDEX,
            identity: 0,
        })
    );
    // Against a root that lists no TSA the token does not count, and the
    // SET alone still passes (D5).
    let mut root = real::json(real::TRUSTED_ROOT);
    remove(&mut root, &["timestampAuthorities"]);
    let root = std::sync::Arc::new(TrustedRoot::from_json(&to_bytes(&root)).expect("root"));
    assert_eq!(root.tsa_count(), 0);
    let trust = Trust::new(
        Vec::new(),
        Some((root, vec![real::trillian_identity()])),
        vec![boneli_sigstore::COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust");
    assert_eq!(
        verify(&real::trillian(), &real::TRILLIAN_DIGEST, &trust),
        Ok(Accepted::Keyless {
            integrated_time: Some(real::TRILLIAN_INTEGRATED),
            signed_timestamps: 0,
            log_index: real::TRILLIAN_LOG_INDEX,
            identity: 0,
        })
    );
}

/// The Rekor v2 bundles carry no integrated time; their entries are read
/// by PR 2 of #102, so until then they are refused at the entry.
#[test]
fn real_rekor_v2_bundles_still_refused() {
    for bytes in [real::BEX_BUNDLE, real::AICR_RECIPE_BUNDLE] {
        assert_eq!(
            Evidence::from_bundle(bytes).err(),
            Some(Refusal::MalformedTlogEntry)
        );
    }
}

#[test]
fn keyed_bundle_tokens_not_read() {
    let key = boneli_https::PublicKey::from_pem(real::COSIGN_RELEASE_KEY).expect("key");
    let trust = Trust::new(
        vec![key],
        None,
        vec![boneli_sigstore::COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust");
    // The real token, and garbage in its place.
    let mut garbage = real::json(real::COSIGN_BUNDLE);
    garbage = with_tokens(garbage, &[b"not a token".to_vec()]);
    for bundle in [real::COSIGN_BUNDLE.to_vec(), to_bytes(&garbage)] {
        let evidence = Evidence::from_bundle(&bundle).expect("bundle");
        assert_eq!(
            verify(&evidence, &real::COSIGN_DIGEST, &trust),
            Ok(Accepted::Keyed { key: 0 })
        );
    }
}

#[test]
fn time_source_threshold() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let trust = trusting(&tsa_root(&pki, &tsa));
    let spec = email_bundle(&pki);
    let good = tsa.token(&spec.signature, T + 10);
    let failing = tsa.token(b"another message", T + 10);
    let unknown = Tsa::attacker(&pki).token(&spec.signature, T + 10);
    let check = |tokens: &[Vec<u8>], promise: bool| {
        verify(&bundle(&pki, &spec, tokens, promise), &IMAGE, &trust)
    };
    // With a SET.
    assert_eq!(check(&[], true), accepted(Some(INTEGRATED), 0));
    assert_eq!(
        check(std::slice::from_ref(&failing), true),
        accepted(Some(INTEGRATED), 0)
    );
    assert_eq!(
        check(std::slice::from_ref(&good), true),
        accepted(Some(INTEGRATED), 1)
    );
    assert_eq!(
        check(&[failing.clone(), good.clone(), good.clone()], true),
        accepted(Some(INTEGRATED), 2)
    );
    // Without: a verified token is a time source, failing ones are not.
    assert_eq!(
        check(&[failing.clone(), good.clone()], false),
        Err(Refusal::TlogEntries)
    );
    assert_eq!(
        check(&[failing.clone(), unknown.clone()], false),
        Err(Refusal::Timestamp(TimestampError::Imprint))
    );
    assert_eq!(
        check(&[unknown, failing], false),
        Err(Refusal::Timestamp(TimestampError::SigningCertificate))
    );
    assert_eq!(check(&[], false), Err(Refusal::NoTimeSource));
    // A token that does not parse is a failing token too.
    assert_eq!(
        check(&[b"not a token".to_vec()], false),
        Err(Refusal::Timestamp(TimestampError::Malformed))
    );
}

#[test]
fn timestamp_at_leaf_bounds() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let trust = trusting(&tsa_root(&pki, &tsa));
    let spec = email_bundle(&pki);
    for (at, ok) in [
        (T - 1, false),
        (T, true),
        (T + LIFETIME, true),
        (T + LIFETIME + 1, false),
    ] {
        let evidence = bundle(&pki, &spec, &[tsa.token(&spec.signature, at)], true);
        let expected = if ok {
            accepted(Some(INTEGRATED), 1)
        } else {
            Err(Refusal::Certificate(CertError::OutsideValidity))
        };
        assert_eq!(verify(&evidence, &IMAGE, &trust), expected, "{at}");
    }
}

#[test]
fn every_verified_time_holds() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let trust = trusting(&tsa_root(&pki, &tsa));
    // A SET inside the leaf's validity and a verified token outside it.
    let spec = email_bundle(&pki);
    let late = tsa.token(&spec.signature, T + LIFETIME + 60);
    assert_eq!(
        verify(&bundle(&pki, &spec, &[late], true), &IMAGE, &trust),
        Err(Refusal::Certificate(CertError::OutsideValidity))
    );
    // A SET outside it and a verified token inside.
    let mut early = email_bundle(&pki);
    early.entry.integrated_time = T - 1;
    let token = tsa.token(&early.signature, T + 10);
    assert_eq!(
        verify(&bundle(&pki, &early, &[token], true), &IMAGE, &trust),
        Err(Refusal::Certificate(CertError::OutsideValidity))
    );
    // A token where no Fulcio authority of the root is valid.
    let mut v = tsa_root(&pki, &tsa);
    set(
        &mut v,
        &["certificateAuthorities"],
        Value::Array(vec![pki::authority(
            &[&pki.intermediate, &pki.root],
            EPOCH_2020,
            Some(&rfc3339_ms((T + 100) * 1_000)),
        )]),
    );
    let token = tsa.token(&spec.signature, T + 101);
    assert_eq!(
        verify(&bundle(&pki, &spec, &[token], true), &IMAGE, &trusting(&v)),
        Err(Refusal::NoCaAtTime)
    );
}

#[test]
fn tsa_window_bounds() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let start = T;
    let end = T + 100;
    let root = with_tsas(
        root_value(&pki),
        vec![tsa.authority(&rfc3339_ms(start * 1_000), Some(&rfc3339_ms(end * 1_000)))],
    );
    let trust = trusting(&root);
    let spec = email_bundle(&pki);
    // The TSA leaf is valid at every one of these times; only the root's
    // window decides.
    for (at, counts) in [
        (start - 1, false),
        (start, true),
        (end, true),
        (end + 1, false),
    ] {
        let evidence = bundle(&pki, &spec, &[tsa.token(&spec.signature, at)], false);
        let expected = if counts {
            Err(Refusal::TlogEntries)
        } else {
            Err(Refusal::NoTsaAtTime)
        };
        assert_eq!(verify(&evidence, &IMAGE, &trust), expected, "{at}");
    }
}

#[test]
fn timestamp_count_limit() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let trust = trusting(&tsa_root(&pki, &tsa));
    let spec = email_bundle(&pki);
    // Absent, `{}` and `[]`: the verdict as before timestamps.
    let absent = spec.value(&pki);
    let mut empty_object = spec.value(&pki);
    set(
        &mut empty_object,
        &["verificationMaterial", "timestampVerificationData"],
        obj(vec![]),
    );
    let empty_list = with_tokens(spec.value(&pki), &[]);
    for value in [absent, empty_object, empty_list] {
        let evidence = Evidence::from_bundle(&to_bytes(&value)).expect("bundle");
        assert_eq!(
            verify(&evidence, &IMAGE, &trust),
            accepted(Some(INTEGRATED), 0)
        );
    }
    let token = tsa.token(&spec.signature, T + 10);
    let all = vec![token; MAX_TIMESTAMPS];
    assert_eq!(MAX_TIMESTAMPS, 32);
    let evidence = bundle(&pki, &spec, &all, true);
    assert_eq!(
        verify(&evidence, &IMAGE, &trust),
        accepted(Some(INTEGRATED), 32)
    );
    let mut over = all;
    over.push(over[0].clone());
    let value = with_tokens(spec.value(&pki), &over);
    assert_eq!(
        Evidence::from_bundle(&to_bytes(&value)).err(),
        Some(Refusal::TooManyTimestamps)
    );
}

#[test]
fn timestamp_data_shapes() {
    let pki = Pki::new();
    let spec = email_bundle(&pki);
    let field = ["verificationMaterial", "timestampVerificationData"];
    let token_entry = |value: Value| obj(vec![("signedTimestamp", value)]);
    for data in [
        s("x"),
        Value::Array(vec![]),
        obj(vec![("rfc3161Timestamps", s("x"))]),
        obj(vec![("rfc3161Timestamps", Value::Array(vec![s("x")]))]),
        obj(vec![("rfc3161Timestamps", Value::Array(vec![obj(vec![])]))]),
        obj(vec![(
            "rfc3161Timestamps",
            Value::Array(vec![token_entry(s(""))]),
        )]),
        obj(vec![(
            "rfc3161Timestamps",
            Value::Array(vec![token_entry(s("AA="))]),
        )]),
        obj(vec![(
            "rfc3161Timestamps",
            Value::Array(vec![token_entry(Value::Array(vec![]))]),
        )]),
        obj(vec![
            ("rfc3161Timestamps", Value::Array(vec![])),
            ("other", s("x")),
        ]),
    ] {
        let mut value = spec.value(&pki);
        set(&mut value, &field, data.clone());
        assert_eq!(
            Evidence::from_bundle(&to_bytes(&value)).err(),
            Some(Refusal::MalformedBundle),
            "{:?}",
            String::from_utf8(to_bytes(&data))
        );
    }
}

#[test]
fn imprint_over_wrong_bytes() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let trust = trusting(&tsa_root(&pki, &tsa));
    let spec = email_bundle(&pki);
    let other = BundleSpec::keyless(&pki, &LeafSpec::email(), &pki::OTHER_IMAGE);
    let pae = pae(IN_TOTO_PAYLOAD_TYPE.as_bytes(), &spec.statement);
    let text = base64::encode(&spec.signature);
    for (name, message) in [
        ("the PAE", pae.as_slice()),
        ("the payload", spec.statement.as_slice()),
        ("the signature's base64 text", text.as_bytes()),
        ("another bundle's signature", other.signature.as_slice()),
    ] {
        let evidence = bundle(&pki, &spec, &[tsa.token(message, T + 10)], false);
        assert_eq!(
            verify(&evidence, &IMAGE, &trust),
            Err(Refusal::Timestamp(TimestampError::Imprint)),
            "{name}"
        );
    }
}

#[test]
fn tsa_not_in_root() {
    let pki = Pki::new();
    let ours = Tsa::new(&pki);
    let attacker = Tsa::attacker(&pki);
    let spec = email_bundle(&pki);
    let token = attacker.token(&spec.signature, T + 10);
    // The root lists our TSA: the attacker's token names another leaf.
    let trust_ours = trusting(&tsa_root(&pki, &ours));
    assert_eq!(
        verify(
            &bundle(&pki, &spec, std::slice::from_ref(&token), false),
            &IMAGE,
            &trust_ours
        ),
        Err(Refusal::Timestamp(TimestampError::SigningCertificate))
    );
    // The root lists the attacker's leaf under our anchor: the attacker's
    // CA has our anchor's name, not its key.
    let forged = Tsa {
        anchor: pki.root.clone(),
        ..Tsa::attacker(&pki)
    };
    let trust_forged = trusting(&with_tsas(
        root_value(&pki),
        vec![forged.authority(EPOCH_2020, None)],
    ));
    assert_eq!(
        verify(
            &bundle(&pki, &spec, std::slice::from_ref(&token), false),
            &IMAGE,
            &trust_forged
        ),
        Err(Refusal::Timestamp(TimestampError::Chain(
            CertError::Invalid
        )))
    );
    // A TSA leaf from a CA of another name: no path to our anchor at all.
    let elsewhere = Tsa::issued(
        &pki.root,
        "Boneli attacker TSA root",
        &pki.attacker_key,
        pki::TSA_FROM,
        pki::TSA_TO,
    );
    let trust_elsewhere = trusting(&with_tsas(
        root_value(&pki),
        vec![elsewhere.authority(EPOCH_2020, None)],
    ));
    assert_eq!(
        verify(
            &bundle(
                &pki,
                &spec,
                &[elsewhere.token(&spec.signature, T + 10)],
                false
            ),
            &IMAGE,
            &trust_elsewhere
        ),
        Err(Refusal::Timestamp(TimestampError::Chain(
            CertError::UnknownIssuer
        )))
    );
    // The real token against a root without TSAs, and with them.
    let mut value = real::json(real::TRILLIAN_BUNDLE);
    let entries = value
        .get("verificationMaterial")
        .and_then(|m| m.get("tlogEntries"))
        .and_then(Value::as_array)
        .expect("entries");
    let mut entry = entries[0].clone();
    remove(&mut entry, &["inclusionPromise"]);
    set(
        &mut value,
        &["verificationMaterial", "tlogEntries"],
        Value::Array(vec![entry]),
    );
    let evidence = Evidence::from_bundle(&to_bytes(&value)).expect("bundle");
    let identity = || vec![real::trillian_identity()];
    let predicates = || vec![boneli_sigstore::COSIGN_SIGN_PREDICATE.to_owned()];
    let mut no_tsa = real::json(real::TRUSTED_ROOT);
    remove(&mut no_tsa, &["timestampAuthorities"]);
    let no_tsa = Trust::new(
        Vec::new(),
        Some((pki::trusted_root(&no_tsa), identity())),
        predicates(),
    )
    .expect("trust");
    assert_eq!(
        verify(&evidence, &real::TRILLIAN_DIGEST, &no_tsa),
        Err(Refusal::NoTsaAtTime)
    );
    let public_good = Trust::new(
        Vec::new(),
        Some((real::public_good(), identity())),
        predicates(),
    )
    .expect("trust");
    assert_eq!(
        verify(&evidence, &real::TRILLIAN_DIGEST, &public_good),
        Err(Refusal::TlogEntries)
    );
}

/// A TSA entry that cannot serve as a TSA chain (one certificate, or CAs
/// only) leaves the root readable, so a Rekor v1 bundle still verifies by
/// its SET, and a token that chains only to that entry does not count
/// (ADR-038, D4; review of PR #132, run 1).
#[test]
fn unusable_tsa_entry_anchors_no_token() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let spec = email_bundle(&pki);
    let token = tsa.token(&spec.signature, T + 10);
    for (chain, without_set) in [
        // The TSA's issuing CA alone: skipped, so the root has no TSA.
        (vec![&tsa.anchor[..]], Refusal::NoTsaAtTime),
        // The TSA's leaf alone: skipped too.
        (vec![&tsa.leaf[..]], Refusal::NoTsaAtTime),
        // CAs only: listed, but its first certificate is not the signer.
        (
            vec![&pki.intermediate[..], &pki.root[..]],
            Refusal::Timestamp(TimestampError::SigningCertificate),
        ),
    ] {
        let root = with_tsas(
            root_value(&pki),
            vec![pki::authority(&chain, EPOCH_2020, None)],
        );
        let trust = trusting(&root);
        assert_eq!(
            verify(&bundle(&pki, &spec, &[], true), &IMAGE, &trust),
            accepted(Some(INTEGRATED), 0)
        );
        assert_eq!(
            verify(
                &bundle(&pki, &spec, std::slice::from_ref(&token), true),
                &IMAGE,
                &trust
            ),
            accepted(Some(INTEGRATED), 0)
        );
        assert_eq!(
            verify(
                &bundle(&pki, &spec, std::slice::from_ref(&token), false),
                &IMAGE,
                &trust
            ),
            Err(without_set)
        );
    }
}

#[test]
fn embedded_certificates_not_read() {
    let pki = Pki::new();
    let ours = Tsa::new(&pki);
    let attacker = Tsa::attacker(&pki);
    let trust = trusting(&tsa_root(&pki, &ours));
    let spec = email_bundle(&pki);
    // The attacker's leaf in `certificates [0]`, the token signed by it.
    let token = attacker.token_with(&spec.signature, T + 10, Some(attacker.leaf.clone()));
    assert_eq!(
        verify(&bundle(&pki, &spec, &[token], true), &IMAGE, &trust),
        accepted(Some(INTEGRATED), 0)
    );
    assert_eq!(
        verify(
            &bundle(
                &pki,
                &spec,
                &[attacker.token_with(&spec.signature, T + 10, Some(attacker.leaf.clone()))],
                false
            ),
            &IMAGE,
            &trust
        ),
        Err(Refusal::Timestamp(TimestampError::SigningCertificate))
    );
    // Bytes that are no certificate at all, in a token of our TSA.
    let token = ours.token_with(&spec.signature, T + 10, Some(vec![0xFF, 0x00, 0x13, 0x37]));
    assert_eq!(
        verify(&bundle(&pki, &spec, &[token], true), &IMAGE, &trust),
        accepted(Some(INTEGRATED), 1)
    );
}

#[test]
fn builders_round_trip() {
    let pki = Pki::new();
    let tsa = Tsa::new(&pki);
    let message = b"round trip";
    let token = TimestampToken::from_response_der(&tsa.token(message, T + 42)).expect("token");
    assert_eq!(token.gen_time(), T + 42);
    assert_eq!(token.message_imprint(), &Sha256::digest(message));
    assert_eq!(token.verify(message, &tsa.leaf, &[], &tsa.anchor), Ok(()));
}

#[test]
fn refusal_texts() {
    for (refusal, text) in [
        (
            Refusal::NoTimeSource,
            "a keyless signature needs an inclusion promise or a verified timestamp",
        ),
        (
            Refusal::NoTsaAtTime,
            "no trusted timestamp authority is valid at the timestamp's time",
        ),
        (
            Refusal::TooManyTimestamps,
            "the bundle carries too many timestamps",
        ),
        (
            Refusal::Timestamp(TimestampError::Imprint),
            "the timestamp does not verify: the timestamp is not over the signature",
        ),
    ] {
        assert_eq!(refusal.to_string(), text);
    }
}
