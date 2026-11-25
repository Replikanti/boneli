//! Rekor v2 `hashedrekord` 0.0.2 entries (ADR-038, D2, D6 and D7): the
//! real bundles of `log2025-1` as known answers, then every rule over the
//! synthetic v2 log of `support::pki` (an Ed25519 key that signs its
//! checkpoints, a P-256 leaf, the test TSA for the time).

mod support;

use boneli_json::Value;
use boneli_sigstore::{
    Accepted, COSIGN_SIGN_PREDICATE, Evidence, IN_TOTO_PAYLOAD_TYPE, Refusal,
    SLSA_PROVENANCE_V1_PREDICATE, Trust, TrustedRoot, base64, pae, verify,
};
use support::pki::{
    self, BundleSpec, EPOCH_2020, IMAGE, LeafSpec, NoteLog, Pki, T, Tsa, V2_INDEX, V2_ORIGIN,
    V2Spec, email_identity, keyless_trust_in, note_body, remove, rfc3339_ms, root_value, set,
    to_bytes, v2_root, with_tsas, witness_line,
};
use support::real;

/// The genTime of every synthetic token: inside the leaf's validity.
const AT: u64 = T + 10;

struct Fixture {
    pki: Pki,
    log: NoteLog,
    tsa: Tsa,
    trust: Trust,
}

fn fixture() -> Fixture {
    let pki = Pki::new();
    let log = NoteLog::new();
    let tsa = Tsa::new(&pki);
    let trust = keyless_trust_in(&v2_root(&pki, &log, &tsa), vec![email_identity()]);
    Fixture {
        pki,
        log,
        tsa,
        trust,
    }
}

impl Fixture {
    fn spec(&self) -> V2Spec {
        V2Spec::new(&self.pki, &self.log, &IMAGE)
    }

    /// The verdict over `spec` with one token of the test TSA at `AT`.
    fn verdict(&self, spec: &V2Spec) -> Result<Accepted, Refusal> {
        self.verdict_under(spec, &self.trust)
    }

    fn verdict_under(&self, spec: &V2Spec, trust: &Trust) -> Result<Accepted, Refusal> {
        let token = self.tsa.token(&spec.signature, AT);
        verify(&spec.evidence(&[token])?, &IMAGE, trust)
    }
}

fn accepted_at(log_index: u64) -> Result<Accepted, Refusal> {
    Ok(Accepted::Keyless {
        integrated_time: None,
        signed_timestamps: 1,
        log_index,
        identity: 0,
    })
}

fn public_good_trust(identity: boneli_sigstore::Identity, predicate: &str) -> Trust {
    Trust::new(
        Vec::new(),
        Some((real::public_good(), vec![identity])),
        vec![predicate.to_owned()],
    )
    .expect("trust")
}

// ---- Real known answers ------------------------------------------------

/// The two real v2 bundles whose statements a bundle may carry verify
/// against the public-good root, their time from their token alone.
#[test]
fn real_rekor_v2_bundles_verify() {
    let trust = public_good_trust(real::bex_identity(), COSIGN_SIGN_PREDICATE);
    assert_eq!(
        verify(&real::bex(), &real::BEX_DIGEST, &trust),
        accepted_at(real::BEX_LOG_INDEX)
    );
    let trust = public_good_trust(real::aicr_identity(), SLSA_PROVENANCE_V1_PREDICATE);
    let aicr = Evidence::from_bundle(real::AICR_RECIPE_BUNDLE).expect("aicr bundle");
    assert_eq!(
        verify(&aicr, &real::AICR_RECIPE_DIGEST, &trust),
        accepted_at(real::AICR_RECIPE_LOG_INDEX)
    );
    // Another identity is still refused after the entry passed.
    let other = public_good_trust(real::aicr_identity(), COSIGN_SIGN_PREDICATE);
    assert_eq!(
        verify(&real::bex(), &real::BEX_DIGEST, &other),
        Err(Refusal::IdentityMismatch)
    );
}

/// The body rebuilt from each real bundle equals its `canonicalizedBody`
/// byte for byte (3 of 3, the SBOM bundle included), and a synthetic
/// bundle reads back what it was built from.
#[test]
fn builders_round_trip() {
    for bytes in [
        real::BEX_BUNDLE,
        real::AICR_RECIPE_BUNDLE,
        real::AICR_SBOM_BUNDLE,
    ] {
        let bundle = real::json(bytes);
        let material = bundle.get("verificationMaterial").expect("material");
        let certificate = base64::decode(
            material
                .get("certificate")
                .and_then(|c| c.get("rawBytes"))
                .and_then(Value::as_str)
                .expect("certificate")
                .as_bytes(),
        )
        .expect("base64");
        let envelope = bundle.get("dsseEnvelope").expect("envelope");
        let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).expect(key).to_owned();
        let payload = base64::decode(text(envelope, "payload").as_bytes()).expect("payload");
        let signatures = envelope
            .get("signatures")
            .and_then(Value::as_array)
            .expect("signatures");
        let signature = base64::decode(text(&signatures[0], "sig").as_bytes()).expect("sig");
        let entry = &material
            .get("tlogEntries")
            .and_then(Value::as_array)
            .expect("entries")[0];
        let body = base64::decode(text(entry, "canonicalizedBody").as_bytes()).expect("body");
        let rebuilt = pki::hashedrekord_v2(
            &pae(IN_TOTO_PAYLOAD_TYPE.as_bytes(), &payload),
            &signature,
            &certificate,
            "PKIX_ECDSA_P256_SHA_256",
        );
        assert_eq!(rebuilt, body);
    }
    // The synthetic proof reaches the synthetic root by the support code's
    // own RFC 6962 tree, and the checkpoint names it.
    let f = fixture();
    let spec = f.spec();
    assert!(
        spec.checkpoint
            .starts_with(&note_body(V2_ORIGIN, spec.size, &spec.root))
    );
    assert_eq!(f.verdict(&spec), accepted_at(V2_INDEX));
}

// ---- The body ----------------------------------------------------------

#[test]
fn v2_body_rules() {
    let f = fixture();
    let base = f.spec();
    let message = base.message();
    let other_leaf = pki::p256(&LeafSpec {
        serial: 8,
        ..LeafSpec::email()
    })
    .build(&f.pki);
    let other_signature = pki::p256_leaf_key().sign(b"another message").expect("sign");
    let bodies = [
        (
            "the signature",
            pki::hashedrekord_v2(
                &message,
                &other_signature,
                &base.certificate,
                "PKIX_ECDSA_P256_SHA_256",
            ),
        ),
        (
            "the certificate",
            pki::hashedrekord_v2(
                &message,
                &base.signature,
                &other_leaf,
                "PKIX_ECDSA_P256_SHA_256",
            ),
        ),
        (
            "the digest",
            pki::hashedrekord_v2(
                b"another message",
                &base.signature,
                &base.certificate,
                "PKIX_ECDSA_P256_SHA_256",
            ),
        ),
        (
            "the key details",
            pki::hashedrekord_v2(
                &message,
                &base.signature,
                &base.certificate,
                "PKIX_ECDSA_P384_SHA_384",
            ),
        ),
        (
            "the serialization",
            to_bytes(&real::json(&base.body))
                .into_iter()
                .fold(Vec::new(), |mut out, b| {
                    out.push(b);
                    if b == b',' {
                        out.push(b' ');
                    }
                    out
                }),
        ),
    ];
    for (name, body) in bodies {
        let mut spec = base.clone();
        spec.body = body;
        // A valid proof and checkpoint over the changed body: only the
        // rebuild can refuse it.
        spec.seal(&f.log);
        assert_eq!(f.verdict(&spec), Err(Refusal::BodyMismatch), "{name}");
    }

    // `kindVersion` must name the body's kind and version.
    let mut spec = base.clone();
    spec.version = "0.0.1".to_owned();
    assert_eq!(spec.evidence(&[]).err(), Some(Refusal::MalformedTlogEntry));

    // A Rekor v2 `dsse` 0.0.2 entry is not read (out of scope).
    let mut spec = base.clone();
    spec.kind = "dsse".to_owned();
    spec.body = br#"{"apiVersion":"0.0.2","kind":"dsse","spec":{}}"#.to_vec();
    spec.seal(&f.log);
    assert_eq!(f.verdict(&spec), Err(Refusal::EntryKind));
    let mut spec = base.clone();
    spec.version = "0.0.1".to_owned();
    spec.body = br#"{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{}}"#.to_vec();
    spec.seal(&f.log);
    assert_eq!(f.verdict(&spec), Err(Refusal::EntryKind));

    // An RSA leaf: Rekor v2 bodies here are P-256 only.
    let mut spec = base.clone();
    spec.certificate = LeafSpec::email().build(&f.pki);
    spec.signature = f.pki.leaf_key.sign(&message);
    spec.body = pki::hashedrekord_v2(
        &message,
        &spec.signature,
        &spec.certificate,
        "PKIX_RSA_PKCS1V15_2048_SHA256",
    );
    spec.seal(&f.log);
    assert_eq!(f.verdict(&spec), Err(Refusal::EntryKeyKind));

    // The real aicr entry, which is in the log with a valid proof and
    // checkpoint, attached to the bex envelope: the body the proof commits
    // to is not the one the bex signature rebuilds.
    let aicr = real::json(real::AICR_RECIPE_BUNDLE);
    let entries = aicr
        .get("verificationMaterial")
        .and_then(|m| m.get("tlogEntries"))
        .expect("entries")
        .clone();
    let mut bex = real::json(real::BEX_BUNDLE);
    set(&mut bex, &["verificationMaterial", "tlogEntries"], entries);
    let evidence = Evidence::from_bundle(&to_bytes(&bex)).expect("bundle");
    let trust = public_good_trust(real::bex_identity(), COSIGN_SIGN_PREDICATE);
    assert_eq!(
        verify(&evidence, &real::BEX_DIGEST, &trust),
        Err(Refusal::BodyMismatch)
    );
}

// ---- The log -----------------------------------------------------------

#[test]
fn v2_log_lookup() {
    let f = fixture();
    // A log ID no log of the root has.
    let mut spec = f.spec();
    spec.log_id = [7; 32];
    assert_eq!(f.verdict(&spec), Err(Refusal::UnknownLog));
    // The Rekor v1 log's ID without a promise: a v1 entry needs its SET.
    let mut spec = f.spec();
    spec.log_id = f.pki.rekor_key.id();
    assert_eq!(f.verdict(&spec), Err(Refusal::TlogEntries));
    // The v2 log's ID in an entry with a promise: no v1 log has it.
    let mut v1 = BundleSpec::keyless(&f.pki, &LeafSpec::email(), &IMAGE);
    v1.entry.log_id = f.log.key_id();
    let evidence = Evidence::from_bundle(&v1.bytes(&f.pki)).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &f.trust),
        Err(Refusal::UnknownLog)
    );
    // A root that does not list the v2 log.
    let without = keyless_trust_in(
        &with_tsas(root_value(&f.pki), vec![f.tsa.authority(EPOCH_2020, None)]),
        vec![email_identity()],
    );
    assert_eq!(
        f.verdict_under(&f.spec(), &without),
        Err(Refusal::UnknownLog)
    );
    // The real bex bundle against the public-good root without log2025-1.
    let mut root = real::json(real::TRUSTED_ROOT);
    let tlogs = root
        .get("tlogs")
        .and_then(Value::as_array)
        .expect("tlogs")
        .iter()
        .filter(|l| {
            l.get("publicKey")
                .and_then(|k| k.get("keyDetails"))
                .and_then(Value::as_str)
                != Some("PKIX_ED25519")
        })
        .cloned()
        .collect();
    set(&mut root, &["tlogs"], Value::Array(tlogs));
    let root = std::sync::Arc::new(TrustedRoot::from_json(&to_bytes(&root)).expect("root"));
    assert_eq!(root.note_log_count(), 0);
    let trust = Trust::new(
        Vec::new(),
        Some((root, vec![real::bex_identity()])),
        vec![COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust");
    assert_eq!(
        verify(&real::bex(), &real::BEX_DIGEST, &trust),
        Err(Refusal::UnknownLog)
    );
}

#[test]
fn v2_log_window_bounds() {
    let f = fixture();
    let spec = f.spec();
    let at_ms = AT * 1_000;
    let with_window = |start: &str, end: Option<&str>| {
        let mut root = with_tsas(root_value(&f.pki), vec![f.tsa.authority(EPOCH_2020, None)]);
        let mut tlogs = root
            .get("tlogs")
            .and_then(Value::as_array)
            .expect("tlogs")
            .to_vec();
        tlogs.push(f.log.instance(start, end));
        set(&mut root, &["tlogs"], Value::Array(tlogs));
        keyless_trust_in(&root, vec![email_identity()])
    };
    for (start, end, ok) in [
        (
            EPOCH_2020.to_owned(),
            Some(rfc3339_ms(at_ms - 1_000)),
            false,
        ),
        (EPOCH_2020.to_owned(), Some(rfc3339_ms(at_ms)), true),
        (rfc3339_ms(at_ms), None, true),
        (rfc3339_ms(at_ms + 1_000), None, false),
    ] {
        let trust = with_window(&start, end.as_deref());
        let expected = if ok {
            accepted_at(V2_INDEX)
        } else {
            Err(Refusal::LogOutsideWindow)
        };
        assert_eq!(f.verdict_under(&spec, &trust), expected, "{start} {end:?}");
    }
    // The window must hold every verified time, not only the first.
    let trust = with_window(EPOCH_2020, Some(&rfc3339_ms(at_ms)));
    let tokens = [
        f.tsa.token(&spec.signature, AT),
        f.tsa.token(&spec.signature, AT + 20),
    ];
    let evidence = spec.evidence(&tokens).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &trust),
        Err(Refusal::LogOutsideWindow)
    );
    let trust = with_window(EPOCH_2020, Some(&rfc3339_ms(at_ms + 20_000)));
    assert_eq!(
        verify(&evidence, &IMAGE, &trust),
        Ok(Accepted::Keyless {
            integrated_time: None,
            signed_timestamps: 2,
            log_index: V2_INDEX,
            identity: 0,
        })
    );
}

/// A v2 entry carries no time: without a token that verifies there is
/// none (ADR-038 AC 4, conformance `rekor2-no-timestamp_fail`).
#[test]
fn rekor_v2_needs_a_timestamp() {
    let f = fixture();
    let spec = f.spec();
    let evidence = spec.evidence(&[]).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &f.trust),
        Err(Refusal::NoTimeSource)
    );
    let failing = f.tsa.token(b"another message", AT);
    let evidence = spec.evidence(&[failing]).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &f.trust),
        Err(Refusal::Timestamp(boneli_https::TimestampError::Imprint))
    );
    // A token outside the leaf's validity: the chain refuses, as for v1.
    let late = f.tsa.token(&spec.signature, T + pki::LIFETIME + 1);
    let evidence = spec.evidence(&[late]).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &f.trust),
        Err(Refusal::Certificate(
            boneli_https::CertError::OutsideValidity
        ))
    );
}

// ---- The inclusion proof -----------------------------------------------

/// Every index of every tree size from 1 to 17 verifies: the head, the
/// tail, and a tree of one leaf with no hashes.
#[test]
fn merkle_paths_all_indices() {
    let f = fixture();
    let mut spec = f.spec();
    let token = f.tsa.token(&spec.signature, AT);
    for size in 1..=17u64 {
        for index in 0..size {
            spec.size = size;
            spec.index = index;
            spec.proof_index = index;
            spec.seal(&f.log);
            if size == 1 {
                assert!(spec.hashes.is_empty());
            }
            let evidence = spec.evidence(std::slice::from_ref(&token)).expect("bundle");
            assert_eq!(
                verify(&evidence, &IMAGE, &f.trust),
                accepted_at(index),
                "{index} of {size}"
            );
        }
    }
}

#[test]
fn inclusion_proof_rejections() {
    let f = fixture();
    let base = f.spec();
    assert!(base.hashes.len() >= 2);
    let mut cases: Vec<(&str, V2Spec)> = Vec::new();
    for at in [0, base.hashes.len() - 1] {
        let mut spec = base.clone();
        spec.hashes[at][31] ^= 1;
        cases.push(("a flipped hash", spec));
    }
    let mut spec = base.clone();
    spec.hashes.push([0; 32]);
    cases.push(("an extra hash", spec));
    let mut spec = base.clone();
    spec.hashes.pop();
    cases.push(("a missing hash", spec));
    let mut spec = base.clone();
    spec.hashes.clear();
    cases.push(("no hash", spec));
    let mut spec = base.clone();
    spec.index = spec.size;
    spec.proof_index = spec.size;
    cases.push(("index = size", spec));
    let mut spec = base.clone();
    spec.index = spec.size + 1;
    spec.proof_index = spec.size + 1;
    cases.push(("index > size", spec));
    for delta in [-1i64, 1] {
        let mut spec = base.clone();
        spec.proof_index = (spec.index as i64 + delta) as u64;
        cases.push(("proof index != entry index", spec));
    }
    // A valid proof of index 5 under an entry that says index 4.
    let mut spec = base.clone();
    spec.index = V2_INDEX + 1;
    spec.proof_index = V2_INDEX + 1;
    spec.seal(&f.log);
    spec.index = V2_INDEX;
    cases.push(("an entry index the proof does not have", spec));
    // A tree of one leaf, the body, claimed at index 1: the empty path
    // would reach the root from there too.
    let mut spec = base.clone();
    spec.size = 1;
    spec.index = 0;
    spec.proof_index = 0;
    spec.seal(&f.log);
    spec.index = 1;
    spec.proof_index = 1;
    cases.push(("index 1 of a tree of one", spec));
    // A hash past the path, and a log that signed the root that hash
    // leads to: RFC 9162 stops at the end of the path all the same.
    let mut spec = base.clone();
    let extra = [0x42; 32];
    spec.root = pki::node_hash(&extra, &spec.root);
    spec.hashes.push(extra);
    spec.checkpoint = f.log.checkpoint(spec.size, &spec.root);
    cases.push(("a hash past the path to a signed root", spec));
    // The path of a tree of 4 under a checkpoint of 8 the log signed over
    // the smaller tree's root: a path cut short.
    let mut spec = base.clone();
    spec.size = 4;
    spec.index = 1;
    spec.proof_index = 1;
    spec.seal(&f.log);
    spec.size = 8;
    spec.checkpoint = f.log.checkpoint(8, &spec.root);
    cases.push(("a path cut short under a signed root", spec));
    // The path of index 4 claimed for index 5, with a checkpoint over the
    // same root.
    let mut spec = base.clone();
    spec.index = V2_INDEX + 1;
    spec.proof_index = V2_INDEX + 1;
    cases.push(("another position", spec));
    // A tree of one leaf that is not the body.
    let mut spec = base.clone();
    spec.size = 1;
    spec.index = 0;
    spec.proof_index = 0;
    spec.seal(&f.log);
    let other = pki::leaf_hash(b"other entry 0");
    spec.root = other;
    spec.checkpoint = f.log.checkpoint(1, &other);
    cases.push(("one leaf, another body", spec));
    for (name, spec) in cases {
        assert_eq!(f.verdict(&spec), Err(Refusal::InclusionProof), "{name}");
    }
}

// ---- The checkpoint ----------------------------------------------------

#[test]
fn checkpoint_rules() {
    let f = fixture();
    let base = f.spec();
    let (size, root) = (base.size, base.root);
    let body = note_body(V2_ORIGIN, size, &root);
    let key_id = f.log.key_id();
    let log_line = f.log.line(V2_ORIGIN, &key_id, &body);
    let witness = witness_line("witness.boneli.test");
    // A checkpoint signed by the log key over `text`, named `origin`, with
    // the hint of the log's key ID from the root, as anyone holding a real
    // checkpoint can copy it: only the key-ID binding of the origin tells
    // another origin apart.
    let signed_as =
        |origin: &str, text: &str| format!("{text}\n{}", f.log.line(origin, &key_id, text));
    let refused: Vec<(&str, String)> = vec![
        (
            "a bad log signature",
            format!(
                "{body}\n{}",
                f.log
                    .line(V2_ORIGIN, &key_id, &note_body(V2_ORIGIN, size + 1, &root))
            ),
        ),
        ("two log lines", format!("{body}\n{log_line}{log_line}")),
        ("no log line", format!("{body}\n{witness}")),
        (
            "a wrong key hint",
            format!("{body}\n{}", f.log.line(V2_ORIGIN, &[9; 32], &body)),
        ),
        (
            "the log line under another name",
            format!(
                "{body}\n{}",
                f.log.line("witness.boneli.test", &key_id, &body)
            ),
        ),
        (
            "another origin",
            signed_as(
                "other.boneli.test",
                &note_body("other.boneli.test", size, &root),
            ),
        ),
        (
            "a Cyrillic look-alike origin",
            signed_as(
                "rek\u{043E}r-v2.boneli.test",
                &note_body("rek\u{043E}r-v2.boneli.test", size, &root),
            ),
        ),
        (
            "a zero-width space",
            signed_as(
                "rekor-v2.boneli.test\u{200B}",
                &note_body("rekor-v2.boneli.test\u{200B}", size, &root),
            ),
        ),
        (
            "a trailing space",
            signed_as(
                "rekor-v2.boneli.test ",
                &note_body("rekor-v2.boneli.test ", size, &root),
            ),
        ),
        (
            "an en dash",
            format!("{body}\n{}", log_line.replace('\u{2014}', "\u{2013}")),
        ),
        (
            "a minus sign",
            format!("{body}\n{}", log_line.replace('\u{2014}', "\u{2212}")),
        ),
        (
            "a hyphen",
            format!("{body}\n{}", log_line.replace('\u{2014}', "-")),
        ),
        ("CRLF", format!("{body}\n{log_line}").replace('\n', "\r\n")),
        (
            "a signed CRLF body",
            signed_as(V2_ORIGIN, &body.replace('\n', "\r\n")),
        ),
        (
            "a control character in a witness name",
            format!("{body}\n{log_line}{}", witness_line("wit\u{7}ness")),
        ),
        ("no blank line", format!("{body}{log_line}")),
        ("two blank lines", format!("{body}\n\n{log_line}")),
        ("no signature", format!("{body}\n")),
        (
            "no final newline",
            format!("{body}\n{}", log_line.trim_end_matches('\n')),
        ),
        (
            "a leading zero in the size",
            signed_as(
                V2_ORIGIN,
                &format!("{V2_ORIGIN}\n0{size}\n{}\n", base64::encode(&root)),
            ),
        ),
        (
            "a sign in the size",
            signed_as(
                V2_ORIGIN,
                &format!("{V2_ORIGIN}\n+{size}\n{}\n", base64::encode(&root)),
            ),
        ),
        (
            "a root of 31 bytes",
            signed_as(
                V2_ORIGIN,
                &format!("{V2_ORIGIN}\n{size}\n{}\n", base64::encode(&root[..31])),
            ),
        ),
        (
            "a CR in an extension line",
            signed_as(V2_ORIGIN, &format!("{body}ext\rension\n")),
        ),
        (
            "an empty extension line",
            signed_as(V2_ORIGIN, &format!("{body}\nextension\n")),
        ),
        (
            "a size the proof does not have",
            signed_as(V2_ORIGIN, &note_body(V2_ORIGIN, size + 1, &root)),
        ),
        (
            "a root the proof does not have",
            signed_as(V2_ORIGIN, &note_body(V2_ORIGIN, size, &[0x11; 32])),
        ),
        (
            "a signature of 63 bytes",
            format!(
                "{body}\n\u{2014} {V2_ORIGIN} {}\n",
                base64::encode(
                    &[
                        &key_id[..4],
                        &f.log.key.sign(body.as_bytes()).expect("sign")[..63]
                    ]
                    .concat()
                )
            ),
        ),
    ];
    for (name, checkpoint) in refused {
        let mut spec = base.clone();
        spec.checkpoint = checkpoint;
        assert_eq!(f.verdict(&spec), Err(Refusal::Checkpoint), "{name}");
    }
    let passes: Vec<(&str, String)> = vec![
        ("no witness", format!("{body}\n{log_line}")),
        (
            "an unknown witness more",
            format!(
                "{body}\n{witness}{log_line}{}",
                witness_line("other-witness.boneli.test")
            ),
        ),
        (
            "an extension line",
            signed_as(V2_ORIGIN, &format!("{body}extension line\n")),
        ),
    ];
    for (name, checkpoint) in passes {
        let mut spec = base.clone();
        spec.checkpoint = checkpoint;
        assert_eq!(f.verdict(&spec), accepted_at(V2_INDEX), "{name}");
    }
}

#[test]
fn proof_fields_read_strictly() {
    let f = fixture();
    let spec = f.spec();
    let good = spec.value(&[]);
    let entry = spec.entry();
    let proof = ["inclusionProof"];
    for (path, new) in [
        (&["inclusionProof", "logIndex"][..], pki::s("04")),
        (&["inclusionProof", "logIndex"][..], pki::s("-1")),
        (&["inclusionProof", "treeSize"][..], pki::s("")),
        (
            &["inclusionProof", "treeSize"][..],
            pki::s("9223372036854775808"),
        ),
        (&["inclusionProof", "rootHash"][..], pki::s("AAAA")),
        (
            &["inclusionProof", "hashes"][..],
            Value::Array(vec![pki::s("AAAA")]),
        ),
        (&["inclusionProof", "hashes"][..], pki::s("x")),
        (&["inclusionProof", "checkpoint"][..], pki::s("x")),
        (
            &["inclusionProof", "checkpoint"][..],
            pki::obj(vec![("envelope", Value::Array(vec![]))]),
        ),
        (&proof[..], pki::s("x")),
    ] {
        let mut e = entry.clone();
        set(&mut e, path, new.clone());
        let mut b = good.clone();
        set(
            &mut b,
            &["verificationMaterial", "tlogEntries"],
            Value::Array(vec![e]),
        );
        assert_eq!(
            Evidence::from_bundle(&to_bytes(&b)).err(),
            Some(Refusal::MalformedTlogEntry),
            "{path:?} {new:?}"
        );
    }
    for path in [
        &["inclusionProof"][..],
        &["inclusionProof", "logIndex"][..],
        &["inclusionProof", "treeSize"][..],
        &["inclusionProof", "rootHash"][..],
        &["inclusionProof", "hashes"][..],
        &["inclusionProof", "checkpoint"][..],
        &["inclusionProof", "checkpoint", "envelope"][..],
    ] {
        let mut e = entry.clone();
        remove(&mut e, path);
        let mut b = good.clone();
        set(
            &mut b,
            &["verificationMaterial", "tlogEntries"],
            Value::Array(vec![e]),
        );
        assert_eq!(
            Evidence::from_bundle(&to_bytes(&b)).err(),
            Some(Refusal::MalformedTlogEntry),
            "{path:?}"
        );
    }
}

/// The public-good root keeps `log2025-1` as a v2 log; a log whose key
/// ID is not its key's SHA-256 counts as one only with an Ed25519 key.
#[test]
fn root_note_logs() {
    let root = TrustedRoot::from_json(real::TRUSTED_ROOT).expect("public-good root");
    assert_eq!((root.tlog_count(), root.note_log_count()), (1, 1));
    assert_eq!(
        format!("{root:?}"),
        "TrustedRoot { tlogs: 1, note_logs: 1, authorities: 2, ctlogs: 2, tsas: 1 }"
    );
    let f = fixture();
    let root = TrustedRoot::from_json(&to_bytes(&v2_root(&f.pki, &f.log, &f.tsa))).expect("root");
    assert_eq!((root.tlog_count(), root.note_log_count()), (1, 1));
    // An RSA log under a key ID that is not its key's SHA-256: left out.
    let mut v = root_value(&f.pki);
    let mut log = pki::log_instance(&f.pki.rekor_key, EPOCH_2020, None);
    set(
        &mut log,
        &["logId", "keyId"],
        pki::s(&base64::encode(&f.log.key_id())),
    );
    set(&mut v, &["tlogs"], Value::Array(vec![log]));
    let root = TrustedRoot::from_json(&to_bytes(&v)).expect("root");
    assert_eq!((root.tlog_count(), root.note_log_count()), (0, 0));
    // The Ed25519 key of a v2 log listed under its SHA-256: a v1 log.
    let mut v = root_value(&f.pki);
    let mut log = f.log.instance(EPOCH_2020, None);
    set(
        &mut log,
        &["logId", "keyId"],
        pki::s(&base64::encode(&f.log.key.public_key().key_id())),
    );
    set(&mut v, &["tlogs"], Value::Array(vec![log]));
    let root = TrustedRoot::from_json(&to_bytes(&v)).expect("root");
    assert_eq!((root.tlog_count(), root.note_log_count()), (1, 0));
    // A v2 log's window reads as every other.
    let mut v = root_value(&f.pki);
    set(
        &mut v,
        &["tlogs"],
        Value::Array(vec![
            f.log.instance("2026-01-01T00:00:00Z", Some(EPOCH_2020)),
        ]),
    );
    assert_eq!(
        TrustedRoot::from_json(&to_bytes(&v)).err(),
        Some(boneli_sigstore::ConfigError::RootReversedWindow)
    );
}

#[test]
fn refusal_texts() {
    for (refusal, text) in [
        (
            Refusal::InclusionProof,
            "the inclusion proof does not reach the checkpoint's root",
        ),
        (
            Refusal::Checkpoint,
            "the checkpoint is malformed or not signed by the transparency log",
        ),
        (
            Refusal::EntryKeyKind,
            "the transparency log entry's key kind is not supported",
        ),
    ] {
        assert_eq!(refusal.to_string(), text);
    }
}
