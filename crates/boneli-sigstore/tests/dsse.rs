//! DSSE and the in-toto statement (ADR-029, S5): PAE, the envelope's
//! shape, the statement type, the subjects and the predicate type.

mod support;

use boneli_json::Value;
use boneli_sigstore::{
    COSIGN_SIGN_PREDICATE, Evidence, Refusal, SLSA_PROVENANCE_V1_PREDICATE, pae, verify,
};
use support::pki::{
    self, IMAGE, OTHER_IMAGE, Pki, hex, keyed_bundle, keyed_trust, s, set, statement, to_bytes,
};

fn keyed(
    pki: &Pki,
    statement: &[u8],
    predicates: &[&str],
) -> Result<boneli_sigstore::Accepted, Refusal> {
    let evidence = Evidence::from_bundle(&to_bytes(&keyed_bundle(&pki.signer_key, statement)))?;
    verify(&evidence, &IMAGE, &keyed_trust(pki, predicates))
}

#[test]
fn pae_known_answer() {
    // The DSSE specification's example.
    assert_eq!(
        pae(b"http://example.com/HelloWorld", b"hello world"),
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
    );
    assert_eq!(pae(b"", b""), b"DSSEv1 0  0 ".to_vec());
    // Lengths count bytes, not characters.
    assert_eq!(
        pae("é".as_bytes(), b"x"),
        "DSSEv1 2 é 1 x".as_bytes().to_vec()
    );
}

#[test]
fn keyed_statement_passes() {
    let pki = Pki::new();
    let st = statement(&[&hex(&IMAGE)], COSIGN_SIGN_PREDICATE);
    assert_eq!(
        keyed(&pki, &st, &[COSIGN_SIGN_PREDICATE]),
        Ok(boneli_sigstore::Accepted::Keyed { key: 0 })
    );
}

#[test]
fn matching_second_subject_passes() {
    let pki = Pki::new();
    let st = statement(&[&hex(&OTHER_IMAGE), &hex(&IMAGE)], COSIGN_SIGN_PREDICATE);
    assert!(keyed(&pki, &st, &[COSIGN_SIGN_PREDICATE]).is_ok());
    let st = statement(&[&hex(&OTHER_IMAGE)], COSIGN_SIGN_PREDICATE);
    assert_eq!(
        keyed(&pki, &st, &[COSIGN_SIGN_PREDICATE]),
        Err(Refusal::SubjectMismatch)
    );
    let st = statement(&[], COSIGN_SIGN_PREDICATE);
    assert_eq!(
        keyed(&pki, &st, &[COSIGN_SIGN_PREDICATE]),
        Err(Refusal::SubjectMismatch)
    );
}

#[test]
fn digest_forms_refused() {
    let pki = Pki::new();
    let lower = hex(&IMAGE);
    for digest in [
        lower.to_uppercase(),
        format!("sha256:{lower}"),
        format!("{lower}0"),
        lower[..63].to_owned(),
        lower.replacen('5', "\u{ff15}", 1),
        format!("{lower}\u{200b}"),
    ] {
        let st = statement(&[&digest], COSIGN_SIGN_PREDICATE);
        assert_eq!(
            keyed(&pki, &st, &[COSIGN_SIGN_PREDICATE]),
            Err(Refusal::SubjectMismatch),
            "{digest}"
        );
    }
    // A sha512 digest of the same text does not stand in for sha256.
    let mut st: Value = support::real::json(&statement(&[&lower], COSIGN_SIGN_PREDICATE));
    let subject = pki::obj(vec![("digest", pki::obj(vec![("sha512", s(&lower))]))]);
    set(&mut st, &["subject"], Value::Array(vec![subject]));
    assert_eq!(
        keyed(&pki, &to_bytes(&st), &[COSIGN_SIGN_PREDICATE]),
        Err(Refusal::SubjectMismatch)
    );
}

#[test]
fn predicate_type_exact() {
    let pki = Pki::new();
    for predicate in [
        "https://sigstore.dev/cosign/sign/v1 ",
        "http://sigstore.dev/cosign/sign/v1",
        "https://sigstore.dev/cosign%2Fsign/v1",
        "https://sigstore.dev/cosign/sign/v1/",
        "https://Sigstore.dev/cosign/sign/v1",
    ] {
        let st = statement(&[&hex(&IMAGE)], predicate);
        assert_eq!(
            keyed(&pki, &st, &[COSIGN_SIGN_PREDICATE]),
            Err(Refusal::PredicateType),
            "{predicate}"
        );
    }
    // SLSA provenance is opt-in.
    let st = statement(&[&hex(&IMAGE)], SLSA_PROVENANCE_V1_PREDICATE);
    assert_eq!(
        keyed(&pki, &st, &[COSIGN_SIGN_PREDICATE]),
        Err(Refusal::PredicateType)
    );
    assert!(
        keyed(
            &pki,
            &st,
            &[COSIGN_SIGN_PREDICATE, SLSA_PROVENANCE_V1_PREDICATE]
        )
        .is_ok()
    );
    // An empty list admits no bundle.
    let st = statement(&[&hex(&IMAGE)], COSIGN_SIGN_PREDICATE);
    assert_eq!(keyed(&pki, &st, &[]), Err(Refusal::PredicateType));
}

#[test]
fn predicate_annotation_lies() {
    // The registry annotation says cosign sign; the signed statement is
    // an SBOM. Only the statement counts.
    let pki = Pki::new();
    let st = statement(&[&hex(&IMAGE)], "https://spdx.dev/Document");
    assert_eq!(
        keyed(&pki, &st, &[COSIGN_SIGN_PREDICATE]),
        Err(Refusal::PredicateType)
    );
}

#[test]
fn statement_type_exact() {
    let pki = Pki::new();
    for kind in [
        "https://in-toto.io/Statement/v0.1",
        "https://in-toto.io/Statement/v1 ",
        "https://in-toto.io/statement/v1",
    ] {
        let mut st: Value = support::real::json(&statement(&[&hex(&IMAGE)], COSIGN_SIGN_PREDICATE));
        set(&mut st, &["_type"], s(kind));
        assert_eq!(
            keyed(&pki, &to_bytes(&st), &[COSIGN_SIGN_PREDICATE]),
            Err(Refusal::StatementType),
            "{kind}"
        );
    }
    for bad in [
        &b"[]"[..],
        b"{}",
        b"not json",
        b"{\"_type\":\"https://in-toto.io/Statement/v1\"}",
    ] {
        let result = keyed(&pki, bad, &[COSIGN_SIGN_PREDICATE]);
        assert!(
            matches!(
                result,
                Err(Refusal::MalformedStatement | Refusal::StatementType)
            ),
            "{result:?}"
        );
    }
}

#[test]
fn dsse_envelope_shape() {
    let pki = Pki::new();
    let st = statement(&[&hex(&IMAGE)], COSIGN_SIGN_PREDICATE);
    let good = keyed_bundle(&pki.signer_key, &st);
    let one = good
        .get("dsseEnvelope")
        .and_then(|e| e.get("signatures"))
        .and_then(Value::as_array)
        .expect("signatures")[0]
        .clone();
    for signatures in [
        Value::Array(vec![]),
        Value::Array(vec![one.clone(), one.clone()]),
    ] {
        let mut b = good.clone();
        set(&mut b, &["dsseEnvelope", "signatures"], signatures);
        assert_eq!(
            Evidence::from_bundle(&to_bytes(&b)).err(),
            Some(Refusal::DsseShape)
        );
    }
    for payload_type in [
        "application/vnd.in-toto+JSON",
        "application/vnd.in-toto+json; charset=utf-8",
        "application/json",
        "",
    ] {
        let mut b = good.clone();
        set(&mut b, &["dsseEnvelope", "payloadType"], s(payload_type));
        assert_eq!(
            Evidence::from_bundle(&to_bytes(&b)).err(),
            Some(Refusal::DsseShape),
            "{payload_type}"
        );
    }
    // The signature covers the payload type: the same signature under PAE
    // with another type does not verify, so a signature over a raw
    // payload cannot be replayed as DSSE.
    let raw = pki.signer_key.sign(&st);
    let mut b = good.clone();
    set(
        &mut b,
        &["dsseEnvelope", "signatures"],
        Value::Array(vec![pki::obj(vec![(
            "sig",
            s(&boneli_sigstore::base64::encode(&raw)),
        )])]),
    );
    let evidence = Evidence::from_bundle(&to_bytes(&b)).expect("parses");
    assert_eq!(
        verify(
            &evidence,
            &IMAGE,
            &keyed_trust(&pki, &[COSIGN_SIGN_PREDICATE])
        ),
        Err(Refusal::NoTrustedKey)
    );
}
