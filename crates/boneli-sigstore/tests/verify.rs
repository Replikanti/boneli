//! `verify` end to end (ADR-029, S2): the three real signatures as known
//! answers, then one negative case per check over the synthetic
//! instance of `support::pki`.

mod support;

use std::sync::Arc;

use boneli_https::PublicKey;
use boneli_sigstore::{Accepted, Evidence, Identity, Refusal, SanRule, Trust, TrustedRoot, verify};

use boneli_https::{CertError, SctError};
use boneli_json::Value;
use boneli_sigstore::ConfigError;
use support::pki::{
    self, BundleSpec, CODE_SIGNING, CosignLayer, EPOCH_2020, IMAGE, INTEGRATED, ISSUER, LeafIssuer,
    LeafSpec, OTHER_IMAGE, Pki, RFC822_NAME, SERVER_AUTH, SctSigner, SctSpec, URI_NAME, authority,
    email_identity, keyless_trust, keyless_trust_in, log_instance, rfc3339_ms, root_value, san,
    set, utf8, verify_leaf,
};
use support::real;

#[test]
fn kubernetes_passes_with_its_email_identity() {
    let trust = real::keyless(vec![real::kubernetes_identity()]);
    let accepted = verify(&real::kubernetes(), &real::KUBERNETES_DIGEST, &trust).expect("pass");
    assert_eq!(
        accepted,
        Accepted::Keyless {
            integrated_time: real::KUBERNETES_INTEGRATED,
            log_index: 96_410_323,
            identity: 0
        }
    );
}

#[test]
fn chainguard_passes_with_its_uri_and_its_prefix() {
    let exact = real::keyless(vec![real::chainguard_identity()]);
    let prefix = real::keyless(vec![
        Identity::new(
            real::GITHUB_ACTIONS,
            SanRule::UriPrefix(real::CHAINGUARD_PREFIX.to_owned()),
        )
        .expect("identity"),
    ]);
    for trust in [exact, prefix] {
        let accepted = verify(&real::chainguard(), &real::CHAINGUARD_DIGEST, &trust).expect("pass");
        assert!(matches!(
            accepted,
            Accepted::Keyless {
                integrated_time: real::CHAINGUARD_INTEGRATED,
                ..
            }
        ));
    }
}

#[test]
fn cosign_latest_passes_with_the_release_key() {
    let key = PublicKey::from_pem(real::COSIGN_RELEASE_KEY).expect("release key");
    // The bundle's key hint is the SHA-256 of this key's SPKI.
    let bundle = real::json(real::COSIGN_BUNDLE);
    let hint = bundle
        .get("verificationMaterial")
        .and_then(|m| m.get("publicKey"))
        .and_then(|k| k.get("hint"))
        .and_then(|h| h.as_str())
        .expect("hint");
    assert_eq!(
        boneli_sigstore::base64::decode(hint.as_bytes()).expect("b64"),
        key.key_id()
    );
    let trust = Trust::new(
        vec![key],
        None,
        vec![boneli_sigstore::COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust");
    assert_eq!(
        verify(&real::cosign(), &real::COSIGN_DIGEST, &trust),
        Ok(Accepted::Keyed { key: 0 })
    );
}

#[test]
fn synthetic_cosign_and_bundle_pass() {
    let pki = Pki::new();
    let root =
        Arc::new(TrustedRoot::from_json(&pki::to_bytes(&pki::root_value(&pki))).expect("root"));
    let identity = Identity::new(pki::ISSUER, SanRule::Email(pki::EMAIL.to_owned())).expect("id");
    let trust = Trust::new(
        Vec::new(),
        Some((root, vec![identity])),
        vec![boneli_sigstore::COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust");
    let layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let evidence = layer.evidence(&pki).expect("evidence");
    assert!(
        matches!(
            verify(&evidence, &IMAGE, &trust),
            Ok(Accepted::Keyless { .. })
        ),
        "{:?}",
        verify(&evidence, &IMAGE, &trust)
    );
    let bundle = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let evidence = Evidence::from_bundle(&bundle.bytes(&pki)).expect("bundle");
    assert!(
        matches!(
            verify(&evidence, &IMAGE, &trust),
            Ok(Accepted::Keyless { .. })
        ),
        "{:?}",
        verify(&evidence, &IMAGE, &trust)
    );
}

// ---- Synthetic negatives, one per check -------------------------------

fn email_trust(pki: &Pki) -> Trust {
    keyless_trust(pki, vec![email_identity()])
}

#[test]
fn trust_configuration() {
    let pki = Pki::new();
    assert_eq!(
        Trust::new(Vec::new(), None, Vec::new()).err(),
        Some(ConfigError::TrustEmpty)
    );
    let root = pki::trusted_root(&root_value(&pki));
    assert_eq!(
        Trust::new(Vec::new(), Some((root.clone(), Vec::new())), Vec::new()).err(),
        Some(ConfigError::NoIdentities)
    );
    for predicate in ["", "https://x.test/a b", "https://x.test/\u{e9}"] {
        assert_eq!(
            Trust::new(
                vec![pki.signer_key.public.clone()],
                None,
                vec![predicate.to_owned()]
            )
            .err(),
            Some(ConfigError::PredicateTypeNotAscii)
        );
    }
    let trust = Trust::new(
        vec![pki.signer_key.public.clone()],
        Some((root, vec![email_identity()])),
        vec![],
    )
    .expect("both");
    assert_eq!(
        format!("{trust:?}"),
        "Trust { keys: 1, identities: 1, predicate_types: 0 }"
    );
}

#[test]
fn keyless_and_keyed_paths_meet() {
    let pki = Pki::new();
    let layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let keyless_evidence = layer.evidence(&pki).expect("evidence");
    // Keys only: a keyless signature by an untrusted key.
    let keyed_only = pki::keyed_trust(&pki, &[]);
    assert_eq!(
        verify(&keyless_evidence, &IMAGE, &keyed_only),
        Err(Refusal::NoTrustedKey)
    );
    // Keys and keyless: the keyless path decides.
    let both = Trust::new(
        vec![pki.signer_key.public.clone()],
        Some((pki::trusted_root(&root_value(&pki)), vec![email_identity()])),
        vec![],
    )
    .expect("trust");
    assert!(matches!(
        verify(&keyless_evidence, &IMAGE, &both),
        Ok(Accepted::Keyless { .. })
    ));
    // A keyed layer under both: the key decides; an untrusted key with no
    // certificate is NoTrustedKey.
    let payload = pki::payload_for(&IMAGE);
    let keyed = Evidence::from_cosign_layer(
        &real::pairs(&pki::keyed_layer(&pki.signer_key, &payload)),
        &payload,
    )
    .expect("keyed");
    assert_eq!(
        verify(&keyed, &IMAGE, &both),
        Ok(Accepted::Keyed { key: 0 })
    );
    let other = Evidence::from_cosign_layer(
        &real::pairs(&pki::keyed_layer(&pki.other_key, &payload)),
        &payload,
    )
    .expect("keyed");
    assert_eq!(verify(&other, &IMAGE, &both), Err(Refusal::NoTrustedKey));
    assert_eq!(
        verify(&other, &IMAGE, &email_trust(&pki)),
        Err(Refusal::NoCertificate)
    );
}

#[test]
fn signature_must_be_the_leafs() {
    // Logged consistently, chained and SCT'd, but signed by another key.
    let pki = Pki::new();
    let mut layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    layer.signature = pki.other_key.sign(&layer.payload);
    layer.relog(&pki);
    let evidence = layer.evidence(&pki).expect("evidence");
    assert_eq!(
        verify(&evidence, &IMAGE, &email_trust(&pki)),
        Err(Refusal::SignatureInvalid)
    );
}

#[test]
fn integrated_time_at_leaf_bounds() {
    let pki = Pki::new();
    let trust = email_trust(&pki);
    let leaf = LeafSpec::email();
    for (at, ok) in [
        (leaf.not_before, true),
        (leaf.not_after, true),
        (leaf.not_before - 1, false),
        (leaf.not_after + 1, false),
    ] {
        let mut layer = CosignLayer::keyless(&pki, &leaf, &IMAGE);
        layer.entry.integrated_time = at;
        let result = verify(&layer.evidence(&pki).expect("evidence"), &IMAGE, &trust);
        if ok {
            assert!(result.is_ok(), "{at}: {result:?}");
        } else {
            assert_eq!(
                result,
                Err(Refusal::Certificate(CertError::OutsideValidity)),
                "{at}"
            );
        }
    }
}

#[test]
fn root_window_bounds() {
    let pki = Pki::new();
    let at_ms = INTEGRATED * 1_000;
    let at = rfc3339_ms(at_ms);
    let before = rfc3339_ms(at_ms - 1);
    let after = rfc3339_ms(at_ms + 1);
    let layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE);
    let evidence = layer.evidence(&pki).expect("evidence");
    let check = |root: Value| {
        verify(
            &evidence,
            &IMAGE,
            &keyless_trust_in(&root, vec![email_identity()]),
        )
    };
    // Rekor's window.
    for (start, end, expected) in [
        (at.as_str(), None, Ok(())),
        (after.as_str(), None, Err(Refusal::LogOutsideWindow)),
        (EPOCH_2020, Some(at.as_str()), Ok(())),
        (
            EPOCH_2020,
            Some(before.as_str()),
            Err(Refusal::LogOutsideWindow),
        ),
    ] {
        let mut root = root_value(&pki);
        set(
            &mut root,
            &["tlogs"],
            Value::Array(vec![log_instance(&pki.rekor_key, start, end)]),
        );
        assert_eq!(check(root).map(|_| ()), expected, "tlog {start} {end:?}");
    }
    // The CA's window.
    for (start, end, expected) in [
        (at.as_str(), None, Ok(())),
        (after.as_str(), None, Err(Refusal::NoCaAtTime)),
        (EPOCH_2020, Some(at.as_str()), Ok(())),
        (EPOCH_2020, Some(before.as_str()), Err(Refusal::NoCaAtTime)),
    ] {
        let mut root = root_value(&pki);
        set(
            &mut root,
            &["certificateAuthorities"],
            Value::Array(vec![authority(&[&pki.intermediate, &pki.root], start, end)]),
        );
        assert_eq!(check(root).map(|_| ()), expected, "ca {start} {end:?}");
    }
}

#[test]
fn overlapping_ca_windows() {
    let pki = Pki::new();
    let ours = authority(&[&pki.intermediate, &pki.root], EPOCH_2020, None);
    // A CA that does not issue our leaves, anchored at the attacker's
    // self-signed intermediate, with an overlapping window.
    let theirs = authority(&[&pki.attacker_intermediate], EPOCH_2020, None);
    let ended = authority(
        &[&pki.intermediate, &pki.root],
        EPOCH_2020,
        Some("2021-01-01T00:00:00Z"),
    );
    let evidence = CosignLayer::keyless(&pki, &LeafSpec::email(), &IMAGE)
        .evidence(&pki)
        .expect("e");
    let with_cas = |cas: Vec<Value>| {
        let mut root = root_value(&pki);
        set(&mut root, &["certificateAuthorities"], Value::Array(cas));
        verify(
            &evidence,
            &IMAGE,
            &keyless_trust_in(&root, vec![email_identity()]),
        )
    };
    assert!(with_cas(vec![theirs.clone(), ours.clone()]).is_ok());
    assert!(with_cas(vec![ours.clone(), theirs.clone()]).is_ok());
    // Ours only outside its window: the other CA does not chain it.
    assert_eq!(
        with_cas(vec![ended, theirs.clone()]),
        Err(Refusal::Certificate(CertError::Invalid))
    );
    assert_eq!(with_cas(vec![]), Err(Refusal::NoCaAtTime));
    // The public-good root's two windows overlap from 2022-04-13 to the
    // end of 2022; Kubernetes' 2024 leaf lies in the second only and
    // passes (`kubernetes_passes_with_its_email_identity`).
}

#[test]
fn leaf_usage_cases() {
    let pki = Pki::new();
    let trust = email_trust(&pki);
    for (leaf, expected) in [
        (
            LeafSpec {
                eku: None,
                ..LeafSpec::email()
            },
            CertError::NotCodeSigning,
        ),
        (
            LeafSpec {
                eku: Some(vec![SERVER_AUTH]),
                ..LeafSpec::email()
            },
            CertError::NotCodeSigning,
        ),
        (
            LeafSpec {
                ca: true,
                ..LeafSpec::email()
            },
            CertError::IsCa,
        ),
        (
            LeafSpec {
                issuer: LeafIssuer::Attacker,
                ..LeafSpec::email()
            },
            CertError::Invalid,
        ),
    ] {
        assert_eq!(
            verify_leaf(&pki, &leaf, &trust),
            Err(Refusal::Certificate(expected))
        );
    }
    let both = LeafSpec {
        eku: Some(vec![SERVER_AUTH, CODE_SIGNING]),
        ..LeafSpec::email()
    };
    assert!(verify_leaf(&pki, &both, &trust).is_ok());
}

#[test]
fn sct_cases() {
    let pki = Pki::new();
    let trust = email_trust(&pki);
    let none = LeafSpec {
        scts: vec![],
        ..LeafSpec::email()
    };
    assert_eq!(
        verify_leaf(&pki, &none, &trust),
        Err(Refusal::Sct(SctError::Missing))
    );
    let unknown = LeafSpec {
        scts: vec![SctSpec {
            signer: SctSigner::Other,
            ..SctSpec::good()
        }],
        ..LeafSpec::email()
    };
    assert_eq!(
        verify_leaf(&pki, &unknown, &trust),
        Err(Refusal::Sct(SctError::NoneVerified))
    );
    let other_tbs = LeafSpec {
        scts: vec![SctSpec {
            over_other_tbs: true,
            ..SctSpec::good()
        }],
        ..LeafSpec::email()
    };
    assert_eq!(
        verify_leaf(&pki, &other_tbs, &trust),
        Err(Refusal::Sct(SctError::NoneVerified))
    );
    // Outside the CT log's window.
    let mut root = root_value(&pki);
    let end = rfc3339_ms(pki::SCT_MS - 1);
    set(
        &mut root,
        &["ctlogs"],
        Value::Array(vec![log_instance(&pki.ct_key, EPOCH_2020, Some(&end))]),
    );
    let late = keyless_trust_in(&root, vec![email_identity()]);
    assert_eq!(
        verify_leaf(&pki, &LeafSpec::email(), &late),
        Err(Refusal::Sct(SctError::NoneVerified))
    );
    // A bad SCT next to a good one: one is enough.
    let mixed = LeafSpec {
        scts: vec![
            SctSpec {
                signer: SctSigner::Other,
                ..SctSpec::good()
            },
            SctSpec::good(),
        ],
        ..LeafSpec::email()
    };
    assert!(verify_leaf(&pki, &mixed, &trust).is_ok());
}

#[test]
fn two_sans_refused() {
    let pki = Pki::new();
    let trust = email_trust(&pki);
    let two = LeafSpec {
        san: Some(san(&[
            (RFC822_NAME, pki::EMAIL.as_bytes()),
            (URI_NAME, b"https://x.test/"),
        ])),
        ..LeafSpec::email()
    };
    assert_eq!(verify_leaf(&pki, &two, &trust), Err(Refusal::SanCount));
    let same_twice = LeafSpec {
        san: Some(san(&[
            (RFC822_NAME, pki::EMAIL.as_bytes()),
            (RFC822_NAME, pki::EMAIL.as_bytes()),
        ])),
        ..LeafSpec::email()
    };
    assert_eq!(
        verify_leaf(&pki, &same_twice, &trust),
        Err(Refusal::SanCount)
    );
    let none = LeafSpec {
        san: None,
        ..LeafSpec::email()
    };
    assert_eq!(verify_leaf(&pki, &none, &trust), Err(Refusal::SanCount));
}

#[test]
fn issuer_extensions_disagree() {
    let pki = Pki::new();
    let trust = email_trust(&pki);
    let leaf = LeafSpec {
        issuer_v1: Some(b"https://other.test".to_vec()),
        ..LeafSpec::email()
    };
    assert_eq!(
        verify_leaf(&pki, &leaf, &trust),
        Err(Refusal::IssuerDisagree)
    );
    let leaf = LeafSpec {
        issuer_v2: Some(utf8(b"https://other.test")),
        ..LeafSpec::email()
    };
    assert_eq!(
        verify_leaf(&pki, &leaf, &trust),
        Err(Refusal::IssuerDisagree)
    );
    // 1.8 is read as a UTF8String: raw bytes or another string type are
    // malformed.
    for v2 in [
        ISSUER.as_bytes().to_vec(),
        pki::tlv(0x16, ISSUER.as_bytes()),
        {
            let mut v = utf8(ISSUER.as_bytes());
            v.push(0);
            v
        },
        vec![0x0C, 0x81, 0x05, b'a', b'b', b'c', b'd', b'e'],
    ] {
        let leaf = LeafSpec {
            issuer_v2: Some(v2),
            ..LeafSpec::email()
        };
        assert_eq!(
            verify_leaf(&pki, &leaf, &trust),
            Err(Refusal::MalformedIssuer)
        );
    }
    let leaf = LeafSpec {
        issuer_v1: None,
        issuer_v2: None,
        ..LeafSpec::email()
    };
    assert_eq!(verify_leaf(&pki, &leaf, &trust), Err(Refusal::NoIssuer));
}

#[test]
fn legacy_issuer_extension() {
    let pki = Pki::new();
    let trust = email_trust(&pki);
    let v1_only = LeafSpec {
        issuer_v2: None,
        ..LeafSpec::email()
    };
    assert!(verify_leaf(&pki, &v1_only, &trust).is_ok());
    let v2_only = LeafSpec {
        issuer_v1: None,
        ..LeafSpec::email()
    };
    assert!(verify_leaf(&pki, &v2_only, &trust).is_ok());
    // A long issuer: 1.8 with a two-byte length.
    let long = format!("https://issuer.boneli.test/{}", "a".repeat(200));
    let leaf = LeafSpec {
        issuer_v1: None,
        issuer_v2: Some(utf8(long.as_bytes())),
        ..LeafSpec::email()
    };
    let id = Identity::new(&long, SanRule::Email(pki::EMAIL.to_owned())).expect("id");
    assert!(verify_leaf(&pki, &leaf, &keyless_trust(&pki, vec![id])).is_ok());
}

#[test]
fn platform_and_other_subjects() {
    // The verdict is per subject digest: the same signature passes for
    // the digest it names and fails for any other.
    let pki = Pki::new();
    let layer = CosignLayer::keyless(&pki, &LeafSpec::email(), &OTHER_IMAGE);
    let evidence = layer.evidence(&pki).expect("evidence");
    assert!(verify(&evidence, &OTHER_IMAGE, &email_trust(&pki)).is_ok());
    assert_eq!(
        verify(&evidence, &IMAGE, &email_trust(&pki)),
        Err(Refusal::SubjectMismatch)
    );
    let bundle = BundleSpec::keyless(&pki, &LeafSpec::email(), &OTHER_IMAGE);
    let evidence = Evidence::from_bundle(&bundle.bytes(&pki)).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &email_trust(&pki)),
        Err(Refusal::SubjectMismatch)
    );
}

#[test]
fn real_signatures_negative() {
    // Kubernetes' signature under Chainguard's identity, and Chainguard's
    // under a prefix that is not its own.
    let trust = real::keyless(vec![real::chainguard_identity()]);
    assert_eq!(
        verify(&real::kubernetes(), &real::KUBERNETES_DIGEST, &trust),
        Err(Refusal::IdentityMismatch)
    );
    let trust = real::keyless(vec![
        Identity::new(
            real::GITHUB_ACTIONS,
            SanRule::UriPrefix("https://github.com/chainguard-images/images-private/".to_owned()),
        )
        .expect("id"),
    ]);
    assert_eq!(
        verify(&real::chainguard(), &real::CHAINGUARD_DIGEST, &trust),
        Err(Refusal::IdentityMismatch)
    );
    // cosign's bundle under another key.
    let key = PublicKey::from_pem(include_bytes!("data/test-only-signer.pub.pem")).expect("key");
    let trust = Trust::new(
        vec![key],
        None,
        vec![boneli_sigstore::COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("trust");
    assert_eq!(
        verify(&real::cosign(), &real::COSIGN_DIGEST, &trust),
        Err(Refusal::NoTrustedKey)
    );
}

#[test]
fn refusal_detail_carries_no_untrusted_text() {
    let pki = Pki::new();
    // ASCII controls pass boneli-https's reader; bidi controls do not.
    let hostile_ascii = "https://x.test/\n\u{1b}[31mEVIL";
    let hostile_bidi = "https://x.test/\u{202e}EVIL";
    let mut texts = Vec::new();
    for uri in [hostile_ascii, hostile_bidi] {
        let leaf = LeafSpec::uri(uri);
        let result = verify_leaf(&pki, &leaf, &email_trust(&pki));
        let refusal = result.expect_err("refused");
        texts.push(refusal.to_string());
        texts.push(format!("{refusal:?}"));
    }
    // A payload with a hostile reference and type.
    let payload = pki::simple_signing(&pki::hex(&IMAGE), "EVIL\n\u{1b}[0m");
    let annotations = pki::keyed_layer(&pki.signer_key, &payload);
    let refusal =
        Evidence::from_cosign_layer(&real::pairs(&annotations), &payload).expect_err("refused");
    texts.push(refusal.to_string());
    let evidence = CosignLayer::keyless(&pki, &LeafSpec::uri(hostile_ascii), &IMAGE)
        .evidence(&pki)
        .expect("e");
    texts.push(format!("{evidence:?}"));
    for text in texts {
        assert!(
            !text.contains("EVIL")
                && !text.contains('\n')
                && !text.contains('\u{1b}')
                && !text.contains('\u{202e}'),
            "{text:?}"
        );
    }
}

#[test]
fn refusal_texts() {
    let all = [
        (Refusal::PayloadTooLarge, "the signed payload is too large"),
        (Refusal::MalformedPayload, "the signed payload is malformed"),
        (
            Refusal::PayloadType,
            "the signed payload is not a cosign image signature",
        ),
        (
            Refusal::MalformedDigest,
            "a digest is not sha256 in lower-case hex",
        ),
        (
            Refusal::MalformedAnnotations,
            "the signature annotations are malformed",
        ),
        (Refusal::MalformedSignature, "the signature is malformed"),
        (
            Refusal::MalformedCertificate,
            "the certificate is malformed",
        ),
        (
            Refusal::MalformedTlogEntry,
            "the transparency log entry is malformed",
        ),
        (Refusal::BundleTooLarge, "the bundle is too large"),
        (Refusal::MalformedBundle, "the bundle is malformed"),
        (
            Refusal::BundleVersion,
            "the bundle is not a Sigstore bundle v0.3",
        ),
        (
            Refusal::MessageSignature,
            "the bundle holds a message signature, not DSSE",
        ),
        (
            Refusal::DsseShape,
            "the DSSE envelope is not one in-toto signature",
        ),
        (
            Refusal::MalformedStatement,
            "the in-toto statement is malformed",
        ),
        (
            Refusal::StatementType,
            "the payload is not an in-toto statement v1",
        ),
        (Refusal::PredicateType, "the predicate type is not trusted"),
        (
            Refusal::SubjectMismatch,
            "the signature is not over this digest",
        ),
        (
            Refusal::NoTrustedKey,
            "no trusted key verifies the signature",
        ),
        (Refusal::NoCertificate, "the signature has no certificate"),
        (
            Refusal::TlogEntries,
            "a keyless signature needs exactly one log entry with an inclusion promise",
        ),
        (
            Refusal::IntegratedTimeRange,
            "the integrated time is out of range",
        ),
        (Refusal::UnknownLog, "the transparency log is not trusted"),
        (
            Refusal::LogOutsideWindow,
            "the transparency log key is not valid at the integrated time",
        ),
        (Refusal::SetInvalid, "the inclusion promise does not verify"),
        (
            Refusal::EntryKind,
            "the transparency log entry is of the wrong kind",
        ),
        (
            Refusal::BodyMismatch,
            "the transparency log entry does not match the signature",
        ),
        (
            Refusal::NoCaAtTime,
            "no trusted certificate authority is valid at the integrated time",
        ),
        (
            Refusal::Certificate(CertError::UnknownIssuer),
            "the certificate does not verify: the certificate does not chain to a trust root",
        ),
        (
            Refusal::Sct(SctError::Missing),
            "no embedded SCT verifies: the certificate carries no embedded SCT list",
        ),
        (
            Refusal::SignatureInvalid,
            "the certificate's key does not verify the signature",
        ),
        (
            Refusal::SanCount,
            "the certificate does not hold exactly one SAN",
        ),
        (Refusal::NoIssuer, "the certificate names no OIDC issuer"),
        (
            Refusal::MalformedIssuer,
            "the certificate's OIDC issuer is malformed",
        ),
        (
            Refusal::IssuerDisagree,
            "the certificate names two different OIDC issuers",
        ),
        (
            Refusal::IdentityMismatch,
            "the signer is not a trusted identity",
        ),
    ];
    for (refusal, text) in all {
        assert_eq!(refusal.to_string(), text);
    }
}

#[test]
fn truncated_inputs_never_panic() {
    let pki = Pki::new();
    let trust = email_trust(&pki);
    let public_good = real::keyless(vec![
        real::kubernetes_identity(),
        real::chainguard_identity(),
    ]);
    for end in 0..real::COSIGN_BUNDLE.len() {
        assert!(
            Evidence::from_bundle(&real::COSIGN_BUNDLE[..end]).is_err(),
            "bundle prefix {end}"
        );
    }
    // The file ends in a newline; without it, it is still the whole root.
    let whole = real::TRUSTED_ROOT
        .iter()
        .rposition(|b| *b == b'}')
        .expect("end")
        + 1;
    for end in 0..whole {
        assert!(
            TrustedRoot::from_json(&real::TRUSTED_ROOT[..end]).is_err(),
            "root prefix {end}"
        );
    }
    for (sig, payload, digest) in [
        (
            real::KUBERNETES_SIG,
            real::KUBERNETES_PAYLOAD,
            real::KUBERNETES_DIGEST,
        ),
        (
            real::CHAINGUARD_SIG,
            real::CHAINGUARD_PAYLOAD,
            real::CHAINGUARD_DIGEST,
        ),
    ] {
        let annotations = real::annotations(sig);
        for end in 0..payload.len() {
            let result = Evidence::from_cosign_layer(&real::pairs(&annotations), &payload[..end]);
            assert!(result.is_err(), "payload prefix {end}");
        }
        // Every prefix of every annotation the reader uses: refused at
        // parse or at verify, never a panic and never a pass.
        for (key, value) in &annotations {
            if !key.starts_with("dev.") || key.ends_with("/chain") {
                continue;
            }
            for end in 0..value.len() {
                let Some(prefix) = value.get(..end) else {
                    continue;
                };
                // The PEM without its final newline is the same
                // certificate.
                if prefix == value.trim_end_matches('\n') {
                    continue;
                }
                let changed = real::with(&annotations, key, prefix);
                if let Ok(evidence) = Evidence::from_cosign_layer(&real::pairs(&changed), payload) {
                    assert!(
                        verify(&evidence, &digest, &public_good).is_err(),
                        "{key} prefix {end}"
                    );
                }
            }
        }
    }
    // And the synthetic bundle, through verify where it parses.
    let bytes = BundleSpec::keyless(&pki, &LeafSpec::email(), &IMAGE).bytes(&pki);
    for end in 0..bytes.len() {
        if let Ok(evidence) = Evidence::from_bundle(&bytes[..end]) {
            assert!(verify(&evidence, &IMAGE, &trust).is_err());
        }
    }
}
