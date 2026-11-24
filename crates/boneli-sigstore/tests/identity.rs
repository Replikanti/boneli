//! Identities (ADR-029, S2): configuration rules, and byte-exact matching
//! of the issuer and the one SAN through `verify`.

mod support;

use boneli_sigstore::{ConfigError, Identity, Refusal, SanRule};
use support::pki::{self, LeafSpec, Pki, RFC822_NAME, URI_NAME, san, verify_leaf};

#[test]
fn prefix_without_boundary_refused() {
    for prefix in [
        "https://github.com/acme",
        "https://github.com/acme/app/.github/workflows/release.yaml",
        "https://github.com/acme/app/.github/workflows/release.yaml@refs",
        // `@` is no boundary: it would trust every ref of the workflow.
        "https://github.com/acme/app/.github/workflows/release.yaml@",
        "https://github.com/acme/app/x.yaml@",
        "https://github.com/acme/app.",
    ] {
        assert_eq!(
            Identity::new(pki::ISSUER, SanRule::UriPrefix(prefix.to_owned())).err(),
            Some(ConfigError::PrefixWithoutBoundary),
            "{prefix}"
        );
    }
    for prefix in [
        "https://github.com/acme/",
        "https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/",
        "https://github.com/acme/app/.github/workflows/release.yaml@refs/heads/",
    ] {
        assert!(Identity::new(pki::ISSUER, SanRule::UriPrefix(prefix.to_owned())).is_ok());
    }
    // Exact rules need no boundary.
    assert!(
        Identity::new(
            pki::ISSUER,
            SanRule::Uri("https://github.com/acme".to_owned())
        )
        .is_ok()
    );
}

#[test]
fn identity_config_ascii_only() {
    for (issuer, text) in [
        ("https://issuer.boneli.test", "sign\u{0435}r@boneli.test"),
        ("https://\u{0456}ssuer.boneli.test", "signer@boneli.test"),
        ("https://issuer.boneli.test ", "signer@boneli.test"),
        ("https://issuer.boneli.test", "signer@boneli.test\n"),
        ("https://issuer.boneli.test", "signer@boneli.test\u{200b}"),
        ("https://issuer.boneli.test", ""),
        ("", "signer@boneli.test"),
        ("https://issuer.boneli.test", "a b@boneli.test"),
    ] {
        for rule in [
            SanRule::Email(text.to_owned()),
            SanRule::Uri(text.to_owned()),
            SanRule::UriPrefix(format!("{text}/")),
        ] {
            let empty_prefix = text.is_empty() && matches!(rule, SanRule::UriPrefix(_));
            if empty_prefix && !issuer.is_empty() {
                continue; // "/" alone is printable ASCII
            }
            assert_eq!(
                Identity::new(issuer, rule.clone()).err(),
                Some(ConfigError::IdentityNotAscii),
                "{issuer:?} {rule:?}"
            );
        }
    }
}

fn uri_identity(rule: SanRule) -> Identity {
    Identity::new(pki::ISSUER, rule).expect("identity")
}

#[test]
fn identity_look_alikes_do_not_match() {
    let pki = Pki::new();
    let exact = pki::URI;
    let leaf = LeafSpec::uri(exact);
    // The real one matches, exactly and by its tag-ref prefix.
    for rule in [
        SanRule::Uri(exact.to_owned()),
        SanRule::UriPrefix(
            "https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/".to_owned(),
        ),
        SanRule::UriPrefix("https://github.com/acme/".to_owned()),
    ] {
        let trust = pki::keyless_trust(&pki, vec![uri_identity(rule.clone())]);
        assert!(verify_leaf(&pki, &leaf, &trust).is_ok(), "{rule:?}");
    }
    // SANs that look like the rule's URI, each in its own leaf.
    for look_alike in [
        "https://github.com/\u{0430}cme/app/.github/workflows/release.yaml@refs/tags/v1.2.3",
        "https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1.2.3/",
        "https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v1.2.3.",
        "https://github.com/acme%2Fapp/.github/workflows/release.yaml@refs/tags/v1.2.3",
        "https://GitHub.com/acme/app/.github/workflows/release.yaml@refs/tags/v1.2.3",
    ] {
        let leaf = LeafSpec::uri(look_alike);
        let trust = pki::keyless_trust(&pki, vec![uri_identity(SanRule::Uri(exact.to_owned()))]);
        let result = verify_leaf(&pki, &leaf, &trust);
        // A non-ASCII SAN already refuses the leaf in boneli-https.
        assert!(
            matches!(
                result,
                Err(Refusal::IdentityMismatch)
                    | Err(Refusal::Certificate(boneli_https::CertError::NonAsciiSan))
            ),
            "{look_alike}: {result:?}"
        );
    }
    // An email SAN against a URI rule with the same text, and the reverse.
    let text = "signer@boneli.test";
    let email_leaf = LeafSpec {
        san: Some(san(&[(RFC822_NAME, text.as_bytes())])),
        ..LeafSpec::email()
    };
    let uri_leaf = LeafSpec {
        san: Some(san(&[(URI_NAME, text.as_bytes())])),
        ..LeafSpec::email()
    };
    let as_uri = pki::keyless_trust(&pki, vec![uri_identity(SanRule::Uri(text.to_owned()))]);
    let as_email = pki::keyless_trust(&pki, vec![uri_identity(SanRule::Email(text.to_owned()))]);
    assert_eq!(
        verify_leaf(&pki, &email_leaf, &as_uri),
        Err(Refusal::IdentityMismatch)
    );
    assert_eq!(
        verify_leaf(&pki, &uri_leaf, &as_email),
        Err(Refusal::IdentityMismatch)
    );
    assert!(verify_leaf(&pki, &email_leaf, &as_email).is_ok());
    // A prefix rule never matches an email SAN, even one whose text starts
    // with the prefix (`/` is allowed in an email's local part).
    let slash_email = LeafSpec {
        san: Some(san(&[(RFC822_NAME, b"team/signer@boneli.test")])),
        ..LeafSpec::email()
    };
    let prefix = pki::keyless_trust(
        &pki,
        vec![uri_identity(SanRule::UriPrefix("team/".to_owned()))],
    );
    assert_eq!(
        verify_leaf(&pki, &slash_email, &prefix),
        Err(Refusal::IdentityMismatch)
    );
}

#[test]
fn issuer_matched_exactly() {
    let pki = Pki::new();
    let leaf = LeafSpec::email();
    for issuer in [
        "https://issuer.boneli.test/",
        "https://Issuer.boneli.test",
        "http://issuer.boneli.test",
        "https://issuer.boneli.tes",
    ] {
        let id = Identity::new(issuer, SanRule::Email(pki::EMAIL.to_owned())).expect("id");
        let trust = pki::keyless_trust(&pki, vec![id]);
        assert_eq!(
            verify_leaf(&pki, &leaf, &trust),
            Err(Refusal::IdentityMismatch),
            "{issuer}"
        );
    }
}

#[test]
fn prefix_boundary_not_crossed() {
    let pki = Pki::new();
    let trust = pki::keyless_trust(
        &pki,
        vec![uri_identity(SanRule::UriPrefix(
            "https://github.com/acme/".to_owned(),
        ))],
    );
    let evil = LeafSpec::uri("https://github.com/acme-evil/x");
    assert_eq!(
        verify_leaf(&pki, &evil, &trust),
        Err(Refusal::IdentityMismatch)
    );
}

const WORKFLOW: &str = "https://github.com/acme/app/.github/workflows/release.yaml";

fn prefix_trust(pki: &Pki, prefix: &str) -> boneli_sigstore::Trust {
    pki::keyless_trust(
        pki,
        vec![uri_identity(SanRule::UriPrefix(format!(
            "{WORKFLOW}{prefix}"
        )))],
    )
}

fn san_result(pki: &Pki, trust: &boneli_sigstore::Trust, suffix: &str) -> Result<(), Refusal> {
    verify_leaf(pki, &LeafSpec::uri(&format!("{WORKFLOW}{suffix}")), trust).map(|_| ())
}

#[test]
fn tag_prefix_trusts_tags_only() {
    let pki = Pki::new();
    let tags = prefix_trust(&pki, "@refs/tags/");
    assert_eq!(san_result(&pki, &tags, "@refs/tags/v1.2.3"), Ok(()));
    // A branch, a commit SHA and a pull request's merge ref are other
    // refs of the same workflow, which an `@` prefix would have let in.
    for suffix in [
        "@refs/heads/x",
        "@refs/heads/main",
        "@0123456789abcdef0123456789abcdef01234567",
        "@refs/pull/7/merge",
        "@refs/tagsx/v1",
        "-evil@refs/tags/v1",
    ] {
        assert_eq!(
            san_result(&pki, &tags, suffix),
            Err(Refusal::IdentityMismatch),
            "{suffix}"
        );
    }
}

#[test]
fn branch_prefix_and_exact_san() {
    let pki = Pki::new();
    let heads = prefix_trust(&pki, "@refs/heads/");
    assert_eq!(san_result(&pki, &heads, "@refs/heads/main"), Ok(()));
    assert_eq!(
        san_result(&pki, &heads, "@refs/tags/v1"),
        Err(Refusal::IdentityMismatch)
    );
    // An exact SAN matches only itself: the protected branch.
    let exact = pki::keyless_trust(
        &pki,
        vec![uri_identity(SanRule::Uri(format!(
            "{WORKFLOW}@refs/heads/main"
        )))],
    );
    assert_eq!(san_result(&pki, &exact, "@refs/heads/main"), Ok(()));
    for suffix in ["@refs/heads/main2", "@refs/heads/x", "@refs/heads/mai"] {
        assert_eq!(
            san_result(&pki, &exact, suffix),
            Err(Refusal::IdentityMismatch),
            "{suffix}"
        );
    }
}

#[test]
fn second_identity_matches() {
    let pki = Pki::new();
    let trust = pki::keyless_trust(
        &pki,
        vec![
            uri_identity(SanRule::Uri("https://other.test/x".to_owned())),
            pki::email_identity(),
        ],
    );
    assert!(matches!(
        verify_leaf(&pki, &LeafSpec::email(), &trust),
        Ok(boneli_sigstore::Accepted::Keyless { identity: 1, .. })
    ));
}
