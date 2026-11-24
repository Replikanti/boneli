//! Fulcio certificate claims (ADR-034): the three real GitHub leaves as
//! known answers, then one test per edge case of the plan over synthetic
//! GitHub leaves of `support::pki` (`LeafSpec::github`), on keyless cosign
//! layers and keyless bundles.

mod support;

use boneli_sigstore::{
    Accepted, COSIGN_SIGN_PREDICATE, CertificateClaims, CertificateRefusal, ClaimMatch, Claims,
    ConfigError, Evidence, Extension, GITHUB_ACTIONS_ISSUER, GITHUB_WORKFLOW_BUILD_TYPE, Identity,
    Material, Refusal, SLSA_PROVENANCE_V1_PREDICATE, SanRule, Trust, verify,
};
use support::pki::{
    self, BundleSpec, GH_COMMIT, GH_ID, GH_MATERIAL, GH_REF, GH_REPOSITORY, GH_TRIGGER,
    GH_WORKFLOW, GITHUB_ISSUER, IMAGE, LeafSpec, Pki, ext, fulcio_ext, fulcio_oid, hex, root_value,
    tlv, trusted_root, utf8, verify_leaf,
};
use support::real;

// ---------------------------------------------------------------------
// Rules, trusts and evidence
// ---------------------------------------------------------------------

fn exact(text: &str) -> Option<ClaimMatch> {
    Some(ClaimMatch::Exact(text.to_owned()))
}

fn prefix(text: &str) -> Option<ClaimMatch> {
    Some(ClaimMatch::Prefix(text.to_owned()))
}

fn triggers(list: &[&str]) -> Vec<String> {
    list.iter().map(|t| (*t).to_owned()).collect()
}

/// Certificate claims with a trigger list only.
fn only_triggers(list: &[&str]) -> CertificateClaims {
    CertificateClaims::new(None, None, triggers(list)).expect("certificate claims")
}

/// Certificate claims the synthetic GitHub leaf meets in full.
fn gh_claims() -> CertificateClaims {
    CertificateClaims::new(exact(GH_REPOSITORY), exact(GH_REF), triggers(&[GH_TRIGGER]))
        .expect("certificate claims")
        .with_repository_id(GH_ID)
        .expect("repository id")
}

fn with_cc(trust: Trust, claims: CertificateClaims) -> Trust {
    trust
        .with_certificate_claims(claims)
        .expect("with certificate claims")
}

fn gh_identity() -> Identity {
    Identity::new(GITHUB_ISSUER, SanRule::Uri(GH_WORKFLOW.to_owned())).expect("identity")
}

/// A keyless trust in the test instance for the GitHub identity, with
/// `predicates`.
fn gh_trust(pki: &Pki, predicates: &[&str]) -> Trust {
    Trust::new(
        Vec::new(),
        Some((trusted_root(&root_value(pki)), vec![gh_identity()])),
        predicates.iter().map(|p| (*p).to_owned()).collect(),
    )
    .expect("trust")
}

/// `gh_trust` for cosign layers with `claims`.
fn layer_trust(pki: &Pki, claims: CertificateClaims) -> Trust {
    with_cc(gh_trust(pki, &[COSIGN_SIGN_PREDICATE]), claims)
}

fn gh_leaf() -> LeafSpec {
    LeafSpec::github(GH_WORKFLOW)
}

const PASS: Result<Accepted, Refusal> = Ok(Accepted::Keyless {
    integrated_time: pki::INTEGRATED,
    log_index: pki::LOG_INDEX,
    identity: 0,
});

fn refused(refusal: CertificateRefusal) -> Result<Accepted, Refusal> {
    Err(Refusal::CertificateClaim(refusal))
}

fn mismatch(ext: Extension) -> Result<Accepted, Refusal> {
    refused(CertificateRefusal::Mismatch(ext))
}

fn malformed(ext: Extension) -> Result<Accepted, Refusal> {
    refused(CertificateRefusal::Malformed(ext))
}

fn missing(ext: Extension) -> Result<Accepted, Refusal> {
    refused(CertificateRefusal::Missing(ext))
}

fn disagrees(ext: Extension) -> Result<Accepted, Refusal> {
    refused(CertificateRefusal::StatementDisagrees(ext))
}

/// The keyless cosign layer of `leaf` over `IMAGE`, verified under a
/// cosign trust with `claims`.
fn layer(pki: &Pki, leaf: &LeafSpec, claims: CertificateClaims) -> Result<Accepted, Refusal> {
    verify_leaf(pki, leaf, &layer_trust(pki, claims))
}

/// A GitHub-shaped SLSA v1 statement over `IMAGE`. `repository` is put
/// in as raw JSON string content, so a test may escape it; `dependencies`
/// is the raw JSON of `resolvedDependencies`.
fn gh_statement(builder: &str, repository: &str, git_ref: &str, dependencies: &str) -> Vec<u8> {
    gh_statement_typed(
        GITHUB_WORKFLOW_BUILD_TYPE,
        builder,
        repository,
        git_ref,
        dependencies,
    )
}

fn gh_statement_typed(
    build_type: &str,
    builder: &str,
    repository: &str,
    git_ref: &str,
    dependencies: &str,
) -> Vec<u8> {
    format!(
        r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[{{"name":"registry.boneli.test/app","digest":{{"sha256":"{image}"}}}}],"predicateType":"{SLSA_PROVENANCE_V1_PREDICATE}","predicate":{{"buildDefinition":{{"buildType":"{build_type}","externalParameters":{{"workflow":{{"ref":"{git_ref}","repository":"{repository}","path":".github/workflows/release.yml"}}}},"resolvedDependencies":{dependencies}}},"runDetails":{{"builder":{{"id":"{builder}"}}}}}}}}"#,
        image = hex(&IMAGE),
    )
    .into_bytes()
}

fn source(uri: &str, digest: &str) -> String {
    format!(r#"{{"uri":"{uri}","digest":{{"gitCommit":"{digest}"}}}}"#)
}

/// The source dependency the GitHub leaf agrees with.
fn gh_dependencies() -> String {
    format!("[{}]", source(GH_MATERIAL, GH_COMMIT))
}

/// The statement the GitHub leaf agrees with in every field.
fn agreeing() -> Vec<u8> {
    gh_statement(GH_WORKFLOW, GH_REPOSITORY, GH_REF, &gh_dependencies())
}

/// A #104 claim list the agreeing statement meets.
fn repository_claim(repository: &str) -> Claims {
    Claims::new(None, exact(repository), None, vec![]).expect("claims")
}

/// A keyless SLSA trust for the GitHub identity with #104 `claims` (if
/// any) and certificate `cc`.
fn slsa_trust(pki: &Pki, claims: Option<Claims>, cc: CertificateClaims) -> Trust {
    let trust = gh_trust(pki, &[SLSA_PROVENANCE_V1_PREDICATE]);
    let trust = match claims {
        Some(claims) => trust.with_claims(claims).expect("with claims"),
        None => trust,
    };
    with_cc(trust, cc)
}

/// The keyless bundle of `statement` signed under `leaf`, verified over
/// `IMAGE` under `trust`.
fn bundle(
    pki: &Pki,
    leaf: &LeafSpec,
    statement: Vec<u8>,
    trust: &Trust,
) -> Result<Accepted, Refusal> {
    let spec = BundleSpec::keyless_statement(pki, leaf, statement);
    let evidence = Evidence::from_bundle(&spec.bytes(pki))?;
    verify(&evidence, &IMAGE, trust)
}

/// `bundle` under #104's repository claim and the GitHub certificate
/// claims with the statement agreement.
fn agreement(pki: &Pki, leaf: &LeafSpec, statement: Vec<u8>) -> Result<Accepted, Refusal> {
    let trust = slsa_trust(
        pki,
        Some(repository_claim(GH_REPOSITORY)),
        gh_claims().with_statement_agreement(),
    );
    bundle(pki, leaf, statement, &trust)
}

// ---------------------------------------------------------------------
// Known answers
// ---------------------------------------------------------------------

fn runner_cc() -> CertificateClaims {
    CertificateClaims::new(
        exact(real::RUNNER_REPOSITORY),
        exact(real::RUNNER_REF),
        triggers(&[real::RUNNER_TRIGGER]),
    )
    .expect("runner")
    .with_repository_id(real::RUNNER_REPOSITORY_ID)
    .expect("id")
}

fn jq_cc() -> CertificateClaims {
    CertificateClaims::new(
        exact(real::JQ_REPOSITORY),
        prefix("refs/tags/"),
        triggers(&[real::JQ_TRIGGER]),
    )
    .expect("jq")
    .with_repository_id(real::JQ_REPOSITORY_ID)
    .expect("id")
}

fn chainguard_cc() -> CertificateClaims {
    CertificateClaims::new(
        exact(real::CHAINGUARD_REPOSITORY),
        exact(real::CHAINGUARD_REF),
        triggers(&[real::CHAINGUARD_TRIGGER]),
    )
    .expect("chainguard")
    .with_repository_id(real::CHAINGUARD_REPOSITORY_ID)
    .expect("id")
}

/// #104's claims each real attestation meets.
fn runner_claims() -> Claims {
    Claims::new(
        Some(real::RUNNER_WORKFLOW),
        exact(real::RUNNER_REPOSITORY),
        exact(real::RUNNER_REF),
        vec![Material::new(real::RUNNER_MATERIAL, "gitCommit", real::RUNNER_COMMIT).expect("m")],
    )
    .expect("claims")
}

fn jq_claims() -> Claims {
    Claims::new(
        None,
        exact(real::JQ_REPOSITORY),
        prefix("refs/tags/"),
        vec![Material::new(real::JQ_MATERIAL, "gitCommit", real::JQ_COMMIT).expect("m")],
    )
    .expect("claims")
}

fn runner_verify(cc: CertificateClaims) -> Result<Accepted, Refusal> {
    let trust = with_cc(real::slsa_keyless(real::runner_identity()), cc);
    verify(&real::runner(), &real::RUNNER_DIGEST, &trust)
}

fn jq_verify(cc: CertificateClaims) -> Result<Accepted, Refusal> {
    let trust = with_cc(real::slsa_keyless(real::jq_identity()), cc);
    verify(&real::jq(), &real::JQ_DIGEST, &trust)
}

fn chainguard_verify(cc: CertificateClaims) -> Result<Accepted, Refusal> {
    let trust = with_cc(real::keyless(vec![real::chainguard_identity()]), cc);
    verify(&real::chainguard(), &real::CHAINGUARD_DIGEST, &trust)
}

/// The runner and jq attestations and Chainguard's `.sig` meet their
/// certificate claims and give the same `Accepted` as without them; the
/// two attestations also pass with #104's claims and the statement
/// agreement.
#[test]
fn real_certificates_meet_their_claims() {
    let runner = verify(
        &real::runner(),
        &real::RUNNER_DIGEST,
        &real::slsa_keyless(real::runner_identity()),
    );
    assert!(runner.is_ok());
    assert_eq!(runner_verify(runner_cc()), runner);
    let trust = real::slsa_keyless(real::runner_identity())
        .with_claims(runner_claims())
        .expect("claims");
    let trust = with_cc(trust, runner_cc().with_statement_agreement());
    assert_eq!(
        verify(&real::runner(), &real::RUNNER_DIGEST, &trust),
        runner
    );

    let jq = verify(
        &real::jq(),
        &real::JQ_DIGEST,
        &real::slsa_keyless(real::jq_identity()),
    );
    assert!(jq.is_ok());
    assert_eq!(jq_verify(jq_cc()), jq);
    let trust = real::slsa_keyless(real::jq_identity())
        .with_claims(jq_claims())
        .expect("claims");
    let trust = with_cc(trust, jq_cc().with_statement_agreement());
    assert_eq!(verify(&real::jq(), &real::JQ_DIGEST, &trust), jq);
    // jq's exact ref too.
    let exact_ref = CertificateClaims::new(
        exact(real::JQ_REPOSITORY),
        exact(real::JQ_REF),
        triggers(&[real::JQ_TRIGGER]),
    )
    .expect("jq exact");
    assert_eq!(jq_verify(exact_ref), jq);

    let chainguard = verify(
        &real::chainguard(),
        &real::CHAINGUARD_DIGEST,
        &real::keyless(vec![real::chainguard_identity()]),
    );
    assert!(chainguard.is_ok());
    assert_eq!(chainguard_verify(chainguard_cc()), chainguard);
}

/// One field of the rule off on a real leaf: each refusal names it.
#[test]
fn real_certificates_negative() {
    let cases = [
        (
            runner_verify(
                CertificateClaims::new(
                    exact("https://github.com/actions/other"),
                    exact(real::RUNNER_REF),
                    triggers(&[real::RUNNER_TRIGGER]),
                )
                .expect("cc"),
            ),
            Extension::SourceRepositoryUri,
        ),
        (
            runner_verify(
                CertificateClaims::new(
                    exact(real::RUNNER_REPOSITORY),
                    exact("refs/heads/dev"),
                    triggers(&[real::RUNNER_TRIGGER]),
                )
                .expect("cc"),
            ),
            Extension::SourceRepositoryRef,
        ),
        (
            jq_verify(
                CertificateClaims::new(
                    exact(real::JQ_REPOSITORY),
                    prefix("refs/heads/"),
                    triggers(&[real::JQ_TRIGGER]),
                )
                .expect("cc"),
            ),
            Extension::SourceRepositoryRef,
        ),
        (
            runner_verify(
                CertificateClaims::new(
                    exact(real::RUNNER_REPOSITORY),
                    exact(real::RUNNER_REF),
                    triggers(&["push"]),
                )
                .expect("cc"),
            ),
            Extension::BuildTrigger,
        ),
        (
            runner_verify(
                CertificateClaims::new(
                    exact(real::RUNNER_REPOSITORY),
                    exact(real::RUNNER_REF),
                    triggers(&[real::RUNNER_TRIGGER]),
                )
                .expect("cc")
                .with_repository_id("184286876")
                .expect("id"),
            ),
            Extension::SourceRepositoryIdentifier,
        ),
        (
            chainguard_verify(only_triggers(&["schedule"])),
            Extension::BuildTrigger,
        ),
    ];
    for (i, (got, ext)) in cases.into_iter().enumerate() {
        assert_eq!(got, mismatch(ext), "case {i}");
    }
}

// ---------------------------------------------------------------------
// Reading the extensions
// ---------------------------------------------------------------------

/// A trust without certificate claims reads no Fulcio extension beyond
/// the issuer: a malformed 1.12 and no 1.20 pass, on a cosign layer and
/// on an SLSA bundle under #104's claims.
#[test]
fn no_certificate_claims_reads_no_extension() {
    let pki = Pki::new();
    let leaf = gh_leaf()
        .fulcio(12, Some(b"https://github.com/acme/app".to_vec()))
        .fulcio(20, None);
    assert_eq!(
        verify_leaf(&pki, &leaf, &gh_trust(&pki, &[COSIGN_SIGN_PREDICATE])),
        PASS
    );
    let trust = gh_trust(&pki, &[SLSA_PROVENANCE_V1_PREDICATE])
        .with_claims(repository_claim(GH_REPOSITORY))
        .expect("claims");
    assert_eq!(bundle(&pki, &leaf, agreeing(), &trust), PASS);
}

/// A 1.12 of `len` bytes of `a`, as a whole UTF8String.
fn text_of(len: usize) -> String {
    "a".repeat(len)
}

#[test]
fn extension_der_forms() {
    let pki = Pki::new();
    // Accepted lengths, short and long form, each read as its text.
    for len in [1, 127, 128, 255, 256] {
        let text = text_of(len);
        let value = utf8(text.as_bytes());
        let header = match len {
            0..=127 => vec![0x0C, len as u8],
            128..=255 => vec![0x0C, 0x81, len as u8],
            _ => vec![0x0C, 0x82, (len >> 8) as u8, len as u8],
        };
        assert!(value.starts_with(&header), "{len}");
        let leaf = gh_leaf().fulcio(12, Some(value));
        let cc = CertificateClaims::new(exact(&text), None, triggers(&[GH_TRIGGER])).expect("cc");
        assert_eq!(layer(&pki, &leaf, cc), PASS, "{len}");
    }
    let text = b"https://github.com/acme/app";
    let with = |head: &[u8], tail: &[u8]| [head, &text[..], tail].concat();
    let long = text_of(128);
    let bad: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![0x0C, 0x00]),
        (
            "non-minimal 0x81",
            with(&[0x0C, 0x81, text.len() as u8], &[]),
        ),
        (
            "non-minimal 0x82",
            [&[0x0C, 0x82, 0x00, 0x80][..], long.as_bytes()].concat(),
        ),
        (
            "0x83 form",
            with(&[0x0C, 0x83, 0x00, 0x00, text.len() as u8], &[]),
        ),
        ("indefinite", with(&[0x0C, 0x80], &[0x00, 0x00])),
        ("truncated 0x81", vec![0x0C, 0x81]),
        ("truncated 0x82", vec![0x0C, 0x82, 0x01]),
        ("trailing byte", with(&[0x0C, text.len() as u8], &[0x00])),
        ("short content", with(&[0x0C, text.len() as u8 + 1], &[])),
        ("IA5String", with(&[0x16, text.len() as u8], &[])),
        ("PrintableString", with(&[0x13, text.len() as u8], &[])),
        ("OCTET STRING", with(&[0x04, text.len() as u8], &[])),
        ("raw, no tag", text.to_vec()),
        ("nothing", vec![]),
    ];
    for (name, value) in bad {
        let leaf = gh_leaf().fulcio(12, Some(value));
        assert_eq!(
            layer(&pki, &leaf, only_triggers(&[GH_TRIGGER])),
            malformed(Extension::SourceRepositoryUri),
            "{name}"
        );
    }
}

#[test]
fn extension_utf8() {
    let pki = Pki::new();
    for (name, bytes) in [
        ("lone continuation", &[0x80][..]),
        ("overlong", &[0xC0, 0xAF][..]),
        ("surrogate", &[0xED, 0xA0, 0x80][..]),
        ("truncated", &[0xE2, 0x82][..]),
    ] {
        let mut text = b"https://github.com/acme/".to_vec();
        text.extend_from_slice(bytes);
        let leaf = gh_leaf().fulcio(12, Some(utf8(&text)));
        assert_eq!(
            layer(&pki, &leaf, only_triggers(&[GH_TRIGGER])),
            malformed(Extension::SourceRepositoryUri),
            "{name}"
        );
    }
    // Valid non-ASCII parses, and then does not meet an ASCII rule.
    let cyrillic = "https://github.com/\u{430}cme/app";
    let leaf = gh_leaf().fulcio(12, Some(utf8(cyrillic.as_bytes())));
    assert_eq!(
        layer(&pki, &leaf, only_triggers(&[GH_TRIGGER])),
        PASS,
        "read"
    );
    assert_eq!(
        layer(&pki, &leaf, gh_claims()),
        mismatch(Extension::SourceRepositoryUri)
    );
}

/// The certificate reader of `boneli-https` refuses a leaf with an
/// extension twice, under any trust.
#[test]
fn duplicated_extension_refuses_the_leaf() {
    let pki = Pki::new();
    for nn in [12, 20] {
        let mut leaf = gh_leaf();
        leaf.extra
            .push(fulcio_ext(nn, &utf8(b"https://github.com/acme/other")));
        let plain = gh_trust(&pki, &[COSIGN_SIGN_PREDICATE]);
        for trust in [plain, layer_trust(&pki, gh_claims())] {
            assert_eq!(
                verify_leaf(&pki, &leaf, &trust),
                Err(Refusal::Certificate(boneli_https::CertError::Malformed)),
                "1.{nn}"
            );
        }
    }
}

#[test]
fn missing_extension_named() {
    let pki = Pki::new();
    let repository =
        CertificateClaims::new(exact(GH_REPOSITORY), None, triggers(&[GH_TRIGGER])).expect("cc");
    let git_ref = CertificateClaims::new(None, exact(GH_REF), triggers(&[GH_TRIGGER])).expect("cc");
    let id = only_triggers(&[GH_TRIGGER])
        .with_repository_id(GH_ID)
        .expect("id");
    for (nn, cc, ext) in [
        (12, repository, Extension::SourceRepositoryUri),
        (14, git_ref, Extension::SourceRepositoryRef),
        (15, id, Extension::SourceRepositoryIdentifier),
        (20, only_triggers(&[GH_TRIGGER]), Extension::BuildTrigger),
    ] {
        let leaf = gh_leaf().fulcio(nn, None);
        assert_eq!(layer(&pki, &leaf, cc), missing(ext), "1.{nn}");
    }
    // A missing extension no rule needs passes.
    for nn in [9, 12, 13, 14, 15] {
        let leaf = gh_leaf().fulcio(nn, None);
        assert_eq!(
            layer(&pki, &leaf, only_triggers(&[GH_TRIGGER])),
            PASS,
            "1.{nn}"
        );
    }
    // The agreement needs 1.9, 1.12, 1.13 and 1.14.
    for (nn, ext) in [
        (9, Extension::BuildSignerUri),
        (12, Extension::SourceRepositoryUri),
        (13, Extension::SourceRepositoryDigest),
        (14, Extension::SourceRepositoryRef),
    ] {
        let leaf = gh_leaf().fulcio(nn, None);
        let trust = slsa_trust(
            &pki,
            Some(repository_claim(GH_REPOSITORY)),
            only_triggers(&[GH_TRIGGER]).with_statement_agreement(),
        );
        assert_eq!(
            bundle(&pki, &leaf, agreeing(), &trust),
            missing(ext),
            "1.{nn}"
        );
    }
}

/// Under any certificate claims, every modeled extension that is present
/// is read, and the first malformed one in OID order is named.
#[test]
fn one_reading_under_any_certificate_claim() {
    let pki = Pki::new();
    let raw = Some(b"not DER".to_vec());
    let leaf = gh_leaf().fulcio(13, raw.clone());
    assert_eq!(
        layer(&pki, &leaf, only_triggers(&[GH_TRIGGER])),
        malformed(Extension::SourceRepositoryDigest)
    );
    let leaf = gh_leaf().fulcio(20, raw.clone()).fulcio(9, raw.clone());
    assert_eq!(
        layer(&pki, &leaf, only_triggers(&[GH_TRIGGER])),
        malformed(Extension::BuildSignerUri)
    );
    for (nn, ext) in [
        (9, Extension::BuildSignerUri),
        (12, Extension::SourceRepositoryUri),
        (13, Extension::SourceRepositoryDigest),
        (14, Extension::SourceRepositoryRef),
        (15, Extension::SourceRepositoryIdentifier),
        (20, Extension::BuildTrigger),
    ] {
        let leaf = gh_leaf().fulcio(nn, Some(utf8(b"")));
        assert_eq!(
            layer(&pki, &leaf, only_triggers(&[GH_TRIGGER])),
            malformed(ext),
            "1.{nn}"
        );
    }
}

#[test]
fn deprecated_extensions_never_read() {
    let pki = Pki::new();
    // 1.2 (raw trigger) says `pull_request_target`, 1.20 says `push`.
    let leaf = gh_leaf().fulcio(2, Some(b"pull_request_target".to_vec()));
    assert_eq!(layer(&pki, &leaf, only_triggers(&["push"])), PASS);
    assert_eq!(
        layer(&pki, &leaf, only_triggers(&["pull_request_target"])),
        mismatch(Extension::BuildTrigger)
    );
    // 1.6 (raw ref) says another ref.
    let leaf = gh_leaf().fulcio(6, Some(b"refs/heads/other".to_vec()));
    assert_eq!(layer(&pki, &leaf, gh_claims()), PASS);
    // Without 1.20, a raw 1.2 is no fallback.
    let leaf = gh_leaf().fulcio(20, None).fulcio(2, Some(b"push".to_vec()));
    assert_eq!(
        layer(&pki, &leaf, only_triggers(&["push"])),
        missing(Extension::BuildTrigger)
    );
}

#[test]
fn extension_position_irrelevant() {
    let pki = Pki::new();
    let value = utf8(GH_REPOSITORY.as_bytes());
    let mut first = gh_leaf().fulcio(12, None);
    first.first = vec![fulcio_ext(12, &value)];
    let mut after = gh_leaf().fulcio(12, None);
    after.after_sct = vec![fulcio_ext(12, &value)];
    for leaf in [first, after] {
        assert_eq!(layer(&pki, &leaf, gh_claims()), PASS);
        let other = CertificateClaims::new(
            exact("https://github.com/acme/other"),
            None,
            triggers(&[GH_TRIGGER]),
        )
        .expect("cc");
        assert_eq!(
            layer(&pki, &leaf, other),
            mismatch(Extension::SourceRepositoryUri)
        );
    }
}

/// webpki refuses a leaf with an unknown critical extension when it
/// parses it, before any chain is built (`Malformed`), under any trust.
#[test]
fn critical_fulcio_extension_refused() {
    let pki = Pki::new();
    let mut leaf = gh_leaf().fulcio(12, None);
    leaf.extra
        .push(ext(&fulcio_oid(12), true, &utf8(GH_REPOSITORY.as_bytes())));
    for trust in [
        gh_trust(&pki, &[COSIGN_SIGN_PREDICATE]),
        layer_trust(&pki, gh_claims()),
    ] {
        assert_eq!(
            verify_leaf(&pki, &leaf, &trust),
            Err(Refusal::Certificate(boneli_https::CertError::Malformed))
        );
    }
}

// ---------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------

#[test]
fn certificate_rule_matching_is_byte_exact() {
    let pki = Pki::new();
    let rule =
        || CertificateClaims::new(exact(GH_REPOSITORY), None, triggers(&[GH_TRIGGER])).expect("cc");
    let leaf = gh_leaf();
    assert_eq!(layer(&pki, &leaf, rule()), PASS);
    for value in [
        "https://github.com/acme/app.git",
        "http://github.com/acme/app",
        "https://github.com/Acme/app",
        "https://github.com/acme/app/",
        "https://github.com/acme/app ",
        "https://github.com/acme/app\u{200b}",
        "https://github.com/\u{430}cme/app",
        "https://github.com/acme\u{ff0f}app",
    ] {
        let leaf = gh_leaf().fulcio(12, Some(utf8(value.as_bytes())));
        assert_eq!(
            layer(&pki, &leaf, rule()),
            mismatch(Extension::SourceRepositoryUri),
            "{value:?}"
        );
    }
}

#[test]
fn certificate_prefix_boundary() {
    let pki = Pki::new();
    let rule =
        || CertificateClaims::new(None, prefix("refs/tags/"), triggers(&[GH_TRIGGER])).expect("cc");
    for (value, passes) in [
        ("refs/tags/v1", true),
        ("refs/tags/v1/rc", true),
        ("refs/tags/", false),
        ("refs/tagsx/v1", false),
        ("refs/tags/a/../b", false),
        ("refs/tags/v1#x", false),
        ("refs/tags/%2e%2e", false),
        ("refs/tags/a\\b", false),
        ("refs/tags//x", false),
        ("refs/heads/main", false),
    ] {
        let leaf = gh_leaf().fulcio(14, Some(utf8(value.as_bytes())));
        let expected = if passes {
            PASS
        } else {
            mismatch(Extension::SourceRepositoryRef)
        };
        assert_eq!(layer(&pki, &leaf, rule()), expected, "{value:?}");
    }
    let rule = CertificateClaims::new(
        prefix("https://github.com/acme/"),
        None,
        triggers(&[GH_TRIGGER]),
    )
    .expect("cc");
    let leaf = gh_leaf().fulcio(12, Some(utf8(b"https://github.com/acme-evil/x")));
    assert_eq!(
        layer(&pki, &leaf, rule.clone()),
        mismatch(Extension::SourceRepositoryUri)
    );
    assert_eq!(layer(&pki, &gh_leaf(), rule), PASS);
}

#[test]
fn trigger_list_membership() {
    let pki = Pki::new();
    for (value, passes) in [
        ("push", true),
        ("release", true),
        ("pull_request_target", false),
        ("Push", false),
        ("push ", false),
        ("push\u{200b}", false),
        ("pus", false),
        ("pushx", false),
    ] {
        let leaf = gh_leaf().fulcio(20, Some(utf8(value.as_bytes())));
        let expected = if passes {
            PASS
        } else {
            mismatch(Extension::BuildTrigger)
        };
        assert_eq!(
            layer(&pki, &leaf, only_triggers(&["push", "release"])),
            expected,
            "{value:?}"
        );
    }
    // A trigger listed twice is accepted.
    assert_eq!(
        layer(&pki, &gh_leaf(), only_triggers(&["push", "push"])),
        PASS
    );
}

#[test]
fn repository_id_exact() {
    let pki = Pki::new();
    for (value, passes) in [
        (GH_ID, true),
        ("42420", false),
        ("424", false),
        ("04242", false),
        ("4242 ", false),
    ] {
        let leaf = gh_leaf().fulcio(15, Some(utf8(value.as_bytes())));
        let expected = if passes {
            PASS
        } else {
            mismatch(Extension::SourceRepositoryIdentifier)
        };
        assert_eq!(layer(&pki, &leaf, gh_claims()), expected, "{value:?}");
    }
}

// ---------------------------------------------------------------------
// Order
// ---------------------------------------------------------------------

#[test]
fn rules_checked_in_order() {
    let pki = Pki::new();
    let other = |_: u8, text: &str| Some(utf8(text.as_bytes()));
    let all_wrong = gh_leaf()
        .fulcio(12, other(12, "https://github.com/acme/other"))
        .fulcio(14, other(14, "refs/heads/dev"))
        .fulcio(15, other(15, "1"))
        .fulcio(20, other(20, "schedule"));
    assert_eq!(
        layer(&pki, &all_wrong, gh_claims()),
        mismatch(Extension::SourceRepositoryUri)
    );
    let ref_on = gh_leaf()
        .fulcio(14, other(14, "refs/heads/dev"))
        .fulcio(15, other(15, "1"))
        .fulcio(20, other(20, "schedule"));
    assert_eq!(
        layer(&pki, &ref_on, gh_claims()),
        mismatch(Extension::SourceRepositoryRef)
    );
    let id_on = gh_leaf()
        .fulcio(15, other(15, "1"))
        .fulcio(20, other(20, "schedule"));
    assert_eq!(
        layer(&pki, &id_on, gh_claims()),
        mismatch(Extension::SourceRepositoryIdentifier)
    );
    // The certificate before the statement's claims.
    let release = || {
        CertificateClaims::new(exact(GH_REPOSITORY), exact(GH_REF), triggers(&["release"]))
            .expect("cc")
    };
    let trust = slsa_trust(
        &pki,
        Some(repository_claim("https://github.com/acme/other")),
        release(),
    );
    assert_eq!(
        bundle(&pki, &gh_leaf(), agreeing(), &trust),
        mismatch(Extension::BuildTrigger)
    );
    // ... and before the predicate is parsed.
    let malformed_predicate = pki::statement(&[&hex(&IMAGE)], SLSA_PROVENANCE_V1_PREDICATE);
    assert_eq!(
        bundle(&pki, &gh_leaf(), malformed_predicate.clone(), &trust),
        mismatch(Extension::BuildTrigger)
    );
    let trust = slsa_trust(&pki, Some(repository_claim(GH_REPOSITORY)), gh_claims());
    assert_eq!(
        bundle(&pki, &gh_leaf(), malformed_predicate, &trust),
        Err(Refusal::MalformedProvenance)
    );
}

// ---------------------------------------------------------------------
// The statement agreement
// ---------------------------------------------------------------------

#[test]
fn agreement_fields() {
    let pki = Pki::new();
    let leaf = gh_leaf();
    assert_eq!(agreement(&pki, &leaf, agreeing()), PASS);
    let deps = gh_dependencies();
    let builder = GH_WORKFLOW.replace("@refs/heads/main", "@refs/heads/dev");
    assert_eq!(
        agreement(
            &pki,
            &leaf,
            gh_statement(&builder, GH_REPOSITORY, GH_REF, &deps)
        ),
        disagrees(Extension::BuildSignerUri)
    );
    for repository in [
        "https://github.com/acme/app.git",
        "https://github.com/Acme/app",
        "https://github.com/\u{430}cme/app",
    ] {
        assert_eq!(
            agreement(
                &pki,
                &leaf,
                gh_statement(GH_WORKFLOW, repository, GH_REF, &deps)
            ),
            disagrees(Extension::SourceRepositoryUri),
            "{repository:?}"
        );
    }
    assert_eq!(
        agreement(
            &pki,
            &leaf,
            gh_statement(GH_WORKFLOW, GH_REPOSITORY, "refs/heads/dev", &deps)
        ),
        disagrees(Extension::SourceRepositoryRef)
    );
    let other_commit = "1123456789abcdef0123456789abcdef01234567";
    for (name, dependencies) in [
        ("none", "[]".to_owned()),
        (
            "other URI",
            format!(
                "[{}]",
                source(
                    "git+https://github.com/acme/other@refs/heads/main",
                    GH_COMMIT
                )
            ),
        ),
        (
            "other commit",
            format!("[{}]", source(GH_MATERIAL, other_commit)),
        ),
        (
            "sha1 only",
            format!(r#"[{{"uri":"{GH_MATERIAL}","digest":{{"sha1":"{GH_COMMIT}"}}}}]"#),
        ),
        ("no digest", format!(r#"[{{"uri":"{GH_MATERIAL}"}}]"#)),
        (
            "one right, one wrong",
            format!(
                "[{},{}]",
                source(GH_MATERIAL, GH_COMMIT),
                source(GH_MATERIAL, other_commit)
            ),
        ),
        (
            "upper-case hex",
            format!("[{}]", source(GH_MATERIAL, &GH_COMMIT.to_uppercase())),
        ),
    ] {
        assert_eq!(
            agreement(
                &pki,
                &leaf,
                gh_statement(GH_WORKFLOW, GH_REPOSITORY, GH_REF, &dependencies)
            ),
            disagrees(Extension::SourceRepositoryDigest),
            "{name}"
        );
    }
    // Two right entries, and other entries next to them, agree.
    let two = format!(
        "[{},{},{}]",
        source(GH_MATERIAL, GH_COMMIT),
        source(
            "git+https://github.com/acme/lib@refs/heads/main",
            other_commit
        ),
        source(GH_MATERIAL, GH_COMMIT)
    );
    assert_eq!(
        agreement(
            &pki,
            &leaf,
            gh_statement(GH_WORKFLOW, GH_REPOSITORY, GH_REF, &two)
        ),
        PASS
    );
    // JSON escapes are undone before comparing.
    assert_eq!(
        agreement(
            &pki,
            &leaf,
            gh_statement(
                GH_WORKFLOW,
                r"https:\/\/github.com\/acme\/app",
                GH_REF,
                &deps
            )
        ),
        PASS
    );
}

#[test]
fn agreement_before_statement_claims() {
    let pki = Pki::new();
    let leaf = gh_leaf();
    let deps = gh_dependencies();
    let builder = GH_WORKFLOW.replace("@refs/heads/main", "@refs/heads/dev");
    // Disagrees on the builder and fails the repository claim.
    let trust = slsa_trust(
        &pki,
        Some(repository_claim("https://github.com/acme/other")),
        gh_claims().with_statement_agreement(),
    );
    assert_eq!(
        bundle(
            &pki,
            &leaf,
            gh_statement(&builder, GH_REPOSITORY, GH_REF, &deps),
            &trust
        ),
        disagrees(Extension::BuildSignerUri)
    );
    // Meets the claims, disagrees on the ref.
    assert_eq!(
        agreement(
            &pki,
            &leaf,
            gh_statement(GH_WORKFLOW, GH_REPOSITORY, "refs/heads/dev", &deps)
        ),
        disagrees(Extension::SourceRepositoryRef)
    );
}

#[test]
fn agreement_is_opt_in() {
    let pki = Pki::new();
    let statement = gh_statement(GH_WORKFLOW, GH_REPOSITORY, "refs/heads/dev", "[]");
    let trust = slsa_trust(&pki, Some(repository_claim(GH_REPOSITORY)), gh_claims());
    assert_eq!(bundle(&pki, &gh_leaf(), statement.clone(), &trust), PASS);
    assert_eq!(
        agreement(&pki, &gh_leaf(), statement),
        disagrees(Extension::SourceRepositoryRef)
    );
}

#[test]
fn agreement_needs_github_build_type() {
    let pki = Pki::new();
    let statement = gh_statement_typed(
        "https://example.com/buildtypes/other/v1",
        GH_WORKFLOW,
        GH_REPOSITORY,
        GH_REF,
        &gh_dependencies(),
    );
    let material = || {
        Claims::new(
            None,
            None,
            None,
            vec![Material::new(GH_MATERIAL, "gitCommit", GH_COMMIT).expect("m")],
        )
        .expect("claims")
    };
    let without = slsa_trust(&pki, Some(material()), gh_claims());
    assert_eq!(bundle(&pki, &gh_leaf(), statement.clone(), &without), PASS);
    let with = slsa_trust(
        &pki,
        Some(material()),
        gh_claims().with_statement_agreement(),
    );
    assert_eq!(
        bundle(&pki, &gh_leaf(), statement, &with),
        Err(Refusal::UnknownBuildType)
    );
}

// ---------------------------------------------------------------------
// Carriers, configuration and texts
// ---------------------------------------------------------------------

#[test]
fn every_keyless_carrier_under_certificate_claims() {
    let pki = Pki::new();
    let leaf = gh_leaf();
    // A keyless cosign layer.
    assert_eq!(layer(&pki, &leaf, gh_claims()), PASS);
    // A keyless cosign/sign/v1 bundle.
    let spec = BundleSpec::keyless(&pki, &leaf, &IMAGE);
    let evidence = Evidence::from_bundle(&spec.bytes(&pki)).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &layer_trust(&pki, gh_claims())),
        PASS
    );
    // An SLSA bundle whose predicate is never parsed.
    let malformed_predicate = pki::statement(&[&hex(&IMAGE)], SLSA_PROVENANCE_V1_PREDICATE);
    let trust = slsa_trust(&pki, None, gh_claims());
    assert_eq!(bundle(&pki, &leaf, malformed_predicate, &trust), PASS);
    // A cosign layer that fails the certificate claims is refused too.
    let layer_other = gh_leaf().fulcio(20, Some(utf8(b"schedule")));
    assert_eq!(
        layer(&pki, &layer_other, gh_claims()),
        mismatch(Extension::BuildTrigger)
    );
}

#[test]
fn certificate_claims_configuration() {
    assert_eq!(
        CertificateClaims::new(exact(GH_REPOSITORY), None, vec![]).err(),
        Some(ConfigError::TriggersEmpty)
    );
    for trigger in ["", "pu sh", "p\u{fc}sh", "push\t"] {
        assert_eq!(
            CertificateClaims::new(None, None, triggers(&["push", trigger])).err(),
            Some(ConfigError::ClaimNotAscii),
            "{trigger:?}"
        );
    }
    for rule in [
        (prefix("https://github.com/acme"), None),
        (None, prefix("refs/tags")),
    ] {
        assert_eq!(
            CertificateClaims::new(rule.0, rule.1, triggers(&["push"])).err(),
            Some(ConfigError::ClaimPrefixWithoutBoundary)
        );
    }
    for rule in [
        (exact(""), None),
        (None, exact("refs/heads/ma in")),
        (prefix("https://github.com/\u{430}cme/"), None),
    ] {
        assert_eq!(
            CertificateClaims::new(rule.0, rule.1, triggers(&["push"])).err(),
            Some(ConfigError::ClaimNotAscii)
        );
    }
    for id in ["", "0", "01", "12a", "\u{ff11}\u{ff12}", "-1", "+1", " 1"] {
        assert_eq!(
            only_triggers(&["push"]).with_repository_id(id).err(),
            Some(ConfigError::RepositoryIdNotDecimal),
            "{id:?}"
        );
    }
    for id in ["1", "10", "5101141", "184286875"] {
        assert!(only_triggers(&["push"]).with_repository_id(id).is_ok());
    }

    let pki = Pki::new();
    let root = || trusted_root(&root_value(&pki));
    let keyed = Trust::new(
        vec![pki.signer_key.public.clone()],
        None,
        vec![COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("keyed");
    let both = Trust::new(
        vec![pki.signer_key.public.clone()],
        Some((root(), vec![gh_identity()])),
        vec![COSIGN_SIGN_PREDICATE.to_owned()],
    )
    .expect("both");
    for trust in [keyed, both] {
        assert_eq!(
            trust.with_certificate_claims(gh_claims()).err(),
            Some(ConfigError::CertificateClaimsWithKeys)
        );
    }
    let identity = |issuer: &str| {
        Identity::new(issuer, SanRule::Uri(GH_WORKFLOW.to_owned())).expect("identity")
    };
    for identities in [
        vec![identity(real::GOOGLE)],
        vec![identity(&format!("{GITHUB_ACTIONS_ISSUER}/"))],
        vec![identity("http://token.actions.githubusercontent.com")],
        vec![identity("https://token.actions.githubusercontent.com/acme")],
        vec![identity(GITHUB_ACTIONS_ISSUER), identity(real::GOOGLE)],
    ] {
        let trust = Trust::new(
            Vec::new(),
            Some((root(), identities)),
            vec![COSIGN_SIGN_PREDICATE.to_owned()],
        )
        .expect("trust");
        assert_eq!(
            trust.with_certificate_claims(gh_claims()).err(),
            Some(ConfigError::CertificateClaimsIssuer)
        );
    }
    assert_eq!(GITHUB_ACTIONS_ISSUER, GITHUB_ISSUER);
    // The agreement needs #104's claims, set first.
    assert_eq!(
        gh_trust(&pki, &[SLSA_PROVENANCE_V1_PREDICATE])
            .with_certificate_claims(gh_claims().with_statement_agreement())
            .err(),
        Some(ConfigError::AgreementWithoutClaims)
    );
    let trust = gh_trust(&pki, &[SLSA_PROVENANCE_V1_PREDICATE])
        .with_claims(repository_claim(GH_REPOSITORY))
        .expect("claims")
        .with_certificate_claims(gh_claims().with_statement_agreement())
        .expect("agreement after claims");
    assert_eq!(
        trust.certificate_claims(),
        Some(&gh_claims().with_statement_agreement())
    );
    // Claims set after the certificate claims keep them.
    let trust = with_cc(gh_trust(&pki, &[SLSA_PROVENANCE_V1_PREDICATE]), gh_claims())
        .with_claims(repository_claim(GH_REPOSITORY))
        .expect("claims after");
    assert_eq!(trust.certificate_claims(), Some(&gh_claims()));
    assert!(
        gh_trust(&pki, &[COSIGN_SIGN_PREDICATE])
            .certificate_claims()
            .is_none()
    );
}

#[test]
fn trust_debug_shows_no_certificate_claim_text() {
    let pki = Pki::new();
    let plain = format!("{:?}", gh_trust(&pki, &[COSIGN_SIGN_PREDICATE]));
    assert_eq!(
        plain,
        "Trust { keys: 0, identities: 1, predicate_types: 1 }"
    );
    let cc = CertificateClaims::new(
        exact("https://github.com/secret-owner/app"),
        exact("refs/heads/secret-branch"),
        triggers(&["secret_trigger"]),
    )
    .expect("cc")
    .with_repository_id("987654321")
    .expect("id");
    let with = format!("{:?}", layer_trust(&pki, cc));
    assert_eq!(
        with,
        "Trust { keys: 0, identities: 1, predicate_types: 1, certificate_claims: true }"
    );
}

#[test]
fn certificate_refusal_texts() {
    use CertificateRefusal::{Malformed, Mismatch, Missing, StatementDisagrees};
    let extensions = [
        (
            Extension::BuildSignerUri,
            "Build Signer URI (1.3.6.1.4.1.57264.1.9)",
        ),
        (
            Extension::SourceRepositoryUri,
            "Source Repository URI (1.3.6.1.4.1.57264.1.12)",
        ),
        (
            Extension::SourceRepositoryDigest,
            "Source Repository Digest (1.3.6.1.4.1.57264.1.13)",
        ),
        (
            Extension::SourceRepositoryRef,
            "Source Repository Ref (1.3.6.1.4.1.57264.1.14)",
        ),
        (
            Extension::SourceRepositoryIdentifier,
            "Source Repository Identifier (1.3.6.1.4.1.57264.1.15)",
        ),
        (
            Extension::BuildConfigUri,
            "Build Config URI (1.3.6.1.4.1.57264.1.18)",
        ),
        (
            Extension::BuildTrigger,
            "Build Trigger (1.3.6.1.4.1.57264.1.20)",
        ),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (ext, name) in extensions {
        assert_eq!(ext.to_string(), name);
        for (refusal, text) in [
            (
                Missing(ext),
                format!("the certificate has no Fulcio {name}"),
            ),
            (
                Malformed(ext),
                format!("the certificate's Fulcio {name} is malformed"),
            ),
            (
                Mismatch(ext),
                format!("the certificate's Fulcio {name} does not meet the rule"),
            ),
            (
                StatementDisagrees(ext),
                format!("the provenance disagrees with the certificate's Fulcio {name}"),
            ),
        ] {
            assert_eq!(Refusal::CertificateClaim(refusal).to_string(), text);
            assert!(text.is_ascii());
            assert!(seen.insert(text));
        }
    }
    for (error, text) in [
        (
            ConfigError::TriggersEmpty,
            "certificate claims list no trigger",
        ),
        (
            ConfigError::RepositoryIdNotDecimal,
            "a repository ID is not a decimal number without a leading zero",
        ),
        (
            ConfigError::CertificateClaimsWithKeys,
            "a trust with keys cannot have certificate claims",
        ),
        (
            ConfigError::CertificateClaimsIssuer,
            "certificate claims need every identity's issuer to be GitHub Actions'",
        ),
        (
            ConfigError::AgreementWithoutClaims,
            "the statement agreement needs provenance claims, set first",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
}

/// Every Fulcio TLV the leaf carries, cut at every length, is refused as
/// malformed, never a panic.
#[test]
fn truncated_extensions_refused() {
    let pki = Pki::new();
    let value = utf8(GH_REPOSITORY.as_bytes());
    for n in 0..value.len() {
        let leaf = gh_leaf().fulcio(12, Some(value[..n].to_vec()));
        assert_eq!(
            layer(&pki, &leaf, only_triggers(&[GH_TRIGGER])),
            malformed(Extension::SourceRepositoryUri),
            "{n}"
        );
    }
    let long = tlv(0x0C, text_of(300).as_bytes());
    for n in [1, 2, 3, 4, 150, 303] {
        let leaf = gh_leaf().fulcio(12, Some(long[..n].to_vec()));
        assert_eq!(
            layer(&pki, &leaf, only_triggers(&[GH_TRIGGER])),
            malformed(Extension::SourceRepositoryUri),
            "{n}"
        );
    }
}

// ---------------------------------------------------------------------
// The calling workflow file: Build Config URI (1.18)
// ---------------------------------------------------------------------

fn workflow_path(cc: CertificateClaims, path: &str) -> CertificateClaims {
    cc.with_workflow_path(path).expect("workflow path")
}

/// The three real leaves meet a workflow-path rule naming their own
/// workflow file, with the same `Accepted` as without it (each 1.18 is
/// `<1.12>/<path>@<1.14>`), and another path refuses naming 1.18.
#[test]
fn real_workflow_path_known_answer() {
    let runner = runner_verify(runner_cc());
    assert!(runner.is_ok());
    assert_eq!(
        runner_verify(workflow_path(
            runner_cc(),
            ".github/workflows/docker-publish.yml"
        )),
        runner
    );
    let jq = jq_verify(jq_cc());
    assert!(jq.is_ok());
    assert_eq!(
        jq_verify(workflow_path(jq_cc(), ".github/workflows/ci.yml")),
        jq
    );
    let chainguard = chainguard_verify(chainguard_cc());
    assert!(chainguard.is_ok());
    assert_eq!(
        chainguard_verify(workflow_path(
            chainguard_cc(),
            ".github/workflows/release.yaml"
        )),
        chainguard
    );
    for other in [
        ".github/workflows/release.yml",
        ".github/workflows/docker-publish.yaml",
        ".github/workflows/docker-publish.yml/x",
        "github/workflows/docker-publish.yml",
        "docker-publish.yml",
    ] {
        assert_eq!(
            runner_verify(workflow_path(runner_cc(), other)),
            mismatch(Extension::BuildConfigUri),
            "{other}"
        );
    }
    // The 1.18 rule comes after the ID and before the trigger.
    let cc = CertificateClaims::new(
        exact(real::RUNNER_REPOSITORY),
        exact(real::RUNNER_REF),
        triggers(&["push"]),
    )
    .expect("cc");
    assert_eq!(
        runner_verify(workflow_path(cc, ".github/workflows/ci.yml")),
        mismatch(Extension::BuildConfigUri)
    );
}

const CALLER: &str = "https://github.com/acme/app/.github/workflows/release.yml";
const CALLER_PATH: &str = ".github/workflows/release.yml";

/// A leaf of a tag release of `acme/app` signed in a reusable workflow:
/// 1.9 names the called generator, 1.18 the caller at `tag`; 1.14 is the
/// tag.
fn release_leaf(tag: &str) -> LeafSpec {
    let git_ref = format!("refs/tags/{tag}");
    let called = "https://github.com/acme/generator/.github/workflows/build.yml@refs/tags/v1";
    LeafSpec::github(GH_WORKFLOW)
        .fulcio(9, Some(utf8(called.as_bytes())))
        .fulcio(14, Some(utf8(git_ref.as_bytes())))
        .fulcio(18, Some(utf8(format!("{CALLER}@{git_ref}").as_bytes())))
}

/// Certificate claims for `acme/app`'s tag releases with `path`.
fn release_claims(path: &str) -> CertificateClaims {
    let cc = CertificateClaims::new(
        exact(GH_REPOSITORY),
        prefix("refs/tags/"),
        triggers(&[GH_TRIGGER]),
    )
    .expect("cc");
    workflow_path(cc, path)
}

/// Under a reusable workflow, the caller's path passes and the called
/// generator's refuses: only 1.18 binds the calling workflow file. Two
/// tags of the same caller both pass under one rule.
#[test]
fn workflow_path_names_the_caller() {
    let pki = Pki::new();
    for tag in ["v2.4.0", "v2.4.1"] {
        let leaf = release_leaf(tag);
        assert_eq!(
            layer(&pki, &leaf, release_claims(CALLER_PATH)),
            PASS,
            "{tag}"
        );
        assert_eq!(
            layer(&pki, &leaf, release_claims(".github/workflows/build.yml")),
            mismatch(Extension::BuildConfigUri),
            "{tag}"
        );
    }
}

/// 1.18 is compared whole against the leaf's own 1.12 and 1.14: a 1.18
/// that names another ref, repository or path, or differs in a byte,
/// refuses; a missing or malformed 1.18 refuses naming it.
#[test]
fn workflow_path_mismatch() {
    let pki = Pki::new();
    let tagged = |uri: &str| release_leaf("v2.4.0").fulcio(18, Some(utf8(uri.as_bytes())));
    for uri in [
        format!("{CALLER}@refs/tags/v2.3.0"),
        format!("{CALLER}@refs/heads/main"),
        "https://github.com/acme/other/.github/workflows/release.yml@refs/tags/v2.4.0".to_owned(),
        "https://github.com/acme/app/.github/workflows/release.yaml@refs/tags/v2.4.0".to_owned(),
        format!("{CALLER}@refs/tags/v2.4.0 "),
        format!("{CALLER}/@refs/tags/v2.4.0"),
        "https://github.com/acme/app//.github/workflows/release.yml@refs/tags/v2.4.0".to_owned(),
        "https://github.com/Acme/app/.github/workflows/release.yml@refs/tags/v2.4.0".to_owned(),
    ] {
        assert_eq!(
            layer(&pki, &tagged(&uri), release_claims(CALLER_PATH)),
            mismatch(Extension::BuildConfigUri),
            "{uri:?}"
        );
    }
    assert_eq!(
        layer(
            &pki,
            &release_leaf("v2.4.0").fulcio(18, None),
            release_claims(CALLER_PATH)
        ),
        missing(Extension::BuildConfigUri)
    );
}

/// A malformed 1.18 refuses under the workflow-path rule, named before a
/// malformed 1.20 (OID order); without the rule it is not read and the
/// leaf passes.
#[test]
fn workflow_path_malformed() {
    let pki = Pki::new();
    for value in [
        b"https://github.com/acme/app".to_vec(),
        vec![0x0C, 0x00],
        vec![0x0C, 0x02, 0xC0, 0xAF],
        vec![0x16, 0x01, b'a'],
    ] {
        let leaf = release_leaf("v2.4.0").fulcio(18, Some(value.clone()));
        assert_eq!(
            layer(&pki, &leaf, release_claims(CALLER_PATH)),
            malformed(Extension::BuildConfigUri),
            "{value:?}"
        );
        let without = CertificateClaims::new(None, None, triggers(&[GH_TRIGGER])).expect("cc");
        assert_eq!(layer(&pki, &leaf, without), PASS, "{value:?}");
    }
    let leaf = release_leaf("v2.4.0")
        .fulcio(18, Some(b"raw".to_vec()))
        .fulcio(20, Some(b"raw".to_vec()));
    assert_eq!(
        layer(&pki, &leaf, release_claims(CALLER_PATH)),
        malformed(Extension::BuildConfigUri)
    );
}

#[test]
fn workflow_path_configuration() {
    for path in [
        "",
        "/.github/workflows/release.yml",
        ".github/workflows/release.yml@refs/tags/v1",
        "@",
        ".github/../release.yml",
        "./release.yml",
        ".github/workflows/.",
        ".github//workflows/release.yml",
        ".github/workflows/",
        ".github/workflows/re lease.yml",
        ".github/workflows/r\u{e9}lease.yml",
        ".github/workflows/release.yml\n",
    ] {
        assert_eq!(
            gh_claims().with_workflow_path(path).err(),
            Some(ConfigError::WorkflowPathNotPlain),
            "{path:?}"
        );
    }
    for path in [
        "release.yml",
        ".github/workflows/release.yml",
        ".github/workflows/..x.yml",
        ".github/workflows/x..yml",
    ] {
        assert!(gh_claims().with_workflow_path(path).is_ok(), "{path:?}");
    }
    assert_eq!(
        ConfigError::WorkflowPathNotPlain.to_string(),
        "a workflow path is not a plain relative path of printable ASCII without @"
    );
}
