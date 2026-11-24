//! SLSA provenance v1 claims (ADR-031): the two real GitHub attestations
//! as known answers, then one test per edge case of the plan over the
//! runner's real statement, edited and signed again with the keyed test
//! signer of `support::pki`.

mod support;

use boneli_https::Sha256;
use boneli_json::Value;
use boneli_sigstore::{
    Accepted, COSIGN_SIGN_PREDICATE, ClaimMatch, ClaimRefusal, Claims, ConfigError, Evidence,
    GITHUB_WORKFLOW_BUILD_TYPE, Material, Refusal, SLSA_PROVENANCE_V1_PREDICATE, Trust, verify,
};
use support::pki::{
    self, IMAGE, OTHER_IMAGE, Pki, hex, keyed_bundle, keyed_layer, obj, payload_for, remove, s,
    set, statement, to_bytes,
};
use support::real;

// ---------------------------------------------------------------------
// Rules and statements
// ---------------------------------------------------------------------

fn exact(text: &str) -> Option<ClaimMatch> {
    Some(ClaimMatch::Exact(text.to_owned()))
}

fn prefix(text: &str) -> Option<ClaimMatch> {
    Some(ClaimMatch::Prefix(text.to_owned()))
}

fn material(uri: &str, digest: &str) -> Material {
    Material::new(uri, "gitCommit", digest).expect("material")
}

fn runner_material() -> Material {
    material(real::RUNNER_MATERIAL, real::RUNNER_COMMIT)
}

/// Every claim the runner's statement meets.
fn runner_claims() -> Claims {
    Claims::new(
        Some(real::RUNNER_WORKFLOW),
        exact(real::RUNNER_REPOSITORY),
        exact(real::RUNNER_REF),
        vec![runner_material()],
    )
    .expect("claims")
}

/// The four single-claim lists the runner's statement meets.
fn single_claims() -> Vec<Claims> {
    vec![
        Claims::new(Some(real::RUNNER_WORKFLOW), None, None, vec![]).expect("builder"),
        Claims::new(None, exact(real::RUNNER_REPOSITORY), None, vec![]).expect("repository"),
        Claims::new(None, None, exact(real::RUNNER_REF), vec![]).expect("ref"),
        Claims::new(None, None, None, vec![runner_material()]).expect("material"),
    ]
}

fn slsa(trust: Trust, claims: Claims) -> Trust {
    trust.with_claims(claims).expect("with claims")
}

/// The runner's real trust with `claims`.
fn runner_trust(claims: Claims) -> Trust {
    slsa(real::slsa_keyless(real::runner_identity()), claims)
}

fn runner_verify(claims: Claims) -> Result<Accepted, Refusal> {
    verify(&real::runner(), &real::RUNNER_DIGEST, &runner_trust(claims))
}

/// A keyed trust in the test signer with the SLSA predicate only.
fn keyed_slsa(pki: &Pki) -> Trust {
    pki::keyed_trust(pki, &[SLSA_PROVENANCE_V1_PREDICATE])
}

/// The runner's real statement over the synthetic `IMAGE`, edited.
fn statement_with(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut st = real::runner_statement();
    set(
        &mut st,
        &["subject"],
        Value::Array(vec![obj(vec![
            ("name", s("registry.boneli.test/app")),
            ("digest", obj(vec![("sha256", s(&hex(&IMAGE)))])),
        ])]),
    );
    edit(&mut st);
    to_bytes(&st)
}

/// `statement` signed by the test signer and verified over `IMAGE` under
/// the keyed SLSA trust with `claims`.
fn keyed_verify(pki: &Pki, statement: &[u8], claims: Option<Claims>) -> Result<Accepted, Refusal> {
    let evidence = Evidence::from_bundle(&to_bytes(&keyed_bundle(&pki.signer_key, statement)))?;
    let trust = match claims {
        Some(claims) => slsa(keyed_slsa(pki), claims),
        None => keyed_slsa(pki),
    };
    verify(&evidence, &IMAGE, &trust)
}

const KEYED: Result<Accepted, Refusal> = Ok(Accepted::Keyed { key: 0 });

fn claim(refusal: ClaimRefusal) -> Result<Accepted, Refusal> {
    Err(Refusal::Claim(refusal))
}

/// An object of `members`, for `resolvedDependencies` entries.
fn dependency(uri: &str, digest: Vec<(&str, &str)>) -> Value {
    obj(vec![
        ("uri", s(uri)),
        (
            "digest",
            obj(digest.into_iter().map(|(k, v)| (k, s(v))).collect()),
        ),
    ])
}

const DEPENDENCIES: &[&str] = &["predicate", "buildDefinition", "resolvedDependencies"];
const REPOSITORY: &[&str] = &[
    "predicate",
    "buildDefinition",
    "externalParameters",
    "workflow",
    "repository",
];
const REF: &[&str] = &[
    "predicate",
    "buildDefinition",
    "externalParameters",
    "workflow",
    "ref",
];
const BUILDER_ID: &[&str] = &["predicate", "runDetails", "builder", "id"];
const BUILD_TYPE: &[&str] = &["predicate", "buildDefinition", "buildType"];

// ---------------------------------------------------------------------
// Known answers
// ---------------------------------------------------------------------

/// The two real GitHub attestations (captured 2026-11-24) verify against
/// the public-good root and meet their claims: the runner with an exact
/// builder, repository, ref and source commit; jq under its tag prefix
/// identity with an exact repository, the ref prefix `refs/tags/` and
/// its source commit. The bundle and subject digests are pinned.
#[test]
fn real_provenance_meets_its_claims() {
    assert_eq!(
        Sha256::digest(real::RUNNER_BUNDLE),
        real::RUNNER_BUNDLE_SHA256
    );
    assert_eq!(Sha256::digest(real::JQ_BUNDLE), real::JQ_BUNDLE_SHA256);
    assert_eq!(
        runner_verify(runner_claims()),
        Ok(Accepted::Keyless {
            integrated_time: real::RUNNER_INTEGRATED,
            log_index: real::RUNNER_LOG_INDEX,
            identity: 0
        })
    );
    let jq_claims = Claims::new(
        None,
        exact(real::JQ_REPOSITORY),
        prefix("refs/tags/"),
        vec![material(real::JQ_MATERIAL, real::JQ_COMMIT)],
    )
    .expect("claims");
    let trust = slsa(real::slsa_keyless(real::jq_identity()), jq_claims);
    assert_eq!(
        verify(&real::jq(), &real::JQ_DIGEST, &trust),
        Ok(Accepted::Keyless {
            integrated_time: real::JQ_INTEGRATED,
            log_index: real::JQ_LOG_INDEX,
            identity: 0
        })
    );
    // Each single claim passes on its own too.
    for claims in single_claims() {
        assert!(runner_verify(claims).is_ok());
    }
}

/// The issue's five negative fixtures, over the real runner statement:
/// one field of the rule changed each.
#[test]
fn real_provenance_negative() {
    let builder = real::RUNNER_WORKFLOW.replace("@refs/heads/main", "@refs/heads/other");
    let cases: Vec<(Claims, ClaimRefusal)> = vec![
        (
            Claims::new(
                Some(&builder),
                exact(real::RUNNER_REPOSITORY),
                exact(real::RUNNER_REF),
                vec![runner_material()],
            )
            .expect("claims"),
            ClaimRefusal::BuilderId,
        ),
        (
            Claims::new(
                Some(real::RUNNER_WORKFLOW),
                exact("https://github.com/actions/runner2"),
                exact(real::RUNNER_REF),
                vec![runner_material()],
            )
            .expect("claims"),
            ClaimRefusal::SourceRepository,
        ),
        (
            Claims::new(
                Some(real::RUNNER_WORKFLOW),
                exact(real::RUNNER_REPOSITORY),
                exact("refs/heads/mai"),
                vec![runner_material()],
            )
            .expect("claims"),
            ClaimRefusal::SourceRef,
        ),
        (
            Claims::new(
                Some(real::RUNNER_WORKFLOW),
                exact(real::RUNNER_REPOSITORY),
                exact("refs/heads/main/"),
                vec![runner_material()],
            )
            .expect("claims"),
            ClaimRefusal::SourceRef,
        ),
        (
            Claims::new(
                Some(real::RUNNER_WORKFLOW),
                exact(real::RUNNER_REPOSITORY),
                exact(real::RUNNER_REF),
                vec![material(
                    "git+https://github.com/actions/runner@refs/heads/other",
                    real::RUNNER_COMMIT,
                )],
            )
            .expect("claims"),
            ClaimRefusal::MaterialMissing(0),
        ),
        (
            Claims::new(
                Some(real::RUNNER_WORKFLOW),
                exact(real::RUNNER_REPOSITORY),
                exact(real::RUNNER_REF),
                vec![material(
                    real::RUNNER_MATERIAL,
                    "8cfa1049f86781d141056082d73802d56cd2b434",
                )],
            )
            .expect("claims"),
            ClaimRefusal::MaterialDigest(0),
        ),
    ];
    for (claims, refusal) in cases {
        assert_eq!(runner_verify(claims), claim(refusal));
    }
}

// ---------------------------------------------------------------------
// #57's behavior without claims
// ---------------------------------------------------------------------

/// Without claims a signed SLSA v1 statement whose predicate is `5`
/// passes exactly as in #57; with any one claim the same bundle is
/// refused as malformed provenance.
#[test]
fn no_claims_behaves_as_before() {
    let pki = Pki::new();
    let st = statement_with(|st| {
        set(
            st,
            &["predicate"],
            Value::Number(boneli_json::Number::from_lexeme("5").expect("number")),
        )
    });
    assert_eq!(keyed_verify(&pki, &st, None), KEYED);
    assert!(keyed_slsa(&pki).claims().is_none());
    for claims in single_claims() {
        assert_eq!(
            keyed_verify(&pki, &st, Some(claims)),
            Err(Refusal::MalformedProvenance)
        );
    }
}

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

#[test]
fn claims_configuration() {
    assert_eq!(
        Claims::new(None, None, None, vec![]).err(),
        Some(ConfigError::ClaimsEmpty)
    );
    let hexd = real::RUNNER_COMMIT;
    for bad in ["", " ", "\t", "a b", "caf\u{e9}", "a\u{200b}b"] {
        let refusals = [
            Claims::new(Some(bad), None, None, vec![]).err(),
            Claims::new(None, exact(bad), None, vec![]).err(),
            Claims::new(None, prefix(bad), None, vec![]).err(),
            Claims::new(None, None, exact(bad), vec![]).err(),
            Claims::new(None, None, prefix(bad), vec![]).err(),
            Material::new(bad, "gitCommit", hexd).err(),
            Material::new(real::RUNNER_MATERIAL, bad, hexd).err(),
        ];
        for refusal in refusals {
            assert_eq!(refusal, Some(ConfigError::ClaimNotAscii), "{bad:?}");
        }
    }
    for unbounded in ["https://github.com/acme", "refs/tags"] {
        assert_eq!(
            Claims::new(None, prefix(unbounded), None, vec![]).err(),
            Some(ConfigError::ClaimPrefixWithoutBoundary)
        );
        assert_eq!(
            Claims::new(None, None, prefix(unbounded), vec![]).err(),
            Some(ConfigError::ClaimPrefixWithoutBoundary)
        );
    }
    for digest in ["8CFA1049", "\u{ff18}cfa", "", "abcg", "8cfa 1049"] {
        assert_eq!(
            Material::new(real::RUNNER_MATERIAL, "gitCommit", digest).err(),
            Some(ConfigError::MaterialDigestNotHex),
            "{digest:?}"
        );
    }
    // Any algorithm name: the source commit is `gitCommit`.
    assert!(Material::new(real::RUNNER_MATERIAL, "sha256", "00ff").is_ok());

    let pki = Pki::new();
    let lists: [(&[&str], bool); 5] = [
        (&[], false),
        (&[COSIGN_SIGN_PREDICATE], false),
        (
            &[SLSA_PROVENANCE_V1_PREDICATE, COSIGN_SIGN_PREDICATE],
            false,
        ),
        (
            &[SLSA_PROVENANCE_V1_PREDICATE, SLSA_PROVENANCE_V1_PREDICATE],
            false,
        ),
        (&[SLSA_PROVENANCE_V1_PREDICATE], true),
    ];
    for (list, ok) in lists {
        let result = pki::keyed_trust(&pki, list).with_claims(runner_claims());
        match result {
            Ok(trust) => {
                assert!(ok, "{list:?}");
                assert!(trust.claims().is_some());
            }
            Err(e) => {
                assert!(!ok, "{list:?}");
                assert_eq!(e, ConfigError::ClaimsPredicateTypes);
            }
        }
    }
}

/// `Debug` of a trust says when claims are set, shows no claim text,
/// and reads as in #57 without them.
#[test]
fn trust_debug_shows_no_claim_text() {
    let pki = Pki::new();
    let without = format!("{:?}", keyed_slsa(&pki));
    let with = format!("{:?}", slsa(keyed_slsa(&pki), runner_claims()));
    assert!(!without.contains("claims"), "{without}");
    assert!(with.contains("claims: true"), "{with}");
    assert!(!with.contains("github"), "{with}");
}

// ---------------------------------------------------------------------
// Evidence that carries no claims
// ---------------------------------------------------------------------

/// Under claims, a cosign layer signed by the trusted key is refused as
/// not provenance, whatever digest it names; a `cosign/sign/v1` bundle is
/// refused by the predicate list.
#[test]
fn other_evidence_refused_under_claims() {
    let pki = Pki::new();
    let trust = slsa(keyed_slsa(&pki), runner_claims());
    for digest in [IMAGE, OTHER_IMAGE] {
        let payload = payload_for(&digest);
        let owned = keyed_layer(&pki.signer_key, &payload);
        let pairs: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let evidence = Evidence::from_cosign_layer(&pairs, &payload).expect("layer");
        // Without claims the layer over IMAGE passes (#57).
        if digest == IMAGE {
            assert_eq!(
                verify(&evidence, &IMAGE, &pki::keyed_trust(&pki, &[])),
                KEYED
            );
        }
        assert_eq!(
            verify(&evidence, &IMAGE, &trust),
            Err(Refusal::NotProvenance)
        );
    }
    let st = statement(&[&hex(&IMAGE)], COSIGN_SIGN_PREDICATE);
    let evidence =
        Evidence::from_bundle(&to_bytes(&keyed_bundle(&pki.signer_key, &st))).expect("bundle");
    assert_eq!(
        verify(&evidence, &IMAGE, &trust),
        Err(Refusal::PredicateType)
    );
}

/// Claims never decide alone: a statement that meets them but is signed
/// by an untrusted key is refused for its signature, and so is one that
/// fails them (the signature is checked first).
#[test]
fn claims_after_signature() {
    let pki = Pki::new();
    let trust = slsa(keyed_slsa(&pki), runner_claims());
    let good = statement_with(|_| {});
    let bad = statement_with(|st| set(st, BUILDER_ID, s("https://example.com/other")));
    for st in [good, bad] {
        let evidence =
            Evidence::from_bundle(&to_bytes(&keyed_bundle(&pki.other_key, &st))).expect("bundle");
        assert_eq!(
            verify(&evidence, &IMAGE, &trust),
            Err(Refusal::NoTrustedKey)
        );
    }
    // The keyless path too: the runner's real bundle over another digest
    // is refused for the subject, not the claims.
    let failing = Claims::new(Some("https://example.com/other"), None, None, vec![]).expect("c");
    assert_eq!(
        verify(&real::runner(), &real::JQ_DIGEST, &runner_trust(failing)),
        Err(Refusal::SubjectMismatch)
    );
    // And under another identity it is the identity that refuses.
    let failing = Claims::new(Some("https://example.com/other"), None, None, vec![]).expect("c");
    let trust = slsa(real::slsa_keyless(real::jq_identity()), failing);
    assert_eq!(
        verify(&real::runner(), &real::RUNNER_DIGEST, &trust),
        Err(Refusal::IdentityMismatch)
    );
}

// ---------------------------------------------------------------------
// Order of the checks
// ---------------------------------------------------------------------

#[test]
fn first_failing_claim_named() {
    let other_material = material(real::RUNNER_MATERIAL.replace("main", "x").as_str(), "00");
    let cases: Vec<(Claims, ClaimRefusal)> = vec![
        (
            Claims::new(
                Some("https://example.com/other"),
                exact("https://github.com/actions/other"),
                None,
                vec![],
            )
            .expect("claims"),
            ClaimRefusal::BuilderId,
        ),
        (
            Claims::new(
                None,
                exact("https://github.com/actions/other"),
                exact("refs/heads/other"),
                vec![other_material.clone()],
            )
            .expect("claims"),
            ClaimRefusal::SourceRepository,
        ),
        (
            Claims::new(
                None,
                None,
                exact("refs/heads/other"),
                vec![other_material.clone()],
            )
            .expect("claims"),
            ClaimRefusal::SourceRef,
        ),
        (
            Claims::new(None, None, None, vec![runner_material(), other_material]).expect("c"),
            ClaimRefusal::MaterialMissing(1),
        ),
    ];
    for (claims, refusal) in cases {
        assert_eq!(runner_verify(claims), claim(refusal));
    }
    // The shape is read before any claim.
    let pki = Pki::new();
    let st = statement_with(|st| set(st, DEPENDENCIES, obj(vec![])));
    let claims = Claims::new(Some("https://example.com/other"), None, None, vec![]).expect("c");
    assert_eq!(
        keyed_verify(&pki, &st, Some(claims)),
        Err(Refusal::MalformedProvenance)
    );
}

// ---------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------

type Edit = Box<dyn Fn(&mut Value)>;

fn edit(f: impl Fn(&mut Value) + 'static) -> Edit {
    Box::new(f)
}

fn number() -> Value {
    Value::Number(boneli_json::Number::from_lexeme("5").expect("number"))
}

/// Every field the reader models, absent or of the wrong type, refuses
/// as malformed provenance, under every single claim and all of them: a
/// statement has one reading whatever the rule asks.
#[test]
fn malformed_predicate_shapes() {
    let pki = Pki::new();
    let edits: Vec<(&str, Edit)> = vec![
        ("predicate absent", edit(|st| remove(st, &["predicate"]))),
        (
            "predicate null",
            edit(|st| set(st, &["predicate"], Value::Null)),
        ),
        (
            "predicate array",
            edit(|st| set(st, &["predicate"], Value::Array(vec![]))),
        ),
        (
            "predicate string",
            edit(|st| set(st, &["predicate"], s("x"))),
        ),
        (
            "buildDefinition absent",
            edit(|st| remove(st, &["predicate", "buildDefinition"])),
        ),
        ("buildType number", edit(|st| set(st, BUILD_TYPE, number()))),
        ("buildType absent", edit(|st| remove(st, BUILD_TYPE))),
        (
            "externalParameters absent",
            edit(|st| remove(st, &["predicate", "buildDefinition", "externalParameters"])),
        ),
        (
            "externalParameters array",
            edit(|st| {
                set(
                    st,
                    &["predicate", "buildDefinition", "externalParameters"],
                    Value::Array(vec![]),
                )
            }),
        ),
        (
            "runDetails absent",
            edit(|st| remove(st, &["predicate", "runDetails"])),
        ),
        (
            "builder absent",
            edit(|st| remove(st, &["predicate", "runDetails", "builder"])),
        ),
        (
            "builder.id number",
            edit(|st| set(st, BUILDER_ID, number())),
        ),
        ("builder.id absent", edit(|st| remove(st, BUILDER_ID))),
        (
            "resolvedDependencies object",
            edit(|st| set(st, DEPENDENCIES, obj(vec![]))),
        ),
        (
            "resolvedDependencies null",
            edit(|st| set(st, DEPENDENCIES, Value::Null)),
        ),
        (
            "entry string",
            edit(|st| set(st, DEPENDENCIES, Value::Array(vec![s("x")]))),
        ),
        (
            "uri number",
            edit(|st| {
                let entry = obj(vec![("uri", number())]);
                set(st, DEPENDENCIES, Value::Array(vec![entry]))
            }),
        ),
        (
            "digest array",
            edit(|st| {
                let entry = obj(vec![
                    ("uri", s(real::RUNNER_MATERIAL)),
                    ("digest", Value::Array(vec![])),
                ]);
                set(st, DEPENDENCIES, Value::Array(vec![entry]))
            }),
        ),
        (
            "digest value number",
            edit(|st| {
                let entry = obj(vec![
                    ("uri", s(real::RUNNER_MATERIAL)),
                    ("digest", obj(vec![("gitCommit", number())])),
                ]);
                set(st, DEPENDENCIES, Value::Array(vec![entry]))
            }),
        ),
        (
            "workflow absent",
            edit(|st| {
                set(
                    st,
                    &["predicate", "buildDefinition", "externalParameters"],
                    obj(vec![]),
                )
            }),
        ),
        (
            "workflow string",
            edit(|st| {
                set(
                    st,
                    &[
                        "predicate",
                        "buildDefinition",
                        "externalParameters",
                        "workflow",
                    ],
                    s("x"),
                )
            }),
        ),
        (
            "repository number",
            edit(|st| set(st, REPOSITORY, number())),
        ),
        ("repository absent", edit(|st| remove(st, REPOSITORY))),
        ("ref absent", edit(|st| remove(st, REF))),
        ("ref null", edit(|st| set(st, REF, Value::Null))),
        (
            "path number",
            edit(|st| {
                set(
                    st,
                    &[
                        "predicate",
                        "buildDefinition",
                        "externalParameters",
                        "workflow",
                        "path",
                    ],
                    number(),
                )
            }),
        ),
    ];
    for (name, edit) in edits {
        let st = statement_with(|st| edit(st));
        assert_eq!(
            keyed_verify(&pki, &st, None),
            KEYED,
            "{name}: without claims"
        );
        let mut lists = single_claims();
        lists.push(runner_claims());
        for claims in lists {
            assert_eq!(
                keyed_verify(&pki, &st, Some(claims)),
                Err(Refusal::MalformedProvenance),
                "{name}"
            );
        }
    }
}

/// GitHub's build type defines exactly `workflow.{ref, repository,
/// path}`; another external parameter refuses, whichever claims are set.
#[test]
fn unknown_parameters_refused() {
    let pki = Pki::new();
    let extra_input = statement_with(|st| {
        set(
            st,
            &[
                "predicate",
                "buildDefinition",
                "externalParameters",
                "inputs",
            ],
            obj(vec![("tag", s("v1"))]),
        )
    });
    let extra_sha = statement_with(|st| {
        set(
            st,
            &[
                "predicate",
                "buildDefinition",
                "externalParameters",
                "workflow",
                "sha",
            ],
            s(real::RUNNER_COMMIT),
        )
    });
    // `path` is optional.
    let no_path = statement_with(|st| {
        remove(
            st,
            &[
                "predicate",
                "buildDefinition",
                "externalParameters",
                "workflow",
                "path",
            ],
        )
    });
    for st in [extra_input, extra_sha] {
        for claims in [runner_claims(), single_claims().remove(0)] {
            assert_eq!(
                keyed_verify(&pki, &st, Some(claims)),
                Err(Refusal::UnknownParameters)
            );
        }
    }
    assert_eq!(keyed_verify(&pki, &no_path, Some(runner_claims())), KEYED);
}

/// A build type other than GitHub's (look-alikes included) refuses a
/// repository or ref claim, and leaves builder and material claims
/// working.
#[test]
fn unknown_build_type() {
    let pki = Pki::new();
    let look_alikes = [
        "https://example.com/build/v1".to_owned(),
        format!("{GITHUB_WORKFLOW_BUILD_TYPE}/"),
        GITHUB_WORKFLOW_BUILD_TYPE.replace("https://", "http://"),
        GITHUB_WORKFLOW_BUILD_TYPE.replace("/v1", "/v2"),
        GITHUB_WORKFLOW_BUILD_TYPE.replace("/v1", "/V1"),
    ];
    for build_type in look_alikes {
        let st = statement_with(|st| set(st, BUILD_TYPE, s(&build_type)));
        for claims in [
            Claims::new(None, exact(real::RUNNER_REPOSITORY), None, vec![]).expect("c"),
            Claims::new(None, None, exact(real::RUNNER_REF), vec![]).expect("c"),
            runner_claims(),
        ] {
            assert_eq!(
                keyed_verify(&pki, &st, Some(claims)),
                Err(Refusal::UnknownBuildType),
                "{build_type}"
            );
        }
        let generic = Claims::new(
            Some(real::RUNNER_WORKFLOW),
            None,
            None,
            vec![runner_material()],
        )
        .expect("c");
        assert_eq!(
            keyed_verify(&pki, &st, Some(generic)),
            KEYED,
            "{build_type}"
        );
        // An unknown type's external parameters are not read: an extra
        // one does not refuse.
        let st = statement_with(|st| {
            set(st, BUILD_TYPE, s(&build_type));
            set(
                st,
                &["predicate", "buildDefinition", "externalParameters"],
                obj(vec![("anything", number())]),
            );
        });
        let generic = Claims::new(Some(real::RUNNER_WORKFLOW), None, None, vec![]).expect("c");
        assert_eq!(
            keyed_verify(&pki, &st, Some(generic)),
            KEYED,
            "{build_type}"
        );
        // But `externalParameters` is still a required object: absent or
        // an array refuses under any build type.
        for external in [None, Some(Value::Array(vec![]))] {
            let st = statement_with(|st| {
                set(st, BUILD_TYPE, s(&build_type));
                let path = &["predicate", "buildDefinition", "externalParameters"];
                match external {
                    None => remove(st, path),
                    Some(value) => set(st, path, value),
                }
            });
            let generic = Claims::new(Some(real::RUNNER_WORKFLOW), None, None, vec![]).expect("c");
            assert_eq!(
                keyed_verify(&pki, &st, Some(generic)),
                Err(Refusal::MalformedProvenance),
                "{build_type}"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------

#[test]
fn prefix_boundary_and_remainder() {
    let pki = Pki::new();
    let repo_rule = || Claims::new(None, prefix("https://github.com/acme/"), None, vec![]);
    let accepted = [
        "https://github.com/acme/app",
        "https://github.com/acme/sub/app",
    ];
    let refused = [
        "https://github.com/acme-evil/x",
        "https://github.com/acme/",
        "https://github.com/acme//x",
        "https://github.com/acme/./x",
        "https://github.com/acme/../evil",
        "https://github.com/acme/%2e%2e/evil",
        "https://github.com/acme/app?x",
        "https://github.com/acme/app#x",
        "https://github.com/acme/a\\b",
        "https://github.com/acme/app/",
        "https://github.com/acme/ap p",
        "https://github.com/acme/app\u{200b}",
        "https://github.com/acme/\u{430}pp",
    ];
    for (value, ok) in accepted
        .iter()
        .map(|v| (v, true))
        .chain(refused.iter().map(|v| (v, false)))
    {
        let st = statement_with(|st| set(st, REPOSITORY, s(value)));
        let expected = if ok {
            KEYED
        } else {
            claim(ClaimRefusal::SourceRepository)
        };
        assert_eq!(
            keyed_verify(&pki, &st, Some(repo_rule().expect("c"))),
            expected,
            "{value:?}"
        );
    }
    let ref_rule = || Claims::new(None, None, prefix("refs/tags/"), vec![]);
    for (value, ok) in [
        ("refs/tags/v1.2.3", true),
        ("refs/tags/release/1.0", true),
        ("refs/tags/", false),
        ("refs/tags/../heads/x", false),
        ("refs/tagsx/v1", false),
    ] {
        let st = statement_with(|st| set(st, REF, s(value)));
        let expected = if ok {
            KEYED
        } else {
            claim(ClaimRefusal::SourceRef)
        };
        assert_eq!(
            keyed_verify(&pki, &st, Some(ref_rule().expect("c"))),
            expected,
            "{value:?}"
        );
    }
}

/// No normalization: other forms of the same repository, case and
/// trailing whitespace all refuse; a JSON escape decodes to the same
/// string and passes, as JSON defines it.
#[test]
fn exact_matching_is_byte_exact() {
    let pki = Pki::new();
    let repo_rule = || Claims::new(None, exact(real::RUNNER_REPOSITORY), None, vec![]);
    for value in [
        "https://github.com/actions/runner.git",
        "http://github.com/actions/runner",
        "git+https://github.com/actions/runner",
        "https://github.com/Actions/runner",
        "https://github.com/actions/runner ",
        "https://github.com/actions/runner\t",
        "https://github.com/actions/runner\n",
        "https://github.com/actions/runner\u{a0}",
    ] {
        let st = statement_with(|st| set(st, REPOSITORY, s(value)));
        assert_eq!(
            keyed_verify(&pki, &st, Some(repo_rule().expect("c"))),
            claim(ClaimRefusal::SourceRepository),
            "{value:?}"
        );
    }
    let st = statement_with(|st| set(st, BUILDER_ID, s(&format!("{} ", real::RUNNER_WORKFLOW))));
    let builder = Claims::new(Some(real::RUNNER_WORKFLOW), None, None, vec![]).expect("c");
    assert_eq!(
        keyed_verify(&pki, &st, Some(builder)),
        claim(ClaimRefusal::BuilderId)
    );
    let plain = String::from_utf8(statement_with(|_| {})).expect("utf-8");
    let needle = format!("\"repository\":\"{}\"", real::RUNNER_REPOSITORY);
    assert!(plain.contains(&needle));
    let escaped = plain.replace(
        &needle,
        r#""repository":"https:\/\/github.com\/actions\/runner""#,
    );
    assert_ne!(escaped, plain);
    assert_eq!(
        keyed_verify(&pki, escaped.as_bytes(), Some(repo_rule().expect("c"))),
        KEYED
    );
}

#[test]
fn material_matching() {
    let pki = Pki::new();
    let rule = || Claims::new(None, None, None, vec![runner_material()]).expect("c");
    let ours = || {
        dependency(
            real::RUNNER_MATERIAL,
            vec![("gitCommit", real::RUNNER_COMMIT)],
        )
    };
    let other = |n: u8| {
        dependency(
            &format!("git+https://github.com/acme/dep{n}@refs/heads/main"),
            vec![("gitCommit", real::RUNNER_COMMIT)],
        )
    };
    let with =
        |entries: Vec<Value>| statement_with(|st| set(st, DEPENDENCIES, Value::Array(entries)));
    let cases: Vec<(&str, Vec<u8>, Result<Accepted, Refusal>)> = vec![
        ("first of 3", with(vec![ours(), other(1), other(2)]), KEYED),
        ("last of 3", with(vec![other(1), other(2), ours()]), KEYED),
        (
            "same digest twice",
            with(vec![ours(), other(1), ours()]),
            KEYED,
        ),
        (
            "second with another digest",
            with(vec![
                ours(),
                dependency(real::RUNNER_MATERIAL, vec![("gitCommit", "00")]),
            ]),
            claim(ClaimRefusal::MaterialDigest(0)),
        ),
        (
            "first with another digest",
            with(vec![
                dependency(real::RUNNER_MATERIAL, vec![("gitCommit", "00")]),
                ours(),
            ]),
            claim(ClaimRefusal::MaterialDigest(0)),
        ),
        (
            "only sha256",
            with(vec![dependency(
                real::RUNNER_MATERIAL,
                vec![("sha256", real::RUNNER_COMMIT)],
            )]),
            claim(ClaimRefusal::MaterialDigest(0)),
        ),
        (
            "no digest",
            with(vec![obj(vec![("uri", s(real::RUNNER_MATERIAL))])]),
            claim(ClaimRefusal::MaterialDigest(0)),
        ),
        (
            "upper-case digest",
            with(vec![dependency(
                real::RUNNER_MATERIAL,
                vec![("gitCommit", &real::RUNNER_COMMIT.to_uppercase())],
            )]),
            claim(ClaimRefusal::MaterialDigest(0)),
        ),
        (
            "an entry without uri",
            with(vec![obj(vec![(
                "digest",
                obj(vec![("gitCommit", s(real::RUNNER_COMMIT))]),
            )])]),
            claim(ClaimRefusal::MaterialMissing(0)),
        ),
        (
            "only in byproducts",
            statement_with(|st| {
                set(st, DEPENDENCIES, Value::Array(vec![]));
                set(
                    st,
                    &["predicate", "runDetails", "byproducts"],
                    Value::Array(vec![ours()]),
                );
            }),
            claim(ClaimRefusal::MaterialMissing(0)),
        ),
        (
            "only in builderDependencies",
            statement_with(|st| {
                remove(st, DEPENDENCIES);
                set(
                    st,
                    &["predicate", "runDetails", "builder", "builderDependencies"],
                    Value::Array(vec![ours()]),
                );
            }),
            claim(ClaimRefusal::MaterialMissing(0)),
        ),
        (
            "empty",
            with(vec![]),
            claim(ClaimRefusal::MaterialMissing(0)),
        ),
        (
            "absent",
            statement_with(|st| remove(st, DEPENDENCIES)),
            claim(ClaimRefusal::MaterialMissing(0)),
        ),
    ];
    for (name, st, expected) in cases {
        assert_eq!(keyed_verify(&pki, &st, Some(rule())), expected, "{name}");
    }
    // Absent without a material claim is fine.
    let st = statement_with(|st| remove(st, DEPENDENCIES));
    let builder = Claims::new(Some(real::RUNNER_WORKFLOW), None, None, vec![]).expect("c");
    assert_eq!(keyed_verify(&pki, &st, Some(builder)), KEYED);
}

/// A member twice (`id` in `builder`) never reaches the claim reader:
/// `boneli-json` refuses the statement at `Evidence::from_bundle`, so the
/// reader never sees two readings.
#[test]
fn duplicate_member_refused_before_claims() {
    let pki = Pki::new();
    let plain = String::from_utf8(statement_with(|_| {})).expect("utf-8");
    let needle = format!("\"id\":\"{}\"", real::RUNNER_WORKFLOW);
    for twice in [
        format!("{needle},\"id\":\"https://example.com/other\""),
        format!("\"id\":\"https://example.com/other\",{needle}"),
    ] {
        let st = plain.replace(&needle, &twice);
        assert_ne!(st, plain);
        let bundle = to_bytes(&keyed_bundle(&pki.signer_key, st.as_bytes()));
        assert_eq!(
            Evidence::from_bundle(&bundle).err(),
            Some(Refusal::MalformedStatement)
        );
    }
}

/// Members the reader does not model are ignored, at every level, and
/// `internalParameters` naming another repository changes nothing: the
/// claims read `externalParameters` only.
#[test]
fn unknown_fields_ignored() {
    let pki = Pki::new();
    let st = statement_with(|st| {
        set(st, &["predicate", "extra"], number());
        set(st, &["predicate", "buildDefinition", "extra"], s("x"));
        set(st, &["predicate", "runDetails", "extra"], Value::Null);
        set(
            st,
            &["predicate", "runDetails", "builder", "version"],
            obj(vec![("v", s("1"))]),
        );
        let entry = obj(vec![
            ("uri", s(real::RUNNER_MATERIAL)),
            ("digest", obj(vec![("gitCommit", s(real::RUNNER_COMMIT))])),
            ("name", s("source")),
            ("annotations", obj(vec![("k", number())])),
        ]);
        set(st, DEPENDENCIES, Value::Array(vec![entry]));
        set(
            st,
            &[
                "predicate",
                "buildDefinition",
                "internalParameters",
                "github",
                "repository",
            ],
            s("https://github.com/evil/x"),
        );
    });
    assert_eq!(keyed_verify(&pki, &st, Some(runner_claims())), KEYED);
}

/// No new limit: the payload is read again under the limits it already
/// passed (4 MiB, depth 16, 65,536 values). An entry `{uri, digest:
/// {alg: v}}` is 4 values, so 16,000 of them fit with room for the rest
/// of the statement, and the match at the last one passes.
#[test]
fn many_dependencies_last_matches() {
    let pki = Pki::new();
    let st = statement_with(|st| {
        let mut entries: Vec<Value> = (0..15_999)
            .map(|n| {
                dependency(
                    &format!("git+https://example.com/dep/{n}"),
                    vec![("gitCommit", real::RUNNER_COMMIT)],
                )
            })
            .collect();
        entries.push(dependency(
            real::RUNNER_MATERIAL,
            vec![("gitCommit", real::RUNNER_COMMIT)],
        ));
        set(st, DEPENDENCIES, Value::Array(entries));
    });
    assert!(st.len() < boneli_sigstore::MAX_BUNDLE_BYTES);
    let rule = Claims::new(None, None, None, vec![runner_material()]).expect("c");
    assert_eq!(keyed_verify(&pki, &st, Some(rule)), KEYED);
}

/// Every new text is pinned, names its claim, and carries none of the
/// statement: the statement's fields hold a marker, and no refusal shows
/// it.
#[test]
fn claim_refusal_texts() {
    let texts: [(Refusal, &str); 10] = [
        (
            Refusal::NotProvenance,
            "the rule requires SLSA provenance claims, which a simple-signing signature does not carry",
        ),
        (
            Refusal::MalformedProvenance,
            "the SLSA provenance predicate is malformed",
        ),
        (
            Refusal::UnknownParameters,
            "the provenance has external parameters its build type does not define",
        ),
        (
            Refusal::UnknownBuildType,
            "the provenance's build type is not one whose source the rule can read",
        ),
        (
            Refusal::Claim(ClaimRefusal::BuilderId),
            "the provenance's builder ID does not meet the rule",
        ),
        (
            Refusal::Claim(ClaimRefusal::SourceRepository),
            "the provenance's source repository does not meet the rule",
        ),
        (
            Refusal::Claim(ClaimRefusal::SourceRef),
            "the provenance's source ref does not meet the rule",
        ),
        (
            Refusal::Claim(ClaimRefusal::MaterialMissing(2)),
            "the provenance lists no resolved dependency for material 2 of the rule",
        ),
        (
            Refusal::Claim(ClaimRefusal::MaterialDigest(0)),
            "the provenance's resolved dependency for material 0 of the rule has another digest",
        ),
        (
            Refusal::Claim(ClaimRefusal::MaterialDigest(17)),
            "the provenance's resolved dependency for material 17 of the rule has another digest",
        ),
    ];
    for (refusal, text) in texts {
        assert_eq!(refusal.to_string(), text);
    }
    let config: [(ConfigError, &str); 5] = [
        (ConfigError::ClaimsEmpty, "a claim list names no claim"),
        (
            ConfigError::ClaimNotAscii,
            "a claim's text is empty or not printable ASCII",
        ),
        (
            ConfigError::ClaimPrefixWithoutBoundary,
            "a claim prefix does not end in /",
        ),
        (
            ConfigError::MaterialDigestNotHex,
            "a material digest is not lower-case hex",
        ),
        (
            ConfigError::ClaimsPredicateTypes,
            "a trust with claims must list exactly the SLSA provenance v1 predicate type",
        ),
    ];
    for (error, text) in config {
        assert_eq!(error.to_string(), text);
    }

    const MARKER: &str = "MARKER-31-c7f2";
    let pki = Pki::new();
    let marked = |path: &'static [&'static str]| {
        statement_with(move |st| set(st, path, s(&format!("https://{MARKER}/x"))))
    };
    let unknown_type = statement_with(|st| {
        set(st, BUILD_TYPE, s(MARKER));
    });
    let unknown_param = statement_with(|st| {
        set(
            st,
            &["predicate", "buildDefinition", "externalParameters", MARKER],
            s(MARKER),
        )
    });
    let malformed = statement_with(|st| {
        set(st, DEPENDENCIES, Value::Array(vec![s(MARKER)]));
    });
    let material_digest = statement_with(|st| {
        set(
            st,
            DEPENDENCIES,
            Value::Array(vec![dependency(
                real::RUNNER_MATERIAL,
                vec![("gitCommit", MARKER)],
            )]),
        )
    });
    let cases = [
        (marked(BUILDER_ID), ClaimRefusal::BuilderId),
        (marked(REPOSITORY), ClaimRefusal::SourceRepository),
        (marked(REF), ClaimRefusal::SourceRef),
    ];
    for (st, expected) in cases {
        let refusal = keyed_verify(&pki, &st, Some(runner_claims())).expect_err("refused");
        assert_eq!(refusal, Refusal::Claim(expected));
        assert!(!refusal.to_string().contains(MARKER));
    }
    for (st, expected) in [
        (unknown_type, Refusal::UnknownBuildType),
        (unknown_param, Refusal::UnknownParameters),
        (malformed, Refusal::MalformedProvenance),
        (
            material_digest,
            Refusal::Claim(ClaimRefusal::MaterialDigest(0)),
        ),
    ] {
        let refusal = keyed_verify(&pki, &st, Some(runner_claims())).expect_err("refused");
        assert_eq!(refusal, expected);
        assert!(!refusal.to_string().contains(MARKER));
    }
}
