//! SLSA provenance v0.2 claims (ADR-036): one test per edge case of the
//! plan over flux-cli v2.4.0's real statement, edited and signed again in
//! a keyed `.att` envelope by the test signer of `support::pki`.

mod support;

use boneli_json::Value;
use boneli_sigstore::{
    Accepted, COSIGN_SIGN_PREDICATE, ClaimMatch, ClaimRefusal, Claims, ConfigError, Evidence,
    Material, Refusal, SLSA_GITHUB_GENERATOR_CONTAINER_BUILD_TYPE, SLSA_PROVENANCE_V1_PREDICATE,
    SLSA_PROVENANCE_V02_PREDICATE, Trust, verify,
};
use support::pki::{
    self, IMAGE, Pki, hex, keyed_attestation_annotations, keyed_envelope, obj, remove, s, set,
    to_bytes,
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
    Material::new(uri, "sha1", digest).expect("material")
}

fn flux_material() -> Material {
    material(real::FLUX_MATERIAL, real::FLUX_COMMIT)
}

/// Every claim the flux statement meets, the ref exact.
fn flux_claims() -> Claims {
    Claims::new(
        Some(real::GENERATOR_V200),
        exact(real::FLUX_REPOSITORY),
        exact(real::FLUX_REF),
        vec![flux_material()],
    )
    .expect("claims")
}

fn repository_claim(repository: &str) -> Claims {
    Claims::new(None, exact(repository), None, vec![]).expect("claims")
}

fn ref_claim(rule: Option<ClaimMatch>) -> Claims {
    Claims::new(None, exact(real::FLUX_REPOSITORY), rule, vec![]).expect("claims")
}

const KEYED: Result<Accepted, Refusal> = Ok(Accepted::Keyed { key: 0 });

fn claim(refusal: ClaimRefusal) -> Result<Accepted, Refusal> {
    Err(Refusal::Claim(refusal))
}

/// The real flux statement over the synthetic `IMAGE`, edited.
fn statement_with(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut st = real::flux_statement();
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

fn pairs(owned: &[(String, String)]) -> Vec<(&str, &str)> {
    owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// `statement` in a keyed `.att` envelope by the test signer.
fn evidence(pki: &Pki, statement: &[u8]) -> Evidence {
    let owned = keyed_attestation_annotations(SLSA_PROVENANCE_V02_PREDICATE);
    let envelope = to_bytes(&keyed_envelope(&pki.signer_key, statement));
    Evidence::from_cosign_attestation(&pairs(&owned), &envelope).expect("evidence")
}

/// The keyed trust in the test signer with `predicates` and `claims`.
fn keyed(pki: &Pki, predicates: &[&str], claims: Claims) -> Trust {
    pki::keyed_trust(pki, predicates)
        .with_claims(claims)
        .expect("with claims")
}

/// `statement`, keyed, verified over `IMAGE` under the v0.2 trust with
/// `claims`.
fn check(pki: &Pki, statement: &[u8], claims: Claims) -> Result<Accepted, Refusal> {
    verify(
        &evidence(pki, statement),
        &IMAGE,
        &keyed(pki, &[SLSA_PROVENANCE_V02_PREDICATE], claims),
    )
}

const BUILDER_ID: &[&str] = &["predicate", "builder", "id"];
const BUILD_TYPE: &[&str] = &["predicate", "buildType"];
const INVOCATION: &[&str] = &["predicate", "invocation"];
const CONFIG_SOURCE: &[&str] = &["predicate", "invocation", "configSource"];
const URI: &[&str] = &["predicate", "invocation", "configSource", "uri"];
const PARAMETERS: &[&str] = &["predicate", "invocation", "parameters"];
const MATERIALS: &[&str] = &["predicate", "materials"];

/// One edit of a statement.
type Edit = Box<dyn Fn(&mut Value)>;

fn number() -> Value {
    Value::Number(7u64.into())
}

fn sha1_entry(uri: &str, digest: &str) -> Value {
    obj(vec![
        ("uri", s(uri)),
        ("digest", obj(vec![("sha1", s(digest))])),
    ])
}

// ---------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------

/// The issue's five negative fixtures over the edited real statement: one
/// field of the statement changed each, and the claim named.
#[test]
fn v02_negative_fixtures() {
    let pki = Pki::new();
    assert_eq!(check(&pki, &statement_with(|_| {}), flux_claims()), KEYED);
    let other_uri = "git+https://github.com/fluxcd/other@refs/tags/v2.4.0";
    let cases: Vec<(Vec<u8>, ClaimRefusal)> = vec![
        (
            statement_with(|st| set(st, BUILDER_ID, s("https://example.com/builder"))),
            ClaimRefusal::BuilderId,
        ),
        (
            statement_with(|st| set(st, URI, s(other_uri))),
            ClaimRefusal::SourceRepository,
        ),
        (
            statement_with(|st| {
                set(
                    st,
                    URI,
                    s("git+https://github.com/fluxcd/flux2@refs/tags/v2.4.1"),
                )
            }),
            ClaimRefusal::SourceRef,
        ),
        (
            statement_with(|st| {
                set(
                    st,
                    MATERIALS,
                    Value::Array(vec![sha1_entry(other_uri, real::FLUX_COMMIT)]),
                )
            }),
            ClaimRefusal::MaterialMissing(0),
        ),
        (
            statement_with(|st| {
                set(
                    st,
                    MATERIALS,
                    Value::Array(vec![sha1_entry(
                        real::FLUX_MATERIAL,
                        "0000000000000000000000000000000000000000",
                    )]),
                )
            }),
            ClaimRefusal::MaterialDigest(0),
        ),
    ];
    for (st, refusal) in cases {
        assert_eq!(check(&pki, &st, flux_claims()), claim(refusal));
    }
}

/// Every shape rule of the reader, one fault each: `MalformedProvenance`
/// under any claim list.
#[test]
fn v02_malformed_shapes() {
    let pki = Pki::new();
    let edits: Vec<(&str, Edit)> = vec![
        (
            "predicate number",
            Box::new(|st| set(st, &["predicate"], number())),
        ),
        (
            "predicate null",
            Box::new(|st| set(st, &["predicate"], Value::Null)),
        ),
        (
            "predicate missing",
            Box::new(|st| remove(st, &["predicate"])),
        ),
        (
            "builder missing",
            Box::new(|st| remove(st, &["predicate", "builder"])),
        ),
        (
            "builder string",
            Box::new(|st| set(st, &["predicate", "builder"], s("x"))),
        ),
        ("builder.id missing", Box::new(|st| remove(st, BUILDER_ID))),
        (
            "builder.id number",
            Box::new(|st| set(st, BUILDER_ID, number())),
        ),
        ("buildType missing", Box::new(|st| remove(st, BUILD_TYPE))),
        (
            "buildType number",
            Box::new(|st| set(st, BUILD_TYPE, number())),
        ),
        (
            "invocation string",
            Box::new(|st| set(st, INVOCATION, s("x"))),
        ),
        (
            "invocation null",
            Box::new(|st| set(st, INVOCATION, Value::Null)),
        ),
        (
            "materials object",
            Box::new(|st| set(st, MATERIALS, obj(vec![]))),
        ),
        (
            "materials null",
            Box::new(|st| set(st, MATERIALS, Value::Null)),
        ),
        (
            "material string",
            Box::new(|st| set(st, MATERIALS, Value::Array(vec![s("x")]))),
        ),
        (
            "material uri number",
            Box::new(|st| {
                set(
                    st,
                    MATERIALS,
                    Value::Array(vec![obj(vec![("uri", number())])]),
                )
            }),
        ),
        (
            "material digest string",
            Box::new(|st| {
                set(
                    st,
                    MATERIALS,
                    Value::Array(vec![obj(vec![("digest", s("x"))])]),
                )
            }),
        ),
        (
            "material digest value number",
            Box::new(|st| {
                set(
                    st,
                    MATERIALS,
                    Value::Array(vec![obj(vec![("digest", obj(vec![("sha1", number())]))])]),
                )
            }),
        ),
        // The known build type's fields.
        ("invocation missing", Box::new(|st| remove(st, INVOCATION))),
        (
            "configSource missing",
            Box::new(|st| remove(st, CONFIG_SOURCE)),
        ),
        (
            "configSource string",
            Box::new(|st| set(st, CONFIG_SOURCE, s("x"))),
        ),
        ("uri missing", Box::new(|st| remove(st, URI))),
        (
            "configSource missing, its uri in invocation",
            Box::new(|st| {
                remove(st, CONFIG_SOURCE);
                set(
                    st,
                    &["predicate", "invocation", "uri"],
                    s(real::FLUX_MATERIAL),
                );
            }),
        ),
        ("uri number", Box::new(|st| set(st, URI, number()))),
        (
            "configSource digest string",
            Box::new(|st| {
                set(
                    st,
                    &["predicate", "invocation", "configSource", "digest"],
                    s("x"),
                )
            }),
        ),
        (
            "configSource digest value number",
            Box::new(|st| {
                set(
                    st,
                    &["predicate", "invocation", "configSource", "digest"],
                    obj(vec![("sha1", number())]),
                )
            }),
        ),
        (
            "entryPoint number",
            Box::new(|st| {
                set(
                    st,
                    &["predicate", "invocation", "configSource", "entryPoint"],
                    number(),
                )
            }),
        ),
        (
            "environment array",
            Box::new(|st| {
                set(
                    st,
                    &["predicate", "invocation", "environment"],
                    Value::Array(vec![]),
                )
            }),
        ),
        (
            "parameters array",
            Box::new(|st| set(st, PARAMETERS, Value::Array(vec![]))),
        ),
        (
            "parameters null",
            Box::new(|st| set(st, PARAMETERS, Value::Null)),
        ),
        (
            "parameters string",
            Box::new(|st| set(st, PARAMETERS, s("x"))),
        ),
        (
            "vars array",
            Box::new(|st| set(st, PARAMETERS, obj(vec![("vars", Value::Array(vec![]))]))),
        ),
        (
            "vars value number",
            Box::new(|st| {
                set(
                    st,
                    PARAMETERS,
                    obj(vec![("vars", obj(vec![("A", number())]))]),
                )
            }),
        ),
        (
            "event_inputs string",
            Box::new(|st| set(st, PARAMETERS, obj(vec![("event_inputs", s("x"))]))),
        ),
        (
            "event_inputs array",
            Box::new(|st| {
                set(
                    st,
                    PARAMETERS,
                    obj(vec![("event_inputs", Value::Array(vec![s("x")]))]),
                )
            }),
        ),
    ];
    let claim_lists = || {
        vec![
            flux_claims(),
            Claims::new(
                Some(real::GENERATOR_V200),
                None,
                None,
                vec![flux_material()],
            )
            .expect("claims"),
            Claims::new(None, None, None, vec![flux_material()]).expect("claims"),
        ]
    };
    for (name, edit) in &edits {
        let st = statement_with(|st| edit(st));
        for claims in claim_lists() {
            assert_eq!(
                check(&pki, &st, claims),
                Err(Refusal::MalformedProvenance),
                "{name}"
            );
        }
    }
    // Members the reader does not model are ignored.
    for (path, value) in [
        (&["predicate", "metadata"][..], number()),
        (&["predicate", "buildConfig"], s("x")),
        (&["predicate", "extra"], Value::Null),
        (&["extra"], number()),
        (&["predicate", "invocation", "environment"], obj(vec![])),
    ] {
        let st = statement_with(|st| set(st, path, value));
        assert_eq!(check(&pki, &st, flux_claims()), KEYED, "{path:?}");
    }
    // Absent materials are empty: the claim then misses, the others pass.
    let st = statement_with(|st| remove(st, MATERIALS));
    assert_eq!(
        check(&pki, &st, flux_claims()),
        claim(ClaimRefusal::MaterialMissing(0))
    );
    assert_eq!(
        check(&pki, &st, repository_claim(real::FLUX_REPOSITORY)),
        KEYED
    );
}

/// A build type other than the container generator's, look-alikes
/// included, refuses a repository or ref claim and reads no invocation;
/// builder and material claims still apply.
#[test]
fn v02_unknown_build_type() {
    let pki = Pki::new();
    let known = SLSA_GITHUB_GENERATOR_CONTAINER_BUILD_TYPE;
    assert_eq!(
        known,
        "https://github.com/slsa-framework/slsa-github-generator/container@v1"
    );
    let look_alikes = [
        format!("{known}/"),
        known.replace("https://", "http://"),
        known.replace("container@v1", "Container@v1"),
        known.replace("container@v1", "container@v2"),
        known.replace("container@", "container\u{200b}@"),
        "https://github.com/slsa-framework/slsa-github-generator/generic@v1".to_owned(),
        "https://actions.github.io/buildtypes/workflow/v1".to_owned(),
    ];
    for build_type in &look_alikes {
        let st = statement_with(|st| set(st, BUILD_TYPE, s(build_type)));
        for claims in [
            repository_claim(real::FLUX_REPOSITORY),
            ref_claim(exact(real::FLUX_REF)),
            flux_claims(),
        ] {
            assert_eq!(
                check(&pki, &st, claims),
                Err(Refusal::UnknownBuildType),
                "{build_type:?}"
            );
        }
        let builder_and_material = Claims::new(
            Some(real::GENERATOR_V200),
            None,
            None,
            vec![flux_material()],
        )
        .expect("claims");
        assert_eq!(
            check(&pki, &st, builder_and_material),
            KEYED,
            "{build_type:?}"
        );
        // The generic shape still holds: `invocation` is an object where
        // present.
        let not_object = statement_with(|st| {
            set(st, BUILD_TYPE, s(build_type));
            set(st, INVOCATION, s("x"));
        });
        let material_only = Claims::new(None, None, None, vec![flux_material()]).expect("m");
        assert_eq!(
            check(&pki, &not_object, material_only),
            Err(Refusal::MalformedProvenance),
            "{build_type:?}"
        );
        // Its invocation is not read otherwise: an unknown member or none
        // at all.
        let bare = statement_with(|st| {
            set(st, BUILD_TYPE, s(build_type));
            remove(st, INVOCATION);
        });
        let material_only = Claims::new(None, None, None, vec![flux_material()]).expect("m");
        assert_eq!(check(&pki, &bare, material_only), KEYED, "{build_type:?}");
        let odd = statement_with(|st| {
            set(st, BUILD_TYPE, s(build_type));
            set(st, &["predicate", "invocation", "foo"], number());
        });
        let material_only = Claims::new(None, None, None, vec![flux_material()]).expect("m");
        assert_eq!(check(&pki, &odd, material_only), KEYED, "{build_type:?}");
    }
}

/// `invocation.parameters` under D1 (b): absent, `{}`, `vars` (`null` or
/// an object of strings, read for nothing) pass; `event_inputs` absent,
/// `null` or `{}` passes and non-empty refuses with `WorkflowInputs`; any
/// other member, and an extra member of `invocation` or `configSource`,
/// is `UnknownParameters`.
#[test]
fn v02_parameters() {
    let pki = Pki::new();
    let vars = obj(vec![("TF_VAR_X", s("eastus")), ("Y", s(""))]);
    let passing: Vec<Edit> = vec![
        Box::new(|_| {}),
        Box::new(|st| remove(st, PARAMETERS)),
        Box::new(|st| set(st, PARAMETERS, obj(vec![]))),
        Box::new(|st| set(st, PARAMETERS, obj(vec![("vars", obj(vec![]))]))),
        Box::new(|st| set(st, PARAMETERS, obj(vec![("vars", Value::Null)]))),
        Box::new(move |st| set(st, PARAMETERS, obj(vec![("vars", vars.clone())]))),
        Box::new(|st| set(st, PARAMETERS, obj(vec![("event_inputs", Value::Null)]))),
        Box::new(|st| set(st, PARAMETERS, obj(vec![("event_inputs", obj(vec![]))]))),
        Box::new(|st| {
            set(
                st,
                PARAMETERS,
                obj(vec![("event_inputs", obj(vec![])), ("vars", obj(vec![]))]),
            )
        }),
        Box::new(|st| remove(st, &["predicate", "invocation", "environment"])),
        Box::new(|st| remove(st, &["predicate", "invocation", "configSource", "digest"])),
        Box::new(|st| {
            remove(
                st,
                &["predicate", "invocation", "configSource", "entryPoint"],
            )
        }),
    ];
    for (i, edit) in passing.iter().enumerate() {
        let st = statement_with(|st| edit(st));
        assert_eq!(check(&pki, &st, flux_claims()), KEYED, "passing {i}");
    }
    let unknown: Vec<Edit> = vec![
        Box::new(|st| set(st, PARAMETERS, obj(vec![("foo", number())]))),
        Box::new(|st| {
            set(
                st,
                PARAMETERS,
                obj(vec![("vars", obj(vec![])), ("Vars", obj(vec![]))]),
            )
        }),
        Box::new(|st| {
            set(
                st,
                &["predicate", "invocation", "configSource", "x"],
                s("y"),
            )
        }),
        Box::new(|st| set(st, &["predicate", "invocation", "extra"], obj(vec![]))),
    ];
    for (i, edit) in unknown.iter().enumerate() {
        let st = statement_with(|st| edit(st));
        assert_eq!(
            check(&pki, &st, flux_claims()),
            Err(Refusal::UnknownParameters),
            "unknown {i}"
        );
        // Whichever claims: the build type is read the same way.
        let builder = Claims::new(
            Some(real::GENERATOR_V200),
            None,
            None,
            vec![flux_material()],
        )
        .expect("claims");
        assert_eq!(
            check(&pki, &st, builder),
            Err(Refusal::UnknownParameters),
            "unknown {i}"
        );
    }
    for inputs in [
        obj(vec![("tag", s("v1"))]),
        obj(vec![("x", obj(vec![]))]),
        obj(vec![("dry_run", Value::Bool(false))]),
    ] {
        let st = statement_with(|st| set(st, PARAMETERS, obj(vec![("event_inputs", inputs)])));
        assert_eq!(
            check(&pki, &st, flux_claims()),
            Err(Refusal::WorkflowInputs)
        );
        let material_only = Claims::new(None, None, None, vec![flux_material()]).expect("m");
        assert_eq!(
            check(&pki, &st, material_only),
            Err(Refusal::WorkflowInputs)
        );
    }
}

/// How `configSource.uri` splits into repository and ref, and what each
/// claim then sees (the plan's table).
#[test]
fn config_source_split() {
    let pki = Pki::new();
    let with_uri = |uri: &str| statement_with(|st| set(st, URI, s(uri)));
    let repo = |text: &str| Claims::new(None, exact(text), None, vec![]).expect("claims");
    // A ref claim next to an owner prefix every URI below meets: a v0.2
    // trust needs a source claim that names an owner (`ClaimsWithoutSource`).
    let git_ref = |rule: Option<ClaimMatch>| {
        Claims::new(None, prefix("https://github.com/a/"), rule, vec![]).expect("claims")
    };

    // The first `@` ends the repository; the round trip rebuilds the URI.
    for (repository, r) in [
        ("https://github.com/a/b", "refs/tags/v1@beta"),
        ("https://github.com/fluxcd/flux2", "refs/tags/v2.4.0"),
        ("https://github.com/a/b", "refs/heads/main"),
    ] {
        let uri = format!("git+{repository}@{r}");
        let st = with_uri(&uri);
        assert_eq!(check(&pki, &st, repo(repository)), KEYED, "{uri}");
        let both = Claims::new(None, exact(repository), exact(r), vec![]).expect("claims");
        assert_eq!(check(&pki, &st, both), KEYED, "{uri}");
        assert_eq!(format!("git+{repository}@{r}"), uri);
    }
    // No `@`: no ref. A repository claim passes, a ref claim refuses.
    let st = with_uri("git+https://github.com/a/b");
    assert_eq!(check(&pki, &st, repo("https://github.com/a/b")), KEYED);
    assert_eq!(
        check(&pki, &st, git_ref(exact("refs/heads/main"))),
        claim(ClaimRefusal::SourceRef)
    );
    assert_eq!(
        check(&pki, &st, git_ref(prefix("refs/"))),
        claim(ClaimRefusal::SourceRef)
    );
    // No normalization.
    let st = with_uri("git+https://github.com/a/b.git@refs/heads/main");
    assert_eq!(
        check(&pki, &st, repo("https://github.com/a/b")),
        claim(ClaimRefusal::SourceRepository)
    );
    let st = with_uri("git+https://github.com/a/b@refs/heads/main.git");
    assert_eq!(
        check(&pki, &st, git_ref(exact("refs/heads/main"))),
        claim(ClaimRefusal::SourceRef)
    );
    // Userinfo: the repository is what precedes the first `@`.
    let st = with_uri("git+https://x@github.com/a/b@refs/heads/main");
    assert_eq!(
        check(&pki, &st, repo("https://github.com/a/b")),
        claim(ClaimRefusal::SourceRepository)
    );
    assert_eq!(check(&pki, &st, repo("https://x")), KEYED);
    // Other schemes parse and fail the claim; `GIT+` is not the prefix.
    let st = with_uri("git+ssh://github.com/a/b@refs/heads/main");
    assert_eq!(
        check(&pki, &st, repo("https://github.com/a/b")),
        claim(ClaimRefusal::SourceRepository)
    );
    for malformed in [
        "GIT+https://github.com/a/b@refs/heads/main",
        "https://github.com/a/b@refs/heads/main",
        "git+@refs/heads/main",
        "git+https://github.com/a/b@",
        "git+",
        "git+@",
        "",
    ] {
        let st = with_uri(malformed);
        for claims in [repo("https://github.com/a/b"), flux_claims()] {
            assert_eq!(
                check(&pki, &st, claims),
                Err(Refusal::MalformedProvenance),
                "{malformed:?}"
            );
        }
    }
    // Look-alikes never match.
    for uri in [
        "git+https://github.com/\u{430}/b@refs/heads/main",
        "git+https://github.com/a/b\u{200b}@refs/heads/main",
    ] {
        let st = with_uri(uri);
        assert_eq!(
            check(&pki, &st, repo("https://github.com/a/b")),
            claim(ClaimRefusal::SourceRepository),
            "{uri:?}"
        );
    }
    for uri in [
        "git+https://github.com/a/b@refs/heads/main ",
        "git+https://github.com/a/b@refs/heads/main\t",
    ] {
        let st = with_uri(uri);
        assert_eq!(
            check(&pki, &st, git_ref(exact("refs/heads/main"))),
            claim(ClaimRefusal::SourceRef),
            "{uri:?}"
        );
    }
    // A ref prefix needs a plain path after it (`under`).
    for r in [
        "refs/tags/../heads/x",
        "refs/tags/%2e%2e/x",
        "refs/tags//x",
        "refs/tags/x?y",
        "refs/tags/",
    ] {
        let st = with_uri(&format!("git+https://github.com/a/b@{r}"));
        assert_eq!(
            check(&pki, &st, git_ref(prefix("refs/tags/"))),
            claim(ClaimRefusal::SourceRef),
            "{r}"
        );
    }
    let st = with_uri("git+https://github.com/a/b@refs/tags/v1.2.3");
    assert_eq!(check(&pki, &st, git_ref(prefix("refs/tags/"))), KEYED);
    // The repository prefix too.
    let prefix_repo = Claims::new(None, prefix("https://github.com/a/"), None, vec![]).expect("c");
    assert_eq!(check(&pki, &st, prefix_repo), KEYED);
}

/// ADR-031's material rule over `materials`: at least one entry with the
/// URI, and every entry with it has the digest.
#[test]
fn v02_materials_matching() {
    let pki = Pki::new();
    let uri = real::FLUX_MATERIAL;
    let with = |entries: Vec<Value>| statement_with(|st| set(st, MATERIALS, Value::Array(entries)));
    let material_only = || Claims::new(None, None, None, vec![flux_material()]).expect("m");
    let other = "1111111111111111111111111111111111111111";
    assert_eq!(
        check(
            &pki,
            &with(vec![
                sha1_entry(uri, real::FLUX_COMMIT),
                sha1_entry(uri, other)
            ]),
            material_only()
        ),
        claim(ClaimRefusal::MaterialDigest(0))
    );
    assert_eq!(
        check(
            &pki,
            &with(vec![
                sha1_entry(uri, real::FLUX_COMMIT),
                sha1_entry(uri, real::FLUX_COMMIT)
            ]),
            material_only()
        ),
        KEYED
    );
    // Another algorithm name is another digest.
    let git_commit = Claims::new(
        None,
        None,
        None,
        vec![Material::new(uri, "gitCommit", real::FLUX_COMMIT).expect("m")],
    )
    .expect("claims");
    assert_eq!(
        check(
            &pki,
            &with(vec![sha1_entry(uri, real::FLUX_COMMIT)]),
            git_commit
        ),
        claim(ClaimRefusal::MaterialDigest(0))
    );
    // An entry without a digest, or with another algorithm only.
    assert_eq!(
        check(
            &pki,
            &with(vec![obj(vec![("uri", s(uri))])]),
            material_only()
        ),
        claim(ClaimRefusal::MaterialDigest(0))
    );
    // None with the URI, an empty list, entries without a URI.
    for entries in [
        vec![],
        vec![obj(vec![])],
        vec![sha1_entry(&format!("{uri} "), real::FLUX_COMMIT)],
    ] {
        assert_eq!(
            check(&pki, &with(entries), material_only()),
            claim(ClaimRefusal::MaterialMissing(0))
        );
    }
    // The second material of the rule is named by its index; the last of
    // many entries matches.
    let two = Claims::new(
        None,
        None,
        None,
        vec![
            flux_material(),
            material("git+https://github.com/x/y@refs/heads/main", other),
        ],
    )
    .expect("claims");
    let mut many: Vec<Value> = (0..1_000)
        .map(|i| sha1_entry(&format!("git+https://example.com/{i}"), other))
        .collect();
    many.push(sha1_entry(uri, real::FLUX_COMMIT));
    assert_eq!(
        check(&pki, &with(many.clone()), two.clone()),
        claim(ClaimRefusal::MaterialMissing(1))
    );
    many.push(sha1_entry(
        "git+https://github.com/x/y@refs/heads/main",
        other,
    ));
    assert_eq!(check(&pki, &with(many), two), KEYED);
}

// ---------------------------------------------------------------------
// Configuration and dispatch
// ---------------------------------------------------------------------

/// The predicate list of a trust with claims: SLSA v1 and v0.2, each at
/// most once, in any order; a list with v0.2 needs a repository or
/// material claim.
#[test]
fn claims_predicate_lists() {
    let pki = Pki::new();
    let v1 = SLSA_PROVENANCE_V1_PREDICATE;
    let v02 = SLSA_PROVENANCE_V02_PREDICATE;
    let lists: [(&[&str], bool); 9] = [
        (&[v1], true),
        (&[v02], true),
        (&[v1, v02], true),
        (&[v02, v1], true),
        (&[v02, v02], false),
        (&[v1, v02, v1], false),
        (&[], false),
        (&[v02, COSIGN_SIGN_PREDICATE], false),
        (&["https://slsa.dev/provenance/v0.1"], false),
    ];
    for (list, ok) in lists {
        let result = pki::keyed_trust(&pki, list).with_claims(flux_claims());
        match result {
            Ok(trust) => assert!(ok && trust.claims().is_some(), "{list:?}"),
            Err(e) => {
                assert!(!ok, "{list:?}");
                assert_eq!(e, ConfigError::ClaimsPredicateTypes, "{list:?}");
            }
        }
    }
    assert_eq!(
        ConfigError::ClaimsPredicateTypes.to_string(),
        "a trust with claims must list SLSA provenance v1 or v0.2, each at most once, and nothing else"
    );
    let builder_only = || Claims::new(Some(real::GENERATOR_V200), None, None, vec![]).expect("b");
    let ref_only = || Claims::new(None, None, prefix("refs/tags/"), vec![]).expect("r");
    let both = || {
        Claims::new(
            Some(real::GENERATOR_V200),
            None,
            prefix("refs/tags/"),
            vec![],
        )
        .expect("br")
    };
    for list in [&[v02][..], &[v1, v02], &[v02, v1]] {
        for claims in [builder_only(), ref_only(), both()] {
            assert_eq!(
                pki::keyed_trust(&pki, list).with_claims(claims).err(),
                Some(ConfigError::ClaimsWithoutSource),
                "{list:?}"
            );
        }
        for claims in [
            repository_claim(real::FLUX_REPOSITORY),
            Claims::new(None, None, None, vec![flux_material()]).expect("m"),
            ref_claim(prefix("refs/tags/")),
        ] {
            assert!(pki::keyed_trust(&pki, list).with_claims(claims).is_ok());
        }
    }
    // The source claim must name one owner at least (review of PR #122):
    // a prefix that covers every owner of a host, or a material that is
    // no `git+` repository URI, binds no project.
    let repo_prefix = |p: &str| Claims::new(None, prefix(p), None, vec![]).expect("prefix");
    let material_only = |uri: &str| {
        Claims::new(None, None, None, vec![material(uri, real::FLUX_COMMIT)]).expect("material")
    };
    for list in [&[v02][..], &[v1, v02]] {
        for p in [
            "https://",
            "https://github.com/",
            "https:///fluxcd/",
            "https://github.com//",
            "https://github.com/fluxcd//",
            "https://github.com/./",
            "https://github.com/../",
            "github.com/fluxcd/",
            "://github.com/fluxcd/",
        ] {
            assert_eq!(
                pki::keyed_trust(&pki, list)
                    .with_claims(repo_prefix(p))
                    .err(),
                Some(ConfigError::ClaimsWithoutSource),
                "{p:?}"
            );
        }
        for uri in [
            "https://github.com/fluxcd/flux2@refs/tags/v2.4.0",
            "git+https://github.com/@refs/tags/v1",
            "git+https://github.com@refs/tags/v1",
            "git+https://@refs/tags/v1",
            "git+@refs/tags/v1",
            "pkg:docker/alpine",
        ] {
            assert_eq!(
                pki::keyed_trust(&pki, list)
                    .with_claims(material_only(uri))
                    .err(),
                Some(ConfigError::ClaimsWithoutSource),
                "{uri:?}"
            );
        }
        for p in [
            "https://github.com/fluxcd/",
            "https://github.com/fluxcd/flux2/",
        ] {
            assert!(
                pki::keyed_trust(&pki, list)
                    .with_claims(repo_prefix(p))
                    .is_ok(),
                "{p:?}"
            );
        }
        for uri in [
            real::FLUX_MATERIAL,
            "git+https://github.com/fluxcd/flux2",
            "git+https://github.com/fluxcd@refs/tags/v1",
        ] {
            assert!(
                pki::keyed_trust(&pki, list)
                    .with_claims(material_only(uri))
                    .is_ok(),
                "{uri:?}"
            );
        }
        // An exact repository names one URI, whatever its text.
        for e in ["https://github.com", "https://github.com/fluxcd/flux2"] {
            assert!(
                pki::keyed_trust(&pki, list)
                    .with_claims(repository_claim(e))
                    .is_ok(),
                "{e:?}"
            );
        }
        // One binding material is enough next to ones that bind nothing.
        let mixed = Claims::new(
            None,
            None,
            None,
            vec![material("pkg:docker/alpine", "00"), flux_material()],
        )
        .expect("claims");
        assert!(pki::keyed_trust(&pki, list).with_claims(mixed).is_ok());
    }
    // A host without its `/` is no prefix at all.
    assert_eq!(
        Claims::new(None, prefix("https://github.com"), None, vec![]).err(),
        Some(ConfigError::ClaimPrefixWithoutBoundary)
    );
    // A v1-only list keeps ADR-031's rule: any claim alone is enough, a
    // host-wide prefix included.
    assert!(
        pki::keyed_trust(&pki, &[v1])
            .with_claims(repo_prefix("https://github.com/"))
            .is_ok()
    );
    for claims in [builder_only(), ref_only()] {
        assert!(pki::keyed_trust(&pki, &[v1]).with_claims(claims).is_ok());
    }
}

/// The reader is chosen by the statement's predicate type: the runner's
/// real v1 bundle passes under `[v1, v0.2]`, a v0.2 statement under `[v1]`
/// is refused by the predicate list, and a predicate of one version
/// labelled as the other is malformed for that version's reader.
#[test]
fn dispatch_by_predicate_type() {
    let pki = Pki::new();
    let v1 = SLSA_PROVENANCE_V1_PREDICATE;
    let v02 = SLSA_PROVENANCE_V02_PREDICATE;
    let runner_claims = Claims::new(
        Some(real::RUNNER_WORKFLOW),
        exact(real::RUNNER_REPOSITORY),
        exact(real::RUNNER_REF),
        vec![Material::new(real::RUNNER_MATERIAL, "gitCommit", real::RUNNER_COMMIT).expect("m")],
    )
    .expect("claims");
    let trust = Trust::new(
        Vec::new(),
        Some((real::public_good(), vec![real::runner_identity()])),
        vec![v1.to_owned(), v02.to_owned()],
    )
    .expect("trust")
    .with_claims(runner_claims)
    .expect("with claims");
    assert_eq!(
        verify(&real::runner(), &real::RUNNER_DIGEST, &trust),
        Ok(Accepted::Keyless {
            integrated_time: real::RUNNER_INTEGRATED,
            log_index: real::RUNNER_LOG_INDEX,
            identity: 0
        })
    );
    let st = statement_with(|_| {});
    assert_eq!(
        verify(
            &evidence(&pki, &st),
            &IMAGE,
            &keyed(&pki, &[v1], flux_claims())
        ),
        Err(Refusal::PredicateType)
    );
    assert_eq!(
        verify(
            &evidence(&pki, &st),
            &IMAGE,
            &keyed(&pki, &[v1, v02], flux_claims())
        ),
        KEYED
    );
    // A v0.2 predicate labelled v1, under a list with both.
    let labelled_v1 = statement_with(|st| set(st, &["predicateType"], s(v1)));
    assert_eq!(
        verify(
            &evidence(&pki, &labelled_v1),
            &IMAGE,
            &keyed(&pki, &[v1, v02], flux_claims())
        ),
        Err(Refusal::MalformedProvenance)
    );
    // The runner's v1 predicate labelled v0.2.
    let mut runner = real::runner_statement();
    set(
        &mut runner,
        &["subject"],
        Value::Array(vec![obj(vec![
            ("name", s("x")),
            ("digest", obj(vec![("sha256", s(&hex(&IMAGE)))])),
        ])]),
    );
    set(&mut runner, &["predicateType"], s(v02));
    assert_eq!(
        verify(
            &evidence(&pki, &to_bytes(&runner)),
            &IMAGE,
            &keyed(&pki, &[v1, v02], flux_claims())
        ),
        Err(Refusal::MalformedProvenance)
    );
}

/// The review's repro (PR #122): another project's `.att` from the same
/// generator, under the generator's shared identity. A host-wide
/// repository prefix would accept it, so a v0.2 trust with one is
/// refused at configuration; an owner prefix refuses the statement for
/// its repository, and admits the owner's own.
#[test]
fn host_wide_prefix_refused_for_v02() {
    let pki = Pki::new();
    let project = |repository: &str| {
        let uri = format!("git+{repository}@refs/tags/v1");
        statement_with(|st| {
            set(st, URI, s(&uri));
            set(
                st,
                MATERIALS,
                Value::Array(vec![sha1_entry(
                    &uri,
                    "0123456789abcdef0123456789abcdef01234567",
                )]),
            );
        })
    };
    let attacker = project("https://github.com/attacker/evil");
    for p in ["https://github.com/", "https://"] {
        let claims =
            Claims::new(Some(real::GENERATOR_V200), prefix(p), None, vec![]).expect("claims");
        assert_eq!(
            pki::keyed_trust(&pki, &[SLSA_PROVENANCE_V02_PREDICATE])
                .with_claims(claims)
                .err(),
            Some(ConfigError::ClaimsWithoutSource),
            "{p:?}"
        );
    }
    let owner = || {
        Claims::new(
            Some(real::GENERATOR_V200),
            prefix("https://github.com/fluxcd/"),
            None,
            vec![],
        )
        .expect("claims")
    };
    assert_eq!(
        check(&pki, &attacker, owner()),
        claim(ClaimRefusal::SourceRepository)
    );
    assert_eq!(
        check(&pki, &project("https://github.com/fluxcd/flux2"), owner()),
        KEYED
    );
}
