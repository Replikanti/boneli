//! The SLSA provenance v0.2 reader (ADR-036), for statements of predicate
//! type `https://slsa.dev/provenance/v0.2` as `slsa-github-generator`'s
//! container workflow writes them into cosign `.att` attestations. It
//! gives the parent module the same three things the v1 reader gives, and
//! the claims are matched there.
//!
//! 1. **The generic v0.2 shape**, whichever claims are set: `predicate`,
//!    `builder` (an object), `builder.id` and `buildType` (strings) are
//!    required; `invocation` is an object where present; `materials` is
//!    an array where present (absent is empty) whose entries follow the
//!    v1 reader's dependency rule (an object, `uri` a string and `digest`
//!    an object of strings where present). `metadata`, `buildConfig` and
//!    other members are not read.
//! 2. **The container generator's build type**
//!    ([`SLSA_GITHUB_GENERATOR_CONTAINER_BUILD_TYPE`]), always when the
//!    statement names it. `invocation` is required and holds no member
//!    but `configSource`, `parameters` and `environment` (an object, not
//!    read). `configSource` is required and holds no member but `uri` (a
//!    required string), `digest` (an object of strings) and `entryPoint`
//!    (a string, not read). `uri` is `git+<repository>[@<ref>]`, split at
//!    the first `@`: the generator writes `git+<server>/<owner>/<repo>`
//!    and `@<ref>` only when the ref is non-empty, and a GitHub owner or
//!    repository name cannot hold `@`. `parameters` is absent or an
//!    object with no member but `vars` (`null` or an object of strings,
//!    not read) and `event_inputs` (absent, `null` or `{}` pass; a
//!    non-empty object is `WorkflowInputs`), the two members of the
//!    generator's `WorkflowParameters`. An undefined member anywhere in
//!    `invocation` is `UnknownParameters`.
//! 3. **Another build type** has no source: the parent refuses a
//!    repository or ref claim (`UnknownBuildType`).
//!
//! The builder ID is `builder.id`, the dependencies are `materials`.

use boneli_json::Value;

use super::{Dependency, Provenance, dependency};
use crate::error::Refusal;
use crate::json;

/// The build type of `slsa-github-generator`'s container workflow
/// (`generator_container_slsa3.yml`), the one v0.2 build type whose
/// source the reader knows (ADR-036).
pub const SLSA_GITHUB_GENERATOR_CONTAINER_BUILD_TYPE: &str =
    "https://github.com/slsa-framework/slsa-github-generator/container@v1";

const MALFORMED: Refusal = Refusal::MalformedProvenance;

/// Steps 1 and 2 of the module doc.
pub(super) fn read(statement: &Value) -> Result<Provenance<'_>, Refusal> {
    let predicate = json::object(statement, "predicate").ok_or(MALFORMED)?;
    let builder = json::object(predicate, "builder").ok_or(MALFORMED)?;
    let builder_id = json::string(builder, "id").ok_or(MALFORMED)?;
    let build_type = json::string(predicate, "buildType").ok_or(MALFORMED)?;
    let invocation = optional_object(predicate, "invocation")?;
    let dependencies: Vec<Dependency<'_>> = match predicate.get("materials") {
        None => Vec::new(),
        Some(list) => list
            .as_array()
            .ok_or(MALFORMED)?
            .iter()
            .map(dependency)
            .collect::<Option<Vec<_>>>()
            .ok_or(MALFORMED)?,
    };
    let source = if build_type == SLSA_GITHUB_GENERATOR_CONTAINER_BUILD_TYPE {
        Some(generator_source(invocation.ok_or(MALFORMED)?)?)
    } else {
        None
    };
    Ok(Provenance {
        builder_id,
        source,
        dependencies,
    })
}

/// The member `key` of `value`: absent is `None`, an object is itself,
/// anything else (`null` included) is malformed.
fn optional_object<'a>(value: &'a Value, key: &str) -> Result<Option<&'a Value>, Refusal> {
    match value.get(key) {
        None => Ok(None),
        Some(member) if member.as_object().is_some() => Ok(Some(member)),
        Some(_) => Err(MALFORMED),
    }
}

/// Whether `value`, an object, has no member outside `keys`.
fn only(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.keys().all(|k| keys.contains(&k)))
}

/// Whether `value` is an object of strings.
fn strings(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.iter().all(|(_, v)| v.as_str().is_some()))
}

/// The repository and optional ref of the container generator's
/// `invocation` (module doc, step 2). Types first, then undefined
/// members, then the workflow inputs.
fn generator_source(invocation: &Value) -> Result<(&str, Option<&str>), Refusal> {
    let config = json::object(invocation, "configSource").ok_or(MALFORMED)?;
    let uri = json::string(config, "uri").ok_or(MALFORMED)?;
    if config.get("digest").is_some_and(|d| !strings(d))
        || config
            .get("entryPoint")
            .is_some_and(|e| e.as_str().is_none())
        || optional_object(invocation, "environment").is_err()
    {
        return Err(MALFORMED);
    }
    let parameters = optional_object(invocation, "parameters")?;
    let (vars, inputs) = match parameters {
        None => (None, None),
        Some(p) => (p.get("vars"), p.get("event_inputs")),
    };
    if vars.is_some_and(|v| !v.is_null() && !strings(v)) {
        return Err(MALFORMED);
    }
    let inputs_given = match inputs {
        None => false,
        Some(v) if v.is_null() => false,
        Some(v) => !v.as_object().ok_or(MALFORMED)?.is_empty(),
    };
    let source = split_uri(uri).ok_or(MALFORMED)?;
    if !only(invocation, &["configSource", "parameters", "environment"])
        || !only(config, &["uri", "digest", "entryPoint"])
        || parameters.is_some_and(|p| !only(p, &["vars", "event_inputs"]))
    {
        return Err(Refusal::UnknownParameters);
    }
    if inputs_given {
        return Err(Refusal::WorkflowInputs);
    }
    Ok(source)
}

/// `git+<repository>[@<ref>]` split at the first `@`: the repository
/// non-empty, and the ref non-empty when `@` is there.
fn split_uri(uri: &str) -> Option<(&str, Option<&str>)> {
    let rest = uri.strip_prefix("git+")?;
    match rest.split_once('@') {
        None => (!rest.is_empty()).then_some((rest, None)),
        Some((repository, git_ref)) => {
            (!repository.is_empty() && !git_ref.is_empty()).then_some((repository, Some(git_ref)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_uri;
    use crate::provenance::{ClaimMatch, Claims, Material, check};
    use crate::{SLSA_PROVENANCE_V02_PREDICATE, json};

    /// flux-cli v2.4.0's real statement, from its envelope.
    fn flux_statement() -> Vec<u8> {
        let envelope = json::parse(
            include_bytes!("../../tests/data/flux-cli-2.4.0.envelope.json"),
            crate::MAX_BUNDLE_BYTES,
        )
        .expect("envelope");
        json::base64(&envelope, "payload").expect("payload")
    }

    /// Every strict prefix of flux's statement is refused, never a panic;
    /// the whole statement meets its claims.
    #[test]
    fn v02_truncated_statements_never_panic() {
        let statement = flux_statement();
        let claims = Claims::new(
            Some(
                "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0",
            ),
            Some(ClaimMatch::Exact("https://github.com/fluxcd/flux2".to_owned())),
            Some(ClaimMatch::Prefix("refs/tags/".to_owned())),
            vec![
                Material::new(
                    "git+https://github.com/fluxcd/flux2@refs/tags/v2.4.0",
                    "sha1",
                    "5350425cdcd5fa015337e09fa502153c0275bd4b",
                )
                .expect("material"),
            ],
        )
        .expect("claims");
        let v02 = SLSA_PROVENANCE_V02_PREDICATE;
        assert_eq!(check(&statement, v02, &claims, None), Ok(()));
        for n in 0..statement.len() {
            assert!(
                check(&statement[..n], v02, &claims, None).is_err(),
                "prefix {n}"
            );
        }
    }

    #[test]
    fn split_uri_table() {
        for (uri, want) in [
            (
                "git+https://github.com/a/b@refs/tags/v1",
                Some(("https://github.com/a/b", Some("refs/tags/v1"))),
            ),
            (
                "git+https://github.com/a/b@refs/tags/v1@beta",
                Some(("https://github.com/a/b", Some("refs/tags/v1@beta"))),
            ),
            (
                "git+https://github.com/a/b",
                Some(("https://github.com/a/b", None)),
            ),
            ("git+x@y", Some(("x", Some("y")))),
            ("git+@refs/heads/main", None),
            ("git+https://github.com/a/b@", None),
            ("git+", None),
            ("git+@", None),
            ("GIT+https://github.com/a/b", None),
            ("https://github.com/a/b", None),
            ("", None),
        ] {
            assert_eq!(split_uri(uri), want, "{uri:?}");
            if let Some((repository, Some(git_ref))) = want {
                assert_eq!(format!("git+{repository}@{git_ref}"), uri);
            }
        }
    }
}
