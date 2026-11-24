//! SLSA provenance claims (ADR-031, ADR-036): what a `Required` rule may
//! ask of a signed SLSA statement beyond its predicate type.
//!
//! [`check`] runs only after [`verify`](crate::verify) has accepted the
//! statement's predicate type, its subject and its signature, so it never
//! reads a predicate nobody trusted signed. It reads the DSSE payload
//! again under the limits it already passed, with the reader of its
//! predicate type: SLSA v0.2 goes to [`v02`] (ADR-036), and every other
//! type to the v1 reader below, since v1 is the only other type a trust
//! with claims admits. The v1 reader checks, in this order:
//!
//! 1. **The generic SLSA v1 shape.** `predicate`, `buildDefinition`,
//!    `buildType`, `externalParameters`, `runDetails`, `builder` and
//!    `builder.id` are required and of their type; `resolvedDependencies`
//!    is optional (absent is empty) and otherwise an array of objects
//!    whose `uri` is a string and whose `digest` is an object of strings
//!    where present. Every modeled field is checked whichever claims are
//!    set, so a statement has one reading under every rule. Members the
//!    reader does not model are ignored, as in-toto and SLSA parse.
//! 2. **GitHub's build type** ([`GITHUB_WORKFLOW_BUILD_TYPE`]), always
//!    when the statement names it: `externalParameters` is exactly
//!    `{"workflow": {ref, repository, path?}}` of strings. Another
//!    external parameter is refused, as that type's specification asks
//!    ("Consumers SHOULD reject unrecognized external parameters").
//! 3. **Another build type** refuses a repository or ref claim: where the
//!    source sits is defined per build type, and GitHub's is the only one
//!    measured. Builder and material claims are generic SLSA v1 fields.
//! 4. **The statement agreement** (ADR-034), when the trust's certificate
//!    claims ask for it: `builder.id`, the source repository, the ref and
//!    the source commit must equal what Fulcio wrote into the certificate
//!    (`fulcio`); it needs GitHub's build type (`UnknownBuildType`).
//! 5. **The claims:** builder, repository, ref, then the materials in rule
//!    order; the first that fails is the refusal.
//!
//! Both readers give the same three things (builder ID, source repository
//! and optional ref, dependencies), and one claim matcher decides; a ref
//! claim against a statement whose source names no ref is not met.
//!
//! Matching is byte for byte after JSON unescaping, with no normalization:
//! `.git`, `http://`, other case and trailing whitespace never match. A
//! [`ClaimMatch::Prefix`] ends in `/`, and what follows it must be a
//! plain path ([`under`]), because unlike Fulcio's SAN this text is
//! written by the signer.

use std::fmt;

use boneli_json::{Object, Value};

use crate::error::{ConfigError, Refusal};
use crate::fulcio::{Agreement, CertificateRefusal, Extension};
use crate::identity::printable;
use crate::verify::SLSA_PROVENANCE_V02_PREDICATE;
use crate::{MAX_BUNDLE_BYTES, json};

mod v02;

pub use v02::SLSA_GITHUB_GENERATOR_CONTAINER_BUILD_TYPE;

/// The build type of GitHub's artifact attestations
/// (`actions/buildtypes`, `workflow/v1`).
pub const GITHUB_WORKFLOW_BUILD_TYPE: &str = "https://actions.github.io/buildtypes/workflow/v1";

/// How a source repository or ref must read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimMatch {
    /// Equal to this.
    Exact(String),
    /// This, which ends in `/`, followed by a plain path (module doc).
    Prefix(String),
}

/// A resolved dependency the statement must list: its URI, and its
/// digest under one algorithm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Material {
    uri: String,
    algorithm: String,
    digest: String,
}

impl Material {
    /// A material. The URI and the algorithm must be non-empty printable
    /// ASCII without spaces; the digest non-empty lower-case hex. Any
    /// algorithm name is allowed: GitHub's source commit is `gitCommit`.
    pub fn new(uri: &str, algorithm: &str, digest: &str) -> Result<Material, ConfigError> {
        if !printable(uri) || !printable(algorithm) {
            return Err(ConfigError::ClaimNotAscii);
        }
        if digest.is_empty()
            || !digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ConfigError::MaterialDigestNotHex);
        }
        Ok(Material {
            uri: uri.to_owned(),
            algorithm: algorithm.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

/// The claims of a rule: at least one of an exact builder ID, a source
/// repository, a source ref and materials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    builder_id: Option<String>,
    repository: Option<ClaimMatch>,
    git_ref: Option<ClaimMatch>,
    materials: Vec<Material>,
}

impl Claims {
    /// A claim list. Every text must be non-empty printable ASCII without
    /// spaces, a prefix must end in `/`, and at least one claim must be
    /// set.
    pub fn new(
        builder_id: Option<&str>,
        repository: Option<ClaimMatch>,
        git_ref: Option<ClaimMatch>,
        materials: Vec<Material>,
    ) -> Result<Claims, ConfigError> {
        if builder_id.is_none() && repository.is_none() && git_ref.is_none() && materials.is_empty()
        {
            return Err(ConfigError::ClaimsEmpty);
        }
        if builder_id.is_some_and(|b| !printable(b)) {
            return Err(ConfigError::ClaimNotAscii);
        }
        for rule in [&repository, &git_ref].into_iter().flatten() {
            check_match(rule)?;
        }
        Ok(Claims {
            builder_id: builder_id.map(str::to_owned),
            repository,
            git_ref,
            materials,
        })
    }

    /// Whether a claim binds a statement to one owner's repositories at
    /// least, which is what ties a v0.2 statement to one project when the
    /// signer's identity is shared (ADR-036 item 4, `ClaimsWithoutSource`):
    /// an exact repository (it names one URI), a repository prefix that
    /// names an owner ([`names_owner`]), or a material whose URI is a
    /// `git+` repository URI whose repository names one. A host-wide prefix
    /// such as `https://github.com/` binds no more than a ref claim does,
    /// and a material that is no repository URI may be a dependency every
    /// project lists.
    pub(crate) fn names_source(&self) -> bool {
        let repository = match &self.repository {
            Some(ClaimMatch::Exact(_)) => true,
            Some(ClaimMatch::Prefix(prefix)) => names_owner(prefix),
            None => false,
        };
        repository
            || self.materials.iter().any(|m| {
                v02::split_uri(&m.uri).is_some_and(|(repository, _)| names_owner(repository))
            })
    }
}

/// A repository or ref rule's text is non-empty printable ASCII without
/// spaces, and a prefix ends in `/` (also for Fulcio's certificate claims,
/// ADR-034).
pub(crate) fn check_match(rule: &ClaimMatch) -> Result<(), ConfigError> {
    match rule {
        ClaimMatch::Exact(text) | ClaimMatch::Prefix(text) if !printable(text) => {
            Err(ConfigError::ClaimNotAscii)
        }
        ClaimMatch::Prefix(text) if !text.ends_with('/') => {
            Err(ConfigError::ClaimPrefixWithoutBoundary)
        }
        _ => Ok(()),
    }
}

/// Whether `text` is `<scheme>://<host>/<owner>`, optionally followed by
/// more path and a final `/`: a non-empty scheme and host, and at least
/// one path segment, none of them empty, `.` or `..`. The owner is the
/// smallest unit a forge gives one party control of; anything shorter
/// covers every party on the host.
fn names_owner(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once("://") else {
        return false;
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let mut segments = rest.split('/');
    let host = segments.next().unwrap_or_default();
    let path: Vec<&str> = segments.collect();
    !scheme.is_empty()
        && !host.is_empty()
        && !path.is_empty()
        && path
            .iter()
            .all(|s| !s.is_empty() && *s != "." && *s != "..")
}

/// Which claim a statement failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimRefusal {
    /// The builder ID (`runDetails.builder.id` in v1, `builder.id` in
    /// v0.2) is not the rule's.
    BuilderId,
    /// The source repository does not meet the rule.
    SourceRepository,
    /// The source ref does not meet the rule.
    SourceRef,
    /// No resolved dependency has the URI of the rule's material at this
    /// index (0-based).
    MaterialMissing(usize),
    /// A resolved dependency with that URI lacks the digest or has another.
    MaterialDigest(usize),
}

impl fmt::Display for ClaimRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimRefusal::BuilderId => {
                f.write_str("the provenance's builder ID does not meet the rule")
            }
            ClaimRefusal::SourceRepository => {
                f.write_str("the provenance's source repository does not meet the rule")
            }
            ClaimRefusal::SourceRef => {
                f.write_str("the provenance's source ref does not meet the rule")
            }
            ClaimRefusal::MaterialMissing(i) => write!(
                f,
                "the provenance lists no resolved dependency for material {i} of the rule"
            ),
            ClaimRefusal::MaterialDigest(i) => write!(
                f,
                "the provenance's resolved dependency for material {i} of the rule has another digest"
            ),
        }
    }
}

/// One resolved dependency as the reader models it.
struct Dependency<'a> {
    uri: Option<&'a str>,
    digest: Option<&'a Object>,
}

/// What the reader takes from a statement.
struct Provenance<'a> {
    builder_id: &'a str,
    /// The source repository and its ref, where the build type says where
    /// they sit: `workflow.repository` and `workflow.ref` of GitHub's
    /// build type (the ref always set), the two parts of the container
    /// generator's `configSource.uri` (ADR-036); `None` for any other
    /// build type.
    source: Option<(&'a str, Option<&'a str>)>,
    dependencies: Vec<Dependency<'a>>,
}

/// Whether the signed statement `payload`, of `predicate_type`, meets
/// `claims` (module doc), after it agrees with the certificate's
/// `agreement` if one is given (ADR-034).
pub(crate) fn check(
    payload: &[u8],
    predicate_type: &str,
    claims: &Claims,
    agreement: Option<&Agreement<'_>>,
) -> Result<(), Refusal> {
    let statement = json::parse(payload, MAX_BUNDLE_BYTES).ok_or(Refusal::MalformedProvenance)?;
    let v02 = predicate_type == SLSA_PROVENANCE_V02_PREDICATE;
    let provenance = if v02 {
        v02::read(&statement)?
    } else {
        read(&statement)?
    };
    let source = match provenance.source {
        // The agreement is defined for GitHub's build type only (ADR-034,
        // item 5): the container generator's v0.2 fields have no reading
        // against Fulcio's yet (ADR-036, known limits).
        Some(_) if v02 && agreement.is_some() => return Err(Refusal::UnknownBuildType),
        Some(source) => Some(source),
        None if agreement.is_some() || claims.repository.is_some() || claims.git_ref.is_some() => {
            return Err(Refusal::UnknownBuildType);
        }
        None => None,
    };
    if let (Some(agreement), Some(source)) = (agreement, source) {
        agrees(&provenance, source, agreement)?;
    }
    if claims
        .builder_id
        .as_ref()
        .is_some_and(|b| b != provenance.builder_id)
    {
        return Err(Refusal::Claim(ClaimRefusal::BuilderId));
    }
    if let (Some(rule), Some((repository, _))) = (&claims.repository, source)
        && !meets(rule, repository)
    {
        return Err(Refusal::Claim(ClaimRefusal::SourceRepository));
    }
    if let (Some(rule), Some((_, git_ref))) = (&claims.git_ref, source)
        && !git_ref.is_some_and(|r| meets(rule, r))
    {
        return Err(Refusal::Claim(ClaimRefusal::SourceRef));
    }
    for (i, material) in claims.materials.iter().enumerate() {
        let mut listed = false;
        for dependency in &provenance.dependencies {
            if dependency.uri != Some(material.uri.as_str()) {
                continue;
            }
            listed = true;
            let digest = dependency
                .digest
                .and_then(|d| d.get(&material.algorithm))
                .and_then(Value::as_str);
            if digest != Some(material.digest.as_str()) {
                return Err(Refusal::Claim(ClaimRefusal::MaterialDigest(i)));
            }
        }
        if !listed {
            return Err(Refusal::Claim(ClaimRefusal::MaterialMissing(i)));
        }
    }
    Ok(())
}

/// Whether the statement says what Fulcio wrote from the same OIDC
/// token (ADR-034): `builder.id` is 1.9, the source repository 1.12, the
/// ref 1.14, and at least one resolved dependency has the URI
/// `git+<1.12>@<1.14>`, every one of them with the `gitCommit` 1.13.
fn agrees(
    provenance: &Provenance<'_>,
    (repository, git_ref): (&str, Option<&str>),
    agreement: &Agreement<'_>,
) -> Result<(), Refusal> {
    let disagrees = |ext| Refusal::CertificateClaim(CertificateRefusal::StatementDisagrees(ext));
    if provenance.builder_id != agreement.builder {
        return Err(disagrees(Extension::BuildSignerUri));
    }
    if repository != agreement.repository {
        return Err(disagrees(Extension::SourceRepositoryUri));
    }
    if git_ref != Some(agreement.git_ref) {
        return Err(disagrees(Extension::SourceRepositoryRef));
    }
    let uri = format!("git+{}@{}", agreement.repository, agreement.git_ref);
    let mut listed = false;
    for dependency in &provenance.dependencies {
        if dependency.uri != Some(uri.as_str()) {
            continue;
        }
        listed = true;
        let commit = dependency
            .digest
            .and_then(|d| d.get("gitCommit"))
            .and_then(Value::as_str);
        if commit != Some(agreement.commit) {
            return Err(disagrees(Extension::SourceRepositoryDigest));
        }
    }
    if !listed {
        return Err(disagrees(Extension::SourceRepositoryDigest));
    }
    Ok(())
}

/// Steps 1 and 2 of the module doc.
fn read(statement: &Value) -> Result<Provenance<'_>, Refusal> {
    const MALFORMED: Refusal = Refusal::MalformedProvenance;
    let predicate = json::object(statement, "predicate").ok_or(MALFORMED)?;
    let definition = json::object(predicate, "buildDefinition").ok_or(MALFORMED)?;
    let build_type = json::string(definition, "buildType").ok_or(MALFORMED)?;
    let external = json::object(definition, "externalParameters").ok_or(MALFORMED)?;
    let run = json::object(predicate, "runDetails").ok_or(MALFORMED)?;
    let builder = json::object(run, "builder").ok_or(MALFORMED)?;
    let builder_id = json::string(builder, "id").ok_or(MALFORMED)?;
    let dependencies = match definition.get("resolvedDependencies") {
        None => Vec::new(),
        Some(list) => list
            .as_array()
            .ok_or(MALFORMED)?
            .iter()
            .map(dependency)
            .collect::<Option<Vec<_>>>()
            .ok_or(MALFORMED)?,
    };
    let source = if build_type == GITHUB_WORKFLOW_BUILD_TYPE {
        let (repository, git_ref) = github_source(external)?;
        Some((repository, Some(git_ref)))
    } else {
        None
    };
    Ok(Provenance {
        builder_id,
        source,
        dependencies,
    })
}

/// One `resolvedDependencies` entry, or `None` if a modeled field has
/// the wrong type.
fn dependency(entry: &Value) -> Option<Dependency<'_>> {
    entry.as_object()?;
    let uri = match entry.get("uri") {
        None => None,
        Some(uri) => Some(uri.as_str()?),
    };
    let digest = match entry.get("digest") {
        None => None,
        Some(digest) => {
            let digest = digest.as_object()?;
            if !digest.iter().all(|(_, v)| v.as_str().is_some()) {
                return None;
            }
            Some(digest)
        }
    };
    Some(Dependency { uri, digest })
}

/// `workflow.repository` and `workflow.ref` of GitHub's build type
/// (module doc, step 2).
fn github_source(external: &Value) -> Result<(&str, &str), Refusal> {
    let workflow = json::object(external, "workflow").ok_or(Refusal::MalformedProvenance)?;
    let repository = json::string(workflow, "repository").ok_or(Refusal::MalformedProvenance)?;
    let git_ref = json::string(workflow, "ref").ok_or(Refusal::MalformedProvenance)?;
    if workflow.get("path").is_some_and(|p| p.as_str().is_none()) {
        return Err(Refusal::MalformedProvenance);
    }
    let only = |value: &Value, keys: &[&str]| {
        value
            .as_object()
            .is_some_and(|o| o.keys().all(|k| keys.contains(&k)))
    };
    if !only(external, &["workflow"]) || !only(workflow, &["ref", "repository", "path"]) {
        return Err(Refusal::UnknownParameters);
    }
    Ok((repository, git_ref))
}

/// Whether `value` meets `rule`.
pub(crate) fn meets(rule: &ClaimMatch, value: &str) -> bool {
    match rule {
        ClaimMatch::Exact(want) => want == value,
        ClaimMatch::Prefix(prefix) => under(value, prefix),
    }
}

/// Whether `value` is `prefix` followed by a plain path: only bytes `!`
/// to `~` other than `%`, `?`, `#` and `\`, and every `/`-segment
/// non-empty and neither `.` nor `..` (an empty remainder is one empty
/// segment, so it is refused too). A URL or ref reader would resolve
/// anything else (a dot segment, a percent-encoding, a query or fragment,
/// a backslash taken for `/`) to somewhere the prefix may not cover.
fn under(value: &str, prefix: &str) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    rest.bytes()
        .all(|b| (b'!'..=b'~').contains(&b) && !matches!(b, b'%' | b'?' | b'#' | b'\\'))
        && rest
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
    use super::{ClaimMatch, Claims, Material, check, under};
    use crate::SLSA_PROVENANCE_V1_PREDICATE;

    /// The runner's real statement, from its bundle.
    fn runner_statement() -> Vec<u8> {
        let bundle = crate::json::parse(
            include_bytes!("../tests/data/actions-runner.bundle.json"),
            crate::MAX_BUNDLE_BYTES,
        )
        .expect("bundle");
        let envelope = crate::json::object(&bundle, "dsseEnvelope").expect("envelope");
        crate::json::base64(envelope, "payload").expect("payload")
    }

    fn runner_claims() -> Claims {
        Claims::new(
            Some(
                "https://github.com/actions/runner/.github/workflows/docker-publish.yml@refs/heads/main",
            ),
            Some(ClaimMatch::Exact(
                "https://github.com/actions/runner".to_owned(),
            )),
            Some(ClaimMatch::Prefix("refs/heads/".to_owned())),
            vec![
                Material::new(
                    "git+https://github.com/actions/runner@refs/heads/main",
                    "gitCommit",
                    "8cfa1049f86781d141056082d73802d56cd2b433",
                )
                .expect("material"),
            ],
        )
        .expect("claims")
    }

    /// Every strict prefix of the runner's statement is refused, never a
    /// panic; the whole statement meets its claims.
    #[test]
    fn truncated_statements_never_panic() {
        let statement = runner_statement();
        let claims = runner_claims();
        let v1 = SLSA_PROVENANCE_V1_PREDICATE;
        assert_eq!(check(&statement, v1, &claims, None), Ok(()));
        for n in 0..statement.len() {
            assert!(
                check(&statement[..n], v1, &claims, None).is_err(),
                "prefix {n}"
            );
        }
    }

    #[test]
    fn under_table() {
        let p = "https://github.com/acme/";
        for (value, ok) in [
            ("https://github.com/acme/app", true),
            ("https://github.com/acme/sub/app", true),
            ("https://github.com/acme/a.b-c_d~e", true),
            ("https://github.com/acme/.hidden", true),
            ("https://github.com/acme/...", true),
            ("https://github.com/acme", false),
            ("https://github.com/acme/", false),
            ("https://github.com/acme-evil/x", false),
            ("https://github.com/acme//x", false),
            ("https://github.com/acme/./x", false),
            ("https://github.com/acme/.", false),
            ("https://github.com/acme/..", false),
            ("https://github.com/acme/../evil", false),
            ("https://github.com/acme/x/..", false),
            ("https://github.com/acme/%2e%2e/evil", false),
            ("https://github.com/acme/app?x", false),
            ("https://github.com/acme/app#x", false),
            ("https://github.com/acme/a\\b", false),
            ("https://github.com/acme/app/", false),
            ("https://github.com/acme/ap p", false),
            ("https://github.com/acme/app\t", false),
            ("https://github.com/acme/app\u{7f}", false),
            ("https://github.com/acme/app\u{200b}", false),
            ("https://github.com/acme/\u{430}pp", false),
            ("HTTPS://github.com/acme/app", false),
        ] {
            assert_eq!(under(value, p), ok, "{value:?}");
        }
    }
}
