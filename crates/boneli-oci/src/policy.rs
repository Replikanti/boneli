//! The signature policy (ADR-029, S4): which images must carry a trusted
//! signature before the store unpacks them.
//!
//! Two modes, [`Requirement::Off`] and [`Requirement::Required`], no
//! "optional": whoever chooses the digest would choose an unsigned image,
//! and anyone who can push could block an unsigned one by attaching junk.
//! Rules are keyed by registry, exactly [`Registry::name`](crate::Registry::name),
//! and by repository: the whole registry, one repository exactly, or a
//! prefix that ends in `/`. The most specific rule wins: an exact
//! repository over any prefix, a longer prefix over a shorter one, a prefix
//! over the registry-wide rule, and that over the default, which is `Off`
//! in [`SignaturePolicy::off`]. A repository is matched as written, as
//! ADR-009 D9 reads it: `node` is not `library/node`.

use std::sync::Arc;

use boneli_sigstore::Trust;

use crate::error::Error;
use crate::reference::Repository;

/// What a matching rule asks of an image.
#[derive(Clone, Debug)]
pub enum Requirement {
    /// No signature check: the request sequence of ADR-009.
    Off,
    /// Only an image a candidate signature verifies for under this trust
    /// is unpacked; errors, absences and caps never let it pass. A trust
    /// with provenance claims (`Trust::with_claims`) admits only SLSA v1
    /// statements that meet them (ADR-031).
    Required(Arc<Trust>),
}

/// The repositories of a registry a rule applies to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoScope {
    /// Every repository of the registry.
    Registry,
    /// This repository, as written.
    Exact(Repository),
    /// Every repository whose path starts with this prefix, which ends in
    /// `/` and whose components follow the repository grammar of D9.
    Prefix(String),
}

/// One rule: a registry, a scope in it and the requirement.
#[derive(Clone, Debug)]
pub struct PolicyRule {
    /// The registry's name, as [`Registry::name`](crate::Registry::name)
    /// gives it (`docker.io`).
    pub registry: String,
    /// The repositories.
    pub scope: RepoScope,
    /// What the rule asks.
    pub requirement: Requirement,
}

/// The rules and the default (module doc).
#[derive(Clone, Debug)]
pub struct SignaturePolicy {
    default: Requirement,
    rules: Vec<PolicyRule>,
}

impl SignaturePolicy {
    /// No rule and the default `Off`: no image is checked.
    pub fn off() -> SignaturePolicy {
        SignaturePolicy {
            default: Requirement::Off,
            rules: Vec::new(),
        }
    }

    /// A policy. Refused (`Error::InvalidPolicy`): two rules with the same
    /// registry and scope, and a prefix that does not end in `/` or whose
    /// components break the repository grammar of D9. A `Trust` is never
    /// empty (`Trust::new` refuses one with neither keys nor a keyless
    /// part). Whether each rule's registry is configured is checked by
    /// `OciImageStore::open`.
    pub fn new(default: Requirement, rules: Vec<PolicyRule>) -> Result<SignaturePolicy, Error> {
        for (i, rule) in rules.iter().enumerate() {
            if let RepoScope::Prefix(prefix) = &rule.scope {
                let path = prefix.strip_suffix('/').ok_or_else(|| {
                    Error::InvalidPolicy(format!(
                        "the prefix of rule {i} for {} does not end in /",
                        rule.registry
                    ))
                })?;
                if Repository::parse(path).is_err() {
                    return Err(Error::InvalidPolicy(format!(
                        "the prefix of rule {i} for {} is not repository components joined by /",
                        rule.registry
                    )));
                }
            }
            if rules
                .iter()
                .take(i)
                .any(|r| r.registry == rule.registry && r.scope == rule.scope)
            {
                return Err(Error::InvalidPolicy(format!(
                    "rule {i} for {} has the scope of an earlier rule",
                    rule.registry
                )));
            }
        }
        Ok(SignaturePolicy { default, rules })
    }

    /// The registry names the rules use.
    pub(crate) fn registries(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|r| r.registry.as_str())
    }

    /// The requirement for `repository` of the registry named `registry`
    /// (module doc).
    pub fn requirement(&self, registry: &str, repository: &Repository) -> &Requirement {
        let path = repository.as_str();
        // Higher is more specific: the registry-wide rule 0, a prefix one
        // more than its length, an exact rule above every prefix.
        let rank = |scope: &RepoScope| -> Option<usize> {
            match scope {
                RepoScope::Registry => Some(0),
                RepoScope::Prefix(prefix) => {
                    path.starts_with(prefix.as_str()).then(|| prefix.len() + 1)
                }
                RepoScope::Exact(repo) => (repo == repository).then_some(usize::MAX),
            }
        };
        self.rules
            .iter()
            .filter(|r| r.registry == registry)
            .filter_map(|r| rank(&r.scope).map(|rank| (rank, &r.requirement)))
            .max_by_key(|(rank, _)| *rank)
            .map_or(&self.default, |(_, requirement)| requirement)
    }
}
