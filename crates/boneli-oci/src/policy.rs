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
//!
//! A reference an agent chose is decided more strictly (ADR-032,
//! [`SignaturePolicy::decide`]): it is checked under the `Required` rule
//! that covers it, or let through by an operator [`AgentExemption`] that
//! names its repository or a prefix of it, and refused otherwise. An
//! exemption never lifts a `Required` rule, and `Off` rules do not apply
//! to the agent at all: neither as an exemption nor by shadowing a
//! `Required` rule that covers the repository.

use std::sync::Arc;

use boneli_app::ImageOrigin;
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

/// The repositories of a registry an agent exemption names (ADR-032):
/// one repository or a prefix, never a whole registry, because the agent
/// can choose any namespace of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExemptScope {
    /// This repository, as written.
    Exact(Repository),
    /// Every repository whose path starts with this prefix, which ends in
    /// `/` and whose components follow the repository grammar of D9.
    Prefix(String),
}

impl ExemptScope {
    /// A trailing `/` makes a prefix, anything else one repository; both
    /// must follow the repository grammar of D9 (`Error::InvalidPolicy`).
    pub fn parse(text: &str) -> Result<ExemptScope, Error> {
        if text.ends_with('/') {
            check_prefix(text)
                .map_err(|why| Error::InvalidPolicy(format!("exemption prefix {text:?} {why}")))?;
            return Ok(ExemptScope::Prefix(text.to_owned()));
        }
        Repository::parse(text)
            .map(ExemptScope::Exact)
            .map_err(|e| Error::InvalidPolicy(format!("exemption scope {text:?}: {e}")))
    }

    /// The scope as written: a repository never ends in `/`, a prefix
    /// always does, so the text alone says which it is.
    pub fn as_str(&self) -> &str {
        match self {
            ExemptScope::Exact(repo) => repo.as_str(),
            ExemptScope::Prefix(prefix) => prefix,
        }
    }
}

/// An operator exemption for references an agent chose (ADR-032): images
/// of `scope` in `registry` pass without a signature check unless a
/// `Required` rule covers them, and every pull that it admits reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentExemption {
    /// The registry's name, as [`Registry::name`](crate::Registry::name)
    /// gives it (`docker.io`).
    pub registry: String,
    /// The repositories.
    pub scope: ExemptScope,
}

impl AgentExemption {
    /// The documented first-stack configuration (ADR-032, S4): the
    /// Docker Official Images, `docker.io` with the prefix `library/`.
    pub fn docker_official_images() -> AgentExemption {
        AgentExemption {
            registry: "docker.io".to_owned(),
            scope: ExemptScope::Prefix("library/".to_owned()),
        }
    }
}

/// How a pull goes on under the policy (ADR-032).
#[derive(Clone, Copy, Debug)]
pub enum Decision<'p> {
    /// No signature check: the request sequence of ADR-009.
    Unchecked,
    /// Checked under this trust before any layer is requested (ADR-029).
    Required(&'p Arc<Trust>),
    /// An agent's reference that this exemption lets through unchecked;
    /// the pull reports it.
    Exempted(&'p AgentExemption),
    /// An agent's reference that no `Required` rule and no exemption
    /// covers: refused before any request.
    Refused,
}

/// Whether `prefix` ends in `/` and its components follow the repository
/// grammar of D9; the reason otherwise.
fn check_prefix(prefix: &str) -> Result<(), &'static str> {
    let path = prefix.strip_suffix('/').ok_or("does not end in /")?;
    Repository::parse(path)
        .map(|_| ())
        .map_err(|_| "is not repository components joined by /")
}

/// How specific a prefix is for `path`, higher is more specific: one more
/// than its length where `path` starts with it.
fn prefix_rank(path: &str, prefix: &str) -> Option<usize> {
    path.starts_with(prefix).then(|| prefix.len() + 1)
}

/// How specific a rule's scope is for `repository`, higher is more
/// specific: the registry-wide rule 0, a prefix one more than its length,
/// an exact rule above every prefix; `None` where it does not apply.
fn rule_rank(scope: &RepoScope, repository: &Repository) -> Option<usize> {
    match scope {
        RepoScope::Registry => Some(0),
        RepoScope::Prefix(prefix) => prefix_rank(repository.as_str(), prefix),
        RepoScope::Exact(repo) => (repo == repository).then_some(usize::MAX),
    }
}

/// The rules, the default and the agent exemptions (module doc).
#[derive(Clone, Debug)]
pub struct SignaturePolicy {
    default: Requirement,
    rules: Vec<PolicyRule>,
    exemptions: Vec<AgentExemption>,
}

impl SignaturePolicy {
    /// No rule and the default `Off`: no image is checked.
    pub fn off() -> SignaturePolicy {
        SignaturePolicy {
            default: Requirement::Off,
            rules: Vec::new(),
            exemptions: Vec::new(),
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
                check_prefix(prefix).map_err(|why| {
                    Error::InvalidPolicy(format!(
                        "the prefix of rule {i} for {} {why}",
                        rule.registry
                    ))
                })?;
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
        Ok(SignaturePolicy {
            default,
            rules,
            exemptions: Vec::new(),
        })
    }

    /// The same policy with these agent exemptions in place of any
    /// earlier ones (ADR-032). Refused (`Error::InvalidPolicy`): two
    /// exemptions with the same registry and scope, and a prefix that does
    /// not end in `/` or whose components break the repository grammar of
    /// D9. Whether each exemption's registry is configured is checked by
    /// `OciImageStore::open`. An empty list admits no agent reference
    /// outside a `Required` rule.
    pub fn with_agent_exemptions(
        mut self,
        exemptions: Vec<AgentExemption>,
    ) -> Result<SignaturePolicy, Error> {
        for (i, exemption) in exemptions.iter().enumerate() {
            if let ExemptScope::Prefix(prefix) = &exemption.scope {
                check_prefix(prefix).map_err(|why| {
                    Error::InvalidPolicy(format!(
                        "the prefix of agent exemption {i} for {} {why}",
                        exemption.registry
                    ))
                })?;
            }
            if exemptions.iter().take(i).any(|e| e == exemption) {
                return Err(Error::InvalidPolicy(format!(
                    "agent exemption {i} for {} has the scope of an earlier one",
                    exemption.registry
                )));
            }
        }
        self.exemptions = exemptions;
        Ok(self)
    }

    /// The registry names the rules and the agent exemptions use.
    pub(crate) fn registries(&self) -> impl Iterator<Item = &str> {
        self.rules
            .iter()
            .map(|r| r.registry.as_str())
            .chain(self.exemptions.iter().map(|e| e.registry.as_str()))
    }

    /// How a pull of `repository` of the registry named `registry` goes
    /// on, for a reference chosen by `origin` (ADR-032). The operator's
    /// reference gets [`SignaturePolicy::requirement`]. The agent's
    /// reference ignores `Off` rules: it is checked under the most
    /// specific `Required` rule that covers it, or the default when that
    /// is `Required`, so an operator's `Off` rule never shadows a
    /// `Required` one for the agent; otherwise it gets the most specific
    /// exemption of the registry that covers it (an exact one over a
    /// longer prefix, a longer prefix over a shorter one) or `Refused`.
    pub fn decide(
        &self,
        registry: &str,
        repository: &Repository,
        origin: ImageOrigin,
    ) -> Decision<'_> {
        if origin == ImageOrigin::Operator {
            return match self.requirement(registry, repository) {
                Requirement::Required(trust) => Decision::Required(trust),
                Requirement::Off => Decision::Unchecked,
            };
        }
        let required = self
            .rules
            .iter()
            .filter(|r| r.registry == registry)
            .filter_map(|r| match &r.requirement {
                Requirement::Required(trust) => rule_rank(&r.scope, repository).map(|k| (k, trust)),
                Requirement::Off => None,
            })
            .max_by_key(|(rank, _)| *rank)
            .map(|(_, trust)| trust);
        if let Some(trust) = required {
            return Decision::Required(trust);
        }
        if let Requirement::Required(trust) = &self.default {
            return Decision::Required(trust);
        }
        let path = repository.as_str();
        let rank = |scope: &ExemptScope| -> Option<usize> {
            match scope {
                ExemptScope::Prefix(prefix) => prefix_rank(path, prefix),
                ExemptScope::Exact(repo) => (repo == repository).then_some(usize::MAX),
            }
        };
        self.exemptions
            .iter()
            .filter(|e| e.registry == registry)
            .filter_map(|e| rank(&e.scope).map(|rank| (rank, e)))
            .max_by_key(|(rank, _)| *rank)
            .map_or(Decision::Refused, |(_, e)| Decision::Exempted(e))
    }

    /// The requirement for `repository` of the registry named `registry`
    /// (module doc).
    pub fn requirement(&self, registry: &str, repository: &Repository) -> &Requirement {
        self.rules
            .iter()
            .filter(|r| r.registry == registry)
            .filter_map(|r| rule_rank(&r.scope, repository).map(|rank| (rank, &r.requirement)))
            .max_by_key(|(rank, _)| *rank)
            .map_or(&self.default, |(_, requirement)| requirement)
    }
}
