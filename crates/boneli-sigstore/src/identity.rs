//! Keyless identities (ADR-029, S2): the OIDC issuer Fulcio recorded,
//! matched exactly, and the certificate's one SAN, matched as an exact
//! email, an exact URI, or a URI prefix that ends in `/`. No regex
//! and no normalization: comparison is byte for byte, so a look-alike
//! (another script's letter, a percent-encoding, other case) never
//! matches.
//!
//! Why a prefix: a GitHub workflow's SAN is `<workflow>@<ref>`, and a
//! workflow that releases from tags gets a new `@refs/tags/<version>` with
//! every release, which `…/release.yaml@refs/tags/` covers. The boundary
//! rule keeps a prefix from crossing into a sibling:
//! `https://github.com/acme/` cannot match `https://github.com/acme-evil/x`.
//!
//! Why only `/`: a prefix ending in `@` (`…/release.yaml@`) would trust
//! every ref the workflow can run at, any branch, any commit SHA and
//! `refs/pull/N/merge`, so anyone who may push a branch to the repository
//! could sign as the release workflow. The ref class is written out
//! instead (`@refs/tags/`, or `@refs/heads/` on purpose), and a protected
//! branch is trusted by its exact SAN.

use boneli_https::San;

use crate::error::ConfigError;

/// How the SAN must read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SanRule {
    /// An `rfc822Name` SAN equal to this.
    Email(String),
    /// A URI SAN equal to this.
    Uri(String),
    /// A URI SAN that starts with this, which ends in `/`.
    UriPrefix(String),
}

/// A trusted signer: the OIDC issuer and the SAN rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    issuer: String,
    san: SanRule,
}

impl Identity {
    /// An identity. The issuer and the SAN text must be non-empty and
    /// printable ASCII without spaces (`!` to `~`), and a `UriPrefix` must
    /// end in `/` (module doc).
    pub fn new(issuer: &str, san: SanRule) -> Result<Identity, ConfigError> {
        let text = match &san {
            SanRule::Email(t) | SanRule::Uri(t) | SanRule::UriPrefix(t) => t,
        };
        if !printable(issuer) || !printable(text) {
            return Err(ConfigError::IdentityNotAscii);
        }
        if let SanRule::UriPrefix(prefix) = &san
            && !prefix.ends_with('/')
        {
            return Err(ConfigError::PrefixWithoutBoundary);
        }
        Ok(Identity {
            issuer: issuer.to_owned(),
            san,
        })
    }

    /// The OIDC issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The SAN rule.
    pub fn san(&self) -> &SanRule {
        &self.san
    }

    /// Whether a certificate with OIDC issuer `issuer` and the one SAN
    /// `san` is this identity.
    pub(crate) fn matches(&self, issuer: &[u8], san: &San) -> bool {
        if issuer != self.issuer.as_bytes() {
            return false;
        }
        match (&self.san, san) {
            (SanRule::Email(want), San::Email(have)) => want == have,
            (SanRule::Uri(want), San::Uri(have)) => want == have,
            (SanRule::UriPrefix(prefix), San::Uri(have)) => have.starts_with(prefix.as_str()),
            _ => false,
        }
    }
}

/// Non-empty, and every byte from `!` to `~`.
pub(crate) fn printable(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| (b'!'..=b'~').contains(&b))
}
