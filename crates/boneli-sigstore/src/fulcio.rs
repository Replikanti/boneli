//! Fulcio certificate claims (ADR-033): what a `Required` rule may ask of
//! the extensions Fulcio wrote into a GitHub Actions leaf from the OIDC
//! token, beyond the issuer and the SAN of ADR-029 S2.
//!
//! Fulcio writes these extensions itself, from the token GitHub minted for
//! the run (Fulcio's `config/identity/config.yaml`), so unlike the SLSA
//! statement of ADR-031 no step of the job chooses them. They are read
//! only from a leaf webpki has verified (`verify`'s keyless path), and only
//! under a trust with [`CertificateClaims`]; without them nothing beyond
//! the issuer is read, so ADR-029 and ADR-031 verdicts stay as they were.
//!
//! - **One reading.** Every modeled extension that is present must be one
//!   whole DER UTF8String with a minimal length, non-empty and valid
//!   UTF-8, whichever rules are set; the first that is not, in OID order,
//!   is [`CertificateRefusal::Malformed`]. Build Config URI (1.18) is read
//!   the same way, but only under its rule, so rules without it read what
//!   they read before it was added. A missing extension refuses only
//!   where a rule needs it ([`CertificateRefusal::Missing`]).
//! - **The rules,** in this order: Source Repository URI (1.12, exact or
//!   a prefix ending in `/`), Source Repository Ref (1.14, the same),
//!   Source Repository Identifier (1.15, exact), Build Config URI (1.18,
//!   exact) and Build Trigger (1.20, one of a list of exact names, which
//!   every set of claims has). The first that fails is
//!   [`CertificateRefusal::Mismatch`].
//! - **The statement agreement** (opt-in): the SLSA statement's
//!   `builder.id`, `workflow.repository`, `workflow.ref` and source
//!   commit must equal 1.9, 1.12, 1.14 and 1.13 (`provenance`); the four
//!   must then be present here.
//!
//! The deprecated raw extensions 1.2 to 1.6 are never read: a leaf without
//! the newer one it would stand for is refused where a rule needs it, so
//! nothing needs a fallback. Matching is byte for byte with ADR-031's
//! `under` rule for the remainder after a prefix.

use std::fmt;

use boneli_https::CodeSigningCert;

use crate::error::{ConfigError, Refusal};
use crate::identity::printable;
use crate::provenance::{ClaimMatch, check_match, meets};

/// GitHub Actions' OIDC issuer: the only one whose meaning of these
/// extensions this module knows (ADR-033).
pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// A Fulcio extension the reader models, in OID order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Extension {
    /// 1.3.6.1.4.1.57264.1.9: the workflow that ran, `<repo>/<path>@<ref>`.
    BuildSignerUri,
    /// 1.3.6.1.4.1.57264.1.12: the repository the run belongs to.
    SourceRepositoryUri,
    /// 1.3.6.1.4.1.57264.1.13: the commit the run started on.
    SourceRepositoryDigest,
    /// 1.3.6.1.4.1.57264.1.14: the run's ref.
    SourceRepositoryRef,
    /// 1.3.6.1.4.1.57264.1.15: the repository's numeric ID.
    SourceRepositoryIdentifier,
    /// 1.3.6.1.4.1.57264.1.18: the top-level workflow the run started,
    /// `<repo>/<path>@<ref>`: the caller where 1.9 is a reusable one.
    BuildConfigUri,
    /// 1.3.6.1.4.1.57264.1.20: the event that started the run.
    BuildTrigger,
}

impl Extension {
    const ALL: [Extension; 7] = [
        Extension::BuildSignerUri,
        Extension::SourceRepositoryUri,
        Extension::SourceRepositoryDigest,
        Extension::SourceRepositoryRef,
        Extension::SourceRepositoryIdentifier,
        Extension::BuildConfigUri,
        Extension::BuildTrigger,
    ];

    /// The last arc of the OID under 1.3.6.1.4.1.57264.1.
    fn arc(self) -> u8 {
        match self {
            Extension::BuildSignerUri => 9,
            Extension::SourceRepositoryUri => 12,
            Extension::SourceRepositoryDigest => 13,
            Extension::SourceRepositoryRef => 14,
            Extension::SourceRepositoryIdentifier => 15,
            Extension::BuildConfigUri => 18,
            Extension::BuildTrigger => 20,
        }
    }

    /// The OID's content octets: 1.3.6.1.4.1.57264.1 is `2B 06 01 04 01
    /// 83 BF 30 01`, and every modeled arc is below 128.
    fn oid(self) -> [u8; 10] {
        [
            0x2B,
            0x06,
            0x01,
            0x04,
            0x01,
            0x83,
            0xBF,
            0x30,
            0x01,
            self.arc(),
        ]
    }

    fn name(self) -> &'static str {
        match self {
            Extension::BuildSignerUri => "Build Signer URI",
            Extension::SourceRepositoryUri => "Source Repository URI",
            Extension::SourceRepositoryDigest => "Source Repository Digest",
            Extension::SourceRepositoryRef => "Source Repository Ref",
            Extension::SourceRepositoryIdentifier => "Source Repository Identifier",
            Extension::BuildConfigUri => "Build Config URI",
            Extension::BuildTrigger => "Build Trigger",
        }
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (1.3.6.1.4.1.57264.1.{})", self.name(), self.arc())
    }
}

/// The certificate claims of a rule (module doc).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateClaims {
    repository: Option<ClaimMatch>,
    git_ref: Option<ClaimMatch>,
    repository_id: Option<String>,
    build_config: Option<String>,
    triggers: Vec<String>,
    pub(crate) agreement: bool,
}

impl CertificateClaims {
    /// Certificate claims. The trigger list must not be empty: the
    /// repository, ref and commit name the code that was built only for
    /// some triggers (ADR-031 item 4), so every rule says which it trusts.
    /// Every text must be non-empty printable ASCII without spaces, and a
    /// prefix must end in `/`. A trigger listed twice counts once.
    pub fn new(
        repository: Option<ClaimMatch>,
        git_ref: Option<ClaimMatch>,
        triggers: Vec<String>,
    ) -> Result<CertificateClaims, ConfigError> {
        if triggers.is_empty() {
            return Err(ConfigError::TriggersEmpty);
        }
        if !triggers.iter().all(|t| printable(t)) {
            return Err(ConfigError::ClaimNotAscii);
        }
        for rule in [&repository, &git_ref].into_iter().flatten() {
            check_match(rule)?;
        }
        Ok(CertificateClaims {
            repository,
            git_ref,
            repository_id: None,
            build_config: None,
            triggers,
            agreement: false,
        })
    }

    /// These claims with an exact Source Repository Identifier (1.15):
    /// ASCII digits without a leading zero. A repository name can be
    /// registered again after a deletion or rename; its ID cannot.
    pub fn with_repository_id(self, id: &str) -> Result<CertificateClaims, ConfigError> {
        let decimal = id.bytes().all(|b| b.is_ascii_digit());
        if !decimal || !id.bytes().next().is_some_and(|b| b != b'0') {
            return Err(ConfigError::RepositoryIdNotDecimal);
        }
        Ok(CertificateClaims {
            repository_id: Some(id.to_owned()),
            ..self
        })
    }

    /// These claims with an exact Build Config URI (1.18),
    /// `<repository>/<workflow path>@<ref>`: the workflow file the run
    /// started, which a reusable workflow's SAN and 1.9 do not name.
    /// Non-empty printable ASCII without spaces.
    pub fn with_build_config(self, uri: &str) -> Result<CertificateClaims, ConfigError> {
        if !printable(uri) {
            return Err(ConfigError::ClaimNotAscii);
        }
        Ok(CertificateClaims {
            build_config: Some(uri.to_owned()),
            ..self
        })
    }

    /// These claims with the statement agreement (module doc). Needs the
    /// trust's provenance claims (`Trust::with_claims` first).
    pub fn with_statement_agreement(self) -> CertificateClaims {
        CertificateClaims {
            agreement: true,
            ..self
        }
    }
}

/// Which certificate claim a leaf failed, and on which extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateRefusal {
    /// A rule needs the extension and the leaf has none.
    Missing(Extension),
    /// The extension is not one minimal DER UTF8String of non-empty UTF-8.
    Malformed(Extension),
    /// The extension does not meet the rule.
    Mismatch(Extension),
    /// The statement's field differs from the extension.
    StatementDisagrees(Extension),
}

impl fmt::Display for CertificateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertificateRefusal::Missing(e) => write!(f, "the certificate has no Fulcio {e}"),
            CertificateRefusal::Malformed(e) => {
                write!(f, "the certificate's Fulcio {e} is malformed")
            }
            CertificateRefusal::Mismatch(e) => {
                write!(f, "the certificate's Fulcio {e} does not meet the rule")
            }
            CertificateRefusal::StatementDisagrees(e) => write!(
                f,
                "the provenance disagrees with the certificate's Fulcio {e}"
            ),
        }
    }
}

/// The modeled extensions of a verified leaf, each read once.
pub(crate) struct Facts<'a> {
    values: [Option<&'a str>; 7],
}

/// What the statement agreement compares (module doc): 1.9, 1.12, 1.14
/// and 1.13, all present.
pub(crate) struct Agreement<'a> {
    pub(crate) builder: &'a str,
    pub(crate) repository: &'a str,
    pub(crate) git_ref: &'a str,
    pub(crate) commit: &'a str,
}

impl<'a> Facts<'a> {
    /// Reads every modeled extension of `cert`, 1.18 only under its rule
    /// in `claims` (module doc, one reading).
    pub(crate) fn read(
        cert: &'a CodeSigningCert,
        claims: &CertificateClaims,
    ) -> Result<Facts<'a>, Refusal> {
        let mut values = [None; 7];
        for (slot, ext) in values.iter_mut().zip(Extension::ALL) {
            if ext == Extension::BuildConfigUri && claims.build_config.is_none() {
                continue;
            }
            if let Some(der) = cert.extension(&ext.oid()) {
                *slot = Some(utf8_text(der).ok_or(Refusal::CertificateClaim(
                    CertificateRefusal::Malformed(ext),
                ))?);
            }
        }
        Ok(Facts { values })
    }

    fn get(&self, ext: Extension) -> Option<&'a str> {
        Extension::ALL
            .iter()
            .position(|e| *e == ext)
            .and_then(|i| self.values[i])
    }

    fn need(&self, ext: Extension) -> Result<&'a str, Refusal> {
        self.get(ext)
            .ok_or(Refusal::CertificateClaim(CertificateRefusal::Missing(ext)))
    }
}

/// Whether `facts` meet `claims` (module doc, the rules in order); with
/// the agreement, what it compares.
pub(crate) fn check<'a>(
    facts: &Facts<'a>,
    claims: &CertificateClaims,
) -> Result<Option<Agreement<'a>>, Refusal> {
    let mismatch = |ext| Refusal::CertificateClaim(CertificateRefusal::Mismatch(ext));
    if let Some(rule) = &claims.repository
        && !meets(rule, facts.need(Extension::SourceRepositoryUri)?)
    {
        return Err(mismatch(Extension::SourceRepositoryUri));
    }
    if let Some(rule) = &claims.git_ref
        && !meets(rule, facts.need(Extension::SourceRepositoryRef)?)
    {
        return Err(mismatch(Extension::SourceRepositoryRef));
    }
    if let Some(id) = &claims.repository_id
        && facts.need(Extension::SourceRepositoryIdentifier)? != id
    {
        return Err(mismatch(Extension::SourceRepositoryIdentifier));
    }
    if let Some(uri) = &claims.build_config
        && facts.need(Extension::BuildConfigUri)? != uri
    {
        return Err(mismatch(Extension::BuildConfigUri));
    }
    let trigger = facts.need(Extension::BuildTrigger)?;
    if !claims.triggers.iter().any(|t| t == trigger) {
        return Err(mismatch(Extension::BuildTrigger));
    }
    if !claims.agreement {
        return Ok(None);
    }
    Ok(Some(Agreement {
        builder: facts.need(Extension::BuildSignerUri)?,
        repository: facts.need(Extension::SourceRepositoryUri)?,
        commit: facts.need(Extension::SourceRepositoryDigest)?,
        git_ref: facts.need(Extension::SourceRepositoryRef)?,
    }))
}

/// The text of a whole minimal DER UTF8String: non-empty, valid UTF-8.
fn utf8_text(der: &[u8]) -> Option<&str> {
    let bytes = utf8_string(der)?;
    if bytes.is_empty() {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

/// The content of a whole DER UTF8String with a minimal length.
pub(crate) fn utf8_string(der: &[u8]) -> Option<&[u8]> {
    let (&tag, rest) = der.split_first()?;
    if tag != 0x0C {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..=0x7F => (usize::from(first), rest),
        0x81 => {
            let (&n, rest) = rest.split_first()?;
            (n >= 0x80).then_some((usize::from(n), rest))?
        }
        0x82 => {
            let [hi, lo, rest @ ..] = rest else {
                return None;
            };
            let n = usize::from(*hi) << 8 | usize::from(*lo);
            (n >= 0x100).then_some((n, rest))?
        }
        _ => return None,
    };
    (rest.len() == len).then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::{Extension, utf8_text};

    fn tlv(len: usize) -> Vec<u8> {
        let mut out = vec![0x0C];
        match len {
            0..=0x7F => out.push(len as u8),
            0x80..=0xFF => out.extend([0x81, len as u8]),
            _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend(std::iter::repeat_n(b'a', len));
        out
    }

    /// Every strict prefix of a value of every length form is refused,
    /// never a panic; the whole value is read.
    #[test]
    fn truncated_values_never_panic() {
        for len in [1, 27, 90, 127, 128, 255, 256, 300, 65_535] {
            let value = tlv(len);
            assert_eq!(utf8_text(&value).map(str::len), Some(len), "{len}");
            for n in 0..value.len() {
                assert_eq!(utf8_text(&value[..n]), None, "{len} cut at {n}");
            }
        }
        // 65,536 bytes needs the 0x83 form, which is refused.
        let mut long = vec![0x0C, 0x83, 0x01, 0x00, 0x00];
        long.extend(std::iter::repeat_n(b'a', 65_536));
        assert_eq!(utf8_text(&long), None);
    }

    #[test]
    fn oids_in_order() {
        let arcs: Vec<u8> = Extension::ALL.iter().map(|e| e.oid()[9]).collect();
        assert_eq!(arcs, [9, 12, 13, 14, 15, 18, 20]);
        assert!(Extension::ALL.windows(2).all(|w| w[0] < w[1]));
    }
}
