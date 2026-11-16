//! Image references: the registry, repository, digest and platform of an
//! `ImageRef`, parsed strictly before any request is made (ADR-009, D9).
//!
//! Nothing is repaired or normalized: `node` is not rewritten to
//! `library/node`, uppercase is not lowered, whitespace is not trimmed.
//! Every rejection is `PullError::Failed`, because a malformed reference is
//! the caller's error, not a missing image.

use std::fmt;

use crate::error::{PullError, failed};
use crate::url;

/// The longest repository path, `distribution/reference`'s
/// `RepositoryNameTotalLengthMax`.
const MAX_REPOSITORY_BYTES: usize = 255;

/// A SHA-256 digest, written `sha256:` and 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Parses `sha256:<64 lowercase hex digits>`; anything else, other
    /// algorithms included, is refused.
    pub fn parse(text: &str) -> Result<Digest, PullError> {
        let refuse = || {
            failed(format!(
                "digest {text:?} is not sha256: and 64 lowercase hex digits"
            ))
        };
        let hex = text.strip_prefix("sha256:").ok_or_else(refuse)?;
        if hex.len() != 64 {
            return Err(refuse());
        }
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let (Some(hi), Some(lo)) = (nibble(pair[0]), nibble(pair[1])) else {
                return Err(refuse());
            };
            *byte = hi << 4 | lo;
        }
        Ok(Digest(out))
    }

    /// The digest of `bytes`.
    pub fn of(bytes: &[u8]) -> Digest {
        Digest(boneli_https::Sha256::digest(bytes))
    }

    /// A digest from its 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Digest {
        Digest(bytes)
    }

    /// The 32 bytes.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The 64 lowercase hex digits.
    pub fn hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for b in &self.0 {
            out.push(char::from(DIGITS[usize::from(b >> 4)]));
            out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        }
        out
    }
}

/// A lowercase hex digit's value.
fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

/// A platform, `os/architecture[/variant]`, each part `[a-z0-9]+`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    os: String,
    architecture: String,
    variant: Option<String>,
}

impl Platform {
    /// Parses `os/architecture` or `os/architecture/variant`.
    pub fn parse(text: &str) -> Result<Platform, PullError> {
        let refuse = || {
            failed(format!(
                "platform {text:?} is not os/architecture[/variant] of [a-z0-9]+ parts"
            ))
        };
        let parts: Vec<&str> = text.split('/').collect();
        let ok = |p: &&str| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        };
        match parts.as_slice() {
            [os, arch] if ok(os) && ok(arch) => Ok(Platform {
                os: (*os).to_owned(),
                architecture: (*arch).to_owned(),
                variant: None,
            }),
            [os, arch, variant] if ok(os) && ok(arch) && ok(variant) => Ok(Platform {
                os: (*os).to_owned(),
                architecture: (*arch).to_owned(),
                variant: Some((*variant).to_owned()),
            }),
            _ => Err(refuse()),
        }
    }

    /// The operating system, for example `linux`.
    pub fn os(&self) -> &str {
        &self.os
    }

    /// The architecture, for example `amd64`.
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// The variant, for example `v8`.
    pub fn variant(&self) -> Option<&str> {
        self.variant.as_deref()
    }

    /// Whether an index entry or a config with this os, architecture and
    /// variant is this platform. The os and architecture match exactly. A
    /// missing variant matches only a missing variant, except on `arm64`,
    /// where a missing variant and `v8` are the same (ADR-009, D9). An
    /// `unknown` os or architecture, which attestation entries carry, never
    /// matches.
    pub fn matches(&self, os: &str, architecture: &str, variant: Option<&str>) -> bool {
        if os == "unknown" || architecture == "unknown" {
            return false;
        }
        os == self.os
            && architecture == self.architecture
            && normal_variant(architecture, variant)
                == normal_variant(architecture, self.variant.as_deref())
    }
}

/// `v8` on `arm64` is the same as no variant.
fn normal_variant<'v>(architecture: &str, variant: Option<&'v str>) -> Option<&'v str> {
    match variant {
        Some("v8") if architecture == "arm64" => None,
        v => v,
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)?;
        if let Some(variant) = &self.variant {
            write!(f, "/{variant}")?;
        }
        Ok(())
    }
}

/// A repository path: `/`-separated components
/// `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`, at most 255 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository(String);

impl Repository {
    /// Parses a repository path without a registry prefix.
    pub fn parse(text: &str) -> Result<Repository, PullError> {
        if text.len() > MAX_REPOSITORY_BYTES {
            return Err(failed(format!(
                "repository path of {} bytes is longer than {MAX_REPOSITORY_BYTES}",
                text.len()
            )));
        }
        if !text.split('/').all(|c| component(c.as_bytes())) {
            return Err(failed(format!(
                "repository path {text:?} is not lowercase components [a-z0-9] joined by ., _, __ or -"
            )));
        }
        Ok(Repository(text.to_owned()))
    }

    /// The path as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Repository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One path component: runs of `[a-z0-9]` joined by `.`, `_`, `__` or one
/// or more `-`.
fn component(c: &[u8]) -> bool {
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let mut i = 0;
    loop {
        let start = i;
        while c.get(i).copied().is_some_and(alnum) {
            i += 1;
        }
        if i == start {
            return false;
        }
        match c.get(i) {
            None => return true,
            Some(b'.') => i += 1,
            Some(b'_') => {
                i += 1;
                if c.get(i) == Some(&b'_') {
                    i += 1;
                }
            }
            Some(b'-') => {
                while c.get(i) == Some(&b'-') {
                    i += 1;
                }
            }
            Some(_) => return false,
        }
    }
}

/// The registry host a name starts with, before it is matched against the
/// allowlist: a lowercase host and the port, if the name gave one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryHost {
    host: String,
    port: Option<u16>,
}

impl RegistryHost {
    /// The host, lowercase.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, if the name gave one.
    pub fn port(&self) -> Option<u16> {
        self.port
    }
}

/// An image reference: an optional registry host, a repository path, the
/// digest of an index or a manifest, and the platform to pull.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    registry: Option<RegistryHost>,
    repository: Repository,
    digest: Digest,
    platform: Platform,
}

impl Reference {
    /// Parses the three fields of an `ImageRef`. The name's first
    /// component is a registry host when the name has more than one
    /// component and the first contains `.` or `:` or is `localhost`
    /// (`distribution/reference`'s rule); the host must then pass the
    /// grammar of ADR-003 (no userinfo, no numeric forms like `127.1`),
    /// and `Registry` matching decides whether it is allowed. Without a
    /// host the store's default registry applies.
    pub fn parse(name: &str, digest: &str, platform: &str) -> Result<Reference, PullError> {
        let (registry, path) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                let (host, port) = url::host_port(first).map_err(|e| {
                    failed(format!(
                        "registry host {first:?} in {name:?} is invalid: {e}"
                    ))
                })?;
                (Some(RegistryHost { host, port }), rest)
            }
            _ => (None, name),
        };
        Ok(Reference {
            registry,
            repository: Repository::parse(path)?,
            digest: Digest::parse(digest)?,
            platform: Platform::parse(platform)?,
        })
    }

    /// The registry host the name starts with, if any.
    pub fn registry(&self) -> Option<&RegistryHost> {
        self.registry.as_ref()
    }

    /// The repository path.
    pub fn repository(&self) -> &Repository {
        &self.repository
    }

    /// The digest of the index or manifest.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// The platform to pull.
    pub fn platform(&self) -> &Platform {
        &self.platform
    }
}

#[cfg(test)]
mod tests {
    use super::component;

    #[test]
    fn component_grammar() {
        for ok in ["a", "a0", "a.b", "a_b", "a__b", "a-b", "a---b", "a.b-c__d"] {
            assert!(component(ok.as_bytes()), "{ok}");
        }
        for bad in [
            "", ".a", "a.", "a..b", "a___b", "a_", "-a", "a-", "A", "a/b", "a b",
        ] {
            assert!(!component(bad.as_bytes()), "{bad}");
        }
    }
}
