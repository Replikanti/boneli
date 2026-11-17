//! The transports `fetch_base` accepts (ADR-010, D5).
//!
//! A URL is checked before any process starts and reaches git only after
//! `--`, so it can never be read as an option. Only `https://` is a
//! production transport; `file://` exists for the adapter's own tests.

use std::fmt;

/// Which URL forms `fetch_base` accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transports {
    /// `https://<host>/<path>` only. Production roots use this.
    Https,
    /// `https://` and `file:///<absolute path>`, for tests over local
    /// fixture repositories.
    HttpsAndFile,
}

/// Why a URL is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlProblem {
    /// Whitespace, a control character or NUL.
    Character,
    /// Not `https://` (lowercase), or `file://` where it is not accepted.
    Scheme,
    /// No host, or no `/` after it.
    Host,
    /// Userinfo (`@`) in the authority: credentials never ride in a URL.
    Userinfo,
    /// A `file://` URL with a host, a relative path, or a `.`, `..` or empty
    /// component.
    FilePath,
}

impl fmt::Display for UrlProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UrlProblem::Character => "the URL holds whitespace, a control character or NUL",
            UrlProblem::Scheme => "the URL's scheme is not an accepted transport",
            UrlProblem::Host => "the URL has no host or no path after it",
            UrlProblem::Userinfo => "the URL carries userinfo",
            UrlProblem::FilePath => {
                "a file URL must be file:/// and an absolute path without ., .. or empty components"
            }
        })
    }
}

impl Transports {
    /// Whether `url` is accepted, and why not.
    pub fn check(self, url: &str) -> Result<(), UrlProblem> {
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(UrlProblem::Character);
        }
        if let Some(rest) = url.strip_prefix("https://") {
            let (authority, _) = rest.split_once('/').ok_or(UrlProblem::Host)?;
            if authority.contains('@') {
                return Err(UrlProblem::Userinfo);
            }
            if authority.is_empty() {
                return Err(UrlProblem::Host);
            }
            return Ok(());
        }
        match (self, url.strip_prefix("file://")) {
            (Transports::HttpsAndFile, Some(path)) => {
                let absolute = path.strip_prefix('/').ok_or(UrlProblem::FilePath)?;
                let bad = absolute
                    .split('/')
                    .any(|c| c.is_empty() || c == "." || c == "..");
                if bad {
                    return Err(UrlProblem::FilePath);
                }
                Ok(())
            }
            _ => Err(UrlProblem::Scheme),
        }
    }

    /// `GIT_ALLOW_PROTOCOL`.
    pub(crate) fn allow_protocol(self) -> &'static str {
        match self {
            Transports::Https => "https",
            Transports::HttpsAndFile => "https:file",
        }
    }
}
