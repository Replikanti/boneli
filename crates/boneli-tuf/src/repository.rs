//! The TUF repository a refresh fetches from (ADR-033, item 7): one host,
//! https only, and an optional path prefix. Only that host is ever dialed.

use std::fmt;

use boneli_http::Target;

/// The port of a repository URL without one.
const HTTPS_PORT: u16 = 443;

/// A repository URL, `https://<host>[:port][/<prefix>]`, in canonical form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    /// A host in ADR-003's grammar: lower-case LDH labels, a canonical
    /// dotted-decimal IPv4 address, or an IPv6 address without brackets.
    host: String,
    port: u16,
    /// Empty, or the segments of the prefix, each with a leading `/`.
    prefix: String,
}

/// Why a repository URL was refused: a fixed reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryError(pub &'static str);

impl fmt::Display for RepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the repository URL {}", self.0)
    }
}

impl std::error::Error for RepositoryError {}

impl Repository {
    /// Parses `https://<host>[:port][/<prefix>]`:
    ///
    /// - the scheme is `https://`, byte for byte;
    /// - no userinfo, query, fragment or percent sign anywhere, so no byte
    ///   of the URL means something other than what it shows;
    /// - host and port in ADR-003's grammar (`Target::parse_authority`)
    ///   and written as that grammar writes them: lower case, no leading
    ///   zeros in the port, no `127.1` or other numeric form only
    ///   `inet_aton` reads; the port defaults to 443;
    /// - every prefix segment is `[A-Za-z0-9._~-]+` and not `.` or `..`,
    ///   so no empty segment and no trailing `/`.
    pub fn parse(url: &str) -> Result<Repository, RepositoryError> {
        let rest = url
            .strip_prefix("https://")
            .ok_or(RepositoryError("must start with https://"))?;
        if rest.bytes().any(|b| matches!(b, b'@' | b'?' | b'#' | b'%')) {
            return Err(RepositoryError(
                "must have no userinfo, query, fragment or percent sign",
            ));
        }
        let (authority, prefix) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let (host, port, explicit) = authority_parts(authority)?;
        for segment in prefix.split('/').skip(1) {
            let allowed = |b: u8| b.is_ascii_alphanumeric() || b"._~-".contains(&b);
            if segment.is_empty()
                || segment == "."
                || segment == ".."
                || !segment.bytes().all(allowed)
            {
                return Err(RepositoryError(
                    "must have path segments of [A-Za-z0-9._~-] only, none empty, `.` or `..`",
                ));
            }
        }
        let repository = Repository {
            host,
            port,
            prefix: prefix.to_string(),
        };
        // Written back, the authority must be what was given: the grammar
        // folds case and drops leading zeros, and a URL that means another
        // host than it shows is refused instead.
        if repository.authority(explicit) != authority {
            return Err(RepositoryError(
                "must name its host and port in canonical form (lower case, no leading zeros)",
            ));
        }
        Ok(repository)
    }

    /// The host, as the `Dial` takes it.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The origin-form target of `file` under the prefix.
    pub(crate) fn target(&self, file: &str) -> String {
        format!("{}/{file}", self.prefix)
    }

    /// The `Host` field: the host, bracketed when IPv6, with the port when
    /// it is not 443.
    pub(crate) fn host_field(&self) -> String {
        self.authority(self.port != HTTPS_PORT)
    }

    fn authority(&self, with_port: bool) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if with_port {
            format!("{host}:{}", self.port)
        } else {
            host
        }
    }
}

/// Host, port and whether the port was given, by ADR-003's authority
/// grammar.
fn authority_parts(authority: &str) -> Result<(String, u16, bool), RepositoryError> {
    let bad = RepositoryError("must name a host and port that the HTTP layer accepts (ADR-003)");
    // A port follows the last `:` outside brackets.
    let explicit = match authority.rfind(':') {
        Some(i) => !authority[i..].contains(']'),
        None => false,
    };
    let full = if explicit {
        authority.to_string()
    } else {
        format!("{authority}:{HTTPS_PORT}")
    };
    match Target::parse_authority(&full) {
        Ok(Target::Authority { host, port }) => Ok((host, port, explicit)),
        _ => Err(bad),
    }
}

impl fmt::Display for Repository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}{}", self.host_field(), self.prefix)
    }
}
