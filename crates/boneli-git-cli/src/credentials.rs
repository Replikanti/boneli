//! Credentials for the network git calls (ADR-014, D3).
//!
//! The adapter asks a [`Credentials`] source for an HTTP `Authorization`
//! value once per network git process (`fetch`, `ls-remote`, `push`), so a
//! source that mints short-lived tokens can refresh between them. The
//! value reaches git only as `http.<url>.extraHeader` in that process's
//! command-scope config (ADR-010, D4), never in argv, a file, a snapshot
//! or a failure detail.

use boneli_app::RepoUrl;

/// The longest `Authorization` value the adapter passes to git, in bytes.
/// It holds the Basic form of a 4,096-byte token (about 5,490 bytes) with
/// room to spare (ADR-014, D3).
pub const MAX_AUTHORIZATION: usize = 8_192;

/// Where the network git calls get their `Authorization` header value.
pub trait Credentials: Send + Sync {
    /// The value for `url`, for example `Basic <base64>`, or `None` when
    /// the repository needs none. Called once per network git process. The
    /// value must be 1 to [`MAX_AUTHORIZATION`] bytes of `0x20`-`0x7E`
    /// with no space at either end; anything else, or an error, fails the
    /// operation before that process starts. An error is reported in the
    /// failure detail as given, so it must not carry the secret.
    fn authorization(&self, url: &RepoUrl) -> Result<Option<String>, String>;
}

/// Why a value is refused, or `None` when it passes the rule above. The
/// reason never quotes the value: a CR or LF would let it inject a header,
/// and a NUL or a byte outside printable ASCII has no place in one.
pub(crate) fn refused(value: &str) -> Option<&'static str> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        Some("it is empty")
    } else if bytes.len() > MAX_AUTHORIZATION {
        Some("it is longer than 8192 bytes")
    } else if !bytes.iter().all(|b| (0x20..=0x7E).contains(b)) {
        Some("it holds a byte outside 0x20-0x7E")
    } else if bytes.first() == Some(&b' ') || bytes.last() == Some(&b' ') {
        Some("it starts or ends with a space")
    } else {
        None
    }
}

/// `detail` with every occurrence of `value`, and of its part after the
/// scheme (after the first space, `Basic <this>`), replaced by
/// `[redacted]`.
pub(crate) fn redact(detail: &str, value: &str) -> String {
    let mut out = detail.replace(value, "[redacted]");
    if let Some((_, secret)) = value.split_once(' ')
        && !secret.is_empty()
    {
        out = out.replace(secret, "[redacted]");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_values() {
        assert_eq!(refused("Basic eDp5"), None);
        assert_eq!(refused(&"a".repeat(MAX_AUTHORIZATION)), None);
        assert_eq!(refused("a b"), None);
        for bad in [
            "",
            " Basic x",
            "Basic x ",
            "Basic\rx",
            "Basic\nx",
            "Basic\0x",
            "Basic\tx",
            "Basic \u{17E}",
            "Basic \u{7F}",
        ] {
            assert!(refused(bad).is_some(), "{bad:?}");
        }
        assert!(refused(&"a".repeat(MAX_AUTHORIZATION + 1)).is_some());
    }

    #[test]
    fn redact_value_and_secret() {
        let value = "Basic c2VjcmV0";
        assert_eq!(
            redact("git push: Authorization: Basic c2VjcmV0, c2VjcmV0", value),
            "git push: Authorization: [redacted], [redacted]"
        );
        assert_eq!(redact("nothing here", value), "nothing here");
        assert_eq!(redact("tok tok", "tok"), "[redacted] [redacted]");
    }
}
