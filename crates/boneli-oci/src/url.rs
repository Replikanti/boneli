//! `https://` URLs for the registry client: token realms and redirect
//! targets (ADR-009, D9, D10).
//!
//! The authority goes through `boneli_http::Target::parse_authority`, the
//! grammar of ADR-003, with 443 as the default port, so userinfo, `127.1`
//! and hosts that are not LDH names are refused. The target is origin
//! form, visible ASCII only, with dot segments removed and the fragment
//! dropped. Anything other than `https` is refused; nothing is repaired.

use boneli_http::Target;

/// The port of an `https` URL without one.
const HTTPS_PORT: u16 = 443;

/// An `https` URL as the client requests it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Url {
    /// The host, lowercase; an IPv6 address without brackets.
    pub(crate) host: String,
    /// The port.
    pub(crate) port: u16,
    /// The origin-form target: path and query.
    pub(crate) target: String,
}

impl Url {
    /// Parses an absolute `https://` URL.
    pub(crate) fn parse(text: &str) -> Result<Url, &'static str> {
        let scheme_end = scheme_end(text).ok_or("not an absolute URL")?;
        if !text[..scheme_end].eq_ignore_ascii_case("https") {
            return Err("the scheme is not https");
        }
        let rest = text[scheme_end + 1..]
            .strip_prefix("//")
            .ok_or("no authority")?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let (host, port) = host_port(authority)?;
        Ok(Url {
            host,
            port: port.unwrap_or(HTTPS_PORT),
            target: origin(tail)?,
        })
    }

    /// Resolves `reference` against this URL (RFC 3986, section 5.2): an
    /// absolute URL, `//host/...`, an absolute path, a query or a relative
    /// path.
    pub(crate) fn join(&self, reference: &str) -> Result<Url, &'static str> {
        if scheme_end(reference).is_some() {
            return Url::parse(reference);
        }
        if reference.starts_with("//") {
            return Url::parse(&format!("https:{reference}"));
        }
        let reference = reference.split('#').next().unwrap_or_default();
        let base_path = self.target.split('?').next().unwrap_or("/");
        let tail = if reference.is_empty() {
            self.target.clone()
        } else if reference.starts_with('/') {
            reference.to_owned()
        } else if reference.starts_with('?') {
            format!("{base_path}{reference}")
        } else {
            let dir = base_path.rfind('/').map_or("/", |i| &base_path[..=i]);
            format!("{dir}{reference}")
        };
        Ok(Url {
            host: self.host.clone(),
            port: self.port,
            target: origin(&tail)?,
        })
    }

    /// The value of the `Host` field: the host, with the port when it is
    /// not 443; an IPv6 address in brackets.
    pub(crate) fn host_field(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == HTTPS_PORT {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Where the scheme of an absolute URL ends (the index of its `:`): a
/// letter, then letters, digits, `+`, `-` or `.`, before any `/`, `?` or
/// `#`.
fn scheme_end(text: &str) -> Option<usize> {
    let colon = text.find(':')?;
    let scheme = &text[..colon];
    let mut bytes = scheme.bytes();
    let first = bytes.next()?;
    (first.is_ascii_alphabetic()
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')))
    .then_some(colon)
}

/// `text` with everything up to its last `@` shown as `[userinfo]`, so a
/// detail about a host or an image name never echoes credentials someone
/// wrote into it (ADR-039, D4); `text` itself when it has no `@`.
pub(crate) fn mask_userinfo(text: &str) -> String {
    match text.rsplit_once('@') {
        Some((_, rest)) => format!("[userinfo]@{rest}"),
        None => text.to_owned(),
    }
}

/// `host[:port]` or `[ipv6][:port]` with the grammar of ADR-003: the
/// host lowercase and the port if one was given. Userinfo is refused.
pub(crate) fn host_port(authority: &str) -> Result<(String, Option<u16>), &'static str> {
    if authority.contains('@') {
        return Err("userinfo is not allowed");
    }
    let has_port = match authority.strip_prefix('[') {
        Some(rest) => rest
            .split_once(']')
            .is_some_and(|(_, after)| !after.is_empty()),
        None => authority.contains(':'),
    };
    let text = if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:{HTTPS_PORT}")
    };
    match Target::parse_authority(&text) {
        Ok(Target::Authority { host, port }) => Ok((host, has_port.then_some(port))),
        _ => Err("not a host the HTTP layer accepts"),
    }
}

/// An origin-form target from the part of a URL after its authority:
/// the fragment dropped, `/` for an empty path, dot segments removed,
/// visible ASCII only.
fn origin(tail: &str) -> Result<String, &'static str> {
    let tail = tail.split('#').next().unwrap_or_default();
    if !tail.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("the path is not visible ASCII");
    }
    let (path, query) = match tail.find('?') {
        Some(i) => tail.split_at(i),
        None => (tail, ""),
    };
    let path = if path.is_empty() { "/" } else { path };
    Ok(format!("{}{query}", remove_dot_segments(path)))
}

/// RFC 3986, section 5.2.4, for a path that starts with `/`: `.` goes,
/// `..` removes the segment before it and never climbs above the root.
fn remove_dot_segments(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let mut out: Vec<&str> = Vec::new();
    for (i, segment) in segments.iter().enumerate() {
        let last = i + 1 == segments.len();
        match *segment {
            "." => {}
            ".." => {
                out.pop();
            }
            s => {
                out.push(s);
                continue;
            }
        }
        if last {
            out.push("");
        }
    }
    format!("/{}", out.join("/"))
}

#[cfg(test)]
mod tests {
    use super::{Url, remove_dot_segments};

    fn url(text: &str) -> Url {
        Url::parse(text).expect(text)
    }

    #[test]
    fn parses_https_only() {
        let u = url("https://Auth.Docker.IO/token?service=x#frag");
        assert_eq!(u.host, "auth.docker.io");
        assert_eq!(u.port, 443);
        assert_eq!(u.target, "/token?service=x");
        assert_eq!(url("HTTPS://h.example:8443").target, "/");
        assert_eq!(url("https://h.example:8443").port, 8443);
        assert_eq!(url("https://h.example?q").target, "/?q");
        assert_eq!(url("https://[::1]:5000/a").host, "::1");
        for bad in [
            "http://h.example/",
            "ftp://h.example/",
            "https:h.example/",
            "https://user@h.example/",
            "https://127.1/",
            "https://h.example:/",
            "https://h.example:0/",
            "https://h_x.example/",
            "https:///a",
            "https://h.example/a b",
            "https://h.example/\u{e9}",
            "/relative",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn joins_references() {
        let base = url("https://r.example/v2/a/blobs/sha256:00?x=1");
        assert_eq!(base.join("/b").expect("abs").target, "/b");
        assert_eq!(base.join("c/d").expect("rel").target, "/v2/a/blobs/c/d");
        assert_eq!(base.join("../e").expect("dots").target, "/v2/a/e");
        assert_eq!(
            base.join("?y").expect("query").target,
            "/v2/a/blobs/sha256:00?y"
        );
        assert_eq!(base.join("").expect("empty").target, base.target);
        let other = base.join("//cdn.example/f").expect("network path");
        assert_eq!(
            (other.host.as_str(), other.target.as_str()),
            ("cdn.example", "/f")
        );
        assert!(base.join("http://cdn.example/f").is_err());
        assert!(base.join("javascript:x").is_err());
    }

    #[test]
    fn dot_segments() {
        for (input, want) in [
            ("/a/b/../c", "/a/c"),
            ("/a/b/..", "/a/"),
            ("/a/./b", "/a/b"),
            ("/.", "/"),
            ("/../..", "/"),
            ("/a//b", "/a//b"),
            ("/", "/"),
        ] {
            assert_eq!(remove_dot_segments(input), want, "{input}");
        }
    }

    #[test]
    fn host_field_brackets_and_ports() {
        assert_eq!(url("https://r.example/").host_field(), "r.example");
        assert_eq!(
            url("https://r.example:5000/").host_field(),
            "r.example:5000"
        );
        assert_eq!(url("https://[::1]/").host_field(), "[::1]");
        assert_eq!(url("https://[::1]:5000/").host_field(), "[::1]:5000");
    }
}
