//! The URL grammar of CRL distribution points (ADR-017, item 3).
//!
//! A URI from a leaf is fetched, skipped or refused. `http` and `https`
//! are fetched when the whole URL is well formed and refused otherwise;
//! any other well-formed scheme (`ldap`, `ftp`, `file`, ...) is skipped,
//! so no local file is ever read; anything without a well-formed scheme
//! is refused, so garbage cannot turn into "unchecked".

use std::fmt;

use boneli_http::Target;

use super::MAX_CRL_URL_BYTES;

/// The scheme of a CRL URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CrlScheme {
    /// Plain HTTP, port 80 by default; every point measured for ADR-017.
    Http,
    /// HTTP over TLS, port 443 by default, fetched without a revocation
    /// check of its own (ADR-017, item 6).
    Https,
}

/// A CRL distribution point that will be fetched: `http` or `https`, a
/// host in the canonical form of `boneli-http`'s grammar (ADR-003), a
/// port and a path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CrlUrl {
    scheme: CrlScheme,
    host: String,
    port: u16,
    path: String,
    text: String,
}

impl CrlUrl {
    /// `http` or `https`.
    pub fn scheme(&self) -> CrlScheme {
        self.scheme
    }

    /// The host in lowercase: a name, a dotted-decimal IPv4 address, or an
    /// IPv6 address without brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, the scheme's default when the URL names none.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The path, starting with `/`, percent escapes as the URL has them.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The canonical form: lowercase scheme and host, the port only when
    /// it is not the default. The cache is keyed by it.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The value of the `Host` field: the host, bracketed when IPv6, and
    /// the port when it is not the default.
    pub(crate) fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == default_port(self.scheme) {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Parses an `http` or `https` URL; another scheme is an error here.
    #[cfg(test)]
    pub(crate) fn parse(text: &str) -> Result<CrlUrl, &'static str> {
        match classify(text.as_bytes()) {
            Candidate::Fetch(url) => Ok(url),
            Candidate::Skip => Err("not an http or https URL"),
            Candidate::Bad(why) => Err(why),
        }
    }
}

impl fmt::Display for CrlUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// What to do with one URI of a distribution point.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Candidate {
    /// Fetch it.
    Fetch(CrlUrl),
    /// Another well-formed scheme: not fetched, not an attempt.
    Skip,
    /// Not a URL this client can fetch: a failed attempt.
    Bad(&'static str),
}

fn default_port(scheme: CrlScheme) -> u16 {
    match scheme {
        CrlScheme::Http => 80,
        CrlScheme::Https => 443,
    }
}

/// Classifies one `uniformResourceIdentifier` from a leaf.
pub(crate) fn classify(uri: &[u8]) -> Candidate {
    if uri.is_empty() {
        return Candidate::Bad("empty URL");
    }
    if uri.len() > MAX_CRL_URL_BYTES {
        return Candidate::Bad("URL longer than 1,024 bytes");
    }
    if !uri.iter().all(|b| (0x21..=0x7E).contains(b)) {
        return Candidate::Bad("URL with a byte outside visible ASCII");
    }
    // Visible ASCII only, so the bytes are a `str`.
    let Ok(uri) = std::str::from_utf8(uri) else {
        return Candidate::Bad("URL with a byte outside visible ASCII");
    };
    let Some((scheme, rest)) = uri.split_once(':') else {
        return Candidate::Bad("URL without a scheme");
    };
    // RFC 3986, 3.1: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
    let mut chars = scheme.bytes();
    let well_formed = chars.next().is_some_and(|b| b.is_ascii_alphabetic())
        && chars.all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b));
    if !well_formed {
        return Candidate::Bad("URL without a scheme");
    }
    let scheme = if scheme.eq_ignore_ascii_case("http") {
        CrlScheme::Http
    } else if scheme.eq_ignore_ascii_case("https") {
        CrlScheme::Https
    } else {
        return Candidate::Skip;
    };
    match parse_rest(scheme, rest) {
        Ok(url) => Candidate::Fetch(url),
        Err(why) => Candidate::Bad(why),
    }
}

/// `//authority[/path]` after the scheme.
fn parse_rest(scheme: CrlScheme, rest: &str) -> Result<CrlUrl, &'static str> {
    let rest = rest.strip_prefix("//").ok_or("URL without an authority")?;
    if rest.contains('#') {
        return Err("URL with a fragment");
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };
    let has_port = match authority.strip_prefix('[') {
        Some(inner) => inner
            .split_once(']')
            .is_some_and(|(_, after)| !after.is_empty()),
        None => authority.contains(':'),
    };
    let with_port = if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:{}", default_port(scheme))
    };
    // ADR-003's grammar: no userinfo, no percent-encoded or trailing-dot
    // host, no numeric form like `127.1`, no port 0; lowercase out.
    let (host, port) = match Target::parse_authority(&with_port) {
        Ok(Target::Authority { host, port }) => (host, port),
        _ => return Err("URL with an invalid host or port"),
    };
    let mut url = CrlUrl {
        scheme,
        host,
        port,
        path: path.to_owned(),
        text: String::new(),
    };
    let scheme = match scheme {
        CrlScheme::Http => "http",
        CrlScheme::Https => "https",
    };
    url.text = format!("{scheme}://{}{}", url.authority(), url.path);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetch(uri: &[u8]) -> CrlUrl {
        match classify(uri) {
            Candidate::Fetch(url) => url,
            other => panic!("{:?}: {other:?}", String::from_utf8_lossy(uri)),
        }
    }

    fn is_bad(uri: &[u8]) -> bool {
        matches!(classify(uri), Candidate::Bad(_))
    }

    #[test]
    fn url_length_1024_ok_1025_refused() {
        let prefix = "http://crl.example.com/";
        let at_cap = format!("{prefix}{}", "a".repeat(1024 - prefix.len()));
        assert_eq!(at_cap.len(), 1024);
        assert_eq!(fetch(at_cap.as_bytes()).as_str(), at_cap);
        let over = format!("{at_cap}a");
        assert!(is_bad(over.as_bytes()));
    }

    #[test]
    fn url_refusals() {
        let refused: [&[u8]; 16] = [
            b"http://user@crl.example.com/a",
            b"http://user:pw@crl.example.com/a",
            b"http://127.1/a",
            b"http://crl.example.com./a",
            b"http://crl%2Eexample.com/a",
            b"http://crl.example.com/a#b",
            b"http://crl.example.com/a b",
            b"http://crl.example.com/a\tb",
            b"http://crl.example.com/a\0",
            b"http://crl.example.com/a\x7F",
            b"http://crl.example.com:/a",
            b"http://crl.example.com:0/a",
            b"http://crl.example.com/\xC2\xA0",
            b"http://crl.example\xE2\x80\x8B.com/a",
            b"http://\xD1\x81rl.example.com/a",
            b"http://crl.example.com:99999/a",
        ];
        for uri in refused {
            assert!(is_bad(uri), "{:?}", String::from_utf8_lossy(uri));
        }
    }

    #[test]
    fn garbage_scheme_is_bad() {
        for uri in [
            b"/ca.crl".as_slice(),
            b"://x",
            b"",
            b"ht\0tp://x",
            b"1http://x",
            b"crl.example.com/a",
            b"http:/x",
            b"http:x",
        ] {
            assert!(is_bad(uri), "{:?}", String::from_utf8_lossy(uri));
        }
    }

    #[test]
    fn uppercase_scheme_is_fetched() {
        let url = fetch(b"HTTP://Crl.Example.COM/a");
        assert_eq!(url.as_str(), "http://crl.example.com/a");
        assert_eq!(url.scheme(), CrlScheme::Http);
        assert_eq!(url.host(), "crl.example.com");
        assert_eq!(url.port(), 80);
        assert_eq!(url.path(), "/a");
        let url = fetch(b"HttpS://crl.example.com:8443/a");
        assert_eq!(url.scheme(), CrlScheme::Https);
        assert_eq!(url.as_str(), "https://crl.example.com:8443/a");
    }

    #[test]
    fn other_schemes_are_skipped() {
        for uri in [
            b"ldap://ldap.example.com/cn=x?certificateRevocationList".as_slice(),
            b"ftp://ftp.example.com/ca.crl",
            b"file:///etc/passwd",
            b"x-custom+v1.0:whatever",
        ] {
            assert_eq!(classify(uri), Candidate::Skip);
        }
    }

    #[test]
    fn url_forms() {
        for uri in ["http://x1.c.lencr.org", "http://x1.c.lencr.org/"] {
            let url = fetch(uri.as_bytes());
            assert_eq!(url.path(), "/");
            assert_eq!(url.as_str(), "http://x1.c.lencr.org/");
        }
        let ms = "http://www.microsoft.com/pkiops/crl/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2004.crl";
        let url = fetch(ms.as_bytes());
        assert_eq!(
            url.path(),
            "/pkiops/crl/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2004.crl"
        );
        assert_eq!(url.as_str(), ms);
        let url = fetch(b"http://192.0.2.1/x");
        assert_eq!((url.host(), url.port()), ("192.0.2.1", 80));
        let url = fetch(b"http://[2001:db8::1]:8080/x");
        assert_eq!((url.host(), url.port()), ("2001:db8::1", 8080));
        assert_eq!(url.as_str(), "http://[2001:db8::1]:8080/x");
        assert_eq!(url.authority(), "[2001:db8::1]:8080");
        let url = fetch(b"http://[2001:DB8::1]/x");
        assert_eq!(url.as_str(), "http://[2001:db8::1]/x");
        let url = fetch(b"http://crl.example.com:80/a?b=c");
        assert_eq!(url.as_str(), "http://crl.example.com/a?b=c");
        assert_eq!(url.authority(), "crl.example.com");
        let url = fetch(b"https://crl.example.com:443/a");
        assert_eq!(url.as_str(), "https://crl.example.com/a");
        let url = fetch(b"http://127.0.0.1:8080/ca.crl");
        assert_eq!(url.authority(), "127.0.0.1:8080");
    }

    #[test]
    fn url_canonical_form_round_trips() {
        for uri in [
            "http://crl.boneli.test/ca.crl",
            "HTTP://Crl.Example.COM/a",
            "http://x1.c.lencr.org",
            "http://192.0.2.1/x",
            "http://[2001:db8::1]:8080/x",
            "http://[2001:db8::1]/x",
            "https://crl.example.com:443/a",
            "https://crl.example.com:8443/a%20b?c",
            "http://127.0.0.1:1/",
        ] {
            let url = fetch(uri.as_bytes());
            assert_eq!(CrlUrl::parse(url.as_str()), Ok(url.clone()), "{uri}");
            assert_eq!(url.to_string(), url.as_str());
        }
        assert!(CrlUrl::parse("ldap://x/").is_err());
    }
}
