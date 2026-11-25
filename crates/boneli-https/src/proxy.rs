//! The customer's HTTP proxy (ADR-039): a forward proxy every connection
//! of a [`TlsConfig`](crate::TlsConfig) goes through once
//! [`TlsConfig::with_proxy`](crate::TlsConfig::with_proxy) sets it. HTTPS
//! goes through a `CONNECT` tunnel with TLS end to end, so the proxy sees
//! the target's name and port and nothing else; the `http` fetches of
//! revocation (CRLs, OCSP) go as absolute-form `GET`s (ADR-039, D6).
//!
//! Set only explicitly: no `HTTPS_PROXY`, `NO_PROXY` or `ALL_PROXY` is
//! read, because in the sandbox `HTTPS_PROXY` names `boneli-egress`, and a
//! runner that picked it up would route itself through the sandbox's
//! broker (ADR-039, D8). Proxy credentials are `Basic` only. They go with
//! every `CONNECT` without waiting for a `407`, because the proxy consumes
//! that head; a proxied `GET` carries them only on its retry after a
//! `407`, because a proxy that did not ask for them may pass the field on
//! to the server (ADR-039, D8).

use std::fmt;
use std::io::{Read, Write};

use boneli_http::{Headers, Limits, Tunnel, connect_tunnel_with};

use crate::{Error, Result};

/// The longest `username:password` of [`BasicCredentials`], in bytes
/// (ADR-039, D9): the largest pair whose `Proxy-Authorization: Basic …`
/// line, with its CRLF, fits nginx's default 8,192-byte header line.
pub const MAX_BASIC_CREDENTIAL_BYTES: usize = 6_120;

/// The largest head of a proxy's answer to `CONNECT`, in bytes (ADR-039,
/// D9).
pub const PROXY_MAX_HEAD_BYTES: usize = 16_384;

/// The most header fields in a proxy's answer to `CONNECT` (ADR-039, D9).
pub const PROXY_MAX_HEADERS: usize = 64;

/// A username and password for HTTP `Basic` authentication (RFC 7617):
/// the username is not empty and has no `:`, the password is not empty,
/// neither holds a control character (U+0000 to U+001F, U+007F to
/// U+009F; other UTF-8 is allowed), and `username:password` is at most
/// [`MAX_BASIC_CREDENTIAL_BYTES`]. `Debug` prints no part of it, and it
/// has no `Display` (ADR-039, D4).
#[derive(Clone, PartialEq, Eq)]
pub struct BasicCredentials {
    /// `username:password`.
    pair: String,
}

impl BasicCredentials {
    /// Checks and keeps `username` and `password`. An error names the rule
    /// broken, never the value.
    pub fn new(username: &str, password: &str) -> Result<BasicCredentials> {
        if username.is_empty() {
            return Err(Error::InvalidInput("the username is empty"));
        }
        if password.is_empty() {
            return Err(Error::InvalidInput("the password is empty"));
        }
        if username.contains(':') {
            return Err(Error::InvalidInput("the username contains a colon"));
        }
        if username.chars().any(char::is_control) {
            return Err(Error::InvalidInput(
                "the username contains a control character",
            ));
        }
        if password.chars().any(char::is_control) {
            return Err(Error::InvalidInput(
                "the password contains a control character",
            ));
        }
        if username.len() + 1 + password.len() > MAX_BASIC_CREDENTIAL_BYTES {
            return Err(Error::InvalidInput(
                "username:password is longer than MAX_BASIC_CREDENTIAL_BYTES",
            ));
        }
        Ok(BasicCredentials {
            pair: format!("{username}:{password}"),
        })
    }

    /// The field value `Basic <base64(username:password)>`, for
    /// `Proxy-Authorization` here and for a registry's `Authorization`
    /// (ADR-039, D2). It is the secret itself: never log or echo it.
    pub fn header_value(&self) -> String {
        format!("Basic {}", crate::base64::encode(self.pair.as_bytes()))
    }

    /// `text` with every run of [`REDACT_WINDOW`] bytes of the username,
    /// the password, `username:password` or its base64 replaced
    /// ([`redact`]): for a detail built from text a server chose, which a
    /// server that holds these credentials could have filled with them
    /// (ADR-039, D4).
    pub fn redact(&self, text: &str) -> String {
        let (username, password) = self.pair.split_once(':').unwrap_or((&self.pair, ""));
        let encoded = crate::base64::encode(self.pair.as_bytes());
        redact(text, &[username, password, &self.pair, &encoded])
    }
}

/// The length of the runs of a secret [`redact`] removes, in bytes
/// (ADR-039, D4): 16 bytes of base64 carry 96 bits (about 80 with the
/// case folded), so a run that long
/// in a detail is the secret and not a host, a digest or a word by
/// chance; a shorter run would start to match ordinary text, a longer
/// one would let a piece of that length through.
pub const REDACT_WINDOW: usize = 16;

/// `text` with every byte that lies in a copy of a run of
/// [`REDACT_WINDOW`] bytes of one of `secrets`, or of a whole secret that
/// is shorter, replaced: each stretch of such bytes, widened to whole
/// characters, becomes one `[redacted]`. Letters compare ASCII
/// case-insensitively: the hosts a server chooses reach a detail
/// lowercased by the URL parser, so a mixed-case secret put into a host
/// label arrives lowercase (ADR-039, D4). Empty secrets are skipped. A
/// piece of a secret shorter than the window stays.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    // ASCII lowercasing keeps every byte where it is, so a position in
    // `folded` is the same position in `text`.
    let folded = text.to_ascii_lowercase();
    let bytes = folded.as_bytes();
    let mut hit = vec![false; bytes.len()];
    let secrets: Vec<String> = secrets.iter().map(|s| s.to_ascii_lowercase()).collect();
    for secret in secrets.iter().map(|s| s.as_bytes()) {
        if secret.is_empty() {
            continue;
        }
        let width = secret.len().min(REDACT_WINDOW);
        let runs: std::collections::BTreeSet<&[u8]> = secret.windows(width).collect();
        for (at, window) in bytes.windows(width).enumerate() {
            if runs.contains(window) {
                hit[at..at + width].fill(true);
            }
        }
    }
    // A secret with multi-byte characters may match mid-character: the
    // whole character goes.
    for at in 0..bytes.len() {
        if hit[at] && !text.is_char_boundary(at) {
            let start = (0..at)
                .rev()
                .find(|&i| text.is_char_boundary(i))
                .unwrap_or(0);
            hit[start..at].fill(true);
        }
        if at > 0 && hit[at - 1] && !text.is_char_boundary(at) {
            hit[at] = true;
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut in_hit = false;
    for (at, c) in text.char_indices() {
        if hit[at] {
            if !in_hit {
                out.push_str("[redacted]");
            }
            in_hit = true;
        } else {
            out.push(c);
            in_hit = false;
        }
    }
    out
}

impl fmt::Debug for BasicCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BasicCredentials([redacted])")
    }
}

/// An HTTP forward proxy: its host and port in ADR-003's grammar, and
/// optional [`BasicCredentials`] for it: up front on `CONNECT`, after a
/// `407` on a proxied `GET` (ADR-039, D8). Plain
/// HTTP to the proxy: TLS to the proxy, NTLM, Negotiate, Digest and SOCKS
/// are not supported.
#[derive(Clone, PartialEq, Eq)]
pub struct Proxy {
    host: String,
    port: u16,
    credentials: Option<BasicCredentials>,
}

impl Proxy {
    /// The proxy at `host:port`. The host is a lowercase LDH name whose
    /// last label is not a number, a canonical dotted-decimal IPv4 address
    /// or an IPv6 address without brackets; no userinfo, no port 0
    /// (ADR-003, item 3). An error does not echo the host, which may hold
    /// userinfo.
    pub fn new(host: &str, port: u16) -> Result<Proxy> {
        crate::dial::check_host(host, port).map_err(|_| {
            Error::InvalidInput("the proxy is not a host and port the HTTP layer accepts")
        })?;
        Ok(Proxy {
            host: host.to_owned(),
            port,
            credentials: None,
        })
    }

    /// The same proxy with `credentials` in `Proxy-Authorization`.
    pub fn with_credentials(self, credentials: BasicCredentials) -> Proxy {
        Proxy {
            credentials: Some(credentials),
            ..self
        }
    }

    /// The proxy's host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The proxy's port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether credentials are set.
    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    /// `host:port`, an IPv6 host in brackets.
    pub(crate) fn authority(&self) -> String {
        authority(&self.host, self.port)
    }

    /// The fields every request to the proxy carries: `Proxy-Authorization`
    /// when credentials are set, nothing otherwise.
    pub(crate) fn fields(&self) -> Headers {
        let mut fields = Headers::new();
        if let Some(credentials) = &self.credentials {
            fields.append("Proxy-Authorization", credentials.header_value());
        }
        fields
    }

    /// `CONNECT host:port` over `stream`, a connection to the proxy, with
    /// the answer's head held to [`PROXY_MAX_HEAD_BYTES`] and
    /// [`PROXY_MAX_HEADERS`]. A refusal is `boneli_http::Error::Status`.
    pub(crate) fn tunnel<S: Read + Write>(
        &self,
        stream: S,
        host: &str,
        port: u16,
    ) -> boneli_http::Result<Tunnel<S>> {
        // The answer to a CONNECT has no body this client reads; the body
        // limit only has to be non-zero.
        let limits = Limits::new(PROXY_MAX_HEAD_BYTES, PROXY_MAX_HEADERS, 1)?;
        connect_tunnel_with(stream, host, port, &self.fields(), &limits)
    }

    /// The error for a refused `CONNECT host:port`.
    pub(crate) fn refused(&self, host: &str, port: u16, status: u16) -> Error {
        Error::Proxy {
            proxy: self.authority(),
            target: authority(host, port),
            status,
        }
    }
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "credentials",
                &format_args!(
                    "{}",
                    if self.credentials.is_some() {
                        "[redacted]"
                    } else {
                        "None"
                    }
                ),
            )
            .finish()
    }
}

/// Whether the `Proxy-Authenticate` field values `values` hold a `Basic`
/// challenge (RFC 9110, 11.6.1 and 11.7.1; RFC 7617): one of the
/// challenges, in one field or in several, whose auth-scheme is `Basic`,
/// compared case-insensitively. A field value is a comma-separated list
/// whose elements are challenges (`scheme`, `scheme token68`, `scheme
/// param=value`) or further auth-params of the challenge before them
/// (`param=value`, `param = "quoted, value"`); commas inside a quoted
/// string do not separate elements. An element starts a challenge when it
/// begins with a token that is not followed by `=`.
///
/// Only a proxy's own `407` carries this field: a proxy does not pass a
/// server's `Proxy-Authenticate` on (RFC 9110, 11.7.1; Apache httpd strips
/// it), so a `407` without a `Basic` challenge did not come from a proxy
/// that will consume `Basic` credentials (ADR-039, D8).
pub(crate) fn offers_basic<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> bool {
    values.into_iter().any(|value| {
        split_list(value).into_iter().any(|element| {
            let element = element.trim_ascii();
            let token_end = element
                .iter()
                .position(|&b| !is_tchar(b))
                .unwrap_or(element.len());
            if token_end == 0 {
                return false;
            }
            let rest = element[token_end..].trim_ascii_start();
            // `token =` is an auth-param, not a scheme.
            if rest.first() == Some(&b'=') {
                return false;
            }
            element[..token_end].eq_ignore_ascii_case(b"basic")
        })
    })
}

/// RFC 9110 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// `value` split at the commas outside quoted strings (RFC 9110, 5.6.1 and
/// 5.6.4: a backslash escapes the next byte inside quotes).
fn split_list(value: &[u8]) -> Vec<&[u8]> {
    let mut elements = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, &b) in value.iter().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            quoted = !quoted;
        } else if b == b',' && !quoted {
            elements.push(&value[start..i]);
            start = i + 1;
        }
    }
    elements.push(&value[start..]);
    elements
}

/// `host:port`, an IPv6 host in brackets.
pub(crate) fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinctive 24-character username and 40-character password, so
    /// a scan for them cannot match by chance.
    const USER: &str = "u5Er-q8RzT3vW1xY7kLmN2pQ";
    const PASS: &str = "pA55-w0rD9xK2mN7qR4tV6yZ8bC1dF3gH5jL7nPs";

    fn windows(secret: &str) -> Vec<String> {
        let bytes = secret.as_bytes();
        if bytes.len() <= 16 {
            return vec![secret.to_owned()];
        }
        bytes
            .windows(16)
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect()
    }

    fn assert_no_secret(text: &str) {
        let encoded = crate::base64::encode(format!("{USER}:{PASS}").as_bytes());
        for secret in [USER, PASS, encoded.as_str()] {
            for window in windows(secret) {
                assert!(!text.contains(&window), "{window:?} in {text:?}");
            }
        }
    }

    #[test]
    fn basic_credentials_rules() {
        let ok = |u: &str, p: &str| BasicCredentials::new(u, p).is_ok();
        assert!(ok("user", "pass"));
        assert!(!ok("", "pass"), "empty username");
        assert!(!ok("user", ""), "empty password");
        assert!(!ok("us:er", "pass"), "colon in the username");
        assert!(ok("user", "pa:ss"), "colon in the password");
        assert!(ok("užívatel", "heslo-ščř-日本"), "non-ASCII UTF-8");
        for bad in [
            '\0', '\t', '\r', '\n', '\u{7f}', '\u{85}', '\u{9f}', '\u{1f}',
        ] {
            let user = format!("{USER}{bad}");
            let pass = format!("{PASS}{bad}");
            for (u, p) in [(user.as_str(), PASS), (USER, pass.as_str())] {
                let err = BasicCredentials::new(u, p).expect_err("control character");
                assert_no_secret(&err.to_string());
                assert_no_secret(&format!("{err:?}"));
            }
        }
        // U+00A0 and U+200B are not control characters.
        assert!(ok("a\u{a0}b", "c\u{200b}d"));
    }

    #[test]
    fn basic_credential_cap_inclusive() {
        let user = "u";
        let at_cap = "p".repeat(MAX_BASIC_CREDENTIAL_BYTES - 2);
        assert_eq!(user.len() + 1 + at_cap.len(), 6_120);
        BasicCredentials::new(user, &at_cap).expect("6,120 B");
        let over = "p".repeat(MAX_BASIC_CREDENTIAL_BYTES - 1);
        assert!(BasicCredentials::new(user, &over).is_err(), "6,121 B");
        // Counted in bytes, not characters: 3,059 two-byte characters
        // after `u:` make 6,120 B.
        let wide = "ž".repeat(3_059);
        BasicCredentials::new(user, &wide).expect("6,120 B of UTF-8");
        let wider = format!("{wide}p");
        assert!(BasicCredentials::new(user, &wider).is_err());
        // The longest field line still fits nginx's 8,192-byte buffer.
        let line = format!(
            "Proxy-Authorization: {}\r\n",
            BasicCredentials::new(user, &at_cap)
                .expect("cap")
                .header_value()
        );
        assert!(line.len() <= 8_192, "{}", line.len());
    }

    /// Every 16-byte run of the username, the password, the pair and its
    /// base64 goes, wherever it sits in the text; a 15-byte piece stays,
    /// and so does everything else.
    #[test]
    fn redact_removes_every_window() {
        let credentials = BasicCredentials::new(USER, PASS).expect("credentials");
        let encoded = crate::base64::encode(format!("{USER}:{PASS}").as_bytes());
        let text = format!(
            "a {PASS} b {} c {} d {USER}e {USER}:{PASS}",
            &encoded[3..19],
            &PASS[..15]
        );
        let out = credentials.redact(&text);
        assert_no_secret(&out);
        assert_eq!(
            out,
            format!(
                "a [redacted] b [redacted] c {} d [redacted]e [redacted]",
                &PASS[..15]
            )
        );
        assert_eq!(
            credentials.redact("host:443 answered 401"),
            "host:443 answered 401"
        );
    }

    /// Letters compare ASCII case-insensitively: a mixed-case password or
    /// token that reached the text lowercased, as a host does, goes too,
    /// and so does an uppercased copy; the rest keeps its case.
    #[test]
    fn redact_ignores_ascii_case() {
        let credentials = BasicCredentials::new(USER, PASS).expect("credentials");
        let text = format!(
            "realm {}.example and {}",
            PASS.to_ascii_lowercase(),
            USER.to_ascii_uppercase()
        );
        assert_eq!(
            credentials.redact(&text),
            "realm [redacted].example and [redacted]"
        );
        let token = "Tok-9fH2kL7mQ4rT8vX1zB5nC3dG6jP0sW2yA4eU";
        let text = format!("Redirect to {}.Example", token.to_ascii_lowercase());
        assert_eq!(redact(&text, &[token]), "Redirect to [redacted].Example");
    }

    /// A secret shorter than the window goes where it appears whole; an
    /// empty one is skipped; a run that starts or ends inside a character
    /// takes the whole character, so the result stays UTF-8.
    #[test]
    fn redact_short_secrets_and_characters() {
        assert_eq!(redact("x-AWS-y", &["AWS"]), "x-[redacted]-y");
        assert_eq!(redact("abc", &[""]), "abc");
        let secret = format!("a{}", "\u{e9}".repeat(8));
        let text = format!("<a{}\u{e8}>", "\u{e9}".repeat(7));
        assert_eq!(redact(&text, &[&secret]), "<[redacted]>");
        let tail = format!("<{}>", &secret[1..]);
        assert_eq!(redact(&tail, &[&secret]), "<[redacted]>");
    }

    /// RFC 7617, 2: `Aladdin:open sesame`, decoded back byte for byte.
    #[test]
    fn basic_header_round_trip() {
        let credentials = BasicCredentials::new("Aladdin", "open sesame").expect("valid");
        let value = credentials.header_value();
        assert_eq!(value, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        let encoded = value.strip_prefix("Basic ").expect("scheme");
        let digit = |c: u8| -> u32 {
            match c {
                b'A'..=b'Z' => u32::from(c - b'A'),
                b'a'..=b'z' => u32::from(c - b'a') + 26,
                b'0'..=b'9' => u32::from(c - b'0') + 52,
                b'+' => 62,
                b'/' => 63,
                other => panic!("{other}"),
            }
        };
        let mut decoded = Vec::new();
        for quad in encoded.as_bytes().chunks(4) {
            let pad = quad.iter().filter(|c| **c == b'=').count();
            let n = quad
                .iter()
                .filter(|c| **c != b'=')
                .fold(0u32, |n, c| (n << 6) | digit(*c))
                << (6 * pad);
            let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
            decoded.extend_from_slice(&bytes[..3 - pad]);
        }
        assert_eq!(decoded, b"Aladdin:open sesame");
        // Non-ASCII goes in as UTF-8 (RFC 7617, 2.1: charset UTF-8).
        let utf8 = BasicCredentials::new("test", "123£").expect("valid");
        assert_eq!(utf8.header_value(), "Basic dGVzdDoxMjPCow==");
    }

    #[test]
    fn proxy_host_rules() {
        for (host, port) in [
            ("Proxy.corp.example", 3128u16),
            ("proxy.corp.example.", 3128),
            ("127.1", 3128),
            ("0x7f000001", 3128),
            ("prox\u{430}.corp.example", 3128),
            ("proxy\u{200b}.corp.example", 3128),
            ("proxy\u{a0}.corp.example", 3128),
            (
                "u5Er-q8RzT3vW1xY7kLmN2pQ:pA55-w0rD9xK2mN7qR4tV6yZ8bC1dF3gH5jL7nPs@proxy",
                3128,
            ),
            ("[::1]", 3128),
            ("", 3128),
            ("proxy.corp.example", 0),
        ] {
            let err = Proxy::new(host, port).expect_err(host);
            assert_no_secret(&err.to_string());
            assert!(!err.to_string().contains(host) || host.is_empty(), "{host}");
        }
        for (host, port) in [
            ("10.0.0.1", 3128u16),
            ("::1", 8080),
            ("proxy.corp.example", 3128),
        ] {
            let proxy = Proxy::new(host, port).expect(host);
            assert_eq!((proxy.host(), proxy.port()), (host, port));
            assert!(!proxy.has_credentials());
        }
        assert_eq!(
            Proxy::new("::1", 8080).expect("IPv6").authority(),
            "[::1]:8080"
        );
    }

    #[test]
    fn proxy_debug_redacts_credentials() {
        let proxy = Proxy::new("proxy.corp.example", 3128).expect("proxy");
        assert_eq!(
            format!("{proxy:?}"),
            "Proxy { host: \"proxy.corp.example\", port: 3128, credentials: None }"
        );
        let credentials = BasicCredentials::new(USER, PASS).expect("valid");
        assert_eq!(format!("{credentials:?}"), "BasicCredentials([redacted])");
        let proxy = proxy.with_credentials(credentials);
        assert!(proxy.has_credentials());
        let debug = format!("{proxy:?} {proxy:#?}");
        assert!(debug.contains("[redacted]"), "{debug}");
        assert_no_secret(&debug);
    }

    #[test]
    fn basic_challenge_detection() {
        let offers = |fields: &[&str]| offers_basic(fields.iter().map(|f| f.as_bytes()));
        for yes in [
            &["Basic realm=\"proxy\""][..],
            &["basic realm=\"proxy\""],
            &["BASIC"],
            &["  Basic  "],
            &["Negotiate, Basic realm=\"p\""],
            &["Negotiate abc==, Basic realm=\"p\""],
            &["Negotiate", "Basic realm=\"p\""],
            &["Digest realm=\"a, Basic b\", nonce=\"1\", Basic realm=\"x\""],
            // RFC 9110, 11.6.1's example.
            &[
                "Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"",
            ],
        ] {
            assert!(offers(yes), "{yes:?}");
        }
        for no in [
            &[][..],
            &[""],
            &["Negotiate"],
            &["NTLM", "Negotiate abc=="],
            &["Digest realm=\"Basic\", nonce=\"Basic, Basic x\""],
            &["Digest realm=\"a\", basic=1"],
            &["Digest realm=\"a\", basic = \"x\""],
            &["Basicx realm=\"p\""],
            &["Bearer realm=\"Basic realm\""],
        ] {
            assert!(!offers(no), "{no:?}");
        }
    }

    #[test]
    fn proxy_error_text_has_no_secret() {
        let proxy = Proxy::new("proxy.corp.example", 3128)
            .expect("proxy")
            .with_credentials(BasicCredentials::new(USER, PASS).expect("valid"));
        for status in [403, 407, 502] {
            let err = proxy.refused("registry.example", 443, status);
            let text = err.to_string();
            assert!(
                text.starts_with(&format!(
                    "the proxy proxy.corp.example:3128 answered {status} to CONNECT registry.example:443"
                )),
                "{text}"
            );
            assert_eq!(text.contains("only Basic is sent"), status == 407, "{text}");
            assert_no_secret(&text);
            assert_no_secret(&format!("{err:?}"));
        }
        assert_eq!(
            proxy.refused("::1", 443, 403).to_string(),
            "the proxy proxy.corp.example:3128 answered 403 to CONNECT [::1]:443"
        );
    }
}
