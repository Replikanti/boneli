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
