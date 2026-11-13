//! Request and response heads: the types, parsing through httparse plus
//! the checks httparse leaves out, and serialization that validates every
//! byte before it writes one (ADR-003).

use std::net::Ipv6Addr;

use crate::error::{Error, Result};
use crate::limits::Limits;
use crate::wire::HeadScan;

/// A request method: a token, compared case-sensitively (RFC 9110 §9.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Method(String);

impl Method {
    /// A method; anything but a non-empty token is an error.
    pub fn new(method: &str) -> Result<Method> {
        if is_token(method.as_bytes()) {
            Ok(Method(method.to_owned()))
        } else {
            Err(Error::InvalidInput("method is not a token"))
        }
    }

    /// The method as sent.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Exactly `CONNECT`.
    pub fn is_connect(&self) -> bool {
        self.0 == "CONNECT"
    }

    /// Exactly `HEAD`.
    pub fn is_head(&self) -> bool {
        self.0 == "HEAD"
    }
}

/// A request target. The absolute and asterisk forms are not accepted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// Origin form: a path starting with `/`, with an optional query;
    /// visible ASCII only.
    Origin(String),
    /// Authority form, for CONNECT only.
    Authority {
        /// The host in lowercase ASCII (RFC 4343), without userinfo or `%`;
        /// an IPv6 address without its brackets.
        host: String,
        /// The port, 1 to 65535.
        port: u16,
    },
}

/// Header fields in the order received, duplicates kept. Names compare
/// case-insensitively.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Headers {
    fields: Vec<(String, Vec<u8>)>,
}

impl Headers {
    /// No fields.
    pub fn new() -> Headers {
        Headers::default()
    }

    /// Appends a field. Names and values are checked when the head is
    /// serialized, before any byte is written.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) {
        self.fields.push((name.into(), value.into()));
    }

    /// The first value of `name`.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// Every value of `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.fields
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }

    /// Whether a field named `name` is present.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Every field, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.fields.iter().map(|(n, v)| (n.as_str(), v.as_slice()))
    }

    /// The number of fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether there are no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Whether any field has one of `names`.
    pub(crate) fn has_any(&self, names: &[&str]) -> bool {
        self.fields
            .iter()
            .any(|(n, _)| names.iter().any(|f| n.eq_ignore_ascii_case(f)))
    }

    /// Whether a `Connection` field lists the `close` option.
    pub(crate) fn wants_close(&self) -> bool {
        self.get_all("connection")
            .flat_map(|v| v.split(|&b| b == b','))
            .any(|token| trim_ows(token).eq_ignore_ascii_case(b"close"))
    }
}

/// A request head. The version is always HTTP/1.1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RequestHead {
    /// The method.
    pub method: Method,
    /// The target.
    pub target: Target,
    /// The header fields.
    pub headers: Headers,
}

impl RequestHead {
    /// A head without fields.
    pub fn new(method: Method, target: Target) -> RequestHead {
        RequestHead {
            method,
            target,
            headers: Headers::new(),
        }
    }

    /// Parses exactly one head with every check the server applies: the
    /// version, the target form, one `Host` and the framing fields.
    pub fn parse(bytes: &[u8], limits: &Limits) -> Result<RequestHead> {
        let content = whole_head(bytes, limits)?;
        Ok(parse_request(&bytes[content..], limits)?.head)
    }

    /// The head as sent on the wire. Every byte is checked first; on an
    /// error nothing is produced.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        encode_request_line(&mut out, &self.method, &self.target)?;
        encode_fields(&mut out, &self.headers)?;
        out.extend_from_slice(b"\r\n");
        Ok(out)
    }
}

/// A response head. The version is always HTTP/1.1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResponseHead {
    /// The status, 100 to 999.
    pub status: u16,
    /// The reason phrase; may be empty.
    pub reason: String,
    /// The header fields.
    pub headers: Headers,
}

impl ResponseHead {
    /// A head with the standard reason phrase for `status` and no fields.
    pub fn new(status: u16) -> ResponseHead {
        ResponseHead {
            status,
            reason: reason_phrase(status).to_owned(),
            headers: Headers::new(),
        }
    }

    /// Parses exactly one head: HTTP/1.1, a three-digit status from 100 and
    /// at most one framing field.
    pub fn parse(bytes: &[u8], limits: &Limits) -> Result<ResponseHead> {
        let content = whole_head(bytes, limits)?;
        let head = parse_response(&bytes[content..], limits)?;
        response_framing(&head.headers)?;
        Ok(head)
    }

    /// The head as sent on the wire. Every byte is checked first; on an
    /// error nothing is produced.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        encode_status_line(&mut out, self.status, &self.reason)?;
        encode_fields(&mut out, &self.headers)?;
        out.extend_from_slice(b"\r\n");
        Ok(out)
    }
}

/// Checks that `bytes` is one complete head and nothing more; returns where
/// its content starts (after leading empty lines).
fn whole_head(bytes: &[u8], limits: &Limits) -> Result<usize> {
    let mut scan = HeadScan::default();
    match scan.advance(bytes, limits.max_head_bytes())? {
        Some(end) if end == bytes.len() => Ok(scan.content.unwrap_or(0)),
        Some(_) => Err(Error::Malformed("bytes after the head")),
        None => Err(Error::Malformed("incomplete head")),
    }
}

/// How a message body is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    None,
    Length(u64),
    Chunked,
}

/// A request as the server sees it.
pub(crate) struct ParsedRequest {
    pub(crate) head: RequestHead,
    pub(crate) framing: Framing,
    pub(crate) close: bool,
    pub(crate) expect_continue: bool,
}

/// Allocates the field array for httparse. A field line takes at least
/// four bytes (`a:` and CRLF), so a head cannot hold more than a quarter of
/// its bytes in fields; a huge `max_headers` then costs nothing.
fn field_slots<'a>(limits: &Limits) -> Vec<httparse::Header<'a>> {
    let cap = limits.max_headers().min(limits.max_head_bytes() / 4 + 1);
    vec![httparse::EMPTY_HEADER; cap]
}

fn map_parse_error(e: httparse::Error) -> Error {
    match e {
        httparse::Error::TooManyHeaders => Error::TooManyHeaders,
        _ => Error::Malformed("rejected by the parser"),
    }
}

fn collect_fields(fields: &[httparse::Header<'_>]) -> Headers {
    let mut headers = Headers::new();
    for field in fields {
        headers.append(field.name, field.value);
    }
    headers
}

/// Parses a request head (without leading empty lines) and applies the
/// server's rules.
pub(crate) fn parse_request(bytes: &[u8], limits: &Limits) -> Result<ParsedRequest> {
    let mut slots = field_slots(limits);
    let mut req = httparse::Request::new(&mut slots);
    match req.parse(bytes).map_err(map_parse_error)? {
        httparse::Status::Complete(n) if n == bytes.len() => {}
        _ => return Err(Error::Malformed("incomplete head")),
    }
    if req.version != Some(1) {
        // httparse accepts only 1.0 and 1.1 and rejects any other version.
        return Err(Error::UnsupportedVersion);
    }
    let method = Method(req.method.unwrap_or_default().to_owned());
    let raw_target = req.path.unwrap_or_default();
    let target = if method.is_connect() {
        let (host, port) = parse_authority(raw_target)?;
        Target::Authority { host, port }
    } else {
        Target::Origin(parse_origin(raw_target)?)
    };
    let headers = collect_fields(req.headers);

    if headers.get_all("host").count() != 1 {
        return Err(Error::Malformed("not exactly one Host field"));
    }
    let framing = request_framing(&headers)?;
    if method.is_connect() && headers.has_any(&["content-length", "transfer-encoding"]) {
        return Err(Error::Malformed("CONNECT with body framing"));
    }
    if let Framing::Length(n) = framing {
        if n > limits.max_body_bytes() {
            return Err(Error::BodyTooLarge);
        }
    }
    let mut expect_continue = false;
    for value in headers.get_all("expect") {
        if trim_ows(value).eq_ignore_ascii_case(b"100-continue") {
            expect_continue = true;
        } else {
            return Err(Error::ExpectationFailed);
        }
    }
    let close = headers.wants_close();
    Ok(ParsedRequest {
        head: RequestHead {
            method,
            target,
            headers,
        },
        framing,
        close,
        expect_continue,
    })
}

/// Parses a response head (without leading empty lines). Framing is decided
/// by the caller, which knows the request method.
pub(crate) fn parse_response(bytes: &[u8], limits: &Limits) -> Result<ResponseHead> {
    let mut slots = field_slots(limits);
    let mut res = httparse::Response::new(&mut slots);
    match res.parse(bytes).map_err(map_parse_error)? {
        httparse::Status::Complete(n) if n == bytes.len() => {}
        _ => return Err(Error::Malformed("incomplete head")),
    }
    if res.version != Some(1) {
        return Err(Error::UnsupportedVersion);
    }
    let status = res.code.unwrap_or(0);
    if status < 100 {
        return Err(Error::Malformed("status below 100"));
    }
    Ok(ResponseHead {
        status,
        reason: res.reason.unwrap_or_default().to_owned(),
        headers: collect_fields(res.headers),
    })
}

/// Framing of a request: at most one `Content-Length`, at most one
/// `Transfer-Encoding`, never both (ADR-003 rejects RFC 9112's lenient
/// options).
pub(crate) fn request_framing(headers: &Headers) -> Result<Framing> {
    message_framing(headers)
}

/// Framing fields of a response, with the same rules as requests.
pub(crate) fn response_framing(headers: &Headers) -> Result<Framing> {
    message_framing(headers)
}

fn message_framing(headers: &Headers) -> Result<Framing> {
    let lengths: Vec<&[u8]> = headers.get_all("content-length").collect();
    let codings: Vec<&[u8]> = headers.get_all("transfer-encoding").collect();
    if lengths.len() > 1 {
        return Err(Error::Malformed("more than one Content-Length"));
    }
    if codings.len() > 1 {
        return Err(Error::Malformed("more than one Transfer-Encoding"));
    }
    match (lengths.first(), codings.first()) {
        (Some(_), Some(_)) => Err(Error::Malformed(
            "Content-Length together with Transfer-Encoding",
        )),
        (Some(value), None) => Ok(Framing::Length(parse_content_length(value)?)),
        (None, Some(value)) => {
            if trim_ows(value).eq_ignore_ascii_case(b"chunked") {
                Ok(Framing::Chunked)
            } else {
                Err(Error::UnsupportedTransferCoding)
            }
        }
        (None, None) => Ok(Framing::None),
    }
}

/// A `Content-Length` value: optional whitespace around one or more ASCII
/// digits; no sign, no list, no overflow.
pub(crate) fn parse_content_length(value: &[u8]) -> Result<u64> {
    let digits = trim_ows(value);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Error::Malformed("invalid Content-Length"));
    }
    let mut n: u64 = 0;
    for &d in digits {
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(d - b'0')))
            .ok_or(Error::Malformed("Content-Length overflows"))?;
    }
    Ok(n)
}

/// An origin-form target: `/` followed by visible ASCII.
fn parse_origin(target: &str) -> Result<String> {
    if !target.starts_with('/') {
        return Err(Error::Malformed("target is not in origin form"));
    }
    if !target.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::Malformed("target is not visible ASCII"));
    }
    Ok(target.to_owned())
}

/// An authority-form target: `host:port` or `[ipv6]:port`. The host is
/// returned in lowercase and an IPv6 address without brackets.
pub(crate) fn parse_authority(authority: &str) -> Result<(String, u16)> {
    let bad = Error::Malformed("invalid authority");
    if !authority.bytes().all(|b| b.is_ascii_graphic()) || authority.contains(['@', '%']) {
        return Err(bad);
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (inner, after) = rest
            .split_once(']')
            .ok_or(Error::Malformed("invalid authority"))?;
        let port = after
            .strip_prefix(':')
            .ok_or(Error::Malformed("invalid authority"))?;
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err(bad);
        }
        (inner.to_ascii_lowercase(), port)
    } else {
        let (host, port) = authority
            .split_once(':')
            .ok_or(Error::Malformed("invalid authority"))?;
        (check_reg_name(host)?, port)
    };
    Ok((host, parse_port(port)?))
}

/// A host name or IPv4 address: letters, digits, `-`, `.` and `_`;
/// returned in lowercase.
fn check_reg_name(host: &str) -> Result<String> {
    let ok = !host.is_empty()
        && host.len() <= 255
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
    if ok {
        Ok(host.to_ascii_lowercase())
    } else {
        Err(Error::Malformed("invalid host"))
    }
}

/// A port: one to five decimal digits, 1 to 65535.
fn parse_port(port: &str) -> Result<u16> {
    let ok = !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit());
    match port.parse::<u16>() {
        Ok(n) if ok && n != 0 => Ok(n),
        _ => Err(Error::Malformed("invalid port")),
    }
}

/// A host for the caller's side (client `Host`, CONNECT destination): a
/// name, an IPv4 address or an IPv6 address without brackets. Returned as
/// written in an authority, lowercase, IPv6 in brackets.
pub(crate) fn authority_host(host: &str) -> Result<String> {
    if host.contains(':') {
        return match host.parse::<Ipv6Addr>() {
            Ok(_)
                if host
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.') =>
            {
                Ok(format!("[{}]", host.to_ascii_lowercase()))
            }
            _ => Err(Error::InvalidInput("invalid host")),
        };
    }
    check_reg_name(host).map_err(|_| Error::InvalidInput("invalid host"))
}

/// A `Host` value for the client: a host with an optional port.
pub(crate) fn host_field(value: &str) -> Result<String> {
    let invalid = Error::InvalidInput("invalid host");
    if value.starts_with('[') {
        return match parse_authority(value) {
            Ok((host, port)) => Ok(format!("[{host}]:{port}")),
            Err(_) => match value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
                Some(inner) => authority_host(inner),
                None => Err(invalid),
            },
        };
    }
    match value.split_once(':') {
        // Two or more colons: a bare IPv6 address.
        Some((_, rest)) if rest.contains(':') => authority_host(value),
        Some((host, port)) => {
            let host = check_reg_name(host).map_err(|_| Error::InvalidInput("invalid host"))?;
            let port = parse_port(port).map_err(|_| Error::InvalidInput("invalid port"))?;
            Ok(format!("{host}:{port}"))
        }
        None => authority_host(value),
    }
}

/// RFC 9110 `tchar`.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A non-empty token.
pub(crate) fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| is_tchar(b))
}

/// A field value we send: no control character except HTAB (so no CR, LF
/// or NUL); obs-text bytes are allowed.
pub(crate) fn is_valid_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// Strips optional whitespace (SP and HTAB) at both ends.
pub(crate) fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |i| i + 1);
    &value[start..end]
}

fn encode_request_line(out: &mut Vec<u8>, method: &Method, target: &Target) -> Result<()> {
    if !is_token(method.as_str().as_bytes()) {
        return Err(Error::InvalidInput("method is not a token"));
    }
    let target = match target {
        Target::Origin(path) => {
            parse_origin(path).map_err(|_| Error::InvalidInput("invalid origin-form target"))?;
            path.clone()
        }
        Target::Authority { host, port } => {
            if *port == 0 {
                return Err(Error::InvalidInput("port is zero"));
            }
            format!("{}:{port}", authority_host(host)?)
        }
    };
    out.extend_from_slice(method.as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    Ok(())
}

pub(crate) fn encode_status_line(out: &mut Vec<u8>, status: u16, reason: &str) -> Result<()> {
    if !(100..=999).contains(&status) {
        return Err(Error::InvalidInput("status out of range"));
    }
    if !is_valid_value(reason.as_bytes()) {
        return Err(Error::InvalidInput("invalid reason phrase"));
    }
    out.extend_from_slice(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes());
    Ok(())
}

/// Appends `name: value` lines. Checks every field before appending any.
pub(crate) fn encode_fields(out: &mut Vec<u8>, headers: &Headers) -> Result<()> {
    for (name, value) in headers.iter() {
        if !is_token(name.as_bytes()) {
            return Err(Error::InvalidInput("field name is not a token"));
        }
        if !is_valid_value(value) {
            return Err(Error::InvalidInput("control character in a field value"));
        }
    }
    for (name, value) in headers.iter() {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    Ok(())
}

/// The standard reason phrase, or an empty one.
pub(crate) fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        417 => "Expectation Failed",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_values() {
        for (value, n) in [
            (&b"5"[..], 5u64),
            (b" 5", 5),
            (b"5\t", 5),
            (b"05", 5),
            (b"0", 0),
        ] {
            assert_eq!(parse_content_length(value).expect("valid"), n);
        }
        assert_eq!(
            parse_content_length(b"18446744073709551615").expect("u64::MAX"),
            u64::MAX
        );
        for value in [
            &b"+5"[..],
            b"-1",
            b"5,5",
            b"",
            b" ",
            b"5\xc2\xa0",
            "\u{665}".as_bytes(),
            b"18446744073709551616",
            b"99999999999999999999999",
            b"5 5",
        ] {
            assert!(parse_content_length(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn authority_values() {
        let ok = |s: &str| parse_authority(s).expect(s);
        assert_eq!(ok("Example.COM:443"), ("example.com".into(), 443));
        assert_eq!(ok("[::1]:8443"), ("::1".into(), 8443));
        assert_eq!(ok("[FE80::1]:1"), ("fe80::1".into(), 1));
        assert_eq!(ok("h:65535"), ("h".into(), 65535));
        assert_eq!(ok("h:00443"), ("h".into(), 443));
        for bad in [
            "h:65536",
            "h:0",
            "h",
            "h:",
            "h:+443",
            "h:0x1bb",
            "u@h:443",
            "h%2e:443",
            "::1:443",
            ":443",
            "[]:443",
            "[::1]",
            "[::1]x:443",
            "[fe80::1%25eth0]:443",
            "h:443:1",
            "h:004430",
            "h :443",
            "h/x:443",
            "[1.2.3.4]:443",
        ] {
            assert!(parse_authority(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn client_hosts() {
        assert_eq!(host_field("Example.test").expect("name"), "example.test");
        assert_eq!(
            host_field("example.test:8080").expect("with port"),
            "example.test:8080"
        );
        assert_eq!(host_field("[::1]:80").expect("ipv6 with port"), "[::1]:80");
        assert_eq!(host_field("[::1]").expect("ipv6"), "[::1]");
        assert_eq!(host_field("::1").expect("bare ipv6"), "[::1]");
        for bad in ["", "a b", "a\r\nb", "u@h", "h:0", "h:x", "[::1", "h/p"] {
            assert!(host_field(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn field_validation() {
        assert!(is_token(b"Content-Length"));
        assert!(!is_token(b""));
        assert!(!is_token(b"X Y"));
        assert!(!is_token(b"X:Y"));
        assert!(!is_token("Content\u{2011}Length".as_bytes()));
        assert!(is_valid_value(b"a\tb \xff"));
        assert!(is_valid_value(b""));
        for bad in [&b"a\rb"[..], b"a\nb", b"a\x00b", b"a\x7fb", b"a\x0bb"] {
            assert!(!is_valid_value(bad), "{bad:?}");
        }
        let mut headers = Headers::new();
        headers.append("A", "1");
        headers.append("B", "2\r\nC: 3");
        let mut out = Vec::new();
        assert!(encode_fields(&mut out, &headers).is_err());
        assert!(
            out.is_empty(),
            "nothing appended before the bad field is found"
        );
    }

    #[test]
    fn connection_close_option() {
        let mut headers = Headers::new();
        headers.append("Connection", "keep-alive, Close");
        assert!(headers.wants_close());
        let mut headers = Headers::new();
        headers.append("Connection", "keep-alive");
        headers.append("connection", " close ");
        assert!(headers.wants_close());
        let mut headers = Headers::new();
        headers.append("Connection", "closed");
        assert!(!headers.wants_close());
    }
}
