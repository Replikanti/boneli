//! The anonymous token flow of a registry (ADR-009, D9): the Bearer
//! challenge of a `401`, the token request it names, and the token in the
//! answer.
//!
//! `WWW-Authenticate` is read as RFC 9110, section 11.6.1, defines it:
//! one or more challenges per field, each a scheme followed by
//! comma-separated auth-params (token or quoted-string values, with
//! backslash escapes) or one token68. Exactly one `Bearer` challenge must
//! be present; its parameters are unique and their names compare
//! case-insensitively. Non-ASCII bytes are refused.

use crate::url::Url;

/// A Bearer challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Challenge {
    /// The token endpoint.
    pub(crate) realm: Url,
    /// The `service` parameter, if any.
    pub(crate) service: Option<String>,
    /// The `scope` parameter, if any.
    pub(crate) scope: Option<String>,
}

/// One challenge: its scheme and its parameters (a token68 has the name
/// `""`).
type Raw = (String, Vec<(String, String)>);

/// The Bearer challenge among every `WWW-Authenticate` value.
pub(crate) fn bearer<'a>(values: impl Iterator<Item = &'a [u8]>) -> Result<Challenge, String> {
    let mut found = None;
    for value in values {
        for (scheme, params) in challenges(value)? {
            if !scheme.eq_ignore_ascii_case("bearer") {
                continue;
            }
            if found.is_some() {
                return Err("more than one Bearer challenge".into());
            }
            found = Some(params);
        }
    }
    let params = found.ok_or("no Bearer challenge")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for (name, value) in params {
        let slot = match name.as_str() {
            "realm" => &mut realm,
            "service" => &mut service,
            "scope" => &mut scope,
            "" => return Err("a Bearer challenge with a token68".into()),
            _ => continue,
        };
        *slot = Some(value);
    }
    let realm = realm.ok_or("the Bearer challenge has no realm")?;
    let realm = Url::parse(&realm).map_err(|e| format!("the realm is not usable: {e}"))?;
    Ok(Challenge {
        realm,
        service,
        scope,
    })
}

/// The URL of the anonymous token request: the realm with `service` and
/// `scope` appended to its query, percent-encoded.
pub(crate) fn token_url(challenge: &Challenge, scope: &str) -> Url {
    let mut url = challenge.realm.clone();
    let mut sep = if url.target.contains('?') { '&' } else { '?' };
    if let Some(service) = &challenge.service {
        url.target.push(sep);
        url.target.push_str("service=");
        url.target.push_str(&encode(service));
        sep = '&';
    }
    url.target.push(sep);
    url.target.push_str("scope=");
    url.target
        .push_str(&encode(challenge.scope.as_deref().unwrap_or(scope)));
    url
}

/// Percent-encodes everything but RFC 3986's unreserved characters.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The token in a token response: `token`, or else `access_token`. It must
/// be a non-empty string of visible ASCII, so it cannot break or extend
/// the `Authorization` field it goes into.
pub(crate) fn token(body: &[u8], limits: &boneli_json::Limits) -> Result<String, String> {
    let value = boneli_json::parse(body, limits).map_err(|e| e.to_string())?;
    let object = value.as_object().ok_or("not a JSON object")?;
    let field = object
        .get("token")
        .or_else(|| object.get("access_token"))
        .ok_or("no token")?;
    let token = field.as_str().ok_or("the token is not a string")?;
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("the token is blank or not visible ASCII".into());
    }
    Ok(token.to_owned())
}

/// A cursor over one field value.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// RFC 9110 `tchar`.
fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// RFC 9110 `token68` characters, without the trailing `=`.
fn token68_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~+/".contains(&b)
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    fn take_while(&mut self, f: impl Fn(u8) -> bool) -> String {
        let start = self.pos;
        while self.peek().is_some_and(&f) {
            self.pos += 1;
        }
        String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned()
    }

    fn quoted(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("an unterminated quoted string".into()),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    match self.peek() {
                        Some(b) if b == b'\t' || (0x20..0x7f).contains(&b) => {
                            out.push(char::from(b));
                            self.pos += 1;
                        }
                        _ => return Err("an invalid escape in a quoted string".into()),
                    }
                }
                Some(b) if b == b'\t' || (0x20..0x7f).contains(&b) => {
                    out.push(char::from(b));
                    self.pos += 1;
                }
                Some(_) => return Err("a byte outside visible ASCII in a quoted string".into()),
            }
        }
    }

    /// After a `,`: whether an auth-param (`name =`) follows, which
    /// continues the current challenge, rather than a new scheme.
    fn param_follows(&mut self) -> bool {
        let save = self.pos;
        self.pos += 1;
        self.skip_ows();
        let name = self.take_while(tchar);
        self.skip_ows();
        let param = !name.is_empty() && self.peek() == Some(b'=');
        self.pos = save;
        param
    }
}

/// Every challenge in one field value.
fn challenges(value: &[u8]) -> Result<Vec<Raw>, String> {
    if !value.is_ascii() {
        return Err("WWW-Authenticate is not ASCII".into());
    }
    let mut c = Cursor {
        bytes: value,
        pos: 0,
    };
    let mut out: Vec<Raw> = Vec::new();
    loop {
        while matches!(c.peek(), Some(b' ' | b'\t' | b',')) {
            c.pos += 1;
        }
        if c.peek().is_none() {
            return Ok(out);
        }
        let scheme = c.take_while(tchar);
        if scheme.is_empty() {
            return Err("WWW-Authenticate has no auth scheme".into());
        }
        let mut params: Vec<(String, String)> = Vec::new();
        if c.peek() == Some(b' ') {
            c.skip_ows();
            params_of(&mut c, &mut params)?;
        }
        match c.peek() {
            None | Some(b',') => {}
            Some(_) => return Err("WWW-Authenticate is malformed".into()),
        }
        out.push((scheme, params));
    }
}

/// The parameters (or the token68) of one challenge, up to the `,` before
/// the next challenge or the end.
fn params_of(c: &mut Cursor<'_>, params: &mut Vec<(String, String)>) -> Result<(), String> {
    loop {
        let start = c.pos;
        let name = c.take_while(tchar);
        c.skip_ows();
        if name.is_empty() || c.peek() != Some(b'=') {
            c.pos = start;
            if !params.is_empty() {
                return Err("WWW-Authenticate is malformed".into());
            }
            return token68(c, params);
        }
        c.pos += 1;
        c.skip_ows();
        let quoted = c.peek() == Some(b'"');
        let value = if quoted {
            c.quoted()?
        } else {
            c.take_while(tchar)
        };
        if value.is_empty() && !quoted {
            if params.is_empty() {
                c.pos = start;
                return token68(c, params);
            }
            return Err("an auth-param without a value".into());
        }
        let name = name.to_ascii_lowercase();
        if params.iter().any(|(n, _)| *n == name) {
            return Err(format!("the auth-param {name:?} appears twice"));
        }
        params.push((name, value));
        c.skip_ows();
        if c.peek() != Some(b',') {
            return Ok(());
        }
        if !c.param_follows() {
            return Ok(());
        }
        c.pos += 1;
        c.skip_ows();
    }
}

/// A token68: its characters, then any number of `=`, then the end of the
/// challenge.
fn token68(c: &mut Cursor<'_>, params: &mut Vec<(String, String)>) -> Result<(), String> {
    let mut value = c.take_while(token68_char);
    if value.is_empty() {
        return Err("WWW-Authenticate is malformed".into());
    }
    value.push_str(&c.take_while(|b| b == b'='));
    c.skip_ows();
    params.push((String::new(), value));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bearer, challenges, token};

    fn json() -> boneli_json::Limits {
        boneli_json::Limits::new(65_536, 16, 65_536).expect("limits")
    }

    #[test]
    fn several_challenges_in_one_field() {
        let parsed = challenges(
            br#"Basic realm="a, b", Bearer realm="https://auth.example/token",service="reg",scope="repository:x:pull", Negotiate abc==, Other"#,
        )
        .expect("parsed");
        let schemes: Vec<&str> = parsed.iter().map(|(s, _)| s.as_str()).collect();
        assert_eq!(schemes, ["Basic", "Bearer", "Negotiate", "Other"]);
        assert_eq!(parsed[0].1, [("realm".to_owned(), "a, b".to_owned())]);
        assert_eq!(parsed[1].1.len(), 3);
        assert_eq!(parsed[2].1, [(String::new(), "abc==".to_owned())]);
    }

    #[test]
    fn malformed_challenges_refused() {
        for bad in [
            &br#"Bearer realm="unterminated"#[..],
            br#"Bearer realm="a", realm="b""#,
            br#"Bearer realm="a" junk"#,
            br#"Bearer realm="a\"#,
            "Bearer realm=\"\u{e9}\"".as_bytes(),
            br#"Bearer realm="https://a.example/", x="#,
            b"=x",
        ] {
            assert!(challenges(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn bearer_needs_one_challenge_with_a_realm() {
        let one = [&br#"Bearer realm="https://a.example/t""#[..]];
        assert!(bearer(one.into_iter()).is_ok());
        let two = [
            &br#"Bearer realm="https://a.example/t""#[..],
            br#"Bearer realm="https://b.example/t""#,
        ];
        assert!(bearer(two.into_iter()).is_err());
        assert!(bearer([&b"Bearer service=x"[..]].into_iter()).is_err());
        assert!(bearer([&b"Bearer abc="[..]].into_iter()).is_err());
    }

    #[test]
    fn token_forms() {
        let limits = json();
        assert_eq!(token(br#"{"token":"t1"}"#, &limits).expect("token"), "t1");
        assert_eq!(
            token(br#"{"access_token":"t2"}"#, &limits).expect("access"),
            "t2"
        );
        assert_eq!(
            token(br#"{"access_token":"t2","token":"t1"}"#, &limits).expect("both"),
            "t1"
        );
        for bad in [
            &br#"{"token":""}"#[..],
            br#"{"token":" "}"#,
            br#"{"token":"a\r\nX: y"}"#,
            br#"{"token":"a b"}"#,
            br#"{"token":1}"#,
            br#"{"token":"","access_token":"t2"}"#,
            br#"{}"#,
            br#"[]"#,
        ] {
            assert!(
                token(bad, &limits).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
