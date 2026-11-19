//! The App's JWT (ADR-014, D4): RS256 over a fixed header and three
//! claims, signed once per token exchange and never cached or stored.

use boneli_https::{KeyError, RsaSha256Key};

use crate::base64;
use crate::config::ClientId;

/// The JWT header, byte for byte.
pub const HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

/// How far `iat` is back-dated: a runner clock up to 60 s ahead of
/// GitHub's still gives an `iat` that is not in the future (ADR-014, D4).
pub const BACKDATE: u64 = 60;

/// How far `exp` is ahead of now: 540 + 60 = 600 s, GitHub's documented
/// maximum lifetime of an App JWT, so a clock up to 540 s behind still
/// gives an `exp` that has not passed (ADR-014, D4).
pub const LIFETIME: u64 = 540;

/// The claims for `now`: `{"iat":now-60,"exp":now+540,"iss":"<client id>"}`,
/// or `None` when `now` is before the 60th second of 1970 or so close to
/// `u64::MAX` that `exp` overflows.
pub fn claims(client_id: &ClientId, now: u64) -> Option<String> {
    let iat = now.checked_sub(BACKDATE)?;
    let exp = now.checked_add(LIFETIME)?;
    // The client id is [A-Za-z0-9._-] (ClientId), so it needs no escaping.
    Some(format!(
        r#"{{"iat":{iat},"exp":{exp},"iss":"{}"}}"#,
        client_id.as_str()
    ))
}

/// Why no JWT was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwtError {
    /// The clock reading cannot carry the claims.
    Clock,
    /// Signing failed.
    Sign(KeyError),
}

/// The signed JWT for `now`: `b64url(header).b64url(claims).b64url(sig)`.
pub fn app_jwt(key: &RsaSha256Key, client_id: &ClientId, now: u64) -> Result<String, JwtError> {
    let claims = claims(client_id, now).ok_or(JwtError::Clock)?;
    let mut jwt = base64::url_safe(HEADER.as_bytes());
    jwt.push('.');
    jwt.push_str(&base64::url_safe(claims.as_bytes()));
    let signature = key.sign(jwt.as_bytes()).map_err(JwtError::Sign)?;
    jwt.push('.');
    jwt.push_str(&base64::url_safe(&signature));
    Ok(jwt)
}
