//! Installation tokens (ADR-014, D5): the App's JWT exchanged for a token
//! scoped to one repository and three permissions, checked, cached and
//! refreshed.

use std::fmt;
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use boneli_app::RepoUrl;
use boneli_https::{Dial, RsaSha256Key};
use boneli_json::{Object, Value};

use crate::api::{Endpoint, Failure, Http, Limits, Reply};
use crate::base64;
use crate::config::{ClientId, GitHubRepository};
use crate::jwt::{JwtError, app_jwt};
use crate::key::{KeyFileError, load_key};
use crate::time::{WallClock, format_rfc3339, parse_rfc3339};

/// The longest installation token, in bytes: 100 times the 40 characters
/// of today's format, and the bound behind the git `Authorization` cap
/// (ADR-014, D3 and D5).
pub const MAX_TOKEN: usize = 4_096;

/// A token is reused while more than this many seconds of it remain: the
/// 60 s clock skew bound plus the 300 s stall bound of a git transfer
/// (`http.lowSpeedTime`), which can separate the first and the last
/// authenticated request of one git process, rounded up (ADR-014, D5).
pub const MARGIN: u64 = 600;

/// The longest lifetime the cache believes, GitHub's documented hour: an
/// `expires_at` further out cannot extend the cache (ADR-014, D5).
pub const MAX_LIFETIME: u64 = 3_600;

/// The permissions every token is requested with, and must be granted
/// with exactly (plus `metadata: read`, which GitHub always adds).
pub const PERMISSIONS: [(&str, &str); 3] = [
    ("contents", "write"),
    ("issues", "write"),
    ("pull_requests", "write"),
];

/// How many recent tokens and JWTs the redaction pass knows.
const REMEMBERED_SECRETS: usize = 16;

/// Why a token value is unusable, or `None`: 1 to [`MAX_TOKEN`] bytes of
/// visible ASCII (`0x21`-`0x7E`). The reason never quotes the value.
pub fn token_problem(token: &str) -> Option<&'static str> {
    if token.is_empty() || token.len() > MAX_TOKEN {
        Some("the token is empty or longer than 4096 bytes")
    } else if !token.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        Some("the token holds a byte outside 0x21-0x7E")
    } else {
        None
    }
}

/// A GitHub App: its client id, the installation on the customer's
/// account and its private key.
pub struct App {
    client_id: ClientId,
    installation: NonZeroU64,
    key: RsaSha256Key,
}

impl App {
    /// An App with a key already loaded.
    pub fn new(client_id: ClientId, installation: NonZeroU64, key: RsaSha256Key) -> App {
        App {
            client_id,
            installation,
            key,
        }
    }

    /// An App whose key is read once from `key_file` under the rules of
    /// [`load_key`] (ADR-014, D6).
    pub fn open(
        client_id: ClientId,
        installation: NonZeroU64,
        key_file: &Path,
    ) -> Result<App, KeyFileError> {
        Ok(App::new(client_id, installation, load_key(key_file)?))
    }
}

impl fmt::Debug for App {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("App")
            .field("client_id", &self.client_id.as_str())
            .field("installation", &self.installation)
            .field("key", &self.key)
            .finish()
    }
}

/// An installation token. `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(Arc<str>);

impl Token {
    /// The secret itself, for an `Authorization` field. Never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token([redacted])")
    }
}

struct Cached {
    token: Token,
    minted_at: u64,
    expires: u64,
}

impl Cached {
    /// Reusable at `now`: the clock has not gone back since the mint, and
    /// more than [`MARGIN`] seconds remain.
    fn fresh_at(&self, now: u64) -> bool {
        now >= self.minted_at && now.checked_add(MARGIN).is_some_and(|m| self.expires > m)
    }
}

/// The token source of one installation and one repository (ADR-014, D5).
/// It is shared: concurrent callers wait for one exchange and reuse its
/// token.
pub struct InstallationTokens {
    app: App,
    repository: GitHubRepository,
    http: Http,
    clock: Arc<dyn WallClock>,
    cache: Mutex<Option<Cached>>,
    secrets: Mutex<Vec<String>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl InstallationTokens {
    /// The token source for `repository`, talking to GitHub through
    /// `dial` under `limits` ([`Limits::GITHUB`] in production) and reading
    /// the time from `clock`. Nothing is requested until a token is needed.
    pub fn open(
        app: App,
        repository: GitHubRepository,
        dial: Arc<dyn Dial + Send + Sync>,
        clock: Arc<dyn WallClock>,
        limits: Limits,
    ) -> InstallationTokens {
        InstallationTokens {
            app,
            repository,
            http: Http::new(dial, limits),
            clock,
            cache: Mutex::new(None),
            secrets: Mutex::new(Vec::new()),
        }
    }

    /// The repository every token is scoped to.
    pub fn repository(&self) -> &GitHubRepository {
        &self.repository
    }

    /// The repository's git URL, the only one the token is for.
    pub fn repository_url(&self) -> RepoUrl {
        self.repository.git_url()
    }

    /// A token with more than [`MARGIN`] seconds left: the cached one, or
    /// a new one.
    pub fn token(&self) -> Result<Token, Failure> {
        self.get(None)
    }

    /// A token after GitHub refused `rejected` with a `401`: the cache is
    /// dropped if it still holds `rejected`, so the next token is new.
    pub fn refresh(&self, rejected: &Token) -> Result<Token, Failure> {
        self.get(Some(rejected))
    }

    /// The `Authorization` value for git over HTTPS:
    /// `Basic base64("x-access-token:" + token)`. The error never holds a
    /// secret.
    pub fn git_authorization(&self) -> Result<String, String> {
        let token = self.token().map_err(|f| f.to_string())?;
        let pair = format!("x-access-token:{}", token.expose());
        Ok(format!("Basic {}", base64::standard(pair.as_bytes())))
    }

    pub(crate) fn http(&self) -> &Http {
        &self.http
    }

    /// The recent tokens and JWTs, for the final redaction pass.
    pub(crate) fn secrets(&self) -> Vec<String> {
        lock(&self.secrets).clone()
    }

    fn remember(&self, secret: &str) {
        let mut secrets = lock(&self.secrets);
        if secrets.len() == REMEMBERED_SECRETS {
            secrets.remove(0);
        }
        secrets.push(secret.to_owned());
    }

    fn now(&self) -> Result<u64, Failure> {
        self.clock.unix_seconds().ok_or_else(|| {
            Failure::new(
                "the installation token",
                "the system clock reads before 1970",
            )
        })
    }

    fn get(&self, rejected: Option<&Token>) -> Result<Token, Failure> {
        let mut cache = lock(&self.cache);
        if let (Some(rejected), Some(cached)) = (rejected, cache.as_ref())
            && &cached.token == rejected
        {
            *cache = None;
        }
        let now = self.now()?;
        if let Some(cached) = cache.as_ref().filter(|c| c.fresh_at(now)) {
            return Ok(cached.token.clone());
        }
        *cache = None;
        let minted = self.exchange(now)?;
        let token = minted.token.clone();
        *cache = Some(minted);
        Ok(token)
    }

    /// One exchange: a JWT for `now`, the scoped request, and the checks
    /// of ADR-014, D5 on the answer.
    fn exchange(&self, now: u64) -> Result<Cached, Failure> {
        let endpoint = Endpoint::AccessToken {
            installation: self.app.installation.get(),
        };
        let what = endpoint.what();
        let jwt = app_jwt(&self.app.key, &self.app.client_id, now).map_err(|e| match e {
            JwtError::Clock => Failure::new(what, "the clock reading cannot carry a JWT"),
            JwtError::Sign(e) => Failure::new(what, format!("signing the JWT failed: {e}")),
        })?;
        self.remember(&jwt);
        let authorization = format!("Bearer {jwt}");
        let secrets = [authorization.clone()];
        let body = request_body(&self.repository);
        let reply = self
            .http
            .send(&endpoint, &self.repository, &authorization, Some(&body))?;
        if reply.status != endpoint.expected_status() {
            return Err(reply.failure(what, &self.http.limits, &secrets));
        }
        let unusable = |reason: String| {
            Failure::new(format!("{what}: GitHub's answer is unusable"), reason).redacted(&secrets)
        };
        let (token, expires_at) = self.check(&reply).map_err(unusable)?;
        self.remember(&token);
        let after = self.now()?;
        let expires = expires_at.min(now.saturating_add(MAX_LIFETIME));
        if after
            .checked_add(MARGIN)
            .is_none_or(|limit| expires <= limit)
        {
            return Err(unusable(format!(
                "the token expires at {}, not more than {MARGIN} s after now ({})",
                format_rfc3339(expires_at),
                format_rfc3339(after)
            ))
            .redacted(&[token]));
        }
        Ok(Cached {
            token: Token(token.into()),
            minted_at: now,
            expires,
        })
    }

    /// The token and its `expires_at`, once the answer grants exactly the
    /// requested permissions on exactly this repository.
    fn check(&self, reply: &Reply) -> Result<(String, u64), String> {
        let value = reply.json(&self.http.limits)?;
        let token = value
            .get("token")
            .and_then(Value::as_str)
            .ok_or("no token string")?;
        if let Some(problem) = token_problem(token) {
            return Err(problem.to_owned());
        }
        let expires_at = value
            .get("expires_at")
            .and_then(Value::as_str)
            .ok_or("no expires_at string")?;
        let expires_at = parse_rfc3339(expires_at).ok_or_else(|| {
            format!(
                "expires_at {:?} is not an RFC 3339 date-time",
                cut16(expires_at)
            )
        })?;
        let permissions = value
            .get("permissions")
            .and_then(Value::as_object)
            .ok_or("no permissions object")?;
        if !permissions_match(permissions) {
            return Err(format!(
                "the permissions {:?} are not exactly the requested {PERMISSIONS:?} (plus metadata: read)",
                permission_names(permissions)
            ));
        }
        if value.get("repository_selection").and_then(Value::as_str) != Some("selected") {
            return Err("repository_selection is not \"selected\"".to_owned());
        }
        let repositories = value
            .get("repositories")
            .and_then(Value::as_array)
            .ok_or("no repositories array")?;
        let ours = match repositories {
            [one] => one
                .get("full_name")
                .and_then(Value::as_str)
                .is_some_and(|name| self.repository.is(name)),
            _ => false,
        };
        if !ours {
            return Err(format!(
                "the token is not scoped to exactly {} ({} repositories)",
                self.repository.full_name(),
                repositories.len()
            ));
        }
        Ok((token.to_owned(), expires_at))
    }
}

/// At most 32 bytes of a value GitHub sent, for a failure detail.
fn cut16(text: &str) -> &str {
    crate::api::cut(text, 32)
}

fn permission_names(permissions: &Object) -> Vec<String> {
    permissions
        .iter()
        .map(|(k, v)| {
            format!(
                "{}: {}",
                crate::api::cut(k, 32),
                crate::api::cut(v.as_str().unwrap_or("?"), 16)
            )
        })
        .take(16)
        .collect()
}

/// Exactly [`PERMISSIONS`], plus optionally `metadata: read`.
fn permissions_match(permissions: &Object) -> bool {
    let granted =
        |key: &str, level: &str| permissions.get(key).and_then(Value::as_str) == Some(level);
    PERMISSIONS.iter().all(|(k, v)| granted(k, v))
        && permissions.iter().all(|(key, level)| {
            PERMISSIONS.iter().any(|(k, _)| *k == key)
                || (key == "metadata" && level.as_str() == Some("read"))
        })
}

/// `{"repositories":["<name>"],"permissions":{"contents":"write","issues":"write","pull_requests":"write"}}`.
pub(crate) fn request_body(repository: &GitHubRepository) -> Vec<u8> {
    let mut permissions = Object::new();
    for (key, level) in PERMISSIONS {
        permissions.insert(key, Value::String(level.to_owned()));
    }
    let mut body = Object::new();
    body.insert(
        "repositories",
        Value::Array(vec![Value::String(repository.name().to_owned())]),
    );
    body.insert("permissions", Value::Object(permissions));
    // A value built here from checked parts always serializes.
    boneli_json::to_vec(&Value::Object(body)).unwrap_or_default()
}

impl fmt::Debug for InstallationTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstallationTokens")
            .field("app", &self.app)
            .field("repository", &self.repository)
            .field(
                "cached",
                &match self.cache.try_lock().as_deref() {
                    Ok(Some(_)) => "Some([redacted])",
                    Ok(None) => "None",
                    Err(_) => "(in use)",
                },
            )
            .finish()
    }
}
