//! The REST client (ADR-014, D7, D9 and D10): a closed set of endpoints,
//! one connection per request to `api.github.com:443` through the `Dial`
//! seam, response limits, and the mapping of answers to failures.
//!
//! Nothing here retries or follows a redirect; the token cache retries a
//! `401` once ([`crate::InstallationTokens`]) and the forge looks up an
//! ambiguous pull-request creation once ([`crate::GitHubForge`]).

use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boneli_app::{BranchName, JobFailure};
use boneli_http::{Connection, Method, RequestBody, RequestHead, ResponseHead, Target};
use boneli_https::{Dial, Timed};
use boneli_json::Value;

use crate::config::GitHubRepository;
use crate::time::format_rfc3339;

/// The API host. Only github.com is supported (ADR-014, D11).
pub const API_HOST: &str = "api.github.com";

/// The API port.
pub const API_PORT: u16 = 443;

/// The REST API version every request names.
pub const API_VERSION: &str = "2022-11-28";

/// The media type every request accepts.
pub const ACCEPT: &str = "application/vnd.github+json";

/// The `User-Agent` every request sends; GitHub refuses requests without
/// one.
pub const USER_AGENT: &str = "boneli-forge-github";

/// The longest GitHub `message` a failure quotes, in bytes. The longest
/// common message, the secondary rate limit's, is about 170 characters
/// (ADR-014, D9).
pub const MAX_MESSAGE: usize = 256;

/// Every request the adapter can make (ADR-014, D7). GET or POST only:
/// there is no merge, `PATCH`, `PUT` or `DELETE`, so the adapter cannot
/// merge, edit or delete anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// `POST /app/installations/{id}/access_tokens`, with the App's JWT.
    AccessToken {
        /// The installation.
        installation: u64,
    },
    /// `GET /repos/{owner}/{name}`, for `default_branch`.
    Repository,
    /// `POST /repos/{owner}/{name}/pulls`.
    CreatePull,
    /// `GET /repos/{owner}/{name}/pulls?head={owner}:{branch}&state=all&per_page=2`.
    PullsByHead {
        /// The head branch.
        branch: BranchName,
    },
    /// `POST /repos/{owner}/{name}/issues/{number}/comments`.
    IssueComment {
        /// The issue.
        issue: u64,
    },
}

impl Endpoint {
    /// `GET` or `POST`.
    pub fn method(&self) -> &'static str {
        match self {
            Endpoint::Repository | Endpoint::PullsByHead { .. } => "GET",
            Endpoint::AccessToken { .. } | Endpoint::CreatePull | Endpoint::IssueComment { .. } => {
                "POST"
            }
        }
    }

    /// The origin-form target for `repository`. Every value in it comes
    /// from a checked type ([`GitHubRepository`], [`BranchName`], a
    /// number), whose characters need no percent-encoding.
    pub fn target(&self, repository: &GitHubRepository) -> String {
        let repo = format!("/repos/{}/{}", repository.owner(), repository.name());
        match self {
            Endpoint::AccessToken { installation } => {
                format!("/app/installations/{installation}/access_tokens")
            }
            Endpoint::Repository => repo,
            Endpoint::CreatePull => format!("{repo}/pulls"),
            Endpoint::PullsByHead { branch } => format!(
                "{repo}/pulls?head={}:{}&state=all&per_page=2",
                repository.owner(),
                branch.as_str()
            ),
            Endpoint::IssueComment { issue } => format!("{repo}/issues/{issue}/comments"),
        }
    }

    /// What the request is for, as failures name it.
    pub fn what(&self) -> &'static str {
        match self {
            Endpoint::AccessToken { .. } => "the installation token",
            Endpoint::Repository => "the repository",
            Endpoint::CreatePull => "the pull request",
            Endpoint::PullsByHead { .. } => "the pull-request lookup",
            Endpoint::IssueComment { .. } => "the comment",
        }
    }

    /// The status a success has: `201` for a creation, `200` for a read.
    pub fn expected_status(&self) -> u16 {
        match self.method() {
            "POST" => 201,
            _ => 200,
        }
    }
}

/// The limits of the client (ADR-014, D10). Every limit is inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    body_bytes: usize,
    depth: usize,
    values: usize,
    head_bytes: usize,
    head_fields: usize,
    deadline: Duration,
}

impl Limits {
    /// The limits of ADR-014, D10, from the sizes measured on GitHub's
    /// REST objects: a body of 1,048,576 bytes (two pull requests whose
    /// 65,536-byte bodies GitHub echoes HTML-escaped, 6 bytes per `<`),
    /// depth 16, 4,096 values, a head of 16,384 bytes and 64 fields, and a
    /// 30 s deadline per request (GitHub's 10 s processing cap, plus
    /// connect, TLS and transfer).
    pub const GITHUB: Limits = Limits {
        body_bytes: 1_048_576,
        depth: 16,
        values: 4_096,
        head_bytes: 16_384,
        head_fields: 64,
        deadline: Duration::from_secs(30),
    };

    /// Other limits, for tests; `None` when one is zero or the depth is
    /// above [`boneli_json::MAX_DEPTH`].
    pub fn new(
        body_bytes: usize,
        depth: usize,
        values: usize,
        head_bytes: usize,
        head_fields: usize,
        deadline: Duration,
    ) -> Option<Limits> {
        let ok = body_bytes > 0
            && (1..=boneli_json::MAX_DEPTH).contains(&depth)
            && values > 0
            && head_bytes > 0
            && head_fields > 0
            && !deadline.is_zero();
        ok.then_some(Limits {
            body_bytes,
            depth,
            values,
            head_bytes,
            head_fields,
            deadline,
        })
    }

    /// These limits with another deadline per request; a zero deadline
    /// keeps the old one.
    pub fn with_deadline(self, deadline: Duration) -> Limits {
        if deadline.is_zero() {
            return self;
        }
        Limits { deadline, ..self }
    }

    /// The deadline of one request.
    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    fn json(&self) -> Option<boneli_json::Limits> {
        boneli_json::Limits::new(self.body_bytes, self.depth, self.values).ok()
    }
}

/// Why a GitHub operation failed: the status, and the error output (a
/// quoted GitHub `message`, or a transport error). It becomes a
/// [`JobFailure`] with cost 0 (ADR-014, D9). Neither part ever holds a
/// response body, a request header, a token, a JWT or key bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Failure {
    status: String,
    output: String,
}

impl Failure {
    pub(crate) fn new(status: impl Into<String>, output: impl Into<String>) -> Failure {
        Failure {
            status: status.into(),
            output: output.into(),
        }
    }

    /// The status, for example
    /// `the pull request: GitHub answered 422 (request AB12:CD34)`.
    pub fn status(&self) -> &str {
        &self.status
    }

    /// The error output; may be empty.
    pub fn output(&self) -> &str {
        &self.output
    }

    /// The failure as the port reports it: no cost.
    pub fn to_job_failure(&self) -> JobFailure {
        JobFailure::new(&self.output, &self.status, 0)
    }

    /// Both parts with every secret in `secrets` replaced (the final pass
    /// of ADR-014, D9).
    pub(crate) fn redacted(self, secrets: &[String]) -> Failure {
        Failure {
            status: redact(&self.status, secrets),
            output: redact(&self.output, secrets),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_job_failure().detail())
    }
}

impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failure({:?})", self.to_string())
    }
}

/// `text` with each secret, and the part of it after its first space (the
/// credential of `Bearer <credential>`), replaced by `[redacted]`.
pub(crate) fn redact(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_owned();
    for secret in secrets {
        let mut parts = vec![secret.as_str()];
        if let Some((_, rest)) = secret.split_once(' ') {
            parts.push(rest);
        }
        for part in parts {
            if !part.is_empty() {
                out = out.replace(part, "[redacted]");
            }
        }
    }
    out
}

/// One answer: its status, the fields the adapter reads and the body.
pub(crate) struct Reply {
    pub(crate) status: u16,
    request_id: Option<String>,
    rate_limited: bool,
    retry_after: Option<u64>,
    reset: Option<u64>,
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// The body as JSON within the limits.
    pub(crate) fn json(&self, limits: &Limits) -> Result<Value, String> {
        let json = limits
            .json()
            .ok_or_else(|| "the JSON limits are invalid".to_owned())?;
        boneli_json::parse(&self.body, &json)
            .map_err(|e| format!("the answer is not JSON within the limits: {e}"))
    }

    /// The failure for this answer (ADR-014, D9): the status names what the
    /// request was for, GitHub's status and its request id; the output is
    /// GitHub's `message`, redacted, cut to [`MAX_MESSAGE`] bytes and
    /// quoted.
    pub(crate) fn failure(&self, what: &str, limits: &Limits, secrets: &[String]) -> Failure {
        let mut status = format!("{what}: GitHub answered {}", self.status);
        if let Some(id) = &self.request_id {
            status.push_str(&format!(" (request {id})"));
        }
        if (300..400).contains(&self.status) {
            status.push_str(", a redirect, which the adapter does not follow");
        }
        if self.rate_limited {
            match (self.retry_after, self.reset) {
                (Some(seconds), _) => {
                    status.push_str(&format!(", rate limited, retry after {seconds} s"))
                }
                (None, Some(reset)) => {
                    status.push_str(&format!(", rate limited until {}", format_rfc3339(reset)))
                }
                (None, None) => status.push_str(", rate limited"),
            }
        }
        let message = self
            .json(limits)
            .ok()
            .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_owned))
            .map(|m| format!("{:?}", cut(&redact(&m, secrets), MAX_MESSAGE)))
            .unwrap_or_default();
        Failure::new(status, message).redacted(secrets)
    }
}

/// `text` cut to at most `max` bytes at a char boundary.
pub(crate) fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The value of a field that appears exactly once, as text.
fn single<'h>(head: &'h ResponseHead, name: &'h str) -> Option<&'h str> {
    let mut values = head.headers.get_all(name);
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    std::str::from_utf8(value).ok()
}

fn digits(text: Option<&str>, max_len: usize) -> Option<u64> {
    let text = text?;
    let ok = (1..=max_len).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_digit());
    if ok { text.parse().ok() } else { None }
}

/// A positive integer: a JSON number lexeme without fraction, exponent or
/// sign, from 1 to `u64::MAX`. `"42"`, `1.0`, `1e3`, `0` and `-1` are not.
pub(crate) fn positive(value: Option<&Value>) -> Option<u64> {
    value?.as_number()?.as_u64().filter(|n| *n > 0)
}

/// The client: the dial and the limits, shared by the token cache and the
/// forge.
#[derive(Clone)]
pub(crate) struct Http {
    dial: Arc<dyn Dial + Send + Sync>,
    pub(crate) limits: Limits,
}

impl Http {
    pub(crate) fn new(dial: Arc<dyn Dial + Send + Sync>, limits: Limits) -> Http {
        Http { dial, limits }
    }

    /// One request on a new connection. Any answer is `Ok`, whatever its
    /// status; `Err` is a request that got no complete answer within the
    /// limits and the deadline. `authorization` is the whole field value
    /// (`Bearer <jwt or token>`); every detail is redacted of it.
    pub(crate) fn send(
        &self,
        endpoint: &Endpoint,
        repository: &GitHubRepository,
        authorization: &str,
        body: Option<&[u8]>,
    ) -> Result<Reply, Failure> {
        let what = endpoint.what();
        let secrets = [authorization.to_owned()];
        let fail = |detail: String| {
            Failure::new(format!("{what}: the request to GitHub failed"), detail).redacted(&secrets)
        };
        let deadline = Instant::now() + self.limits.deadline;
        let http = boneli_http::Limits::new(
            self.limits.head_bytes,
            self.limits.head_fields,
            self.limits.body_bytes as u64,
        )
        .map_err(|e| fail(format!("HTTP limits: {e}")))?;
        let stream = self
            .dial
            .dial(API_HOST, API_PORT, deadline)
            .map_err(|e| fail(e.to_string()))?;
        let timed = Timed::new(stream, deadline, self.limits.deadline);
        let mut conn = Connection::new(timed, API_HOST, http).map_err(|e| fail(e.to_string()))?;
        let method = Method::new(endpoint.method()).map_err(|e| fail(e.to_string()))?;
        let mut head = RequestHead::new(method, Target::Origin(endpoint.target(repository)));
        head.headers.append("Accept", ACCEPT);
        head.headers.append("X-GitHub-Api-Version", API_VERSION);
        head.headers.append("User-Agent", USER_AGENT);
        head.headers.append("Authorization", authorization);
        let request_body = match body {
            Some(bytes) => {
                head.headers.append("Content-Type", "application/json");
                RequestBody::Bytes(bytes)
            }
            None => RequestBody::None,
        };
        let mut response = conn
            .request(&head, request_body)
            .map_err(|e| fail(e.to_string()))?;
        let answer = response.head.clone();
        let cap = self.limits.body_bytes as u64;
        let mut bytes = Vec::new();
        (&mut response)
            .take(cap + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| fail(boneli_http::Error::from(e).to_string()))?;
        if bytes.len() as u64 > cap {
            return Err(fail(format!(
                "GitHub answered {} with a body longer than {cap} bytes",
                answer.status
            )));
        }
        let request_id = single(&answer, "x-github-request-id")
            .filter(|id| {
                (1..=64).contains(&id.len())
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':')
            })
            .map(str::to_owned);
        let retry_after = digits(single(&answer, "retry-after"), 10);
        let remaining = single(&answer, "x-ratelimit-remaining");
        let reset = digits(single(&answer, "x-ratelimit-reset"), 20);
        let rate_limited = matches!(answer.status, 403 | 429)
            && (remaining == Some("0") || answer.headers.contains("retry-after"));
        Ok(Reply {
            status: answer.status,
            request_id,
            rate_limited,
            retry_after,
            reset,
            body: bytes,
        })
    }
}
