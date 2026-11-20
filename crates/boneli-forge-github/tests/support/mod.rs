//! A fake GitHub for the forge tests: a `Dial` that answers each
//! connection on its own thread over `UnixStream::pair`, so the adapter's
//! HTTP framing and deadline wrapper are the real code. Every request is
//! recorded with its method, target, header fields and body. [`Hub`] is a
//! small GitHub (token exchange, repository, pull requests, comments) that
//! a test can override per request; [`FakeGit`] is a `Git` double.
#![allow(dead_code)]

use std::fs;
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use boneli_app::{
    Attached, BranchName, CheckoutId, CommitInfo, Git, GitError, PullRequest, RelativePath, RepoUrl,
};
use boneli_domain::{
    CheckStatus, Citation, CommitSha, EvidenceRef, FixChecks, RunId, TestStatus, Ticket,
    TicketSource, Usage,
};
use boneli_forge_github::{
    App, ClientId, ForgeConfig, GitHubForge, GitHubRepository, InstallationTokens, Limits,
    WallClock,
};
use boneli_http::{Headers, RequestHead, ResponseHead, Target};
use boneli_https::{Dial, RsaSha256Key, Stream};

/// The test key's PEM.
pub const KEY_PEM: &[u8] = include_bytes!("../data/test-only-rsa-2048.key");

/// The clock every test starts at.
pub const T0: u64 = 1_700_000_000;

/// The repository the tests use.
pub const REPO: &str = "octo-org/demo.repo";

/// The installation the tests use.
pub const INSTALLATION: u64 = 4242;

/// The client id the tests use.
pub const CLIENT_ID: &str = "Iv23liTestOnly0000";

/// The GitHub ticket key of the sample request: issue 7 of [`REPO`].
pub const KEY: &str = "octo-org/demo.repo#7";

/// The base commit of the sample request.
pub const BASE: &str = "0123456789abcdef0123456789abcdef01234567";

/// The test key.
pub fn key() -> RsaSha256Key {
    let mut pem = KEY_PEM.to_vec();
    RsaSha256Key::from_pem(&mut pem).expect("the test key loads")
}

/// The test key's base64 lines, joined, for the "no key material" checks.
pub fn key_base64() -> String {
    std::str::from_utf8(KEY_PEM)
        .expect("PEM is ASCII")
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect()
}

pub fn repository() -> GitHubRepository {
    GitHubRepository::parse(REPO).expect("a valid repository")
}

/// A clock a test sets.
#[derive(Debug)]
pub struct FakeClock(pub AtomicU64);

impl FakeClock {
    pub fn at(now: u64) -> Arc<FakeClock> {
        Arc::new(FakeClock(AtomicU64::new(now)))
    }

    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl WallClock for FakeClock {
    fn unix_seconds(&self) -> Option<u64> {
        Some(self.get())
    }
}

/// One request as the fake saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    /// The first value of `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The bearer credential.
    pub fn bearer(&self) -> Option<&str> {
        self.header("authorization")?.strip_prefix("Bearer ")
    }

    pub fn is_token_exchange(&self) -> bool {
        self.target == format!("/app/installations/{INSTALLATION}/access_tokens")
    }

    pub fn body_json(&self) -> boneli_json::Value {
        let limits = boneli_json::Limits::new(1 << 20, 64, 1 << 16).expect("limits");
        boneli_json::parse(&self.body, &limits).expect("a JSON request body")
    }
}

/// How the fake answers.
pub enum Reply {
    /// A response encoded by `boneli_http`, with `Content-Length`.
    Http {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// These bytes, as they are.
    Raw(Vec<u8>),
    /// Nothing, until the client gives up.
    Stall,
}

impl Reply {
    pub fn http(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        Reply::Http {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.to_vec(),
        }
    }

    pub fn json(status: u16, body: &str) -> Reply {
        Reply::http(
            status,
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        )
    }

    pub fn status(status: u16) -> Reply {
        Reply::http(status, &[], b"")
    }
}

type Handler = dyn Fn(&Seen) -> Reply + Send + Sync;

/// The fake: a handler and the log of what it saw.
#[derive(Clone)]
pub struct Fake {
    handler: Arc<Handler>,
    log: Arc<Mutex<Vec<Seen>>>,
}

impl Fake {
    pub fn new(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Fake {
        Fake {
            handler: Arc::new(handler),
            log: Arc::default(),
        }
    }

    /// Every request seen so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.log.lock().expect("log").clone()
    }

    /// How many token exchanges were requested.
    pub fn exchanges(&self) -> usize {
        self.seen().iter().filter(|s| s.is_token_exchange()).count()
    }

    /// The requests that were not token exchanges.
    pub fn api_calls(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|s| !s.is_token_exchange())
            .collect()
    }
}

impl Dial for Fake {
    fn dial(&self, host: &str, port: u16, _deadline: Instant) -> io::Result<Box<dyn Stream>> {
        let (client, server) = UnixStream::pair()?;
        let handler = Arc::clone(&self.handler);
        let log = Arc::clone(&self.log);
        let host = host.to_owned();
        thread::spawn(move || serve(server, host, port, &*handler, &log));
        Ok(Box::new(client))
    }
}

fn serve(
    mut stream: UnixStream,
    host: String,
    port: u16,
    handler: &Handler,
    log: &Mutex<Vec<Seen>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) if bytes.len() < 1 << 16 => bytes.push(byte[0]),
            _ => return,
        }
    }
    let limits = boneli_http::Limits::new(1 << 16, 256, 1 << 24).expect("limits");
    let head = RequestHead::parse(&bytes, &limits).expect("the client sent a valid head");
    let Target::Origin(target) = head.target.clone() else {
        panic!("the client sent a non-origin target");
    };
    let length: usize = head
        .headers
        .get("content-length")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    if stream.read_exact(&mut body).is_err() {
        return;
    }
    let seen = Seen {
        host,
        port,
        method: head.method.as_str().to_owned(),
        target,
        headers: head
            .headers
            .iter()
            .map(|(n, v)| (n.to_owned(), String::from_utf8_lossy(v).into_owned()))
            .collect(),
        body,
    };
    log.lock().expect("log").push(seen.clone());
    match handler(&seen) {
        Reply::Http {
            status,
            headers,
            body,
        } => {
            let mut response = ResponseHead::new(status);
            let mut fields = Headers::new();
            for (n, v) in headers {
                fields.append(n, v);
            }
            fields.append("Content-Length", body.len().to_string());
            response.headers = fields;
            let mut out = response.encode().expect("encode");
            out.extend_from_slice(&body);
            let _ = stream.write_all(&out);
        }
        Reply::Raw(bytes) => {
            let _ = stream.write_all(&bytes);
        }
        Reply::Stall => {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
            let _ = stream.read(&mut byte);
        }
    }
}

/// The token the hub issues on its `n`th exchange (from 1).
pub fn hub_token(n: usize) -> String {
    format!("ghs_TestOnlyToken{n:04}xxxxxxxxxxxxxxxxxxxx")
}

/// A token exchange answer with `token` expiring at `expires_at`, the
/// requested permissions and this repository.
pub fn token_answer(token: &str, expires_at: &str) -> String {
    format!(
        r#"{{"token":"{token}","expires_at":"{expires_at}","permissions":{{"contents":"write","issues":"write","metadata":"read","pull_requests":"write"}},"repository_selection":"selected","repositories":[{{"id":1,"name":"demo.repo","full_name":"octo-org/demo.repo"}}]}}"#
    )
}

/// A small GitHub: tokens that expire an hour after the clock, the
/// repository with default branch `main`, pull requests numbered from 1,
/// comments with ids from 9001, and a lookup that finds what was created
/// for a head branch.
pub struct Hub {
    clock: Arc<FakeClock>,
    exchanges: AtomicU32,
    pulls: Mutex<Vec<String>>,
    comments: AtomicU64,
}

impl Hub {
    pub fn new(clock: Arc<FakeClock>) -> Arc<Hub> {
        Arc::new(Hub {
            clock,
            exchanges: AtomicU32::new(0),
            pulls: Mutex::new(Vec::new()),
            comments: AtomicU64::new(9_000),
        })
    }

    pub fn handle(&self, seen: &Seen) -> Reply {
        if seen.is_token_exchange() {
            let n = self.exchanges.fetch_add(1, Ordering::SeqCst) as usize + 1;
            let expires = boneli_forge_github::time::format_rfc3339(self.clock.get() + 3_600);
            return Reply::json(201, &token_answer(&hub_token(n), &expires));
        }
        let repo = format!("/repos/{REPO}");
        if seen.target == repo && seen.method == "GET" {
            return Reply::json(
                200,
                r#"{"id":1,"full_name":"octo-org/demo.repo","default_branch":"main"}"#,
            );
        }
        if seen.target == format!("{repo}/pulls") && seen.method == "POST" {
            let head = seen.body_json();
            let branch = head
                .get("head")
                .and_then(boneli_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let mut pulls = self.pulls.lock().expect("pulls");
            pulls.push(branch);
            return Reply::json(201, &format!(r#"{{"id":77,"number":{}}}"#, pulls.len()));
        }
        if let Some(query) = seen
            .target
            .strip_prefix(&format!("{repo}/pulls?head=octo-org:"))
        {
            let branch = query.split('&').next().unwrap_or_default();
            let pulls = self.pulls.lock().expect("pulls");
            let found: Vec<String> = pulls
                .iter()
                .enumerate()
                .filter(|(_, b)| b.as_str() == branch)
                .map(|(k, _)| format!(r#"{{"number":{}}}"#, k + 1))
                .collect();
            return Reply::json(200, &format!("[{}]", found.join(",")));
        }
        if seen.target.starts_with(&format!("{repo}/issues/")) && seen.method == "POST" {
            let id = self.comments.fetch_add(1, Ordering::SeqCst) + 1;
            return Reply::json(201, &format!(r#"{{"id":{id}}}"#));
        }
        Reply::status(404)
    }

    /// A fake that answers with `override_` first and the hub otherwise.
    pub fn fake(
        self: &Arc<Hub>,
        override_: impl Fn(&Seen) -> Option<Reply> + Send + Sync + 'static,
    ) -> Fake {
        let hub = Arc::clone(self);
        Fake::new(move |seen| override_(seen).unwrap_or_else(|| hub.handle(seen)))
    }
}

/// The token source over `fake` at `clock`, with `limits`.
pub fn tokens_with(fake: &Fake, clock: &Arc<FakeClock>, limits: Limits) -> Arc<InstallationTokens> {
    let app = App::new(
        ClientId::parse(CLIENT_ID).expect("client id"),
        NonZeroU64::new(INSTALLATION).expect("non-zero"),
        key(),
    );
    Arc::new(InstallationTokens::open(
        app,
        repository(),
        Arc::new(fake.clone()),
        clock.clone(),
        limits,
    ))
}

pub fn tokens(fake: &Fake, clock: &Arc<FakeClock>) -> Arc<InstallationTokens> {
    tokens_with(fake, clock, Limits::GITHUB)
}

pub fn config() -> ForgeConfig {
    ForgeConfig {
        commit_name: "boneli-test[bot]".to_owned(),
        commit_email: "1+boneli-test[bot]@users.noreply.github.com".to_owned(),
        base_branch: None,
    }
}

pub fn forge(tokens: Arc<InstallationTokens>, git: Arc<FakeGit>) -> GitHubForge {
    GitHubForge::new(tokens, git, config()).expect("a valid forge config")
}

/// A `Git` double: every call succeeds, and `push` records the branch
/// and commit and refuses a branch it saw before.
#[derive(Default)]
pub struct FakeGit {
    pub calls: Mutex<Vec<String>>,
    pub pushed: Mutex<Vec<(BranchName, CommitInfo)>>,
}

impl FakeGit {
    pub fn branches(&self) -> Vec<String> {
        self.pushed
            .lock()
            .expect("pushed")
            .iter()
            .map(|(b, _)| b.as_str().to_owned())
            .collect()
    }
}

impl Git for FakeGit {
    fn fetch_base(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError> {
        self.calls.lock().expect("calls").push(format!(
            "fetch_base {} {}",
            repo.as_str(),
            base.as_str()
        ));
        Ok(CheckoutId::new("base".to_owned()))
    }

    fn read(&self, _: &CheckoutId, _: &RelativePath) -> Result<Option<Vec<u8>>, GitError> {
        Ok(None)
    }

    fn snapshot(&self, _: &CheckoutId) -> Result<Vec<u8>, GitError> {
        Ok(Vec::new())
    }

    fn diff(&self, _: &CheckoutId, _: &[u8]) -> Result<Vec<u8>, GitError> {
        Ok(Vec::new())
    }

    fn apply(&self, checkout: &CheckoutId, diff: &[u8]) -> Result<CheckoutId, GitError> {
        self.calls.lock().expect("calls").push(format!(
            "apply {} {}",
            checkout.as_str(),
            String::from_utf8_lossy(diff)
        ));
        Ok(CheckoutId::new("applied".to_owned()))
    }

    /// Never called: the forge pushes, it does not judge patches.
    fn patch_between(
        &self,
        _: &CheckoutId,
        _: &CheckoutId,
    ) -> Result<Result<boneli_domain::Patch, boneli_domain::UnreadablePath>, GitError> {
        Err(GitError::Failed {
            detail: "the fake git judges no patches".to_owned(),
        })
    }

    fn push(
        &self,
        checkout: &CheckoutId,
        branch: &BranchName,
        commit: &CommitInfo,
    ) -> Result<CommitSha, GitError> {
        self.calls.lock().expect("calls").push(format!(
            "push {} {}",
            checkout.as_str(),
            branch.as_str()
        ));
        let mut pushed = self.pushed.lock().expect("pushed");
        if pushed.iter().any(|(b, _)| b == branch) {
            return Err(GitError::BranchExists);
        }
        pushed.push((branch.clone(), commit.clone()));
        Ok(CommitSha::parse("fedcba9876543210fedcba9876543210fedcba98").expect("sha"))
    }
}

pub fn ticket(key: &str) -> Ticket {
    Ticket {
        source: TicketSource::GitHub,
        key: key.to_owned(),
        title: "Crash on empty input".to_owned(),
        body: String::new(),
    }
}

fn attached(reference: &str, content: &[u8]) -> Attached {
    Attached {
        reference: EvidenceRef::parse(reference).expect("evidence ref"),
        content: content.to_vec(),
    }
}

/// A pull-request request for GitHub issue 7, with two citations.
pub fn request() -> PullRequest {
    let base = CommitSha::parse(BASE).expect("sha");
    PullRequest {
        run: RunId::new("run-1".to_owned()),
        ticket: ticket(KEY),
        base: base.clone(),
        diff: attached("sha256-diff", b"the diff"),
        test: attached("sha256-test", b"#[test]\nfn empty() { parse(\"\"); }\n"),
        analysis: attached(
            "sha256-analysis",
            b"The parser indexes [0] of an empty slice.",
        ),
        citations: vec![
            Citation {
                path: "src/parse.rs".to_owned(),
                line: 12,
                sha: base.clone(),
                quote: "let first = input[0];".to_owned(),
            },
            Citation {
                path: "src/lib.rs".to_owned(),
                line: 3,
                sha: base,
                quote: "pub mod parse;".to_owned(),
            },
        ],
        checks: FixChecks {
            reproduction_test: TestStatus::Passed,
            reproduction_test_unchanged: CheckStatus::Passed,
            previously_green_tests: CheckStatus::Passed,
            lint: CheckStatus::NotConfigured,
            typecheck: CheckStatus::Passed,
        },
        spent: Usage {
            cost_micro_usd: 1_234_567,
            duration_ms: 3_723_456,
        },
        overrun: None,
    }
}

/// A private directory under cargo's test temp dir, removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("forge-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create the test's temp dir");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod");
        TempDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Writes the test key to `dir/name` with `mode`.
pub fn key_file(dir: &Path, name: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, KEY_PEM).expect("write the key file");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod the key file");
    path
}
