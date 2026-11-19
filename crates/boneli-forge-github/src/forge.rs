//! [`GitHubForge`]: the `Forge` port over GitHub (ADR-014, D1, D7 to D9).
//!
//! `open_pull_request` composes `fetch_base` → `apply` (the verified diff)
//! → `push` (a new `boneli/` branch) through the `Git` port, then creates
//! the pull request, ready for review. `post_questions` posts one comment
//! on the ticket's issue. Every failure costs nothing and is redacted of
//! every recent token and JWT before it leaves the adapter.

use std::fmt;
use std::sync::Arc;

use boneli_app::{BranchName, CommitInfo, Forge, ForgeRef, Git, GitError, JobFailure, PullRequest};
use boneli_domain::{RunId, Ticket, TicketSource};
use boneli_https::fill_random;
use boneli_json::{Object, Value};

use crate::api::{Endpoint, Failure, Reply, positive};
use crate::config::base_branch_problem;
use crate::render::{self, MAX_BODY, MAX_TITLE};
use crate::tokens::InstallationTokens;

/// The longest run slug in a branch name, in bytes (ADR-014, D2).
pub const MAX_SLUG: usize = 40;

/// The run id as a branch slug (ADR-014, D2): `[a-z0-9]` kept, `[A-Z]`
/// lowercased, every other byte `-`; runs of `-` collapsed and trimmed,
/// cut to [`MAX_SLUG`] bytes (and trimmed again), and `run` when nothing
/// is left.
pub fn run_slug(run: &str) -> String {
    let mut slug = String::new();
    for b in run.bytes() {
        let c = match b {
            b'a'..=b'z' | b'0'..=b'9' => char::from(b),
            b'A'..=b'Z' => char::from(b.to_ascii_lowercase()),
            _ => '-',
        };
        if !(c == '-' && (slug.is_empty() || slug.ends_with('-'))) {
            slug.push(c);
        }
    }
    slug.truncate(MAX_SLUG);
    let slug = slug.trim_end_matches('-');
    if slug.is_empty() {
        "run".to_owned()
    } else {
        slug.to_owned()
    }
}

/// `boneli/<run slug>-<nonce as 8 hex digits>`. Always a valid
/// [`BranchName`]: at most 7 + 40 + 1 + 8 = 56 bytes of `[a-z0-9-]` that
/// starts and ends with `[a-z0-9]`.
pub fn branch_name(run: &RunId, nonce: [u8; 4]) -> Option<BranchName> {
    let hex: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    BranchName::parse(&format!("boneli/{}-{hex}", run_slug(run.as_str())))
}

/// What the forge needs besides the token source and the `Git` port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForgeConfig {
    /// The pushed commit's author and committer name: the App's bot,
    /// `<app-slug>[bot]`.
    pub commit_name: String,
    /// Its email: `<bot user id>+<app-slug>[bot]@users.noreply.github.com`.
    pub commit_email: String,
    /// The branch pull requests target; `None` for the repository's
    /// default branch, read from GitHub on every pull request.
    pub base_branch: Option<String>,
}

/// Why [`GitHubForge::new`] refused its configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// The commit name or email breaks `CommitInfo`'s rules (ADR-014, D2).
    CommitIdentity,
    /// The base branch breaks [`base_branch_problem`]'s rules.
    BaseBranch(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::CommitIdentity => f.write_str(
                "the commit name or email is not one git accepts as an ident (ADR-014, D2)",
            ),
            ConfigError::BaseBranch(problem) => write!(f, "the base branch is refused: {problem}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The `Forge` port on one GitHub repository, as a GitHub App.
pub struct GitHubForge {
    tokens: Arc<InstallationTokens>,
    git: Arc<dyn Git + Send + Sync>,
    config: ForgeConfig,
}

impl GitHubForge {
    /// The forge for the repository of `tokens`, pushing through `git`.
    pub fn new(
        tokens: Arc<InstallationTokens>,
        git: Arc<dyn Git + Send + Sync>,
        config: ForgeConfig,
    ) -> Result<GitHubForge, ConfigError> {
        if CommitInfo::new(&config.commit_name, &config.commit_email, "check").is_none() {
            return Err(ConfigError::CommitIdentity);
        }
        if let Some(problem) = config.base_branch.as_deref().and_then(base_branch_problem) {
            return Err(ConfigError::BaseBranch(problem));
        }
        Ok(GitHubForge {
            tokens,
            git,
            config,
        })
    }

    /// A request with an installation token; a `401` drops the token and
    /// the request is sent once more with a new one (ADR-014, D5).
    fn call(&self, endpoint: &Endpoint, body: Option<&[u8]>) -> Result<Reply, Failure> {
        let http = self.tokens.http();
        let repository = self.tokens.repository();
        let token = self.tokens.token()?;
        let reply = http.send(
            endpoint,
            repository,
            &format!("Bearer {}", token.expose()),
            body,
        )?;
        if reply.status != 401 {
            return Ok(reply);
        }
        let token = self.tokens.refresh(&token)?;
        http.send(
            endpoint,
            repository,
            &format!("Bearer {}", token.expose()),
            body,
        )
    }

    fn failure(&self, reply: &Reply, endpoint: &Endpoint) -> Failure {
        reply.failure(
            endpoint.what(),
            &self.tokens.http().limits,
            &self.tokens.secrets(),
        )
    }

    /// The configured base branch, or the repository's `default_branch`.
    fn base_branch(&self) -> Result<String, Failure> {
        if let Some(branch) = &self.config.base_branch {
            return Ok(branch.clone());
        }
        let endpoint = Endpoint::Repository;
        let reply = self.call(&endpoint, None)?;
        if reply.status != endpoint.expected_status() {
            return Err(self.failure(&reply, &endpoint));
        }
        let unusable = |reason: String| {
            Failure::new(
                format!(
                    "{}: GitHub's answer {} is unusable",
                    endpoint.what(),
                    reply.status
                ),
                reason,
            )
        };
        let value = reply.json(&self.tokens.http().limits).map_err(unusable)?;
        let branch = value
            .get("default_branch")
            .and_then(Value::as_str)
            .ok_or_else(|| unusable("no default_branch string".to_owned()))?;
        if let Some(problem) = base_branch_problem(branch) {
            return Err(unusable(format!(
                "the default branch is refused: {problem}"
            )));
        }
        Ok(branch.to_owned())
    }

    fn open(&self, request: &PullRequest) -> Result<ForgeRef, Failure> {
        let what = Endpoint::CreatePull.what();
        let repository = self.tokens.repository();
        let title = render::title(&request.ticket.title);
        let body = render::pull_request_body(request, repository);
        if title.len() > MAX_TITLE || body.text.len() > MAX_BODY {
            return Err(Failure::new(
                what,
                "the rendered title or body is over its cap",
            ));
        }
        let message = render::commit_message(&request.ticket, &request.run);
        let commit = CommitInfo::new(
            &self.config.commit_name,
            &self.config.commit_email,
            &message,
        )
        .ok_or_else(|| Failure::new(what, "the commit message breaks CommitInfo's rules"))?;
        let base_branch = self.base_branch()?;
        let mut nonce = [0u8; 4];
        fill_random(&mut nonce).map_err(|e| Failure::new(what, e.to_string()))?;
        let branch = branch_name(&request.run, nonce)
            .ok_or_else(|| Failure::new(what, "the branch name is not a valid BranchName"))?;
        let git = |step: &str, e: GitError| {
            Failure::new(
                format!("pushing the fix branch: {step} failed"),
                e.to_string(),
            )
        };
        let checkout = self
            .git
            .fetch_base(&repository.git_url(), &request.base)
            .map_err(|e| git("fetch_base", e))?;
        let applied = self
            .git
            .apply(&checkout, &request.diff.content)
            .map_err(|e| git("apply", e))?;
        self.git
            .push(&applied, &branch, &commit)
            .map_err(|e| git("push", e))?;
        self.create(&title, &body.text, &branch, &base_branch)
    }

    /// Creates the pull request. An ambiguous answer (a 5xx, a network
    /// error or deadline, a 2xx that is not a usable 201) gets one lookup
    /// by the head branch, which is unique per call: exactly one pull
    /// request found is success (ADR-014, D9).
    fn create(
        &self,
        title: &str,
        body: &str,
        branch: &BranchName,
        base: &str,
    ) -> Result<ForgeRef, Failure> {
        let endpoint = Endpoint::CreatePull;
        let mut request = Object::new();
        request.insert("title", Value::String(title.to_owned()));
        request.insert("head", Value::String(branch.as_str().to_owned()));
        request.insert("base", Value::String(base.to_owned()));
        request.insert("body", Value::String(body.to_owned()));
        request.insert("draft", Value::Bool(false));
        let bytes = boneli_json::to_vec(&Value::Object(request))
            .map_err(|e| Failure::new(endpoint.what(), format!("the request: {e}")))?;
        let first = match self.call(&endpoint, Some(&bytes)) {
            Ok(reply) if reply.status == endpoint.expected_status() => {
                match reply
                    .json(&self.tokens.http().limits)
                    .ok()
                    .and_then(|v| positive(v.get("number")))
                {
                    Some(number) => return pull_ref(number),
                    None => Failure::new(
                        format!("{}: GitHub answered {}", endpoint.what(), reply.status),
                        "the answer holds no pull-request number",
                    ),
                }
            }
            Ok(reply) if (200..300).contains(&reply.status) || reply.status >= 500 => {
                self.failure(&reply, &endpoint)
            }
            Ok(reply) => return Err(self.failure(&reply, &endpoint)),
            Err(failure) => failure,
        };
        self.look_up(branch, first)
    }

    fn look_up(&self, branch: &BranchName, first: Failure) -> Result<ForgeRef, Failure> {
        let endpoint = Endpoint::PullsByHead {
            branch: branch.clone(),
        };
        let both = |second: Failure| {
            let output = [first.output(), second.output()]
                .iter()
                .filter(|o| !o.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(" / ");
            Failure::new(
                format!("{}; then {}", first.status(), second.status()),
                output,
            )
        };
        let reply = self.call(&endpoint, None).map_err(&both)?;
        if reply.status != endpoint.expected_status() {
            return Err(both(self.failure(&reply, &endpoint)));
        }
        let found = reply
            .json(&self.tokens.http().limits)
            .map_err(|e| both(Failure::new(endpoint.what(), e)))?;
        let pulls = found
            .as_array()
            .ok_or_else(|| both(Failure::new(endpoint.what(), "the answer is not an array")))?;
        match pulls {
            [one] => match positive(one.get("number")) {
                Some(number) => pull_ref(number),
                None => Err(both(Failure::new(
                    endpoint.what(),
                    "the pull request found holds no number",
                ))),
            },
            _ => Err(both(Failure::new(
                format!(
                    "{} found {} pull requests for the branch",
                    endpoint.what(),
                    pulls.len()
                ),
                "",
            ))),
        }
    }

    fn post(&self, ticket: &Ticket, questions: &[String]) -> Result<ForgeRef, Failure> {
        let what = "the comment";
        let repository = self.tokens.repository();
        if ticket.source != TicketSource::GitHub {
            return Err(Failure::new(
                what,
                format!(
                    "the ticket is a {} ticket; this forge posts on issues of {} only",
                    render::source_label(ticket.source),
                    repository.full_name()
                ),
            ));
        }
        let issue = render::issue_in(ticket, repository).ok_or_else(|| {
            Failure::new(
                what,
                format!(
                    "the GitHub ticket key {:?} is not owner/name#N of {}",
                    crate::api::cut(&ticket.key, 64),
                    repository.full_name()
                ),
            )
        })?;
        if questions.is_empty() {
            return Err(Failure::new(what, "there are no questions to post"));
        }
        let comment = render::questions_comment(questions);
        if comment.text.len() > MAX_BODY {
            return Err(Failure::new(what, "the rendered comment is over its cap"));
        }
        let endpoint = Endpoint::IssueComment { issue };
        let mut body = Object::new();
        body.insert("body", Value::String(comment.text));
        let bytes = boneli_json::to_vec(&Value::Object(body))
            .map_err(|e| Failure::new(what, format!("the request: {e}")))?;
        let reply = self.call(&endpoint, Some(&bytes))?;
        if reply.status != endpoint.expected_status() {
            return Err(self.failure(&reply, &endpoint));
        }
        let id = reply
            .json(&self.tokens.http().limits)
            .ok()
            .and_then(|v| positive(v.get("id")))
            .ok_or_else(|| {
                Failure::new(
                    format!("{what}: GitHub answered {}", reply.status),
                    "the answer holds no comment id",
                )
            })?;
        reference(format!("comment/{id}"))
    }

    fn port_failure(&self, failure: Failure) -> JobFailure {
        failure.redacted(&self.tokens.secrets()).to_job_failure()
    }
}

fn reference(text: String) -> Result<ForgeRef, Failure> {
    ForgeRef::parse(&text).ok_or_else(|| Failure::new("the reference", "it is blank"))
}

/// `pull/<number>`.
fn pull_ref(number: u64) -> Result<ForgeRef, Failure> {
    reference(format!("pull/{number}"))
}

impl Forge for GitHubForge {
    /// Posts the questions as one comment on the ticket's issue; the
    /// reference is `comment/<id>`. Only a GitHub ticket whose key is
    /// `owner/name#N` of this repository qualifies (ASCII case-insensitive),
    /// and an empty list is refused; either fails before any request.
    fn post_questions(
        &self,
        ticket: &Ticket,
        questions: &[String],
    ) -> Result<ForgeRef, JobFailure> {
        self.post(ticket, questions)
            .map_err(|f| self.port_failure(f))
    }

    /// Pushes the fix to a new `boneli/` branch and opens the pull request,
    /// ready for review; the reference is `pull/<number>`.
    fn open_pull_request(&self, request: &PullRequest) -> Result<ForgeRef, JobFailure> {
        self.open(request).map_err(|f| self.port_failure(f))
    }
}

impl fmt::Debug for GitHubForge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubForge")
            .field("tokens", &self.tokens)
            .field("config", &self.config)
            .finish()
    }
}
