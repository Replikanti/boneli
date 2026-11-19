//! The live acceptance test of the GitHub forge (ADR-014, D12): the real
//! `GitCli` and `GitHubForge` against the operator's GitHub App and
//! private test repository. Setup and variables: `docs/forge-github.md`.
//!
//! Run by hand, before a change to `boneli-forge-github` or to the git
//! push and credential path merges:
//!
//! ```sh
//! cargo test -p boneli-acceptance --test github -- --ignored --nocapture
//! ```
//!
//! A missing variable fails the test and names it; the test never skips.
//! It cleans up what it created (the pull request is closed, the branch
//! and the comment are deleted) through a client of its own, because the
//! adapter has no such endpoints.

use std::fs;
use std::io::Read;
use std::num::NonZeroU64;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boneli_app::{Attached, Forge, Git, PullRequest, RelativePath, RepoUrl};
use boneli_domain::{
    CheckStatus, Citation, CommitSha, EvidenceRef, FixChecks, RunId, TestStatus, Ticket,
    TicketSource, Usage,
};
use boneli_forge_github::{
    App, ClientId, ForgeConfig, GitHubForge, GitHubRepository, InstallationTokens, Limits,
    SystemClock, app_jwt, load_key,
};
use boneli_git_cli::{Credentials, DEFAULT_MAX_NODES, GitCli, GitCliConfig, Transports, Workspace};
use boneli_http::{Connection, Method, RequestBody, RequestHead, Target};
use boneli_https::{ConnectOptions, Dial, Roots, Timed, TlsConfig, TlsDial};

/// The bridge a composition root needs: the git adapter's credentials
/// from the forge's token source, for its own repository URL only.
struct TokenCredentials(Arc<InstallationTokens>);

impl Credentials for TokenCredentials {
    fn authorization(&self, url: &RepoUrl) -> Result<Option<String>, String> {
        if *url == self.0.repository_url() {
            self.0.git_authorization().map(Some)
        } else {
            Ok(None)
        }
    }
}

/// A required variable, or a failure that names it.
fn var(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => panic!("{name} is not set: the live test needs it (docs/forge-github.md)"),
    }
}

/// The test's own git: the first `git` on `PATH`, as an absolute path.
fn host_git() -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH is set");
    std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|candidate| candidate.is_absolute() && candidate.is_file())
        .expect("a git on PATH")
}

/// A test-local REST client with the installation token: the reads that
/// check the result and the cleanup, which the adapter cannot do.
struct Rest {
    dial: TlsDial,
    tokens: Arc<InstallationTokens>,
}

impl Rest {
    fn call(
        &self,
        method: &str,
        target: &str,
        accept: &str,
        body: Option<&[u8]>,
    ) -> (u16, Vec<u8>) {
        let token = self.tokens.token().expect("a token");
        self.send(
            method,
            target,
            accept,
            &format!("Bearer {}", token.expose()),
            body,
        )
    }

    fn send(
        &self,
        method: &str,
        target: &str,
        accept: &str,
        authorization: &str,
        body: Option<&[u8]>,
    ) -> (u16, Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let stream = self
            .dial
            .dial("api.github.com", 443, deadline)
            .expect("dial api.github.com");
        let timed = Timed::new(stream, deadline, Duration::from_secs(30));
        let limits = boneli_http::Limits::new(16_384, 64, 8 << 20).expect("limits");
        let mut conn = Connection::new(timed, "api.github.com", limits).expect("connection");
        let mut head = RequestHead::new(
            Method::new(method).expect("method"),
            Target::Origin(target.to_owned()),
        );
        head.headers.append("Accept", accept);
        head.headers.append("X-GitHub-Api-Version", "2022-11-28");
        head.headers.append("User-Agent", "boneli-acceptance");
        head.headers.append("Authorization", authorization);
        let request_body = match body {
            Some(bytes) => {
                head.headers.append("Content-Type", "application/json");
                RequestBody::Bytes(bytes)
            }
            None => RequestBody::None,
        };
        let mut response = conn.request(&head, request_body).expect("a response");
        let status = response.head.status;
        let mut bytes = Vec::new();
        response.read_to_end(&mut bytes).expect("the body");
        (status, bytes)
    }
}

fn json(bytes: &[u8]) -> boneli_json::Value {
    let limits = boneli_json::Limits::new(8 << 20, 64, 1 << 20).expect("limits");
    boneli_json::parse(bytes, &limits).expect("JSON")
}

/// Values and depth of a JSON value, counted as boneli-json counts them.
fn stats(value: &boneli_json::Value) -> (usize, usize) {
    match value {
        boneli_json::Value::Array(items) => items
            .iter()
            .map(stats)
            .fold((1, 1), |(v, d), (iv, id)| (v + iv, d.max(id + 1))),
        boneli_json::Value::Object(members) => members
            .iter()
            .map(|(_, m)| stats(m))
            .fold((1, 1), |(v, d), (mv, md)| (v + mv, d.max(md + 1))),
        _ => (1, 0),
    }
}

/// Prints a response's size, values and depth for ADR-014 D10, and checks
/// them against the adapter's limits.
fn measure(what: &str, bytes: &[u8]) {
    let (values, depth) = stats(&json(bytes));
    println!(
        "size {what}: {} B, {values} values, depth {depth}",
        bytes.len()
    );
    assert!(bytes.len() <= 1_048_576, "{what} is over the body limit");
    assert!(values <= 4_096, "{what} is over the value limit");
    assert!(depth <= 16, "{what} is over the depth limit");
}

fn get_str<'v>(value: &'v boneli_json::Value, path: &[&str]) -> &'v str {
    let mut v = value;
    for key in path {
        v = v.get(key).unwrap_or_else(|| panic!("no {key} in {path:?}"));
    }
    v.as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string"))
}

/// The `href`s of every anchor with `class` in `html`.
fn anchors_with_class<'h>(html: &'h str, class: &str) -> Vec<&'h str> {
    html.split("<a ")
        .skip(1)
        .filter_map(|tag| tag.split('>').next())
        .filter(|attrs| attrs.contains(class))
        .map(|attrs| {
            attrs
                .split("href=\"")
                .nth(1)
                .and_then(|h| h.split('"').next())
                .unwrap_or("")
        })
        .collect()
}

/// Every form of a reference to the decoy issue `decoy` of `repo`
/// (`owner/name`), each after a closing keyword: `#D`, `owner/repo#D`,
/// `GH-D` and the issue and pull URLs, in several cases, with and without
/// a colon.
fn decoy_forms(repo: &str, decoy: u64) -> String {
    format!(
        "Closes #{decoy} fixes: {repo}#{decoy} RESOLVED https://github.com/{repo}/issues/{decoy} \
         Fixed: GH-{decoy} close https://github.com/{repo}/pull/{decoy} resolves: #{decoy} "
    )
}

/// Text written to be hostile on GitHub: mentions of the `ghost`
/// placeholder account (a mention that escaped would notify no one real),
/// closing references to the decoy issue, markup, fences and invisible
/// characters, repeated to `n` bytes.
fn hostile(n: usize, decoys: &str) -> String {
    let unit = format!(
        "@ghost @ghost/team {decoys}``` ~~~ </pre> <img src=x onerror=alert(1)> \
         <!-- [x](javascript:alert(1)) - [ ] task > quote\r lone CR\r\nCRLF \u{202e}rlo \u{200b}zwsp \u{2028}\n"
    );
    let mut text = String::new();
    while text.len() < n {
        text.push_str(&unit);
    }
    text
}

/// The `href` of every anchor in `html`.
fn hrefs(html: &str) -> Vec<&str> {
    html.split("<a ")
        .skip(1)
        .filter_map(|tag| tag.split('>').next())
        .filter_map(|attrs| {
            attrs
                .split("href=\"")
                .nth(1)
                .and_then(|h| h.split('"').next())
        })
        .collect()
}

/// No anchor in `html` points at the decoy issue or a pull request of
/// that number.
fn assert_no_decoy_link(html: &str, decoy: u64) {
    for href in hrefs(html) {
        let issue = href.ends_with(&format!("/issues/{decoy}"));
        let pull = href.ends_with(&format!("/pull/{decoy}"));
        assert!(!issue && !pull, "a link to the decoy: {href}");
    }
}

/// What the test created, removed when it ends, also when it fails.
struct Cleanup<'r> {
    rest: &'r Rest,
    repo: String,
    pull: Option<u64>,
    branch: Option<String>,
    comment: Option<u64>,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let accept = "application/vnd.github+json";
        if let Some(pull) = self.pull {
            let (status, _) = self.rest.call(
                "PATCH",
                &format!("/repos/{}/pulls/{pull}", self.repo),
                accept,
                Some(br#"{"state":"closed"}"#),
            );
            println!("cleanup: close pull request {pull}: {status}");
        }
        if let Some(branch) = &self.branch {
            let (status, _) = self.rest.call(
                "DELETE",
                &format!("/repos/{}/git/refs/heads/{branch}", self.repo),
                accept,
                None,
            );
            println!("cleanup: delete branch {branch}: {status}");
        }
        if let Some(comment) = self.comment {
            let (status, _) = self.rest.call(
                "DELETE",
                &format!("/repos/{}/issues/comments/{comment}", self.repo),
                accept,
                None,
            );
            println!("cleanup: delete comment {comment}: {status}");
        }
    }
}

/// The values of the trace2 data event `pack-objects` / `key` in a
/// `GIT_TRACE2_EVENT` file.
fn trace2_data(trace: &Path, key: &str) -> Vec<u64> {
    let needle = format!("\"category\":\"pack-objects\",\"key\":\"{key}\",\"value\":\"");
    fs::read_to_string(trace)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let rest = &line[line.find(&needle)? + needle.len()..];
            rest[..rest.find('"')?].parse().ok()
        })
        .collect()
}

#[test]
#[ignore = "network: needs the operator's GitHub App, docs/forge-github.md"]
fn opens_a_pull_request_on_the_test_repository() {
    let client_id = var("BONELI_GITHUB_CLIENT_ID");
    let installation = var("BONELI_GITHUB_INSTALLATION_ID");
    let key_file = var("BONELI_GITHUB_KEY");
    let repo = var("BONELI_GITHUB_REPO");
    let issue = var("BONELI_GITHUB_ISSUE");
    let decoy = var("BONELI_GITHUB_DECOY_ISSUE");
    let base = var("BONELI_GITHUB_BASE");
    let commit_name = var("BONELI_GITHUB_COMMIT_NAME");
    let commit_email = var("BONELI_GITHUB_COMMIT_EMAIL");

    let client_id = ClientId::parse(&client_id).expect("BONELI_GITHUB_CLIENT_ID");
    let installation: NonZeroU64 = installation
        .parse()
        .expect("BONELI_GITHUB_INSTALLATION_ID is a positive number");
    let repository = GitHubRepository::parse(&repo).expect("BONELI_GITHUB_REPO is owner/name");
    let issue_number: u64 = issue.parse().expect("BONELI_GITHUB_ISSUE is a number");
    let decoy: u64 = decoy
        .parse()
        .expect("BONELI_GITHUB_DECOY_ISSUE is a number");
    assert_ne!(decoy, issue_number, "the decoy must be another issue");
    let started = boneli_forge_github::time::format_rfc3339(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_secs(),
    );
    let decoys = decoy_forms(&repo, decoy);
    let base = CommitSha::parse(&base).expect("BONELI_GITHUB_BASE is a full SHA");

    let roots = Roots::mozilla();
    let options = ConnectOptions::new(
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(30),
    )
    .expect("options");
    let dial = TlsDial::new(TlsConfig::new(roots).expect("TLS"), options);
    let app =
        App::open(client_id.clone(), installation, Path::new(&key_file)).expect("the key file");
    let tokens = Arc::new(InstallationTokens::open(
        app,
        repository.clone(),
        Arc::new(dial.clone()),
        Arc::new(SystemClock),
        Limits::GITHUB,
    ));
    let rest = Rest {
        dial: dial.clone(),
        tokens: tokens.clone(),
    };
    let accept = "application/vnd.github+json";
    let full = "application/vnd.github.full+json";
    let repo_path = format!("/repos/{}", repository.full_name());

    // A token exchange of the test's own, to measure its answer (D10).
    let key = load_key(Path::new(&key_file)).expect("the key file");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs();
    let jwt = app_jwt(&key, &client_id, now).expect("a JWT");
    let (status, token_answer) = rest.send(
        "POST",
        &format!("/app/installations/{installation}/access_tokens"),
        accept,
        &format!("Bearer {jwt}"),
        Some(format!(r#"{{"repositories":["{}"],"permissions":{{"contents":"write","issues":"write","pull_requests":"write"}}}}"#, repository.name()).as_bytes()),
    );
    assert_eq!(status, 201, "the test's own token exchange");
    measure("token", &token_answer);
    let (status, repo_answer) = rest.call("GET", &repo_path, accept, None);
    assert_eq!(status, 200);
    measure("repository", &repo_answer);
    let default_branch = get_str(&json(&repo_answer), &["default_branch"]).to_owned();

    // git through the adapter, with the App's token, traced so the push's
    // pack can be measured (ADR-014 D2, the shallow negotiation item).
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("live-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("tmp");
    let trace = tmp.join("trace2.json");
    let wrapper = tmp.join("tracing-git");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nGIT_TRACE2_EVENT='{}' exec '{}' \"$@\"\n",
            trace.display(),
            host_git().display()
        ),
    )
    .expect("the wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).expect("chmod");
    let git = Arc::new(
        GitCli::open(GitCliConfig {
            git: wrapper,
            root: tmp.join("git"),
            transports: Transports::Https,
            max_workspace_nodes: DEFAULT_MAX_NODES,
            credentials: Some(Arc::new(TokenCredentials(tokens.clone()))),
        })
        .expect("GitCli"),
    );

    // The fix: one line appended to README.md, made through the adapter.
    let url = repository.git_url();
    let checkout = git
        .fetch_base(&url, &base)
        .expect("the authenticated fetch");
    let snapshot = Workspace::decode(
        &git.snapshot(&checkout).expect("snapshot"),
        DEFAULT_MAX_NODES,
    )
    .expect("decode");
    let readme = RelativePath::parse("README.md").expect("path");
    assert!(snapshot.get(&readme).is_some(), "the base has README.md");
    let entries: Vec<_> = snapshot
        .iter()
        .filter(|(path, ..)| !path.is_repository_metadata())
        .map(|(path, kind, data)| {
            let mut data = data.to_vec();
            if *path == readme {
                data.extend_from_slice(b"\nboneli live acceptance test\n");
            }
            (path.clone(), kind, data)
        })
        .collect();
    let edited = Workspace::from_sorted(entries, DEFAULT_MAX_NODES).expect("the edited workspace");
    let diff = git.diff(&checkout, &edited.encode()).expect("the diff");

    let forge = GitHubForge::new(
        tokens.clone(),
        git.clone(),
        ForgeConfig {
            commit_name,
            commit_email,
            base_branch: None,
        },
    )
    .expect("the forge");
    let ticket = Ticket {
        source: TicketSource::GitHub,
        key: format!("{}#{issue_number}", repository.full_name()),
        // Closing references to the decoy, cut by the adapter to 256 bytes.
        title: decoys.repeat(4),
        body: String::new(),
    };
    let mut cleanup = Cleanup {
        rest: &rest,
        repo: repository.full_name(),
        pull: None,
        branch: None,
        comment: None,
    };

    // The questions comment.
    let comment = forge
        .post_questions(
            &ticket,
            &[
                hostile(2_000, &decoys),
                decoys.clone(),
                "Which version?".to_owned(),
            ],
        )
        .expect("the comment");
    let comment_id: u64 = comment
        .as_str()
        .strip_prefix("comment/")
        .and_then(|id| id.parse().ok())
        .expect("comment/<id>");
    cleanup.comment = Some(comment_id);
    let (status, comment_answer) = rest.call(
        "GET",
        &format!("{repo_path}/issues/comments/{comment_id}"),
        full,
        None,
    );
    assert_eq!(status, 200);
    measure("comment", &comment_answer);
    let html = get_str(&json(&comment_answer), &["body_html"]).to_owned();
    assert!(
        anchors_with_class(&html, "user-mention").is_empty(),
        "{html}"
    );
    assert!(anchors_with_class(&html, "issue-link").is_empty(), "{html}");
    assert_no_decoy_link(&html, decoy);

    // The pull request.
    let evidence = |r: &str, content: Vec<u8>| Attached {
        reference: EvidenceRef::parse(r).expect("ref"),
        content,
    };
    let request = PullRequest {
        run: RunId::new("live-acceptance".to_owned()),
        ticket: ticket.clone(),
        base: base.clone(),
        diff: evidence("live-diff", diff),
        test: evidence("live-test", hostile(3_000, &decoys).into_bytes()),
        analysis: evidence("live-analysis", hostile(70_000, &decoys).into_bytes()),
        citations: vec![Citation {
            path: "docs/a b.md".to_owned(),
            line: 1,
            sha: base.clone(),
            quote: hostile(200, &decoys),
        }],
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
    };
    let pull = forge.open_pull_request(&request).expect("the pull request");
    let number: u64 = pull
        .as_str()
        .strip_prefix("pull/")
        .and_then(|n| n.parse().ok())
        .expect("pull/<number>");
    cleanup.pull = Some(number);
    let (status, pull_answer) =
        rest.call("GET", &format!("{repo_path}/pulls/{number}"), full, None);
    assert_eq!(status, 200);
    measure("pull request", &pull_answer);
    let pull_json = json(&pull_answer);
    let branch = get_str(&pull_json, &["head", "ref"]).to_owned();
    cleanup.branch = Some(branch.clone());
    assert!(branch.starts_with("boneli/live-acceptance-"), "{branch}");
    assert_eq!(get_str(&pull_json, &["base", "ref"]), default_branch);
    assert_eq!(
        pull_json.get("draft").and_then(|v| v.as_bool()),
        Some(false)
    );
    let title = get_str(&pull_json, &["title"]);
    assert!(title.len() <= 256, "{title}");
    assert!(title.ends_with('…'), "the title was cut: {title}");
    let body = get_str(&pull_json, &["body"]);
    assert!(body.len() <= 65_536, "{}", body.len());
    println!(
        "pull request body: {} B, title {} B",
        body.len(),
        title.len()
    );
    let html = get_str(&pull_json, &["body_html"]);
    assert!(
        anchors_with_class(html, "user-mention").is_empty(),
        "{html}"
    );
    for href in anchors_with_class(html, "issue-link") {
        assert!(href.ends_with(&format!("/issues/{issue_number}")), "{href}");
    }
    assert_no_decoy_link(html, decoy);

    // GitHub's own closing references: exactly the ticket's issue, so the
    // generated `Fixes` line is the only one and no hostile text formed
    // another. GitHub computes them asynchronously, hence the wait.
    std::thread::sleep(Duration::from_secs(10));
    let query = format!(
        r#"{{"query":"query($o:String!,$n:String!,$p:Int!){{repository(owner:$o,name:$n){{pullRequest(number:$p){{closingIssuesReferences(first:20){{nodes{{number}}}}}}}}}}","variables":{{"o":"{}","n":"{}","p":{number}}}}}"#,
        repository.owner(),
        repository.name()
    );
    let (status, closing) = rest.call("POST", "/graphql", accept, Some(query.as_bytes()));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&closing));
    let closing = json(&closing);
    let nodes = closing
        .get("data")
        .and_then(|d| d.get("repository"))
        .and_then(|r| r.get("pullRequest"))
        .and_then(|p| p.get("closingIssuesReferences"))
        .and_then(|c| c.get("nodes"))
        .and_then(|n| n.as_array())
        .expect("closingIssuesReferences");
    let mut closes: Vec<u64> = nodes
        .iter()
        .filter_map(|n| {
            n.get("number")
                .and_then(|v| v.as_number())
                .and_then(|v| v.as_u64())
        })
        .collect();
    closes.sort_unstable();
    println!("closing references: {closes:?}");
    assert_eq!(closes, [issue_number], "the closing references");

    // The decoy's timeline: no cross-reference from this pull request, and
    // no connected or referenced event since the test started.
    let (status, timeline) = rest.call(
        "GET",
        &format!("{repo_path}/issues/{decoy}/timeline?per_page=100"),
        accept,
        None,
    );
    assert_eq!(status, 200, "the decoy's timeline");
    let timeline = json(&timeline);
    for event in timeline.as_array().expect("timeline events") {
        let kind = event.get("event").and_then(|v| v.as_str()).unwrap_or("");
        let at = event
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let from_this_pull = event
            .get("source")
            .and_then(|s| s.get("issue"))
            .and_then(|i| i.get("number"))
            .and_then(|v| v.as_number())
            .and_then(|v| v.as_u64())
            == Some(number);
        assert!(
            !(kind == "cross-referenced" && from_this_pull),
            "the decoy got a cross-reference from the pull request"
        );
        assert!(
            !(matches!(kind, "connected" | "referenced" | "cross-referenced")
                && at >= started.as_str()),
            "the decoy got a {kind} event at {at}"
        );
    }
    let head_sha = get_str(&pull_json, &["head", "sha"]).to_owned();
    let (status, commit) = rest.call(
        "GET",
        &format!("{repo_path}/commits/{head_sha}"),
        accept,
        None,
    );
    assert_eq!(status, 200);
    let commit = json(&commit);
    let parents = commit
        .get("parents")
        .and_then(|p| p.as_array())
        .expect("parents");
    assert_eq!(parents.len(), 1);
    assert_eq!(get_str(&parents[0], &["sha"]), base.as_str());
    let (status, files) = rest.call(
        "GET",
        &format!("{repo_path}/pulls/{number}/files"),
        accept,
        None,
    );
    assert_eq!(status, 200);
    let files = json(&files);
    let files = files.as_array().expect("files");
    assert_eq!(files.len(), 1);
    assert_eq!(get_str(&files[0], &["filename"]), "README.md");
    let (status, lookup) = rest.call(
        "GET",
        &format!(
            "{repo_path}/pulls?head={}:{branch}&state=all&per_page=2",
            repository.owner()
        ),
        accept,
        None,
    );
    assert_eq!(status, 200);
    measure("lookup", &lookup);

    // What the push sent (ADR-014 D2): pack-objects' own count.
    let wrote = trace2_data(&trace, "write_pack_file/wrote");
    let negotiated = fs::read_to_string(&trace)
        .unwrap_or_default()
        .contains("--negotiate-only");
    let (status, tip) = rest.call(
        "GET",
        &format!("{repo_path}/branches/{default_branch}"),
        accept,
        None,
    );
    assert_eq!(status, 200);
    let tip = get_str(&json(&tip), &["commit", "sha"]).to_owned();
    println!(
        "push: pack-objects wrote {wrote:?} objects; negotiation child ran: {negotiated}; \
         {default_branch} moved past the base: {}",
        tip != base.as_str()
    );
    let _ = fs::remove_dir_all(&tmp);
}
