//! The REST client and the forge's requests (ADR-014, D7, D9 and D10),
//! against the fake GitHub.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use boneli_app::{BranchName, Forge, ForgeRef, JobFailure};
use boneli_domain::{RunId, TicketSource};
use boneli_forge_github::render::{self, MAX_BODY};
use boneli_forge_github::{
    ConfigError, Endpoint, ForgeConfig, GitHubForge, Limits, branch_name, run_slug,
};
use support::*;

/// Opens the sample pull request on a hub with `override_`, under
/// `limits`.
fn open_with(
    limits: Limits,
    override_: impl Fn(&Seen) -> Option<Reply> + Send + Sync + 'static,
) -> (Result<ForgeRef, JobFailure>, Fake, Arc<FakeGit>) {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(override_);
    let git = Arc::new(FakeGit::default());
    let github = forge(tokens_with(&fake, &clock, limits), git.clone());
    (github.open_pull_request(&request()), fake, git)
}

fn open(
    override_: impl Fn(&Seen) -> Option<Reply> + Send + Sync + 'static,
) -> (Result<ForgeRef, JobFailure>, Fake, Arc<FakeGit>) {
    open_with(Limits::GITHUB, override_)
}

fn is_create(seen: &Seen) -> bool {
    seen.method == "POST" && seen.target == "/repos/octo-org/demo.repo/pulls"
}

fn is_lookup(seen: &Seen) -> bool {
    seen.target
        .starts_with("/repos/octo-org/demo.repo/pulls?head=")
}

fn is_repository(seen: &Seen) -> bool {
    seen.method == "GET" && seen.target == "/repos/octo-org/demo.repo"
}

#[test]
fn pull_request_request_is_exact() {
    let (result, fake, git) = open(|_| None);
    assert_eq!(result.expect("opened").as_str(), "pull/1");
    let calls = fake.seen();
    let targets: Vec<(String, String)> = calls
        .iter()
        .map(|s| (s.method.clone(), s.target.clone()))
        .collect();
    assert_eq!(
        targets,
        [
            ("POST", "/app/installations/4242/access_tokens"),
            ("GET", "/repos/octo-org/demo.repo"),
            ("POST", "/repos/octo-org/demo.repo/pulls"),
        ]
        .map(|(m, t)| (m.to_owned(), t.to_owned()))
    );
    let branch = git.branches().pop().expect("one push");
    assert!(branch.starts_with("boneli/run-1-"), "{branch}");
    assert_eq!(branch.len(), "boneli/run-1-".len() + 8);
    let git_calls = git.calls.lock().expect("calls").clone();
    assert_eq!(
        git_calls,
        [
            format!("fetch_base https://github.com/octo-org/demo.repo.git {BASE}"),
            "apply base the diff".to_owned(),
            format!("push applied {branch}"),
        ]
    );
    let (_, commit) = git.pushed.lock().expect("pushed")[0].clone();
    assert_eq!(
        commit.message(),
        "boneli: fix for GitHub ticket 7\n\nRun run-1\n"
    );
    assert_eq!(commit.name(), "boneli-test[bot]");
    let create = &calls[2];
    let body = render::pull_request_body(&request(), &repository()).text;
    let mut expected = boneli_json::Object::new();
    for (k, v) in [
        ("title", "Fix: Crash on empty input"),
        ("head", branch.as_str()),
        ("base", "main"),
        ("body", body.as_str()),
    ] {
        expected.insert(k, boneli_json::Value::String(v.to_owned()));
    }
    expected.insert("draft", boneli_json::Value::Bool(false));
    assert_eq!(
        create.body,
        boneli_json::to_vec(&boneli_json::Value::Object(expected)).expect("JSON")
    );
    assert_eq!(create.bearer(), Some(hub_token(1).as_str()));
    assert_eq!(create.header("content-type"), Some("application/json"));
    assert_eq!(create.header("x-github-api-version"), Some("2022-11-28"));
    assert_eq!(calls[1].header("content-type"), None, "a GET has no body");
    assert!(body.starts_with("Fixes #7\n\n"), "{body}");
}

#[test]
fn configured_base_branch_skips_the_repository_read() {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(|_| None);
    let config = ForgeConfig {
        base_branch: Some("release/2026.11".to_owned()),
        ..config()
    };
    let github = GitHubForge::new(tokens(&fake, &clock), Arc::new(FakeGit::default()), config)
        .expect("valid");
    github.open_pull_request(&request()).expect("opened");
    assert!(!fake.seen().iter().any(is_repository));
    let create = fake.seen().into_iter().find(is_create).expect("created");
    assert_eq!(
        create.body_json().get("base").and_then(|v| v.as_str()),
        Some("release/2026.11")
    );
    for (name, email, base) in [
        ("", "a@b", None),
        ("a<b", "a@b", None),
        ("n", "nope", None),
        ("n", "a@b", Some("a..b")),
        ("n", "a@b", Some("")),
    ] {
        let config = ForgeConfig {
            commit_name: name.to_owned(),
            commit_email: email.to_owned(),
            base_branch: base.map(str::to_owned),
        };
        let error = GitHubForge::new(tokens(&fake, &clock), Arc::new(FakeGit::default()), config)
            .expect_err("refused");
        assert!(
            matches!(
                error,
                ConfigError::CommitIdentity | ConfigError::BaseBranch(_)
            ),
            "{error:?}"
        );
    }
}

#[test]
fn reference_comes_from_number() {
    let (result, ..) = open(|seen| {
        is_create(seen).then(|| {
            Reply::json(
                201,
                r#"{"id":99,"number":42,"html_url":"https://example.invalid/x","node_id":"PR_1"}"#,
            )
        })
    });
    assert_eq!(result.expect("opened").as_str(), "pull/42");
}

#[test]
fn number_forms() {
    for (number, expected) in [
        ("18446744073709551615", Some("pull/18446744073709551615")),
        ("1", Some("pull/1")),
        ("0", None),
        ("-1", None),
        ("1.0", None),
        ("1e3", None),
        (r#""42""#, None),
        ("18446744073709551616", None),
        ("null", None),
    ] {
        let answer = format!(r#"{{"number":{number}}}"#);
        let (result, fake, _) =
            open(move |seen| is_create(seen).then(|| Reply::json(201, &answer)));
        assert_eq!(
            result.as_ref().ok().map(ForgeRef::as_str),
            expected,
            "{number}: {result:?}"
        );
        if expected.is_none() {
            // An unusable 201 is ambiguous: one lookup, which finds none.
            assert_eq!(fake.seen().iter().filter(|s| is_lookup(s)).count(), 1);
        }
    }
}

#[test]
fn ambiguous_creation_looks_up_by_head() {
    for (lookup, ok) in [
        (Reply::json(200, "[]"), false),
        (Reply::json(200, r#"[{"number":5}]"#), true),
        (Reply::json(200, r#"[{"number":5},{"number":6}]"#), false),
        (Reply::json(500, r#"{"message":"lookup broke"}"#), false),
        (Reply::json(200, r#"{"number":5}"#), false),
    ] {
        let lookup = std::sync::Mutex::new(Some(lookup));
        let (result, fake, git) = open(move |seen| {
            if is_create(seen) {
                Some(Reply::json(502, r#"{"message":"Server Error"}"#))
            } else if is_lookup(seen) {
                lookup.lock().expect("lookup").take()
            } else {
                None
            }
        });
        let branch = git.branches().pop().expect("pushed");
        let lookups: Vec<Seen> = fake.seen().into_iter().filter(is_lookup).collect();
        assert_eq!(lookups.len(), 1);
        assert_eq!(
            lookups[0].target,
            format!("/repos/octo-org/demo.repo/pulls?head=octo-org:{branch}&state=all&per_page=2")
        );
        assert_eq!(lookups[0].method, "GET");
        match result {
            Ok(reference) => {
                assert!(ok);
                assert_eq!(reference.as_str(), "pull/5");
            }
            Err(failure) => {
                assert!(!ok, "{failure:?}");
                // The failure carries both errors.
                let detail = failure.detail();
                assert!(detail.contains("GitHub answered 502"), "{detail}");
                assert!(detail.contains("the pull-request lookup"), "{detail}");
                assert_eq!(failure.cost_micro_usd(), 0);
            }
        }
    }
}

#[test]
fn timeout_on_create_looks_up_by_head() {
    let limits = Limits::GITHUB.with_deadline(Duration::from_millis(300));
    let created = std::sync::Mutex::new(false);
    let start = Instant::now();
    let (result, fake, _) = open_with(limits, move |seen| {
        if is_create(seen) {
            *created.lock().expect("created") = true;
            Some(Reply::Stall)
        } else if is_lookup(seen) {
            Some(Reply::json(200, r#"[{"number":8}]"#))
        } else {
            None
        }
    });
    assert_eq!(result.expect("found by the lookup").as_str(), "pull/8");
    assert!(start.elapsed() < Duration::from_secs(10));
    assert_eq!(fake.seen().iter().filter(|s| is_create(s)).count(), 1);
}

#[test]
fn rate_limit_is_reported_not_retried() {
    for (status, headers, expect) in [
        (
            403,
            vec![
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-reset", "1700003600"),
            ],
            "rate limited until 2023-11-14T23:13:20Z",
        ),
        (
            429,
            vec![("retry-after", "60")],
            "rate limited, retry after 60 s",
        ),
        (
            403,
            vec![("retry-after", "7")],
            "rate limited, retry after 7 s",
        ),
    ] {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        let (result, fake, _) = open(move |seen| {
            is_create(seen).then(|| Reply::Http {
                status,
                headers: headers.clone(),
                body: br#"{"message":"API rate limit exceeded"}"#.to_vec(),
            })
        });
        let failure = result.expect_err("rate limited");
        assert!(failure.detail().contains(expect), "{failure:?}");
        assert!(
            failure.detail().contains("\"API rate limit exceeded\""),
            "{failure:?}"
        );
        assert_eq!(fake.seen().iter().filter(|s| is_create(s)).count(), 1);
        assert_eq!(fake.seen().iter().filter(|s| is_lookup(s)).count(), 0);
    }
}

/// Posts one question with the comment endpoint answering `reply`.
fn post_with(
    reply: impl Fn() -> Reply + Send + Sync + 'static,
) -> (Result<ForgeRef, JobFailure>, Fake) {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(move |seen| seen.target.contains("/issues/").then(&reply));
    let github = forge(tokens(&fake, &clock), Arc::new(FakeGit::default()));
    (
        github.post_questions(&ticket("7"), &["Which version?".to_owned()]),
        fake,
    )
}

#[test]
fn status_mapping_table() {
    type Row<'a> = (u16, Vec<(&'a str, &'a str)>, &'a str, Option<&'a str>);
    let rows: Vec<Row> = vec![
        (
            404,
            vec![("x-github-request-id", "AB12:CD34:5678")],
            "the comment: GitHub answered 404 (request AB12:CD34:5678): \"Not Found\"",
            Some("Not Found"),
        ),
        (
            422,
            vec![("x-github-request-id", "bad id!")],
            "the comment: GitHub answered 422: \"Validation Failed\"",
            Some("Validation Failed"),
        ),
        (
            301,
            vec![("location", "https://api.github.com/elsewhere")],
            "the comment: GitHub answered 301, a redirect, which the adapter does not follow, no error output",
            None,
        ),
        (
            403,
            vec![],
            "the comment: GitHub answered 403: \"Resource not accessible by integration\"",
            Some("Resource not accessible by integration"),
        ),
        (
            503,
            vec![],
            "the comment: GitHub answered 503, no error output",
            None,
        ),
        (
            200,
            vec![],
            "the comment: GitHub answered 200, no error output",
            None,
        ),
        (
            400,
            vec![],
            "the comment: GitHub answered 400: \"line\\nbreak \\u{202e}\"",
            Some("line\nbreak \u{202e}"),
        ),
    ];
    for (status, headers, expected, message) in rows {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        let body = match message {
            Some(m) => {
                let mut o = boneli_json::Object::new();
                o.insert("message", boneli_json::Value::String(m.to_owned()));
                boneli_json::to_vec(&boneli_json::Value::Object(o)).expect("JSON")
            }
            None => Vec::new(),
        };
        let (result, fake) = post_with(move || Reply::Http {
            status,
            headers: headers.clone(),
            body: body.clone(),
        });
        let failure = result.expect_err("refused");
        assert_eq!(failure.detail(), expected, "{status}");
        assert_eq!(failure.cost_micro_usd(), 0);
        assert_eq!(fake.api_calls().len(), 1, "{status}: no retry");
    }
    // A long message is cut at 256 bytes, at a char boundary.
    let long = format!("{}{}", "m".repeat(255), "\u{17e}".repeat(10));
    let answer = format!(r#"{{"message":"{long}"}}"#);
    let (result, _) = post_with(move || Reply::json(422, &answer));
    let detail = result.expect_err("refused").detail().to_owned();
    assert!(
        detail.ends_with(&format!("\"{}\"", "m".repeat(255))),
        "{detail}"
    );
}

#[test]
fn response_limits() {
    /// The repository read answered with `body` (status 200).
    fn read(body: Vec<u8>) -> Result<ForgeRef, JobFailure> {
        open(move |seen| is_repository(seen).then(|| Reply::http(200, &[], &body))).0
    }
    let base = br#"{"default_branch":"main"}"#;
    let padded = |len: usize| {
        let mut body = base.to_vec();
        body.resize(len, b' ');
        body
    };
    read(padded(1_048_576)).expect("1,048,576 bytes");
    let failure = read(padded(1_048_577)).expect_err("1,048,577 bytes");
    assert!(failure.detail().contains("the repository"), "{failure:?}");

    let nested = |depth: usize| {
        format!(
            r#"{{"default_branch":"main","x":{}{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        )
        .into_bytes()
    };
    read(nested(16)).expect("depth 16");
    read(nested(17)).expect_err("depth 17");

    // The object, its two members and the array's elements: 3 + n values.
    let values = |total: usize| {
        let elements = vec!["0"; total - 3].join(",");
        format!(r#"{{"default_branch":"main","x":[{elements}]}}"#).into_bytes()
    };
    read(values(4_096)).expect("4,096 values");
    read(values(4_097)).expect_err("4,097 values");

    // Heads: exactly 16,384 bytes with the final CRLF CRLF, then one more.
    let head = |len: usize, fields: usize| {
        let body = br#"{"default_branch":"main"}"#;
        let mut head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n", body.len());
        for k in 1..fields - 1 {
            head.push_str(&format!("x-f{k}: v\r\n"));
        }
        let pad = len - head.len() - "x-pad: \r\n\r\n".len();
        head.push_str(&format!("x-pad: {}\r\n\r\n", "p".repeat(pad)));
        assert_eq!(head.len(), len);
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    };
    let raw =
        |bytes: Vec<u8>| open(move |seen| is_repository(seen).then(|| Reply::Raw(bytes.clone()))).0;
    raw(head(16_384, 3)).expect("a 16,384-byte head");
    raw(head(16_385, 3)).expect_err("a 16,385-byte head");
    raw(head(2_000, 64)).expect("64 fields");
    raw(head(2_000, 65)).expect_err("65 fields");
}

#[test]
fn malformed_json_refused() {
    for body in [
        br#"{"default_branch":"main","default_branch":"x"}"#.to_vec(),
        b"\xEF\xBB\xBF{\"default_branch\":\"main\"}".to_vec(),
        br#"{"default_branch":"main"} x"#.to_vec(),
        b"{\"default_branch\":\"ma\xFFin\"}".to_vec(),
        b"{\"default_branch\":".to_vec(),
        b"".to_vec(),
        b"[\"main\"]".to_vec(),
    ] {
        let shown = String::from_utf8_lossy(&body).into_owned();
        let (result, _, git) =
            open(move |seen| is_repository(seen).then(|| Reply::http(200, &[], &body)));
        let failure = result.expect_err(&shown);
        assert!(failure.detail().contains("the repository"), "{failure:?}");
        assert!(git.branches().is_empty(), "nothing is pushed");
    }
}

#[test]
fn default_branch_rules() {
    for (branch, ok) in [
        ("main", true),
        ("release/2026.11", true),
        ("feature-x_y", true),
        ("\u{17e}luty", true),
        ("", false),
        ("-x", false),
        ("a..b", false),
        ("a b", false),
        ("a~1", false),
        ("a^", false),
        ("a:b", false),
        ("a?", false),
        ("a*", false),
        ("a[", false),
        ("a\\\\b", false),
        ("x.lock", false),
        ("x.", false),
        ("/x", false),
        ("x/", false),
        ("a//b", false),
        (".x", false),
        ("a/.b", false),
        ("@", false),
        ("a@{b", false),
        ("a\\u0001", false),
        ("a\\u007f", false),
    ] {
        let answer = format!(r#"{{"default_branch":"{branch}"}}"#);
        let (result, _, git) =
            open(move |seen| is_repository(seen).then(|| Reply::json(200, &answer)));
        assert_eq!(result.is_ok(), ok, "{branch:?}: {result:?}");
        assert_eq!(git.branches().is_empty(), !ok, "{branch:?}");
    }
    let long = format!(r#"{{"default_branch":"{}"}}"#, "b".repeat(256));
    let (result, ..) = open(move |seen| is_repository(seen).then(|| Reply::json(200, &long)));
    result.expect_err("256 bytes");
    let at_cap = format!(r#"{{"default_branch":"{}"}}"#, "b".repeat(255));
    let (result, ..) = open(move |seen| is_repository(seen).then(|| Reply::json(200, &at_cap)));
    result.expect("255 bytes");
    for value in ["1", "null", r#"["main"]"#] {
        let answer = format!(r#"{{"default_branch":{value}}}"#);
        let (result, ..) = open(move |seen| is_repository(seen).then(|| Reply::json(200, &answer)));
        result.expect_err(value);
    }
}

/// Every variant, through an exhaustive match: a new variant does not
/// compile until this test lists it.
fn every_endpoint() -> Vec<Endpoint> {
    let branch = BranchName::parse("boneli/run-1-0123abcd").expect("branch");
    let all = vec![
        Endpoint::AccessToken { installation: 1 },
        Endpoint::Repository,
        Endpoint::CreatePull,
        Endpoint::PullsByHead { branch },
        Endpoint::IssueComment { issue: 7 },
    ];
    for endpoint in &all {
        match endpoint {
            Endpoint::AccessToken { .. }
            | Endpoint::Repository
            | Endpoint::CreatePull
            | Endpoint::PullsByHead { .. }
            | Endpoint::IssueComment { .. } => {}
        }
    }
    all
}

#[test]
fn endpoints_are_a_closed_set() {
    let repo = repository();
    let shown: Vec<(&str, String)> = every_endpoint()
        .iter()
        .map(|e| (e.method(), e.target(&repo)))
        .collect();
    assert_eq!(
        shown,
        [
            ("POST", "/app/installations/1/access_tokens"),
            ("GET", "/repos/octo-org/demo.repo"),
            ("POST", "/repos/octo-org/demo.repo/pulls"),
            (
                "GET",
                "/repos/octo-org/demo.repo/pulls?head=octo-org:boneli/run-1-0123abcd&state=all&per_page=2"
            ),
            ("POST", "/repos/octo-org/demo.repo/issues/7/comments"),
        ]
        .map(|(m, t)| (m, t.to_owned()))
    );
    for (method, target) in &shown {
        assert!(matches!(*method, "GET" | "POST"));
        assert!(!target.to_ascii_lowercase().contains("merge"), "{target}");
    }
}

#[test]
fn failure_details_never_carry_secrets() {
    let windows: Vec<String> = key_base64()
        .as_bytes()
        .windows(16)
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .collect();
    let echo = |status: u16| {
        move |seen: &Seen| {
            let authorization = seen.header("authorization").unwrap_or_default().to_owned();
            let mut o = boneli_json::Object::new();
            o.insert(
                "message",
                boneli_json::Value::String(format!("bad credentials {authorization}")),
            );
            Reply::http(
                status,
                &[],
                &boneli_json::to_vec(&boneli_json::Value::Object(o)).expect("JSON"),
            )
        }
    };
    let check = |failure: &JobFailure, fake: &Fake| {
        let detail = format!("{} {failure:?}", failure.detail());
        for seen in fake.seen() {
            let bearer = seen.bearer().expect("bearer");
            assert!(!detail.contains(bearer), "{detail}");
        }
        for k in 1..=4 {
            assert!(!detail.contains(&hub_token(k)), "{detail}");
        }
        for w in &windows {
            assert!(!detail.contains(w.as_str()), "{detail}");
        }
    };
    for status in [400, 401, 403, 404, 422, 500, 503] {
        // The token exchange echoes the JWT.
        let clock = FakeClock::at(T0);
        let fake = Fake::new(echo(status));
        let github = forge(tokens(&fake, &clock), Arc::new(FakeGit::default()));
        let failure = github
            .post_questions(&ticket("7"), &["q".to_owned()])
            .expect_err("refused");
        assert!(failure.detail().contains("[redacted]"), "{failure:?}");
        check(&failure, &fake);
        // Every other endpoint echoes the token.
        for target in ["/repos/octo-org/demo.repo", "/pulls", "/issues/"] {
            let clock = FakeClock::at(T0);
            let hub = Hub::new(clock.clone());
            let reply = echo(status);
            let fake = hub.fake(move |seen| {
                (!seen.is_token_exchange() && seen.target.contains(target)).then(|| reply(seen))
            });
            let github = forge(tokens(&fake, &clock), Arc::new(FakeGit::default()));
            let failure = if target == "/issues/" {
                github
                    .post_questions(&ticket("7"), &["q".to_owned()])
                    .expect_err("refused")
            } else {
                github.open_pull_request(&request()).expect_err("refused")
            };
            assert!(failure.detail().contains("[redacted]"), "{failure:?}");
            check(&failure, &fake);
        }
    }
}

#[test]
fn debug_output_redacts() {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(|_| None);
    let tokens = tokens(&fake, &clock);
    let token = tokens.token().expect("a token");
    let github = forge(tokens.clone(), Arc::new(FakeGit::default()));
    let shown = format!(
        "{github:?} {tokens:?} {token:?} {:?} {:?}",
        key(),
        tokens.git_authorization().map(|_| "value")
    );
    assert!(!shown.contains(token.expose()), "{shown}");
    assert!(shown.contains("[redacted]"), "{shown}");
    for w in key_base64().as_bytes().windows(16) {
        assert!(
            !shown.contains(std::str::from_utf8(w).expect("ASCII")),
            "{shown}"
        );
    }
}

#[test]
fn github_issue_key_forms() {
    for (key, ok) in [
        ("1", true),
        ("18446744073709551615", true),
        ("0", false),
        ("0123", false),
        ("+1", false),
        ("\u{ff11}\u{ff12}\u{ff13}", false),
        ("12 ", false),
        (" 12", false),
        ("1\u{a0}", false),
        ("18446744073709551616", false),
        ("CONTRACT-1", false),
        ("", false),
    ] {
        assert_eq!(render::github_issue_number(key).is_some(), ok, "{key:?}");
        let clock = FakeClock::at(T0);
        let hub = Hub::new(clock.clone());
        let fake = hub.fake(|_| None);
        let github = forge(tokens(&fake, &clock), Arc::new(FakeGit::default()));
        let result = github.post_questions(&ticket(key), &["q".to_owned()]);
        assert_eq!(result.is_ok(), ok, "{key:?}: {result:?}");
        if ok {
            let comment = fake.api_calls().pop().expect("posted");
            assert_eq!(
                comment.target,
                format!("/repos/octo-org/demo.repo/issues/{key}/comments")
            );
        } else {
            assert!(fake.seen().is_empty(), "{key:?}: no request");
        }
    }
    // Another tracker: refused before any request.
    for source in [
        TicketSource::Jira,
        TicketSource::GitLab,
        TicketSource::Sentry,
    ] {
        let clock = FakeClock::at(T0);
        let hub = Hub::new(clock.clone());
        let fake = hub.fake(|_| None);
        let github = forge(tokens(&fake, &clock), Arc::new(FakeGit::default()));
        let mut ticket = ticket("7");
        ticket.source = source;
        let failure = github
            .post_questions(&ticket, &["q".to_owned()])
            .expect_err("refused");
        assert!(
            failure.detail().contains("this forge posts on issues of"),
            "{failure:?}"
        );
        assert!(fake.seen().is_empty());
    }
}

#[test]
fn no_questions_no_comment() {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(|_| None);
    let github = forge(tokens(&fake, &clock), Arc::new(FakeGit::default()));
    let failure = github.post_questions(&ticket("7"), &[]).expect_err("empty");
    assert!(failure.detail().contains("no questions"), "{failure:?}");
    assert!(fake.seen().is_empty());
    let reference = github
        .post_questions(&ticket("7"), &["Which version?".to_owned()])
        .expect("one question");
    assert_eq!(reference.as_str(), "comment/9001");
    let posted = fake.api_calls().pop().expect("posted");
    let body = posted.body_json();
    let text = body.get("body").and_then(|v| v.as_str()).expect("a body");
    assert_eq!(
        text,
        render::questions_comment(&["Which version?".to_owned()]).text
    );
    assert_eq!(text.matches("### Question").count(), 1);
    assert!(text.contains("\n\n    Which version?\n"), "{text}");
}

#[test]
fn run_slug_examples() {
    for (run, slug) in [
        ("run-1", "run-1"),
        ("RUN_7", "run-7"),
        ("../x", "x"),
        ("\u{65e5}\u{672c}", "run"),
        ("", "run"),
        ("--", "run"),
        ("a..b", "a-b"),
        ("a/b c", "a-b-c"),
    ] {
        assert_eq!(run_slug(run), slug, "{run:?}");
    }
    assert_eq!(run_slug(&"a".repeat(300)), "a".repeat(40));
    // A cut that ends on `-` is trimmed again.
    let edge = format!("{}-b", "a".repeat(39));
    assert_eq!(run_slug(&edge), "a".repeat(39));
    let longest = branch_name(&RunId::new("x".repeat(300)), [0xff; 4]).expect("valid");
    assert_eq!(longest.as_str().len(), 56);
    assert_eq!(
        branch_name(&RunId::new("RUN_7".to_owned()), [0x01, 0x23, 0xab, 0xcd])
            .expect("valid")
            .as_str(),
        "boneli/run-7-0123abcd"
    );
}

#[test]
fn branch_names_differ_per_call() {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(|_| None);
    let git = Arc::new(FakeGit::default());
    let github = forge(tokens(&fake, &clock), git.clone());
    let first = github.open_pull_request(&request()).expect("first");
    let second = github.open_pull_request(&request()).expect("second");
    assert_ne!(first, second);
    let branches = git.branches();
    assert_eq!(branches.len(), 2);
    assert_ne!(branches[0], branches[1]);
    assert!(branches.iter().all(|b| b.starts_with("boneli/run-1-")));
    assert_eq!(fake.exchanges(), 1, "one token serves both");
}

#[test]
fn rendered_body_fits_the_cap() {
    let mut big = request();
    big.analysis.content = vec![b'a'; 200_000];
    big.test.content = vec![b't'; 200_000];
    let body = render::pull_request_body(&big, &repository());
    assert!(body.text.len() <= MAX_BODY);
    assert_eq!(body.cut, [1, 2]);
}
