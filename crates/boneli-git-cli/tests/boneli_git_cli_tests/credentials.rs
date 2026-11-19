//! Credentials: the `Authorization` value reaches only the network git
//! calls, as one command-scope pair scoped to the repository URL, is
//! checked before any process starts, and never shows in a failure
//! detail or a snapshot (ADR-014, D3; ADR-010, D4).

use std::sync::{Arc, Mutex};

use boneli_app::{BranchName, CommitInfo, Git, GitError, RepoUrl};
use boneli_git_cli::{Credentials, DEFAULT_MAX_NODES, MAX_AUTHORIZATION};

use crate::support::record::{Call, Recorder};
use crate::support::{
    EDITED, TempDir, contract_source, decode, edit, failed, host_git, open_with, path, sha,
    tracing_git, write_executable,
};

/// The secret part of [`VALUE`].
const SECRET: &str = "eC1hY2Nlc3MtdG9rZW46c2VjcmV0";
/// What the test credentials hand out.
const VALUE: &str = "Basic eC1hY2Nlc3MtdG9rZW46c2VjcmV0";

/// The subcommands that talk to the remote.
const NETWORK: &[&str] = &["fetch", "ls-remote", "push"];

/// Credentials that answer with a fixed result and record every URL they
/// were asked for.
struct Fixed {
    answer: Mutex<Result<Option<String>, String>>,
    asked: Mutex<Vec<String>>,
}

impl Fixed {
    fn new(answer: Result<Option<String>, String>) -> Arc<Fixed> {
        Arc::new(Fixed {
            answer: Mutex::new(answer),
            asked: Mutex::new(Vec::new()),
        })
    }

    fn set(&self, answer: Result<Option<String>, String>) {
        *self.answer.lock().expect("not poisoned") = answer;
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("not poisoned").clone()
    }
}

impl Credentials for Fixed {
    fn authorization(&self, url: &RepoUrl) -> Result<Option<String>, String> {
        self.asked
            .lock()
            .expect("not poisoned")
            .push(url.as_str().to_owned());
        self.answer.lock().expect("not poisoned").clone()
    }
}

fn info() -> CommitInfo {
    CommitInfo::new("t", "t@example.invalid", "m\n").expect("valid")
}

fn branch(name: &str) -> BranchName {
    BranchName::parse(name).expect("valid")
}

/// The `http.*.extraHeader` pairs of a call's command-scope config, and
/// whether `GIT_CONFIG_COUNT` covers every pair.
fn headers(call: &Call) -> Vec<(String, String)> {
    let count: usize = call
        .var("GIT_CONFIG_COUNT")
        .expect("a count")
        .parse()
        .expect("a number");
    let mut out = Vec::new();
    for n in 0..count {
        let key = call
            .var(&format!("GIT_CONFIG_KEY_{n}"))
            .unwrap_or_else(|| panic!("no key {n}: {call:?}"));
        let value = call
            .var(&format!("GIT_CONFIG_VALUE_{n}"))
            .unwrap_or_else(|| panic!("no value {n}: {call:?}"));
        if key.starts_with("http.") && key.ends_with(".extraHeader") {
            out.push((key.to_owned(), value.to_owned()));
        }
    }
    assert!(
        call.var(&format!("GIT_CONFIG_KEY_{count}")).is_none(),
        "{call:?}"
    );
    out
}

/// Every operation of the port through a recording git, with credentials.
#[test]
fn authorization_only_on_network_calls() {
    let tmp = TempDir::new("cred-network");
    let (source, base) = contract_source(&tmp);
    let recorder = Recorder::new(&tmp);
    let creds = Fixed::new(Ok(Some(VALUE.to_owned())));
    let git = open_with(&tmp, &recorder.git, DEFAULT_MAX_NODES, Some(creds.clone()));
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    git.read(&c, &path("src/lib.rs")).expect("read");
    let workspace = edit(&snapshot, &path("src/lib.rs"), Some(EDITED));
    let diff = git.diff(&c, &workspace).expect("diff");
    let after = git.apply(&c, &diff).expect("apply");
    git.push(&after, &branch("boneli/cred"), &info())
        .expect("push");
    // A fetch of an absent commit runs `ls-remote` and the probe `fetch`
    // as well.
    assert_eq!(
        git.fetch_base(&source.url(), &sha(crate::support::ABSENT)),
        Err(GitError::UnknownCommit)
    );

    let want = (
        format!("http.{}.extraHeader", source.url().as_str()),
        format!("Authorization: {VALUE}"),
    );
    let mut seen = std::collections::BTreeSet::new();
    for call in recorder.calls() {
        let sub = call.subcommand().unwrap_or("").to_owned();
        let got = headers(&call);
        if NETWORK.contains(&sub.as_str()) {
            assert_eq!(got, vec![want.clone()], "{call:?}");
        } else {
            assert_eq!(got, vec![], "{call:?}");
        }
        assert!(
            call.args
                .iter()
                .all(|a| !a.contains(SECRET) && !a.contains("extraHeader")),
            "{call:?}"
        );
        seen.insert(sub);
    }
    for sub in [
        "fetch",
        "ls-remote",
        "push",
        "read-tree",
        "add",
        "write-tree",
        "ls-tree",
        "cat-file",
        "apply",
        "commit-tree",
    ] {
        assert!(seen.contains(sub), "no {sub} call was recorded: {seen:?}");
    }
    // Once per network process: the fetch; the push's `ls-remote` and
    // `push`; the failed fetch, its `ls-remote` and its probe fetch.
    assert_eq!(creds.asked().len(), 6, "{:?}", creds.asked());
}

#[test]
fn authorization_scoped_to_its_url() {
    let tmp = TempDir::new("cred-scope");
    let (source, base) = contract_source(&tmp);
    let recorder = Recorder::new(&tmp);
    let creds = Fixed::new(Ok(Some(VALUE.to_owned())));
    let git = open_with(&tmp, &recorder.git, DEFAULT_MAX_NODES, Some(creds.clone()));
    git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let url = source.url().as_str().to_owned();
    assert_eq!(creds.asked(), vec![url.clone()]);
    let fetch = recorder
        .calls()
        .into_iter()
        .find(|c| c.subcommand() == Some("fetch"))
        .expect("a fetch");
    assert_eq!(
        headers(&fetch),
        vec![(
            format!("http.{url}.extraHeader"),
            format!("Authorization: {VALUE}")
        )]
    );
    // The URL in the key is the one git is given after `--`.
    let at = fetch.args.iter().position(|a| a == "--").expect("--");
    assert_eq!(fetch.args[at + 1], url);
}

/// Credentials that fail start no git process: not at `fetch_base`, and
/// not at `push`, where `commit-tree` would come first.
#[test]
fn credentials_error_fails_closed() {
    let tmp = TempDir::new("cred-error");
    let (source, base) = contract_source(&tmp);
    let recorder = Recorder::new(&tmp);
    let creds = Fixed::new(Err("the token source is down".to_owned()));
    let git = open_with(&tmp, &recorder.git, DEFAULT_MAX_NODES, Some(creds.clone()));
    recorder.clear();
    let detail = failed(git.fetch_base(&source.url(), &sha(&base)));
    assert!(detail.contains("the token source is down"), "{detail}");
    assert_eq!(recorder.calls().len(), 0);
    assert_eq!(
        crate::support::listing(&git.root().join("stores")),
        Vec::<String>::new()
    );

    creds.set(Ok(Some(VALUE.to_owned())));
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    creds.set(Err("the token source is down".to_owned()));
    recorder.clear();
    let detail = failed(git.push(&c, &branch("boneli/down"), &info()));
    assert!(detail.contains("the token source is down"), "{detail}");
    assert_eq!(recorder.calls().len(), 0);
    assert_eq!(crate::support::branch_at(&source.dir, "boneli/down"), None);
}

/// A value that could inject a header or is out of bounds fails before any
/// git process, and the detail never quotes it; the bound itself passes.
#[test]
fn header_value_rules() {
    let tmp = TempDir::new("cred-rules");
    let (source, base) = contract_source(&tmp);
    let recorder = Recorder::new(&tmp);
    let creds = Fixed::new(Ok(None));
    let git = open_with(&tmp, &recorder.git, DEFAULT_MAX_NODES, Some(creds.clone()));
    let long = "a".repeat(MAX_AUTHORIZATION + 1);
    for bad in [
        "Basic x\r\nX-Injected: 1",
        "Basic x\nX-Injected: 1",
        "Basic x\rX",
        "Basic x\0",
        " Basic x",
        "Basic x ",
        "",
        "Basic \u{17E}",
        "Basic\tx",
        long.as_str(),
    ] {
        creds.set(Ok(Some(bad.to_owned())));
        recorder.clear();
        let detail = failed(git.fetch_base(&source.url(), &sha(&base)));
        assert!(detail.contains("refused"), "{bad:?}: {detail}");
        assert!(!detail.contains("Basic"), "{bad:?}: {detail}");
        assert_eq!(recorder.calls().len(), 0, "{bad:?}");
    }
    // The longest value passes and reaches the fetch as given.
    let longest = format!("Basic {}", "a".repeat(MAX_AUTHORIZATION - 6));
    assert_eq!(longest.len(), MAX_AUTHORIZATION);
    creds.set(Ok(Some(longest.clone())));
    recorder.clear();
    git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let fetch = recorder
        .calls()
        .into_iter()
        .find(|c| c.subcommand() == Some("fetch"))
        .expect("a fetch");
    assert_eq!(headers(&fetch)[0].1, format!("Authorization: {longest}"));
    // `None` means no header at all.
    creds.set(Ok(None));
    recorder.clear();
    git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    for call in recorder.calls() {
        assert_eq!(headers(&call), vec![], "{call:?}");
    }
}

/// A git that prints its whole environment to stderr and fails each
/// network call in `failing`; every other call runs the real git.
fn env_dumping_git(tmp: &TempDir, failing: &[&str]) -> std::path::PathBuf {
    let git = tmp.path().join("env-git");
    let cases: String = failing.iter().map(|s| format!(" {s} ")).collect();
    write_executable(
        &git,
        format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do\n\
             case '{cases}' in *\" $a \"*) env >&2; exit 1 ;; esac\n\
             done\n\
             exec '{real}' \"$@\"\n",
            real = host_git().display()
        )
        .as_bytes(),
    );
    git
}

#[test]
fn failure_detail_redacts_authorization() {
    let tmp = TempDir::new("cred-redact");
    let (source, base) = contract_source(&tmp);
    let creds = Fixed::new(Ok(Some(VALUE.to_owned())));

    let fetching = open_with(
        &tmp,
        &env_dumping_git(&tmp, &["fetch", "ls-remote"]),
        DEFAULT_MAX_NODES,
        Some(creds.clone()),
    );
    let detail = failed(fetching.fetch_base(&source.url(), &sha(&base)));
    // Not vacuous: the dump reached the detail, header pair included.
    assert!(detail.contains("GIT_CONFIG_VALUE_"), "{detail}");
    assert!(detail.contains("Authorization: [redacted]"), "{detail}");
    assert!(!detail.contains(SECRET), "{detail}");

    let pushing_git = TempDir::new("cred-redact-push");
    let pushing = open_with(
        &pushing_git,
        &env_dumping_git(&pushing_git, &["push"]),
        DEFAULT_MAX_NODES,
        Some(creds),
    );
    let c = pushing
        .fetch_base(&source.url(), &sha(&base))
        .expect("fetch");
    let detail = failed(pushing.push(&c, &branch("boneli/redact"), &info()));
    assert!(detail.contains("Authorization: [redacted]"), "{detail}");
    assert!(!detail.contains(SECRET), "{detail}");
}

/// The snapshot the sandbox gets holds neither the value nor any http
/// config, whatever the fetch carried.
#[test]
fn snapshot_never_carries_authorization() {
    let tmp = TempDir::new("cred-snapshot");
    let (source, base) = contract_source(&tmp);
    let creds = Fixed::new(Ok(Some(VALUE.to_owned())));
    let git = open_with(&tmp, &host_git(), DEFAULT_MAX_NODES, Some(creds));
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    let window = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    assert!(!window(&snapshot, SECRET.as_bytes()));
    assert!(!window(&snapshot, b"extraHeader"));
    for (p, _, data) in decode(&snapshot).iter() {
        if p.as_str() == ".git/config" {
            let text = String::from_utf8_lossy(data);
            assert!(!text.contains("http"), "{text}");
        }
    }
}

/// `push.negotiate` (ADR-014, D2) makes the push run a child
/// `git fetch --negotiate-only` against the same URL. That child inherits
/// the push's environment, so it reads the same scoped header, once;
/// trace2 logs the `http.*` config every process read.
#[test]
fn negotiation_fetch_carries_the_scoped_header() {
    let tmp = TempDir::new("cred-negotiate");
    let (source, base) = contract_source(&tmp);
    let trace = tmp.path().join("trace2.json");
    let creds = Fixed::new(Ok(Some(VALUE.to_owned())));
    let git = open_with(
        &tmp,
        &tracing_git(&tmp, &trace),
        DEFAULT_MAX_NODES,
        Some(creds),
    );
    let c = git.fetch_base(&source.url(), &sha(&base)).expect("fetch");
    let snapshot = git.snapshot(&c).expect("snapshot");
    let workspace = edit(&snapshot, &path("src/lib.rs"), Some(EDITED));
    let after = git
        .apply(&c, &git.diff(&c, &workspace).expect("diff"))
        .expect("apply");
    source.write("docs/later.md", b"later\n", false);
    source.commit("later");
    let _ = std::fs::remove_file(&trace);
    git.push(&after, &branch("boneli/negotiate"), &info())
        .expect("push");
    let text = std::fs::read_to_string(&trace).expect("a trace");
    let field = |line: &str, name: &str| -> Option<String> {
        let key = format!("\"{name}\":\"");
        let rest = &line[line.find(&key)? + key.len()..];
        Some(rest[..rest.find('"')?].to_owned())
    };
    let negotiating: Vec<String> = text
        .lines()
        .filter(|l| l.contains("\"event\":\"start\"") && l.contains("\"--negotiate-only\""))
        .filter_map(|l| field(l, "sid"))
        .collect();
    assert_eq!(negotiating.len(), 1, "no negotiation ran: {text}");
    let param = format!("http.{}.extraheader", source.url().as_str());
    let read: Vec<(String, String)> = text
        .lines()
        .filter(|l| l.contains("\"event\":\"def_param\""))
        .filter(|l| field(l, "sid").as_deref() == Some(negotiating[0].as_str()))
        .filter_map(|l| Some((field(l, "param")?, field(l, "value")?)))
        .filter(|(p, _)| p.ends_with(".extraheader"))
        .collect();
    assert_eq!(
        read,
        vec![(param, format!("Authorization: {VALUE}"))],
        "{text}"
    );
}
