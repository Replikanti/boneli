//! Registry credentials (ADR-039, D2 and D4) against the fake registry:
//! the Basic and the token flow, where credentials and tokens go, how a
//! refusal is classified, and that no failure detail or `Debug` output
//! carries a secret. The fake records every request, so every test can
//! check every request the client made, the signature lookups included
//! (`signatures.rs`, `signature_lookups_inherit_the_credentials`).

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use boneli_app::{ImageError, ImageOrigin, ImageRef, ImageStore};
use boneli_https::{BasicCredentials, Proxy, Roots, TlsConfig};
use boneli_oci::{
    Client, FetchLimits, IO_TIMEOUT, MIN_RATE, OciImageStore, PROXIED_SETUP_TIMEOUT, PullError,
    Reference, Registry, SETUP_TIMEOUT, StoreConfig, Timeouts,
};

use support::TempDir;
use support::images::{Layer, Pushed, config, push};
use support::registry::{Fake, Flow, Hub, Private, Reply, Seen};

/// A distinctive 24-character username and 40-character password, and a
/// 40-character token, so a scan for them cannot match by chance.
const USER: &str = "rEg-u5Er9q8RzT3vW1xY7kLm";
const PASS: &str = "rEg-pA55w0rD9xK2mN7qR4tV6yZ8bC1dF3gH5jL7";
const SECRET_TOKEN: &str = "tOk-9fH2kL7mQ4rT8vX1zB5nC3dG6jP0sW2yA4eU";

const REPO: &str = "library/app";
const API: &str = "registry-1.docker.io";
const AUTH: &str = "auth.docker.io";

fn credentials() -> BasicCredentials {
    BasicCredentials::new(USER, PASS).expect("credentials")
}

/// `Basic <base64(USER:PASS)>`.
fn basic() -> String {
    credentials().header_value()
}

fn bearer() -> String {
    format!("Bearer {SECRET_TOKEN}")
}

/// Every run of 16 bytes of every secret (the whole secret if shorter):
/// the username, the password, `user:pass` and its base64, the token.
fn secret_windows() -> Vec<String> {
    let encoded = basic()["Basic ".len()..].to_owned();
    let pair = format!("{USER}:{PASS}");
    let mut out = Vec::new();
    for secret in [USER, PASS, pair.as_str(), encoded.as_str(), SECRET_TOKEN] {
        let bytes = secret.as_bytes();
        if bytes.len() <= 16 {
            out.push(secret.to_owned());
        } else {
            out.extend(
                bytes
                    .windows(16)
                    .map(|w| String::from_utf8_lossy(w).into_owned()),
            );
        }
    }
    out
}

fn assert_clean(text: &str, what: &str) {
    for window in secret_windows() {
        assert!(
            !text.contains(&window),
            "{what}: a secret run {window:?} in {text:?}"
        );
    }
}

/// `library/app`: three plain layers under an index.
fn app(hub: &mut Hub) -> Pushed {
    push(
        hub,
        REPO,
        &[
            Layer::file("etc/a", b"a\n"),
            Layer::file("etc/b", b"b\n"),
            Layer::file("etc/c", b"c\n"),
        ],
        r#"{"Cmd":["tool"]}"#,
    )
}

/// A private registry over `library/app` in `flow`, accepting the test
/// credentials.
fn private(flow: Flow) -> (Private, Pushed) {
    let mut hub = Hub::default();
    let pushed = app(&mut hub);
    (Private::new(hub, flow, &basic(), SECRET_TOKEN), pushed)
}

fn fake_of(private: Private) -> Fake {
    Fake::new(move |s| private.handle(s))
}

/// Docker Hub's allowlist entry with the test credentials.
fn hub_registry() -> Registry {
    Registry::docker_hub().with_credentials(credentials())
}

fn store(fake: &Fake, registry: Registry) -> (TempDir, OciImageStore) {
    store_with(fake, vec![registry.clone()], registry)
}

fn store_with(
    fake: &Fake,
    registries: Vec<Registry>,
    default: Registry,
) -> (TempDir, OciImageStore) {
    let tmp = TempDir::new("creds");
    let mut config = config(fake);
    config.registries = registries;
    config.default_registry = default;
    let store = OciImageStore::open(&tmp.path().join("store"), config).expect("open");
    (tmp, store)
}

fn image_ref(name: &str, digest: &str) -> ImageRef {
    ImageRef {
        name: name.to_owned(),
        digest: digest.to_owned(),
        platform: "linux/amd64".to_owned(),
        origin: ImageOrigin::Operator,
    }
}

fn pull(store: &OciImageStore, digest: &str) -> Result<String, ImageError> {
    pull_name(store, REPO, digest)
}

fn pull_name(store: &OciImageStore, name: &str, digest: &str) -> Result<String, ImageError> {
    store
        .pull(&image_ref(name, digest))
        .map(|p| p.rootfs.as_str().to_owned())
}

fn failed_detail(result: Result<String, ImageError>, what: &str) -> String {
    match result {
        Err(ImageError::Failed { detail }) => {
            assert_clean(&detail, what);
            detail
        }
        other => panic!("{what}: expected Failed, got {other:?}"),
    }
}

fn is_token_request(s: &Seen) -> bool {
    s.host == AUTH && s.target.starts_with("/token")
}

fn auth(s: &Seen) -> Option<&str> {
    s.header("authorization")
}

/// What each recorded request may carry (ADR-039, D2): the token request
/// the credentials, the API host the credentials (Basic flow) or the
/// token, every other host nothing; and no secret in any target, query
/// or other header field, in any flow.
fn assert_scoped(seen: &[Seen], flow: Flow, token_requests: &dyn Fn(&Seen) -> bool) {
    let basic = basic();
    let bearer = bearer();
    for s in seen {
        let carried = auth(s);
        if token_requests(s) {
            assert_eq!(carried, Some(basic.as_str()), "token request {s:?}");
        } else if s.host == API {
            let allowed = match flow {
                Flow::Basic => basic.as_str(),
                Flow::Token | Flow::Both => bearer.as_str(),
            };
            assert!(
                carried.is_none() || carried == Some(allowed),
                "API request {s:?}"
            );
        } else {
            assert_eq!(carried, None, "{}:{} got Authorization", s.host, s.port);
        }
        assert_clean(&s.target, "a request target");
        for (name, value) in &s.headers {
            if !name.eq_ignore_ascii_case("authorization") {
                assert_clean(value, "a request field");
            }
        }
    }
}

// --- The Basic flow -------------------------------------------------------

/// A `Basic` challenge from the API host with credentials configured: one
/// retry with Basic, to the API host only. The first request carries
/// nothing (no credentials before the host's own challenge), and no token
/// host is asked.
#[test]
fn basic_challenge_with_credentials() {
    let (private, pushed) = private(Flow::Basic);
    let fake = fake_of(private);
    let (_tmp, store) = store(&fake, hub_registry());
    assert_eq!(pull(&store, &pushed.index).expect("pull"), pushed.manifest);
    let seen = fake.seen();
    assert_eq!(auth(&seen[0]), None, "credentials before a challenge");
    let bare = seen.iter().filter(|s| auth(s).is_none()).count();
    assert_eq!(bare, 1, "one challenge per pull: {seen:?}");
    assert!(seen.iter().all(|s| s.host == API), "{seen:?}");
    assert_scoped(&seen, Flow::Basic, &|_| false);
    assert!(
        seen.iter()
            .skip(1)
            .all(|s| auth(s) == Some(basic().as_str()))
    );
}

/// A `Basic` challenge without configured credentials fails, names the
/// registry and sends nothing more.
#[test]
fn basic_challenge_without_credentials_is_failed() {
    let (private, pushed) = private(Flow::Basic);
    let fake = fake_of(private);
    let (_tmp, store) = store(&fake, Registry::docker_hub());
    let detail = failed_detail(pull(&store, &pushed.index), "no credentials");
    assert!(
        detail.contains("asks for credentials (Basic)")
            && detail.contains("none are configured for docker.io"),
        "{detail}"
    );
    let seen = fake.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(auth(&seen[0]), None);
}

/// Credentials the API host refuses: the second `401` is `Failed`, never
/// `NotFound`, after exactly one retry.
#[test]
fn basic_second_401_is_failed() {
    let (mut private, pushed) = private(Flow::Basic);
    private.basic = BasicCredentials::new("someone", "else")
        .expect("other")
        .header_value();
    let fake = fake_of(private);
    let (_tmp, store) = store(&fake, hub_registry());
    let detail = failed_detail(pull(&store, &pushed.index), "refused credentials");
    assert!(
        detail.contains("refused the configured credentials") && detail.contains("(401)"),
        "{detail}"
    );
    let seen = fake.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(auth(&seen[1]), Some(basic().as_str()));
}

// --- The token flow -------------------------------------------------------

/// The token request carries the credentials; the API gets the token
/// only, never the password.
#[test]
fn token_request_carries_credentials() {
    let (private, pushed) = private(Flow::Token);
    let fake = fake_of(private);
    let (_tmp, store) = store(&fake, hub_registry());
    assert_eq!(pull(&store, &pushed.index).expect("pull"), pushed.manifest);
    let seen = fake.seen();
    let tokens: Vec<&Seen> = seen.iter().filter(|s| is_token_request(s)).collect();
    assert_eq!(tokens.len(), 1, "{seen:?}");
    assert_scoped(&seen, Flow::Token, &is_token_request);
    assert!(
        seen.iter()
            .filter(|s| s.host == API)
            .all(|s| auth(s) != Some(basic().as_str()))
    );
}

/// The token host refusing the credentials (`401` or `403`) fails the
/// pull, naming the host, port and status and no secret.
#[test]
fn token_host_refusing_credentials_is_failed() {
    for status in [401, 403] {
        let (private, pushed) = private(Flow::Token);
        let fake = Fake::new(move |s| {
            if is_token_request(s) {
                Reply::http(
                    status,
                    &[("WWW-Authenticate", r#"Basic realm="token""#)],
                    b"",
                )
            } else {
                private.handle(s)
            }
        });
        let (_tmp, store) = store(&fake, hub_registry());
        let detail = failed_detail(pull(&store, &pushed.index), "token host refusal");
        assert!(
            detail.contains(&format!(
                "auth.docker.io:443 refused the configured credentials ({status})"
            )),
            "{detail}"
        );
        assert_eq!(
            fake.seen().iter().filter(|s| is_token_request(s)).count(),
            1
        );
    }
}

/// GHCR's shape: the realm on the API host itself, allowlisted as a token
/// host. Basic goes on the token request only, the token to the API.
#[test]
fn realm_on_the_api_host_with_credentials() {
    let (mut private, pushed) = private(Flow::Token);
    private.realm = format!("https://{API}/token");
    let fake = fake_of(private);
    let registry = Registry::new("docker.io", API, &[API], &[])
        .expect("registry")
        .with_credentials(credentials());
    let (_tmp, store) = store(&fake, registry);
    assert_eq!(pull(&store, &pushed.index).expect("pull"), pushed.manifest);
    let seen = fake.seen();
    let to_realm = |s: &Seen| s.host == API && s.target.starts_with("/token");
    assert_eq!(seen.iter().filter(|s| to_realm(s)).count(), 1);
    for s in &seen {
        if to_realm(s) {
            assert_eq!(auth(s), Some(basic().as_str()));
        } else {
            assert!(
                auth(s).is_none() || auth(s) == Some(bearer().as_str()),
                "{s:?}"
            );
        }
    }
}

/// A `Basic` and a `Bearer` challenge together: the Bearer flow, so the
/// password never reaches the API host.
#[test]
fn bearer_preferred_over_basic() {
    let (private, pushed) = private(Flow::Both);
    let fake = fake_of(private);
    let (_tmp, store) = store(&fake, hub_registry());
    assert_eq!(pull(&store, &pushed.index).expect("pull"), pushed.manifest);
    let seen = fake.seen();
    assert!(seen.iter().any(is_token_request));
    assert_scoped(&seen, Flow::Both, &is_token_request);
}

/// The token expires on the last blob: one new token request, with the
/// credentials again, and the pull completes.
#[test]
fn token_expiry_on_the_last_blob() {
    let (private, pushed) = private(Flow::Token);
    let last = format!("/blobs/{}", pushed.blobs.last().expect("a layer"));
    let expired = Arc::new(AtomicBool::new(false));
    let fake = {
        let expired = Arc::clone(&expired);
        Fake::new(move |s| {
            if s.host == API && s.target.ends_with(&last) && !expired.swap(true, Ordering::SeqCst) {
                let challenge = format!(
                    r#"Bearer realm="https://{AUTH}/token",service="private",scope="repository:{REPO}:pull""#
                );
                return Reply::http(401, &[("WWW-Authenticate", &challenge)], b"");
            }
            private.handle(s)
        })
    };
    let (_tmp, store) = store(&fake, hub_registry());
    assert_eq!(pull(&store, &pushed.index).expect("pull"), pushed.manifest);
    assert!(expired.load(Ordering::SeqCst));
    let seen = fake.seen();
    assert_eq!(seen.iter().filter(|s| is_token_request(s)).count(), 2);
    assert_scoped(&seen, Flow::Token, &is_token_request);
}

// --- Host scoping ---------------------------------------------------------

/// Over a 3-hop redirect chain of the CDN, every request is checked:
/// Basic only on the token request (token flow) or on the API host (Basic
/// flow), the token only on the API host, nothing on the CDN hosts and no
/// secret in any target or query.
#[test]
fn credentials_and_tokens_reach_only_their_hosts() {
    for flow in [Flow::Basic, Flow::Token, Flow::Both] {
        let (mut private, pushed) = private(flow);
        private.chain = ["a.docker.com", "b.docker.com", "c.docker.com"]
            .map(str::to_owned)
            .to_vec();
        let fake = fake_of(private);
        let (_tmp, store) = store(&fake, hub_registry());
        assert_eq!(pull(&store, &pushed.index).expect("pull"), pushed.manifest);
        let seen = fake.seen();
        assert!(
            seen.iter().any(|s| s.host == "c.docker.com"),
            "{flow:?}: the chain was not followed"
        );
        assert_scoped(&seen, flow, &is_token_request);
        for (host, _) in fake.dials() {
            assert!(
                [API, AUTH, "a.docker.com", "b.docker.com", "c.docker.com"]
                    .contains(&host.as_str()),
                "{flow:?}: dialed {host}"
            );
        }
    }
}

/// A redirect suffix that covers the token host: a blob redirected there
/// is a redirect like any other and carries nothing.
#[test]
fn redirect_to_the_token_host_carries_no_credentials() {
    let (mut private, pushed) = private(Flow::Token);
    private.chain = vec![AUTH.to_owned()];
    let fake = fake_of(private);
    let registry = Registry::new("docker.io", API, &[AUTH], &[".docker.io"])
        .expect("registry")
        .with_credentials(credentials());
    let (_tmp, store) = store(&fake, registry);
    assert_eq!(pull(&store, &pushed.index).expect("pull"), pushed.manifest);
    let seen = fake.seen();
    let hops: Vec<&Seen> = seen
        .iter()
        .filter(|s| s.host == AUTH && s.target.starts_with("/hop/"))
        .collect();
    assert_eq!(hops.len(), pushed.blobs.len() + 1, "{seen:?}");
    assert!(hops.iter().all(|s| auth(s).is_none()), "{hops:?}");
    assert_scoped(&seen, Flow::Token, &is_token_request);
}

/// A realm off the allowlist is refused before any request goes to it,
/// so it gets no credentials.
#[test]
fn realm_off_the_allowlist_gets_no_credentials() {
    let (mut private, pushed) = private(Flow::Token);
    private.realm = "https://evil.example/token".to_owned();
    let fake = fake_of(private);
    let (_tmp, store) = store(&fake, hub_registry());
    let detail = failed_detail(pull(&store, &pushed.index), "realm off the list");
    assert!(
        detail.contains("evil.example:443 is not on the allowlist"),
        "{detail}"
    );
    assert!(
        fake.dials().iter().all(|(h, _)| h == API),
        "{:?}",
        fake.dials()
    );
}

/// Credentials belong to one allowlist entry: registry A's never go to
/// the default registry or its token host, even when both pulls share a
/// store.
#[test]
fn credentials_follow_the_registry() {
    let (private, pushed_a) = private(Flow::Basic);
    let mut hub = Hub::default();
    let pushed_hub = push(
        &mut hub,
        REPO,
        &[Layer::file("etc/other", b"other\n")],
        r#"{"Cmd":["other"]}"#,
    );
    let fake = Fake::new(move |s| {
        if s.host == "registry.a.example" {
            let mut inner = s.clone();
            inner.host = API.to_owned();
            private.handle(&inner)
        } else {
            hub.handle(s)
        }
    });
    let a = Registry::new("registry.a.example", "registry.a.example", &[], &[])
        .expect("registry")
        .with_credentials(credentials());
    let (_tmp, store) = store_with(
        &fake,
        vec![Registry::docker_hub(), a],
        Registry::docker_hub(),
    );
    pull_name(
        &store,
        &format!("registry.a.example/{REPO}"),
        &pushed_a.index,
    )
    .expect("A");
    pull(&store, &pushed_hub.index).expect("default");
    let seen = fake.seen();
    assert!(seen.iter().any(|s| s.host == AUTH), "the default pull ran");
    for s in &seen {
        if s.host != "registry.a.example" {
            assert!(auth(s).is_none_or(|a| !a.starts_with("Basic ")), "{s:?}");
        }
    }
    assert!(
        seen.iter()
            .any(|s| s.host == "registry.a.example" && auth(s) == Some(basic().as_str()))
    );
}

/// The redirect limit holds with credentials: 10 redirects pass, the 11th
/// is refused, and no CDN host got anything.
#[test]
fn redirect_limit_10_ok_11_refused_with_credentials() {
    for (hops, ok) in [(10, true), (11, false)] {
        let (mut private, pushed) = private(Flow::Basic);
        private.chain = (0..hops).map(|i| format!("h{i}.docker.com")).collect();
        let fake = fake_of(private);
        let (_tmp, store) = store(&fake, hub_registry());
        let result = pull(&store, &pushed.index);
        if ok {
            assert_eq!(result.expect("10 redirects"), pushed.manifest);
        } else {
            let detail = failed_detail(result, "11 redirects");
            assert!(detail.contains("more than 10 redirects"), "{detail}");
            let followed = fake
                .seen()
                .iter()
                .filter(|s| s.host.ends_with(".docker.com"))
                .count();
            assert_eq!(followed, 10, "the 11th redirect was followed");
        }
        assert_scoped(&fake.seen(), Flow::Basic, &|_| false);
    }
}

/// A `401` with a `Basic` challenge from a redirect host is that host's
/// status, not the registry's challenge: the pull fails and nothing more
/// is sent, to it or to the token host.
#[test]
fn challenge_from_a_redirect_host_sends_nothing() {
    for flow in [Flow::Basic, Flow::Token] {
        let (mut private, pushed) = private(flow);
        private.chain = vec!["cdn.docker.com".to_owned()];
        let fake = Fake::new(move |s| {
            if s.host == "cdn.docker.com" {
                Reply::http(401, &[("WWW-Authenticate", r#"Basic realm="cdn""#)], b"")
            } else {
                private.handle(s)
            }
        });
        let (_tmp, store) = store(&fake, hub_registry());
        let detail = failed_detail(pull(&store, &pushed.index), "CDN 401");
        assert!(
            detail.contains("cdn.docker.com:443 answered 401"),
            "{detail}"
        );
        let seen = fake.seen();
        let cdn: Vec<&Seen> = seen.iter().filter(|s| s.host == "cdn.docker.com").collect();
        assert_eq!(cdn.len(), 1, "{flow:?}: {seen:?}");
        assert_eq!(auth(cdn[0]), None);
        assert!(seen.iter().filter(|s| is_token_request(s)).count() <= 1);
        assert_scoped(&seen, flow, &is_token_request);
    }
}

// --- Secrets in details and Debug -----------------------------------------

/// The secrets a hostile registry that holds them echoes back.
fn echo() -> String {
    format!("{USER} {PASS} {} {SECRET_TOKEN}", basic())
}

/// The same, with no spaces, for places a space would end.
fn echo_word() -> String {
    format!("{USER}{PASS}{}{SECRET_TOKEN}", &basic()["Basic ".len()..])
}

/// A raw response: `status` with `echo` as its reason phrase, in a field
/// and as the body, plus `fields`.
fn hostile(status: u16, fields: &[(&str, String)], body: &[u8]) -> Reply {
    let mut out = format!("HTTP/1.1 {status} {}\r\nX-Echo: {}\r\n", echo(), echo());
    for (name, value) in fields {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    Reply::Raw(bytes)
}

/// Where the hostile registry turns on the client.
#[derive(Clone, Copy, Debug)]
enum At {
    /// A manifest request with the token.
    Manifest,
    /// A blob request with the token.
    Blob,
    /// The token request.
    Token,
    /// The first API request, before any credentials.
    Challenge,
    /// A manifest request with the token, answered with the right bytes
    /// and the secrets as its `Content-Type`.
    ManifestType,
}

/// Every failure path a hostile registry can drive, each with the
/// secrets echoed into the reason phrase, a field and the body: statuses
/// the client cannot continue from, redirects to hosts off the list and
/// to unparsable places, challenges whose realm or parameters hold the
/// secrets, unusable tokens and a document whose `Content-Type` holds
/// them.
fn hostile_cases() -> Vec<(At, Reply)> {
    let echo_body = echo().into_bytes();
    let word = echo_word();
    let mut cases = Vec::new();
    for at in [At::Manifest, At::Blob, At::Token, At::Challenge] {
        for status in [400, 403, 404, 429, 500, 502] {
            cases.push((at, hostile(status, &[], &echo_body)));
        }
    }
    for at in [At::Manifest, At::Blob] {
        for location in [
            format!("https://{}.example/x", word.to_ascii_lowercase()),
            format!("https://evil.example/{word}"),
            format!("https://{word}/x"),
            format!("http://cdn.docker.com/{word}"),
            format!("{word}\u{7f}"),
        ] {
            cases.push((at, hostile(307, &[("Location", location)], b"")));
        }
        cases.push((at, hostile(401, &[], &echo_body)));
    }
    for challenge in [
        format!(r#"Bearer realm="https://{word}/t""#),
        format!(
            r#"Bearer realm="https://{}.example/t""#,
            word.to_ascii_lowercase()
        ),
        format!(
            r#"Bearer realm="https://{AUTH}/token",{w}=1,{w}=2"#,
            w = &word[..60]
        ),
        format!(r#"Bearer realm="https://{AUTH}/token", Bearer realm="{word}""#),
        format!("Bearer {word}"),
        format!("{word} x"),
    ] {
        cases.push((
            At::Challenge,
            hostile(401, &[("WWW-Authenticate", challenge)], &echo_body),
        ));
    }
    cases.push((At::ManifestType, Reply::Raw(Vec::new())));
    for body in [
        format!(r#"{{"token":"{}"}}"#, echo()),
        format!(r#"{{"token":1,"x":"{}"}}"#, echo()),
        format!(r#"{{"x":"{}""#, echo()),
    ] {
        cases.push((At::Token, hostile(200, &[], body.as_bytes())));
    }
    cases
}

/// The hostile registry: a private registry in the token flow that turns
/// on the client once, at `at`.
fn hostile_fake(private: Private, pushed: &Pushed, at: At, reply: Reply) -> Fake {
    let reply = Arc::new(std::sync::Mutex::new(Some(reply)));
    let blob = format!("/blobs/{}", pushed.blobs[0]);
    Fake::new(move |s| {
        let hit = match at {
            At::Manifest | At::ManifestType => {
                s.host == API && s.target.contains("/manifests/") && auth(s).is_some()
            }
            At::Blob => s.host == API && s.target.ends_with(&blob) && auth(s).is_some(),
            At::Token => is_token_request(s),
            At::Challenge => s.host == API && auth(s).is_none(),
        };
        if hit && let Some(reply) = reply.lock().expect("reply").take() {
            if !matches!(at, At::ManifestType) {
                return reply;
            }
            if let Reply::Http {
                status,
                mut headers,
                body,
            } = private.handle(s)
            {
                headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-type"));
                headers.push(("Content-Type".to_owned(), echo()));
                return Reply::Http {
                    status,
                    headers,
                    body,
                };
            }
        }
        private.handle(s)
    })
}

/// No failure detail of the store carries a secret, on every path of
/// [`hostile_cases`], in both flows.
#[test]
fn store_failure_details_never_carry_secrets() {
    let mut failures = 0;
    for flow in [Flow::Basic, Flow::Token] {
        for (i, (at, reply)) in hostile_cases().into_iter().enumerate() {
            if flow == Flow::Basic && matches!(at, At::Token) {
                continue;
            }
            let (private, pushed) = private(flow);
            let fake = hostile_fake(private, &pushed, at, reply);
            let (_tmp, store) = store(&fake, hub_registry());
            match pull(&store, &pushed.index) {
                Ok(_) => {}
                Err(e) => {
                    failures += 1;
                    let what = format!("{flow:?} case {i} at {at:?}");
                    assert_clean(&e.to_string(), &what);
                    assert_clean(&format!("{e:?}"), &what);
                }
            }
        }
    }
    assert!(failures > 40, "only {failures} cases failed");
}

/// The registry client's own failures, through its public API, carry no
/// secret either.
#[test]
fn failure_details_never_carry_secrets() {
    let limits = FetchLimits::new(
        boneli_json::Limits::new(4_194_304, 16, 65_536).expect("json"),
        65_536,
        16_384,
        64,
        128,
        4_294_967_296,
        17_196_646_400,
    )
    .expect("limits");
    let timeouts =
        Timeouts::new(Duration::from_secs(5), Duration::from_secs(10), 1 << 20).expect("timeouts");
    let registry = hub_registry();
    let mut failures = 0;
    for (i, (at, reply)) in hostile_cases().into_iter().enumerate() {
        let (private, pushed) = private(Flow::Token);
        let fake = hostile_fake(private, &pushed, at, reply);
        let reference = Reference::parse(REPO, &pushed.index, "linux/amd64").expect("reference");
        let result: Result<_, PullError> =
            Client::new(&registry, &fake, &limits, &timeouts).resolve(&reference);
        if let Err(e) = result {
            failures += 1;
            assert_clean(&e.to_string(), &format!("case {i} at {at:?}"));
            assert_clean(&format!("{e:?}"), &format!("case {i} at {at:?}"));
        }
    }
    assert!(failures > 20, "only {failures} cases failed");
}

/// An image name with userinfo is refused before any connection, and the
/// detail shows `[userinfo]` in its place.
#[test]
fn image_name_userinfo_never_echoed() {
    let (private, pushed) = private(Flow::Basic);
    let fake = fake_of(private);
    let (_tmp, store) = store(&fake, hub_registry());
    for name in [
        format!("{USER}:{PASS}@ghcr.io/x/y"),
        format!("{PASS}@localhost/x/y"),
        format!("{USER}:{PASS}@ghcr.io"),
        format!("ghcr.io/x/{PASS}@y"),
    ] {
        let detail = failed_detail(pull_name(&store, &name, &pushed.index), &name);
        assert!(detail.contains("[userinfo]"), "{detail}");
    }
    assert!(fake.dials().is_empty(), "{:?}", fake.dials());
}

/// `Debug` of a registry and of a store configuration with credentials,
/// and with a proxy that has its own, shows no secret.
#[test]
fn debug_output_redacts_credentials() {
    let registry = hub_registry();
    let text = format!("{registry:?}");
    assert_clean(&text, "Registry");
    assert!(text.contains("[redacted]"), "{text}");
    let proxy = Proxy::new("proxy.corp.example", 3128)
        .expect("proxy")
        .with_credentials(credentials());
    let tls = TlsConfig::new(Roots::mozilla())
        .expect("tls")
        .with_proxy(proxy);
    let mut config = StoreConfig::production(tls).expect("config");
    config.registries = vec![registry.clone()];
    config.default_registry = registry;
    assert_clean(&format!("{config:?}"), "StoreConfig");
}

/// A store over a proxied TLS configuration gets the proxied setup time
/// (ADR-039, D9), a direct one ADR-009's.
#[test]
fn proxied_store_uses_the_proxied_setup() {
    assert_eq!(PROXIED_SETUP_TIMEOUT, Duration::from_secs(40));
    let tls = TlsConfig::new(Roots::mozilla()).expect("tls");
    let direct = StoreConfig::production(tls.clone()).expect("direct");
    assert_eq!(
        direct.timeouts,
        Timeouts::new(IO_TIMEOUT, SETUP_TIMEOUT, MIN_RATE).expect("timeouts")
    );
    let proxy = Proxy::new("10.0.0.1", 3128).expect("proxy");
    let proxied = StoreConfig::production(tls.with_proxy(proxy)).expect("proxied");
    assert_eq!(
        proxied.timeouts,
        Timeouts::new(IO_TIMEOUT, PROXIED_SETUP_TIMEOUT, MIN_RATE).expect("timeouts")
    );
}

/// Hosts the server chose reach a detail as they are, lowercase: a
/// registry holding lowercase credentials or a lowercase token can put
/// them into a realm or a redirect host. The client's redaction takes
/// them out (ADR-039, D4).
#[test]
fn hosts_holding_secrets_are_redacted() {
    let user = "lowercase-user-0123456789abcdef";
    let pass = "lowercase-pass-0123456789abcdef0123456789";
    let token = "lowercase-token-0123456789abcdef01234567";
    let credentials = BasicCredentials::new(user, pass).expect("credentials");
    let basic = credentials.header_value();
    let registry = Registry::docker_hub().with_credentials(credentials);
    let cases: [(&str, String); 3] = [
        ("realm", format!("https://{pass}.example/token")),
        ("realm", format!("https://{user}.example/token")),
        ("redirect", format!("{token}.example")),
    ];
    for (kind, value) in cases {
        let mut hub = Hub::default();
        let pushed = app(&mut hub);
        let mut private = Private::new(hub, Flow::Token, &basic, token);
        if kind == "realm" {
            private.realm = value.clone();
        } else {
            private.chain = vec![value.clone()];
        }
        let fake = fake_of(private);
        let (_tmp, store) = store(&fake, registry.clone());
        let detail = match pull(&store, &pushed.index) {
            Err(ImageError::Failed { detail }) => detail,
            other => panic!("{kind}: expected Failed, got {other:?}"),
        };
        assert!(detail.contains("[redacted]"), "{detail}");
        for secret in [user, pass, token] {
            for window in secret.as_bytes().windows(16) {
                let window = std::str::from_utf8(window).expect("ASCII");
                assert!(!detail.contains(window), "{window:?} in {detail:?}");
            }
        }
    }
}
