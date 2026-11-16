//! The registry client against a fake registry (ADR-009, D9 to D12): one
//! test per edge case of the #7 plan, part 2. The fake records every
//! request, so the tests assert what was sent where, and that refused
//! input makes no request at all.

mod support;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use boneli_oci::{
    Client, Descriptor, Digest, FetchLimits, PullError, Reference, Registry, Repository, Resolved,
    Timeouts, select,
};

use support::TempDir;
use support::registry::{
    Fake, Hub, Reply, Seen, TOKEN, challenge_for, config, descriptor, digest_of, entry, image,
    index, manifest, media,
};

const AMD64: (&str, &str, Option<&str>) = ("linux", "amd64", None);

/// The values ADR-009 D12 states.
fn limits() -> FetchLimits {
    let document = boneli_json::Limits::new(4_194_304, 16, 65_536).expect("json limits");
    FetchLimits::new(document, 65_536, 16_384, 64, 128, 4_294_967_296).expect("limits")
}

fn timeouts() -> Timeouts {
    Timeouts::new(Duration::from_secs(5), Duration::from_secs(10), 1 << 20).expect("timeouts")
}

fn any_digest() -> String {
    digest_of(b"anything")
}

fn hub_fake(hub: Hub) -> Fake {
    Fake::new(move |s| hub.handle(s))
}

/// Parses, selects Docker Hub and resolves, the way the store will.
fn resolve_with(
    fake: &Fake,
    name: &str,
    digest: &str,
    platform: &str,
    timeouts: &Timeouts,
) -> Result<Resolved, PullError> {
    let reference = Reference::parse(name, digest, platform)?;
    let hub = Registry::docker_hub();
    let registries = [hub.clone()];
    let registry = select(&registries, &hub, &reference)?;
    let limits = limits();
    Client::new(registry, fake, &limits, timeouts).resolve(&reference)
}

fn resolve(fake: &Fake, name: &str, digest: &str, platform: &str) -> Result<Resolved, PullError> {
    resolve_with(fake, name, digest, platform, &timeouts())
}

fn assert_failed<T: std::fmt::Debug>(got: Result<T, PullError>, what: &str) -> String {
    match got {
        Err(PullError::Failed(detail)) => {
            assert!(!detail.trim().is_empty(), "{what}: blank detail");
            detail
        }
        other => panic!("{what}: expected Failed, got {other:?}"),
    }
}

fn assert_not_found<T: std::fmt::Debug>(got: Result<T, PullError>, what: &str) {
    match got {
        Err(PullError::NotFound(detail)) => assert!(!detail.trim().is_empty(), "{what}"),
        other => panic!("{what}: expected NotFound, got {other:?}"),
    }
}

fn is_api(s: &Seen) -> bool {
    s.host == "registry-1.docker.io"
}

fn authorized(s: &Seen) -> bool {
    s.header("authorization") == Some(&format!("Bearer {TOKEN}"))
}

fn repo(name: &str) -> Repository {
    Repository::parse(name).expect("repository")
}

// --- References and platforms -------------------------------------------

#[test]
fn reference_rejections() {
    let fake = hub_fake(Hub::default());
    for name in [
        "library/n\u{43e}de",
        "library/no\u{200b}de",
        "library/node ",
        "library/node\t",
        "library/no\u{a0}de",
        "library/Node",
        "LIBRARY/node",
        "library//node",
        "/library/node",
        "library/node/",
        "",
    ] {
        assert_failed(resolve(&fake, name, &any_digest(), "linux/amd64"), name);
    }
    assert!(fake.dials().is_empty(), "a refused name made a request");
}

#[test]
fn reference_255_ok_256_refused() {
    let at = |len: usize| format!("library/{}", "a".repeat(len - "library/".len()));
    assert_eq!(at(255).len(), 255);
    assert!(Reference::parse(&at(255), &any_digest(), "linux/amd64").is_ok());
    assert_failed(
        Reference::parse(&at(256), &any_digest(), "linux/amd64"),
        "256",
    );
    // With a registry host the limit applies to the path after it.
    let with_host = format!("docker.io/{}", at(255));
    assert!(Reference::parse(&with_host, &any_digest(), "linux/amd64").is_ok());
}

#[test]
fn digest_rejections() {
    let fake = hub_fake(Hub::default());
    let hex = "a".repeat(64);
    for digest in [
        format!("SHA256:{hex}"),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{}", "a".repeat(63)),
        format!("sha256:{}", "a".repeat(65)),
        format!("sha256:{}\u{200b}{}", "a".repeat(32), "a".repeat(31)),
        format!("sha512:{}", "a".repeat(128)),
        format!("sha256:{}g", "a".repeat(63)),
        format!(" sha256:{hex}"),
        hex.clone(),
    ] {
        assert_failed(
            resolve(&fake, "library/node", &digest, "linux/amd64"),
            &digest,
        );
    }
    assert!(fake.dials().is_empty());
    assert!(Digest::parse(&format!("sha256:{hex}")).is_ok());
}

#[test]
fn platform_rejections() {
    let fake = hub_fake(Hub::default());
    for platform in [
        "linux/amd64 ",
        "Linux/amd64",
        "linux/amd64/",
        "linux",
        "linux/",
        "linux/amd64/v8/x",
        "",
    ] {
        assert_failed(
            resolve(&fake, "library/node", &any_digest(), platform),
            platform,
        );
    }
    assert!(fake.dials().is_empty());
}

/// An index over one image per platform; returns the hub and the index
/// digest.
fn indexed(platforms: &[(&str, &str, Option<&str>)]) -> (Hub, String) {
    let mut hub = Hub::default();
    let mut entries = Vec::new();
    for p in platforms {
        let (digest, size) = image(&mut hub, "library/node", *p, 1);
        entries.push(entry(media::MANIFEST, &digest, size, Some(*p)));
    }
    let bytes = index(&entries);
    let digest = hub.document("library/node", media::INDEX, &bytes);
    (hub, digest)
}

#[test]
fn platform_matching() {
    let pull = |platforms: &[(&str, &str, Option<&str>)], want: &str| {
        let (hub, digest) = indexed(platforms);
        resolve(&hub_fake(hub), "library/node", &digest, want)
    };
    for listed in [("linux", "arm64", None), ("linux", "arm64", Some("v8"))] {
        for want in ["linux/arm64", "linux/arm64/v8"] {
            let got = pull(&[listed, AMD64], want).expect(want);
            assert_eq!(got.config.architecture, "arm64");
        }
    }
    let got = pull(&[("linux", "arm", Some("v7")), AMD64], "linux/arm/v7").expect("arm/v7");
    assert_eq!(got.config.variant.as_deref(), Some("v7"));
    assert_not_found(
        pull(&[("linux", "arm", Some("v7")), AMD64], "linux/arm64"),
        "arm/v7 is not arm64",
    );
    assert_not_found(
        pull(&[("linux", "arm64", None)], "linux/arm/v7"),
        "arm64 is not arm/v7",
    );
    assert_not_found(
        pull(&[("linux", "amd64", Some("v3"))], "linux/amd64"),
        "amd64/v3 is not amd64",
    );
    let detail = assert_failed(pull(&[AMD64, AMD64], "linux/amd64"), "two amd64");
    assert!(detail.contains("more than one"), "{detail}");
    assert_failed(
        pull(
            &[("linux", "arm64", None), ("linux", "arm64", Some("v8"))],
            "linux/arm64",
        ),
        "arm64 and arm64/v8 are the same platform",
    );

    // Attestation entries (unknown/unknown) never match, not even when
    // asked for by name.
    let mut hub = Hub::default();
    let (amd, amd_size) = image(&mut hub, "library/node", AMD64, 1);
    let (att, att_size) = image(&mut hub, "library/node", ("unknown", "unknown", None), 1);
    let bytes = index(&[
        entry(
            media::MANIFEST,
            &att,
            att_size,
            Some(("unknown", "unknown", None)),
        ),
        entry(media::MANIFEST, &amd, amd_size, Some(AMD64)),
    ]);
    let digest = hub.document("library/node", media::INDEX, &bytes);
    let fake = hub_fake(hub);
    let got = resolve(&fake, "library/node", &digest, "linux/amd64").expect("amd64");
    assert_eq!(got.manifest_digest.to_string(), amd);
    assert_not_found(
        resolve(&fake, "library/node", &digest, "unknown/unknown"),
        "attestation",
    );
}

#[test]
fn single_manifest_platform() {
    let mut hub = Hub::default();
    let (digest, _) = image(&mut hub, "library/node", AMD64, 2);
    let fake = hub_fake(hub);
    let got = resolve(&fake, "library/node", &digest, "linux/amd64").expect("amd64");
    assert_eq!(got.index, None);
    assert_eq!(got.manifest_digest.to_string(), digest);
    assert_eq!(got.manifest.layers.len(), 2);
    assert_not_found(
        resolve(&fake, "library/node", &digest, "linux/arm64"),
        "platform-pinned",
    );
}

// --- Hosts, auth, redirects ---------------------------------------------

#[test]
fn registry_allowlist_bypasses() {
    let mut hub = Hub::default();
    let (digest, _) = image(&mut hub, "library/node", AMD64, 1);
    let fake = hub_fake(hub);
    for ok in [
        "REGISTRY-1.DOCKER.IO/library/node",
        "registry-1.docker.io/library/node",
        "registry-1.docker.io:443/library/node",
        "docker.io/library/node",
        "Docker.IO/library/node",
    ] {
        resolve(&fake, ok, &digest, "linux/amd64").expect(ok);
    }
    assert!(fake.seen().iter().all(is_api_or_auth));
    let before = fake.dials().len();
    for bad in [
        "registry-1.docker.io./library/node",
        "registry-1.docker.io.evil.example/library/node",
        "evil-registry-1.docker.io/library/node",
        "xn--rgistry-1-g4a.docker.io/library/node",
        "user@registry-1.docker.io/library/node",
        "user:pw@registry-1.docker.io/library/node",
        "registry-1.docker.io:5000/library/node",
        "docker.io:443/library/node",
        "127.0.0.1/library/node",
        "[::1]/library/node",
        "127.1/library/node",
        "localhost/library/node",
        "localhost:443/library/node",
    ] {
        let detail = assert_failed(resolve(&fake, bad, &digest, "linux/amd64"), bad);
        if bad.contains('@') {
            assert!(detail.contains("userinfo"), "{bad}: {detail}");
        }
    }
    assert_eq!(fake.dials().len(), before, "a refused registry was dialed");
}

fn is_api_or_auth(s: &Seen) -> bool {
    s.host == "registry-1.docker.io" || s.host == "auth.docker.io"
}

/// A hub with one blob whose API answer, once authorized, is `answer`.
fn blob_hub(
    bytes: &[u8],
    answer: impl Fn(&Seen) -> Option<Reply> + Send + Sync + 'static,
) -> (Fake, Descriptor) {
    let mut hub = Hub::default();
    let digest = hub.blob("library/node", bytes);
    hub.cdn = true;
    let fake = Fake::new(move |s| answer(s).unwrap_or_else(|| hub.handle(s)));
    let descriptor = Descriptor {
        media_type: media::TAR.to_owned(),
        digest: Digest::parse(&digest).expect("digest"),
        size: bytes.len() as u64,
    };
    (fake, descriptor)
}

fn get_blob(fake: &Fake, descriptor: &Descriptor, dest: &Path) -> Result<(), PullError> {
    get_blob_with(fake, descriptor, dest, &timeouts())
}

fn get_blob_with(
    fake: &Fake,
    descriptor: &Descriptor,
    dest: &Path,
    timeouts: &Timeouts,
) -> Result<(), PullError> {
    let hub = Registry::docker_hub();
    let limits = limits();
    Client::new(&hub, fake, &limits, timeouts).get_blob(&repo("library/node"), descriptor, dest)
}

/// A blobs directory and the destination of `descriptor` in it.
fn blobs(tmp: &TempDir, descriptor: &Descriptor) -> std::path::PathBuf {
    let dir = tmp.path().join("blobs/sha256");
    std::fs::create_dir_all(&dir).expect("blobs dir");
    dir.join(descriptor.digest.hex())
}

fn entries(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn redirect_suffix_dot_boundary() {
    let tmp = TempDir::new("redirect-suffix");
    let (fake, d) = blob_hub(b"blob bytes", |_| None);
    let dest = blobs(&tmp, &d);
    get_blob(&fake, &d, &dest).expect("the CDN under .docker.com");
    assert_eq!(std::fs::read(&dest).expect("blob"), b"blob bytes");
    assert!(
        fake.seen()
            .iter()
            .any(|s| s.host == "production.cloudfront.docker.com")
    );

    for location in [
        "https://evildocker.com/blob",
        "https://docker.com.evil.example/blob",
        "https://docker.com/blob",
        "https://production.cloudfront.docker.com:8443/blob",
        "https://production.cloudfront.docker.com./blob",
        "https://127.0.0.1/blob",
    ] {
        let tmp = TempDir::new("redirect-refused");
        let target = location.to_owned();
        let (fake, d) = blob_hub(b"blob bytes", move |s| {
            (is_api(s) && authorized(s) && s.target.contains("/blobs/"))
                .then(|| Reply::http(307, &[("Location", &target)], b""))
        });
        let dest = blobs(&tmp, &d);
        assert_failed(get_blob(&fake, &d, &dest), location);
        assert!(
            fake.dials().iter().all(|(h, _)| is_api_or_auth(&Seen {
                host: h.clone(),
                port: 443,
                target: String::new(),
                headers: Vec::new(),
            })),
            "{location}: dialed {:?}",
            fake.dials()
        );
        assert!(
            entries(dest.parent().expect("dir")).is_empty(),
            "{location}"
        );
    }
}

#[test]
fn redirect_rules() {
    // A relative Location stays on the same host.
    let tmp = TempDir::new("redirect-relative");
    let bytes = b"relative".to_vec();
    let mut hub = Hub::default();
    let digest = hub.blob("library/node", &bytes);
    let fake = Fake::new(move |s| {
        if is_api(s) && authorized(s) && s.target.ends_with("?hop=1") {
            return Reply::http(200, &[], &bytes);
        }
        if is_api(s) && authorized(s) && s.target.contains("/blobs/") {
            return Reply::http(307, &[("Location", "elsewhere/x?hop=1")], b"");
        }
        hub.handle(s)
    });
    let d = Descriptor {
        media_type: media::TAR.to_owned(),
        digest: Digest::parse(&digest).expect("digest"),
        size: 8,
    };
    let dest = blobs(&tmp, &d);
    get_blob(&fake, &d, &dest).expect("relative redirect");
    let last = fake.seen().pop().expect("requests");
    assert_eq!(last.host, "registry-1.docker.io");
    assert_eq!(last.target, "/v2/library/node/blobs/elsewhere/x?hop=1");

    // http:// is refused.
    let tmp = TempDir::new("redirect-http");
    let (fake, d) = blob_hub(b"blob", |s| {
        (is_api(s) && authorized(s)).then(|| {
            Reply::http(
                307,
                &[("Location", "http://production.cloudfront.docker.com/blob")],
                b"",
            )
        })
    });
    let dest = blobs(&tmp, &d);
    assert_failed(get_blob(&fake, &d, &dest), "http redirect");
    assert!(
        !fake
            .dials()
            .iter()
            .any(|(h, _)| h == "production.cloudfront.docker.com")
    );

    // A redirect without exactly one Location is refused.
    let tmp = TempDir::new("redirect-no-location");
    let (fake, d) = blob_hub(b"blob", |s| {
        (is_api(s) && authorized(s)).then(|| Reply::status(302))
    });
    assert_failed(get_blob(&fake, &d, &blobs(&tmp, &d)), "no Location");
}

/// A blob behind `hops` redirects: the API sends one to the CDN, and the
/// CDN chains `/hop/1` .. `/hop/<hops>` before it serves the bytes.
fn chained(hops: usize) -> (Fake, Descriptor) {
    blob_hub(b"chained", move |s| {
        if is_api(s) && authorized(s) {
            return Some(Reply::http(
                307,
                &[("Location", "https://production.cloudfront.docker.com/hop/1")],
                b"",
            ));
        }
        let n: usize = s.target.strip_prefix("/hop/")?.parse().ok()?;
        Some(if n < hops {
            Reply::http(302, &[("Location", &format!("/hop/{}", n + 1))], b"")
        } else {
            Reply::http(200, &[], b"chained")
        })
    })
}

#[test]
fn redirect_limit_10_ok_11_refused() {
    let tmp = TempDir::new("redirect-10");
    let (fake, d) = chained(10);
    get_blob(&fake, &d, &blobs(&tmp, &d)).expect("10 redirects");
    let redirected = fake
        .seen()
        .iter()
        .filter(|s| s.host.ends_with(".docker.com"))
        .count();
    assert_eq!(redirected, 10);

    let tmp = TempDir::new("redirect-11");
    let (fake, d) = chained(11);
    let detail = assert_failed(get_blob(&fake, &d, &blobs(&tmp, &d)), "11 redirects");
    assert!(detail.contains("redirects"), "{detail}");
    let redirected = fake
        .seen()
        .iter()
        .filter(|s| s.host.ends_with(".docker.com"))
        .count();
    assert_eq!(redirected, 10, "the 11th redirect was followed");
}

#[test]
fn authorization_only_to_registry_host() {
    let tmp = TempDir::new("auth-only-api");
    let (fake, d) = chained(3);
    get_blob(&fake, &d, &blobs(&tmp, &d)).expect("blob");
    let seen = fake.seen();
    assert!(seen.iter().any(|s| s.host == "auth.docker.io"));
    for s in &seen {
        let auth = s.header("authorization");
        if is_api(s) {
            continue;
        }
        assert_eq!(auth, None, "Authorization sent to {}", s.host);
    }
    assert!(seen.iter().any(|s| is_api(s) && authorized(s)));
}

/// A manifest request whose API answers `challenge` until it sees the
/// hub's token; any host that gets a request for `/token` hands it out.
fn with_challenge(challenge: &str) -> (Result<boneli_oci::Fetched, PullError>, Fake) {
    let body = manifest(&descriptor(media::CONFIG, &any_digest(), 2), &[]);
    let digest = digest_of(&body);
    let challenge = challenge.to_owned();
    let fake = Fake::new(move |s| {
        if is_api(s) {
            if authorized(s) {
                return Reply::http(200, &[("Content-Type", media::MANIFEST)], &body);
            }
            return Reply::http(401, &[("WWW-Authenticate", &challenge)], b"");
        }
        Reply::http(200, &[], format!(r#"{{"token":"{TOKEN}"}}"#).as_bytes())
    });
    let hub = Registry::docker_hub();
    let limits = limits();
    let timeouts = timeouts();
    let got = Client::new(&hub, &fake, &limits, &timeouts).get_manifest(
        &repo("library/node"),
        &Digest::parse(&digest).expect("digest"),
        None,
    );
    (got, fake)
}

fn token_request(fake: &Fake) -> Option<Seen> {
    fake.seen().into_iter().find(|s| !is_api(s))
}

#[test]
fn challenge_parsing() {
    let (got, fake) = with_challenge(
        r#"Bearer realm="https://auth.docker.io/token?a=1",service="reg,istry",scope="repository:library/node:pull""#,
    );
    got.expect("quoted comma");
    assert_eq!(
        token_request(&fake).expect("token request").target,
        "/token?a=1&service=reg%2Cistry&scope=repository%3Alibrary%2Fnode%3Apull"
    );

    let (got, fake) =
        with_challenge(r#"Bearer realm="https://auth.docker.io/token",service="reg\"istry""#);
    got.expect("escaped quote, missing scope");
    assert_eq!(
        token_request(&fake).expect("token request").target,
        "/token?service=reg%22istry&scope=repository%3Alibrary%2Fnode%3Apull"
    );

    let (got, _) = with_challenge(
        r#"Basic realm="registry", Bearer realm="https://auth.docker.io/token",service=registry.docker.io"#,
    );
    got.expect("Basic next to Bearer, token value");

    for bad in [
        r#"Basic realm="registry""#,
        r#"Bearer realm="http://auth.docker.io/token""#,
        r#"Bearer realm="https://auth.evil.example/token""#,
        r#"Bearer realm="https://auth.docker.io:8443/token""#,
        r#"Bearer realm="https://user@auth.docker.io/token""#,
        r#"Bearer service="registry.docker.io""#,
        r#"Bearer realm="https://auth.docker.io/token", Bearer realm="https://auth.docker.io/t2""#,
        r#"Bearer realm="https://auth.docker.io/token"#,
        "",
    ] {
        let (got, fake) = with_challenge(bad);
        assert_failed(got, bad);
        assert!(
            fake.dials()
                .iter()
                .all(|(h, _)| h == "registry-1.docker.io"),
            "{bad}: dialed {:?}",
            fake.dials()
        );
    }
}

/// A manifest request whose token host answers `token_body`; returns the
/// result and the requests.
fn with_token_body(token_body: Vec<u8>) -> (Result<boneli_oci::Fetched, PullError>, Fake) {
    let body = manifest(&descriptor(media::CONFIG, &any_digest(), 2), &[]);
    let digest = digest_of(&body);
    let fake = Fake::new(move |s| {
        if is_api(s) {
            let token_sent = s.header("authorization").is_some();
            if token_sent {
                return Reply::http(200, &[("Content-Type", media::MANIFEST)], &body);
            }
            return Reply::http(
                401,
                &[("WWW-Authenticate", &challenge_for("library/node"))],
                b"",
            );
        }
        Reply::http(200, &[], &token_body)
    });
    let hub = Registry::docker_hub();
    let limits = limits();
    let timeouts = timeouts();
    let got = Client::new(&hub, &fake, &limits, &timeouts).get_manifest(
        &repo("library/node"),
        &Digest::parse(&digest).expect("digest"),
        None,
    );
    (got, fake)
}

#[test]
fn token_rules() {
    for bad in [
        &br#"{"token":"a\r\nX-Evil: 1"}"#[..],
        br#"{"token":"a\nb"}"#,
        br#"{"token":"a\rb"}"#,
        br#"{"token":""}"#,
        br#"{"token":"   "}"#,
        br#"{"token":"a b"}"#,
        br#"{"token":"","access_token":"tok-1"}"#,
        br#"{"expires_in":300}"#,
    ] {
        let (got, fake) = with_token_body(bad.to_vec());
        assert_failed(got, &String::from_utf8_lossy(bad));
        let api: Vec<Seen> = fake.seen().into_iter().filter(is_api).collect();
        assert_eq!(api.len(), 1, "a refused token was sent");
        assert_eq!(api[0].header("authorization"), None);
    }
    let (got, fake) = with_token_body(br#"{"token":"tok-1","access_token":"other"}"#.to_vec());
    got.expect("token wins");
    let last = fake.seen().pop().expect("requests");
    assert_eq!(last.header("authorization"), Some("Bearer tok-1"));
    let (got, fake) = with_token_body(br#"{"access_token":"acc-2"}"#.to_vec());
    got.expect("access_token");
    let last = fake.seen().pop().expect("requests");
    assert_eq!(last.header("authorization"), Some("Bearer acc-2"));
}

#[test]
fn reauth_once() {
    // An unknown repository: Docker Hub answers 401 even with a fresh
    // token, which is NotFound, after exactly one token request.
    let fake = hub_fake(Hub::default());
    assert_not_found(
        resolve(&fake, "library/ghost", &any_digest(), "linux/amd64"),
        "unknown repository",
    );
    let hosts: Vec<String> = fake.seen().into_iter().map(|s| s.host).collect();
    assert_eq!(
        hosts,
        [
            "registry-1.docker.io",
            "auth.docker.io",
            "registry-1.docker.io"
        ]
    );

    // A token that expires after the manifest: the blob request gets a
    // 401, one new token, and succeeds.
    let mut hub = Hub::default();
    let (digest, _) = image(&mut hub, "library/node", AMD64, 1);
    let generation = Arc::new(AtomicUsize::new(1));
    let reject_all = Arc::new(AtomicUsize::new(0));
    let fake = {
        let generation = Arc::clone(&generation);
        let reject_all = Arc::clone(&reject_all);
        Fake::new(move |s| {
            let current = format!("tok-{}", generation.load(Ordering::SeqCst));
            if s.host == "auth.docker.io" {
                return Reply::http(200, &[], format!(r#"{{"token":"{current}"}}"#).as_bytes());
            }
            let ok = s.header("authorization") == Some(&format!("Bearer {current}"));
            if !ok || reject_all.load(Ordering::SeqCst) == 1 {
                return Reply::http(
                    401,
                    &[("WWW-Authenticate", &challenge_for("library/node"))],
                    b"",
                );
            }
            let mut seen = s.clone();
            seen.headers = vec![("Authorization".into(), format!("Bearer {TOKEN}"))];
            hub.handle(&seen)
        })
    };
    let registry = Registry::docker_hub();
    let limits = limits();
    let timeouts = timeouts();
    let reference = Reference::parse("library/node", &digest, "linux/amd64").expect("ref");
    let mut client = Client::new(&registry, &fake, &limits, &timeouts);
    let resolved = client.resolve(&reference).expect("resolve");
    let layer = resolved.manifest.layers[0].descriptor.clone();
    let token_requests = |fake: &Fake| fake.seen().iter().filter(|s| !is_api(s)).count();
    assert_eq!(token_requests(&fake), 1);

    generation.store(2, Ordering::SeqCst);
    let tmp = TempDir::new("reauth");
    let dest = blobs(&tmp, &layer);
    client
        .get_blob(reference.repository(), &layer, &dest)
        .expect("one re-authentication");
    assert_eq!(token_requests(&fake), 2);

    // A second 401 after the new token: Failed, not NotFound, because the
    // repository answered before; and no third token request.
    reject_all.store(1, Ordering::SeqCst);
    std::fs::remove_file(&dest).expect("remove");
    assert_failed(
        client.get_blob(reference.repository(), &layer, &dest),
        "second 401",
    );
    assert_eq!(token_requests(&fake), 3);
    assert!(!dest.exists());

    // A later manifest request with a second 401 is Failed too.
    assert_failed(
        client.get_manifest(reference.repository(), reference.digest(), None),
        "manifest after authorization",
    );
}

#[test]
fn manifest_404_is_not_found() {
    let mut hub = Hub::default();
    image(&mut hub, "library/node", AMD64, 1);
    let fake = hub_fake(hub);
    assert_not_found(
        resolve(&fake, "library/node", &any_digest(), "linux/amd64"),
        "unknown digest",
    );
}

// --- Documents and blobs ------------------------------------------------

/// A valid OCI manifest body for linux/amd64 (one layer), with its hub
/// blobs, as a JSON text whose fields can be rewritten; returns the hub
/// and the text.
fn base_manifest(hub: &mut Hub) -> String {
    let layer = b"layer".to_vec();
    let layer_digest = hub.blob("library/node", &layer);
    let cfg = config("linux", "amd64", None, std::slice::from_ref(&layer_digest));
    let cfg_digest = hub.blob("library/node", &cfg);
    String::from_utf8(manifest(
        &descriptor(media::CONFIG, &cfg_digest, cfg.len()),
        &[descriptor(media::TAR, &layer_digest, layer.len())],
    ))
    .expect("utf8")
}

fn serve(mut hub: Hub, content_type: &str, text: &str) -> Result<Resolved, PullError> {
    let digest = hub.document("library/node", content_type, text.as_bytes());
    resolve(&hub_fake(hub), "library/node", &digest, "linux/amd64")
}

#[test]
fn manifest_kind_rules() {
    let mut hub = Hub::default();
    let text = base_manifest(&mut hub);
    serve(hub.clone(), media::MANIFEST, &text).expect("valid");
    serve(
        hub.clone(),
        "application/vnd.oci.image.manifest.v1+json; charset=utf-8",
        &text,
    )
    .expect("parameters dropped");
    let without_field = text.replace(&format!(r#""mediaType":"{}","#, media::MANIFEST), "");
    assert_ne!(without_field, text);
    serve(hub.clone(), media::MANIFEST, &without_field).expect("Content-Type decides");

    let detail = assert_failed(serve(hub.clone(), media::DOCKER_MANIFEST, &text), "differs");
    assert!(detail.contains("differs"), "{detail}");
    assert_failed(serve(hub.clone(), "", &without_field), "no type at all");
    assert_failed(
        serve(
            hub.clone(),
            media::MANIFEST,
            &text.replace(r#""layers":"#, r#""manifests":[],"layers":"#),
        ),
        "manifests and layers",
    );
    assert_failed(
        serve(
            hub.clone(),
            "application/vnd.docker.distribution.manifest.v1+prettyjws",
            r#"{"schemaVersion":1,"name":"library/node","tag":"22","fsLayers":[]}"#,
        ),
        "schema1",
    );
    assert_failed(
        serve(
            hub.clone(),
            media::MANIFEST,
            &text.replace(r#""schemaVersion":2"#, r#""schemaVersion":1"#),
        ),
        "schemaVersion 1",
    );

    // A nested index: an entry that names an index, and an entry that
    // claims a manifest but serves an index.
    let (mut nested, inner) = indexed(&[AMD64]);
    let inner_size = nested.manifests["library/node"][&inner].1.len();
    let outer = index(&[entry(media::INDEX, &inner, inner_size, Some(AMD64))]);
    let digest = nested.document("library/node", media::INDEX, &outer);
    let detail = assert_failed(
        resolve(
            &hub_fake(nested.clone()),
            "library/node",
            &digest,
            "linux/amd64",
        ),
        "nested index entry",
    );
    assert!(
        detail.contains("the entry for linux/amd64 is a nested index"),
        "{detail}"
    );
    let fake = hub_fake(nested.clone());
    resolve(&fake, "library/node", &digest, "linux/amd64").expect_err("again");
    assert!(
        !fake.seen().iter().any(|s| s.target.ends_with(&inner)),
        "the nested index was fetched"
    );
    let liar = index(&[entry(media::MANIFEST, &inner, inner_size, Some(AMD64))]);
    let digest = nested.document("library/node", media::INDEX, &liar);
    let detail = assert_failed(
        resolve(&hub_fake(nested), "library/node", &digest, "linux/amd64"),
        "index behind a manifest entry",
    );
    assert!(
        detail.contains(&format!("manifest {inner} is a nested index")),
        "{detail}"
    );
}

#[test]
fn media_type_allowlist() {
    let mut hub = Hub::default();
    let text = base_manifest(&mut hub);
    for refused in [
        "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/x-tar",
        "application/vnd.oci.image.layer.v1.t\u{430}r",
        "application/vnd.oci.image.layer.v1.tar+bzip2",
    ] {
        let changed = text.replace(
            &format!(r#""mediaType":"{}","#, media::TAR),
            &format!(r#""mediaType":"{refused}","#),
        );
        assert_ne!(changed, text);
        assert_failed(serve(hub.clone(), media::MANIFEST, &changed), refused);
    }
    for accepted in [
        media::TAR,
        media::GZIP,
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
    ] {
        let changed = text.replace(
            &format!(r#""mediaType":"{}","#, media::TAR),
            &format!(r#""mediaType":"{accepted}","#),
        );
        serve(hub.clone(), media::MANIFEST, &changed).expect(accepted);
    }
    let with_urls = text.replace(
        &format!(r#""mediaType":"{}","#, media::TAR),
        &format!(
            r#""urls":["https://example.com/l"],"mediaType":"{}","#,
            media::TAR
        ),
    );
    assert_failed(serve(hub.clone(), media::MANIFEST, &with_urls), "urls");
    let cyrillic = "application/vnd.oci.image.m\u{430}nifest.v1+json";
    let changed = text.replace(media::MANIFEST, cyrillic);
    assert_failed(serve(hub.clone(), cyrillic, &changed), "document type");
    let config_type = text.replace(media::CONFIG, "application/vnd.cncf.helm.config.v1+json");
    assert_failed(serve(hub, media::MANIFEST, &config_type), "config type");
}

#[test]
fn layer_count_128_ok_129_refused() {
    let mut hub = Hub::default();
    let (ok, _) = image(&mut hub, "library/node", AMD64, 128);
    let (over, _) = image(
        &mut hub,
        "library/node",
        ("linux", "amd64", Some("v2")),
        129,
    );
    let fake = hub_fake(hub);
    let got = resolve(&fake, "library/node", &ok, "linux/amd64").expect("128");
    assert_eq!(got.manifest.layers.len(), 128);
    let detail = assert_failed(
        resolve(&fake, "library/node", &over, "linux/amd64/v2"),
        "129",
    );
    assert!(detail.contains("129 layers"), "{detail}");
}

#[test]
fn config_consistency() {
    // diff_ids that do not match the layer count.
    let mut hub = Hub::default();
    let text = base_manifest(&mut hub);
    let layer_digest = hub.blob("library/node", b"layer");
    let two = config(
        "linux",
        "amd64",
        None,
        &[layer_digest.clone(), layer_digest],
    );
    let two_digest = hub.blob("library/node", &two);
    let start = text.find(r#""config":"#).expect("config") + r#""config":"#.len();
    let end = start + text[start..].find('}').expect("end") + 1;
    let changed = format!(
        "{}{}{}",
        &text[..start],
        descriptor(media::CONFIG, &two_digest, two.len()),
        &text[end..]
    );
    let detail = assert_failed(serve(hub, media::MANIFEST, &changed), "diff_ids count");
    assert!(detail.contains("diff_ids"), "{detail}");

    // An index entry for amd64 whose config says arm64: Failed, because
    // the index contradicts the image, not NotFound.
    let mut hub = Hub::default();
    let (arm, size) = image(&mut hub, "library/node", ("linux", "arm64", None), 1);
    let bytes = index(&[entry(media::MANIFEST, &arm, size, Some(AMD64))]);
    let digest = hub.document("library/node", media::INDEX, &bytes);
    assert_failed(
        resolve(&hub_fake(hub), "library/node", &digest, "linux/amd64"),
        "config platform",
    );

    // The entry's media type must be the manifest's.
    let mut hub = Hub::default();
    let (amd, size) = image(&mut hub, "library/node", AMD64, 1);
    let bytes = index(&[entry(media::DOCKER_MANIFEST, &amd, size, Some(AMD64))]);
    let digest = hub.document("library/node", media::INDEX, &bytes);
    let detail = assert_failed(
        resolve(&hub_fake(hub), "library/node", &digest, "linux/amd64"),
        "entry type",
    );
    assert!(detail.contains("but the index says"), "{detail}");
    // The entry's size must be the manifest's.
    let mut hub = Hub::default();
    let (amd, size) = image(&mut hub, "library/node", AMD64, 1);
    let bytes = index(&[entry(media::MANIFEST, &amd, size + 1, Some(AMD64))]);
    let digest = hub.document("library/node", media::INDEX, &bytes);
    assert_failed(
        resolve(&hub_fake(hub), "library/node", &digest, "linux/amd64"),
        "entry size",
    );
}

#[test]
fn descriptor_numbers() {
    let mut hub = Hub::default();
    let text = base_manifest(&mut hub);
    let size = r#""size":5}"#;
    assert!(text.contains(size));
    for bad in [
        "-1",
        "-0",
        "1.5",
        "5.0",
        "1e3",
        "18446744073709551616",
        "\"5\"",
        "null",
    ] {
        let changed = text.replace(size, &format!(r#""size":{bad}}}"#));
        assert_failed(serve(hub.clone(), media::MANIFEST, &changed), bad);
    }
}

#[test]
fn duplicate_keys_refused() {
    let mut hub = Hub::default();
    let text = base_manifest(&mut hub);
    let changed = text.replace(r#""layers":"#, r#""layers":[],"layers":"#);
    assert_failed(
        serve(hub.clone(), media::MANIFEST, &changed),
        "duplicate layers",
    );
    let changed = text.replacen(r#""size":"#, r#""size":1,"size":"#, 1);
    assert_failed(serve(hub, media::MANIFEST, &changed), "duplicate size");
}

/// Counts values the way `boneli_json::Limits::max_values` does.
fn count(value: &boneli_json::Value) -> usize {
    1 + match (value.as_array(), value.as_object()) {
        (Some(items), _) => items.iter().map(count).sum(),
        (_, Some(object)) => object.iter().map(|(_, v)| count(v)).sum(),
        _ => 0,
    }
}

#[test]
fn json_limits_inclusive() {
    let mut hub = Hub::default();
    let text = base_manifest(&mut hub);
    let body = text.trim_end_matches('}');
    let with = |extra: &str| format!("{body},{extra}}}");

    // Bytes: trailing whitespace fills the document to the limit.
    let pad = |n: usize| format!("{text}{}", " ".repeat(n - text.len()));
    serve(hub.clone(), media::MANIFEST, &pad(4_194_304)).expect("4 MiB");
    let detail = assert_failed(
        serve(hub.clone(), media::MANIFEST, &pad(4_194_305)),
        "4 MiB + 1",
    );
    assert!(
        detail.contains("longer than the limit of 4194304"),
        "{detail}"
    );

    // Depth: the manifest object is 1, each array one more.
    let nest = |k: usize| with(&format!(r#""x":{}{}"#, "[".repeat(k), "]".repeat(k)));
    serve(hub.clone(), media::MANIFEST, &nest(15)).expect("depth 16");
    assert_failed(serve(hub.clone(), media::MANIFEST, &nest(16)), "depth 17");

    // Values: an array of n nulls adds n + 1.
    let wide = boneli_json::Limits::new(1 << 24, 64, 1 << 20).expect("wide");
    let base = count(&boneli_json::parse(text.as_bytes(), &wide).expect("parse"));
    let nulls = |n: usize| with(&format!(r#""pad":[{}]"#, vec!["null"; n].join(",")));
    let at = |total: usize| nulls(total - base - 1);
    let check = boneli_json::parse(at(65_536).as_bytes(), &wide).expect("parse");
    assert_eq!(count(&check), 65_536);
    serve(hub.clone(), media::MANIFEST, &at(65_536)).expect("65,536 values");
    assert_failed(serve(hub, media::MANIFEST, &at(65_537)), "65,537 values");
}

#[test]
fn token_body_cap() {
    let token = format!(r#"{{"token":"{TOKEN}"}}"#);
    let padded = |n: usize| format!("{token}{}", " ".repeat(n - token.len())).into_bytes();
    let (got, _) = with_token_body(padded(65_536));
    got.expect("65,536 B");
    let (got, fake) = with_token_body(padded(65_537));
    let detail = assert_failed(got, "65,537 B");
    // Refused while it is read, before the JSON parser sees it.
    assert!(
        detail.contains("longer than the limit of 65536"),
        "{detail}"
    );
    assert_eq!(fake.seen().iter().filter(|s| is_api(s)).count(), 1);
}

/// A raw `200` head for `body` with `fields` extra fields; `total` pads
/// the last field so the head is exactly that many bytes.
fn raw_head(body: &[u8], fields: usize, total: Option<usize>) -> Vec<u8> {
    let mut head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        media::MANIFEST,
        body.len()
    );
    for i in 0..fields {
        head.push_str(&format!("X-F{i}: 1\r\n"));
    }
    if let Some(total) = total {
        let fixed = head.len() + "X-Pad: \r\n\r\n".len();
        head.push_str(&format!("X-Pad: {}\r\n", "p".repeat(total - fixed)));
    }
    head.push_str("\r\n");
    if let Some(total) = total {
        assert_eq!(head.len(), total);
    }
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Resolves an image whose top manifest the API answers with
/// `raw(manifest body)` once authorized.
fn with_raw_manifest(
    raw: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
) -> Result<Resolved, PullError> {
    let mut hub = Hub::default();
    let (digest, _) = image(&mut hub, "library/node", AMD64, 1);
    let body = hub.manifests["library/node"][&digest].1.clone();
    let path = format!("/v2/library/node/manifests/{digest}");
    let fake = Fake::new(move |s| {
        if is_api(s) && authorized(s) && s.target == path {
            return Reply::Raw(raw(&body));
        }
        hub.handle(s)
    });
    resolve(&fake, "library/node", &digest, "linux/amd64")
}

#[test]
fn head_limits_inclusive() {
    with_raw_manifest(|b| raw_head(b, 0, Some(16_384))).expect("16,384 B head");
    assert_failed(
        with_raw_manifest(|b| raw_head(b, 0, Some(16_385))),
        "16,385 B head",
    );
    // Content-Type and Content-Length plus 62 more is 64 fields.
    with_raw_manifest(|b| raw_head(b, 62, None)).expect("64 fields");
    assert_failed(with_raw_manifest(|b| raw_head(b, 63, None)), "65 fields");
}

/// A blob request whose authorized API answer is `reply(bytes)`.
fn blob_answer(
    bytes: &'static [u8],
    reply: impl Fn() -> Reply + Send + Sync + 'static,
) -> (Fake, Descriptor) {
    blob_hub(bytes, move |s| (is_api(s) && authorized(s)).then(&reply))
}

#[test]
fn blob_length_and_digest() {
    const BYTES: &[u8] = b"exactly these bytes";
    let tmp = TempDir::new("blob-ok");
    let (fake, d) = blob_answer(BYTES, || Reply::http(200, &[], BYTES));
    let dest = blobs(&tmp, &d);
    get_blob(&fake, &d, &dest).expect("exact");
    assert_eq!(std::fs::read(&dest).expect("blob"), BYTES);
    assert_eq!(entries(dest.parent().expect("dir")), [d.digest.hex()]);

    let mut tampered = BYTES.to_vec();
    tampered[0] ^= 1;
    let longer = [BYTES, b"!"].concat();
    let shorter = BYTES[..BYTES.len() - 1].to_vec();
    let chunked_longer = {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        raw.extend_from_slice(format!("{:x}\r\n", longer.len()).as_bytes());
        raw.extend_from_slice(&longer);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        raw
    };
    let close_shorter = {
        let mut raw = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        raw.extend_from_slice(&shorter);
        raw
    };
    for (what, reply, reason) in [
        (
            "one byte longer",
            Reply::http(200, &[], &longer),
            "longer than",
        ),
        (
            "one byte shorter",
            Reply::http(200, &[], &shorter),
            "ended 1 bytes before",
        ),
        (
            "wrong digest",
            Reply::http(200, &[], &tampered),
            "does not match its digest",
        ),
        ("chunked, longer", Reply::Raw(chunked_longer), "longer than"),
        (
            "until close, shorter",
            Reply::Raw(close_shorter),
            "ended 1 bytes before",
        ),
        ("404", Reply::status(404), "answered 404"),
        ("429", Reply::status(429), "answered 429"),
        ("503", Reply::status(503), "answered 503"),
    ] {
        let tmp = TempDir::new("blob-bad");
        let reply = std::sync::Mutex::new(Some(reply));
        let (fake, d) = blob_answer(BYTES, move || {
            reply
                .lock()
                .expect("reply")
                .take()
                .unwrap_or(Reply::status(500))
        });
        let dest = blobs(&tmp, &d);
        let detail = assert_failed(get_blob(&fake, &d, &dest), what);
        assert!(detail.contains(reason), "{what}: {detail}");
        assert!(entries(dest.parent().expect("dir")).is_empty(), "{what}");
    }
}

#[test]
fn tampered_blob_never_cached() {
    // The CDN serves other bytes of the right length.
    const BYTES: &[u8] = b"the real layer";
    let tmp = TempDir::new("tampered");
    let (fake, d) = blob_hub(BYTES, |s| {
        (s.host == "production.cloudfront.docker.com")
            .then(|| Reply::http(200, &[], b"the fake layer"))
    });
    let dest = blobs(&tmp, &d);
    let detail = assert_failed(get_blob(&fake, &d, &dest), "tampered");
    assert!(detail.contains("digest"), "{detail}");
    assert!(entries(dest.parent().expect("dir")).is_empty());
    assert!(!dest.exists());

    // A tampered manifest is refused before it is parsed.
    let mut hub = Hub::default();
    let (digest, _) = image(&mut hub, "library/node", AMD64, 1);
    let docs = hub.manifests.get_mut("library/node").expect("repo");
    let entry = docs.get_mut(&digest).expect("doc");
    entry.1 = entry
        .1
        .iter()
        .map(|b| if *b == b'1' { b'2' } else { *b })
        .collect();
    let detail = assert_failed(
        resolve(&hub_fake(hub), "library/node", &digest, "linux/amd64"),
        "tampered manifest",
    );
    assert!(detail.contains("digest"), "{detail}");
}

#[test]
fn slow_body_deadline() {
    const BYTES: &[u8] = b"0123456789012345678901234567890123456789";
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", BYTES.len()).into_bytes();

    // A stall longer than the io timeout fails within about one io
    // timeout, long before the deadline.
    let io = Duration::from_millis(300);
    let stall_timeouts = Timeouts::new(io, Duration::from_secs(20), 1 << 20).expect("timeouts");
    let tmp = TempDir::new("stall");
    let h = head.clone();
    let (fake, d) = blob_answer(BYTES, move || Reply::Trickle {
        head: [h.as_slice(), &BYTES[..10]].concat(),
        chunks: vec![BYTES[10..].to_vec()],
        delay: Duration::from_secs(3),
    });
    let dest = blobs(&tmp, &d);
    let start = Instant::now();
    assert_failed(get_blob_with(&fake, &d, &dest, &stall_timeouts), "stall");
    let elapsed = start.elapsed();
    assert!(elapsed >= io, "{elapsed:?}");
    assert!(elapsed < io + Duration::from_millis(1500), "{elapsed:?}");
    assert!(entries(dest.parent().expect("dir")).is_empty());

    // One byte every 100 ms keeps every read under the io timeout, so only
    // the deadline (setup 1 s) stops it, within one io timeout of it.
    let setup = Duration::from_secs(1);
    let trickle_timeouts = Timeouts::new(io, setup, 1 << 30).expect("timeouts");
    let tmp = TempDir::new("trickle");
    let (fake, d) = blob_answer(BYTES, move || Reply::Trickle {
        head: head.clone(),
        chunks: BYTES.iter().map(|b| vec![*b]).collect(),
        delay: Duration::from_millis(100),
    });
    let dest = blobs(&tmp, &d);
    let start = Instant::now();
    assert_failed(
        get_blob_with(&fake, &d, &dest, &trickle_timeouts),
        "trickle",
    );
    let elapsed = start.elapsed();
    assert!(elapsed >= setup, "{elapsed:?}");
    assert!(
        elapsed < setup + io + Duration::from_millis(500),
        "{elapsed:?}"
    );
    assert!(entries(dest.parent().expect("dir")).is_empty());
}

#[test]
fn descriptor_size_cap_before_download() {
    let tmp = TempDir::new("size-cap");
    let fake = hub_fake(Hub::default());
    let over = Descriptor {
        media_type: media::GZIP.to_owned(),
        digest: Digest::parse(&any_digest()).expect("digest"),
        size: 4_294_967_297,
    };
    let dest = blobs(&tmp, &over);
    let detail = assert_failed(get_blob(&fake, &over, &dest), "4 GiB + 1");
    assert!(detail.contains("limit"), "{detail}");
    assert!(fake.dials().is_empty(), "a request was made");
    assert!(entries(dest.parent().expect("dir")).is_empty());

    // At the cap the request is made (and fails here, because the fake
    // has no such blob).
    let at = Descriptor {
        size: 4_294_967_296,
        ..over
    };
    assert_failed(get_blob(&fake, &at, &dest), "4 GiB");
    assert!(!fake.dials().is_empty());

    // A layer descriptor above the cap refuses its manifest, before the
    // config or any blob is requested.
    let mut hub = Hub::default();
    let text = base_manifest(&mut hub);
    let changed = text.replace(r#""size":5}"#, r#""size":4294967297}"#);
    assert_ne!(changed, text);
    let digest = hub.document("library/node", media::MANIFEST, changed.as_bytes());
    let fake = hub_fake(hub);
    assert_failed(
        resolve(&fake, "library/node", &digest, "linux/amd64"),
        "manifest with a 4 GiB + 1 layer",
    );
    assert!(fake.seen().iter().all(|s| !s.target.contains("/blobs/")));
}

#[test]
fn expired_deadline_makes_no_request() {
    let fake = hub_fake(Hub::default());
    let hub = Registry::docker_hub();
    let limits = limits();
    let timeouts =
        Timeouts::new(Duration::from_secs(5), Duration::from_nanos(1), u64::MAX).expect("timeouts");
    let got = Client::new(&hub, &fake, &limits, &timeouts).get_manifest(
        &repo("library/node"),
        &Digest::parse(&any_digest()).expect("digest"),
        Some(2),
    );
    let detail = assert_failed(got, "expired deadline");
    assert!(detail.contains("deadline"), "{detail}");
    assert!(fake.dials().is_empty(), "dialed after the deadline");
}

/// A blob fetched first (part 3 reads cached manifests from disk): the
/// API's redirect proves the repository exists, so a later manifest `401`
/// with a fresh token is `Failed`, not `NotFound`.
#[test]
fn api_redirect_counts_as_authorized() {
    let tmp = TempDir::new("redirect-authorized");
    let (fake, d) = blob_hub(b"blob bytes", |s| {
        (is_api(s) && s.target.contains("/manifests/")).then(|| {
            Reply::http(
                401,
                &[("WWW-Authenticate", &challenge_for("library/node"))],
                b"",
            )
        })
    });
    let hub = Registry::docker_hub();
    let limits = limits();
    let timeouts = timeouts();
    let mut client = Client::new(&hub, &fake, &limits, &timeouts);
    client
        .get_blob(&repo("library/node"), &d, &blobs(&tmp, &d))
        .expect("blob through the CDN");
    assert_failed(
        client.get_manifest(&repo("library/node"), &d.digest, None),
        "manifest 401 after an authorized redirect",
    );
}
