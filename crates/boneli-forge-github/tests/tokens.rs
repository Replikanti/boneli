//! The App JWT, the installation token cache and the key file (ADR-014,
//! D4 to D6), against the fake GitHub.

mod support;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use boneli_app::Forge;
use boneli_forge_github::time::{civil_from_days, days_from_civil, format_rfc3339, parse_rfc3339};
use boneli_forge_github::{
    ClientId, HEADER, KeyFileError, KeyFileFacts, KeyFileProblem, MAX_TOKEN, app_jwt, base64,
    claims, key_file_problem, load_key, token_problem,
};
use support::*;

/// RFC 4648 base64 decoding, both alphabets, for the tests only.
fn decode(text: &str) -> Vec<u8> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => panic!("not base64: {c}"),
    };
    let symbols: Vec<u8> = text.bytes().filter(|&c| c != b'=').map(value).collect();
    let mut out = Vec::new();
    for chunk in symbols.chunks(4) {
        let mut acc = 0u32;
        for (k, s) in chunk.iter().enumerate() {
            acc |= u32::from(*s) << (18 - 6 * k);
        }
        for k in 0..chunk.len() - 1 {
            out.push((acc >> (16 - 8 * k)) as u8);
        }
    }
    out
}

fn client() -> ClientId {
    ClientId::parse(CLIENT_ID).expect("client id")
}

#[test]
fn base64_rfc4648_vectors() {
    for (input, standard, url) in [
        ("", "", ""),
        ("f", "Zg==", "Zg"),
        ("fo", "Zm8=", "Zm8"),
        ("foo", "Zm9v", "Zm9v"),
        ("foob", "Zm9vYg==", "Zm9vYg"),
        ("fooba", "Zm9vYmE=", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy", "Zm9vYmFy"),
    ] {
        assert_eq!(base64::standard(input.as_bytes()), standard, "{input:?}");
        assert_eq!(base64::url_safe(input.as_bytes()), url, "{input:?}");
    }
    // The two alphabets differ only in 62 and 63.
    assert_eq!(base64::standard(&[0xfb, 0xff]), "+/8=");
    assert_eq!(base64::url_safe(&[0xfb, 0xff]), "-_8");
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(decode(&base64::standard(&all)), all);
    assert_eq!(decode(&base64::url_safe(&all)), all);
}

#[test]
fn jwt_header_and_claims_are_exact() {
    assert_eq!(HEADER, r#"{"alg":"RS256","typ":"JWT"}"#);
    assert_eq!(
        claims(&client(), 1_700_000_000).as_deref(),
        Some(r#"{"iat":1699999940,"exp":1700000540,"iss":"Iv23liTestOnly0000"}"#)
    );
    assert_eq!(claims(&client(), 59), None);
    assert!(claims(&client(), 60).is_some());
    assert_eq!(claims(&client(), u64::MAX - 539), None);
    let jwt = app_jwt(&key(), &client(), 1_700_000_000).expect("a JWT");
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(decode(parts[0]), HEADER.as_bytes());
    assert_eq!(
        decode(parts[1]),
        br#"{"iat":1699999940,"exp":1700000540,"iss":"Iv23liTestOnly0000"}"#
    );
    // URL-safe, unpadded.
    assert!(
        jwt.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    );
}

#[test]
fn jwt_round_trips() {
    let key = key();
    let jwt = app_jwt(&key, &client(), T0).expect("a JWT");
    let (input, signature) = jwt.rsplit_once('.').expect("three parts");
    let signature = decode(signature);
    assert_eq!(signature.len(), 256);
    // RSASSA-PKCS1-v1_5 is deterministic: the signature over the signing
    // input is the one the JWT carries.
    assert_eq!(key.sign(input.as_bytes()).expect("sign"), signature);
    assert_ne!(app_jwt(&key, &client(), T0 + 1).expect("a JWT"), jwt);
}

#[test]
fn token_request_is_scoped() {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(|_| None);
    let tokens = tokens(&fake, &clock);
    let token = tokens.token().expect("a token");
    assert_eq!(token.expose(), hub_token(1));
    let seen = fake.seen();
    assert_eq!(seen.len(), 1);
    let exchange = &seen[0];
    assert_eq!(
        (exchange.host.as_str(), exchange.port),
        ("api.github.com", 443)
    );
    assert_eq!(exchange.method, "POST");
    assert_eq!(exchange.target, "/app/installations/4242/access_tokens");
    assert_eq!(
        String::from_utf8_lossy(&exchange.body),
        r#"{"repositories":["demo.repo"],"permissions":{"contents":"write","issues":"write","pull_requests":"write"}}"#
    );
    let names: Vec<String> = exchange
        .headers
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect();
    assert_eq!(
        names,
        [
            "host",
            "content-length",
            "accept",
            "x-github-api-version",
            "user-agent",
            "authorization",
            "content-type"
        ]
    );
    assert_eq!(
        exchange.header("accept"),
        Some("application/vnd.github+json")
    );
    assert_eq!(exchange.header("x-github-api-version"), Some("2022-11-28"));
    assert_eq!(exchange.header("user-agent"), Some("boneli-forge-github"));
    assert_eq!(exchange.header("content-type"), Some("application/json"));
    let jwt = exchange.bearer().expect("a bearer JWT");
    assert_eq!(jwt, app_jwt(&key(), &client(), T0).expect("a JWT"));
    // The git form.
    let basic = tokens.git_authorization().expect("a git value");
    let encoded = basic.strip_prefix("Basic ").expect("Basic");
    assert_eq!(
        decode(encoded),
        format!("x-access-token:{}", hub_token(1)).as_bytes()
    );
    assert_eq!(fake.exchanges(), 1, "the git value reuses the token");
    assert_eq!(
        tokens.repository_url().as_str(),
        "https://github.com/octo-org/demo.repo.git"
    );
}

#[test]
fn token_is_cached_until_margin() {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(|_| None);
    let tokens = tokens(&fake, &clock);
    let first = tokens.token().expect("a token");
    clock.set(T0 + 2_999); // 601 s left
    assert_eq!(tokens.token().expect("reused"), first);
    assert_eq!(fake.exchanges(), 1);
    clock.set(T0 + 3_000); // 600 s left
    let second = tokens.token().expect("a new token");
    assert_ne!(second, first);
    assert_eq!(fake.exchanges(), 2);
}

/// A hub whose single exchange answers `expires_at`.
fn expiring(expires_at: u64) -> (Arc<FakeClock>, Fake) {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(move |seen| {
        seen.is_token_exchange().then(|| {
            Reply::json(
                201,
                &token_answer(&hub_token(1), &format_rfc3339(expires_at)),
            )
        })
    });
    (clock, fake)
}

#[test]
fn expires_at_beyond_an_hour_is_clamped() {
    let (clock, fake) = expiring(T0 + 7_200);
    let tokens = tokens(&fake, &clock);
    tokens.token().expect("a token");
    clock.set(T0 + 2_999);
    tokens.token().expect("reused");
    assert_eq!(fake.exchanges(), 1);
    clock.set(T0 + 3_000);
    tokens.token().expect("a refresh");
    assert_eq!(
        fake.exchanges(),
        2,
        "the hour cap holds over a later expires_at"
    );
}

#[test]
fn token_expiring_within_margin_is_refused() {
    let (clock, fake) = expiring(T0 + 600);
    let failure = tokens(&fake, &clock).token().expect_err("too short");
    assert!(
        failure.output().contains("not more than 600 s"),
        "{failure}"
    );
    assert!(!failure.to_string().contains(&hub_token(1)), "{failure}");
    let (clock, fake) = expiring(T0 + 601);
    tokens(&fake, &clock).token().expect("601 s is enough");
}

#[test]
fn clock_going_back_refreshes() {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(|_| None);
    let tokens = tokens(&fake, &clock);
    tokens.token().expect("a token");
    clock.set(T0 - 1);
    tokens.token().expect("a refresh");
    assert_eq!(fake.exchanges(), 2);
}

#[test]
fn expires_at_forms() {
    let noon = days_from_civil(2026, 11, 19) as u64 * 86_400 + 12 * 3_600;
    for (text, expected) in [
        ("2026-11-19T12:00:00Z", noon),
        ("2026-11-19T12:00:00.123Z", noon),
        ("2026-11-19T12:00:00.123456789Z", noon),
        ("2026-11-19T13:00:00+01:00", noon),
        ("2026-11-19T11:30:00-00:30", noon),
        ("2026-11-19t12:00:00z", noon),
        ("2026-11-19T12:00:00+00:00", noon),
        (
            "2024-02-29T00:00:00Z",
            days_from_civil(2024, 2, 29) as u64 * 86_400,
        ),
        ("1970-01-01T00:00:00Z", 0),
    ] {
        assert_eq!(parse_rfc3339(text), Some(expected), "{text}");
    }
    for text in [
        "2026-02-29T00:00:00Z",
        "2026-11-19T23:59:60Z",
        "2026-11-19 12:00:00Z",
        "2026-11-19T12:00:00",
        "2026-11-19T12:00:00+24:00",
        "2026-11-19T12:00:00+01:60",
        "1969-12-31T23:59:59Z",
        "1970-01-01T00:30:00+01:00",
        "2026-11-19T12:00:00.Z",
        "2026-11-19T12:00:00.1234567890Z",
        "2026-11-19T24:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-00-01T00:00:00Z",
        "2026-11-00T00:00:00Z",
        "2026-11-19T12:00:00ZZ",
        "2026-11-19T12:00:00+0100",
        "+2026-11-19T12:00:00Z",
        "2026-11-19T12:00:00Z ",
        "２026-11-19T12:00:00Z",
        "",
    ] {
        assert_eq!(parse_rfc3339(text), None, "{text}");
    }
}

#[test]
fn rfc3339_round_trips_every_day() {
    let first = days_from_civil(1970, 1, 1);
    let last = days_from_civil(2100, 12, 31);
    assert_eq!(first, 0);
    let mut expected = (1970, 1, 1);
    for day in first..=last {
        assert_eq!(civil_from_days(day), expected, "day {day}");
        let (y, m, d) = expected;
        let text = format!("{y:04}-{m:02}-{d:02}T00:00:00Z");
        let secs = day as u64 * 86_400;
        assert_eq!(format_rfc3339(secs), text);
        assert_eq!(parse_rfc3339(&text), Some(secs), "{text}");
        assert_eq!(
            parse_rfc3339(&format!("{y:04}-{m:02}-{d:02}T23:59:59Z")),
            Some(secs + 86_399)
        );
        // The next date, counted by hand.
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let len = match m {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        expected = if d < len {
            (y, m, d + 1)
        } else if m < 12 {
            (y, m + 1, 1)
        } else {
            (y + 1, 1, 1)
        };
    }
    assert_eq!(parse_rfc3339("2100-02-29T00:00:00Z"), None);
    assert!(parse_rfc3339("2000-02-29T00:00:00Z").is_some());
}

#[test]
fn token_value_rules() {
    assert_eq!(token_problem(&"t".repeat(MAX_TOKEN)), None);
    for bad in [
        String::new(),
        "t".repeat(MAX_TOKEN + 1),
        "ghs_a b".to_owned(),
        "ghs_a\u{1}".to_owned(),
        "ghs_a\u{7f}".to_owned(),
        "ghs_\u{17e}".to_owned(),
    ] {
        assert!(token_problem(&bad).is_some(), "{bad:?}");
    }
    // Through the exchange: the token in JSON, escaped where needed.
    for (json_token, ok) in [
        ("t".repeat(MAX_TOKEN), true),
        ("t".repeat(MAX_TOKEN + 1), false),
        (String::new(), false),
        ("a b".to_owned(), false),
        ("a\\u0001".to_owned(), false),
        ("a\\n".to_owned(), false),
        ("\u{17e}".to_owned(), false),
    ] {
        let clock = FakeClock::at(T0);
        let answer = token_answer(&json_token, &format_rfc3339(T0 + 3_600));
        let fake = Fake::new(move |_| Reply::json(201, &answer));
        let result = tokens(&fake, &clock).token();
        assert_eq!(result.is_ok(), ok, "{json_token:?}: {result:?}");
    }
}

fn answer_with(permissions: &str, selection: &str, repositories: &str) -> String {
    format!(
        r#"{{"token":"ghs_x","expires_at":"{}","permissions":{permissions},"repository_selection":"{selection}","repositories":{repositories}}}"#,
        format_rfc3339(T0 + 3_600)
    )
}

const OURS: &str = r#"[{"full_name":"octo-org/demo.repo"}]"#;
const EXACT: &str = r#"{"contents":"write","issues":"write","pull_requests":"write"}"#;

fn exchange(answer: String) -> Result<(), String> {
    let clock = FakeClock::at(T0);
    let fake = Fake::new(move |_| Reply::json(201, &answer));
    tokens(&fake, &clock)
        .token()
        .map(|_| ())
        .map_err(|f| f.to_string())
}

#[test]
fn permissions_must_equal_request() {
    exchange(answer_with(EXACT, "selected", OURS)).expect("exact");
    exchange(answer_with(
        r#"{"contents":"write","issues":"write","metadata":"read","pull_requests":"write"}"#,
        "selected",
        OURS,
    ))
    .expect("plus metadata read");
    for permissions in [
        r#"{"administration":"write","contents":"write","issues":"write","pull_requests":"write"}"#,
        r#"{"contents":"read","issues":"write","pull_requests":"write"}"#,
        r#"{"contents":"write","pull_requests":"write"}"#,
        r#"{"contents":"write","issues":"write","metadata":"write","pull_requests":"write"}"#,
        r#"{"contents":"admin","issues":"write","pull_requests":"write"}"#,
        r#"{"contents":"write","issues":"write","pull_requests":1}"#,
        r#"{}"#,
        r#"[]"#,
    ] {
        let error = exchange(answer_with(permissions, "selected", OURS)).expect_err(permissions);
        assert!(error.contains("unusable"), "{error}");
    }
}

#[test]
fn repository_scope_is_checked() {
    exchange(answer_with(
        EXACT,
        "selected",
        r#"[{"full_name":"OCTO-ORG/Demo.Repo"}]"#,
    ))
    .expect("ASCII case-insensitive");
    for (selection, repositories) in [
        ("all", OURS),
        ("selected", "[]"),
        (
            "selected",
            r#"[{"full_name":"octo-org/demo.repo"},{"full_name":"octo-org/other"}]"#,
        ),
        ("selected", r#"[{"full_name":"octo-org/other"}]"#),
        ("selected", r#"[{"full_name":"evil/demo.repo"}]"#),
        ("selected", r#"[{"name":"demo.repo"}]"#),
    ] {
        exchange(answer_with(EXACT, selection, repositories))
            .expect_err(&format!("{selection} {repositories}"));
    }
}

#[test]
fn unauthorized_refreshes_once() {
    // 401 twice: two exchanges, then a failure.
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(|seen| (!seen.is_token_exchange()).then(|| Reply::status(401)));
    let git = Arc::new(FakeGit::default());
    let github = forge(tokens(&fake, &clock), git);
    let failure = github
        .post_questions(&ticket(KEY), &["Which version?".to_owned()])
        .expect_err("401 twice");
    assert_eq!(fake.exchanges(), 2);
    assert_eq!(fake.api_calls().len(), 2);
    assert!(
        failure.detail().contains("GitHub answered 401"),
        "{failure:?}"
    );
    let bearers: Vec<String> = fake
        .api_calls()
        .iter()
        .map(|s| s.bearer().expect("bearer").to_owned())
        .collect();
    assert_eq!(bearers, [hub_token(1), hub_token(2)]);

    // 401 once: the retry with the new token succeeds.
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let refused = hub_token(1);
    let fake =
        hub.fake(move |seen| (seen.bearer() == Some(refused.as_str())).then(|| Reply::status(401)));
    let github = forge(tokens(&fake, &clock), Arc::new(FakeGit::default()));
    let reference = github
        .post_questions(&ticket(KEY), &["Which version?".to_owned()])
        .expect("the retry succeeds");
    assert_eq!(reference.as_str(), "comment/9001");
    assert_eq!(fake.exchanges(), 2);
}

#[test]
fn concurrent_callers_share_one_exchange() {
    let clock = FakeClock::at(T0);
    let hub = Hub::new(clock.clone());
    let fake = hub.fake(|seen| {
        if seen.is_token_exchange() {
            thread::sleep(Duration::from_millis(200));
        }
        None
    });
    let tokens = tokens(&fake, &clock);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let tokens = Arc::clone(&tokens);
            thread::spawn(move || tokens.token().expect("a token").expose().to_owned())
        })
        .collect();
    let all: Vec<String> = handles
        .into_iter()
        .map(|h| h.join().expect("thread"))
        .collect();
    assert!(all.iter().all(|t| *t == hub_token(1)), "{all:?}");
    assert_eq!(fake.exchanges(), 1);
}

fn refused(path: &Path) -> KeyFileError {
    load_key(path).expect_err(&format!("{} must be refused", path.display()))
}

#[test]
fn key_file_rules() {
    let tmp = TempDir::new("key");
    let dir = tmp.path();
    for mode in [0o600, 0o400] {
        let path = key_file(dir, &format!("ok-{mode:o}.key"), mode);
        let key = load_key(&path).expect("a private key file loads");
        assert_eq!(key.modulus_bits(), 2048);
    }
    for mode in [0o640, 0o604, 0o644, 0o610, 0o601, 0o660, 0o666] {
        let path = key_file(dir, &format!("open-{mode:o}.key"), mode);
        let error = refused(&path);
        assert!(
            matches!(error, KeyFileError::Problem(KeyFileProblem::Mode(m)) if m == mode),
            "{mode:o}: {error:?}"
        );
        assert!(
            error.to_string().contains(&format!("{mode:04o}")),
            "{error}"
        );
    }
    // 0700 has no group or other bit: an executable key file is odd but
    // private, so the rule (ssh's) accepts it.
    assert!(load_key(&key_file(dir, "exec.key", 0o700)).is_ok());

    // Relative and tilde paths.
    for path in ["key.pem", "./key.pem", "~/key.pem"] {
        assert!(
            matches!(refused(Path::new(path)), KeyFileError::NotAbsolute),
            "{path}"
        );
    }
    // A symlink to a good key file.
    let target = key_file(dir, "target.key", 0o600);
    let link = dir.join("link.key");
    symlink(&target, &link).expect("symlink");
    assert!(matches!(
        refused(&link),
        KeyFileError::Problem(KeyFileProblem::Symlink)
    ));
    // A directory.
    let sub = dir.join("dir.key");
    fs::create_dir(&sub).expect("mkdir");
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(matches!(
        refused(&sub),
        KeyFileError::Problem(KeyFileProblem::NotRegular)
    ));
    // A FIFO, refused before it is opened (an open would block).
    let fifo = dir.join("fifo.key");
    let status = std::process::Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    assert!(matches!(
        refused(&fifo),
        KeyFileError::Problem(KeyFileProblem::NotRegular)
    ));
    // Missing.
    assert!(matches!(
        refused(&dir.join("missing.key")),
        KeyFileError::Io(std::io::ErrorKind::NotFound)
    ));
    // Too large: a valid key with 16 KiB of text in front.
    let large = dir.join("large.key");
    let mut content = vec![b'#'; 16_384];
    content.extend_from_slice(KEY_PEM);
    fs::write(&large, content).expect("write");
    fs::set_permissions(&large, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert!(matches!(refused(&large), KeyFileError::TooLarge));
    // Not a key.
    let junk = dir.join("junk.key");
    fs::write(&junk, b"not a key").expect("write");
    fs::set_permissions(&junk, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert!(matches!(refused(&junk), KeyFileError::Key(_)));

    // The owner rule, on synthetic facts: no test user can own a file as
    // another uid.
    let facts = KeyFileFacts {
        symlink: false,
        regular: true,
        uid: 1000,
        mode: 0o100_600,
    };
    assert_eq!(key_file_problem(&facts, 1000), None);
    assert_eq!(
        key_file_problem(&facts, 1001),
        Some(KeyFileProblem::Owner {
            owner: 1000,
            process: 1001
        })
    );
    assert_eq!(
        key_file_problem(&KeyFileFacts { uid: 0, ..facts }, 1000),
        Some(KeyFileProblem::Owner {
            owner: 0,
            process: 1000
        })
    );
    // No error message quotes key bytes.
    let windows = key_base64();
    for error in [refused(&junk), refused(&large)] {
        let text = format!("{error} {error:?}");
        for w in windows.as_bytes().windows(16) {
            assert!(!text.contains(std::str::from_utf8(w).expect("ASCII")));
        }
    }
}
