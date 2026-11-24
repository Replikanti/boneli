//! The refresh against a fake repository (ADR-033 items 2, 6 and 7): the
//! fetches with their statuses, caps, codings and deadlines, the root
//! chain with its rotation cap and the 5.3.11 drop, the outcome, and the
//! repository URL.

mod support;

use std::fs;
use std::time::{Duration, Instant};

use boneli_tuf::{MAX_ROOT_BYTES, MAX_TIMESTAMP_BYTES, Outcome, Repository, Step, Timeouts};
use support::real;
use support::repo::{
    MetaSpec, RootBuilder, START, SnapshotBuilder, TargetsBuilder, TimestampBuilder, obj, s,
};
use support::server::{
    HOST, Reply, Scratch, Server, fixture, pinned, publish, publish_with, root_v1, run, run_with,
    sha256_hex, trusted_root_v2,
};

/// The step a failed run stopped at.
fn step(result: Result<Outcome, boneli_tuf::RefreshError>) -> Step {
    result.expect_err("the refresh must fail").step
}

/// `bytes` with spaces after the JSON up to `len` bytes: still the same
/// document, and its signatures still verify.
fn padded(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.resize(len, b' ');
    out
}

#[test]
fn whole_refresh_installs_target() {
    let scratch = Scratch::new("whole");
    let (server, initial, published) = fixture();
    let outcome = run(&server, &scratch.trust(), &initial).expect("refresh");
    let Outcome::Updated(report) = &outcome else {
        panic!("a first run updates: {outcome:?}");
    };
    assert_eq!(
        (
            report.root_version,
            report.timestamp_version,
            report.snapshot_version,
            report.targets_version
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(
        fs::read(scratch.at("trusted_root.json")).expect("installed"),
        published.target
    );
    assert_eq!(
        server.requested(),
        [
            "2.root.json".to_string(),
            "timestamp.json".to_string(),
            "1.snapshot.json".to_string(),
            "1.targets.json".to_string(),
            format!(
                "targets/{}.trusted_root.json",
                sha256_hex(real::TRUSTED_ROOT)
            ),
        ]
    );
}

#[test]
fn written_file_matches_target() {
    let scratch = Scratch::new("written");
    let (server, initial, _) = fixture();
    let outcome = run(&server, &scratch.trust(), &initial).expect("refresh");
    let written = fs::read(scratch.at("trusted_root.json")).expect("installed");
    assert_eq!(sha256_hex(&written), sha256_hex(real::TRUSTED_ROOT));
    assert_eq!(
        outcome.report().sha256,
        boneli_https::Sha256::digest(&written)
    );
}

#[test]
fn second_run_unchanged() {
    let scratch = Scratch::new("second");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("first run");
    let before = fs::metadata(scratch.at("trusted_root.json")).expect("installed");
    server.clear_log();
    let outcome = run(&server, &scratch.trust(), &initial).expect("second run");
    assert!(matches!(outcome, Outcome::Unchanged(_)), "{outcome:?}");
    assert_eq!(
        server.requested(),
        [
            "2.root.json",
            "timestamp.json",
            "1.snapshot.json",
            "1.targets.json"
        ]
    );
    let after = fs::metadata(scratch.at("trusted_root.json")).expect("still there");
    use std::os::unix::fs::MetadataExt;
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.modified().ok(), after.modified().ok());
}

#[test]
fn new_target_replaces_file() {
    let scratch = Scratch::new("replace");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("first run");
    let v2 = trusted_root_v2();
    publish(&server, 2, &v2);
    let outcome = run(&server, &scratch.trust(), &initial).expect("second run");
    assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
    assert_eq!(fs::read(scratch.at("trusted_root.json")).expect("file"), v2);
}

#[test]
fn only_repository_host_dialed() {
    let scratch = Scratch::new("hosts");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("refresh");
    let dials = server.dials();
    assert_eq!(dials.len(), 5);
    assert!(
        dials.iter().all(|d| d == &(HOST.to_string(), 443)),
        "{dials:?}"
    );
    for seen in server.seen() {
        let names: Vec<&str> = seen.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["Host"], "one GET with Host only");
        assert_eq!(seen.headers[0].1, HOST);
    }
}

#[test]
fn missing_timestamp_refused() {
    let scratch = Scratch::new("no-ts");
    let (server, initial, _) = fixture();
    server.remove("timestamp.json");
    let err = run(&server, &scratch.trust(), &initial).expect_err("no timestamp");
    assert_eq!(err.step, Step::Timestamp);
    assert!(err.detail.contains("404"), "{err}");
}

#[test]
fn root_probe_status_refused() {
    for status in [403, 500] {
        let scratch = Scratch::new(&format!("probe-{status}"));
        let (server, initial, _) = fixture();
        server.answer("2.root.json", Reply::status(status));
        let err = run(&server, &scratch.trust(), &initial).expect_err("a status");
        assert_eq!(err.step, Step::Root(Some(2)), "{status}");
        assert!(err.detail.contains(&status.to_string()), "{err}");
        assert_eq!(server.requested(), ["2.root.json"]);
    }
}

#[test]
fn redirect_refused() {
    let scratch = Scratch::new("redirect");
    let (server, initial, _) = fixture();
    server.answer(
        "timestamp.json",
        Reply::http(
            302,
            &[("Location", "https://evil.example/timestamp.json")],
            b"",
        ),
    );
    assert_eq!(
        step(run(&server, &scratch.trust(), &initial)),
        Step::Timestamp
    );
    assert!(
        server.dials().iter().all(|(h, _)| h == HOST),
        "{:?}",
        server.dials()
    );
}

#[test]
fn content_coding_refused() {
    let scratch = Scratch::new("coding");
    let (server, initial, published) = fixture();
    server.answer(
        "timestamp.json",
        Reply::http(200, &[("Content-Encoding", "gzip")], &published.timestamp),
    );
    let err = run(&server, &scratch.trust(), &initial).expect_err("gzip");
    assert_eq!(err.step, Step::Timestamp);
    assert!(err.detail.contains("coding"), "{err}");
    // `identity` is no coding.
    server.answer(
        "timestamp.json",
        Reply::http(
            200,
            &[("Content-Encoding", "identity")],
            &published.timestamp,
        ),
    );
    run(&server, &scratch.trust(), &initial).expect("identity passes");
}

#[test]
fn content_length_over_cap_refused() {
    let scratch = Scratch::new("length");
    let (server, initial, _) = fixture();
    let declared = MAX_TIMESTAMP_BYTES + 1;
    // A head that declares one byte over the cap, then nothing for 30 s:
    // a client that read the body would wait for it.
    server.answer(
        "timestamp.json",
        Reply::Raw {
            bytes: format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n\r\n").into_bytes(),
            hold: Duration::from_secs(30),
        },
    );
    let begun = Instant::now();
    let err = run(&server, &scratch.trust(), &initial).expect_err("over the cap");
    assert!(
        begun.elapsed() < Duration::from_secs(10),
        "{:?}",
        begun.elapsed()
    );
    assert_eq!(err.step, Step::Timestamp);
    assert!(
        err.detail.contains(&MAX_TIMESTAMP_BYTES.to_string()),
        "{err}"
    );
}

#[test]
fn content_length_other_than_listed_refused() {
    let scratch = Scratch::new("listed-length");
    let (server, initial, _) = fixture();
    let name = format!(
        "targets/{}.trusted_root.json",
        sha256_hex(real::TRUSTED_ROOT)
    );
    let declared = real::TRUSTED_ROOT.len() - 1;
    server.answer(
        &name,
        Reply::Raw {
            bytes: format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n\r\n").into_bytes(),
            hold: Duration::from_secs(30),
        },
    );
    let begun = Instant::now();
    assert_eq!(step(run(&server, &scratch.trust(), &initial)), Step::Target);
    assert!(
        begun.elapsed() < Duration::from_secs(10),
        "{:?}",
        begun.elapsed()
    );
}

#[test]
fn fetched_metadata_cap_inclusive() {
    // Root: 65,536 bytes pass, 65,537 are refused at Root(2).
    let scratch = Scratch::new("cap-root");
    let (server, initial, _) = fixture();
    let v2 = RootBuilder::new(2).bytes();
    server.put("2.root.json", &padded(&v2, MAX_ROOT_BYTES));
    let outcome = run(&server, &scratch.trust(), &initial).expect("root at the cap");
    assert_eq!(outcome.report().root_version, 2);

    let scratch = Scratch::new("cap-root-over");
    let (server, initial, _) = fixture();
    server.put("2.root.json", &padded(&v2, MAX_ROOT_BYTES + 1));
    assert_eq!(
        step(run(&server, &scratch.trust(), &initial)),
        Step::Root(Some(2))
    );

    // Timestamp: 16,384 pass, 16,385 are refused.
    let scratch = Scratch::new("cap-ts");
    let (server, initial, published) = fixture();
    server.put(
        "timestamp.json",
        &padded(&published.timestamp, MAX_TIMESTAMP_BYTES),
    );
    run(&server, &scratch.trust(), &initial).expect("timestamp at the cap");

    let scratch = Scratch::new("cap-ts-over");
    let (server, initial, published) = fixture();
    server.put(
        "timestamp.json",
        &padded(&published.timestamp, MAX_TIMESTAMP_BYTES + 1),
    );
    assert_eq!(
        step(run(&server, &scratch.trust(), &initial)),
        Step::Timestamp
    );
}

#[test]
fn body_without_length_capped() {
    // A body framed by the end of the stream: one byte over the cap is
    // refused, the cap itself passes.
    let raw = |body: &[u8]| {
        let mut bytes = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        bytes.extend_from_slice(body);
        Reply::Raw {
            bytes,
            hold: Duration::ZERO,
        }
    };
    let scratch = Scratch::new("eof-cap");
    let (server, initial, published) = fixture();
    server.answer(
        "timestamp.json",
        raw(&padded(&published.timestamp, MAX_TIMESTAMP_BYTES)),
    );
    run(&server, &scratch.trust(), &initial).expect("at the cap");

    let scratch = Scratch::new("eof-cap-over");
    let (server, initial, published) = fixture();
    server.answer(
        "timestamp.json",
        raw(&padded(&published.timestamp, MAX_TIMESTAMP_BYTES + 1)),
    );
    assert_eq!(
        step(run(&server, &scratch.trust(), &initial)),
        Step::Timestamp
    );
}

#[test]
fn trickle_fails_at_deadline() {
    let scratch = Scratch::new("trickle");
    let (server, initial, published) = fixture();
    let body = published.timestamp.clone();
    server.answer(
        "timestamp.json",
        Reply::Trickle {
            head: format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
            chunks: body.iter().map(|b| vec![*b]).collect(),
            delay: Duration::from_millis(200),
        },
    );
    let io = Duration::from_secs(1);
    let setup = Duration::from_secs(1);
    let timeouts = Timeouts::new(io, setup, 1 << 30).expect("timeouts");
    let begun = Instant::now();
    let result = run_with(&server, &scratch.trust(), &initial, START, timeouts);
    let took = begun.elapsed();
    assert_eq!(step(result), Step::Timestamp);
    // Each byte arrives within `io`, so only the deadline ends it.
    assert!(took >= setup, "{took:?}");
    assert!(took < setup + io + Duration::from_secs(1), "{took:?}");
}

#[test]
fn timeouts_refuse_zero() {
    assert!(Timeouts::new(Duration::ZERO, Duration::from_secs(1), 1).is_err());
    assert!(Timeouts::new(Duration::from_secs(1), Duration::ZERO, 1).is_err());
    assert!(Timeouts::new(Duration::from_secs(1), Duration::from_secs(1), 0).is_err());
    let d = Timeouts::default();
    assert_eq!(
        d,
        Timeouts::new(Duration::from_secs(30), Duration::from_secs(30), 1_048_576).expect("ok")
    );
}

#[test]
fn chain_persists_each_root() {
    let scratch = Scratch::new("chain");
    let (server, initial, _) = fixture();
    let roots: Vec<Vec<u8>> = (2..=4).map(|v| RootBuilder::new(v).bytes()).collect();
    for (i, root) in roots.iter().enumerate() {
        server.put(&format!("{}.root.json", i + 2), root);
    }
    let outcome = run(&server, &scratch.trust(), &initial).expect("refresh");
    assert_eq!(outcome.report().root_version, 4);
    assert_eq!(
        fs::read(scratch.at("tuf/root.json")).expect("root"),
        roots[2]
    );
}

#[test]
fn chain_failure_persists_verified_prefix() {
    let scratch = Scratch::new("prefix");
    let (server, initial, _) = fixture();
    let v2 = RootBuilder::new(2).bytes();
    let v3 = RootBuilder::new(3).bytes();
    // v4 signed by 2 of the 3 root keys it needs.
    let forged = RootBuilder::new(4).signed_by(&[1, 2]);
    server.put("2.root.json", &v2);
    server.put("3.root.json", &v3);
    server.put("4.root.json", &forged);
    let err = run(&server, &scratch.trust(), &initial).expect_err("forged v4");
    assert_eq!(err.step, Step::Root(Some(4)));
    assert_eq!(fs::read(scratch.at("tuf/root.json")).expect("root"), v3);
    assert!(!scratch.at("trusted_root.json").exists());
}

#[test]
fn thirty_two_rotations_pass() {
    let scratch = Scratch::new("thirty-two");
    let (server, initial, _) = fixture();
    for v in 2..=33 {
        server.put(&format!("{v}.root.json"), &RootBuilder::new(v).bytes());
    }
    let outcome = run(&server, &scratch.trust(), &initial).expect("32 rotations");
    assert_eq!(outcome.report().root_version, 33);
    let roots = server
        .requested()
        .iter()
        .filter(|t| t.ends_with(".root.json"))
        .count();
    assert_eq!(roots, 33);
}

#[test]
fn rotation_cap_resumes() {
    let scratch = Scratch::new("cap-resume");
    let (server, initial, _) = fixture();
    let roots: Vec<Vec<u8>> = (2..=34).map(|v| RootBuilder::new(v).bytes()).collect();
    for (i, root) in roots.iter().enumerate() {
        server.put(&format!("{}.root.json", i + 2), root);
    }
    let err = run(&server, &scratch.trust(), &initial).expect_err("33 rotations");
    assert_eq!(err.step, Step::Root(Some(34)));
    let root_requests = |server: &Server| {
        server
            .requested()
            .iter()
            .filter(|t| t.ends_with(".root.json"))
            .count()
    };
    assert_eq!(root_requests(&server), 33);
    // The 32 verified roots stay; the 33rd was not trusted.
    assert_eq!(
        fs::read(scratch.at("tuf/root.json")).expect("root"),
        roots[31]
    );
    server.clear_log();
    let outcome = run(&server, &scratch.trust(), &initial).expect("the next run continues");
    assert_eq!(outcome.report().root_version, 34);
    assert_eq!(root_requests(&server), 2);
}

#[test]
fn root_version_overflow_no_request() {
    let scratch = Scratch::new("overflow");
    let server = Server::new();
    publish(&server, 1, real::TRUSTED_ROOT);
    let max = RootBuilder::new(i64::MAX).bytes();
    let initial = pinned(&max);
    let err = run(&server, &scratch.trust(), &initial).expect_err("no successor");
    assert_eq!(err.step, Step::Root(Some(i64::MAX)));
    assert!(server.requested().is_empty());
}

#[test]
fn expired_final_root_refused() {
    let scratch = Scratch::new("expired-root");
    let server = Server::new();
    publish(&server, 1, real::TRUSTED_ROOT);
    let mut old = RootBuilder::new(1);
    old.expires = "2020-01-01T00:00:00Z".to_string();
    let initial = pinned(&old.bytes());
    let err = run(&server, &scratch.trust(), &initial).expect_err("expired");
    assert_eq!(err.step, Step::Root(Some(1)));
    // An expired intermediate passes when a valid root follows.
    let mut v2 = RootBuilder::new(2);
    v2.expires = "2020-01-01T00:00:00Z".to_string();
    server.put("2.root.json", &v2.bytes());
    server.put("3.root.json", &RootBuilder::new(3).bytes());
    let scratch = Scratch::new("expired-intermediate");
    run(&server, &scratch.trust(), &initial).expect("expired intermediates pass");
}

#[test]
fn inconsistent_repository_refused() {
    let scratch = Scratch::new("inconsistent");
    let server = Server::new();
    publish(&server, 1, real::TRUSTED_ROOT);
    let mut root = RootBuilder::new(1);
    root.consistent_snapshot = false;
    let initial = pinned(&root.bytes());
    let err = run(&server, &scratch.trust(), &initial).expect_err("no consistent snapshots");
    assert_eq!(err.step, Step::Root(Some(1)));
    assert!(!server.requested().contains(&"timestamp.json".to_string()));
}

#[test]
fn rotated_online_keys_deleted_with_root() {
    // Review of PR 2: a run that saves a root which changes the online keys
    // and stops before the timestamp must not leave the old timestamp and
    // snapshot for the next run, whose set starts from that root and no
    // longer sees the change (TUF 5.3.11).
    let scratch = Scratch::new("ff-delete");
    let server = Server::new();
    let initial = pinned(&root_v1());
    publish(&server, 1000, real::TRUSTED_ROOT);
    run(&server, &scratch.trust(), &initial).expect("first run at v1000");
    assert!(scratch.at("tuf/timestamp.json").exists());
    assert!(scratch.at("tuf/snapshot.json").exists());

    // Root v2 adds key 7 to the timestamp role: changed key material, and
    // the stored timestamp v1000 (key 6) still verifies under it.
    let mut v2 = RootBuilder::new(2);
    v2.timestamp.keys = vec![6, 7];
    let v2 = v2.bytes();
    server.put("2.root.json", &v2);
    server.remove("timestamp.json");
    let err = run(&server, &scratch.trust(), &initial).expect_err("stops at the timestamp");
    assert_eq!(err.step, Step::Timestamp);
    assert_eq!(fs::read(scratch.at("tuf/root.json")).expect("root"), v2);
    assert!(!scratch.at("tuf/timestamp.json").exists());
    assert!(!scratch.at("tuf/snapshot.json").exists());

    // The recovered repository starts again at version 1.
    publish(&server, 1, real::TRUSTED_ROOT);
    let outcome = run(&server, &scratch.trust(), &initial).expect("versions start again");
    assert_eq!(outcome.report().timestamp_version, 1);
}

#[test]
fn unrotated_root_keeps_rollback_state() {
    let scratch = Scratch::new("ff-keep");
    let server = Server::new();
    let initial = pinned(&root_v1());
    publish(&server, 1000, real::TRUSTED_ROOT);
    run(&server, &scratch.trust(), &initial).expect("first run at v1000");
    server.put("2.root.json", &RootBuilder::new(2).bytes());
    publish(&server, 1, real::TRUSTED_ROOT);
    let err = run(&server, &scratch.trust(), &initial).expect_err("rollback");
    assert_eq!(err.step, Step::Timestamp);
    assert!(err.detail.contains("below"), "{err}");
}

#[test]
fn rollback_against_stored_timestamp_refused() {
    let scratch = Scratch::new("rollback");
    let server = Server::new();
    let initial = pinned(&root_v1());
    publish(&server, 5, real::TRUSTED_ROOT);
    run(&server, &scratch.trust(), &initial).expect("v5");
    publish(&server, 4, real::TRUSTED_ROOT);
    assert_eq!(
        step(run(&server, &scratch.trust(), &initial)),
        Step::Timestamp
    );
}

#[test]
fn snapshot_rollback_against_stored_snapshot_refused() {
    let scratch = Scratch::new("snap-rollback");
    let server = Server::new();
    let initial = pinned(&root_v1());
    publish(&server, 5, real::TRUSTED_ROOT);
    run(&server, &scratch.trust(), &initial).expect("v5");
    // A timestamp v6 naming snapshot v6, whose targets entry is lowered to 4.
    let mut targets = TargetsBuilder::new(4);
    targets.targets = vec![(
        support::repo::TARGET_NAME.to_string(),
        support::repo::target_entry(real::TRUSTED_ROOT),
    )];
    let targets_bytes = targets.bytes();
    let snapshot = SnapshotBuilder::new(6, MetaSpec::version(4)).bytes();
    let timestamp = TimestampBuilder::new(6, MetaSpec::version(6)).bytes();
    server.put("timestamp.json", &timestamp);
    server.put("6.snapshot.json", &snapshot);
    server.put("4.targets.json", &targets_bytes);
    assert_eq!(
        step(run(&server, &scratch.trust(), &initial)),
        Step::Snapshot(6)
    );
}

#[test]
fn listed_snapshot_hash_checked() {
    let scratch = Scratch::new("snap-hash");
    let (server, initial, published) = fixture();
    let other = SnapshotBuilder::new(1, MetaSpec::version(1)).bytes();
    let timestamp = TimestampBuilder::new(1, MetaSpec::of(1, &other)).bytes();
    server.put("timestamp.json", &timestamp);
    assert_ne!(other, published.snapshot);
    assert_eq!(
        step(run(&server, &scratch.trust(), &initial)),
        Step::Snapshot(1)
    );
}

#[test]
fn target_hash_mismatch_refused() {
    let scratch = Scratch::new("target-hash");
    let (server, initial, _) = fixture();
    let name = format!(
        "targets/{}.trusted_root.json",
        sha256_hex(real::TRUSTED_ROOT)
    );
    let mut wrong = real::TRUSTED_ROOT.to_vec();
    wrong[10] ^= 1;
    server.put(&name, &wrong);
    assert_eq!(step(run(&server, &scratch.trust(), &initial)), Step::Target);
    assert!(!scratch.at("trusted_root.json").exists());
}

#[test]
fn target_not_listed_refused() {
    let scratch = Scratch::new("not-listed");
    let server = Server::new();
    let mut targets = TargetsBuilder::new(1);
    targets.targets = vec![(
        "trusted_root.json ".to_string(),
        support::repo::target_entry(real::TRUSTED_ROOT),
    )];
    publish_with(&server, 1, &targets, real::TRUSTED_ROOT);
    let initial = pinned(&root_v1());
    assert_eq!(step(run(&server, &scratch.trust(), &initial)), Step::Target);
    assert!(!server.requested().iter().any(|t| t.starts_with("targets/")));
}

#[test]
fn target_over_cap_never_requested() {
    let cap = boneli_sigstore::MAX_TRUSTED_ROOT_BYTES;
    // At the cap: fetched, then refused by `TrustedRoot::from_json`.
    let scratch = Scratch::new("target-cap");
    let server = Server::new();
    let big = {
        let mut b = b"{}".to_vec();
        b.resize(cap, b' ');
        b
    };
    publish(&server, 1, &big);
    let initial = pinned(&root_v1());
    assert_eq!(
        step(run(&server, &scratch.trust(), &initial)),
        Step::TrustedRoot
    );
    assert!(server.requested().iter().any(|t| t.starts_with("targets/")));

    // One byte over: never requested.
    let scratch = Scratch::new("target-cap-over");
    let server = Server::new();
    let mut targets = TargetsBuilder::new(1);
    let mut entry = support::repo::target_entry(real::TRUSTED_ROOT);
    support::repo::set(
        &mut entry,
        "length",
        boneli_json::Value::from(cap as i64 + 1),
    );
    targets.targets = vec![(support::repo::TARGET_NAME.to_string(), entry)];
    publish_with(&server, 1, &targets, real::TRUSTED_ROOT);
    assert_eq!(step(run(&server, &scratch.trust(), &initial)), Step::Target);
    assert!(!server.requested().iter().any(|t| t.starts_with("targets/")));
}

#[test]
fn unreadable_trusted_root_not_installed() {
    let scratch = Scratch::new("unreadable");
    let server = Server::new();
    publish(&server, 1, b"{}");
    let initial = pinned(&root_v1());
    let err = run(&server, &scratch.trust(), &initial).expect_err("{} is no trusted root");
    assert_eq!(err.step, Step::TrustedRoot);
    assert!(!scratch.at("trusted_root.json").exists());
}

#[test]
fn errors_echo_no_metadata_text() {
    let scratch = Scratch::new("echo");
    let server = Server::new();
    let initial = pinned(&root_v1());
    let mut targets = TargetsBuilder::new(1);
    targets.targets = vec![(
        support::repo::TARGET_NAME.to_string(),
        obj([
            ("length", boneli_json::Value::from(1_i64)),
            ("hashes", obj([("sha256", s("SECRET-HASH"))])),
        ]),
    )];
    publish_with(&server, 1, &targets, real::TRUSTED_ROOT);
    let err = run(&server, &scratch.trust(), &initial).expect_err("not listed");
    let text = err.to_string();
    assert!(!text.contains("SECRET"), "{text}");
}

#[test]
fn repository_url_refused_forms() {
    // Named as such, not as a host the grammar refuses.
    for bad in [
        "https://user@tuf.example",
        "https://tuf.example?x=1",
        "https://tuf.example/a?x=1",
        "https://tuf.example#frag",
        "https://tuf.example/a%2fb",
        "https://tuf%2eexample",
    ] {
        assert_eq!(
            Repository::parse(bad),
            Err(boneli_tuf::RepositoryError(
                "must have no userinfo, query, fragment or percent sign"
            )),
            "{bad:?}"
        );
    }
    for bad in [
        "http://tuf.example",
        "file:///tuf",
        "https://user@tuf.example",
        "https://tuf.example?x=1",
        "https://tuf.example#frag",
        "https://tuf.example/a%2fb",
        "https://tuf.example/a/../b",
        "https://tuf.example/./b",
        "https://tuf.example/a//b",
        "https://tuf.example/",
        "https://tuf.example/a b",
        "https://TUF.example",
        "https://127.1",
        "https://tuf.example:0",
        "https://tuf.example:0443",
        "https://tuf.example:",
        "https://",
        "https:/tuf.example",
        "HTTPS://tuf.example",
        " https://tuf.example",
    ] {
        assert!(Repository::parse(bad).is_err(), "{bad:?} must be refused");
    }
}

#[test]
fn repository_url_round_trip() {
    for (url, host, port) in [
        (
            "https://tuf-repo-cdn.sigstore.dev",
            "tuf-repo-cdn.sigstore.dev",
            443,
        ),
        ("https://tuf.example:8443/a/b.c~d_e-f", "tuf.example", 8443),
        ("https://[::1]:8443/repo", "::1", 8443),
        ("https://192.0.2.1", "192.0.2.1", 443),
    ] {
        let parsed = Repository::parse(url).expect(url);
        assert_eq!((parsed.host(), parsed.port()), (host, port), "{url}");
        let rendered = parsed.to_string();
        assert_eq!(rendered, url);
        assert_eq!(Repository::parse(&rendered).expect("again"), parsed);
    }
    // An explicit default port renders without it and parses equal.
    let explicit = Repository::parse("https://tuf.example:443").expect("443");
    assert_eq!(explicit.to_string(), "https://tuf.example");
    assert_eq!(
        Repository::parse(&explicit.to_string()).expect("again"),
        explicit
    );
}

#[test]
fn rotation_deletes_before_root_stored() {
    // The stored timestamp and snapshot go before the rotating root is
    // stored: when their removal fails, the root is not stored either.
    let scratch = Scratch::new("ff-order");
    let server = Server::new();
    let v1 = root_v1();
    let initial = pinned(&v1);
    publish(&server, 3, real::TRUSTED_ROOT);
    run(&server, &scratch.trust(), &initial).expect("first run");
    fs::remove_file(scratch.at("tuf/timestamp.json")).expect("remove");
    fs::create_dir(scratch.at("tuf/timestamp.json")).expect("a directory in its place");
    let mut v2 = RootBuilder::new(2);
    v2.snapshot.keys = vec![7];
    server.put("2.root.json", &v2.bytes());
    let err = run(&server, &scratch.trust(), &initial).expect_err("removal fails");
    assert_eq!(err.step, Step::Write);
    assert_eq!(fs::read(scratch.at("tuf/root.json")).expect("root"), v1);
}

#[test]
fn same_length_target_replaces_file() {
    let scratch = Scratch::new("same-length");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("first run");
    // The last line feed becomes a space: same length, another SHA-256.
    let mut other = real::TRUSTED_ROOT.to_vec();
    let last = other.len() - 1;
    other[last] = b' ';
    publish(&server, 2, &other);
    let outcome = run(&server, &scratch.trust(), &initial).expect("second run");
    assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
    assert_eq!(
        fs::read(scratch.at("trusted_root.json")).expect("file"),
        other
    );
}

#[test]
fn listed_length_over_cap_never_requested() {
    let scratch = Scratch::new("listed-cap");
    let (server, initial, _) = fixture();
    let over = boneli_tuf::MAX_SNAPSHOT_BYTES as i64 + 1;
    let mut listed = MetaSpec::version(1);
    listed.length = Some(over);
    server.put("timestamp.json", &TimestampBuilder::new(1, listed).bytes());
    assert_eq!(
        step(run(&server, &scratch.trust(), &initial)),
        Step::Snapshot(1)
    );
    assert!(!server.requested().contains(&"1.snapshot.json".to_string()));
}
