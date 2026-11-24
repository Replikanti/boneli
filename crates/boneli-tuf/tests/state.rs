//! The trust directory (ADR-033 items 5 and 6): its path rules, the lock,
//! the pin, the stored metadata, the output file and its atomic
//! replacement, which leaves the old file untouched on every failure.

mod support;

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::thread;
use std::time::Duration;

use boneli_private_dir::lock::{FileLock, Kind};
use boneli_tuf::{InitialRoot, Outcome, Step};
use support::real;
use support::repo::{
    MetaSpec, RoleSpec, RootBuilder, SnapshotBuilder, TargetsBuilder, TimestampBuilder,
};
use support::server::{
    Reply, Scratch, Server, fixture, pinned, publish, root_v1, run, sha256_hex, trusted_root_v2,
};

/// What identifies the installed file: its bytes, inode and mtime.
fn identity(path: &Path) -> (Vec<u8>, u64, Option<std::time::SystemTime>) {
    let meta = fs::symlink_metadata(path).expect("the file");
    (
        fs::read(path).expect("its bytes"),
        meta.ino(),
        meta.modified().ok(),
    )
}

#[test]
fn trust_dir_path_rules() {
    let (server, initial, _) = fixture();
    for bad in ["trust", "~/trust"] {
        let err = run(&server, Path::new(bad), &initial).expect_err("relative");
        assert_eq!(err.step, Step::Lock, "{bad}");
    }
    let scratch = Scratch::new("dir-dots");
    for bad in [scratch.0.join("a/../trust"), scratch.0.join("./trust")] {
        let err = run(&server, &bad, &initial).expect_err("dot component");
        assert_eq!(err.step, Step::Lock, "{}", bad.display());
    }
    assert!(server.requested().is_empty());

    // A group-writable ancestor is refused.
    let scratch = Scratch::new("dir-group");
    let open = scratch.0.join("open");
    fs::create_dir(&open).expect("dir");
    fs::set_permissions(&open, fs::Permissions::from_mode(0o775)).expect("chmod");
    let err = run(&server, &open.join("trust"), &initial).expect_err("group-writable");
    assert_eq!(err.step, Step::Lock);

    // A symlinked directory resolves, and its ancestors are checked.
    let scratch = Scratch::new("dir-link");
    let real_dir = scratch.0.join("real");
    fs::create_dir(&real_dir).expect("dir");
    fs::set_permissions(&real_dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    let link = scratch.0.join("link");
    symlink(&real_dir, &link).expect("link");
    run(&server, &link, &initial).expect("a symlinked trust directory");
    assert!(real_dir.join("trusted_root.json").is_file());

    let hidden = open.join("real");
    fs::create_dir(&hidden).expect("dir");
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o700)).expect("chmod");
    let link2 = scratch.0.join("link2");
    symlink(&hidden, &link2).expect("link");
    let err = run(&server, &link2, &initial).expect_err("resolved under a group-writable dir");
    assert_eq!(err.step, Step::Lock);
}

#[test]
fn trust_dir_created_private() {
    let scratch = Scratch::new("private");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("refresh");
    for (path, mode) in [
        (scratch.trust(), 0o700),
        (scratch.at("tuf"), 0o700),
        (scratch.at("trusted_root.json"), 0o600),
        (scratch.at("tuf/root.json"), 0o600),
        (scratch.at("tuf/timestamp.json"), 0o600),
        (scratch.at("tuf/snapshot.json"), 0o600),
        (scratch.at("tuf/pin"), 0o600),
        (scratch.at("lock"), 0o600),
    ] {
        let meta = fs::symlink_metadata(&path).expect("exists");
        assert_eq!(meta.mode() & 0o777, mode, "{}", path.display());
    }
}

#[test]
fn concurrent_refresh_busy() {
    let scratch = Scratch::new("busy");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("first run");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(scratch.at("lock"))
        .expect("lock file");
    let held = FileLock::try_take(file, Kind::Exclusive).expect("lock");
    server.clear_log();
    let err = run(&server, &scratch.trust(), &initial).expect_err("busy");
    assert_eq!(err.step, Step::Lock);
    assert!(err.detail.contains("busy"), "{err}");
    assert!(server.requested().is_empty());
    drop(held);
    run(&server, &scratch.trust(), &initial).expect("free again");
}

#[test]
fn stale_temporary_removed() {
    let scratch = Scratch::new("stale");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("first run");
    let stale = [
        scratch.at(".tmp-trusted_root.json"),
        scratch.at("tuf/.tmp-timestamp.json"),
    ];
    for path in &stale {
        fs::write(path, b"left by a crashed run").expect("plant");
    }
    run(&server, &scratch.trust(), &initial).expect("second run");
    for path in &stale {
        assert!(!path.exists(), "{}", path.display());
    }
}

#[test]
fn state_files_are_fetched_bytes() {
    let scratch = Scratch::new("state-bytes");
    let (server, initial, published) = fixture();
    let v2 = RootBuilder::new(2).bytes();
    server.put("2.root.json", &v2);
    let first = run(&server, &scratch.trust(), &initial).expect("refresh");
    assert_eq!(fs::read(scratch.at("tuf/root.json")).expect("root"), v2);
    assert_eq!(
        fs::read(scratch.at("tuf/timestamp.json")).expect("timestamp"),
        published.timestamp
    );
    assert_eq!(
        fs::read(scratch.at("tuf/snapshot.json")).expect("snapshot"),
        published.snapshot
    );
    assert!(!scratch.at("tuf/targets.json").exists());
    assert_eq!(
        fs::read_to_string(scratch.at("tuf/pin")).expect("pin"),
        format!("{}\n", initial.sha256_hex())
    );
    let second = run(&server, &scratch.trust(), &initial).expect("again");
    let versions = |o: &Outcome| {
        let r = o.report();
        (
            r.root_version,
            r.timestamp_version,
            r.snapshot_version,
            r.targets_version,
        )
    };
    assert_eq!(versions(&first), versions(&second));
}

#[test]
fn pin_mismatch_refused() {
    let root = root_v1();
    let other = sha256_hex(b"another root");
    let err = InitialRoot::new(root, &other).expect_err("mismatch");
    assert_eq!(err.step, Step::InitialRoot);
}

#[test]
fn pin_malformed_refused() {
    let root = root_v1();
    let pin = sha256_hex(&root);
    for bad in [
        pin.to_uppercase(),
        pin[..63].to_string(),
        format!("{pin}0"),
        format!("sha256:{pin}"),
        format!(" {pin}"),
        String::new(),
    ] {
        let err = InitialRoot::new(root.clone(), &bad).expect_err("malformed pin");
        assert_eq!(err.step, Step::InitialRoot, "{bad:?}");
        assert!(err.detail.contains("64 lower-case hex"), "{bad:?}: {err}");
    }
}

#[test]
fn pinned_root_unverified_refused() {
    let below = RootBuilder::new(1).signed_by(&[1, 2]);
    let err = InitialRoot::new(below.clone(), &sha256_hex(&below)).expect_err("2 of 3");
    assert_eq!(err.step, Step::InitialRoot);
    let big = vec![b' '; boneli_tuf::MAX_ROOT_BYTES + 1];
    let err = InitialRoot::new(big.clone(), &sha256_hex(&big)).expect_err("too large");
    assert_eq!(err.step, Step::InitialRoot);
    assert!(err.detail.contains("larger than"), "{err}");
}

#[test]
fn pin_change_refused() {
    let scratch = Scratch::new("pin-change");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("bootstrap");
    let other = pinned(&root_v1());
    assert_ne!(other.sha256_hex(), initial.sha256_hex());
    server.clear_log();
    let err = run(&server, &scratch.trust(), &other).expect_err("another pin");
    assert_eq!(err.step, Step::InitialRoot);
    assert!(err.detail.contains("tuf/"), "names the remedy: {err}");
    assert!(server.requested().is_empty());
    // The remedy works.
    fs::remove_dir_all(scratch.at("tuf")).expect("remove tuf/");
    run(&server, &scratch.trust(), &other).expect("bootstrap again");
}

#[test]
fn stored_root_without_pin_refused() {
    let scratch = Scratch::new("no-pin");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("bootstrap");
    fs::remove_file(scratch.at("tuf/pin")).expect("remove pin");
    let err = run(&server, &scratch.trust(), &initial).expect_err("no pin");
    assert_eq!(err.step, Step::InitialRoot);
}

#[test]
fn stored_root_is_used_not_the_pin() {
    // Once bootstrapped, the chain starts at the stored root: v2 stored,
    // so the next run asks for 3.root.json.
    let scratch = Scratch::new("stored-root");
    let (server, initial, _) = fixture();
    server.put("2.root.json", &RootBuilder::new(2).bytes());
    run(&server, &scratch.trust(), &initial).expect("to v2");
    server.clear_log();
    run(&server, &scratch.trust(), &initial).expect("again");
    assert_eq!(server.requested()[0], "3.root.json");
}

#[test]
fn corrupt_stored_root_fails_closed() {
    let scratch = Scratch::new("corrupt-root");
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("bootstrap");
    for corrupt in [
        b"not json".to_vec(),
        RootBuilder::new(1).signed_by(&[1]),
        vec![b' '; boneli_tuf::MAX_ROOT_BYTES + 1],
    ] {
        fs::write(scratch.at("tuf/root.json"), &corrupt).expect("corrupt");
        server.clear_log();
        let err = run(&server, &scratch.trust(), &initial).expect_err("corrupt root");
        assert_eq!(err.step, Step::Root(None));
        assert!(err.detail.contains("tuf/"), "names the remedy: {err}");
        assert!(server.requested().is_empty());
    }
}

#[test]
fn corrupt_local_timestamp_ignored() {
    let scratch = Scratch::new("corrupt-ts");
    let (server, initial, published) = fixture();
    run(&server, &scratch.trust(), &initial).expect("bootstrap");
    for corrupt in [
        b"not json".to_vec(),
        TimestampBuilder::new(5000, MetaSpec::version(1)).signed_by(&[1]),
        vec![b' '; boneli_tuf::MAX_TIMESTAMP_BYTES + 1],
    ] {
        fs::write(scratch.at("tuf/timestamp.json"), &corrupt).expect("corrupt");
        run(&server, &scratch.trust(), &initial).expect("ignored");
        assert_eq!(
            fs::read(scratch.at("tuf/timestamp.json")).expect("rewritten"),
            published.timestamp
        );
    }
}

#[test]
fn corrupt_local_snapshot_ignored() {
    let scratch = Scratch::new("corrupt-snap");
    let (server, initial, published) = fixture();
    run(&server, &scratch.trust(), &initial).expect("bootstrap");
    // Signed by a key that is not the snapshot key, naming targets v9.
    let foreign = SnapshotBuilder::new(9, MetaSpec::version(9)).signed_by(&[1]);
    fs::write(scratch.at("tuf/snapshot.json"), &foreign).expect("corrupt");
    run(&server, &scratch.trust(), &initial).expect("ignored");
    assert_eq!(
        fs::read(scratch.at("tuf/snapshot.json")).expect("rewritten"),
        published.snapshot
    );
}

#[test]
fn output_symlink_replaced_not_followed() {
    let scratch = Scratch::new("out-link");
    let (server, initial, published) = fixture();
    fs::create_dir(scratch.trust()).expect("dir");
    fs::set_permissions(scratch.trust(), fs::Permissions::from_mode(0o700)).expect("chmod");
    let elsewhere = scratch.0.join("elsewhere.json");
    fs::write(&elsewhere, b"someone else's file").expect("write");
    symlink(&elsewhere, scratch.at("trusted_root.json")).expect("link");
    let outcome = run(&server, &scratch.trust(), &initial).expect("refresh");
    assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
    let meta = fs::symlink_metadata(scratch.at("trusted_root.json")).expect("file");
    assert!(meta.file_type().is_file());
    assert_eq!(
        fs::read(scratch.at("trusted_root.json")).expect("bytes"),
        published.target
    );
    assert_eq!(
        fs::read(&elsewhere).expect("untouched"),
        b"someone else's file"
    );
}

#[test]
fn output_symlink_to_identical_file_replaced() {
    // A link to a file with the target's bytes is no installed file.
    let scratch = Scratch::new("out-link-same");
    let (server, initial, _) = fixture();
    fs::create_dir(scratch.trust()).expect("dir");
    fs::set_permissions(scratch.trust(), fs::Permissions::from_mode(0o700)).expect("chmod");
    let elsewhere = scratch.0.join("elsewhere.json");
    fs::write(&elsewhere, real::TRUSTED_ROOT).expect("write");
    symlink(&elsewhere, scratch.at("trusted_root.json")).expect("link");
    let outcome = run(&server, &scratch.trust(), &initial).expect("refresh");
    assert!(matches!(outcome, Outcome::Updated(_)), "{outcome:?}");
    assert!(
        fs::symlink_metadata(scratch.at("trusted_root.json"))
            .expect("file")
            .file_type()
            .is_file()
    );
}

#[test]
fn output_unwritable_fails_at_write() {
    let scratch = Scratch::new("out-dir");
    let (server, initial, published) = fixture();
    fs::create_dir(scratch.trust()).expect("dir");
    fs::set_permissions(scratch.trust(), fs::Permissions::from_mode(0o700)).expect("chmod");
    fs::create_dir(scratch.at("trusted_root.json")).expect("a directory in its place");
    let err = run(&server, &scratch.trust(), &initial).expect_err("a directory");
    assert_eq!(err.step, Step::Write);
    // TUF state is kept.
    assert_eq!(
        fs::read(scratch.at("tuf/timestamp.json")).expect("timestamp"),
        published.timestamp
    );
    assert!(scratch.at("trusted_root.json").is_dir());
    let leftovers: Vec<_> = fs::read_dir(scratch.trust())
        .expect("list")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// After a first run installs the real trusted root, `break_it` makes the
/// next run fail at `expected`; the installed file keeps its bytes, inode
/// and mtime.
fn keeps_file(
    tag: &str,
    expected: Step,
    break_it: impl FnOnce(&Server, &Scratch) -> Option<InitialRoot>,
) {
    let scratch = Scratch::new(tag);
    let (server, initial, _) = fixture();
    run(&server, &scratch.trust(), &initial).expect("first run");
    let before = identity(&scratch.at("trusted_root.json"));
    // A newer target, so a run that got through would replace the file.
    publish(&server, 2, &trusted_root_v2());
    let initial = break_it(&server, &scratch).unwrap_or(initial);
    let err = run(&server, &scratch.trust(), &initial).expect_err("broken");
    assert_eq!(err.step, expected, "{tag}: {err}");
    assert_eq!(identity(&scratch.at("trusted_root.json")), before, "{tag}");
}

#[test]
fn failure_leaves_file_unchanged() {
    let mut held = None;
    keeps_file("keep-lock", Step::Lock, |_, scratch| {
        let file = File::options()
            .read(true)
            .write(true)
            .open(scratch.at("lock"))
            .expect("lock file");
        held = Some(FileLock::try_take(file, Kind::Exclusive).expect("lock"));
        None
    });
    drop(held);
    keeps_file("keep-pin", Step::InitialRoot, |_, _| {
        Some(pinned(&root_v1()))
    });
    keeps_file("keep-root", Step::Root(Some(2)), |server, _| {
        server.put("2.root.json", &RootBuilder::new(2).signed_by(&[1, 2]));
        None
    });
    keeps_file("keep-ts", Step::Timestamp, |server, _| {
        server.answer("timestamp.json", Reply::status(404));
        None
    });
    keeps_file("keep-snap", Step::Snapshot(2), |server, _| {
        let mut expired = SnapshotBuilder::new(2, MetaSpec::version(2));
        expired.expires = "2020-01-01T00:00:00Z".to_string();
        server.put("2.snapshot.json", &expired.bytes());
        None
    });
    keeps_file("keep-targets", Step::Targets(2), |server, _| {
        server.put("2.targets.json", &TargetsBuilder::new(2).signed_by(&[1, 2]));
        None
    });
    keeps_file("keep-target", Step::Target, |server, _| {
        let name = format!(
            "targets/{}.trusted_root.json",
            sha256_hex(&trusted_root_v2())
        );
        server.put(&name, real::TRUSTED_ROOT);
        None
    });
    keeps_file("keep-trusted-root", Step::TrustedRoot, |server, _| {
        publish(server, 3, b"{}");
        None
    });
    keeps_file("keep-write", Step::Write, |_, scratch| {
        // The snapshot cannot be stored: a directory holds its name.
        fs::remove_file(scratch.at("tuf/snapshot.json")).expect("remove");
        fs::create_dir(scratch.at("tuf/snapshot.json")).expect("a directory");
        None
    });
}

#[test]
fn tuf_symlink_refused() {
    let scratch = Scratch::new("tuf-link");
    let (server, initial, _) = fixture();
    fs::create_dir(scratch.trust()).expect("dir");
    fs::set_permissions(scratch.trust(), fs::Permissions::from_mode(0o700)).expect("chmod");
    let elsewhere = scratch.0.join("elsewhere");
    fs::create_dir(&elsewhere).expect("dir");
    symlink(&elsewhere, scratch.at("tuf")).expect("link");
    let err = run(&server, &scratch.trust(), &initial).expect_err("tuf/ is a link");
    assert_eq!(err.step, Step::Lock);
    assert_eq!(fs::read_dir(&elsewhere).expect("list").count(), 0);
}

/// A server whose `2.root.json` (the default root v2) arrives over about
/// 1.8 s, so a refresh against it is still in its root chain while the
/// test works on the trust directory; and that v2.
fn slow_chain() -> (Server, Vec<u8>) {
    let server = Server::new();
    publish(&server, 1, real::TRUSTED_ROOT);
    let v2 = RootBuilder::new(2).bytes();
    let chunks = v2.chunks(v2.len() / 5 + 1).map(<[u8]>::to_vec).collect();
    server.answer(
        "2.root.json",
        Reply::Trickle {
            head: format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", v2.len()).into_bytes(),
            chunks,
            delay: Duration::from_millis(300),
        },
    );
    (server, v2)
}

/// An initial root of another chain (root key 7 only), so another pin.
fn other_root() -> Vec<u8> {
    let mut b = RootBuilder::new(1);
    b.root = RoleSpec {
        keys: vec![7],
        threshold: 1,
    };
    b.bytes()
}

#[test]
fn remove_tuf_during_refresh_mixes_no_chains() {
    // Review of PR 3: the remedy "remove tuf/" while a refresh runs. The
    // lock is outside tuf/, so a refresh under the new pin is busy until
    // the old one ends, and the old one writes nothing into a new tuf/.
    let scratch = Scratch::new("race-tuf");
    let (server_a, a_v2) = slow_chain();
    let initial_a = pinned(&root_v1());
    let b_v1 = other_root();
    let initial_b = pinned(&b_v1);
    let server_b = Server::new();
    publish(&server_b, 1, real::TRUSTED_ROOT);

    let trust = scratch.trust();
    let a = {
        let (trust, server_a) = (trust.clone(), server_a.clone());
        thread::spawn(move || run(&server_a, &trust, &initial_a))
    };
    thread::sleep(Duration::from_millis(400));
    fs::remove_dir_all(trust.join("tuf")).expect("remove tuf/");
    let b = run(&server_b, &trust, &initial_b).expect_err("A still holds the lock");
    assert_eq!(b.step, Step::Lock);
    assert!(b.detail.contains("busy"), "{b}");
    let a = a
        .join()
        .expect("join")
        .expect_err("tuf/ was removed under A");
    assert_eq!(a.step, Step::Lock, "{a}");

    // Now the new pin bootstraps, and its chain is the only one stored.
    let outcome = run(&server_b, &trust, &initial_b).expect("the new pin");
    assert_eq!(outcome.report().root_version, 1);
    assert_eq!(fs::read(trust.join("tuf/root.json")).expect("root"), b_v1);
    assert_ne!(fs::read(trust.join("tuf/root.json")).expect("root"), a_v2);
    assert_eq!(
        fs::read_to_string(trust.join("tuf/pin")).expect("pin"),
        format!("{}\n", initial_b.sha256_hex())
    );
}

#[test]
fn replaced_trust_dir_during_refresh_written_no_more() {
    // The whole trust directory removed while a refresh runs: a refresh
    // under the new pin creates a new one with a new lock and finishes;
    // the old refresh then finds its directory replaced and writes nothing
    // into the new one.
    let scratch = Scratch::new("race-dir");
    let (server_a, _) = slow_chain();
    let initial_a = pinned(&root_v1());
    let b_v1 = other_root();
    let initial_b = pinned(&b_v1);
    let server_b = Server::new();
    publish(&server_b, 1, &trusted_root_v2());

    let trust = scratch.trust();
    let a = {
        let (trust, server_a) = (trust.clone(), server_a.clone());
        thread::spawn(move || run(&server_a, &trust, &initial_a))
    };
    thread::sleep(Duration::from_millis(400));
    fs::remove_dir_all(&trust).expect("remove the trust directory");
    run(&server_b, &trust, &initial_b).expect("the new directory");
    let before = (
        fs::read(trust.join("tuf/root.json")).expect("root"),
        fs::read(trust.join("tuf/timestamp.json")).expect("timestamp"),
        identity(&trust.join("trusted_root.json")),
    );
    let a = a
        .join()
        .expect("join")
        .expect_err("A's directory was replaced");
    assert_eq!(a.step, Step::Lock, "{a}");
    let after = (
        fs::read(trust.join("tuf/root.json")).expect("root"),
        fs::read(trust.join("tuf/timestamp.json")).expect("timestamp"),
        identity(&trust.join("trusted_root.json")),
    );
    assert_eq!(before, after);
    assert_eq!(before.0, b_v1);
    let next = run(&server_b, &trust, &initial_b).expect("the new pin goes on");
    assert_eq!(next.report().root_version, 1);
}
