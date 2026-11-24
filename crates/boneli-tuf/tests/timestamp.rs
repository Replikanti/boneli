//! The timestamp (TUF 5.4, ADR-033 item 2): threshold, type, rollback of
//! its own version and of the snapshot version it names, freeze, the
//! stored copy, fast-forward recovery and the order of the update, on
//! fixture timestamps signed at test time and on Sigstore's real v842.

mod support;

use boneli_json::Value;
use boneli_tuf::{Error, MAX_TIMESTAMP_BYTES, TrustedSet};
use support::real;
use support::repo::{
    FAR_SECS, MetaSpec, ONLINE, RootBuilder, START, SnapshotBuilder, TimestampBuilder, at, obj,
    remove, s, set, signed_by,
};

const EXPIRED: Error = Error::Expired { role: "timestamp" };

/// A change to a `signed` value.
type Mutation = Box<dyn Fn(&mut Value)>;

fn trusted() -> TrustedSet {
    TrustedSet::new(&RootBuilder::new(1).bytes(), START).expect("root")
}

/// Timestamp `v` naming snapshot `snapshot` by version only.
fn ts(v: i64, snapshot: i64) -> Vec<u8> {
    TimestampBuilder::new(v, MetaSpec::version(snapshot)).bytes()
}

fn rollback(role: &'static str, trusted: i64, found: i64) -> Error {
    Error::Rollback {
        role,
        trusted,
        found,
    }
}

#[test]
fn timestamp_passes() {
    let mut set = trusted();
    assert_eq!(set.timestamp_version(), None);
    assert!(set.snapshot_meta().is_none());
    let snapshot = b"the snapshot bytes";
    let bytes = TimestampBuilder::new(7, MetaSpec::of(3, snapshot)).bytes();
    set.update_timestamp(&bytes).expect("timestamp");
    assert_eq!(set.timestamp_version(), Some(7));
    let meta = set.snapshot_meta().expect("snapshot meta");
    assert_eq!(meta.version(), 3);
    assert_eq!(meta.length(), Some(snapshot.len() as u64));
    assert!(meta.sha256().is_some());
}

// ---- Freeze (5.4.4) ----

/// Expired when start >= expires.
#[test]
fn expired_timestamp_refused() {
    let mut set = trusted();
    let mut b = TimestampBuilder::new(1, MetaSpec::version(1));
    b.expires = "2020-01-01T00:00:00Z".to_string();
    assert_eq!(set.update_timestamp(&b.bytes()), Err(EXPIRED));
    assert_eq!(set.timestamp_version(), None);
    // At expires itself it has expired, one second before it has not.
    let bytes = ts(1, 1);
    let mut at = TrustedSet::new(&RootBuilder::new(1).bytes(), FAR_SECS - 1).expect("root");
    assert_eq!(at.update_timestamp(&bytes), Ok(()));
    let mut root = RootBuilder::new(1);
    root.expires = "2031-01-01T00:00:00Z".to_string();
    let mut at = TrustedSet::new(&root.bytes(), FAR_SECS).expect("root");
    assert_eq!(at.update_timestamp(&bytes), Err(EXPIRED));
}

/// On the real timestamp (expires 1,796,001,652): one second before
/// passes, the second itself is expired.
#[test]
fn expiry_boundary_inclusive() {
    let mut set = TrustedSet::new(real::root(16), real::TIMESTAMP_EXPIRES - 1).expect("v16");
    assert_eq!(set.update_timestamp(real::TIMESTAMP), Ok(()));
    assert_eq!(set.timestamp_version(), Some(842));
    let mut set = TrustedSet::new(real::root(16), real::TIMESTAMP_EXPIRES).expect("v16");
    assert_eq!(set.update_timestamp(real::TIMESTAMP), Err(EXPIRED));
    assert_eq!(set.timestamp_version(), None);
}

/// A frozen repository serves the same timestamp past its expiry: the
/// stored copy loads (its expiry is never checked), the served one is
/// refused at the timestamp step.
#[test]
fn frozen_timestamp_refused() {
    let later = real::TIMESTAMP_EXPIRES + 86_400;
    let mut set = TrustedSet::new(real::root(16), later).expect("v16");
    set.load_local_timestamp(real::TIMESTAMP)
        .expect("stored copy");
    assert_eq!(set.update_timestamp(real::TIMESTAMP), Err(EXPIRED));
    // On a fixture: equal version, same bytes, past expiry.
    let mut b = TimestampBuilder::new(5, MetaSpec::version(5));
    b.expires = "2026-11-25T00:00:00Z".to_string();
    let bytes = b.bytes();
    let mut set = trusted();
    set.update_timestamp(&bytes).expect("before the freeze");
    let mut frozen =
        TrustedSet::new(&RootBuilder::new(1).bytes(), START + 2 * 86_400).expect("root");
    frozen.load_local_timestamp(&bytes).expect("stored copy");
    assert_eq!(frozen.update_timestamp(&bytes), Err(EXPIRED));
}

/// A repository that hides a root rotation (serves 404 for N+1) is caught
/// once the stored root expires: no timestamp is trusted under an expired
/// root (5.3.10).
#[test]
fn hidden_rotation_caught_by_root_expiry() {
    let mut root = RootBuilder::new(1);
    root.expires = "2026-12-01T00:00:00Z".to_string();
    let root = root.bytes();
    let bytes = ts(1, 1);
    let mut before = TrustedSet::new(&root, START).expect("root");
    assert_eq!(before.update_timestamp(&bytes), Ok(()));
    let mut after = TrustedSet::new(&root, 1_796_083_200).expect("root");
    assert_eq!(
        after.check_root_expiry(),
        Err(Error::Expired { role: "root" })
    );
    assert_eq!(
        after.update_timestamp(&bytes),
        Err(Error::Expired { role: "root" })
    );
    assert_eq!(after.timestamp_version(), None);
}

// ---- Rollback (5.4.3) ----

/// v841 after a stored v842 is refused, from the stored copy and from a
/// timestamp verified earlier in the same update; v843 passes.
#[test]
fn timestamp_rollback_refused() {
    let mut set = trusted();
    set.load_local_timestamp(&ts(842, 10)).expect("stored");
    assert_eq!(
        set.update_timestamp(&ts(841, 10)),
        Err(rollback("timestamp", 842, 841))
    );
    assert_eq!(set.timestamp_version(), Some(842));
    set.update_timestamp(&ts(843, 10)).expect("newer");
    assert_eq!(
        set.update_timestamp(&ts(842, 10)),
        Err(rollback("timestamp", 843, 842))
    );
    assert_eq!(set.timestamp_version(), Some(843));
}

/// An equal version passes, and only when every check passes again:
/// threshold, expiry and the snapshot version.
#[test]
fn equal_timestamp_version_rechecked() {
    let mut set = trusted();
    set.load_local_timestamp(&ts(842, 10)).expect("stored");
    set.update_timestamp(&ts(842, 10)).expect("equal version");
    let mut set = trusted();
    set.load_local_timestamp(&ts(842, 10)).expect("stored");
    let mut expired = TimestampBuilder::new(842, MetaSpec::version(10));
    expired.expires = "2020-01-01T00:00:00Z".to_string();
    assert_eq!(set.update_timestamp(&expired.bytes()), Err(EXPIRED));
    let unsigned = TimestampBuilder::new(842, MetaSpec::version(10)).signed_by(&[7]);
    assert_eq!(
        set.update_timestamp(&unsigned),
        Err(Error::BelowThreshold { role: "timestamp" })
    );
    assert_eq!(
        set.update_timestamp(&ts(842, 9)),
        Err(rollback("snapshot", 10, 9))
    );
    set.update_timestamp(&ts(842, 11))
        .expect("equal, newer snapshot");
}

/// A timestamp whose snapshot version is below the stored timestamp's is
/// refused; equal and higher pass.
#[test]
fn snapshot_version_rollback_refused() {
    let mut set = trusted();
    set.load_local_timestamp(&ts(10, 5)).expect("stored");
    assert_eq!(
        set.update_timestamp(&ts(11, 4)),
        Err(rollback("snapshot", 5, 4))
    );
    set.update_timestamp(&ts(11, 5))
        .expect("equal snapshot version");
    set.update_timestamp(&ts(12, 6)).expect("higher");
    assert_eq!(
        set.update_timestamp(&ts(13, 5)),
        Err(rollback("snapshot", 6, 5))
    );
}

// ---- Fast-forward recovery (5.3.11) ----

/// A new root that rotates the online key lets timestamp v1 pass after a
/// stored v1000: the stored copy is not used. Also when the old key still
/// signs for the timestamp role and only the snapshot key changed.
#[test]
fn rotated_timestamp_key_resets_rollback_state() {
    let stored = ts(1000, 1000);
    // The timestamp key moves from 6 to 7.
    let mut set = trusted();
    let mut v2 = RootBuilder::new(2);
    v2.timestamp.keys = vec![7];
    v2.snapshot.keys = vec![7];
    set.update_root(&v2.bytes()).expect("v2");
    assert!(set.online_keys_changed());
    assert_eq!(
        set.load_local_timestamp(&stored),
        Err(Error::OnlineKeysChanged)
    );
    set.update_timestamp(&TimestampBuilder::new(1, MetaSpec::version(1)).signed_by(&[7]))
        .expect("v1 under the new key");
    // Only the snapshot key moves: the stored timestamp still verifies
    // under the timestamp role, and is dropped all the same.
    let mut set = trusted();
    let mut v2 = RootBuilder::new(2);
    v2.snapshot.keys = vec![7];
    set.update_root(&v2.bytes()).expect("v2");
    assert_eq!(
        set.load_local_timestamp(&stored),
        Err(Error::OnlineKeysChanged)
    );
    set.update_timestamp(&ts(1, 1)).expect("v1");
    assert_eq!(set.timestamp_version(), Some(1));
}

/// The same new root without a rotation keeps the stored copy, so v1 is
/// refused.
#[test]
fn unrotated_key_keeps_rollback_state() {
    let mut set = trusted();
    set.update_root(&RootBuilder::new(2).bytes()).expect("v2");
    assert!(!set.online_keys_changed());
    set.load_local_timestamp(&ts(1000, 1000)).expect("stored");
    assert_eq!(
        set.update_timestamp(&ts(1, 1)),
        Err(rollback("timestamp", 1000, 1))
    );
}

// ---- Signatures, type, shape ----

#[test]
fn timestamp_below_threshold_refused() {
    let below = Error::BelowThreshold { role: "timestamp" };
    let b = TimestampBuilder::new(1, MetaSpec::version(1));
    for signers in [&[][..], &[7], &[1, 2, 3, 4, 5]] {
        let mut set = trusted();
        assert_eq!(set.update_timestamp(&b.signed_by(signers)), Err(below));
        assert_eq!(set.load_local_timestamp(&b.signed_by(signers)), Err(below));
        assert_eq!(set.timestamp_version(), None);
    }
    // A threshold of 2 online keys needs both.
    let mut root = RootBuilder::new(1);
    root.timestamp.keys = vec![6, 7];
    root.timestamp.threshold = 2;
    let mut set = TrustedSet::new(&root.bytes(), START).expect("root");
    assert_eq!(set.update_timestamp(&b.signed_by(&[ONLINE])), Err(below));
    set.update_timestamp(&b.signed_by(&[ONLINE, 7]))
        .expect("two of two");
}

/// A snapshot or root offered as the timestamp is refused by `_type`,
/// even when the online key signed it.
#[test]
fn timestamp_type_confusion_refused() {
    let mut set = trusted();
    let snapshot = SnapshotBuilder::new(1, MetaSpec::version(1)).bytes();
    assert_eq!(
        set.update_timestamp(&snapshot),
        Err(Error::Type {
            expected: "timestamp"
        })
    );
    let mut b = TimestampBuilder::new(1, MetaSpec::version(1));
    b.type_ = "Timestamp".to_string();
    assert_eq!(
        set.load_local_timestamp(&b.bytes()),
        Err(Error::Type {
            expected: "timestamp"
        })
    );
}

/// The timestamp cap is inclusive: a valid timestamp padded with
/// whitespace to exactly `MAX_TIMESTAMP_BYTES` passes, one byte more is
/// refused before parsing.
#[test]
fn metadata_cap_inclusive() {
    assert_eq!(MAX_TIMESTAMP_BYTES, 16_384);
    let mut bytes = ts(1, 1);
    bytes.resize(MAX_TIMESTAMP_BYTES, b' ');
    trusted().update_timestamp(&bytes).expect("at the cap");
    bytes.push(b' ');
    assert_eq!(
        trusted().update_timestamp(&bytes),
        Err(Error::TooLarge {
            cap: MAX_TIMESTAMP_BYTES
        })
    );
}

/// `meta` must hold `snapshot.json` with a version of at least 1; a
/// length is a non-negative integer; a hash map must hold `sha256` as 64
/// lower-case hex characters, other algorithms are not read.
#[test]
fn timestamp_meta_rules() {
    let base = TimestampBuilder::new(1, MetaSpec::version(1)).signed();
    let mutate = |f: &dyn Fn(&mut Value)| {
        let mut signed = base.clone();
        f(&mut signed);
        trusted().update_timestamp(&signed_by(&signed, &[ONLINE]))
    };
    let entry = ["meta", "snapshot.json"];
    let hex64 = "ab".repeat(32);
    let cases: Vec<(Error, Mutation)> = vec![
        (Error::Field("meta"), Box::new(|v| remove(v, "meta"))),
        (Error::Field("meta"), Box::new(|v| set(v, "meta", s("x")))),
        (
            Error::Field("meta"),
            Box::new(|v| remove(at(v, &["meta"]), "snapshot.json")),
        ),
        (
            Error::Field("meta"),
            Box::new(|v| set(at(v, &["meta"]), "snapshot.json", s("x"))),
        ),
        (
            Error::Field("version"),
            Box::new(move |v| set(at(v, &entry), "version", 0i64.into())),
        ),
        (
            Error::Field("version"),
            Box::new(move |v| remove(at(v, &entry), "version")),
        ),
        (
            Error::Field("length"),
            Box::new(move |v| set(at(v, &entry), "length", (-1i64).into())),
        ),
        (
            Error::Field("length"),
            Box::new(move |v| set(at(v, &entry), "length", s("1"))),
        ),
        (
            Error::Field("hashes"),
            Box::new(move |v| set(at(v, &entry), "hashes", s("x"))),
        ),
        (
            Error::NoSha256,
            Box::new(move |v| set(at(v, &entry), "hashes", obj([]))),
        ),
        (
            Error::NoSha256,
            Box::new(move |v| {
                set(
                    at(v, &entry),
                    "hashes",
                    obj([("sha512", s(&"ab".repeat(64)))]),
                )
            }),
        ),
        (
            Error::Field("hashes"),
            Box::new(move |v| {
                set(
                    at(v, &entry),
                    "hashes",
                    obj([("sha256", s(&"AB".repeat(32)))]),
                )
            }),
        ),
        (
            Error::Field("hashes"),
            Box::new(move |v| {
                set(
                    at(v, &entry),
                    "hashes",
                    obj([("sha256", s(&"ab".repeat(31)))]),
                )
            }),
        ),
        (
            Error::Field("hashes"),
            Box::new(move |v| {
                set(
                    at(v, &entry),
                    "hashes",
                    obj([("sha256", Value::from(1i64))]),
                )
            }),
        ),
    ];
    for (i, (want, f)) in cases.iter().enumerate() {
        assert_eq!(mutate(f.as_ref()), Err(*want), "{i}");
    }
    // A sha256 next to other algorithms passes; length 0 is a length.
    let ok = |f: &dyn Fn(&mut Value)| mutate(f).expect("valid");
    let hashes = obj([("sha256", s(&hex64)), ("sha512", s("not read"))]);
    ok(&move |v| set(at(v, &entry), "hashes", hashes.clone()));
    ok(&move |v| set(at(v, &entry), "length", 0i64.into()));
    // Other entries of `meta` are not read.
    ok(&|v| set(at(v, &["meta"]), "other.json", s("not read")));
}

// ---- Order of the update ----

/// The stored copy loads only first; no root after a timestamp; the
/// timestamp only before any snapshot.
#[test]
fn timestamp_order_enforced() {
    let mut set = trusted();
    set.load_local_timestamp(&ts(1, 1)).expect("stored");
    assert_eq!(set.load_local_timestamp(&ts(1, 1)), Err(Error::OutOfOrder));
    assert_eq!(
        set.update_root(&RootBuilder::new(2).bytes()),
        Err(Error::OutOfOrder)
    );
    set.update_timestamp(&ts(1, 1)).expect("timestamp");
    assert_eq!(set.load_local_timestamp(&ts(1, 1)), Err(Error::OutOfOrder));
    let mut set = trusted();
    set.update_timestamp(&ts(1, 1)).expect("timestamp");
    assert_eq!(
        set.update_root(&RootBuilder::new(2).bytes()),
        Err(Error::OutOfOrder)
    );
    set.load_local_snapshot(&SnapshotBuilder::new(1, MetaSpec::version(1)).bytes())
        .expect("stored snapshot");
    assert_eq!(set.update_timestamp(&ts(2, 1)), Err(Error::OutOfOrder));
    assert_eq!(set.timestamp_version(), Some(1));
}

/// The stored copy's expiry is never checked; it serves only for
/// rollback checks and names no snapshot to fetch.
#[test]
fn local_timestamp_ignores_expiry() {
    let mut b = TimestampBuilder::new(9, MetaSpec::version(4));
    b.expires = "2020-01-01T00:00:00Z".to_string();
    let mut set = trusted();
    set.load_local_timestamp(&b.bytes()).expect("expired copy");
    assert_eq!(set.timestamp_version(), Some(9));
    assert!(set.snapshot_meta().is_none(), "a stored copy names nothing");
}
