//! The snapshot (TUF 5.5, ADR-033 item 2): length and SHA-256 against the
//! timestamp's entry, threshold, type, version equal to the timestamp's
//! entry, rollback of every role the stored snapshot lists, expiry, the
//! stored copy and the order of the update.

mod support;

use boneli_json::Value;
use boneli_tuf::{Error, MAX_SNAPSHOT_BYTES, TrustedSet};
use support::repo::{
    MetaSpec, ONLINE, RootBuilder, START, SnapshotBuilder, TimestampBuilder, at, remove, s, set,
    signed_by,
};

fn limits() -> boneli_json::Limits {
    boneli_json::Limits::new(MAX_SNAPSHOT_BYTES, 16, 65_536).expect("limits")
}

/// A set that has verified a timestamp naming the snapshot as `meta`.
fn at_timestamp(meta: MetaSpec) -> TrustedSet {
    let mut set = TrustedSet::new(&RootBuilder::new(1).bytes(), START).expect("root");
    set.update_timestamp(&TimestampBuilder::new(1, meta).bytes())
        .expect("timestamp");
    set
}

/// Snapshot `v` naming targets `targets` by version only, plus `extra`.
fn snapshot(v: i64, targets: i64, extra: &[(&str, i64)]) -> Vec<u8> {
    let mut b = SnapshotBuilder::new(v, MetaSpec::version(targets));
    for (name, version) in extra {
        b.meta.push((name.to_string(), MetaSpec::version(*version)));
    }
    b.bytes()
}

#[test]
fn snapshot_passes() {
    // By version only.
    let mut set = at_timestamp(MetaSpec::version(4));
    set.update_snapshot(&snapshot(4, 2, &[])).expect("snapshot");
    assert_eq!(set.snapshot_version(), Some(4));
    assert_eq!(set.targets_meta().map(|m| m.version()), Some(2));
    // With length and hash.
    let bytes = snapshot(4, 2, &[]);
    let mut set = at_timestamp(MetaSpec::of(4, &bytes));
    set.update_snapshot(&bytes).expect("snapshot");
}

/// A version other than the timestamp's entry is refused, lower or
/// higher.
#[test]
fn snapshot_version_mismatch_refused() {
    for found in [1, 2, 4, 1000] {
        let mut set = at_timestamp(MetaSpec::version(3));
        assert_eq!(
            set.update_snapshot(&snapshot(found, 1, &[])),
            Err(Error::VersionMismatch {
                role: "snapshot",
                expected: 3,
                found
            })
        );
        assert_eq!(set.snapshot_version(), None);
    }
}

/// A SHA-256 other than the timestamp's is refused before the bytes are
/// parsed: the listed bytes with one byte changed (same length), and,
/// where only a hash is listed, with one byte more.
#[test]
fn snapshot_hash_mismatch_refused() {
    let bytes = snapshot(1, 1, &[]);
    let mut other = bytes.clone();
    *other.last_mut().expect("bytes") = b' ';
    let mut set = at_timestamp(MetaSpec::of(1, &bytes));
    assert_eq!(
        set.update_snapshot(&other),
        Err(Error::HashMismatch { role: "snapshot" })
    );
    let mut meta = MetaSpec::of(1, &bytes);
    meta.length = None;
    let mut set = at_timestamp(meta);
    let mut longer = bytes.clone();
    longer.push(b'\n');
    assert_eq!(
        set.update_snapshot(&longer),
        Err(Error::HashMismatch { role: "snapshot" })
    );
    set.update_snapshot(&bytes).expect("listed bytes");
}

/// A length other than the timestamp's is refused, one byte more or
/// less, even when no hash is listed.
#[test]
fn snapshot_length_mismatch_refused() {
    let bytes = snapshot(1, 1, &[]);
    let len = bytes.len() as u64;
    for listed in [len - 1, len + 1] {
        let mut meta = MetaSpec::version(1);
        meta.length = Some(listed as i64);
        let mut set = at_timestamp(meta);
        assert_eq!(
            set.update_snapshot(&bytes),
            Err(Error::LengthMismatch {
                role: "snapshot",
                expected: listed,
                found: len
            })
        );
    }
    let mut meta = MetaSpec::version(1);
    meta.length = Some(len as i64);
    at_timestamp(meta)
        .update_snapshot(&bytes)
        .expect("exact length");
}

/// An entry of the stored snapshot that the new one no longer lists is
/// refused.
#[test]
fn snapshot_drops_role_refused() {
    let mut set = at_timestamp(MetaSpec::version(2));
    set.load_local_snapshot(&snapshot(1, 1, &[("role-a.json", 3)]))
        .expect("stored");
    assert_eq!(
        set.update_snapshot(&snapshot(2, 1, &[("role-b.json", 3)])),
        Err(Error::EntryDropped)
    );
    // Every stored entry kept, plus a new one, passes.
    let mut set = at_timestamp(MetaSpec::version(2));
    set.load_local_snapshot(&snapshot(1, 1, &[("role-a.json", 3)]))
        .expect("stored");
    set.update_snapshot(&snapshot(2, 1, &[("role-a.json", 3), ("role-b.json", 1)]))
        .expect("kept, plus a new role");
}

/// An entry of the stored snapshot with a lower version in the new one is
/// refused; equal and higher pass.
#[test]
fn snapshot_lowers_role_refused() {
    let lowered = |trusted, found| Error::EntryRollback { trusted, found };
    let stored = snapshot(1, 5, &[("role-a.json", 3)]);
    let mut set = at_timestamp(MetaSpec::version(2));
    set.load_local_snapshot(&stored).expect("stored");
    assert_eq!(
        set.update_snapshot(&snapshot(2, 5, &[("role-a.json", 2)])),
        Err(lowered(3, 2))
    );
    assert_eq!(
        set.update_snapshot(&snapshot(2, 4, &[("role-a.json", 3)])),
        Err(lowered(5, 4))
    );
    set.update_snapshot(&snapshot(2, 5, &[("role-a.json", 4)]))
        .expect("equal and higher");
}

#[test]
fn expired_snapshot_refused() {
    let mut b = SnapshotBuilder::new(1, MetaSpec::version(1));
    b.expires = "2026-11-24T00:00:00Z".to_string();
    let mut set = at_timestamp(MetaSpec::version(1));
    assert_eq!(
        set.update_snapshot(&b.bytes()),
        Err(Error::Expired { role: "snapshot" })
    );
    b.expires = "2026-11-24T00:00:01Z".to_string();
    set.update_snapshot(&b.bytes())
        .expect("one second before expires");
}

#[test]
fn snapshot_below_threshold_refused() {
    let below = Error::BelowThreshold { role: "snapshot" };
    let b = SnapshotBuilder::new(1, MetaSpec::version(1));
    for signers in [&[][..], &[7], &[1, 2, 3]] {
        let mut set = at_timestamp(MetaSpec::version(1));
        assert_eq!(set.update_snapshot(&b.signed_by(signers)), Err(below));
        assert_eq!(set.load_local_snapshot(&b.signed_by(signers)), Err(below));
    }
}

#[test]
fn snapshot_type_confusion_refused() {
    let mut b = SnapshotBuilder::new(1, MetaSpec::version(1));
    b.type_ = "timestamp".to_string();
    let mut set = at_timestamp(MetaSpec::version(1));
    assert_eq!(
        set.update_snapshot(&b.bytes()),
        Err(Error::Type {
            expected: "snapshot"
        })
    );
}

/// The snapshot cap is inclusive.
#[test]
fn metadata_cap_inclusive() {
    assert_eq!(MAX_SNAPSHOT_BYTES, 1_048_576);
    let mut bytes = snapshot(1, 1, &[]);
    bytes.resize(MAX_SNAPSHOT_BYTES, b' ');
    at_timestamp(MetaSpec::version(1))
        .update_snapshot(&bytes)
        .expect("at the cap");
    bytes.push(b' ');
    assert_eq!(
        at_timestamp(MetaSpec::version(1)).update_snapshot(&bytes),
        Err(Error::TooLarge {
            cap: MAX_SNAPSHOT_BYTES
        })
    );
}

/// `meta` must hold `targets.json`, and every entry an object with a
/// version of at least 1. Lengths and hashes of other entries are not
/// read; those of `targets.json` follow the timestamp's rules.
#[test]
fn snapshot_meta_rules() {
    let base = snapshot(1, 1, &[("role-a.json", 1)]);
    let base: Value = {
        let doc = boneli_json::parse(&base, &limits()).expect("parse");
        doc.get("signed").expect("signed").clone()
    };
    let run = |f: &dyn Fn(&mut Value)| {
        let mut signed = base.clone();
        f(&mut signed);
        at_timestamp(MetaSpec::version(1)).update_snapshot(&signed_by(&signed, &[ONLINE]))
    };
    let field = Error::Field;
    assert_eq!(run(&|v| remove(v, "meta")), Err(field("meta")));
    assert_eq!(
        run(&|v| remove(at(v, &["meta"]), "targets.json")),
        Err(field("meta"))
    );
    assert_eq!(
        run(&|v| set(at(v, &["meta"]), "role-a.json", s("x"))),
        Err(field("meta"))
    );
    assert_eq!(
        run(&|v| set(at(v, &["meta", "role-a.json"]), "version", 0i64.into())),
        Err(field("version"))
    );
    assert_eq!(
        run(&|v| remove(at(v, &["meta", "role-a.json"]), "version")),
        Err(field("version"))
    );
    assert_eq!(
        run(&|v| set(at(v, &["meta", "targets.json"]), "length", (-1i64).into())),
        Err(field("length"))
    );
    assert_eq!(
        run(&|v| set(at(v, &["meta", "targets.json"]), "hashes", s("x"))),
        Err(field("hashes"))
    );
    // Not read for other entries.
    run(&|v| set(at(v, &["meta", "role-a.json"]), "hashes", s("x"))).expect("not read");
    run(&|v| set(at(v, &["meta", "role-a.json"]), "length", s("x"))).expect("not read");
}

/// The stored copy: signature and type only, no expiry and no version
/// check; it loads only before any snapshot, and the snapshot is updated
/// only after a verified timestamp and before targets.
#[test]
fn snapshot_order_and_local_copy() {
    let mut old = SnapshotBuilder::new(1, MetaSpec::version(1));
    old.expires = "2020-01-01T00:00:00Z".to_string();
    let mut set = at_timestamp(MetaSpec::version(9));
    set.load_local_snapshot(&old.bytes()).expect("expired copy");
    assert_eq!(set.snapshot_version(), Some(1));
    assert!(set.targets_meta().is_none(), "a stored copy names nothing");
    assert_eq!(
        set.load_local_snapshot(&old.bytes()),
        Err(Error::OutOfOrder)
    );
    set.update_snapshot(&snapshot(9, 1, &[])).expect("snapshot");
    assert_eq!(
        set.load_local_snapshot(&snapshot(9, 1, &[])),
        Err(Error::OutOfOrder)
    );
    assert_eq!(
        set.update_snapshot(&snapshot(9, 1, &[])),
        Err(Error::OutOfOrder)
    );
    // No verified timestamp: a stored one is not enough.
    let mut set = TrustedSet::new(&RootBuilder::new(1).bytes(), START).expect("root");
    assert_eq!(
        set.update_snapshot(&snapshot(1, 1, &[])),
        Err(Error::OutOfOrder)
    );
    set.load_local_timestamp(&TimestampBuilder::new(1, MetaSpec::version(1)).bytes())
        .expect("stored timestamp");
    assert_eq!(
        set.update_snapshot(&snapshot(1, 1, &[])),
        Err(Error::OutOfOrder)
    );
}

/// After a rotation of the online keys the stored snapshot is not used
/// either (5.3.11).
#[test]
fn rotated_snapshot_key_drops_stored_snapshot() {
    let mut set = TrustedSet::new(&RootBuilder::new(1).bytes(), START).expect("root");
    let mut v2 = RootBuilder::new(2);
    v2.timestamp.keys = vec![7];
    set.update_root(&v2.bytes()).expect("v2");
    assert_eq!(
        set.load_local_snapshot(&snapshot(50, 50, &[])),
        Err(Error::OnlineKeysChanged)
    );
    set.update_timestamp(&TimestampBuilder::new(1, MetaSpec::version(1)).signed_by(&[7]))
        .expect("timestamp");
    set.update_snapshot(&snapshot(1, 1, &[])).expect("v1");
}
