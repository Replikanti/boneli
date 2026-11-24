//! Targets and the target (TUF 5.6 and 5.7, ADR-033 item 2): length and
//! SHA-256 against the snapshot's entry, threshold, type, version equal
//! to the snapshot's entry, expiry; then the one target looked up
//! byte-exact in the top-level `targets`, never in a delegation, with its
//! length cap and its exact length and SHA-256.

mod support;

use boneli_json::Value;
use boneli_tuf::{Error, MAX_TARGETS_BYTES, TrustedSet};
use support::repo::{
    MetaSpec, RootBuilder, START, SnapshotBuilder, TARGET, TARGET_NAME, TargetsBuilder,
    TimestampBuilder, files, hex, obj, s, target_entry, through_targets,
};

const MAX_TARGET: u64 = 1_048_576;

/// A set that has verified a snapshot naming targets as `meta`.
fn at_snapshot(meta: MetaSpec) -> TrustedSet {
    let mut set = TrustedSet::new(&RootBuilder::new(1).bytes(), START).expect("root");
    set.update_timestamp(&TimestampBuilder::new(1, MetaSpec::version(1)).bytes())
        .expect("timestamp");
    set.update_snapshot(&SnapshotBuilder::new(1, meta).bytes())
        .expect("snapshot");
    set
}

/// A set that has verified `targets` (version 1).
fn with_targets(targets: &TargetsBuilder) -> TrustedSet {
    let mut set = at_snapshot(MetaSpec::version(targets.version));
    set.update_targets(&targets.bytes()).expect("targets");
    set
}

/// Targets v1 listing only `entries`.
fn listing(entries: Vec<(&str, Value)>) -> TargetsBuilder {
    let mut b = TargetsBuilder::new(1);
    b.targets = entries
        .into_iter()
        .map(|(n, v)| (n.to_string(), v))
        .collect();
    b
}

#[test]
fn whole_fixture_repository_passes() {
    let files = files(3);
    let set = through_targets(&files);
    assert_eq!(set.timestamp_version(), Some(3));
    assert_eq!(set.snapshot_version(), Some(3));
    assert_eq!(set.targets_version(), Some(3));
    let target = set.target(TARGET_NAME).expect("target");
    assert_eq!(target.length(), TARGET.len() as u64);
    assert_eq!(
        hex(target.sha256()),
        hex(&boneli_https::Sha256::digest(TARGET))
    );
    assert_eq!(target.verify(TARGET), Ok(()));
}

// ---- Targets (5.6) ----

#[test]
fn targets_version_mismatch_refused() {
    for found in [1, 3, 9] {
        let mut set = at_snapshot(MetaSpec::version(2));
        assert_eq!(
            set.update_targets(&TargetsBuilder::new(found).bytes()),
            Err(Error::VersionMismatch {
                role: "targets",
                expected: 2,
                found
            })
        );
        assert_eq!(set.targets_version(), None);
    }
}

/// A SHA-256 other than the snapshot's is refused: a validly signed
/// targets document that is not the one the snapshot names.
#[test]
fn targets_hash_differs_from_snapshot_refused() {
    let listed = TargetsBuilder::new(1).bytes();
    let mut other = TargetsBuilder::new(1);
    other
        .targets
        .push(("extra".to_string(), target_entry(b"x")));
    let mut meta = MetaSpec::of(1, &listed);
    meta.length = None;
    let mut set = at_snapshot(meta.clone());
    assert_eq!(
        set.update_targets(&other.bytes()),
        Err(Error::HashMismatch { role: "targets" })
    );
    // Re-signed, same content, same length: still other bytes.
    let resigned = loop {
        let b = TargetsBuilder::new(1).bytes();
        if b.len() == listed.len() && b != listed {
            break b;
        }
    };
    let mut set = at_snapshot(MetaSpec::of(1, &listed));
    assert_eq!(
        set.update_targets(&resigned),
        Err(Error::HashMismatch { role: "targets" })
    );
    set.update_targets(&listed).expect("listed bytes");
}

#[test]
fn targets_length_mismatch_refused() {
    let bytes = TargetsBuilder::new(1).bytes();
    let mut meta = MetaSpec::version(1);
    meta.length = Some(bytes.len() as i64 + 1);
    assert_eq!(
        at_snapshot(meta).update_targets(&bytes),
        Err(Error::LengthMismatch {
            role: "targets",
            expected: bytes.len() as u64 + 1,
            found: bytes.len() as u64
        })
    );
}

#[test]
fn expired_targets_refused() {
    let mut b = TargetsBuilder::new(1);
    b.expires = "2026-11-24T00:00:00Z".to_string();
    assert_eq!(
        at_snapshot(MetaSpec::version(1)).update_targets(&b.bytes()),
        Err(Error::Expired { role: "targets" })
    );
    b.expires = "2026-11-24T00:00:01Z".to_string();
    at_snapshot(MetaSpec::version(1))
        .update_targets(&b.bytes())
        .expect("one second before expires");
}

/// Two of the three targets signatures needed, or the online key, are
/// refused.
#[test]
fn targets_below_threshold_refused() {
    let below = Error::BelowThreshold { role: "targets" };
    let b = TargetsBuilder::new(1);
    for signers in [&[1, 2][..], &[6], &[6, 7, 1], &[]] {
        assert_eq!(
            at_snapshot(MetaSpec::version(1)).update_targets(&b.signed_by(signers)),
            Err(below),
            "{signers:?}"
        );
    }
    at_snapshot(MetaSpec::version(1))
        .update_targets(&b.signed_by(&[3, 4, 5]))
        .expect("three of five");
}

#[test]
fn targets_type_confusion_refused() {
    let mut b = TargetsBuilder::new(1);
    b.type_ = "root".to_string();
    assert_eq!(
        at_snapshot(MetaSpec::version(1)).update_targets(&b.bytes()),
        Err(Error::Type {
            expected: "targets"
        })
    );
}

/// The targets cap is inclusive.
#[test]
fn metadata_cap_inclusive() {
    assert_eq!(MAX_TARGETS_BYTES, 1_048_576);
    let mut bytes = TargetsBuilder::new(1).bytes();
    bytes.resize(MAX_TARGETS_BYTES, b' ');
    at_snapshot(MetaSpec::version(1))
        .update_targets(&bytes)
        .expect("at the cap");
    bytes.push(b' ');
    assert_eq!(
        at_snapshot(MetaSpec::version(1)).update_targets(&bytes),
        Err(Error::TooLarge {
            cap: MAX_TARGETS_BYTES
        })
    );
}

/// `targets` must be an object; entries other than the one looked up are
/// not read.
#[test]
fn targets_shape_rules() {
    let mut b = TargetsBuilder::new(1);
    let mut signed = b.signed();
    support::repo::set(&mut signed, "targets", Value::Array(vec![]));
    let bytes = support::repo::signed_by(&signed, &support::repo::TARGETS_SIGNERS);
    assert_eq!(
        at_snapshot(MetaSpec::version(1)).update_targets(&bytes),
        Err(Error::Field("targets"))
    );
    b.targets.push(("other".to_string(), s("not read")));
    let set = with_targets(&b);
    assert_eq!(
        set.target(TARGET_NAME).map(|t| t.length()),
        Ok(TARGET.len() as u64)
    );
    assert_eq!(set.target("other"), Err(Error::Field("targets")));
}

/// Targets come only after a verified snapshot, once; the target only
/// after targets.
#[test]
fn targets_order_enforced() {
    let mut set = TrustedSet::new(&RootBuilder::new(1).bytes(), START).expect("root");
    assert_eq!(set.target(TARGET_NAME), Err(Error::OutOfOrder));
    set.update_timestamp(&TimestampBuilder::new(1, MetaSpec::version(1)).bytes())
        .expect("timestamp");
    set.load_local_snapshot(&SnapshotBuilder::new(1, MetaSpec::version(1)).bytes())
        .expect("stored snapshot");
    assert_eq!(
        set.update_targets(&TargetsBuilder::new(1).bytes()),
        Err(Error::OutOfOrder)
    );
    let mut set = at_snapshot(MetaSpec::version(1));
    assert_eq!(set.target(TARGET_NAME), Err(Error::OutOfOrder));
    set.update_targets(&TargetsBuilder::new(1).bytes())
        .expect("targets");
    assert_eq!(
        set.update_targets(&TargetsBuilder::new(1).bytes()),
        Err(Error::OutOfOrder)
    );
}

// ---- The target (5.7) ----

/// A name that top-level `targets` does not hold is not listed, also when
/// a delegation's paths cover it: delegations are never followed.
#[test]
fn target_only_in_delegation_refused() {
    let mut b = listing(vec![("other.json", target_entry(b"other"))]);
    b.delegations = Some(obj([
        ("keys", obj([])),
        (
            "roles",
            Value::Array(vec![obj([
                ("name", s("delegate")),
                ("keyids", Value::Array(vec![])),
                ("threshold", Value::from(1i64)),
                ("terminating", Value::Bool(true)),
                ("paths", Value::Array(vec![s(TARGET_NAME), s("*")])),
            ])]),
        ),
    ]));
    let set = with_targets(&b);
    assert_eq!(set.target(TARGET_NAME), Err(Error::NotListed));
    assert_eq!(set.target("absent"), Err(Error::NotListed));
    assert!(set.target("other.json").is_ok());
}

/// Look-alike names are other names: a Cyrillic `е`, a trailing space, a
/// zero-width space, another case, a path prefix.
#[test]
fn target_lookalike_name_not_matched() {
    for name in [
        "trusted_root.js\u{043e}n",
        "trust\u{0435}d_root.json",
        "trusted_root.json ",
        " trusted_root.json",
        "trusted_root.json\u{200b}",
        "Trusted_root.json",
        "./trusted_root.json",
        "a/trusted_root.json",
    ] {
        let set = with_targets(&listing(vec![(name, target_entry(TARGET))]));
        assert_eq!(set.target(TARGET_NAME), Err(Error::NotListed), "{name:?}");
        assert!(set.target(name).is_ok(), "{name:?}");
    }
}

/// The hash map must hold `sha256` (64 lower-case hex); other algorithms
/// are not read. A target without a hash map is refused too.
#[test]
fn target_without_sha256_refused() {
    let entry = |hashes: Option<Value>| {
        let mut o = boneli_json::Object::new();
        o.insert("length", TARGET.len() as i64);
        if let Some(h) = hashes {
            o.insert("hashes", h);
        }
        Value::Object(o)
    };
    let sha256 = hex(&boneli_https::Sha256::digest(TARGET));
    for (hashes, want) in [
        (
            Some(obj([("sha512", s(&"ab".repeat(64)))])),
            Error::NoSha256,
        ),
        (Some(obj([])), Error::NoSha256),
        (None, Error::Field("hashes")),
        (Some(s(&sha256)), Error::Field("hashes")),
        (
            Some(obj([("sha256", s(&sha256.to_uppercase()))])),
            Error::Field("hashes"),
        ),
        (
            Some(obj([("sha256", s(&sha256[..62]))])),
            Error::Field("hashes"),
        ),
        (Some(obj([("SHA256", s(&sha256))])), Error::NoSha256),
    ] {
        let set = with_targets(&listing(vec![(TARGET_NAME, entry(hashes.clone()))]));
        assert_eq!(set.target(TARGET_NAME), Err(want), "{hashes:?}");
    }
    let both = obj([("sha512", s("not read")), ("sha256", s(&sha256))]);
    let set = with_targets(&listing(vec![(TARGET_NAME, entry(Some(both)))]));
    assert_eq!(
        set.target(TARGET_NAME).map(|t| t.verify(TARGET)),
        Ok(Ok(()))
    );
}

/// A listed length up to `MAX_TRUSTED_ROOT_BYTES` is accepted, one more
/// is refused at the lookup, so the file is never requested. Lengths that
/// are not non-negative integers are refused.
#[test]
fn target_length_cap_before_request() {
    assert_eq!(boneli_sigstore::MAX_TRUSTED_ROOT_BYTES as u64, MAX_TARGET);
    let entry = |length: Value| {
        obj([
            ("length", length),
            ("hashes", obj([("sha256", s(&"ab".repeat(32)))])),
        ])
    };
    let set = with_targets(&listing(vec![(
        TARGET_NAME,
        entry(Value::from(MAX_TARGET)),
    )]));
    assert_eq!(set.target(TARGET_NAME).map(|t| t.length()), Ok(MAX_TARGET));
    let set = with_targets(&listing(vec![(
        TARGET_NAME,
        entry(Value::from(MAX_TARGET + 1)),
    )]));
    assert_eq!(
        set.target(TARGET_NAME),
        Err(Error::TargetTooLarge {
            cap: MAX_TARGET as usize
        })
    );
    for bad in [Value::from(-1i64), s("6787"), Value::Null] {
        let set = with_targets(&listing(vec![(TARGET_NAME, entry(bad.clone()))]));
        assert_eq!(
            set.target(TARGET_NAME),
            Err(Error::Field("length")),
            "{bad:?}"
        );
    }
    let mut missing = entry(Value::Null);
    support::repo::remove(&mut missing, "length");
    let set = with_targets(&listing(vec![(TARGET_NAME, missing)]));
    assert_eq!(set.target(TARGET_NAME), Err(Error::Field("length")));
}

/// A body longer or shorter than the listed length is refused.
#[test]
fn target_length_mismatch_refused() {
    let set = with_targets(&TargetsBuilder::new(1));
    let target = set.target(TARGET_NAME).expect("target");
    let len = TARGET.len() as u64;
    let mut longer = TARGET.to_vec();
    longer.push(b'\n');
    assert_eq!(
        target.verify(&longer),
        Err(Error::LengthMismatch {
            role: "target",
            expected: len,
            found: len + 1
        })
    );
    assert_eq!(
        target.verify(&TARGET[..TARGET.len() - 1]),
        Err(Error::LengthMismatch {
            role: "target",
            expected: len,
            found: len - 1
        })
    );
    assert_eq!(
        target.verify(b""),
        Err(Error::LengthMismatch {
            role: "target",
            expected: len,
            found: 0
        })
    );
}

/// The listed length with another content is refused by the hash.
#[test]
fn target_hash_mismatch_refused() {
    let set = with_targets(&TargetsBuilder::new(1));
    let target = set.target(TARGET_NAME).expect("target");
    let mut other = TARGET.to_vec();
    other[0] ^= 1;
    assert_eq!(
        target.verify(&other),
        Err(Error::HashMismatch { role: "target" })
    );
    assert_eq!(target.verify(TARGET), Ok(()));
}
