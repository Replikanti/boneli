//! Known answers on Sigstore's real online metadata (ADR-033): timestamp
//! v842, `166.snapshot.json` and `14.targets.json`, captured on
//! 2026-11-24 with the roots, verify under root v16, and the
//! `trusted_root.json` target is the file `boneli-sigstore` verifies
//! against. The root chain's known answers are in `tests/root.rs`.

mod support;

use boneli_tuf::{Error, TrustedSet};
use support::real;
use support::repo::hex;

/// The SHA-256 of the `trusted_root.json` target and of the
/// `boneli-sigstore` fixture.
const TRUSTED_ROOT_SHA256: &str =
    "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66";

fn v16() -> TrustedSet {
    TrustedSet::new(real::root(16), real::START).expect("v16")
}

fn through_targets() -> TrustedSet {
    let mut set = v16();
    set.update_timestamp(real::TIMESTAMP).expect("timestamp");
    set.update_snapshot(real::SNAPSHOT).expect("snapshot");
    set.update_targets(real::TARGETS).expect("targets");
    set
}

#[test]
fn sigstore_metadata_verifies_under_v16() {
    let set = through_targets();
    assert_eq!(set.timestamp_version(), Some(842));
    assert_eq!(set.snapshot_version(), Some(166));
    assert_eq!(set.targets_version(), Some(14));
    // Sigstore names snapshot and targets by version only.
    let snapshot = set.snapshot_meta().expect("snapshot meta");
    assert_eq!((snapshot.version(), snapshot.length()), (166, None));
    assert!(snapshot.sha256().is_none());
    let targets = set.targets_meta().expect("targets meta");
    assert_eq!((targets.version(), targets.length()), (14, None));
    // The whole chain from the earliest pin the rules accept.
    let mut set = TrustedSet::new(real::root(5), real::START).expect("v5");
    for version in 6..=16 {
        set.update_root(real::root(version)).expect("chain");
    }
    set.check_root_expiry().expect("v16 current");
    set.update_timestamp(real::TIMESTAMP).expect("timestamp");
    set.update_snapshot(real::SNAPSHOT).expect("snapshot");
    set.update_targets(real::TARGETS).expect("targets");
    // The stored copies load as such too.
    let mut set = v16();
    set.load_local_timestamp(real::TIMESTAMP).expect("stored");
    set.update_timestamp(real::TIMESTAMP)
        .expect("equal version");
    set.load_local_snapshot(real::SNAPSHOT).expect("stored");
    set.update_snapshot(real::SNAPSHOT).expect("equal version");
}

#[test]
fn sigstore_target_is_the_sigstore_fixture() {
    let target = through_targets()
        .target("trusted_root.json")
        .expect("listed");
    assert_eq!(target.length(), 6_787);
    assert_eq!(hex(target.sha256()), TRUSTED_ROOT_SHA256);
    assert_eq!(target.verify(real::TRUSTED_ROOT), Ok(()));
    boneli_sigstore::TrustedRoot::from_json(real::TRUSTED_ROOT).expect("readable");
}

/// A name only npm's delegation covers is not listed: the delegation is
/// never followed. Other top-level targets are found.
#[test]
fn sigstore_delegated_names_not_listed() {
    let set = through_targets();
    assert_eq!(
        set.target("registry.npmjs.org/keys.json"),
        Err(Error::NotListed)
    );
    assert_eq!(set.target("rekor.pub").map(|t| t.length()), Ok(178));
}

/// One changed signed byte in each real online file breaks its signature.
#[test]
fn sigstore_online_files_tampered_refused() {
    let tamper = |bytes: &[u8], from: &str, to: &str| {
        let text = std::str::from_utf8(bytes).expect("UTF-8");
        let out = text.replacen(from, to, 1);
        assert_ne!(out, text);
        out.into_bytes()
    };
    let mut set = v16();
    assert_eq!(
        set.update_timestamp(&tamper(
            real::TIMESTAMP,
            "\"version\": 842",
            "\"version\": 843"
        )),
        Err(Error::BelowThreshold { role: "timestamp" })
    );
    set.update_timestamp(real::TIMESTAMP).expect("timestamp");
    assert_eq!(
        set.update_snapshot(&tamper(real::SNAPSHOT, "\"version\": 9", "\"version\": 10")),
        Err(Error::BelowThreshold { role: "snapshot" })
    );
    set.update_snapshot(real::SNAPSHOT).expect("snapshot");
    assert_eq!(
        set.update_targets(&tamper(
            real::TARGETS,
            "\"length\": 6787",
            "\"length\": 6788"
        )),
        Err(Error::BelowThreshold { role: "targets" })
    );
}

/// The online files under the expired v15 still verify (same online and
/// targets keys), but no timestamp is trusted under an expired root.
#[test]
fn sigstore_timestamp_under_expired_root_refused() {
    let mut set = TrustedSet::new(real::root(15), real::START).expect("v15");
    assert_eq!(
        set.update_timestamp(real::TIMESTAMP),
        Err(Error::Expired { role: "root" })
    );
}
