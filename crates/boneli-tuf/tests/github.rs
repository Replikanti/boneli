//! Known answers on GitHub's real TUF repository `tuf-repo.github.com`
//! (ADR-041): roots v1 to v9, timestamp v1027, `84.snapshot.json` and
//! `10.targets.json`, captured on 2026-11-26, verify under the unchanged
//! rules of ADR-033, and the `trusted_root.json` target is GitHub's
//! no-log root of ADR-040 in its pretty-printed form.

mod support;

use std::sync::Arc;

use boneli_sigstore::TrustedRoot;
use boneli_tuf::{Error, InitialRoot, Outcome, Timeouts, TrustedSet};
use support::real::{self, K1, K2};
use support::repo::hex;
use support::server::{Scratch, Server, run_with, sha256_hex};

fn v9_at(start: u64) -> TrustedSet {
    TrustedSet::new(real::github_root(9), start).expect("v9")
}

fn through_targets() -> TrustedSet {
    let mut set = v9_at(real::GITHUB_START);
    set.update_timestamp(real::GITHUB_TIMESTAMP)
        .expect("timestamp");
    set.update_snapshot(real::GITHUB_SNAPSHOT)
        .expect("snapshot");
    set.update_targets(real::GITHUB_TARGETS).expect("targets");
    set
}

/// A fake repository serving GitHub's captured files under their
/// repository names.
fn github_server() -> Server {
    let server = Server::new();
    for v in 1..=real::GITHUB_NEWEST {
        server.put(&format!("{v}.root.json"), real::github_root(v));
    }
    server.put("timestamp.json", real::GITHUB_TIMESTAMP);
    server.put(
        &format!("{}.snapshot.json", real::GITHUB_SNAPSHOT_VERSION),
        real::GITHUB_SNAPSHOT,
    );
    server.put(
        &format!("{}.targets.json", real::GITHUB_TARGETS_VERSION),
        real::GITHUB_TARGETS,
    );
    server.put(
        &format!(
            "targets/{}.trusted_root.json",
            real::GITHUB_TRUSTED_ROOT_SHA256
        ),
        real::GITHUB_TRUSTED_ROOT,
    );
    server
}

fn pin(version: usize) -> InitialRoot {
    let bytes = real::github_root(version);
    InitialRoot::new(bytes.to_vec(), &sha256_hex(bytes)).expect("a pin")
}

/// Head of the chain: v1 to v9 each pass their own threshold and publish
/// consistent snapshots, and the chain from v1 verifies with no online
/// key change, so the 5.3.11 drop never fires.
#[test]
fn github_roots_chain_from_v1() {
    for v in 1..=real::GITHUB_NEWEST {
        let set = TrustedSet::new(real::github_root(v), real::GITHUB_START)
            .unwrap_or_else(|e| panic!("v{v}: {e}"));
        assert_eq!(set.root().version(), v as i64);
        assert!(set.root().consistent_snapshot(), "v{v}");
    }
    let mut set = TrustedSet::new(real::github_root(1), real::GITHUB_START).expect("v1");
    for v in 2..=real::GITHUB_NEWEST {
        set.update_root(real::github_root(v))
            .unwrap_or_else(|e| panic!("v{v}: {e}"));
        assert!(!set.online_keys_changed(), "v{v}");
    }
    assert_eq!(set.root().version(), 9);
    set.check_root_expiry().expect("v9 current");
    // Every root before v9 had expired on the capture date.
    for v in 1..real::GITHUB_NEWEST {
        let set = TrustedSet::new(real::github_root(v), real::GITHUB_START).expect("root");
        assert_eq!(
            set.check_root_expiry(),
            Err(Error::Expired { role: "root" }),
            "v{v}"
        );
    }
}

/// Every captured root is a pin the rules accept, and v3 is the one
/// ADR-041 pins.
#[test]
fn github_every_root_is_a_pin() {
    for v in 1..=real::GITHUB_NEWEST {
        let bytes = real::github_root(v);
        InitialRoot::new(bytes.to_vec(), &sha256_hex(bytes))
            .unwrap_or_else(|e| panic!("v{v}: {e}"));
    }
    assert_eq!(sha256_hex(real::github_root(3)), real::GITHUB_PIN_V3);
    assert_eq!(real::github_root(3).len(), 7_480);
    InitialRoot::new(real::github_root(3).to_vec(), real::GITHUB_PIN_V3).expect("the pin");
}

#[test]
fn github_metadata_verifies_under_v9() {
    let set = through_targets();
    assert_eq!(
        set.timestamp_version(),
        Some(real::GITHUB_TIMESTAMP_VERSION)
    );
    assert_eq!(set.snapshot_version(), Some(real::GITHUB_SNAPSHOT_VERSION));
    assert_eq!(set.targets_version(), Some(real::GITHUB_TARGETS_VERSION));
    // GitHub names snapshot and targets by version only, as Sigstore.
    let snapshot = set.snapshot_meta().expect("snapshot meta");
    assert_eq!(
        (snapshot.version(), snapshot.length()),
        (real::GITHUB_SNAPSHOT_VERSION, None)
    );
    assert!(snapshot.sha256().is_none());
    let targets = set.targets_meta().expect("targets meta");
    assert_eq!(
        (targets.version(), targets.length()),
        (real::GITHUB_TARGETS_VERSION, None)
    );
    assert!(targets.sha256().is_none());
    let target = set.target("trusted_root.json").expect("listed");
    assert_eq!(target.length(), real::GITHUB_TRUSTED_ROOT.len() as u64);
    assert_eq!(target.length(), 31_645);
    assert_eq!(hex(target.sha256()), real::GITHUB_TRUSTED_ROOT_SHA256);
    assert_eq!(target.verify(real::GITHUB_TRUSTED_ROOT), Ok(()));
    let root = TrustedRoot::from_json(real::GITHUB_TRUSTED_ROOT).expect("readable");
    assert_eq!(
        format!("{root:?}"),
        "TrustedRoot { tlogs: 0, note_logs: 0, authorities: 6, ctlogs: 0, tsas: 6 }"
    );
    // The stored copies load as such too.
    let mut set = v9_at(real::GITHUB_START);
    set.load_local_timestamp(real::GITHUB_TIMESTAMP)
        .expect("stored");
    set.update_timestamp(real::GITHUB_TIMESTAMP)
        .expect("equal version");
    set.load_local_snapshot(real::GITHUB_SNAPSHOT)
        .expect("stored");
    set.update_snapshot(real::GITHUB_SNAPSHOT)
        .expect("equal version");
}

/// The whole refresh over GitHub's real files: from the pin v3 the first
/// run verifies v4 to v9, ends the chain at the 404 of `10.root.json`
/// and fetches the three online files and the target (11 requests); the
/// second run finds the file current (4). From v9 (the tail of the
/// chain) the first run starts at `10.root.json` (5). No other target,
/// such as the `prod-*` tenant roots, is ever requested.
#[test]
fn github_refresh_offline() {
    let snapshot = format!("{}.snapshot.json", real::GITHUB_SNAPSHOT_VERSION);
    let targets = format!("{}.targets.json", real::GITHUB_TARGETS_VERSION);
    let target = format!(
        "targets/{}.trusted_root.json",
        real::GITHUB_TRUSTED_ROOT_SHA256
    );
    let online = [
        "timestamp.json".to_string(),
        snapshot.clone(),
        targets.clone(),
    ];
    let next = format!("{}.root.json", real::GITHUB_NEWEST + 1);
    let refresh = |server: &Server, scratch: &Scratch, initial: &InitialRoot| {
        run_with(
            server,
            &scratch.trust(),
            initial,
            real::GITHUB_START,
            Timeouts::default(),
        )
    };

    let server = github_server();
    let scratch = Scratch::new("github-v3");
    let initial = InitialRoot::new(real::github_root(3).to_vec(), real::GITHUB_PIN_V3).expect("v3");
    let first = refresh(&server, &scratch, &initial).expect("first run");
    let Outcome::Updated(report) = &first else {
        panic!("an empty trust directory is updated: {first:?}");
    };
    assert_eq!(
        (
            report.root_version,
            report.timestamp_version,
            report.snapshot_version,
            report.targets_version
        ),
        (
            9,
            real::GITHUB_TIMESTAMP_VERSION,
            real::GITHUB_SNAPSHOT_VERSION,
            real::GITHUB_TARGETS_VERSION
        )
    );
    assert_eq!(hex(&report.sha256), real::GITHUB_TRUSTED_ROOT_SHA256);
    let mut expected: Vec<String> = (4..=real::GITHUB_NEWEST)
        .map(|v| format!("{v}.root.json"))
        .collect();
    expected.push(next.clone());
    expected.extend(online.iter().cloned());
    expected.push(target.clone());
    assert_eq!(server.requested(), expected);
    assert_eq!(expected.len(), 11);
    assert_eq!(
        std::fs::read(scratch.at("trusted_root.json")).expect("installed"),
        real::GITHUB_TRUSTED_ROOT
    );
    assert_eq!(
        std::fs::read(scratch.at("tuf/root.json")).expect("stored root"),
        real::github_root(9)
    );

    server.clear_log();
    let second = refresh(&server, &scratch, &initial).expect("second run");
    assert!(matches!(second, Outcome::Unchanged(_)), "{second:?}");
    let mut expected = vec![next.clone()];
    expected.extend(online.iter().cloned());
    assert_eq!(server.requested(), expected);

    let server = github_server();
    let scratch = Scratch::new("github-v9");
    let first = refresh(&server, &scratch, &pin(9)).expect("from v9");
    assert!(matches!(first, Outcome::Updated(_)), "{first:?}");
    let mut expected = vec![next];
    expected.extend(online.iter().cloned());
    expected.push(target);
    assert_eq!(server.requested(), expected);
    assert!(server.requested().iter().all(|r| !r.contains("prod-")));
}

/// The round trip of the rendered form: the TUF file and the compact line
/// of `gh attestation trusted-root` are the same root, and K1 and K2 get
/// the same verdict under both.
#[test]
fn github_tuf_form_verifies_k1_k2() {
    assert_ne!(real::GITHUB_TRUSTED_ROOT, real::GITHUB_COMPACT_TRUSTED_ROOT);
    let tuf = Arc::new(TrustedRoot::from_json(real::GITHUB_TRUSTED_ROOT).expect("TUF form"));
    let compact =
        Arc::new(TrustedRoot::from_json(real::GITHUB_COMPACT_TRUSTED_ROOT).expect("gh form"));
    assert_eq!(format!("{tuf:?}"), format!("{compact:?}"));
    for (name, bundle) in [("K1", &K1), ("K2", &K2)] {
        assert_eq!(
            bundle.verify(Arc::clone(&tuf)),
            Ok(real::GITHUB_VERDICT),
            "{name}"
        );
        assert_eq!(
            bundle.verify(Arc::clone(&compact)),
            Ok(real::GITHUB_VERDICT),
            "{name}"
        );
    }
}

/// One root's metadata never verifies under the other's keys.
#[test]
fn cross_root_metadata_refused() {
    let mut github = v9_at(real::GITHUB_START);
    assert_eq!(
        github.update_timestamp(real::TIMESTAMP),
        Err(Error::BelowThreshold { role: "timestamp" })
    );
    let mut sigstore = TrustedSet::new(real::root(16), real::START).expect("Sigstore v16");
    assert_eq!(
        sigstore.update_timestamp(real::GITHUB_TIMESTAMP),
        Err(Error::BelowThreshold { role: "timestamp" })
    );
    // Sigstore's v10 offered as GitHub's next root: version 10 is GitHub's
    // next, but no GitHub root key signed it.
    let mut github = v9_at(real::GITHUB_START);
    assert_eq!(
        github.update_root(real::root(10)),
        Err(Error::BelowThreshold { role: "root" })
    );
    assert_eq!(github.root().version(), 9);
}

/// Expiry is exclusive at `expires`, on GitHub's own numbers: the
/// timestamp at its expiry second and root v9 at its.
#[test]
fn github_expiry_bounds() {
    let expires = real::GITHUB_TIMESTAMP_EXPIRES;
    let mut set = v9_at(expires);
    assert_eq!(
        set.update_timestamp(real::GITHUB_TIMESTAMP),
        Err(Error::Expired { role: "timestamp" })
    );
    let mut set = v9_at(expires - 1);
    set.update_timestamp(real::GITHUB_TIMESTAMP)
        .expect("one second before");

    let expires = real::GITHUB_ROOT_V9_EXPIRES;
    assert_eq!(
        v9_at(expires).check_root_expiry(),
        Err(Error::Expired { role: "root" })
    );
    v9_at(expires - 1)
        .check_root_expiry()
        .expect("one second before");
}

/// The target is looked up by its exact bytes: a tenant root is listed
/// but is another name, and look-alikes of `trusted_root.json` are not
/// listed.
#[test]
fn github_target_lookup_is_byte_exact() {
    let set = through_targets();
    assert_eq!(
        set.target("trusted_root.json").map(|t| t.length()),
        Ok(31_645)
    );
    assert_eq!(
        set.target("prod-weu-01.trusted_root.json")
            .map(|t| t.length()),
        Ok(26_576)
    );
    for name in [
        "Trusted_root.json",
        "trusted_root.json ",
        "trusted_root.json\u{200b}",
        "trusted_root\u{2024}json",
        "targets/trusted_root.json",
    ] {
        assert_eq!(
            set.target(name).map(|_| ()),
            Err(Error::NotListed),
            "{name:?}"
        );
    }
}
