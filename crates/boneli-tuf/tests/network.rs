//! The live refresh (ADR-033, Accept when): from the pinned Sigstore root
//! v16 against `tuf-repo-cdn.sigstore.dev` over `TlsDial`, so revocation
//! (ADR-017, ADR-020, ADR-027) and name resolution (ADR-022) apply. Run by
//! hand and weekly in the `oci-acceptance` workflow:
//!
//! ```sh
//! cargo test -p boneli-tuf --test network -- --ignored --nocapture
//! ```

mod support;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boneli_https::{ConnectOptions, Roots, Sha256, TlsConfig, TlsDial};
use boneli_tuf::{InitialRoot, Outcome, Refresh, Repository, Timeouts, refresh_trusted_root};
use support::real;
use support::server::{Scratch, sha256_hex};

/// Sigstore's public-good TUF repository.
const SIGSTORE: &str = "https://tuf-repo-cdn.sigstore.dev";

/// The SHA-256 of `tests/data/sigstore-16.root.json`, the pin (its
/// README lists it).
const ROOT_V16_SHA256: &str = "27aea7e372aa7864065174f0661784fcf8b0e28b1dbfebeada31a0f1fb19167f";

#[test]
#[ignore = "network: refreshes trusted_root.json from tuf-repo-cdn.sigstore.dev"]
fn sigstore_refresh_live() {
    let initial = InitialRoot::new(real::root(16).to_vec(), ROOT_V16_SHA256).expect("pinned v16");
    let repository = Repository::parse(SIGSTORE).expect("Sigstore's URL");
    let config = TlsConfig::new(Roots::mozilla()).expect("TLS config");
    // ADR-033's connect and handshake timeouts, and io as `Timeouts`.
    let options = ConnectOptions::new(
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(30),
    )
    .expect("options");
    let dial = TlsDial::new(config, options);
    let scratch = Scratch::new("live");
    let start_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();
    let refresh = Refresh {
        repository: &repository,
        initial_root: &initial,
        dir: &scratch.trust(),
        dial: &dial,
        timeouts: Timeouts::default(),
        start_secs,
    };

    let begun = Instant::now();
    let first = refresh_trusted_root(&refresh).expect("live refresh");
    let took = begun.elapsed();
    let Outcome::Updated(report) = &first else {
        panic!("an empty trust directory is updated: {first:?}");
    };
    let written = std::fs::read(scratch.at("trusted_root.json")).expect("installed");
    assert_eq!(Sha256::digest(&written), report.sha256);
    boneli_sigstore::TrustedRoot::from_json(&written).expect("a trusted root");
    println!(
        "first run: {took:?}; root v{}, timestamp v{}, snapshot v{}, targets v{}; \
         trusted_root.json {} bytes, sha256 {}; same as boneli-sigstore's fixture: {}",
        report.root_version,
        report.timestamp_version,
        report.snapshot_version,
        report.targets_version,
        written.len(),
        sha256_hex(&written),
        written == real::TRUSTED_ROOT,
    );

    let begun = Instant::now();
    let second = refresh_trusted_root(&refresh).expect("second live refresh");
    println!("second run: {:?}, {second:?}", begun.elapsed());
    assert!(matches!(second, Outcome::Unchanged(_)), "{second:?}");
}
