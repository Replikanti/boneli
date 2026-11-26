//! The live refreshes over `TlsDial`, so revocation (ADR-017, ADR-020,
//! ADR-027) and name resolution (ADR-022) apply: from the pinned Sigstore
//! root v16 against `tuf-repo-cdn.sigstore.dev` (ADR-033, Accept when),
//! and from the pinned GitHub root v3 against `tuf-repo.github.com`,
//! whose installed file must verify K1 and K2, two private-repository
//! attestations, under the no-log opt-in of ADR-040 (ADR-041). Run by
//! hand and weekly in the `oci-acceptance` workflow:
//!
//! ```sh
//! cargo test -p boneli-tuf --test network -- --ignored --nocapture
//! ```

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boneli_https::{ConnectOptions, Roots, Sha256, TlsConfig, TlsDial};
use boneli_sigstore::TrustedRoot;
use boneli_tuf::{
    InitialRoot, Outcome, Refresh, Report, Repository, Timeouts, refresh_trusted_root,
};
use support::real::{self, K1, K2};
use support::server::{Scratch, sha256_hex};

/// Sigstore's public-good TUF repository.
const SIGSTORE: &str = "https://tuf-repo-cdn.sigstore.dev";

/// GitHub's TUF repository (ADR-041).
const GITHUB: &str = "https://tuf-repo.github.com";

/// The SHA-256 of `tests/data/sigstore-16.root.json`, the pin (its
/// README lists it).
const ROOT_V16_SHA256: &str = "27aea7e372aa7864065174f0661784fcf8b0e28b1dbfebeada31a0f1fb19167f";

/// A first refresh into an empty trust directory and a second one, which
/// must find the file current. Returns the first run's report and the
/// installed bytes.
fn refresh_twice(url: &str, initial: &InitialRoot, tag: &str) -> (Report, Vec<u8>) {
    let repository = Repository::parse(url).expect("the repository URL");
    let config = TlsConfig::new(Roots::mozilla()).expect("TLS config");
    // ADR-033's connect and handshake timeouts, and io as `Timeouts`.
    let options = ConnectOptions::new(
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(30),
    )
    .expect("options");
    let dial = TlsDial::new(config, options);
    let scratch = Scratch::new(tag);
    let start_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs();
    let refresh = Refresh {
        repository: &repository,
        initial_root: initial,
        dir: &scratch.trust(),
        dial: &dial,
        timeouts: Timeouts::default(),
        start_secs,
    };

    let begun = Instant::now();
    let first = refresh_trusted_root(&refresh).expect("live refresh");
    let took = begun.elapsed();
    let Outcome::Updated(report) = first else {
        panic!("an empty trust directory is updated: {first:?}");
    };
    let written = std::fs::read(scratch.at("trusted_root.json")).expect("installed");
    assert_eq!(Sha256::digest(&written), report.sha256);
    TrustedRoot::from_json(&written).expect("a trusted root");
    println!(
        "{url} first run: {took:?}; root v{}, timestamp v{}, snapshot v{}, targets v{}; \
         trusted_root.json {} bytes, sha256 {}",
        report.root_version,
        report.timestamp_version,
        report.snapshot_version,
        report.targets_version,
        written.len(),
        sha256_hex(&written),
    );

    let begun = Instant::now();
    let second = refresh_trusted_root(&refresh).expect("second live refresh");
    println!("{url} second run: {:?}, {second:?}", begun.elapsed());
    assert!(matches!(second, Outcome::Unchanged(_)), "{second:?}");
    (report, written)
}

#[test]
#[ignore = "network: refreshes trusted_root.json from tuf-repo-cdn.sigstore.dev"]
fn sigstore_refresh_live() {
    let initial = InitialRoot::new(real::root(16).to_vec(), ROOT_V16_SHA256).expect("pinned v16");
    let (_, written) = refresh_twice(SIGSTORE, &initial, "live");
    println!(
        "same as boneli-sigstore's fixture: {}",
        written == real::TRUSTED_ROOT
    );
}

/// From the pin of ADR-041 (root v3) into an empty trust directory. The
/// live versions are not pinned here: GitHub rotates its root about every
/// 4 to 8 months, so only "at least the capture's v9" is asserted. K1 and
/// K2 verifying under the installed file shows that GitHub still serves
/// its private-repository root under the name `trusted_root.json` and
/// still keeps the CA and TSA windows they were signed in.
#[test]
#[ignore = "network: refreshes GitHub's trusted_root.json from tuf-repo.github.com"]
fn github_refresh_live() {
    let initial =
        InitialRoot::new(real::github_root(3).to_vec(), real::GITHUB_PIN_V3).expect("pinned v3");
    let (report, written) = refresh_twice(GITHUB, &initial, "live-github");
    assert!(
        report.root_version >= real::GITHUB_NEWEST as i64,
        "{report:?}"
    );
    let root = Arc::new(TrustedRoot::from_json(&written).expect("GitHub's root"));
    println!("installed: {root:?}");
    for (name, bundle) in [("K1", &K1), ("K2", &K2)] {
        assert_eq!(
            bundle.verify(Arc::clone(&root)),
            Ok(real::GITHUB_VERDICT),
            "{name}"
        );
    }
    println!(
        "same as the captured TUF form: {}",
        written == real::GITHUB_TRUSTED_ROOT
    );
}
