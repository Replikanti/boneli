//! The real Sigstore roots, captured from `tuf-repo-cdn.sigstore.dev` on
//! 2026-11-24, and GitHub's TUF repository `tuf-repo.github.com`,
//! captured on 2026-11-26 (`tests/data/README.md`).

use std::sync::Arc;

use boneli_sigstore::{
    CertificateClaims, ClaimMatch, Evidence, GITHUB_ACTIONS_ISSUER, Identity,
    SLSA_PROVENANCE_V1_PREDICATE, SanRule, Trust, TrustedRoot,
};

/// The start time of the known answers: 2026-11-24T00:00:00Z.
pub const START: u64 = 1_795_478_400;

/// `N.root.json` for N from 3 to 16, by version.
pub fn root(version: usize) -> &'static [u8] {
    ROOTS[version - 3]
}

const ROOTS: [&[u8]; 14] = [
    include_bytes!("../data/sigstore-3.root.json"),
    include_bytes!("../data/sigstore-4.root.json"),
    include_bytes!("../data/sigstore-5.root.json"),
    include_bytes!("../data/sigstore-6.root.json"),
    include_bytes!("../data/sigstore-7.root.json"),
    include_bytes!("../data/sigstore-8.root.json"),
    include_bytes!("../data/sigstore-9.root.json"),
    include_bytes!("../data/sigstore-10.root.json"),
    include_bytes!("../data/sigstore-11.root.json"),
    include_bytes!("../data/sigstore-12.root.json"),
    include_bytes!("../data/sigstore-13.root.json"),
    include_bytes!("../data/sigstore-14.root.json"),
    include_bytes!("../data/sigstore-15.root.json"),
    include_bytes!("../data/sigstore-16.root.json"),
];

/// `timestamp.json` v842, captured 2026-11-24 with `166.snapshot.json`
/// and `14.targets.json`; signed by root v16's online key.
pub const TIMESTAMP: &[u8] = include_bytes!("../data/sigstore-timestamp.json");
pub const SNAPSHOT: &[u8] = include_bytes!("../data/sigstore-166.snapshot.json");
pub const TARGETS: &[u8] = include_bytes!("../data/sigstore-14.targets.json");

/// The timestamp's `expires`, 2026-11-30T01:20:52Z, in seconds.
pub const TIMESTAMP_EXPIRES: u64 = 1_796_001_652;

/// The `trusted_root.json` that `boneli-sigstore` verifies against, which
/// is the target `14.targets.json` lists (same SHA-256).
pub const TRUSTED_ROOT: &[u8] =
    include_bytes!("../../../boneli-sigstore/tests/data/sigstore-trusted-root.json");

// ---- GitHub's TUF repository (ADR-041) -----------------------------------

/// The start time of GitHub's known answers: 2026-11-26T00:00:00Z, the
/// capture date of `tests/data/github-*` (`tests/data/README.md`).
pub const GITHUB_START: u64 = 1_795_651_200;

/// GitHub's `N.root.json` for N from 1 to 9, by version, captured from
/// `tuf-repo.github.com` (`10.root.json` was 404).
pub fn github_root(version: usize) -> &'static [u8] {
    GITHUB_ROOTS[version - 1]
}

/// The newest GitHub root of the capture.
pub const GITHUB_NEWEST: usize = 9;

const GITHUB_ROOTS: [&[u8]; 9] = [
    include_bytes!("../data/github-1.root.json"),
    include_bytes!("../data/github-2.root.json"),
    include_bytes!("../data/github-3.root.json"),
    include_bytes!("../data/github-4.root.json"),
    include_bytes!("../data/github-5.root.json"),
    include_bytes!("../data/github-6.root.json"),
    include_bytes!("../data/github-7.root.json"),
    include_bytes!("../data/github-8.root.json"),
    include_bytes!("../data/github-9.root.json"),
];

/// The pin of ADR-041: the SHA-256 of `github-3.root.json`, which is byte
/// for byte the root `cli/cli` embeds for `tuf-repo.github.com`.
pub const GITHUB_PIN_V3: &str = "98cba97be9075bc98b2322de3de85fbd1b70ec7392991dfd2f53d215bede1a8d";

/// GitHub's `timestamp.json` v1027, captured with `84.snapshot.json` and
/// `10.targets.json`; signed by root v9's online key.
pub const GITHUB_TIMESTAMP: &[u8] = include_bytes!("../data/github-timestamp.json");
pub const GITHUB_SNAPSHOT: &[u8] = include_bytes!("../data/github-84.snapshot.json");
pub const GITHUB_TARGETS: &[u8] = include_bytes!("../data/github-10.targets.json");
/// Their versions.
pub const GITHUB_TIMESTAMP_VERSION: i64 = 1027;
pub const GITHUB_SNAPSHOT_VERSION: i64 = 84;
pub const GITHUB_TARGETS_VERSION: i64 = 10;

/// The timestamp's `expires`, 2026-12-03T07:22:31Z, in seconds.
pub const GITHUB_TIMESTAMP_EXPIRES: u64 = 1_796_282_551;
/// Root v9's `expires`, 2027-01-28T20:18:53Z, in seconds.
pub const GITHUB_ROOT_V9_EXPIRES: u64 = 1_801_167_533;

/// The `trusted_root.json` target of `10.targets.json`, as the repository
/// serves it: pretty-printed, 31,645 bytes. The same JSON as
/// boneli-sigstore's compact `github-trusted-root.json`, other bytes.
pub const GITHUB_TRUSTED_ROOT: &[u8] = include_bytes!("../data/github-tuf-trusted-root.json");
/// Its SHA-256.
pub const GITHUB_TRUSTED_ROOT_SHA256: &str =
    "484cdfe1a7c65479c5ba2a22193d1be90f0020db1997de696ab207434c62fbb7";

/// boneli-sigstore's copy of GitHub's root, the compact line of
/// `gh attestation trusted-root` (ADR-040).
pub const GITHUB_COMPACT_TRUSTED_ROOT: &[u8] =
    include_bytes!("../../../boneli-sigstore/tests/data/github-trusted-root.json");

/// One private-repository attestation of GitHub's instance and what its
/// leaf meets, copied from boneli-sigstore's `tests/support/real.rs`.
pub struct GithubBundle {
    pub bundle: &'static [u8],
    pub digest: [u8; 32],
    pub san: &'static str,
    pub repository: &'static str,
    pub repository_id: &'static str,
    pub trigger: &'static str,
}

/// K1: the attest-demo bundle cli/cli keeps as a test fixture (MIT), from
/// the private `actions/attest-demo`, CA and TSA window 0. In its SAN
/// `\x79` is a `y`: the workflow file is named after an interpreter, a
/// name CI refuses in tracked files (ADR-015, D10).
pub const K1: GithubBundle = GithubBundle {
    bundle: include_bytes!("../../../boneli-sigstore/tests/data/attest-demo-0.0.12.bundle.json"),
    digest: hex32("ae57936def59bc4c75edd3a837d89bcefc6d3a5e31d55a6fa7a71624f92c3c3b"),
    san: "https://github.com/actions/attest-demo/.github/workflows/build-p\x79thon.yml@refs/heads/main",
    repository: "https://github.com/actions/attest-demo",
    repository_id: "763287532",
    trigger: "workflow_dispatch",
};

/// K2: the bundle of GitHub's prober of its instance in the MIT
/// `actions/attest-build-provenance`, CA and TSA window 4.
pub const K2: GithubBundle = GithubBundle {
    bundle: include_bytes!("../../../boneli-sigstore/tests/data/attest-prober-github.bundle.json"),
    digest: hex32("f4a0d47c6bdbf3bdbe3478a043b7030fcef5fdf34be90d841891803c2efe9fc5"),
    san: "https://github.com/actions/attest-build-provenance/.github/workflows/prober.yml@refs/heads/main",
    repository: "https://github.com/actions/attest-build-provenance",
    repository_id: "760702757",
    trigger: "schedule",
};

impl GithubBundle {
    /// The verdict on this bundle under `root`, in a trust of ADR-040's
    /// form: its exact SAN, SLSA v1, certificate claims on its exact
    /// repository, repository ID and trigger, and the no-log opt-in.
    pub fn verify(
        &self,
        root: Arc<TrustedRoot>,
    ) -> Result<boneli_sigstore::Accepted, boneli_sigstore::Refusal> {
        let identity = Identity::new(GITHUB_ACTIONS_ISSUER, SanRule::Uri(self.san.to_owned()))
            .expect("identity");
        let claims = CertificateClaims::new(
            Some(ClaimMatch::Exact(self.repository.to_owned())),
            None,
            vec![self.trigger.to_owned()],
        )
        .expect("claims")
        .with_repository_id(self.repository_id)
        .expect("repository id");
        let trust = Trust::new(
            Vec::new(),
            Some((root, vec![identity])),
            vec![SLSA_PROVENANCE_V1_PREDICATE.to_owned()],
        )
        .expect("trust")
        .with_certificate_claims(claims)
        .expect("certificate claims")
        .with_no_log()
        .expect("no log");
        let evidence = Evidence::from_bundle(self.bundle).expect("bundle");
        boneli_sigstore::verify(&evidence, &self.digest, &trust)
    }
}

/// The verdict K1 and K2 get under GitHub's root (ADR-040).
pub const GITHUB_VERDICT: boneli_sigstore::Accepted =
    boneli_sigstore::Accepted::KeylessWithoutLog {
        signed_timestamps: 1,
        identity: 0,
    };

/// 64 hex characters as 32 bytes, at compile time.
const fn hex32(text: &str) -> [u8; 32] {
    const fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not lower-case hex"),
        }
    }
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = digit(bytes[2 * i]) << 4 | digit(bytes[2 * i + 1]);
        i += 1;
    }
    out
}
