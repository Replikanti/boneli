//! The real Sigstore roots, captured from `tuf-repo-cdn.sigstore.dev` on
//! 2026-11-24 (`tests/data/README.md`).

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
