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
