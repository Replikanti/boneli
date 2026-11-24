//! A client for Sigstore's TUF repository that keeps the operator's
//! `trusted_root.json` current (ADR-033), written here because every TUF
//! crate pulls crates that `deny.toml` bans.
//!
//! The workflow is the TUF specification's (5.1 to 5.7), top-level roles
//! only. [`refresh_trusted_root`] runs it: it fetches each file through
//! the caller's `boneli_https::Dial` ([`Repository`], [`Timeouts`]), keeps
//! the TUF state in a private trust directory under its lock, starts from
//! the operator's pinned [`InitialRoot`] once, and installs
//! `trusted_root.json` by rename only after every step and
//! `TrustedRoot::from_json` passed ([`Outcome`], [`RefreshError`]). It
//! spawns no thread. Under it is the pure core:
//!
//! - [`canonical`]: the canonical form TUF metadata is signed over:
//!   sorted keys, no whitespace, only `\` and `"` escaped, control
//!   characters raw, integers only;
//! - thresholds over **distinct** keys: ECDSA P-256 keys under scheme
//!   `ecdsa-sha2-nistp256` only; every other key and every signature that
//!   does not decode or verify counts zero without refusing the document;
//! - [`TrustedSet`]: a trusted root, verified against its own threshold,
//!   and the root chain (5.3): each next root is signed by a threshold of
//!   the trusted root's keys and of its own, has version N+1 exactly and
//!   type `root`; the newest must not be expired; a change to the
//!   timestamp or snapshot keys raises the fast-forward signal (5.3.11)
//!   and drops the stored timestamp and snapshot;
//! - on top of it the timestamp (5.4), the snapshot (5.5) and the
//!   top-level targets (5.6), each with its threshold, type, version
//!   rules and expiry, the snapshot and targets also with the length and
//!   SHA-256 the referring file lists ([`MetaFile`]); and the target
//!   lookup (5.7) in top-level `targets` only, which yields a
//!   [`TargetFile`] to check the fetched bytes with.
//!
//! The core reads no clock, file or network: the caller passes the bytes
//! and the update's start time (5.1), and the refresh reads no clock
//! either. Every refusal is an [`Error`] with a fixed reason that echoes no
//! metadata text.
#![doc(test(attr(forbid(unsafe_code))))]

mod canonical;
mod envelope;
mod error;
mod expires;
mod fetch;
mod key;
mod meta;
mod refresh;
mod repository;
mod root;
mod snapshot;
mod state;
mod targets;
mod threshold;
mod timestamp;
mod trusted;

pub use canonical::canonical;
pub use error::Error;
pub use fetch::{InvalidTimeouts, MAX_HEAD_BYTES, MAX_HEADERS, Timeouts};
pub use meta::MetaFile;
pub use refresh::{
    InitialRoot, Outcome, Refresh, RefreshError, Report, Step, refresh_trusted_root,
};
pub use repository::{Repository, RepositoryError};
pub use root::Root;
pub use targets::TargetFile;
pub use trusted::TrustedSet;

/// The largest `root.json` accepted: 65,536 bytes. The largest Sigstore
/// root is 6,911 bytes (v10), so the cap is 9.5 times that. A signing key
/// costs about 854 bytes (key entry 550, signature 234, key ID in a role
/// about 70), so the cap holds about 76 signing keys against today's 6.
/// A cap below about 7 KB refuses today's v10; a higher one only costs
/// memory (ADR-033, limits).
pub const MAX_ROOT_BYTES: usize = 65_536;

/// The largest `timestamp.json` accepted: 16,384 bytes, 36.7 times the
/// measured 447. One entry of at most 304 bytes (two hashes) leaves room
/// for about 68 signatures of 234 bytes (ADR-033, limits).
pub const MAX_TIMESTAMP_BYTES: usize = 16_384;

/// The largest `snapshot.json` accepted: 1 MiB, 595 times the measured
/// 1,760 bytes. At 304 bytes per entry that is about 3,449 roles; entries
/// grow with delegated roles, of which Sigstore has 1 live and 4 stale
/// (ADR-033, limits).
pub const MAX_SNAPSHOT_BYTES: usize = 1_048_576;

/// The largest `targets.json` accepted: 1 MiB, 212 times the measured
/// 4,942 bytes. At 287 bytes per target that is about 3,650 targets
/// (ADR-033, limits).
pub const MAX_TARGETS_BYTES: usize = 1_048_576;

/// The deepest nesting a metadata document may have: 16, the document
/// limit of ADR-009 D12 that ADR-029 uses too. Measured at most 7
/// (targets); a deeper document is not TUF metadata (ADR-033, limits).
pub const MAX_JSON_DEPTH: usize = 16;

/// The most JSON values a metadata document may hold: 65,536, the
/// document limit of ADR-009 D12. Measured at most 124 (root); the byte
/// caps bound memory first for root and timestamp, this one for snapshot
/// and targets (ADR-033, limits).
pub const MAX_JSON_VALUES: usize = 65_536;

/// The most new roots one refresh verifies and stores: 32. Sigstore
/// rotated 15 times in about 5.3 years (about 2.8 a year, inferred from
/// expiry dates), so 32 is about 11 years of lag. A 33rd new root stops
/// the run with an error, the 32 stay stored, and the next run goes on
/// from there: the cap bounds one run (at most 33 root requests), not how
/// far behind a trust directory may be (ADR-033, limits).
pub const MAX_ROOT_ROTATIONS: usize = 32;
