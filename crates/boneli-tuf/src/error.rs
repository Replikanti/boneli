//! The one error type of the pure core. Every variant is a fixed reason:
//! role names, versions and caps are echoed, metadata text never is
//! (ADR-033, item 9).

use std::fmt;

/// Why a metadata document was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The document is longer than its role's cap.
    TooLarge {
        /// The cap in bytes.
        cap: usize,
    },
    /// The document is not JSON within the limits (`MAX_JSON_DEPTH`,
    /// `MAX_JSON_VALUES`), or an object holds a key twice.
    Json(boneli_json::ErrorKind),
    /// The envelope is not an object with a `signed` object and a
    /// `signatures` array of objects with string `keyid` and `sig`.
    Envelope,
    /// `signed` holds a number that is not a canonical integer within
    /// `i64` (a fraction, an exponent, `-0`), or a value nested deeper
    /// than `boneli_json::MAX_DEPTH`; the canonical form has neither.
    NotCanonical,
    /// A field of `signed` is missing, of the wrong JSON type or out of
    /// its range.
    Field(&'static str),
    /// `_type` is not the role expected here.
    Type {
        /// The role name the document had to carry.
        expected: &'static str,
    },
    /// `spec_version` is not `1.<n>` or `1.<n>.<m>`.
    SpecVersion,
    /// `expires` is not of the form `YYYY-MM-DDTHH:MM:SSZ` or names no
    /// real time.
    Expires,
    /// A role lists one key ID twice.
    DuplicateKeyId {
        /// The role.
        role: &'static str,
    },
    /// A role lists a key ID that `keys` does not hold.
    UnknownKeyId {
        /// The role.
        role: &'static str,
    },
    /// A role's threshold is below 1.
    InvalidThreshold {
        /// The role.
        role: &'static str,
    },
    /// The document's signatures do not reach the threshold of the role
    /// as the trusted root defines it.
    BelowThreshold {
        /// The role.
        role: &'static str,
    },
    /// A root's signatures do not reach the threshold of its own root
    /// role.
    BelowOwnThreshold,
    /// A new root's version is not the trusted one plus 1.
    NotNextVersion {
        /// The version required.
        expected: i64,
        /// The version found.
        found: i64,
    },
    /// The trusted root's version is `i64::MAX`, which has no successor.
    NoNextVersion,
    /// The document has expired at the update's start time.
    Expired {
        /// The role.
        role: &'static str,
    },
    /// A version is below the one trusted before (5.4.3): the timestamp's
    /// own, or the snapshot version a timestamp names.
    Rollback {
        /// The role whose version went back.
        role: &'static str,
        /// The version trusted before.
        trusted: i64,
        /// The version found.
        found: i64,
    },
    /// A document's version is not the one the referring metadata names
    /// (5.5.4, 5.6.4).
    VersionMismatch {
        /// The role.
        role: &'static str,
        /// The version named.
        expected: i64,
        /// The version found.
        found: i64,
    },
    /// A file's length is not the one listed for it.
    LengthMismatch {
        /// `snapshot`, `targets` or `target`.
        role: &'static str,
        /// The listed length.
        expected: u64,
        /// The length found.
        found: u64,
    },
    /// A file's SHA-256 is not the one listed for it.
    HashMismatch {
        /// `snapshot`, `targets` or `target`.
        role: &'static str,
    },
    /// A hash map holds no `sha256`, the one algorithm read.
    NoSha256,
    /// The new snapshot no longer lists a file the stored one listed
    /// (5.5.5).
    EntryDropped,
    /// The new snapshot lists a file with a lower version than the stored
    /// one did (5.5.5).
    EntryRollback {
        /// The version in the stored snapshot.
        trusted: i64,
        /// The version in the new one.
        found: i64,
    },
    /// The trusted targets do not list the target in top-level `targets`.
    /// Delegations are never followed.
    NotListed,
    /// The target's listed length is above the cap of the file it
    /// becomes, so it is never fetched.
    TargetTooLarge {
        /// The cap in bytes, `boneli_sigstore::MAX_TRUSTED_ROOT_BYTES`.
        cap: usize,
    },
    /// The call does not follow the update order: the root chain, the
    /// stored timestamp, the timestamp, the stored snapshot, the snapshot,
    /// targets, then the target, each at most once except the timestamp.
    OutOfOrder,
    /// A root of this update changed the timestamp or snapshot keys or
    /// thresholds, so stored timestamp and snapshot metadata are not used
    /// (5.3.11, fast-forward recovery).
    OnlineKeysChanged,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooLarge { cap } => write!(f, "the document is larger than {cap} bytes"),
            Error::Json(kind) => write!(f, "the document is not JSON within its limits ({kind:?})"),
            Error::Envelope => f.write_str(
                "the document is not an object with a signed object and a signatures array",
            ),
            Error::NotCanonical => {
                f.write_str("the signed part holds a value the canonical form cannot write")
            }
            Error::Field(name) => write!(f, "the field {name} is missing or invalid"),
            Error::Type { expected } => write!(f, "the document's _type is not {expected}"),
            Error::SpecVersion => f.write_str("the spec_version is not 1.<n> or 1.<n>.<m>"),
            Error::Expires => f.write_str("expires is not of the form YYYY-MM-DDTHH:MM:SSZ"),
            Error::DuplicateKeyId { role } => write!(f, "the {role} role lists a key ID twice"),
            Error::UnknownKeyId { role } => {
                write!(f, "the {role} role lists a key ID that keys does not hold")
            }
            Error::InvalidThreshold { role } => {
                write!(f, "the {role} role's threshold is below 1")
            }
            Error::BelowThreshold { role } => write!(
                f,
                "the signatures do not reach the threshold of the trusted {role} role"
            ),
            Error::BelowOwnThreshold => {
                f.write_str("the root's signatures do not reach its own root threshold")
            }
            Error::NotNextVersion { expected, found } => {
                write!(f, "the root's version is {found}, not {expected}")
            }
            Error::NoNextVersion => f.write_str("the trusted root's version has no successor"),
            Error::Expired { role } => write!(f, "the {role} metadata has expired"),
            Error::Rollback {
                role,
                trusted,
                found,
            } => write!(
                f,
                "the {role} version {found} is below the trusted version {trusted}"
            ),
            Error::VersionMismatch {
                role,
                expected,
                found,
            } => write!(f, "the {role} version is {found}, not {expected}"),
            Error::LengthMismatch {
                role,
                expected,
                found,
            } => write!(f, "the {role} file is {found} bytes, not {expected}"),
            Error::HashMismatch { role } => {
                write!(f, "the {role} file's SHA-256 is not the listed one")
            }
            Error::NoSha256 => f.write_str("the hashes hold no sha256"),
            Error::EntryDropped => {
                f.write_str("the snapshot no longer lists a file the stored snapshot lists")
            }
            Error::EntryRollback { trusted, found } => write!(
                f,
                "the snapshot lists a file at version {found}, below the stored {trusted}"
            ),
            Error::NotListed => f.write_str("the target is not listed in the top-level targets"),
            Error::TargetTooLarge { cap } => {
                write!(f, "the target is listed as larger than {cap} bytes")
            }
            Error::OutOfOrder => f.write_str("the metadata was offered out of the update order"),
            Error::OnlineKeysChanged => f.write_str(
                "the root changed the timestamp or snapshot keys, so stored metadata is not used",
            ),
        }
    }
}

impl std::error::Error for Error {}
