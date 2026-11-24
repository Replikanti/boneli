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
        }
    }
}

impl std::error::Error for Error {}
