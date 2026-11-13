//! The `Evidence` port: content-addressed storage of the run's artifacts
//! (ADR-004, D1).
//!
//! The reproduction test, the analysis and the diff are stored here, and the
//! run's events point at them through an `EvidenceRef`. The reference format
//! belongs to the real adapter (#4).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use boneli_domain::EvidenceRef;

/// Why the evidence store did not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// Nothing is stored under this reference.
    NotFound,
    /// The reference has a form this store never issues.
    InvalidReference,
    /// The store could not be reached or written.
    Unavailable {
        /// What went wrong, as the store reports it.
        detail: String,
    },
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvidenceError::NotFound => f.write_str("nothing is stored under this reference"),
            EvidenceError::InvalidReference => {
                f.write_str("the reference has a form this store never issues")
            }
            EvidenceError::Unavailable { detail } => {
                write!(f, "the evidence store is unavailable: {detail}")
            }
        }
    }
}

impl core::error::Error for EvidenceError {}

/// Content-addressed storage: the same bytes give the same reference, and
/// different bytes give different references.
pub trait Evidence {
    /// Stores the bytes and returns their reference.
    fn put(&self, content: &[u8]) -> Result<EvidenceRef, EvidenceError>;

    /// The bytes stored under the reference, exactly as put.
    fn get(&self, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError>;
}
