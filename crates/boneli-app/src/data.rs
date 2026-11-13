//! The `DataSnapshot` port: the application's data, loaded once per
//! snapshot and copied per run (ADR-004, D1; `docs/ARCHITECTURE.md`,
//! "Environment and data").
//!
//! Minimal on purpose: the real adapter (#31) runs its commands through the
//! `Sandbox` port and may add operations and clauses under the extension
//! rule of ADR-004. Removing a copy is `remove_copy`, not named after the
//! SQL statement: that name ends in a letter the core's format-spec scan
//! would trip on inside a brace group (ADR-001).

use alloc::string::String;
use core::fmt;

use boneli_domain::RunId;

use crate::sandbox::SandboxId;

/// Where the data comes from: seed data in the repository or an anonymized
/// snapshot. Opaque here; the adapter (#31) decides which forms it accepts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotSource(String);

impl SnapshotSource {
    /// Wraps a source.
    pub fn new(source: String) -> SnapshotSource {
        SnapshotSource(source)
    }

    /// The source as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The adapter's handle to a loaded snapshot, the template copies are
/// made from. Opaque; the adapter issues it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotId(String);

impl SnapshotId {
    /// Wraps a handle the adapter issued.
    pub fn new(id: String) -> SnapshotId {
        SnapshotId(id)
    }

    /// The handle as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One run's own copy of a snapshot, for example a database created from
/// the snapshot as a template. Opaque; the adapter issues it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DatabaseCopy(String);

impl DatabaseCopy {
    /// Wraps a handle the adapter issued.
    pub fn new(name: String) -> DatabaseCopy {
        DatabaseCopy(name)
    }

    /// The handle as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why the data adapter did not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataError {
    /// No snapshot with this handle was loaded.
    UnknownSnapshot,
    /// No copy with this handle exists: never made, or removed.
    UnknownCopy,
    /// Loading, copying or removing failed.
    Failed {
        /// What went wrong, as the adapter reports it.
        detail: String,
    },
}

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataError::UnknownSnapshot => f.write_str("unknown snapshot"),
            DataError::UnknownCopy => f.write_str("unknown database copy"),
            DataError::Failed { detail } => write!(f, "the data snapshot failed: {detail}"),
        }
    }
}

impl core::error::Error for DataError {}

/// Snapshots of the application's data and the runs' copies of them. A
/// change in one copy is never visible in another copy or in the snapshot.
pub trait DataSnapshot {
    /// Loads the source into the database of the sandbox's pod, as a
    /// snapshot that copies are made from.
    fn load(&self, sandbox: &SandboxId, source: &SnapshotSource) -> Result<SnapshotId, DataError>;

    /// Makes a run's own copy of the snapshot.
    fn copy(&self, snapshot: &SnapshotId, run: &RunId) -> Result<DatabaseCopy, DataError>;

    /// Removes a copy; its handle is unknown from then on.
    fn remove_copy(&self, copy: &DatabaseCopy) -> Result<(), DataError>;
}
