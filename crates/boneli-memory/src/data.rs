//! [`MemoryDataSnapshot`]: the `DataSnapshot` port in memory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use boneli_app::{DataError, DataSnapshot, DatabaseCopy, SandboxId, SnapshotId, SnapshotSource};
use boneli_domain::RunId;

use crate::lock;

#[derive(Debug, Default)]
struct State {
    /// The number of the next handle, starting at 1; one counter for
    /// snapshots and copies, never reused.
    next: u64,
    snapshots: BTreeMap<SnapshotId, Vec<String>>,
    copies: BTreeMap<DatabaseCopy, Vec<String>>,
}

impl State {
    fn issue(&mut self) -> u64 {
        let n = self.next;
        self.next = n.saturating_add(1);
        n
    }
}

/// A `DataSnapshot` whose databases are lists of rows. Loading a source
/// gives `snapshot-<n>` with the source's rows; a copy, `copy-<n>`, starts
/// as a clone of its snapshot's rows, so a change in one copy is visible
/// nowhere else. The sandbox is not checked: nothing runs.
#[derive(Debug, Default)]
pub struct MemoryDataSnapshot {
    sources: BTreeMap<SnapshotSource, Vec<String>>,
    state: Mutex<State>,
}

impl MemoryDataSnapshot {
    /// An adapter that can load these sources, each with its rows; a source
    /// outside them fails to load.
    pub fn new(sources: Vec<(SnapshotSource, Vec<String>)>) -> MemoryDataSnapshot {
        MemoryDataSnapshot {
            sources: sources.into_iter().collect(),
            state: Mutex::new(State {
                next: 1,
                ..State::default()
            }),
        }
    }

    /// Adds a row to a copy, as the application under test would write to
    /// its database.
    pub fn insert(&self, copy: &DatabaseCopy, row: &str) -> Result<(), DataError> {
        match lock(&self.state).copies.get_mut(copy) {
            Some(rows) => {
                rows.push(String::from(row));
                Ok(())
            }
            None => Err(DataError::UnknownCopy),
        }
    }

    /// The rows of a copy, in insertion order.
    pub fn rows(&self, copy: &DatabaseCopy) -> Result<Vec<String>, DataError> {
        lock(&self.state)
            .copies
            .get(copy)
            .cloned()
            .ok_or(DataError::UnknownCopy)
    }
}

impl DataSnapshot for MemoryDataSnapshot {
    fn load(&self, _sandbox: &SandboxId, source: &SnapshotSource) -> Result<SnapshotId, DataError> {
        let rows = self
            .sources
            .get(source)
            .cloned()
            .ok_or_else(|| DataError::Failed {
                detail: format!("unknown source {:?}", source.as_str()),
            })?;
        let mut state = lock(&self.state);
        let id = SnapshotId::new(format!("snapshot-{}", state.issue()));
        state.snapshots.insert(id.clone(), rows);
        Ok(id)
    }

    fn copy(&self, snapshot: &SnapshotId, _run: &RunId) -> Result<DatabaseCopy, DataError> {
        let mut state = lock(&self.state);
        let rows = state
            .snapshots
            .get(snapshot)
            .cloned()
            .ok_or(DataError::UnknownSnapshot)?;
        let copy = DatabaseCopy::new(format!("copy-{}", state.issue()));
        state.copies.insert(copy.clone(), rows);
        Ok(copy)
    }

    fn remove_copy(&self, copy: &DatabaseCopy) -> Result<(), DataError> {
        match lock(&self.state).copies.remove(copy) {
            Some(_) => Ok(()),
            None => Err(DataError::UnknownCopy),
        }
    }
}
