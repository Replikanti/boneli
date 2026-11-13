//! [`MemoryEventStore`]: the `EventStore` port in memory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use boneli_app::{EventStore, RunLog, RunStart, StoreError};
use boneli_domain::{RunEvent, RunId};

use crate::lock;

/// An `EventStore` on a `BTreeMap` from run id to log. Any id is held in
/// isolation, so no id is invalid here.
#[derive(Debug, Default)]
pub struct MemoryEventStore {
    logs: Mutex<BTreeMap<RunId, RunLog>>,
}

impl MemoryEventStore {
    /// An empty store.
    pub fn new() -> MemoryEventStore {
        MemoryEventStore::default()
    }

    /// Every log, in `RunId` order.
    pub fn logs(&self) -> Vec<(RunId, RunLog)> {
        lock(&self.logs)
            .iter()
            .map(|(id, log)| (id.clone(), log.clone()))
            .collect()
    }
}

impl EventStore for MemoryEventStore {
    fn create(&self, id: &RunId, start: &RunStart) -> Result<(), StoreError> {
        let mut logs = lock(&self.logs);
        if logs.contains_key(id) {
            return Err(StoreError::AlreadyExists);
        }
        let log = RunLog {
            start: start.clone(),
            events: Vec::new(),
        };
        logs.insert(id.clone(), log);
        Ok(())
    }

    fn append(&self, id: &RunId, event: &RunEvent) -> Result<(), StoreError> {
        match lock(&self.logs).get_mut(id) {
            Some(log) => {
                log.events.push(event.clone());
                Ok(())
            }
            None => Err(StoreError::UnknownRun),
        }
    }

    fn load(&self, id: &RunId) -> Result<RunLog, StoreError> {
        lock(&self.logs)
            .get(id)
            .cloned()
            .ok_or(StoreError::UnknownRun)
    }
}
