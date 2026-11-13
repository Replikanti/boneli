//! [`MemoryEvidence`]: the `Evidence` port in memory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use boneli_app::{Evidence, EvidenceError};
use boneli_domain::EvidenceRef;

use crate::lock;

#[derive(Debug, Default)]
struct State {
    by_content: BTreeMap<Vec<u8>, EvidenceRef>,
    by_reference: BTreeMap<EvidenceRef, Vec<u8>>,
    /// The number of the next reference, starting at 1.
    next: u64,
}

/// An `Evidence` store that issues `blob-<n>` from a counter starting at 1;
/// the same bytes get the same reference.
#[derive(Debug)]
pub struct MemoryEvidence {
    state: Mutex<State>,
}

impl Default for MemoryEvidence {
    fn default() -> MemoryEvidence {
        MemoryEvidence::new()
    }
}

impl MemoryEvidence {
    /// An empty store.
    pub fn new() -> MemoryEvidence {
        MemoryEvidence {
            state: Mutex::new(State {
                next: 1,
                ..State::default()
            }),
        }
    }
}

impl Evidence for MemoryEvidence {
    fn put(&self, content: &[u8]) -> Result<EvidenceRef, EvidenceError> {
        let mut state = lock(&self.state);
        if let Some(reference) = state.by_content.get(content) {
            return Ok(reference.clone());
        }
        let n = state.next;
        let reference = EvidenceRef::parse(&format!("blob-{n}")).map_err(|error| {
            EvidenceError::Unavailable {
                detail: error.to_string(),
            }
        })?;
        state.next = n.saturating_add(1);
        state.by_content.insert(content.to_vec(), reference.clone());
        state
            .by_reference
            .insert(reference.clone(), content.to_vec());
        Ok(reference)
    }

    fn get(&self, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError> {
        lock(&self.state)
            .by_reference
            .get(reference)
            .cloned()
            .ok_or(EvidenceError::NotFound)
    }
}
