//! [`MemoryEvidence`]: the `Evidence` port in memory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use boneli_app::{Evidence, EvidenceError};
use boneli_domain::EvidenceRef;

use crate::lock;

/// The reference of some bytes: `fnv1a64-` and the 64-bit FNV-1a digest in
/// hex. A function of the bytes alone, so `get` can re-derive it.
///
/// FNV-1a is not cryptographic, and it need not be here (ADR-004, D9): this
/// store's memory belongs to the process, so no other writer can forge a
/// collision. A store whose bytes another process can write (#4) must use a
/// cryptographic digest from a vetted crate.
fn reference_of(content: &[u8]) -> String {
    // The 64-bit FNV offset basis and prime.
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in content {
        digest ^= u64::from(*byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a64-{digest:016x}")
}

/// An `Evidence` store whose references are derived from the content.
/// `get` re-derives the reference from the bytes it holds and returns
/// `Corrupted` on a mismatch. Two different blobs with the same digest are
/// refused on `put`, so a collision fails closed instead of aliasing.
#[derive(Debug, Default)]
pub struct MemoryEvidence {
    blobs: Mutex<BTreeMap<EvidenceRef, Vec<u8>>>,
}

impl MemoryEvidence {
    /// An empty store.
    pub fn new() -> MemoryEvidence {
        MemoryEvidence::default()
    }
}

impl Evidence for MemoryEvidence {
    fn put(&self, content: &[u8]) -> Result<EvidenceRef, EvidenceError> {
        let reference = EvidenceRef::parse(&reference_of(content)).map_err(|error| {
            EvidenceError::Unavailable {
                detail: error.to_string(),
            }
        })?;
        let mut blobs = lock(&self.blobs);
        match blobs.get(&reference) {
            Some(stored) if stored != content => Err(EvidenceError::Unavailable {
                detail: format!("digest collision on {}", reference.as_str()),
            }),
            Some(_) => Ok(reference),
            None => {
                blobs.insert(reference.clone(), content.to_vec());
                Ok(reference)
            }
        }
    }

    fn get(&self, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError> {
        let blobs = lock(&self.blobs);
        let content = blobs.get(reference).ok_or(EvidenceError::NotFound)?;
        if reference_of(content) != reference.as_str() {
            return Err(EvidenceError::Corrupted);
        }
        Ok(content.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boneli_app::contract;

    /// Overwrites the stored blob only, as another writer of a file store's
    /// directory would. Test-only, so the shipped build has no way to write
    /// behind the store (ADR-004, D9).
    fn tamper(store: &MemoryEvidence, reference: &EvidenceRef, content: &[u8]) {
        if let Some(stored) = lock(&store.blobs).get_mut(reference) {
            *stored = content.to_vec();
        }
    }

    #[test]
    fn in_memory_evidence_passes_contract() {
        assert_eq!(contract::evidence::run(MemoryEvidence::new, tamper), Ok(()));
    }

    #[test]
    fn references_are_content_digests() {
        // The FNV-1a test vectors for "" and "a".
        assert_eq!(reference_of(b""), "fnv1a64-cbf29ce484222325");
        assert_eq!(reference_of(b"a"), "fnv1a64-af63dc4c8601ec8c");
        let store = MemoryEvidence::new();
        let reference = store.put(b"diff").expect("stored");
        assert_eq!(reference.as_str(), reference_of(b"diff"));
    }

    #[test]
    fn a_digest_collision_is_refused() {
        let store = MemoryEvidence::new();
        let reference = store.put(b"one").expect("stored");
        // Plant other bytes under the same reference, as a collision would.
        tamper(&store, &reference, b"two");
        let refused = store.put(b"one");
        assert!(
            matches!(refused, Err(EvidenceError::Unavailable { .. })),
            "{refused:?}"
        );
        assert_eq!(store.get(&reference), Err(EvidenceError::Corrupted));
    }
}
