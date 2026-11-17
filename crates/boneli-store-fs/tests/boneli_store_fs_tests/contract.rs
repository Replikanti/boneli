//! The `EventStore` and `Evidence` contract suites (ADR-004, D2) on the file
//! store, a fresh store on its own root per clause.

use boneli_app::contract;
use boneli_app::{Evidence, EvidenceError};
use boneli_domain::EvidenceRef;

use crate::support::{Fresh, blob_path, snapshot};

#[test]
fn event_store_passes_contract() {
    assert_eq!(
        contract::event_store::run(|| Fresh::new("contract-events")),
        Ok(())
    );
}

/// Overwrites the stored blob, and nothing else, behind the store's back
/// with bytes of the same length, the way another process with the
/// runner's uid could (ADR-004, D9).
fn tamper(store: &Fresh, reference: &EvidenceRef, content: &[u8]) {
    std::fs::write(blob_path(store.store.root(), reference), content).expect("tamper");
}

#[test]
fn evidence_passes_contract() {
    assert_eq!(
        contract::evidence::run(|| Fresh::new("contract-evidence"), tamper),
        Ok(())
    );
}

/// The reviewer's check of the hook (ADR-004, D9), made mechanical: the
/// hook changes the bytes of the blob's file and of no other file under
/// the root, and the store then reports `Corrupted`.
#[test]
fn tamper_hook_writes_only_the_blob() {
    let fresh = Fresh::new("tamper-hook");
    let reference = fresh.put(b"original").expect("put");
    let other = fresh.put(b"another blob").expect("put");
    let root = fresh.store.root().to_path_buf();
    let blob = blob_path(&root, &reference);
    let mut before = snapshot(&root);
    // Directory timestamps move with any entry change, so a rename or a
    // new file next to the blob shows up here too.
    std::thread::sleep(std::time::Duration::from_millis(20));
    tamper(&fresh, &reference, b"tampered");
    let mut after = snapshot(&root);
    let changed = after.remove(&blob).expect("the blob is still there");
    let original = before.remove(&blob).expect("the blob was there");
    assert_eq!(original.0.as_deref(), Some(&b"original"[..]));
    assert_eq!(changed.0.as_deref(), Some(&b"tampered"[..]));
    assert_eq!(before, after, "the hook touched more than the blob");
    assert_eq!(fresh.get(&reference), Err(EvidenceError::Corrupted));
    assert_eq!(fresh.get(&other).as_deref(), Ok(&b"another blob"[..]));
}
