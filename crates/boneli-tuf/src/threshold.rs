//! Threshold counting (ADR-033, item 3). A signature counts when its key
//! ID is one of the role's, it is the first entry with that key ID, the
//! key is of the one kind that counts, and it verifies over the canonical
//! bytes. The count is of **distinct SPKI DER**: two key IDs of one key,
//! or one key ID listed twice, count once. Nothing here refuses a
//! document; a signature that does not decode or verify counts zero.

use std::collections::{BTreeMap, BTreeSet};

use crate::envelope::Envelope;
use crate::root::{Key, Role};

/// The number of distinct keys of `role` whose signature in `env`
/// verifies.
pub(crate) fn count(keys: &BTreeMap<String, Key>, role: &Role, env: &Envelope) -> usize {
    let mut checked: BTreeSet<&str> = BTreeSet::new();
    let mut counted: BTreeSet<&[u8]> = BTreeSet::new();
    for signature in &env.signatures {
        let id = signature.keyid.as_str();
        if !role.keyids.iter().any(|k| k == id) || !checked.insert(id) {
            continue;
        }
        let Some(public) = keys.get(id).and_then(|k| k.public.as_ref()) else {
            continue;
        };
        let Some(sig) = &signature.sig else {
            continue;
        };
        if public.verify(&env.canonical, sig).is_ok() {
            counted.insert(public.spki_der());
        }
    }
    counted.len()
}

/// Whether the signatures in `env` reach `role`'s threshold.
pub(crate) fn met(keys: &BTreeMap<String, Key>, role: &Role, env: &Envelope) -> bool {
    count(keys, role, env) as u64 >= role.threshold
}
