//! A root document (TUF 5.2 and 5.3, ADR-033 items 2 and 3): its keys,
//! the four top-level roles with their key IDs and thresholds, and the
//! header fields.

use std::collections::BTreeMap;

use boneli_https::PublicKey;
use boneli_json::{Object, Value};

use crate::canonical::canonical;
use crate::envelope::{Envelope, RoleName, integer};
use crate::{Error, key, threshold};

/// One key of `keys`: the key when it is of the one kind that counts,
/// and its material for the fast-forward signal: the SPKI DER of a
/// counted key, the canonical form of any other entry.
pub(crate) struct Key {
    pub(crate) public: Option<PublicKey>,
    material: Vec<u8>,
}

/// A role of the root: its key IDs, distinct and all present in `keys`,
/// and its threshold, at least 1.
pub(crate) struct Role {
    pub(crate) keyids: Vec<String>,
    pub(crate) threshold: u64,
}

/// A parsed root whose own threshold has not necessarily been checked;
/// the [`TrustedSet`](crate::TrustedSet) only ever holds verified ones.
pub struct Root {
    version: i64,
    expires: u64,
    consistent_snapshot: bool,
    keys: BTreeMap<String, Key>,
    roles: [Role; 4],
}

impl Root {
    /// The root's `version`, at least 1.
    pub fn version(&self) -> i64 {
        self.version
    }

    /// The root's `expires`, in seconds since the Unix epoch.
    pub fn expires(&self) -> u64 {
        self.expires
    }

    /// Whether the repository publishes consistent snapshots
    /// (`N.snapshot.json`, `<hash>.<name>` targets). The refresh refuses a
    /// repository without them (ADR-033, item 2).
    pub fn consistent_snapshot(&self) -> bool {
        self.consistent_snapshot
    }

    /// Reads the root from a parsed envelope of role root.
    pub(crate) fn parse(env: &Envelope) -> Result<Root, Error> {
        let signed = &env.signed;
        let consistent_snapshot = signed
            .get("consistent_snapshot")
            .and_then(Value::as_bool)
            .ok_or(Error::Field("consistent_snapshot"))?;
        let keys = signed
            .get("keys")
            .and_then(Value::as_object)
            .ok_or(Error::Field("keys"))?;
        let keys = keys
            .iter()
            .map(|(id, entry)| {
                let public = key::public_key(entry);
                let material = match &public {
                    Some(k) => k.spki_der().to_vec(),
                    None => canonical(entry)?,
                };
                Ok((id.to_string(), Key { public, material }))
            })
            .collect::<Result<BTreeMap<_, _>, Error>>()?;
        let roles = signed
            .get("roles")
            .and_then(Value::as_object)
            .ok_or(Error::Field("roles"))?;
        let [root, timestamp, snapshot, targets] =
            RoleName::ALL.map(|name| role(roles, name, &keys));
        Ok(Root {
            version: env.version,
            expires: env.expires,
            consistent_snapshot,
            keys,
            roles: [root?, timestamp?, snapshot?, targets?],
        })
    }

    pub(crate) fn role(&self, name: RoleName) -> &Role {
        &self.roles[name as usize]
    }

    /// Whether `env`'s signatures reach the threshold of role `name` as
    /// this root defines it.
    pub(crate) fn verifies(&self, name: RoleName, env: &Envelope) -> bool {
        threshold::met(&self.keys, self.role(name), env)
    }

    /// What the fast-forward signal compares for role `name`: the
    /// threshold and the sorted, distinct material of its keys. Key IDs
    /// are labels, so renaming a key is no change and another key behind
    /// the same key ID is one.
    pub(crate) fn key_material(&self, name: RoleName) -> (u64, Vec<&[u8]>) {
        let role = self.role(name);
        let mut material: Vec<&[u8]> = role
            .keyids
            .iter()
            .filter_map(|id| self.keys.get(id))
            .map(|k| k.material.as_slice())
            .collect();
        material.sort_unstable();
        material.dedup();
        (role.threshold, material)
    }
}

/// Reads role `name` of `roles`. Duplicate key IDs, a key ID `keys` does
/// not hold and a threshold below 1 refuse the root; a threshold above
/// the number of keys refuses only by never being met.
fn role(roles: &Object, name: RoleName, keys: &BTreeMap<String, Key>) -> Result<Role, Error> {
    let role = roles
        .get(name.name())
        .and_then(Value::as_object)
        .ok_or(Error::Field("roles"))?;
    let ids = role
        .get("keyids")
        .and_then(Value::as_array)
        .ok_or(Error::Field("keyids"))?;
    let mut keyids: Vec<String> = Vec::with_capacity(ids.len());
    for id in ids {
        let id = id.as_str().ok_or(Error::Field("keyids"))?;
        if keyids.iter().any(|k| k == id) {
            return Err(Error::DuplicateKeyId { role: name.name() });
        }
        if !keys.contains_key(id) {
            return Err(Error::UnknownKeyId { role: name.name() });
        }
        keyids.push(id.to_string());
    }
    let threshold = integer(role, "threshold")?;
    let threshold = u64::try_from(threshold)
        .ok()
        .filter(|t| *t >= 1)
        .ok_or(Error::InvalidThreshold { role: name.name() })?;
    Ok(Role { keyids, threshold })
}
