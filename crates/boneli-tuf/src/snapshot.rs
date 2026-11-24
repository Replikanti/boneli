//! A snapshot document (TUF 5.5, ADR-033 item 2): its header, the version
//! of every entry of `meta` (each one decides a rollback check, 5.5.5),
//! and the whole `targets.json` entry, the only file this client fetches
//! from it. Lengths and hashes of other entries are not read: this client
//! never fetches those files.

use std::collections::BTreeMap;

use boneli_json::Value;

use crate::Error;
use crate::envelope::Envelope;
use crate::meta::{self, MetaFile};

/// A parsed snapshot whose signatures the caller checked.
pub(crate) struct Snapshot {
    pub(crate) version: i64,
    pub(crate) expires: u64,
    /// The version of every entry of `meta`, by file name.
    pub(crate) versions: BTreeMap<String, i64>,
    /// What it says about `targets.json`.
    pub(crate) targets: MetaFile,
}

impl Snapshot {
    /// Reads the snapshot from a parsed envelope of role snapshot: `meta`
    /// is an object of objects, each with a version of at least 1, and
    /// holds `targets.json`.
    pub(crate) fn parse(env: &Envelope) -> Result<Snapshot, Error> {
        let entries = env
            .signed
            .get("meta")
            .and_then(Value::as_object)
            .ok_or(Error::Field("meta"))?;
        let mut versions = BTreeMap::new();
        for (name, entry) in entries.iter() {
            let entry = entry.as_object().ok_or(Error::Field("meta"))?;
            versions.insert(name.to_string(), meta::version(entry)?);
        }
        let targets = entries.get("targets.json").ok_or(Error::Field("meta"))?;
        Ok(Snapshot {
            version: env.version,
            expires: env.expires,
            versions,
            targets: meta::parse(targets)?,
        })
    }

    /// Checks that every entry of `self`, the stored snapshot, is still
    /// in `new` with a version at least as high (5.5.5). The error names
    /// no file: entry names are metadata text.
    pub(crate) fn check_successor(&self, new: &Snapshot) -> Result<(), Error> {
        for (name, &trusted) in &self.versions {
            let found = *new.versions.get(name).ok_or(Error::EntryDropped)?;
            if found < trusted {
                return Err(Error::EntryRollback { trusted, found });
            }
        }
        Ok(())
    }
}
