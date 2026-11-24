//! A timestamp document (TUF 5.4, ADR-033 item 2): its header and the
//! `snapshot.json` entry of `meta`. Other entries of `meta` are not read.

use boneli_json::Value;

use crate::Error;
use crate::envelope::Envelope;
use crate::meta::{self, MetaFile};

/// A parsed timestamp whose signatures the caller checked.
pub(crate) struct Timestamp {
    pub(crate) version: i64,
    pub(crate) expires: u64,
    /// What it says about `snapshot.json`.
    pub(crate) snapshot: MetaFile,
}

impl Timestamp {
    /// Reads the timestamp from a parsed envelope of role timestamp.
    pub(crate) fn parse(env: &Envelope) -> Result<Timestamp, Error> {
        let snapshot = env
            .signed
            .get("meta")
            .and_then(Value::as_object)
            .and_then(|m| m.get("snapshot.json"))
            .ok_or(Error::Field("meta"))?;
        Ok(Timestamp {
            version: env.version,
            expires: env.expires,
            snapshot: meta::parse(snapshot)?,
        })
    }
}
