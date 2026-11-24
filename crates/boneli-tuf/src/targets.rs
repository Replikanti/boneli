//! A top-level targets document (TUF 5.6 and 5.7, ADR-033 item 2) and
//! the one lookup this client makes in it. `delegations` is never read: a
//! target that only a delegation lists is not listed (S3).

use boneli_json::{Object, Value};
use boneli_sigstore::MAX_TRUSTED_ROOT_BYTES;

use crate::Error;
use crate::envelope::Envelope;
use crate::meta;

/// A parsed targets document whose signatures the caller checked.
pub(crate) struct Targets {
    pub(crate) version: i64,
    pub(crate) expires: u64,
    /// `targets`; an entry is read only when it is looked up.
    targets: Object,
}

impl Targets {
    /// Reads the document from a parsed envelope of role targets:
    /// `targets` must be an object.
    pub(crate) fn parse(env: Envelope) -> Result<Targets, Error> {
        let Envelope {
            mut signed,
            version,
            expires,
            ..
        } = env;
        let Some(Value::Object(targets)) = signed.remove("targets") else {
            return Err(Error::Field("targets"));
        };
        Ok(Targets {
            version,
            expires,
            targets,
        })
    }

    /// The entry of `name`, compared byte for byte (5.7.1): an object
    /// with `length`, a non-negative integer of at most
    /// `boneli_sigstore::MAX_TRUSTED_ROOT_BYTES`, and `hashes` under the
    /// hash rule. Other members, `custom` among them, are not read.
    pub(crate) fn lookup(&self, name: &str) -> Result<TargetFile, Error> {
        let entry = self.targets.get(name).ok_or(Error::NotListed)?;
        let entry = entry.as_object().ok_or(Error::Field("targets"))?;
        let length = meta::length(entry)?;
        if length > MAX_TRUSTED_ROOT_BYTES as u64 {
            return Err(Error::TargetTooLarge {
                cap: MAX_TRUSTED_ROOT_BYTES,
            });
        }
        let hashes = entry.get("hashes").ok_or(Error::Field("hashes"))?;
        let sha256 = meta::sha256(hashes)?;
        Ok(TargetFile { length, sha256 })
    }
}

/// A target file as the trusted targets list it: its exact length, at
/// most `boneli_sigstore::MAX_TRUSTED_ROOT_BYTES`, and its SHA-256. The
/// file itself is fetched as `targets/<sha256 hex>.<name>` (consistent
/// snapshots, ADR-033 item 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetFile {
    length: u64,
    sha256: [u8; 32],
}

impl TargetFile {
    /// The exact length in bytes. A fetch reads this many bytes and no
    /// more.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// The SHA-256 the file must have.
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Checks fetched `bytes`: the exact length first, then the SHA-256
    /// (5.7.3).
    pub fn verify(&self, bytes: &[u8]) -> Result<(), Error> {
        meta::check_length("target", self.length, bytes)?;
        meta::check_sha256("target", &self.sha256, bytes)
    }
}
