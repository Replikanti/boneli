//! A `meta` entry (TUF 5.4 and 5.5, ADR-033 item 2): the version a
//! timestamp names for `snapshot.json` or a snapshot names for
//! `targets.json`, and, when listed, its length and SHA-256.
//!
//! The hash rule, shared with target entries: a hash map is an object
//! that holds `sha256` as 64 lower-case hex characters, the form every
//! Sigstore file uses and the one securesystemslib writes; other
//! algorithms are not read. A map without `sha256` is refused rather than
//! skipped, because the repository asked for a check this client cannot
//! make.

use boneli_https::Sha256;
use boneli_json::{Object, Value};

use crate::Error;
use crate::envelope::integer;

/// What referring metadata says about one metadata file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaFile {
    version: i64,
    length: Option<u64>,
    sha256: Option<[u8; 32]>,
}

impl MetaFile {
    /// The version the file must have, at least 1.
    pub fn version(&self) -> i64 {
        self.version
    }

    /// The file's exact length in bytes, when listed.
    pub fn length(&self) -> Option<u64> {
        self.length
    }

    /// The file's SHA-256, when listed.
    pub fn sha256(&self) -> Option<&[u8; 32]> {
        self.sha256.as_ref()
    }

    /// Checks `bytes` against the listed length and SHA-256, in that
    /// order, before they are parsed (5.5.2, 5.6.2). `role` names the file
    /// in the error.
    pub(crate) fn verify(&self, role: &'static str, bytes: &[u8]) -> Result<(), Error> {
        if let Some(length) = self.length {
            check_length(role, length, bytes)?;
        }
        if let Some(sha256) = &self.sha256 {
            check_sha256(role, sha256, bytes)?;
        }
        Ok(())
    }
}

/// Reads a `meta` entry: an object with `version` at least 1, `length`
/// a non-negative integer when present, `hashes` under the hash rule
/// when present. Other members are not read.
pub(crate) fn parse(entry: &Value) -> Result<MetaFile, Error> {
    let entry = entry.as_object().ok_or(Error::Field("meta"))?;
    let version = version(entry)?;
    let length = match entry.get("length") {
        None => None,
        Some(_) => Some(length(entry)?),
    };
    let sha256 = match entry.get("hashes") {
        None => None,
        Some(hashes) => Some(sha256(hashes)?),
    };
    Ok(MetaFile {
        version,
        length,
        sha256,
    })
}

/// The `version` of an entry, at least 1.
pub(crate) fn version(entry: &Object) -> Result<i64, Error> {
    let version = integer(entry, "version")?;
    if version < 1 {
        return Err(Error::Field("version"));
    }
    Ok(version)
}

/// The `length` of an entry: a non-negative integer.
pub(crate) fn length(entry: &Object) -> Result<u64, Error> {
    let length = integer(entry, "length")?;
    u64::try_from(length).map_err(|_| Error::Field("length"))
}

/// The SHA-256 of a hash map under the hash rule.
pub(crate) fn sha256(hashes: &Value) -> Result<[u8; 32], Error> {
    let hashes = hashes.as_object().ok_or(Error::Field("hashes"))?;
    let text = hashes.get("sha256").ok_or(Error::NoSha256)?;
    let text = text.as_str().ok_or(Error::Field("hashes"))?;
    decode_sha256(text).ok_or(Error::Field("hashes"))
}

/// 64 lower-case hex characters, or `None`.
fn decode_sha256(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (slot, [hi, lo]) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *slot = nibble(*hi)? << 4 | nibble(*lo)?;
    }
    Some(out)
}

/// `bytes` is exactly `expected` bytes long.
pub(crate) fn check_length(role: &'static str, expected: u64, bytes: &[u8]) -> Result<(), Error> {
    let found = bytes.len() as u64;
    if found != expected {
        return Err(Error::LengthMismatch {
            role,
            expected,
            found,
        });
    }
    Ok(())
}

/// `bytes` hashes to `expected`.
pub(crate) fn check_sha256(
    role: &'static str,
    expected: &[u8; 32],
    bytes: &[u8],
) -> Result<(), Error> {
    if Sha256::digest(bytes) != *expected {
        return Err(Error::HashMismatch { role });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_forms() {
        let lower = "00ff".repeat(16);
        let mut want = [0u8; 32];
        for pair in want.chunks_mut(2) {
            pair[1] = 0xff;
        }
        assert_eq!(decode_sha256(&lower), Some(want));
        assert_eq!(decode_sha256(&"00FF".repeat(16)), None);
        assert_eq!(decode_sha256(&"0".repeat(63)), None);
        assert_eq!(decode_sha256(&"0".repeat(65)), None);
        assert_eq!(decode_sha256(&format!("{}g0", "0".repeat(62))), None);
        assert_eq!(decode_sha256(&format!("{}+1", "0".repeat(62))), None);
        assert_eq!(decode_sha256(""), None);
    }
}
