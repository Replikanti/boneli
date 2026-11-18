//! The evidence store (ADR-012, D2, D4 and D6): `evidence/sha256/<hex>`,
//! referenced as `sha256:<hex>`.
//!
//! `get` accepts only that form, checks that the path is a regular file
//! before it opens it, reads at most one byte more than the file's size,
//! and hashes the buffer it returns, so a blob changed on disk after
//! verification is `Corrupted` and never reaches the forge (ADR-004, D9).
//! `put` returns the reference when the existing blob verifies, after it
//! syncs that blob and its directory, and otherwise writes the bytes
//! through a temporary name, syncs them and renames them onto the name,
//! which also repairs a tampered blob: the new bytes hash to the name.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use boneli_app::EvidenceError;
use boneli_domain::EvidenceRef;
use boneli_https::Sha256;

use crate::root::{EVIDENCE, SHA256, sync_dir};
use crate::{FsStore, Regular, hex, open_regular};

/// The prefix of every reference.
const PREFIX: &str = "sha256:";

fn unavailable(detail: String) -> EvidenceError {
    EvidenceError::Unavailable { detail }
}

/// The hex digest of a reference this store issues: `sha256:` and exactly
/// 64 lowercase hex digits, nothing else (D2). Decided on the text alone,
/// before any path is built.
fn digest_of(reference: &str) -> Option<&str> {
    let hex = reference.strip_prefix(PREFIX)?;
    let valid = hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    valid.then_some(hex)
}

fn blob_dir(store: &FsStore) -> PathBuf {
    store.root.join(EVIDENCE).join(SHA256)
}

/// The blob named `hex`, open for reading, and its verified bytes (D6).
fn read_blob(store: &FsStore, hex_digest: &str) -> Result<(File, Vec<u8>), EvidenceError> {
    let path = blob_dir(store).join(hex_digest);
    let label = format!("{EVIDENCE}/{SHA256}/{hex_digest}");
    let (file, meta) = match open_regular(&path, OpenOptions::new().read(true)) {
        Regular::File(file, meta) => (file, meta),
        Regular::Missing => return Err(EvidenceError::NotFound),
        Regular::Other => return Err(EvidenceError::Corrupted),
        Regular::Failed(e) => return Err(unavailable(format!("{label}: {e}"))),
    };
    let len = meta.len();
    let mut content = Vec::new();
    (&file)
        .take(len.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(|e| unavailable(format!("{label}: {e}")))?;
    if u64::try_from(content.len()).ok() != Some(len) {
        return Err(EvidenceError::Corrupted);
    }
    if hex(&Sha256::digest(&content)) != hex_digest {
        return Err(EvidenceError::Corrupted);
    }
    Ok((file, content))
}

pub(crate) fn get(store: &FsStore, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError> {
    let hex_digest = digest_of(reference.as_str()).ok_or(EvidenceError::InvalidReference)?;
    read_blob(store, hex_digest).map(|(_, content)| content)
}

pub(crate) fn put(store: &FsStore, content: &[u8]) -> Result<EvidenceRef, EvidenceError> {
    let hex_digest = hex(&Sha256::digest(content));
    let reference = EvidenceRef::parse(&format!("{PREFIX}{hex_digest}"))
        .map_err(|e| unavailable(format!("reference: {e}")))?;
    let dir = blob_dir(store);
    match read_blob(store, &hex_digest) {
        // The writer that renamed this blob into place may have died
        // before it synced the directory, so the blob is synced again
        // before its reference is acknowledged (D4).
        Ok((file, _)) => {
            let label = format!("{EVIDENCE}/{SHA256}/{hex_digest}");
            file.sync_data()
                .map_err(|e| unavailable(format!("{label}: sync: {e}")))?;
            sync_dir(&dir).map_err(|e| unavailable(format!("{label}: sync the directory: {e}")))?;
            return Ok(reference);
        }
        Err(EvidenceError::NotFound | EvidenceError::Corrupted) => {}
        Err(e) => return Err(e),
    }
    let temp = store.temp_path(&dir);
    let result = write_blob(&temp, &dir.join(&hex_digest), &dir, &hex_digest, content);
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map(|()| reference)
}

/// Writes `content` to `temp`, syncs it, renames it onto `path` and syncs
/// the directory.
fn write_blob(
    temp: &Path,
    path: &Path,
    dir: &Path,
    hex_digest: &str,
    content: &[u8],
) -> Result<(), EvidenceError> {
    let label = format!("{EVIDENCE}/{SHA256}/{hex_digest}");
    let io = |what: &str, e: io::Error| unavailable(format!("{label}: {what}: {e}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)
        .map_err(|e| io("create", e))?;
    file.write_all(content).map_err(|e| io("write", e))?;
    file.sync_data().map_err(|e| io("sync", e))?;
    fs::rename(temp, path).map_err(|e| io("rename", e))?;
    sync_dir(dir).map_err(|e| io("sync the directory", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_of_accepts_exactly_the_issued_form() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(digest_of(&format!("sha256:{hex}")), Some(hex));
        for bad in [
            format!("sha256:{}", hex.to_uppercase()),
            format!("sha256:{}", &hex[..63]),
            format!("sha256:{hex}a"),
            format!("SHA256:{hex}"),
            format!("sha256-{hex}"),
            format!(" sha256:{hex}"),
            format!("sha256:{hex}\n"),
            hex.to_owned(),
            String::from("sha256:"),
        ] {
            assert_eq!(digest_of(&bad), None, "{bad:?}");
        }
    }
}
