//! The store root (ADR-012, D1): the lock, the sweep of temporary files and
//! directory syncs. The root rules, shared with `boneli-oci`, live in
//! `boneli-private-dir` (ADR-021).

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::OpenError;

/// The prefix of every temporary name the store makes. `open` removes
/// every file in `runs/` and `evidence/sha256/` that starts with it.
pub(crate) const TEMP_PREFIX: &str = ".tmp-";

/// The run logs, under the root.
pub(crate) const RUNS: &str = "runs";

/// The blobs, under the root.
pub(crate) const EVIDENCE: &str = "evidence";

/// The blobs' digest directory, under [`EVIDENCE`].
pub(crate) const SHA256: &str = "sha256";

/// The lock file, under the root.
const LOCK: &str = "lock";

fn io_err(path: &Path, source: io::Error) -> OpenError {
    OpenError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The shared root rules' errors as this crate's: a broken rule is
/// `Root`, a filesystem failure `Io`. A private mapping, so
/// `boneli-private-dir` stays out of this adapter's public API (ADR-021,
/// D5).
fn root_err(e: boneli_private_dir::Error) -> OpenError {
    match e {
        boneli_private_dir::Error::Rule { path, reason } => OpenError::Root { path, reason },
        boneli_private_dir::Error::Io { path, source } => OpenError::Io { path, source },
    }
}

/// `fsync` of a directory, so the entries created or renamed in it are
/// durable.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Removes every file in `dir` whose name starts with [`TEMP_PREFIX`]. A
/// name whose removal fails stays, whatever the error: it is a dot name,
/// never read as a log or a blob, so it costs disk, while failing `open`
/// for it would leave the store unopenable until someone removed it by
/// hand. Safe only under the lock: no other store writes here.
fn sweep(dir: &Path) -> Result<(), OpenError> {
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        let name = entry.file_name();
        if name.as_encoded_bytes().starts_with(TEMP_PREFIX.as_bytes()) {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// A directory the store made under the root must be a directory, not a
/// symlink to one somewhere else.
fn check_store_dir(dir: &Path) -> Result<(), OpenError> {
    let meta = fs::symlink_metadata(dir).map_err(|e| io_err(dir, e))?;
    if meta.is_dir() {
        Ok(())
    } else {
        Err(OpenError::Root {
            path: dir.to_path_buf(),
            reason: "a store directory must be a directory, not a symlink",
        })
    }
}

/// Checks the root, takes the lock, prepares the directories and sweeps
/// them; returns the resolved root and the locked file.
pub(crate) fn open(root: &Path) -> Result<(PathBuf, File), OpenError> {
    // No rule of its own on the root's text: no mount option is built
    // from it.
    let resolved = boneli_private_dir::prepare_root(root, &|_| Ok(())).map_err(root_err)?;

    let lock_path = resolved.join(LOCK);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|e| io_err(&lock_path, e))?;
    let lock_meta = lock.metadata().map_err(|e| io_err(&lock_path, e))?;
    if !lock_meta.is_file() {
        return Err(OpenError::Root {
            path: lock_path,
            reason: "the lock must be a regular file",
        });
    }
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Err(OpenError::InUse { path: lock_path }),
        Err(TryLockError::Error(e)) => return Err(io_err(&lock_path, e)),
    }

    let runs = resolved.join(RUNS);
    let evidence = resolved.join(EVIDENCE);
    let blobs = evidence.join(SHA256);
    boneli_private_dir::create(&runs).map_err(root_err)?;
    boneli_private_dir::create(&blobs).map_err(root_err)?;
    for dir in [&runs, &evidence, &blobs] {
        check_store_dir(dir)?;
    }
    sweep(&runs)?;
    sweep(&blobs)?;
    for dir in [&resolved, &runs, &evidence, &blobs] {
        sync_dir(dir).map_err(|e| io_err(dir, e))?;
    }
    Ok((resolved, lock))
}
