//! The store root (ADR-012, D1): the root rules, the lock, the sweep of
//! temporary files and directory syncs.
//!
//! `own_uid`, `private_dir` and `check_ancestors` are copies of the
//! functions of the same names in `boneli-oci`'s `store.rs` (ADR-009, D8),
//! and the tests copy its root matrix. An adapter cannot depend on another
//! adapter, so the rules live in both crates until #66 extracts them; a
//! fix to one copy goes into the other.

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
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

/// The owner of the root and of this process: the uid of `/proc/self`,
/// which is this process's effective uid.
fn own_uid(at: &Path) -> Result<u32, OpenError> {
    let me = Path::new("/proc/self");
    fs::metadata(me).map(|m| m.uid()).map_err(|e| io_err(at, e))
}

/// Creates `dir` with mode `0o700` where it is missing.
fn private_dir(dir: &Path) -> Result<(), OpenError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| io_err(dir, e))
}

/// Checks `dir` and each of its ancestors the way sshd's `StrictModes`
/// checks a path: a directory, owned by root or by `uid`, and not writable
/// by its group or by others unless it is sticky. Anyone who can rename an
/// entry of an ancestor can swap the root after `open` and rewrite the run
/// logs, which have no integrity check of their own (ADR-012, D7); in a
/// sticky directory only an entry's owner can rename it, and the next
/// entry down is root's or the caller's. The filesystem root is checked
/// for its mode only: whoever owns it owns every path on the host, and in
/// a user namespace it shows the overflow uid. `dir` must be resolved, so
/// the walk sees no symlink.
fn check_ancestors(dir: &Path, uid: u32) -> Result<(), OpenError> {
    for at in dir.ancestors() {
        let refuse = |reason| {
            Err(OpenError::Root {
                path: at.to_path_buf(),
                reason,
            })
        };
        let meta = fs::symlink_metadata(at).map_err(|e| io_err(at, e))?;
        if !meta.is_dir() {
            return refuse("an ancestor of the root must be a directory");
        }
        if at.parent().is_some() && meta.uid() != 0 && meta.uid() != uid {
            return refuse("an ancestor of the root must be owned by root or the caller");
        }
        if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
            return refuse(
                "an ancestor of the root must not be writable by its group or others unless it is sticky",
            );
        }
    }
    Ok(())
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
    if !root.is_absolute() {
        return Err(OpenError::Root {
            path: root.to_path_buf(),
            reason: "must be an absolute path",
        });
    }
    let uid = own_uid(root)?;
    if fs::symlink_metadata(root).is_err() {
        // Nothing is created under an ancestor that fails the check.
        if let Some(existing) = root
            .ancestors()
            .skip(1)
            .find(|a| fs::symlink_metadata(a).is_ok())
        {
            let existing = existing.canonicalize().map_err(|e| io_err(existing, e))?;
            check_ancestors(&existing, uid)?;
        }
        private_dir(root)?;
    }
    let resolved = root.canonicalize().map_err(|e| io_err(root, e))?;
    let refuse = |reason| OpenError::Root {
        path: resolved.clone(),
        reason,
    };
    let meta = fs::metadata(&resolved).map_err(|e| io_err(&resolved, e))?;
    if !meta.is_dir() {
        return Err(refuse("must be a directory"));
    }
    if meta.uid() != uid {
        return Err(refuse("must be owned by the caller"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(refuse("must have no group or other permission bits"));
    }
    if let Some(parent) = resolved.parent() {
        check_ancestors(parent, uid)?;
    }

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
    private_dir(&runs)?;
    private_dir(&blobs)?;
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
