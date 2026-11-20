//! Lock files (ADR-025, D3): `flock` locks through std's `File::lock*`,
//! on regular files under `<root>/locks/`.
//!
//! - `locks/owners/<token>`: a process that writes into the root holds a
//!   shared lock on its owner lock file for as long as its cache lives
//!   (D1). A judge that takes the exclusive lock knows the owner is gone,
//!   in every PID and time namespace and across reboots.
//! - `locks/sha256/<hex>`: every user of the layer `<hex>`, a pull or a
//!   sandbox's lease, holds a shared lock on it (D2); only a holder of the
//!   exclusive lock may remove the layer.
//!
//! The protocol: open (creating the file `0o600` where it is missing),
//! lock, then check that the open file is still the one the path names
//! (`dev`/`ino`). A mismatch means an exclusive holder unlinked the file
//! in the meantime, and the caller tries again, at most [`LOCK_ATTEMPTS`]
//! times. Only an exclusive holder ever unlinks a lock file. A path that
//! is not a regular file is an error, never followed. Shared lockers block;
//! exclusive lockers only ever try, so no lock cycle can form. Every file
//! is opened by std, with `O_CLOEXEC`, so no sandbox inherits a lock.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::error::Error;

/// How many times a lock is tried before [`Error::LockChanged`]. A hang
/// bound, not a target: each retry needs an exclusive holder to unlink
/// this very file between our open and our lock (D3).
pub(crate) const LOCK_ATTEMPTS: u32 = 1_024;

/// A lock held on a lock file; dropping it closes the file and releases
/// the lock.
#[derive(Debug)]
pub(crate) struct Held {
    file: File,
    path: PathBuf,
}

impl Held {
    /// The lock file.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Unlinks the lock file while the lock is still held, then releases
    /// it. Only an exclusive holder calls this (D3): a shared locker that
    /// opened the file before the unlink sees the mismatch once it gets
    /// the lock, and tries again on a new file.
    pub(crate) fn remove(self) -> Result<(), Error> {
        let result = match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(lock_err(&self.path, e)),
        };
        drop(self.file);
        result
    }
}

/// What an exclusive try on an existing lock file found.
#[derive(Debug)]
pub(crate) enum Exclusive {
    /// The exclusive lock, on the file the path names.
    Held(Held),
    /// Someone holds a lock on it.
    Busy,
    /// There is no lock file.
    Missing,
}

/// Takes a shared lock on `path`, creating the file where it is missing,
/// and waits while an exclusive holder has it.
pub(crate) fn lock_shared(path: &Path) -> Result<Held, Error> {
    match acquire(path, Mode::Shared, Create::Yes, &mut |_, _| {})? {
        Exclusive::Held(held) => Ok(held),
        // `Mode::Shared` waits and `Create::Yes` creates, so neither
        // answer comes back; kept total rather than unreachable.
        Exclusive::Busy | Exclusive::Missing => Err(Error::LockChanged(path.to_path_buf())),
    }
}

/// Tries the exclusive lock on the lock file at `path` without creating
/// one and without waiting.
pub(crate) fn try_exclusive_existing(path: &Path) -> Result<Exclusive, Error> {
    acquire(path, Mode::TryExclusive, Create::No, &mut |_, _| {})
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Shared,
    TryExclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Create {
    Yes,
    No,
}

fn lock_err(path: &Path, source: io::Error) -> Error {
    Error::Cache {
        path: path.to_path_buf(),
        source,
    }
}

fn not_regular(path: &Path) -> Error {
    lock_err(
        path,
        io::Error::new(
            io::ErrorKind::InvalidData,
            "a lock file must be a regular file",
        ),
    )
}

/// What opening a lock file gave.
enum Opened {
    File(File),
    /// The file went or came between the check and the open: try again.
    Raced,
    /// No lock file, and none is to be created.
    Missing,
}

/// Opens the lock file at `path` without following a symlink into it: the
/// path is checked first, an existing regular file is opened, and a
/// missing one is created with `O_CREAT | O_EXCL`, which never follows a
/// symlink. A swap between the check and the open is caught by the inode
/// check in [`acquire`]. Opened read-write: `O_RDWR` never blocks, not
/// even on a FIFO swapped in, and the file's type is checked once it is
/// open.
fn open(path: &Path, create: Create) -> Result<Opened, Error> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(file) => Ok(Opened::File(file)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(match create {
                    Create::Yes => Opened::Raced,
                    Create::No => Opened::Missing,
                }),
                Err(e) => Err(lock_err(path, e)),
            }
        }
        Ok(_) => Err(not_regular(path)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => match create {
            Create::No => Ok(Opened::Missing),
            Create::Yes => match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(file) => Ok(Opened::File(file)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(Opened::Raced),
                Err(e) => Err(lock_err(path, e)),
            },
        },
        Err(e) => Err(lock_err(path, e)),
    }
}

/// The protocol of D3. `between(attempt, path)` runs after the open and
/// before the lock: a no-op in production, the seam a test replaces the
/// file through.
fn acquire(
    path: &Path,
    mode: Mode,
    create: Create,
    between: &mut dyn FnMut(u32, &Path),
) -> Result<Exclusive, Error> {
    for attempt in 0..LOCK_ATTEMPTS {
        let file = match open(path, create)? {
            Opened::File(file) => file,
            Opened::Raced => continue,
            Opened::Missing => return Ok(Exclusive::Missing),
        };
        between(attempt, path);
        let opened = file.metadata().map_err(|e| lock_err(path, e))?;
        if !opened.file_type().is_file() {
            return Err(not_regular(path));
        }
        match mode {
            Mode::Shared => file.lock_shared().map_err(|e| lock_err(path, e))?,
            Mode::TryExclusive => match file.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => return Ok(Exclusive::Busy),
                Err(TryLockError::Error(e)) => return Err(lock_err(path, e)),
            },
        }
        match fs::symlink_metadata(path) {
            Ok(now) if now.dev() == opened.dev() && now.ino() == opened.ino() => {
                return Ok(Exclusive::Held(Held {
                    file,
                    path: path.to_path_buf(),
                }));
            }
            // Replaced or unlinked by an exclusive holder (or a symlink
            // planted, which the next attempt refuses).
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(lock_err(path, e)),
        }
    }
    Err(Error::LockChanged(path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use std::fs::{File, TryLockError};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    use super::{Create, Exclusive, LOCK_ATTEMPTS, Mode, acquire, lock_shared};
    use crate::error::Error;
    use crate::scratch::ScratchDir;

    fn is_held(path: &Path) -> bool {
        match File::open(path).expect("open").try_lock() {
            Ok(()) => false,
            Err(TryLockError::WouldBlock) => true,
            Err(TryLockError::Error(e)) => panic!("{e}"),
        }
    }

    /// Replaces the lock file at `path` by a new one, as an exclusive
    /// holder that unlinked it and a new locker that created it again
    /// would.
    fn replace(path: &Path) {
        std::fs::remove_file(path).expect("unlink");
        std::fs::write(path, b"").expect("re-create");
    }

    /// The lock path is unlinked and created again between our open and
    /// our lock: the inode check fails, the caller tries again and ends
    /// holding the file the path names, for a shared and an exclusive
    /// lock. A path replaced on every attempt gives up after
    /// `LOCK_ATTEMPTS` with `LockChanged`.
    #[test]
    fn lock_retries_when_path_was_replaced() {
        let scratch = ScratchDir::new("lock-replaced");
        let path = scratch.path().join("lock");
        for (mode, create) in [
            (Mode::Shared, Create::Yes),
            (Mode::TryExclusive, Create::No),
        ] {
            std::fs::write(&path, b"").expect("lock file");
            let mut attempts = Vec::new();
            let got = acquire(&path, mode, create, &mut |attempt, p| {
                attempts.push(attempt);
                if attempt == 0 {
                    replace(p);
                }
            })
            .expect("acquired");
            let held = match got {
                Exclusive::Held(held) => held,
                other => panic!("{mode:?}: {other:?}"),
            };
            assert_eq!(attempts, [0, 1], "{mode:?}");
            let opened = held.file.metadata().expect("fstat");
            let now = std::fs::metadata(&path).expect("stat");
            assert_eq!((opened.dev(), opened.ino()), (now.dev(), now.ino()));
            assert!(is_held(&path), "{mode:?}: the lock is on the named file");
            drop(held);
            assert!(!is_held(&path));
        }
        let mut attempts = 0;
        match acquire(&path, Mode::Shared, Create::Yes, &mut |_, p| {
            attempts += 1;
            replace(p);
        }) {
            Err(Error::LockChanged(p)) => assert_eq!(p, path),
            other => panic!("replaced on every attempt: {other:?}"),
        }
        assert_eq!(attempts, LOCK_ATTEMPTS);
    }

    /// A symlink (to a file, or dangling), a directory or a FIFO at a lock
    /// path is an error that names the path, for every kind of lock; a
    /// symlink is never followed: its target is neither created nor
    /// locked.
    #[test]
    fn non_regular_lock_path_refused() {
        let scratch = ScratchDir::new("lock-non-regular");
        let dir = scratch.path();
        let target = dir.join("target");
        std::fs::write(&target, b"untouched").expect("target");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).expect("symlink");
        let subdir = dir.join("dir");
        std::fs::create_dir(&subdir).expect("dir");
        let fifo = dir.join("fifo");
        boneli_sys::make_fifo(&fifo, 0o600).expect("fifo");
        for path in [&link, &dangling, &subdir, &fifo] {
            for (mode, create) in [
                (Mode::Shared, Create::Yes),
                (Mode::TryExclusive, Create::No),
                (Mode::TryExclusive, Create::Yes),
            ] {
                match acquire(path, mode, create, &mut |_, _| {}) {
                    Err(Error::Cache { path: p, source }) => {
                        assert_eq!(&p, path);
                        assert!(source.to_string().contains("regular file"), "{source}");
                    }
                    other => panic!("{}: {mode:?} gave {other:?}", path.display()),
                }
            }
        }
        assert_eq!(std::fs::read(&target).expect("target"), b"untouched");
        assert!(!is_held(&target), "the symlink's target was locked");
        assert!(
            !dir.join("nowhere").exists(),
            "a dangling target was created"
        );
        assert!(subdir.is_dir(), "the directory was touched");
    }

    /// A shared lock creates a missing file `0o600`; an exclusive try on
    /// an existing file is `Busy` while it is held, through another open
    /// file description of this process too, and `Held` once it is not;
    /// on a missing file it is `Missing` and creates nothing. `remove`
    /// unlinks the file while holding it.
    #[test]
    fn shared_and_exclusive() {
        let scratch = ScratchDir::new("lock-modes");
        let path = scratch.path().join("lock");
        let missing = scratch.path().join("missing");
        assert!(matches!(
            super::try_exclusive_existing(&missing),
            Ok(Exclusive::Missing)
        ));
        assert!(!missing.exists());
        let shared = lock_shared(&path).expect("shared");
        assert_eq!(
            std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
            0o600
        );
        let again = lock_shared(&path).expect("a second shared lock");
        assert!(matches!(
            super::try_exclusive_existing(&path),
            Ok(Exclusive::Busy)
        ));
        drop(shared);
        assert!(matches!(
            super::try_exclusive_existing(&path),
            Ok(Exclusive::Busy)
        ));
        drop(again);
        let Ok(Exclusive::Held(held)) = super::try_exclusive_existing(&path) else {
            panic!("free, so held");
        };
        assert_eq!(held.path(), path);
        held.remove().expect("remove");
        assert!(!path.exists());
    }
}
