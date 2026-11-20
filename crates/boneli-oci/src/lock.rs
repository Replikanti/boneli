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
//! is not a regular file is an error, never followed. Shared lockers wait
//! up to a deadline ([`LOCK_WAIT`]); exclusive lockers only ever try, so no
//! lock cycle can form. Every file is opened by std, with `O_CLOEXEC`, so
//! no sandbox inherits a lock by accident; a lease hands out descriptors
//! for that on purpose ([`crate::Lease::pin_descriptors`]).

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::Error;

/// How many times a lock is tried before [`Error::LockChanged`]. A hang
/// bound, not a target: each retry needs an exclusive holder to unlink
/// this very file between our open and our lock (D3).
pub(crate) const LOCK_ATTEMPTS: u32 = 1_024;

/// How long a shared locker waits for an exclusive holder before it gives
/// up with [`Error::LockBusy`] (ADR-025, D3). An exclusive holder holds a
/// lock while it removes what the lock covers: a dead owner's names, or
/// (#56 part 2) one layer's tree. The largest tree is one layer at the
/// image's entry cap, 1,048,576 entries; ADR-009 D8 measured the removal at
/// 80,000 directories in 2.6 s (about 32.5 µs each, release build, btrfs),
/// so about 34 s for the cap (extrapolated, not measured). 120 s leaves
/// 3.5 times that for slower disks and debug builds. Shorter fails a pull
/// while a legitimate removal still runs; longer lets a stopped holder
/// stall a pull, and every pull queued behind it on the store's mutex,
/// for longer.
pub(crate) const LOCK_WAIT: Duration = Duration::from_secs(120);

/// The first pause of a waiting shared locker; it doubles up to
/// [`POLL_MAX`].
const POLL_MIN: Duration = Duration::from_millis(1);

/// The longest pause of a waiting shared locker: at most 100 ms between a
/// holder's release and the waiter's lock, against a pull that takes
/// seconds, and about 1,200 wake-ups over a whole [`LOCK_WAIT`].
const POLL_MAX: Duration = Duration::from_millis(100);

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

    /// A new open file description of this lock file, read-only, with its
    /// own shared lock: it keeps the lock as long as any process holds a
    /// descriptor of it, whatever happens to `self`, and its own release
    /// (`close`, `LOCK_UN`) never releases `self`'s (ADR-025, D2). The
    /// descriptor carries `O_CLOEXEC`; the caller clears it where it hands
    /// the descriptor on. Opened only once the path is checked to still name
    /// the locked file (no exclusive holder can unlink it while `self`
    /// holds the shared lock), and checked again once open.
    pub(crate) fn reopen_shared(&self) -> Result<OwnedFd, Error> {
        let held = self.file.metadata().map_err(|e| lock_err(&self.path, e))?;
        let same = |m: &fs::Metadata| m.dev() == held.dev() && m.ino() == held.ino();
        match fs::symlink_metadata(&self.path) {
            Ok(m) if m.file_type().is_file() && same(&m) => {}
            Ok(_) | Err(_) => return Err(Error::LockChanged(self.path.clone())),
        }
        let file = File::open(&self.path).map_err(|e| lock_err(&self.path, e))?;
        let opened = file.metadata().map_err(|e| lock_err(&self.path, e))?;
        if !same(&opened) {
            return Err(Error::LockChanged(self.path.clone()));
        }
        match file.try_lock_shared() {
            Ok(()) => Ok(OwnedFd::from(file)),
            Err(TryLockError::WouldBlock) => Err(Error::LockBusy(self.path.clone())),
            Err(TryLockError::Error(e)) => Err(lock_err(&self.path, e)),
        }
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
/// and waits while an exclusive holder has it, until `deadline`
/// ([`Error::LockBusy`] after it).
pub(crate) fn lock_shared(path: &Path, deadline: Instant) -> Result<Held, Error> {
    match acquire(path, Mode::Shared(deadline), Create::Yes, &mut |_, _| {})? {
        Exclusive::Held(held) => Ok(held),
        // `Mode::Shared` gives up with `LockBusy` and `Create::Yes`
        // creates, so neither answer comes back; kept total rather than
        // unreachable.
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
    /// Wait for the shared lock until the deadline.
    Shared(Instant),
    TryExclusive,
}

/// Waits for the shared lock on `file` until `deadline`, polling
/// `try_lock_shared` with pauses from [`POLL_MIN`] doubling to
/// [`POLL_MAX`]. std's `lock_shared` has no timeout.
fn wait_shared(file: &File, path: &Path, deadline: Instant) -> Result<(), Error> {
    let mut pause = POLL_MIN;
    loop {
        match file.try_lock_shared() {
            Ok(()) => return Ok(()),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(e)) => return Err(lock_err(path, e)),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::LockBusy(path.to_path_buf()));
        }
        std::thread::sleep(pause.min(left));
        pause = pause.saturating_mul(2).min(POLL_MAX);
    }
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
            Mode::Shared(deadline) => wait_shared(&file, path, deadline)?,
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

    use std::time::{Duration, Instant};

    use super::{Create, Exclusive, LOCK_ATTEMPTS, Mode, acquire, lock_shared};
    use crate::error::Error;
    use crate::scratch::ScratchDir;

    /// A deadline no test reaches.
    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

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
            (Mode::Shared(far()), Create::Yes),
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
        match acquire(&path, Mode::Shared(far()), Create::Yes, &mut |_, p| {
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
                (Mode::Shared(far()), Create::Yes),
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
        let shared = lock_shared(&path, far()).expect("shared");
        assert_eq!(
            std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
            0o600
        );
        let again = lock_shared(&path, far()).expect("a second shared lock");
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

    /// The review of #92: a shared locker waits for an exclusive holder
    /// only until its deadline, then fails with `LockBusy` naming the path,
    /// so a stopped holder cannot stall a pull, and every pull queued on
    /// the store's mutex behind it, for good. The wait ends close to the
    /// deadline, not a full `POLL_MAX` or more past it.
    #[test]
    fn shared_wait_is_bounded() {
        let scratch = ScratchDir::new("lock-bounded");
        let path = scratch.path().join("lock");
        std::fs::write(&path, b"").expect("lock file");
        let holder = File::open(&path).expect("open");
        holder.lock().expect("exclusive");
        let started = Instant::now();
        let wait = Duration::from_millis(300);
        match lock_shared(&path, started + wait) {
            Err(Error::LockBusy(p)) => assert_eq!(p, path),
            other => panic!("waited past an exclusive holder: {other:?}"),
        }
        let took = started.elapsed();
        assert!(took >= wait, "gave up early: {took:?}");
        assert!(took < wait + Duration::from_secs(2), "overslept: {took:?}");
        // A deadline already past still tries once.
        drop(holder);
        let held = lock_shared(&path, Instant::now()).expect("free, so locked at once");
        assert!(is_held(&path));
        drop(held);
    }

    /// A shared locker that waits while an exclusive holder removes the
    /// file gets the lock once the holder is done, on the new file the
    /// path names, well before its deadline.
    #[test]
    fn shared_wait_ends_when_the_holder_unlinks() {
        let scratch = ScratchDir::new("lock-unlinked");
        let path = scratch.path().join("lock");
        std::fs::write(&path, b"").expect("lock file");
        let holder = File::open(&path).expect("open");
        holder.lock().expect("exclusive");
        let remover = {
            let path = path.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                std::fs::remove_file(&path).expect("unlink while holding");
                drop(holder);
            })
        };
        let held = lock_shared(&path, far()).expect("locked once the holder is done");
        remover.join().expect("remover");
        let opened = held.file.metadata().expect("fstat");
        let now = std::fs::metadata(&path).expect("stat");
        assert_eq!((opened.dev(), opened.ino()), (now.dev(), now.ino()));
    }

    /// `reopen_shared` gives a new open file description with its own
    /// shared lock: it keeps the file locked after the original is
    /// dropped, and releasing it does not release the original.
    #[test]
    fn reopened_description_holds_its_own_lock() {
        let scratch = ScratchDir::new("lock-reopen");
        let path = scratch.path().join("lock");
        let held = lock_shared(&path, far()).expect("shared");
        let other = File::from(held.reopen_shared().expect("reopen"));
        other.unlock().expect("unlock the copy");
        assert!(is_held(&path), "the copy's release released the original");
        other.lock_shared().expect("lock the copy again");
        drop(held);
        assert!(is_held(&path), "the copy holds the file on its own");
        drop(other);
        assert!(!is_held(&path));
    }
}
