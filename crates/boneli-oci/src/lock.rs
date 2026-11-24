//! Lock files (ADR-025, D3): `flock` locks on regular files under
//! `<root>/locks/`, taken through the workspace's one file-lock type,
//! `boneli_private_dir::lock` (ADR-030).
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
//! up to a deadline ([`LOCK_WAIT`]); exclusive lockers of layer and owner
//! locks only ever try, and the one exclusive lock that is waited for,
//! `locks/trim` (ADR-025, D6), is held by a trim that never waits for
//! another lock, so no lock cycle can form. Every file is opened by std, with `O_CLOEXEC`, so
//! no sandbox inherits a lock by accident; a lease hands out descriptors
//! for that on purpose ([`crate::Lease::pin_descriptors`]). Every lock is
//! released by an explicit unlock, from the moment it is taken, a retry's
//! too ([`Held`]), and so is a lease's descriptor until it is handed on
//! ([`HandOff`]); a descriptor handed on is released by whoever holds it
//! (ADR-030, D1).

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use boneli_private_dir::lock::{FileLock, HandOff, Kind, TakeError};

use crate::error::Error;

/// How many times a lock is tried before [`Error::LockChanged`]. A hang
/// bound, not a target: each retry needs an exclusive holder to unlink
/// this very file between our open and our lock (D3).
pub(crate) const LOCK_ATTEMPTS: u32 = 1_024;

/// How long a shared locker waits for an exclusive holder before it gives
/// up with [`Error::LockBusy`] (ADR-025, D3). An exclusive holder holds a
/// lock only for O(1) steps: it renames what it removes to an owned name
/// of its own and removes the tree after it released the lock (the rule
/// for #56 part 2). The longest of those steps is a directory `fsync`,
/// which on ext4 can wait for the dirty page cache, at most
/// `vm.dirty_ratio` (20 %) of memory: about 12.8 GiB on a 64 GiB runner,
/// about 105 s at gp3's documented 125 MiB/s baseline. 120 s covers that.
/// Shorter fails a pull while a legitimate `fsync` runs; longer lets a
/// stopped holder stall a pull, and every pull queued behind it on the
/// store's mutex, for longer.
pub(crate) const LOCK_WAIT: Duration = Duration::from_secs(120);

/// A lock held on a lock file, with the path it was taken at; dropping it
/// releases the lock by an explicit `LOCK_UN`, then closes the file.
///
/// Not by the close alone (the flake of #99): a child that any thread of
/// this process forks or spawns holds a copy of every descriptor until it
/// execs (the sandbox's launch runs its setup in that window), so a close
/// released nothing until then; a dropped pin kept its layer from a trim,
/// and a trim's dropped exclusive lock kept pins waiting. The release, and
/// that only the process that took the lock unlocks it, are the shared
/// type's ([`FileLock`], ADR-030, D1).
#[derive(Debug)]
pub(crate) struct Held {
    lock: FileLock,
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
    /// holds the shared lock), and checked again once open. Kept in `into`
    /// from the moment it is locked, so one abandoned before its handoff
    /// is released by an unlock too ([`HandOff`], ADR-030).
    pub(crate) fn reopen_shared(&self, into: &mut HandOff) -> Result<(), Error> {
        let held = self
            .lock
            .file()
            .metadata()
            .map_err(|e| lock_err(&self.path, e))?;
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
        match into.try_take(file, Kind::Shared) {
            Ok(()) => Ok(()),
            Err(TakeError::Busy) => Err(Error::LockBusy(self.path.clone())),
            Err(TakeError::Io(e)) => Err(lock_err(&self.path, e)),
        }
    }

    /// Unlinks the lock file while the lock is still held, then releases
    /// it (the drop). Only an exclusive holder calls this (D3): a shared
    /// locker that opened the file before the unlink sees the mismatch
    /// once it gets the lock, and tries again on a new file.
    pub(crate) fn remove(self) -> Result<(), Error> {
        self.remove_with(&mut |_| {})
    }

    /// [`Held::remove`], with `unlinked(path)` run after the unlink and
    /// before the release: a no-op in production, the seam a test checks
    /// the order through.
    fn remove_with(self, unlinked: &mut dyn FnMut(&Path)) -> Result<(), Error> {
        let removed = match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(lock_err(&self.path, e)),
        };
        unlinked(&self.path);
        drop(self);
        removed
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
pub(crate) fn shared(path: &Path, deadline: Instant) -> Result<Held, Error> {
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

/// Tries the exclusive lock on the lock file at `path`, creating the file
/// where it is missing, without waiting: a layer committed by a build
/// before ADR-025 has no lock file, and is evicted under one all the same
/// (ADR-025, D7). Never [`Exclusive::Missing`].
pub(crate) fn try_exclusive(path: &Path) -> Result<Exclusive, Error> {
    acquire(path, Mode::TryExclusive, Create::Yes, &mut |_, _| {})
}

/// Takes the exclusive lock on `path`, creating the file where it is
/// missing, and waits while anyone else holds a lock on it, until
/// `deadline` ([`Error::LockBusy`] after it). Only the trim lock
/// `locks/trim` is taken this way (ADR-025, D6); its holder never waits
/// for a layer lock, so no lock cycle can form.
pub(crate) fn exclusive(path: &Path, deadline: Instant) -> Result<Held, Error> {
    match acquire(path, Mode::Exclusive(deadline), Create::Yes, &mut |_, _| {})? {
        Exclusive::Held(held) => Ok(held),
        // As in `shared`: neither answer comes back.
        Exclusive::Busy | Exclusive::Missing => Err(Error::LockChanged(path.to_path_buf())),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Wait for the shared lock until the deadline.
    Shared(Instant),
    /// Wait for the exclusive lock until the deadline.
    Exclusive(Instant),
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
    acquire_with(path, mode, create, between, &mut |_, _| {})
}

/// [`acquire`], with `after_lock(attempt, file)` run right after the lock
/// is taken, before the inode check: the seam a test hands a copy of a
/// lock on a replaced file to a child through.
fn acquire_with(
    path: &Path,
    mode: Mode,
    create: Create,
    between: &mut dyn FnMut(u32, &Path),
    after_lock: &mut dyn FnMut(u32, &File),
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
        // The lock is a `FileLock` from the moment it is taken (ADR-030,
        // D1), so a lock on a replaced file and one an error abandons are
        // released by the drop's unlock too, not by the close alone (#98).
        let taken = match mode {
            Mode::Shared(deadline) => FileLock::take_until(file, Kind::Shared, deadline),
            Mode::Exclusive(deadline) => FileLock::take_until(file, Kind::Exclusive, deadline),
            Mode::TryExclusive => FileLock::try_take(file, Kind::Exclusive),
        };
        let lock = match taken {
            Ok(lock) => lock,
            Err(TakeError::Busy) => match mode {
                Mode::Shared(_) | Mode::Exclusive(_) => {
                    return Err(Error::LockBusy(path.to_path_buf()));
                }
                Mode::TryExclusive => return Ok(Exclusive::Busy),
            },
            Err(TakeError::Io(e)) => return Err(lock_err(path, e)),
        };
        after_lock(attempt, lock.file());
        let held = Held {
            lock,
            path: path.to_path_buf(),
        };
        match fs::symlink_metadata(path) {
            Ok(now) if now.dev() == opened.dev() && now.ino() == opened.ino() => {
                return Ok(Exclusive::Held(held));
            }
            // Replaced or unlinked by an exclusive holder (or a symlink
            // planted, which the next attempt refuses); `held` drops here.
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(lock_err(path, e)),
        }
    }
    Err(Error::LockChanged(path.to_path_buf()))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::{File, TryLockError};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};

    use std::time::{Duration, Instant};

    use super::{Create, Exclusive, LOCK_ATTEMPTS, Mode, acquire, shared};
    use crate::error::Error;
    use crate::scratch::ScratchDir;

    /// A deadline no test reaches.
    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// Whether a lock is held on the file at `path`. A probe that got the
    /// lock unlocks it before it closes, so a child another test spawns
    /// cannot keep it held (#98).
    pub(crate) fn is_held(path: &Path) -> bool {
        let probe = File::open(path).expect("open");
        match probe.try_lock() {
            Ok(()) => {
                probe.unlock().expect("unlock the probe");
                false
            }
            Err(TryLockError::WouldBlock) => true,
            Err(TryLockError::Error(e)) => panic!("{e}"),
        }
    }

    /// `held.reopen_shared`, handed on as a `File`.
    fn reopen(held: &super::Held) -> File {
        let mut taken = boneli_private_dir::lock::HandOff::new();
        held.reopen_shared(&mut taken).expect("reopen");
        File::from(taken.hand_on().pop().expect("one descriptor"))
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
            let opened = held.lock.file().metadata().expect("fstat");
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
        let first = shared(&path, far()).expect("shared");
        assert_eq!(
            std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
            0o600
        );
        let again = shared(&path, far()).expect("a second shared lock");
        assert!(matches!(
            super::try_exclusive_existing(&path),
            Ok(Exclusive::Busy)
        ));
        drop(first);
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
        match shared(&path, started + wait) {
            Err(Error::LockBusy(p)) => assert_eq!(p, path),
            other => panic!("waited past an exclusive holder: {other:?}"),
        }
        let took = started.elapsed();
        assert!(took >= wait, "gave up early: {took:?}");
        assert!(took < wait + Duration::from_secs(2), "overslept: {took:?}");
        // A deadline already past still tries once.
        holder.unlock().expect("unlock");
        drop(holder);
        let held = shared(&path, Instant::now()).expect("free, so locked at once");
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
        let held = shared(&path, far()).expect("locked once the holder is done");
        remover.join().expect("remover");
        let opened = held.lock.file().metadata().expect("fstat");
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
        let held = shared(&path, far()).expect("shared");
        let other = reopen(&held);
        other.unlock().expect("unlock the copy");
        assert!(is_held(&path), "the copy's release released the original");
        other.lock_shared().expect("lock the copy again");
        drop(held);
        assert!(is_held(&path), "the copy holds the file on its own");
        other.unlock().expect("unlock the copy");
        drop(other);
        assert!(!is_held(&path));
    }

    /// The trim lock (ADR-025, D6): `exclusive` creates a missing
    /// file `0o600`, waits while a shared or exclusive lock is held
    /// elsewhere, only until its deadline (`LockBusy`), and gets the lock
    /// once the other holder lets go. `try_exclusive` creates a missing
    /// file, as an eviction does for a layer committed before ADR-025.
    #[test]
    fn exclusive_wait_is_bounded() {
        let scratch = ScratchDir::new("lock-exclusive");
        let path = scratch.path().join("trim");
        let held = super::exclusive(&path, far()).expect("created and locked");
        assert_eq!(
            std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
            0o600
        );
        let started = Instant::now();
        let wait = Duration::from_millis(300);
        match super::exclusive(&path, started + wait) {
            Err(Error::LockBusy(p)) => assert_eq!(p, path),
            other => panic!("waited past an exclusive holder: {other:?}"),
        }
        assert!(started.elapsed() >= wait);
        drop(held);
        let shared = File::open(&path).expect("open");
        shared.lock_shared().expect("shared");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(shared);
        });
        let held = super::exclusive(&path, far()).expect("locked once free");
        releaser.join().expect("releaser");
        assert!(is_held(&path));
        drop(held);

        let missing = scratch.path().join("layer");
        let Ok(Exclusive::Held(held)) = super::try_exclusive(&missing) else {
            panic!("a missing lock file is created and locked");
        };
        assert!(is_held(&missing));
        held.remove().expect("remove");
        assert!(!missing.exists());
    }

    /// A copy of a lock dropped by a process other than its owner, by pid
    /// or by pid namespace (a sandbox child is pid 1 of a new namespace, as
    /// a runner that is its namespace's init is of its own), and one whose
    /// namespace could not be read, leave the lock held; the owner's own
    /// drop releases it (ADR-030, D1). The copies come from the shared
    /// type's test seam (ADR-030, D4), so this test also fails when the
    /// owner check there is gone.
    #[test]
    fn foreign_drop_keeps_the_lock() {
        use boneli_private_dir::lock::Foreign;
        let scratch = ScratchDir::new("lock-foreign-drop");
        let path = scratch.path().join("lock");
        assert!(
            std::fs::metadata("/proc/thread-self/ns/pid").is_ok(),
            "the test host reads its pid namespace"
        );
        for how in [
            Foreign::OtherPid,
            Foreign::OtherPidNamespace,
            Foreign::UnreadableNamespace,
        ] {
            let held = shared(&path, far()).expect("shared");
            let copy = reopen(&held);
            copy.unlock().expect("only the reopened copy holds");
            let foreign = super::Held {
                lock: held.lock.copy_as(how).expect("a copy of the description"),
                path: held.path.clone(),
            };
            drop(foreign);
            // The description survives in `held`; a drop that unlocked it
            // would have released the lock.
            assert!(is_held(&path), "{how:?}: a foreign drop released the lock");
            // Released by the owner's unlock, not the close alone, which a
            // child another test spawns could delay (#98).
            drop(held);
            assert!(!is_held(&path), "{how:?}: the owner's drop kept the lock");
        }
        let held = shared(&path, far()).expect("shared");
        let same = held.lock.file().try_clone().expect("a copy");
        drop(held);
        assert!(!is_held(&path), "the owner's drop did not release the lock");
        drop(same);
    }

    /// A child that holds a copy of a lock's open file description, as one
    /// a thread spawned holds it between fork and exec (#98): `sleep` with
    /// the copy as its stdin, killed and reaped on drop.
    pub(crate) struct Holder(Child);

    impl Holder {
        pub(crate) fn spawn(file: &File) -> Holder {
            let copy = file.try_clone().expect("dup the lock");
            let child = Command::new("sleep")
                .arg("60")
                .stdin(Stdio::from(copy))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sleep");
            Holder(child)
        }
    }

    impl Drop for Holder {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn exclusive_held(path: &Path) -> super::Held {
        match super::try_exclusive_existing(path) {
            Ok(Exclusive::Held(held)) => held,
            other => panic!("{}: {other:?}", path.display()),
        }
    }

    /// A shared lock dropped while a child holds a copy of its description
    /// is free at once: an exclusive try gets it (#98).
    #[test]
    fn shared_drop_releases_while_a_child_holds_a_copy() {
        let scratch = ScratchDir::new("lock-shared-child");
        let path = scratch.path().join("lock");
        let held = shared(&path, far()).expect("shared");
        let _holder = Holder::spawn(held.lock.file());
        drop(held);
        assert!(!is_held(&path), "the child's copy kept the lock");
        drop(exclusive_held(&path));
    }

    /// The same for the exclusive locks: an eviction's try and the trim
    /// lock's wait (#98).
    #[test]
    fn exclusive_drop_releases_while_a_child_holds_a_copy() {
        let scratch = ScratchDir::new("lock-exclusive-child");
        let path = scratch.path().join("lock");
        std::fs::write(&path, b"").expect("lock file");
        let held = exclusive_held(&path);
        let _holder = Holder::spawn(held.lock.file());
        drop(held);
        assert!(
            !is_held(&path),
            "try_exclusive: the child's copy kept the lock"
        );
        let trim = scratch.path().join("trim");
        let held = super::exclusive(&trim, far()).expect("trim lock");
        let _holder = Holder::spawn(held.lock.file());
        drop(held);
        assert!(!is_held(&trim), "exclusive: the child's copy kept the lock");
    }

    /// `remove` with a child holding a copy: the file is gone, and its
    /// inode, still open through a handle taken before, is unlocked (#98).
    #[test]
    fn remove_releases_while_a_child_holds_a_copy() {
        let scratch = ScratchDir::new("lock-remove-child");
        let path = scratch.path().join("lock");
        std::fs::write(&path, b"").expect("lock file");
        let stale = File::open(&path).expect("open before remove");
        let held = exclusive_held(&path);
        let _holder = Holder::spawn(held.lock.file());
        held.remove().expect("remove");
        assert!(!path.exists());
        stale.try_lock().expect("the removed file is unlocked");
    }

    /// `remove` unlinks the file while the lock is still held, and only
    /// then unlocks it (D3): a shared locker that got the lock between an
    /// unlock and the unlink would pass its inode check on a file about to
    /// go, and pin a layer under a lock no later eviction sees. At the
    /// seam between the two steps the path is gone and a description
    /// opened before still finds the inode locked; after it, free.
    #[test]
    fn remove_unlinks_before_it_unlocks() {
        let scratch = ScratchDir::new("lock-remove-order");
        let path = scratch.path().join("lock");
        std::fs::write(&path, b"").expect("lock file");
        let stale = File::open(&path).expect("open before remove");
        let held = exclusive_held(&path);
        let mut seen = 0;
        held.remove_with(&mut |p| {
            seen += 1;
            assert!(!p.exists(), "the seam ran before the unlink");
            assert!(
                matches!(stale.try_lock_shared(), Err(TryLockError::WouldBlock)),
                "unlocked before the unlink"
            );
        })
        .expect("remove");
        assert_eq!(seen, 1);
        stale.try_lock().expect("the removed file is unlocked");
    }

    /// While the lock lives, a child's copy changes nothing: an exclusive
    /// try is `Busy`, so the unlock on drop releases nothing early.
    #[test]
    fn live_lock_stays_held_with_a_child_copy() {
        let scratch = ScratchDir::new("lock-live-child");
        let path = scratch.path().join("lock");
        let held = shared(&path, far()).expect("shared");
        let _holder = Holder::spawn(held.lock.file());
        assert!(matches!(
            super::try_exclusive_existing(&path),
            Ok(Exclusive::Busy)
        ));
        drop(held);
    }

    /// A lock taken on a file that an exclusive holder replaced between our
    /// open and our lock is released before the retry, also while a child
    /// holds a copy of it: the lock is wrapped from the moment it is taken
    /// (ADR-030, D1), not only once the inode check passed (#98). For every
    /// mode; the stale inode stays reachable through a handle opened
    /// before the replacement.
    #[test]
    fn replaced_file_lock_is_released_with_a_child_copy() {
        let scratch = ScratchDir::new("lock-replaced-child");
        let path = scratch.path().join("lock");
        for (mode, create) in [
            (Mode::Shared(far()), Create::Yes),
            (Mode::Exclusive(far()), Create::Yes),
            (Mode::TryExclusive, Create::No),
        ] {
            std::fs::write(&path, b"").expect("lock file");
            let mut stale = None;
            let mut holders = Vec::new();
            let got = super::acquire_with(
                &path,
                mode,
                create,
                &mut |attempt, p| {
                    if attempt == 0 {
                        stale = Some(File::open(p).expect("open the file to replace"));
                        replace(p);
                    }
                },
                &mut |attempt, file| {
                    if attempt == 0 {
                        holders.push(Holder::spawn(file));
                    }
                },
            )
            .expect("acquired");
            let Exclusive::Held(held) = got else {
                panic!("{mode:?}: {got:?}");
            };
            assert_eq!(holders.len(), 1, "{mode:?}: locked the replaced file once");
            let stale = stale.expect("replaced");
            stale
                .try_lock()
                .unwrap_or_else(|e| panic!("{mode:?}: the replaced file is still locked: {e:?}"));
            drop(held);
            drop(holders);
        }
    }

    /// Every lock file is `O_CLOEXEC` (octal 02000000 in the `flags:` line
    /// of `/proc/self/fdinfo`), whether opened or created, so a child's
    /// copy lives only from fork to exec, also after a crash of the
    /// holder (ADR-030, D1).
    #[test]
    fn lock_file_is_close_on_exec() {
        let scratch = ScratchDir::new("lock-cloexec");
        let created = shared(&scratch.path().join("created"), far()).expect("created");
        let existing = scratch.path().join("existing");
        std::fs::write(&existing, b"").expect("lock file");
        let opened = exclusive_held(&existing);
        for held in [&created, &opened] {
            let info = std::fs::read_to_string(format!(
                "/proc/self/fdinfo/{}",
                held.lock.file().as_raw_fd()
            ))
            .expect("fdinfo");
            let flags = info
                .lines()
                .find_map(|line| line.strip_prefix("flags:"))
                .expect("a flags line");
            let flags = u32::from_str_radix(flags.trim(), 8).expect("octal flags");
            assert_ne!(
                flags & 0o2000000,
                0,
                "{}: flags {flags:o}",
                held.path().display()
            );
        }
    }
}
