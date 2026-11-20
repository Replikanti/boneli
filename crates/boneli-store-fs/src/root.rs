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

/// The store's exclusive lock on `<root>/lock` (ADR-012, D1), released by an
/// explicit unlock when it drops, not by the close alone (ADR-026). `flock`
/// belongs to the open file description, and a child process spawned by any
/// thread holds a copy of that description from fork until exec (the file
/// is `O_CLOEXEC`, so exec closes it). A close while such a copy lives
/// leaves the lock held, and a reopen gets `InUse`; an unlock acts on the
/// description, so it releases the lock whatever copies exist (#94).
///
/// Only the process that took the lock unlocks it. A process forked
/// without exec runs on a copy of its parent's memory, so an unwinding
/// panic there could drop a copy of this value; an unlock from it would
/// release the parent's live lock, while its close only closes its own
/// descriptor (ADR-026, D1).
#[derive(Debug)]
pub(crate) struct StoreLock {
    file: File,
    /// The id of the process that took the lock.
    owner: u32,
}

impl StoreLock {
    /// Takes the lock on `file` at `path` without waiting: `InUse` while
    /// another store, in this process or another, holds it.
    fn acquire(file: File, path: &Path) -> Result<StoreLock, OpenError> {
        match file.try_lock() {
            Ok(()) => Ok(StoreLock {
                file,
                owner: std::process::id(),
            }),
            Err(TryLockError::WouldBlock) => Err(OpenError::InUse {
                path: path.to_path_buf(),
            }),
            Err(TryLockError::Error(e)) => Err(io_err(path, e)),
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // A copy dropped in a forked child leaves the parent's lock alone.
        if std::process::id() != self.owner {
            return;
        }
        // An error is ignored: the close that follows still releases the
        // lock when no child holds a copy, and a drop has no caller to
        // report to.
        let _ = self.file.unlock();
    }
}

/// Checks the root, takes the lock, prepares the directories and sweeps
/// them; returns the resolved root and the lock. The lock is a
/// [`StoreLock`] from the moment it is taken, so every error after that
/// unlocks it too.
pub(crate) fn open(root: &Path) -> Result<(PathBuf, StoreLock), OpenError> {
    open_with(root, &mut |_| {})
}

/// [`open`], with `after_lock` called on the locked file right after the
/// lock is taken. [`open`] passes a no-op; the tests give a child a copy of
/// the lock there, so a failing `open` is checked with a copy alive
/// (ADR-026, D3).
fn open_with(
    root: &Path,
    after_lock: &mut dyn FnMut(&File),
) -> Result<(PathBuf, StoreLock), OpenError> {
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
    let lock = StoreLock::acquire(lock, &lock_path)?;
    after_lock(&lock.file);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, RawFd};
    use std::process::{Child, Command, Stdio};

    /// Test-only access to the locked file: a copy of its description for
    /// a child to hold, and its descriptor for `/proc/self/fdinfo`.
    impl StoreLock {
        fn try_clone(&self) -> io::Result<File> {
            self.file.try_clone()
        }
    }

    impl AsRawFd for StoreLock {
        fn as_raw_fd(&self) -> RawFd {
            self.file.as_raw_fd()
        }
    }

    /// A fresh directory under the system temporary directory, removed on
    /// drop; the store root is `store` in it.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir()
                .join(format!("boneli-store-fs-root-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("scratch dir");
            // Resolved, because `open` refuses a root with dot components
            // (ADR-012 D1) and `TMPDIR` may hold some.
            Scratch(dir.canonicalize().expect("resolve the scratch dir"))
        }

        fn root(&self) -> PathBuf {
            self.0.join("store")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A child process that holds a copy of the lock's open file
    /// description as its stdin, as every child does between fork and
    /// exec; killed and reaped on drop, also when the test panics.
    struct Holder(Child);

    impl Holder {
        fn spawn(copy: File) -> Holder {
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

    /// A store dropped while a child holds a copy of its lock description
    /// leaves the root openable: the drop releases the lock itself, not
    /// only its own descriptor (#94).
    #[test]
    fn unlock_on_drop_releases_while_a_child_holds_a_copy() {
        let scratch = Scratch::new("unlock-on-drop");
        let (_, lock) = open(&scratch.root()).expect("open");
        let _holder = Holder::spawn(lock.try_clone().expect("dup the lock"));
        drop(lock);
        let reopened = open(&scratch.root());
        assert!(reopened.is_ok(), "reopen gave {:?}", reopened.err());
    }

    /// While the store lives, a child's copy changes nothing: a second
    /// `open` is `InUse`.
    #[test]
    fn live_store_stays_locked_with_a_child_copy() {
        let scratch = Scratch::new("live-locked");
        let (resolved, lock) = open(&scratch.root()).expect("open");
        let _holder = Holder::spawn(lock.try_clone().expect("dup the lock"));
        match open(&scratch.root()) {
            Err(OpenError::InUse { path }) => assert_eq!(path, resolved.join(LOCK)),
            other => panic!("a second open gave {other:?}"),
        }
        drop(lock);
    }

    /// The lock descriptor is `O_CLOEXEC` (octal 02000000 in the `flags:`
    /// line of `/proc/self/fdinfo`), so a child's copy lives only from
    /// fork to exec, also after a crash of the store's process (ADR-026).
    #[test]
    fn lock_file_is_close_on_exec() {
        let scratch = Scratch::new("cloexec");
        let (_, lock) = open(&scratch.root()).expect("open");
        let info =
            fs::read_to_string(format!("/proc/self/fdinfo/{}", lock.as_raw_fd())).expect("fdinfo");
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .expect("a flags line");
        let flags = u32::from_str_radix(flags.trim(), 8).expect("octal flags");
        assert_ne!(flags & 0o2000000, 0, "flags {flags:o}");
    }

    /// An `open` that fails after it took the lock (here `runs` is a
    /// symlink) releases it, also while a child holds a copy of the lock
    /// taken right after the lock: the root opens once the symlink is
    /// gone, with the child still alive.
    #[test]
    fn failed_open_leaves_the_root_openable() {
        let scratch = Scratch::new("failed-open");
        let root = scratch.root();
        drop(open(&root).expect("open"));
        let elsewhere = scratch.0.join("elsewhere");
        fs::create_dir(&elsewhere).expect("dir");
        fs::remove_dir(root.join(RUNS)).expect("remove runs");
        std::os::unix::fs::symlink(&elsewhere, root.join(RUNS)).expect("symlink");
        let mut holder = None;
        let failed = open_with(&root, &mut |file| {
            holder = Some(Holder::spawn(file.try_clone().expect("dup the lock")));
        });
        match failed {
            Err(OpenError::Root { .. }) => {}
            other => panic!("a symlinked runs gave {other:?}"),
        }
        assert!(holder.is_some(), "open failed before it took the lock");
        fs::remove_file(root.join(RUNS)).expect("remove the symlink");
        let reopened = open(&root);
        assert!(reopened.is_ok(), "reopen gave {:?}", reopened.err());
    }

    /// A copy of the lock dropped in another process, as in a child forked
    /// without exec that unwinds, does not unlock: its owner is not that
    /// process. The test cannot fork without `unsafe`, so it builds the
    /// copy with an owner id that is not this process's, which is what a
    /// forked child's copy looks like from inside the child.
    #[test]
    fn copy_dropped_in_another_process_keeps_the_lock() {
        let scratch = Scratch::new("foreign-drop");
        let (resolved, lock) = open(&scratch.root()).expect("open");
        let foreign = StoreLock {
            file: lock.try_clone().expect("dup the lock"),
            owner: lock.owner.wrapping_add(1),
        };
        drop(foreign);
        match open(&scratch.root()) {
            Err(OpenError::InUse { path }) => assert_eq!(path, resolved.join(LOCK)),
            other => panic!("an open after a foreign drop gave {other:?}"),
        }
        drop(lock);
        let reopened = open(&scratch.root());
        assert!(reopened.is_ok(), "reopen gave {:?}", reopened.err());
    }
}
