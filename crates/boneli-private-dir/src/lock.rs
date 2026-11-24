//! The one file-lock type of the workspace (ADR-030): `flock` locks taken
//! through std's `File::try_lock*`, wrapped from the moment they are taken
//! and released by an explicit unlock, in the process that took them only.
//!
//! The rule, stated once for every file lock (ADR-030, D1):
//!
//! - A lock is released by `LOCK_UN` before its file closes, not by the
//!   close alone. A `flock` lock belongs to the open file description, and
//!   a child that any thread forks or spawns holds a copy of every
//!   descriptor until it execs; a close while such a copy lives releases
//!   nothing until then. `LOCK_UN` acts on the description, whatever copies
//!   of it exist.
//! - Only the process that took a lock unlocks it. A child forked without
//!   exec runs on a copy of its parent's memory and may unwind through a
//!   frame that holds a lock; an unlock there would release the parent's
//!   live lock, so it only closes its own copy. The process is told by its
//!   pid and the `(st_dev, st_ino)` of `/proc/thread-self/ns/pid`, read
//!   when the lock is taken and again when it is released: a sandbox child
//!   is pid 1 of a new pid namespace, and so is a runner that is its
//!   namespace's init. A link unreadable at either end keeps the lock, and
//!   only the close runs.
//! - A lock is wrapped in the same expression that receives the `Ok` of
//!   its `try_lock*`, so nothing fallible runs between the lock and the
//!   wrap, and no path releases it by the close alone.
//! - An unlock error is ignored: the close that follows still releases the
//!   lock when no child holds a copy, and a drop has no caller to report
//!   to.
//! - A lock handed to another process on purpose ([`HandOff::hand_on`]) is
//!   released by whoever holds its descriptor.
//!
//! [`FileLock`] is a lock its process keeps; [`HandOff`] holds locks taken
//! to be handed on, until they are. Both release through one private
//! function with the one owner check. Which file is locked, how it is
//! opened and what its path must be stay with the caller: the lock-file
//! protocols of `boneli-store-fs` (ADR-012, D1) and `boneli-oci` (ADR-025,
//! D3) are theirs.

use std::fmt;
use std::fs::{self, File, TryLockError};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

/// The first pause of [`FileLock::take_until`]; it doubles up to
/// [`POLL_MAX`] (ADR-030, D3).
const POLL_MIN: Duration = Duration::from_millis(1);

/// The longest pause of [`FileLock::take_until`]: a waiter gets the lock
/// at most 100 ms after its holder released it, against a pull that takes
/// seconds, at about 1,200 wake-ups over the 120 s wait of `boneli-oci`
/// (ADR-030, D3).
const POLL_MAX: Duration = Duration::from_millis(100);

/// The link whose `(st_dev, st_ino)` names the caller's pid namespace.
/// `thread-self`, not `self`: `/proc/self` fails once the main thread has
/// exited (#35), and every thread of a process shares its pid namespace.
const PID_NS: &str = "/proc/thread-self/ns/pid";

/// Which lock to take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `LOCK_SH`: any number of shared holders at once.
    Shared,
    /// `LOCK_EX`: one holder, no shared ones.
    Exclusive,
}

/// Why a lock was not taken.
#[derive(Debug)]
pub enum TakeError {
    /// Someone else holds a lock that conflicts (`WouldBlock`), at once or
    /// until the deadline.
    Busy,
    /// The lock call failed otherwise.
    Io(io::Error),
}

impl fmt::Display for TakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TakeError::Busy => f.write_str("the file is locked by someone else"),
            TakeError::Io(e) => write!(f, "file lock: {e}"),
        }
    }
}

impl std::error::Error for TakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TakeError::Io(e) => Some(e),
            TakeError::Busy => None,
        }
    }
}

/// A process as the owner check sees it (ADR-030, D1): its pid and its pid
/// namespace, `None` when the namespace link cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owner {
    pid: u32,
    pid_ns: Option<(u64, u64)>,
}

impl Owner {
    /// The calling process. `fs::metadata` on a short literal path builds
    /// the C string on std's stack buffer (384 bytes), so a release in an
    /// unwinding forked child allocates nothing here.
    fn current() -> Owner {
        Owner {
            pid: std::process::id(),
            pid_ns: fs::metadata(PID_NS).ok().map(|m| (m.dev(), m.ino())),
        }
    }
}

/// Whether `now` is the process that `recorded` took the lock in: the same
/// pid in the same pid namespace, read at both ends. An unreadable link,
/// at either end or at both, is a mismatch, so the release keeps the lock
/// and only the close runs: without the namespace a pid-1 runner and its
/// sandbox child look alike (ADR-030, D1).
fn owns(recorded: &Owner, now: &Owner) -> bool {
    recorded.pid_ns.is_some() && recorded == now
}

/// The one release of every lock of this module: unlocks each of `files`
/// when the calling process is `owner`, and does nothing otherwise, which
/// leaves the close that follows to release what it can. Errors are
/// ignored (ADR-030, D1).
fn release(owner: &Owner, files: &[File]) {
    if !owns(owner, &Owner::current()) {
        return;
    }
    for file in files {
        let _ = file.unlock();
    }
}

/// One non-blocking try of `kind` on `file`.
fn try_lock(file: &File, kind: Kind) -> Result<(), TryLockError> {
    match kind {
        Kind::Shared => file.try_lock_shared(),
        Kind::Exclusive => file.try_lock(),
    }
}

/// The pause after `pause` in [`FileLock::take_until`]: doubled, at most
/// [`POLL_MAX`].
fn next_pause(pause: Duration) -> Duration {
    pause.saturating_mul(2).min(POLL_MAX)
}

/// A lock held on a file by this process; dropping it unlocks the file in
/// the process that took it (ADR-030, D1), then closes it.
#[derive(Debug)]
pub struct FileLock {
    file: File,
    /// The process that took the lock.
    owner: Owner,
}

impl FileLock {
    /// Tries `kind` on `file` once, without waiting: [`TakeError::Busy`]
    /// while a conflicting lock is held, in this process (through another
    /// open file description) or another.
    pub fn try_take(file: File, kind: Kind) -> Result<FileLock, TakeError> {
        match try_lock(&file, kind) {
            // Wrapped in the arm that receives the lock (ADR-030, D1).
            Ok(()) => Ok(FileLock {
                file,
                owner: Owner::current(),
            }),
            Err(TryLockError::WouldBlock) => Err(TakeError::Busy),
            Err(TryLockError::Error(e)) => Err(TakeError::Io(e)),
        }
    }

    /// Takes `kind` on `file`, waiting while a conflicting lock is held,
    /// until `deadline`; [`TakeError::Busy`] after it. Tries at least once,
    /// so a deadline already past gets a free lock. std's `lock` and
    /// `lock_shared` have no timeout, so this polls, with pauses from 1 ms
    /// doubling to 100 ms and never past the deadline (ADR-030, D3).
    pub fn take_until(file: File, kind: Kind, deadline: Instant) -> Result<FileLock, TakeError> {
        let mut pause = POLL_MIN;
        loop {
            match try_lock(&file, kind) {
                // Wrapped in the arm that receives the lock (ADR-030, D1).
                Ok(()) => {
                    return Ok(FileLock {
                        file,
                        owner: Owner::current(),
                    });
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(e)) => return Err(TakeError::Io(e)),
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(TakeError::Busy);
            }
            std::thread::sleep(pause.min(left));
            pause = next_pause(pause);
        }
    }

    /// The locked file.
    pub fn file(&self) -> &File {
        &self.file
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        release(&self.owner, std::slice::from_ref(&self.file));
    }
}

/// Locks taken to be handed to another process, kept by this value until
/// they are: dropped before [`HandOff::hand_on`], as when an error
/// abandons them, each is released by an unlock in the process that took
/// it, as a [`FileLock`] is (ADR-030, D1). Once handed on, whoever holds a
/// descriptor releases it, by `close` or `LOCK_UN`.
#[derive(Debug)]
pub struct HandOff {
    files: Vec<File>,
    /// The process that took the locks.
    owner: Owner,
}

impl HandOff {
    /// None yet, owned by the calling process.
    pub fn new() -> HandOff {
        HandOff {
            files: Vec::new(),
            owner: Owner::current(),
        }
    }

    /// Tries `kind` on `file` once, without waiting, and keeps `file` from
    /// the moment it is locked; [`TakeError::Busy`] as in
    /// [`FileLock::try_take`].
    pub fn try_take(&mut self, file: File, kind: Kind) -> Result<(), TakeError> {
        // Room first, so the push after the lock cannot allocate.
        self.files.reserve(1);
        match try_lock(&file, kind) {
            Ok(()) => {
                self.files.push(file);
                Ok(())
            }
            Err(TryLockError::WouldBlock) => Err(TakeError::Busy),
            Err(TryLockError::Error(e)) => Err(TakeError::Io(e)),
        }
    }

    /// The file locked last.
    pub fn last(&self) -> Option<&File> {
        self.files.last()
    }

    /// The descriptors, in the order they were taken, no longer released
    /// by this value.
    pub fn hand_on(mut self) -> Vec<OwnedFd> {
        std::mem::take(&mut self.files)
            .into_iter()
            .map(OwnedFd::from)
            .collect()
    }
}

impl Default for HandOff {
    fn default() -> HandOff {
        HandOff::new()
    }
}

impl Drop for HandOff {
    fn drop(&mut self) {
        release(&self.owner, &self.files);
    }
}

/// How a test copy of a lock differs from its owner (ADR-030, D4): as a
/// copy looks from inside a child forked without exec, which no test can
/// make without `unsafe`.
#[cfg(any(test, feature = "test-seam"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Foreign {
    /// Another pid in this pid namespace: a plain forked child.
    OtherPid,
    /// This pid in another pid namespace: the sandbox child of a runner
    /// that is pid 1 of its own.
    OtherPidNamespace,
    /// A namespace link that could not be read.
    UnreadableNamespace,
}

#[cfg(any(test, feature = "test-seam"))]
impl FileLock {
    /// A second handle on the same open file description, recorded as
    /// taken by a process other than this one, as `how` says. Dropped, it
    /// fails the owner check and only closes its descriptor, so it can
    /// never unlock a lock it does not own; only for tests of the owner
    /// check (ADR-030, D4).
    pub fn copy_as(&self, how: Foreign) -> io::Result<FileLock> {
        let owner = match how {
            Foreign::OtherPid => Owner {
                pid: self.owner.pid.wrapping_add(1),
                ..self.owner
            },
            Foreign::OtherPidNamespace => Owner {
                pid_ns: self.owner.pid_ns.map(|(d, i)| (d, i.wrapping_add(1))),
                ..self.owner
            },
            Foreign::UnreadableNamespace => Owner {
                pid_ns: None,
                ..self.owner
            },
        };
        Ok(FileLock {
            file: self.file.try_clone()?,
            owner,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    /// A fresh directory under the system temporary directory, removed on
    /// drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!(
                "boneli-private-dir-lock-{tag}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("scratch dir");
            Scratch(dir)
        }

        /// The file `name` in it, created empty.
        fn file(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, b"").expect("lock file");
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open(path: &Path) -> File {
        File::open(path).expect("open")
    }

    /// Whether any lock is held on the file at `path`. A probe that got
    /// the lock unlocks it before it closes, so a child another test
    /// spawns cannot keep it held (#98).
    fn is_held(path: &Path) -> bool {
        let probe = open(path);
        match probe.try_lock() {
            Ok(()) => {
                probe.unlock().expect("unlock the probe");
                false
            }
            Err(TryLockError::WouldBlock) => true,
            Err(TryLockError::Error(e)) => panic!("{e}"),
        }
    }

    /// A child that holds a copy of a lock's open file description, as one
    /// a thread spawned holds it between fork and exec: `sleep` with the
    /// copy as its stdin, killed and reaped on drop.
    struct Holder(Child);

    impl Holder {
        fn spawn(file: &File) -> Holder {
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

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// A copy of a lock dropped by another pid, by another pid namespace,
    /// or with an unreadable namespace link leaves the lock held; the
    /// owner's own drop releases it, also while a child holds a copy.
    #[test]
    fn foreign_copy_keeps_the_lock() {
        let scratch = Scratch::new("foreign-copy");
        let path = scratch.file("lock");
        assert!(
            fs::metadata(PID_NS).is_ok(),
            "the test host reads its pid namespace"
        );
        for how in [
            Foreign::OtherPid,
            Foreign::OtherPidNamespace,
            Foreign::UnreadableNamespace,
        ] {
            for kind in [Kind::Shared, Kind::Exclusive] {
                let lock = FileLock::try_take(open(&path), kind).expect("free");
                let copy = lock.copy_as(how).expect("copy");
                drop(copy);
                assert!(
                    is_held(&path),
                    "{how:?}, {kind:?}: a foreign drop released the lock"
                );
                let _holder = Holder::spawn(lock.file());
                drop(lock);
                assert!(
                    !is_held(&path),
                    "{how:?}, {kind:?}: the owner's drop did not release the lock"
                );
            }
        }
    }

    /// The owner check over every combination of pid and namespace,
    /// including the unreadable links this host cannot produce (ADR-030,
    /// D1).
    #[test]
    fn owner_comparison_table() {
        let ns = Some((5, 4_026_531_836));
        let owner = |pid, pid_ns| Owner { pid, pid_ns };
        let cases = [
            ("the owner itself", owner(1, ns), owner(1, ns), true),
            (
                "other pid, same namespace",
                owner(1, ns),
                owner(2, ns),
                false,
            ),
            (
                "same pid, other namespace inode",
                owner(1, ns),
                owner(1, Some((5, 4_026_533_368))),
                false,
            ),
            (
                "same pid and inode, other device",
                owner(1, ns),
                owner(1, Some((6, 4_026_531_836))),
                false,
            ),
            (
                "readable at acquire, unreadable at drop",
                owner(1, ns),
                owner(1, None),
                false,
            ),
            (
                "unreadable at acquire, readable at drop",
                owner(1, None),
                owner(1, ns),
                false,
            ),
            (
                "unreadable at both, same pid",
                owner(1, None),
                owner(1, None),
                false,
            ),
            (
                "unreadable at both, other pid",
                owner(1, None),
                owner(2, None),
                false,
            ),
        ];
        for (name, recorded, now, unlocks) in cases {
            assert_eq!(owns(&recorded, &now), unlocks, "{name}");
        }
    }

    /// The owner carries this process's pid and pid namespace, the one
    /// `/proc/self/ns/pid` names.
    #[test]
    fn owner_reads_the_pid_namespace() {
        let meta = fs::metadata("/proc/self/ns/pid").expect("the pid namespace link");
        let owner = Owner::current();
        assert_eq!(owner.pid, std::process::id());
        assert_eq!(owner.pid_ns, Some((meta.dev(), meta.ino())));
    }

    /// A lock taken on one thread and dropped on another unlocks: the
    /// owner is the process, not the thread.
    #[test]
    fn drop_on_another_thread_unlocks() {
        let scratch = Scratch::new("other-thread");
        let path = scratch.file("lock");
        let lock = FileLock::try_take(open(&path), Kind::Exclusive).expect("free");
        let _holder = Holder::spawn(lock.file());
        std::thread::spawn(move || drop(lock))
            .join()
            .expect("the dropping thread");
        assert!(!is_held(&path));
    }

    /// A `HandOff` dropped before `hand_on`, while a child holds a copy of
    /// its last lock, releases every lock it took at once (#98).
    #[test]
    fn hand_off_dropped_early_releases_with_a_child_copy() {
        let scratch = Scratch::new("hand-off-early");
        let (a, b) = (scratch.file("a"), scratch.file("b"));
        let mut taken = HandOff::new();
        taken.try_take(open(&a), Kind::Shared).expect("a");
        taken.try_take(open(&b), Kind::Shared).expect("b");
        let _holders = [
            Holder::spawn(&taken.files[0]),
            Holder::spawn(taken.last().expect("b is last")),
        ];
        assert!(is_held(&a) && is_held(&b));
        drop(taken);
        assert!(!is_held(&a), "the child's copy kept a locked");
        assert!(!is_held(&b), "the child's copy kept b locked");
    }

    /// A `HandOff` dropped by a process that did not take its locks leaves
    /// them held.
    #[test]
    fn foreign_hand_off_drop_keeps_its_pins() {
        let scratch = Scratch::new("hand-off-foreign");
        let path = scratch.file("lock");
        let mut taken = HandOff::new();
        taken.try_take(open(&path), Kind::Shared).expect("free");
        let same = taken.files[0]
            .try_clone()
            .expect("a copy of the description");
        taken.owner.pid = taken.owner.pid.wrapping_add(1);
        drop(taken);
        assert!(is_held(&path), "a foreign drop released the pin");
        same.unlock().expect("unlock the copy");
        assert!(!is_held(&path));
    }

    /// Handed-on descriptors keep their locks after the `HandOff` is gone,
    /// and a holder's `LOCK_UN` releases its own lock only.
    #[test]
    fn handed_on_descriptors_keep_their_locks() {
        let scratch = Scratch::new("hand-on");
        let (a, b) = (scratch.file("a"), scratch.file("b"));
        let mut taken = HandOff::new();
        taken.try_take(open(&a), Kind::Shared).expect("a");
        taken.try_take(open(&b), Kind::Shared).expect("b");
        let fds = taken.hand_on();
        assert_eq!(fds.len(), 2);
        assert!(is_held(&a) && is_held(&b), "handing on released a lock");
        let mut files = fds.into_iter().map(File::from);
        let first = files.next().expect("a");
        let second = files.next().expect("b");
        first.unlock().expect("a holder's unlock");
        assert!(!is_held(&a));
        assert!(is_held(&b), "one holder's unlock released another lock");
        second.unlock().expect("unlock b");
    }

    /// An empty `HandOff` hands on nothing, and its drop does nothing.
    #[test]
    fn empty_hand_off() {
        assert!(HandOff::new().last().is_none());
        assert!(HandOff::default().hand_on().is_empty());
        drop(HandOff::new());
    }

    /// A deadline already past still tries once: a free lock is taken, a
    /// held one is `Busy` at once.
    #[test]
    fn take_until_past_deadline_tries_once() {
        let scratch = Scratch::new("past-deadline");
        let path = scratch.file("lock");
        for kind in [Kind::Shared, Kind::Exclusive] {
            let past = Instant::now();
            let lock = FileLock::take_until(open(&path), kind, past).expect("free, so taken");
            assert!(is_held(&path), "{kind:?}");
            drop(lock);
        }
        let holder = FileLock::try_take(open(&path), Kind::Exclusive).expect("free");
        for kind in [Kind::Shared, Kind::Exclusive] {
            let started = Instant::now();
            match FileLock::take_until(open(&path), kind, started) {
                Err(TakeError::Busy) => {}
                other => panic!("{kind:?}: {other:?}"),
            }
            assert!(started.elapsed() < Duration::from_secs(1), "{kind:?}");
        }
        drop(holder);
    }

    /// A wait on a lock that is never released ends at its deadline, not a
    /// full pause or more past it; one released meanwhile is taken.
    #[test]
    fn take_until_ends_at_its_deadline() {
        let scratch = Scratch::new("deadline");
        let path = scratch.file("lock");
        let holder = FileLock::try_take(open(&path), Kind::Exclusive).expect("free");
        let wait = Duration::from_millis(300);
        for kind in [Kind::Shared, Kind::Exclusive] {
            let started = Instant::now();
            match FileLock::take_until(open(&path), kind, started + wait) {
                Err(TakeError::Busy) => {}
                other => panic!("{kind:?}: waited past a holder: {other:?}"),
            }
            let took = started.elapsed();
            assert!(took >= wait, "{kind:?}: gave up early: {took:?}");
            assert!(took < wait + Duration::from_secs(2), "{kind:?}: overslept");
        }
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(holder);
        });
        let lock = FileLock::take_until(open(&path), Kind::Exclusive, far()).expect("once free");
        releaser.join().expect("releaser");
        assert!(is_held(&path));
        drop(lock);
    }

    /// The pauses: 1, 2, 4, 8, 16, 32, 64 ms, then 100 ms (64 doubled is
    /// 128, capped). The first seven take 127 ms; a whole 120 s wait is
    /// 1,206 sleeps, the last one cut to what is left, and 1,207 tries
    /// (ADR-030, D3).
    #[test]
    fn poll_pauses_double_to_100_ms() {
        let mut pause = POLL_MIN;
        let mut seen = Vec::new();
        for _ in 0..9 {
            seen.push(pause.as_millis());
            pause = next_pause(pause);
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 32, 64, 100, 100]);
        assert_eq!(seen[..7].iter().sum::<u128>(), 127);

        let mut left = Duration::from_secs(120);
        let (mut pause, mut sleeps) = (POLL_MIN, 0u32);
        while !left.is_zero() {
            left -= pause.min(left);
            sleeps += 1;
            pause = next_pause(pause);
        }
        assert_eq!(sleeps, 1_206);
    }

    /// `WouldBlock` is `Busy`; any other failure of the lock call is `Io`,
    /// never `Busy`: an `O_PATH` descriptor, which `flock` refuses with
    /// `EBADF` (O_PATH is 0o10000000 on x86_64 and aarch64).
    #[test]
    fn busy_and_io_errors_differ() {
        const O_PATH: i32 = 0o10000000;
        let scratch = Scratch::new("errors");
        let path = scratch.file("lock");
        let holder = FileLock::try_take(open(&path), Kind::Exclusive).expect("free");
        for kind in [Kind::Shared, Kind::Exclusive] {
            assert!(
                matches!(FileLock::try_take(open(&path), kind), Err(TakeError::Busy)),
                "{kind:?}"
            );
            let mut taken = HandOff::new();
            assert!(
                matches!(taken.try_take(open(&path), kind), Err(TakeError::Busy)),
                "{kind:?}"
            );
            assert!(taken.last().is_none(), "{kind:?}: a busy file was kept");
        }
        drop(holder);
        let o_path = || {
            OpenOptions::new()
                .read(true)
                .custom_flags(O_PATH)
                .open(&path)
                .expect("an O_PATH descriptor")
        };
        for kind in [Kind::Shared, Kind::Exclusive] {
            match FileLock::try_take(o_path(), kind) {
                Err(TakeError::Io(e)) => assert_eq!(e.raw_os_error(), Some(9), "{kind:?}: {e}"),
                other => panic!("{kind:?}: {other:?}"),
            }
            match FileLock::take_until(o_path(), kind, far()) {
                Err(TakeError::Io(e)) => assert_eq!(e.raw_os_error(), Some(9), "{kind:?}: {e}"),
                other => panic!("{kind:?}: {other:?}"),
            }
            let mut taken = HandOff::new();
            match taken.try_take(o_path(), kind) {
                Err(TakeError::Io(e)) => assert_eq!(e.raw_os_error(), Some(9), "{kind:?}: {e}"),
                other => panic!("{kind:?}: {other:?}"),
            }
        }
        assert!(!is_held(&path));
    }
}
