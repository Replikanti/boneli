//! The trust directory (ADR-033, item 6): a private directory under the
//! root rules of ADR-021 that holds `trusted_root.json`, and under `tuf/`
//! the stored root, timestamp and snapshot (the fetched bytes unchanged)
//! and the pin of the initial root; and `lock`, which the whole refresh
//! holds. The lock is in the trust directory itself, not under `tuf/`, so
//! removing `tuf/` (the documented remedy) never frees it: a second refresh
//! stays "busy" while the first runs. Before every read and write the
//! refresh checks that the trust directory, `tuf/` and the lock file are
//! still the inodes it locked, so a refresh whose directory was removed or
//! replaced under it writes nothing more there (ADR-033, item 6).
//!
//! Every write goes to a temporary name in the same directory, created
//! anew with mode 0600, then `sync_all`, a rename over the final name and
//! a sync of the directory, so a reader sees the old file or the new one,
//! never a part, and a crash leaves at most a temporary file that the next
//! refresh removes under the lock, once the pin check has passed: a
//! directory set up from another pin keeps even those (ADR-041, R1).
//!
//! No component of a trust directory's path is a `tuf` entry (ADR-041,
//! R2): its name is not `tuf` in any ASCII case, and it is not the entry
//! its parent's `tuf` names, which catches what a case-folding filesystem
//! folds to `tuf`. So no trust directory is another's `tuf/` or lies
//! inside it, where the other refresh's sweep or the documented remedy
//! (remove `tuf/`) would reach it. The rule runs on the path as given, as
//! it would be created and as resolved. A refused path leaves nothing
//! behind: the first two forms are refused before anything is created,
//! and what only the resolved form shows (a name a case-folding
//! filesystem folds to `tuf`) is removed again, empty directories only.
//!
//! A path cannot show an alias, such as a bind mount of another root's
//! `tuf/`. So R2 also reads contents, before anything is written: a trust
//! directory that holds TUF state (`pin`, `root.json`, ...) is another
//! one's `tuf/`, and a `tuf/` that holds `lock`, `trusted_root.json` or
//! `tuf` is another trust directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{self, Path, PathBuf};

use boneli_private_dir::lock::{FileLock, Kind, TakeError};

/// The installed file, in the trust directory.
pub(crate) const TRUSTED_ROOT: &str = "trusted_root.json";
/// The TUF state, under the trust directory.
pub(crate) const TUF: &str = "tuf";
/// The stored root, timestamp and snapshot, and the pin, under `tuf/`.
pub(crate) const ROOT: &str = "root.json";
pub(crate) const TIMESTAMP: &str = "timestamp.json";
pub(crate) const SNAPSHOT: &str = "snapshot.json";
pub(crate) const PIN: &str = "pin";
/// The lock file, in the trust directory, never under `tuf/`.
const LOCK: &str = "lock";
/// The prefix of every temporary name. Under the lock no other refresh
/// writes, so one fixed name per file suffices, and every name with this
/// prefix in the two directories is a crashed run's.
const TEMP_PREFIX: &str = ".tmp-";

/// Why the trust directory could not be opened: a fixed sentence and the
/// path, or the lock is held.
#[derive(Debug)]
pub(crate) enum OpenError {
    /// The directory or a path in it breaks a rule, or the filesystem
    /// failed.
    Dir(String),
    /// Another refresh holds the lock.
    Busy,
}

/// Why a read or write of the trust directory failed.
#[derive(Debug)]
pub(crate) enum StateError {
    /// The trust directory, `tuf/` or the lock file is no longer the inode
    /// this refresh locked: removed, or replaced by another one.
    Replaced(&'static str),
    /// The filesystem failed.
    Io(io::Error),
}

impl From<io::Error> for StateError {
    fn from(e: io::Error) -> StateError {
        StateError::Io(e)
    }
}

/// A file's `(st_dev, st_ino)`.
type Identity = (u64, u64);

fn identity(meta: &fs::Metadata) -> Identity {
    (meta.dev(), meta.ino())
}

/// The trust directory, opened under its lock. The lock is released when
/// this drops.
#[derive(Debug)]
pub(crate) struct TrustDir {
    root: PathBuf,
    tuf: PathBuf,
    lock_path: PathBuf,
    /// What [`check_held`](Self::check_held) compares: the trust
    /// directory, `tuf/` and the lock file as they were locked.
    held: [Identity; 3],
    _lock: FileLock,
}

impl TrustDir {
    /// Checks `dir` by ADR-021 (`prepare_root`: absolute, no `.` or `..`
    /// component, `0o700` and the caller's, every ancestor not writable by
    /// others unless sticky), creating it where it is missing; takes the
    /// exclusive lock on `<dir>/lock` without waiting; creates `tuf/`;
    /// records the identities of the three. `dir` must pass the `tuf` rule
    /// of ADR-041 (R2) in each form `prepare_root` checks. What a crashed
    /// run left is removed by [`sweep`](Self::sweep), which the refresh
    /// calls after the pin check.
    pub(crate) fn open(dir: &Path) -> Result<TrustDir, OpenError> {
        let root = prepare(dir, &tuf_rule)?;
        content_rule(&root)?;
        let lock_path = root.join(LOCK);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|e| dir_err(&lock_path, &e))?;
        let lock_meta = file.metadata().map_err(|e| dir_err(&lock_path, &e))?;
        if !lock_meta.is_file() {
            return Err(OpenError::Dir(format!(
                "{}: the lock must be a regular file",
                lock_path.display()
            )));
        }
        let lock = match FileLock::try_take(file, Kind::Exclusive) {
            Ok(lock) => lock,
            Err(TakeError::Busy) => return Err(OpenError::Busy),
            Err(TakeError::Io(e)) => return Err(dir_err(&lock_path, &e)),
        };
        let tuf = root.join(TUF);
        boneli_private_dir::create(&tuf).map_err(|e| OpenError::Dir(e.to_string()))?;
        let tuf_meta = fs::symlink_metadata(&tuf).map_err(|e| dir_err(&tuf, &e))?;
        if !tuf_meta.is_dir() {
            return Err(OpenError::Dir(format!(
                "{}: must be a directory, not a symlink",
                tuf.display()
            )));
        }
        let root_meta = fs::symlink_metadata(&root).map_err(|e| dir_err(&root, &e))?;
        let held = [
            identity(&root_meta),
            identity(&tuf_meta),
            identity(&lock_meta),
        ];
        let dir = TrustDir {
            root,
            tuf,
            lock_path,
            held,
            _lock: lock,
        };
        Ok(dir)
    }

    /// Removes what a crashed run left: every name with the temporary
    /// prefix in the trust directory and in `tuf/`, not recursively. A
    /// directory replaced since the lock is not swept. The refresh calls
    /// it after the pin check and before its first write, whose
    /// `create_new` a leftover temporary file would fail (ADR-041, R1).
    pub(crate) fn sweep(&self) -> Result<(), StateError> {
        self.check_held()?;
        sweep(&self.root)?;
        sweep(&self.tuf)?;
        Ok(())
    }

    /// Fails with [`StateError::Replaced`] when the trust directory,
    /// `tuf/` or the lock file is missing or another inode than the one
    /// locked: an operator removed `tuf/` or the whole directory during
    /// the refresh, and perhaps another refresh set up a new one, whose
    /// state this one must not write into. std has no `openat`, so a window
    /// stays open from this check through the whole write it guards (the
    /// temporary file is created by path, written, synced and renamed). It
    /// is reachable only when the whole trust directory is removed and a
    /// new refresh recreates it inside that span, not by removing `tuf/`
    /// (the lock stays held), and only by the runner's own uid, which owns
    /// the `0700` directory and can already write `trusted_root.json`
    /// (ADR-033, item 6).
    pub(crate) fn check_held(&self) -> Result<(), StateError> {
        let paths = [&self.root, &self.tuf, &self.lock_path];
        for (path, held) in paths.into_iter().zip(self.held) {
            match fs::symlink_metadata(path) {
                Ok(meta) if identity(&meta) == held => {}
                Ok(_) => return Err(StateError::Replaced(REPLACED)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(StateError::Replaced(REPLACED));
                }
                Err(e) => return Err(StateError::Io(e)),
            }
        }
        Ok(())
    }

    /// The bytes of `tuf/<name>`: `Ok(None)` when it is missing, and
    /// `Ok(Some(None))` when it is longer than `max`, which the caller
    /// treats as a copy that does not parse.
    pub(crate) fn read_tuf(
        &self,
        name: &str,
        max: usize,
    ) -> Result<Option<Option<Vec<u8>>>, StateError> {
        self.check_held()?;
        Ok(read_capped(&self.tuf.join(name), max as u64)?)
    }

    /// Writes `tuf/<name>` durably.
    pub(crate) fn write_tuf(&self, name: &str, bytes: &[u8]) -> Result<(), StateError> {
        self.check_held()?;
        Ok(write_durably(&self.tuf, name, bytes)?)
    }

    /// Removes `tuf/<name>` durably; a missing file is no error.
    pub(crate) fn remove_tuf(&self, name: &str) -> Result<(), StateError> {
        self.check_held()?;
        match fs::remove_file(self.tuf.join(name)) {
            Ok(()) => Ok(sync_dir(&self.tuf)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The bytes of the installed `trusted_root.json` when it is a regular
    /// file of at most `max` bytes; `None` otherwise (missing, a symlink,
    /// a directory, or longer), so it is not the current target. A
    /// symlink is never followed.
    pub(crate) fn installed(&self, max: u64) -> Result<Option<Vec<u8>>, StateError> {
        self.check_held()?;
        let path = self.root.join(TRUSTED_ROOT);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        Ok(read_capped(&path, max)?.flatten())
    }

    /// Installs `trusted_root.json` durably: a rename over the old name,
    /// which replaces a symlink there and never follows it.
    pub(crate) fn install(&self, bytes: &[u8]) -> Result<(), StateError> {
        self.check_held()?;
        Ok(write_durably(&self.root, TRUSTED_ROOT, bytes)?)
    }
}

/// The reason of [`StateError::Replaced`].
const REPLACED: &str = "the trust directory, its tuf/ or its lock was removed or replaced \
     during the refresh, so this refresh writes nothing more there";

fn dir_err(path: &Path, e: &io::Error) -> OpenError {
    OpenError::Dir(format!("{}: {e}", path.display()))
}

/// `prepare_root` under `rule`, leaving nothing behind when it refuses.
/// `prepare_root` creates a missing directory before it checks the
/// resolved form, and only that check can see a name that a case-folding
/// filesystem folds to `tuf` (as given and as it would be created, the
/// name and its parent's `tuf` are both missing). So on any refusal the
/// directories of `dir`'s tail that were missing before the call are
/// removed again, deepest first, each only while empty, so no state is
/// ever removed: a directory another process made there in the meantime
/// and wrote into stays (ADR-041, R2).
fn prepare(
    dir: &Path,
    rule: &dyn Fn(&Path) -> Result<(), &'static str>,
) -> Result<PathBuf, OpenError> {
    // A relative path or one with `.` or `..` is refused before anything
    // is created, and its text does not name what creation would make.
    let undoable = dir.is_absolute()
        && !dir
            .components()
            .any(|c| matches!(c, path::Component::CurDir | path::Component::ParentDir));
    let missing: Vec<&Path> = if undoable {
        dir.ancestors()
            .take_while(|a| {
                matches!(fs::symlink_metadata(a), Err(e) if e.kind() == io::ErrorKind::NotFound)
            })
            .collect()
    } else {
        Vec::new()
    };
    boneli_private_dir::prepare_root(dir, rule).map_err(|e| {
        for created in &missing {
            let _ = fs::remove_dir(created);
        }
        OpenError::Dir(e.to_string())
    })
}

/// The TUF state names under `tuf/`, and the entries of a trust
/// directory itself (ADR-041, R2 by content).
const TUF_STATE: [&str; 4] = [PIN, ROOT, TIMESTAMP, SNAPSHOT];
const TRUST_DIR_ENTRIES: [&str; 3] = [LOCK, TRUSTED_ROOT, TUF];

/// R2 by content (ADR-041): `root` must not hold a trust directory's TUF
/// state (it would be another trust directory's `tuf/`), and its `tuf/`
/// must not hold a trust directory's own entries (it would be another
/// trust directory). A name counts in its final and its temporary form.
/// This catches the aliases no path can show, such as a bind mount of
/// another root's `tuf/` or of its whole trust directory one level too
/// deep, once that root has written its first file. It runs before
/// anything is written to `root`.
fn content_rule(root: &Path) -> Result<(), OpenError> {
    if let Some(name) = holds(root, &TUF_STATE)? {
        return Err(OpenError::Dir(format!(
            "{}: holds the TUF state of a trust directory ({name}), so it is another trust \
             directory's tuf/ reached by another path (ADR-041)",
            root.display()
        )));
    }
    let tuf = root.join(TUF);
    if fs::symlink_metadata(&tuf).is_ok_and(|m| m.is_dir())
        && let Some(name) = holds(&tuf, &TRUST_DIR_ENTRIES)?
    {
        return Err(OpenError::Dir(format!(
            "{}: holds a trust directory ({name}), so the trust directory is another one's \
             tuf/ or this tuf/ is another trust directory (ADR-041)",
            tuf.display()
        )));
    }
    Ok(())
}

/// The first of `names` that `dir` holds, as given or behind
/// [`TEMP_PREFIX`].
fn holds(dir: &Path, names: &[&'static str]) -> Result<Option<&'static str>, OpenError> {
    for entry in fs::read_dir(dir).map_err(|e| dir_err(dir, &e))? {
        let entry = entry.map_err(|e| dir_err(dir, &e))?;
        let file_name = entry.file_name();
        let bytes = file_name.as_encoded_bytes();
        let bare = bytes.strip_prefix(TEMP_PREFIX.as_bytes()).unwrap_or(bytes);
        if let Some(name) = names.iter().find(|n| n.as_bytes() == bare) {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// The reasons of the `tuf` rule (ADR-041, R2).
const IS_TUF: &str = "must not be, or lie inside, a directory named tuf: that name holds a \
     trust directory's TUF state (ADR-041)";
const TUF_UNCHECKED: &str = "a component of the path could not be compared with its parent's \
     tuf entry, so the tuf rule cannot pass (ADR-041)";

/// What the `tuf` rule knows of one component of a path: its name, and
/// the identity of the component and of its parent's `tuf` entry, each
/// `Ok(None)` when missing and `Err(())` when it could not be read.
#[derive(Clone, Copy, Debug)]
struct Component<'a> {
    name: &'a [u8],
    identity: Result<Option<Identity>, ()>,
    parent_tuf: Result<Option<Identity>, ()>,
}

/// The `tuf` rule of ADR-041 (R2) as `prepare_root`'s text rule: no
/// component of `path` other than `/` is a `tuf` entry. `prepare_root`
/// calls it on the path as given, as it would be created and as
/// resolved; [`prepare`] removes again what a refusal of the resolved
/// form leaves.
fn tuf_rule(path: &Path) -> Result<(), &'static str> {
    tuf_problem(path.ancestors().filter_map(|at| {
        let name = at.file_name()?;
        let parent_tuf = at.parent().map_or(Ok(None), |p| stat(&p.join(TUF)));
        Some(Component {
            name: name.as_encoded_bytes(),
            identity: stat(at),
            parent_tuf,
        })
    }))
}

/// The decision of the `tuf` rule over the facts of each component: a
/// name equal to `tuf` ignoring ASCII case, or the entry the parent's
/// `tuf` names, refuses; so does a component whose facts could not be
/// read (fail closed).
fn tuf_problem<'a>(
    components: impl IntoIterator<Item = Component<'a>>,
) -> Result<(), &'static str> {
    for c in components {
        if c.name.eq_ignore_ascii_case(TUF.as_bytes()) {
            return Err(IS_TUF);
        }
        match (c.identity, c.parent_tuf) {
            (Err(()), _) | (_, Err(())) => return Err(TUF_UNCHECKED),
            (Ok(Some(it)), Ok(Some(tuf))) if it == tuf => return Err(IS_TUF),
            _ => {}
        }
    }
    Ok(())
}

/// The identity of `path` itself, a symlink not followed: `Ok(None)` when
/// it is missing, `Err(())` on any other failure.
fn stat(path: &Path) -> Result<Option<Identity>, ()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(identity(&meta))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

/// Removes every file in `dir` whose name starts with [`TEMP_PREFIX`]. A
/// name whose removal fails stays: it is never read, and failing the
/// refresh for it would leave the directory stuck until removed by hand.
/// Safe only under the lock.
fn sweep(dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry
            .file_name()
            .as_encoded_bytes()
            .starts_with(TEMP_PREFIX.as_bytes())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// `fsync` of a directory, so the entries created, renamed or removed in
/// it are durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// The bytes of `path`: `None` when it is missing, `Some(None)` when it is
/// longer than `max`. Never more than `max + 1` bytes are read.
fn read_capped(path: &Path, max: u64) -> io::Result<Option<Option<Vec<u8>>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok(Some((bytes.len() as u64 <= max).then_some(bytes)))
}

/// Writes `bytes` to `.tmp-<name>` in `dir` (created anew, mode 0600),
/// syncs it, renames it to `name` and syncs `dir`. On a failure before
/// the rename the temporary file is removed and `name` is as it was; after
/// it only the sync of `dir` can fail, and `name` holds the new bytes.
fn write_durably(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temp = dir.join(format!("{TEMP_PREFIX}{name}"));
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            f.sync_all()
        })
        .and_then(|()| fs::rename(&temp, dir.join(name)))
        .and_then(|()| sync_dir(dir));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A component named `name` whose identity is `it` and whose parent's
    /// `tuf` entry is `tuf`.
    fn c(
        name: &[u8],
        it: Result<Option<Identity>, ()>,
        tuf: Result<Option<Identity>, ()>,
    ) -> Component<'_> {
        Component {
            name,
            identity: it,
            parent_tuf: tuf,
        }
    }

    /// A component that exists and is not its parent's `tuf` entry.
    fn plain(name: &[u8]) -> Component<'_> {
        c(name, Ok(Some((1, 10))), Ok(Some((1, 11))))
    }

    #[test]
    fn tuf_rule_by_name() {
        assert_eq!(tuf_problem([]), Ok(()));
        assert_eq!(tuf_problem([plain(b"trust"), plain(b"home")]), Ok(()));
        for name in [&b"tuf"[..], b"TUF", b"Tuf", b"tUf", b"tuF"] {
            // As the last component, as an ancestor, existing or missing.
            assert_eq!(tuf_problem([plain(name)]), Err(IS_TUF), "{name:?}");
            assert_eq!(
                tuf_problem([plain(b"github"), plain(name), plain(b"base")]),
                Err(IS_TUF),
                "{name:?}"
            );
            assert_eq!(
                tuf_problem([c(name, Ok(None), Ok(None))]),
                Err(IS_TUF),
                "{name:?}"
            );
        }
        for name in [
            &b"tuff"[..],
            b".tuf",
            b"tuf.d",
            b"tu",
            b"tu\xff",
            "tuf\u{200b}".as_bytes(),
            "\u{ff54}\u{ff55}\u{ff46}".as_bytes(),
        ] {
            assert_eq!(tuf_problem([plain(name)]), Ok(()), "{name:?}");
        }
        // Missing components and missing parents' entries pass.
        assert_eq!(
            tuf_problem([
                c(b"github", Ok(None), Ok(None)),
                c(b"base", Ok(Some((1, 3))), Ok(None)),
            ]),
            Ok(())
        );
    }

    #[test]
    fn tuf_rule_by_identity() {
        // What a case-folding filesystem resolves to the parent's `tuf`.
        for name in [&b"TUF"[..], "tu\u{200d}f".as_bytes(), b"github"] {
            let same = c(name, Ok(Some((7, 42))), Ok(Some((7, 42))));
            assert_eq!(tuf_problem([same]), Err(IS_TUF), "{name:?}");
            assert_eq!(
                tuf_problem([plain(b"x"), same, plain(b"base")]),
                Err(IS_TUF),
                "{name:?}"
            );
        }
        // Same inode on another device, or another inode: not the entry.
        for other in [(8, 42), (7, 43)] {
            assert_eq!(
                tuf_problem([c(b"github", Ok(Some((7, 42))), Ok(Some(other)))]),
                Ok(())
            );
        }
        // A fact that could not be read refuses, never passes.
        for unread in [
            c(b"github", Err(()), Ok(None)),
            c(b"github", Ok(Some((1, 2))), Err(())),
            c(b"github", Err(()), Err(())),
        ] {
            assert_eq!(tuf_problem([unread]), Err(TUF_UNCHECKED));
            assert_eq!(
                tuf_problem([plain(b"x"), unread, plain(b"base")]),
                Err(TUF_UNCHECKED)
            );
        }
    }

    /// Review run 1 of #137: a path that only the check of the resolved
    /// form refuses, such as a name a case-folding filesystem folds to
    /// `tuf`, leaves nothing behind: the directories this call created are
    /// removed again, and a directory that was there before stays. The
    /// rule here refuses an existing `folded`, as the resolved check
    /// refuses the folded name once it exists.
    #[test]
    fn refused_after_creation_leaves_nothing() {
        let base = std::env::temp_dir().join(format!("boneli-tuf-undo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("kept")).expect("dirs");
        fs::create_dir_all(base.join("before/folded")).expect("dirs");
        let rule = |p: &Path| {
            if p.file_name() == Some(std::ffi::OsStr::new("folded")) && p.exists() {
                Err("folded")
            } else {
                Ok(())
            }
        };
        let outcome = [
            prepare(&base.join("new/deeper/folded"), &rule).map(|_| ()),
            prepare(&base.join("kept/folded"), &rule).map(|_| ()),
            prepare(&base.join("before/folded"), &rule).map(|_| ()),
        ];
        let left = [
            base.join("new").exists(),
            base.join("kept").exists(),
            base.join("kept/folded").exists(),
            base.join("before/folded").exists(),
        ];
        let plain = prepare(&base.join("new/plain"), &rule).map(|_| ());
        let made = base.join("new/plain").is_dir();
        let _ = fs::remove_dir_all(&base);
        for result in outcome {
            match result {
                Err(OpenError::Dir(why)) => assert!(why.contains("folded"), "{why}"),
                other => panic!("refused: {other:?}"),
            }
        }
        assert_eq!(left, [false, true, false, true]);
        assert!(plain.is_ok(), "{plain:?}");
        assert!(made, "a path that passes is created");
    }

    /// Review run 2 of #137: the removal after a refusal takes only empty
    /// directories. A file written into a directory this call created
    /// (here by the rule itself, standing in for another process) keeps
    /// that directory and the file; the created directories below it that
    /// stayed empty are still removed.
    #[test]
    fn refused_after_creation_keeps_what_was_written() {
        let base =
            std::env::temp_dir().join(format!("boneli-tuf-undo-kept-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("base");
        let written = base.join("new/state");
        let rule = |p: &Path| {
            if p.file_name() == Some(std::ffi::OsStr::new("folded")) && p.exists() {
                fs::write(&written, b"another process's").expect("write");
                Err("folded")
            } else {
                Ok(())
            }
        };
        let outcome = prepare(&base.join("new/deeper/folded"), &rule).map(|_| ());
        let left = (
            fs::read(&written).ok(),
            base.join("new/deeper/folded").exists(),
            base.join("new/deeper").exists(),
        );
        let _ = fs::remove_dir_all(&base);
        assert!(matches!(outcome, Err(OpenError::Dir(_))), "{outcome:?}");
        assert_eq!(left, (Some(b"another process's".to_vec()), false, false));
    }

    /// The facts `tuf_rule` gathers on a real filesystem: a missing path
    /// passes, an entry under a regular file is refused (its stat fails
    /// with `ENOTDIR`), and the parent's `tuf` itself is refused by name.
    #[test]
    fn tuf_rule_on_paths() {
        let base = std::env::temp_dir().join(format!("boneli-tuf-rule-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("tuf")).expect("dirs");
        fs::write(base.join("file"), b"").expect("file");
        let outcome = [
            tuf_rule(&base.join("missing/trust")),
            tuf_rule(&base.join("file/trust")),
            tuf_rule(&base.join("tuf")),
            tuf_rule(&base.join("tuf/trust")),
            tuf_rule(&base.join("trust")),
        ];
        let _ = fs::remove_dir_all(&base);
        assert_eq!(
            outcome,
            [Ok(()), Err(TUF_UNCHECKED), Err(IS_TUF), Err(IS_TUF), Ok(())]
        );
    }
}
