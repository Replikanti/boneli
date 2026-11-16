//! The layer cache (ADR-009, D8): one directory per layer, keyed by its
//! `diff_id`, under `<root>/layers/sha256/<hex>`, with a sidecar
//! `<hex>.stats` next to it.
//!
//! A layer is unpacked into `<root>/layers/sha256/.tmp-<owner>.<n>/` while
//! its uncompressed stream is hashed, where `<owner>` names this process by
//! its PID namespace, pid and start time ([`Owner`]); lookups use hex names
//! only, so they never see a dot name. On a `diff_id` match the sidecar is written
//! (to a staged file, then renamed), and then the directory is renamed to
//! its hex name: that rename, within one directory, is the commit point.
//! One `syncfs` before the renames and an `fsync` of `layers/sha256/` after
//! each make the commit durable. A mismatch or an error removes the
//! temporary tree. When another store committed the same layer first, its
//! directory stays and this one is discarded; the same `diff_id` means the
//! same bytes, so both trees are equal.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::Error;
use crate::limits::Budget;
use crate::unpack::{Compression, LayerStats, unpack};

/// The layer cache under a store root.
#[derive(Debug, Clone)]
pub struct LayerCache {
    root: PathBuf,
}

static NEXT: AtomicU64 = AtomicU64::new(0);

fn hex(digest: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn cache_err(path: &Path, source: io::Error) -> Error {
    Error::Cache {
        path: path.to_path_buf(),
        source,
    }
}

/// A temporary tree being unpacked, with the descriptor `syncfs` runs on.
struct Staging {
    path: PathBuf,
    sidecar: PathBuf,
    /// Opened before anything is written into the tree, so the writeback
    /// error state it samples predates the layer's own writeback: an error
    /// another `syncfs` caller already saw is still reported to this one.
    dir: File,
}

impl LayerCache {
    /// The length of the name a layer is unpacked under before it is
    /// renamed to its 64 hex digits (D8). It is longer, so a committed
    /// layer's paths are shorter than the ones the unpacker created, and
    /// every one of them still fits `PATH_MAX`; a layer whose deepest path
    /// would not fit at the staging name is refused while it is unpacked.
    pub const STAGING_NAME_LEN: usize = TEMPORARY_NAME_LEN;

    /// The cache under `root`, creating `layers/sha256/` with mode `0o700`
    /// where it is missing. The store ([`crate::OciImageStore`]) checks the
    /// root itself: absolute, private, owned by the caller.
    ///
    /// Refuses a `layers/sha256/` where names alias each other (a
    /// case-insensitive or normalizing directory, D8): there a symlink
    /// named `A` replaces the directory `a`. Probed by creating one name
    /// and looking up its case-folded and its decomposed form. Probe names
    /// carry the owner (PID namespace, pid, start time) and a counter, and
    /// a name that exists is skipped, never removed here, so a crashed
    /// process's leftover blocks no later one; the store removes it once
    /// its owner is gone.
    pub fn new(root: &Path) -> Result<LayerCache, Error> {
        let layers = root.join("layers").join("sha256");
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&layers)
            .map_err(|e| cache_err(&layers, e))?;
        let owner = Owner::current()?;
        for (stem, alias_stem) in [
            (".probe-case-", ".PROBE-CASE-"),
            (".probe-\u{e9}-", ".probe-e\u{301}-"),
        ] {
            let (probe, n) = create_probe(&layers, &owner, stem)?;
            let alias = layers.join(format!("{alias_stem}{}.{n}", owner.token()));
            let aliased = fs::symlink_metadata(&alias);
            fs::remove_file(&probe).map_err(|e| cache_err(&probe, e))?;
            match aliased {
                Ok(_) => return Err(Error::CaseInsensitive(layers)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(cache_err(&layers, e)),
            }
        }
        Ok(LayerCache {
            root: root.to_path_buf(),
        })
    }

    fn layers_dir(&self) -> PathBuf {
        self.root.join("layers").join("sha256")
    }

    /// Where the layer with `diff_id` lives once committed.
    pub fn layer_path(&self, diff_id: &[u8; 32]) -> PathBuf {
        self.layers_dir().join(hex(diff_id))
    }

    fn sidecar_path(&self, diff_id: &[u8; 32]) -> PathBuf {
        self.layers_dir().join(format!("{}.stats", hex(diff_id)))
    }

    /// The totals of a committed layer from its sidecar, `None` if the
    /// layer is not in the cache.
    pub fn cached(&self, diff_id: &[u8; 32]) -> Result<Option<LayerStats>, Error> {
        let path = self.layer_path(diff_id);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => return Err(Error::Sidecar(path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(cache_err(&path, e)),
        }
        let sidecar = self.sidecar_path(diff_id);
        let text = fs::read(&sidecar).map_err(|e| cache_err(&sidecar, e))?;
        let (bytes, entries, skipped_devices) =
            parse_sidecar(&text).ok_or_else(|| Error::Sidecar(sidecar.clone()))?;
        Ok(Some(LayerStats {
            diff_id: *diff_id,
            bytes,
            entries,
            skipped_devices,
        }))
    }

    /// Unpacks the layer `blob`, compressed as `compression`, checks it
    /// against `diff_id` and commits it durably. `budget` is charged only
    /// when the layer is committed (or was committed by another store); on
    /// every error it is left as it was.
    pub fn unpack(
        &self,
        diff_id: &[u8; 32],
        compression: Compression,
        blob: impl Read,
        budget: &mut Budget,
    ) -> Result<LayerStats, Error> {
        let staging = self.temporary()?;
        let mut trial = budget.clone();
        let result = self.unpack_into(&staging, diff_id, compression, blob, &mut trial);
        match &result {
            Ok(stats) => {
                // The committed tree may be another store's; its sidecar
                // holds the same totals for the same bytes.
                let mut charged = budget.clone();
                charged.charge(stats)?;
                *budget = charged;
            }
            Err(_) => {
                remove_tree(&staging.path);
                let _ = fs::remove_file(&staging.sidecar);
            }
        }
        result
    }

    /// A new, empty `layers/sha256/.tmp-<owner>.<n>` directory and its
    /// descriptor. The owner tells the store's cleanup whose tree it is.
    fn temporary(&self) -> Result<Staging, Error> {
        let name = temporary_name()?;
        let path = self.layers_dir().join(&name);
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| cache_err(&path, e))?;
        let dir = match File::open(&path) {
            Ok(dir) => dir,
            Err(e) => {
                let _ = fs::remove_dir(&path);
                return Err(cache_err(&path, e));
            }
        };
        Ok(Staging {
            sidecar: self.layers_dir().join(format!("{name}.stats")),
            path,
            dir,
        })
    }

    /// The commit (D8). Before any rename, one `syncfs` makes the layer's
    /// data, its directory entries and the staged sidecar durable. The
    /// sidecar is renamed into place and its directory synced before the
    /// layer is, so a committed layer always has its sidecar; the layer's
    /// rename, the commit point, is synced last. Both renames stay within
    /// `layers/sha256/`, so a directory's `..` is never rewritten and a
    /// read-only layer root needs no write permission lent to it.
    fn unpack_into(
        &self,
        staging: &Staging,
        diff_id: &[u8; 32],
        compression: Compression,
        blob: impl Read,
        budget: &mut Budget,
    ) -> Result<LayerStats, Error> {
        let stats = unpack(blob, compression, &staging.path, budget)?;
        if stats.diff_id != *diff_id {
            return Err(Error::DiffId {
                expected: format!("sha256:{}", hex(diff_id)),
                actual: format!("sha256:{}", hex(&stats.diff_id)),
            });
        }

        let text = format!(
            "bytes {}\nentries {}\nskipped-devices {}\n",
            stats.bytes, stats.entries, stats.skipped_devices
        );
        fs::write(&staging.sidecar, text).map_err(|e| cache_err(&staging.sidecar, e))?;
        boneli_sys::sync_filesystem(&staging.dir).map_err(|e| Error::Sys {
            path: staging.path.display().to_string(),
            source: e,
        })?;

        let layers = self.layers_dir();
        let sidecar = self.sidecar_path(diff_id);
        fs::rename(&staging.sidecar, &sidecar).map_err(|e| cache_err(&sidecar, e))?;
        sync_dir(&layers)?;

        let final_path = self.layer_path(diff_id);
        match fs::rename(&staging.path, &final_path) {
            Ok(()) => {
                sync_dir(&layers)?;
                Ok(stats)
            }
            Err(_) if final_path.is_dir() => {
                // Another store committed this layer first.
                remove_tree(&staging.path);
                self.cached(diff_id)?
                    .ok_or_else(|| Error::Sidecar(self.sidecar_path(diff_id)))
            }
            Err(e) => Err(cache_err(&final_path, e)),
        }
    }
}

/// A new temporary name, `.tmp-<owner>.<n>`: a dot name, so lookups by hex
/// never see it, and one the store's cleanup can attribute to its owner
/// (D8). The registry client stages blobs under such names too. Its length
/// is fixed at [`TEMPORARY_NAME_LEN`], more than a committed layer's 64 hex
/// digits, so a tree that fit `PATH_MAX` while it was unpacked still fits
/// once it is renamed to its hex name.
pub(crate) fn temporary_name() -> Result<String, Error> {
    let owner = Owner::current()?;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    Ok(format!(".tmp-{}.{n:020}", owner.token()))
}

/// A new name `<stem><owner>.<n>` for a probe the store creates itself;
/// `stem` is one of [`OWNED_PREFIXES`].
pub(crate) fn owned_name(stem: &str) -> Result<String, Error> {
    let owner = Owner::current()?;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    Ok(format!("{stem}{}.{n:020}", owner.token()))
}

/// The length of every [`temporary_name`]: `.tmp-`, the 52 characters of an
/// owner token, a dot and a 20-digit counter.
pub(crate) const TEMPORARY_NAME_LEN: usize = 5 + OWNER_TOKEN_LEN + 1 + 20;

// A committed layer is named by 64 hex digits; its staging name is longer.
const _: () = assert!(TEMPORARY_NAME_LEN > 64);

/// The length of [`Owner::token`]: 20 + 1 + 10 + 1 + 20.
const OWNER_TOKEN_LEN: usize = 52;

/// The prefixes of the dot names this crate creates in `layers/sha256/`
/// and `blobs/sha256/`, each followed by an owner token: staging trees,
/// staged sidecars and blobs, and the probes of [`LayerCache::new`] and
/// the store.
pub(crate) const OWNED_PREFIXES: [&str; 5] = [
    ".tmp-",
    ".probe-case-",
    ".probe-\u{e9}-",
    ".probe-wh-",
    ".probe-opq-",
];

/// The process that owns a temporary name (D8): its PID namespace (the
/// inode of `/proc/self/ns/pid`), its pid in that namespace and its start
/// time in clock ticks since boot. The pid alone does not identify a
/// process: two runners in different PID namespaces can share a store and
/// have the same pid, and a pid is reused once its process is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Owner {
    pidns: u64,
    pid: u32,
    start: u64,
}

/// Whether the owner of a temporary name is alive, as far as this process
/// can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Liveness {
    /// It runs, or a process with its pid and start time does.
    Alive,
    /// It is gone: no process has its pid in this PID namespace, or the one
    /// that has it started at another time.
    Dead,
    /// It lives in another PID namespace, whose processes this one may not
    /// see, so nothing can be concluded and its names are left alone.
    Unknown,
}

impl Owner {
    /// This process.
    pub(crate) fn current() -> Result<Owner, Error> {
        Ok(Owner {
            pidns: own_pid_namespace()?,
            pid: std::process::id(),
            start: own_start_time()?,
        })
    }

    /// `<pidns>.<pid>.<start>`, zero-padded to fixed widths (20, 10 and 20
    /// digits), so every name built on it has one length.
    pub(crate) fn token(&self) -> String {
        format!("{:020}.{:010}.{:020}", self.pidns, self.pid, self.start)
    }

    /// The owner of a name `<prefix><token>.<n>` or
    /// `<prefix><token>.<n>.stats`, with a prefix of [`OWNED_PREFIXES`];
    /// `None` for any other name.
    pub(crate) fn of_name(name: &str) -> Option<Owner> {
        let rest = OWNED_PREFIXES
            .iter()
            .find_map(|prefix| name.strip_prefix(prefix))?;
        let mut fields = rest.split('.');
        let mut number = |width: usize| -> Option<u64> {
            let f = fields.next()?;
            (f.len() == width && f.bytes().all(|b| b.is_ascii_digit()))
                .then(|| f.parse().ok())
                .flatten()
        };
        let pidns = number(20)?;
        let pid = u32::try_from(number(10)?).ok()?;
        let start = number(20)?;
        number(20)?;
        match (fields.next(), fields.next()) {
            (None, _) | (Some("stats"), None) => Some(Owner { pidns, pid, start }),
            _ => None,
        }
    }

    /// Whether this owner is alive, seen from `me`. In `me`'s PID namespace
    /// the pid and the start time decide; in any other, nothing does.
    pub(crate) fn liveness(&self, me: &Owner) -> Liveness {
        if self.pidns != me.pidns {
            return Liveness::Unknown;
        }
        let path = PathBuf::from(format!("/proc/{}/stat", self.pid));
        match fs::read(&path) {
            Ok(stat) if start_time_of(&stat) == Some(self.start) => Liveness::Alive,
            // A process whose stat cannot be read for another reason than
            // its absence is alive as far as anyone can tell.
            Ok(stat) if start_time_of(&stat).is_none() => Liveness::Alive,
            Ok(_) => Liveness::Dead,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Liveness::Dead,
            Err(_) => Liveness::Alive,
        }
    }
}

/// How many probe names `create_probe` tries before it gives up.
const PROBE_ATTEMPTS: u32 = 1024;

/// Creates a new probe file `<stem><token>.<n>` in `layers` and returns it
/// with its `n`. A name that exists already is skipped, never removed here:
/// it is a leftover of a crashed process with the same identity, which the
/// store's cleanup removes once its owner is gone (D8).
pub(crate) fn create_probe(
    layers: &Path,
    owner: &Owner,
    stem: &str,
) -> Result<(PathBuf, String), Error> {
    for _ in 0..PROBE_ATTEMPTS {
        let n = format!("{:020}", NEXT.fetch_add(1, Ordering::Relaxed));
        let probe = layers.join(format!("{stem}{}.{n}", owner.token()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe)
        {
            Ok(_) => return Ok((probe, n)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(cache_err(&probe, e)),
        }
    }
    Err(cache_err(
        layers,
        io::Error::other("no free name for the case probe"),
    ))
}

/// Makes the entries of the directory `dir` durable.
fn sync_dir(dir: &Path) -> Result<(), Error> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| cache_err(dir, e))
}

/// `bytes N\nentries N\nskipped-devices N\n`, exactly.
fn parse_sidecar(text: &[u8]) -> Option<(u64, u64, u64)> {
    let text = std::str::from_utf8(text).ok()?;
    let mut lines = text.split_terminator('\n');
    let mut value = |key: &str| -> Option<u64> {
        let rest = lines.next()?.strip_prefix(key)?.strip_prefix(' ')?;
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        rest.parse().ok()
    };
    let parsed = (
        value("bytes")?,
        value("entries")?,
        value("skipped-devices")?,
    );
    (lines.next().is_none() && text.ends_with('\n')).then_some(parsed)
}

/// The start time of this process in clock ticks since boot, field 22 of
/// `/proc/self/stat`.
fn own_start_time() -> Result<u64, Error> {
    let path = Path::new("/proc/self/stat");
    let stat = fs::read(path).map_err(|e| cache_err(path, e))?;
    start_time_of(&stat).ok_or_else(|| cache_err(path, io::Error::other("unreadable start time")))
}

/// Field 22 of a `/proc/<pid>/stat` text, the start time.
fn start_time_of(stat: &[u8]) -> Option<u64> {
    // The command name may contain spaces and parentheses; the fields
    // after the last ')' start with field 3.
    let after = stat
        .iter()
        .rposition(|&b| b == b')')
        .and_then(|i| stat.get(i + 1..))?;
    let text = std::str::from_utf8(after).ok()?;
    text.split_ascii_whitespace()
        .nth(22 - 3)
        .and_then(|f| f.parse().ok())
}

/// The inode of this process's PID namespace, from the link
/// `/proc/self/ns/pid`, which reads `pid:[<inode>]`.
fn own_pid_namespace() -> Result<u64, Error> {
    let path = Path::new("/proc/self/ns/pid");
    let link = fs::read_link(path).map_err(|e| cache_err(path, e))?;
    link.to_str()
        .and_then(|l| l.strip_prefix("pid:["))
        .and_then(|l| l.strip_suffix(']'))
        .and_then(|l| l.parse().ok())
        .ok_or_else(|| cache_err(path, io::Error::other("unreadable PID namespace")))
}

/// Removes a temporary tree whose directories may have any final mode.
/// Best effort; the store removes what is left of dead processes when it
/// opens.
fn remove_tree(path: &Path) {
    let _ = remove_tree_bounded(path);
}

/// One directory on the way down: its path and the subdirectories still
/// to remove.
struct Level {
    path: PathBuf,
    subdirs: Vec<OsString>,
}

impl Level {
    /// Gives `path` `u+rwx` (final modes may be 0), lists it once, removes
    /// every entry that is not a directory, and keeps the names of the
    /// subdirectories. The listing's descriptor is closed when this
    /// returns.
    fn open(path: PathBuf) -> io::Result<Level> {
        let mode = fs::symlink_metadata(&path)?.permissions().mode() & 0o7777;
        if mode & 0o700 != 0o700 {
            fs::set_permissions(&path, Permissions::from_mode(mode | 0o700))?;
        }
        let mut subdirs = Vec::new();
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                subdirs.push(entry.file_name());
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(Level { path, subdirs })
    }
}

/// Removes `top` and everything under it and returns how many directories
/// it listed. It holds at most one directory descriptor at any time,
/// whatever the depth (std's `remove_dir_all` holds one per level), and
/// lists every directory exactly once, so a wide tree costs one pass. The
/// names of the subdirectories still to visit are kept in memory instead,
/// at most the tree's entry count. Paths are used throughout: every path
/// the unpacker created fits `PATH_MAX`.
pub(crate) fn remove_tree_bounded(top: &Path) -> io::Result<u64> {
    match fs::symlink_metadata(top) {
        Ok(m) if m.file_type().is_dir() => {}
        Ok(_) => return fs::remove_file(top).map(|()| 0),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    }
    let mut listings = 1;
    let mut chain = vec![Level::open(top.to_path_buf())?];
    while let Some(level) = chain.last_mut() {
        match level.subdirs.pop() {
            Some(name) => {
                let next = level.path.join(name);
                chain.push(Level::open(next)?);
                listings += 1;
            }
            None => {
                fs::remove_dir(&level.path)?;
                chain.pop();
            }
        }
    }
    Ok(listings)
}

#[cfg(test)]
mod tests {
    use super::{
        Liveness, OWNED_PREFIXES, Owner, TEMPORARY_NAME_LEN, own_start_time, parse_sidecar,
        temporary_name,
    };

    /// Every temporary name has one length, longer than a committed
    /// layer's 64 hex digits, so renaming a tree to its hex name never
    /// makes a path inside it longer (D8).
    #[test]
    fn temporary_names_are_longer_than_hex() {
        for _ in 0..3 {
            let name = temporary_name().expect("name");
            assert_eq!(name.len(), TEMPORARY_NAME_LEN, "{name}");
        }
    }

    /// Every owned name parses back to its owner; names with a missing,
    /// short, long or non-digit field, an unknown prefix or a suffix other
    /// than `.stats` carry no owner.
    #[test]
    fn owner_round_trips_through_names() {
        let me = Owner::current().expect("owner");
        let token = me.token();
        assert_eq!(token.len(), 52);
        for prefix in OWNED_PREFIXES {
            let name = format!("{prefix}{token}.{:020}", 7);
            assert_eq!(Owner::of_name(&name), Some(me), "{name}");
            assert_eq!(
                Owner::of_name(&format!("{name}.stats")),
                Some(me),
                "{name}.stats"
            );
        }
        let n = format!("{:020}", 7);
        for bad in [
            format!(".tmp-{token}"),
            format!(".tmp-{token}.7"),
            format!(".tmp-{token}.{n}.type"),
            format!(".tmp-{token}.{n}.stats.x"),
            format!(".tmp-{token}0.{n}"),
            format!(".TMP-{token}.{n}"),
            format!(".other-{token}.{n}"),
            format!(".tmp-{}.{n}", token.replacen('0', "x", 1)),
            format!(".tmp-{}.{n}", token.replacen('.', "-", 1)),
            ".tmp-1234.5678.0".to_owned(),
            format!(
                ".tmp-{:020}.{:010}.{:020}.{n}",
                1,
                u64::from(u32::MAX) + 1,
                1
            ),
        ] {
            assert_eq!(Owner::of_name(&bad), None, "{bad}");
        }
    }

    /// This process is alive; its pid with another start time is a reused
    /// pid, so dead; a pid no process has is dead; an owner in another PID
    /// namespace cannot be judged.
    #[test]
    fn liveness_rules() {
        let me = Owner::current().expect("owner");
        assert_eq!(me.liveness(&me), Liveness::Alive);
        let reused = Owner {
            start: me.start.wrapping_sub(1),
            ..me
        };
        assert_eq!(reused.liveness(&me), Liveness::Dead);
        let mut child = std::process::Command::new("true").spawn().expect("spawn");
        let pid = child.id();
        child.wait().expect("wait");
        let gone = Owner { pid, ..me };
        assert_eq!(gone.liveness(&me), Liveness::Dead);
        let foreign = Owner {
            pidns: me.pidns.wrapping_add(1),
            ..reused
        };
        assert_eq!(foreign.liveness(&me), Liveness::Unknown);
    }

    /// Every directory is listed once, so removing a wide tree is linear:
    /// 1,000 sibling directories take 1,001 listings, not one listing of
    /// the parent per child (review measured 28 s for 80,000).
    #[test]
    fn removal_lists_each_directory_once() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = crate::scratch::ScratchDir::new("remove");
        let root = scratch.path().join("tree");
        std::fs::create_dir(&root).expect("root");
        for i in 0..1000 {
            let d = root.join(format!("d{i}"));
            std::fs::create_dir(&d).expect("dir");
            std::fs::write(d.join("f"), b"x").expect("file");
        }
        std::fs::set_permissions(root.join("d7"), std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        let listings = super::remove_tree_bounded(&root).expect("removed");
        assert_eq!(listings, 1001);
        assert!(!root.exists());
    }

    #[test]
    fn sidecar_format() {
        assert_eq!(
            parse_sidecar(b"bytes 10\nentries 2\nskipped-devices 0\n"),
            Some((10, 2, 0))
        );
        for bad in [
            &b""[..],
            b"bytes 10\nentries 2\nskipped-devices 0",
            b"bytes 10\nentries 2\n",
            b"bytes +10\nentries 2\nskipped-devices 0\n",
            b"bytes 10\nentries 2\nskipped-devices 0\n\n",
            b"entries 2\nbytes 10\nskipped-devices 0\n",
            b"bytes  10\nentries 2\nskipped-devices 0\n",
            b"bytes 99999999999999999999\nentries 2\nskipped-devices 0\n",
        ] {
            assert_eq!(parse_sidecar(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn start_time_is_stable() {
        let a = own_start_time().expect("start time");
        assert_eq!(own_start_time().expect("start time"), a);
    }
}
