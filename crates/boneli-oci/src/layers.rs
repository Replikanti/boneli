//! The layer cache (ADR-009, D8): one directory per layer, keyed by its
//! `diff_id`, under `<root>/layers/sha256/<hex>`, with a sidecar
//! `<hex>.stats` next to it.
//!
//! A layer is unpacked into `<root>/layers/sha256/.tmp-<pid>.<starttime>.<n>/`
//! while its uncompressed stream is hashed; lookups use hex names only, so
//! they never see a dot name. On a `diff_id` match the sidecar is written
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
    /// The cache under `root`, creating `layers/sha256/` with mode `0o700`
    /// where it is missing. The store (#7, part 3) checks the root itself:
    /// absolute, private, owned by the caller.
    ///
    /// Refuses a `layers/sha256/` where names alias each other (a
    /// case-insensitive or normalizing directory, D8): there a symlink
    /// named `A` replaces the directory `a`. Probed by creating one name
    /// and looking up its case-folded and its decomposed form.
    pub fn new(root: &Path) -> Result<LayerCache, Error> {
        let layers = root.join("layers").join("sha256");
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&layers)
            .map_err(|e| cache_err(&layers, e))?;
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        for (created, alias) in [
            (
                format!(".probe-case-{pid}-{n}"),
                format!(".PROBE-CASE-{pid}-{n}"),
            ),
            (
                format!(".probe-\u{e9}-{pid}-{n}"),
                format!(".probe-e\u{301}-{pid}-{n}"),
            ),
        ] {
            let probe = layers.join(&created);
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&probe)
                .map_err(|e| cache_err(&probe, e))?;
            let aliased = fs::symlink_metadata(layers.join(&alias));
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

    /// A new, empty `layers/sha256/.tmp-<pid>.<starttime>.<n>` directory
    /// and its descriptor. The start time tells a live owner from a reused
    /// pid when the store cleans up.
    fn temporary(&self) -> Result<Staging, Error> {
        let start = own_start_time()?;
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!(".tmp-{}.{start}.{n}", std::process::id());
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
    let bad = || cache_err(path, io::Error::other("unreadable start time"));
    // The command name may contain spaces and parentheses; the fields
    // after the last ')' start with field 3.
    let after = stat
        .iter()
        .rposition(|&b| b == b')')
        .and_then(|i| stat.get(i + 1..))
        .ok_or_else(bad)?;
    let text = std::str::from_utf8(after).map_err(|_| bad())?;
    text.split_ascii_whitespace()
        .nth(22 - 3)
        .and_then(|f| f.parse().ok())
        .ok_or_else(bad)
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
    use super::{own_start_time, parse_sidecar};

    /// Every directory is listed once, so removing a wide tree is linear:
    /// 1,000 sibling directories take 1,001 listings, not one listing of
    /// the parent per child (review measured 28 s for 80,000).
    #[test]
    fn removal_lists_each_directory_once() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("boneli-oci-unit-remove-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
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
