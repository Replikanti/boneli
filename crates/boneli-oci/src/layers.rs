//! The layer cache (ADR-009, D8): one directory per layer, keyed by its
//! `diff_id`, under `<root>/layers/sha256/<hex>`, with a sidecar
//! `<hex>.stats` next to it.
//!
//! A layer is unpacked into `<root>/tmp/<pid>.<starttime>.<n>/` while its
//! uncompressed stream is hashed. On a `diff_id` match the sidecar is
//! written (to a temporary file, then renamed), and then the directory is
//! renamed into place: that rename is the commit point. A mismatch or an
//! error removes the temporary tree. When another store committed the same
//! layer first, its directory stays and this one is discarded; the same
//! `diff_id` means the same bytes, so both trees are equal.

use std::fs::{self, DirBuilder, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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

impl LayerCache {
    /// The cache under `root`, creating `tmp/` and `layers/sha256/` with
    /// mode `0o700` where they are missing. The store (#7, part 3) checks
    /// the root itself: absolute, private, owned by the caller.
    pub fn new(root: &Path) -> Result<LayerCache, Error> {
        for dir in [root.join("tmp"), root.join("layers").join("sha256")] {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .map_err(|e| cache_err(&dir, e))?;
        }
        Ok(LayerCache {
            root: root.to_path_buf(),
        })
    }

    /// Where the layer with `diff_id` lives once committed.
    pub fn layer_path(&self, diff_id: &[u8; 32]) -> PathBuf {
        self.root.join("layers").join("sha256").join(hex(diff_id))
    }

    fn sidecar_path(&self, diff_id: &[u8; 32]) -> PathBuf {
        self.root
            .join("layers")
            .join("sha256")
            .join(format!("{}.stats", hex(diff_id)))
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
    /// against `diff_id` and commits it, charging `budget`.
    pub fn unpack(
        &self,
        diff_id: &[u8; 32],
        compression: Compression,
        blob: impl Read,
        budget: &mut Budget,
    ) -> Result<LayerStats, Error> {
        let tmp = self.temporary()?;
        let result = self.unpack_into(&tmp, diff_id, compression, blob, budget);
        if result.is_err() {
            remove_tree(&tmp);
        }
        result
    }

    /// A new, empty `tmp/<pid>.<starttime>.<n>` directory. The start time
    /// tells a live owner from a reused pid when the store cleans up.
    fn temporary(&self) -> Result<PathBuf, Error> {
        let start = own_start_time()?;
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = self
            .root
            .join("tmp")
            .join(format!("{}.{start}.{n}", std::process::id()));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| cache_err(&path, e))?;
        Ok(path)
    }

    fn unpack_into(
        &self,
        tmp: &Path,
        diff_id: &[u8; 32],
        compression: Compression,
        blob: impl Read,
        budget: &mut Budget,
    ) -> Result<LayerStats, Error> {
        let stats = unpack(blob, compression, tmp, budget)?;
        if stats.diff_id != *diff_id {
            return Err(Error::DiffId {
                expected: format!("sha256:{}", hex(diff_id)),
                actual: format!("sha256:{}", hex(&stats.diff_id)),
            });
        }

        let sidecar = self.sidecar_path(diff_id);
        let staged = tmp.with_extension("stats");
        let text = format!(
            "bytes {}\nentries {}\nskipped-devices {}\n",
            stats.bytes, stats.entries, stats.skipped_devices
        );
        fs::write(&staged, text).map_err(|e| cache_err(&staged, e))?;
        let renamed = fs::rename(&staged, &sidecar).map_err(|e| cache_err(&sidecar, e));
        if renamed.is_err() {
            let _ = fs::remove_file(&staged);
        }
        renamed?;

        // Moving a directory to another parent rewrites its `..`, which
        // needs write permission on it: a root without u+w gets it for
        // the rename only.
        let final_path = self.layer_path(diff_id);
        let mode = fs::symlink_metadata(tmp)
            .map_err(|e| cache_err(tmp, e))?
            .permissions()
            .mode()
            & 0o7777;
        let lifted = mode & 0o200 == 0;
        if lifted {
            fs::set_permissions(tmp, Permissions::from_mode(mode | 0o200))
                .map_err(|e| cache_err(tmp, e))?;
        }
        match fs::rename(tmp, &final_path) {
            Ok(()) => {
                if lifted {
                    fs::set_permissions(&final_path, Permissions::from_mode(mode))
                        .map_err(|e| cache_err(&final_path, e))?;
                }
                Ok(stats)
            }
            Err(e) if final_path.is_dir() => {
                // Another store committed this layer first.
                let _ = e;
                remove_tree(tmp);
                self.cached(diff_id)?
                    .ok_or_else(|| Error::Sidecar(self.sidecar_path(diff_id)))
            }
            Err(e) => Err(cache_err(&final_path, e)),
        }
    }
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

/// Removes a temporary tree whose directories may have any final mode:
/// first every directory gets `u+rwx`, then the tree goes. Best effort;
/// the store removes what is left of dead processes when it opens.
fn remove_tree(path: &Path) {
    make_owner_rwx(path);
    let _ = fs::remove_dir_all(path);
}

fn make_owner_rwx(path: &Path) {
    let Ok(m) = fs::symlink_metadata(path) else {
        return;
    };
    if !m.file_type().is_dir() {
        return;
    }
    let mode = m.permissions().mode() & 0o7777;
    let _ = fs::set_permissions(path, Permissions::from_mode(mode | 0o700));
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            make_owner_rwx(&entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{own_start_time, parse_sidecar};

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
