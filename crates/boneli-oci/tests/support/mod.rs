//! Shared helpers of the `boneli-oci` integration tests.

#![allow(dead_code)]

pub mod images;
pub mod registry;
pub mod sandbox;
pub mod tarball;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A directory under `CARGO_TARGET_TMPDIR`, unique per process and call,
/// removed on drop even when the unpacker left directories with mode 0.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates `<CARGO_TARGET_TMPDIR>/<tag>-<pid>-<counter>`.
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("oci-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create the test's temp dir");
        TempDir { path }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        make_writable(&self.path);
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Gives every directory under `path` (not following symlinks) `u+rwx`, so
/// a test can look inside and remove it.
pub fn make_writable(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let mode = meta.permissions().mode() | 0o700;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            make_writable(&entry.path());
        }
    }
}
