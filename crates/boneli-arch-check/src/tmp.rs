//! Temporary directories: `boneli arch <label> <unique>` in the system
//! temp directory, mode 0700, removed on drop. The space in the name keeps
//! every path the fixtures build exercising paths with a space (ADR-001,
//! D5).

use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A directory removed with its contents when dropped.
#[derive(Debug)]
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a new directory; tries the next name when one exists.
    pub(crate) fn create(label: &str) -> std::io::Result<TempDir> {
        let base = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let name = format!("boneli arch {label} {}-{n}-{nanos}", std::process::id());
            let path = base.join(name);
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(TempDir { path }),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        }
    }

    /// [`TempDir::create`] for tests, which panic when it fails.
    #[cfg(test)]
    pub(crate) fn new(label: &str) -> TempDir {
        TempDir::create(label).expect("temporary directory")
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
