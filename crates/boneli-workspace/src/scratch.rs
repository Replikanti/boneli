//! Temporary directories for the unit tests, removed on drop.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// `<temp dir>/boneli-workspace-unit-<tag>-<pid>-<n>`, removed on drop.
/// `remove_dir_all` does not follow symlinks, so a test that plants a
/// symlink to `/` removes only the link.
pub(crate) struct ScratchDir(PathBuf);

impl ScratchDir {
    pub(crate) fn new(tag: &str) -> ScratchDir {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "boneli-workspace-unit-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create the scratch dir");
        ScratchDir(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
