//! Temporary directories for the unit tests, removed on drop, panics
//! included, whatever modes the code under test left on them.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// `<temp dir>/boneli-oci-unit-<tag>-<pid>-<n>`, removed on drop with the
/// layer cache's own removal, which restores `u+rwx` on the way down.
pub(crate) struct ScratchDir(PathBuf);

impl ScratchDir {
    pub(crate) fn new(tag: &str) -> ScratchDir {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("boneli-oci-unit-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).expect("create the scratch dir");
        ScratchDir(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = crate::layers::remove_tree_bounded(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::ScratchDir;

    /// A test that panics with mode-0 directories in its scratch tree
    /// still leaves nothing behind.
    #[test]
    fn removed_on_panic_with_mode_0_directories() {
        let mut kept = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let dir = ScratchDir::new("panic");
            kept = Some(dir.path().to_path_buf());
            let locked = dir.path().join("a/b");
            std::fs::create_dir_all(&locked).expect("dirs");
            std::fs::write(locked.join("f"), b"x").expect("file");
            for p in [locked.clone(), dir.path().join("a")] {
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000))
                    .expect("chmod");
            }
            panic!("the test under test fails");
        }));
        assert!(result.is_err());
        let path = kept.expect("the scratch dir was made");
        assert!(!path.exists(), "{} left behind", path.display());
    }
}
