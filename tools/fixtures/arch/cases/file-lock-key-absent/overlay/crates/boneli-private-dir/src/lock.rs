//! The one file that may take file locks.

/// Takes and releases a lock.
pub fn take(file: &std::fs::File) -> std::io::Result<()> {
    file.try_lock_shared().map_err(std::io::Error::other)?;
    file.lock()?;
    std::fs::File::unlock(file)
}
