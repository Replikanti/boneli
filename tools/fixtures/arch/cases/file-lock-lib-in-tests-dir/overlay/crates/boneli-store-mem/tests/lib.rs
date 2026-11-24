//! Fixture crate whose lib lives under tests/.
#![doc(test(attr(forbid(unsafe_code))))]

/// Takes the lock outside the shared lock type, which ADR-030 forbids.
pub fn take(file: &std::fs::File) -> std::io::Result<()> {
    file.lock()?;
    std::fs::File::unlock(file)
}
