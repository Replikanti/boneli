//! Fixture crate with a custom lib path.

/// Reads a byte.
pub fn read(p: *const u8) -> u8 {
    unsafe { *p }
}
