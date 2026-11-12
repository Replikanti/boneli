//! Fixture crate.
#![doc(test(attr(forbid(unsafe_code))))]

/// Reads a byte.
pub fn read(p: *const u8) -> u8 {
    unsafe { *p }
}
