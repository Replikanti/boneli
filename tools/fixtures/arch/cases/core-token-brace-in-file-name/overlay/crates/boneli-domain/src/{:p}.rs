//! Fixture domain crate.
#![no_std]
#![doc(test(attr(forbid(unsafe_code))))]

pub mod extra;

/// Writes `x` with this file's path as the format string.
pub fn leak_file(x: &u8, w: &mut dyn core::fmt::Write) -> core::fmt::Result {
    write!(w, file!(), x)
}
