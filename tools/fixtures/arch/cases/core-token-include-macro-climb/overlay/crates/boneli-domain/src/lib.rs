//! Fixture domain crate.
#![no_std]
#![doc(test(attr(forbid(unsafe_code))))]

pub mod extra;
mod inc;

/// Writes `x` with a format string read by a macro from another directory.
pub fn leak_inc(x: &u8, w: &mut dyn core::fmt::Write) -> core::fmt::Result {
    write!(w, inc::deep::grab!(), x)
}
