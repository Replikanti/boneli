//! Fixture domain crate.
#![no_std]
#![doc(test(attr(forbid(unsafe_code))))]

pub mod extra;

/// Only in the no-std build.
#[cfg(target_os = "none")]
pub use leftpad as pad;
