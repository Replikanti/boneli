//! Fixture domain crate.
#![no_std]
#![doc(test(attr(forbid(unsafe_code))))]

pub mod extra;

/// In a static build the core re-exports an external crate.
#[cfg(target_feature = "crt-static")]
pub use leftpad as impure;
