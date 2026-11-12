//! Fixture crate.
#![doc(test(attr(forbid(unsafe_code))))]

/// Reads through a raw pointer.
#[macro_export]
macro_rules! raw_read {
    ($p:expr) => {
        unsafe { *$p }
    };
}
