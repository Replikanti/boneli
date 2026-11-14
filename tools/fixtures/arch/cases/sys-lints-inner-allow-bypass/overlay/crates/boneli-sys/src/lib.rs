//! Fixture crate.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, clippy::unwrap_used)]

/// Two unsafe operations in one block, no SAFETY comment, an unwrap.
pub fn parents() -> core::num::NonZeroI32 {
    let v = unsafe { libc_getpid() + libc_getppid() };
    core::num::NonZeroI32::new(v).unwrap()
}

unsafe fn libc_getpid() -> i32 {
    1
}

unsafe fn libc_getppid() -> i32 {
    1
}
