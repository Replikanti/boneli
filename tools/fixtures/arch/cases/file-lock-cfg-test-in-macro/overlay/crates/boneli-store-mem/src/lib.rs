//! Fixture crate.
#![doc(test(attr(forbid(unsafe_code))))]

macro_rules! keep {
    ($($t:tt)*) => { $($t)* };
}

keep!(#[cfg(test)] mod t {
    fn take(file: &std::fs::File) {
        let _ = file.lock();
    }
});
