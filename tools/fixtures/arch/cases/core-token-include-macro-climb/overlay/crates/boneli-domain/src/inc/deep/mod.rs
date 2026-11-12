//! A macro that reads a file.

/// Reads a file at compile time.
macro_rules! grab {
    () => {
        include_str!("../../../notes.txt")
    };
}
pub(crate) use grab;
