//! Limits for untrusted input. They have no defaults: a playbook, a Cargo
//! manifest of a contributor's pull request and a file an agent writes
//! differ in size and trust, so every consumer states and justifies its own
//! (ADR-011, D5).

use crate::error::{Error, ErrorKind};

/// The ceiling for `Limits::max_depth`.
///
/// The parser recurses through arrays and inline tables, and the move of
/// the parsed tree into a `Table`, `Clone`, `PartialEq`, `Debug` and
/// `Drop` of `Value` recurse too, so this bound keeps every operation on a
/// parsed value inside the stack. The deepest known document is 9 levels
/// deep; 128 is the next power of two above ten times that. The stack the
/// deepest operation needs at this depth, and the thread size it was
/// measured on, are in ADR-011, D6, and `tests/stack.rs` enforces them.
pub const MAX_DEPTH: usize = 128;

/// Limits on what one input may contain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    max_bytes: usize,
    max_depth: usize,
}

impl Limits {
    /// Limits on one input:
    ///
    /// - `max_bytes`: the length of the input, checked before anything
    ///   else;
    /// - `max_depth`: how deeply tables and arrays nest, at most
    ///   `MAX_DEPTH`. The document's root table is depth 1, and every
    ///   table or array below it adds 1, whether a header, a dotted key or
    ///   an inline value creates it: `a = 1` is 1, `a = []` and `[a]` are
    ///   2, `[[a]]` is 3 (the array and its element).
    ///
    /// Both are inclusive. A zero is an error, because it would reject
    /// every input, and so is a `max_depth` above `MAX_DEPTH`.
    pub fn new(max_bytes: usize, max_depth: usize) -> Result<Limits, Error> {
        if max_bytes == 0 || max_depth == 0 || max_depth > MAX_DEPTH {
            return Err(Error::without_input(ErrorKind::InvalidLimit));
        }
        Ok(Limits {
            max_bytes,
            max_depth,
        })
    }

    /// The longest input in bytes.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// The deepest nesting of tables and arrays.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }
}
