//! Limits for untrusted input. They have no defaults: a registry's image
//! config, a Messages API request with images and a stream-json line differ
//! by orders of magnitude, so every consumer states and justifies its own
//! (ADR-008, D5).

use crate::error::{Error, ErrorKind};

/// The ceiling for `Limits::max_depth`, and the depth the serializer
/// refuses to exceed.
///
/// The parser and the serializer recurse, and `Clone`, `PartialEq`,
/// `Debug` and `Drop` of `Value` are recursive, so this bound is what keeps
/// every operation on a parsed value inside the stack. At 512 the deepest
/// operation in the test profile (parsing nested objects) uses 764,247
/// bytes, 73% of 1 MiB, half the stack std gives a spawned thread; the
/// measurement and the derivation are in ADR-008, D6, and
/// `tests/stack.rs` enforces it.
pub const MAX_DEPTH: usize = 512;

/// Limits on what one input may contain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    max_bytes: usize,
    max_depth: usize,
    max_values: usize,
}

impl Limits {
    /// Limits on one input:
    ///
    /// - `max_bytes`: the length of the whole input for `parse`, or of one
    ///   line without its `\n` for NDJSON; checked before anything else;
    /// - `max_depth`: how deeply arrays and objects nest (a scalar is 0,
    ///   `[]` is 1, `[[]]` is 2), at most `MAX_DEPTH`;
    /// - `max_values`: how many values the input holds, every scalar,
    ///   array, object and element once, keys not counted (`[1,2]` is 3,
    ///   `{"a":1}` is 2). It bounds the memory a parsed value takes
    ///   independently of `max_bytes` (ADR-008, D5).
    ///
    /// All three are inclusive. A zero is an error, because it would
    /// reject every input, and so is a `max_depth` above `MAX_DEPTH`.
    pub fn new(max_bytes: usize, max_depth: usize, max_values: usize) -> Result<Limits, Error> {
        if max_bytes == 0 || max_depth == 0 || max_values == 0 || max_depth > MAX_DEPTH {
            return Err(Error::new(ErrorKind::InvalidLimit, 0));
        }
        Ok(Limits {
            max_bytes,
            max_depth,
            max_values,
        })
    }

    /// The longest input, or NDJSON line, in bytes.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// The deepest nesting of arrays and objects.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// The most values in one input.
    pub fn max_values(&self) -> usize {
        self.max_values
    }
}
