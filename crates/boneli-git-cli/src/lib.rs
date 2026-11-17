//! Boneli adapter: the `Git` port over the git binary (#30, ADR-010).
//!
//! The workspace an agent returns from the sandbox is agent-controlled,
//! and this crate reads it on the host as the runner user. Part 2 adds the
//! two pieces that touch those bytes before any git runs:
//!
//! - [`Workspace`] is the snapshot and workspace format (ADR-010, D2): a
//!   magic line and canonical, length-prefixed entries, each a file, an
//!   executable or a symlink. [`Workspace::decode`] refuses every
//!   malformed or non-canonical encoding, bounds the entry count and
//!   checks every length against what is left before it allocates.
//! - [`materialize`] writes a workspace into a new, empty, private
//!   directory under the rules of ADR-010, D3: no symlink it created is
//!   ever followed, modes are explicit, and repository metadata or an
//!   entry at or under a gitlink is refused.
//!
//! Part 3 adds the adapter that runs git.
#![doc(test(attr(forbid(unsafe_code))))]

mod materialize;
#[cfg(test)]
mod scratch;
mod workspace;

pub use materialize::{DirectoryProblem, Item, MaterializeError, materialize};
pub use workspace::{DEFAULT_MAX_ENTRIES, DecodeError, EntryProblem, Kind, MAGIC, Workspace};
