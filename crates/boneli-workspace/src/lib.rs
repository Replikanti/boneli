//! Boneli support crate: the workspace format (ADR-010, D2 and D3), moved
//! out of `boneli-git-cli` so that the sandbox adapter can use it too
//! (ADR-042, D1).
//!
//! A workspace is agent-controlled. The git adapter reads it on the host
//! as the runner user, who will hold the git token, and the sandbox copies
//! it into a sandbox and exports it from one.
//!
//! - [`Workspace`] is the snapshot and workspace format: a magic line and
//!   canonical, length-prefixed entries, each a file, an executable or a
//!   symlink. [`Workspace::decode`] refuses every malformed or
//!   non-canonical encoding, bounds the nodes (files, symlinks and the
//!   directories they imply) and checks every length against what is left
//!   before it allocates.
//! - [`PathRule`] is the path rule a workspace is checked against, passed
//!   in by the adapter as a type, so this crate depends on no core crate.
//!   Both adapters pass the tree path rule of ADR-018, under which a
//!   backslash, a blank name and a name that is not UTF-8 are carried.
//! - [`materialize`] writes a workspace into a new, empty, private
//!   directory: no symlink it created is ever followed, modes are
//!   explicit, each directory is made once, and an entry at or under a
//!   gitlink or more nodes than the cap is refused. Repository metadata is
//!   refused or carried, as the caller says ([`Metadata`]).
#![doc(test(attr(forbid(unsafe_code))))]

mod materialize;
#[cfg(test)]
mod scratch;
#[cfg(test)]
mod test_rule;
mod workspace;

pub use materialize::{DirectoryProblem, Item, MaterializeError, Metadata, materialize};
pub use workspace::{
    DEFAULT_MAX_NODES, DecodeError, EntryProblem, Kind, MAGIC, PathRule, Workspace,
};
