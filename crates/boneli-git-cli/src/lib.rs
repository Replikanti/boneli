//! Boneli adapter: the `Git` port over the git binary (#30, ADR-010).
//!
//! The workspace an agent returns from the sandbox is agent-controlled,
//! and this crate reads it on the host as the runner user, who will hold
//! the git token.
//!
//! - [`Workspace`] is the snapshot and workspace format (ADR-010, D2) of
//!   `boneli-workspace` under this crate's [`TreeRule`] (ADR-042, D1): a
//!   magic line and canonical, length-prefixed entries, each a file, an
//!   executable or a symlink. [`Workspace::decode`] refuses every
//!   malformed or non-canonical encoding, bounds the nodes (files,
//!   symlinks and the directories they imply) and checks every length
//!   against what is left before it allocates. Its paths are
//!   `TreePath`s, so a backslash, a blank name and a name that is not
//!   UTF-8 are carried (ADR-018).
//! - [`materialize`] writes a workspace into a new, empty, private
//!   directory under the rules of ADR-010, D3: no symlink it created is
//!   ever followed, modes are explicit, each directory is made once, and
//!   an entry at or under a gitlink or more nodes than the cap is refused;
//!   this crate passes `Metadata::Refuse`, so repository metadata is
//!   refused too.
//! - [`GitCli`] implements the port by running git (D4 to D7): every call
//!   gets a cleared, fixed environment and command-scope config and names
//!   its repository explicitly, so nothing in a workspace or in the host's
//!   environment steers it; [`Transports`] limits the URLs `fetch_base`
//!   takes; [`GitCli::open`] refuses a git older than [`MIN_GIT_VERSION`]
//!   and creates its root under a resolved parent whose ancestors no one
//!   else can rename, by the rules of `boneli-private-dir` (ADR-024).
//! - [`patch_between`] describes the change between two workspaces as the
//!   patch policy's input (ADR-013, D1), or a
//!   `boneli_domain::UnreadablePath` when a path it would carry is not
//!   UTF-8 (ADR-018, D5); `GitCli::patch_between` builds the same input
//!   from two checkouts' trees, gitlinks included (ADR-023, D4).
//! - `push` (ADR-014, D1 and D2) commits a checkout's tree on its base and
//!   creates a branch with it, never moving one that exists; with
//!   [`Credentials`] every network call gets an `Authorization` header
//!   scoped to the repository URL, in its environment only (D3).
#![doc(test(attr(forbid(unsafe_code))))]

mod cli;
mod credentials;
mod lookalike;
mod patch;
mod rule;
mod run;
mod url;

pub use boneli_workspace::{
    DEFAULT_MAX_NODES, DirectoryProblem, EntryProblem, Item, Kind, MAGIC, MaterializeError,
    Metadata, PathRule, materialize,
};
pub use cli::{GitCli, GitCliConfig, OpenError};
pub use credentials::{Credentials, MAX_AUTHORIZATION};
pub use patch::patch_between;
pub use rule::TreeRule;
pub use run::MIN_GIT_VERSION;
pub use url::{Transports, UrlProblem};

/// A workspace under the tree path rule (ADR-010 D2, ADR-018, ADR-042 D1).
pub type Workspace = boneli_workspace::Workspace<TreeRule>;

/// Why bytes are not an encoded workspace under the tree path rule.
pub type DecodeError = boneli_workspace::DecodeError<boneli_app::TreePathProblem>;
