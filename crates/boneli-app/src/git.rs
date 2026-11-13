//! The `Git` port: the repository at the base commit, snapshots for the
//! sandbox, and diffs (ADR-004, D1; `docs/ARCHITECTURE.md`, "Debugging
//! line").
//!
//! Minimal on purpose: the real adapter (#30) owns the snapshot and diff
//! formats, and #19 adds branch push, both under the extension rule of
//! ADR-004.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use boneli_domain::CommitSha;

use crate::path::RelativePath;

/// Where the repository is fetched from. Opaque here; the adapter (#30)
/// decides which forms it accepts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RepoUrl(String);

impl RepoUrl {
    /// Wraps a repository location.
    pub fn new(url: String) -> RepoUrl {
        RepoUrl(url)
    }

    /// The location as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The adapter's handle to one tree: the base commit, or the base with a
/// diff applied. Opaque; the adapter issues it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheckoutId(String);

impl CheckoutId {
    /// Wraps a handle the adapter issued.
    pub fn new(id: String) -> CheckoutId {
        CheckoutId(id)
    }

    /// The handle as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why the git adapter did not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitError {
    /// The repository has no such commit.
    UnknownCommit,
    /// No checkout with this handle exists.
    UnknownCheckout,
    /// The fetch failed, or a workspace or diff could not be read or
    /// applied.
    Failed {
        /// What went wrong, as the adapter reports it.
        detail: String,
    },
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::UnknownCommit => f.write_str("the repository has no such commit"),
            GitError::UnknownCheckout => f.write_str("unknown checkout"),
            GitError::Failed { detail } => write!(f, "git failed: {detail}"),
        }
    }
}

impl core::error::Error for GitError {}

/// The repository, rebuilt from the base commit only.
pub trait Git {
    /// Fetches the base commit and nothing else, and checks it out.
    fn fetch_base(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError>;

    /// The content of a file in the checkout, or `None` when the checkout
    /// has no file at that path.
    fn read(&self, checkout: &CheckoutId, path: &RelativePath)
    -> Result<Option<Vec<u8>>, GitError>;

    /// The checkout as a workspace for the sandbox, without remotes, hooks
    /// or credentials.
    fn snapshot(&self, checkout: &CheckoutId) -> Result<Vec<u8>, GitError>;

    /// The diff from the checkout to a workspace in the snapshot format.
    /// Empty when the workspace is the checkout's own snapshot.
    fn diff(&self, checkout: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError>;

    /// Applies a diff to the checkout and returns a new checkout; the one
    /// it was applied to does not change.
    fn apply(&self, checkout: &CheckoutId, diff: &[u8]) -> Result<CheckoutId, GitError>;
}
