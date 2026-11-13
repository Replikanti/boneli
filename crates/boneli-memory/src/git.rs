//! [`MemoryGit`]: the `Git` port in memory, and its snapshot and diff
//! formats.
//!
//! A snapshot is a packed tree: for every file in path order, the path and
//! the content, each as its length in 8 big-endian bytes followed by the
//! bytes. A diff is a list of changes in path order: the path, then `1` and
//! the new content, or `0` for a removed file. The formats are this
//! adapter's own; the real adapter (#30) has its own. Unpacking checks
//! every length against what is left and every path against the citation
//! path rule ([`RelativePath`]), so a workspace from the sandbox cannot
//! name a path outside the tree.

use std::collections::BTreeMap;
use std::sync::Mutex;

use boneli_app::{CheckoutId, Git, GitError, RelativePath, RepoUrl};
use boneli_domain::CommitSha;

use crate::lock;

/// A tree: every file's content by path.
pub type Tree = BTreeMap<RelativePath, Vec<u8>>;

/// One commit a [`MemoryGit`] holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitCommit {
    /// The repository.
    pub repo: RepoUrl,
    /// The commit.
    pub sha: CommitSha,
    /// Its tree.
    pub files: Tree,
}

fn put_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}

/// Reads length-prefixed fields; every read checks what is left.
struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Fields<'a> {
    fn bytes(&mut self, n: usize, what: &str) -> Result<&'a [u8], String> {
        if self.rest.len() < n {
            return Err(format!(
                "{what}: {n} bytes wanted, {} left",
                self.rest.len()
            ));
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn field(&mut self, what: &str) -> Result<&'a [u8], String> {
        let mut length = [0u8; 8];
        length.copy_from_slice(self.bytes(8, what)?);
        let n = usize::try_from(u64::from_be_bytes(length))
            .map_err(|_| format!("{what}: the length does not fit in memory"))?;
        self.bytes(n, what)
    }

    fn path(&mut self) -> Result<RelativePath, String> {
        let raw = self.field("path")?;
        let text = std::str::from_utf8(raw).map_err(|_| String::from("a path is not UTF-8"))?;
        RelativePath::parse(text).map_err(|problem| format!("path {text:?}: {problem:?}"))
    }
}

/// Packs a tree into this adapter's snapshot format.
pub fn pack_tree(tree: &Tree) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, content) in tree {
        put_field(&mut out, path.as_str().as_bytes());
        put_field(&mut out, content);
    }
    out
}

/// Unpacks a workspace in this adapter's snapshot format. A path given
/// twice, a path the citation path rule rejects or a truncated field is an
/// error.
pub fn unpack_tree(packed: &[u8]) -> Result<Tree, String> {
    let mut fields = Fields { rest: packed };
    let mut tree = Tree::new();
    while !fields.rest.is_empty() {
        let path = fields.path()?;
        let content = fields.field("content")?.to_vec();
        if tree.contains_key(&path) {
            return Err(format!("path {:?} given twice", path.as_str()));
        }
        tree.insert(path, content);
    }
    Ok(tree)
}

/// The changes from `from` to `to`, in path order: `Some` is the new
/// content, `None` a removed file.
fn changes(from: &Tree, to: &Tree) -> Vec<(RelativePath, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    for (path, content) in to {
        if from.get(path) != Some(content) {
            out.push((path.clone(), Some(content.clone())));
        }
    }
    for path in from.keys() {
        if !to.contains_key(path) {
            out.push((path.clone(), None));
        }
    }
    out.sort();
    out
}

fn pack_diff(changes: &[(RelativePath, Option<Vec<u8>>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, content) in changes {
        put_field(&mut out, path.as_str().as_bytes());
        match content {
            Some(content) => {
                out.push(1);
                put_field(&mut out, content);
            }
            None => out.push(0),
        }
    }
    out
}

fn apply_diff(tree: &Tree, diff: &[u8]) -> Result<Tree, String> {
    let mut fields = Fields { rest: diff };
    let mut tree = tree.clone();
    while !fields.rest.is_empty() {
        let path = fields.path()?;
        match fields.bytes(1, "change")? {
            [1] => {
                tree.insert(path, fields.field("content")?.to_vec());
            }
            [0] => {
                if tree.remove(&path).is_none() {
                    return Err(format!("removes {:?}, which does not exist", path.as_str()));
                }
            }
            other => return Err(format!("unknown change {other:?}")),
        }
    }
    Ok(tree)
}

#[derive(Debug, Default)]
struct State {
    /// The number of the next checkout, starting at 1; never reused.
    next: u64,
    checkouts: BTreeMap<CheckoutId, Tree>,
}

/// A `Git` over fixed commits. Checkouts are `checkout-<n>` from a counter
/// starting at 1; applying a diff makes a new checkout and leaves the old
/// one as it was.
#[derive(Debug, Default)]
pub struct MemoryGit {
    commits: BTreeMap<(RepoUrl, CommitSha), Tree>,
    state: Mutex<State>,
}

impl MemoryGit {
    /// A git adapter that holds these commits; of two with the same
    /// repository and SHA, the later one counts.
    pub fn new(commits: Vec<GitCommit>) -> MemoryGit {
        MemoryGit {
            commits: commits
                .into_iter()
                .map(|c| ((c.repo, c.sha), c.files))
                .collect(),
            state: Mutex::new(State {
                next: 1,
                ..State::default()
            }),
        }
    }

    fn checkout(&self, tree: Tree) -> CheckoutId {
        let mut state = lock(&self.state);
        let n = state.next;
        state.next = n.saturating_add(1);
        let id = CheckoutId::new(format!("checkout-{n}"));
        state.checkouts.insert(id.clone(), tree);
        id
    }

    fn tree(&self, checkout: &CheckoutId) -> Result<Tree, GitError> {
        lock(&self.state)
            .checkouts
            .get(checkout)
            .cloned()
            .ok_or(GitError::UnknownCheckout)
    }
}

fn failed(detail: String) -> GitError {
    GitError::Failed { detail }
}

impl Git for MemoryGit {
    fn fetch_base(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError> {
        let key = (repo.clone(), base.clone());
        match self.commits.get(&key) {
            Some(tree) => Ok(self.checkout(tree.clone())),
            None if self.commits.keys().any(|(r, _)| r == repo) => Err(GitError::UnknownCommit),
            None => Err(failed(format!("unknown repository {:?}", repo.as_str()))),
        }
    }

    fn read(
        &self,
        checkout: &CheckoutId,
        path: &RelativePath,
    ) -> Result<Option<Vec<u8>>, GitError> {
        Ok(self.tree(checkout)?.get(path).cloned())
    }

    fn snapshot(&self, checkout: &CheckoutId) -> Result<Vec<u8>, GitError> {
        Ok(pack_tree(&self.tree(checkout)?))
    }

    fn diff(&self, checkout: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError> {
        let from = self.tree(checkout)?;
        let to = unpack_tree(workspace).map_err(|e| failed(format!("the workspace: {e}")))?;
        Ok(pack_diff(&changes(&from, &to)))
    }

    fn apply(&self, checkout: &CheckoutId, diff: &[u8]) -> Result<CheckoutId, GitError> {
        let tree = self.tree(checkout)?;
        let applied = apply_diff(&tree, diff).map_err(|e| failed(format!("the diff: {e}")))?;
        Ok(self.checkout(applied))
    }
}
