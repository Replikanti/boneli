//! The `Git` port: the repository at the base commit, snapshots for the
//! sandbox, and diffs (ADR-004, D1; `docs/ARCHITECTURE.md`, "Debugging
//! line").
//!
//! Minimal on purpose: the real adapter (#30) owns the snapshot and diff
//! formats, both under the extension rule of ADR-004. #19 adds branch push
//! (ADR-014, D1): [`Git::push`] commits a checkout's tree on top of its
//! base and creates a [`BranchName`] under [`BRANCH_PREFIX`] with it,
//! never moving a branch that exists.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use boneli_domain::CommitSha;
use boneli_domain::values::is_blank;

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

/// Every branch the port pushes starts with this (ADR-014, D2), so no
/// push can name `main` or any branch a human owns.
pub const BRANCH_PREFIX: &str = "boneli/";

/// The longest part of a [`BranchName`] after [`BRANCH_PREFIX`], in bytes
/// (ADR-014, D2).
pub const MAX_BRANCH_SUFFIX: usize = 100;

/// A branch the port may create: [`BRANCH_PREFIX`], then one component of
/// 1 to [`MAX_BRANCH_SUFFIX`] bytes of `[a-z0-9._-]` that starts and ends
/// with `[a-z0-9]`, holds no `..` and does not end in `.lock`. That is a
/// strict subset of what `git check-ref-format --branch` accepts, and of
/// what a forge accepts as a branch name (ADR-014, D2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BranchName(String);

impl BranchName {
    /// The branch, or `None` for any other form.
    pub fn parse(name: &str) -> Option<BranchName> {
        let suffix = name.strip_prefix(BRANCH_PREFIX)?;
        let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        let inner = |b: &u8| edge(b) || matches!(b, b'.' | b'_' | b'-');
        let bytes = suffix.as_bytes();
        let ok = (1..=MAX_BRANCH_SUFFIX).contains(&bytes.len())
            && bytes.iter().all(inner)
            && bytes.first().is_some_and(edge)
            && bytes.last().is_some_and(edge)
            && !suffix.contains("..")
            && !suffix.ends_with(".lock");
        ok.then(|| BranchName(String::from(name)))
    }

    /// The full name, prefix included.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The longest author name of a [`CommitInfo`], in bytes (ADR-014, D2).
pub const MAX_COMMIT_NAME: usize = 128;

/// The longest author email of a [`CommitInfo`], in bytes (ADR-014, D2).
pub const MAX_COMMIT_EMAIL: usize = 254;

/// The longest commit message of a [`CommitInfo`], in bytes (ADR-014, D2).
pub const MAX_COMMIT_MESSAGE: usize = 65_536;

/// Who a pushed commit is by, and its message; the author is also the
/// committer (ADR-014, D2).
///
/// - The name is 1 to [`MAX_COMMIT_NAME`] bytes, not blank, with no
///   control character, `<` or `>`, which would end git's ident early.
/// - The email is 3 to [`MAX_COMMIT_EMAIL`] bytes of visible ASCII
///   (`0x21`-`0x7E`), contains `@` and has no `<` or `>`.
/// - The message is not blank, has no NUL and is at most
///   [`MAX_COMMIT_MESSAGE`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitInfo {
    name: String,
    email: String,
    message: String,
}

impl CommitInfo {
    /// The commit's identity and message, or `None` when a rule above
    /// fails.
    pub fn new(name: &str, email: &str, message: &str) -> Option<CommitInfo> {
        let name_ok = (1..=MAX_COMMIT_NAME).contains(&name.len())
            && !is_blank(name)
            && !name.chars().any(|c| c.is_control() || c == '<' || c == '>');
        let email_ok = (3..=MAX_COMMIT_EMAIL).contains(&email.len())
            && email
                .bytes()
                .all(|b| (0x21..=0x7E).contains(&b) && b != b'<' && b != b'>')
            && email.contains('@');
        let message_ok =
            message.len() <= MAX_COMMIT_MESSAGE && !is_blank(message) && !message.contains('\0');
        (name_ok && email_ok && message_ok).then(|| CommitInfo {
            name: String::from(name),
            email: String::from(email),
            message: String::from(message),
        })
    }

    /// The author and committer name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The author and committer email.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// The commit message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Why the git adapter did not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitError {
    /// The repository answered and has no commit with this id: the id is
    /// absent there, or names a tree, blob or tag. An adapter reports it
    /// only on evidence that the id is at fault, and reports a failure
    /// that may pass on a retry as `Failed`. Residual of the git adapter
    /// (ADR-010, D6): a remote that lists its refs, then fails both the
    /// fetch of a commit that is not a tip and the probe fetch of that
    /// commit alone (a remote that ignores `--filter` and a full disk, or
    /// a connection cut twice), is reported here too, so a caller that
    /// got the SHA from the forge may retry once before it reports the
    /// SHA as wrong.
    UnknownCommit,
    /// No checkout with this handle exists.
    UnknownCheckout,
    /// `push` found the branch on the remote already; nothing was pushed
    /// and the branch was left as it was (ADR-014, D2).
    BranchExists,
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
            GitError::BranchExists => f.write_str("the branch already exists"),
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
    ///
    /// The workspace comes from the sandbox, where the agent writes. Its
    /// repository metadata ([`RelativePath::is_repository_metadata`]) is
    /// not content and never steers the adapter's git: it is left out of
    /// the diff, nothing it names (a hook, `core.fsmonitor`) runs, and no
    /// later operation follows its config (ADR-010, D1).
    fn diff(&self, checkout: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError>;

    /// Applies a diff to the checkout and returns a new checkout; the one
    /// it was applied to does not change. A diff that does not apply to
    /// this checkout (for example, one that removes a file the checkout
    /// does not have) is an error: no checkout is created and nothing
    /// changes, so a fix is never verified on a tree it was not written
    /// against.
    fn apply(&self, checkout: &CheckoutId, diff: &[u8]) -> Result<CheckoutId, GitError>;

    /// Commits the checkout's tree with its base commit as the only parent
    /// and pushes that commit to a new branch of the repository the base
    /// was fetched from; returns the commit. Create-only: when the branch
    /// exists it is [`GitError::BranchExists`], and the branch is neither
    /// overwritten nor fast-forwarded (ADR-014, D1 and D2).
    fn push(
        &self,
        checkout: &CheckoutId,
        branch: &BranchName,
        commit: &CommitInfo,
    ) -> Result<CommitSha, GitError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::ToString;

    fn suffix(n: usize) -> String {
        let mut s = String::from("a");
        while s.len() < n {
            s.push('b');
        }
        s
    }

    #[test]
    fn branch_name_accepts_the_forge_form() {
        for name in [
            "boneli/run-1-0123abcd",
            "boneli/a",
            "boneli/0",
            "boneli/a.b",
            "boneli/a_b",
            "boneli/a-b",
            "boneli/run-7-ffffffff",
            "boneli/contract-push-reads-back",
            "boneli/a.lockx",
            "boneli/a.locka.b",
        ] {
            let got = BranchName::parse(name).map(|b| b.as_str().to_string());
            assert_eq!(got.as_deref(), Some(name), "{name:?}");
        }
    }

    #[test]
    fn branch_name_refuses_hostile_forms() {
        for name in [
            "boneli/",
            "main",
            "refs/heads/main",
            "Boneli/a",
            "boneli/a..b",
            "boneli/a.lock",
            "boneli/.a",
            "boneli/a/b",
            "boneli/a b",
            "boneli/a\u{200B}",
            "boneli/\u{0430}",
            "boneli/A",
            "boneli/a.",
            "boneli/-a",
            "boneli/a-",
            "boneli/_a",
            "boneli/a@{1}",
            "boneli/a~1",
            "boneli/a^",
            "boneli/a:b",
            "boneli/a?",
            "boneli/a*",
            "boneli/a[",
            "boneli/a\\b",
            "boneli/a\u{0}",
            "boneli/a\n",
            "boneli//a",
            " boneli/a",
            "boneli/a ",
            "",
            "boneli",
            "x/boneli/a",
        ] {
            assert_eq!(BranchName::parse(name), None, "{name:?}");
        }
    }

    #[test]
    fn branch_name_length_bound() {
        let at = format!("{BRANCH_PREFIX}{}", suffix(MAX_BRANCH_SUFFIX));
        assert_eq!(at.len(), 107);
        assert!(BranchName::parse(&at).is_some());
        let over = format!("{BRANCH_PREFIX}{}", suffix(MAX_BRANCH_SUFFIX + 1));
        assert_eq!(BranchName::parse(&over), None);
    }

    #[test]
    fn commit_info_rules() {
        let email = "1+app[bot]@users.noreply.github.com";
        let ok = |n: &str, e: &str, m: &str| CommitInfo::new(n, e, m).is_some();
        assert!(ok("app[bot]", email, "boneli: fix\n\nRun r-1\n"));
        let info = CommitInfo::new("A B", "a@b", "m").expect("valid");
        assert_eq!(
            (info.name(), info.email(), info.message()),
            ("A B", "a@b", "m")
        );
        // Name.
        assert!(ok(&"n".repeat(MAX_COMMIT_NAME), email, "m"));
        assert!(!ok(&"n".repeat(MAX_COMMIT_NAME + 1), email, "m"));
        assert!(ok("\u{17E}", email, "m"));
        for name in [
            "", " ", "\u{200B}", "a<b", "a>b", "a\nb", "a\u{0}", "a\u{7F}", "a\tb",
        ] {
            assert!(!ok(name, email, "m"), "{name:?}");
        }
        // Email.
        assert!(ok("n", "a@b", "m"));
        assert!(!ok("n", "@b", "m"));
        assert!(!ok("n", "abc", "m"));
        let long = format!("{}@b", "a".repeat(MAX_COMMIT_EMAIL - 2));
        assert_eq!(long.len(), MAX_COMMIT_EMAIL);
        assert!(ok("n", &long, "m"));
        assert!(!ok("n", &format!("a{long}"), "m"));
        for e in [
            "a @b",
            "a@b<",
            "<a@b",
            "a@b>",
            "a@\u{17E}",
            "a@b\n",
            "a@\u{7F}b",
        ] {
            assert!(!ok("n", e, "m"), "{e:?}");
        }
        // Message.
        assert!(ok("n", email, &"m".repeat(MAX_COMMIT_MESSAGE)));
        assert!(!ok("n", email, &"m".repeat(MAX_COMMIT_MESSAGE + 1)));
        for m in ["", " \n", "\u{FEFF}", "a\u{0}b"] {
            assert!(!ok("n", email, m), "{m:?}");
        }
    }
}
