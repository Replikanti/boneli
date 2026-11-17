//! `GitCli`, the `Git` port over the git binary (ADR-010, D6 and D7).
//!
//! The adapter never gives git a working tree it did not build itself:
//!
//! - Each `fetch_base` makes a fresh bare store under `<root>/stores/` and
//!   fetches the base commit alone, depth 1, by URL: no remote, no refs,
//!   no `FETCH_HEAD`. A checkout is a tree id in a store, so a checkout
//!   never changes.
//! - `diff` decodes the workspace with the strict codec, drops repository
//!   metadata, refuses a name that is `.git` on another file system,
//!   writes the rest into a fresh `<root>/scratch/<n>` and runs
//!   `git add -A` there with an explicit `--git-dir`, a throwaway index
//!   and a throwaway object directory under `<root>/tmp/<n>`, so the store
//!   keeps nothing of the workspace. Both directories are removed on every
//!   path.
//! - `apply` is `git apply --cached` on a throwaway index.
//! - `snapshot` is the tree's files plus a generated one-commit `.git`
//!   with no remote, hook or credential.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use boneli_app::{CheckoutId, Git, GitError, RelativePath, RepoUrl};
use boneli_domain::CommitSha;

use crate::lookalike::names_git_elsewhere;
use crate::materialize::materialize;
use crate::run::{Call, MIN_GIT_VERSION, Runner, parse_version};
use crate::url::Transports;
use crate::workspace::{Kind, Workspace};

/// What `GitCli::open` needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitCliConfig {
    /// The git binary, an absolute path; `PATH` is never searched.
    pub git: PathBuf,
    /// The adapter's own directory. It must not exist; `open` creates it
    /// with mode 0700.
    pub root: PathBuf,
    /// The URL forms `fetch_base` accepts.
    pub transports: Transports,
    /// The node cap of a workspace and of a snapshot (ADR-010, D2):
    /// [`DEFAULT_MAX_NODES`](crate::DEFAULT_MAX_NODES) in production.
    pub max_workspace_nodes: usize,
}

/// Why `GitCli::open` refused.
#[derive(Debug)]
pub enum OpenError {
    /// The git path is relative.
    GitNotAbsolute,
    /// The root already exists.
    RootExists,
    /// The root could not be created.
    Io(std::io::Error),
    /// `git version` failed; the detail is its error.
    Git(String),
    /// git is older than [`MIN_GIT_VERSION`], or its version is
    /// unreadable.
    Version {
        /// What `git version` printed.
        found: String,
    },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::GitNotAbsolute => f.write_str("the git binary must be an absolute path"),
            OpenError::RootExists => f.write_str("the adapter root already exists"),
            OpenError::Io(e) => write!(f, "cannot create the adapter root: {e}"),
            OpenError::Git(detail) => write!(f, "git version failed: {detail}"),
            OpenError::Version { found } => {
                let (major, minor, patch) = MIN_GIT_VERSION;
                write!(
                    f,
                    "git {major}.{minor}.{patch} or newer is required, found {found:?}"
                )
            }
        }
    }
}

impl std::error::Error for OpenError {}

/// One fetched base commit: a bare store holding it and nothing newer.
#[derive(Debug)]
struct Store {
    dir: PathBuf,
    base: String,
    base_tree: String,
    sha256: bool,
}

/// A checkout: a tree in a store, the base's or an applied one.
#[derive(Clone, Debug)]
struct Checkout {
    store: Arc<Store>,
    tree: String,
}

#[derive(Debug, Default)]
struct State {
    issued: u64,
    checkouts: BTreeMap<CheckoutId, Checkout>,
}

/// The `Git` port over the git binary (#30, ADR-010).
#[derive(Debug)]
pub struct GitCli {
    root: PathBuf,
    runner: Runner,
    transports: Transports,
    max_nodes: usize,
    state: Mutex<State>,
    next_dir: AtomicU64,
}

/// `<path>` removed on drop unless kept.
struct Removed {
    path: PathBuf,
    keep: bool,
}

impl Removed {
    fn new(path: PathBuf) -> Removed {
        Removed { path, keep: false }
    }
}

impl Drop for Removed {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Creates a new directory with mode 0700, whatever the umask.
fn private_dir(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

fn failed(detail: impl Into<String>) -> GitError {
    GitError::Failed {
        detail: detail.into(),
    }
}

fn os(text: &str) -> &OsStr {
    OsStr::new(text)
}

/// One record of `git ls-tree -z`.
struct TreeEntry {
    mode: String,
    oid: String,
    path: Vec<u8>,
}

/// Parses `git ls-tree -z` output: `<mode> SP <type> SP <oid> TAB <path>`,
/// each record ended by NUL.
fn ls_tree(bytes: &[u8]) -> Result<Vec<TreeEntry>, GitError> {
    let bad = || failed("git ls-tree printed a record that is not <mode> <type> <oid>\\t<path>");
    let mut out = Vec::new();
    let mut records = bytes.split(|b| *b == 0);
    // The output ends with NUL, so the last piece is empty.
    let last = records.next_back();
    if last.is_some_and(|l| !l.is_empty()) {
        return Err(bad());
    }
    for record in records {
        let tab = record.iter().position(|b| *b == b'\t').ok_or_else(bad)?;
        let head = std::str::from_utf8(&record[..tab]).map_err(|_| bad())?;
        let mut fields = head.split(' ');
        let (Some(mode), Some(_kind), Some(oid), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(bad());
        };
        out.push(TreeEntry {
            mode: mode.to_owned(),
            oid: oid.to_owned(),
            path: record[tab + 1..].to_vec(),
        });
    }
    Ok(out)
}

/// A path git listed, as a `RelativePath`, or `Failed` naming it.
fn tree_path(raw: &[u8]) -> Result<RelativePath, GitError> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        failed(format!(
            "the tree has a path that is not UTF-8: {:?}",
            String::from_utf8_lossy(raw)
        ))
    })?;
    RelativePath::parse(text).map_err(|problem| {
        failed(format!(
            "the tree has a path a workspace cannot carry: {text:?} ({problem:?})"
        ))
    })
}

/// Whether `ls-remote` output, `<oid> TAB <ref>` lines, names `sha` as an
/// object id.
fn advertises(refs: &[u8], sha: &str) -> bool {
    refs.split(|b| *b == b'\n')
        .any(|line| line.split(|b| *b == b'\t').next() == Some(sha.as_bytes()))
}

/// The fixed config of a snapshot's `.git`: no remote, credential, URL,
/// http, include or hooks path.
fn snapshot_config(sha256: bool) -> String {
    let mut config = format!(
        "[core]\n\
         \trepositoryformatversion = {}\n\
         \tfilemode = true\n\
         \tbare = false\n\
         \tlogallrefupdates = true\n",
        if sha256 { 1 } else { 0 }
    );
    if sha256 {
        config.push_str("[extensions]\n\tobjectformat = sha256\n");
    }
    config
}

impl GitCli {
    /// Creates the root and checks the git version (ADR-010, D7).
    pub fn open(config: GitCliConfig) -> Result<GitCli, OpenError> {
        if !config.git.is_absolute() {
            return Err(OpenError::GitNotAbsolute);
        }
        let root = config.root;
        match private_dir(&root) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => return Err(OpenError::RootExists),
            Err(e) => return Err(OpenError::Io(e)),
        }
        // Created here, so removed here if `open` fails.
        let mut guard = Removed::new(root.clone());
        let home = root.join("home");
        for dir in [
            &home,
            &root.join("stores"),
            &root.join("scratch"),
            &root.join("tmp"),
        ] {
            private_dir(dir).map_err(OpenError::Io)?;
        }
        let runner = Runner::new(config.git, home, config.transports);
        let call = Call {
            git_dir: None,
            work_tree: None,
            index: None,
            objects: None,
            stdin: None,
        };
        let out = runner.run(call, &[os("version")]).map_err(OpenError::Git)?;
        let found = String::from_utf8_lossy(&out).trim().to_owned();
        match parse_version(&found) {
            Some(version) if version >= MIN_GIT_VERSION => {}
            _ => return Err(OpenError::Version { found }),
        }
        guard.keep = true;
        Ok(GitCli {
            root,
            runner,
            transports: config.transports,
            max_nodes: config.max_workspace_nodes,
            state: Mutex::new(State::default()),
            next_dir: AtomicU64::new(0),
        })
    }

    /// The adapter's root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn state(&self) -> Result<MutexGuard<'_, State>, GitError> {
        self.state
            .lock()
            .map_err(|_| failed("the adapter's checkout table is poisoned"))
    }

    fn checkout(&self, id: &CheckoutId) -> Result<Checkout, GitError> {
        self.state()?
            .checkouts
            .get(id)
            .cloned()
            .ok_or(GitError::UnknownCheckout)
    }

    /// Issues the next id for `checkout`; ids never repeat.
    fn issue(&self, checkout: Checkout) -> Result<CheckoutId, GitError> {
        let mut state = self.state()?;
        state.issued += 1;
        let id = CheckoutId::new(format!("checkout-{}", state.issued));
        state.checkouts.insert(id.clone(), checkout);
        Ok(id)
    }

    /// A new private directory `<root>/<kind>/<n>`, removed on drop.
    fn fresh(&self, kind: &str) -> Result<Removed, GitError> {
        let n = self.next_dir.fetch_add(1, Ordering::Relaxed);
        let dir = self.root.join(kind).join(n.to_string());
        private_dir(&dir).map_err(|e| failed(format!("cannot create a {kind} directory: {e}")))?;
        Ok(Removed::new(dir))
    }

    fn git(&self, call: Call<'_>, args: &[&OsStr]) -> Result<Vec<u8>, GitError> {
        self.runner.run(call, args).map_err(failed)
    }

    /// One line of output without its newline, as text.
    fn line(&self, call: Call<'_>, args: &[&OsStr]) -> Result<String, GitError> {
        let out = self.git(call, args)?;
        let text = String::from_utf8(out).map_err(|_| failed("git printed non-UTF-8"))?;
        Ok(text.trim_end_matches('\n').to_owned())
    }

    fn fetch(&self, store: &Path, url: &str, sha: &str) -> Result<String, GitError> {
        let sha256 = sha.len() == 64;
        let format = if sha256 {
            "--object-format=sha256"
        } else {
            "--object-format=sha1"
        };
        self.git(
            Call::on(store),
            &[
                os("init"),
                os("--bare"),
                os("-q"),
                os("--template="),
                os(format),
            ],
        )?;
        // Attributes are neutral, so `add` stores bytes as written and no
        // agent-written `.gitattributes` converts or filters content.
        let info = store.join("info");
        fs::create_dir(&info).map_err(|e| failed(format!("cannot create info/: {e}")))?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(info.join("attributes"))
            .and_then(|mut f| f.write_all(b"* -text -eol -filter -ident -working-tree-encoding\n"))
            .map_err(|e| failed(format!("cannot write info/attributes: {e}")))?;
        let fetched = self.git(
            Call::on(store),
            &[
                os("fetch"),
                os("-q"),
                os("--depth=1"),
                os("--no-tags"),
                os("--no-write-fetch-head"),
                os("--no-recurse-submodules"),
                os("--"),
                os(url),
                os(sha),
            ],
        );
        if let Err(error) = fetched {
            // What the remote advertises decides; git's message is never
            // parsed. A remote that does not answer, or that advertises
            // the commit, failed the fetch for another reason (the network,
            // a full disk, a broken remote).
            let advertised = self.git(
                Call::on(store),
                &[os("ls-remote"), os("-q"), os("--"), os(url)],
            );
            return Err(match advertised {
                Ok(refs) if !advertises(&refs, sha) => GitError::UnknownCommit,
                _ => error,
            });
        }
        match self.line(Call::on(store), &[os("cat-file"), os("-t"), os(sha)]) {
            Ok(kind) if kind == "commit" => {}
            _ => return Err(GitError::UnknownCommit),
        }
        let tree = format!("{sha}^{{tree}}");
        self.line(
            Call::on(store),
            &[os("rev-parse"), os("--verify"), os("-q"), os(&tree)],
        )
    }

    /// The gitlinks of a tree.
    fn gitlinks(&self, store: &Path, tree: &str) -> Result<Vec<RelativePath>, GitError> {
        let out = self.git(
            Call::on(store),
            &[
                os("ls-tree"),
                os("-r"),
                os("-z"),
                os("--full-tree"),
                os(tree),
            ],
        )?;
        ls_tree(&out)?
            .into_iter()
            .filter(|e| e.mode == "160000")
            .map(|e| tree_path(&e.path))
            .collect()
    }

    /// The blobs `oids` name, in order, through `cat-file --batch` (raw, no
    /// filters).
    fn blobs(&self, store: &Path, oids: &[String]) -> Result<Vec<Vec<u8>>, GitError> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        let mut input = Vec::new();
        for oid in oids {
            input.extend_from_slice(oid.as_bytes());
            input.push(b'\n');
        }
        let call = Call {
            stdin: Some(&input),
            ..Call::on(store)
        };
        let out = self.git(call, &[os("cat-file"), os("--batch")])?;
        let bad =
            || failed("git cat-file --batch printed something other than the blobs asked for");
        let mut rest = out.as_slice();
        let mut blobs = Vec::with_capacity(oids.len());
        for oid in oids {
            let eol = rest.iter().position(|b| *b == b'\n').ok_or_else(bad)?;
            let header = std::str::from_utf8(&rest[..eol]).map_err(|_| bad())?;
            let mut fields = header.split(' ');
            let (Some(got), Some("blob"), Some(size), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(bad());
            };
            if got != oid {
                return Err(bad());
            }
            let size: usize = size.parse().map_err(|_| bad())?;
            let body = &rest[eol + 1..];
            let end = size.checked_add(1).ok_or_else(bad)?;
            if body.len() < end || body[size] != b'\n' {
                return Err(bad());
            }
            blobs.push(body[..size].to_vec());
            rest = &body[end..];
        }
        if !rest.is_empty() {
            return Err(bad());
        }
        Ok(blobs)
    }

    /// The generated `.git` of a store's base commit, in path order.
    fn generated_git(&self, store: &Store) -> Result<Vec<(RelativePath, Kind, Vec<u8>)>, GitError> {
        let tmp = self.fresh("tmp")?;
        let index = tmp.path.join("index");
        self.git(
            Call {
                index: Some(&index),
                ..Call::on(&store.dir)
            },
            &[os("read-tree"), os(&store.base_tree)],
        )?;
        let index = fs::read(&index).map_err(|e| failed(format!("cannot read the index: {e}")))?;
        let prefix = tmp.path.join("pack");
        let mut input = store.base.clone().into_bytes();
        input.push(b'\n');
        let name = self.line(
            Call {
                stdin: Some(&input),
                ..Call::on(&store.dir)
            },
            &[
                os("pack-objects"),
                os("--revs"),
                os("-q"),
                prefix.as_os_str(),
            ],
        )?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(failed("git pack-objects printed no pack name"));
        }
        let read = |ext: &str| {
            fs::read(tmp.path.join(format!("pack-{name}.{ext}")))
                .map_err(|e| failed(format!("cannot read the {ext} file: {e}")))
        };
        let line = format!("{}\n", store.base);
        let mut entries = vec![
            (".git/HEAD".to_owned(), b"ref: refs/heads/main\n".to_vec()),
            (
                ".git/config".to_owned(),
                snapshot_config(store.sha256).into_bytes(),
            ),
            (".git/index".to_owned(), index),
            (format!(".git/objects/pack/pack-{name}.idx"), read("idx")?),
            (format!(".git/objects/pack/pack-{name}.pack"), read("pack")?),
            (".git/refs/heads/main".to_owned(), line.clone().into_bytes()),
            (".git/shallow".to_owned(), line.into_bytes()),
        ];
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        entries
            .into_iter()
            .map(|(p, data)| {
                RelativePath::parse(&p)
                    .map(|p| (p, Kind::File, data))
                    .map_err(|_| failed("a generated .git path is refused"))
            })
            .collect()
    }
}

impl Git for GitCli {
    fn fetch_base(&self, repo: &RepoUrl, base: &CommitSha) -> Result<CheckoutId, GitError> {
        let url = repo.as_str();
        self.transports
            .check(url)
            .map_err(|problem| failed(format!("the repository URL is refused: {problem}")))?;
        let sha = base.as_str();
        let mut store = self.fresh("stores")?;
        let base_tree = self.fetch(&store.path, url, sha)?;
        let id = self.issue(Checkout {
            store: Arc::new(Store {
                dir: store.path.clone(),
                base: sha.to_owned(),
                base_tree: base_tree.clone(),
                sha256: sha.len() == 64,
            }),
            tree: base_tree,
        })?;
        store.keep = true;
        Ok(id)
    }

    fn read(&self, id: &CheckoutId, path: &RelativePath) -> Result<Option<Vec<u8>>, GitError> {
        let c = self.checkout(id)?;
        let store = &c.store.dir;
        let out = self.git(
            Call::on(store),
            &[
                os("ls-tree"),
                os("-z"),
                os("--full-tree"),
                os(&c.tree),
                os("--"),
                os(path.as_str()),
            ],
        )?;
        let want = path.as_str().as_bytes();
        let Some(entry) = ls_tree(&out)?.into_iter().find(|e| e.path == want) else {
            return Ok(None);
        };
        if entry.mode != "100644" && entry.mode != "100755" {
            return Ok(None);
        }
        self.blobs(store, &[entry.oid]).map(|mut blobs| blobs.pop())
    }

    fn snapshot(&self, id: &CheckoutId) -> Result<Vec<u8>, GitError> {
        let c = self.checkout(id)?;
        let store = &c.store.dir;
        let out = self.git(
            Call::on(store),
            &[
                os("ls-tree"),
                os("-r"),
                os("-z"),
                os("--full-tree"),
                os(&c.tree),
            ],
        )?;
        let mut files = Vec::new();
        let mut oids = Vec::new();
        for entry in ls_tree(&out)? {
            let kind = match entry.mode.as_str() {
                "160000" => continue,
                "100644" => Kind::File,
                "100755" => Kind::Executable,
                "120000" => Kind::Symlink,
                other => {
                    return Err(failed(format!(
                        "the tree has an entry of mode {other:?}, which a workspace cannot carry"
                    )));
                }
            };
            let path = tree_path(&entry.path)?;
            if path.is_repository_metadata() {
                return Err(failed(format!(
                    "the tree holds repository metadata at {:?}",
                    path.as_str()
                )));
            }
            files.push((path, kind));
            oids.push(entry.oid);
        }
        let blobs = self.blobs(store, &oids)?;
        let generated = self.generated_git(&c.store)?;
        // Both lists are in path order (`ls-tree -r` lists a tree in the
        // byte order of full paths); merging keeps git's order as it came,
        // so a listing out of order still fails in `from_sorted`.
        let mut tree = files
            .into_iter()
            .zip(blobs)
            .map(|((p, k), d)| (p, k, d))
            .peekable();
        let mut git = generated.into_iter().peekable();
        let mut merged = Vec::new();
        loop {
            let take_tree = match (tree.peek(), git.peek()) {
                (Some(t), Some(g)) => t.0.as_str().as_bytes() < g.0.as_str().as_bytes(),
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            let next = if take_tree { tree.next() } else { git.next() };
            merged.extend(next);
        }
        Workspace::from_sorted(merged, self.max_nodes)
            .map(|w| w.encode())
            .map_err(|e| failed(format!("the checkout is not a workspace: {e}")))
    }

    fn diff(&self, id: &CheckoutId, workspace: &[u8]) -> Result<Vec<u8>, GitError> {
        let c = self.checkout(id)?;
        let store = &c.store.dir;
        let workspace = Workspace::decode(workspace, self.max_nodes)
            .map_err(|e| failed(format!("the workspace is refused: {e}")))?
            .without_metadata();
        // Before anything is written: on a case-insensitive scratch
        // directory git would read `sub/.GIT` as `sub/.git` while it walks
        // the tree, before its own path checks see the name.
        if let Some((path, _, _)) = workspace
            .iter()
            .find(|(p, _, _)| p.as_str().split('/').any(names_git_elsewhere))
        {
            return Err(failed(format!(
                "the workspace has a path that is .git on another file system: {:?}",
                path.as_str()
            )));
        }
        let gitlinks = self.gitlinks(store, &c.tree)?;
        let scratch = self.fresh("scratch")?;
        let tmp = self.fresh("tmp")?;
        materialize(&workspace, &scratch.path, &gitlinks, self.max_nodes)
            .map_err(|e| failed(format!("the workspace cannot be written: {e}")))?;
        let index = tmp.path.join("index");
        // The workspace's blobs and trees go here and are removed with
        // `tmp`; the store is only read.
        let objects = tmp.path.join("objects");
        private_dir(&objects)
            .map_err(|e| failed(format!("cannot create an object directory: {e}")))?;
        let throwaway = || Call {
            objects: Some(&objects),
            ..Call::on(store)
        };
        let in_tree = || Call {
            work_tree: Some(&scratch.path),
            index: Some(&index),
            ..throwaway()
        };
        self.git(in_tree(), &[os("read-tree"), os(&c.tree)])?;
        self.git(in_tree(), &[os("add"), os("-A")])?;
        let new = self.line(
            Call {
                index: Some(&index),
                ..throwaway()
            },
            &[os("write-tree")],
        )?;
        if new == c.tree {
            return Ok(Vec::new());
        }
        self.git(
            throwaway(),
            &[
                os("diff-tree"),
                os("-r"),
                os("-p"),
                os("--binary"),
                os("--full-index"),
                os("--no-renames"),
                os("--no-ext-diff"),
                os("--no-textconv"),
                os("--no-color"),
                os("--src-prefix=a/"),
                os("--dst-prefix=b/"),
                os(&c.tree),
                os(&new),
            ],
        )
    }

    fn apply(&self, id: &CheckoutId, diff: &[u8]) -> Result<CheckoutId, GitError> {
        let c = self.checkout(id)?;
        if diff.is_empty() {
            return self.issue(c);
        }
        let store = &c.store.dir;
        let tmp = self.fresh("tmp")?;
        let index = tmp.path.join("index");
        let indexed = || Call {
            index: Some(&index),
            ..Call::on(store)
        };
        self.git(indexed(), &[os("read-tree"), os(&c.tree)])?;
        self.git(
            Call {
                stdin: Some(diff),
                ..indexed()
            },
            &[os("apply"), os("--cached"), os("--whitespace=nowarn")],
        )?;
        let tree = self.line(indexed(), &[os("write-tree")])?;
        self.issue(Checkout {
            store: Arc::clone(&c.store),
            tree,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_tree_parses_records() {
        let out = b"100644 blob abc\ta b\x00160000 commit def\tmod\x00";
        let entries = ls_tree(out).expect("parses");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, b"a b");
        assert_eq!(entries[1].mode, "160000");
        assert!(ls_tree(b"").expect("empty").is_empty());
        for bad in [
            &b"100644 blob abc a\0"[..],
            b"100644 blob\tabc\0",
            b"100644 blob abc\ta",
        ] {
            assert!(ls_tree(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn advertises_matches_whole_ids() {
        let a = "0123456789abcdef0123456789abcdef01234567";
        let refs = format!("{a}\tHEAD\n{a}\trefs/heads/main\n");
        assert!(advertises(refs.as_bytes(), a));
        assert!(!advertises(refs.as_bytes(), &a[..39]));
        assert!(!advertises(b"", a));
        // A ref name is not an id.
        let named = format!("1111111111111111111111111111111111111111\trefs/heads/{a}\n");
        assert!(!advertises(named.as_bytes(), a));
    }
}
