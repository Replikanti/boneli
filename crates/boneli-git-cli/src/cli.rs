//! `GitCli`, the `Git` port over the git binary (ADR-010, D6 and D7).
//!
//! The adapter never gives git a working tree it did not build itself:
//!
//! - Each `fetch_base` makes a fresh bare store under `<root>/stores/` and
//!   fetches the base commit alone, depth 1, by URL: no remote, no refs,
//!   no `FETCH_HEAD`. A checkout is a tree id in a store, so a checkout
//!   never changes. When that fetch fails, the remote's tips and a probe
//!   fetch of the commit alone, in a throwaway repository under
//!   `<root>/tmp/<n>`, decide between `UnknownCommit` and `Failed`.
//! - `diff` decodes the workspace with the strict codec, drops repository
//!   metadata, refuses a name that is `.git` on another file system,
//!   writes the rest into a fresh `<root>/scratch/<n>` and runs
//!   `git add -A` there with an explicit `--git-dir`, a throwaway index
//!   and a throwaway object directory under `<root>/tmp/<n>`, so the store
//!   keeps nothing of the workspace. Both directories are removed on every
//!   path.
//! - `apply` is `git apply --cached` on a throwaway index; a result that
//!   holds a path `snapshot` refuses is refused.
//! - `snapshot` is the tree's files plus a generated one-commit `.git`
//!   with no remote, hook or credential; a tree that holds a path the
//!   workspace cannot carry or a name `diff` refuses, gitlinks included,
//!   is refused.
//! - `push` (ADR-014, D1 and D2) is `commit-tree` of the checkout's tree
//!   with the base as the only parent, then `ls-remote` of the branch,
//!   where an existing branch is `BranchExists` and nothing is pushed,
//!   then a push whose empty lease means "must not exist", so a branch
//!   created in between is refused by the remote too. The URL is the one
//!   the base was fetched from.
//! - With [`Credentials`], every network call (`fetch`, `ls-remote`,
//!   `push`) gets a fresh `Authorization` value, checked before the
//!   process starts (ADR-014, D3).

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use boneli_app::{BranchName, CheckoutId, CommitInfo, Git, GitError, RelativePath, RepoUrl};
use boneli_domain::CommitSha;

use crate::credentials::{Credentials, refused};
use crate::lookalike::names_git_elsewhere;
use crate::materialize::materialize;
use crate::run::{Authorization, Call, MIN_GIT_VERSION, Runner, parse_version};
use crate::url::Transports;
use crate::workspace::{Kind, Workspace};

/// What `GitCli::open` needs.
#[derive(Clone)]
pub struct GitCliConfig {
    /// The git binary, an absolute path; `PATH` is never searched.
    pub git: PathBuf,
    /// The adapter's own directory, an absolute path. It must not exist;
    /// `open` creates it with mode 0700.
    pub root: PathBuf,
    /// The URL forms `fetch_base` accepts.
    pub transports: Transports,
    /// The node cap of a workspace and of a snapshot (ADR-010, D2):
    /// [`DEFAULT_MAX_NODES`](crate::DEFAULT_MAX_NODES) in production.
    pub max_workspace_nodes: usize,
    /// Where the network calls get their `Authorization` value; `None` for
    /// repositories that need none (ADR-014, D3).
    pub credentials: Option<Arc<dyn Credentials>>,
}

impl fmt::Debug for GitCliConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitCliConfig")
            .field("git", &self.git)
            .field("root", &self.root)
            .field("transports", &self.transports)
            .field("max_workspace_nodes", &self.max_workspace_nodes)
            .field("credentials", &CredentialSource(self.credentials.clone()))
            .finish()
    }
}

/// The credentials of a `GitCli`; its `Debug` shows only whether there are
/// any.
#[derive(Clone)]
struct CredentialSource(Option<Arc<dyn Credentials>>);

impl fmt::Debug for CredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0.is_some() { "Some(..)" } else { "None" })
    }
}

/// Why `GitCli::open` refused.
#[derive(Debug)]
pub enum OpenError {
    /// The git path is relative.
    GitNotAbsolute,
    /// The root is relative.
    RootNotAbsolute,
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
            OpenError::RootNotAbsolute => f.write_str("the adapter root must be an absolute path"),
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
    /// The repository it was fetched from; `push` pushes there.
    url: RepoUrl,
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
    credentials: CredentialSource,
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

/// The `Authorization` of a call to `url`, when there is a value.
fn scoped<'a>(url: &'a str, value: Option<&'a str>) -> Option<Authorization<'a>> {
    value.map(|value| Authorization { url, value })
}

/// Whether some component of `path` is `.git` on another file system
/// (`src/lookalike.rs`).
fn lookalike(path: &str) -> bool {
    path.split('/').any(names_git_elsewhere)
}

/// `Failed` for a tree path with a component that is `.git` on another
/// file system.
fn refuse_lookalike(path: &RelativePath) -> Result<(), GitError> {
    if lookalike(path.as_str()) {
        return Err(failed(format!(
            "the tree has a path that is .git on another file system: {:?}",
            path.as_str()
        )));
    }
    Ok(())
}

/// The object id `ls-remote` output gives for exactly `refname`.
fn tip_of(refs: &[u8], refname: &str) -> Option<String> {
    refs.split(|b| *b == b'\n').find_map(|line| {
        let (oid, name) = line.split_at(line.iter().position(|b| *b == b'\t')?);
        (&name[1..] == refname.as_bytes()).then(|| String::from_utf8_lossy(oid).into_owned())
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
        // Every call runs with its store as the working directory and the
        // same path in `--git-dir`, so a relative root names another
        // directory there.
        if !config.root.is_absolute() {
            return Err(OpenError::RootNotAbsolute);
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
            ..Call::on(Path::new("/"))
        };
        let out = runner
            .run(call, &[os("version")])
            .map_err(|e| OpenError::Git(e.detail))?;
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
            credentials: CredentialSource(config.credentials),
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
        self.runner.run(call, args).map_err(|e| failed(e.detail))
    }

    /// Like [`Self::git`], for a call whose refusal is itself an answer:
    /// `Ok(None)` when git ran and exited with a non-zero status, `Err`
    /// when git gave no answer (it could not start, be waited for or read,
    /// or a signal ended it).
    fn answer(&self, call: Call<'_>, args: &[&OsStr]) -> Result<Option<Vec<u8>>, GitError> {
        match self.runner.run(call, args) {
            Ok(out) => Ok(Some(out)),
            Err(e) if e.answered => Ok(None),
            Err(e) => Err(failed(e.detail)),
        }
    }

    /// One line of output without its newline, as text.
    fn line(&self, call: Call<'_>, args: &[&OsStr]) -> Result<String, GitError> {
        let out = self.git(call, args)?;
        let text = String::from_utf8(out).map_err(|_| failed("git printed non-UTF-8"))?;
        Ok(text.trim_end_matches('\n').to_owned())
    }

    /// The `Authorization` value for one network call to `url`, fresh from
    /// the credentials and checked (ADR-014, D3); `None` without
    /// credentials or when they give none. Never quoted in an error.
    fn authorization(&self, url: &RepoUrl) -> Result<Option<String>, GitError> {
        let Some(credentials) = &self.credentials.0 else {
            return Ok(None);
        };
        let value = credentials
            .authorization(url)
            .map_err(|e| failed(format!("the credentials failed: {e}")))?;
        if let Some(problem) = value.as_deref().and_then(refused) {
            return Err(failed(format!(
                "the credentials' authorization value is refused: {problem}"
            )));
        }
        Ok(value)
    }

    /// `init --bare` of an empty repository at `dir` for objects of `sha`'s
    /// format.
    fn init(&self, dir: &Path, sha: &str) -> Result<(), GitError> {
        let format = if sha.len() == 64 {
            "--object-format=sha256"
        } else {
            "--object-format=sha1"
        };
        self.git(
            Call::on(dir),
            &[
                os("init"),
                os("--bare"),
                os("-q"),
                os("--template="),
                os(format),
            ],
        )
        .map(drop)
    }

    /// Whether the remote has `sha` as a commit: a fetch of that commit
    /// alone, `--depth=1 --filter=tree:0`, into a throwaway repository
    /// `<root>/tmp/<n>` that is removed on every path, so no store sees
    /// it. `Ok(false)` when git refuses that fetch (it ran and exited
    /// non-zero) or the fetch gets something other than a commit; `Err`
    /// when the probe could not be set up or a step gave no answer from git
    /// (it could not start, or a signal ended it), which is no evidence
    /// either way.
    fn remote_has_commit(&self, repo: &RepoUrl, sha: &str) -> Result<bool, GitError> {
        let url = repo.as_str();
        let value = self.authorization(repo)?;
        let tmp = self.fresh("tmp")?;
        self.init(&tmp.path, sha)?;
        let probe = Call {
            authorization: scoped(url, value.as_deref()),
            ..Call::on(&tmp.path)
        };
        let fetched = self.answer(
            probe,
            &[
                os("fetch"),
                os("-q"),
                os("--depth=1"),
                os("--filter=tree:0"),
                os("--no-tags"),
                os("--no-write-fetch-head"),
                os("--no-recurse-submodules"),
                os("--"),
                os(url),
                os(sha),
            ],
        )?;
        if fetched.is_none() {
            return Ok(false);
        }
        let kind = self.answer(Call::on(&tmp.path), &[os("cat-file"), os("-t"), os(sha)])?;
        Ok(
            kind.is_some_and(|out| {
                String::from_utf8_lossy(&out).trim_end_matches('\n') == "commit"
            }),
        )
    }

    /// Fetches `sha` alone into a new store; `value` is the `Authorization`
    /// of the fetch, taken before any process started.
    fn fetch(
        &self,
        store: &Path,
        repo: &RepoUrl,
        sha: &str,
        value: Option<&str>,
    ) -> Result<String, GitError> {
        let url = repo.as_str();
        self.init(store, sha)?;
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
            Call {
                authorization: scoped(url, value),
                ..Call::on(store)
            },
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
            // Evidence decides; git's message is never parsed. A remote
            // that does not answer, that advertises the commit, or that
            // hands it out alone to the probe has it, so the fetch failed
            // for another reason (the network, a full disk, a broken
            // remote). Only a remote that answers, does not advertise the
            // SHA and fails the probe too leaves `UnknownCommit`.
            // A credentials failure here is no evidence either way.
            let advertised = match self.authorization(repo) {
                Ok(value) => self.git(
                    Call {
                        authorization: scoped(url, value.as_deref()),
                        ..Call::on(store)
                    },
                    &[os("ls-remote"), os("-q"), os("--"), os(url)],
                ),
                Err(e) => Err(e),
            };
            return Err(match advertised {
                Ok(refs) if !advertises(&refs, sha) => match self.remote_has_commit(repo, sha) {
                    Ok(false) => GitError::UnknownCommit,
                    Ok(true) | Err(_) => error,
                },
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

    /// The tip of `refname` on the remote, from `ls-remote --refs` with a
    /// fresh `Authorization`; `None` when the remote has no such ref.
    fn remote_tip(
        &self,
        repo: &RepoUrl,
        store: &Path,
        refname: &str,
    ) -> Result<Option<String>, GitError> {
        let url = repo.as_str();
        let value = self.authorization(repo)?;
        let refs = self.git(
            Call {
                authorization: scoped(url, value.as_deref()),
                ..Call::on(store)
            },
            &[
                os("ls-remote"),
                os("--refs"),
                os("--"),
                os(url),
                os(refname),
            ],
        )?;
        Ok(tip_of(&refs, refname))
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
        // Before any process starts: a credentials failure starts none.
        let value = self.authorization(repo)?;
        let mut store = self.fresh("stores")?;
        let base_tree = self.fetch(&store.path, repo, sha, value.as_deref())?;
        let id = self.issue(Checkout {
            store: Arc::new(Store {
                dir: store.path.clone(),
                url: repo.clone(),
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
                // Not in the snapshot, but `diff` reads its path and
                // `apply` checks it: the same refusals, before anything is
                // written.
                "160000" => {
                    refuse_lookalike(&tree_path(&entry.path)?)?;
                    continue;
                }
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
            // `diff` refuses these names, so a checkout that holds one
            // could never return a diff.
            refuse_lookalike(&path)?;
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
        if let Some((path, _, _)) = workspace.iter().find(|(p, _, _)| lookalike(p.as_str())) {
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
        // git refuses its own look-alikes only, and accepts paths a
        // workspace cannot carry. Every path of the applied tree, gitlinks
        // included, gets the checks `snapshot` makes, so no checkout holds
        // a path that `snapshot` or `diff` would refuse.
        let out = self.git(
            Call::on(store),
            &[
                os("ls-tree"),
                os("-r"),
                os("-z"),
                os("--full-tree"),
                os(&tree),
            ],
        )?;
        for (n, entry) in ls_tree(&out)?.into_iter().enumerate() {
            let shown = String::from_utf8_lossy(&entry.path);
            let path = tree_path(&entry.path).map_err(|_| {
                failed(format!(
                    "the diff leaves a path a workspace cannot carry: entry {n}, {shown:?}"
                ))
            })?;
            if lookalike(path.as_str()) {
                return Err(failed(format!(
                    "the diff leaves a path that is .git on another file system: entry {n}, \
                     {shown:?}"
                )));
            }
        }
        self.issue(Checkout {
            store: Arc::clone(&c.store),
            tree,
        })
    }

    fn push(
        &self,
        id: &CheckoutId,
        branch: &BranchName,
        commit: &CommitInfo,
    ) -> Result<CommitSha, GitError> {
        let c = self.checkout(id)?;
        let store = &c.store;
        let repo = &store.url;
        let url = repo.as_str();
        // Checked again, as at `fetch_base`: the URL reaches git after `--`
        // only.
        self.transports
            .check(url)
            .map_err(|problem| failed(format!("the repository URL is refused: {problem}")))?;
        let refname = format!("refs/heads/{}", branch.as_str());
        // Before any process starts: a credentials failure starts none.
        let first = self.authorization(repo)?;
        let new = self.line(
            Call {
                stdin: Some(commit.message().as_bytes()),
                identity: Some(commit),
                ..Call::on(&store.dir)
            },
            &[
                os("commit-tree"),
                os(&c.tree),
                os("-p"),
                os(&store.base),
                os("-F"),
                os("-"),
            ],
        )?;
        let sha = CommitSha::parse(&new)
            .map_err(|_| failed("git commit-tree printed something other than a commit id"))?;
        let refs = self.git(
            Call {
                authorization: scoped(url, first.as_deref()),
                ..Call::on(&store.dir)
            },
            &[
                os("ls-remote"),
                os("--refs"),
                os("--"),
                os(url),
                os(&refname),
            ],
        )?;
        if tip_of(&refs, &refname).is_some() {
            return Err(GitError::BranchExists);
        }
        // The empty lease means "must not exist": a branch created since
        // `ls-remote` is refused by the remote, never overwritten.
        let lease = format!("--force-with-lease={refname}:");
        let refspec = format!("{new}:{refname}");
        let value = self.authorization(repo)?;
        let pushed = self.git(
            Call {
                authorization: scoped(url, value.as_deref()),
                ..Call::on(&store.dir)
            },
            &[
                os("push"),
                os("--porcelain"),
                os("--no-verify"),
                os(&lease),
                os("--"),
                os(url),
                os(&refspec),
            ],
        );
        if let Err(error) = pushed {
            // Evidence decides, as in `fetch_base`: the branch now holds
            // another commit (it was created in between) or ours (the push
            // landed and only its answer was lost). Anything else, a failed
            // lookup included, is the push's own error.
            return match self.remote_tip(repo, &store.dir, &refname) {
                Ok(Some(tip)) if tip == new => Ok(sha),
                Ok(Some(_)) => Err(GitError::BranchExists),
                _ => Err(error),
            };
        }
        Ok(sha)
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
    fn tip_of_matches_the_whole_ref() {
        let a = "0123456789abcdef0123456789abcdef01234567";
        let refs = format!(
            "{a}\trefs/heads/boneli/ab\n1111111111111111111111111111111111111111\trefs/heads/boneli/a\n"
        );
        assert_eq!(
            tip_of(refs.as_bytes(), "refs/heads/boneli/a").as_deref(),
            Some("1111111111111111111111111111111111111111")
        );
        assert_eq!(tip_of(refs.as_bytes(), "refs/heads/boneli/a/b"), None);
        assert_eq!(tip_of(refs.as_bytes(), "heads/boneli/a"), None);
        // A tail match of `ls-remote`'s pattern is not the ref.
        let tail = format!("{a}\trefs/x/refs/heads/boneli/a\n");
        assert_eq!(tip_of(tail.as_bytes(), "refs/heads/boneli/a"), None);
        assert_eq!(tip_of(b"", "refs/heads/boneli/a"), None);
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
