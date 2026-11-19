//! Shared helpers of the `boneli-git-cli` integration tests: temporary
//! directories, fixture repositories built with the test's own git, the
//! workspace hooks the `Git` suite needs, a tripwire and a recording git.

#![allow(dead_code)]

pub mod record;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use std::sync::Arc;

use boneli_app::contract::git::{Remote, Repository, Tripwire};
use boneli_app::{BranchName, GitError, RelativePath, RepoUrl};
use boneli_domain::CommitSha;
use boneli_git_cli::{
    Credentials, DEFAULT_MAX_NODES, GitCli, GitCliConfig, Kind, Transports, Workspace,
};

/// A directory under `CARGO_TARGET_TMPDIR`, unique per process and call,
/// removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates `<CARGO_TARGET_TMPDIR>/git-<tag>-<pid>-<counter>`.
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("git-{tag}-{}-{n}", std::process::id()));
        fs::create_dir_all(&path).expect("create the test's temp dir");
        TempDir { path }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Writes `data` to `file` with mode 0755 through a child process
/// (`sh -c 'cat > "$1" && chmod 755 "$1"'`, the data on stdin), so the
/// test process never holds a write descriptor to the file. A process
/// another test thread forks inherits every descriptor the test process
/// has open until it execs, and exec of a file that some process holds
/// open for writing fails with ETXTBSY ("Text file busy"); every file a
/// test may exec, a fake git or a planted hook, is written here.
pub fn write_executable(file: &Path, data: &[u8]) {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(file)
        .stdin(Stdio::piped())
        .spawn()
        .expect("start the writer");
    {
        let mut stdin = child.stdin.take().expect("the writer's stdin");
        stdin.write_all(data).expect("feed the writer");
    }
    let status = child.wait().expect("wait for the writer");
    assert!(status.success(), "writing {}: {status}", file.display());
}

/// The test's own git: the first `git` on `PATH`, as an absolute path. The
/// adapter never searches `PATH`; the test does it for it.
pub fn host_git() -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH is set for the tests");
    std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|candidate| candidate.is_absolute() && candidate.is_file())
        .expect("a git on PATH")
}

pub fn path(text: &str) -> RelativePath {
    RelativePath::parse(text).expect("a valid path")
}

pub fn sha(text: &str) -> CommitSha {
    CommitSha::parse(text).expect("a valid SHA")
}

/// Runs the test's own git with a cleared environment, so a developer's
/// global config (signing, hooks, templates) cannot leak into a fixture,
/// and with fixed identities and dates, so commit ids are stable.
pub fn fixture_git(cwd: &Path, args: &[&OsStr]) -> Vec<u8> {
    let out = Command::new(host_git())
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .env("LC_ALL", "C")
        .output()
        .expect("run the fixture git");
    assert!(
        out.status.success(),
        "fixture git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// `fixture_git` over string arguments.
pub fn fgit(cwd: &Path, args: &[&str]) -> String {
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    String::from_utf8(fixture_git(cwd, &args))
        .expect("UTF-8 output")
        .trim_end()
        .to_owned()
}

/// A source repository with a work tree, built by the test's own git.
pub struct Source {
    pub dir: PathBuf,
}

impl Source {
    /// `git init` at `<tmp>/<name>` on branch `main`, SHA-1 or SHA-256.
    pub fn new(tmp: &TempDir, name: &str, sha256: bool) -> Source {
        let dir = tmp.path().join(name);
        fs::create_dir_all(&dir).expect("source dir");
        let format = if sha256 { "sha256" } else { "sha1" };
        fgit(
            &dir,
            &[
                "init",
                "-q",
                "-b",
                "main",
                &format!("--object-format={format}"),
                ".",
            ],
        );
        Source { dir }
    }

    /// Writes a file, with its parents; `executable` sets 0755.
    pub fn write(&self, rel: &str, data: &[u8], executable: bool) -> &Source {
        let file = self.dir.join(OsStr::from_bytes(rel.as_bytes()));
        fs::create_dir_all(file.parent().expect("a parent")).expect("parents");
        if executable {
            write_executable(&file, data);
        } else {
            fs::write(&file, data).expect("write");
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("mode");
        }
        self
    }

    /// Creates a symlink.
    pub fn link(&self, rel: &str, target: &str) -> &Source {
        let file = self.dir.join(rel);
        fs::create_dir_all(file.parent().expect("a parent")).expect("parents");
        symlink(target, &file).expect("symlink");
        self
    }

    /// Records a gitlink at `rel` pointing at `commit`, with the empty
    /// directory that keeps `add -A` from removing it.
    pub fn gitlink(&self, rel: &str, commit: &str) -> &Source {
        fs::create_dir_all(self.dir.join(rel)).expect("gitlink dir");
        fgit(
            &self.dir,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{commit},{rel}"),
            ],
        );
        self
    }

    /// Stages everything and commits; returns the commit id. NTFS and HFS
    /// protection are off here only, so a fixture can hold a path the
    /// adapter must refuse.
    pub fn commit(&self, message: &str) -> String {
        fgit(
            &self.dir,
            &[
                "-c",
                "core.protectNTFS=false",
                "-c",
                "core.protectHFS=false",
                "add",
                "-A",
            ],
        );
        fgit(
            &self.dir,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "--no-verify",
                "-m",
                message,
            ],
        );
        fgit(&self.dir, &["rev-parse", "HEAD"])
    }

    /// The `file://` URL of the repository.
    pub fn url(&self) -> RepoUrl {
        RepoUrl::new(format!("file://{}", self.dir.display()))
    }
}

/// A `GitCli` on its own root under `tmp`, with the file transport, and the
/// directory that holds the root.
pub fn open(tmp: &TempDir, git: &Path, max_nodes: usize) -> GitCli {
    open_with(tmp, git, max_nodes, None)
}

/// [`open`] with credentials.
pub fn open_with(
    tmp: &TempDir,
    git: &Path,
    max_nodes: usize,
    credentials: Option<Arc<dyn Credentials>>,
) -> GitCli {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    GitCli::open(GitCliConfig {
        git: git.to_path_buf(),
        root: tmp.path().join(format!("root-{n}")),
        transports: Transports::HttpsAndFile,
        max_workspace_nodes: max_nodes,
        credentials,
    })
    .expect("open the adapter")
}

/// The directory of a `file://` fixture URL.
pub fn url_dir(repo: &RepoUrl) -> Result<PathBuf, String> {
    repo.as_str()
        .strip_prefix("file://")
        .map(PathBuf::from)
        .ok_or_else(|| format!("not a fixture URL: {:?}", repo.as_str()))
}

/// The tip of `refs/heads/<branch>` in the fixture repository at `dir` and
/// its parents, read with the test's own git; `None` when it is absent.
pub fn branch_at(dir: &Path, branch: &str) -> Option<(String, Vec<String>)> {
    let refname = format!("refs/heads/{branch}");
    let out = fgit(
        dir,
        &[
            "for-each-ref",
            "--format=%(refname)%09%(objectname)%09%(parent)",
            &refname,
        ],
    );
    out.lines().find_map(|line| {
        let mut fields = line.split('\t');
        (fields.next()? == refname).then(|| {
            let tip = fields.next().unwrap_or_default().to_owned();
            let parents = fields
                .next()
                .unwrap_or_default()
                .split(' ')
                .filter(|p| !p.is_empty())
                .map(str::to_owned)
                .collect();
            (tip, parents)
        })
    })
}

/// The suite's `Remote` hook for `file://` fixtures: the repository read
/// with the test's own git, so nothing the adapter does can colour it.
pub struct HostRemote;

impl<G> Remote<G> for HostRemote {
    fn branch(
        &self,
        _adapter: &G,
        repo: &RepoUrl,
        branch: &BranchName,
    ) -> Result<Option<(CommitSha, Vec<CommitSha>)>, String> {
        let dir = url_dir(repo)?;
        let Some((tip, parents)) = branch_at(&dir, branch.as_str()) else {
            return Ok(None);
        };
        let parse = |s: &str| CommitSha::parse(s).map_err(|e| format!("{s:?}: {e}"));
        Ok(Some((
            parse(&tip)?,
            parents.iter().map(|p| parse(p)).collect::<Result<_, _>>()?,
        )))
    }
}

/// A `GitCli` over the test's own git, with the default node cap.
pub fn cli(tmp: &TempDir) -> GitCli {
    open(tmp, &host_git(), DEFAULT_MAX_NODES)
}

/// Decodes a workspace the adapter produced.
pub fn decode(bytes: &[u8]) -> Workspace {
    Workspace::decode(bytes, usize::MAX).expect("the adapter's own format")
}

/// Every entry of a workspace, by path.
pub fn entries(bytes: &[u8]) -> Vec<(String, Kind, Vec<u8>)> {
    decode(bytes)
        .iter()
        .map(|(p, kind, data)| (p.as_str().to_owned(), kind, data.to_vec()))
        .collect()
}

/// Builds an encoded workspace from entries in any order.
pub fn encode(mut list: Vec<(RelativePath, Kind, Vec<u8>)>) -> Vec<u8> {
    list.sort_by(|a, b| a.0.cmp(&b.0));
    Workspace::from_sorted(list, usize::MAX)
        .expect("a valid workspace")
        .encode()
}

/// Sets `file` to `content` with `kind`, or removes it for `None`.
pub fn edit_kind(workspace: &[u8], file: &RelativePath, content: Option<(Kind, &[u8])>) -> Vec<u8> {
    let mut list: Vec<(RelativePath, Kind, Vec<u8>)> = decode(workspace)
        .iter()
        .filter(|(p, _, _)| *p != file)
        .map(|(p, kind, data)| (p.clone(), kind, data.to_vec()))
        .collect();
    if let Some((kind, data)) = content {
        list.push((file.clone(), kind, data.to_vec()));
    }
    encode(list)
}

/// The suite's `edit` hook: sets or removes a file and keeps its kind. A new
/// file under a `hooks` directory of repository metadata is executable,
/// because git ignores a hook that is not (ADR-010, "Accept when").
pub fn edit(workspace: &[u8], file: &RelativePath, content: Option<&[u8]>) -> Vec<u8> {
    let existing = decode(workspace).get(file).map(|(kind, _)| kind);
    let hook = file.is_repository_metadata() && file.as_str().contains("/hooks/");
    let kind = existing.unwrap_or(if hook { Kind::Executable } else { Kind::File });
    edit_kind(workspace, file, content.map(|c| (kind, c)))
}

/// The suite's `retarget` hook for the adapter's diff format (`git
/// diff-tree -p`): moves every header that names `from` to `to`. Hunk lines
/// are left alone, so content that looks like a header is not touched.
pub fn retarget(diff: &[u8], from: &RelativePath, to: &RelativePath) -> Vec<u8> {
    let (f, t) = (from.as_str(), to.as_str());
    let text = String::from_utf8_lossy(diff);
    let mut out = String::new();
    let mut in_hunk = false;
    for line in text.split_inclusive('\n') {
        if line.starts_with("diff --git ") {
            in_hunk = false;
        } else if line.starts_with("@@") {
            in_hunk = true;
        }
        let moved = if in_hunk {
            line.to_owned()
        } else if line == format!("diff --git a/{f} b/{f}\n") {
            format!("diff --git a/{t} b/{t}\n")
        } else if line == format!("--- a/{f}\n") {
            format!("--- a/{t}\n")
        } else if line == format!("+++ b/{f}\n") {
            format!("+++ b/{t}\n")
        } else {
            line.to_owned()
        };
        out.push_str(&moved);
    }
    out.into_bytes()
}

/// Writes every entry of a workspace into `dir`, repository metadata
/// included, as a sandbox would hold it. Test-only and for the adapter's
/// own snapshots and fixtures; the adapter writes with `materialize`.
pub fn unpack_all(workspace: &[u8], dir: &Path) {
    for (p, kind, data) in decode(workspace).iter() {
        let file = dir.join(OsStr::from_bytes(p.as_str().as_bytes()));
        fs::create_dir_all(file.parent().expect("a parent")).expect("parents");
        match kind {
            Kind::Symlink => symlink(OsStr::from_bytes(data), &file).expect("symlink"),
            Kind::Executable => write_executable(&file, data),
            Kind::File => {
                fs::write(&file, data).expect("write");
                fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("mode");
            }
        }
    }
}

/// The names under `dir`, sorted; empty when it is missing.
pub fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// A sentinel directory in the test's own temporary directory, outside
/// every adapter root: the planted metadata names `touch <dir>/tripped`,
/// and the tripwire reports whatever appears in the directory. One per
/// test, so parallel tests never see or reset each other's trips.
pub struct Trip {
    pub dir: PathBuf,
}

impl Trip {
    pub fn new(tmp: &TempDir) -> Trip {
        let dir = tmp.path().join("tripwire");
        fs::create_dir_all(&dir).expect("tripwire dir");
        Trip { dir }
    }

    /// The command the planted metadata runs. `#` ends it, so the
    /// arguments git appends to `core.fsmonitor` create nothing.
    pub fn touch(&self) -> String {
        format!("touch {}/tripped #", self.dir.display())
    }

    /// A planted `.git/config` that names a command for `core.fsmonitor`
    /// and the workspace's own hooks directory.
    pub fn fsmonitor_config(&self) -> (RelativePath, Vec<u8>) {
        (
            path(".git/config"),
            format!(
                "[core]\n\tfsmonitor = {}\n\thooksPath = .git/hooks\n",
                self.touch()
            )
            .into_bytes(),
        )
    }

    /// A planted hook git runs when it writes an index.
    pub fn hook(&self) -> (RelativePath, Vec<u8>) {
        (
            path(".git/hooks/post-index-change"),
            format!("#!/bin/sh\n{}\n", self.touch()).into_bytes(),
        )
    }

    /// The config of a nested repository.
    pub fn nested(&self) -> (RelativePath, Vec<u8>) {
        (
            path("sub/.git/config"),
            format!("[core]\n\tfsmonitor = {}\n", self.touch()).into_bytes(),
        )
    }

    /// All three, as the suite plants them.
    pub fn metadata(&self) -> Vec<(RelativePath, Vec<u8>)> {
        vec![self.fsmonitor_config(), self.hook(), self.nested()]
    }

    pub fn tripped(&self) -> Vec<String> {
        listing(&self.dir)
    }
}

impl<G> Tripwire<G> for Trip {
    fn tripped(&self, _adapter: &G) -> Result<Vec<String>, String> {
        fs::read_dir(&self.dir)
            .map_err(|e| format!("cannot list the sentinel directory: {e}"))
            .map(|_| Trip::tripped(self))
    }
}

pub const LIB: &[u8] = b"fn total() {}\n";
pub const EDITED: &[u8] = b"fn total() { 1 }\n";
pub const ABSENT: &str = "89abcdef0123456789abcdef0123456789abcdef";

/// The contract's source repository: one commit with `src/lib.rs` and
/// `README`.
pub fn contract_source(tmp: &TempDir) -> (Source, String) {
    let source = Source::new(tmp, "contract-source", false);
    source.write("src/lib.rs", LIB, false);
    source.write("README", b"app", false);
    let base = source.commit("base");
    (source, base)
}

/// The suite's fixture over any adapter `G` on the contract source.
pub fn repository<G>(
    adapter: G,
    source: &Source,
    base: &str,
    metadata: Vec<(RelativePath, Vec<u8>)>,
) -> Repository<G> {
    Repository {
        adapter,
        repo: source.url(),
        base: sha(base),
        path: path("src/lib.rs"),
        content: LIB.to_vec(),
        missing: path("src/missing.rs"),
        unknown: sha(ABSENT),
        edited: EDITED.to_vec(),
        metadata,
    }
}

/// The detail of a `Failed`, or a panic naming what came instead.
pub fn failed<T: std::fmt::Debug>(result: Result<T, GitError>) -> String {
    match result {
        Err(GitError::Failed { detail }) => detail,
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// A git that runs the real one with `GIT_TRACE2_EVENT` set to `trace`
/// and the `http.*` config keys logged, so the test sees what the push's
/// `pack-objects` wrote and which config each process read. The adapter
/// clears the environment; the wrapper adds the variables after that.
pub fn tracing_git(tmp: &TempDir, trace: &std::path::Path) -> std::path::PathBuf {
    let git = tmp.path().join("tracing-git");
    write_executable(
        &git,
        format!(
            "#!/bin/sh\n\
             GIT_TRACE2_EVENT='{trace}' GIT_TRACE2_CONFIG_PARAMS='http.*' \
             exec '{real}' \"$@\"\n",
            trace = trace.display(),
            real = host_git().display()
        )
        .as_bytes(),
    );
    git
}
