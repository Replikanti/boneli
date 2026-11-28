//! Reading the trees a pod wrote: `copy_out`, `export` and `seal`'s copier
//! (ADR-042, D5 and D6).
//!
//! The workspace is agent-written, and the runner that reads it holds the
//! git token, so nothing here follows what the tree holds:
//!
//! - Every name is resolved through [`open_beneath`], with
//!   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
//!   RESOLVE_NO_XDEV`, one component at a time from a directory descriptor
//!   the walk holds; `copy_out` resolves its whole path in one call. A
//!   symlink is never passed, a mount point never crossed.
//! - An entry is first opened as itself (`O_PATH`, which never blocks on a
//!   FIFO and never reaches a device driver) and classified by `fstat` on
//!   that descriptor, never by name or by `d_type`. A file or directory is
//!   then opened again by name with `O_NOFOLLOW | O_NONBLOCK` and must be
//!   the same inode, a symlink is read with `readlinkat(fd, "")` and
//!   carried raw.
//! - FIFOs, sockets, devices (the 0:0 whiteout included) and empty
//!   directories are skipped, as git skips them (ADR-010 left this to #8).
//!   A mount point (`EXDEV`, a dependency bind) is not part of the
//!   workspace and is skipped too. A hardlink is read as its content, once
//!   per name. A file is `x` when its owner may execute it, else `f`; the
//!   setuid, setgid and sticky bits do not count.
//! - Siblings are taken in the order of a git tree, where a directory sorts
//!   as `name/`, so the entries come out in the byte order of their full
//!   paths; the export encodes each into its output as it comes, under the
//!   checks `Workspace::from_sorted` makes, so it holds its bytes once.
//! - [`Caps`] bounds the nodes (files, symlinks and the directories they
//!   imply, as the format counts them), the names the walk looks at and
//!   the bytes of the export; a path longer than [`PATH_MAX`] is refused.
//! - A walk holds at most 34 directory descriptors whatever the depth
//!   (`HELD_MAX`): its top level, one every 64 levels and the level it is
//!   in; any other level is opened again beneath the checkpoint above it
//!   when the walk returns to it.
//!
//! The pod is frozen (`Cgroup::freeze`) while any of this runs, so the tree
//! does not change under the walk; the inode checks catch a tree that
//! changed anyway, and every function fails closed on what it does not
//! expect. Freezing and the per-pod lock are the pod's (part 5).

use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use boneli_app::{RelativePath, SandboxError, TreePath, TreePathProblem, overlapping_paths};
use boneli_sys::fs::{Met, Open, open_beneath, read_dir, read_link};
use boneli_workspace::{DEFAULT_MAX_NODES, Kind, MAGIC, PathRule};

/// The tree path rule (ADR-018): [`TreePath::parse`] and
/// [`TreePath::is_repository_metadata`], as the git adapter's rule
/// (ADR-042, D1). A test pins the two to each other.
#[derive(Clone, Copy, Debug)]
pub struct TreeRule;

impl PathRule for TreeRule {
    type Path = TreePath;
    type Problem = TreePathProblem;

    fn check(path: &[u8]) -> Result<TreePath, TreePathProblem> {
        TreePath::parse(path)
    }

    fn is_metadata(path: &[u8]) -> bool {
        // A path the rule refuses is no entry's path; were it asked, it
        // counts as metadata, which fails closed for every caller.
        TreePath::parse(path).map_or(true, |p| p.is_repository_metadata())
    }

    fn bytes(path: &TreePath) -> &[u8] {
        path.as_bytes()
    }
}

/// A workspace under the tree path rule.
pub type Workspace = boneli_workspace::Workspace<TreeRule>;

/// The longest path a walk accepts, in bytes: `PATH_MAX` (4,096) less its
/// NUL. The git adapter writes every exported path onto the host with
/// path-based calls (`materialize`, ADR-010 D3) and git does the same, and
/// both fail with ENAMETOOLONG past it, so a longer path could never reach
/// a diff. It also bounds a walk's depth, at 2,048 directories of a
/// one-byte name each, and with it the checkpoints a walk keeps open
/// (`CHECKPOINT`).
pub const PATH_MAX: usize = 4095;

/// The bytes of an encoded entry besides its path and data: the kind byte
/// and the two 8-byte lengths (ADR-010, D2).
pub const ENTRY_BYTES: u64 = 17;

/// The longest path of the largest measured candidate tree, in bytes
/// (ADR-010, D2).
pub const LONGEST_PATH: u64 = 242;

/// The export's byte budget beyond the file data (ADR-042, D5): the node
/// cap ([`DEFAULT_MAX_NODES`], 200,000) times [`ENTRY_BYTES`] plus
/// [`LONGEST_PATH`], 259 bytes, which is 51,800,000. File data is already
/// bounded by the workspace's tmpfs; this budget bounds what the tmpfs
/// size does not, the paths and the link targets. Without it a hostile
/// tree at the node cap reaches 200,000 × (17 + 4,096 + 4,095) =
/// 1,641,600,000 bytes of metadata.
pub const METADATA_BUDGET: u64 = DEFAULT_MAX_NODES as u64 * (ENTRY_BYTES + LONGEST_PATH);

/// The bounds of a walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// Files, symlinks and the directories they imply, together, as
    /// `Workspace::nodes` counts them.
    pub nodes: usize,
    /// Names the walk looks at, the skipped ones included: each costs an
    /// open and an `fstat`, whether it is exported or not.
    pub names: usize,
    /// Bytes of the encoded export, [`MAGIC`] included; for a seal, the
    /// same count over the entries it copies, without the magic.
    pub bytes: u64,
}

impl Caps {
    /// The caps of a pod whose workspace tmpfs holds `workspace_bytes`
    /// (ADR-042, D5): the node cap of the format, [`DEFAULT_MAX_NODES`]
    /// (ADR-010, D2); twice as many names, so a tree at the node cap may
    /// hold as many names again that git would skip (FIFOs, sockets,
    /// devices, empty directories, mount points), which a checkout holds
    /// none of; and `workspace_bytes` + [`METADATA_BUDGET`] bytes. `None`
    /// when that sum passes 2^64.
    pub fn for_workspace(workspace_bytes: u64) -> Option<Caps> {
        Some(Caps {
            nodes: DEFAULT_MAX_NODES,
            names: 2 * DEFAULT_MAX_NODES,
            bytes: workspace_bytes.checked_add(METADATA_BUDGET)?,
        })
    }
}

/// Why a path of a tree was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Problem {
    /// It is a symlink, or a parent is, and nothing here follows one.
    Symlink,
    /// It is a mount point or lies beneath one (a dependency bind), which
    /// is not part of the workspace.
    MountPoint,
    /// It is a FIFO, a socket or a device, not a regular file.
    Special,
    /// It is not a directory of the workspace (a seal path).
    NotADirectory,
    /// The file or directory cannot be read (its mode).
    Unreadable,
    /// It is another inode or kind than a moment before: the tree changed
    /// during the walk.
    Changed,
    /// A sealed directory holds no file and no symlink.
    NoEntries,
    /// A seal was asked for no path.
    NoPaths,
    /// A seal path is equal to or nested with this other one.
    Overlap {
        /// The other path.
        other: Vec<u8>,
    },
    /// More nodes than the cap.
    TooManyNodes {
        /// The cap.
        max: usize,
    },
    /// More names than the cap.
    TooManyNames {
        /// The cap.
        max: usize,
    },
    /// More bytes than the cap.
    TooManyBytes {
        /// The cap.
        max: u64,
    },
    /// A path longer than [`PATH_MAX`].
    PathTooLong {
        /// The cap.
        max: usize,
    },
    /// The seal's target is not a new, empty directory of mode 0700.
    Target,
    /// The entries do not form a workspace (a bug of the walk).
    Format(String),
    /// A call failed.
    Io {
        /// The call.
        call: &'static str,
        /// Its error.
        detail: String,
    },
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::Symlink => f.write_str("is or passes a symlink, which is never followed"),
            Problem::MountPoint => f.write_str(
                "is or lies beneath a mount point (a dependency), which is not part of the workspace",
            ),
            Problem::Special => f.write_str("is a FIFO, a socket or a device, not a file"),
            Problem::NotADirectory => f.write_str("is not a directory of the workspace"),
            Problem::Unreadable => f.write_str("cannot be read (its mode)"),
            Problem::Changed => f.write_str("changed while it was read"),
            Problem::NoEntries => f.write_str("holds no file and no symlink"),
            Problem::NoPaths => f.write_str("a seal needs at least one path"),
            Problem::Overlap { other } => {
                write!(f, "overlaps the path \"{}\"", other.escape_ascii())
            }
            Problem::TooManyNodes { max } => write!(
                f,
                "makes more than {max} files, symlinks and directories (the node cap)"
            ),
            Problem::TooManyNames { max } => write!(f, "makes the walk see more than {max} names"),
            Problem::TooManyBytes { max } => write!(f, "makes more than {max} bytes"),
            Problem::PathTooLong { max } => write!(f, "is longer than {max} bytes"),
            Problem::Target => {
                f.write_str("the target is not a new, empty directory of mode 0700")
            }
            Problem::Format(why) => write!(f, "does not form a workspace: {why}"),
            Problem::Io { call, detail } => write!(f, "{call} failed: {detail}"),
        }
    }
}

/// An error of a tree read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeError {
    /// `copy_out`: nothing is at the path, a parent is a file, or it is a
    /// directory: the workspace has no file there.
    NotFound,
    /// The path was refused or could not be read.
    Refused {
        /// The path, relative to the workspace; empty for its root.
        path: Vec<u8>,
        /// Why.
        problem: Problem,
    },
}

impl TreeError {
    fn at(path: &[u8], problem: Problem) -> TreeError {
        TreeError::Refused {
            path: path.to_vec(),
            problem,
        }
    }
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeError::NotFound => f.write_str("the workspace has no file at this path"),
            TreeError::Refused { path, problem } if path.is_empty() => {
                write!(f, "the workspace {problem}")
            }
            TreeError::Refused { path, problem } => {
                write!(f, "\"{}\" {problem}", path.escape_ascii())
            }
        }
    }
}

impl std::error::Error for TreeError {}

/// `NotFound` stays `NotFound`; every refusal is `Failed` with the
/// error's text, which is never blank (ADR-004, D4).
impl From<TreeError> for SandboxError {
    fn from(e: TreeError) -> SandboxError {
        match e {
            TreeError::NotFound => SandboxError::NotFound,
            refused => SandboxError::Failed {
                detail: refused.to_string(),
            },
        }
    }
}

/// What a failed call of `boneli-sys` means for the path; `caps` names the
/// name cap a listing ran into.
fn problem_of(call: &'static str, e: &boneli_sys::Error, caps: &Caps) -> Problem {
    if let boneli_sys::Error::TooManyEntries { .. } = e {
        return Problem::TooManyNames { max: caps.names };
    }
    match Met::of(e) {
        Met::Symlink => Problem::Symlink,
        Met::MountPoint => Problem::MountPoint,
        Met::Denied => Problem::Unreadable,
        Met::Nothing | Met::NotADirectory | Met::Other => Problem::Io {
            call,
            detail: e.to_string(),
        },
    }
}

fn io_problem(call: &'static str, e: &io::Error) -> Problem {
    Problem::Io {
        call,
        detail: e.to_string(),
    }
}

/// `copy_out`: the content of the regular file at `path` in the workspace
/// whose root is the directory `root`, at most `max_bytes` bytes.
///
/// Nothing at the path, a file as a parent, and a directory at the path
/// are [`TreeError::NotFound`]; a symlink at the path or at a parent, a
/// mount point, a FIFO, a socket, a device, a mode that forbids the read
/// and a file longer than `max_bytes` are refused. A FIFO is refused at
/// once, without waiting for a writer.
pub fn read_file(
    root: BorrowedFd<'_>,
    path: &RelativePath,
    max_bytes: u64,
) -> Result<Vec<u8>, TreeError> {
    let bytes = path.as_str().as_bytes();
    // No cap to name: copy_out lists no directory.
    let caps = Caps {
        nodes: 0,
        names: 0,
        bytes: max_bytes,
    };
    let opened = |open: Open| {
        open_beneath(root, bytes, open).map_err(|e| match Met::of(&e) {
            Met::Nothing | Met::NotADirectory => TreeError::NotFound,
            _ => TreeError::at(bytes, problem_of("openat2", &e, &caps)),
        })
    };
    let itself = opened(Open::Path)?;
    let meta = stat(&itself, bytes)?;
    let kind = meta.file_type();
    if kind.is_dir() {
        return Err(TreeError::NotFound);
    }
    if kind.is_symlink() {
        return Err(TreeError::at(bytes, Problem::Symlink));
    }
    if !kind.is_file() {
        return Err(TreeError::at(bytes, Problem::Special));
    }
    let fd = opened(Open::Read)?;
    same(&fd, &meta, bytes)?;
    let mut out = Vec::new();
    File::from(fd)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| TreeError::at(bytes, io_problem("read", &e)))?;
    if out.len() as u64 > max_bytes {
        return Err(TreeError::at(
            bytes,
            Problem::TooManyBytes { max: max_bytes },
        ));
    }
    Ok(out)
}

/// `fstat` of a descriptor this module opened.
fn stat(fd: &OwnedFd, path: &[u8]) -> Result<fs::Metadata, TreeError> {
    let file = File::from(
        fd.try_clone()
            .map_err(|e| TreeError::at(path, io_problem("dup", &e)))?,
    );
    file.metadata()
        .map_err(|e| TreeError::at(path, io_problem("fstat", &e)))
}

/// `fd` is the inode `before` described, and of its kind.
fn same(fd: &OwnedFd, before: &fs::Metadata, path: &[u8]) -> Result<(), TreeError> {
    let now = stat(fd, path)?;
    if now.dev() != before.dev()
        || now.ino() != before.ino()
        || now.file_type() != before.file_type()
    {
        return Err(TreeError::at(path, Problem::Changed));
    }
    Ok(())
}

/// The workspace whose root is the directory `root`, encoded in the
/// workspace format (ADR-010, D2), under `caps`: the export (ADR-042, D5).
/// Repository metadata is carried: the snapshot's `.git` is part of the
/// workspace, and `Git::diff` drops it (ADR-010, D1).
pub fn export(root: BorrowedFd<'_>, caps: &Caps) -> Result<Vec<u8>, TreeError> {
    export_measured(root, caps).map(|(bytes, _)| bytes)
}

/// What a walk measured, for the tests of its bounds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Measure {
    /// The walk's work counter.
    pub work: u64,
    /// The most directory descriptors the walk held at once.
    pub held: usize,
}

/// [`export`] and what the walk measured.
///
/// The output is reserved once, at `caps.bytes` and one byte more, and
/// every entry is encoded into it as the walk accepts it: a file's data is
/// read straight into the output and held nowhere else, so the export's
/// memory is the output, at most `caps.bytes`, plus the walk's names and
/// path checks. The reservation is address space; its pages become
/// resident as they are written. A reservation the allocator refuses
/// fails the export, it never aborts the runner.
pub(crate) fn export_measured(
    root: BorrowedFd<'_>,
    caps: &Caps,
) -> Result<(Vec<u8>, Measure), TreeError> {
    let reserve = usize::try_from(caps.bytes.saturating_add(1)).unwrap_or(usize::MAX);
    let mut out = Vec::new();
    out.try_reserve_exact(reserve).map_err(|e| {
        TreeError::at(
            b"",
            Problem::Io {
                call: "reserve",
                detail: e.to_string(),
            },
        )
    })?;
    out.extend_from_slice(MAGIC);
    let mut walk = Walk::new(caps, MAGIC.len() as u64);
    let top = root
        .try_clone_to_owned()
        .map_err(|e| TreeError::at(b"", io_problem("dup", &e)))?;
    let mut sink = Encode::new(out);
    walk.walk(top, b"", &mut sink)?;
    let mut encoded = sink.out;
    if encoded.len() as u64 > caps.bytes {
        return Err(TreeError::at(
            b"",
            Problem::TooManyBytes { max: caps.bytes },
        ));
    }
    encoded.shrink_to_fit();
    Ok((
        encoded,
        Measure {
            work: walk.work,
            held: walk.max_held,
        },
    ))
}

/// `seal`'s copier (ADR-042, D6): copies each directory of `paths` in the
/// workspace whose root is `root` into `target`, at the same relative
/// path, entry by entry under the rules of [`export`] and one set of
/// `caps` for all of them. `target` must be a new, empty, real directory
/// of mode 0700; its files get mode 0644 or 0755 by their kind, its
/// directories 0755, its symlinks their raw targets.
///
/// Refused: no path, two paths that are equal or nested, a path that is
/// not a directory of the workspace (a symlink, a file, a mount point,
/// nothing), and a directory that holds no file and no symlink. On an
/// error `target` may hold part of the copy; the caller removes it.
///
/// The writes are path-based, as `materialize`'s (ADR-010, D3): within the
/// private 0700 target only a process of the runner's own uid could plant
/// a symlink while the copy runs, and such a process holds everything the
/// runner holds already.
pub fn copy_tree(
    root: BorrowedFd<'_>,
    paths: &[RelativePath],
    target: &Path,
    caps: &Caps,
) -> Result<(), TreeError> {
    if paths.is_empty() {
        return Err(TreeError::at(b"", Problem::NoPaths));
    }
    if let Some((a, b)) = overlapping_paths(paths) {
        return Err(TreeError::at(
            a.as_str().as_bytes(),
            Problem::Overlap {
                other: b.as_str().as_bytes().to_vec(),
            },
        ));
    }
    check_target(target)?;
    let mut walk = Walk::new(caps, 0);
    for path in paths {
        let bytes = path.as_str().as_bytes();
        let not_dir = |e: boneli_sys::Error| match Met::of(&e) {
            Met::Nothing | Met::NotADirectory => TreeError::at(bytes, Problem::NotADirectory),
            _ => TreeError::at(bytes, problem_of("openat2", &e, caps)),
        };
        let itself = open_beneath(root, bytes, Open::Path).map_err(not_dir)?;
        let meta = stat(&itself, bytes)?;
        if meta.file_type().is_symlink() {
            return Err(TreeError::at(bytes, Problem::Symlink));
        }
        if !meta.file_type().is_dir() {
            return Err(TreeError::at(bytes, Problem::NotADirectory));
        }
        let dir = open_beneath(root, bytes, Open::Directory).map_err(not_dir)?;
        same(&dir, &meta, bytes)?;
        let mut sink = CopyInto {
            target: target.to_path_buf(),
            previous: None,
        };
        if walk.walk(dir, bytes, &mut sink)? == 0 {
            return Err(TreeError::at(bytes, Problem::NoEntries));
        }
    }
    Ok(())
}

/// `target` is a real directory (not a symlink to one), mode 0700, empty.
fn check_target(target: &Path) -> Result<(), TreeError> {
    let refused = || TreeError::at(b"", Problem::Target);
    let meta = fs::symlink_metadata(target).map_err(|_| refused())?;
    if !meta.file_type().is_dir() || meta.permissions().mode() & 0o7777 != 0o700 {
        return Err(refused());
    }
    let mut listing = fs::read_dir(target).map_err(|_| refused())?;
    if listing.next().is_some() {
        return Err(refused());
    }
    Ok(())
}

/// What the walk does with an entry it accepted.
trait Sink {
    /// The regular file at `path`, read from `file`: reads at most
    /// `limit + 1` bytes and returns how many it read, so a count past
    /// `limit` shows a file over the budget without reading all of it.
    fn file(&mut self, path: &[u8], exec: bool, file: File, limit: u64) -> Result<u64, TreeError>;

    /// The symlink at `path` with its raw target.
    fn link(&mut self, path: &[u8], target: Vec<u8>) -> Result<(), TreeError>;
}

/// Bytes a file is read in, into the export's output.
const READ_CHUNK: usize = 64 << 10;

/// The export's sink: every entry encoded into `out` as it comes
/// (ADR-010, D2), after the checks `Workspace::from_sorted` makes, so a
/// walk that broke the format's order or nesting fails closed: each path
/// passes the tree path rule, sorts after the one before it, and lies
/// beneath no earlier entry. The nesting check keeps, as `from_sorted`
/// does, only the earlier paths that are a string prefix of the previous
/// one, at most 4,095 paths of at most [`PATH_MAX`] bytes.
struct Encode {
    out: Vec<u8>,
    previous: Option<Vec<u8>>,
    prefixes: Vec<Vec<u8>>,
    chunk: Vec<u8>,
}

impl Encode {
    fn new(out: Vec<u8>) -> Encode {
        Encode {
            out,
            previous: None,
            prefixes: Vec::new(),
            chunk: vec![0; READ_CHUNK],
        }
    }

    /// The checks, then the kind byte and the path.
    fn begin(&mut self, path: &[u8], kind: Kind) -> Result<(), TreeError> {
        let bad = |why: &str| TreeError::at(path, Problem::Format(why.to_string()));
        TreePath::parse(path).map_err(|e| bad(&format!("{e:?}")))?;
        if let Some(previous) = &self.previous
            && path <= previous.as_slice()
        {
            return Err(bad("not after the previous entry"));
        }
        while self
            .prefixes
            .last()
            .is_some_and(|top| !path.starts_with(top))
        {
            self.prefixes.pop();
        }
        if self
            .prefixes
            .iter()
            .any(|p| path.get(p.len()) == Some(&b'/'))
        {
            return Err(bad("beneath a file or symlink entry"));
        }
        self.prefixes.push(path.to_vec());
        self.previous = Some(path.to_vec());
        self.out.push(kind.byte());
        self.out
            .extend_from_slice(&(path.len() as u64).to_be_bytes());
        self.out.extend_from_slice(path);
        Ok(())
    }
}

impl Sink for Encode {
    fn file(
        &mut self,
        path: &[u8],
        exec: bool,
        mut file: File,
        limit: u64,
    ) -> Result<u64, TreeError> {
        self.begin(path, if exec { Kind::Executable } else { Kind::File })?;
        let at = self.out.len();
        self.out.extend_from_slice(&[0; 8]);
        let mut n = 0u64;
        while n <= limit {
            let want = usize::try_from((limit - n).saturating_add(1))
                .unwrap_or(usize::MAX)
                .min(READ_CHUNK);
            let got = match file.read(&mut self.chunk[..want]) {
                Ok(0) => break,
                Ok(got) => got,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(TreeError::at(path, io_problem("read", &e))),
            };
            self.out.extend_from_slice(&self.chunk[..got]);
            n += got as u64;
        }
        self.out[at..at + 8].copy_from_slice(&n.to_be_bytes());
        Ok(n)
    }

    fn link(&mut self, path: &[u8], target: Vec<u8>) -> Result<(), TreeError> {
        if target.is_empty() || target.contains(&0) {
            return Err(TreeError::at(
                path,
                Problem::Format("a symlink target that is empty or holds NUL".to_string()),
            ));
        }
        self.begin(path, Kind::Symlink)?;
        self.out
            .extend_from_slice(&(target.len() as u64).to_be_bytes());
        self.out.extend_from_slice(&target);
        Ok(())
    }
}

/// The seal's sink: every entry written into `target` as it comes.
struct CopyInto {
    target: PathBuf,
    /// The previous entry's path, whose parents exist already.
    previous: Option<Vec<u8>>,
}

impl CopyInto {
    /// Creates the parents of `path` below `target` that the previous
    /// entry did not need: those whose `/` lies past the common prefix.
    /// One that exists must be a real directory.
    fn parents(&mut self, path: &[u8]) -> Result<PathBuf, TreeError> {
        let shared = self.previous.as_deref().map_or(0, |p| {
            p.iter().zip(path).take_while(|(a, b)| a == b).count()
        });
        for (i, _) in path
            .iter()
            .enumerate()
            .filter(|(i, b)| **b == b'/' && *i >= shared)
        {
            let dir = self.target.join(OsStr::from_bytes(&path[..i]));
            match fs::create_dir(&dir) {
                Ok(()) => fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))
                    .map_err(|e| TreeError::at(&path[..i], io_problem("chmod", &e)))?,
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    let meta = fs::symlink_metadata(&dir)
                        .map_err(|e| TreeError::at(&path[..i], io_problem("lstat", &e)))?;
                    if !meta.file_type().is_dir() {
                        return Err(TreeError::at(&path[..i], Problem::Changed));
                    }
                }
                Err(e) => return Err(TreeError::at(&path[..i], io_problem("mkdir", &e))),
            }
        }
        self.previous = Some(path.to_vec());
        Ok(self.target.join(OsStr::from_bytes(path)))
    }
}

impl Sink for CopyInto {
    fn file(&mut self, path: &[u8], exec: bool, file: File, limit: u64) -> Result<u64, TreeError> {
        let at = self.parents(path)?;
        let io = |e: io::Error| TreeError::at(path, io_problem("write", &e));
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&at)
            .map_err(io)?;
        let n = io::copy(&mut file.take(limit.saturating_add(1)), &mut out).map_err(io)?;
        let mode = if exec { 0o755 } else { 0o644 };
        out.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(io)?;
        Ok(n)
    }

    fn link(&mut self, path: &[u8], target: Vec<u8>) -> Result<(), TreeError> {
        let at = self.parents(path)?;
        symlink(OsStr::from_bytes(&target), &at)
            .map_err(|e| TreeError::at(path, io_problem("symlink", &e)))
    }
}

/// What a name of a directory is, by `fstat` of the name opened as itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node {
    Directory,
    File {
        exec: bool,
    },
    Symlink,
    /// A FIFO, a socket, a device or a mount point.
    Skipped,
}

/// A name of a directory with what it is and its inode.
struct Child {
    name: Vec<u8>,
    node: Node,
    dev: u64,
    ino: u64,
}

impl Child {
    /// The key a git tree sorts by: a directory as `name/`.
    fn key(&self) -> impl Iterator<Item = &u8> {
        let slash: &[u8] = if self.node == Node::Directory {
            b"/"
        } else {
            b""
        };
        self.name.iter().chain(slash)
    }
}

/// Every this many levels of the walk's stack keep their descriptor while
/// the walk is deeper (ADR-042, D5): the top level, at index 0, and each
/// at a multiple of 64. Any other level's descriptor is closed once the
/// walk opens a directory below it, and opened again from the checkpoint
/// above it, at most 63 components down, when the walk returns to it with
/// names left. With [`PATH_MAX`] a stack has at most [`DEPTH_MAX`]
/// levels, so a walk holds at most [`HELD_MAX`] directory descriptors,
/// whatever the depth. 64 keeps both costs small: 34 descriptors, about 3 %
/// of the default soft `RLIMIT_NOFILE` of 1,024, and a re-open of at most
/// 63 lookups per directory the walk returns to; 32 would hold 66, 128
/// would re-open through 127.
pub(crate) const CHECKPOINT: usize = 64;

/// The most levels a walk's stack holds: a directory at depth 2,047 of
/// one-byte names has a path of 4,093 bytes, and a name beneath it makes
/// 4,095 ([`PATH_MAX`]).
pub(crate) const DEPTH_MAX: usize = PATH_MAX / 2 + 1;

/// The most directory descriptors a walk holds at once: the checkpoints
/// of a full stack (index 0 to 1,984, 32 of them), the deepest level and,
/// for a moment, the directory it enters before the deepest level's
/// descriptor is closed: 34. The walk's other descriptors are one at a
/// time: the name it classifies (and its `fstat` copy) or the file it
/// reads.
pub(crate) const HELD_MAX: usize = DEPTH_MAX.div_ceil(CHECKPOINT) + 2;

/// A directory on the walk's stack.
struct Level {
    /// Its descriptor, `None` while the walk is below it and it is no
    /// checkpoint.
    dir: Option<OwnedFd>,
    /// Its inode, checked when it is opened again.
    dev: u64,
    ino: u64,
    children: Vec<Child>,
    next: usize,
    /// The length of the walk's path buffer that is this directory's path.
    path_len: usize,
    /// Whether this directory was counted as a node: once the first entry
    /// beneath it was accepted.
    counted: bool,
}

/// One walk's budget and counters.
struct Walk<'c> {
    caps: &'c Caps,
    names: usize,
    nodes: usize,
    bytes: u64,
    /// Operations: every call into the kernel and every byte of a path
    /// written or copied, for `export_deep_chain_is_linear`.
    work: u64,
    /// Directory descriptors held now, and the most held at once.
    held: usize,
    max_held: usize,
}

impl<'c> Walk<'c> {
    fn new(caps: &'c Caps, bytes: u64) -> Walk<'c> {
        Walk {
            caps,
            names: 0,
            nodes: 0,
            bytes,
            work: 0,
            held: 0,
            max_held: 0,
        }
    }

    fn hold(&mut self) {
        self.held += 1;
        self.max_held = self.max_held.max(self.held);
        debug_assert!(self.held <= HELD_MAX, "{} directories held", self.held);
    }

    /// Walks the directory `top`, whose path in the workspace is `prefix`
    /// (empty for the root, which is no node), and hands every file and
    /// symlink to `sink` in path order; returns how many.
    fn walk(
        &mut self,
        top: OwnedFd,
        prefix: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<usize, TreeError> {
        let mut path = prefix.to_vec();
        let children = self.list(&top, &mut path)?;
        let meta = stat(&top, &path)?;
        self.hold();
        let mut stack = vec![Level {
            dir: Some(top),
            dev: meta.dev(),
            ino: meta.ino(),
            children,
            next: 0,
            path_len: path.len(),
            counted: prefix.is_empty(),
        }];
        let mut entries = 0usize;
        while let Some(level) = stack.last_mut() {
            let Some(child) = level.children.get_mut(level.next) else {
                if stack.pop().is_some_and(|l| l.dir.is_some()) {
                    self.held -= 1;
                }
                continue;
            };
            level.next += 1;
            let (node, dev, ino) = (child.node, child.dev, child.ino);
            let name = std::mem::take(&mut child.name);
            path.truncate(level.path_len);
            push_name(&mut path, &name);
            self.work += name.len() as u64 + 1;
            if path.len() > PATH_MAX {
                return Err(TreeError::at(&path, Problem::PathTooLong { max: PATH_MAX }));
            }
            let open = match node {
                Node::Skipped => continue,
                Node::Directory => Open::Directory,
                Node::File { .. } => Open::Read,
                Node::Symlink => Open::Path,
            };
            let depth = stack.len() - 1;
            if stack[depth].dir.is_none() {
                self.restore(&mut stack, &path)?;
            }
            let parent = stack[depth].dir.as_ref().ok_or_else(|| {
                TreeError::at(&path, Problem::Format("no descriptor".to_string()))
            })?;
            let fd = self.reopen(parent, &name, &path, open, dev, ino)?;
            match node {
                Node::Skipped => {}
                Node::Directory => {
                    // Unreachable under PATH_MAX; kept so the descriptor
                    // bound cannot outgrow its derivation.
                    if stack.len() >= DEPTH_MAX {
                        return Err(TreeError::at(&path, Problem::PathTooLong { max: PATH_MAX }));
                    }
                    let children = self.list(&fd, &mut path)?;
                    self.hold();
                    // The parent stays open only as a checkpoint.
                    if depth % CHECKPOINT != 0 && stack[depth].dir.take().is_some() {
                        self.held -= 1;
                    }
                    stack.push(Level {
                        dir: Some(fd),
                        dev,
                        ino,
                        children,
                        next: 0,
                        path_len: path.len(),
                        counted: false,
                    });
                }
                Node::File { exec } => {
                    let limit = self.admit(&mut stack, &path)?;
                    let n = sink.file(&path, exec, File::from(fd), limit)?;
                    self.work += 1;
                    if n > limit {
                        return Err(TreeError::at(
                            &path,
                            Problem::TooManyBytes {
                                max: self.caps.bytes,
                            },
                        ));
                    }
                    self.bytes += n;
                    entries += 1;
                }
                Node::Symlink => {
                    let target = read_link(fd.as_fd()).map_err(|e| {
                        TreeError::at(&path, problem_of("readlinkat", &e, self.caps))
                    })?;
                    self.work += 1;
                    let limit = self.admit(&mut stack, &path)?;
                    if target.len() as u64 > limit {
                        return Err(TreeError::at(
                            &path,
                            Problem::TooManyBytes {
                                max: self.caps.bytes,
                            },
                        ));
                    }
                    self.bytes += target.len() as u64;
                    sink.link(&path, target)?;
                    entries += 1;
                }
            }
        }
        Ok(entries)
    }

    /// Opens the deepest level of `stack` again, whose descriptor was
    /// closed while the walk was below it: from the checkpoint above it by
    /// its path relative to that checkpoint, at most `CHECKPOINT - 1`
    /// components, beneath it and without following anything, and checks
    /// it is the inode the walk entered. `path` holds the level's path.
    fn restore(&mut self, stack: &mut [Level], path: &[u8]) -> Result<(), TreeError> {
        let depth = stack.len() - 1;
        let checkpoint = depth - depth % CHECKPOINT;
        let here = &path[..stack[depth].path_len];
        let from = stack[checkpoint].path_len;
        let suffix = &here[if from == 0 { 0 } else { from + 1 }..];
        let base = stack[checkpoint]
            .dir
            .as_ref()
            .ok_or_else(|| TreeError::at(here, Problem::Format("no checkpoint".to_string())))?;
        let (dev, ino) = (stack[depth].dev, stack[depth].ino);
        self.work += 2 + suffix.len() as u64;
        let fd = open_beneath(base.as_fd(), suffix, Open::Directory)
            .map_err(|e| TreeError::at(here, problem_of("openat2", &e, self.caps)))?;
        let meta = stat(&fd, here)?;
        if meta.dev() != dev || meta.ino() != ino {
            return Err(TreeError::at(here, Problem::Changed));
        }
        self.hold();
        stack[depth].dir = Some(fd);
        Ok(())
    }

    /// Counts the entry at `path` and every directory above it on the
    /// stack not counted yet against the node cap, and its kind byte,
    /// lengths and path against the byte cap; returns the bytes left for
    /// its data.
    fn admit(&mut self, stack: &mut [Level], path: &[u8]) -> Result<u64, TreeError> {
        for level in stack.iter_mut().rev() {
            if level.counted {
                break;
            }
            level.counted = true;
            self.nodes += 1;
        }
        self.nodes += 1;
        if self.nodes > self.caps.nodes {
            return Err(TreeError::at(
                path,
                Problem::TooManyNodes {
                    max: self.caps.nodes,
                },
            ));
        }
        self.work += path.len() as u64;
        let need = ENTRY_BYTES + path.len() as u64;
        match self
            .caps
            .bytes
            .checked_sub(self.bytes)
            .and_then(|left| left.checked_sub(need))
        {
            Some(left) => {
                self.bytes += need;
                Ok(left)
            }
            None => Err(TreeError::at(
                path,
                Problem::TooManyBytes {
                    max: self.caps.bytes,
                },
            )),
        }
    }

    /// Opens `name` of `dir` again as `open` and checks it is still the
    /// inode the listing saw.
    fn reopen(
        &mut self,
        dir: &OwnedFd,
        name: &[u8],
        path: &[u8],
        open: Open,
        dev: u64,
        ino: u64,
    ) -> Result<OwnedFd, TreeError> {
        self.work += 2;
        let fd = open_beneath(dir.as_fd(), name, open)
            .map_err(|e| TreeError::at(path, problem_of("openat2", &e, self.caps)))?;
        let meta = stat(&fd, path)?;
        if meta.dev() != dev || meta.ino() != ino {
            return Err(TreeError::at(path, Problem::Changed));
        }
        Ok(fd)
    }

    /// The names of `dir`, whose path is `path`, each opened as itself and
    /// classified, in git tree order.
    fn list(&mut self, dir: &OwnedFd, path: &mut Vec<u8>) -> Result<Vec<Child>, TreeError> {
        let left = self.caps.names.saturating_sub(self.names);
        let names = read_dir(dir.as_fd(), left)
            .map_err(|e| TreeError::at(path, problem_of("getdents64", &e, self.caps)))?;
        self.work += 1 + names.len() as u64 / 128;
        self.names += names.len();
        let base = path.len();
        let mut children = Vec::with_capacity(names.len());
        for name in names {
            self.work += 2 + name.len() as u64;
            let opened = open_beneath(dir.as_fd(), &name, Open::Path);
            let (node, dev, ino) = match opened {
                // A mount point: not part of the workspace.
                Err(e) if Met::of(&e) == Met::MountPoint => (Node::Skipped, 0, 0),
                Err(e) => {
                    push_name(path, &name);
                    let problem = problem_of("openat2", &e, self.caps);
                    return Err(TreeError::at(path, problem));
                }
                Ok(fd) => {
                    push_name(path, &name);
                    let meta = stat(&fd, path)?;
                    path.truncate(base);
                    let kind = meta.file_type();
                    let node = if kind.is_dir() {
                        Node::Directory
                    } else if kind.is_file() {
                        Node::File {
                            exec: meta.mode() & 0o100 != 0,
                        }
                    } else if kind.is_symlink() {
                        Node::Symlink
                    } else {
                        Node::Skipped
                    };
                    (node, meta.dev(), meta.ino())
                }
            };
            children.push(Child {
                name,
                node,
                dev,
                ino,
            });
        }
        children.sort_by(|a, b| a.key().cmp(b.key()));
        Ok(children)
    }
}

/// Appends `/name` to `path`, or `name` to an empty one.
fn push_name(path: &mut Vec<u8>, name: &[u8]) {
    if !path.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(name);
}

#[cfg(test)]
mod tests;
