//! The snapshot and workspace format (ADR-010, D2).
//!
//! An encoded workspace is [`MAGIC`] followed by its entries in path order.
//! Each entry is a kind byte (`f` a file, mode 0644; `x` an executable,
//! mode 0755; `l` a symlink), the path and the data (the content, or the
//! link target), each as its length in 8 big-endian bytes followed by the
//! bytes. Directories are implicit, as in git: an entry's parents are
//! directories, and an empty directory is not representable.
//!
//! The encoding is canonical: a tree has exactly one encoding, and
//! [`Workspace::decode`] refuses every other byte string, so a workspace
//! that decodes and encodes again gives back its own bytes. The decoder
//! takes agent-written bytes: it checks every length against what is left
//! before it copies anything, never allocates ahead of the input, stops
//! once the tree would hold more than `max_nodes` files, symlinks and
//! directories, and runs in time linear in the input.
//!
//! The node cap counts the directories an entry implies, not only the
//! entries: a directory costs two bytes of input (`a/`), so one entry can
//! imply as many directories as half its path length, and only a cap on
//! both bounds what [`materialize`](crate::materialize) creates on the
//! host.
//!
//! A path is what the caller's [`PathRule`] accepts (ADR-042, D1). Both
//! adapters pass the tree path rule of ADR-018 (D2): a backslash, a blank
//! name and bytes that are not UTF-8 are name bytes, because a repository
//! may hold such a file and the replica must hold it too. Whatever the
//! rule, only `/` makes a directory, on the host as in git, and entries
//! are ordered by the bytes of their paths, never by the rule's own type.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;

/// The path rule a workspace is checked against (ADR-042, D1): which
/// bytes are a path, the type a path is kept as, and which paths are
/// repository metadata. The adapter passes it as a type parameter, so this
/// crate never names a core type; the rule is a set of functions, never a
/// value, and a workspace holds none.
///
/// A rule must keep what the format relies on: a path it accepts is not
/// empty, does not start with `/`, holds no NUL and no empty, `.` or `..`
/// component between its `/` bytes, and [`PathRule::bytes`] gives back
/// exactly the bytes [`PathRule::check`] accepted. The tree path rule of
/// ADR-018 is that rule.
pub trait PathRule {
    /// A path the rule accepted.
    type Path: Clone + fmt::Debug;
    /// Why the rule refuses bytes.
    type Problem: fmt::Debug;

    /// The bytes as a path, or why they are not one.
    fn check(path: &[u8]) -> Result<Self::Path, Self::Problem>;

    /// Whether the path is repository metadata (ADR-010, D1).
    fn is_metadata(path: &[u8]) -> bool;

    /// The bytes of a path, as [`PathRule::check`] accepted them.
    fn bytes(path: &Self::Path) -> &[u8];
}

/// A path as a map key, ordered and compared by its bytes, so the order of
/// a workspace and every range over it never depend on the rule's type.
struct Key<R: PathRule>(R::Path);

impl<R: PathRule> Key<R> {
    fn bytes(&self) -> &[u8] {
        R::bytes(&self.0)
    }
}

impl<R: PathRule> Clone for Key<R> {
    fn clone(&self) -> Key<R> {
        Key(self.0.clone())
    }
}

impl<R: PathRule> PartialEq for Key<R> {
    fn eq(&self, other: &Key<R>) -> bool {
        self.bytes() == other.bytes()
    }
}

impl<R: PathRule> Eq for Key<R> {}

impl<R: PathRule> PartialOrd for Key<R> {
    fn partial_cmp(&self, other: &Key<R>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<R: PathRule> Ord for Key<R> {
    fn cmp(&self, other: &Key<R>) -> Ordering {
        self.bytes().cmp(other.bytes())
    }
}

/// Consistent with `Eq` and `Ord`: both are those of the bytes.
impl<R: PathRule> Borrow<[u8]> for Key<R> {
    fn borrow(&self) -> &[u8] {
        self.bytes()
    }
}

/// What a workspace keeps for each path: its kind and its data.
type Value = (Kind, Vec<u8>);

/// The first bytes of every encoded workspace.
pub const MAGIC: &[u8] = b"boneli-workspace 1\n";

/// The default node cap of a decoded workspace (ADR-010, D2): files,
/// symlinks and the directories they imply, together. About 3.6 times the
/// largest base tree measured (55,025 files and directories); without it
/// a 200 MB workspace could ask the host for about 100 million
/// directories.
pub const DEFAULT_MAX_NODES: usize = 200_000;

/// What an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A regular file, mode 0644 (`f`).
    File,
    /// An executable regular file, mode 0755 (`x`).
    Executable,
    /// A symlink; the data is its target (`l`).
    Symlink,
}

impl Kind {
    /// The kind byte in the encoding.
    pub fn byte(self) -> u8 {
        match self {
            Kind::File => b'f',
            Kind::Executable => b'x',
            Kind::Symlink => b'l',
        }
    }

    /// The kind a byte names, if any.
    pub fn from_byte(byte: u8) -> Option<Kind> {
        match byte {
            b'f' => Some(Kind::File),
            b'x' => Some(Kind::Executable),
            b'l' => Some(Kind::Symlink),
            _ => None,
        }
    }

    /// The mode a file of this kind gets; `None` for a symlink.
    pub fn mode(self) -> Option<u32> {
        match self {
            Kind::File => Some(0o644),
            Kind::Executable => Some(0o755),
            Kind::Symlink => None,
        }
    }
}

/// Why an entry cannot join a workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryProblem {
    /// The path lies beneath a file or symlink entry.
    BeneathEntry,
    /// Other entries lie beneath the path.
    HasEntriesBeneath,
    /// A symlink's target is empty.
    EmptyTarget,
    /// A symlink's target contains NUL.
    NulInTarget,
}

impl fmt::Display for EntryProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EntryProblem::BeneathEntry => "lies beneath a file or symlink entry",
            EntryProblem::HasEntriesBeneath => "has entries beneath it",
            EntryProblem::EmptyTarget => "is a symlink with an empty target",
            EntryProblem::NulInTarget => "is a symlink whose target contains NUL",
        })
    }
}

/// Why bytes are not an encoded workspace, with `P` the path rule's
/// problem type ([`PathRule::Problem`]). Entries are counted from 0 in
/// encoding order; a detail quotes indexes and lengths, never the
/// agent-written bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError<P> {
    /// The bytes do not start with [`MAGIC`].
    Magic,
    /// A length or field runs past the end of the bytes.
    Truncated {
        /// The entry being read.
        entry: usize,
        /// The field being read.
        field: &'static str,
        /// The bytes the field needs.
        wanted: u64,
        /// The bytes left.
        left: usize,
    },
    /// The kind byte is not `f`, `x` or `l`.
    UnknownKind {
        /// The entry.
        entry: usize,
        /// The byte.
        byte: u8,
    },
    /// The path breaks the path rule ([`PathRule::check`]).
    Path {
        /// The entry.
        entry: usize,
        /// The rule's reason.
        problem: P,
    },
    /// The path equals the previous entry's.
    Duplicate {
        /// The entry.
        entry: usize,
    },
    /// The path sorts before the previous entry's.
    Unsorted {
        /// The entry.
        entry: usize,
    },
    /// The entry breaks a workspace invariant.
    Entry {
        /// The entry.
        entry: usize,
        /// The invariant.
        problem: EntryProblem,
    },
    /// More files, symlinks and implied directories than the cap.
    TooManyNodes {
        /// The cap.
        max: usize,
    },
}

impl<P: fmt::Debug> fmt::Display for DecodeError<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Magic => write!(f, "not a boneli workspace (wrong or missing magic)"),
            DecodeError::Truncated {
                entry,
                field,
                wanted,
                left,
            } => write!(
                f,
                "entry {entry}: the {field} needs {wanted} bytes, {left} left"
            ),
            DecodeError::UnknownKind { entry, byte } => {
                write!(f, "entry {entry}: unknown kind byte 0x{byte:02x}")
            }
            DecodeError::Path { entry, problem } => {
                write!(f, "entry {entry}: the path is refused ({problem:?})")
            }
            DecodeError::Duplicate { entry } => {
                write!(f, "entry {entry}: the path repeats the previous one")
            }
            DecodeError::Unsorted { entry } => {
                write!(f, "entry {entry}: the path sorts before the previous one")
            }
            DecodeError::Entry { entry, problem } => write!(f, "entry {entry} {problem}"),
            DecodeError::TooManyNodes { max } => write!(
                f,
                "more than {max} files, symlinks and directories (the node cap)"
            ),
        }
    }
}

impl<P: fmt::Debug> std::error::Error for DecodeError<P> {}

/// A workspace under the path rule `R`: every entry's kind and data by
/// path, in the byte order of the paths. No entry lies beneath a file or
/// symlink entry, and no symlink target is empty or contains NUL;
/// [`Workspace::decode`] and [`Workspace::from_sorted`] keep both.
pub struct Workspace<R: PathRule> {
    entries: BTreeMap<Key<R>, Value>,
}

impl<R: PathRule> Clone for Workspace<R> {
    fn clone(&self) -> Workspace<R> {
        Workspace {
            entries: self.entries.clone(),
        }
    }
}

impl<R: PathRule> Default for Workspace<R> {
    fn default() -> Workspace<R> {
        Workspace {
            entries: BTreeMap::new(),
        }
    }
}

/// Two workspaces are equal when they hold the same paths, by their
/// bytes, with the same kinds and data.
impl<R: PathRule> PartialEq for Workspace<R> {
    fn eq(&self, other: &Workspace<R>) -> bool {
        self.entries == other.entries
    }
}

impl<R: PathRule> Eq for Workspace<R> {}

/// The entries in path order, each path in the rule's own `Debug`.
impl<R: PathRule> fmt::Debug for Workspace<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Workspace")
            .field("entries", &Entries(&self.entries))
            .finish()
    }
}

/// The entry map as `Debug` prints it: each path in the rule's `Debug`.
struct Entries<'a, R: PathRule>(&'a BTreeMap<Key<R>, Value>);

impl<R: PathRule> fmt::Debug for Entries<'_, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(key, value)| (&key.0, value)))
            .finish()
    }
}

impl<R: PathRule> Workspace<R> {
    /// An empty workspace.
    pub fn new() -> Workspace<R> {
        Workspace::default()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at `path`.
    pub fn get(&self, path: &R::Path) -> Option<(Kind, &[u8])> {
        self.get_bytes(R::bytes(path))
    }

    /// The entry whose path has these bytes.
    pub(crate) fn get_bytes(&self, path: &[u8]) -> Option<(Kind, &[u8])> {
        self.entries
            .get(path)
            .map(|(kind, data)| (*kind, data.as_slice()))
    }

    /// Every entry in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&R::Path, Kind, &[u8])> {
        self.entries
            .iter()
            .map(|(path, (kind, data))| (&path.0, *kind, data.as_slice()))
    }

    /// Adds or replaces the entry at `path`, unless that breaks an
    /// invariant. Test-only: it looks every ancestor up, so it costs
    /// O(depth * length) per path, and a tree whose paths an agent chose
    /// (a workspace, or a checkout after `apply`) could make that hours of
    /// CPU (review of part 2). Code builds a workspace with
    /// [`Workspace::decode`] or [`Workspace::from_sorted`], both linear.
    /// Built only for this crate's tests and, through the `test-seam`
    /// feature, for the adapters' tests.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn insert(&mut self, path: R::Path, kind: Kind, data: Vec<u8>) -> Result<(), EntryProblem> {
        target_problem(kind, &data).map_or(Ok(()), Err)?;
        let text = R::bytes(&path);
        // Every proper ancestor of `path`, at each `/`.
        let beneath = slashes(text).any(|at| self.entries.contains_key(&text[..at]));
        if beneath {
            return Err(EntryProblem::BeneathEntry);
        }
        if self.implies_directory(text) {
            return Err(EntryProblem::HasEntriesBeneath);
        }
        self.entries.insert(Key(path), (kind, data));
        Ok(())
    }

    /// Whether some entry lies beneath `dir`, which makes it a directory.
    pub(crate) fn implies_directory(&self, dir: &[u8]) -> bool {
        // Paths beneath `dir` all start with `dir/`, so they sort together
        // in byte order, the order of the map, and the first path at or
        // after `dir/` is beneath `dir` exactly when some path is.
        let prefix = [dir, b"/"].concat();
        self.entries
            .range::<[u8], _>((Bound::Included(prefix.as_slice()), Bound::Unbounded))
            .next()
            .is_some_and(|(next, _)| next.bytes().starts_with(&prefix))
    }

    /// The files, symlinks and directories the workspace makes on disk:
    /// every entry and every distinct directory an entry implies. Linear in
    /// the path bytes.
    pub fn nodes(&self) -> usize {
        let mut previous = None;
        let mut nodes = 0usize;
        for path in self.entries.keys() {
            let text = path.bytes();
            nodes = nodes.saturating_add(1 + new_directories(previous, text));
            previous = Some(text);
        }
        nodes
    }

    /// Removes the entry at `path` and returns it.
    pub fn remove(&mut self, path: &R::Path) -> Option<(Kind, Vec<u8>)> {
        self.entries.remove(R::bytes(path))
    }

    /// The workspace without repository metadata
    /// ([`PathRule::is_metadata`], ADR-010 D1).
    pub fn without_metadata(mut self) -> Workspace<R> {
        self.entries.retain(|path, _| !R::is_metadata(path.bytes()));
        self
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for (path, (kind, data)) in &self.entries {
            out.push(kind.byte());
            put_field(&mut out, path.bytes());
            put_field(&mut out, data);
        }
        out
    }

    /// Builds a workspace from entries in path order (the byte order of the
    /// full paths, which is the order `git ls-tree -r -z` lists a tree in),
    /// under the same rules and the same node cap as
    /// [`Workspace::decode`], in time linear in the path bytes. Input out
    /// of order or with a duplicate path is refused (`Unsorted`,
    /// `Duplicate`), never sorted silently, so a listing that is not what
    /// it claims fails closed. Errors count entries from 0 in input order.
    /// This is the constructor for a tree read from git, the snapshot of
    /// an applied checkout included, whose paths the agent chose.
    pub fn from_sorted<I>(
        entries: I,
        max_nodes: usize,
    ) -> Result<Workspace<R>, DecodeError<R::Problem>>
    where
        I: IntoIterator<Item = (R::Path, Kind, Vec<u8>)>,
    {
        let mut sorted = Sorted::new(max_nodes);
        for (path, kind, data) in entries {
            sorted.room()?;
            sorted.check_path(R::bytes(&path))?;
            sorted.push(path, kind, data)?;
        }
        Ok(sorted.finish())
    }

    /// Decodes an encoded workspace of at most `max_nodes` files, symlinks
    /// and implied directories ([`Workspace::nodes`]), refusing every
    /// encoding [`Workspace::encode`] would not produce.
    ///
    /// The ancestor check runs in linear time over a stack: the earlier
    /// entries that are a string prefix of the previous path. Paths that
    /// start with a prefix sort together, so every earlier entry that is a
    /// string prefix of the current path is still on the stack, and the
    /// path lies beneath one of them exactly when the byte after it is
    /// `/`. Looking every ancestor up in the map instead costs quadratic
    /// time on a deep path next to a sibling that shares its prefixes.
    pub fn decode(bytes: &[u8], max_nodes: usize) -> Result<Workspace<R>, DecodeError<R::Problem>> {
        let rest = bytes.strip_prefix(MAGIC).ok_or(DecodeError::Magic)?;
        let mut reader = Reader { rest, entry: 0 };
        let mut sorted = Sorted::new(max_nodes);
        while !reader.rest.is_empty() {
            let entry = reader.entry;
            sorted.room()?;
            let byte = reader.bytes("kind", 1)?[0];
            let kind = Kind::from_byte(byte).ok_or(DecodeError::UnknownKind { entry, byte })?;
            let raw = reader.field("path")?;
            let path = R::check(raw).map_err(|problem| DecodeError::Path { entry, problem })?;
            sorted.check_path(R::bytes(&path))?;
            let data = reader.field("data")?;
            sorted.push(path, kind, data.to_vec())?;
            reader.entry += 1;
        }
        Ok(sorted.finish())
    }
}

/// The checks that `decode` and `from_sorted` share, over entries that
/// arrive in path order, in time linear in the path bytes.
///
/// The ancestor check keeps a stack (`prefixes`, indexes into `entries`)
/// of the earlier entries that are a string prefix of the previous path.
/// Paths that start with a prefix sort together, so every earlier entry
/// that is a string prefix of the current path is still on the stack, and
/// the path lies beneath one of them exactly when the byte after it is
/// `/`. Looking every ancestor up in the map instead costs quadratic time
/// on a deep path next to a sibling that shares its prefixes.
struct Sorted<R: PathRule> {
    entries: Vec<(Key<R>, Value)>,
    prefixes: Vec<usize>,
    nodes: usize,
    max_nodes: usize,
}

impl<R: PathRule> Sorted<R> {
    fn new(max_nodes: usize) -> Sorted<R> {
        Sorted {
            entries: Vec::new(),
            prefixes: Vec::new(),
            nodes: 0,
            max_nodes,
        }
    }

    fn too_many(&self) -> DecodeError<R::Problem> {
        DecodeError::TooManyNodes {
            max: self.max_nodes,
        }
    }

    /// Before the next entry is read: every entry adds at least itself.
    fn room(&self) -> Result<(), DecodeError<R::Problem>> {
        if self.nodes >= self.max_nodes {
            return Err(self.too_many());
        }
        Ok(())
    }

    /// Checks the next path against the earlier ones: order, the node cap
    /// and the ancestors. It then sits on the stack as the entry
    /// [`Sorted::push`] adds next.
    fn check_path(&mut self, text: &[u8]) -> Result<(), DecodeError<R::Problem>> {
        let entry = self.entries.len();
        let previous = self.entries.last().map(|(p, _)| p.bytes());
        if let Some(previous) = previous {
            match text.cmp(previous) {
                Ordering::Equal => return Err(DecodeError::Duplicate { entry }),
                Ordering::Less => return Err(DecodeError::Unsorted { entry }),
                Ordering::Greater => {}
            }
        }
        self.nodes = self
            .nodes
            .saturating_add(1 + new_directories(previous, text));
        if self.nodes > self.max_nodes {
            return Err(self.too_many());
        }
        let entries = &self.entries;
        let path_of = |i: usize| entries[i].0.bytes();
        while self
            .prefixes
            .last()
            .is_some_and(|top| !text.starts_with(path_of(*top)))
        {
            self.prefixes.pop();
        }
        // Each element is a shorter string prefix of `text`.
        let beneath = self
            .prefixes
            .iter()
            .any(|i| text[path_of(*i).len()] == b'/');
        if beneath {
            return Err(DecodeError::Entry {
                entry,
                problem: EntryProblem::BeneathEntry,
            });
        }
        self.prefixes.push(entry);
        Ok(())
    }

    /// Adds the entry whose path [`Sorted::check_path`] just accepted.
    fn push(
        &mut self,
        path: R::Path,
        kind: Kind,
        data: Vec<u8>,
    ) -> Result<(), DecodeError<R::Problem>> {
        let entry = self.entries.len();
        if let Some(problem) = target_problem(kind, &data) {
            return Err(DecodeError::Entry { entry, problem });
        }
        self.entries.push((Key(path), (kind, data)));
        Ok(())
    }

    /// Already sorted, so the map is built in one pass, without a search
    /// per entry.
    fn finish(self) -> Workspace<R> {
        Workspace {
            entries: self.entries.into_iter().collect(),
        }
    }
}

/// The directories `path` implies that the previous path in sorted order
/// did not. A directory `d` both imply sits inside their common prefix:
/// everything between two paths that start with `d/` starts with it too,
/// so no earlier path implies a directory the previous one does not. The
/// new ones are therefore the `/` positions of `path` at or past the
/// common prefix. Only `/` counts: a backslash is a name byte on the host
/// (ADR-018, D2). Linear in `path`.
pub(crate) fn new_directories(previous: Option<&[u8]>, path: &[u8]) -> usize {
    let shared = previous.map_or(0, |p| common_prefix(p, path));
    path[shared..].iter().filter(|b| **b == b'/').count()
}

/// The length in bytes of the common prefix of `a` and `b`.
pub(crate) fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// The positions of the `/` bytes of `path`, in order.
pub(crate) fn slashes(path: &[u8]) -> impl Iterator<Item = usize> + '_ {
    path.iter()
        .enumerate()
        .filter(|(_, b)| **b == b'/')
        .map(|(i, _)| i)
}

/// What is wrong with a symlink's target, if `kind` is a symlink.
fn target_problem(kind: Kind, data: &[u8]) -> Option<EntryProblem> {
    match kind {
        Kind::Symlink if data.is_empty() => Some(EntryProblem::EmptyTarget),
        Kind::Symlink if data.contains(&0) => Some(EntryProblem::NulInTarget),
        _ => None,
    }
}

fn put_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}

/// Reads one entry's fields; every read checks what is left first, so
/// nothing is allocated for a length the input does not hold.
struct Reader<'a> {
    rest: &'a [u8],
    entry: usize,
}

impl<'a> Reader<'a> {
    fn bytes<P>(&mut self, field: &'static str, n: u64) -> Result<&'a [u8], DecodeError<P>> {
        let left = self.rest.len();
        // Compared as u64, so a length past usize never wraps.
        if n > left as u64 {
            return Err(DecodeError::Truncated {
                entry: self.entry,
                field,
                wanted: n,
                left,
            });
        }
        let (head, tail) = self.rest.split_at(n as usize);
        self.rest = tail;
        Ok(head)
    }

    fn field<P>(&mut self, field: &'static str) -> Result<&'a [u8], DecodeError<P>> {
        let length_field = if field == "path" {
            "path length"
        } else {
            "data length"
        };
        let mut length = [0u8; 8];
        length.copy_from_slice(self.bytes(length_field, 8)?);
        self.bytes(field, u64::from_be_bytes(length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rule::{TestPath, TestProblem, TestRule};

    type Workspace = super::Workspace<TestRule>;
    type DecodeError = super::DecodeError<TestProblem>;

    fn path(text: &str) -> TestPath {
        bpath(text.as_bytes())
    }

    fn bpath(bytes: &[u8]) -> TestPath {
        TestPath::parse(bytes).expect("a valid path")
    }

    fn bworkspace(entries: &[(&[u8], Kind, &[u8])]) -> Workspace {
        let mut w = Workspace::new();
        for (p, kind, data) in entries {
            w.insert(bpath(p), *kind, data.to_vec())
                .expect("a valid entry");
        }
        w
    }

    fn workspace(entries: &[(&str, Kind, &[u8])]) -> Workspace {
        let mut w = Workspace::new();
        for (p, kind, data) in entries {
            w.insert(path(p), *kind, data.to_vec())
                .expect("a valid entry");
        }
        w
    }

    /// Encodes raw entries without any check, so a test can build what
    /// `encode` never would.
    fn raw(entries: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for (kind, p, data) in entries {
            out.push(*kind);
            out.extend_from_slice(&(p.len() as u64).to_be_bytes());
            out.extend_from_slice(p);
            out.extend_from_slice(&(data.len() as u64).to_be_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn workspace_round_trip() {
        let every_byte: Vec<u8> = (0..=255u8).collect();
        let cases = [
            Workspace::new(),
            workspace(&[("a", Kind::File, b"x")]),
            workspace(&[("empty", Kind::File, b"")]),
            workspace(&[("run.sh", Kind::Executable, b"#!/bin/sh\n")]),
            workspace(&[("link", Kind::Symlink, b"../elsewhere")]),
            workspace(&[("bytes", Kind::File, &every_byte)]),
            workspace(&[
                ("ž/ř.txt", Kind::File, b"1"),
                ("a\u{200B}", Kind::File, b"2"),
                ("a\nb", Kind::File, b"3"),
                (" a ", Kind::File, b"4"),
                ("~/x", Kind::File, b"5"),
                ("file:x", Kind::File, b"6"),
                ("-rf", Kind::Executable, b"7"),
                (":(top)x", Kind::Symlink, b"/"),
            ]),
            // Paths the citation rule refuses, each class alone and all
            // together (ADR-018, D2).
            bworkspace(&[(b"a\\b", Kind::File, b"1")]),
            bworkspace(&[(b" ", Kind::File, b"2")]),
            bworkspace(&[(b"x\xff", Kind::Executable, b"3")]),
            bworkspace(&[
                (b"\t", Kind::File, b"1"),
                (b" ", Kind::File, b"2"),
                ("\u{200B}".as_bytes(), Kind::File, b"3"),
                (b"a\\b", Kind::File, b"4"),
                (b"d\\e/f", Kind::File, b"5"),
                (b"l\\x", Kind::Symlink, b"x\xff"),
                (b"run\\x.sh", Kind::Executable, b"6"),
                (b"x\xff", Kind::File, b"7"),
            ]),
        ];
        assert_eq!(Workspace::new().encode(), MAGIC.to_vec());
        for w in cases {
            let bytes = w.encode();
            assert_eq!(
                Workspace::decode(&bytes, DEFAULT_MAX_NODES),
                Ok(w.clone()),
                "{w:?}"
            );
            // Canonical: decoding and encoding again gives the same bytes.
            let again = Workspace::decode(&bytes, DEFAULT_MAX_NODES)
                .expect("decodes")
                .encode();
            assert_eq!(again, bytes);
        }
        // The format as ADR-010 D2 states it, byte for byte.
        let one = workspace(&[("ab", Kind::Executable, b"xyz")]).encode();
        let mut expected = MAGIC.to_vec();
        expected.push(b'x');
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
        expected.extend_from_slice(b"ab");
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 3]);
        expected.extend_from_slice(b"xyz");
        assert_eq!(one, expected);
    }

    /// A workspace of `MAGIC` alone is the empty workspace, both ways, and
    /// makes no node; one byte after it is a truncated entry.
    #[test]
    fn empty_workspace_round_trips() {
        let empty = Workspace::decode(MAGIC, DEFAULT_MAX_NODES).expect("decodes");
        assert!(empty.is_empty());
        assert_eq!(empty.nodes(), 0);
        assert_eq!(empty, Workspace::new());
        assert_eq!(empty.encode(), MAGIC);
        assert_eq!(
            Workspace::from_sorted(Vec::new(), 0).map(|w| w.encode()),
            Ok(MAGIC.to_vec())
        );
        let mut one_more = MAGIC.to_vec();
        one_more.push(b'f');
        assert_eq!(
            Workspace::decode(&one_more, DEFAULT_MAX_NODES),
            Err(DecodeError::Truncated {
                entry: 0,
                field: "path length",
                wanted: 8,
                left: 0,
            })
        );
    }

    #[test]
    fn encode_is_canonical() {
        let entries: [(&str, Kind, &[u8]); 5] = [
            ("b", Kind::File, b"1"),
            ("a/c", Kind::Executable, b"2"),
            ("a.txt", Kind::File, b"3"),
            ("a/b", Kind::Symlink, b"t"),
            ("Z", Kind::File, b"4"),
        ];
        let forward = workspace(&entries);
        let mut reversed = entries;
        reversed.reverse();
        let backward = workspace(&reversed);
        assert_eq!(forward.encode(), backward.encode());
        // Path order is byte order: `Z` < `a.txt` < `a/b` < `a/c` < `b`.
        let order: Vec<&[u8]> = forward.iter().map(|(p, _, _)| p.as_bytes()).collect();
        assert_eq!(order, [&b"Z"[..], b"a.txt", b"a/b", b"a/c", b"b"]);
    }

    /// Byte order over paths that are not citable: tab, space, `.git`,
    /// `a.b`, `a/x`, `a\b`, `ž` (C5 BE) and 0xFF. Any insertion order
    /// gives one encoding, and a duplicate or a reversed pair is refused.
    #[test]
    fn encode_is_canonical_over_bytes() {
        let sorted: [&[u8]; 8] = [
            b"\t",
            b" ",
            b".git/HEAD",
            b"a.b",
            b"a/x",
            b"a\\b",
            "\u{17E}".as_bytes(),
            b"\xff",
        ];
        let entries: Vec<(&[u8], Kind, &[u8])> =
            sorted.iter().map(|p| (*p, Kind::File, &b"x"[..])).collect();
        let forward = bworkspace(&entries);
        let mut reversed = entries.clone();
        reversed.reverse();
        assert_eq!(forward.encode(), bworkspace(&reversed).encode());
        let order: Vec<&[u8]> = forward.iter().map(|(p, _, _)| p.as_bytes()).collect();
        assert_eq!(order, sorted);
        let rows: Vec<(u8, &[u8], &[u8])> = sorted.iter().map(|p| (b'f', *p, &b"x"[..])).collect();
        assert_eq!(
            Workspace::decode(&raw(&rows), DEFAULT_MAX_NODES),
            Ok(forward)
        );
        for k in 1..rows.len() {
            let mut swapped = rows.clone();
            swapped.swap(k - 1, k);
            assert_eq!(
                Workspace::decode(&raw(&swapped), DEFAULT_MAX_NODES),
                Err(DecodeError::Unsorted { entry: k }),
                "{k}"
            );
            let mut doubled = rows.clone();
            doubled.insert(k, rows[k - 1]);
            assert_eq!(
                Workspace::decode(&raw(&doubled), DEFAULT_MAX_NODES),
                Err(DecodeError::Duplicate { entry: k }),
                "{k}"
            );
        }
    }

    /// A workspace of one blank entry decodes, and paths of every class
    /// decode to themselves (ADR-018, D2).
    #[test]
    fn decode_accepts_uncitable_paths() {
        let blank = Workspace::decode(&raw(&[(b'f', b" ", b"x")]), DEFAULT_MAX_NODES)
            .expect("a blank path decodes");
        assert_eq!(blank.nodes(), 1);
        assert_eq!(blank.get(&bpath(b" ")), Some((Kind::File, &b"x"[..])));
        for p in [
            &b"a\\b"[..],
            b"x\xff",
            b"\xc0\xae\xc0\xae",
            b"..\\x",
            "\u{3000}".as_bytes(),
        ] {
            let w = Workspace::decode(&raw(&[(b'f', p, b"")]), DEFAULT_MAX_NODES).expect("decodes");
            assert_eq!(
                w.iter().map(|(q, _, _)| q.as_bytes()).collect::<Vec<_>>(),
                [p]
            );
        }
    }

    /// Only `/` makes a directory: `{a\b\c, d\e/f}` is two files and the
    /// directory `d\e`, three nodes.
    #[test]
    fn nodes_count_only_slashes() {
        let rows: [(u8, &[u8], &[u8]); 2] = [(b'f', b"a\\b\\c", b""), (b'f', b"d\\e/f", b"")];
        assert_eq!(Workspace::decode(&raw(&rows), 3).map(|w| w.nodes()), Ok(3));
        assert_eq!(
            Workspace::decode(&raw(&rows), 2),
            Err(DecodeError::TooManyNodes { max: 2 })
        );
        let w = bworkspace(&[(b"a\\b\\c", Kind::File, b""), (b"d\\e/f", Kind::File, b"")]);
        assert!(w.implies_directory(b"d\\e"));
        assert!(!w.implies_directory(b"a\\b"));
        assert!(!w.implies_directory(b"d"));
    }

    #[test]
    fn decode_refuses() {
        let f = b'f';
        let mut bad_magic = raw(&[]);
        bad_magic[MAGIC.len() - 2] = b'2';
        let one = raw(&[(f, b"a", b"x")]);
        // A path length one past the end.
        let mut past_end = MAGIC.to_vec();
        past_end.push(f);
        past_end.extend_from_slice(&2u64.to_be_bytes());
        past_end.push(b'a');
        // Path and data lengths of u64::MAX.
        let mut huge_path = MAGIC.to_vec();
        huge_path.push(f);
        huge_path.extend_from_slice(&u64::MAX.to_be_bytes());
        let mut huge_data = MAGIC.to_vec();
        huge_data.push(f);
        huge_data.extend_from_slice(&1u64.to_be_bytes());
        huge_data.push(b'a');
        huge_data.extend_from_slice(&u64::MAX.to_be_bytes());
        // A whole entry, then a kind byte and half a length.
        let mut partial = one.clone();
        partial.extend_from_slice(&[f, 0, 0, 0]);
        // A data length one past the end.
        let mut data_past_end = one.clone();
        let last = data_past_end.len() - 2;
        data_past_end[last] = 2;

        let truncated = |entry, field, wanted, left| DecodeError::Truncated {
            entry,
            field,
            wanted,
            left,
        };
        let path_problem = |problem| DecodeError::Path { entry: 0, problem };
        let entry = |entry, problem| DecodeError::Entry { entry, problem };
        let rows: Vec<(&str, Vec<u8>, DecodeError)> = vec![
            ("bad magic", bad_magic, DecodeError::Magic),
            ("magic cut short", MAGIC[..10].to_vec(), DecodeError::Magic),
            ("no bytes", Vec::new(), DecodeError::Magic),
            (
                "unknown kind",
                raw(&[(b'd', b"a", b"")]),
                DecodeError::UnknownKind {
                    entry: 0,
                    byte: b'd',
                },
            ),
            (
                "kind 0",
                raw(&[(0, b"a", b"")]),
                DecodeError::UnknownKind { entry: 0, byte: 0 },
            ),
            ("length past end", past_end, truncated(0, "path", 2, 1)),
            (
                "data length past end",
                data_past_end,
                truncated(0, "data", 2, 1),
            ),
            (
                "path u64::MAX",
                huge_path,
                truncated(0, "path", u64::MAX, 0),
            ),
            (
                "data u64::MAX",
                huge_data,
                truncated(0, "data", u64::MAX, 0),
            ),
            (
                "trailing partial entry",
                partial,
                truncated(1, "path length", 8, 3),
            ),
            (
                "absolute",
                raw(&[(f, b"/abs", b"")]),
                path_problem(TestProblem::Absolute),
            ),
            (
                "parent",
                raw(&[(f, b"../x", b"")]),
                path_problem(TestProblem::ParentComponent),
            ),
            (
                "dot",
                raw(&[(f, b"a/./x", b"")]),
                path_problem(TestProblem::DotComponent),
            ),
            (
                "empty component",
                raw(&[(f, b"a//b", b"")]),
                path_problem(TestProblem::EmptyComponent),
            ),
            (
                "NUL",
                raw(&[(f, b"a\0b", b"")]),
                path_problem(TestProblem::Nul),
            ),
            (
                "empty path",
                raw(&[(f, b"", b"")]),
                path_problem(TestProblem::Empty),
            ),
            (
                "duplicate",
                raw(&[(f, b"a", b"1"), (f, b"a", b"2")]),
                DecodeError::Duplicate { entry: 1 },
            ),
            (
                "unsorted",
                raw(&[(f, b"b", b""), (f, b"a", b"")]),
                DecodeError::Unsorted { entry: 1 },
            ),
            (
                "file then a path beneath it",
                raw(&[(f, b"a", b""), (f, b"a/b", b"")]),
                entry(1, EntryProblem::BeneathEntry),
            ),
            (
                "symlink then a path beneath it",
                raw(&[(b'l', b"l", b"/"), (f, b"l/x", b"")]),
                entry(1, EntryProblem::BeneathEntry),
            ),
            (
                "non-adjacent ancestor",
                raw(&[(f, b"a", b""), (f, b"a.txt", b""), (f, b"a/b", b"")]),
                entry(2, EntryProblem::BeneathEntry),
            ),
            (
                "deep non-adjacent ancestor",
                raw(&[
                    (f, b"a", b""),
                    (f, b"a.b", b""),
                    (f, b"a.c/d", b""),
                    (f, b"a/x/y/z", b""),
                ]),
                entry(3, EntryProblem::BeneathEntry),
            ),
            (
                "empty link target",
                raw(&[(b'l', b"l", b"")]),
                entry(0, EntryProblem::EmptyTarget),
            ),
            (
                "NUL in a link target",
                raw(&[(b'l', b"l", b"a\0b")]),
                entry(0, EntryProblem::NulInTarget),
            ),
        ];
        for (name, bytes, expected) in rows {
            assert_eq!(
                Workspace::decode(&bytes, DEFAULT_MAX_NODES),
                Err(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn decode_entry_cap_is_inclusive() {
        let names = ["a", "b", "c", "d", "e"];
        let entries: Vec<(u8, &[u8], &[u8])> = names
            .iter()
            .map(|n| (b'f', n.as_bytes(), &b""[..]))
            .collect();
        assert_eq!(
            Workspace::decode(&raw(&entries[..4]), 4).map(|w| w.len()),
            Ok(4)
        );
        let refused = Workspace::decode(&raw(&entries), 4);
        assert_eq!(refused, Err(DecodeError::TooManyNodes { max: 4 }));
        let detail = refused.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(detail.contains("more than 4 files"), "{detail}");
        // The cap holds before the fifth entry is read, even a malformed one.
        let mut garbage = raw(&entries[..4]);
        garbage.push(b'?');
        assert_eq!(
            Workspace::decode(&garbage, 4),
            Err(DecodeError::TooManyNodes { max: 4 })
        );
        assert_eq!(
            Workspace::decode(MAGIC, 0).map(|w| w.len()),
            Ok(0),
            "an empty workspace fits a cap of 0"
        );
    }

    /// A path two million components deep next to a sibling that shares
    /// every one of its prefixes. An ancestor check that looks every
    /// ancestor up in an ordered map compares about 2 * 10^12 bytes here
    /// (minutes; a mutant doing that took 40 s at a quarter of this
    /// depth); the decoder must stay linear in the input (well under a
    /// second). The bound leaves a wide margin both ways.
    #[test]
    fn decode_is_linear_in_path_depth() {
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
        let deep = "a/".repeat(2_000_000) + "a";
        let sibling = format!("{deep}.b");
        let child = format!("{deep}/x");
        let bytes = raw(&[
            (b'f', sibling.as_bytes(), b"1"),
            (b'f', child.as_bytes(), b"2"),
        ]);
        // Time only: the node cap (about two million directories here) is
        // lifted, so the decoder walks every byte.
        let start = std::time::Instant::now();
        let decoded = Workspace::decode(&bytes, usize::MAX).map(|w| w.len());
        assert_eq!(decoded, Ok(2));
        // The same shape with the deep path itself as a file is refused.
        let bytes = raw(&[
            (b'f', deep.as_bytes(), b"0"),
            (b'f', sibling.as_bytes(), b"1"),
            (b'f', child.as_bytes(), b"2"),
        ]);
        assert_eq!(
            Workspace::decode(&bytes, usize::MAX),
            Err(DecodeError::Entry {
                entry: 2,
                problem: EntryProblem::BeneathEntry
            })
        );
        assert!(start.elapsed() < DEADLINE, "{:?}", start.elapsed());
    }

    /// The cap counts the directories an entry implies: one entry 3,837
    /// bytes long once made 1,900 directories under a cap of 1 (review of
    /// part 2).
    #[test]
    fn decode_node_cap_counts_directories() {
        let f = b'f';
        // One deep entry: ten directories and the file.
        let deep = "a/".repeat(10) + "f";
        let one = raw(&[(f, deep.as_bytes(), b"")]);
        assert_eq!(
            Workspace::decode(&one, 10),
            Err(DecodeError::TooManyNodes { max: 10 })
        );
        assert_eq!(Workspace::decode(&one, 11).map(|w| w.nodes()), Ok(11));
        // The review's shape (1,900 directories) under a cap of 1.
        let probe = "a/".repeat(1900) + "f";
        assert_eq!(
            Workspace::decode(&raw(&[(f, probe.as_bytes(), b"")]), 1),
            Err(DecodeError::TooManyNodes { max: 1 })
        );
        // Entries that share their parents count each directory once:
        // `d`, `d/e` and 100 files.
        let names: Vec<String> = (0..100).map(|n| format!("d/e/f{n:03}")).collect();
        let shared: Vec<(u8, &[u8], &[u8])> =
            names.iter().map(|n| (f, n.as_bytes(), &b""[..])).collect();
        assert_eq!(
            Workspace::decode(&raw(&shared), 102).map(|w| w.nodes()),
            Ok(102)
        );
        assert_eq!(
            Workspace::decode(&raw(&shared), 101),
            Err(DecodeError::TooManyNodes { max: 101 })
        );
        // Branches: `a`, `a/b`, `a/c`, `a/c/d` and three entries.
        let branches = raw(&[(f, b"a/b/x", b""), (f, b"a/c/d/y", b""), (f, b"a/c/z", b"")]);
        assert_eq!(Workspace::decode(&branches, 7).map(|w| w.nodes()), Ok(7));
        assert_eq!(
            Workspace::decode(&branches, 6),
            Err(DecodeError::TooManyNodes { max: 6 })
        );
    }

    /// `nodes` agrees with a direct count of every entry and every
    /// distinct ancestor directory.
    #[test]
    fn nodes_counts_entries_and_distinct_directories() {
        let w = workspace(&[
            ("Z", Kind::File, b""),
            ("a b/c", Kind::File, b""),
            ("a.txt", Kind::File, b""),
            ("a/b/c/d", Kind::File, b""),
            ("a/b/c/e", Kind::Symlink, b"/"),
            ("a/b/x", Kind::Executable, b""),
            ("a/bc/y", Kind::File, b""),
            ("a/c", Kind::File, b""),
            ("b/a/b/c", Kind::File, b""),
        ]);
        let mut directories = std::collections::BTreeSet::new();
        for (p, _, _) in w.iter() {
            let text = p.as_bytes();
            for i in slashes(text) {
                directories.insert(&text[..i]);
            }
        }
        assert_eq!(w.nodes(), w.len() + directories.len());
        assert_eq!(w.nodes(), 9 + 8);
        assert_eq!(Workspace::new().nodes(), 0);
    }

    /// `from_sorted` accepts and refuses exactly what `decode` does on the
    /// same entries, with the same error.
    #[test]
    fn from_sorted_agrees_with_decode() {
        let deep = "a/".repeat(10) + "f";
        // (kind, path, data) rows, and the node cap.
        type Row<'a> = (u8, &'a [u8], &'a [u8]);
        let cases: Vec<(Vec<Row>, usize)> = vec![
            (vec![], DEFAULT_MAX_NODES),
            (
                vec![
                    (b'f', b"Z", b"1"),
                    (b'x', b"a.txt", b"2"),
                    (b'l', b"a/b", b"/"),
                    (b'f', b"a/c/d", b""),
                ],
                DEFAULT_MAX_NODES,
            ),
            (
                vec![(b'f', b"b", b""), (b'f', b"a", b"")],
                DEFAULT_MAX_NODES,
            ),
            (
                vec![(b'f', b"a", b"1"), (b'f', b"a", b"2")],
                DEFAULT_MAX_NODES,
            ),
            (
                vec![
                    (b'f', b"a", b""),
                    (b'f', b"a.txt", b""),
                    (b'f', b"a/b", b""),
                ],
                DEFAULT_MAX_NODES,
            ),
            (
                vec![(b'l', b"l", b"/"), (b'f', b"l/x", b"")],
                DEFAULT_MAX_NODES,
            ),
            (vec![(b'l', b"l", b"")], DEFAULT_MAX_NODES),
            (vec![(b'l', b"l", b"a\0")], DEFAULT_MAX_NODES),
            (vec![(b'f', deep.as_bytes(), b"")], 10),
            (vec![(b'f', deep.as_bytes(), b"")], 11),
            (
                vec![(b'f', b"a", b""), (b'f', b"b", b""), (b'f', b"c", b"")],
                2,
            ),
            // Paths the citation rule refuses, in byte order and reversed.
            (
                vec![
                    (b'f', b"\t", b""),
                    (b'f', b" ", b""),
                    (b'f', b"a\\b", b""),
                    (b'l', b"l\\x", b"x\xff"),
                    (b'x', b"x\xff", b""),
                ],
                DEFAULT_MAX_NODES,
            ),
            (
                vec![(b'f', b"\xff", b""), (b'f', b" ", b"")],
                DEFAULT_MAX_NODES,
            ),
            (vec![(b'f', b"a\\b\\c", b""), (b'f', b"d\\e/f", b"")], 2),
        ];
        for (entries, cap) in cases {
            let decoded = Workspace::decode(&raw(&entries), cap);
            let built = Workspace::from_sorted(
                entries.iter().map(|(kind, p, data)| {
                    (
                        bpath(p),
                        Kind::from_byte(*kind).expect("a kind"),
                        data.to_vec(),
                    )
                }),
                cap,
            );
            assert_eq!(built, decoded, "{entries:?} cap {cap}");
        }
    }

    /// The review's shape for the snapshot of an applied checkout: files
    /// under one chain of 1,900 directories. A constructor that looks
    /// every ancestor up (`insert`) took 13-19 ms per path in a release
    /// build, about an hour for a tree that fills the node cap;
    /// `from_sorted` stays linear (well under a second here). The bound
    /// leaves a wide margin both ways.
    #[test]
    fn from_sorted_is_linear_in_path_depth() {
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);
        let chain = "a/".repeat(1900);
        let paths: Vec<TestPath> = (0..3000)
            .map(|n| path(&format!("{chain}f{n:05}")))
            .collect();
        let start = std::time::Instant::now();
        let built = Workspace::from_sorted(
            paths.into_iter().map(|p| (p, Kind::File, b"x".to_vec())),
            DEFAULT_MAX_NODES,
        );
        assert!(start.elapsed() < DEADLINE, "{:?}", start.elapsed());
        let built = built.expect("built");
        assert_eq!((built.len(), built.nodes()), (3000, 1900 + 3000));
    }

    #[test]
    fn without_metadata_drops_exact_git_only() {
        let kept: [(&str, Kind, &[u8]); 3] = [
            (".github/workflows/ci.yml", Kind::File, b"on: push"),
            (".gitignore", Kind::File, b"dist/"),
            ("src/x.rs", Kind::File, b"fn x() {}"),
        ];
        let expected = workspace(&kept);
        let cases: [&[(&str, Kind, &[u8])]; 3] = [
            &[
                (".git/config", Kind::File, b"[core]"),
                ("sub/.git/HEAD", Kind::File, b"ref: x"),
            ],
            &[(".git", Kind::File, b"gitdir: /elsewhere")],
            &[
                (".git", Kind::Symlink, b"/"),
                ("sub/.git", Kind::Symlink, b"../.."),
            ],
        ];
        for metadata in cases {
            let mut w = expected.clone();
            for (p, kind, data) in metadata {
                w.insert(path(p), *kind, data.to_vec()).expect("valid");
            }
            assert_eq!(w.len(), kept.len() + metadata.len());
            assert_eq!(w.without_metadata(), expected, "{metadata:?}");
        }
    }

    #[test]
    fn insert_keeps_the_invariants() {
        let mut w = workspace(&[("a/b", Kind::File, b"1")]);
        assert_eq!(
            w.insert(path("a"), Kind::File, b"x".to_vec()),
            Err(EntryProblem::HasEntriesBeneath)
        );
        assert_eq!(
            w.insert(path("a/b/c"), Kind::File, b"x".to_vec()),
            Err(EntryProblem::BeneathEntry)
        );
        assert_eq!(
            w.insert(path("l"), Kind::Symlink, Vec::new()),
            Err(EntryProblem::EmptyTarget)
        );
        assert_eq!(
            w.insert(path("l"), Kind::Symlink, b"a\0".to_vec()),
            Err(EntryProblem::NulInTarget)
        );
        // A sibling that shares a prefix but not a component is fine.
        assert_eq!(w.insert(path("a.txt"), Kind::File, b"2".to_vec()), Ok(()));
        assert_eq!(w.insert(path("a b"), Kind::File, b"3".to_vec()), Ok(()));
        // Replacing an entry, including its kind, is fine.
        assert_eq!(w.insert(path("a/b"), Kind::Symlink, b"t".to_vec()), Ok(()));
        assert_eq!(w.get(&path("a/b")), Some((Kind::Symlink, &b"t"[..])));
        assert_eq!(w.len(), 3);
        // Refused inserts change nothing.
        assert_eq!(w.get(&path("a")), None);
        assert_eq!(w.get(&path("l")), None);
        // After a removal the path is free for a directory's place.
        assert_eq!(w.remove(&path("a/b")), Some((Kind::Symlink, b"t".to_vec())));
        assert_eq!(w.remove(&path("a/b")), None);
        assert_eq!(w.insert(path("a"), Kind::File, b"x".to_vec()), Ok(()));
        // Whatever insert accepts, decode accepts again.
        let bytes = w.encode();
        assert_eq!(Workspace::decode(&bytes, DEFAULT_MAX_NODES), Ok(w));
    }

    #[test]
    fn kinds_have_their_bytes_and_modes() {
        let table = [
            (Kind::File, b'f', Some(0o644)),
            (Kind::Executable, b'x', Some(0o755)),
            (Kind::Symlink, b'l', None),
        ];
        for (kind, byte, mode) in table {
            assert_eq!(kind.byte(), byte);
            assert_eq!(Kind::from_byte(byte), Some(kind));
            assert_eq!(kind.mode(), mode);
        }
        for byte in 0..=255u8 {
            if !b"fxl".contains(&byte) {
                assert_eq!(Kind::from_byte(byte), None, "{byte}");
            }
        }
    }
}
