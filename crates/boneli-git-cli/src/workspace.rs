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

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use boneli_app::RelativePath;
use boneli_domain::CitationProblem;

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

/// Why bytes are not an encoded workspace. Entries are counted from 0 in
/// encoding order; a detail quotes indexes and lengths, never the
/// agent-written bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
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
    /// The path is not UTF-8.
    PathNotUtf8 {
        /// The entry.
        entry: usize,
    },
    /// The path breaks the citation path rule ([`RelativePath`]).
    Path {
        /// The entry.
        entry: usize,
        /// The rule's reason.
        problem: CitationProblem,
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

impl fmt::Display for DecodeError {
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
            DecodeError::PathNotUtf8 { entry } => write!(f, "entry {entry}: the path is not UTF-8"),
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

impl std::error::Error for DecodeError {}

/// A workspace: every entry's kind and data by path. No entry lies beneath
/// a file or symlink entry, and no symlink target is empty or contains
/// NUL; [`Workspace::insert`] and [`Workspace::decode`] keep both.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Workspace {
    entries: BTreeMap<RelativePath, (Kind, Vec<u8>)>,
}

impl Workspace {
    /// An empty workspace.
    pub fn new() -> Workspace {
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
    pub fn get(&self, path: &RelativePath) -> Option<(Kind, &[u8])> {
        self.entries
            .get(path)
            .map(|(kind, data)| (*kind, data.as_slice()))
    }

    /// Every entry in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&RelativePath, Kind, &[u8])> {
        self.entries
            .iter()
            .map(|(path, (kind, data))| (path, *kind, data.as_slice()))
    }

    /// Adds or replaces the entry at `path`, unless that breaks an
    /// invariant. It looks every ancestor up, so it costs O(depth * length)
    /// per path: meant for trees from git, whose paths are short.
    /// Agent-written bytes go through [`Workspace::decode`], which is
    /// linear.
    pub fn insert(
        &mut self,
        path: RelativePath,
        kind: Kind,
        data: Vec<u8>,
    ) -> Result<(), EntryProblem> {
        target_problem(kind, &data).map_or(Ok(()), Err)?;
        let text = path.as_str();
        // Every proper ancestor of `path`, at each `/`.
        let beneath = text.match_indices('/').any(|(at, _)| {
            RelativePath::parse(&text[..at])
                .map(|ancestor| self.entries.contains_key(&ancestor))
                .unwrap_or(false)
        });
        if beneath {
            return Err(EntryProblem::BeneathEntry);
        }
        if self.implies_directory(text) {
            return Err(EntryProblem::HasEntriesBeneath);
        }
        self.entries.insert(path, (kind, data));
        Ok(())
    }

    /// Whether some entry lies beneath `dir`, which makes it a directory.
    pub(crate) fn implies_directory(&self, dir: &str) -> bool {
        // Paths beneath `dir` all start with `dir/`, so they sort together,
        // and `dir/\u{1}` is the least valid one: NUL is the only smaller
        // byte, and no path holds it. It always parses; were it refused,
        // the answer is yes, which fails closed for every caller.
        let Ok(least_child) = RelativePath::parse(&format!("{dir}/\u{1}")) else {
            return true;
        };
        let prefix = format!("{dir}/");
        self.entries
            .range(least_child..)
            .next()
            .is_some_and(|(next, _)| next.as_str().starts_with(&prefix))
    }

    /// The files, symlinks and directories the workspace makes on disk:
    /// every entry and every distinct directory an entry implies. Linear in
    /// the path bytes.
    pub fn nodes(&self) -> usize {
        let mut previous = None;
        let mut nodes = 0usize;
        for path in self.entries.keys() {
            let text = path.as_str();
            nodes = nodes.saturating_add(1 + new_directories(previous, text));
            previous = Some(text);
        }
        nodes
    }

    /// Removes the entry at `path` and returns it.
    pub fn remove(&mut self, path: &RelativePath) -> Option<(Kind, Vec<u8>)> {
        self.entries.remove(path)
    }

    /// The workspace without repository metadata
    /// ([`RelativePath::is_repository_metadata`], ADR-010 D1).
    pub fn without_metadata(mut self) -> Workspace {
        self.entries
            .retain(|path, _| !path.is_repository_metadata());
        self
    }

    /// The canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for (path, (kind, data)) in &self.entries {
            out.push(kind.byte());
            put_field(&mut out, path.as_str().as_bytes());
            put_field(&mut out, data);
        }
        out
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
    pub fn decode(bytes: &[u8], max_nodes: usize) -> Result<Workspace, DecodeError> {
        let too_many = DecodeError::TooManyNodes { max: max_nodes };
        let rest = bytes.strip_prefix(MAGIC).ok_or(DecodeError::Magic)?;
        let mut reader = Reader { rest, entry: 0 };
        let mut entries = Vec::new();
        let mut prefixes: Vec<&str> = Vec::new();
        let mut nodes = 0usize;
        while !reader.rest.is_empty() {
            let entry = reader.entry;
            // Every entry adds at least itself.
            if nodes >= max_nodes {
                return Err(too_many);
            }
            let byte = reader.bytes("kind", 1)?[0];
            let kind = Kind::from_byte(byte).ok_or(DecodeError::UnknownKind { entry, byte })?;
            let raw = reader.field("path")?;
            let text = std::str::from_utf8(raw).map_err(|_| DecodeError::PathNotUtf8 { entry })?;
            let path = RelativePath::parse(text)
                .map_err(|problem| DecodeError::Path { entry, problem })?;
            if let Some(previous) = prefixes.last() {
                // The top of the stack is always the previous path.
                match text.cmp(*previous) {
                    Ordering::Equal => return Err(DecodeError::Duplicate { entry }),
                    Ordering::Less => return Err(DecodeError::Unsorted { entry }),
                    Ordering::Greater => {}
                }
            }
            nodes = nodes.saturating_add(1 + new_directories(prefixes.last().copied(), text));
            if nodes > max_nodes {
                return Err(too_many);
            }
            while prefixes.last().is_some_and(|top| !text.starts_with(top)) {
                prefixes.pop();
            }
            // Each element is a shorter string prefix of `text`.
            if prefixes.iter().any(|p| text.as_bytes()[p.len()] == b'/') {
                return Err(DecodeError::Entry {
                    entry,
                    problem: EntryProblem::BeneathEntry,
                });
            }
            prefixes.push(text);
            let data = reader.field("data")?;
            if let Some(problem) = target_problem(kind, data) {
                return Err(DecodeError::Entry { entry, problem });
            }
            entries.push((path, (kind, data.to_vec())));
            reader.entry += 1;
        }
        // Already sorted, so the map is built in one pass, without a
        // search per entry.
        Ok(Workspace {
            entries: entries.into_iter().collect(),
        })
    }
}

/// The directories `path` implies that the previous path in sorted order
/// did not. A directory `d` both imply sits inside their common prefix:
/// everything between two paths that start with `d/` starts with it too,
/// so no earlier path implies a directory the previous one does not. The
/// new ones are therefore the `/` positions of `path` at or past the
/// common prefix. Linear in `path`.
pub(crate) fn new_directories(previous: Option<&str>, path: &str) -> usize {
    let shared = previous.map_or(0, |p| common_prefix(p, path));
    path.as_bytes()[shared..]
        .iter()
        .filter(|b| **b == b'/')
        .count()
}

/// The length in bytes of the common prefix of `a` and `b`.
pub(crate) fn common_prefix(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
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
    fn bytes(&mut self, field: &'static str, n: u64) -> Result<&'a [u8], DecodeError> {
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

    fn field(&mut self, field: &'static str) -> Result<&'a [u8], DecodeError> {
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

    fn path(text: &str) -> RelativePath {
        RelativePath::parse(text).expect("a valid path")
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
        let order: Vec<&str> = forward.iter().map(|(p, _, _)| p.as_str()).collect();
        assert_eq!(order, ["Z", "a.txt", "a/b", "a/c", "b"]);
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
                "non-UTF-8 path",
                raw(&[(f, &[b'a', 0xff], b"")]),
                DecodeError::PathNotUtf8 { entry: 0 },
            ),
            (
                "absolute",
                raw(&[(f, b"/abs", b"")]),
                path_problem(CitationProblem::AbsolutePath),
            ),
            (
                "parent",
                raw(&[(f, b"../x", b"")]),
                path_problem(CitationProblem::ParentComponent),
            ),
            (
                "empty component",
                raw(&[(f, b"a//b", b"")]),
                path_problem(CitationProblem::EmptyComponent),
            ),
            (
                "backslash",
                raw(&[(f, b"a\\b", b"")]),
                path_problem(CitationProblem::Backslash),
            ),
            (
                "NUL",
                raw(&[(f, b"a\0b", b"")]),
                path_problem(CitationProblem::Nul),
            ),
            (
                "zero-width space alone",
                raw(&[(f, "\u{200B}".as_bytes(), b"")]),
                path_problem(CitationProblem::BlankPath),
            ),
            (
                "empty path",
                raw(&[(f, b"", b"")]),
                path_problem(CitationProblem::BlankPath),
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
            let text = p.as_str();
            for (i, _) in text.match_indices('/') {
                directories.insert(&text[..i]);
            }
        }
        assert_eq!(w.nodes(), w.len() + directories.len());
        assert_eq!(w.nodes(), 9 + 8);
        assert_eq!(Workspace::new().nodes(), 0);
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
