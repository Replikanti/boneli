//! The patch policy: the rules a fix diff must pass before it is verified
//! (`docs/ARCHITECTURE.md`, "Debugging line", "Patch policy"; ADR-013).
//!
//! [`patch_policy`] is a pure function over a [`Patch`], the changed paths
//! with their full before and after entries and the base tree's symlinks.
//! The domain computes everything itself: the line edit distance, the path
//! classes, the symlink walks and the JS/TS markers, so the verdict never
//! rests on a number an adapter computed, and the replay gate covers it
//! (`patch_corpus`). It is deterministic and fails closed: what the policy
//! cannot judge (a gitlink, a binary, a link through a link) is refused.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use crate::gate::{CitationProblem, path_problem};
use crate::line_diff::{Cost, Over, cost, line_count};
use crate::patch_js::{
    Marker, after_declarations, base_declarations, base_marker_counts, has_test_key, marker_counts,
};
use crate::patch_path::{
    ForbiddenClass, alias_key, forbidden_class, is_js_ts, is_test_config, is_test_file,
    is_test_path,
};

/// What a git tree entry is: git's modes 100644, 100755, 120000 and 160000
/// (ADR-013, D1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// An executable regular file.
    Executable,
    /// A symlink; the data is its target.
    Symlink,
    /// A submodule commit; the data is the commit id in hex.
    Gitlink,
}

/// One side of a changed path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The kind.
    pub kind: EntryKind,
    /// The content, the link target or the gitlink's commit id.
    pub data: Vec<u8>,
}

/// One changed path: `None` on a side where the path is absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// Repository-relative path (the citation path rule, ADR-002 D2).
    pub path: String,
    /// The entry in the base tree.
    pub before: Option<Entry>,
    /// The entry after the fix.
    pub after: Option<Entry>,
}

/// A symlink of the base tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseLink {
    /// Repository-relative path.
    pub path: String,
    /// The target.
    pub target: Vec<u8>,
}

/// A fix diff as the policy sees it: the changes in strictly ascending byte
/// order of their paths, and every symlink of the base tree in the same
/// order (ADR-013, D1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    /// The changed paths.
    pub changes: Vec<Change>,
    /// The base tree's symlinks.
    pub base_links: Vec<BaseLink>,
}

/// Why two trees have no [`Patch`] the policy can read: a path the patch
/// would carry is not UTF-8, so it has no text form (ADR-018, D5;
/// ADR-023, D6). The first such path is reported, changes before base
/// links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnreadablePath {
    /// A changed path is not UTF-8.
    Change {
        /// The index the change would have in [`Patch::changes`].
        index: usize,
    },
    /// The path of a symlink of the base is not UTF-8.
    BaseLink {
        /// The index the link would have in [`Patch::base_links`].
        index: usize,
    },
}

/// The size limits, inclusive (ADR-013, D3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatchLimits {
    /// At most this many changed paths.
    pub max_changed_files: NonZeroU32,
    /// At most this many inserted plus deleted lines.
    pub max_changed_lines: NonZeroU32,
    /// At most this many bytes in those lines.
    pub max_changed_bytes: NonZeroU32,
}

impl PatchLimits {
    /// 25 files, 1,000 lines and 42,000 bytes: the 97th percentile of
    /// human bug fixes in the first stack's repositories, rounded up
    /// (ADR-013, D3 and D8).
    pub const DEFAULT: PatchLimits = PatchLimits {
        max_changed_files: NonZeroU32::MIN.saturating_add(24),
        max_changed_lines: NonZeroU32::MIN.saturating_add(999),
        max_changed_bytes: NonZeroU32::MIN.saturating_add(41_999),
    };
}

/// Why a change or a base link is malformed (ADR-013, D2 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeProblem {
    /// The path is not strictly greater than the previous one in byte
    /// order (a duplicate included).
    OutOfOrder,
    /// The path breaks the citation path rule.
    Path(CitationProblem),
    /// The before and after sides are equal.
    NoChange,
    /// A symlink side has an empty target.
    EmptyLinkTarget,
    /// A symlink side has NUL in its target.
    NulInLinkTarget,
    /// The before side and the base links disagree: a `before` symlink
    /// without an equal base link, or a base link whose change's `before`
    /// is not that symlink.
    BaseLinkMismatch,
}

/// Why a file's after side is not text (ADR-013, D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NotText {
    /// NUL anywhere in the content.
    Nul,
    /// Not valid UTF-8.
    NotUtf8,
    /// An explicit bidi formatting character (Trojan Source).
    BidiControl,
}

/// Why a symlink, or an entry beneath one, is refused (ADR-013, D6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkProblem {
    /// The target is not UTF-8.
    NotUtf8,
    /// The target is longer than 4,095 bytes.
    TooLong,
    /// The target starts with `/`.
    Absolute,
    /// The target holds `\` or `:`, or a component of dots and spaces that
    /// Windows trims to `.` or `..`.
    WindowsForm,
    /// The walk pops past the repository root.
    Escapes,
    /// The walk, or the entry's own path, passes through a symlink of the
    /// tree after the fix.
    ThroughLink,
    /// The target resolves into a forbidden path.
    Into(ForbiddenClass),
    /// The target resolves to the root, which holds `.git`, or to a
    /// directory above a forbidden path the patch or its links name.
    Encloses(ForbiddenClass),
}

/// Why a change disables tests (ADR-013, D7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TestDisabling {
    /// More occurrences of the marker after the change than before.
    Marker(Marker),
    /// A test file is deleted or stops being a regular file.
    DeletedTestFile,
    /// A test file has fewer active test declarations.
    TestsRemoved,
    /// A test runner's configuration changes.
    TestConfigChanged,
}

/// One reason the policy refuses a patch. Indices count changes or base
/// links from 0; a violation never carries content (ADR-013, D1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatchViolation {
    /// More changed paths than the limit; nothing else is judged.
    TooManyFiles {
        /// The number of changes.
        files: usize,
        /// The limit.
        limit: u32,
    },
    /// No changes: an empty fix is not a fix.
    Empty,
    /// A change is malformed; the patch is not judged further.
    Malformed {
        /// The change.
        index: usize,
        /// What is wrong with it.
        problem: ChangeProblem,
    },
    /// A base link is malformed; the patch is not judged further.
    BaseLinkMalformed {
        /// The base link.
        index: usize,
        /// What is wrong with it.
        problem: ChangeProblem,
    },
    /// More changed lines than the limit.
    TooManyLines {
        /// The limit.
        limit: u32,
    },
    /// More bytes in the changed lines than the limit.
    TooManyBytes {
        /// The limit.
        limit: u32,
    },
    /// The change touches a forbidden path, or a path a link at a
    /// forbidden path reaches.
    Forbidden {
        /// The change.
        index: usize,
        /// The first matching class.
        class: ForbiddenClass,
    },
    /// The change has a gitlink side, whose content the policy cannot see.
    Gitlink {
        /// The change.
        index: usize,
    },
    /// The after side is a file that is not text.
    NotText {
        /// The change.
        index: usize,
        /// The first reason.
        reason: NotText,
    },
    /// The after side is a symlink that is refused, or lies beneath one.
    Link {
        /// The change.
        index: usize,
        /// The first problem.
        problem: LinkProblem,
    },
    /// The change disables tests.
    DisablesTests {
        /// The change.
        index: usize,
        /// How.
        reason: TestDisabling,
    },
}

/// The policy's decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatchVerdict {
    /// The patch passes, with its size.
    Pass {
        /// Changed paths.
        files: u32,
        /// Inserted plus deleted lines.
        lines: u32,
    },
    /// The patch is refused, every violation in order (ADR-013, D2).
    Reject(Vec<PatchViolation>),
}

/// Judges a patch (ADR-013, D2).
///
/// 1. More changes than the file limit: `TooManyFiles`, nothing else runs.
///    This bounds every later step by the file limit.
/// 2. No changes: `Empty`.
/// 3. Validation of the changes, then of the base links; every problem is
///    reported and nothing else runs, so an inconsistent patch is never
///    judged.
/// 4. Size: `TooManyLines` or `TooManyBytes`, whichever budget the count
///    crosses first, first in the list.
/// 5. Per change, in index order, each family once: `Forbidden`,
///    `Gitlink`, `NotText`, `Link`, then `DisablesTests` for each marker
///    in [`Marker`] order, `DeletedTestFile`, `TestsRemoved` and
///    `TestConfigChanged`.
/// 6. No violation: `Pass`.
///
/// No input panics: arithmetic is checked or saturating, and indexing goes
/// through `get`.
pub fn patch_policy(patch: &Patch, limits: &PatchLimits) -> PatchVerdict {
    let files = patch.changes.len();
    let file_limit = limits.max_changed_files.get();
    let within = u32::try_from(files)
        .ok()
        .filter(|count| *count <= file_limit);
    let Some(file_count) = within else {
        return PatchVerdict::Reject(vec![PatchViolation::TooManyFiles {
            files,
            limit: file_limit,
        }]);
    };
    if patch.changes.is_empty() {
        return PatchVerdict::Reject(vec![PatchViolation::Empty]);
    }
    let malformed = validate(patch);
    if !malformed.is_empty() {
        return PatchVerdict::Reject(malformed);
    }
    let mut violations = Vec::new();
    let line_limit = limits.max_changed_lines.get();
    let byte_limit = limits.max_changed_bytes.get();
    let lines = match changed_size(&patch.changes, line_limit, byte_limit) {
        Ok(lines) => Some(lines),
        Err(Over::Lines) => {
            violations.push(PatchViolation::TooManyLines { limit: line_limit });
            None
        }
        Err(Over::Bytes) => {
            violations.push(PatchViolation::TooManyBytes { limit: byte_limit });
            None
        }
    };
    let context = Context::new(patch);
    for (index, change) in patch.changes.iter().enumerate() {
        judge_change(index, change, &context, &mut violations);
    }
    match lines {
        Some(lines) if violations.is_empty() => PatchVerdict::Pass {
            files: file_count,
            lines,
        },
        _ => PatchVerdict::Reject(violations),
    }
}

fn is_link(entry: Option<&Entry>) -> bool {
    entry.is_some_and(|e| e.kind == EntryKind::Symlink)
}

fn is_regular(entry: Option<&Entry>) -> bool {
    entry.is_some_and(|e| matches!(e.kind, EntryKind::File | EntryKind::Executable))
}

/// The problems of a symlink target that make a tree inconsistent
/// (ADR-010, D2): empty, or NUL in it.
fn target_problems(target: &[u8]) -> impl Iterator<Item = ChangeProblem> {
    [
        target.is_empty().then_some(ChangeProblem::EmptyLinkTarget),
        target
            .contains(&0)
            .then_some(ChangeProblem::NulInLinkTarget),
    ]
    .into_iter()
    .flatten()
}

/// The problems of one path in a sorted list: out of order, then the path
/// rule.
fn path_problems(path: &str, previous: Option<&str>) -> impl Iterator<Item = ChangeProblem> {
    [
        previous
            .is_some_and(|p| path <= p)
            .then_some(ChangeProblem::OutOfOrder),
        path_problem(path).map(ChangeProblem::Path),
    ]
    .into_iter()
    .flatten()
}

/// Step 3 of [`patch_policy`]: every problem of the changes, then of the
/// base links.
fn validate(patch: &Patch) -> Vec<PatchViolation> {
    let mut base_problems = Vec::new();
    let mut previous: Option<&str> = None;
    for (index, link) in patch.base_links.iter().enumerate() {
        let problems = path_problems(&link.path, previous).chain(target_problems(&link.target));
        base_problems
            .extend(problems.map(|problem| PatchViolation::BaseLinkMalformed { index, problem }));
        previous = Some(&link.path);
    }
    // Matching a change against the base links needs them sorted and
    // well formed; when they are not, they are refused anyway.
    let base_ok = base_problems.is_empty();
    let mut out = Vec::new();
    let mut previous: Option<&str> = None;
    for (index, change) in patch.changes.iter().enumerate() {
        let mut problems: Vec<ChangeProblem> = path_problems(&change.path, previous).collect();
        previous = Some(&change.path);
        if change.before == change.after {
            problems.push(ChangeProblem::NoChange);
        }
        for side in [&change.before, &change.after].into_iter().flatten() {
            if side.kind == EntryKind::Symlink {
                for problem in target_problems(&side.data) {
                    if !problems.contains(&problem) {
                        problems.push(problem);
                    }
                }
            }
        }
        if base_ok && base_link_mismatch(patch, change) {
            problems.push(ChangeProblem::BaseLinkMismatch);
        }
        out.extend(
            problems
                .into_iter()
                .map(|problem| PatchViolation::Malformed { index, problem }),
        );
    }
    out.extend(base_problems);
    out
}

/// Whether a change's before side disagrees with the base links: a
/// `before` symlink without an equal base link, or a base link at the
/// path whose change's `before` is not that symlink.
fn base_link_mismatch(patch: &Patch, change: &Change) -> bool {
    let base = patch
        .base_links
        .binary_search_by(|link| link.path.as_str().cmp(change.path.as_str()))
        .ok()
        .and_then(|at| patch.base_links.get(at));
    match (&change.before, base) {
        (Some(before), Some(link)) => {
            before.kind != EntryKind::Symlink || before.data != link.target
        }
        (Some(before), None) => before.kind == EntryKind::Symlink,
        (None, Some(_)) => true,
        (None, None) => false,
    }
}

/// What a side contributes to the size.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Category {
    Absent,
    Regular,
    Link,
    Gitlink,
}

/// The text of a regular file: valid UTF-8 without NUL.
fn text(entry: Option<&Entry>) -> Option<&str> {
    let entry = entry.filter(|e| is_regular(Some(e)))?;
    if entry.data.contains(&0) {
        return None;
    }
    core::str::from_utf8(&entry.data).ok()
}

/// What a side contributes (ADR-013, D3): a text file's content, a
/// symlink's target or a gitlink's id (one line), nothing for a binary or
/// an absent side.
fn side(entry: Option<&Entry>) -> (&[u8], Category) {
    match entry {
        None => (&[], Category::Absent),
        Some(e) => match e.kind {
            EntryKind::File | EntryKind::Executable => (
                text(Some(e)).map_or(&[][..], str::as_bytes),
                Category::Regular,
            ),
            EntryKind::Symlink => (e.data.as_slice(), Category::Link),
            EntryKind::Gitlink => (e.data.as_slice(), Category::Gitlink),
        },
    }
}

/// A change's lines and bytes, or the budget it crosses. A type change (a
/// file to a symlink, say) shares no lines, as git shows it as a deletion
/// and an addition.
fn change_cost(change: &Change, max_lines: usize, max_bytes: usize) -> Result<Cost, Over> {
    let (before, from) = side(change.before.as_ref());
    let (after, to) = side(change.after.as_ref());
    if from == to || from == Category::Absent || to == Category::Absent {
        return cost(before, after, max_lines, max_bytes);
    }
    let lines = line_count(before).saturating_add(line_count(after));
    let bytes = before.len().saturating_add(after.len());
    if lines > max_lines {
        Err(Over::Lines)
    } else if bytes > max_bytes {
        Err(Over::Bytes)
    } else {
        Ok(Cost { lines, bytes })
    }
}

/// Step 4 of [`patch_policy`]: the total lines, or the budget the count
/// crosses first. Each change's search is cut off at what is left.
fn changed_size(changes: &[Change], line_limit: u32, byte_limit: u32) -> Result<u32, Over> {
    let max_lines = usize::try_from(line_limit).unwrap_or(usize::MAX);
    let max_bytes = usize::try_from(byte_limit).unwrap_or(usize::MAX);
    let (mut lines, mut bytes) = (0usize, 0usize);
    for change in changes {
        let left_lines = max_lines.checked_sub(lines).ok_or(Over::Lines)?;
        let left_bytes = max_bytes.checked_sub(bytes).ok_or(Over::Bytes)?;
        let cost = change_cost(change, left_lines, left_bytes)?;
        lines = lines.saturating_add(cost.lines);
        bytes = bytes.saturating_add(cost.bytes);
    }
    u32::try_from(lines).map_err(|_| Over::Lines)
}

/// The explicit bidi formatting characters (Trojan Source, CVE-2021-42574).
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Why a file's content is not text (ADR-013, D5): NUL anywhere, not
/// UTF-8, or a bidi control. The whole content is read: git's own check
/// reads only the first 8,000 bytes.
fn not_text(data: &[u8]) -> Option<NotText> {
    if data.contains(&0) {
        return Some(NotText::Nul);
    }
    match core::str::from_utf8(data) {
        Err(_) => Some(NotText::NotUtf8),
        Ok(text) => text
            .chars()
            .any(is_bidi_control)
            .then_some(NotText::BidiControl),
    }
}

/// The longest symlink target Linux stores: 4,096 bytes fail with
/// ENAMETOOLONG (ADR-013, D6).
const MAX_TARGET: usize = 4095;

/// The most links one resolution follows, as Linux's ELOOP limit (40).
const MAX_HOPS: usize = 40;

/// The most walk states one protected link's resolution visits before the
/// policy gives up and protects every path (ADR-013, D6).
const MAX_STATES: usize = 256;

/// The alias keys of a path's components ([`alias_key`]).
fn keys(path: &str) -> Vec<String> {
    path.split('/').map(alias_key).collect()
}

/// Whether one key path is a component prefix of the other, or equal.
fn overlaps(a: &[String], b: &[String]) -> bool {
    a.iter().zip(b).all(|(x, y)| x == y)
}

/// The symlinks of the tree after the fix, by alias key: the base links
/// the patch does not change plus the after-side links. A flat trie, so a
/// deep path costs no recursion: node 0 is the root, `children` maps a
/// node and an alias key to the child node, and `targets` holds the
/// targets of the links at a node (several when names alias).
struct LinkTree<'a> {
    children: BTreeMap<(usize, String), usize>,
    targets: Vec<Vec<&'a [u8]>>,
    /// Every link, path and target.
    links: Vec<(&'a str, &'a [u8])>,
}

const ROOT: usize = 0;

impl<'a> LinkTree<'a> {
    fn after(patch: &'a Patch) -> LinkTree<'a> {
        let mut tree = LinkTree {
            children: BTreeMap::new(),
            targets: vec![Vec::new()],
            links: Vec::new(),
        };
        let changed = |path: &str| {
            patch
                .changes
                .binary_search_by(|c| c.path.as_str().cmp(path))
                .is_ok()
        };
        for link in &patch.base_links {
            if !changed(&link.path) {
                tree.insert(&link.path, &link.target);
            }
        }
        for change in &patch.changes {
            if let Some(after) = change.after.as_ref().filter(|e| is_link(Some(e))) {
                tree.insert(&change.path, &after.data);
            }
        }
        tree
    }

    fn insert(&mut self, path: &'a str, target: &'a [u8]) {
        let mut node = ROOT;
        for component in path.split('/') {
            let next = self.targets.len();
            let child = *self
                .children
                .entry((node, alias_key(component)))
                .or_insert(next);
            if child == next {
                self.targets.push(Vec::new());
            }
            node = child;
        }
        if let Some(targets) = self.targets.get_mut(node) {
            targets.push(target);
        }
        self.links.push((path, target));
    }

    /// The child of `node` at `component`; `None` off the trie, where no
    /// link can be.
    fn child(&self, node: Option<usize>, component: &str) -> Option<usize> {
        self.children.get(&(node?, alias_key(component))).copied()
    }

    /// The targets of the links at `node`; empty where there is none.
    fn targets(&self, node: Option<usize>) -> &[&'a [u8]] {
        node.and_then(|n| self.targets.get(n))
            .map_or(&[], Vec::as_slice)
    }
}

/// What a link at a protected path protects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Guard {
    Class(ForbiddenClass),
    TestConfig,
    /// A link at a test file or in a test directory: what it reaches is a
    /// test file (D7).
    TestFile,
}

/// The readings of a link target, each as its components in order: split
/// at `/`, and when it holds a `\`, also split at both, as a Windows
/// checkout reads it. A reading that is absolute (`/x`, `\\server`) is
/// dropped: nothing in the patch can be there.
fn readings(target: &str) -> Vec<Vec<&str>> {
    let mut out = Vec::new();
    if !target.starts_with('/') {
        out.push(target.split('/').collect());
    }
    if target.contains('\\') && !target.starts_with(['/', '\\']) {
        out.push(target.split(['/', '\\']).collect());
    }
    out
}

/// The work budget of all protected-link resolutions of one patch
/// together, in bytes walked: each component costs its length plus one.
/// It is 256 walks ([`MAX_STATES`]) of one longest target (4,095 bytes,
/// [`MAX_TARGET`]) each, rounded to 2^20. It bounds the time, the places
/// the arena holds and the key bytes they store; past it, every path is
/// protected (ADR-013, D6).
const MAX_STEPS: usize = 1 << 20;

/// One directory a resolution reached, in an arena shared by every
/// resolution of a patch: its parent, its trie node in the link tree, and
/// the guards of the protected paths at it and beneath it.
struct Place {
    parent: usize,
    node: Option<usize>,
    at: u8,
    beneath: u8,
}

/// The guard bits of a [`Guard`]: one per forbidden class, then test
/// configuration, then test file.
fn guard_bit(guard: Guard) -> u8 {
    match guard {
        Guard::Class(class) => 1 << (class as u8),
        Guard::TestConfig => 1 << 6,
        Guard::TestFile => 1 << 7,
    }
}

fn guards_of(bits: u8) -> impl Iterator<Item = Guard> {
    const CLASSES: [ForbiddenClass; 6] = [
        ForbiddenClass::RepositoryMetadata,
        ForbiddenClass::Ci,
        ForbiddenClass::ContainerBuild,
        ForbiddenClass::CodeOwners,
        ForbiddenClass::GitConfig,
        ForbiddenClass::Dependencies,
    ];
    let mut all: Vec<Guard> = CLASSES.into_iter().map(Guard::Class).collect();
    all.push(Guard::TestConfig);
    all.push(Guard::TestFile);
    all.into_iter().filter(move |g| bits & guard_bit(*g) != 0)
}

/// One resolution in progress: its place, its stack of (parts index, next
/// component), innermost last, and the links it followed.
type State = (usize, Vec<(usize, usize)>, usize);

/// The paths every protected link reaches, as places in an arena (the
/// root is place 0), so a branch copies a place index instead of a path,
/// and a path is stored once however often it is reached.
struct Reached<'a> {
    places: Vec<Place>,
    children: BTreeMap<(usize, String), usize>,
    /// Target components, one entry per (link node, target, reading)
    /// followed, shared by every branch.
    parts: Vec<Vec<&'a str>>,
    followed: BTreeMap<(usize, usize, usize), usize>,
    /// Work left for the whole patch, in bytes walked ([`MAX_STEPS`]).
    steps: usize,
}

const PLACE_ROOT: usize = 0;

impl<'a> Reached<'a> {
    fn new() -> Reached<'a> {
        Reached {
            places: vec![Place {
                parent: PLACE_ROOT,
                node: Some(ROOT),
                at: 0,
                beneath: 0,
            }],
            children: BTreeMap::new(),
            parts: Vec::new(),
            followed: BTreeMap::new(),
            steps: MAX_STEPS,
        }
    }

    /// The child place of `place` at `component`, made on first use.
    fn child(&mut self, tree: &LinkTree<'a>, place: usize, component: &str) -> usize {
        let key = (place, alias_key(component));
        if let Some(&child) = self.children.get(&key) {
            return child;
        }
        let node = self
            .places
            .get(place)
            .and_then(|p| tree.child(p.node, component));
        let child = self.places.len();
        self.places.push(Place {
            parent: place,
            node,
            at: 0,
            beneath: 0,
        });
        self.children.insert(key, child);
        child
    }

    fn parent(&self, place: usize) -> usize {
        self.places.get(place).map_or(PLACE_ROOT, |p| p.parent)
    }

    /// Marks `place` protected by `bits` and every ancestor as having a
    /// protected path beneath it.
    fn mark(&mut self, place: usize, bits: u8) {
        if let Some(p) = self.places.get_mut(place) {
            p.at |= bits;
        }
        let mut current = place;
        while current != PLACE_ROOT {
            current = self.parent(current);
            match self.places.get_mut(current) {
                Some(p) if p.beneath & bits != bits => p.beneath |= bits,
                _ => break,
            }
        }
    }

    /// The parts index of one reading of one target of the links at a
    /// trie node, stored once.
    fn parts_of(&mut self, key: (usize, usize, usize), reading: Vec<&'a str>) -> usize {
        if let Some(&index) = self.followed.get(&key) {
            return index;
        }
        let index = self.parts.len();
        self.parts.push(reading);
        self.followed.insert(key, index);
        index
    }

    /// Marks every place a reader of the link at `path` with `target` may
    /// land on or pass. At a component that aliases a link, both readings
    /// continue: the link is followed (every target of every aliasing
    /// link, in every reading of [`readings`]) up to [`MAX_HOPS`], and the
    /// name is also walked as the real directory a case-sensitive checkout
    /// may hold. `false` when a resolution needs more than [`MAX_STATES`]
    /// states, meets a target over [`MAX_TARGET`] bytes or that is not
    /// UTF-8, or the patch runs out of [`MAX_STEPS`]; the caller then
    /// protects every path. Outward and absolute targets end a branch:
    /// nothing in the patch can be there.
    fn resolve(&mut self, tree: &LinkTree<'a>, path: &'a str, target: &'a [u8], bits: u8) -> bool {
        if target.len() > MAX_TARGET {
            return false;
        }
        let Ok(target) = core::str::from_utf8(target) else {
            return false;
        };
        let mut start = PLACE_ROOT;
        let mut parents: Vec<&str> = path.split('/').collect();
        parents.pop();
        for component in parents {
            if !self.charge(component) {
                return false;
            }
            start = self.child(tree, start, component);
        }
        // A branch copies at most MAX_HOPS + 1 frames.
        // States are counted when they are made, so at most MAX_STATES
        // wait at any time.
        let mut work: Vec<State> = Vec::new();
        for reading in readings(target) {
            let index = self.parts.len();
            self.parts.push(reading);
            work.push((start, vec![(index, 0)], 0));
        }
        let mut states = work.len();
        while let Some((mut place, mut frames, hops)) = work.pop() {
            let mut outward = false;
            while let Some(&(index, next)) = frames.last() {
                let Some(component) = self.parts.get(index).and_then(|p| p.get(next)).copied()
                else {
                    frames.pop();
                    continue;
                };
                if let Some(top) = frames.last_mut() {
                    top.1 += 1;
                }
                if !self.charge(component) {
                    return false;
                }
                match component {
                    "" | "." => continue,
                    ".." => {
                        if place == PLACE_ROOT {
                            outward = true;
                            break;
                        }
                        place = self.parent(place);
                        continue;
                    }
                    _ => {}
                }
                place = self.child(tree, place, component);
                let node = self.places.get(place).and_then(|p| p.node);
                let targets = tree.targets(node);
                if targets.is_empty() {
                    continue;
                }
                self.mark(place, bits);
                if hops >= MAX_HOPS {
                    continue;
                }
                for (t, next_target) in targets.iter().enumerate() {
                    if next_target.len() > MAX_TARGET {
                        return false;
                    }
                    let Ok(text) = core::str::from_utf8(next_target) else {
                        return false;
                    };
                    for (r, reading) in readings(text).into_iter().enumerate() {
                        states += 1;
                        if states > MAX_STATES {
                            return false;
                        }
                        let key = (node.unwrap_or(ROOT), t, r);
                        let index = self.parts_of(key, reading);
                        let mut branch = frames.clone();
                        branch.push((index, 0));
                        work.push((self.parent(place), branch, hops + 1));
                    }
                }
                // The directory reading goes on in this state.
            }
            if !outward {
                self.mark(place, bits);
            }
        }
        true
    }

    /// Takes one component's cost from the budget: its length plus one.
    fn charge(&mut self, component: &str) -> bool {
        match self.steps.checked_sub(component.len() + 1) {
            Some(left) => {
                self.steps = left;
                true
            }
            None => false,
        }
    }

    /// The guard bits that protect a change at `path`: a protected place
    /// at or above it, or beneath it.
    fn bits_for(&self, path: &str) -> u8 {
        let mut place = PLACE_ROOT;
        let mut bits = 0u8;
        for component in path.split('/') {
            match self.children.get(&(place, alias_key(component))) {
                Some(&child) => place = child,
                None => return bits,
            }
            bits |= self.places.get(place).map_or(0, |p| p.at);
        }
        bits | self.places.get(place).map_or(0, |p| p.beneath)
    }
}

/// What the whole patch tells about paths, built once: the link tree, the
/// paths links at protected paths reach, and the forbidden paths it names.
struct Context<'a> {
    tree: LinkTree<'a>,
    /// Paths reached from a link at a protected path.
    reached: Reached<'a>,
    /// Guards whose resolution gave up: they protect every path.
    everywhere: u8,
    /// Forbidden paths the changes and links name, with their class.
    forbidden: Vec<(Vec<String>, ForbiddenClass)>,
}

impl<'a> Context<'a> {
    fn new(patch: &'a Patch) -> Context<'a> {
        let tree = LinkTree::after(patch);
        let mut reached = Reached::new();
        let mut everywhere = 0u8;
        let mut forbidden = Vec::new();
        for &(path, target) in &tree.links {
            let bits = [
                forbidden_class(path).map(Guard::Class),
                is_test_config(path, || true).then_some(Guard::TestConfig),
                is_test_path(path).then_some(Guard::TestFile),
            ]
            .into_iter()
            .flatten()
            .fold(0u8, |bits, g| bits | guard_bit(g));
            if bits != 0 && !reached.resolve(&tree, path, target, bits) {
                everywhere |= bits;
            }
        }
        for path in patch
            .changes
            .iter()
            .map(|c| c.path.as_str())
            .chain(tree.links.iter().map(|l| l.0))
        {
            if let Some(class) = forbidden_class(path) {
                forbidden.push((keys(path), class));
            }
        }
        Context {
            tree,
            reached,
            everywhere,
            forbidden,
        }
    }

    /// The guards that protect a change at `path`: a protected path at,
    /// above or beneath it, or a resolution that gave up.
    fn guards(&self, path: &str) -> impl Iterator<Item = Guard> + use<> {
        guards_of(self.reached.bits_for(path) | self.everywhere)
    }
}

/// A lexical walk over a path's components that refuses every position
/// that is a link of the tree after the fix.
struct Walk<'t, 'a> {
    tree: &'t LinkTree<'a>,
    nodes: Vec<Option<usize>>,
    components: Vec<&'t str>,
}

impl<'t, 'a> Walk<'t, 'a> {
    /// Starts at the parent directory of `path`, checking every prefix.
    fn at_parent_of(tree: &'t LinkTree<'a>, path: &'t str) -> Result<Walk<'t, 'a>, LinkProblem> {
        let mut walk = Walk {
            tree,
            nodes: Vec::new(),
            components: Vec::new(),
        };
        let mut components: Vec<&str> = path.split('/').collect();
        components.pop();
        for component in components {
            walk.push(component)?;
        }
        Ok(walk)
    }

    fn push(&mut self, component: &'t str) -> Result<(), LinkProblem> {
        let top = self.nodes.last().copied().unwrap_or(Some(ROOT));
        let node = self.tree.child(top, component);
        if !self.tree.targets(node).is_empty() {
            return Err(LinkProblem::ThroughLink);
        }
        self.nodes.push(node);
        self.components.push(component);
        Ok(())
    }

    fn pop(&mut self) -> Result<(), LinkProblem> {
        self.components.pop().ok_or(LinkProblem::Escapes)?;
        self.nodes.pop();
        Ok(())
    }
}

/// Whether a target component is one Windows trims to `.` or `..`: only
/// dots and spaces, other than `.` and `..` themselves.
fn windows_dots(component: &str) -> bool {
    !matches!(component, "" | "." | "..") && component.chars().all(|c| c == '.' || c == ' ')
}

/// The first problem of a symlink at `path` with `target` (ADR-013, D6).
fn symlink_problem(path: &str, target: &[u8], context: &Context<'_>) -> Option<LinkProblem> {
    let Ok(target) = core::str::from_utf8(target) else {
        return Some(LinkProblem::NotUtf8);
    };
    if target.len() > MAX_TARGET {
        return Some(LinkProblem::TooLong);
    }
    if target.starts_with('/') {
        return Some(LinkProblem::Absolute);
    }
    if target.contains(['\\', ':']) || target.split('/').any(windows_dots) {
        return Some(LinkProblem::WindowsForm);
    }
    let walked = Walk::at_parent_of(&context.tree, path).and_then(|mut walk| {
        for component in target.split('/') {
            match component {
                "" | "." => {}
                ".." => walk.pop()?,
                _ => walk.push(component)?,
            }
        }
        Ok(walk.components.join("/"))
    });
    let resolved = match walked {
        Err(problem) => return Some(problem),
        Ok(resolved) => resolved,
    };
    if let Some(class) = forbidden_class(&resolved) {
        return Some(LinkProblem::Into(class));
    }
    // The root holds `.git`; a directory above a forbidden path holds it.
    if resolved.is_empty() {
        return Some(LinkProblem::Encloses(ForbiddenClass::RepositoryMetadata));
    }
    let resolved = keys(&resolved);
    context
        .forbidden
        .iter()
        .filter(|(path, _)| path.len() > resolved.len() && overlaps(path, &resolved))
        .map(|(_, class)| *class)
        .min()
        .map(LinkProblem::Encloses)
}

/// The link family of one change: a symlink's own problem, or a regular
/// file beneath a link of the tree after the fix.
fn link_problem(change: &Change, context: &Context<'_>) -> Option<LinkProblem> {
    let after = change.after.as_ref()?;
    match after.kind {
        EntryKind::Symlink => symlink_problem(&change.path, &after.data, context),
        EntryKind::File | EntryKind::Executable => {
            Walk::at_parent_of(&context.tree, &change.path).err()
        }
        EntryKind::Gitlink => None,
    }
}

/// Step 5 of [`patch_policy`] for one change.
fn judge_change(
    index: usize,
    change: &Change,
    context: &Context<'_>,
    out: &mut Vec<PatchViolation>,
) {
    let before = change.before.as_ref();
    let after = change.after.as_ref();
    let guards: Vec<Guard> = context.guards(&change.path).collect();
    let guarded_class = guards
        .iter()
        .filter_map(|g| match g {
            Guard::Class(class) => Some(*class),
            Guard::TestConfig | Guard::TestFile => None,
        })
        .min();
    if let Some(class) = forbidden_class(&change.path).or(guarded_class) {
        out.push(PatchViolation::Forbidden { index, class });
    }
    let gitlink = [before, after]
        .into_iter()
        .flatten()
        .any(|e| e.kind == EntryKind::Gitlink);
    if gitlink {
        out.push(PatchViolation::Gitlink { index });
    }
    if let Some(reason) = after
        .filter(|e| is_regular(Some(e)))
        .and_then(|e| not_text(&e.data))
    {
        out.push(PatchViolation::NotText { index, reason });
    }
    if let Some(problem) = link_problem(change, context) {
        out.push(PatchViolation::Link { index, problem });
    }
    let mut disables = |reason| out.push(PatchViolation::DisablesTests { index, reason });
    let (before_text, after_text) = (text(before), text(after));
    // What a link at a test path reaches is a JS/TS test file, whatever its
    // name (D7).
    let reached_test = guards.contains(&Guard::TestFile);
    if is_js_ts(&change.path) || reached_test {
        let test_file = is_test_file(&change.path) || reached_test;
        // A lower bound of the base's markers and an upper bound of the
        // after side's: only a net increase refuses (ADR-013, D7).
        let was = before_text.map(|t| base_marker_counts(t, test_file));
        let now = after_text.map(|t| marker_counts(t, test_file));
        for marker in Marker::ALL {
            let at = |counts: Option<[u32; crate::patch_js::MARKERS]>| {
                counts
                    .and_then(|c| c.get(marker.index()).copied())
                    .unwrap_or(0)
            };
            if at(now) > at(was) {
                disables(TestDisabling::Marker(marker));
            }
        }
        if test_file {
            if !is_regular(after) {
                disables(TestDisabling::DeletedTestFile);
            } else if is_regular(before) {
                // The base's count is an upper bound and the after side's a
                // lower bound; a side that is not text cannot be counted,
                // so it counts as a removal.
                let removed = match (before_text, after_text) {
                    (Some(was), Some(now)) => after_declarations(now) < base_declarations(was),
                    _ => true,
                };
                if removed {
                    disables(TestDisabling::TestsRemoved);
                }
            }
        }
    }
    let test_key = || {
        [before_text, after_text]
            .into_iter()
            .flatten()
            .any(has_test_key)
    };
    if is_test_config(&change.path, test_key) || guards.contains(&Guard::TestConfig) {
        disables(TestDisabling::TestConfigChanged);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn entry(kind: EntryKind, data: &[u8]) -> Option<Entry> {
        Some(Entry {
            kind,
            data: data.to_vec(),
        })
    }

    fn file(text: &str) -> Option<Entry> {
        entry(EntryKind::File, text.as_bytes())
    }

    fn bytes(data: &[u8]) -> Option<Entry> {
        entry(EntryKind::File, data)
    }

    fn exe(text: &str) -> Option<Entry> {
        entry(EntryKind::Executable, text.as_bytes())
    }

    fn link(target: &str) -> Option<Entry> {
        entry(EntryKind::Symlink, target.as_bytes())
    }

    fn gitlink() -> Option<Entry> {
        entry(
            EntryKind::Gitlink,
            b"0123456789abcdef0123456789abcdef01234567",
        )
    }

    fn change(path: &str, before: Option<Entry>, after: Option<Entry>) -> Change {
        Change {
            path: String::from(path),
            before,
            after,
        }
    }

    fn add(path: &str, after: Option<Entry>) -> Change {
        change(path, None, after)
    }

    fn base_link(path: &str, target: &str) -> BaseLink {
        BaseLink {
            path: String::from(path),
            target: target.as_bytes().to_vec(),
        }
    }

    fn judge(changes: Vec<Change>) -> PatchVerdict {
        judge_with(changes, Vec::new())
    }

    fn judge_with(changes: Vec<Change>, base_links: Vec<BaseLink>) -> PatchVerdict {
        patch_policy(
            &Patch {
                changes,
                base_links,
            },
            &PatchLimits::DEFAULT,
        )
    }

    fn limits(files: u32, lines: u32) -> PatchLimits {
        PatchLimits {
            max_changed_files: NonZeroU32::new(files).expect("non-zero"),
            max_changed_lines: NonZeroU32::new(lines).expect("non-zero"),
            max_changed_bytes: PatchLimits::DEFAULT.max_changed_bytes,
        }
    }

    fn reject(violations: Vec<PatchViolation>) -> PatchVerdict {
        PatchVerdict::Reject(violations)
    }

    fn one(violation: PatchViolation) -> PatchVerdict {
        PatchVerdict::Reject(vec![violation])
    }

    fn numbered(prefix: &str, count: usize) -> String {
        (0..count).map(|k| format!("{prefix}{k}\n")).collect()
    }

    fn passes(verdict: &PatchVerdict) -> bool {
        matches!(verdict, PatchVerdict::Pass { .. })
    }

    #[test]
    fn empty_patch_is_rejected() {
        assert_eq!(judge(Vec::new()), one(PatchViolation::Empty));
        // Base links alone are no change.
        assert_eq!(
            judge_with(Vec::new(), vec![base_link("l", "a")]),
            one(PatchViolation::Empty)
        );
    }

    #[test]
    fn single_edit_passes_with_its_size() {
        assert_eq!(
            judge(vec![change("src/a.ts", file("a\n"), file("b\n"))]),
            PatchVerdict::Pass { files: 1, lines: 2 }
        );
    }

    #[test]
    fn file_limit_is_inclusive() {
        let adds = |count: usize| -> Vec<Change> {
            (0..count)
                .map(|k| add(&format!("f{k:02}"), file("x\n")))
                .collect()
        };
        assert_eq!(
            judge(adds(25)),
            PatchVerdict::Pass {
                files: 25,
                lines: 25
            }
        );
        // Nothing else is judged, not even a forbidden path or a
        // malformed change.
        let mut over = adds(25);
        over.push(add(".github/workflows/ci.yml", file("x\n")));
        over.push(add("f00", file("x\n")));
        assert_eq!(
            judge(over),
            one(PatchViolation::TooManyFiles {
                files: 27,
                limit: 25
            })
        );
        let tight = limits(1, 1000);
        let patch = |changes| Patch {
            changes,
            base_links: Vec::new(),
        };
        assert!(passes(&patch_policy(&patch(adds(1)), &tight)));
        assert_eq!(
            patch_policy(&patch(adds(2)), &tight),
            one(PatchViolation::TooManyFiles { files: 2, limit: 1 })
        );
    }

    #[test]
    fn line_limit_is_inclusive_across_files() {
        let a = |b_lines: usize| {
            vec![
                change("a.ts", file(&numbered("a", 250)), file(&numbered("b", 250))),
                add("b.ts", file(&numbered("c", b_lines))),
            ]
        };
        assert_eq!(
            judge(a(500)),
            PatchVerdict::Pass {
                files: 2,
                lines: 1000
            }
        );
        assert_eq!(
            judge(a(501)),
            one(PatchViolation::TooManyLines { limit: 1000 })
        );
        let edit = Patch {
            changes: vec![change("a", file("a"), file("b"))],
            base_links: Vec::new(),
        };
        assert_eq!(
            patch_policy(&edit, &limits(25, 1)),
            one(PatchViolation::TooManyLines { limit: 1 })
        );
        assert!(passes(&patch_policy(&edit, &limits(25, 2))));
    }

    #[test]
    fn line_counting_follows_git() {
        let size = |before: Option<Entry>, after: Option<Entry>| match judge(vec![change(
            "a.txt", before, after,
        )]) {
            PatchVerdict::Pass { lines, .. } => lines,
            other => panic!("{other:?}"),
        };
        assert_eq!(size(None, file("")), 0, "an empty added file");
        assert_eq!(size(None, file("a")), 1);
        assert_eq!(size(None, file("a\n")), 1);
        assert_eq!(size(None, file("\n")), 1);
        assert_eq!(size(None, file("a\nb")), 2);
        assert_eq!(size(file("a"), file("a\n")), 2);
        assert_eq!(size(file("a\r\nb\r\nc\r\n"), file("a\nb\nc\n")), 6);
        assert_eq!(size(file("a\nb\n"), None), 2, "a deletion");
        assert_eq!(size(None, link("b")), 1, "a symlink is one line");
        assert_eq!(
            size(file("b"), link("b")),
            2,
            "a type change shares no lines"
        );
    }

    #[test]
    fn reordered_lines_count() {
        let size = |before: &str, after: &str| match judge(vec![change(
            "a.txt",
            file(before),
            file(after),
        )]) {
            PatchVerdict::Pass { lines, .. } => lines,
            other => panic!("{other:?}"),
        };
        assert_eq!(size("a\nb\n", "b\na\n"), 2);
        let first = numbered("a", 10);
        let second = numbered("b", 10);
        assert_eq!(
            size(&format!("{first}{second}"), &format!("{second}{first}")),
            20
        );
    }

    #[test]
    fn mode_change_counts_no_lines() {
        assert_eq!(
            judge(vec![change("run.sh", file("echo\n"), exe("echo\n"))]),
            PatchVerdict::Pass { files: 1, lines: 0 }
        );
    }

    #[test]
    fn line_count_stops_past_the_limit() {
        assert_eq!(
            judge(vec![
                add("a.ts", file(&numbered("a", 600))),
                add("b.ts", file(&numbered("b", 600))),
            ]),
            one(PatchViolation::TooManyLines { limit: 1000 })
        );
    }

    #[test]
    fn unsorted_or_duplicate_paths_are_malformed() {
        let malformed = |index| {
            one(PatchViolation::Malformed {
                index,
                problem: ChangeProblem::OutOfOrder,
            })
        };
        assert_eq!(
            judge(vec![add("b", file("x\n")), add("a", file("x\n"))]),
            malformed(1)
        );
        assert_eq!(
            judge(vec![add("a", file("x\n")), add("a", file("y\n"))]),
            malformed(1)
        );
        // Byte order, not character order: "a/b" < "a0" since '/' < '0'.
        assert!(passes(&judge(vec![
            add("a/b", file("x\n")),
            add("a0", file("x\n"))
        ])));
    }

    #[test]
    fn malformed_patch_is_not_judged_further() {
        assert_eq!(
            judge(vec![
                add(".github/workflows/ci.yml", bytes(b"\0")),
                change("b", file("x\n"), file("x\n")),
            ]),
            one(PatchViolation::Malformed {
                index: 1,
                problem: ChangeProblem::NoChange,
            })
        );
        // Every problem is collected, changes first.
        assert_eq!(
            judge_with(
                vec![add("/a", file("x\n")), add("/a", link(""))],
                vec![base_link("z", ""), base_link("y", "a")]
            ),
            reject(vec![
                PatchViolation::Malformed {
                    index: 0,
                    problem: ChangeProblem::Path(CitationProblem::AbsolutePath),
                },
                PatchViolation::Malformed {
                    index: 1,
                    problem: ChangeProblem::OutOfOrder,
                },
                PatchViolation::Malformed {
                    index: 1,
                    problem: ChangeProblem::Path(CitationProblem::AbsolutePath),
                },
                PatchViolation::Malformed {
                    index: 1,
                    problem: ChangeProblem::EmptyLinkTarget,
                },
                PatchViolation::BaseLinkMalformed {
                    index: 0,
                    problem: ChangeProblem::EmptyLinkTarget,
                },
                PatchViolation::BaseLinkMalformed {
                    index: 1,
                    problem: ChangeProblem::OutOfOrder,
                },
            ])
        );
    }

    #[test]
    fn paths_follow_the_citation_rule() {
        for path in [
            "/a", "a\\b", "a\0b", "", " ", "\u{200B}", "a//b", "./a", "a/..", "a/",
        ] {
            let problem = path_problem(path).expect("the path is refused");
            assert_eq!(
                judge(vec![add(path, file("x\n"))]),
                one(PatchViolation::Malformed {
                    index: 0,
                    problem: ChangeProblem::Path(problem),
                }),
                "{path:?}"
            );
        }
        for path in ["~/x", "file:x"] {
            assert!(passes(&judge(vec![add(path, file("x\n"))])), "{path:?}");
        }
    }

    #[test]
    fn noop_change_is_malformed() {
        let noop = |index| {
            one(PatchViolation::Malformed {
                index,
                problem: ChangeProblem::NoChange,
            })
        };
        assert_eq!(judge(vec![change("a", file("x\n"), file("x\n"))]), noop(0));
        assert_eq!(judge(vec![change("a", None, None)]), noop(0));
    }

    #[test]
    fn link_target_empty_or_nul_is_malformed() {
        let malformed = |problem| one(PatchViolation::Malformed { index: 0, problem });
        assert_eq!(
            judge(vec![add("l", link(""))]),
            malformed(ChangeProblem::EmptyLinkTarget)
        );
        assert_eq!(
            judge(vec![add("l", link("a\0b"))]),
            malformed(ChangeProblem::NulInLinkTarget)
        );
        // The before side too; the base link it matches is malformed as
        // well.
        assert_eq!(
            judge_with(
                vec![change("l", link("a\0"), None)],
                vec![base_link("l", "a\0")]
            ),
            reject(vec![
                PatchViolation::Malformed {
                    index: 0,
                    problem: ChangeProblem::NulInLinkTarget,
                },
                PatchViolation::BaseLinkMalformed {
                    index: 0,
                    problem: ChangeProblem::NulInLinkTarget,
                },
            ])
        );
    }

    #[test]
    fn before_link_must_match_base_links() {
        let mismatch = one(PatchViolation::Malformed {
            index: 0,
            problem: ChangeProblem::BaseLinkMismatch,
        });
        assert_eq!(judge(vec![change("l", link("x"), None)]), mismatch);
        assert_eq!(
            judge_with(
                vec![change("l", link("x"), None)],
                vec![base_link("l", "y")]
            ),
            mismatch
        );
        assert_eq!(
            judge_with(
                vec![change("l", file("x\n"), None)],
                vec![base_link("l", "x")]
            ),
            mismatch
        );
        assert_eq!(
            judge_with(vec![add("l", file("x\n"))], vec![base_link("l", "x")]),
            mismatch
        );
        assert!(passes(&judge_with(
            vec![change("l", link("x"), file("x\n"))],
            vec![base_link("l", "x")]
        )));
    }

    #[test]
    fn base_links_are_validated() {
        let changes = || vec![add("src/a.ts", file("x\n"))];
        let malformed = |index, problem| one(PatchViolation::BaseLinkMalformed { index, problem });
        assert_eq!(
            judge_with(changes(), vec![base_link("b", "x"), base_link("a", "x")]),
            malformed(1, ChangeProblem::OutOfOrder)
        );
        assert_eq!(
            judge_with(changes(), vec![base_link("a", "x"), base_link("a", "x")]),
            malformed(1, ChangeProblem::OutOfOrder)
        );
        assert_eq!(
            judge_with(changes(), vec![base_link("/a", "x")]),
            malformed(0, ChangeProblem::Path(CitationProblem::AbsolutePath))
        );
        assert_eq!(
            judge_with(changes(), vec![base_link("a", "")]),
            malformed(0, ChangeProblem::EmptyLinkTarget)
        );
    }

    fn class_of(path: &str) -> Option<ForbiddenClass> {
        match judge(vec![add(path, file("x\n"))]) {
            PatchVerdict::Pass { .. } => None,
            PatchVerdict::Reject(violations) => match violations.as_slice() {
                [PatchViolation::Forbidden { index: 0, class }] => Some(*class),
                other => panic!("{path:?}: {other:?}"),
            },
        }
    }

    #[test]
    fn forbidden_paths_by_class() {
        use ForbiddenClass::*;
        for (path, class) in [
            (".github/workflows/ci.yml", Ci),
            (".github/CODEOWNERS", Ci),
            (".github/dependabot.yml", Ci),
            (".gitlab/ci/x.yml", Ci),
            ("sub/.gitlab-ci.yml", Ci),
            (".circleci/config.yml", Ci),
            (".buildkite/pipeline.yml", Ci),
            (".azure-pipelines/x.yml", Ci),
            (".woodpecker/x.yml", Ci),
            (".travis.yml", Ci),
            ("Jenkinsfile", Ci),
            ("Jenkinsfile.release", Ci),
            ("azure-pipelines.yaml", Ci),
            ("bitbucket-pipelines.yml", Ci),
            (".drone.yml", Ci),
            (".woodpecker.yaml", Ci),
            ("appveyor.yml", Ci),
            (".appveyor.yml", Ci),
            (".cirrus.yml", Ci),
            ("Dockerfile", ContainerBuild),
            ("docker/Dockerfile.dev", ContainerBuild),
            ("api.Dockerfile", ContainerBuild),
            ("Containerfile", ContainerBuild),
            ("x.containerfile", ContainerBuild),
            (".dockerignore", ContainerBuild),
            (".containerignore", ContainerBuild),
            ("compose.yaml", ContainerBuild),
            ("compose.yml", ContainerBuild),
            ("docker-compose.yml", ContainerBuild),
            ("docker-compose.override.yml", ContainerBuild),
            ("deploy/compose.prod.yaml", ContainerBuild),
            ("CODEOWNERS", CodeOwners),
            ("docs/CODEOWNERS", CodeOwners),
            ("src/.gitattributes", GitConfig),
            (".gitmodules", GitConfig),
            (".git/config", RepositoryMetadata),
            ("a/.git/hooks/x", RepositoryMetadata),
            ("package.json", Dependencies),
            ("apps/web/package.json", Dependencies),
            ("pnpm-lock.yaml", Dependencies),
            ("pnpm-workspace.yaml", Dependencies),
            ("yarn.lock", Dependencies),
            ("package-lock.json", Dependencies),
            ("npm-shrinkwrap.json", Dependencies),
            (".yarnrc", Dependencies),
            (".yarnrc.yml", Dependencies),
            (".npmrc", Dependencies),
            (".pnpmfile.cjs", Dependencies),
            ("bun.lock", Dependencies),
            ("bun.lockb", Dependencies),
            (".yarn/releases/yarn.cjs", Dependencies),
        ] {
            assert_eq!(class_of(path), Some(class), "{path:?}");
        }
    }

    #[test]
    fn forbidden_path_rejects_every_change_kind() {
        let path = ".github/workflows/ci.yml";
        let forbidden = one(PatchViolation::Forbidden {
            index: 0,
            class: ForbiddenClass::Ci,
        });
        assert_eq!(judge(vec![add(path, file("x\n"))]), forbidden);
        assert_eq!(
            judge(vec![change(path, file("x\n"), file("y\n"))]),
            forbidden
        );
        assert_eq!(judge(vec![change(path, file("x\n"), None)]), forbidden);
    }

    #[test]
    fn forbidden_paths_fold_lookalikes() {
        use ForbiddenClass::*;
        for (path, class) in [
            (".GitHub/x", Ci),
            (".github./x", Ci),
            (".github /x", Ci),
            (".git\u{200B}hub/x", Ci),
            (".github\u{202E}/x", Ci),
            ("DOCKERFILE", ContainerBuild),
            ("Docker\u{FEFF}file", ContainerBuild),
            ("Docker\u{FB01}le", ContainerBuild),
            ("CODEOWNER\u{17F}", CodeOwners),
            ("DOC\u{212A}ERFILE", ContainerBuild),
            (".g\u{131}thub/x", Ci),
            (".G\u{130}THUB/x", Ci),
            ("Dockerfile:x", ContainerBuild),
            ("GIT~1/config", RepositoryMetadata),
            (".git::$INDEX_ALLOCATION/x", RepositoryMetadata),
        ] {
            assert_eq!(class_of(path), Some(class), "{path:?}");
        }
    }

    #[test]
    fn near_misses_are_content() {
        for path in [
            ".githubx/a",
            "github/workflows/x.yml",
            "dockerfile-notes.md",
            ".gitattributes.orig",
            "src/ci.ts",
            ".githu\u{042C}/x",
            "\u{FF24}ockerfile",
            "git~/x",
            "git~1a/x",
            "packages.json",
            "src/compose.ts",
            "docs/docker.md",
        ] {
            assert_eq!(class_of(path), None, "{path:?}");
        }
    }

    #[test]
    fn gitlink_changes_are_rejected() {
        let gitlink_at = one(PatchViolation::Gitlink { index: 0 });
        let mut other = gitlink();
        if let Some(e) = other.as_mut() {
            e.data = b"fedcba9876543210fedcba9876543210fedcba98".to_vec();
        }
        for (before, after) in [
            (None, gitlink()),
            (gitlink(), other),
            (gitlink(), None),
            (file("x\n"), gitlink()),
            (gitlink(), file("x\n")),
        ] {
            assert_eq!(judge(vec![change("vendor/lib", before, after)]), gitlink_at);
        }
    }

    fn not_text(reason: NotText) -> PatchVerdict {
        one(PatchViolation::NotText { index: 0, reason })
    }

    #[test]
    fn nul_anywhere_is_binary() {
        let mut late = vec![b'a'; 8_000];
        late.push(0);
        late.extend_from_slice(b"tail\n");
        for data in [&b"\0abc\n"[..], &late[..], &b"abc\0"[..]] {
            assert_eq!(
                judge(vec![add("a.txt", bytes(data))]),
                not_text(NotText::Nul)
            );
            assert_eq!(
                judge(vec![add("a.sh", entry(EntryKind::Executable, data))]),
                not_text(NotText::Nul)
            );
        }
    }

    #[test]
    fn invalid_utf8_is_binary() {
        for data in [
            &b"\xFF\n"[..],
            &b"ok \xE2\x82"[..],
            &b"\xC0\x80"[..],
            &b"\xED\xA0\x80"[..],
        ] {
            assert_eq!(
                judge(vec![add("a.txt", bytes(data))]),
                not_text(NotText::NotUtf8),
                "{data:?}"
            );
        }
    }

    #[test]
    fn bidi_controls_are_rejected() {
        for c in ['\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}'] {
            assert_eq!(
                judge(vec![add("a.ts", file(&format!("const a = 1; //{c}x\n")))]),
                not_text(NotText::BidiControl),
                "{c:?}"
            );
        }
    }

    #[test]
    fn bom_and_rtl_text_are_text() {
        for text in [
            "\u{FEFF}const a = 1;\n",
            "x\u{200E}y\u{200F}\n",
            "const s = '\u{645}\u{631}\u{62D}\u{628}\u{627}';\n",
        ] {
            assert!(passes(&judge(vec![add("a.ts", file(text))])), "{text:?}");
        }
    }

    #[test]
    fn binary_rule_checks_the_after_side() {
        assert!(passes(&judge(vec![change(
            "a.png",
            bytes(b"\x89PNG\0"),
            None
        )])));
        assert!(passes(&judge(vec![change(
            "a.txt",
            bytes(b"\xFF\0"),
            file("now text\n")
        )])));
        assert_eq!(
            judge(vec![change("a.txt", file("x\n"), bytes(b"\0"))]),
            not_text(NotText::Nul)
        );
    }

    fn link_problem(index: usize, problem: LinkProblem) -> PatchVerdict {
        one(PatchViolation::Link { index, problem })
    }

    #[test]
    fn inward_links_pass() {
        for (path, target) in [
            ("docs/README.md", "../README.md"),
            ("a", "b"),
            ("x/l", "../y/z"),
            ("x/l", "./"),
            ("x/l", "..//y/./z/"),
        ] {
            assert!(
                passes(&judge(vec![add(path, link(target))])),
                "{path} -> {target}"
            );
        }
    }

    #[test]
    fn outward_links_are_rejected() {
        assert_eq!(
            judge(vec![add("l", link("/etc/passwd"))]),
            link_problem(0, LinkProblem::Absolute)
        );
        for (path, target) in [
            ("l", "../x"),
            ("a/l", "../../x"),
            ("a/l", "../a/../../x"),
            ("l", ".."),
        ] {
            assert_eq!(
                judge(vec![add(path, link(target))]),
                link_problem(0, LinkProblem::Escapes),
                "{path} -> {target}"
            );
        }
    }

    #[test]
    fn windows_and_non_utf8_link_targets() {
        for target in [
            "..\\..\\x",
            "C:/x",
            "C:x",
            "file:///etc/passwd",
            ".. /x",
            "a/.../x",
            ". .",
        ] {
            assert_eq!(
                judge(vec![add("l", link(target))]),
                link_problem(0, LinkProblem::WindowsForm),
                "{target:?}"
            );
        }
        assert_eq!(
            judge(vec![add("l", entry(EntryKind::Symlink, b"a\xFF"))]),
            link_problem(0, LinkProblem::NotUtf8)
        );
    }

    #[test]
    fn link_target_length_bound() {
        let longest = format!("{}a", "a/".repeat(2047));
        assert_eq!(longest.len(), 4095);
        assert!(passes(&judge(vec![add("l", link(&longest))])));
        let too_long = "a/".repeat(2048);
        assert_eq!(too_long.len(), 4096);
        assert_eq!(
            judge(vec![add("l", link(&too_long))]),
            link_problem(0, LinkProblem::TooLong)
        );
    }

    #[test]
    fn links_never_resolve_through_links() {
        let through = link_problem(0, LinkProblem::ThroughLink);
        let etc = || vec![base_link("b", "/etc")];
        assert_eq!(judge_with(vec![add("a", link("b/passwd"))], etc()), through);
        assert_eq!(judge_with(vec![add("a", link("b/../c"))], etc()), through);
        assert_eq!(
            judge_with(vec![add("a", link("b"))], vec![base_link("b", "c")]),
            through,
            "an inward chain"
        );
        assert_eq!(
            judge_with(vec![add("a", link("B/x"))], vec![base_link("b", "c")]),
            through,
            "a case alias"
        );
        assert_eq!(
            judge_with(
                vec![add("a", link("x/b\u{200B}/y"))],
                vec![base_link("x/B", "c")]
            ),
            through,
            "an ignorable alias"
        );
        assert_eq!(
            judge(vec![add("a", link("a"))]),
            through,
            "a link to itself"
        );
        assert_eq!(
            judge(vec![add("l", link("d")), add("l/x", link("y"))]),
            link_problem(1, LinkProblem::ThroughLink),
            "a link beneath a link the patch adds"
        );
        assert_eq!(
            judge_with(vec![add("l/x", link("y"))], vec![base_link("l", "d")]),
            through,
            "a link beneath a base link"
        );
    }

    #[test]
    fn entries_beneath_an_after_link_are_rejected() {
        // Lexically `docs/workflows/evil.yml` is content; through the base
        // link `docs -> .github` it is a workflow.
        assert_eq!(
            judge_with(
                vec![add("docs/workflows/evil.yml", file("x\n"))],
                vec![base_link("docs", ".github")]
            ),
            link_problem(0, LinkProblem::ThroughLink)
        );
        assert_eq!(
            judge_with(
                vec![add("Docs/x.ts", file("x\n"))],
                vec![base_link("docs", "src")]
            ),
            link_problem(0, LinkProblem::ThroughLink)
        );
        // Deleting the link first makes `docs` a directory again.
        assert!(passes(&judge_with(
            vec![
                change("docs", link("src"), None),
                add("docs/x.ts", file("x\n"))
            ],
            vec![base_link("docs", "src")]
        )));
    }

    #[test]
    fn every_after_link_is_checked() {
        assert_eq!(
            judge_with(
                vec![change("l", link("a"), link("/etc"))],
                vec![base_link("l", "a")]
            ),
            link_problem(0, LinkProblem::Absolute),
            "a retarget"
        );
        assert!(
            passes(&judge_with(
                vec![change("l", link("/etc"), None)],
                vec![base_link("l", "/etc")]
            )),
            "a deleted link"
        );
        assert_eq!(
            judge(vec![change("l", file("x\n"), link("../x"))]),
            link_problem(0, LinkProblem::Escapes),
            "a file turned into a link"
        );
        assert!(
            passes(&judge_with(
                vec![add("src/a.ts", file("x\n"))],
                vec![base_link("o", "/etc")]
            )),
            "an untouched outward base link"
        );
    }

    #[test]
    fn deleted_base_link_no_longer_counts() {
        assert!(passes(&judge_with(
            vec![add("a", link("b/x")), change("b", link("c"), None)],
            vec![base_link("b", "c")]
        )));
    }

    #[test]
    fn links_into_forbidden_paths_are_rejected() {
        use ForbiddenClass::*;
        for (path, target, class) in [
            ("docs/wf", "../.github/workflows", Ci),
            ("x", ".git", RepositoryMetadata),
            ("x", ".GIT/config", RepositoryMetadata),
            ("x", "Dockerfile", ContainerBuild),
            ("x", "a/../.github.", Ci),
        ] {
            assert_eq!(
                judge(vec![add(path, link(target))]),
                link_problem(0, LinkProblem::Into(class)),
                "{path} -> {target}"
            );
        }
    }

    const SUITE: &str = "describe('totals', () => {\n  it('adds', () => {\n    expect(sum(1, 2)).toBe(3)\n  })\n  it('rounds', () => {\n    expect(sum(0.1, 0.2)).toBeCloseTo(0.3)\n  })\n})\n";

    fn with_line(line: &str) -> String {
        format!("{SUITE}{line}\n")
    }

    fn disables(index: usize, reason: TestDisabling) -> PatchViolation {
        PatchViolation::DisablesTests { index, reason }
    }

    fn marker_verdict(path: &str, line: &str) -> PatchVerdict {
        judge(vec![change(path, file(SUITE), file(&with_line(line)))])
    }

    #[test]
    fn markers_added_are_rejected() {
        use Marker::*;
        for (line, marker) in [
            ("it.skip('x', f)", Skip),
            ("describe.only('x', f)", Only),
            ("test.todo('x')", Todo),
            ("test.fixme('x', f)", Fixme),
            ("it.skipIf(c)('x', f)", SkipIf),
            ("it.runIf(c)('x', f)", RunIf),
            ("it.fails('x', f)", Fails),
            ("test.failing('x', f)", Failing),
            ("test.fail('x', f)", Fail),
            ("xit('x', f)", Xit),
            ("xtest('x', f)", Xtest),
            ("xdescribe('x', f)", Xdescribe),
            ("xcontext('x', f)", Xcontext),
            ("xspecify('x', f)", Xspecify),
            ("fit('x', f)", Fit),
            ("fdescribe('x', f)", Fdescribe),
            ("fcontext('x', f)", Fcontext),
            ("it['skip']('x', f)", Skip),
            ("it[`only`]('x', f)", Only),
            ("it?.skip('x', f)", Skip),
            ("it . skip ('x', f)", Skip),
            ("it./* c */skip('x', f)", Skip),
            ("it.// c\nskip('x', f)", Skip),
            ("const d = describe.skip;", Skip),
            ("test('x', { skip: true }, f)", Skip),
            ("it.sk\\u0069p('x', f)", Skip),
            ("it.sk\\u{69}p('x', f)", Skip),
            ("it.sk\\u{000069}p('x', f)", Skip),
            ("it['sk\\x69p']('x', f)", Skip),
            ("it.\u{A0}skip('x', f)", Skip),
            ("it\u{2028}.skip('x', f)", Skip),
        ] {
            assert_eq!(
                marker_verdict("src/totals.test.ts", line),
                one(disables(0, TestDisabling::Marker(marker))),
                "{line:?}"
            );
        }
    }

    #[test]
    fn marker_forms_by_file_class() {
        let skip = one(disables(0, TestDisabling::Marker(Marker::Skip)));
        // Member, call and bracket forms count in every JS/TS file.
        for line in ["it.skip('x', f)", "it['skip']('x', f)"] {
            assert_eq!(marker_verdict("src/helpers.ts", line), skip, "{line}");
        }
        assert_eq!(
            marker_verdict("src/helpers.ts", "xit('x', f)"),
            one(disables(0, TestDisabling::Marker(Marker::Xit)))
        );
        // The key form only in test files: Prisma pagination is not a skip.
        assert!(passes(&marker_verdict(
            "src/users.ts",
            "db.user.findMany({ skip: 10, take: 5 })"
        )));
        assert_eq!(
            marker_verdict(
                "src/users.test.ts",
                "db.user.findMany({ skip: 10, take: 5 })"
            ),
            skip
        );
    }

    /// Decision 3 of #18 (ADR-013, D7): v1 scans JS/TS only. Python and
    /// in-source tests of `.vue` and `.svelte` files are #69; this pins
    /// the residual so changing it is deliberate.
    #[test]
    fn python_markers_are_out_of_v1() {
        for (path, line) in [
            ("tests/test_totals.py", "@pytest.mark.skip(reason='x')"),
            ("docs/testing.md", "Use `it.skip(` to skip a test."),
            ("src/Totals.vue", "it.skip('x', f)"),
            ("src/Totals.svelte", "it.skip('x', f)"),
        ] {
            assert!(passes(&marker_verdict(path, line)), "{path}");
        }
    }

    #[test]
    fn markers_are_counted_per_name() {
        let with_skip = with_line("it.skip('old', f)");
        assert!(
            passes(&judge(vec![change(
                "a.test.ts",
                file(&with_skip),
                file(&with_skip.replace("toBe(3)", "toBe(4)"))
            )])),
            "an existing skip and an unrelated edit"
        );
        let moved = format!("it.skip('old', f)\n{SUITE}");
        assert!(
            passes(&judge(vec![change(
                "a.test.ts",
                file(&with_skip),
                file(&moved)
            )])),
            "a moved skip"
        );
        assert_eq!(
            judge(vec![change(
                "a.test.ts",
                file(&with_line("it.only('x', f)")),
                file(&with_line("it.skip('x', f)"))
            )]),
            one(disables(0, TestDisabling::Marker(Marker::Skip))),
            ".only to .skip"
        );
        assert_eq!(
            judge(vec![add("a.test.ts", file("it.skip"))]),
            one(disables(0, TestDisabling::Marker(Marker::Skip))),
            "last in the file without a newline"
        );
        assert_eq!(
            judge(vec![add("a.test.ts", file("xit('a', f)"))]),
            one(disables(0, TestDisabling::Marker(Marker::Xit))),
            "first in the file"
        );
    }

    #[test]
    fn marker_words_are_not_markers() {
        for line in [
            "it('should skip weekends', f)",
            "it('only admins', f)",
            "it('x', () => expect.fail())",
            "it('x', () => assert.fail())",
            "const skipped = 1",
            "it.onlyIf(c)",
            "it.sk\u{200D}ip('x', f)",
            "it.\u{FF53}\u{FF4B}\u{FF49}\u{FF50}('x', f)",
            "const todo = list.filter(f)",
        ] {
            assert!(passes(&marker_verdict("a.test.ts", line)), "{line:?}");
        }
    }

    #[test]
    fn new_test_file_is_checked_like_any() {
        assert!(passes(&judge(vec![add("src/totals.test.ts", file(SUITE))])));
        assert_eq!(
            judge(vec![add(
                "src/totals.test.ts",
                file(&with_line("it.skip('x', f)"))
            )]),
            one(disables(0, TestDisabling::Marker(Marker::Skip)))
        );
    }

    #[test]
    fn deleted_test_files_are_rejected() {
        for path in [
            "a.test.ts",
            "__tests__/x.ts",
            "e2e/a.spec.ts",
            "x.e2e-spec.ts",
        ] {
            assert_eq!(
                judge(vec![change(path, file(SUITE), None)]),
                one(disables(0, TestDisabling::DeletedTestFile)),
                "{path}"
            );
        }
        assert!(passes(&judge(vec![change("src/a.ts", file(SUITE), None)])));
        assert_eq!(
            judge(vec![change("a.test.ts", file(SUITE), link("b.test.ts"))]),
            one(disables(0, TestDisabling::DeletedTestFile)),
            "a test file turned into a symlink"
        );
        assert_eq!(
            judge(vec![change("a.test.ts", file(SUITE), link("/etc"))]),
            reject(vec![
                PatchViolation::Link {
                    index: 0,
                    problem: LinkProblem::Absolute,
                },
                disables(0, TestDisabling::DeletedTestFile),
            ])
        );
    }

    #[test]
    fn removed_or_commented_tests_are_rejected() {
        let removed = one(disables(0, TestDisabling::TestsRemoved));
        let edit = |after: String| judge(vec![change("a.test.ts", file(SUITE), file(&after))]);
        let rounds = "  it('rounds', () => {\n    expect(sum(0.1, 0.2)).toBeCloseTo(0.3)\n  })\n";
        assert!(SUITE.contains(rounds));
        assert_eq!(edit(SUITE.replace(rounds, "")), removed);
        assert_eq!(
            edit(SUITE.replace("  it('rounds'", "  // it('rounds'")),
            removed
        );
        assert_eq!(
            edit(SUITE.replace(rounds, &format!("  /*\n{rounds}  */\n"))),
            removed
        );
        assert!(passes(&edit(with_line("it('new', f)"))));
        assert!(passes(&edit(
            SUITE.replace("it('rounds'", "test.each([1])('rounds'")
        )));
        assert!(passes(&edit(with_line(
            "const u = 'http://x'; it('new', f)"
        ))));
        assert!(passes(&judge(vec![change(
            "src/a.ts",
            file(SUITE),
            file("x\n")
        )])));
    }

    #[test]
    fn test_runner_config_changes_are_rejected() {
        let changed = one(disables(0, TestDisabling::TestConfigChanged));
        for path in [
            "jest.config.ts",
            "vitest.config.mts",
            "vitest.workspace.ts",
            "playwright.config.ts",
            "cypress.config.js",
            ".mocharc.yml",
            "karma.conf.js",
        ] {
            assert_eq!(
                judge(vec![change(path, file("a\n"), file("b\n"))]),
                changed,
                "{path}"
            );
            assert_eq!(
                judge(vec![change(path, file("a\n"), None)]),
                changed,
                "{path}"
            );
        }
        let vite = |before: &str, after: &str| {
            judge(vec![change("vite.config.ts", file(before), file(after))])
        };
        assert!(passes(&vite(
            "export default { plugins: [] }\n",
            "export default { plugins: [a] }\n"
        )));
        assert_eq!(
            vite(
                "export default { test: { globals: true } }\n",
                "export default {}\n"
            ),
            changed
        );
        assert_eq!(
            vite(
                "export default {}\n",
                "export default { 'test': { exclude: ['**'] } }\n"
            ),
            changed
        );
    }

    #[test]
    fn violations_are_ordered() {
        let patch = Patch {
            changes: vec![
                add("a/.github/w.ts", bytes(b"\0")),
                change(
                    "b.test.ts",
                    file(SUITE),
                    file(&format!("{SUITE}it.only('x', f)\nit.skip('y', f)\n")),
                ),
            ],
            base_links: Vec::new(),
        };
        let expected = reject(vec![
            PatchViolation::TooManyLines { limit: 1 },
            PatchViolation::Forbidden {
                index: 0,
                class: ForbiddenClass::Ci,
            },
            PatchViolation::NotText {
                index: 0,
                reason: NotText::Nul,
            },
            disables(1, TestDisabling::Marker(Marker::Skip)),
            disables(1, TestDisabling::Marker(Marker::Only)),
        ]);
        assert_eq!(patch_policy(&patch, &limits(25, 1)), expected);
        assert_eq!(patch_policy(&patch, &limits(25, 1)), expected);
    }

    // Review round 1 of PR #70.

    /// Item 1: a link at a forbidden path protects what it points to.
    #[test]
    fn links_at_forbidden_paths_protect_their_targets() {
        use ForbiddenClass::*;
        let edit = |path: &str| change(path, file("a\n"), file("b\n"));
        for (link, target, edited, class) in [
            (".npmrc", "config/npmrc", "config/npmrc", Dependencies),
            (".dockerignore", ".gitignore", ".gitignore", ContainerBuild),
            ("Jenkinsfile", "ci/build.groovy", "ci/build.groovy", Ci),
            (".github", "ci", "ci/workflows/x.yml", Ci),
            ("docs/CODEOWNERS", "../owners.txt", "owners.txt", CodeOwners),
        ] {
            assert_eq!(
                judge_with(vec![edit(edited)], vec![base_link(link, target)]),
                one(PatchViolation::Forbidden { index: 0, class }),
                "{link} -> {target}, edit {edited}"
            );
        }
        assert_eq!(
            judge_with(
                vec![edit("config/vitest.ts")],
                vec![base_link("vitest.config.ts", "config/vitest.ts")]
            ),
            one(disables(0, TestDisabling::TestConfigChanged))
        );
        // Through a chain of links, and at every link the chain passes.
        let chain = || vec![base_link(".npmrc", "cfg"), base_link("cfg", "config/npmrc")];
        for edited in ["config/npmrc", "config"] {
            assert_eq!(
                judge_with(vec![edit(edited)], chain()),
                one(PatchViolation::Forbidden {
                    index: 0,
                    class: Dependencies
                }),
                "{edited}"
            );
        }
        assert_eq!(
            judge_with(
                vec![change("cfg", link("config/npmrc"), link("elsewhere"))],
                chain()
            ),
            one(PatchViolation::Forbidden {
                index: 0,
                class: Dependencies
            }),
            "retargeting a link the chain passes"
        );
        // A link the patch adds at a forbidden path protects its target too.
        assert_eq!(
            judge(vec![add(".npmrc", link("npmrc.txt")), edit("npmrc.txt")]),
            reject(vec![
                PatchViolation::Forbidden {
                    index: 0,
                    class: Dependencies
                },
                PatchViolation::Forbidden {
                    index: 1,
                    class: Dependencies
                },
            ])
        );
        // Unrelated paths, loops and outward links protect nothing.
        assert!(passes(&judge_with(
            vec![edit("src/a.ts")],
            vec![
                base_link(".npmrc", "loop"),
                base_link("Dockerfile", "/etc/x"),
                base_link("Jenkinsfile", "../x"),
                base_link("loop", ".npmrc"),
            ]
        )));
    }

    /// Item 1: a resolution that branches past the state cap protects
    /// every path.
    #[test]
    fn protected_resolution_gives_up_closed() {
        // Twenty non-ASCII links share one alias key, and each points back
        // through it: the resolution branches twenty ways per hop.
        let mut links = vec![base_link(".npmrc", "\u{E0}/x")];
        for k in 0..20u32 {
            let name = char::from_u32(0xE0 + k).expect("a letter");
            links.push(base_link(&format!("{name}"), "\u{E0}/x"));
        }
        links.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(
            judge_with(vec![change("src/a.ts", file("a\n"), file("b\n"))], links),
            one(PatchViolation::Forbidden {
                index: 0,
                class: ForbiddenClass::Dependencies
            })
        );
    }

    /// Item 2: non-ASCII components alias each other for links.
    #[test]
    fn non_ascii_components_alias_links() {
        let through = link_problem(0, LinkProblem::ThroughLink);
        for (link, file_path) in [
            ("\u{C4}", "\u{E4}/workflows/ci.yml"),
            ("\u{E4}", "\u{C4}/workflows/ci.yml"),
            ("caf\u{E9}", "cafe\u{301}/workflows/ci.yml"),
            ("cafe\u{301}", "caf\u{E9}/workflows/ci.yml"),
        ] {
            assert_eq!(
                judge_with(
                    vec![add(file_path, file("x\n"))],
                    vec![base_link(link, ".github")]
                ),
                through,
                "{link:?} {file_path:?}"
            );
        }
        // ASCII names still alias by case only.
        assert!(passes(&judge_with(
            vec![add("docs2/x.ts", file("x\n"))],
            vec![base_link("docs", "src")]
        )));
    }

    /// Items 3, 4 and 6: the base counts an upper bound of its tests, the
    /// after side a lower bound.
    #[test]
    fn declaration_counts_are_bounded() {
        let removed = one(disables(0, TestDisabling::TestsRemoved));
        let edit = |before: &str, after: &str| {
            judge(vec![change("e2e/x.spec.ts", file(before), file(after))])
        };
        let three = "test('a', f)\ntest('b', f)\ntest('c', f)\n";
        // A comment opener in a base string hides no base test.
        let api = format!("const api = '/api/*'\n{three}");
        assert_eq!(edit(&api, "const api = '/api/*'\ntest('a', f)\n"), removed);
        // A test inside a string or template does not offset a deletion.
        assert_eq!(
            edit(
                three,
                "test('a', f)\ntest('b', f)\nconst s = \"test('c', f)\"\n"
            ),
            removed
        );
        assert_eq!(
            edit(
                three,
                "test('a', f)\ntest('b', f)\nconst s = `\ntest('c', f)\n`\n"
            ),
            removed
        );
        // HTML-like comments comment a test out.
        for hidden in ["--> test('c', f)", "<!-- test('c', f)"] {
            assert_eq!(
                edit(three, &format!("test('a', f)\ntest('b', f)\n{hidden}\n")),
                removed,
                "{hidden}"
            );
        }
        // An unrelated edit next to such strings passes.
        assert!(passes(&edit(&api, &format!("{api}// note\n"))));
    }

    /// Item 6: a test file whose base or after side is not text cannot be
    /// counted, so it counts as a removal.
    #[test]
    fn test_files_that_are_not_text_count_as_removed() {
        let removed = disables(0, TestDisabling::TestsRemoved);
        assert_eq!(
            judge(vec![change(
                "src/a.test.ts",
                bytes(b"test('a', f)\ntest('b', f)\n// caf\xE9\n"),
                file("test('a', f)\n")
            )]),
            one(removed.clone())
        );
        assert_eq!(
            judge(vec![change(
                "src/a.test.ts",
                file("test('a', f)\n"),
                bytes(b"test('a', f)\0")
            )]),
            reject(vec![
                PatchViolation::NotText {
                    index: 0,
                    reason: NotText::Nul
                },
                removed,
            ])
        );
    }

    /// Item 5: the shorthand `{ test }` is a Vitest key.
    #[test]
    fn vite_shorthand_test_key_counts() {
        assert_eq!(
            judge(vec![change(
                "vite.config.ts",
                file(
                    "const test = { include: ['src'] }\nexport default defineConfig({ plugins: [], test })\n"
                ),
                file(
                    "const test = { include: ['none'] }\nexport default defineConfig({ plugins: [], test })\n"
                )
            )]),
            one(disables(0, TestDisabling::TestConfigChanged))
        );
    }

    /// Item 8: call markers accept the member rule's separators.
    #[test]
    fn call_markers_accept_separators() {
        for line in [
            "fit?.('b', f)",
            "fit/**/('b', f)",
            "fit!('b', f)",
            "xit?.('b', f)",
        ] {
            let marker = if line.starts_with('x') {
                Marker::Xit
            } else {
                Marker::Fit
            };
            assert_eq!(
                marker_verdict("src/totals.test.ts", line),
                one(disables(0, TestDisabling::Marker(marker))),
                "{line}"
            );
        }
    }

    /// Item 9: a link to the root or above a known forbidden path.
    #[test]
    fn links_enclosing_forbidden_paths_are_rejected() {
        use ForbiddenClass::*;
        for (path, target) in [
            ("x", "."),
            ("docs/x", ".."),
            ("x", ".github/.."),
            ("a/b/l", "../.."),
        ] {
            assert_eq!(
                judge(vec![add(path, link(target))]),
                link_problem(0, LinkProblem::Encloses(RepositoryMetadata)),
                "{path} -> {target}"
            );
        }
        assert_eq!(
            judge(vec![
                add("apps/web/Dockerfile", file("x\n")),
                add("l", link("apps"))
            ]),
            reject(vec![
                PatchViolation::Forbidden {
                    index: 0,
                    class: ContainerBuild
                },
                PatchViolation::Link {
                    index: 1,
                    problem: LinkProblem::Encloses(ContainerBuild)
                },
            ])
        );
        assert_eq!(
            judge_with(
                vec![add("l", link("apps/web"))],
                vec![base_link("apps/web/package.json", "../p.json")]
            ),
            link_problem(0, LinkProblem::Encloses(Dependencies))
        );
        // A directory above nothing forbidden that the patch names passes.
        assert!(passes(&judge(vec![add("l", link("src/lib"))])));
    }

    /// Item 10: a byte budget next to the line budget.
    #[test]
    fn byte_budget_bounds_long_lines() {
        let over = one(PatchViolation::TooManyBytes { limit: 42_000 });
        assert_eq!(
            judge(vec![add("dist/app.js", file(&"x".repeat(42_001)))]),
            over
        );
        assert_eq!(
            judge(vec![add("dist/app.js", file(&"x".repeat(42_000)))]),
            PatchVerdict::Pass { files: 1, lines: 1 }
        );
        // Across files, and only the changed lines count.
        let base: String = (0..2_000).map(|k| format!("line {k:05}\n")).collect();
        let edited = base.replacen("line 01000\n", "line 01000 edited\n", 1);
        assert!(passes(&judge(vec![change(
            "big.txt",
            file(&base),
            file(&edited)
        )])));
        assert_eq!(
            judge(vec![
                add("a.js", file(&"x".repeat(21_000))),
                add("b.js", file(&"y".repeat(21_001)))
            ]),
            over
        );
    }

    /// Markers count as a net increase, so the base's count is a lower
    /// bound (markers in code under both readings only) and the after
    /// side's an upper bound (every occurrence): deleting a marker the base
    /// holds in a comment or a string cannot offset a real one.
    #[test]
    fn base_markers_outside_code_do_not_offset() {
        let skip = one(disables(0, TestDisabling::Marker(Marker::Skip)));
        for hidden in [
            "// it.skip('a', f)",
            "/* it.skip('a', f) */",
            "const note = 'it.skip(a)'",
            "const t = `it.skip('a', f)`",
            "<!-- it.skip('a', f)",
        ] {
            assert_eq!(
                judge(vec![change(
                    "src/totals.test.ts",
                    file(&with_line(hidden)),
                    file(&with_line("it.skip('b', f)"))
                )]),
                skip,
                "{hidden}"
            );
        }
        // A real base marker in code still offsets, in every form.
        for real in [
            "it.skip('a', f)",
            "it['skip']('a', f)",
            "test('x', { skip: true }, f)",
        ] {
            assert!(
                passes(&judge(vec![change(
                    "src/totals.test.ts",
                    file(&with_line(real)),
                    file(&with_line(
                        &real.replace("'a'", "'b'").replace("'x'", "'y'")
                    ))
                )])),
                "{real}"
            );
        }
    }

    // Review round 2 of PR #70.

    /// Item 1: a fake test inside an after-side string never counts, in
    /// every string form JS defines, and `/` after any word is ambiguous.
    #[test]
    fn after_strings_hide_no_declarations() {
        let before = "import { test } from 'vitest';\ntest('a', () => {});\ntest('b', () => {});\n";
        let removed = one(disables(0, TestDisabling::TestsRemoved));
        for extra in [
            "const s = '\\u0027test(\"b\", () => {})\\u0027';\n",
            "const s = '\\x27test(\"b\", () => {})\\x27';\n",
            "const s = 'x\\\r\ntest(\"b\", () => {})';\n",
            "const s = 'x\\\ntest(\"b\", () => {})';\n",
            "const s = 'x\u{2028}test(\"b\", () => {})';\n",
            "const s = 'x\u{2029}test(\"b\", () => {})';\n",
            "function g() { return aw\u{61}it /'/ + 'test(\"b\", () => {})'; }\n",
            "function* g() { yield /'/ + 'test(\"b\", () => {})'; }\n",
            "const t = typeof /'/ + 'test(\"b\", () => {})';\n",
            "const s = `\\u0060test(\"b\", () => {})\\u0060`;\n",
            "const s = `\\`test(\"b\", () => {})\\``;\n",
            "const s = 'test(\"b\", () => {})';\n",
        ] {
            let after =
                format!("import {{ test }} from 'vitest';\ntest('a', () => {{}});\n{extra}");
            assert_eq!(
                judge(vec![change("src/a.test.ts", file(before), file(&after))]),
                removed,
                "{extra:?}"
            );
        }
        // An escaped identifier in code is still a declaration.
        let escaped =
            "import { test } from 'vitest';\ntest('a', () => {});\n\\u0074est('b', () => {});\n";
        assert!(passes(&judge(vec![change(
            "src/a.test.ts",
            file(before),
            file(escaped)
        )])));
    }

    /// Item 3: a name that aliases a link is also read as the real
    /// directory of that name.
    #[test]
    fn protected_walk_keeps_the_directory_reading() {
        let links = || {
            vec![
                base_link(".npmrc", "config/../real/npmrc"),
                base_link("Config", "x/y"),
            ]
        };
        assert_eq!(
            judge_with(
                vec![change("real/npmrc", file("a\n"), file("b\n"))],
                links()
            ),
            one(PatchViolation::Forbidden {
                index: 0,
                class: ForbiddenClass::Dependencies
            })
        );
        // The link reading still counts too.
        let through = || {
            vec![
                base_link(".npmrc", "config/npmrc"),
                base_link("Config", "x"),
            ]
        };
        assert_eq!(
            judge_with(vec![change("x/npmrc", file("a\n"), file("b\n"))], through()),
            one(PatchViolation::Forbidden {
                index: 0,
                class: ForbiddenClass::Dependencies
            })
        );
    }

    /// Item 4: a link at a test file or test directory makes what it
    /// reaches a test file.
    #[test]
    fn links_at_test_paths_protect_their_targets() {
        let suite = "test('a', () => {});\ntest('b', () => {});\n";
        let removed = one(disables(0, TestDisabling::TestsRemoved));
        let edit = || {
            vec![change(
                "shared/cases.ts",
                file(suite),
                file("test('a', () => {});\n"),
            )]
        };
        assert_eq!(
            judge_with(
                edit(),
                vec![base_link("src/a.test.ts", "../shared/cases.ts")]
            ),
            removed
        );
        assert_eq!(
            judge_with(edit(), vec![base_link("tests", "shared")]),
            removed
        );
        assert_eq!(
            judge_with(
                vec![change(
                    "shared/cases.ts",
                    file(suite),
                    file(&format!("{suite}it.skip('c', f)\n"))
                )],
                vec![base_link("tests", "shared")]
            ),
            one(disables(0, TestDisabling::Marker(Marker::Skip)))
        );
        assert_eq!(
            judge_with(
                vec![change("shared/cases.ts", file(suite), None)],
                vec![base_link("tests", "shared")]
            ),
            one(disables(0, TestDisabling::DeletedTestFile))
        );
        // A link at an ordinary path protects nothing.
        assert!(passes(&judge_with(
            edit(),
            vec![base_link("src/cases.ts", "../shared/cases.ts")]
        )));
    }

    /// Item 5: a backslash in a protected link's target is also read as a
    /// separator.
    #[test]
    fn protected_targets_split_on_backslash() {
        for target in ["config\\npmrc", "config\\sub/..\\npmrc"] {
            assert_eq!(
                judge_with(
                    vec![change("config/npmrc", file("a\n"), file("b\n"))],
                    vec![base_link(".npmrc", target)]
                ),
                one(PatchViolation::Forbidden {
                    index: 0,
                    class: ForbiddenClass::Dependencies
                }),
                "{target:?}"
            );
        }
    }

    // Review round 3 of PR #70.

    /// Item 1: `/` after any token that can end an expression is ambiguous,
    /// and a hashbang line is a comment on the after side.
    #[test]
    fn slash_after_any_expression_end_is_ambiguous() {
        let before = "import { test } from 'vitest';\ntest('a', () => {});\ntest('b', () => {});\n";
        let removed = one(disables(0, TestDisabling::TestsRemoved));
        let head = "import { test } from 'vitest';\ntest('a', () => {});\n";
        let fake = "const s = '/test(\"b\", () => {})//';";
        for line in [
            format!("let x = 0; x++ / 2; {fake}"),
            format!("let x = 0; x-- / 2; {fake}"),
            format!("let x: number | undefined = 4; const y = x! / 2; {fake}"),
            format!("const y = [1][0] / 2; {fake}"),
            format!("const y = 'a'.length / 2; {fake}"),
            format!("const y = `a` / 2; {fake}"),
        ] {
            assert_eq!(
                judge(vec![change(
                    "src/a.test.ts",
                    file(before),
                    file(&format!("{head}{line}\n"))
                )]),
                removed,
                "{line}"
            );
        }
        let hashbang = format!("#!/x/ test(\"b\", () => {{}})\n{head}");
        assert_eq!(
            judge(vec![change("src/a.test.ts", file(before), file(&hashbang))]),
            removed
        );
        // The base reads a hashbang line as code: its count stays an upper
        // bound, so keeping the line passes.
        let base = format!("#!/usr/bin/node\n{before}");
        assert!(passes(&judge(vec![change(
            "src/a.test.ts",
            file(&base),
            file(&format!("{base}// note\n"))
        )])));
    }

    /// Item 2: the protected-link walk has a per-patch budget of
    /// components; past it, or at a target over 4,095 bytes, every path is
    /// protected.
    #[test]
    fn protected_walk_budget_fails_closed() {
        let deps = |index| PatchViolation::Forbidden {
            index,
            class: ForbiddenClass::Dependencies,
        };
        // A guard link through an over-long target.
        let long = "x/".repeat(2048);
        assert_eq!(
            judge_with(
                vec![change("src/a.ts", file("a\n"), file("b\n"))],
                vec![base_link(".npmrc", "x"), base_link("x", &long)]
            ),
            one(deps(0))
        );
        // Guard links whose walks together pass the budget.
        let deep = format!("{}npmrc", "d/".repeat(2040));
        let mut links: Vec<BaseLink> = (0..600)
            .map(|k| base_link(&format!("p{k:03}/.npmrc"), &format!("../{deep}")))
            .collect();
        links.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(
            judge_with(vec![change("src/a.ts", file("a\n"), file("b\n"))], links),
            one(deps(0))
        );
    }

    // The work bound of review round 3 of PR #70 (item 2), counted instead
    // of timed (#125). The counts are private fields of `Reached`: `steps`
    // is the byte budget left of `MAX_STEPS`, `places` the arena. A
    // refactor of either keeps a counter these tests can read.

    /// Links whose walk branches: every name `a{i}` aliases the links
    /// `a{i}` and `A{i}`, both to `a{i + 1}`, so each level doubles the
    /// states, down to `end` at depth 13; and the guard
    /// `p/package.json -> ../a0`.
    fn branching_links() -> Patch {
        let mut links = Vec::new();
        for i in 0..12 {
            let next = format!("a{}", i + 1);
            links.push(base_link(&format!("a{i}"), &next));
            links.push(base_link(&format!("A{i}"), &next));
        }
        links.push(base_link("a12", "end"));
        links.push(base_link("A12", "end"));
        links.push(base_link("p/package.json", "../a0"));
        links.sort_by(|a, b| a.path.cmp(&b.path));
        Patch {
            changes: Vec::new(),
            base_links: links,
        }
    }

    /// A branching walk stops at `MAX_STATES` (ADR-013, D6), long before
    /// the byte budget. Depth 13 stays under `MAX_HOPS` (40), so only the
    /// state cap can stop the walk early; without it the walk ends on its
    /// own with every path marked, and without both caps (the PR #70
    /// regression) too.
    #[test]
    fn protected_walk_state_cap_stops_branching() {
        let patch = branching_links();
        let tree = LinkTree::after(&patch);
        let mut reached = Reached::new();
        let ok = reached.resolve(&tree, "p/package.json", b"../a0", 1);
        let charged = MAX_STEPS - reached.steps;
        let places = reached.places.len();
        assert!(
            !ok,
            "the walk did not give up: {charged} bytes, {places} places"
        );
        assert!(
            charged < 4_096,
            "the byte budget stopped it: {charged} bytes"
        );
        assert!(places <= 64, "{places} places");
    }

    /// The two review shapes of PR #70 give up within the byte budget
    /// (ADR-013, D6), as the clock-free test in `boneli-replay-check`
    /// builds them: links `X` and `x` to `x/` repeated, and guards
    /// `pNN/package.json -> ../x`. 20,000 components make a 40 KB target,
    /// over `MAX_TARGET`, so the walk gives up before it reads any of it;
    /// 23 guards over 2,047 components exhaust the budget on the first
    /// guard, and the other 22 still give up.
    #[test]
    fn protected_walk_cost_is_bounded_on_the_review_shapes() {
        // The review shapes end only through the caps: without one, or
        // with a budget that followed links do not drain, the second
        // shape runs for minutes. Both caps are checked on finite walks
        // first, so such a change fails here by assertion.
        let finite = branching_links();
        let tree = LinkTree::after(&finite);
        assert!(
            !Reached::new().resolve(&tree, "p/package.json", b"../a0", 1),
            "the state cap does not stop a branching walk"
        );
        let mut drained = Reached::new();
        drained.steps = 8;
        assert!(
            !drained.resolve(&tree, "p/package.json", b"../end/a/b/c", 1),
            "the byte budget does not stop a straight walk"
        );
        // Through a followed link: `p`, `..` and `q` (7 bytes) fit, the
        // target `end/a/b/c` of `q` (10 bytes) does not.
        let followed = Patch {
            changes: Vec::new(),
            base_links: vec![
                base_link("p/package.json", "../q"),
                base_link("q", "end/a/b/c"),
            ],
        };
        let tree = LinkTree::after(&followed);
        let mut drained = Reached::new();
        drained.steps = 8;
        assert!(
            !drained.resolve(&tree, "p/package.json", b"../q", 1),
            "the byte budget does not stop a walk through a followed link"
        );
        for (k, guards) in [(20_000, 1), (2_047, 1), (2_047, 23)] {
            let target = "x/".repeat(k);
            let mut changes = vec![add("X", link(&target)), add("x", link(&target))];
            for g in 0..guards {
                changes.push(add(&format!("p{g:02}/package.json"), link("../x")));
            }
            changes.sort_by(|a, b| a.path.cmp(&b.path));
            let patch = Patch {
                changes,
                base_links: Vec::new(),
            };
            let ctx = Context::new(&patch);
            let charged = MAX_STEPS - ctx.reached.steps;
            let places = ctx.reached.places.len();
            assert!(
                ctx.everywhere & guard_bit(Guard::Class(ForbiddenClass::Dependencies)) != 0,
                "{guards} guards over {k}: the walk did not give up"
            );
            // The first guard's walk through the followed links `X` and
            // `x` drains the budget: less than one longest target is left,
            // with that guard alone as with all 23.
            if k == 2_047 {
                assert!(
                    charged > MAX_STEPS - MAX_TARGET - 1,
                    "{guards} guards over {k}: the budget was not drained: \
                     {charged} bytes, {places} places"
                );
            }
            // The over-long target stops the walk where it is met, after
            // `p00`, `..` and `x` (9 bytes), not after a walk of it.
            if k == 20_000 {
                assert!(
                    charged < 4_096,
                    "the 40 KB target was walked: {charged} bytes"
                );
            }
        }
    }

    /// Every followed link is charged, up to the last hop `MAX_HOPS` allows,
    /// not only the first few: a straight chain `p/package.json -> ../l0`,
    /// `l{i} -> l{i+1}`, `l39 -> end` takes hops 1 to 40 (`MAX_HOPS`)
    /// without branching, so the charge is exact. A budget that stops charging at some hop lets
    /// the review shapes run on to the state cap and fails here at once.
    #[test]
    fn protected_walk_charges_every_hop() {
        let mut links = vec![base_link("p/package.json", "../l0")];
        let mut expected = "p".len() + 1 + "..".len() + 1 + "l0".len() + 1;
        for i in 0..MAX_HOPS {
            let next = if i == MAX_HOPS - 1 {
                String::from("end")
            } else {
                format!("l{}", i + 1)
            };
            expected += next.len() + 1;
            links.push(base_link(&format!("l{i}"), &next));
        }
        links.sort_by(|a, b| a.path.cmp(&b.path));
        let patch = Patch {
            changes: Vec::new(),
            base_links: links,
        };
        let tree = LinkTree::after(&patch);
        let mut reached = Reached::new();
        assert!(reached.resolve(&tree, "p/package.json", b"../l0", 1));
        assert_eq!(MAX_STEPS - reached.steps, expected, "a hop went uncharged");
    }
}
