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
use crate::line_diff::{distance, lines};
use crate::patch_js::{Marker, active_declarations, has_test_key, marker_counts};
use crate::patch_path::{
    ForbiddenClass, fold_component, forbidden_class, is_js_ts, is_test_config, is_test_file,
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

/// The size limits, inclusive (ADR-013, D3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatchLimits {
    /// At most this many changed paths.
    pub max_changed_files: NonZeroU32,
    /// At most this many inserted plus deleted lines.
    pub max_changed_lines: NonZeroU32,
}

impl PatchLimits {
    /// 25 files and 1,000 lines: the 97th percentile of human bug fixes in
    /// the first stack's repositories (ADR-013, D3 and D8).
    pub const DEFAULT: PatchLimits = PatchLimits {
        max_changed_files: NonZeroU32::MIN.saturating_add(24),
        max_changed_lines: NonZeroU32::MIN.saturating_add(999),
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
    /// The change touches a forbidden path.
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
/// 4. Lines: `TooManyLines`, first in the list.
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
    let lines = changed_lines(&patch.changes, line_limit);
    if lines.is_none() {
        violations.push(PatchViolation::TooManyLines { limit: line_limit });
    }
    let tree = LinkTree::after(patch);
    for (index, change) in patch.changes.iter().enumerate() {
        judge_change(index, change, &tree, &mut violations);
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

/// What a side contributes to the line count.
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

/// A side's lines (ADR-013, D3): a text file's lines, one line for a
/// symlink or a gitlink, none for a binary or an absent side.
fn side_lines(entry: Option<&Entry>) -> (Vec<&[u8]>, Category) {
    match entry {
        None => (Vec::new(), Category::Absent),
        Some(e) => match e.kind {
            EntryKind::File | EntryKind::Executable => (
                text(Some(e))
                    .map(|t| lines(t.as_bytes()))
                    .unwrap_or_default(),
                Category::Regular,
            ),
            EntryKind::Symlink => (vec![e.data.as_slice()], Category::Link),
            EntryKind::Gitlink => (vec![e.data.as_slice()], Category::Gitlink),
        },
    }
}

/// A change's inserted plus deleted lines, or `None` above `max`. A type
/// change (a file to a symlink, say) shares no lines, as git shows it as a
/// deletion and an addition.
fn change_cost(change: &Change, max: usize) -> Option<usize> {
    let (before, from) = side_lines(change.before.as_ref());
    let (after, to) = side_lines(change.after.as_ref());
    if from == to || from == Category::Absent || to == Category::Absent {
        distance(&before, &after, max)
    } else {
        Some(before.len().checked_add(after.len())?).filter(|cost| *cost <= max)
    }
}

/// Step 4 of [`patch_policy`]: the total, or `None` once it passes the
/// limit. Each change's search is cut off at what is left of the limit.
fn changed_lines(changes: &[Change], limit: u32) -> Option<u32> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut total = 0usize;
    for change in changes {
        let cost = change_cost(change, limit.checked_sub(total)?)?;
        total = total.checked_add(cost)?;
    }
    u32::try_from(total).ok()
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

/// The symlinks of the tree after the fix, by folded path: the base links
/// the patch does not change plus the after-side links. A flat trie, so a
/// deep path costs no recursion: node 0 is the root, and `children` maps a
/// node and a folded component to the child node.
struct LinkTree {
    children: BTreeMap<(usize, String), usize>,
    links: Vec<bool>,
}

const ROOT: usize = 0;

impl LinkTree {
    fn after(patch: &Patch) -> LinkTree {
        let mut tree = LinkTree {
            children: BTreeMap::new(),
            links: vec![false],
        };
        let changed = |path: &str| {
            patch
                .changes
                .binary_search_by(|c| c.path.as_str().cmp(path))
                .is_ok()
        };
        for link in &patch.base_links {
            if !changed(&link.path) {
                tree.insert(&link.path);
            }
        }
        for change in &patch.changes {
            if is_link(change.after.as_ref()) {
                tree.insert(&change.path);
            }
        }
        tree
    }

    fn insert(&mut self, path: &str) {
        let mut node = ROOT;
        for component in path.split('/') {
            let next = self.links.len();
            let child = *self
                .children
                .entry((node, fold_component(component)))
                .or_insert(next);
            if child == next {
                self.links.push(false);
            }
            node = child;
        }
        if let Some(flag) = self.links.get_mut(node) {
            *flag = true;
        }
    }

    /// The child of `node` at `component`; `None` off the trie, where no
    /// link can be.
    fn child(&self, node: Option<usize>, component: &str) -> Option<usize> {
        self.children
            .get(&(node?, fold_component(component)))
            .copied()
    }

    fn is_link(&self, node: Option<usize>) -> bool {
        node.is_some_and(|n| self.links.get(n) == Some(&true))
    }
}

/// A lexical walk over a path's components that refuses every position
/// that is a link of the tree after the fix.
struct Walk<'a> {
    tree: &'a LinkTree,
    nodes: Vec<Option<usize>>,
    components: Vec<&'a str>,
}

impl<'a> Walk<'a> {
    /// Starts at the parent directory of `path`, checking every prefix.
    fn at_parent_of(tree: &'a LinkTree, path: &'a str) -> Result<Walk<'a>, LinkProblem> {
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

    fn push(&mut self, component: &'a str) -> Result<(), LinkProblem> {
        let top = self.nodes.last().copied().unwrap_or(Some(ROOT));
        let node = self.tree.child(top, component);
        if self.tree.is_link(node) {
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
fn symlink_problem(path: &str, target: &[u8], tree: &LinkTree) -> Option<LinkProblem> {
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
    let walked = Walk::at_parent_of(tree, path).and_then(|mut walk| {
        for component in target.split('/') {
            match component {
                "" | "." => {}
                ".." => walk.pop()?,
                _ => walk.push(component)?,
            }
        }
        Ok(walk.components.join("/"))
    });
    match walked {
        Err(problem) => Some(problem),
        Ok(resolved) => forbidden_class(&resolved).map(LinkProblem::Into),
    }
}

/// The link family of one change: a symlink's own problem, or a regular
/// file beneath a link of the tree after the fix.
fn link_problem(change: &Change, tree: &LinkTree) -> Option<LinkProblem> {
    let after = change.after.as_ref()?;
    match after.kind {
        EntryKind::Symlink => symlink_problem(&change.path, &after.data, tree),
        EntryKind::File | EntryKind::Executable => Walk::at_parent_of(tree, &change.path).err(),
        EntryKind::Gitlink => None,
    }
}

/// Step 5 of [`patch_policy`] for one change.
fn judge_change(index: usize, change: &Change, tree: &LinkTree, out: &mut Vec<PatchViolation>) {
    let before = change.before.as_ref();
    let after = change.after.as_ref();
    if let Some(class) = forbidden_class(&change.path) {
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
    if let Some(problem) = link_problem(change, tree) {
        out.push(PatchViolation::Link { index, problem });
    }
    let mut disables = |reason| out.push(PatchViolation::DisablesTests { index, reason });
    let (before_text, after_text) = (text(before), text(after));
    if is_js_ts(&change.path) {
        let test_file = is_test_file(&change.path);
        let count = |side: Option<&str>| side.map(|t| marker_counts(t, test_file));
        let (was, now) = (count(before_text), count(after_text));
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
                let declarations = |side: Option<&str>| side.map_or(0, active_declarations);
                if declarations(after_text) < declarations(before_text) {
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
    if is_test_config(&change.path, test_key) {
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
            ("a", "."),
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
}
