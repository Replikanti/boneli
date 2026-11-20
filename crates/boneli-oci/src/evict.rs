//! Eviction and the leftover sweep (ADR-025, D1 and D4 to D7).
//!
//! A trim keeps the store's accounted bytes (D4) at or under its budget by
//! evicting the units used least recently (D5): committed layers, kept
//! documents and the compressed layer blobs a failed pull left. Layers in
//! use are pinned (D2) and skipped, so the budget is soft over data in use.
//! Trims are serialized per root by `locks/trim` (D6).
//!
//! One rule decides every removal: content is deleted only under a name
//! the cache never lists, once that name is durable, and an exclusive
//! holder never removes a tree while it holds a lock. A layer is evicted in
//! O(1) steps under its exclusive lock (D7): lock, check, rename the tree
//! to an owned `.tmp-` name of this process, `fsync` `layers/sha256/`,
//! unlink the sidecar, unlink the lock file and release. The trees are
//! removed after the trim lock is released. The sweep takes over a dead
//! owner's names the same way before it removes them (D1).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use crate::error::Error;
use crate::layers::{self, Judge, Liveness, Owner};
use crate::lock::{self, Exclusive};
use crate::store::BLOCK_ALLOWANCE;

/// What one trim found and did (ADR-025, D5). Byte totals are the
/// accounted bytes of D4, saturated at `u64::MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct TrimReport {
    /// The accounted bytes before the trim.
    pub before: u64,
    /// The accounted bytes after it. Above `budget` only when the units in
    /// use alone exceed it: the budget is soft over data in use.
    pub after: u64,
    /// The store's budget.
    pub budget: u64,
    /// Layer directories removed from the listed names: evicted layers and
    /// corrupt entries.
    pub removed_layers: u64,
    /// Files removed from `blobs/sha256/`: documents, their `.type`
    /// files, kept layer blobs and orphan `.type` files.
    pub removed_files: u64,
    /// Layers the trim would have evicted but found pinned.
    pub skipped_in_use: u64,
}

/// The points an eviction or a sweep passes, in order. The unit tests stop
/// the process at each of them (`interrupted_eviction_at_every_step`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// 1. The layer's exclusive lock is held, on the file the path names.
    Locked,
    /// 2. The layer is checked to still be what the scan found.
    Checked,
    /// 3. The tree is renamed to an owned `.tmp-` name.
    Renamed,
    /// 4. `layers/sha256/` is synced: the rename is durable.
    Synced,
    /// 5. The sidecar is unlinked.
    SidecarRemoved,
    /// 6. The lock file is unlinked and the lock released.
    Released,
    /// 7. The tree is removed (after the trim lock is released).
    Removed,
    /// A document's file is unlinked.
    DocumentRemoved,
    /// Then its `.type`.
    TypeRemoved,
    /// The sweep renamed a dead owner's names to its own and synced them.
    SweepRenamed,
    /// The sweep unlinked the dead owner's lock file and released it.
    SweepReleased,
}

#[cfg(test)]
impl Step {
    pub(crate) const ALL: [Step; 11] = [
        Step::Locked,
        Step::Checked,
        Step::Renamed,
        Step::Synced,
        Step::SidecarRemoved,
        Step::Released,
        Step::Removed,
        Step::DocumentRemoved,
        Step::TypeRemoved,
        Step::SweepRenamed,
        Step::SweepReleased,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Step::Locked => "locked",
            Step::Checked => "checked",
            Step::Renamed => "renamed",
            Step::Synced => "synced",
            Step::SidecarRemoved => "sidecar-removed",
            Step::Released => "released",
            Step::Removed => "removed",
            Step::DocumentRemoved => "document-removed",
            Step::TypeRemoved => "type-removed",
            Step::SweepRenamed => "sweep-renamed",
            Step::SweepReleased => "sweep-released",
        }
    }
}

/// The test hook: a unit test's child process exits at the step its
/// environment names, with no destructor run, as a crash would.
#[cfg(test)]
fn reached(step: Step) {
    if std::env::var(tests::EXIT_AT).is_ok_and(|s| s == step.name()) {
        std::process::exit(tests::EXITED);
    }
}

/// Release builds carry no hook.
#[cfg(not(test))]
fn reached(_: Step) {}

/// Sets the mtime of `path`, a sidecar or a kept document, to now: the
/// unit's last use (ADR-025, D5). Best effort: a failure only changes the
/// eviction order.
pub(crate) fn stamp(path: &Path) {
    let _ = File::open(path).and_then(|f| f.set_modified(SystemTime::now()));
}

/// 64 lower-case hex digits, the only name of a layer, a layer's lock file
/// or a blob. Upper case, other lengths, other scripts and suffixes are
/// never counted and never removed.
fn is_hex64(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The accounted bytes of a committed layer (ADR-025, D4): its
/// uncompressed bytes plus [`BLOCK_ALLOWANCE`] for each entry and one more
/// for the sidecar, saturated at `u64::MAX`.
fn layer_cost(bytes: u64, entries: u64) -> u64 {
    bytes.saturating_add(BLOCK_ALLOWANCE.saturating_mul(entries.saturating_add(1)))
}

/// The accounted bytes of one file in `blobs/sha256/` (D4).
fn file_cost(len: u64) -> u64 {
    len.saturating_add(BLOCK_ALLOWANCE)
}

/// A total as the report gives it. Totals are summed as `u128`, so
/// evicting a unit whose cost saturated does not lose the others.
fn saturated(total: u128) -> u64 {
    u64::try_from(total).unwrap_or(u64::MAX)
}

/// What a layer's names in `layers/sha256/` are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerState {
    /// Listed, with a sidecar that parses: its accounted bytes and the
    /// sidecar's mtime.
    Committed { cost: u64, stamp: SystemTime },
    /// A hex name that is not a directory, or a directory without a
    /// sidecar that parses. Every pull of it would fail, forever.
    Corrupt,
    /// A sidecar without its layer: a crash between steps 3 and 5, or a
    /// pull between the two renames of its commit.
    OrphanSidecar,
    /// Neither name.
    Absent,
}

impl LayerState {
    fn kind(self) -> u8 {
        match self {
            LayerState::Committed { .. } => 0,
            LayerState::Corrupt => 1,
            LayerState::OrphanSidecar => 2,
            LayerState::Absent => 3,
        }
    }
}

/// The longest sidecar read: `bytes`, `entries` and `skipped-devices` with
/// 20 digits each fit in 64 bytes; anything longer does not parse.
const MAX_SIDECAR_BYTES: u64 = 4_096;

fn layer_state(layers: &Path, hex: &str) -> io::Result<LayerState> {
    let sidecar = layers.join(format!("{hex}.stats"));
    let tree = match fs::symlink_metadata(layers.join(hex)) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return match fs::symlink_metadata(&sidecar) {
                Ok(_) => Ok(LayerState::OrphanSidecar),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(LayerState::Absent),
                Err(e) => Err(e),
            };
        }
        Err(e) => return Err(e),
    };
    if !tree.file_type().is_dir() {
        return Ok(LayerState::Corrupt);
    }
    let meta = match fs::symlink_metadata(&sidecar) {
        Ok(m) if m.file_type().is_file() => m,
        Ok(_) => return Ok(LayerState::Corrupt),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(LayerState::Corrupt),
        Err(e) => return Err(e),
    };
    let mut text = Vec::new();
    File::open(&sidecar)?
        .take(MAX_SIDECAR_BYTES)
        .read_to_end(&mut text)?;
    Ok(match layers::parse_sidecar(&text) {
        Some((bytes, entries, _)) => LayerState::Committed {
            cost: layer_cost(bytes, entries),
            stamp: meta.modified()?,
        },
        None => LayerState::Corrupt,
    })
}

/// What evicting one layer gave.
enum Evicted {
    /// Renamed out of the listed names, durably: the tree to remove.
    Tree(PathBuf),
    /// The sidecar alone was removed (an orphan).
    Sidecar,
    /// Someone holds the layer's lock: it is in use.
    Busy,
    /// The layer is no longer what the scan found; left alone.
    Changed,
}

/// The steps of D7 for the layer `hex`, which the scan found in `expect`'s
/// state: under its exclusive lock the state is checked again, the tree
/// (if any) renamed to an owned `.tmp-` name of this process and made
/// durable, the sidecar unlinked, the lock file unlinked and the lock
/// released. The tree is not removed here: the caller removes it once it
/// holds no lock (ADR-025, D3).
fn evict_layer(dirs: &Dirs, hex: &str, expect: LayerState) -> Result<Evicted, Error> {
    #[cfg(test)]
    tests::before_lock(hex);
    let held = match lock::try_exclusive(&dirs.locks.join(hex))? {
        Exclusive::Held(held) => held,
        Exclusive::Busy => return Ok(Evicted::Busy),
        Exclusive::Missing => return Ok(Evicted::Changed),
    };
    reached(Step::Locked);
    let state = layer_state(&dirs.layers, hex).map_err(|e| cache_err(&dirs.layers, e))?;
    if state.kind() != expect.kind() {
        return Ok(Evicted::Changed);
    }
    reached(Step::Checked);
    let renamed = if state == LayerState::OrphanSidecar {
        None
    } else {
        let tree = dirs.layers.join(hex);
        let temp = dirs.layers.join(layers::temporary_name()?);
        // A symlink at the name is moved itself, never its target.
        fs::rename(&tree, &temp).map_err(|e| cache_err(&tree, e))?;
        reached(Step::Renamed);
        layers::sync_dir(&dirs.layers)?;
        reached(Step::Synced);
        Some(temp)
    };
    let sidecar = dirs.layers.join(format!("{hex}.stats"));
    match fs::remove_file(&sidecar) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        // The lock file stays, and the next trim removes the orphan.
        Err(_) => return Ok(renamed.map_or(Evicted::Changed, Evicted::Tree)),
    }
    reached(Step::SidecarRemoved);
    let _ = held.remove();
    reached(Step::Released);
    Ok(renamed.map_or(Evicted::Sidecar, Evicted::Tree))
}

fn cache_err(path: &Path, source: io::Error) -> Error {
    Error::Cache {
        path: path.to_path_buf(),
        source,
    }
}

/// The store directories a trim works on.
struct Dirs {
    layers: PathBuf,
    blobs: PathBuf,
    locks: PathBuf,
}

/// One evictable unit.
struct Unit {
    stamp: SystemTime,
    path: PathBuf,
    cost: u64,
    kind: UnitKind,
}

enum UnitKind {
    /// A committed layer, by its hex name.
    Layer(String),
    /// A file in `blobs/sha256/`, and its `.type` if it is a document.
    Blob { typed: Option<PathBuf> },
}

/// The names of `dir` that are UTF-8, in name order.
fn names(dir: &Path) -> Result<BTreeSet<String>, Error> {
    let mut out = BTreeSet::new();
    for entry in fs::read_dir(dir).map_err(|e| cache_err(dir, e))? {
        let entry = entry.map_err(|e| cache_err(dir, e))?;
        if let Ok(name) = entry.file_name().into_string() {
            out.insert(name);
        }
    }
    Ok(out)
}

/// Trims the store at `root` to `budget` (ADR-025, D5 to D7). The caller
/// holds this process's owner lock (a `LayerCache`), which keeps the trees
/// renamed here from being judged dead. Waits for `locks/trim` until
/// `deadline` (`Error::LockBusy` after it). Fails only when a store
/// directory cannot be listed or the trim lock cannot be taken; an entry it
/// cannot handle is skipped.
pub(crate) fn trim(root: &Path, budget: u64, deadline: Instant) -> Result<TrimReport, Error> {
    let dirs = Dirs {
        layers: root.join("layers").join("sha256"),
        blobs: root.join("blobs").join("sha256"),
        locks: layers::layer_locks_dir(root),
    };
    let trim_lock = lock::lock_exclusive(&root.join("locks").join("trim"), deadline)?;
    let mut report = TrimReport {
        budget,
        ..TrimReport::default()
    };
    let mut doomed = Vec::new();
    let result = trim_locked(&dirs, &mut report, &mut doomed);
    drop(trim_lock);
    // Outside every lock: the trees are owned names of this process, which
    // the cache never lists.
    for tree in &doomed {
        let _ = layers::remove_tree_bounded(tree);
        reached(Step::Removed);
    }
    result.map(|()| report)
}

fn trim_locked(
    dirs: &Dirs,
    report: &mut TrimReport,
    doomed: &mut Vec<PathBuf>,
) -> Result<(), Error> {
    let mut units = Vec::new();

    // Layers: committed ones are units; corrupt entries and orphan
    // sidecars go now, whatever the budget.
    let mut hexes = BTreeSet::new();
    for name in names(&dirs.layers)? {
        if is_hex64(&name) {
            hexes.insert(name);
        } else if let Some(hex) = name.strip_suffix(".stats").filter(|h| is_hex64(h)) {
            hexes.insert(hex.to_owned());
        }
    }
    for hex in &hexes {
        let Ok(state) = layer_state(&dirs.layers, hex) else {
            continue;
        };
        match state {
            LayerState::Committed { cost, stamp } => units.push(Unit {
                stamp,
                path: dirs.layers.join(hex),
                cost,
                kind: UnitKind::Layer(hex.clone()),
            }),
            LayerState::Corrupt | LayerState::OrphanSidecar => {
                match evict_layer(dirs, hex, state) {
                    Ok(Evicted::Tree(tree)) => {
                        report.removed_layers += 1;
                        doomed.push(tree);
                    }
                    Ok(Evicted::Sidecar | Evicted::Busy | Evicted::Changed) | Err(_) => {}
                }
            }
            LayerState::Absent => {}
        }
    }

    // Blobs: every regular file with a hex name is a unit, a document with
    // its `.type`; a `.type` without its document goes now.
    let blob_names = names(&dirs.blobs)?;
    for name in &blob_names {
        let path = dirs.blobs.join(name);
        if is_hex64(name) {
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.file_type().is_file() {
                continue;
            }
            let type_path = dirs.blobs.join(format!("{name}.type"));
            let typed = fs::symlink_metadata(&type_path)
                .ok()
                .filter(|m| m.file_type().is_file());
            let mut cost = u128::from(file_cost(meta.len()));
            if let Some(t) = &typed {
                cost += u128::from(file_cost(t.len()));
            }
            let Ok(stamp) = meta.modified() else {
                continue;
            };
            units.push(Unit {
                stamp,
                path,
                cost: saturated(cost),
                kind: UnitKind::Blob {
                    typed: typed.map(|_| type_path),
                },
            });
        } else if let Some(doc) = name.strip_suffix(".type").filter(|h| is_hex64(h)) {
            let document = fs::symlink_metadata(dirs.blobs.join(doc));
            if document.is_ok_and(|m| m.file_type().is_file()) {
                continue;
            }
            if fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_dir())
                && fs::remove_file(&path).is_ok()
            {
                report.removed_files += 1;
            }
        }
    }

    // Least recently used first; ties by path bytes (D5).
    units.sort_by(|a, b| {
        (a.stamp, a.path.as_os_str().as_bytes()).cmp(&(b.stamp, b.path.as_os_str().as_bytes()))
    });
    let mut total: u128 = units.iter().map(|u| u128::from(u.cost)).sum();
    report.before = saturated(total);
    let budget = u128::from(report.budget);
    for unit in &units {
        if total <= budget {
            break;
        }
        match &unit.kind {
            UnitKind::Layer(hex) => {
                let expect = LayerState::Committed {
                    cost: unit.cost,
                    stamp: unit.stamp,
                };
                match evict_layer(dirs, hex, expect) {
                    Ok(Evicted::Tree(tree)) => {
                        total -= u128::from(unit.cost);
                        report.removed_layers += 1;
                        doomed.push(tree);
                    }
                    Ok(Evicted::Busy) => report.skipped_in_use += 1,
                    Ok(Evicted::Sidecar | Evicted::Changed) | Err(_) => {}
                }
            }
            UnitKind::Blob { typed } => {
                // The document first, then its type: the reverse of `put`,
                // and a document without its type reads as absent.
                match fs::remove_file(&unit.path) {
                    Ok(()) => report.removed_files += 1,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => continue,
                }
                reached(Step::DocumentRemoved);
                if let Some(type_path) = typed {
                    if fs::remove_file(type_path).is_ok() {
                        report.removed_files += 1;
                    }
                    reached(Step::TypeRemoved);
                }
                total -= u128::from(unit.cost);
            }
        }
    }
    report.after = saturated(total);

    // Lock files of layers that are not in the store, once nobody holds
    // them: a failed pull's, or one a crash left after step 5.
    for name in names(&dirs.locks)? {
        if !is_hex64(&name) || !matches!(layer_state(&dirs.layers, &name), Ok(LayerState::Absent)) {
            continue;
        }
        if let Ok(Exclusive::Held(held)) = lock::try_exclusive_existing(&dirs.locks.join(&name))
            && matches!(layer_state(&dirs.layers, &name), Ok(LayerState::Absent))
        {
            let _ = held.remove();
        }
    }
    Ok(())
}

/// Removes the names in `blobs/sha256/` and `layers/sha256/` that carry an
/// owner (ADR-009, D8) whose owner is gone, then the owner lock files no
/// name needs any more (ADR-025, D1). The names are grouped by owner, and
/// each owner is judged once:
///
/// - Its lock file `locks/owners/<token>` exists and an exclusive
///   `try_lock` gets it: the owner is gone, in whatever namespace or boot
///   it ran. Its names are renamed to owned names of this process and
///   made durable; then the lock file is unlinked, still locked, if every
///   name was taken over, and released. Only then are the names removed,
///   so a judge never removes a tree while it holds a lock (D3). A name
///   that cannot be removed is this process's now, and the first judge
///   after this process is gone tries again.
/// - The lock is held: the owner is alive, and its names stay.
/// - There is no lock file: the names come from a build before ADR-025,
///   and the `/proc` rule of ADR-009 D8 decides through `judge`, as it did;
///   no lock is held, so they are removed where they are.
/// - The lock path is not a regular file, or cannot be read: nothing is
///   concluded, and the names stay (fail closed).
///
/// Then every lock file in `owners/` named by a token that no name carries
/// is removed when its exclusive lock can be taken: an owner that left no
/// name and is gone. Names that carry no owner stay, in both places.
///
/// A name whose removal fails stays too, whatever the error: it is a dot
/// name, never read as a layer or a blob, so it costs disk, while failing
/// `open` for it would leave the store unopenable until someone removed it
/// by hand. An error is another store's sweep that removed it first, or a
/// tree that cannot be removed by path (one deeper than `PATH_MAX` under
/// this root's path, left by a process that reached the root through a
/// shorter one).
pub(crate) fn sweep(root: &Path, judge: &Judge) -> Result<(), Error> {
    let dirs = [
        root.join("blobs").join("sha256"),
        root.join("layers").join("sha256"),
    ];
    let owners = layers::owners_dir(root);
    let mut by_owner: BTreeMap<String, (Owner, Vec<PathBuf>)> = BTreeMap::new();
    for dir in &dirs {
        for entry in fs::read_dir(dir).map_err(|e| cache_err(dir, e))? {
            let entry = entry.map_err(|e| cache_err(dir, e))?;
            let name = entry.file_name();
            let Some(owner) = name.to_str().and_then(Owner::of_name) else {
                continue;
            };
            by_owner
                .entry(owner.token())
                .or_insert_with(|| (owner, Vec::new()))
                .1
                .push(entry.path());
        }
    }
    for (token, (owner, names)) in &by_owner {
        match lock::try_exclusive_existing(&owners.join(token)) {
            Ok(Exclusive::Held(held)) => {
                let (taken, all) = take_over(names, &dirs);
                reached(Step::SweepRenamed);
                if all {
                    let _ = held.remove();
                } else {
                    drop(held);
                }
                reached(Step::SweepReleased);
                remove_all(&taken);
            }
            Ok(Exclusive::Missing) if owner.liveness(judge) == Liveness::Dead => {
                remove_all(names);
            }
            Ok(Exclusive::Missing | Exclusive::Busy) | Err(_) => {}
        }
    }
    for entry in fs::read_dir(&owners).map_err(|e| cache_err(&owners, e))? {
        let entry = entry.map_err(|e| cache_err(&owners, e))?;
        let name = entry.file_name();
        let Some(token) = name.to_str().filter(|t| Owner::of_token(t).is_some()) else {
            continue;
        };
        if by_owner.contains_key(token) {
            continue;
        }
        if let Ok(Exclusive::Held(held)) = lock::try_exclusive_existing(&entry.path()) {
            let _ = held.remove();
        }
    }
    Ok(())
}

/// Renames each of `names` to an owned temporary name of this process in
/// its own directory, then syncs `dirs`. Returns the new names and whether
/// every one of `names` is now gone from its old name durably (a name that
/// is already gone counts as taken).
fn take_over(names: &[PathBuf], dirs: &[PathBuf]) -> (Vec<PathBuf>, bool) {
    let mut taken = Vec::new();
    let mut all = true;
    for name in names {
        let Some(dir) = name.parent() else {
            all = false;
            continue;
        };
        let Ok(temp) = layers::temporary_name().map(|n| dir.join(n)) else {
            all = false;
            continue;
        };
        match fs::rename(name, &temp) {
            Ok(()) => taken.push(temp),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => all = false,
        }
    }
    for dir in dirs {
        if layers::sync_dir(dir).is_err() {
            all = false;
        }
    }
    (taken, all)
}

/// Removes every path in `names`, each one tried even after a failure.
fn remove_all(names: &[PathBuf]) {
    for name in names {
        let _ = layers::remove_tree_bounded(name);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant, SystemTime};

    use boneli_https::Sha256;

    use super::{Step, sweep, trim};
    use crate::layers::{Judge, LayerCache, Owner};
    use crate::limits::{Budget, Limits};
    use crate::scratch::ScratchDir;
    use crate::unpack::Compression;

    /// The step a child process exits at.
    pub(crate) const EXIT_AT: &str = "BONELI_OCI_EVICT_EXIT_AT";
    /// Its exit status there, so the parent knows the step was reached.
    pub(crate) const EXITED: i32 = 75;
    /// The root the child trims or sweeps.
    const ROOT: &str = "BONELI_OCI_EVICT_ROOT";

    type Seam = Box<dyn FnMut(&str)>;

    std::thread_local! {
        /// Runs between a trim's scan and its lock on a layer, on this
        /// thread only: the race a pull can win in between.
        static BEFORE_LOCK: std::cell::RefCell<Option<Seam>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(crate) fn before_lock(hex: &str) {
        BEFORE_LOCK.with(|seam| {
            if let Some(f) = seam.borrow_mut().as_mut() {
                f(hex);
            }
        });
    }

    /// Step 2 of D7: under the layer's lock the trim checks again what the
    /// scan found. A corrupt entry (a directory without a sidecar) that a
    /// pull committed between the scan and the lock is a layer now, and
    /// stays; so is an orphan sidecar whose tree was committed meanwhile.
    #[test]
    fn state_checked_again_under_the_lock() {
        let scratch = ScratchDir::new("evict-recheck");
        let root = scratch.path();
        let _cache = LayerCache::new(root).expect("cache");
        boneli_private_dir::create(&root.join("blobs/sha256")).expect("blobs");
        let layers = root.join("layers/sha256");
        let bare = format!("{:064x}", 1);
        let orphan = format!("{:064x}", 2);
        std::fs::create_dir(layers.join(&bare)).expect("bare");
        std::fs::write(layers.join(format!("{orphan}.stats")), SIDECAR).expect("orphan");
        let committing = layers.clone();
        BEFORE_LOCK.with(|seam| {
            *seam.borrow_mut() = Some(Box::new(move |hex: &str| {
                let tree = committing.join(hex);
                if !tree.exists() {
                    std::fs::create_dir(&tree).expect("commit the tree");
                }
                std::fs::write(committing.join(format!("{hex}.stats")), SIDECAR)
                    .expect("commit the sidecar");
            }));
        });
        let report = trim(root, u64::MAX, far()).expect("trim");
        BEFORE_LOCK.with(|seam| *seam.borrow_mut() = None);
        assert_eq!(report.removed_layers, 0, "{report:?}");
        for hex in [&bare, &orphan] {
            assert!(layers.join(hex).is_dir(), "{hex} went");
            assert!(
                layers.join(format!("{hex}.stats")).is_file(),
                "{hex}'s sidecar went"
            );
        }
    }

    const SIDECAR: &str = "bytes 1\nentries 0\nskipped-devices 0\n";

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// A ustar archive of `entries`: a directory where the data is `None`.
    fn tar(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in entries {
            let mut h = [0u8; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            let mode: &[u8] = if data.is_some() {
                b"0000644"
            } else {
                b"0000755"
            };
            h[100..107].copy_from_slice(mode);
            h[108..115].copy_from_slice(b"0000000");
            h[116..123].copy_from_slice(b"0000000");
            let len = data.map_or(0, <[u8]>::len);
            h[124..135].copy_from_slice(format!("{len:011o}").as_bytes());
            h[136..147].copy_from_slice(b"00000000000");
            h[156] = if data.is_some() { b'0' } else { b'5' };
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            h[148..156].fill(b' ');
            let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
            h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            out.extend_from_slice(&h);
            if let Some(data) = data {
                out.extend_from_slice(data);
                out.resize(out.len().div_ceil(512) * 512, 0);
            }
        }
        out.resize(out.len() + 1024, 0);
        out
    }

    /// Every path under `top` with what it is: a directory, or a file with
    /// its contents.
    fn snapshot(top: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        let mut todo = vec![top.to_path_buf()];
        while let Some(dir) = todo.pop() {
            for entry in std::fs::read_dir(&dir).expect("list") {
                let path = entry.expect("entry").path();
                let rel = path.strip_prefix(top).expect("under top").to_path_buf();
                if path.is_dir() {
                    out.push((rel, None));
                    todo.push(path);
                } else {
                    out.push((rel, Some(std::fs::read(&path).expect("read"))));
                }
            }
        }
        out.sort();
        out
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .expect("list")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// The child: holds an owner lock of its own on `root`, then trims to a
    /// budget of 1 or sweeps, and exits at the step `EXIT_AT` names.
    fn child(root: &Path) {
        let _cache = LayerCache::new(root).expect("cache");
        let step = std::env::var(EXIT_AT).expect("step");
        if step.starts_with("sweep-") {
            sweep(root, &Judge::current().expect("judge")).expect("sweep");
        } else {
            trim(root, 1, far()).expect("trim");
        }
    }

    /// The acceptance of #56: an eviction interrupted at any point leaves
    /// the store consistent. A child process exits (`process::exit`, no
    /// destructor) at each step of D7, at each of the two document steps
    /// and at each step of the sweep's take-over (D1). After every exit
    /// every listed layer has its sidecar and the tree it was committed
    /// with; the next `open` (sweep, then trim) leaves no `.tmp-` name, no
    /// orphan sidecar, `.type` or lock file and no owner lock but its own;
    /// and the layer unpacks again.
    #[test]
    fn interrupted_eviction_at_every_step() {
        if let Some(root) = std::env::var_os(ROOT) {
            child(Path::new(&root));
            return;
        }
        let bytes = tar(&[
            ("etc/", None),
            ("etc/conf", Some(b"conf\n")),
            ("bin", Some(b"\x7fELF")),
        ]);
        let id = Sha256::digest(&bytes);
        let limits = Limits::new(1 << 20, 1 << 20, 64, 1 << 10, 16).expect("limits");
        for step in Step::ALL {
            let scratch = ScratchDir::new("evict-step");
            let root = scratch.path();
            let cache = LayerCache::new(root).expect("cache");
            let unpack = || {
                cache
                    .unpack(
                        &cache.pin(&id).expect("pin"),
                        Compression::None,
                        &bytes[..],
                        &mut Budget::new(limits.clone()),
                    )
                    .expect("unpack")
            };
            unpack();
            let layer = cache.layer_path(&id);
            let original = snapshot(&layer);
            assert_eq!(original.len(), 3, "{original:?}");
            // A document with its type, older than the layer: the trim
            // evicts it first.
            let blobs = root.join("blobs/sha256");
            boneli_private_dir::create(&blobs).expect("blobs");
            let doc = blobs.join(format!("{:064x}", 7));
            std::fs::write(&doc, b"{}").expect("doc");
            std::fs::write(blobs.join(format!("{:064x}.type", 7)), b"").expect("type");
            std::fs::File::open(&doc)
                .and_then(|f| f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)))
                .expect("old");
            // A dead owner with a free lock file and two names, for the
            // sweep's steps.
            let mine = Owner::current().expect("owner").token();
            let mut fields: Vec<&str> = mine.split('.').collect();
            fields[1] = "00000000000000000001";
            let dead = fields.join(".");
            assert!(Owner::of_token(&dead).is_some());
            std::fs::write(root.join("locks/owners").join(&dead), b"").expect("lock");
            let staged = root
                .join("layers/sha256")
                .join(format!(".tmp-{dead}.{:020}", 1));
            std::fs::create_dir_all(staged.join("d")).expect("staged");
            std::fs::write(staged.join("d/f"), b"x").expect("staged file");
            std::fs::write(blobs.join(format!(".tmp-{dead}.{:020}", 2)), b"x").expect("blob");

            let out = Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "evict::tests::interrupted_eviction_at_every_step",
                    "--test-threads=1",
                ])
                .env(EXIT_AT, step.name())
                .env(ROOT, root)
                .output()
                .expect("spawn the child");
            assert_eq!(
                out.status.code(),
                Some(EXITED),
                "{step:?}: not reached: {out:?}"
            );

            // Listed means complete.
            if std::fs::symlink_metadata(&layer).is_ok() {
                assert!(
                    cache.cached(&id).expect("sidecar").is_some(),
                    "{step:?}: listed without a sidecar"
                );
                assert_eq!(
                    snapshot(&layer),
                    original,
                    "{step:?}: a listed layer changed"
                );
            }

            // A tree is removed only after its lock is released (D3): up
            // to step 6 the renamed tree is still there, whole, under a
            // `.tmp-` name; so are the dead owner's names once the sweep
            // took them over.
            let temps = |dir: &Path| -> Vec<PathBuf> {
                names(dir)
                    .into_iter()
                    .filter(|n| n.starts_with(".tmp-") && !n.contains(&dead))
                    .map(|n| dir.join(n))
                    .collect()
            };
            let layers = root.join("layers/sha256");
            match step {
                Step::Renamed | Step::Synced | Step::SidecarRemoved | Step::Released => {
                    let moved = temps(&layers);
                    assert_eq!(moved.len(), 1, "{step:?}: {moved:?}");
                    assert_eq!(
                        snapshot(&moved[0]),
                        original,
                        "{step:?}: removed under the lock"
                    );
                }
                Step::SweepRenamed | Step::SweepReleased => {
                    let moved = temps(&layers);
                    assert_eq!(moved.len(), 1, "{step:?}: {moved:?}");
                    assert!(
                        moved[0].join("d/f").is_file(),
                        "{step:?}: removed under the lock"
                    );
                    assert_eq!(temps(&blobs).len(), 1, "{step:?}");
                    let lock = root.join("locks/owners").join(&dead);
                    assert_eq!(
                        lock.exists(),
                        step == Step::SweepRenamed,
                        "{step:?}: the dead owner's lock file"
                    );
                }
                _ => {}
            }

            // The next open.
            sweep(root, &Judge::current().expect("judge")).expect("sweep");
            trim(root, u64::MAX, far()).expect("trim");
            for dir in [&layers, &blobs] {
                let dots: Vec<String> = names(dir)
                    .into_iter()
                    .filter(|n| n.starts_with('.'))
                    .collect();
                assert!(
                    dots.is_empty(),
                    "{step:?}: {} keeps {dots:?}",
                    dir.display()
                );
            }
            let listed = names(&layers);
            for name in &listed {
                if let Some(h) = name.strip_suffix(".stats") {
                    assert!(listed.iter().any(|n| n == h), "{step:?}: orphan {name}");
                }
            }
            for name in names(&blobs) {
                if let Some(h) = name.strip_suffix(".type") {
                    assert!(blobs.join(h).is_file(), "{step:?}: orphan {name}");
                }
            }
            for name in names(&root.join("locks/sha256")) {
                assert!(listed.contains(&name), "{step:?}: orphan lock {name}");
            }
            assert_eq!(
                names(&root.join("locks/owners")),
                std::slice::from_ref(&mine),
                "{step:?}"
            );

            // And it unpacks again.
            if std::fs::symlink_metadata(&layer).is_err() {
                unpack();
            }
            assert_eq!(snapshot(&layer), original, "{step:?}");
            assert!(cache.cached(&id).expect("sidecar").is_some(), "{step:?}");
        }
    }
}
