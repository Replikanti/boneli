//! The layer cache (ADR-009, D8): one directory per layer, keyed by its
//! `diff_id`, under `<root>/layers/sha256/<hex>`, with a sidecar
//! `<hex>.stats` next to it.
//!
//! A layer is unpacked into `<root>/layers/sha256/.tmp-<owner>.<n>/` while
//! its uncompressed stream is hashed, where `<owner>` names this process by
//! the kernel's boot id, its PID and time namespaces, pid and start time
//! ([`Owner`]); lookups use hex names
//! only, so they never see a dot name. On a `diff_id` match the sidecar is written
//! (to a staged file, then renamed), and then the directory is renamed to
//! its hex name: that rename, within one directory, is the commit point.
//! One `syncfs` before the renames and an `fsync` of `layers/sha256/` after
//! each make the commit durable. A mismatch or an error removes the
//! temporary tree. When another store committed the same layer first, its
//! directory stays and this one is discarded; the same `diff_id` means the
//! same bytes, so both trees are equal.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::Error;
use crate::limits::Budget;
use crate::unpack::{Compression, LayerStats, unpack};

/// The layer cache under a store root.
#[derive(Debug, Clone)]
pub struct LayerCache {
    root: PathBuf,
}

static NEXT: AtomicU64 = AtomicU64::new(0);

fn hex(digest: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

fn cache_err(path: &Path, source: io::Error) -> Error {
    Error::Cache {
        path: path.to_path_buf(),
        source,
    }
}

/// A temporary tree being unpacked, with the descriptor `syncfs` runs on.
struct Staging {
    path: PathBuf,
    sidecar: PathBuf,
    /// Opened before anything is written into the tree, so the writeback
    /// error state it samples predates the layer's own writeback: an error
    /// another `syncfs` caller already saw is still reported to this one.
    dir: File,
}

impl LayerCache {
    /// The length of the name a layer is unpacked under before it is
    /// renamed to its 64 hex digits (D8). It is longer, so a committed
    /// layer's paths are shorter than the ones the unpacker created, and
    /// every one of them still fits `PATH_MAX`; a layer whose deepest path
    /// would not fit at the staging name is refused while it is unpacked.
    pub const STAGING_NAME_LEN: usize = TEMPORARY_NAME_LEN;

    /// The cache under `root`, creating `layers/sha256/` with mode `0o700`
    /// where it is missing. The store ([`crate::OciImageStore`]) checks the
    /// root itself: absolute, private, owned by the caller.
    ///
    /// Refuses a `layers/sha256/` where names alias each other (a
    /// case-insensitive or normalizing directory, D8): there a symlink
    /// named `A` replaces the directory `a`. Probed by creating one name
    /// and looking up its case-folded and its decomposed form. Probe names
    /// carry the owner (boot id, PID and time namespaces, pid, start time)
    /// and a
    /// counter, and
    /// a name that exists is skipped, never removed here, so a crashed
    /// process's leftover blocks no later one; the store removes it once
    /// its owner is gone.
    pub fn new(root: &Path) -> Result<LayerCache, Error> {
        let layers = root.join("layers").join("sha256");
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&layers)
            .map_err(|e| cache_err(&layers, e))?;
        let owner = Owner::current()?;
        for (stem, alias_stem) in [
            (".probe-case-", ".PROBE-CASE-"),
            (".probe-\u{e9}-", ".probe-e\u{301}-"),
        ] {
            let (probe, n) = create_probe(&layers, &owner, stem)?;
            let alias = layers.join(format!("{alias_stem}{}.{n}", owner.token()));
            let aliased = fs::symlink_metadata(&alias);
            fs::remove_file(&probe).map_err(|e| cache_err(&probe, e))?;
            match aliased {
                Ok(_) => return Err(Error::CaseInsensitive(layers)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(cache_err(&layers, e)),
            }
        }
        Ok(LayerCache {
            root: root.to_path_buf(),
        })
    }

    fn layers_dir(&self) -> PathBuf {
        self.root.join("layers").join("sha256")
    }

    /// Where the layer with `diff_id` lives once committed.
    pub fn layer_path(&self, diff_id: &[u8; 32]) -> PathBuf {
        self.layers_dir().join(hex(diff_id))
    }

    fn sidecar_path(&self, diff_id: &[u8; 32]) -> PathBuf {
        self.layers_dir().join(format!("{}.stats", hex(diff_id)))
    }

    /// The totals of a committed layer from its sidecar, `None` if the
    /// layer is not in the cache.
    pub fn cached(&self, diff_id: &[u8; 32]) -> Result<Option<LayerStats>, Error> {
        let path = self.layer_path(diff_id);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => return Err(Error::Sidecar(path)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(cache_err(&path, e)),
        }
        let sidecar = self.sidecar_path(diff_id);
        let text = fs::read(&sidecar).map_err(|e| cache_err(&sidecar, e))?;
        let (bytes, entries, skipped_devices) =
            parse_sidecar(&text).ok_or_else(|| Error::Sidecar(sidecar.clone()))?;
        Ok(Some(LayerStats {
            diff_id: *diff_id,
            bytes,
            entries,
            skipped_devices,
        }))
    }

    /// Unpacks the layer `blob`, compressed as `compression`, checks it
    /// against `diff_id` and commits it durably. `budget` is charged only
    /// when the layer is committed (or was committed by another store); on
    /// every error it is left as it was.
    pub fn unpack(
        &self,
        diff_id: &[u8; 32],
        compression: Compression,
        blob: impl Read,
        budget: &mut Budget,
    ) -> Result<LayerStats, Error> {
        let staging = self.temporary()?;
        let mut trial = budget.clone();
        let result = self.unpack_into(&staging, diff_id, compression, blob, &mut trial);
        match &result {
            Ok(stats) => {
                // The committed tree may be another store's; its sidecar
                // holds the same totals for the same bytes.
                let mut charged = budget.clone();
                charged.charge(stats)?;
                *budget = charged;
            }
            Err(_) => {
                remove_tree(&staging.path);
                let _ = fs::remove_file(&staging.sidecar);
            }
        }
        result
    }

    /// A new, empty `layers/sha256/.tmp-<owner>.<n>` directory and its
    /// descriptor. The owner tells the store's cleanup whose tree it is.
    fn temporary(&self) -> Result<Staging, Error> {
        let name = temporary_name()?;
        let path = self.layers_dir().join(&name);
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| cache_err(&path, e))?;
        let dir = match File::open(&path) {
            Ok(dir) => dir,
            Err(e) => {
                let _ = fs::remove_dir(&path);
                return Err(cache_err(&path, e));
            }
        };
        Ok(Staging {
            sidecar: self.layers_dir().join(format!("{name}.stats")),
            path,
            dir,
        })
    }

    /// The commit (D8). Before any rename, one `syncfs` makes the layer's
    /// data, its directory entries and the staged sidecar durable. The
    /// sidecar is renamed into place and its directory synced before the
    /// layer is, so a committed layer always has its sidecar; the layer's
    /// rename, the commit point, is synced last. Both renames stay within
    /// `layers/sha256/`, so a directory's `..` is never rewritten and a
    /// read-only layer root needs no write permission lent to it.
    fn unpack_into(
        &self,
        staging: &Staging,
        diff_id: &[u8; 32],
        compression: Compression,
        blob: impl Read,
        budget: &mut Budget,
    ) -> Result<LayerStats, Error> {
        let stats = unpack(blob, compression, &staging.path, budget)?;
        if stats.diff_id != *diff_id {
            return Err(Error::DiffId {
                expected: format!("sha256:{}", hex(diff_id)),
                actual: format!("sha256:{}", hex(&stats.diff_id)),
            });
        }

        let text = format!(
            "bytes {}\nentries {}\nskipped-devices {}\n",
            stats.bytes, stats.entries, stats.skipped_devices
        );
        fs::write(&staging.sidecar, text).map_err(|e| cache_err(&staging.sidecar, e))?;
        boneli_sys::sync_filesystem(&staging.dir).map_err(|e| Error::Sys {
            path: staging.path.display().to_string(),
            source: e,
        })?;

        let layers = self.layers_dir();
        let sidecar = self.sidecar_path(diff_id);
        fs::rename(&staging.sidecar, &sidecar).map_err(|e| cache_err(&sidecar, e))?;
        sync_dir(&layers)?;

        let final_path = self.layer_path(diff_id);
        match fs::rename(&staging.path, &final_path) {
            Ok(()) => {
                sync_dir(&layers)?;
                Ok(stats)
            }
            Err(_) if final_path.is_dir() => {
                // Another store committed this layer first.
                remove_tree(&staging.path);
                self.cached(diff_id)?
                    .ok_or_else(|| Error::Sidecar(self.sidecar_path(diff_id)))
            }
            Err(e) => Err(cache_err(&final_path, e)),
        }
    }
}

/// A new temporary name, `.tmp-<owner>.<n>`: a dot name, so lookups by hex
/// never see it, and one the store's cleanup can attribute to its owner
/// (D8). The registry client stages blobs under such names too. Its length
/// is fixed at [`TEMPORARY_NAME_LEN`], more than a committed layer's 64 hex
/// digits, so a tree that fit `PATH_MAX` while it was unpacked still fits
/// once it is renamed to its hex name.
pub(crate) fn temporary_name() -> Result<String, Error> {
    let owner = Owner::current()?;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    Ok(format!(".tmp-{}.{n:020}", owner.token()))
}

/// A new name `<stem><owner>.<n>` for a probe the store creates itself;
/// `stem` is one of [`OWNED_PREFIXES`].
pub(crate) fn owned_name(stem: &str) -> Result<String, Error> {
    let owner = Owner::current()?;
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    Ok(format!("{stem}{}.{n:020}", owner.token()))
}

/// The length of every [`temporary_name`]: `.tmp-`, the 106 characters of
/// an owner token, a dot and a 20-digit counter.
pub(crate) const TEMPORARY_NAME_LEN: usize = 5 + OWNER_TOKEN_LEN + 1 + 20;

// A committed layer is named by 64 hex digits; its staging name is longer.
const _: () = assert!(TEMPORARY_NAME_LEN > 64);

/// The length of [`Owner::token`]: 32 + 1 + 20 + 1 + 20 + 1 + 10 + 1 + 20.
const OWNER_TOKEN_LEN: usize = 106;

/// The prefixes of the dot names this crate creates in `layers/sha256/`
/// and `blobs/sha256/`, each followed by an owner token: staging trees,
/// staged sidecars and blobs, and the probes of [`LayerCache::new`] and
/// the store.
pub(crate) const OWNED_PREFIXES: [&str; 5] = [
    ".tmp-",
    ".probe-case-",
    ".probe-\u{e9}-",
    ".probe-wh-",
    ".probe-opq-",
];

/// The process that owns a temporary name (D8): the kernel's boot id, its
/// PID namespace (the inode of `/proc/thread-self/ns/pid`), its time
/// namespace (the inode of `/proc/thread-self/ns/time`), its pid in the PID namespace and
/// its start time in clock ticks since boot, as its time namespace shows
/// it: `/proc/<pid>/stat` shifts start times by the boottime offset of
/// the reader's time namespace, so only a reader in the same one reads
/// the start time the owner recorded. The pid alone
/// does not identify a process: two runners in different PID namespaces
/// can share a store and have the same pid, and a pid is reused once its
/// process is gone. Nor does the namespace inode identify a host: every
/// host's initial PID namespace has the same one, so two hosts sharing a
/// root over a network filesystem tell each other apart by the boot id,
/// which also changes on every reboot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Owner {
    boot: u128,
    pidns: u64,
    timens: u64,
    pid: u32,
    start: u64,
}

/// The time namespace an owner records on a kernel built without time
/// namespaces, which has no `ns/time` entry and shifts no start time.
const NO_TIME_NAMESPACE: u64 = 0;

/// The namespace links of the calling thread. Not `/proc/self/ns`:
/// `/proc/self` names the thread-group leader, and once the main thread has
/// exited while others run, the kernel has cleared its namespaces, so its
/// `ns/time` link fails with `ENOENT` on a kernel that has time namespaces
/// (round-3 review of #60). A running thread's own links always read, and
/// a thread group shares its PID and time namespaces: `setns` into a time
/// namespace needs a single-threaded caller, and a PID namespace is never
/// a thread's own. `tests/exited_main_thread.rs` checks these kernel facts
/// on a real process whose main thread has exited (#35).
const OWN_NAMESPACES: &str = "/proc/thread-self/ns";

/// The time namespace an owner records when it cannot read its own. No
/// namespace inode equals it, and a judge that records it judges no owner,
/// so the names of such an owner are never judged, by anyone.
const UNREADABLE_TIME_NAMESPACE: u64 = u64::MAX;

/// Whether the owner of a temporary name is alive, as far as this process
/// can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Liveness {
    /// It runs, or a process with its pid and start time does.
    Alive,
    /// It is gone: no process has its pid in this PID namespace, or the one
    /// that has it started at another time.
    Dead,
    /// Nothing can be concluded, so its names are left alone: it lives in
    /// another PID namespace, whose processes this one may not see, in
    /// another time namespace, whose start times read differently here, or
    /// on another host or an earlier boot (another boot id); or the
    /// `/proc` this process reads is not its own PID namespace's, or one of
    /// the two cannot read its time namespace or boot id.
    Unknown,
}

/// What this process judges the liveness of owners from (D8): its own
/// identity, and whether the `/proc` it reads numbers processes the way
/// its own PID namespace does. A process in a PID namespace whose `/proc`
/// was mounted for another one (`unshare -pf` without `--mount-proc`) has
/// pid 1 while `/proc/1` is the host's init, so every pid lookup there
/// names the wrong process.
pub(crate) struct Judge {
    me: Owner,
    own_proc: bool,
}

impl Judge {
    /// This process, and its `/proc` as it is now.
    pub(crate) fn current() -> Result<Judge, Error> {
        let pid = std::process::id();
        let link = fs::read_link("/proc/self").ok();
        let status = fs::read("/proc/self/status").ok();
        Ok(Judge {
            me: Owner::current()?,
            own_proc: proc_is_own(
                link.as_deref().and_then(Path::to_str),
                status.as_deref(),
                pid,
            ),
        })
    }
}

/// Whether a `/proc` belongs to the PID namespace of the process `pid`
/// reading it, from that `/proc`'s `self` link and `self/status`: the link
/// must read `pid`, and the `NSpid` line, which lists the process's pid in
/// the namespace the `/proc` was mounted for and in every namespace below
/// it down to the process's own, must hold exactly `pid`. A `/proc` of an
/// ancestor namespace lists more than one pid; one of an unrelated
/// namespace has no `self`. Anything unreadable counts as not its own.
fn proc_is_own(self_link: Option<&str>, status: Option<&[u8]>, pid: u32) -> bool {
    let pid = pid.to_string();
    if self_link != Some(pid.as_str()) {
        return false;
    }
    let Some(status) = status.and_then(|s| std::str::from_utf8(s).ok()) else {
        return false;
    };
    let mut lines = status.lines().filter_map(|l| l.strip_prefix("NSpid:"));
    match (lines.next(), lines.next()) {
        (Some(ids), None) => ids.split_ascii_whitespace().eq([pid.as_str()]),
        _ => false,
    }
}

impl Owner {
    /// This process.
    pub(crate) fn current() -> Result<Owner, Error> {
        let ns = Path::new(OWN_NAMESPACES);
        Ok(Owner {
            boot: own_boot_id(),
            pidns: own_pid_namespace(ns)?,
            timens: own_time_namespace(ns),
            pid: std::process::id(),
            start: own_start_time()?,
        })
    }

    /// `<boot>.<pidns>.<timens>.<pid>.<start>`: the boot id as 32
    /// lower-case hex digits, then zero-padded decimals of fixed widths
    /// (20, 20, 10 and 20 digits), so every name built on it has one
    /// length.
    pub(crate) fn token(&self) -> String {
        format!(
            "{:032x}.{:020}.{:020}.{:010}.{:020}",
            self.boot, self.pidns, self.timens, self.pid, self.start
        )
    }

    /// The owner of a name `<prefix><token>.<n>` or
    /// `<prefix><token>.<n>.stats`, with a prefix of [`OWNED_PREFIXES`];
    /// `None` for any other name.
    pub(crate) fn of_name(name: &str) -> Option<Owner> {
        let rest = OWNED_PREFIXES
            .iter()
            .find_map(|prefix| name.strip_prefix(prefix))?;
        let mut fields = rest.split('.');
        let boot = fields.next().filter(|f| is_boot_hex(f))?;
        let boot = u128::from_str_radix(boot, 16).ok()?;
        let mut number = |width: usize| -> Option<u64> {
            let f = fields.next()?;
            (f.len() == width && f.bytes().all(|b| b.is_ascii_digit()))
                .then(|| f.parse().ok())
                .flatten()
        };
        let pidns = number(20)?;
        let timens = number(20)?;
        let pid = u32::try_from(number(10)?).ok()?;
        let start = number(20)?;
        number(20)?;
        match (fields.next(), fields.next()) {
            (None, _) | (Some("stats"), None) => Some(Owner {
                boot,
                pidns,
                timens,
                pid,
                start,
            }),
            _ => None,
        }
    }

    /// Whether this owner is alive, as `judge` sees it. In the judge's
    /// boot, PID namespace and time namespace, through a `/proc` of that
    /// PID namespace, the pid and the start time decide; anywhere else
    /// nothing does.
    pub(crate) fn liveness(&self, judge: &Judge) -> Liveness {
        if !self.judged_by(judge) {
            return Liveness::Unknown;
        }
        let path = PathBuf::from(format!("/proc/{}/stat", self.pid));
        match fs::read(&path) {
            Ok(stat) if start_time_of(&stat) == Some(self.start) => Liveness::Alive,
            // A process whose stat cannot be read for another reason than
            // its absence is alive as far as anyone can tell.
            Ok(stat) if start_time_of(&stat).is_none() => Liveness::Alive,
            Ok(_) => Liveness::Dead,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Liveness::Dead,
            Err(_) => Liveness::Alive,
        }
    }

    /// Whether `judge` can tell this owner's liveness from its pid and
    /// start time: same boot id, same PID namespace read through its own
    /// `/proc`, and same time namespace, which the judge could read.
    fn judged_by(&self, judge: &Judge) -> bool {
        self.boot == judge.me.boot
            && self.pidns == judge.me.pidns
            && self.timens == judge.me.timens
            && judge.me.timens != UNREADABLE_TIME_NAMESPACE
            && judge.own_proc
    }
}

/// How many probe names `create_probe` tries before it gives up.
const PROBE_ATTEMPTS: u32 = 1024;

/// Creates a new probe file `<stem><token>.<n>` in `layers` and returns it
/// with its `n`. A name that exists already is skipped, never removed here:
/// it is a leftover of a crashed process with the same identity, which the
/// store's cleanup removes once its owner is gone (D8).
pub(crate) fn create_probe(
    layers: &Path,
    owner: &Owner,
    stem: &str,
) -> Result<(PathBuf, String), Error> {
    for _ in 0..PROBE_ATTEMPTS {
        let n = format!("{:020}", NEXT.fetch_add(1, Ordering::Relaxed));
        let probe = layers.join(format!("{stem}{}.{n}", owner.token()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe)
        {
            Ok(_) => return Ok((probe, n)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(cache_err(&probe, e)),
        }
    }
    Err(cache_err(
        layers,
        io::Error::other("no free name for the case probe"),
    ))
}

/// Makes the entries of the directory `dir` durable.
fn sync_dir(dir: &Path) -> Result<(), Error> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| cache_err(dir, e))
}

/// `bytes N\nentries N\nskipped-devices N\n`, exactly.
fn parse_sidecar(text: &[u8]) -> Option<(u64, u64, u64)> {
    let text = std::str::from_utf8(text).ok()?;
    let mut lines = text.split_terminator('\n');
    let mut value = |key: &str| -> Option<u64> {
        let rest = lines.next()?.strip_prefix(key)?.strip_prefix(' ')?;
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        rest.parse().ok()
    };
    let parsed = (
        value("bytes")?,
        value("entries")?,
        value("skipped-devices")?,
    );
    (lines.next().is_none() && text.ends_with('\n')).then_some(parsed)
}

/// The start time of this process in clock ticks since boot, field 22 of
/// `/proc/self/stat`.
fn own_start_time() -> Result<u64, Error> {
    let path = Path::new("/proc/self/stat");
    let stat = fs::read(path).map_err(|e| cache_err(path, e))?;
    start_time_of(&stat).ok_or_else(|| cache_err(path, io::Error::other("unreadable start time")))
}

/// Field 22 of a `/proc/<pid>/stat` text, the start time.
fn start_time_of(stat: &[u8]) -> Option<u64> {
    // The command name may contain spaces and parentheses; the fields
    // after the last ')' start with field 3.
    let after = stat
        .iter()
        .rposition(|&b| b == b')')
        .and_then(|i| stat.get(i + 1..))?;
    let text = std::str::from_utf8(after).ok()?;
    text.split_ascii_whitespace()
        .nth(22 - 3)
        .and_then(|f| f.parse().ok())
}

/// The kernel's boot id, `/proc/sys/kernel/random/boot_id`: a UUID, random
/// per boot. Where it cannot be read (a `/proc` mounted with
/// `subset=pid`, systemd's `ProcSubset=pid`), a random id instead, which
/// no boot id equals ([`boot_id_or_random`]). Read once per process, so
/// every name of one process carries the same id.
fn own_boot_id() -> u128 {
    static BOOT: OnceLock<u128> = OnceLock::new();
    *BOOT.get_or_init(|| {
        let text = fs::read("/proc/sys/kernel/random/boot_id").ok();
        boot_id_or_random(text.as_deref(), random_u128)
    })
}

/// The version digit of a UUID in the `u128` of its 32 hex digits: the
/// 13th digit, the first of the third group.
const UUID_VERSION: u128 = 0xf << 76;

/// The boot id in `text`, or, where there is none, `random()` with its
/// UUID version digit cleared. The kernel makes every boot id a version 4
/// UUID, so a fallback id never equals one: no other process judges the
/// names of an owner that could not read its boot id (D8), and the
/// randomness keeps two such processes apart.
fn boot_id_or_random(text: Option<&[u8]>, random: impl FnOnce() -> u128) -> u128 {
    text.and_then(parse_boot_id)
        .unwrap_or_else(|| random() & !UUID_VERSION)
}

/// 128 random bits from std's `RandomState`, whose keys std draws from the
/// operating system's random source: two SipHash outputs under one
/// random key. Not for secrets; it keeps owner ids apart.
fn random_u128() -> u128 {
    use std::hash::BuildHasher;
    let state = std::collections::hash_map::RandomState::new();
    (u128::from(state.hash_one(0u8)) << 64) | u128::from(state.hash_one(1u8))
}

/// A boot id as the kernel prints it, `8-4-4-4-12` lower-case hex digits
/// and a newline.
fn parse_boot_id(text: &[u8]) -> Option<u128> {
    let text = std::str::from_utf8(text).ok()?.strip_suffix('\n')?;
    let groups: Vec<&str> = text.split('-').collect();
    let widths = groups.iter().map(|g| g.len());
    if !widths.eq([8, 4, 4, 4, 12]) {
        return None;
    }
    let hex = groups.concat();
    is_boot_hex(&hex)
        .then(|| u128::from_str_radix(&hex, 16).ok())
        .flatten()
}

/// 32 lower-case hex digits.
fn is_boot_hex(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The inode of this process's PID namespace, from the link `pid` in the
/// calling thread's namespace directory `ns`, which reads `pid:[<inode>]`.
fn own_pid_namespace(ns: &Path) -> Result<u64, Error> {
    let path = &ns.join("pid");
    let link = fs::read_link(path).map_err(|e| cache_err(path, e))?;
    link.to_str()
        .and_then(|l| l.strip_prefix("pid:["))
        .and_then(|l| l.strip_suffix(']'))
        .and_then(|l| l.parse().ok())
        .ok_or_else(|| cache_err(path, io::Error::other("unreadable PID namespace")))
}

/// The time namespace of the thread whose namespace directory is `ns`
/// ([`OWN_NAMESPACES`] for this one), by the rule of [`time_namespace_of`].
fn own_time_namespace(ns: &Path) -> u64 {
    time_namespace_of(
        fs::read_link(ns.join("time")),
        kernel_lacks_time_namespaces(ns),
    )
}

/// The time namespace in the link `ns/time`, which reads `time:[<inode>]`.
/// A link that fails with `ENOENT` is [`NO_TIME_NAMESPACE`] only when
/// `lacks` proves the kernel was built without time namespaces
/// ([`kernel_lacks_time_namespaces`]); without that proof, any other
/// failure, and a link that does not parse, it is
/// [`UNREADABLE_TIME_NAMESPACE`], whose owner nobody judges (D8).
fn time_namespace_of(link: io::Result<PathBuf>, lacks: bool) -> u64 {
    match link {
        Ok(link) => link
            .to_str()
            .and_then(|l| l.strip_prefix("time:["))
            .and_then(|l| l.strip_suffix(']'))
            .and_then(|l| l.parse().ok())
            .filter(|&ino| ino != NO_TIME_NAMESPACE && ino != UNREADABLE_TIME_NAMESPACE)
            .unwrap_or(UNREADABLE_TIME_NAMESPACE),
        Err(e) if e.kind() == io::ErrorKind::NotFound && lacks => NO_TIME_NAMESPACE,
        Err(_) => UNREADABLE_TIME_NAMESPACE,
    }
}

/// Whether the namespace directory `ns` of a running thread proves a
/// kernel without time namespaces: it is a directory and has no `time`
/// entry. `/proc/<pid>/ns/` lists exactly the namespace types the kernel
/// was built with, whether or not their links read, so a link that does
/// not read still has its entry (`tests/exited_main_thread.rs` checks that
/// on an exited main thread, #35). A missing or unreadable directory is no
/// proof.
fn kernel_lacks_time_namespaces(ns: &Path) -> bool {
    fs::symlink_metadata(ns).is_ok_and(|m| m.is_dir())
        && fs::symlink_metadata(ns.join("time")).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
}

/// Removes a temporary tree whose directories may have any final mode.
/// Best effort; the store removes what is left of dead processes when it
/// opens.
fn remove_tree(path: &Path) {
    let _ = remove_tree_bounded(path);
}

/// One directory on the way down: its path and the subdirectories still
/// to remove.
struct Level {
    path: PathBuf,
    subdirs: Vec<OsString>,
}

impl Level {
    /// Gives `path` `u+rwx` (final modes may be 0), lists it once, removes
    /// every entry that is not a directory, and keeps the names of the
    /// subdirectories. The listing's descriptor is closed when this
    /// returns.
    fn open(path: PathBuf) -> io::Result<Level> {
        let mode = fs::symlink_metadata(&path)?.permissions().mode() & 0o7777;
        if mode & 0o700 != 0o700 {
            fs::set_permissions(&path, Permissions::from_mode(mode | 0o700))?;
        }
        let mut subdirs = Vec::new();
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                subdirs.push(entry.file_name());
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(Level { path, subdirs })
    }
}

/// Removes `top` and everything under it and returns how many directories
/// it listed. It holds at most one directory descriptor at any time,
/// whatever the depth (std's `remove_dir_all` holds one per level), and
/// lists every directory exactly once, so a wide tree costs one pass. The
/// names of the subdirectories still to visit are kept in memory instead,
/// at most the tree's entry count. Paths are used throughout: every path
/// the unpacker created fits `PATH_MAX`.
pub(crate) fn remove_tree_bounded(top: &Path) -> io::Result<u64> {
    match fs::symlink_metadata(top) {
        Ok(m) if m.file_type().is_dir() => {}
        Ok(_) => return fs::remove_file(top).map(|()| 0),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    }
    let mut listings = 1;
    let mut chain = vec![Level::open(top.to_path_buf())?];
    while let Some(level) = chain.last_mut() {
        match level.subdirs.pop() {
            Some(name) => {
                let next = level.path.join(name);
                chain.push(Level::open(next)?);
                listings += 1;
            }
            None => {
                fs::remove_dir(&level.path)?;
                chain.pop();
            }
        }
    }
    Ok(listings)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use super::{
        Judge, Liveness, NO_TIME_NAMESPACE, OWN_NAMESPACES, OWNED_PREFIXES, Owner,
        TEMPORARY_NAME_LEN, UNREADABLE_TIME_NAMESPACE, UUID_VERSION, boot_id_or_random,
        kernel_lacks_time_namespaces, own_boot_id, own_start_time, parse_boot_id, parse_sidecar,
        proc_is_own, random_u128, temporary_name, time_namespace_of,
    };

    /// Every temporary name has one length, longer than a committed
    /// layer's 64 hex digits, so renaming a tree to its hex name never
    /// makes a path inside it longer (D8).
    #[test]
    fn temporary_names_are_longer_than_hex() {
        for _ in 0..3 {
            let name = temporary_name().expect("name");
            assert_eq!(name.len(), TEMPORARY_NAME_LEN, "{name}");
        }
    }

    /// Every owned name parses back to its owner; names with a missing,
    /// short, long or non-digit field, an unknown prefix or a suffix other
    /// than `.stats` carry no owner.
    #[test]
    fn owner_round_trips_through_names() {
        let me = Owner::current().expect("owner");
        let token = me.token();
        assert_eq!(token.len(), 106);
        for prefix in OWNED_PREFIXES {
            let name = format!("{prefix}{token}.{:020}", 7);
            assert_eq!(Owner::of_name(&name), Some(me), "{name}");
            assert_eq!(
                Owner::of_name(&format!("{name}.stats")),
                Some(me),
                "{name}.stats"
            );
        }
        let n = format!("{:020}", 7);
        for bad in [
            format!(".tmp-{token}"),
            format!(".tmp-{token}.7"),
            format!(".tmp-{token}.{n}.type"),
            format!(".tmp-{token}.{n}.stats.x"),
            format!(".tmp-{token}0.{n}"),
            format!(".TMP-{token}.{n}"),
            format!(".other-{token}.{n}"),
            format!(".tmp-{}.{n}", token.replacen('0', "x", 1)),
            format!(".tmp-{}.{n}", token.replacen('.', "-", 1)),
            ".tmp-1234.5678.0".to_owned(),
            format!(
                ".tmp-{:032x}.{:020}.{:020}.{:010}.{:020}.{n}",
                1,
                1,
                1,
                u64::from(u32::MAX) + 1,
                1
            ),
            // The format before the boot id, and the one before the time
            // namespace.
            format!(".tmp-{:020}.{:010}.{:020}.{n}", me.pidns, me.pid, me.start),
            format!(
                ".tmp-{:032x}.{:020}.{:010}.{:020}.{n}",
                me.boot, me.pidns, me.pid, me.start
            ),
            // A boot id in upper case, one digit short or long, with dashes.
            format!(".tmp-{}.{n}", token.replacen(&token[..1], "A", 1)),
            format!(".tmp-{}.{n}", &token[1..]),
            format!(".tmp-0{token}.{n}"),
            format!(".tmp-{}-{}.{n}", &token[..8], &token[8..]),
        ] {
            assert_eq!(Owner::of_name(&bad), None, "{bad}");
        }
    }

    /// This process is alive; its pid with another start time is a reused
    /// pid, so dead; a pid no process has is dead; an owner in another PID
    /// namespace or with another boot id cannot be judged, and through a
    /// `/proc` that is not this namespace's no owner can.
    #[test]
    fn liveness_rules() {
        let judge = Judge::current().expect("judge");
        assert!(judge.own_proc, "the test runs with its own /proc");
        let me = judge.me;
        assert_eq!(me.liveness(&judge), Liveness::Alive);
        let reused = Owner {
            start: me.start.wrapping_sub(1),
            ..me
        };
        assert_eq!(reused.liveness(&judge), Liveness::Dead);
        let mut child = std::process::Command::new("true").spawn().expect("spawn");
        let pid = child.id();
        child.wait().expect("wait");
        let gone = Owner { pid, ..me };
        assert_eq!(gone.liveness(&judge), Liveness::Dead);
        let foreign = Owner {
            pidns: me.pidns.wrapping_add(1),
            ..reused
        };
        assert_eq!(foreign.liveness(&judge), Liveness::Unknown);
        for other_boot in [me.boot ^ 1, me.boot ^ (1 << 127)] {
            for owner in [reused, gone, me] {
                let elsewhere = Owner {
                    boot: other_boot,
                    ..owner
                };
                assert_eq!(elsewhere.liveness(&judge), Liveness::Unknown);
            }
        }
        let blind = Judge {
            me,
            own_proc: false,
        };
        for owner in [reused, gone, me, foreign] {
            assert_eq!(owner.liveness(&blind), Liveness::Unknown, "{owner:?}");
        }
        // Another time namespace reads start times shifted (review of
        // #60): even this live process's own name is not judged there,
        // nor are a reused or a vanished pid.
        for other_timens in [
            me.timens.wrapping_add(1),
            NO_TIME_NAMESPACE,
            UNREADABLE_TIME_NAMESPACE,
        ] {
            if other_timens == me.timens {
                continue;
            }
            for owner in [reused, gone, me] {
                let shifted = Owner {
                    timens: other_timens,
                    ..owner
                };
                assert_eq!(shifted.liveness(&judge), Liveness::Unknown, "{shifted:?}");
            }
        }
    }

    /// The time-namespace rule of D8 on fixed identities, so it holds on a
    /// kernel with and one without time namespaces: equal namespaces are
    /// judged, another one is not, and a judge that could not read its
    /// own judges no owner, even one that recorded the same value.
    #[test]
    fn time_namespace_rules() {
        let judge = Judge::current().expect("judge");
        let me = judge.me;
        for timens in [NO_TIME_NAMESPACE, 4_026_531_834] {
            let judge = Judge {
                me: Owner { timens, ..me },
                own_proc: true,
            };
            let owner = Owner { timens, ..me };
            assert!(owner.judged_by(&judge), "{owner:?}");
            assert_eq!(owner.liveness(&judge), Liveness::Alive);
            let dead = Owner {
                start: me.start.wrapping_sub(1),
                ..owner
            };
            assert_eq!(dead.liveness(&judge), Liveness::Dead);
            for other in [NO_TIME_NAMESPACE, 4_026_531_834, 4_026_532_000] {
                if other != timens {
                    let elsewhere = Owner {
                        timens: other,
                        ..dead
                    };
                    assert!(!elsewhere.judged_by(&judge), "{elsewhere:?}");
                    assert_eq!(elsewhere.liveness(&judge), Liveness::Unknown);
                }
            }
        }
        let unreadable = Judge {
            me: Owner {
                timens: UNREADABLE_TIME_NAMESPACE,
                ..me
            },
            own_proc: true,
        };
        let dead = Owner {
            timens: UNREADABLE_TIME_NAMESPACE,
            start: me.start.wrapping_sub(1),
            ..me
        };
        assert!(!dead.judged_by(&unreadable));
        assert_eq!(dead.liveness(&unreadable), Liveness::Unknown);
    }

    /// The link `time:[<inode>]` gives the inode. A link that does not
    /// read (`ENOENT`) is a kernel without time namespaces only where the
    /// thread's `ns/` directory proves it has no `time` entry; any other
    /// failure, a malformed link and an inode equal to one of the two
    /// markers are unreadable.
    #[test]
    fn time_namespace_link() {
        let link = |s: &str| Ok(PathBuf::from(s));
        for lacks in [false, true] {
            assert_eq!(
                time_namespace_of(link("time:[4026531834]"), lacks),
                4_026_531_834
            );
        }
        assert_eq!(
            time_namespace_of(Err(io::ErrorKind::NotFound.into()), true),
            NO_TIME_NAMESPACE
        );
        // The round-3 review of #60: a process whose main thread has exited
        // reads `ENOENT` for the leader's `ns/time` on a kernel that has
        // time namespaces. Without proof that the kernel lacks them, that
        // is unreadable, never 0.
        assert_eq!(
            time_namespace_of(Err(io::ErrorKind::NotFound.into()), false),
            UNREADABLE_TIME_NAMESPACE
        );
        for err in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::Other,
        ] {
            for lacks in [false, true] {
                assert_eq!(
                    time_namespace_of(Err(err.into()), lacks),
                    UNREADABLE_TIME_NAMESPACE,
                    "{err:?} {lacks}"
                );
            }
        }
        for bad in [
            "pid:[4026531834]",
            "time:4026531834",
            "time:[4026531834",
            "time:[]",
            "time:[-1]",
            "time:[0x10]",
            "time:[0]",
            "time:[18446744073709551615]",
            "time:[18446744073709551616]",
            "time_for_children:[4026531834]",
        ] {
            for lacks in [false, true] {
                assert_eq!(
                    time_namespace_of(link(bad), lacks),
                    UNREADABLE_TIME_NAMESPACE,
                    "{bad}"
                );
            }
        }
        // This process reads its own, or runs on a kernel without them.
        let me = Owner::current().expect("owner");
        assert_ne!(me.timens, UNREADABLE_TIME_NAMESPACE);
        assert_eq!(
            me.timens == NO_TIME_NAMESPACE,
            std::fs::symlink_metadata("/proc/thread-self/ns/time").is_err()
        );
    }

    /// The proof that a kernel has no time namespaces: a directory without
    /// a `time` entry. A `time` entry, even one whose link does not read,
    /// a missing directory and a file are no proof.
    #[test]
    fn time_namespace_absence_needs_proof() {
        let scratch = crate::scratch::ScratchDir::new("timens");
        let ns = scratch.path().join("ns");
        assert!(!kernel_lacks_time_namespaces(&ns), "missing directory");
        std::fs::write(&ns, b"").expect("file");
        assert!(!kernel_lacks_time_namespaces(&ns), "a file");
        std::fs::remove_file(&ns).expect("remove");
        std::fs::create_dir(&ns).expect("dir");
        std::os::unix::fs::symlink("pid:[4026531836]", ns.join("pid")).expect("pid");
        assert!(kernel_lacks_time_namespaces(&ns), "no time entry");
        // A directory that cannot be searched answers `EACCES`, not
        // `ENOENT`, for every entry: no proof (unless the tests run with
        // `CAP_DAC_OVERRIDE`, which searches anyway).
        let mode = |m| std::fs::set_permissions(&ns, std::fs::Permissions::from_mode(m));
        mode(0o600).expect("chmod");
        if std::fs::symlink_metadata(ns.join("pid")).is_err() {
            assert!(!kernel_lacks_time_namespaces(&ns), "unsearchable");
        }
        mode(0o700).expect("chmod");
        std::os::unix::fs::symlink("time:[4026531834]", ns.join("time")).expect("time");
        assert!(!kernel_lacks_time_namespaces(&ns), "a time entry");
        assert_eq!(
            kernel_lacks_time_namespaces(Path::new(OWN_NAMESPACES)),
            std::fs::symlink_metadata("/proc/thread-self/ns/time").is_err()
        );
    }

    /// The owner reads the namespace links of the calling thread, not of
    /// the thread-group leader behind `/proc/self`, whose links stop
    /// reading once the main thread has exited (round-3 review of #60).
    #[test]
    fn namespaces_are_read_from_the_calling_thread() {
        let own = std::thread::spawn(|| std::fs::canonicalize(OWN_NAMESPACES))
            .join()
            .expect("thread")
            .expect("canonical");
        let leader = std::fs::canonicalize("/proc/self/ns").expect("leader");
        assert_ne!(own, leader);
        let parts: Vec<_> = own.components().collect();
        let n = parts.len();
        assert!(
            n >= 3 && parts[n - 3].as_os_str() == "task" && parts[n - 1].as_os_str() == "ns",
            "{}",
            own.display()
        );
    }

    /// `/proc` is this process's own only if `self` reads its pid and
    /// `NSpid` lists exactly that pid: the `unshare -pf` case of the #60
    /// review (`self` reads the host pid, `NSpid` two pids), a `/proc` of
    /// an ancestor namespace where the pids happen to agree, a missing or
    /// repeated `NSpid` line and unreadable files all count as foreign.
    #[test]
    fn proc_view_rules() {
        let own = b"Name:\tx\nPid:\t42\nNSpid:\t42\nNSsid:\t1\n";
        assert!(proc_is_own(Some("42"), Some(own), 42));
        for (link, status) in [
            (Some("2550293"), &b"Pid:\t2550293\nNSpid:\t2550293\t1\n"[..]),
            (Some("42"), b"Pid:\t42\nNSpid:\t42\t42\n"),
            (Some("42"), b"Pid:\t42\nNSpid:\t42\t1\n"),
            (Some("42"), b"Pid:\t42\n"),
            (Some("42"), b"NSpid:\t42\nNSpid:\t42\n"),
            (Some("42"), b"NSpid:\n"),
            (Some("42"), b"NSpid:\t420\n"),
            (Some("42"), b"NSpid:\t4\n"),
            (Some("42"), b"NSpid:\t42\xff\n"),
            (Some("4"), own),
            (Some("042"), own),
            (Some("self"), own),
            (None, own),
        ] {
            assert!(!proc_is_own(link, Some(status), 42), "{link:?} {status:?}");
        }
        assert!(!proc_is_own(Some("42"), None, 42));
        let judge = Judge::current().expect("judge");
        assert!(judge.own_proc, "the test runs with its own /proc");
    }

    #[test]
    fn boot_id_format() {
        assert_eq!(
            parse_boot_id(b"0123abcd-4567-89ef-0123-456789abcdef\n"),
            Some(0x0123abcd_4567_89ef_0123_456789abcdef)
        );
        for bad in [
            &b"0123abcd-4567-89ef-0123-456789abcdef"[..],
            b"0123ABCD-4567-89ef-0123-456789abcdef\n",
            b"0123abcd4567-89ef-0123-456789abcdef-\n",
            b"0123abcd-4567-89ef-0123-456789abcde\n",
            b"0123abcd-4567-89ef-0123-456789abcdef0\n",
            b"0123abcd-4567-89ef-0123-456789abcdeg\n",
            b"0123abcd-4567-89ef-0123-456789abcdef\n\n",
            b"+123abcd-4567-89ef-0123-456789abcdef\n",
            b"",
        ] {
            assert_eq!(parse_boot_id(bad), None, "{bad:?}");
        }
        let a = own_boot_id();
        assert_eq!(own_boot_id(), a);
        // The kernel's boot ids are version 4 UUIDs, which the fallback
        // relies on; the test host reads its own.
        let text = std::fs::read("/proc/sys/kernel/random/boot_id").expect("boot id");
        assert_eq!(parse_boot_id(&text), Some(a));
        assert_eq!(a & UUID_VERSION, 4 << 76, "{a:032x}");
    }

    /// The second review of #60: an unreadable or malformed boot id no
    /// longer fails `open`. It is replaced by a random id with its UUID
    /// version digit cleared, so it never equals a kernel's boot id, and
    /// two fallbacks differ; a readable boot id is used as it is.
    #[test]
    fn boot_id_fallback() {
        let id = b"0123abcd-4567-49ef-8123-456789abcdef\n";
        assert_eq!(
            boot_id_or_random(Some(id), || unreachable!("the boot id was read")),
            0x0123abcd_4567_49ef_8123_456789abcdef
        );
        for text in [None, Some(&b""[..]), Some(&id[..id.len() - 1])] {
            assert_eq!(
                boot_id_or_random(text, || u128::MAX),
                0xffff_ffff_ffff_0fff_ffff_ffff_ffff_ffff,
                "{text:?}"
            );
            // Only the version digit is cleared.
            let fallback = boot_id_or_random(text, || 0x4000_0000_0000_4000_0000_0000_0000_0042);
            assert_eq!(fallback, 0x4000_0000_0000_0000_0000_0000_0000_0042);
            assert_eq!(fallback & UUID_VERSION, 0);
        }
        let a = boot_id_or_random(None, random_u128);
        let b = boot_id_or_random(None, random_u128);
        assert_ne!(a, b);
        assert_ne!(a, 0);
        assert_eq!(a & UUID_VERSION, 0);
        // An owner with a fallback id is never judged by a process that
        // read its boot id, nor the other way round.
        let judge = Judge::current().expect("judge");
        let me = judge.me;
        let fallback = Owner { boot: a, ..me };
        assert_eq!(fallback.liveness(&judge), Liveness::Unknown);
        let blind = Judge {
            me: fallback,
            own_proc: true,
        };
        assert_eq!(me.liveness(&blind), Liveness::Unknown);
        assert_eq!(fallback.liveness(&blind), Liveness::Alive);
    }

    /// Every directory is listed once, so removing a wide tree is linear:
    /// 1,000 sibling directories take 1,001 listings, not one listing of
    /// the parent per child (review measured 28 s for 80,000).
    #[test]
    fn removal_lists_each_directory_once() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = crate::scratch::ScratchDir::new("remove");
        let root = scratch.path().join("tree");
        std::fs::create_dir(&root).expect("root");
        for i in 0..1000 {
            let d = root.join(format!("d{i}"));
            std::fs::create_dir(&d).expect("dir");
            std::fs::write(d.join("f"), b"x").expect("file");
        }
        std::fs::set_permissions(root.join("d7"), std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        let listings = super::remove_tree_bounded(&root).expect("removed");
        assert_eq!(listings, 1001);
        assert!(!root.exists());
    }

    #[test]
    fn sidecar_format() {
        assert_eq!(
            parse_sidecar(b"bytes 10\nentries 2\nskipped-devices 0\n"),
            Some((10, 2, 0))
        );
        for bad in [
            &b""[..],
            b"bytes 10\nentries 2\nskipped-devices 0",
            b"bytes 10\nentries 2\n",
            b"bytes +10\nentries 2\nskipped-devices 0\n",
            b"bytes 10\nentries 2\nskipped-devices 0\n\n",
            b"entries 2\nbytes 10\nskipped-devices 0\n",
            b"bytes  10\nentries 2\nskipped-devices 0\n",
            b"bytes 99999999999999999999\nentries 2\nskipped-devices 0\n",
        ] {
            assert_eq!(parse_sidecar(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn start_time_is_stable() {
        let a = own_start_time().expect("start time");
        assert_eq!(own_start_time().expect("start time"), a);
    }
}
