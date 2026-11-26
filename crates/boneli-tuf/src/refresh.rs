//! The refresh (ADR-033, items 5 to 9): the TUF workflow over the
//! repository's files and the trust directory, which installs
//! `trusted_root.json` only after every step has verified.

use std::fmt;
use std::path::Path;

use boneli_https::{Dial, Sha256};
use boneli_sigstore::TrustedRoot;

use crate::fetch::{self, Fetched, Size, Timeouts};
use crate::repository::Repository;
use crate::state::{self, OpenError, StateError, TrustDir};
use crate::{
    Error, MAX_ROOT_BYTES, MAX_ROOT_ROTATIONS, MAX_SNAPSHOT_BYTES, MAX_TARGETS_BYTES,
    MAX_TIMESTAMP_BYTES, TrustedSet,
};

/// The target the refresh installs.
const TARGET: &str = "trusted_root.json";

/// What the remedy for a trust directory that cannot go on is.
const REMEDY: &str = "remove the trust directory's tuf/ to bootstrap again from the initial root";

/// The step a refresh failed at (ADR-033, item 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The trust directory broke a rule of ADR-021 or the `tuf` rule of
    /// ADR-041 (it is, or lies inside, a directory named `tuf`, or it
    /// holds another trust directory's state), its lock could not be
    /// taken ("busy" while another refresh holds it), or it could not be
    /// opened; or, later in the run, the trust directory, its `tuf/` or
    /// its lock was removed or replaced, so the refresh stopped writing
    /// there.
    Lock,
    /// The initial root does not hash to its pin, the pin is malformed,
    /// the root does not reach its own threshold, or the trust directory
    /// was set up with another pin.
    InitialRoot,
    /// The root chain (5.3): `Some(v)` names root version `v`, the file
    /// `v.root.json` or the trusted root of that version; `None` is the
    /// stored root `tuf/root.json`, which does not parse or verify.
    Root(Option<i64>),
    /// `timestamp.json` (5.4).
    Timestamp,
    /// `V.snapshot.json` (5.5).
    Snapshot(i64),
    /// `V.targets.json` (5.6).
    Targets(i64),
    /// The `trusted_root.json` target (5.7): not listed, too large,
    /// fetched with another length or hash.
    Target,
    /// The target passed TUF but `TrustedRoot::from_json` refused it.
    TrustedRoot,
    /// The trust directory could not be read or written.
    Write,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::Lock => f.write_str("lock"),
            Step::InitialRoot => f.write_str("initial root"),
            Step::Root(Some(v)) => write!(f, "root {v}"),
            Step::Root(None) => f.write_str("stored root"),
            Step::Timestamp => f.write_str("timestamp"),
            Step::Snapshot(v) => write!(f, "snapshot {v}"),
            Step::Targets(v) => write!(f, "targets {v}"),
            Step::Target => f.write_str("target"),
            Step::TrustedRoot => f.write_str("trusted root"),
            Step::Write => f.write_str("write"),
        }
    }
}

/// Why a refresh failed: the step, and a fixed reason that echoes file
/// names, versions, statuses, sizes, hosts and paths, never metadata text
/// (ADR-033, item 9). `trusted_root.json` is as it was, except after a
/// `Write` failure in the sync that follows its rename: the new, verified
/// file is then in place, and the next run finds it current.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshError {
    /// Where it failed.
    pub step: Step,
    /// Why.
    pub detail: String,
}

impl RefreshError {
    fn new(step: Step, detail: impl fmt::Display) -> RefreshError {
        RefreshError {
            step,
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "refresh failed at {}: {}", self.step, self.detail)
    }
}

impl std::error::Error for RefreshError {}

/// The operator's initial root (ADR-033, item 5): bytes and the SHA-256
/// they are pinned by. Used only to bootstrap an empty trust directory,
/// whose `tuf/pin` then records the pin.
#[derive(Clone)]
pub struct InitialRoot {
    bytes: Vec<u8>,
    sha256_hex: String,
}

impl fmt::Debug for InitialRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialRoot")
            .field("sha256", &self.sha256_hex)
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl InitialRoot {
    /// `bytes` pinned by `sha256_hex`, 64 lower-case hex characters. The
    /// bytes must be at most [`MAX_ROOT_BYTES`], hash to the pin, and be a
    /// root that reaches its own root threshold; its expiry is judged only
    /// when it is the newest root of a refresh. Every failure is
    /// [`Step::InitialRoot`].
    pub fn new(bytes: Vec<u8>, sha256_hex: &str) -> Result<InitialRoot, RefreshError> {
        let fail = |detail: &str| RefreshError::new(Step::InitialRoot, detail);
        let well_formed = sha256_hex.len() == 64
            && sha256_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !well_formed {
            return Err(fail("the pin is not 64 lower-case hex characters"));
        }
        if hex(&Sha256::digest(&bytes)) != sha256_hex {
            return Err(fail("the initial root does not hash to its pin"));
        }
        TrustedSet::new(&bytes, 0).map_err(|e| fail(&format!("the initial root: {e}")))?;
        Ok(InitialRoot {
            bytes,
            sha256_hex: sha256_hex.to_string(),
        })
    }

    /// The pin, 64 lower-case hex characters.
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }
}

/// One refresh's inputs.
pub struct Refresh<'a> {
    /// The repository fetched from; only its host is dialed.
    pub repository: &'a Repository,
    /// The pinned initial root.
    pub initial_root: &'a InitialRoot,
    /// The trust directory (ADR-033, item 6).
    pub dir: &'a Path,
    /// Where requests go: `TlsDial` in production.
    pub dial: &'a dyn Dial,
    /// The fetches' time limits.
    pub timeouts: Timeouts,
    /// The update's start time in seconds since the Unix epoch, read once
    /// by the caller (5.1): every expiry is judged against it.
    pub start_secs: u64,
}

/// The trusted versions a successful refresh ended with, and the SHA-256
/// of `trusted_root.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The newest root.
    pub root_version: i64,
    /// The timestamp.
    pub timestamp_version: i64,
    /// The snapshot.
    pub snapshot_version: i64,
    /// The top-level targets.
    pub targets_version: i64,
    /// The target's SHA-256, which `trusted_root.json` now has.
    pub sha256: [u8; 32],
}

/// What a successful refresh did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `trusted_root.json` was replaced (or written for the first time).
    Updated(Report),
    /// `trusted_root.json` already was the target; nothing was fetched for
    /// it or written.
    Unchanged(Report),
}

impl Outcome {
    /// The versions and the SHA-256.
    pub fn report(&self) -> &Report {
        match self {
            Outcome::Updated(r) | Outcome::Unchanged(r) => r,
        }
    }
}

/// Refreshes `trusted_root.json` in the trust directory from the
/// repository by the TUF workflow 5.1 to 5.7 (ADR-033). Spawns no thread.
///
/// 1. The trust directory is checked, no component of its path may be a
///    `tuf` entry (ADR-041, R2), and its lock (`<dir>/lock`, outside
///    `tuf/`) is taken for the whole refresh; before every read and write
///    the directory, `tuf/` and the lock must still be the ones locked.
/// 2. A recorded pin other than the initial root's fails until `tuf/` is
///    removed, before anything in the directory changes (ADR-041, R1).
///    Then a crashed run's temporary files are removed, and the trusted
///    root is the stored one or, in an empty directory, the initial root,
///    whose pin is recorded.
/// 3. `N+1.root.json` is fetched until a `404`, each root verified and
///    stored before the next is fetched, at most [`MAX_ROOT_ROTATIONS`]
///    per run. A root that changes the timestamp or snapshot keys deletes
///    the stored timestamp and snapshot before it is stored (5.3.11). The
///    newest root must not have expired, and the repository must publish
///    consistent snapshots.
/// 4. Timestamp, snapshot and targets are fetched and verified, each
///    against the stored copy of the role where one is kept; timestamp and
///    snapshot are stored once verified.
/// 5. The target is looked up; when the installed file already is the
///    target, the refresh ends [`Outcome::Unchanged`]. Otherwise the
///    target is fetched, checked against its length and SHA-256, read by
///    `TrustedRoot::from_json`, and installed by rename.
///
/// On an error before the rename `trusted_root.json` is as it was. After
/// the rename only the directory sync can fail: the result is `Write` with
/// the new, fully verified file in place, and the next run returns
/// [`Outcome::Unchanged`] while the repository still lists it, or installs
/// the target again if a crash lost the rename. The TUF state keeps what
/// verified before the error.
pub fn refresh_trusted_root(refresh: &Refresh<'_>) -> Result<Outcome, RefreshError> {
    let dir = TrustDir::open(refresh.dir).map_err(|e| match e {
        OpenError::Dir(detail) => RefreshError::new(Step::Lock, detail),
        OpenError::Busy => RefreshError::new(
            Step::Lock,
            "busy: another refresh holds the trust directory's lock",
        ),
    })?;
    // The pin before anything is written or swept: a directory of another
    // root keeps every entry, a crashed run's included (ADR-041, R1). The
    // sweep precedes the first write, whose `create_new` a leftover
    // temporary file would fail.
    let pinned = check_pin(&dir, refresh)?;
    dir.sweep()
        .map_err(|e| state_err(e, "removing a crashed run's temporary files"))?;
    let mut set = trusted_root(&dir, refresh, pinned)?;
    root_chain(&dir, refresh, &mut set)?;
    let fetch = |file: &str, size: Size, step: Step| match fetch::get(
        refresh.dial,
        refresh.repository,
        &refresh.timeouts,
        file,
        size,
    ) {
        Ok(Fetched::Body(bytes)) => Ok(bytes),
        // `200` only; `404` ends nothing but the root chain (ADR-033,
        // item 7).
        Ok(Fetched::NotFound) => Err(RefreshError::new(
            step,
            format!("GET {}/{file}: answered 404", refresh.repository),
        )),
        Err(e) => Err(RefreshError::new(step, e)),
    };

    // Timestamp (5.4).
    if let Some(stored) = read_tuf(&dir, state::TIMESTAMP, MAX_TIMESTAMP_BYTES)? {
        stored_copy(
            stored.map_or(
                Err(Error::TooLarge {
                    cap: MAX_TIMESTAMP_BYTES,
                }),
                |b| set.load_local_timestamp(&b),
            ),
            Step::Timestamp,
        )?;
    }
    let bytes = fetch(
        state::TIMESTAMP,
        Size::Cap(MAX_TIMESTAMP_BYTES as u64),
        Step::Timestamp,
    )?;
    set.update_timestamp(&bytes)
        .map_err(|e| RefreshError::new(Step::Timestamp, e))?;
    write_tuf(&dir, state::TIMESTAMP, &bytes)?;

    // Snapshot (5.5).
    let meta = set
        .snapshot_meta()
        .cloned()
        .ok_or_else(|| RefreshError::new(Step::Timestamp, Error::OutOfOrder))?;
    let step = Step::Snapshot(meta.version());
    let size = listed_size(meta.length(), MAX_SNAPSHOT_BYTES, step)?;
    if let Some(stored) = read_tuf(&dir, state::SNAPSHOT, MAX_SNAPSHOT_BYTES)? {
        stored_copy(
            stored.map_or(
                Err(Error::TooLarge {
                    cap: MAX_SNAPSHOT_BYTES,
                }),
                |b| set.load_local_snapshot(&b),
            ),
            step,
        )?;
    }
    let bytes = fetch(&format!("{}.snapshot.json", meta.version()), size, step)?;
    set.update_snapshot(&bytes)
        .map_err(|e| RefreshError::new(step, e))?;
    write_tuf(&dir, state::SNAPSHOT, &bytes)?;

    // Targets (5.6).
    let meta = set
        .targets_meta()
        .cloned()
        .ok_or_else(|| RefreshError::new(step, Error::OutOfOrder))?;
    let step = Step::Targets(meta.version());
    let size = listed_size(meta.length(), MAX_TARGETS_BYTES, step)?;
    let bytes = fetch(&format!("{}.targets.json", meta.version()), size, step)?;
    set.update_targets(&bytes)
        .map_err(|e| RefreshError::new(step, e))?;

    // The target (5.7).
    let target = set
        .target(TARGET)
        .map_err(|e| RefreshError::new(Step::Target, e))?;
    let report = Report {
        root_version: set.root().version(),
        timestamp_version: set.timestamp_version().unwrap_or_default(),
        snapshot_version: set.snapshot_version().unwrap_or_default(),
        targets_version: set.targets_version().unwrap_or_default(),
        sha256: *target.sha256(),
    };
    let installed = dir
        .installed(target.length())
        .map_err(|e| state_err(e, "reading trusted_root.json"))?;
    if installed.is_some_and(|bytes| target.verify(&bytes).is_ok()) {
        return Ok(Outcome::Unchanged(report));
    }
    let file = format!("targets/{}.{TARGET}", hex(target.sha256()));
    let bytes = fetch(&file, Size::Exact(target.length()), Step::Target)?;
    target
        .verify(&bytes)
        .map_err(|e| RefreshError::new(Step::Target, e))?;
    // The one reader of the file decides last (ADR-033, item 6).
    TrustedRoot::from_json(&bytes).map_err(|e| RefreshError::new(Step::TrustedRoot, e))?;
    dir.install(&bytes)
        .map_err(|e| state_err(e, "installing trusted_root.json"))?;
    Ok(Outcome::Updated(report))
}

/// The recorded pin `tuf/pin` (ADR-033 item 5, ADR-041 R1), read only:
/// `true` when it is the initial root's, `false` when none is recorded,
/// and [`Step::InitialRoot`] when it is another one, so the directory
/// belongs to another root and nothing in it changes.
fn check_pin(dir: &TrustDir, refresh: &Refresh<'_>) -> Result<bool, RefreshError> {
    match read_tuf(dir, state::PIN, 65)? {
        Some(Some(recorded)) if recorded == pin_line(refresh).as_bytes() => Ok(true),
        Some(_) => Err(RefreshError::new(
            Step::InitialRoot,
            format!("the trust directory was set up from another initial root (tuf/pin); {REMEDY}"),
        )),
        None => Ok(false),
    }
}

/// The content of `tuf/pin` for the initial root.
fn pin_line(refresh: &Refresh<'_>) -> String {
    format!("{}\n", refresh.initial_root.sha256_hex)
}

/// The trusted root to start the chain from (5.2): the stored one, or the
/// initial root in an empty trust directory, which is then stored with
/// its pin (pin first, so a stored root always has one). `pinned` is what
/// [`check_pin`] found.
fn trusted_root(
    dir: &TrustDir,
    refresh: &Refresh<'_>,
    pinned: bool,
) -> Result<TrustedSet, RefreshError> {
    match read_tuf(dir, state::ROOT, MAX_ROOT_BYTES)? {
        Some(stored) => {
            if !pinned {
                return Err(RefreshError::new(
                    Step::InitialRoot,
                    format!("the stored root tuf/root.json has no tuf/pin; {REMEDY}"),
                ));
            }
            let stored = stored.ok_or(Error::TooLarge {
                cap: MAX_ROOT_BYTES,
            });
            stored
                .and_then(|bytes| TrustedSet::new(&bytes, refresh.start_secs))
                .map_err(|e| {
                    RefreshError::new(
                        Step::Root(None),
                        format!("the stored root tuf/root.json: {e}; {REMEDY}"),
                    )
                })
        }
        None => {
            let initial = &refresh.initial_root.bytes;
            let set = TrustedSet::new(initial, refresh.start_secs)
                .map_err(|e| RefreshError::new(Step::InitialRoot, e))?;
            if !pinned {
                write_tuf(dir, state::PIN, pin_line(refresh).as_bytes())?;
            }
            write_tuf(dir, state::ROOT, initial)?;
            Ok(set)
        }
    }
}

/// The root chain (5.3): `N+1.root.json` until a `404`, each root verified
/// and stored before the next is fetched, at most [`MAX_ROOT_ROTATIONS`]
/// in one run; then the newest root's expiry and consistent snapshots.
fn root_chain(
    dir: &TrustDir,
    refresh: &Refresh<'_>,
    set: &mut TrustedSet,
) -> Result<(), RefreshError> {
    let mut rotations = 0;
    loop {
        let current = set.root().version();
        let next = set
            .next_root_version()
            .map_err(|e| RefreshError::new(Step::Root(Some(current)), e))?;
        let step = Step::Root(Some(next));
        let file = format!("{next}.root.json");
        let bytes = match fetch::get(
            refresh.dial,
            refresh.repository,
            &refresh.timeouts,
            &file,
            Size::Cap(MAX_ROOT_BYTES as u64),
        ) {
            Ok(Fetched::NotFound) => break,
            Ok(Fetched::Body(bytes)) => bytes,
            Err(e) => return Err(RefreshError::new(step, e)),
        };
        if rotations == MAX_ROOT_ROTATIONS {
            return Err(RefreshError::new(
                step,
                format!(
                    "more than {MAX_ROOT_ROTATIONS} new roots in one run; the verified ones are \
                     kept and the next run goes on from root {current}"
                ),
            ));
        }
        set.update_root(&bytes)
            .map_err(|e| RefreshError::new(step, e))?;
        // 5.3.11: the stored timestamp and snapshot go before the root
        // that rotated their keys is stored, so a run that stops after it
        // never leaves them to the next run, whose set starts from this
        // root and sees no change. The core's signal is sticky over the
        // run, so later roots delete again, which finds nothing.
        if set.online_keys_changed() {
            remove_tuf(dir, state::TIMESTAMP)?;
            remove_tuf(dir, state::SNAPSHOT)?;
        }
        write_tuf(dir, state::ROOT, &bytes)?;
        rotations += 1;
    }
    let newest = Step::Root(Some(set.root().version()));
    set.check_root_expiry()
        .map_err(|e| RefreshError::new(newest, e))?;
    if !set.root().consistent_snapshot() {
        return Err(RefreshError::new(
            newest,
            "the repository does not publish consistent snapshots",
        ));
    }
    Ok(())
}

/// The result of loading a stored timestamp or snapshot. A copy that does
/// not parse or verify under the trusted root is ignored and serves no
/// rollback check (ADR-033, item 6). [`Error::OutOfOrder`] is no verdict
/// on the copy but a call the driver made out of the core's order, so it
/// fails the refresh: ignoring it would drop the rollback checks quietly.
fn stored_copy(result: Result<(), Error>, step: Step) -> Result<(), RefreshError> {
    match result {
        Err(Error::OutOfOrder) => Err(RefreshError::new(
            step,
            "the stored copy was loaded out of the update order (a bug in the refresh)",
        )),
        Ok(()) | Err(_) => Ok(()),
    }
}

/// The size of a metadata fetch: the listed length, which must be within
/// the role's cap and is refused before any request otherwise, or the cap.
fn listed_size(length: Option<u64>, cap: usize, step: Step) -> Result<Size, RefreshError> {
    match length {
        Some(n) if n > cap as u64 => Err(RefreshError::new(
            step,
            format!("the file is listed as {n} bytes, above the limit of {cap}"),
        )),
        Some(n) => Ok(Size::Exact(n)),
        None => Ok(Size::Cap(cap as u64)),
    }
}

fn read_tuf(
    dir: &TrustDir,
    name: &str,
    max: usize,
) -> Result<Option<Option<Vec<u8>>>, RefreshError> {
    dir.read_tuf(name, max)
        .map_err(|e| state_err(e, &format!("reading tuf/{name}")))
}

fn write_tuf(dir: &TrustDir, name: &str, bytes: &[u8]) -> Result<(), RefreshError> {
    dir.write_tuf(name, bytes)
        .map_err(|e| state_err(e, &format!("writing tuf/{name}")))
}

fn remove_tuf(dir: &TrustDir, name: &str) -> Result<(), RefreshError> {
    dir.remove_tuf(name)
        .map_err(|e| state_err(e, &format!("removing tuf/{name}")))
}

/// A trust directory replaced under the lock is `Lock`: this refresh no
/// longer holds the directory it writes to. Any other failure is `Write`.
fn state_err(e: StateError, what: &str) -> RefreshError {
    match e {
        StateError::Replaced(why) => RefreshError::new(Step::Lock, format!("{what}: {why}")),
        StateError::Io(e) => RefreshError::new(Step::Write, format!("{what}: {e}")),
    }
}

/// Lower-case hex.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review of PR 2: the driver fails on `OutOfOrder` from a stored-copy
    /// load and ignores only verdicts on the copy.
    #[test]
    fn stored_copy_out_of_order_is_fatal() {
        let step = Step::Timestamp;
        let err = stored_copy(Err(Error::OutOfOrder), step).expect_err("fatal");
        assert_eq!(err.step, step);
        for ignored in [
            Ok(()),
            Err(Error::Envelope),
            Err(Error::TooLarge { cap: 1 }),
            Err(Error::Json(boneli_json::ErrorKind::UnexpectedByte)),
            Err(Error::BelowThreshold { role: "timestamp" }),
            Err(Error::Type {
                expected: "timestamp",
            }),
            Err(Error::Field("meta")),
            Err(Error::OnlineKeysChanged),
        ] {
            assert_eq!(stored_copy(ignored, step), Ok(()), "{ignored:?}");
        }
    }

    #[test]
    fn hex_is_lower_case() {
        assert_eq!(hex(&[0x00, 0x9f, 0xa0, 0xff]), "009fa0ff");
    }
}
