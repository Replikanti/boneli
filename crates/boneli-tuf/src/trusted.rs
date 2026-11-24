//! The trusted set: the client's trusted metadata of one update (TUF 5.2
//! to 5.7, ADR-033 item 2): the root and its chain, the timestamp, the
//! snapshot, the top-level targets and the target lookup.

use crate::envelope::{self, Envelope, RoleName};
use crate::meta::MetaFile;
use crate::root::Root;
use crate::snapshot::Snapshot;
use crate::targets::{TargetFile, Targets};
use crate::timestamp::Timestamp;
use crate::{Error, expires};

/// A timestamp or snapshot the set holds: either a stored copy, loaded
/// for rollback checks only, or one this update verified in full.
enum Held<T> {
    Stored(T),
    Verified(T),
}

impl<T> Held<T> {
    fn doc(&self) -> &T {
        match self {
            Held::Stored(doc) | Held::Verified(doc) => doc,
        }
    }

    fn verified(&self) -> Option<&T> {
        match self {
            Held::Verified(doc) => Some(doc),
            Held::Stored(_) => None,
        }
    }
}

/// The trusted metadata of one update, with the update's start time.
///
/// Every root it holds passed its own threshold; every root after the
/// first also passed the previous one's (5.3.4 to 5.3.6). The start time
/// is the caller's, read once at the start of the update (5.1), so one
/// update judges every expiry against the same instant.
///
/// The update runs in one order, and a call out of it fails with
/// [`Error::OutOfOrder`]: [`update_root`](Self::update_root) for each
/// next root, [`load_local_timestamp`](Self::load_local_timestamp),
/// [`update_timestamp`](Self::update_timestamp),
/// [`load_local_snapshot`](Self::load_local_snapshot),
/// [`update_snapshot`](Self::update_snapshot),
/// [`update_targets`](Self::update_targets), then
/// [`target`](Self::target). The two loads are optional. On any error the
/// set stays as it was.
pub struct TrustedSet {
    root: Root,
    start_secs: u64,
    online_keys_changed: bool,
    timestamp: Option<Held<Timestamp>>,
    snapshot: Option<Held<Snapshot>>,
    targets: Option<Targets>,
}

impl TrustedSet {
    /// Trusts `root_bytes`, the initial root or the one stored by an
    /// earlier update, when it reaches its own root threshold (5.2). Its
    /// expiry is not checked here: an expired stored root still starts
    /// the chain, and [`check_root_expiry`](Self::check_root_expiry) judges
    /// the newest one.
    pub fn new(root_bytes: &[u8], start_secs: u64) -> Result<TrustedSet, Error> {
        let env = envelope::parse(root_bytes, RoleName::Root)?;
        let root = Root::parse(&env)?;
        if !root.verifies(RoleName::Root, &env) {
            return Err(Error::BelowOwnThreshold);
        }
        Ok(TrustedSet {
            root,
            start_secs,
            online_keys_changed: false,
            timestamp: None,
            snapshot: None,
            targets: None,
        })
    }

    /// The trusted root.
    pub fn root(&self) -> &Root {
        &self.root
    }

    /// The update's start time, in seconds since the Unix epoch.
    pub fn start_secs(&self) -> u64 {
        self.start_secs
    }

    /// The version the next root must have: the trusted one plus 1, or
    /// [`Error::NoNextVersion`] at `i64::MAX`, so a caller asks for no file
    /// that could never be accepted.
    pub fn next_root_version(&self) -> Result<i64, Error> {
        self.root
            .version()
            .checked_add(1)
            .ok_or(Error::NoNextVersion)
    }

    /// Verifies `bytes` as the next root (5.3.4 to 5.3.6) and trusts it:
    /// type `root`, signed by a threshold of the trusted root's root keys
    /// and by a threshold of its own, version exactly N+1. Its expiry is
    /// not checked; an intermediate root may have expired. On any error
    /// the trusted root stays as it was. No root is accepted once a
    /// timestamp is held.
    pub fn update_root(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.timestamp.is_some() {
            return Err(Error::OutOfOrder);
        }
        let expected = self.next_root_version()?;
        let env = envelope::parse(bytes, RoleName::Root)?;
        if !self.root.verifies(RoleName::Root, &env) {
            return Err(Error::BelowThreshold {
                role: RoleName::Root.name(),
            });
        }
        let new = Root::parse(&env)?;
        if !new.verifies(RoleName::Root, &env) {
            return Err(Error::BelowOwnThreshold);
        }
        if env.version != expected {
            return Err(Error::NotNextVersion {
                expected,
                found: env.version,
            });
        }
        let online = [RoleName::Timestamp, RoleName::Snapshot];
        if online
            .iter()
            .any(|r| self.root.key_material(*r) != new.key_material(*r))
        {
            self.online_keys_changed = true;
        }
        self.root = new;
        Ok(())
    }

    /// Fails with [`Error::Expired`] when the trusted root has expired at
    /// the start time (5.3.10): the caller runs it after the last root of
    /// the chain.
    pub fn check_root_expiry(&self) -> Result<(), Error> {
        if expires::is_expired(self.root.expires(), self.start_secs) {
            return Err(Error::Expired {
                role: RoleName::Root.name(),
            });
        }
        Ok(())
    }

    /// Whether a root this set accepted changed the key material or the
    /// threshold of the timestamp or snapshot role against its
    /// predecessor (5.3.11). Once set it stays set. The caller then drops
    /// the stored timestamp and snapshot, so a repository that recovers
    /// from a compromised online key can start its versions again
    /// (fast-forward recovery).
    pub fn online_keys_changed(&self) -> bool {
        self.online_keys_changed
    }

    /// Loads the timestamp an earlier update stored, for the rollback
    /// checks of [`update_timestamp`](Self::update_timestamp) only:
    /// signatures under the trusted root and `_type`, no expiry. Refused
    /// when a timestamp is already held, and with
    /// [`Error::OnlineKeysChanged`] after a root of this update rotated
    /// the online keys (5.3.11). The caller ignores a failure and goes on
    /// without the copy.
    pub fn load_local_timestamp(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.timestamp.is_some() {
            return Err(Error::OutOfOrder);
        }
        if self.online_keys_changed {
            return Err(Error::OnlineKeysChanged);
        }
        let env = self.verified_envelope(bytes, RoleName::Timestamp)?;
        self.timestamp = Some(Held::Stored(Timestamp::parse(&env)?));
        Ok(())
    }

    /// Verifies `bytes` as the timestamp (5.4) and trusts it. The trusted
    /// root must not have expired (5.3.10). Then: `_type`, signatures by a
    /// threshold of the root's timestamp keys, a version not below the
    /// held timestamp's and a snapshot version not below the held
    /// timestamp's (an equal version passes, after every check again),
    /// and not expired at the start time. Refused once a snapshot is
    /// held.
    pub fn update_timestamp(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.snapshot.is_some() || self.targets.is_some() {
            return Err(Error::OutOfOrder);
        }
        self.check_root_expiry()?;
        let env = self.verified_envelope(bytes, RoleName::Timestamp)?;
        let new = Timestamp::parse(&env)?;
        if let Some(held) = &self.timestamp {
            let old = held.doc();
            if new.version < old.version {
                return Err(Error::Rollback {
                    role: RoleName::Timestamp.name(),
                    trusted: old.version,
                    found: new.version,
                });
            }
            if new.snapshot.version() < old.snapshot.version() {
                return Err(Error::Rollback {
                    role: RoleName::Snapshot.name(),
                    trusted: old.snapshot.version(),
                    found: new.snapshot.version(),
                });
            }
        }
        self.check_expiry(RoleName::Timestamp, new.expires)?;
        self.timestamp = Some(Held::Verified(new));
        Ok(())
    }

    /// Loads the snapshot an earlier update stored, for the rollback
    /// checks of [`update_snapshot`](Self::update_snapshot) only:
    /// signatures under the trusted root and `_type`, no expiry and no
    /// version check. Needs a timestamp verified in this update, so the
    /// copy is read under the final root of the chain; refused when a
    /// snapshot is already held, and with [`Error::OnlineKeysChanged`]
    /// after a root of this update rotated the online keys. The caller
    /// ignores a failure.
    pub fn load_local_snapshot(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.timestamp.as_ref().and_then(Held::verified).is_none() {
            return Err(Error::OutOfOrder);
        }
        if self.snapshot.is_some() || self.targets.is_some() {
            return Err(Error::OutOfOrder);
        }
        if self.online_keys_changed {
            return Err(Error::OnlineKeysChanged);
        }
        let env = self.verified_envelope(bytes, RoleName::Snapshot)?;
        self.snapshot = Some(Held::Stored(Snapshot::parse(&env)?));
        Ok(())
    }

    /// Verifies `bytes` as the snapshot (5.5) and trusts it: length and
    /// SHA-256 as the verified timestamp lists them, before parsing;
    /// `_type`; signatures by a threshold of the root's snapshot keys;
    /// version equal to the timestamp's entry; every entry of a stored
    /// snapshot still listed with a version at least as high; not
    /// expired. Needs a verified timestamp and no verified snapshot.
    pub fn update_snapshot(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let Some(timestamp) = self.timestamp.as_ref().and_then(Held::verified) else {
            return Err(Error::OutOfOrder);
        };
        let stored = match &self.snapshot {
            None => None,
            Some(Held::Stored(old)) => Some(old),
            Some(Held::Verified(_)) => return Err(Error::OutOfOrder),
        };
        if self.targets.is_some() {
            return Err(Error::OutOfOrder);
        }
        let listed = &timestamp.snapshot;
        listed.verify(RoleName::Snapshot.name(), bytes)?;
        let env = self.verified_envelope(bytes, RoleName::Snapshot)?;
        let new = Snapshot::parse(&env)?;
        if new.version != listed.version() {
            return Err(Error::VersionMismatch {
                role: RoleName::Snapshot.name(),
                expected: listed.version(),
                found: new.version,
            });
        }
        if let Some(old) = stored {
            old.check_successor(&new)?;
        }
        self.check_expiry(RoleName::Snapshot, new.expires)?;
        self.snapshot = Some(Held::Verified(new));
        Ok(())
    }

    /// Verifies `bytes` as the top-level targets (5.6) and trusts them:
    /// length and SHA-256 as the verified snapshot lists them, before
    /// parsing; `_type`; signatures by a threshold of the root's targets
    /// keys; version equal to the snapshot's entry; not expired. Needs a
    /// verified snapshot and no targets.
    pub fn update_targets(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let Some(snapshot) = self.snapshot.as_ref().and_then(Held::verified) else {
            return Err(Error::OutOfOrder);
        };
        if self.targets.is_some() {
            return Err(Error::OutOfOrder);
        }
        let listed = &snapshot.targets;
        listed.verify(RoleName::Targets.name(), bytes)?;
        let env = self.verified_envelope(bytes, RoleName::Targets)?;
        let new = Targets::parse(env)?;
        if new.version != listed.version() {
            return Err(Error::VersionMismatch {
                role: RoleName::Targets.name(),
                expected: listed.version(),
                found: new.version,
            });
        }
        self.check_expiry(RoleName::Targets, new.expires)?;
        self.targets = Some(new);
        Ok(())
    }

    /// The target `name` as the verified targets list it (5.7): looked up
    /// byte for byte in top-level `targets`, never in a delegation
    /// ([`Error::NotListed`]); its listed length at most
    /// `boneli_sigstore::MAX_TRUSTED_ROOT_BYTES`
    /// ([`Error::TargetTooLarge`], so a larger file is never requested);
    /// a hash map with `sha256`. Check the fetched bytes with
    /// [`TargetFile::verify`].
    pub fn target(&self, name: &str) -> Result<TargetFile, Error> {
        self.targets.as_ref().ok_or(Error::OutOfOrder)?.lookup(name)
    }

    /// The version of the timestamp the set holds, stored or verified.
    pub fn timestamp_version(&self) -> Option<i64> {
        self.timestamp.as_ref().map(|t| t.doc().version)
    }

    /// The version of the snapshot the set holds, stored or verified.
    pub fn snapshot_version(&self) -> Option<i64> {
        self.snapshot.as_ref().map(|s| s.doc().version)
    }

    /// The version of the verified targets.
    pub fn targets_version(&self) -> Option<i64> {
        self.targets.as_ref().map(|t| t.version)
    }

    /// What the verified timestamp says about `snapshot.json`: the version
    /// to fetch as `V.snapshot.json`, and its length and SHA-256 when
    /// listed. `None` before a timestamp is verified.
    pub fn snapshot_meta(&self) -> Option<&MetaFile> {
        let timestamp = self.timestamp.as_ref().and_then(Held::verified)?;
        Some(&timestamp.snapshot)
    }

    /// What the verified snapshot says about `targets.json`. `None` before
    /// a snapshot is verified.
    pub fn targets_meta(&self) -> Option<&MetaFile> {
        let snapshot = self.snapshot.as_ref().and_then(Held::verified)?;
        Some(&snapshot.targets)
    }

    /// Parses `bytes` as a document of `role` and checks that its
    /// signatures reach the trusted root's threshold for that role.
    fn verified_envelope(&self, bytes: &[u8], role: RoleName) -> Result<Envelope, Error> {
        let env = envelope::parse(bytes, role)?;
        if !self.root.verifies(role, &env) {
            return Err(Error::BelowThreshold { role: role.name() });
        }
        Ok(env)
    }

    /// Fails with [`Error::Expired`] when `expires` is not after the
    /// start time (5.4.4, 5.5.6, 5.6.5).
    fn check_expiry(&self, role: RoleName, expires: u64) -> Result<(), Error> {
        if expires::is_expired(expires, self.start_secs) {
            return Err(Error::Expired { role: role.name() });
        }
        Ok(())
    }
}
