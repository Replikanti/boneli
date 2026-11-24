//! The trusted set: the client's trusted metadata, today the root and its
//! chain (TUF 5.2 and 5.3, ADR-033 item 2).

use crate::envelope::{self, RoleName};
use crate::root::Root;
use crate::{Error, expires};

/// The trusted root of one update, with the update's start time.
///
/// Every root it holds passed its own threshold; every root after the
/// first also passed the previous one's (5.3.4 to 5.3.6). The start time
/// is the caller's, read once at the start of the update (5.1), so one
/// update judges every expiry against the same instant.
pub struct TrustedSet {
    root: Root,
    start_secs: u64,
    online_keys_changed: bool,
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
    /// the trusted root stays as it was.
    pub fn update_root(&mut self, bytes: &[u8]) -> Result<(), Error> {
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
}
