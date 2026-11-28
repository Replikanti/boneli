//! Landlock for the calling process (ADR-007, D10): an in-process API that
//! the shim (#9) applies to itself as PID 1 before the agent starts.
//!
//! ABI 2 is the minimum (it came with Linux 5.19; the floor is 6.1,
//! ADR-044); ABIs above 10, the newest the 7.2.4 headers describe, are
//! treated as 10, because rights only grow.
//! Every request is checked against the ABI: a right the kernel does not
//! know is an error, never a silent best effort.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::error::{Error, Result, errno};
use crate::ffi;

/// The oldest ABI the runtime accepts: ABI 1 denies every rename or link
/// into another directory (`LANDLOCK_ACCESS_FS_REFER` came with ABI 2).
pub const ABI_REQUIRED: u32 = crate::host::LANDLOCK_ABI_REQUIRED;

/// The newest ABI the 7.2.4 headers describe.
pub const ABI_KNOWN: u32 = 10;

/// A Landlock ABI version between [`ABI_REQUIRED`] and [`ABI_KNOWN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Abi(u32);

impl Abi {
    /// The ABI for a version the kernel reported: below 2 is
    /// [`Error::LandlockAbiTooOld`], above 10 is 10.
    pub fn new(version: u32) -> Result<Abi> {
        if version < ABI_REQUIRED {
            return Err(Error::LandlockAbiTooOld {
                found: version,
                required: ABI_REQUIRED,
            });
        }
        Ok(Abi(version.min(ABI_KNOWN)))
    }

    /// The running kernel's ABI. EOPNOTSUPP (Landlock built but off) and
    /// ENOSYS (not built) are [`Error::LandlockUnavailable`].
    pub fn current() -> Result<Abi> {
        // SAFETY: with LANDLOCK_CREATE_RULESET_VERSION the attribute pointer
        // must be null and the size 0; the call returns the ABI version.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0usize,
                ffi::LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if rc < 0 {
            return Err(Error::LandlockUnavailable { errno: errno() });
        }
        Abi::new(rc as u32)
    }

    /// The version number.
    pub fn version(self) -> u32 {
        self.0
    }
}

/// Filesystem rights (`LANDLOCK_ACCESS_FS_*`), with the ABI that added each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessFs(pub u64);

/// Network rights (`LANDLOCK_ACCESS_NET_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessNet(pub u64);

/// Scopes (`LANDLOCK_SCOPE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope(pub u64);

/// Name, bit and first ABI of every filesystem right
/// (`include/uapi/linux/landlock.h`, 7.2.4).
const FS_RIGHTS: [(&str, u64, u32); 17] = [
    ("execute", 1 << 0, 1),
    ("write_file", 1 << 1, 1),
    ("read_file", 1 << 2, 1),
    ("read_dir", 1 << 3, 1),
    ("remove_dir", 1 << 4, 1),
    ("remove_file", 1 << 5, 1),
    ("make_char", 1 << 6, 1),
    ("make_dir", 1 << 7, 1),
    ("make_reg", 1 << 8, 1),
    ("make_sock", 1 << 9, 1),
    ("make_fifo", 1 << 10, 1),
    ("make_block", 1 << 11, 1),
    ("make_sym", 1 << 12, 1),
    ("refer", 1 << 13, 2),
    ("truncate", 1 << 14, 3),
    ("ioctl_dev", 1 << 15, 5),
    // Applies only to Unix sockets created outside the domain.
    ("resolve_unix", 1 << 16, 9),
];

/// The network rights: TCP since ABI 4, UDP since ABI 10.
const NET_RIGHTS: [(&str, u64, u32); 4] = [
    ("bind_tcp", 1 << 0, 4),
    ("connect_tcp", 1 << 1, 4),
    ("bind_udp", 1 << 2, 10),
    ("connect_send_udp", 1 << 3, 10),
];

/// The scopes, since ABI 6.
const SCOPES: [(&str, u64, u32); 2] = [("abstract_unix_socket", 1 << 0, 6), ("signal", 1 << 1, 6)];

fn all(table: &[(&str, u64, u32)], abi: Abi) -> u64 {
    table
        .iter()
        .filter(|(_, _, since)| *since <= abi.0)
        .fold(0, |acc, (_, bit, _)| acc | bit)
}

/// The first bit of `bits` outside `allowed`, by name.
fn first_outside(
    table: &[(&'static str, u64, u32)],
    bits: u64,
    allowed: u64,
) -> Option<&'static str> {
    let extra = bits & !allowed;
    if extra == 0 {
        return None;
    }
    Some(
        table
            .iter()
            .find(|(_, bit, _)| extra & bit != 0)
            .map_or("an unknown bit", |(name, _, _)| name),
    )
}

impl AccessFs {
    /// Read a file.
    pub const READ_FILE: AccessFs = AccessFs(1 << 2);
    /// List a directory.
    pub const READ_DIR: AccessFs = AccessFs(1 << 3);
    /// Execute a file.
    pub const EXECUTE: AccessFs = AccessFs(1 << 0);
    /// Connect to a Unix socket created outside the domain (ABI 9).
    pub const RESOLVE_UNIX: AccessFs = AccessFs(1 << 16);

    /// Every filesystem right `abi` knows.
    pub fn all_for(abi: Abi) -> AccessFs {
        AccessFs(all(&FS_RIGHTS, abi))
    }

    /// Both sets together.
    pub fn union(self, other: AccessFs) -> AccessFs {
        AccessFs(self.0 | other.0)
    }
}

impl AccessNet {
    /// Connect a TCP socket to a port (ABI 4).
    pub const CONNECT_TCP: AccessNet = AccessNet(1 << 1);

    /// Every network right `abi` knows.
    pub fn all_for(abi: Abi) -> AccessNet {
        AccessNet(all(&NET_RIGHTS, abi))
    }
}

impl Scope {
    /// Every scope `abi` knows.
    pub fn all_for(abi: Abi) -> Scope {
        Scope(all(&SCOPES, abi))
    }
}

/// The handled sets requested for `abi`, checked: a right `abi` does not
/// know is [`Error::LandlockUnsupported`] (pure, no syscall).
pub(crate) fn check_handled(abi: Abi, fs: AccessFs, net: AccessNet, scope: Scope) -> Result<()> {
    let unsupported = |right| Error::LandlockUnsupported { right, abi: abi.0 };
    if let Some(right) = first_outside(&FS_RIGHTS, fs.0, AccessFs::all_for(abi).0) {
        return Err(unsupported(right));
    }
    if let Some(right) = first_outside(&NET_RIGHTS, net.0, AccessNet::all_for(abi).0) {
        return Err(unsupported(right));
    }
    if let Some(right) = first_outside(&SCOPES, scope.0, Scope::all_for(abi).0) {
        return Err(unsupported(right));
    }
    Ok(())
}

/// A rule's rights against the ruleset's handled set: a right the ruleset
/// does not handle is [`Error::LandlockRuleNotHandled`] (pure).
pub(crate) fn check_rule(table: RuleKind, rights: u64, handled: u64) -> Result<()> {
    let names: &[(&'static str, u64, u32)] = match table {
        RuleKind::Fs => &FS_RIGHTS,
        RuleKind::Net => &NET_RIGHTS,
    };
    match first_outside(names, rights, handled) {
        Some(right) => Err(Error::LandlockRuleNotHandled { right }),
        None if rights == 0 => Err(Error::LandlockRuleNotHandled { right: "no right" }),
        None => Ok(()),
    }
}

/// Which kind of rule [`check_rule`] checks.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RuleKind {
    Fs,
    Net,
}

/// A Landlock ruleset being built for this process.
#[derive(Debug)]
pub struct Ruleset {
    fd: OwnedFd,
    fs: AccessFs,
    net: AccessNet,
}

impl Ruleset {
    /// A ruleset that handles exactly `fs`, `net` and `scope`; each must be
    /// known to `abi` ([`Error::LandlockUnsupported`] otherwise).
    pub fn new(abi: Abi, fs: AccessFs, net: AccessNet, scope: Scope) -> Result<Ruleset> {
        check_handled(abi, fs, net, scope)?;
        let attr = ffi::LandlockRulesetAttr {
            handled_access_fs: fs.0,
            handled_access_net: net.0,
            scoped: scope.0,
        };
        // SAFETY: attr is a valid ruleset attribute of the size passed for
        // the call's duration.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const ffi::LandlockRulesetAttr,
                std::mem::size_of::<ffi::LandlockRulesetAttr>(),
                0u32,
            )
        };
        if rc < 0 {
            return Err(Error::last("landlock_create_ruleset"));
        }
        // SAFETY: the kernel returned a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(rc as i32) };
        Ok(Ruleset { fd, fs, net })
    }

    /// Allows `rights` beneath `path` (a directory, or a file for file
    /// rights). Every right must be handled by the ruleset.
    pub fn allow_path(&mut self, path: &Path, rights: AccessFs) -> Result<()> {
        check_rule(RuleKind::Fs, rights.0, self.fs.0)?;
        let c =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Nul("a Landlock path"))?;
        // SAFETY: c is NUL-terminated; O_PATH opens without reading.
        let raw = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(Error::last("open (Landlock rule)"));
        }
        // SAFETY: open returned a new descriptor that nothing else owns.
        let parent = unsafe { OwnedFd::from_raw_fd(raw) };
        let attr = ffi::LandlockPathBeneathAttr {
            allowed_access: rights.0,
            parent_fd: parent.as_raw_fd(),
        };
        self.add_rule(
            ffi::LANDLOCK_RULE_PATH_BENEATH,
            (&attr as *const ffi::LandlockPathBeneathAttr).cast(),
        )
    }

    /// Allows `rights` for TCP `port`. Every right must be handled.
    pub fn allow_port(&mut self, port: u16, rights: AccessNet) -> Result<()> {
        check_rule(RuleKind::Net, rights.0, self.net.0)?;
        let attr = ffi::LandlockNetPortAttr {
            allowed_access: rights.0,
            port: u64::from(port),
        };
        self.add_rule(
            ffi::LANDLOCK_RULE_NET_PORT,
            (&attr as *const ffi::LandlockNetPortAttr).cast(),
        )
    }

    fn add_rule(&self, kind: u32, attr: *const u8) -> Result<()> {
        // SAFETY: attr points at the rule attribute of `kind`, valid for the
        // call's duration (the callers' locals).
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd.as_raw_fd(),
                kind,
                attr,
                0u32,
            )
        };
        if rc < 0 {
            return Err(Error::last("landlock_add_rule"));
        }
        Ok(())
    }

    /// Sets `PR_SET_NO_NEW_PRIVS`, which Landlock requires without
    /// `CAP_SYS_ADMIN`, and restricts the calling thread, and the threads
    /// and processes it starts from now on, to the ruleset.
    pub fn restrict_self(self) -> Result<()> {
        // SAFETY: PR_SET_NO_NEW_PRIVS takes plain integers.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
            return Err(Error::last("prctl(PR_SET_NO_NEW_PRIVS)"));
        }
        // SAFETY: the descriptor is the ruleset's; no flags.
        let rc =
            unsafe { libc::syscall(libc::SYS_landlock_restrict_self, self.fd.as_raw_fd(), 0u32) };
        if rc < 0 {
            return Err(Error::last("landlock_restrict_self"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abi(n: u32) -> Abi {
        Abi::new(n).expect("ABI")
    }

    #[test]
    fn access_sets_per_abi() {
        // ABI 1 is refused as an Abi, so its set is checked on the table.
        assert_eq!(all(&FS_RIGHTS, Abi(1)), 0x1FFF);
        assert_eq!(AccessFs::all_for(abi(2)).0, 0x3FFF);
        assert_eq!(AccessFs::all_for(abi(3)).0, 0x7FFF);
        assert_eq!(AccessFs::all_for(abi(4)).0, 0x7FFF);
        assert_eq!(AccessFs::all_for(abi(5)).0, 0xFFFF);
        assert_eq!(AccessFs::all_for(abi(8)).0, 0xFFFF);
        assert_eq!(AccessFs::all_for(abi(9)).0, 0x1FFFF);
        assert_eq!(AccessFs::all_for(abi(10)), AccessFs::all_for(abi(9)));
        assert_eq!(AccessNet::all_for(abi(3)).0, 0);
        assert_eq!(AccessNet::all_for(abi(4)).0, 0x3);
        assert_eq!(AccessNet::all_for(abi(9)).0, 0x3);
        assert_eq!(AccessNet::all_for(abi(10)).0, 0xF);
        assert_eq!(Scope::all_for(abi(5)).0, 0);
        assert_eq!(Scope::all_for(abi(6)).0, 0x3);
        // Above the newest known ABI: treated as 10.
        assert_eq!(abi(11), abi(10));
        assert_eq!(abi(11).version(), 10);
        assert_eq!(AccessFs::all_for(abi(11)), AccessFs::all_for(abi(10)));
        assert_eq!(AccessNet::all_for(abi(11)), AccessNet::all_for(abi(10)));
        // The named constants are the header's bits.
        assert_eq!(AccessFs::RESOLVE_UNIX.0, 1 << 16);
        assert_eq!(AccessNet::CONNECT_TCP.0, 1 << 1);
    }

    #[test]
    fn ruleset_fails_closed() {
        assert!(matches!(
            Abi::new(1),
            Err(Error::LandlockAbiTooOld {
                found: 1,
                required: 2
            })
        ));
        assert!(matches!(
            Abi::new(0),
            Err(Error::LandlockAbiTooOld { found: 0, .. })
        ));
        // TRUNCATE came with ABI 3.
        let truncate = AccessFs(1 << 14);
        let err = check_handled(abi(2), truncate, AccessNet(0), Scope(0));
        assert!(
            matches!(
                err,
                Err(Error::LandlockUnsupported {
                    right: "truncate",
                    abi: 2
                })
            ),
            "{err:?}"
        );
        assert!(check_handled(abi(3), truncate, AccessNet(0), Scope(0)).is_ok());
        // Network rights before ABI 4, UDP before 10, scopes before 6, and
        // bits no ABI defines.
        assert!(matches!(
            check_handled(abi(3), AccessFs(0), AccessNet(1 << 1), Scope(0)),
            Err(Error::LandlockUnsupported {
                right: "connect_tcp",
                abi: 3
            })
        ));
        assert!(matches!(
            check_handled(abi(9), AccessFs(0), AccessNet(1 << 2), Scope(0)),
            Err(Error::LandlockUnsupported {
                right: "bind_udp",
                abi: 9
            })
        ));
        assert!(matches!(
            check_handled(abi(5), AccessFs(0), AccessNet(0), Scope(1 << 1)),
            Err(Error::LandlockUnsupported {
                right: "signal",
                abi: 5
            })
        ));
        assert!(matches!(
            check_handled(abi(10), AccessFs(1 << 17), AccessNet(0), Scope(0)),
            Err(Error::LandlockUnsupported {
                right: "an unknown bit",
                abi: 10
            })
        ));
        // A rule right outside the handled set, and an empty rule.
        assert!(matches!(
            check_rule(RuleKind::Fs, (1 << 2) | (1 << 1), 1 << 2),
            Err(Error::LandlockRuleNotHandled {
                right: "write_file"
            })
        ));
        assert!(matches!(
            check_rule(RuleKind::Net, 1 << 0, 1 << 1),
            Err(Error::LandlockRuleNotHandled { right: "bind_tcp" })
        ));
        assert!(matches!(
            check_rule(RuleKind::Fs, 0, 0x3FFF),
            Err(Error::LandlockRuleNotHandled { right: "no right" })
        ));
        assert!(check_rule(RuleKind::Fs, 1 << 2, 0x3FFF).is_ok());
    }
}
