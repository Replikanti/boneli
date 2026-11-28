//! Errors of the sandbox runtime.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::child::Step;
use crate::host::Missing;

/// A `Result` with this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Why a setup report from the child was rejected (fail closed, ADR-007 D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// The report had neither 0 nor exactly 12 bytes.
    Length(usize),
    /// The report named a step code that does not exist.
    UnknownStep(u32),
    /// The child's listener message was not exactly one byte with one
    /// `SCM_RIGHTS` descriptor (ADR-043, D3).
    Listener(ListenerError),
    /// A progress record of this step came where another record was
    /// expected (ADR-042, D3).
    Unexpected(Step),
    /// The report ended before the progress record of this step
    /// (ADR-042, D3).
    Ended(Step),
    /// A progress record of this step carried a value it cannot hold: a
    /// pid of 0, loopback families outside the two known bits
    /// (ADR-042, D3).
    Value {
        /// The step.
        step: Step,
        /// The value.
        value: u32,
    },
}

/// What was wrong with the listener message the child sends before
/// `execve` (ADR-043, D3). Every descriptor that came with it was closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerError {
    /// No message was queued: the socket was empty or at its end.
    Missing,
    /// The payload had this many bytes instead of 1.
    Payload(usize),
    /// The kernel truncated the ancillary data (`MSG_CTRUNC`): more
    /// descriptors than the one expected.
    Truncated,
    /// The ancillary data held this many descriptors instead of 1 (0 for
    /// none or another kind of message).
    Descriptors(usize),
    /// `recvmsg` failed with this errno.
    Recv(i32),
}

impl fmt::Display for ListenerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListenerError::Missing => write!(f, "no listener message"),
            ListenerError::Payload(n) => write!(f, "a listener message of {n} bytes instead of 1"),
            ListenerError::Truncated => {
                write!(f, "a listener message with truncated ancillary data")
            }
            ListenerError::Descriptors(n) => {
                write!(f, "a listener message with {n} descriptors instead of 1")
            }
            ListenerError::Recv(errno) => {
                write!(f, "recvmsg of the listener failed: {}", strerror(*errno))
            }
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Length(n) => write!(f, "{n} bytes instead of 0 or 12"),
            ProtocolError::UnknownStep(code) => write!(f, "unknown step code {code}"),
            ProtocolError::Listener(e) => write!(f, "{e}"),
            ProtocolError::Unexpected(step) => {
                write!(f, "an unexpected progress record of step {}", step.name())
            }
            ProtocolError::Ended(step) => {
                write!(f, "the report ended before step {}", step.name())
            }
            ProtocolError::Value { step, value } => {
                write!(f, "step {} reported the value {value}", step.name())
            }
        }
    }
}

/// An error of the sandbox runtime.
#[derive(Debug)]
pub enum Error {
    /// 4294967295 is `(uid_t)-1`, never an id (ADR-007, D1).
    InvalidId(u32),
    /// The caller runs with effective uid or gid 0: an escape would yield
    /// host root (ADR-007, D1).
    RunningAsRoot,
    /// The caller's real and effective uid or gid differ (a setuid or setgid
    /// binary), so the map would grant an id the caller does not own.
    SetuidCaller,
    /// The program path is not absolute; there is no `PATH` search.
    RelativeProgram(PathBuf),
    /// The setup timeout is zero.
    ZeroSetupTimeout,
    /// A program path, argument or environment entry holds a NUL byte.
    Nul(&'static str),
    /// An environment name is empty or holds `=`.
    InvalidEnvName(OsString),
    /// The child failed a setup step before `execve` (ADR-007, D4).
    Setup {
        /// The step that failed.
        step: Step,
        /// The item within the step (a signal or descriptor number), else 0.
        index: u32,
        /// The `errno` the step got.
        errno: i32,
    },
    /// The child did not exec within the setup timeout; it was killed and
    /// reaped.
    SetupTimeout(Duration),
    /// The child's setup report was malformed; it was killed and reaped.
    Protocol(ProtocolError),
    /// A syscall in the calling process failed.
    Sys {
        /// The syscall.
        call: &'static str,
        /// Its `errno`.
        errno: i32,
    },
    /// The host lacks features the runtime needs (ADR-007, D3).
    HostUnsupported(Vec<Missing>),
    /// The child was already waited for.
    AlreadyWaited,
    /// `exit_main_thread` was called on a thread other than the main
    /// thread; nothing changed (#35).
    NotMainThread,
    /// A path inside the sandbox is not of the accepted form (ADR-007, D7).
    InvalidInsidePath {
        /// The path, lossily rendered.
        path: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A hostname is not 1-64 bytes of `[A-Za-z0-9.-]` (ADR-007, D7).
    InvalidHostname(String),
    /// The root's layers or staging directory are unusable (ADR-007, D7).
    InvalidRoot(&'static str),
    /// A mount of the root is unusable (ADR-007, D7).
    InvalidMount {
        /// Its index in `Root::mounts`.
        index: usize,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// An overlay's mount options do not fit one page: 4096 bytes with the
    /// terminating NUL (ADR-007, D7).
    MountOptionsTooLong {
        /// Their length with the NUL.
        len: usize,
    },
    /// The path is not a directory of a cgroup v2 hierarchy (ADR-007, D8).
    NotCgroup2(PathBuf),
    /// A cgroup parent lacks one of the cpu, io, memory and pids
    /// controllers for its children; the first one missing in that order
    /// (ADR-007, D8).
    ControllerMissing(&'static str),
    /// The limits are outside the kernel's bounds or cannot be meant
    /// (ADR-007, D8).
    InvalidLimits(&'static str),
    /// A cgroup name is not 1-255 bytes of `[A-Za-z0-9_-]` (ADR-007, D8).
    InvalidCgroupName(String),
    /// A file of a cgroup could not be opened, read or written.
    CgroupFile {
        /// The file, relative to its cgroup.
        file: &'static str,
        /// The `errno`.
        errno: i32,
    },
    /// A limit read back other than it was written (ADR-007, D8).
    CgroupReadBack {
        /// The file.
        file: &'static str,
        /// What the limit should read as.
        expected: String,
        /// What it read as.
        found: String,
    },
    /// A cgroup still held processes this long after `cgroup.kill`.
    CgroupKillTimeout(Duration),
    /// Tearing a sandbox cgroup down failed in at least one step; every
    /// step was still tried (ADR-007, D8).
    CgroupTeardown {
        /// The cgroup.
        path: PathBuf,
        /// Whether its directory is gone; if not, it is also listed by
        /// [`crate::leaked_cgroups`].
        removed: bool,
        /// Every failure, in order.
        errors: Vec<Error>,
    },
    /// The cgroup2 hierarchy is mounted without `nsdelegate`, so a sandbox
    /// could raise its own limits (ADR-007, D8); the mount's super options,
    /// or why they are unknown.
    NsdelegateMissing(String),
    /// The path's file system has no block device to limit with `io.max`
    /// (tmpfs, overlay).
    NoBlockDevice(PathBuf),
    /// The path's file system spans several devices (multi-device btrfs),
    /// so one `io.max` line would limit only one of them (ADR-007, D8).
    MultiDeviceFilesystem {
        /// The path.
        path: PathBuf,
        /// The number of devices, 0 if it could not be read.
        devices: u64,
    },
    /// The memory statistics keeper of a sandbox cgroup failed: in
    /// [`crate::Cgroup::create`], its first read of `memory.stat` read
    /// nothing, and no sandbox is created without it (ADR-007, D8). A read
    /// error after the start shows in [`crate::KeeperReport::failed`].
    StatsKeeper {
        /// The `errno`; `EIO` for a file that read as empty.
        errno: i32,
    },
    /// A bind source, root layer or overlay directory is on hugetlbfs, which
    /// would map huge pages past the memory limit without any flag the
    /// seccomp rows see (ADR-007, D2 and D7).
    HugetlbfsSource {
        /// The host path.
        path: PathBuf,
    },
    /// `/proc/sys/kernel/cap_last_cap` could not be read, so the bounding
    /// set cannot be dropped completely (ADR-007, D9).
    CapLastCap(String),
    /// The seccomp program could not be assembled (ADR-007, D2).
    SeccompProgram(crate::seccomp::AsmError),
    /// The kernel's seccomp notification structs are smaller than the
    /// ones this crate is built against (80, 24 and 64 bytes; ADR-043, D7):
    /// the sizes `SECCOMP_GET_NOTIF_SIZES` reported.
    NotifySizes {
        /// The notification struct.
        notif: u16,
        /// The reply struct.
        resp: u16,
        /// `struct seccomp_data`.
        data: u16,
    },
    /// The seccomp supervisor thread could not be started (ADR-043, D4);
    /// the child was killed and reaped.
    Supervisor {
        /// The `errno` of the thread's creation.
        errno: i32,
    },
    /// Landlock is not built into the kernel or not enabled (ADR-007, D10).
    LandlockUnavailable {
        /// The `errno` of `landlock_create_ruleset`.
        errno: i32,
    },
    /// The kernel's Landlock ABI is older than the runtime needs.
    LandlockAbiTooOld {
        /// The ABI found.
        found: u32,
        /// The ABI required.
        required: u32,
    },
    /// A ruleset asks for a right the ABI does not know; Landlock is never
    /// applied as a best effort (ADR-007, D10).
    LandlockUnsupported {
        /// The right.
        right: &'static str,
        /// The ABI.
        abi: u32,
    },
    /// A rule allows a right its ruleset does not handle, or none.
    LandlockRuleNotHandled {
        /// The right.
        right: &'static str,
    },
    /// An anchor (ADR-042, D3) was asked for something its spec or state
    /// does not allow: a fill point past the last mount, a root without a
    /// procfs or a minimal `/dev`, other ids than its pod's, an exec
    /// before the fill point was resumed, or an anchor that has failed.
    InvalidAnchor(&'static str),
}

impl Error {
    pub(crate) fn last(call: &'static str) -> Error {
        Error::Sys {
            call,
            errno: errno(),
        }
    }
}

/// The calling thread's `errno`. Reads thread-local storage only, so the
/// cloned child may call it.
pub(crate) fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn strerror(errno: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidId(id) => write!(f, "{id} is not a valid id (it is (uid_t)-1)"),
            Error::RunningAsRoot => write!(
                f,
                "refusing to run as uid or gid 0: an escape would yield host root"
            ),
            Error::SetuidCaller => write!(
                f,
                "refusing to run with real and effective ids that differ (setuid or setgid caller)"
            ),
            Error::RelativeProgram(p) => write!(f, "program path {} is not absolute", p.display()),
            Error::ZeroSetupTimeout => write!(f, "the setup timeout must not be zero"),
            Error::Nul(what) => write!(f, "{what} contains a NUL byte"),
            Error::InvalidEnvName(name) => {
                write!(f, "environment name {name:?} is empty or contains '='")
            }
            Error::Setup { step, index, errno } => {
                write!(
                    f,
                    "setup step {} (item {index}) failed: {}",
                    step.name(),
                    strerror(*errno)
                )
            }
            Error::SetupTimeout(t) => write!(f, "the child did not exec within {t:?}; killed"),
            Error::Protocol(p) => write!(f, "malformed setup report from the child: {p}"),
            Error::Sys { call, errno } => write!(f, "{call} failed: {}", strerror(*errno)),
            Error::HostUnsupported(missing) => {
                write!(f, "the host lacks what the sandbox needs:")?;
                for m in missing {
                    write!(f, " [{}] {m};", m.id().as_str())?;
                }
                Ok(())
            }
            Error::AlreadyWaited => write!(f, "the child was already waited for"),
            Error::NotMainThread => write!(
                f,
                "exit_main_thread was called on a thread that is not the main thread"
            ),
            Error::InvalidInsidePath { path, reason } => {
                write!(f, "sandbox path {path:?} {reason}")
            }
            Error::InvalidHostname(name) => {
                write!(f, "hostname {name:?} is not 1-64 bytes of [A-Za-z0-9.-]")
            }
            Error::InvalidRoot(reason) => write!(f, "invalid sandbox root: {reason}"),
            Error::InvalidMount { index, reason } => write!(f, "mount {index}: {reason}"),
            Error::MountOptionsTooLong { len } => write!(
                f,
                "overlay options take {len} bytes with the NUL, more than one page (4096)"
            ),
            Error::NotCgroup2(p) => write!(f, "{} is not on a cgroup v2 hierarchy", p.display()),
            Error::ControllerMissing(c) => write!(
                f,
                "the cgroup parent does not enable the {c} controller for its children (cgroup.subtree_control)"
            ),
            Error::InvalidLimits(reason) => write!(f, "invalid cgroup limits: {reason}"),
            Error::InvalidCgroupName(name) => {
                write!(
                    f,
                    "cgroup name {name:?} is not 1-255 bytes of [A-Za-z0-9_-]"
                )
            }
            Error::CgroupFile { file, errno } => {
                write!(f, "cgroup file {file}: {}", strerror(*errno))
            }
            Error::CgroupReadBack {
                file,
                expected,
                found,
            } => write!(
                f,
                "cgroup file {file} reads {found:?} after writing, expected {expected:?}"
            ),
            Error::CgroupKillTimeout(t) => {
                write!(f, "the cgroup still had processes {t:?} after cgroup.kill")
            }
            Error::CgroupTeardown {
                path,
                removed,
                errors,
            } => {
                let what = if *removed {
                    "was removed, with errors"
                } else {
                    "was not removed"
                };
                write!(f, "the sandbox cgroup {} {what}:", path.display())?;
                for err in errors {
                    write!(f, " {err};")?;
                }
                Ok(())
            }
            Error::NsdelegateMissing(options) => write!(
                f,
                "the cgroup v2 hierarchy is mounted without nsdelegate ({options}); \
                 refusing a cgroup parent, since a sandbox could raise its own limits"
            ),
            Error::NoBlockDevice(p) => {
                write!(
                    f,
                    "no block device holds {} (io.max needs one)",
                    p.display()
                )
            }
            Error::MultiDeviceFilesystem { path, devices: 0 } => write!(
                f,
                "the btrfs file system of {} has an unreadable device count; io.max needs exactly one device",
                path.display()
            ),
            Error::MultiDeviceFilesystem { path, devices } => write!(
                f,
                "the file system of {} spans {devices} devices; io.max would limit only one",
                path.display()
            ),
            Error::StatsKeeper { errno } => write!(
                f,
                "the memory statistics keeper of a sandbox cgroup failed (errno {errno}); \
                 no sandbox is created without it (ADR-007, D8)"
            ),
            Error::HugetlbfsSource { path } => write!(
                f,
                "{} is on hugetlbfs, which would map huge pages past the memory limit",
                path.display()
            ),
            Error::CapLastCap(why) => write!(
                f,
                "cannot read /proc/sys/kernel/cap_last_cap to drop every capability: {why}"
            ),
            Error::SeccompProgram(e) => write!(f, "the seccomp program does not assemble: {e}"),
            Error::NotifySizes { notif, resp, data } => write!(
                f,
                "the kernel's seccomp notification sizes {notif}/{resp}/{data} are below 80/24/64"
            ),
            Error::Supervisor { errno } => write!(
                f,
                "the seccomp supervisor thread could not start: {}; the child was killed",
                strerror(*errno)
            ),
            Error::LandlockUnavailable { errno } => {
                write!(f, "Landlock is unavailable: {}", strerror(*errno))
            }
            Error::LandlockAbiTooOld { found, required } => write!(
                f,
                "the kernel's Landlock ABI is {found}, the runtime needs {required}"
            ),
            Error::LandlockUnsupported { right, abi } => {
                write!(f, "Landlock ABI {abi} does not know the right {right}")
            }
            Error::LandlockRuleNotHandled { right } => write!(
                f,
                "a Landlock rule allows {right}, which its ruleset does not handle"
            ),
            Error::InvalidAnchor(why) => write!(f, "invalid anchor request: {why}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_keeper_error_text() {
        assert_eq!(
            Error::StatsKeeper { errno: libc::EIO }.to_string(),
            format!(
                "the memory statistics keeper of a sandbox cgroup failed (errno {}); \
                 no sandbox is created without it (ADR-007, D8)",
                libc::EIO
            )
        );
    }

    #[test]
    fn setup_error_renders_step_index_and_strerror() {
        let e = Error::Setup {
            step: Step::Signals,
            index: 13,
            errno: libc::EIO,
        };
        assert_eq!(
            e.to_string(),
            format!(
                "setup step signals (item 13) failed: {}",
                std::io::Error::from_raw_os_error(libc::EIO)
            )
        );
    }
}
