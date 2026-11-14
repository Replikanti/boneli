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
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Length(n) => write!(f, "{n} bytes instead of 0 or 12"),
            ProtocolError::UnknownStep(code) => write!(f, "unknown step code {code}"),
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
    /// The path's file system has no block device to limit with `io.max`
    /// (tmpfs, overlay).
    NoBlockDevice(PathBuf),
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
            Error::NoBlockDevice(p) => {
                write!(
                    f,
                    "no block device holds {} (io.max needs one)",
                    p.display()
                )
            }
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

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
