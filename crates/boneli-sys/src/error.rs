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
