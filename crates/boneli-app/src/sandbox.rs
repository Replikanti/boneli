//! The `Sandbox` port: isolated workspaces that run commands (ADR-004, D1;
//! `docs/ARCHITECTURE.md`, "Isolation" and "Code architecture").
//!
//! Minimal on purpose: the real adapter (#8) and the environments (#13)
//! choose the limits, and may add operations and clauses under the
//! extension rule of ADR-004.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::image::RootfsRef;
use crate::path::RelativePath;

/// The phase a sandbox serves (`docs/ARCHITECTURE.md`, "Isolation").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Building the environment: installing dependencies, loading data.
    Prepare,
    /// The agent's work.
    Agent,
    /// The gates, in a clean sandbox from the base SHA and the diff only.
    Verify,
}

/// What a sandbox is created from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxSpec {
    /// The phase.
    pub phase: Phase,
    /// The root filesystem, from the `ImageStore` port.
    pub rootfs: RootfsRef,
}

/// The sandbox's handle. Opaque; the sandbox issues it, and never issues
/// the same handle twice, so a stale handle cannot reach a newer sandbox.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SandboxId(String);

impl SandboxId {
    /// Wraps a handle the sandbox issued.
    pub fn new(id: String) -> SandboxId {
        SandboxId(id)
    }

    /// The handle as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A command to run inside a sandbox. The field is called `environment`,
/// not by the usual short name, which the core token scan bans (ADR-001).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// The program, as the sandbox resolves it.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// The only environment variables it gets, as name and value.
    pub environment: Vec<(String, String)>,
}

/// The limits of one command. The values are chosen by #8 and #13.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Wall time, in milliseconds.
    pub wall_ms: u64,
    /// Memory, in bytes.
    pub memory_bytes: u64,
    /// The number of processes.
    pub processes: u32,
}

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// It exited with this code.
    Code(i32),
    /// A signal with this number ended it.
    Signal(i32),
}

/// What a command did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecResult {
    /// How it ended.
    pub status: ExitStatus,
    /// Its standard output.
    pub stdout: Vec<u8>,
    /// Its error output.
    pub stderr: Vec<u8>,
}

/// Why the sandbox did not do what was asked. A command that ran and
/// failed is not an error: it is an [`ExecResult`] with its status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxError {
    /// No sandbox with this handle exists: never created, or destroyed.
    UnknownSandbox,
    /// The workspace has no file at this path.
    NotFound,
    /// The sandbox could not be created or reached, or could not start the
    /// command.
    Failed {
        /// What went wrong, as the sandbox reports it.
        detail: String,
    },
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SandboxError::UnknownSandbox => f.write_str("unknown sandbox"),
            SandboxError::NotFound => f.write_str("the workspace has no file at this path"),
            SandboxError::Failed { detail } => write!(f, "the sandbox failed: {detail}"),
        }
    }
}

impl core::error::Error for SandboxError {}

/// Isolated workspaces. Each sandbox has its own workspace: a file written
/// in one is never visible in another.
pub trait Sandbox {
    /// Creates a sandbox and returns a handle never issued before.
    fn create(&self, spec: &SandboxSpec) -> Result<SandboxId, SandboxError>;

    /// Runs a command inside the sandbox, within the limits.
    fn exec(
        &self,
        id: &SandboxId,
        command: &Command,
        limits: &Limits,
    ) -> Result<ExecResult, SandboxError>;

    /// The content of a file in the sandbox's workspace. The path is a
    /// [`RelativePath`], so it cannot leave the workspace lexically (no
    /// absolute path, no `..`). The rule does not resolve symlinks: the
    /// adapter must not follow a symlink planted in the workspace out of
    /// it (ADR-004, D11).
    fn copy_out(&self, id: &SandboxId, path: &RelativePath) -> Result<Vec<u8>, SandboxError>;

    /// Destroys the sandbox; its handle is unknown from then on.
    fn destroy(&self, id: &SandboxId) -> Result<(), SandboxError>;
}
