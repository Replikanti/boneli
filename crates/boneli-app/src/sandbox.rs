//! The `Sandbox` port: pods of containers that share a workspace exchange,
//! a loopback network and a set of limits (ADR-004, D1; ADR-042, D2;
//! `docs/ARCHITECTURE.md`, "Isolation" and "Code architecture").
//!
//! A sandbox is a pod: one or more containers, each from its own root
//! filesystem, in one cgroup and one network namespace with loopback only.
//! The first container holds the workspace, the dependency layers and the
//! broker sockets. The workspace crosses the boundary only as bytes in the
//! `Git` adapter's snapshot format: copied in at `create`
//! ([`SandboxSpec::workspace`]) and read back by [`Sandbox::export`]. A
//! `Prepare` sandbox can seal directories of its workspace into a layer
//! that later sandboxes mount read-only ([`Sandbox::seal`]); nothing an
//! agent wrote can become such a layer, because only a `Prepare` sandbox
//! can be sealed (invariant 6).
//!
//! The limits of the pod are checked by one core function that every
//! adapter calls ([`SandboxSpec::check`], [`PodLimits::check`]), so the two
//! adapters cannot disagree on what a valid pod is.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::image::RootfsRef;
use crate::path::RelativePath;

/// The phase a sandbox serves (`docs/ARCHITECTURE.md`, "Isolation").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Building the environment: installing dependencies, loading data.
    /// The only phase that can be sealed into a layer.
    Prepare,
    /// The agent's work.
    Agent,
    /// The gates, in a clean sandbox from the base SHA and the diff only,
    /// without any broker socket.
    Verify,
}

/// Why a name is not a [`ContainerName`] or a [`BrokerName`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameProblem {
    /// No bytes.
    Empty,
    /// Longer than the grammar allows.
    TooLong {
        /// The name's length in bytes.
        length: usize,
        /// The longest name the grammar allows.
        max: usize,
    },
    /// A byte the grammar does not allow at this offset: anything outside
    /// ASCII lower-case letters, digits and `-`, a hyphen at either end of
    /// a container name, or anything but a letter first in a broker name.
    Character {
        /// The byte offset.
        offset: usize,
    },
    /// `localhost`, which every pod's `/etc/hosts` already names.
    Reserved,
}

impl fmt::Display for NameProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameProblem::Empty => f.write_str("the name is empty"),
            NameProblem::TooLong { length, max } => {
                write!(
                    f,
                    "the name is {length} bytes long, at most {max} are allowed"
                )
            }
            NameProblem::Character { offset } => {
                write!(
                    f,
                    "the name has a byte the grammar refuses at offset {offset}"
                )
            }
            NameProblem::Reserved => f.write_str("the name localhost is reserved"),
        }
    }
}

/// Whether `b` may appear inside a name: ASCII lower case, a digit or `-`.
fn name_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
}

/// The first byte of `name` that `allowed` refuses, as a problem.
fn grammar(name: &str, max: usize, allowed: impl Fn(usize, u8) -> bool) -> Result<(), NameProblem> {
    if name.is_empty() {
        return Err(NameProblem::Empty);
    }
    if name.len() > max {
        return Err(NameProblem::TooLong {
            length: name.len(),
            max,
        });
    }
    match name.bytes().enumerate().find(|&(k, b)| !allowed(k, b)) {
        Some((offset, _)) => Err(NameProblem::Character { offset }),
        None => Ok(()),
    }
}

/// The name of a container in a pod: an RFC 1123 label,
/// `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, and not `localhost`. It becomes
/// the container's host name and an alias in every `/etc/hosts` of the
/// pod, so the grammar is also what keeps a name from injecting a line
/// into those files (ADR-042, D2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContainerName(String);

impl ContainerName {
    /// The longest name, the RFC 1123 label limit.
    pub const MAX_LENGTH: usize = 63;

    /// Accepts exactly the grammar above, kept as written.
    pub fn parse(name: &str) -> Result<ContainerName, NameProblem> {
        let last = name.len().saturating_sub(1);
        grammar(name, Self::MAX_LENGTH, |k, b| {
            name_byte(b) && !(b == b'-' && (k == 0 || k == last))
        })?;
        if name == "localhost" {
            return Err(NameProblem::Reserved);
        }
        Ok(ContainerName(String::from(name)))
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name of a broker socket, `[a-z][a-z0-9-]{0,30}`: the socket is
/// bound at `/run/boneli/<name>.sock` (ADR-042, D2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BrokerName(String);

impl BrokerName {
    /// The longest name.
    pub const MAX_LENGTH: usize = 31;

    /// Accepts exactly the grammar above, kept as written.
    pub fn parse(name: &str) -> Result<BrokerName, NameProblem> {
        grammar(name, Self::MAX_LENGTH, |k, b| {
            if k == 0 {
                b.is_ascii_lowercase()
            } else {
                name_byte(b)
            }
        })?;
        Ok(BrokerName(String::from(name)))
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One container of a pod.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerSpec {
    /// Its name, unique in the pod.
    pub name: ContainerName,
    /// Its root filesystem, from the `ImageStore` port.
    pub rootfs: RootfsRef,
}

/// A broker socket on the host, bound read-only into the first container
/// for the shim (#9). Only `Prepare` and `Agent` sandboxes have brokers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Broker {
    /// Its name, unique in the pod.
    pub name: BrokerName,
    /// The absolute host path of the socket; the adapter refuses anything
    /// that is not a Unix socket, without following a symlink.
    pub socket: String,
}

/// A workspace in the `Git` adapter's snapshot format. Its `Debug` prints
/// only the length: the bytes are the customer's code.
#[derive(Clone, PartialEq, Eq)]
pub struct WorkspaceBytes(Vec<u8>);

impl WorkspaceBytes {
    /// Wraps the bytes of a snapshot.
    pub fn new(bytes: Vec<u8>) -> WorkspaceBytes {
        WorkspaceBytes(bytes)
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The number of bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for WorkspaceBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WorkspaceBytes({} bytes)", self.0.len())
    }
}

/// The sandbox's handle to a sealed layer. Opaque; the sandbox issues it,
/// and never issues the same handle twice.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LayerRef(String);

impl LayerRef {
    /// Wraps a handle the sandbox issued.
    pub fn new(reference: String) -> LayerRef {
        LayerRef(reference)
    }

    /// The handle as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The limits of a pod. Memory and the process count are the pod's, not a
/// command's, because the cgroup is the pod's (ADR-042, D2). All writable
/// storage is memory, so the storage sizes are part of `memory_bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PodLimits {
    /// The pod's memory, in bytes (`memory.max`).
    pub memory_bytes: u64,
    /// The pod's tasks (`pids.max`).
    pub processes: u32,
    /// The pod's CPU time per 100 ms period, in thousandths of a CPU;
    /// `cpu.max` is `cpu_millis × 100` µs over 100,000 µs.
    pub cpu_millis: u32,
    /// The size of the workspace in bytes.
    pub workspace_bytes: u64,
    /// The inodes of the workspace: every file, directory and dependency
    /// mount point, and the root.
    pub workspace_inodes: u64,
    /// The size of each container's `/tmp` in bytes.
    pub tmp_bytes: u64,
    /// The size of each container's `/dev/shm` in bytes.
    pub shm_bytes: u64,
}

/// Why pod limits do not fit a pod (ADR-042, D2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitProblem {
    /// A pod has at least one container.
    NoContainers,
    /// A limit is 0, which for a memory file system means unlimited.
    Zero {
        /// The field.
        field: &'static str,
    },
    /// The memory file systems can hold more than the pod's memory, so
    /// their caps would never fire before the OOM kill. `None` when the
    /// sum does not fit in 64 bits.
    MemoryBelowStorage {
        /// `workspace_bytes + n × (tmp_bytes + shm_bytes)`.
        storage: Option<u64>,
        /// `memory_bytes`.
        memory: u64,
    },
    /// Fewer tasks than one anchor per container plus the two an exec
    /// needs while it starts.
    TooFewProcesses {
        /// `n + 2`.
        needed: u64,
        /// `processes`.
        processes: u32,
    },
    /// A CPU quota below the kernel's floor of 1,000 µs.
    CpuBelowFloor {
        /// `cpu_millis`.
        cpu_millis: u32,
    },
}

impl fmt::Display for LimitProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitProblem::NoContainers => f.write_str("a pod needs at least one container"),
            LimitProblem::Zero { field } => {
                write!(f, "{field} is 0, which would leave it unlimited")
            }
            LimitProblem::MemoryBelowStorage {
                storage: Some(storage),
                memory,
            } => write!(
                f,
                "the memory file systems hold up to {storage} bytes, more than the pod's \
                 memory_bytes {memory}"
            ),
            LimitProblem::MemoryBelowStorage {
                storage: None,
                memory,
            } => write!(
                f,
                "the memory file systems hold more than 2^64 bytes, more than the pod's \
                 memory_bytes {memory}"
            ),
            LimitProblem::TooFewProcesses { needed, processes } => write!(
                f,
                "processes is {processes}, the pod needs at least {needed}: one anchor per \
                 container and two for an exec while it starts"
            ),
            LimitProblem::CpuBelowFloor { cpu_millis } => write!(
                f,
                "cpu_millis {cpu_millis} gives a quota below the kernel's floor of 1,000 µs \
                 per 100,000 µs"
            ),
        }
    }
}

impl PodLimits {
    /// The lowest `cpu_millis`: a quota of 1,000 µs per period of
    /// 100,000 µs, the kernel's floor for `cpu.max`.
    pub const MIN_CPU_MILLIS: u32 = 10;

    /// Whether the limits fit a pod of `containers` containers: every
    /// size above 0, the memory file systems within `memory_bytes`, one
    /// task per container's anchor plus two for an exec while it starts,
    /// and a CPU quota at the kernel's floor or above (ADR-042, D2).
    pub fn check(&self, containers: usize) -> Result<(), LimitProblem> {
        if containers == 0 {
            return Err(LimitProblem::NoContainers);
        }
        let sizes = [
            ("memory_bytes", self.memory_bytes),
            ("processes", u64::from(self.processes)),
            ("cpu_millis", u64::from(self.cpu_millis)),
            ("workspace_bytes", self.workspace_bytes),
            ("workspace_inodes", self.workspace_inodes),
            ("tmp_bytes", self.tmp_bytes),
            ("shm_bytes", self.shm_bytes),
        ];
        if let Some((field, _)) = sizes.iter().find(|(_, value)| *value == 0) {
            return Err(LimitProblem::Zero { field });
        }
        // A pod of more than 2^64 containers does not exist; saturating
        // keeps the arithmetic below checked all the same.
        let n = u64::try_from(containers).unwrap_or(u64::MAX);
        let storage = self
            .tmp_bytes
            .checked_add(self.shm_bytes)
            .and_then(|each| each.checked_mul(n))
            .and_then(|all| all.checked_add(self.workspace_bytes));
        if storage.is_none_or(|storage| storage > self.memory_bytes) {
            return Err(LimitProblem::MemoryBelowStorage {
                storage,
                memory: self.memory_bytes,
            });
        }
        let needed = n.saturating_add(2);
        if u64::from(self.processes) < needed {
            return Err(LimitProblem::TooFewProcesses {
                needed,
                processes: self.processes,
            });
        }
        if self.cpu_millis < Self::MIN_CPU_MILLIS {
            return Err(LimitProblem::CpuBelowFloor {
                cpu_millis: self.cpu_millis,
            });
        }
        Ok(())
    }
}

/// What a sandbox is created from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxSpec {
    /// The phase.
    pub phase: Phase,
    /// The containers; the first holds the workspace, the dependencies
    /// and the brokers.
    pub containers: Vec<ContainerSpec>,
    /// The workspace copied in before any process runs, in the `Git`
    /// adapter's snapshot format.
    pub workspace: WorkspaceBytes,
    /// Sealed layers, each mounted read-only at its paths under the
    /// workspace. A path at or above a file of the workspace is refused.
    pub dependencies: Vec<LayerRef>,
    /// The broker sockets; a `Verify` sandbox has none.
    pub brokers: Vec<Broker>,
    /// The pod's limits.
    pub limits: PodLimits,
    /// The user every process runs as inside: 0 or the image's user, never
    /// 4,294,967,295, the "no change" value of `setresuid` (ADR-007, D1).
    pub user: u32,
}

/// Why a [`SandboxSpec`] is refused before anything is created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecProblem {
    /// The limits do not fit the pod.
    Limits(LimitProblem),
    /// Two containers have this name.
    DuplicateContainer(ContainerName),
    /// Two brokers have this name.
    DuplicateBroker(BrokerName),
    /// This layer is listed twice.
    DuplicateDependency(LayerRef),
    /// The broker's socket is not an absolute path without NUL.
    BrokerSocket(BrokerName),
    /// A `Verify` sandbox has a broker ("without either socket").
    VerifyWithBrokers,
    /// The user is 4,294,967,295.
    User,
}

impl fmt::Display for SpecProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpecProblem::Limits(problem) => write!(f, "the pod limits: {problem}"),
            SpecProblem::DuplicateContainer(name) => {
                write!(f, "two containers are named {:?}", name.as_str())
            }
            SpecProblem::DuplicateBroker(name) => {
                write!(f, "two brokers are named {:?}", name.as_str())
            }
            SpecProblem::DuplicateDependency(layer) => {
                write!(f, "the layer {:?} is listed twice", layer.as_str())
            }
            SpecProblem::BrokerSocket(name) => write!(
                f,
                "the socket of broker {:?} is not an absolute path without NUL",
                name.as_str()
            ),
            SpecProblem::VerifyWithBrokers => {
                f.write_str("a verify sandbox runs without any broker socket")
            }
            SpecProblem::User => {
                f.write_str("the user 4294967295 is the \"no change\" id and cannot be mapped")
            }
        }
    }
}

/// The first value that occurs twice, by `key`.
fn first_duplicate<T, K: PartialEq>(items: &[T], key: impl Fn(&T) -> &K) -> Option<&T> {
    items
        .iter()
        .enumerate()
        .find(|(k, item)| items[..*k].iter().any(|before| key(before) == key(item)))
        .map(|(_, item)| item)
}

impl SandboxSpec {
    /// Everything about the spec that needs no file system: the pod
    /// limits for its number of containers, unique container, broker and
    /// layer names, absolute broker sockets, no broker in a `Verify`
    /// sandbox, and a user that can be mapped. Every adapter calls it
    /// first in `create`.
    pub fn check(&self) -> Result<(), SpecProblem> {
        self.limits
            .check(self.containers.len())
            .map_err(SpecProblem::Limits)?;
        if let Some(c) = first_duplicate(&self.containers, |c| &c.name) {
            return Err(SpecProblem::DuplicateContainer(c.name.clone()));
        }
        if let Some(b) = first_duplicate(&self.brokers, |b| &b.name) {
            return Err(SpecProblem::DuplicateBroker(b.name.clone()));
        }
        if let Some(layer) = first_duplicate(&self.dependencies, |l| l) {
            return Err(SpecProblem::DuplicateDependency(layer.clone()));
        }
        if let Some(b) = self
            .brokers
            .iter()
            .find(|b| !b.socket.starts_with('/') || b.socket.contains('\u{0}'))
        {
            return Err(SpecProblem::BrokerSocket(b.name.clone()));
        }
        if self.phase == Phase::Verify && !self.brokers.is_empty() {
            return Err(SpecProblem::VerifyWithBrokers);
        }
        if self.user == u32::MAX {
            return Err(SpecProblem::User);
        }
        Ok(())
    }
}

/// The first two paths of `paths` that are equal or where one lies beneath
/// the other (`node_modules` and `node_modules/x`), in the order given;
/// `None` when no two overlap. Two dependency paths that overlap would
/// mount one layer over the other (ADR-042, D6).
pub fn overlapping_paths(paths: &[RelativePath]) -> Option<(&RelativePath, &RelativePath)> {
    let beneath = |inner: &str, outer: &str| {
        inner
            .strip_prefix(outer)
            .is_some_and(|rest| rest.starts_with('/'))
    };
    paths.iter().enumerate().find_map(|(k, a)| {
        paths[k + 1..]
            .iter()
            .find(|b| a == *b || beneath(a.as_str(), b.as_str()) || beneath(b.as_str(), a.as_str()))
            .map(|b| (a, b))
    })
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
    /// The container it runs in.
    pub container: ContainerName,
    /// The program, as the sandbox resolves it.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// The only environment variables it gets, as name and value.
    pub environment: Vec<(String, String)>,
}

/// The limits of one command; memory and processes are the pod's
/// ([`PodLimits`]). The values are chosen by #13.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Wall time, in milliseconds; past it the command is killed and ends
    /// with [`ExitStatus::TimedOut`].
    pub wall_ms: u64,
    /// The most bytes each of its two output streams may carry; one byte
    /// more kills the command and fails the exec, so a cut transcript is
    /// never returned as whole.
    pub output_bytes: u64,
}

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// It exited with this code.
    Code(i32),
    /// A signal with this number ended it.
    Signal(i32),
    /// The sandbox killed it at its wall limit. Not a `Signal(9)`, which
    /// the workload can raise itself.
    TimedOut,
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
    /// The sandbox could not be created or reached, could not start the
    /// command, or refused what was asked.
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

/// Isolated pods. Each sandbox has its own workspace: a file written in
/// one is never visible in another.
pub trait Sandbox {
    /// Creates a pod from the spec, copies the workspace in and mounts the
    /// dependencies, and returns a handle never issued before. A spec that
    /// [`SandboxSpec::check`] refuses, a malformed workspace, an unknown
    /// or released layer, and a dependency path that overlaps another or
    /// lies at or above a file of the workspace are `Failed`, before any
    /// process runs.
    fn create(&self, spec: &SandboxSpec) -> Result<SandboxId, SandboxError>;

    /// Runs a command inside the sandbox, in its container, within the
    /// limits. A container the pod does not have is `Failed`.
    fn exec(
        &self,
        id: &SandboxId,
        command: &Command,
        limits: &Limits,
    ) -> Result<ExecResult, SandboxError>;

    /// Starts a service: the command runs until the sandbox is destroyed,
    /// and its output is discarded.
    fn start(&self, id: &SandboxId, command: &Command) -> Result<(), SandboxError>;

    /// The content of a file in the sandbox's workspace. The path is a
    /// [`RelativePath`], so it cannot leave the workspace lexically (no
    /// absolute path, no `..`). The rule does not resolve symlinks: the
    /// adapter must not follow a symlink planted in the workspace out of
    /// it, at the path or at any of its parents (ADR-004, D11).
    fn copy_out(&self, id: &SandboxId, path: &RelativePath) -> Result<Vec<u8>, SandboxError>;

    /// The workspace in the `Git` adapter's snapshot format, without the
    /// dependency layers mounted into it. A sandbox that nothing wrote to
    /// exports the workspace it was created from, byte for byte.
    fn export(&self, id: &SandboxId) -> Result<Vec<u8>, SandboxError>;

    /// Seals these directories of a `Prepare` sandbox's workspace into a
    /// new layer, with a handle never issued before. Any other phase, no
    /// path, and two paths that overlap are `Failed`.
    fn seal(&self, id: &SandboxId, paths: &[RelativePath]) -> Result<LayerRef, SandboxError>;

    /// Removes a sealed layer; from then on a spec that names it is
    /// `Failed`. A layer a live sandbox mounts, and one that is unknown or
    /// already released, are `Failed`.
    fn release(&self, layer: &LayerRef) -> Result<(), SandboxError>;

    /// Destroys the sandbox; its handle is unknown from then on.
    fn destroy(&self, id: &SandboxId) -> Result<(), SandboxError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    /// The limits of the plan's sum example: 2 GiB of memory, a 512 MiB
    /// workspace, 256 MiB `/tmp` and 64 MiB `/dev/shm` per container.
    fn limits() -> PodLimits {
        PodLimits {
            memory_bytes: 2_147_483_648,
            processes: 64,
            cpu_millis: 1_000,
            workspace_bytes: 536_870_912,
            workspace_inodes: 100_000,
            tmp_bytes: 268_435_456,
            shm_bytes: 67_108_864,
        }
    }

    fn container(name: &str) -> ContainerSpec {
        ContainerSpec {
            name: ContainerName::parse(name).expect("a valid name"),
            rootfs: RootfsRef::new(String::from("rootfs-1")),
        }
    }

    fn broker(name: &str) -> Broker {
        Broker {
            name: BrokerName::parse(name).expect("a valid name"),
            socket: String::from("/run/brokers/sql.sock"),
        }
    }

    fn spec() -> SandboxSpec {
        SandboxSpec {
            phase: Phase::Agent,
            containers: vec![container("app"), container("db")],
            workspace: WorkspaceBytes::new(Vec::new()),
            dependencies: vec![],
            brokers: vec![broker("sql")],
            limits: limits(),
            user: 1000,
        }
    }

    fn path(text: &str) -> RelativePath {
        RelativePath::parse(text).expect("a valid path")
    }

    #[test]
    fn pod_container_count_bounds() {
        assert_eq!(limits().check(0), Err(LimitProblem::NoContainers));
        assert_eq!(limits().check(1), Ok(()));
        let empty = SandboxSpec {
            containers: vec![],
            ..spec()
        };
        assert_eq!(
            empty.check(),
            Err(SpecProblem::Limits(LimitProblem::NoContainers))
        );
    }

    #[test]
    fn processes_cover_anchors_and_one_exec() {
        let with = |processes| PodLimits {
            processes,
            ..limits()
        };
        assert_eq!(with(4).check(2), Ok(()));
        assert_eq!(
            with(3).check(2),
            Err(LimitProblem::TooFewProcesses {
                needed: 4,
                processes: 3
            })
        );
    }

    #[test]
    fn cpu_quota_floor() {
        let with = |cpu_millis| PodLimits {
            cpu_millis,
            ..limits()
        };
        // 10 × 100 µs = 1,000 µs, the kernel's floor; 9 gives 900 µs.
        assert_eq!(with(10).check(1), Ok(()));
        assert_eq!(
            with(9).check(1),
            Err(LimitProblem::CpuBelowFloor { cpu_millis: 9 })
        );
    }

    #[test]
    fn tmpfs_sum_within_memory() {
        // 536,870,912 + 2 × (268,435,456 + 67,108,864) = 1,207,959,552.
        assert_eq!(limits().check(2), Ok(()));
        let big_tmp = PodLimits {
            tmp_bytes: 536_870_912,
            ..limits()
        };
        // 536,870,912 + 3 × (536,870,912 + 67,108,864) = 2,348,810,240.
        assert_eq!(
            big_tmp.check(3),
            Err(LimitProblem::MemoryBelowStorage {
                storage: Some(2_348_810_240),
                memory: 2_147_483_648,
            })
        );
        // Exactly the memory is accepted, one byte more is not.
        let exact = PodLimits {
            memory_bytes: 1_207_959_552,
            ..limits()
        };
        assert_eq!(exact.check(2), Ok(()));
        let over = PodLimits {
            memory_bytes: 1_207_959_551,
            ..limits()
        };
        assert!(matches!(
            over.check(2),
            Err(LimitProblem::MemoryBelowStorage { .. })
        ));
        // A sum past 2^64 is refused, not wrapped.
        let huge = PodLimits {
            memory_bytes: u64::MAX,
            tmp_bytes: u64::MAX / 2,
            shm_bytes: u64::MAX / 2,
            ..limits()
        };
        assert_eq!(
            huge.check(2),
            Err(LimitProblem::MemoryBelowStorage {
                storage: None,
                memory: u64::MAX,
            })
        );
    }

    #[test]
    fn zero_sizes_refused() {
        type Zero = fn(&mut PodLimits);
        let fields: [(&str, Zero); 7] = [
            ("memory_bytes", |l| l.memory_bytes = 0),
            ("processes", |l| l.processes = 0),
            ("cpu_millis", |l| l.cpu_millis = 0),
            ("workspace_bytes", |l| l.workspace_bytes = 0),
            ("workspace_inodes", |l| l.workspace_inodes = 0),
            ("tmp_bytes", |l| l.tmp_bytes = 0),
            ("shm_bytes", |l| l.shm_bytes = 0),
        ];
        for (field, zero) in fields {
            let mut l = limits();
            zero(&mut l);
            assert_eq!(l.check(1), Err(LimitProblem::Zero { field }));
        }
    }

    #[test]
    fn container_name_length() {
        let longest = "a".repeat(63);
        assert!(ContainerName::parse(&longest).is_ok());
        assert_eq!(
            ContainerName::parse(&"a".repeat(64)),
            Err(NameProblem::TooLong {
                length: 64,
                max: 63
            })
        );
        assert!(ContainerName::parse("a").is_ok());
        assert!(ContainerName::parse("0").is_ok());
        assert!(ContainerName::parse("a-0").is_ok());
    }

    #[test]
    fn container_name_grammar() {
        let refused = [
            ("", NameProblem::Empty),
            ("localhost", NameProblem::Reserved),
            ("App", NameProblem::Character { offset: 0 }),
            ("-db", NameProblem::Character { offset: 0 }),
            ("db-", NameProblem::Character { offset: 2 }),
            ("-", NameProblem::Character { offset: 0 }),
            ("d b", NameProblem::Character { offset: 1 }),
            ("db\n", NameProblem::Character { offset: 2 }),
            ("db\u{0}", NameProblem::Character { offset: 2 }),
            ("a.b", NameProblem::Character { offset: 1 }),
            ("a_b", NameProblem::Character { offset: 1 }),
            // Cyrillic а (U+0430) and е (U+0435) look like a and e.
            ("\u{430}pp", NameProblem::Character { offset: 0 }),
            ("db\u{435}", NameProblem::Character { offset: 2 }),
            // Zero-width space and no-break space.
            ("d\u{200b}b", NameProblem::Character { offset: 1 }),
            ("d\u{a0}b", NameProblem::Character { offset: 1 }),
            ("\tdb", NameProblem::Character { offset: 0 }),
        ];
        for (name, problem) in refused {
            assert_eq!(ContainerName::parse(name), Err(problem), "{name:?}");
        }
        // Only the exact name is reserved.
        assert!(ContainerName::parse("localhost0").is_ok());
        assert!(ContainerName::parse("local-host").is_ok());
    }

    #[test]
    fn broker_name_grammar() {
        let refused = [
            ("", NameProblem::Empty),
            ("0sql", NameProblem::Character { offset: 0 }),
            ("-sql", NameProblem::Character { offset: 0 }),
            ("Sql", NameProblem::Character { offset: 0 }),
            ("sql\n", NameProblem::Character { offset: 3 }),
            ("sql.sock", NameProblem::Character { offset: 3 }),
            ("s/q", NameProblem::Character { offset: 1 }),
            ("s q", NameProblem::Character { offset: 1 }),
            ("\u{455}ql", NameProblem::Character { offset: 0 }),
            ("sq\u{200b}l", NameProblem::Character { offset: 2 }),
        ];
        for (name, problem) in refused {
            assert_eq!(BrokerName::parse(name), Err(problem), "{name:?}");
        }
        assert!(BrokerName::parse(&"s".repeat(31)).is_ok());
        assert_eq!(
            BrokerName::parse(&"s".repeat(32)),
            Err(NameProblem::TooLong {
                length: 32,
                max: 31
            })
        );
        assert!(BrokerName::parse("s").is_ok());
        assert!(BrokerName::parse("sql-").is_ok());
        assert!(BrokerName::parse("localhost").is_ok());
    }

    #[test]
    fn spec_duplicates_refused() {
        assert_eq!(spec().check(), Ok(()));
        let twins = SandboxSpec {
            containers: vec![container("app"), container("db"), container("app")],
            ..spec()
        };
        assert_eq!(
            twins.check(),
            Err(SpecProblem::DuplicateContainer(
                ContainerName::parse("app").expect("valid")
            ))
        );
        let brokers = SandboxSpec {
            brokers: vec![broker("sql"), broker("logs"), broker("sql")],
            ..spec()
        };
        assert_eq!(
            brokers.check(),
            Err(SpecProblem::DuplicateBroker(
                BrokerName::parse("sql").expect("valid")
            ))
        );
        let layer = LayerRef::new(String::from("layer-1"));
        let layers = SandboxSpec {
            dependencies: vec![layer.clone(), layer.clone()],
            ..spec()
        };
        assert_eq!(layers.check(), Err(SpecProblem::DuplicateDependency(layer)));
    }

    #[test]
    fn dependency_paths_overlap_refused() {
        let paths = |list: &[&str]| list.iter().map(|p| path(p)).collect::<Vec<_>>();
        let nested = paths(&["node_modules", "node_modules/x"]);
        assert_eq!(overlapping_paths(&nested), Some((&nested[0], &nested[1])));
        let reversed = paths(&["vendor", "node_modules/x", "node_modules"]);
        assert_eq!(
            overlapping_paths(&reversed),
            Some((&reversed[1], &reversed[2]))
        );
        let equal = paths(&["a", "b", "a"]);
        assert_eq!(overlapping_paths(&equal), Some((&equal[0], &equal[2])));
        // A shared prefix is not nesting.
        let siblings = paths(&[
            "node_modules",
            "node_modules-x",
            "node_modulesx",
            "x/node_modules",
        ]);
        assert_eq!(overlapping_paths(&siblings), None);
        assert_eq!(overlapping_paths(&[]), None);
    }

    #[test]
    fn verify_has_no_brokers() {
        let verify = SandboxSpec {
            phase: Phase::Verify,
            ..spec()
        };
        assert_eq!(verify.check(), Err(SpecProblem::VerifyWithBrokers));
        let clean = SandboxSpec {
            brokers: vec![],
            ..verify
        };
        assert_eq!(clean.check(), Ok(()));
        for phase in [Phase::Prepare, Phase::Agent] {
            assert_eq!(SandboxSpec { phase, ..spec() }.check(), Ok(()));
        }
    }

    #[test]
    fn broker_socket_and_user() {
        for socket in ["run/sql.sock", "", "/run/sql\u{0}.sock"] {
            let s = SandboxSpec {
                brokers: vec![Broker {
                    socket: String::from(socket),
                    ..broker("sql")
                }],
                ..spec()
            };
            assert_eq!(
                s.check(),
                Err(SpecProblem::BrokerSocket(
                    BrokerName::parse("sql").expect("valid")
                )),
                "{socket:?}"
            );
        }
        assert_eq!(
            SandboxSpec {
                user: u32::MAX,
                ..spec()
            }
            .check(),
            Err(SpecProblem::User)
        );
        for user in [0, 999, u32::MAX - 1] {
            assert_eq!(SandboxSpec { user, ..spec() }.check(), Ok(()));
        }
    }

    #[test]
    fn workspace_bytes_debug_is_its_length() {
        let w = WorkspaceBytes::new(b"secret source".to_vec());
        assert_eq!(format!("{w:?}"), "WorkspaceBytes(13 bytes)");
        assert_eq!(w.len(), 13);
        assert!(!w.is_empty());
        assert!(!format!("{:?}", spec()).contains("secret"));
    }

    /// Every problem has a detail that is not blank (ADR-004, D4).
    #[test]
    fn failure_details_are_never_blank() {
        let name = || ContainerName::parse("app").expect("valid");
        let bname = || BrokerName::parse("sql").expect("valid");
        let limits = [
            LimitProblem::NoContainers,
            LimitProblem::Zero { field: "tmp_bytes" },
            LimitProblem::MemoryBelowStorage {
                storage: Some(2),
                memory: 1,
            },
            LimitProblem::MemoryBelowStorage {
                storage: None,
                memory: 1,
            },
            LimitProblem::TooFewProcesses {
                needed: 4,
                processes: 3,
            },
            LimitProblem::CpuBelowFloor { cpu_millis: 9 },
        ];
        let mut texts: Vec<String> = limits.iter().map(|p| format!("{p}")).collect();
        texts.extend(
            limits
                .iter()
                .map(|p| format!("{}", SpecProblem::Limits(*p))),
        );
        for p in [
            SpecProblem::DuplicateContainer(name()),
            SpecProblem::DuplicateBroker(bname()),
            SpecProblem::DuplicateDependency(LayerRef::new(String::from("layer-1"))),
            SpecProblem::BrokerSocket(bname()),
            SpecProblem::VerifyWithBrokers,
            SpecProblem::User,
        ] {
            texts.push(format!("{p}"));
        }
        for p in [
            NameProblem::Empty,
            NameProblem::TooLong {
                length: 64,
                max: 63,
            },
            NameProblem::Character { offset: 0 },
            NameProblem::Reserved,
        ] {
            texts.push(format!("{p}"));
        }
        for text in texts {
            assert!(!boneli_domain::values::is_blank(&text), "{text:?}");
        }
    }
}
