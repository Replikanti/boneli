//! Boneli application layer.
//!
//! Use cases (`BuildEnvironment`, `OnboardRepo`, `DebugTicket`, `BuildCase`,
//! `RunBench`) and the ports they drive, as synchronous traits. Depends only
//! on `boneli-domain`; adapters implement the ports in their own crates.
//! The crate is `#![no_std]` with `alloc` (ADR-001).
//!
//! Design: `docs/ARCHITECTURE.md`, section "Code architecture"; the ports,
//! the contract suites and `DebugTicket` are fixed in ADR-004
//! (`docs/adr/004-ports-in-memory-adapters-and-debug-ticket.md`).
//!
//! The ports are object-safe traits with `&self` methods, one module each:
//! [`Agent`], [`Verifier`], [`Forge`], [`Git`], [`EventStore`],
//! [`Evidence`], [`Clock`] and [`Ids`], which [`DebugTicket`] drives
//! through one run (`Git` for the patch check, ADR-023), and [`Sandbox`],
//! [`ImageStore`] and [`DataSnapshot`], which the verifier, the
//! environments and the agent's workspace build on. Paths
//! that ports take are [`RelativePath`]s, the citation path rule of the
//! domain; the paths a tree holds are [`TreePath`]s, which also carry
//! names an agent cannot cite (ADR-018). An [`ImageRef`] carries who
//! chose it ([`ImageOrigin`], ADR-032). [`contract`] holds the suites every adapter of a port must pass;
//! the in-memory adapters live in the `boneli-memory` crate.
#![no_std]
#![doc(test(attr(forbid(unsafe_code))))]

extern crate alloc;

pub mod agent;
pub mod clock;
pub mod contract;
pub mod data;
pub mod debug_ticket;
pub mod evidence;
pub mod forge;
pub mod git;
pub mod ids;
pub mod image;
pub mod job;
pub mod path;
pub mod sandbox;
pub mod store;
pub mod verifier;

pub use agent::{
    Agent, FixRequest, PreviousTriage, ReproductionRequest, RootCauseReport, RootCauseRequest,
    TriageReport, TriageRequest, Written,
};
pub use clock::Clock;
pub use data::{DataError, DataSnapshot, DatabaseCopy, SnapshotId, SnapshotSource};
pub use debug_ticket::{
    DebugReport, DebugRequest, DebugTicket, DebugTicketError, PreviousRunError,
};
pub use evidence::{Evidence, EvidenceError};
pub use forge::{Attached, Forge, ForgeRef, PullRequest};
pub use git::{BranchName, CheckoutId, CommitInfo, Git, GitError, RepoUrl};
pub use ids::Ids;
pub use image::{ImageError, ImageExemption, ImageOrigin, ImageRef, ImageStore, Pulled, RootfsRef};
pub use job::{JobFailure, MAX_DETAIL_BYTES, cap_detail};
pub use path::{RelativePath, TreePath, TreePathProblem, Uncitable};
pub use sandbox::{
    Broker, BrokerName, Command, ContainerName, ContainerSpec, ExecResult, ExitStatus, LayerRef,
    LimitProblem, Limits, NameProblem, Phase, PodLimits, Sandbox, SandboxError, SandboxId,
    SandboxSpec, SpecProblem, WorkspaceBytes, overlapping_paths,
};
pub use store::{EventStore, RunLog, RunStart, StoreError, replay};
pub use verifier::Verifier;
