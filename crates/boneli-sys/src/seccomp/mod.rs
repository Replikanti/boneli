//! The seccomp-bpf policy of the sandbox (ADR-007, D2): the syscall
//! numbers it names per architecture ([`table`]), a classic BPF assembler
//! and evaluator for the subset it uses ([`bpf`]) and the policy itself
//! ([`policy`]). `spawn` installs it as the child's last step before
//! `execve` (D9).
//!
//! ADR-043 (proposed) answers the errno rows through a supervisor that
//! records each denied call: the notifying program
//! ([`Policy::notifying_program`]), the record of denied calls
//! ([`record`]) and the supervisor's deny-only reply ([`notify`]). Until
//! the supervisor lands, `spawn` installs the plain program.

pub mod bpf;
pub mod notify;
pub mod policy;
pub mod record;
pub mod table;

pub use bpf::{AsmError, Data, Insn, Outcome, evaluate};
pub use notify::{Buffers, Decision, Deny, Notification, decide};
pub use policy::{Policy, Program, Row, errno_action};
pub use record::{
    Call, Denial, Denials, Key, Occurrence, Record, Selector, Status, SupervisorFailure,
    describe_call, escape_comm, parse_status,
};
pub use table::{Arch, CEILING};
