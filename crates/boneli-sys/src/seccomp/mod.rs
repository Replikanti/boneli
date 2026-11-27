//! The seccomp-bpf policy of the sandbox (ADR-007, D2): the syscall
//! numbers it names per architecture ([`table`]), a classic BPF assembler
//! for the subset it uses ([`bpf`]) and the policy itself ([`policy`]).
//! `spawn` installs it as the child's last step before `execve` (D9).

pub mod bpf;
pub mod policy;
pub mod table;

pub use bpf::{AsmError, Insn};
pub use policy::{Policy, Program, Row, errno_action};
pub use table::{Arch, CEILING};
