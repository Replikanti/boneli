//! A classic BPF interpreter for the subset the policy uses, over a
//! `seccomp_data`: the oracle of the pure policy tests (ADR-007, D2). It
//! is written from the opcode definitions, not from the assembler, and
//! fails on anything outside the subset; the kernel rows (`seccomp_rows`)
//! run the real program in the kernel.

use boneli_sys::seccomp::{Arch, Insn, Policy};

/// The input of a filter: `struct seccomp_data`.
#[derive(Debug, Clone, Copy)]
pub struct Data {
    /// The syscall number.
    pub nr: u32,
    /// `AUDIT_ARCH_*`.
    pub arch: u32,
    /// The six arguments.
    pub args: [u64; 6],
}

impl Data {
    /// A call with zeroed arguments.
    pub fn call(arch: u32, nr: u32) -> Data {
        Data {
            nr,
            arch,
            args: [0; 6],
        }
    }

    /// The same call with `args[i] = value`.
    pub fn arg(mut self, i: usize, value: u64) -> Data {
        self.args[i] = value;
        self
    }

    /// The 32-bit word at byte offset `k` of the little-endian layout.
    fn word(&self, k: u32) -> u32 {
        match k {
            0 => self.nr,
            4 => self.arch,
            // instruction_pointer: the policy never reads it.
            8 | 12 => panic!("the program read instruction_pointer"),
            16..=63 if k.is_multiple_of(4) => {
                let arg = self.args[((k - 16) / 8) as usize];
                if (k - 16).is_multiple_of(8) {
                    arg as u32
                } else {
                    (arg >> 32) as u32
                }
            }
            _ => panic!("load from offset {k} outside seccomp_data"),
        }
    }
}

/// Runs `program` on `data` and returns the seccomp action.
pub fn run(program: &[Insn], data: &Data) -> u32 {
    let mut a: u32 = 0;
    let mut pc = 0usize;
    loop {
        let insn = program
            .get(pc)
            .unwrap_or_else(|| panic!("ran off the end at {pc}"));
        pc += 1;
        let jump = |taken: bool| usize::from(if taken { insn.jt } else { insn.jf });
        match insn.code {
            // BPF_LD | BPF_W | BPF_ABS
            0x20 => a = data.word(insn.k),
            // BPF_JMP | BPF_JEQ | BPF_K
            0x15 => pc += jump(a == insn.k),
            // BPF_JMP | BPF_JGT | BPF_K
            0x25 => pc += jump(a > insn.k),
            // BPF_JMP | BPF_JSET | BPF_K
            0x45 => pc += jump(a & insn.k != 0),
            // BPF_RET | BPF_K
            0x06 => return insn.k,
            other => panic!("opcode {other:#x} at {} outside the subset", pc - 1),
        }
    }
}

/// `SECCOMP_RET_ALLOW`.
pub const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;

/// The sandbox program for `arch`.
pub fn program(arch: Arch) -> Vec<Insn> {
    Policy::sandbox()
        .program(arch)
        .unwrap_or_else(|e| panic!("the {} program does not assemble: {e}", arch.name()))
        .instructions()
        .to_vec()
}
