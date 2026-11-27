//! A classic BPF assembler for the subset the seccomp policy uses
//! (ADR-007, D2): `LD|W|ABS`, `JMP|JEQ`, `JMP|JGT` and `JMP|JSET` with a
//! constant, and `RET` with a constant. Jumps go forward to labels; the
//! assembler checks the kernel's limits (`BPF_MAXINSNS`, 8-bit offsets)
//! instead of letting the kernel refuse the program at install.

/// One classic BPF instruction, laid out as `struct sock_filter`
/// (`include/uapi/linux/filter.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    /// The opcode.
    pub code: u16,
    /// The jump offset if the condition holds.
    pub jt: u8,
    /// The jump offset if it does not.
    pub jf: u8,
    /// The constant operand.
    pub k: u32,
}

const _: () = assert!(core::mem::size_of::<Insn>() == core::mem::size_of::<libc::sock_filter>());
const _: () = assert!(core::mem::size_of::<Insn>() == 8);

/// `BPF_LD | BPF_W | BPF_ABS`: load the 32-bit word at offset `k` of
/// `seccomp_data`.
pub const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
/// `BPF_JMP | BPF_JEQ | BPF_K`.
pub const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
/// `BPF_JMP | BPF_JGT | BPF_K` (unsigned).
pub const JGT: u16 = (libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K) as u16;
/// `BPF_JMP | BPF_JSET | BPF_K`: true if `A & k` is not zero.
pub const JSET: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
/// `BPF_RET | BPF_K`.
pub const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

/// `BPF_MAXINSNS`, `include/uapi/linux/bpf_common.h`: the kernel refuses
/// longer classic programs.
pub const MAX_INSNS: usize = 4096;

const _: () = assert!(MAX_INSNS == libc::BPF_MAXINSNS as usize);

/// The longest jump an 8-bit offset holds.
pub const MAX_JUMP: usize = 255;

/// A jump target: the next instruction or a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    Next,
    Label(Label),
}

/// A label of the program; the policy names its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Label(pub u16);

/// One item of the source: an instruction or the position of a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    /// Load the word at this offset of `seccomp_data`.
    Load(u32),
    /// `A == k`.
    Jeq(u32, Target, Target),
    /// `A > k`, unsigned.
    Jgt(u32, Target, Target),
    /// `A & k != 0`.
    Jset(u32, Target, Target),
    /// Return this seccomp action.
    Ret(u32),
    /// The next instruction carries this label.
    Mark(Label),
}

/// Why a program cannot be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsmError {
    /// More instructions than the kernel accepts.
    TooLong(usize),
    /// A jump from instruction `at` would skip more than 255 instructions.
    JumpTooFar {
        /// The jumping instruction.
        at: usize,
        /// The offset it would need.
        offset: usize,
    },
    /// A jump to a label that is not marked after it.
    BadLabel(u16),
    /// The program does not end in a return, so it could run off its end.
    NoFinalReturn,
}

impl core::fmt::Display for AsmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AsmError::TooLong(n) => write!(f, "{n} instructions, more than {MAX_INSNS}"),
            AsmError::JumpTooFar { at, offset } => {
                write!(
                    f,
                    "the jump at {at} needs offset {offset}, more than {MAX_JUMP}"
                )
            }
            AsmError::BadLabel(l) => write!(f, "label {l} is not marked after its jump"),
            AsmError::NoFinalReturn => write!(f, "the program does not end in a return"),
        }
    }
}

/// Assembles `ops` into instructions.
pub(crate) fn assemble(ops: &[Op]) -> Result<Vec<Insn>, AsmError> {
    // Pass 1: the instruction index of every label.
    let mut labels: Vec<(u16, usize)> = Vec::new();
    let mut n = 0usize;
    for op in ops {
        match op {
            Op::Mark(Label(l)) => labels.push((*l, n)),
            _ => n += 1,
        }
    }
    if n > MAX_INSNS {
        return Err(AsmError::TooLong(n));
    }
    let resolve = |at: usize, t: Target| -> Result<u8, AsmError> {
        let to = match t {
            Target::Next => return Ok(0),
            Target::Label(Label(l)) => labels
                .iter()
                .find(|(name, _)| *name == l)
                .map(|(_, pos)| *pos)
                .ok_or(AsmError::BadLabel(l))?,
        };
        // A jump skips (to - at - 1) instructions; it may only go forward.
        if to <= at {
            let Target::Label(Label(l)) = t else {
                return Err(AsmError::NoFinalReturn);
            };
            return Err(AsmError::BadLabel(l));
        }
        let offset = to - at - 1;
        u8::try_from(offset).map_err(|_| AsmError::JumpTooFar { at, offset })
    };
    // Pass 2: the instructions.
    let mut out = Vec::with_capacity(n);
    for op in ops {
        let at = out.len();
        let insn = match *op {
            Op::Mark(_) => continue,
            Op::Load(k) => Insn {
                code: LD_W_ABS,
                jt: 0,
                jf: 0,
                k,
            },
            Op::Jeq(k, t, f) | Op::Jgt(k, t, f) | Op::Jset(k, t, f) => Insn {
                code: match op {
                    Op::Jeq(..) => JEQ,
                    Op::Jgt(..) => JGT,
                    _ => JSET,
                },
                jt: resolve(at, t)?,
                jf: resolve(at, f)?,
                k,
            },
            Op::Ret(k) => Insn {
                code: RET,
                jt: 0,
                jf: 0,
                k,
            },
        };
        out.push(insn);
    }
    if out.last().map(|i| i.code) != Some(RET) {
        return Err(AsmError::NoFinalReturn);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: Label = Label(1);

    #[test]
    fn assembler_rejects_long_jump() {
        // A jump over 255 instructions fits; over 256 it does not.
        for (skipped, ok) in [(255usize, true), (256, false)] {
            let mut ops = vec![Op::Load(0), Op::Jeq(1, Target::Label(L), Target::Next)];
            ops.extend(std::iter::repeat_n(Op::Ret(0), skipped));
            ops.push(Op::Mark(L));
            ops.push(Op::Ret(1));
            let result = assemble(&ops);
            if ok {
                let prog = result.expect("255 fits");
                assert_eq!(prog[1].jt, 255);
            } else {
                assert_eq!(result, Err(AsmError::JumpTooFar { at: 1, offset: 256 }));
            }
        }
    }

    #[test]
    fn assembler_limits_and_labels() {
        // 4096 instructions fit, 4097 do not.
        let ops: Vec<Op> = std::iter::repeat_n(Op::Ret(0), MAX_INSNS).collect();
        assert_eq!(assemble(&ops).map(|p| p.len()), Ok(MAX_INSNS));
        let ops: Vec<Op> = std::iter::repeat_n(Op::Ret(0), MAX_INSNS + 1).collect();
        assert_eq!(assemble(&ops), Err(AsmError::TooLong(MAX_INSNS + 1)));
        // An unmarked label, a backward jump and a missing final return.
        let unmarked = [Op::Jeq(0, Target::Label(L), Target::Next), Op::Ret(0)];
        assert_eq!(assemble(&unmarked), Err(AsmError::BadLabel(1)));
        let backward = [
            Op::Mark(L),
            Op::Load(0),
            Op::Jeq(0, Target::Label(L), Target::Next),
            Op::Ret(0),
        ];
        assert_eq!(assemble(&backward), Err(AsmError::BadLabel(1)));
        assert_eq!(assemble(&[Op::Load(0)]), Err(AsmError::NoFinalReturn));
        // Opcodes are the kernel's.
        assert_eq!(LD_W_ABS, 0x20);
        assert_eq!(JEQ, 0x15);
        assert_eq!(JGT, 0x25);
        assert_eq!(JSET, 0x45);
        assert_eq!(RET, 0x06);
    }
}
