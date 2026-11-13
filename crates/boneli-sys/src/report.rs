//! The setup report from the child (ADR-007, D4): nothing at all when the
//! exec succeeded (the close-on-exec pipe just closes), or exactly 12 bytes
//! `step: u32, index: u32, errno: i32` in native (little-endian) order.
//! Anything else is a protocol error, and the parent fails closed.

use crate::child::Step;
use crate::error::{Error, ProtocolError, Result};

/// The length of a failure report.
pub(crate) const LEN: usize = 12;

/// The report of a failed step.
pub(crate) fn encode(step: Step, index: u32, errno: i32) -> [u8; LEN] {
    let mut out = [0; LEN];
    out[0..4].copy_from_slice(&step.code().to_ne_bytes());
    out[4..8].copy_from_slice(&index.to_ne_bytes());
    out[8..12].copy_from_slice(&errno.to_ne_bytes());
    out
}

/// Decodes everything read from the pipe up to EOF: `Ok` for an exec,
/// `Error::Setup` for a failed step, `Error::Protocol` otherwise.
pub(crate) fn decode(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let Ok(raw) = <[u8; LEN]>::try_from(bytes) else {
        return Err(Error::Protocol(ProtocolError::Length(bytes.len())));
    };
    let word = |i: usize| [raw[i], raw[i + 1], raw[i + 2], raw[i + 3]];
    let code = u32::from_ne_bytes(word(0));
    let step = Step::from_code(code).ok_or(Error::Protocol(ProtocolError::UnknownStep(code)))?;
    Err(Error::Setup {
        step,
        index: u32::from_ne_bytes(word(4)),
        errno: i32::from_ne_bytes(word(8)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_decoding() {
        assert!(decode(&[]).is_ok(), "EOF without bytes: exec'd");
        for step in Step::ALL {
            match decode(&encode(step, 7, libc::ENOENT)) {
                Err(Error::Setup {
                    step: s,
                    index: 7,
                    errno,
                }) => {
                    assert_eq!(s, step);
                    assert_eq!(errno, libc::ENOENT);
                }
                other => panic!("{step:?}: {other:?}"),
            }
        }
        for n in [1, 11, 13] {
            let bytes = vec![0u8; n];
            assert!(
                matches!(decode(&bytes), Err(Error::Protocol(ProtocolError::Length(m))) if m == n),
                "{n} bytes"
            );
        }
        let mut unknown = encode(Step::Exec, 0, 0);
        unknown[0..4].copy_from_slice(&9999u32.to_ne_bytes());
        assert!(matches!(
            decode(&unknown),
            Err(Error::Protocol(ProtocolError::UnknownStep(9999)))
        ));
        // Little-endian on every supported target (lib.rs).
        assert_eq!(
            encode(Step::Stdio, 2, 5),
            [6, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0]
        );
    }
}
