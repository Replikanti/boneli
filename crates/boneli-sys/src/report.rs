//! The setup report from the child (ADR-007, D4; ADR-042, D3): a stream of
//! 12-byte records `step: u32, index: u32, errno: i32` in native
//! (little-endian) order, ended by EOF.
//!
//! `spawn`'s child sends nothing when the exec succeeded (the close-on-exec
//! pipe just closes) or exactly one failure record. An anchor and a join
//! also send progress records: errno 0 and one of the steps
//! [`Step::Forked`], [`Step::Fill`] or [`Step::Release`], whose index
//! carries a value (a pid, the loopback families, 0). A failure never
//! carries errno 0 (`child::fail`). Anything else is a protocol error, and
//! the parent fails closed.

use crate::child::Step;
use crate::error::{Error, ProtocolError, Result};

/// The length of a record.
pub(crate) const LEN: usize = 12;

/// The record of a step: a failure, or progress where `errno` is 0.
pub(crate) fn encode(step: Step, index: u32, errno: i32) -> [u8; LEN] {
    let mut out = [0; LEN];
    out[0..4].copy_from_slice(&step.code().to_ne_bytes());
    out[4..8].copy_from_slice(&index.to_ne_bytes());
    out[8..12].copy_from_slice(&errno.to_ne_bytes());
    out
}

/// One decoded record.
#[derive(Debug)]
pub(crate) enum Record {
    /// A progress record of an anchor or a join, with its value.
    Progress {
        /// The step.
        step: Step,
        /// The index field.
        value: u32,
    },
    /// A failed step: always [`Error::Setup`].
    Failed(Error),
}

/// Decodes one record: an unknown step code, or errno 0 on a step that has
/// no progress record, is a protocol error.
pub(crate) fn decode_record(raw: &[u8; LEN]) -> std::result::Result<Record, ProtocolError> {
    let word = |i: usize| [raw[i], raw[i + 1], raw[i + 2], raw[i + 3]];
    let code = u32::from_ne_bytes(word(0));
    let step = Step::from_code(code).ok_or(ProtocolError::UnknownStep(code))?;
    let index = u32::from_ne_bytes(word(4));
    let errno = i32::from_ne_bytes(word(8));
    if errno == 0 {
        return if step.is_progress() {
            Ok(Record::Progress { step, value: index })
        } else {
            Err(ProtocolError::Unexpected(step))
        };
    }
    Ok(Record::Failed(Error::Setup { step, index, errno }))
}

/// Decodes everything `spawn`'s child wrote up to EOF: `Ok` for an exec,
/// `Error::Setup` for a failed step, `Error::Protocol` otherwise, a
/// progress record included.
pub(crate) fn decode(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let Ok(raw) = <[u8; LEN]>::try_from(bytes) else {
        return Err(Error::Protocol(ProtocolError::Length(bytes.len())));
    };
    match decode_record(&raw).map_err(Error::Protocol)? {
        Record::Failed(e) => Err(e),
        Record::Progress { step, .. } => Err(Error::Protocol(ProtocolError::Unexpected(step))),
    }
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

    #[test]
    fn progress_records() {
        // Exactly the three progress steps have a record with errno 0; the
        // index is their value.
        for step in Step::ALL {
            let decoded = decode_record(&encode(step, 42, 0));
            if matches!(step, Step::Forked | Step::Fill | Step::Release) {
                assert!(
                    matches!(decoded, Ok(Record::Progress { step: s, value: 42 }) if s == step),
                    "{step:?}: {decoded:?}"
                );
            } else {
                assert!(
                    matches!(decoded, Err(ProtocolError::Unexpected(s)) if s == step),
                    "{step:?}: {decoded:?}"
                );
            }
        }
        // spawn's child never sends progress: a protocol error there.
        assert!(matches!(
            decode(&encode(Step::Fill, 3, 0)),
            Err(Error::Protocol(ProtocolError::Unexpected(Step::Fill)))
        ));
        // A failure of a progress step stays a failure.
        assert!(matches!(
            decode_record(&encode(Step::Forked, 4321, libc::EPIPE)),
            Ok(Record::Failed(Error::Setup {
                step: Step::Forked,
                index: 4321,
                errno: libc::EPIPE
            }))
        ));
        assert_eq!(encode(Step::Release, 0, 0)[0..4], 36u32.to_ne_bytes());
    }
}
