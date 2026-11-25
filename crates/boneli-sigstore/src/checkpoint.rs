//! Rekor v2 checkpoints: signed notes over a tree size and root hash
//! (ADR-038, D6 and D7).
//!
//! A note is its text, a blank line and its signature lines. It is read
//! strictly; anything else, CR included, is no note:
//!
//! - The text ends at the first `\n\n` (its own last `\n` included). Its
//!   lines are the origin (non-empty printable ASCII), the tree size
//!   (canonical decimal, at most `i64::MAX`), the root hash (canonical
//!   base64 of 32 bytes), then optional extension lines, which must not be
//!   empty or hold a control character and are not read.
//! - Each signature line is `U+2014 U+0020 <name> U+0020 <base64>\n`: a
//!   name without spaces or control characters, and canonical base64 of at
//!   least 5 bytes, a 4-byte key hint and the signature. At least one.
//!
//! [`verify`] then binds the note to the log: the SHA-256 of origin ‖
//! `\n` ‖ 0x01 ‖ raw key must be the log's key ID from the trusted root,
//! the signed-note key ID, so the origin is the one the operator's root
//! names without reading `baseUrl`; exactly one line must carry the
//! origin as its name and the key ID's first 4 bytes as its hint, and its
//! signature must verify under the log's Ed25519 key over the text; the
//! size and root must be the proof's. Other lines (witness cosignatures;
//! the root lists no witness keys) are parsed and not verified.

use boneli_https::Sha256;

use crate::error::Refusal;
use crate::root::NoteLog;

/// A parsed note.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Note<'a> {
    /// The signed text, its last `\n` included.
    pub(crate) text: &'a str,
    pub(crate) origin: &'a str,
    pub(crate) size: u64,
    pub(crate) root: [u8; 32],
    /// Each signature line's name and decoded bytes (hint and signature).
    pub(crate) signatures: Vec<(&'a str, Vec<u8>)>,
}

/// The signature line's prefix: an em dash (U+2014) and a space.
const DASH: &str = "\u{2014} ";

/// Reads `note` (module doc), or `None`.
pub(crate) fn parse(note: &str) -> Option<Note<'_>> {
    let split = note.find("\n\n")?;
    let (text, signatures) = (&note[..=split], &note[split + 2..]);
    let mut lines = text[..split].split('\n');
    let origin = lines.next()?;
    if origin.is_empty() || !origin.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
        return None;
    }
    let size = decimal(lines.next()?)?;
    let root: [u8; 32] = crate::base64::decode(lines.next()?.as_bytes())?
        .try_into()
        .ok()?;
    if !lines.all(|line| !line.is_empty() && !line.chars().any(char::is_control)) {
        return None;
    }
    let body = signatures.strip_suffix('\n')?;
    let signatures = body
        .split('\n')
        .map(|line| {
            let (name, b64) = line.strip_prefix(DASH)?.split_once(' ')?;
            if name.is_empty() || name.chars().any(char::is_control) {
                return None;
            }
            let bytes = crate::base64::decode(b64.as_bytes())?;
            (bytes.len() >= 5).then_some((name, bytes))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(Note {
        text,
        origin,
        size,
        root,
        signatures,
    })
}

/// Canonical decimal digits (no sign, no leading zero) up to `i64::MAX`.
fn decimal(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
        return None;
    }
    let n: u64 = text.parse().ok()?;
    (n <= i64::MAX as u64).then_some(n)
}

/// Checks that `note` is a checkpoint of `log` over `size` and `root`
/// (module doc). Every failure is [`Refusal::Checkpoint`].
pub(crate) fn verify(note: &str, log: &NoteLog, size: u64, root: &[u8; 32]) -> Result<(), Refusal> {
    let note = parse(note).ok_or(Refusal::Checkpoint)?;
    // The raw Ed25519 key: the last 32 bytes of its 44-byte SPKI.
    let spki = log.key.spki_der();
    let raw = spki
        .get(spki.len().saturating_sub(32)..)
        .ok_or(Refusal::Checkpoint)?;
    let mut bound = note.origin.as_bytes().to_vec();
    bound.extend_from_slice(&[0x0A, 0x01]);
    bound.extend_from_slice(raw);
    if Sha256::digest(&bound) != log.key_id {
        return Err(Refusal::Checkpoint);
    }
    let mut ours = note
        .signatures
        .iter()
        .filter(|(name, bytes)| *name == note.origin && bytes.get(..4) == log.key_id.get(..4));
    let (Some((_, bytes)), None) = (ours.next(), ours.next()) else {
        return Err(Refusal::Checkpoint);
    };
    let signature = bytes.get(4..).ok_or(Refusal::Checkpoint)?;
    log.key
        .verify(note.text.as_bytes(), signature)
        .map_err(|_| Refusal::Checkpoint)?;
    if note.size != size || note.root != *root {
        return Err(Refusal::Checkpoint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64;

    /// A rendered note reads back as its parts (`builders_round_trip`).
    #[test]
    fn note_round_trip() {
        let root = [0xA7; 32];
        let text = format!("log.boneli.test\n42\n{}\next\n", base64::encode(&root));
        let line =
            |name: &str, n: usize| format!("\u{2014} {name} {}\n", base64::encode(&vec![7; n]));
        let note = format!("{text}\n{}{}", line("log.boneli.test", 68), line("w", 76));
        let parsed = parse(&note).expect("note");
        assert_eq!(
            parsed,
            Note {
                text: &text,
                origin: "log.boneli.test",
                size: 42,
                root,
                signatures: vec![("log.boneli.test", vec![7; 68]), ("w", vec![7; 76])],
            }
        );
        // The real form: a size at `i64::MAX`, a zero size, the shortest
        // signature.
        for (size, ok) in [
            ("9223372036854775807", true),
            ("9223372036854775808", false),
            ("0", true),
        ] {
            let note = format!("o\n{size}\n{}\n\n{}", base64::encode(&root), line("o", 5));
            assert_eq!(parse(&note).is_some(), ok, "{size}");
        }
        let short = format!("o\n1\n{}\n\n{}", base64::encode(&root), line("o", 4));
        assert_eq!(parse(&short), None);
        // Fewer than three text lines.
        let two = format!("o\n1\n\n{}", line("o", 5));
        assert_eq!(parse(&two), None);
    }
}
