//! `expires` (ADR-033, item 4): exactly `YYYY-MM-DDTHH:MM:SSZ`, 20 bytes,
//! read with `boneli_sigstore::time::parse`, so the workspace has one
//! RFC 3339 reader. The length rules out a fraction; the reader rules out
//! an offset, lower-case `t` or `z`, a leap second and dates that do not
//! exist. Every Sigstore root from v4 on and every online file use this
//! form.

/// The seconds since the Unix epoch `text` names, or `None` when it is
/// not of the one form.
pub(crate) fn parse(text: &str) -> Option<u64> {
    if text.len() != 20 {
        return None;
    }
    boneli_sigstore::time::parse(text).map(|t| t.secs())
}

/// Whether metadata that expires at `expires` has expired at `start`: at
/// the second it names it already has, because TUF requires `expires` to
/// be higher than the update's start time (5.3.10, 5.4.4).
pub(crate) fn is_expired(expires: u64, start: u64) -> bool {
    start >= expires
}
