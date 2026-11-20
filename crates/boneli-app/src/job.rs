//! Job failures (ADR-004, D4).
//!
//! A job that fails reports a [`JobFailure`]. Its detail becomes the detail
//! of the run's `JobFailed` event, which the domain rejects when it is blank
//! (ADR-002, `BlankEventField`): the run would stay waiting with nothing
//! charged. [`JobFailure::new`] is the only constructor and never produces a
//! blank detail, so no `Agent`, `Verifier` or `Forge` adapter can hand
//! `DebugTicket` one.

use alloc::format;
use alloc::string::String;

use boneli_domain::values::is_blank;

/// The detail of a failure that left neither error output nor a status.
pub const NO_OUTPUT_NO_STATUS: &str = "the job failed with no error output and no status";

/// The longest `JobFailed` detail `DebugTicket` records, in bytes: 1 MiB
/// (ADR-023, D2). A stored line is at most 8 MiB (ADR-012, D3), and JSON
/// escapes a byte into at most 6 (`\u0000`), so a 1 MiB detail takes at
/// most 6 MiB and leaves 2 MiB for the rest of the line, which is under
/// 200 bytes. 2 MiB would need up to 12 MiB. Details come from adapters
/// that echo their input (a git error lists every patch of a diff that
/// does not apply), so without a cap an outcome the run accepted could
/// fail its append and go unrecorded.
pub const MAX_DETAIL_BYTES: usize = 1_048_576;

/// `detail` cut to at most [`MAX_DETAIL_BYTES`]: a longer one keeps its
/// longest prefix that ends on a UTF-8 character boundary and fits with a
/// marker that gives the original length,
/// ` [truncated, <n> bytes in all]`. A detail within the cap is returned
/// as it is. The marker is not blank, so a cut detail never is either.
pub fn cap_detail(detail: String) -> String {
    if detail.len() <= MAX_DETAIL_BYTES {
        return detail;
    }
    let marker = format!(" [truncated, {} bytes in all]", detail.len());
    let mut keep = MAX_DETAIL_BYTES.saturating_sub(marker.len());
    while !detail.is_char_boundary(keep) {
        keep -= 1;
    }
    let mut capped = detail;
    capped.truncate(keep);
    capped.push_str(&marker);
    capped
}

/// Why a job failed, and what it cost before it failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobFailure {
    detail: String,
    cost_micro_usd: u64,
}

impl JobFailure {
    /// A failure from the job's error output and its status (an exit
    /// status, a signal, an HTTP status), with the provider cost it ran up
    /// before it failed. The detail is
    ///
    /// - the status, a colon and the error output when neither is blank;
    /// - the error output as it is when only the status is blank;
    /// - the status followed by `, no error output` when only the error
    ///   output is blank;
    /// - [`NO_OUTPUT_NO_STATUS`] when both are blank.
    ///
    /// Blank is [`is_blank`], the predicate behind the domain's
    /// `BlankEventField`, so a detail built here always passes the domain.
    /// Text is never trimmed: ADR-002 keeps caller text as issued.
    pub fn new(error_output: &str, status: &str, cost_micro_usd: u64) -> JobFailure {
        let detail = match (is_blank(error_output), is_blank(status)) {
            (false, false) => format!("{status}: {error_output}"),
            (false, true) => String::from(error_output),
            (true, false) => format!("{status}, no error output"),
            (true, true) => String::from(NO_OUTPUT_NO_STATUS),
        };
        JobFailure {
            detail,
            cost_micro_usd,
        }
    }

    /// What went wrong; never blank.
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The provider cost in micro-USD the job ran up before it failed.
    pub fn cost_micro_usd(&self) -> u64 {
        self.cost_micro_usd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every blank form of the domain's tests that a process or a forge
    /// could plausibly return: empty, spaces, control whitespace, zero-width
    /// space, BOM, Hangul filler and soft hyphen.
    const BLANK: [&str; 7] = [
        "", " ", "\t\n", "\u{200B}", "\u{FEFF}", "\u{3164}", "\u{00AD}",
    ];

    #[test]
    fn detail_is_never_blank() {
        for output in BLANK {
            for status in BLANK {
                let failure = JobFailure::new(output, status, 0);
                assert_eq!(
                    failure.detail(),
                    NO_OUTPUT_NO_STATUS,
                    "{output:?} {status:?}"
                );
            }
            let only_status = JobFailure::new(output, "exit status 3", 0);
            assert_eq!(
                only_status.detail(),
                "exit status 3, no error output",
                "{output:?}"
            );
        }
        for status in BLANK {
            let only_output = JobFailure::new("runner crashed", status, 0);
            assert_eq!(only_output.detail(), "runner crashed", "{status:?}");
        }
        assert_eq!(
            JobFailure::new("runner crashed", "exit status 1", 0).detail(),
            "exit status 1: runner crashed"
        );
        // A one-dot leader is text, not blank, and is kept.
        assert_eq!(JobFailure::new("\u{2024}", "", 0).detail(), "\u{2024}");
        assert_eq!(
            JobFailure::new("", "\u{2024}", 0).detail(),
            "\u{2024}, no error output"
        );
        for output in BLANK.iter().copied().chain(["x", "\u{2024}"]) {
            for status in BLANK.iter().copied().chain(["x", "\u{2024}"]) {
                let failure = JobFailure::new(output, status, 0);
                assert!(!is_blank(failure.detail()), "{output:?} {status:?}");
            }
        }
    }

    #[test]
    fn cap_detail_bounds_and_marks() {
        let at = "x".repeat(MAX_DETAIL_BYTES);
        assert_eq!(cap_detail(at.clone()), at);
        assert_eq!(cap_detail(String::from("boom")), "boom");
        let over = "x".repeat(MAX_DETAIL_BYTES + 1);
        let capped = cap_detail(over);
        assert!(capped.len() <= MAX_DETAIL_BYTES, "{}", capped.len());
        assert!(capped.ends_with(" [truncated, 1048577 bytes in all]"));
        assert!(capped.starts_with("xxx"));
        // A 4-byte character across the cut is dropped whole: the cut at
        // `MAX_DETAIL_BYTES - 34` falls one byte into it.
        let marker = " [truncated, 1048582 bytes in all]";
        assert_eq!(marker.len(), 34);
        let mut wide = "x".repeat(MAX_DETAIL_BYTES - marker.len() - 1);
        wide.push('\u{1F600}');
        wide.push_str(&"y".repeat(37));
        assert_eq!(wide.len(), MAX_DETAIL_BYTES + 6);
        let capped = cap_detail(wide);
        assert!(capped.len() <= MAX_DETAIL_BYTES);
        assert!(!capped.contains('\u{1F600}'));
        assert_eq!(capped.len(), MAX_DETAIL_BYTES - 1);
        assert!(capped.ends_with(marker));
        // Blank content is still not blank after the cut.
        let blank = "\u{200B}".repeat(MAX_DETAIL_BYTES);
        assert!(!is_blank(&cap_detail(blank)));
    }

    #[test]
    fn detail_keeps_output_verbatim() {
        assert_eq!(JobFailure::new("  boom\n", "", 0).detail(), "  boom\n");
        assert_eq!(
            JobFailure::new(" x ", " exit status 1 ", 0).detail(),
            " exit status 1 :  x "
        );
        assert_eq!(
            JobFailure::new("a\u{0}b", "\u{200B}", 0).detail(),
            "a\u{0}b"
        );
        let failure = JobFailure::new("", "", u64::MAX);
        assert_eq!(failure.cost_micro_usd(), u64::MAX);
        assert_eq!(JobFailure::new("x", "y", 7).cost_micro_usd(), 7);
    }
}
