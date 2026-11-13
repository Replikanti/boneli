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
