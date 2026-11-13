//! The `Forge` port: the code host the run talks to (ADR-004, D1, D5).
//!
//! The forge posts triage questions on the ticket and opens the pull
//! request. Forge calls spend no agent budget and carry no usage (ADR-002,
//! D3). Rendering the comment and the pull-request body, including the
//! overrun statement, is the adapter's job (#19), because the format depends
//! on the forge; the port hands it structured data.

use alloc::string::String;
use alloc::vec::Vec;

use boneli_domain::values::is_blank;
use boneli_domain::{CommitSha, EvidenceRef, FixChecks, Overrun, RunId, Ticket, Usage};

use crate::job::JobFailure;

/// The forge's reference to a comment or a pull request. Never blank: the
/// domain rejects a blank reference as a caller error and leaves the run
/// waiting (ADR-002, D1, step 2), so the type cannot hold one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ForgeRef(String);

impl ForgeRef {
    /// Accepts any reference that is not blank in the domain's sense
    /// ([`is_blank`]); text is kept as issued, never trimmed.
    pub fn parse(reference: &str) -> Option<ForgeRef> {
        if is_blank(reference) {
            None
        } else {
            Some(ForgeRef(String::from(reference)))
        }
    }

    /// The reference as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stored evidence together with its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attached {
    /// Where the evidence store keeps it.
    pub reference: EvidenceRef,
    /// The bytes.
    pub content: Vec<u8>,
}

/// What the forge needs to open a pull request: the run's
/// `OpenPullRequest` command with its evidence loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullRequest {
    /// The run that produced it.
    pub run: RunId,
    /// The bug report.
    pub ticket: Ticket,
    /// The base commit.
    pub base: CommitSha,
    /// The verified fix.
    pub diff: Attached,
    /// The reproduction test.
    pub test: Attached,
    /// The verified root-cause analysis.
    pub analysis: Attached,
    /// The fix gate's observations, for the before and after results.
    pub checks: FixChecks,
    /// The run's total consumption.
    pub spent: Usage,
    /// Set when the verify job crossed a limit; the body must state it
    /// (ADR-002, D3).
    pub overrun: Option<Overrun>,
}

/// The code host. Every failure is a [`JobFailure`], whose detail is never
/// blank.
pub trait Forge {
    /// Posts the triage questions as one comment on the ticket.
    fn post_questions(&self, ticket: &Ticket, questions: &[String])
    -> Result<ForgeRef, JobFailure>;

    /// Opens the pull request. A human always merges.
    fn open_pull_request(&self, request: &PullRequest) -> Result<ForgeRef, JobFailure>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forge_ref_rejects_exactly_blank() {
        for blank in [
            "", " ", "\t\n", "\u{200B}", "\u{FEFF}", "\u{3164}", "\u{00AD}",
        ] {
            assert_eq!(ForgeRef::parse(blank), None, "{blank:?}");
        }
        for text in ["pull-1", " a ", "\u{2024}", "\u{200B}x", "0", "a\u{0}b"] {
            let parsed = ForgeRef::parse(text).map(|r| String::from(r.as_str()));
            assert_eq!(parsed, Some(String::from(text)), "{text:?}");
        }
        // The same predicate as the domain's, over every sample.
        for sample in [
            "",
            " ",
            "\u{3000}",
            "\u{E0041}",
            "\u{115F}\u{1160}",
            "x",
            "\u{0430}",
        ] {
            assert_eq!(
                ForgeRef::parse(sample).is_none(),
                is_blank(sample),
                "{sample:?}"
            );
        }
    }
}
