//! Values a run is about: identifiers, the ticket, commit SHAs and
//! citations (`docs/ARCHITECTURE.md`, "Debugging line"; ADR-002).

use alloc::string::String;

use crate::error::DomainError;

/// Identifier of a run. Opaque to the domain; the application gets it from
/// the `Ids` port.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RunId(String);

impl RunId {
    /// Wraps an identifier issued by the `Ids` port.
    pub fn new(id: String) -> RunId {
        RunId(id)
    }

    /// The identifier as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A full git object name: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits.
///
/// No uppercase, no trimming and no abbreviations: an abbreviated name can
/// become ambiguous as the repository grows, and the domain compares SHAs as
/// strings (ADR-002).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CommitSha(String);

impl CommitSha {
    /// Accepts exactly 40 or 64 characters of `0-9a-f`.
    pub fn parse(text: &str) -> Result<CommitSha, DomainError> {
        let hex = text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if hex && (text.len() == 40 || text.len() == 64) {
            Ok(CommitSha(String::from(text)))
        } else {
            Err(DomainError::InvalidCommitSha)
        }
    }

    /// The object name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// For the scenario corpus only: its SHAs are fixed literals, and a unit
    /// test parses each of them.
    pub(crate) fn from_corpus(hex: &'static str) -> CommitSha {
        CommitSha(String::from(hex))
    }
}

/// A reference to stored evidence: a reproduction test, an analysis or a
/// diff. Opaque here; the event log and evidence store (#4) own its format.
/// Never blank (ADR-002): a finished run must point at its evidence.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceRef(String);

impl EvidenceRef {
    /// Accepts a reference issued by the evidence store; a blank one (see
    /// [`is_blank`]) is rejected.
    pub fn parse(reference: &str) -> Result<EvidenceRef, DomainError> {
        if is_blank(reference) {
            Err(DomainError::BlankEvidenceRef)
        } else {
            Ok(EvidenceRef(String::from(reference)))
        }
    }

    /// For the scenario corpus only: its references are fixed literals, and
    /// a unit test parses each of them.
    pub(crate) fn from_corpus(reference: &'static str) -> EvidenceRef {
        EvidenceRef(String::from(reference))
    }

    /// The reference as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Where a ticket came from: the intake list of `docs/ARCHITECTURE.md`,
/// "Debugging line", step 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TicketSource {
    /// A GitHub issue.
    GitHub,
    /// A GitLab issue.
    GitLab,
    /// A Jira issue.
    Jira,
    /// A Sentry issue.
    Sentry,
}

/// The bug report a run starts from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    /// The tracker it came from.
    pub source: TicketSource,
    /// The tracker's key for it; must not be blank.
    pub key: String,
    /// The title; must not be blank.
    pub title: String,
    /// The description; may be blank.
    pub body: String,
}

/// A ticket field that intake validation checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TicketField {
    /// [`Ticket::key`].
    Key,
    /// [`Ticket::title`].
    Title,
}

impl Ticket {
    /// The first required field that is blank (see [`is_blank`]).
    pub fn blank_field(&self) -> Option<TicketField> {
        if is_blank(&self.key) {
            Some(TicketField::Key)
        } else if is_blank(&self.title) {
            Some(TicketField::Title)
        } else {
            None
        }
    }
}

/// One citation of a root-cause analysis, `path:line@sha` with the quoted
/// text (`docs/ARCHITECTURE.md`, "Debugging line", step 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Citation {
    /// Repository-relative path.
    pub path: String,
    /// 1-based line number.
    pub line: u32,
    /// The commit the citation refers to; must be the run's base.
    pub sha: CommitSha,
    /// The quoted text; must not be blank.
    pub quote: String,
}

/// Unicode `Default_Ignorable_Code_Point` ranges, inclusive, adjacent ranges
/// merged. Source: DerivedCoreProperties.txt of Unicode 18.0.0.
const DEFAULT_IGNORABLE: [(u32, u32); 17] = [
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

fn is_default_ignorable(c: char) -> bool {
    let code = u32::from(c);
    DEFAULT_IGNORABLE
        .iter()
        .any(|&(first, last)| first <= code && code <= last)
}

/// True when the text renders as nothing: every character is whitespace
/// (`char::is_whitespace`) or a Unicode `Default_Ignorable_Code_Point`
/// (zero-width space and joiners, BOM, soft hyphen, Hangul fillers,
/// variation selectors, tags). The empty string is blank.
pub fn is_blank(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_whitespace() || is_default_ignorable(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_blank_cases() {
        for blank in [
            "",
            " ",
            "  \t",
            "\n",
            "\u{FEFF}",
            "\u{200B}",
            "\u{3000}",
            "\u{3164}",
            "\u{00AD}",
            "\u{FE0F}",
            "\u{E0041}",
            "\u{115F}\u{1160}",
            "\u{FFA0}",
            "\u{2060}",
        ] {
            assert!(is_blank(blank), "{blank:?} must be blank");
        }
        // Cyrillic look-alike letters are text, not blank: no allow or deny
        // list of scripts is involved.
        for text in ["a", " a ", "\u{0430}\u{0435}", "\u{200B}x", "\u{2024}", "0"] {
            assert!(!is_blank(text), "{text:?} must not be blank");
        }
    }

    #[test]
    fn default_ignorable_table_is_sorted_and_disjoint() {
        for pair in DEFAULT_IGNORABLE.windows(2) {
            assert!(pair[0].1 < pair[1].0, "{pair:?}");
        }
        for &(first, last) in DEFAULT_IGNORABLE.iter() {
            assert!(first <= last);
        }
    }

    #[test]
    fn commit_sha_parse() {
        let forty = "0123456789abcdef0123456789abcdef01234567";
        let sixty_four = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(CommitSha::parse(forty).map(|s| s.as_str().len()), Ok(40));
        assert_eq!(
            CommitSha::parse(sixty_four).map(|s| s.as_str().len()),
            Ok(64)
        );
        let rejected = [
            String::from(&forty[..39]),
            alloc::format!("{forty}a"),
            String::from(&sixty_four[..63]),
            alloc::format!("{sixty_four}a"),
            String::new(),
            forty.to_uppercase(),
            alloc::format!("g{}", &forty[1..]),
            alloc::format!("{}\n", &forty[..39]),
            alloc::format!("{forty}\n"),
            alloc::format!(" {}", &forty[1..]),
            alloc::format!(" {forty}"),
            alloc::format!("\u{FF10}{}", &forty[1..]),
        ];
        for text in rejected {
            assert_eq!(
                CommitSha::parse(&text),
                Err(DomainError::InvalidCommitSha),
                "{text:?}"
            );
        }
    }

    #[test]
    fn evidence_ref_parse_rejects_blank() {
        for blank in ["", " ", "\t\n", "\u{200B}", "\u{FEFF}", "\u{3164}"] {
            assert_eq!(
                EvidenceRef::parse(blank),
                Err(DomainError::BlankEvidenceRef),
                "{blank:?}"
            );
        }
        let parsed = EvidenceRef::parse("evidence/fix-diff").expect("not blank");
        assert_eq!(parsed.as_str(), "evidence/fix-diff");
        // Not trimmed: the store's reference is kept as issued.
        assert_eq!(
            EvidenceRef::parse(" a ").map(|r| String::from(r.as_str())),
            Ok(String::from(" a "))
        );
    }

    #[test]
    fn blank_field_reports_key_before_title() {
        let mut ticket = Ticket {
            source: TicketSource::Jira,
            key: String::new(),
            title: String::new(),
            body: String::new(),
        };
        assert_eq!(ticket.blank_field(), Some(TicketField::Key));
        ticket.key = String::from("BUG-7");
        assert_eq!(ticket.blank_field(), Some(TicketField::Title));
        ticket.title = String::from("Totals are off by one");
        assert_eq!(ticket.blank_field(), None);
    }
}
