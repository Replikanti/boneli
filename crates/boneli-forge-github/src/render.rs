//! What the adapter writes on GitHub (ADR-014, D8): the pull request's
//! title and body, the questions comment and the commit message.
//!
//! **The inert rule.** Outside code blocks there is only text this module
//! generates from validated values: numbers, SHAs in URLs, enum labels,
//! and keys and ids in a narrow character set, in inline code. Agent and
//! reporter text (the analysis, the test, citation paths and quotes, the
//! questions) goes into indented code blocks, where GitHub's Markdown
//! creates no mention, no issue reference, no closing keyword and no
//! markup. Before it is indented, [`escape`] shows every C0 and C1 control
//! character except LF and TAB, U+2028, U+2029 and every
//! `Default_Ignorable_Code_Point` as `\u{XXXX}`, so a lone CR cannot end
//! a line inside the block and invisible text cannot hide.
//!
//! Every code block follows a blank line and is followed by one, and no
//! list item is ever open before one: an indented line after a list item
//! continues the item instead of starting a code block.
//!
//! **Caps.** A body or comment is at most [`MAX_BODY`] bytes: bytes are at
//! least as many as UTF-16 units and as scalar values, so it stays under
//! GitHub's 65,536-character limit however GitHub counts. The fixed parts
//! take at most [`MAX_FIXED`] bytes; the rest is shared by
//! [`water_fill`], and a cut block ends with a generated marker.

use boneli_app::PullRequest;
use boneli_domain::values::is_default_ignorable;
use boneli_domain::{BudgetDimension, CheckStatus, RunId, TestStatus, Ticket, TicketSource};

use crate::api::cut;
use crate::config::GitHubRepository;

/// The longest body or comment, in bytes.
pub const MAX_BODY: usize = 65_536;

/// The longest title, in bytes.
pub const MAX_TITLE: usize = 256;

/// The most the generated parts of a body or comment take, in bytes.
pub const MAX_FIXED: usize = 4_096;

/// The most questions one comment shows; the rest are counted in a
/// generated line. 64 keeps the headings inside [`MAX_FIXED`] and leaves
/// each question at least 960 bytes.
pub const MAX_QUESTIONS: usize = 64;

/// The longest citation permalink; a longer one (a very long path) is left
/// out, and the path still shows in the code block.
pub const MAX_LINK: usize = 1_024;

/// The longest ticket key shown outside the `Fixes` line.
pub const MAX_KEY: usize = 64;

/// The longest run id or evidence reference shown.
pub const MAX_ID: usize = 128;

/// Whether `c` is shown as an escape: Cc except LF and TAB when
/// `keep_lines`, U+2028, U+2029 and `Default_Ignorable_Code_Point`.
fn escaped(c: char, keep_lines: bool) -> bool {
    (c.is_control() && !(keep_lines && (c == '\n' || c == '\t')))
        || c == '\u{2028}'
        || c == '\u{2029}'
        || is_default_ignorable(c)
}

fn escape_with(text: &str, keep_lines: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if escaped(c, keep_lines) {
            out.push_str(&format!("\\u{{{:04X}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// Agent or reporter text for a code block: every character of the rule
/// above as `\u{XXXX}`; LF and TAB stay.
pub fn escape(text: &str) -> String {
    escape_with(text, true)
}

/// The pull request's title: `Fix: ` and the ticket's title, escaped (LF
/// and TAB too), at most [`MAX_TITLE`] bytes; a longer one is cut at a
/// char boundary and ends with `…`.
pub fn title(ticket_title: &str) -> String {
    let full = format!("Fix: {}", escape_with(ticket_title, false));
    if full.len() <= MAX_TITLE {
        return full;
    }
    format!("{}…", cut(&full, MAX_TITLE - '…'.len_utf8()))
}

/// `text` when it is 1 to `max` bytes of `[A-Za-z0-9._-]`: the only form
/// of a key, id or reference shown outside code blocks.
pub fn safe_id(text: &str, max: usize) -> Option<&str> {
    let ok = (1..=max).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ok.then_some(text)
}

/// The issue number of a GitHub ticket key: `[1-9][0-9]*` up to
/// `u64::MAX`. `0`, `0123`, `+1`, fullwidth digits and surrounding spaces
/// are refused.
pub fn github_issue_number(key: &str) -> Option<u64> {
    let bytes = key.as_bytes();
    let ok = bytes.first().is_some_and(|b| (b'1'..=b'9').contains(b))
        && bytes.iter().all(u8::is_ascii_digit);
    if ok { key.parse().ok() } else { None }
}

/// The tracker's name.
pub fn source_label(source: TicketSource) -> &'static str {
    match source {
        TicketSource::GitHub => "GitHub",
        TicketSource::GitLab => "GitLab",
        TicketSource::Jira => "Jira",
        TicketSource::Sentry => "Sentry",
    }
}

/// The ticket's key as shown: the issue number for GitHub, a [`safe_id`]
/// of at most [`MAX_KEY`] bytes otherwise.
fn shown_key(ticket: &Ticket) -> Option<String> {
    match ticket.source {
        TicketSource::GitHub => github_issue_number(&ticket.key).map(|n| n.to_string()),
        _ => safe_id(&ticket.key, MAX_KEY).map(str::to_owned),
    }
}

/// The pushed commit's message, generated with no closing keyword:
/// `boneli: fix for <Source> ticket <key>`, a blank line and `Run <id>`.
/// A key or run id outside the safe forms is left out.
pub fn commit_message(ticket: &Ticket, run: &RunId) -> String {
    let source = source_label(ticket.source);
    let mut message = match shown_key(ticket) {
        Some(key) => format!("boneli: fix for {source} ticket {key}\n"),
        None => format!("boneli: fix for a {source} ticket\n"),
    };
    if let Some(id) = safe_id(run.as_str(), MAX_ID) {
        message.push_str(&format!("\nRun {id}\n"));
    }
    message
}

/// The permalink of `path` at `line` on `base`: every byte of the path
/// outside `[A-Za-z0-9._~/-]` percent-encoded.
pub fn permalink(repository: &GitHubRepository, base: &str, path: &str, line: u32) -> String {
    let mut encoded = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'/' | b'-') {
            encoded.push(char::from(b));
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    format!(
        "https://github.com/{}/{}/blob/{base}/{encoded}#L{line}",
        repository.owner(),
        repository.name()
    )
}

/// The label of a test result.
pub fn test_status_label(status: TestStatus) -> &'static str {
    match status {
        TestStatus::Passed => "passes",
        TestStatus::FailedOnAssertion => "fails on an assertion",
        TestStatus::FailedToBuild => "fails to build",
        TestStatus::Errored => "errors",
        TestStatus::TimedOut => "times out",
        TestStatus::Unknown => "unknown",
    }
}

/// The label of a check result.
pub fn check_status_label(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Passed => "passed",
        CheckStatus::Failed => "failed",
        CheckStatus::NotConfigured => "not configured",
        CheckStatus::Unknown => "unknown",
    }
}

/// Micro-USD as dollars with six decimals: `$1.234567`.
pub fn usd(micro_usd: u64) -> String {
    format!("${}.{:06}", micro_usd / 1_000_000, micro_usd % 1_000_000)
}

/// Milliseconds as seconds with three decimals: `3723.456 s`.
pub fn seconds(ms: u64) -> String {
    format!("{}.{:03} s", ms / 1_000, ms % 1_000)
}

/// `value` rendered, with `at least ` in front when it saturated at
/// `u64::MAX` (ADR-002, D3).
fn amount(value: u64, show: fn(u64) -> String) -> String {
    if value == u64::MAX {
        format!("at least {}", show(value))
    } else {
        show(value)
    }
}

/// Shares `budget` bytes over blocks that need `needs` bytes: every block
/// gets min(its need, an equal share of what is left), smallest needs
/// first, so what a small block leaves passes on to the larger ones. The
/// sum never exceeds `budget`, and a block whose need fits gets all of it.
pub fn water_fill(budget: usize, needs: &[usize]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..needs.len()).collect();
    order.sort_by_key(|&i| (needs[i], i));
    let mut shares = vec![0; needs.len()];
    let mut left = budget;
    for (k, &i) in order.iter().enumerate() {
        let share = left / (needs.len() - k);
        shares[i] = needs[i].min(share);
        left -= shares[i];
    }
    shares
}

/// A piece of a block: generated text (all or nothing), or escaped agent
/// text for a code block (cut anywhere).
enum Unit {
    Generated(String),
    Code(String),
}

impl Unit {
    fn render(&self) -> String {
        match self {
            Unit::Generated(text) => format!("{text}\n\n"),
            Unit::Code(text) => {
                let mut out = String::with_capacity(text.len() + 16);
                for line in text.split('\n') {
                    out.push_str("    ");
                    out.push_str(line);
                    out.push('\n');
                }
                out.push('\n');
                out
            }
        }
    }
}

/// Agent text as a block unit: a code block, or a generated `(empty)`.
fn agent_text(text: &str) -> Unit {
    if text.is_empty() {
        Unit::Generated("_(empty)_".to_owned())
    } else {
        Unit::Code(escape(text))
    }
}

/// A block: its units and the marker it ends with when cut.
struct Block {
    units: Vec<Unit>,
    marker: String,
}

impl Block {
    fn need(&self) -> usize {
        self.units.iter().map(|u| u.render().len()).sum()
    }

    /// The block in at most `share` bytes, and whether it was cut.
    fn render(&self, share: usize) -> (String, bool) {
        let full: String = self.units.iter().map(Unit::render).collect();
        if full.len() <= share {
            return (full, false);
        }
        let marker = format!("{}\n\n", self.marker);
        let limit = share.saturating_sub(marker.len());
        let mut out = String::new();
        for unit in &self.units {
            let rendered = unit.render();
            if out.len() + rendered.len() <= limit {
                out.push_str(&rendered);
                continue;
            }
            let room = limit - out.len();
            if let Unit::Code(_) = unit
                && room >= 8
            {
                // Two bytes stay for the line end and the blank line.
                out.push_str(cut(&rendered, room - 2));
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push('\n');
            }
            break;
        }
        if out.len() + marker.len() <= share {
            out.push_str(&marker);
        }
        (out, true)
    }
}

/// A rendered body or comment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The Markdown.
    pub text: String,
    /// The bytes of the generated parts.
    pub fixed: usize,
    /// The blocks that were cut, by index in render order.
    pub cut: Vec<usize>,
}

/// One part of a document: generated text or a shared block.
enum Part {
    Fixed(String),
    Block(Block),
}

fn assemble(parts: Vec<Part>) -> Rendered {
    let fixed: usize = parts
        .iter()
        .map(|p| match p {
            Part::Fixed(text) => text.len(),
            Part::Block(_) => 0,
        })
        .sum();
    let needs: Vec<usize> = parts
        .iter()
        .filter_map(|p| match p {
            Part::Block(block) => Some(block.need()),
            Part::Fixed(_) => None,
        })
        .collect();
    let shares = water_fill(MAX_BODY.saturating_sub(fixed), &needs);
    let mut text = String::new();
    let mut cut_blocks = Vec::new();
    let mut k = 0;
    for part in parts {
        match part {
            Part::Fixed(fixed) => text.push_str(&fixed),
            Part::Block(block) => {
                let (rendered, was_cut) = block.render(shares[k]);
                if was_cut {
                    cut_blocks.push(k);
                }
                text.push_str(&rendered);
                k += 1;
            }
        }
    }
    Rendered {
        text,
        fixed,
        cut: cut_blocks,
    }
}

const ESCAPES: &str = "control and invisible characters in it are shown as `\\u{XXXX}`";

fn cut_marker(reference: &str) -> String {
    match safe_id(reference, MAX_ID) {
        Some(r) => format!(
            "_Cut here to fit GitHub's limit of 65,536 bytes; the full text is the run's evidence `{r}`._"
        ),
        None => {
            "_Cut here to fit GitHub's limit of 65,536 bytes; the full text is in the run's evidence._"
                .to_owned()
        }
    }
}

fn utf8_note(what: &str, content: &[u8]) -> String {
    if std::str::from_utf8(content).is_ok() {
        String::new()
    } else {
        format!("_The {what} is not valid UTF-8; the bytes that are not are shown as U+FFFD._\n\n")
    }
}

/// The pull request's body (ADR-014, D8): the ticket line (`Fixes #N` for
/// a GitHub ticket), the root cause with a permalink per citation, the
/// analysis, the reproduction test, the results, the cost, the overrun
/// statement and a footer.
pub fn pull_request_body(request: &PullRequest, repository: &GitHubRepository) -> Rendered {
    let ticket = &request.ticket;
    let source = source_label(ticket.source);
    let ticket_line = match (ticket.source, shown_key(ticket)) {
        (TicketSource::GitHub, Some(number)) => format!("Fixes #{number}"),
        (_, Some(key)) => format!("Ticket: {source} `{key}`"),
        (_, None) => format!("Ticket: {source} (its key is not shown)"),
    };
    let base = request.base.as_str();
    let n = request.citations.len();
    let mut citations = Vec::new();
    for (k, citation) in request.citations.iter().enumerate() {
        let link = permalink(repository, base, &citation.path, citation.line);
        citations.push(Unit::Generated(if link.len() <= MAX_LINK {
            format!("[Citation {} of {n}]({link})", k + 1)
        } else {
            format!(
                "Citation {} of {n} (its path is too long for a link)",
                k + 1
            )
        }));
        citations.push(Unit::Code(escape(&format!(
            "{}:{}\n{}",
            citation.path, citation.line, citation.quote
        ))));
    }
    if citations.is_empty() {
        citations.push(Unit::Generated("_(no citations)_".to_owned()));
    }
    let analysis = String::from_utf8_lossy(&request.analysis.content);
    let test = String::from_utf8_lossy(&request.test.content);
    let analysis_ref = request.analysis.reference.as_str();

    let checks = &request.checks;
    let rows = [
        (
            "Reproduction test",
            "fails on an assertion",
            test_status_label(checks.reproduction_test),
        ),
        (
            "Reproduction test unchanged by the fix",
            "not run",
            check_status_label(checks.reproduction_test_unchanged),
        ),
        (
            "Previously green tests",
            "not run",
            check_status_label(checks.previously_green_tests),
        ),
        ("Lint", "not run", check_status_label(checks.lint)),
        ("Typecheck", "not run", check_status_label(checks.typecheck)),
    ];
    let mut results =
        "### Results\n\n| Check | Before the fix | With the fix |\n| --- | --- | --- |\n"
            .to_owned();
    for (check, before, after) in rows {
        results.push_str(&format!("| {check} | {before} | {after} |\n"));
    }
    results.push('\n');

    let spent = request.spent;
    let mut cost = format!(
        "### Cost\n\nThe run cost {} and took {} of job time.\n\n",
        amount(spent.cost_micro_usd, usd),
        amount(spent.duration_ms, seconds)
    );
    if let Some(overrun) = &request.overrun {
        let (limit, used, budget) = match overrun.dimension {
            BudgetDimension::Cost => (
                "cost",
                amount(overrun.spent.cost_micro_usd, usd),
                usd(overrun.budget.cost_micro_usd),
            ),
            BudgetDimension::Duration => (
                "job time",
                amount(overrun.spent.duration_ms, seconds),
                seconds(overrun.budget.duration_ms),
            ),
        };
        cost.push_str(&format!(
            "**Over budget.** The verify job took the run past its {limit} limit: it used {used} against a limit of {budget}. Boneli opened this pull request because the fix passed every gate, and opening it spends no budget.\n\n"
        ));
    }

    let mut footer = "---\n\n".to_owned();
    if let Some(run) = safe_id(request.run.as_str(), MAX_ID) {
        footer.push_str(&format!("Run `{run}`. "));
    }
    let evidence: Vec<String> = [
        ("diff", &request.diff.reference),
        ("test", &request.test.reference),
        ("analysis", &request.analysis.reference),
    ]
    .iter()
    .filter_map(|(what, r)| safe_id(r.as_str(), MAX_ID).map(|r| format!("{what} `{r}`")))
    .collect();
    if !evidence.is_empty() {
        footer.push_str(&format!("Evidence: {}. ", evidence.join(", ")));
    }
    footer.push_str("Boneli never merges; a human reviews and merges this pull request.\n");

    assemble(vec![
        Part::Fixed(format!(
            "{ticket_line}\n\nBoneli reproduced this bug with a failing test, traced it to the cited lines and verified this fix in a clean sandbox. Text written by the agent or the reporter is shown as code; {ESCAPES} escapes.\n\n### Root cause\n\n"
        )),
        Part::Block(Block {
            units: citations,
            marker: cut_marker(analysis_ref),
        }),
        Part::Fixed(format!(
            "### Analysis\n\n{}",
            utf8_note("analysis", &request.analysis.content)
        )),
        Part::Block(Block {
            units: vec![agent_text(&analysis)],
            marker: cut_marker(analysis_ref),
        }),
        Part::Fixed(format!(
            "### Reproduction test\n\n{}",
            utf8_note("test", &request.test.content)
        )),
        Part::Block(Block {
            units: vec![agent_text(&test)],
            marker: cut_marker(request.test.reference.as_str()),
        }),
        Part::Fixed(format!("{results}{cost}{footer}")),
    ])
}

/// The questions comment (ADR-014, D8): a generated intro and each
/// question in a code block under its own heading, at most
/// [`MAX_QUESTIONS`] of them.
pub fn questions_comment(questions: &[String]) -> Rendered {
    let n = questions.len();
    let mut parts = vec![Part::Fixed(format!(
        "Boneli needs more information before it can reproduce this bug. The questions below were written by its agent and are shown as code; {ESCAPES} escapes.\n\n"
    ))];
    for (k, question) in questions.iter().take(MAX_QUESTIONS).enumerate() {
        parts.push(Part::Fixed(format!("### Question {} of {n}\n\n", k + 1)));
        parts.push(Part::Block(Block {
            units: vec![agent_text(question)],
            marker: "_Cut here to fit GitHub's limit of 65,536 bytes._".to_owned(),
        }));
    }
    if n > MAX_QUESTIONS {
        parts.push(Part::Fixed(format!(
            "_{} more questions are not shown: a comment shows at most {MAX_QUESTIONS}._\n",
            n - MAX_QUESTIONS
        )));
    }
    assemble(parts)
}
