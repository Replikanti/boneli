//! The run log format, version 2 (ADR-012, D3; ADR-023, D7): one JSON
//! object per line, encoded and decoded by hand over `boneli_json::Value`
//! (ADR-008).
//!
//! Line 1 is the header,
//! `{"format":"boneli-run-log","version":2,"run":s,"budget":{"cost_micro_usd":n,"duration_ms":n},"previous":null|s}`;
//! every further line is one event, `{"event":"<RunEvent variant>", ...}`
//! with the variant's fields in declaration order and named as in
//! `boneli_domain`. Enums without data are their variant names, numbers
//! `u64` lexemes. Enums with data (the patch check, its verdict, its
//! violations and their payloads) are objects, `{"kind":"<variant>", ...}`
//! with the variant's fields in declaration order; a payload that is an
//! enum without data is named for its type (`problem`, `class`, `marker`).
//!
//! Version 2 added `PatchChecked` between `FixWritten` and `FixVerified`.
//! Version 1 logs are read with the same decoder, except that a version 1
//! log holding `FixWritten` or `PatchChecked` is refused: after
//! `FixWritten` the run table of version 2 expects another event, so such a
//! log would replay to another run ([`admits`]). New logs are written as
//! version 2 only.
//!
//! Decoding is strict and fails closed: a wrong type, a missing or unknown
//! key, an unknown variant, a number that is not a `u64` (or a `u32` for a
//! citation's line), a `CommitSha` or `EvidenceRef` the domain rejects.
//! On top of that a line must be byte for byte the encoding of what it
//! decodes to, so whitespace, `\r`, key order and escapes the serializer
//! never writes fail too: every line the store wrote passes, and nothing
//! else does. Errors are [`Malformed`]: static text and static key names,
//! never content from the line (ADR-008, D9).

use std::fmt;

use boneli_app::RunStart;
use std::num::NonZeroU32;

use boneli_domain::{
    Budget, ChangeProblem, CheckStatus, Citation, CitationProblem, CitationStatus, CommitSha,
    EventKind, EvidenceRef, FixChecks, ForbiddenClass, LinkProblem, Marker, NotText, PatchCheck,
    PatchLimits, PatchVerdict, PatchViolation, RunEvent, RunId, TestDisabling, TestStatus, Ticket,
    TicketSource, TriageVerdict, UnreadablePath, Usage,
};
use boneli_json::{Limits, Object, Value};

/// The longest line, without its `\n`: 8 MiB (ADR-012, D3). Derived from
/// the largest ticket body the store must take, at the worst JSON escape
/// ratio of 6 bytes per input byte; a longer event fails its append.
pub const MAX_LINE_BYTES: usize = 8_388_608;

/// The deepest nesting of a line: the schema's own depth, event → `check`
/// → `verdict` → `violations` → violation → `problem` (ADR-023, D7; 3 in
/// version 1, ADR-012 D3).
pub const MAX_DEPTH: usize = 6;

/// The most values in one line: 2^16, where the per-value memory term of
/// ADR-008 D5 (136 B × 65,536 = 8.5 MiB) matches the byte term (ADR-012,
/// D3). Admits 13,105 citations or 65,528 questions in one event.
pub const MAX_VALUES: usize = 65_536;

/// The `format` of the header.
const FORMAT: &str = "boneli-run-log";

/// The version of a log's format, from its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Version {
    /// ADR-012: no `PatchChecked`, `FixVerified` after `FixWritten`.
    V1,
    /// ADR-023: `PatchChecked` between `FixWritten` and `FixVerified`.
    V2,
}

/// The version new logs are written in.
pub(crate) const CURRENT: Version = Version::V2;

fn version_number(version: Version) -> u64 {
    match version {
        Version::V1 => 1,
        Version::V2 => 2,
    }
}

/// Whether a log of `version` may hold an event of `kind`: a version 1
/// log may not hold `FixWritten`, because the version 2 table expects
/// `PatchChecked` after it where version 1 expected `FixVerified`, and it
/// cannot hold `PatchChecked`, which version 1 did not have. A version 1
/// log that ends before the fix still replays the same, so a previous-run
/// lookup (ADR-004, D6) on it works.
pub(crate) fn admits(version: Version, kind: EventKind) -> Result<(), Malformed> {
    match (version, kind) {
        (Version::V1, EventKind::FixWritten | EventKind::PatchChecked) => Err(Malformed::Line(
            "a version 1 log cannot hold the fix: version 2 checks the patch after it",
        )),
        _ => Ok(()),
    }
}

/// Why a line does not decode. Only static text, so no content of the line
/// can reach an error detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Malformed {
    /// The line is not JSON within the limits; the parser's error kind.
    Json(boneli_json::ErrorKind),
    /// A value of the wrong type, or another wrong value, at a key.
    Field(&'static str, &'static str),
    /// A key the schema requires is missing.
    Missing(&'static str),
    /// The object holds a key the schema does not have.
    UnknownKey,
    /// Something at the top level of the line.
    Line(&'static str),
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Malformed::Json(kind) => write!(f, "not JSON within the log's limits ({kind:?})"),
            Malformed::Field(key, what) => write!(f, "\"{key}\": {what}"),
            Malformed::Missing(key) => write!(f, "missing key \"{key}\""),
            Malformed::UnknownKey => f.write_str("an unknown key"),
            Malformed::Line(what) => f.write_str(what),
        }
    }
}

type Decoded<T> = Result<T, Malformed>;

/// The limits every line is parsed with. `None` cannot happen (the
/// constants are non-zero and `MAX_DEPTH` is far below boneli-json's
/// ceiling, `limits_are_valid`); if it did, every line would fail to parse,
/// which fails closed.
pub(crate) fn limits() -> Option<Limits> {
    Limits::new(MAX_LINE_BYTES, MAX_DEPTH, MAX_VALUES).ok()
}

// ------------------------------------------------------------- Encoding

fn usage_value(usage: &Usage) -> Value {
    let mut o = Object::with_capacity(2);
    o.insert("cost_micro_usd", usage.cost_micro_usd);
    o.insert("duration_ms", usage.duration_ms);
    Value::Object(o)
}

fn budget_value(budget: &Budget) -> Value {
    let mut o = Object::with_capacity(2);
    o.insert("cost_micro_usd", budget.cost_micro_usd);
    o.insert("duration_ms", budget.duration_ms);
    Value::Object(o)
}

fn source_name(source: TicketSource) -> &'static str {
    match source {
        TicketSource::GitHub => "GitHub",
        TicketSource::GitLab => "GitLab",
        TicketSource::Jira => "Jira",
        TicketSource::Sentry => "Sentry",
    }
}

fn test_status_name(status: TestStatus) -> &'static str {
    match status {
        TestStatus::Passed => "Passed",
        TestStatus::FailedOnAssertion => "FailedOnAssertion",
        TestStatus::FailedToBuild => "FailedToBuild",
        TestStatus::Errored => "Errored",
        TestStatus::TimedOut => "TimedOut",
        TestStatus::Unknown => "Unknown",
    }
}

fn check_status_name(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Passed => "Passed",
        CheckStatus::Failed => "Failed",
        CheckStatus::NotConfigured => "NotConfigured",
        CheckStatus::Unknown => "Unknown",
    }
}

fn citation_status_name(status: CitationStatus) -> &'static str {
    match status {
        CitationStatus::Verified => "Verified",
        CitationStatus::Mismatch => "Mismatch",
        CitationStatus::Unverifiable => "Unverifiable",
    }
}

/// Every value of each leaf enum, for decoding by name. A value missing
/// here encodes but never decodes, so its append fails its self-check
/// (closed), and `every_event_kind_round_trips` lists every value.
const SOURCES: [TicketSource; 4] = [
    TicketSource::GitHub,
    TicketSource::GitLab,
    TicketSource::Jira,
    TicketSource::Sentry,
];
const TEST_STATUSES: [TestStatus; 6] = [
    TestStatus::Passed,
    TestStatus::FailedOnAssertion,
    TestStatus::FailedToBuild,
    TestStatus::Errored,
    TestStatus::TimedOut,
    TestStatus::Unknown,
];
const CHECK_STATUSES: [CheckStatus; 4] = [
    CheckStatus::Passed,
    CheckStatus::Failed,
    CheckStatus::NotConfigured,
    CheckStatus::Unknown,
];
const CITATION_STATUSES: [CitationStatus; 3] = [
    CitationStatus::Verified,
    CitationStatus::Mismatch,
    CitationStatus::Unverifiable,
];

const CITATION_PROBLEMS: [CitationProblem; 10] = [
    CitationProblem::BlankPath,
    CitationProblem::AbsolutePath,
    CitationProblem::Backslash,
    CitationProblem::Nul,
    CitationProblem::EmptyComponent,
    CitationProblem::DotComponent,
    CitationProblem::ParentComponent,
    CitationProblem::LineZero,
    CitationProblem::BlankQuote,
    CitationProblem::NotOnBase,
];
const FORBIDDEN_CLASSES: [ForbiddenClass; 6] = [
    ForbiddenClass::RepositoryMetadata,
    ForbiddenClass::Ci,
    ForbiddenClass::ContainerBuild,
    ForbiddenClass::CodeOwners,
    ForbiddenClass::GitConfig,
    ForbiddenClass::Dependencies,
];
const NOT_TEXT: [NotText; 3] = [NotText::Nul, NotText::NotUtf8, NotText::BidiControl];

fn citation_problem_name(problem: CitationProblem) -> &'static str {
    match problem {
        CitationProblem::BlankPath => "BlankPath",
        CitationProblem::AbsolutePath => "AbsolutePath",
        CitationProblem::Backslash => "Backslash",
        CitationProblem::Nul => "Nul",
        CitationProblem::EmptyComponent => "EmptyComponent",
        CitationProblem::DotComponent => "DotComponent",
        CitationProblem::ParentComponent => "ParentComponent",
        CitationProblem::LineZero => "LineZero",
        CitationProblem::BlankQuote => "BlankQuote",
        CitationProblem::NotOnBase => "NotOnBase",
    }
}

fn forbidden_class_name(class: ForbiddenClass) -> &'static str {
    match class {
        ForbiddenClass::RepositoryMetadata => "RepositoryMetadata",
        ForbiddenClass::Ci => "Ci",
        ForbiddenClass::ContainerBuild => "ContainerBuild",
        ForbiddenClass::CodeOwners => "CodeOwners",
        ForbiddenClass::GitConfig => "GitConfig",
        ForbiddenClass::Dependencies => "Dependencies",
    }
}

fn not_text_name(reason: NotText) -> &'static str {
    match reason {
        NotText::Nul => "Nul",
        NotText::NotUtf8 => "NotUtf8",
        NotText::BidiControl => "BidiControl",
    }
}

fn marker_name(marker: Marker) -> &'static str {
    match marker {
        Marker::Skip => "Skip",
        Marker::Only => "Only",
        Marker::Todo => "Todo",
        Marker::Fixme => "Fixme",
        Marker::SkipIf => "SkipIf",
        Marker::RunIf => "RunIf",
        Marker::Fails => "Fails",
        Marker::Failing => "Failing",
        Marker::Fail => "Fail",
        Marker::Xit => "Xit",
        Marker::Xtest => "Xtest",
        Marker::Xdescribe => "Xdescribe",
        Marker::Xcontext => "Xcontext",
        Marker::Xspecify => "Xspecify",
        Marker::Fit => "Fit",
        Marker::Fdescribe => "Fdescribe",
        Marker::Fcontext => "Fcontext",
    }
}

/// The event's variant name, the value of its `event` key.
fn kind_name(kind: EventKind) -> &'static str {
    match kind {
        EventKind::TicketReceived => "TicketReceived",
        EventKind::TriageFinished => "TriageFinished",
        EventKind::QuestionsPosted => "QuestionsPosted",
        EventKind::ReproductionWritten => "ReproductionWritten",
        EventKind::ReproductionChecked => "ReproductionChecked",
        EventKind::RootCauseProposed => "RootCauseProposed",
        EventKind::CitationsChecked => "CitationsChecked",
        EventKind::FixWritten => "FixWritten",
        EventKind::PatchChecked => "PatchChecked",
        EventKind::FixVerified => "FixVerified",
        EventKind::PullRequestOpened => "PullRequestOpened",
        EventKind::JobFailed => "JobFailed",
    }
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(s.as_str())).collect())
}

/// `{"kind":<name>}`, plus one payload member when the variant has one.
fn kind_object(name: &'static str, payload: Option<(&'static str, &'static str)>) -> Value {
    let mut o = Object::with_capacity(2);
    o.insert("kind", name);
    if let Some((key, value)) = payload {
        o.insert(key, value);
    }
    Value::Object(o)
}

fn change_problem_value(problem: ChangeProblem) -> Value {
    match problem {
        ChangeProblem::OutOfOrder => kind_object("OutOfOrder", None),
        ChangeProblem::Path(p) => kind_object("Path", Some(("problem", citation_problem_name(p)))),
        ChangeProblem::NoChange => kind_object("NoChange", None),
        ChangeProblem::EmptyLinkTarget => kind_object("EmptyLinkTarget", None),
        ChangeProblem::NulInLinkTarget => kind_object("NulInLinkTarget", None),
        ChangeProblem::BaseLinkMismatch => kind_object("BaseLinkMismatch", None),
    }
}

fn link_problem_value(problem: LinkProblem) -> Value {
    let class = |c| Some(("class", forbidden_class_name(c)));
    match problem {
        LinkProblem::NotUtf8 => kind_object("NotUtf8", None),
        LinkProblem::TooLong => kind_object("TooLong", None),
        LinkProblem::Absolute => kind_object("Absolute", None),
        LinkProblem::WindowsForm => kind_object("WindowsForm", None),
        LinkProblem::Escapes => kind_object("Escapes", None),
        LinkProblem::ThroughLink => kind_object("ThroughLink", None),
        LinkProblem::Into(c) => kind_object("Into", class(c)),
        LinkProblem::Encloses(c) => kind_object("Encloses", class(c)),
    }
}

fn test_disabling_value(reason: TestDisabling) -> Value {
    match reason {
        TestDisabling::Marker(m) => kind_object("Marker", Some(("marker", marker_name(m)))),
        TestDisabling::DeletedTestFile => kind_object("DeletedTestFile", None),
        TestDisabling::TestsRemoved => kind_object("TestsRemoved", None),
        TestDisabling::TestConfigChanged => kind_object("TestConfigChanged", None),
    }
}

/// A `usize` as its `u64` lexeme; every supported target has a `usize` of
/// at most 64 bits, so `u64::MAX` is never written.
fn index_value(index: usize) -> u64 {
    u64::try_from(index).unwrap_or(u64::MAX)
}

/// One violation. The match is exhaustive, so a new variant does not
/// compile until it has an encoding.
fn violation_value(violation: &PatchViolation) -> Value {
    let mut o = Object::with_capacity(3);
    match violation {
        PatchViolation::TooManyFiles { files, limit } => {
            o.insert("kind", "TooManyFiles");
            o.insert("files", index_value(*files));
            o.insert("limit", u64::from(*limit));
        }
        PatchViolation::Empty => {
            o.insert("kind", "Empty");
        }
        PatchViolation::Malformed { index, problem } => {
            o.insert("kind", "Malformed");
            o.insert("index", index_value(*index));
            o.insert("problem", change_problem_value(*problem));
        }
        PatchViolation::BaseLinkMalformed { index, problem } => {
            o.insert("kind", "BaseLinkMalformed");
            o.insert("index", index_value(*index));
            o.insert("problem", change_problem_value(*problem));
        }
        PatchViolation::TooManyLines { limit } => {
            o.insert("kind", "TooManyLines");
            o.insert("limit", u64::from(*limit));
        }
        PatchViolation::TooManyBytes { limit } => {
            o.insert("kind", "TooManyBytes");
            o.insert("limit", u64::from(*limit));
        }
        PatchViolation::Forbidden { index, class } => {
            o.insert("kind", "Forbidden");
            o.insert("index", index_value(*index));
            o.insert("class", forbidden_class_name(*class));
        }
        PatchViolation::Gitlink { index } => {
            o.insert("kind", "Gitlink");
            o.insert("index", index_value(*index));
        }
        PatchViolation::NotText { index, reason } => {
            o.insert("kind", "NotText");
            o.insert("index", index_value(*index));
            o.insert("reason", not_text_name(*reason));
        }
        PatchViolation::Link { index, problem } => {
            o.insert("kind", "Link");
            o.insert("index", index_value(*index));
            o.insert("problem", link_problem_value(*problem));
        }
        PatchViolation::DisablesTests { index, reason } => {
            o.insert("kind", "DisablesTests");
            o.insert("index", index_value(*index));
            o.insert("reason", test_disabling_value(*reason));
        }
    }
    Value::Object(o)
}

fn patch_check_value(check: &PatchCheck) -> Value {
    let mut o = Object::with_capacity(3);
    match check {
        PatchCheck::Judged { limits, verdict } => {
            o.insert("kind", "Judged");
            let mut l = Object::with_capacity(3);
            l.insert(
                "max_changed_files",
                u64::from(limits.max_changed_files.get()),
            );
            l.insert(
                "max_changed_lines",
                u64::from(limits.max_changed_lines.get()),
            );
            l.insert(
                "max_changed_bytes",
                u64::from(limits.max_changed_bytes.get()),
            );
            o.insert("limits", Value::Object(l));
            let mut v = Object::with_capacity(3);
            match verdict {
                PatchVerdict::Pass { files, lines } => {
                    v.insert("kind", "Pass");
                    v.insert("files", u64::from(*files));
                    v.insert("lines", u64::from(*lines));
                }
                PatchVerdict::Reject(violations) => {
                    v.insert("kind", "Reject");
                    let list = violations.iter().map(violation_value).collect();
                    v.insert("violations", Value::Array(list));
                }
            }
            o.insert("verdict", Value::Object(v));
        }
        PatchCheck::Unreadable(path) => {
            o.insert("kind", "Unreadable");
            let mut p = Object::with_capacity(2);
            let (kind, index) = match path {
                UnreadablePath::Change { index } => ("Change", index),
                UnreadablePath::BaseLink { index } => ("BaseLink", index),
            };
            p.insert("kind", kind);
            p.insert("index", index_value(*index));
            o.insert("path", Value::Object(p));
        }
    }
    Value::Object(o)
}

/// The header of a run's log, in `version`.
pub(crate) fn encode_header(id: &RunId, start: &RunStart, version: Version) -> Value {
    let mut o = Object::with_capacity(5);
    o.insert("format", FORMAT);
    o.insert("version", version_number(version));
    o.insert("run", id.as_str());
    o.insert("budget", budget_value(&start.budget));
    o.insert(
        "previous",
        match &start.previous {
            Some(previous) => Value::from(previous.as_str()),
            None => Value::Null,
        },
    );
    Value::Object(o)
}

/// One event. The match is exhaustive, so a new `RunEvent` variant does not
/// compile until it has an encoding.
pub(crate) fn encode_event(event: &RunEvent) -> Value {
    let mut o = Object::with_capacity(4);
    o.insert("event", kind_name(event.kind()));
    match event {
        RunEvent::TicketReceived { ticket, base } => {
            let mut t = Object::with_capacity(4);
            t.insert("source", source_name(ticket.source));
            t.insert("key", ticket.key.as_str());
            t.insert("title", ticket.title.as_str());
            t.insert("body", ticket.body.as_str());
            o.insert("ticket", Value::Object(t));
            o.insert("base", base.as_str());
        }
        RunEvent::TriageFinished { verdict, usage } => {
            let mut v = Object::with_capacity(2);
            match verdict {
                TriageVerdict::Ready => {
                    v.insert("kind", "Ready");
                }
                TriageVerdict::NeedsInformation { questions } => {
                    v.insert("kind", "NeedsInformation");
                    v.insert("questions", strings(questions));
                }
            }
            o.insert("verdict", Value::Object(v));
            o.insert("usage", usage_value(usage));
        }
        RunEvent::QuestionsPosted { reference } | RunEvent::PullRequestOpened { reference } => {
            o.insert("reference", reference.as_str());
        }
        RunEvent::ReproductionWritten { test, usage } => {
            o.insert("test", test.as_str());
            o.insert("usage", usage_value(usage));
        }
        RunEvent::ReproductionChecked { status, usage } => {
            o.insert("status", test_status_name(*status));
            o.insert("usage", usage_value(usage));
        }
        RunEvent::RootCauseProposed {
            analysis,
            citations,
            usage,
        } => {
            o.insert("analysis", analysis.as_str());
            let list = citations
                .iter()
                .map(|c| {
                    let mut e = Object::with_capacity(4);
                    e.insert("path", c.path.as_str());
                    e.insert("line", u64::from(c.line));
                    e.insert("sha", c.sha.as_str());
                    e.insert("quote", c.quote.as_str());
                    Value::Object(e)
                })
                .collect();
            o.insert("citations", Value::Array(list));
            o.insert("usage", usage_value(usage));
        }
        RunEvent::CitationsChecked { results, usage } => {
            let list = results
                .iter()
                .map(|s| Value::from(citation_status_name(*s)))
                .collect();
            o.insert("results", Value::Array(list));
            o.insert("usage", usage_value(usage));
        }
        RunEvent::FixWritten { diff, usage } => {
            o.insert("diff", diff.as_str());
            o.insert("usage", usage_value(usage));
        }
        RunEvent::PatchChecked { check, usage } => {
            o.insert("check", patch_check_value(check));
            o.insert("usage", usage_value(usage));
        }
        RunEvent::FixVerified { checks, usage } => {
            let mut c = Object::with_capacity(5);
            c.insert(
                "reproduction_test",
                test_status_name(checks.reproduction_test),
            );
            c.insert(
                "reproduction_test_unchanged",
                check_status_name(checks.reproduction_test_unchanged),
            );
            c.insert(
                "previously_green_tests",
                check_status_name(checks.previously_green_tests),
            );
            c.insert("lint", check_status_name(checks.lint));
            c.insert("typecheck", check_status_name(checks.typecheck));
            o.insert("checks", Value::Object(c));
            o.insert("usage", usage_value(usage));
        }
        RunEvent::JobFailed { detail, usage } => {
            o.insert("detail", detail.as_str());
            o.insert("usage", usage_value(usage));
        }
    }
    Value::Object(o)
}

// ------------------------------------------------------------- Decoding

/// The object at `value`, which must hold exactly `keys`.
fn object<'a>(value: &'a Value, at: &'static str, keys: &[&'static str]) -> Decoded<&'a Object> {
    let o = value
        .as_object()
        .ok_or(Malformed::Field(at, "not an object"))?;
    for key in keys {
        if !o.contains_key(key) {
            return Err(Malformed::Missing(key));
        }
    }
    if o.len() != keys.len() {
        return Err(Malformed::UnknownKey);
    }
    Ok(o)
}

/// The member `key`, which `object` has checked to exist.
fn member<'a>(o: &'a Object, key: &'static str) -> Decoded<&'a Value> {
    o.get(key).ok_or(Malformed::Missing(key))
}

fn string(o: &Object, key: &'static str) -> Decoded<String> {
    member(o, key)?
        .as_str()
        .map(String::from)
        .ok_or(Malformed::Field(key, "not a string"))
}

fn number(o: &Object, key: &'static str) -> Decoded<u64> {
    member(o, key)?
        .as_number()
        .and_then(|n| n.as_u64())
        .ok_or(Malformed::Field(key, "not an unsigned 64-bit integer"))
}

fn usage(o: &Object) -> Decoded<Usage> {
    let u = object(
        member(o, "usage")?,
        "usage",
        &["cost_micro_usd", "duration_ms"],
    )?;
    Ok(Usage {
        cost_micro_usd: number(u, "cost_micro_usd")?,
        duration_ms: number(u, "duration_ms")?,
    })
}

fn evidence_ref(o: &Object, key: &'static str) -> Decoded<EvidenceRef> {
    EvidenceRef::parse(&string(o, key)?).map_err(|_| Malformed::Field(key, "a blank reference"))
}

fn commit_sha(o: &Object, key: &'static str) -> Decoded<CommitSha> {
    CommitSha::parse(&string(o, key)?).map_err(|_| Malformed::Field(key, "not a commit SHA"))
}

/// The enum value whose name is the string at `key`.
fn named<T: Copy>(
    o: &Object,
    key: &'static str,
    all: &[T],
    name: fn(T) -> &'static str,
) -> Decoded<T> {
    let text = member(o, key)?
        .as_str()
        .ok_or(Malformed::Field(key, "not a string"))?;
    named_value(text, key, all, name)
}

fn named_value<T: Copy>(
    text: &str,
    key: &'static str,
    all: &[T],
    name: fn(T) -> &'static str,
) -> Decoded<T> {
    all.iter()
        .copied()
        .find(|v| name(*v) == text)
        .ok_or(Malformed::Field(key, "an unknown variant"))
}

fn string_list(o: &Object, key: &'static str) -> Decoded<Vec<String>> {
    member(o, key)?
        .as_array()
        .ok_or(Malformed::Field(key, "not an array"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(String::from)
                .ok_or(Malformed::Field(key, "an element is not a string"))
        })
        .collect()
}

/// The number at `key` as a `usize` (an index or a count).
fn index(o: &Object, key: &'static str) -> Decoded<usize> {
    usize::try_from(number(o, key)?).map_err(|_| Malformed::Field(key, "above usize::MAX"))
}

/// The number at `key` as a `u32`.
fn number_u32(o: &Object, key: &'static str) -> Decoded<u32> {
    u32::try_from(number(o, key)?).map_err(|_| Malformed::Field(key, "above u32::MAX"))
}

/// A patch limit: a `u32` that is not 0, as `PatchLimits` holds it.
fn limit(o: &Object, key: &'static str) -> Decoded<NonZeroU32> {
    NonZeroU32::new(number_u32(o, key)?).ok_or(Malformed::Field(key, "zero"))
}

/// The `kind` of the object at `value`; the caller checks its keys.
fn kind_of<'a>(value: &'a Value, at: &'static str) -> Decoded<&'a str> {
    value
        .as_object()
        .ok_or(Malformed::Field(at, "not an object"))?
        .get("kind")
        .ok_or(Malformed::Missing("kind"))?
        .as_str()
        .ok_or(Malformed::Field("kind", "not a string"))
}

const UNKNOWN_KIND: Malformed = Malformed::Field("kind", "an unknown variant");

fn change_problem(value: &Value, at: &'static str) -> Decoded<ChangeProblem> {
    let unit = |problem| object(value, at, &["kind"]).map(|_| problem);
    match kind_of(value, at)? {
        "OutOfOrder" => unit(ChangeProblem::OutOfOrder),
        "Path" => {
            let o = object(value, at, &["kind", "problem"])?;
            let problem = named(o, "problem", &CITATION_PROBLEMS, citation_problem_name)?;
            Ok(ChangeProblem::Path(problem))
        }
        "NoChange" => unit(ChangeProblem::NoChange),
        "EmptyLinkTarget" => unit(ChangeProblem::EmptyLinkTarget),
        "NulInLinkTarget" => unit(ChangeProblem::NulInLinkTarget),
        "BaseLinkMismatch" => unit(ChangeProblem::BaseLinkMismatch),
        _ => Err(UNKNOWN_KIND),
    }
}

fn link_problem(value: &Value, at: &'static str) -> Decoded<LinkProblem> {
    let unit = |problem| object(value, at, &["kind"]).map(|_| problem);
    let class = || {
        let o = object(value, at, &["kind", "class"])?;
        named(o, "class", &FORBIDDEN_CLASSES, forbidden_class_name)
    };
    match kind_of(value, at)? {
        "NotUtf8" => unit(LinkProblem::NotUtf8),
        "TooLong" => unit(LinkProblem::TooLong),
        "Absolute" => unit(LinkProblem::Absolute),
        "WindowsForm" => unit(LinkProblem::WindowsForm),
        "Escapes" => unit(LinkProblem::Escapes),
        "ThroughLink" => unit(LinkProblem::ThroughLink),
        "Into" => class().map(LinkProblem::Into),
        "Encloses" => class().map(LinkProblem::Encloses),
        _ => Err(UNKNOWN_KIND),
    }
}

fn test_disabling(value: &Value, at: &'static str) -> Decoded<TestDisabling> {
    let unit = |reason| object(value, at, &["kind"]).map(|_| reason);
    match kind_of(value, at)? {
        "Marker" => {
            let o = object(value, at, &["kind", "marker"])?;
            let marker = named(o, "marker", &Marker::ALL, marker_name)?;
            Ok(TestDisabling::Marker(marker))
        }
        "DeletedTestFile" => unit(TestDisabling::DeletedTestFile),
        "TestsRemoved" => unit(TestDisabling::TestsRemoved),
        "TestConfigChanged" => unit(TestDisabling::TestConfigChanged),
        _ => Err(UNKNOWN_KIND),
    }
}

fn violation(value: &Value) -> Decoded<PatchViolation> {
    let at = "violations";
    let with = |keys: &[&'static str]| object(value, at, keys);
    let violation = match kind_of(value, at)? {
        "TooManyFiles" => {
            let o = with(&["kind", "files", "limit"])?;
            PatchViolation::TooManyFiles {
                files: index(o, "files")?,
                limit: number_u32(o, "limit")?,
            }
        }
        "Empty" => {
            with(&["kind"])?;
            PatchViolation::Empty
        }
        "Malformed" => {
            let o = with(&["kind", "index", "problem"])?;
            PatchViolation::Malformed {
                index: index(o, "index")?,
                problem: change_problem(member(o, "problem")?, "problem")?,
            }
        }
        "BaseLinkMalformed" => {
            let o = with(&["kind", "index", "problem"])?;
            PatchViolation::BaseLinkMalformed {
                index: index(o, "index")?,
                problem: change_problem(member(o, "problem")?, "problem")?,
            }
        }
        "TooManyLines" => {
            let o = with(&["kind", "limit"])?;
            PatchViolation::TooManyLines {
                limit: number_u32(o, "limit")?,
            }
        }
        "TooManyBytes" => {
            let o = with(&["kind", "limit"])?;
            PatchViolation::TooManyBytes {
                limit: number_u32(o, "limit")?,
            }
        }
        "Forbidden" => {
            let o = with(&["kind", "index", "class"])?;
            PatchViolation::Forbidden {
                index: index(o, "index")?,
                class: named(o, "class", &FORBIDDEN_CLASSES, forbidden_class_name)?,
            }
        }
        "Gitlink" => {
            let o = with(&["kind", "index"])?;
            PatchViolation::Gitlink {
                index: index(o, "index")?,
            }
        }
        "NotText" => {
            let o = with(&["kind", "index", "reason"])?;
            PatchViolation::NotText {
                index: index(o, "index")?,
                reason: named(o, "reason", &NOT_TEXT, not_text_name)?,
            }
        }
        "Link" => {
            let o = with(&["kind", "index", "problem"])?;
            PatchViolation::Link {
                index: index(o, "index")?,
                problem: link_problem(member(o, "problem")?, "problem")?,
            }
        }
        "DisablesTests" => {
            let o = with(&["kind", "index", "reason"])?;
            PatchViolation::DisablesTests {
                index: index(o, "index")?,
                reason: test_disabling(member(o, "reason")?, "reason")?,
            }
        }
        _ => return Err(UNKNOWN_KIND),
    };
    Ok(violation)
}

fn patch_check(value: &Value) -> Decoded<PatchCheck> {
    let at = "check";
    match kind_of(value, at)? {
        "Judged" => {
            let o = object(value, at, &["kind", "limits", "verdict"])?;
            let l = object(
                member(o, "limits")?,
                "limits",
                &[
                    "max_changed_files",
                    "max_changed_lines",
                    "max_changed_bytes",
                ],
            )?;
            let limits = PatchLimits {
                max_changed_files: limit(l, "max_changed_files")?,
                max_changed_lines: limit(l, "max_changed_lines")?,
                max_changed_bytes: limit(l, "max_changed_bytes")?,
            };
            let v = member(o, "verdict")?;
            let verdict = match kind_of(v, "verdict")? {
                "Pass" => {
                    let p = object(v, "verdict", &["kind", "files", "lines"])?;
                    PatchVerdict::Pass {
                        files: number_u32(p, "files")?,
                        lines: number_u32(p, "lines")?,
                    }
                }
                "Reject" => {
                    let r = object(v, "verdict", &["kind", "violations"])?;
                    let violations = member(r, "violations")?
                        .as_array()
                        .ok_or(Malformed::Field("violations", "not an array"))?
                        .iter()
                        .map(violation)
                        .collect::<Decoded<Vec<PatchViolation>>>()?;
                    PatchVerdict::Reject(violations)
                }
                _ => return Err(UNKNOWN_KIND),
            };
            Ok(PatchCheck::Judged { limits, verdict })
        }
        "Unreadable" => {
            let o = object(value, at, &["kind", "path"])?;
            let p = member(o, "path")?;
            let kind = kind_of(p, "path")?;
            let index = index(object(p, "path", &["kind", "index"])?, "index")?;
            let path = match kind {
                "Change" => UnreadablePath::Change { index },
                "BaseLink" => UnreadablePath::BaseLink { index },
                _ => return Err(UNKNOWN_KIND),
            };
            Ok(PatchCheck::Unreadable(path))
        }
        _ => Err(UNKNOWN_KIND),
    }
}

/// The header: the run id, how the run started and the log's version.
pub(crate) fn decode_header(value: &Value) -> Decoded<(RunId, RunStart, Version)> {
    let o = value
        .as_object()
        .ok_or(Malformed::Line("the header is not an object"))?;
    if o.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(Malformed::Line("not a boneli run log"));
    }
    let version = match o
        .get("version")
        .and_then(Value::as_number)
        .map(|n| n.as_str())
    {
        Some("1") => Version::V1,
        Some("2") => Version::V2,
        _ => return Err(Malformed::Line("an unsupported log version")),
    };
    let o = object(
        value,
        "header",
        &["format", "version", "run", "budget", "previous"],
    )?;
    let b = object(
        member(o, "budget")?,
        "budget",
        &["cost_micro_usd", "duration_ms"],
    )?;
    let previous = match member(o, "previous")? {
        Value::Null => None,
        Value::String(s) => Some(RunId::new(s.clone())),
        _ => return Err(Malformed::Field("previous", "neither null nor a string")),
    };
    Ok((
        RunId::new(string(o, "run")?),
        RunStart {
            budget: Budget {
                cost_micro_usd: number(b, "cost_micro_usd")?,
                duration_ms: number(b, "duration_ms")?,
            },
            previous,
        },
        version,
    ))
}

/// One event. The match over `EventKind` is exhaustive, so a new event
/// kind does not compile until it decodes.
pub(crate) fn decode_event(value: &Value) -> Decoded<RunEvent> {
    let o = value
        .as_object()
        .ok_or(Malformed::Line("an event is not an object"))?;
    let name = o
        .get("event")
        .ok_or(Malformed::Missing("event"))?
        .as_str()
        .ok_or(Malformed::Field("event", "not a string"))?;
    let kind = named_value(name, "event", &EventKind::ALL, kind_name)?;
    let event = match kind {
        EventKind::TicketReceived => {
            let o = object(value, "event", &["event", "ticket", "base"])?;
            let t = object(
                member(o, "ticket")?,
                "ticket",
                &["source", "key", "title", "body"],
            )?;
            RunEvent::TicketReceived {
                ticket: Ticket {
                    source: named(t, "source", &SOURCES, source_name)?,
                    key: string(t, "key")?,
                    title: string(t, "title")?,
                    body: string(t, "body")?,
                },
                base: commit_sha(o, "base")?,
            }
        }
        EventKind::TriageFinished => {
            let o = object(value, "event", &["event", "verdict", "usage"])?;
            let verdict = member(o, "verdict")?;
            let kind = verdict
                .as_object()
                .ok_or(Malformed::Field("verdict", "not an object"))?
                .get("kind")
                .ok_or(Malformed::Missing("kind"))?
                .as_str()
                .ok_or(Malformed::Field("kind", "not a string"))?;
            let verdict = match kind {
                "Ready" => {
                    object(verdict, "verdict", &["kind"])?;
                    TriageVerdict::Ready
                }
                "NeedsInformation" => {
                    let v = object(verdict, "verdict", &["kind", "questions"])?;
                    TriageVerdict::NeedsInformation {
                        questions: string_list(v, "questions")?,
                    }
                }
                _ => return Err(Malformed::Field("kind", "an unknown variant")),
            };
            RunEvent::TriageFinished {
                verdict,
                usage: usage(o)?,
            }
        }
        EventKind::QuestionsPosted => {
            let o = object(value, "event", &["event", "reference"])?;
            RunEvent::QuestionsPosted {
                reference: string(o, "reference")?,
            }
        }
        EventKind::ReproductionWritten => {
            let o = object(value, "event", &["event", "test", "usage"])?;
            RunEvent::ReproductionWritten {
                test: evidence_ref(o, "test")?,
                usage: usage(o)?,
            }
        }
        EventKind::ReproductionChecked => {
            let o = object(value, "event", &["event", "status", "usage"])?;
            RunEvent::ReproductionChecked {
                status: named(o, "status", &TEST_STATUSES, test_status_name)?,
                usage: usage(o)?,
            }
        }
        EventKind::RootCauseProposed => {
            let o = object(value, "event", &["event", "analysis", "citations", "usage"])?;
            let citations = member(o, "citations")?
                .as_array()
                .ok_or(Malformed::Field("citations", "not an array"))?
                .iter()
                .map(|c| {
                    let c = object(c, "citations", &["path", "line", "sha", "quote"])?;
                    Ok(Citation {
                        path: string(c, "path")?,
                        line: u32::try_from(number(c, "line")?)
                            .map_err(|_| Malformed::Field("line", "above u32::MAX"))?,
                        sha: commit_sha(c, "sha")?,
                        quote: string(c, "quote")?,
                    })
                })
                .collect::<Decoded<Vec<Citation>>>()?;
            RunEvent::RootCauseProposed {
                analysis: evidence_ref(o, "analysis")?,
                citations,
                usage: usage(o)?,
            }
        }
        EventKind::CitationsChecked => {
            let o = object(value, "event", &["event", "results", "usage"])?;
            let results = member(o, "results")?
                .as_array()
                .ok_or(Malformed::Field("results", "not an array"))?
                .iter()
                .map(|v| {
                    let text = v
                        .as_str()
                        .ok_or(Malformed::Field("results", "an element is not a string"))?;
                    named_value(text, "results", &CITATION_STATUSES, citation_status_name)
                })
                .collect::<Decoded<Vec<CitationStatus>>>()?;
            RunEvent::CitationsChecked {
                results,
                usage: usage(o)?,
            }
        }
        EventKind::FixWritten => {
            let o = object(value, "event", &["event", "diff", "usage"])?;
            RunEvent::FixWritten {
                diff: evidence_ref(o, "diff")?,
                usage: usage(o)?,
            }
        }
        EventKind::PatchChecked => {
            let o = object(value, "event", &["event", "check", "usage"])?;
            RunEvent::PatchChecked {
                check: patch_check(member(o, "check")?)?,
                usage: usage(o)?,
            }
        }
        EventKind::FixVerified => {
            let o = object(value, "event", &["event", "checks", "usage"])?;
            let c = object(
                member(o, "checks")?,
                "checks",
                &[
                    "reproduction_test",
                    "reproduction_test_unchanged",
                    "previously_green_tests",
                    "lint",
                    "typecheck",
                ],
            )?;
            let check = |key| named(c, key, &CHECK_STATUSES, check_status_name);
            RunEvent::FixVerified {
                checks: FixChecks {
                    reproduction_test: named(
                        c,
                        "reproduction_test",
                        &TEST_STATUSES,
                        test_status_name,
                    )?,
                    reproduction_test_unchanged: check("reproduction_test_unchanged")?,
                    previously_green_tests: check("previously_green_tests")?,
                    lint: check("lint")?,
                    typecheck: check("typecheck")?,
                },
                usage: usage(o)?,
            }
        }
        EventKind::PullRequestOpened => {
            let o = object(value, "event", &["event", "reference"])?;
            RunEvent::PullRequestOpened {
                reference: string(o, "reference")?,
            }
        }
        EventKind::JobFailed => {
            let o = object(value, "event", &["event", "detail", "usage"])?;
            RunEvent::JobFailed {
                detail: string(o, "detail")?,
                usage: usage(o)?,
            }
        }
    };
    Ok(event)
}

// ---------------------------------------------------------------- Lines

/// Why an event or header cannot be written; no content either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unwritable {
    /// The line would be this many bytes, above [`MAX_LINE_BYTES`].
    TooLong(usize),
    /// The line does not read back as what was encoded: a limit other than
    /// the length (depth, values), or a codec bug.
    SelfCheck(Malformed),
}

impl fmt::Display for Unwritable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unwritable::TooLong(n) => write!(
                f,
                "the line would be {n} bytes, above the limit of {MAX_LINE_BYTES}"
            ),
            Unwritable::SelfCheck(m) => write!(f, "the line does not read back: {m}"),
        }
    }
}

/// Parses one line (without its `\n`) under [`limits`].
fn parse(line: &[u8]) -> Decoded<Value> {
    let limits = limits().ok_or(Malformed::Line("the log's limits are invalid"))?;
    boneli_json::parse(line, &limits).map_err(|e| Malformed::Json(e.kind()))
}

/// The encoding of `value`, or `None` when the serializer refuses it (only
/// for values nested deeper than boneli-json's `MAX_DEPTH`, which the
/// schema never builds).
fn serialize(value: &Value) -> Option<Vec<u8>> {
    boneli_json::to_vec(value).ok()
}

/// The line of a value the codec built, checked to read back as `want`
/// through `decode`, so whatever is written loads (ADR-012, D3).
fn checked_line<T: PartialEq>(
    value: &Value,
    want: &T,
    decode: fn(&Value) -> Decoded<T>,
) -> Result<Vec<u8>, Unwritable> {
    let line = serialize(value).ok_or(Unwritable::SelfCheck(Malformed::Line(
        "the encoder built a value too deep to serialize",
    )))?;
    if line.len() > MAX_LINE_BYTES {
        return Err(Unwritable::TooLong(line.len()));
    }
    let back = parse(&line).and_then(|v| decode(&v));
    match back {
        Ok(got) if &got == want => Ok(line),
        Ok(_) => Err(Unwritable::SelfCheck(Malformed::Line(
            "the line decodes to another value",
        ))),
        Err(m) => Err(Unwritable::SelfCheck(m)),
    }
}

/// The header line of a new log, in the [`CURRENT`] version, without its
/// `\n`.
pub(crate) fn header_line(id: &RunId, start: &RunStart) -> Result<Vec<u8>, Unwritable> {
    let want = (id.clone(), start.clone(), CURRENT);
    checked_line(&encode_header(id, start, CURRENT), &want, decode_header)
}

/// The line of an event, without its `\n`.
pub(crate) fn event_line(event: &RunEvent) -> Result<Vec<u8>, Unwritable> {
    checked_line(&encode_event(event), event, decode_event)
}

/// A stored line, without its `\n`, decoded and required to be the
/// canonical encoding of what it decodes to.
fn read_line<T>(
    line: &[u8],
    decode: fn(&Value) -> Decoded<T>,
    encode: impl Fn(&T) -> Value,
) -> Decoded<T> {
    let value = parse(line)?;
    let decoded = decode(&value)?;
    if serialize(&encode(&decoded)).as_deref() != Some(line) {
        return Err(Malformed::Line(
            "not the store's own encoding of its content",
        ));
    }
    Ok(decoded)
}

/// The header of a stored log, of either version.
pub(crate) fn read_header(line: &[u8]) -> Decoded<(RunId, RunStart, Version)> {
    read_line(line, decode_header, |(id, start, version)| {
        encode_header(id, start, *version)
    })
}

/// One stored event of a log in `version` ([`admits`]).
pub(crate) fn read_event(line: &[u8], version: Version) -> Decoded<RunEvent> {
    let event = read_line(line, decode_event, encode_event)?;
    admits(version, event.kind())?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boneli_app::RunLog;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn sha() -> CommitSha {
        CommitSha::parse(SHA).expect("sha")
    }

    fn reference(text: &str) -> EvidenceRef {
        EvidenceRef::parse(text).expect("reference")
    }

    #[test]
    fn limits_are_valid() {
        let limits = Limits::new(MAX_LINE_BYTES, MAX_DEPTH, MAX_VALUES).expect("valid");
        assert_eq!(Some(limits), super::limits());
    }

    /// Texts a serializer tends to break: NUL, BOM, CR, DEL, the line and
    /// paragraph separators, a quote, a backslash and characters outside
    /// the BMP.
    fn texts() -> Vec<String> {
        [
            "",
            "\u{0}",
            "\u{FEFF}x",
            "a\rb",
            "\u{7F}",
            "\u{2028}\u{2029}",
            "\"",
            "\\",
            "\n",
            "\u{1F600}\u{10FFFF}",
            "plain",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    fn usages() -> [Usage; 3] {
        [
            Usage::default(),
            Usage {
                cost_micro_usd: u64::MAX,
                duration_ms: u64::MAX,
            },
            Usage {
                cost_micro_usd: 1,
                duration_ms: 2,
            },
        ]
    }

    /// The values from `first` on, each giving the next through `next`.
    /// `next` matches every variant, so a new variant does not compile
    /// until it is in the chain.
    fn chain<T>(first: T, next: impl Fn(&T) -> Option<T>) -> Vec<T> {
        let mut all = Vec::new();
        let mut at = Some(first);
        while let Some(value) = at {
            at = next(&value);
            all.push(value);
        }
        all
    }

    fn every_citation_problem() -> Vec<CitationProblem> {
        use CitationProblem as P;
        chain(P::BlankPath, |p| match p {
            P::BlankPath => Some(P::AbsolutePath),
            P::AbsolutePath => Some(P::Backslash),
            P::Backslash => Some(P::Nul),
            P::Nul => Some(P::EmptyComponent),
            P::EmptyComponent => Some(P::DotComponent),
            P::DotComponent => Some(P::ParentComponent),
            P::ParentComponent => Some(P::LineZero),
            P::LineZero => Some(P::BlankQuote),
            P::BlankQuote => Some(P::NotOnBase),
            P::NotOnBase => None,
        })
    }

    fn every_forbidden_class() -> Vec<ForbiddenClass> {
        use ForbiddenClass as C;
        chain(C::RepositoryMetadata, |c| match c {
            C::RepositoryMetadata => Some(C::Ci),
            C::Ci => Some(C::ContainerBuild),
            C::ContainerBuild => Some(C::CodeOwners),
            C::CodeOwners => Some(C::GitConfig),
            C::GitConfig => Some(C::Dependencies),
            C::Dependencies => None,
        })
    }

    fn every_not_text() -> Vec<NotText> {
        chain(NotText::Nul, |r| match r {
            NotText::Nul => Some(NotText::NotUtf8),
            NotText::NotUtf8 => Some(NotText::BidiControl),
            NotText::BidiControl => None,
        })
    }

    fn every_marker() -> Vec<Marker> {
        use Marker as M;
        chain(M::Skip, |m| match m {
            M::Skip => Some(M::Only),
            M::Only => Some(M::Todo),
            M::Todo => Some(M::Fixme),
            M::Fixme => Some(M::SkipIf),
            M::SkipIf => Some(M::RunIf),
            M::RunIf => Some(M::Fails),
            M::Fails => Some(M::Failing),
            M::Failing => Some(M::Fail),
            M::Fail => Some(M::Xit),
            M::Xit => Some(M::Xtest),
            M::Xtest => Some(M::Xdescribe),
            M::Xdescribe => Some(M::Xcontext),
            M::Xcontext => Some(M::Xspecify),
            M::Xspecify => Some(M::Fit),
            M::Fit => Some(M::Fdescribe),
            M::Fdescribe => Some(M::Fcontext),
            M::Fcontext => None,
        })
    }

    /// Every `ChangeProblem`, `Path` with every `CitationProblem`.
    fn every_change_problem() -> Vec<ChangeProblem> {
        use ChangeProblem as P;
        let variants = chain(P::OutOfOrder, |p| match p {
            P::OutOfOrder => Some(P::Path(CitationProblem::BlankPath)),
            P::Path(_) => Some(P::NoChange),
            P::NoChange => Some(P::EmptyLinkTarget),
            P::EmptyLinkTarget => Some(P::NulInLinkTarget),
            P::NulInLinkTarget => Some(P::BaseLinkMismatch),
            P::BaseLinkMismatch => None,
        });
        variants
            .into_iter()
            .flat_map(|p| match p {
                P::Path(_) => every_citation_problem().into_iter().map(P::Path).collect(),
                other => vec![other],
            })
            .collect()
    }

    /// Every `LinkProblem`, `Into` and `Encloses` with every class.
    fn every_link_problem() -> Vec<LinkProblem> {
        use LinkProblem as P;
        let variants = chain(P::NotUtf8, |p| match p {
            P::NotUtf8 => Some(P::TooLong),
            P::TooLong => Some(P::Absolute),
            P::Absolute => Some(P::WindowsForm),
            P::WindowsForm => Some(P::Escapes),
            P::Escapes => Some(P::ThroughLink),
            P::ThroughLink => Some(P::Into(ForbiddenClass::Ci)),
            P::Into(_) => Some(P::Encloses(ForbiddenClass::Ci)),
            P::Encloses(_) => None,
        });
        variants
            .into_iter()
            .flat_map(|p| match p {
                P::Into(_) => every_forbidden_class().into_iter().map(P::Into).collect(),
                P::Encloses(_) => every_forbidden_class()
                    .into_iter()
                    .map(P::Encloses)
                    .collect(),
                other => vec![other],
            })
            .collect()
    }

    /// Every `TestDisabling`, `Marker` with every marker.
    fn every_test_disabling() -> Vec<TestDisabling> {
        use TestDisabling as D;
        let variants = chain(D::Marker(Marker::Skip), |d| match d {
            D::Marker(_) => Some(D::DeletedTestFile),
            D::DeletedTestFile => Some(D::TestsRemoved),
            D::TestsRemoved => Some(D::TestConfigChanged),
            D::TestConfigChanged => None,
        });
        variants
            .into_iter()
            .flat_map(|d| match d {
                D::Marker(_) => every_marker().into_iter().map(D::Marker).collect(),
                other => vec![other],
            })
            .collect()
    }

    /// Every `PatchViolation` with every value of every nested enum, and
    /// the extremes of every number.
    fn every_violation() -> Vec<PatchViolation> {
        use PatchViolation as V;
        let variants = chain(
            V::TooManyFiles {
                files: usize::MAX,
                limit: u32::MAX,
            },
            |v| match v {
                V::TooManyFiles { .. } => Some(V::Empty),
                V::Empty => Some(V::Malformed {
                    index: 0,
                    problem: ChangeProblem::OutOfOrder,
                }),
                V::Malformed { .. } => Some(V::BaseLinkMalformed {
                    index: 1,
                    problem: ChangeProblem::OutOfOrder,
                }),
                V::BaseLinkMalformed { .. } => Some(V::TooManyLines { limit: 0 }),
                V::TooManyLines { .. } => Some(V::TooManyBytes { limit: u32::MAX }),
                V::TooManyBytes { .. } => Some(V::Forbidden {
                    index: 2,
                    class: ForbiddenClass::Ci,
                }),
                V::Forbidden { .. } => Some(V::Gitlink { index: usize::MAX }),
                V::Gitlink { .. } => Some(V::NotText {
                    index: 3,
                    reason: NotText::Nul,
                }),
                V::NotText { .. } => Some(V::Link {
                    index: 4,
                    problem: LinkProblem::NotUtf8,
                }),
                V::Link { .. } => Some(V::DisablesTests {
                    index: 5,
                    reason: TestDisabling::DeletedTestFile,
                }),
                V::DisablesTests { .. } => None,
            },
        );
        variants
            .into_iter()
            .flat_map(|v| match v {
                V::Malformed { index, .. } => every_change_problem()
                    .into_iter()
                    .map(|problem| V::Malformed { index, problem })
                    .collect(),
                V::BaseLinkMalformed { index, .. } => every_change_problem()
                    .into_iter()
                    .map(|problem| V::BaseLinkMalformed { index, problem })
                    .collect(),
                V::Forbidden { index, .. } => every_forbidden_class()
                    .into_iter()
                    .map(|class| V::Forbidden { index, class })
                    .collect(),
                V::NotText { index, .. } => every_not_text()
                    .into_iter()
                    .map(|reason| V::NotText { index, reason })
                    .collect(),
                V::Link { index, .. } => every_link_problem()
                    .into_iter()
                    .map(|problem| V::Link { index, problem })
                    .collect(),
                V::DisablesTests { index, .. } => every_test_disabling()
                    .into_iter()
                    .map(|reason| V::DisablesTests { index, reason })
                    .collect(),
                other => vec![other],
            })
            .collect()
    }

    fn limits(files: u32, lines: u32, bytes: u32) -> PatchLimits {
        let n = |v| NonZeroU32::new(v).expect("a test limit is not 0");
        PatchLimits {
            max_changed_files: n(files),
            max_changed_lines: n(lines),
            max_changed_bytes: n(bytes),
        }
    }

    /// Every shape of a patch check: both verdicts and their extremes,
    /// every violation alone and all of them in one list, and both
    /// unreadable paths at 0 and `usize::MAX`.
    fn every_patch_check() -> Vec<PatchCheck> {
        let mut checks = Vec::new();
        for limits in [
            PatchLimits::DEFAULT,
            limits(1, 1, 1),
            limits(u32::MAX, u32::MAX, u32::MAX),
        ] {
            for verdict in [
                PatchVerdict::Pass { files: 0, lines: 0 },
                PatchVerdict::Pass {
                    files: u32::MAX,
                    lines: u32::MAX,
                },
                PatchVerdict::Reject(vec![]),
            ] {
                checks.push(PatchCheck::Judged { limits, verdict });
            }
        }
        for violation in every_violation() {
            checks.push(PatchCheck::Judged {
                limits: PatchLimits::DEFAULT,
                verdict: PatchVerdict::Reject(vec![violation]),
            });
        }
        checks.push(PatchCheck::Judged {
            limits: PatchLimits::DEFAULT,
            verdict: PatchVerdict::Reject(every_violation()),
        });
        for index in [0, usize::MAX] {
            checks.push(PatchCheck::Unreadable(UnreadablePath::Change { index }));
            checks.push(PatchCheck::Unreadable(UnreadablePath::BaseLink { index }));
        }
        checks
    }

    /// Events of every kind, with every value of every enum, every text of
    /// [`texts`], zero and `u64::MAX` usage and a citation line of
    /// `u32::MAX`, and every patch check of [`every_patch_check`].
    fn every_event() -> Vec<RunEvent> {
        let mut events = Vec::new();
        for (k, check) in every_patch_check().into_iter().enumerate() {
            events.push(RunEvent::PatchChecked {
                check,
                usage: usages()[k % 3],
            });
        }
        for (k, text) in texts().into_iter().enumerate() {
            let usage = usages()[k % 3];
            let source = SOURCES[k % SOURCES.len()];
            events.push(RunEvent::TicketReceived {
                ticket: Ticket {
                    source,
                    key: text.clone(),
                    title: format!("t{text}"),
                    body: text.repeat(3),
                },
                base: sha(),
            });
            events.push(RunEvent::TriageFinished {
                verdict: TriageVerdict::NeedsInformation {
                    questions: vec![text.clone(), String::new()],
                },
                usage,
            });
            events.push(RunEvent::QuestionsPosted {
                reference: text.clone(),
            });
            events.push(RunEvent::PullRequestOpened {
                reference: text.clone(),
            });
            events.push(RunEvent::JobFailed {
                detail: text.clone(),
                usage,
            });
            events.push(RunEvent::RootCauseProposed {
                analysis: reference(&format!("a{text}")),
                citations: vec![Citation {
                    path: text.clone(),
                    line: u32::MAX,
                    sha: CommitSha::parse(&"f".repeat(64)).expect("sha"),
                    quote: text.clone(),
                }],
                usage,
            });
        }
        for source in SOURCES {
            events.push(RunEvent::TicketReceived {
                ticket: Ticket {
                    source,
                    key: String::from("k"),
                    title: String::from("t"),
                    body: String::new(),
                },
                base: sha(),
            });
        }
        for usage in usages() {
            events.push(RunEvent::TriageFinished {
                verdict: TriageVerdict::Ready,
                usage,
            });
            events.push(RunEvent::TriageFinished {
                verdict: TriageVerdict::NeedsInformation { questions: vec![] },
                usage,
            });
            events.push(RunEvent::ReproductionWritten {
                test: reference("sha256:00"),
                usage,
            });
            events.push(RunEvent::FixWritten {
                diff: reference("d"),
                usage,
            });
            events.push(RunEvent::RootCauseProposed {
                analysis: reference("a"),
                citations: vec![],
                usage,
            });
            events.push(RunEvent::CitationsChecked {
                results: CITATION_STATUSES.to_vec(),
                usage,
            });
            events.push(RunEvent::CitationsChecked {
                results: vec![],
                usage,
            });
        }
        for status in TEST_STATUSES {
            events.push(RunEvent::ReproductionChecked {
                status,
                usage: Usage::default(),
            });
            events.push(RunEvent::FixVerified {
                checks: FixChecks {
                    reproduction_test: status,
                    reproduction_test_unchanged: CheckStatus::Passed,
                    previously_green_tests: CheckStatus::Passed,
                    lint: CheckStatus::Passed,
                    typecheck: CheckStatus::Passed,
                },
                usage: Usage::default(),
            });
        }
        for status in CHECK_STATUSES {
            events.push(RunEvent::FixVerified {
                checks: FixChecks {
                    reproduction_test: TestStatus::Passed,
                    reproduction_test_unchanged: status,
                    previously_green_tests: status,
                    lint: status,
                    typecheck: status,
                },
                usage: Usage::default(),
            });
        }
        events
    }

    /// Encode, serialize, parse with the log's limits, decode: the same
    /// event, for every kind and every enum value; and the stored line
    /// reads back through the canonical check.
    #[test]
    fn every_event_kind_round_trips() {
        let events = every_event();
        for kind in EventKind::ALL {
            assert!(events.iter().any(|e| e.kind() == kind), "{kind:?}");
        }
        for event in &events {
            let line = event_line(event).expect("writable");
            assert!(!line.contains(&b'\n'), "{event:?}");
            assert_eq!(read_event(&line, CURRENT).as_ref(), Ok(event));
        }
        assert_eq!(SOURCES.len(), 4);
        assert_eq!(TEST_STATUSES.len(), 6);
        assert_eq!(CHECK_STATUSES.len(), 4);
        assert_eq!(CITATION_STATUSES.len(), 3);
        for (id, previous) in [
            ("run-1", None),
            ("", Some(RunId::new(String::from("\u{0}\n\"")))),
        ] {
            let start = RunStart {
                budget: Budget {
                    cost_micro_usd: u64::MAX,
                    duration_ms: 0,
                },
                previous,
            };
            let id = RunId::new(String::from(id));
            let line = header_line(&id, &start).expect("writable");
            assert_eq!(read_header(&line), Ok((id, start, CURRENT)));
        }
    }

    /// The on-disk format of version 1, pinned: a hand-written v1 log
    /// decodes to a known `RunLog`, and encoding that log gives the bytes
    /// back exactly. Its event lines are version 2 lines too; as a version
    /// 1 log it holds `FixWritten`, which [`admits`] refuses there.
    #[test]
    fn golden_v1_log() {
        let golden = concat!(
            r#"{"format":"boneli-run-log","version":1,"run":"run-7","budget":{"cost_micro_usd":1000000,"duration_ms":600000},"previous":"run-6"}"#,
            "\n",
            r#"{"event":"TicketReceived","ticket":{"source":"GitLab","key":"BUG-17","title":"Total \"off\"","body":"line 1\nline 2\u0000"},"base":"0123456789abcdef0123456789abcdef01234567"}"#,
            "\n",
            r#"{"event":"TriageFinished","verdict":{"kind":"NeedsInformation","questions":["Which record?"]},"usage":{"cost_micro_usd":1000,"duration_ms":100}}"#,
            "\n",
            r#"{"event":"TriageFinished","verdict":{"kind":"Ready"},"usage":{"cost_micro_usd":0,"duration_ms":0}}"#,
            "\n",
            r#"{"event":"QuestionsPosted","reference":"issue-comment/55"}"#,
            "\n",
            r#"{"event":"ReproductionWritten","test":"sha256:aa","usage":{"cost_micro_usd":1,"duration_ms":2}}"#,
            "\n",
            r#"{"event":"ReproductionChecked","status":"FailedOnAssertion","usage":{"cost_micro_usd":3,"duration_ms":4}}"#,
            "\n",
            r#"{"event":"RootCauseProposed","analysis":"sha256:bb","citations":[{"path":"src/a.rs","line":4294967295,"sha":"0123456789abcdef0123456789abcdef01234567","quote":"x"}],"usage":{"cost_micro_usd":5,"duration_ms":6}}"#,
            "\n",
            r#"{"event":"CitationsChecked","results":["Verified","Mismatch","Unverifiable"],"usage":{"cost_micro_usd":7,"duration_ms":8}}"#,
            "\n",
            r#"{"event":"FixWritten","diff":"sha256:cc","usage":{"cost_micro_usd":9,"duration_ms":10}}"#,
            "\n",
            r#"{"event":"FixVerified","checks":{"reproduction_test":"Passed","reproduction_test_unchanged":"Passed","previously_green_tests":"Failed","lint":"NotConfigured","typecheck":"Unknown"},"usage":{"cost_micro_usd":11,"duration_ms":12}}"#,
            "\n",
            r#"{"event":"PullRequestOpened","reference":"pull/101"}"#,
            "\n",
            r#"{"event":"JobFailed","detail":"sandbox exited with status 137","usage":{"cost_micro_usd":18446744073709551615,"duration_ms":0}}"#,
            "\n",
        );
        let usage = |cost_micro_usd, duration_ms| Usage {
            cost_micro_usd,
            duration_ms,
        };
        let want = RunLog {
            start: RunStart {
                budget: Budget {
                    cost_micro_usd: 1_000_000,
                    duration_ms: 600_000,
                },
                previous: Some(RunId::new(String::from("run-6"))),
            },
            events: vec![
                RunEvent::TicketReceived {
                    ticket: Ticket {
                        source: TicketSource::GitLab,
                        key: String::from("BUG-17"),
                        title: String::from("Total \"off\""),
                        body: String::from("line 1\nline 2\u{0}"),
                    },
                    base: sha(),
                },
                RunEvent::TriageFinished {
                    verdict: TriageVerdict::NeedsInformation {
                        questions: vec![String::from("Which record?")],
                    },
                    usage: usage(1_000, 100),
                },
                RunEvent::TriageFinished {
                    verdict: TriageVerdict::Ready,
                    usage: usage(0, 0),
                },
                RunEvent::QuestionsPosted {
                    reference: String::from("issue-comment/55"),
                },
                RunEvent::ReproductionWritten {
                    test: reference("sha256:aa"),
                    usage: usage(1, 2),
                },
                RunEvent::ReproductionChecked {
                    status: TestStatus::FailedOnAssertion,
                    usage: usage(3, 4),
                },
                RunEvent::RootCauseProposed {
                    analysis: reference("sha256:bb"),
                    citations: vec![Citation {
                        path: String::from("src/a.rs"),
                        line: u32::MAX,
                        sha: sha(),
                        quote: String::from("x"),
                    }],
                    usage: usage(5, 6),
                },
                RunEvent::CitationsChecked {
                    results: CITATION_STATUSES.to_vec(),
                    usage: usage(7, 8),
                },
                RunEvent::FixWritten {
                    diff: reference("sha256:cc"),
                    usage: usage(9, 10),
                },
                RunEvent::FixVerified {
                    checks: FixChecks {
                        reproduction_test: TestStatus::Passed,
                        reproduction_test_unchanged: CheckStatus::Passed,
                        previously_green_tests: CheckStatus::Failed,
                        lint: CheckStatus::NotConfigured,
                        typecheck: CheckStatus::Unknown,
                    },
                    usage: usage(11, 12),
                },
                RunEvent::PullRequestOpened {
                    reference: String::from("pull/101"),
                },
                RunEvent::JobFailed {
                    detail: String::from("sandbox exited with status 137"),
                    usage: usage(u64::MAX, 0),
                },
            ],
        };
        let mut lines = golden.split_terminator('\n');
        let (id, start, version) =
            read_header(lines.next().expect("header").as_bytes()).expect("header");
        assert_eq!(id, RunId::new(String::from("run-7")));
        assert_eq!(version, Version::V1);
        let lines: Vec<&str> = lines.collect();
        let events: Vec<RunEvent> = lines
            .iter()
            .map(|l| read_event(l.as_bytes(), Version::V2).expect("event"))
            .collect();
        assert_eq!(RunLog { start, events }, want);
        for (line, event) in lines.iter().zip(&want.events) {
            let v1 = read_event(line.as_bytes(), Version::V1);
            if event.kind() == EventKind::FixWritten {
                assert!(v1.is_err(), "{line}");
            } else {
                assert_eq!(v1.as_ref(), Ok(event), "{line}");
            }
        }

        let mut encoded = serialize(&encode_header(&id, &want.start, Version::V1)).expect("header");
        encoded.push(b'\n');
        for event in &want.events {
            encoded.extend(event_line(event).expect("event"));
            encoded.push(b'\n');
        }
        assert_eq!(String::from_utf8(encoded).expect("UTF-8"), golden);
    }

    /// The on-disk format of version 2, pinned: the header and the three
    /// shapes of `PatchChecked`, with payload objects at the deepest
    /// nesting, decode to known events and encode back exactly.
    #[test]
    fn golden_v2_log() {
        let golden = concat!(
            r#"{"format":"boneli-run-log","version":2,"run":"run-8","budget":{"cost_micro_usd":5,"duration_ms":6},"previous":null}"#,
            "\n",
            r#"{"event":"PatchChecked","check":{"kind":"Judged","limits":{"max_changed_files":25,"max_changed_lines":1000,"max_changed_bytes":42000},"verdict":{"kind":"Pass","files":1,"lines":2}},"usage":{"cost_micro_usd":0,"duration_ms":1000}}"#,
            "\n",
            r#"{"event":"PatchChecked","check":{"kind":"Judged","limits":{"max_changed_files":2,"max_changed_lines":3,"max_changed_bytes":4},"verdict":{"kind":"Reject","violations":[{"kind":"TooManyLines","limit":3},{"kind":"Malformed","index":0,"problem":{"kind":"Path","problem":"Backslash"}},{"kind":"Link","index":1,"problem":{"kind":"Into","class":"Ci"}},{"kind":"DisablesTests","index":1,"reason":{"kind":"Marker","marker":"SkipIf"}},{"kind":"DisablesTests","index":1,"reason":{"kind":"TestsRemoved"}},{"kind":"NotText","index":1,"reason":"BidiControl"},{"kind":"Empty"}]}},"usage":{"cost_micro_usd":0,"duration_ms":7}}"#,
            "\n",
            r#"{"event":"PatchChecked","check":{"kind":"Unreadable","path":{"kind":"BaseLink","index":3}},"usage":{"cost_micro_usd":0,"duration_ms":0}}"#,
            "\n",
        );
        let usage = |duration_ms| Usage {
            cost_micro_usd: 0,
            duration_ms,
        };
        let want = vec![
            RunEvent::PatchChecked {
                check: PatchCheck::Judged {
                    limits: PatchLimits::DEFAULT,
                    verdict: PatchVerdict::Pass { files: 1, lines: 2 },
                },
                usage: usage(1_000),
            },
            RunEvent::PatchChecked {
                check: PatchCheck::Judged {
                    limits: limits(2, 3, 4),
                    verdict: PatchVerdict::Reject(vec![
                        PatchViolation::TooManyLines { limit: 3 },
                        PatchViolation::Malformed {
                            index: 0,
                            problem: ChangeProblem::Path(CitationProblem::Backslash),
                        },
                        PatchViolation::Link {
                            index: 1,
                            problem: LinkProblem::Into(ForbiddenClass::Ci),
                        },
                        PatchViolation::DisablesTests {
                            index: 1,
                            reason: TestDisabling::Marker(Marker::SkipIf),
                        },
                        PatchViolation::DisablesTests {
                            index: 1,
                            reason: TestDisabling::TestsRemoved,
                        },
                        PatchViolation::NotText {
                            index: 1,
                            reason: NotText::BidiControl,
                        },
                        PatchViolation::Empty,
                    ]),
                },
                usage: usage(7),
            },
            RunEvent::PatchChecked {
                check: PatchCheck::Unreadable(UnreadablePath::BaseLink { index: 3 }),
                usage: usage(0),
            },
        ];
        let mut lines = golden.split_terminator('\n');
        let (id, start, version) =
            read_header(lines.next().expect("header").as_bytes()).expect("header");
        assert_eq!(version, Version::V2);
        let events: Vec<RunEvent> = lines
            .map(|l| read_event(l.as_bytes(), Version::V2).expect("event"))
            .collect();
        assert_eq!(events, want);
        let mut encoded = header_line(&id, &start).expect("header");
        encoded.push(b'\n');
        for event in &want {
            encoded.extend(event_line(event).expect("event"));
            encoded.push(b'\n');
        }
        assert_eq!(String::from_utf8(encoded).expect("UTF-8"), golden);
    }

    /// Every value of every enum a patch check holds is listed for
    /// decoding: the codec's tables equal the chains, which match every
    /// variant, and every check round-trips as a canonical line.
    #[test]
    fn patch_checked_round_trips_every_variant() {
        assert_eq!(CITATION_PROBLEMS.to_vec(), every_citation_problem());
        assert_eq!(FORBIDDEN_CLASSES.to_vec(), every_forbidden_class());
        assert_eq!(NOT_TEXT.to_vec(), every_not_text());
        assert_eq!(Marker::ALL.to_vec(), every_marker());
        assert_eq!(every_change_problem().len(), 15);
        assert_eq!(every_link_problem().len(), 18);
        assert_eq!(every_test_disabling().len(), 20);
        // 5 variants without a nested enum, 15 + 15 + 6 + 3 + 18 + 20 with.
        assert_eq!(every_violation().len(), 82);
        for check in every_patch_check() {
            let event = RunEvent::PatchChecked {
                check,
                usage: Usage::default(),
            };
            let line = event_line(&event).expect("writable");
            assert_eq!(read_event(&line, Version::V2), Ok(event.clone()));
            assert!(read_event(&line, Version::V1).is_err(), "{event:?}");
        }
    }

    /// A patch check that does not decode exactly fails closed: a zero
    /// limit, a number above `u32::MAX` where the domain holds a `u32`, an
    /// unknown variant at every level, a missing or extra key, and a
    /// payload enum written as a string.
    #[test]
    fn patch_checked_malformed_fails_closed() {
        let line = |check: &str| {
            format!(
                r#"{{"event":"PatchChecked","check":{check},"usage":{{"cost_micro_usd":0,"duration_ms":0}}}}"#
            )
        };
        let judged = |limits: &str, verdict: &str| {
            line(&format!(
                r#"{{"kind":"Judged","limits":{limits},"verdict":{verdict}}}"#
            ))
        };
        let limits =
            r#"{"max_changed_files":25,"max_changed_lines":1000,"max_changed_bytes":42000}"#;
        let reject = |violation: &str| {
            judged(
                limits,
                &format!(r#"{{"kind":"Reject","violations":[{violation}]}}"#),
            )
        };
        let good = [
            judged(limits, r#"{"kind":"Pass","files":1,"lines":2}"#),
            reject(r#"{"kind":"TooManyLines","limit":4294967295}"#),
            reject(r#"{"kind":"Link","index":0,"problem":{"kind":"TooLong"}}"#),
            line(r#"{"kind":"Unreadable","path":{"kind":"Change","index":0}}"#),
        ];
        for text in &good {
            assert!(read_event(text.as_bytes(), Version::V2).is_ok(), "{text}");
        }
        let bad = [
            judged(
                r#"{"max_changed_files":0,"max_changed_lines":1000,"max_changed_bytes":42000}"#,
                r#"{"kind":"Pass","files":1,"lines":2}"#,
            ),
            judged(
                r#"{"max_changed_files":4294967296,"max_changed_lines":1000,"max_changed_bytes":42000}"#,
                r#"{"kind":"Pass","files":1,"lines":2}"#,
            ),
            judged(
                r#"{"max_changed_files":25,"max_changed_lines":1000}"#,
                r#"{"kind":"Pass","files":1,"lines":2}"#,
            ),
            judged(limits, r#"{"kind":"Pass","files":4294967296,"lines":2}"#),
            judged(limits, r#"{"kind":"Pass","files":1,"lines":2,"extra":0}"#),
            judged(limits, r#"{"kind":"Accept","files":1,"lines":2}"#),
            judged(limits, r#"{"kind":"Reject","violations":{}}"#),
            judged(limits, r#""Pass""#),
            reject(r#"{"kind":"TooManyLines","limit":4294967296}"#),
            reject(r#"{"kind":"TooManyLines","limit":-1}"#),
            reject(r#"{"kind":"Gitlink","index":1.5}"#),
            reject(r#"{"kind":"Gitlink"}"#),
            reject(r#"{"kind":"Empty","index":0}"#),
            reject(r#"{"kind":"Bogus","index":0}"#),
            reject(r#""Empty""#),
            reject(r#"{"kind":"Forbidden","index":0,"class":"Docs"}"#),
            reject(r#"{"kind":"NotText","index":0,"reason":{"kind":"Nul"}}"#),
            reject(r#"{"kind":"Link","index":0,"problem":"TooLong"}"#),
            reject(r#"{"kind":"Link","index":0,"problem":{"kind":"Into"}}"#),
            reject(r#"{"kind":"Link","index":0,"problem":{"kind":"TooLong","class":"Ci"}}"#),
            reject(r#"{"kind":"Link","index":0,"problem":{"kind":"Sideways"}}"#),
            reject(r#"{"kind":"Malformed","index":0,"problem":{"kind":"Path","problem":"Tab"}}"#),
            reject(
                r#"{"kind":"DisablesTests","index":0,"reason":{"kind":"Marker","marker":"skip"}}"#,
            ),
            line(r#"{"kind":"Unreadable","path":{"kind":"Tree","index":0}}"#),
            line(r#"{"kind":"Unreadable","path":{"kind":"Change"}}"#),
            line(r#"{"kind":"Unreadable","path":{"kind":"Change","index":18446744073709551616}}"#),
            line(r#"{"kind":"Unknown"}"#),
            line(r#"{"limits":{},"verdict":{}}"#),
        ];
        for text in &bad {
            assert!(read_event(text.as_bytes(), Version::V2).is_err(), "{text}");
        }
    }

    /// The deepest line of every kind, measured on the parser: each parses
    /// at `MAX_DEPTH` and none parses one level lower, so the limit is the
    /// schema's own depth.
    #[test]
    fn schema_depth_is_the_limit() {
        let deepest = |line: &[u8]| {
            (1..=MAX_DEPTH)
                .find(|&d| {
                    let limits = Limits::new(MAX_LINE_BYTES, d, MAX_VALUES).expect("limits");
                    boneli_json::parse(line, &limits).is_ok()
                })
                .expect("parses within MAX_DEPTH")
        };
        let mut max = 0;
        for event in every_event() {
            let line = event_line(&event).expect("writable");
            max = max.max(deepest(&line));
        }
        let header = header_line(
            &RunId::new(String::from("r")),
            &RunStart {
                budget: Budget {
                    cost_micro_usd: 1,
                    duration_ms: 1,
                },
                previous: None,
            },
        )
        .expect("header");
        max = max.max(deepest(&header));
        assert_eq!(max, MAX_DEPTH);
    }

    /// No error of the codec carries content: a marker in a key, a value,
    /// a variant name or a malformed line never reaches its text.
    #[test]
    fn malformed_never_echoes_content() {
        const MARK: &str = "MARK-91c2";
        let lines = [
            format!("{{\"event\":\"{MARK}\"}}"),
            format!("{{\"event\":\"QuestionsPosted\",\"reference\":\"x\",\"{MARK}\":1}}"),
            format!("{{\"event\":\"QuestionsPosted\",\"reference\":{MARK}}}"),
            format!(
                "{{\"event\":\"ReproductionChecked\",\"status\":\"{MARK}\",\"usage\":{{\"cost_micro_usd\":0,\"duration_ms\":0}}}}"
            ),
            MARK.to_owned(),
        ];
        for line in lines {
            let error = read_event(line.as_bytes(), CURRENT).expect_err("malformed");
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains(MARK), "{shown}");
        }
    }
}
