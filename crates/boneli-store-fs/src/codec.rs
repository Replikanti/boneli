//! The run log format, version 1 (ADR-012, D3): one JSON object per line,
//! encoded and decoded by hand over `boneli_json::Value` (ADR-008).
//!
//! Line 1 is the header,
//! `{"format":"boneli-run-log","version":1,"run":s,"budget":{"cost_micro_usd":n,"duration_ms":n},"previous":null|s}`;
//! every further line is one event, `{"event":"<RunEvent variant>", ...}`
//! with the variant's fields in declaration order and named as in
//! `boneli_domain`. Enums are their variant names, numbers `u64` lexemes.
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
use boneli_domain::{
    Budget, CheckStatus, Citation, CitationStatus, CommitSha, EventKind, EvidenceRef, FixChecks,
    RunEvent, RunId, TestStatus, Ticket, TicketSource, TriageVerdict, Usage,
};
use boneli_json::{Limits, Object, Value};

/// The longest line, without its `\n`: 8 MiB (ADR-012, D3). Derived from
/// the largest ticket body the store must take, at the worst JSON escape
/// ratio of 6 bytes per input byte; a longer event fails its append.
pub const MAX_LINE_BYTES: usize = 8_388_608;

/// The deepest nesting of a line: the schema's own depth, event →
/// `citations` → citation and event → `verdict` → `questions` (ADR-012, D3).
pub const MAX_DEPTH: usize = 3;

/// The most values in one line: 2^16, where the per-value memory term of
/// ADR-008 D5 (136 B × 65,536 = 8.5 MiB) matches the byte term (ADR-012,
/// D3). Admits 13,105 citations or 65,528 questions in one event.
pub const MAX_VALUES: usize = 65_536;

/// The `format` of the header.
const FORMAT: &str = "boneli-run-log";

/// The `version` of the header.
const VERSION: u64 = 1;

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
        EventKind::FixVerified => "FixVerified",
        EventKind::PullRequestOpened => "PullRequestOpened",
        EventKind::JobFailed => "JobFailed",
    }
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::from(s.as_str())).collect())
}

/// The header of a run's log.
pub(crate) fn encode_header(id: &RunId, start: &RunStart) -> Value {
    let mut o = Object::with_capacity(5);
    o.insert("format", FORMAT);
    o.insert("version", VERSION);
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

/// The header: the run id and how the run started.
pub(crate) fn decode_header(value: &Value) -> Decoded<(RunId, RunStart)> {
    let o = value
        .as_object()
        .ok_or(Malformed::Line("the header is not an object"))?;
    if o.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(Malformed::Line("not a boneli run log"));
    }
    if o.get("version")
        .and_then(Value::as_number)
        .map(|n| n.as_str())
        != Some("1")
    {
        return Err(Malformed::Line("an unsupported log version"));
    }
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

/// The header line of a new log, without its `\n`.
pub(crate) fn header_line(id: &RunId, start: &RunStart) -> Result<Vec<u8>, Unwritable> {
    let want = (id.clone(), start.clone());
    checked_line(&encode_header(id, start), &want, decode_header)
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

/// The header of a stored log.
pub(crate) fn read_header(line: &[u8]) -> Decoded<(RunId, RunStart)> {
    read_line(line, decode_header, |(id, start)| encode_header(id, start))
}

/// One stored event.
pub(crate) fn read_event(line: &[u8]) -> Decoded<RunEvent> {
    read_line(line, decode_event, encode_event)
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

    /// Events of every kind, with every value of every enum, every text of
    /// [`texts`], zero and `u64::MAX` usage and a citation line of
    /// `u32::MAX`.
    fn every_event() -> Vec<RunEvent> {
        let mut events = Vec::new();
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
            assert_eq!(read_event(&line).as_ref(), Ok(event));
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
            assert_eq!(read_header(&line), Ok((id, start)));
        }
    }

    /// The on-disk format, pinned: a hand-written v1 log decodes to a known
    /// `RunLog`, and encoding that log gives the bytes back exactly.
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
        let (id, start) = read_header(lines.next().expect("header").as_bytes()).expect("header");
        assert_eq!(id, RunId::new(String::from("run-7")));
        let events: Vec<RunEvent> = lines
            .map(|l| read_event(l.as_bytes()).expect("event"))
            .collect();
        assert_eq!(RunLog { start, events }, want);

        let mut encoded = header_line(&id, &want.start).expect("header");
        encoded.push(b'\n');
        for event in &want.events {
            encoded.extend(event_line(event).expect("event"));
            encoded.push(b'\n');
        }
        assert_eq!(String::from_utf8(encoded).expect("UTF-8"), golden);
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
            let error = read_event(line.as_bytes()).expect_err("malformed");
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains(MARK), "{shown}");
        }
    }
}
