//! The run log (ADR-012, D2 to D5).

use std::path::{Path, PathBuf};
use std::time::Instant;

use boneli_app::{EventStore, RunLog, RunStart, StoreError};
use boneli_domain::{
    Budget, CommitSha, EvidenceRef, ForbiddenClass, LinkProblem, Marker, NotText, PatchCheck,
    PatchLimits, PatchVerdict, PatchViolation, RunEvent, RunId, TestDisabling, Ticket,
    TicketSource, TriageVerdict, Usage,
};
use boneli_store_fs::{FsStore, MAX_DEPTH, MAX_LINE_BYTES, MAX_VALUES};

use crate::support::{
    Fresh, TempDir, append_raw, id, log_path, marker, names_in, sha256_hex, start,
    unavailable_detail,
};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

/// The header line `create` writes for [`start`], without its `\n`.
fn header_line(run: &str) -> String {
    format!(
        "{{\"format\":\"boneli-run-log\",\"version\":2,\"run\":\"{run}\",\"budget\":{{\"cost_micro_usd\":1000000,\"duration_ms\":600000}},\"previous\":null}}"
    )
}

/// A store with one run `run-1` holding `marker(1)`, and its log's path.
fn one_run(tag: &str) -> (Fresh, RunId, PathBuf) {
    let fresh = Fresh::new(tag);
    let run = id("run-1");
    fresh.create(&run, &start()).expect("create");
    fresh.append(&run, &marker(1)).expect("append");
    let path = log_path(fresh.store.root(), &run);
    (fresh, run, path)
}

fn log_of(events: Vec<RunEvent>) -> RunLog {
    RunLog {
        start: start(),
        events,
    }
}

/// `load` and `append` both refuse the log with `Unavailable`, the
/// details name the line, and the file is byte for byte as before.
fn assert_fails_closed(fresh: &Fresh, run: &RunId, path: &Path, line: Option<u64>, why: &str) {
    let before = std::fs::read(path).expect("read");
    let loaded = unavailable_detail(fresh.load(run));
    let appended = unavailable_detail(fresh.append(run, &marker(9)));
    if let Some(n) = line {
        let at = format!("line {n}");
        assert!(loaded.contains(&at), "{why}: load said {loaded:?}");
        assert!(appended.contains(&at), "{why}: append said {appended:?}");
    }
    assert_eq!(
        std::fs::read(path).expect("read"),
        before,
        "{why}: the file changed"
    );
}

/// Look-alike ids are distinct runs: each loads its own log.
#[test]
fn lookalike_run_ids_are_distinct_runs() {
    let fresh = Fresh::new("lookalike-ids");
    let ids = lookalikes();
    for (k, text) in ids.iter().enumerate() {
        let own = RunStart {
            previous: Some(id(&format!("previous-{k}"))),
            ..start()
        };
        fresh.create(&id(text), &own).expect("create");
        fresh.append(&id(text), &marker(k)).expect("append");
    }
    for (k, text) in ids.iter().enumerate() {
        let want = RunLog {
            start: RunStart {
                previous: Some(id(&format!("previous-{k}"))),
                ..start()
            },
            events: vec![marker(k)],
        };
        assert_eq!(fresh.load(&id(text)), Ok(want), "{text:?}");
    }
}

fn lookalikes() -> Vec<String> {
    vec![
        String::from("run-1"),
        String::from("run\u{2010}1"),
        String::from("run-\u{0430}"),
        String::from("run-a"),
        String::from("run-1 "),
        String::from("run-\u{200B}1"),
        String::from("caf\u{e9}"),
        String::from("cafe\u{301}"),
        String::from("\u{FF52}\u{FF55}\u{FF4E}-1"),
        String::from("RUN-1"),
        String::new(),
        String::from("\u{0}"),
        "r".repeat(300),
    ]
}

/// `runs/` holds exactly `<sha256 of the id>.log` per run, 64 lowercase hex
/// digits each, and the file's first line carries the id.
#[test]
fn log_layout_is_hashed_names() {
    let fresh = Fresh::new("layout");
    let ids = lookalikes();
    for text in &ids {
        fresh.create(&id(text), &start()).expect("create");
    }
    let mut want: Vec<String> = ids
        .iter()
        .map(|t| format!("{}.log", sha256_hex(t.as_bytes())))
        .collect();
    want.sort();
    let runs = fresh.store.root().join("runs");
    assert_eq!(names_in(&runs), want);
    for name in names_in(&runs) {
        let (stem, ext) = name.split_once('.').expect("extension");
        assert_eq!(ext, "log");
        assert_eq!(stem.len(), 64);
        assert!(stem.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }
    let path = log_path(fresh.store.root(), &id("run-1"));
    let text = std::fs::read_to_string(&path).expect("read");
    assert_eq!(text, format!("{}\n", header_line("run-1")));
}

/// A file without a complete header line fails closed for `load` and
/// `append`, and `append` does not truncate it as a torn tail.
#[test]
fn log_without_complete_header_fails_closed() {
    let fresh = Fresh::new("no-header");
    let run = id("run-1");
    fresh.create(&run, &start()).expect("create");
    let path = log_path(fresh.store.root(), &run);
    for content in [String::new(), header_line("run-1"), String::from("{")] {
        std::fs::write(&path, content.as_bytes()).expect("write");
        assert_fails_closed(&fresh, &run, &path, None, "no complete header");
    }
}

/// A log copied onto another run's name names the other run in its
/// header: that run fails closed and the original stays intact.
#[test]
fn header_run_mismatch_fails_closed() {
    let fresh = Fresh::new("header-mismatch");
    let (a, b) = (id("run-a"), id("run-b"));
    fresh.create(&a, &start()).expect("create");
    fresh.append(&a, &marker(1)).expect("append");
    fresh.create(&b, &start()).expect("create");
    let (pa, pb) = (
        log_path(fresh.store.root(), &a),
        log_path(fresh.store.root(), &b),
    );
    std::fs::copy(&pa, &pb).expect("copy");
    assert_fails_closed(&fresh, &b, &pb, Some(1), "copied log");
    assert_eq!(fresh.load(&a), Ok(log_of(vec![marker(1)])));
}

/// Version 3, version 0, version `2.0`, another format or a header with an
/// extra key fails closed.
#[test]
fn unknown_format_or_version_fails_closed() {
    let fresh = Fresh::new("format-version");
    let run = id("run-1");
    fresh.create(&run, &start()).expect("create");
    let path = log_path(fresh.store.root(), &run);
    let good = header_line("run-1");
    for header in [
        good.replace("\"version\":2", "\"version\":3"),
        good.replace("\"version\":2", "\"version\":0"),
        good.replace("\"version\":2", "\"version\":2.0"),
        good.replace("\"version\":2", "\"version\":\"2\""),
        good.replace("\"version\":2", "\"version\":1.0"),
        good.replace("boneli-run-log", "boneli-run-log2"),
        good.replace(",\"previous\":null}", ",\"previous\":null,\"extra\":0}"),
        good.replace(",\"previous\":null}", "}"),
    ] {
        std::fs::write(&path, format!("{header}\n")).expect("write");
        assert_fails_closed(&fresh, &run, &path, Some(1), &header);
    }
}

/// An unterminated tail (1 byte, half a line, a whole line without its
/// `\n` that parses) is ignored by `load`.
#[test]
fn torn_tail_ignored_on_load() {
    let full = "{\"event\":\"QuestionsPosted\",\"reference\":\"event-2\"}";
    for tail in ["{", &full[..20], full] {
        let (fresh, run, path) = one_run("tail-load");
        append_raw(&path, tail.as_bytes());
        assert_eq!(fresh.load(&run), Ok(log_of(vec![marker(1)])), "{tail:?}");
    }
}

/// The next `append` truncates the tail first: the file then holds exactly
/// the header and the acknowledged lines.
#[test]
fn torn_tail_truncated_on_append() {
    let full = "{\"event\":\"QuestionsPosted\",\"reference\":\"event-2\"}";
    for tail in ["{", &full[..20], full] {
        let (fresh, run, path) = one_run("tail-append");
        append_raw(&path, tail.as_bytes());
        fresh.append(&run, &marker(3)).expect("append");
        assert_eq!(fresh.load(&run), Ok(log_of(vec![marker(1), marker(3)])));
        let text = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            text,
            format!(
                "{}\n{}\n{}\n",
                header_line("run-1"),
                "{\"event\":\"QuestionsPosted\",\"reference\":\"event-1\"}",
                "{\"event\":\"QuestionsPosted\",\"reference\":\"event-3\"}",
            ),
            "{tail:?}"
        );
    }
}

/// A tail of exactly `MAX_LINE_BYTES` is an unacknowledged append and is
/// ignored; one byte more cannot be one, and fails closed.
#[test]
fn torn_tail_limit_boundary() {
    let (fresh, run, path) = one_run("tail-limit");
    append_raw(&path, &vec![b'x'; MAX_LINE_BYTES]);
    assert_eq!(fresh.load(&run), Ok(log_of(vec![marker(1)])));
    append_raw(&path, b"x");
    assert_fails_closed(&fresh, &run, &path, Some(3), "tail over the limit");
}

/// Complete lines that do not decode: each fails closed with its line
/// number, and the file stays byte for byte.
#[test]
fn corrupt_complete_line_fails_closed() {
    let fix = "{\"event\":\"FixWritten\",\"diff\":\"d\",\"usage\":{\"cost_micro_usd\":1,\"duration_ms\":2}}";
    let citation = format!(
        "{{\"event\":\"RootCauseProposed\",\"analysis\":\"a\",\"citations\":[{{\"path\":\"p\",\"line\":1,\"sha\":\"{SHA}\",\"quote\":\"q\"}}],\"usage\":{{\"cost_micro_usd\":1,\"duration_ms\":2}}}}"
    );
    let ticket = format!(
        "{{\"event\":\"TicketReceived\",\"ticket\":{{\"source\":\"GitHub\",\"key\":\"k\",\"title\":\"t\",\"body\":\"b\"}},\"base\":\"{SHA}\"}}"
    );
    // The valid lines first, so a failure below is the mutation's.
    for line in [fix, &citation, &ticket] {
        let (fresh, run, path) = one_run("corrupt-valid");
        append_raw(&path, format!("{line}\n").as_bytes());
        assert_eq!(fresh.load(&run).map(|l| l.events.len()), Ok(2), "{line}");
    }
    let corrupt = [
        String::from("garbage"),
        String::new(),
        String::from("{\"event\":\"Nope\"}"),
        fix.replace("\"diff\"", "\"diff\":\"d\",\"extra\""),
        fix.replace("\"diff\":\"d\",", ""),
        fix.replace("\"diff\":\"d\"", "\"diff\":\"d\",\"diff\":\"d\""),
        fix.replace(":1,", ":1.0,"),
        fix.replace(":1,", ":1e3,"),
        fix.replace(":1,", ":-1,"),
        fix.replace(":1,", ":18446744073709551616,"),
        fix.replace(":1,", ":\"1\","),
        citation.replace("\"line\":1", "\"line\":4294967296"),
        citation.replace(SHA, &SHA.to_uppercase()),
        ticket.replace(SHA, &SHA[..39]),
        ticket.replace("\"GitHub\"", "\"github\""),
        fix.replace("\"diff\":\"d\"", "\"diff\":\" \""),
        fix.replace("\"diff\":\"d\"", "\"diff\":null"),
        String::from("[]"),
        String::from("null"),
    ];
    for line in corrupt {
        let (fresh, run, path) = one_run("corrupt");
        append_raw(&path, format!("{line}\n").as_bytes());
        assert_fails_closed(&fresh, &run, &path, Some(3), &line);
    }
}

/// A line must be the store's own encoding of its event: whitespace, `\r`,
/// another key order or an escape the serializer does not write fail
/// closed, though each decodes to a valid event.
#[test]
fn non_canonical_line_fails_closed() {
    let line = "{\"event\":\"QuestionsPosted\",\"reference\":\"event-2\"}";
    for variant in [
        format!(" {line}"),
        format!("{line} "),
        format!("{line}\r"),
        line.replace(",", ", "),
        String::from("{\"reference\":\"event-2\",\"event\":\"QuestionsPosted\"}"),
        line.replace("event-2", "\\u0065vent-2"),
        line.replace("event-2", "event\\/2"),
    ] {
        let (fresh, run, path) = one_run("canonical");
        append_raw(&path, format!("{variant}\n").as_bytes());
        assert_fails_closed(&fresh, &run, &path, Some(3), &variant);
    }
    let (fresh, run, path) = one_run("canonical-header");
    let header = header_line("run-1").replace(",", ", ");
    let rest = std::fs::read_to_string(&path).expect("read");
    let (_, events) = rest.split_once('\n').expect("header");
    std::fs::write(&path, format!("{header}\n{events}")).expect("write");
    assert_fails_closed(&fresh, &run, &path, Some(1), "spaced header");
}

/// `JobFailed` with the detail sized so its line is exactly
/// `MAX_LINE_BYTES` is stored and loads; one byte more is refused before
/// the file is touched.
#[test]
fn line_limit_boundary() {
    let empty = "{\"event\":\"JobFailed\",\"detail\":\"\",\"usage\":{\"cost_micro_usd\":0,\"duration_ms\":0}}";
    let detail = |n: usize| RunEvent::JobFailed {
        detail: "x".repeat(n),
        usage: Usage::default(),
    };
    let (fresh, run, path) = one_run("line-limit");
    let at_limit = detail(MAX_LINE_BYTES - empty.len());
    fresh
        .append(&run, &at_limit)
        .expect("a line of exactly the limit");
    let bytes = std::fs::read(&path).expect("read");
    let last = bytes[..bytes.len() - 1]
        .rsplit(|&b| b == b'\n')
        .next()
        .expect("last line");
    assert_eq!(last.len(), MAX_LINE_BYTES);
    assert_eq!(
        fresh.load(&run),
        Ok(log_of(vec![marker(1), at_limit.clone()]))
    );
    let over = detail(MAX_LINE_BYTES - empty.len() + 1);
    let refused = unavailable_detail(fresh.append(&run, &over));
    assert!(refused.contains(&MAX_LINE_BYTES.to_string()), "{refused}");
    assert_eq!(std::fs::read(&path).expect("read"), bytes);
    assert_eq!(fresh.load(&run), Ok(log_of(vec![marker(1), at_limit])));
}

/// `TriageFinished` with 65,528 questions holds exactly `MAX_VALUES`
/// values (8 for the event and 1 per question) and is stored; one question
/// more is refused before the file is touched.
#[test]
fn value_limit_boundary() {
    assert_eq!(MAX_VALUES, 65_536);
    let triage = |n: usize| RunEvent::TriageFinished {
        verdict: TriageVerdict::NeedsInformation {
            questions: vec![String::from("q"); n],
        },
        usage: Usage::default(),
    };
    let (fresh, run, path) = one_run("value-limit");
    fresh
        .append(&run, &triage(MAX_VALUES - 8))
        .expect("exactly the value limit");
    let before = std::fs::read(&path).expect("read");
    unavailable_detail(fresh.append(&run, &triage(MAX_VALUES - 7)));
    assert_eq!(std::fs::read(&path).expect("read"), before);
    assert_eq!(
        fresh.load(&run),
        Ok(log_of(vec![marker(1), triage(MAX_VALUES - 8)]))
    );
}

/// `create` publishes the header complete or not at all: the file holds
/// exactly the header line, no temporary name is left, and a second create
/// is `AlreadyExists` with the file unchanged.
#[test]
fn create_publishes_complete_file_only() {
    let fresh = Fresh::new("create-complete");
    let run = id("run-1");
    fresh.create(&run, &start()).expect("create");
    let path = log_path(fresh.store.root(), &run);
    let runs = fresh.store.root().join("runs");
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        format!("{}\n", header_line("run-1"))
    );
    assert_eq!(names_in(&runs).len(), 1);
    fresh.append(&run, &marker(1)).expect("append");
    let before = std::fs::read(&path).expect("read");
    let other = RunStart {
        budget: Budget {
            cost_micro_usd: 1,
            duration_ms: 1,
        },
        previous: Some(id("other")),
    };
    assert_eq!(fresh.create(&run, &other), Err(StoreError::AlreadyExists));
    assert_eq!(std::fs::read(&path).expect("read"), before);
    assert_eq!(names_in(&runs).len(), 1, "{:?}", names_in(&runs));
}

/// Neither a ticket body nor a corrupted line reaches an error detail or
/// its `Display`, whatever the failure.
#[test]
fn error_details_never_echo_content() {
    const SECRET: &str = "SECRET-MARKER-7f3a";
    let (fresh, run, path) = one_run("no-echo");
    let ticket = RunEvent::TicketReceived {
        ticket: Ticket {
            source: TicketSource::Jira,
            key: String::from(SECRET),
            title: String::from(SECRET),
            body: SECRET.repeat(MAX_LINE_BYTES / SECRET.len()),
        },
        base: CommitSha::parse(SHA).expect("sha"),
    };
    let mut errors = vec![fresh.append(&run, &ticket).expect_err("over the limit")];
    let lines = [
        format!("{{\"event\":\"QuestionsPosted\",\"{SECRET}\":\"x\"}}"),
        format!("{{\"event\":\"{SECRET}\"}}"),
        SECRET.to_owned(),
        format!("{{\"event\":\"QuestionsPosted\",\"reference\":\"{SECRET}\"}} "),
    ];
    for line in lines {
        let (fresh, run, path) = one_run("no-echo-line");
        append_raw(&path, format!("{line}\n").as_bytes());
        errors.push(fresh.load(&run).expect_err("corrupt"));
        errors.push(fresh.append(&run, &marker(2)).expect_err("corrupt"));
    }
    let header = header_line(SECRET);
    std::fs::write(&path, format!("{header}\n")).expect("write");
    errors.push(fresh.load(&run).expect_err("mismatch"));
    for error in errors {
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains(SECRET), "{shown}");
        assert!(matches!(error, StoreError::Unavailable { .. }), "{shown}");
    }
}

/// The events of a run up to `CitationsChecked`, as version 1 had them.
fn before_the_fix() -> Vec<RunEvent> {
    let usage = Usage {
        cost_micro_usd: 1,
        duration_ms: 2,
    };
    vec![
        RunEvent::TicketReceived {
            ticket: Ticket {
                source: TicketSource::GitHub,
                key: String::from("BUG-1"),
                title: String::from("t"),
                body: String::new(),
            },
            base: CommitSha::parse(SHA).expect("sha"),
        },
        RunEvent::TriageFinished {
            verdict: TriageVerdict::NeedsInformation {
                questions: vec![String::from("Which record?")],
            },
            usage,
        },
        marker(1),
    ]
}

fn fix_written() -> RunEvent {
    RunEvent::FixWritten {
        diff: EvidenceRef::parse("sha256:00").expect("reference"),
        usage: Usage::default(),
    }
}

fn patch_checked() -> RunEvent {
    RunEvent::PatchChecked {
        check: PatchCheck::Judged {
            limits: PatchLimits::DEFAULT,
            verdict: PatchVerdict::Pass { files: 1, lines: 2 },
        },
        usage: Usage::default(),
    }
}

/// Turns the log's header into a version 1 header; the event lines are
/// the same in both versions.
fn make_version_1(path: &Path) {
    let text = std::fs::read_to_string(path).expect("read");
    let (header, rest) = text.split_once('\n').expect("a header line");
    assert!(header.contains("\"version\":2,"), "{header}");
    let header = header.replace("\"version\":2,", "\"version\":1,");
    std::fs::write(path, format!("{header}\n{rest}")).expect("write");
}

/// A version 1 log that ends before `FixWritten` loads as written, so a
/// previous-run lookup (ADR-004, D6) still finds its questions, and it
/// takes appends of events version 1 allows.
#[test]
fn version_1_log_before_fix_written_loads() {
    let fresh = Fresh::new("v1-loads");
    let run = id("run-1");
    fresh.create(&run, &start()).expect("create");
    for event in before_the_fix() {
        fresh.append(&run, &event).expect("append");
    }
    let path = log_path(fresh.store.root(), &run);
    make_version_1(&path);
    assert_eq!(fresh.load(&run), Ok(log_of(before_the_fix())));
    fresh
        .append(&run, &marker(2))
        .expect("append to a version 1 log");
    let mut events = before_the_fix();
    events.push(marker(2));
    assert_eq!(fresh.load(&run), Ok(log_of(events.clone())));
    // The fix cannot be appended to it: the log would no longer load.
    for event in [fix_written(), patch_checked()] {
        let before = std::fs::read(&path).expect("read");
        let refused = unavailable_detail(fresh.append(&run, &event));
        assert!(refused.contains("version 1"), "{refused}");
        assert_eq!(std::fs::read(&path).expect("read"), before);
    }
    assert_eq!(fresh.load(&run), Ok(log_of(events)));
}

/// A version 1 log that holds `FixWritten` is refused: under version 2 the
/// event after it replays differently.
#[test]
fn version_1_log_past_fix_written_is_refused() {
    let fresh = Fresh::new("v1-fix");
    let run = id("run-1");
    fresh.create(&run, &start()).expect("create");
    for event in before_the_fix() {
        fresh.append(&run, &event).expect("append");
    }
    fresh.append(&run, &fix_written()).expect("append");
    let path = log_path(fresh.store.root(), &run);
    make_version_1(&path);
    assert_fails_closed(&fresh, &run, &path, Some(5), "version 1 with FixWritten");
}

/// `PatchChecked`, which version 1 did not have, in a version 1 log is
/// refused; the same lines under the version 2 header load.
#[test]
fn version_1_patch_checked_is_refused() {
    let fresh = Fresh::new("v1-patch");
    let run = id("run-1");
    fresh.create(&run, &start()).expect("create");
    fresh.append(&run, &marker(1)).expect("append");
    fresh.append(&run, &patch_checked()).expect("append");
    assert_eq!(
        fresh.load(&run),
        Ok(log_of(vec![marker(1), patch_checked()]))
    );
    let path = log_path(fresh.store.root(), &run);
    make_version_1(&path);
    assert_fails_closed(&fresh, &run, &path, Some(3), "version 1 with PatchChecked");
}

/// The worst-case `PatchChecked` line of ADR-023 D7: a size violation and,
/// for each of `files` changes, the most violations one change can have
/// (`Forbidden`, `Gitlink`, `NotText`, `Link` with a payload, every
/// marker and the three other test families), each at its most values.
fn worst_case_check(files: usize) -> RunEvent {
    let mut violations = vec![PatchViolation::TooManyLines { limit: u32::MAX }];
    for index in 0..files {
        violations.push(PatchViolation::Forbidden {
            index,
            class: ForbiddenClass::Dependencies,
        });
        violations.push(PatchViolation::Gitlink { index });
        violations.push(PatchViolation::NotText {
            index,
            reason: NotText::BidiControl,
        });
        violations.push(PatchViolation::Link {
            index,
            problem: LinkProblem::Encloses(ForbiddenClass::RepositoryMetadata),
        });
        for marker in Marker::ALL {
            violations.push(PatchViolation::DisablesTests {
                index,
                reason: TestDisabling::Marker(marker),
            });
        }
        for reason in [
            TestDisabling::DeletedTestFile,
            TestDisabling::TestsRemoved,
            TestDisabling::TestConfigChanged,
        ] {
            violations.push(PatchViolation::DisablesTests { index, reason });
        }
    }
    RunEvent::PatchChecked {
        check: PatchCheck::Judged {
            limits: PatchLimits::DEFAULT,
            verdict: PatchVerdict::Reject(violations),
        },
        usage: Usage {
            cost_micro_usd: u64::MAX,
            duration_ms: u64::MAX,
        },
    }
}

/// The log-line bound of a verdict (ADR-023, D7): 17 values for the event
/// and the size violation, 134 per change, so 488 changes are 65,409
/// values and append, and 489 are 65,543, above `MAX_VALUES`, and are
/// refused before the file is touched. The worst case nests at
/// `MAX_DEPTH`.
#[test]
fn patch_verdict_line_bound() {
    assert_eq!((MAX_VALUES, MAX_DEPTH), (65_536, 6));
    assert_eq!(17 + 134 * 488, 65_409);
    assert_eq!(17 + 134 * 489, 65_543);
    let (fresh, run, path) = one_run("verdict-bound");
    let fits = worst_case_check(488);
    fresh.append(&run, &fits).expect("488 changes fit");
    let before = std::fs::read(&path).expect("read");
    let refused = unavailable_detail(fresh.append(&run, &worst_case_check(489)));
    assert!(refused.contains("TooManyValues"), "{refused}");
    assert_eq!(std::fs::read(&path).expect("read"), before);
    assert_eq!(fresh.load(&run), Ok(log_of(vec![marker(1), fits])));
}

/// Logs written before the store is dropped load the same after a reopen;
/// the reopened store appends to them.
#[test]
fn logs_survive_reopen() {
    let tmp = TempDir::new("logs-reopen");
    let root = tmp.path().join("store");
    let run = id("run-1");
    let reference = EvidenceRef::parse("sha256:00").expect("reference");
    let written = RunEvent::FixWritten {
        diff: reference,
        usage: Usage {
            cost_micro_usd: 7,
            duration_ms: 8,
        },
    };
    {
        let store = FsStore::open(&root).expect("open");
        store.create(&run, &start()).expect("create");
        store.append(&run, &written).expect("append");
    }
    let store = FsStore::open(&root).expect("reopen");
    assert_eq!(store.load(&run), Ok(log_of(vec![written.clone()])));
    store.append(&run, &marker(1)).expect("append");
    assert_eq!(store.load(&run), Ok(log_of(vec![written, marker(1)])));
    assert_eq!(store.load(&id("run-2")), Err(StoreError::UnknownRun));
}

/// The latency of a durable append (D4): median and maximum of 1,000
/// appends of a small event, each with its `fdatasync`. A measurement for
/// ADR-012, run by hand in release:
/// `cargo test --release -p boneli-store-fs --test boneli_store_fs_tests -- --ignored --nocapture append_latency`.
#[test]
#[ignore = "measurement"]
fn append_latency() {
    let fresh = Fresh::new("latency");
    let run = id("run-1");
    fresh.create(&run, &start()).expect("create");
    let mut samples = Vec::with_capacity(1_000);
    for k in 0..1_000 {
        let at = Instant::now();
        fresh.append(&run, &marker(k)).expect("append");
        samples.push(at.elapsed());
    }
    samples.sort();
    println!(
        "append latency over 1000 appends: median {:?}, max {:?}",
        samples[500], samples[999]
    );
}
