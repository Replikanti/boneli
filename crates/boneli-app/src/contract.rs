//! Contract suites: what every adapter of a port must do (ADR-004, D2).
//!
//! One module per port. Each exports `CLAUSES`, the names of its clauses in
//! the order they are checked, and `run`, a generic function over the port
//! that checks them and returns the first violated clause. A suite never
//! panics on an adapter bug: it returns a [`Violation`]. The in-memory
//! adapters in `boneli-memory` and every real adapter run the same suites
//! from their own tests, and `boneli-memory` also proves each clause can
//! fail, with one mutant adapter per clause.
//!
//! Suites that need a fresh adapter per clause take a constructor; suites
//! for job ports also take adapter-supplied fixtures, because only the
//! adapter's own test knows how to make a real process or forge fail.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use boneli_domain::values::is_blank;
use boneli_domain::{
    Budget, CheckStatus, Citation, CitationStatus, CommitSha, DomainError, EvidenceRef, FixChecks,
    RunId, TestStatus, Ticket, TicketSource,
};

use crate::job::JobFailure;

/// A clause an adapter broke.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The port, for example `EventStore`.
    pub port: &'static str,
    /// The clause, one of the suite's `CLAUSES`.
    pub clause: &'static str,
    /// What the adapter did instead.
    pub detail: String,
}

/// An adapter set up so that every operation the suite calls fails with no
/// error output, and the status text that the failure detail must then
/// contain (for example `exit status 3`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SilentFailure<P> {
    /// The adapter.
    pub adapter: P,
    /// The status it fails with.
    pub status: String,
}

fn violation(port: &'static str, clause: &'static str, detail: String) -> Violation {
    Violation {
        port,
        clause,
        detail,
    }
}

/// `Ok` when `ok`, otherwise the clause with the detail.
fn ensure(
    ok: bool,
    port: &'static str,
    clause: &'static str,
    detail: impl FnOnce() -> String,
) -> Result<(), Violation> {
    if ok {
        Ok(())
    } else {
        Err(violation(port, clause, detail()))
    }
}

/// The value of a constructor over a fixed literal; a failure would be a bug
/// in the suite, reported against the clause instead of a panic.
fn fixed<T>(
    port: &'static str,
    clause: &'static str,
    value: Result<T, DomainError>,
) -> Result<T, Violation> {
    value.map_err(|error| violation(port, clause, format!("suite fixture rejected: {error}")))
}

/// `silent-failure-detail` for one operation: it failed, and its detail is
/// not blank and contains the status. A blank fixture status is itself a
/// violation: every detail contains the empty string, so the clause would
/// check nothing. Every violation detail starts with the operation's name.
fn silent_detail<T: core::fmt::Debug>(
    port: &'static str,
    operation: &str,
    result: Result<T, JobFailure>,
    status: &str,
) -> Result<(), Violation> {
    let clause = "silent-failure-detail";
    if is_blank(status) {
        return Err(violation(
            port,
            clause,
            format!(
                "{operation}: the fixture's status {status:?} is blank, so the clause cannot \
                 check that the detail names it"
            ),
        ));
    }
    match result {
        Ok(value) => Err(violation(
            port,
            clause,
            format!("{operation}: succeeded with {value:?} instead of failing"),
        )),
        Err(failure) => ensure(
            !is_blank(failure.detail()) && failure.detail().contains(status),
            port,
            clause,
            || {
                format!(
                    "{operation}: failed with detail {:?}, which does not name the status {status:?}",
                    failure.detail()
                )
            },
        ),
    }
}

const BASE: &str = "0123456789abcdef0123456789abcdef01234567";

fn sample_base(port: &'static str, clause: &'static str) -> Result<CommitSha, Violation> {
    fixed(port, clause, CommitSha::parse(BASE))
}

/// The ticket the suites use where the adapter does not supply one: a
/// GitHub ticket with key `CONTRACT-1`. The `Forge` suite takes its ticket
/// from the adapter's test instead, because only the adapter knows which
/// keys its forge can post on; an in-memory forge passes this one.
pub fn sample_ticket() -> Ticket {
    Ticket {
        source: TicketSource::GitHub,
        key: String::from("CONTRACT-1"),
        title: String::from("Contract suite ticket"),
        body: String::new(),
    }
}

fn sample_citations(base: &CommitSha) -> Vec<Citation> {
    ["src/a.rs", "src/b.rs", "src/c.rs"]
        .into_iter()
        .enumerate()
        .map(|(k, path)| Citation {
            path: String::from(path),
            line: u32::try_from(k).unwrap_or(0) + 1,
            sha: base.clone(),
            quote: String::from("let x = 1;"),
        })
        .collect()
}

fn sample_checks() -> FixChecks {
    FixChecks {
        reproduction_test: TestStatus::Passed,
        reproduction_test_unchanged: CheckStatus::Passed,
        previously_green_tests: CheckStatus::Passed,
        lint: CheckStatus::NotConfigured,
        typecheck: CheckStatus::Passed,
    }
}

/// The hostile names of `hostile-run-ids` and `hostile-references`:
/// traversal, separators, dot names, empty, NUL, backslash, absolute, and
/// 300 bytes (Linux `NAME_MAX` is 255, so a file store must hash or reject
/// it).
fn hostile_names() -> Vec<String> {
    let mut names: Vec<String> = ["../x", "a/b", ".", "..", "", "\u{0}", "a\\b", "/abs"]
        .into_iter()
        .map(String::from)
        .collect();
    names.push("a".repeat(300));
    names
}

/// The `EventStore` suite.
pub mod event_store {
    use super::*;
    use crate::store::{EventStore, RunLog, RunStart, StoreError};
    use boneli_domain::{
        ChangeProblem, CitationProblem, ForbiddenClass, LinkProblem, Marker, NotText, PatchCheck,
        PatchLimits, PatchVerdict, PatchViolation, RunEvent, TestDisabling, TriageVerdict,
        UnreadablePath, Usage,
    };
    use core::num::NonZeroU32;

    const PORT: &str = "EventStore";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &[
        "create-then-load",
        "append-order",
        "duplicates-kept",
        "runs-isolated",
        "unknown-run",
        "create-twice",
        "round-trip",
        "hostile-run-ids",
    ];

    /// Checks every clause; each clause gets a fresh store from `make`.
    pub fn run<S: EventStore>(make: impl Fn() -> S) -> Result<(), Violation> {
        create_then_load(&make())?;
        append_order(&make())?;
        duplicates_kept(&make())?;
        runs_isolated(&make())?;
        unknown_run(&make())?;
        create_twice(&make())?;
        round_trip(&make())?;
        hostile_run_ids(&make())
    }

    fn id(text: &str) -> RunId {
        RunId::new(String::from(text))
    }

    fn start(previous: Option<RunId>) -> RunStart {
        RunStart {
            budget: Budget {
                cost_micro_usd: 1_000_000,
                duration_ms: 600_000,
            },
            previous,
        }
    }

    fn marker(n: usize) -> RunEvent {
        RunEvent::QuestionsPosted {
            reference: format!("event-{n}"),
        }
    }

    fn log(start: RunStart, events: Vec<RunEvent>) -> RunLog {
        RunLog { start, events }
    }

    /// `Ok(())` or the clause, for a store call.
    fn call(
        clause: &'static str,
        what: &str,
        result: Result<(), StoreError>,
    ) -> Result<(), Violation> {
        result.map_err(|error| violation(PORT, clause, format!("{what} failed: {error:?}")))
    }

    /// The log must load and equal `want`.
    fn expect_log(
        store: &dyn EventStore,
        clause: &'static str,
        run: &RunId,
        want: &RunLog,
    ) -> Result<(), Violation> {
        match store.load(run) {
            Ok(got) => ensure(&got == want, PORT, clause, || {
                format!("{run:?} loaded as {got:?}, expected {want:?}")
            }),
            Err(error) => Err(violation(
                PORT,
                clause,
                format!("loading {run:?} failed: {error:?}"),
            )),
        }
    }

    fn create_then_load(store: &dyn EventStore) -> Result<(), Violation> {
        let clause = "create-then-load";
        let a = id("contract-a");
        call(clause, "create", store.create(&a, &start(None)))?;
        expect_log(store, clause, &a, &log(start(None), vec![]))
    }

    fn append_order(store: &dyn EventStore) -> Result<(), Violation> {
        let clause = "append-order";
        let a = id("contract-a");
        call(clause, "create", store.create(&a, &start(None)))?;
        for n in 1..=3 {
            call(clause, "append", store.append(&a, &marker(n)))?;
        }
        let want = log(start(None), vec![marker(1), marker(2), marker(3)]);
        expect_log(store, clause, &a, &want)
    }

    fn duplicates_kept(store: &dyn EventStore) -> Result<(), Violation> {
        let clause = "duplicates-kept";
        let a = id("contract-a");
        call(clause, "create", store.create(&a, &start(None)))?;
        call(clause, "append", store.append(&a, &marker(1)))?;
        call(clause, "append", store.append(&a, &marker(1)))?;
        expect_log(
            store,
            clause,
            &a,
            &log(start(None), vec![marker(1), marker(1)]),
        )
    }

    fn runs_isolated(store: &dyn EventStore) -> Result<(), Violation> {
        let clause = "runs-isolated";
        let (a, b) = (id("contract-a"), id("contract-b"));
        call(clause, "create", store.create(&a, &start(None)))?;
        call(clause, "create", store.create(&b, &start(Some(a.clone()))))?;
        call(clause, "append", store.append(&a, &marker(1)))?;
        call(clause, "append", store.append(&b, &marker(2)))?;
        call(clause, "append", store.append(&a, &marker(3)))?;
        expect_log(
            store,
            clause,
            &a,
            &log(start(None), vec![marker(1), marker(3)]),
        )?;
        expect_log(store, clause, &b, &log(start(Some(a)), vec![marker(2)]))
    }

    fn unknown_run(store: &dyn EventStore) -> Result<(), Violation> {
        let clause = "unknown-run";
        let (a, b) = (id("contract-a"), id("contract-b"));
        call(clause, "create", store.create(&a, &start(None)))?;
        let expect_unknown = |what: &str, result: Result<(), StoreError>| {
            ensure(result == Err(StoreError::UnknownRun), PORT, clause, || {
                format!("{what} of a run never created gave {result:?}, expected UnknownRun")
            })
        };
        expect_unknown("load", store.load(&b).map(|_| ()))?;
        expect_unknown("append", store.append(&b, &marker(1)))?;
        expect_unknown("load after append", store.load(&b).map(|_| ()))?;
        expect_log(store, clause, &a, &log(start(None), vec![]))
    }

    fn create_twice(store: &dyn EventStore) -> Result<(), Violation> {
        let clause = "create-twice";
        let a = id("contract-a");
        call(clause, "create", store.create(&a, &start(None)))?;
        call(clause, "append", store.append(&a, &marker(1)))?;
        let again = store.create(&a, &start(Some(id("contract-other"))));
        ensure(
            again == Err(StoreError::AlreadyExists),
            PORT,
            clause,
            || format!("a second create gave {again:?}, expected AlreadyExists"),
        )?;
        expect_log(store, clause, &a, &log(start(None), vec![marker(1)]))
    }

    /// Texts a serializing store tends to break: NUL, a BOM in front of
    /// text, quotes, backslash, newline and a character outside the BMP.
    const TEXTS: [&str; 6] = [
        "\u{0}",
        "\u{FEFF}x",
        "\"quoted\"",
        "back\\slash",
        "new\nline",
        "\u{1F600}",
    ];

    /// One violation of every family of the patch policy, each with a
    /// payload a store must carry: the extremes of every number and a
    /// nested enum value (ADR-023, D7).
    fn every_violation() -> Vec<PatchViolation> {
        vec![
            PatchViolation::TooManyFiles {
                files: usize::MAX,
                limit: u32::MAX,
            },
            PatchViolation::Empty,
            PatchViolation::Malformed {
                index: 0,
                problem: ChangeProblem::Path(CitationProblem::ParentComponent),
            },
            PatchViolation::BaseLinkMalformed {
                index: 1,
                problem: ChangeProblem::BaseLinkMismatch,
            },
            PatchViolation::TooManyLines { limit: 1 },
            PatchViolation::TooManyBytes { limit: 42_000 },
            PatchViolation::Forbidden {
                index: 2,
                class: ForbiddenClass::GitConfig,
            },
            PatchViolation::Gitlink { index: 3 },
            PatchViolation::NotText {
                index: 4,
                reason: NotText::BidiControl,
            },
            PatchViolation::Link {
                index: 5,
                problem: LinkProblem::Encloses(ForbiddenClass::RepositoryMetadata),
            },
            PatchViolation::DisablesTests {
                index: usize::MAX,
                reason: TestDisabling::Marker(Marker::Fcontext),
            },
        ]
    }

    /// One event of every kind, with the texts above, an empty `Vec`, zero
    /// and `u64::MAX` usage, and every shape of a patch check.
    pub(crate) fn every_event(base: &CommitSha) -> Result<Vec<RunEvent>, Violation> {
        let clause = "round-trip";
        let max = Usage {
            cost_micro_usd: u64::MAX,
            duration_ms: u64::MAX,
        };
        let zero = Usage::default();
        let reference = |text: &str| fixed(PORT, clause, EvidenceRef::parse(text));
        let texts: Vec<String> = TEXTS.into_iter().map(String::from).collect();
        let citation = Citation {
            path: String::from("a\u{0}b/\u{1F600}"),
            line: u32::MAX,
            sha: base.clone(),
            quote: TEXTS.into_iter().collect(),
        };
        Ok(vec![
            RunEvent::TicketReceived {
                ticket: Ticket {
                    source: TicketSource::Sentry,
                    key: String::from(TEXTS[1]),
                    title: format!("{}{}", TEXTS[2], TEXTS[3]),
                    body: format!("{}{}{}", TEXTS[0], TEXTS[4], TEXTS[5]),
                },
                base: base.clone(),
            },
            RunEvent::TriageFinished {
                verdict: TriageVerdict::NeedsInformation { questions: texts },
                usage: max,
            },
            RunEvent::TriageFinished {
                verdict: TriageVerdict::NeedsInformation { questions: vec![] },
                usage: zero,
            },
            RunEvent::TriageFinished {
                verdict: TriageVerdict::Ready,
                usage: zero,
            },
            RunEvent::QuestionsPosted {
                reference: String::from(TEXTS[5]),
            },
            RunEvent::ReproductionWritten {
                test: reference(TEXTS[1])?,
                usage: max,
            },
            RunEvent::ReproductionChecked {
                status: TestStatus::TimedOut,
                usage: zero,
            },
            RunEvent::RootCauseProposed {
                analysis: reference(TEXTS[0])?,
                citations: vec![citation],
                usage: max,
            },
            RunEvent::RootCauseProposed {
                analysis: reference(TEXTS[4])?,
                citations: vec![],
                usage: zero,
            },
            RunEvent::CitationsChecked {
                results: vec![
                    CitationStatus::Verified,
                    CitationStatus::Mismatch,
                    CitationStatus::Unverifiable,
                ],
                usage: zero,
            },
            RunEvent::CitationsChecked {
                results: vec![],
                usage: max,
            },
            RunEvent::FixWritten {
                diff: reference(TEXTS[3])?,
                usage: zero,
            },
            RunEvent::PatchChecked {
                check: PatchCheck::Judged {
                    limits: PatchLimits {
                        max_changed_files: NonZeroU32::MIN,
                        max_changed_lines: NonZeroU32::MAX,
                        max_changed_bytes: NonZeroU32::MIN.saturating_add(41_999),
                    },
                    verdict: PatchVerdict::Reject(every_violation()),
                },
                usage: max,
            },
            RunEvent::PatchChecked {
                check: PatchCheck::Judged {
                    limits: PatchLimits::DEFAULT,
                    verdict: PatchVerdict::Reject(vec![]),
                },
                usage: zero,
            },
            RunEvent::PatchChecked {
                check: PatchCheck::Judged {
                    limits: PatchLimits::DEFAULT,
                    verdict: PatchVerdict::Pass {
                        files: u32::MAX,
                        lines: 0,
                    },
                },
                usage: zero,
            },
            RunEvent::PatchChecked {
                check: PatchCheck::Unreadable(UnreadablePath::BaseLink { index: usize::MAX }),
                usage: max,
            },
            RunEvent::PatchChecked {
                check: PatchCheck::Unreadable(UnreadablePath::Change { index: 0 }),
                usage: zero,
            },
            RunEvent::FixVerified {
                checks: FixChecks {
                    reproduction_test: TestStatus::FailedToBuild,
                    reproduction_test_unchanged: CheckStatus::Unknown,
                    previously_green_tests: CheckStatus::Failed,
                    lint: CheckStatus::NotConfigured,
                    typecheck: CheckStatus::Passed,
                },
                usage: max,
            },
            RunEvent::PullRequestOpened {
                reference: String::from(TEXTS[4]),
            },
            RunEvent::JobFailed {
                detail: format!("{}{}", TEXTS[2], TEXTS[3]),
                usage: max,
            },
        ])
    }

    fn round_trip(store: &dyn EventStore) -> Result<(), Violation> {
        let clause = "round-trip";
        let base = sample_base(PORT, clause)?;
        let events = every_event(&base)?;
        let (a, b) = (id("contract-a"), id("contract-b"));
        let unlimited = RunStart {
            budget: Budget {
                cost_micro_usd: u64::MAX,
                duration_ms: u64::MAX,
            },
            previous: Some(id("run-\u{0}\u{FEFF}x\"\\\n\u{1F600}")),
        };
        call(clause, "create", store.create(&a, &unlimited))?;
        call(clause, "create", store.create(&b, &start(None)))?;
        for event in &events {
            call(clause, "append", store.append(&a, event))?;
        }
        expect_log(store, clause, &a, &log(unlimited, events))?;
        expect_log(store, clause, &b, &log(start(None), vec![]))
    }

    /// Victims named after the last components of the hostile names, so a
    /// store that resolves `../x` to `x` overwrites or returns them.
    const VICTIMS: [&str; 4] = ["x", "a", "b", "abs"];

    fn hostile_run_ids(store: &dyn EventStore) -> Result<(), Violation> {
        let clause = "hostile-run-ids";
        let mut want: Vec<(RunId, RunLog)> = Vec::new();
        for (k, victim) in VICTIMS.into_iter().enumerate() {
            let run = id(victim);
            call(clause, "create", store.create(&run, &start(None)))?;
            call(clause, "append", store.append(&run, &marker(k)))?;
            want.push((run, log(start(None), vec![marker(k)])));
        }
        let mut rejected = Vec::new();
        for (k, name) in hostile_names().into_iter().enumerate() {
            let run = id(&name);
            let own = start(Some(id(&format!("hostile-{k}"))));
            match store.create(&run, &own) {
                Ok(()) => {
                    call(clause, "append", store.append(&run, &marker(100 + k)))?;
                    want.push((run, log(own, vec![marker(100 + k)])));
                }
                Err(StoreError::InvalidRunId) => rejected.push(run),
                Err(error) => {
                    return Err(violation(
                        PORT,
                        clause,
                        format!("create {run:?} gave {error:?}, expected Ok or InvalidRunId"),
                    ));
                }
            }
        }
        // Checked after every write, so a later name that lands on an
        // earlier one is caught.
        for (run, log) in &want {
            expect_log(store, clause, run, log)?;
        }
        for run in rejected {
            let loaded = store.load(&run);
            let appended = store.append(&run, &marker(0));
            let refused =
                |e: &StoreError| matches!(e, StoreError::InvalidRunId | StoreError::UnknownRun);
            ensure(
                loaded.as_ref().is_err_and(refused) && appended.as_ref().is_err_and(refused),
                PORT,
                clause,
                || format!("rejected {run:?}, then load gave {loaded:?} and append {appended:?}"),
            )?;
        }
        Ok(())
    }
}

/// The `Evidence` suite.
pub mod evidence {
    use super::*;
    use crate::evidence::{Evidence, EvidenceError};

    const PORT: &str = "Evidence";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &[
        "round-trip",
        "content-addressed",
        "distinct-content",
        "reference-from-content",
        "unknown-reference",
        "hostile-references",
        "tampered-content-rejected",
    ];

    /// 1 MiB: above the 8 KiB `BufReader` default and the 64 KiB Linux pipe
    /// buffer, so a store that truncates at a buffer boundary fails.
    pub const LARGE_BLOB: usize = 1 << 20;

    /// Checks every clause; each clause gets a fresh store from `make`.
    ///
    /// `tamper` overwrites what the store holds under a reference behind
    /// its back, the way another process with write access to a file store's
    /// directory could (ADR-004, D9). Only the adapter's own test knows how.
    pub fn run<E: Evidence>(
        make: impl Fn() -> E,
        tamper: impl Fn(&E, &EvidenceRef, &[u8]),
    ) -> Result<(), Violation> {
        round_trip(&make())?;
        content_addressed(&make())?;
        distinct_content(&make())?;
        reference_from_content(&make(), &make())?;
        unknown_reference(&make(), &make())?;
        hostile_references(&make())?;
        tampered_content_rejected(&make(), tamper)
    }

    /// `get` re-derives the reference from the bytes it read, so content
    /// changed behind the store's back is `Corrupted`, never returned. This
    /// is what makes the pull request carry the bytes the verifier checked
    /// (D9). The replacement has the same length, so a length check is not
    /// enough. The hook must write only the stored blob, nothing the store
    /// keeps beside it; the adapter's review checks that.
    fn tampered_content_rejected<E: Evidence>(
        store: &E,
        tamper: impl Fn(&E, &EvidenceRef, &[u8]),
    ) -> Result<(), Violation> {
        let clause = "tampered-content-rejected";
        let reference = put(store, clause, b"original")?;
        tamper(store, &reference, b"tampered");
        let got = store.get(&reference);
        ensure(got == Err(EvidenceError::Corrupted), PORT, clause, || {
            format!("get {reference:?} after its content changed gave {got:?}, expected Corrupted")
        })
    }

    fn put(
        store: &dyn Evidence,
        clause: &'static str,
        content: &[u8],
    ) -> Result<EvidenceRef, Violation> {
        store.put(content).map_err(|error| {
            violation(
                PORT,
                clause,
                format!("put of {} bytes failed: {error:?}", content.len()),
            )
        })
    }

    fn expect_content(
        store: &dyn Evidence,
        clause: &'static str,
        reference: &EvidenceRef,
        want: &[u8],
    ) -> Result<(), Violation> {
        match store.get(reference) {
            Ok(got) => ensure(got == want, PORT, clause, || {
                format!(
                    "{reference:?} returned {} bytes that differ from the {} put",
                    got.len(),
                    want.len()
                )
            }),
            Err(error) => Err(violation(
                PORT,
                clause,
                format!("get {reference:?} failed: {error:?}"),
            )),
        }
    }

    /// The empty blob; every byte value once, which catches stores that
    /// validate UTF-8, translate newlines or stop at NUL; and
    /// [`LARGE_BLOB`] bytes.
    fn blobs() -> Vec<Vec<u8>> {
        let every_byte: Vec<u8> = (0..=u8::MAX).collect();
        // 251 is prime, so the pattern does not repeat at any power-of-two
        // buffer boundary.
        let large: Vec<u8> = (0..LARGE_BLOB)
            .map(|k| u8::try_from(k % 251).unwrap_or(0))
            .collect();
        vec![Vec::new(), every_byte, large]
    }

    fn round_trip(store: &dyn Evidence) -> Result<(), Violation> {
        let clause = "round-trip";
        let blobs = blobs();
        let mut stored = Vec::new();
        for blob in &blobs {
            stored.push(put(store, clause, blob)?);
        }
        // All read back after all puts: a later put must not clobber.
        for (reference, blob) in stored.iter().zip(&blobs) {
            expect_content(store, clause, reference, blob)?;
        }
        Ok(())
    }

    fn content_addressed(store: &dyn Evidence) -> Result<(), Violation> {
        let clause = "content-addressed";
        let content = b"the same bytes";
        let first = put(store, clause, content)?;
        let second = put(store, clause, content)?;
        ensure(first == second, PORT, clause, || {
            format!("the same bytes got {first:?} and then {second:?}")
        })?;
        expect_content(store, clause, &first, content)
    }

    fn distinct_content(store: &dyn Evidence) -> Result<(), Violation> {
        let clause = "distinct-content";
        let pairs: [(&[u8], &[u8]); 3] = [(b"a", b"b"), (b"ab", b"abc"), (b"", b"\0")];
        for (left, right) in pairs {
            let l = put(store, clause, left)?;
            let r = put(store, clause, right)?;
            ensure(l != r, PORT, clause, || {
                format!("{left:?} and {right:?} got the same reference {l:?}")
            })?;
            expect_content(store, clause, &l, left)?;
            expect_content(store, clause, &r, right)?;
        }
        Ok(())
    }

    /// A reference is a function of the bytes alone (ADR-004, D9): two
    /// fresh stores that get the same blobs in opposite orders issue the
    /// same reference for each. A counter, a timestamp or any other state
    /// in the reference fails, so `get` can re-derive the reference from
    /// the bytes it read, and no side record that a writer could rewrite
    /// together with the blob decides what is genuine.
    fn reference_from_content(left: &dyn Evidence, right: &dyn Evidence) -> Result<(), Violation> {
        let clause = "reference-from-content";
        let blobs: [&[u8]; 3] = [b"first", b"second", b""];
        let mut forward = Vec::new();
        for blob in blobs {
            forward.push(put(left, clause, blob)?);
        }
        let mut backward = Vec::new();
        for blob in blobs.iter().rev() {
            backward.push(put(right, clause, blob)?);
        }
        backward.reverse();
        for ((blob, l), r) in blobs.iter().zip(&forward).zip(&backward) {
            ensure(l == r, PORT, clause, || {
                format!("{blob:?} got {l:?} in one store and {r:?} in another")
            })?;
        }
        Ok(())
    }

    /// A reference another store issued is well formed but unknown here.
    fn unknown_reference(issuer: &dyn Evidence, empty: &dyn Evidence) -> Result<(), Violation> {
        let clause = "unknown-reference";
        let reference = put(issuer, clause, b"issued elsewhere")?;
        let got = empty.get(&reference);
        ensure(got == Err(EvidenceError::NotFound), PORT, clause, || {
            format!(
                "get {reference:?} from a store that never issued it gave {got:?}, expected NotFound"
            )
        })
    }

    fn hostile_references(store: &dyn Evidence) -> Result<(), Violation> {
        let clause = "hostile-references";
        let victim = put(store, clause, b"victim")?;
        let v = victim.as_str();
        let mut names = hostile_names();
        // The same forms around a reference the store did issue.
        for derived in [
            format!("../{v}"),
            format!("./{v}"),
            format!("/{v}"),
            format!("a/../{v}"),
            format!("{v}/."),
            format!("{v}/"),
            format!("{v}\u{0}"),
        ] {
            names.push(derived);
        }
        for name in names {
            // A blank reference cannot be represented, so the port never
            // sees one.
            let Ok(reference) = EvidenceRef::parse(&name) else {
                continue;
            };
            let got = store.get(&reference);
            ensure(
                matches!(
                    got,
                    Err(EvidenceError::NotFound | EvidenceError::InvalidReference)
                ),
                PORT,
                clause,
                || format!("get {name:?} gave {got:?}, expected NotFound or InvalidReference"),
            )?;
        }
        expect_content(store, clause, &victim, b"victim")
    }
}

/// The `Clock` suite.
pub mod clock {
    use super::*;
    use crate::clock::Clock;

    const PORT: &str = "Clock";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &["non-decreasing"];

    /// Consecutive readings: enough to exercise any per-call state in a
    /// double, and well under 1 ms. No test can prove a real clock
    /// monotonic; its adapter is built on a monotonic source.
    pub const READINGS: usize = 1_000;

    /// Checks every clause.
    pub fn run<C: Clock>(clock: &C) -> Result<(), Violation> {
        let mut last = clock.now_ms();
        for k in 1..READINGS {
            let now = clock.now_ms();
            ensure(now >= last, PORT, "non-decreasing", || {
                format!("reading {k} is {now} ms, after {last} ms")
            })?;
            last = now;
        }
        Ok(())
    }
}

/// The `Ids` suite.
pub mod ids {
    use super::*;
    use crate::ids::Ids;

    const PORT: &str = "Ids";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &["not-blank", "distinct"];

    /// 2^16 + 1: by pigeonhole no 8- or 16-bit counter can issue that many
    /// distinct values.
    pub const COUNT: usize = (1 << 16) + 1;

    /// Checks every clause over [`COUNT`] ids.
    pub fn run<I: Ids>(ids: &I) -> Result<(), Violation> {
        let issued: Vec<RunId> = (0..COUNT).map(|_| ids.run_id()).collect();
        for (k, id) in issued.iter().enumerate() {
            ensure(!is_blank(id.as_str()), PORT, "not-blank", || {
                format!("id {k} is blank: {id:?}")
            })?;
        }
        let mut seen = BTreeSet::new();
        for (k, id) in issued.iter().enumerate() {
            ensure(seen.insert(id.as_str()), PORT, "distinct", || {
                format!("id {k} repeats an earlier one: {id:?}")
            })?;
        }
        Ok(())
    }
}

/// The `Agent` suite.
pub mod agent {
    use super::*;
    use crate::agent::{Agent, FixRequest, ReproductionRequest, RootCauseRequest, TriageRequest};

    const PORT: &str = "Agent";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &["silent-failure-detail"];

    /// The operations `silent-failure-detail` checks, in order; a violation
    /// detail starts with one of them.
    pub const OPERATIONS: &[&str] = &[
        "triage",
        "write_reproduction",
        "analyze_root_cause",
        "write_fix",
    ];

    /// Checks every clause. `silent` gives a fresh adapter for each of the
    /// four operations.
    pub fn run<A: Agent>(silent: impl Fn() -> SilentFailure<A>) -> Result<(), Violation> {
        let base = sample_base(PORT, "silent-failure-detail")?;
        let ticket = sample_ticket();
        let fixture = silent();
        let request = TriageRequest {
            ticket: ticket.clone(),
            base: base.clone(),
            previous: None,
        };
        silent_detail(
            PORT,
            "triage",
            fixture.adapter.triage(&request),
            &fixture.status,
        )?;
        let fixture = silent();
        let request = ReproductionRequest {
            ticket: ticket.clone(),
            base: base.clone(),
        };
        let result = fixture.adapter.write_reproduction(&request);
        silent_detail(PORT, "write_reproduction", result, &fixture.status)?;
        let fixture = silent();
        let request = RootCauseRequest {
            ticket: ticket.clone(),
            base: base.clone(),
            test: b"test".to_vec(),
        };
        let result = fixture.adapter.analyze_root_cause(&request);
        silent_detail(PORT, "analyze_root_cause", result, &fixture.status)?;
        let fixture = silent();
        let request = FixRequest {
            ticket,
            base,
            test: b"test".to_vec(),
            analysis: b"analysis".to_vec(),
        };
        silent_detail(
            PORT,
            "write_fix",
            fixture.adapter.write_fix(&request),
            &fixture.status,
        )
    }
}

/// The `Verifier` suite.
pub mod verifier {
    use super::*;
    use crate::verifier::Verifier;

    const PORT: &str = "Verifier";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &["one-status-per-citation", "silent-failure-detail"];

    /// The operations `silent-failure-detail` checks, in order; a violation
    /// detail starts with one of them.
    pub const OPERATIONS: &[&str] = &["check_reproduction", "verify_citations", "verify_fix"];

    /// A verifier set up to answer `verify_citations` for these citations
    /// at this base.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Answering<V> {
        /// The adapter.
        pub adapter: V,
        /// The base commit.
        pub base: CommitSha,
        /// The citations it is asked about.
        pub citations: Vec<Citation>,
    }

    /// The citations the suite's sample uses, for fixtures that need them.
    pub fn sample(base: &CommitSha) -> Vec<Citation> {
        sample_citations(base)
    }

    /// Checks every clause. Over a scripted double,
    /// `one-status-per-citation` holds by construction; it bites on real
    /// adapters (ADR-004).
    pub fn run<V: Verifier>(
        answering: impl Fn() -> Answering<V>,
        silent: impl Fn() -> SilentFailure<V>,
    ) -> Result<(), Violation> {
        let clause = "one-status-per-citation";
        let fixture = answering();
        match fixture
            .adapter
            .verify_citations(&fixture.base, &fixture.citations)
        {
            Ok(statuses) => ensure(
                statuses.len() == fixture.citations.len(),
                PORT,
                clause,
                || {
                    format!(
                        "{} citations got {} statuses",
                        fixture.citations.len(),
                        statuses.len()
                    )
                },
            )?,
            Err(failure) => {
                return Err(violation(
                    PORT,
                    clause,
                    format!("verify_citations failed: {:?}", failure.detail()),
                ));
            }
        }

        let base = sample_base(PORT, "silent-failure-detail")?;
        let fixture = silent();
        let result = fixture.adapter.check_reproduction(&base, b"test");
        silent_detail(PORT, "check_reproduction", result, &fixture.status)?;
        let fixture = silent();
        let result = fixture
            .adapter
            .verify_citations(&base, &sample_citations(&base));
        silent_detail(PORT, "verify_citations", result, &fixture.status)?;
        let fixture = silent();
        let result = fixture.adapter.verify_fix(&base, b"diff", b"test");
        silent_detail(PORT, "verify_fix", result, &fixture.status)
    }
}

/// The `Forge` suite.
pub mod forge {
    use super::*;
    use crate::forge::{Attached, Forge, PullRequest};
    use boneli_domain::Usage;

    const PORT: &str = "Forge";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &["distinct-references", "silent-failure-detail"];

    /// The operations `silent-failure-detail` checks, in order; a violation
    /// detail starts with one of them.
    pub const OPERATIONS: &[&str] = &["post_questions", "open_pull_request"];

    fn sample_request(clause: &'static str, ticket: &Ticket) -> Result<PullRequest, Violation> {
        let attached = |reference: &str, content: &[u8]| {
            fixed(PORT, clause, EvidenceRef::parse(reference)).map(|reference| Attached {
                reference,
                content: content.to_vec(),
            })
        };
        let base = sample_base(PORT, clause)?;
        Ok(PullRequest {
            run: RunId::new(String::from("contract-run")),
            ticket: ticket.clone(),
            citations: sample_citations(&base),
            base,
            diff: attached("contract-diff", b"diff")?,
            test: attached("contract-test", b"test")?,
            analysis: attached("contract-analysis", b"analysis")?,
            checks: sample_checks(),
            spent: Usage {
                cost_micro_usd: 1,
                duration_ms: 1,
            },
            overrun: None,
        })
    }

    /// Checks every clause. `working` gives an adapter on which every call
    /// succeeds; `silent` one on which every call fails with no error
    /// output. `ticket` is the ticket every call names: only the adapter's
    /// own test knows which ticket keys its forge can post on
    /// ([`sample_ticket`] for a forge that takes any). A ticket with a
    /// blank key or title is a fixture violation, because the domain never
    /// hands a forge such a ticket.
    pub fn run<F: Forge>(
        working: impl Fn() -> F,
        silent: impl Fn() -> SilentFailure<F>,
        ticket: &Ticket,
    ) -> Result<(), Violation> {
        let clause = "distinct-references";
        if let Some(field) = ticket.blank_field() {
            return Err(violation(
                PORT,
                clause,
                format!(
                    "fixture: the ticket's {field:?} is blank, and the domain never hands a \
                     forge such a ticket"
                ),
            ));
        }
        let forge = working();
        let questions = [String::from("Which version?")];
        let request = sample_request(clause, ticket)?;
        let mut references = Vec::new();
        for k in 0..4 {
            let result = if k % 2 == 0 {
                forge.post_questions(ticket, &questions)
            } else {
                forge.open_pull_request(&request)
            };
            match result {
                Ok(reference) => references.push(reference),
                Err(failure) => {
                    return Err(violation(
                        PORT,
                        clause,
                        format!("call {k} failed: {:?}", failure.detail()),
                    ));
                }
            }
        }
        let distinct: BTreeSet<&str> = references.iter().map(|r| r.as_str()).collect();
        ensure(distinct.len() == references.len(), PORT, clause, || {
            format!("references repeat: {references:?}")
        })?;

        let fixture = silent();
        let result = fixture.adapter.post_questions(ticket, &questions);
        silent_detail(PORT, "post_questions", result, &fixture.status)?;
        let fixture = silent();
        let request = sample_request("silent-failure-detail", ticket)?;
        let result = fixture.adapter.open_pull_request(&request);
        silent_detail(PORT, "open_pull_request", result, &fixture.status)
    }
}

/// The `Sandbox` suite.
pub mod sandbox {
    use super::*;
    use crate::path::{RelativePath, TreePath};
    use crate::sandbox::{
        Broker, Command, ContainerName, ContainerSpec, ExecResult, ExitStatus, LayerRef, Limits,
        Phase, Sandbox, SandboxError, SandboxId, SandboxSpec, WorkspaceBytes,
    };

    const PORT: &str = "Sandbox";

    /// The clauses, in the order [`run`] checks them. The first seven are
    /// ADR-004's (D11); `isolated`, `fresh-after-destroy` and
    /// `destroyed-is-unknown` are stronger since ADR-042 (D2), which adds
    /// the other seventeen.
    pub const CLAUSES: &[&str] = &[
        "distinct-ids",
        "copy-out-after-write",
        "copy-out-missing",
        "isolated",
        "fresh-after-destroy",
        "exit-status",
        "destroyed-is-unknown",
        "unknown-container",
        "limits-checked",
        "output-cap",
        "start-runs",
        "export-round-trip",
        "export-sees-write",
        "copy-out-no-symlink",
        "verify-without-brokers",
        "seal-prepare-only",
        "seal-no-symlink",
        "sealed-layer-mounted",
        "dependency-read-only",
        "export-without-mounts",
        "dependency-overlap-refused",
        "distinct-layers",
        "released-layer-unknown",
        "layer-in-use-kept",
    ];

    /// An adapter and the commands that drive it, which only the adapter's
    /// own test knows (for a real sandbox, programs in the image). Every
    /// command names the spec's first container, except where a field says
    /// otherwise.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Workspace<S> {
        /// The adapter.
        pub adapter: S,
        /// A sandbox the adapter can create: no dependency, no broker, and
        /// a workspace ([`SandboxSpec::workspace`]) with no file at or
        /// beneath [`Workspace::dependency`]. Its limits must also fit a pod
        /// with [`Workspace::container`] added. The suite sets the phase
        /// where a clause needs one.
        pub spec: SandboxSpec,
        /// The limits every command runs under.
        pub limits: Limits,
        /// A command that writes [`Workspace::content`] to
        /// [`Workspace::path`] in the workspace.
        pub write: Command,
        /// A path the workspace has no file at until `write` runs.
        pub path: RelativePath,
        /// What `write` writes; not empty, or an adapter that copies out an
        /// empty file for every path would pass.
        pub content: Vec<u8>,
        /// A command that ends with [`Workspace::status`], in the first
        /// container and, with its container changed, in
        /// [`Workspace::container`].
        pub exit: Command,
        /// How `exit` ends; not `Code(0)`, or an adapter that reports
        /// success for every command would pass.
        pub status: ExitStatus,
        /// A second container the adapter can add to the spec, with a name
        /// the spec does not use.
        pub container: ContainerSpec,
        /// A command that writes [`Workspace::outside`] to a file outside
        /// the workspace.
        pub plant: Command,
        /// What `plant` writes; not empty, so that an adapter that follows
        /// a link to it copies out something.
        pub outside: Vec<u8>,
        /// A command that makes [`Workspace::path`] a symlink to the file
        /// `plant` writes.
        pub link: Command,
        /// A command that makes a parent directory of [`Workspace::path`] a
        /// symlink to a directory outside the workspace, in which the rest
        /// of the path names the file `plant` writes.
        pub through: Command,
        /// A broker the adapter can bind.
        pub broker: Broker,
        /// A directory that [`Workspace::path`] lies beneath, sealed into a
        /// layer after `write`.
        pub dependency: RelativePath,
        /// A command that copies the file at [`Workspace::path`], which a
        /// mounted dependency provides, to [`Workspace::copied`].
        pub read: Command,
        /// Where `read` copies to: not beneath `dependency`, and no file
        /// there until `read` runs.
        pub copied: RelativePath,
        /// A command that writes [`Workspace::overwritten`] to
        /// [`Workspace::path`]: after a seal in the sandbox that was
        /// sealed, and beneath the mount in one that mounts the layer.
        pub overwrite: Command,
        /// What `overwrite` writes; not empty and not
        /// [`Workspace::content`], or a layer that took the write could not
        /// be told from one that did not.
        pub overwritten: Vec<u8>,
        /// A command that makes [`Workspace::path`] a symlink with a
        /// relative target to a file inside the workspace that it writes
        /// with [`Workspace::outside`], so that the container and the host
        /// resolve the link to the same bytes.
        pub relative: Command,
        /// A command whose standard output is [`Workspace::printed`].
        pub print: Command,
        /// What `print` prints; not empty.
        pub printed: Vec<u8>,
        /// A command whose error output is [`Workspace::printed`].
        pub print_err: Command,
        /// A service: it writes [`Workspace::content`] to
        /// [`Workspace::path`] and keeps running.
        pub service: Command,
        /// A command that exits once [`Workspace::path`] exists, within
        /// [`Workspace::limits`]: the suite runs it after starting
        /// `service`, so a service that writes late is not a failure.
        pub settle: Command,
    }

    /// Checks every clause; each clause gets a fresh adapter from `make`.
    ///
    /// `edit` takes a workspace in the adapter's snapshot format (the
    /// `Git` adapter's, which the sandbox shares), a path and content, and
    /// returns the workspace with that file set to that content, or
    /// removed for `None`; only the adapter's own test knows the format,
    /// as for the `Git` suite.
    pub fn run<S: Sandbox>(
        make: impl Fn() -> Workspace<S>,
        edit: impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        distinct_ids(&make())?;
        copy_out_after_write(&make())?;
        copy_out_missing(&make())?;
        isolated(&make())?;
        fresh_after_destroy(&make())?;
        exit_status(&make())?;
        destroyed_is_unknown(&make())?;
        unknown_container(&make())?;
        limits_checked(&make())?;
        output_cap(&make())?;
        start_runs(&make())?;
        export_round_trip(&make(), &edit)?;
        export_sees_write(&make(), &edit)?;
        copy_out_no_symlink(&make())?;
        verify_without_brokers(&make())?;
        seal_prepare_only(&make())?;
        seal_no_symlink(&make())?;
        sealed_layer_mounted(&make())?;
        dependency_read_only(&make())?;
        export_without_mounts(&make())?;
        dependency_overlap_refused(&make())?;
        distinct_layers(&make())?;
        released_layer_unknown(&make())?;
        layer_in_use_kept(&make())
    }

    fn create<S: Sandbox>(w: &Workspace<S>, clause: &'static str) -> Result<SandboxId, Violation> {
        create_from(w, clause, &w.spec)
    }

    fn create_from<S: Sandbox>(
        w: &Workspace<S>,
        clause: &'static str,
        spec: &SandboxSpec,
    ) -> Result<SandboxId, Violation> {
        w.adapter
            .create(spec)
            .map_err(|error| violation(PORT, clause, format!("create failed: {error:?}")))
    }

    /// The fixture's spec in another phase.
    fn in_phase<S>(w: &Workspace<S>, phase: Phase) -> SandboxSpec {
        SandboxSpec {
            phase,
            ..w.spec.clone()
        }
    }

    fn exec<S: Sandbox>(
        w: &Workspace<S>,
        clause: &'static str,
        id: &SandboxId,
        command: &Command,
    ) -> Result<ExecResult, Violation> {
        w.adapter.exec(id, command, &w.limits).map_err(|error| {
            violation(
                PORT,
                clause,
                format!("exec of {:?} in {id:?} failed: {error:?}", command.program),
            )
        })
    }

    fn destroy<S: Sandbox>(
        w: &Workspace<S>,
        clause: &'static str,
        id: &SandboxId,
    ) -> Result<(), Violation> {
        w.adapter
            .destroy(id)
            .map_err(|error| violation(PORT, clause, format!("destroy failed: {error:?}")))
    }

    fn export<S: Sandbox>(
        w: &Workspace<S>,
        clause: &'static str,
        id: &SandboxId,
    ) -> Result<Vec<u8>, Violation> {
        w.adapter
            .export(id)
            .map_err(|error| violation(PORT, clause, format!("export of {id:?} failed: {error:?}")))
    }

    fn seal<S: Sandbox>(
        w: &Workspace<S>,
        clause: &'static str,
        id: &SandboxId,
    ) -> Result<LayerRef, Violation> {
        w.adapter
            .seal(id, core::slice::from_ref(&w.dependency))
            .map_err(|error| {
                violation(
                    PORT,
                    clause,
                    format!("seal of {:?} in {id:?} failed: {error:?}", w.dependency),
                )
            })
    }

    /// A `Prepare` sandbox in which `write` ran, sealed into a layer. Then
    /// `overwrite` runs in it and it is destroyed, as the prepare sandbox
    /// is before the agent's: a layer is the snapshot at the seal, and it
    /// outlives the sandbox it was sealed from.
    fn sealed<S: Sandbox>(w: &Workspace<S>, clause: &'static str) -> Result<LayerRef, Violation> {
        dependency_fixture(w, clause)?;
        let p = create_from(w, clause, &in_phase(w, Phase::Prepare))?;
        exec(w, clause, &p, &w.write)?;
        let layer = seal(w, clause, &p)?;
        exec(w, clause, &p, &w.overwrite)?;
        destroy(w, clause, &p)?;
        Ok(layer)
    }

    /// The fixture's spec with `layer` as its one dependency.
    fn with_layer<S>(w: &Workspace<S>, layer: &LayerRef) -> SandboxSpec {
        SandboxSpec {
            dependencies: vec![layer.clone()],
            ..w.spec.clone()
        }
    }

    /// The export of `id` is the workspace it was created from: nothing
    /// another sandbox wrote reached it.
    fn export_unchanged<S: Sandbox>(
        w: &Workspace<S>,
        clause: &'static str,
        id: &SandboxId,
        why: &str,
    ) -> Result<(), Violation> {
        let got = export(w, clause, id)?;
        ensure(got == w.spec.workspace.as_bytes(), PORT, clause, || {
            format!(
                "export of {id:?}, {why}, is {} bytes, not the {} bytes it was created from",
                got.len(),
                w.spec.workspace.len()
            )
        })
    }

    /// `path` lies beneath `dependency`, `copied` does not, and
    /// `overwritten` differs from `content`: otherwise the dependency
    /// clauses would test nothing.
    fn dependency_fixture<S>(w: &Workspace<S>, clause: &'static str) -> Result<(), Violation> {
        ensure(
            !w.overwritten.is_empty() && w.overwritten != w.content,
            PORT,
            clause,
            || {
                String::from(
                    "fixture: the overwritten content is empty or equals the content, so a \
                     layer that took the write could not be told from one that did not",
                )
            },
        )?;
        let beneath = |path: &RelativePath| {
            path.as_str()
                .strip_prefix(w.dependency.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        };
        ensure(beneath(&w.path), PORT, clause, || {
            format!(
                "fixture: the path {:?} is not beneath the dependency {:?}, so a sealed layer \
                 would not hold it",
                w.path, w.dependency
            )
        })?;
        ensure(
            !beneath(&w.copied) && w.copied != w.dependency,
            PORT,
            clause,
            || {
                format!(
                    "fixture: the copy target {:?} lies in the dependency {:?}, which is \
                     mounted read-only",
                    w.copied, w.dependency
                )
            },
        )
    }

    /// `write` ran in `id`, and copying out its path gives its content.
    fn expect_written<S: Sandbox>(
        w: &Workspace<S>,
        clause: &'static str,
        id: &SandboxId,
    ) -> Result<(), Violation> {
        if w.content.is_empty() {
            return Err(violation(
                PORT,
                clause,
                String::from(
                    "the fixture's content is empty, so the clause cannot tell a written file \
                     from an empty one",
                ),
            ));
        }
        let got = w.adapter.copy_out(id, &w.path);
        ensure(got.as_ref() == Ok(&w.content), PORT, clause, || {
            format!(
                "copy_out of {:?} from {id:?} after write gave {got:?}, expected {} bytes",
                w.path,
                w.content.len()
            )
        })
    }

    /// `read` ran in `id`, which mounts the sealed layer, and its copy
    /// holds the content the layer was sealed with. `copied` has no file
    /// before `read` runs, so a workspace that already held it cannot
    /// pass for a mounted layer.
    fn expect_read<S: Sandbox>(
        w: &Workspace<S>,
        clause: &'static str,
        id: &SandboxId,
    ) -> Result<(), Violation> {
        let before = w.adapter.copy_out(id, &w.copied);
        ensure(before == Err(SandboxError::NotFound), PORT, clause, || {
            format!(
                "copy_out of {:?} from {id:?} before read gave {before:?}, expected NotFound",
                w.copied
            )
        })?;
        exec(w, clause, id, &w.read)?;
        let got = w.adapter.copy_out(id, &w.copied);
        ensure(got.as_ref() == Ok(&w.content), PORT, clause, || {
            format!(
                "copy_out of {:?} from {id:?} after read gave {got:?}, expected the {} bytes \
                 sealed at {:?}",
                w.copied,
                w.content.len(),
                w.path
            )
        })
    }

    /// `result` is `Failed`: refused, not run, and not mistaken for an
    /// unknown handle.
    fn expect_failed<T: core::fmt::Debug>(
        clause: &'static str,
        what: &str,
        result: Result<T, SandboxError>,
    ) -> Result<(), Violation> {
        ensure(
            matches!(result, Err(SandboxError::Failed { .. })),
            PORT,
            clause,
            || format!("{what} gave {result:?}, expected Failed"),
        )
    }

    fn distinct_ids<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "distinct-ids";
        let a = create(w, clause)?;
        let b = create(w, clause)?;
        destroy(w, clause, &a)?;
        // A handle issued again after a destroy would let a stale handle
        // reach the newer sandbox.
        let c = create(w, clause)?;
        let ids = [a, b, c];
        let distinct: BTreeSet<&SandboxId> = ids.iter().collect();
        ensure(distinct.len() == ids.len(), PORT, clause, || {
            format!("handles repeat: {ids:?}")
        })
    }

    fn copy_out_after_write<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "copy-out-after-write";
        let id = create(w, clause)?;
        exec(w, clause, &id, &w.write)?;
        expect_written(w, clause, &id)
    }

    fn copy_out_missing<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "copy-out-missing";
        let id = create(w, clause)?;
        let got = w.adapter.copy_out(&id, &w.path);
        ensure(got == Err(SandboxError::NotFound), PORT, clause, || {
            format!(
                "copy_out of {:?} before anything wrote it gave {got:?}, expected NotFound",
                w.path
            )
        })
    }

    fn isolated<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "isolated";
        let a = create(w, clause)?;
        let b = create(w, clause)?;
        exec(w, clause, &a, &w.write)?;
        let other = w.adapter.copy_out(&b, &w.path);
        ensure(other == Err(SandboxError::NotFound), PORT, clause, || {
            format!(
                "copy_out of {:?} from {b:?} after a write in {a:?} gave {other:?}, expected \
                 NotFound",
                w.path
            )
        })?;
        export_unchanged(w, clause, &b, "after a write in another sandbox")?;
        expect_written(w, clause, &a)
    }

    /// A sandbox created after another was destroyed starts from its own
    /// workspace: a pooled adapter that hands the destroyed workspace on
    /// unwiped would let the agent's files reach the verify sandbox
    /// (invariant 6).
    fn fresh_after_destroy<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "fresh-after-destroy";
        let a = create(w, clause)?;
        exec(w, clause, &a, &w.write)?;
        expect_written(w, clause, &a)?;
        destroy(w, clause, &a)?;
        let b = create(w, clause)?;
        let got = w.adapter.copy_out(&b, &w.path);
        ensure(got == Err(SandboxError::NotFound), PORT, clause, || {
            format!(
                "copy_out of {:?} from {b:?}, created after {a:?} wrote it and was destroyed, \
                 gave {got:?}, expected NotFound",
                w.path
            )
        })?;
        export_unchanged(
            w,
            clause,
            &b,
            "created after a written sandbox was destroyed",
        )
    }

    fn exit_status<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "exit-status";
        if w.status == ExitStatus::Code(0) {
            return Err(violation(
                PORT,
                clause,
                String::from(
                    "the fixture's status is Code(0), so the clause cannot tell it from an \
                     adapter that reports success for every command",
                ),
            ));
        }
        let id = create(w, clause)?;
        let result = exec(w, clause, &id, &w.exit)?;
        ensure(result.status == w.status, PORT, clause, || {
            format!(
                "exec of {:?} ended with {:?}, expected {:?}",
                w.exit.program, result.status, w.status
            )
        })
    }

    fn destroyed_is_unknown<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "destroyed-is-unknown";
        let id = create(w, clause)?;
        exec(w, clause, &id, &w.write)?;
        destroy(w, clause, &id)?;
        let unknown = Err(SandboxError::UnknownSandbox);
        let ran = w.adapter.exec(&id, &w.write, &w.limits).map(|_| ());
        let started = w.adapter.start(&id, &w.write);
        let copied = w.adapter.copy_out(&id, &w.path).map(|_| ());
        let exported = w.adapter.export(&id).map(|_| ());
        let sealed = w
            .adapter
            .seal(&id, core::slice::from_ref(&w.dependency))
            .map(|_| ());
        let again = w.adapter.destroy(&id);
        ensure(
            [&ran, &started, &copied, &exported, &sealed, &again]
                .iter()
                .all(|got| **got == unknown),
            PORT,
            clause,
            || {
                format!(
                    "after destroy, exec gave {ran:?}, start {started:?}, copy_out {copied:?}, \
                     export {exported:?}, seal {sealed:?} and destroy {again:?}, expected \
                     UnknownSandbox"
                )
            },
        )
    }

    /// The fixture's spec with [`Workspace::container`] added.
    fn two_containers<S>(w: &Workspace<S>, clause: &'static str) -> Result<SandboxSpec, Violation> {
        ensure(
            w.spec.containers.iter().all(|c| c.name != w.container.name),
            PORT,
            clause,
            || {
                format!(
                    "fixture: the second container's name {:?} is taken in the spec",
                    w.container.name.as_str()
                )
            },
        )?;
        let mut spec = w.spec.clone();
        spec.containers.push(w.container.clone());
        ensure(spec.check().is_ok(), PORT, clause, || {
            format!(
                "fixture: the spec with a second container is refused by the core check: {:?}",
                spec.check()
            )
        })?;
        Ok(spec)
    }

    /// A command in a container the pod does not have is refused, never
    /// run in another: an adapter that ignored the name would run a
    /// service meant for the database next to the workspace.
    fn unknown_container<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "unknown-container";
        let spec = two_containers(w, clause)?;
        let id = create_from(w, clause, &spec)?;
        let second = Command {
            container: w.container.name.clone(),
            ..w.exit.clone()
        };
        let result = exec(w, clause, &id, &second)?;
        ensure(result.status == w.status, PORT, clause, || {
            format!(
                "exec of {:?} in the second container ended with {:?}, expected {:?}",
                w.exit.program, result.status, w.status
            )
        })?;
        // The second container does not hold the workspace: a `write` run
        // there leaves it as it was. An adapter that checked the name and
        // then ran the command in the first container would hand the
        // second image's program the workspace, the layers and the
        // brokers.
        let write = Command {
            container: w.container.name.clone(),
            ..w.write.clone()
        };
        exec(w, clause, &id, &write)?;
        let got = w.adapter.copy_out(&id, &w.path);
        ensure(got == Err(SandboxError::NotFound), PORT, clause, || {
            format!(
                "copy_out of {:?} after write in the second container gave {got:?}, expected \
                 NotFound",
                w.path
            )
        })?;
        export_unchanged(w, clause, &id, "after a write in the second container")?;
        let unknown = (0u32..)
            .filter_map(|k| ContainerName::parse(&format!("contract-unknown-{k}")).ok())
            .find(|name| spec.containers.iter().all(|c| c.name != *name))
            .ok_or_else(|| {
                violation(
                    PORT,
                    clause,
                    String::from("fixture: no container name is free"),
                )
            })?;
        let elsewhere = Command {
            container: unknown,
            ..w.exit.clone()
        };
        expect_failed(
            clause,
            "exec in a container the pod does not have",
            w.adapter.exec(&id, &elsewhere, &w.limits),
        )?;
        expect_failed(
            clause,
            "start in a container the pod does not have",
            w.adapter.start(&id, &elsewhere),
        )
    }

    /// Pod limits the core check refuses are refused by `create`, counted
    /// over every container: an adapter that skipped the check would set
    /// a tmpfs cap the OOM kill always beats, or a `pids.max` no exec can
    /// start under (ADR-042, D2). So is the rest of `SandboxSpec::check`:
    /// two containers of one name, two brokers of one name, a broker
    /// socket that is relative or holds NUL. A layer listed twice is in
    /// `dependency-overlap-refused`, which needs sealed layers.
    fn limits_checked<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "limits-checked";
        let spec = two_containers(w, clause)?;
        create_from(w, clause, &spec)?;
        let l = spec.limits;
        let storage = l
            .tmp_bytes
            .checked_add(l.shm_bytes)
            .and_then(|each| each.checked_mul(2))
            .and_then(|all| all.checked_add(l.workspace_bytes))
            .ok_or_else(|| {
                violation(
                    PORT,
                    clause,
                    String::from("fixture: the storage sizes overflow"),
                )
            })?;
        let agent = SandboxSpec {
            phase: Phase::Agent,
            ..spec.clone()
        };
        let mut relative = w.broker.clone();
        relative.socket = String::from(relative.socket.trim_start_matches('/'));
        let mut nul = w.broker.clone();
        nul.socket.push('\u{0}');
        let variants: [(&str, SandboxSpec); 9] = [
            // 3 tasks are enough for one container, not for two.
            ("processes for one container only", {
                let mut s = spec.clone();
                s.limits.processes = 3;
                s
            }),
            ("memory one byte below the storage of two containers", {
                let mut s = spec.clone();
                s.limits.memory_bytes = storage - 1;
                s
            }),
            ("cpu_millis below the floor", {
                let mut s = spec.clone();
                s.limits.cpu_millis = 9;
                s
            }),
            ("an unlimited /tmp", {
                let mut s = spec.clone();
                s.limits.tmp_bytes = 0;
                s
            }),
            ("the user 4294967295", {
                let mut s = spec.clone();
                s.user = u32::MAX;
                s
            }),
            // The rest of `SandboxSpec::check`, on specs whose limits fit.
            ("two containers of one name", {
                let mut s = spec.clone();
                s.containers[1].name = s.containers[0].name.clone();
                s
            }),
            ("two brokers of one name", {
                let mut s = agent.clone();
                s.brokers = vec![w.broker.clone(), w.broker.clone()];
                s
            }),
            ("a broker socket at a relative path", {
                let mut s = agent.clone();
                s.brokers = vec![relative];
                s
            }),
            ("a broker socket with NUL", {
                let mut s = agent;
                s.brokers = vec![nul];
                s
            }),
        ];
        for (what, variant) in variants {
            expect_failed(
                clause,
                &format!("create with {what}"),
                w.adapter.create(&variant),
            )?;
        }
        Ok(())
    }

    /// Output of exactly `output_bytes` is returned whole, one byte more
    /// fails the exec: a cut transcript is never returned as a whole one.
    /// Each stream is capped on its own; test runners put their failure
    /// output on the error stream.
    fn output_cap<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "output-cap";
        ensure(!w.printed.is_empty(), PORT, clause, || {
            String::from("fixture: the printed output is empty, so no cap below it exists")
        })?;
        let n = u64::try_from(w.printed.len()).unwrap_or(u64::MAX);
        let at = |output_bytes| Limits {
            output_bytes,
            ..w.limits
        };
        let id = create(w, clause)?;
        type Stream = fn(&ExecResult) -> &Vec<u8>;
        let streams: [(&str, &Command, Stream); 2] = [
            ("print", &w.print, |r| &r.stdout),
            ("print_err", &w.print_err, |r| &r.stderr),
        ];
        for (name, command, stream) in streams {
            let whole = w.adapter.exec(&id, command, &at(n));
            ensure(
                whole.as_ref().map(stream) == Ok(&w.printed),
                PORT,
                clause,
                || {
                    format!(
                        "exec of {name} with output_bytes {n} gave {whole:?}, expected its output"
                    )
                },
            )?;
            expect_failed(
                clause,
                &format!("exec of {name} with output_bytes {}", n - 1),
                w.adapter.exec(&id, command, &at(n - 1)),
            )?;
        }
        Ok(())
    }

    /// A started service runs: what it writes is in the workspace.
    fn start_runs<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "start-runs";
        let id = create(w, clause)?;
        w.adapter.start(&id, &w.service).map_err(|error| {
            violation(
                PORT,
                clause,
                format!("start of {:?} failed: {error:?}", w.service.program),
            )
        })?;
        exec(w, clause, &id, &w.settle)?;
        let got = w.adapter.copy_out(&id, &w.path);
        ensure(got.as_ref() == Ok(&w.content), PORT, clause, || {
            format!(
                "copy_out of {:?} after the service started gave {got:?}, expected {} bytes",
                w.path,
                w.content.len()
            )
        })
    }

    /// A sandbox exports the workspace it was created from, byte for byte,
    /// and holds its files: the copy-in and the export agree.
    fn export_round_trip<S: Sandbox>(
        w: &Workspace<S>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "export-round-trip";
        let base = w.spec.workspace.as_bytes();
        let tracked = edit(base, &TreePath::from(&w.path), Some(&w.content));
        ensure(tracked != base, PORT, clause, || {
            String::from("fixture: edit did not change the workspace")
        })?;
        let spec = SandboxSpec {
            workspace: WorkspaceBytes::new(tracked.clone()),
            ..w.spec.clone()
        };
        let id = create_from(w, clause, &spec)?;
        expect_written(w, clause, &id)?;
        let got = export(w, clause, &id)?;
        ensure(got == tracked, PORT, clause, || {
            format!(
                "export of a sandbox created from a {}-byte workspace is {} bytes, not that \
                 workspace",
                tracked.len(),
                got.len()
            )
        })
    }

    /// A file a command wrote reaches the export: the agent's work is what
    /// the diff sees.
    fn export_sees_write<S: Sandbox>(
        w: &Workspace<S>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "export-sees-write";
        let base = w.spec.workspace.as_bytes();
        let expected = edit(base, &TreePath::from(&w.path), Some(&w.content));
        ensure(expected != base, PORT, clause, || {
            String::from("fixture: edit did not change the workspace")
        })?;
        let id = create(w, clause)?;
        exec(w, clause, &id, &w.write)?;
        let got = export(w, clause, &id)?;
        ensure(got == expected, PORT, clause, || {
            format!(
                "export after write is {} bytes, not the {} bytes of the workspace with {:?} \
                 written",
                got.len(),
                expected.len(),
                w.path
            )
        })
    }

    /// `copy_out` follows no symlink, neither at the path nor at a parent,
    /// and refuses it as `Failed` rather than `NotFound`, so a fixture
    /// that planted nothing cannot pass (ADR-004, D11). The relative link
    /// points inside the workspace, so an adapter that follows links where
    /// the absolute targets do not resolve (on the host, say) still shows.
    fn copy_out_no_symlink<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "copy-out-no-symlink";
        ensure(!w.outside.is_empty(), PORT, clause, || {
            String::from(
                "fixture: the planted content is empty, so a copy-out that followed the link \
                 could not be told from an empty file",
            )
        })?;
        for (how, command) in [
            ("at the path", &w.link),
            ("at a parent", &w.through),
            ("with a relative target at the path", &w.relative),
        ] {
            let id = create(w, clause)?;
            exec(w, clause, &id, &w.plant)?;
            exec(w, clause, &id, command)?;
            let got = w.adapter.copy_out(&id, &w.path);
            if got.as_ref() == Ok(&w.outside) {
                return Err(violation(
                    PORT,
                    clause,
                    format!(
                        "copy_out of {:?} with a symlink {how} followed it to the planted file",
                        w.path
                    ),
                ));
            }
            expect_failed(
                clause,
                &format!("copy_out of {:?} with a symlink {how}", w.path),
                got,
            )?;
        }
        Ok(())
    }

    /// A `Verify` spec with a broker is refused, and an `Agent` spec with
    /// the same broker is not, so an adapter that refused every broker
    /// fails too ("without either socket", invariant 6).
    fn verify_without_brokers<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "verify-without-brokers";
        let with = |phase| SandboxSpec {
            brokers: vec![w.broker.clone()],
            ..in_phase(w, phase)
        };
        expect_failed(
            clause,
            "create of a verify sandbox with a broker",
            w.adapter.create(&with(Phase::Verify)),
        )?;
        create_from(w, clause, &with(Phase::Agent)).map(|_| ())
    }

    /// Only a `Prepare` sandbox can be sealed, so nothing the agent wrote
    /// becomes a layer the verify sandbox trusts (invariant 6).
    fn seal_prepare_only<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "seal-prepare-only";
        dependency_fixture(w, clause)?;
        for phase in [Phase::Agent, Phase::Verify] {
            let id = create_from(w, clause, &in_phase(w, phase))?;
            exec(w, clause, &id, &w.write)?;
            expect_failed(
                clause,
                &format!("seal of a {phase:?} sandbox"),
                w.adapter.seal(&id, core::slice::from_ref(&w.dependency)),
            )?;
        }
        sealed(w, clause).map(|_| ())
    }

    /// A seal follows no symlink: a sealed directory that is a link, or a
    /// link in it, never brings the file behind it into the layer. The
    /// adapter refuses the seal or carries the link as it is; either way a
    /// sandbox that mounts the layer does not read the planted file. A
    /// seal runs on the host as the runner user, so a followed link there
    /// would seal host files into every later sandbox.
    fn seal_no_symlink<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "seal-no-symlink";
        dependency_fixture(w, clause)?;
        // The relative link resolves on the host as it does inside, so a
        // host-side copier that follows links shows there too.
        for (how, command) in [
            ("at the path", &w.link),
            ("at a parent", &w.through),
            ("with a relative target at the path", &w.relative),
        ] {
            let p = create_from(w, clause, &in_phase(w, Phase::Prepare))?;
            exec(w, clause, &p, &w.plant)?;
            exec(w, clause, &p, command)?;
            let layer = match w.adapter.seal(&p, core::slice::from_ref(&w.dependency)) {
                Err(SandboxError::Failed { .. }) => continue,
                Err(error) => {
                    return Err(violation(
                        PORT,
                        clause,
                        format!(
                            "seal with a symlink {how} gave {error:?}, expected Failed or a layer"
                        ),
                    ));
                }
                Ok(layer) => layer,
            };
            let id = create_from(w, clause, &with_layer(w, &layer))?;
            exec(w, clause, &id, &w.read)?;
            let got = w.adapter.copy_out(&id, &w.copied);
            ensure(got.as_ref() != Ok(&w.outside), PORT, clause, || {
                format!(
                    "a layer sealed with a symlink {how} holds the planted file: read gave \
                     {got:?}"
                )
            })?;
        }
        Ok(())
    }

    /// A sealed layer is mounted in a sandbox that names it: its files are
    /// there for a command to read, as they were at the seal, after the
    /// sealed sandbox wrote again and was destroyed. A sandbox without the
    /// layer reads nothing.
    fn sealed_layer_mounted<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "sealed-layer-mounted";
        let layer = sealed(w, clause)?;
        let bare = create(w, clause)?;
        exec(w, clause, &bare, &w.read)?;
        let got = w.adapter.copy_out(&bare, &w.copied);
        ensure(got == Err(SandboxError::NotFound), PORT, clause, || {
            format!(
                "copy_out of {:?} after read in a sandbox without the layer gave {got:?}, \
                 expected NotFound",
                w.copied
            )
        })?;
        let id = create_from(w, clause, &with_layer(w, &layer))?;
        expect_read(w, clause, &id)
    }

    /// A mounted layer is read-only: a write beneath the mount in one
    /// sandbox changes neither that sandbox's view nor another's. A layer
    /// is the one thing that travels between sandboxes, so a writable one
    /// would carry the agent's bytes into the verify sandbox (invariant
    /// 6).
    fn dependency_read_only<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "dependency-read-only";
        let layer = sealed(w, clause)?;
        let mounting = |phase| SandboxSpec {
            phase,
            ..with_layer(w, &layer)
        };
        let agent = create_from(w, clause, &mounting(Phase::Agent))?;
        // The write is refused; whether the command reports that is the
        // command's business.
        match w.adapter.exec(&agent, &w.overwrite, &w.limits) {
            Ok(_) | Err(SandboxError::Failed { .. }) => {}
            Err(error) => {
                return Err(violation(
                    PORT,
                    clause,
                    format!("exec of overwrite beneath the mount gave {error:?}"),
                ));
            }
        }
        expect_read(w, clause, &agent)?;
        let verify = create_from(w, clause, &mounting(Phase::Verify))?;
        expect_read(w, clause, &verify)
    }

    /// The export of a sandbox that mounts a layer is its own workspace,
    /// without the layer: the agent's diff never carries the dependencies.
    fn export_without_mounts<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "export-without-mounts";
        let layer = sealed(w, clause)?;
        let id = create_from(w, clause, &with_layer(w, &layer))?;
        export_unchanged(w, clause, &id, "which mounts a layer")
    }

    /// Dependencies that overlap are refused at `create`: a layer listed
    /// twice, and two layers sealed from the same directory. Mounted
    /// together, one would hide the other, and what the gates read would
    /// depend on the mount order (ADR-042, D6).
    fn dependency_overlap_refused<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "dependency-overlap-refused";
        let a = sealed(w, clause)?;
        let b = sealed(w, clause)?;
        for (what, dependencies) in [
            ("one layer listed twice", vec![a.clone(), a.clone()]),
            ("two layers sealed from one directory", vec![a, b]),
        ] {
            expect_failed(
                clause,
                &format!("create with {what}"),
                w.adapter.create(&SandboxSpec {
                    dependencies,
                    ..w.spec.clone()
                }),
            )?;
        }
        Ok(())
    }

    /// Two seals give two handles, even of the same content: a reused
    /// handle would let a `release` of one remove the other.
    fn distinct_layers<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "distinct-layers";
        dependency_fixture(w, clause)?;
        let p = create_from(w, clause, &in_phase(w, Phase::Prepare))?;
        exec(w, clause, &p, &w.write)?;
        let first = seal(w, clause, &p)?;
        let second = seal(w, clause, &p)?;
        let third = sealed(w, clause)?;
        let layers = [first, second, third];
        let distinct: BTreeSet<&LayerRef> = layers.iter().collect();
        ensure(distinct.len() == layers.len(), PORT, clause, || {
            format!("layer handles repeat: {layers:?}")
        })
    }

    /// A released layer is gone: a spec that names it, and a second
    /// release, are refused.
    fn released_layer_unknown<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "released-layer-unknown";
        let layer = sealed(w, clause)?;
        w.adapter.release(&layer).map_err(|error| {
            violation(
                PORT,
                clause,
                format!("release of {layer:?}, which no sandbox mounts, failed: {error:?}"),
            )
        })?;
        expect_failed(
            clause,
            "create with a released layer",
            w.adapter.create(&with_layer(w, &layer)),
        )?;
        expect_failed(clause, "a second release", w.adapter.release(&layer))
    }

    /// A layer a live sandbox mounts is not released: deleting it under a
    /// live mount would empty that sandbox's dependencies. Once the
    /// sandbox is destroyed, it is.
    fn layer_in_use_kept<S: Sandbox>(w: &Workspace<S>) -> Result<(), Violation> {
        let clause = "layer-in-use-kept";
        let layer = sealed(w, clause)?;
        let id = create_from(w, clause, &with_layer(w, &layer))?;
        expect_failed(
            clause,
            "release of a layer a live sandbox mounts",
            w.adapter.release(&layer),
        )?;
        expect_read(w, clause, &id)?;
        destroy(w, clause, &id)?;
        w.adapter.release(&layer).map_err(|error| {
            violation(
                PORT,
                clause,
                format!(
                    "release of {layer:?} after the sandbox that mounted it was destroyed \
                     failed: {error:?}"
                ),
            )
        })
    }
}

/// The `Git` suite.
pub mod git {
    use super::*;
    use crate::git::{BranchName, CheckoutId, CommitInfo, Git, GitError, RepoUrl};
    use crate::path::{RelativePath, TreePath, Uncitable};
    use boneli_domain::{Change, CitationProblem, Entry, EntryKind, Patch, UnreadablePath};

    const PORT: &str = "Git";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &[
        "read-at-base",
        "read-missing",
        "unknown-commit",
        "apply-then-read",
        "apply-leaves-base",
        "base-refetch-unchanged",
        "unchanged-snapshot-empty-diff",
        "added-file",
        "removed-file",
        "apply-mismatch-fails",
        "workspace-metadata-inert",
        "push-reads-back",
        "push-parent-is-base",
        "push-never-overwrites",
        "push-unknown-checkout",
        "uncitable-paths-carried",
        "patch-unchanged-empty",
        "patch-full-sides",
        "patch-added-removed",
        "patch-unknown-checkout",
        "patch-uncitable-paths",
    ];

    /// The sub-checks of `workspace-metadata-inert`, each with its own
    /// mutant (ADR-004, D2; ADR-010, D1).
    pub const METADATA_CHECKS: &[&str] = &[
        "nothing-ran",
        "same-diff",
        "same-checkout",
        "fresh-checkout",
        "same-apply",
        "apply-refuses",
    ];

    /// The sub-checks of `uncitable-paths-carried`, each with its own
    /// mutant (ADR-004, D2; ADR-018, D6).
    pub const UNCITABLE_CHECKS: &[&str] = &[
        "snapshot-carries",
        "edit-round-trip",
        "remove-round-trip",
        "add-round-trip",
    ];

    /// The sub-checks of `patch-uncitable-paths`, each with its own mutant
    /// (ADR-004, D2; ADR-023, D6).
    pub const PATCH_UNCITABLE_CHECKS: &[&str] = &["uncitable-carried", "unreadable-refused"];

    /// An adapter with a repository whose content at the base commit the
    /// adapter's own test knows.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Repository<G> {
        /// The adapter.
        pub adapter: G,
        /// The repository.
        pub repo: RepoUrl,
        /// A commit the repository has.
        pub base: CommitSha,
        /// A file at the base commit.
        pub path: RelativePath,
        /// Its content at the base commit.
        pub content: Vec<u8>,
        /// A path with no file at the base commit.
        pub missing: RelativePath,
        /// A commit the repository does not have.
        pub unknown: CommitSha,
        /// The content the suite gives [`Repository::path`] in a workspace;
        /// not equal to [`Repository::content`], or an adapter that ignores
        /// diffs would pass.
        pub edited: Vec<u8>,
        /// Repository metadata the suite plants in a workspace, path and
        /// content; every path must be [`RelativePath::is_repository_metadata`].
        pub metadata: Vec<(RelativePath, Vec<u8>)>,
        /// Files at the base commit whose paths the citation rule refuses
        /// ([`TreePath::citable`]), with their content at the base: at
        /// least one path that is not UTF-8, one with a backslash and one
        /// that is blank, none of them repository metadata (ADR-018, D6).
        pub uncitable: Vec<(TreePath, Vec<u8>)>,
    }

    /// Whether anything the planted metadata asks for ran on the host. Only
    /// the adapter's own test knows how to look (for the git binary, a
    /// sentinel that a hook or `core.fsmonitor` would create). The sentinel
    /// must sit at an absolute path outside every directory the adapter
    /// creates or removes: a relative one lands in the directory git runs
    /// in, which the adapter deletes, and the run would go unseen. It must
    /// also be unique to the fixture, in the test's own temporary
    /// directory: tests run in parallel, and one that resets a shared
    /// sentinel would erase another's trip.
    pub trait Tripwire<G> {
        /// What ran, one entry each; empty when nothing did. An error is
        /// reported as the clause's detail.
        fn tripped(&self, adapter: &G) -> Result<Vec<String>, String>;
    }

    /// What the remote holds after a push, as only the adapter's own test
    /// can see it: for the git binary, the fixture repository read with the
    /// test's own git; for an in-memory adapter, its state. The push
    /// clauses use one branch each, `boneli/contract-<clause>`, which must
    /// not exist on the fixture's remote before the suite runs.
    pub trait Remote<G> {
        /// The tip of `branch` in `repo` and the tip's parents, in order;
        /// `None` when the branch does not exist. An error is reported as
        /// the clause's detail.
        fn branch(
            &self,
            adapter: &G,
            repo: &RepoUrl,
            branch: &BranchName,
        ) -> Result<Option<(CommitSha, Vec<CommitSha>)>, String>;
    }

    /// Checks every clause; each clause gets a fresh adapter from `make`.
    ///
    /// `edit` takes a workspace in the adapter's snapshot format, a path
    /// and content, and returns the workspace with that file set to that
    /// content, or removed for `None`. The snapshot format belongs to the
    /// adapter (#30), so only its own test knows how. Its path is a
    /// [`TreePath`], because a workspace carries paths an agent cannot cite
    /// (ADR-018). `retarget` takes a
    /// diff in the adapter's format and two paths and returns the diff with
    /// every change of the first path moved to the second; the suite proves
    /// on a content path that the result applies. `tripwire` reports what
    /// the planted metadata of `workspace-metadata-inert` made run, and
    /// `remote` what the push clauses left on the remote.
    pub fn run<G: Git>(
        make: impl Fn() -> Repository<G>,
        edit: impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        retarget: impl Fn(&[u8], &RelativePath, &RelativePath) -> Vec<u8>,
        tripwire: &impl Tripwire<G>,
        remote: &impl Remote<G>,
    ) -> Result<(), Violation> {
        read_at_base(&make())?;
        read_missing(&make())?;
        unknown_commit(&make())?;
        apply_then_read(&make(), &edit)?;
        apply_leaves_base(&make(), &edit)?;
        base_refetch_unchanged(&make(), &edit)?;
        unchanged_snapshot_empty_diff(&make())?;
        added_file(&make(), &edit)?;
        removed_file(&make(), &edit)?;
        apply_mismatch_fails(&make(), &edit)?;
        workspace_metadata_inert(&make(), &edit, &retarget, tripwire)?;
        push_reads_back(&make(), &edit, remote)?;
        push_parent_is_base(&make(), &edit, remote)?;
        push_never_overwrites(&make(), &edit, remote)?;
        push_unknown_checkout(&make(), remote)?;
        uncitable_paths_carried(&make(), &edit)?;
        patch_unchanged_empty(&make())?;
        patch_full_sides(&make(), &edit)?;
        patch_added_removed(&make(), &edit)?;
        patch_unknown_checkout(&make())?;
        patch_uncitable_paths(&make(), &edit)
    }

    /// A content path as the `edit` hook takes it.
    fn tree(path: &RelativePath) -> TreePath {
        TreePath::from(path)
    }

    fn call<T>(
        clause: &'static str,
        what: &str,
        result: Result<T, GitError>,
    ) -> Result<T, Violation> {
        result.map_err(|error| violation(PORT, clause, format!("{what} failed: {error:?}")))
    }

    fn checkout<G: Git>(r: &Repository<G>, clause: &'static str) -> Result<CheckoutId, Violation> {
        call(clause, "fetch_base", r.adapter.fetch_base(&r.repo, &r.base))
    }

    fn expect_read<G: Git>(
        r: &Repository<G>,
        clause: &'static str,
        checkout: &CheckoutId,
        path: &RelativePath,
        want: Option<&[u8]>,
    ) -> Result<(), Violation> {
        let got = call(clause, "read", r.adapter.read(checkout, path))?;
        ensure(got.as_deref() == want, PORT, clause, || {
            format!("read of {path:?} in {checkout:?} gave {got:?}, expected {want:?}")
        })
    }

    /// Fetches the base, applies `change` to its snapshot, diffs and
    /// applies the diff; returns the base checkout and the applied one.
    fn changed<G: Git>(
        r: &Repository<G>,
        clause: &'static str,
        change: impl Fn(&[u8]) -> Vec<u8>,
    ) -> Result<(CheckoutId, CheckoutId), Violation> {
        let base = checkout(r, clause)?;
        let snapshot = call(clause, "snapshot", r.adapter.snapshot(&base))?;
        let workspace = change(&snapshot);
        let diff = call(clause, "diff", r.adapter.diff(&base, &workspace))?;
        let after = call(clause, "apply", r.adapter.apply(&base, &diff))?;
        Ok((base, after))
    }

    /// Fetches the base, edits the path in its snapshot, diffs and applies
    /// the diff; returns the base checkout and the applied one.
    fn applied<G: Git>(
        r: &Repository<G>,
        clause: &'static str,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(CheckoutId, CheckoutId), Violation> {
        if r.edited == r.content {
            return Err(violation(
                PORT,
                clause,
                String::from(
                    "the fixture's edited content equals the base content, so the clause \
                     cannot tell an applied diff from an ignored one",
                ),
            ));
        }
        changed(r, clause, |snapshot| {
            edit(snapshot, &tree(&r.path), Some(&r.edited))
        })
    }

    fn read_at_base<G: Git>(r: &Repository<G>) -> Result<(), Violation> {
        let clause = "read-at-base";
        let base = checkout(r, clause)?;
        expect_read(r, clause, &base, &r.path, Some(&r.content))
    }

    fn read_missing<G: Git>(r: &Repository<G>) -> Result<(), Violation> {
        let clause = "read-missing";
        let base = checkout(r, clause)?;
        expect_read(r, clause, &base, &r.missing, None)
    }

    fn unknown_commit<G: Git>(r: &Repository<G>) -> Result<(), Violation> {
        let clause = "unknown-commit";
        if r.unknown == r.base {
            return Err(violation(
                PORT,
                clause,
                String::from("the fixture's unknown commit is its base commit"),
            ));
        }
        let got = r.adapter.fetch_base(&r.repo, &r.unknown);
        ensure(got == Err(GitError::UnknownCommit), PORT, clause, || {
            format!(
                "fetch_base of {:?}, which the repository does not have, gave {got:?}, expected \
                 UnknownCommit",
                r.unknown
            )
        })
    }

    fn apply_then_read<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "apply-then-read";
        let (_, after) = applied(r, clause, edit)?;
        expect_read(r, clause, &after, &r.path, Some(&r.edited))
    }

    /// The verify sandbox starts from the base and the diff only
    /// (invariant 6), so applying a diff must not change the base.
    fn apply_leaves_base<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "apply-leaves-base";
        let (base, _) = applied(r, clause, edit)?;
        expect_read(r, clause, &base, &r.path, Some(&r.content))
    }

    /// The base fetched again after an apply is still the base: an adapter
    /// that caches checkouts per repository and commit must not let an
    /// apply write into the cache.
    fn base_refetch_unchanged<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "base-refetch-unchanged";
        applied(r, clause, edit)?;
        let again = checkout(r, clause)?;
        expect_read(r, clause, &again, &r.path, Some(&r.content))
    }

    /// A file the base does not have reaches the diff: reproduction tests
    /// are usually new files, and a diff of tracked files only would drop
    /// them.
    fn added_file<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "added-file";
        let (_, after) = changed(r, clause, |snapshot| {
            edit(snapshot, &tree(&r.missing), Some(&r.edited))
        })?;
        expect_read(r, clause, &after, &r.missing, Some(&r.edited))
    }

    /// A file removed from the workspace is removed by the diff.
    fn removed_file<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "removed-file";
        let (_, after) = changed(r, clause, |snapshot| edit(snapshot, &tree(&r.path), None))?;
        expect_read(r, clause, &after, &r.path, None)
    }

    /// Applying a patch fails closed. A diff that removes the file is taken
    /// from the base and applied once; applied again, to the checkout that
    /// no longer has the file, it must be an error, and that checkout must
    /// read as before. Built from the adapter's own operations only, so it
    /// holds for any diff format. That no new checkout appears cannot be
    /// observed through the port; the error is what the clause pins.
    fn apply_mismatch_fails<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "apply-mismatch-fails";
        let base = checkout(r, clause)?;
        let snapshot = call(clause, "snapshot", r.adapter.snapshot(&base))?;
        let workspace = edit(&snapshot, &tree(&r.path), None);
        let diff = call(clause, "diff", r.adapter.diff(&base, &workspace))?;
        let once = call(clause, "apply", r.adapter.apply(&base, &diff))?;
        let before = call(clause, "snapshot", r.adapter.snapshot(&once))?;
        let again = r.adapter.apply(&once, &diff);
        ensure(again.is_err(), PORT, clause, || {
            format!(
                "a diff that removes {:?}, applied to {once:?}, which does not have it, gave \
                 {again:?}, expected an error",
                r.path
            )
        })?;
        let after = call(clause, "snapshot", r.adapter.snapshot(&once))?;
        ensure(after == before, PORT, clause, || {
            format!("{once:?} changed when a diff failed to apply to it")
        })?;
        expect_read(r, clause, &once, &r.path, None)
    }

    const METADATA: &str = "workspace-metadata-inert";

    /// A fixture that would make `workspace-metadata-inert` vacuous.
    fn metadata_fixture(detail: String) -> Violation {
        violation(PORT, METADATA, format!("fixture: {detail}"))
    }

    /// The tripwire's report; an error is the clause's detail under
    /// `check`, so a tripwire that cannot look never passes.
    fn tripped<G: Git>(
        r: &Repository<G>,
        tripwire: &impl Tripwire<G>,
        check: &str,
    ) -> Result<Vec<String>, Violation> {
        tripwire.tripped(&r.adapter).map_err(|error| {
            violation(
                PORT,
                METADATA,
                format!("{check}: the tripwire failed: {error}"),
            )
        })
    }

    /// `nothing-ran`: the tripwire reports nothing.
    fn nothing_ran<G: Git>(
        r: &Repository<G>,
        tripwire: &impl Tripwire<G>,
        after: &str,
    ) -> Result<(), Violation> {
        let ran = tripped(r, tripwire, "nothing-ran")?;
        ensure(ran.is_empty(), PORT, METADATA, || {
            format!(
                "nothing-ran: after {after}, the tripwire reports {} runs of what the \
                 workspace's repository metadata asks for: {ran:?}",
                ran.len()
            )
        })
    }

    /// The snapshot of the checkout that applying `diff` to `checkout`
    /// makes.
    fn applied_snapshot<G: Git>(
        r: &Repository<G>,
        checkout: &CheckoutId,
        diff: &[u8],
    ) -> Result<Vec<u8>, Violation> {
        let after = call(METADATA, "apply", r.adapter.apply(checkout, diff))?;
        call(METADATA, "snapshot", r.adapter.snapshot(&after))
    }

    /// `sub`: the diffs of `checkout`'s snapshot, edited as for `d_plain`
    /// and unchanged, are `d_plain` and empty.
    fn diffs_as_before<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        checkout: &CheckoutId,
        d_plain: &[u8],
        sub: &str,
        which: &str,
    ) -> Result<(), Violation> {
        let snapshot = call(METADATA, "snapshot", r.adapter.snapshot(checkout))?;
        let edited = edit(&snapshot, &tree(&r.path), Some(&r.edited));
        let d_edited = call(METADATA, "diff", r.adapter.diff(checkout, &edited))?;
        let d_unchanged = call(METADATA, "diff", r.adapter.diff(checkout, &snapshot))?;
        ensure(
            d_edited == d_plain && d_unchanged.is_empty(),
            PORT,
            METADATA,
            || {
                format!(
                    "{sub}: after a diff of a workspace with repository metadata, {which} \
                     diffs the edited snapshot to {} bytes ({} before, equal: {}) and the \
                     unchanged snapshot to {} bytes (expected none)",
                    d_edited.len(),
                    d_plain.len(),
                    d_edited == d_plain,
                    d_unchanged.len()
                )
            },
        )
    }

    /// Applies `diff` to `base` and reads `twin` from the result: `Ok` when
    /// it reads back [`Repository::edited`], otherwise what it gave
    /// instead (lengths, not bytes), for the detail.
    fn adds_twin<G: Git>(
        r: &Repository<G>,
        base: &CheckoutId,
        diff: &[u8],
        twin: &RelativePath,
    ) -> Result<(), String> {
        let read = r
            .adapter
            .apply(base, diff)
            .and_then(|after| r.adapter.read(&after, twin));
        if read.as_ref().map(Option::as_deref) == Ok(Some(r.edited.as_slice())) {
            Ok(())
        } else {
            Err(format!(
                "{:?}",
                read.map(|got| got.map(|bytes| bytes.len()))
            ))
        }
    }

    /// The fixture half of `apply-refuses`, run before any metadata reaches
    /// the adapter. It makes a diff that adds [`Repository::missing`] and,
    /// with `retarget`, one diff per metadata path that adds the file
    /// there; it returns those. Each must first prove itself: moved back
    /// from its metadata path to a twin content path (`<missing>.twin`,
    /// absent at the base), it applies and reads back the fixture's
    /// content. Otherwise it is a fixture violation, because a `retarget`
    /// that makes garbage, ignores its target or breaks only diffs pointed
    /// at metadata would make every refusal a parse error and let every
    /// adapter pass (review rounds 1 and 2 of #61). The round trip also
    /// covers a plain move to content, so no separate proof is needed.
    ///
    /// A `retarget` that breaks a diff on the way to a metadata path and
    /// repairs it on the way back is out of reach of any such proof; it
    /// would have to recognize metadata paths and undo its own damage.
    fn metadata_diffs<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        retarget: &impl Fn(&[u8], &RelativePath, &RelativePath) -> Vec<u8>,
        base: &CheckoutId,
        snapshot: &[u8],
    ) -> Result<Vec<(RelativePath, Vec<u8>)>, Violation> {
        let added = edit(snapshot, &tree(&r.missing), Some(&r.edited));
        let d_add = call(METADATA, "diff", r.adapter.diff(base, &added))?;
        let twin_name = format!("{}.twin", r.missing.as_str());
        let twin = RelativePath::parse(&twin_name).map_err(|problem| {
            metadata_fixture(format!(
                "the twin path {twin_name:?} is invalid: {problem:?}"
            ))
        })?;
        if call(METADATA, "read", r.adapter.read(base, &twin))?.is_some() {
            return Err(metadata_fixture(format!(
                "the base has a file at the twin path {twin_name:?}, so a retargeted diff \
                 cannot be shown to add it"
            )));
        }
        let mut diffs = Vec::new();
        for (path, _) in &r.metadata {
            let to_metadata = retarget(&d_add, &r.missing, path);
            let back = retarget(&to_metadata, path, &twin);
            adds_twin(r, base, &back, &twin).map_err(|got| {
                metadata_fixture(format!(
                    "the retarget hook moved a diff that adds {:?} to {:?} and back to \
                     {twin_name:?}, and applying that gave {got}, expected a file there with \
                     the fixture's content ({} bytes); the diff pointed at the metadata path \
                     is not shown to be well formed, so its refusal would prove nothing",
                    r.missing.as_str(),
                    path.as_str(),
                    r.edited.len()
                ))
            })?;
            diffs.push((path.clone(), to_metadata));
        }
        Ok(diffs)
    }

    /// Every metadata entry reaches the workspace: leaving it out of the
    /// full set changes `hostile`. An `edit` that skips an entry, or drops
    /// it once another is there (the nested `.git` after the top-level
    /// one, say), would otherwise let an adapter that mishandles only that
    /// entry pass (review round 2 of #61). This also covers an `edit` that
    /// writes no metadata at all. Pure: the adapter sees none of it.
    fn every_entry_reaches_the_workspace(
        r_metadata: &[(RelativePath, Vec<u8>)],
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        plain: &[u8],
        hostile: &[u8],
    ) -> Result<(), Violation> {
        for (k, (path, _)) in r_metadata.iter().enumerate() {
            let without = r_metadata
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != k)
                .fold(plain.to_vec(), |workspace, (_, (other, content))| {
                    edit(&workspace, &tree(other), Some(content))
                });
            if without == hostile {
                return Err(metadata_fixture(format!(
                    "the workspace with every metadata entry equals the one without {:?}, so \
                     the edit hook dropped it and the adapter never sees it",
                    path.as_str()
                )));
            }
        }
        Ok(())
    }

    /// The workspace comes from the sandbox, where the agent writes, and
    /// the adapter diffs it on the host as the runner user (#30). Its
    /// repository metadata (`.git`, also nested) is not content and never
    /// steers the adapter's git (ADR-010, D1):
    ///
    /// - `nothing-ran`: nothing it asks for runs, checked after every
    ///   later step too;
    /// - `same-diff`: the diff is the one without it;
    /// - `same-checkout`: later diffs of the checkout that saw it are as
    ///   before, the edited one and the unchanged one, so an adapter that
    ///   adopted the config into that checkout's store is caught, also
    ///   when the config changes only non-empty diffs;
    /// - `fresh-checkout`: the same for a checkout fetched afterwards, so
    ///   adoption into what new checkouts start from is caught;
    /// - `same-apply`: applying the plain diff to either checkout gives
    ///   the snapshot it gave before the metadata was seen;
    /// - `apply-refuses`: a diff that writes a metadata path, made by
    ///   moving a diff that adds a file there with the adapter's own
    ///   `retarget` and shown to apply once moved back to content, does
    ///   not apply, and the checkout stays as it was.
    ///
    /// Everything compared later is taken before the hostile diff, so an
    /// adapter that adopts the metadata cannot pass by spoiling both sides.
    /// Details quote lengths, not bytes (ADR-004, D10).
    fn workspace_metadata_inert<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        retarget: &impl Fn(&[u8], &RelativePath, &RelativePath) -> Vec<u8>,
        tripwire: &impl Tripwire<G>,
    ) -> Result<(), Violation> {
        if r.metadata.is_empty() {
            return Err(metadata_fixture(String::from(
                "no repository metadata, so the clause cannot tell an adapter that obeys it \
                 from one that ignores it",
            )));
        }
        if let Some((path, _)) = r.metadata.iter().find(|(p, _)| !p.is_repository_metadata()) {
            return Err(metadata_fixture(format!(
                "{:?} is not repository metadata, so an adapter that diffs metadata as \
                 content could pass on it",
                path.as_str()
            )));
        }
        let before = tripped(r, tripwire, "fixture")?;
        if !before.is_empty() {
            return Err(metadata_fixture(format!(
                "the tripwire reports {} runs before the clause ran anything, so it cannot \
                 tell what the clause caused: {before:?}",
                before.len()
            )));
        }
        let base = checkout(r, METADATA)?;
        let snapshot = call(METADATA, "snapshot", r.adapter.snapshot(&base))?;
        let plain = edit(&snapshot, &tree(&r.path), Some(&r.edited));
        let hostile = r
            .metadata
            .iter()
            .fold(plain.clone(), |workspace, (path, content)| {
                edit(&workspace, &tree(path), Some(content))
            });
        every_entry_reaches_the_workspace(&r.metadata, edit, &plain, &hostile)?;
        // Taken before any metadata reaches the adapter.
        let d_plain = call(METADATA, "diff", r.adapter.diff(&base, &plain))?;
        let reference = applied_snapshot(r, &base, &d_plain)?;
        let metadata_diffs = metadata_diffs(r, edit, retarget, &base, &snapshot)?;

        let d_hostile = call(METADATA, "diff", r.adapter.diff(&base, &hostile))?;
        nothing_ran(r, tripwire, "the diff of a workspace with metadata")?;
        ensure(d_hostile == d_plain, PORT, METADATA, || {
            format!(
                "same-diff: with {} metadata entries planted the diff has {} bytes, without \
                 them {} bytes; expected the same diff",
                r.metadata.len(),
                d_hostile.len(),
                d_plain.len()
            )
        })?;

        diffs_as_before(
            r,
            edit,
            &base,
            &d_plain,
            "same-checkout",
            "the same checkout",
        )?;
        nothing_ran(r, tripwire, "later diffs of the same checkout")?;

        let fresh = checkout(r, METADATA)?;
        diffs_as_before(
            r,
            edit,
            &fresh,
            &d_plain,
            "fresh-checkout",
            "a fresh checkout",
        )?;
        nothing_ran(r, tripwire, "diffs of a fresh checkout")?;

        for (which, from) in [("the same checkout", &base), ("a fresh checkout", &fresh)] {
            let got = applied_snapshot(r, from, &d_plain)?;
            ensure(got == reference, PORT, METADATA, || {
                format!(
                    "same-apply: applying the plain diff to {which} gives a snapshot of {} \
                     bytes that differs from the one it gave before the metadata was seen \
                     ({} bytes)",
                    got.len(),
                    reference.len()
                )
            })?;
        }
        nothing_ran(r, tripwire, "the applies")?;

        for (path, hostile_diff) in &metadata_diffs {
            let got = r.adapter.apply(&base, hostile_diff);
            ensure(got.is_err(), PORT, METADATA, || {
                format!(
                    "apply-refuses: a diff that writes {:?} applied to {base:?} as {got:?}, \
                     expected an error",
                    path.as_str()
                )
            })?;
        }
        let after = call(METADATA, "snapshot", r.adapter.snapshot(&base))?;
        ensure(after == snapshot, PORT, METADATA, || {
            format!("apply-refuses: {base:?} changed when diffs that write metadata were refused")
        })?;
        nothing_ran(r, tripwire, "the refused applies")
    }

    /// The clause's own branch, `boneli/contract-<clause>`.
    fn contract_branch(clause: &'static str) -> Result<BranchName, Violation> {
        let name = format!("boneli/contract-{clause}");
        BranchName::parse(&name).ok_or_else(|| {
            violation(
                PORT,
                clause,
                format!("suite fixture rejected: {name:?} is not a branch name"),
            )
        })
    }

    /// The clause's commit identity and message.
    fn contract_commit(clause: &'static str) -> Result<CommitInfo, Violation> {
        let message = format!("contract: {clause}\n");
        CommitInfo::new("Boneli contract", "contract@example.invalid", &message).ok_or_else(|| {
            violation(
                PORT,
                clause,
                String::from("suite fixture rejected: the commit identity"),
            )
        })
    }

    /// What `remote` reports for the clause's branch; an error is the
    /// clause's detail, so a remote hook that cannot look never passes.
    fn remote_branch<G: Git>(
        r: &Repository<G>,
        remote: &impl Remote<G>,
        clause: &'static str,
        branch: &BranchName,
    ) -> Result<Option<(CommitSha, Vec<CommitSha>)>, Violation> {
        remote
            .branch(&r.adapter, &r.repo, branch)
            .map_err(|error| violation(PORT, clause, format!("the remote hook failed: {error}")))
    }

    /// The clause's branch, checked absent on the remote before anything is
    /// pushed: a branch left over from another run would let a push that
    /// never happened read back.
    fn absent_branch<G: Git>(
        r: &Repository<G>,
        remote: &impl Remote<G>,
        clause: &'static str,
    ) -> Result<BranchName, Violation> {
        let branch = contract_branch(clause)?;
        let before = remote_branch(r, remote, clause, &branch)?;
        ensure(before.is_none(), PORT, clause, || {
            format!(
                "fixture: {:?} exists on the remote before the clause pushed it: {before:?}",
                branch.as_str()
            )
        })?;
        Ok(branch)
    }

    /// Fetches the base, edits the path, applies the diff and pushes the
    /// result to the clause's branch; returns the base checkout, the
    /// applied one, the branch and the pushed commit.
    fn pushed<G: Git>(
        r: &Repository<G>,
        clause: &'static str,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        remote: &impl Remote<G>,
    ) -> Result<(CheckoutId, CheckoutId, BranchName, CommitSha), Violation> {
        let branch = absent_branch(r, remote, clause)?;
        let commit = contract_commit(clause)?;
        let (base, after) = applied(r, clause, edit)?;
        let sha = call(clause, "push", r.adapter.push(&after, &branch, &commit))?;
        Ok((base, after, branch, sha))
    }

    /// A pushed commit is the branch's tip on the remote, and checked out
    /// again it holds the applied tree, not the base's: the pull request
    /// shows the verified fix.
    fn push_reads_back<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        remote: &impl Remote<G>,
    ) -> Result<(), Violation> {
        let clause = "push-reads-back";
        let (_, _, branch, sha) = pushed(r, clause, edit, remote)?;
        let tip = remote_branch(r, remote, clause, &branch)?;
        ensure(
            tip.as_ref().map(|(tip, _)| tip) == Some(&sha),
            PORT,
            clause,
            || {
                format!(
                    "push returned {sha:?}, and the remote's {:?} is {tip:?}",
                    branch.as_str()
                )
            },
        )?;
        let fetched = call(clause, "fetch_base", r.adapter.fetch_base(&r.repo, &sha))?;
        expect_read(r, clause, &fetched, &r.path, Some(&r.edited))
    }

    /// The pushed commit's only parent is the base commit, so the pull
    /// request shows the fix and nothing else.
    fn push_parent_is_base<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        remote: &impl Remote<G>,
    ) -> Result<(), Violation> {
        let clause = "push-parent-is-base";
        let (_, _, branch, sha) = pushed(r, clause, edit, remote)?;
        let tip = remote_branch(r, remote, clause, &branch)?;
        let want = Some((sha, vec![r.base.clone()]));
        ensure(tip == want, PORT, clause, || {
            format!(
                "the remote's {:?} is {tip:?}, expected the pushed commit with the base as its \
                 only parent: {want:?}",
                branch.as_str()
            )
        })
    }

    /// A push to a branch that exists is `BranchExists`, and the branch
    /// keeps its tip: a run never moves a branch, its own earlier one
    /// included (ADR-014, D2).
    fn push_never_overwrites<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        remote: &impl Remote<G>,
    ) -> Result<(), Violation> {
        let clause = "push-never-overwrites";
        let (base, _, branch, first) = pushed(r, clause, edit, remote)?;
        let commit = contract_commit(clause)?;
        let again = r.adapter.push(&base, &branch, &commit);
        ensure(again == Err(GitError::BranchExists), PORT, clause, || {
            format!(
                "a second push to {:?}, which the first push created, gave {again:?}, expected \
                 BranchExists",
                branch.as_str()
            )
        })?;
        let tip = remote_branch(r, remote, clause, &branch)?;
        ensure(
            tip.as_ref().map(|(tip, _)| tip) == Some(&first),
            PORT,
            clause,
            || {
                format!(
                    "after the refused push the remote's {:?} is {tip:?}, expected its first tip \
                     {first:?}",
                    branch.as_str()
                )
            },
        )
    }

    /// A push from a checkout the adapter never issued is
    /// `UnknownCheckout`, and creates no branch.
    fn push_unknown_checkout<G: Git>(
        r: &Repository<G>,
        remote: &impl Remote<G>,
    ) -> Result<(), Violation> {
        let clause = "push-unknown-checkout";
        let branch = absent_branch(r, remote, clause)?;
        let commit = contract_commit(clause)?;
        let issued = checkout(r, clause)?;
        let unknown = CheckoutId::new(format!("{}-unknown", issued.as_str()));
        let got = r.adapter.push(&unknown, &branch, &commit);
        ensure(got == Err(GitError::UnknownCheckout), PORT, clause, || {
            format!("push from {unknown:?}, which was never issued, gave {got:?}")
        })?;
        let after = remote_branch(r, remote, clause, &branch)?;
        ensure(after.is_none(), PORT, clause, || {
            format!(
                "a refused push created {:?} on the remote: {after:?}",
                branch.as_str()
            )
        })
    }

    fn unchanged_snapshot_empty_diff<G: Git>(r: &Repository<G>) -> Result<(), Violation> {
        let clause = "unchanged-snapshot-empty-diff";
        let base = checkout(r, clause)?;
        let snapshot = call(clause, "snapshot", r.adapter.snapshot(&base))?;
        let diff = call(clause, "diff", r.adapter.diff(&base, &snapshot))?;
        ensure(diff.is_empty(), PORT, clause, || {
            format!(
                "the diff of an unchanged snapshot has {} bytes, expected none",
                diff.len()
            )
        })
    }
    const UNCITABLE: &str = "uncitable-paths-carried";

    /// A fixture that would make `uncitable-paths-carried` vacuous.
    fn uncitable_fixture(detail: String) -> Violation {
        violation(PORT, UNCITABLE, format!("fixture: {detail}"))
    }

    /// Content that differs from `content`: it with `+` appended.
    fn altered(content: &[u8]) -> Vec<u8> {
        let mut other = content.to_vec();
        other.push(b'+');
        other
    }

    /// The class of an uncitable path, for the fixture guards; `None` for
    /// a citable one.
    fn class(path: &TreePath) -> Option<Uncitable> {
        path.citable().err()
    }

    /// The twin of an uncitable path: its last component with U+200B
    /// appended. That keeps its class (a byte string that is not UTF-8
    /// stays so, a backslash stays, and U+200B is blank), and it is a
    /// path the base must not have.
    fn twin(k: usize, path: &TreePath) -> Result<TreePath, Violation> {
        let mut bytes = path.as_bytes().to_vec();
        bytes.extend_from_slice("\u{200B}".as_bytes());
        TreePath::parse(&bytes).map_err(|problem| {
            uncitable_fixture(format!(
                "the twin of path {k} is not a tree path: {problem:?}"
            ))
        })
    }

    /// The list guards, each a `fixture:` violation, checked before the
    /// adapter is called: the list holds one path of each class and no
    /// citable or metadata path.
    fn uncitable_list<G>(r: &Repository<G>) -> Result<(), Violation> {
        if r.uncitable.is_empty() {
            return Err(uncitable_fixture(String::from(
                "no uncitable paths, so the clause cannot tell an adapter that carries them from \
                 one that drops them",
            )));
        }
        for (k, (path, _)) in r.uncitable.iter().enumerate() {
            if class(path).is_none() {
                return Err(uncitable_fixture(format!(
                    "path {k} is citable, so it proves nothing about the paths an agent cannot cite"
                )));
            }
            if path.is_repository_metadata() {
                return Err(uncitable_fixture(format!(
                    "path {k} is repository metadata, which a diff drops"
                )));
            }
        }
        let wanted = [
            ("not UTF-8", Uncitable::NotUtf8),
            (
                "a backslash",
                Uncitable::Citation(CitationProblem::Backslash),
            ),
            ("blank", Uncitable::Citation(CitationProblem::BlankPath)),
        ];
        for (name, want) in wanted {
            if !r.uncitable.iter().any(|(p, _)| class(p) == Some(want)) {
                return Err(uncitable_fixture(format!(
                    "no path is {name}, so that class is not covered"
                )));
            }
        }
        Ok(())
    }

    /// The `edit` guards, each a `fixture:` violation: `edit` really
    /// writes, removes and adds each path, and the base has no file at a
    /// twin. `full` is the base snapshot with every listed file written by
    /// `edit`, so the guards hold for an adapter whose snapshot leaves the
    /// paths out too, and that adapter is caught by `snapshot-carries`
    /// instead. Returns the twins.
    fn uncitable_edits<G>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        snapshot: &[u8],
    ) -> Result<Vec<TreePath>, Violation> {
        let full = r
            .uncitable
            .iter()
            .fold(snapshot.to_vec(), |workspace, (path, content)| {
                edit(&workspace, path, Some(content))
            });
        let mut twins = Vec::new();
        for (k, (path, content)) in r.uncitable.iter().enumerate() {
            let other = altered(content);
            if edit(&full, path, Some(&other)) == full {
                return Err(uncitable_fixture(format!(
                    "the edit hook does not write path {k}, so the adapter never sees a change \
                     there"
                )));
            }
            if edit(&full, path, None) == full {
                return Err(uncitable_fixture(format!(
                    "the edit hook does not remove path {k}, so the adapter never sees a removal \
                     there"
                )));
            }
            let twin = twin(k, path)?;
            if class(&twin) != class(path) {
                return Err(uncitable_fixture(format!(
                    "the twin of path {k} has another class than the path"
                )));
            }
            if edit(snapshot, &twin, None) != snapshot {
                return Err(uncitable_fixture(format!(
                    "the base snapshot has a file at the twin of path {k}, so adding it proves \
                     nothing"
                )));
            }
            if edit(snapshot, &twin, Some(content)) == snapshot {
                return Err(uncitable_fixture(format!(
                    "the edit hook does not add the twin of path {k}"
                )));
            }
            twins.push(twin);
        }
        Ok(twins)
    }

    /// `sub`: `workspace`, diffed against the base and applied to it,
    /// gives a checkout whose snapshot is `workspace`.
    fn round_trip<G: Git>(
        r: &Repository<G>,
        base: &CheckoutId,
        workspace: &[u8],
        sub: &str,
        what: &str,
    ) -> Result<(), Violation> {
        let diff = call(UNCITABLE, "diff", r.adapter.diff(base, workspace))?;
        let after = call(UNCITABLE, "apply", r.adapter.apply(base, &diff))?;
        let got = call(UNCITABLE, "snapshot", r.adapter.snapshot(&after))?;
        ensure(got == workspace, PORT, UNCITABLE, || {
            format!(
                "{sub}: {what}, diffed ({} bytes) and applied, gives a snapshot of {} bytes \
                 that differs from the workspace ({} bytes)",
                diff.len(),
                got.len(),
                workspace.len()
            )
        })
    }

    /// A repository may hold files whose paths an agent cannot cite (a
    /// backslash, a blank name, a name that is not UTF-8), and the replica
    /// must hold them too (ADR-018, D4 and D6):
    ///
    /// - `snapshot-carries`: the base snapshot holds every such file with
    ///   its base content;
    /// - `edit-round-trip`: each, changed, diffs and applies to a checkout
    ///   whose snapshot is the edited workspace;
    /// - `remove-round-trip`: the same with the file removed;
    /// - `add-round-trip`: the same with a new file at its twin, a path of
    ///   the same class the base does not have.
    ///
    /// Fixture guards come first (`uncitable_list`, `uncitable_edits`).
    /// Details quote
    /// indexes and lengths, never path bytes (ADR-004, D10).
    fn uncitable_paths_carried<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        uncitable_list(r)?;
        let base = checkout(r, UNCITABLE)?;
        let snapshot = call(UNCITABLE, "snapshot", r.adapter.snapshot(&base))?;
        let twins = uncitable_edits(r, edit, &snapshot)?;
        for (k, (path, content)) in r.uncitable.iter().enumerate() {
            ensure(
                edit(&snapshot, path, Some(content)) == snapshot,
                PORT,
                UNCITABLE,
                || {
                    format!(
                        "snapshot-carries: the base snapshot does not hold path {k} with its \
                         base content ({} bytes)",
                        content.len()
                    )
                },
            )?;
        }
        for (k, (path, content)) in r.uncitable.iter().enumerate() {
            let other = altered(content);
            let workspace = edit(&snapshot, path, Some(&other));
            let what = format!("the base with path {k} changed");
            round_trip(r, &base, &workspace, "edit-round-trip", &what)?;
        }
        for (k, (path, _)) in r.uncitable.iter().enumerate() {
            let workspace = edit(&snapshot, path, None);
            let what = format!("the base without path {k}");
            round_trip(r, &base, &workspace, "remove-round-trip", &what)?;
        }
        for (k, ((_, content), twin)) in r.uncitable.iter().zip(&twins).enumerate() {
            let workspace = edit(&snapshot, twin, Some(content));
            let what = format!("the base with the twin of path {k} added");
            round_trip(r, &base, &workspace, "add-round-trip", &what)?;
        }
        Ok(())
    }

    /// What `patch_between` gave, for a detail: the number of changes and
    /// their sides as kind and length, never paths or bytes (ADR-004, D10).
    fn shape(got: &Result<Result<Patch, UnreadablePath>, GitError>) -> String {
        let side = |e: &Option<Entry>| e.as_ref().map(|e| (e.kind, e.data.len()));
        match got {
            Ok(Ok(patch)) => {
                let sides: Vec<_> = patch
                    .changes
                    .iter()
                    .map(|c| (side(&c.before), side(&c.after)))
                    .collect();
                format!(
                    "a patch of {} changes with sides {sides:?} and {} base links",
                    patch.changes.len(),
                    patch.base_links.len()
                )
            }
            Ok(Err(unreadable)) => format!("{unreadable:?}"),
            Err(error) => format!("{error:?}"),
        }
    }

    /// Whether `entry` is a regular file, executable or not, with `data`.
    fn regular(entry: &Entry, data: &[u8]) -> bool {
        matches!(entry.kind, EntryKind::File | EntryKind::Executable) && entry.data == data
    }

    /// Equal trees have no changes: a checkout against itself, and the
    /// base against a second fetch of it, which a real adapter may hold in
    /// another store (ADR-023, D4). A change with equal sides would be
    /// refused by the policy as malformed, so an adapter that reports one
    /// fails every fix.
    fn patch_unchanged_empty<G: Git>(r: &Repository<G>) -> Result<(), Violation> {
        let clause = "patch-unchanged-empty";
        let base = checkout(r, clause)?;
        let again = checkout(r, clause)?;
        for (which, after) in [("itself", &base), ("a second fetch of the base", &again)] {
            let got = r.adapter.patch_between(&base, after);
            ensure(
                matches!(&got, Ok(Ok(patch)) if patch.changes.is_empty()),
                PORT,
                clause,
                || {
                    format!(
                        "the patch from the base to {which} is {}, expected no changes",
                        shape(&got)
                    )
                },
            )?;
        }
        Ok(())
    }

    /// An edit is one change with both full sides: the base content
    /// before, the edited content after, the same regular kind. The policy
    /// counts the base's test declarations from the before side (ADR-013,
    /// D7), so an adapter that reports every edit as an add hides a removed
    /// test. The base links do not depend on the after tree.
    fn patch_full_sides<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "patch-full-sides";
        let (base, after) = applied(r, clause, edit)?;
        let got = r.adapter.patch_between(&base, &after);
        let ok = match &got {
            Ok(Ok(patch)) => match patch.changes.as_slice() {
                [
                    Change {
                        path,
                        before: Some(before),
                        after: Some(now),
                    },
                ] => {
                    path == r.path.as_str()
                        && regular(before, &r.content)
                        && now.kind == before.kind
                        && now.data == r.edited
                }
                _ => false,
            },
            _ => false,
        };
        ensure(ok, PORT, clause, || {
            format!(
                "after an edit of the fixture's file the patch is {}, expected one change at \
                 that path from the base content ({} bytes) to the edited content ({} bytes), \
                 of the same regular kind",
                shape(&got),
                r.content.len(),
                r.edited.len()
            )
        })?;
        let links = |got: &Result<Result<Patch, UnreadablePath>, GitError>| match got {
            Ok(Ok(patch)) => Some(patch.base_links.clone()),
            _ => None,
        };
        let unchanged = r.adapter.patch_between(&base, &base);
        ensure(links(&got) == links(&unchanged), PORT, clause, || {
            format!(
                "the patch of the edit is {} and the unchanged patch is {}, expected the same \
                 base links",
                shape(&got),
                shape(&unchanged)
            )
        })
    }

    /// One workspace adds [`Repository::missing`] and removes
    /// [`Repository::path`]: exactly those two changes, in byte order, with
    /// `None` on the absent sides. The policy refuses a deleted test file
    /// (ADR-013, D7), so a removal must not be left out.
    fn patch_added_removed<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let clause = "patch-added-removed";
        let (base, after) = changed(r, clause, |snapshot| {
            let added = edit(snapshot, &tree(&r.missing), Some(&r.edited));
            edit(&added, &tree(&r.path), None)
        })?;
        let got = r.adapter.patch_between(&base, &after);
        let mut want = [(r.path.as_str(), false), (r.missing.as_str(), true)];
        want.sort();
        let ok = match &got {
            Ok(Ok(patch)) => {
                patch.changes.len() == want.len()
                    && patch.changes.iter().zip(want).all(|(c, (path, added))| {
                        let (absent, present, data) = if added {
                            (&c.before, &c.after, &r.edited)
                        } else {
                            (&c.after, &c.before, &r.content)
                        };
                        c.path == path
                            && absent.is_none()
                            && present.as_ref().is_some_and(|e| regular(e, data))
                    })
            }
            _ => false,
        };
        ensure(ok, PORT, clause, || {
            format!(
                "after adding a file and removing another the patch is {}, expected two \
                 changes in byte order: the added file ({} bytes) with no before side and the \
                 removed one ({} bytes) with no after side",
                shape(&got),
                r.edited.len(),
                r.content.len()
            )
        })
    }

    /// A handle the adapter never issued, on either side, is
    /// `UnknownCheckout`: an empty patch would read as an empty fix, and a
    /// patch of the other tree alone as a fix of everything.
    fn patch_unknown_checkout<G: Git>(r: &Repository<G>) -> Result<(), Violation> {
        let clause = "patch-unknown-checkout";
        let issued = checkout(r, clause)?;
        let unknown = CheckoutId::new(format!("{}-unknown", issued.as_str()));
        for (which, base, after) in [("base", &unknown, &issued), ("after", &issued, &unknown)] {
            let got = r.adapter.patch_between(base, after);
            ensure(
                matches!(got, Err(GitError::UnknownCheckout)),
                PORT,
                clause,
                || {
                    format!(
                        "patch_between with a {which} handle that was never issued gave {}, \
                         expected UnknownCheckout",
                        shape(&got)
                    )
                },
            )?;
        }
        Ok(())
    }

    const PATCH_UNCITABLE: &str = "patch-uncitable-paths";

    /// The patch of an edit of uncitable path `k`.
    fn uncitable_patch<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
        base: &CheckoutId,
        snapshot: &[u8],
        k: usize,
    ) -> Result<Result<Result<Patch, UnreadablePath>, GitError>, Violation> {
        let (path, content) = &r.uncitable[k];
        let workspace = edit(snapshot, path, Some(&altered(content)));
        let diff = call(PATCH_UNCITABLE, "diff", r.adapter.diff(base, &workspace))?;
        let after = call(PATCH_UNCITABLE, "apply", r.adapter.apply(base, &diff))?;
        Ok(r.adapter.patch_between(base, &after))
    }

    /// Paths an agent cannot cite reach the policy as they are (ADR-018,
    /// D5; ADR-023, D6):
    ///
    /// - `uncitable-carried`: an edit of each UTF-8 one (a backslash, a
    ///   blank name) is one change whose path is that text as written, so
    ///   the policy refuses it as malformed;
    /// - `unreadable-refused`: an edit of each one that is not UTF-8 is
    ///   `UnreadablePath::Change { index: 0 }`, never a path rendered
    ///   through U+FFFD that the policy would accept.
    ///
    /// The fixture must hold a backslash path and one that is not UTF-8.
    /// Details quote indexes and lengths, never path bytes (ADR-004, D10).
    fn patch_uncitable_paths<G: Git>(
        r: &Repository<G>,
        edit: &impl Fn(&[u8], &TreePath, Option<&[u8]>) -> Vec<u8>,
    ) -> Result<(), Violation> {
        let wanted = [
            (
                "a backslash",
                Uncitable::Citation(CitationProblem::Backslash),
            ),
            ("not UTF-8", Uncitable::NotUtf8),
        ];
        for (name, want) in wanted {
            if !r.uncitable.iter().any(|(p, _)| class(p) == Some(want)) {
                return Err(violation(
                    PORT,
                    PATCH_UNCITABLE,
                    format!("fixture: no uncitable path is {name}, so that case is not covered"),
                ));
            }
        }
        let base = checkout(r, PATCH_UNCITABLE)?;
        let snapshot = call(PATCH_UNCITABLE, "snapshot", r.adapter.snapshot(&base))?;
        let text = |k: usize| core::str::from_utf8(r.uncitable[k].0.as_bytes()).ok();
        for k in (0..r.uncitable.len()).filter(|k| text(*k).is_some()) {
            let got = uncitable_patch(r, edit, &base, &snapshot, k)?;
            let (_, content) = &r.uncitable[k];
            let ok = match (&got, text(k)) {
                (Ok(Ok(patch)), Some(want)) => match patch.changes.as_slice() {
                    [
                        Change {
                            path,
                            before: Some(before),
                            after: Some(now),
                        },
                    ] => {
                        path == want && regular(before, content) && regular(now, &altered(content))
                    }
                    _ => false,
                },
                _ => false,
            };
            ensure(ok, PORT, PATCH_UNCITABLE, || {
                format!(
                    "uncitable-carried: an edit of path {k} gives {}, expected one change at that \
                     path as written",
                    shape(&got)
                )
            })?;
        }
        for k in (0..r.uncitable.len()).filter(|k| text(*k).is_none()) {
            let got = uncitable_patch(r, edit, &base, &snapshot, k)?;
            ensure(
                matches!(got, Ok(Err(UnreadablePath::Change { index: 0 }))),
                PORT,
                PATCH_UNCITABLE,
                || {
                    format!(
                        "unreadable-refused: an edit of path {k}, which is not UTF-8, gives {}, \
                         expected Change {{ index: 0 }}",
                        shape(&got)
                    )
                },
            )?;
        }
        Ok(())
    }
}

/// The `ImageStore` suite.
pub mod image {
    use super::*;
    use crate::image::{ImageError, ImageOrigin, ImageRef, ImageStore};

    const PORT: &str = "ImageStore";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &[
        "pull-idempotent",
        "missing-image",
        "digest-pinned",
        "platform-pinned",
        "tampered-refused",
        "agent-origin-refused",
        "exemption-reported",
    ];

    /// The two pulls `tampered-refused` checks, each its own sub-check
    /// with its own mutant (ADR-004, D2): a store that accepts tampered
    /// bytes at once fails the first, one that keeps them after a refused
    /// pull fails the second.
    pub const TAMPERED_PULLS: &[&str] = &["first-pull", "second-pull"];

    /// The two pulls `exemption-reported` checks, each its own sub-check
    /// with its own mutant (ADR-032): a store that drops the exemption
    /// fails the first, one that reports an exemption for a reference the
    /// operator chose fails the second.
    pub const EXEMPTION_PULLS: &[&str] = &["agent-pull", "operator-pull"];

    /// An adapter and the images its own test knows.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Images<I> {
        /// The adapter.
        pub adapter: I,
        /// An image the registry has.
        pub present: ImageRef,
        /// An image the registry does not have.
        pub missing: ImageRef,
        /// [`Images::present`] with a digest the registry does not have.
        pub other_digest: ImageRef,
        /// [`Images::present`] with a platform its index does not list.
        pub other_platform: ImageRef,
        /// An image the registry serves with bytes that do not match their
        /// digest (#7, ADR-009).
        pub tampered: ImageRef,
        /// An image the registry has, chosen by the agent, that the
        /// adapter's policy does not admit for the agent; the same
        /// reference chosen by the operator pulls (ADR-032).
        pub agent_refused: ImageRef,
        /// An image the registry has, chosen by the agent, that an
        /// operator exemption admits (ADR-032).
        pub agent_exempted: ImageRef,
    }

    /// Checks every clause; each clause gets a fresh adapter from `make`.
    pub fn run<I: ImageStore>(make: impl Fn() -> Images<I>) -> Result<(), Violation> {
        pull_idempotent(&make())?;
        missing_image(&make())?;
        digest_pinned(&make())?;
        platform_pinned(&make())?;
        tampered_refused(&make())?;
        agent_origin_refused(&make())?;
        exemption_reported(&make())
    }

    /// `image` as the operator's reference, every other field kept.
    fn by_operator(image: &ImageRef) -> ImageRef {
        ImageRef {
            origin: ImageOrigin::Operator,
            ..image.clone()
        }
    }

    /// The fixture's agent reference must say `Agent`, or the clause
    /// would check an operator pull.
    fn agent_fixture(clause: &'static str, field: &str, image: &ImageRef) -> Result<(), Violation> {
        ensure(image.origin == ImageOrigin::Agent, PORT, clause, || {
            format!("fixture: {field} {image:?} must have the origin Agent")
        })
    }

    /// The origin is a port promise (ADR-032): an image the policy does
    /// not admit for the agent is `Failed`, with a detail, even though
    /// the same reference chosen by the operator pulls. The operator pull
    /// runs first, so an adapter that keyed its cache by name alone would
    /// hand the agent what the operator pulled.
    fn agent_origin_refused<I: ImageStore>(i: &Images<I>) -> Result<(), Violation> {
        let clause = "agent-origin-refused";
        agent_fixture(clause, "agent_refused", &i.agent_refused)?;
        let operator = by_operator(&i.agent_refused);
        i.adapter.pull(&operator).map_err(|error| {
            violation(
                PORT,
                clause,
                format!("fixture: the operator's pull of {operator:?} failed: {error:?}"),
            )
        })?;
        let got = i.adapter.pull(&i.agent_refused);
        let refused = matches!(&got, Err(ImageError::Failed { detail }) if !is_blank(detail));
        ensure(refused, PORT, clause, || {
            format!(
                "pull of {:?}, which the agent chose and no exemption admits, gave {got:?}, \
                 expected Failed with a detail",
                i.agent_refused
            )
        })
    }

    /// The exemption that admitted an agent's image comes back with the
    /// pull, both fields filled, so the caller can log it; the operator's
    /// pull of the same image right after reports none, because the
    /// exemption belongs to the pull, not to the image.
    fn exemption_reported<I: ImageStore>(i: &Images<I>) -> Result<(), Violation> {
        let clause = "exemption-reported";
        agent_fixture(clause, "agent_exempted", &i.agent_exempted)?;
        let [agent_pull, operator_pull] = EXEMPTION_PULLS else {
            return Err(violation(PORT, clause, String::from("two pulls")));
        };
        let got = i.adapter.pull(&i.agent_exempted);
        let reported = matches!(
            &got,
            Ok(p) if p.exemption.as_ref().is_some_and(|e| !is_blank(&e.registry) && !is_blank(&e.scope))
        );
        ensure(reported, PORT, clause, || {
            format!(
                "{agent_pull}: pull of {:?}, which an exemption admits, gave {got:?}, expected \
                 Ok with the exemption",
                i.agent_exempted
            )
        })?;
        let operator = by_operator(&i.agent_exempted);
        let got = i.adapter.pull(&operator);
        ensure(
            matches!(&got, Ok(p) if p.exemption.is_none()),
            PORT,
            clause,
            || {
                format!(
                    "{operator_pull}: pull of {operator:?}, which the operator chose, gave {got:?}, \
                 expected Ok with no exemption"
                )
            },
        )
    }

    /// Digest verification is the port's main security property: an image
    /// whose bytes do not match their digest fails, with a detail, on the
    /// first pull and again on the second, so a store that keeps what it
    /// fetched before checking it cannot hand it out later.
    fn tampered_refused<I: ImageStore>(i: &Images<I>) -> Result<(), Violation> {
        let clause = "tampered-refused";
        for &pull in TAMPERED_PULLS {
            let got = i.adapter.pull(&i.tampered);
            let refused = matches!(&got, Err(ImageError::Failed { detail }) if !is_blank(detail));
            ensure(refused, PORT, clause, || {
                format!(
                    "{pull}: pull of {:?}, whose bytes do not match its digest, gave {got:?}, \
                     expected Failed with a detail",
                    i.tampered
                )
            })?;
        }
        Ok(())
    }

    /// A pull of `variant`, which differs from the present image in one
    /// field only, is `NotFound`, even after the present image was pulled.
    fn pinned<I: ImageStore>(
        i: &Images<I>,
        clause: &'static str,
        variant: &ImageRef,
        same_but: bool,
        field: &str,
    ) -> Result<(), Violation> {
        if !same_but {
            return Err(violation(
                PORT,
                clause,
                format!(
                    "the fixture's {variant:?} must equal the present image in every field but \
                     the {field}"
                ),
            ));
        }
        i.adapter.pull(&i.present).map_err(|error| {
            violation(
                PORT,
                clause,
                format!("pull of {:?} failed: {error:?}", i.present),
            )
        })?;
        let got = i.adapter.pull(variant);
        ensure(got == Err(ImageError::NotFound), PORT, clause, || {
            format!(
                "pull of {variant:?}, which differs from a present image in its {field} only, \
                 gave {got:?}, expected NotFound"
            )
        })
    }

    /// The digest pins the content: a store that resolves by name alone
    /// would hand out whatever it pulled under that name.
    fn digest_pinned<I: ImageStore>(i: &Images<I>) -> Result<(), Violation> {
        let p = &i.present;
        let o = &i.other_digest;
        let same_but = o.name == p.name
            && o.platform == p.platform
            && o.origin == p.origin
            && o.digest != p.digest;
        pinned(i, "digest-pinned", o, same_but, "digest")
    }

    fn platform_pinned<I: ImageStore>(i: &Images<I>) -> Result<(), Violation> {
        let p = &i.present;
        let o = &i.other_platform;
        let same_but = o.name == p.name
            && o.digest == p.digest
            && o.origin == p.origin
            && o.platform != p.platform;
        pinned(i, "platform-pinned", o, same_but, "platform")
    }

    fn pull_idempotent<I: ImageStore>(i: &Images<I>) -> Result<(), Violation> {
        let clause = "pull-idempotent";
        let pull = || {
            i.adapter.pull(&i.present).map_err(|error| {
                violation(
                    PORT,
                    clause,
                    format!("pull of {:?} failed: {error:?}", i.present),
                )
            })
        };
        let first = pull()?;
        let second = pull()?;
        ensure(first == second, PORT, clause, || {
            format!("two pulls of the same image gave {first:?} and {second:?}")
        })
    }

    fn missing_image<I: ImageStore>(i: &Images<I>) -> Result<(), Violation> {
        let clause = "missing-image";
        let got = i.adapter.pull(&i.missing);
        ensure(got == Err(ImageError::NotFound), PORT, clause, || {
            format!(
                "pull of {:?}, which the registry does not have, gave {got:?}, expected NotFound",
                i.missing
            )
        })
    }
}

/// The `DataSnapshot` suite.
pub mod data {
    use super::*;
    use crate::data::{DataError, DataSnapshot, DatabaseCopy, SnapshotId, SnapshotSource};
    use crate::sandbox::SandboxId;

    const PORT: &str = "DataSnapshot";

    /// The clauses, in the order [`run`] checks them.
    pub const CLAUSES: &[&str] = &[
        "distinct-copies",
        "copies-independent",
        "removed-copy-unknown",
        "hostile-run-ids",
    ];

    /// An adapter and a source it can load into a sandbox, which only its
    /// own test knows.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Database<D> {
        /// The adapter.
        pub adapter: D,
        /// The sandbox whose pod runs the database.
        pub sandbox: SandboxId,
        /// A source the adapter can load.
        pub source: SnapshotSource,
    }

    /// How the suite changes the data in a copy and looks for the change;
    /// only the adapter's own test knows how (for Postgres, SQL through the
    /// sandbox). Errors are reported as the clause's detail.
    pub trait Probe<D> {
        /// Makes one change in the copy.
        fn change(&self, adapter: &D, copy: &DatabaseCopy) -> Result<(), String>;

        /// Whether the copy shows that change.
        fn changed(&self, adapter: &D, copy: &DatabaseCopy) -> Result<bool, String>;
    }

    /// Checks every clause; each clause gets a fresh adapter from `make`.
    pub fn run<D: DataSnapshot>(
        make: impl Fn() -> Database<D>,
        probe: &impl Probe<D>,
    ) -> Result<(), Violation> {
        distinct_copies(&make())?;
        copies_independent(&make(), probe)?;
        removed_copy_unknown(&make())?;
        hostile_run_ids(&make(), probe)
    }

    fn call<T>(
        clause: &'static str,
        what: &str,
        result: Result<T, DataError>,
    ) -> Result<T, Violation> {
        result.map_err(|error| violation(PORT, clause, format!("{what} failed: {error:?}")))
    }

    fn load<D: DataSnapshot>(
        d: &Database<D>,
        clause: &'static str,
    ) -> Result<SnapshotId, Violation> {
        call(clause, "load", d.adapter.load(&d.sandbox, &d.source))
    }

    fn copy<D: DataSnapshot>(
        d: &Database<D>,
        clause: &'static str,
        snapshot: &SnapshotId,
        run: &str,
    ) -> Result<DatabaseCopy, Violation> {
        let run = RunId::new(String::from(run));
        call(clause, "copy", d.adapter.copy(snapshot, &run))
    }

    fn distinct_copies<D: DataSnapshot>(d: &Database<D>) -> Result<(), Violation> {
        let clause = "distinct-copies";
        let snapshot = load(d, clause)?;
        let a = copy(d, clause, &snapshot, "contract-a")?;
        let b = copy(d, clause, &snapshot, "contract-b")?;
        ensure(a != b, PORT, clause, || {
            format!("two runs got the same copy {a:?}")
        })
    }

    /// #31's acceptance: a change in one copy is visible in neither another
    /// copy nor a copy made after it, so the snapshot did not change.
    fn copies_independent<D: DataSnapshot>(
        d: &Database<D>,
        probe: &impl Probe<D>,
    ) -> Result<(), Violation> {
        let clause = "copies-independent";
        let snapshot = load(d, clause)?;
        let a = copy(d, clause, &snapshot, "contract-a")?;
        let b = copy(d, clause, &snapshot, "contract-b")?;
        let probed = |result: Result<bool, String>, copy: &DatabaseCopy| {
            result.map_err(|error| {
                violation(PORT, clause, format!("probing {copy:?} failed: {error}"))
            })
        };
        let unchanged = |copy: &DatabaseCopy| -> Result<(), Violation> {
            let seen = probed(probe.changed(&d.adapter, copy), copy)?;
            ensure(!seen, PORT, clause, || {
                format!("{copy:?} shows a change made in {a:?}")
            })
        };
        unchanged(&a)?;
        probe
            .change(&d.adapter, &a)
            .map_err(|error| violation(PORT, clause, format!("changing {a:?} failed: {error}")))?;
        // Without this the probe could see nothing and every copy pass.
        let seen = probed(probe.changed(&d.adapter, &a), &a)?;
        ensure(seen, PORT, clause, || {
            format!("{a:?} does not show its own change")
        })?;
        unchanged(&b)?;
        let c = copy(d, clause, &snapshot, "contract-c")?;
        unchanged(&c)
    }

    /// Victims named after the last components of the hostile names, so an
    /// adapter that names a copy after the run's last path component hands
    /// `../x` the copy of run `x`.
    const VICTIMS: [&str; 4] = ["x", "a", "b", "abs"];

    /// The real adapter turns the run id into a database name (#31). Every
    /// hostile id of the `EventStore` clause is either refused with
    /// `InvalidRunId` or gets a copy of its own: a handle no other run has,
    /// whose change no victim shows.
    fn hostile_run_ids<D: DataSnapshot>(
        d: &Database<D>,
        probe: &impl Probe<D>,
    ) -> Result<(), Violation> {
        let clause = "hostile-run-ids";
        let snapshot = load(d, clause)?;
        let mut victims = Vec::new();
        for victim in VICTIMS {
            victims.push(copy(d, clause, &snapshot, victim)?);
        }
        let mut seen: Vec<DatabaseCopy> = victims.clone();
        for name in hostile_names() {
            let run = RunId::new(name.clone());
            match d.adapter.copy(&snapshot, &run) {
                Ok(hostile) => {
                    ensure(!seen.contains(&hostile), PORT, clause, || {
                        format!("run {name:?} got {hostile:?}, which another run already has")
                    })?;
                    probe.change(&d.adapter, &hostile).map_err(|error| {
                        violation(
                            PORT,
                            clause,
                            format!("changing {hostile:?} failed: {error}"),
                        )
                    })?;
                    seen.push(hostile);
                }
                Err(DataError::InvalidRunId) => {}
                Err(error) => {
                    return Err(violation(
                        PORT,
                        clause,
                        format!(
                            "copy for run {name:?} gave {error:?}, expected Ok or InvalidRunId"
                        ),
                    ));
                }
            }
        }
        // Checked after every write, so a later copy that lands on a victim
        // is caught.
        for victim in &victims {
            let shown = probe.changed(&d.adapter, victim).map_err(|error| {
                violation(PORT, clause, format!("probing {victim:?} failed: {error}"))
            })?;
            ensure(!shown, PORT, clause, || {
                format!("{victim:?} shows a change made in a copy for a hostile run id")
            })?;
        }
        Ok(())
    }

    fn removed_copy_unknown<D: DataSnapshot>(d: &Database<D>) -> Result<(), Violation> {
        let clause = "removed-copy-unknown";
        let snapshot = load(d, clause)?;
        let a = copy(d, clause, &snapshot, "contract-a")?;
        call(clause, "remove_copy", d.adapter.remove_copy(&a))?;
        let again = d.adapter.remove_copy(&a);
        ensure(again == Err(DataError::UnknownCopy), PORT, clause, || {
            format!("a second remove_copy of {a:?} gave {again:?}, expected UnknownCopy")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boneli_domain::EventKind;

    #[test]
    fn round_trip_covers_every_event_kind() {
        let base = CommitSha::parse(BASE).expect("the suite's base is valid");
        let events = event_store::every_event(&base).expect("the fixtures are valid");
        let kinds: BTreeSet<EventKind> = events.iter().map(|e| e.kind()).collect();
        let all: BTreeSet<EventKind> = EventKind::ALL.into_iter().collect();
        assert_eq!(kinds, all);
    }

    #[test]
    fn clause_names_are_unique_per_suite() {
        for clauses in [
            event_store::CLAUSES,
            evidence::CLAUSES,
            clock::CLAUSES,
            ids::CLAUSES,
            agent::CLAUSES,
            verifier::CLAUSES,
            forge::CLAUSES,
            sandbox::CLAUSES,
            git::CLAUSES,
            image::CLAUSES,
            data::CLAUSES,
        ] {
            let unique: BTreeSet<&str> = clauses.iter().copied().collect();
            assert_eq!(unique.len(), clauses.len(), "{clauses:?}");
        }
    }
}
