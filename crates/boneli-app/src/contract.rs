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

fn sample_ticket() -> Ticket {
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
    use boneli_domain::{RunEvent, TriageVerdict, Usage};

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

    /// One event of every kind, with the texts above, an empty `Vec`, zero
    /// and `u64::MAX` usage.
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

    fn sample_request(clause: &'static str) -> Result<PullRequest, Violation> {
        let attached = |reference: &str, content: &[u8]| {
            fixed(PORT, clause, EvidenceRef::parse(reference)).map(|reference| Attached {
                reference,
                content: content.to_vec(),
            })
        };
        Ok(PullRequest {
            run: RunId::new(String::from("contract-run")),
            ticket: sample_ticket(),
            base: sample_base(PORT, clause)?,
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
    /// output.
    pub fn run<F: Forge>(
        working: impl Fn() -> F,
        silent: impl Fn() -> SilentFailure<F>,
    ) -> Result<(), Violation> {
        let clause = "distinct-references";
        let forge = working();
        let ticket = sample_ticket();
        let questions = [String::from("Which version?")];
        let request = sample_request(clause)?;
        let mut references = Vec::new();
        for k in 0..4 {
            let result = if k % 2 == 0 {
                forge.post_questions(&ticket, &questions)
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
        let result = fixture.adapter.post_questions(&ticket, &questions);
        silent_detail(PORT, "post_questions", result, &fixture.status)?;
        let fixture = silent();
        let request = sample_request("silent-failure-detail")?;
        let result = fixture.adapter.open_pull_request(&request);
        silent_detail(PORT, "open_pull_request", result, &fixture.status)
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
        ] {
            let unique: BTreeSet<&str> = clauses.iter().copied().collect();
            assert_eq!(unique.len(), clauses.len(), "{clauses:?}");
        }
    }
}
