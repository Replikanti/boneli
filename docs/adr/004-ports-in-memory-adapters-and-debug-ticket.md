# ADR-004: Ports, in-memory adapters, contract suites and `DebugTicket`

- Status: accepted
- Date: 2026-11-13

## Context

`docs/ARCHITECTURE.md` ("Code architecture") names the ports of
`boneli-app` and requires that every port has an in-memory adapter and a
contract suite that real adapters reuse. It sketches `Sandbox` as a trait
with `&self` methods and says ports are synchronous. Issue #3 defines the
ports, their in-memory adapters and contract suites, and the `DebugTicket`
use case that drives `Run::handle` (ADR-002) through them. ADR-001 (D1)
makes a two-process replay of `DebugTicket` the gate for address leaks from
`boneli-app`, and ADR-002 left two requirements for #3: a run that ends
with triage questions is followed by a new run that gets those questions,
and a job adapter never sends a blank `JobFailed` detail.

Issue #3 is delivered in two pull requests. This ADR covers both; part 1
adds the seven ports `DebugTicket` drives (`Agent`, `Verifier`, `Forge`,
`EventStore`, `Evidence`, `Clock`, `Ids`), and part 2 adds `Sandbox`, `Git`,
`ImageStore` and `DataSnapshot`, which have no consumer in #3 (#7, #8, #12,
#17, #30 and #31 consume them). Part 1 is a vertical slice: `DebugTicket`
uses every port shape it adds, in the same pull request.

## Decision

### D1. Ports

Synchronous, object-safe traits with `&self` methods, one module per port
in `boneli-app`, no `Send + Sync` supertraits.

- **`&self`** follows ARCHITECTURE's `Sandbox` sketch. Shared real adapters
  (the file store, the sandbox runtime) then synchronize internally, so a
  root does not need one lock that serializes every run.
- **Object-safe**, because `DebugTicket` holds `&dyn Port`: roots pick
  adapters at run time (`Subscription` or `ApiKey`, ARCHITECTURE "LLM
  access"). Monomorphizing gains nothing measurable: a run makes at most 8
  port calls that do work (4 agent jobs, 3 verifier jobs and 1 forge call on
  the delivered path), next to model and sandbox time in seconds.
- **No supertraits**, because `DebugTicket` borrows its ports for one run. A
  root that shares adapters across threads holds `Arc<dyn Port + Send +
  Sync>`, and the bound belongs there. A supertrait would force every test
  double and mutant to be `Sync`, and nothing needs that yet (#33 adds
  threads).
- **Extension rule:** the issue that implements a port's real adapter may
  add operations and contract clauses in its own pull request without a new
  ADR. Removing or weakening a clause needs a new ADR. Why: until a real
  adapter exists, the shapes of the infra ports and of `Agent` and
  `Verifier` are minimal guesses, and adding a clause only makes the
  contract stricter.
- **Paths** that ports take (part 2) go through the citation path rule of
  ADR-002 (D2), through one shared function, so a sandbox or git path
  cannot leave the tree by a route the citation precheck rejects.
- `Clock::now_ms` returns milliseconds since an origin the adapter chooses
  and never decreases; `Ids::run_id` returns a run id that is not blank and
  never repeats. The type is not called `Instant`, which the core token scan
  bans (ADR-001).

### D2. Placement

- **`crates/boneli-memory` is one adapter crate** with the in-memory adapter
  of every port. It depends on the domain and the application only and
  keeps state behind `std::sync::Mutex`.
  - Why not one `boneli-<port>-memory` crate per port: there is no
    dependency, `unsafe` or I/O boundary between them for separate crates to
    protect, and every consumer needs several (the replay check uses seven,
    #32 wires the stores). Eleven crates would be eleven manifests and lib
    roots with no isolation gained. The name breaks the
    `boneli-<port>-<impl>` pattern; ARCHITECTURE says so, and
    `boneli-store-fs` already holds two ports.
  - Rejected: in-memory adapters inside `boneli-app` on `RefCell`. They
    would not need `std`, but the core would ship test doubles that are not
    `Sync`, so the roots of #32 and #33 could not share them across threads.
    ARCHITECTURE "Testing" also puts them in adapter crates.
- **No change to `tools/architecture.toml` or the checker.** A member in no
  role is an adapter, and adapters may depend only on the domain, the
  application and support crates; roots may depend on any member that is not
  a root. So `boneli-memory -> {domain, app}` and
  `boneli-replay-check -> boneli-memory` pass as they are, while the domain,
  the application, support crates and other adapters cannot depend on
  `boneli-memory` (ADR-002 D4: "in-memory adapter crates, which only roots
  may depend on"). Known gap, left as it is: the graph rules skip
  dev-dependencies. This pull request adds none, and real adapters need
  none, because they run the suites from `boneli-app`.
- **Contract suites live in `boneli_app::contract`**, `no_std` and generic
  over the port, as ARCHITECTURE "Testing" and ADR-001 allow. They ship in
  the library because core crates declare no features (ADR-001), the same
  trade-off ADR-002 D4 made for the domain's corpus. They cannot live in
  `boneli-memory`: adapters cannot depend on other adapters, so #4, #8 and
  the others could not reuse them.
- **A suite returns `Result<(), Violation>`** with
  `Violation { port, clause, detail }` and never panics: a public function
  of a production library should not panic on an adapter bug, and a
  returned clause lets a mutant test check which clause failed. Each suite
  exports `CLAUSES`, its clause names in check order, and `run`. A suite
  that needs a fresh adapter per clause takes a constructor, so one broken
  clause cannot leave state that fails a later one. The job-port suites also
  take adapter-supplied fixtures (an adapter set up to fail with no error
  output and the status it must then report; a verifier set up to answer
  given citations), because only the adapter's own test knows the inputs
  that make a real process or forge do that.
- **One mutant per clause.** `boneli-memory/tests/mutants.rs` wraps the
  in-memory adapter once per clause so that exactly that clause breaks, and
  checks that the suite names it; a second test checks that mutants and
  clauses are a bijection. Without it a suite could pass every adapter
  vacuously.

The clauses of part 1:

| Port | Clauses |
| --- | --- |
| `EventStore` | `create-then-load`, `append-order`, `duplicates-kept`, `runs-isolated`, `unknown-run`, `create-twice`, `round-trip`, `hostile-run-ids` |
| `Evidence` | `round-trip`, `content-addressed`, `distinct-content`, `unknown-reference`, `hostile-references` |
| `Clock` | `non-decreasing` |
| `Ids` | `not-blank`, `distinct` |
| `Agent` | `silent-failure-detail` |
| `Verifier` | `one-status-per-citation`, `silent-failure-detail` |
| `Forge` | `distinct-references`, `silent-failure-detail` |

The numbers in the suites:

- **`Ids`: 65 537 ids** (2^16 + 1). By pigeonhole no 8- or 16-bit counter
  can issue that many distinct values, so a narrow counter that wraps fails
  `distinct`. More would only cost time: the next width worth catching,
  32 bits, needs 4 billion ids. They are collected in a `BTreeSet`, because
  `HashSet` is banned in the core.
- **`Clock`: 1 000 consecutive readings.** Enough to exercise any per-call
  state in a double (the mutant goes back once, at reading 500), and well
  under 1 ms. No test can prove a real clock monotonic, so the real adapter
  must be built on a monotonic source, and its review checks that.
- **`Evidence` round trip:** the empty blob; all 256 byte values, which
  catches stores that validate UTF-8, translate newlines or stop at NUL; and
  1 MiB, above the 8 KiB `BufReader` default and the 64 KiB Linux pipe
  buffer, so a store that truncates at a buffer boundary fails. The large
  blob's bytes repeat with period 251, a prime, so the pattern never lines
  up with a power-of-two boundary.
- **Hostile names** for `hostile-run-ids` and `hostile-references`: `../x`,
  `a/b`, `.`, `..`, the empty string, NUL, `a\b`, `/abs`, and a 300-byte
  name, because Linux `NAME_MAX` is 255 bytes, so a file store must hash or
  reject it. `hostile-references` adds the same forms around a reference
  the store did issue (`../<ref>`, `/<ref>`, `<ref>/.` and others), and the
  run-id clause first creates victim runs named after the last components
  (`x`, `a`, `b`, `abs`). A hostile value is either rejected
  (`InvalidRunId`, or `NotFound` / `InvalidReference`) or stored in
  isolation; loading never returns another run's or blob's data.
- **`round-trip`** stores one event of every kind with NUL, a BOM before
  text, quotes, backslash, newline and a character outside the BMP, empty
  `Vec`s, zero and `u64::MAX` usage, and a `RunStart` with `previous` both
  set and unset, on a budget of `u64::MAX`. No event carries an `Overrun`,
  so there is none to store.

Over scripted doubles some clauses, such as `one-status-per-citation`, hold
by construction and only bite on real adapters.

### D3. `Verifier`, an 11th port

The three check commands (`CheckReproduction`, `VerifyCitations`,
`VerifyFix`) go through a `Verifier` port, and #17 implements it on
`Sandbox` and `Git`. Why: their observations need stack-specific test
running and classification (#13, #17, a JUnit reporter); without pulling
#17 into this issue, `DebugTicket` cannot compute them from `Sandbox` and
`Git`. "Verifier" is already ARCHITECTURE's name for this part of the core
("System parts"), and the port table gets a row. Rejected: `DebugTicket`
composing `Sandbox` and `Git` itself, which would move test classification
into #3. Decided by the operator at STOP 1 of #3.

### D4. Failure details are never blank

ADR-002 rejects a blank `JobFailed` detail as a caller error
(`BlankEventField`): the run stays waiting with nothing charged. The job
adapters therefore cannot produce one.

- `JobFailure` (`boneli_app::job`) has private fields and one constructor,
  `JobFailure::new(error_output, status, cost_micro_usd)`. The detail is
  `"<status>: <error output>"` when neither is blank; the error output as it
  is when only the status is blank (no trimming: ADR-002 keeps caller text
  as issued); `"<status>, no error output"` when only the error output is
  blank; `"the job failed with no error output and no status"` when both
  are.
- "Blank" is `boneli_domain::values::is_blank`, the predicate behind
  `BlankEventField`, so a detail that passes here passes there.
- `Agent`, `Verifier` and `Forge` return `JobFailure`, and each of their
  suites has the clause `silent-failure-detail`: the fixture makes the
  adapter fail with no error output and names the status it must report
  (for example `exit status 3`), and the suite checks that the detail is not
  blank and contains it. A mutant that drops the status fails the clause.
- `ForgeRef::parse` rejects exactly what `is_blank` rejects, so a forge
  cannot hand `DebugTicket` a blank reference either (ADR-002 D1, step 2).
- No cap on detail length: the adapters that capture process output (#12,
  #17) decide it from measured output sizes and keep the full output as
  evidence.

### D5. `DebugTicket`

- **Start order:** resolve `previous` (D6); take an id from `Ids` and call
  `Run::new`; pass `TicketReceived` to `handle`; then `EventStore::create`
  with `RunStart { budget, previous }` and `append(TicketReceived)`. A
  failure before `create` returns an error and stores nothing, and because
  `previous` is resolved first, a rejected re-run uses up no id.
- **Loop:** commands run in order from a queue, each as one job that yields
  one event. `run.handle(event)` comes first, and the event is appended only
  if the run accepted it, so a rejected event never enters the log and every
  log replays. New commands join the queue. When the queue is empty, a done
  run gives `Ok(DebugReport { run, commands })` with every command in order,
  and a run that still waits gives `Err(Stalled(kind))`. `Stalled` cannot
  happen under ADR-002's table, where every transition into a waiting state
  emits a command; it stays so that a later domain change fails closed
  instead of returning a waiting run as finished, and it has no test.
- **A job** is everything done for one command: load inputs from
  `Evidence`, call the port, store outputs. Any failure inside it becomes
  `JobFailed` with the job's usage; evidence failures read
  `loading the <what> failed: <error>` or `storing the <what> failed:
  <error>`. Why: the run should end with a recorded outcome, not with an
  error that leaves it waiting. A failure of the `EventStore` itself is
  different: it returns `Err(Store)` at once, and the log stays the prefix
  of accepted events.
- **Usage.** Cost comes from `Agent` reports and agent failures. Verifier
  and evidence steps cost 0, because µUSD are provider prices (ADR-002 D3);
  a cost a verifier reports with its failure is not charged. Duration is the
  `Clock` reading after the job minus the reading before it; equal readings
  are 0 ms and legal. A second reading lower than the first ends the job as
  `JobFailed` with `the clock went backwards: <a> ms, then <b> ms`, duration
  0 and the job's cost: a clock that goes backwards under-charges the
  duration budget, and ending the run stops all further spending. Forge
  calls read no clock and carry no usage, so a forge failure is `JobFailed`
  with zero usage (ADR-002 D3).
- **Pull request.** `Forge::open_pull_request` gets a structured
  `PullRequest`: run id, ticket, base, the diff, test and analysis
  (reference and content each), the fix checks, `spent` and `overrun`.
  Rendering the body, including the overrun statement, is the forge
  adapter's job (#19), because the body format depends on the forge. This
  settles the open consequence of ADR-002 ("`DebugTicket` in #3, or the
  forge adapter in #19").

### D6. Re-run after `NeedsInformation`

- `DebugRequest.previous: Option<RunId>`. `DebugTicket` loads that run's
  log, replays it with `boneli_app::store::replay` and requires, in order:
  the run exists (a store `UnknownRun` or `InvalidRunId` is
  `PreviousRun(Unknown)`); the log replays (`Unreplayable`); the run ended
  as `Done(NeedsInformation)` (`NotNeedsInformation(stage)`); and the
  previous ticket has the same `source` and `key` (`DifferentTicket`).
  Comparison is exact, as the domain compares strings, so a trailing space
  or a look-alike letter is another ticket; the title and body may differ,
  because the reporter edits them.
- Triage then gets `TriageRequest.previous = Some(PreviousTriage { run,
  outcome, questions })`. The questions come from the logged
  `TriageFinished` event, not from the caller.
- **Only the immediate predecessor counts.** Each re-run's triage already
  saw its predecessor's questions, so the latest ones are the open ones, and
  following links would walk a chain with no bound.
- The link is stored in `RunStart.previous`, so the new run's log records
  what it started from. The domain does not change: the context goes into
  the agent's request, not into a domain event, so replaying the new run is
  unaffected.
- Re-runs follow only `NeedsInformation`: ADR-002 D2 defines re-runs for
  triage questions only, and a retry after `GateFailed` waits for #25's data.

### D7. The replay gate, app mode

- **Corpus:** `boneli_replay_check::app::scenarios()` (31 scenarios) and
  `play()`, which runs one on fresh in-memory adapters and returns each
  request's result, every run log in `RunId` order and every request the
  agent, verifier and forge recorded. `tests/debug_ticket.rs` checks each
  scenario against a table of expected results, call counts and spending,
  with a bijection test between scenarios and expectations, and checks that
  every reported run equals the replay of its log.
- **Output of the binary:** the probe line; the domain section, unchanged;
  for each app scenario `app-scenario <name>`, the pretty `Debug` of the
  played result and `display <k>: <error>` for each error; then the
  `Display` and `Debug` of every variant of every `boneli-app` type with a
  hand-written `Display` (`StoreError`, `EvidenceError`,
  `DebugTicketError`). The fmt-impl tripwire now also scans
  `crates/boneli-app/src` against `RENDERED_APP_FMT_IMPLS`, and a test fails
  on a subdirectory in either core crate, because the tripwire's `read_dir`
  does not recurse.
- **Probe reused unchanged.** The domain and the application link
  statically into one position-independent binary, so one load bias and one
  heap cover both crates (ADR-002 D4, "Why both probes"); the false-failure
  rate of ADR-002 D4 is unchanged.
- **Corpus location:** the replay check, not `boneli-memory`. #32 wires
  `boneli-memory` into the production CLI, so test data there would ship.
  The corpus is also the only place `DebugTicket` tests run, so the gate sees
  every path those tests exercise (the ADR-002 D4 principle).
- **Clock:** `StepClock` from 0 in steps of 1 000 ms. A constant clock would
  make every duration 0 and leave the duration budget untested through
  `DebugTicket`; 1 000 ms keeps the arithmetic readable (the delivered path
  has 7 measured jobs, so 7 000 ms). **Ids:** `SequentialIds` (`run-1`,
  `run-2`, ...).
- **Budgets:** 1 000 000 µUSD and 600 000 ms by default, far above the
  largest spend of one corpus run (4 000 µUSD and 7 000 ms: 4 agent jobs of
  1 000 µUSD), so only the budget scenarios cross a limit. Those use limits
  one unit below or exactly at that spend (999 µUSD, 6 999 ms, 4 000 µUSD
  and 7 000 ms), the boundaries where an inclusive limit differs from an
  exclusive one.
- **Fault doubles** in the replay check knowingly break their port's
  contract, to reach paths no conforming adapter reaches: a clock with
  given readings, an evidence store that fails the n-th `put` or `get`, and
  an event store that fails the n-th `append`. Scripts are plain data, so
  nothing printed holds a function pointer or a reference.

### D8. Mutex poisoning

The in-memory adapters recover a poisoned `Mutex` with
`PoisonError::into_inner`. Every critical section is one push, pop, insert
or increment, which cannot leave data half written; the only panic possible
inside is an allocation failure, and that aborts. `unwrap` is denied across
the workspace, and propagating the poison would turn one panicked test
thread into failures in unrelated ones.

## Consequences

- The contract suites and their fixtures ship in the `boneli-app` library,
  like the domain's corpus. They are small and pure.
- The port shapes of `Agent`, `Verifier` and the infra ports are fixed
  before any real adapter exists. The extension rule (D1), fixture-driven
  suites and a minimal part 2 keep the cost of a wrong guess low.
- `boneli-memory` is a production crate (#32 wires it into the CLI for local
  runs), so it carries no test data; the corpus lives in the replay check.
- The replay gate sees only exercised paths: every new `DebugTicket` path
  needs a scenario and an expectation, or its output goes unchecked. The
  bijection test makes a forgotten expectation fail.
- A re-run chain is followed one link at a time. A reporter who answers an
  old questions comment after a newer one starts from the older run; the
  check that it ended with questions still holds.
- Resuming an interrupted run from its log, threads and `Send + Sync`
  bounds are #33's; the log format and versioning are #4's.

## Alternatives considered

- **Ten `boneli-<port>-memory` crates:** no boundary to protect, ten
  manifests.
- **In-memory adapters in `boneli-app` on `RefCell`:** not `Sync`, test
  doubles in the core.
- **Suites in `boneli-memory`:** adapters cannot depend on adapters, so real
  adapters could not reuse them.
- **Suites that panic:** a production library would panic on an adapter
  bug, and a mutant test could not tell which clause failed.
- **Generic `DebugTicket<A: Agent, ...>`:** seven type parameters, no
  run-time adapter choice, no measurable gain.
- **`Send + Sync` supertraits now:** every double and mutant must be `Sync`
  before anything needs it.
- **`DebugTicket` composing `Sandbox` and `Git`:** moves #17's test
  classification into #3.
- **Rendering the pull-request body in `DebugTicket`:** the body format
  depends on the forge.
- **Following the whole re-run chain:** unbounded, and the latest questions
  are the open ones.
- **`saturating_sub` for durations:** a clock that goes backwards would
  read as 0 ms and keep the run going, under-charging the budget.
- **The corpus in `boneli-memory`:** it would ship with the production CLI.
- **Language:** the ports, adapters and suites are Rust because the whole
  workspace is; no other language was a candidate for code inside the
  crate graph.
