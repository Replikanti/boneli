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
- **Paths** that ports take go through the citation path rule of ADR-002
  (D2), through one shared function, so a sandbox or git path cannot leave
  the tree by a route the citation precheck rejects. The function is
  `boneli_domain::gate::path_problem`, extracted from `citation_problem`
  without a change in behavior (the citation tests and the 63 domain
  scenarios pin it); `boneli_app::RelativePath::parse` delegates to it, and
  `Sandbox::copy_out` and `Git::read` take a `RelativePath`, so a path that
  is hostile as written is refused by the type before it reaches a port.
  The rule is lexical; what it does not stop is in D11.
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
- **One mutant per clause, and per operation.** The mutant table
  (`boneli_replay_check::mutants`) wraps an in-memory adapter once per
  clause so that exactly that clause breaks; `tests/mutants.rs` checks that
  the suite names it and that mutants and clause cases are a bijection. A
  clause that checks several operations (`silent-failure-detail`: 4 agent,
  3 verifier and 2 forge operations) has one mutant per operation that
  breaks only that operation, and its violation detail must start with that
  operation's name, so each sub-check is shown to bite, not only the first.
  `mutant_table_covers_every_clause` prints the counts: 47 clauses, 53
  mutant cases (part 1: 23 and 29; part 2 adds 24 clauses with one mutant
  each). Without them a suite could pass every adapter vacuously.
  The table lives in the replay check, not in `boneli-memory`'s tests, so
  the replay binary can render every mutant's violation (D10).
- **A fixture cannot make a clause vacuous.** `silent-failure-detail`
  checks that the detail contains the fixture's status, and every text
  contains the empty string, so a blank fixture status (by `is_blank`) is
  itself a violation of the clause. Part 2 applies the same rule to its
  fixtures (D11).

The clauses of part 1:

| Port | Clauses |
| --- | --- |
| `EventStore` | `create-then-load`, `append-order`, `duplicates-kept`, `runs-isolated`, `unknown-run`, `create-twice`, `round-trip`, `hostile-run-ids` |
| `Evidence` | `round-trip`, `content-addressed`, `distinct-content`, `reference-from-content` (D9), `unknown-reference`, `hostile-references`, `tampered-content-rejected` (D9) |
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
by construction and only bite on real adapters. The clauses of part 2 are
in D11.

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
  are 0 ms and legal. Every reading is checked against the run's reading
  before it, so a clock that goes backwards is caught within a job and
  between jobs, with `the clock went backwards: <a> ms, then <b> ms`. A
  second reading lower than the first ends the job as `JobFailed` with
  duration 0 and the job's cost, and this takes precedence over the job's
  own failure; a first reading lower than the previous job's last ends the
  run before the job runs, with zero usage. Why: a clock that goes
  backwards under-charges the duration budget, and ending the run stops all
  further spending. A run's first reading has nothing to compare with.
  Forge
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

- **Corpus:** `boneli_replay_check::app::scenarios()` and `play()`, which
  runs one scenario on fresh in-memory adapters behind recording adapters
  and returns each request's result, every run log in `RunId` order, every
  request the agent, verifier and forge recorded, and every port call with
  its request. 31 scenarios are written by hand (budgets, re-runs, gates,
  invalid input); the fault matrix below adds the rest. The test
  `expectations_and_scenarios_are_a_bijection` prints the counts: 1 786
  scenarios, 31 hand-written, 25 bases, 1 755 from the fault matrix, 140
  with exact expectations. `tests/debug_ticket.rs` checks those 140 against expected
  results, call counts and spending, every fault scenario against
  fail-closed properties, and every reported run against the replay of its
  log.
- **Fault matrix.** `fault_scenarios()` plays every hand-written scenario
  that has no fault of its own as a base (25 make a fallible port call, the
  re-runs after triage questions included; the two invalid-input scenarios
  make none) and, for every port call the base made, adds
  one scenario per fault kind that fails exactly that call (the N-th call of
  that operation, for every N). The kinds are tied to the port operations
  without a hand-kept list: the recording adapters implement every port
  trait, so a new port operation does not compile until it records a `Call`
  variant, and `Call::fault_kinds` matches every variant. A job port call
  fails with a scripted failure; every `EventStore` call (`create`,
  `append`, `load`) fails with each `StoreError` variant and every
  `Evidence` call with each `EvidenceError` variant, both enumerated by an
  exhaustive match, so a new variant becomes a new fault kind; the clock
  reads 1 ms below its previous reading. `Ids` cannot fail, and the first
  clock reading of a request is no fault point, because nothing earlier in
  the run exists to go back from. Why generated, and from every base: a
  fail-closed branch that no scenario plays is invisible to both the tests
  and the replay gate. The review of this pull request found such branches
  twice: loads in later jobs of the delivered run, and then the store
  failure while loading the previous run of a re-run, which only a re-run
  base reaches.
- **Expectations.** The faults of the delivered run (109 scenarios) get
  exact expectations from an independent model: the test writes that run
  out as a table of jobs (the evidence each loads, the port it calls, the
  evidence it stores) and derives each fault's name, outcome, charged usage
  and call counts from it. Agent jobs cost 1 000 µUSD, and 700 µUSD when the
  injected failure hits them, so charging a failure as a success or as zero
  changes the total; measured jobs last 1 000 ms; verifier failure costs and
  forge calls are not charged; a backwards reading charges as D5 says.
  Spot checks pin worked numbers (a failed `write_fix` after five jobs
  spends 3 700 µUSD and 6 000 ms), so a model bug cannot silently agree with
  a `DebugTicket` bug. Every fault scenario, of every base, must fail
  closed at the faulted call (`every_fault_fails_closed`): the requests
  before it end as in its base, and the faulted request ends as the fault
  calls for, never as if the call had succeeded. A job fault ends the run
  as `JobFailed` awaiting that job, with the injected detail or the
  evidence error in it. It may instead end as `BudgetExceeded`, when the
  job's usage crosses a limit, or with a backwards-clock detail, when the
  base's clock already goes back in that job (D5 precedence). A store
  fault returns that `StoreError`. A `load` that finds no run returns
  `PreviousRun(Unknown)`, and any other `load` failure returns `Store`, so
  a re-run never goes on without its previous questions. When the faulted
  request is a scenario's last, the store also holds exactly the runs and
  events the base had before the fault.
- **Size.** The replay output is about 658 000 lines (20 MB); one run of
  the debug-build binary took 1 to 5 s on the dev host. It is compared in
  two child processes and the test process.
- **Output of the binary:** the probe line; the domain section, unchanged;
  for each app scenario `app-scenario <name>`, the pretty `Debug` of the
  played result and `display <k>: <error>` for each error; then the
  `Display` and `Debug` of every variant of every `boneli-app` type with a
  hand-written `Display` (`StoreError`, `EvidenceError`,
  `DebugTicketError`, and from part 2 `SandboxError`, `GitError`,
  `ImageError` and `DataError`). The fmt-impl tripwire now also scans
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
- **Clock:** `StepClock` from 1 000 ms in steps of 1 000 ms (not from 0,
  so a backwards fault always has 1 ms to go back). A constant clock would
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
- **Fault injection** happens in the recording adapters, which knowingly
  break their port's contract to reach paths no conforming adapter
  reaches; `ScriptedClock` gives fixed readings. A job port is called
  before the fault replaces its result, so its script and request record
  advance as for a real failure; a store fails instead of being called.
  Scripts and faults are plain data, so nothing printed holds a function
  pointer or a reference.

### D8. Mutex poisoning

The in-memory adapters recover a poisoned `Mutex` with
`PoisonError::into_inner`. Every critical section is one push, pop, insert
or increment, which cannot leave data half written; the only panic possible
inside is an allocation failure, and that aborts. `unwrap` is denied across
the workspace, and propagating the poison would turn one panicked test
thread into failures in unrelated ones.

### D9. The pull request carries the bytes the verifier checked

`VerifyFix` and `OpenPullRequest` each load the diff and the test by
reference, so the forge gets the bytes the verifier checked only if a
reference always reads back what was put under it. The `Evidence`
contract makes references come from content, and makes `get` check it:

- `content-addressed`: the same bytes give the same reference.
- `distinct-content`: different bytes give different references.
- `reference-from-content`: the reference is a function of the bytes
  alone. Two fresh stores that get the same blobs in opposite orders issue
  the same reference for each, so a counter, a timestamp or any other state
  in the reference fails. Why: a store with counter references and a
  checksum kept beside each blob passed the other clauses, and a writer
  who rewrites the blob and its checksum together then has `get` return
  the forged bytes. With content-derived references there is no side
  record that decides what is genuine.
- `tampered-content-rejected`: `get` re-derives the reference from the
  bytes it read, so content changed after `put` is
  `EvidenceError::Corrupted`, never returned. The clause overwrites a blob
  through an adapter-supplied `tamper` hook with bytes of the same length,
  so a length check is not enough. The hook must write only the stored
  blob, nothing the store keeps beside it. A black-box suite cannot tell a
  hook that cooperates (for example, by marking the reference bad), so the
  real adapter's review checks the hook.

A changed blob then ends the run as `JobFailed` with `loading the <what>
failed: the stored content does not match its reference`, and the forge is
never called. The fault matrix plays `Corrupted` on every load of every
base, including the diff for the pull request, and
`forge_gets_the_bytes_the_verifier_checked` checks that in every corpus
scenario where the forge got a pull request, its diff and test equal the
bytes of that run's `VerifyFix`.

- **Digest.** `MemoryEvidence` names a blob `fnv1a64-<digest>`, the 64-bit
  FNV-1a digest of its bytes, and refuses a second blob with the same
  digest, so a collision fails closed instead of aliasing. FNV-1a is not
  cryptographic, and it does not need to be here: the store's memory
  belongs to the process, so no untrusted writer exists who could look for
  a collision. Real adapters, whose bytes another process can write (#4,
  a file store), must use a cryptographic digest from a vetted crate
  (`sha2` is already planned for `boneli-store-fs` in ARCHITECTURE), never
  hand-rolled cryptography; that is part of #4's acceptance. This pull
  request adds no dependency edge.
- **The tamper hook is test code only.** `MemoryEvidence` has no method
  that writes behind its own index. Its contract test lives in the
  `#[cfg(test)]` unit tests of `crates/boneli-memory/src/evidence.rs`, where
  the hook can reach the private map, so the shipped build has no tamper
  capability. Rejected: a non-default cargo feature. The replay corpus
  plays the faults in its binary, so the feature would be enabled in every
  workspace build that includes the replay check. Cargo unifies features
  across a build, so the composition roots (#32) would link a tamper
  method too. Enabling it through a dev-dependency only would add the
  first dev-dependency edge, which the architecture check does not
  inspect. The corpus therefore injects `Corrupted` with its recording
  adapter, and the unit test proves that `MemoryEvidence` returns it on a
  real overwrite.
- Why the check sits in the store: the reference already names the
  content, so the check needs no new state, survives a run resumed from
  its log (#33), and keeps `DebugTicket` deterministic (ADR-002): the
  decision depends only on what the store returns.
- Rejected: keeping the verified bytes in `DebugTicket` between the two
  commands. It breaks a resumed run, which has only the log.
- Rejected: `DebugTicket` putting the loaded bytes again and comparing the
  reference. Every load would write attacker-controlled bytes into the
  store as a side effect.
- Rejected: declaring the evidence store trusted. Another process with
  write access to its directory is exactly the case the review raised, and
  the check costs one hash per read.

### D10. Contract violations are under the replay gate

The contract suites ship in `boneli-app`, so the text of a `Violation`
must not hold an address or other nondeterministic data either. The replay
binary renders the result of every mutant in the table (D2) and the three
blank-status violations after the app section, in both child processes
and the test process, and the replay compares them byte for byte like run
data. So every violation that a mutant produces is gated, wherever
violations flow. A violation site that no mutant reaches is not: each
clause case is reached once, by its mutant, and a clause with several
`ensure` sites has the others unplayed. A cheap tripwire,
`contract_suites_stay_out_of_library_code`, tokenizes every library source
of `boneli-domain`, `boneli-app` (outside the module) and `boneli-memory`
with comments and literals removed, drops only the items under a real `#[cfg(test)]`
attribute, and fails if the identifier `contract` or `Violation` is left
anywhere: in a `use` tree, a path, a rename, a raw identifier or a macro
argument. So a use case cannot turn violation text into run data without a
visible change; `tripwire_tokens_are_not_fooled` pins the bypasses review
found (a renamed brace import, the attribute text in a comment) and the
literal forms around them. The domain is in the scan because a
`macro_rules!` there could emit the path inside a use case; core, alloc and
std are the only other macro sources these crates see. It is still a
tripwire over the token stream, not a parser, and it does not scan real
adapters or roots, which call the suites from their tests.

### D11. The infra ports (part 2)

`Sandbox`, `Git`, `ImageStore` and `DataSnapshot` are minimal: #3 has no
consumer for them, and their real adapters (#7 images, #8 sandbox, #30
git, #31 data, and #17 and #19 on top) extend them under the extension
rule (D1). Each operation returns a `Result` with an error enum of its
own (`SandboxError`, `GitError`, `ImageError`, `DataError`) that has a
`Failed { detail }` variant for whatever the real adapter cannot classify
yet, and the variants a clause needs. Every handle (`SandboxId`,
`CheckoutId`, `RootfsRef`, `SnapshotId`, `DatabaseCopy`) is an opaque
string the adapter issues, like `RunId`.

- **`Sandbox`** follows ARCHITECTURE's sketch: `create(SandboxSpec { phase,
  rootfs })`, `exec(id, Command { program, args, environment }, Limits {
  wall_ms, memory_bytes, processes })`, `copy_out(id, RelativePath)` and
  `destroy`. A command that ran and failed is an `ExecResult` with its
  `ExitStatus` (`Code` or `Signal`), not an error. #8 and #13 choose the
  limits.
- **`Git`**: `fetch_base(RepoUrl, CommitSha)`, `read(checkout, path)` with
  `None` for a missing file, `snapshot(checkout)`, `diff(checkout,
  workspace)` and `apply(checkout, diff)`, which returns a new checkout.
  #30 owns the snapshot and diff formats; #19 adds branch push.
- **`ImageStore`**: `pull(ImageRef { name, digest, platform })`.
- **`DataSnapshot`**: `load(sandbox, source)`, `copy(snapshot, run)` and
  `remove_copy(copy)`.
- **Names the core scan would trip on.** The command's variables are
  `environment` and the image's target is `platform`, because the core
  token scan bans the usual short names (ADR-001). The removal of a copy is
  `remove_copy`, not the SQL verb: a brace group that holds a `:` and ends
  in an identifier ending in `p` matches the format-spec scan.

The clauses:

| Port | Clauses |
| --- | --- |
| `Sandbox` | `distinct-ids`, `copy-out-after-write`, `copy-out-missing`, `isolated`, `fresh-after-destroy`, `exit-status`, `destroyed-is-unknown` |
| `Git` | `read-at-base`, `read-missing`, `unknown-commit`, `apply-then-read`, `apply-leaves-base`, `base-refetch-unchanged`, `unchanged-snapshot-empty-diff`, `added-file`, `removed-file` |
| `ImageStore` | `pull-idempotent`, `missing-image`, `digest-pinned`, `platform-pinned` |
| `DataSnapshot` | `distinct-copies`, `copies-independent`, `removed-copy-unknown`, `hostile-run-ids` |

- **`distinct-ids`** creates two sandboxes, destroys the first and creates a
  third, and requires three different handles: a handle issued again after
  a destroy would let a stale handle reach the newer sandbox.
  **`fresh-after-destroy`**: a sandbox created after another wrote a file
  and was destroyed does not see that file. A pooled adapter that hands a
  destroyed workspace on unwiped passed every other clause, and it would
  carry the agent sandbox's files into the verify sandbox (invariant 6).
- **`apply-leaves-base`**: the verify sandbox starts from the base SHA and
  the diff only (invariant 6), so applying a diff must not change the base
  checkout. **`base-refetch-unchanged`**: the base fetched again after an
  apply is still the base; an adapter that cached checkouts per repository
  and commit and let `apply` write into that cache passed
  `apply-leaves-base`, which only rereads the old handle.
  **`unchanged-snapshot-empty-diff`**: the diff of the checkout's own
  snapshot is empty, so an unchanged workspace never yields a pull request.
  **`added-file`** and **`removed-file`**: a file the base does not have
  reaches the diff, and so does a removed one. Reproduction tests are
  usually new files, and a diff of tracked files only (`git diff` without
  the untracked files) passed every other clause with a 0-byte diff.
- **`digest-pinned`** and **`platform-pinned`**: an image that differs from
  a present one in its digest only, or its platform only, is `NotFound`,
  also after the present one was pulled. A store that resolved by name
  alone passed the first two clauses, because the fixture's missing image
  differed by name.
- **`copies-independent`** is #31's acceptance as a clause: after a change
  in one copy, neither a second copy nor a copy made after the change shows
  it, so neither the other copy nor the snapshot changed.
  **`hostile-run-ids`**: #31 turns the run id into a database name, so
  the hostile names of the `EventStore` clause (D2) each get a copy no
  other run has, whose change none of the victim copies (`x`, `a`, `b`,
  `abs`) shows, or are refused with `DataError::InvalidRunId`.

The fixtures carry what only the adapter's own test knows, as in part 1:

- `Sandbox`: a spec it can create, a command that writes given content to a
  given path, and a command with a given exit status. The suite rejects
  empty content (an adapter that copies out an empty file for every path
  would pass) and the status `Code(0)` (an adapter that reports success for
  every command would pass). The fixtures here exit with 3, any non-zero
  code would do; the job fixtures of part 1 use `exit status 3` too.
- `Git`: a repository with a base commit, a file and its content there, a
  missing path, a commit the repository does not have and new content for
  the file, plus an `edit` hook that sets or removes a file in a workspace
  of the adapter's snapshot format. `added-file` writes the new content to
  the missing path. The suite rejects new content equal to the old (an
  adapter that ignores diffs would pass) and an unknown commit equal to
  the base.
- `ImageStore`: an image the registry has, one it does not, and the
  present image with another digest and with another platform. The suite
  rejects a variant that differs in more than its one field, which would
  test the name again.
- `DataSnapshot`: a sandbox, a source, and a `Probe` that makes a change in
  a copy and looks for it (for Postgres, SQL through the sandbox). The
  suite requires that the probe sees the change in the copy it made it in,
  or a probe that sees nothing would pass every copy.

The in-memory adapters: `MemorySandbox` runs scripted programs that each
return a result and write files into that sandbox's own workspace map,
issues `sandbox-<n>` from a counter that is never reused, and answers a
program it does not know with code 127 and the error output `program not
found`, the code POSIX shells use for a command not found, so a test that
calls a program the script forgot sees the same failure as on a real
sandbox. `MemoryGit` holds fixed commits and has its own length-prefixed
snapshot and diff formats; unpacking a workspace checks every length
against the bytes left and every path with `RelativePath::parse`, so a
workspace from a sandbox cannot name a path outside the tree.
`MemoryImageStore` holds a fixed set of images, and `MemoryDataSnapshot`
databases as lists of rows, with `insert` and `rows` on a copy for the
probe.

**What the path rule does not stop.** `RelativePath` is lexical: it
refuses absolute paths, `..`, backslashes and NUL as written, but it does
not resolve symlinks, and it accepts `.git/config` or
`.git/hooks/post-checkout`. A symlink the agent plants in its workspace
(`out/result.txt` pointing at a host file) or a path into the repository's
own metadata therefore leaves the tree by a route the citation precheck
does not see. A core type cannot close this, because only the adapter
touches a filesystem; the real adapters close it with contract clauses of
their own, added under the extension rule:

- #8 (`boneli-sandbox-linux`) shows that `copy_out` reads beneath the
  workspace root and follows no symlink, with a fixture command that plants
  a symlink escaping the workspace and a clause that requires the copy-out
  through it to fail.
- #30 (`boneli-git-cli`) shows that a workspace's `.git` cannot steer the
  host git: a workspace that carries a `.git/config` or a hook does not
  change the configuration or run the hook when `diff` reads it.

**What the ports do not carry yet.** `Git::snapshot` produces a workspace
and `Git::diff` takes one, but the `Sandbox` port has no operation to copy
a workspace in or export one. #8 adds them under the extension rule, as it
does the pods and phases of its own scope.

Rejected: moving each port definition into its adapter issue, where a real
implementation would check its shape. The issue asks for every port, its
in-memory adapter and its suite in #3, and the extension rule keeps the
cost of a wrong guess to an added operation or clause (decided at STOP 1
of #3).

## Consequences

- The contract suites and their fixtures ship in the `boneli-app` library,
  like the domain's corpus. They are small and pure.
- The port shapes of `Agent`, `Verifier` and the infra ports are fixed
  before any real adapter exists; the infra ports have no consumer in #3,
  and their suites run only on the in-memory adapters and the mutants until
  #7, #8, #30 and #31 land. The extension rule (D1), fixture-driven
  suites and a minimal part 2 keep the cost of a wrong guess low.
- `boneli-memory` is a production crate (#32 wires it into the CLI for local
  runs), so it carries no test data; the corpus lives in the replay check.
- The replay gate sees only exercised paths. A path reached through a
  failing port call of any hand-written base is generated by the fault
  matrix; any other new `DebugTicket` path needs a hand-written scenario.
  The bijection test makes a forgotten expectation fail, and a new port call
  on the delivered path changes its fault model, which must then be updated
  by hand.
- The replay output grows with the matrix (D7, size); a new base adds about
  one scenario per port call and fault kind.
- Every `Evidence` adapter derives its references from content and verifies
  them on read (D9), one hash per `get` for a file store.
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
- **Hand-picking fault scenarios:** the first version did, and left the
  loads in `VerifyFix` and `OpenPullRequest`, later agent and verifier
  failures and later clock faults unplayed.
- **Faults only on the delivered run:** the second version did, and left
  the store failure while loading a re-run's previous run unplayed.
- **Proving by name scan that violations never reach run data:** a scan
  is a tripwire, not a proof (a renamed import got past the first one);
  replaying the violations removes the dependency on where they flow.
- **Language:** the ports, adapters and suites are Rust because the whole
  workspace is; no other language was a candidate for code inside the
  crate graph.
