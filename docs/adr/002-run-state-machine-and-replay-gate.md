# ADR-002: Run state machine, budget units, gates and the replay gate

- Status: accepted
- Date: 2026-11-13

## Context

`docs/ARCHITECTURE.md` ("Debugging line", "Code architecture") describes the
run as a state machine in `boneli-domain`: every step is a job, every gate
is deterministic and fails closed, and
`Run::handle(self, RunEvent) -> Result<(Run, Vec<RunCommand>), DomainError>`
is the signature. It leaves open the exact states and events, what a gate
failure or a triage question does to the run, how the budget is counted,
and what happens when a limit is crossed late in the run (issue #2).

ADR-001 (decision D1) made the two-process replay tests the gate for
address leaks from the core, because the token scan is only a best-effort
first layer. That gate needs a home: the token scan covers every file of a
core package, tests included, and bans `std`, so a test that starts
processes cannot live in `boneli-domain`.

## Decision

### D1. States, events and commands

The run has the stages `Intake`, `Triage`, `Reproduce`, `RootCause`, `Fix`,
`Verify`, `Deliver` and `Done(Outcome)`. Inside them it waits for exactly one
event kind at a time (`Run::expects()`, `None` once done), which gives 11
states: Intake, 9 states that wait for a job or forge result, and Done.

| Waits for | Stage | On that event | Command |
|---|---|---|---|
| `TicketReceived` | Intake | ticket valid | `Triage` |
| `TriageFinished` | Triage | `Ready`; `NeedsInformation`; no question or a blank one ends `InvalidAgentOutput` | `WriteReproduction` / `PostQuestions` / none |
| `QuestionsPosted` | Triage | ends `NeedsInformation` | none |
| `ReproductionWritten` | Reproduce | | `CheckReproduction` |
| `ReproductionChecked` | Reproduce | reproduction gate | `AnalyzeRootCause` / none |
| `RootCauseProposed` | RootCause | citation precheck | `VerifyCitations` / none |
| `CitationsChecked` | RootCause | root-cause gate | `WriteFix` / none |
| `FixWritten` | Fix | | `VerifyFix` |
| `FixVerified` | Verify | fix gate | `OpenPullRequest` / none |
| `PullRequestOpened` | Deliver | ends `Delivered` | none |
| nothing | Done | every event rejected | none |

`JobFailed` is accepted in the 9 waiting states and ends the run as
`JobFailed { awaiting, detail }`. Every other (state, event kind) pair is a
`DomainError::UnexpectedEvent`: of the 11 × 11 = 121 pairs, 1 + 9 × 2 = 19 are
legal and 102 are rejected. Why one kind at a time: the application runs one
job per run at a time, so a second kind in flight would be a caller bug,
and a table this small is checked exhaustively by the tests.

**Errors and outcomes.** A `DomainError` means the caller sent something the
run cannot accept: a wrong sequence, a ticket with a blank key or title, a
blank forge reference on `QuestionsPosted` or `PullRequestOpened`
(`BlankForgeReference`), a zero budget limit, or a malformed SHA. The run does not advance, and since
`handle` consumes the run, a caller that goes on keeps a clone. Agent
output is untrusted content, not a caller error: a bad result ends the run
with an outcome (fail closed, invariant 6), so a run never stalls on it.
The outcomes are `Delivered { pull_request, overrun }`,
`NeedsInformation { comment }`, `GateFailed`, `BudgetExceeded`,
`JobFailed { awaiting, detail }` and `InvalidAgentOutput { awaiting, problem }`.
A finished run keeps the evidence it collected (ticket, base, test,
analysis, citations, diff, fix checks).

**Order inside `handle`**, which decides the ties:

1. The state and kind check. A rejected event is never charged.
2. Caller input inside a legal pair. On `TicketReceived` a blank key or
   title is `InvalidTicket`, and the run stays in Intake, because the ticket
   comes from an intake adapter before any work and the caller can fix it.
   On `QuestionsPosted` and `PullRequestOpened` a blank reference is
   `BlankForgeReference`: the reference comes from our own forge adapter, and
   a finished run that points at no comment or pull request has lost its
   evidence. The same blank rule applies, and the run neither advances nor
   is charged (forge results carry no usage). This is validation inside a
   legal pair, so the pair counts above do not change.
3. Usage accounting (D3). A total over a limit ends the run as
   `BudgetExceeded` with no command, whatever the event says, with the one
   exception in D3.
4. The event's own rule: gate, validation, transition.

`CommitSha` accepts exactly 40 or 64 lowercase hex digits (SHA-1 and SHA-256
object names). No abbreviations, because an abbreviated name can become
ambiguous as the repository grows; no uppercase or trimming, because the
domain compares SHAs as strings. "Blank" means every character is
whitespace or a Unicode `Default_Ignorable_Code_Point` (Unicode 18.0.0):
that property is Unicode's own list of code points that render as nothing
(zero-width space, BOM, Hangul fillers, variation selectors, tags), so text
made only of them is blank to a reader.

### D2. Gates

Every gate is a pure function over observation values and fails closed.
Who produces the values (sandboxes, git) is #17's; the domain only decides.

- **Reproduction:** passes only on `FailedOnAssertion` (ARCHITECTURE: "fails
  on an assertion, not on compilation"). `Passed` fails as
  `ReproductionPassedOnBase`; `FailedToBuild`, `Errored` and `TimedOut` as
  `ReproductionNotAnAssertion`; `Unknown` as `ReproductionInconclusive`.
- **Citation precheck** on `RootCauseProposed`: at least one citation, and
  every one has the run's base SHA, a line of at least 1, a non-blank quote
  and a relative canonical path (not blank, no leading `/`, no `\`, no NUL,
  no empty, `.` or `..` component). The first bad one is reported. Only `/`
  and ASCII `.` are structural in a git path, so `~/x`, `file:x` and
  look-alike dots are literal paths that cannot leave the tree; verification
  reports them `Unverifiable` if they are absent.
- **Root cause:** one result per citation, all `Verified`. A different count
  is inconclusive (`CitationResultsMismatch`) and never indexes past the end.
  ARCHITECTURE says unverifiable citations "are flagged"; read with
  invariant 6, a flagged citation is a gate that is not sure, so the gate
  fails and lists every flagged index.
- **Fix:** checked in field order: the reproduction test `Passed`, the test
  unchanged and previously green tests `Passed`, lint and typecheck `Passed`
  or `NotConfigured` (ARCHITECTURE: "lint and typecheck per configuration";
  the other three are always required). `Unknown`, or `NotConfigured` on a
  required check, is inconclusive. `VerifyFix` carries only the base, the
  diff and the test reference (invariant 6: a clean sandbox gets the base
  and the diff only).

**A gate failure ends the run** (`Done(GateFailed)`). There is no retry loop:
an attempt limit needs data, which debugger v0 (#25) will bring.

**Triage questions end the run once posted** (`Done(NeedsInformation)`). The
questions are about intent, the specific record, the production
configuration and version, client-side inputs and recurrence, which only
the reporter can answer; the answer comes at human pace; and the domain has
no clock (invariant 2) to time out a parked run. The reporter's answer starts
a new run, and #3 hands it the previous run's questions comment and outcome
so it does not repeat triage blind.

### D3. Budget

Two dimensions, both integers: cost in micro-USD and the sum of reported job
durations in milliseconds. Limits are run input (the CLI in #32, later the
control plane); the domain fixes no number and rejects a zero limit, because
a zero is a missing value, not a budget.

- **Cost in µUSD:** provider prices are quoted in USD and integer sums are
  exact. Rounding each job's cost to 1 µUSD is off by at most 0.5 µUSD per
  job, so at most 500 µUSD (0.05 %) of a 1 USD limit over 1000 jobs. Floats
  were rejected because their sums are inexact.
- **Time as summed job durations in ms:** the domain has no clock
  (invariant 2), so the application measures each job with the `Clock` port
  (#3) and reports it. A sum of durations is monotonic by construction, while
  timestamps would need a rule for a clock that goes backwards. Waiting
  between jobs, for example for a subscription window, is not work and does
  not count.
- **No token dimension:** cost already covers token spend, weighted by
  price. Under the `Subscription` access configuration the µUSD figure is a
  list-price conversion of the reported tokens, owned by the application and
  gateway side (the `Agent` adapter, #12; the gateway, #20), not by the
  domain, which only sums the integers it receives.
- **Range:** a u64 of ms is about 584 million years and a u64 of µUSD is
  1.8e13 USD, so overflow is out of reach in practice. It is handled anyway:
  sums use `checked_add`, an overflow counts as exceeded even against a
  `u64::MAX` limit, and the reported total saturates at `u64::MAX`.
- **A crossing is sticky:** the run keeps the first exceeded dimension, and
  every later charge reports it as exceeded, with the new total. Why: a
  saturated total equals a `u64::MAX` limit, so re-deriving "exceeded" from
  the total alone would read an overflowed run as within its limit again.
  Only a run that delivers over budget (below) charges after a crossing.
- **Limits are inclusive:** a limit is exceeded when the total is greater
  than it. With a limit of 100, spending 60 and then 40 continues; one more
  µUSD ends the run.
- **Both at once:** when one event exceeds both limits, `Cost` is reported
  (a fixed order, so the outcome is deterministic).
- **Forge results carry no usage:** `QuestionsPosted` and `PullRequestOpened`
  spend no agent budget. The domain stops between jobs; the hard cut inside
  a request belongs to the gateway (#20).

**Over budget at a passing fix gate, the run still opens the pull request
and states the overrun.** A `FixVerified` whose usage pushes the total over a
limit and whose fix gate passes emits `OpenPullRequest` with
`overrun: Some(Overrun { dimension, spent, budget })`, and
`PullRequestOpened` ends the run as `Delivered` with the same value. Why:

- The budget protects against further spending, and opening the pull
  request spends no agent budget: it is a forge call and carries no usage.
- The realistic trigger is the verify job's own duration (a test-suite run in
  a sandbox, not a model call) pushing the summed job time over the limit.
  Every earlier crossing has already ended the run, so the overrun is at
  most that one job's usage.
- The fix gate is deterministic, and a human always merges (ARCHITECTURE,
  "Debugging line", step 6).

**Only there.** A `FixVerified` with a failing gate over a limit ends
`BudgetExceeded`, not `GateFailed`: the exception exists because opening the
pull request spends nothing, and a failing gate opens none, so the general
rule applies, and the failing checks stay in the run's record. Every other
event that leaves the total over a limit ends `BudgetExceeded`, including a
passing gate on `ReproductionChecked`, `RootCauseProposed` or
`CitationsChecked`, and a `JobFailed`, also a `JobFailed` in Deliver after an
overrun (the crossing is sticky, so charging zero usage still reports it,
also when the total saturated at a `u64::MAX` limit).

### D4. The replay gate: `boneli-replay-check`

- **Corpus:** `boneli_domain::scenarios` holds the event sequences as data:
  `all()` returns 62 named scenarios in a fixed order, and `fold` runs one
  through `Run::handle`. It ships in the library because core crates may
  not declare features (ADR-001). The domain's unit tests fold only through
  `fold` and compare each trace with a test-only table of expected results,
  so "every sequence the unit tests use" is `all()` by construction. The
  corpus runs every error path: all 102 rejected pairs, every gate failure,
  every outcome, and an overrun both set and unset, because the gate sees
  only exercised paths (ADR-001 residual risk).
- **Harness:** a test-only crate `crates/boneli-replay-check` that depends on
  the domain only. Its binary prints a probe line, the address of a fresh
  `Box<u64>` and of `Run::handle`, then `scenario <name>`, the pretty
  `Debug` output of each trace and the `Display` of every error in it, and
  finally the `Display` and `Debug` of the errors only constructors return
  (`Run::new` with a zero limit, `CommitSha::parse`). The comparison sees
  only what is printed, so every hand-written formatting impl of the domain
  is printed (today only `DomainError`'s `Display`); a test lists those impls
  in the domain sources and fails when one is added that the harness does
  not render. Its integration test runs the binary twice
  and fails unless both the heap and the code addresses differ (address
  randomization is on); then both outputs must be equal byte for byte, and
  equal to the test process's own rendering, and the scenario headers must
  be exactly the `all()` names in order.
- **Why both probes:** the code probe proves the load bias of the
  position-independent executable, which would expose a leaked function
  address; the heap probe proves heap randomization, which would expose a
  leaked `Box` or `Vec` address. If only one were randomized, a leak of the
  other kind would compare equal.
- **False failures:** measured on the dev host (Linux, x86_64,
  `randomize_va_space = 2`): a probe binary printed its heap and code
  addresses 2000 times, and all 2000 of each were distinct. 2000 runs make
  about 2 million pairs, so with 20 or fewer random bits about 2 collisions
  would be expected; none occurred. The code address varies in 30 bits
  (mask `0x3fffffff000`) and the heap's offset from the code in 18 more (the
  1 GiB brk randomization). So two children get
  the same one with a probability of about 2^-30, and the heap check adds
  about as much: a false failure below 2e-9 per run. It then fails, and
  never passes wrongly. Under `setarch -R` (randomization off) the test fails
  with a message that says so.
- **Role:** the crate is listed in `roles.roots` of `tools/architecture.toml`.
  Roots are leaves, so no production crate can depend on it, and the
  application replay of #3 can later add in-memory adapter crates, which only
  roots may depend on.

## Consequences

- The corpus ships in the domain library. It is small data, and keeping it
  there is what lets the domain's own tests and the harness fold the same
  list.
- The replay gate sees only exercised paths; a new transition, gate or
  outcome needs a scenario and an expectation, or its `Debug` output goes
  unchecked. The bijection test between scenarios and expectations makes a
  forgotten expectation fail.
- Changing a transition later changes how stored event logs replay; log
  versioning is #4's.
- A delivered run can be over its limit by at most the verify job's usage,
  and it says so in `OpenPullRequest` and `Delivered`. Writing that into the
  pull request body is the job of whoever renders it (`DebugTicket` in #3,
  or the forge adapter in #19).
- A CI runner without address randomization turns the replay test red; the
  message says why.

## Alternatives considered

- **The harness in `crates/boneli-domain/tests/`:** `std::process` trips the
  core token scan, which covers every file of a core package.
- **Re-executing the domain's unit-test binary:** a `no_std` test cannot
  print without naming `std`.
- **Re-executing the harness test binary with a filter:** works, but depends
  on libtest's argument handling; a binary is simpler and can be run by hand.
- **Unit tests in the harness crate:** they would leave the core scan and
  lose access to the domain's private items.
- **The harness as a default-role member:** #3 needs adapter dependencies,
  which only roots may have.
- **Floats for cost:** inexact sums.
- **Tokens as a budget dimension:** cost already covers them, weighted by
  price.
- **A retry loop on gate failures:** no data yet for an attempt limit (#25).
- **A parked triage state that waits for the answer:** the domain has no
  clock to time it out, and the answer comes at human pace.
- **The budget winning over a passing fix gate too:** it discards a
  verified fix to avoid spending that opening the pull request does not
  incur.
