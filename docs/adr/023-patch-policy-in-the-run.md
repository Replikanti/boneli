# ADR-023: The patch policy in the run

- Status: accepted
- Date: 2026-11-20

## Context

ADR-013 made the patch policy a pure domain function,
`boneli_domain::patch_policy(&Patch, &PatchLimits)`, and recorded that
nothing calls it yet: #68 wires it into the run between `FixWritten` and
`VerifyFix`. Two questions decide the wiring, and the port question is
settled first because the run needs it:

- **Which tree is judged.** The forge pushes the tree that `Git::apply`
  builds from the base and the stored diff (ADR-014). A policy that judged
  anything else, such as the agent's workspace, could pass one tree and
  push another. So the policy must judge the change from the base
  checkout to the checkout `apply` made.
- **Who builds the `Patch`.** `boneli-git-cli` already has
  `patch_between(base, after)` over two ADR-010 workspaces (ADR-013, D1).
  A workspace holds no gitlinks (ADR-010, D3: `snapshot` skips them), so a
  `Patch` built from two snapshots cannot see a diff that adds, removes or
  retargets a submodule, and the policy's `Gitlink` violation would never
  fire. That fails open.

This ADR was written in two parts, one per pull request of #68. Part 1
added the port operation and decided D4 and D6. Part 2 wires the check
into the run and decides D1 to D3, D5, D7 and D8.

It changes four accepted ADRs, which their lifecycle rule leaves as they
are (`docs/adr/README.md`): this ADR replaces, without editing them,

- ADR-002 D1's table and counts and D4's scenario count (D1 and D8 here);
- ADR-004 D5's list of the ports `DebugTicket` drives, and D7's counts,
  budgets and replay size (D3 and D8);
- ADR-012 D3's version and `MAX_DEPTH` (D7);
- ADR-013's consequence "Nothing calls the policy yet" (D1 to D3).

## Decision

### D1. Evaluation point and counts

The run checks the patch between `FixWritten` and `VerifyFix`, so a fix
the policy refuses never reaches a sandbox and is never pushed. ADR-002
D1's table gets one state; the other rows stay as they are:

| Waits for | Stage | On that event | Command |
|---|---|---|---|
| `FixWritten` | Fix | | `CheckPatch { base, diff }` |
| `PatchChecked` | Fix | patch gate (D2) | `VerifyFix` / none |
| `FixVerified` | Verify | fix gate | `OpenPullRequest` / none |

- **Event.** `RunEvent::PatchChecked { check: PatchCheck, usage: Usage }`
  carries the limits the policy judged against and its verdict
  (`PatchCheck::Judged { limits, verdict }`), or the first path that left
  it nothing to judge (`PatchCheck::Unreadable(UnreadablePath)`, D6).
  `EventKind::PatchChecked` is declared between `FixWritten` and
  `FixVerified`, so `EventKind::ALL` has 12 kinds and lists them in run
  order.
- **The `Patch` stays out of the event.** It holds the full before and
  after content of every changed path. That content is agent output, its
  size has no bound the run sets, and ADR-012 keeps content out of events
  and references in them. The verdict holds no content (ADR-013, D1), and
  the stored diff it was computed from is already in the record.
- **Stage and record.** The new state is in `Stage::Fix`: checking the
  patch is part of producing a fix, and `Verify` stays the stage of the
  clean sandbox. A run that ends there keeps `Record::Fixed`, the diff.
- **Counts.** 12 states: Intake, 10 that wait for a job or forge result,
  and Done. Of the 12 × 12 = 144 (state, event kind) pairs, 1 + 10 × 2 =
  21 are legal and 123 rejected. 9 event kinds carry usage.
- **Budget.** ADR-002 D3's order is unchanged. `PatchChecked` is charged
  like every job result, and a total over a limit ends the run as
  `BudgetExceeded` whatever the verdict says. The one exception stays a
  passing `FixVerified`: it exists because only opening the pull request
  follows, which spends no agent budget, while a passing patch check is
  followed by the verify job, which does.

### D2. Gate

`boneli_domain::patch_gate(&PatchCheck)`:

- `Judged` with `Pass` passes, and the run emits `VerifyFix`.
- `Judged` with `Reject(violations)` fails as
  `GateFailure::PatchRefused(violations)`, every violation in the policy's
  order. A `Reject` with an empty list fails too, as `PatchRefused([])`:
  the policy never builds one, so it can only come from a bug, and a gate
  passes only on proof (ADR-002, D2).
- `Unreadable(path)` fails as `GateFailure::PatchUnreadable(path)` (D6).
  Rejected: a `ChangeProblem::PathNotUtf8` inside a verdict. The policy
  never emits it, so it would be a violation no policy run produces, and
  the corpus coverage of every label (`patch_corpus`) would need an
  exception for it.
- The gate does not compare the verdict with the limits (for example a
  `Pass` with more files than `max_changed_files`). The verdict is not
  input from an adapter: `DebugTicket`, core code under the replay gate,
  computes it with the domain's own function (D3).
- **A diff that does not apply** to the base is a `GitError` from
  `Git::apply`, and the job fails: the run ends as
  `JobFailed { awaiting: PatchChecked, detail }` with `applying the diff
  failed: ...` (decided at #68 STOP 1). It is not a gate failure, because
  `GitError::Failed` does not tell agent output that does not apply from
  an infrastructure failure, and a gate failure would blame the agent for
  a full disk. Both fail closed; the outcome label is coarse until a
  classifying variant exists, which would need its own fault-matrix
  meaning (D4).

### D3. Who evaluates

`DebugTicket` runs `CheckPatch` as one measured job:

1. `Evidence::get` of the diff (`loading the diff failed: ...`);
2. `Git::fetch_base(request.repo, base)` (`fetching the base failed:
   ...`);
3. `Git::apply(checkout, diff)` (`applying the diff failed: ...`);
4. `Git::patch_between(checkout, applied)` (`describing the patch failed:
   ...`);
5. `patch_policy(&patch, &request.patch_limits)`, or `Unreadable` when
   step 4 named a path that is not UTF-8.

The job costs 0 µUSD, as verifier and evidence steps do (ADR-004, D5); its
duration is measured. A git or evidence error ends it as `JobFailed` with
the step in the detail.

- **One tree throughout.** The policy judges the tree `Git::apply` builds
  from the base and the stored diff. The forge pushes from the same
  operation on the same diff (ADR-014), and the content-addressed diff
  (ADR-004, D9) is the one the verifier and the forge load, so the judged,
  the verified and the pushed change come from one function and one diff.
  `forge_gets_the_bytes_the_verifier_checked` pins that every verified
  diff is one `Git::apply` got first.
- **`DebugTicket` drives 8 ports**, `Git` added to ADR-004 D5's seven.
  `DebugRequest` gets `repo: RepoUrl` and `patch_limits: PatchLimits`, run
  input like the budget; `RunStart` and the log header do not change.
- **Rejected: the policy inside `Run::handle`.** The event would have to
  carry the `Patch` (D1).
- **Rejected: the check folded into the `WriteFix` job.** One usage
  figure and one failure detail would cover an agent job and a git job: a
  git failure would be charged the agent's cost and labelled `awaiting:
  FixWritten`.
- **One repository.** The run fetches the base from `DebugRequest.repo`;
  the forge pushes to the repository it was built for. The composition
  root (#32) must build both from one configuration value, or a run could
  judge one repository and push to another.

### D4. The port operation `Git::patch_between`

`Git` gets one operation:

```rust
fn patch_between(&self, base: &CheckoutId, after: &CheckoutId)
    -> Result<Result<Patch, UnreadablePath>, GitError>;
```

It returns the lossless change from `base`'s tree to `after`'s tree as
the policy's input:

- Every path whose entry differs in kind or bytes is a change, with both
  full sides and `None` on an absent side, in strictly ascending byte
  order of the paths, the order `Patch` requires (ADR-013, D1).
- `base_links` holds every symlink of `base`'s tree, unchanged ones
  included, so the policy's link walks see every link a checkout of the
  base holds (ADR-013, D6).
- A gitlink is a side of kind `Gitlink` whose data is the commit id in
  hex, 40 or 64 digits.
- Nothing is filtered out, not even a repository-metadata path. The
  policy refuses what it must; an adapter that filtered would be a second
  policy that no gate covers.
- An unknown handle on either side is `Err(GitError::UnknownCheckout)`,
  never an empty patch: an empty patch reads as an empty fix, and a patch
  against the wrong tree reads as some other fix.

The outer `Result` covers the adapter and the inner one the content. No
new `GitError` variant: the fault matrix of ADR-004 injects every
`GitError` kind at every git call, and a content variant would mean
nothing at `fetch_base` or `push`.

**`GitCli`** merge-joins the `git ls-tree -r -z --full-tree` listings of
both trees by raw path bytes and compares `(mode, object id)`:

- Modes 100644, 100755, 120000 and 160000 map to `File`, `Executable`,
  `Symlink` and `Gitlink`. Any other mode is `Failed`, wherever it sits in
  the listing. git canonicalizes modes when it reads a tree, so a tree git
  wrote has no other mode.
- A listing that is not strictly ascending in byte order (a duplicate
  included) is `Failed`, and so is a path a tree cannot hold
  (`TreePath`). `ls-tree -r` prints a tree in the byte order of the full
  paths, because git sorts a directory as its name followed by `/`. A
  listing out of that order is a tree git did not write, and a join over
  it could pair the wrong entries.
- A listing with more than the adapter's node cap
  (`GitCliConfig::max_workspace_nodes`, `DEFAULT_MAX_NODES` = 200,000 in
  production, ADR-010 D2) is `Failed`. This is a memory bound only: the
  cap counts files, symlinks and the directories they imply, so a tree
  with more listed entries than the cap cannot be snapshotted for a
  sandbox either, and no fix can have been written on it. A separate
  number would need its own derivation and buys nothing.
- Only the blobs of changed sides are read, through one
  `cat-file --batch` per side, plus the base's symlink targets. Each side
  is read from its own checkout's store, because two `fetch_base` calls
  make two stores.
- Both handles are resolved before any process starts.

**`MemoryGit`** joins its two `Tree`s the same way. Every side is `File`
and `base_links` is empty, because the in-memory adapter has no modes,
symlinks or gitlinks; those cases are covered by the `GitCli` tests.

**Contract** (ADR-004, D2): five clauses, each with its own mutant in
`boneli-replay-check`, the last with two sub-checks:

| Clause | What it pins | Mutant |
|--------|--------------|--------|
| `patch-unchanged-empty` | a checkout against itself, and against a second fetch of the same base, has no changes | `PatchSpurious`: a change with equal sides |
| `patch-full-sides` | an edit is one change from the base content to the edited content, same regular kind; base links as for the unchanged patch | `PatchDropsBefore`: every edit an add, which hides the base's test declarations |
| `patch-added-removed` | an add and a removal are two changes in byte order with `None` on the absent sides | `PatchDropsRemovals`, which hides a deleted test file |
| `patch-unknown-checkout` | an unknown handle on either side is `UnknownCheckout` | `PatchUnknownEmpty` |
| `patch-uncitable-paths` / `uncitable-carried` | an edit of a backslash or blank path is one change at that path as written | `PatchDropsUncitable` |
| `patch-uncitable-paths` / `unreadable-refused` | an edit of a path that is not UTF-8 is `UnreadablePath::Change { index: 0 }` | `PatchLossyPaths`: a U+FFFD path the policy would accept |

The counts go from 55 clauses and 70 mutant cases (ADR-018) to 60 and 76
(`mutant_table_covers_every_clause`).

### D5. Limits

The limits are run input, `DebugRequest.patch_limits`, as the budget is.
`DebugTicket` applies no default of its own; `PatchLimits::DEFAULT` (25
files, 1,000 lines, 42,000 bytes, ADR-013 D3) is what a caller passes when
it has no repository setting. Reading them from configuration is the
composition root's job (#32), which must also refuse a file limit above
488, the bound of D7. The limits are logged in every `PatchChecked`, so a
stored run says what its fix was judged against even though the header
does not hold them (that is #33's question).

### D6. Unreadable paths

The policy's paths are text, and a path that is not UTF-8 has no text
form (ADR-018, D5). `boneli_domain::UnreadablePath` names the first such
path the patch would carry, by the index the entry would have in
`Patch::changes` (`Change { index }`) or `Patch::base_links`
(`BaseLink { index }`), changes first. It derives `Debug` and has no
hand-written `fmt` (ADR-013, D1).

It replaces `boneli-git-cli`'s `PatchInputError`, which had the same two
cases and indices; the workspace `patch_between` now returns it too and
stays as the differential oracle of the `GitCli` tests.

A lossy conversion through U+FFFD is ruled out: the policy would judge a
path that is not in the tree, and a forbidden name could pass under it.
An unchanged file at such a path is no part of the patch, so a repository
that holds one can still be fixed elsewhere; a base symlink at such a path
makes every fix unreadable, as a base link with a backslash makes every
fix malformed (ADR-018, D5). Part 2 ends the run on an unreadable patch
as a gate failure.

### D7. Log format

`boneli-store-fs` writes **version 2** (ADR-012 D3 was version 1). The
header has the same shape with `"version":2`.

- **`PatchChecked`:** `{"event":"PatchChecked","check":...,"usage":...}`
  with `check` one of
  - `{"kind":"Judged","limits":{"max_changed_files":n,"max_changed_lines":n,"max_changed_bytes":n},"verdict":{"kind":"Pass","files":n,"lines":n}}`,
  - the same with `"verdict":{"kind":"Reject","violations":[...]}`,
  - `{"kind":"Unreadable","path":{"kind":"Change"|"BaseLink","index":n}}`.
- **Violations** are `{"kind":"<variant>", ...}` with the fields in
  declaration order. The payload enums are objects too:
  `{"kind":"Path","problem":"<CitationProblem>"}`,
  `{"kind":"Into"|"Encloses","class":"<ForbiddenClass>"}`,
  `{"kind":"Marker","marker":"<Marker>"}`, and `{"kind":"<variant>"}` for
  a variant without data. Enums without data (`CitationProblem`,
  `ForbiddenClass`, `NotText`, `Marker`) are their variant names.
- **Decoding** stays strict and canonical (ADR-012, D3). A limit decodes
  through `NonZeroU32`, so 0 fails; a `u32` field through
  `u32::try_from`; an index or count through `usize::try_from`. Every
  enum is matched exhaustively in the encoder, and the tests list every
  value through chains that match every variant, so a new value does not
  compile until it is listed.
- **`MAX_DEPTH` = 6**, the schema's own depth: event → `check` →
  `verdict` → `violations` → violation → `problem` or `reason`.
  `schema_depth_is_the_limit` measures it on the parser.
- **`MAX_VALUES` and `MAX_LINE_BYTES` stay** (65,536 and 8 MiB). The
  values bind first. boneli-json counts every scalar, array, object and
  element once and keys not at all (ADR-008, D5):
  - one violation is at most 6 values (`Link` or `DisablesTests` with a
    payload object: the object, `kind`, `index`, the payload object, its
    `kind` and its member);
  - one change has at most 24 violations, each family once (ADR-013, D2
    step 5): `Forbidden` 4, `Gitlink` 3, `NotText` 4, `Link` 6, 17
    markers at 6 and the other three test families at 5, so 4 + 3 + 4 +
    6 + 17 × 6 + 3 × 5 = 134 values;
  - the event around them is 14 values (event, name, `check`, its kind,
    `limits` and 3 numbers, `verdict`, its kind, the array, `usage` and 2
    numbers), and the one size violation that can come before them 3;
  - so 17 + 134 × 488 = 65,409 values fit and 489 changes need 65,543:
    **488 changed files** is the most a worst-case verdict can describe.
    At the default 25 files the worst case is 3,367 values, 5.1% of the
    cap. The worst line at 488 files is about 0.9 MB, 11% of
    `MAX_LINE_BYTES`. `patch_verdict_line_bound` appends 488 and gets
    `Unavailable` for 489, with the file unchanged.
  - A malformed base link costs at most 16 values: `OutOfOrder` (5), a
    `Path` problem (6) and an empty target (5), the most problems one link
    can have (ADR-013, D2 step 3), so about 4,095 fit in one line. A
    repository with more malformed links than that is refused for every
    fix anyway (ADR-018, D5); its append fails closed as above.
  A verdict over the bound is an `append` that fails: the request ends
  with `Err(Store)` and the log stays the accepted prefix, closed but not
  a recorded gate failure. That is why #32 must refuse a file limit above
  488 (D5).
- **Version 1 reader.** A version 1 log is read with the same decoder, so
  ADR-012 D3's "a reader for both" holds, with one rule
  (`codec::admits`): a version 1 log may hold neither `FixWritten` nor
  `PatchChecked`. After `FixWritten` the version 1 table expected
  `FixVerified` and the version 2 table expects `PatchChecked`, so such a
  log would replay to another run, and `PatchChecked` did not exist. A
  version 1 log that ends earlier replays the same, so a previous-run
  lookup (ADR-004, D6) on it still works
  (`rerun_reads_questions_from_a_version_1_log`). `append` refuses those
  two events on a version 1 log, so whatever is appended loads. No version
  1 log exists outside tests: no composition root writes logs before #32.
  Rejected: refusing version 1 outright, which would break the
  `previous` lookup for no gain, and replaying version 1 logs under the
  old table, which would keep two run tables alive for logs that do not
  exist.

### D8. Corpus

- **Domain** (`boneli_domain::scenarios`, ADR-002 D4): the default path
  gets `PatchChecked` (`Judged`, `PatchLimits::DEFAULT`, `Pass { files: 1,
  lines: 2 }`) after `FixWritten`, with zero usage, so the totals of the
  other scenarios stay as they were; every sequence past the fix gets it
  too. New: `reject-in-patch-check`, `patch-refused`,
  `patch-reject-empty-list`, `patch-unreadable` (a base link),
  `patch-check-job-failed`, `patch-check-over-budget` (a passing check
  over the budget ends `BudgetExceeded`) and `patch-refused-over-budget`
  (a refusal over the budget ends `BudgetExceeded`, not `GateFailed`, and
  keeps the diff). 63 scenarios become 70; the pair test sees all 144
  pairs and accepts the 21 legal ones.
- **App** (`boneli_replay_check::app`, ADR-004 D7): every scenario runs
  on one `MemoryGit` commit at the base holding `src/invoice.rs`,
  `tests/invoice.test.ts` and `.github/workflows/ci.yml`; the delivering
  agent's fix changes one line of `src/invoice.rs`. The recording adapters
  record the seven `Git` operations as `Call`s, and their fault kinds are
  every `GitError` variant, chained like the store errors; a git call
  fails instead of being called. `Played` also records the diffs
  `Git::apply` got. New hand-written scenarios: `patch-forbidden-path`,
  `patch-disables-test`, `patch-over-file-limit` (limit 1, two files),
  `patch-at-file-limit` (limit 2, delivered), `patch-empty-fix`,
  `patch-unreadable-path`, `patch-diff-does-not-apply`,
  `patch-check-over-duration` and `patch-refused-over-duration`. With
  `StepClock` at 1,000 ms per measured job the delivered run is 8 jobs,
  so `delivered-at-limits` is `(4,000 µUSD, 8,000 ms)` and
  `delivered-over-duration` 7,999 ms.
- **Model.** The independent table of the delivered run in
  `tests/debug_ticket.rs` gets the check row (loads the diff, calls
  `fetch_base`, `apply` and `patch_between`, stores nothing, costs 0);
  spot checks pin that a failed `patch_between` spends 4,000 µUSD and
  7,000 ms and the verifier never runs.
- **Counts and size.** `expectations_and_scenarios_are_a_bijection`
  prints 2,978 app scenarios: 40 hand-written, 34 bases, 2,938 from the
  fault matrix, 171 with exact expectations (ADR-004 D7: 1,786, 31, 25,
  1,755 and 140). The replay output grows from 663,500 lines (20 MB) to
  1,235,260 lines (36 MB); one run of the debug-build binary took 1.2 to
  4.9 s before and 1.9 to 7.5 s after, three interleaved runs each on the
  dev host under other load. More than the fifth the plan expected: the 9
  new scenarios are bases themselves, every base that reaches the check
  gains 18 fault points (4 `GitError` kinds at 3 git calls, 4 evidence
  errors on the diff and 2 clock readings), and the diff, now a real one,
  is printed byte by byte in the verifier's, the forge's and `Git::apply`'s
  records. The fixture code is kept to three lines for that reason. The
  contract counts are those of D4, 60 clauses and 76 mutant cases.

## Consequences

- A fix the policy refuses ends the run before any sandbox runs it and
  before anything is pushed, and the log records why, violation by
  violation.
- The policy can see gitlinks: a fix that adds, removes or retargets a
  submodule reaches it as a `Gitlink` change and is refused.
- `GitCli` lists both trees in full on every call, so the cost grows with
  the tree, not with the fix. One `ls-tree -r` of the largest base tree
  measured for ADR-010 (55,025 files and directories) is one process; the
  blobs read are the fix's.
- `MemoryGit` cannot exercise modes, symlinks or gitlinks; the `GitCli`
  integration tests carry those cases.
- Every patch check fetches the base and applies the diff once more,
  after the agent's own work and before the verifier's. The port has no
  operation to release a checkout, so `GitCli` keeps both checkouts and
  the fetched object store until the adapter drops. The composition root
  (#32) decides the adapter's lifetime.
- The `JobFailed` label of a diff that does not apply is coarse (D2).
- Log format version 2 strands no stored log: none exists outside tests,
  and a version 1 log past the fix fails closed.

## Alternatives considered

- **Snapshot both checkouts and call the workspace `patch_between`.**
  `snapshot` skips gitlinks, so a diff that adds a submodule would reach
  the policy as no change: fail open. It would also read every blob of
  both trees, not only the changed ones.
- **A `GitError` variant for unreadable paths.** The fault matrix would
  inject it at every git call, where it means nothing.
- **Filtering repository metadata in the adapter**, as the workspace
  `patch_between` does. The policy already refuses those paths; a second
  filter would be policy outside the gate.

## Accept when

Part 2 of #68 merges with D1 to D3, D5, D7 and D8 written, and the replay
gate passes with the check in the run.
