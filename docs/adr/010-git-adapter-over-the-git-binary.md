# ADR-010: boneli-git-cli, the Git port over the git binary

- Status: proposed
- Date: 2026-11-17

## Context

Issue #30 builds the real adapter of the `Git` port (ADR-004, D11):
`boneli-git-cli`, which fetches the base commit, hands the sandbox a
snapshot, diffs the workspace the sandbox returns and applies diffs, all by
running the host's `git` binary.

The threat model comes from where the workspace is written. The agent
writes it in the sandbox, and `diff` reads it on the host as the runner
user, who will hold the git token (#19). Any byte of the workspace is
therefore agent-controlled, and git treats some of those bytes as
instructions rather than content. A `.git` directory in a working tree is
where git discovers its repository, and its config can name commands to
run: `core.fsmonitor` is a command git runs to list changed files, and
`core.hooksPath` or a file under `.git/hooks/` names a hook. A check on
git 2.56.0 shows that `git add -A` in a working tree with a planted
`.git/config` that sets `core.fsmonitor` to a command and an executable
`.git/hooks/post-index-change` runs both. A git that discovers the
workspace's repository is a host command execution for whoever controls
the workspace. The requirement on #30 (comment of 2026-11-13) is binding:
a workspace `.git`, its config or its hooks must not change the host
git's configuration and must not run when `diff` reads it, and a mutant
must be caught at that clause.

#30 is split into three PRs. Part 1 adds the contract clause (D1), so the
rule binds every `Git` adapter before the real one exists. Part 2 adds the
crate with the workspace codec and the materializer, which run no git.
Part 3 adds the adapter and its acceptance and settles this ADR.

Decided at #30 STOP 1 (2026-11-17): branch push and every token path,
authenticated fetch included, belong to #19; the sandbox gets the files of
the base tree plus a generated one-commit `.git` with no remote, hook or
credential; `boneli-git-cli` joins the list of crates that always get an
adversarial review.

## Decision

### D1. Repository metadata in a workspace is inert, and dropped

- **The rule.** A path is repository metadata when some component is
  exactly `.git` (`RelativePath::is_repository_metadata`): the top-level
  repository's and a nested one's, as a directory, a file or a symlink.
  It is one function, used by the contract suite, `MemoryGit` and the
  real adapter. Look-alikes (`.GIT`, `git~1`, `.git.`, `.git `, a
  zero-width character inside the name) are content as far as the core is
  concerned; they name `.git` only on case-insensitive or Windows file
  systems, and part 3 refuses them through git's own `core.protectNTFS`
  and `core.protectHFS` path checks.
- **The port's semantic** (doc comment on `Git::diff`): repository
  metadata in a workspace is not content and never steers the adapter's
  git. It is left out of the diff, nothing it names runs, and no later
  operation follows its config.
- **Dropped, not refused.** The snapshot already carries a `.git` (the
  generated one-commit repository decided at STOP 1), and an agent that
  runs `git status` or `git add` in the sandbox changes it. Refusing a
  workspace that holds metadata would fail every run. `diff` therefore
  ignores it, and `apply` refuses a diff that writes or removes a metadata
  path, as `git apply` refuses it as an invalid path. `MemoryGit` follows
  both halves.
- **The clause `workspace-metadata-inert`** is the 11th `Git` clause,
  added under ADR-004's extension rule. It binds both halves of the rule,
  `diff` and `apply`. Its fixtures are new:
  - a list of metadata entries (path and content) that the suite plants in
    a workspace;
  - `retarget`, a hook that moves every change of one path in a diff of
    the adapter's own format to another path, because only the adapter's
    test knows that format;
  - a `Tripwire` that reports what the planted metadata made run on the
    host. Only the adapter's own test knows how to look; for the git
    binary it is a sentinel file that the planted hook or `core.fsmonitor`
    would create. The sentinel must sit at an absolute path outside every
    directory the adapter creates or removes: git runs a relative command
    in the directory it works in, which the adapter deletes, and the run
    would go unseen (review of the part 1 PR). It must also be unique to
    the fixture, inside the test's own temporary directory: tests run in
    parallel, and one that resets a shared sentinel would erase another's
    trip (review round 2). The in-memory fixture shows the pattern; the
    replay fixture keeps a fixed one, because nothing runs it and the
    replay gate compares rendered lengths across processes.

  The clause works in this order:
  1. Fixture guards, each a violation and not a pass: the metadata list is
     not empty, every path is repository metadata, the tripwire reports
     nothing before the clause starts (a tripwire that fails to look is a
     violation too), and `edit` really writes every metadata entry: for
     each entry, the workspace with all entries differs from the one
     without that entry. An `edit` that drops `.git` paths, as a codec
     that keeps its own invariants might, would otherwise make every
     sub-check vacuous, and one that skips or later drops only the nested
     entry would let an adapter that mishandles only nested metadata pass
     (review round 2). This check needs no adapter call. A check that
     each entry alone changes the workspace adds nothing to it: any skip
     or drop already makes the two workspaces equal.
  2. Before any metadata reaches the adapter: `plain` is the base snapshot
     with the fixture's file edited, `d_plain` its diff, `reference` the
     snapshot of `d_plain` applied to the base, and `d_add` a diff that
     adds the fixture's missing path. For each metadata path, `retarget`
     moves `d_add` there and back to a twin content path
     (`<missing>.twin`, absent at the base), and that diff must apply and
     read back the fixture's content. This proves that the diff pointed
     at metadata carries the change, so its refusal can only come from
     the adapter's metadata rule. Without it, a `retarget` that makes
     garbage, ignores its target, or breaks only diffs pointed at `.git`
     (review round 2) would pass `apply-refuses` on every adapter. The
     round trip also covers a plain move to content; round 1's separate
     proof of that was dropped as redundant. `apply-refuses` applies
     exactly these proven diffs. What no
     such proof reaches is a `retarget` that recognizes metadata paths,
     breaks the diff on the way there and repairs it on the way back.
  3. `hostile` is `plain` plus every metadata entry, and `d_hostile` its
     diff.
  4. `nothing-ran`: the tripwire is empty. It is checked again after each
     later step.
  5. `same-diff`: `d_hostile == d_plain`.
  6. `same-checkout`: the base checkout, diffed again, gives `d_plain` for
     the edited snapshot and an empty diff for the unchanged one. This
     catches config or hooks adopted into the store of the checkout that
     was diffed, which is where part 3's per-fetch stores would hold
     them. It also catches adopted config that changes only non-empty
     diffs (`diff.noprefix`, `core.quotePath`).
  7. `fresh-checkout`: the same for a checkout fetched afterwards, which
     catches adoption into whatever new checkouts start from.
  8. `same-apply`: `d_plain` applied to either checkout gives `reference`.
  9. `apply-refuses`: `d_add` retargeted to each metadata path does not
     apply, and the base checkout's snapshot is unchanged afterwards.

  Each violation detail starts with its sub-check name (or `fixture:`)
  and quotes lengths, not bytes, so the replay gate renders it
  deterministically (ADR-004, D10).
- **Mutants.** Each sub-check has its own mutant in `boneli-replay-check`
  (ADR-004, D2), and its violation must start with that sub-check's name:
  - `RunsMetadata` (`nothing-ran`): a correct diff that records a run when
    it sees a `.git/hooks/` entry;
  - `MetadataIsContent` (`same-diff`): the metadata is encoded into the
    diff;
  - `AdoptsPerCheckout` (`same-checkout`): later diffs of the checkout
    that saw metadata start with a header;
  - `AdoptsIntoNewCheckouts` (`fresh-checkout`): diffs of checkouts
    fetched after a diff saw metadata start with a header;
  - `AdoptsOnApply` (`same-apply`): after a diff saw metadata, `apply`
    also writes a file;
  - `AppliesMetadata` (`apply-refuses`): `apply` accepts a diff that
    writes metadata.

  The table stays a bijection of mutants and clause cases. Mutants that a
  review found passing an earlier version of the clause, or that pin a
  second check site of a case, go into a separate regression table that
  is checked and rendered the same way, and each must name a case the
  table covers: `AdoptsMetadata` and `AdoptsOnChanges` (`same-checkout`),
  `RunsOnRediff` (`nothing-ran`, a hook that runs only on a second diff
  of the same checkout), `WritesThenRefuses` (`apply-refuses`, the
  unchanged-checkout check) and `NestedIsContent` (`same-diff`, only the
  top-level `.git` dropped). The fixture hooks that made the clause
  vacuous in review are rendered as fixture violations, like the
  blank-status ones, each on a mutant it let through: an `edit` that
  writes no metadata (`RunsMetadata`, `MetadataIsContent`), one that
  skips or later drops the nested entry (`NestedIsContent`), and a
  `retarget` that breaks diffs pointed at metadata (`AppliesMetadata`). Everything compared later is taken before
  `d_hostile`, so an adapter that adopts the metadata cannot pass by
  spoiling both sides. Counts: 50 clauses and 62 mutant cases (49 and 56
  before), plus 5 regression mutants and 5 vacuous fixtures.
- **ADR-004 is accepted and stays unchanged.** Its D2 counts and its D11
  clause table describe the suites as it accepted them; this ADR records
  the addition, as ADR-009 D13 did for `tampered-refused`.

### Later parts

Part 2 adds the workspace and snapshot format, its entry cap and the
materializer rules (D2 and D3). Part 3 adds the git runner with its fixed
environment and command-scope config, the transports, the operations and
the git version floor (D4 to D7), and the rule for #19: the token reaches
git only as `http.<url>.extraHeader` through `GIT_CONFIG_KEY_n` and
`GIT_CONFIG_VALUE_n` in that one git process's environment, never in argv,
a file or the snapshot.

## Consequences

- Every `Git` adapter must pass `workspace-metadata-inert`. Its test has
  to supply a tripwire that would actually see a hook or `core.fsmonitor`
  run, with a sentinel at an absolute path outside the adapter's
  directories, and a `retarget` hook for its diff format. Part 3 proves
  the fixture is not vacuous on real git: a test-local wrapper that runs
  `git add -A` with discovery inside the unpacked workspace, and then
  deletes that directory as the adapter does, fails the clause at
  `nothing-ran`.
- The `Git` suite's `run` takes two more arguments, `retarget` and the
  tripwire.
- A fix that edits a repository's own `.git` content cannot reach a pull
  request. That is intended: such a change is not source.
- An agent that changes the sandbox's `.git` (commits, config) changes
  nothing that leaves the sandbox; only the working tree's content does.

## Alternatives considered

- **Refusing a workspace that holds `.git`.** Fails every run, because the
  snapshot carries one and the agent may run git in the sandbox (D1).
- **Running git in the unpacked workspace with discovery.** That is the
  steering bug itself: git 2.56.0 runs a planted `core.fsmonitor` and
  `post-index-change` hook there (Context).
- **Checking only that the diff is unchanged.** An adapter that runs a hook
  and then diffs correctly would pass; `nothing-ran` needs the tripwire.
- **Checking later only a fresh checkout's unchanged diff** (the first
  version of this clause). Review showed adoption into the diffed
  checkout's own store, adoption that changes only non-empty diffs and a
  hook that runs only on a second diff all passing it (step 6).
- **Leaving `apply`'s refusal to the adapter's own tests.** The rule is the
  port's, so the contract binds it; the cost is the `retarget` fixture.
- **A dedicated `GitError` variant for a refused metadata path**, so that
  `apply-refuses` could require that variant instead of any error. It
  would close the residual named in step 2 without the round-trip proof,
  but `GitCli` would then have to classify git's refusal. Its plan reads
  only exit codes and never git's English messages, so it would need its
  own parse of the diff's paths before `git apply`. That is a change to
  part 3's plan, not made here.
- **A rule that also matches look-alikes** (case-folded `.git`, 8.3 short
  names). The core cannot know the file system the pull request will be
  checked out on, and git's own `protectNTFS`/`protectHFS` checks are the
  maintained list; part 3 relies on them.

## Accept when

Part 3 of #30 merges with `GitCli` passing the whole `Git` suite,
`workspace-metadata-inert` included, on a fixture repository whose
tripwire sentinel is unique to each fixture and sits in the test's own
temporary directory, outside the adapter root. The same PR's
`metadata_fixture_trips_a_discovering_git` must fail that clause at
`nothing-ran` through a wrapper that runs `git add -A` with discovery
inside the unpacked workspace and then deletes that working directory,
as the adapter does, so the trip is seen only through the sentinel.
