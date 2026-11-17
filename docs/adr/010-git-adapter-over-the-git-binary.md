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
  added under ADR-004's extension rule. Its fixture is new: a list of
  metadata entries (path and content) that the suite plants in a
  workspace, and a `Tripwire` that reports what that metadata made run on
  the host. Only the adapter's own test knows how to look; for the git
  binary it is a sentinel file that the planted hook or `core.fsmonitor`
  would create. The clause works in this order:
  1. Fixture guards, each a violation and not a pass: the metadata list is
     not empty, every path is repository metadata, and the tripwire
     reports nothing before the clause starts. A tripwire that fails to
     look is a violation too. So no fixture can make the clause vacuous.
  2. `plain` is the base snapshot with the fixture's file edited, and
     `hostile` is `plain` plus every metadata entry. `d_plain` is the diff
     of `plain`, taken before `d_hostile`, the diff of `hostile`.
  3. `nothing-ran`: the tripwire is empty.
  4. `same-diff`: `d_hostile == d_plain`.
  5. `later-diff`: a fresh `fetch_base`, and the diff of its unchanged
     snapshot is empty. This catches an adapter that adopted the planted
     config into a store it reuses.
  6. `nothing-ran` again, after the later diff.

  Each violation detail starts with its sub-check name (or `fixture:`)
  and quotes lengths, not bytes, so the replay gate renders it
  deterministically (ADR-004, D10).
- **Mutants.** Each sub-check has its own mutant in `boneli-replay-check`
  (ADR-004, D2), and its violation must start with that sub-check's name:
  `RunsMetadata` (a correct diff that records a run when it sees a
  `.git/hooks/` entry), `MetadataIsContent` (the metadata is encoded into
  the diff) and `AdoptsMetadata` (after a diff that saw metadata, every
  later diff starts with a header). `d_plain` comes before `d_hostile`
  because otherwise `AdoptsMetadata` would spoil `d_plain` and be caught
  at `same-diff`, so `later-diff` would have no mutant of its own. Counts:
  50 clauses and 59 mutant cases (49 and 56 before).
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

- Every `Git` adapter must pass `workspace-metadata-inert`; its test has to
  supply a tripwire that would actually see a hook or `core.fsmonitor` run.
  Part 3 proves the fixture is not vacuous on real git: a test-local
  wrapper that runs `git add -A` with discovery inside the unpacked
  workspace fails the clause at `nothing-ran`.
- The `Git` suite's `run` takes a third argument, the tripwire.
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
- **A rule that also matches look-alikes** (case-folded `.git`, 8.3 short
  names). The core cannot know the file system the pull request will be
  checked out on, and git's own `protectNTFS`/`protectHFS` checks are the
  maintained list; part 3 relies on them.

## Accept when

Part 3 of #30 merges with `GitCli` passing the whole `Git` suite,
`workspace-metadata-inert` included, on a fixture repository, and with the
discovering-git wrapper failing that clause at `nothing-ran`.
