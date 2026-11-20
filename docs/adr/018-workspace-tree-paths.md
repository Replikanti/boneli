# ADR-018: Workspace tree paths carry what the citation rule refuses

- Status: accepted
- Date: 2026-11-20

## Context

`snapshot` in `boneli-git-cli` (ADR-010, D2 and D6) fails closed on any
base tree path that `RelativePath::parse` refuses: a path with a
backslash, a blank name, or a name that is not UTF-8. The run then stops
before a sandbox starts, so boneli cannot debug any repository that holds
such a file (#64). ADR-010's Consequences record the limit and say that
widening it is a change to its D1 and D2.

`RelativePath` is the citation path rule of ADR-002 (D2) through one
shared function, `boneli_domain::gate::path_problem`. It binds citations,
the gates, the patch policy (ADR-013) and every port argument, not only
git, so it cannot be widened for the workspace alone.

**How often.** A sample of 28 local repositories, about 10,000 files
(issue #64), had exactly one such file. This repository's `main` at
`14e3869` tracks 2,083 files (`git ls-tree -r`), and one of them is such
a file: the architecture-checker fixture
`tools/fixtures/arch/cases/core-token-include-backslash/overlay/crates/boneli-domain/src/a\b.txt`.
No blank or non-UTF-8 path was found. The sample is mostly our own
repositories, so it says little about frequency elsewhere; it does show
that the class exists in a repository boneli must debug, its own.

**What git does with these paths** (git 2.56.0, with the adapter's
command-scope config, `core.protectNTFS=true`, `core.protectHFS=true`,
`transfer.fsckObjects=true`):

- A base holding `a\b.txt`, a space, `<U+200B>`, `x<0xFF>` and `d\e/f`
  passes `fetch --depth=1`, `fsck --strict`, `read-tree`, `add -A`,
  `write-tree`, and `diff-tree --binary` followed by `apply --cached`.
  The same holds for edits, removals and additions of every class,
  including a tab name and a trailing-space name, and the applied tree id
  equals the written one.
- In diff headers git C-quotes non-UTF-8 and backslash names (`"a/x\377"`,
  `"a/n\\ew"`) and ends a trailing-space name with a tab on the `---` and
  `+++` lines; `apply` reads all of them back.
- git's NTFS check treats `\` as a separator on Linux too: `add` and
  `apply` refuse `x\.git`, `.git\config` and `x\GIT~1`, and
  `transfer.fsckObjects` refuses them at the fetch (`hasDotgit`). git
  accepts `x\.g<U+200B>it`.

The tests named below re-run these observations on every CI run:
`apply_carries_uncitable_paths`, `diff_carries_uncitable_changes`,
`snapshot_refuses_backslash_lookalikes` and the contract suite on a base
that holds all three classes.

## Decision

### D1. Two path types

`boneli_app` gets a second path type, `TreePath`, for what a tree holds.
`RelativePath` stays what an agent or a port argument names.

- **`RelativePath`** (unchanged): citations, `Git::read`,
  `Sandbox::copy_out`, the changes and base links of the patch policy.
  `path_problem` and ADR-002 D2 do not move; the existing tests
  `path_problem_matches_citation_rule` and `citation_problem_path_forms`
  pass unmodified.
- **`TreePath`** (bytes): the paths of a workspace, a snapshot and a
  diff, in the codec, `materialize`, `snapshot`, `diff`, `apply`,
  `MemoryGit` and the `Git` contract fixtures. `TreePath::parse` refuses,
  in this order:
  - `Empty`: no path; git has no empty tree entry.
  - `Absolute`: a leading `/` would leave the target directory on the
    host.
  - `Nul`: the kernel ends a path at NUL, and git's index cannot hold one.
  - `EmptyComponent`, `DotComponent`, `ParentComponent`: `a//b`, `a/` and
    `.` resolve to another name and `..` leaves its directory, on the
    host as in git (`verify_path` refuses all three).

  Components are split at `/` only, because only `/` splits a path for
  the kernel and in a git tree. Every other byte is a name byte: `a\b`,
  ` `, `x<0xFF>`, an overlong `/` (`<0xC0 0xAF>`) and `..\x` are one name
  each.
- **The order** is byte order, derived from `Vec<u8>`, which equals
  `RelativePath`'s order on UTF-8 paths and `git ls-tree`'s order.
- **Every `RelativePath` is a `TreePath`** (`From`). The way back is
  `TreePath::citable`, which checks UTF-8 first and then
  `RelativePath::parse`, and names the reason as
  `Uncitable::{NotUtf8, Citation(CitationProblem)}`. A tree path in two
  classes (`<0xFF>\`) is `NotUtf8`.
- **`TreePath::is_repository_metadata`**: some `/`-component is exactly
  `.git`, the rule of ADR-010 D1 on bytes. `.git\x` is one name, so it is
  not metadata; the adapter refuses it as a look-alike (D3).
- **`Debug`** shows a UTF-8 path as a string and any other as escaped
  ASCII (`TreePath(b"x\xff")`), both lossless. It is hand-written, so the
  replay harness renders it (ADR-004, D10).

### D2. The workspace format

- **The path field is a `TreePath`.** `Workspace::decode` parses it with
  `TreePath::parse`; `DecodeError::PathNotUtf8` is gone and
  `DecodeError::Path` carries a `TreePathProblem`. Every other rule of
  ADR-010 D2 holds as written.
- **The magic stays `boneli-workspace 1`.** The change only widens what
  `decode` accepts: every encoding that decoded before decodes to the same
  workspace, and `encode` of such a workspace gives the same bytes. No
  reader of the format is deployed (#8, which copies a snapshot into the
  sandbox, has not landed), so no reader exists that a new magic would
  protect.
- **Canonical order is byte order** of the path bytes; ADR-010 D2's
  "byte order of the UTF-8 path" is the special case.
- **The node cap counts `/` only.** A backslash is a name byte on the
  host, so `a\b\c` is one file and `d\e/f` is a file in the directory
  `d\e`. `DEFAULT_MAX_NODES` stays 200,000 with ADR-010 D2's derivation:
  it counted nodes with `git ls-tree -r -t`, which splits at `/` only, so
  a backslash name was one node in that count as it is here, and no
  number of that derivation changes.

### D3. Look-alikes over bytes

`names_git_elsewhere` takes the whole path as bytes:

- **Components split at `/` and at `\`.** git's own NTFS check does the
  same on every host (Context), so `x\.git`, which git refuses itself, is
  refused before git runs, and `x\.g<U+200B>it`, which git accepts, is
  refused by the adapter. The set stays a superset of git's.
- **The NTFS form** reads bytes, as git's `is_ntfs_dotgit` does.
- **The folded form** reads a UTF-8 component as before. A component that
  is not UTF-8 is read twice: once with every maximal run of invalid bytes
  removed, and once with each such run replaced by `.`. Either reading
  that is `.git` refuses. Removal covers a file system that drops what it
  cannot decode (`.g<0xFF>it`); `.` covers one that decodes overlong
  sequences, where the overlong `.` is `<0xC0 0xAE>`, two invalid bytes,
  so removal alone would read `<0xC0 0xAE>git` as `git` and miss it.
- **Over-refusal** costs nothing observed: in this repository's tree at
  `14e3869` the only name either widening reads differently is
  `a\b.txt`, whose parts `a` and `b.txt` are content. This is ADR-010
  D6's trade-off: a name no repository needs may be refused, a name that
  is `.git` somewhere may not be written.

### D4. What `snapshot`, `diff` and `apply` carry and still refuse

This replaces ADR-010 D2's path bullet ("a path that is not UTF-8 or that
`RelativePath::parse` refuses (absolute, `..`, `.`, empty components,
backslash, NUL, blank)") and the refusals of ADR-010 D6 ("A tree path the
path rule refuses (a backslash, a blank name, non-UTF-8) ... are
`Failed`", and in `apply`, "a non-UTF-8 name, a backslash or a blank
name").

- **Carried** in all three operations: every tree path that
  `TreePath::parse` accepts, with its kind (file, executable, symlink) and
  content. The `Git` port's doc says so on `snapshot`, `diff` and `apply`;
  the trait does not change.
- **Still refused**, as `Failed` naming the path: repository metadata in
  the base tree, a component that is `.git` on another file system (D3,
  gitlinks included), a mode other than file, executable, symlink or
  gitlink, and in `apply` a result path that `TreePath::parse` refuses
  (defense in depth; a NUL-free git path always parses).
- **Details** name a path losslessly: a UTF-8 path in its `Debug` form, as
  before, any other in quotes with its bytes escaped to ASCII
  (`"x\xff"`), so a detail never carries an invalid byte.
- **`materialize`** writes paths as raw bytes (`OsStr::from_bytes`). The
  kernel splits at `/` only, so `..\x` and overlong forms are single
  entries inside the target (`materialize_writes_uncitable_names_literally`).
- **`MemoryGit`** unpacks its own formats with `TreePath::parse`, so the
  in-memory adapter carries the same classes.

### D5. The agent-facing rule does not change

A citation of such a path fails the precheck, and a fix that touches one
is refused by the patch policy; `Git::read` takes a `RelativePath`, so
such a file is not readable through it either. Reasons:

- **A blank path renders as nothing** to the reviewer of the pull request
  and of the evidence: a citation of ` ` or `<U+200B>` points at nothing
  anyone can see, the case ADR-002 D2 refuses blank paths for.
- **`\` is a separator on a Windows checkout** and in ADR-013's threat
  model: ADR-013 D6 refuses `\` in link targets for that reason, and its
  forbidden classes match `/`-split components, so `.github\workflows\x.yml`
  would need a second separator in every class to stay forbidden.
- **`Citation`, `Patch` and the pull request are text.** A name that is
  not UTF-8 has no faithful text form; a lossy one names another file or
  none.
- **The cost side** is the frequency in Context: one file in about 10,000
  sampled, one in 2,083 here, a test fixture.

Consequences, recorded so they are not discovered in a run:

- A run whose root cause or fix lies in such a file ends at the precheck
  or at the policy, failing closed.
- `patch_between` returns `Result<Patch, PatchInputError>`. A changed path
  or a base link path with a backslash or a blank name reaches the policy
  as written and is refused there (`Malformed { Path(..) }`,
  `BaseLinkMalformed`); one that is not UTF-8 is
  `PatchInputError::{ChangePathNotUtf8, BaseLinkPathNotUtf8}` with its
  index, which #68 maps to a refused fix. Base links are kept as they
  are, not dropped (Alternatives).
- **A symlink at an uncitable path in the base refuses every fix** of that
  repository: the policy checks every base link (`BaseLinkMalformed`, or
  the input error for a non-UTF-8 path). An unchanged regular file at such
  a path is no part of the patch, so this repository's case passes
  (`patch_between_with_uncitable_paths`).

### D6. The contract clause `uncitable-paths-carried`

The 16th `Git` clause, added under ADR-004's extension rule. The fixture
`Repository` gets `uncitable: Vec<(TreePath, Vec<u8>)>`, files of the base
whose paths `citable()` refuses, and the `edit` hook takes a `&TreePath`
(`retarget` keeps `RelativePath`: metadata paths are citable). Every
existing clause passes `TreePath::from(&path)` to `edit`. The clause runs
last, in this order:

1. **List guards**, before the adapter is called, each a `fixture:`
   violation: the list is not empty; every path is uncitable and none is
   repository metadata; one path each is `NotUtf8`, `Citation(Backslash)`
   and `Citation(BlankPath)`.
2. **`edit` guards** on the base snapshot `s` and on `full`, `s` with every
   listed file written by `edit`: `edit` really changes each path in
   `full` (its content with `+` appended; one byte always differs) and
   really removes it; each path's twin, the path with U+200B appended, has
   the path's class (an invalid byte stays invalid, a backslash stays, and
   U+200B is blank), is absent from `s` and is really added by `edit`. The
   guards run on `full`, not on `s`, so an adapter whose snapshot leaves
   the files out is caught by `snapshot-carries` below and not reported as
   a fixture problem.
3. **`snapshot-carries`**: `edit(s, p, Some(content)) == s` for every path,
   so the snapshot holds it with exactly its base content and kind.
4. **`edit-round-trip`**: per path, the content changed, then `diff`,
   `apply` and `snapshot` of the result equal the edited workspace.
5. **`remove-round-trip`**: the same with the path removed.
6. **`add-round-trip`**: the same with the twin added.

Details quote indexes and lengths, never path bytes (ADR-004, D10).

**Mutants.** One per sub-check in the bijective table:
`HidesUncitable` (the snapshot leaves uncitable paths out and `diff` keeps
the base's where the workspace has none: the "drop them" design) fails
`snapshot-carries`; `IgnoresUncitableEdits` fails `edit-round-trip`;
`KeepsUncitableRemovals` fails `remove-round-trip`; `DropsNewUncitable`
fails `add-round-trip`. Regression mutants: `RefusesUncitableSnapshot`
and `RefusesUncitableTrees`, `GitCli`'s `snapshot` and `apply` before this
ADR, fail `apply-then-read`, the first clause that snapshots and applies,
because the shared fixture now holds every class; `LossyUncitable`, a
snapshot that renders a non-UTF-8 path through U+FFFD and a `diff` that
reads the rendered name back as the base's, fails `snapshot-carries`.
Vacuous fixtures, rendered like the others, each on the mutant it would
let through: an `edit` that skips uncitable paths (`HidesUncitable`), a
list without the non-UTF-8 class (`LossyUncitable`), and a base that has
a twin (`DropsNewUncitable`).

**Counts** (`mutant_table_covers_every_clause`): 55 clauses and 70 mutant
cases (54 and 66 before, ADR-014), 8 regression mutants (5 before) and 8
vacuous fixtures (5 before).

## Consequences

- Two path types. Code that names a file for an agent or a port takes a
  `RelativePath`; code that walks a tree takes a `TreePath`. The compiler
  keeps them apart; `citable()` is the only way from tree to citation.
- The `Git` contract's `edit` hook and `Repository` changed: every
  adapter test passes a `&TreePath` hook and an `uncitable` fixture, and
  `GitCli` and `MemoryGit` pass the suite on a base holding all three
  classes, so every existing clause also holds on such a tree.
- #8 uses `TreePath::parse` and `TreePath::is_repository_metadata` as the
  validator it passes to the moved codec. This replaces ADR-010's
  sentence that names `RelativePath::parse` there.
- This repository snapshots: the ignored network test fetches commit
  `58e8013e` and finds the backslash fixture in the snapshot as a file
  with content `x`.
- **Residual: a casefold scratch root with strict encoding.** Such a file
  system refuses names that are not valid UTF-8 (EINVAL). `diff` then
  fails closed, naming the entry index. Not tested here, since no CI host
  of this crate mounts one; the failure is a `Failed`, never a write
  outside the target.
- **Residual: look-alike over-refusal** (D3): a base tree with a `\`-split
  or non-UTF-8 component that one of the readings folds to `.git` fails
  `snapshot`. None has been observed.
- The agent-facing refusals of D5 stay: such files are carried but cannot
  be cited, read through the port or changed by a fix.

## Alternatives considered

- **Widen `RelativePath`** (#64's first candidate). It moves `String` to
  bytes through every port, `Citation`, the patch model and the forge, and
  reopens ADR-002 D2 and ADR-013, both on the always-review list. ADR-013's
  forbidden classes match `/`-split components, so a backslash path such
  as `.github\workflows\x.yml` would need a second separator in every
  class. That is a large cost for a class with one observed file.
- **Escape inside `RelativePath`** (#64's second candidate). Any escape
  needs an escape character that is valid today (say `%`), which must
  then be escaped too: every path containing it gets a second spelling,
  which breaks ADR-010 D2's one encoding per tree. The escaped string
  would also be a citable `RelativePath` that names a file that does not
  exist, or one that does. And the sandbox would see escaped names unless
  #8 unescapes them, so the replica would not be the repository.
- **Leave such files out of the snapshot.** This repository's own
  architecture-checker test needs its backslash file in the sandbox, and
  the verify sandbox would differ from the base. `HidesUncitable` is this
  design as a mutant, and `snapshot-carries` catches it.
- **A new magic `boneli-workspace 2`.** It protects a reader that does
  not exist (D2), and every encoding of version 1 stays valid.
- **A lossy U+FFFD path in `patch_between`.** It would name another file,
  or none, in the policy's input; `LossyUncitable` shows the same
  failure in a snapshot.
- **Dropping base links the policy cannot read.** It would need a proof
  over every rule that reads base links (`ThroughLink`,
  `BaseLinkMismatch`, `Encloses`) that a dropped link changes no verdict,
  for a case nobody has observed. Refusing is the fail-closed choice.
- **Language.** The change is Rust in the crates that already hold the
  rules; no other language was a candidate.

## Accept when

`GitCli` and `MemoryGit` pass the `Git` suite with
`uncitable-paths-carried` on a base holding all three classes; the mutant
table, the regression mutants and the vacuous fixtures are green; the
ignored network test passes on commit `58e8013e`. All of this is
reachable in the PR that adds this ADR, so it is accepted there.

Met on 2026-11-20 by the PR for #64: `git_cli_passes_contract` and
`in_memory_git_passes_contract` pass with the new clause,
`every_clause_is_killed`, `regression_mutants_name_covered_cases` and
`vacuous_fixture_hooks_are_violations` pass with the counts in D6, and
`network::fetches_this_repository` passes with git 2.56.0.
