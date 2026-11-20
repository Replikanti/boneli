# ADR-023: The patch policy in the run

- Status: proposed
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

This ADR is written in two parts, one per pull request of #68. Part 1
adds the port operation and decides D4 and D6 in full. Part 2 wires the
check into the run and fills in D1 to D3, D5, D7 and D8. The ADR stays
proposed until part 2.

## Decision

### D1. Evaluation point and counts

Written in part 2 of #68.

### D2. Gate

Written in part 2 of #68.

### D3. Who evaluates

Written in part 2 of #68.

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

Written in part 2 of #68.

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

Written in part 2 of #68.

### D8. Corpus

Written in part 2 of #68.

## Consequences

- The policy can see gitlinks: a fix that adds, removes or retargets a
  submodule reaches it as a `Gitlink` change and is refused.
- `GitCli` lists both trees in full on every call, so the cost grows with
  the tree, not with the fix. One `ls-tree -r` of the largest base tree
  measured for ADR-010 (55,025 files and directories) is one process; the
  blobs read are the fix's.
- `MemoryGit` cannot exercise modes, symlinks or gitlinks; the `GitCli`
  integration tests carry those cases.

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
