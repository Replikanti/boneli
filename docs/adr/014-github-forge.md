# ADR-014: GitHub forge: App tokens, create-only branch push through the Git port, inert pull-request bodies

- Status: proposed
- Date: 2026-11-19

## Context

Issue #19 builds the first real adapter of the `Forge` port (ADR-004):
`boneli-forge-github`, which posts triage questions on a GitHub issue and
opens the pull request with the verified fix. A pull request needs a
branch on the customer's repository that holds the fix, so the adapter
pushes one before it calls the GitHub API. That branch and the token that
pushes it are where this ADR starts:

- ADR-004 (D11) gives the repository to the `Git` port, and ADR-010 (D4)
  fixes how a token may reach the host git: only as
  `http.<url>.extraHeader` in the command-scope config of the one git
  process that needs it, never in argv, a file or the snapshot. It names
  that rule "the rule for #19".
- The runner pushes to a repository whose `main` a human owns. A push
  that names the wrong ref, or moves a ref that exists, writes into the
  customer's history with the customer's token.
- The token comes from a GitHub App installation and lives for an hour
  (D5, part 3), so a long run needs a fresh value per git process, not
  one value read at start.

#19 is delivered in three PRs. Part 1 (this ADR's D1 to D3) adds branch
push to the `Git` port and to `boneli-git-cli`, with the credential path,
and carries the verified citations into the pull-request request. Part 2
adds RS256 signing and a random source to `boneli-https` (D4). Part 3 adds
the forge crate, its token cache, endpoints, rendering and limits (D5 to
D11) and the gated live test (D12), and settles this ADR.

Decided at #19 STOP 1 (2026-11-19): `boneli-forge-github` joins the list
of crates that always get an adversarial review; the live test runs by
hand before part 3 merges and on any change to the forge or to the git
push and credential path, with no App key in this repository's secrets;
a pull request for a GitHub ticket of the same repository carries
`Fixes #N`; pull requests open ready for review.

## Decision

### D1. The push goes through the `Git` port

`Git` gains one operation:

```rust
fn push(&self, checkout: &CheckoutId, branch: &BranchName, commit: &CommitInfo)
    -> Result<CommitSha, GitError>;
```

It commits the checkout's tree with the base commit as the only parent
and pushes that commit to a new branch of the repository the base was
fetched from. The forge composes `fetch_base` → `apply` (the verified
diff) → `push` → create the pull request (part 3). The port takes no URL:
a checkout knows its repository, so a push can only go back where the
base came from.

- **Why the base as the only parent:** the pull request then shows the
  verified diff and nothing else. The verifier checked that diff against
  that base (invariant 6), so any other parent would ship a tree nobody
  verified.
- **The contract** (`boneli_app::contract::git`) gains four clauses, each
  with a mutant in `boneli-replay-check` (ADR-004, D2):
  - `push-reads-back`: the pushed commit is the branch's tip on the
    remote, and fetched again it holds the applied tree (mutant: push
    the base's tree);
  - `push-parent-is-base`: the tip's parents are exactly `[base]`
    (mutant: an orphan commit);
  - `push-never-overwrites`: a second push to the branch is
    `BranchExists` and the tip stays (mutant: a forced push);
  - `push-unknown-checkout`: `UnknownCheckout`, and no branch appears
    (mutant: `Failed`).

  The suite reads the remote through a new fixture hook, `Remote<G>`,
  because only the adapter's own test can see it: the host git on the
  fixture repository for `boneli-git-cli`, the adapter's state for
  `MemoryGit`. Each clause uses its own branch,
  `boneli/contract-<clause>`, which must be absent before it pushes (a
  fixture violation otherwise, so a leftover branch cannot make a push
  that never happened read back). The counts are now 54 clauses and 66
  mutant cases (`mutant_table_covers_every_clause`).
- **`MemoryGit`** records pushed commits and branches in its state.
  Commit ids are `0…0<n>` in hex from a counter, as long as the base's
  id, so a replayed run gets the same ids; an id a fixed commit already
  has is refused (`Failed`), never shadowed. A pushed commit can be
  fetched like a fixed one, which `push-reads-back` needs.

### D2. Branches: create-only, under `boneli/`

- **`BranchName`** is `boneli/` followed by one component of 1 to 100
  bytes of `[a-z0-9._-]` that starts and ends with `[a-z0-9]`, holds no
  `..` and does not end in `.lock`. That is a strict subset of
  `git check-ref-format --branch` (pinned by
  `every_branch_name_passes_check_ref_format`), so the port can never
  name `main`, a tag or any branch outside `boneli/`, and no name needs
  quoting anywhere it travels (a refspec, a URL query, a forge's API).
  Uppercase is out because branches on case-insensitive file systems
  collide when only case differs.
- **The forge's names** (part 3) are `boneli/<run-slug>-<8 hex nonce>`.
  The slug keeps `[a-z0-9]`, lowercases `[A-Z]` and maps every other
  byte to `-`; runs of `-` are collapsed and trimmed, the result is cut
  to 40 bytes, and an empty slug becomes `run`. The nonce exists because
  the `Forge` suite's `distinct-references` clause opens two pull
  requests from one request, so one run must be able to push twice; two
  attempts of one run collide with probability 2^-32, and a collision
  fails closed (`BranchExists`).
- **Why 100 bytes:** the longest forge name is 7 + 40 + 1 + 8 = 56
  bytes (a 49-byte suffix), so 100 leaves room for another forge's
  longer names. A remote that stores the branch as a loose ref writes
  the suffix as one file name, `<suffix>.lock` while it updates it, so
  105 bytes against the 255-byte `NAME_MAX`. A cap below 49 bytes would
  refuse the forge's own names; one above 250 would let such a remote
  fail to write the ref.
- **Create-only.** `boneli-git-cli` first asks the remote for the exact
  ref (`ls-remote --refs -- <url> refs/heads/<branch>`); a branch that
  exists is `BranchExists` and nothing is pushed. Then it pushes with
  `--force-with-lease=refs/heads/<branch>:`, whose empty expected value
  means "must not exist", so a branch created between the check and the
  push is refused by the remote too. Checked on git 2.56.0: that lease
  refused even a fast-forward over an existing branch and left its tip
  unchanged (`push_lease_refuses_a_branch_created_after_the_check` fakes
  the race with a git whose first `ls-remote` answers nothing).
  After a failed push the remote is asked again: a tip that is another
  commit is `BranchExists`, a tip that is the pushed commit means the
  push landed and only its answer was lost (until the push, that commit
  exists only in the adapter's store), and anything else is the push's
  own error.
- **The push command** is `push --porcelain --no-verify
  --force-with-lease=<ref>: -- <url> <commit>:<ref>`. `--` before the
  URL works on git 2.56.0; the URL is checked against the transports
  (ADR-010, D5) again before any process starts. The command scope adds
  `push.recurseSubmodules=no`, `push.followTags=false` and
  `push.gpgSign=false`, so a push sends the one ref it names and asks for
  no signing that the remote could demand.
- **What it sends.** Measured on git 2.56.0 by
  `push_sends_only_new_objects_when_main_moved`: from a depth-1 store,
  after the remote's `main` moved past the base, a one-file change sent
  4 objects (the commit, the root and `src` trees, the blob). No
  negotiation setting is needed.
- **`CommitInfo`** is the author and committer of the pushed commit and
  its message, set through `GIT_AUTHOR_*` and `GIT_COMMITTER_*` on
  `commit-tree` only, with the message on stdin (`-F -`):
  - the name is 1 to 128 bytes, not blank, with no control character,
    `<` or `>`, which would end git's ident early or split the commit
    header. git sets no limit; the name comes from the operator's
    configuration (a GitHub App's bot login in part 3), never from the
    agent, so 128 is a sanity bound that stops a misconfigured value from
    writing an unbounded header, chosen well above any bot login. A lower
    cap risks refusing a real bot or person name; a higher one changes
    nothing but the size of a commit a misconfiguration can produce;
  - the email is 3 to 254 bytes of visible ASCII, contains `@` and has
    no `<` or `>`. 254 is the longest address that fits RFC 5321's
    256-octet path, which includes the two angle brackets; 3 is the
    shortest form `a@b`;
  - the message is not blank, has no NUL (a commit message is text, and
    a NUL would hide what follows it from most readers) and is at most
    65,536 bytes. The forge generates it (part 3: a
    summary line naming the ticket and the run id, with no closing
    keyword), so it stays under a few hundred bytes; the cap bounds what
    the adapter writes to git's stdin if a caller passes something else.
    A cap below a generated message would fail every push; a higher one
    only admits larger commit objects.

### D3. Credentials into git

`boneli-git-cli` exports `Credentials`:

```rust
pub trait Credentials: Send + Sync {
    fn authorization(&self, url: &RepoUrl) -> Result<Option<String>, String>;
}
```

`GitCliConfig.credentials: Option<Arc<dyn Credentials>>` holds the
source. The ADR-010 D4 rule applies, plus these choices:

- **Scoped to the exact repository URL.** The value reaches git as one
  more command-scope pair, `http.<url>.extraHeader` = `Authorization:
  <value>`, where `<url>` is the URL git is given after `--`.
  `http.followRedirects=false` (ADR-010, D4) keeps a redirect from
  carrying the header to another URL.
- **Only network calls carry it:** `fetch` (the base and the probe of
  ADR-010 D6), `ls-remote` and `push`. `init`, `read-tree`, `add`,
  `write-tree`, `ls-tree`, `cat-file`, `apply`, `commit-tree` and
  `pack-objects` get none (`authorization_only_on_network_calls`), and
  no argv ever holds it.
- **Fetched fresh for each process.** A source that mints tokens with an
  hour's life can refresh between the calls of one operation; the value
  for the first network call of `fetch_base` and `push` is taken before
  any process starts, so a source that fails starts nothing
  (`credentials_error_fails_closed`).
- **The value is checked before use:** 1 to 8,192 bytes of `0x20`-`0x7E`
  with no space at either end. CR, LF and NUL cannot get in, so the value
  cannot inject a second header or cut the config value; a refusal names
  the rule, never the value (`header_value_rules`). Why 8,192: the
  Basic form of a token is `Basic ` plus the base64 of
  `x-access-token:<token>`, about 5,490 bytes for a 4,096-byte token, the
  cap part 3 sets on installation tokens (D5); 8,192 holds that with
  room and stays far below Linux's limit on one environment string
  (`MAX_ARG_STRLEN`, 128 KiB), past which git would not start. A lower
  cap would refuse tokens part 3 accepts; a higher one only admits
  larger headers.
- **Failure details are redacted.** The detail of a call that carried a
  value has the value, and its part after the scheme, replaced by
  `[redacted]`; a git that prints its whole environment to stderr shows
  that (`failure_detail_redacts_authorization`). The snapshot's
  generated `.git` has no http config and never sees the value
  (`snapshot_never_carries_authorization`).
- **Residual:** the environment of a running git process is readable by
  the same uid and by root. Both already hold what mints the token (the
  App key, part 3), so the environment discloses nothing they lack; argv,
  which every user can read in `/proc`, never holds it.

## Consequences

- Every `Git` adapter must implement `push`; `MemoryGit`, `GitCli` and
  the mutants do. The contract's four push clauses bind any future
  adapter, a GitLab one included.
- The `Forge` suite's `run` takes the ticket every call names, because
  only the adapter's test knows which ticket keys its forge can post on;
  `contract::sample_ticket()` serves forges that take any, and a ticket
  with a blank key or title is a fixture violation.
- `RunCommand::OpenPullRequest` and `PullRequest` carry the run's
  citations, all `Verified` by the root-cause gate, so the forge can
  quote them. The replay corpus changes with the command, in both
  processes alike.
- `GitCliConfig` loses `PartialEq` and `Eq` (a trait object cannot be
  compared), and its `Debug` shows `Some(..)` or `None` for the
  credentials.
- A push writes one commit object into the adapter's store; nothing
  reads it there, and the store goes with the adapter's root.
- A branch pushed by a run that then fails to open a pull request stays
  on the remote. Its name carries the run, so a cleanup can find it; the
  cleanup itself is out of scope (#19 plan).

## Alternatives considered

- **Push through GitHub's Git Data API** (blobs, trees, commits, refs).
  The forge would have to read `boneli-git-cli`'s diff format, or the
  port would need a "changed files" operation; it costs n + 3 requests
  for n files; and it contradicts the push path ADR-004 D11 and ADR-010
  D4 already decided. It stays the route to GitHub-signed commits later.
- **Push from `DebugTicket`** instead of from the forge adapter. It
  would add a command to the run and change the replay corpus for a step
  that only the forge needs.
- **A push that may fast-forward an existing `boneli/` branch.** A rerun
  could then move a branch that a human already reviewed. Create-only
  costs a nonce in the name and nothing else.
- **Credentials in a git credential helper** or a credential file. A
  helper is a program named by config, which ADR-010 D4 shuts off
  (`credential.helper=` empty); a file is something a later process or a
  snapshot could read.

## Accept when

Part 3 of #19 adds D4 to D12 and the live test passes on the operator's
private test repository: the pull request's head is a `boneli/` branch
whose parent is the base and which changes exactly the fixed file, both
pushed and fetched with the App's token through `Credentials`.
