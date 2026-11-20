# ADR-010: boneli-git-cli, the Git port over the git binary

- Status: accepted
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
  concerned; they name `.git` only on case-insensitive, normalizing or
  Windows file systems, and part 3's `diff` refuses them before it writes
  anything, as `snapshot` and `apply` refuse a tree that holds one (D6). git's own `core.protectNTFS` and `core.protectHFS` path
  checks stay on as a second layer, but alone they come too late: they
  check the names `add` records, and on a casefold scratch directory git
  reads an untracked `sub/.GIT` gitfile as `sub/.git` while it walks the
  tree, before any name is checked. In review, plain git 2.56.0 on a
  tmpfs `casefold` directory recorded `sub` as a gitlink to the HEAD of
  another repository on the host that the gitfile named.
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

### D2. The workspace and snapshot format

Part 2 of #30. A snapshot the adapter hands the sandbox and a workspace
the sandbox hands back share one format, `boneli_git_cli::Workspace`.

- **Encoding.** The magic `boneli-workspace 1\n`, then the entries in
  path order. Each entry is a kind byte, the path and the data; path and
  data are each a length in 8 big-endian bytes followed by the bytes.
  The kinds are exactly the blob modes git records: `f` a regular file
  (0644), `x` an executable (0755) and `l` a symlink, whose data is its
  target as raw bytes. Directories are implicit, as in a git tree: an
  entry's parents are directories, and an empty directory cannot be
  expressed. Gitlinks are not entries; the adapter reads them from the
  base tree (D3).
- **Canonical.** Path order is the byte order of the UTF-8 path, which is
  `RelativePath`'s order and needs no collation. A tree has exactly one
  encoding, so two snapshots of one tree are equal byte strings, and
  `decode` refuses every byte string `encode` would not produce.
- **What `decode` refuses**, each as a `DecodeError` that names the entry
  by index and quotes lengths, never the agent-written bytes (as ADR-004
  D10 does for violation details):
  - a wrong or truncated magic, an unknown kind byte, and a length past
    the end, `u64::MAX` included, or a partial trailing entry;
  - a path that is not UTF-8 or that `RelativePath::parse` refuses
    (absolute, `..`, `.`, empty components, backslash, NUL, blank);
  - a path equal to or sorting before the previous one;
  - an entry beneath a file or symlink entry, against every ancestor and
    not only the previous entry: `a`, `a.txt`, `a/b` sorts `a.txt`
    between the file `a` and the entry beneath it;
  - a symlink with an empty target or a NUL in it. Any other target is
    kept as written, absolute or with `..`: a link is never resolved on
    the host (D3), and which links a fix may add is the patch policy's
    question (#17);
  - more nodes than the cap (below).
- **Bounded on hostile input.** Every length is compared with the bytes
  left, as a `u64`, before anything is copied, so nothing is allocated
  ahead of the input: a decoded workspace holds at most the input's bytes
  plus a fixed overhead per entry, and the node cap bounds the entries. The
  ancestor check runs in linear time over a stack of the earlier paths
  that are a string prefix of the current one. Paths that share a prefix
  sort together, so every earlier entry that is a prefix of the current
  path is still on the stack, and the path lies beneath one exactly when
  the next byte is `/`. A lookup of every ancestor in an ordered map
  instead compares O(L^2) bytes for a path of length L next to a sibling
  that shares its prefixes; a test of a 4 MB path holds the decoder under
  a deadline that such a lookup misses.
- **The node cap.** `decode(bytes, max_nodes)` counts nodes, the files
  and symlinks plus every distinct directory they imply
  (`Workspace::nodes`), and refuses past `max_nodes`, which defaults to
  200,000 (`DEFAULT_MAX_NODES`). That is the number of file system
  objects `materialize` creates (D3), so the cap bounds the inodes a
  hostile workspace can ask of the host, whatever its size. It bounds
  them across calls too, because `diff` keeps nothing: the scratch
  directory and the workspace's objects are both removed after each call
  (D6).
  - *Why directories count.* A directory costs two bytes of input (`a/`),
    so one entry can imply as many directories as half its path length.
    A cap on entries alone bounded nothing: in review one entry of 3,837
    bytes made 1,900 directories under a cap of 1, and a 200 MB workspace
    could ask for about 100 million directories (200 MB / 2 bytes),
    about 380 million under 200,000 entries. Without any cap the bound
    is that same input size / 2.
  - *Counting is linear.* In path order, a directory two paths both imply
    lies inside their common prefix, and everything between two paths
    that start with `d/` starts with it too. So a path adds exactly the
    directories at its `/` positions at or past its common prefix with
    the previous path, and the count costs one pass over the bytes. The
    cap is checked before each entry is read and after its path is
    counted.
  - *Derivation of 200,000.* The candidate repositories of
    docs/ARCHITECTURE.md, measured on 2026-11-17 at the head of each
    default branch through a tree-only shallow clone (depth 1, no
    blobs) and counted with `git ls-tree -r -t`: 3,731, 10,291 and
    55,025 nodes. The trees move with every commit; a recount later
    that day found the largest a few nodes bigger, which changes
    nothing below. The largest has 44,776 files and 10,249
    directories, at most 12 directories deep and with paths of at most
    242 bytes. The cap is about 3.6 times the largest, room for a
    larger repository or a generated tree without letting a hostile
    workspace grow the host's inode use past 200,000.
  - A workspace that carries `node_modules` may exceed it; that fails
    closed with a detail naming the cap, and #8 decides what an export
    carries.
- **`without_metadata`** drops every path `is_repository_metadata` names
  (D1), as a file, a directory's entries or a symlink.
- **Constructors.** A `Workspace` is built by `decode` or by
  `Workspace::from_sorted(entries, max_nodes)`, which takes entries in
  path order and applies the same checks and the same node cap through
  the same linear code. Byte order of the full paths is the order
  `git ls-tree -r -z` lists a tree in; input out of order or with a
  duplicate is refused, never sorted silently. **Part 3 builds every
  snapshot with `from_sorted`**, the applied checkout's included: its
  paths come from the agent's workspace through `apply`, so they are as
  long and deep as `PATH_MAX` allows. In review a constructor that
  looked every ancestor up took 13 to 19 ms per path under one chain of
  1,900 directories, about an hour of CPU for a tree that fills the
  node cap; a test holds `from_sorted` under a deadline on that shape.
  `insert`, which has that cost, is test-only. `remove` keeps the
  invariants, so every `Workspace` encodes to bytes `decode` accepts.

### D3. Writing a workspace onto the host

`boneli_git_cli::materialize(workspace, dir, gitlinks, max_nodes)` writes a decoded
workspace for `git add -A` (part 3). It runs as the runner user on
agent-written entries, so it never trusts what is on disk and never
follows a symlink.

- **The target** must be a new, empty directory with mode 0700, checked
  through `symlink_metadata`, so a symlink to a directory is refused.
- **Checked before anything is written.** Repository metadata is refused
  (defense in depth: `diff` drops it first, D1), and so is an entry at or
  under a gitlink, a gitlink beneath an entry, and a gitlink that is
  repository metadata. The gitlink lookups for an entry stop at the
  length of the longest gitlink, so a deep agent-written path costs no
  more than that.
- **The node cap, again.** The workspace's nodes (D2) plus the
  directories the gitlinks add (each gitlink and its parents, once,
  unless an entry already implies them) must fit `max_nodes`, checked
  before the first write. A decoded workspace already holds the cap;
  this check also covers the gitlinks and a workspace built in code, and
  what `materialize` creates is exactly what it counted.
- **Parents** are created one component at a time with `create_dir`, and
  each directory once: the parents an entry shares with the previous
  entry lie inside their common prefix and were made for it, so only the
  rest are created. Creating every parent again for every entry costs
  O(depth^2) path lookups per entry; in review 500 entries under one
  chain of 1,900 directories took 150 s that way. Every call is
  path-based and the kernel refuses a path over `PATH_MAX` (4,096 bytes),
  so each call walks at most that many bytes, and the work is linear in
  the node count; a test holds the review's shape under a deadline. One
  that already exists must be a real directory by `symlink_metadata`;
  anything else is `NotADirectory`. D2 keeps every entry off the paths
  beneath another entry, so on a case-sensitive file system this check
  never fires for a valid workspace; it is the guard against a symlink
  entry that a case or normalization alias makes a parent, and against
  anything else on disk that the format rules out.
- **Files** are opened with `create_new` (`O_CREAT | O_EXCL`, which also
  refuses a symlink at the final name) with mode 0600, written, and then
  given 0644 or 0755 through the open file (`fchmod`), so the umask does
  not matter. A directory gets 0755 by a `chmod` of its path right after
  `create_dir` made it, so the umask does not matter there either; a test
  runs again in a child under `umask 077` to hold both.
- **Symlinks** are created with `std::os::unix::fs::symlink`, their target
  passed as raw bytes through `OsStrExt`, and never resolved.
- **Gitlinks.** Each gitlink of the base tree becomes an empty directory
  after the entries, so `git add -A` keeps the gitlink instead of
  recording its removal.
- **Order and failure.** Entries are written in path order. On an error
  the directory may hold part of the workspace; the caller removes it
  (part 3 removes its scratch directory on every path). Errors name the
  entry or gitlink by index, never by its path.
- **Same-user races.** The calls are path-based, so the kernel follows a
  symlink in an intermediate component, and "never follows a symlink"
  holds only while nothing else writes into the target during the call.
  Inside the private 0700 target only a process with the runner's own uid
  could plant one, and such a process already holds everything the
  runner holds, so the race crosses no permission boundary.

### D4. The git runner

Part 3 of #30. Every git process the adapter starts goes through one
runner (`src/run.rs`), so no call can forget a rule.

- **The binary** is an absolute path from the configuration; a relative
  one is refused at `open`, and `PATH` is never searched. The runner
  user's `PATH` is part of the host environment this decision shuts out.
- **The environment** is cleared, then holds exactly: `HOME` (an empty
  0700 directory under the root) and `XDG_CONFIG_HOME` (beneath it,
  absent), `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_ATTR_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`,
  `GIT_LITERAL_PATHSPECS=1`, `GIT_NO_REPLACE_OBJECTS=1`,
  `GIT_ALLOW_PROTOCOL` (`https`, or `https:file` for the test transport),
  `GIT_PROTOCOL_FROM_USER=0`, `LC_ALL=C`, `TZ=UTC`, the command-scope
  config below, `GIT_INDEX_FILE` on the calls that use a throwaway
  index (`read-tree`, `add`, `write-tree`, `apply`), and on `diff`'s
  calls (`read-tree`, `add`, `write-tree`, `diff-tree`) a throwaway
  `GIT_OBJECT_DIRECTORY` with the store's `objects` as the only entry of
  `GIT_ALTERNATE_OBJECT_DIRECTORIES` (D6). That entry is C-quoted, every
  byte outside `[A-Za-z0-9/._-]` as an octal escape, because git splits
  the variable at `:` and reads an entry that starts with `#` as a
  comment; a root's path may hold either. Why cleared rather
  than filtered: git reads dozens of variables (`GIT_DIR`,
  `GIT_CONFIG_PARAMETERS`, `GIT_SSH_COMMAND`, `GIT_ASKPASS`,
  `GIT_EXEC_PATH`, `GIT_INDEX_FILE`, ...), and a denylist misses the next
  one; an allowlist cannot. Without `PATH`, git puts its own exec path
  first and falls back to a fixed system path, which is what finds
  `git-remote-https`.
- **The command-scope config** (`GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_n`,
  `GIT_CONFIG_VALUE_n`) overrides every repository config, the store's
  included, and is one of the protected scopes `safe.bareRepository`
  obeys:
  - nothing named by config runs: `core.hooksPath=/dev/null`,
    `core.fsmonitor=false`, `core.untrackedCache=false`,
    `credential.helper=` (empty);
  - bytes, modes and links are stored as written: `core.autocrlf=false`,
    `core.symlinks=true`, `core.fileMode=true`, `core.ignoreCase=false`;
  - names that are `.git` on another file system fail:
    `core.protectNTFS=true`, `core.protectHFS=true` (D1's look-alikes;
    git 2.56.0 refuses `.GIT`, `.Git`, `git~1`, `GIT~1`, `.git.`,
    `.git ` and `.g<U+200C>it` with them, checked by
    `lookalikes_are_refused`);
  - `safe.bareRepository=explicit`, so only an explicit `--git-dir`
    names a repository;
  - transports: `protocol.allow=never`, `protocol.https.allow=always`
    (plus `protocol.file.allow=always` for the test transport),
    `protocol.version=2`, `http.followRedirects=false`, and
    `transfer.fsckObjects=true`, `fetch.recurseSubmodules=false`,
    `submodule.recurse=false`;
  - `http.lowSpeedLimit=1` and `http.lowSpeedTime=300`: below one byte
    per second for five minutes is a stalled connection, not a slow
    one, so a dead remote fails a fetch instead of holding the run;
    a lower time would cut off a server that pauses while it builds a
    large pack, a higher one only delays the failure;
  - no background work and stable packs: `gc.auto=0`,
    `maintenance.auto=false`, `pack.threads=1` (one delta search order,
    so a snapshot's pack is the same bytes every time),
    `pack.writeReverseIndex=false` (no `.rev` file next to the pack).
- **No discovery.** Every call except `git version` passes
  `--git-dir=<store>` and runs with the store as its working directory;
  only `read-tree` and `add` in `diff` also pass `--work-tree=<scratch>`.
  git never looks for a repository in a directory the agent wrote.
- **stdin** is written from its own thread and stderr read from another,
  so a large diff cannot deadlock against a full pipe
  (`large_diff_applies` moves more than 1 MiB each way).
- **Failure details** are git's stderr, prefixed with the subcommand, or
  `git <cmd>: exit status N, no error output` / `killed by signal N`
  when stderr is blank (ADR-004, D4). git's English messages are
  reported and never parsed. A failure also records whether git
  answered: it ran and exited with a non-zero status, or it gave no
  answer (it could not start, be waited for or read, or a signal ended
  it). Only the probe (D6) tells the two apart.
- **The rule for #19.** The token reaches git only as
  `http.<url>.extraHeader` through `GIT_CONFIG_KEY_n` and
  `GIT_CONFIG_VALUE_n` in the environment of the one git process that
  needs it: never in argv (which other users of the host can read in
  `/proc`), a file or the snapshot. #19 implements it; nothing in this
  part handles a token.

### D5. Transports

`fetch_base` checks the URL before any process starts, and passes it after
`--`, so it can never be read as an option.

- `Transports::Https`, the production setting, accepts only
  `https://<host>/<path>`: a lowercase scheme, a non-empty authority
  without userinfo (`@`), a `/` after it, and no whitespace, control
  character or NUL anywhere. Credentials never ride in a URL, and the
  test table refuses `http`, `ssh`, `git`, `ext::`, `file` and a leading
  `-` or space.
- `Transports::HttpsAndFile` also accepts `file:///<absolute path>` with
  no `.`, `..` or empty component, for the adapter's tests over local
  fixture repositories.
- The same set is enforced twice, by the check and by
  `GIT_ALLOW_PROTOCOL` plus `protocol.*.allow`, so a URL that slipped past
  the check still cannot reach another transport.

### D6. The operations

- **Stores and checkouts.** `fetch_base` makes a fresh bare store,
  `<root>/stores/<n>`, per call: `init --bare --template=` with an
  explicit `--object-format` (`sha256` for a 64-hex SHA), then
  `info/attributes` with `* -text -eol -filter -ident
  -working-tree-encoding`, then `fetch --depth=1 --no-tags
  --no-write-fetch-head --no-recurse-submodules -- <url> <sha>`. No
  remote, ref or `FETCH_HEAD` is written; the store holds the base commit
  and its tree, and its `shallow` file cuts the history. A checkout is a
  tree id in a store, so checkouts never change and an applied one shares
  its base's store. Ids are `checkout-<n>` from a counter that only a
  successful `fetch_base` or `apply` advances.
- **Failure classification.** When the fetch fails, evidence decides;
  git's message is never read. `UnknownCommit` reads as a wrong SHA, so a
  caller neither retries it nor alerts anyone; `Failed` stays the kind
  for what may pass on a retry or needs an operator. So `UnknownCommit`
  needs evidence that the commit is the input's fault:
  1. `ls-remote -- <url>`. A remote that does not answer, or that
     advertises the SHA, gives `Failed` with the fetch's error: then the
     commit exists, or the remote cannot be asked, and the fetch broke
     for another reason (a full disk under the root, an object the
     remote lost, a connection cut mid-pack).
  2. A remote that answers without advertising the SHA, the usual case,
     since the base of a bug is rarely a tip, gets a probe: `fetch
     --depth=1 --filter=tree:0 -- <url> <sha>` into a fresh bare
     repository `<root>/tmp/<n>`, through the same runner, environment
     and config as every call, and removed on every path, so no store
     sees it. Depth 1 cuts the parents and `tree:0` leaves out every tree
     and blob, so where the remote serves filters the pack is the commit
     object alone (in review, a non-tip commit of this repository from
     GitHub: a pack directory of 3,516 bytes). If the probe succeeds and
     `cat-file -t` there says `commit`, the commit exists: `Failed` with
     the first fetch's error. A full disk or a cut that hit the base's
     tree, and a tree or blob the remote lost, therefore no longer read
     as a wrong SHA.
  3. Only a probe that fails too, or that gets a tree, blob or tag (the
     wanted object is sent despite the filter), leaves `UnknownCommit`.
     A probe that cannot be set up (its `init` fails), or whose fetch or
     `cat-file -t` gives no answer from git (it cannot start, as on
     EAGAIN or ENOMEM at fork, or a signal ends it), is no evidence
     either way and gives `Failed`. Only an observed answer counts: git
     ran the fetch and refused it, or fetched an object that is not a
     commit.

  A remote that does not serve filters (`uploadpack.allowFilter` off)
  ignores the filter with a warning, and the probe is a full depth-1
  fetch of the same commit: no larger than the fetch that failed, so a
  failure costs at most one more fetch of that size, and one that
  depends on size fails the same way (the residual in Consequences).
  Then `cat-file -t` must say `commit` (a tree, blob or tag id is
  `UnknownCommit`). A fetch that `transfer.fsckObjects` refuses is
  `UnknownCommit` or `Failed` by the same rule; a bad tree under a
  commit that is not a tip is `Failed`, since the probe does not fetch
  the tree. The store is removed on every failure.
- **`read`** lists the path with `ls-tree -z --full-tree <tree> -- <path>`
  (literal pathspecs, so `*` and `:(top)x` are file names) and returns
  the blob for a regular or executable file, `None` for anything else.
- **`snapshot`** is the tree's files from `ls-tree -r -z` and one
  `cat-file --batch` (raw blobs, no smudge), gitlinks left out (their
  paths still get the path rule and the look-alike check below, since
  `diff` reads them and `apply` checks them), plus the
  generated `.git`: exactly `HEAD` (`ref: refs/heads/main`), `config`
  (fixed text without remote, credential, URL, http, include or hooks
  path; SHA-256 adds `extensions.objectformat`), `index` (from
  `read-tree` of the base tree: zeroed stat data, so deterministic),
  `shallow`, `refs/heads/main` (the base SHA) and one pack with its index
  from `pack-objects --revs` of the base commit. The pack holds what is
  reachable from the base, which the shallow boundary limits to the base
  commit and its tree. The `.git` is always the base's, also for an
  applied checkout, so `git diff` in the verify sandbox shows the fix.
  The entries are merged in path order and built with
  `Workspace::from_sorted` under the node cap (D2). A tree path the path
  rule refuses (a backslash, a blank name, non-UTF-8), a tree path that
  is repository metadata and a tree path with a component that is
  `.git` on another file system (the check `diff` makes, below) are
  `Failed`, naming the path, before anything is written: git only warns
  about a `.git` tree entry, and such an entry would otherwise merge into
  the generated `.git`; git and its fsck accept a look-alike outside
  git's HFS list, such as `.g<U+200B>it`, and every later `diff` of the
  checkout would refuse it.
- **`diff`** decodes the workspace under the node cap, drops metadata
  (D1), and refuses, as `Failed` naming the path, any path with a
  component that is `.git` on another file system, before it lists the
  checkout's gitlinks or writes anything (`src/lookalike.rs`). That is
  git's own NTFS form (`.git` or `git~1` in any case, followed only by
  dots and spaces, or by `:`) and its HFS form widened to every Unicode
  default-ignorable code point (`.git` in any case once those are
  removed): git's HFS list is a subset, and the full set also covers a
  case-insensitive file system that drops any ignorable code point from
  a name, where `.g<U+200B>it`, which git accepts, would be `.git`.
  Over-refusal costs little: no repository needs such a name, and git
  already refuses the narrower set. Then it writes the rest
  with `materialize` (D3) into `<root>/scratch/<n>`, and builds the new
  tree in a throwaway index under `<root>/tmp/<n>`: `read-tree <tree>`,
  `add -A`, `write-tree`. Every object these write goes to a throwaway
  object directory, `<root>/tmp/<n>/objects`, which reads the store's
  objects as its alternate, and `diff-tree` reads both; the store is
  only read. Without it every call left the workspace's new blobs and
  trees as loose objects in the store (`gc.auto=0`, and nothing removes
  a store), about one inode per new file per call: in review, three
  diffs of 2,000 new files added 2,003 files each, so the node cap
  bounded nothing across calls. `apply` still writes into the store,
  since its checkout lives there. `add -A` follows the workspace's
  `.gitignore`, so an ignored untracked file stays out and a tracked one
  stays in. The diff
  is `diff-tree -r -p --binary --full-index --no-renames --no-ext-diff
  --no-textconv --no-color --src-prefix=a/ --dst-prefix=b/`, empty when
  the trees are equal. Both directories are removed on every path, and
  each call has its own, so concurrent diffs of one checkout share
  nothing.
- **`apply`** of an empty diff issues a new id for the same tree.
  Otherwise `read-tree`, `apply --cached --whitespace=nowarn` (never
  `--unsafe-paths` or `--reject`) and `write-tree` on a throwaway index.
  git refuses a path into `.git` (also nested, and its own look-alikes:
  the NTFS forms and its HFS list), `..`, an absolute path and a file
  beyond a symlink, and applies all hunks or none. Then every path of
  the new tree (`ls-tree -r`, gitlinks included) gets the path rule and
  the look-alike check `snapshot` makes, and a refusal names the entry
  by its index in that listing and by its path: git accepts
  `.g<U+200B>it`, also as a rename target, and a non-UTF-8 name, a
  backslash or a blank name, and without the checks `apply` would issue
  a checkout that no `snapshot` or `diff` can read. Any failure is
  `Failed`, with no new checkout.

### D7. The git version floor

`GitCli::open` runs `git version` and refuses anything older than
2.39.1 (`MIN_GIT_VERSION`), comparing the first three components as
numbers (`2.100.0` is newer than `2.39.1`; `2.43.0.windows.1` reads as
2.43.0; an unreadable version is refused).

- **Why 2.39.1.** It is the 2.39 release that carries the fix for
  CVE-2022-23521, integer overflows in `.gitattributes` parsing that can
  give arbitrary heap reads and writes (the git release notes of 2.30.7,
  which 2.39.1 merges, describe it). `diff` runs `git add` over a
  workspace whose `.gitattributes` the agent wrote, and the attributes
  from the tree reach git through `read-tree` too, so a git without the
  fix is a host code execution path. The same release fixes
  CVE-2022-41903 (`--format` padding), which this adapter does not
  reach.
- **Why not the patched maintenance releases.** 2.30.7, 2.31.6, 2.32.5,
  2.33.6, 2.34.6, 2.35.6, 2.36.4, 2.37.5 and 2.38.3 carry the same fix,
  but a version string cannot tell a distribution's patched 2.34.1 from
  an unpatched one, so the floor fails closed at one version that
  certainly has it. The features the adapter uses are older:
  `GIT_CONFIG_COUNT` (2.31), `GIT_CONFIG_GLOBAL` (2.32),
  `--no-write-fetch-head` and `--object-format` (2.29), the probe's
  `tree:0` filter (2.20). A host with an
  older git installs a newer one and names it in the configuration.
- **`open`** also refuses a relative git path, a relative root (every
  call runs with its store as the working directory and the same path in
  `--git-dir`, so a relative root would name another directory there and
  every `fetch_base` would fail) and a root that exists; it
  creates the root with mode 0700 and its `home`, `stores`, `scratch`
  and `tmp` directories, and removes the root again when the version
  check fails.

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
- The workspace codec lives in the adapter crate, and nothing may depend
  on an adapter. #8, which copies a snapshot into a sandbox and exports a
  workspace from one, needs the same codec: when it does, it moves
  `Workspace` and `materialize` into a support crate and passes the path
  rule (`RelativePath::parse` and `is_repository_metadata`) in as a
  validator, so the support crate stays generic.
- An empty directory, a FIFO, a device or a hard link in the sandbox
  cannot be expressed in a workspace (D2). #8 decides how the export
  treats them; nothing the format cannot carry reaches `diff`.
- A base tree with a path the workspace cannot carry, or with a component
  that is `.git` on another file system, fails `snapshot`, and with it
  the run, before a sandbox starts rather than at every `diff` after it. This repository is one: at the commit the network
  test fetches, an architecture-checker fixture has a backslash in its
  name, and the test pins that the snapshot names it. Widening the path
  rule is a change to D1 and D2, not made here. ADR-018 closes this limit
  for backslash, blank and non-UTF-8 paths; a component that is `.git`
  on another file system stays refused.
- A failed fetch of a commit the remote does not advertise as a tip
  costs one more fetch, the probe (D6). The residual: a remote that
  answers `ls-remote` and then fails both fetches still reports
  `UnknownCommit`, also when the real cause is a full disk (the probe
  of a remote that ignores `--filter` is a full depth-1 fetch and meets
  the same limit) or a connection cut twice; git reports those causes
  only in English. The port's doc comment on `GitError::UnknownCommit`
  says so: a caller that sees `UnknownCommit` for a SHA it got from the
  forge may retry once before it reports the SHA as wrong.
- The adapter never removes a store; `<root>` grows by one depth-1 store
  per `fetch_base` until whoever owns the root removes it (the
  composition roots, #32 and #33).
- A host needs git 2.39.1 or newer (D7); a long-term-support
  distribution with an older, patched git needs a newer git installed.

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
- **Filtering the host environment instead of clearing it.** A denylist
  of the variables git reads misses the next one git adds; the cleared
  environment plus an allowlist cannot (D4).
- **Running git in the scratch directory without `--git-dir`.** Discovery
  would find nothing there after metadata is dropped, but it would also
  walk up into whatever repository holds the root; an explicit
  `--git-dir` with the store as the working directory needs no such
  argument (D4).
- **tar as the workspace format.** A tar stream has many encodings of one
  tree (header variants, pax and GNU extensions, hard links, devices,
  directory entries in any order), so it is not canonical, and the tar
  reader of `boneli-oci` lives in another adapter, which this crate may
  not depend on. The length-prefixed format needs a few dozen lines and
  has exactly one encoding per tree.
- **`MemoryGit`'s snapshot format.** It has no kinds, so it cannot carry
  the executable bit or a symlink, and it is that adapter's own (ADR-004).
- **An ancestor check by map lookup.** Simpler, but quadratic in the path
  length on hostile input (D2).
- **A rule that also matches look-alikes** (case-folded `.git`, 8.3 short
  names) in the core. The core cannot know the file system the pull
  request will be checked out on, so look-alikes stay content there; the
  adapter, which does write onto a file system, refuses them (D6).
- **Leaving look-alikes to git's `protectNTFS`/`protectHFS` alone.** They
  check the names `add` records, after git has walked the tree and
  looked up `.git` in every directory, which is too late on a casefold
  scratch directory (D1).
- **Refusing a case-insensitive root at `open`**, as `boneli-oci` does
  with a probe (ADR-009). It would cover aliasing forms nobody listed, but
  its test needs a tmpfs `casefold` mount in a user namespace, which the
  CI job of this crate does not prepare; the name refusal holds on every
  file system and is tested on every host.
- **Writing `diff`'s objects into the store and pruning them after.**
  `git prune` would also take objects a concurrent `apply` on the same
  store has written but not yet referenced; a throwaway object
  directory per call shares nothing.
- **Classifying a fetch failure by git's message** (`not our ref`,
  `No space left on device`). Messages change between versions and
  locales; this ADR reports them and never parses them (D4).

## Accept when

Part 3 of #30 merges with `GitCli` passing the whole `Git` suite,
`workspace-metadata-inert` included, on a fixture repository whose
tripwire sentinel is unique to each fixture and sits in the test's own
temporary directory, outside the adapter root. The same PR's
`metadata_fixture_trips_a_discovering_git` must fail that clause at
`nothing-ran` through a wrapper that runs `git add -A` with discovery
inside the unpacked workspace and then deletes that working directory,
as the adapter does, so the trip is seen only through the sentinel.
That proof runs twice, once with only the hook entry and once with only
the `core.fsmonitor` entry, and each run must fail at `nothing-ran` on
its own. Git ignores a hook that is not executable, so the hook entry
must reach the workspace with its executable bit set; a GitCli that pins
fsmonitor off but still runs workspace hooks would otherwise pass.

Met on 2026-11-17 by part 3's PR: `git_cli_passes_contract` passes the
whole suite over `file://` with a sentinel directory per test in that
test's own temporary directory (the `Tripwire` is passed once per suite
run, so its sentinel is per run, which is per test), and
`metadata_fixture_trips_a_discovering_git` fails the clause at
`nothing-ran` with the hook entry alone (written executable by the
test's `edit`), with the `core.fsmonitor` entry alone, and with both.
