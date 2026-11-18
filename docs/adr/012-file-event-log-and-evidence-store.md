# ADR-012: boneli-store-fs, the run event log and evidence store on the filesystem

- Status: accepted
- Date: 2026-11-17

## Context

Issue #4 builds `boneli-store-fs`, the filesystem adapter of two ports of
ADR-004 (D1): `EventStore`, the append-only log of every run, and
`Evidence`, the content-addressed store of the reproduction test, the
analysis and the diff. ADR-004 left two formats to this issue: "the log
format and versioning" (Consequences) and the evidence reference format
(`crates/boneli-app/src/evidence.rs`). It also fixed what the evidence
store must guarantee: a reference is the digest of the content, and `get`
re-derives it from the bytes it returns, so a blob changed on disk after
verification never reaches the forge (D9).

What is at stake:

- The store writes on the host as the runner user, who holds the git
  token, and its `get` check is what keeps unverified bytes away from the
  forge. That is why the operator put `boneli-store-fs` on the
  always-review list at #4 STOP 1.
- The log is the audit trail of a run and the source a re-run reads its
  triage questions from (ADR-004, D6), so whoever can rewrite it chooses
  what the agent is asked next.
- A run replays from its log (`boneli_app::store::replay`), and a resumed
  run (#33) will continue from it, so every event the store acknowledged
  must survive a crash, and nothing it did not acknowledge may be read as
  accepted.

The decisions below were settled at #4 STOP 1 (decisions 1 to 6 of the
plan; all six as recommended).

## Decision

### D1. The root and the lock

`FsStore::open(root)` applies the root rules of ADR-009 D8 ("The store
root"), without the overlay rule that forbids `,`, `:` and `\`: no mount
option is built from this root. The root must be absolute and must not
have a `.` or `..` component; a missing root is created `0o700`, but only
after its existing ancestors pass the check, and then resolved. It must
be a directory owned by the uid of
`/proc/self` with no group or other permission bits, and its ancestors
must pass sshd's `StrictModes` rule: each owned by root or the caller and
not writable by its group or others unless it is sticky; the filesystem
root is checked for its mode only. `open` then takes an exclusive
`std::fs::File::try_lock` on `<root>/lock` (mode `0o600`, held for the
store's lifetime; `WouldBlock` is `OpenError::InUse`), creates `runs/` and
`evidence/sha256/` with mode `0o700`, refuses them if they are not
directories (a symlink to another directory, for example), removes every
file in them whose name starts with `.tmp-` (a removal that fails is
skipped), and `fsync`s the root and the three directories.

Why no `.` or `..`: the check before creation finds the existing
ancestors by walking the root's text, and creation resolves `..` against
the filesystem, so the two can disagree. `<d>/missing/../gw/store` checks
`<d>`, the deepest existing ancestor of the text, while creation makes
`<d>/missing` and `<d>/gw/store`, under `gw` whatever its mode; the check
of the resolved root then refuses it, but the directories stay (review
of #67). The rule is lexical and runs before any filesystem access, on
the path's bytes split at `/`, because `Path::components` drops every `.`
but a leading one. Refusing `.` as well costs nothing (a root never needs
one) and keeps the rule one sentence. Rejected: resolving the deepest
existing ancestor and checking each component before creating it, which
is longer and still has to define what `..` means past a component that
does not exist yet.

Why the rules matter here: the log has no integrity check of its own
(D7), so whoever can rename an entry of an ancestor can swap the root
after `open` and rewrite the audit trail and the questions of a re-run.
Why `0o700` and `0o600`: only the runner user reads or writes the store;
the log holds ticket text and the blobs hold the customer's code.

**Two copies.** The checks are copies of `own_uid`, `private_dir` and
`check_ancestors` in `crates/boneli-oci/src/store.rs`, and the root tests
copy `boneli-oci`'s matrix (`crates/boneli-oci/tests/store.rs`). An adapter
cannot depend on another adapter (`tools/check_architecture.py`, rule
`graph-adapter`), and extracting them would have put two always-review
crates and a role change in `tools/architecture.toml` into a medium issue
(decision 6). A fix to one copy goes into the other; a comment at each
copy names the other. Extracting them into a shared support crate is
#66. The `.` and `..` rule above is the first such fix: this PR adds it
to `boneli-oci`'s `check_root_text` too, with the same test
(`root_dot_components_refused` in both crates). It narrows ADR-009 D8's
root rules for that crate; ADR-009 is accepted and keeps its text, so
this ADR is the record of the change.

**The lock and the MSRV.** `File::try_lock` is stable since Rust 1.89.0,
and clippy's `incompatible_msrv` refuses it under `-D warnings` while the
workspace declares 1.87, so the workspace `rust-version` moves from 1.87
to 1.89 (decision 4). ADR-009 rejected an `flock` for exactly this reason
and no other: in D8, "Cleanup of temporary names", the last paragraph says
"Rejected: an `flock` on a per-process lock file, which decides liveness
in every namespace, because std's `File::lock` needs Rust 1.89 (the MSRV
is 1.87) and the alternative is a new `unsafe` wrapper in `boneli-sys`".
The cost is the declared floor only: CI and the hosts build with current
stable, there is no MSRV job and no release yet (#22), and ADR-009 set the
precedent with 1.85 → 1.87. This ADR does not change `boneli-oci`'s
liveness scheme; whether it should now use the lock is a question for
that crate. One side effect: clippy suggests let-chains (stable in 1.88)
and `as_chunks` once the MSRV allows them, so the PR collapses 14 nested
`if let`s and replaces 2 `chunks_exact` loops with `as_chunks` across the
workspace, with no change in behavior, to keep `-D warnings` green.

What the lock buys: one store per root, enforced, so three gaps that
would otherwise be documented assumptions become rules. Two processes
cannot append to one run; temporary names (D2) cannot collide across PID
namespaces; and `open` can remove every temporary file without judging
whether its owner is alive, the part of `boneli-oci` that took three
review rounds on #60. Weak spot: `flock` is advisory and may be emulated
or missing on network filesystems, which are not supported (D7); two
runners need two roots.

### D2. Names

- **Run logs** are `runs/<hex>.log`, where `<hex>` is the SHA-256 of the
  run id's UTF-8 bytes in lowercase hex. The header carries the id, and
  `load` and `append` require it to equal the requested id (decision 3).
  Why: the domain leaves run ids opaque and the `Ids` adapter does not
  exist yet, so the store must take any id. Hashing removes the whole
  class of hostile names (traversal, separators, NUL, length, case
  folding, Unicode normalization) by construction, so the `hostile-run-ids`
  clause holds in its stronger branch (every id stored, none
  `InvalidRunId`), and the header check catches a log copied or renamed
  onto another run's name. The price: `ls runs/` is unreadable; the id is
  on each file's first line.
- **Blobs** are `evidence/sha256/<hex>`, and the reference is
  `sha256:<hex>`, 64 lowercase hex digits, the digest form ADR-009
  already uses. `get` accepts exactly that form and returns
  `InvalidReference` for anything else (uppercase hex, another length,
  another prefix, whitespace, a path) before any path is built. The hash
  is `boneli_https::Sha256`, ring's SHA-256 (ADR-009, D6, which records
  that #4 uses the same type; ADR-004 D9 planned `sha2`, and ADR-009 D6
  is the record of the swap).
- **Temporary names** are `.tmp-<n>`, `<n>` from a per-store counter,
  created with `create_new`. The lock (D1) makes the store the root's only
  writer, so a counter is unique.

Every name the store makes is lowercase ASCII of fixed form, at most 68
bytes (64 hex digits and `.log`), far below `NAME_MAX` (255), so case
folding, normalization, dot names and traversal cannot arise, and no
casefold probe is needed. ADR-009 D8 needed one because layer contents
choose their own names.

### D3. The log format, version 1

Newline-delimited JSON through `boneli-json` (ADR-008).

- **Line 1, the header:**
  `{"format":"boneli-run-log","version":1,"run":s,"budget":{"cost_micro_usd":n,"duration_ms":n},"previous":null|s}`.
- **One line per accepted event:** `{"event":"<RunEvent variant>", ...}`,
  the variant's fields in declaration order and named as in
  `boneli_domain`. Nested values are objects: `ticket`, `usage`,
  `checks`, `verdict` (`{"kind":"Ready"}` or
  `{"kind":"NeedsInformation","questions":[...]}`), and `citations`, an
  array of `{"path","line","sha","quote"}`. Enum values are their variant
  names. Numbers are `u64` lexemes, decoded with `as_u64`; a citation's
  `line` also goes through `u32::try_from`. `CommitSha::parse` and
  `EvidenceRef::parse` run on decode.
- **Strict decoding.** A line fails on a wrong type, a missing or unknown
  key, an unknown variant, a number that is not a `u64` (`1.0`, `1e3`,
  `-1`, `18446744073709551616`), a `format` other than `boneli-run-log`
  or a `version` lexeme other than `1`, or a header that names another
  run. On top of that, a stored line must be byte for byte the encoding
  of what it decodes to. Whitespace, a `\r` before the `\n`, another key
  order and escapes the serializer never writes (`e`, `\/`) parse to
  the same value, so without this they would pass; with it, every line
  the store wrote passes (the serializer is deterministic, ADR-008 D7) and
  nothing else does. The plan required strict decoding; the canonical
  check is the shortest way to make "strict" mean one encoding per
  event, and `non_canonical_line_fails_closed` pins it.
- **Exhaustive codec.** The encoder matches `RunEvent` and the decoder
  matches `EventKind` exhaustively, so a new event variant does not
  compile until the codec handles it. A new value of a leaf enum
  (`TestStatus` and the others) does not compile in the encoder; if it is
  not added to the decoder's list of values, its append fails the
  self-check below, closed.
- **Self-check.** `append` and `create` serialize the line, check its
  length, parse it with the log's limits and decode it, and write only if
  that gives back the same event. Whatever is written therefore loads, and
  an event over a limit is `Unavailable` with the file unchanged.
- **Versioning.** A reader that meets a `version` it does not know fails
  closed; a format change takes a new version and a reader for both.

**Limits** (`boneli_json::Limits`, ADR-008 D5: no defaults, every number
justified):

- `MAX_LINE_BYTES = 8_388_608` (8 MiB, without the `\n`). The largest
  event is `TicketReceived`: agent outputs go to `Evidence`, and events
  carry their references. The size of a ticket is set by the tracker, so
  the plan asked for each tracker's cap, checked against its primary
  source (2026-11-17):
  - **GitLab:** verified. Issue descriptions are validated by *byte*
    size against the instance setting `description_and_note_max_size`,
    whose default is `1.megabyte`, and the title by length, at most 255
    characters. Source: `app/models/concerns/issuable.rb` lines 35, 82 and
    85 and `app/models/application_setting.rb` lines 1081 and 1085 at
    gitlab-org/gitlab commit `91125c60b2ff50036bbc5b555f6ce4bc71dc095f`;
    Rails defines `megabyte` as 1024 × 1024 bytes
    (`activesupport/lib/active_support/core_ext/numeric/bytes.rb`). The
    instance-limits page of the GitLab docs says "~1 million characters /
    ~1 MB"; the code is the precise source. The setting is only checked
    to be a positive integer, so a self-managed instance can raise it
    without bound.
  - **Sentry:** documented, approximately. "Events that exceed 200KB
    compressed or 1MB decompressed will be rejected"
    (docs.sentry.io, Concepts, Data Management, Size Limits), with the
    note that the limits may change; a ticket built from one event is
    bounded by it.
  - **GitHub:** not verified. Neither the REST documentation of the issue
    endpoints nor the OpenAPI description
    (`github/rest-api-description`, `POST /repos/{owner}/{repo}/issues`:
    `body` is a plain string with no `maxLength`) states a cap.
  - **Jira:** not verified. No primary Atlassian source for the
    description field's limit was found.

  So no cap holds for every tracker, and the number does not rest on one.
  It is derived from the one verified default and from what an oversized
  ticket costs:

  - The JSON encoding of a string grows by at most 6 times its UTF-8
    bytes: a control character (1 byte) becomes `\u00XX` (6 bytes), `"`
    and `\` become 2 bytes, everything else is copied (ADR-008, D7).
    GitLab's default body of 1,048,576 bytes is therefore at most
    6,291,456 bytes encoded, its 255-character title at most 1,530 bytes
    (a character is 1 to 4 bytes raw, and the 6 times bound applies to
    1-byte control characters), and the key (a short tracker reference), the base SHA and the fixed
    keys about 200 bytes more: about 6,293,200 bytes, under 8,388,608
    with 2,095,000 bytes to spare. Rounding up to the next power of two
    leaves that headroom for an instance that raised its setting to about
    1.39 million bytes, and for a Sentry event's 1 MB.
  - A ticket above the limit is refused closed and early: `DebugTicket`
    appends `TicketReceived` right after `create`, before any job runs
    (ADR-004, D5), so such a run fails with `Store(Unavailable)` having
    spent nothing, and an intake that must take larger bodies truncates
    them first. Neither GitHub's nor Jira's cap therefore changes what
    the store guarantees.
  - What a larger limit costs: peak memory per line is at most
    2 × `MAX_LINE_BYTES` plus 136 B × `MAX_VALUES` (ADR-008 D5), here
    16 MiB + 8.5 MiB ≈ 24.5 MiB, and `append` re-reads the log (D4). At
    64 MiB it would be about 136 MiB per line for tickets no verified
    tracker default produces.
- `MAX_DEPTH = 3`: the depth of the schema itself, event → `citations` →
  citation, and event → `verdict` → `questions`. A lower limit rejects
  valid events, a higher one admits nesting no event has.
  `schema_depth_is_the_limit` measures the deepest line of every kind on
  the parser.
- `MAX_VALUES = 65_536`. The largest legitimate counts are 7 + 5 per
  citation (`RootCauseProposed`) and 8 + 1 per question
  (`TriageFinished`), so the limit admits 13,105 citations or 65,528
  questions, orders of magnitude above what an analysis or a triage
  produces. Why 2^16: it is where the per-value term of ADR-008 D5's peak
  memory (136 B × 65,536 = 8.5 MiB) matches the byte term
  (`MAX_LINE_BYTES` = 8 MiB), so neither term dominates the 24.5 MiB
  bound. A lower limit fails a long citation list at append (closed);
  a higher one raises the cost of a hostile line without admitting any
  event a run produces.

### D4. Durability

- `create`: write the header line to `runs/.tmp-<n>`, `sync_data`,
  `hard_link` it to the final name (`EEXIST` is `AlreadyExists`, so a
  name never appears half written and two creators cannot both win),
  `fsync` `runs/`, then unlink the temporary name.
- `append`: under the store's log mutex, read the log (D5), encode and
  self-check the line, truncate an unacknowledged tail, write the line
  with one `write_all` on an `O_APPEND` handle, `sync_data`, and only
  then return `Ok`. On a write or sync error it tries `set_len` back to
  the acknowledged length and returns `Unavailable`. Either way the log
  stays a prefix of the events the run accepted (ADR-004, D5): after a
  failed sync the kernel may still write the line, but `DebugTicket`
  appends an event only after `Run::handle` accepted it, so such a line
  is an accepted event and the log still replays.
- `put`: write `evidence/sha256/.tmp-<n>`, `sync_data`, rename it onto the
  final name, `fsync` `evidence/sha256/`, then return the reference.
- `put` of bytes already stored (D6): `sync_data` the existing blob
  through the descriptor it was verified on and `fsync`
  `evidence/sha256/`, then return the reference; a failed sync is
  `Unavailable`. Why: the writer that renamed the blob into place may
  have died before its directory sync (or that sync failed and its `put`
  returned an error), and the runner restarted without a reboot. The
  blob then reads and verifies from the page cache while its directory
  entry is not durable, and a run that logs its reference after the
  dedup `put` could leave a durable event pointing at a blob that power
  loss removes (review of #67). The cost is one file sync and one
  directory sync per dedup `put`, the same as a fresh one. Pinned in
  part only: `dedup_put_syncs_the_existing_blob` makes the directory
  unreadable so its `fsync` cannot open it, which catches a missing
  directory sync; a missing `sync_data` of the blob is not caught by
  any test today. Power loss cannot be produced in a test, and a
  failing `fdatasync` on a readable regular file needs fault injection
  the workspace does not have yet: an unprivileged per-thread seccomp
  filter that returns `EIO` for `fdatasync` produces it (shown outside
  the workspace in the review of #67), and a test that pins the blob
  sync with it becomes possible once `boneli-sys` can install seccomp
  filters (#6).
- Why every acknowledgement is durable: `DebugTicket` logs a reference
  right after `put`, so a blob that is not yet durable could leave a
  durable event pointing at nothing; a lost `PullRequestOpened` or
  `QuestionsPosted` would make a resumed run (#33) open a second pull
  request or post the questions again.
- Cost on the delivered path: 9 events (ADR-002's delivered scenario,
  no retry loop) plus 1 create and 3 puts (test, analysis, diff): 13 file
  syncs and 4 directory syncs per run, against jobs that take seconds to
  minutes. Measured with `append_latency` (`#[ignore = "measurement"]`;
  1,000 appends of a small event to one log, each with its `fdatasync`
  and the re-read of the log so far; release build; btrfs with
  `compress=zstd:1` on LUKS on the dev host's NVMe SSD; two runs): median
  2.09 ms and 2.15 ms, maximum 4.06 ms and 7.97 ms. A delivered run's
  syncs therefore cost tens of milliseconds.
- The log mutex is recovered when poisoned, as in ADR-004 D8: disk state
  commits only through `hard_link`, `sync_data` and rename, and an
  interrupted append leaves at most an unacknowledged tail.
  `poisoned_lock_recovers` pins it.
- The platform must honour `fdatasync`; some virtual disks acknowledge
  early. That is outside the store's control and an assumption of this
  design.

### D5. The unacknowledged tail and corruption

`\n` is the last byte of every line and is synced before `Ok`, so the
bytes after the last `\n` belong to an append that never returned `Ok`.
`load` ignores them, even when they parse (an unterminated line is never
trusted, as in ADR-008 D8), and `append` truncates them first (decision
5). Failing closed instead would strand every run whose process died
mid-append, a previous run a re-run must load included, and the bytes
dropped were never acknowledged. Truncating is safe only because the lock
makes the store the single writer (D1).

Such a tail is at most `MAX_LINE_BYTES` long: an append writes one line
of at most that much plus its `\n`, and truncates any earlier tail before
it writes. A longer tail, a file with no complete header line, and any
complete line that does not parse or decode (D3) are `Unavailable` for
both `load` and `append`; neither then modifies the file, and nothing
repairs it. A filesystem that persists a file's size before its data
could turn an interrupted append into a complete line of zeros; that line
fails to decode, so it fails closed, never silently.

Error details name the file (`runs/<hex>.log`) and the line number and
never echo log content, which can hold ticket text (ADR-008, D9): decode
errors are a type with static text and static key names only.

### D6. Evidence I/O

`get` checks with `symlink_metadata` that the path is a regular file; a
symlink, directory, FIFO or device is `Corrupted` and never opened, so a
FIFO cannot block the open and `/dev/zero` cannot be read forever. It
then opens the file, requires its `fstat` to show a regular file with the
same device and inode, reads at most its size plus one byte and requires
exactly its size, and hashes the buffer it returns, not the file. A
mismatch is `Corrupted`. The logs are opened the same way.

`put` returns the reference when the existing file under that name
verifies, after syncing it and its directory, and otherwise writes it
again (D4). Rewriting is always safe,
because the new bytes hash to the name, so a tampered blob is repaired by
the next `put` of the genuine bytes, and concurrent puts of the same
bytes rename equal files onto one name.

### D7. What this does not protect

- Per-line checksums or a hash chain on the log: rejected. A writer with
  the runner's uid recomputes them, which is ADR-004 D9's argument
  against side records, and media corruption already fails the JSON
  decode. An HMAC: rejected, its key would sit with the same uid. The
  log's protection is the root rules (D1).
- The window between `symlink_metadata` and `open` (D6): a file swapped
  in it for a FIFO could block the open. Only the runner's uid can write
  inside the root (D1), and the `fstat` check catches every other swap.
- Network filesystems are not supported: `flock` may be emulated or
  missing there, and `hard_link` may be missing.
- Encryption at rest, retention and garbage collection of blobs, and
  listing runs are out of scope.

## Consequences

- Runs survive a restart of the runner: every acknowledged event and blob
  is on disk, and a run replays from its log
  (`domain_corpus_replays_after_reopen`; `debug_ticket_on_fs_store_replays`
  in `boneli-replay-check`, which also requires the logs, results and job
  requests on the file store to equal the in-memory run's up to the
  form of the evidence references).
- The `EventStore` and `Evidence` contracts pass unchanged; no clause is
  added, so the mutant table and the replay output stay as they are.
- `InvalidRunId` is never returned: every id is stored in isolation (D2).
- One process per root (D1). Two runners need two roots, and a second
  `open` fails with `InUse` instead of waiting.
- The workspace MSRV is 1.89 (D1).
- The root rules exist twice until #66 (D1).
- A ticket whose encoded event exceeds 8 MiB fails its run at the first
  append (D3); an intake for larger tickets must truncate them.
- `append` re-reads the whole log: a few KiB on today's state machine
  (at most 10 lines a run), at worst 10 × 8 MiB parsed under the limits.
- `boneli-store-fs` is on the always-review list (#4 STOP 1).

## Alternatives considered

- **Run names as an allowlist (`[a-z0-9-]{1,64}`), others
  `InvalidRunId`:** readable names, but it couples the store to the `Ids`
  adapter that does not exist yet and keeps a name class to get right;
  hashing removes it (D2).
- **A binary framed log:** needs its own framing parser and torn-record
  rules, while `boneli-json` already has a strict parser with limits,
  never writes a raw line feed inside a line (ADR-008, D7) and reports an
  unterminated last line (D8). SQLite is banned (`rusqlite` in
  `deny.toml`).
- **Failing closed on an unacknowledged tail until #33:** strands every
  run whose process died mid-append, to protect bytes that were never
  acknowledged (D5).
- **No lock:** one writer per run becomes an assumption, temporary files
  are never swept (judging their owners' liveness is `boneli-oci`'s
  hardest part), and the tail could not be truncated safely (D1, D5).
- **A directory per run** (header file, one file per event): more
  directory syncs per event and a torn state across files instead of one
  tail.
- **Per-line checksums, a hash chain or an HMAC:** D7.
- **Extracting the root rules now:** D1; tracked in #66.
- **`O_TMPFILE`, `openat` and friends** for the temporary files and a
  descriptor-relative root: they need new `unsafe` wrappers in
  `boneli-sys`, as ADR-009 D8 notes for the same choice; with every
  ancestor closed to others (D1), a path cannot be swapped.
- **Another language:** the workspace is Rust, and the store is an
  adapter of Rust ports; nothing here favours another language.
