# ADR-030: One file-lock type for the workspace

- Status: proposed
- Date: 2026-11-24

## Context

Two crates take `flock` locks through std's `File::try_lock*`:
`boneli-store-fs` on `<root>/lock` (ADR-012, D1) and `boneli-oci` on the
owner, layer and trim lock files under `<root>/locks/` (ADR-025, D3).
Each held its own copy of the same release rule: `StoreLock` in
`crates/boneli-store-fs/src/root.rs`, and `Held` plus `Reopened` in
`crates/boneli-oci/src/lock.rs`. Each copy unlocks explicitly before the
close (ADR-026), unlocks only in the process that took the lock, where
that process is a pid within a pid namespace (ADR-028), and wraps the
descriptor in its owning type at the moment the lock is taken, so no
path releases a lock by the close alone (#98, PR #106).

The rule text is spread over ADR-025 D3, ADR-026 and ADR-028, and the
code over two crates with an owner type each (`Owner` and `LockOwner`).
Merging them was deferred to #97 at #98 STOP 1, but #97 (PR #101)
changed `boneli-store-fs` only, and #106 then added `Reopened` to the
`boneli-oci` copy. Two copies of an owner check can drift on the next
fix to it: a fix that reaches one crate leaves the other able to steal a
lock or to keep one held. #109 consolidates the copies; it does not
change the rule.

## Decision

### D1. The rule, stated once

Every file lock in the workspace follows this rule.

- **A lock is released by `LOCK_UN` before its file closes.** A `flock`
  lock belongs to the open file description, not to one descriptor.
  `fork`, and the `clone` behind `posix_spawn`, give the child a copy of
  every descriptor, all pointing at the same descriptions, and the child
  holds them until it execs; the sandbox's launch runs its setup in that
  window. A close while such a copy lives releases nothing until the
  child's exec. That was the `InUse` flake of #94 (a reopen of a store
  right after its drop failed in 200 of 200 stress runs, one reopen in
  four or five) and the arm64 flake of #99 (a trim right after a lease's
  drop found the layers still pinned; 125 of 300 rounds kept a lock
  before, none of 6,000 after). `LOCK_UN` acts on the description,
  whatever copies of it exist.
- **Only the process that took a lock unlocks it.** A child forked
  without exec runs on a copy of its parent's memory, so an unwinding
  panic there can drop a copy of a lock value; an unlock from it would
  release the parent's live lock (a second store `open` would then
  succeed and sweep the first one's temporary files; a trim could evict
  a layer under a running sandbox). Such a child only closes its own
  copy.
- **The owner is the pid and the pid namespace**, read when the lock is
  taken and again when it is released: `std::process::id()` and the
  `(st_dev, st_ino)` of `/proc/thread-self/ns/pid`, the pair the kernel
  names a namespace by. The pid alone is not enough: the sandbox child
  is pid 1 of a new pid namespace (`CLONE_NEWPID`), and so is a runner
  that is its namespace's init, so their ids match (#97). The namespace
  alone is not enough either: a plain forked child shares it.
  `thread-self`, not `self`, because `/proc/self` fails once the main
  thread has exited (#35), and every thread of a process shares its pid
  namespace, so the reading does not depend on the dropping thread. The
  path is shorter than std's 384-byte stack buffer, so the read in an
  unwinding child allocates nothing and costs one `stat`.
- **An unreadable namespace link, at either end or at both, keeps the
  lock**, and only the close runs. With the pid alone a pid-1 runner and
  its sandbox child are not told apart, and the review of PR #101
  reproduced the lock theft there. The cost is #94's `InUse` window on a
  host whose `/proc` hides the link, which no supported deployment uses
  (`/proc/thread-self` exists since Linux 3.17, the sandbox needs 5.19,
  ADR-007). The kernel gives a process one pid namespace for its
  lifetime, so the real owner reads the same pair at both ends.
- **A lock is wrapped from the moment it is taken**: the owning value is
  built in the expression that receives the `Ok` of `try_lock*`, and
  nothing fallible runs between the two. A lock on a lock file that was
  replaced before `boneli-oci`'s inode check, and a lock an error
  abandons, are released by the unlock too (#98).
- **An unlock error is ignored.** The close that follows still releases
  the lock when no child holds a copy, and a drop has no caller to report
  to.
- **A lock handed on is released by whoever holds its descriptor.**
  `Lease::pin_descriptors` hands pins to a holder process on purpose
  (ADR-025, D2); from then on its `close` or `LOCK_UN` releases them.
- **Lock files are opened by std, with `O_CLOEXEC`.** After a crash no
  unlock runs, and the kernel releases a lock when the last descriptor of
  its description closes; the only copies besides the process's own are
  held by children between fork and exec, and each closes at that
  child's exec. So after a crash a lock outlives its process by at most
  one child's fork-to-exec window. The tests pin the flag, not the
  window, whose length depends on the host.

### D2. Two types and one release in `boneli-private-dir`

The module `boneli_private_dir::lock` holds the rule:

- `FileLock { file, owner }`: a lock its process keeps. `try_take(file,
  kind)` tries once, `take_until(file, kind, deadline)` waits (D3);
  `file()` lends the file. Its drop releases it.
- `HandOff { files, owner }`: locks taken to be handed to another
  process. `try_take(&mut self, file, kind)` locks and keeps the file at
  once (the room for it is reserved before the lock, so the push cannot
  allocate); `last()` lends the file taken last; `hand_on(self)` gives up
  the descriptors as `Vec<OwnedFd>` and cannot fail. Dropped before
  `hand_on`, it releases every lock it took.
- One private `release(owner, files)` with the one owner check, `owns`,
  called by both drops. A fix to the check is a fix in one place.
- `Kind { Shared, Exclusive }` and `TakeError { Busy, Io }`, where
  `WouldBlock` is `Busy` and every other error `Io`. The consumers map
  `TakeError` to their own errors privately, so the support crate stays
  out of their public APIs (ADR-021, D5).

The lock-file protocols stay with their crates, because merging them
would change `boneli-store-fs`'s `open`, which #109 does not: store-fs
takes one `try_lock` on `<root>/lock` (ADR-012, D1); `boneli-oci` keeps
`O_EXCL` creation, the inode recheck and its `LOCK_ATTEMPTS` retries,
unlink before unlock and `LOCK_WAIT` (ADR-025, D3). `boneli-oci`'s
`Reopened` becomes `HandOff`; its `Held` becomes a `FileLock` with the
path it was taken at, and loses its own drop.

Why two public types and not one: Rust does not allow moving a field out
of a type that implements `Drop`, so a single `FileLock` that is also
handed on would need a `dup` of every pin at hand-off (N more
descriptors during `pin_descriptors` and a new `EMFILE` failure point
there) or a panic arm. The two types share everything that decides a
release.

`boneli-private-dir` holds it because it is the std-only support crate
that the two consumers already share for their root rules (ADR-021) and
it is on the always-review list; a new crate would add a member, a
policy record and a review-list entry for a module of about 330 lines,
docs included, tests apart.

### D3. The wait

`take_until` tries at least once, so a deadline already past still gets a
free lock, and then polls with pauses from 1 ms doubling to 100 ms
(1, 2, 4, 8, 16, 32, 64, then 100: 64 doubled is 128, capped), each cut to
what is left of the deadline, so the wait ends at the deadline and never
a full pause past it. After the deadline it is `Busy`. std's `lock` and
`lock_shared` have no timeout. These are the numbers of ADR-025 D3 for
`boneli-oci`'s shared waits, moved here unchanged: a waiter gets the lock
at most 100 ms after its holder released it, against a pull that takes
seconds; the first seven pauses take 127 ms, and a whole 120 s
`LOCK_WAIT` is 7 + 1,199 = 1,206 sleeps and 1,207 tries, the "about
1,200 wake-ups" of ADR-025. The deadline itself (`LOCK_WAIT`) stays with
the caller.

### D4. The test seam cannot steal a lock

A test of the owner check needs a copy of a lock as a forked child sees
it, and a test cannot fork without `unsafe`. Behind
`#[cfg(any(test, feature = "test-seam"))]`, `Foreign { OtherPid,
OtherPidNamespace, UnreadableNamespace }` and `FileLock::copy_as(&self,
Foreign)` build a `try_clone` of the same open file description with the
recorded owner changed: pid + 1, namespace inode + 1, or no namespace.
That is how a copy looks from inside a plain forked child, a sandbox
child of a pid-1 runner, and a child whose `/proc` hides the link.

Such a copy can only fail the owner check: its drop closes its own
descriptor and never unlocks. It cannot make a copy that passes the check
in another process, and it cannot unlock the original. Only
`[dev-dependencies]` of `boneli-oci` and `boneli-store-fs` enable the
feature, and resolver 3 keeps dev-dependency features out of normal
builds; if a normal build enabled it, it would add a constructor of a
lock that does not unlock.

### D5. The `file-lock` rule

A rule `file-lock` in `crates/boneli-arch-check` fails any file-lock
call outside the file named by `[check] file-lock` in
`tools/architecture.toml` (`crates/boneli-private-dir/src/lock.rs`);
with the key absent nothing is exempt. It lands in PR 2 of #109.

- Raw names are flagged wherever they stand: `flock`, `lockf`,
  `SYS_flock`, `LOCK_SH`, `LOCK_EX`, `LOCK_NB`, `LOCK_UN` and the `fcntl`
  record and open-file-description lock commands.
- The lock names `lock`, `try_lock`, `lock_shared`, `try_lock_shared` and
  `unlock` are flagged in method position and in path position, and
  anywhere inside a macro group, because a macro can rearrange its input.
- `lock` and `try_lock` pass only in forms the compiler proves are not
  `File`'s: `io::stdout|stderr|stdin().lock()`, a Mutex lock followed by
  `.unwrap_or_else(PoisonError::into_inner)` or by `.as_deref()`, and a
  `Mutex::` prefix. Shadowing the names these proofs trust (`Mutex`,
  `PoisonError`, `io`, a `fn as_deref`) is flagged too.
- `#[cfg(test)] mod` bodies and integration tests under `tests/` are not
  scanned.

`lock()` and `try_lock()` also name Mutex methods, and a name match alone
cannot tell them apart; the checker has no types. The forms above are
the ones a name scan can prove. Clippy's `disallowed_methods` sees types
but needs a `clippy.toml`, which ADR-001 bans.

Blind spots: test code (production builds never compile it, unless built
with `--cfg test`); a lock taken by another program (`flock(1)`); a raw
syscall by number, which needs `unsafe` and so lives only in
`boneli-sys`, on the review list; an external crate's own locks, whose
edge needs an ADR anyway; and a macro that assembles a shadowing item
from reordered tokens.

### D6. Tests

The shared module's unit tests (`crates/boneli-private-dir/src/lock.rs`):

- `foreign_copy_keeps_the_lock`: a copy of a shared and of an exclusive
  lock, for each `Foreign` kind, leaves the lock held when it drops; the
  owner's drop releases it while a child holds a copy.
- `owner_comparison_table`: `owns` over eight rows (the owner itself,
  another pid, another inode, another device, unreadable at take, at
  release, at both with the same pid and with another pid); only the
  first unlocks. Moved from `boneli-store-fs`.
- `owner_reads_the_pid_namespace`: the owner carries this process's pid
  and the pair `/proc/self/ns/pid` names. Moved from `boneli-store-fs`.
- `drop_on_another_thread_unlocks`: the owner is the process, not the
  thread.
- `hand_off_dropped_early_releases_with_a_child_copy`,
  `foreign_hand_off_drop_keeps_its_pins`,
  `handed_on_descriptors_keep_their_locks` and `empty_hand_off`: a
  `HandOff` dropped early releases every lock with a child copy alive,
  one dropped by another process keeps them, handed-on descriptors keep
  their locks and a holder's `LOCK_UN` releases only its own, and an
  empty one hands on nothing.
- `take_until_past_deadline_tries_once`, `take_until_ends_at_its_deadline`
  and `poll_pauses_double_to_100_ms`: D3, the 300 ms wait ending after at
  least 300 ms and before 2.3 s.
- `busy_and_io_errors_differ`: `WouldBlock` is `Busy`; an `O_PATH`
  descriptor, which `flock` refuses with `EBADF` (checked on the
  development host), is `Io`, never `Busy`, through all three entry
  points.

The consumers keep their tests, with every assertion; only API names
changed. In `boneli-oci`: `foreign_drop_keeps_the_lock` (now over the
three `Foreign` kinds through the seam),
`replaced_file_lock_is_released_with_a_child_copy`,
`remove_unlinks_before_it_unlocks`, `shared_wait_is_bounded`,
`exclusive_wait_is_bounded`, the child-copy tests,
`lease::tests::abandoned_pin_descriptors_are_released_with_a_child_copy`,
`tests/locks.rs` and `tests/evict.rs::locks_released_under_concurrent_spawns`.
In `boneli-store-fs`: `copy_dropped_in_another_process_keeps_the_lock`
(`Foreign::OtherPid`), `copy_in_another_pid_namespace_keeps_the_lock`
(`Foreign::OtherPidNamespace`, still asserting that the host reads the
link), `unlock_on_drop_releases_while_a_child_holds_a_copy`,
`failed_open_leaves_the_root_openable` (its `open_with` hook hands a child
a copy right after the lock is taken), `drop_on_another_thread_unlocks`,
`lock_file_is_close_on_exec` and `reopen_survives_concurrent_spawns`.

Mutation check, run by hand on a copy of the PR head with `cargo test -p
boneli-private-dir -p boneli-store-fs -p boneli-oci`, which lists every
test that failed. Every mutant is killed. The four that remove or weaken
the pid and namespace comparison are killed by a test in `boneli-store-fs`
and by one in `boneli-oci`; the fifth drops only the unreadable-at-both
arm, which a consumer cannot reach on a host that reads the link, and the
moved table kills it.

| Mutant (shared module) | Failing tests (crate: test) |
| --- | --- |
| `release` unlocks without `owns` | store-fs: `copy_dropped_in_another_process_keeps_the_lock`, `copy_in_another_pid_namespace_keeps_the_lock`; oci: `foreign_drop_keeps_the_lock`; shared: `foreign_copy_keeps_the_lock`, `foreign_hand_off_drop_keeps_its_pins` |
| `owns` returns `true` | the same five, plus shared: `owner_comparison_table` |
| `owns` compares the pid only (ADR-026) | store-fs: `copy_in_another_pid_namespace_keeps_the_lock`; oci: `foreign_drop_keeps_the_lock`; shared: `foreign_copy_keeps_the_lock`, `owner_comparison_table` |
| `owns` compares the namespace only | store-fs: `copy_dropped_in_another_process_keeps_the_lock`; oci: `foreign_drop_keeps_the_lock`, `orphan_lock_files_removed_when_free`; shared: `foreign_copy_keeps_the_lock`, `foreign_hand_off_drop_keeps_its_pins`, `owner_comparison_table` |
| `owns` without `pid_ns.is_some()` | shared: `owner_comparison_table` (the row "unreadable at both, same pid", which no consumer can produce on this host) |
| `release` never unlocks | store-fs: `unlock_on_drop_releases_while_a_child_holds_a_copy`, `failed_open_leaves_the_root_openable`, `reopen_survives_concurrent_spawns`; oci: `shared_drop_releases_while_a_child_holds_a_copy`, `exclusive_drop_releases_while_a_child_holds_a_copy`, `remove_releases_while_a_child_holds_a_copy`, `replaced_file_lock_is_released_with_a_child_copy`, `abandoned_pin_descriptors_are_released_with_a_child_copy`, `foreign_drop_keeps_the_lock`, `locks_released_under_concurrent_spawns`; shared: `foreign_copy_keeps_the_lock`, `drop_on_another_thread_unlocks`, `hand_off_dropped_early_releases_with_a_child_copy` |
| `HandOff`'s drop skips `release` | oci: `abandoned_pin_descriptors_are_released_with_a_child_copy`; shared: `hand_off_dropped_early_releases_with_a_child_copy` |
| `hand_on` returns duplicates and leaves the files in place | oci: `pin_descriptors_outlive_the_runner`; shared: `handed_on_descriptors_keep_their_locks` |
| `take_until` returns `Busy` before its first try once the deadline is past | oci: `shared_wait_is_bounded`; shared: `take_until_past_deadline_tries_once` |
| `Owner::current` never reads the namespace | store-fs: `unlock_on_drop_releases_while_a_child_holds_a_copy`, `failed_open_leaves_the_root_openable`, `reopen_survives_concurrent_spawns`; oci: the six child-copy and spawn tests above, `foreign_drop_keeps_the_lock`; shared: `owner_reads_the_pid_namespace`, `foreign_copy_keeps_the_lock`, `drop_on_another_thread_unlocks`, `hand_off_dropped_early_releases_with_a_child_copy` |


## Consequences

- A fix to the owner check or the release is made once and reaches both
  stores; the rule text is in one ADR.
- `boneli-private-dir` grows from root rules to root rules and file
  locks, both std-only; it stays without dependencies.
- No behaviour changes: the same system calls at take and release
  (`getpid`, `stat`, `flock`), the same pauses and deadlines, the same
  errors to callers. `HandOff::try_take` reserves room for one more file
  before each lock.
- Once D5 lands, every Mutex lock outside test code has to take one of
  the proven forms; the rule's message names them.
- ADR-025 D3 keeps its protocol, `LOCK_ATTEMPTS` and `LOCK_WAIT`; its
  release sentence, ADR-026 and ADR-028 are superseded by this ADR once
  it is accepted.

## Alternatives considered

- **Two copies plus a parity test**: keeps the drift, and a parity test
  over two owner checks pins their equality, not their correctness.
- **A new crate `boneli-file-lock`**: a member, a policy record and a
  review-list entry for a module of about 330 lines that
  `boneli-private-dir`, which both consumers already link, can hold (D2).
- **Moving both lock-file protocols into the shared crate**: changes
  `boneli-store-fs`'s `open` (O_EXCL creation, an inode recheck), a rule
  change out of #109's scope.
- **One type that is also handed on**: a `dup` per pin or a panic arm
  (D2).
- **Clippy `disallowed_methods`** for D5: needs a `clippy.toml`, which
  ADR-001 bans because a clippy config can relax lints; lifting that ban
  is a wider decision.
- **A per-file count pin of Mutex calls** (the pattern of #95): every new
  Mutex call anywhere would need a policy edit.
- **Scanning only files that name `File`**: misses a `File` value that
  reaches a file without its type name, and `EntryKind::File` is a false
  positive.

The checker stays in Rust (ADR-015), so there is no language choice.

## Accept when

PR 2 of #109 is green on main: the `file-lock` rule (D5) with its
fixtures in `tools/check-architecture.sh --fixtures`, no file-lock call
left in `boneli-store-fs` or `boneli-oci` outside this module, and the
Mutex call sites rewritten to the proven forms. That PR flips this ADR to
accepted, sets ADR-026 and ADR-028 to superseded by ADR-030 and adds the
pointer sentence to ADR-025 D3.
