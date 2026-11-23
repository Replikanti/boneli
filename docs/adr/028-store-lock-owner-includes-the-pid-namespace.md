# ADR-028: The store lock's owner is a pid in a pid namespace

- Status: accepted
- Date: 2026-11-23

## Context

ADR-026 D1 makes `StoreLock` (`crates/boneli-store-fs/src/root.rs`)
unlock its `flock` when it drops, and only in the process that took the
lock: `acquire` records `std::process::id()`, and the drop skips the
unlock when the id differs. The unlock acts on the open file description,
which a child forked without exec shares with its parent, so without the
check a copy of the store dropped in such a child would release the
parent's live lock; a second `open` would then succeed and its sweep would
delete the first store's temporary files.

A pid only names a process inside its own pid namespace. The sandbox
launch clones with `CLONE_NEWPID` (`SPAWN_NAMESPACES` in
`crates/boneli-sys/src/spawn.rs`), so the sandbox child is always pid 1 of
a new namespace. When the runner is pid 1 of its own namespace (a
container entrypoint without an init, for example), the child's id equals
the recorded one and the check of ADR-026 passes in the child. The second
review round on PR #96 found this, and #97 carried it.

The failure needs three faults at once: a panic that unwinds in the
sandbox child between the clone and its `_exit`, a store held in a frame
of the spawning thread that the unwind passes, and a runner deployed as
pid 1. Normal operation hits none of them, but the outcome, a live store
that loses its lock and its temporary files, is the one the check exists
to prevent.

Measured on the development host (Linux, glibc), with `stat -L` on
`/proc/self/ns/pid`: the shell outside reads `pid:[4026531836]`, device 5,
inode 4026531836. `unshare -Urpf --mount-proc` starts a child that is pid
1 and reads `pid:[4026533368]`, device 5, inode 4026533368 (the inode is
new for every namespace; the planning run of #97 saw 4026533461). The pid
is the same as a pid-1 runner's, the namespace differs. A child of
`CLONE_NEWPID` sits in the new namespace itself, as the `unshare -f`
child does, so it differs in the same place.

## Decision

### D1. The owner is the pid and the pid namespace

`acquire` records an `Owner { pid, pid_ns }`: `std::process::id()` and the
`(st_dev, st_ino)` of `/proc/thread-self/ns/pid`, read with
`fs::metadata`. The drop reads the same pair again and unlocks only when
both are equal (`owns`, a plain equality of the two values). Everything
else in ADR-026 D1 stays: the unlock before the close, the ignored
`unlock` error, the wrapper from the moment the lock is taken.

Why both fields: the pid alone is ADR-026's check, which this ADR exists
to close. The namespace alone would let a plain forked child (same
namespace, other pid) unlock. Why `st_dev` too: the kernel names a
namespace by the device and inode of its nsfs file, and `namespaces(7)`
names both as what two processes in one namespace share; comparing the inode alone works on every
kernel today (nsfs is one device), but costs nothing to make exact. While
the parent's store lives its namespace lives, so a second live namespace
cannot have its identity.

Why `/proc/thread-self` and not `/proc/self`: `/proc/self` fails once the
main thread has exited (#35; `boneli-oci` reads its own namespaces through
`thread-self` for the same reason), and every thread of a process is in
the same pid namespace, so the reading does not depend on the thread that
drops.

Why no `unsafe` and no allocation: `fs::metadata` on a path shorter than
std's stack buffer (384 bytes) builds its C string on the stack, and the
result is two integers. A drop in an unwinding forked child therefore
adds one `stat` call (`statx` on glibc, `stat` on musl) and no heap use.
`readlink` would allocate the target.

### D2. An unreadable namespace link

`pid_ns` is `None` when the link cannot be read. Equality is over the
`Option`s:

- Readable at `acquire`, unreadable at the drop (a sandbox child after it
  replaced its mounts, so `/proc` is gone or another procfs): mismatch,
  the drop keeps the lock and only closes its descriptor, which is the
  behaviour before ADR-026 and the safe side.
- Unreadable at `acquire`, readable at the drop: mismatch, same outcome.
- Unreadable at both: the pid check of ADR-026 alone. This is the weak
  spot of D1: there a pid-1 runner and its sandbox child are not told
  apart. It needs a runner whose `/proc` has no namespace links: without
  `/proc` at all `open` already fails, because the root rules read the
  owner of `/proc/self` (ADR-012 D1, ADR-021), and the pid link exists
  since Linux 3.8, far below the 5.19 the sandbox needs (ADR-007). What
  remains is a `/proc` that hides the link (a hardened or emulated
  procfs), which no supported deployment uses and no test can produce
  here; the table of D3 pins the arm.

A mismatch for the real owner would bring #94's `InUse` window back for
that store, never a stolen lock. The kernel gives a process one pid
namespace for its lifetime (`setns` and `unshare` with `CLONE_NEWPID`
change only `pid_for_children`), so the owner reads the same pair at
`acquire` and at the drop unless its own `/proc` is remounted in
between, which nothing in the runner does.

### D3. Tests

All unit tests in `root.rs`; none forks, none needs `unsafe`, a user
namespace or a new dependency.

- `copy_in_another_pid_namespace_keeps_the_lock`: the acceptance test. A
  copy of the live lock whose owner has this process's pid and the
  namespace inode plus one is dropped; a second `open` is `InUse`, and
  after the real drop the root reopens. With the pid-only check of
  ADR-026 it fails (the copy unlocks and the second `open` succeeds).
- `owner_comparison_table`: `owns` over eight cases, the owner itself,
  another pid, another inode, another device, the three unreadable-link
  arms of D2 and an unreadable link with another pid. It pins the arms
  this host cannot produce.
- `copy_dropped_in_another_process_keeps_the_lock` (ADR-026 D3): adapted
  to an owner with another pid in this namespace, a plain forked child.
- `drop_on_another_thread_unlocks`: a lock taken on one thread and
  dropped on another unlocks, so the identity is the process, not the
  thread. A regression pin: it passes on the pid-only check too.
- `owner_reads_the_pid_namespace`: `Owner::current()` holds this process's
  pid and the `(st_dev, st_ino)` of `/proc/self/ns/pid`.
- The `unshare` measurement in the context is recorded once, not a test:
  unprivileged user namespaces are not guaranteed on CI runners, and a
  test that skips there would read green without running.

Mutation check, run before the PR with `cargo test -p boneli-store-fs
--lib root::`; every mutant fails at least one test:

| Mutant | Failing tests |
| --- | --- |
| pid-only compare (ADR-026) | `copy_in_another_pid_namespace_keeps_the_lock`, `owner_comparison_table` |
| pid and inode only | `owner_comparison_table` |
| pid and device only | `copy_in_another_pid_namespace_keeps_the_lock`, `owner_comparison_table` |
| an unreadable link at either end unlocks | `owner_comparison_table` |
| the drop without the unlock | `unlock_on_drop_releases_while_a_child_holds_a_copy`, `failed_open_leaves_the_root_openable` |
| the namespace never read (`pid_ns: None`) | `copy_in_another_pid_namespace_keeps_the_lock`, `owner_reads_the_pid_namespace` |

## Consequences

- A copy of a store dropped in a sandbox child no longer unlocks the
  parent's lock when the runner is pid 1 of its namespace.
- One more system call (`stat`, D1) per `acquire` and one per store
  drop: a drop now makes three (`getpid`, `stat`, `flock`), `acquire` two
  (`getpid`, `stat`) besides the lock itself.
- The owner check is as good as ADR-026's on a host without `/proc`
  namespace links (D2).
- Unchanged: the lock primitive, the root rules (ADR-021), the run log and
  blob rules (ADR-012 D2 to D6), ADR-026 D2 and D3, and `boneli-oci`'s
  owner scheme (ADR-009 D8).

## Alternatives considered

- **A never-unwind guard around the sandbox child in `boneli-sys`** (abort
  or `_exit` when `child::run` panics), the alternative #97 named. It
  protects only that one launch path, sits in the crate that holds every
  `unsafe` block, and leaves any other fork without exec unguarded, while
  the check at the unlock covers every copy of the store whatever made
  it. It may still be worth having on its own, as a change to the
  sandbox crate.
- **Reusing `boneli-oci`'s owner** (`crates/boneli-oci/src/layers.rs`): it
  is crate-private and carries the boot id, the time namespace and the
  start time, which a drop-time comparison inside one boot does not need.
  Moving it into `boneli-private-dir` would widen a support crate on the
  always-review list for a two-field `stat`, so the small duplication is
  cheaper than the extraction.
- **`getppid`:** changes when the parent dies and the child is
  reparented, so a live owner could see a mismatch, and it tells nothing
  about the child of a pid-1 runner, whose parent id is 0 in its own
  namespace either way.
- **The pid only (ADR-026 as it stands):** the failure above.
