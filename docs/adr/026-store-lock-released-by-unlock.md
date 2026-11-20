# ADR-026: The store lock is released by an explicit unlock

- Status: accepted
- Date: 2026-11-20

## Context

`FsStore::open` takes an exclusive `flock` on `<root>/lock` through
`File::try_lock`, and the store keeps the file until it drops (ADR-012,
D1). Until this ADR the close of that file released the lock. During a
full `cargo test --workspace` at a host load average of about 27,
`evidence::blob_survives_reopen` failed once with `InUse` on the reopen
right after the first store dropped (#94).

The mechanism: a `flock` lock belongs to the open file description, not to
one descriptor. `fork`, and the `clone` behind `posix_spawn`, give the
child a copy of every descriptor of the process, all pointing at the same
descriptions. std opens files `O_CLOEXEC`, so the child's exec closes its
copy, but from fork to exec the child holds the lock's description. A store
dropped in that window closes only its own descriptor, the lock stays held
until the child's exec, and an `open` in the window gets `WouldBlock`,
which the store reports as `InUse`. Any thread that spawns anything opens
such a window: the test binary spawns `mkfifo`, and the runner spawns git
and the sandbox while it may reopen a store. The bug is not test-only.

Measured on the development host (Linux, 12 threads, glibc), the test
process capped at 300 % CPU (four CPU spinners in the same cap for the
loaded runs): the stress test `reopen_survives_concurrent_spawns`, in which
one thread spawns `true` in a loop while the test thread opens a store,
puts a blob and drops it, on one root, failed in 200 of 200 runs on the old
code, 100 loaded and 100 unloaded. The first failing reopen came at cycle 1
to 23, mean 4.2 loaded and 4.5 unloaded, so about one reopen in four or
five failed. A deterministic reproduction gives a child a duplicate of the
lock's descriptor as its stdin, which is the state of a child between fork
and exec held for as long as the test needs, drops the store and reopens:
`InUse` on the old code.

With this ADR's fix the same stress test passed 220 of 220 runs under the
same cap: 120 loaded, 100 unloaded.

## Decision

### D1. The drop unlocks, then closes

`root::open` wraps the locked file in `StoreLock` as soon as `try_lock`
succeeds. `StoreLock`'s `Drop` calls `File::unlock` (`flock(LOCK_UN)`)
before the file closes. `LOCK_UN` acts on the description, so it releases
the lock whatever copies of it exist. Because the wrapper exists from the
moment the lock is taken, every error path of `open` after that point
unlocks as well. An error from `unlock` is ignored: the close that follows
still releases the lock when no copy exists, and a drop has no caller to
report to.

`File::unlock` is in std since Rust 1.89, the MSRV ADR-012 set for
`try_lock`, so there is no MSRV change, no `unsafe` and no new crate.

Exclusion does not change: while the store lives the lock is held, and a
second `open`, from this process or another, is `InUse` with or without a
child holding a copy.

Only the process that took the lock unlocks it: `acquire` records
`std::process::id()`, and the drop skips the unlock when the id differs.
The unlock acts on a description that forked children share, so without
the check a child forked without exec (the sandbox launch runs on a copy
of the parent's stack, review of #96) that unwinds through a frame holding
a store would unlock the parent's live store, and a second `open` would
succeed and sweep its temporary files. With the check such a child only
closes its own copy, as before this ADR. `getpid` is a system call in
glibc and musl (glibc dropped its pid cache in 2.25), so the child sees
its own id.

### D2. After a crash the lock lasts at most until a child's exec

When the store's process dies without dropping the store (a crash,
`SIGKILL`), no unlock runs, and the kernel releases the lock when the last
descriptor of the description closes. The process's own descriptors close
when it exits. The only other copies are held by children between fork and
exec, and the lock file is `O_CLOEXEC`, so each such copy closes at that
child's exec (or at its exit, if the exec fails). A child that has exec'ed
holds no copy. So after a crash the lock outlives the process by at most
the fork-to-exec interval of a child spawned just before it.

The guard is `lock_file_is_close_on_exec`: it reads the flags of the lock
descriptor from `/proc/self/fdinfo` and asserts `O_CLOEXEC`, so an open
that drops the flag fails the test. Weak spot: the test pins the flag, not
the timing. The length of the fork-to-exec interval depends on the host
(scheduler, load) and no test measures or bounds it.

### D3. Tests

- `unlock_on_drop_releases_while_a_child_holds_a_copy` (unit test in
  `root.rs`) is the pin: the deterministic reproduction above, `InUse` on
  the old code, `Ok` now.
- `live_store_stays_locked_with_a_child_copy`: a second `open` while the
  store lives is `InUse` with a child copy alive (exclusion, D1).
- `failed_open_leaves_the_root_openable`: an `open` that fails after the
  lock is taken leaves the root openable while a child holds a copy of
  the lock (D1, error paths). The copy is handed to the child through a
  private hook, `open_with`, called right after the lock is taken; `open`
  passes a no-op. Without the hook no copy can be taken from inside
  `open`, and the test caught a lock wrapped only on success by chance
  only (review of #96: green in 10 of 10 runs); with it that regression
  fails in 6 of 6 runs, parallel and single-threaded.
- `copy_dropped_in_another_process_keeps_the_lock`: the owner check of D1.
  Forking in a test needs `unsafe`, which this crate forbids, so the test
  builds a copy whose owner is not this process, which is how a forked
  child's copy looks from inside the child, and drops it: the lock stays
  held. It pins the comparison, not that a child sees its own id (D1).
  Without the check it fails in 6 of 6 runs.
- `lock_file_is_close_on_exec`: the guard of D2.
- `reopen_survives_concurrent_spawns` (integration test) is the smoke
  test: 300 open, put and drop cycles on one root while another thread
  spawns processes. It is probabilistic before the fix and cannot fail
  after it. Why 300: in the baseline above the first failure came at cycle
  23 at the latest, and the per-reopen failure rate was about 0.22 (one
  over the mean first failing cycle). 300 is 13 times the worst observed
  cycle, so on a host whose window is ten times narrower than this one
  (rate about 0.022) a regression still fails the test with probability
  1 - (1 - 0.022)^299, about 0.999. At 30 cycles that probability would be
  about 0.48 on such a host. A larger count buys nothing: the
  deterministic pin is the evidence, and each cycle costs an `open` with
  four directory syncs and a synced blob: the 300 cycles take about 2 s
  unloaded and 2.5 s under the loaded cap above (100 runs in 200 s, 20
  runs in 49 s).

## Consequences

- A reopen no longer fails because another thread spawned a process, so
  the runner can spawn git and the sandbox while it reopens a store.
- Two more system calls per store drop (`getpid`, `flock`).
- The unit tests need `sleep` on `PATH` and `/proc/self/fdinfo`; the crate
  is Linux-only already (`flock`, `/proc/self` in ADR-012 D1).
- Unchanged: the lock primitive, the root rules (ADR-021), the run log and
  blob rules (ADR-012 D2 to D6), and `boneli-oci`'s liveness scheme
  (ADR-009).

## Alternatives considered

- **Retrying `try_lock` for a bounded time on `WouldBlock`:** the timeout
  has nothing to derive it from, because the window depends on the host;
  every genuine `InUse` would wait the full timeout; it hides contention
  instead of removing it; and a child that lingers between fork and exec
  on a loaded host outlasts any short timeout.
- **`fcntl` record locks:** owned by the process, so a second `open` in the
  same process would succeed and break the one-store-per-root rule that
  `second_open_is_refused_while_held` pins; they are also dropped when any
  descriptor of the file closes anywhere in the process.
- **Open file description locks (`F_OFD_SETLK`):** owned by the description
  like `flock`, so children inherit them the same way, and std has no API
  for them, so they would need a new `unsafe` wrapper in `boneli-sys`.
- **Fixing it on the spawning side** (sharing the descriptor table with
  `CLONE_FILES`, or one spawn lock every spawning thread takes): every
  spawn in the process, std's and other crates' included, would have to go
  through one place, which the store cannot enforce.
- **Keeping sibling spawns out of the tests:** hides a bug the runner hits
  in production.
