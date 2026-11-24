# ADR-030: One file-lock type for the workspace

- Status: accepted
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

A rule `file-lock` in `crates/boneli-arch-check` (the 33rd, listed last
by `--list-rules`) fails any file-lock call outside the one file named
by `[check] file-lock` in `tools/architecture.toml`,
`crates/boneli-private-dir/src/lock.rs`. The key is optional, and
without it no file is exempt, so deleting the line fails closed. It is
`policy-format` unless it is a string of printable ASCII of the form
`crates/<crate>/src/<path>.rs`, relative, without an empty, `.` or `..`
component or a backslash, with `<crate>` in `roles.support`: it can
name exactly one file, and only a support crate's source.

The rule reads the token stream of the lenient lexer (comments dropped,
literals one token each, so a name inside a string, a character or a
comment is no hit) and reports. The lexer drops a first-line shebang as
rustc does: `#!` at the start of the file (after a byte order mark)
whose next token, past whitespace and comments that are no doc comments,
is not `[`, up to the end of its line. Read as code, a shebang
`#!/usr/bin/env cargo /*` would open a block comment that rustc never
sees and hide the file from every token rule.

- **Raw names, wherever they stand**: `flock`, `lockf`, `SYS_flock`,
  `LOCK_SH`, `LOCK_EX`, `LOCK_NB`, `LOCK_UN` and the `fcntl` record and
  open file description lock commands `F_SETLK`, `F_SETLKW`, `F_GETLK`,
  `F_OFD_SETLK`, `F_OFD_SETLKW`, `F_OFD_GETLK`, and what an `fcntl` lock
  is described by, `flock64` and the lock types `F_RDLCK`, `F_WRLCK`,
  `F_UNLCK`. None of them occurs in the workspace outside the exempt
  file.
- **The lock names** `lock`, `try_lock`, `lock_shared`,
  `try_lock_shared` and `unlock`, std's `File` methods:
  - inside a macro group (`name!(..)`, `name![..]`, `name!{..}` and the
    body of `macro_rules! name { .. }`), wherever they stand, because a
    macro can rearrange its input: `m!(File :: lock :: f)` or a
    transcriber `$r.$m()` invoked as `g!(f, lock)` builds a call that no
    token pattern sees. Identifiers cannot be built from pieces on
    stable Rust without proc macros, which ADR-001 bans, so the name is
    always there as a token. A keyword written without `r#` names no
    macro, so `if !(..)` opens no group;
  - outside one, in method position (`.name(` or `.name::`) and in path
    position (`::name` outside a `use` item and a `pub(in path)`
    visibility, whose `crate::lock` names a module, and not followed by
    `::` and
    a further segment, so `File::lock::<>(&f)` is a call and
    `crate::lock::Held` is not). A `use` item is `use` up to its `;` with
    only path tokens between, so `impl Sized + use<> { .. }` is no
    `use` item and stays scanned.
- **Proven forms pass**, for `lock` and `try_lock` only, because the
  checker has no types and these are the forms whose types the compiler
  pins:
  - P1 `io::stdout().lock()` (and `stderr`, `stdin`), with `io` the first
    path segment or right after a first-segment `std::`: `Stdout::lock`
    is inherent, and inherent methods win over trait methods;
  - P2 `.lock()` or `.try_lock()` followed by
    `.unwrap_or_else(PoisonError::into_inner)`, also with `sync::` or
    `std::sync::` in front: `File::lock` returns `io::Result<()>` and
    `File::try_lock` `Result<(), fs::TryLockError>`, and neither error is
    a `PoisonError`, so the call does not compile on a `File`;
  - P3 `.lock()` or `.try_lock()` followed by `.as_deref()`:
    `Result::as_deref` needs `T: Deref`, and `()` is not;
  - P4 a `Mutex::` prefix, `Mutex::lock(&m)` and `Mutex::try_lock(&m)`.

  A closure `|p| p.into_inner()` is no proof: a user trait can give
  `fs::TryLockError` an `into_inner` that returns `()`, and `fn
  into_inner` exists in `boneli-oci` and `boneli-json`.
- **Redefinitions of the names the proofs trust**, wherever they stand,
  inside macros too: `Mutex`, `PoisonError` or `io` after `struct`,
  `enum`, `union`, `type`, `trait` or `mod`, after `as` where `;`, `,` or
  `}` follows, the end of a `use` tree or an `extern crate` item (so `use
  std::fs::File as Mutex`, `use a::{File as Mutex, b}`, `mod io`, `extern
  crate core as io`; `<W as io::Write>::flush(w)` and `fd as io::RawFd`
  name a trait and a type and pass), declared as a generic
  parameter (`fn f<io>()`, `impl<Mutex: T>`), and `Mutex` or
  `PoisonError` followed by a single `:` (a bound, as in `where
  PoisonError: T`); and `fn as_deref`. In a manifest, a dependency
  renamed to one of the three names and a lib target named after one:
  either makes `io::stdout()` a function of a workspace crate in its
  dependents. `fn io(..)`, a field or parameter named `io` and a value of
  any of the names are in the value namespace and pass.
- **Not scanned**: `#[cfg(test)]` followed by further outer attributes,
  an optional visibility and `mod name { .. }` outside a macro group, and
  the files under a member's `tests/` when every target whose source lies
  there has kind `test`. `#[cfg(test)] fn`, `#[cfg(test)] mod t;` (its
  file is scanned), `#[cfg(any(test))]`, `#[cfg(not(test))]`,
  `#![cfg(test)]` and a `[lib]` under `tests/` are scanned. Benches and
  examples are scanned.

`lock()` and `try_lock()` also name Mutex methods, and a name match alone
cannot tell them apart. Clippy's `disallowed_methods` sees types but
needs a `clippy.toml`, which ADR-001 bans because a clippy config can
relax lints. So every Mutex lock outside test code takes one of the four
forms, and the FAIL message names them. On the head of #109's PR 2 the
rule found 53 lines in four crates, all Mutex locks, rewritten to the
proven forms with the same behaviour: 40 `X.lock().expect("not
poisoned")` in `boneli-replay-check` became `Mutex::lock(&X)`, the
keeper's `Shared::lock` in `boneli-sys` became `Shared::guard` (6
flagged callers, 7 with one in a test module), the five `|p|
p.into_inner()` closures of `boneli-sys` became `PoisonError::into_inner`,
and one `Mutex::lock` each went into `boneli-git-cli` and `boneli-https`:
54 edits, the renamed definition included. It found no raw name, no lock name
inside a macro group and no redefinition.

Blind spots:

- **Test code**: `tests/` and `#[cfg(test)]` modules. Production builds
  never compile them, unless someone builds with `--cfg test` through
  `RUSTFLAGS`.
- **A lock taken by another program** (`Command::new("flock")`).
- **A libc lock call by number or under another link name**: a raw
  syscall (`syscall(73, ..)`), `fcntl(fd, 6, ..)` with the command as a
  number (6 is `F_SETLK` on x86_64 and aarch64), or an `extern` function
  declared `#[link_name = "flock"]`, whose name is a string. Each needs
  `unsafe` and `libc`, so it can live only in `boneli-sys`, which is on
  the review list.
- **An external crate's own locks and items**: its locks, and a module
  `io` or a type `Mutex` it exports. A new external edge needs an ADR.
- **A macro that assembles a redefinition** (`type Mutex = File`, `mod
  io`, `fn as_deref`) from reordered tokens: the redefinition check
  matches neighbouring tokens, and a tt muncher can emit `type` and
  `Mutex` from different places of its input. No `macro_rules!` is
  defined in the workspace today; the name appears only in strings and
  comments.

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


The rule (D5) has unit tests in `crates/boneli-arch-check/src/scan.rs`
(`file_lock_calls_flagged`, `file_lock_raw_names_flagged`,
`file_lock_proofs_pass`, `file_lock_unproven_forms_flagged`,
`file_lock_non_calls_pass`, `file_lock_macro_tokens_strict`,
`file_lock_shadowing_flagged`,
`file_lock_test_modules_skipped_only_when_real`,
`file_lock_unicode_whitespace_and_raw_identifiers`,
`file_lock_shebang_line_is_skipped_as_rustc_does`) and in `policy.rs`
(`file_lock_key_forms`), and 14 fixture cases: `file-lock-raw-call`,
`file-lock-outside-module`, `file-lock-lib-in-tests-dir`,
`file-lock-cfg-test-in-macro`, `file-lock-key-absent`,
`file-lock-dependency-renamed-io`, `file-lock-lib-named-io` and
`file-lock-shebang` fail with
`file-lock`; `ok-file-lock-mutex` (with the form of
`crates/boneli-forge-github/src/tokens.rs`,
`&match self.cache.try_lock().as_deref() {`), `ok-file-lock-module`,
`ok-file-lock-tests-dir` and `ok-file-lock-cfg-test-mod` pass;
`policy-file-lock-not-support` and `policy-file-lock-malformed` fail with
`policy-format`. Its mutation check ran by hand on a copy of the PR head,
the unit mutants with `cargo test -p boneli-arch-check --lib` and the
others with `tools/check-architecture.sh --fixtures`. Every mutant is
killed:

| Mutant (rule `file-lock`) | Killed by |
| --- | --- |
| rule not run (`file_lock_hits` never called) | fixtures `file-lock-raw-call`, `-outside-module`, `-lib-in-tests-dir`, `-cfg-test-in-macro`, `-key-absent` |
| raw names not reported | `file_lock_raw_names_flagged` |
| every `.lock()`/`.try_lock()` counts as proven | `file_lock_calls_flagged`, `_unproven_forms_flagged`, `_macro_tokens_strict`, `_test_modules_skipped_only_when_real`, `_unicode_whitespace_and_raw_identifiers` |
| P2 accepts any `.unwrap_or_else(..)` | `file_lock_unproven_forms_flagged` |
| P1 accepts any path before `io` | `file_lock_unproven_forms_flagged` |
| P1 accepts any first segment, not only `io` (`x::stdout().lock()`) | `file_lock_unproven_forms_flagged` |
| P2 accepts any `X::into_inner`, not only `PoisonError` (`Tr::into_inner`) | `file_lock_unproven_forms_flagged` |
| no strict mode in macro groups | `file_lock_macro_tokens_strict` |
| test-module skip applied inside macros | `file_lock_macro_tokens_strict` |
| any `#[cfg(<word>)] mod` skipped | `file_lock_test_modules_skipped_only_when_real` |
| `r#` ignored (`r#if!` no macro, `cfg(r#test)` skipped) | `file_lock_macro_tokens_strict`, `_test_modules_skipped_only_when_real` |
| `::name::<` read as a path continuation | `file_lock_calls_flagged` |
| a `use` item runs to any `;` | `file_lock_calls_flagged` |
| redefinitions not reported | `file_lock_shadowing_flagged` |
| generic parameters not read as redefinitions | `file_lock_shadowing_flagged` |
| `tests/` exempt without the target check | fixture `file-lock-lib-in-tests-dir` |
| the whole `src/` of the key's crate exempt | fixture `file-lock-outside-module` |
| an absent key exempts the shared module | fixture `file-lock-key-absent` |
| key form unchecked | `file_lock_key_forms`; fixtures `policy-file-lock-not-support`, `-malformed` |
| dependency renames not checked | fixture `file-lock-dependency-renamed-io` |
| lib target names not checked | fixture `file-lock-lib-named-io` |
| a shebang line read as code | `file_lock_shebang_line_is_skipped_as_rustc_does`; fixture `file-lock-shebang` |
| every `as NAME` read as a rename | `file_lock_shadowing_flagged` |
| `as NAME` never read as a rename | `file_lock_shadowing_flagged` |
| `::lock` in a `pub(in ..)` visibility read as a call | `file_lock_non_calls_pass` |

## Consequences

- A fix to the owner check or the release is made once and reaches both
  stores; the rule text is in one ADR.
- `boneli-private-dir` grows from root rules to root rules and file
  locks, both std-only; it stays without dependencies.
- No behaviour changes: the same system calls at take and release
  (`getpid`, `stat`, `flock`), the same pauses and deadlines, the same
  errors to callers. `HandOff::try_take` reserves room for one more file
  before each lock.
- Every Mutex lock outside test code takes one of the proven forms of
  D5, workspace-wide; the rule's message names them. A Mutex lock in
  another form fails the check even where no file is near.
- ADR-025 D3 keeps its protocol, `LOCK_ATTEMPTS` and `LOCK_WAIT`; its
  release sentence, ADR-026 and ADR-028 are superseded by this ADR.

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

## Acceptance

Accepted with PR 2 of #109: the `file-lock` rule (D5) with its fixtures
in `tools/check-architecture.sh --fixtures`, no file-lock call left in
`boneli-store-fs` or `boneli-oci` outside this module, and the 53 Mutex
lines rewritten to the proven forms. The same PR sets ADR-026 and
ADR-028 to superseded by ADR-030 and adds the pointer sentence to
ADR-025 D3.
