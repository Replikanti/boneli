# ADR-015: The architecture checker in Rust

- Status: accepted (2026-11-20, after the parity run in CI)
- Date: 2026-11-20

## Context

ADR-001 (D4) wrote the architecture checker in Python 3.11's standard
library, because the workspace had no JSON or TOML parser that `deny.toml`
allows: serde is banned, and the `toml` crate pulls it. Rust lost "for
now"; the port is #35, after `boneli-json` (#29, ADR-008) and `boneli-toml`
(#34, ADR-011). Both exist now.

Keeping Python costs three things. The gate depends on an interpreter that
nothing else in the repository needs, in a version CI does not pin. The
checker is the one piece of tooling that is not held to the rules it
enforces: it is not a workspace member, so no lint, no `unsafe` scan and no
dependency rule applies to it. And its regular expressions backtrack: the
format-spec pattern is quadratic on a hostile file (measured below), which
an outside contributor's pull request can hand it.

One boneli-oci test also ran Python: `exited_main_thread_reads_unreadable`
started a `python3` helper that ends its own main thread with a raw
`SYS_exit` while another thread runs, because std cannot do that. Issue #35
was widened at STOP 1 to "zero Python in boneli", so that test moves too
(D10).

This ADR records the port. It replaces ADR-001 D4 (the checker's language)
and the Python details of D5 (how the fixture runner builds a case),
without editing ADR-001, which stays accepted: `[external.libc] strict`
and the `boneli-sys -> libc` record cite it, and rule `policy-strict`
requires the ADR they cite to be accepted.

## Decision

### D1. A workspace member that is a tool root

The checker is the crate `crates/boneli-arch-check`: a library with the
rules and a binary that calls it. It depends on `boneli-json` and
`boneli-toml` only, no external crate and no build script, and it is listed
in `roles.roots` of `tools/architecture.toml`. As a root it is a leaf: no
crate may depend on it, so the gate never becomes a library the product
links. As a member it is held to every rule it enforces: the workspace
lints (`unsafe_code = "forbid"`), the `unsafe` token scan, the doctest
attribute, the dependency edges, the source rules. Its own sources write
the `unsafe` token as `\x75nsafe` where a string has to hold it (D8).

Rejected:

- **A nested workspace under `tools/`.** Not a member, so outside the rules
  it enforces again, with its own lockfile, its own CI steps and its own
  `cargo deny` run.
- **A binary inside a support crate.** Support crates stay generic
  (invariant 1); a checker of this repository's architecture is not.
- **`cargo run -p boneli-arch-check` from the repository.** Measured while
  planning (cargo 1.98.0): with the repository as the working directory, a
  committed `.cargo/config.toml` with
  `[target.x86_64-unknown-linux-gnu] runner = [...]` made `cargo run` exit
  0 without running the binary, and a `rust-toolchain.toml` with
  `path = ...` ran a fake `cargo`. The check reports both files, but only
  if it runs.

### D2. The entry point runs no code from the checkout before the check

`tools/check-architecture.sh` stays the entry point (POSIX sh, CI runs it
under dash and bash). It takes the repository root from `$0` with
`pwd -P`, runs every cargo call from `/` with
`--manifest-path "$root/Cargo.toml"`, and in this order:

1. **The host triple** from `rustc -vV`.
2. **The three checker crates are real directories**:
   `crates/boneli-arch-check`, `crates/boneli-json` and `crates/boneli-toml`
   must each resolve (`pwd -P`) to themselves, so no symlink anywhere on
   the path points the build at other sources.
3. **The build closure** (`cargo tree --locked -p boneli-arch-check -e
   normal,build --target <host> --prefix none --format '{p}'`) must be
   exactly those three crates, each at its path under this checkout's
   `crates/`. Anything else, a crates.io crate, a git crate, another
   member, a path crate elsewhere or a `[patch]` replacement (both change
   the printed path), is a tool error (exit 2) before anything is
   compiled: building it could run its build script or proc macro.
4. **Each of the three is a workspace member**: its `manifest_path`
   appears in `cargo metadata --no-deps --offline` (which runs no code),
   else a tool error (exit 2). Found in round 2 of the review: with
   `exclude = ["crates/boneli-toml"]` and a standalone manifest, the
   closure still listed `crates/boneli-toml` by path, the member checks
   below no longer saw it, and its build script ran before the checker
   was compiled; it swapped the checker's `main.rs` for one that printed
   OK and restored the original, and the gate step stayed green. The
   same holds for a crate that is the root of a workspace of its own.
5. **No workspace member has a build script or is a proc macro** (the
   same output): a
   `custom-build` target is `FAIL [build-script] Cargo.toml: ...`, a
   `proc-macro` target `FAIL [proc-macro] Cargo.toml: ...`, exit 1, the
   rules the checker would report. Found in round 1 of the review: a
   `build.rs` added to `boneli-toml` ran during the checker's build,
   deleted itself, and the check then printed OK. `roles.build-script` is
   empty, so a member with a build script is a violation anyway; a PR that
   lists one there has to scope this step to the three crates of the
   closure.
6. **The build** for the host triple:
   `rm -f "$root/target/arch-check/<host>/debug/boneli-arch-check"`, then
   `cargo build --quiet --locked -p boneli-arch-check --target <host> --target-dir "$root/target/arch-check"`,
   and a missing binary afterwards is a tool error. With the target
   explicit, `CARGO_BUILD_TARGET` or a user's `build.target` cannot move
   the build elsewhere, and with the old binary deleted first, a stale
   binary can never run: cargo puts back its own artifact for the current
   sources. The artifacts under `target/arch-check` are trusted as far as
   cargo's fingerprints are; in CI the directory does not exist yet when
   the gate runs, because nothing before it builds and rust-cache restores
   after it. Found in round 1: with `build.target` set, the
   fresh build went to `<triple>/debug/` while an older binary at the
   fixed `debug/` path ran, with the older rules.
7. **`exec`** of that binary from the caller's working directory, with the
   caller's arguments.

Why each part:

- **From `/`:** cargo and rustup look for config and toolchain files from
  the working directory upwards. Measured while planning: with `/` as the
  working directory and `--manifest-path`, neither the committed
  `.cargo/config.toml` nor the `rust-toolchain.toml` above applied.
- **`--locked`:** the build uses the committed `Cargo.lock`; a stale one is
  a failure, as it is a check failure (ADR-001).
- **Its own target directory:** `target/arch-check` is not shared with the
  workspace build, whose flags and environment the caller controls.
- **A failed build** (a stale lockfile, no cargo) prints one line,
  `FAIL [tool-error] Cargo.toml: cannot build the architecture checker (cargo output on stderr)`,
  then `1 violation(s)`, and exits 2, as any tool error does.
- **`exec` from the caller's directory:** a relative `--root` resolves as
  before, and the checker's own cargo and rustc calls get the caller's
  environment, without the variables `cargo run` adds.

What the entry point does not cover: the checker's own cargo calls
(`cargo metadata`, the no-std `cargo check`) still run from the root and
see a committed cargo config, as they did under Python; `cargo metadata`
calls `build.rustc-wrapper` for `rustc -vV`. The config walk records the
file before any of those calls, so the run fails with `cargo-config`
whatever the wrapper does afterwards, short of the exit code, which only
the checker sets.

**In CI, the gate runs first.** In the `check` job only git (the issue
link, the grep of D10, the tracked-`target/` check), the toolchain action
(rustup and version queries; the job's `RUSTUP_TOOLCHAIN` outranks a
committed toolchain file) and the bash step that hides Python run before
the "Architecture rules" step. `Swatinem/rust-cache` and `cargo fmt`
come after it, because both read the checkout's cargo config: found in
round 1, a committed `[alias] fmt` ran PR code as `cargo fmt`, which
deleted the config and itself, and the gate then printed OK. The gate step
also fails if `git status --porcelain --untracked-files=all` is not empty
afterwards, so anything that changed the checkout while it ran turns it
red. The fixtures run next; they execute fixture code in temporary
directories, after the gate has judged the real tree.

**What proves it in CI:**

- "Architecture check builds outside committed cargo config" writes
  `.cargo/config.toml` with `build.rustc-wrapper` set to a script that
  logs its arguments and then runs rustc, touches the checker's `lib.rs`
  and runs the entry point. It requires exit 1, a
  `FAIL [cargo-config] .cargo/config.toml` line, a non-empty log (the
  wrapper did run, for the checker's own cargo calls) and no
  `--crate-name boneli_arch_check` in it. A mutant of the entry point that
  builds from the repository fails it (checked by hand).
- "Architecture check refuses code that runs before it" runs the review's
  attacks on fresh exports of HEAD: a self-deleting `build.rs` in
  `boneli-toml` (exit 1, the `build-script` line, the file still there and
  nothing built), a new member in the checker's closure (exit 2, nothing
  built), stale binaries at the host path and at the old `debug/` path
  with `CARGO_BUILD_TARGET` set (the real checker runs), `boneli-toml`
  excluded from the workspace with a build script that leaves a marker
  (exit 2, no marker, nothing built) and `crates/boneli-json` as a
  symlink (exit 2, nothing built). It also requires that no step before
  the gate in the `check` job uses cargo or rust-cache. Each part fails
  on the code before its fix, run by hand: on 6abcd3a, OK and exit 0
  after the build script deleted itself, exit 1 from the old checker
  after compiling the extra crate, the stale `OK`, and rust-cache and
  `cargo fmt` before the gate; on 126cfb5, the excluded crate's build
  script ran (the marker exists) and the symlinked crate gave OK.
- "No build output in the checkout" fails if anything under `target/` is
  tracked.

### D3. The contract does not change

Exit codes (0 OK, 1 violations, 2 tool errors), the line format
`FAIL [<rule-id>] <path>[:<line>]: <message>`, the summary line, the flags
`--root`, `--list-rules` and `--fixtures`, the 32 rule ids and their order,
the fixture format and the OK line are those of ADR-001. A usage error
prints the usage to stderr and exits 2 without stdout. A panic or a thread
that cannot start is `FAIL [tool-error] crates/boneli-arch-check: internal error: ...`
and exit 2, as Python's `except Exception` was, never Rust's 101; a write
error on stdout is exit 2.

New: every FAIL line goes through `show()`, path and message, so a newline
or another control character in a file name is printed as `\u{a}` and
cannot forge a line (`output_lines_parse_back`). Python printed both raw.
A byte outside UTF-8 in a path prints as `\u{dcXX}`, the character
Python's file-system decoding gave it. No fixture path is outside
printable ASCII, so no fixture result changes.

### D4. Limits, each derived

| Limit | Value | Derivation |
|---|---|---|
| TOML `max_bytes` | 1,048,576 | The largest TOML input the checker read when this was planned (at 0e29ca7) is `tools/architecture.toml`, 9,688 bytes; 100 times that is 968,800, and 1,048,576 is the next power of two. With ADR-011's worst factor of 64.5 (D5), one parse peaks at about 65 MiB. |
| TOML depth | 128 | boneli-toml's `MAX_DEPTH`. Measured while planning: cargo accepts 80 nested arrays or 80 dotted segments under `[package.metadata]` and rejects 81, so the deepest manifest cargo accepts is 3 + 80 = 83 levels; 128 is above it, and the deepest input today has 5. |
| JSON `max_bytes` | 16,777,216 | `cargo metadata --format-version 1 --locked --all-features` printed 152,604 bytes for 45 packages at 0e29ca7, 3,391 bytes per package; 16,777,216 is 109.9 times that, room for about 4,947 packages. |
| JSON `max_values` | 1,048,576 | That output had 6,603 values, 146.7 per package; 4,947 packages × 146.7 is about 725,700, and 1,048,576 is the next power of two. |
| JSON depth | 128 | That output nests 8 deep (boneli-json's count). Cargo's 80 levels of `[package.metadata]` appear in the output inside 4 more (root, `packages`, the package, `metadata`): 84, and 128 is the next power of two. |
| cfg depth | 32 | The deepest dependency `cfg` at 0e29ca7 nests 3 combinators (`all(any(all(...)))`, among 18 distinct target expressions); 10 × 3 = 30, and 32 is the next power of two. Python had no bound but its recursion limit. |
| `CHECK_STACK` | 524,288 | Below. |

Peak memory of the JSON parse at both limits, measured (test profile, the
profile the entry point builds; glibc, x86_64, rustc 1.98.0; peak RSS of
the process, about 3.8 MiB before the parse): an object of 1,048,575
members with 11-digit keys, 16,777,201 bytes, peaks at 159,056 KiB (155.3
MiB); 1,048,575 zeros in an array (2 MiB) at 71,192 KiB; 1,048,575
16-byte strings (16 MiB) at 85,324 KiB; 524,287 one-member objects at
89,304 KiB. The planning estimate was 2 × `max_bytes` plus ADR-008's
worst case of 136 bytes per value × `max_values`, 32 MiB + 136 MiB = 168
MiB; the measured worst is below it.

`CHECK_STACK`: the check runs on one spawned thread whose stack is the
smallest power of two on which the deepest operation uses at most 75% in
the test profile, the rule of ADR-008 D6 and ADR-011 D6 (a quarter of
headroom for frames that grow with a compiler upgrade). Bisected to 1 KiB
in a child process (an overflow aborts; rustc 1.98.0, x86_64, glibc; the
ignored test `stack_probe` is the aid), each operation at the deepest
input the limits accept and read the way the check reads it (parsed,
printed as a message would print it, dropped):

| Operation | Input | Smallest thread |
|---|---|---|
| TOML | dotted key of 128 levels | 245,296 B |
| TOML | inline tables, depth 128 | 245,296 B |
| TOML | header chain, depth 128 | 243,252 B |
| TOML | arrays, depth 128 | 189,086 B |
| `cargo metadata` | objects, depth 128 | 210,548 B |
| `cargo metadata` | arrays, depth 128 | 125,722 B |
| cfg | 32 combinators, parsed and evaluated | 52,138 B |

The deepest needs 245,296 bytes. 262,144 (256 KiB) would be 93.6%, so the
stack is 524,288 (512 KiB), where it is 46.8%.
`deepest_inputs_fit_check_stack` runs every operation on a `CHECK_STACK`
thread.

### D5. Matching without regular expressions

The checker has no regex crate (no new crate, and backtracking is what
made the format-spec match quadratic). Every pattern is a hand-written
matcher with the semantics of Python's `finditer`: leftmost,
non-overlapping, the same matched text. The expected outputs of the
matchers, the lexer and the helpers were computed once from the Python
functions and are committed as literals (`src/py_vectors.rs`, 14 tables).

- **Whitespace, as explicit sets.** Rust's Pattern_White_Space (11
  characters: U+0009 to U+000D, U+0020, U+0085, U+200E, U+200F, U+2028,
  U+2029) for the lexer, comment blanking and attributes, as before.
  Python's `\s` and `str.isspace` (29: U+0009 to U+000D, U+001C to
  U+001F, U+0020, U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028,
  U+2029, U+202F, U+205F, U+3000) for format specs, cfg tokens and every
  strip and split. Never `str::trim` or `char::is_whitespace` (Unicode's
  White_Space, 25 characters, without U+001C to U+001F): a reason of only
  U+001C is empty, as it was. Where rustc accepts fewer characters than
  the 29 (in `{:p }`), the larger set makes a match more likely, never
  less, so it fails closed. The 29 are pinned against `str.isspace` over
  all of Unicode (`whitespace_set_matches_python`).
- **Word boundaries stay ASCII**, as in ADR-001: a non-ASCII neighbour
  makes a match more likely, never less.
- **Identifier classes:** ASCII as before; a non-ASCII character continues
  an identifier if `char::is_alphanumeric` and starts one if it is also not
  `char::is_numeric`. Python's `\w` differs from that on two classes:
  combining marks with the Alphabetic property (U+093F continues an
  identifier here, as in rustc, where Python splits `task` from it) and
  letter numbers (U+2167 starts an identifier for Python, not here or in
  rustc). Merging or splitting an identifier can only cause a false
  positive or affect code rustc rejects, because no character rustc accepts
  outside an identifier is alphanumeric: `task` followed by U+093F is one
  identifier for rustc, so it is no path through `core::task`. Both cases
  are pinned in `non_ascii_identifier_classes`.
- **The format spec in one pass.** The pattern is `{`, no braces, `:`,
  optionally any character and one of `<^>` (a fill, which may itself be
  a brace, and an alignment), no braces, `p`, whitespace, `}`. Without a
  fill nothing between the braces can be a brace, so a match from a `{`
  can only end at the first brace after it, and its text does not depend
  on which `:` is taken. A brace can be the fill only when that first
  brace directly follows a `:` and is followed by one of `<^>`; the match
  then ends at the next brace after the alignment. Python tries that case
  first (its `*` takes the rightmost `:` and its `?` takes the fill), so
  it is checked first. Each run between braces is read a bounded number
  of times, so a whole file is linear: `format_spec_is_linear` matches a
  megabyte of `{` followed by a megabyte of `:` (Python's regex is
  quadratic there) and four other worst cases.
- **`\u{d800}` to `\u{dfff}`** in a string literal decode to U+FFFD, a
  character no rule matches, as Python's lone surrogate did.

### D6. Deliberate differences from Python, all fail closed

- **Unsupported TOML scalars:** a float, a date or time, or a hexadecimal,
  octal or binary integer anywhere in a manifest or the policy is a tool
  error that names the feature (`invalid TOML: unsupported TOML feature:
  float ...`); Python parsed it. Measured while planning: none of the 170
  TOML inputs the checker reads (every workspace and fixture manifest, the
  policy, its 8 overlay copies, the policy with each of the 29
  `policy-append` files) uses one, and all 170 give the same result under
  `tomllib` and `boneli-toml` (167 equal values, 3 errors in both). The
  fixtures `tool-manifest-float` (a float in `[package.metadata]`, which
  Python read and ignored) and `tool-policy-date` (a date in a policy
  record, which Python read and reported only as an unknown key) pin it.
  Widening goes through ADR-011 D1.
- **Integers outside `i64`** are a tool error; cargo rejects them too.
- **The limits of D4**, where Python had none.
- **A directory that cannot be read**, in a member or anywhere in the
  config walk, is a tool error naming it; `os.walk` skipped it, which
  failed open (`unreadable_directory_is_tool_error`).
- **`[lints] workspace = 1`** is `lints-inherit`; Python accepted it
  because `True == 1`, but cargo rejects such a manifest before the
  members are read.
- **Values in messages** are printed as TOML (`nothing`, `true`, `5`,
  `["a"]`, `{ level = "x" }`) where Python printed `str()` of a Python
  value (`None`, `True`, `{'level': 'x'}`). Messages that interpolate a
  string are verbatim. TOML parse errors carry boneli-toml's text.

### D7. Parity

Until the removal commit, CI ran both checkers on the workspace, and the
fixture runner ran the Python checker on every fixture workspace it built
(`BONELI_ARCH_PARITY` named the script). A run failed unless both outputs
were well formed, with equal exit codes, equal summary counts and equal
multisets of `(rule, path, line)` over the FAIL lines, which is stronger
than the issue's rule sets: a lost duplicate or a finding on the wrong
line fails. The runner also counted byte-identical FAIL lines and listed
the pairs that differ, report-only.

Result (1 base run, 141 single-run cases and 60 `core-token` snippets:
202 runs, each by both checkers): every run agreed. 244 of 247 FAIL lines
were byte-identical; the 3 that differ are the TOML parse errors of
`policy-duplicate-edge`, `policy-duplicate-table` and
`tool-invalid-manifest`, where the two parsers word the error differently.
In CI, on the parity commit 17626fe of the pull request that adds this ADR
(https://github.com/Replikanti/boneli/actions/runs/44659024845, job
`check`), every one of the 202 runs agreed, with the same 244 of 247
byte-identical lines, and both checkers printed OK on the workspace.

### D8. Self-scan

The checker scans its own package like any other member. Where its source
must hold the `unsafe` token in a string (the rule ids `lints-unsafe`,
`doctest-unsafe` and `unsafe-token`, the doctest attribute, messages, test
inputs), it writes `\x75nsafe`, which rustc decodes and the token scan does
not match. It uses no `macro_rules!`, because the source-redirect rule
reads `#[doc = $x]` inside a macro as a possible `#[path = ...]`. Test
inputs that must hold the token are escaped the same way; no test data
file ends in `.rs`.

### D9. The fixture runner

`--fixtures` follows ADR-001 D5 step for step: the base run, the overlay
with `.fixture` suffixes stripped and symlinks kept, `remove`,
`policy-append`, `snippets`, `outside` and `git`, then the fake registry,
the `.cargo/config.toml` that replaces crates.io one level above the
workspace, the offline lockfile, the output checks and the rule coverage
check. Two details changed:

- **Empty checksums.** Each fake registry crate gets
  `.cargo-checksum.json` = `{"files":{},"package":null}`. Measured while
  planning: cargo accepts that for `generate-lockfile --offline`,
  `metadata --locked` and `check --locked`, so the runner needs no SHA-256
  (Python hashed every file).
- **Git isolation.** The fixture repositories are created with
  `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=/dev/null`, so a
  developer's commit signing or hooks cannot break them
  (`fixture_git_ignores_user_config`).

The temporary directory is `boneli arch <label> <unique>` in the system
temp directory, mode 0700, removed when the run ends; its name keeps the
space ADR-001 D5 requires. The checker under test is the runner's own
binary.

Times on one machine (12 cores, Linux 7.2, the entry point's build
warm): the 202 fixture runs take 99.3 s with the Rust checker, 152.4 s with
the Python checker, and 219.5 s in the parity mode, which runs both.
With the two fixtures of D6 the suite is 204 runs in 144 cases, and every
one of the 32 rules stays pinned by some `expect`.

### D10. No Python in tooling or tests

**The boneli-oci test.** `exited_main_thread_reads_unreadable` (round 3 of
the review of #60) checked the store's liveness rule (ADR-009, D8) on a
process whose main thread has exited while another thread runs: the
leader's `ns/time` link then fails with `ENOENT`, and the store must
record `UNREADABLE_TIME_NAMESPACE` for it, never 0. A `python3` helper
produced that process with `ctypes` and a raw `SYS_exit`. Measured while
planning, on this toolchain: libtest runs every test on a spawned thread,
also with `--test-threads=1` (the main thread waits on a channel), so a
re-executed test binary cannot end its own main thread; a process whose
main thread has exited needs a binary with its own `main`. On Linux 7.2,
once the leader has exited while a thread runs, its state is `Z`,
`/proc/<pid>/ns` is still a directory with a `time` entry whose link
fails with `ENOENT`, and the running thread's
`/proc/<pid>/task/<tid>/ns/time` reads the same link as the parent's
`/proc/thread-self/ns/time`.

**`boneli_sys::exit_main_thread() -> Result<Infallible>`.** It compares
`SYS_gettid` with the process id. On any other thread it returns
`Error::NotMainThread` and changes nothing. On the main thread it calls
`SYS_exit(0)`, not `exit_group`, which ends that thread only; the process
runs until its last thread ends. If the syscall ever returned, it aborts;
it never returns `Ok`. Each syscall has its own `unsafe` block with a
`// SAFETY:` comment (rule `sys-lints`).

Why a safe function is sound: only the main thread can end itself this
way, and that is checked before any effect. Its stack is the process's
initial stack, which stays mapped while any thread runs, so a reference
another thread holds into it stays valid, and no thread can join the main
thread. Its destructors and thread-local destructors do not run, which is
a leak, and safe Rust allows leaks (`mem::forget`). A lock it holds stays
held, which is a deadlock, not undefined behaviour. Output std still
buffers is lost; the doc comment says to flush first.

Why this is the smallest surface: std ends a thread only when it returns,
and returning from `main` ends the process, while boneli-oci forbids
`unsafe`. Rejected: ending the main thread from another thread with a
signal whose handler calls `SYS_exit` (a process-wide handler installed by
a safe function, interrupting the main thread wherever it is, possibly
inside `malloc`); `CommandExt::pre_exec` or a fork-based helper (`unsafe`
in boneli-oci, or a fork of a multithreaded process); re-executing a
libtest binary as the helper (every test runs on a spawned thread).

**Two `harness = false` tests**, each the parent and, with a marker
variable, its own helper: the helper's second thread polls
`/proc/self/stat` until the leader is `Z` (at most 1,000 polls of 10 ms,
a hang bound of 10 s, not a target), prints its thread id from
`/proc/thread-self` and sleeps 60 s, while its main thread calls
`exit_main_thread`. The parent reads the id, checks the helper, then kills
and reaps it; a helper that ends early, prints no id or never sees a
zombie leader fails the test without a hang (a helper with the call
delayed past the bound failed in 10.9 s, checked by hand). Both tests
ignore the arguments cargo passes and need no host preparation, so both
run in `check` (`cargo test --workspace`); the `boneli-sys` one also runs
in the `sandbox` job, whose `boneli-oci` step runs only the
`boneli_oci_tests` target.

- `crates/boneli-sys/tests/exit_main_thread.rs`: the leader is `Z`, the
  running thread is neither `Z` nor `X`, and the helper still runs until
  it is killed. `exit_main_thread_refuses_other_threads` covers the
  other path.
- `crates/boneli-oci/tests/exited_main_thread.rs` asserts the kernel facts
  the liveness rule reads. With time namespaces (the parent's
  `/proc/thread-self/ns/time` reads): the exited leader's `ns/time` fails
  with `ENOENT` while `/proc/<pid>/ns` is still a directory with a `time`
  entry, so `kernel_lacks_time_namespaces` cannot take it for a kernel
  without time namespaces and `time_namespace_of` gives
  `UNREADABLE_TIME_NAMESPACE`; the running thread's link reads the
  parent's namespace. Without time namespaces, neither directory has a
  `time` entry. How these facts map to the stored value stays pinned by
  the unit tests of `time_namespace_of` and `kernel_lacks_time_namespaces`
  on synthetic directories. Decided at STOP 1 of #35: the binary asserts
  the facts, and boneli-oci's API does not grow a `#[doc(hidden)]` wrapper
  of `own_time_namespace` for a test.

**CI without Python.** Both jobs that build code, `check` and `sandbox`,
run a step "Hide Python" right after the toolchain and cache actions: for
every directory on PATH, each `python*` executable gets a stub of the same
name in `$RUNNER_TEMP/no-py`, which appends its arguments to `calls.log`
there and exits 127; the directory is prepended through `$GITHUB_PATH`.
The step globs `[p]ython*`, so the workflow itself has no hit of the
grep below. The last step of
each job, "No Python was called", fails if `calls.log` exists, so a call
whose error some script swallows still turns the job red. The stub sees
only calls through PATH; a `#!/usr/bin/python3` shebang or a call by
absolute path gets past it (round 1 of the review ran both). The step
"No Python in tracked files", git only and before the toolchain, catches
those in what the repository holds: it fails unless
`git grep -n -a -E '\bpython3?\b' -- ':!docs/adr' ':!crates/boneli-toml/tests/toml-test'`
prints nothing (checked by hand: a tracked `#!/usr/bin/python3` script
fails it). `-a` reads every file as text: with `-I`, found in round 2,
a `.gitattributes` line `tools/gen -diff` in the PR marked such a script
binary and the grep skipped it. Making the runner's interpreters non-executable was rejected:
the runner's own system tools may need them, and a name built at run time
from pieces would still pass both; D10 is a policy, and review owns what
a grep cannot see. Without the exclusions it finds only the vendored
toml-test pair `valid/inline-table/end-in-bool` (a `python` key) and ADR
history. Mentions of the language that stay, none an invocation, are
the stacks Boneli debugs in `docs/ARCHITECTURE.md`, the Python test
markers of #69 in `boneli-domain`, the changelog and the ADRs. The weekly
`oci-acceptance` workflow never ran Python and gets no stub.

ADR-007 (proposed, owned by #6) is not edited.

## Consequences

- The gate's trusted base now includes `boneli-json`, `boneli-toml`, the
  checker crate and their compilation, instead of a Python interpreter.
  The entry point refuses to build them when the build could run code
  (a build script, a proc macro, another crate in the closure, a checker
  crate outside the workspace or behind a symlink; D2), so
  what runs before the check is rustc compiling those three crates. In
  CI the gate is the first step of `check` that runs cargo (D2), and all
  three crates are reviewed on every change (the always-review list).
- A float, date or non-decimal integer in a manifest's
  `[package.metadata]` blocks the check (D6), where cargo would accept it.
  The message names the file and the feature.
- Cold build of the checker by the entry point: 4.97 s on the machine of
  D9, where the check of the workspace then takes 1.78 s and the Python
  checker took 6.47 s. In CI (the parity run above, `ubuntu-latest`, no
  cached `target/arch-check`), the "Architecture rules" step, cold build
  included, took 12 s and the Python checker's step 3 s; the parity
  fixture step, both checkers on 202 runs, took 83 s, and the job as a
  whole 3 min 40 s. Without the parity mode the fixture step runs one
  checker per run instead of two.

## Accept when

CI runs both checkers on every fixture run and they agree, on the parity
commit of the pull request that adds this ADR. Met on 2026-11-20 (D7).

## Alternatives considered

- **Keep Python** and pin a version in CI. Keeps the unchecked tooling,
  the quadratic regex and the second runtime.
- **A regex crate.** A new external crate for the gate, with an ADR of its
  own, and the matchers would still need the Python semantics pinned.
  `regex` is linear, but its leftmost-first semantics on these patterns
  would have to be proven equal anyway.
- **Canned `cargo metadata` JSON for the fixtures**, rejected in ADR-001 D5
  for the same reasons as then.
