# ADR-001: Semantic core purity, unsafe containment and a transitive dependency allowlist

- Status: accepted
- Date: 2026-11-12

## Context

The setup put the architecture rules of `docs/ARCHITECTURE.md` into a bash
script, `tools/check-architecture.sh`. The adversarial review of that setup
(boneli#27) found changes a later pull request could make that break a stated
invariant while CI stays green (issue #28):

- **Lint inheritance** was a text grep on `crates/<name>/Cargo.toml`. A crate
  whose directory differs from its package name was skipped, and a
  `workspace = true` line in a dependency table satisfied the grep. Nothing
  checked that the workspace lints still forbid `unsafe_code`, and a committed
  `.cargo/config.toml` with `--cap-lints allow` switched every lint off.
- **`unsafe` through a macro:** a `macro_rules!` exported by another crate
  expands `unsafe` that `forbid(unsafe_code)` in the calling crate does not
  see.
- **Core purity** was a text scan over `src/`. An aliased import, an import
  that rustfmt wraps, a `#[path]` module outside `src/` or a moved crate
  directory bypassed it, and a grep error was swallowed by `|| true`.
- **Sources:** external crates were checked by name only, so a vendored path
  crate with an allowlisted name passed, and cargo-deny ignores path sources.
- **Transitive allowlist:** ARCHITECTURE says the allowlist covers transitive
  crates, but only direct dependencies were checked.

None of these was reachable yet, because the workspace has no external crate.
This decision lands before the first one (#5, #6).

The adversarial review of the first version of this decision (PR #36)
reproduced six more holes, all closed below:

- A target source that is not a `.rs` file (`[lib] path = "src/lib.in"`)
  hid a whole crate root, including an exported `unsafe` macro, from every
  scan.
- A build script in an adapter compiled and linked C code that ran before
  `main`; no `unsafe` rule sees the C compiler.
- A committed `rust-toolchain.toml` with `path = ...` replaced the `cargo`
  that CI and the checker run, and that `cargo` rewrote the metadata.
- `--filter-platform` evaluates `cfg(...)` without the flags a real build
  uses, so an edge behind `cfg(target_feature = "crt-static")` (a static
  binary) disappeared, also into a core crate or into `libc`.
- Escapes in a format string (`"{:\u{70}}"`), `concat!`, and
  `core::fmt::Pointer` printed addresses without the listed `{...:p}` token.
- Two rule branches (declared dependency sources, build-dependencies in
  the member graph) had no fixture, so weakening them kept the suite green.

A second review round and QA found more, also closed below: seven more ways
for a core crate to print an address (an alias of `concat!`, a comment
before its `!`, `env!` reading a format string from the manifest,
`include_str!` of a `.rs` file holding the spec in a comment, `{` or `}` as
the fill character, and a glob import from `core::fmt` that brings
`Pointer` into scope without naming it); a core dependency under
`cfg(target_os = "none")` that only the no-std build compiles; and cfg
evaluator branches (`any`/`all` with an unknown operand, plain target
triples, a cfg the parser rejects) that no fixture pinned.

### Measurements

All runs used cargo 1.98.0, clippy 0.1.98 and cargo-deny 0.20.2 on a scratch
copy of `main` at the setup commit, during planning of #28.

Core purity, bypasses tried in `boneli-domain`. "caught" means
`cargo clippy --all-targets -- -D warnings` or `cargo check` failed.

| Bypass | old scan | `#![no_std]` | clippy lists (14 types, 16 methods) | build for `x86_64-unknown-none` |
|---|---|---|---|---|
| `use std::time::SystemTime as Clock;` | missed | caught | caught | caught |
| wrapped `use std::{ fs as storage, thread as worker, };` | missed | caught | caught | caught |
| `#[path = "../clock.rs"] mod clock;` | missed | caught | caught | caught |
| `include!("../clock.rs")` | missed | caught | caught | caught |
| `std::println!` and `std::io::stdin()` | missed | caught | missed (not enumerated) | caught |
| `pub async fn` | caught | missed | missed | missed |
| `extern crate std;` | caught only via `Instant::now` in the same case | missed | caught | caught |
| `#[cfg(not(target_os = "none"))] extern crate std;` | not run | missed | not run | missed |
| `core::arch::x86_64::__cpuid(0)` (no `unsafe` needed on 1.98) | missed | missed | missed | missed |
| `(x as *const u8).addr()` (differs per run, ASLR) | missed | missed | missed | missed |

Other measurements:

- `boneli-domain` with `#![no_std]`, `extern crate alloc;`, `BTreeMap`,
  `String`, `Vec`, an error type implementing `core::error::Error`, a
  `#[cfg(test)]` unit test without `extern crate std`, and an integration test
  in `tests/` that uses `std`: clippy `--all-targets -D warnings` clean,
  `cargo test` green.
- `rustup target add x86_64-unknown-none` took 6.5 s and 84 MB on disk;
  `cargo check` of both core crates for that target took under 1 s.
- A doctest with `unsafe { *p }` and `std::time::SystemTime::now()` passes
  `cargo test` although the crate inherits `unsafe_code = "forbid"`: the
  workspace lints do not reach doctests. With
  `#![doc(test(attr(forbid(unsafe_code))))]` in the crate root that doctest
  fails, and `#![allow(unsafe_code)]` inside the doctest is rejected (E0453).
- cargo-deny `[bans] allow`: (a) every workspace member has to be listed too,
  otherwise one `not-allowed` error per member; (b) `wrappers` on an `allow`
  entry is accepted and silently ignored (`boneli-http -> libc` passed with
  `wrappers = ["boneli-sys", "getrandom", "ring"]`); (c) `deny` entries with
  `wrappers` do limit the direct parents, but the crate then has to be in both
  lists and an allowed crate is reported as "explicitly banned"; (d) a
  non-member path crate named `httparse` passes both `bans` and `sources`;
  (e) an `allow` entry for a crate that is not in the graph gives no warning.
- A cargo config with `[source.crates-io] replace-with` pointing at a local
  directory makes vendored code report the crates.io source in
  `cargo metadata`, and `cargo deny check sources` passes.
- Graph size for `boneli-sys -> libc 0.2`, `boneli-http -> httparse 1` and
  `boneli-https -> rustls 0.23 (ring, std) + webpki-roots 1`, resolved with
  `--all-features`: 27 external crates and 36 edges without a platform filter,
  11 of them `windows-*`/`wasi` crates; 16 crates and 24 edges with
  `--filter-platform x86_64-unknown-linux-gnu`; 16 crates and 25 edges with
  `aarch64-unknown-linux-gnu` added. The extra edge, `ring -> libc`, exists
  only on aarch64, and `libc` also arrives through `getrandom`.
- `cargo metadata` has no `lints` field, so lint inheritance can only be
  checked by parsing the manifests.
- Re-measured on 2026-11-12 for the cfg evaluation of D3, same setup and
  cargo 1.98.0, resolving rustls 0.23.46, ring 0.17.14, getrandom 0.2.17,
  libc 0.2.191 (scratch workspace, review round of PR #36): 27 external
  crates and 35 edges without a filter; 16 and 23 with
  `--filter-platform x86_64-unknown-linux-gnu`; 16 and 24 with aarch64 gnu
  added, and still 16 and 24 with both musl targets added. The cfg
  evaluation of D3 over the four targets, walking only reachable packages,
  gives the same 16 crates and 24 edges: the new method needs no extra
  policy records for this stack. The two conditional edges into `libc` are
  `getrandom -> libc` (`cfg(unix)`) and `ring -> libc` (aarch64 Linux
  only). All 13 distinct target specs in that graph parse.
- `rustc --print cfg --target <t>` works for targets whose standard library
  is not installed, and for musl it prints `target_feature="crt-static"`
  (a default that `-C target-feature=-crt-static` turns off).
- Format strings: `format!` accepts `"{:\u{70}}"`, `"{:\x70}"`, a line
  continuation inside the spec, `concat!("{:", "p}")`, `stringify!({:p})`
  and `include_str!("fmt.txt")` with a file containing `{:p}`; all compile
  and print an address.
- cargo rejects a malformed `cfg(...)` in a target table and a `links` key
  without a build script when it loads the manifest ("package specifies
  that it links to `native` but does not have a custom build script"), and
  it lists build-dependencies even when the package has no build script.
  It takes a backslash in a cfg string literally: `cfg(target_os = "li\nux")`
  loads, and the checker's parser rejects it.
- TOML (Python 3.14 `tomllib`): declaring the same edge table twice is an
  error, not last-wins.

## Decision

The checker is `tools/check_architecture.py`, run through the unchanged entry
point `tools/check-architecture.sh`. It takes members, manifests, targets and
dependency edges only from `cargo metadata`, fails on any tool error and
reads its policy data from `tools/architecture.toml`.

### D1. Core purity: `#![no_std]` with `alloc`, a no-std build, a token scan

- **Attribute.** The leading inner-attribute block of each core crate's lib
  root (`roles.core`: `boneli-domain`, `boneli-app`) contains an
  unconditional `#![no_std]`. The leading block is the file start, skipping
  blank and `//` lines, then `#![...]` attributes.
- **No-std build.** The checker runs
  `cargo check --locked --lib --target x86_64-unknown-none` for the core
  crates. That target is tier 2 with prebuilt `core` and `alloc` and no
  `std`, so it needs no nightly `build-std`, and it is 64-bit like the
  shipped targets, so `usize` behaves the same. `#![no_std]` removes all of
  `std` by construction; clippy `disallowed-*` lists cover only what someone
  enumerated (they missed `println!` and `stdin`, table above).
- **Token layer** over every `.rs` file in the core package directories
  (and every target source, see D2), for what `no_std` cannot remove and
  for `std` behind a `cfg`. Whole-line `//`
  comments are blanked, unless the line contains `*/` or `"`: such a line can
  close a block comment or a string from an earlier line, and what follows is
  code. Everything else, block comments and strings included, is scanned
  (fail closed). Tokens match at identifier boundaries; the whitespace class
  is Rust's `Pattern_White_Space` (U+0009-U+000D, U+0020, U+0085, U+200E,
  U+200F, U+2028, U+2029). The tokens and why:
  - `std`, and `extern crate` except `extern crate alloc;`: `std` behind a
    `cfg` passes the no-std build (measured). Core crates have no external
    dependencies, so `std` cannot be reached without writing the token.
  - `async`, `await`: `no_std` does not remove them (measured).
  - `HashMap`, `HashSet`, `RandomState`, `SystemTime`, `Instant`,
    `UNIX_EPOCH`: hash order and the wall clock; a second layer behind
    `no_std`.
  - `arch`: `core::arch` gives machine-dependent results (`__cpuid` needs no
    `unsafe` on 1.98), and `asm!` lives there.
  - `atomic`: shared mutable state across runs and threads.
  - `*const`, `*mut`, `&raw const`, `&raw mut`, `ptr`, `UnsafeCell`,
    `as_ptr...`, `as_mut_ptr...`, `into_raw...`, `addr`, `expose_provenance`,
    `Pointer` (`core::fmt::Pointer::fmt` prints an address without a format
    spec) and format specs that end in `p` (`{:p}`, `{0:p}`, `{name:p}`,
    `{:#p}`, fill, width and precision variants): addresses differ per run
    (ASLR).
  - The format spec is matched on the raw content of every file in a core
    package, any extension and comments included, because `include_str!`
    turns any file, also a `.rs` file whose only line is a comment, into a
    format string; a spec inside a comment therefore fails closed. It is
    also matched on every string literal after its escapes are decoded
    (`\u{..}`, `\x..`, line continuations), because rustc decodes them
    before it parses the spec. The fill character may be any character,
    `{` and `}` included (`{:}>16p}` compiles). `include_str!` and
    `include_bytes!` take exactly one literal path inside the package, so
    the file they read is one of those.
  - `concat`, `stringify`, `env` and `option_env`, as identifiers with or
    without a following `!`: the first two build a format string from pieces
    that are no single literal (`concat!("{:", "p}")`), and matching the bare
    identifier also catches an alias (`use core::concat as cc;`) and a
    comment between the name and `!`. `env!` and `option_env!` read the
    build environment at compile time, an impure input to the core on its
    own, and can carry a format string (from a manifest field, for example).
  - A glob import from a `fmt` module path (`core::fmt::*`, `alloc::fmt::*`,
    `fmt::{self, *}`, also inside use-groups) and a rename of a `fmt` module
    (`use core::fmt as f;`): the glob brings the `Pointer` trait into scope,
    and method resolution can then print an address without the name
    `Pointer` appearing (reproduced in review).
  - **Limit, stated plainly.** A text scan cannot enumerate every way to
    obtain an address; a function pointer cast to an integer
    (`marker as fn() as usize`) has no token at all. The token list is a
    best-effort first layer. The gate for this class is #2's acceptance
    test: folding the same event sequence through `Run::handle` in two
    separate processes gives byte-identical `Debug` output for the final
    run and every command list.
  - The old `fs::`/`net::`/`env::`/`thread::`/`process::` and `.elapsed()`
    patterns are dropped: the `std` token covers them without aliases, and
    they flag names the domain needs, such as a budget's `elapsed`.
- **Shape.** A core crate has exactly one `lib` target with crate type `lib`
  plus `test` targets, no build script, bin, example, bench or proc macro,
  and no `[features]`.

### D2. `unsafe` only in `boneli-sys`

- Every member except `roles.unsafe` has a manifest `lints` table equal to
  `{ workspace = true }`, parsed with `tomllib`. The root
  `workspace.lints.rust.unsafe_code` is `forbid` (string or `level`): `deny`
  can be lowered by `#[allow]` in source.
- An `unsafe` token scan covers every member outside `roles.unsafe`. Macro
  bodies are text, so an exported `macro_rules!` with `unsafe` is caught
  where it is defined.
- Every lib root outside `roles.unsafe` carries
  `#![doc(test(attr(forbid(unsafe_code))))]` (measured: closes the doctest
  hole). `boneli-domain` pins it with a `compile_fail` doctest.
- `boneli-sys` has no `macro_export`, and no member is a proc-macro crate: a
  proc macro can emit `unsafe` built from strings that no text scan sees.
- **Complete file set.** No member uses `#[path = ...]` (also in
  `cfg_attr`) or `include!`, no attribute or macro name is built from a
  macro metavariable (it could carry either), every target's source file
  (lib, bin, test, bench, example, build script) ends in `.rs` and lies
  inside its package, and no package directory contains a symlink. The
  scans read `.rs` files, and `mod` declarations only resolve `.rs` files,
  so they see every crate root and every module. A non-`.rs` crate root is
  scanned as well, so its content is reported too.
- **No build scripts** outside `roles.build-script` in the policy, in any
  member, core or not. A build script runs arbitrary code at build time and
  can compile and link native code (measured in review: a C constructor ran
  before `main`) that no Rust scan sees. A native library declared with
  `links` is covered too: cargo rejects `links` without a build script
  when it loads the manifest (measured), so the build-script rule always
  fires for such a crate, and a separate `links` check would be dead code
  that no fixture can pin. The list is empty today, and a core crate cannot
  be listed. A crate that needs one (for example a vendored C library) is
  added in the same PR as an ADR that names it; review enforces that, as
  for a new crate name.
- **No toolchain files.** No `rust-toolchain` or `rust-toolchain.toml`
  anywhere in the tree. Such a file picks the `cargo` and `rustc` that CI
  and this check run: `path = ...` can point at a committed fake `cargo`
  (reproduced in review), and a nightly `channel` unlocks
  `profile-rustflags`, which can cap lints. A pin is out of scope here; the
  ADR that adds one will allow `channel` and forbid `path`. As defense in
  depth, both CI jobs set `RUSTUP_TOOLCHAIN` to the toolchain the workflow
  installs, which outranks any toolchain file. The check looks for these
  files before it runs any cargo command.
- **No config files.** No `.cargo/config` or `.cargo/config.toml` anywhere in
  the tree: each can open a bypass (`--cap-lints allow`, `[source]`
  replacement, `[patch]`, `[env]`, `build.rustc-wrapper`). No `clippy.toml`
  or `.clippy.toml`: they can relax lints. Setting `RUSTFLAGS: -D warnings` in
  the workflow, the review's proposal, overrides only config `rustflags` and
  leaves the rest open.

### D3. Dependencies: an edge allowlist, sources from crates.io only

- **Graph.** The checker reads `cargo metadata --locked --all-features`
  without `--filter-platform` and filters edges itself. Every edge whose
  child is not a workspace member, from a package reachable from the
  members over applying edges, needs a record
  `[external.<child>.pulled-by.<parent>]`. All dependency kinds count
  (normal, build, dev). Edges match by package name, not version; member
  status comes from package IDs, never from a `boneli-` prefix.
- **Which edges apply.** An edge's `cfg(...)` (or target triple) is
  evaluated with three-valued logic against each checked target, with the
  values `rustc --print cfg --target <t>` prints. Names whose whole value
  set that output covers (`target_os`, `target_family`, `target_arch`,
  `target_env`, `target_abi`, `target_vendor`, `target_endian`,
  `target_pointer_width`, `target_has_atomic`, `unix`, `windows`) are
  known: a value it does not print is false. Every other name is unknown,
  because it depends on flags, the profile or the build: `target_feature`
  (`crt-static` for a static binary), `debug_assertions`, `panic`,
  `overflow_checks`, any custom `--cfg`. An edge is ignored only when it is
  false on every checked target under every value of the unknowns. A
  malformed cfg is a tool error. Edges of the core crates are also
  evaluated on the no-std build target (`x86_64-unknown-none`), because the
  checker builds them there: a dependency under `cfg(target_os = "none")`
  reaches no shipped binary but is compiled, build script included, in CI
  (reproduced in review). Why not `--filter-platform`: cargo
  evaluates the cfg without the flags a real build uses, so an edge behind
  `crt-static` vanished from the checked graph (reproduced in review) while
  a static release build compiles it. The same evaluation decides which
  declared dependencies of members the crate-graph rules see.
- **Core crates take no external dependency** on any applying target: a
  declared non-member dependency of `boneli-domain` or `boneli-app` (dev
  aside) fails the graph rule, besides the missing edge record.
- **Why edges and not a set of names:** `libc` reaches `boneli-https` through
  `getrandom` (measured). With a name set, `libc`, approved for
  `boneli-sys`, would pass under any parent. Edges keep ARCHITECTURE's
  "Where it may appear" column true transitively.
- **Platforms.** The runner is Linux-only: x86_64 and aarch64, each with
  glibc and with musl, because static binaries such as the shim may ship on
  musl. Without filtering, the policy would need 11 crates that never build
  here (27 vs 16 crates); without aarch64 the aarch64-only edge
  `ring -> libc` would go unchecked. Further release triples are added by
  the release work (#22).
- **Sources.** Every reachable non-member package has the crates.io source;
  every declared dependency of a member, on any target, is a path to a
  member directory or comes from crates.io; the root manifest has no
  `[patch]`, `[replace]` or `workspace.exclude`. An unreachable package can
  only enter through a member's declared dependency, because crates.io
  does not accept crates with git or path dependencies.
- **Policy shape.** `[external.<crate>]` has `reason` and `decision`: why the
  crate is allowed and what approved its name. Each allowed parent has its
  own `[external.<crate>.pulled-by.<parent>]` with `reason` and `decision`.
  A `decision` is `ARCHITECTURE` or `ADR-NNN`, and `ADR-NNN` resolves to
  exactly one `docs/adr/NNN-*.md`.
- **Strict crates.** A crate with a `strict` key is strict; the value names
  the ADR that marked it (`strict = "ADR-NNN"`). A malformed marker is a
  format failure and the crate stays strict (fail closed). Every edge into a
  strict crate cites an `ADR-NNN`, never `ARCHITECTURE`, and that ADR's first
  `- Status:` line is `- Status: accepted` and it contains the edge literally
  in ASCII as `` `<parent> -> <crate>` ``. Both file checks run after HTML
  comments are removed, an unterminated one up to the end of the file,
  because rendered Markdown hides them. So an ADR that names an edge must
  not open an HTML comment before it, not even in prose or code. Accepted
  only, because a proposed, rejected or superseded ADR has not approved
  anything; when an approving ADR is superseded, the record moves to the new
  ADR, which names the edge again.
- **`libc` is strict.** It is the only approved crate with raw syscall
  access, so every new parent is a new path to the kernel next to
  `boneli-sys`, the security boundary of ARCHITECTURE "Isolation".
  ARCHITECTURE's table says only "only `boneli-sys`" and names no edge the
  checker can match, so this ADR records that one approved edge:
  `boneli-sys -> libc`.
- **Content today.** The 8 crates ARCHITECTURE approves, with
  `decision = "ARCHITECTURE"`, and today's direct parents as edge records;
  the `libc` record cites this ADR. Entries not used yet pass.

**Who enforces what.** "Review" is the adversarial security review that every
change to the checker, its policy and its fixtures gets.

| Change | Needs | The checker enforces | Review enforces |
|---|---|---|---|
| A new external crate name | an ADR, or a row in the ARCHITECTURE table | a crate table with `reason` and `decision`; an `ADR-NNN` resolves to one file | that the ADR or the row actually approves the crate |
| A new edge into a non-strict crate already in the policy | a record with `reason` and the ADR (or `ARCHITECTURE`) that approved the parent's stack | the record and both keys exist; an `ADR-NNN` resolves to one file | that the cited ADR covers the edge. This is the known weak spot: for non-strict crates the checker verifies only that the cited ADR file exists |
| A new edge into a strict crate (`libc`) | its own accepted ADR that names the edge | everything under "Strict crates" | that the ADR approves the edge instead of only mentioning it, and that no accepted ADR was edited to add it (the ADR README allows only status changes) |
| Adding a crate to `roles.build-script` | an ADR that names the crate and why it needs native code or a build step | the crate has a build script only if listed (cargo allows `links` only with one); a core crate cannot be listed | that the ADR approves this crate's build script |
| Marking a crate strict, or removing the marker | an ADR | `strict` cites an existing ADR; removing `libc`'s marker turns the `strict-edge-architecture` fixture red | that an ADR admitting another crate with raw syscall access (for example `rustix`, `linux-raw-sys` or `nix`) marks it strict |

**Rejected: cargo-deny `[bans] allow` as the allowlist or as a second layer**
(measurements (a)-(e)). It is a set of names: it cannot say which parent may
pull a crate (`wrappers` on `allow` is ignored), a vendored path crate passes
it by name, it would need every workspace member listed, and either
`[graph] targets` or the 11 never-built windows/wasi names. The failure it
would guard against, a bug in the checker's graph walk, is pinned by
fixtures instead: feature-gated, dev, build, target-specific, renamed and
two-version edges.

### D4. Checker language and contract

- **Python 3.11+ standard library** (`json`, `tomllib`, `re`, `subprocess`,
  `pathlib`, `tempfile`), run as `python3 -I`. The checker needs a JSON
  parser for `cargo metadata` and a TOML parser for the manifests, whose
  `lints` metadata does not report.
- **Rust was weighed and lost for now:** serde and serde_json are banned in
  `deny.toml`, the `toml` crate pulls serde, and the workspace's own parsers
  do not exist yet (`boneli-json` #29, `boneli-toml` #34, both waiting on
  this decision). The port is #35, after #29 and #34.
- **Bash lost** because it cannot parse TOML, and the swallowed grep exit
  code (`|| true`) was a bash failure class.
- **Contract:** subprocesses get argument lists, never a shell. Exit 0 means
  OK, 1 violations, 2 a tool error: any non-zero tool exit, an exception,
  invalid TOML, a non-UTF-8 `.rs` file, Python older than 3.11 or a missing
  `x86_64-unknown-none` target. Output is one line per violation,
  `FAIL [<rule-id>] <path>[:<line>]: <message>`, then `OK: ...` or
  `N violation(s)`. Flags: `--root <dir>`, `--list-rules`, `--fixtures`.
- **Fixtures are language-neutral** so the Rust port can run the same cases:
  a case is a directory of plain files, the expected result a set of rule
  IDs, and the policy uses only `[table]` headers, bare keys, basic strings
  and arrays of strings.

### D5. Fail fixtures

`tools/fixtures/arch/` holds a minimal passing workspace (`base/`), fake
crates.io crates (`registry/`) and one directory per case (`cases/<id>/`:
`expect`, `overlay/`, and optionally `remove`, `git/`, `outside/`,
`snippets`, `policy-append`). `tools/check-architecture.sh --fixtures`
copies `base` plus the real policy, `docs/ARCHITECTURE.md` and `docs/adr/`
into a temporary directory whose path contains a space, applies the case,
points crates.io at the fake registry through a `.cargo/config.toml` one
level above the fixture workspace, generates the lockfile offline, runs the
checker and requires the set of rule IDs and the exit code to equal the
case's `expect`. `base` must give no FAIL line, every rule ID must appear in
at least one `expect`, and an unparseable output line fails the run. CI runs
it on every pull request.

Copying the real policy means the fixtures also pin the real role lists,
platforms and allowlist: removing `libc`'s `strict` marker makes
`strict-edge-architecture` report nothing, so that case fails. Canned
`cargo metadata` JSON was rejected because it would not exercise the
checker's own flags, and real crates.io crates because they need the network
and upstream releases would change the results.

## Consequences

- Core code imports from `alloc` explicitly and has no `println!`, `Mutex` or
  `thread_local!`. Error types use `core::error::Error` (stable since Rust
  1.81; MSRV 1.85). Unit tests run without `std`.
- Tests in core crates do not write `std` either, because the scan covers the
  whole package directory; `include_str!` replaces reading fixture files at
  run time. In-memory adapters that need `std` (for example a `Mutex` once
  ports are `Send + Sync`) live in adapter crates; contract suites, generic
  functions over a port, can stay in `boneli-app`.
- Developers and CI need `rustup target add x86_64-unknown-none` once and
  Python 3.11 or newer.
- `--locked` makes a stale `Cargo.lock` fail the check, on purpose.
- **False positives** in the token layer fail closed: an `arch` field for an
  image platform, an error string containing `unsafe`, a `{:p}`, a `"` in a
  doc comment line of a core crate, or a macro that forwards attributes
  through a metavariable (`#[$meta]`). Rename, or widen the rule through a
  new ADR.
- **Residual risks:** a pointer address can still leak through a `core` or
  `alloc` API that is not listed, or through a function pointer cast to an
  integer (`marker as fn() as usize`, reproduced in review); see "Limit,
  stated plainly" in D1. The gate is #2's two-process replay test.
- **More false positives** in core crates: a field or variable named
  `env`, a glob import from `core::fmt`, or a `{...p}` pattern in a comment
  or a data file of a core package fail the check. The strict check is a text match, so an accepted ADR
  that names an edge only to reject it passes the checker; review owns the
  meaning, and the checker makes sure no edge into `libc` lands without an
  accepted ADR naming it. The runner itself can be weakened (for example by
  comparing as a superset); the exact comparison, the coverage check and
  review of `tools/` guard it.

## Alternatives considered

- **Clippy `disallowed-types`/`disallowed-methods` for core purity:**
  enumerates items, missed `println!`/`stdin` (measured); a lint level can be
  lowered in source unless it is `forbid`, and the config is found by a
  directory search, a second surface to guard.
- **cargo-deny `[bans] allow` for the transitive allowlist:** see D3.
- **`RUSTFLAGS: "-D warnings"` in the workflow against `.cargo/config`:** see
  D2.
- **Canned metadata fixtures, real crates.io crates:** see D5.
- **Rust or bash for the checker:** see D4.
- **`--filter-platform` for the platform filter:** see D3, "Which edges
  apply".
- **An allow list of toolchain-file keys** (`channel`, `components`,
  `targets`, `profile`) instead of banning the files: there is no pin to
  keep yet, so the ban is the smaller surface; the ADR that adds a pin
  allows `channel` and forbids `path`.
- **Build scripts allowed outside core, `unsafe` scan only:** a build script
  compiles C without any Rust token (reproduced in review); listing the
  few crates that need one keeps each in front of a reviewer.
