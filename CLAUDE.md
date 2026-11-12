# CLAUDE.md — boneli

Boneli reproduces bugs in a replica of the application with data, finds the
root cause with verified evidence and opens the fix as a pull request. This
repository holds everything that runs at the customer: domain, application,
sandbox runtime, shim, gateway, egress, adapters, runner, CLI and the bench
harness. Rust workspace, hexagonal architecture. Public repository
(Apache-2.0).

## Sources of truth

- Design: `docs/ARCHITECTURE.md` is the design baseline.
- Decisions since: `docs/adr/` (process in its README). A PR that makes a
  design decision adds or flips an ADR.
- Work: GitHub issues, labelled `area::*`, `P1`–`P3`, `size::*`, `epic`,
  `needs-adr`. The pinned "Task ledger" issue lists them in processing order.

## Invariants

1. **Crate graph:** `boneli-domain` → nothing; `boneli-app` → domain;
   adapters → domain, app and support crates; support crates (`boneli-sys`,
   `boneli-http`, `boneli-https`, ...) stay generic; composition roots
   (`boneli-runner`, `boneli-gw`, `boneli-egress`, `boneli-shim`,
   `boneli-cli`) wire adapters and nothing depends on them.
   `tools/check-architecture.sh` enforces it.
2. **Core purity** (domain, app): no external dependencies, no wall clock,
   filesystem, network, environment, threads, processes, async or
   `HashMap`/`HashSet`. Runs replay deterministically from the event log.
   Both crates are `#![no_std]` with `alloc` and must build for
   `x86_64-unknown-none`; a token scan covers what `no_std` cannot remove
   (async, `core::arch`, atomics, pointer addresses, format specs that end
   in `p` in any file of the package and after escapes, `concat`,
   `stringify`, `env`, `option_env`, glob imports from `fmt`). The scan is
   a first layer; the two-process replay test (#2) is the gate for address
   leaks it cannot enumerate. Dependency `cfg`s of core crates are also
   evaluated on `x86_64-unknown-none` (ADR-001).
3. **Pure Rust, minimal dependencies:** every edge into an external crate,
   transitive ones included, needs a record with a reason in
   `tools/architecture.toml`; a new crate name needs an ADR or a row in
   ARCHITECTURE, and every edge into `libc` needs its own accepted ADR that
   names it. Edges count unless their `cfg` is false on every checked Linux
   target (x86_64 and aarch64, gnu and musl); flag-dependent cfgs such as
   `crt-static` count as true. Sources are crates.io only; path dependencies
   point to members. The "do not use" list is enforced in `deny.toml`.
   Widening either needs an ADR (ADR-001).
4. **Unsafe only in `boneli-sys`.** Every other crate inherits the workspace
   lints, which forbid it; the check also scans every other crate for the
   `unsafe` token and requires the doctest attribute
   `#![doc(test(attr(forbid(unsafe_code))))]` in its lib root. No
   `.cargo/config*`, `clippy.toml`, `rust-toolchain*`, proc-macro crate,
   `#[path]`, `include!` or target source outside `.rs`; no build script
   outside `roles.build-script` in `tools/architecture.toml` (empty; adding
   a crate needs an ADR) (ADR-001).
5. **The sandbox holds no secrets and has no network.** Capabilities reach it
   only through broker sockets. The MVP subscription token is the one
   documented exception.
6. **Gates are deterministic and fail closed.** A fix is verified in a clean
   sandbox from the base SHA and the diff only; nothing from the agent's
   sandbox is trusted.
7. **Ports are synchronous traits** in `boneli-app` (std threads, no async
   runtime). Every port has an in-memory adapter and a contract test suite
   that the real adapters reuse.

## Validation (CI equivalent — run before every commit)

Once per machine: `rustup target add x86_64-unknown-none`. The architecture
check needs Python 3.11 or newer.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
tools/check-architecture.sh
tools/check-architecture.sh --fixtures
cargo deny check
```

## Conventions

- English in code, comments, commits, PRs and issues.
- Branch and PR for every change; never push to main. The PR body carries
  `Closes #N` or a
  `No-Issue: <reason>` line (CI-enforced).
- Domain items cite the design section or ADR they implement.
- Every new dependency is justified in a `Cargo.toml` comment; licenses per
  `deny.toml`. Core crates take none.
- Changes go to `CHANGELOG.md` under `## [Unreleased]`.
- **Public repository:** no local paths, credentials, API keys or private
  data. Agent prompts and playbooks, benchmark cases, pricing and strategy
  belong to the private `Replikanti/boneli-cloud`, never here. Only the
  playbook and case *formats* are defined in this repository.
