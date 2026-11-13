# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Architecture proposal (`docs/ARCHITECTURE.md`) and ADR process.
- Cargo workspace with the core crates `boneli-domain` and `boneli-app`.
- CI: issue-link gate, rustfmt, clippy, tests, architecture rules and
  `cargo deny`.
- ADR-001: semantic core purity, `unsafe` containment and a transitive
  dependency allowlist.
- `tools/architecture.toml`: roles, checked platforms and an allowlist of
  dependency edges, each with a reason and the decision that approved it;
  `libc` is strict, so every edge into it needs its own accepted ADR.
- Fail fixtures for every architecture rule (`tools/fixtures/arch/`), run in
  CI by `tools/check-architecture.sh --fixtures`.
- `boneli-domain`: the run state machine (`Run::handle`), its events,
  commands and outcomes, the reproduction, citation, root-cause and fix
  gates, and budget accounting in micro-USD and milliseconds (ADR-002).
- `boneli_domain::scenarios`: 62 event sequences that the domain's unit
  tests and the replay gate fold.
- `boneli-replay-check`: a test-only root that folds the scenarios in two
  child processes and in its own, checks that address randomization is on,
  and compares the `Debug` output and the `Display` of every error byte for
  byte; the gate for address leaks
  from the domain (ADR-001, ADR-002).
- ADR-002: run state machine, budget units, gates and the replay gate.

### Changed

- The architecture check is now `tools/check_architecture.py` behind the
  same `tools/check-architecture.sh`. It reads the workspace from
  `cargo metadata`, checks every resolved dependency edge on both Linux
  targets, limits sources to crates.io and member paths, parses the manifest
  lint tables, scans every non-`boneli-sys` crate for `unsafe`, rejects
  `.cargo/config*`, `clippy.toml`, proc-macro crates, `#[path]` and
  `include!`, and fails on any tool error.
- `boneli-domain` and `boneli-app` are `#![no_std]` and build for
  `x86_64-unknown-none`; their doctests cannot use `unsafe`.
- The architecture check evaluates dependency `cfg`s itself against x86_64
  and aarch64 Linux with glibc and musl (core crates also on
  `x86_64-unknown-none`), treating flag-dependent conditions such as
  `crt-static` as true, instead of `--filter-platform`. It rejects crate
  roots that are not `.rs` files, build scripts outside
  `roles.build-script` (empty), and `rust-toolchain` files; CI pins
  `RUSTUP_TOOLCHAIN`. The core token scan matches `{:p}`-style specs (any
  fill character) in the raw content of every core file and in string
  literals after escape decoding (whitespace before the closing brace
  included), and also bans `Pointer`, `concat`, `stringify`, `env`,
  `option_env`, glob imports from `fmt`, `use` items built from macro
  metavariables, `core::task` paths and wakers, `{` or `}` in core file
  paths, and `include_str!`/`include_bytes!` paths that are absolute or
  contain `..` or a backslash.
