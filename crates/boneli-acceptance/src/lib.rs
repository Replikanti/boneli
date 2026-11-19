//! Test-only composition root: live acceptance tests (ADR-014, D12).
//!
//! The library is empty; the tests under `tests/` wire real adapters
//! against real services and are `#[ignore]`d, because CI has neither the
//! services nor their credentials. Each test names what it needs in its
//! ignore reason and fails, naming the missing variable, when run without
//! it; it never skips.
//!
//! - `tests/github.rs`: `boneli-git-cli` and `boneli-forge-github` on the
//!   operator's private test repository (`docs/forge-github.md`).
#![doc(test(attr(forbid(unsafe_code))))]
