//! Shared test support: a fixture-repository builder that signs at test
//! time with the committed test-only P-256 keys (`repo`), and the real
//! Sigstore roots (`real`).
#![allow(dead_code)]

pub mod real;
pub mod repo;
