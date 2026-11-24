//! Shared test support: a fixture-repository builder that signs at test
//! time with the committed test-only P-256 keys (`repo`), and the real
//! Sigstore roots (`real`), and a fake TUF repository over a fake `Dial`
//! with scratch trust directories (`server`).
#![allow(dead_code)]

pub mod real;
pub mod repo;
pub mod server;
