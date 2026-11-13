//! The egress proxy of a run phase (`docs/ARCHITECTURE.md`, "LLM access and
//! egress"; ADR-006): HTTP CONNECT over a Unix socket to an exact allowlist
//! of `host:port` pairs, without MITM, with every connection logged before
//! it has an effect.
//!
//! The proxy is a small hexagon. This crate's pure policy decides:
//!
//! - [`allowlist`]: exact canonical `host:port` pairs, parsed with the
//!   CONNECT target grammar of `boneli-http`, so that an entry and a target
//!   canonicalize identically (ADR-006, D2). A refused name is never
//!   resolved (D3).
//! - [`address`]: only globally reachable addresses, including the IPv4
//!   address inside a NAT64 prefix (D4), the order of connect attempts and
//!   the connect budget (D5).
//! - [`log`]: the connection log, one line per record in a closed alphabet,
//!   with a strict parser (D8).
//!
//! The I/O around it (the relay, the server and the binary) and its seams,
//! `Upstream` and `LogSink`, come with the second part of issue #10.
#![doc(test(attr(forbid(unsafe_code))))]

pub mod address;
pub mod allowlist;
pub mod log;

pub use allowlist::{Allowlist, AllowlistError, Decision, Endpoint};
