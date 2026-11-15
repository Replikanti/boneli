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
//! Around it, the I/O:
//!
//! - [`proxy`]: the server on `boneli_http::accept_loop`, the handler that
//!   applies the policy in its order with a log record before every
//!   effect, and [`launch`], the startup order of the binary (D1, D4, D6,
//!   D8, D10).
//! - [`relay`]: the bytes of an open tunnel, half-close and the shared idle
//!   timeout (D7).
//! - The seams (D11): [`Upstream`] (resolve and connect; [`TcpUpstream`])
//!   and [`LogSink`] ([`StdoutSink`]), and the [`MonotonicClock`] adapter
//!   of the `Clock` port.
//! - [`Settings`] (D5, D7, D9) and [`Args`], the command line (D1).
#![doc(test(attr(forbid(unsafe_code))))]

pub mod address;
pub mod allowlist;
pub mod args;
pub mod clock;
pub mod log;
pub mod proxy;
pub mod relay;
pub mod settings;
pub mod sink;
pub mod upstream;

pub use allowlist::{Allowlist, AllowlistError, Decision, Endpoint};
pub use args::{Args, USAGE, UsageError};
pub use clock::MonotonicClock;
pub use proxy::{Config, DISCOVERY_NAME, Egress, LaunchError, launch};
pub use relay::{RelayOutcome, relay};
pub use settings::{Settings, SettingsError};
pub use sink::{LogSink, StdoutSink};
pub use upstream::{RelayStream, TcpUpstream, Upstream};
