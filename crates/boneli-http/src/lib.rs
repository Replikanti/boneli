//! A strict HTTP/1.1 subset for Boneli's gateway, egress proxy and
//! adapters, on `httparse`.
//!
//! - A server over Unix sockets (one thread per connection, a connection
//!   cap, idle, request and write timeouts) and a client over any stream.
//! - Bodies framed by `Content-Length`, chunked, or (responses only) by the
//!   end of the stream; event streams pass through unbuffered.
//! - CONNECT on both sides.
//!
//! Accepted is HTTP/1.1 only, with CRLF line endings, origin-form targets
//! (authority form for CONNECT), exactly one `Host`, and at most one of
//! `Content-Length` or a single `chunked` `Transfer-Encoding`. Everything
//! else is rejected, never repaired. Limits have no defaults; each consumer
//! states its own. The reasons for each choice are in ADR-003
//! (`docs/adr/003-http-1-1-subset.md`).
#![doc(test(attr(forbid(unsafe_code))))]

mod body;
mod client;
mod error;
mod head;
mod limits;
mod server;
mod transport;
mod wire;

pub use body::{BodyReader, BodyWriter, pass_through};
pub use client::{Connection, RequestBody, Response, connect_tunnel};
pub use error::{Error, Result};
pub use head::{Headers, Method, RequestHead, ResponseHead, Target};
pub use limits::{Limits, ServerLimits};
pub use server::{Exchange, accept_loop, serve, serve_connection};
pub use transport::{IdleCheck, Transport, Tunnel};
