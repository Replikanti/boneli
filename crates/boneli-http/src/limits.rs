//! Size, count and time limits. They have no defaults: the right value
//! depends on the peer, so every consumer states and justifies its own
//! (ADR-003).

use std::time::Duration;

use crate::error::{Error, Result};

/// Limits on what one message may contain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    max_head_bytes: usize,
    max_headers: usize,
    max_body_bytes: u64,
}

impl Limits {
    /// Limits for heads (bytes including the request or status line, leading
    /// empty lines and the final empty line; interim responses count
    /// together with the final one), header fields per head, and body bytes.
    /// Trailer sections are held to the same head limits. A zero value is an
    /// error: it would reject every message.
    pub fn new(max_head_bytes: usize, max_headers: usize, max_body_bytes: u64) -> Result<Limits> {
        if max_head_bytes == 0 || max_headers == 0 || max_body_bytes == 0 {
            return Err(Error::InvalidInput("a limit is zero"));
        }
        Ok(Limits {
            max_head_bytes,
            max_headers,
            max_body_bytes,
        })
    }

    /// The largest head in bytes.
    pub fn max_head_bytes(&self) -> usize {
        self.max_head_bytes
    }

    /// The largest number of header fields in one head.
    pub fn max_headers(&self) -> usize {
        self.max_headers
    }

    /// The largest body in bytes.
    pub fn max_body_bytes(&self) -> u64 {
        self.max_body_bytes
    }
}

/// Limits of one server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerLimits {
    http: Limits,
    max_connections: usize,
    idle_timeout: Duration,
    request_timeout: Duration,
    write_timeout: Duration,
}

impl ServerLimits {
    /// Server limits:
    ///
    /// - `http`: the message limits for requests;
    /// - `max_connections`: connections served at once; at the cap the
    ///   server stops accepting and the kernel backlog holds new clients;
    /// - `idle_timeout`: how long a connection may wait for the first byte
    ///   of a request;
    /// - `request_timeout`: from the first byte of a request until its head
    ///   and body are read;
    /// - `write_timeout`: per write of a response (a total deadline would
    ///   cut long event streams).
    ///
    /// A zero value is an error: std rejects a zero socket timeout, and a
    /// zero connection cap would never serve.
    pub fn new(
        http: Limits,
        max_connections: usize,
        idle_timeout: Duration,
        request_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<ServerLimits> {
        if max_connections == 0 {
            return Err(Error::InvalidInput("max_connections is zero"));
        }
        if idle_timeout.is_zero() || request_timeout.is_zero() || write_timeout.is_zero() {
            return Err(Error::InvalidInput("a timeout is zero"));
        }
        Ok(ServerLimits {
            http,
            max_connections,
            idle_timeout,
            request_timeout,
            write_timeout,
        })
    }

    /// The message limits for requests.
    pub fn http(&self) -> &Limits {
        &self.http
    }

    /// Connections served at once.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// The wait for the first byte of a request.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// The deadline from the first byte of a request until it is read.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// The timeout of each write.
    pub fn write_timeout(&self) -> Duration {
        self.write_timeout
    }
}
