//! The numbers of one egress: the server's limits, the connect budget, the
//! tunnel's idle timeout and the relay buffer (ADR-006, D5, D7 and D9).

use std::fmt;
use std::time::Duration;

use boneli_http::{Limits, ServerLimits};

/// The limits of one egress. Every value is positive; the production
/// values are derived in ADR-006 and pinned by a test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    server: ServerLimits,
    connect_attempt: Duration,
    connect_total: Duration,
    tunnel_idle: Duration,
    relay_buffer: usize,
}

/// A setting that is zero. Names the setting, never a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettingsError {
    setting: &'static str,
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is zero", self.setting)
    }
}

impl std::error::Error for SettingsError {}

impl Settings {
    /// Settings from their parts:
    ///
    /// - `server`: the limits of the CONNECT server (D9);
    /// - `connect_attempt`: the longest single connect attempt (D5);
    /// - `connect_total`: the budget of all attempts of one connection (D5);
    /// - `tunnel_idle`: how long a tunnel may move no byte in either
    ///   direction, and the write timeout of both its sockets (D7);
    /// - `relay_buffer`: bytes per read of each relay direction (D7).
    ///
    /// A zero value is an error: std rejects a zero socket or connect
    /// timeout, and a zero buffer would read nothing.
    pub fn new(
        server: ServerLimits,
        connect_attempt: Duration,
        connect_total: Duration,
        tunnel_idle: Duration,
        relay_buffer: usize,
    ) -> Result<Settings, SettingsError> {
        let zero = |setting| Err(SettingsError { setting });
        if connect_attempt.is_zero() {
            return zero("connect_attempt");
        }
        if connect_total.is_zero() {
            return zero("connect_total");
        }
        if tunnel_idle.is_zero() {
            return zero("tunnel_idle");
        }
        if relay_buffer == 0 {
            return zero("relay_buffer");
        }
        Ok(Settings {
            server,
            connect_attempt,
            connect_total,
            tunnel_idle,
            relay_buffer,
        })
    }

    /// The production settings, each derived in ADR-006:
    ///
    /// - heads up to 8192 bytes and 32 fields, a body limit of 1 byte (the
    ///   egress never reads one), 64 connections, and 10 s idle, request
    ///   and write timeouts (D9);
    /// - 10 s per connect attempt out of 30 s in total (D5);
    /// - a tunnel idle timeout of 660 s, the Anthropic SDKs' default
    ///   request timeout of 600 s plus 60 s (D7);
    /// - a 16 KiB relay buffer, the TLS plaintext fragment limit of 2^14
    ///   bytes (D7).
    pub fn production() -> Settings {
        const MAX_HEAD_BYTES: usize = 8192;
        const MAX_HEADERS: usize = 32;
        const MAX_BODY_BYTES: u64 = 1;
        const MAX_CONNECTIONS: usize = 64;
        const SERVER_TIMEOUT: Duration = Duration::from_secs(10);
        const CONNECT_ATTEMPT: Duration = Duration::from_secs(10);
        const CONNECT_TOTAL: Duration = Duration::from_secs(30);
        const TUNNEL_IDLE: Duration = Duration::from_secs(660);
        const RELAY_BUFFER: usize = 16 * 1024;

        let built = Limits::new(MAX_HEAD_BYTES, MAX_HEADERS, MAX_BODY_BYTES)
            .and_then(|http| {
                ServerLimits::new(
                    http,
                    MAX_CONNECTIONS,
                    SERVER_TIMEOUT,
                    SERVER_TIMEOUT,
                    SERVER_TIMEOUT,
                )
            })
            .ok()
            .and_then(|server| {
                Settings::new(
                    server,
                    CONNECT_ATTEMPT,
                    CONNECT_TOTAL,
                    TUNNEL_IDLE,
                    RELAY_BUFFER,
                )
                .ok()
            });
        match built {
            Some(settings) => settings,
            // Every constant above is positive, so the constructors cannot
            // refuse them; `production_settings_match_adr_006` runs this.
            None => unreachable!("the production settings are all positive"),
        }
    }

    /// The limits of the CONNECT server.
    pub fn server(&self) -> &ServerLimits {
        &self.server
    }

    /// The longest single connect attempt.
    pub fn connect_attempt(&self) -> Duration {
        self.connect_attempt
    }

    /// The budget of all connect attempts of one connection.
    pub fn connect_total(&self) -> Duration {
        self.connect_total
    }

    /// The idle timeout of a tunnel, shared by both directions, and the
    /// write timeout of both its sockets.
    pub fn tunnel_idle(&self) -> Duration {
        self.tunnel_idle
    }

    /// Bytes per read of each relay direction.
    pub fn relay_buffer(&self) -> usize {
        self.relay_buffer
    }
}
