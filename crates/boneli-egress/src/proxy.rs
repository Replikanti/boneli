//! The proxy: one CONNECT server per run phase on `boneli-http`'s accept
//! loop, the decisions of ADR-006 in their order, and a write-ahead log
//! record before every effect (D3 to D8, D10).
//!
//! The handler of a connection runs, in this order: method check →
//! allowlist → `allowed` record → resolve → address check → ordered
//! connects → `open` record → `200` (`accept_tunnel`) → relay → `close`
//! record. A connection the server rejects before the handler runs gets a
//! `no-request`, `aborted` or `rejected` record from what
//! `serve_connection` returns.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use boneli_app::Clock;
use boneli_http::{Error, Exchange, Headers, accept_loop, serve_connection};

use crate::address::{Nat64Prefix, attempt_timeout, connect_order, first_forbidden};
use crate::allowlist::{Allowlist, Decision, Endpoint};
use crate::log::{End, FailReason, Record, RejectedStatus};
use crate::relay::relay;
use crate::settings::Settings;
use crate::sink::LogSink;
use crate::upstream::{RelayStream, Upstream};

/// The name whose AAAA answer reveals the NAT64 prefixes of the network
/// (RFC 7050; ADR-006, D4).
pub const DISCOVERY_NAME: &str = "ipv4only.arpa";

/// Everything one egress is built from.
pub struct Config {
    /// The exact `host:port` pairs of this run phase (D2).
    pub allowlist: Allowlist,
    /// NAT64 prefixes in effect (D4). `launch` adds the discovered ones.
    pub nat64: BTreeSet<Nat64Prefix>,
    /// Resolution and connects (D11).
    pub upstream: Arc<dyn Upstream>,
    /// Where the connection log goes (D8).
    pub sink: Arc<dyn LogSink>,
    /// The source of every record's `t` (D8, D11).
    pub clock: Box<dyn Clock + Send + Sync>,
    /// Limits and timeouts (D5, D7, D9).
    pub settings: Settings,
    /// Called once per failed append, after which the connection takes no
    /// further effect. The binary exits with 3 here (D8).
    pub on_log_failure: Box<dyn Fn() + Send + Sync>,
}

/// A configured egress, ready to serve a listener.
pub struct Egress {
    allowlist: Allowlist,
    nat64_set: BTreeSet<Nat64Prefix>,
    nat64: Vec<Nat64Prefix>,
    upstream: Arc<dyn Upstream>,
    sink: Arc<dyn LogSink>,
    clock: Box<dyn Clock + Send + Sync>,
    settings: Settings,
    on_log_failure: Box<dyn Fn() + Send + Sync>,
    /// The last connection id issued; ids start at 1.
    last_id: AtomicU64,
    /// Held while a record takes its `t` and is appended, so `t` never
    /// decreases from one line to the next.
    log_order: Mutex<()>,
}

/// The log append failed; nothing more happens for this connection.
#[derive(Debug)]
struct LogFailed(io::Error);

impl From<LogFailed> for Error {
    fn from(e: LogFailed) -> Error {
        // `Error::Io` has no status, so the server writes no answer (D8).
        Error::Io(e.0)
    }
}

impl Egress {
    /// An egress from `config`, without the `start` record (see `launch`).
    pub fn new(config: Config) -> Egress {
        Egress {
            allowlist: config.allowlist,
            nat64: config.nat64.iter().copied().collect(),
            nat64_set: config.nat64,
            upstream: config.upstream,
            sink: config.sink,
            clock: config.clock,
            settings: config.settings,
            on_log_failure: config.on_log_failure,
            last_id: AtomicU64::new(0),
            log_order: Mutex::new(()),
        }
    }

    /// Serves `listener` with `boneli_http::accept_loop` until accepting
    /// fails, one thread per connection, at most `max_connections` at once.
    pub fn serve(self, listener: UnixListener) -> io::Result<()> {
        let egress = Arc::new(self);
        let limits = *egress.settings.server();
        accept_loop(listener, &limits, move |stream| egress.connection(stream))
    }

    /// Writes the `start` record: the clock reading, `unix_ms`, the list
    /// and the NAT64 prefixes in effect (D8).
    fn start(&self, unix_ms: u64) -> io::Result<()> {
        self.append(|t| Record::Start {
            t,
            unix_ms,
            allow: self.allowlist.clone(),
            nat64: self.nat64_set.clone(),
        })
    }

    /// Takes the clock reading and appends the record built from it, under
    /// the order lock.
    fn append(&self, record: impl FnOnce(u64) -> Record) -> io::Result<()> {
        let _order = self
            .log_order
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let line = record(self.clock.now_ms()).render();
        self.sink.append(&line)
    }

    /// Appends a connection's record; on failure calls `on_log_failure`.
    fn log(&self, record: impl FnOnce(u64) -> Record) -> Result<(), LogFailed> {
        self.append(record).map_err(|e| {
            (self.on_log_failure)();
            LogFailed(e)
        })
    }

    /// One accepted connection: its id, the server's loop with the
    /// handler, and a terminal record when the handler never ran.
    fn connection(&self, stream: UnixStream) {
        let id = self.last_id.fetch_add(1, Ordering::Relaxed) + 1;
        let ran = Cell::new(false);
        let handler = |exchange: Exchange<'_, UnixStream>| {
            ran.set(true);
            self.handle(id, exchange)
        };
        let result = serve_connection(stream, self.settings.server(), &handler);
        if ran.get() {
            // The handler wrote the terminal record, or a log failure
            // stopped it.
            return;
        }
        let _ = match result {
            // Closed or idle before the first byte of a request.
            Ok(()) => self.log(|t| Record::NoRequest { t, id }),
            Err(e) => match e.status().and_then(RejectedStatus::from_status) {
                Some(status) => self.log(|t| Record::Rejected { t, id, status }),
                // The stream ended or failed inside the head.
                None => self.log(|t| Record::Aborted { t, id }),
            },
        };
    }

    /// The handler: D3 to D8 in their order. Every refusal is logged
    /// before it is answered, has an empty body and closes the connection.
    fn handle(&self, id: u64, exchange: Exchange<'_, UnixStream>) -> boneli_http::Result<()> {
        if !exchange.head().method.is_connect() {
            self.log(|t| Record::Method { t, id })?;
            let mut headers = Headers::new();
            headers.append("Allow", "CONNECT");
            return refuse(exchange, 405, &headers);
        }
        let Some(endpoint) = Endpoint::from_target(&exchange.head().target) else {
            // The server hands a CONNECT only an authority-form target from
            // the grammar, so this does not happen; if it does, it fails
            // closed as a malformed request.
            self.log(|t| Record::Rejected {
                t,
                id,
                status: RejectedStatus::BadRequest,
            })?;
            return Err(Error::Status(400));
        };
        if self.allowlist.decide(&exchange.head().target) == Decision::NotAllowed {
            // D3: never resolved.
            self.log(|t| Record::Refused {
                t,
                id,
                endpoint: endpoint.clone(),
            })?;
            return refuse(exchange, 403, &Headers::new());
        }
        self.log(|t| Record::Allowed {
            t,
            id,
            endpoint: endpoint.clone(),
        })?;

        let addrs = match self.upstream.resolve(endpoint.host(), endpoint.port()) {
            Ok(addrs) if !addrs.is_empty() => addrs,
            _ => {
                self.log(|t| failed(t, id, FailReason::Resolve, None))?;
                return refuse(exchange, 502, &Headers::new());
            }
        };
        // D4: one forbidden address refuses the name, with the same status
        // as a name off the list (D6).
        if let Some(addr) = first_forbidden(&addrs, &self.nat64) {
            self.log(|t| failed(t, id, FailReason::ForbiddenAddress, Some(addr)))?;
            return refuse(exchange, 403, &Headers::new());
        }
        let (addr, upstream) = match self.connect(addrs) {
            Ok(connected) => connected,
            Err((reason, addr)) => {
                self.log(|t| failed(t, id, reason, addr))?;
                let status = if reason == FailReason::ConnectTimeout {
                    504
                } else {
                    502
                };
                return refuse(exchange, status, &Headers::new());
            }
        };
        if let Err(e) = self.log(|t| Record::Open { t, id, addr }) {
            // No log, no tunnel: the upstream is closed before anything
            // reaches the sandbox.
            drop(upstream);
            return Err(e.into());
        }

        // From here every path writes a `close`.
        let opened = exchange.accept_tunnel().map(|tunnel| {
            let (early, stream) = tunnel.into_parts();
            (early, stream.try_clone())
        });
        let outcome = match opened {
            Ok((early, Ok(sandbox))) => relay(Box::new(sandbox), early, upstream, &self.settings),
            Ok((_, Err(_))) | Err(_) => {
                drop(upstream);
                crate::relay::RelayOutcome {
                    up: 0,
                    down: 0,
                    end: End::Error,
                }
            }
        };
        self.log(|t| Record::Close {
            t,
            id,
            up: outcome.up,
            down: outcome.down,
            end: outcome.end,
        })?;
        Ok(())
    }

    /// Connects to the checked addresses in the order of D5, within the
    /// budget. On failure: the reason and the last address tried.
    fn connect(
        &self,
        addrs: Vec<SocketAddr>,
    ) -> Result<Connected, (FailReason, Option<SocketAddr>)> {
        let order = connect_order(addrs);
        let begun = Instant::now();
        let budget = self.settings.connect_total();
        let per_attempt = self.settings.connect_attempt();
        // The caller passes a non-empty answer; an empty one is a failed
        // resolution. Until an attempt fails, the first address stands for
        // the answer; the budget is positive, so that attempt is made.
        let Some(&first) = order.first() else {
            return Err((FailReason::Resolve, None));
        };
        let mut last = (first, false);
        for addr in order {
            let remaining = budget.saturating_sub(begun.elapsed());
            let Some(timeout) = attempt_timeout(remaining, per_attempt) else {
                break;
            };
            match self.upstream.connect(addr, timeout) {
                Ok(stream) => return Ok((addr, stream)),
                Err(e) => last = (addr, e.kind() == io::ErrorKind::TimedOut),
            }
        }
        let (addr, timed_out) = last;
        let exhausted =
            attempt_timeout(budget.saturating_sub(begun.elapsed()), per_attempt).is_none();
        // D5: 504 only when the budget ran out on a timeout.
        let reason = if timed_out && exhausted {
            FailReason::ConnectTimeout
        } else {
            FailReason::Connect
        };
        Err((reason, Some(addr)))
    }
}

/// The address connected to and its stream.
type Connected = (SocketAddr, Box<dyn RelayStream>);

fn failed(t: u64, id: u64, reason: FailReason, addr: Option<SocketAddr>) -> Record {
    Record::Failed {
        t,
        id,
        reason,
        addr,
    }
}

/// Answers with `status`, an empty body and `Connection: close` (D6).
fn refuse(
    mut exchange: Exchange<'_, UnixStream>,
    status: u16,
    headers: &Headers,
) -> boneli_http::Result<()> {
    exchange.close_after();
    exchange.respond(status, headers, b"")
}

/// Why `launch` returned. It returns only on failure: the egress serves
/// until the runner ends the process.
#[derive(Debug)]
pub enum LaunchError {
    /// NAT64 discovery got no address for `ipv4only.arpa`, or an error
    /// (D4). Exit 1.
    Discovery(Option<io::Error>),
    /// The `start` record could not be written (D8). Exit 3.
    Log(io::Error),
    /// Accepting failed (D1). Exit 1.
    Accept(io::Error),
}

impl LaunchError {
    /// The exit code of D1.
    pub fn exit_code(&self) -> i32 {
        match self {
            LaunchError::Discovery(_) | LaunchError::Accept(_) => 1,
            LaunchError::Log(_) => 3,
        }
    }
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchError::Discovery(None) => {
                write!(f, "NAT64 discovery: no address for {DISCOVERY_NAME}")
            }
            LaunchError::Discovery(Some(e)) => {
                write!(f, "NAT64 discovery: resolving {DISCOVERY_NAME} failed: {e}")
            }
            LaunchError::Log(e) => write!(f, "the start record could not be written: {e}"),
            LaunchError::Accept(e) => write!(f, "accepting failed: {e}"),
        }
    }
}

impl std::error::Error for LaunchError {}

/// Starts an egress on a bound `listener` in the order of D1: discover the
/// NAT64 prefixes (D4) and merge them with `config.nat64`, write the
/// `start` record with `unix_ms()`, then accept. Returns only on failure;
/// the listener is dropped before it returns, so a client waiting in the
/// backlog is never served.
pub fn launch(
    listener: UnixListener,
    mut config: Config,
    unix_ms: impl FnOnce() -> u64,
) -> LaunchError {
    let answer = match config.upstream.resolve(DISCOVERY_NAME, 0) {
        Ok(answer) if !answer.is_empty() => answer,
        Ok(_) => return LaunchError::Discovery(None),
        Err(e) => return LaunchError::Discovery(Some(e)),
    };
    let aaaa: Vec<Ipv6Addr> = answer
        .iter()
        .filter_map(|addr| match addr.ip() {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => None,
        })
        .collect();
    config.nat64.extend(Nat64Prefix::discover(&aaaa));
    let egress = Egress::new(config);
    if let Err(e) = egress.start(unix_ms()) {
        return LaunchError::Log(e);
    }
    match egress.serve(listener) {
        Err(e) => LaunchError::Accept(e),
        Ok(()) => LaunchError::Accept(io::Error::other("the accept loop ended")),
    }
}
