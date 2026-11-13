//! The connection log (ADR-006, D8): one record per line,
//! `<kind> key=value ...`, with a fixed field order per kind.
//!
//! Every value comes from a closed alphabet: hosts that passed the CONNECT
//! grammar, decimal numbers, `SocketAddr` display and fixed words. No value
//! can contain a space, `=`, a comma or a line break, so the format has no
//! escaping. The parser is strict: a line parses only if rendering the
//! record it describes gives the same bytes back, so there is exactly one
//! spelling of every record.
//!
//! | kind | fields, in this order |
//! |---|---|
//! | `start` | `t v=1 unix_ms allow=<host:port>(,<host:port>)* nat64=<-\|<prefix/len>(,<prefix/len>)*>` |
//! | `allowed` | `t id host port` |
//! | `refused` | `t id host port` |
//! | `open` | `t id addr` |
//! | `failed` | `t id reason addr` (`addr=-` when there is none) |
//! | `close` | `t id up down end` |
//! | `method` | `t id` |
//! | `rejected` | `t id status` |
//! | `aborted` | `t id` |
//! | `no-request` | `t id` |
//!
//! `t` is milliseconds from a monotonic origin at the start of the egress,
//! which the `start` record anchors to `unix_ms`. Records with the same `t`
//! are ordered by their line order. Socket addresses are logged as their
//! `Display` form: an IPv6 flow label is not part of the log, and a scope
//! id only appears on link-local addresses, which the egress never
//! connects to (D4).

use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;

use crate::address::Nat64Prefix;
use crate::allowlist::{Allowlist, Endpoint};

/// The version written in every `start` record.
const VERSION: u64 = 1;

/// Why an allowed connection failed before its tunnel opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailReason {
    /// The name resolved to at least one forbidden address (D4); answered
    /// with 403.
    ForbiddenAddress,
    /// Resolution failed or returned no address; answered with 502.
    Resolve,
    /// Every connect attempt failed, the last one not by a timeout;
    /// answered with 502.
    Connect,
    /// The connect budget ran out on a timeout (D5); answered with 504.
    ConnectTimeout,
}

impl FailReason {
    const ALL: [FailReason; 4] = [
        FailReason::ForbiddenAddress,
        FailReason::Resolve,
        FailReason::Connect,
        FailReason::ConnectTimeout,
    ];

    /// The word in the log.
    pub fn as_str(self) -> &'static str {
        match self {
            FailReason::ForbiddenAddress => "forbidden-address",
            FailReason::Resolve => "resolve",
            FailReason::Connect => "connect",
            FailReason::ConnectTimeout => "connect-timeout",
        }
    }
}

/// How a tunnel ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum End {
    /// Both directions reached the end of their stream.
    Eof,
    /// No byte moved in either direction for the idle timeout (D7).
    Idle,
    /// A read, a write or the relay itself failed.
    Error,
}

impl End {
    const ALL: [End; 3] = [End::Eof, End::Idle, End::Error];

    /// The word in the log.
    pub fn as_str(self) -> &'static str {
        match self {
            End::Eof => "eof",
            End::Idle => "idle",
            End::Error => "error",
        }
    }
}

/// The status the HTTP server answered a request with before the egress
/// saw it: exactly the statuses `boneli_http::Error::status` maps a
/// rejected request to (ADR-003).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RejectedStatus {
    /// 400: the head is outside the accepted subset.
    BadRequest,
    /// 408: the head did not arrive within the request timeout.
    RequestTimeout,
    /// 413: a declared body over the limit.
    ContentTooLarge,
    /// 417: an `Expect` other than `100-continue`.
    ExpectationFailed,
    /// 431: the head is over the byte or field limit.
    HeaderFieldsTooLarge,
    /// 501: a transfer coding other than `chunked`.
    NotImplemented,
    /// 505: a version other than HTTP/1.1.
    VersionNotSupported,
}

impl RejectedStatus {
    const ALL: [RejectedStatus; 7] = [
        RejectedStatus::BadRequest,
        RejectedStatus::RequestTimeout,
        RejectedStatus::ContentTooLarge,
        RejectedStatus::ExpectationFailed,
        RejectedStatus::HeaderFieldsTooLarge,
        RejectedStatus::NotImplemented,
        RejectedStatus::VersionNotSupported,
    ];

    /// The status code.
    pub fn status(self) -> u16 {
        match self {
            RejectedStatus::BadRequest => 400,
            RejectedStatus::RequestTimeout => 408,
            RejectedStatus::ContentTooLarge => 413,
            RejectedStatus::ExpectationFailed => 417,
            RejectedStatus::HeaderFieldsTooLarge => 431,
            RejectedStatus::NotImplemented => 501,
            RejectedStatus::VersionNotSupported => 505,
        }
    }

    /// The variant for `status`, or `None` for any other code.
    pub fn from_status(status: u16) -> Option<RejectedStatus> {
        RejectedStatus::ALL
            .into_iter()
            .find(|candidate| candidate.status() == status)
    }
}

/// One line of the connection log (ADR-006, D8). `t` is the clock reading
/// in milliseconds and `id` the connection's number in this process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// The egress is bound and about to accept; written once, first.
    Start {
        /// Clock reading.
        t: u64,
        /// Milliseconds since the Unix epoch at the same moment.
        unix_ms: u64,
        /// The allowlist, in canonical order.
        allow: Allowlist,
        /// The NAT64 prefixes the address check uses (ADR-006, D4), in
        /// canonical order; `nat64=-` when there are none.
        nat64: BTreeSet<Nat64Prefix>,
    },
    /// The target is on the list; written before any DNS query.
    Allowed {
        /// Clock reading.
        t: u64,
        /// Connection number.
        id: u64,
        /// The canonical target.
        endpoint: Endpoint,
    },
    /// The target is not on the list (403). Terminal.
    Refused {
        /// Clock reading.
        t: u64,
        /// Connection number.
        id: u64,
        /// The canonical target.
        endpoint: Endpoint,
    },
    /// The upstream is connected; written before the `200`.
    Open {
        /// Clock reading.
        t: u64,
        /// Connection number.
        id: u64,
        /// The address connected to.
        addr: SocketAddr,
    },
    /// An allowed connection failed before its tunnel opened. Terminal.
    Failed {
        /// Clock reading.
        t: u64,
        /// Connection number.
        id: u64,
        /// Why.
        reason: FailReason,
        /// The first forbidden address, or the last address tried; `None`
        /// after a failed resolution.
        addr: Option<SocketAddr>,
    },
    /// A tunnel ended. Terminal; every `Open` gets one.
    Close {
        /// Clock reading.
        t: u64,
        /// Connection number.
        id: u64,
        /// Bytes from the sandbox to the upstream, including those that
        /// arrived with the CONNECT head.
        up: u64,
        /// Bytes from the upstream to the sandbox.
        down: u64,
        /// How it ended.
        end: End,
    },
    /// A method other than CONNECT (405). Terminal.
    Method {
        /// Clock reading.
        t: u64,
        /// Connection number.
        id: u64,
    },
    /// The server rejected the request before the egress saw it. Terminal.
    Rejected {
        /// Clock reading.
        t: u64,
        /// Connection number.
        id: u64,
        /// The status the server answered with.
        status: RejectedStatus,
    },
    /// The stream ended or failed before a complete head. Terminal.
    Aborted {
        /// Clock reading.
        t: u64,
        /// Connection number.
        id: u64,
    },
    /// Closed or idle before the first byte. Terminal.
    NoRequest {
        /// Clock reading.
        t: u64,
        /// Connection number.
        id: u64,
    },
}

/// Why a line is not a record. It never repeats the line's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogParseError {
    what: &'static str,
}

impl LogParseError {
    fn new(what: &'static str) -> LogParseError {
        LogParseError { what }
    }
}

impl fmt::Display for LogParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid log record: {}", self.what)
    }
}

impl std::error::Error for LogParseError {}

/// A log that does not parse, and the first line that does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogError {
    line: usize,
    error: LogParseError,
}

impl LogError {
    /// The one-based number of the first bad line.
    pub fn line(&self) -> usize {
        self.line
    }

    /// What is wrong with it.
    pub fn error(&self) -> LogParseError {
        self.error
    }
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.error)
    }
}

impl std::error::Error for LogError {}

impl Record {
    /// The kind word that starts the line.
    pub fn kind(&self) -> &'static str {
        match self {
            Record::Start { .. } => "start",
            Record::Allowed { .. } => "allowed",
            Record::Refused { .. } => "refused",
            Record::Open { .. } => "open",
            Record::Failed { .. } => "failed",
            Record::Close { .. } => "close",
            Record::Method { .. } => "method",
            Record::Rejected { .. } => "rejected",
            Record::Aborted { .. } => "aborted",
            Record::NoRequest { .. } => "no-request",
        }
    }

    /// The clock reading.
    pub fn t(&self) -> u64 {
        match self {
            Record::Start { t, .. }
            | Record::Allowed { t, .. }
            | Record::Refused { t, .. }
            | Record::Open { t, .. }
            | Record::Failed { t, .. }
            | Record::Close { t, .. }
            | Record::Method { t, .. }
            | Record::Rejected { t, .. }
            | Record::Aborted { t, .. }
            | Record::NoRequest { t, .. } => *t,
        }
    }

    /// The connection number; `None` for `start`.
    pub fn id(&self) -> Option<u64> {
        match self {
            Record::Start { .. } => None,
            Record::Allowed { id, .. }
            | Record::Refused { id, .. }
            | Record::Open { id, .. }
            | Record::Failed { id, .. }
            | Record::Close { id, .. }
            | Record::Method { id, .. }
            | Record::Rejected { id, .. }
            | Record::Aborted { id, .. }
            | Record::NoRequest { id, .. } => Some(*id),
        }
    }

    /// Whether the record ends its connection: every connection ends with
    /// exactly one of `refused`, `failed`, `close`, `method`, `rejected`,
    /// `aborted` or `no-request` (ADR-006, D8).
    pub fn is_terminal(&self) -> bool {
        !matches!(
            self,
            Record::Start { .. } | Record::Allowed { .. } | Record::Open { .. }
        )
    }

    /// The record as one line, ending in `\n`.
    pub fn render(&self) -> String {
        let kind = self.kind();
        let t = self.t();
        let mut line = match self {
            Record::Start {
                unix_ms,
                allow,
                nat64,
                ..
            } => {
                let list: Vec<String> = allow.entries().map(Endpoint::to_string).collect();
                let prefixes: Vec<String> = nat64.iter().map(Nat64Prefix::to_string).collect();
                let prefixes = if prefixes.is_empty() {
                    "-".to_owned()
                } else {
                    prefixes.join(",")
                };
                format!(
                    "{kind} t={t} v={VERSION} unix_ms={unix_ms} allow={} nat64={prefixes}",
                    list.join(",")
                )
            }
            Record::Allowed { id, endpoint, .. } | Record::Refused { id, endpoint, .. } => {
                format!(
                    "{kind} t={t} id={id} host={} port={}",
                    endpoint.host(),
                    endpoint.port()
                )
            }
            Record::Open { id, addr, .. } => format!("{kind} t={t} id={id} addr={addr}"),
            Record::Failed {
                id, reason, addr, ..
            } => {
                let reason = reason.as_str();
                match addr {
                    Some(addr) => format!("{kind} t={t} id={id} reason={reason} addr={addr}"),
                    None => format!("{kind} t={t} id={id} reason={reason} addr=-"),
                }
            }
            Record::Close {
                id, up, down, end, ..
            } => format!(
                "{kind} t={t} id={id} up={up} down={down} end={}",
                end.as_str()
            ),
            Record::Rejected { id, status, .. } => {
                format!("{kind} t={t} id={id} status={}", status.status())
            }
            Record::Method { id, .. }
            | Record::Aborted { id, .. }
            | Record::NoRequest { id, .. } => {
                format!("{kind} t={t} id={id}")
            }
        };
        line.push('\n');
        line
    }

    /// Parses one line without its `\n`. Strict: the kind, the exact field
    /// order, no unknown, missing or repeated keys, single spaces, canonical
    /// numbers, `v=1` only, and hosts that pass the CONNECT grammar in
    /// canonical form. A line parses only if `render` gives it back.
    pub fn parse(line: &str) -> Result<Record, LogParseError> {
        let mut words = line.split(' ');
        let kind = words.next().unwrap_or_default();
        let mut fields = Fields { words };
        let record = match kind {
            "start" => {
                let t = number(fields.take("t")?)?;
                if number(fields.take("v")?)? != VERSION {
                    return Err(LogParseError::new("unknown version"));
                }
                let unix_ms = number(fields.take("unix_ms")?)?;
                let entries: Vec<&str> = fields.take("allow")?.split(',').collect();
                let allow = Allowlist::parse(&entries)
                    .map_err(|_| LogParseError::new("invalid allow list"))?;
                let nat64 = match fields.take("nat64")? {
                    "-" => BTreeSet::new(),
                    list => list
                        .split(',')
                        .map(|p| {
                            Nat64Prefix::parse(p).ok_or(LogParseError::new("invalid NAT64 prefix"))
                        })
                        .collect::<Result<BTreeSet<_>, _>>()?,
                };
                Record::Start {
                    t,
                    unix_ms,
                    allow,
                    nat64,
                }
            }
            "allowed" | "refused" => {
                let t = number(fields.take("t")?)?;
                let id = number(fields.take("id")?)?;
                let host = fields.take("host")?;
                let port = fields.take("port")?;
                let endpoint = endpoint(host, port)?;
                if kind == "allowed" {
                    Record::Allowed { t, id, endpoint }
                } else {
                    Record::Refused { t, id, endpoint }
                }
            }
            "open" => {
                let t = number(fields.take("t")?)?;
                let id = number(fields.take("id")?)?;
                let addr = socket_addr(fields.take("addr")?)?;
                Record::Open { t, id, addr }
            }
            "failed" => {
                let t = number(fields.take("t")?)?;
                let id = number(fields.take("id")?)?;
                let reason = word(fields.take("reason")?, &FailReason::ALL, |r| r.as_str())?;
                let addr = match fields.take("addr")? {
                    "-" => None,
                    value => Some(socket_addr(value)?),
                };
                Record::Failed {
                    t,
                    id,
                    reason,
                    addr,
                }
            }
            "close" => {
                let t = number(fields.take("t")?)?;
                let id = number(fields.take("id")?)?;
                let up = number(fields.take("up")?)?;
                let down = number(fields.take("down")?)?;
                let end = word(fields.take("end")?, &End::ALL, |e| e.as_str())?;
                Record::Close {
                    t,
                    id,
                    up,
                    down,
                    end,
                }
            }
            "rejected" => {
                let t = number(fields.take("t")?)?;
                let id = number(fields.take("id")?)?;
                let status = number(fields.take("status")?)?;
                let status = u16::try_from(status)
                    .ok()
                    .and_then(RejectedStatus::from_status)
                    .ok_or(LogParseError::new("not a rejected status"))?;
                Record::Rejected { t, id, status }
            }
            "method" | "aborted" | "no-request" => {
                let t = number(fields.take("t")?)?;
                let id = number(fields.take("id")?)?;
                match kind {
                    "method" => Record::Method { t, id },
                    "aborted" => Record::Aborted { t, id },
                    _ => Record::NoRequest { t, id },
                }
            }
            _ => return Err(LogParseError::new("unknown kind")),
        };
        if fields.words.next().is_some() {
            return Err(LogParseError::new("extra field"));
        }
        // The one-spelling rule: every check above is repeated here as a
        // whole, so a field form that slipped through a value parser still
        // cannot give a second spelling of a record.
        let rendered = record.render();
        if rendered.strip_suffix('\n') != Some(line) {
            return Err(LogParseError::new("not the canonical form"));
        }
        Ok(record)
    }
}

/// Parses a whole log: every line, the last one included, ends in `\n`. A
/// last line without it was cut off mid-write and is an error, like any
/// other bad line. Records keep their line order.
pub fn parse_log(text: &str) -> Result<Vec<Record>, LogError> {
    let mut out = Vec::new();
    for (index, piece) in text.split_inclusive('\n').enumerate() {
        let line = index + 1;
        let body = piece.strip_suffix('\n').ok_or(LogError {
            line,
            error: LogParseError::new("line without its newline"),
        })?;
        out.push(Record::parse(body).map_err(|error| LogError { line, error })?);
    }
    Ok(out)
}

/// The fields after the kind, taken in order.
struct Fields<'a> {
    words: std::str::Split<'a, char>,
}

impl<'a> Fields<'a> {
    /// The value of the next field, which must be `key`.
    fn take(&mut self, key: &str) -> Result<&'a str, LogParseError> {
        let field = self
            .words
            .next()
            .ok_or(LogParseError::new("missing field"))?;
        match field.split_once('=') {
            Some((k, value)) if k == key => Ok(value),
            _ => Err(LogParseError::new("unexpected field")),
        }
    }
}

/// A decimal `u64`: digits only, no sign, no leading zero, no overflow.
fn number(value: &str) -> Result<u64, LogParseError> {
    let bad = LogParseError::new("not a canonical number");
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(bad);
    }
    value.parse::<u64>().map_err(|_| bad)
}

/// A host and port in canonical form, through the CONNECT grammar.
fn endpoint(host: &str, port: &str) -> Result<Endpoint, LogParseError> {
    let bad = LogParseError::new("invalid host or port");
    let port = number(port)?;
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let endpoint = Endpoint::parse(&authority).map_err(|_| bad)?;
    if endpoint.host() != host || u64::from(endpoint.port()) != port {
        return Err(bad);
    }
    Ok(endpoint)
}

/// A socket address in exactly its `Display` form.
fn socket_addr(value: &str) -> Result<SocketAddr, LogParseError> {
    let bad = LogParseError::new("invalid socket address");
    let addr: SocketAddr = value.parse().map_err(|_| bad)?;
    if addr.to_string() != value {
        return Err(bad);
    }
    Ok(addr)
}

/// One of a closed set of words.
fn word<T: Copy>(value: &str, all: &[T], name: fn(T) -> &'static str) -> Result<T, LogParseError> {
    all.iter()
        .copied()
        .find(|candidate| name(*candidate) == value)
        .ok_or(LogParseError::new("unknown word"))
}
