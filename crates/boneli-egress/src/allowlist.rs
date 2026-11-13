//! The per-run allowlist: exact canonical `host:port` pairs (ADR-006, D2).
//!
//! Entries are parsed by `Target::parse_authority`, the function that
//! parses a CONNECT target, so an entry and a target canonicalize the same
//! way (lowercase host, numeric port: `:0443` is 443). Matching is
//! equality of host and port: no wildcards, no suffix match, no IP
//! literals.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use boneli_http::Target;

/// A canonical destination: the host and port of an authority-form
/// `Target`. The host is lowercase, an IPv6 address has no brackets, and
/// the port is 1 to 65535 (ADR-003, item 3). Ordered by host, then port.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    host: String,
    port: u16,
}

impl Endpoint {
    /// The endpoint of an authority-form target, or `None` for origin form
    /// and for any host and port that the CONNECT grammar would not have
    /// produced. `Target::Authority` has public fields, so a target need not
    /// come from the parser; this re-parses its authority and takes it only
    /// if the result is the same target. An `Endpoint` therefore always
    /// holds a canonical host in the grammar's closed alphabet and a port
    /// from 1 to 65535, which is what keeps the connection log free of
    /// escaping (ADR-006, D8).
    pub fn from_target(target: &Target) -> Option<Endpoint> {
        let Target::Authority { host, port } = target else {
            return None;
        };
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        match Target::parse_authority(&authority) {
            Ok(parsed) if parsed == *target => Some(Endpoint {
                host: host.clone(),
                port: *port,
            }),
            _ => None,
        }
    }

    /// Parses `host:port` or `[ipv6]:port` with the CONNECT target grammar
    /// (`Target::parse_authority`).
    pub fn parse(authority: &str) -> boneli_http::Result<Endpoint> {
        let target = Target::parse_authority(authority)?;
        Endpoint::from_target(&target).ok_or(boneli_http::Error::Malformed("not an authority"))
    }

    /// The canonical host: lowercase, IPv6 without brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, 1 to 65535.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the host is an IPv4 or IPv6 address rather than a name. The
    /// grammar admits only canonical dotted-decimal IPv4, so `Ipv4Addr`
    /// recognizes every IPv4 form it lets through, and only IPv6 hosts
    /// contain a colon.
    pub fn is_ip_literal(&self) -> bool {
        self.host.contains(':') || self.host.parse::<Ipv4Addr>().is_ok()
    }
}

impl fmt::Display for Endpoint {
    /// The authority form: `host:port`, or `[ipv6]:port`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Why an allowlist was not built. Errors name the entry by its index in
/// the input and never repeat its bytes, which may come from anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowlistError {
    /// No entries: a proxy that allows nothing has no reason to run.
    Empty,
    /// The entry is not an authority in the CONNECT target grammar.
    Invalid {
        /// Zero-based index of the entry.
        entry_index: usize,
    },
    /// The entry names an IP address; only names are allowed, so that every
    /// connection is decided and logged by name (ADR-006, D2).
    IpLiteral {
        /// Zero-based index of the entry.
        entry_index: usize,
    },
    /// The entry equals an earlier one after canonicalization.
    Duplicate {
        /// Zero-based index of the later entry.
        entry_index: usize,
    },
}

impl fmt::Display for AllowlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllowlistError::Empty => f.write_str("the allowlist is empty"),
            AllowlistError::Invalid { entry_index } => write!(
                f,
                "allowlist entry {entry_index} is not host:port in the CONNECT grammar"
            ),
            AllowlistError::IpLiteral { entry_index } => {
                write!(f, "allowlist entry {entry_index} is an IP address")
            }
            AllowlistError::Duplicate { entry_index } => {
                write!(f, "allowlist entry {entry_index} repeats an earlier entry")
            }
        }
    }
}

impl std::error::Error for AllowlistError {}

/// The allowlist's answer for one target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The target is exactly one of the entries.
    Allowed,
    /// Anything else. The name is then never resolved (ADR-006, D3).
    NotAllowed,
}

/// A non-empty set of exact, canonical `host:port` names (ADR-006, D2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowlist {
    entries: BTreeSet<Endpoint>,
}

impl Allowlist {
    /// Builds the list from `host:port` entries. The first entry that is not
    /// in the CONNECT target grammar, names an IP address or repeats an
    /// earlier entry after canonicalization is an error; nothing is trimmed
    /// or repaired.
    pub fn parse(entries: &[&str]) -> Result<Allowlist, AllowlistError> {
        if entries.is_empty() {
            return Err(AllowlistError::Empty);
        }
        let mut set = BTreeSet::new();
        for (entry_index, entry) in entries.iter().enumerate() {
            let endpoint =
                Endpoint::parse(entry).map_err(|_| AllowlistError::Invalid { entry_index })?;
            if endpoint.is_ip_literal() {
                return Err(AllowlistError::IpLiteral { entry_index });
            }
            if !set.insert(endpoint) {
                return Err(AllowlistError::Duplicate { entry_index });
            }
        }
        Ok(Allowlist { entries: set })
    }

    /// `Allowed` exactly when `target` is in authority form and its host and
    /// port equal an entry's.
    pub fn decide(&self, target: &Target) -> Decision {
        match Endpoint::from_target(target) {
            Some(endpoint) if self.entries.contains(&endpoint) => Decision::Allowed,
            _ => Decision::NotAllowed,
        }
    }

    /// The entries in canonical order: by host, then by port.
    pub fn entries(&self) -> impl Iterator<Item = &Endpoint> {
        self.entries.iter()
    }
}
