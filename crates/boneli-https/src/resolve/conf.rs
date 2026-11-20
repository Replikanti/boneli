//! The resolver's configuration: the subset of resolv.conf(5) it reads
//! (ADR-022, D3), or values a caller sets.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::{
    DNS_DEFAULT_ATTEMPTS, DNS_DEFAULT_NDOTS, DNS_DEFAULT_TRY_TIMEOUT, DNS_MAX_ATTEMPTS,
    DNS_MAX_NAME_SERVERS, DNS_MAX_NDOTS, DNS_MAX_TRY_TIMEOUT, DNS_PORT,
};
use crate::{Error, Result};

/// Where and how the resolver asks: name servers, search domains, `ndots`,
/// the timeout of one try, the number of rounds over the servers, TCP only
/// (`use-vc`), and hosts(5) text read before any query.
///
/// [`ResolverConfig::parse`] reads it from resolv.conf(5) text the way
/// [`Resolver::system`](super::Resolver::system) does at every lookup;
/// [`ResolverConfig::new`] builds it for a runner with its own name
/// servers, or for a test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolverConfig {
    pub(super) servers: Vec<SocketAddr>,
    pub(super) search: Vec<String>,
    pub(super) ndots: u8,
    pub(super) try_timeout: Duration,
    pub(super) attempts: u8,
    pub(super) use_vc: bool,
    pub(super) hosts: Option<String>,
    /// The first `nameserver` value that was listed but cannot be used,
    /// kept only when no listed server can: the lookup then fails naming
    /// it instead of asking `127.0.0.1:53` (ADR-022, D3).
    pub(super) unusable: Option<String>,
}

impl ResolverConfig {
    /// The configuration resolv.conf(5) text gives (ADR-022, D3):
    /// `nameserver` lines (port 53, the first three that parse; one with
    /// a zone such as `fe80::1%eth0` or one that is not an address is
    /// skipped), `search` and `domain` (the last such line wins; `.`, the
    /// root, adds nothing), and the options `ndots:`, `timeout:`,
    /// `attempts:` and `use-vc`. Values are clamped: `ndots` to 15,
    /// `timeout` to 1..=30 seconds, `attempts` to 1..=5; a value that is
    /// not a number keeps the default. Every other line, option and
    /// comment (`#` or `;` at the start of a line) is ignored. With no
    /// `nameserver` line at all the resolver asks `127.0.0.1:53`, as libc
    /// does; when lines list servers and none of them can be used, it
    /// asks no server and a lookup that needs DNS fails, naming the first
    /// (`ErrorKind::Unsupported`).
    pub fn parse(text: &str) -> ResolverConfig {
        let mut config = ResolverConfig {
            servers: Vec::new(),
            search: Vec::new(),
            ndots: DNS_DEFAULT_NDOTS,
            try_timeout: DNS_DEFAULT_TRY_TIMEOUT,
            attempts: DNS_DEFAULT_ATTEMPTS,
            use_vc: false,
            hosts: None,
            unusable: None,
        };
        let mut listed = false;
        for line in text.lines() {
            let mut words = line.split_ascii_whitespace();
            match words.next() {
                Some("nameserver") => {
                    let Some(word) = words.next() else {
                        continue;
                    };
                    listed = true;
                    match word.parse::<IpAddr>() {
                        Ok(ip) if config.servers.len() < DNS_MAX_NAME_SERVERS => {
                            config.servers.push(SocketAddr::new(ip, DNS_PORT));
                        }
                        Ok(_) => {}
                        Err(_) => {
                            config.unusable.get_or_insert_with(|| word.to_owned());
                        }
                    }
                }
                Some("search" | "domain") => config.search = search_domains(words),
                Some("options") => {
                    for option in words {
                        config.option(option);
                    }
                }
                _ => {}
            }
        }
        if !config.servers.is_empty() {
            config.unusable = None;
        } else if !listed {
            config
                .servers
                .push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_PORT));
        }
        config
    }

    fn option(&mut self, option: &str) {
        if option == "use-vc" {
            self.use_vc = true;
        } else if let Some(n) = option.strip_prefix("ndots:").and_then(number) {
            self.ndots = clamp_u8(n, 0, DNS_MAX_NDOTS);
        } else if let Some(n) = option.strip_prefix("timeout:").and_then(number) {
            let max = DNS_MAX_TRY_TIMEOUT.as_secs();
            self.try_timeout = Duration::from_secs(n.clamp(1, max));
        } else if let Some(n) = option.strip_prefix("attempts:").and_then(number) {
            self.attempts = clamp_u8(n, 1, DNS_MAX_ATTEMPTS);
        }
    }

    /// Name servers at any address and port, `try_timeout` per try and
    /// `attempts` rounds over the servers; no search domains, `ndots` 1,
    /// UDP first, no hosts entries. Refused with [`Error::InvalidInput`]:
    /// no server or more than [`DNS_MAX_NAME_SERVERS`], a zero timeout or
    /// one above [`DNS_MAX_TRY_TIMEOUT`], zero attempts or more than
    /// [`DNS_MAX_ATTEMPTS`].
    pub fn new(
        servers: Vec<SocketAddr>,
        try_timeout: Duration,
        attempts: u8,
    ) -> Result<ResolverConfig> {
        if servers.is_empty() {
            return Err(Error::InvalidInput("no name server"));
        }
        if servers.len() > DNS_MAX_NAME_SERVERS {
            return Err(Error::InvalidInput("more than three name servers"));
        }
        if try_timeout.is_zero() || try_timeout > DNS_MAX_TRY_TIMEOUT {
            return Err(Error::InvalidInput("the try timeout is zero or above 30 s"));
        }
        if attempts == 0 || attempts > DNS_MAX_ATTEMPTS {
            return Err(Error::InvalidInput("attempts are zero or above five"));
        }
        Ok(ResolverConfig {
            servers,
            search: Vec::new(),
            ndots: DNS_DEFAULT_NDOTS,
            try_timeout,
            attempts,
            use_vc: false,
            hosts: None,
            unusable: None,
        })
    }

    /// The search domains, in order, as a `search` line gives them:
    /// lowercased, a trailing dot dropped, `.` left out.
    pub fn with_search(mut self, search: Vec<String>) -> ResolverConfig {
        self.search = search_domains(search.iter().map(String::as_str));
        self
    }

    /// The `ndots` threshold: a name with fewer dots tries the search
    /// domains first. Clamped to [`DNS_MAX_NDOTS`].
    pub fn with_ndots(mut self, ndots: u8) -> ResolverConfig {
        self.ndots = ndots.min(DNS_MAX_NDOTS);
        self
    }

    /// TCP for every query, as resolv.conf's `use-vc`.
    pub fn with_use_vc(mut self, use_vc: bool) -> ResolverConfig {
        self.use_vc = use_vc;
        self
    }

    /// hosts(5) text, read before any query by the reader `/etc/hosts`
    /// goes through.
    pub fn with_hosts(mut self, hosts: String) -> ResolverConfig {
        self.hosts = Some(hosts);
        self
    }
}

fn search_domains<'a>(words: impl Iterator<Item = &'a str>) -> Vec<String> {
    words
        .map(|w| w.strip_suffix('.').unwrap_or(w).to_ascii_lowercase())
        .filter(|w| !w.is_empty())
        .collect()
}

/// A decimal number, saturated at `u64::MAX`, or `None` when the text is
/// not one.
fn number(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(text.parse().unwrap_or(u64::MAX))
}

fn clamp_u8(n: u64, min: u8, max: u8) -> u8 {
    u8::try_from(n.clamp(u64::from(min), u64::from(max))).unwrap_or(max)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::ResolverConfig;

    fn servers(config: &ResolverConfig) -> Vec<String> {
        config.servers.iter().map(SocketAddr::to_string).collect()
    }

    #[test]
    fn empty_resolv_conf_uses_defaults() {
        let config = ResolverConfig::parse("");
        assert_eq!(servers(&config), ["127.0.0.1:53"]);
        assert_eq!(config.ndots, 1);
        assert_eq!(config.try_timeout, Duration::from_secs(5));
        assert_eq!(config.attempts, 2);
        assert!(config.search.is_empty());
        assert!(!config.use_vc);
        assert_eq!(config.hosts, None);
    }

    #[test]
    fn option_values_are_clamped() {
        let parse = |options: &str| ResolverConfig::parse(&format!("options {options}\n"));
        assert_eq!(parse("ndots:15").ndots, 15);
        assert_eq!(parse("ndots:16").ndots, 15);
        assert_eq!(parse("ndots:0").ndots, 0);
        assert_eq!(parse("ndots:x").ndots, 1);
        assert_eq!(parse("ndots:").ndots, 1);
        assert_eq!(parse("ndots:99999999999999999999999").ndots, 15);
        assert_eq!(parse("timeout:30").try_timeout, Duration::from_secs(30));
        assert_eq!(parse("timeout:31").try_timeout, Duration::from_secs(30));
        assert_eq!(parse("timeout:0").try_timeout, Duration::from_secs(1));
        assert_eq!(parse("attempts:5").attempts, 5);
        assert_eq!(parse("attempts:6").attempts, 5);
        assert_eq!(parse("attempts:0").attempts, 1);
        assert!(parse("use-vc").use_vc);
        // Several options on one line, and later lines override.
        let config = ResolverConfig::parse("options ndots:3 timeout:2\noptions ndots:4\n");
        assert_eq!(config.ndots, 4);
        assert_eq!(config.try_timeout, Duration::from_secs(2));

        // The builders clamp the same way.
        let fixed = ResolverConfig::new(
            vec!["192.0.2.53:53".parse().expect("addr")],
            Duration::from_secs(1),
            1,
        )
        .expect("config")
        .with_ndots(200);
        assert_eq!(fixed.ndots, 15);
    }

    #[test]
    fn name_servers_beyond_three_are_ignored() {
        let config = ResolverConfig::parse(
            "nameserver 192.0.2.1\nnameserver 192.0.2.2\nnameserver 2001:db8::3\nnameserver 192.0.2.4\n",
        );
        assert_eq!(
            servers(&config),
            ["192.0.2.1:53", "192.0.2.2:53", "[2001:db8::3]:53"]
        );
    }

    #[test]
    fn zoned_and_invalid_name_servers_are_skipped() {
        let config = ResolverConfig::parse(
            "nameserver fe80::1%eth0\nnameserver x\nnameserver 127.1\nnameserver\nnameserver 192.0.2.7\n",
        );
        assert_eq!(servers(&config), ["192.0.2.7:53"]);
        assert_eq!(config.unusable, None);
        // Only unusable servers listed: no server, not the default one;
        // the lookup fails naming the first (ADR-022, D3).
        let config = ResolverConfig::parse("nameserver x\nnameserver fe80::1%eth0\n");
        assert_eq!(servers(&config), Vec::<String>::new());
        assert_eq!(config.unusable.as_deref(), Some("x"));
        // A `nameserver` line without a value lists nothing.
        let config = ResolverConfig::parse("nameserver\n");
        assert_eq!(servers(&config), ["127.0.0.1:53"]);
        assert_eq!(config.unusable, None);
    }

    #[test]
    fn comments_and_unknown_options_are_ignored() {
        let config = ResolverConfig::parse(
            "# nameserver 192.0.2.1\n; nameserver 192.0.2.2\n\
             options rotate edns0 trust-ad single-request ndots:2\n\
             sortlist 192.0.2.0/24\nlookup file bind\n\
             nameserver 192.0.2.3 # trailing words\n",
        );
        assert_eq!(servers(&config), ["192.0.2.3:53"]);
        assert_eq!(config.ndots, 2);
        assert!(!config.use_vc);
    }

    #[test]
    fn last_search_or_domain_line_wins() {
        let config = ResolverConfig::parse("search a.example b.example\ndomain C.Example.\n");
        assert_eq!(config.search, ["c.example"]);
        let config = ResolverConfig::parse("domain c.example\nsearch a.example b.example\n");
        assert_eq!(config.search, ["a.example", "b.example"]);
        // A trailing CR (a file with CRLF lines) is whitespace.
        let config = ResolverConfig::parse("search a.example\r\n");
        assert_eq!(config.search, ["a.example"]);
    }

    #[test]
    fn root_search_domain_adds_nothing() {
        // What systemd-resolved writes into its resolv.conf.
        let config =
            ResolverConfig::parse("nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n");
        assert!(config.search.is_empty());
        let fixed = ResolverConfig::new(
            vec!["192.0.2.53:53".parse().expect("addr")],
            Duration::from_secs(1),
            1,
        )
        .expect("config")
        .with_search(vec![".".into(), "Corp.Example.".into()]);
        assert_eq!(fixed.search, ["corp.example"]);
    }

    #[test]
    fn new_refuses_values_outside_the_bounds() {
        let one: SocketAddr = "192.0.2.53:5353".parse().expect("addr");
        let sec = Duration::from_secs(1);
        assert!(ResolverConfig::new(vec![], sec, 1).is_err());
        assert!(ResolverConfig::new(vec![one; 4], sec, 1).is_err());
        assert!(ResolverConfig::new(vec![one], Duration::ZERO, 1).is_err());
        assert!(ResolverConfig::new(vec![one], Duration::from_millis(30_001), 1).is_err());
        assert!(ResolverConfig::new(vec![one], sec, 0).is_err());
        assert!(ResolverConfig::new(vec![one], sec, 6).is_err());
        let ok = ResolverConfig::new(vec![one; 3], Duration::from_secs(30), 5).expect("bounds");
        assert_eq!(servers(&ok), ["192.0.2.53:5353"; 3]);
    }
}
