//! A stub resolver whose every wait ends by the caller's deadline
//! (ADR-022). std's `to_socket_addrs` calls `getaddrinfo`, which takes no
//! timeout: against name servers that never answer, glibc waited 10.0 s
//! with one server and 28.0 s with three (ADR-006). This resolver runs on
//! the caller's thread and starts no thread or process, so nothing it
//! does outlives the call.
//!
//! It has the semantics of musl's `getaddrinfo`, which has no NSS: an IP
//! literal as it is, `localhost` as loopback, then hosts(5), then A and
//! AAAA queries over UDP (TCP when an answer is truncated) to the name
//! servers of resolv.conf(5). Names that only another NSS source knows
//! (mDNS, LDAP, systemd-resolved's split DNS behind uplink servers) do not
//! resolve.

mod conf;
mod exchange;
mod hosts;
mod message;

pub use conf::ResolverConfig;

use std::borrow::Cow;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::dial::{check_host, time_left};
use exchange::{Fail, TryResult};

/// The DNS port (RFC 1035, 4.2).
pub const DNS_PORT: u16 = 53;

/// The most name servers asked, glibc's `MAXNS`: the set libc uses. More
/// would add tries before a failure; fewer would drop a configured server.
pub const DNS_MAX_NAME_SERVERS: usize = 3;

/// The default `ndots` (glibc's and resolv.conf(5)'s): a name with fewer
/// dots tries the search domains first.
pub const DNS_DEFAULT_NDOTS: u8 = 1;

/// The largest `ndots`, glibc's `RES_MAXNDOTS`.
pub const DNS_MAX_NDOTS: u8 = 15;

/// The default wait of one try against one server, glibc's `RES_TIMEOUT`.
/// Lower re-asks a slow but alive server on a cold recursive lookup;
/// higher lets a dead first server take more of the deadline.
pub const DNS_DEFAULT_TRY_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest wait of one try, glibc's `RES_MAXRETRANS`.
pub const DNS_MAX_TRY_TIMEOUT: Duration = Duration::from_secs(30);

/// The default number of rounds over the servers, glibc's `RES_DFLRETRY`.
pub const DNS_DEFAULT_ATTEMPTS: u8 = 2;

/// The most rounds over the servers, glibc's `RES_MAXRETRY`.
pub const DNS_MAX_ATTEMPTS: u8 = 5;

/// The largest answer over UDP: queries carry no EDNS record, so a server
/// answers in at most 512 bytes (RFC 1035, 4.2.1) and sets TC=1 when the
/// answer does not fit; the resolver then asks over TCP.
pub const DNS_UDP_MESSAGE_BYTES: usize = 512;

const RESOLV_CONF: &str = "/etc/resolv.conf";
const HOSTS: &str = "/etc/hosts";

/// A name resolver whose lookups end by a deadline (ADR-022).
///
/// [`Resolver::system`] reads `/etc/resolv.conf` and `/etc/hosts` at every
/// lookup, as musl does; [`Resolver::fixed`] uses a [`ResolverConfig`].
/// A lookup takes, in order: an IP literal as it is; `localhost` and
/// names under `.localhost` as `::1` and `127.0.0.1` (RFC 6761, 6.3); the
/// hosts entries of the name; then DNS, for each candidate name of the
/// search list, `attempts` rounds over the name servers, each try waiting
/// at most the try timeout and never past the deadline. Addresses are
/// returned once each, IPv6 first, by the precedence of RFC 3484's
/// default table. Nothing runs on another thread or outlives the call.
#[derive(Clone, Debug)]
pub struct Resolver {
    source: Source,
}

#[derive(Clone, Debug)]
enum Source {
    System {
        resolv_conf: PathBuf,
        hosts: PathBuf,
    },
    Fixed(Arc<ResolverConfig>),
}

impl Resolver {
    /// The host's resolver configuration: `/etc/resolv.conf` and
    /// `/etc/hosts`, read at every lookup. A missing file counts as an
    /// empty one; environment variables (`LOCALDOMAIN`, `RES_OPTIONS`,
    /// `HOSTALIASES`) and nsswitch.conf are not read.
    pub fn system() -> Resolver {
        Resolver::from_paths(PathBuf::from(RESOLV_CONF), PathBuf::from(HOSTS))
    }

    /// Like [`Resolver::system`] over other files, for the tests.
    pub(crate) fn from_paths(resolv_conf: PathBuf, hosts: PathBuf) -> Resolver {
        Resolver {
            source: Source::System { resolv_conf, hosts },
        }
    }

    /// A resolver that asks as `config` says and reads no file.
    pub fn fixed(config: ResolverConfig) -> Resolver {
        Resolver {
            source: Source::Fixed(Arc::new(config)),
        }
    }

    /// The addresses of `host` with `port`, by `deadline`.
    ///
    /// `host` is ASCII-lowercased, then must be in ADR-003's grammar (an
    /// LDH name whose last label is not a number, a canonical IPv4
    /// address, or an IPv6 address without brackets), and `port` must not
    /// be 0; otherwise `InvalidInput`, before any file is read or query
    /// sent. Errors: `TimedOut` once the deadline passed or when every
    /// name server timed out for a candidate name; `NotFound` when no
    /// candidate has an address; `Other` when name servers failed;
    /// `Unsupported` when resolv.conf lists name servers and none of them
    /// can be used (a zoned IPv6 address, a word that is not an address).
    pub fn lookup(&self, host: &str, port: u16, deadline: Instant) -> io::Result<Vec<SocketAddr>> {
        let host = host.to_ascii_lowercase();
        check_host(&host, port)?;
        time_left(deadline)?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let ips = self.lookup_name(&host, deadline)?;
        Ok(order(ips)
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    fn lookup_name(&self, name: &str, deadline: Instant) -> io::Result<Vec<IpAddr>> {
        if name == "localhost" || name.ends_with(".localhost") {
            return Ok(vec![
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ]);
        }
        let from_hosts = self.hosts_entries(name, deadline)?;
        if !from_hosts.is_empty() {
            return Ok(from_hosts);
        }
        let config = self.config()?;
        if config.servers.is_empty() {
            let listed = config.unusable.as_deref().unwrap_or_default();
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("resolv.conf lists no name server the resolver can use, first {listed:?}"),
            ));
        }
        let mut last = None;
        for candidate in candidates(name, &config) {
            let Some(wire) = message::wire_name(&candidate) else {
                continue;
            };
            match query_candidate(&config, &wire, deadline)? {
                Outcome::Found(ips) => return Ok(ips),
                Outcome::NoName => {}
                Outcome::Failed(server, fail) => last = Some(format!("{server}: {fail}")),
            }
        }
        match last {
            Some(failure) => Err(io::Error::other(format!(
                "the name servers failed: {failure}"
            ))),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the host has no address",
            )),
        }
    }

    fn hosts_entries(&self, name: &str, deadline: Instant) -> io::Result<Vec<IpAddr>> {
        match &self.source {
            Source::Fixed(config) => match &config.hosts {
                Some(text) => hosts::lookup_hosts(text.as_bytes(), name, deadline),
                None => Ok(Vec::new()),
            },
            Source::System { hosts, .. } => match File::open(hosts) {
                Ok(file) => hosts::lookup_hosts(BufReader::new(file), name, deadline),
                Err(e) if is_absent(&e) => Ok(Vec::new()),
                Err(e) => Err(e),
            },
        }
    }

    fn config(&self) -> io::Result<Cow<'_, ResolverConfig>> {
        match &self.source {
            Source::Fixed(config) => Ok(Cow::Borrowed(config)),
            Source::System { resolv_conf, .. } => {
                let text = match std::fs::read(resolv_conf) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                    Err(e) if is_absent(&e) => String::new(),
                    Err(e) => return Err(e),
                };
                Ok(Cow::Owned(ResolverConfig::parse(&text)))
            }
        }
    }
}

/// A file libc would also pass over: missing, or not readable by us.
fn is_absent(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied | io::ErrorKind::NotADirectory
    )
}

/// The names to ask, in order (ADR-022, D5): with at least `ndots` dots
/// the name itself first, then the name under each search domain;
/// with fewer, the search domains first and the name last, as glibc's
/// `res_search`. A candidate over 253 bytes is left out.
fn candidates(name: &str, config: &ResolverConfig) -> Vec<String> {
    let dots = name.bytes().filter(|&b| b == b'.').count();
    let searched = config
        .search
        .iter()
        .map(|domain| format!("{name}.{domain}"));
    let list: Vec<String> = if dots >= usize::from(config.ndots) {
        std::iter::once(name.to_owned()).chain(searched).collect()
    } else {
        searched.chain(std::iter::once(name.to_owned())).collect()
    };
    list.into_iter().filter(|c| c.len() <= 253).collect()
}

enum Outcome {
    Found(Vec<IpAddr>),
    NoName,
    Failed(SocketAddr, Fail),
}

/// `attempts` rounds over the servers for one candidate; each try waits at
/// most `min(try timeout, time left)`. Every try timing out ends the
/// lookup with `TimedOut`, as glibc's `res_search` stops; NXDOMAIN, NODATA
/// and failures go on to the next candidate.
fn query_candidate(config: &ResolverConfig, wire: &[u8], deadline: Instant) -> io::Result<Outcome> {
    let mut last = None;
    for _ in 0..config.attempts {
        for &server in &config.servers {
            let left = time_left(deadline)?;
            let try_end = Instant::now() + config.try_timeout.min(left);
            match exchange::try_server(
                server,
                wire,
                config.use_vc,
                config.try_timeout,
                try_end,
                deadline,
            )? {
                TryResult::Found(ips) => return Ok(Outcome::Found(ips)),
                TryResult::NoName => return Ok(Outcome::NoName),
                TryResult::Failed(fail) => last = Some((server, fail)),
                TryResult::TimedOut => {}
            }
        }
    }
    time_left(deadline)?;
    match last {
        Some((server, fail)) => Ok(Outcome::Failed(server, fail)),
        None => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no name server answered in time",
        )),
    }
}

/// Duplicates removed (the first stays), then a stable sort by the
/// precedence of RFC 3484's default policy table as gai.conf(5) prints
/// it: `::1/128` 50, `::/0` 40, `2002::/16` 30, `::/96` 20,
/// `::ffff:0:0/96` 10, IPv4 as `::ffff:0:0/96`. The other rules of RFC
/// 3484 are not applied.
fn order(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut unique: Vec<IpAddr> = Vec::with_capacity(ips.len());
    for ip in ips {
        if !unique.contains(&ip) {
            unique.push(ip);
        }
    }
    unique.sort_by_key(|ip| std::cmp::Reverse(precedence(ip)));
    unique
}

fn precedence(ip: &IpAddr) -> u8 {
    let v6 = match ip {
        IpAddr::V4(_) => return 10,
        IpAddr::V6(v6) => v6.segments(),
    };
    match v6 {
        [0, 0, 0, 0, 0, 0, 0, 1] => 50,
        [0, 0, 0, 0, 0, 0xffff, _, _] => 10,
        [0, 0, 0, 0, 0, 0, _, _] => 20,
        [0x2002, ..] => 30,
        _ => 40,
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use super::{Resolver, ResolverConfig, candidates, order};

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().expect("ip")).collect()
    }

    fn search(domains: &[&str], ndots: u8) -> ResolverConfig {
        ResolverConfig::parse(&format!(
            "search {}\noptions ndots:{ndots}\n",
            domains.join(" ")
        ))
    }

    #[test]
    fn order_follows_the_rfc3484_precedence_table() {
        let input = ips(&[
            "192.0.2.1",
            "fd00::1",
            "2001:db8::1",
            "::1",
            "2002::1",
            "::c000:201",
        ]);
        assert_eq!(
            order(input),
            ips(&[
                "::1",
                "fd00::1",
                "2001:db8::1",
                "2002::1",
                "::c000:201",
                "192.0.2.1"
            ])
        );
        // A mapped IPv4 address ranks with IPv4, in input order.
        assert_eq!(
            order(ips(&["::ffff:192.0.2.1", "192.0.2.2", "::ffff:192.0.2.3"])),
            ips(&["::ffff:192.0.2.1", "192.0.2.2", "::ffff:192.0.2.3"])
        );
    }

    #[test]
    fn duplicate_addresses_are_tried_once() {
        assert_eq!(
            order(ips(&[
                "192.0.2.1",
                "2001:db8::1",
                "192.0.2.1",
                "2001:db8::1"
            ])),
            ips(&["2001:db8::1", "192.0.2.1"])
        );
    }

    #[test]
    fn search_candidates_follow_ndots() {
        let config = search(&["corp.example", "example"], 1);
        assert_eq!(
            candidates("git", &config),
            ["git.corp.example", "git.example", "git"]
        );
        assert_eq!(
            candidates("git.lab", &config),
            ["git.lab", "git.lab.corp.example", "git.lab.example"]
        );
        let config = search(&["corp.example", "example"], 2);
        assert_eq!(
            candidates("git.lab", &config),
            ["git.lab.corp.example", "git.lab.example", "git.lab"]
        );
        // ndots 0: the name itself always comes first.
        let config = search(&["corp.example"], 0);
        assert_eq!(candidates("git", &config), ["git", "git.corp.example"]);
    }

    #[test]
    fn candidates_longer_than_253_bytes_are_skipped() {
        // 245 bytes: 4 labels of 60 and one of 1, with 4 dots.
        let name = format!("{0}.{0}.{0}.{0}.a", "a".repeat(60));
        assert_eq!(name.len(), 245);
        let config = search(&["corp.example", "ex"], 1);
        // 245 + ".corp.example" = 258 is left out; 245 + ".ex" = 248 stays.
        assert_eq!(
            candidates(&name, &config),
            [name.clone(), format!("{name}.ex")]
        );
    }

    /// A directory of its own under the system's temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "boneli-resolve-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir(&dir).expect("scratch dir");
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn missing_files_use_defaults() {
        let dir = Scratch::new("missing");
        let resolver = Resolver::from_paths(dir.0.join("resolv.conf"), dir.0.join("hosts"));
        let config = resolver.config().expect("config");
        assert_eq!(*config, ResolverConfig::parse(""));
        assert_eq!(
            resolver.hosts_entries("git", far()).expect("hosts"),
            ips(&[])
        );
        // A path under a file is absent too.
        let file = dir.0.join("file");
        std::fs::write(&file, "").expect("file");
        let resolver = Resolver::from_paths(file.join("resolv.conf"), file.join("hosts"));
        assert_eq!(
            *resolver.config().expect("config"),
            ResolverConfig::parse("")
        );
        assert_eq!(
            resolver.hosts_entries("git", far()).expect("hosts"),
            ips(&[])
        );
    }

    #[test]
    fn symlinked_resolv_conf_is_followed() {
        let dir = Scratch::new("symlink");
        let real = dir.0.join("stub-resolv.conf");
        std::fs::write(&real, "nameserver 192.0.2.53\nsearch corp.example\n").expect("write");
        let link = dir.0.join("resolv.conf");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let hosts_real = dir.0.join("hosts.real");
        std::fs::write(&hosts_real, "192.0.2.1 git\n").expect("write");
        let hosts = dir.0.join("hosts");
        std::os::unix::fs::symlink(&hosts_real, &hosts).expect("symlink");
        let resolver = Resolver::from_paths(link, hosts);
        let config = resolver.config().expect("config");
        assert_eq!(
            *config,
            ResolverConfig::parse("nameserver 192.0.2.53\nsearch corp.example\n")
        );
        assert_eq!(
            resolver.hosts_entries("git", far()).expect("hosts"),
            ips(&["192.0.2.1"])
        );
        // The system paths are absolute constants.
        assert!(PathBuf::from(super::RESOLV_CONF).is_absolute());
        assert!(PathBuf::from(super::HOSTS).is_absolute());
    }
}
