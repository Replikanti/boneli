//! Which resolved addresses the egress may connect to, in which order, and
//! for how long (ADR-006, D4 and D5).
//!
//! Only globally reachable unicast addresses are allowed. The IPv4 table
//! lists every block of the IANA IPv4 Special-Purpose Address Registry that
//! is not globally reachable, plus multicast and the reserved space above
//! it; IPv6 is allowed only inside global unicast `2000::/3`, minus the
//! special-purpose blocks inside it that are not globally reachable. Both
//! tables were checked against the IANA registries, retrieved 2026-11-13
//! (ADR-006, D4).
//!
//! Behind DNS64 and NAT64 with a network-specific prefix, a synthesized
//! address is global unicast whatever IPv4 address it carries, so the
//! IPv6 table alone would let an A answer of `169.254.169.254` through as
//! `<prefix>::a9fe:a9fe`. The classification therefore takes the NAT64
//! prefixes in effect ([`Nat64Prefix`]) and also checks the IPv4 address
//! embedded in any address inside one of them. A prefix only ever adds
//! refusals: it never makes an address allowed that the tables forbid.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Forbidden IPv4 blocks: (network, prefix length). Each row names its
/// IANA registry entry.
const IPV4_FORBIDDEN: [(Ipv4Addr, u8); 15] = [
    // "This network" (RFC 791), including "this host" 0.0.0.0/32.
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    // Private-Use (RFC 1918).
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    // Shared Address Space (RFC 6598), carrier-grade NAT.
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    // Loopback (RFC 1122).
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    // Link Local (RFC 3927), with the cloud metadata address
    // 169.254.169.254.
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    // Private-Use (RFC 1918).
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    // IETF Protocol Assignments (RFC 6890), the whole /24: its two globally
    // reachable anycast addresses (192.0.0.9, 192.0.0.10) serve no
    // registry.
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    // Documentation, TEST-NET-1 (RFC 5737).
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    // Deprecated 6to4 Relay Anycast (RFC 7526), with 192.88.99.2/32.
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    // Private-Use (RFC 1918).
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    // Benchmarking (RFC 2544).
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    // Documentation, TEST-NET-2 (RFC 5737).
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    // Documentation, TEST-NET-3 (RFC 5737).
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    // Multicast (RFC 5771), from the IANA IPv4 Address Space Registry.
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    // Reserved (RFC 1112), including Limited Broadcast 255.255.255.255/32.
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// The only IPv6 space that may be allowed: global unicast (RFC 4291).
const IPV6_GLOBAL_UNICAST: (Ipv6Addr, u8) = (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);

/// Forbidden IPv6 blocks inside `2000::/3`: (network, prefix length). Every
/// other address outside `2000::/3` is forbidden too, which covers `::`,
/// `::1`, IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96` and
/// `64:ff9b:1::/48`, discard-only `100::/64`, SRv6 `5f00::/16`, unique
/// local `fc00::/7`, link-local `fe80::/10` and multicast `ff00::/8`.
const IPV6_FORBIDDEN: [(Ipv6Addr, u8); 4] = [
    // IETF Protocol Assignments (RFC 2928), with Teredo 2001::/32: the whole
    // /23, so its few globally reachable anycast and overlay blocks are
    // refused too; none of them serves a registry.
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    // Documentation (RFC 3849).
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
    // 6to4 (RFC 3056): the IPv4 address it embeds is not checked.
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
    // Documentation (RFC 9637).
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
];

fn in_v4(ip: Ipv4Addr, (net, prefix): (Ipv4Addr, u8)) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(net) & mask
}

fn in_v6(ip: Ipv6Addr, (net, prefix): (Ipv6Addr, u8)) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    u128::from(ip) & mask == u128::from(net) & mask
}

/// The prefix lengths RFC 6052 (section 2.2) allows for a NAT64 prefix.
const NAT64_LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];

/// The two well-known IPv4 addresses of `ipv4only.arpa` (RFC 7050,
/// section 2.2), which reveal a NAT64 prefix in a DNS64 answer.
const WELL_KNOWN_IPV4: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

/// A NAT64 prefix (`Pref64::/n`, RFC 6052): the well-known `64:ff9b::/96`
/// or a network-specific prefix of 32, 40, 48, 56, 64 or 96 bits. Ordered
/// by address, then length. Its text form is `<ipv6>/<len>` with the
/// address in `Ipv6Addr` display (ADR-006, D4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nat64Prefix {
    prefix: Ipv6Addr,
    len: u8,
}

/// Where RFC 6052 puts an embedded IPv4 address for a prefix length: its
/// four octets follow the prefix and skip octet 8, the "u" octet (bits 64
/// to 71), which must be zero. The octets after them are the suffix, which
/// RFC 6052 reserves and sets to zero.
fn ipv4_octets(len: u8) -> [usize; 4] {
    let mut out = [0; 4];
    let mut at = usize::from(len / 8);
    for slot in &mut out {
        if at == 8 {
            at += 1;
        }
        *slot = at;
        at += 1;
    }
    out
}

/// The four octets at the RFC 6052 IPv4 position for `len`, whatever the
/// u octet and the suffix hold. Does not check the prefix.
fn ipv4_at(ip: Ipv6Addr, len: u8) -> Ipv4Addr {
    let bytes = ip.octets();
    let at = ipv4_octets(len);
    Ipv4Addr::new(bytes[at[0]], bytes[at[1]], bytes[at[2]], bytes[at[3]])
}

/// The IPv4 address embedded in `ip` at the RFC 6052 position for `len`,
/// or `None` when the address is not the canonical form of a synthesized
/// one: for lengths up to 64 the u octet, which decides where the IPv4
/// bits sit, must be zero, and so must the suffix. A /96 has neither; its
/// IPv4 bits are 96 to 127 whatever its prefix holds in bits 64 to 71.
/// Does not check the prefix.
fn embedded_at(ip: Ipv6Addr, len: u8) -> Option<Ipv4Addr> {
    let bytes = ip.octets();
    let after = ipv4_octets(len)[3] + 1;
    if len <= 64 && bytes[8] != 0 {
        return None;
    }
    if bytes[after..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(ipv4_at(ip, len))
}

impl Nat64Prefix {
    /// A prefix of an RFC 6052 length with no bits set after it; `None`
    /// otherwise. RFC 6052 (section 2.2) also wants a /96 to leave the u
    /// octet (bits 64 to 71) zero, but a /96 that does not is accepted: a
    /// translator still takes the IPv4 address from bits 96 to 127, and a
    /// prefix only adds refusals, so rejecting it would only send that
    /// network's synthesized addresses back to the plain IPv6 check
    /// (ADR-006, D4).
    pub fn new(prefix: Ipv6Addr, len: u8) -> Option<Nat64Prefix> {
        if !NAT64_LENGTHS.contains(&len) {
            return None;
        }
        let host_bits = u128::MAX >> len;
        if u128::from(prefix) & host_bits != 0 {
            return None;
        }
        Some(Nat64Prefix { prefix, len })
    }

    /// Parses exactly the text form, `<ipv6>/<len>`, as `Display` writes
    /// it; anything else is `None`.
    pub fn parse(text: &str) -> Option<Nat64Prefix> {
        let (prefix, len) = text.split_once('/')?;
        let prefix: Ipv6Addr = prefix.parse().ok()?;
        let len: u8 = len.parse().ok()?;
        let out = Nat64Prefix::new(prefix, len)?;
        (out.to_string() == text).then_some(out)
    }

    /// The prefixes revealed by the AAAA answer for `ipv4only.arpa` (RFC
    /// 7050, section 3): for every address and every RFC 6052 length at
    /// which a well-known IPv4 address sits, the prefix before it. Sorted,
    /// without duplicates. The u octet and the suffix are not checked here:
    /// a network that sets them still has that prefix, and a surplus prefix
    /// only adds refusals, so keeping it fails closed (its non-canonical
    /// addresses are then all refused). For the same reason an address that
    /// matches at more than one length gives every match, where RFC 7050
    /// retries with the other well-known address.
    pub fn discover(aaaa: &[Ipv6Addr]) -> Vec<Nat64Prefix> {
        let mut out = Vec::new();
        for &ip in aaaa {
            for len in NAT64_LENGTHS {
                if WELL_KNOWN_IPV4.contains(&ipv4_at(ip, len)) {
                    let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
                    let prefix = Ipv6Addr::from(u128::from(ip) & mask);
                    out.extend(Nat64Prefix::new(prefix, len));
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// The network address.
    pub fn prefix(&self) -> Ipv6Addr {
        self.prefix
    }

    /// The prefix length in bits.
    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    fn contains(&self, ip: Ipv6Addr) -> bool {
        in_v6(ip, (self.prefix, self.len))
    }
}

impl fmt::Display for Nat64Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.prefix, self.len)
    }
}

/// Whether the egress refuses to connect to `ip` (ADR-006, D4), given the
/// NAT64 prefixes in effect. IPv4-mapped IPv6 addresses are forbidden
/// outright, never classified by the IPv4 address inside. An IPv6 address
/// inside one of `nat64` is also forbidden when the IPv4 address it embeds
/// is forbidden, or when it is not in the canonical form of a synthesized
/// address (u octet or suffix not zero). The prefixes only add refusals.
pub fn forbidden(ip: IpAddr, nat64: &[Nat64Prefix]) -> bool {
    match ip {
        IpAddr::V4(ip) => forbidden_v4(ip),
        IpAddr::V6(ip) => {
            !in_v6(ip, IPV6_GLOBAL_UNICAST)
                || IPV6_FORBIDDEN.iter().any(|&block| in_v6(ip, block))
                || nat64
                    .iter()
                    .any(|p| p.contains(ip) && embedded_at(ip, p.len).is_none_or(forbidden_v4))
        }
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    IPV4_FORBIDDEN.iter().any(|&block| in_v4(ip, block))
}

/// The first forbidden address in resolver order, or `None` when every
/// address may be used, given the NAT64 prefixes in effect. One forbidden
/// address refuses the whole name (ADR-006, D4): a resolver that returns
/// loopback or metadata space for a public name is not trusted for the
/// rest of its answer either.
pub fn first_forbidden(addrs: &[SocketAddr], nat64: &[Nat64Prefix]) -> Option<SocketAddr> {
    addrs
        .iter()
        .copied()
        .find(|addr| forbidden(addr.ip(), nat64))
}

/// The order of connect attempts (ADR-006, D5; RFC 8305, section 4):
/// families alternate, starting with the family of the resolver's first
/// address, and each family keeps the resolver's order. When one family
/// runs out, the rest of the other follows.
pub fn connect_order(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addrs.first() else {
        return addrs;
    };
    let first_is_v6 = first.is_ipv6();
    let (mut lead, mut other): (Vec<_>, Vec<_>) = (Vec::new(), Vec::new());
    for addr in &addrs {
        if addr.is_ipv6() == first_is_v6 {
            lead.push(*addr);
        } else {
            other.push(*addr);
        }
    }
    let mut out = Vec::with_capacity(addrs.len());
    let mut lead = lead.into_iter();
    let mut other = other.into_iter();
    loop {
        match (lead.next(), other.next()) {
            (None, None) => break,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
    out
}

/// The timeout of the next connect attempt: `per_attempt`, or what is left
/// of the total budget when that is less. `None` when nothing is left, so no
/// further attempt is made (std rejects a zero connect timeout; ADR-006,
/// D5).
pub fn attempt_timeout(remaining: Duration, per_attempt: Duration) -> Option<Duration> {
    let timeout = remaining.min(per_attempt);
    if timeout.is_zero() {
        None
    } else {
        Some(timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every table row is a network address: no bits set past its prefix,
    /// so a typo in an octet cannot silently widen or move a block.
    #[test]
    fn tables_are_networks() {
        for (net, prefix) in IPV4_FORBIDDEN {
            assert!((1..=32).contains(&prefix), "{net}/{prefix}");
            let host_bits = u32::MAX >> prefix;
            assert_eq!(u32::from(net) & host_bits, 0, "{net}/{prefix}");
        }
        for (net, prefix) in IPV6_FORBIDDEN.into_iter().chain([IPV6_GLOBAL_UNICAST]) {
            assert!((1..=128).contains(&prefix), "{net}/{prefix}");
            let host_bits = u128::MAX >> prefix;
            assert_eq!(u128::from(net) & host_bits, 0, "{net}/{prefix}");
            if (net, prefix) != IPV6_GLOBAL_UNICAST {
                assert!(in_v6(net, IPV6_GLOBAL_UNICAST), "{net}/{prefix}");
            }
        }
    }

    #[test]
    fn membership_edges() {
        let block = (Ipv4Addr::new(10, 0, 0, 0), 8);
        assert!(in_v4(Ipv4Addr::new(10, 255, 255, 255), block));
        assert!(!in_v4(Ipv4Addr::new(11, 0, 0, 0), block));
        let host = (Ipv4Addr::new(1, 2, 3, 4), 32);
        assert!(in_v4(Ipv4Addr::new(1, 2, 3, 4), host));
        assert!(!in_v4(Ipv4Addr::new(1, 2, 3, 5), host));
        let all = (Ipv4Addr::new(0, 0, 0, 0), 0);
        assert!(in_v4(Ipv4Addr::new(255, 255, 255, 255), all));
        let all6 = (Ipv6Addr::UNSPECIFIED, 0);
        assert!(in_v6(Ipv6Addr::LOCALHOST, all6));
    }
}
