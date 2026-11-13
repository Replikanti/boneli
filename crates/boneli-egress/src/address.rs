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

/// Whether the egress refuses to connect to `ip` (ADR-006, D4). IPv4-mapped
/// IPv6 addresses are forbidden outright, never classified by the IPv4
/// address inside.
pub fn forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => IPV4_FORBIDDEN.iter().any(|&block| in_v4(ip, block)),
        IpAddr::V6(ip) => {
            !in_v6(ip, IPV6_GLOBAL_UNICAST) || IPV6_FORBIDDEN.iter().any(|&block| in_v6(ip, block))
        }
    }
}

/// The first forbidden address in resolver order, or `None` when every
/// address may be used. One forbidden address refuses the whole name
/// (ADR-006, D4): a resolver that returns loopback or metadata space for a
/// public name is not trusted for the rest of its answer either.
pub fn first_forbidden(addrs: &[SocketAddr]) -> Option<SocketAddr> {
    addrs.iter().copied().find(|addr| forbidden(addr.ip()))
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
