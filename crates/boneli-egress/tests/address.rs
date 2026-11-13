//! Address classes, connect order and the connect budget (ADR-006, D4 and
//! D5). Every block is pinned on both sides of both of its edges.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use boneli_egress::address::{
    Nat64Prefix, attempt_timeout, connect_order, first_forbidden, forbidden,
};

fn v4(s: &str) -> IpAddr {
    IpAddr::V4(s.parse::<Ipv4Addr>().expect(s))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().expect(s))
}

fn sock(s: &str) -> SocketAddr {
    s.parse().expect(s)
}

fn assert_allowed(ips: &[IpAddr]) {
    for ip in ips {
        assert!(!forbidden(*ip, &[]), "{ip} must be allowed");
    }
}

fn assert_forbidden(ips: &[IpAddr]) {
    for ip in ips {
        assert!(forbidden(*ip, &[]), "{ip} must be forbidden");
    }
}

#[test]
fn ipv4_block_boundaries() {
    // (last allowed below, first forbidden, last forbidden, first allowed
    // above); `None` where the neighbour is forbidden too or does not exist.
    let blocks: [(Option<&str>, &str, &str, Option<&str>); 15] = [
        (None, "0.0.0.0", "0.255.255.255", Some("1.0.0.0")),
        (
            Some("9.255.255.255"),
            "10.0.0.0",
            "10.255.255.255",
            Some("11.0.0.0"),
        ),
        (
            Some("100.63.255.255"),
            "100.64.0.0",
            "100.127.255.255",
            Some("100.128.0.0"),
        ),
        (
            Some("126.255.255.255"),
            "127.0.0.0",
            "127.255.255.255",
            Some("128.0.0.0"),
        ),
        (
            Some("169.253.255.255"),
            "169.254.0.0",
            "169.254.255.255",
            Some("169.255.0.0"),
        ),
        (
            Some("172.15.255.255"),
            "172.16.0.0",
            "172.31.255.255",
            Some("172.32.0.0"),
        ),
        (
            Some("191.255.255.255"),
            "192.0.0.0",
            "192.0.0.255",
            Some("192.0.1.0"),
        ),
        (
            Some("192.0.1.255"),
            "192.0.2.0",
            "192.0.2.255",
            Some("192.0.3.0"),
        ),
        (
            Some("192.88.98.255"),
            "192.88.99.0",
            "192.88.99.255",
            Some("192.88.100.0"),
        ),
        (
            Some("192.167.255.255"),
            "192.168.0.0",
            "192.168.255.255",
            Some("192.169.0.0"),
        ),
        (
            Some("198.17.255.255"),
            "198.18.0.0",
            "198.19.255.255",
            Some("198.20.0.0"),
        ),
        (
            Some("198.51.99.255"),
            "198.51.100.0",
            "198.51.100.255",
            Some("198.51.101.0"),
        ),
        (
            Some("203.0.112.255"),
            "203.0.113.0",
            "203.0.113.255",
            Some("203.0.114.0"),
        ),
        // Multicast, then reserved space up to the limited broadcast.
        (
            Some("223.255.255.255"),
            "224.0.0.0",
            "239.255.255.255",
            None,
        ),
        (None, "240.0.0.0", "255.255.255.255", None),
    ];
    for (below, first, last, above) in blocks {
        assert_forbidden(&[v4(first), v4(last)]);
        if let Some(below) = below {
            assert_allowed(&[v4(below)]);
        }
        if let Some(above) = above {
            assert_allowed(&[v4(above)]);
        }
    }
    // Points inside, named by the plan and by the registry.
    assert_forbidden(&[
        v4("169.254.169.254"),
        v4("127.0.0.1"),
        v4("192.0.0.9"),
        v4("192.0.0.170"),
        v4("192.88.99.2"),
    ]);
    // Globally reachable special-purpose blocks stay allowed (AS112, AMT),
    // and so do the MVP hosts' addresses.
    assert_allowed(&[
        v4("192.31.196.1"),
        v4("192.52.193.1"),
        v4("192.175.48.1"),
        v4("104.16.0.34"),
        v4("151.101.0.223"),
        v4("160.79.104.10"),
        v4("1.1.1.1"),
        v4("8.8.8.8"),
    ]);
}

#[test]
fn ipv6_global_unicast_boundaries() {
    assert_forbidden(&[
        // Just below and just above 2000::/3.
        v6("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        v6("4000::"),
        // 2001::/23, Teredo included, both ends.
        v6("2001::"),
        v6("2001::1"),
        v6("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff"),
        // Documentation, both ends.
        v6("2001:db8::"),
        v6("2001:db8::1"),
        v6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"),
        // 6to4, both ends.
        v6("2002::"),
        v6("2002::1"),
        v6("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        // 3fff::/20 (RFC 9637), both ends.
        v6("3fff::"),
        v6("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"),
    ]);
    assert_allowed(&[
        v6("2000::"),
        v6("2001:200::"),
        v6("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"),
        v6("2001:db9::"),
        v6("2001:1fff:ffff:ffff:ffff:ffff:ffff:ffff"),
        v6("2003::"),
        v6("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        v6("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        v6("3fff:1000::"),
        v6("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        // The four MVP AAAA prefixes.
        v6("2606:4700::6810:22"),
        v6("2a04:4e42::223"),
        v6("2607:6bc0::10"),
        v6("2a04:4e42:200::223"),
    ]);
}

#[test]
fn ipv6_special_forms_are_forbidden() {
    assert_forbidden(&[
        v6("::"),
        v6("::1"),
        v6("::ffff:127.0.0.1"),
        v6("::ffff:104.16.0.34"),
        v6("::127.0.0.1"),
        v6("64:ff9b::808:808"),
        v6("64:ff9b:1::1"),
        v6("100::1"),
        v6("5f00::1"),
        v6("fe80::1"),
        v6("fc00::1"),
        v6("fd00::1"),
        v6("ff02::1"),
        v6("ff0e::1"),
    ]);
}

#[test]
fn any_forbidden_address_refuses_the_name() {
    let addrs = [
        sock("104.16.0.34:443"),
        sock("127.0.0.1:443"),
        sock("10.0.0.1:443"),
    ];
    assert_eq!(first_forbidden(&addrs, &[]), Some(sock("127.0.0.1:443")));
    let mixed = [sock("[2606:4700::6810:22]:443"), sock("[::1]:443")];
    assert_eq!(first_forbidden(&mixed, &[]), Some(sock("[::1]:443")));
    let global = [sock("104.16.0.34:443"), sock("[2606:4700::6810:22]:443")];
    assert_eq!(first_forbidden(&global, &[]), None);
    assert_eq!(first_forbidden(&[], &[]), None);
}

#[test]
fn connect_order_interleaves_families() {
    let v6a = sock("[2606:4700::1]:443");
    let v6b = sock("[2606:4700::2]:443");
    let v6c = sock("[2606:4700::3]:443");
    let v4a = sock("104.16.0.1:443");
    let v4b = sock("104.16.0.2:443");
    assert_eq!(
        connect_order(vec![v6a, v6b, v4a, v4b]),
        [v6a, v4a, v6b, v4b]
    );
    // The resolver's first address picks the first family.
    assert_eq!(
        connect_order(vec![v4a, v6a, v6b, v4b]),
        [v4a, v6a, v4b, v6b]
    );
    // The longer family's tail keeps its order.
    assert_eq!(
        connect_order(vec![v6a, v6b, v6c, v4a]),
        [v6a, v4a, v6b, v6c]
    );
    assert_eq!(connect_order(vec![v4a, v4b]), [v4a, v4b]);
    assert_eq!(connect_order(vec![v6b, v6a]), [v6b, v6a]);
    assert_eq!(connect_order(vec![v4a]), [v4a]);
    assert_eq!(connect_order(Vec::new()), []);
}

#[test]
fn attempt_budget_arithmetic() {
    let ten = Duration::from_secs(10);
    let attempts = |total: Duration| {
        let mut remaining = total;
        let mut out = Vec::new();
        while let Some(timeout) = attempt_timeout(remaining, ten) {
            out.push(timeout);
            remaining -= timeout;
            assert!(out.len() <= 100, "the budget never ends");
        }
        out
    };
    assert_eq!(attempts(Duration::from_secs(30)), [ten, ten, ten]);
    assert_eq!(
        attempts(Duration::from_secs(25)),
        [ten, ten, Duration::from_secs(5)]
    );
    assert_eq!(
        attempts(Duration::from_millis(1)),
        [Duration::from_millis(1)]
    );
    assert_eq!(attempt_timeout(Duration::ZERO, ten), None);
    assert_eq!(attempt_timeout(ten, Duration::ZERO), None);
    assert_eq!(
        attempt_timeout(Duration::from_nanos(1), ten),
        Some(Duration::from_nanos(1))
    );
}

fn v6addr(s: &str) -> Ipv6Addr {
    s.parse().expect(s)
}

fn nat64(prefix: &str, len: u8) -> Nat64Prefix {
    Nat64Prefix::new(v6addr(prefix), len).expect(prefix)
}

/// `v4` embedded into `prefix/len` at the RFC 6052 (section 2.2) position
/// for that length, with the u octet and the suffix zero.
fn embed(prefix: &str, len: u8, v4: Ipv4Addr) -> Ipv6Addr {
    let mut bytes = v6addr(prefix).octets();
    let positions: Vec<usize> = (usize::from(len / 8)..16)
        .filter(|&i| i != 8)
        .take(4)
        .collect();
    for (i, b) in positions.into_iter().zip(v4.octets()) {
        bytes[i] = b;
    }
    Ipv6Addr::from(bytes)
}

/// The network-specific prefixes of the tests, one per RFC 6052 length,
/// all inside global unicast space.
const NSPS: [(&str, u8); 6] = [
    ("2a00:1234::", 32),
    ("2a00:1234:5600::", 40),
    ("2a00:1234:5678::", 48),
    ("2a00:1234:5678:9a00::", 56),
    ("2a00:1234:5678:9abc::", 64),
    ("2a00:1234:5678:9abc::", 96),
];

#[test]
fn nat64_network_specific_prefix_classifies_the_embedded_ipv4() {
    for (prefix, len) in NSPS {
        let prefixes = [nat64(prefix, len)];
        for bad in [
            "169.254.169.254",
            "10.0.0.5",
            "127.0.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
        ] {
            let ip = IpAddr::V6(embed(prefix, len, bad.parse().expect(bad)));
            assert!(forbidden(ip, &prefixes), "{ip} ({bad} in {prefix}/{len})");
            // Without the prefix the address looks global: this is the
            // hole the prefix list closes (ADR-006, D4).
            assert!(!forbidden(ip, &[]), "{ip} without the prefix");
        }
        for good in ["104.16.0.34", "151.101.0.223", "160.79.104.10", "1.1.1.1"] {
            let ip = IpAddr::V6(embed(prefix, len, good.parse().expect(good)));
            assert!(!forbidden(ip, &prefixes), "{ip} ({good} in {prefix}/{len})");
        }
        // first_forbidden sees through the prefix too.
        let metadata = SocketAddr::new(
            IpAddr::V6(embed(prefix, len, Ipv4Addr::new(169, 254, 169, 254))),
            443,
        );
        let global = sock("[2606:4700::6810:22]:443");
        assert_eq!(
            first_forbidden(&[global, metadata], &prefixes),
            Some(metadata)
        );
    }
}

#[test]
fn nat64_u_octet_and_suffix_must_be_zero() {
    let good = Ipv4Addr::new(104, 16, 0, 34);
    for (prefix, len) in NSPS {
        let prefixes = [nat64(prefix, len)];
        let clean = embed(prefix, len, good);
        assert!(!forbidden(IpAddr::V6(clean), &prefixes), "{clean}");
        let mut bytes = clean.octets();
        if len <= 64 {
            // The u octet (bits 64 to 71) set.
            let mut u = bytes;
            u[8] = 1;
            let ip = IpAddr::V6(Ipv6Addr::from(u));
            assert!(forbidden(ip, &prefixes), "{ip} u octet");
            // The last suffix byte set.
            bytes[15] = 1;
            let ip = IpAddr::V6(Ipv6Addr::from(bytes));
            assert!(forbidden(ip, &prefixes), "{ip} suffix");
        }
    }
    // Outside the prefix, the address is classified as plain IPv6.
    let prefixes = [nat64("2a00:1234:5678:9abc::", 96)];
    assert!(!forbidden(v6("2a00:1234:5678:9abd::a9fe:a9fe"), &prefixes));
}

#[test]
fn nat64_prefixes_only_narrow() {
    // Prefixes outside global space, including the well-known one, never
    // make a forbidden address allowed.
    let prefixes = [
        nat64("64:ff9b::", 96),
        nat64("fc00::", 96),
        nat64("fe80::", 64),
        nat64("2001:db8::", 32),
        nat64("2a00:1234:5678:9abc::", 96),
    ];
    let samples = [
        "64:ff9b::808:808",
        "64:ff9b::a9fe:a9fe",
        "fc00::808:808",
        "fe80::8:808:800:0",
        "2001:db8:808:808::",
        "::1",
        "::ffff:8.8.8.8",
        "2a00:1234:5678:9abc::808:808",
        "2a00:1234:5678:9abc::a00:5",
        "2606:4700::6810:22",
        "2a00:1234:5678:9abc:1::808:808",
    ];
    for s in samples {
        let ip = v6(s);
        if forbidden(ip, &[]) {
            assert!(forbidden(ip, &prefixes), "{s} became allowed");
        }
    }
    // The well-known prefix stays forbidden even for a global IPv4.
    assert!(forbidden(v6("64:ff9b::808:808"), &prefixes));
}

#[test]
fn nat64_prefix_validation() {
    for len in [32, 40, 48, 56, 64, 96] {
        assert!(
            Nat64Prefix::new(v6addr("2a00:1234::"), len).is_some(),
            "/{len}"
        );
    }
    for len in [0, 1, 31, 33, 72, 80, 95, 97, 128, 255] {
        assert!(
            Nat64Prefix::new(v6addr("2a00:1234::"), len).is_none(),
            "/{len}"
        );
    }
    // Bits after the prefix must be zero.
    assert!(Nat64Prefix::new(v6addr("2a00:1234::1"), 32).is_none());
    assert!(Nat64Prefix::new(v6addr("2a00:1234:5678:9abc:1::"), 64).is_none());
    // A /96 must leave the u octet (bits 64 to 71) zero (RFC 6052).
    assert!(Nat64Prefix::new(v6addr("2a00:1234:5678:9abc:100::"), 96).is_none());
    assert!(Nat64Prefix::new(v6addr("2a00:1234:5678:9abc:ff:ffff::"), 96).is_some());
    // The text form is `<prefix>/<len>`, in `Ipv6Addr` display.
    let p = nat64("2a00:1234:5678:9abc::", 96);
    assert_eq!(p.to_string(), "2a00:1234:5678:9abc::/96");
    assert_eq!(Nat64Prefix::parse("2a00:1234:5678:9abc::/96"), Some(p));
    for bad in [
        "2a00:1234:5678:9abc::",
        "2a00:1234:5678:9abc::/",
        "2a00:1234:5678:9abc::/096",
        "2a00:1234:5678:9abc::/+96",
        "2A00:1234:5678:9abc::/96",
        "2a00:1234:5678:9abc:0:0::/96",
        "[2a00:1234:5678:9abc::]/96",
        "2a00:1234:5678:9abc::/96 ",
        "2a00:1234:5678:9abc::/97",
        "10.0.0.0/8",
        "",
    ] {
        assert_eq!(Nat64Prefix::parse(bad), None, "{bad:?}");
    }
}

#[test]
fn nat64_discovery_from_ipv4only_arpa() {
    let wka = [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];
    for (prefix, len) in NSPS {
        for known in wka {
            let answer = [embed(prefix, len, known)];
            assert_eq!(
                Nat64Prefix::discover(&answer),
                [nat64(prefix, len)],
                "{prefix}/{len} via {known}"
            );
        }
    }
    // The well-known prefix, both answers, duplicates removed.
    let wkp = [
        v6addr("64:ff9b::c000:aa"),
        v6addr("64:ff9b::c000:ab"),
        v6addr("64:ff9b::c000:aa"),
    ];
    assert_eq!(Nat64Prefix::discover(&wkp), [nat64("64:ff9b::", 96)]);
    // Two prefixes in one answer are both kept, in canonical order.
    let two = [
        embed("2a00:1234:5678:9abc::", 96, wka[0]),
        embed("2a00:1234::", 32, wka[1]),
    ];
    assert_eq!(
        Nat64Prefix::discover(&two),
        [nat64("2a00:1234::", 32), nat64("2a00:1234:5678:9abc::", 96)]
    );
    // No answer, an answer without a well-known address, and one with the
    // u octet or the suffix set are no NAT64.
    assert_eq!(Nat64Prefix::discover(&[]), []);
    assert_eq!(Nat64Prefix::discover(&[v6addr("2606:4700::6810:22")]), []);
    let mut u = embed("2a00:1234::", 32, wka[0]).octets();
    u[8] = 1;
    let mut suffix = embed("2a00:1234::", 32, wka[0]).octets();
    suffix[15] = 1;
    assert_eq!(
        Nat64Prefix::discover(&[Ipv6Addr::from(u), Ipv6Addr::from(suffix)]),
        []
    );
}
