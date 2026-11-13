//! The allowlist: exact canonical `host:port` pairs, parsed with the
//! CONNECT target grammar (ADR-006, D2).

use boneli_egress::{Allowlist, AllowlistError, Decision, Endpoint};
use boneli_http::{Limits, RequestHead, Target};

fn list(entries: &[&str]) -> Allowlist {
    Allowlist::parse(entries).expect("valid allowlist")
}

fn target(host: &str, port: u16) -> Target {
    Target::Authority {
        host: host.into(),
        port,
    }
}

fn entries(allowlist: &Allowlist) -> Vec<(String, u16)> {
    allowlist
        .entries()
        .map(|e| (e.host().to_owned(), e.port()))
        .collect()
}

#[test]
fn allowlist_rejects_empty() {
    assert_eq!(Allowlist::parse(&[]), Err(AllowlistError::Empty));
}

#[test]
fn single_entry_allows_only_that_pair() {
    let allowlist = list(&["registry.npmjs.org:443"]);
    assert_eq!(
        allowlist.decide(&target("registry.npmjs.org", 443)),
        Decision::Allowed
    );
    for port in [1, 80, 442, 444, 8443, 65535] {
        assert_eq!(
            allowlist.decide(&target("registry.npmjs.org", port)),
            Decision::NotAllowed,
            "port {port}"
        );
    }
    assert_eq!(
        allowlist.decide(&Target::Origin("/".into())),
        Decision::NotAllowed
    );
}

#[test]
fn allowlist_rejects_canonical_duplicates() {
    for pair in [
        ["Registry.NPMJS.org:443", "registry.npmjs.org:443"],
        ["registry.npmjs.org:0443", "registry.npmjs.org:443"],
        ["registry.npmjs.org:443", "registry.npmjs.org:443"],
    ] {
        assert_eq!(
            Allowlist::parse(&pair),
            Err(AllowlistError::Duplicate { entry_index: 1 }),
            "{pair:?}"
        );
    }
    // The index names the later entry, after a valid one.
    assert_eq!(
        Allowlist::parse(&["pypi.org:443", "a.example:443", "PYPI.org:443"]),
        Err(AllowlistError::Duplicate { entry_index: 2 })
    );
    // The same host on another port is not a duplicate.
    assert!(Allowlist::parse(&["pypi.org:443", "pypi.org:8443"]).is_ok());
}

#[test]
fn allowlist_rejects_ip_literals() {
    for entry in [
        "104.16.0.34:443",
        "[2606:4700::6810:22]:443",
        "127.0.0.1:443",
        "[::1]:443",
        "[::ffff:127.0.0.1]:443",
    ] {
        assert_eq!(
            Allowlist::parse(&["registry.npmjs.org:443", entry]),
            Err(AllowlistError::IpLiteral { entry_index: 1 }),
            "{entry}"
        );
    }
}

#[test]
fn allowlist_rejects_entries_outside_the_connect_grammar() {
    for entry in [
        // Ports.
        "registry.npmjs.org",
        "registry.npmjs.org:",
        "registry.npmjs.org:0",
        "registry.npmjs.org:65536",
        "registry.npmjs.org:000443",
        // Host forms.
        "registry.npmjs.org.:443",
        "*.npmjs.org:443",
        "_x.example.org:443",
        "example.123:443",
        "0x7f.1:443",
        "127.1:443",
        "user@registry.npmjs.org:443",
        "registry%2Enpmjs.org:443",
        // Unicode look-alikes and invisible characters.
        "r\u{435}gistry.npmjs.org:443",
        "registry\u{200b}.npmjs.org:443",
        "registry.npmjs.org\u{a0}:443",
        // Whitespace is never trimmed.
        " registry.npmjs.org:443",
        "registry.npmjs.org:443 ",
        "\tregistry.npmjs.org:443",
        "registry.npmjs.org:443\n",
        "registry.npmjs.org:443\r\n",
        "",
    ] {
        assert_eq!(
            Allowlist::parse(&["pypi.org:443", entry]),
            Err(AllowlistError::Invalid { entry_index: 1 }),
            "{entry:?}"
        );
    }
}

#[test]
fn allowlist_entries_are_canonical() {
    let allowlist = list(&["REGISTRY.NPMJS.ORG:0443", "Pypi.Org:443", "a.example:8443"]);
    assert_eq!(
        entries(&allowlist),
        [
            ("a.example".to_owned(), 8443),
            ("pypi.org".to_owned(), 443),
            ("registry.npmjs.org".to_owned(), 443),
        ]
    );
    assert_eq!(
        allowlist
            .entries()
            .map(Endpoint::to_string)
            .collect::<Vec<_>>(),
        ["a.example:8443", "pypi.org:443", "registry.npmjs.org:443"]
    );
}

#[test]
fn entry_and_target_canonicalize_identically() {
    let limits = Limits::new(8192, 32, 1).expect("limits");
    for entry in [
        "registry.npmjs.org:443",
        "REGISTRY.NPMJS.ORG:0443",
        "Registry.Npmjs.Org:00443",
        "files.pythonhosted.org:443",
        "api.anthropic.com:443",
        "a:1",
        "xn--80ak6aa92e.com:65535",
        "a-1.b-2.example:8080",
    ] {
        let allowlist = list(&[entry]);
        let head = format!("CONNECT {entry} HTTP/1.1\r\nHost: {entry}\r\n\r\n");
        let parsed = RequestHead::parse(head.as_bytes(), &limits).expect(entry);
        assert_eq!(
            allowlist.decide(&parsed.target),
            Decision::Allowed,
            "{entry}"
        );
        let stored = allowlist.entries().next().expect("one entry");
        assert_eq!(
            parsed.target,
            target(stored.host(), stored.port()),
            "{entry}"
        );
        assert_eq!(
            Endpoint::from_target(&parsed.target).as_ref(),
            Some(stored),
            "{entry}"
        );
    }
}

#[test]
fn decide_matches_exact_host_and_port_only() {
    let allowlist = list(&["registry.npmjs.org:443"]);
    assert_eq!(
        allowlist.decide(&target("registry.npmjs.org", 443)),
        Decision::Allowed
    );
    for (host, port) in [
        ("registry.npmjs.org", 80),
        ("evil.registry.npmjs.org", 443),
        ("registry.npmjs.org.evil.example", 443),
        ("npmjs.org", 443),
        ("xn--rgistry-n5f.npmjs.org", 443),
        ("104.16.0.34", 443),
        ("2606:4700::6810:22", 443),
        ("registry.npmjs.or", 443),
        ("egistry.npmjs.org", 443),
    ] {
        assert_eq!(
            allowlist.decide(&target(host, port)),
            Decision::NotAllowed,
            "{host}:{port}"
        );
    }
}

#[test]
fn errors_name_the_index_and_never_echo_the_entry() {
    let secret = "s3cr3t-token.attacker.example:443 extra";
    let err = Allowlist::parse(&["pypi.org:443", secret]).expect_err("invalid");
    let text = err.to_string();
    assert!(text.contains('1'), "{text}");
    assert!(!text.contains("s3cr3t"), "{text}");
}
