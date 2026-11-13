//! The connection log codec: one record per line, fixed field order, a
//! closed alphabet and a strict parser (ADR-006, D8).

use std::collections::BTreeSet;
use std::net::SocketAddr;

use boneli_egress::address::Nat64Prefix;

use boneli_egress::log::{End, FailReason, Record, RejectedStatus, parse_log};
use boneli_egress::{Allowlist, Endpoint};

fn endpoint(authority: &str) -> Endpoint {
    Endpoint::parse(authority).expect(authority)
}

fn prefix(s: &str) -> Nat64Prefix {
    Nat64Prefix::parse(s).expect(s)
}

fn sock(s: &str) -> SocketAddr {
    s.parse().expect(s)
}

/// A name of exactly 253 bytes: three labels of 63 bytes and one of 61.
fn longest_host() -> String {
    let label = "a".repeat(63);
    let host = format!("{label}.{label}.{label}.{}", "b".repeat(61));
    assert_eq!(host.len(), 253);
    host
}

/// One record of every kind and every enum value, at the edges of every
/// number.
fn samples() -> Vec<Record> {
    let max = u64::MAX;
    let long = endpoint(&format!("{}:65535", longest_host()));
    let mut out = vec![
        Record::Start {
            t: 0,
            unix_ms: 0,
            allow: Allowlist::parse(&["registry.npmjs.org:443"]).expect("list"),
            nat64: BTreeSet::new(),
        },
        Record::Start {
            t: max,
            unix_ms: max,
            allow: Allowlist::parse(&[
                "registry.npmjs.org:443",
                "pypi.org:443",
                "files.pythonhosted.org:443",
                "pypi.org:1",
            ])
            .expect("list"),
            nat64: [
                prefix("64:ff9b::/96"),
                prefix("2a00:1234::/32"),
                prefix("2a00:1234:5678:9abc::/96"),
                prefix("2a00:1234:5678:9abc::/64"),
            ]
            .into(),
        },
        Record::Allowed {
            t: 0,
            id: 0,
            endpoint: endpoint("registry.npmjs.org:443"),
        },
        Record::Allowed {
            t: max,
            id: max,
            endpoint: long.clone(),
        },
        Record::Allowed {
            t: 1,
            id: 1,
            endpoint: endpoint("a:1"),
        },
        Record::Refused {
            t: 5,
            id: 2,
            endpoint: endpoint("evil.example:443"),
        },
        Record::Refused {
            t: 5,
            id: 3,
            endpoint: endpoint("[2606:4700::6810:22]:443"),
        },
        Record::Refused {
            t: 5,
            id: 4,
            endpoint: endpoint("169.254.169.254:80"),
        },
        Record::Refused {
            t: max,
            id: max,
            endpoint: long,
        },
        Record::Open {
            t: 0,
            id: 0,
            addr: sock("104.16.0.34:443"),
        },
        Record::Open {
            t: max,
            id: max,
            addr: sock("[2606:4700::6810:22]:443"),
        },
        Record::Open {
            t: 1,
            id: 1,
            addr: sock("[::ffff:1.2.3.4]:1"),
        },
        Record::Close {
            t: 0,
            id: 0,
            up: 0,
            down: 0,
            end: End::Eof,
        },
        Record::Close {
            t: max,
            id: max,
            up: max,
            down: max,
            end: End::Idle,
        },
        Record::Close {
            t: 9,
            id: 9,
            up: 517,
            down: 0,
            end: End::Error,
        },
        Record::Method { t: 0, id: 0 },
        Record::Method { t: max, id: max },
        Record::Aborted { t: 0, id: 0 },
        Record::Aborted { t: max, id: max },
        Record::NoRequest { t: 0, id: 0 },
        Record::NoRequest { t: max, id: max },
    ];
    for (i, reason) in [
        FailReason::ForbiddenAddress,
        FailReason::Resolve,
        FailReason::Connect,
        FailReason::ConnectTimeout,
    ]
    .into_iter()
    .enumerate()
    {
        let i = i as u64;
        out.push(Record::Failed {
            t: i,
            id: i,
            reason,
            addr: None,
        });
        out.push(Record::Failed {
            t: max - i,
            id: max - i,
            reason,
            addr: Some(sock("[2606:4700::6810:22]:443")),
        });
        out.push(Record::Failed {
            t: i,
            id: i,
            reason,
            addr: Some(sock("127.0.0.1:65535")),
        });
    }
    for status in [400, 408, 413, 417, 431, 501, 505] {
        let status = RejectedStatus::from_status(status).expect("a rejected status");
        out.push(Record::Rejected {
            t: 0,
            id: 0,
            status,
        });
        out.push(Record::Rejected {
            t: max,
            id: max,
            status,
        });
    }
    out
}

/// `line` without its terminator.
fn body(line: &str) -> &str {
    line.strip_suffix('\n').expect("ends in a newline")
}

#[test]
fn every_record_kind_round_trips() {
    let samples = samples();
    let kinds: std::collections::BTreeSet<&str> = samples
        .iter()
        .map(|r| {
            let line = r.render();
            let kind = line.split(' ').next().expect("a kind");
            match kind {
                "start" => "start",
                "allowed" => "allowed",
                "refused" => "refused",
                "open" => "open",
                "failed" => "failed",
                "close" => "close",
                "method" => "method",
                "rejected" => "rejected",
                "aborted" => "aborted",
                "no-request" => "no-request",
                other => panic!("unknown kind {other}"),
            }
        })
        .collect();
    assert_eq!(kinds.len(), 10, "every kind is sampled: {kinds:?}");
    for record in &samples {
        let line = record.render();
        let parsed = Record::parse(body(&line)).unwrap_or_else(|e| panic!("{line:?}: {e}"));
        assert_eq!(&parsed, record, "{line:?}");
        assert_eq!(parsed.render(), line);
    }
}

#[test]
fn exact_renderings() {
    let start = Record::Start {
        t: 0,
        unix_ms: 1_763_049_600_000,
        allow: Allowlist::parse(&["registry.npmjs.org:443", "PyPI.org:443"]).expect("list"),
        nat64: BTreeSet::new(),
    };
    assert_eq!(
        start.render(),
        "start t=0 v=1 unix_ms=1763049600000 allow=pypi.org:443,registry.npmjs.org:443 nat64=-\n"
    );
    let failed = Record::Failed {
        t: 12,
        id: 3,
        reason: FailReason::ForbiddenAddress,
        addr: Some(sock("[::1]:443")),
    };
    assert_eq!(
        failed.render(),
        "failed t=12 id=3 reason=forbidden-address addr=[::1]:443\n"
    );
    let refused = Record::Refused {
        t: 1,
        id: 2,
        endpoint: endpoint("[2606:4700::6810:22]:443"),
    };
    assert_eq!(
        refused.render(),
        "refused t=1 id=2 host=2606:4700::6810:22 port=443\n"
    );
    let failed = Record::Failed {
        t: 1,
        id: 2,
        reason: FailReason::Resolve,
        addr: None,
    };
    assert_eq!(failed.render(), "failed t=1 id=2 reason=resolve addr=-\n");
    assert_eq!(
        Record::NoRequest { t: 7, id: 8 }.render(),
        "no-request t=7 id=8\n"
    );
}

#[test]
fn render_is_one_line() {
    for record in samples() {
        let line = record.render();
        assert!(line.ends_with('\n'), "{line:?}");
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        assert!(!line.contains('\r'), "{line:?}");
        assert!(!line.contains("  "), "{line:?}");
        assert!(!body(&line).ends_with(' '), "{line:?}");
        assert!(line.is_ascii(), "{line:?}");
        // Every field after the kind is one `key=value` with one `=`.
        for field in body(&line).split(' ').skip(1) {
            assert_eq!(field.matches('=').count(), 1, "{line:?}");
        }
    }
}

#[test]
fn parse_rejects_noncanonical_numbers() {
    for line in [
        "method t=01 id=1",
        "method t=+1 id=1",
        "method t=-1 id=1",
        "method t=18446744073709551616 id=1",
        "method t= id=1",
        "method t=1_0 id=1",
        "method t=0x1 id=1",
        "method t=1\u{661} id=1",
        "method t=1 id=00",
        "allowed t=1 id=1 host=a port=0",
        "allowed t=1 id=1 host=a port=65536",
        "allowed t=1 id=1 host=a port=0443",
        "close t=1 id=1 up=01 down=0 end=eof",
        "close t=1 id=1 up=0 down=+0 end=eof",
        "start t=0 v=01 unix_ms=0 allow=a:443 nat64=-",
        "rejected t=1 id=1 status=0400",
        "start t=0 v=1 unix_ms=0 allow=a:0443 nat64=-",
        "open t=1 id=1 addr=104.16.0.034:443",
        "open t=1 id=1 addr=104.16.0.34:0443",
        "open t=1 id=1 addr=[2606:4700:0::6810:22]:443",
        "open t=1 id=1 addr=[2606:4700::6810:0022]:443",
        "open t=1 id=1 addr=[2606:4700::6810:22%0]:443",
    ] {
        assert!(Record::parse(line).is_err(), "{line:?}");
    }
}

#[test]
fn parse_rejects_malformed_lines() {
    let good = [
        "start t=0 v=1 unix_ms=5 allow=pypi.org:443,registry.npmjs.org:443 nat64=-",
        "allowed t=1 id=1 host=registry.npmjs.org port=443",
        "refused t=1 id=1 host=2606:4700::6810:22 port=443",
        "open t=1 id=1 addr=[2606:4700::6810:22]:443",
        "failed t=1 id=1 reason=connect-timeout addr=104.16.0.34:443",
        "failed t=1 id=1 reason=resolve addr=-",
        "close t=1 id=1 up=5 down=6 end=idle",
        "method t=1 id=1",
        "rejected t=1 id=1 status=431",
        "aborted t=1 id=1",
        "no-request t=1 id=1",
        // The grammar lowercases an IPv6 host but keeps its spelling
        // (ADR-003), so the log records the target as the sandbox wrote it.
        "refused t=1 id=1 host=2606:4700:0::1 port=443",
    ];
    for line in good {
        assert!(Record::parse(line).is_ok(), "{line:?}");
    }
    for line in [
        // Kinds.
        "",
        "unknown t=1 id=1",
        "Method t=1 id=1",
        "no_request t=1 id=1",
        // Missing, extra, repeated and reordered fields.
        "method t=1",
        "method id=1 t=1",
        "method t=1 id=1 x=1",
        "method t=1 id=1 id=1",
        "method t=1 t=1 id=1",
        "allowed t=1 id=1 port=443 host=a",
        "close t=1 id=1 down=6 up=5 end=idle",
        "failed t=1 id=1 reason=resolve",
        "start t=0 unix_ms=5 v=1 allow=a:443 nat64=-",
        "start t=0 v=1 unix_ms=5 nat64=-",
        // Versions.
        "start t=0 v=2 unix_ms=5 allow=a:443 nat64=-",
        "start t=0 v=0 unix_ms=5 allow=a:443 nat64=-",
        // Spacing and line ends.
        "method  t=1 id=1",
        "method t=1  id=1",
        "method t=1 id=1 ",
        " method t=1 id=1",
        "method t=1 id=1\r",
        "method t=1 id=1\r\n",
        "method t=1 id=1\n",
        "method\tt=1 id=1",
        "method t=1\nmethod t=2 id=1",
        // Keys and values.
        "method t=1 id",
        "method t=1 id=",
        "method t=1 =1",
        "method t=1 id==1",
        "method t=1 id=1=1",
        "method T=1 id=1",
        // Enum words.
        "close t=1 id=1 up=5 down=6 end=EOF",
        "close t=1 id=1 up=5 down=6 end=timeout",
        "failed t=1 id=1 reason=forbidden addr=-",
        "failed t=1 id=1 reason=resolve addr=",
        "failed t=1 id=1 reason=resolve addr=--",
        "rejected t=1 id=1 status=403",
        "rejected t=1 id=1 status=200",
        "rejected t=1 id=1 status=500",
        // Hosts must pass the CONNECT grammar and be canonical.
        "allowed t=1 id=1 host=Registry.npmjs.org port=443",
        "allowed t=1 id=1 host=registry.npmjs.org. port=443",
        "allowed t=1 id=1 host=*.npmjs.org port=443",
        "allowed t=1 id=1 host=127.1 port=443",
        "allowed t=1 id=1 host=[::1] port=443",
        "allowed t=1 id=1 host=2606:4700::ABCD port=443",
        "allowed t=1 id=1 host=r\u{435}gistry.npmjs.org port=443",
        "allowed t=1 id=1 host= port=443",
        // Addresses.
        "open t=1 id=1 addr=-",
        "open t=1 id=1 addr=104.16.0.34",
        "open t=1 id=1 addr=2606:4700::6810:22:443",
        "open t=1 id=1 addr=registry.npmjs.org:443",
        // The allow list: canonical, sorted, unique, names only.
        "start t=0 v=1 unix_ms=5 allow= nat64=-",
        "start t=0 v=1 unix_ms=5 allow=registry.npmjs.org:443,pypi.org:443 nat64=-",
        "start t=0 v=1 unix_ms=5 allow=pypi.org:443,pypi.org:443 nat64=-",
        "start t=0 v=1 unix_ms=5 allow=PyPI.org:443 nat64=-",
        "start t=0 v=1 unix_ms=5 allow=pypi.org:443, nat64=-",
        "start t=0 v=1 unix_ms=5 allow=,pypi.org:443 nat64=-",
        "start t=0 v=1 unix_ms=5 allow=pypi.org:443;a:1 nat64=-",
        "start t=0 v=1 unix_ms=5 allow=1.2.3.4:443 nat64=-",
        "start t=0 v=1 unix_ms=5 allow=[::1]:443 nat64=-",
        "start t=0 v=1 unix_ms=5 allow=pypi.org nat64=-",
        // Ports sort numerically, not as text.
        "start t=0 v=1 unix_ms=5 allow=a:10,a:9 nat64=-",
    ] {
        assert!(Record::parse(line).is_err(), "{line:?}");
    }
    assert!(Record::parse("start t=0 v=1 unix_ms=5 allow=a:9,a:10 nat64=-").is_ok());
}

#[test]
fn same_millisecond_records_keep_write_order() {
    let records = vec![
        Record::Allowed {
            t: 7,
            id: 2,
            endpoint: endpoint("pypi.org:443"),
        },
        Record::Allowed {
            t: 7,
            id: 1,
            endpoint: endpoint("registry.npmjs.org:443"),
        },
        Record::Open {
            t: 7,
            id: 2,
            addr: sock("151.101.0.223:443"),
        },
        Record::Refused {
            t: 7,
            id: 3,
            endpoint: endpoint("github.com:443"),
        },
        Record::Failed {
            t: 7,
            id: 1,
            reason: FailReason::Connect,
            addr: Some(sock("104.16.0.34:443")),
        },
    ];
    let text: String = records.iter().map(Record::render).collect();
    assert_eq!(parse_log(&text).expect("a log"), records);
    assert_eq!(parse_log("").expect("an empty log"), []);
}

#[test]
fn parse_log_names_the_bad_line() {
    let good = Record::Method { t: 1, id: 1 }.render();
    // A last line without its newline was cut off mid-write.
    let cut = format!("{good}method t=2 id=2");
    assert_eq!(parse_log(&cut).expect_err("cut").line(), 2);
    let bad = format!("{good}{good}method t=02 id=3\n{good}");
    assert_eq!(parse_log(&bad).expect_err("bad").line(), 3);
    assert_eq!(parse_log("\n").expect_err("empty line").line(), 1);
}

#[test]
fn terminal_records_are_the_seven_of_adr_006() {
    let terminal: Vec<bool> = [
        Record::Start {
            t: 0,
            unix_ms: 0,
            allow: Allowlist::parse(&["a:1"]).expect("list"),
            nat64: BTreeSet::new(),
        },
        Record::Allowed {
            t: 0,
            id: 1,
            endpoint: endpoint("a:1"),
        },
        Record::Open {
            t: 0,
            id: 1,
            addr: sock("104.16.0.34:443"),
        },
        Record::Refused {
            t: 0,
            id: 1,
            endpoint: endpoint("a:1"),
        },
        Record::Failed {
            t: 0,
            id: 1,
            reason: FailReason::Resolve,
            addr: None,
        },
        Record::Close {
            t: 0,
            id: 1,
            up: 0,
            down: 0,
            end: End::Eof,
        },
        Record::Method { t: 0, id: 1 },
        Record::Rejected {
            t: 0,
            id: 1,
            status: RejectedStatus::from_status(400).expect("400"),
        },
        Record::Aborted { t: 0, id: 1 },
        Record::NoRequest { t: 0, id: 1 },
    ]
    .iter()
    .map(Record::is_terminal)
    .collect();
    assert_eq!(
        terminal,
        [
            false, false, false, true, true, true, true, true, true, true
        ]
    );
    for status in [0, 200, 403, 404, 405, 500, 502, 504, 999, u16::MAX] {
        assert!(RejectedStatus::from_status(status).is_none(), "{status}");
    }
}

/// The review's forgery: a hand-built target with a line break in its host
/// would render as two records. No `Endpoint`, and so no record, can be
/// built from it.
#[test]
fn hand_built_targets_cannot_forge_records() {
    let forged = boneli_http::Target::Authority {
        host: "x.example port=1\nallowed t=0 id=99 host=evil.example".into(),
        port: 443,
    };
    assert_eq!(Endpoint::from_target(&forged), None);
    let zero = boneli_http::Target::Authority {
        host: "x.example".into(),
        port: 0,
    };
    assert_eq!(Endpoint::from_target(&zero), None);
    // What can be built renders a line the parser takes back.
    let ok = boneli_http::Target::Authority {
        host: "x.example".into(),
        port: 443,
    };
    let endpoint = Endpoint::from_target(&ok).expect("canonical");
    let line = Record::Refused {
        t: 1,
        id: 1,
        endpoint,
    }
    .render();
    assert_eq!(parse_log(&line).expect("one record").len(), 1);
}

/// The `start` record names the NAT64 prefixes the address check used
/// (ADR-006, D4), `-` for none, in canonical order.
#[test]
fn start_records_the_nat64_prefixes() {
    let start = Record::Start {
        t: 0,
        unix_ms: 5,
        allow: Allowlist::parse(&["a:1"]).expect("list"),
        nat64: [prefix("2a00:1234:5678:9abc::/96"), prefix("2a00:1234::/32")].into(),
    };
    assert_eq!(
        start.render(),
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234::/32,2a00:1234:5678:9abc::/96\n"
    );
    assert_eq!(
        Record::parse(
            "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234::/32,2a00:1234:5678:9abc::/96"
        ),
        Ok(start)
    );
    for line in [
        "start t=0 v=1 unix_ms=5 allow=a:1",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=-,-",
        "start t=0 v=1 unix_ms=5 nat64=- allow=a:1",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234:5678:9abc::/96,2a00:1234::/32",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234::/32,2a00:1234::/32",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234::/32,-",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234::/33",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234::1/32",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2A00:1234::/32",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234:0::/32",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234::/032",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=2a00:1234::",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=10.0.0.0/8",
        "start t=0 v=1 unix_ms=5 allow=a:1 nat64=- x=1",
    ] {
        assert!(Record::parse(line).is_err(), "{line:?}");
    }
}
