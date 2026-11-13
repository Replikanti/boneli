//! Request heads as the server reads them, and head round trips (ADR-003).

mod common;

use std::cell::RefCell;

use boneli_http::{Error, Exchange, Headers, Method, RequestHead, ResponseHead, Target};
use common::{MemStream, limits, run_server, server_limits, wide};

/// `GET / HTTP/1.1` with `Host: a` and an `X` field padded so that the head
/// is exactly `len` bytes long (32 bytes without padding).
fn head_of_len(len: usize) -> Vec<u8> {
    assert!(len >= 32);
    let mut head = b"GET / HTTP/1.1\r\nHost: a\r\nX: ".to_vec();
    head.extend(std::iter::repeat_n(b'a', len - 32));
    head.extend_from_slice(b"\r\n\r\n");
    assert_eq!(head.len(), len);
    head
}

/// One request built from its lines, each ended with CRLF, plus the empty
/// line and `body`.
fn request(lines: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// Asserts that `input` is rejected with `status` before the handler runs.
fn assert_rejected(input: &[u8], status: u16) {
    let out = run_server(input, 4096, wide());
    assert_eq!(
        out.status(),
        status,
        "input {:?}",
        String::from_utf8_lossy(input)
    );
    assert!(
        out.requests.is_empty(),
        "the handler ran for {:?}",
        String::from_utf8_lossy(input)
    );
    assert!(out.result.is_err());
}

/// The single head the handler saw for `input`.
fn accepted(input: &[u8]) -> RequestHead {
    let out = run_server(input, 4096, wide());
    assert_eq!(out.requests.len(), 1, "output {:?}", out.text());
    out.requests[0].0.clone()
}

#[test]
fn head_limit_inclusive_64_ok_65_rejected() {
    let ok = run_server(&head_of_len(64), 4096, limits(64, 8, 10));
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.requests.len(), 1);

    let over = run_server(&head_of_len(65), 4096, limits(64, 8, 10));
    assert_eq!(over.status(), 431);
    assert!(over.requests.is_empty());
    assert!(over.text().contains("Connection: close"));
}

#[test]
fn header_count_limit_3_ok_4_rejected() {
    let three = request(&["GET / HTTP/1.1", "Host: a", "A: 1", "B: 2"], b"");
    let ok = run_server(&three, 4096, limits(1024, 3, 10));
    assert_eq!(ok.status(), 200);

    let four = request(&["GET / HTTP/1.1", "Host: a", "A: 1", "B: 2", "C: 3"], b"");
    let over = run_server(&four, 4096, limits(1024, 3, 10));
    assert_eq!(over.status(), 431);
    assert!(over.requests.is_empty());
}

#[test]
fn head_split_at_every_offset_parses_identically() {
    let input = request(
        &[
            "POST /a/b?c=d HTTP/1.1",
            "Host: example.test",
            "X-Dup: 1",
            "x-dup: 2",
            "Content-Length: 3",
        ],
        b"abc",
    );
    let whole = run_server(&input, input.len(), wide());
    assert_eq!(whole.requests.len(), 1);
    for at in 1..input.len() {
        let (stream, output) = MemStream::from_pieces(common::split_at(&input, &[at]));
        let split = common::run_server_on(stream, output, wide());
        assert_eq!(split.requests.len(), 1, "split at {at}");
        assert_eq!(split.requests[0].0, whole.requests[0].0, "split at {at}");
        assert_eq!(split.requests[0].1, whole.requests[0].1, "split at {at}");
    }
    // One byte per read as well.
    let bytewise = run_server(&input, 1, wide());
    assert_eq!(bytewise.requests[0].0, whole.requests[0].0);
}

#[test]
fn bare_lf_in_head_rejected() {
    for input in [
        &b"GET / HTTP/1.1\nHost: a\r\n\r\n"[..],
        b"GET / HTTP/1.1\r\nHost: a\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\n\n",
        b"GET / HTTP/1.1\r\nHost: a\n\n",
        b"\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n",
    ] {
        assert_rejected(input, 400);
    }
}

#[test]
fn leading_empty_line_counts_toward_limit() {
    let mut ok = b"\r\n".to_vec();
    ok.extend(head_of_len(62));
    let out = run_server(&ok, 4096, limits(64, 8, 10));
    assert_eq!(out.status(), 200);
    assert_eq!(out.requests.len(), 1);

    let mut over = b"\r\n".to_vec();
    over.extend(head_of_len(63));
    let out = run_server(&over, 4096, limits(64, 8, 10));
    assert_eq!(out.status(), 431);
}

#[test]
fn version_other_than_1_1_rejected() {
    assert_rejected(&request(&["GET / HTTP/1.0", "Host: a"], b""), 505);
    assert_rejected(&request(&["GET / HTTP/2.0", "Host: a"], b""), 400);
    assert_rejected(&request(&["GET / HTTP/1.2", "Host: a"], b""), 400);
}

#[test]
fn absolute_and_asterisk_form_rejected() {
    assert_rejected(&request(&["GET http://x/ HTTP/1.1", "Host: x"], b""), 400);
    assert_rejected(&request(&["OPTIONS * HTTP/1.1", "Host: x"], b""), 400);
    assert_rejected(&request(&["GET x/y HTTP/1.1", "Host: x"], b""), 400);
}

#[test]
fn connect_requires_exact_method_and_authority_form() {
    let host = "Host: example.com:443";
    assert_rejected(
        &request(&["connect example.com:443 HTTP/1.1", host], b""),
        400,
    );
    assert_rejected(
        &request(&["Connect example.com:443 HTTP/1.1", host], b""),
        400,
    );
    assert_rejected(&request(&["CONNECT /path HTTP/1.1", host], b""), 400);
    assert_rejected(&request(&["GET example.com:443 HTTP/1.1", host], b""), 400);

    let head = accepted(&request(&["CONNECT example.com:443 HTTP/1.1", host], b""));
    assert!(head.method.is_connect());
    assert_eq!(
        head.target,
        Target::Authority {
            host: "example.com".into(),
            port: 443
        }
    );
}

#[test]
fn non_ascii_target_rejected() {
    // Cyrillic a (U+0430) in place of the Latin one; httparse accepts it.
    assert_rejected(
        &request(
            &[
                "CONNECT \u{430}pi.example.com:443 HTTP/1.1",
                "Host: \u{430}pi.example.com:443",
            ],
            b"",
        ),
        400,
    );
    assert_rejected(&request(&["GET /caf\u{e9} HTTP/1.1", "Host: x"], b""), 400);
}

#[test]
fn connect_authority_forms() {
    // `Host` names the target, so that only the target decides.
    let connect = |authority: &str| {
        request(
            &[
                &format!("CONNECT {authority} HTTP/1.1"),
                &format!("Host: {authority}"),
            ],
            b"",
        )
    };
    let authority = |host: &str, port| Target::Authority {
        host: host.into(),
        port,
    };

    assert_eq!(
        accepted(&connect("Example.COM:443")).target,
        authority("example.com", 443)
    );
    assert_eq!(
        accepted(&connect("[::1]:8443")).target,
        authority("::1", 8443)
    );
    assert_eq!(accepted(&connect("h:65535")).target, authority("h", 65535));
    assert_eq!(
        accepted(&connect("10.0.0.1:1")).target,
        authority("10.0.0.1", 1)
    );

    for bad in [
        "h:65536",
        "h:0",
        "h",
        "h:",
        "h:+443",
        "h:0x1bb",
        "u@h:443",
        "h%2e:443",
        "::1:443",
        ":443",
        "[]:443",
        "[::1]",
        "[::1]x:443",
        "[fe80::1%25eth0]:443",
        "h:443:1",
        "h:4430000",
    ] {
        assert_rejected(&connect(bad), 400);
    }
}

/// Hosts that getaddrinfo (inet_aton) resolves as IPv4 addresses although
/// `Ipv4Addr::from_str` rejects them: the last label "ends in a number"
/// (WHATWG URL), so they are neither a canonical address nor a name.
const NUMERIC_HOSTS: [&str; 10] = [
    "0xa9fea9fe",
    "2130706433",
    "127.1",
    "0177.0.0.1",
    "10.1",
    "1.0x1",
    "0x",
    "0X7F.1",
    "1.2.3.4.5",
    "example.123",
];

/// A CONNECT to `authority` whose `Host` names the same authority.
fn connect_to(authority: &str) -> Vec<u8> {
    request(
        &[
            &format!("CONNECT {authority} HTTP/1.1"),
            &format!("Host: {authority}"),
        ],
        b"",
    )
}

#[test]
fn connect_numeric_hosts_rejected() {
    for host in NUMERIC_HOSTS {
        assert_rejected(&connect_to(&format!("{host}:80")), 400);
    }
    // Names whose last label is not a number, and canonical addresses, pass.
    for (host, want) in [
        ("1.2.3.4", "1.2.3.4"),
        ("0xg.example", "0xg.example"),
        ("123abc", "123abc"),
        ("a-1.Example", "a-1.example"),
        ("example.com1", "example.com1"),
    ] {
        let head = accepted(&connect_to(&format!("{host}:80")));
        assert_eq!(
            head.target,
            Target::Authority {
                host: want.into(),
                port: 80
            }
        );
    }
}

#[test]
fn host_value_validated() {
    for value in [
        "",
        "a b",
        "a/b",
        "u@h",
        "h:0",
        "h:x",
        "h:",
        "[::1",
        "::1",
        "a_b",
        "-a",
        "a..b",
        "a.",
        "\u{430}pi",
        "%61",
    ]
    .into_iter()
    .chain(NUMERIC_HOSTS)
    {
        assert_rejected(
            &request(&["GET / HTTP/1.1", &format!("Host: {value}")], b""),
            400,
        );
    }
    for value in [
        "a",
        "example.com",
        "Example.COM:8080",
        "[::1]",
        "[::1]:80",
        "10.0.0.1",
        "10.0.0.1:80",
    ] {
        accepted(&request(
            &["GET / HTTP/1.1", &format!("Host: {value}")],
            b"",
        ));
    }
}

#[test]
fn connect_host_must_match_target() {
    let connect = |host: &str| {
        request(
            &[
                "CONNECT allowed.example:443 HTTP/1.1",
                &format!("Host: {host}"),
            ],
            b"",
        )
    };
    // A different host, or a different explicit port, is refused; so is
    // a different host without a port.
    for host in [
        "169.254.169.254:80",
        "169.254.169.254",
        "allowed.example:444",
        "allowed.example:80",
        "other.example:443",
        "other.example",
        "[::1]:443",
        "[::1]",
    ] {
        assert_rejected(&connect(host), 400);
    }
    // The same host, with the target's port or without a port.
    for host in ["ALLOWED.example:443", "allowed.example", "Allowed.Example"] {
        let head = accepted(&connect(host));
        assert_eq!(
            head.target,
            Target::Authority {
                host: "allowed.example".into(),
                port: 443
            },
            "Host: {host}"
        );
    }
    for host in ["[::1]:443", "[::1]"] {
        let head = accepted(&request(
            &["CONNECT [::1]:443 HTTP/1.1", &format!("Host: {host}")],
            b"",
        ));
        assert_eq!(
            head.target,
            Target::Authority {
                host: "::1".into(),
                port: 443
            },
            "Host: {host}"
        );
    }
}

/// The CONNECT that undici 7.19.2 `ProxyAgent` sends (Node `fetch` through
/// a proxy), byte for byte: `Host` carries no port.
const UNDICI_CONNECT: &[u8] = b"CONNECT api.example.com:443 HTTP/1.1\r\nhost: api.example.com\r\nconnection: close\r\nproxy-connection: keep-alive\r\n\r\n";

#[test]
fn connect_undici_host_without_port_accepted() {
    let want = Target::Authority {
        host: "api.example.com".into(),
        port: 443,
    };
    let head = RequestHead::parse(UNDICI_CONNECT, &wide()).expect("undici CONNECT");
    assert_eq!(head.target, want);
    assert_eq!(accepted(UNDICI_CONNECT).target, want);
}

#[test]
fn connect_host_with_port_accepted() {
    // The form https-proxy-agent sends: `Host` repeats the target's port.
    let input = b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nProxy-Connection: close\r\n\r\n";
    let head = RequestHead::parse(input, &wide()).expect("CONNECT with port");
    assert_eq!(
        head.target,
        Target::Authority {
            host: "api.example.com".into(),
            port: 443
        }
    );
    // The undici bytes with any other port in `Host` stay refused.
    let other = b"CONNECT api.example.com:443 HTTP/1.1\r\nhost: api.example.com:8443\r\nconnection: close\r\nproxy-connection: keep-alive\r\n\r\n";
    assert!(matches!(
        RequestHead::parse(other, &wide()),
        Err(Error::Malformed(_))
    ));
    assert_rejected(other, 400);
}

#[test]
fn host_missing_or_duplicate_rejected() {
    assert_rejected(&request(&["GET / HTTP/1.1"], b""), 400);
    assert_rejected(
        &request(&["GET / HTTP/1.1", "Host: a", "Host: a"], b""),
        400,
    );
    assert_rejected(
        &request(&["GET / HTTP/1.1", "Host: a", "host: b"], b""),
        400,
    );
}

#[test]
fn content_length_forms() {
    for value in ["5", " 5", "5\t", "05"] {
        let input = request(
            &[
                "POST / HTTP/1.1",
                "Host: a",
                &format!("Content-Length:{value}"),
            ],
            b"hello",
        );
        let out = run_server(&input, 4096, wide());
        assert_eq!(out.status(), 200, "value {value:?}");
        assert_eq!(
            out.complete_bodies(),
            vec![b"hello".to_vec()],
            "value {value:?}"
        );
    }
    for value in [
        "+5",
        "-1",
        "5,5",
        "",
        "5\u{a0}",
        "\u{665}",
        "5 5",
        "0x5",
        "18446744073709551616",
    ] {
        let input = request(
            &[
                "POST / HTTP/1.1",
                "Host: a",
                &format!("Content-Length: {value}"),
            ],
            b"hello",
        );
        assert_rejected(&input, 400);
    }
    assert_rejected(
        &request(
            &[
                "POST / HTTP/1.1",
                "Host: a",
                "Content-Length: 5",
                "Content-Length: 5",
            ],
            b"hello",
        ),
        400,
    );

    // u64::MAX against a 10-byte limit: 413, and no body byte is read.
    let input = request(
        &[
            "POST / HTTP/1.1",
            "Host: a",
            "Content-Length: 18446744073709551615",
        ],
        b"hello",
    );
    let out = run_server(&input, 4096, limits(1024, 8, 10));
    assert_eq!(out.status(), 413);
    assert!(out.requests.is_empty());
}

#[test]
fn framing_headers_case_insensitive() {
    let out = run_server(
        &request(
            &["POST / HTTP/1.1", "Host: a", "content-length: 5"],
            b"hello",
        ),
        4096,
        wide(),
    );
    assert_eq!(out.complete_bodies(), vec![b"hello".to_vec()]);

    let out = run_server(
        &request(
            &["POST / HTTP/1.1", "Host: a", "transfer-ENCODING: chunked"],
            b"5\r\nhello\r\n0\r\n\r\n",
        ),
        4096,
        wide(),
    );
    assert_eq!(out.complete_bodies(), vec![b"hello".to_vec()]);

    assert_rejected(
        &request(
            &[
                "POST / HTTP/1.1",
                "Host: a",
                "CONTENT-LENGTH: 5",
                "transfer-ENCODING: chunked",
            ],
            b"5\r\nhello\r\n0\r\n\r\n",
        ),
        400,
    );
}

#[test]
fn content_length_with_transfer_encoding_rejected() {
    // A smuggled second request after the body is never answered: the
    // connection closes after the 400.
    let mut input = request(
        &[
            "POST / HTTP/1.1",
            "Host: a",
            "Content-Length: 5",
            "Transfer-Encoding: chunked",
        ],
        b"0\r\n\r\n",
    );
    input.extend(request(&["GET /smuggled HTTP/1.1", "Host: a"], b""));
    let out = run_server(&input, 4096, wide());
    assert_eq!(out.statuses(), vec![400]);
    assert!(out.requests.is_empty());
    assert!(out.text().contains("Connection: close"));
}

#[test]
fn transfer_encoding_forms() {
    for value in ["chunked", "Chunked", "chunked\t", "CHUNKED"] {
        let input = request(
            &[
                "POST / HTTP/1.1",
                "Host: a",
                &format!("Transfer-Encoding: {value}"),
            ],
            b"5\r\nhello\r\n0\r\n\r\n",
        );
        let out = run_server(&input, 4096, wide());
        assert_eq!(
            out.complete_bodies(),
            vec![b"hello".to_vec()],
            "value {value:?}"
        );
    }
    for value in [
        "gzip, chunked",
        "chunked, chunked",
        "identity",
        "chunked;q=1",
        "\u{200b}chunked",
        "chunked\u{a0}",
        "",
    ] {
        let input = request(
            &[
                "POST / HTTP/1.1",
                "Host: a",
                &format!("Transfer-Encoding: {value}"),
            ],
            b"5\r\nhello\r\n0\r\n\r\n",
        );
        assert_rejected(&input, 501);
    }
    assert_rejected(
        &request(
            &[
                "POST / HTTP/1.1",
                "Host: a",
                "Transfer-Encoding: chunked",
                "Transfer-Encoding: chunked",
            ],
            b"5\r\nhello\r\n0\r\n\r\n",
        ),
        400,
    );
}

#[test]
fn httparse_rejections_map_to_400() {
    for input in [
        &b"GET / HTTP/1.1\r\nHost: a\r\nX: a\r\n b\r\n\r\n"[..],
        b"GET / HTTP/1.1\r\nHost: a\r\nX : a\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: a\x0bb\r\n\r\n",
        b"G(T / HTTP/1.1\r\nHost: a\r\n\r\n",
        b"GET  / HTTP/1.1\r\nHost: a\r\n\r\n",
    ] {
        assert_rejected(input, 400);
    }
}

#[test]
fn expect_continue_and_417() {
    let input = request(
        &[
            "POST / HTTP/1.1",
            "Host: a",
            "Expect: 100-CONTINUE",
            "Content-Length: 5",
        ],
        b"hello",
    );
    let (stream, output) = MemStream::new(&input, 4096);
    let seen_at_entry = RefCell::new(Vec::new());
    let limits = server_limits(wide());
    let result =
        boneli_http::serve_connection(stream, &limits, &|mut ex: Exchange<'_, MemStream>| {
            seen_at_entry
                .borrow_mut()
                .extend_from_slice(&output.borrow());
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut ex.body(), &mut body)?;
            assert_eq!(body, b"hello");
            ex.respond(200, &Headers::new(), b"")
        });
    result.expect("served");
    assert_eq!(seen_at_entry.into_inner(), b"HTTP/1.1 100 Continue\r\n\r\n");
    assert_eq!(common::statuses(&output.borrow()), vec![100, 200]);

    assert_rejected(
        &request(
            &[
                "POST / HTTP/1.1",
                "Host: a",
                "Expect: foo",
                "Content-Length: 5",
            ],
            b"hello",
        ),
        417,
    );
}

#[test]
fn connect_with_body_framing_rejected() {
    let line = "CONNECT example.com:443 HTTP/1.1";
    assert_rejected(&request(&[line, "Host: x", "Content-Length: 0"], b""), 400);
    assert_rejected(
        &request(
            &[line, "Host: x", "Transfer-Encoding: chunked"],
            b"0\r\n\r\n",
        ),
        400,
    );
}

#[test]
fn request_head_round_trip() {
    let headers = |host: &str| {
        let mut headers = Headers::new();
        headers.append("Host", host);
        headers.append("X-Dup", "1");
        headers.append("x-dup", "2");
        headers.append("Accept", "*/*");
        headers
    };
    let heads = [
        RequestHead {
            method: Method::new("POST").expect("method"),
            target: Target::Origin("/a/b?c=d&e=%20".into()),
            headers: headers("example.test"),
        },
        RequestHead {
            method: Method::new("CONNECT").expect("method"),
            target: Target::Authority {
                host: "::1".into(),
                port: 8443,
            },
            headers: headers("[::1]:8443"),
        },
    ];
    for head in heads {
        let bytes = head.encode().expect("encodes");
        let parsed = RequestHead::parse(&bytes, &wide()).expect("parses");
        assert_eq!(parsed, head);
        assert_eq!(
            parsed.headers.get_all("x-dup").collect::<Vec<_>>(),
            vec![&b"1"[..], b"2"]
        );
    }
}

#[test]
fn response_head_round_trip() {
    let mut headers = Headers::new();
    headers.append("Set-Cookie", "a=1");
    headers.append("set-cookie", "b=2");
    headers.append("Content-Type", "text/plain");
    let head = ResponseHead {
        status: 404,
        reason: "Not Found".into(),
        headers,
    };
    let bytes = head.encode().expect("encodes");
    assert!(bytes.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
    let parsed = ResponseHead::parse(&bytes, &wide()).expect("parses");
    assert_eq!(parsed, head);

    // A head with trailing bytes or without its end is not one head.
    let mut longer = bytes.clone();
    longer.push(b'x');
    assert!(matches!(
        ResponseHead::parse(&longer, &wide()),
        Err(Error::Malformed(_))
    ));
    assert!(ResponseHead::parse(&bytes[..bytes.len() - 1], &wide()).is_err());
}
