//! Request bodies: limits, chunk lines, trailers, truncation and the body
//! writers (ADR-003).

mod common;

use std::io::{ErrorKind, Write};

use boneli_http::BodyWriter;
use common::{limits, run_server, wide};

/// A POST with `Transfer-Encoding: chunked` and the raw chunked `body`.
fn chunked(body: &[u8]) -> Vec<u8> {
    let mut out = b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    out.extend_from_slice(body);
    out
}

/// A POST with `Content-Length: declared` followed by `body`.
fn with_length(declared: u64, body: &[u8]) -> Vec<u8> {
    let mut out =
        format!("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {declared}\r\n\r\n").into_bytes();
    out.extend_from_slice(body);
    out
}

#[test]
fn body_limit_10_inclusive() {
    let ten = limits(1024, 8, 10);

    let out = run_server(&with_length(10, b"0123456789"), 4096, ten);
    assert_eq!(out.status(), 200);
    assert_eq!(out.complete_bodies(), vec![b"0123456789".to_vec()]);

    let out = run_server(&with_length(11, b"0123456789a"), 4096, ten);
    assert_eq!(out.status(), 413);
    assert!(out.requests.is_empty(), "rejected before the handler runs");

    let out = run_server(
        &chunked(b"4\r\n0123\r\n6\r\n456789\r\n0\r\n\r\n"),
        4096,
        ten,
    );
    assert_eq!(out.status(), 200);
    assert_eq!(out.complete_bodies(), vec![b"0123456789".to_vec()]);

    // 4 + 7: the second size line already exceeds the limit, so the error
    // comes before any of its data is read, and no response has started.
    let out = run_server(
        &chunked(b"4\r\n0123\r\n7\r\n456789a\r\n0\r\n\r\n"),
        4096,
        ten,
    );
    assert_eq!(out.status(), 413);
    assert_eq!(out.requests.len(), 1);
    assert!(out.requests[0].1.is_err());
    assert!(out.text().contains("Connection: close"));
}

#[test]
fn chunk_size_line_forms() {
    for line in [
        &b"a\r\n"[..],
        b"A\r\n",
        b"a;x=1\r\n",
        b"a ;x\r\n",
        b"a\t;x\r\n",
        b"00a\r\n",
    ] {
        let mut body = line.to_vec();
        body.extend_from_slice(b"0123456789\r\n0\r\n\r\n");
        let out = run_server(&chunked(&body), 4096, wide());
        assert_eq!(
            out.complete_bodies(),
            vec![b"0123456789".to_vec()],
            "line {:?}",
            String::from_utf8_lossy(line)
        );
    }

    // 16 hex digits fit a u64 and parse; the size then exceeds the limit.
    let out = run_server(
        &chunked(b"ffffffffffffffff\r\n0123456789\r\n0\r\n\r\n"),
        4096,
        wide(),
    );
    assert_eq!(out.status(), 413);

    for line in [
        &b"0xa\r\n"[..],
        b"+a\r\n",
        b" a\r\n",
        b"a \r\n",
        b"a\n",
        b"a;x\n",
        b"a;x\rz\r\n",
        b"10000000000000000\r\n",
        b"0000000000000000000a\r\n",
        b"\r\n",
        b"g\r\n",
        b"a;x\x00\r\n",
    ] {
        let mut body = line.to_vec();
        body.extend_from_slice(b"0123456789\r\n0\r\n\r\n");
        let out = run_server(&chunked(&body), 4096, wide());
        assert_eq!(
            out.status(),
            400,
            "line {:?}",
            String::from_utf8_lossy(line)
        );
        assert!(out.complete_bodies().is_empty());
    }
}

#[test]
fn chunk_data_overrun_rejected() {
    for body in [
        &b"5\r\nhelloX\r\n0\r\n\r\n"[..],
        b"5\r\nhello\n0\r\n\r\n",
        b"5\r\nhello\r0\r\n\r\n",
        b"5\r\nhello0\r\n\r\n",
    ] {
        let out = run_server(&chunked(body), 4096, wide());
        assert_eq!(
            out.status(),
            400,
            "body {:?}",
            String::from_utf8_lossy(body)
        );
        assert!(out.complete_bodies().is_empty());
    }
}

#[test]
fn trailers_discarded_and_bounded() {
    let small = limits(64, 3, 1024);

    let out = run_server(
        &chunked(b"5\r\nhello\r\n0\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n"),
        4096,
        small,
    );
    assert_eq!(out.status(), 200);
    assert_eq!(out.complete_bodies(), vec![b"hello".to_vec()]);
    assert!(
        out.requests[0].0.headers.get("A").is_none(),
        "trailers are discarded"
    );

    let out = run_server(
        &chunked(b"5\r\nhello\r\n0\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\n"),
        4096,
        small,
    );
    assert_eq!(out.status(), 431);

    // The trailer section "X: <pad>\r\n\r\n" is 7 bytes plus the padding.
    let section = |pad: usize| {
        let mut body = b"5\r\nhello\r\n0\r\nX: ".to_vec();
        body.extend(std::iter::repeat_n(b'a', pad));
        body.extend_from_slice(b"\r\n\r\n");
        chunked(&body)
    };
    assert_eq!(run_server(&section(57), 4096, small).status(), 200);
    assert_eq!(run_server(&section(58), 4096, small).status(), 431);

    for body in [
        &b"5\r\nhello\r\n0\r\nA: 1\n\r\n"[..],
        b"5\r\nhello\r\n0\r\n\n",
        b"5\r\nhello\r\n0\r\nA: 1\r\n\rx",
        b"5\r\nhello\r\n0\r\nnot a field\r\n\r\n",
    ] {
        let out = run_server(&chunked(body), 4096, small);
        assert_eq!(
            out.status(),
            400,
            "body {:?}",
            String::from_utf8_lossy(body)
        );
        assert!(out.complete_bodies().is_empty());
    }
}

#[test]
fn truncated_body_is_error() {
    for input in [
        with_length(10, b"01234"),
        with_length(1, b""),
        chunked(b"5\r\nhel"),
        chunked(b"5\r\nhello\r\n"),
        chunked(b"5\r\nhello\r\n0\r\n"),
        chunked(b"5\r\nhello\r\n0\r\nA: 1\r\n"),
        chunked(b"5\r\nhello"),
    ] {
        let out = run_server(&input, 4096, wide());
        assert_eq!(out.requests.len(), 1);
        assert_eq!(
            out.requests[0].1,
            Err(ErrorKind::UnexpectedEof),
            "input {:?}",
            String::from_utf8_lossy(&input)
        );
        assert!(
            out.statuses().is_empty(),
            "nothing to answer on a closed stream"
        );
    }
}

#[test]
fn chunked_round_trip() {
    for len in [0usize, 1, 8191, 8192, 8193] {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        for piece in [1usize, 7, 8192] {
            let mut encoded = Vec::new();
            let mut writer = BodyWriter::chunked(&mut encoded);
            for part in data.chunks(piece) {
                writer.write_all(part).expect("write");
            }
            writer.finish().expect("finish");
            assert!(encoded.ends_with(b"0\r\n\r\n"));

            let out = run_server(&chunked(&encoded), 4096, wide());
            assert_eq!(
                out.complete_bodies(),
                vec![data.clone()],
                "len {len}, piece {piece}"
            );
        }
    }
}

#[test]
fn chunked_empty_write_is_noop() {
    let mut out = Vec::new();
    let mut writer = BodyWriter::chunked(&mut out);
    assert_eq!(writer.write(&[]).expect("empty write"), 0);
    writer.write_all(b"ab").expect("write");
    assert_eq!(writer.write(&[]).expect("empty write"), 0);
    writer.flush().expect("flush");
    writer.finish().expect("finish");
    assert_eq!(out, b"2\r\nab\r\n0\r\n\r\n");

    let mut out = Vec::new();
    {
        let mut writer = BodyWriter::chunked(&mut out);
        assert_eq!(writer.write(&[]).expect("empty write"), 0);
    }
    assert!(
        out.is_empty(),
        "an empty write emits nothing, not even a terminator"
    );
}

#[test]
fn length_writer_enforces_declared_length() {
    let mut out = Vec::new();
    let mut writer = BodyWriter::length(&mut out, 3);
    writer.write_all(b"ab").expect("write");
    assert!(writer.write_all(b"cd").is_err(), "over the declared length");
    writer.write_all(b"c").expect("write");
    writer.finish().expect("finish");
    assert_eq!(out, b"abc");

    let mut out = Vec::new();
    {
        let mut writer = BodyWriter::length(&mut out, 3);
        let err = writer.write(b"abcd").expect_err("over the declared length");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }
    assert!(out.is_empty(), "nothing of an oversized write is written");

    let mut out = Vec::new();
    let mut writer = BodyWriter::length(&mut out, 3);
    writer.write_all(b"ab").expect("write");
    assert!(writer.finish().is_err(), "a short body is an error");
}
