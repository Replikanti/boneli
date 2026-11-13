//! Deterministic hostile-input sweeps over one chunked request (ADR-003
//! uses these in place of a fuzzer).

mod common;

use common::{limits, run_server};

const BODY_LIMIT: u64 = 64;
const HEADERS_LIMIT: usize = 8;

/// A 150-byte chunked request with an extension and a trailer.
fn request() -> Vec<u8> {
    let head = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";
    let chunks = b"a;ext=1\r\n0123456789\r\n5\r\nhello\r\n0\r\n";
    let mut out = head.to_vec();
    out.extend_from_slice(chunks);
    out.extend_from_slice(b"T: ");
    let pad = 150 - out.len() - 4;
    out.extend(std::iter::repeat_n(b'p', pad));
    out.extend_from_slice(b"\r\n\r\n");
    assert_eq!(out.len(), 150);
    out
}

#[test]
fn mutation_sweep_never_panics() {
    let original = request();
    let control = run_server(&original, 4096, limits(128, HEADERS_LIMIT, BODY_LIMIT));
    assert_eq!(control.complete_bodies(), vec![b"0123456789hello".to_vec()]);

    let mut runs = 0;
    for at in 0..original.len() {
        for byte in [0x00u8, 0x0a, 0x0d, 0x20, 0x3a, 0x3b, 0xff] {
            let mut input = original.clone();
            input[at] = byte;
            for piece in [4096, 7] {
                let out = run_server(&input, piece, limits(128, HEADERS_LIMIT, BODY_LIMIT));
                for (head, body) in &out.requests {
                    assert!(head.headers.len() <= HEADERS_LIMIT);
                    if let Ok(body) = body {
                        assert!(body.len() as u64 <= BODY_LIMIT, "byte {byte:#04x} at {at}");
                    }
                }
            }
            runs += 1;
        }
    }
    assert_eq!(runs, 150 * 7);
}

#[test]
fn truncation_sweep() {
    let original = request();
    for len in 0..original.len() {
        for piece in [4096, 1] {
            let out = run_server(
                &original[..len],
                piece,
                limits(128, HEADERS_LIMIT, BODY_LIMIT),
            );
            assert!(
                out.complete_bodies().is_empty(),
                "prefix of {len} bytes completed"
            );
            assert!(
                !out.statuses().contains(&200),
                "prefix of {len} bytes answered 200"
            );
            if len > 0 {
                assert!(out.result.is_err(), "prefix of {len} bytes");
            }
        }
    }
}
