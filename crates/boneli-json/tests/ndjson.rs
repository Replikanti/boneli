//! Newline-delimited JSON: one value per line, bounded lines, errors that
//! name the line, and no desynchronisation (ADR-008, D8).

mod common;

use std::io::{self, BufRead, BufReader, Read, Write};

use boneli_json::ndjson::{Reader, write_line};
use boneli_json::{ErrorKind, Value, parse};
use common::{Rng, gen_value, harness_limits, limits};

/// Every item of a reader over `input` as `Ok(value)` or `Err((kind, line))`.
fn items(
    input: &[u8],
    capacity: usize,
    max_bytes: usize,
) -> Vec<Result<Value, (ErrorKind, Option<u64>)>> {
    let reader = BufReader::with_capacity(capacity, input);
    Reader::new(reader, limits(max_bytes, 16, 1_024))
        .map(|item| item.map_err(|e| (e.kind(), e.line())))
        .collect()
}

fn num(n: i64) -> Value {
    Value::from(n)
}

#[test]
fn blank_line_is_error_and_reader_continues() {
    assert_eq!(
        items(b"1\n\n2\n \n3\n", 8192, 64),
        [
            Ok(num(1)),
            Err((ErrorKind::UnexpectedEnd, Some(2))),
            Ok(num(2)),
            Err((ErrorKind::UnexpectedEnd, Some(4))),
            Ok(num(3)),
        ]
    );
}

#[test]
fn ndjson_line_limit_inclusive() {
    assert_eq!(
        items(b"[1,2,3]\r\n[1,2,3] \r\n4\n", 8192, 8),
        [
            Ok(Value::Array(vec![num(1), num(2), num(3)])),
            Err((ErrorKind::LineTooLong, Some(2))),
            Ok(num(4)),
        ]
    );
    assert_eq!(
        items(b"[1,2,3] \r\n4\n", 8192, 8),
        [Err((ErrorKind::LineTooLong, Some(1))), Ok(num(4))]
    );
    let lim = limits(8, 16, 1_024);
    let mut reader = Reader::new(BufReader::new(&b"123456789\n"[..]), lim);
    let e = reader.next().expect("an item").expect_err("too long");
    assert_eq!(
        (e.kind(), e.offset(), e.line()),
        (ErrorKind::LineTooLong, 8, Some(1))
    );
    assert!(reader.next().is_none());
}

/// A reader that never ends a line and counts what was read from it.
struct Endless {
    read: usize,
}

impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        buf.fill(b'7');
        self.read += buf.len();
        Ok(buf.len())
    }
}

#[test]
fn over_long_line_reported_before_its_end() {
    for (capacity, max_bytes) in [(16, 100), (8192, 1_000), (1, 10), (100, 100)] {
        let mut endless = Endless { read: 0 };
        {
            let buffered = BufReader::with_capacity(capacity, &mut endless);
            let mut reader = Reader::new(buffered, limits(max_bytes, 4, 4));
            let e = reader.next().expect("an item").expect_err("too long");
            assert_eq!((e.kind(), e.line()), (ErrorKind::LineTooLong, Some(1)));
        }
        assert!(
            endless.read <= max_bytes + capacity,
            "read {} with capacity {capacity}, max_bytes {max_bytes}",
            endless.read
        );
    }
}

#[test]
fn malformed_line_does_not_desync() {
    assert_eq!(
        items(b"{\"a\":\"x\n\"}\n3\n", 8192, 64),
        [
            Err((ErrorKind::UnexpectedEnd, Some(1))),
            Err((ErrorKind::UnexpectedEnd, Some(2))),
            Ok(num(3)),
        ]
    );
    assert_eq!(
        items(b"[1,\n2]\n", 8192, 64),
        [
            Err((ErrorKind::UnexpectedEnd, Some(1))),
            Err((ErrorKind::TrailingData, Some(2)))
        ]
    );
    // An error's offset counts from the start of its line.
    let mut reader = Reader::new(&b"1\n[x]\n"[..], limits(64, 4, 16));
    assert_eq!(reader.next().expect("line 1").expect("1"), num(1));
    let e = reader.next().expect("line 2").expect_err("x");
    assert_eq!(
        (e.kind(), e.offset(), e.line()),
        (ErrorKind::UnexpectedByte, 1, Some(2))
    );
}

#[test]
fn u2028_is_not_a_line_break() {
    let input = "\"a\u{2028}b\u{2029}c\u{85}d\"\n\"\r\"\n";
    let out = items(input.as_bytes(), 8192, 64);
    assert_eq!(out[0], Ok(Value::from("a\u{2028}b\u{2029}c\u{85}d")));
    assert_eq!(out[1], Err((ErrorKind::ControlCharacter, Some(2))));
    assert_eq!(out.len(), 2);
}

#[test]
fn unterminated_tail() {
    assert_eq!(
        items(b"1\n12345", 8192, 64),
        [Ok(num(1)), Err((ErrorKind::UnterminatedLine, Some(2)))]
    );
    assert_eq!(items(b"1\n", 8192, 64), [Ok(num(1))]);
    assert_eq!(
        items(b"1", 8192, 64),
        [Err((ErrorKind::UnterminatedLine, Some(1)))]
    );
    assert_eq!(
        items(b"1\n\r", 8192, 64),
        [Ok(num(1)), Err((ErrorKind::UnterminatedLine, Some(2)))]
    );
    let mut reader = Reader::new(&b"12345"[..], limits(64, 4, 16));
    let e = reader.next().expect("an item").expect_err("unterminated");
    assert_eq!((e.kind(), e.offset()), (ErrorKind::UnterminatedLine, 5));
    assert!(reader.next().is_none());
}

#[test]
fn empty_stream_yields_nothing() {
    assert!(items(b"", 8192, 64).is_empty());
    assert!(items(b"", 1, 1).is_empty());
}

/// A `BufRead` that returns a scripted sequence of reads and errors.
struct Scripted {
    steps: Vec<io::Result<Vec<u8>>>,
    current: Vec<u8>,
    pos: usize,
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.fill_buf()?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Scripted {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.pos == self.current.len() {
            if self.steps.is_empty() {
                return Ok(&[]);
            }
            self.current = self.steps.remove(0)?;
            self.pos = 0;
        }
        Ok(&self.current[self.pos..])
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
    }
}

#[test]
fn io_error_fuses() {
    let steps = vec![
        Ok(b"1\n2".to_vec()),
        Err(io::Error::from(io::ErrorKind::Interrupted)),
        Ok(b"\n3".to_vec()),
        Err(io::Error::other("broken")),
        Ok(b"\n4\n".to_vec()),
    ];
    let scripted = Scripted {
        steps,
        current: Vec::new(),
        pos: 0,
    };
    let mut reader = Reader::new(scripted, limits(64, 4, 16));
    assert_eq!(reader.next().expect("1").expect("1"), num(1));
    assert_eq!(reader.next().expect("2").expect("2"), num(2));
    let e = reader.next().expect("an error").expect_err("I/O");
    assert_eq!((e.kind(), e.line()), (ErrorKind::Io, Some(3)));
    assert!(std::error::Error::source(&e).is_some());
    assert!(reader.next().is_none());
    assert!(reader.next().is_none());
}

#[test]
fn one_byte_buffer_matches_default() {
    let mut input = Vec::new();
    input.extend_from_slice("\"\u{e9}\u{1f600}\u{2028}\"\n".as_bytes());
    input.extend_from_slice(b"\n[1,2]\r\n{\"k\":\"\xc3\"}\n");
    input.extend_from_slice("1".repeat(300).as_bytes());
    input.push(b'\n');
    input.extend_from_slice("{\"\u{10ffff}\":[true,null]}\n\"x".as_bytes());
    let mut rng = Rng::new(7);
    for _ in 0..200 {
        let v = gen_value(&mut rng, 3);
        write_line(&mut input, &v).expect("write");
    }
    let wide = items(&input, 8192, 256);
    let narrow = items(&input, 1, 256);
    assert_eq!(wide, narrow);
    for capacity in [2, 3, 5, 7, 255, 256, 257] {
        assert_eq!(items(&input, capacity, 256), wide, "capacity {capacity}");
    }
    assert!(
        wide.iter()
            .any(|item| matches!(item, Err((ErrorKind::LineTooLong, _))))
    );
    assert!(
        wide.iter()
            .any(|item| matches!(item, Err((ErrorKind::InvalidUtf8, _))))
    );
    assert!(wide.iter().filter(|item| item.is_ok()).count() > 100);
}

/// A `Write` that counts its calls.
#[derive(Default)]
struct Counting {
    out: Vec<u8>,
    write_calls: usize,
    write_all_calls: usize,
}

impl Write for Counting {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_calls += 1;
        self.out.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_all_calls += 1;
        self.out.extend_from_slice(buf);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn write_line_single_newline() {
    let mut rng = Rng::new(0x29);
    for _ in 0..2_000 {
        let v = gen_value(&mut rng, 6);
        let mut sink = Counting::default();
        write_line(&mut sink, &v).expect("write");
        assert_eq!((sink.write_calls, sink.write_all_calls), (0, 1));
        let newlines: Vec<usize> = sink
            .out
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == b'\n')
            .map(|(i, _)| i)
            .collect();
        assert_eq!(newlines, [sink.out.len() - 1]);
        let line = &sink.out[..sink.out.len() - 1];
        assert_eq!(parse(line, &harness_limits()).expect("line parses"), v);
    }
    let too_deep = common::built_arrays(boneli_json::MAX_DEPTH + 1);
    let mut sink = Counting::default();
    let e = write_line(&mut sink, &too_deep).expect_err("too deep");
    assert_eq!(e.kind(), ErrorKind::TooDeep);
    assert!(sink.out.is_empty());
}

#[test]
fn write_read_round_trip() {
    let mut rng = Rng::new(0xbeef);
    let values: Vec<Value> = (0..500).map(|_| gen_value(&mut rng, 5)).collect();
    let mut stream = Vec::new();
    for v in &values {
        write_line(&mut stream, v).expect("write");
    }
    let reader = Reader::new(&stream[..], harness_limits());
    let mut lines = 0;
    for (i, item) in reader.enumerate() {
        assert_eq!(item.expect("line"), values[i]);
        lines += 1;
    }
    assert_eq!(lines, values.len());
    let mut reader = Reader::new(&b"1\n["[..], harness_limits());
    reader.next();
    assert_eq!(
        reader.next().expect("line 2").expect_err("tail").line(),
        Some(2)
    );
}
