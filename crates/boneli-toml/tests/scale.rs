//! Key lookup is not quadratic: a table of m keys costs O(log m) per
//! lookup, so 2^18 keys need about 2^18 * 18 comparisons where a scan
//! would need about 2^35, 3.4e10 (ADR-011, D11). 30 s is a bound a
//! quadratic check cannot meet even at 1 ns per comparison.

mod common;

use std::time::{Duration, Instant};

use boneli_toml::{Value, parse};
use common::{harness_limits, lookup};

const BOUND: Duration = Duration::from_secs(30);

fn timed(what: &str, input: &str) -> boneli_toml::Table {
    let started = Instant::now();
    let t = parse(input.as_bytes(), &harness_limits()).expect(what);
    let took = started.elapsed();
    assert!(took < BOUND, "{what}: {took:?}");
    eprintln!("{what}: {} bytes in {took:?}", input.len());
    t
}

#[test]
fn many_keys_not_quadratic() {
    let n = 1 << 18;
    let input: String = (0..n).map(|i| format!("k{i} = {i}\n")).collect();
    let t = timed("2^18 keys", &input);
    assert_eq!(t.len(), n);
    assert_eq!(t.get("k262143"), Some(&Value::Integer(262_143)));
    let input: String = (0..n).map(|i| format!("a.k{i} = 0\n")).collect();
    let t = timed("2^18 dotted keys", &input);
    assert_eq!(
        t.get("a").and_then(Value::as_table).map(|a| a.len()),
        Some(n)
    );
    let mut input = String::from("a = {");
    for i in 0..n {
        if i > 0 {
            input.push_str(", ");
        }
        input.push_str(&format!("k{i} = 0"));
    }
    input.push('}');
    let t = timed("2^18 inline keys", &input);
    assert_eq!(
        t.get("a").and_then(Value::as_table).map(|a| a.len()),
        Some(n)
    );
    // The duplicate is found after the whole table was read.
    input.truncate(input.len() - 1);
    input.push_str(", k0 = 1}");
    assert!(parse(input.as_bytes(), &harness_limits()).is_err());
}

#[test]
fn many_tables_not_quadratic() {
    let n = 1 << 16;
    let input = "[[a]]\nx = 1\n".repeat(n);
    let t = timed("2^16 [[a]]", &input);
    assert_eq!(
        t.get("a").and_then(Value::as_array).map(<[Value]>::len),
        Some(n)
    );
    let input: String = (0..n).map(|i| format!("[t{i}]\nx = 1\n")).collect();
    let t = timed("2^16 [tN]", &input);
    assert_eq!(t.len(), n);
    let input: String = (0..n).map(|i| format!("[s.t{i}]\n[s.t{i}.u]\n")).collect();
    let t = timed("2^16 [s.tN.u]", &input);
    assert!(lookup(&t, &["s", "t65535", "u"]).is_some());
}
