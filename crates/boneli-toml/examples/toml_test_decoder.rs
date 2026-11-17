//! A decoder for the toml-test protocol: TOML on stdin, the tagged JSON
//! of its value on stdout, or the error on stderr and exit code 1. It runs
//! the upstream toml-test harness or a differential against another parser
//! over the same files (ADR-011, D9). The tagged JSON conversion repeats the
//! one in `tests/common`, because examples cannot share test modules.
//!
//! ```sh
//! cargo run -q -p boneli-toml --example toml_test_decoder < file.toml
//! ```

use std::io::{Read, Write};
use std::process::ExitCode;

use boneli_toml::{Limits, MAX_DEPTH, Table, Value, parse};

/// 64 MiB: far above any configuration file; the limit exists because
/// `parse` has no default.
const MAX_BYTES: usize = 64 << 20;

fn tagged(table: &Table) -> boneli_json::Value {
    let mut o = boneli_json::Object::new();
    for (k, v) in table {
        o.insert(k, tagged_value(v));
    }
    boneli_json::Value::Object(o)
}

fn tagged_value(value: &Value) -> boneli_json::Value {
    let leaf = |ty: &str, v: String| {
        let mut o = boneli_json::Object::new();
        o.insert("type", ty);
        o.insert("value", v);
        boneli_json::Value::Object(o)
    };
    match value {
        Value::String(s) => leaf("string", s.clone()),
        Value::Integer(i) => leaf("integer", i.to_string()),
        Value::Boolean(b) => leaf("bool", b.to_string()),
        Value::Array(items) => boneli_json::Value::Array(items.iter().map(tagged_value).collect()),
        Value::Table(t) => tagged(t),
    }
}

fn main() -> ExitCode {
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut input)
    {
        eprintln!("toml_test_decoder: reading stdin: {e}");
        return ExitCode::FAILURE;
    }
    let limits = match Limits::new(MAX_BYTES, MAX_DEPTH) {
        Ok(limits) => limits,
        Err(e) => {
            eprintln!("toml_test_decoder: {e}");
            return ExitCode::FAILURE;
        }
    };
    let table = match parse(&input, &limits) {
        Ok(table) => table,
        Err(e) => {
            eprintln!("toml_test_decoder: {e}");
            return ExitCode::FAILURE;
        }
    };
    match boneli_json::to_string(&tagged(&table)) {
        Ok(json) => {
            let mut out = std::io::stdout().lock();
            if writeln!(out, "{json}").is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("toml_test_decoder: {e}");
            ExitCode::FAILURE
        }
    }
}
