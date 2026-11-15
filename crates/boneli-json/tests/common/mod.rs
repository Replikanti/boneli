//! Helpers shared by the integration tests: the vendored JSONTestSuite
//! corpus, limit constructors, a depth and value-count walker, a seeded
//! generator of values and FNV-1a-64.
#![allow(dead_code)]

use std::path::PathBuf;

use boneli_json::{Limits, Number, Object, Value};

/// The limits the conformance tests run with: `max_bytes` above the largest
/// suite file (250,001 bytes), the crate's depth ceiling and a value count
/// no suite file reaches.
pub fn harness_limits() -> Limits {
    limits(1_048_576, boneli_json::MAX_DEPTH, 1_048_576)
}

/// Limits that the caller knows to be valid.
pub fn limits(max_bytes: usize, max_depth: usize, max_values: usize) -> Limits {
    Limits::new(max_bytes, max_depth, max_values).expect("valid limits")
}

/// The vendored `test_parsing` directory.
pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/jsontestsuite/test_parsing")
}

/// Every corpus file as (name, bytes), sorted by name.
pub fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(corpus_dir()).expect("corpus directory") {
        let entry = entry.expect("directory entry");
        let name = entry.file_name().into_string().expect("ASCII file name");
        let bytes = std::fs::read(entry.path()).expect("corpus file");
        files.push((name, bytes));
    }
    files.sort();
    files
}

/// Corpus files whose name starts with `prefix`.
pub fn corpus_with(prefix: &str) -> Vec<(String, Vec<u8>)> {
    corpus()
        .into_iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .collect()
}

/// How deeply a value nests (a scalar is 0, `[]` is 1) and how many values
/// it holds (every value once, keys not counted), without recursion.
pub fn shape(value: &Value) -> (usize, usize) {
    let mut deepest = 0;
    let mut count = 0;
    let mut stack = vec![(value, 0usize)];
    while let Some((v, depth)) = stack.pop() {
        count += 1;
        match v {
            Value::Array(items) => {
                deepest = deepest.max(depth + 1);
                stack.extend(items.iter().map(|item| (item, depth + 1)));
            }
            Value::Object(members) => {
                deepest = deepest.max(depth + 1);
                stack.extend(members.iter().map(|(_, item)| (item, depth + 1)));
            }
            _ => {}
        }
    }
    (deepest, count)
}

/// FNV-1a-64 over `data`, continuing from `hash`.
pub fn fnv1a(mut hash: u64, data: &[u8]) -> u64 {
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The FNV-1a-64 offset basis.
pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// xorshift64*: a small deterministic generator, so that every run sees the
/// same values.
pub struct Rng(u64);

impl Rng {
    /// A generator from a nonzero seed.
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }

    /// The next 64 random bits.
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number in `0..n` (`n` > 0).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Characters the generated strings are drawn from: every C0 control, the
/// characters the serializer treats specially or might be tempted to, line
/// separators, noncharacters, an astral character and combining or
/// invisible characters.
pub fn alphabet() -> Vec<char> {
    let mut chars: Vec<char> = (0u8..0x20).map(char::from).collect();
    chars.extend([
        '"',
        '\\',
        '/',
        '\u{7f}',
        '\u{2028}',
        '\u{2029}',
        '\u{feff}',
        '\u{ffff}',
        '\u{10ffff}',
        '\u{1f600}',
        '\u{301}',
        '\u{200b}',
        'a',
        'b',
        'z',
        ' ',
        'e',
        '0',
    ]);
    chars
}

/// Numbers the generator draws from besides random integers: the integer
/// extremes, the `-0` lexeme and the edge values of `Number::from_f64`.
pub fn special_numbers() -> Vec<Number> {
    let mut numbers = vec![
        Number::from(i64::MIN),
        Number::from(i64::MAX),
        Number::from(u64::MAX),
        Number::from(0u64),
        Number::from_lexeme("-0").expect("-0 is a number"),
        Number::from_lexeme("1e400").expect("1e400 is a number"),
        Number::from_lexeme("123456789012345678901234567890").expect("long integer"),
    ];
    for f in [
        -0.0,
        5e-324,
        f64::MIN_POSITIVE,
        f64::MAX,
        f64::MIN,
        0.1,
        1e21,
        1e-7,
        1.0,
    ] {
        numbers.push(Number::from_f64(f).expect("finite"));
    }
    numbers
}

/// A random string of up to `max_len` characters from `alphabet()`; empty
/// strings are included.
pub fn gen_string(rng: &mut Rng, max_len: usize) -> String {
    let chars = alphabet();
    let len = rng.below(max_len + 1);
    (0..len).map(|_| chars[rng.below(chars.len())]).collect()
}

/// A random value that nests at most `depth` deep with at most 8 children
/// per container.
pub fn gen_value(rng: &mut Rng, depth: usize) -> Value {
    let specials = special_numbers();
    let kinds = if depth == 0 { 5 } else { 7 };
    match rng.below(kinds) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 1),
        2 => {
            if rng.below(2) == 0 {
                Value::Number(specials[rng.below(specials.len())].clone())
            } else {
                Value::from(rng.next() as i64)
            }
        }
        3 | 4 => Value::String(gen_string(rng, 6)),
        5 => {
            let n = rng.below(9);
            Value::Array((0..n).map(|_| gen_value(rng, depth - 1)).collect())
        }
        _ => {
            let n = rng.below(9);
            let mut members = Object::new();
            for _ in 0..n {
                let key = gen_string(rng, 3);
                let value = gen_value(rng, depth - 1);
                members.insert(key, value);
            }
            Value::Object(members)
        }
    }
}

/// `[` repeated `depth` times followed by as many `]`.
pub fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut out = vec![b'['; depth];
    out.extend(std::iter::repeat_n(b']', depth));
    out
}

/// `{"k":` repeated `depth` times, `null`, then as many `}`.
pub fn nested_objects(depth: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..depth {
        out.extend_from_slice(b"{\"k\":");
    }
    out.extend_from_slice(b"null");
    out.extend(std::iter::repeat_n(b'}', depth));
    out
}

/// A built (not parsed) array value nested `depth` deep.
pub fn built_arrays(depth: usize) -> Value {
    let mut v = Value::Array(Vec::new());
    for _ in 1..depth {
        v = Value::Array(vec![v]);
    }
    v
}

/// A built object value nested `depth` deep.
pub fn built_objects(depth: usize) -> Value {
    let mut v = Value::Null;
    for _ in 0..depth {
        let mut o = Object::new();
        o.insert("k", v);
        v = Value::Object(o);
    }
    v
}
