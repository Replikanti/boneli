//! Helpers shared by the integration tests: the vendored toml-test corpus,
//! limit constructors, a depth walker, the tagged JSON of toml-test,
//! FNV-1a-64, a seeded generator of values and a test-only TOML writer
//! with several syntactic forms per value (ADR-011, D9 and D10). The crate
//! has no public serializer; the writer exists to round-trip values.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use boneli_toml::{Error, ErrorKind, Limits, MAX_DEPTH, Table, Value, parse};

/// The limits the conformance tests run with: `max_bytes` far above the
/// largest corpus or workspace file (both are a few KiB) and the crate's
/// depth ceiling.
pub fn harness_limits() -> Limits {
    limits(1 << 24, MAX_DEPTH)
}

/// Limits that the caller knows to be valid.
pub fn limits(max_bytes: usize, max_depth: usize) -> Limits {
    Limits::new(max_bytes, max_depth).expect("valid limits")
}

/// Parses `input` under the harness limits.
pub fn ok(input: &str) -> Table {
    match parse(input.as_bytes(), &harness_limits()) {
        Ok(t) => t,
        Err(e) => panic!("{input:?}: {e}"),
    }
}

/// The error of `input` under the harness limits.
pub fn err(input: &str) -> Error {
    match parse(input.as_bytes(), &harness_limits()) {
        Ok(t) => panic!("{input:?} parsed: {t:?}"),
        Err(e) => e,
    }
}

/// The kind and offset of the error of `input` under the harness limits.
pub fn kind_at(input: &str) -> (ErrorKind, usize) {
    let e = err(input);
    (e.kind(), e.offset())
}

/// The value at `path` below `table`.
pub fn lookup<'a>(table: &'a Table, path: &[&str]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    let mut v = table.get(first)?;
    for key in rest {
        v = v.as_table()?.get(key)?;
    }
    Some(v)
}

/// How deeply a table nests: the table itself is 1, and every table or
/// array below it adds 1 (ADR-011, D6). Without recursion.
pub fn depth(table: &Table) -> usize {
    let mut deepest = 1;
    let mut stack: Vec<(&Value, usize)> = table.iter().map(|(_, v)| (v, 2)).collect();
    while let Some((v, d)) = stack.pop() {
        match v {
            Value::Array(items) => {
                deepest = deepest.max(d);
                stack.extend(items.iter().map(|item| (item, d + 1)));
            }
            Value::Table(t) => {
                deepest = deepest.max(d);
                stack.extend(t.iter().map(|(_, item)| (item, d + 1)));
            }
            _ => {}
        }
    }
    deepest
}

/// The vendored toml-test directory.
pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/toml-test")
}

/// The names upstream's `files-toml-1.0.0` lists, in its order.
pub fn listed_files() -> Vec<String> {
    let list = std::fs::read_to_string(corpus_dir().join("files-toml-1.0.0")).expect("file list");
    list.lines().map(str::to_owned).collect()
}

/// Every listed `.toml` file as (name, bytes), sorted by name.
pub fn corpus_toml() -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = listed_files()
        .into_iter()
        .filter(|name| name.ends_with(".toml"))
        .map(|name| {
            let bytes = std::fs::read(corpus_dir().join(&name)).expect("corpus file");
            (name, bytes)
        })
        .collect();
    files.sort();
    files
}

/// Relative paths of every file below `dir`, without following symlinks.
pub fn files_below(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("directory") {
            let entry = entry.expect("directory entry");
            let kind = entry.file_type().expect("file type");
            if kind.is_dir() {
                stack.push(entry.path());
            } else {
                let rel = entry.path().strip_prefix(dir).expect("below").to_owned();
                out.push(rel.to_str().expect("UTF-8 path").to_owned());
            }
        }
    }
    out.sort();
    out
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

/// The tagged JSON of toml-test for a table: every scalar becomes
/// `{"type": ..., "value": ...}` with the value as a string.
pub fn tagged(table: &Table) -> boneli_json::Value {
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

/// Tagged JSON equality as toml-test defines it: objects compare without
/// order, and integer leaves compare as numbers.
pub fn tagged_eq(a: &boneli_json::Value, b: &boneli_json::Value) -> bool {
    use boneli_json::Value as J;
    match (a, b) {
        (J::Object(x), J::Object(y)) => {
            if let (Some(i), Some(j)) = (integer_leaf(x), integer_leaf(y)) {
                return i == j;
            }
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| tagged_eq(v, w)))
        }
        (J::Array(x), J::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(v, w)| tagged_eq(v, w))
        }
        _ => a == b,
    }
}

fn integer_leaf(o: &boneli_json::Object) -> Option<i64> {
    if o.len() != 2 || o.get("type")?.as_str()? != "integer" {
        return None;
    }
    o.get("value")?.as_str()?.parse().ok()
}

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

/// Characters of generated strings: every C0 control, DEL, quotes and
/// backslashes (for quote runs and escapes), CR and LF (for CRLF), comment
/// and key syntax, non-ASCII, zero-width and look-alike characters.
pub fn string_alphabet() -> Vec<char> {
    let mut chars: Vec<char> = (0u8..0x20).map(char::from).collect();
    chars.extend([
        '\u{7f}',
        '"',
        '"',
        '"',
        '\'',
        '\'',
        '\'',
        '\\',
        '\r',
        '\n',
        '#',
        '=',
        '.',
        '[',
        ']',
        '{',
        '}',
        ',',
        ' ',
        'a',
        'z',
        '0',
        '\u{e9}',
        '\u{301}',
        '\u{200b}',
        '\u{feff}',
        '\u{131}',
        '\u{435}',
        '\u{ff41}',
        '\u{1f600}',
        '\u{10ffff}',
        '\u{80}',
    ]);
    chars
}

/// Characters of generated keys: bare-key characters, and everything that
/// forces quoting.
pub fn key_alphabet() -> Vec<char> {
    vec![
        'a', 'b', 'Z', '0', '9', '_', '-', '.', ' ', '\t', '#', '=', '"', '\'', '\\', '\n', '\r',
        '\u{0}', '\u{1f}', '\u{7f}', '\u{e9}', '\u{301}', '\u{200b}', '\u{131}', '\u{435}',
        '\u{ff41}', '[', ']',
    ]
}

/// A random string of up to `max_len` characters from `alphabet`.
pub fn gen_text(rng: &mut Rng, alphabet: &[char], max_len: usize) -> String {
    let len = rng.below(max_len + 1);
    (0..len)
        .map(|_| alphabet[rng.below(alphabet.len())])
        .collect()
}

/// Integers the generator draws from besides random ones.
pub const SPECIAL_INTEGERS: [i64; 8] = [i64::MIN, i64::MAX, 0, -1, 1, 999, 1000, -1000];

/// A random scalar.
pub fn gen_scalar(rng: &mut Rng) -> Value {
    match rng.below(4) {
        0 => Value::Boolean(rng.below(2) == 1),
        1 => {
            if rng.below(2) == 0 {
                Value::Integer(SPECIAL_INTEGERS[rng.below(SPECIAL_INTEGERS.len())])
            } else {
                Value::Integer(rng.next() as i64 >> rng.below(64))
            }
        }
        _ => Value::String(gen_text(rng, &string_alphabet(), 8)),
    }
}

/// A random value whose containers nest at most `levels` deep below it
/// (a scalar uses none, `[]` one), with at most 4 children per container.
pub fn gen_value(rng: &mut Rng, levels: usize) -> Value {
    if levels == 0 || rng.below(3) == 0 {
        return gen_scalar(rng);
    }
    match rng.below(3) {
        0 => {
            let n = rng.below(4);
            Value::Array((0..n).map(|_| gen_value(rng, levels - 1)).collect())
        }
        1 => {
            // An array of tables, which the header layout writes as
            // `[[...]]`.
            let n = 1 + rng.below(2);
            Value::Array(
                (0..n)
                    .map(|_| Value::Table(gen_table(rng, levels - 1)))
                    .collect(),
            )
        }
        _ => Value::Table(gen_table(rng, levels - 1)),
    }
}

/// A random table whose members nest at most `levels` deep below it.
pub fn gen_table(rng: &mut Rng, levels: usize) -> Table {
    let mut t = Table::new();
    for _ in 0..rng.below(5) {
        let key = gen_text(rng, &key_alphabet(), 4);
        let value = gen_value(rng, levels);
        t.insert(key, value);
    }
    t
}

/// Tables holding a chain of one container route each, `MAX_DEPTH` deep
/// counting the root: tables, arrays, arrays and tables alternating (an
/// array of tables in the header layout), and the same with siblings.
pub fn deepest_tables() -> Vec<Table> {
    let table = |members: Vec<(String, Value)>| Value::Table(members.into_iter().collect());
    let routes: [&dyn Fn(Value, usize) -> Value; 4] = [
        &|v, _| table(vec![("k".to_owned(), v)]),
        &|v, _| Value::Array(vec![v]),
        &|v, level| {
            if level.is_multiple_of(2) {
                table(vec![("k".to_owned(), v)])
            } else {
                Value::Array(vec![v])
            }
        },
        &|v, level| {
            if level.is_multiple_of(2) {
                table(vec![
                    ("x y".to_owned(), Value::Integer(level as i64)),
                    ("k".to_owned(), v),
                ])
            } else {
                Value::Array(vec![v, Value::Integer(1)])
            }
        },
    ];
    routes
        .iter()
        .map(|wrap| {
            // The root is depth 1, so MAX_DEPTH - 1 containers go below it.
            let mut v = Value::Integer(7);
            for level in 0..MAX_DEPTH - 1 {
                v = wrap(v, level);
            }
            let mut root = Table::new();
            root.insert("k", v);
            root
        })
        .collect()
}

/// How the writer lays out tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// `k = {..}` and `k = [..]` only.
    Inline,
    /// `a.b.c = v` for every non-empty table, inline tables included.
    Dotted,
    /// `[a.b]` sections and `[[a]]` arrays of tables where the order of
    /// members allows them, dotted keys elsewhere.
    Headers,
}

/// The string form the writer prefers; a form that cannot hold a string
/// falls back to a basic string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strings {
    /// `"..."` with raw non-ASCII.
    Basic,
    /// `"..."` with every non-ASCII character as `\u` or `\U`.
    Escaped,
    /// `'...'`.
    Literal,
    /// `"""..."""` with raw newlines and quote runs.
    MultiBasic,
    /// `'''...'''`.
    MultiLiteral,
}

/// One syntactic form of a document.
#[derive(Clone, Copy, Debug)]
pub struct Style {
    /// Table layout.
    pub layout: Layout,
    /// Preferred string form.
    pub strings: Strings,
    /// Quote every key, literal where possible.
    pub quote_keys: bool,
    /// Integers: 0 plain, 1 with `+` on non-negative ones, 2 with `_`
    /// between groups of three digits.
    pub integers: u8,
    /// Arrays over several lines, with comments and a trailing comma.
    pub multiline_arrays: bool,
    /// CRLF instead of LF between lines.
    pub crlf: bool,
}

/// The styles every round trip is written in: each layout with each
/// string form, and the other switches spread over them.
pub fn styles() -> Vec<Style> {
    let mut out = Vec::new();
    let strings = [
        Strings::Basic,
        Strings::Escaped,
        Strings::Literal,
        Strings::MultiBasic,
        Strings::MultiLiteral,
    ];
    let mut n = 0u8;
    for layout in [Layout::Inline, Layout::Dotted, Layout::Headers] {
        for s in strings {
            out.push(Style {
                layout,
                strings: s,
                quote_keys: !n.is_multiple_of(2),
                integers: n % 3,
                multiline_arrays: n % 4 >= 2,
                crlf: n % 5 == 4,
            });
            n += 1;
        }
    }
    out
}

/// `table` as a TOML document in `style`.
pub fn write(table: &Table, style: Style) -> String {
    let mut w = Writer {
        out: String::new(),
        style,
    };
    match style.layout {
        Layout::Headers => w.section(&mut Vec::new(), table),
        _ => {
            for (k, v) in table {
                w.member(&[], k, v);
            }
        }
    }
    w.out
}

struct Writer {
    out: String,
    style: Style,
}

fn is_bare(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_control(c: char) -> bool {
    (c < ' ' && c != '\t') || c == '\u{7f}'
}

/// Whether the header layout can write `v` as a `[section]` or as
/// `[[sections]]`.
fn is_section(v: &Value) -> bool {
    matches!(v, Value::Table(_)) || is_array_of_tables(v)
}

fn is_array_of_tables(v: &Value) -> bool {
    matches!(v, Value::Array(items) if !items.is_empty() && items.iter().all(|i| matches!(i, Value::Table(_))))
}

impl Writer {
    fn newline(&mut self) {
        self.out
            .push_str(if self.style.crlf { "\r\n" } else { "\n" });
    }

    fn key(&mut self, key: &str) {
        if is_bare(key) && !self.style.quote_keys {
            self.out.push_str(key);
        } else if self.style.quote_keys && !key.contains('\'') && !key.chars().any(is_control) {
            self.out.push('\'');
            self.out.push_str(key);
            self.out.push('\'');
        } else {
            self.basic(key, false);
        }
    }

    fn path(&mut self, path: &[String]) {
        for (i, k) in path.iter().enumerate() {
            if i > 0 {
                self.out
                    .push_str(if i.is_multiple_of(2) { "." } else { " . " });
            }
            self.key(k);
        }
    }

    fn basic(&mut self, s: &str, escape_non_ascii: bool) {
        self.out.push('"');
        for c in s.chars() {
            self.escaped_char(c, escape_non_ascii);
        }
        self.out.push('"');
    }

    fn escaped_char(&mut self, c: char, escape_non_ascii: bool) {
        match c {
            '"' => self.out.push_str("\\\""),
            '\\' => self.out.push_str("\\\\"),
            '\n' => self.out.push_str("\\n"),
            '\r' => self.out.push_str("\\r"),
            '\t' => self.out.push_str("\\t"),
            '\u{8}' => self.out.push_str("\\b"),
            '\u{c}' => self.out.push_str("\\f"),
            c if is_control(c) => self.out.push_str(&format!("\\u{:04X}", c as u32)),
            c if escape_non_ascii && !c.is_ascii() => {
                if (c as u32) > 0xffff {
                    self.out.push_str(&format!("\\U{:08x}", c as u32));
                } else {
                    self.out.push_str(&format!("\\u{:04x}", c as u32));
                }
            }
            c => self.out.push(c),
        }
    }

    fn string(&mut self, s: &str) {
        let literal_ok = !s.contains('\'') && !s.chars().any(is_control);
        let multi_literal_ok = !s.contains("'''") && !s.chars().any(|c| is_control(c) && c != '\n');
        match self.style.strings {
            Strings::Basic => self.basic(s, false),
            Strings::Escaped => self.basic(s, true),
            Strings::Literal if literal_ok => {
                self.out.push('\'');
                self.out.push_str(s);
                self.out.push('\'');
            }
            Strings::MultiLiteral if multi_literal_ok => {
                // The newline after the delimiter is trimmed, so a string
                // that starts with one keeps it.
                self.out.push_str("'''\n");
                self.out.push_str(s);
                self.out.push_str("'''");
            }
            Strings::MultiBasic => {
                self.out.push_str("\"\"\"\n");
                let mut quotes = 0;
                for c in s.chars() {
                    match c {
                        '"' if quotes < 2 => {
                            self.out.push('"');
                            quotes += 1;
                            continue;
                        }
                        '\n' => self.out.push('\n'),
                        c => self.escaped_char(c, false),
                    }
                    quotes = 0;
                }
                self.out.push_str("\"\"\"");
            }
            _ => self.basic(s, false),
        }
    }

    fn integer(&mut self, i: i64) {
        let digits = i.unsigned_abs().to_string();
        if i < 0 {
            self.out.push('-');
        } else if self.style.integers == 1 {
            self.out.push('+');
        }
        if self.style.integers == 2 {
            for (n, c) in digits.chars().enumerate() {
                if n > 0 && (digits.len() - n).is_multiple_of(3) {
                    self.out.push('_');
                }
                self.out.push(c);
            }
        } else {
            self.out.push_str(&digits);
        }
    }

    fn inline(&mut self, v: &Value) {
        match v {
            Value::String(s) => self.string(s),
            Value::Integer(i) => self.integer(*i),
            Value::Boolean(b) => self.out.push_str(if *b { "true" } else { "false" }),
            Value::Array(items) => {
                self.out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if self.style.multiline_arrays {
                        self.out.push_str(" # item");
                        self.newline();
                        self.out.push_str("  ");
                    } else if i > 0 {
                        self.out.push(' ');
                    }
                    self.inline(item);
                    if i + 1 < items.len() || self.style.multiline_arrays {
                        self.out.push(',');
                    }
                }
                if self.style.multiline_arrays {
                    self.newline();
                }
                self.out.push(']');
            }
            Value::Table(t) => {
                self.out.push('{');
                let mut first = true;
                for (k, item) in t {
                    let mut path = vec![k.to_owned()];
                    self.inline_member(&mut path, item, &mut first);
                }
                self.out.push_str(if first { "}" } else { " }" });
            }
        }
    }

    /// A member of an inline table, dotted in the dotted layout.
    fn inline_member(&mut self, path: &mut Vec<String>, v: &Value, first: &mut bool) {
        if self.style.layout == Layout::Dotted
            && let Value::Table(t) = v
            && !t.is_empty()
        {
            for (k, item) in t {
                path.push(k.to_owned());
                self.inline_member(path, item, first);
                path.pop();
            }
            return;
        }
        self.out.push_str(if *first { " " } else { ", " });
        *first = false;
        self.path(path);
        self.out.push_str(" = ");
        self.inline(v);
    }

    /// `key = v` below `prefix`, dotted outside the inline layout.
    fn member(&mut self, prefix: &[String], key: &str, v: &Value) {
        let mut path = prefix.to_vec();
        path.push(key.to_owned());
        if self.style.layout != Layout::Inline
            && let Value::Table(t) = v
            && !t.is_empty()
        {
            for (k, item) in t {
                self.member(&path, k, item);
            }
            return;
        }
        self.path(&path);
        self.out.push_str(" = ");
        self.inline(v);
        self.newline();
    }

    /// The body of the table at `path`, whose header is written: members
    /// up to the trailing run of tables and arrays of tables as key-value
    /// pairs, that run as sections.
    fn section(&mut self, path: &mut Vec<String>, table: &Table) {
        let members: Vec<(&str, &Value)> = table.iter().collect();
        let mut k = members.len();
        while k > 0 && is_section(members[k - 1].1) {
            k -= 1;
        }
        for (key, v) in &members[..k] {
            self.member(&[], key, v);
        }
        for (key, v) in &members[k..] {
            path.push((*key).to_owned());
            match v {
                Value::Table(t) => {
                    self.out.push('[');
                    self.path(path);
                    self.out.push(']');
                    self.newline();
                    self.section(path, t);
                }
                Value::Array(items) => {
                    for item in items {
                        if let Value::Table(t) = item {
                            self.out.push_str("[[");
                            self.path(path);
                            self.out.push_str("]]");
                            self.newline();
                            self.section(path, t);
                        }
                    }
                }
                _ => {}
            }
            path.pop();
        }
    }
}

/// Writes `table` in every style, parses each document back and checks
/// that it equals `table`.
pub fn assert_round_trips(table: &Table, what: &str) {
    for style in styles() {
        let text = write(table, style);
        match parse(text.as_bytes(), &harness_limits()) {
            Ok(back) => assert!(
                back == *table,
                "{what}: {style:?} changed the value\n{text}\n{back:?}\n{table:?}"
            ),
            Err(e) => panic!("{what}: {style:?} does not parse: {e}\n{text}"),
        }
    }
}
