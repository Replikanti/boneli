//! Source scans: comment blanking, the leading attribute block, a lenient
//! Rust lexer and hand-written matchers for the token rules (ADR-001;
//! matching without regex in ADR-015, D5).
//!
//! Every matcher has the semantics of a leftmost, non-overlapping search:
//! the same matches with the same text as the reference checker's regular
//! expressions, so that messages and their deduplication agree.

use crate::text::{Lines, is_ascii_word, is_ident_start, is_pws, is_space, is_word};

/// Blanks whole-line `//` comments (doc comments included) and keeps the
/// newlines. A comment line that contains `*/` or a double quote stays
/// code: it may close a block comment or a string opened on an earlier
/// line, and what follows is then real code. Everything else (block
/// comments, strings) is scanned as code.
pub(crate) fn blank_comment_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let stripped = line.trim_start_matches(is_pws);
        let comment =
            stripped.starts_with("//") && !stripped.contains("*/") && !stripped.contains('"');
        if !comment {
            out.push_str(line);
        }
    }
    out
}

/// Whether `chars[i..]` starts with `pat`.
fn starts(chars: &[char], i: usize, pat: &str) -> bool {
    pat.chars()
        .enumerate()
        .all(|(k, p)| chars.get(i + k) == Some(&p))
}

/// The index of the `]` that matches the `[` at `start`, skipping string
/// literals.
fn closing_bracket(chars: &[char], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = start;
    let n = chars.len();
    while i < n {
        match chars[i] {
            '"' => {
                i += 1;
                while i < n && chars[i] != '"' {
                    i += if chars[i] == '\\' { 2 } else { 1 };
                }
            }
            '[' => depth += 1,
            ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The index of the `[` when an inner attribute (`#`, `!`, `[` with Rust
/// whitespace between them) starts at `i`.
fn inner_attr_start(chars: &[char], i: usize) -> Option<usize> {
    if chars.get(i) != Some(&'#') {
        return None;
    }
    let mut j = i + 1;
    while chars.get(j).is_some_and(|&c| is_pws(c)) {
        j += 1;
    }
    if chars.get(j) != Some(&'!') {
        return None;
    }
    j += 1;
    while chars.get(j).is_some_and(|&c| is_pws(c)) {
        j += 1;
    }
    (chars.get(j) == Some(&'[')).then_some(j)
}

/// The inner attributes of the leading block, whitespace removed. The
/// block is the file start, skipping blank and `//` lines, then `#![...]`
/// attributes, which may span several lines. Anything else ends it.
pub(crate) fn leading_attributes(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut attrs = Vec::new();
    let mut i = 0;
    while i < n {
        if is_pws(chars[i]) {
            i += 1;
            continue;
        }
        if starts(&chars, i, "//") {
            i = chars[i..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(n, |j| i + j + 1);
            continue;
        }
        let Some(open) = inner_attr_start(&chars, i) else {
            break;
        };
        let Some(close) = closing_bracket(&chars, open) else {
            break;
        };
        attrs.push(chars[i..=close].iter().filter(|&&c| !is_pws(c)).collect());
        i = close + 1;
    }
    attrs
}

/// What a token is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A string literal of any form; `value` is its body as written.
    Str,
    /// A character or number literal.
    Lit,
    /// A lifetime or label.
    Lifetime,
    /// An identifier, without its `r#` prefix.
    Ident,
    /// Any other single character.
    Punct,
}

/// A token of the lenient lexer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) kind: Kind,
    pub(crate) value: String,
    /// For a string: whether it is raw (its escapes are not decoded).
    pub(crate) raw: bool,
    pub(crate) line: usize,
}

impl Token {
    fn is_punct(&self, c: char) -> bool {
        self.kind == Kind::Punct && self.value.chars().eq(std::iter::once(c))
    }

    fn is_ident(&self, name: &str) -> bool {
        self.kind == Kind::Ident && self.value == name
    }
}

fn is_hex(c: Option<&char>) -> bool {
    c.is_some_and(char::is_ascii_hexdigit)
}

/// The length of the run of hex digits and `_` at `chars[i..]`, counted
/// up to 9 (the escapes take at most 8).
fn hex_run(chars: &[char], i: usize) -> usize {
    chars[i.min(chars.len())..]
        .iter()
        .take(9)
        .take_while(|c| c.is_ascii_hexdigit() || **c == '_')
        .count()
}

/// The end of a character literal at `i`.
fn char_literal(chars: &[char], i: usize) -> Option<usize> {
    let j = if chars.get(i) == Some(&'b') && chars.get(i + 1) == Some(&'\'') {
        i + 1
    } else if chars.get(i) == Some(&'\'') {
        i
    } else {
        return None;
    };
    let k = j + 1;
    let quote_at = |p: usize| (chars.get(p) == Some(&'\'')).then_some(p + 1);
    match chars.get(k) {
        Some('\\') => {
            if chars.get(k + 1) == Some(&'x')
                && is_hex(chars.get(k + 2))
                && is_hex(chars.get(k + 3))
                && let Some(end) = quote_at(k + 4)
            {
                return Some(end);
            }
            if chars.get(k + 1) == Some(&'u') && chars.get(k + 2) == Some(&'{') {
                let r = hex_run(chars, k + 3);
                if (1..=8).contains(&r)
                    && chars.get(k + 3 + r) == Some(&'}')
                    && let Some(end) = quote_at(k + 4 + r)
                {
                    return Some(end);
                }
            }
            match chars.get(k + 1) {
                Some(&c) if c != '\n' => quote_at(k + 2),
                _ => None,
            }
        }
        Some(&c) if c != '\'' && c != '\n' => quote_at(k + 1),
        _ => None,
    }
}

/// The end of an identifier at `i` (after an optional `r#`), and where its
/// name starts.
fn identifier(chars: &[char], i: usize) -> Option<(usize, usize)> {
    let start = if chars.get(i) == Some(&'r')
        && chars.get(i + 1) == Some(&'#')
        && chars.get(i + 2).is_some_and(|&c| is_ident_start(c))
    {
        i + 2
    } else if chars.get(i).is_some_and(|&c| is_ident_start(c)) {
        i
    } else {
        return None;
    };
    let mut end = start + 1;
    while chars.get(end).is_some_and(|&c| is_word(c)) {
        end += 1;
    }
    Some((start, end))
}

/// Where the body of a raw string starts at `i`, and its number of `#`.
fn raw_string_start(chars: &[char], i: usize) -> Option<(usize, usize)> {
    let mut j = i;
    if matches!(chars.get(j), Some('b' | 'c')) && chars.get(j + 1) == Some(&'r') {
        j += 1;
    }
    if chars.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let hashes = chars[j..].iter().take_while(|&&c| c == '#').count();
    j += hashes;
    (chars.get(j) == Some(&'"')).then_some((j + 1, hashes))
}

/// A lenient Rust lexer for the source-redirect and core rules: comments
/// are dropped and literals become one token, so a name inside a string or
/// a comment cannot hide or fake an attribute. An unterminated literal or
/// block comment is an error with its line.
pub(crate) fn rust_tokens(text: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut line_at = Vec::with_capacity(n + 1);
    let mut line = 1;
    for &c in &chars {
        line_at.push(line);
        if c == '\n' {
            line += 1;
        }
    }
    line_at.push(line);
    let text_of = |a: usize, b: usize| -> String { chars[a..b].iter().collect() };
    let mut toks = Vec::new();
    let mut push = |kind: Kind, value: String, raw: bool, line: usize| {
        toks.push(Token {
            kind,
            value,
            raw,
            line,
        });
    };
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if is_pws(c) {
            i += 1;
            continue;
        }
        if starts(&chars, i, "//") {
            i = chars[i..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(n, |j| i + j);
            continue;
        }
        if starts(&chars, i, "/*") {
            let mut depth = 1usize;
            let mut j = i + 2;
            while j < n && depth > 0 {
                if starts(&chars, j, "/*") {
                    depth += 1;
                    j += 2;
                } else if starts(&chars, j, "*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            if depth > 0 {
                return Err(format!("unterminated block comment at line {}", line_at[i]));
            }
            i = j;
            continue;
        }
        if let Some((body, hashes)) = raw_string_start(&chars, i) {
            let end = (body..n)
                .find(|&j| chars[j] == '"' && (1..=hashes).all(|h| chars.get(j + h) == Some(&'#')));
            let Some(end) = end else {
                return Err(format!("unterminated raw string at line {}", line_at[i]));
            };
            push(Kind::Str, text_of(body, end), true, line_at[i]);
            i = end + 1 + hashes;
            continue;
        }
        let quote = if c == '"' {
            Some(i + 1)
        } else if matches!(c, 'b' | 'c') && chars.get(i + 1) == Some(&'"') {
            Some(i + 2)
        } else {
            None
        };
        if let Some(body) = quote {
            let mut j = body;
            while j < n && chars[j] != '"' {
                j += if chars[j] == '\\' { 2 } else { 1 };
            }
            if j >= n {
                return Err(format!("unterminated string at line {}", line_at[i]));
            }
            push(Kind::Str, text_of(body, j), false, line_at[i]);
            i = j + 1;
            continue;
        }
        if let Some(end) = char_literal(&chars, i) {
            push(Kind::Lit, text_of(i, end), false, line_at[i]);
            i = end;
            continue;
        }
        if c == '\''
            && let Some((_, end)) = identifier(&chars, i + 1)
        {
            push(Kind::Lifetime, text_of(i, end), false, line_at[i]);
            i = end;
            continue;
        }
        if let Some((start, end)) = identifier(&chars, i) {
            push(Kind::Ident, text_of(start, end), false, line_at[i]);
            i = end;
            continue;
        }
        if c.is_ascii_digit() {
            let mut end = i + 1;
            while chars.get(end).is_some_and(|&c| is_word(c)) {
                end += 1;
            }
            push(Kind::Lit, text_of(i, end), false, line_at[i]);
            i = end;
            continue;
        }
        push(Kind::Punct, c.to_string(), false, line_at[i]);
        i += 1;
    }
    Ok(toks)
}

/// The tokens of a file, or the reason they cannot be trusted.
pub(crate) fn tokenize(text: &str) -> (Vec<Token>, Option<String>) {
    match rust_tokens(text) {
        Ok(toks) => (toks, None),
        Err(err) => (
            Vec::new(),
            Some(format!(
                "cannot tokenize ({err}), so the file set cannot be verified"
            )),
        ),
    }
}

/// Decodes the escapes of a non-raw string literal body, as rustc does
/// before it parses a format string. An escape rustc rejects is kept as
/// written; `\u{d800}` to `\u{dfff}` decode to U+FFFD, a character no
/// rule matches, as the reference checker's lone surrogate did.
pub(crate) fn unescape(body: &str) -> String {
    let chars: Vec<char> = body.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(body.len());
    let mut i = 0;
    while i < n {
        let c = chars[i];
        if c != '\\' || i + 1 >= n {
            out.push(c);
            i += 1;
            continue;
        }
        let e = chars[i + 1];
        if e == '\r' || e == '\n' {
            i += 2;
            while i < n && matches!(chars[i], ' ' | '\t' | '\n' | '\r') {
                i += 1;
            }
            continue;
        }
        let simple = match e {
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            '\\' => Some('\\'),
            '0' => Some('\0'),
            '\'' => Some('\''),
            '"' => Some('"'),
            _ => None,
        };
        if let Some(s) = simple {
            out.push(s);
            i += 2;
            continue;
        }
        if e == 'x' && is_hex(chars.get(i + 2)) && is_hex(chars.get(i + 3)) {
            let hex: String = chars[i + 2..i + 4].iter().collect();
            let byte = u8::from_str_radix(&hex, 16).unwrap_or(0);
            out.push(char::from(byte));
            i += 4;
            continue;
        }
        if e == 'u' && chars.get(i + 2) == Some(&'{') {
            let r = hex_run(&chars, i + 3);
            if (1..=8).contains(&r) && chars.get(i + 3 + r) == Some(&'}') {
                let digits: String = chars[i + 3..i + 3 + r]
                    .iter()
                    .filter(|&&c| c != '_')
                    .collect();
                let end = i + 4 + r;
                match u32::from_str_radix(&digits, 16) {
                    Ok(v) if v <= 0x10_ffff => {
                        out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
                    }
                    _ => out.extend(&chars[i..end]),
                }
                i = end;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Lines of `use` items that glob-import from a `fmt` module path or
/// rename it (a glob brings `Pointer` into scope without naming it, and a
/// rename hides the path from this check), that are built from macro
/// metavariables (`use core::$m::*;` can be either), or that name `task`.
pub(crate) fn fmt_imports(toks: &[Token]) -> Vec<(usize, &'static str)> {
    let mut hits = Vec::new();
    let n = toks.len();
    let mut k = 0;
    while k < n {
        if !toks[k].is_ident("use") {
            k += 1;
            continue;
        }
        let line = toks[k].line;
        let mut levels: Vec<Vec<&str>> = vec![Vec::new()];
        k += 1;
        while k < n && !toks[k].is_punct(';') {
            let tok = &toks[k];
            let chain_has_fmt = || levels.iter().flatten().any(|s| *s == "fmt");
            if tok.is_punct('$') {
                hits.push((line, "use item built from a macro metavariable"));
            } else if tok.is_ident("task") {
                hits.push((
                    line,
                    "imports from a task module (Waker and Context print addresses)",
                ));
            }
            if tok.is_ident("as") {
                let prev = levels.last().and_then(|l| l.last()).copied();
                if prev == Some("fmt") || (prev == Some("self") && chain_has_fmt()) {
                    hits.push((line, "renames a fmt module in a use item"));
                }
            } else if tok.kind == Kind::Ident {
                if let Some(level) = levels.last_mut() {
                    level.push(&tok.value);
                }
            } else if tok.is_punct('{') {
                levels.push(Vec::new());
            } else if tok.is_punct('}') {
                if levels.len() > 1 {
                    levels.pop();
                }
            } else if tok.is_punct(',') {
                if let Some(level) = levels.last_mut() {
                    level.clear();
                }
            } else if tok.is_punct('*') && chain_has_fmt() {
                hits.push((
                    line,
                    "glob import from a fmt module brings Pointer into scope",
                ));
            }
            k += 1;
        }
    }
    hits
}

/// Lines where a path goes through a `task` module (`core::task::...`).
pub(crate) fn task_paths(toks: &[Token]) -> Vec<(usize, &'static str)> {
    (2..toks.len())
        .filter(|&k| {
            toks[k].is_ident("task") && toks[k - 1].is_punct(':') && toks[k - 2].is_punct(':')
        })
        .map(|k| {
            (
                toks[k].line,
                "path through a task module (Waker and Context print addresses)",
            )
        })
        .collect()
}

/// Why an `include_str!` or `include_bytes!` path is not allowed in core.
/// rustc resolves the path from the file where a macro is invoked, not
/// where its body is written, so a `..` inside a macro can climb past the
/// package. Only plain relative paths downwards are allowed.
pub(crate) fn include_path_problem(path: &str) -> Option<&'static str> {
    if path.starts_with('/') {
        Some("absolute path")
    } else if path.contains('\\') {
        Some("backslash in path")
    } else if path.split('/').any(|seg| seg == "..") {
        Some("`..` component")
    } else {
        None
    }
}

/// Lines where a file reaches the compiler past the scans: `#[path = ...]`
/// (also inside `cfg_attr`), `include!`, and attributes or macro names
/// built from macro metavariables, which can carry either.
pub(crate) fn source_redirects(toks: &[Token]) -> Vec<(usize, &'static str)> {
    let punct = |k: usize, c: char| toks.get(k).is_some_and(|t| t.is_punct(c));
    let ident = |k: usize| toks.get(k).is_some_and(|t| t.kind == Kind::Ident);
    let named = |k: usize, name: &str| toks.get(k).is_some_and(|t| t.is_ident(name));
    let mut hits = Vec::new();
    for (k, tok) in toks.iter().enumerate() {
        if named(k, "include") && punct(k + 1, '!') {
            hits.push((tok.line, "include! reads a file the scans do not see"));
        }
        if punct(k, '$') && ident(k + 1) && punct(k + 2, '!') && !punct(k + 3, '=') {
            hits.push((
                tok.line,
                "macro invoked through a metavariable ($name!) can be include!",
            ));
        }
        if !punct(k, '#') {
            continue;
        }
        let mut j = k + 1;
        if punct(j, '!') {
            j += 1;
        }
        if !punct(j, '[') {
            continue;
        }
        let mut depth = 0usize;
        while j < toks.len() {
            if punct(j, '[') {
                depth += 1;
            } else if punct(j, ']') {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            } else if named(j, "path") && punct(j + 1, '=') && !punct(j + 2, '=') {
                hits.push((
                    toks[j].line,
                    "#[path = ...] points the compiler at another file",
                ));
            } else if punct(j, '$') {
                hits.push((
                    toks[j].line,
                    "attribute built from a macro metavariable can be #[path = ...]",
                ));
            }
            j += 1;
        }
    }
    hits
}

// ---------------------------------------------------------------- matchers

/// No ASCII word character before byte `i` (the `(?<![A-Za-z0-9_])`
/// boundary).
fn begins_word(bytes: &[u8], i: usize) -> bool {
    i == 0 || !is_ascii_word(bytes[i - 1])
}

/// No ASCII word character at byte `i` (the `(?![A-Za-z0-9_])` boundary).
fn ends_word(bytes: &[u8], i: usize) -> bool {
    bytes.get(i).is_none_or(|&b| !is_ascii_word(b))
}

/// The end of the run of Rust whitespace at byte `i`.
fn skip_pws(text: &str, i: usize) -> usize {
    i + text[i..]
        .chars()
        .take_while(|&c| is_pws(c))
        .map(char::len_utf8)
        .sum::<usize>()
}

/// A token pattern of the core scan, or one of the other token rules.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Pat {
    /// One of the words after an ASCII boundary, the first that matches;
    /// with `end`, an ASCII boundary must follow it.
    Words(&'static [&'static str], bool),
    /// `*`, Rust whitespace, then `const` or `mut` as a word.
    RawPointer,
    /// `&`, whitespace, `raw`, at least one whitespace, `const` or `mut`.
    RawBorrow,
    /// `Waker` as a word, or `RawWaker` followed by anything.
    Waker,
    /// `extern` and `crate` as words with whitespace between them.
    ExternCrate,
}

/// The token layer of the core crates, one entry per group of ADR-001, in
/// the reference checker's order.
pub(crate) const CORE_TOKENS: [Pat; 12] = [
    Pat::Words(&["std"], true),
    Pat::Words(&["async", "await"], true),
    Pat::Words(
        &[
            "HashMap",
            "HashSet",
            "RandomState",
            "SystemTime",
            "Instant",
            "UNIX_EPOCH",
        ],
        true,
    ),
    Pat::Words(&["arch"], true),
    Pat::Words(&["atomic"], true),
    Pat::RawPointer,
    Pat::RawBorrow,
    Pat::Words(&["ptr", "UnsafeCell", "addr", "expose_provenance"], true),
    Pat::Words(&["as_ptr", "as_mut_ptr", "into_raw"], false),
    Pat::Words(&["Pointer"], true),
    // core::task: its Debug output holds vtable and data addresses, and the
    // core has no async to need it. The module path itself is matched on
    // the token stream (task_paths).
    Pat::Waker,
    // Macros that build a format string from pieces no single literal
    // holds, or from the build environment, which is also an impure input
    // on its own. Matched as identifiers, so an alias or a comment before
    // the `!` does not hide them.
    Pat::Words(&["concat", "stringify", "env", "option_env"], true),
];

/// The `unsafe` token outside the unsafe crates.
pub(crate) const UNSAFE: Pat = Pat::Words(&["\x75nsafe"], true);
/// `#[macro_export]` in an unsafe crate.
pub(crate) const MACRO_EXPORT: Pat = Pat::Words(&["macro_export"], true);
/// `extern crate` in core, which only `extern crate alloc;` may use.
pub(crate) const EXTERN_CRATE: Pat = Pat::ExternCrate;

/// The end of `word` at byte `i`, with an end boundary if `end`.
fn word_at(text: &str, i: usize, word: &str, end: bool) -> Option<usize> {
    let e = i + word.len();
    (text.as_bytes()[i..].starts_with(word.as_bytes()) && (!end || ends_word(text.as_bytes(), e)))
        .then_some(e)
}

/// `const` or `mut` as a word at byte `i`.
fn const_or_mut(text: &str, i: usize) -> Option<usize> {
    word_at(text, i, "const", true).or_else(|| word_at(text, i, "mut", true))
}

impl Pat {
    /// The end of a match that starts at byte `i`.
    pub(crate) fn match_at(self, text: &str, i: usize) -> Option<usize> {
        let bytes = text.as_bytes();
        match self {
            Pat::Words(words, end) => {
                if !begins_word(bytes, i) {
                    return None;
                }
                words.iter().find_map(|w| word_at(text, i, w, end))
            }
            Pat::RawPointer => {
                if bytes[i] != b'*' {
                    return None;
                }
                const_or_mut(text, skip_pws(text, i + 1))
            }
            Pat::RawBorrow => {
                if bytes[i] != b'&' {
                    return None;
                }
                let r = skip_pws(text, i + 1);
                let after = word_at(text, r, "raw", false)?;
                let k = skip_pws(text, after);
                if k == after {
                    return None;
                }
                const_or_mut(text, k)
            }
            Pat::Waker => {
                if !begins_word(bytes, i) {
                    return None;
                }
                word_at(text, i, "Waker", true).or_else(|| word_at(text, i, "RawWaker", false))
            }
            Pat::ExternCrate => {
                if !begins_word(bytes, i) {
                    return None;
                }
                let after = word_at(text, i, "extern", false)?;
                let k = skip_pws(text, after);
                if k == after {
                    return None;
                }
                word_at(text, k, "crate", true)
            }
        }
    }

    /// Every match, leftmost first and non-overlapping, as byte ranges.
    pub(crate) fn find_iter(self, text: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < text.len() {
            if !text.is_char_boundary(i) {
                i += 1;
                continue;
            }
            match self.match_at(text, i) {
                Some(end) => {
                    out.push((i, end));
                    i = end;
                }
                None => i += 1,
            }
        }
        out
    }
}

/// Whether `extern crate` that ends at byte `pos` names `alloc`:
/// whitespace, `alloc`, optional whitespace, `;`.
pub(crate) fn extern_alloc_at(text: &str, pos: usize) -> bool {
    let k = skip_pws(text, pos);
    if k == pos {
        return false;
    }
    let Some(after) = word_at(text, k, "alloc", false) else {
        return false;
    };
    text.as_bytes().get(skip_pws(text, after)) == Some(&b';')
}

/// The index of the first `{` or `}` at or after byte `i`.
fn next_brace(bytes: &[u8], i: usize) -> Option<usize> {
    bytes
        .get(i..)?
        .iter()
        .position(|&b| b == b'{' || b == b'}')
        .map(|j| i + j)
}

/// The byte index of the `p` that `seg` ends in before trailing
/// whitespace, relative to `seg`.
fn ends_in_p(seg: &str) -> Option<usize> {
    let t = seg.trim_end_matches(is_space);
    t.ends_with('p').then(|| t.len() - 1)
}

/// The end of a format spec that ends in `p` and starts at the `{` at
/// byte `s`: `{`, no braces, `:`, optionally any character and one of
/// `<^>` (a fill and an alignment), no braces, `p`, whitespace, `}`.
///
/// Why one pass suffices: without a fill, nothing between the braces can
/// be a brace, so a match can only end at the first brace after `s`, and
/// its text is the same whichever `:` is taken. A fill can be a brace only
/// when that first brace follows a `:` directly and is itself followed by
/// one of `<^>`; then the match ends at the next brace after the
/// alignment. A backtracking search tries that case first, because it
/// takes the rightmost `:` and the fill first, so it is checked first.
/// Each segment between braces is read a bounded number of times, so the
/// search over a whole text is linear.
fn format_spec_at(text: &str, s: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes[s] != b'{' {
        return None;
    }
    let e1 = next_brace(bytes, s + 1)?;
    if bytes[e1 - 1] == b':'
        && matches!(bytes.get(e1 + 1), Some(b'<' | b'^' | b'>'))
        && let Some(e2) = next_brace(bytes, e1 + 2)
        && bytes[e2] == b'}'
        && ends_in_p(&text[e1 + 2..e2]).is_some()
    {
        return Some(e2 + 1);
    }
    if bytes[e1] != b'}' {
        return None;
    }
    let content = &text[s + 1..e1];
    let p = ends_in_p(content)?;
    content[..p].contains(':').then_some(e1 + 1)
}

/// Every format spec that ends in `p`, leftmost first and non-overlapping,
/// as byte ranges.
pub(crate) fn format_specs(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(s) = next_open(text.as_bytes(), i) {
        match format_spec_at(text, s) {
            Some(end) => {
                out.push((s, end));
                i = end;
            }
            None => i = s + 1,
        }
    }
    out
}

/// The first format spec that ends in `p`.
pub(crate) fn first_format_spec(text: &str) -> Option<(usize, usize)> {
    let mut i = 0;
    while let Some(s) = next_open(text.as_bytes(), i) {
        if let Some(end) = format_spec_at(text, s) {
            return Some((s, end));
        }
        i = s + 1;
    }
    None
}

fn next_open(bytes: &[u8], i: usize) -> Option<usize> {
    bytes
        .get(i..)?
        .iter()
        .position(|&b| b == b'{')
        .map(|j| i + j)
}

/// Line numbers for the matches of one text.
pub(crate) fn with_lines(text: &str, matches: Vec<(usize, usize)>) -> Vec<(usize, &str)> {
    let mut lines = Lines::new(text);
    matches
        .into_iter()
        .map(|(a, b)| (lines.at(a), &text[a..b]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        CORE_TOKENS, EXTERN_CRATE, Kind, Pat, UNSAFE, blank_comment_lines, extern_alloc_at,
        first_format_spec, fmt_imports, format_specs, include_path_problem, leading_attributes,
        rust_tokens, source_redirects, task_paths, unescape,
    };
    use crate::py_vectors;

    /// Byte offset to character offset.
    fn chars_before(text: &str, byte: usize) -> usize {
        text[..byte].chars().count()
    }

    #[test]
    fn format_spec_matches_python() {
        for &(input, want) in py_vectors::FORMAT_SPEC {
            let got: Vec<(usize, usize)> = format_specs(input)
                .into_iter()
                .map(|(a, b)| (chars_before(input, a), chars_before(input, b)))
                .collect();
            assert_eq!(got, want, "{input:?}");
            let first = first_format_spec(input)
                .map(|(a, b)| (chars_before(input, a), chars_before(input, b)));
            assert_eq!(first, want.first().copied(), "{input:?}");
        }
    }

    /// A megabyte of `{` and then of `:` is one pass, where a backtracking
    /// search is quadratic. A quadratic matcher would not finish here.
    #[test]
    fn format_spec_is_linear() {
        let started = std::time::Instant::now();
        for input in [
            format!("{}{}", "{".repeat(1 << 20), ":".repeat(1 << 20)),
            "{:".repeat(1 << 19),
            "{:{<".repeat(1 << 18),
            format!("{{{}", ":".repeat(1 << 20)),
            format!("{{{}}}", " :".repeat(1 << 19)),
        ] {
            assert!(format_specs(&input).is_empty());
        }
        let many = "{:p}".repeat(1 << 18);
        assert_eq!(format_specs(&many).len(), 1 << 18);
        assert!(started.elapsed().as_secs() < 60, "{:?}", started.elapsed());
    }

    #[test]
    fn core_tokens_match_python() {
        for &(input, want) in py_vectors::CORE_TOKENS {
            let mut got = Vec::new();
            for (k, pat) in CORE_TOKENS.iter().enumerate() {
                for (a, b) in pat.find_iter(input) {
                    got.push((k, chars_before(input, a), &input[a..b]));
                }
            }
            assert_eq!(got, want, "{input:?}");
        }
    }

    #[test]
    fn other_token_rules() {
        let code = "\x75nsafe x\x75nsafe \x75nsafe_fn _\x75nsafe é\x75nsafe";
        let hits: Vec<usize> = UNSAFE.find_iter(code).iter().map(|m| m.0).collect();
        assert_eq!(
            hits,
            [0, "\x75nsafe x\x75nsafe \x75nsafe_fn _\x75nsafe é".len()]
        );
        let src = "extern crate alloc;\nextern  crate alloc ;\nextern crate core;\nextern\u{2028}crate\nalloc;\nexterncrate x;\nextern crate allocx;";
        let found: Vec<bool> = EXTERN_CRATE
            .find_iter(src)
            .into_iter()
            .map(|(_, end)| extern_alloc_at(src, end))
            .collect();
        assert_eq!(found, [true, true, false, true, false]);
        assert!(matches!(Pat::Words(&["a"], true).match_at("a", 0), Some(1)));
    }

    #[test]
    fn lexer_matches_python() {
        for &(input, want) in py_vectors::LEXER {
            let got = rust_tokens(input);
            match (got, want) {
                (Ok(toks), Ok(want)) => {
                    let got: Vec<(&str, &str, bool, usize)> = toks
                        .iter()
                        .map(|t| {
                            let kind = match t.kind {
                                Kind::Str => "str",
                                Kind::Lit => "lit",
                                Kind::Lifetime => "lifetime",
                                Kind::Ident => "ident",
                                Kind::Punct => "punct",
                            };
                            (kind, t.value.as_str(), t.raw, t.line)
                        })
                        .collect();
                    assert_eq!(got, want, "{input:?}");
                }
                (Err(e), Err(want)) => assert_eq!(e, want, "{input:?}"),
                (got, want) => panic!("{input:?}: {got:?} != {want:?}"),
            }
        }
    }

    /// Where the identifier classes differ on purpose (ADR-015, D5): a
    /// combining mark with the Alphabetic property continues an identifier
    /// (as for rustc, whose identifiers are XID), and a letter number does
    /// not start one (rustc rejects it there). Either reading can only
    /// split or merge identifiers that rustc would reject or that are
    /// checked anyway: `task` followed by U+093F is one identifier for
    /// rustc, so it is no path through `core::task`.
    #[test]
    fn non_ascii_identifier_classes() {
        let toks = rust_tokens("task\u{93f}").expect("lexes");
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].value, "task\u{93f}");
        let toks = rust_tokens("\u{2167}x").expect("lexes");
        assert_eq!(toks[0].kind, Kind::Punct);
        assert_eq!(toks[1].value, "x");
    }

    #[test]
    fn unescape_matches_python() {
        for &(input, want) in py_vectors::UNESCAPE {
            assert_eq!(unescape(input), want, "{input:?}");
        }
        // The decoded surrogate is a neutral character inside a spec.
        assert_eq!(first_format_spec(&unescape("{:\\u{d800}p}")), Some((0, 7)));
    }

    #[test]
    fn blank_comment_lines_matches_python() {
        for &(input, want) in py_vectors::BLANK_COMMENT_LINES {
            assert_eq!(blank_comment_lines(input), want, "{input:?}");
        }
    }

    #[test]
    fn leading_attributes_match_python() {
        for &(input, want) in py_vectors::LEADING_ATTRIBUTES {
            assert_eq!(leading_attributes(input), want, "{input:?}");
        }
    }

    #[test]
    fn fmt_imports_and_task_paths_match_python() {
        for &(input, want) in py_vectors::FMT_IMPORTS_AND_TASK_PATHS {
            let toks = rust_tokens(input).expect("lexes");
            let mut got = fmt_imports(&toks);
            got.extend(task_paths(&toks));
            assert_eq!(got, want, "{input:?}");
        }
        for &(input, want) in py_vectors::INCLUDE_PATH_PROBLEM {
            assert_eq!(include_path_problem(input), want, "{input:?}");
        }
    }

    #[test]
    fn source_redirects_match_python() {
        for &(input, want) in py_vectors::SOURCE_REDIRECTS {
            let toks = rust_tokens(input).expect("lexes");
            assert_eq!(source_redirects(&toks), want, "{input:?}");
        }
    }
}
