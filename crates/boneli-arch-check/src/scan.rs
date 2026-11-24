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
    /// For an identifier: whether it was written with `r#`, which makes a
    /// keyword an identifier (the file-lock rule tells `if !(..)` from a
    /// macro `r#if!(..)` by it).
    pub(crate) raw_ident: bool,
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

/// The end of a shebang line that rustc drops before it lexes (its
/// `strip_shebang`): after an optional byte order mark, `#!` at the start
/// of the file whose next token, past whitespace and comments that are no
/// doc comments, is not `[`; the line ends before its `\n`. A file that
/// starts with `#!/usr/bin/env cargo /*` is code from line 2 for rustc,
/// so the lexer must not read that `/*` as a comment (ADR-030, D5).
fn shebang_end(chars: &[char]) -> Option<usize> {
    let start = usize::from(chars.first() == Some(&'\u{feff}'));
    if !starts(chars, start, "#!") {
        return None;
    }
    let n = chars.len();
    let mut i = start + 2;
    loop {
        while i < n && is_pws(chars[i]) {
            i += 1;
        }
        let doc_line = starts(chars, i, "///") && !starts(chars, i, "////");
        let doc_block =
            (starts(chars, i, "/**") && !starts(chars, i, "/**/") && !starts(chars, i, "/***"))
                || starts(chars, i, "/*!");
        if starts(chars, i, "//") && !doc_line && !starts(chars, i, "//!") {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
        } else if starts(chars, i, "/*") && !doc_block {
            // An unterminated comment runs to the end, as in rustc.
            let mut depth = 1usize;
            i += 2;
            while i < n && depth > 0 {
                if starts(chars, i, "/*") {
                    depth += 1;
                    i += 2;
                } else if starts(chars, i, "*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else {
            break;
        }
    }
    if chars.get(i) == Some(&'[') {
        return None;
    }
    Some(
        chars[start..]
            .iter()
            .position(|&c| c == '\n')
            .map_or(n, |j| start + j),
    )
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
    let mut push = |kind: Kind, value: String, raw: bool, raw_ident: bool, line: usize| {
        toks.push(Token {
            kind,
            value,
            raw,
            raw_ident,
            line,
        });
    };
    // A shebang line is no code for rustc, so it is skipped too.
    let mut i = shebang_end(&chars).unwrap_or(0);
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
            push(Kind::Str, text_of(body, end), true, false, line_at[i]);
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
            push(Kind::Str, text_of(body, j), false, false, line_at[i]);
            i = j + 1;
            continue;
        }
        if let Some(end) = char_literal(&chars, i) {
            push(Kind::Lit, text_of(i, end), false, false, line_at[i]);
            i = end;
            continue;
        }
        if c == '\''
            && let Some((_, end)) = identifier(&chars, i + 1)
        {
            push(Kind::Lifetime, text_of(i, end), false, false, line_at[i]);
            i = end;
            continue;
        }
        if let Some((start, end)) = identifier(&chars, i) {
            push(
                Kind::Ident,
                text_of(start, end),
                false,
                start != i,
                line_at[i],
            );
            i = end;
            continue;
        }
        if c.is_ascii_digit() {
            let mut end = i + 1;
            while chars.get(end).is_some_and(|&c| is_word(c)) {
                end += 1;
            }
            push(Kind::Lit, text_of(i, end), false, false, line_at[i]);
            i = end;
            continue;
        }
        push(Kind::Punct, c.to_string(), false, false, line_at[i]);
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

// --------------------------------------------------------------- file-lock

/// The names a file lock is taken by in libc: `flock`, `lockf`, the
/// `flock` syscall and operations, the `fcntl` record and open file
/// description lock commands, and the `struct flock64` and lock types an
/// `fcntl` lock is described by (ADR-030, D5).
const RAW_LOCK_NAMES: [&str; 17] = [
    "flock",
    "flock64",
    "lockf",
    "SYS_flock",
    "LOCK_SH",
    "LOCK_EX",
    "LOCK_NB",
    "LOCK_UN",
    "F_SETLK",
    "F_SETLKW",
    "F_GETLK",
    "F_OFD_SETLK",
    "F_OFD_SETLKW",
    "F_OFD_GETLK",
    "F_RDLCK",
    "F_WRLCK",
    "F_UNLCK",
];

/// The file-lock methods of std's `File`.
const LOCK_NAMES: [&str; 5] = [
    "lock",
    "try_lock",
    "lock_shared",
    "try_lock_shared",
    "unlock",
];

/// The names the proven forms trust to be std's: a redefinition of one of
/// them could make a proven form call `File`'s lock.
pub(crate) const TRUSTED_NAMES: [&str; 3] = ["Mutex", "PoisonError", "io"];

/// The forms a FAIL message offers.
const PROVEN_FORMS: &str = "Mutex::lock(&m), m.lock().unwrap_or_else(PoisonError::into_inner), \
    m.try_lock().as_deref() or io::stdout().lock()";

/// Rust's strict keywords. Written without `r#`, none of them names a
/// macro, so `if !(..)` opens no macro group.
const KEYWORDS: [&str; 38] = [
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "Self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "\x75nsafe",
    "use",
    "where",
    "while",
];

/// The items that declare a name in the type namespace (`as`, which
/// renames one, is read apart in `shadows`).
const DECLARERS: [&str; 6] = ["struct", "enum", "union", "type", "trait", "mod"];

fn punct_at(toks: &[Token], k: usize, c: char) -> bool {
    toks.get(k).is_some_and(|t| t.is_punct(c))
}

fn ident_at(toks: &[Token], k: usize, name: &str) -> bool {
    toks.get(k).is_some_and(|t| t.is_ident(name))
}

/// A keyword written as one (not `r#`) at `k`.
fn keyword_at(toks: &[Token], k: usize, words: &[&str]) -> bool {
    toks.get(k)
        .is_some_and(|t| t.kind == Kind::Ident && !t.raw_ident && words.contains(&t.value.as_str()))
}

/// `::` at `k` and `k + 1`.
fn path_sep_at(toks: &[Token], k: usize) -> bool {
    punct_at(toks, k, ':') && punct_at(toks, k + 1, ':')
}

fn opener(t: &Token) -> Option<char> {
    match t.value.as_str() {
        "(" if t.kind == Kind::Punct => Some(')'),
        "[" if t.kind == Kind::Punct => Some(']'),
        "{" if t.kind == Kind::Punct => Some('}'),
        _ => None,
    }
}

fn is_closer(t: &Token) -> bool {
    t.kind == Kind::Punct && matches!(t.value.as_str(), ")" | "]" | "}")
}

/// Whether the delimiter at `k` opens a macro group: `name!(..)`,
/// `name![..]`, `name!{..}`, or the body of `macro_rules! name { .. }`.
fn opens_macro(toks: &[Token], k: usize) -> bool {
    let invoked = k >= 2
        && punct_at(toks, k - 1, '!')
        && toks[k - 2].kind == Kind::Ident
        && !keyword_at(toks, k - 2, &KEYWORDS);
    let defined = k >= 3
        && toks[k - 1].kind == Kind::Ident
        && punct_at(toks, k - 2, '!')
        && ident_at(toks, k - 3, "macro_rules");
    invoked || defined
}

/// For every token, whether it lies in a macro group (its delimiters
/// included). Unbalanced closers are ignored, as the lenient lexer is.
fn macro_mask(toks: &[Token]) -> Vec<bool> {
    let mut mask = Vec::with_capacity(toks.len());
    let mut stack: Vec<bool> = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        let inside = stack.last().copied().unwrap_or(false);
        if opener(t).is_some() {
            let group = inside || opens_macro(toks, k);
            stack.push(group);
            mask.push(group);
        } else if is_closer(t) {
            stack.pop();
            mask.push(inside);
        } else {
            mask.push(inside);
        }
    }
    mask
}

/// The index after the closer that matches the opener at `open`.
fn group_end(toks: &[Token], open: usize) -> Option<usize> {
    let close = opener(toks.get(open)?)?;
    let open_c = toks[open].value.chars().next()?;
    let mut depth = 0usize;
    for (j, t) in toks.iter().enumerate().skip(open) {
        if t.is_punct(open_c) {
            depth += 1;
        } else if t.is_punct(close) {
            depth -= 1;
            if depth == 0 {
                return Some(j + 1);
            }
        }
    }
    None
}

/// The end of `#[cfg(test)]`, further outer attributes, an optional
/// visibility and `mod name { .. }` starting at `k`, or `None` when the
/// tokens there are anything else (`#[cfg(test)] fn`, `mod t;`).
fn test_module_end(toks: &[Token], k: usize) -> Option<usize> {
    let cfg_test = punct_at(toks, k, '#')
        && punct_at(toks, k + 1, '[')
        && keyword_at(toks, k + 2, &["cfg"])
        && punct_at(toks, k + 3, '(')
        && keyword_at(toks, k + 4, &["test"])
        && punct_at(toks, k + 5, ')')
        && punct_at(toks, k + 6, ']');
    if !cfg_test {
        return None;
    }
    let mut j = k + 7;
    while punct_at(toks, j, '#') && punct_at(toks, j + 1, '[') {
        j = group_end(toks, j + 1)?;
    }
    if keyword_at(toks, j, &["pub"]) {
        j += 1;
        if punct_at(toks, j, '(') {
            j = group_end(toks, j)?;
        }
    }
    if !keyword_at(toks, j, &["mod"]) || toks.get(j + 1).is_none_or(|t| t.kind != Kind::Ident) {
        return None;
    }
    if !punct_at(toks, j + 2, '{') {
        return None;
    }
    group_end(toks, j + 2)
}

/// The tokens without the bodies of `#[cfg(test)] mod name { .. }`, which
/// no production build compiles (ADR-030, D5). Only the real form outside
/// macro groups is removed: inside one, a macro can turn the tokens into
/// anything.
pub(crate) fn without_test_modules(toks: &[Token]) -> Vec<Token> {
    let mask = macro_mask(toks);
    let mut out = Vec::with_capacity(toks.len());
    let mut k = 0;
    while k < toks.len() {
        if !mask[k]
            && let Some(end) = test_module_end(toks, k)
        {
            k = end;
            continue;
        }
        out.push(toks[k].clone());
        k += 1;
    }
    out
}

/// For every token, whether it lies in a `use` item outside a macro: from
/// `use` to its `;`, with only path tokens between (so `impl Trait +
/// use<'a>` and anything that is no use item stay scanned).
fn use_mask(toks: &[Token], macros: &[bool]) -> Vec<bool> {
    let mut mask = vec![false; toks.len()];
    for k in 0..toks.len() {
        if macros[k] || !keyword_at(toks, k, &["use"]) {
            continue;
        }
        let mut j = k + 1;
        while toks.get(j).is_some_and(|t| {
            t.kind == Kind::Ident
                || (t.kind == Kind::Punct
                    && matches!(t.value.as_str(), ":" | "{" | "}" | "," | "*"))
        }) {
            j += 1;
        }
        if j > k + 1 && punct_at(toks, j, ';') {
            mask[k..=j].fill(true);
        }
    }
    mask
}

/// For every token, whether it lies in a restricted visibility `pub(in
/// path)` outside a macro, with only path tokens between: its `::lock`
/// names a module, not a call.
fn visibility_mask(toks: &[Token], macros: &[bool]) -> Vec<bool> {
    let mut mask = vec![false; toks.len()];
    for k in 0..toks.len() {
        if macros[k]
            || !keyword_at(toks, k, &["pub"])
            || !punct_at(toks, k + 1, '(')
            || !keyword_at(toks, k + 2, &["in"])
        {
            continue;
        }
        let mut j = k + 3;
        while toks
            .get(j)
            .is_some_and(|t| t.kind == Kind::Ident || t.is_punct(':'))
        {
            j += 1;
        }
        if j > k + 3 && punct_at(toks, j, ')') {
            mask[k..=j].fill(true);
        }
    }
    mask
}

/// The indices of the names declared in a generic parameter list: the
/// first token after the `<` of `impl<`, `fn name<`, `struct name<` (and
/// `enum`, `union`, `trait`, `type`), and after each `,` at its top level.
fn generic_params(toks: &[Token]) -> Vec<usize> {
    let mut params = Vec::new();
    for k in 0..toks.len() {
        if !punct_at(toks, k, '<') {
            continue;
        }
        let after_impl = k >= 1 && keyword_at(toks, k - 1, &["impl"]);
        let after_item = k >= 2
            && toks[k - 1].kind == Kind::Ident
            && keyword_at(
                toks,
                k - 2,
                &["fn", "struct", "enum", "union", "trait", "type"],
            );
        if !after_impl && !after_item {
            continue;
        }
        params.push(k + 1);
        let (mut angles, mut parens) = (1usize, 0usize);
        for j in k + 1..toks.len() {
            let t = &toks[j];
            if t.is_punct('<') {
                angles += 1;
            } else if t.is_punct('>') && !punct_at(toks, j - 1, '-') {
                angles -= 1;
                if angles == 0 {
                    break;
                }
            } else if opener(t).is_some() {
                parens += 1;
            } else if is_closer(t) {
                if parens == 0 {
                    break;
                }
                parens -= 1;
            } else if t.is_punct(',') && angles == 1 && parens == 0 {
                params.push(j + 1);
            }
        }
    }
    params.sort_unstable();
    params.dedup();
    params
}

/// `Mutex`, `PoisonError` or `io` redefined at `k`, so that a proven form
/// could resolve to something else: after `struct`, `enum`, `union`,
/// `type`, `trait`, `mod` or `as`, as a generic parameter, or (`Mutex`
/// and `PoisonError`) followed by one `:`, a bound.
fn shadows(toks: &[Token], k: usize, generics: &[usize]) -> bool {
    let name = toks[k].value.as_str();
    if !TRUSTED_NAMES.contains(&name) {
        return false;
    }
    // `as` renames only in a `use` tree or after `extern crate`, where the
    // name ends the item or a group member; `<W as io::Write>` and
    // `fd as io::RawFd` name the trait or type, they do not rename it.
    let renamed = k >= 1
        && keyword_at(toks, k - 1, &["as"])
        && (punct_at(toks, k + 1, ';') || punct_at(toks, k + 1, ',') || punct_at(toks, k + 1, '}'));
    let declared = (k >= 1 && keyword_at(toks, k - 1, &DECLARERS)) || renamed;
    let bound = name != "io" && punct_at(toks, k + 1, ':') && !punct_at(toks, k + 2, ':');
    declared || bound || generics.binary_search(&k).is_ok()
}

/// `( )` at `k`.
fn empty_call_at(toks: &[Token], k: usize) -> bool {
    punct_at(toks, k, '(') && punct_at(toks, k + 1, ')')
}

/// The first segment of a path at `k`: no `::`, `$` or `.` before it.
fn first_segment(toks: &[Token], k: usize) -> bool {
    k == 0
        || !(punct_at(toks, k - 1, ':') || punct_at(toks, k - 1, '$') || punct_at(toks, k - 1, '.'))
}

/// Whether `lock` or `try_lock` at `k` is in a form the compiler proves is
/// not `File`'s (ADR-030, D5):
///
/// - P1 `io::stdout().lock()` (or `stderr`, `stdin`), `io` the first
///   segment or right after a first-segment `std::`: `Stdout::lock` is
///   inherent, and inherent methods win.
/// - P2 `.lock()` or `.try_lock()` followed by
///   `.unwrap_or_else(PoisonError::into_inner)` (also `sync::` or
///   `std::sync::` in front): `File`'s locks return `io::Result<()>` and
///   `Result<(), fs::TryLockError>`, whose error is no `PoisonError`.
/// - P3 followed by `.as_deref()`: `Result::as_deref` needs `T: Deref`,
///   and `()` is not.
/// - P4 a `Mutex::` prefix.
fn proven(toks: &[Token], k: usize) -> bool {
    let name = toks[k].value.as_str();
    if !matches!(name, "lock" | "try_lock") {
        return false;
    }
    if k >= 3 && path_sep_at(toks, k - 2) && ident_at(toks, k - 3, "Mutex") {
        return true;
    }
    if k == 0 || !punct_at(toks, k - 1, '.') || !empty_call_at(toks, k + 1) {
        return false;
    }
    // P1: `io :: stdout ( ) . lock ( )`, `io` at k - 7.
    if name == "lock"
        && k >= 7
        && empty_call_at(toks, k - 3)
        && toks[k - 4].kind == Kind::Ident
        && matches!(toks[k - 4].value.as_str(), "stdout" | "stderr" | "stdin")
        && path_sep_at(toks, k - 6)
        && ident_at(toks, k - 7, "io")
    {
        let io = k - 7;
        let std_first = io >= 3
            && path_sep_at(toks, io - 2)
            && ident_at(toks, io - 3, "std")
            && first_segment(toks, io - 3);
        if first_segment(toks, io) || std_first {
            return true;
        }
    }
    let after = k + 3;
    if !punct_at(toks, after, '.') {
        return false;
    }
    // P3: `. as_deref ( )`.
    if ident_at(toks, after + 1, "as_deref") && empty_call_at(toks, after + 2) {
        return true;
    }
    // P2: `. unwrap_or_else ( [std ::] [sync ::] PoisonError :: into_inner )`.
    if !ident_at(toks, after + 1, "unwrap_or_else") || !punct_at(toks, after + 2, '(') {
        return false;
    }
    let mut j = after + 3;
    if ident_at(toks, j, "std") && path_sep_at(toks, j + 1) && ident_at(toks, j + 3, "sync") {
        j += 3;
    }
    if ident_at(toks, j, "sync") && path_sep_at(toks, j + 1) {
        j += 3;
    }
    ident_at(toks, j, "PoisonError")
        && path_sep_at(toks, j + 1)
        && ident_at(toks, j + 3, "into_inner")
        && punct_at(toks, j + 4, ')')
}

/// The file-lock calls of a file, as (line, message) (ADR-030, D5):
///
/// - raw libc lock names, wherever they stand;
/// - the file-lock method names inside a macro group, wherever they
///   stand, because a macro can rearrange its input;
/// - outside one, in method position (`.name(` or `.name::`) and in path
///   position (`::name` outside a `use` item and a `pub(in ..)`
///   visibility, not followed by `::` and a
///   further segment), unless `lock`/`try_lock` takes a proven form;
/// - a redefinition of a name the proven forms trust, and `fn as_deref`.
pub(crate) fn file_lock_hits(toks: &[Token]) -> Vec<(usize, String)> {
    let macros = macro_mask(toks);
    let uses = use_mask(toks, &macros);
    let visibility = visibility_mask(toks, &macros);
    let generics = generic_params(toks);
    let mut hits = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        if t.kind != Kind::Ident {
            continue;
        }
        let name = t.value.as_str();
        if RAW_LOCK_NAMES.contains(&name) {
            hits.push((
                t.line,
                format!(
                    "`{name}` is a raw file-lock name; file locks go through boneli_private_dir::lock (ADR-030, D5)"
                ),
            ));
            continue;
        }
        if shadows(toks, k, &generics)
            || (name == "as_deref" && k >= 1 && keyword_at(toks, k - 1, &["fn"]))
        {
            hits.push((
                t.line,
                format!(
                    "`{name}` is redefined here, and the proven Mutex and stdio lock forms trust it: {PROVEN_FORMS} (ADR-030, D5)"
                ),
            ));
        }
        if !LOCK_NAMES.contains(&name) {
            continue;
        }
        if macros[k] {
            hits.push((
                t.line,
                format!(
                    "`{name}` inside a macro, which can rearrange its input into a file-lock call; lock outside the macro (ADR-030, D5)"
                ),
            ));
            continue;
        }
        let method = k >= 1
            && punct_at(toks, k - 1, '.')
            && (punct_at(toks, k + 1, '(') || path_sep_at(toks, k + 1));
        let continued = path_sep_at(toks, k + 1) && !punct_at(toks, k + 3, '<');
        let path = k >= 2 && path_sep_at(toks, k - 2) && !uses[k] && !visibility[k] && !continued;
        if (method || path) && !proven(toks, k) {
            hits.push((
                t.line,
                format!(
                    "`{name}` may be File's lock; file locks go through boneli_private_dir::lock, Mutex and stdio locks take a proven form: {PROVEN_FORMS} (ADR-030, D5)"
                ),
            ));
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
        file_lock_hits, first_format_spec, fmt_imports, format_specs, include_path_problem,
        leading_attributes, rust_tokens, source_redirects, task_paths, unescape,
        without_test_modules,
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

    /// The lines rule file-lock reports for `src`, test modules removed as
    /// in the check.
    fn lock_lines(src: &str) -> Vec<usize> {
        let toks = rust_tokens(src).expect("lexes");
        file_lock_hits(&without_test_modules(&toks))
            .into_iter()
            .map(|(line, _)| line)
            .collect()
    }

    fn assert_flagged(cases: &[&str]) {
        for src in cases {
            assert!(!lock_lines(src).is_empty(), "not flagged: {src:?}");
        }
    }

    fn assert_passes(cases: &[&str]) {
        for src in cases {
            let toks = rust_tokens(src).expect("lexes");
            let hits = file_lock_hits(&without_test_modules(&toks));
            assert!(hits.is_empty(), "flagged: {src:?}: {hits:?}");
        }
    }

    /// Every spelling of a call of File's five lock methods (ADR-030, D5).
    #[test]
    fn file_lock_calls_flagged() {
        assert_flagged(&[
            "fn f(f: &File) { f.lock()?; }",
            "fn f(f: &File) { f\n    .lock()\n    .expect(\"x\"); }",
            "fn f(f: &File) { f.r#lock(); }",
            "fn f(f: &File) { f.lock::<>(); }",
            "fn f(f: &File) { f.try_lock().is_ok(); }",
            "fn f(f: &File) { f.try_lock().map_err(e)?; }",
            "fn f(f: &File) { f.lock_shared().expect(\"x\"); }",
            "fn f(f: &File) { f.try_lock_shared()?; }",
            "fn f(f: &File) { f.unlock(); }",
            "fn f(f: &File) { File::lock(&f); }",
            "fn f(f: &File) { std::fs::File::try_lock(&f); }",
            "fn f(f: &File) { <File>::lock(&f); }",
            "fn f(f: &File) { File::lock::<>(&f); }",
            "fn f(f: &File) { <File as X>::unlock(&f); }",
            "fn f() { let g = File::lock; }",
            "fn f(v: &[File]) { v.iter().map(File::lock_shared); }",
            "use std::fs::File as F;\nfn f(f: &F) { F::lock(&f); }",
            "impl X { fn f(&self) { Self::unlock(&self.0); } }",
            "fn f() -> impl Sized + use<> { File::lock(&f); }",
            "fn f() { use_it(); File::try_lock(&f); }",
        ]);
        assert_eq!(lock_lines("fn f() {\n\n    a\n        .lock();\n}"), [4]);
    }

    #[test]
    fn file_lock_raw_names_flagged() {
        for name in [
            "flock",
            "lockf",
            "SYS_flock",
            "LOCK_SH",
            "LOCK_EX",
            "LOCK_NB",
            "LOCK_UN",
            "F_SETLK",
            "F_SETLKW",
            "F_GETLK",
            "F_OFD_SETLK",
            "F_OFD_SETLKW",
            "F_OFD_GETLK",
            "flock64",
            "F_RDLCK",
            "F_WRLCK",
            "F_UNLCK",
        ] {
            assert_eq!(
                lock_lines(&format!("fn f() {{ libc::{name}; }}")),
                [1],
                "{name}"
            );
            assert_eq!(
                lock_lines(&format!("const X: i32 = {name};")),
                [1],
                "{name}"
            );
        }
        assert_flagged(&[
            "use libc::{flock, LOCK_EX};",
            "fn f() { libc::syscall(libc::SYS_flock, fd, 2); }",
            "fn f() { libc::fcntl(fd, libc::F_OFD_SETLKW, &l); }",
            "fn f() { r#flock(fd, 2); }",
            "fn f() { libc::fcntl(fd, 6, &libc::flock64 { l_type: libc::F_WRLCK as i16, ..z }); }",
        ]);
    }

    /// The forms the compiler proves are not File's pass.
    #[test]
    fn file_lock_proofs_pass() {
        assert_passes(&[
            "fn f() { let o = io::stdout().lock(); }",
            "fn f() { let o = io::stderr().lock(); }",
            "fn f() { let o = io::stdin().lock(); }",
            "fn f() { let o = std::io::stdout().lock(); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(PoisonError::into_inner); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(sync::PoisonError::into_inner); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(std::sync::PoisonError::into_inner); }",
            "fn f(m: &Mutex<u8>) { m\n    .lock()\n    .unwrap_or_else(std::sync::PoisonError::into_inner)\n    .push(1); }",
            "fn f(m: &Mutex<u8>) { m.try_lock().unwrap_or_else(PoisonError::into_inner); }",
            "fn f(&self) { &match self.cache.try_lock().as_deref() { Ok(x) => x, _ => y }; }",
            "fn f(m: &Mutex<u8>) { m.lock().as_deref(); }",
            "fn f(m: &Mutex<u8>) { Mutex::lock(m).expect(\"x\"); }",
            "fn f(m: &Mutex<u8>) { match Mutex::try_lock(m) { _ => {} } }",
            "fn f(m: &Mutex<u8>) { std::sync::Mutex::lock(m)?; }",
            "fn f(v: &[Mutex<u8>]) { v.iter().map(Mutex::lock); }",
        ]);
    }

    /// Mutex and stdio locks outside the proven forms are flagged: the name
    /// scan cannot tell them from File's.
    #[test]
    fn file_lock_unproven_forms_flagged() {
        assert_flagged(&[
            "fn f(m: &Mutex<u8>) { m.lock().expect(\"x\"); }",
            "fn f(m: &Mutex<u8>) { match m.lock() { _ => {} } }",
            "fn f(m: &Mutex<u8>) { m.lock()?; }",
            "fn f(m: &Mutex<u8>) { m.lock().map_err(e); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(|p| p.into_inner()); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(PoisonError::into_inner()); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(PoisonError::into_inner, x); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(other::PoisonError::into_inner); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(std::PoisonError::into_inner); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(::std::sync::PoisonError::into_inner); }",
            "fn f(m: &Mutex<u8>) { m.lock().as_deref; }",
            "fn f(m: &Mutex<u8>) { m.lock().as_deref(x); }",
            "fn f(m: &Mutex<u8>) { m.lock(x).as_deref(); }",
            "fn f(m: &Mutex<u8>) { m.lock::<>().as_deref(); }",
            "fn f(m: &Mutex<u8>) { m.lock_shared().as_deref(); }",
            "fn f(m: &Mutex<u8>) { Mutex::<u8>::lock(m); }",
            "fn f(m: &Mutex<u8>) { Mutex::unlock(m); }",
            "fn f() { stdout().lock(); }",
            "fn f() { crate::io::stdout().lock(); }",
            "fn f() { ::std::io::stdout().lock(); }",
            "fn f() { a::std::io::stdout().lock(); }",
            "fn f() { io::stdout().try_lock(); }",
            "fn f() { io::stdout(x).lock(); }",
            "fn f() { io::other().lock(); }",
            "fn f() { x::stdout().lock(); }",
            "fn f(m: &Mutex<u8>) { m.lock().unwrap_or_else(Tr::into_inner); }",
            "fn f() { if !(m.lock().is_ok()) {} }",
        ]);
    }

    /// Names that are no call of a lock method pass, and so does any name
    /// inside a literal or a comment.
    #[test]
    fn file_lock_non_calls_pass() {
        assert_passes(&[
            "fn f(&self) { self.lock.len(); }",
            "fn f(&self) { let x = self.lock; }",
            "fn f() { crate::lock::Held::new(); }",
            "use crate::lock;",
            "use a::{lock, b};",
            "pub(crate) use a::b::{c::{try_lock, unlock as u}, *};",
            "use ::a::lock_shared;",
            "fn lock(&self) {}",
            "fn unlock() {}",
            "fn f() { let lock = 1; let unlock = lock; }",
            "mod lock;",
            "pub mod try_lock {}",
            "fn f(m: &M) { lock(&m); }",
            "struct S { lock: u8 }",
            "fn f() { let s = \"x.lock() File::lock flock LOCK_EX\"; }",
            "fn f() { let s = r#\"x.lock()\"#; }",
            "fn f() { let c = 'l'; let b = b\"lock\"; }",
            "// x.lock(); flock(fd, LOCK_EX);\nfn f() {}",
            "/// x.lock()\n//! LOCK_UN\nfn f() {}",
            "/* a /* x.lock() */ File::lock(&f) */ fn f() {}",
            "fn f() { io::stdout().lock(); } fn io() {}",
            "pub(in crate::lock) fn helper() {}",
            "pub(in crate::a::lock) struct S;",
        ]);
        // Only the visibility is a path; a call after it is still one.
        assert_eq!(
            lock_lines("pub(in crate::lock) fn f(f: &File) {\n    File::lock(&f);\n}"),
            [2]
        );
    }

    /// Inside a macro group every lock name is flagged wherever it stands,
    /// test modules and use items included: a macro can rearrange its
    /// input, and identifiers cannot be built on stable Rust without proc
    /// macros, which ADR-001 bans.
    #[test]
    fn file_lock_macro_tokens_strict() {
        assert_flagged(&[
            "fn f() { m!(f.lock()); }",
            "fn f() { m![f.lock()]; }",
            "m! { f.lock() }",
            "fn f() { m!(x.lock().unwrap_or_else(PoisonError::into_inner)); }",
            "fn f() { m!(Mutex::lock(&x)); }",
            "fn f() { m!(io::stdout().lock()); }",
            "fn f() { m!(File :: lock :: f); }",
            "m!(use a::lock;);",
            "m!(#[cfg(test)] mod t { f.lock() });",
            "macro_rules! g { ($a:ident $b:ident) => { $a lock ($b) }; }",
            "macro_rules! g { ($r:ident, $m:ident) => { $r.$m() }; }\nfn f() { g!(f, lock); }",
            "fn f() { a::b!(c(d(x.unlock()))); }",
            "fn f() { r#if!(x.lock_shared); }",
            "fn f() { m!(lock); }",
        ]);
        assert_passes(&[
            "fn f() { m!(x.len()); }",
            "fn f() { if !(x.is_empty()) {} }",
            "fn f() { while !(done) {} }",
            "fn f() { a != (lock); }",
        ]);
        // A lock name outside the group, after it, is judged on its own.
        assert_eq!(lock_lines("fn f() { m!(x);\n m.lock()?; }"), [2]);
        assert!(lock_lines("fn f() { m!(x); Mutex::lock(&m); }").is_empty());
    }

    /// A redefinition of a name the proofs trust is flagged, inside macros
    /// too; a value of that name is not.
    #[test]
    fn file_lock_shadowing_flagged() {
        assert_flagged(&[
            "struct Mutex;",
            "pub struct Mutex<T>(T);",
            "type Mutex = File;",
            "use std::fs::File as Mutex;",
            "use std::fs::{File as PoisonError};",
            "use std::fs::{File as Mutex, read};",
            "enum PoisonError {}",
            "union Mutex { a: u8 }",
            "trait Mutex {}",
            "mod io {}",
            "pub mod io;",
            "use std::fs as io;",
            "extern crate core as io;",
            "fn f<Mutex: T>() {}",
            "fn f<T>() where PoisonError: T {}",
            "fn f<io>() {}",
            "fn f<T, io: X>() {}",
            "impl<'a, io> X for Y {}",
            "struct S<T: Fn(u8) -> u8, Mutex> {}",
            "trait X { type io; }",
            "fn as_deref(&self) {}",
            "m!(struct Mutex;);",
            "macro_rules! g { () => { type io = X; }; }",
        ]);
        assert_passes(&[
            "fn io(x: u8) {}",
            "fn f(io: Duration) {}",
            "struct S { io: Duration }",
            "fn f() { S { io: x }; }",
            "fn f(m: &std::sync::Mutex<u8>) {}",
            "fn f() -> Mutex<u8> { Mutex::new(0) }",
            "fn f<T: Fn(u8, io::Error)>() {}",
            "fn f<T>(a: X<u8, Mutex<T>>) {}",
            "fn f() { x.as_deref(); }",
            "use std::sync::{Mutex, PoisonError};",
            "use std::io;",
            "fn f<W: io::Write>(w: &mut W) -> io::Result<()> { <W as io::Write>::flush(w) }",
            "fn f(fd: i32) { let x = fd as io::RawFd; }",
            "fn f(r: &mut R) { let x = r as &mut dyn io::Read; }",
        ]);
    }

    /// Only `#[cfg(test)]`, further outer attributes, a visibility and
    /// `mod name { .. }` outside a macro are skipped; every other form is
    /// scanned.
    #[test]
    fn file_lock_test_modules_skipped_only_when_real() {
        assert_passes(&[
            "#[cfg(test)]\nmod tests { fn t(f: &File) { f.lock(); } }",
            "#[cfg(test)] #[allow(x)] pub(in crate::a) mod t { fn t() { f.lock(); } }",
            "#[cfg(test)] pub mod t { fn t() { let a = \"}\"; let b = '}'; f.lock(); } }",
            "#[cfg(test)] mod t { mod u { fn t() { f.lock(); } } fn v() { f.unlock(); } }",
            "fn g() { #[cfg(test)] mod t { fn t() { f.lock(); } } }",
        ]);
        assert_flagged(&[
            "#[cfg(any(test))] mod t { fn t() { f.lock(); } }",
            "#[cfg(not(test))] mod t { fn t() { f.lock(); } }",
            "#[cfg(unix)] mod t { fn t() { f.lock(); } }",
            "#![cfg(test)]\nfn t() { f.lock(); }",
            "// #[cfg(test)]\nmod t { fn t() { f.lock(); } }",
            "/* #[cfg(test)] */ mod t { fn t() { f.lock(); } }",
            "#[cfg(test)] fn helper() { f.lock(); }",
            "#[cfg(test)] mod t;\nfn g() { f.lock(); }",
            "#[cfg(r#test)] mod t { fn t() { f.lock(); } }",
            "#[cfg(test)] struct S; fn g() { f.lock(); }",
        ]);
        // Code after a skipped module is scanned, on its own line.
        assert_eq!(
            lock_lines("#[cfg(test)]\nmod t { fn t() { f.lock(); } }\nfn g() { f.lock(); }"),
            [3]
        );
    }

    /// Pattern_White_Space that rustc skips does not hide a call; `r#`
    /// does not either. A look-alike name is no identifier rustc resolves
    /// to File's method, so it does not compile and passes.
    #[test]
    fn file_lock_unicode_whitespace_and_raw_identifiers() {
        assert_flagged(&[
            "fn f() { f.\u{200e}lock(); }",
            "fn f() { f.\u{2028}lock(); }",
            "fn f() { f.\u{85}lock(); }",
            "fn f() { f.r#try_lock(); }",
            "fn f() { File::r#unlock(&f); }",
        ]);
        assert_passes(&["fn f() { f.l\u{43e}ck(); }"]);
    }

    /// A shebang line is dropped as rustc drops it, so a `/*` on it hides
    /// nothing: `#!` at the start (after a byte order mark) whose next
    /// token, past whitespace and plain comments, is not `[`.
    #[test]
    fn file_lock_shebang_line_is_skipped_as_rustc_does() {
        let hidden = "#!/usr/bin/env cargo /*\nfn f(f: &File) -> R { f.lock() }\n// */";
        assert_eq!(lock_lines(hidden), [2]);
        assert_eq!(lock_lines(&format!("\u{feff}{hidden}")), [2]);
        let values = |src: &str| -> Vec<String> {
            rust_tokens(src)
                .expect("lexes")
                .into_iter()
                .map(|t| t.value)
                .collect()
        };
        // A doc comment ends the search: rustc reads `#! /// d` as a
        // shebang line.
        assert_eq!(
            values("#! /// d\nfn f() {}"),
            ["fn", "f", "(", ")", "{", "}"]
        );
        assert_eq!(values("#!x\ny"), ["y"]);
        assert!(values("#!").is_empty());
        // `#![` is an inner attribute, also past whitespace and plain
        // comments, and `#!` later in the file is no shebang.
        assert_eq!(values("#! /* c */ // d\n [a]"), ["#", "!", "[", "a", "]"]);
        assert_eq!(values("#![a]"), ["#", "!", "[", "a", "]"]);
        assert_eq!(values(" #!x"), ["#", "!", "x"]);
        assert_eq!(lock_lines("#![a] /*\n*/ fn f() { f.lock(); }"), [2]);
    }
}
