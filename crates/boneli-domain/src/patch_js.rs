//! The lexical JavaScript and TypeScript layer of the disabled-test rule
//! (ADR-013, D7).
//!
//! The authoritative check is the dynamic "previously green" check of the
//! fix gate (#17); this layer catches the common forms before a fix is
//! verified, and refuses too much rather than too little.
//!
//! - Markers are found by identifiers and the significant characters
//!   around them, everywhere in the file (comments and strings included),
//!   on both sides.
//! - Test declarations are counted twice under different assumptions: the
//!   base's count is an upper bound and the after side's a lower bound
//!   ([`base_declarations`], [`after_declarations`]). A small lexer
//!   (strings, template literals, regular expressions, comments) runs once
//!   with each reading of the one ambiguity it knows, `/` after `)` or `}`
//!   (division or a regular expression); the base counts a declaration
//!   unless both readings put it in a comment, the after side only when
//!   both put it in code, reading the HTML-like comments `<!--` and `-->`
//!   as comments, which the base ignores.
//!
//! Every function decodes the JS escapes `\uXXXX`, `\u{...}` and `\xHH`
//! first, in one pass, because JS allows escapes in identifiers. Positions
//! are byte offsets into the decoded text; nothing is allocated per
//! character.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// The number of [`Marker`]s.
pub const MARKERS: usize = 17;

/// A name that skips, focuses or marks a test as expected to fail
/// (ADR-013, D7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Marker {
    /// `.skip`.
    Skip,
    /// `.only`.
    Only,
    /// `.todo`.
    Todo,
    /// `.fixme` (Playwright).
    Fixme,
    /// `.skipIf` (Vitest).
    SkipIf,
    /// `.runIf` (Vitest).
    RunIf,
    /// `.fails` (Vitest).
    Fails,
    /// `.failing` (Jest).
    Failing,
    /// `.fail` on `test` or `it` (Playwright).
    Fail,
    /// `xit(`.
    Xit,
    /// `xtest(`.
    Xtest,
    /// `xdescribe(`.
    Xdescribe,
    /// `xcontext(`.
    Xcontext,
    /// `xspecify(`.
    Xspecify,
    /// `fit(`.
    Fit,
    /// `fdescribe(`.
    Fdescribe,
    /// `fcontext(`.
    Fcontext,
}

impl Marker {
    /// Every marker, in order.
    pub const ALL: [Marker; MARKERS] = [
        Marker::Skip,
        Marker::Only,
        Marker::Todo,
        Marker::Fixme,
        Marker::SkipIf,
        Marker::RunIf,
        Marker::Fails,
        Marker::Failing,
        Marker::Fail,
        Marker::Xit,
        Marker::Xtest,
        Marker::Xdescribe,
        Marker::Xcontext,
        Marker::Xspecify,
        Marker::Fit,
        Marker::Fdescribe,
        Marker::Fcontext,
    ];

    /// The identifier.
    pub fn name(self) -> &'static str {
        match self {
            Marker::Skip => "skip",
            Marker::Only => "only",
            Marker::Todo => "todo",
            Marker::Fixme => "fixme",
            Marker::SkipIf => "skipIf",
            Marker::RunIf => "runIf",
            Marker::Fails => "fails",
            Marker::Failing => "failing",
            Marker::Fail => "fail",
            Marker::Xit => "xit",
            Marker::Xtest => "xtest",
            Marker::Xdescribe => "xdescribe",
            Marker::Xcontext => "xcontext",
            Marker::Xspecify => "xspecify",
            Marker::Fit => "fit",
            Marker::Fdescribe => "fdescribe",
            Marker::Fcontext => "fcontext",
        }
    }

    /// Whether the marker is a member name (`it.skip`) rather than a call
    /// (`xit(`).
    fn is_member(self) -> bool {
        self <= Marker::Fail
    }

    /// Its position in [`Marker::ALL`].
    pub fn index(self) -> usize {
        self as usize
    }
}

/// Decodes `\uXXXX`, `\u{hex digits}` (any number of digits, value at most
/// U+10FFFF, no surrogates) and `\xHH` in one pass. Anything else,
/// including an escape that does not decode, is kept as written.
pub fn decode_escapes(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut k = 0;
    while k < bytes.len() {
        if bytes.get(k) == Some(&b'\\')
            && let Some((decoded, next)) = escape_at(bytes, k + 1)
        {
            out.push(decoded);
            k = next;
            continue;
        }
        let Some(c) = text.get(k..).and_then(|rest| rest.chars().next()) else {
            break;
        };
        out.push(c);
        k += c.len_utf8();
    }
    out
}

/// The character an escape decodes to, for the escape whose letter is at
/// `k`, and the index after it.
fn escape_at(bytes: &[u8], k: usize) -> Option<(char, usize)> {
    let hex = |from: usize, count: usize| -> Option<u32> {
        bytes
            .get(from..from.checked_add(count)?)?
            .iter()
            .try_fold(0u32, |value, b| {
                value
                    .checked_mul(16)?
                    .checked_add(char::from(*b).to_digit(16)?)
            })
    };
    let after = k.checked_add(1)?;
    match bytes.get(k)? {
        b'u' if bytes.get(after) == Some(&b'{') => {
            let mut j = after + 1;
            let mut value = 0u32;
            let mut digits = 0usize;
            loop {
                let b = *bytes.get(j)?;
                if b == b'}' {
                    break;
                }
                value = value
                    .checked_mul(16)?
                    .checked_add(char::from(b).to_digit(16)?)?;
                if value > 0x10FFFF {
                    return None;
                }
                digits += 1;
                j += 1;
            }
            if digits == 0 {
                return None;
            }
            Some((char::from_u32(value)?, j + 1))
        }
        b'u' => Some((char::from_u32(hex(after, 4)?)?, after + 4)),
        b'x' => Some((char::from_u32(hex(after, 2)?)?, after + 2)),
        _ => None,
    }
}

/// JS whitespace for this scanner: `char::is_whitespace` (which includes
/// NBSP and the line terminators) plus U+FEFF.
fn is_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{FEFF}'
}

/// JS line terminators.
fn is_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// An identifier character at a name's boundary: ASCII letters, digits,
/// `_`, `$`, and any non-ASCII character that is not whitespace.
fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$' || (!c.is_ascii() && !is_space(c))
}

/// The character before byte offset `i` and its offset.
fn char_before(s: &str, i: usize) -> Option<(char, usize)> {
    s.get(..i)?
        .char_indices()
        .next_back()
        .map(|(at, c)| (c, at))
}

/// The last non-whitespace character of `line` and its offset in it.
fn last_significant(line: &str) -> Option<(char, usize)> {
    line.char_indices()
        .rev()
        .find(|(_, c)| !is_space(*c))
        .map(|(at, c)| (c, at))
}

/// The offset of a `.` that ends the line, or ends it once the line is cut
/// at one of its `//`s.
fn line_dot(line: &str) -> Option<usize> {
    let ends_in_dot = |cut: &str| {
        last_significant(cut)
            .filter(|(c, _)| *c == '.')
            .map(|(_, at)| at)
    };
    if let Some(at) = ends_in_dot(line) {
        return Some(at);
    }
    line.match_indices("//")
        .find_map(|(at, _)| line.get(..at).and_then(ends_in_dot))
}

/// The previous significant character before offset `i` and its offset.
///
/// Whitespace is skipped. When the scan crosses a line terminator into a
/// line L: L counts as `.` if L, or L cut at any of its `//`s, ends in `.`
/// once right-trimmed; otherwise a blank line or a line that starts with
/// `//` is skipped and the scan goes on; otherwise L's last non-whitespace
/// character decides. So `it.// c` followed by `skip` on the next line is
/// `it.skip`.
fn scan_back(s: &str, i: usize) -> Option<(char, usize)> {
    let mut k = i;
    loop {
        let (c, at) = char_before(s, k)?;
        if !is_space(c) {
            return Some((c, at));
        }
        if !is_terminator(c) {
            k = at;
            continue;
        }
        let before = s.get(..at)?;
        let start = before
            .char_indices()
            .rev()
            .find(|(_, c)| is_terminator(*c))
            .map_or(0, |(t, c)| t + c.len_utf8());
        let line = s.get(start..at)?;
        if let Some(dot) = line_dot(line) {
            return Some(('.', start + dot));
        }
        let trimmed = line.trim_start_matches(is_space);
        if trimmed.is_empty() || trimmed.starts_with("//") {
            k = start;
            continue;
        }
        let (c, last) = last_significant(line)?;
        return Some((c, start + last));
    }
}

/// The next significant character at or after offset `j`.
fn next_significant(s: &str, j: usize) -> Option<char> {
    s.get(j..)?.chars().find(|c| !is_space(*c))
}

/// The next significant character at or after offset `j` once comments,
/// a TypeScript non-null `!` and optional chaining `?.` are skipped: what
/// a call like `fit?.(`, `fit!(` or `fit/* c */(` is followed by.
fn next_after_separators(s: &str, j: usize) -> Option<char> {
    let mut rest = s.get(j..)?;
    loop {
        rest = rest.trim_start_matches(is_space);
        if let Some(after) = rest.strip_prefix("/*") {
            rest = after.find("*/").and_then(|at| after.get(at + 2..))?;
        } else if let Some(after) = rest.strip_prefix("//") {
            rest = after.find(is_terminator).and_then(|at| after.get(at..))?;
        } else if let Some(after) = rest.strip_prefix("?.") {
            rest = after;
        } else if let Some(after) = rest.strip_prefix('!') {
            if after.starts_with('=') {
                return Some('!');
            }
            rest = after;
        } else {
            return rest.chars().next();
        }
    }
}

/// The identifier that ends right before offset `end`, after whitespace.
fn identifier_before(s: &str, end: usize) -> &str {
    let before = s.get(..end).unwrap_or("");
    let trimmed = before.trim_end_matches(is_space);
    let start = trimmed
        .char_indices()
        .rev()
        .find(|(_, c)| !is_ident(*c))
        .map_or(0, |(at, c)| at + c.len_utf8());
    trimmed.get(start..).unwrap_or("")
}

/// Whether the receiver before the `.` or `[` at `at` is `test` or `it`
/// (`it.fail`, `it?.fail`, `it['fail']`, `it?.['fail']`).
fn receiver_is_test(s: &str, at: usize) -> bool {
    let mut end = at;
    if s.get(at..).is_some_and(|rest| rest.starts_with('['))
        && let Some(('.', dot)) = scan_back(s, at)
    {
        end = dot;
    }
    if let Some(('?', question)) = scan_back(s, end) {
        end = question;
    }
    matches!(identifier_before(s, end), "test" | "it")
}

/// Every identifier: its start and end offset.
fn identifiers(s: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut chars = s.char_indices().peekable();
    core::iter::from_fn(move || {
        while let Some((start, c)) = chars.next() {
            if is_ident(c) {
                let mut end = start + c.len_utf8();
                while let Some((at, c)) = chars.next_if(|(_, c)| is_ident(*c)) {
                    end = at + c.len_utf8();
                }
                return Some((start, end));
            }
        }
        None
    })
}

const QUOTES: [char; 3] = ['\'', '"', '`'];

/// Whether the name at `start..end` is quoted between brackets:
/// `['skip']`, `` [`only`] ``, and `/` on either side for a comment.
/// Returns the offset of the opening bracket (for the receiver).
fn bracketed(s: &str, start: usize, end: usize) -> Option<usize> {
    let (quote, open) = char_before(s, start)?;
    if !QUOTES.contains(&quote) || !s.get(end..)?.starts_with(quote) {
        return None;
    }
    let (before, at) = scan_back(s, open)?;
    let after = next_significant(s, end + quote.len_utf8())?;
    ((before == '[' || before == '/') && (after == ']' || after == '/')).then_some(at)
}

/// How often each [`Marker`] occurs in `text`, by [`Marker::index`]
/// (ADR-013, D7).
///
/// A member marker counts when it stands as a whole identifier and (a) the
/// previous significant character is `.` or `/`, or (b) it is quoted
/// between brackets, or (c), in test files only, `skip`, `only` or `todo`
/// is an object key (followed by `:`). `fail` counts only on the receiver
/// `test` or `it` (`expect.fail` is an assertion). A call marker counts
/// when it is not preceded by `.` and is followed by `(`, `.` or a
/// backtick, after the separators the member rule accepts: whitespace,
/// comments, `?.` and a TypeScript `!`.
pub fn marker_counts(text: &str, is_test_file: bool) -> [u32; MARKERS] {
    let s = decode_escapes(text);
    let s = s.as_str();
    let mut counts = [0u32; MARKERS];
    for (start, end) in identifiers(s) {
        if end - start > 9 {
            continue;
        }
        let Some(word) = s.get(start..end) else {
            continue;
        };
        let Some(marker) = Marker::ALL.into_iter().find(|m| m.name() == word) else {
            continue;
        };
        let previous = scan_back(s, start);
        let counted = if marker.is_member() {
            let fail = marker == Marker::Fail;
            let member = match previous {
                Some(('.', at)) => !fail || receiver_is_test(s, at),
                Some(('/', _)) => true,
                _ => false,
            };
            let quoted = bracketed(s, start, end).is_some_and(|at| {
                !fail || s.get(at..).is_some_and(|r| r.starts_with('/')) || receiver_is_test(s, at)
            });
            let key = is_test_file
                && matches!(marker, Marker::Skip | Marker::Only | Marker::Todo)
                && next_significant(s, end) == Some(':');
            member || quoted || key
        } else {
            !matches!(previous, Some(('.', _)))
                && matches!(next_after_separators(s, end), Some('(' | '.' | '`'))
        };
        if counted && let Some(count) = counts.get_mut(marker.index()) {
            *count = count.saturating_add(1);
        }
    }
    counts
}

/// Where a lexer is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Code,
    LineComment,
    BlockComment,
    Quoted(u8),
    Template,
    Regex { class: bool },
}

/// What a position is, for one reading of the text.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Region {
    Code,
    Literal,
    Comment,
}

impl Mode {
    fn region(self) -> Region {
        match self {
            Mode::Code => Region::Code,
            Mode::LineComment | Mode::BlockComment => Region::Comment,
            Mode::Quoted(_) | Mode::Template | Mode::Regex { .. } => Region::Literal,
        }
    }
}

/// Keywords after which `/` starts a regular expression. The keyword that
/// awaits a promise is left out: the core token scan bans the word, and
/// awaiting a regular expression literal is not code anyone writes, so
/// both readings take `/` after it as a division.
const REGEX_KEYWORDS: [&str; 13] = [
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
];

fn is_line_end(bytes: &[u8], i: usize) -> bool {
    match bytes.get(i) {
        Some(b'\n' | b'\r') => true,
        // U+2028 and U+2029: E2 80 A8 and E2 80 A9.
        Some(0xE2) => {
            bytes.get(i + 1) == Some(&0x80) && matches!(bytes.get(i + 2), Some(0xA8 | 0xA9))
        }
        _ => false,
    }
}

/// The region of each of the sorted `positions` under one reading of the
/// text: strings, template literals (with `${...}` code), regular
/// expressions and comments. `regex_after_close` decides the one ambiguity
/// the lexer knows: whether `/` after `)` or `}` starts a regular
/// expression (`if (x) /re/`) or divides (`(a) / b`). With `html`, the
/// HTML-like comments of script code, `<!--` and `-->`, run to the end of
/// their line wherever they stand in code. All syntax is ASCII,
/// so the lexer walks bytes; a multi-byte character never holds an ASCII
/// byte.
fn classify(s: &str, positions: &[usize], regex_after_close: bool, html: bool) -> Vec<Region> {
    let bytes = s.as_bytes();
    let mut out = vec![Region::Code; positions.len()];
    let mut next = 0;
    let mut mode = Mode::Code;
    // The brace depth at each open `${`, innermost last.
    let mut substitutions: Vec<usize> = Vec::new();
    let mut depth = 0usize;
    // The previous significant byte in code; `a` stands for an operand (an
    // identifier, a number, a closed string or regular expression).
    let mut previous: Option<u8> = None;
    let mut last_word = (0usize, 0usize);
    let mut i = 0;
    while i < bytes.len() {
        while let Some(&p) = positions.get(next) {
            if p > i {
                break;
            }
            if let Some(slot) = out.get_mut(next) {
                *slot = mode.region();
            }
            next += 1;
        }
        let c = bytes.get(i).copied().unwrap_or(0);
        let c2 = bytes.get(i + 1).copied();
        match mode {
            Mode::Code => match c {
                b'<' if html && bytes.get(i..).is_some_and(|r| r.starts_with(b"<!--")) => {
                    mode = Mode::LineComment;
                    i += 4;
                }
                b'-' if html && bytes.get(i..).is_some_and(|r| r.starts_with(b"-->")) => {
                    mode = Mode::LineComment;
                    i += 3;
                }
                b'/' if c2 == Some(b'/') => {
                    mode = Mode::LineComment;
                    i += 2;
                }
                b'/' if c2 == Some(b'*') => {
                    mode = Mode::BlockComment;
                    i += 2;
                }
                b'/' => {
                    let regex = match previous {
                        None => true,
                        Some(b'a') => {
                            let word = s.get(last_word.0..last_word.1).unwrap_or("");
                            let property = matches!(scan_back(s, last_word.0), Some(('.', _)));
                            REGEX_KEYWORDS.contains(&word) && !property
                        }
                        Some(b')' | b'}') => regex_after_close,
                        Some(p) => b"(,=:[!&|?{};+-*%<>~^/".contains(&p),
                    };
                    if regex {
                        mode = Mode::Regex { class: false };
                    } else {
                        previous = Some(b'/');
                    }
                    i += 1;
                }
                b'\'' | b'"' => {
                    mode = Mode::Quoted(c);
                    i += 1;
                }
                b'`' => {
                    mode = Mode::Template;
                    i += 1;
                }
                b'}' if substitutions.last() == Some(&depth) => {
                    substitutions.pop();
                    mode = Mode::Template;
                    i += 1;
                }
                _ if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c >= 0x80 => {
                    let start = i;
                    while bytes.get(i).is_some_and(|b| {
                        b.is_ascii_alphanumeric() || *b == b'_' || *b == b'$' || *b >= 0x80
                    }) && !is_line_end(bytes, i)
                    {
                        i += 1;
                    }
                    if i == start {
                        i += 1;
                    }
                    last_word = (start, i);
                    previous = Some(b'a');
                }
                _ => {
                    match c {
                        b'{' => depth += 1,
                        b'}' => depth = depth.saturating_sub(1),
                        _ => {}
                    }
                    if !c.is_ascii_whitespace() {
                        previous = Some(c);
                    }
                    i += 1;
                }
            },
            Mode::LineComment => {
                if is_line_end(bytes, i) {
                    mode = Mode::Code;
                }
                i += 1;
            }
            Mode::BlockComment => {
                if c == b'*' && c2 == Some(b'/') {
                    mode = Mode::Code;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Mode::Quoted(quote) => {
                if c == b'\\' {
                    i += 2;
                } else {
                    if c == quote || is_line_end(bytes, i) {
                        mode = Mode::Code;
                        previous = Some(b'a');
                    }
                    i += 1;
                }
            }
            Mode::Template => {
                if c == b'\\' {
                    i += 2;
                } else if c == b'`' {
                    mode = Mode::Code;
                    previous = Some(b'a');
                    i += 1;
                } else if c == b'$' && c2 == Some(b'{') {
                    substitutions.push(depth);
                    mode = Mode::Code;
                    previous = None;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Mode::Regex { class } => {
                if c == b'\\' {
                    i += 2;
                } else {
                    if is_line_end(bytes, i) || (c == b'/' && !class) {
                        mode = Mode::Code;
                        previous = Some(b'a');
                    } else if c == b'[' {
                        mode = Mode::Regex { class: true };
                    } else if c == b']' {
                        mode = Mode::Regex { class: false };
                    }
                    i += 1;
                }
            }
        }
    }
    while let Some(slot) = out.get_mut(next) {
        *slot = mode.region();
        next += 1;
    }
    out
}

/// The offsets of every test declaration (`it`, `test` or `specify` with
/// no `.` before them) followed, after `separators`, by `(`, `.` or a
/// backtick.
fn declarations(s: &str, wide: bool) -> Vec<usize> {
    identifiers(s)
        .filter(|(start, end)| {
            matches!(s.get(*start..*end), Some("it" | "test" | "specify"))
                && !matches!(scan_back(s, *start), Some(('.', _)))
                && matches!(
                    if wide {
                        next_after_separators(s, *end)
                    } else {
                        next_significant(s, *end)
                    },
                    Some('(' | '.' | '`')
                )
        })
        .map(|(start, _)| start)
        .collect()
}

fn count(flags: impl Iterator<Item = bool>) -> u32 {
    u32::try_from(flags.filter(|f| *f).count()).unwrap_or(u32::MAX)
}

/// An upper bound of the base's active test declarations (ADR-013, D7):
/// every declaration form, the wider call forms included (`it!(`,
/// `it?.(`), that not both readings of the lexer put in a comment.
/// Declarations in strings count.
pub fn base_declarations(text: &str) -> u32 {
    let s = decode_escapes(text);
    let positions = declarations(&s, true);
    let division = classify(&s, &positions, false, false);
    let regex = classify(&s, &positions, true, false);
    count(
        division
            .iter()
            .zip(&regex)
            .map(|(d, r)| *d != Region::Comment || *r != Region::Comment),
    )
}

/// A lower bound of the after side's active test declarations (ADR-013,
/// D7): declarations both readings of the lexer put in code, with the
/// HTML-like comments `<!--` and `-->` read as comments anywhere in code.
/// Commenting a test out therefore counts as removing it.
pub fn after_declarations(text: &str) -> u32 {
    let s = decode_escapes(text);
    let positions = declarations(&s, false);
    let division = classify(&s, &positions, false, true);
    let regex = classify(&s, &positions, true, true);
    count(
        division
            .iter()
            .zip(&regex)
            .map(|(d, r)| *d == Region::Code && *r == Region::Code),
    )
}

/// Whether `text` has a `test` key, where Vite configures Vitest (ADR-013,
/// D7): `test:`, a quoted `'test':` or `['test']:`, and the shorthand
/// `{ test }` (`test` after `{` or `,` and before `,`, `}` or `(`).
pub fn has_test_key(text: &str) -> bool {
    let s = decode_escapes(text);
    let s = s.as_str();
    identifiers(s).any(|(start, end)| {
        if s.get(start..end) != Some("test") {
            return false;
        }
        let quote = char_before(s, start).map(|(c, _)| c);
        let quoted = quote
            .is_some_and(|q| QUOTES.contains(&q) && s.get(end..).is_some_and(|r| r.starts_with(q)));
        let mut after = if quoted { end + 1 } else { end };
        if quoted && next_significant(s, after) == Some(']') {
            after = s
                .get(after..)
                .and_then(|r| r.find(']'))
                .map_or(after, |at| after + at + 1);
        }
        let next = next_significant(s, after);
        let shorthand = !quoted
            && matches!(scan_back(s, start), Some(('{' | ',', _)))
            && matches!(next, Some(',' | '}' | '('));
        next == Some(':') || shorthand
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(text: &str, marker: Marker) -> u32 {
        marker_counts(text, true)[marker.index()]
    }

    #[test]
    fn decode_escapes_cases() {
        for (raw, decoded) in [
            ("sk\\u0069p", "skip"),
            ("sk\\u{69}p", "skip"),
            ("sk\\u{000069}p", "skip"),
            ("sk\\x69p", "skip"),
            ("\\u{110000}", "\\u{110000}"),
            ("\\uD800", "\\uD800"),
            ("\\u{D800}", "\\u{D800}"),
            ("\\u{}", "\\u{}"),
            ("\\u006", "\\u006"),
            ("\\x6", "\\x6"),
            ("\\n", "\\n"),
            ("a\\", "a\\"),
            ("\\\\u0069", "\\i"),
            ("\u{E9}\\u00e9", "\u{E9}\u{E9}"),
        ] {
            assert_eq!(decode_escapes(raw), decoded, "{raw:?}");
        }
        let zeros: String = core::iter::repeat_n('0', 10_000).collect();
        assert_eq!(decode_escapes(&alloc::format!("\\u{{{zeros}69}}")), "i");
    }

    #[test]
    fn scan_back_crosses_comment_lines() {
        assert_eq!(count("it.// c\nskip(f)", Marker::Skip), 1);
        assert_eq!(count("it. // c // d\n  skip(f)", Marker::Skip), 1);
        assert_eq!(count("it.\n// only a comment\n\nskip(f)", Marker::Skip), 1);
        assert_eq!(count("it.\r\nskip(f)", Marker::Skip), 1);
        assert_eq!(count("x = 1\nskip(f)", Marker::Skip), 0);
        assert_eq!(count("skip(f)", Marker::Skip), 0);
    }

    #[test]
    fn fail_needs_a_test_receiver() {
        for text in [
            "test.fail(",
            "it.fail(",
            "it?.fail(",
            "it['fail'](",
            "it?.['fail'](",
            "test . fail(",
        ] {
            assert_eq!(count(text, Marker::Fail), 1, "{text}");
        }
        for text in [
            "expect.fail()",
            "assert.fail()",
            "unit.fail()",
            "fail()",
            "atest.fail(",
        ] {
            assert_eq!(count(text, Marker::Fail), 0, "{text}");
        }
    }

    #[test]
    fn calls_need_a_call() {
        assert_eq!(count("xit('a', f)", Marker::Xit), 1);
        assert_eq!(count("xit `a`", Marker::Xit), 1);
        assert_eq!(count("fdescribe.each([])", Marker::Fdescribe), 1);
        assert_eq!(count("a.xit(f)", Marker::Xit), 0);
        assert_eq!(count("const fit = 1", Marker::Fit), 0);
        assert_eq!(count("fitness(1)", Marker::Fit), 0);
        assert_eq!(count("if (fit != 1) {}", Marker::Fit), 0);
    }

    /// Review round 1 (item 8): the separators the member rule accepts.
    #[test]
    fn calls_accept_member_separators() {
        for text in [
            "fit?.('b', f)",
            "fit/**/('b', f)",
            "fit /* c */ ('b', f)",
            "fit!('b', f)",
            "fit // c\n('b', f)",
            "fit?.['each']",
        ] {
            assert_eq!(
                count(text, Marker::Fit),
                u32::from(!text.ends_with(']')),
                "{text}"
            );
        }
        assert_eq!(count("xit?.('b', f)", Marker::Xit), 1);
    }

    #[test]
    fn declarations_and_comments() {
        let text = "it('a', f)\ntest('b', f)\nspecify`c`";
        assert_eq!(after_declarations(text), 3);
        assert_eq!(base_declarations(text), 3);
        let commented = "// it('a', f)\n/* test('b', f) */ it('c', f)";
        assert_eq!(after_declarations(commented), 1);
        assert_eq!(base_declarations(commented), 1);
        assert_eq!(after_declarations("x.it('a')\nit = 1\nsuite('x')"), 0);
        assert_eq!(after_declarations("test.each([1])('a', f)"), 1);
        assert_eq!(after_declarations("/* never closed\nit('a', f)"), 0);
    }

    /// Review round 1 (items 3, 4, 6): the base counts an upper bound, the
    /// after side a lower bound.
    #[test]
    fn declaration_bounds() {
        // A comment opener in a base string hides nothing.
        let api = "const api = '/api/*'\ntest('a', f)\ntest('b', f)\n";
        assert_eq!(base_declarations(api), 2);
        assert_eq!(after_declarations(api), 2);
        assert_eq!(base_declarations("const g = `**/*.ts`\ntest('a', f)\n"), 1);
        assert_eq!(
            base_declarations("s.replace(/\\/*$/, '')\ntest('a', f)\n"),
            1
        );
        assert_eq!(base_declarations("const r = /[/*]/\ntest('a', f)\n"), 1);
        // Both readings of `/` after `)`: a comment only if both say so.
        assert_eq!(base_declarations("if (x) /a/.test(s)\ntest('a', f)\n"), 1);
        // Declarations in strings and templates count in the base only.
        let quoted = "const s = \"test('c', f)\"\nconst t = `\n  it('d', f)\n`\n";
        assert_eq!(base_declarations(quoted), 2);
        assert_eq!(after_declarations(quoted), 0);
        // HTML-like comments in a string hide nothing.
        assert_eq!(
            after_declarations("expect(h).toBe('<!-- x -->'); test('a', f)\n"),
            1
        );
        // A regex read as a string by one reading only: the test after the
        // real comment counts in neither.
        assert_eq!(
            after_declarations("if (x) /'/.test(s) // ' test('c', f)\n"),
            0
        );
        // Template substitutions are code.
        assert_eq!(after_declarations("const t = `${it('e', f)}`\n"), 1);
        // HTML-like comments hide a test on the after side only.
        for line in [
            "--> test('b', f)\n",
            "<!-- test('b', f)\n",
            "x <!-- test('b', f)\n",
        ] {
            assert_eq!(after_declarations(line), 0, "{line:?}");
            assert_eq!(base_declarations(line), 1, "{line:?}");
        }
        // The wider call forms count in the base.
        assert_eq!(base_declarations("it!('a', f)\nit?.('b', f)\n"), 2);
        assert_eq!(after_declarations("it!('a', f)\nit?.('b', f)\n"), 0);
    }

    #[test]
    fn test_keys() {
        assert!(has_test_key("export default { test: { globals: true } }"));
        assert!(has_test_key("export default { 'test' : {} }"));
        assert!(has_test_key("export default { ['test']: {} }"));
        assert!(!has_test_key("export default { plugins: [] } // testing"));
        assert!(!has_test_key("const latest = { tests: 1 }"));
        assert!(!has_test_key("const test = { a: 1 }"));
    }

    /// Review round 1 (item 5): the shorthand property.
    #[test]
    fn shorthand_test_key() {
        assert!(has_test_key(
            "export default defineConfig({ plugins: [], test })"
        ));
        assert!(has_test_key("export default { test, plugins: [] }"));
        assert!(has_test_key("export default {\n  test\n}"));
    }
}
