//! Character classes and string helpers with explicit sets, never
//! `str::trim` or `char::is_whitespace`, so that every rule reads text the
//! way its specification says (ADR-015, D5).

/// Rust's Pattern_White_Space, the whitespace of the Rust lexer: what the
/// source scans, comment blanking and attributes skip.
pub(crate) const PWS: [char; 11] = [
    '\u{9}', '\u{a}', '\u{b}', '\u{c}', '\u{d}', '\u{20}', '\u{85}', '\u{200e}', '\u{200f}',
    '\u{2028}', '\u{2029}',
];

/// The whitespace of the reference checker's `\s` and `str.isspace`: the
/// 25 characters of Unicode's White_Space without U+200E and U+200F, plus
/// U+001C to U+001F. Used for format specs, cfg tokens and every strip and
/// split. Where rustc allows fewer characters, the larger set makes a
/// match more likely, never less (fail closed, ADR-015 D5).
pub(crate) const PY_SPACE: [char; 29] = [
    '\u{9}', '\u{a}', '\u{b}', '\u{c}', '\u{d}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}', '\u{20}',
    '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
    '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}',
    '\u{202f}', '\u{205f}', '\u{3000}',
];

/// Line separators of `str.splitlines`.
const LINE_BREAKS: [char; 10] = [
    '\u{a}', '\u{b}', '\u{c}', '\u{d}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
    '\u{2029}',
];

/// Whether `c` is Rust whitespace.
pub(crate) fn is_pws(c: char) -> bool {
    PWS.contains(&c)
}

/// Whether `c` is whitespace for strips, splits and format specs.
pub(crate) fn is_space(c: char) -> bool {
    PY_SPACE.contains(&c)
}

/// `s` without leading and trailing [`PY_SPACE`].
pub(crate) fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// The fields of `s` between runs of [`PY_SPACE`], empty fields dropped.
pub(crate) fn split_space(s: &str) -> impl Iterator<Item = &str> {
    s.split(is_space).filter(|f| !f.is_empty())
}

/// The lines of `s` as `str.splitlines` gives them: separated by any of
/// [`LINE_BREAKS`] or CRLF, without the separators, and no empty last line
/// after a final separator.
pub(crate) fn splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if !LINE_BREAKS.contains(&c) {
            continue;
        }
        lines.push(&s[start..i]);
        start = i + c.len_utf8();
        if c == '\r' && chars.peek().is_some_and(|&(_, n)| n == '\n') {
            chars.next();
            start += 1;
        }
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

/// Text as a file opened in text mode reads it: CRLF and a lone CR become
/// LF (universal newlines), which the fixture files were written for.
pub(crate) fn universal_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// ASCII letters, digits and `_`: the identifier boundary of the token
/// rules, ASCII on purpose (a non-ASCII neighbour makes a match more
/// likely, never less).
pub(crate) fn is_ascii_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// A character that continues an identifier: ASCII letters, digits and
/// `_`, or a non-ASCII alphanumeric character (ADR-015, D5).
pub(crate) fn is_word(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric() || c == '_'
    } else {
        c.is_alphanumeric()
    }
}

/// A character that starts an identifier: a word character that is not
/// numeric.
pub(crate) fn is_ident_start(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphabetic() || c == '_'
    } else {
        c.is_alphanumeric() && !c.is_numeric()
    }
}

/// Printable form of a text: printable ASCII as is, every other character
/// as `\u{...}`, so an output line never holds a control character or a
/// line break.
pub(crate) fn show(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        push_shown(&mut out, c);
    }
    out
}

fn push_shown(out: &mut String, c: char) {
    if (' '..='~').contains(&c) {
        out.push(c);
    } else {
        out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
    }
}

/// Printable form of bytes that are mostly UTF-8, such as a path: valid
/// characters as in [`show`], a byte outside UTF-8 as `\u{dcXX}`, the
/// character the reference checker's file system decoding gave it.
pub(crate) fn show_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            push_shown(&mut out, c);
        }
        for &b in chunk.invalid() {
            out.push_str(&format!("\\u{{dc{b:02x}}}"));
        }
    }
    out
}

/// Line numbers for many offsets of one text, in increasing order, without
/// rescanning it from the start each time.
pub(crate) struct Lines<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: usize,
}

impl<'a> Lines<'a> {
    pub(crate) fn new(text: &'a str) -> Lines<'a> {
        Lines {
            bytes: text.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    /// The line of `pos`; `pos` must not be below the previous call's.
    pub(crate) fn at(&mut self, pos: usize) -> usize {
        if pos < self.pos {
            self.pos = 0;
            self.line = 1;
        }
        self.line += self.bytes[self.pos..pos]
            .iter()
            .filter(|&&b| b == b'\n')
            .count();
        self.pos = pos;
        self.line
    }
}

#[cfg(test)]
mod tests {
    use super::{PY_SPACE, is_space, show, show_bytes, split_space, splitlines, strip};
    use crate::py_vectors;

    #[test]
    fn whitespace_set_matches_python() {
        let ours: Vec<u32> = PY_SPACE.iter().map(|&c| u32::from(c)).collect();
        assert_eq!(ours, py_vectors::PY_SPACE);
        // U+200E is Rust whitespace but not in the strip set.
        assert!(!is_space('\u{200e}'));
        assert_eq!(strip("\u{1c}\u{3000}x\u{a0}"), "x");
    }

    #[test]
    fn splitlines_matches_python() {
        for &(input, want) in py_vectors::SPLITLINES {
            assert_eq!(splitlines(input), want, "{input:?}");
        }
        for &(input, want) in py_vectors::PY_SPLIT {
            assert_eq!(split_space(input).collect::<Vec<_>>(), want, "{input:?}");
        }
    }

    #[test]
    fn show_escapes_non_printable() {
        assert_eq!(show("a b~"), "a b~");
        assert_eq!(show("a\nb\u{7f}\u{e9}"), "a\\u{a}b\\u{7f}\\u{e9}");
        assert_eq!(show("\\u{e9}"), "\\u{e9}", "idempotent on its own output");
        assert_eq!(show_bytes(b"a\xffb\n"), "a\\u{dcff}b\\u{a}");
        assert_eq!(show_bytes("é".as_bytes()), "\\u{e9}");
    }
}
