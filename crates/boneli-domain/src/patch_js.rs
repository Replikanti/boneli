//! The lexical JavaScript and TypeScript layer of the disabled-test rule
//! (ADR-013, D7).
//!
//! No lexer: a JS lexer desyncs on regular expression literals, and a
//! desync hides code as a string, which fails open. The scanner looks at
//! identifiers and the significant characters around them instead, and
//! refuses too much rather than too little. The authoritative check is the
//! dynamic "previously green" check of the fix gate (#17); this layer
//! catches the common forms before a fix is verified.
//!
//! Every function decodes the JS escapes `\uXXXX`, `\u{...}` and `\xHH`
//! first, in one pass, because JS allows escapes in identifiers: `it.skip`
//! is `it.skip`.

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
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut k = 0;
    while let Some(&c) = chars.get(k) {
        if c == '\\'
            && let Some((decoded, next)) = escape_at(&chars, k.saturating_add(1))
        {
            out.push(decoded);
            k = next;
            continue;
        }
        out.push(c);
        k = k.saturating_add(1);
    }
    out
}

/// The character an escape decodes to, for the escape whose letter is at
/// `k`, and the index after it.
fn escape_at(chars: &[char], k: usize) -> Option<(char, usize)> {
    let hex = |from: usize, count: usize| -> Option<u32> {
        let digits = chars.get(from..from.checked_add(count)?)?;
        digits.iter().try_fold(0u32, |value, c| {
            value.checked_mul(16)?.checked_add(c.to_digit(16)?)
        })
    };
    let after = k.checked_add(1)?;
    match chars.get(k)? {
        'u' if chars.get(after) == Some(&'{') => {
            let mut j = after.checked_add(1)?;
            let mut value = 0u32;
            let mut digits = 0usize;
            loop {
                let c = *chars.get(j)?;
                if c == '}' {
                    break;
                }
                value = value.checked_mul(16)?.checked_add(c.to_digit(16)?)?;
                if value > 0x10FFFF {
                    return None;
                }
                digits += 1;
                j = j.checked_add(1)?;
            }
            if digits == 0 {
                return None;
            }
            Some((char::from_u32(value)?, j.checked_add(1)?))
        }
        'u' => Some((char::from_u32(hex(after, 4)?)?, after.checked_add(4)?)),
        'x' => Some((char::from_u32(hex(after, 2)?)?, after.checked_add(2)?)),
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

/// The last non-whitespace index before `end` in `line`.
fn last_significant(line: &[char], end: usize) -> Option<usize> {
    line.get(..end)?.iter().rposition(|c| !is_space(*c))
}

/// The index of a `.` that ends the line, or ends it once the line is cut
/// at one of its `//`s.
fn line_dot(line: &[char]) -> Option<usize> {
    let ends_in_dot =
        |end: usize| last_significant(line, end).filter(|at| line.get(*at) == Some(&'.'));
    if let Some(at) = ends_in_dot(line.len()) {
        return Some(at);
    }
    line.windows(2)
        .enumerate()
        .filter(|(_, pair)| pair == &['/', '/'])
        .find_map(|(at, _)| ends_in_dot(at))
}

/// The previous significant character before index `i` and its index.
///
/// Whitespace is skipped. When the scan crosses a line terminator into a
/// line L: L counts as `.` if L, or L cut at any of its `//`s, ends in `.`
/// once right-trimmed; otherwise a blank line or a line that starts with
/// `//` is skipped and the scan goes on; otherwise L's last non-whitespace
/// character decides. So `it.// c` followed by `skip` on the next line is
/// `it.skip`.
fn scan_back(chars: &[char], i: usize) -> Option<(char, usize)> {
    let mut k = i;
    loop {
        let at = k.checked_sub(1)?;
        let c = *chars.get(at)?;
        if !is_space(c) {
            return Some((c, at));
        }
        if !is_terminator(c) {
            k = at;
            continue;
        }
        let start = chars
            .get(..at)?
            .iter()
            .rposition(|c| is_terminator(*c))
            .map_or(0, |t| t + 1);
        let line = chars.get(start..at)?;
        if let Some(dot) = line_dot(line) {
            return Some(('.', start + dot));
        }
        match line.iter().position(|c| !is_space(*c)) {
            Some(first) if line.get(first..first + 2) != Some(&['/', '/'][..]) => {
                let last = last_significant(line, line.len())?;
                return Some((*line.get(last)?, start + last));
            }
            _ => k = start,
        }
    }
}

/// The next significant character at or after index `j`.
fn next_significant(chars: &[char], j: usize) -> Option<char> {
    chars.get(j..)?.iter().copied().find(|c| !is_space(*c))
}

/// The identifier that ends right before index `end`, after whitespace.
fn identifier_before(chars: &[char], end: usize) -> &[char] {
    let end = chars
        .get(..end)
        .and_then(|before| before.iter().rposition(|c| !is_space(*c)))
        .map_or(0, |at| at + 1);
    let start = chars
        .get(..end)
        .and_then(|before| before.iter().rposition(|c| !is_ident(*c)))
        .map_or(0, |at| at + 1);
    chars.get(start..end).unwrap_or(&[])
}

/// Whether the receiver before the `.` or `[` at `at` is `test` or `it`
/// (`it.fail`, `it?.fail`, `it['fail']`, `it?.['fail']`).
fn receiver_is_test(chars: &[char], at: usize) -> bool {
    let mut end = at;
    if chars.get(at) == Some(&'[')
        && let Some(('.', dot)) = scan_back(chars, at)
    {
        end = dot;
    }
    if let Some(('?', question)) = scan_back(chars, end) {
        end = question;
    }
    let receiver = identifier_before(chars, end);
    receiver == ['t', 'e', 's', 't'] || receiver == ['i', 't']
}

/// Every identifier: its start and end index.
fn identifiers(chars: &[char]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut k = 0;
    core::iter::from_fn(move || {
        while let Some(&c) = chars.get(k) {
            if is_ident(c) {
                let start = k;
                while chars.get(k).is_some_and(|c| is_ident(*c)) {
                    k += 1;
                }
                return Some((start, k));
            }
            k += 1;
        }
        None
    })
}

/// Whether the identifier `chars[start..end]` is `name`.
fn is_word(chars: &[char], start: usize, end: usize, name: &str) -> bool {
    chars
        .get(start..end)
        .is_some_and(|word| word.iter().copied().eq(name.chars()))
}

const QUOTES: [char; 3] = ['\'', '"', '`'];

/// Whether the name at `start..end` is quoted between brackets:
/// `['skip']`, `` [`only`] ``, and `/` on either side for a comment.
/// Returns the index of the opening bracket's position (for the receiver).
fn bracketed(chars: &[char], start: usize, end: usize) -> Option<usize> {
    let open = start.checked_sub(1)?;
    let quote = *chars.get(open)?;
    if !QUOTES.contains(&quote) || chars.get(end) != Some(&quote) {
        return None;
    }
    let (before, at) = scan_back(chars, open)?;
    let after = next_significant(chars, end.checked_add(1)?)?;
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
/// backtick.
pub fn marker_counts(text: &str, is_test_file: bool) -> [u32; MARKERS] {
    let chars: Vec<char> = decode_escapes(text).chars().collect();
    let mut counts = [0u32; MARKERS];
    for (start, end) in identifiers(&chars) {
        if end - start > 9 {
            continue;
        }
        let Some(marker) = Marker::ALL
            .into_iter()
            .find(|m| is_word(&chars, start, end, m.name()))
        else {
            continue;
        };
        let previous = scan_back(&chars, start);
        let next = next_significant(&chars, end);
        let counted = if marker.is_member() {
            let fail = marker == Marker::Fail;
            let member = match previous {
                Some(('.', at)) => !fail || receiver_is_test(&chars, at),
                Some(('/', _)) => true,
                _ => false,
            };
            let quoted = bracketed(&chars, start, end).is_some_and(|at| {
                !fail || chars.get(at) == Some(&'/') || receiver_is_test(&chars, at)
            });
            let key = is_test_file
                && matches!(marker, Marker::Skip | Marker::Only | Marker::Todo)
                && next == Some(':');
            member || quoted || key
        } else {
            !matches!(previous, Some(('.', _))) && matches!(next, Some('(' | '.' | '`'))
        };
        if counted && let Some(count) = counts.get_mut(marker.index()) {
            *count = count.saturating_add(1);
        }
    }
    counts
}

/// Which characters are inside a comment: from `//` to the end of its
/// line, and from `/*` to the next `*/`. Strings are not tracked, so a `//`
/// in a string can only make what follows on its line look commented.
fn commented(chars: &[char]) -> Vec<bool> {
    let mut mask = vec![false; chars.len()];
    let mut k = 0;
    while let Some(&c) = chars.get(k) {
        let next = chars.get(k + 1).copied();
        let end = match (c, next) {
            ('/', Some('/')) => chars
                .get(k..)
                .and_then(|rest| rest.iter().position(|c| is_terminator(*c)))
                .map_or(chars.len(), |at| k + at),
            ('/', Some('*')) => chars
                .get(k + 2..)
                .and_then(|rest| rest.windows(2).position(|pair| pair == ['*', '/']))
                .map_or(chars.len(), |at| k + 2 + at + 2),
            _ => {
                k += 1;
                continue;
            }
        };
        for flag in mask.get_mut(k..end).unwrap_or(&mut []) {
            *flag = true;
        }
        k = end;
    }
    mask
}

/// The number of active test declarations in `text` (ADR-013, D7): `it`,
/// `test` or `specify` with no `.` before them, followed by `(`, `.` or a
/// backtick, and not inside a comment.
pub fn active_declarations(text: &str) -> u32 {
    let chars: Vec<char> = decode_escapes(text).chars().collect();
    let mask = commented(&chars);
    let mut count = 0u32;
    for (start, end) in identifiers(&chars) {
        let declaration = ["it", "test", "specify"]
            .iter()
            .any(|name| is_word(&chars, start, end, name));
        if declaration
            && mask.get(start) == Some(&false)
            && !matches!(scan_back(&chars, start), Some(('.', _)))
            && matches!(next_significant(&chars, end), Some('(' | '.' | '`'))
        {
            count = count.saturating_add(1);
        }
    }
    count
}

/// Whether `text` has a `test` key (`test:`, `'test':`), where Vite
/// configures Vitest (ADR-013, D7).
pub fn has_test_key(text: &str) -> bool {
    let chars: Vec<char> = decode_escapes(text).chars().collect();
    identifiers(&chars).any(|(start, end)| {
        if !is_word(&chars, start, end, "test") {
            return false;
        }
        let quote = start.checked_sub(1).and_then(|at| chars.get(at));
        let quoted = quote.is_some_and(|q| QUOTES.contains(q) && chars.get(end) == Some(q));
        let after = if quoted { end + 1 } else { end };
        next_significant(&chars, after) == Some(':')
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
    }

    #[test]
    fn declarations_and_comments() {
        assert_eq!(
            active_declarations("it('a', f)\ntest('b', f)\nspecify`c`"),
            3
        );
        assert_eq!(
            active_declarations("// it('a', f)\n/* test('b', f) */ it('c', f)"),
            1
        );
        assert_eq!(active_declarations("x.it('a')\nit = 1\nsuite('x')"), 0);
        assert_eq!(active_declarations("test.each([1])('a', f)"), 1);
        assert_eq!(active_declarations("/* never closed\nit('a', f)"), 0);
    }

    #[test]
    fn test_keys() {
        assert!(has_test_key("export default { test: { globals: true } }"));
        assert!(has_test_key("export default { 'test' : {} }"));
        assert!(!has_test_key("export default { plugins: [] } // testing"));
        assert!(!has_test_key("const latest = { tests: 1 }"));
    }
}
