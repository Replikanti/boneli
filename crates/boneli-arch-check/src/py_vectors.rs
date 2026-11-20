//! Reference vectors for the matchers, the lexer and the helpers,
//! computed once from the functions of the former reference checker
//! (Python 3.14) and committed as literals (ADR-015, D5). Generated;
//! the inputs are listed with their expected outputs.

/// FORMAT_SPEC: input, then every match as (start, end) in characters.
pub(crate) const FORMAT_SPEC: &[(&str, &[(usize, usize)])] = &[
    ("{:}>16p}", &[(0, 8)]),
    ("{:{<p}", &[(0, 6)]),
    ("{::p}", &[(0, 5)]),
    ("{a:b:p}", &[(0, 7)]),
    ("{:p\u{1c}}", &[(0, 5)]),
    ("{:p\u{3000}}", &[(0, 5)]),
    ("{:pp }x}", &[(0, 6)]),
    ("{:p}}", &[(0, 4)]),
    ("{{:p}}", &[(1, 5)]),
    ("{:p}", &[(0, 4)]),
    ("{0:p}", &[(0, 5)]),
    ("{x:#p}", &[(0, 6)]),
    ("{:x^#12.3p}", &[(0, 11)]),
    ("{:p }", &[(0, 5)]),
    ("{:p\u{a0}}", &[(0, 5)]),
    ("{:>10p} {:p}", &[(0, 7), (8, 12)]),
    ("{p}", &[]),
    ("{:}", &[]),
    ("{:}^p}", &[(0, 6)]),
    ("{:}xp}", &[]),
    ("{:{^}", &[]),
    ("{ :p }", &[(0, 6)]),
    ("a{b{:p}c", &[(3, 7)]),
    ("{:p", &[]),
    ("{:\u{200e}p}", &[(0, 5)]),
    ("{:p\u{200e}}", &[]),
    ("{:\u{e9}<p}", &[(0, 6)]),
    ("{:}<\u{3000}p}", &[(0, 7)]),
    ("{::}>p}", &[(0, 7)]),
    ("{:}}p}", &[]),
    ("{:{{p}", &[]),
    ("{:}>p}}{:p}", &[(0, 6), (7, 11)]),
    ("x{:}", &[]),
    ("{:p}{:p}", &[(0, 4), (4, 8)]),
    ("{\n:p\n}", &[(0, 6)]),
    ("{a:}>p}", &[(0, 7)]),
    ("{:a}<p}", &[]),
    ("{:}>p {:p}", &[(6, 10)]),
    ("{:}>p", &[]),
    ("{:}>", &[]),
    ("{:{>p}}", &[(0, 6)]),
    ("\u{e9}{:p}\u{e9}", &[(1, 5)]),
    ("{:p\u{1f}}", &[(0, 5)]),
    ("{:p\u{85}}", &[(0, 5)]),
    ("{:p\u{2028}}", &[(0, 5)]),
    ("{:}^\u{3000}}", &[]),
    ("}{:p}{", &[(1, 5)]),
    ("{:{<p {:p}", &[(6, 10)]),
    ("{:x}<p}", &[]),
    ("{:\n<p}", &[(0, 6)]),
    ("{{{{:p}", &[(3, 7)]),
    ("{:}{:p}", &[(3, 7)]),
    ("{:pP}", &[]),
    ("{:P}", &[]),
];

/// CORE_TOKENS: input, then every match as (pattern, start, text), in
/// pattern order and then by position.
pub(crate) type TokenMatch = (usize, usize, &'static str);
pub(crate) const CORE_TOKENS: &[(&str, &[TokenMatch])] = &[
    ("\u{e9}std", &[(0, 1, "std")]),
    ("std\u{e9}", &[(0, 0, "std")]),
    ("xstd", &[]),
    ("std_", &[]),
    ("as_ptr_x", &[(8, 0, "as_ptr")]),
    ("RawWakerX", &[(10, 0, "RawWaker")]),
    ("WakerX", &[]),
    ("Waker", &[(10, 0, "Waker")]),
    ("*\u{2028}const", &[(5, 0, "*\u{2028}const")]),
    ("* const", &[(5, 0, "* const")]),
    ("*mut", &[(5, 0, "*mut")]),
    ("*mutx", &[]),
    ("& raw  const", &[(6, 0, "& raw  const")]),
    ("&raw\u{9}mut", &[(6, 0, "&raw\u{9}mut")]),
    ("&rawconst", &[]),
    ("&raw const_", &[]),
    ("async await", &[(1, 0, "async"), (1, 6, "await")]),
    ("HashMapX", &[]),
    ("core::arch", &[(3, 6, "arch")]),
    ("atomic", &[(4, 0, "atomic")]),
    ("ptr::eq", &[(7, 0, "ptr")]),
    ("x.addr()", &[(7, 2, "addr")]),
    ("expose_provenance", &[(7, 0, "expose_provenance")]),
    ("into_raw", &[(8, 0, "into_raw")]),
    ("Pointer", &[(9, 0, "Pointer")]),
    ("concat!", &[(11, 0, "concat")]),
    ("env", &[(11, 0, "env")]),
    ("option_env", &[(11, 0, "option_env")]),
    ("stringify", &[(11, 0, "stringify")]),
    ("UNIX_EPOCH", &[(2, 0, "UNIX_EPOCH")]),
    ("Instant", &[(2, 0, "Instant")]),
    (
        "SystemTime RandomState HashSet",
        &[
            (2, 0, "SystemTime"),
            (2, 11, "RandomState"),
            (2, 23, "HashSet"),
        ],
    ),
    ("1std", &[]),
    ("std::std", &[(0, 0, "std"), (0, 5, "std")]),
    ("a\nstd\n  *const", &[(0, 2, "std"), (5, 8, "*const")]),
    ("*\u{200e}const", &[(5, 0, "*\u{200e}const")]),
    ("*\u{a0}const", &[]),
    (
        "& \u{2029}raw\u{85}mut",
        &[(6, 0, "& \u{2029}raw\u{85}mut")],
    ),
    ("RawWaker_", &[(10, 0, "RawWaker")]),
    ("xRawWaker", &[]),
    ("_Waker", &[]),
    ("as_mut_ptr()", &[(8, 0, "as_mut_ptr")]),
    ("UnsafeCell", &[(7, 0, "UnsafeCell")]),
    ("envs", &[]),
    ("&raw  \n const", &[(6, 0, "&raw  \n const")]),
    ("**const", &[(5, 1, "*const")]),
    ("*const*mut", &[(5, 0, "*const"), (5, 6, "*mut")]),
    ("stdstd std", &[(0, 7, "std")]),
    ("Instant::now", &[(2, 0, "Instant")]),
    ("x.as_ptr", &[(8, 2, "as_ptr")]),
    ("Pointerx", &[]),
];

/// The lexer: input, then the tokens as (kind, value, raw, line) or the
/// error message. The two inputs whose identifier classes differ on
/// purpose are in scan::tests::non_ascii_identifier_classes.
pub(crate) type Lexed = (&'static str, &'static str, bool, usize);
pub(crate) const LEXER: &[(&str, Result<&[Lexed], &str>)] = &[
    ("", Ok(&[])),
    ("a", Ok(&[("ident", "a", false, 1)])),
    (
        "fn f() {}\nlet x = 1",
        Ok(&[
            ("ident", "fn", false, 1),
            ("ident", "f", false, 1),
            ("punct", "(", false, 1),
            ("punct", ")", false, 1),
            ("punct", "{", false, 1),
            ("punct", "}", false, 1),
            ("ident", "let", false, 2),
            ("ident", "x", false, 2),
            ("punct", "=", false, 2),
            ("lit", "1", false, 2),
        ]),
    ),
    ("\"unterminated", Err("unterminated string at line 1")),
    (
        "/* unterminated",
        Err("unterminated block comment at line 1"),
    ),
    (
        "x\n/* a /* b */ c */ y",
        Ok(&[("ident", "x", false, 1), ("ident", "y", false, 2)]),
    ),
    ("r#\"raw \"# str\"#", Err("unterminated string at line 1")),
    ("br##\"x\"##", Ok(&[("str", "x", true, 1)])),
    ("c\"cstr\"", Ok(&[("str", "cstr", false, 1)])),
    (
        "b'a' '\\n' '\\x41' '\\u{1F600}' 'a 'lifetime",
        Ok(&[
            ("lit", "b'a'", false, 1),
            ("lit", "'\\n'", false, 1),
            ("lit", "'\\x41'", false, 1),
            ("lit", "'\\u{1F600}'", false, 1),
            ("lifetime", "'a", false, 1),
            ("lifetime", "'lifetime", false, 1),
        ]),
    ),
    (
        "'\\x4'",
        Ok(&[
            ("punct", "'", false, 1),
            ("punct", "\\", false, 1),
            ("ident", "x4", false, 1),
            ("punct", "'", false, 1),
        ]),
    ),
    (
        "r#match r#1",
        Ok(&[
            ("ident", "match", false, 1),
            ("ident", "r", false, 1),
            ("punct", "#", false, 1),
            ("lit", "1", false, 1),
        ]),
    ),
    (
        "1u8 0x1F 1.5",
        Ok(&[
            ("lit", "1u8", false, 1),
            ("lit", "0x1F", false, 1),
            ("lit", "1", false, 1),
            ("punct", ".", false, 1),
            ("lit", "5", false, 1),
        ]),
    ),
    ("// comment\nident", Ok(&[("ident", "ident", false, 2)])),
    ("\"a\\\"b\"", Ok(&[("str", "a\\\"b", false, 1)])),
    (
        "\"line1\nline2\" x",
        Ok(&[("str", "line1\nline2", false, 1), ("ident", "x", false, 2)]),
    ),
    ("'\\u{_}'", Ok(&[("lit", "'\\u{_}'", false, 1)])),
    (
        "\u{e9} ident",
        Ok(&[("ident", "\u{e9}", false, 1), ("ident", "ident", false, 1)]),
    ),
    (
        "_x __",
        Ok(&[("ident", "_x", false, 1), ("ident", "__", false, 1)]),
    ),
    (
        "#![no_std]",
        Ok(&[
            ("punct", "#", false, 1),
            ("punct", "!", false, 1),
            ("punct", "[", false, 1),
            ("ident", "no_std", false, 1),
            ("punct", "]", false, 1),
        ]),
    ),
    (
        "r\"unterminated raw",
        Err("unterminated raw string at line 1"),
    ),
    ("b\"x", Err("unterminated string at line 1")),
    ("x // c", Ok(&[("ident", "x", false, 1)])),
    ("'", Ok(&[("punct", "'", false, 1)])),
    (
        "''",
        Ok(&[("punct", "'", false, 1), ("punct", "'", false, 1)]),
    ),
    ("'\\''", Ok(&[("lit", "'\\''", false, 1)])),
    (
        "a\n\n\"x\" /* \n */ b",
        Ok(&[
            ("ident", "a", false, 1),
            ("str", "x", false, 3),
            ("ident", "b", false, 4),
        ]),
    ),
    (
        "x\n'\n'",
        Ok(&[
            ("ident", "x", false, 1),
            ("punct", "'", false, 2),
            ("punct", "'", false, 3),
        ]),
    ),
    ("'ab", Ok(&[("lifetime", "'ab", false, 1)])),
    (
        "r#",
        Ok(&[("ident", "r", false, 1), ("punct", "#", false, 1)]),
    ),
    ("br\"x\"", Ok(&[("str", "x", true, 1)])),
    (
        "rb\"x\"",
        Ok(&[("ident", "rb", false, 1), ("str", "x", false, 1)]),
    ),
    ("cr#\"x\"#", Ok(&[("str", "x", true, 1)])),
    ("b'\\u{41}'", Ok(&[("lit", "b'\\u{41}'", false, 1)])),
    (
        "'\\u{123456789}'",
        Ok(&[
            ("punct", "'", false, 1),
            ("punct", "\\", false, 1),
            ("ident", "u", false, 1),
            ("punct", "{", false, 1),
            ("lit", "123456789", false, 1),
            ("punct", "}", false, 1),
            ("punct", "'", false, 1),
        ]),
    ),
    (
        "x\u{200e}y\u{2028}z",
        Ok(&[
            ("ident", "x", false, 1),
            ("ident", "y", false, 1),
            ("ident", "z", false, 1),
        ]),
    ),
    ("\u{a0}", Ok(&[("punct", "\u{a0}", false, 1)])),
    ("'\u{e9}'", Ok(&[("lit", "'\u{e9}'", false, 1)])),
    ("'r#x", Ok(&[("lifetime", "'r#x", false, 1)])),
    (
        "\u{661}\u{662}",
        Ok(&[
            ("punct", "\u{661}", false, 1),
            ("punct", "\u{662}", false, 1),
        ]),
    ),
    ("x\u{661}", Ok(&[("ident", "x\u{661}", false, 1)])),
    (
        "a::b",
        Ok(&[
            ("ident", "a", false, 1),
            ("punct", ":", false, 1),
            ("punct", ":", false, 1),
            ("ident", "b", false, 1),
        ]),
    ),
    (
        "\"\\\\\"x",
        Ok(&[("str", "\\\\", false, 1), ("ident", "x", false, 1)]),
    ),
    ("\"esc\\", Err("unterminated string at line 1")),
    ("1_000", Ok(&[("lit", "1_000", false, 1)])),
    (
        "'\\\n'",
        Ok(&[
            ("punct", "'", false, 1),
            ("punct", "\\", false, 1),
            ("punct", "'", false, 2),
        ]),
    ),
    ("/**/x", Ok(&[("ident", "x", false, 1)])),
    ("/*/x*/y", Ok(&[("ident", "y", false, 1)])),
    (
        "a/b",
        Ok(&[
            ("ident", "a", false, 1),
            ("punct", "/", false, 1),
            ("ident", "b", false, 1),
        ]),
    ),
    ("x\u{b2}", Ok(&[("ident", "x\u{b2}", false, 1)])),
    (
        "\"one\"\n\"two\"\n",
        Ok(&[("str", "one", false, 1), ("str", "two", false, 2)]),
    ),
    (
        "\u{3042}\u{3044}",
        Ok(&[("ident", "\u{3042}\u{3044}", false, 1)]),
    ),
    (
        "x\u{300}",
        Ok(&[("ident", "x", false, 1), ("punct", "\u{300}", false, 1)]),
    ),
    ("r##\"a\"#b\"##", Ok(&[("str", "a\"#b", true, 1)])),
];

/// unescape: body, then the decoded text (a lone surrogate as U+FFFD).
pub(crate) const UNESCAPE: &[(&str, &str)] = &[
    ("\\n\\t\\r\\0\\\\\\'\\\"", "\n\u{9}\u{d}\u{0}\\'\""),
    ("\\x41", "A"),
    ("\\x4", "\\x4"),
    ("\\u{70}", "p"),
    ("\\u{d800}", "\u{fffd}"),
    ("\\u{110000}", "\\u{110000}"),
    ("\\u{_}", "\\u{_}"),
    ("\\u{1_F600}", "\u{1f600}"),
    ("a\\\n   b", "ab"),
    ("a\\\u{d}\n\u{9}b", "ab"),
    ("\\q", "\\q"),
    ("trailing\\", "trailing\\"),
    ("{:\\u{70}}", "{:p}"),
    ("\\u{70", "\\u{70"),
    ("\\u{123456789}", "\\u{123456789}"),
    ("\\x7g", "\\x7g"),
    ("\\u{}", "\\u{}"),
    ("a\\\n\n\n  \u{d} b", "ab"),
    ("\\\\x41", "\\x41"),
    ("\\u{0}", "\u{0}"),
    ("\\u{dfff}x", "\u{fffd}x"),
    ("\\x{41}", "\\x{41}"),
    ("\\X41", "\\X41"),
    ("\\u{FFFFFFFF}", "\\u{FFFFFFFF}"),
    ("\\u{10ffff}", "\u{10ffff}"),
    ("\\\u{d}", ""),
    ("{:\\x70}", "{:p}"),
];

/// blank_comment_lines: input, output.
pub(crate) const BLANK_COMMENT_LINES: &[(&str, &str)] = &[
    ("// x\ncode", "\ncode"),
    ("  // x */ y\n", "  // x */ y\n"),
    ("// \"x\"", "// \"x\""),
    ("\u{200e}// x", ""),
    ("\u{a0}// x", "\u{a0}// x"),
    ("code // x", "code // x"),
    ("///doc\n//!inner", "\n"),
    ("\n\n", "\n\n"),
    ("\u{9}\u{2028} //x\n//", "\n"),
    ("/ / x", "/ / x"),
    ("//\n", "\n"),
    ("x\n  //y\nz", "x\n\nz"),
];

/// leading_attributes: input, then the attributes without whitespace.
pub(crate) const LEADING_ATTRIBUTES: &[(&str, &[&str])] = &[
    ("#![no_std]", &["#![no_std]"]),
    ("\u{feff}#![no_std]", &[]),
    ("#\u{200e}![no_std]", &["#![no_std]"]),
    ("#![no_\u{200b}std]", &["#![no_\u{200b}std]"]),
    ("// c\n#![a]\n#![b(\"]\")]\nfn", &["#![a]", "#![b(\"]\")]"]),
    ("#![a\n  (b)]", &["#![a(b)]"]),
    ("#![unclosed", &[]),
    ("#[outer]", &[]),
    ("  \n#!  [ x ]", &["#![x]"]),
    ("#![a]#![b]", &["#![a]", "#![b]"]),
    ("/* c */ #![a]", &[]),
    ("#![doc = \"[\"]", &["#![doc=\"[\"]"]),
    ("#![a] fn x() {} #![b]", &["#![a]"]),
    ("//x", &[]),
    ("#![a(\"\\\"]\")]", &["#![a(\"\\\"]\")]"]),
    ("#! \u{2029}[x]", &["#![x]"]),
    ("#!\u{a0}[x]", &[]),
    ("#![a[b]c]", &["#![a[b]c]"]),
    ("#![a]]", &["#![a]"]),
    ("#![doc = \"\\\\\"] #![b]", &["#![doc=\"\\\\\"]", "#![b]"]),
];

/// fmt_imports followed by task_paths: input, then (line, message).
pub(crate) const FMT_IMPORTS_AND_TASK_PATHS: &[(&str, &[(usize, &str)])] = &[
    (
        "use core::fmt::*;",
        &[(1, "glob import from a fmt module brings Pointer into scope")],
    ),
    (
        "use core::fmt::{self, *};",
        &[(1, "glob import from a fmt module brings Pointer into scope")],
    ),
    (
        "use core::{fmt::*, ops};",
        &[(1, "glob import from a fmt module brings Pointer into scope")],
    ),
    (
        "use core::fmt as f;",
        &[(1, "renames a fmt module in a use item")],
    ),
    (
        "use core::fmt::{self as ff};",
        &[(1, "renames a fmt module in a use item")],
    ),
    (
        "use core::$m::*;",
        &[(1, "use item built from a macro metavariable")],
    ),
    (
        "use core::{task as t};",
        &[(
            1,
            "imports from a task module (Waker and Context print addresses)",
        )],
    ),
    (
        "fn f() { core::task::Poll }",
        &[(
            1,
            "path through a task module (Waker and Context print addresses)",
        )],
    ),
    ("use a::{b, fmt}; use c::*;", &[]),
    ("use x::fmt::{Debug, Write as W};", &[]),
    ("use fmt::{self};", &[]),
    ("use core::{fmt, ops::*};", &[]),
    ("use a::{fmt::{b}, *};", &[]),
    ("use x", &[]),
    ("task::x", &[]),
    (
        ":: task",
        &[(
            1,
            "path through a task module (Waker and Context print addresses)",
        )],
    ),
    (
        "use\ntask;",
        &[(
            1,
            "imports from a task module (Waker and Context print addresses)",
        )],
    ),
    ("use a::{fmt::{b}}::*;", &[]),
    (
        "use fmt as x; use a as fmt;",
        &[(1, "renames a fmt module in a use item")],
    ),
    (
        "x::task y::task",
        &[
            (
                1,
                "path through a task module (Waker and Context print addresses)",
            ),
            (
                1,
                "path through a task module (Waker and Context print addresses)",
            ),
        ],
    ),
    (
        "use r#fmt::*;",
        &[(1, "glob import from a fmt module brings Pointer into scope")],
    ),
    (
        "use self::fmt::{self as s};",
        &[(1, "renames a fmt module in a use item")],
    ),
    (
        "use core::fmt::{}; use core::fmt::{self, Pointer as P};",
        &[],
    ),
    ("use a::{{fmt}}::*;", &[]),
];

/// source_redirects: input, then (line, message).
pub(crate) const SOURCE_REDIRECTS: &[(&str, &[(usize, &str)])] = &[
    (
        "#[path = \"x.rs\"] mod m;",
        &[(1, "#[path = ...] points the compiler at another file")],
    ),
    (
        "#[cfg_attr(a, path = \"x.rs\")] mod m;",
        &[(1, "#[path = ...] points the compiler at another file")],
    ),
    ("#[path == 1]", &[]),
    (
        "include!(\"x\");",
        &[(1, "include! reads a file the scans do not see")],
    ),
    (
        "$m!(x)",
        &[(
            1,
            "macro invoked through a metavariable ($name!) can be include!",
        )],
    ),
    ("$m! = 1", &[]),
    (
        "#[$a]",
        &[(
            1,
            "attribute built from a macro metavariable can be #[path = ...]",
        )],
    ),
    (
        "#![path=\"a\"]",
        &[(1, "#[path = ...] points the compiler at another file")],
    ),
    ("# [ doc = \"path = x\" ]", &[]),
    ("#[a[b]] path = 1", &[]),
    (
        "#[cfg(x)\npath = 1",
        &[(2, "#[path = ...] points the compiler at another file")],
    ),
    ("path = 1", &[]),
    ("# x [path = 1]", &[]),
    (
        "#[a]\n#[b(path\n=\n\"x\")]",
        &[(2, "#[path = ...] points the compiler at another file")],
    ),
    (
        "include ! ()",
        &[(1, "include! reads a file the scans do not see")],
    ),
    (
        "$ m ! ()",
        &[(
            1,
            "macro invoked through a metavariable ($name!) can be include!",
        )],
    ),
    ("$m !=", &[]),
    ("#![doc = r#\"path = 1\"#]", &[]),
    (
        "#[r#path = \"x\"]",
        &[(1, "#[path = ...] points the compiler at another file")],
    ),
    (
        "macro_rules! m { ($i:ident) => { $i!(); } }",
        &[(
            1,
            "macro invoked through a metavariable ($name!) can be include!",
        )],
    ),
    (
        "x.include!()",
        &[(1, "include! reads a file the scans do not see")],
    ),
    (
        "#[a(b[c])] #[path=\"y\"]",
        &[(1, "#[path = ...] points the compiler at another file")],
    ),
    (
        "#[ $x ] #[ y ]",
        &[(
            1,
            "attribute built from a macro metavariable can be #[path = ...]",
        )],
    ),
];

/// include_path_problem: path, then the problem.
pub(crate) const INCLUDE_PATH_PROBLEM: &[(&str, Option<&str>)] = &[
    ("a.txt", None),
    ("/abs", Some("absolute path")),
    ("a\\b", Some("backslash in path")),
    ("../x", Some("`..` component")),
    ("a/../b", Some("`..` component")),
    ("a/..", Some("`..` component")),
    ("..", Some("`..` component")),
    ("a..b", None),
    ("./a", None),
    ("", None),
    ("a//b", None),
    (".../x", None),
];

/// cfg: expression, then its value on a fixed target or the error. The
/// target's cfg: unix, target_os="linux", target_arch="x86_64",
/// target_family="unix", target_has_atomic="64", debug_assertions.
pub(crate) const CFG: &[(&str, Result<&str, &str>)] = &[
    ("all()", Ok("true")),
    ("any()", Ok("false")),
    ("not(a, b)", Err("cannot parse cfg(not(a, b))")),
    ("r#true", Ok("true")),
    (
        "feature = \"a\\\"b\"",
        Err("cannot parse cfg(feature = \"a\\\"b\")"),
    ),
    ("all(unix,\u{1c}windows)", Ok("false")),
    ("all(unix,)", Ok("true")),
    ("target_os = \"linux\"", Ok("true")),
    ("not(windows)", Ok("true")),
    ("any(target_os = \"none\", custom)", Ok("unknown")),
    ("all(any(all(unix)))", Ok("true")),
    ("", Err("cannot parse cfg()")),
    ("unix windows", Err("cannot parse cfg(unix windows)")),
    ("target_has_atomic = \"64\"", Ok("true")),
    ("true", Ok("true")),
    ("false", Ok("false")),
    ("not(false)", Ok("true")),
    ("all(true, custom)", Ok("unknown")),
    ("any(false, custom)", Ok("unknown")),
    ("\u{3000}unix\u{3000}", Ok("true")),
    ("debug_assertions", Ok("unknown")),
    ("all(", Err("cannot parse cfg(all()")),
    ("not()", Err("cannot parse cfg(not())")),
    ("feature=\"a\"", Ok("unknown")),
    ("a = b", Err("cannot parse cfg(a = b)")),
    ("all = \"x\"", Ok("unknown")),
    ("any(unix, windows)", Ok("true")),
    ("all(unix, not(windows))", Ok("true")),
    ("not(custom)", Ok("unknown")),
    ("r#all(unix)", Ok("true")),
    ("all (unix)", Ok("true")),
    ("target_os=\"windows\"", Ok("false")),
    ("unix,", Err("cannot parse cfg(unix,)")),
    ("(unix)", Err("cannot parse cfg((unix))")),
    ("true = \"x\"", Ok("unknown")),
    ("windows", Ok("false")),
    ("target_vendor = \"x\"", Ok("false")),
    ("all(unix, any())", Ok("false")),
    ("not(not(unix))", Ok("true")),
    ("target_os = \"\"", Ok("false")),
    ("\"x\"", Err("cannot parse cfg(\"x\")")),
    ("r#", Err("cannot parse cfg(r#)")),
    ("x\u{a0}", Ok("unknown")),
    ("all(unix)\u{1f}", Ok("true")),
    (
        "target_os = 'linux'",
        Err("cannot parse cfg(target_os = 'linux')"),
    ),
    ("not(any(custom, windows))", Ok("unknown")),
    ("all(not(custom), unix)", Ok("unknown")),
];

/// strip_html_comments: input, output.
pub(crate) const STRIP_HTML_COMMENTS: &[(&str, &str)] = &[
    ("a<!-- x -->b", "ab"),
    ("a<!-->b-->c", "ac"),
    ("a<!--b", "a"),
    ("<!-- a --><!-- b -->c", "c"),
    ("a<!--x-->b<!--", "ab"),
    ("<!<!-- x -->--x", ""),
    ("a-->b", "a-->b"),
    ("<!---->x", "x"),
    ("<!--->x-->y", "y"),
    ("a\n<!--\nb\n-->\nc", "a\n\nc"),
    ("", ""),
    ("<!--", ""),
];

/// names_build_script: text, crate, result.
pub(crate) const NAMES_BUILD_SCRIPT: &[(&str, &str, bool)] = &[
    ("libc's build script is approved", "libc", true),
    ("xlibc's build script is approved", "libc", false),
    ("x-libc's build script is approved", "libc", false),
    ("(libc's build script is approved)", "libc", true),
    ("libc's build\nscript   is\u{9}approved", "libc", true),
    ("libc's build\u{a0}script is approved", "libc", true),
    ("libc's build script is approved", "lib.c", false),
    ("lib.c's build script is approved", "lib.c", true),
    ("libcs build script is approved", "libc", false),
    ("\u{e9}libc's build script is approved", "libc", true),
    ("_libc's build script is approved", "libc", false),
    ("libc's build\u{200b}script is approved", "libc", false),
    ("libc's build\u{1c}script is approved", "libc", true),
    ("libc's  build script is approved.", "libc", true),
    (
        "xlibc's build script is approved, libc's build script is approved",
        "libc",
        true,
    ),
    ("libc's build script is approve", "libc", false),
    ("LIBC's build script is approved", "libc", false),
    ("libc\n's build script is approved", "libc", false),
    ("a+'s build script is approved", "a+", true),
];

/// os.path.relpath on absolute paths: root, path, result.
pub(crate) const REL: &[(&str, &str, &str)] = &[
    ("/a/b", "/a/b/c/d", "c/d"),
    ("/a/b", "/a/x", "../x"),
    ("/a/b", "/a/b", "."),
    ("/a/b", "/a/b/../c", "../c"),
    ("/", "/x", "x"),
    ("/a/b/", "/a/b/c/", "c"),
    ("/a//b", "/a/b/./c", "c"),
    ("/a/b", "/", "../.."),
    ("/a b/c", "/a b/c/d e", "d e"),
    ("/a/b/c", "/x/y", "../../../x/y"),
    ("/a/./b", "/a/b/c", "c"),
    ("/a/b", "/a/bc", "../bc"),
    ("/a/b/..", "/a/c", "c"),
    ("/", "/", "."),
];

/// Path.as_uri: path, URI.
pub(crate) const FILE_URI: &[(&str, &str)] = &[
    (
        "/tmp/boneli arch x/git/name",
        "file:///tmp/boneli%20arch%20x/git/name",
    ),
    ("/r~%\u{e9}", "file:///r~%25%C3%A9"),
    ("/a#b?c", "file:///a%23b%3Fc"),
    ("/a+b,c;d=e&f@g", "file:///a%2Bb%2Cc%3Bd%3De%26f%40g"),
    ("/\u{7f}", "file:///%7F"),
    ("/a:b", "file:///a%3Ab"),
    ("/A-Z_a.z~0", "file:///A-Z_a.z~0"),
    ("/\"<>\\^`{|}", "file:///%22%3C%3E%5C%5E%60%7B%7C%7D"),
    ("/", "file:///"),
    ("/a\u{9}b", "file:///a%09b"),
];

/// str.splitlines: input, lines.
pub(crate) const SPLITLINES: &[(&str, &[&str])] = &[
    ("a\nb", &["a", "b"]),
    ("a\u{d}\nb", &["a", "b"]),
    ("a\u{d}b", &["a", "b"]),
    ("a\u{b}b\u{c}c", &["a", "b", "c"]),
    ("a\u{1c}b\u{1d}c\u{1e}d", &["a", "b", "c", "d"]),
    ("a\u{85}b", &["a", "b"]),
    ("a\u{2028}b\u{2029}c", &["a", "b", "c"]),
    ("a\n", &["a"]),
    ("", &[]),
    ("\n", &[""]),
    ("a\n\nb", &["a", "", "b"]),
    ("a\u{1f}b", &["a\u{1f}b"]),
    ("\u{d}\n\u{d}\n", &["", ""]),
    ("a\n\u{d}b", &["a", "", "b"]),
    ("a\u{d}\u{d}\nb", &["a", "", "b"]),
    ("\u{b}", &[""]),
];

/// Every character for which str.isspace() holds.
pub(crate) const PY_SPACE: &[u32] = &[
    0x9, 0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001,
    0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f,
    0x205f, 0x3000,
];

/// str.split() without arguments: input, fields.
pub(crate) const PY_SPLIT: &[(&str, &[&str])] = &[
    ("a\u{1c}b", &["a", "b"]),
    (" a  b ", &["a", "b"]),
    ("\u{3000}x\u{3000}", &["x"]),
    ("a\u{200b}b", &["a\u{200b}b"]),
    ("\u{85}a\u{a0}b\n", &["a", "b"]),
];
