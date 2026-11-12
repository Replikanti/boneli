#!/usr/bin/env python3
"""Architecture and dependency rules of the boneli workspace.

Why every rule exists: docs/adr/001-core-purity-and-dependency-allowlist.md.
Policy data: tools/architecture.toml. Entry point: tools/check-architecture.sh.

Facts about the workspace come from `cargo metadata` and from the manifests
it names, never from directory names. Any tool failure fails the check.

Output contract: one line per violation, `FAIL [<rule-id>] <path>[:<line>]:
<message>`, then `OK: ...` or `N violation(s)`. Exit 0 means OK, 1 means
violations, 2 means a tool error. Diagnostics from cargo go to stderr.

Flags: --root <dir> (default: the repository root), --list-rules,
--fixtures (runs tools/fixtures/arch/cases, see run_fixtures).
"""

import sys

if sys.version_info < (3, 11):
    sys.stdout.write(
        "FAIL [tool-error] tools/check_architecture.py: Python 3.11 or newer is required\n"
        "1 violation(s)\n"
    )
    sys.exit(2)

import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import tomllib  # noqa: E402
from pathlib import Path  # noqa: E402

SCRIPT = Path(__file__).resolve()
REPO = SCRIPT.parent.parent
POLICY = "tools/architecture.toml"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"

# Graph roles that are fixed by name (docs/ARCHITECTURE.md, "Code architecture").
DOMAIN = "boneli-domain"
APP = "boneli-app"

RULES = [
    "tool-error",
    "member-name",
    "core-missing",
    "graph-domain",
    "graph-app",
    "graph-support",
    "graph-adapter",
    "graph-root-leaf",
    "lints-inherit",
    "lints-unsafe",
    "cargo-config",
    "clippy-config",
    "toolchain-file",
    "doctest-unsafe",
    "unsafe-token",
    "sys-macro-export",
    "proc-macro",
    "build-script",
    "source-redirect",
    "symlink",
    "core-no-std-attr",
    "core-no-std-build",
    "core-targets",
    "core-features",
    "core-token",
    "manifest-redirect",
    "dep-source",
    "dep-edge",
    "policy-format",
    "policy-strict",
]

# Rust's Pattern_White_Space. Python's \s misses U+200E and U+200F.
PWS = "\t\n\x0b\x0c\r \x85‎‏  "
WS = "[" + PWS + "]"
# Identifier boundaries, ASCII on purpose: a non-ASCII neighbour makes a
# match more likely, never less (fail closed).
B = r"(?<![A-Za-z0-9_])"
E = r"(?![A-Za-z0-9_])"

# D1 token layer for the core crates, one entry per group of ADR-001.
CORE_TOKENS = [
    re.compile(B + "std" + E),
    re.compile(B + "(?:async|await)" + E),
    re.compile(B + "(?:HashMap|HashSet|RandomState|SystemTime|Instant|UNIX_EPOCH)" + E),
    re.compile(B + "arch" + E),
    re.compile(B + "atomic" + E),
    re.compile(r"\*" + WS + "*(?:const|mut)" + E),
    re.compile("&" + WS + "*raw" + WS + "+(?:const|mut)" + E),
    re.compile(B + "(?:ptr|UnsafeCell|addr|expose_provenance)" + E),
    re.compile(B + "(?:as_ptr|as_mut_ptr|into_raw)"),
    re.compile(B + "Pointer" + E),
    # Macros that build a format string from pieces no single literal holds
    # (concat!("{:", "p}"), stringify!({:p})), or from the build environment
    # (env!, option_env!), which is also an impure input on its own. Matched
    # as identifiers, so an alias (`use core::concat as c;`) or a comment
    # before the `!` does not hide them.
    re.compile(B + "(?:concat|stringify|env|option_env)" + E),
]
# A format spec that ends in `p` prints an address: {:p}, {0:p}, {name:p},
# {:#p}, {:>10p}, {:x^#12.3p}, and with `{` or `}` as the fill character
# ({:}>16p}). Matched on the raw content of every file in a core package
# (comments included, any extension: include_str! can read any of them) and
# on every string literal after its escapes are decoded.
FORMAT_SPEC = re.compile(r"\{[^{}]*:(?:[\s\S][<^>])?[^{}]*p\}")
EXTERN_CRATE = re.compile(B + "extern" + WS + "+crate" + E)
EXTERN_ALLOC = re.compile(WS + "+alloc" + WS + "*;")
UNSAFE = re.compile(B + "unsafe" + E)
MACRO_EXPORT = re.compile(B + "macro_export" + E)

NO_STD_ATTR = "#![no_std]"
DOCTEST_ATTR = "#![doc(test(attr(forbid(unsafe_code))))]"
INNER_ATTR_START = re.compile("#" + WS + "*!" + WS + r"*\[")

MEMBER_NAME = re.compile(r"boneli-[a-z0-9]+(?:-[a-z0-9]+)*")
POLICY_NAME = re.compile(r"[A-Za-z0-9_-]+")
ADR_REF = re.compile(r"ADR-([0-9]{3})")
LIB_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}


class ToolError(Exception):
    def __init__(self, path, message):
        super().__init__(message)
        self.path = path
        self.message = message


class Report:
    def __init__(self):
        self.items = []

    def fail(self, rule, path, message, line=None):
        if rule not in RULES:
            raise ValueError("unknown rule " + rule)
        item = (rule, path, line, message)
        if item not in self.items:
            self.items.append(item)


def show(text):
    """Printable form of a matched token: non-ASCII as \\u{...}."""
    return "".join(c if " " <= c <= "~" else "\\u{%x}" % ord(c) for c in text)


def rel(root, path):
    return Path(os.path.relpath(path, root)).as_posix()


def run(args, cwd, env=None):
    try:
        return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    except OSError as err:
        raise ToolError(args[0], "cannot run: %s" % err) from err


def dig(table, *keys):
    for key in keys:
        if not isinstance(table, dict):
            return None
        table = table.get(key)
    return table


def load_toml(path, root):
    try:
        data = path.read_bytes()
    except OSError as err:
        raise ToolError(rel(root, path), "cannot read: %s" % err.strerror) from err
    try:
        return tomllib.loads(data.decode("utf-8"))
    except UnicodeDecodeError as err:
        raise ToolError(rel(root, path), "not UTF-8") from err
    except tomllib.TOMLDecodeError as err:
        raise ToolError(rel(root, path), "invalid TOML: %s" % err) from err


def read_text(path, root):
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as err:
        raise ToolError(rel(root, path), "not UTF-8") from err
    except OSError as err:
        raise ToolError(rel(root, path), "cannot read: %s" % err.strerror) from err


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def blank_comment_lines(text):
    """Blank whole-line // comments (doc comments included), keep newlines.

    A comment line that contains `*/` or `"` stays code: it may close a block
    comment or a string opened on an earlier line, and what follows is then
    real code. Everything else (block comments, strings) is scanned as code.
    """
    out = []
    for line in text.split("\n"):
        stripped = line.lstrip(PWS)
        if stripped.startswith("//") and "*/" not in stripped and '"' not in stripped:
            out.append("")
        else:
            out.append(line)
    return "\n".join(out)


def closing_bracket(text, start):
    """Index of the `]` matching the `[` at start, skipping string literals."""
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def leading_attributes(text):
    """Inner attributes of the leading block, whitespace removed.

    The block is the file start, skipping blank and // lines, then #![...]
    attributes, which may span several lines. Anything else ends it.
    """
    attrs, i, n = [], 0, len(text)
    while i < n:
        if text[i] in PWS:
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        m = INNER_ATTR_START.match(text, i)
        if not m:
            break
        j = closing_bracket(text, m.end() - 1)
        if j is None:
            break
        attrs.append("".join(c for c in text[i : j + 1] if c not in PWS))
        i = j + 1
    return attrs


# A lenient Rust lexer for the source-redirect rule: comments are dropped and
# literals become one token, so `path` inside a string or a comment cannot
# hide or fake an attribute.
RAW_STR = re.compile(r'(?:b|c)?r(#*)"')
STR = re.compile(r'(?:b|c)?"')
CHAR = re.compile(r"b?'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,8}\}|.)|[^\\'\n])'")
LIFETIME = re.compile(r"'(?:r#)?[^\W\d]\w*")
IDENT = re.compile(r"(?:r#)?[^\W\d]\w*")
NUMBER = re.compile(r"[0-9]\w*")


def rust_tokens(text):
    """List of (kind, value, line); raises ValueError on an unterminated literal."""
    toks, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in PWS:
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            if depth:
                raise ValueError("unterminated block comment at line %d" % line_of(text, i))
            i = j
            continue
        m = RAW_STR.match(text, i)
        if m:
            end = text.find('"' + m.group(1), m.end())
            if end < 0:
                raise ValueError("unterminated raw string at line %d" % line_of(text, i))
            toks.append(("str", (True, text[m.end() : end]), line_of(text, i)))
            i = end + 1 + len(m.group(1))
            continue
        m = STR.match(text, i)
        if m:
            j = m.end()
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise ValueError("unterminated string at line %d" % line_of(text, i))
            toks.append(("str", (False, text[m.end() : j]), line_of(text, i)))
            i = j + 1
            continue
        for kind, rx in (("lit", CHAR), ("lifetime", LIFETIME), ("ident", IDENT), ("lit", NUMBER)):
            m = rx.match(text, i)
            if m:
                value = m.group(0)
                if kind == "ident" and value.startswith("r#"):
                    value = value[2:]
                toks.append((kind, value, line_of(text, i)))
                i = m.end()
                break
        else:
            toks.append(("punct", c, line_of(text, i)))
            i += 1
    return toks


def unescape(body):
    """Decode the escapes of a non-raw Rust string literal body, as rustc does
    before it parses a format string."""
    simple = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "0": "\0", "'": "'", '"': '"'}
    out, i, n = [], 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        e = body[i + 1]
        if e in "\r\n":
            # Line continuation: skip the newline and the leading whitespace.
            i += 2
            while i < n and body[i] in " \t\n\r":
                i += 1
            continue
        if e in simple:
            out.append(simple[e])
            i += 2
            continue
        m = re.match(r"x([0-9A-Fa-f]{2})", body[i + 1 :])
        if m:
            out.append(chr(int(m.group(1), 16)))
            i += 1 + m.end()
            continue
        m = re.match(r"u\{([0-9A-Fa-f_]{1,8})\}", body[i + 1 :])
        if m:
            try:
                out.append(chr(int(m.group(1).replace("_", ""), 16)))
            except (ValueError, OverflowError):
                out.append(body[i : i + 1 + m.end()])
            i += 1 + m.end()
            continue
        out.append(c)
        i += 1
    return "".join(out)


def tokenize(text):
    """(tokens, error message or None) for a file."""
    try:
        return rust_tokens(text), None
    except ValueError as err:
        return [], "cannot tokenize (%s), so the file set cannot be verified" % err


def fmt_imports(toks):
    """Lines of `use` items that glob-import from a `fmt` module path or
    rename it: a glob brings `Pointer` into scope without naming it, and a
    rename hides the path from this check."""
    hits, k, n = [], 0, len(toks)
    while k < n:
        if not (toks[k][0] == "ident" and toks[k][1] == "use"):
            k += 1
            continue
        line, levels, k = toks[k][2], [[]], k + 1
        while k < n and not (toks[k][0] == "punct" and toks[k][1] == ";"):
            kind, value, _ = toks[k]
            chain = [seg for level in levels for seg in level]
            if kind == "ident" and value == "as":
                prev = levels[-1][-1] if levels[-1] else None
                if prev == "fmt" or (prev == "self" and "fmt" in chain):
                    hits.append((line, "renames a fmt module in a use item"))
            elif kind == "ident":
                levels[-1].append(value)
            elif kind == "punct" and value == "{":
                levels.append([])
            elif kind == "punct" and value == "}":
                if len(levels) > 1:
                    levels.pop()
            elif kind == "punct" and value == ",":
                levels[-1] = []
            elif kind == "punct" and value == "*" and "fmt" in chain:
                hits.append((line, "glob import from a fmt module brings Pointer into scope"))
            k += 1
    return hits


def source_redirects(toks):
    """Lines where a file reaches the compiler past the scans: #[path = ...]
    (also inside cfg_attr), include!, and attributes or macro names built
    from macro metavariables, which can carry either."""

    def is_punct(k, ch):
        return 0 <= k < len(toks) and toks[k][0] == "punct" and toks[k][1] == ch

    def is_ident(k, name=None):
        return 0 <= k < len(toks) and toks[k][0] == "ident" and (name is None or toks[k][1] == name)

    hits = []
    for k, (kind, value, line) in enumerate(toks):
        if is_ident(k, "include") and is_punct(k + 1, "!"):
            hits.append((line, "include! reads a file the scans do not see"))
        if is_punct(k, "$") and is_ident(k + 1) and is_punct(k + 2, "!") and not is_punct(k + 3, "="):
            hits.append((line, "macro invoked through a metavariable ($name!) can be include!"))
        if is_punct(k, "#"):
            j = k + 1
            if is_punct(j, "!"):
                j += 1
            if not is_punct(j, "["):
                continue
            depth, j = 0, j
            while j < len(toks):
                if is_punct(j, "["):
                    depth += 1
                elif is_punct(j, "]"):
                    depth -= 1
                    if depth == 0:
                        break
                elif is_ident(j, "path") and is_punct(j + 1, "=") and not is_punct(j + 2, "="):
                    hits.append((toks[j][2], "#[path = ...] points the compiler at another file"))
                elif is_punct(j, "$"):
                    hits.append((toks[j][2], "attribute built from a macro metavariable can be #[path = ...]"))
                j += 1
    return hits


def walk_package(pkg_dir):
    """(rs files, other files, symlinks) under a package directory; symlinks
    are not followed."""
    files, others, links = [], [], []
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        for name in sorted(dirnames + filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                links.append(p)
        dirnames[:] = sorted(d for d in dirnames if not (Path(dirpath) / d).is_symlink())
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            (files if name.endswith(".rs") else others).append(p)
    return files, others, links


# Target cfg evaluation (ADR-001 D3). Names whose whole value set rustc
# prints for a target with no flags: a value it does not print is false.
# Every other name (target_feature, panic, debug_assertions, overflow_checks,
# custom cfgs, ...) depends on flags or the profile and is unknown.
CFG_KNOWN = {"target_os", "target_family", "target_arch", "target_env", "target_abi",
             "target_vendor", "target_endian", "target_pointer_width", "target_has_atomic",
             "unix", "windows"}
UNKNOWN = "unknown"
CFG_TOKEN = re.compile(r"\s*(?:(?P<ident>(?:r#)?[A-Za-z_][A-Za-z0-9_]*)|\"(?P<str>[^\"\\]*)\"|(?P<punct>[(),=]))")


def parse_cfg(expr):
    """Parse a cargo cfg expression (without the outer cfg(...))."""
    toks, i = [], 0
    while i < len(expr):
        if expr[i:].strip() == "":
            break
        m = CFG_TOKEN.match(expr, i)
        if not m:
            raise ValueError("cannot parse cfg(%s)" % expr)
        toks.append(m)
        i = m.end()
    pos = [0]

    def peek(kind, value=None):
        if pos[0] >= len(toks):
            return False
        g = toks[pos[0]].group(kind)
        return g is not None and (value is None or g == value)

    def take(kind, value=None):
        if not peek(kind, value):
            raise ValueError("cannot parse cfg(%s)" % expr)
        pos[0] += 1
        return toks[pos[0] - 1].group(kind)

    def pred():
        name = take("ident").removeprefix("r#")
        if name in ("all", "any", "not") and peek("punct", "("):
            take("punct", "(")
            args = []
            while not peek("punct", ")"):
                args.append(pred())
                if not peek("punct", ")"):
                    take("punct", ",")
            take("punct", ")")
            if name == "not" and len(args) != 1:
                raise ValueError("cannot parse cfg(%s)" % expr)
            return (name, args)
        if peek("punct", "="):
            take("punct", "=")
            return ("pred", name, take("str"))
        return ("pred", name, None)

    tree = pred()
    if pos[0] != len(toks):
        raise ValueError("cannot parse cfg(%s)" % expr)
    return tree


def eval_cfg(tree, cfg):
    """Three-valued: True, False or UNKNOWN on one target's printed cfg."""
    kind = tree[0]
    if kind == "pred":
        name, value = tree[1], tree[2]
        if value is None and name in ("true", "false"):
            return name == "true"
        if name not in CFG_KNOWN:
            return UNKNOWN
        return (name, value) in cfg
    vals = [eval_cfg(t, cfg) for t in tree[1]]
    if kind == "not":
        return UNKNOWN if vals[0] is UNKNOWN else not vals[0]
    if kind == "all":
        return False if False in vals else (UNKNOWN if UNKNOWN in vals else True)
    return True if True in vals else (UNKNOWN if UNKNOWN in vals else False)


class Platforms:
    """The checked Linux targets and their cfg, from rustc."""

    def __init__(self, root, triples):
        self.cfgs = {}
        for t in triples:
            res = run(["rustc", "--print", "cfg", "--target", t], root)
            if res.returncode != 0:
                sys.stderr.write(res.stderr)
                raise ToolError(POLICY, "rustc --print cfg --target %s failed" % t)
            cfg = set()
            for line in res.stdout.splitlines():
                name, _, value = line.partition("=")
                cfg.add((name, value[1:-1] if value else None))
            self.cfgs[t] = cfg
        self.cache = {}

    def applies(self, target):
        """False only when the target spec is false on every checked platform
        under every value of the unknown names; a malformed cfg is a tool error."""
        if target is None:
            return True
        if target not in self.cache:
            if target.startswith("cfg(") and target.endswith(")"):
                try:
                    tree = parse_cfg(target[4:-1])
                except ValueError as err:
                    raise ToolError("Cargo.toml", "%s in a dependency target" % err) from err
                self.cache[target] = any(eval_cfg(tree, c) is not False for c in self.cfgs.values())
            else:
                self.cache[target] = target in self.cfgs
        return self.cache[target]


def adr_files(root, number):
    adr_dir = root / "docs" / "adr"
    if not adr_dir.is_dir():
        return []
    return sorted(p for p in adr_dir.glob(number + "-*.md") if p.is_file())


def strip_html_comments(text):
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    cut = text.find("<!--")
    return text if cut < 0 else text[:cut]


class Policy:
    pass


def check_policy(data, root, rep):
    """Validate tools/architecture.toml; None when roles or check are unusable."""
    def bad(message):
        rep.fail("policy-format", POLICY, message)

    def names(value, where):
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            bad("%s must be an array of strings" % where)
            return None
        for v in value:
            if not POLICY_NAME.fullmatch(v):
                bad("%s: name %s is not [A-Za-z0-9_-]+" % (where, show(v)))
        return list(value)

    resolved = {}

    def resolves(ref):
        """True when ref is ADR-NNN with exactly one file docs/adr/NNN-*.md."""
        m = ADR_REF.fullmatch(ref)
        if not m:
            return False
        if ref not in resolved:
            resolved[ref] = adr_files(root, m.group(1))
        return len(resolved[ref]) == 1

    def decision(value, where):
        if not isinstance(value, str) or not value:
            bad("%s: missing or empty `decision`" % where)
        elif value != "ARCHITECTURE" and not ADR_REF.fullmatch(value):
            bad("%s: decision %s is neither ARCHITECTURE nor ADR-NNN" % (where, show(value)))
        elif value != "ARCHITECTURE" and not resolves(value):
            bad("%s: %s does not resolve to exactly one docs/adr/NNN-*.md" % (where, value))

    def reason(value, where):
        if not isinstance(value, str) or not value.strip():
            bad("%s: missing or empty `reason`" % where)

    for key in data:
        if key not in ("roles", "check", "external"):
            bad("unknown top-level table [%s]" % show(key))

    pol = Policy()
    roles = data.get("roles")
    check = data.get("check")
    usable = True
    if not isinstance(roles, dict):
        bad("missing [roles]")
        usable = False
    else:
        for key in roles:
            if key not in ("core", "support", "roots", "unsafe", "build-script"):
                bad("unknown key roles.%s" % show(key))
        for key in ("core", "support", "roots", "unsafe", "build-script"):
            value = names(roles.get(key), "roles." + key)
            if value is None:
                usable = False
            setattr(pol, key.replace("-", "_"), value or [])
    if not isinstance(check, dict):
        bad("missing [check]")
        usable = False
    else:
        for key in check:
            if key not in ("platforms", "no-std-target"):
                bad("unknown key check.%s" % show(key))
        platforms = check.get("platforms")
        target = check.get("no-std-target")
        if not isinstance(platforms, list) or not platforms or not all(isinstance(p, str) and p for p in platforms):
            bad("check.platforms must be a non-empty array of strings")
            usable = False
        if not isinstance(target, str) or not target:
            bad("check.no-std-target must be a string")
            usable = False
        pol.platforms, pol.no_std_target = platforms, target
    if not usable:
        return None

    groups = {"core": pol.core, "support": pol.support, "roots": pol.roots}
    seen = {}
    for group, members in groups.items():
        for name in members:
            if name in seen and seen[name] != group:
                bad("%s is in both roles.%s and roles.%s" % (name, seen[name], group))
            seen.setdefault(name, group)
    for name in pol.unsafe:
        if name in pol.core:
            bad("%s is in both roles.core and roles.unsafe" % name)
    for name in pol.build_script:
        if name in pol.core:
            bad("%s is in both roles.core and roles.build-script" % name)

    pol.edges = {}
    pol.strict = {}
    external = data.get("external", {})
    if not isinstance(external, dict):
        bad("[external] must be a table")
        external = {}
    for crate, table in external.items():
        where = "[external.%s]" % show(crate)
        if not POLICY_NAME.fullmatch(crate):
            bad("%s: name is not [A-Za-z0-9_-]+" % where)
        if not isinstance(table, dict):
            bad("%s must be a table" % where)
            continue
        for key in table:
            if key not in ("reason", "decision", "strict", "pulled-by"):
                bad("%s: unknown key %s" % (where, show(key)))
        reason(table.get("reason"), where)
        decision(table.get("decision"), where)
        if "strict" in table:
            marker = table["strict"]
            # Any strict key makes the crate strict, a malformed one included.
            pol.strict[crate] = marker
            if not isinstance(marker, str) or not ADR_REF.fullmatch(marker):
                bad("%s: strict must be \"ADR-NNN\"" % where)
            elif not resolves(marker):
                bad("%s: strict %s does not resolve to exactly one docs/adr/NNN-*.md" % (where, marker))
        parents = table.get("pulled-by")
        if not isinstance(parents, dict) or not parents:
            bad("%s: no edge record [external.%s.pulled-by.<parent>]" % (where, show(crate)))
            continue
        for parent, record in parents.items():
            ewhere = "[external.%s.pulled-by.%s]" % (show(crate), show(parent))
            if not POLICY_NAME.fullmatch(parent):
                bad("%s: name is not [A-Za-z0-9_-]+" % ewhere)
            if parent in pol.core:
                bad("%s: core crates take no external dependencies" % ewhere)
            if not isinstance(record, dict):
                bad("%s must be a table" % ewhere)
                continue
            for key in record:
                if key not in ("reason", "decision"):
                    bad("%s: unknown key %s" % (ewhere, show(key)))
            reason(record.get("reason"), ewhere)
            decision(record.get("decision"), ewhere)
            pol.edges[(parent, crate)] = record

    # Strict crates: every edge cites its own accepted ADR that names it.
    for crate in pol.strict:
        parents = dig(external, crate, "pulled-by")
        if not isinstance(parents, dict):
            continue
        for parent, record in parents.items():
            ewhere = "[external.%s.pulled-by.%s]" % (show(crate), show(parent))
            ref = record.get("decision") if isinstance(record, dict) else None
            edge = "`%s -> %s`" % (parent, crate)
            if not isinstance(ref, str) or not ADR_REF.fullmatch(ref):
                rep.fail("policy-strict", POLICY,
                         "%s: %s is strict, so this edge needs its own accepted ADR, not %s"
                         % (ewhere, crate, show(str(ref))))
                continue
            if not resolves(ref):
                rep.fail("policy-strict", POLICY, "%s: %s does not resolve to exactly one ADR file" % (ewhere, ref))
                continue
            adr = resolved[ref][0]
            text = strip_html_comments(read_text(adr, root))
            status = next((ln for ln in text.split("\n") if ln.startswith("- Status:")), None)
            if status is None or status.rstrip("\r") != "- Status: accepted":
                rep.fail("policy-strict", rel(root, adr), "%s is not accepted (cited by %s)" % (ref, ewhere))
            if edge not in text:
                rep.fail("policy-strict", rel(root, adr), "%s does not name the edge %s (cited by %s)" % (ref, edge, ewhere))
    return pol


def cargo_metadata(root):
    # No --filter-platform: cargo evaluates cfg() without the flags a real
    # build uses (crt-static, custom --cfg), so edges are filtered here.
    args = ["cargo", "metadata", "--format-version", "1", "--locked", "--all-features",
            "--manifest-path", str(root / "Cargo.toml")]
    res = run(args, root)
    if res.returncode != 0:
        sys.stderr.write(res.stderr)
        first = next((ln for ln in res.stderr.splitlines() if ln.startswith("error")), "see stderr")
        raise ToolError("Cargo.toml", "cargo metadata --locked failed (is Cargo.lock committed and current?): " + first)
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError as err:
        raise ToolError("Cargo.toml", "cargo metadata printed invalid JSON") from err


def walk_config_files(root, skip):
    """Cargo, clippy and rustup toolchain files anywhere in the tree."""
    cargo, clippy, toolchain = [], [], []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            p = here / d
            if d == ".git" or p.resolve() in skip:
                continue
            if (p / ".git").exists() and p != root:
                continue  # a nested checkout, such as a git worktree
            kept.append(d)
        dirnames[:] = kept
        for name in ("config", "config.toml"):
            p = here / ".cargo" / name
            if p.exists() or p.is_symlink():
                cargo.append(p)
        for name in sorted(filenames):
            if name in ("clippy.toml", ".clippy.toml"):
                clippy.append(here / name)
            if name in ("rust-toolchain", "rust-toolchain.toml"):
                toolchain.append(here / name)
    return cargo, clippy, toolchain


def check(root):
    rep = Report()
    policy = load_toml(root / POLICY, root)
    manifest = load_toml(root / "Cargo.toml", root)
    pol = check_policy(policy, root, rep)
    if pol is None:
        return rep

    # Files that change which tools run or how: checked before any cargo
    # call, because a toolchain file can replace cargo itself.
    skip = {(root / "target").resolve()}
    if os.environ.get("CARGO_TARGET_DIR"):
        skip.add(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
    cargo_cfg, clippy_cfg, toolchain = walk_config_files(root, skip)
    for p in cargo_cfg:
        rep.fail("cargo-config", rel(root, p), "a cargo config can cap lints, replace sources, patch or wrap rustc")
    for p in clippy_cfg:
        rep.fail("clippy-config", rel(root, p), "a clippy config can relax lints")
    for p in toolchain:
        rep.fail("toolchain-file", rel(root, p), "a toolchain file picks the cargo and rustc that CI and this check run")

    platforms = Platforms(root, pol.platforms)
    # Core crates are also built for the no-std target, so their edges are
    # evaluated there too.
    core_platforms = Platforms(root, pol.platforms + [pol.no_std_target])
    meta = cargo_metadata(root)
    packages = {p["id"]: p for p in meta["packages"]}
    member_ids = set(meta["workspace_members"])
    members = sorted((packages[i] for i in member_ids), key=lambda p: p["manifest_path"])
    member_dirs = {Path(p["manifest_path"]).parent.resolve(): p for p in members}
    names = {p["name"] for p in members}

    def mpath(pkg):
        return rel(root, pkg["manifest_path"])

    # Manifest-level rules.
    lvl = dig(manifest, "workspace", "lints", "rust", "unsafe_code")
    if isinstance(lvl, dict):
        lvl = lvl.get("level")
    if lvl != "forbid":
        rep.fail("lints-unsafe", "Cargo.toml", "workspace.lints.rust.unsafe_code must be \"forbid\" (found %s)" % ("nothing" if lvl is None else show(str(lvl))))
    for key in ("patch", "replace"):
        if key in manifest:
            rep.fail("manifest-redirect", "Cargo.toml", "[%s] redirects dependencies past the source check" % key)
    if dig(manifest, "workspace", "exclude") is not None:
        rep.fail("manifest-redirect", "Cargo.toml", "workspace.exclude keeps path crates out of the member rules")

    for core in pol.core:
        if core not in names:
            rep.fail("core-missing", "Cargo.toml", "core crate %s is not a workspace member" % core)

    # Per-member rules.
    texts = {}
    for pkg in members:
        name = pkg["name"]
        pkg_dir = Path(pkg["manifest_path"]).parent
        is_core = name in pol.core
        is_unsafe = name in pol.unsafe
        if not MEMBER_NAME.fullmatch(name):
            rep.fail("member-name", mpath(pkg), "%s: every workspace crate is named boneli-<name>" % name)

        member_manifest = load_toml(Path(pkg["manifest_path"]), root)
        if not is_unsafe and member_manifest.get("lints") != {"workspace": True}:
            rep.fail("lints-inherit", mpath(pkg), "%s: [lints] must be exactly `workspace = true`" % name)

        files, others, links = walk_package(pkg_dir)
        for link in links:
            rep.fail("symlink", rel(root, link), "symlinks in a package are not followed by the scans")

        lib_roots = []
        for t in pkg["targets"]:
            src = Path(t["src_path"])
            inside = pkg_dir.resolve() in src.resolve().parents
            if not inside:
                rep.fail("source-redirect", mpath(pkg), "target %s reads %s, outside the package" % (t["name"], rel(root, src)))
            if not src.name.endswith(".rs"):
                # The scans read .rs files; a crate root under another name
                # would be invisible to them. It is scanned below anyway.
                rep.fail("source-redirect", mpath(pkg), "target %s has source %s, not a .rs file" % (t["name"], rel(root, src)))
                if inside and src not in files and not src.is_symlink():
                    files.append(src)
            if "proc-macro" in t["kind"]:
                rep.fail("proc-macro", mpath(pkg), "%s: proc macros can emit unsafe that no scan sees" % name)
            if "custom-build" in t["kind"] and name not in pol.build_script:
                rep.fail("build-script", mpath(pkg), "%s: a build script can compile and link native code no scan sees" % name)
            if LIB_KINDS.intersection(t["kind"]):
                lib_roots.append(src)
        for f in files:
            if f not in texts:
                texts[f] = read_text(f, root)
        for src in lib_roots:
            attrs = leading_attributes(texts.get(src) or read_text(src, root))
            if not is_unsafe and DOCTEST_ATTR not in attrs:
                rep.fail("doctest-unsafe", rel(root, src), "lib root lacks %s in its leading attribute block" % DOCTEST_ATTR)
            if is_core and NO_STD_ATTR not in attrs:
                rep.fail("core-no-std-attr", rel(root, src), "core lib root lacks an unconditional #![no_std] in its leading attribute block")

        if is_core:
            kinds = [(t["kind"], t["crate_types"]) for t in pkg["targets"]]
            libs = [k for k in kinds if k == (["lib"], ["lib"])]
            extra = [k for k in kinds if k != (["lib"], ["lib"]) and k[0] != ["test"]]
            if len(libs) != 1 or extra:
                rep.fail("core-targets", mpath(pkg), "%s: a core crate has one lib target and test targets only" % name)
            if pkg["features"]:
                rep.fail("core-features", mpath(pkg), "%s: a core crate declares no features" % name)

        for f in files:
            text = texts[f]
            code = blank_comment_lines(text)
            if not is_unsafe:
                for m in UNSAFE.finditer(code):
                    rep.fail("unsafe-token", rel(root, f), "`unsafe` outside %s" % ", ".join(pol.unsafe), line_of(code, m.start()))
            else:
                for m in MACRO_EXPORT.finditer(code):
                    rep.fail("sys-macro-export", rel(root, f), "an exported macro would carry unsafe out of %s" % name, line_of(code, m.start()))
            toks, error = tokenize(text)
            if error:
                rep.fail("source-redirect", rel(root, f), error, 1)
            for line, message in source_redirects(toks):
                rep.fail("source-redirect", rel(root, f), message, line)
            if is_core:
                for rx in CORE_TOKENS:
                    for m in rx.finditer(code):
                        rep.fail("core-token", rel(root, f), "banned in core crates: %s" % show(m.group(0)), line_of(code, m.start()))
                for m in FORMAT_SPEC.finditer(text):
                    rep.fail("core-token", rel(root, f), "banned in core crates: format spec %s" % show(m.group(0)), line_of(text, m.start()))
                for line, message in fmt_imports(toks):
                    rep.fail("core-token", rel(root, f), message, line)
                for m in EXTERN_CRATE.finditer(code):
                    if not EXTERN_ALLOC.match(code, m.end()):
                        rep.fail("core-token", rel(root, f), "banned in core crates: extern crate (only `extern crate alloc;`)", line_of(code, m.start()))
                for k, (kind, value, line) in enumerate(toks):
                    if kind == "str":
                        raw, body = value
                        m = FORMAT_SPEC.search(body if raw else unescape(body))
                        if m:
                            rep.fail("core-token", rel(root, f), "banned in core crates: format spec %s (after escapes)" % show(m.group(0)), line)
                    if kind == "ident" and value in ("include_str", "include_bytes"):
                        lit = toks[k + 3] if k + 4 < len(toks) else None
                        ok = (lit is not None and toks[k + 1][:2] == ("punct", "!") and toks[k + 2][0] == "punct"
                              and lit[0] == "str" and toks[k + 4][0] == "punct")
                        if ok:
                            target = (f.parent / (lit[1][1] if lit[1][0] else unescape(lit[1][1]))).resolve()
                            ok = pkg_dir.resolve() in target.parents
                        if not ok:
                            rep.fail("core-token", rel(root, f), "%s! must take one literal path inside the package" % value, line)
        if is_core:
            # include_str! turns these into string literals, format strings
            # included.
            for f in others:
                try:
                    data = f.read_bytes().decode("utf-8", errors="replace")
                except OSError as err:
                    raise ToolError(rel(root, f), "cannot read: %s" % err.strerror) from err
                for m in FORMAT_SPEC.finditer(data):
                    rep.fail("core-token", rel(root, f), "banned in core crates: format spec %s" % show(m.group(0)), line_of(data, m.start()))

        # Graph rules over declared dependencies on other members.
        if not MEMBER_NAME.fullmatch(name):
            continue
        plats = core_platforms if name in pol.core else platforms
        for dep in pkg["dependencies"]:
            if dep["kind"] == "dev" or not plats.applies(dep.get("target")):
                continue
            target = member_dirs.get(Path(dep["path"]).resolve()) if dep.get("path") else None
            if target is None:
                # External: core crates take none (dev-dependencies aside).
                if name == DOMAIN:
                    rep.fail("graph-domain", mpath(pkg), "%s -> %s: the domain depends on nothing" % (name, dep["name"]))
                elif name == APP:
                    rep.fail("graph-app", mpath(pkg), "%s -> %s: the application depends only on the domain" % (name, dep["name"]))
                continue
            dname = target["name"]
            if dname in pol.roots:
                rep.fail("graph-root-leaf", mpath(pkg), "%s -> %s: composition roots must stay leaves" % (name, dname))
            elif name == DOMAIN:
                rep.fail("graph-domain", mpath(pkg), "%s -> %s: the domain depends on nothing" % (name, dname))
            elif name == APP:
                if dname != DOMAIN:
                    rep.fail("graph-app", mpath(pkg), "%s -> %s: the application depends only on the domain" % (name, dname))
            elif name in pol.support:
                if dname not in pol.support:
                    rep.fail("graph-support", mpath(pkg), "%s -> %s: support crates stay generic (support crates only)" % (name, dname))
            elif name not in pol.roots:
                if dname not in (DOMAIN, APP) and dname not in pol.support:
                    rep.fail("graph-adapter", mpath(pkg), "%s -> %s: adapters depend on the domain, the application and support crates only" % (name, dname))

    # The graph that builds on a checked platform: edges whose target is not
    # false everywhere, reachable from the members.
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    reachable, todo, edges = set(member_ids), sorted(member_ids), []
    while todo:
        pid = todo.pop()
        plats = core_platforms if pid in member_ids and packages[pid]["name"] in pol.core else platforms
        for d in nodes[pid]["deps"]:
            kinds = [k for k in d["dep_kinds"] if plats.applies(k.get("target"))]
            if not kinds:
                continue
            edges.append((pid, d["pkg"], kinds))
            if d["pkg"] not in reachable:
                reachable.add(d["pkg"])
                todo.append(d["pkg"])

    # Sources: crates.io only, path dependencies only to members. Declared
    # dependencies count on every target; an unreachable package can only
    # come from one of them, because crates.io crates cannot depend on git
    # or path crates.
    for pid, pkg in sorted(packages.items()):
        if pid in reachable and pid not in member_ids and pkg.get("source") != CRATES_IO:
            rep.fail("dep-source", "Cargo.lock", "%s %s comes from %s, not crates.io" % (pkg["name"], pkg["version"], pkg.get("source") or "a path"))
    for pkg in members:
        for dep in pkg["dependencies"]:
            if dep.get("path"):
                if Path(dep["path"]).resolve() not in member_dirs:
                    rep.fail("dep-source", mpath(pkg), "%s -> %s: path dependency outside the workspace members" % (pkg["name"], dep["name"]))
            elif dep.get("source") != CRATES_IO:
                rep.fail("dep-source", mpath(pkg), "%s -> %s: source %s is not crates.io" % (pkg["name"], dep["name"], dep.get("source")))

    # Edges into external crates, over the resolved graph.
    for pid, cid, dep_kinds in sorted(edges, key=lambda e: (e[0], e[1])):
        if cid in member_ids:
            continue
        parent, child = packages[pid]["name"], packages[cid]["name"]
        if (parent, child) not in pol.edges:
            kinds = sorted({k["kind"] or "normal" for k in dep_kinds})
            rep.fail("dep-edge", POLICY, "%s -> %s (%s): no record [external.%s.pulled-by.%s]"
                     % (parent, child, ", ".join(kinds), child, parent))

    # The core must build for a target without std.
    core_ids = [p["id"] for p in members if p["name"] in pol.core]
    if core_ids:
        target = pol.no_std_target
        res = run(["rustc", "--print", "target-libdir", "--target", target], root)
        libdir = Path(res.stdout.strip()) if res.returncode == 0 else None
        if libdir is None or not libdir.is_dir() or not any(libdir.glob("libcore-*")):
            sys.stderr.write("rustup target add %s\n" % target)
            raise ToolError(POLICY, "Rust target %s is not installed (rustup target add %s)" % (target, target))
        args = ["cargo", "check", "--locked", "--lib", "--target", target, "--message-format", "short",
                "--manifest-path", str(root / "Cargo.toml")]
        for pid in core_ids:
            args += ["-p", pid]
        res = run(args, root)
        if res.returncode != 0:
            sys.stderr.write(res.stderr)
            for pkg in members:
                if pkg["id"] in core_ids:
                    rep.fail("core-no-std-build", mpath(pkg), "core crates must build for %s (no std); cargo output on stderr" % target)
    return rep


def checker_main(root):
    try:
        rep = check(root)
    except ToolError as err:
        print("FAIL [tool-error] %s: %s" % (err.path, err.message))
        print("1 violation(s)")
        return 2
    except Exception as err:  # noqa: BLE001 - any crash is a tool error, never exit 0 or 1
        print("FAIL [tool-error] tools/check_architecture.py: internal error: %s" % show(repr(err)))
        print("1 violation(s)")
        return 2
    for rule, path, line, message in rep.items:
        where = path if line is None else "%s:%d" % (path, line)
        print("FAIL [%s] %s: %s" % (rule, where, message))
    if rep.items:
        print("%d violation(s)" % len(rep.items))
        return 1
    print("OK: crate graph, lints, unsafe containment, core purity, sources and dependency edges")
    return 0


# ---------------------------------------------------------------- fixtures

FAIL_LINE = re.compile(r"FAIL \[([a-z0-9-]+)\] \S.*")
SUMMARY = re.compile(r"OK: .*|([0-9]+) violation\(s\)")


def toml_string(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def assemble(fixtures, case_dir, snippet, tmp):
    """Build one fixture workspace under tmp; returns its root."""
    ws = tmp / "ws"
    shutil.copytree(fixtures / "base", ws, symlinks=True)
    (ws / "tools").mkdir()
    shutil.copy(REPO / POLICY, ws / POLICY)
    (ws / "docs").mkdir()
    shutil.copy(REPO / "docs" / "ARCHITECTURE.md", ws / "docs" / "ARCHITECTURE.md")
    shutil.copytree(REPO / "docs" / "adr", ws / "docs" / "adr")

    overlay = case_dir / "overlay"
    if overlay.is_dir():
        for dirpath, dirnames, filenames in os.walk(overlay):
            for name in filenames + [d for d in dirnames if (Path(dirpath) / d).is_symlink()]:
                src = Path(dirpath) / name
                dest = ws / src.relative_to(overlay)
                if dest.name.endswith(".fixture"):
                    dest = dest.with_name(dest.name[: -len(".fixture")])
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.is_symlink() or dest.exists():
                    dest.unlink()
                if src.is_symlink():
                    os.symlink(os.readlink(src), dest)
                else:
                    shutil.copyfile(src, dest)
    remove = case_dir / "remove"
    if remove.is_file():
        for line in remove.read_text(encoding="utf-8").splitlines():
            if line.strip():
                p = ws / line.strip()
                shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
    append = case_dir / "policy-append"
    if append.is_file():
        with open(ws / POLICY, "a", encoding="utf-8") as fh:
            fh.write("\n" + append.read_text(encoding="utf-8"))
    if snippet is not None:
        (ws / "crates/boneli-domain/src/extra.rs").write_text(snippet + "\n", encoding="utf-8")
    outside = case_dir / "outside"
    if outside.is_dir():
        shutil.copytree(outside, tmp / "outside", symlinks=True)

    git_dir = case_dir / "git"
    if git_dir.is_dir():
        for repo in sorted(git_dir.iterdir()):
            dest = tmp / "git" / repo.name
            shutil.copytree(repo, dest)
            for args in (["init", "-q"], ["add", "-A"],
                         ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                          "commit", "-q", "-m", "fixture"]):
                res = run(["git"] + args, dest)
                if res.returncode != 0:
                    raise ToolError(rel(REPO, repo), "git %s failed: %s" % (args[0], res.stderr.strip()))
            marker = "@GIT:%s@" % repo.name
            for dirpath, _, filenames in os.walk(ws):
                for name in filenames:
                    p = Path(dirpath) / name
                    if p.is_symlink():
                        continue
                    data = p.read_bytes()
                    if marker.encode() in data:
                        p.write_bytes(data.replace(marker.encode(), dest.as_uri().encode()))

    # Fake crates.io: a directory source above the workspace.
    registry = tmp / "registry"
    shutil.copytree(fixtures / "registry", registry)
    for crate_dir in registry.iterdir():
        files = {}
        for dirpath, _, filenames in os.walk(crate_dir):
            for name in filenames:
                p = Path(dirpath) / name
                files[p.relative_to(crate_dir).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
        package = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
        (crate_dir / ".cargo-checksum.json").write_text(json.dumps({"files": files, "package": package}))
    (tmp / ".cargo").mkdir()
    (tmp / ".cargo" / "config.toml").write_text(
        '[source.crates-io]\nreplace-with = "arch-fixtures"\n\n'
        "[source.arch-fixtures]\ndirectory = %s\n" % toml_string(str(registry)),
        encoding="utf-8",
    )
    return ws


def run_case(fixtures, case_dir, snippet, rules, env):
    """Returns None when the run matches its expect file, else a report."""
    expect = set()
    for line in (case_dir / "expect").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            if line not in rules:
                return "expect names unknown rule %s" % line
            expect.add(line)
    tmp = Path(tempfile.mkdtemp(prefix="boneli arch "))
    try:
        ws = assemble(fixtures, case_dir, snippet, tmp)
        lock = ["cargo", "generate-lockfile"]
        if not (case_dir / "git").is_dir():
            lock.append("--offline")
        run(lock, ws, env)  # a failure here is the checker's to report
        res = run([sys.executable, "-I", str(SCRIPT), "--root", str(ws)], ws, env)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    got, problems = set(), []
    lines = res.stdout.splitlines()
    fails = 0
    for i, line in enumerate(lines):
        m = FAIL_LINE.fullmatch(line)
        s = SUMMARY.fullmatch(line)
        if m:
            got.add(m.group(1))
            fails += 1
        elif s and i == len(lines) - 1:
            if s.group(1) is None and fails:
                problems.append("OK after FAIL lines")
            if s.group(1) is not None and int(s.group(1)) != fails:
                problems.append("count %s != %d FAIL lines" % (s.group(1), fails))
        else:
            problems.append("unparseable line: %s" % show(line))
    if not lines or not SUMMARY.fullmatch(lines[-1]):
        problems.append("no summary line")
    want_exit = 2 if "tool-error" in expect else (1 if expect else 0)
    if res.returncode != want_exit:
        problems.append("exit %d, expected %d" % (res.returncode, want_exit))
    if got != expect:
        problems.append("expected %s, got %s" % (sorted(expect), sorted(got)))
    if problems:
        return "; ".join(problems) + "\n--- stdout\n" + res.stdout + "--- stderr\n" + res.stderr[-4000:]
    return None


def run_fixtures():
    fixtures = REPO / "tools" / "fixtures" / "arch"
    env = dict(os.environ, CARGO_TARGET_DIR=str(REPO / "target" / "arch-fixtures"))
    env.pop("RUSTFLAGS", None)
    rules = set(RULES)
    cases = sorted(p for p in (fixtures / "cases").iterdir() if p.is_dir())
    runs, failures, covered = 0, [], set()

    # base: an empty case directory, which must give no FAIL line.
    with tempfile.TemporaryDirectory(prefix="boneli arch base ") as empty:
        Path(empty, "expect").write_text("")
        report = run_case(fixtures, Path(empty), None, rules, env)
        runs += 1
        if report:
            failures.append("base: " + report)
        print("%-48s %s" % ("base", "ok" if report is None else "MISMATCH"), flush=True)

    for case_dir in cases:
        for line in (case_dir / "expect").read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                covered.add(line.strip())
        snippets = [None]
        if (case_dir / "snippets").is_file():
            snippets = [s for s in (case_dir / "snippets").read_text(encoding="utf-8").split("\n") if s.strip()]
        for n, snippet in enumerate(snippets, 1):
            label = case_dir.name if snippet is None else "%s #%d" % (case_dir.name, n)
            report = run_case(fixtures, case_dir, snippet, rules, env)
            runs += 1
            if report:
                failures.append("%s: %s" % (label, report))
            print("%-48s %s" % (label, "ok" if report is None else "MISMATCH"), flush=True)

    uncovered = sorted(rules - covered)
    if uncovered:
        failures.append("rules without a fixture: " + ", ".join(uncovered))
    for f in failures:
        print("\n" + f)
    if failures:
        print("\nfixtures: %d run(s), %d problem(s)" % (runs, len(failures)))
        return 1
    print("\nfixtures: %d run(s) in %d case(s), all match; every rule is pinned" % (runs, len(cases)))
    return 0


def main(argv):
    root = REPO
    args = list(argv)
    if args == ["--list-rules"]:
        print("\n".join(RULES))
        return 0
    if args == ["--fixtures"]:
        return run_fixtures()
    if len(args) == 2 and args[0] == "--root":
        root = Path(args[1]).resolve()
    elif args:
        sys.stderr.write("usage: check-architecture.sh [--root <dir> | --list-rules | --fixtures]\n")
        return 2
    return checker_main(root)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
