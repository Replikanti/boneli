//! Target cfg evaluation (ADR-001, D3): cargo's `cfg(...)` expressions,
//! three-valued over the cfg that rustc prints for each checked target.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use crate::rules::ToolError;
use crate::text::{is_space, splitlines};

/// How deeply `all`, `any` and `not` may nest: the next power of two above
/// ten times the deepest dependency cfg in the workspace (3), so the parser
/// recursion stays bounded (ADR-015, D4).
pub(crate) const MAX_CFG_DEPTH: usize = 32;

/// Names whose whole value set rustc prints for a target with no flags: a
/// value it does not print is false. Every other name (`target_feature`,
/// `panic`, `debug_assertions`, `overflow_checks`, custom cfgs, ...)
/// depends on flags or the profile and is unknown.
const CFG_KNOWN: [&str; 11] = [
    "target_os",
    "target_family",
    "target_arch",
    "target_env",
    "target_abi",
    "target_vendor",
    "target_endian",
    "target_pointer_width",
    "target_has_atomic",
    "unix",
    "windows",
];

/// A parsed cfg predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Cfg {
    /// `name` or `name = "value"`.
    Pred(String, Option<String>),
    /// `all(...)`.
    All(Vec<Cfg>),
    /// `any(...)`.
    Any(Vec<Cfg>),
    /// `not(...)`, exactly one argument.
    Not(Box<Cfg>),
}

/// A three-valued truth value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tri {
    True,
    False,
    Unknown,
}

/// One target's printed cfg: names with their values (`None` for a bare
/// name).
pub(crate) type CfgSet = BTreeSet<(String, Option<String>)>;

#[derive(Debug, PartialEq, Eq)]
enum Tok<'a> {
    Ident(&'a str),
    Str(&'a str),
    Punct(char),
}

fn tokens(expr: &str) -> Option<Vec<Tok<'_>>> {
    let mut toks = Vec::new();
    let mut rest = expr;
    loop {
        rest = rest.trim_start_matches(is_space);
        if rest.is_empty() {
            return Some(toks);
        }
        let bytes = rest.as_bytes();
        let ident_start = |b: u8| b.is_ascii_alphabetic() || b == b'_';
        let ident_cont = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        let prefix = if rest.starts_with("r#") && bytes.get(2).is_some_and(|&b| ident_start(b)) {
            2
        } else {
            0
        };
        if bytes.get(prefix).is_some_and(|&b| ident_start(b)) {
            let len = prefix
                + 1
                + bytes[prefix + 1..]
                    .iter()
                    .take_while(|&&b| ident_cont(b))
                    .count();
            toks.push(Tok::Ident(&rest[..len]));
            rest = &rest[len..];
        } else if bytes[0] == b'"' {
            let body = rest[1..].find(['"', '\\'])?;
            if bytes[1 + body] != b'"' {
                return None;
            }
            toks.push(Tok::Str(&rest[1..1 + body]));
            rest = &rest[body + 2..];
        } else if matches!(bytes[0], b'(' | b')' | b',' | b'=') {
            toks.push(Tok::Punct(char::from(bytes[0])));
            rest = &rest[1..];
        } else {
            return None;
        }
    }
}

struct Parser<'a> {
    toks: Vec<Tok<'a>>,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek_punct(&self, c: char) -> bool {
        self.toks.get(self.pos) == Some(&Tok::Punct(c))
    }

    fn take_punct(&mut self, c: char) -> Option<()> {
        self.peek_punct(c).then(|| self.pos += 1)
    }

    fn pred(&mut self, depth: usize) -> Option<Cfg> {
        let Some(Tok::Ident(name)) = self.toks.get(self.pos) else {
            return None;
        };
        let name = name.strip_prefix("r#").unwrap_or(name);
        self.pos += 1;
        if matches!(name, "all" | "any" | "not") && self.peek_punct('(') {
            if depth >= MAX_CFG_DEPTH {
                return None;
            }
            self.take_punct('(')?;
            let mut args = Vec::new();
            while !self.peek_punct(')') {
                args.push(self.pred(depth + 1)?);
                if !self.peek_punct(')') {
                    self.take_punct(',')?;
                }
            }
            self.take_punct(')')?;
            return match name {
                "all" => Some(Cfg::All(args)),
                "any" => Some(Cfg::Any(args)),
                _ => {
                    let mut args = args.into_iter();
                    match (args.next(), args.next()) {
                        (Some(one), None) => Some(Cfg::Not(Box::new(one))),
                        _ => None,
                    }
                }
            };
        }
        if self.take_punct('=').is_some() {
            let Some(Tok::Str(value)) = self.toks.get(self.pos) else {
                return None;
            };
            self.pos += 1;
            return Some(Cfg::Pred(name.to_owned(), Some((*value).to_owned())));
        }
        Some(Cfg::Pred(name.to_owned(), None))
    }
}

/// Parses a cargo cfg expression (without the outer `cfg(...)`). Deeper
/// than [`MAX_CFG_DEPTH`] combinators is an error like any other.
pub(crate) fn parse_cfg(expr: &str) -> Result<Cfg, String> {
    let error = || format!("cannot parse cfg({expr})");
    let toks = tokens(expr).ok_or_else(error)?;
    let mut p = Parser { toks, pos: 0 };
    let tree = p.pred(0).ok_or_else(error)?;
    if p.pos != p.toks.len() {
        return Err(error());
    }
    Ok(tree)
}

/// The value of `tree` on one target's printed cfg.
pub(crate) fn eval_cfg(tree: &Cfg, cfg: &CfgSet) -> Tri {
    match tree {
        Cfg::Pred(name, None) if name == "true" => Tri::True,
        Cfg::Pred(name, None) if name == "false" => Tri::False,
        Cfg::Pred(name, value) => {
            if !CFG_KNOWN.contains(&name.as_str()) {
                Tri::Unknown
            } else if cfg.contains(&(name.clone(), value.clone())) {
                Tri::True
            } else {
                Tri::False
            }
        }
        Cfg::Not(inner) => match eval_cfg(inner, cfg) {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        },
        Cfg::All(args) => {
            let vals: Vec<Tri> = args.iter().map(|a| eval_cfg(a, cfg)).collect();
            if vals.contains(&Tri::False) {
                Tri::False
            } else if vals.contains(&Tri::Unknown) {
                Tri::Unknown
            } else {
                Tri::True
            }
        }
        Cfg::Any(args) => {
            let vals: Vec<Tri> = args.iter().map(|a| eval_cfg(a, cfg)).collect();
            if vals.contains(&Tri::True) {
                Tri::True
            } else if vals.contains(&Tri::Unknown) {
                Tri::Unknown
            } else {
                Tri::False
            }
        }
    }
}

/// Reads the output of `rustc --print cfg`.
pub(crate) fn parse_printed_cfg(stdout: &str) -> CfgSet {
    splitlines(stdout)
        .into_iter()
        .map(|line| match line.split_once('=') {
            Some((name, "")) => (name.to_owned(), None),
            Some((name, value)) => {
                let inner = value.char_indices().nth(1).map_or("", |(start, _)| {
                    let end = value.char_indices().last().map_or(0, |(i, _)| i);
                    if start <= end { &value[start..end] } else { "" }
                });
                (name.to_owned(), Some(inner.to_owned()))
            }
            None => (line.to_owned(), None),
        })
        .collect()
}

/// The printed cfg of each target, from rustc, each target run once in
/// the order first named, so the first failure names the same target as
/// before.
pub(crate) struct Rustc {
    cfgs: BTreeMap<String, CfgSet>,
}

impl Rustc {
    /// Runs `rustc --print cfg --target <t>` for every distinct target of
    /// `triples`, with `root` as the working directory.
    pub(crate) fn probe<'a>(
        root: &Path,
        triples: impl IntoIterator<Item = &'a str>,
    ) -> Result<Rustc, ToolError> {
        let mut cfgs = BTreeMap::new();
        for t in triples {
            if cfgs.contains_key(t) {
                continue;
            }
            let out = crate::check::run(
                Command::new("rustc")
                    .args(["--print", "cfg", "--target", t])
                    .current_dir(root),
                "rustc",
            )?;
            if !out.status.success() {
                crate::check::forward_stderr(&out.stderr);
                return Err(ToolError::new(
                    crate::check::POLICY,
                    format!("rustc --print cfg --target {t} failed"),
                ));
            }
            cfgs.insert(
                t.to_owned(),
                parse_printed_cfg(&String::from_utf8_lossy(&out.stdout)),
            );
        }
        Ok(Rustc { cfgs })
    }

    /// The platforms for `triples`, all of them probed.
    pub(crate) fn platforms<'a>(&self, triples: impl IntoIterator<Item = &'a str>) -> Platforms {
        let mut cfgs = Vec::new();
        for t in triples {
            if let Some(cfg) = self.cfgs.get(t)
                && !cfgs.iter().any(|(name, _)| name == t)
            {
                cfgs.push((t.to_owned(), cfg.clone()));
            }
        }
        Platforms {
            cfgs,
            cache: BTreeMap::new(),
        }
    }
}

/// A set of checked targets and their cfg.
pub(crate) struct Platforms {
    cfgs: Vec<(String, CfgSet)>,
    cache: BTreeMap<String, bool>,
}

impl Platforms {
    #[cfg(test)]
    pub(crate) fn from_sets(cfgs: Vec<(String, CfgSet)>) -> Platforms {
        Platforms {
            cfgs,
            cache: BTreeMap::new(),
        }
    }

    /// False only when the target spec is false on every checked platform
    /// under every value of the unknown names; a malformed cfg is a tool
    /// error.
    pub(crate) fn applies(&mut self, target: Option<&str>) -> Result<bool, ToolError> {
        let Some(target) = target else {
            return Ok(true);
        };
        if let Some(&known) = self.cache.get(target) {
            return Ok(known);
        }
        let value = match target
            .strip_prefix("cfg(")
            .and_then(|t| t.strip_suffix(')'))
        {
            Some(expr) => {
                let tree = parse_cfg(expr).map_err(|err| {
                    ToolError::new("Cargo.toml", format!("{err} in a dependency target"))
                })?;
                self.cfgs
                    .iter()
                    .any(|(_, cfg)| eval_cfg(&tree, cfg) != Tri::False)
            }
            None => self.cfgs.iter().any(|(name, _)| name == target),
        };
        self.cache.insert(target.to_owned(), value);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{CfgSet, MAX_CFG_DEPTH, Platforms, Tri, eval_cfg, parse_cfg, parse_printed_cfg};
    use crate::py_vectors;

    fn fixed_target() -> CfgSet {
        [
            ("unix", None),
            ("target_os", Some("linux")),
            ("target_arch", Some("x86_64")),
            ("target_family", Some("unix")),
            ("target_has_atomic", Some("64")),
            ("debug_assertions", None),
        ]
        .into_iter()
        .map(|(n, v)| (n.to_owned(), v.map(str::to_owned)))
        .collect()
    }

    #[test]
    fn cfg_parse_and_eval_match_python() {
        let target = fixed_target();
        for &(input, want) in py_vectors::CFG {
            let got = parse_cfg(input).map(|tree| match eval_cfg(&tree, &target) {
                Tri::True => "true",
                Tri::False => "false",
                Tri::Unknown => "unknown",
            });
            assert_eq!(got.as_deref().map_err(String::as_str), want, "{input:?}");
        }
    }

    fn nested(depth: usize) -> String {
        format!("{}unix{}", "all(".repeat(depth), ")".repeat(depth))
    }

    #[test]
    fn cfg_depth_32_parses_33_is_tool_error() {
        assert_eq!(MAX_CFG_DEPTH, 32);
        let tree = parse_cfg(&nested(32)).expect("32 levels parse");
        assert_eq!(eval_cfg(&tree, &fixed_target()), Tri::True);
        let deep = nested(33);
        assert_eq!(parse_cfg(&deep), Err(format!("cannot parse cfg({deep})")));
        let mut plats = Platforms::from_sets(vec![("t".into(), fixed_target())]);
        let err = plats
            .applies(Some(&format!("cfg({deep})")))
            .expect_err("tool error");
        assert_eq!(err.path, "Cargo.toml");
        assert!(err.message.ends_with(") in a dependency target"));
        assert_eq!(
            plats.applies(Some(&format!("cfg({})", nested(32)))),
            Ok(true)
        );
    }

    #[test]
    fn platforms_apply_like_python() {
        let mut plats = Platforms::from_sets(vec![
            ("x86_64-unknown-linux-gnu".into(), fixed_target()),
            ("other".into(), CfgSet::new()),
        ]);
        assert_eq!(plats.applies(None), Ok(true));
        assert_eq!(plats.applies(Some("x86_64-unknown-linux-gnu")), Ok(true));
        assert_eq!(plats.applies(Some("x86_64-pc-windows-msvc")), Ok(false));
        assert_eq!(plats.applies(Some("cfg(windows)")), Ok(false));
        assert_eq!(
            plats.applies(Some("cfg(target_feature = \"crt-static\")")),
            Ok(true)
        );
        assert_eq!(
            plats.applies(Some("cfg(unix")),
            Ok(false),
            "not cfg(...): a triple"
        );
    }

    #[test]
    fn printed_cfg_reads_like_python() {
        let set = parse_printed_cfg("unix\ntarget_os=\"linux\"\r\nx=\"\"\ny=\nz=\"a\"b\"\n");
        let want: CfgSet = [
            ("unix", None),
            ("target_os", Some("linux")),
            ("x", Some("")),
            ("y", None),
            ("z", Some("a\"b")),
        ]
        .into_iter()
        .map(|(n, v)| (n.to_owned(), v.map(str::to_owned)))
        .collect();
        assert_eq!(set, want);
    }
}
