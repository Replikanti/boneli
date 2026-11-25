//! The check of one workspace, in the reference checker's order, so that
//! the first tool error names the same path (ADR-001; ADR-015, D3).
//!
//! Facts about the workspace come from `cargo metadata` and from the
//! manifests it names, never from directory names. Any tool failure fails
//! the check.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use boneli_toml::{Limits, Table, Value};

use crate::cfg::Rustc;
use crate::fs::{
    read_limited, read_text, rel, resolve, resolve_from, walk_config_files, walk_package,
};
use crate::metadata::{self, Package};
use crate::policy::{check_policy, text_or_nothing, toml_text};
use crate::rules::{Report, Rule, ToolError};
use crate::scan::{
    CORE_TOKENS, EXTERN_CRATE, Kind, MACRO_EXPORT, TRUSTED_NAMES, UNSAFE, blank_comment_lines,
    extern_alloc_at, file_lock_hits, first_format_spec, fmt_imports, format_specs,
    include_path_problem, leading_attributes, source_redirects, task_paths, tokenize, unescape,
    with_lines, without_test_modules,
};
use crate::text::{show, show_bytes, strip};

/// The policy file, relative to the root.
pub(crate) const POLICY: &str = "tools/architecture.toml";
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Graph roles that are fixed by name (docs/ARCHITECTURE.md, "Code
/// architecture").
const DOMAIN: &str = "boneli-domain";
const APP: &str = "boneli-app";

const NO_STD_ATTR: &str = "#![no_std]";
const DOCTEST_ATTR: &str = "#![doc(test(attr(forbid(\x75nsafe_code))))]";
const LIB_KINDS: [&str; 6] = ["lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"];

/// The largest TOML file read: the next power of two above 100 times the
/// largest TOML input today, 9,688 bytes (ADR-015, D4).
pub(crate) const TOML_MAX_BYTES: usize = 1_048_576;
/// The deepest TOML nesting: `MAX_DEPTH` of boneli-toml, above the 83
/// levels cargo accepts in a manifest (ADR-015, D4).
pub(crate) const TOML_MAX_DEPTH: usize = 128;

/// Runs a command and captures its output.
pub(crate) fn run(cmd: &mut Command, name: &str) -> Result<Output, ToolError> {
    cmd.output()
        .map_err(|err| ToolError::new(name, format!("cannot run: {err}")))
}

/// Copies a tool's diagnostics to stderr.
pub(crate) fn forward_stderr(bytes: &[u8]) {
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(bytes);
    let _ = err.flush();
}

/// Reads a TOML file under the checker's limits.
pub(crate) fn load_toml(path: &Path, root: &Path) -> Result<Table, ToolError> {
    let data = read_limited(path, root, TOML_MAX_BYTES)?;
    if data.len() <= TOML_MAX_BYTES && std::str::from_utf8(&data).is_err() {
        return Err(ToolError::new(rel(root, path), "not UTF-8"));
    }
    let limits = Limits::new(TOML_MAX_BYTES, TOML_MAX_DEPTH)
        .map_err(|e| ToolError::new(rel(root, path), format!("TOML limits: {e}")))?;
    boneli_toml::parse(&data, &limits)
        .map_err(|e| ToolError::new(rel(root, path), format!("invalid TOML: {e}")))
}

fn dig<'a>(table: &'a Table, keys: &[&str]) -> Option<&'a Value> {
    let (first, rest) = keys.split_first()?;
    let mut value = table.get(first)?;
    for key in rest {
        value = value.as_table()?.get(key)?;
    }
    Some(value)
}

/// The level of a `[lints]` entry, string or `level` form.
fn lint_level(value: &Value) -> Option<&'static str> {
    let value = match value {
        Value::Table(t) => t.get("level")?,
        v => v,
    };
    match value.as_str()? {
        "allow" => Some("allow"),
        "warn" => Some("warn"),
        "deny" => Some("deny"),
        "forbid" => Some("forbid"),
        _ => None,
    }
}

/// Lint levels, weakest first.
fn rank(level: &str) -> u8 {
    match level {
        "allow" => 0,
        "warn" => 1,
        "deny" => 2,
        _ => 3,
    }
}

/// Problems with the own `[lints]` table of a crate in `roles.unsafe`
/// (ADR-007, D6).
pub(crate) fn sys_lints(
    lints: Option<&Value>,
    ws_lints: Option<&Value>,
    unsafe_lints: &[(String, String)],
) -> Vec<String> {
    let Some(lints) = lints.and_then(Value::as_table).filter(|t| !t.is_empty()) else {
        return vec!["needs its own [lints] table (ADR-007, D6)".to_owned()];
    };
    if lints.get("workspace").is_some() {
        return vec![
            "[lints] must not be `workspace = true`: the \x75nsafe crate keeps its own copy (ADR-007, D6)"
                .to_owned(),
        ];
    }
    let mut required: BTreeMap<(String, String), &str> = BTreeMap::new();
    if let Some(ws) = ws_lints.and_then(Value::as_table) {
        for (tool, table) in ws.iter() {
            let Some(table) = table.as_table() else {
                continue;
            };
            for (name, value) in table.iter() {
                if (tool, name) == ("rust", "\x75nsafe_code") {
                    continue;
                }
                required.insert(
                    (tool.to_owned(), name.to_owned()),
                    lint_level(value).unwrap_or("forbid"),
                );
            }
        }
    }
    // forbid, not deny: cargo passes [lints] as command-line levels, and an
    // inner #![allow(...)] in the source overrides every level but forbid
    // (with forbid it is error E0453).
    for key in unsafe_lints {
        required.insert(key.clone(), "forbid");
    }
    let mut problems = Vec::new();
    for ((tool, name), need) in &required {
        let value = lints
            .get(tool)
            .and_then(Value::as_table)
            .and_then(|t| t.get(name));
        match value {
            None => problems.push(format!(
                "{tool}.{name} is missing (needs {need} or stricter)"
            )),
            Some(value) => match lint_level(value) {
                Some(have) if rank(have) >= rank(need) => {}
                have => problems.push(format!(
                    "{tool}.{name} is {}, needs {need} or stricter",
                    show(&have.map_or_else(|| toml_text(value), str::to_owned))
                )),
            },
        }
    }
    // Anything else must not be weaker than deny: an allowed group with a
    // higher priority would override a required lint.
    for (tool, table) in lints.iter() {
        let Some(table) = table.as_table() else {
            problems.push(format!("[lints.{}] must be a table", show(tool)));
            continue;
        };
        for (name, value) in table.iter() {
            let key = (tool.to_owned(), name.to_owned());
            if required.contains_key(&key) || (tool, name) == ("rust", "\x75nsafe_code") {
                continue;
            }
            match lint_level(value) {
                Some(have) if rank(have) >= rank("deny") => {}
                have => problems.push(format!(
                    "{}.{} is {}: a lint outside the required set must be deny or forbid",
                    show(tool),
                    show(name),
                    show(&have.map_or_else(|| toml_text(value), str::to_owned))
                )),
            }
        }
    }
    problems
}

/// Whether `lints` is exactly `{ workspace = true }`.
fn inherits_workspace_lints(manifest: &Table) -> bool {
    let Some(lints) = manifest.get("lints").and_then(Value::as_table) else {
        return false;
    };
    lints.len() == 1 && lints.get("workspace") == Some(&Value::Boolean(true))
}

fn cargo_metadata(root: &Path) -> Result<metadata::Metadata, ToolError> {
    // No --filter-platform: cargo evaluates cfg() without the flags a real
    // build uses (crt-static, custom --cfg), so edges are filtered here.
    let out = run(
        Command::new("cargo")
            .args([
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--all-features",
                "--manifest-path",
            ])
            .arg(root.join("Cargo.toml"))
            .current_dir(root),
        "cargo",
    )?;
    if !out.status.success() {
        forward_stderr(&out.stderr);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = crate::text::splitlines(&stderr)
            .into_iter()
            .find(|l| l.starts_with("error"))
            .unwrap_or("see stderr")
            .to_owned();
        return Err(ToolError::new(
            "Cargo.toml",
            format!(
                "cargo metadata --locked failed (is Cargo.lock committed and current?): {first}"
            ),
        ));
    }
    metadata::parse(&out.stdout)
}

fn bytes_contain(path: &OsString, b: u8) -> bool {
    path.as_bytes().contains(&b)
}

/// The directories the config walk skips: the root's `target` and
/// `$CARGO_TARGET_DIR` (relative to the working directory), resolved.
pub(crate) fn skipped_dirs(
    root: &Path,
    target_env: Option<&std::ffi::OsStr>,
    cwd: &Path,
) -> Vec<PathBuf> {
    let mut skip = vec![resolve(&root.join("target"))];
    if let Some(dir) = target_env.filter(|d| !d.is_empty()) {
        skip.push(resolve_from(cwd, Path::new(dir)));
    }
    skip
}

/// Checks the workspace at `root`.
pub(crate) fn check(root: &Path) -> Result<Report, ToolError> {
    let mut rep = Report::default();
    let policy = load_toml(&root.join(POLICY), root)?;
    let manifest = load_toml(&root.join("Cargo.toml"), root)?;
    let Some(pol) = check_policy(&policy, root, &mut rep)? else {
        return Ok(rep);
    };

    // Files that change which tools run or how: checked before any cargo
    // call, because a toolchain file can replace cargo itself.
    let skip = skipped_dirs(
        root,
        std::env::var_os("CARGO_TARGET_DIR").as_deref(),
        &crate::fs::cwd(),
    );
    let configs = walk_config_files(root, &skip)?;
    for p in &configs.cargo {
        rep.fail(
            Rule::CargoConfig,
            rel(root, p),
            "a cargo config can cap lints, replace sources, patch or wrap rustc",
            None,
        );
    }
    for p in &configs.clippy {
        rep.fail(
            Rule::ClippyConfig,
            rel(root, p),
            "a clippy config can relax lints",
            None,
        );
    }
    for p in &configs.toolchain {
        rep.fail(
            Rule::ToolchainFile,
            rel(root, p),
            "a toolchain file picks the cargo and rustc that CI and this check run",
            None,
        );
    }

    // Core crates are also built for the no-std target, so their edges are
    // evaluated there too.
    let rustc = Rustc::probe(
        root,
        pol.platforms
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(pol.no_std_target.as_str())),
    )?;
    let mut platforms = rustc.platforms(pol.platforms.iter().map(String::as_str));
    let mut core_platforms = rustc.platforms(
        pol.platforms
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(pol.no_std_target.as_str())),
    );
    let meta = cargo_metadata(root)?;
    let unexpected = |field: &str| {
        ToolError::new(
            "Cargo.toml",
            format!("cargo metadata printed unexpected JSON: {field}"),
        )
    };
    let packages: BTreeMap<&str, &Package> =
        meta.packages.iter().map(|p| (p.id.as_str(), p)).collect();
    let member_ids: BTreeSet<&str> = meta.workspace_members.iter().map(String::as_str).collect();
    let mut members: Vec<&Package> = member_ids
        .iter()
        .map(|id| {
            packages
                .get(id)
                .copied()
                .ok_or_else(|| unexpected("workspace_members"))
        })
        .collect::<Result<_, _>>()?;
    members.sort_by(|a, b| {
        a.manifest_path
            .as_os_str()
            .as_bytes()
            .cmp(b.manifest_path.as_os_str().as_bytes())
    });
    let mut member_dirs: BTreeMap<PathBuf, &Package> = BTreeMap::new();
    for p in &members {
        let dir = p.manifest_path.parent().unwrap_or(Path::new("/"));
        member_dirs.insert(resolve(dir), p);
    }
    let names: BTreeSet<&str> = members.iter().map(|p| p.name.as_str()).collect();
    let mpath = |pkg: &Package| rel(root, &pkg.manifest_path);
    let is_member_name = |name: &str| {
        name.strip_prefix("boneli-").is_some_and(|rest| {
            rest.split('-').all(|seg| {
                !seg.is_empty()
                    && seg
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
        })
    };

    // Manifest-level rules.
    let mut lvl = dig(&manifest, &["workspace", "lints", "rust", "\x75nsafe_code"]);
    if let Some(Value::Table(t)) = lvl {
        lvl = t.get("level");
    }
    if lvl.and_then(Value::as_str) != Some("forbid") {
        rep.fail(
            Rule::LintsUnsafe,
            "Cargo.toml",
            format!(
                "workspace.lints.rust.\x75nsafe_code must be \"forbid\" (found {})",
                show(&text_or_nothing(lvl))
            ),
            None,
        );
    }
    for key in ["patch", "replace"] {
        if manifest.get(key).is_some() {
            rep.fail(
                Rule::ManifestRedirect,
                "Cargo.toml",
                format!("[{key}] redirects dependencies past the source check"),
                None,
            );
        }
    }
    if dig(&manifest, &["workspace", "exclude"]).is_some() {
        rep.fail(
            Rule::ManifestRedirect,
            "Cargo.toml",
            "workspace.exclude keeps path crates out of the member rules",
            None,
        );
    }
    for core in &pol.core {
        if !names.contains(core.as_str()) {
            rep.fail(
                Rule::CoreMissing,
                "Cargo.toml",
                format!("core crate {core} is not a workspace member"),
                None,
            );
        }
    }
    let ws_lints = dig(&manifest, &["workspace", "lints"]);

    // Every target of every member, resolved, for the tests/ exemption of
    // rule file-lock: a member's tests/ directory is test code only when
    // no target that is not a test reads a file under it.
    let targets: Vec<(PathBuf, &[String])> = members
        .iter()
        .flat_map(|p| p.targets.iter())
        .map(|t| (resolve(&t.src_path), t.kind.as_slice()))
        .collect();

    // Per-member rules.
    let mut texts: BTreeMap<PathBuf, String> = BTreeMap::new();
    for pkg in &members {
        let name = pkg.name.as_str();
        let pkg_dir = pkg.manifest_path.parent().unwrap_or(Path::new("/"));
        let is_core = pol.core.iter().any(|c| c == name);
        let is_unsafe = pol.unsafe_crates.iter().any(|c| c == name);
        if !is_member_name(name) {
            rep.fail(
                Rule::MemberName,
                mpath(pkg),
                format!("{name}: every workspace crate is named boneli-<name>"),
                None,
            );
        }

        let member_manifest = load_toml(&pkg.manifest_path, root)?;
        if !is_unsafe && !inherits_workspace_lints(&member_manifest) {
            rep.fail(
                Rule::LintsInherit,
                mpath(pkg),
                format!("{name}: [lints] must be exactly `workspace = true`"),
                None,
            );
        }
        if is_unsafe && let Some(unsafe_lints) = &pol.unsafe_lints {
            for problem in sys_lints(member_manifest.get("lints"), ws_lints, unsafe_lints) {
                rep.fail(
                    Rule::SysLints,
                    mpath(pkg),
                    format!("{name}: {problem}"),
                    None,
                );
            }
        }

        // The names the proven lock forms trust, given to a crate: a
        // dependency renamed to `io` makes `io::stdout()` that crate's
        // function (ADR-030, D5).
        for dep in &pkg.dependencies {
            if let Some(alias) = dep.rename.as_deref()
                && TRUSTED_NAMES.contains(&alias)
            {
                rep.fail(
                    Rule::FileLock,
                    mpath(pkg),
                    format!(
                        "{name}: dependency {} renamed to `{alias}`, a name the proven Mutex and stdio lock forms trust (ADR-030, D5)",
                        show(&dep.name)
                    ),
                    None,
                );
            }
        }
        for t in &pkg.targets {
            if t.kind.iter().any(|k| LIB_KINDS.contains(&k.as_str()))
                && TRUSTED_NAMES.contains(&t.name.as_str())
            {
                rep.fail(
                    Rule::FileLock,
                    mpath(pkg),
                    format!(
                        "{name}: lib target named `{}`, a name the proven Mutex and stdio lock forms trust (ADR-030, D5)",
                        t.name
                    ),
                    None,
                );
            }
        }
        let tests_dir = resolve(pkg_dir).join("tests");
        let tests_only = targets
            .iter()
            .filter(|(src, _)| src.starts_with(&tests_dir))
            .all(|(_, kind)| *kind == ["test"]);

        let (mut files, others, links) = walk_package(pkg_dir, root)?;
        for link in &links {
            rep.fail(
                Rule::Symlink,
                rel(root, link),
                "symlinks in a package are not followed by the scans",
                None,
            );
        }

        let mut lib_roots = Vec::new();
        let pkg_real = resolve(pkg_dir);
        for t in &pkg.targets {
            let src = &t.src_path;
            let src_real = resolve(src);
            let inside = src_real != pkg_real && src_real.starts_with(&pkg_real);
            if !inside {
                rep.fail(
                    Rule::SourceRedirect,
                    mpath(pkg),
                    format!(
                        "target {} reads {}, outside the package",
                        t.name,
                        show_bytes(rel(root, src).as_bytes())
                    ),
                    None,
                );
            }
            let file_name = src.file_name().map(|n| n.as_bytes()).unwrap_or_default();
            if !file_name.ends_with(b".rs") {
                // The scans read .rs files; a crate root under another name
                // would be invisible to them. It is scanned below anyway.
                rep.fail(
                    Rule::SourceRedirect,
                    mpath(pkg),
                    format!(
                        "target {} has source {}, not a .rs file",
                        t.name,
                        show_bytes(rel(root, src).as_bytes())
                    ),
                    None,
                );
                if inside && !files.contains(src) && !src.is_symlink() {
                    files.push(src.clone());
                }
            }
            if t.kind.iter().any(|k| k == "proc-macro") {
                rep.fail(
                    Rule::ProcMacro,
                    mpath(pkg),
                    format!("{name}: proc macros can emit \x75nsafe that no scan sees"),
                    None,
                );
            }
            if t.kind.iter().any(|k| k == "custom-build")
                && !pol.build_script.iter().any(|b| b == name)
            {
                rep.fail(
                    Rule::BuildScript,
                    mpath(pkg),
                    format!("{name}: a build script can compile and link native code no scan sees"),
                    None,
                );
            }
            if t.kind.iter().any(|k| LIB_KINDS.contains(&k.as_str())) {
                lib_roots.push(src.clone());
            }
        }
        for f in &files {
            if !texts.contains_key(f) {
                let text = read_text(f, root)?;
                texts.insert(f.clone(), text);
            }
        }
        for src in &lib_roots {
            let attrs = match texts.get(src) {
                Some(text) if !text.is_empty() => leading_attributes(text),
                _ => leading_attributes(&read_text(src, root)?),
            };
            if !is_unsafe && !attrs.iter().any(|a| a == DOCTEST_ATTR) {
                rep.fail(
                    Rule::DoctestUnsafe,
                    rel(root, src),
                    format!("lib root lacks {DOCTEST_ATTR} in its leading attribute block"),
                    None,
                );
            }
            if is_core && !attrs.iter().any(|a| a == NO_STD_ATTR) {
                rep.fail(
                    Rule::CoreNoStdAttr,
                    rel(root, src),
                    "core lib root lacks an unconditional #![no_std] in its leading attribute block",
                    None,
                );
            }
        }

        if is_core {
            let lib_lib = |t: &&metadata::Target| t.kind == ["lib"] && t.crate_types == ["lib"];
            let libs = pkg.targets.iter().filter(lib_lib).count();
            let extra = pkg
                .targets
                .iter()
                .any(|t| !lib_lib(&t) && t.kind != ["test"]);
            if libs != 1 || extra {
                rep.fail(
                    Rule::CoreTargets,
                    mpath(pkg),
                    format!("{name}: a core crate has one lib target and test targets only"),
                    None,
                );
            }
            if pkg.has_features {
                rep.fail(
                    Rule::CoreFeatures,
                    mpath(pkg),
                    format!("{name}: a core crate declares no features"),
                    None,
                );
            }
        }

        for f in &files {
            let text = texts.get(f).map(String::as_str).unwrap_or_default();
            let fpath = rel(root, f);
            let code = blank_comment_lines(text);
            if !is_unsafe {
                for (line, _) in with_lines(&code, UNSAFE.find_iter(&code)) {
                    rep.fail(
                        Rule::UnsafeToken,
                        fpath.clone(),
                        format!("`\x75nsafe` outside {}", pol.unsafe_crates.join(", ")),
                        Some(line),
                    );
                }
            } else {
                for (line, _) in with_lines(&code, MACRO_EXPORT.find_iter(&code)) {
                    rep.fail(
                        Rule::SysMacroExport,
                        fpath.clone(),
                        format!("an exported macro would carry \x75nsafe out of {name}"),
                        Some(line),
                    );
                }
            }
            let (toks, error) = tokenize(text);
            if let Some(error) = error {
                rep.fail(Rule::SourceRedirect, fpath.clone(), error, Some(1));
            }
            for (line, message) in source_redirects(&toks) {
                rep.fail(Rule::SourceRedirect, fpath.clone(), message, Some(line));
            }
            // File locks only through the one module (ADR-030, D5); test
            // modules and integration tests are not scanned.
            let exempt = pol
                .file_lock
                .as_deref()
                .is_some_and(|p| fpath.as_bytes() == p.as_bytes())
                || (tests_only && resolve(f).starts_with(&tests_dir));
            if !exempt {
                for (line, message) in file_lock_hits(&without_test_modules(&toks)) {
                    rep.fail(Rule::FileLock, fpath.clone(), message, Some(line));
                }
            }
            if !is_core {
                continue;
            }
            for pat in CORE_TOKENS {
                for (line, found) in with_lines(&code, pat.find_iter(&code)) {
                    rep.fail(
                        Rule::CoreToken,
                        fpath.clone(),
                        format!("banned in core crates: {}", show(found)),
                        Some(line),
                    );
                }
            }
            for (line, found) in with_lines(text, format_specs(text)) {
                rep.fail(
                    Rule::CoreToken,
                    fpath.clone(),
                    format!("banned in core crates: format spec {}", show(found)),
                    Some(line),
                );
            }
            let mut uses = fmt_imports(&toks);
            uses.extend(task_paths(&toks));
            for (line, message) in uses {
                rep.fail(Rule::CoreToken, fpath.clone(), message, Some(line));
            }
            let externs = EXTERN_CRATE.find_iter(&code);
            let mut lines = crate::text::Lines::new(&code);
            for (start, end) in externs {
                let line = lines.at(start);
                if !extern_alloc_at(&code, end) {
                    rep.fail(
                        Rule::CoreToken,
                        fpath.clone(),
                        "banned in core crates: extern crate (only `extern crate alloc;`)",
                        Some(line),
                    );
                }
            }
            for (k, tok) in toks.iter().enumerate() {
                if tok.kind == Kind::Str {
                    let decoded;
                    let body = if tok.raw {
                        tok.value.as_str()
                    } else {
                        decoded = unescape(&tok.value);
                        decoded.as_str()
                    };
                    if let Some((a, b)) = first_format_spec(body) {
                        rep.fail(
                            Rule::CoreToken,
                            fpath.clone(),
                            format!(
                                "banned in core crates: format spec {} (after escapes)",
                                show(&body[a..b])
                            ),
                            Some(tok.line),
                        );
                    }
                }
                if tok.kind == Kind::Ident
                    && (tok.value == "include_str" || tok.value == "include_bytes")
                {
                    let lit = if k + 4 < toks.len() {
                        toks.get(k + 3)
                    } else {
                        None
                    };
                    let ok = lit.is_some_and(|lit| {
                        toks[k + 1].kind == Kind::Punct
                            && toks[k + 1].value == "!"
                            && toks[k + 2].kind == Kind::Punct
                            && lit.kind == Kind::Str
                            && toks[k + 4].kind == Kind::Punct
                    });
                    // As written: every escape needs a backslash, which is
                    // rejected, so no decoding is needed.
                    let problem = match lit {
                        Some(lit) if ok => include_path_problem(&lit.value),
                        _ => Some("not a single string literal"),
                    };
                    if let Some(problem) = problem {
                        rep.fail(
                            Rule::CoreToken,
                            fpath.clone(),
                            format!(
                                "{}!: {problem}; only a plain relative path without `..` is allowed",
                                tok.value
                            ),
                            Some(tok.line),
                        );
                    }
                }
            }
        }
        if is_core {
            // file!() turns a path into a string literal, format strings
            // included: no `{` or `}` in the path of any file of the
            // package.
            let mut all: BTreeSet<&Path> = BTreeSet::new();
            all.extend(files.iter().map(PathBuf::as_path));
            all.extend(others.iter().map(PathBuf::as_path));
            all.extend(pkg.targets.iter().map(|t| t.src_path.as_path()));
            for f in all {
                let r = rel(root, f);
                if bytes_contain(&r, b'{') || bytes_contain(&r, b'}') {
                    rep.fail(
                        Rule::CoreToken,
                        r,
                        "`{` or `}` in a core file path (file!() can make it a format string)",
                        None,
                    );
                }
            }
            // include_str! turns these into string literals, format strings
            // included.
            for f in &others {
                let data = std::fs::read(f).map_err(|err| {
                    ToolError::new(
                        rel(root, f),
                        format!("cannot read: {}", crate::fs::strerror(&err)),
                    )
                })?;
                let data = String::from_utf8_lossy(&data);
                for (line, found) in with_lines(&data, format_specs(&data)) {
                    rep.fail(
                        Rule::CoreToken,
                        rel(root, f),
                        format!("banned in core crates: format spec {}", show(found)),
                        Some(line),
                    );
                }
            }
        }

        // Graph rules over declared dependencies on other members.
        if !is_member_name(name) {
            continue;
        }
        let plats = if is_core {
            &mut core_platforms
        } else {
            &mut platforms
        };
        for dep in &pkg.dependencies {
            if dep.kind.as_deref() == Some("dev") || !plats.applies(dep.target.as_deref())? {
                continue;
            }
            let target = dep.path.as_ref().and_then(|p| member_dirs.get(&resolve(p)));
            let Some(target) = target else {
                // External: core crates take none (dev-dependencies aside).
                if name == DOMAIN {
                    rep.fail(
                        Rule::GraphDomain,
                        mpath(pkg),
                        format!("{name} -> {}: the domain depends on nothing", dep.name),
                        None,
                    );
                } else if name == APP {
                    rep.fail(
                        Rule::GraphApp,
                        mpath(pkg),
                        format!(
                            "{name} -> {}: the application depends only on the domain",
                            dep.name
                        ),
                        None,
                    );
                }
                continue;
            };
            let dname = target.name.as_str();
            let support = |n: &str| pol.support.iter().any(|s| s == n);
            if pol.roots.iter().any(|r| r == dname) {
                rep.fail(
                    Rule::GraphRootLeaf,
                    mpath(pkg),
                    format!("{name} -> {dname}: composition roots must stay leaves"),
                    None,
                );
            } else if name == DOMAIN {
                rep.fail(
                    Rule::GraphDomain,
                    mpath(pkg),
                    format!("{name} -> {dname}: the domain depends on nothing"),
                    None,
                );
            } else if name == APP {
                if dname != DOMAIN {
                    rep.fail(
                        Rule::GraphApp,
                        mpath(pkg),
                        format!("{name} -> {dname}: the application depends only on the domain"),
                        None,
                    );
                }
            } else if support(name) {
                if !support(dname) {
                    rep.fail(
                        Rule::GraphSupport,
                        mpath(pkg),
                        format!(
                            "{name} -> {dname}: support crates stay generic (support crates only)"
                        ),
                        None,
                    );
                }
            } else if !pol.roots.iter().any(|r| r == name)
                && dname != DOMAIN
                && dname != APP
                && !support(dname)
            {
                rep.fail(
                    Rule::GraphAdapter,
                    mpath(pkg),
                    format!(
                        "{name} -> {dname}: adapters depend on the domain, the application and support crates only"
                    ),
                    None,
                );
            }
        }
    }

    // The graph that builds on a checked platform: edges whose target is
    // not false everywhere, reachable from the members.
    let nodes: BTreeMap<&str, &metadata::Node> =
        meta.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut reachable: BTreeSet<&str> = member_ids.clone();
    let mut todo: Vec<&str> = member_ids.iter().copied().collect();
    let mut edges: Vec<(&str, &str, Vec<Option<&str>>)> = Vec::new();
    while let Some(pid) = todo.pop() {
        let core_member = member_ids.contains(pid)
            && packages
                .get(pid)
                .is_some_and(|p| pol.core.contains(&p.name));
        let plats = if core_member {
            &mut core_platforms
        } else {
            &mut platforms
        };
        let node = nodes.get(pid).ok_or_else(|| unexpected("resolve.nodes"))?;
        for d in &node.deps {
            let mut kinds = Vec::new();
            for k in &d.dep_kinds {
                if plats.applies(k.target.as_deref())? {
                    kinds.push(k.kind.as_deref());
                }
            }
            if kinds.is_empty() {
                continue;
            }
            edges.push((pid, d.pkg.as_str(), kinds));
            if reachable.insert(d.pkg.as_str()) {
                todo.push(d.pkg.as_str());
            }
        }
    }

    // Sources: crates.io only, path dependencies only to members. Declared
    // dependencies count on every target; an unreachable package can only
    // come from one of them, because crates.io crates cannot depend on git
    // or path crates.
    for (pid, pkg) in &packages {
        if reachable.contains(pid)
            && !member_ids.contains(pid)
            && pkg.source.as_deref() != Some(CRATES_IO)
        {
            rep.fail(
                Rule::DepSource,
                "Cargo.lock",
                format!(
                    "{} {} comes from {}, not crates.io",
                    pkg.name,
                    pkg.version,
                    pkg.source.as_deref().unwrap_or("a path")
                ),
                None,
            );
        }
    }
    for pkg in &members {
        for dep in &pkg.dependencies {
            if let Some(path) = &dep.path {
                if !member_dirs.contains_key(&resolve(path)) {
                    rep.fail(
                        Rule::DepSource,
                        mpath(pkg),
                        format!(
                            "{} -> {}: path dependency outside the workspace members",
                            pkg.name, dep.name
                        ),
                        None,
                    );
                }
            } else if dep.source.as_deref() != Some(CRATES_IO) {
                rep.fail(
                    Rule::DepSource,
                    mpath(pkg),
                    format!(
                        "{} -> {}: source {} is not crates.io",
                        pkg.name,
                        dep.name,
                        dep.source.as_deref().unwrap_or("nothing")
                    ),
                    None,
                );
            }
        }
    }

    // Edges into external crates, over the resolved graph.
    edges.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    for (pid, cid, dep_kinds) in &edges {
        if member_ids.contains(cid) {
            continue;
        }
        let (Some(parent), Some(child)) = (packages.get(pid), packages.get(cid)) else {
            return Err(unexpected("resolve.nodes.deps.pkg"));
        };
        let key = (parent.name.clone(), child.name.clone());
        let kinds: BTreeSet<&str> = dep_kinds.iter().map(|k| k.unwrap_or("normal")).collect();
        if pol.edges.contains(&key) {
            // A record with `kinds` approves the edge for those dependency
            // kinds only (ADR-039, D10): a dev-only record does not let the
            // crate into the build of the parent itself.
            if let Some(allowed) = pol.edge_kinds.get(&key)
                && kinds.iter().any(|k| !allowed.contains(*k))
            {
                let kinds: Vec<&str> = kinds.into_iter().collect();
                let allowed: Vec<&str> = allowed.iter().map(String::as_str).collect();
                rep.fail(
                    Rule::DepEdge,
                    POLICY,
                    format!(
                        "{} -> {} ({}): [external.{}.pulled-by.{}] allows only kinds {}",
                        parent.name,
                        child.name,
                        kinds.join(", "),
                        child.name,
                        parent.name,
                        if allowed.is_empty() {
                            "(none)".to_owned()
                        } else {
                            allowed.join(", ")
                        }
                    ),
                    None,
                );
            }
        } else {
            let kinds: Vec<&str> = kinds.into_iter().collect();
            rep.fail(
                Rule::DepEdge,
                POLICY,
                format!(
                    "{} -> {} ({}): no record [external.{}.pulled-by.{}]",
                    parent.name,
                    child.name,
                    kinds.join(", "),
                    child.name,
                    parent.name
                ),
                None,
            );
        }
    }

    // Build scripts of external crates: each one runs on every machine that
    // builds the workspace and can compile and link native code, so each
    // reachable crate with one needs an ADR that approves it (ADR-005). The
    // target kind comes from cargo metadata, so a renamed script
    // (`build = "gen.rs"`) counts and `build = false` does not.
    for pid in reachable.difference(&member_ids) {
        let Some(pkg) = packages.get(pid) else {
            return Err(unexpected("resolve.nodes.deps.pkg"));
        };
        let script = pkg
            .targets
            .iter()
            .find(|t| t.kind.iter().any(|k| k == "custom-build"));
        if let Some(script) = script
            && !pol.build_scripts.contains_key(&pkg.name)
        {
            let file = script
                .src_path
                .file_name()
                .map(|n| show_bytes(n.as_bytes()))
                .unwrap_or_default();
            rep.fail(
                    Rule::DepBuildScript,
                    POLICY,
                    format!(
                        "{} {} has a build script ({file}): no build-script = \"ADR-NNN\" in [external.{}] that approves it",
                        pkg.name, pkg.version, pkg.name
                    ),
                    None,
                );
        }
    }

    // The core must build for a target without std.
    let core_ids: Vec<&str> = members
        .iter()
        .filter(|p| pol.core.contains(&p.name))
        .map(|p| p.id.as_str())
        .collect();
    if !core_ids.is_empty() {
        let target = pol.no_std_target.as_str();
        let out = run(
            Command::new("rustc")
                .args(["--print", "target-libdir", "--target", target])
                .current_dir(root),
            "rustc",
        )?;
        let libdir = out
            .status
            .success()
            .then(|| strip(&String::from_utf8_lossy(&out.stdout)).to_owned())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let installed = libdir.is_some_and(|dir| {
            dir.is_dir()
                && std::fs::read_dir(&dir).is_ok_and(|entries| {
                    entries
                        .flatten()
                        .any(|e| e.file_name().as_bytes().starts_with(b"libcore-"))
                })
        });
        if !installed {
            forward_stderr(format!("rustup target add {target}\n").as_bytes());
            return Err(ToolError::new(
                POLICY,
                format!("Rust target {target} is not installed (rustup target add {target})"),
            ));
        }
        let mut cmd = Command::new("cargo");
        cmd.args([
            "check",
            "--locked",
            "--lib",
            "--target",
            target,
            "--message-format",
            "short",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .current_dir(root);
        for pid in &core_ids {
            cmd.args(["-p", pid]);
        }
        let out = run(&mut cmd, "cargo")?;
        if !out.status.success() {
            forward_stderr(&out.stderr);
            for pkg in &members {
                if core_ids.contains(&pkg.id.as_str()) {
                    rep.fail(
                        Rule::CoreNoStdBuild,
                        mpath(pkg),
                        format!(
                            "core crates must build for {target} (no std); cargo output on stderr"
                        ),
                        None,
                    );
                }
            }
        }
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::{inherits_workspace_lints, load_toml, skipped_dirs, sys_lints};
    use crate::tmp::TempDir;
    use std::path::Path;

    fn toml(text: &str) -> boneli_toml::Table {
        boneli_toml::parse(
            text.as_bytes(),
            &boneli_toml::Limits::new(1 << 20, 128).expect("limits"),
        )
        .expect("parses")
    }

    /// `workspace = 1` is not `true`. The reference checker accepted it
    /// because `True == 1`, but cargo rejects such a manifest anyway.
    #[test]
    fn lints_workspace_must_be_boolean_true() {
        assert!(inherits_workspace_lints(&toml("[lints]\nworkspace = true")));
        assert!(!inherits_workspace_lints(&toml("[lints]\nworkspace = 1")));
        assert!(!inherits_workspace_lints(&toml(
            "[lints]\nworkspace = false"
        )));
        assert!(!inherits_workspace_lints(&toml(
            "[lints]\nworkspace = true\nrust = {}"
        )));
        assert!(!inherits_workspace_lints(&toml("")));
    }

    /// A quoted look-alike key leaves no `lints` table; a bare non-ASCII
    /// key is not TOML at all (ADR-011, D3).
    #[test]
    fn lints_lookalike_key_fails() {
        assert!(!inherits_workspace_lints(&toml(
            "[\"l\u{131}nts\"]\nworkspace = true"
        )));
        let tmp = TempDir::new("lookalike");
        let path = tmp.path().join("Cargo.toml");
        std::fs::write(&path, "[l\u{131}nts]\nworkspace = true\n").expect("write");
        let err = load_toml(&path, tmp.path()).expect_err("bare non-ASCII key");
        assert_eq!(err.path, "Cargo.toml");
        assert!(err.message.starts_with("invalid TOML: "), "{}", err.message);
    }

    #[test]
    fn toml_limits_are_inclusive() {
        let tmp = TempDir::new("toml-limits");
        let path = tmp.path().join("x.toml");
        let padded = |n: usize| {
            let mut s = String::from("a = 1\n");
            s.push_str(&"#".repeat(n - s.len()));
            s
        };
        std::fs::write(&path, padded(1_048_576)).expect("write");
        assert!(load_toml(&path, tmp.path()).is_ok());
        std::fs::write(&path, padded(1_048_577)).expect("write");
        let err = load_toml(&path, tmp.path()).expect_err("too large");
        assert_eq!(err.path, "x.toml");
        assert!(err.message.contains("too large"), "{}", err.message);
        // Depth: the root table is 1, each array adds 1.
        let nested =
            |depth: usize| format!("a = {}{}", "[".repeat(depth - 1), "]".repeat(depth - 1));
        std::fs::write(&path, nested(128)).expect("write");
        assert!(load_toml(&path, tmp.path()).is_ok());
        std::fs::write(&path, nested(129)).expect("write");
        let err = load_toml(&path, tmp.path()).expect_err("too deep");
        assert!(err.message.contains("too deep"), "{}", err.message);
        std::fs::write(&path, b"a = \"\xff\"").expect("write");
        assert_eq!(
            load_toml(&path, tmp.path()).expect_err("utf-8").message,
            "not UTF-8"
        );
    }

    #[test]
    fn sys_lints_report_each_problem() {
        let ws = toml(
            "[lints.rust]\n\x75nsafe_code = \"forbid\"\nmissing_docs = \"warn\"\n[lints.clippy]\ntodo = { level = \"deny\", priority = 1 }\nodd = 5\n",
        );
        let ws = ws.get("lints");
        let required = [("clippy".to_owned(), "u".to_owned())];
        let lints = |t: &str| toml(t).get("lints").cloned();
        assert_eq!(
            sys_lints(lints("").as_ref(), ws, &required),
            ["needs its own [lints] table (ADR-007, D6)"]
        );
        assert_eq!(
            sys_lints(lints("[lints]\nworkspace = true").as_ref(), ws, &required).len(),
            1
        );
        let got = sys_lints(
            lints(
                "[lints]\nrust = { missing_docs = \"allow\", x = \"warn\" }\nclippy = { todo = { level = \"x\" }, u = \"forbid\", odd = \"deny\", y = { level = \"forbid\" } }\nother = 1\n",
            )
            .as_ref(),
            ws,
            &required,
        );
        assert_eq!(
            got,
            [
                "clippy.odd is deny, needs forbid or stricter",
                "clippy.todo is { level = \"x\" }, needs deny or stricter",
                "rust.missing_docs is allow, needs warn or stricter",
                "rust.x is warn: a lint outside the required set must be deny or forbid",
                "[lints.other] must be a table",
            ]
        );
        let missing = sys_lints(lints("[lints.rust]\na = \"deny\"").as_ref(), ws, &required);
        assert_eq!(
            missing[0],
            "clippy.odd is missing (needs forbid or stricter)"
        );
    }

    /// The root's `target` and `$CARGO_TARGET_DIR` are skipped; a relative
    /// `$CARGO_TARGET_DIR` resolves against the working directory.
    #[test]
    fn skipped_dirs_resolve_target_dir_from_cwd() {
        let tmp = TempDir::new("skip");
        let base = std::fs::canonicalize(tmp.path()).expect("canonical");
        let skip = skipped_dirs(
            &base,
            Some(std::ffi::OsStr::new("rel/t")),
            Path::new("/cwd"),
        );
        assert_eq!(
            skip,
            [base.join("target"), Path::new("/cwd/rel/t").to_path_buf()]
        );
        assert_eq!(
            skipped_dirs(&base, Some(std::ffi::OsStr::new("")), Path::new("/")).len(),
            1
        );
    }
}
