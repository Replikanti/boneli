//! The fixture runner (`--fixtures`): every case under
//! tools/fixtures/arch/cases is a fixture workspace built from `base`,
//! checked by this binary, and must fail exactly the rules its `expect`
//! file names (ADR-001; the runner in ADR-015, D9).
//!
//! A case directory may hold: `expect` (rule ids, `#` comments), `overlay/`
//! (files copied over the base, `.fixture` suffixes stripped, symlinks
//! kept), `remove` (paths to delete), `policy-append` (TOML appended to
//! the policy), `snippets` (one run per line, each written to
//! `crates/boneli-domain/src/extra.rs`), `outside/` (copied next to the
//! workspace) and `git/<name>/` (each made a git repository whose `file:`
//! URI replaces `@GIT:<name>@` in the workspace).

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::check::POLICY;
use crate::rules::{RULES, Rule};
use crate::text::{show, splitlines, strip, universal_newlines};
use crate::tmp::TempDir;

/// The body of every `.cargo-checksum.json` of the fake registry: cargo's
/// directory sources accept an empty file list and no package checksum,
/// so the runner needs no hashing.
pub(crate) const CHECKSUM: &str = "{\"files\":{},\"package\":null}";

/// The variable that names the reference checker for a parity run.
const PARITY_ENV: &str = "BONELI_ARCH_PARITY";

/// A failure of the runner itself, which exits 2.
#[derive(Debug)]
pub(crate) struct RunnerError(String);

impl RunnerError {
    fn io(what: impl std::fmt::Display, err: &io::Error) -> RunnerError {
        RunnerError(format!("{what}: {err}"))
    }
}

type Result<T> = std::result::Result<T, RunnerError>;

fn read_text(path: &Path) -> Result<String> {
    let data = std::fs::read(path).map_err(|e| RunnerError::io(path.display(), &e))?;
    String::from_utf8(data)
        .map(|t| universal_newlines(&t))
        .map_err(|_| RunnerError(format!("{}: not UTF-8", path.display())))
}

/// `"..."` with backslashes and quotes escaped, the string form the cargo
/// config of the fake registry needs.
pub(crate) fn toml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The `file:` URI of an absolute path, encoded like `Path.as_uri()`:
/// every byte outside `A-Za-z0-9_.-~/` as `%XX`.
pub(crate) fn file_uri(path: &Path) -> String {
    let mut out = String::from("file://");
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The cargo config that replaces crates.io with the fake registry.
pub(crate) fn cargo_config(registry: &Path) -> String {
    format!(
        "[source.crates-io]\nreplace-with = \"arch-fixtures\"\n\n[source.arch-fixtures]\ndirectory = {}\n",
        toml_string(&registry.to_string_lossy())
    )
}

/// Copies a tree. With `symlinks`, symlinks are recreated; without, they
/// are followed. Files keep their permission bits.
fn copy_tree(src: &Path, dst: &Path, symlinks: bool) -> Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        std::fs::create_dir_all(&to).map_err(|e| RunnerError::io(to.display(), &e))?;
        let mut entries: Vec<_> = std::fs::read_dir(&from)
            .map_err(|e| RunnerError::io(from.display(), &e))?
            .collect::<io::Result<_>>()
            .map_err(|e| RunnerError::io(from.display(), &e))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let s = entry.path();
            let d = to.join(entry.file_name());
            let kind = entry
                .file_type()
                .map_err(|e| RunnerError::io(s.display(), &e))?;
            if kind.is_symlink() && symlinks {
                let target =
                    std::fs::read_link(&s).map_err(|e| RunnerError::io(s.display(), &e))?;
                std::os::unix::fs::symlink(target, &d)
                    .map_err(|e| RunnerError::io(d.display(), &e))?;
            } else if std::fs::metadata(&s).is_ok_and(|m| m.is_dir()) {
                stack.push((s, d));
            } else {
                std::fs::copy(&s, &d).map_err(|e| RunnerError::io(s.display(), &e))?;
            }
        }
    }
    Ok(())
}

/// Lays the overlay over the workspace.
fn apply_overlay(overlay: &Path, ws: &Path) -> Result<()> {
    let mut stack = vec![PathBuf::new()];
    while let Some(sub) = stack.pop() {
        let dir = overlay.join(&sub);
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .map_err(|e| RunnerError::io(dir.display(), &e))?
            .collect::<io::Result<_>>()
            .map_err(|e| RunnerError::io(dir.display(), &e))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let src = entry.path();
            let rel = sub.join(entry.file_name());
            let kind = entry
                .file_type()
                .map_err(|e| RunnerError::io(src.display(), &e))?;
            if kind.is_dir() {
                stack.push(rel);
                continue;
            }
            let mut dest = ws.join(&rel);
            let name = entry.file_name();
            if let Some(stripped) = name.as_bytes().strip_suffix(b".fixture") {
                dest.set_file_name(OsStr::from_bytes(stripped));
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RunnerError::io(parent.display(), &e))?;
            }
            if std::fs::symlink_metadata(&dest).is_ok() {
                std::fs::remove_file(&dest).map_err(|e| RunnerError::io(dest.display(), &e))?;
            }
            if kind.is_symlink() {
                let target =
                    std::fs::read_link(&src).map_err(|e| RunnerError::io(src.display(), &e))?;
                std::os::unix::fs::symlink(target, &dest)
                    .map_err(|e| RunnerError::io(dest.display(), &e))?;
            } else {
                let data = std::fs::read(&src).map_err(|e| RunnerError::io(src.display(), &e))?;
                std::fs::write(&dest, data).map_err(|e| RunnerError::io(dest.display(), &e))?;
            }
        }
    }
    Ok(())
}

/// Makes `dir` a git repository with one commit of its files. Git reads
/// neither the system nor the user's global config, so a developer's
/// commit signing or hooks cannot break the setup.
pub(crate) fn git_commit(dir: &Path, envs: &[(&str, &OsStr)]) -> Result<()> {
    let steps: [&[&str]; 3] = [
        &["init", "-q"],
        &["add", "-A"],
        &[
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
    ];
    for args in steps {
        let mut cmd = Command::new("git");
        cmd.args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let out = cmd.output().map_err(|e| RunnerError::io("git", &e))?;
        if !out.status.success() {
            return Err(RunnerError(format!(
                "{}: git {} failed: {}",
                dir.display(),
                args[0],
                strip(&String::from_utf8_lossy(&out.stderr))
            )));
        }
    }
    Ok(())
}

/// Replaces `marker` with `with` in every regular file under `dir`.
fn replace_marker(dir: &Path, marker: &[u8], with: &[u8]) -> Result<()> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).map_err(|e| RunnerError::io(d.display(), &e))? {
            let entry = entry.map_err(|e| RunnerError::io(d.display(), &e))?;
            let p = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| RunnerError::io(p.display(), &e))?;
            if kind.is_dir() {
                stack.push(p);
            } else if kind.is_file() {
                let data = std::fs::read(&p).map_err(|e| RunnerError::io(p.display(), &e))?;
                if data.windows(marker.len()).any(|w| w == marker) {
                    let mut out = Vec::with_capacity(data.len());
                    let mut i = 0;
                    while i < data.len() {
                        if data[i..].starts_with(marker) {
                            out.extend_from_slice(with);
                            i += marker.len();
                        } else {
                            out.push(data[i]);
                            i += 1;
                        }
                    }
                    std::fs::write(&p, out).map_err(|e| RunnerError::io(p.display(), &e))?;
                }
            }
        }
    }
    Ok(())
}

/// What the runner works with.
struct Ctx {
    repo: PathBuf,
    fixtures: PathBuf,
    target_dir: PathBuf,
    checker: PathBuf,
    /// The reference checker of a parity run.
    reference: Option<PathBuf>,
    parity: Parity,
}

/// What a parity run found across all runs.
#[derive(Default)]
struct Parity {
    runs: usize,
    identical: usize,
    lines: usize,
    differing: Vec<String>,
}

/// Builds one fixture workspace under `tmp`; returns its root.
fn assemble(ctx: &Ctx, case: Option<&Path>, snippet: Option<&str>, tmp: &Path) -> Result<PathBuf> {
    let ws = tmp.join("ws");
    let io = |what: &Path, e: io::Error| RunnerError::io(what.display(), &e);
    copy_tree(&ctx.fixtures.join("base"), &ws, true)?;
    std::fs::create_dir(ws.join("tools")).map_err(|e| io(&ws, e))?;
    std::fs::copy(ctx.repo.join(POLICY), ws.join(POLICY)).map_err(|e| io(&ws, e))?;
    std::fs::create_dir(ws.join("docs")).map_err(|e| io(&ws, e))?;
    std::fs::copy(
        ctx.repo.join("docs/ARCHITECTURE.md"),
        ws.join("docs/ARCHITECTURE.md"),
    )
    .map_err(|e| io(&ws, e))?;
    copy_tree(&ctx.repo.join("docs/adr"), &ws.join("docs/adr"), false)?;

    if let Some(case) = case {
        let overlay = case.join("overlay");
        if overlay.is_dir() {
            apply_overlay(&overlay, &ws)?;
        }
        let remove = case.join("remove");
        if remove.is_file() {
            for line in splitlines(&read_text(&remove)?) {
                let line = strip(line);
                if line.is_empty() {
                    continue;
                }
                let p = ws.join(line);
                let removed = if p.is_dir() && !p.is_symlink() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
                removed.map_err(|e| io(&p, e))?;
            }
        }
        let append = case.join("policy-append");
        if append.is_file() {
            let extra = read_text(&append)?;
            let policy = ws.join(POLICY);
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&policy)
                .map_err(|e| io(&policy, e))?;
            file.write_all(format!("\n{extra}").as_bytes())
                .map_err(|e| io(&policy, e))?;
        }
    }
    if let Some(snippet) = snippet {
        let extra = ws.join("crates/boneli-domain/src/extra.rs");
        std::fs::write(&extra, format!("{snippet}\n")).map_err(|e| io(&extra, e))?;
    }
    if let Some(case) = case {
        let outside = case.join("outside");
        if outside.is_dir() {
            copy_tree(&outside, &tmp.join("outside"), true)?;
        }
        let git_dir = case.join("git");
        if git_dir.is_dir() {
            let mut repos: Vec<PathBuf> = std::fs::read_dir(&git_dir)
                .map_err(|e| io(&git_dir, e))?
                .map(|e| e.map(|e| e.path()))
                .collect::<io::Result<_>>()
                .map_err(|e| io(&git_dir, e))?;
            repos.sort();
            for repo in repos {
                let name = repo.file_name().unwrap_or_default().to_owned();
                let dest = tmp.join("git").join(&name);
                copy_tree(&repo, &dest, false)?;
                git_commit(&dest, &[])?;
                let mut marker = b"@GIT:".to_vec();
                marker.extend_from_slice(name.as_bytes());
                marker.push(b'@');
                replace_marker(&ws, &marker, file_uri(&dest).as_bytes())?;
            }
        }
    }

    // Fake crates.io: a directory source above the workspace.
    let registry = tmp.join("registry");
    copy_tree(&ctx.fixtures.join("registry"), &registry, false)?;
    for entry in std::fs::read_dir(&registry).map_err(|e| io(&registry, e))? {
        let crate_dir = entry.map_err(|e| io(&registry, e))?.path();
        if crate_dir.is_dir() {
            let sum = crate_dir.join(".cargo-checksum.json");
            std::fs::write(&sum, CHECKSUM).map_err(|e| io(&sum, e))?;
        }
    }
    let cargo_dir = tmp.join(".cargo");
    std::fs::create_dir(&cargo_dir).map_err(|e| io(&cargo_dir, e))?;
    std::fs::write(cargo_dir.join("config.toml"), cargo_config(&registry))
        .map_err(|e| io(&cargo_dir, e))?;
    Ok(ws)
}

/// The rule, path and line of a FAIL line, and its message.
fn parse_fail(line: &str) -> Option<(String, String, Option<usize>)> {
    let rest = line.strip_prefix("FAIL [")?;
    let (rule, rest) = rest.split_once("] ")?;
    if rule.is_empty()
        || !rule
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    if rest.chars().next().is_none_or(crate::text::is_space) {
        return None;
    }
    let place = rest.split_once(": ").map_or(rest, |(p, _)| p);
    let (path, line_no) = match place.rsplit_once(':') {
        Some((p, n)) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => {
            (p, n.parse().ok())
        }
        _ => (place, None),
    };
    Some((rule.to_owned(), path.to_owned(), line_no))
}

/// A checker's output read as the fixture contract: the FAIL lines, the
/// count of the summary line, and what is malformed.
struct Parsed {
    fails: Vec<(String, String, Option<usize>)>,
    lines: Vec<String>,
    summary: Option<usize>,
    problems: Vec<String>,
}

fn parse_output(stdout: &str) -> Parsed {
    let lines = splitlines(stdout);
    let mut parsed = Parsed {
        fails: Vec::new(),
        lines: Vec::new(),
        summary: None,
        problems: Vec::new(),
    };
    // `OK: ...` is `Some(None)`, `N violation(s)` is `Some(Some(N))`.
    let summary_of = |l: &str| -> Option<Option<u128>> {
        if l.starts_with("OK: ") {
            return Some(None);
        }
        let n = l.strip_suffix(" violation(s)")?;
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Some(n.parse().unwrap_or(u128::MAX)))
    };
    for (i, line) in lines.iter().enumerate() {
        let last = i + 1 == lines.len();
        if let Some(fail) = parse_fail(line) {
            parsed.fails.push(fail);
            parsed.lines.push((*line).to_owned());
        } else if let (Some(summary), true) = (summary_of(line), last) {
            let fails = parsed.fails.len();
            match summary {
                None if fails > 0 => parsed.problems.push("OK after FAIL lines".into()),
                None => parsed.summary = Some(0),
                Some(n) => {
                    if usize::try_from(n).ok() != Some(fails) {
                        parsed
                            .problems
                            .push(format!("count {n} != {fails} FAIL lines"));
                    }
                    parsed.summary = usize::try_from(n).ok();
                }
            }
        } else {
            parsed
                .problems
                .push(format!("unparseable line: {}", show(line)));
        }
    }
    if lines.last().is_none_or(|l| summary_of(l).is_none()) {
        parsed.problems.push("no summary line".into());
    }
    parsed
}

fn exit_code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

/// The checker's command for a fixture workspace.
fn checker_command(ctx: &Ctx, program: &Path, pre: &[&OsStr], ws: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(pre)
        .arg("--root")
        .arg(ws)
        .current_dir(ws)
        .env("CARGO_TARGET_DIR", &ctx.target_dir)
        .env_remove("RUSTFLAGS");
    cmd
}

/// Runs one case; `None` when it matches its expect file, else a report.
fn run_case(ctx: &mut Ctx, case: Option<&Path>, snippet: Option<&str>) -> Result<Option<String>> {
    let mut expect = BTreeSet::new();
    if let Some(case) = case {
        for line in splitlines(&read_text(&case.join("expect"))?) {
            let line = strip(line);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if Rule::from_id(line).is_none() {
                return Ok(Some(format!("expect names unknown rule {line}")));
            }
            expect.insert(line.to_owned());
        }
    }
    let tmp = TempDir::create("case").map_err(|e| RunnerError::io("temporary directory", &e))?;
    let ws = assemble(ctx, case, snippet, tmp.path())?;
    let mut lock = Command::new("cargo");
    lock.arg("generate-lockfile");
    if !case.is_some_and(|c| c.join("git").is_dir()) {
        lock.arg("--offline");
    }
    // A failure here is the checker's to report.
    let _ = lock
        .current_dir(&ws)
        .env("CARGO_TARGET_DIR", &ctx.target_dir)
        .env_remove("RUSTFLAGS")
        .output();
    let res = checker_command(ctx, &ctx.checker, &[], &ws)
        .output()
        .map_err(|e| RunnerError::io(ctx.checker.display(), &e))?;
    let reference = match &ctx.reference {
        Some(script) => {
            let pre = [OsStr::new("-I"), script.as_os_str()];
            let out = checker_command(ctx, Path::new("python3"), &pre, &ws)
                .output()
                .map_err(|e| RunnerError::io("the reference checker", &e))?;
            Some(out)
        }
        None => None,
    };
    drop(tmp);

    let stdout = String::from_utf8_lossy(&res.stdout).into_owned();
    let parsed = parse_output(&stdout);
    let mut problems = parsed.problems.clone();
    let got: BTreeSet<String> = parsed.fails.iter().map(|f| f.0.clone()).collect();
    let want_exit = if expect.contains("tool-error") {
        2
    } else if expect.is_empty() {
        0
    } else {
        1
    };
    if exit_code(&res) != want_exit {
        problems.push(format!("exit {}, expected {want_exit}", exit_code(&res)));
    }
    if got != expect {
        problems.push(format!(
            "expected {:?}, got {:?}",
            expect.iter().collect::<Vec<_>>(),
            got.iter().collect::<Vec<_>>()
        ));
    }
    let mut extra = String::new();
    if let Some(reference) = reference {
        let ref_stdout = String::from_utf8_lossy(&reference.stdout).into_owned();
        let theirs = parse_output(&ref_stdout);
        for p in &theirs.problems {
            problems.push(format!("reference: {p}"));
        }
        if exit_code(&reference) != exit_code(&res) {
            problems.push(format!(
                "parity: exit {} != reference exit {}",
                exit_code(&res),
                exit_code(&reference)
            ));
        }
        if theirs.summary != parsed.summary {
            problems.push(format!(
                "parity: summary {:?} != reference summary {:?}",
                parsed.summary, theirs.summary
            ));
        }
        let mut ours_key = parsed.fails.clone();
        let mut theirs_key = theirs.fails.clone();
        ours_key.sort();
        theirs_key.sort();
        if ours_key != theirs_key {
            problems.push(format!(
                "parity: (rule, path, line) differ: {ours_key:?} != reference {theirs_key:?}"
            ));
        }
        ctx.parity.runs += 1;
        ctx.parity.lines += parsed.lines.len();
        let mut rest: Vec<String> = theirs.lines.clone();
        let mut only_ours = Vec::new();
        for line in &parsed.lines {
            match rest.iter().position(|l| l == line) {
                Some(i) => {
                    rest.remove(i);
                    ctx.parity.identical += 1;
                }
                None => only_ours.push(line.clone()),
            }
        }
        if !only_ours.is_empty() || !rest.is_empty() {
            let label = case
                .and_then(Path::file_name)
                .map_or_else(|| "base".to_owned(), |n| n.to_string_lossy().into_owned());
            let mut entry = format!("{} {}", label, snippet.map_or(String::new(), show));
            for l in &only_ours {
                entry.push_str(&format!("\n  rust:      {l}"));
            }
            for l in &rest {
                entry.push_str(&format!("\n  reference: {}", show(l)));
            }
            ctx.parity.differing.push(entry);
        }
        extra = format!(
            "--- reference stdout\n{ref_stdout}--- reference stderr\n{}",
            tail(&String::from_utf8_lossy(&reference.stderr))
        );
    }
    if problems.is_empty() {
        return Ok(None);
    }
    Ok(Some(format!(
        "{}\n--- stdout\n{stdout}--- stderr\n{}{extra}",
        problems.join("; "),
        tail(&String::from_utf8_lossy(&res.stderr))
    )))
}

/// The last 4,000 characters.
fn tail(s: &str) -> &str {
    let n = s.chars().count();
    match s.char_indices().nth(n.saturating_sub(4000)) {
        Some((i, _)) => &s[i..],
        None => s,
    }
}

fn runner(repo: &Path) -> Result<Ctx> {
    let checker = std::env::current_exe().map_err(|e| RunnerError::io("current_exe", &e))?;
    let reference = std::env::var_os(PARITY_ENV)
        .filter(|v| !v.is_empty())
        .map(|v| crate::fs::resolve(Path::new(&v)));
    Ok(Ctx {
        repo: repo.to_path_buf(),
        fixtures: repo.join("tools/fixtures/arch"),
        target_dir: repo.join("target/arch-fixtures"),
        checker,
        reference,
        parity: Parity::default(),
    })
}

/// Runs every fixture case and prints one line per run; returns the exit
/// code: 0 all match, 1 a mismatch or a rule without a fixture, 2 an error
/// of the runner.
pub(crate) fn run_fixtures(repo: &Path, out: &mut dyn Write) -> u8 {
    match run_all(repo, out) {
        Ok(code) => code,
        Err(err) => {
            let _ = writeln!(out, "\nfixture runner error: {}", show(&err.0));
            let _ = out.flush();
            2
        }
    }
}

fn say(out: &mut dyn Write, text: &str) -> Result<()> {
    writeln!(out, "{text}")
        .and_then(|()| out.flush())
        .map_err(|e| RunnerError::io("stdout", &e))
}

fn run_all(repo: &Path, out: &mut dyn Write) -> Result<u8> {
    let mut ctx = runner(repo)?;
    let cases_dir = ctx.fixtures.join("cases");
    let mut cases: Vec<PathBuf> = Vec::new();
    for entry in
        std::fs::read_dir(&cases_dir).map_err(|e| RunnerError::io(cases_dir.display(), &e))?
    {
        let p = entry
            .map_err(|e| RunnerError::io(cases_dir.display(), &e))?
            .path();
        if p.is_dir() {
            cases.push(p);
        }
    }
    cases.sort();
    let mut runs = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut covered: BTreeSet<String> = BTreeSet::new();

    // base: an empty case, which must give no FAIL line.
    let report = run_case(&mut ctx, None, None)?;
    runs += 1;
    say(
        out,
        &format!(
            "{:<48} {}",
            "base",
            if report.is_none() { "ok" } else { "MISMATCH" }
        ),
    )?;
    if let Some(report) = report {
        failures.push(format!("base: {report}"));
    }

    for case in &cases {
        for line in splitlines(&read_text(&case.join("expect"))?) {
            if !strip(line).is_empty() && !line.starts_with('#') {
                covered.insert(strip(line).to_owned());
            }
        }
        let snippets_file = case.join("snippets");
        let snippets: Vec<Option<String>> = if snippets_file.is_file() {
            read_text(&snippets_file)?
                .split('\n')
                .filter(|s| !strip(s).is_empty())
                .map(|s| Some(s.to_owned()))
                .collect()
        } else {
            vec![None]
        };
        let name = case
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for (n, snippet) in snippets.iter().enumerate() {
            let label = match snippet {
                None => name.clone(),
                Some(_) => format!("{name} #{}", n + 1),
            };
            let report = run_case(&mut ctx, Some(case), snippet.as_deref())?;
            runs += 1;
            say(
                out,
                &format!(
                    "{label:<48} {}",
                    if report.is_none() { "ok" } else { "MISMATCH" }
                ),
            )?;
            if let Some(report) = report {
                failures.push(format!("{label}: {report}"));
            }
        }
    }

    let uncovered: Vec<&str> = RULES
        .iter()
        .map(|r| r.id())
        .filter(|id| !covered.contains(*id))
        .collect();
    if !uncovered.is_empty() {
        failures.push(format!("rules without a fixture: {}", uncovered.join(", ")));
    }
    for f in &failures {
        say(out, &format!("\n{f}"))?;
    }
    if ctx.reference.is_some() {
        let p = &ctx.parity;
        say(
            out,
            &format!(
                "\nparity: {} of {} FAIL lines byte-identical; {} run(s) with differing lines (report-only):",
                p.identical,
                p.lines,
                p.differing.len()
            ),
        )?;
        for d in &p.differing {
            say(out, d)?;
        }
    }
    if !failures.is_empty() {
        say(
            out,
            &format!("\nfixtures: {runs} run(s), {} problem(s)", failures.len()),
        )?;
        return Ok(1);
    }
    if ctx.reference.is_some() {
        say(
            out,
            &format!("\nparity: {} run(s), both checkers agree", ctx.parity.runs),
        )?;
    }
    say(
        out,
        &format!(
            "\nfixtures: {runs} run(s) in {} case(s), all match; every rule is pinned",
            cases.len()
        ),
    )?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::{cargo_config, file_uri, git_commit, parse_fail, parse_output};
    use crate::py_vectors;
    use crate::tmp::TempDir;
    use std::ffi::OsStr;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    #[test]
    fn file_uri_matches_python_as_uri() {
        for &(path, want) in py_vectors::FILE_URI {
            assert_eq!(file_uri(Path::new(path)), want, "{path:?}");
        }
    }

    #[test]
    fn fixture_cargo_config_round_trips() {
        let dir = Path::new("/tmp/boneli arch \"q\" \\b/registry");
        let config = boneli_toml::parse(
            cargo_config(dir).as_bytes(),
            &boneli_toml::Limits::new(1 << 16, 8).expect("limits"),
        )
        .expect("parses");
        let source = config
            .get("source")
            .and_then(|v| v.as_table())
            .expect("source");
        let replace = source
            .get("crates-io")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("replace-with"))
            .and_then(|v| v.as_str());
        assert_eq!(replace, Some("arch-fixtures"));
        let directory = source
            .get("arch-fixtures")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("directory"))
            .and_then(|v| v.as_str());
        assert_eq!(directory, Some(dir.to_str().expect("UTF-8")));
    }

    #[test]
    fn fixture_temp_dir_has_space_and_mode_0700() {
        let tmp = TempDir::create("case").expect("create");
        let name = tmp
            .path()
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("boneli arch case "), "{name}");
        let mode = std::fs::metadata(tmp.path())
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        let path = tmp.path().to_path_buf();
        drop(tmp);
        assert!(!path.exists(), "removed on drop");
    }

    /// A developer's global git config that signs every commit with a
    /// program that fails does not break the fixture repositories.
    #[test]
    fn fixture_git_ignores_user_config() {
        let home = TempDir::new("home");
        std::fs::write(
            home.path().join(".gitconfig"),
            "[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = false\n[user]\n\tsigningkey = x\n",
        )
        .expect("gitconfig");
        let repo = TempDir::new("repo");
        std::fs::write(repo.path().join("Cargo.toml"), "[package]\n").expect("file");
        let envs = [
            ("HOME", home.path().as_os_str()),
            ("XDG_CONFIG_HOME", home.path().as_os_str()),
        ];
        git_commit(repo.path(), &envs).expect("commit despite the signing config");
        assert!(repo.path().join(".git").is_dir());
        let _ = OsStr::new("");
    }

    #[test]
    fn output_contract_parses() {
        assert_eq!(
            parse_fail("FAIL [core-token] a b/c.rs:12: banned in core crates: std"),
            Some(("core-token".into(), "a b/c.rs".into(), Some(12)))
        );
        assert_eq!(
            parse_fail("FAIL [symlink] x: y: z"),
            Some(("symlink".into(), "x".into(), None))
        );
        assert_eq!(parse_fail("FAIL [Bad] x: y"), None);
        assert_eq!(parse_fail("FAIL [x]  y"), None);
        let p = parse_output("FAIL [a] x: y\nFAIL [b] z:3: w\n2 violation(s)\n");
        assert!(p.problems.is_empty(), "{:?}", p.problems);
        assert_eq!(p.summary, Some(2));
        let p = parse_output("FAIL [a] x: y\nOK: fine\n");
        assert_eq!(p.problems, ["OK after FAIL lines"]);
        let p = parse_output("junk\n1 violation(s)\n");
        assert_eq!(
            p.problems,
            ["unparseable line: junk", "count 1 != 0 FAIL lines"]
        );
        assert_eq!(parse_output("").problems, ["no summary line"]);
    }
}
