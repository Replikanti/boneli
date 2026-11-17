//! The git runner: a fixed environment, command-scope config, explicit git
//! dirs, no call inside a workspace, and silent failures named by status
//! (ADR-010, D4).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use boneli_app::Git;
use boneli_app::contract::git::run;
use boneli_git_cli::{DEFAULT_MAX_NODES, GitCli, GitCliConfig, Transports};

use crate::support::record::{Call, Recorder, silent_failure};
use crate::support::{
    Source, TempDir, Trip, contract_source, edit, failed, host_git, open, repository, retarget, sha,
};

/// The variables every call gets, besides the command-scope config.
const FIXED: &[&str] = &[
    "GIT_ALLOW_PROTOCOL",
    "GIT_ATTR_NOSYSTEM",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_LITERAL_PATHSPECS",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_PROTOCOL_FROM_USER",
    "GIT_TERMINAL_PROMPT",
    "HOME",
    "LC_ALL",
    "TZ",
    "XDG_CONFIG_HOME",
];

/// The command-scope config with the file transport, in order.
const CONFIG: &[(&str, &str)] = &[
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("core.untrackedCache", "false"),
    ("core.autocrlf", "false"),
    ("core.symlinks", "true"),
    ("core.fileMode", "true"),
    ("core.ignoreCase", "false"),
    ("core.protectNTFS", "true"),
    ("core.protectHFS", "true"),
    ("credential.helper", ""),
    ("safe.bareRepository", "explicit"),
    ("protocol.allow", "never"),
    ("protocol.https.allow", "always"),
    ("protocol.file.allow", "always"),
    ("protocol.version", "2"),
    ("transfer.fsckObjects", "true"),
    ("fetch.recurseSubmodules", "false"),
    ("submodule.recurse", "false"),
    ("http.followRedirects", "false"),
    ("http.lowSpeedLimit", "1"),
    ("http.lowSpeedTime", "300"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("pack.threads", "1"),
    ("pack.writeReverseIndex", "false"),
];

/// The subcommands that work on a throwaway index.
const INDEXED: &[&str] = &["read-tree", "add", "write-tree", "apply"];

/// The subcommands of `diff`, which write to a throwaway object directory.
const THROWAWAY_OBJECTS: &[&str] = &["read-tree", "add", "write-tree", "diff-tree"];

/// Undoes the runner's quoting of an alternate: `"..."` with octal escapes.
fn unquote(entry: &str) -> String {
    let inner = entry
        .strip_prefix('"')
        .and_then(|e| e.strip_suffix('"'))
        .unwrap_or_else(|| panic!("not quoted: {entry}"));
    let bytes = inner.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let octal = std::str::from_utf8(&bytes[i + 1..i + 4]).expect("ascii");
            out.push(u8::from_str_radix(octal, 8).expect("octal"));
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).expect("utf-8")
}

/// Runs the whole suite through a recording git and returns every call.
fn recorded_suite(tmp: &TempDir) -> (Vec<Call>, std::path::PathBuf) {
    let (source, base) = contract_source(tmp);
    let trip = Trip::new(tmp);
    let recorder = Recorder::new(tmp);
    let make = || {
        repository(
            open(tmp, &recorder.git, DEFAULT_MAX_NODES),
            &source,
            &base,
            trip.metadata(),
        )
    };
    assert_eq!(run(make, edit, retarget, &trip), Ok(()));
    let calls = recorder.calls();
    assert!(calls.len() > 100, "only {} calls", calls.len());
    (calls, tmp.path().to_path_buf())
}

#[test]
fn every_call_has_the_fixed_environment() {
    let tmp = TempDir::new("fixed-env");
    let (calls, base_dir) = recorded_suite(&tmp);
    let mut want: Vec<String> = FIXED.iter().map(|k| (*k).to_owned()).collect();
    for n in 0..CONFIG.len() {
        want.push(format!("GIT_CONFIG_KEY_{n}"));
        want.push(format!("GIT_CONFIG_VALUE_{n}"));
    }
    want.sort();
    let mut seen_indexed = false;
    let mut seen_objects = false;
    for call in &calls {
        let mut keys = call.keys();
        let sub = call.subcommand().unwrap_or("");
        let indexed = INDEXED.contains(&sub);
        if indexed {
            let at = keys
                .iter()
                .position(|k| k == "GIT_INDEX_FILE")
                .unwrap_or_else(|| panic!("no GIT_INDEX_FILE: {call:?}"));
            keys.remove(at);
            seen_indexed = true;
        }
        // `diff`'s calls, and only they, write new objects to a throwaway
        // directory under `<root>/tmp/` and read the store's as the one
        // alternate: `add` and `diff-tree` always, `read-tree` when it
        // reads a work tree.
        let in_work_tree = call.args.iter().any(|a| a.starts_with("--work-tree="));
        let must = sub == "add" || sub == "diff-tree" || (sub == "read-tree" && in_work_tree);
        if let Some(objects) = call.var("GIT_OBJECT_DIRECTORY") {
            assert!(THROWAWAY_OBJECTS.contains(&sub), "{call:?}");
            let root = std::path::Path::new(call.var("HOME").expect("HOME"))
                .parent()
                .expect("the root");
            let objects = std::path::Path::new(objects);
            assert!(objects.starts_with(root.join("tmp")), "{call:?}");
            assert!(objects.ends_with("objects"), "{call:?}");
            let git_dir = call
                .args
                .iter()
                .find_map(|a| a.strip_prefix("--git-dir="))
                .expect("a git dir");
            let alternate = call
                .var("GIT_ALTERNATE_OBJECT_DIRECTORIES")
                .unwrap_or_else(|| panic!("no alternate: {call:?}"));
            assert_eq!(unquote(alternate), format!("{git_dir}/objects"), "{call:?}");
            for key in ["GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"] {
                let at = keys.iter().position(|k| k == key).expect("present");
                keys.remove(at);
            }
            seen_objects = true;
        } else {
            assert!(!must, "no throwaway object directory: {call:?}");
        }
        assert_eq!(keys, want, "{call:?}");
        assert_eq!(
            call.var("GIT_CONFIG_COUNT"),
            Some(&*CONFIG.len().to_string())
        );
        for (n, (key, value)) in CONFIG.iter().enumerate() {
            assert_eq!(
                call.var(&format!("GIT_CONFIG_KEY_{n}")),
                Some(*key),
                "{call:?}"
            );
            assert_eq!(
                call.var(&format!("GIT_CONFIG_VALUE_{n}")),
                Some(*value),
                "{call:?}"
            );
        }
        assert_eq!(call.var("GIT_CONFIG_GLOBAL"), Some("/dev/null"));
        assert_eq!(call.var("GIT_CONFIG_NOSYSTEM"), Some("1"));
        assert_eq!(call.var("GIT_ALLOW_PROTOCOL"), Some("https:file"));
        assert_eq!(call.var("GIT_TERMINAL_PROMPT"), Some("0"));
        assert_eq!(call.var("LC_ALL"), Some("C"));
        let home = call.var("HOME").expect("HOME");
        assert!(home.starts_with(&*base_dir.to_string_lossy()), "{home}");
        assert!(home.ends_with("/home"), "{home}");
        assert_eq!(
            call.var("XDG_CONFIG_HOME"),
            Some(&*format!("{home}/.config"))
        );
    }
    assert!(seen_indexed);
    assert!(seen_objects);
}

#[test]
fn every_call_names_its_git_dir() {
    let tmp = TempDir::new("git-dir");
    let (calls, _) = recorded_suite(&tmp);
    for call in &calls {
        let sub = call.subcommand().expect("a subcommand");
        let at = call.args.iter().position(|a| a == sub).expect("found");
        let globals = &call.args[..at];
        if sub == "version" {
            assert!(globals.is_empty(), "{call:?}");
            continue;
        }
        let dirs: Vec<&String> = globals
            .iter()
            .filter(|a| a.starts_with("--git-dir="))
            .collect();
        assert_eq!(dirs.len(), 1, "{call:?}");
        let dir = dirs[0].strip_prefix("--git-dir=").expect("prefix");
        assert!(dir.contains("/stores/"), "{call:?}");
        assert_eq!(call.cwd.to_string_lossy(), dir, "{call:?}");
        let trees: Vec<&String> = globals
            .iter()
            .filter(|a| a.starts_with("--work-tree="))
            .collect();
        if sub == "read-tree" || sub == "add" {
            assert!(trees.len() <= 1, "{call:?}");
        } else {
            assert!(trees.is_empty(), "{call:?}");
        }
        if sub == "add" {
            assert_eq!(trees.len(), 1, "{call:?}");
            assert!(trees[0].contains("/scratch/"), "{call:?}");
        }
    }
}

#[test]
fn no_call_runs_in_a_workspace() {
    let tmp = TempDir::new("no-workspace");
    let (calls, base_dir) = recorded_suite(&tmp);
    for call in &calls {
        // `HOME` is `<root>/home`; compared as path prefixes, so a
        // checkout under a directory named `scratch...` changes nothing.
        let root = std::path::Path::new(call.var("HOME").expect("HOME"))
            .parent()
            .expect("the root");
        assert!(!call.cwd.starts_with(root.join("scratch")), "{call:?}");
        assert!(!call.cwd.starts_with(root.join("tmp")), "{call:?}");
        assert!(!call.cwd.starts_with(base_dir.join("tripwire")), "{call:?}");
    }
}

#[test]
fn silent_git_failure_names_status() {
    let tmp = TempDir::new("silent");
    let git = open(&tmp, &silent_failure(&tmp, 3), DEFAULT_MAX_NODES);
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    let base = source.commit("base");
    let detail = failed(git.fetch_base(&source.url(), &sha(&base)));
    assert!(detail.contains("exit status 3"), "{detail}");
}

/// Set in the child that runs the suite under a hostile environment; its
/// value is the sentinel directory.
const HOSTILE_CHILD: &str = "BONELI_GIT_CLI_HOSTILE_CHILD";

/// Writes a hostile host configuration under `dir` that runs
/// `touch <sentinel>/tripped` from `core.fsmonitor` and a hook, and
/// returns the variables that point git at it.
fn hostile_env(dir: &std::path::Path, sentinel: &std::path::Path) -> Vec<(String, String)> {
    let touch = format!("touch {}/tripped #", sentinel.display());
    let hooks = dir.join("hooks");
    fs::create_dir_all(&hooks).expect("hooks");
    for hook in ["post-index-change", "pre-auto-gc", "reference-transaction"] {
        let file = hooks.join(hook);
        fs::write(&file, format!("#!/bin/sh\n{touch}\n")).expect("hook");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).expect("mode");
    }
    let config = format!(
        "[core]\n\tfsmonitor = {touch}\n\thooksPath = {}\n[credential]\n\thelper = !{touch}\n",
        hooks.display()
    );
    let home = dir.join("home");
    fs::create_dir_all(&home).expect("home");
    fs::write(home.join(".gitconfig"), &config).expect("gitconfig");
    let xdg = dir.join("xdg");
    fs::create_dir_all(xdg.join("git")).expect("xdg");
    fs::write(xdg.join("git").join("config"), &config).expect("xdg config");
    vec![
        ("GIT_DIR".into(), "/nonexistent".into()),
        ("GIT_WORK_TREE".into(), "/nonexistent".into()),
        ("GIT_INDEX_FILE".into(), "/nonexistent/index".into()),
        ("GIT_OBJECT_DIRECTORY".into(), "/nonexistent/objects".into()),
        ("GIT_TEMPLATE_DIR".into(), dir.display().to_string()),
        (
            "GIT_CONFIG_PARAMETERS".into(),
            format!("'core.fsmonitor'='{touch}'"),
        ),
        ("GIT_CONFIG_COUNT".into(), "1".into()),
        ("GIT_CONFIG_KEY_0".into(), "core.hooksPath".into()),
        ("GIT_CONFIG_VALUE_0".into(), hooks.display().to_string()),
        ("HOME".into(), home.display().to_string()),
        ("XDG_CONFIG_HOME".into(), xdg.display().to_string()),
        ("GIT_SSH_COMMAND".into(), touch.clone()),
        ("GIT_ASKPASS".into(), touch),
    ]
}

/// The suite passes in a child whose environment points git at a hostile
/// configuration, and nothing in it runs. `std::env::set_var` is `unsafe`
/// in edition 2024, so the hostile environment exists only in a child.
#[test]
fn host_environment_cannot_steer_git() {
    if let Some(sentinel) = std::env::var_os(HOSTILE_CHILD) {
        let tmp = TempDir::new("hostile-child");
        let (source, base) = contract_source(&tmp);
        let trip = Trip::new(&tmp);
        let make = || repository(crate::support::cli(&tmp), &source, &base, trip.metadata());
        assert_eq!(run(make, edit, retarget, &trip), Ok(()));
        assert_eq!(
            crate::support::listing(std::path::Path::new(&sentinel)),
            Vec::<String>::new()
        );
        return;
    }
    let tmp = TempDir::new("hostile");
    let sentinel = tmp.path().join("sentinel");
    fs::create_dir(&sentinel).expect("sentinel");
    let env = hostile_env(tmp.path(), &sentinel);

    // Not vacuous: the same environment steers a git that inherits it.
    let probe = Source::new(&tmp, "probe", false);
    probe.write("a", b"a", false);
    probe.commit("probe");
    let steered = Command::new(host_git())
        .args(["add", "-A"])
        .current_dir(&probe.dir)
        .envs(
            env.iter()
                .filter(|(k, _)| !k.starts_with("GIT_DIR") && k != "GIT_WORK_TREE")
                .filter(|(k, _)| k != "GIT_INDEX_FILE" && k != "GIT_OBJECT_DIRECTORY")
                .map(|(k, v)| (k.clone(), v.clone())),
        )
        .output()
        .expect("probe git");
    assert!(steered.status.success(), "{steered:?}");
    assert!(
        !crate::support::listing(&sentinel).is_empty(),
        "the hostile environment steers nothing, so the test would prove nothing"
    );
    fs::remove_dir_all(&sentinel).expect("reset");
    fs::create_dir(&sentinel).expect("sentinel");

    let exe = std::env::current_exe().expect("the test binary");
    let out = Command::new(exe)
        .args([
            "--exact",
            "environment::host_environment_cannot_steer_git",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .envs(env.iter().map(|(k, v)| (k.clone(), v.clone())))
        .env(HOSTILE_CHILD, &sentinel)
        .output()
        .expect("run the child");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 passed"),
        "the child ran no test: {stdout}"
    );
    assert_eq!(crate::support::listing(&sentinel), Vec::<String>::new());
}

/// The production transport list refuses `file://` at the URL check, and
/// its command scope does not allow the file protocol.
#[test]
fn https_only_has_no_file_protocol() {
    let tmp = TempDir::new("https-only");
    let recorder = Recorder::new(&tmp);
    let git = GitCli::open(GitCliConfig {
        git: recorder.git.clone(),
        root: tmp.path().join("root"),
        transports: Transports::Https,
        max_workspace_nodes: DEFAULT_MAX_NODES,
    })
    .expect("open");
    let source = Source::new(&tmp, "src", false);
    source.write("a", b"a", false);
    let base = source.commit("base");
    failed(git.fetch_base(&source.url(), &sha(&base)));
    let calls = recorder.calls();
    assert_eq!(calls.len(), 1, "only `version`: {calls:?}");
    let call = &calls[0];
    assert_eq!(call.var("GIT_ALLOW_PROTOCOL"), Some("https"));
    assert!(call.env.iter().all(|(_, v)| v != "protocol.file.allow"));
}
