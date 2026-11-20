//! Every TOML file of the workspace parses: the Cargo manifests, the
//! architecture policy, `deny.toml` and the architecture checker's fixture
//! manifests, which the Rust checker of #35 reads through this crate
//! (ADR-011, D1). One fixture is deliberately invalid, and one uses a
//! float, which the subset refuses (ADR-015, D6).

mod common;

use std::path::{Path, PathBuf};

use boneli_toml::{ErrorKind, Feature, Table, Value, parse};
use common::{harness_limits, lookup};

const INVALID: &str = "tools/fixtures/arch/cases/tool-invalid-manifest/overlay/Cargo.toml";
const FLOAT: &str =
    "tools/fixtures/arch/cases/tool-manifest-float/overlay/crates/boneli-app/Cargo.toml";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Relative paths of every `*.toml` below the root, without following
/// symlinks, skipping build output, worktrees, dot-directories and the
/// vendored corpus.
fn toml_files() -> Vec<String> {
    let root = root();
    let corpus = Path::new("crates/boneli-toml/tests/toml-test");
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for entry in std::fs::read_dir(root.join(&rel)).expect("directory") {
            let entry = entry.expect("directory entry");
            let name = entry.file_name().into_string().expect("UTF-8 name");
            let path = rel.join(&name);
            let kind = entry.file_type().expect("file type");
            if kind.is_dir() {
                if !(name.starts_with('.')
                    || name == "target"
                    || name == "worktrees"
                    || path == corpus)
                {
                    stack.push(path);
                }
            } else if kind.is_file() && name.ends_with(".toml") {
                out.push(path.to_str().expect("UTF-8 path").to_owned());
            }
        }
    }
    out.sort();
    out
}

fn read(rel: &str) -> Table {
    let bytes = std::fs::read(root().join(rel)).expect("file");
    parse(&bytes, &harness_limits()).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn every_workspace_toml_parses() {
    let files = toml_files();
    assert!(files.len() >= 139, "{} files", files.len());
    for rel in &files {
        let bytes = std::fs::read(root().join(rel)).expect("file");
        match parse(&bytes, &harness_limits()) {
            Ok(_) => assert!(rel != INVALID && rel != FLOAT, "{rel} parsed"),
            Err(e) if rel == INVALID => {
                assert_eq!(
                    (e.kind(), e.offset(), e.line(), e.column()),
                    (ErrorKind::UnexpectedByte, 10, 1, 11)
                );
            }
            Err(e) if rel == FLOAT => {
                assert_eq!(
                    (e.kind(), e.line(), e.column()),
                    (ErrorKind::Unsupported(Feature::Float), 8, 9)
                );
            }
            Err(e) => panic!("{rel}: {e}"),
        }
    }
    assert!(files.iter().any(|f| f == INVALID));
    assert!(files.iter().any(|f| f == FLOAT));
    eprintln!("{} workspace TOML files", files.len());
}

#[test]
fn workspace_spot_values() {
    let s = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_owned);
    let ws = read("Cargo.toml");
    assert_eq!(
        s(lookup(&ws, &["workspace", "lints", "rust", "unsafe_code"])).as_deref(),
        Some("forbid")
    );
    let sys = read("crates/boneli-sys/Cargo.toml");
    assert_eq!(
        s(lookup(&sys, &["lints", "clippy", "unwrap_used"])).as_deref(),
        Some("forbid")
    );
    let cases = "tools/fixtures/arch/cases";
    let brace = read(&format!(
        "{cases}/core-token-brace-in-file-name/overlay/crates/boneli-domain/Cargo.toml"
    ));
    assert_eq!(
        s(lookup(&brace, &["lib", "path"])).as_deref(),
        Some("src/{:p}.rs")
    );
    let cfg = read(&format!(
        "{cases}/tool-malformed-cfg/overlay/crates/boneli-http/Cargo.toml"
    ));
    let deps = lookup(
        &cfg,
        &[
            "target",
            "cfg(target_os = \"li\\nux\")",
            "dependencies",
            "leftpad",
        ],
    );
    assert_eq!(s(deps).as_deref(), Some("1"));
    let lints = read(&format!(
        "{cases}/ok-sys-lints/overlay/crates/boneli-sys/Cargo.toml"
    ));
    assert_eq!(
        lookup(&lints, &["lints", "clippy", "pedantic", "priority"]).and_then(Value::as_integer),
        Some(-1)
    );
    let bin = read(&format!(
        "{cases}/target-bin-not-rs/overlay/crates/boneli-store-mem/Cargo.toml"
    ));
    let bins = bin.get("bin").and_then(Value::as_array).expect("[[bin]]");
    assert_eq!(bins.len(), 1);
    assert_eq!(
        s(bins[0].as_table().and_then(|t| t.get("name"))).as_deref(),
        Some("store-mem")
    );
    let replace = read(&format!("{cases}/replace-table/overlay/Cargo.toml"));
    assert!(lookup(&replace, &["replace", "httparse:1.0.0", "path"]).is_some());
    let policy = read("tools/architecture.toml");
    assert_eq!(
        lookup(&policy, &["roles", "build-script"]),
        Some(&Value::Array(Vec::new()))
    );
}
