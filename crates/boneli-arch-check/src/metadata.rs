//! The output of `cargo metadata --format-version 1`, parsed under limits
//! into the fields the rules read (ADR-015, D4). A missing or mistyped
//! field is a tool error naming it, never a panic.

use std::path::PathBuf;

use boneli_json::{Limits, Value};

use crate::rules::ToolError;

/// The longest output accepted: 109.9 times the 152,604 bytes the workspace
/// printed when this was planned, room for about 4,947 packages at 3,391
/// bytes each (ADR-015, D4).
pub(crate) const MAX_BYTES: usize = 16_777_216;
/// The deepest nesting: the next power of two above cargo's 80 levels of
/// `[package.metadata]` plus the 4 around them (ADR-015, D4).
pub(crate) const MAX_DEPTH: usize = 128;
/// The most values: the next power of two above 4,947 packages at 146.7
/// values each, about 725,700 (ADR-015, D4).
pub(crate) const MAX_VALUES: usize = 1_048_576;

/// A package.
#[derive(Debug)]
pub(crate) struct Package {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: Option<String>,
    pub(crate) manifest_path: PathBuf,
    pub(crate) targets: Vec<Target>,
    /// Whether the package declares any feature.
    pub(crate) has_features: bool,
    pub(crate) dependencies: Vec<Dependency>,
}

/// A build target of a package.
#[derive(Debug)]
pub(crate) struct Target {
    pub(crate) name: String,
    pub(crate) kind: Vec<String>,
    pub(crate) crate_types: Vec<String>,
    pub(crate) src_path: PathBuf,
}

/// A declared dependency.
#[derive(Debug)]
pub(crate) struct Dependency {
    pub(crate) name: String,
    /// `None` for a normal dependency, else `dev` or `build`.
    pub(crate) kind: Option<String>,
    pub(crate) target: Option<String>,
    pub(crate) path: Option<PathBuf>,
    pub(crate) source: Option<String>,
    /// The name the dependent uses for it, when the manifest renames it.
    pub(crate) rename: Option<String>,
}

/// A node of the resolved graph.
#[derive(Debug)]
pub(crate) struct Node {
    pub(crate) id: String,
    pub(crate) deps: Vec<NodeDep>,
}

/// A resolved edge.
#[derive(Debug)]
pub(crate) struct NodeDep {
    pub(crate) pkg: String,
    pub(crate) dep_kinds: Vec<DepKind>,
}

/// One kind of a resolved edge.
#[derive(Debug)]
pub(crate) struct DepKind {
    pub(crate) kind: Option<String>,
    pub(crate) target: Option<String>,
}

/// What the rules read from `cargo metadata`.
#[derive(Debug)]
pub(crate) struct Metadata {
    pub(crate) packages: Vec<Package>,
    pub(crate) workspace_members: Vec<String>,
    pub(crate) nodes: Vec<Node>,
}

fn unexpected(field: &str) -> ToolError {
    ToolError::new(
        "Cargo.toml",
        format!("cargo metadata printed unexpected JSON: {field}"),
    )
}

fn field<'a>(v: &'a Value, key: &str, path: &str) -> Result<&'a Value, ToolError> {
    v.get(key).ok_or_else(|| unexpected(path))
}

fn string(v: &Value, key: &str, path: &str) -> Result<String, ToolError> {
    field(v, key, path)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| unexpected(path))
}

/// A string that may be missing or null.
fn optional(v: &Value, key: &str, path: &str) -> Result<Option<String>, ToolError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(unexpected(path)),
    }
}

fn array<'a>(v: &'a Value, key: &str, path: &str) -> Result<&'a [Value], ToolError> {
    field(v, key, path)?
        .as_array()
        .ok_or_else(|| unexpected(path))
}

fn strings(v: &Value, key: &str, path: &str) -> Result<Vec<String>, ToolError> {
    array(v, key, path)?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_owned)
                .ok_or_else(|| unexpected(path))
        })
        .collect()
}

/// Parses the output of `cargo metadata`.
pub(crate) fn parse(stdout: &[u8]) -> Result<Metadata, ToolError> {
    let limits = Limits::new(MAX_BYTES, MAX_DEPTH, MAX_VALUES)
        .map_err(|e| ToolError::new("Cargo.toml", format!("JSON limits: {e}")))?;
    let root = boneli_json::parse(stdout, &limits).map_err(|e| {
        ToolError::new(
            "Cargo.toml",
            format!("cargo metadata printed invalid JSON: {e}"),
        )
    })?;
    let mut packages = Vec::new();
    for p in array(&root, "packages", "packages")? {
        let mut targets = Vec::new();
        for t in array(p, "targets", "packages.targets")? {
            targets.push(Target {
                name: string(t, "name", "packages.targets.name")?,
                kind: strings(t, "kind", "packages.targets.kind")?,
                crate_types: strings(t, "crate_types", "packages.targets.crate_types")?,
                src_path: PathBuf::from(string(t, "src_path", "packages.targets.src_path")?),
            });
        }
        let mut dependencies = Vec::new();
        for d in array(p, "dependencies", "packages.dependencies")? {
            dependencies.push(Dependency {
                name: string(d, "name", "packages.dependencies.name")?,
                kind: match field(d, "kind", "packages.dependencies.kind")? {
                    Value::Null => None,
                    Value::String(s) => Some(s.clone()),
                    _ => return Err(unexpected("packages.dependencies.kind")),
                },
                target: optional(d, "target", "packages.dependencies.target")?,
                path: optional(d, "path", "packages.dependencies.path")?.map(PathBuf::from),
                source: optional(d, "source", "packages.dependencies.source")?,
                rename: optional(d, "rename", "packages.dependencies.rename")?,
            });
        }
        let features = field(p, "features", "packages.features")?
            .as_object()
            .ok_or_else(|| unexpected("packages.features"))?;
        packages.push(Package {
            id: string(p, "id", "packages.id")?,
            name: string(p, "name", "packages.name")?,
            version: string(p, "version", "packages.version")?,
            source: optional(p, "source", "packages.source")?,
            manifest_path: PathBuf::from(string(p, "manifest_path", "packages.manifest_path")?),
            targets,
            has_features: !features.is_empty(),
            dependencies,
        });
    }
    let workspace_members = strings(&root, "workspace_members", "workspace_members")?;
    let resolve = field(&root, "resolve", "resolve")?;
    let mut nodes = Vec::new();
    for n in array(resolve, "nodes", "resolve.nodes")? {
        let mut deps = Vec::new();
        for d in array(n, "deps", "resolve.nodes.deps")? {
            let mut dep_kinds = Vec::new();
            for k in array(d, "dep_kinds", "resolve.nodes.deps.dep_kinds")? {
                if k.as_object().is_none() {
                    return Err(unexpected("resolve.nodes.deps.dep_kinds"));
                }
                dep_kinds.push(DepKind {
                    kind: optional(k, "kind", "resolve.nodes.deps.dep_kinds.kind")?,
                    target: optional(k, "target", "resolve.nodes.deps.dep_kinds.target")?,
                });
            }
            deps.push(NodeDep {
                pkg: string(d, "pkg", "resolve.nodes.deps.pkg")?,
                dep_kinds,
            });
        }
        nodes.push(Node {
            id: string(n, "id", "resolve.nodes.id")?,
            deps,
        });
    }
    Ok(Metadata {
        packages,
        workspace_members,
        nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_BYTES, MAX_DEPTH, MAX_VALUES, parse};

    const MINIMAL: &str = r#"{"packages":[{"id":"a 0.0.0","name":"a","version":"0.0.0","source":null,
        "manifest_path":"/w/a/Cargo.toml","targets":[{"name":"a","kind":["lib"],"crate_types":["lib"],
        "src_path":"/w/a/src/lib.rs"}],"features":{},"dependencies":[{"name":"b","kind":null,
        "target":null,"source":"registry+x"}]}],"workspace_members":["a 0.0.0"],
        "resolve":{"nodes":[{"id":"a 0.0.0","deps":[{"pkg":"b","dep_kinds":[{"kind":null,"target":null}]}]}]}}"#;

    #[test]
    fn metadata_reads_the_fields() {
        let meta = parse(MINIMAL.as_bytes()).expect("parses");
        assert_eq!(meta.packages.len(), 1);
        let p = &meta.packages[0];
        assert_eq!((p.name.as_str(), p.source.as_deref()), ("a", None));
        assert!(!p.has_features);
        assert_eq!(p.dependencies[0].path, None);
        assert_eq!(p.dependencies[0].source.as_deref(), Some("registry+x"));
        assert_eq!(meta.nodes[0].deps[0].dep_kinds[0].kind, None);
    }

    #[test]
    fn metadata_missing_field_is_tool_error() {
        for (from, to, field) in [
            (
                r#""src_path":"/w/a/src/lib.rs""#,
                r#""src":"x""#,
                "packages.targets.src_path",
            ),
            (r#""features":{}"#, r#""features":[]"#, "packages.features"),
            (r#""kind":null,"#, "", "packages.dependencies.kind"),
            (
                r#""resolve":{"nodes""#,
                r#""resolve":{"nodez""#,
                "resolve.nodes",
            ),
            (
                r#""workspace_members":["a 0.0.0"]"#,
                r#""workspace_members":[1]"#,
                "workspace_members",
            ),
            (
                r#""dep_kinds":[{"kind":null,"target":null}]"#,
                r#""dep_kinds":[1]"#,
                "resolve.nodes.deps.dep_kinds",
            ),
        ] {
            let input = MINIMAL.replacen(from, to, 1);
            assert_ne!(input, MINIMAL, "{from}");
            let err = parse(input.as_bytes()).expect_err(field);
            assert_eq!(err.path, "Cargo.toml");
            assert_eq!(
                err.message,
                format!("cargo metadata printed unexpected JSON: {field}")
            );
        }
        let err = parse(b"{").expect_err("invalid");
        assert!(
            err.message
                .starts_with("cargo metadata printed invalid JSON: ")
        );
    }

    /// Each limit is inclusive: at the limit the parser accepts the input
    /// (and the missing fields are reported), one above it refuses it.
    #[test]
    fn metadata_limits_are_inclusive() {
        let parsed = |input: &[u8]| match parse(input) {
            Err(e) if e.message.contains("unexpected JSON") => Ok(()),
            Err(e) => Err(e.message),
            Ok(_) => Ok(()),
        };
        // Bytes: an object padded with spaces.
        let mut big = vec![b' '; MAX_BYTES];
        big[0] = b'{';
        big[MAX_BYTES - 1] = b'}';
        assert_eq!(parsed(&big), Ok(()));
        big.push(b' ');
        assert!(parsed(&big).expect_err("too large").contains("too large"));
        // Values: an array holding MAX_VALUES - 1 elements is MAX_VALUES values.
        let values = |n: usize| {
            let mut s = String::with_capacity(2 * n + 2);
            s.push('[');
            for i in 0..n {
                if i > 0 {
                    s.push(',');
                }
                s.push('0');
            }
            s.push(']');
            s
        };
        assert_eq!(parsed(values(MAX_VALUES - 1).as_bytes()), Ok(()));
        assert!(
            parsed(values(MAX_VALUES).as_bytes())
                .expect_err("too many")
                .contains("too many")
        );
        // Depth: nested arrays.
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert_eq!(parsed(deep(MAX_DEPTH).as_bytes()), Ok(()));
        assert!(
            parsed(deep(MAX_DEPTH + 1).as_bytes())
                .expect_err("too deep")
                .contains("too deep")
        );
    }
}
