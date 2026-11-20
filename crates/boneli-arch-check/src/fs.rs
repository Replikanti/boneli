//! File-system helpers: relative paths, lenient resolution, the package
//! and config walks, reads that fail with a tool error. The walks are
//! iterative, list names sorted by bytes and never follow a symlink.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Component, Path, PathBuf};

use crate::rules::ToolError;

/// The text of an I/O error without the ` (os error N)` suffix, like
/// `strerror`.
pub(crate) fn strerror(err: &io::Error) -> String {
    let text = err.to_string();
    match text.rfind(" (os error ") {
        Some(i) if text.ends_with(')') => text[..i].to_owned(),
        _ => text,
    }
}

/// `path` made absolute against `base` without touching the file system,
/// with `.`, `..` and repeated separators collapsed, as `os.path.abspath`
/// does.
pub(crate) fn normalize(base: &Path, path: &Path) -> Vec<OsString> {
    let mut parts: Vec<OsString> = Vec::new();
    let full;
    let path = if path.is_absolute() {
        path
    } else {
        full = base.join(path);
        &full
    };
    for c in path.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_owned()),
            Component::ParentDir => {
                parts.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    parts
}

/// The current working directory, or `/` when it cannot be read.
pub(crate) fn cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
}

/// `path` relative to `root` with `/` separators, as `os.path.relpath`
/// gives it: lexical, `..` where `path` is outside `root`, `.` for
/// `root` itself.
pub(crate) fn rel(root: &Path, path: &Path) -> OsString {
    let base = cwd();
    let r = normalize(&base, root);
    let p = normalize(&base, path);
    let common = r.iter().zip(&p).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<&OsStr> = vec![OsStr::new(".."); r.len() - common];
    parts.extend(p[common..].iter().map(OsString::as_os_str));
    if parts.is_empty() {
        return OsString::from(".");
    }
    let mut out = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(part.as_bytes());
    }
    OsString::from_vec(out)
}

/// How many symlinks [`resolve`] follows before it gives up and appends
/// the rest of the path unresolved (the kernel's own limit is 40).
const MAX_LINKS: usize = 40;

/// `path` with every symlink resolved as far as it exists, like
/// `Path.resolve(strict=False)`: relative to `base`, the existing prefix
/// resolved, a missing rest appended lexically, and a symlink loop left
/// unresolved instead of an error.
pub(crate) fn resolve_from(base: &Path, path: &Path) -> PathBuf {
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    if let Ok(found) = fs::canonicalize(&full) {
        return found;
    }
    let mut todo: Vec<OsString> = Vec::new();
    push_components(&mut todo, &full);
    let mut out = PathBuf::from("/");
    let mut links = 0;
    while let Some(part) = todo.pop() {
        if part == ".." {
            out.pop();
            continue;
        }
        let candidate = out.join(&part);
        match fs::read_link(&candidate) {
            Ok(target) if links < MAX_LINKS => {
                links += 1;
                if target.is_absolute() {
                    out = PathBuf::from("/");
                }
                push_components(&mut todo, &target);
            }
            Ok(_) => {
                out = candidate;
                while let Some(rest) = todo.pop() {
                    if rest == ".." {
                        out.pop();
                    } else {
                        out.push(rest);
                    }
                }
            }
            Err(_) => out = candidate,
        }
    }
    out
}

/// Pushes the components of `path` onto `todo` so that the first is
/// popped first, without `.`.
fn push_components(todo: &mut Vec<OsString>, path: &Path) {
    let parts: Vec<OsString> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_owned()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
        .collect();
    todo.extend(parts.into_iter().rev());
}

/// [`resolve_from`] against the current working directory.
pub(crate) fn resolve(path: &Path) -> PathBuf {
    resolve_from(&cwd(), path)
}

/// Reads at most `limit` bytes plus one, so that a larger file is known to
/// be larger without being read whole.
pub(crate) fn read_limited(path: &Path, root: &Path, limit: usize) -> Result<Vec<u8>, ToolError> {
    let cannot = |err: io::Error| {
        ToolError::new(rel(root, path), format!("cannot read: {}", strerror(&err)))
    };
    let file = fs::File::open(path).map_err(cannot)?;
    let mut data = Vec::new();
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    file.take(cap).read_to_end(&mut data).map_err(cannot)?;
    Ok(data)
}

/// The text of a file, which must be UTF-8.
pub(crate) fn read_text(path: &Path, root: &Path) -> Result<String, ToolError> {
    let data = fs::read(path).map_err(|err| {
        ToolError::new(rel(root, path), format!("cannot read: {}", strerror(&err)))
    })?;
    String::from_utf8(data).map_err(|_| ToolError::new(rel(root, path), "not UTF-8"))
}

/// One directory's entries: (name, is a symlink, is a directory after
/// following a symlink), sorted by name.
fn list_dir(dir: &Path, root: &Path) -> Result<Vec<(OsString, bool, bool)>, ToolError> {
    let cannot = |err: io::Error| {
        ToolError::new(
            rel(root, dir),
            format!("cannot read directory: {}", strerror(&err)),
        )
    };
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(cannot)? {
        let entry = entry.map_err(cannot)?;
        let kind = entry.file_type().map_err(cannot)?;
        let link = kind.is_symlink();
        let is_dir = if link {
            fs::metadata(entry.path()).is_ok_and(|m| m.is_dir())
        } else {
            kind.is_dir()
        };
        entries.push((entry.file_name(), link, is_dir));
    }
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(entries)
}

/// The files under a package directory: `.rs` files, other files and
/// symlinks, in walk order. Symlinks are listed, not followed. A
/// directory that cannot be read is a tool error naming it.
pub(crate) type PackageFiles = (Vec<PathBuf>, Vec<PathBuf>, Vec<PathBuf>);

/// Walks `pkg_dir` depth first, directories in name order.
pub(crate) fn walk_package(pkg_dir: &Path, root: &Path) -> Result<PackageFiles, ToolError> {
    let (mut files, mut others, mut links) = (Vec::new(), Vec::new(), Vec::new());
    let mut stack = vec![pkg_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = list_dir(&dir, root)?;
        let mut subdirs = Vec::new();
        for (name, link, is_dir) in &entries {
            let p = dir.join(name);
            if *link {
                links.push(p);
            } else if *is_dir {
                subdirs.push(p);
            } else if name.as_bytes().ends_with(b".rs") {
                files.push(p);
            } else {
                others.push(p);
            }
        }
        stack.extend(subdirs.into_iter().rev());
    }
    Ok((files, others, links))
}

/// Whether `path` exists (following symlinks if `follow`). A missing file,
/// a missing directory on the way and a symlink loop are `false`; any
/// other error is a tool error, so an unreadable directory never hides a
/// file.
fn exists(path: &Path, root: &Path, follow: bool) -> Result<bool, ToolError> {
    let found = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    match found {
        Ok(_) => Ok(true),
        Err(err)
            if err.kind() == io::ErrorKind::NotFound
                || err.raw_os_error() == Some(20)
                || err.raw_os_error() == Some(40) =>
        {
            Ok(false)
        }
        Err(err) => Err(ToolError::new(
            rel(root, path),
            format!("cannot read: {}", strerror(&err)),
        )),
    }
}

/// Cargo configs, clippy configs and rustup toolchain files anywhere under
/// `root`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ConfigFiles {
    pub(crate) cargo: Vec<PathBuf>,
    pub(crate) clippy: Vec<PathBuf>,
    pub(crate) toolchain: Vec<PathBuf>,
}

/// Walks `root` for files that change which tools run or how. Skips `.git`,
/// the directories in `skip` (compared after resolution: the target
/// directories) and nested checkouts (a directory with its own `.git`, such
/// as a git worktree). A symlink is not followed: one named `clippy.toml`
/// that points to a directory is not reported, a dangling one is.
pub(crate) fn walk_config_files(root: &Path, skip: &[PathBuf]) -> Result<ConfigFiles, ToolError> {
    let mut found = ConfigFiles::default();
    let mut stack = vec![root.to_path_buf()];
    while let Some(here) = stack.pop() {
        let entries = list_dir(&here, root)?;
        let mut kept = Vec::new();
        for (name, link, is_dir) in &entries {
            if !is_dir {
                continue;
            }
            let p = here.join(name);
            if name == ".git" || skip.contains(&resolve(&p)) {
                continue;
            }
            if exists(&p.join(".git"), root, true)? {
                continue;
            }
            if !link {
                kept.push(p);
            }
        }
        for name in ["config", "config.toml"] {
            let p = here.join(".cargo").join(name);
            if exists(&p, root, false)? {
                found.cargo.push(p);
            }
        }
        for (name, _, is_dir) in &entries {
            if *is_dir {
                continue;
            }
            let bytes = name.as_bytes();
            if bytes == b"clippy.toml" || bytes == b".clippy.toml" {
                found.clippy.push(here.join(name));
            }
            if bytes == b"rust-toolchain" || bytes == b"rust-toolchain.toml" {
                found.toolchain.push(here.join(name));
            }
        }
        stack.extend(kept.into_iter().rev());
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::{ConfigFiles, normalize, rel, resolve_from, walk_config_files, walk_package};
    use crate::py_vectors;
    use crate::tmp::TempDir;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    #[test]
    fn rel_matches_python_relpath() {
        for &(root, path, want) in py_vectors::REL {
            assert_eq!(rel(Path::new(root), Path::new(path)), want, "{root} {path}");
        }
        assert_eq!(normalize(Path::new("/b"), Path::new("x/../y")), ["b", "y"]);
    }

    #[test]
    fn resolve_lenient_missing_tail() {
        let tmp = TempDir::new("resolve");
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).expect("dir");
        symlink(&real, tmp.path().join("link")).expect("link");
        let base = std::fs::canonicalize(tmp.path()).expect("canonical");
        let got = resolve_from(Path::new("/"), &tmp.path().join("link/missing/../other/x"));
        assert_eq!(got, base.join("real/other/x"));
        // Relative to the base, not to the process's working directory.
        assert_eq!(resolve_from(&base, Path::new("link")), base.join("real"));
        assert_eq!(
            resolve_from(&base, Path::new("nope/a")),
            base.join("nope/a")
        );
    }

    #[test]
    fn resolve_lenient_symlink_loop() {
        let tmp = TempDir::new("loop");
        symlink("b", tmp.path().join("a")).expect("a");
        symlink("a", tmp.path().join("b")).expect("b");
        let base = std::fs::canonicalize(tmp.path()).expect("canonical");
        let got = resolve_from(&base, Path::new("a/c"));
        assert!(got.starts_with(&base), "{got:?}");
        assert!(got.ends_with("c"), "{got:?}");
    }

    /// A directory that cannot be read is a tool error naming it; the
    /// reference checker skipped it, which failed open. Skipped when the
    /// test runs as root, which reads it anyway.
    #[test]
    fn unreadable_directory_is_tool_error() {
        let tmp = TempDir::new("unreadable");
        let root = tmp.path();
        let pkg = root.join("pkg");
        std::fs::create_dir_all(pkg.join("hidden")).expect("dirs");
        std::fs::write(pkg.join("hidden/x.rs"), "").expect("file");
        let probe = root.join("owner");
        std::fs::write(&probe, "").expect("probe");
        let as_root =
            std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&probe).expect("meta")) == 0;
        let mode =
            |m| std::fs::set_permissions(pkg.join("hidden"), std::fs::Permissions::from_mode(m));
        mode(0o000).expect("chmod");
        let walked = walk_package(&pkg, root);
        let configs = walk_config_files(root, &[]);
        mode(0o755).expect("chmod");
        if as_root {
            return;
        }
        let err = walked.expect_err("unreadable");
        assert_eq!(err.path, "pkg/hidden");
        assert!(
            err.message.starts_with("cannot read directory: "),
            "{}",
            err.message
        );
        // The config walk meets the directory through its `.git` probe.
        let err = configs.expect_err("unreadable");
        assert!(
            err.path.as_encoded_bytes().starts_with(b"pkg/hidden"),
            "{:?}",
            err.path
        );
    }

    #[test]
    fn deep_directory_tree_walks_iteratively() {
        let tmp = TempDir::new("deep");
        let mut dir = tmp.path().join("p");
        for _ in 0..500 {
            dir.push("d");
        }
        std::fs::create_dir_all(&dir).expect("deep");
        std::fs::write(dir.join("x.rs"), "").expect("file");
        std::fs::write(dir.join("clippy.toml"), "").expect("file");
        let small = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn({
                let root = tmp.path().to_path_buf();
                move || {
                    let (files, _, _) = walk_package(&root.join("p"), &root).expect("walk");
                    let configs = walk_config_files(&root, &[]).expect("walk");
                    (files.len(), configs.clippy.len())
                }
            })
            .expect("spawn")
            .join()
            .expect("no overflow");
        assert_eq!(small, (1, 1));
    }

    #[test]
    fn package_walk_order_and_links() {
        let tmp = TempDir::new("walk");
        let pkg = tmp.path().join("pkg");
        for d in ["b", "a/z", "a/y"] {
            std::fs::create_dir_all(pkg.join(d)).expect("dir");
        }
        for f in ["b/1.rs", "a/z/2.rs", "a/y/3.txt", "0.rs", "a/4.rs"] {
            std::fs::write(pkg.join(f), "").expect("file");
        }
        symlink("b", pkg.join("c")).expect("dir link");
        symlink("0.rs", pkg.join("l.rs")).expect("file link");
        let (files, others, links) = walk_package(&pkg, tmp.path()).expect("walk");
        let names = |v: &[PathBuf]| -> Vec<String> {
            v.iter()
                .map(|p| p.strip_prefix(&pkg).expect("inside").display().to_string())
                .collect()
        };
        assert_eq!(names(&files), ["0.rs", "a/4.rs", "a/z/2.rs", "b/1.rs"]);
        assert_eq!(names(&others), ["a/y/3.txt"]);
        assert_eq!(names(&links), ["c", "l.rs"]);
    }

    #[test]
    fn config_walk_reports_links_and_skips() {
        let tmp = TempDir::new("config");
        let root = tmp.path();
        for d in [
            ".cargo",
            "a/.cargo",
            "nested/.cargo",
            "target/.cargo",
            "out/.cargo",
            "dir",
        ] {
            std::fs::create_dir_all(root.join(d)).expect("dir");
        }
        symlink("missing", root.join(".cargo/config.toml")).expect("dangling");
        std::fs::write(root.join("a/.cargo/config"), "").expect("file");
        std::fs::write(root.join("nested/.git"), "gitdir: x").expect("nested checkout");
        std::fs::write(root.join("nested/.cargo/config.toml"), "").expect("file");
        std::fs::write(root.join("target/.cargo/config.toml"), "").expect("file");
        std::fs::write(root.join("out/.cargo/config.toml"), "").expect("file");
        symlink("dir", root.join("clippy.toml")).expect("dir link");
        symlink("missing", root.join("a/.clippy.toml")).expect("dangling");
        std::fs::write(root.join("a/rust-toolchain"), "").expect("file");
        let skip = [
            resolve_from(Path::new("/"), &root.join("target")),
            resolve_from(root, Path::new("out")),
        ];
        let found = walk_config_files(root, &skip).expect("walk");
        let want = ConfigFiles {
            cargo: vec![
                root.join(".cargo/config.toml"),
                root.join("a/.cargo/config"),
            ],
            clippy: vec![root.join("a/.clippy.toml")],
            toolchain: vec![root.join("a/rust-toolchain")],
        };
        assert_eq!(found, want);
    }
}
