//! Boneli support crate: the store-root rules that file-backed adapters
//! share (ADR-021), and the root of the git adapter (ADR-024).
//!
//! A store root is a private directory under ancestors that no one else can
//! rename: [`prepare_root`] checks a root, creates it `0o700` where it is
//! missing and returns it resolved, and [`create`] makes the directories a
//! store keeps under it. The rules come from ADR-009 D8 (`boneli-oci`) and
//! ADR-012 D1 (`boneli-store-fs`), which held one copy each until #66. A
//! consumer adds its own rules on the root's text through the `text_rule`
//! argument; the overlay separators of `boneli-oci` stay there.
//!
//! [`create_new_root`] applies the same rules to a root that must not
//! exist yet, the git adapter's (ADR-024): it is made by one non-recursive
//! `mkdir` under its resolved, checked parent, and one that exists is an
//! error.
#![doc(test(attr(forbid(unsafe_code))))]

use std::fmt;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Why a root was refused.
#[derive(Debug)]
pub enum Error {
    /// The root, or one of its ancestors at `path`, breaks a rule.
    Rule {
        /// The path that breaks it: the root as given, as it would be
        /// created, or as resolved, or an ancestor.
        path: PathBuf,
        /// The rule.
        reason: &'static str,
    },
    /// The filesystem failed at `path`.
    Io {
        /// Where.
        path: PathBuf,
        /// The error.
        source: io::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rule { path, reason } => write!(f, "store root {}: {reason}", path.display()),
            Error::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Rule { .. } => None,
        }
    }
}

fn io_err(path: &Path, source: io::Error) -> Error {
    Error::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn rule(path: &Path, reason: &'static str) -> Error {
    Error::Rule {
        path: path.to_path_buf(),
        reason,
    }
}

/// The owner of the root and of this process: the uid of `/proc/self`,
/// which is this process's effective uid. A std-only crate cannot call
/// `geteuid` (ADR-021, D1).
fn own_uid(at: &Path) -> Result<u32, Error> {
    let me = Path::new("/proc/self");
    fs::metadata(me).map(|m| m.uid()).map_err(|e| io_err(at, e))
}

/// Whether `path` has a `.` or `..` component. Decided on the bytes:
/// `Path::components` drops every `.` but a leading one.
fn has_dot_component(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .split(|&b| b == b'/')
        .any(|c| c == b"." || c == b"..")
}

/// What [`ancestor_problem`] judges of one ancestor.
#[derive(Clone, Copy, Debug)]
struct AncestorFacts {
    is_dir: bool,
    owner: u32,
    /// The full `st_mode`, file type bits included.
    mode: u32,
    /// The ancestor is `/`.
    is_fs_root: bool,
}

/// The rule an ancestor breaks, if any: sshd's `StrictModes`. A directory,
/// owned by root or by `uid`, and not writable by its group or by others
/// unless it is sticky. Anyone who can rename an entry of an ancestor can
/// swap the root after it was checked and plant what the store hands out
/// (layers, ADR-009) or rewrite what it keeps (run logs, ADR-012); in a
/// sticky directory only an entry's owner can rename it, and the next entry
/// down is root's or the caller's. The filesystem root is checked for its
/// mode only: whoever owns it owns every path on the host, and in a user
/// namespace it shows the overflow uid.
fn ancestor_problem(facts: AncestorFacts, uid: u32) -> Option<&'static str> {
    if !facts.is_dir {
        return Some("an ancestor of the root must be a directory");
    }
    if !facts.is_fs_root && facts.owner != 0 && facts.owner != uid {
        return Some("an ancestor of the root must be owned by root or the caller");
    }
    if facts.mode & 0o022 != 0 && facts.mode & 0o1000 == 0 {
        return Some(
            "an ancestor of the root must not be writable by its group or others unless it is sticky",
        );
    }
    None
}

/// Checks `dir` and each of its ancestors by [`ancestor_problem`], from
/// `dir` up, so the deepest offender is reported. `dir` must be resolved,
/// so the walk sees no symlink.
fn check_ancestors(dir: &Path, uid: u32) -> Result<(), Error> {
    for at in dir.ancestors() {
        let meta = fs::symlink_metadata(at).map_err(|e| io_err(at, e))?;
        let facts = AncestorFacts {
            is_dir: meta.is_dir(),
            owner: meta.uid(),
            mode: meta.mode(),
            is_fs_root: at.parent().is_none(),
        };
        if let Some(reason) = ancestor_problem(facts, uid) {
            return Err(rule(at, reason));
        }
    }
    Ok(())
}

/// Creates `dir` with mode `0o700` where it is missing, its missing
/// ancestors included; a `dir` that exists is not an error. Only the
/// caller reads or writes a store (ADR-021, D2).
pub fn create(dir: &Path) -> Result<(), Error> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| io_err(dir, e))
}

/// Checks `root`, creates it `0o700` where it is missing and returns it
/// resolved (ADR-021, D2):
///
/// - `root` must be absolute, without a `.` or `..` component, and pass
///   `text_rule`;
/// - a missing root is created only once the existing ancestors pass the
///   ancestor check below, and only at the path that check saw: the
///   resolved deepest existing ancestor joined with the missing names,
///   which must pass `text_rule` too (ADR-021, D3);
/// - the resolved root must pass `text_rule`, be a directory owned by the
///   caller with no group or other permission bits;
/// - each of its ancestors must be a directory owned by root or the caller
///   and not writable by its group or others unless it is sticky (sshd's
///   `StrictModes`), so no one else can swap the root once it is checked.
///
/// `text_rule` returns the reason it refuses a path; it sees the root as
/// given, then as it would be created (when missing), then as resolved.
pub fn prepare_root(
    root: &Path,
    text_rule: &dyn Fn(&Path) -> Result<(), &'static str>,
) -> Result<PathBuf, Error> {
    if !root.is_absolute() {
        return Err(rule(root, "must be an absolute path"));
    }
    // The check before creation walks the root's text, which `..` makes
    // name an ancestor other than the one creation resolves to.
    if has_dot_component(root) {
        return Err(rule(root, "must not have a `.` or `..` component"));
    }
    text_rule(root).map_err(|reason| rule(root, reason))?;
    let uid = own_uid(root)?;
    if fs::symlink_metadata(root).is_err() {
        // Nothing is created under an ancestor that fails the check.
        match root
            .ancestors()
            .skip(1)
            .find(|a| fs::symlink_metadata(a).is_ok())
        {
            Some(existing) => {
                let canon = existing.canonicalize().map_err(|e| io_err(existing, e))?;
                check_ancestors(&canon, uid)?;
                // Created where the check looked, not through `root` again:
                // an ancestor link re-pointed since cannot redirect it, and
                // a name the text rule refuses is never made (ADR-021, D3).
                let missing = root.strip_prefix(existing).map_err(|_| {
                    let unreachable = "an ancestor of the root is not a prefix of it";
                    io_err(
                        root,
                        io::Error::new(io::ErrorKind::InvalidInput, unreachable),
                    )
                })?;
                let prospective = canon.join(missing);
                text_rule(&prospective).map_err(|reason| rule(&prospective, reason))?;
                create(&prospective)?;
            }
            None => create(root)?,
        }
    }
    let resolved = root.canonicalize().map_err(|e| io_err(root, e))?;
    text_rule(&resolved).map_err(|reason| rule(&resolved, reason))?;
    let meta = fs::metadata(&resolved).map_err(|e| io_err(&resolved, e))?;
    if !meta.is_dir() {
        return Err(rule(&resolved, "must be a directory"));
    }
    if meta.uid() != uid {
        return Err(rule(&resolved, "must be owned by the caller"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(rule(
            &resolved,
            "must have no group or other permission bits",
        ));
    }
    if let Some(parent) = resolved.parent() {
        check_ancestors(parent, uid)?;
    }
    Ok(resolved)
}

/// Checks `root` and creates it, `0o700` whatever the umask, where it must
/// not exist yet; returns it as created (ADR-024, D2):
///
/// - `root` must be absolute, without a `.` or `..` component, and pass
///   `text_rule`;
/// - its parent must exist; it is resolved, and it and each of its
///   ancestors must pass the ancestor check of [`prepare_root`];
/// - the root is the resolved parent joined with the root's name, which
///   must pass `text_rule` too, and is made there by one non-recursive
///   `mkdir`, so a root that exists in any form (a directory, a file, a
///   symlink, a dangling one) is an [`Error::Io`] of kind
///   [`io::ErrorKind::AlreadyExists`], and of two callers racing on one
///   root exactly one succeeds. `/` has no parent and is that error too.
///
/// `text_rule` returns the reason it refuses a path; it sees the root as
/// given, then as it will be created.
pub fn create_new_root(
    root: &Path,
    text_rule: &dyn Fn(&Path) -> Result<(), &'static str>,
) -> Result<PathBuf, Error> {
    if !root.is_absolute() {
        return Err(rule(root, "must be an absolute path"));
    }
    // The parent is resolved, and `..` would make the root's name refer to
    // a directory other than the one checked.
    if has_dot_component(root) {
        return Err(rule(root, "must not have a `.` or `..` component"));
    }
    text_rule(root).map_err(|reason| rule(root, reason))?;
    let (Some(parent), Some(name)) = (root.parent(), root.file_name()) else {
        // Only `/` (and `//`) is left without either: it exists.
        let fs_root = Path::new("/");
        return Err(io_err(fs_root, io::ErrorKind::AlreadyExists.into()));
    };
    let uid = own_uid(root)?;
    // Not created: the parent is the operator's configuration (ADR-024, D2).
    let parent = parent.canonicalize().map_err(|e| io_err(parent, e))?;
    check_ancestors(&parent, uid)?;
    // Created where the check looked, not through `root` again: an
    // ancestor link re-pointed since cannot redirect it (ADR-021, D3).
    let prospective = parent.join(name);
    text_rule(&prospective).map_err(|reason| rule(&prospective, reason))?;
    DirBuilder::new()
        .mode(0o700)
        .create(&prospective)
        .map_err(|e| io_err(&prospective, e))?;
    // The umask may have cleared bits of `0o700`; ADR-010 D7 states the
    // mode, not the mode under some umask.
    fs::set_permissions(&prospective, fs::Permissions::from_mode(0o700))
        .map_err(|e| io_err(&prospective, e))?;
    Ok(prospective)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: u32 = 0o040_000;
    const FILE: u32 = 0o100_000;
    const ME: u32 = 1000;
    const OTHER: u32 = 1001;
    const OVERFLOW: u32 = 65534;

    const NOT_DIR: Option<&str> = Some("an ancestor of the root must be a directory");
    const OWNER: Option<&str> = Some("an ancestor of the root must be owned by root or the caller");
    const MODE: Option<&str> = Some(
        "an ancestor of the root must not be writable by its group or others unless it is sticky",
    );

    fn facts(is_dir: bool, owner: u32, mode: u32, is_fs_root: bool) -> AncestorFacts {
        AncestorFacts {
            is_dir,
            owner,
            mode,
            is_fs_root,
        }
    }

    /// Every row of the ancestor rule on full `st_mode` values, including
    /// the setgid and setuid modes `chmod` may drop on a real directory.
    #[test]
    fn ancestor_problem_table() {
        let rows: &[(AncestorFacts, Option<&str>)] = &[
            // Mode: refused when group or other may write and not sticky.
            (facts(true, ME, DIR | 0o777, false), MODE),
            (facts(true, ME, DIR | 0o775, false), MODE),
            (facts(true, ME, DIR | 0o757, false), MODE),
            (facts(true, ME, DIR | 0o770, false), MODE),
            (facts(true, ME, DIR | 0o707, false), MODE),
            (facts(true, ME, DIR | 0o2775, false), MODE),
            (facts(true, ME, DIR | 0o4777, false), MODE),
            (facts(true, ME, DIR | 0o1777, false), None),
            (facts(true, ME, DIR | 0o1775, false), None),
            (facts(true, ME, DIR | 0o1757, false), None),
            (facts(true, ME, DIR | 0o755, false), None),
            (facts(true, ME, DIR | 0o711, false), None),
            (facts(true, ME, DIR | 0o700, false), None),
            (facts(true, ME, DIR | 0o2755, false), None),
            // Owner: root or the caller.
            (facts(true, 0, DIR | 0o755, false), None),
            (facts(true, OTHER, DIR | 0o755, false), OWNER),
            (facts(true, OTHER, DIR | 0o555, false), OWNER),
            (facts(true, OTHER, DIR | 0o1777, false), OWNER),
            // The owner rule comes before the mode rule.
            (facts(true, OTHER, DIR | 0o777, false), OWNER),
            // The filesystem root: any owner, but not any mode.
            (facts(true, OVERFLOW, DIR | 0o755, true), None),
            (facts(true, OTHER, DIR | 0o555, true), None),
            (facts(true, OVERFLOW, DIR | 0o777, true), MODE),
            (facts(true, OVERFLOW, DIR | 0o1777, true), None),
            // Not a directory comes first.
            (facts(false, OTHER, FILE | 0o777, false), NOT_DIR),
            (facts(false, ME, FILE | 0o600, false), NOT_DIR),
            (facts(false, 0, 0o120_777, true), NOT_DIR),
        ];
        for (row, expected) in rows {
            assert_eq!(ancestor_problem(*row, ME), *expected, "{row:?}");
        }
        // The caller's uid is what counts, not a fixed one.
        assert_eq!(
            ancestor_problem(facts(true, OTHER, DIR | 0o755, false), OTHER),
            None
        );
    }

    /// `.` and `..` components are found wherever they stand; names that
    /// only contain dots, or look like them, are not.
    #[test]
    fn dot_component_bytes() {
        for dotted in [
            "/.", "/..", "/a/.", "/a/..", "/a/./b", "/a/../b", "/a//./b", "/a/b/..", "./a", "../a",
            ".", "..",
        ] {
            assert!(has_dot_component(Path::new(dotted)), "{dotted}");
        }
        for plain in [
            "/",
            "//",
            "",
            "/a/...",
            "/a/.b",
            "/a/..b",
            "/a/b.",
            "/a/b..",
            "/a/\u{2024}",
            "/a/\u{2025}",
            "/a/\u{FF0E}\u{FF0E}",
            "/a/.\u{200B}",
            "/a/ ..",
            "/a/.. ",
            "/a/%2e%2e",
            "/a/..\\x",
            "/a/.\\.",
        ] {
            assert!(!has_dot_component(Path::new(plain)), "{plain}");
        }
    }
}
