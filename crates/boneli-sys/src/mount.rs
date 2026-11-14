//! The sandbox's root, mounts, hostname and loopback (ADR-007, D7).
//!
//! The parent validates a [`Root`] and turns it into a list of operations
//! whose every byte is prepared before the clone ([`plan`]); the cloned
//! child runs them with raw syscalls on that memory ([`run`]), allocating
//! nothing (ADR-007, D4).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::child::{Failure, Fault, Step, fail, inject};
use crate::error::{Error, Result, errno};
use crate::ffi;

/// Mount options must fit one page with their terminating NUL: the kernel
/// copies them with `copy_mount_options`, one page, and 4096 is the
/// x86_64 page and the smallest arm64 page (ADR-007, D7).
pub const OPTIONS_MAX: usize = 4096;

/// The size of the minimal `/dev` tmpfs: it holds only empty files,
/// symlinks and two directories (ADR-007, D7).
const DEV_TMPFS_DATA: &CStr = c"size=65536,mode=0755";

/// The device nodes of the minimal `/dev`: the OCI default devices without
/// `/dev/console`, each bound from the host's node of the same name.
const DEVICES: [(&CStr, &CStr); 6] = [
    (c"null", c"/dev/null"),
    (c"zero", c"/dev/zero"),
    (c"full", c"/dev/full"),
    (c"random", c"/dev/random"),
    (c"urandom", c"/dev/urandom"),
    (c"tty", c"/dev/tty"),
];

/// The symlinks of the minimal `/dev`: name, then target.
const DEV_LINKS: [(&CStr, &CStr); 5] = [
    (c"ptmx", c"pts/ptmx"),
    (c"fd", c"/proc/self/fd"),
    (c"stdin", c"/proc/self/fd/0"),
    (c"stdout", c"/proc/self/fd/1"),
    (c"stderr", c"/proc/self/fd/2"),
];

/// The entries of the minimal `/dev`, sorted: the devices, `pts`, `shm`
/// and the symlinks (13).
pub const DEV_ENTRIES: [&str; 13] = [
    "fd", "full", "null", "ptmx", "pts", "random", "shm", "stderr", "stdin", "stdout", "tty",
    "urandom", "zero",
];

/// An absolute path inside the sandbox: no `.` or `..` component, no empty
/// component (`//` or a trailing `/`), no NUL.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InsidePath(String);

impl InsidePath {
    /// A path that can be a mount target or a working directory. `/` is
    /// refused here, because a mount onto it would replace the root; use
    /// [`InsidePath::root`] for a working directory of `/`.
    pub fn new(path: &str) -> Result<InsidePath> {
        let bad = |reason| Error::InvalidInsidePath {
            path: path.to_string(),
            reason,
        };
        if path.contains('\0') {
            return Err(bad("contains a NUL byte"));
        }
        let Some(rest) = path.strip_prefix('/') else {
            return Err(bad("is not absolute"));
        };
        if rest.is_empty() {
            return Err(bad("is the root, which is not a mount target"));
        }
        for component in rest.split('/') {
            match component {
                "" => return Err(bad("has an empty component (// or a trailing /)")),
                "." | ".." => return Err(bad("has a . or .. component")),
                _ => {}
            }
        }
        Ok(InsidePath(path.to_string()))
    }

    /// `/`, as a working directory.
    pub fn root() -> InsidePath {
        InsidePath("/".to_string())
    }

    /// The path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_root(&self) -> bool {
        self.0 == "/"
    }

    /// Whether `self` is a proper ancestor of `other`.
    fn is_ancestor_of(&self, other: &InsidePath) -> bool {
        other.0.len() > self.0.len()
            && other.0.starts_with(&self.0)
            && other.0.as_bytes()[self.0.len()] == b'/'
    }

    /// The path without its leading `/`, for `openat2` beneath the root.
    fn relative(&self) -> &str {
        &self.0[1..]
    }
}

/// The sandbox's hostname: 1-64 bytes (`HOST_NAME_MAX`) of `[A-Za-z0-9.-]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hostname(String);

impl Hostname {
    /// Checks the form.
    pub fn new(name: &str) -> Result<Hostname> {
        let ok = (1..=64).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        if ok {
            Ok(Hostname(name.to_string()))
        } else {
            Err(Error::InvalidHostname(name.to_string()))
        }
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One mount of the sandbox, on a target that must exist in the root (the
/// image or the top layer provides mount points).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mount {
    /// A host file or directory, not recursive. The target must be of the
    /// same kind (a directory onto a directory, anything else onto a
    /// non-directory, such as a broker's socket onto an empty file).
    /// `nosuid,nodev`, plus `ro` unless writable; flags the source carries
    /// stay.
    Bind {
        /// The host path, resolved without following any symlink.
        source: PathBuf,
        /// Where it appears.
        target: InsidePath,
        /// Whether the sandbox may write through it.
        writable: bool,
    },
    /// A tmpfs, `nosuid,nodev`.
    Tmpfs {
        /// Where it appears.
        target: InsidePath,
        /// Its size limit; no default, zero (unlimited for the kernel) is
        /// refused.
        size_bytes: u64,
        /// The mode of its root, at most `0o7777`.
        mode: u32,
    },
    /// A writable overlay of one host directory, `nosuid,nodev`; writes go
    /// to `upper`.
    Overlay {
        /// The read-only lower directory.
        lower: PathBuf,
        /// The upper directory, which receives every write.
        upper: PathBuf,
        /// Overlay's work directory, on the same filesystem as `upper`.
        work: PathBuf,
        /// Where it appears.
        target: InsidePath,
    },
    /// A procfs of the sandbox's PID namespace, `nosuid,nodev,noexec`.
    Proc {
        /// Where it appears, normally `/proc`.
        target: InsidePath,
    },
    /// The minimal `/dev`: a read-only tmpfs with `null`, `zero`, `full`,
    /// `random`, `urandom` and `tty` bound from the host, a private
    /// `devpts`, the `ptmx`, `fd` and stdio symlinks, and a `shm` tmpfs.
    Dev {
        /// Where it appears, normally `/dev`.
        target: InsidePath,
        /// The size limit of `shm`; no default, zero is refused.
        shm_size_bytes: u64,
    },
}

impl Mount {
    /// The mount's target.
    pub fn target(&self) -> &InsidePath {
        match self {
            Mount::Bind { target, .. }
            | Mount::Tmpfs { target, .. }
            | Mount::Overlay { target, .. }
            | Mount::Proc { target }
            | Mount::Dev { target, .. } => target,
        }
    }
}

/// The sandbox's file system and identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    /// Host directories, bottom first. One layer is bound read-only; more
    /// become a read-only overlay with `userxattr`.
    pub layers: Vec<PathBuf>,
    /// An empty host directory the root is mounted on before
    /// `pivot_root`; nothing appears there on the host, because the mount
    /// lives in the sandbox's mount namespace.
    pub staging: PathBuf,
    /// The mounts, in order. A mount may not hide an earlier one (a later
    /// mount of an ancestor of its target) or share its target.
    pub mounts: Vec<Mount>,
    /// The hostname in the new UTS namespace.
    pub hostname: Hostname,
    /// The working directory of the program.
    pub cwd: InsidePath,
}

/// One operation of the child, with every byte it needs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Op {
    /// `mount("/", MS_REC | MS_PRIVATE)`.
    MakePrivate,
    /// The one layer, bound read-only onto `staging`.
    RootBind { layer: CString, staging: CString },
    /// The layers as a read-only overlay onto `staging`; `options` names
    /// them relative to `parent`, the working directory while mounting.
    RootOverlay {
        parent: CString,
        options: CString,
        staging: CString,
    },
    /// See [`Mount::Bind`].
    Bind {
        index: u32,
        source: CString,
        target: CString,
        attrs: u64,
    },
    /// See [`Mount::Tmpfs`].
    Tmpfs {
        index: u32,
        target: CString,
        data: CString,
    },
    /// See [`Mount::Overlay`].
    Overlay {
        index: u32,
        target: CString,
        data: CString,
    },
    /// See [`Mount::Proc`].
    Proc { index: u32, target: CString },
    /// See [`Mount::Dev`].
    Dev {
        index: u32,
        target: CString,
        shm_data: CString,
    },
    /// `pivot_root` onto the new root, then `cwd`.
    Pivot { cwd: CString },
    /// `sethostname`.
    Hostname { name: CString },
    /// `lo` up.
    Loopback,
}

fn c_string(bytes: &[u8], err: Error) -> Result<CString> {
    CString::new(bytes).map_err(|_| err)
}

/// A host path the child resolves: absolute, without a `..` component.
fn host_path(path: &Path) -> bool {
    path.is_absolute() && !path.components().any(|c| c == Component::ParentDir)
}

/// Bytes overlay's option parser would split or unescape.
fn overlay_safe(path: &Path) -> bool {
    !path
        .as_os_str()
        .as_bytes()
        .iter()
        .any(|b| matches!(b, b',' | b':' | b'\\'))
}

fn check_options(options: &str) -> Result<()> {
    let len = options.len() + 1;
    if len > OPTIONS_MAX {
        return Err(Error::MountOptionsTooLong { len });
    }
    Ok(())
}

/// The longest common ancestor of the layers' parent directories.
fn common_parent(layers: &[PathBuf]) -> PathBuf {
    let mut common: Vec<Component<'_>> = layers[0]
        .parent()
        .map(|p| p.components().collect())
        .unwrap_or_default();
    for layer in &layers[1..] {
        let parent: Vec<Component<'_>> = layer
            .parent()
            .map(|p| p.components().collect())
            .unwrap_or_default();
        let same = common
            .iter()
            .zip(&parent)
            .take_while(|(a, b)| a == b)
            .count();
        common.truncate(same);
    }
    common.iter().collect()
}

/// The options of the read-only root overlay and the directory they are
/// relative to: `lowerdir=<top>:...:<bottom>,userxattr`. `userxattr`
/// because an unprivileged layer unpacker can only write `user.*` xattrs
/// (#7); the names are relative so that more layers fit one page.
pub(crate) fn root_overlay_options(layers: &[PathBuf]) -> Result<(PathBuf, String)> {
    let parent = common_parent(layers);
    let mut names = Vec::with_capacity(layers.len());
    for layer in layers.iter().rev() {
        let rel = layer
            .strip_prefix(&parent)
            .map_err(|_| Error::InvalidRoot("a layer is not beneath the layers' common parent"))?;
        let rel = rel
            .to_str()
            .ok_or(Error::InvalidRoot("a layer path is not UTF-8"))?;
        names.push(rel);
    }
    let options = format!("lowerdir={},userxattr", names.join(":"));
    check_options(&options)?;
    Ok((parent, options))
}

fn validate_root(root: &Root) -> Result<()> {
    if root.layers.is_empty() {
        return Err(Error::InvalidRoot("no layers"));
    }
    for layer in &root.layers {
        if !host_path(layer) || layer.parent().is_none() {
            return Err(Error::InvalidRoot(
                "a layer is not an absolute path below / without '..'",
            ));
        }
        if root.layers.len() > 1 && !overlay_safe(layer) {
            return Err(Error::InvalidRoot(
                "a layer path holds ',', ':' or '\\', which overlay options cannot carry",
            ));
        }
    }
    if !host_path(&root.staging) {
        return Err(Error::InvalidRoot(
            "the staging directory is not an absolute path without '..'",
        ));
    }
    if root.cwd.as_str().contains('\0') {
        return Err(Error::InvalidRoot(
            "the working directory contains a NUL byte",
        ));
    }
    for (j, mount) in root.mounts.iter().enumerate() {
        let bad = |reason| Error::InvalidMount { index: j, reason };
        let target = mount.target();
        if target.is_root() {
            return Err(bad("targets /, which the root already is"));
        }
        for earlier in &root.mounts[..j] {
            if earlier.target() == target {
                return Err(bad("has the same target as an earlier mount"));
            }
            if target.is_ancestor_of(earlier.target()) {
                return Err(bad(
                    "mounts an ancestor of an earlier mount's target, which would hide it",
                ));
            }
        }
        match mount {
            Mount::Bind { source, .. } => {
                if !host_path(source) {
                    return Err(bad("the source is not an absolute path without '..'"));
                }
            }
            Mount::Tmpfs {
                size_bytes, mode, ..
            } => {
                if *size_bytes == 0 {
                    return Err(bad("tmpfs size 0 means unlimited; give a size"));
                }
                if *mode > 0o7777 {
                    return Err(bad("tmpfs mode above 0o7777"));
                }
            }
            Mount::Overlay {
                lower, upper, work, ..
            } => {
                for p in [lower, upper, work] {
                    if !host_path(p) || !overlay_safe(p) {
                        return Err(bad(
                            "an overlay directory is not an absolute path without '..', ',', ':' or '\\'",
                        ));
                    }
                }
            }
            Mount::Proc { .. } => {}
            Mount::Dev { shm_size_bytes, .. } => {
                if *shm_size_bytes == 0 {
                    return Err(bad("shm size 0 means unlimited; give a size"));
                }
            }
        }
    }
    Ok(())
}

/// Validates the root and prepares the child's operations: make every
/// mount private, the root, the mounts in order, `pivot_root`, the
/// hostname, `lo`.
pub(crate) fn plan(root: &Root) -> Result<Vec<Op>> {
    validate_root(root)?;
    let path_bytes = |p: &Path| p.as_os_str().as_bytes().to_vec();
    let nul = |what| Error::InvalidRoot(what);
    let staging = c_string(
        &path_bytes(&root.staging),
        nul("the staging path contains NUL"),
    )?;
    let mut ops = vec![Op::MakePrivate];
    if let [layer] = root.layers.as_slice() {
        ops.push(Op::RootBind {
            layer: c_string(&path_bytes(layer), nul("a layer path contains NUL"))?,
            staging,
        });
    } else {
        let (parent, options) = root_overlay_options(&root.layers)?;
        ops.push(Op::RootOverlay {
            parent: c_string(&path_bytes(&parent), nul("a layer path contains NUL"))?,
            options: c_string(options.as_bytes(), nul("a layer path contains NUL"))?,
            staging,
        });
    }
    for (i, mount) in root.mounts.iter().enumerate() {
        let index = u32::try_from(i).map_err(|_| Error::InvalidMount {
            index: i,
            reason: "more than 2^32 mounts",
        })?;
        let mount_nul = |reason| Error::InvalidMount { index: i, reason };
        let target = c_string(
            mount.target().relative().as_bytes(),
            mount_nul("the target contains NUL"),
        )?;
        ops.push(match mount {
            Mount::Bind {
                source, writable, ..
            } => Op::Bind {
                index,
                source: c_string(&path_bytes(source), mount_nul("the source contains NUL"))?,
                target,
                attrs: ffi::MOUNT_ATTR_NOSUID
                    | ffi::MOUNT_ATTR_NODEV
                    | if *writable { 0 } else { ffi::MOUNT_ATTR_RDONLY },
            },
            Mount::Tmpfs {
                size_bytes, mode, ..
            } => Op::Tmpfs {
                index,
                target,
                data: c_string(
                    format!("size={size_bytes},mode={mode:04o}").as_bytes(),
                    mount_nul("tmpfs data"),
                )?,
            },
            Mount::Overlay {
                lower, upper, work, ..
            } => {
                let data = format!(
                    "lowerdir={},upperdir={},workdir={},userxattr",
                    lower.display(),
                    upper.display(),
                    work.display()
                );
                check_options(&data)?;
                Op::Overlay {
                    index,
                    target,
                    data: c_string(data.as_bytes(), mount_nul("an overlay path contains NUL"))?,
                }
            }
            Mount::Proc { .. } => Op::Proc { index, target },
            Mount::Dev { shm_size_bytes, .. } => Op::Dev {
                index,
                target,
                shm_data: c_string(
                    format!("size={shm_size_bytes},mode=1777").as_bytes(),
                    mount_nul("shm data"),
                )?,
            },
        });
    }
    ops.push(Op::Pivot {
        cwd: c_string(root.cwd.as_str().as_bytes(), nul("the cwd contains NUL"))?,
    });
    ops.push(Op::Hostname {
        name: c_string(
            root.hostname.as_str().as_bytes(),
            nul("the hostname contains NUL"),
        )?,
    });
    ops.push(Op::Loopback);
    Ok(ops)
}

// ---------------------------------------------------------------------------
// The child side. Everything below runs in the cloned child: raw syscalls
// on memory prepared before the clone, no allocation, no lock (ADR-007, D4).

/// The length of a `/proc/self/fd/<n>` buffer: 14 bytes of prefix, at most
/// 10 digits, the NUL, rounded up.
pub(crate) const FD_PATH_LEN: usize = 32;

/// Writes `/proc/self/fd/<fd>` with its NUL into `buf` and returns the
/// bytes up to and including the NUL. Negative descriptors never reach
/// here; they render as 0.
pub(crate) fn fd_path(fd: c_int, buf: &mut [u8; FD_PATH_LEN]) -> &[u8] {
    const PREFIX: &[u8] = b"/proc/self/fd/";
    buf[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut digits = [0u8; 10];
    let mut n = fd.max(0) as u32;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (n % 10) as u8;
        count += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let mut at = PREFIX.len();
    for i in (0..count).rev() {
        buf[at] = digits[i];
        at += 1;
    }
    buf[at] = 0;
    &buf[..=at]
}

/// A descriptor the child owns; closed on drop (no allocation).
struct Fd(c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: the descriptor was opened by this child and is closed once.
        unsafe { libc::close(self.0) };
    }
}

fn openat2(dirfd: c_int, path: &CStr, flags: c_int, resolve: u64) -> std::result::Result<Fd, i32> {
    let how = ffi::OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve,
    };
    // SAFETY: path is NUL-terminated and how is a valid open_how of the
    // size passed, both for the call's duration.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const ffi::OpenHow,
            std::mem::size_of::<ffi::OpenHow>(),
        )
    };
    if fd < 0 {
        Err(errno())
    } else {
        Ok(Fd(fd as c_int))
    }
}

/// A host path as an `O_PATH` descriptor, without following any symlink,
/// so a swapped component cannot redirect it.
fn open_host(path: &CStr) -> std::result::Result<Fd, i32> {
    openat2(
        libc::AT_FDCWD,
        path,
        libc::O_PATH,
        libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )
}

/// A path beneath `root`, resolved as if `root` were `/` and without
/// following any symlink, also in the last component (the CVE-2021-30465
/// class: a target swapped for a symlink). `O_NOFOLLOW` is left out on
/// purpose: with it, openat2 returns a descriptor of a trailing symlink
/// itself instead of failing (measured, ADR-007 D7).
fn open_beneath(root: c_int, rel: &CStr) -> std::result::Result<Fd, i32> {
    openat2(
        root,
        rel,
        libc::O_PATH,
        libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    )
}

fn is_dir(fd: &Fd) -> std::result::Result<bool, i32> {
    // SAFETY: an all-zero stat is valid storage for fstat to fill.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: st is valid storage; fstat accepts O_PATH descriptors.
    if unsafe { libc::fstat(fd.0, &mut st) } < 0 {
        return Err(errno());
    }
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// A detached, non-recursive copy of the mount at `source`.
fn clone_tree(source: &Fd) -> std::result::Result<Fd, i32> {
    // SAFETY: the empty path is NUL-terminated; AT_EMPTY_PATH makes the call
    // act on the descriptor itself.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            source.0,
            c"".as_ptr(),
            ffi::OPEN_TREE_CLONE | ffi::OPEN_TREE_CLOEXEC | libc::AT_EMPTY_PATH as u32,
        )
    };
    if fd < 0 {
        Err(errno())
    } else {
        Ok(Fd(fd as c_int))
    }
}

/// Adds mount flags (never clears one, so flags the kernel locked stay).
fn add_attrs(mount: &Fd, attrs: u64) -> std::result::Result<(), i32> {
    let attr = ffi::MountAttr {
        attr_set: attrs,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: attr is a valid mount_attr of the size passed; the empty
    // path with AT_EMPTY_PATH names the descriptor's mount.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            mount.0,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH as u32,
            &attr as *const ffi::MountAttr,
            ffi::MOUNT_ATTR_SIZE_VER0,
        )
    };
    if rc < 0 { Err(errno()) } else { Ok(()) }
}

/// Attaches a detached tree onto the target descriptor.
fn move_tree(tree: &Fd, target: &Fd) -> std::result::Result<(), i32> {
    // SAFETY: both paths are empty NUL-terminated strings, so the call acts
    // on the two descriptors.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            tree.0,
            c"".as_ptr(),
            target.0,
            c"".as_ptr(),
            ffi::MOVE_MOUNT_F_EMPTY_PATH | ffi::MOVE_MOUNT_T_EMPTY_PATH,
        )
    };
    if rc < 0 { Err(errno()) } else { Ok(()) }
}

/// Binds `source` onto `target` with `attrs` added.
fn bind(source: &Fd, target: &Fd, attrs: u64) -> std::result::Result<(), i32> {
    let tree = clone_tree(source)?;
    add_attrs(&tree, attrs)?;
    move_tree(&tree, target)
}

/// A new filesystem mounted onto the target descriptor through its
/// `/proc/self/fd` path.
fn mount_on(
    target: &Fd,
    source: &CStr,
    fstype: &CStr,
    flags: libc::c_ulong,
    data: Option<&CStr>,
) -> std::result::Result<(), i32> {
    let mut buf = [0u8; FD_PATH_LEN];
    let path = fd_path(target.0, &mut buf);
    let data = data.map_or(std::ptr::null(), |d| d.as_ptr().cast::<libc::c_void>());
    // SAFETY: every string is NUL-terminated (path by fd_path) and lives for
    // the call's duration; data is null or a NUL-terminated string.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            path.as_ptr().cast::<c_char>(),
            fstype.as_ptr(),
            flags,
            data,
        )
    };
    if rc < 0 { Err(errno()) } else { Ok(()) }
}

fn step<T>(r: std::result::Result<T, i32>, step: Step, index: u32) -> Result2<T> {
    r.map_err(|e| fail(step, index, e))
}

type Result2<T> = std::result::Result<T, Failure>;

const ROOT_ATTRS: u64 = ffi::MOUNT_ATTR_RDONLY | ffi::MOUNT_ATTR_NOSUID | ffi::MOUNT_ATTR_NODEV;

/// Opens a mount target beneath the new root.
fn target(root: &Fd, rel: &CStr, index: u32, fault: Fault) -> Result2<Fd> {
    inject(fault, Step::MountTarget)?;
    step(open_beneath(root.0, rel), Step::MountTarget, index)
}

fn dev(root: &Fd, index: u32, rel: &CStr, shm_data: &CStr, fault: Fault) -> Result2<()> {
    let at = target(root, rel, index, fault)?;
    inject(fault, Step::Dev)?;
    step(
        mount_on(
            &at,
            c"tmpfs",
            c"tmpfs",
            libc::MS_NOSUID | libc::MS_NOEXEC,
            Some(DEV_TMPFS_DATA),
        ),
        Step::Dev,
        index,
    )?;
    // The target again: now the root of the new tmpfs.
    let dir = step(open_beneath(root.0, rel), Step::Dev, index)?;
    for (name, host) in DEVICES {
        // SAFETY: name is NUL-terminated; the descriptor is closed at once.
        let fd = unsafe {
            libc::openat(
                dir.0,
                name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o666 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(fail(Step::Dev, index, errno()));
        }
        drop(Fd(fd));
        let source = step(open_host(host), Step::Dev, index)?;
        let node = step(
            openat2(
                dir.0,
                name,
                libc::O_PATH,
                libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS,
            ),
            Step::Dev,
            index,
        )?;
        // Device nodes need dev; nothing in /dev executes.
        step(
            bind(
                &source,
                &node,
                ffi::MOUNT_ATTR_NOSUID | ffi::MOUNT_ATTR_NOEXEC,
            ),
            Step::Dev,
            index,
        )?;
    }
    for (name, mode) in [(c"pts", 0o755), (c"shm", 0o1777)] {
        // SAFETY: name is NUL-terminated; dir is an open directory.
        if unsafe { libc::mkdirat(dir.0, name.as_ptr(), mode) } < 0 {
            return Err(fail(Step::Dev, index, errno()));
        }
    }
    let pts = step(
        openat2(
            dir.0,
            c"pts",
            libc::O_PATH,
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS,
        ),
        Step::Dev,
        index,
    )?;
    step(
        mount_on(
            &pts,
            c"devpts",
            c"devpts",
            libc::MS_NOSUID | libc::MS_NOEXEC,
            Some(c"newinstance,ptmxmode=0666,mode=0620"),
        ),
        Step::Dev,
        index,
    )?;
    let shm = step(
        openat2(
            dir.0,
            c"shm",
            libc::O_PATH,
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS,
        ),
        Step::Dev,
        index,
    )?;
    step(
        mount_on(
            &shm,
            c"tmpfs",
            c"tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            Some(shm_data),
        ),
        Step::Dev,
        index,
    )?;
    for (name, to) in DEV_LINKS {
        // SAFETY: both strings are NUL-terminated; dir is an open directory.
        if unsafe { libc::symlinkat(to.as_ptr(), dir.0, name.as_ptr()) } < 0 {
            return Err(fail(Step::Dev, index, errno()));
        }
    }
    // Filled: read-only from here on (the mounts on it stay writable).
    step(add_attrs(&dir, ffi::MOUNT_ATTR_RDONLY), Step::Dev, index)
}

fn pivot(root: &Fd, cwd: &CStr, fault: Fault) -> Result2<()> {
    inject(fault, Step::Pivot)?;
    let check = |rc: c_int, item: u32| {
        if rc < 0 {
            Err(fail(Step::Pivot, item, errno()))
        } else {
            Ok(())
        }
    };
    // SAFETY: fchdir takes a descriptor; O_PATH directories are accepted.
    check(unsafe { libc::fchdir(root.0) }, 0)?;
    // pivot_root(".", ".") stacks the old root on the new one; detaching
    // "." then removes the old root and every host mount under it.
    // SAFETY: both paths are NUL-terminated.
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) };
    check(rc as c_int, 1)?;
    // SAFETY: the path is NUL-terminated.
    check(unsafe { libc::umount2(c".".as_ptr(), libc::MNT_DETACH) }, 2)?;
    // SAFETY: the path is NUL-terminated.
    check(unsafe { libc::chdir(c"/".as_ptr()) }, 3)?;
    // SAFETY: cwd is NUL-terminated and prepared before the clone.
    check(unsafe { libc::chdir(cwd.as_ptr()) }, 4)
}

fn loopback(fault: Fault) -> Result2<()> {
    inject(fault, Step::Loopback)?;
    // SAFETY: socket takes plain integers.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(fail(Step::Loopback, 0, errno()));
    }
    let sock = Fd(fd);
    // SAFETY: an all-zero ifreq is valid storage for the ioctls below.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name[0] = b'l' as c_char;
    ifr.ifr_name[1] = b'o' as c_char;
    // SAFETY: ifr is a valid ifreq naming "lo" for the call's duration.
    if unsafe { libc::ioctl(sock.0, libc::SIOCGIFFLAGS as _, &mut ifr) } < 0 {
        return Err(fail(Step::Loopback, 1, errno()));
    }
    // SAFETY: SIOCGIFFLAGS filled the flags member of the union.
    let flags = unsafe { ifr.ifr_ifru.ifru_flags };
    ifr.ifr_ifru.ifru_flags = flags | libc::IFF_UP as libc::c_short;
    // SAFETY: as above; SIOCSIFFLAGS reads the flags member.
    if unsafe { libc::ioctl(sock.0, libc::SIOCSIFFLAGS as _, &mut ifr) } < 0 {
        return Err(fail(Step::Loopback, 2, errno()));
    }
    Ok(())
}

/// Runs the operations in order. Runs in the cloned child.
pub(crate) fn run(ops: &[Op], fault: Fault) -> Result2<()> {
    let mut root: Option<Fd> = None;
    for op in ops {
        match op {
            Op::MakePrivate => {
                inject(fault, Step::MakePrivate)?;
                // SAFETY: the strings are NUL-terminated; no data is passed.
                let rc = unsafe {
                    libc::mount(
                        c"none".as_ptr(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        libc::MS_REC | libc::MS_PRIVATE,
                        std::ptr::null(),
                    )
                };
                if rc < 0 {
                    return Err(fail(Step::MakePrivate, 0, errno()));
                }
            }
            Op::RootBind { layer, staging } => {
                inject(fault, Step::Root)?;
                let at = step(open_host(staging), Step::Root, 0)?;
                let layer = step(open_host(layer), Step::Root, 0)?;
                step(bind(&layer, &at, ROOT_ATTRS), Step::Root, 0)?;
                root = Some(step(open_host(staging), Step::Root, 0)?);
            }
            Op::RootOverlay {
                parent,
                options,
                staging,
            } => {
                inject(fault, Step::Root)?;
                let dir = step(open_host(parent), Step::Root, 0)?;
                // Overlay resolves the relative layer names from here.
                // SAFETY: fchdir takes a descriptor.
                if unsafe { libc::fchdir(dir.0) } < 0 {
                    return Err(fail(Step::Root, 0, errno()));
                }
                let at = step(open_host(staging), Step::Root, 0)?;
                step(
                    mount_on(
                        &at,
                        c"overlay",
                        c"overlay",
                        libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
                        Some(options),
                    ),
                    Step::Root,
                    0,
                )?;
                root = Some(step(open_host(staging), Step::Root, 0)?);
            }
            op => {
                let Some(new_root) = root.as_ref() else {
                    // plan() always puts the root first.
                    return Err(fail(Step::Root, 0, libc::EINVAL));
                };
                match op {
                    Op::Bind {
                        index,
                        source,
                        target: rel,
                        attrs,
                    } => {
                        let at = target(new_root, rel, *index, fault)?;
                        inject(fault, Step::Bind)?;
                        let source = step(open_host(source), Step::Bind, *index)?;
                        match (
                            step(is_dir(&source), Step::Bind, *index)?,
                            step(is_dir(&at), Step::Bind, *index)?,
                        ) {
                            (true, false) => return Err(fail(Step::Bind, *index, libc::ENOTDIR)),
                            (false, true) => return Err(fail(Step::Bind, *index, libc::EISDIR)),
                            _ => {}
                        }
                        step(bind(&source, &at, *attrs), Step::Bind, *index)?;
                    }
                    Op::Tmpfs {
                        index,
                        target: rel,
                        data,
                    } => {
                        let at = target(new_root, rel, *index, fault)?;
                        inject(fault, Step::Tmpfs)?;
                        step(
                            mount_on(
                                &at,
                                c"tmpfs",
                                c"tmpfs",
                                libc::MS_NOSUID | libc::MS_NODEV,
                                Some(data),
                            ),
                            Step::Tmpfs,
                            *index,
                        )?;
                    }
                    Op::Overlay {
                        index,
                        target: rel,
                        data,
                    } => {
                        let at = target(new_root, rel, *index, fault)?;
                        inject(fault, Step::Overlay)?;
                        step(
                            mount_on(
                                &at,
                                c"overlay",
                                c"overlay",
                                libc::MS_NOSUID | libc::MS_NODEV,
                                Some(data),
                            ),
                            Step::Overlay,
                            *index,
                        )?;
                    }
                    Op::Proc { index, target: rel } => {
                        // Before pivot_root: a new procfs needs a fully
                        // visible one in the mount namespace.
                        let at = target(new_root, rel, *index, fault)?;
                        inject(fault, Step::Proc)?;
                        step(
                            mount_on(
                                &at,
                                c"proc",
                                c"proc",
                                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                                None,
                            ),
                            Step::Proc,
                            *index,
                        )?;
                    }
                    Op::Dev {
                        index,
                        target: rel,
                        shm_data,
                    } => dev(new_root, *index, rel, shm_data, fault)?,
                    Op::Pivot { cwd } => pivot(new_root, cwd, fault)?,
                    Op::Hostname { name } => {
                        inject(fault, Step::Hostname)?;
                        let bytes = name.to_bytes();
                        // SAFETY: bytes is valid for its length.
                        let rc = unsafe {
                            libc::syscall(libc::SYS_sethostname, bytes.as_ptr(), bytes.len())
                        };
                        if rc < 0 {
                            return Err(fail(Step::Hostname, 0, errno()));
                        }
                    }
                    Op::Loopback => loopback(fault)?,
                    Op::MakePrivate | Op::RootBind { .. } | Op::RootOverlay { .. } => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> InsidePath {
        InsidePath::new(s).expect("valid inside path")
    }

    fn root_with(layers: &[&str], mounts: Vec<Mount>) -> Root {
        Root {
            layers: layers.iter().map(PathBuf::from).collect(),
            staging: PathBuf::from("/s/staging"),
            mounts,
            hostname: Hostname::new("sandbox").expect("valid hostname"),
            cwd: InsidePath::root(),
        }
    }

    fn proc_at(t: &str) -> Mount {
        Mount::Proc { target: p(t) }
    }

    #[test]
    fn inside_path_forms() {
        for ok in [
            "/a",
            "/a/b",
            "/workspace",
            "/run/boneli/egress.sock",
            "/a..b/.c",
        ] {
            assert_eq!(p(ok).as_str(), ok);
        }
        for bad in [
            "workspace",
            "/a/../b",
            "/a/./b",
            "/a//b",
            "/a/",
            "/",
            "/a\0b",
            "",
            "/..",
            "/.",
        ] {
            assert!(
                matches!(InsidePath::new(bad), Err(Error::InvalidInsidePath { .. })),
                "{bad:?}"
            );
        }
        assert_eq!(InsidePath::root().as_str(), "/");
    }

    #[test]
    fn mount_order_rules() {
        let ok = root_with(&["/l/a"], vec![proc_at("/a"), proc_at("/a/b")]);
        assert!(plan(&ok).is_ok());
        let hidden = root_with(&["/l/a"], vec![proc_at("/a/b"), proc_at("/a")]);
        assert!(matches!(
            plan(&hidden),
            Err(Error::InvalidMount { index: 1, .. })
        ));
        let dup = root_with(&["/l/a"], vec![proc_at("/a"), proc_at("/b"), proc_at("/a")]);
        assert!(matches!(
            plan(&dup),
            Err(Error::InvalidMount { index: 2, .. })
        ));
        // A sibling with a common prefix is not an ancestor.
        let sibling = root_with(&["/l/a"], vec![proc_at("/ab/c"), proc_at("/a")]);
        assert!(plan(&sibling).is_ok());
        let root_target = root_with(
            &["/l/a"],
            vec![Mount::Proc {
                target: InsidePath::root(),
            }],
        );
        assert!(matches!(
            plan(&root_target),
            Err(Error::InvalidMount { index: 0, .. })
        ));
    }

    #[test]
    fn hostname_forms() {
        assert!(Hostname::new("").is_err());
        assert!(Hostname::new(&"a".repeat(64)).is_ok());
        assert!(Hostname::new(&"a".repeat(65)).is_err());
        assert!(Hostname::new("boneli-sandbox.local").is_ok());
        for bad in ["\u{430}pi", "a\u{200b}b", "a b", "a\u{a0}b", "a_b", "a\0b"] {
            assert!(
                matches!(Hostname::new(bad), Err(Error::InvalidHostname(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn zero_sizes_rejected() {
        let tmpfs = |size_bytes, mode| Mount::Tmpfs {
            target: p("/tmp"),
            size_bytes,
            mode,
        };
        assert!(plan(&root_with(&["/l/a"], vec![tmpfs(1, 0o1777)])).is_ok());
        assert!(matches!(
            plan(&root_with(&["/l/a"], vec![tmpfs(0, 0o1777)])),
            Err(Error::InvalidMount { index: 0, .. })
        ));
        assert!(matches!(
            plan(&root_with(&["/l/a"], vec![tmpfs(1, 0o10000)])),
            Err(Error::InvalidMount { index: 0, .. })
        ));
        let dev = |shm_size_bytes| Mount::Dev {
            target: p("/dev"),
            shm_size_bytes,
        };
        assert!(plan(&root_with(&["/l/a"], vec![dev(1)])).is_ok());
        assert!(matches!(
            plan(&root_with(&["/l/a"], vec![dev(0)])),
            Err(Error::InvalidMount { index: 0, .. })
        ));
    }

    #[test]
    fn host_paths_rejected() {
        for layers in [&[][..], &["l/a"][..], &["/"][..], &["/l/../a"][..]] {
            assert!(
                matches!(plan(&root_with(layers, vec![])), Err(Error::InvalidRoot(_))),
                "{layers:?}"
            );
        }
        // Overlay option syntax, only where the layers become options.
        assert!(plan(&root_with(&["/l/a,b"], vec![])).is_ok());
        for bad in ["/l/a,b", "/l/a:b", "/l/a\\b"] {
            assert!(
                matches!(
                    plan(&root_with(&["/l/x", bad], vec![])),
                    Err(Error::InvalidRoot(_))
                ),
                "{bad}"
            );
        }
        let bind = Mount::Bind {
            source: PathBuf::from("rel"),
            target: p("/a"),
            writable: false,
        };
        assert!(matches!(
            plan(&root_with(&["/l/a"], vec![bind])),
            Err(Error::InvalidMount { index: 0, .. })
        ));
        let overlay = Mount::Overlay {
            lower: PathBuf::from("/o/l"),
            upper: PathBuf::from("/o/u:x"),
            work: PathBuf::from("/o/w"),
            target: p("/a"),
        };
        assert!(matches!(
            plan(&root_with(&["/l/a"], vec![overlay])),
            Err(Error::InvalidMount { index: 0, .. })
        ));
    }

    #[test]
    fn overlay_option_page_limit() {
        // "lowerdir=" (9) + names joined by ':' + ",userxattr" (10) + NUL.
        let layers_for = |total: usize| -> Vec<PathBuf> {
            let mut names = vec!["b".to_string()];
            let mut len = 9 + 1 + 10;
            while len < total {
                let take = (total - len - 1).min(200);
                names.push("x".repeat(take.max(1)));
                len += take.max(1) + 1;
            }
            assert_eq!(len, total, "test layout");
            names
                .iter()
                .map(|n| PathBuf::from("/layers").join(n))
                .collect()
        };
        let fits = layers_for(4095);
        let (parent, options) = root_overlay_options(&fits).expect("4095 bytes fit");
        assert_eq!(parent, PathBuf::from("/layers"));
        assert_eq!(options.len(), 4095);
        assert!(options.ends_with(":b,userxattr"), "bottom layer last");
        let mut long = fits.clone();
        let last = long.len() - 1;
        long[last] = PathBuf::from(format!("{}x", long[last].display()));
        assert!(matches!(
            root_overlay_options(&long),
            Err(Error::MountOptionsTooLong { len: 4097 })
        ));
        assert!(matches!(
            plan(&root_with(
                &long
                    .iter()
                    .map(|p| p.to_str().expect("utf-8"))
                    .collect::<Vec<_>>(),
                vec![]
            )),
            Err(Error::MountOptionsTooLong { .. })
        ));
        // Layers in different directories are named from their common
        // parent, top first.
        let (parent, options) = root_overlay_options(&[
            PathBuf::from("/v/img/a/base"),
            PathBuf::from("/v/img/b/top"),
        ])
        .expect("short");
        assert_eq!(parent, PathBuf::from("/v/img"));
        assert_eq!(options, "lowerdir=b/top:a/base,userxattr");
    }

    #[test]
    fn mount_step_order() {
        let root = root_with(
            &["/l/a", "/l/b"],
            vec![
                Mount::Bind {
                    source: PathBuf::from("/usr"),
                    target: p("/usr"),
                    writable: false,
                },
                proc_at("/proc"),
                Mount::Dev {
                    target: p("/dev"),
                    shm_size_bytes: 1 << 20,
                },
            ],
        );
        let ops = plan(&root).expect("plan");
        assert_eq!(ops[0], Op::MakePrivate, "every mount private first");
        assert!(matches!(ops[1], Op::RootOverlay { .. }), "then the root");
        let pivot = ops
            .iter()
            .position(|o| matches!(o, Op::Pivot { .. }))
            .expect("a pivot");
        let proc = ops
            .iter()
            .position(|o| matches!(o, Op::Proc { .. }))
            .expect("a proc");
        assert!(proc < pivot, "proc before pivot_root");
        assert!(
            ops[2..pivot]
                .iter()
                .all(|o| matches!(o, Op::Bind { .. } | Op::Proc { .. } | Op::Dev { .. })),
            "only the spec's mounts between the root and the pivot"
        );
        assert!(matches!(ops[pivot + 1], Op::Hostname { .. }));
        assert_eq!(ops[pivot + 2], Op::Loopback);
        assert_eq!(ops.len(), pivot + 3);
        match &ops[2] {
            Op::Bind { attrs, target, .. } => {
                assert_eq!(target.as_bytes(), b"usr", "relative to the new root");
                assert_eq!(
                    *attrs,
                    ffi::MOUNT_ATTR_RDONLY | ffi::MOUNT_ATTR_NOSUID | ffi::MOUNT_ATTR_NODEV
                );
            }
            other => panic!("{other:?}"),
        }
        let single = plan(&root_with(&["/l/a"], vec![])).expect("plan");
        assert!(
            matches!(single[1], Op::RootBind { .. }),
            "one layer is a bind"
        );
    }

    #[test]
    fn fd_path_formatting() {
        for n in [0, 9, 10, 255, 1000, i32::MAX] {
            let mut buf = [0u8; FD_PATH_LEN];
            assert_eq!(
                fd_path(n, &mut buf),
                format!("/proc/self/fd/{n}\0").as_bytes(),
                "{n}"
            );
        }
    }

    #[test]
    fn dev_entries_match_the_steps() {
        let mut names: Vec<&str> = DEVICES
            .iter()
            .chain(DEV_LINKS.iter())
            .map(|(n, _)| n.to_str().expect("ascii"))
            .collect();
        names.extend(["pts", "shm"]);
        names.sort_unstable();
        assert_eq!(names, DEV_ENTRIES);
    }
}
