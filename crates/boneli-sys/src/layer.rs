//! Overlay layer primitives for the OCI unpacker (#7, ADR-009): what an
//! unprivileged process needs to write a layer in the format overlayfs
//! reads with `userxattr` (ADR-007, D7), and that std cannot do without
//! `libc`.
//!
//! Every call is path based and never follows a final symlink: `mknod`
//! fails with `EEXIST` on any existing entry, symlinks included, and the
//! `l*xattr` calls act on the link itself.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::error::{Error, Result};

/// The name overlayfs reads, with `userxattr`, to make a directory opaque.
const OPAQUE: &std::ffi::CStr = c"user.overlay.opaque";

/// The kernel's largest xattr value (`XATTR_SIZE_MAX`).
const XATTR_SIZE_MAX: usize = 65_536;

fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Nul("layer path"))
}

/// Creates the overlay whiteout `path`: a character device with device
/// number 0:0, which hides the entry of the same name in lower layers.
/// Unprivileged users may create it since Linux 5.8 (ADR-007, D7,
/// measured). Fails with `EEXIST` if anything is at `path`.
pub fn make_whiteout(path: &Path) -> Result<()> {
    mknod(path, libc::S_IFCHR, 0)
}

/// Creates a FIFO at `path` with the permission bits `mode & 0o777`; the
/// process umask applies, as for every `mknod`. Fails with `EEXIST` if
/// anything is at `path`.
pub fn make_fifo(path: &Path, mode: u32) -> Result<()> {
    mknod(path, libc::S_IFIFO | (mode & 0o777), 0)
}

fn mknod(path: &Path, mode: libc::mode_t, dev: libc::dev_t) -> Result<()> {
    let c = c_path(path)?;
    // SAFETY: c is a NUL-terminated path that lives for the call; mknod
    // reads it and creates the node without following a final symlink.
    let rc = unsafe { libc::mknod(c.as_ptr(), mode, dev) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::last("mknod"))
    }
}

/// Marks the directory `dir` opaque for overlayfs with `userxattr`:
/// `user.overlay.opaque=y`, so no entry of lower layers shows through it.
/// On a symlink the call acts on the link, which the kernel refuses for
/// `user.*` names, so the target is never marked.
pub fn mark_opaque(dir: &Path) -> Result<()> {
    let c = c_path(dir)?;
    let value = b"y";
    // SAFETY: c and OPAQUE are NUL-terminated and value is valid for
    // value.len() bytes for the call's duration; lsetxattr does not follow
    // a final symlink.
    let rc = unsafe {
        libc::lsetxattr(
            c.as_ptr(),
            OPAQUE.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::last("lsetxattr"))
    }
}

/// Reads the xattr `name` of `path` itself (not of a symlink's target):
/// `None` when it is absent (`ENODATA`). Only `user.` names are read; any
/// other name is refused before the call as `Sys { call: "lgetxattr",
/// errno: EINVAL }`, so this cannot be used to probe `trusted.` or
/// `security.` attributes. A value is at most 65,536 bytes, the kernel's
/// `XATTR_SIZE_MAX`.
pub fn user_xattr(path: &Path, name: &str) -> Result<Option<Vec<u8>>> {
    if !name.starts_with("user.") || name.len() == "user.".len() {
        return Err(Error::Sys {
            call: "lgetxattr",
            errno: libc::EINVAL,
        });
    }
    let c = c_path(path)?;
    let c_name = CString::new(name).map_err(|_| Error::Nul("xattr name"))?;
    let mut buf = vec![0u8; XATTR_SIZE_MAX];
    // SAFETY: c and c_name are NUL-terminated, and buf is valid for
    // buf.len() writable bytes for the call's duration; lgetxattr does not
    // follow a final symlink and writes at most buf.len() bytes.
    let n = unsafe {
        libc::lgetxattr(
            c.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    match usize::try_from(n) {
        Ok(len) => {
            buf.truncate(len);
            Ok(Some(buf))
        }
        Err(_) => {
            let e = Error::last("lgetxattr");
            match e {
                Error::Sys { errno, .. } if errno == libc::ENODATA => Ok(None),
                e => Err(e),
            }
        }
    }
}
