//! Reading a tree that a sandbox wrote, from the runner (ADR-042, D5).
//!
//! The runner holds the git token and reads the workspace a workload has
//! written, so no call here follows anything the workload planted:
//! [`open_beneath`] resolves through `openat2` with `RESOLVE_BENEATH`,
//! `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS` and `RESOLVE_NO_XDEV`
//! always set, and with `O_NOFOLLOW`, so a path cannot leave the directory
//! it starts from, pass a symlink, a magic link of `/proc` or a mount
//! point, or end on a symlink; [`read_link`] reads a symlink that was
//! opened as itself, without resolving it; [`read_dir`] lists a directory
//! up to a cap. What the entries are is the caller's `fstat`, on the
//! descriptor it opened, never on a name.

use std::ffi::CString;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::raw::c_int;

use crate::error::{Error, Result, errno};
use crate::ffi;

/// What [`open_beneath`] opens the final component as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Open {
    /// `O_PATH`: whatever it is, a symlink, a FIFO, a socket or a device
    /// included, without opening it; for `fstat`, [`read_link`] and as the
    /// base of further calls. Opening a FIFO or a device this way never
    /// blocks and never reaches a driver.
    Path,
    /// `O_RDONLY | O_NONBLOCK`: for reading a regular file. A FIFO opened
    /// so does not wait for a writer; a directory opens too, so the caller
    /// checks with `fstat` what it got.
    Read,
    /// `O_RDONLY | O_DIRECTORY`: for [`read_dir`] and as a base; anything
    /// but a directory fails with ENOTDIR.
    Directory,
}

impl Open {
    /// `openat2` refuses `O_PATH` with any flag but `O_DIRECTORY`,
    /// `O_NOFOLLOW` and `O_CLOEXEC` (EINVAL), so `O_NOCTTY` comes only with
    /// the modes that open the file.
    fn flags(self) -> c_int {
        let base = libc::O_NOFOLLOW | libc::O_CLOEXEC;
        base | match self {
            Open::Path => libc::O_PATH,
            Open::Read => libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
            Open::Directory => {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_NOCTTY
            }
        }
    }
}

/// The resolve flags of every [`open_beneath`]: never above `dir`, through
/// no symlink and no magic link, across no mount point.
const RESOLVE: u64 = libc::RESOLVE_BENEATH
    | libc::RESOLVE_NO_SYMLINKS
    | libc::RESOLVE_NO_MAGICLINKS
    | libc::RESOLVE_NO_XDEV;

/// Why [`open_beneath`] refuses a path before any call.
fn path_problem(path: &[u8]) -> Option<&'static str> {
    if path.is_empty() {
        return Some("is empty");
    }
    if path.first() == Some(&b'/') {
        return Some("is absolute");
    }
    if path.contains(&0) {
        return Some("contains NUL");
    }
    if path
        .split(|b| *b == b'/')
        .any(|c| c.is_empty() || c == b"." || c == b"..")
    {
        return Some("has an empty, `.` or `..` component");
    }
    None
}

/// Opens `path`, relative to the directory `dir`, as `open` says, with
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
/// RESOLVE_NO_XDEV` and `O_NOFOLLOW | O_CLOEXEC` (ADR-042, D5).
///
/// The path is relative, without NUL and without an empty, `.` or `..`
/// component, else [`Error::InvalidBeneathPath`] before any call; so a
/// lookup never walks `..`, the one step for which the kernel answers
/// EAGAIN when a rename or a mount anywhere on the host races it. The
/// kernel's answers come back as [`Error::Sys`] with the call
/// `openat2(beneath)` and its errno: ELOOP for a symlink at any component
/// (with [`Open::Path`], a symlink at the final one is opened as itself;
/// with [`Open::Directory`], it is ENOTDIR there),
/// EXDEV for a mount point at any component, ENOENT, ENOTDIR, EACCES.
pub fn open_beneath(dir: BorrowedFd<'_>, path: &[u8], open: Open) -> Result<OwnedFd> {
    if let Some(reason) = path_problem(path) {
        return Err(Error::InvalidBeneathPath(reason));
    }
    let path = CString::new(path).map_err(|_| Error::InvalidBeneathPath("contains NUL"))?;
    let how = ffi::OpenHow {
        flags: open.flags() as u64,
        mode: 0,
        resolve: RESOLVE,
    };
    loop {
        // SAFETY: path is NUL-terminated and how is a valid open_how of the
        // size passed, both for the call's duration; dir is open.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir.as_raw_fd(),
                path.as_ptr(),
                &how as *const ffi::OpenHow,
                std::mem::size_of::<ffi::OpenHow>(),
            )
        };
        if fd >= 0 {
            // SAFETY: openat2 returned a new descriptor that nothing else
            // owns.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) });
        }
        if errno() != libc::EINTR {
            return Err(Error::last("openat2(beneath)"));
        }
    }
}

/// What a failed call of this module met, for callers that tell the
/// cases apart without an edge into `libc` of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Met {
    /// ENOENT: nothing at a component.
    Nothing,
    /// ENOTDIR: a component that must be a directory is not one.
    NotADirectory,
    /// ELOOP: a symlink at a component.
    Symlink,
    /// EXDEV: a mount point at a component.
    MountPoint,
    /// EACCES: the mode forbids it.
    Denied,
    /// Anything else, the cap of [`read_dir`] included.
    Other,
}

impl Met {
    /// What `e` met.
    pub fn of(e: &Error) -> Met {
        match e {
            Error::Sys { errno, .. } => match *errno {
                libc::ENOENT => Met::Nothing,
                libc::ENOTDIR => Met::NotADirectory,
                libc::ELOOP => Met::Symlink,
                libc::EXDEV => Met::MountPoint,
                libc::EACCES => Met::Denied,
                _ => Met::Other,
            },
            _ => Met::Other,
        }
    }
}

/// The longest symlink target the kernel stores: `PATH_MAX` (4,096) bytes
/// with the NUL, so 4,095 without.
pub const LINK_MAX: usize = 4095;

/// The target of the symlink `link`, opened as itself ([`Open::Path`]),
/// as raw bytes: `readlinkat(link, "")`, which resolves nothing. Anything
/// but a symlink fails with ENOENT (the kernel's answer), as
/// [`Error::Sys`] with the call `readlinkat`.
pub fn read_link(link: BorrowedFd<'_>) -> Result<Vec<u8>> {
    // One byte more than any target, so a full buffer means a target the
    // kernel cannot hold, which fails instead of being cut.
    let mut buf = vec![0u8; LINK_MAX + 1];
    // SAFETY: the empty name is NUL-terminated; buf is valid writable
    // memory of the length passed; link is open.
    let n = unsafe {
        libc::readlinkat(
            link.as_raw_fd(),
            c"".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return Err(Error::last("readlinkat"));
    }
    let n = n as usize;
    if n > LINK_MAX {
        return Err(Error::Sys {
            call: "readlinkat",
            errno: libc::ENAMETOOLONG,
        });
    }
    buf.truncate(n);
    Ok(buf)
}

/// Bytes read per `getdents64`: room for at least 128 entries of the
/// longest name (255 bytes, 280 bytes a record), so a directory costs one
/// call per 128 entries at worst.
const DENTS_BUF: usize = 36 << 10;

/// The names in the directory `dir` (opened with [`Open::Directory`]), in
/// the order the file system lists them, without `.` and `..`, read with
/// `getdents64` from the start: at most `max`, else [`Error::TooManyEntries`]
/// once one more is seen, before any further read. A name never holds `/`
/// or NUL.
pub fn read_dir(dir: BorrowedFd<'_>, max: usize) -> Result<Vec<Vec<u8>>> {
    // SAFETY: lseek takes plain integers; dir is open.
    if unsafe { libc::lseek(dir.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(Error::last("lseek(directory)"));
    }
    let mut names = Vec::new();
    let mut buf = vec![0u8; DENTS_BUF];
    loop {
        // SAFETY: buf is valid writable memory of the length passed; dir
        // is an open directory.
        let n = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                dir.as_raw_fd(),
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(Error::last("getdents64"));
        }
        if n == 0 {
            return Ok(names);
        }
        let chunk = buf.get(..n as usize).unwrap_or(&[]);
        for name in records(chunk)? {
            if name == b"." || name == b".." {
                continue;
            }
            if names.len() >= max {
                return Err(Error::TooManyEntries { max });
            }
            names.push(name.to_vec());
        }
    }
}

/// The names of the `struct linux_dirent64` records in `chunk`
/// (`include/linux/dirent.h`: `d_ino` u64, `d_off` s64, `d_reclen` u16,
/// `d_type` u8, then the NUL-terminated name), checked against the
/// record's length; a malformed record is EIO.
fn records(chunk: &[u8]) -> Result<Vec<&[u8]>> {
    const NAME_AT: usize = 19;
    let bad = Error::Sys {
        call: "getdents64",
        errno: libc::EIO,
    };
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < chunk.len() {
        let rest = chunk.get(at..).unwrap_or(&[]);
        let Some(len) = rest.get(16..18) else {
            return Err(bad);
        };
        let len = usize::from(u16::from_ne_bytes([len[0], len[1]]));
        let Some(record) = rest.get(..len).filter(|_| len > NAME_AT) else {
            return Err(bad);
        };
        let field = record.get(NAME_AT..).unwrap_or(&[]);
        let Some(end) = field.iter().position(|b| *b == 0) else {
            return Err(bad);
        };
        out.push(&field[..end]);
        at += len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    /// A fresh directory next to the test binary, on the target
    /// directory's file system, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let exe = std::env::current_exe().expect("current_exe");
            let dir = exe
                .parent()
                .expect("the test binary's directory")
                .join(format!("boneli-sys-fs-{tag}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).expect("create the scratch directory");
            Scratch(dir)
        }

        fn fd(&self) -> OwnedFd {
            std::fs::File::open(&self.0)
                .expect("open the scratch")
                .into()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            crate::test_guard::remove_tree(&self.0);
        }
    }

    fn errno_of(r: Result<OwnedFd>) -> i32 {
        match r {
            Err(Error::Sys {
                call: "openat2(beneath)",
                errno,
            }) => errno,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn open_beneath_follows_nothing() {
        let s = Scratch::new("follow");
        std::fs::create_dir(s.0.join("d")).expect("mkdir");
        std::fs::write(s.0.join("d/f"), b"x").expect("write");
        symlink("f", s.0.join("d/rel")).expect("symlink");
        symlink("/etc/hostname", s.0.join("abs")).expect("symlink");
        symlink("d", s.0.join("dirlink")).expect("symlink");
        let root = s.fd();
        let dir = root.as_fd();
        assert!(open_beneath(dir, b"d/f", Open::Read).is_ok());
        assert!(open_beneath(dir, b"d", Open::Directory).is_ok());
        // A symlink at the end, relative or absolute, and at a parent.
        assert_eq!(
            errno_of(open_beneath(dir, b"d/rel", Open::Read)),
            libc::ELOOP
        );
        assert_eq!(errno_of(open_beneath(dir, b"abs", Open::Read)), libc::ELOOP);
        assert_eq!(
            errno_of(open_beneath(dir, b"dirlink/f", Open::Path)),
            libc::ELOOP
        );
        // As a directory, a symlink at the end is ENOTDIR: the kernel
        // checks O_DIRECTORY on the link itself.
        assert_eq!(
            errno_of(open_beneath(dir, b"dirlink", Open::Directory)),
            libc::ENOTDIR
        );
        // As itself with O_PATH, and its target read raw.
        let link = open_beneath(dir, b"abs", Open::Path).expect("the link itself");
        assert_eq!(read_link(link.as_fd()).expect("readlink"), b"/etc/hostname");
        let file = open_beneath(dir, b"d/f", Open::Path).expect("O_PATH");
        match read_link(file.as_fd()) {
            Err(Error::Sys {
                call: "readlinkat",
                errno: libc::ENOENT,
            }) => {}
            other => panic!("a file is no symlink: {other:?}"),
        }
        // Read opens a directory too: what it opened is the caller's fstat.
        assert!(open_beneath(dir, b"d", Open::Read).is_ok());
        assert_eq!(
            errno_of(open_beneath(dir, b"d/f", Open::Directory)),
            libc::ENOTDIR
        );
        assert_eq!(
            errno_of(open_beneath(dir, b"d/f/x", Open::Path)),
            libc::ENOTDIR
        );
        assert_eq!(
            errno_of(open_beneath(dir, b"none", Open::Path)),
            libc::ENOENT
        );
    }

    /// `RESOLVE_BENEATH` and `RESOLVE_NO_MAGICLINKS` change nothing a
    /// test can see while the path check refuses `..` and absolute paths
    /// and `RESOLVE_NO_SYMLINKS` refuses every symlink, magic links
    /// included; they stay as the second layer, pinned here.
    #[test]
    fn every_open_sets_all_four_resolve_flags() {
        assert_eq!(
            RESOLVE,
            libc::RESOLVE_BENEATH
                | libc::RESOLVE_NO_SYMLINKS
                | libc::RESOLVE_NO_MAGICLINKS
                | libc::RESOLVE_NO_XDEV
        );
    }

    #[test]
    fn met_names_the_errno() {
        let sys = |errno| Error::Sys {
            call: "openat2(beneath)",
            errno,
        };
        for (errno, met) in [
            (libc::ENOENT, Met::Nothing),
            (libc::ENOTDIR, Met::NotADirectory),
            (libc::ELOOP, Met::Symlink),
            (libc::EXDEV, Met::MountPoint),
            (libc::EACCES, Met::Denied),
            (libc::EIO, Met::Other),
        ] {
            assert_eq!(Met::of(&sys(errno)), met, "{errno}");
        }
        assert_eq!(Met::of(&Error::TooManyEntries { max: 1 }), Met::Other);
    }

    #[test]
    fn open_beneath_refuses_paths_before_any_call() {
        let s = Scratch::new("paths");
        let root = s.fd();
        for bad in [
            &b""[..],
            b"/etc",
            b"a\0b",
            b"..",
            b"a/../b",
            b"./a",
            b"a//b",
            b"a/",
        ] {
            assert!(
                matches!(
                    open_beneath(root.as_fd(), bad, Open::Path),
                    Err(Error::InvalidBeneathPath(_))
                ),
                "{bad:?}"
            );
        }
    }

    /// A mount point is EXDEV, at the end and in the middle: `/proc` is a
    /// mount of its own on every Linux host.
    #[test]
    fn open_beneath_crosses_no_mount() {
        let root: OwnedFd = std::fs::File::open("/").expect("/").into();
        for path in [&b"proc"[..], b"proc/self"] {
            assert_eq!(
                errno_of(open_beneath(root.as_fd(), path, Open::Path)),
                libc::EXDEV,
                "{path:?}"
            );
        }
    }

    /// A FIFO opens without a writer under both modes that may meet it.
    #[test]
    fn fifo_opens_without_blocking() {
        let s = Scratch::new("fifo");
        crate::make_fifo(&s.0.join("p"), 0o644).expect("mkfifo");
        let root = s.fd();
        assert!(open_beneath(root.as_fd(), b"p", Open::Path).is_ok());
        assert!(open_beneath(root.as_fd(), b"p", Open::Read).is_ok());
    }

    #[test]
    fn unreadable_is_eacces() {
        let s = Scratch::new("mode");
        std::fs::write(s.0.join("f"), b"x").expect("write");
        std::fs::create_dir(s.0.join("d")).expect("mkdir");
        for name in ["f", "d"] {
            std::fs::set_permissions(s.0.join(name), std::fs::Permissions::from_mode(0o000))
                .expect("chmod 0");
        }
        let root = s.fd();
        assert_eq!(
            errno_of(open_beneath(root.as_fd(), b"f", Open::Read)),
            libc::EACCES
        );
        assert_eq!(
            errno_of(open_beneath(root.as_fd(), b"d", Open::Directory)),
            libc::EACCES
        );
    }

    #[test]
    fn read_dir_lists_up_to_its_cap() {
        let s = Scratch::new("dents");
        // Long names, so the 500 entries take several reads.
        let mut want: Vec<Vec<u8>> = (0..500)
            .map(|i| format!("{i:0>250}").into_bytes())
            .collect();
        for name in &want {
            std::fs::write(s.0.join(std::str::from_utf8(name).expect("ascii")), b"")
                .expect("write");
        }
        let dir = open_beneath(s.fd().as_fd(), b".", Open::Directory);
        assert!(dir.is_err(), "`.` is refused");
        let dir: OwnedFd = std::fs::File::open(&s.0).expect("open").into();
        let mut got = read_dir(dir.as_fd(), 500).expect("exactly the cap");
        got.sort();
        want.sort();
        assert_eq!(got, want);
        // Read again from the start, through the same descriptor.
        assert_eq!(read_dir(dir.as_fd(), 500).expect("again").len(), 500);
        assert!(matches!(
            read_dir(dir.as_fd(), 499),
            Err(Error::TooManyEntries { max: 499 })
        ));
        let empty = Scratch::new("empty");
        let fd = empty.fd();
        assert_eq!(
            read_dir(fd.as_fd(), 0).expect("empty"),
            Vec::<Vec<u8>>::new()
        );
    }

    #[test]
    fn malformed_records_are_eio() {
        // A record shorter than its header, one longer than the chunk, one
        // without a NUL in its name.
        let mut ok = vec![0u8; 24];
        ok[16..18].copy_from_slice(&24u16.to_ne_bytes());
        ok[19] = b'a';
        assert_eq!(records(&ok).expect("one record"), vec![&b"a"[..]]);
        for bad in [
            {
                let mut r = ok.clone();
                r[16..18].copy_from_slice(&19u16.to_ne_bytes());
                r
            },
            {
                let mut r = ok.clone();
                r[16..18].copy_from_slice(&25u16.to_ne_bytes());
                r
            },
            {
                let mut r = ok.clone();
                for b in &mut r[19..] {
                    *b = b'a';
                }
                r
            },
            ok[..17].to_vec(),
        ] {
            assert!(
                matches!(
                    records(&bad),
                    Err(Error::Sys {
                        call: "getdents64",
                        errno: libc::EIO
                    })
                ),
                "{bad:?}"
            );
        }
    }
}
