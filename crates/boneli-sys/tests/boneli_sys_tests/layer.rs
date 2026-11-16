//! The overlay layer primitives for the OCI unpacker (#7, ADR-009): 0:0
//! whiteouts, FIFOs, the opaque marker and `user.*` xattrs. They need no
//! namespace, so they run in every `cargo test`.

use std::os::unix::fs::{FileTypeExt, MetadataExt, symlink};

use boneli_sys::{Error, make_fifo, make_whiteout, mark_opaque, user_xattr};

use crate::support::TempDir;

const OPAQUE: &str = "user.overlay.opaque";

fn errno_of(result: boneli_sys::Result<()>) -> (&'static str, i32) {
    match result {
        Err(Error::Sys { call, errno }) => (call, errno),
        other => panic!("expected a syscall error, got {other:?}"),
    }
}

#[test]
fn whiteout_is_char_0_0() {
    let dir = TempDir::new("layer-whiteout");
    let path = dir.path().join("gone");
    make_whiteout(&path).expect("an unprivileged user may create a 0:0 whiteout");
    let meta = std::fs::symlink_metadata(&path).expect("stat the whiteout");
    assert!(meta.file_type().is_char_device(), "{meta:?}");
    assert_eq!(meta.rdev(), 0, "major and minor are 0");
}

#[test]
fn whiteout_never_follows_symlink() {
    let dir = TempDir::new("layer-whiteout-link");
    let outside = TempDir::new("layer-whiteout-outside");
    let target = outside.path().join("victim");
    let link = dir.path().join("link");
    symlink(&target, &link).expect("dangling symlink");

    // A dangling symlink: mknod fails with EEXIST and creates nothing at
    // the target.
    assert_eq!(errno_of(make_whiteout(&link)), ("mknod", libc::EEXIST));
    assert!(
        std::fs::symlink_metadata(&target).is_err(),
        "nothing was created through the symlink"
    );

    // A file, a directory and a symlink to a file stay as they were.
    let file = dir.path().join("file");
    std::fs::write(&file, b"keep").expect("file");
    std::fs::write(&target, b"victim").expect("target");
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).expect("dir");
    for path in [&file, &sub, &link] {
        assert_eq!(errno_of(make_whiteout(path)), ("mknod", libc::EEXIST));
    }
    assert_eq!(std::fs::read(&file).expect("read"), b"keep");
    assert_eq!(std::fs::read(&target).expect("read"), b"victim");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("link")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn fifo_is_created_with_masked_mode() {
    let dir = TempDir::new("layer-fifo");
    let path = dir.path().join("pipe");
    // Bits above 0o777 (setuid, setgid, sticky, a file type) are dropped.
    make_fifo(&path, 0o104_600).expect("mkfifo");
    let meta = std::fs::symlink_metadata(&path).expect("stat");
    assert!(meta.file_type().is_fifo(), "{meta:?}");
    assert_eq!(meta.mode() & 0o7000, 0, "no special bits");
    assert_eq!(errno_of(make_fifo(&path, 0o600)), ("mknod", libc::EEXIST));
}

#[test]
fn opaque_rules() {
    let dir = TempDir::new("layer-opaque");
    let opaque = dir.path().join("opaque");
    std::fs::create_dir(&opaque).expect("dir");
    mark_opaque(&opaque).expect("user.* xattr on a directory");
    assert_eq!(
        user_xattr(&opaque, OPAQUE).expect("read back"),
        Some(b"y".to_vec())
    );

    // On a symlink the call acts on the link, and Linux allows user.*
    // xattrs only on files and directories: an error, and the directory
    // the link points to stays unmarked.
    let plain = dir.path().join("plain");
    std::fs::create_dir(&plain).expect("dir");
    let link = dir.path().join("link");
    symlink(&plain, &link).expect("symlink");
    let (call, _) = errno_of(mark_opaque(&link));
    assert_eq!(call, "lsetxattr");
    assert_eq!(user_xattr(&plain, OPAQUE).expect("read"), None);
}

#[test]
fn user_xattr_rules() {
    let dir = TempDir::new("layer-xattr");
    let file = dir.path().join("file");
    std::fs::write(&file, b"").expect("file");

    // Absent: None, not an error.
    assert_eq!(user_xattr(&file, OPAQUE).expect("absent"), None);
    assert_eq!(user_xattr(&file, "user.anything").expect("absent"), None);

    // Names outside `user.` are refused before any syscall.
    for name in [
        "trusted.overlay.opaque",
        "security.capability",
        "system.posix_acl_access",
        "user",
        "USER.overlay.opaque",
        "",
    ] {
        match user_xattr(&file, name) {
            Err(Error::Sys { call, errno }) => {
                assert_eq!((call, errno), ("lgetxattr", libc::EINVAL), "{name:?}");
            }
            other => panic!("{name:?}: expected a refusal, got {other:?}"),
        }
    }
    assert!(matches!(user_xattr(&file, "user.a\0b"), Err(Error::Nul(_))));

    // A missing path is a syscall error, not None.
    assert!(user_xattr(&dir.path().join("missing"), OPAQUE).is_err());
}

#[test]
fn layer_paths_with_nul_are_refused() {
    let path = std::path::Path::new("a\0b");
    assert!(matches!(make_whiteout(path), Err(Error::Nul(_))));
    assert!(matches!(make_fifo(path, 0o600), Err(Error::Nul(_))));
    assert!(matches!(mark_opaque(path), Err(Error::Nul(_))));
}

#[test]
fn sync_filesystem_flushes_a_directory() {
    let dir = TempDir::new("layer-syncfs");
    std::fs::write(dir.path().join("f"), b"data").expect("file");
    let handle = std::fs::File::open(dir.path()).expect("open the directory");
    boneli_sys::sync_filesystem(&handle).expect("syncfs");
    let file = std::fs::File::open(dir.path().join("f")).expect("open the file");
    boneli_sys::sync_filesystem(&file).expect("syncfs through a file on the same filesystem");
}
