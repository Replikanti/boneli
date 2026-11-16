//! Shared helpers of the `boneli-oci` integration tests.

#![allow(dead_code)]

pub mod images;
pub mod registry;
pub mod sandbox;
pub mod tarball;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A directory under `CARGO_TARGET_TMPDIR`, unique per process and call,
/// removed on drop even when the unpacker left directories with mode 0.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates `<CARGO_TARGET_TMPDIR>/<tag>-<pid>-<counter>`.
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("oci-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create the test's temp dir");
        TempDir { path }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        make_writable(&self.path);
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Gives every directory under `path` (not following symlinks) `u+rwx`, so
/// a test can look inside and remove it.
pub fn make_writable(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let mode = meta.permissions().mode() | 0o700;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            make_writable(&entry.path());
        }
    }
}

/// The kernel's boot id as the 32 hex digits a temporary name carries
/// (ADR-009, D8): `/proc/sys/kernel/random/boot_id` without its dashes.
pub fn boot_hex() -> String {
    let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").expect("boot id");
    let hex: String = id.trim_end().chars().filter(|c| *c != '-').collect();
    assert_eq!(hex.len(), 32, "{id:?}");
    hex
}

/// This process's PID namespace inode, from `/proc/self/ns/pid`.
pub fn own_pidns() -> u64 {
    let link = std::fs::read_link("/proc/self/ns/pid").expect("ns link");
    link.to_str()
        .and_then(|l| l.strip_prefix("pid:["))
        .and_then(|l| l.strip_suffix(']'))
        .and_then(|l| l.parse().ok())
        .expect("pid:[inode]")
}

/// The start time of the process `/proc/<pid>` names, field 22 of its
/// stat; `"self"` names this one.
pub fn start_of(pid: &str) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let after = &stat[stat.rfind(')').expect("comm") + 1..];
    after
        .split_whitespace()
        .nth(19)
        .and_then(|f| f.parse().ok())
        .expect("starttime")
}

/// The owner token of ADR-009 D8, `<boot>.<pidns>.<pid>.<start>`: 32 hex
/// digits, then 20, 10 and 20 decimal digits.
pub fn owner_token(boot: &str, pidns: u64, pid: u32, start: u64) -> String {
    format!("{boot}.{pidns:020}.{pid:010}.{start:020}")
}

/// An owned name `<prefix><token>.<n>` with a 20-digit counter.
pub fn owned_name(prefix: &str, token: &str, n: u64) -> String {
    format!("{prefix}{token}.{n:020}")
}
