//! A case-insensitive store (ADR-009, D2 and D8). On a casefold directory a
//! symlink named `A` can replace the directory `a`; the store refuses such
//! a root, and the unpacker refuses the alias on its own.
//!
//! The test needs tmpfs with `casefold` (Linux 6.13) and an unprivileged
//! user namespace with its own mount namespace, so it is a host test:
//! `cargo test -p boneli-oci --test casefold -- --ignored`. It never needs
//! root. It re-executes this binary inside `unshare -Urm`, mounts a
//! casefold tmpfs over a temporary directory there, and marks a
//! subdirectory `+F`. Where the kernel lacks tmpfs casefold, list
//! `tmpfs-casefold` in `BONELI_OCI_HOST_GAPS` to skip it by name.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use boneli_https::Sha256;
use boneli_oci::{Budget, Compression, Error, LayerCache, Limits, unpack};

use support::TempDir;
use support::tarball::Tar;

const CHILD: &str = "BONELI_OCI_CASEFOLD_CHILD";
const GAPS: &str = "BONELI_OCI_HOST_GAPS";
const GAP: &str = "tmpfs-casefold";

fn budget() -> Budget {
    Budget::new(Limits::new(1 << 32, 1 << 34, 1 << 20, 1 << 20, 128).expect("limits"))
}

/// The reviewer's sequence: a directory `a`, a symlink `A` pointing out of
/// the tree, then a file under `a`.
fn alias_layer(outside: &Path) -> Vec<u8> {
    Tar::new()
        .dir("a", 0o755)
        .symlink("A", outside.to_str().expect("utf-8"))
        .file("a/pwned", 0o644, b"written through a symlink\n")
        .finish()
}

fn child(cf: &Path) {
    // The store refuses a case-insensitive root at open.
    let store = cf.join("store");
    std::fs::create_dir(&store).expect("store");
    match LayerCache::new(&store) {
        Err(Error::CaseInsensitive(path)) => assert!(path.starts_with(&store), "{path:?}"),
        other => panic!("a casefold store was opened: {other:?}"),
    }

    // The unpacker refuses the alias even without the store's check.
    let outside = cf.join("outside");
    std::fs::create_dir(&outside).expect("outside");
    let layer = cf.join("layer");
    std::fs::create_dir(&layer).expect("layer");
    assert!(
        layer.join("A").exists() == layer.join("a").exists(),
        "casefold applies"
    );
    let bytes = alias_layer(&outside);
    let e = unpack(&bytes[..], Compression::None, &layer, &mut budget()).expect_err("alias");
    assert!(matches!(e, Error::Entry { .. }), "{e}");
    assert!(
        !outside.join("pwned").exists(),
        "a layer wrote outside its tree"
    );
    let _ = Sha256::digest(&bytes);
}

#[test]
#[ignore = "host: needs an unprivileged user namespace and tmpfs casefold"]
fn casefold_store_and_alias_refused() {
    if let Some(cf) = std::env::var_os(CHILD) {
        child(&PathBuf::from(cf));
        return;
    }
    if std::env::var(GAPS).is_ok_and(|g| g.split(',').any(|x| x == GAP)) {
        println!("skipped: {GAP} listed in {GAPS}");
        return;
    }
    let mount_point = TempDir::new("casefold");
    let exe = std::env::current_exe().expect("test binary");
    let script = "mount -t tmpfs -o casefold boneli-oci-casefold \"$1\" \
        && mkdir \"$1/cf\" && chattr +F \"$1/cf\" \
        && BONELI_OCI_CASEFOLD_CHILD=\"$1/cf\" exec \"$0\" --exact casefold_store_and_alias_refused --ignored --test-threads=1 --nocapture";
    let out = Command::new("unshare")
        .args(["-Urm", "sh", "-c", script])
        .arg(&exe)
        .arg(mount_point.path())
        .output()
        .expect("spawn unshare");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "the casefold child failed (list {GAP} in {GAPS} if the kernel lacks tmpfs casefold):\n{text}"
    );
    assert!(text.contains("1 passed"), "the child ran the check: {text}");
}
