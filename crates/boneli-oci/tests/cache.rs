//! The layer cache's commit point under concurrency, failure and a low
//! descriptor limit (ADR-009, D8).

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use boneli_https::Sha256;
use boneli_oci::{Budget, Compression, Error, LayerCache, Limits};

use support::TempDir;
use support::tarball::Tar;

fn limits() -> Limits {
    Limits::new(1 << 32, 1 << 34, 1 << 20, 1 << 20, 512).expect("limits")
}

fn layer_of(files: usize) -> Vec<u8> {
    let mut t = Tar::new();
    for i in 0..files {
        t.file(&format!("f{i}"), 0o644, b"x");
    }
    t.finish()
}

fn tmp_names(store: &Path) -> Vec<String> {
    // Staging trees and staged sidecars are dot names in layers/sha256/.
    let mut v: Vec<String> = std::fs::read_dir(store.join("layers/sha256"))
        .expect("layers")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('.'))
        .collect();
    v.sort();
    v
}

/// Two caches on one root, in one process, unpacking different layers at
/// the same time: every layer is committed with its own sidecar and no
/// unpack fails. Each temporary tree stages its sidecar at its own path.
#[test]
fn concurrent_caches_keep_their_sidecars() {
    let store = TempDir::new("race");
    let root: PathBuf = store.path().to_path_buf();
    let worker = |files: usize, root: PathBuf| {
        std::thread::spawn(move || {
            let bytes = layer_of(files);
            let id = Sha256::digest(&bytes);
            let cache = LayerCache::new(&root).expect("cache");
            let mut anomalies = Vec::new();
            for _ in 0..400 {
                let mut budget = Budget::new(limits());
                match cache.unpack(&id, Compression::None, &bytes[..], &mut budget) {
                    Ok(s) if s.bytes != bytes.len() as u64 => {
                        anomalies.push(format!("stats {s:?}"))
                    }
                    Ok(_) => {}
                    Err(e) => anomalies.push(e.to_string()),
                }
                match cache.cached(&id) {
                    Ok(Some(s)) if s.bytes == bytes.len() as u64 && s.entries == files as u64 => {}
                    other => anomalies.push(format!("sidecar {other:?}")),
                }
            }
            anomalies
        })
    };
    let a = worker(1, root.clone());
    let b = worker(40, root.clone());
    let (a, b) = (a.join().expect("thread"), b.join().expect("thread"));
    assert!(a.is_empty(), "{} anomalies, first {:?}", a.len(), a.first());
    assert!(b.is_empty(), "{} anomalies, first {:?}", b.len(), b.first());
    assert!(tmp_names(store.path()).is_empty());
}

/// A refused layer charges nothing: the budget is the same after
/// `Err(DiffId)` and after a refusal in the middle of the stream.
#[test]
fn refused_layer_leaves_budget_unchanged() {
    let store = TempDir::new("budget");
    let cache = LayerCache::new(store.path()).expect("cache");
    let good = layer_of(3);
    let mut budget = Budget::new(limits());
    cache
        .unpack(
            &Sha256::digest(&good),
            Compression::None,
            &good[..],
            &mut budget,
        )
        .expect("commit");
    let before = (budget.bytes(), budget.entries());
    assert_eq!(before, (good.len() as u64, 3));

    let other = layer_of(2);
    let e = cache
        .unpack(&[0u8; 32], Compression::None, &other[..], &mut budget)
        .expect_err("wrong diff_id");
    assert!(matches!(e, Error::DiffId { .. }), "{e}");
    assert_eq!((budget.bytes(), budget.entries()), before);

    let mut bad = Tar::new();
    bad.file("ok", 0o644, b"x").file("../x", 0o644, b"x");
    let bad = bad.finish();
    let e = cache
        .unpack(
            &Sha256::digest(&bad),
            Compression::None,
            &bad[..],
            &mut budget,
        )
        .expect_err("refused");
    assert!(matches!(e, Error::Entry { .. }), "{e}");
    assert_eq!((budget.bytes(), budget.entries()), before);

    // The loser of a commit race is charged like the winner.
    let again = cache
        .unpack(
            &Sha256::digest(&good),
            Compression::None,
            &good[..],
            &mut budget,
        )
        .expect("already committed");
    assert_eq!(again.bytes, good.len() as u64);
    assert_eq!(
        (budget.bytes(), budget.entries()),
        (2 * good.len() as u64, 6)
    );
}

const CHILD: &str = "BONELI_OCI_LOW_NOFILE_CHILD";
/// Far below the tree's depth, so a removal that holds a descriptor per
/// level runs out of them.
const NOFILE: u32 = 48;
const DEPTH: usize = 400;

/// A failed layer deeper than the descriptor limit is still removed: the
/// cleanup holds a bounded number of descriptors whatever the depth. The
/// check runs in a child process (this test binary again) started under
/// `ulimit -n 48`, so the lowered limit touches nothing else.
#[test]
fn failed_deep_layer_removed_under_low_nofile() {
    if std::env::var_os(CHILD).is_some() {
        let store = PathBuf::from(std::env::var_os(CHILD).expect("store"));
        let cache = LayerCache::new(&store).expect("cache");
        let deep = vec!["d"; DEPTH].join("/");
        let mut t = Tar::new();
        t.pax(&[("path", format!("{deep}/f").as_bytes())])
            .file("x", 0o644, b"x");
        // A read-only directory on the way down, so the removal must also
        // restore permissions level by level.
        t.dir("d/d", 0o500);
        let bytes = t.finish();
        let mut budget = Budget::new(limits());
        let e = cache
            .unpack(&[0u8; 32], Compression::None, &bytes[..], &mut budget)
            .expect_err("wrong diff_id");
        assert!(matches!(e, Error::DiffId { .. }), "{e}");
        assert!(
            tmp_names(&store).is_empty(),
            "left behind: {:?}",
            tmp_names(&store)
        );
        return;
    }
    let store = TempDir::new("nofile");
    let exe = std::env::current_exe().expect("test binary");
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ulimit -n {NOFILE} && exec \"$0\" --exact failed_deep_layer_removed_under_low_nofile --test-threads=1 --nocapture"
        ))
        .arg(&exe)
        .env(CHILD, store.path())
        .output()
        .expect("spawn the child");
    assert!(
        out.status.success(),
        "child failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 passed"),
        "the child ran the check: {stdout}"
    );
}

/// The temporary tree is staged inside `layers/sha256/` under a dot name,
/// so the commit is a rename within one directory (no `..` to rewrite, no
/// `u+w` to lend the root) and nothing else is created at the root.
#[test]
fn staging_stays_in_the_layers_directory() {
    let store = TempDir::new("staging");
    let cache = LayerCache::new(store.path()).expect("cache");
    assert_eq!(names(store.path()), ["layers"]);
    let ro = Tar::new().dir("./", 0o555).file("f", 0o444, b"x").finish();
    let id = Sha256::digest(&ro);
    cache
        .unpack(&id, Compression::None, &ro[..], &mut Budget::new(limits()))
        .expect("commit");
    let layers = store.path().join("layers/sha256");
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(names(&layers), [hex.clone(), format!("{hex}.stats")]);
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(layers.join(&hex))
        .expect("layer")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o555);
    let e = cache
        .unpack(
            &[0u8; 32],
            Compression::None,
            &ro[..],
            &mut Budget::new(limits()),
        )
        .expect_err("mismatch");
    assert!(matches!(e, Error::DiffId { .. }), "{e}");
    assert_eq!(names(&layers), [hex.clone(), format!("{hex}.stats")]);
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}
