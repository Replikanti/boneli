//! Eviction (ADR-025, D4 to D8): one test per edge case of the #56 plan,
//! PR 2. Layers are pulled through the fake registry where the test is
//! about pulls and leases, and planted by hand (a directory and a sidecar
//! with exact totals) where it is about accounting and order.

mod support;

use std::fs::{File, TryLockError};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, SystemTime};

use boneli_app::{ImageError, ImageRef, ImageStore};
use boneli_https::Sha256;
use boneli_oci::{
    BLOCK_ALLOWANCE, Budget, CACHE_BUDGET_BYTES, Compression, Error, LayerCache, Limits,
    MAX_DOCUMENT_BYTES, MAX_HEAD_BYTES, MAX_IMAGE_BYTES, MAX_IMAGE_ENTRIES, MAX_LAYERS,
    OciImageStore, StoreConfig,
};

use support::TempDir;
use support::images::{Layer, blob_requests, config, open, push};
use support::registry::{Fake, Hub, Reply};
use support::tarball::Tar;

fn image_ref(name: &str, digest: &str) -> ImageRef {
    ImageRef {
        name: name.to_owned(),
        digest: digest.to_owned(),
        platform: "linux/amd64".to_owned(),
    }
}

fn hex(digest: &str) -> String {
    digest.trim_start_matches("sha256:").to_owned()
}

/// A store at `root` over `fake` whose budget is `budget`.
fn open_with(root: &Path, fake: &Fake, budget: u64) -> OciImageStore {
    let mut config = config(fake);
    config.cache_budget = budget;
    OciImageStore::open(root, config).expect("open the store")
}

fn no_requests() -> Fake {
    Fake::new(|_| unreachable!("the test makes no request"))
}

/// A hub with `library/app`: three layers, the middle one gzip.
fn app_hub() -> (Hub, support::images::Pushed, Vec<Layer>) {
    let mut hub = Hub::default();
    let layers = vec![
        Layer::file("etc/base", b"base\n"),
        Layer::gzip(Tar::new().file("usr/bin/tool", 0o755, b"#!\n").finish()),
        Layer::file("etc/top", b"top\n"),
    ];
    let pushed = push(&mut hub, "library/app", &layers, "");
    (hub, pushed, layers)
}

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn set_mtime(path: &Path, when: SystemTime) {
    File::open(path)
        .and_then(|f| f.set_modified(when))
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

fn mtime(path: &Path) -> SystemTime {
    std::fs::symlink_metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// The 64 hex digits of `n`, a layer name.
fn hex_of(n: u64) -> String {
    format!("{n:064x}")
}

/// A committed layer planted by hand: `layers/sha256/<hex>` with one file
/// and a sidecar that says `bytes` and `entries`, stamped `when`.
fn plant_layer(root: &Path, hex: &str, bytes: u64, entries: u64, when: SystemTime) -> PathBuf {
    let dir = root.join("layers/sha256").join(hex);
    std::fs::create_dir(&dir).expect("layer");
    std::fs::write(dir.join("f"), b"x").expect("file");
    let sidecar = sidecar_of(&dir);
    std::fs::write(
        &sidecar,
        format!("bytes {bytes}\nentries {entries}\nskipped-devices 0\n"),
    )
    .expect("sidecar");
    set_mtime(&sidecar, when);
    dir
}

fn sidecar_of(layer: &Path) -> PathBuf {
    let mut name = layer.as_os_str().to_owned();
    name.push(".stats");
    PathBuf::from(name)
}

/// What a planted layer of `bytes` with 3 entries counts (D4).
fn cost3(bytes: u64) -> u64 {
    bytes + BLOCK_ALLOWANCE * 4
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// The dot names of `layers/sha256/` and `blobs/sha256/`.
fn dot_names(root: &Path) -> Vec<String> {
    ["layers/sha256", "blobs/sha256"]
        .iter()
        .flat_map(|d| names_in(&root.join(d)))
        .filter(|n| n.starts_with('.'))
        .collect()
}

fn is_held(path: &Path) -> bool {
    let file = File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    match file.try_lock() {
        Ok(()) => false,
        Err(TryLockError::WouldBlock) => true,
        Err(TryLockError::Error(e)) => panic!("{}: {e}", path.display()),
    }
}

/// An empty store trims to nothing and reports zeros.
#[test]
fn trim_empty_store() {
    let tmp = TempDir::new("trim-empty");
    let store = open(&tmp.path().join("store"), &no_requests());
    let report = store.trim().expect("trim");
    assert_eq!(report.before, 0);
    assert_eq!(report.after, 0);
    assert_eq!(report.budget, CACHE_BUDGET_BYTES);
    assert_eq!(report.removed_layers, 0);
    assert_eq!(report.removed_files, 0);
    assert_eq!(report.skipped_in_use, 0);
}

/// The budget is inclusive (D5), with the totals of D4 written out: each
/// planted layer has 3 entries, so it counts its bytes + 4,096 × 4.
/// A = 17,384, B = 25,576, C = 33,768, 76,728 in all, A the oldest.
#[test]
fn budget_bound_is_inclusive() {
    assert_eq!(cost3(1_000), 17_384);
    for (budget, kept, after) in [
        (76_728, ["a", "b", "c"].as_slice(), 76_728),
        (76_727, ["b", "c"].as_slice(), 59_344),
        (59_343, ["c"].as_slice(), 33_768),
    ] {
        let tmp = TempDir::new("budget-bound");
        let root = tmp.path().join("store");
        let store = open_with(&root, &no_requests(), budget);
        let layers = [
            ("a", plant_layer(&root, &hex_of(0xa), 1_000, 3, at(1_000))),
            ("b", plant_layer(&root, &hex_of(0xb), 9_192, 3, at(2_000))),
            ("c", plant_layer(&root, &hex_of(0xc), 17_384, 3, at(3_000))),
        ];
        let report = store.trim().expect("trim");
        assert_eq!(report.before, 76_728, "budget {budget}");
        assert_eq!(report.after, after, "budget {budget}");
        assert_eq!(report.removed_layers, 3 - kept.len() as u64);
        for (name, path) in &layers {
            assert_eq!(
                exists(path) && exists(&sidecar_of(path)),
                kept.contains(name),
                "budget {budget}: {name}"
            );
            if !kept.contains(name) {
                assert!(!exists(&sidecar_of(path)), "{name}'s sidecar stayed");
            }
        }
        assert_eq!(dot_names(&root), Vec::<String>::new(), "budget {budget}");
    }
}

/// A leased image larger than the budget stays, everything else goes, and
/// the report shows the store over its budget (D5, decision 1 of #56 STOP 1).
#[test]
fn in_use_over_budget_is_soft() {
    let (hub, pushed, layers) = app_hub();
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("soft");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let lease = store
        .pull_leased(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let other = plant_layer(&root, &hex_of(1), 10, 0, at(1));
    let small = open_with(&root, &no_requests(), 1);
    let report = small.trim().expect("trim");
    assert!(report.after > report.budget, "{report:?}");
    assert_eq!(report.skipped_in_use, 3, "{report:?}");
    assert!(!exists(&other), "an unused layer stayed");
    for layer in &layers {
        let path = root.join("layers/sha256").join(hex(&layer.diff_id));
        assert!(
            exists(&path) && exists(&sidecar_of(&path)),
            "a leased layer went"
        );
    }
    assert!(
        names_in(&root.join("blobs/sha256")).is_empty(),
        "documents stayed under a budget of 1"
    );
    assert_eq!(lease.layers().len(), 3);
}

/// Least recently used first.
#[test]
fn evicts_least_recently_used_first() {
    let tmp = TempDir::new("lru");
    let root = tmp.path().join("store");
    let store = open_with(&root, &no_requests(), 2 * cost3(100));
    let newest = plant_layer(&root, &hex_of(1), 100, 3, at(3_000));
    let oldest = plant_layer(&root, &hex_of(2), 100, 3, at(1_000));
    let middle = plant_layer(&root, &hex_of(3), 100, 3, at(2_000));
    let report = store.trim().expect("trim");
    assert_eq!(report.removed_layers, 1);
    assert!(!exists(&oldest));
    assert!(exists(&middle) && exists(&newest));
}

/// Equal stamps, set explicitly: the path with the smaller bytes goes
/// first, so the order is deterministic.
#[test]
fn same_stamp_ties_break_by_name() {
    let tmp = TempDir::new("ties");
    let root = tmp.path().join("store");
    let store = open_with(&root, &no_requests(), cost3(100));
    let second = plant_layer(&root, &hex_of(0xb), 100, 3, at(1_000));
    let first = plant_layer(&root, &hex_of(0xa), 100, 3, at(1_000));
    store.trim().expect("trim");
    assert!(!exists(&first));
    assert!(exists(&second));
}

/// A stamp in the future (a clock that jumped back) is evicted last.
#[test]
fn future_stamp_evicted_last() {
    let tmp = TempDir::new("future");
    let root = tmp.path().join("store");
    let store = open_with(&root, &no_requests(), cost3(100));
    let future = plant_layer(
        &root,
        &hex_of(1),
        100,
        3,
        SystemTime::now() + Duration::from_secs(86_400),
    );
    let now = plant_layer(&root, &hex_of(2), 100, 3, SystemTime::now());
    store.trim().expect("trim");
    assert!(!exists(&now));
    assert!(exists(&future));
}

/// A cache hit in a pull, a `lease` and the drop of a lease each move a
/// layer's stamp forward, and reading a document moves its own (D5).
#[test]
fn use_refreshes_stamp() {
    let (hub, pushed, layers) = app_hub();
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("stamps");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let image = image_ref("library/app", &pushed.index);
    let rootfs = store.pull(&image).expect("pull");
    let sidecars: Vec<PathBuf> = layers
        .iter()
        .map(|l| sidecar_of(&root.join("layers/sha256").join(hex(&l.diff_id))))
        .collect();
    let past = at(1_000);
    let age = |what: &str| {
        for s in &sidecars {
            set_mtime(s, past);
        }
        what.to_owned()
    };
    let check = |what: &str| {
        for s in &sidecars {
            assert!(mtime(s) > past, "{what} did not stamp {}", s.display());
        }
    };

    let what = age("a cache hit");
    let lease = store.pull_leased(&image).expect("cache hit");
    check(&what);
    drop(lease);
    let what = age("a lease");
    let lease = store.lease(&rootfs).expect("lease");
    check(&what);
    let what = age("a lease's drop");
    drop(lease);
    check(&what);

    let config = root.join("blobs/sha256").join(hex(&pushed.config));
    set_mtime(&config, past);
    store.config(&rootfs).expect("config");
    assert!(mtime(&config) > past, "reading a document did not stamp it");
}

/// The image of [`documents_and_kept_blobs_evicted`] whose second layer
/// does not hash to its `diff_id`: its pull fails after fetching the blob,
/// which stays for the retry.
fn broken_image(hub: &mut Hub) -> (support::images::Pushed, String) {
    let good = Layer::file("ok", b"ok\n");
    let mut bad = Layer::file("bad", b"bad\n");
    bad.diff_id = format!("sha256:{}", "0".repeat(64));
    let pushed = push(hub, "library/broken", &[good, bad], "");
    let blob = pushed.blobs[1].clone();
    (pushed, blob)
}

/// Documents and kept layer blobs are units of their own, in the same
/// order as layers: the oldest unit, a blob a failed pull left, goes first;
/// under a budget of 1 every document goes with its `.type`.
#[test]
fn documents_and_kept_blobs_evicted() {
    let (mut hub, pushed, _) = app_hub();
    let (broken, kept) = broken_image(&mut hub);
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("docs");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    assert!(
        store
            .pull(&image_ref("library/broken", &broken.index))
            .is_err()
    );
    let blobs = root.join("blobs/sha256");
    let kept = blobs.join(hex(&kept));
    assert!(kept.is_file(), "the failed pull's blob is kept");
    assert!(!exists(&type_of(&kept)), "a layer blob has no type");
    set_mtime(&kept, at(1));
    let before = store.trim().expect("trim").before;
    drop(store);

    drop(open_with(&root, &fake, before - 1));
    assert!(!exists(&kept), "the oldest unit stayed");
    let docs = [&pushed.index, &pushed.manifest, &pushed.config];
    for d in docs {
        assert!(blobs.join(hex(d)).is_file(), "{d} went too");
    }

    let store = open_with(&root, &fake, 1);
    let left: Vec<String> = names_in(&blobs);
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(store.trim().expect("trim").before, 0);
}

fn type_of(blob: &Path) -> PathBuf {
    let mut name = blob.as_os_str().to_owned();
    name.push(".type");
    PathBuf::from(name)
}

/// A `.type` without its document is removed whatever the budget; a
/// document with its type stays.
#[test]
fn orphan_type_removed() {
    let tmp = TempDir::new("orphan-type");
    let root = tmp.path().join("store");
    let store = open(&root, &no_requests());
    let blobs = root.join("blobs/sha256");
    let orphan = blobs.join(format!("{}.type", hex_of(1)));
    std::fs::write(&orphan, b"application/json").expect("orphan");
    let doc = blobs.join(hex_of(2));
    std::fs::write(&doc, b"{}").expect("doc");
    let typed = blobs.join(format!("{}.type", hex_of(2)));
    std::fs::write(&typed, b"").expect("type");
    let report = store.trim().expect("trim");
    assert!(!exists(&orphan));
    assert!(exists(&doc) && exists(&typed));
    assert_eq!(report.removed_files, 1);
    assert_eq!(report.before, 2 + 2 * BLOCK_ALLOWANCE);
}

/// An evicted image pulled again is fetched again, every layer blob and
/// the config, and verified again: a blob tampered with on the second
/// fetch fails the pull.
#[test]
fn evicted_image_refetched_and_verified() {
    let (hub, pushed, _) = app_hub();
    let tamper = Arc::new(AtomicBool::new(false));
    let fake = {
        let tamper = Arc::clone(&tamper);
        let target = pushed.blobs[0].clone();
        Fake::new(move |s| {
            let reply = hub.handle(s);
            match reply {
                Reply::Http {
                    status: 200,
                    headers,
                    mut body,
                } if tamper.load(Ordering::SeqCst) && s.target.ends_with(&target) => {
                    body[0] ^= 1;
                    Reply::Http {
                        status: 200,
                        headers,
                        body,
                    }
                }
                other => other,
            }
        })
    };
    let tmp = TempDir::new("refetch");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let image = image_ref("library/app", &pushed.index);
    let first = store.pull(&image).expect("pull");
    drop(open_with(&root, &fake, 1));
    assert!(
        names_in(&root.join("layers/sha256")).is_empty(),
        "nothing was evicted"
    );
    let before = fake.seen().len();
    assert_eq!(store.pull(&image).expect("pull again"), first);
    let seen = fake.seen();
    let mut again = blob_requests(&seen[before..]);
    again.sort();
    let mut want = pushed.blobs.clone();
    want.push(pushed.config.clone());
    want.sort();
    assert_eq!(again, want);

    drop(open_with(&root, &fake, 1));
    tamper.store(true, Ordering::SeqCst);
    match store.pull(&image) {
        Err(ImageError::Failed { detail }) => assert!(!detail.trim().is_empty()),
        other => panic!("a tampered blob after eviction: {other:?}"),
    }
}

/// A gate in the fake registry: the first request for a blob waits until
/// the test opens it.
struct Gate {
    open: Mutex<bool>,
    opened: Condvar,
}

impl Gate {
    fn new() -> Arc<Gate> {
        Arc::new(Gate {
            open: Mutex::new(false),
            opened: Condvar::new(),
        })
    }

    fn wait(&self) {
        let mut open = self.open.lock().expect("gate");
        while !*open {
            open = self.opened.wait(open).expect("gate");
        }
    }

    fn release(&self) {
        *self.open.lock().expect("gate") = true;
        self.opened.notify_all();
    }
}

/// A second store's trim with a budget of 1, while a pull holds its second
/// layer's blob request: the first layer, committed, stays with its
/// sidecar, and so does every staging name of the pull; the pull then
/// completes with every layer in place.
#[test]
fn trim_spares_layers_of_a_pull_in_flight() {
    let (hub, pushed, layers) = app_hub();
    let gate = Gate::new();
    let (tx, rx) = mpsc::channel();
    let armed = AtomicBool::new(true);
    let reached = Mutex::new(tx);
    let blob = pushed.blobs[1].clone();
    let fake = {
        let gate = Arc::clone(&gate);
        Fake::new(move |s| {
            if s.target.ends_with(&blob)
                && s.header("authorization").is_some()
                && armed.swap(false, Ordering::SeqCst)
            {
                let _ = reached.lock().expect("reached").send(());
                gate.wait();
            }
            hub.handle(s)
        })
    };
    let tmp = TempDir::new("in-flight");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let image = image_ref("library/app", &pushed.index);
    std::thread::scope(|s| {
        let pull = s.spawn(|| store.pull_leased(&image));
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the pull reached the second layer blob");
        let first = root.join("layers/sha256").join(hex(&layers[0].diff_id));
        assert!(first.is_dir(), "the first layer is committed");
        let staging = dot_names(&root);
        let other = open_with(&root, &no_requests(), 1);
        let report = other.trim().expect("trim");
        let kept = exists(&first) && exists(&sidecar_of(&first));
        let staging_kept = staging.iter().all(|n| {
            exists(&root.join("layers/sha256").join(n))
                || exists(&root.join("blobs/sha256").join(n))
        });
        gate.release();
        let lease = pull.join().expect("thread").expect("pull");
        assert!(kept, "the committed layer of a pull in flight went");
        assert!(staging_kept, "a staging name went: {staging:?}");
        assert!(report.skipped_in_use >= 1, "{report:?}");
        for layer in lease.layers() {
            assert!(layer.is_dir() && exists(&sidecar_of(layer)));
        }
    });
}

/// An evicted tree whose directories have mode 0 and whose layer root is
/// read-only is removed completely.
#[test]
fn evicted_tree_with_mode_zero_dirs_removed() {
    let tmp = TempDir::new("mode-zero");
    let root = tmp.path().join("store");
    let store = open_with(&root, &no_requests(), 1);
    let layer = plant_layer(&root, &hex_of(1), 10, 3, at(1));
    std::fs::create_dir_all(layer.join("a/b")).expect("dirs");
    std::fs::write(layer.join("a/b/f"), b"x").expect("file");
    for (path, mode) in [
        (layer.join("a/b"), 0o000),
        (layer.join("a"), 0o000),
        (layer.clone(), 0o555),
    ] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }
    let report = store.trim().expect("trim");
    assert_eq!(report.removed_layers, 1);
    assert!(!exists(&layer));
    assert_eq!(dot_names(&root), Vec::<String>::new());
}

/// A layer whose deepest path is 4,095 bytes at the staging name is
/// committed, then evicted: renamed to a name of the staging length, every
/// path still fits `PATH_MAX`, so it is removed without `ENAMETOOLONG`.
#[test]
fn evicted_layer_paths_fit_path_max() {
    let tmp = TempDir::new("evict-path-max");
    let root = tmp.path().join("store");
    drop(open(&root, &no_requests()));
    let cache = LayerCache::new(&root).expect("cache");
    let staging_dir =
        root.join("layers/sha256").as_os_str().len() + 1 + LayerCache::STAGING_NAME_LEN;
    let rel_len = 4095 - staging_dir - 1;
    let mut rel = String::new();
    while rel.len() + 201 < rel_len {
        rel.push_str(&"d".repeat(200));
        rel.push('/');
    }
    rel.push_str(&"f".repeat(rel_len - rel.len()));
    let bytes = Tar::new()
        .pax(&[("path", rel.as_bytes())])
        .file("placeholder", 0o644, b"deep\n")
        .finish();
    let id = Sha256::digest(&bytes);
    let limits = Limits::new(1 << 32, 1 << 34, 1 << 20, 1 << 20, 128).expect("limits");
    cache
        .unpack(
            &cache.pin(&id).expect("pin"),
            Compression::None,
            &bytes[..],
            &mut Budget::new(limits),
        )
        .expect("unpacked at the staging name");
    drop(cache);
    let store = open_with(&root, &no_requests(), 1);
    assert!(!exists(&root.join("layers/sha256").join(hex_of_bytes(&id))));
    assert_eq!(dot_names(&root), Vec::<String>::new(), "the tree was left");
    drop(store);
}

fn hex_of_bytes(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Names that look like a layer, a sidecar, a blob or a lock file but are
/// not exactly 64 lower-case hex digits (with `.stats` or `.type`) are
/// never counted and never removed, in every store directory.
#[test]
fn trim_ignores_lookalike_names() {
    let tmp = TempDir::new("lookalikes");
    let root = tmp.path().join("store");
    let store = open_with(&root, &no_requests(), 1);
    let h = "a".repeat(64);
    let lookalikes = [
        h.to_uppercase(),
        "a".repeat(63),
        "a".repeat(65),
        format!("{}\u{ff41}", &h[..63]),
        format!("{h}\u{200b}"),
        format!("{h} "),
        format!("{h}.STATS"),
        format!("{h}.stats.x"),
        format!("{h}.TYPE"),
        format!("{h}.type.x"),
    ];
    let sidecar = "bytes 10\nentries 3\nskipped-devices 0\n";
    let mut planted = Vec::new();
    for name in &lookalikes {
        let layer = root.join("layers/sha256").join(name);
        std::fs::create_dir(&layer).expect("layer");
        std::fs::write(sidecar_of(&layer), sidecar).expect("sidecar");
        let blob = root.join("blobs/sha256").join(name);
        std::fs::write(&blob, b"{}").expect("blob");
        let lock = root.join("locks/sha256").join(name);
        std::fs::write(&lock, b"").expect("lock");
        planted.extend([sidecar_of(&layer), layer, blob, lock]);
    }
    let report = store.trim().expect("trim");
    assert_eq!(report.before, 0, "{report:?}");
    assert_eq!(
        report.removed_layers + report.removed_files,
        0,
        "{report:?}"
    );
    for path in &planted {
        assert!(exists(path), "{} was removed", path.display());
    }
}

/// A symlink or a regular file at a layer's hex name, a directory without
/// a sidecar and one with a sidecar that does not parse are corrupt: every
/// pull of them would fail. The trim removes them and their sidecars
/// under the layer's lock, whatever the budget; the symlink's target is
/// untouched.
#[test]
fn corrupt_layer_entry_removed_target_untouched() {
    let tmp = TempDir::new("corrupt");
    let root = tmp.path().join("store");
    let store = open(&root, &no_requests());
    let layers = root.join("layers/sha256");
    let target = tmp.path().join("target");
    std::fs::create_dir(&target).expect("target");
    std::fs::write(target.join("precious"), b"keep\n").expect("precious");
    let sidecar = "bytes 10\nentries 3\nskipped-devices 0\n";
    let link = layers.join(hex_of(1));
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    std::fs::write(sidecar_of(&link), sidecar).expect("sidecar");
    let file = layers.join(hex_of(2));
    std::fs::write(&file, b"not a layer").expect("file");
    std::fs::write(sidecar_of(&file), sidecar).expect("sidecar");
    let bare = layers.join(hex_of(3));
    std::fs::create_dir(&bare).expect("bare");
    let garbled = layers.join(hex_of(4));
    std::fs::create_dir(&garbled).expect("garbled");
    std::fs::write(sidecar_of(&garbled), b"bytes ten\n").expect("sidecar");
    let report = store.trim().expect("trim");
    assert_eq!(report.removed_layers, 4, "{report:?}");
    assert_eq!(report.before, 0, "a corrupt entry was counted");
    for path in [&link, &file, &bare, &garbled] {
        assert!(!exists(path), "{} stayed", path.display());
        assert!(
            !exists(&sidecar_of(path)),
            "{}'s sidecar stayed",
            path.display()
        );
    }
    assert_eq!(
        std::fs::read(target.join("precious")).expect("the target"),
        b"keep\n"
    );
    assert_eq!(dot_names(&root), Vec::<String>::new());
    assert!(names_in(&root.join("locks/sha256")).is_empty());
}

/// A sidecar without its layer, while a pull holds the layer's pin (as
/// between the two renames of a commit), stays; once the pin is released
/// the next trim removes it and the lock file.
#[test]
fn orphan_sidecar_spared_under_pull() {
    let tmp = TempDir::new("orphan-sidecar");
    let root = tmp.path().join("store");
    let store = open(&root, &no_requests());
    let id = [0x5au8; 32];
    let layer = root.join("layers/sha256").join(hex_of_bytes(&id));
    let sidecar = sidecar_of(&layer);
    std::fs::write(&sidecar, "bytes 10\nentries 3\nskipped-devices 0\n").expect("sidecar");
    let cache = LayerCache::new(&root).expect("cache");
    let pin = cache.pin(&id).expect("pin");
    store.trim().expect("trim");
    assert!(exists(&sidecar), "an orphan sidecar under a pin went");
    drop(pin);
    store.trim().expect("trim");
    assert!(!exists(&sidecar));
    assert!(!exists(&root.join("locks/sha256").join(hex_of_bytes(&id))));
}

/// Lock files of layers that are not in the store: a held one stays, a
/// free one goes; the lock files of committed layers stay.
#[test]
fn orphan_lock_files_removed_when_free() {
    let (hub, pushed, layers) = app_hub();
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("orphan-locks");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let locks = root.join("locks/sha256");
    let held = locks.join(hex_of(1));
    let free = locks.join(hex_of(2));
    for path in [&held, &free] {
        std::fs::write(path, b"").expect("lock");
    }
    let holder = File::open(&held).expect("open");
    holder.lock_shared().expect("lock_shared");
    store.trim().expect("trim");
    assert!(exists(&held), "a held lock file went");
    assert!(!exists(&free), "a free orphan lock file stayed");
    for layer in &layers {
        assert!(
            exists(&locks.join(hex(&layer.diff_id))),
            "a committed layer's lock went"
        );
    }
    drop(holder);
    store.trim().expect("trim");
    assert!(!exists(&held));
}

/// A sidecar that claims `u64::MAX` bytes: the total saturates without a
/// panic, the order is still LRU, and evicting the saturated unit leaves
/// the others counted exactly.
#[test]
fn accounted_sum_saturates() {
    let tmp = TempDir::new("saturate");
    let root = tmp.path().join("store");
    let budget = cost3(100) + cost3(200);
    let store = open_with(&root, &no_requests(), budget);
    let huge = plant_layer(&root, &hex_of(1), u64::MAX, 3, at(1));
    let a = plant_layer(&root, &hex_of(2), 100, 3, at(2));
    let b = plant_layer(&root, &hex_of(3), 200, 3, at(3));
    let report = store.trim().expect("trim");
    assert_eq!(report.before, u64::MAX);
    assert_eq!(report.after, budget);
    assert!(!exists(&huge));
    assert!(exists(&a) && exists(&b));
}

/// A budget of 0 is refused before anything is created.
#[test]
fn zero_budget_refused() {
    let tmp = TempDir::new("zero-budget");
    let root = tmp.path().join("store");
    let mut config = config(&no_requests());
    config.cache_budget = 0;
    match OciImageStore::open(&root, config) {
        Err(Error::InvalidLimits(what)) => assert_eq!(what, "cache budget"),
        other => panic!("a budget of 0: {other:?}"),
    }
    assert!(!exists(&root));
}

/// A budget of 1 keeps only what is in use: the layers of a leased image
/// stay, the other image's layers and every document go.
#[test]
fn budget_one_keeps_only_in_use() {
    let (mut hub, pushed, layers) = app_hub();
    let other = push(&mut hub, "library/other", &[Layer::file("o", b"o\n")], "");
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("budget-one");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let lease = store
        .pull_leased(&image_ref("library/app", &pushed.index))
        .expect("pull");
    store
        .pull(&image_ref("library/other", &other.index))
        .expect("pull");
    let small = open_with(&root, &fake, 1);
    let mut want: Vec<String> = layers
        .iter()
        .flat_map(|l| [hex(&l.diff_id), format!("{}.stats", hex(&l.diff_id))])
        .collect();
    want.sort();
    assert_eq!(names_in(&root.join("layers/sha256")), want);
    assert!(names_in(&root.join("blobs/sha256")).is_empty());
    drop(lease);
    small.trim().expect("trim");
    assert!(names_in(&root.join("layers/sha256")).is_empty());
}

/// The default budget is one largest admissible image with its documents
/// (D8): 21,488,017,408 bytes, and `StoreConfig::new` uses it.
#[test]
fn default_budget_is_one_largest_image() {
    assert_eq!(CACHE_BUDGET_BYTES, 21_488_017_408);
    assert_eq!(BLOCK_ALLOWANCE, 4_096);
    assert_eq!(
        CACHE_BUDGET_BYTES,
        MAX_IMAGE_BYTES
            + BLOCK_ALLOWANCE * (MAX_IMAGE_ENTRIES + MAX_LAYERS as u64)
            + 3 * (MAX_DOCUMENT_BYTES as u64 + MAX_HEAD_BYTES as u64 + 2 * BLOCK_ALLOWANCE)
    );
    let config = StoreConfig::new(Box::new(no_requests())).expect("config");
    assert_eq!(config.cache_budget, CACHE_BUDGET_BYTES);
}

/// Trims of two stores run at once are serialized: both succeed, each
/// layer is removed exactly once, and nothing is left. A trim waits while
/// another holds `locks/trim`, and finishes once it is released.
#[test]
fn concurrent_trims_serialize() {
    let tmp = TempDir::new("concurrent-trims");
    let root = tmp.path().join("store");
    let a = open_with(&root, &no_requests(), 1);
    let b = open_with(&root, &no_requests(), 1);
    for i in 0..40 {
        plant_layer(&root, &hex_of(i + 1), 10, 3, at(i));
    }
    let (ra, rb) = std::thread::scope(|s| {
        let ta = s.spawn(|| a.trim());
        let tb = s.spawn(|| b.trim());
        (ta.join().expect("a"), tb.join().expect("b"))
    });
    let (ra, rb) = (ra.expect("a's trim"), rb.expect("b's trim"));
    assert_eq!(ra.removed_layers + rb.removed_layers, 40, "{ra:?} {rb:?}");
    assert!(names_in(&root.join("layers/sha256")).is_empty());
    assert!(names_in(&root.join("locks/sha256")).is_empty());

    plant_layer(&root, &hex_of(99), 10, 3, at(1));
    let trim_lock = File::open(root.join("locks/trim")).expect("the trim lock");
    trim_lock.lock().expect("hold the trim lock");
    std::thread::scope(|s| {
        let (tx, rx) = mpsc::channel();
        s.spawn(move || {
            let _ = tx.send(a.trim());
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(500)).is_err(),
            "a trim ran while another held the trim lock"
        );
        trim_lock.unlock().expect("release");
        let report = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the trim ran once released")
            .expect("trim");
        assert_eq!(report.removed_layers, 1);
    });
}

/// A store reopened with a lower budget is trimmed at `open` (D6).
#[test]
fn open_trims_to_a_lowered_budget() {
    let (hub, pushed, _) = app_hub();
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("lowered");
    let root = tmp.path().join("store");
    open(&root, &fake)
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    assert_eq!(names_in(&root.join("layers/sha256")).len(), 6);
    drop(open_with(&root, &fake, 1));
    assert!(names_in(&root.join("layers/sha256")).is_empty());
}

/// A failed pull trims too, before its pins drop: an unrelated layer goes,
/// and the layer the failed pull committed stays for the retry.
#[test]
fn failed_pull_trims() {
    let mut hub = Hub::default();
    let (broken, _) = broken_image(&mut hub);
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("failed-trims");
    let root = tmp.path().join("store");
    let store = open_with(&root, &fake, 1);
    let unrelated = plant_layer(&root, &hex_of(1), 10, 3, at(1));
    assert!(
        store
            .pull(&image_ref("library/broken", &broken.index))
            .is_err()
    );
    assert!(!exists(&unrelated), "a failed pull did not trim");
    let ok = Layer::file("ok", b"ok\n");
    let committed = root.join("layers/sha256").join(hex(&ok.diff_id));
    assert!(
        exists(&committed) && exists(&sidecar_of(&committed)),
        "the failed pull's committed layer was evicted under its pin"
    );
    assert!(!is_held(&root.join("locks/sha256").join(hex(&ok.diff_id))));
}
