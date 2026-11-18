//! Shared helpers of the `boneli-store-fs` tests.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::SystemTime;

use boneli_app::{EventStore, Evidence, EvidenceError, RunLog, RunStart, StoreError};
use boneli_domain::{Budget, EvidenceRef, RunEvent, RunId};
use boneli_https::Sha256;
use boneli_store_fs::FsStore;

/// A directory under `CARGO_TARGET_TMPDIR`, unique per process and call,
/// removed on drop even when a test left directories without `u+w`.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates `<CARGO_TARGET_TMPDIR>/store-fs-<tag>-<pid>-<counter>` and
    /// returns it resolved: a relative `CARGO_TARGET_DIR` such as
    /// `../target` puts `..` into `CARGO_TARGET_TMPDIR`, and `open` refuses
    /// a root with dot components (ADR-012 D1).
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("store-fs-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create the test's temp dir");
        let path = path.canonicalize().expect("resolve the test's temp dir");
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
/// a test can remove it.
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

/// A store on its own temporary root; the store is dropped first, so its
/// lock is released before the directory goes.
pub struct Fresh {
    pub store: FsStore,
    _dir: TempDir,
}

impl Fresh {
    pub fn new(tag: &str) -> Fresh {
        let dir = TempDir::new(tag);
        let store = FsStore::open(&dir.path().join("store")).expect("open a fresh store");
        Fresh { store, _dir: dir }
    }
}

impl EventStore for Fresh {
    fn create(&self, id: &RunId, start: &RunStart) -> Result<(), StoreError> {
        self.store.create(id, start)
    }
    fn append(&self, id: &RunId, event: &RunEvent) -> Result<(), StoreError> {
        self.store.append(id, event)
    }
    fn load(&self, id: &RunId) -> Result<RunLog, StoreError> {
        self.store.load(id)
    }
}

impl Evidence for Fresh {
    fn put(&self, content: &[u8]) -> Result<EvidenceRef, EvidenceError> {
        self.store.put(content)
    }
    fn get(&self, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError> {
        self.store.get(reference)
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The SHA-256 of `bytes` in lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Where ADR-012 D2 puts a run's log, derived here independently of the
/// crate.
pub fn log_path(root: &Path, id: &RunId) -> PathBuf {
    root.join("runs")
        .join(format!("{}.log", sha256_hex(id.as_str().as_bytes())))
}

/// Where ADR-012 D2 puts a blob.
pub fn blob_path(root: &Path, reference: &EvidenceRef) -> PathBuf {
    let hex = reference
        .as_str()
        .strip_prefix("sha256:")
        .expect("a reference this store issued");
    root.join("evidence").join("sha256").join(hex)
}

pub fn id(text: &str) -> RunId {
    RunId::new(text.to_owned())
}

pub fn start() -> RunStart {
    RunStart {
        budget: Budget {
            cost_micro_usd: 1_000_000,
            duration_ms: 600_000,
        },
        previous: None,
    }
}

pub fn marker(n: usize) -> RunEvent {
    RunEvent::QuestionsPosted {
        reference: format!("event-{n}"),
    }
}

/// Every file under `root` (not following symlinks) with its bytes and
/// modification time; directories are listed with no bytes.
pub fn snapshot(root: &Path) -> BTreeMap<PathBuf, (Option<Vec<u8>>, SystemTime)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("list") {
            let path = entry.expect("entry").path();
            let meta = std::fs::symlink_metadata(&path).expect("stat");
            let mtime = meta.modified().expect("mtime");
            if meta.is_dir() {
                stack.push(path.clone());
                out.insert(path, (None, mtime));
            } else if meta.is_file() {
                let bytes = std::fs::read(&path).expect("read");
                out.insert(path, (Some(bytes), mtime));
            } else {
                out.insert(path, (None, mtime));
            }
        }
    }
    out
}

/// The names in `dir`, sorted.
pub fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Appends raw bytes to a file behind the store's back.
pub fn append_raw(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open for append");
    file.write_all(bytes).expect("append raw");
}

/// The detail of an `Unavailable` store error.
pub fn unavailable_detail<T: std::fmt::Debug>(result: Result<T, StoreError>) -> String {
    match result {
        Err(StoreError::Unavailable { detail }) => detail,
        other => panic!("expected Unavailable, got {other:?}"),
    }
}
