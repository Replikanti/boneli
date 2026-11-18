//! Boneli adapter: the run event log and the evidence store on the
//! filesystem (#4, ADR-012).
//!
//! [`FsStore`] implements the `EventStore` and `Evidence` ports
//! (ADR-004, D1) over one private root:
//!
//! - `runs/<hex>.log`: one append-only log per run, named by the SHA-256 of
//!   the run id, as newline-delimited JSON: a versioned header with the id,
//!   then one line per accepted event, each synced before `append` returns
//!   (ADR-012, D2 to D5).
//! - `evidence/sha256/<hex>`: blobs addressed by their SHA-256; the
//!   reference is `sha256:<hex>`, and `get` hashes the bytes it returns, so
//!   content changed on disk is `Corrupted`, never handed out (ADR-004, D9;
//!   ADR-012, D6).
//! - `lock`: held exclusively for the store's lifetime, so one process owns
//!   the root (ADR-012, D1).
//!
//! The root rules are those of `boneli-oci` (ADR-009, D8), copied rather
//! than shared, because an adapter cannot depend on another adapter;
//! extracting them is #66.
#![doc(test(attr(forbid(unsafe_code))))]

mod codec;
mod evidence;
mod log;
mod root;

use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use boneli_app::{EventStore, Evidence, EvidenceError, RunLog, RunStart, StoreError};
use boneli_domain::{EvidenceRef, RunEvent, RunId};

pub use codec::{MAX_DEPTH, MAX_LINE_BYTES, MAX_VALUES};

/// Why [`FsStore::open`] refused a root.
#[derive(Debug)]
pub enum OpenError {
    /// The root, or one of its ancestors at `path`, breaks a root rule.
    Root {
        /// The path that breaks it.
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
    /// Another store, in this process or another, holds the lock at `path`.
    InUse {
        /// The lock file.
        path: PathBuf,
    },
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Root { path, reason } => {
                write!(f, "store root {}: {reason}", path.display())
            }
            OpenError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            OpenError::InUse { path } => {
                write!(f, "{} is held by another store", path.display())
            }
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OpenError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// The run event log and evidence store on one private root (ADR-012).
///
/// `Send + Sync`: the log operations of one store are serialized by one
/// mutex, evidence operations need none (every write commits by a rename
/// of a file whose name is its digest).
#[derive(Debug)]
pub struct FsStore {
    root: PathBuf,
    /// The exclusive lock on `<root>/lock`, released when the store drops.
    _lock: File,
    log_lock: Mutex<()>,
    next_temp: AtomicU64,
}

impl FsStore {
    /// Opens the store at `root`, creating it `0o700` where it is missing.
    ///
    /// The root must be absolute without a `.` or `..` component, a
    /// directory owned by the caller with no group or other permission
    /// bits, and its ancestors must pass sshd's `StrictModes` rule; a
    /// symlinked root is resolved first. `open` takes
    /// the exclusive lock (`InUse` while another store holds it), removes
    /// the temporary files a crashed store left, and syncs the directories
    /// (ADR-012, D1).
    pub fn open(root: &Path) -> Result<FsStore, OpenError> {
        let (root, lock) = root::open(root)?;
        Ok(FsStore {
            root,
            _lock: lock,
            log_lock: Mutex::new(()),
            next_temp: AtomicU64::new(0),
        })
    }

    /// The resolved root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A temporary name for `dir`, unique within the store: the lock makes
    /// the store the root's only writer, so a counter suffices.
    fn temp_path(&self, dir: &Path) -> PathBuf {
        let n = self.next_temp.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("{}{n}", root::TEMP_PREFIX))
    }
}

impl EventStore for FsStore {
    fn create(&self, id: &RunId, start: &RunStart) -> Result<(), StoreError> {
        log::create(self, id, start)
    }

    fn append(&self, id: &RunId, event: &RunEvent) -> Result<(), StoreError> {
        log::append(self, id, event)
    }

    fn load(&self, id: &RunId) -> Result<RunLog, StoreError> {
        log::load(self, id)
    }
}

impl Evidence for FsStore {
    fn put(&self, content: &[u8]) -> Result<EvidenceRef, EvidenceError> {
        evidence::put(self, content)
    }

    fn get(&self, reference: &EvidenceRef) -> Result<Vec<u8>, EvidenceError> {
        evidence::get(self, reference)
    }
}

/// What [`open_regular`] found at a path.
enum Regular {
    /// A regular file, opened, with its `fstat`.
    File(File, std::fs::Metadata),
    /// Nothing.
    Missing,
    /// A symlink, directory, FIFO, socket or device, which is never opened
    /// (a FIFO would block the open, a device could be read forever), or a
    /// file swapped between the check and the open.
    Other,
    /// The filesystem failed.
    Failed(io::Error),
}

/// Opens `path` with `options` only if it is a regular file: checked with
/// `symlink_metadata` before the open, and the descriptor's `fstat` must
/// show a regular file with the same device and inode (ADR-012, D6).
fn open_regular(path: &Path, options: &std::fs::OpenOptions) -> Regular {
    use std::os::unix::fs::MetadataExt;
    let before = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Regular::Missing,
        Err(e) => return Regular::Failed(e),
    };
    if !before.is_file() {
        return Regular::Other;
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Regular::Missing,
        Err(e) => return Regular::Failed(e),
    };
    match file.metadata() {
        Ok(meta) if meta.is_file() && meta.dev() == before.dev() && meta.ino() == before.ino() => {
            Regular::File(file, meta)
        }
        Ok(_) => Regular::Other,
        Err(e) => Regular::Failed(e),
    }
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store on a fresh directory under the system temporary directory,
    /// removed on drop.
    struct Scratch {
        store: Option<FsStore>,
        dir: PathBuf,
    }

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir()
                .join(format!("boneli-store-fs-unit-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch dir");
            let store = FsStore::open(&dir.join("store")).expect("open");
            Scratch {
                store: Some(store),
                dir,
            }
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            self.store = None;
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn store_is_send_and_sync() {
        assert_send_sync::<FsStore>();
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex(&[]), "");
    }

    /// A thread that panics while it holds the log mutex poisons it; the
    /// next append recovers it (ADR-004, D8) and succeeds, because disk
    /// state commits only through `hard_link`, `sync_data` and rename.
    #[test]
    fn poisoned_lock_recovers() {
        let scratch = Scratch::new("poison");
        let store = scratch.store.as_ref().expect("store");
        let run = RunId::new(String::from("run-1"));
        let start = RunStart {
            budget: boneli_domain::Budget {
                cost_micro_usd: 1,
                duration_ms: 1,
            },
            previous: None,
        };
        store.create(&run, &start).expect("create");
        std::thread::scope(|scope| {
            let poisoner = scope.spawn(|| {
                let _held = store.log_lock.lock();
                panic!("poison the log lock");
            });
            assert!(poisoner.join().is_err());
        });
        assert!(store.log_lock.is_poisoned());
        let event = RunEvent::QuestionsPosted {
            reference: String::from("comment/1"),
        };
        store.append(&run, &event).expect("append after the poison");
        assert_eq!(
            store.load(&run),
            Ok(RunLog {
                start,
                events: vec![event],
            })
        );
    }
}
