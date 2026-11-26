//! A fake TUF repository for the refresh tests: a `Dial` that answers
//! each connection on its own thread over `UnixStream::pair`, so the
//! client's HTTP framing and its deadline wrapper are the real code
//! (modeled on `boneli-oci`'s `tests/support/registry.rs`). It serves
//! files by path, answers a path it does not hold with `404`, and lets a
//! test replace the answer for one path with a status, raw bytes or a
//! trickle. Every dial and every request is recorded.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use boneli_http::{Headers, RequestHead, ResponseHead, Target};
use boneli_https::{Dial, Sha256, Stream};
use boneli_tuf::{InitialRoot, Repository};

use super::real;
use super::repo::{
    self, MetaSpec, RootBuilder, SnapshotBuilder, TargetsBuilder, TimestampBuilder, hex,
};

/// The host of the fake repository.
pub const HOST: &str = "tuf.example";
/// Its URL: a prefix, so every target the client asks for carries it.
pub const URL: &str = "https://tuf.example/repo";
/// The prefix of every path the client asks for.
pub const PREFIX: &str = "/repo/";

/// One request as the fake saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    /// The host the client dialed.
    pub host: String,
    /// The port the client dialed.
    pub port: u16,
    /// The origin-form target.
    pub target: String,
    /// The header fields, in order.
    pub headers: Vec<(String, String)>,
}

/// How the fake answers one path.
#[derive(Clone, Debug)]
pub enum Reply {
    /// `status` with these fields and `body`, framed by `Content-Length`.
    Http {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// These bytes, as they are, then the stream stays open for `hold`.
    Raw { bytes: Vec<u8>, hold: Duration },
    /// `head` at once, then each chunk after `delay`.
    Trickle {
        head: Vec<u8>,
        chunks: Vec<Vec<u8>>,
        delay: Duration,
    },
}

impl Reply {
    /// `status` with `body` and these fields.
    pub fn http(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        Reply::Http {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.to_vec(),
        }
    }

    /// `status` with no body.
    pub fn status(status: u16) -> Reply {
        Reply::http(status, &[], b"")
    }
}

/// The fake: its files, the answers that replace them, and the logs.
#[derive(Clone, Default)]
pub struct Server {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    replies: Arc<Mutex<BTreeMap<String, Reply>>>,
    log: Arc<Mutex<Vec<Seen>>>,
    dials: Arc<Mutex<Vec<(String, u16)>>>,
}

impl Server {
    pub fn new() -> Server {
        Server::default()
    }

    /// Serves `bytes` at `name` under the prefix.
    pub fn put(&self, name: &str, bytes: &[u8]) {
        self.files
            .lock()
            .expect("files")
            .insert(format!("{PREFIX}{name}"), bytes.to_vec());
    }

    /// Stops serving `name`: it answers `404` again.
    pub fn remove(&self, name: &str) {
        self.files
            .lock()
            .expect("files")
            .remove(&format!("{PREFIX}{name}"));
    }

    /// Answers `name` with `reply` instead of its file.
    pub fn answer(&self, name: &str, reply: Reply) {
        self.replies
            .lock()
            .expect("replies")
            .insert(format!("{PREFIX}{name}"), reply);
    }

    /// Answers `name` with its file again.
    pub fn unanswer(&self, name: &str) {
        self.replies
            .lock()
            .expect("replies")
            .remove(&format!("{PREFIX}{name}"));
    }

    /// Every request seen so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.log.lock().expect("log").clone()
    }

    /// The targets of every request seen so far, without the prefix.
    pub fn requested(&self) -> Vec<String> {
        self.seen()
            .into_iter()
            .map(|s| {
                s.target
                    .strip_prefix(PREFIX)
                    .map_or(s.target.clone(), str::to_owned)
            })
            .collect()
    }

    /// Every dial so far, a request or not.
    pub fn dials(&self) -> Vec<(String, u16)> {
        self.dials.lock().expect("dials").clone()
    }

    /// Forgets the requests and dials seen so far.
    pub fn clear_log(&self) {
        self.log.lock().expect("log").clear();
        self.dials.lock().expect("dials").clear();
    }

    fn reply(&self, target: &str) -> Reply {
        if let Some(reply) = self.replies.lock().expect("replies").get(target) {
            return reply.clone();
        }
        match self.files.lock().expect("files").get(target) {
            Some(bytes) => Reply::http(200, &[], bytes),
            None => Reply::http(404, &[], b"<?xml version='1.0'?><Error>NoSuchKey</Error>"),
        }
    }
}

impl Dial for Server {
    fn dial(&self, host: &str, port: u16, _deadline: Instant) -> io::Result<Box<dyn Stream>> {
        self.dials
            .lock()
            .expect("dials")
            .push((host.to_owned(), port));
        let (client, server) = UnixStream::pair()?;
        let this = self.clone();
        let host = host.to_owned();
        thread::spawn(move || serve(server, host, port, &this));
        Ok(Box::new(client))
    }
}

fn serve(mut stream: UnixStream, host: String, port: u16, server: &Server) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) if bytes.len() < 1 << 16 => bytes.push(byte[0]),
            _ => return,
        }
    }
    let limits = boneli_http::Limits::new(1 << 16, 256, 1).expect("limits");
    let head = RequestHead::parse(&bytes, &limits).expect("the client sent a valid head");
    let Target::Origin(target) = head.target else {
        panic!("the client sent a non-origin target");
    };
    let seen = Seen {
        host,
        port,
        target: target.clone(),
        headers: head
            .headers
            .iter()
            .map(|(n, v)| (n.to_owned(), String::from_utf8_lossy(v).into_owned()))
            .collect(),
    };
    server.log.lock().expect("log").push(seen);
    match server.reply(&target) {
        Reply::Http {
            status,
            headers,
            body,
        } => {
            let mut response = ResponseHead::new(status);
            let mut fields = Headers::new();
            for (n, v) in headers {
                fields.append(n, v);
            }
            fields.append("Content-Length", body.len().to_string());
            response.headers = fields;
            let mut out = response.encode().expect("encode");
            out.extend_from_slice(&body);
            let _ = stream.write_all(&out);
        }
        Reply::Raw { bytes, hold } => {
            let _ = stream.write_all(&bytes);
            thread::sleep(hold);
        }
        Reply::Trickle {
            head,
            chunks,
            delay,
        } => {
            let _ = stream.write_all(&head);
            for chunk in chunks {
                thread::sleep(delay);
                if stream.write_all(&chunk).is_err() {
                    return;
                }
            }
        }
    }
}

/// The fake's repository URL, parsed.
pub fn repository() -> Repository {
    Repository::parse(URL).expect("the fake's URL")
}

/// The SHA-256 of `bytes` in lower-case hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// `bytes` as the initial root, pinned by its own SHA-256.
pub fn pinned(bytes: &[u8]) -> InitialRoot {
    InitialRoot::new(bytes.to_vec(), &sha256_hex(bytes)).expect("a pinnable root")
}

/// A second `trusted_root.json` that `TrustedRoot::from_json` reads: the
/// real one with a trailing line feed, so its SHA-256 differs.
pub fn trusted_root_v2() -> Vec<u8> {
    let mut bytes = real::TRUSTED_ROOT.to_vec();
    bytes.push(b'\n');
    bytes
}

/// What one publication of the fake repository consists of.
pub struct Published {
    pub timestamp: Vec<u8>,
    pub snapshot: Vec<u8>,
    pub targets: Vec<u8>,
    pub target: Vec<u8>,
}

/// Publishes version `v` of timestamp, snapshot and targets under the
/// default root, with `target` as `trusted_root.json`: snapshot and
/// targets named by version only, as Sigstore writes them, and the target
/// at its consistent-snapshot path. Replaces what was published before.
pub fn publish(server: &Server, v: i64, target: &[u8]) -> Published {
    let mut targets = TargetsBuilder::new(v);
    targets.targets = vec![(repo::TARGET_NAME.to_string(), repo::target_entry(target))];
    publish_with(server, v, &targets, target)
}

/// [`publish`] with a targets document of the caller's.
pub fn publish_with(server: &Server, v: i64, targets: &TargetsBuilder, target: &[u8]) -> Published {
    let targets = targets.bytes();
    let snapshot = SnapshotBuilder::new(v, MetaSpec::version(v)).bytes();
    let timestamp = TimestampBuilder::new(v, MetaSpec::version(v)).bytes();
    server.put("timestamp.json", &timestamp);
    server.put(&format!("{v}.snapshot.json"), &snapshot);
    server.put(&format!("{v}.targets.json"), &targets);
    server.put(
        &format!("targets/{}.trusted_root.json", sha256_hex(target)),
        target,
    );
    Published {
        timestamp,
        snapshot,
        targets,
        target: target.to_vec(),
    }
}

/// The default root at version 1, the tests' initial root.
pub fn root_v1() -> Vec<u8> {
    RootBuilder::new(1).bytes()
}

/// A fresh directory under the system temporary directory, resolved and
/// removed on drop. The trust directory is `trust` in it, so the temporary
/// directory (sticky) and this one (the caller's, not group-writable) are
/// its ancestors and pass ADR-021.
pub struct Scratch(pub std::path::PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("boneli-tuf-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let dir = dir.canonicalize().expect("resolved scratch dir");
        Scratch(dir)
    }

    /// The trust directory.
    pub fn trust(&self) -> std::path::PathBuf {
        self.0.join("trust")
    }

    /// `name` under the trust directory.
    pub fn at(&self, name: &str) -> std::path::PathBuf {
        self.trust().join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        // A test may have left a directory without write permission.
        for dir in [self.0.clone(), self.trust(), self.at("tuf")] {
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One refresh of the trust directory at `dir` from `server`, at the
/// tests' start time, with the default timeouts.
pub fn run(
    server: &Server,
    dir: &std::path::Path,
    initial: &InitialRoot,
) -> Result<boneli_tuf::Outcome, boneli_tuf::RefreshError> {
    run_with(
        server,
        dir,
        initial,
        repo::START,
        boneli_tuf::Timeouts::default(),
    )
}

/// [`run`] at `start_secs` with `timeouts`.
pub fn run_with(
    server: &Server,
    dir: &std::path::Path,
    initial: &InitialRoot,
    start_secs: u64,
    timeouts: boneli_tuf::Timeouts,
) -> Result<boneli_tuf::Outcome, boneli_tuf::RefreshError> {
    let repository = repository();
    boneli_tuf::refresh_trusted_root(&boneli_tuf::Refresh {
        repository: &repository,
        initial_root: initial,
        dir,
        dial: server,
        timeouts,
        start_secs,
    })
}

/// A server publishing version 1 of everything with the real trusted root
/// as the target, and the default root v1 pinned as the initial root.
pub fn fixture() -> (Server, InitialRoot, Published) {
    let server = Server::new();
    let published = publish(&server, 1, real::TRUSTED_ROOT);
    (server, pinned(&root_v1()), published)
}

/// The fixture root of the second trust root (ADR-041): the default root
/// v1 with another `expires`, so another pin over the same test keys.
pub fn github_root_v1() -> Vec<u8> {
    let mut root = RootBuilder::new(1);
    root.expires = "2030-01-02T00:00:00Z".to_string();
    root.bytes()
}

/// A server for the second trust root: version 1 of everything with
/// GitHub's real trusted root as the target, and [`github_root_v1`]
/// pinned as the initial root.
pub fn github_fixture() -> (Server, InitialRoot, Published) {
    let server = Server::new();
    let published = publish(&server, 1, real::GITHUB_TRUSTED_ROOT);
    (server, pinned(&github_root_v1()), published)
}

/// One entry of [`tree`]: the SHA-256 of its bytes (a file's content, a
/// symlink's target, nothing for a directory), its inode and its mtime.
pub type Entry = ([u8; 32], u64, SystemTime);

/// Every entry under `dir`, by path relative to it, recursively and
/// without following a symlink; empty when `dir` is missing. What the
/// "untouched" assertions compare.
pub fn tree(dir: &Path) -> BTreeMap<PathBuf, Entry> {
    fn walk(base: &Path, at: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        let Ok(entries) = fs::read_dir(at) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("an entry").path();
            let meta = fs::symlink_metadata(&path).expect("its metadata");
            let bytes = if meta.is_dir() {
                Vec::new()
            } else if meta.file_type().is_symlink() {
                fs::read_link(&path)
                    .expect("its target")
                    .into_os_string()
                    .into_encoded_bytes()
            } else {
                fs::read(&path).expect("its bytes")
            };
            let rel = path.strip_prefix(base).expect("under base").to_path_buf();
            out.insert(
                rel,
                (
                    Sha256::digest(&bytes),
                    meta.ino(),
                    meta.modified().expect("an mtime"),
                ),
            );
            if meta.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}
