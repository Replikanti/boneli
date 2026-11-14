//! Helpers shared by the I/O tests of the egress (ADR-006): a recording log
//! sink that can fail on purpose, a scripted upstream that hands the test
//! the origin end of every tunnel, a proxy on a fresh Unix socket, and
//! client helpers with deadlines, so that a hang fails a test instead of
//! stalling it.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use boneli_egress::address::Nat64Prefix;
use boneli_egress::log::Record;
use boneli_egress::{Allowlist, Config, Egress, LogSink, RelayStream, Settings, Upstream};
use boneli_http::{Limits, ServerLimits};
use boneli_memory::StepClock;

/// How long any blocking step of a test may take before it fails.
pub const DEADLINE: Duration = Duration::from_secs(5);

pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A log sink that keeps every line. With `fail_at = Some(n)`, the n-th
/// append (one-based) and every later one fail and keep nothing.
#[derive(Default)]
pub struct MemSink {
    lines: Mutex<Vec<String>>,
    fail_at: Option<usize>,
    appends: AtomicUsize,
}

impl MemSink {
    pub fn new() -> MemSink {
        MemSink::default()
    }

    pub fn failing_at(n: usize) -> MemSink {
        MemSink {
            fail_at: Some(n),
            ..MemSink::default()
        }
    }

    /// The lines appended so far.
    pub fn lines(&self) -> Vec<String> {
        lock(&self.lines).clone()
    }

    /// The lines as records; every line must end in exactly one newline
    /// and parse.
    pub fn records(&self) -> Vec<Record> {
        self.lines()
            .iter()
            .map(|line| {
                let body = line.strip_suffix('\n').expect("a line ends in a newline");
                assert!(!body.contains('\n'), "one record per line: {line:?}");
                Record::parse(body).unwrap_or_else(|e| panic!("{line:?}: {e}"))
            })
            .collect()
    }

    /// Polls until `done` holds for the records, or fails after the
    /// deadline.
    pub fn wait_for(&self, what: &str, done: impl Fn(&[Record]) -> bool) -> Vec<Record> {
        let start = Instant::now();
        loop {
            let records = self.records();
            if done(&records) {
                return records;
            }
            assert!(
                start.elapsed() < DEADLINE,
                "waited for {what}; log: {:?}",
                self.lines()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Polls until `n` terminal records are in the log.
    pub fn wait_terminal(&self, n: usize) -> Vec<Record> {
        self.wait_for(&format!("{n} terminal records"), |records| {
            records.iter().filter(|r| r.is_terminal()).count() >= n
        })
    }
}

impl LogSink for MemSink {
    fn append(&self, line: &str) -> io::Result<()> {
        let n = self.appends.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_at.is_some_and(|at| n >= at) {
            return Err(io::Error::other("sink failure on purpose"));
        }
        lock(&self.lines).push(line.to_owned());
        Ok(())
    }
}

/// What the fake does when asked to connect to an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Connect {
    /// Succeeds: one end of a socket pair goes to the egress, the other to
    /// the test's origin channel.
    Origin,
    /// Fails at once with `ConnectionRefused`.
    Refuse,
    /// Sleeps for the timeout it gets, then fails with `TimedOut`.
    Blackhole,
    /// Fails at once with `TimedOut`, as a blackholed address would after
    /// its timeout, without the wait.
    TimedOutNow,
}

/// One call the egress made on the upstream, with the log as it stood at
/// the moment of the call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Resolve {
        host: String,
        port: u16,
        log: Vec<String>,
    },
    Connect {
        addr: SocketAddr,
        timeout: Duration,
        log: Vec<String>,
    },
}

/// A scripted upstream. Names not in `answers` fail to resolve; addresses
/// not in `connects` behave as `Connect::Origin`.
pub struct FakeUpstream {
    answers: BTreeMap<String, Result<Vec<SocketAddr>, ErrorKind>>,
    connects: BTreeMap<SocketAddr, Connect>,
    calls: Mutex<Vec<Call>>,
    origins: Mutex<Sender<UnixStream>>,
    witness: Mutex<Option<Arc<MemSink>>>,
    gate: Mutex<Option<Receiver<()>>>,
}

impl FakeUpstream {
    /// A fake and the receiver of the origin end of every tunnel.
    pub fn new() -> (FakeUpstream, Receiver<UnixStream>) {
        let (tx, rx) = mpsc::channel();
        let fake = FakeUpstream {
            answers: BTreeMap::new(),
            connects: BTreeMap::new(),
            calls: Mutex::new(Vec::new()),
            origins: Mutex::new(tx),
            witness: Mutex::new(None),
            gate: Mutex::new(None),
        };
        (fake, rx)
    }

    pub fn answer(mut self, host: &str, addrs: &[&str]) -> FakeUpstream {
        let addrs = addrs
            .iter()
            .map(|a| a.parse().expect("socket address"))
            .collect();
        self.answers.insert(host.to_owned(), Ok(addrs));
        self
    }

    pub fn answer_error(mut self, host: &str, kind: ErrorKind) -> FakeUpstream {
        self.answers.insert(host.to_owned(), Err(kind));
        self
    }

    pub fn connect_as(mut self, addr: &str, behaviour: Connect) -> FakeUpstream {
        self.connects
            .insert(addr.parse().expect("socket address"), behaviour);
        self
    }

    /// Every connect waits for one message on `gate` before it proceeds.
    pub fn gated(self, gate: Receiver<()>) -> FakeUpstream {
        *lock(&self.gate) = Some(gate);
        self
    }

    /// Snapshots `sink` into every recorded call.
    pub fn witness(&self, sink: Arc<MemSink>) {
        *lock(&self.witness) = Some(sink);
    }

    pub fn calls(&self) -> Vec<Call> {
        lock(&self.calls).clone()
    }

    pub fn resolves(&self) -> usize {
        self.calls()
            .iter()
            .filter(|c| matches!(c, Call::Resolve { .. }))
            .count()
    }

    pub fn connect_calls(&self) -> Vec<(SocketAddr, Duration)> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Connect { addr, timeout, .. } => Some((addr, timeout)),
                Call::Resolve { .. } => None,
            })
            .collect()
    }

    fn log(&self) -> Vec<String> {
        lock(&self.witness)
            .as_ref()
            .map(|sink| sink.lines())
            .unwrap_or_default()
    }
}

impl Upstream for FakeUpstream {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let log = self.log();
        lock(&self.calls).push(Call::Resolve {
            host: host.to_owned(),
            port,
            log,
        });
        match self.answers.get(host) {
            Some(Ok(addrs)) => Ok(addrs
                .iter()
                .map(|a| SocketAddr::new(a.ip(), port))
                .collect()),
            Some(Err(kind)) => Err(io::Error::from(*kind)),
            None => Err(io::Error::other("no such name in the script")),
        }
    }

    fn connect(&self, addr: SocketAddr, timeout: Duration) -> io::Result<Box<dyn RelayStream>> {
        let log = self.log();
        lock(&self.calls).push(Call::Connect { addr, timeout, log });
        if let Some(gate) = lock(&self.gate).as_ref() {
            gate.recv_timeout(DEADLINE)
                .map_err(|_| io::Error::other("gate never opened"))?;
        }
        match self.connects.get(&addr).copied().unwrap_or(Connect::Origin) {
            Connect::Origin => {
                let (ours, theirs) = UnixStream::pair()?;
                theirs.set_read_timeout(Some(DEADLINE))?;
                theirs.set_write_timeout(Some(DEADLINE))?;
                lock(&self.origins)
                    .send(theirs)
                    .map_err(|_| io::Error::other("test gone"))?;
                Ok(Box::new(ours))
            }
            Connect::Refuse => Err(io::Error::from(ErrorKind::ConnectionRefused)),
            Connect::Blackhole => {
                thread::sleep(timeout);
                Err(io::Error::from(ErrorKind::TimedOut))
            }
            Connect::TimedOutNow => Err(io::Error::from(ErrorKind::TimedOut)),
        }
    }
}

/// A Unix socket path under the temp directory, unique per process and
/// call. Removed when the returned guard drops.
pub fn socket_path() -> SocketFile {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    SocketFile(std::env::temp_dir().join(format!(
        "boneli-egress-{}-{}.sock",
        std::process::id(),
        n
    )))
}

/// Removes the socket file when dropped.
pub struct SocketFile(pub PathBuf);

impl Drop for SocketFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Server limits as in production except for the given counts and times.
pub fn server_limits(max_connections: usize, request: Duration) -> ServerLimits {
    let http = Limits::new(8192, 32, 1).expect("limits");
    ServerLimits::new(http, max_connections, DEADLINE, request, DEADLINE).expect("limits")
}

/// Settings for tests: production message limits, 32 connections, 5 s
/// server timeouts, 1 s per connect attempt out of 3 s, a 5 s idle tunnel
/// timeout and the production buffer.
pub fn test_settings() -> Settings {
    Settings::new(
        server_limits(32, DEADLINE),
        Duration::from_secs(1),
        Duration::from_secs(3),
        DEADLINE,
        16 * 1024,
    )
    .expect("settings")
}

/// A proxy under test.
pub struct Proxy {
    pub socket: SocketFile,
    pub sink: Arc<MemSink>,
    pub upstream: Arc<FakeUpstream>,
    pub log_failures: Arc<AtomicUsize>,
}

/// Starts `Egress::serve` on a fresh socket in a thread, with a step
/// clock (start 0, step 1) and no start record.
pub fn spawn_proxy(
    allow: &[&str],
    upstream: FakeUpstream,
    sink: MemSink,
    settings: Settings,
) -> Proxy {
    spawn_proxy_nat64(allow, &[], upstream, sink, settings)
}

pub fn spawn_proxy_nat64(
    allow: &[&str],
    nat64: &[&str],
    upstream: FakeUpstream,
    sink: MemSink,
    settings: Settings,
) -> Proxy {
    let socket = socket_path();
    let listener = UnixListener::bind(&socket.0).expect("bind");
    let sink = Arc::new(sink);
    let upstream = Arc::new(upstream);
    let log_failures = Arc::new(AtomicUsize::new(0));
    let failures = Arc::clone(&log_failures);
    let config = Config {
        allowlist: Allowlist::parse(allow).expect("allowlist"),
        nat64: nat64
            .iter()
            .map(|p| Nat64Prefix::parse(p).expect("prefix"))
            .collect(),
        upstream: Arc::clone(&upstream) as Arc<dyn Upstream>,
        sink: Arc::clone(&sink) as Arc<dyn LogSink>,
        clock: Box::new(StepClock::new(0, 1)),
        settings,
        on_log_failure: Box::new(move || {
            failures.fetch_add(1, Ordering::SeqCst);
        }),
    };
    let egress = Egress::new(config);
    thread::spawn(move || egress.serve(listener));
    Proxy {
        socket,
        sink,
        upstream,
        log_failures,
    }
}

impl Proxy {
    /// A client connected to the proxy, with 5 s timeouts.
    pub fn client(&self) -> UnixStream {
        let client = UnixStream::connect(&self.socket.0).expect("connect");
        client.set_read_timeout(Some(DEADLINE)).expect("timeout");
        client.set_write_timeout(Some(DEADLINE)).expect("timeout");
        client
    }
}

/// `CONNECT host:port` with a matching `Host`.
pub fn connect_head(authority: &str) -> Vec<u8> {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").into_bytes()
}

/// Reads until a full response head has arrived.
pub fn read_head(stream: &mut impl Read) -> String {
    let mut got = Vec::new();
    let mut byte = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).expect("read response head");
        assert_ne!(n, 0, "closed after {:?}", String::from_utf8_lossy(&got));
        got.push(byte[0]);
    }
    String::from_utf8_lossy(&got).into_owned()
}

/// Reads to the end of the stream; a reset after the peer closed counts as
/// the end (a Unix socket reports unread input of ours that way).
pub fn read_to_close(stream: &mut impl Read) -> Vec<u8> {
    let mut rest = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return rest,
            Ok(n) => rest.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => return rest,
            Err(e) => panic!("read to close: {e:?} after {rest:?}"),
        }
    }
}

/// The status code of a response head.
pub fn status(head: &str) -> u16 {
    head.get(9..12)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status in {head:?}"))
}

/// Receives the next origin stream the fake handed out.
pub fn next_origin(origins: &Receiver<UnixStream>) -> UnixStream {
    origins.recv_timeout(DEADLINE).expect("an upstream connect")
}

/// Joins `handle` or fails after the deadline.
pub fn join<T: Send + 'static>(handle: thread::JoinHandle<T>) -> T {
    let start = Instant::now();
    while !handle.is_finished() {
        assert!(start.elapsed() < DEADLINE, "thread did not finish in time");
        thread::sleep(Duration::from_millis(5));
    }
    handle.join().expect("no panic")
}

/// The records of connection `id`.
pub fn of(records: &[Record], id: u64) -> Vec<Record> {
    records
        .iter()
        .filter(|r| r.id() == Some(id))
        .cloned()
        .collect()
}

/// The kinds of the records of connection `id`, in order.
pub fn kinds(records: &[Record], id: u64) -> Vec<&'static str> {
    of(records, id).iter().map(Record::kind).collect()
}

/// A TCP listener on loopback that the binary tests use as a would-be
/// target.
pub fn loopback_listener() -> std::net::TcpListener {
    std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback")
}

/// Writes all of `bytes` and keeps the stream for later use.
pub fn send(stream: &mut impl Write, bytes: &[u8]) {
    stream.write_all(bytes).expect("send");
    stream.flush().expect("flush");
}
