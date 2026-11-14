//! The `boneli-egress` binary: exit codes, binding without touching what is
//! already at the path, the log on stdout, and the address policy against
//! a real resolver (ADR-006, D1, D4, D8).
//!
//! The tests that start the egress need a working resolver: startup
//! resolves `ipv4only.arpa` for NAT64 discovery (D4) and exits 1 without
//! an answer. `localhost` comes from the hosts file. Only
//! `live_registry_tunnel_opens` connects to the internet; it is ignored by
//! default and run once by QA.

mod common;

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use boneli_egress::log::{FailReason, Record};
use boneli_http::Limits;
use common::{DEADLINE, connect_head, read_head, send, socket_path, status};

const BIN: &str = env!("CARGO_BIN_EXE_boneli-egress");

/// How long the binary may take to start or exit: startup resolves
/// `ipv4only.arpa`, which can take as long as the resolver's own timeouts.
const STARTUP: Duration = Duration::from_secs(40);

/// Kills the child when dropped.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits for the child to exit, or fails after `STARTUP`.
fn exit_code(child: &mut Child) -> i32 {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            return status.code().expect("exited, not killed");
        }
        assert!(start.elapsed() < STARTUP, "the binary did not exit");
        thread::sleep(Duration::from_millis(10));
    }
}

fn run(args: &[&str], stdout: Stdio) -> (i32, String) {
    let child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut running = Running(child);
    let code = exit_code(&mut running.0);
    let mut stderr = String::new();
    if let Some(mut pipe) = running.0.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut pipe, &mut stderr);
    }
    (code, stderr)
}

/// Starts the binary with its stdout piped; returns it and a receiver of
/// its log lines.
fn start(args: &[&str]) -> (Running, Receiver<String>) {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    (Running(child), rx)
}

fn next_record(lines: &Receiver<String>, within: Duration) -> Record {
    let line = lines.recv_timeout(within).expect("a log line");
    Record::parse(&line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
}

#[test]
fn binary_usage_errors_exit_2() {
    let socket = socket_path();
    let path = socket.0.to_str().expect("utf-8 temp dir").to_owned();
    let p = path.as_str();
    let cases: &[&[&str]] = &[
        &["--allow", "registry.npmjs.org:443"],
        &[
            "--socket",
            p,
            "--socket",
            p,
            "--allow",
            "registry.npmjs.org:443",
        ],
        &["--socket", p],
        &["--socket", p, "--allow=registry.npmjs.org:443"],
        &[
            "--socket",
            p,
            "--allow",
            "registry.npmjs.org:443",
            "--verbose",
        ],
        &["--socket", p, "--allow", "104.16.0.34:443"],
        &[
            "--socket",
            p,
            "--allow",
            "pypi.org:443",
            "--allow",
            "PYPI.org:0443",
        ],
        &[
            "--socket",
            p,
            "--allow",
            "pypi.org:443",
            "--nat64-prefix",
            "64:ff9b::/95",
        ],
    ];
    for args in cases {
        let (code, stderr) = run(args, Stdio::null());
        assert_eq!(code, 2, "{args:?}: {stderr}");
        assert!(!stderr.is_empty(), "{args:?}: a message on stderr");
        assert!(!socket.0.exists(), "{args:?}: nothing bound");
    }
}

#[test]
fn binary_non_utf8_allow_exits_2() {
    use std::os::unix::ffi::OsStringExt;
    let socket = socket_path();
    let status = Command::new(BIN)
        .arg("--socket")
        .arg(&socket.0)
        .arg("--allow")
        .arg(std::ffi::OsString::from_vec(b"a\xff.example:443".to_vec()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run");
    assert_eq!(status.code(), Some(2));
    assert!(!socket.0.exists());
}

#[test]
fn binary_bind_failures_exit_1() {
    let allow = ["--allow", "registry.npmjs.org:443"];

    // A regular file at the path is left as it is.
    let file = socket_path();
    fs::write(&file.0, b"keep me").expect("write");
    let path = file.0.to_str().expect("utf-8");
    let (code, stderr) = run(&[&["--socket", path][..], &allow].concat(), Stdio::null());
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(fs::read(&file.0).expect("still there"), b"keep me");

    // A dangling symlink is neither followed nor replaced.
    let link = socket_path();
    let target = socket_path();
    symlink(&target.0, &link.0).expect("symlink");
    let path = link.0.to_str().expect("utf-8");
    let (code, stderr) = run(&[&["--socket", path][..], &allow].concat(), Stdio::null());
    assert_eq!(code, 1, "{stderr}");
    assert_eq!(fs::read_link(&link.0).expect("still a link"), target.0);
    assert!(!target.0.exists(), "nothing created behind the link");

    // A path longer than `sun_path` (108 bytes).
    let long = std::env::temp_dir().join("e".repeat(200));
    let path = long.to_str().expect("utf-8");
    let (code, stderr) = run(&[&["--socket", path][..], &allow].concat(), Stdio::null());
    assert_eq!(code, 1, "{stderr}");
    assert!(!long.exists());
}

#[test]
fn binary_exits_3_when_the_log_cannot_be_written() {
    let socket = socket_path();
    let path = socket.0.to_str().expect("utf-8");
    let full = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("/dev/full");
    let (code, stderr) = run(
        &["--socket", path, "--allow", "registry.npmjs.org:443"],
        Stdio::from(full),
    );
    assert_eq!(code, 3, "{stderr}");
    // The socket was bound and is left at its path, but nobody accepts.
    let err = UnixStream::connect(&socket.0).expect_err("refused");
    assert_eq!(err.kind(), ErrorKind::ConnectionRefused, "{err:?}");
}

#[test]
fn binary_refuses_loopback_even_when_allowlisted() {
    let target = common::loopback_listener();
    target.set_nonblocking(true).expect("non-blocking");
    let port = target.local_addr().expect("addr").port();
    let entry = format!("localhost:{port}");
    let socket = socket_path();
    let path = socket.0.to_str().expect("utf-8");
    let (_child, lines) = start(&["--socket", path, "--allow", &entry]);

    match next_record(&lines, STARTUP) {
        Record::Start { nat64, .. } => {
            // Whatever this network's NAT64 setup, startup succeeded.
            let _ = nat64;
        }
        other => panic!("first record is start: {other:?}"),
    }
    let mut client = UnixStream::connect(&socket.0).expect("connect");
    client.set_read_timeout(Some(DEADLINE)).expect("timeout");
    send(&mut client, &connect_head(&entry));
    assert_eq!(status(&read_head(&mut client)), 403);

    assert!(matches!(
        next_record(&lines, DEADLINE),
        Record::Allowed { id: 1, .. }
    ));
    match next_record(&lines, DEADLINE) {
        Record::Failed {
            id: 1,
            reason: FailReason::ForbiddenAddress,
            addr: Some(addr),
            ..
        } => {
            assert!(addr.ip().is_loopback(), "{addr}");
            assert_eq!(addr.port(), port);
        }
        other => panic!("{other:?}"),
    }
    let err = target.accept().expect_err("no connection reached it");
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
}

/// Opens a real tunnel to the npm registry through the binary. Needs the
/// internet; run with `--ignored`.
#[test]
#[ignore = "needs the internet; QA runs it once"]
fn live_registry_tunnel_opens() {
    let socket = socket_path();
    let path = socket.0.to_str().expect("utf-8");
    let (_child, lines) = start(&["--socket", path, "--allow", "registry.npmjs.org:443"]);
    assert!(matches!(next_record(&lines, STARTUP), Record::Start { .. }));
    let client = UnixStream::connect(&socket.0).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(60)))
        .expect("timeout");
    let limits = Limits::new(8192, 32, 1).expect("limits");
    let tunnel = boneli_http::connect_tunnel(client, "registry.npmjs.org", 443, &limits)
        .expect("200 from the egress");
    assert!(tunnel.early().is_empty());
    assert!(matches!(
        next_record(&lines, DEADLINE),
        Record::Allowed { id: 1, .. }
    ));
    match next_record(&lines, Duration::from_secs(60)) {
        Record::Open { id: 1, addr, .. } => {
            assert!(!boneli_egress::address::forbidden(addr.ip(), &[]), "{addr}")
        }
        other => panic!("{other:?}"),
    }
    drop(tunnel);
}
