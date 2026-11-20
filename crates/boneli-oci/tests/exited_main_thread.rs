//! The kernel facts that the store's liveness rule (ADR-009, D8) reads,
//! on a real process whose main thread has exited while another thread
//! runs (#35, ADR-015 D10). How these facts map to the stored values is
//! pinned by the unit tests of `time_namespace_of` and
//! `kernel_lacks_time_namespaces` in `src/layers.rs`.
//!
//! A `harness = false` test: only a binary with its own `main` can end its
//! main thread, because libtest runs every test on a spawned thread. It
//! ignores the arguments cargo passes (`--ignored`, a filter, `--list`,
//! which runs the check too) and needs no host preparation.
//!
//! Without the marker variable this process is the parent: it starts
//! itself again as the helper, reads the helper's thread id, checks the
//! helper's `/proc` entries, then kills and reaps it. The helper ends its
//! main thread while a second thread waits for the leader to become a
//! zombie, prints its own thread id and sleeps.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::Duration;

const MARKER: &str = "BONELI_OCI_EXITED_MAIN_HELPER";

/// How often and how long the helper polls for the zombie leader: 1,000
/// polls of 10 ms, a hang bound of 10 s, not a target.
const POLLS: u32 = 1_000;
const POLL: Duration = Duration::from_millis(10);

/// The state field of a `/proc/.../stat` file: the first field after the
/// command name, which ends at the last `)`.
fn state(path: &str) -> Option<char> {
    let stat = std::fs::read_to_string(path).ok()?;
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_ascii_whitespace().next()?.chars().next()
}

fn helper() -> ExitCode {
    std::thread::spawn(|| {
        for _ in 0..POLLS {
            if state("/proc/self/stat") == Some('Z') {
                // `/proc/thread-self` reads `<pid>/task/<tid>`.
                let tid = std::fs::read_link("/proc/thread-self")
                    .ok()
                    .and_then(|l| l.file_name().map(|n| n.to_string_lossy().into_owned()));
                let Some(tid) = tid else {
                    eprintln!("helper: /proc/thread-self does not read");
                    std::process::exit(5);
                };
                let mut out = std::io::stdout().lock();
                if writeln!(out, "{tid}").and_then(|()| out.flush()).is_err() {
                    std::process::exit(6);
                }
                drop(out);
                std::thread::sleep(Duration::from_secs(60));
                std::process::exit(0);
            }
            std::thread::sleep(POLL);
        }
        eprintln!("helper: the leader is not a zombie after {POLLS} polls of {POLL:?}");
        std::process::exit(4);
    });
    match boneli_sys::exit_main_thread() {
        Ok(never) => match never {},
        Err(err) => {
            eprintln!("helper: {err}");
            ExitCode::from(3)
        }
    }
}

fn check(child: &mut Child) -> Result<(), String> {
    let stdout = child.stdout.take().ok_or("no helper stdout")?;
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .map_err(|e| format!("reading the helper's thread id: {e}"))?;
    let tid: u32 = line
        .trim_end()
        .parse()
        .map_err(|_| format!("the helper printed {line:?}, not a thread id"))?;
    let pid = child.id();
    let leader = state(&format!("/proc/{pid}/stat"));
    if leader != Some('Z') {
        return Err(format!("the leader's state is {leader:?}, not Z"));
    }
    let leader_ns = format!("/proc/{pid}/ns");
    let thread_ns = format!("/proc/{pid}/task/{tid}/ns");
    let has_time = |ns: &str| {
        std::fs::symlink_metadata(ns).is_ok_and(|m| m.is_dir())
            && std::fs::symlink_metadata(format!("{ns}/time")).is_ok()
    };
    match std::fs::read_link("/proc/thread-self/ns/time") {
        // A kernel with time namespaces. The exited leader's link does not
        // read, but its directory still lists a `time` entry, so
        // `kernel_lacks_time_namespaces` cannot take it for a kernel
        // without time namespaces and `time_namespace_of` gives
        // UNREADABLE_TIME_NAMESPACE, never 0. The running thread's link
        // reads the namespace this process is in.
        Ok(mine) => {
            match std::fs::read_link(format!("{leader_ns}/time")) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                other => return Err(format!("the leader's ns/time gave {other:?}, not ENOENT")),
            }
            if !has_time(&leader_ns) {
                return Err(format!("{leader_ns} is not a directory with a time entry"));
            }
            let theirs = std::fs::read_link(format!("{thread_ns}/time"))
                .map_err(|e| format!("the running thread's ns/time: {e}"))?;
            if theirs != mine {
                return Err(format!(
                    "the running thread's ns/time is {theirs:?}, not {mine:?}"
                ));
            }
        }
        // A kernel without time namespaces: neither directory lists one.
        Err(_) => {
            if has_time(&leader_ns) || has_time(&thread_ns) {
                return Err("this process has no time namespace link, the helper does".into());
            }
        }
    }
    match child.try_wait() {
        Ok(None) => Ok(()),
        Ok(Some(status)) => Err(format!("the helper ended before it was killed: {status}")),
        Err(e) => Err(format!("try_wait: {e}")),
    }
}

fn parent() -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("exited_main_thread: current_exe: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut child = match Command::new(exe)
        .env(MARKER, "1")
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("exited_main_thread: cannot start the helper: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = check(&mut child);
    // Killed and reaped whatever the result; at worst a helper outlives a
    // crashed parent by its 60 s sleep.
    let _ = child.kill();
    let status = child.wait();
    match result {
        Ok(()) => {
            println!("exited_main_thread: the kernel facts of the liveness rule hold: ok");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("exited_main_thread: {msg} (helper {status:?})");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    if std::env::var_os(MARKER).is_some() {
        helper()
    } else {
        parent()
    }
}
