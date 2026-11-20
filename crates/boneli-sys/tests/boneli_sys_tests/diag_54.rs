//! Temporary (#54, M2a and the trace round of the second PR; removed
//! before the PR leaves draft): how late a read of the parent's
//! `memory.stat` may come and still keep a buffered writer from being
//! OOM-killed, at 64, 128 and 256 MiB, and what one read costs (M2a);
//! and why reads every 10 ms still lose sometimes (the trace round,
//! `BONELI_SYS_DIAG_54_ROUND=trace`). No assertions: every run prints one
//! report line, and the PR records the results.
//!
//! Runs only with `BONELI_SYS_DIAG_54=1`. The trace round reads kernel
//! trace events through `sudo` when `BONELI_SYS_DIAG_54_TRACE=1` (the
//! temporary `diag-54` CI job only); nothing else here needs root.

use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use boneli_sys::{
    Cgroup, CpuMax, DeviceNumber, ExitStatus, IoLimits, IoMax, Limits, Mount, Root, Spec, Stdio,
    block_device_of, spawn,
};

use crate::support::cgroup::{self, read};
use crate::support::rootfs::{Fixture, inside};
use crate::support::{self, dev_null, ids, report};

const MIB: u64 = 1 << 20;
const RUNS: u32 = 3;

/// (`memory.max`, `wbps`, bytes written): `wbps` = M / 8 s, 2M written,
/// so every size has the loop bound (2M - M) / (M / 8 s) - 500 ms.
const SIZES: [(u64, u64, u64); 3] = [
    (64 * MIB, 8 * MIB, 128 * MIB),
    (128 * MIB, 16 * MIB, 256 * MIB),
    (256 * MIB, 32 * MIB, 512 * MIB),
];

/// The K arms' read intervals in ms; `None` is K0 (no reads).
const K_PERIODS: [Option<u64>; 6] = [None, Some(10), Some(20), Some(50), Some(100), Some(200)];

/// The N arms' read intervals in ms (256 MiB, no `io.max`, 512 MiB).
const N_PERIODS: [u64; 4] = [10, 20, 50, 100];

/// The C arm's sandbox counts and its read interval.
const C_COUNTS: [usize; 3] = [1, 8, 32];
const C_PERIOD: Duration = Duration::from_millis(5);
const C_IDLE: Duration = Duration::from_secs(2);

/// A run that has not ended by then is killed by the host.
const CAP: Duration = Duration::from_secs(90);

fn file_or(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| format!("unreadable ({e})"))
}

fn field(line: &str, key: &str) -> u64 {
    line.split_whitespace()
        .find_map(|f| f.strip_prefix(key)?.strip_prefix('='))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn io_lines(text: &str) -> String {
    text.lines()
        .map(|l| {
            let wios = field(l, "wios");
            let per = field(l, "wbytes").checked_div(wios).unwrap_or(0);
            format!(
                "{} (w/io {per})",
                l.split_whitespace().collect::<Vec<_>>().join(" ")
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn keyed_or(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
        .map_or("?".to_string(), |v| v.trim().to_string())
}

fn limits(memory_max: u64, io: IoLimits) -> Limits {
    Limits {
        memory_max,
        memory_swap_max: 0,
        pids_max: 16,
        cpu: CpuMax {
            quota_us: 100_000,
            period_us: 100_000,
        },
        io,
    }
}

fn root_with_cgroup(fixture: &Fixture) -> Root {
    let mut mounts = fixture.mounts();
    mounts.push(Mount::Cgroup2 {
        target: inside("/sys/fs/cgroup"),
    });
    fixture.root_with(vec![fixture.layer.clone()], mounts)
}

fn thread_cpu() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: one valid timespec for the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime");
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// `CLOCK_MONOTONIC` in ns: the clock of the trace (`trace_clock` mono).
fn mono_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: one valid timespec for the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime");
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// What one read returned: `file`, `file_dirty` and `file_writeback` of
/// the file read (bytes), and the sandbox's `memory.current` read right
/// after it (that read flushes nothing).
#[derive(Clone, Copy, Debug)]
struct Sample {
    at_ns: u64,
    file: u64,
    dirty: u64,
    writeback: u64,
    current: u64,
}

fn stat_value(text: &str, key: &str) -> u64 {
    keyed_or(text, key).parse().unwrap_or(0)
}

/// The parent's `memory.stat`, held open, read the way the keeper will:
/// `pread` from offset 0 until it returns 0.
fn read_stat(file: &File, buf: &mut [u8]) -> usize {
    let mut off = 0u64;
    loop {
        match file.read_at(buf, off) {
            Ok(0) => return off as usize,
            Ok(n) => off += n as u64,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => panic!("pread memory.stat: {e}"),
        }
    }
}

/// What a reader did.
#[derive(Default, Clone, Debug)]
struct Reads {
    /// Wall time of every read.
    wall: Vec<Duration>,
    /// Thread CPU of every read.
    cpu: Vec<Duration>,
    /// Missed deadlines (a whole period passed without a read).
    late: u64,
    /// Bytes of the last read.
    bytes: usize,
    /// When the first read began, after the reader's start instant.
    first_after: Option<Duration>,
    /// What every read returned.
    samples: Vec<Sample>,
}

impl Reads {
    fn text(&self) -> String {
        let p = |v: &[Duration], q: f64| -> u64 {
            if v.is_empty() {
                return 0;
            }
            let mut s: Vec<u64> = v.iter().map(|d| d.as_micros() as u64).collect();
            s.sort_unstable();
            let i = ((s.len() as f64 - 1.0) * q).round() as usize;
            s[i]
        };
        let sum: Duration = self.cpu.iter().sum();
        let per = sum
            .as_nanos()
            .checked_div(self.cpu.len() as u128)
            .unwrap_or(0);
        format!(
            "reads {} late {} bytes {} first after {}, wall us p50 {} p99 {} max {}, cpu us p50 {} p99 {} max {}, cpu ns per read {per}",
            self.wall.len(),
            self.late,
            self.bytes,
            self.first_after
                .map_or("none".to_string(), |d| format!("{} us", d.as_micros())),
            p(&self.wall, 0.5),
            p(&self.wall, 0.99),
            p(&self.wall, 1.0),
            p(&self.cpu, 0.5),
            p(&self.cpu, 0.99),
            p(&self.cpu, 1.0),
        )
    }
}

/// Reads `stat` (the parent's `memory.stat` unless the arm says
/// otherwise) every `period` on deadlines from the instant it receives
/// until `stop`, one read at once; a whole missed period re-anchors
/// (counted as late). With `current`, every read is followed by a read of
/// that `memory.current`.
fn reader(
    period: Duration,
    start: mpsc::Receiver<Instant>,
    stop: Arc<AtomicBool>,
    stat: PathBuf,
    current: Option<PathBuf>,
) -> std::thread::JoinHandle<Reads> {
    let file = File::open(&stat).unwrap_or_else(|e| panic!("open {}: {e}", stat.display()));
    let current =
        current.map(|p| File::open(&p).unwrap_or_else(|e| panic!("open {}: {e}", p.display())));
    std::thread::spawn(move || {
        let mut r = Reads::default();
        let Ok(t0) = start.recv() else {
            return r;
        };
        let mut buf = [0u8; 4096];
        let mut cur = [0u8; 64];
        let mut deadline = Instant::now();
        r.first_after = Some(deadline.saturating_duration_since(t0));
        while !stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            if now < deadline {
                std::thread::sleep(deadline - now);
                continue;
            }
            let c0 = thread_cpu();
            let at_ns = mono_ns();
            let w0 = Instant::now();
            r.bytes = read_stat(&file, &mut buf);
            r.wall.push(w0.elapsed());
            r.cpu.push(thread_cpu().saturating_sub(c0));
            let current = current.as_ref().map_or(0, |f| {
                let n = read_stat(f, &mut cur);
                String::from_utf8_lossy(&cur[..n])
                    .trim()
                    .parse()
                    .unwrap_or(0)
            });
            let text = String::from_utf8_lossy(&buf[..r.bytes]);
            r.samples.push(Sample {
                at_ns,
                file: stat_value(&text, "file"),
                dirty: stat_value(&text, "file_dirty"),
                writeback: stat_value(&text, "file_writeback"),
                current,
            });
            deadline += period;
            let now = Instant::now();
            if now >= deadline + period {
                r.late += 1;
                deadline = now + period;
            }
        }
        r
    })
}

/// Whose `memory.stat` a K arm reads.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Target {
    /// The parent of every sandbox (the keeper's choice).
    Parent,
    /// The sandbox itself (M1's A2).
    Sandbox,
}

/// One write arm.
#[derive(Clone, Debug)]
struct Arm {
    name: String,
    memory_max: u64,
    wbps: Option<u64>,
    size: u64,
    /// The read period in ms; `None`: no reads.
    period: Option<u64>,
    target: Target,
    /// Destroy the sandbox this long after `loop_start` if the writer is
    /// still alive. The trace round's kills come 43-120 ms after
    /// `loop_start` (M2a), so it cuts held runs short.
    cut: Option<Duration>,
    /// Record kernel trace events (only with `BONELI_SYS_DIAG_54_TRACE=1`).
    trace: bool,
}

impl Arm {
    fn write(
        name: String,
        memory_max: u64,
        wbps: Option<u64>,
        size: u64,
        period: Option<u64>,
    ) -> Arm {
        Arm {
            name,
            memory_max,
            wbps,
            size,
            period,
            target: Target::Parent,
            cut: None,
            trace: false,
        }
    }
}

/// What a run gave back: whether the writer was OOM-killed, and the raw
/// trace when one was recorded.
struct Outcome {
    killed: bool,
    trace: Option<String>,
}

/// One run of a write arm; prints its report line (and with a trace, its
/// trace line).
fn run_write(arm: &Arm, run: u32) -> Outcome {
    let tag = format!("{} run {run}", arm.name);
    let fixture = Fixture::new("diag54");
    let dev: DeviceNumber =
        block_device_of(&fixture.workspace).expect("a block device behind /workspace");
    let io = match arm.wbps {
        Some(w) => IoLimits::new(vec![IoMax {
            dev,
            rbps: None,
            wbps: Some(w),
            riops: None,
            wiops: None,
        }])
        .expect("one device"),
        None => IoLimits::none(),
    };
    let cg = cgroup::create("diag54", &limits(arm.memory_max, io));
    let ino = |p: &std::path::Path| std::fs::metadata(p).map_or(0, |m| m.ino());
    let sandbox_ino = ino(cg.path());
    let parent_ino = ino(cgroup::parent().path());
    let (stat, target_ino) = match arm.target {
        Target::Parent => (cgroup::parent().path().join("memory.stat"), parent_ino),
        Target::Sandbox => (cg.path().join("memory.stat"), sandbox_ino),
    };
    let (out_r, out_w) = support::pipe();
    let (err_r, err_w) = support::pipe();
    let size_text = arm.size.to_string();
    let env = [
        (support::probe::ACTION_VAR, "io-write"),
        ("BONELI_PROBE_FILE", "/workspace/buffered"),
        ("BONELI_PROBE_SIZE", size_text.as_str()),
        ("BONELI_PROBE_DIRECT", "never"),
    ];
    let s = spec(&fixture, &cg, &env, out_w, err_w);
    let stop = Arc::new(AtomicBool::new(false));
    let (start_tx, start_rx) = mpsc::channel::<Instant>();
    let reader = arm.period.map(|p| {
        reader(
            Duration::from_millis(p),
            start_rx,
            stop.clone(),
            stat,
            Some(cg.path().join("memory.current")),
        )
    });
    let tracing = arm.trace && trace_wanted();
    let trace_state = if tracing {
        trace_begin().err()
    } else {
        Some("not requested".to_string())
    };
    let spawn_ns = mono_ns();
    let start = Instant::now();
    let mut child = spawn(&s).expect("spawn the probe");
    drop(s);
    let writer = child.pid();
    let (tx, rx) = mpsc::channel::<(u64, String, u64)>();
    let out_reader = std::thread::spawn(move || {
        use std::io::BufRead;
        let mut r = std::io::BufReader::new(File::from(out_r));
        let mut line = String::new();
        let mut start_tx = Some(start_tx);
        loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let at_ns = mono_ns();
                    if line.contains("BONELI_PROBE loop_start=1")
                        && let Some(t) = start_tx.take()
                    {
                        let _ = t.send(Instant::now());
                    }
                    let _ = tx.send((start.elapsed().as_millis() as u64, line.clone(), at_ns));
                }
            }
        }
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut File::from(err_r), &mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });
    let mut lines: Vec<(u64, String, u64)> = Vec::new();
    let mut cg = Some(cg);
    let mut cap_hit = false;
    let mut cut_hit: Option<u64> = None;
    let mut destroyed: Option<(u64, Duration, String)> = None;
    let mut final_files: Option<(String, String)> = None;
    loop {
        let mut pfd = libc::pollfd {
            fd: child.pidfd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, 10) };
        if rc > 0 {
            break;
        }
        while let Ok(l) = rx.try_recv() {
            lines.push(l);
        }
        if start.elapsed() >= CAP
            && !cap_hit
            && let Some(c) = &cg
        {
            cap_hit = true;
            let _ = std::fs::write(c.path().join("cgroup.kill"), "1");
        }
        let now_ms = start.elapsed().as_millis() as u64;
        let cut_due = arm.cut.is_some_and(|cut| {
            lines
                .iter()
                .find(|(_, l, _)| l.contains("BONELI_PROBE loop_start="))
                .is_some_and(|(at, _, _)| now_ms >= at + cut.as_millis() as u64)
        });
        if destroyed.is_none()
            && (cut_due
                || lines
                    .iter()
                    .any(|(_, l, _)| l.contains("BONELI_PROBE loop_ms=")))
            && let Some(c) = cg.take()
        {
            stop.store(true, Ordering::Relaxed);
            if cut_due
                && !lines
                    .iter()
                    .any(|(_, l, _)| l.contains("BONELI_PROBE loop_ms="))
            {
                cut_hit = Some(now_ms);
            }
            let at = start.elapsed().as_millis() as u64;
            final_files = Some((read(&c, "memory.events"), read(&c, "io.stat")));
            let t = Instant::now();
            let r = c.destroy();
            destroyed = Some((at, t.elapsed(), format!("{r:?}")));
        }
    }
    stop.store(true, Ordering::Relaxed);
    let ms = start.elapsed().as_millis() as u64;
    let status = child.wait().expect("wait for the probe");
    let trace = if tracing && trace_state.is_none() {
        Some(trace_end())
    } else {
        None
    };
    out_reader.join().expect("stdout reader");
    while let Ok(l) = rx.try_recv() {
        lines.push(l);
    }
    let reads = reader.map(|h| h.join().expect("reader"));
    let stderr = err_reader.join().unwrap_or_default();
    let (events, io_stat) = match (&cg, final_files) {
        (Some(c), _) => (read(c, "memory.events"), read(c, "io.stat")),
        (None, Some(f)) => f,
        (None, None) => (String::new(), String::new()),
    };
    let probe = |k: &str| -> Option<(u64, String, u64)> {
        lines.iter().rev().find_map(|(at, l, ns)| {
            let i = l.find("BONELI_PROBE ")?;
            let rest = &l[i + "BONELI_PROBE ".len()..];
            let (key, v) = rest.split_once('=')?;
            (key == k).then(|| (*at, v.trim().to_string(), *ns))
        })
    };
    let progress: Vec<String> = lines
        .iter()
        .filter_map(|(_, l, _)| {
            let i = l.find("BONELI_PROBE progress=")?;
            Some(l[i + "BONELI_PROBE progress=".len()..].trim().to_string())
        })
        .collect();
    let oom_kill: u64 = keyed_or(&events, "oom_kill").parse().unwrap_or(0);
    let killed = oom_kill >= 1
        || (destroyed.is_none() && !cap_hit && status == ExitStatus::Signaled(libc::SIGKILL));
    let loop_start = probe("loop_start");
    report(&format!(
        "diag_54 {tag}: memory.max {} MiB, wbps {}, write {} MiB, T {} on {:?}, dev {}:{}: status {status:?} at {ms} ms{}{}, \
         killed {killed} (oom_kill {oom_kill}, max {}), loop_start at {} ms, loop_ms {}, kill after loop_start {}, \
         {}, io.stat [{}], destroy {}, progress [{}], stderr {:?}",
        arm.memory_max / MIB,
        arm.wbps
            .map_or("none".to_string(), |w| format!("{} MiB/s", w / MIB)),
        arm.size / MIB,
        arm.period.map_or("none".to_string(), |p| format!("{p} ms")),
        arm.target,
        dev.major,
        dev.minor,
        if cap_hit { " (cap hit)" } else { "" },
        cut_hit.map_or(String::new(), |at| format!(" (cut at {at} ms)")),
        keyed_or(&events, "max"),
        loop_start
            .as_ref()
            .map_or("none".to_string(), |(a, _, _)| a.to_string()),
        probe("loop_ms").map_or("none".to_string(), |(_, v, _)| v),
        match (killed, &loop_start) {
            (true, Some((a, _, _))) => format!("{} ms", ms.saturating_sub(*a)),
            _ => "n/a".to_string(),
        },
        reads
            .as_ref()
            .map_or("reads none".to_string(), |r| r.text()),
        io_lines(&io_stat),
        destroyed
            .as_ref()
            .map_or("none".to_string(), |(at, took, r)| format!(
                "at {at} ms took {took:?}: {r}"
            )),
        progress.join(" "),
        stderr
            .lines()
            .filter(|l| l.contains("probe:") || l.contains("panicked"))
            .collect::<Vec<_>>()
    ));
    let raw = match (&trace_state, trace) {
        (Some(why), _) if tracing => {
            report(&format!("diag_54 trace {tag}: not recorded: {why}"));
            None
        }
        (_, Some(Err(e))) => {
            report(&format!("diag_54 trace {tag}: not read: {e}"));
            None
        }
        (_, Some(Ok(text))) => {
            let ids = TraceIds {
                loop_ns: loop_start.as_ref().map_or(spawn_ns, |(_, _, ns)| *ns),
                sandbox: sandbox_ino,
                parent: parent_ino,
                target: target_ino,
                writer: i64::from(writer),
                me: i64::from(std::process::id()),
                dev: (dev.major, dev.minor),
            };
            report(&format!(
                "diag_54 trace {tag}: {}",
                trace_analysis(
                    &text,
                    &ids,
                    reads.as_ref().map_or(&[][..], |r| &r.samples[..])
                )
            ));
            Some(text)
        }
        _ => None,
    };
    if let Some(c) = cg {
        let _ = c.destroy();
    }
    drop(fixture);
    Outcome { killed, trace: raw }
}

/// The events the trace round records. `global_dirty_state` fires each
/// time `balance_dirty_pages` computes the global domain, so once per
/// entry, freerun or not; `balance_dirty_pages` only when the writer is
/// past the freerun ceiling (mm/page-writeback.c, v7.0).
const TRACE_EVENTS: [&str; 13] = [
    "writeback/global_dirty_state",
    "writeback/balance_dirty_pages",
    "writeback/writeback_mark_inode_dirty",
    "writeback/track_foreign_dirty",
    "writeback/inode_switch_wbs",
    "writeback/writeback_queue",
    "writeback/writeback_start",
    "memcg/memcg_flush_stats",
    "vmscan/mm_vmscan_memcg_reclaim_begin",
    "vmscan/mm_vmscan_memcg_reclaim_end",
    "vmscan/mm_vmscan_throttled",
    "oom/mark_victim",
    "block/block_rq_issue",
];

const TRACE_DIR: &str =
    "T=/sys/kernel/tracing; [ -e $T/trace ] || T=/sys/kernel/debug/tracing; [ -e $T/trace ]";

fn trace_wanted() -> bool {
    std::env::var("BONELI_SYS_DIAG_54_TRACE").as_deref() == Ok("1")
}

fn sudo_sh(script: &str) -> Result<String, String> {
    let out = std::process::Command::new("sudo")
        .args(["-n", "sh", "-c", script])
        .output()
        .map_err(|e| format!("sudo: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "sudo -n: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Once per round: the clock (mono, so trace times compare with
/// `CLOCK_MONOTONIC`), the tgid column, the buffer and the events.
/// Returns the events the kernel lacks.
fn trace_setup() -> Result<String, String> {
    let mut s = format!(
        "set -e; {TRACE_DIR}; echo 0 > $T/tracing_on; echo 0 > $T/options/overwrite; \
         echo 16384 > $T/buffer_size_kb; echo mono > $T/trace_clock; echo 1 > $T/options/record-tgid; "
    );
    for e in TRACE_EVENTS {
        s.push_str(&format!(
            "if [ -e $T/events/{e}/enable ]; then echo 1 > $T/events/{e}/enable; else echo 'missing {e}'; fi; "
        ));
    }
    s.push_str("echo > $T/trace; echo \"clock $(cat $T/trace_clock)\"");
    sudo_sh(&s)
}

fn trace_teardown() {
    let mut s = format!("{TRACE_DIR}; echo 0 > $T/tracing_on; ");
    for e in TRACE_EVENTS {
        s.push_str(&format!("echo 0 > $T/events/{e}/enable 2>/dev/null; "));
    }
    s.push_str(
        "echo > $T/trace; echo local > $T/trace_clock; echo 0 > $T/options/record-tgid; true",
    );
    let _ = sudo_sh(&s);
}

fn trace_begin() -> Result<(), String> {
    sudo_sh(&format!(
        "set -e; {TRACE_DIR}; echo 0 > $T/tracing_on; echo > $T/trace; echo 1 > $T/tracing_on"
    ))
    .map(|_| ())
}

fn trace_end() -> Result<String, String> {
    sudo_sh(&format!(
        "set -e; {TRACE_DIR}; echo 0 > $T/tracing_on; \
         echo \"dropped $(cat $T/per_cpu/cpu*/stats | awk '/^(overrun|dropped events):/ {{ n += $NF }} END {{ print n + 0 }}')\"; \
         cat $T/trace"
    ))
}

/// One trace line.
struct Ev<'a> {
    ts_ns: u64,
    tgid: i64,
    name: &'a str,
    rest: &'a str,
}

/// `comm-pid (tgid) [cpu] flags secs.micros: event: fields`.
fn parse_event(line: &str) -> Option<Ev<'_>> {
    if line.starts_with('#') {
        return None;
    }
    let (tgid, from) = match line.find(") [") {
        Some(i) => {
            let open = line[..i].rfind('(')?;
            (line[open + 1..i].trim().parse().unwrap_or(-1), i + 2)
        }
        None => (-1, line.find(" [")? + 1),
    };
    let after = &line[from..];
    let after = &after[after.find("] ")? + 2..];
    let i1 = after.find(": ")?;
    let ts = after[..i1].split_whitespace().last()?;
    let (secs, frac) = ts.split_once('.')?;
    let frac_ns: u64 = format!("{frac:0<9}")[..9].parse().ok()?;
    let ts_ns = secs.parse::<u64>().ok()? * 1_000_000_000 + frac_ns;
    let rest1 = &after[i1 + 2..];
    let i2 = rest1.find(": ")?;
    Some(Ev {
        ts_ns,
        tgid,
        name: rest1[..i2].trim(),
        rest: &rest1[i2 + 2..],
    })
}

/// Who is who in a run's trace.
struct TraceIds {
    /// `CLOCK_MONOTONIC` when the host got `loop_start` (else the spawn).
    loop_ns: u64,
    /// cgroup ids (= the directories' inode numbers on 64-bit kernels).
    sandbox: u64,
    parent: u64,
    /// The id of the cgroup whose `memory.stat` the reader reads.
    target: u64,
    /// The probe's tgid.
    writer: i64,
    /// This process (the reader thread's tgid).
    me: i64,
    dev: (u32, u32),
}

fn mib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / MIB as f64)
}

/// The facts that tell the hypotheses apart, all before `end` (the first
/// `mark_victim`, else the end of the trace), times in ms after
/// `loop_start`.
fn trace_analysis(text: &str, ids: &TraceIds, samples: &[Sample]) -> String {
    let dropped = text
        .lines()
        .find_map(|l| l.strip_prefix("dropped "))
        .unwrap_or("?")
        .trim()
        .to_string();
    let evs: Vec<Ev<'_>> = text.lines().filter_map(parse_event).collect();
    let rel = |ns: u64| (ns as i64 - ids.loop_ns as i64) as f64 / 1e6;
    let victim = evs
        .iter()
        .find(|e| e.name == "mark_victim")
        .map(|e| e.ts_ns);
    let end = victim.unwrap_or(u64::MAX);
    let before: Vec<&Ev<'_>> = evs.iter().filter(|e| e.ts_ns < end).collect();
    let of = |name: &str| -> Vec<&Ev<'_>> {
        before.iter().copied().filter(|e| e.name == name).collect()
    };
    let at = |v: &[&Ev<'_>]| -> String {
        v.first()
            .map_or("-".to_string(), |e| format!("{:.2}", rel(e.ts_ns)))
    };
    // H1: does the writer enter balance_dirty_pages, and how often?
    let entries: Vec<&Ev<'_>> = of("global_dirty_state")
        .into_iter()
        .filter(|e| e.tgid == ids.writer)
        .collect();
    let max_gap = entries
        .windows(2)
        .map(|w| w[1].ts_ns - w[0].ts_ns)
        .max()
        .unwrap_or(0) as f64
        / 1e6;
    let other_entries = of("global_dirty_state")
        .iter()
        .filter(|e| e.tgid != ids.writer)
        .count();
    // The throttle path, by memcg domain.
    let throttle: Vec<&Ev<'_>> = of("balance_dirty_pages")
        .into_iter()
        .filter(|e| e.tgid == ids.writer)
        .collect();
    let mut throttle_cgs: Vec<u64> = throttle
        .iter()
        .map(|e| field(e.rest, "cgroup_ino"))
        .collect();
    throttle_cgs.sort_unstable();
    throttle_cgs.dedup();
    // H3: which bdi the writer dirties.
    let mut bdis: Vec<&str> = of("writeback_mark_inode_dirty")
        .iter()
        .filter(|e| e.tgid == ids.writer)
        .filter_map(|e| e.rest.strip_prefix("bdi ")?.split(": ").next())
        .collect();
    bdis.sort_unstable();
    bdis.dedup();
    // H4: did the reads flush?
    let flushes = of("memcg_flush_stats");
    let mine: Vec<&&Ev<'_>> = flushes
        .iter()
        .filter(|e| e.tgid == ids.me && field(e.rest, "memcg_id") == ids.target)
        .collect();
    let seq: String = mine
        .iter()
        .map(|e| {
            if field(e.rest, "needs_flush") == 1 {
                '1'
            } else {
                '0'
            }
        })
        .collect();
    let skipped: Vec<String> = mine
        .iter()
        .filter(|e| field(e.rest, "needs_flush") != 1)
        .map(|e| {
            let v = e
                .rest
                .split_whitespace()
                .find_map(|f| f.strip_prefix("stats_updates="))
                .unwrap_or("?");
            format!("{:.1}:{v}", rel(e.ts_ns))
        })
        .collect();
    let done: Vec<&&Ev<'_>> = mine
        .iter()
        .filter(|e| field(e.rest, "needs_flush") == 1)
        .copied()
        .collect();
    // After each flush that ran: when the writer next entered
    // balance_dirty_pages, and whether it took the throttle path.
    let mut next_entry_max = 0f64;
    let mut throttled_after = 0;
    for f in &done {
        if let Some(e) = entries.iter().find(|e| e.ts_ns > f.ts_ns) {
            next_entry_max = next_entry_max.max((e.ts_ns - f.ts_ns) as f64 / 1e6);
        }
        if throttle
            .iter()
            .any(|e| e.ts_ns > f.ts_ns && e.ts_ns < f.ts_ns + 5_000_000)
        {
            throttled_after += 1;
        }
    }
    let others: Vec<String> = flushes
        .iter()
        .filter(|e| !(e.tgid == ids.me && field(e.rest, "memcg_id") == ids.target))
        .map(|e| {
            format!(
                "{:.1}:{}:{}{}",
                rel(e.ts_ns),
                match field(e.rest, "memcg_id") {
                    id if id == ids.sandbox => "sandbox".to_string(),
                    id if id == ids.parent => "parent".to_string(),
                    1 => "root".to_string(),
                    id => id.to_string(),
                },
                if field(e.rest, "needs_flush") == 1 {
                    "did"
                } else {
                    "skip"
                },
                if field(e.rest, "force") == 1 {
                    ":force"
                } else {
                    ""
                }
            )
        })
        .take(12)
        .collect();
    let reclaim: Vec<&Ev<'_>> = of("mm_vmscan_memcg_reclaim_begin")
        .into_iter()
        .filter(|e| e.tgid == ids.writer)
        .collect();
    let dev = format!("{},{} ", ids.dev.0, ids.dev.1);
    let issued: Vec<&Ev<'_>> = of("block_rq_issue")
        .into_iter()
        .filter(|e| e.rest.starts_with(&dev))
        .collect();
    let reads: Vec<String> = samples
        .iter()
        .filter(|s| s.at_ns < end)
        .map(|s| {
            format!(
                "{:.1}:{}/{}/{}/{}",
                rel(s.at_ns),
                mib(s.dirty),
                mib(s.writeback),
                mib(s.file),
                mib(s.current)
            )
        })
        .collect();
    let last_reads = &reads[reads.len().saturating_sub(10)..];
    format!(
        "events {} (dropped {dropped}), victim at {}; bdp entries by the writer {} (first {}, last {}, max gap {max_gap:.2} ms), by others {other_entries}; \
         throttle events {} (first {}, cgroup_ino {:?}, sandbox {}, parent {}) first [{}]; bdi {:?}; \
         reader flushes of {} {} [{seq}] skipped at:updates [{}]; after a flush that ran: next entry within {next_entry_max:.2} ms, \
         throttle within 5 ms after {throttled_after} of {}; other flushes [{}]; reclaim begins {} (first {}); \
         writeback queue {} (first {}) start {} (first {}); rq issue on {}:{} {} (first {}); foreign {} switch {}; \
         reads before the end (ms:dirty/writeback/file/current MiB, last 10 of {}) [{}]",
        evs.len(),
        victim.map_or("none".to_string(), |v| format!("{:.2}", rel(v))),
        entries.len(),
        at(&entries),
        entries
            .last()
            .map_or("-".to_string(), |e| format!("{:.2}", rel(e.ts_ns))),
        throttle.len(),
        at(&throttle),
        throttle_cgs,
        ids.sandbox,
        ids.parent,
        throttle.first().map_or(String::new(), |e| clip(e.rest)),
        bdis,
        if ids.target == ids.parent {
            "parent"
        } else {
            "sandbox"
        },
        mine.len(),
        skipped
            .iter()
            .take(16)
            .cloned()
            .collect::<Vec<_>>()
            .join(" "),
        done.len(),
        others.join(" "),
        reclaim.len(),
        at(&reclaim),
        of("writeback_queue").len(),
        at(&of("writeback_queue")),
        of("writeback_start").len(),
        at(&of("writeback_start")),
        ids.dev.0,
        ids.dev.1,
        issued.len(),
        at(&issued),
        of("track_foreign_dirty").len(),
        of("inode_switch_wbs").len(),
        reads.len(),
        last_reads.join(" "),
    )
}

fn clip(s: &str) -> String {
    let t = s.trim();
    if t.len() > 300 {
        let mut end = 300;
        while !t.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &t[..end])
    } else {
        t.to_string()
    }
}

fn spec<'a>(
    fixture: &Fixture,
    cg: &'a Cgroup,
    env: &[(&str, &str)],
    out_w: std::os::fd::OwnedFd,
    err_w: std::os::fd::OwnedFd,
) -> Spec<'a> {
    Spec {
        program: crate::support::rootfs::PROBE.into(),
        args: ["--exact", "probe", "--nocapture", "--quiet"]
            .iter()
            .map(OsString::from)
            .collect(),
        env: env
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect(),
        stdio: Stdio {
            stdin: dev_null(),
            stdout: out_w,
            stderr: err_w,
        },
        ids: ids(0, 0),
        setup_timeout: support::SETUP_TIMEOUT,
        root: root_with_cgroup(fixture),
        cgroup: cg,
    }
}

/// The cost arm: `n` sandboxes (256 MiB, no `io.max`) each write 16 MiB
/// buffered and `fdatasync`, all spawned together; a reader at 5 ms from
/// the first spawn until the last exit, then 2 s with the sandboxes idle.
fn run_cost(n: usize, run: u32) {
    let tag = format!("C{n} run {run}");
    let fixtures: Vec<Fixture> = (0..n).map(|_| Fixture::new("diag54c")).collect();
    let cgs: Vec<Cgroup> = (0..n)
        .map(|_| cgroup::create("diag54c", &limits(256 * MIB, IoLimits::none())))
        .collect();
    let stop = Arc::new(AtomicBool::new(false));
    let (start_tx, start_rx) = mpsc::channel::<Instant>();
    let active = reader(
        C_PERIOD,
        start_rx,
        stop.clone(),
        cgroup::parent().path().join("memory.stat"),
        None,
    );
    let size_text = (16 * MIB).to_string();
    let env = [
        (support::probe::ACTION_VAR, "io-write"),
        ("BONELI_PROBE_FILE", "/workspace/buffered"),
        ("BONELI_PROBE_SIZE", size_text.as_str()),
        ("BONELI_PROBE_DIRECT", "never"),
    ];
    let t0 = Instant::now();
    start_tx.send(t0).expect("start the reader");
    let mut children = Vec::new();
    for (f, c) in fixtures.iter().zip(&cgs) {
        let s = spec(f, c, &env, dev_null(), dev_null());
        children.push(spawn(&s).expect("spawn the probe"));
    }
    let mut ok = 0;
    for c in &mut children {
        if support::wait_bounded(c, CAP) == ExitStatus::Exited(0) {
            ok += 1;
        }
    }
    let busy = t0.elapsed();
    stop.store(true, Ordering::Relaxed);
    let a = active.join().expect("reader");
    let stop = Arc::new(AtomicBool::new(false));
    let (idle_tx, idle_rx) = mpsc::channel::<Instant>();
    let idle = reader(
        C_PERIOD,
        idle_rx,
        stop.clone(),
        cgroup::parent().path().join("memory.stat"),
        None,
    );
    idle_tx.send(Instant::now()).expect("start the idle reader");
    std::thread::sleep(C_IDLE);
    stop.store(true, Ordering::Relaxed);
    let i = idle.join().expect("reader");
    let per_sec = |r: &Reads| -> String {
        let sum: Duration = r.cpu.iter().sum();
        let per = sum.as_nanos().checked_div(r.cpu.len() as u128).unwrap_or(0);
        [50u128, 25, 10, 5]
            .iter()
            .map(|p| format!("{p} ms {:.3} ms/s", per as f64 / *p as f64 / 1000.0))
            .collect::<Vec<_>>()
            .join(", ")
    };
    report(&format!(
        "diag_54 {tag}: {n} sandboxes, {ok} exited 0, busy {} ms; active: {}; cpu per second at [{}]; idle 2 s: {}; cpu per second at [{}]",
        busy.as_millis(),
        a.text(),
        per_sec(&a),
        i.text(),
        per_sec(&i)
    ));
    for c in cgs {
        let _ = c.destroy();
    }
    drop(fixtures);
}

fn host_facts() {
    let k = |p: &str| file_or(p).trim().to_string();
    let mem = file_or("/proc/meminfo")
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    report(&format!(
        "diag_54 host: kernel {}, nproc {}, {mem}, vm.dirty_ratio {} dirty_background_ratio {} dirty_bytes {} \
         dirty_background_bytes {} dirty_expire_centisecs {} dirty_writeback_centisecs {}",
        k("/proc/sys/kernel/osrelease"),
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        k("/proc/sys/vm/dirty_ratio"),
        k("/proc/sys/vm/dirty_background_ratio"),
        k("/proc/sys/vm/dirty_bytes"),
        k("/proc/sys/vm/dirty_background_bytes"),
        k("/proc/sys/vm/dirty_expire_centisecs"),
        k("/proc/sys/vm/dirty_writeback_centisecs"),
    ));
}

fn wanted(name: &str) -> bool {
    // BONELI_SYS_DIAG_54_ONLY: a comma-separated list of arm names to run.
    std::env::var("BONELI_SYS_DIAG_54_ONLY").map_or(true, |only| only.split(',').any(|n| n == name))
}

fn runs() -> u32 {
    std::env::var("BONELI_SYS_DIAG_54_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(RUNS)
}

/// The trace round's runs per K10 arm (`BONELI_SYS_DIAG_54_RUNS` sets it).
const TRACE_RUNS: u32 = 40;

/// The trace round cuts a held run this long after `loop_start`.
const TRACE_CUT: Duration = Duration::from_millis(1500);

/// The trace round: K10 on the parent at every size (M2a's kills), K10
/// on the sandbox (KS10, M1's A2), K0 as the control and N10, run in turn
/// so that a slow drift of the host spreads over every arm. Each run
/// records trace events and prints a trace line; a killed run and the
/// first run of each arm leave their raw trace in
/// `BONELI_SYS_DIAG_54_TRACE_DIR`.
fn trace_round() {
    if trace_wanted() {
        match trace_setup() {
            Ok(out) => report(&format!(
                "diag_54 trace setup: {}",
                out.split_whitespace().collect::<Vec<_>>().join(" ")
            )),
            Err(e) => report(&format!("diag_54 trace setup failed: {e}")),
        }
    }
    let dump = std::env::var_os("BONELI_SYS_DIAG_54_TRACE_DIR").map(PathBuf::from);
    if let Some(d) = &dump {
        std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("create {}: {e}", d.display()));
    }
    let k10 = std::env::var("BONELI_SYS_DIAG_54_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(TRACE_RUNS);
    let traced = |mut arm: Arm, target: Target| -> Arm {
        arm.target = target;
        arm.cut = Some(TRACE_CUT);
        arm.trace = true;
        arm
    };
    let mut arms: Vec<(Arm, u32)> = Vec::new();
    for (m, w, s) in SIZES {
        let at = m / MIB;
        arms.push((
            traced(
                Arm::write(format!("K10@{at}MiB"), m, Some(w), s, Some(10)),
                Target::Parent,
            ),
            k10,
        ));
        arms.push((
            traced(
                Arm::write(format!("KS10@{at}MiB"), m, Some(w), s, Some(10)),
                Target::Sandbox,
            ),
            k10.div_ceil(2),
        ));
        arms.push((
            traced(
                Arm::write(format!("K0@{at}MiB"), m, Some(w), s, None),
                Target::Parent,
            ),
            2,
        ));
    }
    arms.push((
        traced(
            Arm::write("N10".to_string(), 256 * MIB, None, 512 * MIB, Some(10)),
            Target::Parent,
        ),
        k10.div_ceil(4),
    ));
    arms.retain(|(a, _)| wanted(&a.name));
    let mut killed = vec![0u32; arms.len()];
    let most = arms.iter().map(|(_, n)| *n).max().unwrap_or(0);
    for r in 1..=most {
        for (i, (arm, n)) in arms.iter().enumerate() {
            if r > *n {
                continue;
            }
            let o = run_write(arm, r);
            if o.killed {
                killed[i] += 1;
            }
            if let (Some(d), Some(text)) = (&dump, &o.trace)
                && (o.killed || r == 1)
            {
                let name = format!(
                    "{}-run{r}-{}.trace",
                    arm.name,
                    if o.killed { "killed" } else { "held" }
                );
                let _ = std::fs::write(d.join(name), text);
            }
        }
    }
    if trace_wanted() {
        trace_teardown();
    }
    report(&format!(
        "diag_54 summary: {}",
        arms.iter()
            .zip(&killed)
            .map(|((a, n), k)| format!("{} killed {k}/{n}", a.name))
            .collect::<Vec<_>>()
            .join(", ")
    ));
}

#[test]
#[ignore = "host: diagnostic for #54"]
fn buffered_sweep() {
    if std::env::var("BONELI_SYS_DIAG_54").as_deref() != Ok("1") {
        return;
    }
    let _alone = support::exclusive();
    host_facts();
    if std::env::var("BONELI_SYS_DIAG_54_ROUND").as_deref() == Ok("trace") {
        trace_round();
        report("diag_54 done");
        return;
    }
    let mut summary = Vec::new();
    for (m, w, s) in SIZES {
        for t in K_PERIODS {
            let name = format!(
                "K{}@{}MiB",
                t.map_or("0".to_string(), |t| t.to_string()),
                m / MIB
            );
            if !wanted(&name) {
                continue;
            }
            let killed = (1..=runs())
                .filter(|r| run_write(&Arm::write(name.clone(), m, Some(w), s, t), *r).killed)
                .count();
            summary.push(format!("{name} killed {killed}/{}", runs()));
        }
    }
    for t in N_PERIODS {
        let name = format!("N{t}");
        if !wanted(&name) {
            continue;
        }
        let killed = (1..=runs())
            .filter(|r| {
                run_write(
                    &Arm::write(name.clone(), 256 * MIB, None, 512 * MIB, Some(t)),
                    *r,
                )
                .killed
            })
            .count();
        summary.push(format!("{name} killed {killed}/{}", runs()));
    }
    for n in C_COUNTS {
        if !wanted(&format!("C{n}")) {
            continue;
        }
        for r in 1..=runs() {
            run_cost(n, r);
        }
    }
    report(&format!("diag_54 summary: {}", summary.join(", ")));
    report("diag_54 done");
}
