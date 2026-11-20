//! Temporary (#54, M2a of the second PR; removed before the PR leaves
//! draft): how late a read of the parent's `memory.stat` may come and
//! still keep a buffered writer from being OOM-killed, at 64, 128 and
//! 256 MiB, and what one read costs. No assertions: every run prints one
//! report line, and the PR records the results.
//!
//! Runs only with `BONELI_SYS_DIAG_54=1`. Nothing here needs root.

use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
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

/// Reads every `period` on deadlines from the instant it receives until
/// `stop`, one read at once; a whole missed period re-anchors (counted as
/// late).
fn reader(
    period: Duration,
    start: mpsc::Receiver<Instant>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<Reads> {
    let path = cgroup::parent().path().join("memory.stat");
    let file = File::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    std::thread::spawn(move || {
        let mut r = Reads::default();
        let Ok(t0) = start.recv() else {
            return r;
        };
        let mut buf = [0u8; 4096];
        let mut deadline = Instant::now();
        r.first_after = Some(deadline.saturating_duration_since(t0));
        while !stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            if now < deadline {
                std::thread::sleep(deadline - now);
                continue;
            }
            let c0 = thread_cpu();
            let w0 = Instant::now();
            r.bytes = read_stat(&file, &mut buf);
            r.wall.push(w0.elapsed());
            r.cpu.push(thread_cpu().saturating_sub(c0));
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

/// One run of a write arm; prints its report line and returns whether
/// the writer was OOM-killed.
fn run_write(
    name: &str,
    run: u32,
    memory_max: u64,
    wbps: Option<u64>,
    size: u64,
    period: Option<u64>,
) -> bool {
    let tag = format!("{name} run {run}");
    let fixture = Fixture::new("diag54");
    let dev: DeviceNumber =
        block_device_of(&fixture.workspace).expect("a block device behind /workspace");
    let io = match wbps {
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
    let cg = cgroup::create("diag54", &limits(memory_max, io));
    let (out_r, out_w) = support::pipe();
    let (err_r, err_w) = support::pipe();
    let size_text = size.to_string();
    let env = [
        (support::probe::ACTION_VAR, "io-write"),
        ("BONELI_PROBE_FILE", "/workspace/buffered"),
        ("BONELI_PROBE_SIZE", size_text.as_str()),
        ("BONELI_PROBE_DIRECT", "never"),
    ];
    let s = spec(&fixture, &cg, &env, out_w, err_w);
    let stop = Arc::new(AtomicBool::new(false));
    let (start_tx, start_rx) = mpsc::channel::<Instant>();
    let reader = period.map(|p| reader(Duration::from_millis(p), start_rx, stop.clone()));
    let start = Instant::now();
    let mut child = spawn(&s).expect("spawn the probe");
    drop(s);
    let (tx, rx) = mpsc::channel::<(u64, String)>();
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
                    if line.contains("BONELI_PROBE loop_start=1")
                        && let Some(t) = start_tx.take()
                    {
                        let _ = t.send(Instant::now());
                    }
                    let _ = tx.send((start.elapsed().as_millis() as u64, line.clone()));
                }
            }
        }
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut File::from(err_r), &mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });
    let mut lines: Vec<(u64, String)> = Vec::new();
    let mut cg = Some(cg);
    let mut cap_hit = false;
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
        if destroyed.is_none()
            && lines
                .iter()
                .any(|(_, l)| l.contains("BONELI_PROBE loop_ms="))
            && let Some(c) = cg.take()
        {
            stop.store(true, Ordering::Relaxed);
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
    let probe = |k: &str| -> Option<(u64, String)> {
        lines.iter().rev().find_map(|(at, l)| {
            let i = l.find("BONELI_PROBE ")?;
            let rest = &l[i + "BONELI_PROBE ".len()..];
            let (key, v) = rest.split_once('=')?;
            (key == k).then(|| (*at, v.trim().to_string()))
        })
    };
    let progress: Vec<String> = lines
        .iter()
        .filter_map(|(_, l)| {
            let i = l.find("BONELI_PROBE progress=")?;
            Some(l[i + "BONELI_PROBE progress=".len()..].trim().to_string())
        })
        .collect();
    let oom_kill: u64 = keyed_or(&events, "oom_kill").parse().unwrap_or(0);
    let killed = oom_kill >= 1
        || (destroyed.is_none() && !cap_hit && status == ExitStatus::Signaled(libc::SIGKILL));
    let loop_start = probe("loop_start").map(|(at, _)| at);
    report(&format!(
        "diag_54 {tag}: memory.max {} MiB, wbps {}, write {} MiB, T {}, dev {}:{}: status {status:?} at {ms} ms{}, \
         killed {killed} (oom_kill {oom_kill}, max {}), loop_start at {} ms, loop_ms {}, kill after loop_start {}, \
         {}, io.stat [{}], destroy {}, progress [{}], stderr {:?}",
        memory_max / MIB,
        wbps.map_or("none".to_string(), |w| format!("{} MiB/s", w / MIB)),
        size / MIB,
        period.map_or("none".to_string(), |p| format!("{p} ms")),
        dev.major,
        dev.minor,
        if cap_hit { " (cap hit)" } else { "" },
        keyed_or(&events, "max"),
        loop_start.map_or("none".to_string(), |a| a.to_string()),
        probe("loop_ms").map_or("none".to_string(), |(_, v)| v),
        match (killed, loop_start) {
            (true, Some(a)) => format!("{} ms", ms.saturating_sub(a)),
            _ => "n/a".to_string(),
        },
        reads.map_or("reads none".to_string(), |r| r.text()),
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
    if let Some(c) = cg {
        let _ = c.destroy();
    }
    drop(fixture);
    killed
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
    let active = reader(C_PERIOD, start_rx, stop.clone());
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
    let idle = reader(C_PERIOD, idle_rx, stop.clone());
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

#[test]
#[ignore = "host: diagnostic for #54"]
fn buffered_sweep() {
    if std::env::var("BONELI_SYS_DIAG_54").as_deref() != Ok("1") {
        return;
    }
    let _alone = support::exclusive();
    host_facts();
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
                .filter(|r| run_write(&name, *r, m, Some(w), s, t))
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
            .filter(|r| run_write(&name, *r, 256 * MIB, None, 512 * MIB, Some(t)))
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
