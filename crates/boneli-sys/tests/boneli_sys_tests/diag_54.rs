//! Temporary (#54, M1 of the second PR; removed before the PR leaves
//! draft): why a buffered writer under `io.max` is OOM-killed on the 7.0
//! kernels of CI, and which `memory.high` band holds it. No assertions:
//! every run prints one report line, and the PR records the results.
//!
//! Runs only with `BONELI_SYS_DIAG_54=1`; with `BONELI_SYS_DIAG_54_TRACE=1`
//! (the temporary `diag-54` CI job only) it also records kernel trace
//! events through `sudo -n`.

use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use boneli_sys::{
    CpuMax, DeviceNumber, ExitStatus, IoLimits, IoMax, Limits, Mount, Root, Spec, Stdio,
    block_device_of, spawn,
};

use crate::support::cgroup::{self, read};
use crate::support::rootfs::{Fixture, inside};
use crate::support::{self, dev_null, ids, report};

const MIB: u64 = 1 << 20;
const BANDS: [u64; 3] = [2, 5, 15];
const RUNS: u32 = 3;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reads {
    /// The host only waits on the child.
    None,
    /// `memory.current`, `memory.events`, `io.stat` every 50 ms.
    NonFlush,
    /// The sandbox's `memory.stat` every 50 ms.
    OwnStat,
    /// The parent's `memory.stat` every 50 ms.
    ParentStat,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Work {
    /// The probe's `never` writer; `destroy` right after its loop when set.
    Write { size: u64, destroy_after_loop: bool },
    /// The probe's `oom` action, touching twice `memory.max`.
    Anon,
}

#[derive(Clone, Debug)]
struct Arm {
    name: String,
    memory_max: u64,
    /// The `memory.high` band in percent of `memory.max`; `None` is `max`.
    band: Option<u64>,
    wbps: Option<u64>,
    work: Work,
    reads: Reads,
    trace: bool,
    cap: Duration,
}

/// What the driver needs from one run.
#[derive(Clone, Copy, Debug)]
struct Outcome {
    #[allow(dead_code)]
    killed: bool,
    held: bool,
    ms: u64,
    cap_hit: bool,
}

fn page() -> u64 {
    // SAFETY: sysconf takes a plain name.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 { n as u64 } else { 4096 }
}

/// The plan's ceiling: floor_page(m - ceil(m x pct / 100)), m the
/// page-rounded `memory.max`.
fn ceiling(memory_max: u64, pct: u64, page: u64) -> u64 {
    let m = (memory_max / page * page) as u128;
    let band = (m * pct as u128).div_ceil(100);
    let c = (m - band) as u64;
    c / page * page
}

fn file_or(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| format!("unreadable ({e})"))
}

fn vmstat() -> Vec<(String, u64)> {
    let text = file_or("/proc/vmstat");
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(' ')?;
            Some((k.to_string(), v.trim().parse().ok()?))
        })
        .collect()
}

fn vm(stat: &[(String, u64)], key: &str) -> u64 {
    stat.iter().find(|(k, _)| k == key).map_or(0, |(_, v)| *v)
}

fn field(line: &str, key: &str) -> u64 {
    line.split_whitespace()
        .find_map(|f| f.strip_prefix(key)?.strip_prefix('='))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// `io.stat` lines with the bio size at dispatch (`wbytes / wios`).
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

/// Root `io.stat` wbytes per device line.
fn root_wbytes() -> Vec<(String, u64)> {
    let text = file_or("/sys/fs/cgroup/io.stat");
    text.lines()
        .filter_map(|l| {
            let dev = l.split_whitespace().next()?.to_string();
            Some((dev, field(l, "wbytes")))
        })
        .collect()
}

fn root_delta(before: &[(String, u64)], after: &[(String, u64)]) -> String {
    after
        .iter()
        .filter_map(|(d, a)| {
            let b = before.iter().find(|(x, _)| x == d).map_or(0, |(_, v)| *v);
            (a > &b).then(|| format!("{d}:+{}", a - b))
        })
        .collect::<Vec<_>>()
        .join(" ")
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

const EVENTS: [&str; 5] = [
    "writeback/balance_dirty_pages",
    "vmscan/mm_vmscan_lru_shrink_inactive",
    "vmscan/mm_vmscan_throttled",
    "vmscan/mm_vmscan_memcg_reclaim_end",
    "oom/mark_victim",
];

const TRACE_DIR: &str =
    "T=/sys/kernel/tracing; [ -e $T/trace ] || T=/sys/kernel/debug/tracing; [ -e $T/trace ]";

fn trace_wanted() -> bool {
    std::env::var("BONELI_SYS_DIAG_54_TRACE").as_deref() == Ok("1")
}

fn trace_start() -> Result<(), String> {
    let mut s = format!(
        "set -e; {TRACE_DIR}; echo 0 > $T/tracing_on; echo 0 > $T/options/overwrite; \
         echo 8192 > $T/buffer_size_kb; "
    );
    for e in EVENTS {
        s.push_str(&format!("echo 1 > $T/events/{e}/enable; "));
    }
    s.push_str("echo > $T/trace; echo 1 > $T/tracing_on");
    sudo_sh(&s).map(|_| ())
}

fn trace_stop() -> Result<String, String> {
    let mut s = format!("set -e; {TRACE_DIR}; echo 0 > $T/tracing_on; ");
    for e in EVENTS {
        s.push_str(&format!("echo 0 > $T/events/{e}/enable; "));
    }
    s.push_str(
        "echo \"dropped $(cat $T/per_cpu/cpu*/stats | awk '/^(overrun|dropped events):/ { n += $NF } END { print n + 0 }')\"; \
         cat $T/trace; echo > $T/trace",
    );
    sudo_sh(&s)
}

fn clip(s: &str) -> String {
    let t = s.trim();
    if t.len() > 260 {
        let mut end = 260;
        while !t.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &t[..end])
    } else {
        t.to_string()
    }
}

fn trace_summary(tag: &str, text: &str, ino: u64) {
    let dropped = text
        .lines()
        .find_map(|l| l.strip_prefix("dropped "))
        .unwrap_or("?")
        .to_string();
    let mine = format!("cgroup_ino={ino}");
    for e in EVENTS {
        let name = e.split('/').nth(1).unwrap_or(e);
        let key = format!(" {name}: ");
        let all: Vec<&str> = text.lines().filter(|l| l.contains(&key)).collect();
        let mut extra = String::new();
        if name == "balance_dirty_pages" {
            let own: Vec<&&str> = all.iter().filter(|l| l.contains(&mine)).collect();
            extra = format!(
                ", for the sandbox ({mine}) {}, first [{}], last [{}]",
                own.len(),
                own.first().map_or(String::new(), |l| clip(l)),
                own.last().map_or(String::new(), |l| clip(l))
            );
        }
        if name == "mm_vmscan_lru_shrink_inactive" {
            let sums: Vec<String> = [
                "nr_scanned",
                "nr_reclaimed",
                "nr_dirty",
                "nr_writeback",
                "nr_congested",
                "nr_immediate",
            ]
            .iter()
            .map(|k| format!("{k} {}", all.iter().map(|l| field(l, k)).sum::<u64>()))
            .collect();
            extra = format!(", sums: {}", sums.join(" "));
        }
        report(&format!(
            "diag_54 trace {tag}: {name} {} (dropped {dropped}){extra}, first [{}], last [{}]",
            all.len(),
            all.first().map_or(String::new(), |l| clip(l)),
            all.last().map_or(String::new(), |l| clip(l))
        ));
    }
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

fn wbps_text(w: Option<u64>) -> String {
    w.map_or("none".to_string(), |w| format!("{} MiB/s", w / MIB))
}

/// One run of `arm`; prints its report line.
fn run_arm(arm: &Arm, run: u32) -> Outcome {
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
    let high = arm.band.map(|b| ceiling(arm.memory_max, b, page()));
    if let Some(h) = high {
        std::fs::write(cg.path().join("memory.high"), h.to_string()).expect("write memory.high");
    }
    let high_read = read(&cg, "memory.high").trim().to_string();
    let ino = std::fs::metadata(cg.path()).map_or(0, |m| m.ino());
    let (out_r, out_w) = support::pipe();
    let (err_r, err_w) = support::pipe();
    let size_text;
    let env: Vec<(&str, &str)> = match arm.work {
        Work::Write { size, .. } => {
            size_text = size.to_string();
            vec![
                (support::probe::ACTION_VAR, "io-write"),
                ("BONELI_PROBE_FILE", "/workspace/buffered"),
                ("BONELI_PROBE_SIZE", size_text.as_str()),
                ("BONELI_PROBE_DIRECT", "never"),
            ]
        }
        Work::Anon => {
            size_text = (2 * arm.memory_max).to_string();
            vec![
                (support::probe::ACTION_VAR, "oom"),
                ("BONELI_PROBE_SIZE", size_text.as_str()),
            ]
        }
    };
    let s = Spec {
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
        root: root_with_cgroup(&fixture),
        cgroup: &cg,
    };
    let tracing = arm.trace && trace_wanted();
    let trace_state = if tracing {
        trace_start().err()
    } else {
        Some("not requested".to_string())
    };
    let vm0 = vmstat();
    let root0 = root_wbytes();
    let start = Instant::now();
    let mut child = spawn(&s).expect("spawn the probe");
    drop(s);
    let (tx, rx) = mpsc::channel::<(u64, String)>();
    let out_reader = std::thread::spawn(move || {
        use std::io::BufRead;
        let mut r = std::io::BufReader::new(std::fs::File::from(out_r));
        let mut line = String::new();
        loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let _ = tx.send((start.elapsed().as_millis() as u64, line.clone()));
                }
            }
        }
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut std::fs::File::from(err_r), &mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });
    let destroy_after_loop = matches!(
        arm.work,
        Work::Write {
            destroy_after_loop: true,
            ..
        }
    );
    let period = match (arm.reads, destroy_after_loop) {
        (Reads::None, true) => Duration::from_millis(10),
        (Reads::None, false) => Duration::from_millis(200),
        _ => Duration::from_millis(50),
    };
    let parent_stat = cgroup::parent().path().join("memory.stat");
    let mut lines: Vec<(u64, String)> = Vec::new();
    let mut cg = Some(cg);
    let mut host_reads = 0u64;
    let mut cap_hit = false;
    let mut destroyed: Option<(u64, Duration, String, String)> = None;
    let mut events_at_destroy = String::new();
    loop {
        let mut pfd = libc::pollfd {
            fd: child.pidfd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, period.as_millis() as i32) };
        if rc > 0 {
            break;
        }
        while let Ok(l) = rx.try_recv() {
            lines.push(l);
        }
        if let Some(c) = &cg {
            if start.elapsed() >= arm.cap && !cap_hit {
                cap_hit = true;
                let _ = std::fs::write(c.path().join("cgroup.kill"), "1");
            }
            match arm.reads {
                Reads::None => {}
                Reads::NonFlush => {
                    for f in ["memory.current", "memory.events", "io.stat"] {
                        let _ = std::fs::read_to_string(c.path().join(f));
                    }
                    host_reads += 1;
                }
                Reads::OwnStat => {
                    let _ = std::fs::read_to_string(c.path().join("memory.stat"));
                    host_reads += 1;
                }
                Reads::ParentStat => {
                    let _ = std::fs::read_to_string(&parent_stat);
                    host_reads += 1;
                }
            }
        }
        if destroy_after_loop
            && destroyed.is_none()
            && lines
                .iter()
                .any(|(_, l)| l.contains("BONELI_PROBE loop_ms="))
            && let Some(c) = cg.take()
        {
            let at = start.elapsed().as_millis() as u64;
            let events = read(&c, "memory.events");
            events_at_destroy = events.clone();
            let stat = read(&c, "io.stat");
            let ms = read(&c, "memory.stat");
            let backlog = keyed_or(&ms, "file_dirty").parse::<u64>().unwrap_or(0)
                + keyed_or(&ms, "file_writeback").parse::<u64>().unwrap_or(0);
            let before = vmstat();
            let root_before = root_wbytes();
            let t = Instant::now();
            let r = c.destroy();
            let took = t.elapsed();
            drain(&tag, &before, &root_before, backlog, t, took, dev);
            destroyed = Some((
                at,
                took,
                format!("{r:?}"),
                format!("{events:?} io.stat [{}]", io_lines(&stat)),
            ));
        }
    }
    let ms = start.elapsed().as_millis() as u64;
    let status = child.wait().expect("wait for the probe");
    out_reader.join().expect("stdout reader");
    while let Ok(l) = rx.try_recv() {
        lines.push(l);
    }
    let stderr = err_reader.join().unwrap_or_default();
    let trace_text = if tracing && trace_state.is_none() {
        Some(trace_stop())
    } else {
        None
    };
    let vm1 = vmstat();
    let root1 = root_wbytes();
    let probe = |k: &str| -> Option<String> {
        lines.iter().rev().find_map(|(_, l)| {
            let at = l.find("BONELI_PROBE ")?;
            let rest = &l[at + "BONELI_PROBE ".len()..];
            let (key, v) = rest.split_once('=')?;
            (key == k).then(|| v.trim().to_string())
        })
    };
    let progress: Vec<String> = lines
        .iter()
        .filter_map(|(_, l)| {
            let at = l.find("BONELI_PROBE progress=")?;
            Some(l[at + "BONELI_PROBE progress=".len()..].trim().to_string())
        })
        .collect();
    let (events, mstat, io_stat) = match &cg {
        Some(c) => (
            read(c, "memory.events"),
            read(c, "memory.stat"),
            read(c, "io.stat"),
        ),
        None => (events_at_destroy.clone(), String::new(), String::new()),
    };
    let ev = |k: &str| {
        events
            .lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix(' '))
            .map_or("?".to_string(), |v| v.trim().to_string())
    };
    let oom_kill: u64 = ev("oom_kill").parse().unwrap_or(0);
    let killed = oom_kill >= 1
        || (destroyed.is_none() && !cap_hit && status == ExitStatus::Signaled(libc::SIGKILL));
    let loop_ms: Option<u64> = probe("loop_ms").and_then(|v| v.parse().ok());
    let bound = match arm.work {
        Work::Write { size, .. } => arm.wbps.map_or(0, |w| {
            (size.saturating_sub(arm.memory_max) * 1000 / w).saturating_sub(500)
        }),
        Work::Anon => 0,
    };
    let held = !killed && loop_ms.is_some_and(|l| l >= bound);
    let ms_key = |k: &str| keyed_or(&mstat, k);
    let vmd = |k: &str| vm(&vm1, k).saturating_sub(vm(&vm0, k));
    let work = match arm.work {
        Work::Write { size, .. } => format!("write {} MiB", size / MIB),
        Work::Anon => format!("anon touch {} MiB", 2 * arm.memory_max / MIB),
    };
    report(&format!(
        "diag_54 {tag}: memory.max {} MiB, memory.high {high_read}, wbps {}, {work}, reads {:?} ({host_reads}), dev {}:{}: \
         status {status:?} at {ms} ms{}, killed {killed}, held {held} (loop bound {bound}), loop_ms {}, elapsed_ms {}, \
         loop_file_dirty {}, loop_file_writeback {}, loop_io_stat [{}], \
         memory.events max {} high {} oom {} oom_kill {} oom_group_kill {}, \
         memory.stat after file_dirty {} file_writeback {} file {} anon {}, io.stat [{}], root io.stat delta [{}], \
         vmstat nr_dirty {}->{} nr_writeback {}->{} delta pgscan_direct {} pgsteal_direct {} nr_vmscan_write {} nr_vmscan_immediate_reclaim {}, \
         destroy {}, progress [{}], trace {}, stderr {:?}",
        arm.memory_max / MIB,
        wbps_text(arm.wbps),
        arm.reads,
        dev.major,
        dev.minor,
        if cap_hit {
            " (cap hit, killed by the host)"
        } else {
            ""
        },
        probe("loop_ms").unwrap_or("none".into()),
        probe("elapsed_ms").unwrap_or("none".into()),
        probe("loop_file_dirty").unwrap_or("none".into()),
        probe("loop_file_writeback").unwrap_or("none".into()),
        probe("loop_io_stat").unwrap_or_default(),
        ev("max"),
        ev("high"),
        ev("oom"),
        ev("oom_kill"),
        ev("oom_group_kill"),
        ms_key("file_dirty"),
        ms_key("file_writeback"),
        ms_key("file"),
        ms_key("anon"),
        io_lines(&io_stat),
        root_delta(&root0, &root1),
        vm(&vm0, "nr_dirty"),
        vm(&vm1, "nr_dirty"),
        vm(&vm0, "nr_writeback"),
        vm(&vm1, "nr_writeback"),
        vmd("pgscan_direct"),
        vmd("pgsteal_direct"),
        vmd("nr_vmscan_write"),
        vmd("nr_vmscan_immediate_reclaim"),
        destroyed
            .as_ref()
            .map_or("none".to_string(), |(at, took, r, e)| format!(
                "at {at} ms took {took:?}: {r}, before it {e}"
            )),
        progress.join(" "),
        match (&trace_state, &trace_text) {
            (Some(why), _) => format!("unavailable ({why})"),
            (None, Some(Err(e))) => format!("unavailable ({e})"),
            (None, Some(Ok(_))) => format!("recorded, cgroup_ino {ino}"),
            (None, None) => "none".to_string(),
        },
        stderr
            .lines()
            .filter(|l| l.contains("probe:") || l.contains("panicked"))
            .collect::<Vec<_>>()
    ));
    if let Some(Ok(text)) = &trace_text {
        trace_summary(&tag, text, ino);
    }
    if let Some(c) = cg {
        let _ = c.destroy();
    }
    drop(fixture);
    Outcome {
        killed,
        held,
        ms,
        cap_hit,
    }
}

fn keyed_or(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
        .map_or("?".to_string(), |v| v.trim().to_string())
}

/// Right after a `destroy` that left the writer's page cache behind: how
/// long the host's dirty and writeback pages take to fall by 90 % of
/// the sandbox's backlog (its `file_dirty + file_writeback` before the
/// destroy; 90 % because other writers on the host move the total), sampled every 10 ms from the start of the
/// destroy for at most 120 s, with the root `io.stat` wbytes over the
/// window.
fn drain(
    tag: &str,
    before: &[(String, u64)],
    root0: &[(String, u64)],
    backlog: u64,
    t0: Instant,
    took: Duration,
    dev: DeviceNumber,
) {
    let p = page();
    let base = (vm(before, "nr_dirty") + vm(before, "nr_writeback")) * p;
    let target = base.saturating_sub(backlog / 10 * 9);
    let mut samples = Vec::new();
    let mut next = 0u64;
    let end_ms = loop {
        let v = vmstat();
        let bytes = (vm(&v, "nr_dirty") + vm(&v, "nr_writeback")) * p;
        let ms = t0.elapsed().as_millis() as u64;
        if ms >= next {
            samples.push(format!("{}:{}", ms / 100, bytes / MIB));
            next += 100;
        }
        if bytes <= target || ms >= 120_000 {
            break ms;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let root1 = root_wbytes();
    report(&format!(
        "diag_54 drain {tag}: sandbox backlog {} MiB, host dirty+writeback {} MiB before the destroy, destroy took {took:?}, \
         at or under {} MiB after {end_ms} ms from the destroy's start, root io.stat delta [{}] (dev {}:{}), samples (100 ms:MiB) [{}]",
        backlog / MIB,
        base / MIB,
        target / MIB,
        root_delta(root0, &root1),
        dev.major,
        dev.minor,
        samples.join(" ")
    ));
}
fn write_arm(name: &str, memory_max: u64, band: Option<u64>, wbps: Option<u64>, size: u64) -> Arm {
    Arm {
        name: name.to_string(),
        memory_max,
        band,
        wbps,
        work: Work::Write {
            size,
            destroy_after_loop: false,
        },
        reads: Reads::None,
        trace: false,
        cap: Duration::from_secs(150),
    }
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
        "diag_54 host: kernel {}, page {}, nproc {}, {mem}, vm.dirty_ratio {} dirty_background_ratio {} dirty_bytes {} \
         dirty_background_bytes {} dirty_expire_centisecs {} dirty_writeback_centisecs {}, lockdown {}, trace wanted {}",
        k("/proc/sys/kernel/osrelease"),
        page(),
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        k("/proc/sys/vm/dirty_ratio"),
        k("/proc/sys/vm/dirty_background_ratio"),
        k("/proc/sys/vm/dirty_bytes"),
        k("/proc/sys/vm/dirty_background_bytes"),
        k("/proc/sys/vm/dirty_expire_centisecs"),
        k("/proc/sys/vm/dirty_writeback_centisecs"),
        k("/sys/kernel/security/lockdown"),
        trace_wanted()
    ));
}

fn runs(arm: &Arm, skip_over: Option<u64>) -> Vec<Outcome> {
    let mut out = Vec::new();
    // BONELI_SYS_DIAG_54_ONLY: a comma-separated list of arm names to run.
    if let Ok(only) = std::env::var("BONELI_SYS_DIAG_54_ONLY")
        && !only.split(',').any(|n| n == arm.name)
    {
        return out;
    }
    let runs: u32 = std::env::var("BONELI_SYS_DIAG_54_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(RUNS);
    for run in 1..=runs {
        let o = run_arm(arm, run);
        out.push(o);
        if let Some(limit) = skip_over
            && (o.ms > limit || o.cap_hit)
        {
            report(&format!(
                "diag_54 {}: runs after {run} skipped: {} ms is over {limit} ms",
                arm.name, o.ms
            ));
            break;
        }
    }
    out
}

#[test]
#[ignore = "host: diagnostic for #54"]
fn buffered_sweep() {
    if std::env::var("BONELI_SYS_DIAG_54").as_deref() != Ok("1") {
        return;
    }
    let _alone = support::exclusive();
    host_facts();
    for pct in BANDS {
        report(&format!(
            "diag_54 band {pct}%: memory.high at 32 MiB {}, 64 MiB {}, 256 MiB {}, 2 GiB {}",
            ceiling(32 * MIB, pct, page()),
            ceiling(64 * MIB, pct, page()),
            ceiling(256 * MIB, pct, page()),
            ceiling(2048 * MIB, pct, page())
        ));
    }
    let m = 256 * MIB;
    let w = Some(32 * MIB);
    let s = 512 * MIB;
    // M1a: the cause.
    let mut a0 = write_arm("A0", m, None, w, s);
    a0.trace = true;
    let mut a1 = write_arm("A1", m, None, w, s);
    a1.reads = Reads::NonFlush;
    let mut a2 = write_arm("A2", m, None, w, s);
    a2.reads = Reads::OwnStat;
    let mut a3 = write_arm("A3", m, None, w, s);
    a3.reads = Reads::ParentStat;
    for arm in [&a0, &a1, &a2, &a3, &write_arm("N0", m, None, None, s)] {
        runs(arm, None);
    }
    // M1a: the bands.
    let mut local = None;
    for pct in BANDS {
        let mut b = write_arm(&format!("B{pct}"), m, Some(pct), w, s);
        b.trace = true;
        let o = runs(&b, None);
        let all = o.iter().all(|o| o.held);
        report(&format!(
            "diag_54 B{pct}: held in {} of {}",
            o.iter().filter(|o| o.held).count(),
            o.len()
        ));
        if all && local.is_none() {
            local = Some(pct);
        }
    }
    report(&format!("diag_54 local b*: {local:?}"));
    // M1a: AWS writeback.
    runs(
        &write_arm("W1", 1024 * MIB, None, Some(8 * MIB), 64 * MIB),
        None,
    );
    // M1b: the runaway's crawl, every band.
    for size in [32 * MIB, 2048 * MIB] {
        for band in [None, Some(2), Some(5), Some(15)] {
            let arm = Arm {
                name: format!(
                    "X{}@{}MiB",
                    band.map_or("0".to_string(), |b| format!("-{b}")),
                    size / MIB
                ),
                memory_max: size,
                band,
                wbps: None,
                work: Work::Anon,
                reads: Reads::None,
                trace: false,
                cap: Duration::from_secs(180),
            };
            runs(&arm, Some(30_000));
        }
    }
    // M1b: the bands without io.max and at the small size.
    for pct in BANDS {
        runs(&write_arm(&format!("N-{pct}"), m, Some(pct), None, s), None);
    }
    for band in [None, Some(2), Some(5), Some(15)] {
        let mut arm = write_arm(
            &format!("S{}", band.map_or("0".to_string(), |b| format!("-{b}"))),
            64 * MIB,
            band,
            Some(4 * MIB),
            96 * MIB,
        );
        arm.work = Work::Write {
            size: 96 * MIB,
            destroy_after_loop: true,
        };
        runs(&arm, None);
    }
    // M1a: the release after the lift.
    let mut w2 = write_arm("W2", 1024 * MIB, None, Some(8 * MIB), 512 * MIB);
    w2.work = Work::Write {
        size: 512 * MIB,
        destroy_after_loop: true,
    };
    runs(&w2, None);
    report("diag_54 done");
}
