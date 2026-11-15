//! cgroups v2 (ADR-007, D8): delegation, limits written before any
//! process enters, the limits holding, the cgroup namespace rooted at the
//! sandbox's cgroup, and cleanup.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use boneli_sys::{
    Cgroup, CpuMax, Error, ExitStatus, IoLimits, IoMax, Limits, Mount, Parent, Root, Spec, Stdio,
    Step, block_device_of, spawn,
};

use crate::support::cgroup::{self, keyed, read};
use crate::support::rootfs::{Fixture, inside};
use crate::support::{self, dev_null, ids, report, run_probe_in, wait_bounded};

/// The default fixture mounts plus the sandbox's cgroup, read-only at
/// `/sys/fs/cgroup`.
fn root_with_cgroup(fixture: &Fixture) -> Root {
    let mut mounts = fixture.mounts();
    mounts.push(Mount::Cgroup2 {
        target: inside("/sys/fs/cgroup"),
    });
    fixture.root_with(vec![fixture.layer.clone()], mounts)
}

fn spec<'a>(root: Root, cgroup: &'a Cgroup, program: &str, args: &[&str]) -> Spec<'a> {
    Spec {
        program: PathBuf::from(program),
        args: args.iter().map(OsString::from).collect(),
        env: Vec::new(),
        stdio: Stdio {
            stdin: dev_null(),
            stdout: dev_null(),
            stderr: dev_null(),
        },
        ids: ids(0, 0),
        setup_timeout: support::SETUP_TIMEOUT,
        root,
        cgroup,
    }
}

fn limits(memory_max: u64, pids_max: u64, cpu: (u64, u64), io: IoLimits) -> Limits {
    Limits {
        memory_max,
        memory_swap_max: 0,
        pids_max,
        cpu: CpuMax {
            quota_us: cpu.0,
            period_us: cpu.1,
        },
        io,
    }
}

fn populated(cg: &Cgroup) -> u64 {
    keyed(&read(cg, "cgroup.events"), "populated")
}

#[test]
#[ignore = "host: cgroup v2 delegation (cpu, io, memory, pids)"]
fn limit_files_render_and_read_back() {
    // 33554433 is one byte over 32 MiB: the kernel rounds memory limits
    // down to a page, and create's read-back accepts exactly that.
    let cg = cgroup::create(
        "render",
        &limits(33_554_433, 7, (50_000, 100_000), IoLimits::none()),
    );
    assert_eq!(read(&cg, "memory.max").trim(), "33554432");
    assert_eq!(read(&cg, "cpu.max").trim(), "50000 100000");
    assert_eq!(read(&cg, "pids.max").trim(), "7");
    cg.destroy().expect("destroy");
    // The IO line, on the device behind the target dir, in the kernel's
    // own rendering (unset fields are `max`).
    let tree = crate::support::rootfs::Tree::new("render-io");
    let dev = block_device_of(tree.path()).expect("a block device behind the target dir");
    let io = IoLimits::new(vec![IoMax {
        dev,
        rbps: None,
        wbps: Some(4_194_304),
        riops: None,
        wiops: None,
    }])
    .expect("one device");
    let cg = cgroup::create("render-io", &limits(64 << 20, 8, (100_000, 100_000), io));
    assert_eq!(
        read(&cg, "io.max").trim(),
        format!(
            "{}:{} rbps=max wbps=4194304 riops=max wiops=max",
            dev.major, dev.minor
        )
    );
    cg.destroy().expect("destroy");
}

#[test]
#[ignore = "host: cgroup v2 delegation (cpu, io, memory, pids), user namespaces"]
fn limits_written_before_entry() {
    let tree = crate::support::rootfs::Tree::new("before-entry");
    let dev = block_device_of(tree.path()).expect("a block device behind the target dir");
    let io = IoLimits::new(vec![IoMax {
        dev,
        rbps: Some(10_485_760),
        wbps: Some(5_242_880),
        riops: None,
        wiops: Some(1000),
    }])
    .expect("one device");
    let mut l = limits(48 << 20, 17, (30_000, 60_000), io);
    l.memory_swap_max = 1 << 20;
    let cg = cgroup::create("before-entry", &l);
    // Nothing has entered yet, and every limit is already in place.
    assert_eq!(read(&cg, "cgroup.procs").trim(), "", "no process yet");
    assert_eq!(populated(&cg), 0);
    assert_eq!(read(&cg, "memory.max").trim(), (48u64 << 20).to_string());
    assert_eq!(
        read(&cg, "memory.swap.max").trim(),
        (1u64 << 20).to_string()
    );
    assert_eq!(read(&cg, "memory.oom.group").trim(), "1");
    assert_eq!(read(&cg, "cgroup.max.descendants").trim(), "0");
    assert_eq!(read(&cg, "cgroup.max.depth").trim(), "0");
    assert_eq!(read(&cg, "pids.max").trim(), "17");
    assert_eq!(read(&cg, "cpu.max").trim(), "30000 60000");
    assert_eq!(
        read(&cg, "io.max").trim(),
        format!(
            "{}:{} rbps=10485760 wbps=5242880 riops=max wiops=1000",
            dev.major, dev.minor
        )
    );
    // And the workload starts inside them: the probe reads its own view.
    let fixture = Fixture::new("before-entry");
    let p = run_probe_in(
        "read",
        ids(0, 0),
        &[("BONELI_PROBE_FILES", "/sys/fs/cgroup/pids.max")],
        root_with_cgroup(&fixture),
        &cg,
    );
    p.assert_ok();
    assert_eq!(
        p.get("file:/sys/fs/cgroup/pids.max").trim(),
        "17",
        "{}",
        p.raw
    );
    cg.destroy().expect("destroy");
}

#[test]
#[ignore = "host: cgroup v2 delegation (memory), user namespaces"]
fn memory_limit_kills_whole_group() {
    // memory.max 32 MiB without swap; PID 1 of the sandbox forks a child
    // that touches 64 MiB (twice the limit) one byte per page and waits.
    // With memory.oom.group the OOM kill takes PID 1 too; without it only
    // the child would die and PID 1 would exit 0.
    let mut l = limits(32 << 20, 16, (100_000, 100_000), IoLimits::none());
    l.memory_swap_max = 0;
    let cg = cgroup::create("oom", &l);
    let fixture = Fixture::new("oom");
    let p = run_probe_in(
        "oom",
        ids(0, 0),
        &[("BONELI_PROBE_SIZE", &(64u64 << 20).to_string())],
        fixture.root(),
        &cg,
    );
    assert_eq!(
        p.status,
        ExitStatus::Signaled(libc::SIGKILL),
        "PID 1 was not killed with its child: {}",
        p.raw
    );
    let events = read(&cg, "memory.events");
    assert!(keyed(&events, "oom_group_kill") >= 1, "{events}");
    assert!(keyed(&events, "oom_kill") >= 2, "both processes: {events}");
    cg.destroy().expect("destroy");
}

#[test]
#[ignore = "host: cgroup v2 delegation (pids), user namespaces"]
fn pids_limit_exact() {
    let cg = cgroup::create(
        "pids",
        &limits(256 << 20, 8, (100_000, 100_000), IoLimits::none()),
    );
    let fixture = Fixture::new("pids");
    let p = run_probe_in("pids", ids(0, 0), &[], fixture.root(), &cg);
    p.assert_ok();
    // pids.max counts tasks, and libtest may run the probe on a thread.
    let threads: u64 = p.get("threads").parse().expect("threads");
    assert!((1..8).contains(&threads), "{}", p.raw);
    assert_eq!(
        p.get("children"),
        (8 - threads).to_string(),
        "exactly 8 - T children: {}",
        p.raw
    );
    assert_eq!(p.get("fork_errno"), libc::EAGAIN.to_string(), "{}", p.raw);
    cg.destroy().expect("destroy");
}

#[test]
#[ignore = "host: cgroup v2 delegation (cpu), user namespaces; timing"]
fn cpu_limit_throttles() {
    // Half a CPU. The probe spins on four threads for 1.0 s of wall time
    // and reads its own cpu.stat before and after. 650,000 = 500,000
    // (0.5 x 1 s) + 100,000 (the window can straddle one period refill) +
    // 50,000 accounting slack. The quota caps the whole cgroup, so the
    // bound does not depend on the thread count; four threads demand four
    // CPUs, so a loaded host that gives the probe less than a whole one
    // still lets it reach the quota (one thread got 0.3 CPU on the loaded
    // dev host, two threads 0.27-0.40 CPU under other sessions' load,
    // measured). A run with nr_throttled 0 and usage below 500,000 never
    // reached the quota: the host starved it, which proves nothing either
    // way, so it is retried, up to 3 attempts in all; three starved
    // attempts fail with that reason, never pass. Any other run decides.
    // The run excludes the other sandbox runs of this binary.
    let _alone = support::exclusive();
    let cg = cgroup::create(
        "cpu",
        &limits(256 << 20, 16, (50_000, 100_000), IoLimits::none()),
    );
    let fixture = Fixture::new("cpu");
    let mut starved = Vec::new();
    for attempt in 1..=CPU_ATTEMPTS {
        let p = run_probe_in(
            "spin",
            ids(0, 0),
            &[("BONELI_PROBE_MS", "1000"), ("BONELI_PROBE_THREADS", "4")],
            root_with_cgroup(&fixture),
            &cg,
        );
        p.assert_ok();
        let usage: u64 = p.get("usage_usec").parse().expect("usage_usec");
        let throttled: u64 = p.get("nr_throttled").parse().expect("nr_throttled");
        report(&format!(
            "cpu_limit_throttles: attempt {attempt}: usage_usec {usage} (bound 650000, margin {}), nr_throttled {throttled}",
            650_000i64 - usage as i64
        ));
        match cpu_verdict(usage, throttled) {
            CpuVerdict::Starved => starved.push(usage),
            CpuVerdict::Held => {
                cg.destroy().expect("destroy");
                return;
            }
            CpuVerdict::Exceeded => panic!(
                "the probe used {usage} us of CPU in 1 s, over the 650,000 bound: {}",
                p.raw
            ),
            CpuVerdict::NotThrottled => panic!(
                "the probe used {usage} us, at least the quota, and was never throttled: {}",
                p.raw
            ),
        }
    }
    panic!(
        "host starved the probe: {CPU_ATTEMPTS} attempts never reached the 0.5 CPU quota \
         (usage_usec {starved:?}, nr_throttled 0 each), so the limit was not tested; \
         rerun on a host with half a CPU to spare"
    );
}

/// Attempts of `cpu_limit_throttles` before a starved host fails it.
const CPU_ATTEMPTS: usize = 3;

/// What one `cpu_limit_throttles` run shows.
#[derive(Debug, PartialEq, Eq)]
enum CpuVerdict {
    /// Throttled, within the bound: the limit holds.
    Held,
    /// Over the bound: the limit does not hold.
    Exceeded,
    /// At least the quota used and never throttled: the limit does not hold.
    NotThrottled,
    /// Never throttled and under the quota: the host gave the probe less
    /// than the limit, so the run says nothing.
    Starved,
}

fn cpu_verdict(usage_usec: u64, nr_throttled: u64) -> CpuVerdict {
    if usage_usec > 650_000 {
        CpuVerdict::Exceeded
    } else if nr_throttled >= 1 {
        CpuVerdict::Held
    } else if usage_usec < 500_000 {
        CpuVerdict::Starved
    } else {
        CpuVerdict::NotThrottled
    }
}

#[test]
fn cpu_verdicts() {
    assert_eq!(cpu_verdict(521_330, 10), CpuVerdict::Held);
    assert_eq!(cpu_verdict(650_000, 1), CpuVerdict::Held);
    assert_eq!(cpu_verdict(650_001, 10), CpuVerdict::Exceeded);
    assert_eq!(cpu_verdict(1_000_000, 0), CpuVerdict::Exceeded);
    assert_eq!(cpu_verdict(368_488, 0), CpuVerdict::Starved);
    assert_eq!(cpu_verdict(499_999, 0), CpuVerdict::Starved);
    assert_eq!(cpu_verdict(500_000, 0), CpuVerdict::NotThrottled);
    assert_eq!(cpu_verdict(600_000, 0), CpuVerdict::NotThrottled);
}

#[test]
#[ignore = "host: cgroup v2 delegation (io), a block device behind the target dir; timing"]
fn io_limit_throttles_writes() {
    // wbps 4 MiB/s; the probe writes 8 MiB to /workspace. 8 MiB / 4 MiB/s
    // = 2.0 s; one 100 ms throttle slice (0.4 MiB) may pass early, leaving
    // 1.9 s; 1.5 s leaves 0.4 s for timer granularity. The run excludes
    // the other sandbox runs of this binary.
    let _alone = support::exclusive();
    let fixture = Fixture::new("io");
    let dev = block_device_of(&fixture.workspace).unwrap_or_else(|e| {
        panic!(
            "io_limit_throttles_writes needs a block device behind {}: {e}",
            fixture.workspace.display()
        )
    });
    let io = IoLimits::new(vec![IoMax {
        dev,
        rbps: None,
        wbps: Some(4_194_304),
        riops: None,
        wiops: None,
    }])
    .expect("one device");
    let cg = cgroup::create("io", &limits(256 << 20, 16, (100_000, 100_000), io));
    let p = run_probe_in(
        "io-write",
        ids(0, 0),
        &[
            ("BONELI_PROBE_FILE", "/workspace/io-test"),
            ("BONELI_PROBE_SIZE", "8388608"),
        ],
        fixture.root(),
        &cg,
    );
    p.assert_ok();
    let ms: u64 = p.get("elapsed_ms").parse().expect("elapsed_ms");
    let stat = read(&cg, "io.stat");
    let key = format!("{}:{} ", dev.major, dev.minor);
    let line = stat
        .lines()
        .find(|l| l.starts_with(&key))
        .unwrap_or_else(|| panic!("no io.stat line for {key}: {stat:?}"));
    let wbytes: u64 = line
        .split_whitespace()
        .find_map(|f| f.strip_prefix("wbytes="))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("no wbytes in {line:?}"));
    report(&format!(
        "io_limit_throttles_writes: {ms} ms for 8 MiB (bound 1500, margin {} ms), direct={}, wbytes {wbytes}",
        ms as i64 - 1500,
        p.get("direct")
    ));
    assert!(ms >= 1500, "{}", p.raw);
    assert!(wbytes >= 8_388_608, "{line}");
    cg.destroy().expect("destroy");
}

#[test]
#[ignore = "host: cgroup v2 delegation (io, memory), a block device behind the target dir; timing"]
fn io_limit_holds_buffered_writes() {
    // A buffered write is limited at its writeback, not in write(2)
    // (#52). The probe writes S = 512 MiB without O_DIRECT and without a
    // sync in its loop into a cgroup with memory.max M = 256 MiB and wbps
    // W = 32 MiB/s. At the loop's end at most M of the file is dirty or
    // under writeback (charged to the sandbox, not reclaimable before it
    // is written), so at least S - M = 256 MiB passed the throttle, which
    // lets at most W x (t + 0.1 s) through by time t: t >= 8.0 - 0.1 =
    // 7.9 s. 400 ms more for timer and scheduling granularity (the margins
    // of io_limit_throttles_writes): the bound is 7,500 ms, a lower bound
    // only. Dev host, measured in transient units: held loop 12.2-12.7 s,
    // without io.max 2.0-3.0 s; memory.max 32 and 64 MiB OOM-killed the
    // writer instead of slowing it, so the sizes go together. After the
    // loop the probe's fdatasync writes the rest back under the limit, and
    // the device's wbytes must cover every byte (the limited device is the
    // one the bytes go to). The run excludes the other sandbox runs.
    let _alone = support::exclusive();
    let fixture = Fixture::new("io-buffered");
    let dev = block_device_of(&fixture.workspace).unwrap_or_else(|e| {
        panic!(
            "io_limit_holds_buffered_writes needs a block device behind {}: {e}",
            fixture.workspace.display()
        )
    });
    let io = IoLimits::new(vec![IoMax {
        dev,
        rbps: None,
        wbps: Some(IO_BUF_WBPS),
        riops: None,
        wiops: None,
    }])
    .expect("one device");
    let cg = cgroup::create(
        "io-buffered",
        &limits(IO_BUF_MEMORY_MAX, 16, (100_000, 100_000), io),
    );
    let p = buffered_writer_run(&fixture, &cg);
    let events = read(&cg, "memory.events");
    let wbytes = io_stat_wbytes(&read(&cg, "io.stat"), dev.major, dev.minor);
    let f = buffered_facts(
        &p,
        (dev.major, dev.minor),
        keyed(&events, "oom_kill"),
        keyed(&events, "max"),
        wbytes,
    );
    let v = buffered_verdict(&f);
    report(&format!(
        "io_limit_holds_buffered_writes: {}",
        buffered_report(&f)
    ));
    if v != BufferedHold::Held {
        let _ = cg.destroy();
        panic!("{}\n{}", buffered_failure(v, &f), p.raw);
    }
    cg.destroy().expect("destroy");
}

/// What `io_limit_holds_buffered_writes` writes: 512 MiB.
const IO_BUF_SIZE: u64 = 512 << 20;
/// Its `memory.max`: 256 MiB, the harness's `MEMORY_MAX` (32 and 64 MiB
/// OOM-killed the writer on the dev host).
const IO_BUF_MEMORY_MAX: u64 = 256 << 20;
/// Its `wbps`: 32 MiB/s.
const IO_BUF_WBPS: u64 = 32 << 20;
/// One 100 ms throttle slice plus 400 ms of timer and scheduling slack.
const IO_BUF_SLACK_MS: u64 = 500;
/// Hang bound of the buffered writer: about 7 times its 17 s run.
const IO_BUF_HANG: Duration = Duration::from_secs(120);

/// Runs the buffered writer in `cg` on `fixture` and waits for it within
/// [`IO_BUF_HANG`]. Its output goes to files, not pipes: `run_in` reads
/// the pipes to EOF before its hang bound starts, so a stuck writer would
/// hold the job until its timeout.
fn buffered_writer_run(fixture: &Fixture, cg: &Cgroup) -> support::Probe {
    let _runs = support::shared();
    let out_dir = fixture.tree().dir("buffered-out");
    let (out_path, err_path) = (out_dir.join("stdout"), out_dir.join("stderr"));
    let create = |p: &std::path::Path| -> std::os::fd::OwnedFd {
        std::fs::File::create(p)
            .unwrap_or_else(|e| panic!("create {}: {e}", p.display()))
            .into()
    };
    let mut s = spec(
        root_with_cgroup(fixture),
        cg,
        crate::support::rootfs::PROBE,
        &["--exact", "probe", "--nocapture", "--quiet"],
    );
    s.stdio.stdout = create(&out_path);
    s.stdio.stderr = create(&err_path);
    s.env = [
        (support::probe::ACTION_VAR, "io-write"),
        ("BONELI_PROBE_FILE", "/workspace/buffered"),
        ("BONELI_PROBE_SIZE", "536870912"),
        ("BONELI_PROBE_DIRECT", "never"),
    ]
    .iter()
    .map(|(k, v)| (OsString::from(k), OsString::from(v)))
    .collect();
    let mut child = spawn(&s).expect("spawn the buffered writer");
    drop(s);
    let status = wait_bounded(&mut child, IO_BUF_HANG);
    let text = |p: &std::path::Path| {
        String::from_utf8_lossy(
            &std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display())),
        )
        .into_owned()
    };
    support::parse_probe(support::Output {
        status,
        stdout: text(&out_path),
        stderr: text(&err_path),
    })
}

/// What `io_limit_holds_buffered_writes` measured.
#[derive(Debug, Clone)]
struct BufferedFacts {
    dev: (u32, u32),
    status: ExitStatus,
    oom_kill: u64,
    max_events: u64,
    loop_ms: Option<u64>,
    elapsed_ms: Option<u64>,
    loop_wbytes: u64,
    loop_file_dirty: u64,
    loop_file_writeback: u64,
    wbytes: u64,
    size: u64,
    memory_max: u64,
    wbps: u64,
    bound_ms: u64,
}

/// The facts from the probe's keys (a missing number reads 0, a missing
/// time `None`) and the cgroup's files.
fn buffered_facts(
    p: &support::Probe,
    dev: (u32, u32),
    oom_kill: u64,
    max_events: u64,
    wbytes: u64,
) -> BufferedFacts {
    let time = |k: &str| p.values.get(k).and_then(|v| v.parse().ok());
    let number = |k: &str| time(k).unwrap_or(0);
    let loop_stat = p
        .values
        .get("loop_io_stat")
        .map(|s| s.replace(';', "\n"))
        .unwrap_or_default();
    BufferedFacts {
        dev,
        status: p.status,
        oom_kill,
        max_events,
        loop_ms: time("loop_ms"),
        elapsed_ms: time("elapsed_ms"),
        loop_wbytes: io_stat_wbytes(&loop_stat, dev.0, dev.1),
        loop_file_dirty: number("loop_file_dirty"),
        loop_file_writeback: number("loop_file_writeback"),
        wbytes,
        size: IO_BUF_SIZE,
        memory_max: IO_BUF_MEMORY_MAX,
        wbps: IO_BUF_WBPS,
        bound_ms: buffered_bound_ms(IO_BUF_SIZE, IO_BUF_MEMORY_MAX, IO_BUF_WBPS),
    }
}

/// What one buffered run shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferedHold {
    /// The loop took at least the bound, the data was buffered and reached
    /// the limited device.
    Held,
    /// An OOM kill: the sizes are wrong, nothing is said about io.max.
    OomKilled,
    /// The writer did not exit 0 or printed no loop time.
    WriterFailed,
    /// The loop finished under the bound: io.max did not hold.
    Escaped,
    /// No dirty data at the loop's end: not a buffered write.
    NotBuffered,
    /// The limited device did not see every byte.
    OffDevice,
}

/// The least loop time in ms that `wbps` allows when `memory_max` of
/// `size` may still wait in the page cache, minus [`IO_BUF_SLACK_MS`];
/// 0 without a rate. Floors, so it errs low.
fn buffered_bound_ms(size: u64, memory_max: u64, wbps: u64) -> u64 {
    size.saturating_sub(memory_max)
        .saturating_mul(1000)
        .checked_div(wbps)
        .unwrap_or(0)
        .saturating_sub(IO_BUF_SLACK_MS)
}

fn buffered_verdict(f: &BufferedFacts) -> BufferedHold {
    if f.oom_kill >= 1 {
        return BufferedHold::OomKilled;
    }
    let Some(loop_ms) = f.loop_ms.filter(|_| f.status == ExitStatus::Exited(0)) else {
        return BufferedHold::WriterFailed;
    };
    if loop_ms < f.bound_ms {
        BufferedHold::Escaped
    } else if f.loop_file_dirty.saturating_add(f.loop_file_writeback) == 0 {
        BufferedHold::NotBuffered
    } else if f.wbytes < f.size {
        BufferedHold::OffDevice
    } else {
        BufferedHold::Held
    }
}

fn opt_ms(v: Option<u64>) -> String {
    v.map_or("none".to_string(), |v| v.to_string())
}

/// The report line of `io_limit_holds_buffered_writes`.
fn buffered_report(f: &BufferedFacts) -> String {
    let margin = f.loop_ms.map_or("none".to_string(), |l| {
        (l as i64 - f.bound_ms as i64).to_string()
    });
    format!(
        "loop {} ms for {} bytes (bound {}, margin {margin} ms), probe total {} ms, \
         at the loop's end wbytes {} file_dirty {} file_writeback {}, wbytes {} after fdatasync, \
         memory.events max {} oom_kill {}, memory.max {}, wbps {}, device {}:{}",
        opt_ms(f.loop_ms),
        f.size,
        f.bound_ms,
        opt_ms(f.elapsed_ms),
        f.loop_wbytes,
        f.loop_file_dirty,
        f.loop_file_writeback,
        f.wbytes,
        f.max_events,
        f.oom_kill,
        f.memory_max,
        f.wbps,
        f.dev.0,
        f.dev.1
    )
}

fn buffered_failure(v: BufferedHold, f: &BufferedFacts) -> String {
    let why = match v {
        BufferedHold::OomKilled => format!(
            "the buffered writer was OOM-killed (memory.events oom_kill {}): \
             a test-sizing bug, not a result about io.max",
            f.oom_kill
        ),
        BufferedHold::WriterFailed => "the buffered writer failed".to_string(),
        BufferedHold::Escaped => format!(
            "io.max did not hold the buffered write: it finished in {} ms, under the {} ms \
             that wbps {} with memory.max {} allow",
            opt_ms(f.loop_ms),
            f.bound_ms,
            f.wbps,
            f.memory_max
        ),
        BufferedHold::NotBuffered => "the write loop left no dirty data, so it was not a \
             buffered write and the test did not cover the kernel's writeback"
            .to_string(),
        BufferedHold::OffDevice => format!(
            "the buffered bytes did not reach the io.max device: wbytes {} on {}:{} after \
             fdatasync, under the {} bytes written",
            f.wbytes, f.dev.0, f.dev.1, f.size
        ),
        BufferedHold::Held => "the buffered write was held".to_string(),
    };
    format!(
        "{why}: device {}:{}, status {:?}, oom_kill {}, loop_ms {}, elapsed_ms {}, \
         bound {} ms, loop wbytes {}, loop file_dirty {}, loop file_writeback {}, wbytes {}, \
         size {}, memory.max {}, wbps {}",
        f.dev.0,
        f.dev.1,
        f.status,
        f.oom_kill,
        opt_ms(f.loop_ms),
        opt_ms(f.elapsed_ms),
        f.bound_ms,
        f.loop_wbytes,
        f.loop_file_dirty,
        f.loop_file_writeback,
        f.wbytes,
        f.size,
        f.memory_max,
        f.wbps
    )
}

fn buffered_facts_for(loop_ms: Option<u64>) -> BufferedFacts {
    BufferedFacts {
        dev: (259, 0),
        status: ExitStatus::Exited(0),
        oom_kill: 0,
        max_events: 1044,
        loop_ms,
        elapsed_ms: loop_ms.map(|l| l + 4439),
        loop_wbytes: 52_428_800,
        loop_file_dirty: 100_000_000,
        loop_file_writeback: 43_654_912,
        wbytes: IO_BUF_SIZE,
        size: IO_BUF_SIZE,
        memory_max: IO_BUF_MEMORY_MAX,
        wbps: IO_BUF_WBPS,
        bound_ms: buffered_bound_ms(IO_BUF_SIZE, IO_BUF_MEMORY_MAX, IO_BUF_WBPS),
    }
}

#[test]
fn buffered_bound_values() {
    assert_eq!(
        buffered_bound_ms(536_870_912, 268_435_456, 33_554_432),
        7500
    );
    assert_eq!(
        buffered_bound_ms(536_870_912, 268_435_456, 33_554_433),
        7499
    );
    assert_eq!(buffered_bound_ms(268_435_456, 268_435_456, 33_554_432), 0);
    assert_eq!(buffered_bound_ms(1, 268_435_456, 33_554_432), 0);
    assert_eq!(buffered_bound_ms(536_870_912, 268_435_456, 0), 0);
    assert_eq!(
        buffered_bound_ms(u64::MAX, 0, 1),
        18_446_744_073_709_551_115
    );
}

#[test]
fn buffered_verdicts() {
    let f = buffered_facts_for;
    assert_eq!(f(Some(12_232)).bound_ms, 7500);
    assert_eq!(buffered_verdict(&f(Some(12_232))), BufferedHold::Held);
    // The bound is inclusive.
    assert_eq!(buffered_verdict(&f(Some(7500))), BufferedHold::Held);
    assert_eq!(buffered_verdict(&f(Some(7499))), BufferedHold::Escaped);
    // An OOM kill comes first.
    let mut g = f(None);
    g.oom_kill = 1;
    g.status = ExitStatus::Signaled(9);
    assert_eq!(buffered_verdict(&g), BufferedHold::OomKilled);
    let mut g = f(Some(12_000));
    g.oom_kill = 1;
    assert_eq!(buffered_verdict(&g), BufferedHold::OomKilled);
    // Then the writer.
    for (status, loop_ms) in [
        (ExitStatus::Exited(101), Some(12_000)),
        (ExitStatus::Signaled(9), Some(12_000)),
        (ExitStatus::Exited(0), None),
    ] {
        let mut g = f(loop_ms);
        g.status = status;
        assert_eq!(
            buffered_verdict(&g),
            BufferedHold::WriterFailed,
            "{status:?}"
        );
    }
    // Time before the backlog: a fast loop is an escape, not a harness bug.
    let mut g = f(Some(7499));
    g.loop_file_dirty = 0;
    g.loop_file_writeback = 0;
    g.wbytes = 0;
    assert_eq!(buffered_verdict(&g), BufferedHold::Escaped);
    let mut g = f(Some(12_000));
    g.loop_file_dirty = 0;
    g.loop_file_writeback = 0;
    assert_eq!(buffered_verdict(&g), BufferedHold::NotBuffered);
    g.loop_file_writeback = 4096;
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    g.loop_file_dirty = u64::MAX;
    g.loop_file_writeback = 1;
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    let mut g = f(Some(12_000));
    g.wbytes = 536_870_911;
    assert_eq!(buffered_verdict(&g), BufferedHold::OffDevice);
    g.wbytes = 536_870_912;
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
}

#[test]
fn buffered_failure_messages() {
    let f = buffered_facts_for;
    let mut oom = f(None);
    oom.oom_kill = 1;
    oom.status = ExitStatus::Signaled(9);
    let mut failed = f(Some(12_000));
    failed.status = ExitStatus::Exited(101);
    let mut not_buffered = f(Some(12_000));
    not_buffered.loop_file_dirty = 0;
    not_buffered.loop_file_writeback = 0;
    let mut off = f(Some(12_000));
    off.wbytes = 4096;
    let cases = [
        (
            BufferedHold::OomKilled,
            &oom,
            "the buffered writer was OOM-killed (memory.events oom_kill 1): a test-sizing bug, not a result about io.max",
        ),
        (
            BufferedHold::WriterFailed,
            &failed,
            "the buffered writer failed",
        ),
        (
            BufferedHold::Escaped,
            &f(Some(3004)),
            "io.max did not hold the buffered write: it finished in 3004 ms, under the 7500 ms that wbps 33554432 with memory.max 268435456 allow",
        ),
        (
            BufferedHold::NotBuffered,
            &not_buffered,
            "the write loop left no dirty data, so it was not a buffered write and the test did not cover the kernel's writeback",
        ),
        (
            BufferedHold::OffDevice,
            &off,
            "the buffered bytes did not reach the io.max device: wbytes 4096 on 259:0 after fdatasync, under the 536870912 bytes written",
        ),
    ];
    for (v, facts, prefix) in cases {
        let m = buffered_failure(v, facts);
        assert!(m.starts_with(prefix), "{v:?}: {m}");
        let loop_ms = facts.loop_ms.map_or("none".to_string(), |l| l.to_string());
        let elapsed = facts
            .elapsed_ms
            .map_or("none".to_string(), |l| l.to_string());
        for part in [
            "device 259:0".to_string(),
            format!("status {:?}", facts.status),
            format!("oom_kill {}", facts.oom_kill),
            format!("loop_ms {loop_ms}"),
            format!("elapsed_ms {elapsed}"),
            "bound 7500 ms".to_string(),
            format!("loop wbytes {}", facts.loop_wbytes),
            format!("loop file_dirty {}", facts.loop_file_dirty),
            format!("loop file_writeback {}", facts.loop_file_writeback),
            format!("wbytes {}", facts.wbytes),
            "size 536870912".to_string(),
            "memory.max 268435456".to_string(),
            "wbps 33554432".to_string(),
        ] {
            assert!(m.contains(&part), "{v:?}: {part:?} missing in {m}");
        }
    }
    let m = buffered_failure(BufferedHold::OomKilled, &oom);
    assert!(m.contains("test-sizing bug"), "{m}");
    assert!(!m.contains("did not hold"), "{m}");
    assert!(m.contains("loop_ms none"), "{m}");
}

#[test]
fn io_write_plan_forms() {
    use crate::support::probe::{IoDirect, io_write_plan};
    let plan = |size: &str, chunk: Option<&str>, direct: Option<&str>| {
        io_write_plan(size, chunk, direct).map(|p| (p.size, p.chunk, p.direct))
    };
    assert_eq!(
        plan("8388608", None, None),
        Ok((8_388_608, 1 << 20, IoDirect::Auto))
    );
    assert_eq!(8_388_608 / (1 << 20), 8);
    assert_eq!(
        plan("536870912", None, Some("never")),
        Ok((536_870_912, 1 << 20, IoDirect::Never))
    );
    assert_eq!(
        plan("41943040", Some("41943040"), Some("require")),
        Ok((41_943_040, 41_943_040, IoDirect::Require))
    );
    for chunk in ["0", "4097", "", "abc", " 4096", "+4096"] {
        assert!(
            plan("8388608", Some(chunk), None).is_err(),
            "chunk {chunk:?}"
        );
    }
    assert!(plan("8388608", Some("3145728"), None).is_err(), "remainder");
    assert!(
        plan("1048576", Some("2097152"), None).is_err(),
        "chunk over size"
    );
    assert!(plan("abc", None, None).is_err(), "size");
    for direct in [
        "Require", "require ", "Never", "NEVER", " never", "never ", "auto", "1", "",
    ] {
        assert!(
            plan("8388608", None, Some(direct)).is_err(),
            "direct {direct:?}"
        );
    }
}

#[test]
#[ignore = "host: cgroup v2 delegation, user namespaces"]
fn cgroup_namespace_root_is_sandbox_cgroup() {
    // The child enters its cgroup at clone (CLONE_INTO_CGROUP) and creates
    // the cgroup namespace after it, so the namespace is rooted at the
    // sandbox's cgroup: its own path is `/`, and the cgroup2 mount shows
    // the sandbox's limits. A child left in the runner's cgroup (no
    // CLONE_INTO_CGROUP) sees both differ. A namespace created by clone3
    // together with CLONE_INTO_CGROUP is rooted at the sandbox's cgroup too
    // on the dev host's kernel (measured, ADR-007 D8), so this test cannot
    // tell the two orders apart there; `spawn_clone_flags` pins the order.
    let cg = cgroup::create(
        "cgns",
        &limits(40 << 20, 16, (100_000, 100_000), IoLimits::none()),
    );
    let fixture = Fixture::new("cgns");
    let p = run_probe_in(
        "read",
        ids(0, 0),
        &[(
            "BONELI_PROBE_FILES",
            "/proc/self/cgroup,/sys/fs/cgroup/memory.max",
        )],
        root_with_cgroup(&fixture),
        &cg,
    );
    p.assert_ok();
    assert_eq!(p.get("file:/proc/self/cgroup").trim(), "0::/", "{}", p.raw);
    assert_eq!(
        p.get("file:/sys/fs/cgroup/memory.max").trim(),
        (40u64 << 20).to_string(),
        "{}",
        p.raw
    );
    cg.destroy().expect("destroy");
}

#[test]
#[ignore = "host: cgroup v2 delegation, user namespaces"]
fn sandbox_cannot_touch_own_limits() {
    // The sandbox's cgroup files belong to the host user the inside id
    // maps to, so only the read-only mount keeps them unwritable.
    for id in [0, 999] {
        let cg = cgroup::sandbox("own-limits");
        let fixture = Fixture::new("own-limits");
        let p = run_probe_in(
            "write",
            ids(id, id),
            &[(
                "BONELI_PROBE_WRITES",
                "/sys/fs/cgroup/memory.max=max,/sys/fs/cgroup/cgroup.kill=1,/sys/fs/cgroup/pids.max=max",
            )],
            root_with_cgroup(&fixture),
            &cg,
        );
        p.assert_ok();
        for file in ["memory.max", "cgroup.kill", "pids.max"] {
            assert_eq!(
                p.get(&format!("errno:/sys/fs/cgroup/{file}")),
                libc::EROFS.to_string(),
                "inside id {id}, {file}: {}",
                p.raw
            );
        }
        assert_eq!(
            read(&cg, "memory.max").trim(),
            cgroup::MEMORY_MAX.to_string()
        );
        cg.destroy().expect("destroy");
    }
}

/// A sub-cgroup of the harness parent with exactly `controllers` enabled
/// for its children, removed on drop.
struct SubParent {
    path: PathBuf,
}

impl SubParent {
    fn new(tag: &str, controllers: &[&str]) -> SubParent {
        let path = cgroup::parent().path().join(cgroup::unique_name(tag));
        std::fs::create_dir(&path).expect("mkdir a sub-cgroup");
        let sp = SubParent { path };
        let enable: Vec<String> = controllers.iter().map(|c| format!("+{c}")).collect();
        if !enable.is_empty() {
            std::fs::write(sp.path.join("cgroup.subtree_control"), enable.join(" "))
                .expect("enable controllers");
        }
        sp
    }
}

impl Drop for SubParent {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(self.path.join("leaf"));
        let _ = std::fs::remove_dir(&self.path);
    }
}

#[test]
#[ignore = "host: cgroup v2 delegation (cpu, io, memory, pids)"]
fn parent_without_controllers_rejected() {
    let all = ["cpu", "io", "memory", "pids"];
    // Only pids: the first missing one in the order cpu, io, memory, pids.
    let sp = SubParent::new("ctl-pids", &["pids"]);
    assert!(
        matches!(Parent::open(&sp.path), Err(Error::ControllerMissing("cpu"))),
        "{:?}",
        Parent::open(&sp.path)
    );
    drop(sp);
    // Each controller alone missing is named.
    for missing in all {
        let rest: Vec<&str> = all.iter().copied().filter(|c| *c != missing).collect();
        let sp = SubParent::new("ctl", &rest);
        match Parent::open(&sp.path) {
            Err(Error::ControllerMissing(c)) => assert_eq!(c, missing),
            other => panic!("without {missing}: {other:?}"),
        }
    }
    let sp = SubParent::new("ctl-all", &all);
    Parent::open(&sp.path).expect("all four enabled");
    drop(sp);
    // Not a cgroup v2 directory at all.
    let tree = crate::support::rootfs::Tree::new("not-cgroup");
    assert!(
        matches!(Parent::open(tree.path()), Err(Error::NotCgroup2(_))),
        "{:?}",
        Parent::open(tree.path())
    );
}

#[test]
#[ignore = "host: cgroup v2 delegation, user namespaces"]
fn destroy_kills_all_and_removes() {
    let cg = cgroup::sandbox("destroy");
    let fixture = Fixture::new("destroy");
    let mut children: Vec<_> = (0..3)
        .map(|_| spawn(&spec(fixture.root(), &cg, "/bin/sleep", &["30"])).expect("spawn a sleeper"))
        .collect();
    assert_eq!(populated(&cg), 1);
    assert_eq!(read(&cg, "cgroup.procs").lines().count(), 3);
    let path = cg.path().to_path_buf();
    let start = Instant::now();
    cg.destroy().expect("destroy");
    report(&format!(
        "destroy_kills_all_and_removes: destroy took {:?}",
        start.elapsed()
    ));
    assert!(!path.exists(), "{} still exists", path.display());
    for child in &mut children {
        assert_eq!(
            wait_bounded(child, Duration::from_secs(10)),
            ExitStatus::Signaled(libc::SIGKILL)
        );
    }
}

#[test]
#[ignore = "host: cgroup v2 delegation (cpu, io, memory, pids)"]
fn vacate_moves_every_process() {
    let sp = SubParent::new("vacate", &[]);
    let mut sleepers: Vec<_> = (0..2)
        .map(|_| {
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("start a sleeper")
        })
        .collect();
    for s in &sleepers {
        std::fs::write(sp.path.join("cgroup.procs"), s.id().to_string())
            .expect("move a sleeper into the sub-cgroup");
    }
    let parent = Parent::vacate_and_delegate(&sp.path).expect("vacate and delegate");
    let procs = std::fs::read_to_string(sp.path.join("cgroup.procs")).expect("procs");
    assert_eq!(procs.trim(), "", "nothing left in the parent");
    let leaf = std::fs::read_to_string(sp.path.join("leaf/cgroup.procs")).expect("leaf procs");
    for s in &sleepers {
        assert!(
            leaf.lines().any(|l| l == s.id().to_string()),
            "{} not in leaf/: {leaf:?}",
            s.id()
        );
    }
    let enabled =
        std::fs::read_to_string(sp.path.join("cgroup.subtree_control")).expect("subtree_control");
    let mut enabled: Vec<&str> = enabled.split_whitespace().collect();
    enabled.sort_unstable();
    assert_eq!(enabled, ["cpu", "io", "memory", "pids"]);
    // The returned parent takes sandbox cgroups.
    let cg = Cgroup::create(&parent, "child", &cgroup::default_limits()).expect("create");
    cg.destroy().expect("destroy");
    for s in &mut sleepers {
        let _ = s.kill();
        let _ = s.wait();
    }
}

#[test]
#[ignore = "host: cgroup v2 delegation, user namespaces"]
fn failed_spawn_leaves_no_cgroup_process() {
    let fixture = Fixture::new("failed-spawn");
    // An exec failure and a mount failure: both after the clone, so the
    // child was in the cgroup.
    let mut missing_target = fixture.mounts();
    missing_target.push(Mount::Tmpfs {
        target: inside("/no-such-dir"),
        size_bytes: 1 << 20,
        mode: 0o755,
    });
    let cases: [(Root, &str, Step, i32); 2] = [
        (
            fixture.root(),
            "/nonexistent/program",
            Step::Exec,
            libc::ENOENT,
        ),
        (
            fixture.root_with(vec![fixture.layer.clone()], missing_target),
            "/bin/true",
            Step::MountTarget,
            libc::ENOENT,
        ),
    ];
    for (root, program, want_step, want_errno) in cases {
        let cg = cgroup::sandbox("failed-spawn");
        match spawn(&spec(root, &cg, program, &[])) {
            Err(Error::Setup { step, errno, .. }) => {
                assert_eq!((step, errno), (want_step, want_errno));
            }
            other => panic!("{program}: {other:?}"),
        }
        assert_eq!(read(&cg, "cgroup.procs").trim(), "", "{program}");
        assert_eq!(populated(&cg), 0, "{program}");
        let path = cg.path().to_path_buf();
        cg.destroy().expect("destroy");
        assert!(!path.exists(), "{}", path.display());
    }
}

#[test]
#[ignore = "host: cgroup v2 delegation (io), a block device behind the target dir"]
fn destroy_lifts_io_throttle() {
    // Review of PR 3: a task in one large O_DIRECT write at wbps 1 MiB/s
    // waits uninterruptibly for its queued bios, so cgroup.kill cannot end
    // it before they drain at the throttled rate. destroy lifts io.max
    // after the kill, so the bios drain at once (the reviewer measured
    // 97 ms with the lift).
    //
    // The writer is the probe (#52): one 41,943,040-byte O_DIRECT write
    // from a 4096-aligned buffer, never dd, whose write path depends on
    // the image (on AWS runners dd's 40 MiB returned within the 2 s). A
    // held write needs at least (41,943,040 - 104,858) / 1 MiB/s = 39.9 s
    // (one 100 ms slice may pass early), so at the check about 38 MiB
    // are still queued; without the lift that takes past KILL_BOUND
    // (10 s) to drain. The dev host measured the writer inside its write
    // 263-872 ms after the spawn, wchar 38 while held. Before the kill the
    // test checks that io.max holds the writer inside that one write: the
    // cgroup is populated, a task is in write(2) with the 40 MiB count
    // (/proc/<pid>/task/<tid>/syscall), and wchar is under 40 MiB
    // (/proc/<pid>/io adds a write only when it returns). Where the runner
    // refuses those files (EACCES, EPERM), a task in D decides instead,
    // and the report line names the fallback. wbytes is reported, not
    // asserted: where io.stat counts depends on the write path.
    let _alone = support::exclusive();
    let fixture = Fixture::new("io-kill");
    let dev = block_device_of(&fixture.workspace).expect("a block device behind /workspace");
    let io = IoLimits::new(vec![IoMax {
        dev,
        rbps: None,
        wbps: Some(IO_KILL_WBPS),
        riops: None,
        wiops: None,
    }])
    .expect("one device");
    let cg = cgroup::create("io-kill", &limits(256 << 20, 16, (100_000, 100_000), io));
    let size = IO_KILL_SIZE.to_string();
    let mut s = spec(
        fixture.root(),
        &cg,
        crate::support::rootfs::PROBE,
        &["--exact", "probe", "--nocapture", "--quiet"],
    );
    s.env = [
        (support::probe::ACTION_VAR, "io-write"),
        ("BONELI_PROBE_FILE", "/workspace/big"),
        ("BONELI_PROBE_SIZE", size.as_str()),
        ("BONELI_PROBE_CHUNK", size.as_str()),
        ("BONELI_PROBE_DIRECT", "require"),
    ]
    .iter()
    .map(|(k, v)| (OsString::from(k), OsString::from(v)))
    .collect();
    let start = Instant::now();
    let mut child = spawn(&s).expect("spawn the writer");
    drop(s);
    // Let the writer fill its buffer and block in the throttled write.
    std::thread::sleep(Duration::from_secs(2));
    let populated_now = populated(&cg);
    let check = hold_check(child.pid());
    let states = task_states(child.pid());
    let wbytes = io_stat_wbytes(&read(&cg, "io.stat"), dev.major, dev.minor);
    let memory = read(&cg, "memory.stat");
    let facts = IoFacts {
        dev: (dev.major, dev.minor),
        elapsed_ms: start.elapsed().as_millis() as u64,
        populated: populated_now,
        check,
        states,
        wbytes,
        file_dirty: keyed(&memory, "file_dirty"),
        file_writeback: keyed(&memory, "file_writeback"),
    };
    let verdict = io_hold_verdict(&facts);
    report(&format!(
        "destroy_lifts_io_throttle: {}",
        io_hold_text(verdict, &facts)
    ));
    let path = cg.path().to_path_buf();
    if verdict != IoHold::Held {
        let _ = cg.destroy();
        let status = wait_bounded(&mut child, Duration::from_secs(120));
        if path.exists() {
            let _ = std::fs::write(path.join("cgroup.kill"), "1");
            let _ = std::fs::remove_dir(&path);
        }
        panic!("{}", io_hold_failure(verdict, status, &facts));
    }
    let start = Instant::now();
    let result = cg.destroy();
    let took = start.elapsed();
    report(&format!(
        "destroy_lifts_io_throttle: destroy took {took:?}: {result:?}"
    ));
    let status = wait_bounded(&mut child, Duration::from_secs(120));
    if path.exists() {
        // Leave nothing behind when the assertion below fails.
        let _ = std::fs::write(path.join("cgroup.kill"), "1");
        let _ = std::fs::remove_dir(&path);
    }
    assert!(result.is_ok(), "{result:?} after {took:?}");
    assert!(took < Duration::from_secs(5), "destroy took {took:?}");
    assert_eq!(status, ExitStatus::Signaled(libc::SIGKILL));
}

/// The one write of `destroy_lifts_io_throttle`: 40 MiB.
const IO_KILL_SIZE: u64 = 40 << 20;
/// Its `wbps`: 1 MiB/s.
const IO_KILL_WBPS: u64 = 1 << 20;

/// One task's `/proc/<pid>/task/<tid>/syscall`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TaskSyscall {
    /// `running`: the task was on a CPU.
    Running,
    /// A negative number, sp and pc: asleep, not in a syscall (an exited
    /// task reads `-1 0x0 0x0`, measured).
    Blocked,
    /// In syscall `nr` with these six arguments.
    In { nr: libc::c_long, args: [u64; 6] },
}

/// ASCII digits with at most a leading `-`; `str::parse` would also take
/// a leading `+`.
fn is_decimal(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// `0x` and at least one ASCII hex digit, within u64; `from_str_radix`
/// would also take a leading `+`.
fn hex_field(s: &str) -> Option<u64> {
    let digits = s.strip_prefix("0x")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// Parses one `syscall` file; anything but the kernel's three forms
/// panics with the line quoted, never reads as held.
fn parse_syscall(line: &str) -> TaskSyscall {
    let body = line.strip_suffix('\n').unwrap_or(line);
    let fields: Vec<&str> = body.split_ascii_whitespace().collect();
    if fields == ["running"] {
        return TaskSyscall::Running;
    }
    let bad = || -> ! { panic!("unexpected syscall line {line:?}") };
    let Some((first, rest)) = fields.split_first() else {
        bad()
    };
    if !is_decimal(first) {
        bad();
    }
    let nr: libc::c_long = first.parse().unwrap_or_else(|_| bad());
    let hex: Vec<u64> = rest
        .iter()
        .map(|f| hex_field(f).unwrap_or_else(|| bad()))
        .collect();
    match (nr < 0, hex.len()) {
        (true, 2) => TaskSyscall::Blocked,
        (false, 8) => {
            let mut args = [0; 6];
            args.copy_from_slice(&hex[..6]);
            TaskSyscall::In { nr, args }
        }
        _ => bad(),
    }
}

/// One task of the writer as the hold check read it.
#[derive(Debug, Clone)]
struct TaskLine {
    tid: String,
    /// The `syscall` file without its newline, for the report.
    raw: String,
    call: TaskSyscall,
}

/// What the hold check read.
#[derive(Debug)]
enum HoldCheck {
    /// Every task's `syscall` line, then `wchar` from `/proc/<pid>/io`.
    Syscall { tasks: Vec<TaskLine>, wchar: u64 },
    /// One of those files was refused (`syscall: EACCES`, `io: EPERM`):
    /// the task states decide.
    DState { refused: String },
}

/// `wchar` of a `/proc/<pid>/io` text: the first line that starts with
/// `wchar: `, its value ASCII digits within u64; anything else panics
/// with the text or the line quoted.
fn proc_io_wchar(text: &str) -> u64 {
    let Some(line) = text.lines().find(|l| l.starts_with("wchar: ")) else {
        panic!("no wchar line in {text:?}")
    };
    let value = &line["wchar: ".len()..];
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        panic!("unexpected wchar line {line:?}");
    }
    value
        .parse()
        .unwrap_or_else(|_| panic!("wchar out of range in {line:?}"))
}

/// A refusal of a `/proc` file (the fallback's trigger), else `None`.
fn proc_refusal(e: &std::io::Error) -> Option<&'static str> {
    match e.raw_os_error() {
        Some(libc::EACCES) => Some("EACCES"),
        Some(libc::EPERM) => Some("EPERM"),
        _ => None,
    }
}

/// Reads every task's `syscall` file of `pid`, then its `wchar`; a refused
/// file switches to the `D`-state fallback. A task that exited in between
/// (ENOENT, ESRCH) is skipped. The writer is not reaped before
/// `wait_bounded`, so its files stay readable after it exits.
fn hold_check(pid: i32) -> HoldCheck {
    let dir = format!("/proc/{pid}/task");
    let tids: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    let mut tasks = Vec::new();
    for tid in tids {
        match std::fs::read_to_string(format!("{dir}/{tid}/syscall")) {
            Ok(text) => tasks.push(TaskLine {
                call: parse_syscall(&text),
                raw: text.strip_suffix('\n').unwrap_or(&text).to_string(),
                tid,
            }),
            Err(e) => {
                if let Some(r) = proc_refusal(&e) {
                    return HoldCheck::DState {
                        refused: format!("syscall: {r}"),
                    };
                }
            }
        }
    }
    let io = format!("/proc/{pid}/io");
    match std::fs::read_to_string(&io) {
        Ok(text) => HoldCheck::Syscall {
            tasks,
            wchar: proc_io_wchar(&text),
        },
        Err(e) => match proc_refusal(&e) {
            Some(r) => HoldCheck::DState {
                refused: format!("io: {r}"),
            },
            None => panic!("read {io}: {e}"),
        },
    }
}

/// `syscall`, or `d-state (<refused file>: <errno>)`.
fn hold_check_label(c: &HoldCheck) -> String {
    match c {
        HoldCheck::Syscall { .. } => "syscall".to_string(),
        HoldCheck::DState { refused } => format!("d-state ({refused})"),
    }
}

/// What `destroy_lifts_io_throttle` read at the check.
#[derive(Debug)]
struct IoFacts {
    dev: (u32, u32),
    elapsed_ms: u64,
    populated: u64,
    check: HoldCheck,
    states: Vec<char>,
    wbytes: u64,
    file_dirty: u64,
    file_writeback: u64,
}

/// Whether io.max held the writer at the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IoHold {
    /// Alive and inside its 40 MiB write (or in `D` in the fallback).
    Held,
    /// The cgroup was empty: the writer had ended.
    Finished,
    /// Alive, but `wchar` counts the whole write: it returned.
    Returned,
    /// Alive, but no task was inside the 40 MiB write.
    NotInWrite,
    /// Fallback only: no task in `D`.
    NotBlocked,
}

fn io_hold_verdict(f: &IoFacts) -> IoHold {
    if f.populated == 0 {
        return IoHold::Finished;
    }
    match &f.check {
        HoldCheck::Syscall { tasks, wchar } => {
            if *wchar >= IO_KILL_SIZE {
                IoHold::Returned
            } else if tasks.iter().any(|t| {
                matches!(t.call, TaskSyscall::In { nr, args }
                    if nr == libc::SYS_write && args[2] == IO_KILL_SIZE)
            }) {
                IoHold::Held
            } else {
                IoHold::NotInWrite
            }
        }
        HoldCheck::DState { .. } => {
            if f.states.contains(&'D') {
                IoHold::Held
            } else {
                IoHold::NotBlocked
            }
        }
    }
}

/// The report line's text, also the details of every failure message.
fn io_hold_text(v: IoHold, f: &IoFacts) -> String {
    let (tasks, wchar) = match &f.check {
        HoldCheck::Syscall { tasks, wchar } => (
            tasks
                .iter()
                .map(|t| format!("{} {:?}", t.tid, t.raw))
                .collect::<Vec<_>>()
                .join(", "),
            wchar.to_string(),
        ),
        HoldCheck::DState { refused } => (format!("refused {refused}"), "not read".to_string()),
    };
    format!(
        "at {} ms hold-check={} verdict {v:?}, tasks [{tasks}], wchar {wchar}, states {:?}, \
         device {}:{} wbytes {} file_dirty {} file_writeback {}",
        f.elapsed_ms,
        hold_check_label(&f.check),
        f.states,
        f.dev.0,
        f.dev.1,
        f.wbytes,
        f.file_dirty,
        f.file_writeback
    )
}

fn io_hold_failure(v: IoHold, status: ExitStatus, f: &IoFacts) -> String {
    let why = match v {
        IoHold::Finished if status == ExitStatus::Exited(0) => {
            "io.max did not hold the writer: it finished its 40 MiB write before the check"
        }
        IoHold::Finished => "the writer failed before the kill",
        IoHold::Returned => {
            "io.max did not hold the writer: its 40 MiB write returned before the check"
        }
        IoHold::NotInWrite => "the writer was not inside its 40 MiB write",
        IoHold::NotBlocked => "the writer was not blocked in its write",
        IoHold::Held => "the writer was held",
    };
    format!("{why}: {}, status {status:?}", io_hold_text(v, f))
}

/// `wbytes` of the device's line in an `io.stat` text; no line yet means
/// nothing was submitted (0). A line without a parseable `wbytes=` panics
/// with the line quoted.
fn io_stat_wbytes(stat: &str, major: u32, minor: u32) -> u64 {
    let key = format!("{major}:{minor} ");
    let Some(line) = stat.lines().find(|l| l.starts_with(&key)) else {
        return 0;
    };
    line.split_whitespace()
        .find_map(|f| f.strip_prefix("wbytes="))
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("no wbytes in io.stat line {line:?}"))
}

/// The state of a `/proc/.../stat` line: the first non-space character
/// after the last `)` (the name may hold `)` and spaces).
fn stat_state(line: &str) -> Option<char> {
    let pos = line.rfind(')')?;
    line[pos + 1..].chars().find(|c| !c.is_ascii_whitespace())
}

/// The state of every task of `pid`; unreadable entries are skipped.
fn task_states(pid: i32) -> Vec<char> {
    let dir = format!("/proc/{pid}/task");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| std::fs::read_to_string(e.path().join("stat")).ok())
        .filter_map(|s| stat_state(&s))
        .collect()
}

/// A task line of the hold check, for the pure tests.
fn task(tid: &str, raw: &str) -> TaskLine {
    TaskLine {
        tid: tid.to_string(),
        raw: raw.to_string(),
        call: parse_syscall(raw),
    }
}

/// The measured main thread: in `futex`, state `S`.
fn futex_task() -> TaskLine {
    task(
        "4100",
        &format!(
            "{} 0x7f3a1652c910 0x80 0x0 0x0 0x0 0x0 0x7ffc0 0x7f3a1",
            libc::SYS_futex
        ),
    )
}

/// A task in `write(2)` with the given count in the given argument.
fn write_task(count: u64, arg: usize) -> TaskLine {
    let mut args = ["0x3", "0x7f3a0d7ff000", "0x0", "0x0", "0x0", "0x0"].map(String::from);
    args[2] = "0x0".to_string();
    args[arg] = format!("{count:#x}");
    task(
        "4101",
        &format!(
            "{} {} 0x7f3a164aad28 0x7f3a1652b352",
            libc::SYS_write,
            args.join(" ")
        ),
    )
}

fn io_facts(populated: u64, check: HoldCheck, states: &[char]) -> IoFacts {
    IoFacts {
        dev: (259, 0),
        elapsed_ms: 2004,
        populated,
        check,
        states: states.to_vec(),
        wbytes: 1_048_576,
        file_dirty: 0,
        file_writeback: 41_418_752,
    }
}

fn syscall_check(tasks: Vec<TaskLine>, wchar: u64) -> HoldCheck {
    HoldCheck::Syscall { tasks, wchar }
}

#[test]
fn io_hold_verdicts() {
    let w = || write_task(IO_KILL_SIZE, 2);
    // Precedence: an unpopulated cgroup finished, whatever the tasks say.
    assert_eq!(
        io_hold_verdict(&io_facts(0, syscall_check(vec![w()], 38), &['D'])),
        IoHold::Finished
    );
    // wchar first: a returned write is never Held (the bound is inclusive).
    for wchar in [IO_KILL_SIZE, 41_943_130] {
        assert_eq!(
            io_hold_verdict(&io_facts(1, syscall_check(vec![w()], wchar), &['D'])),
            IoHold::Returned,
            "wchar {wchar}"
        );
    }
    for wchar in [IO_KILL_SIZE - 1, 38] {
        let mut f = io_facts(1, syscall_check(vec![w()], wchar), &['D']);
        assert_eq!(io_hold_verdict(&f), IoHold::Held, "wchar {wchar}");
        // wbytes is not part of the verdict (D1: counted at submission).
        f.wbytes = IO_KILL_SIZE;
        assert_eq!(io_hold_verdict(&f), IoHold::Held, "wchar {wchar}, wbytes");
    }
    // The measured layout: the futex main thread plus the writer, in
    // either order; the futex task alone is not in the write.
    for tasks in [vec![futex_task(), w()], vec![w(), futex_task()]] {
        assert_eq!(
            io_hold_verdict(&io_facts(1, syscall_check(tasks, 38), &['S', 'D'])),
            IoHold::Held
        );
    }
    assert_eq!(
        io_hold_verdict(&io_facts(1, syscall_check(vec![futex_task()], 38), &['S'])),
        IoHold::NotInWrite
    );
    // Not in the write.
    let fdatasync = task(
        "4101",
        &format!(
            "{} 0x3 0x0 0x0 0x0 0x0 0x0 0x7ffc0 0x7f3a1",
            libc::SYS_fdatasync
        ),
    );
    let not_in_write: Vec<Vec<TaskLine>> = vec![
        vec![task("4100", "running\n"), task("4101", "running")],
        vec![
            task("4100", "-1 0x7ffc0 0x7f3a1"),
            task("4101", "-1 0x0 0x0"),
        ],
        vec![],
        vec![futex_task(), fdatasync],
        vec![futex_task(), write_task(IO_KILL_SIZE - 1, 2)],
        vec![futex_task(), write_task(IO_KILL_SIZE + 1, 2)],
        vec![futex_task(), write_task(1_048_576, 2)],
        vec![futex_task(), write_task(IO_KILL_SIZE, 0)],
        vec![futex_task(), write_task(IO_KILL_SIZE, 1)],
    ];
    for tasks in not_in_write {
        let raws: Vec<String> = tasks.iter().map(|t| t.raw.clone()).collect();
        // A task in D outside the write does not count when the syscall
        // check ran.
        assert_eq!(
            io_hold_verdict(&io_facts(1, syscall_check(tasks, 38), &['S', 'D'])),
            IoHold::NotInWrite,
            "{raws:?}"
        );
    }
    // The fallback decides by the task states.
    let refused = || HoldCheck::DState {
        refused: "syscall: EACCES".to_string(),
    };
    assert_eq!(
        io_hold_verdict(&io_facts(1, refused(), &['S', 'D'])),
        IoHold::Held
    );
    for states in [&['S', 'R'][..], &[]] {
        assert_eq!(
            io_hold_verdict(&io_facts(1, refused(), states)),
            IoHold::NotBlocked,
            "{states:?}"
        );
    }
    assert_eq!(
        io_hold_verdict(&io_facts(0, refused(), &['D'])),
        IoHold::Finished
    );
    assert_eq!(hold_check_label(&refused()), "d-state (syscall: EACCES)");
    assert_eq!(hold_check_label(&syscall_check(vec![], 38)), "syscall");
}

#[test]
fn io_hold_failure_messages() {
    let w = write_task(IO_KILL_SIZE, 2);
    let f = io_facts(
        1,
        syscall_check(vec![futex_task(), w.clone()], 38),
        &['S', 'D'],
    );
    let finished = io_facts(0, syscall_check(vec![w.clone()], 41_943_130), &[]);
    let returned = io_facts(1, syscall_check(vec![w.clone()], 41_943_130), &['S']);
    let not_in = io_facts(1, syscall_check(vec![futex_task()], 38), &['S']);
    let refused = io_facts(
        1,
        HoldCheck::DState {
            refused: "io: EPERM".to_string(),
        },
        &['S', 'R'],
    );
    let cases = [
        (
            IoHold::Finished,
            ExitStatus::Exited(0),
            &finished,
            "io.max did not hold the writer",
        ),
        (
            IoHold::Returned,
            ExitStatus::Signaled(9),
            &returned,
            "io.max did not hold the writer: its 40 MiB write returned before the check",
        ),
        (
            IoHold::Finished,
            ExitStatus::Exited(3),
            &finished,
            "the writer failed before the kill",
        ),
        (
            IoHold::Finished,
            ExitStatus::Exited(2),
            &finished,
            "the writer failed before the kill",
        ),
        (
            IoHold::NotInWrite,
            ExitStatus::Signaled(9),
            &not_in,
            "the writer was not inside its 40 MiB write",
        ),
        (
            IoHold::NotBlocked,
            ExitStatus::Signaled(9),
            &refused,
            "the writer was not blocked in its write",
        ),
    ];
    for (v, status, facts, prefix) in cases {
        let m = io_hold_failure(v, status, facts);
        assert!(m.starts_with(prefix), "{v:?} {status:?}: {m}");
        if prefix.starts_with("the writer failed") {
            assert!(!m.contains("io.max did not"), "{m}");
        }
        for part in [
            hold_check_label(&facts.check).as_str(),
            "259:0",
            "at 2004 ms",
            "wbytes 1048576",
            "file_dirty 0",
            "file_writeback 41418752",
            &format!("{status:?}"),
            &format!("{:?}", facts.states),
        ] {
            assert!(m.contains(part), "{v:?}: {part:?} missing in {m}");
        }
        match &facts.check {
            HoldCheck::Syscall { tasks, wchar } => {
                assert!(m.contains(&format!("wchar {wchar}")), "{m}");
                for t in tasks {
                    assert!(m.contains(&format!("{} {:?}", t.tid, t.raw)), "{m}");
                }
            }
            HoldCheck::DState { refused } => {
                assert!(m.contains("wchar not read"), "{m}");
                assert!(m.contains(refused.as_str()), "{m}");
            }
        }
    }
    // The held facts render too (the report line uses the same text).
    assert!(io_hold_failure(IoHold::Held, ExitStatus::Signaled(9), &f).contains("4101"));
}

#[test]
fn parse_syscall_forms() {
    assert_eq!(parse_syscall("running\n"), TaskSyscall::Running);
    assert_eq!(parse_syscall("running"), TaskSyscall::Running);
    assert_eq!(parse_syscall("-1 0x0 0x0"), TaskSyscall::Blocked);
    assert_eq!(parse_syscall("-1 0x7ffc0 0x7f3a1\n"), TaskSyscall::Blocked);
    let measured = TaskSyscall::In {
        nr: 1,
        args: [3, 0x7f3a_0d7f_f000, 41_943_040, 0, 0, 0],
    };
    assert_eq!(
        parse_syscall("1 0x3 0x7f3a0d7ff000 0x2800000 0x0 0x0 0x0 0x7f3a164aad28 0x7f3a1652b352\n"),
        measured
    );
    assert_eq!(
        parse_syscall("1 0x3 0x7f3a0d7ff000 0x02800000 0x0 0x0 0x0 0x7f3a164aad28 0x7f3a1652b352"),
        measured
    );
    assert_eq!(
        parse_syscall("1\t0x3 0x7F3A0D7FF000 0x2800000 0x0 0x0 0x0 0x7F3A164AAD28 0x7f3a1652b352"),
        measured
    );
}

/// Runs `f` and returns its panic message; fails when it does not panic.
fn panic_message(f: impl FnOnce() + std::panic::UnwindSafe) -> String {
    match std::panic::catch_unwind(f) {
        Ok(()) => panic!("no panic"),
        Err(e) => e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default(),
    }
}

#[test]
fn parse_syscall_rejects() {
    let nine = |nr: &str, hex: &[&str]| format!("{nr} {}", hex.join(" "));
    let ok8 = [
        "0x3",
        "0x0",
        "0x2800000",
        "0x0",
        "0x0",
        "0x0",
        "0x7ffc0",
        "0x7f3a1",
    ];
    let mut cases: Vec<String> = [
        "",
        "running 1",
        "Running",
        "-1 0x0",
        "-1 0x0 0x0 0x0",
        "running\u{200b}",
        "-1\u{a0}0x0 0x0",
        "-1 0x0 0x\u{200b}0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    cases.push(nine("1", &ok8[..7]));
    cases.push(format!("{} 0x0", nine("1", &ok8)));
    cases.push(nine("+1", &ok8));
    cases.push(nine("\u{ff11}", &ok8));
    for bad in ["3", "0X3", "0x", "0x+3", "0xg", "0x10000000000000000"] {
        let mut f = ok8;
        f[0] = bad;
        cases.push(nine("1", &f));
    }
    for line in cases {
        let l = line.clone();
        let m = panic_message(move || {
            let _ = parse_syscall(&l);
        });
        assert!(m.contains(&format!("{line:?}")), "{line:?}: {m}");
    }
}

#[test]
fn proc_io_wchar_parses() {
    let io = |wchar: &str| {
        format!(
            "rchar: 4096\nwchar: {wchar}\nsyscr: 2\nsyscw: 4\nread_bytes: 0\nwrite_bytes: 41943040\ncancelled_write_bytes: 0\n"
        )
    };
    assert_eq!(proc_io_wchar(&io("38")), 38);
    assert_eq!(proc_io_wchar(&io("41943130")), 41_943_130);
    assert_eq!(proc_io_wchar("xwchar: 1\nwchar: 2\n"), 2);
    assert_eq!(proc_io_wchar(&io("18446744073709551615")), u64::MAX);
}

#[test]
fn proc_io_wchar_rejects() {
    // No line with the key: the whole text is quoted.
    for text in ["rchar: 1\nsyscw: 4\n", "wchar:38\n"] {
        let t = text.to_string();
        let m = panic_message(move || {
            let _ = proc_io_wchar(&t);
        });
        assert!(m.contains(&format!("{text:?}")), "{text:?}: {m}");
    }
    // A line with the key and a bad value: the line is quoted.
    for value in [
        "",
        "+38",
        "-1",
        "3 8",
        "18446744073709551616",
        "\u{ff13}\u{ff18}",
    ] {
        let line = format!("wchar: {value}");
        let t = format!("rchar: 1\n{line}\nsyscr: 2\n");
        let m = panic_message(move || {
            let _ = proc_io_wchar(&t);
        });
        assert!(m.contains(&format!("{line:?}")), "{line:?}: {m}");
    }
}

#[test]
fn proc_refusal_classes() {
    let e = std::io::Error::from_raw_os_error;
    assert_eq!(proc_refusal(&e(libc::EACCES)), Some("EACCES"));
    assert_eq!(proc_refusal(&e(libc::EPERM)), Some("EPERM"));
    assert_eq!(proc_refusal(&e(libc::ENOENT)), None);
    assert_eq!(proc_refusal(&e(libc::ESRCH)), None);
}

#[test]
fn io_stat_wbytes_parses() {
    let stat = "8:16 rbytes=1 wbytes=999 rios=1 wios=1 dbytes=0 dios=0\n\
                8:1 rbytes=0 wbytes=4096 rios=0 wios=1 dbytes=0 dios=0\n";
    // No line for the device yet: nothing submitted.
    assert_eq!(io_stat_wbytes(stat, 259, 0), 0);
    assert_eq!(io_stat_wbytes("", 8, 1), 0);
    // The key ends in a space, so 8:1 never reads the 8:16 line.
    assert_eq!(io_stat_wbytes(stat, 8, 1), 4096);
    assert_eq!(io_stat_wbytes(stat, 8, 16), 999);
    // The probe's loop_io_stat round trip.
    let joined = crate::support::probe::joined_lines(stat);
    assert_eq!(joined.matches(';').count(), 1, "{joined}");
    let back = joined.replace(';', "\n");
    for (major, minor) in [(8, 1), (8, 16), (259, 0)] {
        assert_eq!(
            io_stat_wbytes(&back, major, minor),
            io_stat_wbytes(stat, major, minor)
        );
    }
    assert_eq!(crate::support::probe::joined_lines(""), "");
    assert_eq!(io_stat_wbytes(&"".replace(';', "\n"), 8, 1), 0);
}

#[test]
#[should_panic(expected = "8:1 rbytes=0 wios=1")]
fn io_stat_wbytes_rejects_line_without_wbytes() {
    let _ = io_stat_wbytes("8:1 rbytes=0 wios=1\n", 8, 1);
}

#[test]
fn stat_state_parses() {
    assert_eq!(stat_state("77 (a) D (b) S 1 2"), Some('S'));
    assert_eq!(stat_state("4101 (probe) D 4100 4100 0 0\n"), Some('D'));
    assert_eq!(stat_state("77 probe S 1 2"), None);
    assert_eq!(stat_state("77 (probe)"), None);
    assert_eq!(stat_state("77 (probe)  \n"), None);
}

#[test]
#[ignore = "host: cgroup v2 delegation (cpu), user namespaces"]
fn destroy_lifts_cpu_throttle() {
    // A quota of 1 ms per 1 s period with four spinning threads keeps the
    // group throttled most of the time; destroy must not wait for the next
    // period refill to let the killed tasks exit.
    let _alone = support::exclusive();
    let cg = cgroup::create(
        "cpu-kill",
        &limits(256 << 20, 16, (1000, 1_000_000), IoLimits::none()),
    );
    let fixture = Fixture::new("cpu-kill");
    // stdout stays /dev/null: a closed pipe there made libtest in the probe
    // panic (exit 101) on its first line, before the spin (CI, measured).
    let mut s = spec(
        root_with_cgroup(&fixture),
        &cg,
        crate::support::rootfs::PROBE,
        &["--exact", "probe", "--nocapture", "--quiet"],
    );
    s.env = [
        (support::probe::ACTION_VAR, "spin"),
        ("BONELI_PROBE_MS", "30000"),
        ("BONELI_PROBE_THREADS", "4"),
    ]
    .iter()
    .map(|(k, v)| (OsString::from(k), OsString::from(v)))
    .collect();
    let mut child = spawn(&s).expect("spawn the spinner");
    drop(s);
    std::thread::sleep(Duration::from_millis(1500));
    let throttled = keyed(&read(&cg, "cpu.stat"), "nr_throttled");
    assert_eq!(
        populated(&cg),
        1,
        "the spinner still runs when destroy starts"
    );
    let start = Instant::now();
    let result = cg.destroy();
    let took = start.elapsed();
    report(&format!(
        "destroy_lifts_cpu_throttle: {throttled} throttled periods before, destroy took {took:?}: {result:?}"
    ));
    let status = wait_bounded(&mut child, Duration::from_secs(30));
    assert!(throttled >= 1, "the spinner was never throttled");
    assert!(result.is_ok(), "{result:?}");
    // Without the lift the kill waited for the next refill: about 500 ms
    // here (measured three times); with it, milliseconds.
    assert!(took < Duration::from_millis(200), "destroy took {took:?}");
    assert_eq!(status, ExitStatus::Signaled(libc::SIGKILL));
}

#[test]
#[ignore = "host: cgroup v2 delegation with nsdelegate, user namespaces"]
fn sandbox_cannot_create_sub_cgroups() {
    // Review of PR 3: inside id 0 can mount a cgroup2 of its own (until
    // PR 4 of #6 drops the capability) and create a sub-cgroup, which
    // would make destroy fail with EBUSY. cgroup.max.descendants and
    // cgroup.max.depth are 0, and nsdelegate keeps the sandbox from
    // raising them again.
    let cg = cgroup::sandbox("no-sub");
    assert_eq!(read(&cg, "cgroup.max.descendants").trim(), "0");
    assert_eq!(read(&cg, "cgroup.max.depth").trim(), "0");
    let fixture = Fixture::new("no-sub");
    let p = run_probe_in("cgroup-mkdir", ids(0, 0), &[], fixture.root(), &cg);
    p.assert_ok();
    assert_eq!(p.get("mount_errno"), "0", "{}", p.raw);
    assert_eq!(
        p.get("mkdir_errno"),
        libc::EAGAIN.to_string(),
        "a sub-cgroup was created: {}",
        p.raw
    );
    assert_eq!(p.get("raise_errno"), libc::EPERM.to_string(), "{}", p.raw);
    assert_eq!(read(&cg, "cgroup.max.descendants").trim(), "0");
    let path = cg.path().to_path_buf();
    cg.destroy().expect("destroy");
    assert!(!path.exists());
}

#[test]
#[ignore = "host: cgroup v2 delegation, user namespaces"]
fn oom_score_adj_never_lowered() {
    // The step raises a negative inherited value to 0 and leaves 0 and
    // above alone. Lowering needs CAP_SYS_RESOURCE, so the negative case
    // is the pure test's (`oom_score_adj_raised_never_lowered`); here the
    // runner raises itself to 500, and the sandbox must keep 500.
    let out = std::process::Command::new(std::env::current_exe().expect("current_exe"))
        .args(["--exact", "probe", "--nocapture", "--quiet"])
        .env(support::probe::ACTION_VAR, "oom-adj-spawn")
        .env("BONELI_PROBE_VALUE", "500")
        .output()
        .expect("run the probe");
    let p = support::parse_probe(support::Output {
        status: match out.status.code() {
            Some(c) => ExitStatus::Exited(c),
            None => ExitStatus::Signaled(-1),
        },
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    });
    p.assert_ok();
    assert_eq!(p.get("inside"), "500", "{}", p.raw);
    // And from this process, whatever it inherited (never below 0 inside).
    let own: i32 = std::fs::read_to_string("/proc/self/oom_score_adj")
        .expect("read own oom_score_adj")
        .trim()
        .parse()
        .expect("a number");
    let p = crate::support::run_probe(
        "read",
        ids(999, 999),
        &[("BONELI_PROBE_FILES", "/proc/self/oom_score_adj")],
    );
    p.assert_ok();
    assert_eq!(
        p.get("file:/proc/self/oom_score_adj").trim(),
        own.max(0).to_string(),
        "{}",
        p.raw
    );
}

#[test]
#[ignore = "host: cgroup v2 delegation"]
fn drop_reports_a_cgroup_it_cannot_remove() {
    // A sub-cgroup the host made (the sandbox cannot) keeps the rmdir
    // failing; the drop must leave a trace, not swallow it.
    let cg = cgroup::sandbox("leak");
    let path = cg.path().to_path_buf();
    std::fs::write(path.join("cgroup.max.descendants"), "1").expect("raise from the host");
    std::fs::write(path.join("cgroup.max.depth"), "1").expect("raise from the host");
    std::fs::create_dir(path.join("sub")).expect("a sub-cgroup");
    drop(cg);
    let leaked = boneli_sys::leaked_cgroups();
    let _ = std::fs::remove_dir(path.join("sub"));
    let _ = std::fs::remove_dir(&path);
    assert!(leaked.contains(&path), "{leaked:?}");
}

#[test]
#[ignore = "host: cgroup v2 delegation (io)"]
fn failed_create_removes_its_cgroup() {
    // Re-review of PR 3: a refused io.max line (an unknown device, ENODEV)
    // made the teardown write the same line again, fail, and skip the
    // removal. Only accepted lines are lifted now, and every teardown
    // step runs.
    let bad = boneli_sys::DeviceNumber {
        major: 259,
        minor: 65000,
    };
    let io = IoLimits::new(vec![IoMax {
        dev: bad,
        rbps: None,
        wbps: Some(1 << 20),
        riops: None,
        wiops: None,
    }])
    .expect("one device");
    let name = cgroup::unique_name("bad-io");
    let path = cgroup::parent().path().join(&name);
    let result = Cgroup::create(
        cgroup::parent(),
        &name,
        &limits(64 << 20, 16, (100_000, 100_000), io),
    );
    let left = path.exists();
    let leaked = boneli_sys::leaked_cgroups();
    let _ = std::fs::remove_dir(&path);
    assert!(
        matches!(
            result,
            Err(Error::CgroupFile {
                file: "io.max",
                errno: libc::ENODEV
            })
        ),
        "{result:?}"
    );
    assert!(!left, "the failed create left {}", path.display());
    assert!(!leaked.contains(&path), "{leaked:?}");
}

#[test]
#[ignore = "host: cgroup v2 delegation"]
fn destroy_failure_is_recorded_with_path() {
    // A sub-cgroup the host made keeps the rmdir failing: destroy returns
    // the path with every error and lists the cgroup as leaked.
    let cg = cgroup::sandbox("destroy-leak");
    let path = cg.path().to_path_buf();
    std::fs::write(path.join("cgroup.max.descendants"), "1").expect("raise from the host");
    std::fs::write(path.join("cgroup.max.depth"), "1").expect("raise from the host");
    std::fs::create_dir(path.join("sub")).expect("a sub-cgroup");
    let result = cg.destroy();
    let leaked = boneli_sys::leaked_cgroups();
    let _ = std::fs::remove_dir(path.join("sub"));
    let _ = std::fs::remove_dir(&path);
    match result {
        Err(Error::CgroupTeardown {
            path: p,
            removed: false,
            errors,
        }) => {
            assert_eq!(p, path);
            assert!(
                errors.iter().any(|e| matches!(
                    e,
                    Error::Sys {
                        call: "unlinkat(cgroup)",
                        errno: libc::EBUSY
                    }
                )),
                "{errors:?}"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(leaked.contains(&path), "{leaked:?}");
}

#[test]
#[ignore = "host: cgroup v2 delegation, user namespaces"]
fn kill_survives_chmod_from_inside() {
    // Review round 3 of PR 3: inside id 0 mounts its own cgroup2 and makes
    // cgroup.kill read-only. The kill goes through the descriptor create
    // held open, so destroy still kills the workload and removes the
    // cgroup.
    let cg = cgroup::sandbox("chmod-kill");
    let fixture = Fixture::new("chmod-kill");
    let mut s = spec(
        fixture.root(),
        &cg,
        crate::support::rootfs::PROBE,
        &["--exact", "probe", "--nocapture", "--quiet"],
    );
    s.env = [
        (support::probe::ACTION_VAR, "chmod-kill"),
        ("BONELI_PROBE_FILE", "/workspace/out"),
    ]
    .iter()
    .map(|(k, v)| (OsString::from(k), OsString::from(v)))
    .collect();
    let mut child = spawn(&s).expect("spawn the probe");
    drop(s);
    let out_file = fixture.workspace.join("out");
    let deadline = Instant::now() + Duration::from_secs(10);
    let out = loop {
        let text = std::fs::read_to_string(&out_file).unwrap_or_default();
        if text.contains("done") || Instant::now() > deadline {
            break text;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(
        out.trim(),
        "mount=0 chmod=0 done",
        "the probe did not chmod"
    );
    let path = cg.path().to_path_buf();
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path.join("cgroup.kill"))
            .expect("stat cgroup.kill")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode, 0o444, "cgroup.kill is read-only now");
    let result = cg.destroy();
    let left = path.exists();
    if left {
        // Clean up before waiting, so a failure here leaves nothing running.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            path.join("cgroup.kill"),
            std::fs::Permissions::from_mode(0o644),
        );
        let _ = std::fs::write(path.join("cgroup.kill"), "1");
    }
    let status = wait_bounded(&mut child, Duration::from_secs(10));
    if left {
        std::thread::sleep(Duration::from_millis(100));
        let _ = std::fs::remove_dir(&path);
    }
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(status, ExitStatus::Signaled(libc::SIGKILL));
    assert!(!left, "{} left behind", path.display());
}
