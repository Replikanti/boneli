//! cgroups v2 (ADR-007, D8): delegation, limits written before any
//! process enters, the limits holding, the cgroup namespace rooted at the
//! sandbox's cgroup, and cleanup.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use boneli_sys::{
    Cgroup, CpuMax, Error, ExitStatus, IoLimits, IoMax, KeeperReport, Limits, Mount, Parent, Root,
    STATS_KEEPER_PERIOD, Spec, Stdio, Step, block_device_of, spawn,
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
    // W = 32 MiB/s. Without the sandbox's statistics keeper the 7.0
    // kernels of CI OOM-killed it in 53 of 54 runs, because dirty
    // throttling judged it by stale memcg statistics (#54, ADR-007 D8).
    // With it the writer is slowed: at the loop's end at most M of the
    // file waits in the page cache, so at least S - M passed the throttle
    // (loop >= 8,000 - 500 ms), and the whole S passed it by the end of
    // the final fdatasync (elapsed >= 16,000 - 500 ms); buffered_bounds.
    let _alone = support::exclusive();
    let f = buffered_case(
        "io_limit_holds_buffered_writes",
        IO_BUF_MEMORY_MAX,
        Some(IO_BUF_WBPS),
        IO_BUF_SIZE,
    );
    buffered_assert("io_limit_holds_buffered_writes", &f);
}

#[test]
#[ignore = "host: cgroup v2 delegation (io, memory), a block device behind the target dir; timing"]
fn io_limit_holds_buffered_writes_at_floor() {
    // The same at the keeper's floor F = 64 MiB, the smallest memory.max
    // its period protects (ADR-007 D8): wbps F / 8 s = 8 MiB/s, 2F
    // written, so the bounds are the same 7,500 and 15,500 ms. Without
    // the keeper this size was OOM-killed in every CI run and on the dev
    // host (#54, K0 in M2a, the trace round and M3).
    let _alone = support::exclusive();
    let f = buffered_case(
        "io_limit_holds_buffered_writes_at_floor",
        KEEPER_FLOOR,
        Some(KEEPER_FLOOR / 8),
        2 * KEEPER_FLOOR,
    );
    buffered_assert("io_limit_holds_buffered_writes_at_floor", &f);
}

#[test]
#[ignore = "host: cgroup v2 delegation (memory), a block device behind the target dir"]
fn buffered_writes_without_io_max_are_not_killed() {
    // 256 MiB, no io.max, 512 MiB buffered: the keeper protects every
    // sandbox, not only those with a write limit (#54, STOP 1 decision 2).
    // Without reads the 7.0 kernels of CI killed it in 47 of 54 runs (M1,
    // N0). No time bound: nothing limits the rate.
    // Without a rate the write can drain before the loop's statistics are
    // read, which makes a run inconclusive ([`buffered_inconclusive`]), so
    // it is retried with a fresh cgroup and keeper (#142).
    let _alone = support::exclusive();
    buffered_assert_retrying("buffered_writes_without_io_max_are_not_killed", || {
        buffered_case(
            "buffered_writes_without_io_max_are_not_killed",
            IO_BUF_MEMORY_MAX,
            None,
            IO_BUF_SIZE,
        )
    });
}

/// What `io_limit_holds_buffered_writes` writes: 512 MiB.
const IO_BUF_SIZE: u64 = 512 << 20;
/// Its `memory.max`: 256 MiB, the harness's `MEMORY_MAX`.
const IO_BUF_MEMORY_MAX: u64 = 256 << 20;
/// Its `wbps`: 32 MiB/s, so the run takes about 16 s.
const IO_BUF_WBPS: u64 = 32 << 20;
/// The smallest `memory.max` the statistics keeper protects (ADR-007 D8,
/// #54 M3, rule R-S1).
const KEEPER_FLOOR: u64 = 64 << 20;
/// One 100 ms throttle slice plus 400 ms of timer and scheduling slack.
const IO_BUF_SLACK_MS: u64 = 500;
/// Hang bound of the buffered writer: about 7 times its 17 s run.
const IO_BUF_HANG: Duration = Duration::from_secs(120);

/// Runs the buffered writer in a cgroup with `memory_max` and, if set,
/// `wbps` on the workspace's device, and gathers the facts.
fn buffered_case(name: &str, memory_max: u64, wbps: Option<u64>, size: u64) -> BufferedFacts {
    let fixture = Fixture::new("io-buffered");
    let dev = block_device_of(&fixture.workspace).unwrap_or_else(|e| {
        panic!(
            "{name} needs a block device behind {}: {e}",
            fixture.workspace.display()
        )
    });
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
    let cg = cgroup::create(
        "io-buffered",
        &limits(memory_max, 16, (100_000, 100_000), io),
    );
    let run = buffered_writer_run(&fixture, &cg, size);
    let events = read(&cg, "memory.events");
    let stat = read(&cg, "io.stat");
    let f = buffered_facts(
        &run,
        BufferedSetup {
            dev: (dev.major, dev.minor),
            size,
            memory_max,
            wbps: wbps.unwrap_or(0),
        },
        keyed(&events, "oom_kill"),
        keyed(&events, "max"),
        &stat,
    );
    let _ = cg.destroy();
    f
}

/// Attempts of `buffered_writes_without_io_max_are_not_killed` while its
/// runs are inconclusive. Without `io.max` nothing slows the writeback, so
/// the last MiB can drain between the loop's end and its statistics read
/// (one run on the dev host left 1 MiB dirty, #142), which reads as
/// [`BufferedHold::NotBuffered`]. 0 of 24 loaded runs were inconclusive,
/// so the chance per run is under 3 / 24 = 12.5 % (rule of three, 95 %),
/// and five inconclusive runs in a row under 0.125^5, about 3 in 10^5.
/// Five runs of 1.3 to 5 s stay far under [`IO_BUF_HANG`] each. The
/// precedent is `cpu_limit_throttles` and `CADENCE_ATTEMPTS` (ADR-007 D8).
const BUFFERED_ATTEMPTS: usize = 5;

/// Whether a buffered run says nothing about the keeper: only
/// [`BufferedHold::NotBuffered`], the write was not buffered when the test
/// looked. A dead keeper or a writer that syncs is `NotBuffered` or a
/// keeper verdict on every attempt, so a retry cannot pass it.
fn buffered_inconclusive(v: BufferedHold) -> bool {
    v == BufferedHold::NotBuffered
}

/// Runs `run` until a run is conclusive ([`buffered_inconclusive`]), at
/// most [`BUFFERED_ATTEMPTS`] times, reports every run, and fails unless
/// the conclusive run is [`BufferedHold::Held`]; every verdict but
/// `NotBuffered` decides at once, and `NotBuffered` on every attempt fails.
fn buffered_assert_retrying(name: &str, mut run: impl FnMut() -> BufferedFacts) {
    let mut inconclusive = 0;
    let mut last = None;
    for attempt in 1..=BUFFERED_ATTEMPTS {
        let f = run();
        let v = buffered_verdict(&f);
        report(&format!(
            "{name}: attempt {attempt}: {v:?}: {}",
            buffered_text(&f)
        ));
        if !buffered_inconclusive(v) {
            assert!(
                v == BufferedHold::Held,
                "attempt {attempt}: {}",
                buffered_failure(v, &f)
            );
            return;
        }
        inconclusive += 1;
        last = Some((v, f));
    }
    let (v, f) = last.expect("BUFFERED_ATTEMPTS is at least 1");
    panic!(
        "{name}: inconclusive in all {inconclusive} attempts: {}",
        buffered_failure(v, &f)
    );
}

/// Reports the facts and fails the test unless they are [`BufferedHold::Held`].
fn buffered_assert(name: &str, f: &BufferedFacts) {
    let v = buffered_verdict(f);
    report(&format!("{name}: {v:?}: {}", buffered_text(f)));
    assert!(v == BufferedHold::Held, "{}", buffered_failure(v, f));
}

/// One run of the buffered writer: its output, the keeper's report before
/// the spawn, when the loop ended and once the writer ended, and the run's
/// wall time from the spawn to the writer's end.
struct BufferedRun {
    probe: support::Probe,
    keeper_before: KeeperReport,
    keeper_at_loop_end: Option<KeeperReport>,
    keeper_after: KeeperReport,
    run_ms: u64,
    /// The report once the keeper read again after `keeper_after`, or
    /// failed, or [`KEEPER_RESUME`] passed without either.
    keeper_settled: KeeperReport,
    /// When the keeper's next read after `keeper_after` was seen, if it
    /// came within [`KEEPER_RESUME`].
    keeper_resumed_ms: Option<u64>,
}

/// How long a buffered case waits after the writer's end for the keeper's
/// next read: 200 periods of 5 ms. A keeper that reads at all reads again
/// within one or a few periods (the largest gap a loaded dev host showed
/// was about 56 ms); one that stopped never does. A stop shows nowhere
/// else: `max_gap` grows only when the next read lands, and the read
/// counts run from before the spawn (#78 review, run 2).
const KEEPER_RESUME: Duration = Duration::from_secs(1);

/// Waits up to [`KEEPER_RESUME`] for a read after `after` or a failure,
/// and returns the last report and when a read was seen.
fn keeper_resume(cg: &Cgroup, after: KeeperReport) -> (KeeperReport, Option<u64>) {
    let start = Instant::now();
    loop {
        let r = cg.stats_keeper();
        let waited = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        if r.reads > after.reads {
            return (r, Some(waited));
        }
        if r.failed.is_some() || start.elapsed() >= KEEPER_RESUME {
            return (r, None);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Runs the buffered writer in `cg` on `fixture` and waits for it within
/// [`IO_BUF_HANG`]. Its output goes through pipes read on threads, so the
/// hang bound starts at once: `run_in` reads the pipes to EOF before its
/// hang bound starts, so a stuck writer would hold the job until its
/// timeout. Not files: the probe's output written to a file is a dirty
/// page charged to the sandbox, which hid a loop that synced every write
/// from the not-buffered guard (mutant MD, measured: 4,096 bytes). The
/// stdout reader takes the keeper's report as the `loop_ms` line arrives;
/// a writer killed in its loop prints none, so the report after the
/// writer's end is what shows whether the keeper read during such a run
/// (#54 review).
fn buffered_writer_run(fixture: &Fixture, cg: &Cgroup, size: u64) -> BufferedRun {
    let _runs = support::shared();
    let (out_r, out_w) = support::pipe();
    let (err_r, err_w) = support::pipe();
    let mut s = spec(
        root_with_cgroup(fixture),
        cg,
        crate::support::rootfs::PROBE,
        &["--exact", "probe", "--nocapture", "--quiet"],
    );
    s.stdio.stdout = out_w;
    s.stdio.stderr = err_w;
    let size = size.to_string();
    s.env = [
        (support::probe::ACTION_VAR, "io-write"),
        ("BONELI_PROBE_FILE", "/workspace/buffered"),
        ("BONELI_PROBE_SIZE", size.as_str()),
        ("BONELI_PROBE_DIRECT", "never"),
    ]
    .iter()
    .map(|(k, v)| (OsString::from(k), OsString::from(v)))
    .collect();
    let keeper_before = cg.stats_keeper();
    let started = Instant::now();
    let mut child = spawn(&s).expect("spawn the buffered writer");
    // The write ends live in the spec; dropping it leaves the child as the
    // only writer, so the reads end when it exits.
    drop(s);
    std::thread::scope(|scope| {
        let out = scope.spawn(move || {
            use std::io::BufRead;
            let mut r = std::io::BufReader::new(std::fs::File::from(out_r));
            let mut text = String::new();
            let mut at_loop_end = None;
            loop {
                let n = r
                    .read_line(&mut text)
                    .expect("read the buffered writer's stdout");
                if n == 0 {
                    break;
                }
                if at_loop_end.is_none() && text.contains("BONELI_PROBE loop_ms=") {
                    at_loop_end = Some(cg.stats_keeper());
                }
            }
            (text, at_loop_end)
        });
        let err = scope.spawn(move || {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut std::fs::File::from(err_r), &mut buf)
                .expect("read the buffered writer's stderr");
            String::from_utf8_lossy(&buf).into_owned()
        });
        let status = wait_bounded(&mut child, IO_BUF_HANG);
        // The keeper runs until the cgroup is destroyed, so this report
        // covers the whole run, a killed one too.
        let keeper_after = cg.stats_keeper();
        let run_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let (keeper_settled, keeper_resumed_ms) = keeper_resume(cg, keeper_after);
        let (stdout, keeper_at_loop_end) = out.join().expect("the stdout reader");
        let stderr = err.join().expect("the stderr reader");
        BufferedRun {
            probe: support::parse_probe(support::Output {
                status,
                stdout,
                stderr,
            }),
            keeper_before,
            keeper_at_loop_end,
            keeper_after,
            run_ms,
            keeper_settled,
            keeper_resumed_ms,
        }
    })
}

/// A buffered case's sizes.
#[derive(Debug, Clone, Copy)]
struct BufferedSetup {
    dev: (u32, u32),
    size: u64,
    memory_max: u64,
    /// 0: no `io.max` line.
    wbps: u64,
}

/// What a buffered case measured.
#[derive(Debug, Clone)]
struct BufferedFacts {
    setup: BufferedSetup,
    kernel: String,
    status: ExitStatus,
    oom_kill: u64,
    max_events: u64,
    loop_start: bool,
    loop_ms: Option<u64>,
    elapsed_ms: Option<u64>,
    last_progress: Option<String>,
    loop_wbytes: u64,
    loop_file_dirty: u64,
    loop_file_writeback: u64,
    /// The cgroup's `io.stat` after the run, every line.
    io_stat: String,
    wbytes: u64,
    keeper_before: KeeperReport,
    keeper_at_loop_end: Option<KeeperReport>,
    /// The keeper's report once the writer ended.
    keeper_after: KeeperReport,
    /// From the spawn to the writer's end.
    run_ms: u64,
    /// The keeper's report once it read again after the run, failed, or
    /// [`KEEPER_RESUME`] passed.
    keeper_settled: KeeperReport,
    /// When that next read was seen; `None`: not within [`KEEPER_RESUME`].
    keeper_resumed_ms: Option<u64>,
}

/// The facts from the probe's keys (a missing number reads 0, a missing
/// time `None`), the keeper's reports and the cgroup's files.
fn buffered_facts(
    run: &BufferedRun,
    setup: BufferedSetup,
    oom_kill: u64,
    max_events: u64,
    io_stat: &str,
) -> BufferedFacts {
    let p = &run.probe;
    let time = |k: &str| p.values.get(k).and_then(|v| v.parse().ok());
    let number = |k: &str| time(k).unwrap_or(0);
    let loop_stat = p
        .values
        .get("loop_io_stat")
        .map(|s| s.replace(';', "\n"))
        .unwrap_or_default();
    BufferedFacts {
        setup,
        kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_or_else(|e| format!("unreadable ({e})"), |k| k.trim().to_string()),
        status: p.status,
        oom_kill,
        max_events,
        loop_start: p.values.get("loop_start").is_some_and(|v| v == "1"),
        loop_ms: time("loop_ms"),
        elapsed_ms: time("elapsed_ms"),
        last_progress: p.values.get("progress").cloned(),
        loop_wbytes: io_stat_wbytes(&loop_stat, setup.dev.0, setup.dev.1),
        loop_file_dirty: number("loop_file_dirty"),
        loop_file_writeback: number("loop_file_writeback"),
        io_stat: io_stat.to_string(),
        wbytes: io_stat_wbytes(io_stat, setup.dev.0, setup.dev.1),
        keeper_before: run.keeper_before,
        keeper_at_loop_end: run.keeper_at_loop_end,
        keeper_after: run.keeper_after,
        run_ms: run.run_ms,
        keeper_settled: run.keeper_settled,
        keeper_resumed_ms: run.keeper_resumed_ms,
    }
}

/// What one buffered run shows, in the order of precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferedHold {
    /// The sandbox's statistics keeper failed, before, during or after the
    /// run: nothing protected the writer, so nothing else is said.
    KeeperFailed,
    /// The keeper stopped: no read within [`KEEPER_RESUME`] after the
    /// writer's end, in any run. Or an OOM kill while the keeper stalled:
    /// it read less than once per 10 periods of the run, or paused longer
    /// than 10 periods. The keeper, not the kernel, is the first suspect
    /// (ADR-007 D8, "What could still defeat it" (4)).
    KeeperStalled,
    /// An OOM kill although the keeper kept reading: dirty throttling did
    /// not slow the writer in time, so a read of `memory.stat` may no
    /// longer flush (ADR-007 D8, "What could still defeat it" (3)).
    OomKilled,
    /// The writer did not exit 0 or printed no `loop_start`, `loop_ms` or
    /// `elapsed_ms`.
    WriterFailed,
    /// No dirty data at the loop's end, or the device had counted every
    /// byte by then: not a buffered write. A buffered loop leaves at least
    /// its last write in the page cache when it ends; a loop that synced
    /// every write showed `file_writeback` 1 MiB in statistics read right
    /// after it (mutant MD, dev host), so dirty data alone does not tell.
    NotBuffered,
    /// The loop or the whole write finished under its bound: io.max did
    /// not hold.
    Escaped,
    /// The limited device did not see every byte.
    OffDevice,
    /// The keeper did not read at least once per 10 periods of the loop.
    KeeperIdle,
    /// Slowed, not killed, every bound met.
    Held,
}

/// The least loop time and the least whole-write time in ms that `wbps`
/// allows: (S - M) and S over the rate, each minus [`IO_BUF_SLACK_MS`];
/// (0, 0) without a rate. Floors, so it errs low.
fn buffered_bounds_ms(size: u64, memory_max: u64, wbps: u64) -> (u64, u64) {
    let over = |bytes: u64| {
        bytes
            .saturating_mul(1000)
            .checked_div(wbps)
            .unwrap_or(0)
            .saturating_sub(IO_BUF_SLACK_MS)
    };
    (over(size.saturating_sub(memory_max)), over(size))
}

/// The keeper's reads from before the spawn to the loop's end, and the
/// least it must have done: one per 10 keeper periods of the loop, at
/// least one. A tenth of what it should read: a keeper that reads at all
/// reads far more, one that stopped or stalls for good reads less.
fn keeper_reads(f: &BufferedFacts) -> (u64, u64) {
    let done = f
        .keeper_at_loop_end
        .map_or(0, |r| r.reads.saturating_sub(f.keeper_before.reads));
    let ten_periods = 10 * STATS_KEEPER_PERIOD.as_millis() as u64;
    let need = (f.loop_ms.unwrap_or(0) / ten_periods).max(1);
    (done, need)
}

/// The keeper's reads from before the spawn to the writer's end, and the
/// least it must have done: one per 10 keeper periods of the run, at least
/// one (the measure of [`keeper_reads`], over the whole run).
fn keeper_run_reads(f: &BufferedFacts) -> (u64, u64) {
    let done = f.keeper_after.reads.saturating_sub(f.keeper_before.reads);
    let ten_periods = 10 * STATS_KEEPER_PERIOD.as_millis() as u64;
    (done, (f.run_ms / ten_periods).max(1))
}

/// The keeper read less than [`keeper_run_reads`] asks, or its largest gap
/// between two reads, over its whole life, is over 10 periods, or it
/// stopped ([`keeper_stopped`]).
fn keeper_stalled(f: &BufferedFacts) -> bool {
    let (done, need) = keeper_run_reads(f);
    done < need || f.keeper_after.max_gap > 10 * STATS_KEEPER_PERIOD || keeper_stopped(f)
}

/// No read within [`KEEPER_RESUME`] after the writer's end: the gap still
/// open when the run was judged.
fn keeper_stopped(f: &BufferedFacts) -> bool {
    f.keeper_settled.reads <= f.keeper_after.reads
}

/// The first `errno` a keeper report shows, before, at the loop's end or
/// after the run.
fn keeper_failure(f: &BufferedFacts) -> Option<i32> {
    [
        Some(f.keeper_before),
        f.keeper_at_loop_end,
        Some(f.keeper_after),
        Some(f.keeper_settled),
    ]
    .into_iter()
    .flatten()
    .find_map(|r| r.failed)
}

fn buffered_verdict(f: &BufferedFacts) -> BufferedHold {
    if keeper_failure(f).is_some() {
        return BufferedHold::KeeperFailed;
    }
    if keeper_stopped(f) {
        return BufferedHold::KeeperStalled;
    }
    if f.oom_kill >= 1 {
        return if keeper_stalled(f) {
            BufferedHold::KeeperStalled
        } else {
            BufferedHold::OomKilled
        };
    }
    let (Some(loop_ms), Some(elapsed_ms), true, ExitStatus::Exited(0)) =
        (f.loop_ms, f.elapsed_ms, f.loop_start, f.status)
    else {
        return BufferedHold::WriterFailed;
    };
    let (loop_bound, elapsed_bound) =
        buffered_bounds_ms(f.setup.size, f.setup.memory_max, f.setup.wbps);
    let (done, need) = keeper_reads(f);
    if f.loop_file_dirty.saturating_add(f.loop_file_writeback) == 0 || f.loop_wbytes >= f.setup.size
    {
        BufferedHold::NotBuffered
    } else if loop_ms < loop_bound || elapsed_ms < elapsed_bound {
        BufferedHold::Escaped
    } else if f.wbytes < f.setup.size {
        BufferedHold::OffDevice
    } else if done < need {
        BufferedHold::KeeperIdle
    } else {
        BufferedHold::Held
    }
}

fn opt_ms(v: Option<u64>) -> String {
    v.map_or("none".to_string(), |v| v.to_string())
}

fn keeper_text(r: Option<KeeperReport>) -> String {
    r.map_or("none".to_string(), |r| {
        format!(
            "reads {} late {} max_gap {:?} max_read {:?} cpu {:?} failed {:?}",
            r.reads, r.late, r.max_gap, r.max_read, r.cpu, r.failed
        )
    })
}

/// The facts of a buffered case, for its report line and every message.
fn buffered_text(f: &BufferedFacts) -> String {
    let (loop_bound, elapsed_bound) =
        buffered_bounds_ms(f.setup.size, f.setup.memory_max, f.setup.wbps);
    let (done, need) = keeper_reads(f);
    let (run_done, run_need) = keeper_run_reads(f);
    format!(
        "kernel {}, device {}:{}, status {:?}, oom_kill {}, memory.events max {}, \
         loop_start {}, loop_ms {} (bound {loop_bound}), elapsed_ms {} (bound {elapsed_bound}), \
         last progress {}, loop wbytes {}, loop file_dirty {}, loop file_writeback {}, \
         wbytes {} after fdatasync, io.stat [{}], size {}, memory.max {}, wbps {}, \
         keeper reads in the loop {done} (need {need}), in the run {run_done} (need {run_need}) \
         over run_ms {}, keeper before [{}], at the loop's end [{}], after the run [{}], \
         next read after the run {}, settled [{}], period {:?}",
        f.kernel,
        f.setup.dev.0,
        f.setup.dev.1,
        f.status,
        f.oom_kill,
        f.max_events,
        f.loop_start,
        opt_ms(f.loop_ms),
        opt_ms(f.elapsed_ms),
        f.last_progress.as_deref().unwrap_or("none"),
        f.loop_wbytes,
        f.loop_file_dirty,
        f.loop_file_writeback,
        f.wbytes,
        f.io_stat.lines().collect::<Vec<_>>().join("; "),
        f.setup.size,
        f.setup.memory_max,
        f.setup.wbps,
        f.run_ms,
        keeper_text(Some(f.keeper_before)),
        keeper_text(f.keeper_at_loop_end),
        keeper_text(Some(f.keeper_after)),
        resumed_text(f.keeper_resumed_ms),
        keeper_text(Some(f.keeper_settled)),
        boneli_sys::STATS_KEEPER_PERIOD,
    )
}

/// When the keeper's next read after the run came.
fn resumed_text(ms: Option<u64>) -> String {
    ms.map_or_else(
        || format!("none within {KEEPER_RESUME:?}"),
        |ms| format!("{ms} ms"),
    )
}

fn buffered_failure(v: BufferedHold, f: &BufferedFacts) -> String {
    let (loop_bound, elapsed_bound) =
        buffered_bounds_ms(f.setup.size, f.setup.memory_max, f.setup.wbps);
    let why = match v {
        BufferedHold::KeeperFailed => format!(
            "the sandbox's memory statistics keeper failed (errno {}), so nothing kept the \
             statistics fresh (ADR-007 D8)",
            keeper_failure(f).unwrap_or(0)
        ),
        BufferedHold::KeeperStalled => {
            let (done, need) = keeper_run_reads(f);
            let killed = if f.oom_kill >= 1 {
                format!(
                    "the buffered writer was OOM-killed (memory.events oom_kill {}) while the \
                     statistics keeper stalled",
                    f.oom_kill
                )
            } else {
                "the statistics keeper stopped".to_string()
            };
            format!(
                "{killed}: {done} reads in the run's {} ms (need {need}, one per 10 keeper \
                 periods), largest gap {:?} (bound {:?}), next read after the run {}; suspect \
                 the keeper first (ADR-007 D8)",
                f.run_ms,
                f.keeper_after.max_gap,
                10 * STATS_KEEPER_PERIOD,
                resumed_text(f.keeper_resumed_ms)
            )
        }
        BufferedHold::OomKilled => {
            let (done, need) = keeper_run_reads(f);
            format!(
                "the buffered writer was OOM-killed (memory.events oom_kill {}) although the \
                 statistics keeper read {done} times in the run's {} ms (need {need}), largest \
                 gap {:?}: dirty throttling did not slow it in time, so a read of memory.stat \
                 may no longer flush the statistics (ADR-007 D8)",
                f.oom_kill, f.run_ms, f.keeper_after.max_gap
            )
        }
        BufferedHold::WriterFailed => "the buffered writer failed".to_string(),
        BufferedHold::NotBuffered => format!(
            "the write loop left no dirty data, or the workspace's device had counted all {} bytes \
             ({} by the loop's end), so it was not a buffered write and the test did not \
             cover the kernel's writeback",
            f.setup.size, f.loop_wbytes
        ),
        BufferedHold::Escaped => format!(
            "io.max did not hold the buffered write: the loop took {} ms (bound {loop_bound}) \
             and the whole write {} ms (bound {elapsed_bound}) at wbps {} with memory.max {}",
            opt_ms(f.loop_ms),
            opt_ms(f.elapsed_ms),
            f.setup.wbps,
            f.setup.memory_max
        ),
        BufferedHold::OffDevice => format!(
            "the buffered bytes did not reach the limited device: wbytes {} on {}:{} after \
             fdatasync, under the {} bytes written",
            f.wbytes, f.setup.dev.0, f.setup.dev.1, f.setup.size
        ),
        BufferedHold::KeeperIdle => {
            let (done, need) = keeper_reads(f);
            format!(
                "the statistics keeper read {done} times during the loop, under the {need} \
                 (one per 10 keeper periods): it ran but did not read"
            )
        }
        BufferedHold::Held => "the buffered write was held".to_string(),
    };
    format!("{why}: {}", buffered_text(f))
}

/// A held run at 512 MiB, 256 MiB, 32 MiB/s with `loop_ms` (measured
/// shape: M1's A3 runs); the run takes 200 ms more than the whole write,
/// or 470 ms without a loop time.
fn buffered_facts_for(loop_ms: Option<u64>) -> BufferedFacts {
    let run_ms = loop_ms.map_or(470, |l| l + 1_700);
    let keeper = |reads: u64| KeeperReport {
        reads,
        late: 0,
        max_gap: Duration::from_millis(11),
        max_read: Duration::from_micros(90),
        cpu: Duration::from_micros(70 * reads),
        failed: None,
    };
    BufferedFacts {
        setup: BufferedSetup {
            dev: (259, 0),
            size: IO_BUF_SIZE,
            memory_max: IO_BUF_MEMORY_MAX,
            wbps: IO_BUF_WBPS,
        },
        kernel: "7.0.0-1019-azure".to_string(),
        status: ExitStatus::Exited(0),
        oom_kill: 0,
        max_events: 1044,
        loop_start: true,
        loop_ms,
        elapsed_ms: loop_ms.map(|l| l + 1_500),
        last_progress: Some("512:14600:230000".to_string()),
        loop_wbytes: 480_000_000,
        loop_file_dirty: 30_000_000,
        loop_file_writeback: 3_000_000,
        io_stat: "259:0 rbytes=0 wbytes=536870912 rios=0 wios=4096 dbytes=0 dios=0\n8:0 rbytes=4096 wbytes=0 rios=1 wios=0 dbytes=0 dios=0".to_string(),
        wbytes: IO_BUF_SIZE,
        keeper_before: keeper(100),
        keeper_at_loop_end: Some(keeper(100 + loop_ms.unwrap_or(0) / 10)),
        // A keeper that read every period of the run.
        keeper_after: keeper(100 + run_ms / STATS_KEEPER_PERIOD.as_millis() as u64),
        run_ms,
        // It read again one period after the run.
        keeper_settled: keeper(101 + run_ms / STATS_KEEPER_PERIOD.as_millis() as u64),
        keeper_resumed_ms: Some(STATS_KEEPER_PERIOD.as_millis() as u64),
    }
}

#[test]
fn buffered_bounds() {
    // The three sizes of the keeper's measurement: M / 8 s, 2M written.
    for m in [64u64 << 20, 128 << 20, 256 << 20] {
        assert_eq!(buffered_bounds_ms(2 * m, m, m / 8), (7500, 15_500), "{m}");
    }
    // At F = 64 MiB, written out.
    assert_eq!((134_217_728u64 - 67_108_864) * 1000 / 8_388_608 - 500, 7500);
    assert_eq!(134_217_728u64 * 1000 / 8_388_608 - 500, 15_500);
    assert_eq!(
        buffered_bounds_ms(536_870_912, 268_435_456, 33_554_433),
        (7499, 15_499)
    );
    // S <= M: no loop bound, saturating.
    assert_eq!(
        buffered_bounds_ms(268_435_456, 268_435_456, 33_554_432).0,
        0
    );
    assert_eq!(buffered_bounds_ms(1, 268_435_456, 33_554_432), (0, 0));
    // No rate: no bounds and no division by zero.
    assert_eq!(buffered_bounds_ms(536_870_912, 268_435_456, 0), (0, 0));
    assert_eq!(
        buffered_bounds_ms(u64::MAX, 0, 1),
        (18_446_744_073_709_551_115, 18_446_744_073_709_551_115)
    );
}

#[test]
fn buffered_verdicts() {
    let f = buffered_facts_for;
    assert_eq!(buffered_verdict(&f(Some(14_600))), BufferedHold::Held);
    // The loop bound is inclusive.
    let mut g = f(Some(7500));
    g.elapsed_ms = Some(16_000);
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    g.loop_ms = Some(7499);
    assert_eq!(buffered_verdict(&g), BufferedHold::Escaped);
    // The elapsed bound is inclusive.
    let mut g = f(Some(14_000));
    g.elapsed_ms = Some(15_500);
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    g.elapsed_ms = Some(15_499);
    assert_eq!(buffered_verdict(&g), BufferedHold::Escaped);
    // wbytes, inclusive.
    let mut g = f(Some(14_600));
    g.wbytes = 536_870_911;
    assert_eq!(buffered_verdict(&g), BufferedHold::OffDevice);
    g.wbytes = 536_870_912;
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    // The keeper's reads during the loop: one per 10 periods, at least
    // one. A 7,500 ms loop needs 150 at 5 ms and 75 at 10 ms.
    let need = match STATS_KEEPER_PERIOD.as_millis() {
        5 => 150,
        10 => 75,
        25 => 30,
        50 => 15,
        p => panic!("no case for a period of {p} ms"),
    };
    let mut g = f(Some(7500));
    g.elapsed_ms = Some(16_000);
    let mut at_end = g.keeper_before;
    at_end.reads += need;
    g.keeper_at_loop_end = Some(at_end);
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    at_end.reads -= 1;
    g.keeper_at_loop_end = Some(at_end);
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperIdle);
    // A 40 ms loop needs 1.
    let mut g = f(Some(40));
    g.setup.wbps = 0;
    let mut at_end = g.keeper_before;
    g.keeper_at_loop_end = Some(at_end);
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperIdle);
    at_end.reads += 1;
    g.keeper_at_loop_end = Some(at_end);
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    // No report at the loop's end: no reads counted.
    g.keeper_at_loop_end = None;
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperIdle);

    // Precedence: KeeperFailed > KeeperStalled > OomKilled > WriterFailed >
    // NotBuffered > Escaped > OffDevice > KeeperIdle > Held, each over
    // everything after.
    let mut all = f(None);
    all.status = ExitStatus::Signaled(9);
    all.oom_kill = 1;
    all.loop_start = false;
    all.loop_file_dirty = 0;
    all.loop_file_writeback = 0;
    all.wbytes = 0;
    all.keeper_at_loop_end = None;
    all.keeper_before.failed = Some(libc::ENODEV);
    assert_eq!(buffered_verdict(&all), BufferedHold::KeeperFailed);
    // A failure at the loop's end counts too.
    let mut g = f(Some(14_600));
    let mut at_end = g.keeper_at_loop_end.expect("a report");
    at_end.failed = Some(libc::ENODEV);
    g.keeper_at_loop_end = Some(at_end);
    g.oom_kill = 1;
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperFailed);
    // A failure only in the report after the run counts too: a writer
    // killed in its loop prints no loop_ms, so there is no loop-end report
    // (#54 review, finding 1).
    let mut g = f(None);
    g.oom_kill = 1;
    g.keeper_at_loop_end = None;
    g.keeper_after.failed = Some(libc::EIO);
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperFailed);
    all.keeper_before.failed = None;
    all.keeper_after.reads = all.keeper_before.reads;
    assert_eq!(buffered_verdict(&all), BufferedHold::KeeperStalled);
    all.keeper_after = f(None).keeper_after;
    assert_eq!(buffered_verdict(&all), BufferedHold::OomKilled);
    let mut g = f(Some(14_600));
    g.oom_kill = 1;
    assert_eq!(buffered_verdict(&g), BufferedHold::OomKilled);
    all.oom_kill = 0;
    assert_eq!(buffered_verdict(&all), BufferedHold::WriterFailed);
    for (status, loop_ms, elapsed, start) in [
        (ExitStatus::Exited(101), Some(14_600), Some(16_100), true),
        (ExitStatus::Signaled(9), Some(14_600), Some(16_100), true),
        (ExitStatus::Exited(0), None, Some(16_100), true),
        (ExitStatus::Exited(0), Some(14_600), None, true),
        (ExitStatus::Exited(0), Some(14_600), Some(16_100), false),
    ] {
        let mut g = f(loop_ms);
        g.status = status;
        g.elapsed_ms = elapsed;
        g.loop_start = start;
        assert_eq!(
            buffered_verdict(&g),
            BufferedHold::WriterFailed,
            "{status:?} {loop_ms:?} {elapsed:?} {start}"
        );
    }
    let mut g = f(Some(10));
    g.elapsed_ms = Some(20);
    g.loop_file_dirty = 0;
    g.loop_file_writeback = 0;
    g.wbytes = 0;
    g.keeper_at_loop_end = None;
    assert_eq!(buffered_verdict(&g), BufferedHold::NotBuffered);
    g.loop_file_writeback = 4096;
    assert_eq!(buffered_verdict(&g), BufferedHold::Escaped);
    g.loop_ms = Some(7500);
    g.elapsed_ms = Some(15_500);
    assert_eq!(buffered_verdict(&g), BufferedHold::OffDevice);
    g.wbytes = IO_BUF_SIZE;
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperIdle);
    // The device counted every byte by the loop's end: the loop synced
    // (mutant MD), whatever the statistics still show. One byte short is
    // still buffered.
    let mut g = f(Some(14_600));
    g.loop_wbytes = IO_BUF_SIZE - 1;
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    g.loop_wbytes = IO_BUF_SIZE;
    assert_eq!(buffered_verdict(&g), BufferedHold::NotBuffered);
    g.oom_kill = 1;
    assert_eq!(buffered_verdict(&g), BufferedHold::OomKilled);
    // Dirty plus writeback saturates.
    let mut g = f(Some(14_600));
    g.loop_file_dirty = u64::MAX;
    g.loop_file_writeback = 1;
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
}

/// Runs [`buffered_assert_retrying`] over `script`, one entry per run,
/// and returns its panic message, if it failed, and how many runs it made.
fn retried(script: Vec<BufferedFacts>) -> (Option<String>, usize) {
    let runs = std::cell::Cell::new(0);
    let mut script = script.into_iter();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        buffered_assert_retrying("buffered_retry", || {
            runs.set(runs.get() + 1);
            script.next().expect("a scripted run")
        });
    }));
    let message = outcome.err().map(|e| {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    });
    (message, runs.get())
}

#[test]
fn buffered_retry() {
    let held = || buffered_facts_for(Some(14_600));
    let not_buffered = || {
        let mut g = held();
        g.loop_file_dirty = 0;
        g.loop_file_writeback = 0;
        g
    };
    assert_eq!(buffered_verdict(&not_buffered()), BufferedHold::NotBuffered);
    // Inconclusive four times, then held: passes on the fifth run.
    let mut script: Vec<_> = (0..4).map(|_| not_buffered()).collect();
    script.push(held());
    assert_eq!(retried(script), (None, 5));
    // Held at once: one run.
    assert_eq!(retried(vec![held()]), (None, 1));
    // Inconclusive in every attempt: fails after the last, never a sixth.
    let (m, runs) = retried((0..6).map(|_| not_buffered()).collect());
    assert_eq!(runs, BUFFERED_ATTEMPTS);
    assert_eq!(runs, 5);
    let m = m.expect("five inconclusive runs fail");
    assert!(m.contains("inconclusive in all 5 attempts"), "{m}");
    assert!(m.contains("not a buffered write"), "{m}");
    // A deciding verdict after an inconclusive one fails at once.
    let mut oom = held();
    oom.oom_kill = 1;
    assert_eq!(buffered_verdict(&oom), BufferedHold::OomKilled);
    let (m, runs) = retried(vec![not_buffered(), oom.clone(), held()]);
    assert_eq!(runs, 2);
    assert!(m.expect("an OOM kill fails").contains("OOM-killed"));
    // Every other verdict fails on the first attempt, without a rerun.
    let mut idle = held();
    idle.keeper_at_loop_end = None;
    let mut escaped = held();
    escaped.loop_ms = Some(7499);
    escaped.elapsed_ms = Some(16_000);
    let mut off = held();
    off.wbytes = IO_BUF_SIZE - 1;
    let mut stalled = held();
    stalled.keeper_settled = stalled.keeper_after;
    stalled.keeper_resumed_ms = None;
    let mut failed = held();
    failed.keeper_after.failed = Some(libc::EIO);
    let mut writer = held();
    writer.status = ExitStatus::Exited(101);
    for (g, v) in [
        (idle, BufferedHold::KeeperIdle),
        (escaped, BufferedHold::Escaped),
        (off, BufferedHold::OffDevice),
        (stalled, BufferedHold::KeeperStalled),
        (failed, BufferedHold::KeeperFailed),
        (writer, BufferedHold::WriterFailed),
        (oom, BufferedHold::OomKilled),
    ] {
        assert_eq!(buffered_verdict(&g), v);
        let (m, runs) = retried(vec![g, held()]);
        assert_eq!(runs, 1, "{v:?} was retried");
        assert!(m.is_some(), "{v:?} passed");
    }
    // Only NotBuffered is inconclusive.
    for v in [
        BufferedHold::KeeperFailed,
        BufferedHold::KeeperStalled,
        BufferedHold::OomKilled,
        BufferedHold::WriterFailed,
        BufferedHold::Escaped,
        BufferedHold::OffDevice,
        BufferedHold::KeeperIdle,
        BufferedHold::Held,
    ] {
        assert!(!buffered_inconclusive(v), "{v:?}");
    }
    assert!(buffered_inconclusive(BufferedHold::NotBuffered));
}

#[test]
fn buffered_keeper_stalled() {
    // An OOM kill is the keeper's (KeeperStalled) when it read less than
    // once per 10 periods of the run or paused longer than 10 periods,
    // and the kernel's (OomKilled) otherwise (#54 review, finding 1).
    let ten = 10 * STATS_KEEPER_PERIOD;
    let ten_ms = ten.as_millis() as u64;
    let killed = |run_ms: u64, reads: u64, max_gap: Duration| {
        let mut g = buffered_facts_for(None);
        g.oom_kill = 1;
        g.keeper_at_loop_end = None;
        g.run_ms = run_ms;
        g.keeper_after = g.keeper_before;
        g.keeper_after.reads += reads;
        g.keeper_after.max_gap = max_gap;
        // It read again after the run.
        g.keeper_settled = g.keeper_after;
        g.keeper_settled.reads += 1;
        buffered_verdict(&g)
    };
    let gap = Duration::from_millis(6);
    // Reads: one per 10 periods of the run, inclusive.
    assert_eq!(killed(470, 470 / ten_ms, gap), BufferedHold::OomKilled);
    assert_eq!(
        killed(470, 470 / ten_ms - 1, gap),
        BufferedHold::KeeperStalled
    );
    // At least one, also for a run shorter than 10 periods.
    assert_eq!(killed(ten_ms - 1, 1, gap), BufferedHold::OomKilled);
    assert_eq!(killed(0, 0, gap), BufferedHold::KeeperStalled);
    // The keeper that stopped reading at the spawn.
    assert_eq!(killed(470, 0, gap), BufferedHold::KeeperStalled);
    // The largest gap, inclusive at 10 periods.
    assert_eq!(killed(470, 94, ten), BufferedHold::OomKilled);
    assert_eq!(
        killed(470, 94, ten + Duration::from_nanos(1)),
        BufferedHold::KeeperStalled
    );
    // No OOM kill: a stalled keeper is not a verdict of its own there
    // (KeeperIdle judges the loop's reads).
    let mut g = buffered_facts_for(Some(14_600));
    g.keeper_after = g.keeper_before;
    g.keeper_after.max_gap = Duration::from_secs(1);
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    // A keeper that stopped, whatever it read before: no read within
    // KEEPER_RESUME after the writer's end (#78 review, run 2: a keeper
    // hung after 300 reads read 299 in a 2,814 ms run, largest gap 6 ms).
    let stopped = |mut g: BufferedFacts| {
        g.keeper_settled = g.keeper_after;
        g.keeper_resumed_ms = None;
        g
    };
    let mut g = buffered_facts_for(None);
    g.oom_kill = 1;
    g.keeper_at_loop_end = None;
    g.run_ms = 2814;
    g.keeper_after = g.keeper_before;
    g.keeper_after.reads += 299;
    g.keeper_after.max_gap = Duration::from_micros(6256);
    g.keeper_settled = g.keeper_after;
    g.keeper_settled.reads += 1;
    assert_eq!(buffered_verdict(&g), BufferedHold::OomKilled);
    let g = stopped(g);
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperStalled);
    let m = buffered_failure(BufferedHold::KeeperStalled, &g);
    assert!(
        m.starts_with(
            "the buffered writer was OOM-killed (memory.events oom_kill 1) while the statistics \
             keeper stalled: 299 reads"
        ),
        "{m}"
    );
    assert!(m.contains("next read after the run none within 1s"), "{m}");
    // Also without an OOM kill: a held run with a stopped keeper is not Held.
    let g = stopped(buffered_facts_for(Some(14_600)));
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperStalled);
    let m = buffered_failure(BufferedHold::KeeperStalled, &g);
    assert!(m.starts_with("the statistics keeper stopped: "), "{m}");
    // One more read is enough, however late within the bound.
    let mut g = stopped(buffered_facts_for(Some(14_600)));
    g.keeper_settled.reads += 1;
    g.keeper_resumed_ms = Some(KEEPER_RESUME.as_millis() as u64);
    assert_eq!(buffered_verdict(&g), BufferedHold::Held);
    // A failure seen while waiting for that read is a failure.
    let mut g = stopped(buffered_facts_for(Some(14_600)));
    g.keeper_settled.failed = Some(libc::EIO);
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperFailed);

    // A failure wins over a stall.
    let mut g = buffered_facts_for(None);
    g.oom_kill = 1;
    g.keeper_after = g.keeper_before;
    g.keeper_after.failed = Some(libc::ENODEV);
    assert_eq!(buffered_verdict(&g), BufferedHold::KeeperFailed);
    assert!(
        buffered_failure(BufferedHold::KeeperFailed, &g).contains("failed (errno 19)"),
        "{}",
        buffered_failure(BufferedHold::KeeperFailed, &g)
    );
}

#[test]
fn buffered_failure_messages() {
    let f = buffered_facts_for;
    let mut failed_keeper = f(Some(14_600));
    failed_keeper.keeper_before.failed = Some(libc::ENODEV);
    // A writer OOM-killed mid-loop: loop_start and its last progress key
    // stay, from a partial output parsed like a real one.
    let partial = support::parse_probe(support::Output {
        status: ExitStatus::Signaled(9),
        stdout: "BONELI_PROBE loop_start=1\nBONELI_PROBE progress=16:3:389\n\
                 BONELI_PROBE progress=48:12:470\n"
            .to_string(),
        stderr: String::new(),
    });
    let before = f(None).keeper_before;
    let mut oom = buffered_facts(
        &BufferedRun {
            probe: partial,
            keeper_before: before,
            keeper_at_loop_end: None,
            keeper_after: f(None).keeper_after,
            run_ms: 470,
            keeper_settled: f(None).keeper_settled,
            keeper_resumed_ms: f(None).keeper_resumed_ms,
        },
        f(None).setup,
        1,
        80,
        "259:0 rbytes=0 wbytes=1572864 rios=0 wios=12 dbytes=0 dios=0",
    );
    oom.kernel = "7.0.0-1019-azure".to_string();
    assert!(oom.loop_start);
    assert_eq!(oom.last_progress.as_deref(), Some("48:12:470"));
    assert_eq!((oom.loop_ms, oom.wbytes), (None, 1_572_864));
    let mut writer = f(Some(14_600));
    writer.status = ExitStatus::Exited(101);
    let mut not_buffered = f(Some(14_600));
    not_buffered.loop_file_dirty = 0;
    not_buffered.loop_file_writeback = 0;
    let mut off = f(Some(14_600));
    off.wbytes = 4096;
    let mut stalled = oom.clone();
    stalled.keeper_after = stalled.keeper_before;
    let mut idle = f(Some(14_600));
    idle.keeper_at_loop_end = Some(idle.keeper_before);
    let idle_prefix = format!(
        "the statistics keeper read 0 times during the loop, under the {} \
         (one per 10 keeper periods)",
        14_600 / (10 * STATS_KEEPER_PERIOD.as_millis())
    );
    let cases = [
        (
            BufferedHold::KeeperFailed,
            &failed_keeper,
            "the sandbox's memory statistics keeper failed",
        ),
        (
            BufferedHold::KeeperStalled,
            &stalled,
            "the buffered writer was OOM-killed (memory.events oom_kill 1) while the statistics keeper stalled: 0 reads in the run's 470 ms",
        ),
        (
            BufferedHold::OomKilled,
            &oom,
            "the buffered writer was OOM-killed (memory.events oom_kill 1) although the statistics keeper read",
        ),
        (
            BufferedHold::WriterFailed,
            &writer,
            "the buffered writer failed",
        ),
        (
            BufferedHold::NotBuffered,
            &not_buffered,
            "the write loop left no dirty data",
        ),
        (
            BufferedHold::Escaped,
            &f(Some(3004)),
            "io.max did not hold the buffered write: the loop took 3004 ms (bound 7500) and the whole write 4504 ms (bound 15500) at wbps 33554432 with memory.max 268435456",
        ),
        (
            BufferedHold::OffDevice,
            &off,
            "the buffered bytes did not reach the limited device: wbytes 4096 on 259:0 after fdatasync, under the 536870912 bytes written",
        ),
        (BufferedHold::KeeperIdle, &idle, idle_prefix.as_str()),
    ];
    for (v, facts, prefix) in cases {
        let m = buffered_failure(v, facts);
        assert!(m.starts_with(prefix), "{v:?}: {m}");
        for part in [
            "kernel 7.0.0-1019-azure".to_string(),
            "device 259:0".to_string(),
            format!("status {:?}", facts.status),
            format!("oom_kill {}", facts.oom_kill),
            format!("loop_start {}", facts.loop_start),
            format!("loop_ms {}", opt_ms(facts.loop_ms)),
            format!("elapsed_ms {}", opt_ms(facts.elapsed_ms)),
            format!(
                "last progress {}",
                facts.last_progress.as_deref().unwrap_or("none")
            ),
            format!("loop file_dirty {}", facts.loop_file_dirty),
            format!("loop file_writeback {}", facts.loop_file_writeback),
            format!("wbytes {} after fdatasync", facts.wbytes),
            "size 536870912".to_string(),
            "memory.max 268435456".to_string(),
            "wbps 33554432".to_string(),
            format!("keeper before [{}]", keeper_text(Some(facts.keeper_before))),
            format!(
                "at the loop's end [{}]",
                keeper_text(facts.keeper_at_loop_end)
            ),
            format!("after the run [{}]", keeper_text(Some(facts.keeper_after))),
            format!("over run_ms {}", facts.run_ms),
            format!(
                "next read after the run {}",
                resumed_text(facts.keeper_resumed_ms)
            ),
            format!("settled [{}]", keeper_text(Some(facts.keeper_settled))),
        ] {
            assert!(m.contains(&part), "{v:?}: {part:?} missing in {m}");
        }
        // Every io.stat line.
        for line in facts.io_stat.lines() {
            assert!(m.contains(line), "{v:?}: {line:?} missing in {m}");
        }
    }
    let m = buffered_failure(BufferedHold::OomKilled, &oom);
    assert!(m.contains("loop_ms none"), "{m}");
    assert!(m.contains("last progress 48:12:470"), "{m}");
    assert!(m.contains("at the loop's end [none]"), "{m}");
    assert!(m.contains("reads 100 late 0"), "{m}");
    // A killed run still shows what the keeper did during it.
    let reads = 470 / STATS_KEEPER_PERIOD.as_millis();
    assert_eq!(buffered_verdict(&oom), BufferedHold::OomKilled);
    assert!(
        m.contains(&format!("read {reads} times in the run's 470 ms")),
        "{m}"
    );
    assert!(
        m.contains(&format!("after the run [reads {}", 100 + reads)),
        "{m}"
    );
    assert_eq!(buffered_verdict(&stalled), BufferedHold::KeeperStalled);
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
    // and the report line names the fallback. wbytes on the io.max
    // device must be above 0 (review of PR 53: a limit on a device the
    // bios do not pass plus a slow device would read as held), with no
    // upper bound: where io.stat counts depends on the write path. The
    // first count comes when the first bio is dispatched, about 1 s after
    // the writer enters its write, so the check reads again every 100 ms
    // until the device counts or IO_HOLD_DEADLINE_MS (review round 2 of
    // PR 53: a writer that entered at ~1.2 s read wbytes 0 at 2 s). It
    // also reads again while no task is seen in the write and nothing of
    // it has returned (wchar under IO_ENTRY_WCHAR; #54: under a load
    // average of about 19 the writer was still in futex at 2,014 ms), and
    // fails only when the writer left the write early or the deadline
    // passes.
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
    // Declared before the cgroup, so a panic before the destroy drops the
    // cgroup first: its drop kills and lifts io.max, then Child::drop
    // reaps at once instead of waiting ~38 s for the throttled bios
    // (review of PR 53; a panic injected after the check ended the test
    // after 2.06 s, and after 40.29 s with the old order, on the dev host).
    let mut writer = None;
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
    let child = writer.insert(spawn(&s).expect("spawn the writer"));
    drop(s);
    let pid = child.pid();
    // Let the writer fill its buffer and block in the throttled write,
    // then wait for the io.max device to count its first bio. Each read
    // takes the device's count first and the writer's own files after it.
    std::thread::sleep(Duration::from_secs(2));
    let (verdict, facts) = poll_io_hold(
        || {
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let wbytes = io_stat_wbytes(&read(&cg, "io.stat"), dev.major, dev.minor);
            let populated_now = populated(&cg);
            let check = hold_check(pid);
            let states = task_states(pid);
            let memory = read(&cg, "memory.stat");
            let buffer = buffer_mapping(pid, &check);
            IoFacts {
                dev: (dev.major, dev.minor),
                elapsed_ms,
                populated: populated_now,
                check,
                states,
                wbytes,
                file_dirty: keyed(&memory, "file_dirty"),
                file_writeback: keyed(&memory, "file_writeback"),
                reads: 0,
                waited: Vec::new(),
                buffer,
            }
        },
        || std::thread::sleep(IO_HOLD_POLL),
    );
    report(&format!(
        "destroy_lifts_io_throttle: {}",
        io_hold_text(verdict, &facts)
    ));
    let path = cg.path().to_path_buf();
    if verdict != IoHold::Held {
        let _ = cg.destroy();
        let status = wait_bounded(child, Duration::from_secs(120));
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
    let status = wait_bounded(child, Duration::from_secs(120));
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
    reads: u32,
    /// The reads before this one, which did not end the wait, as runs of
    /// consecutive reads with the same verdict, in order: the verdict, the
    /// run's reads and the time of its first read since the spawn (ms).
    waited: Vec<(IoHold, u32, u64)>,
    buffer: String,
}

/// How long after the spawn `destroy_lifts_io_throttle` waits for the
/// `io.max` device to count a write of the held writer. The first count
/// comes when blk-throttle dispatches the first bio, about its size ÷
/// `wbps` after the writer enters its write: 1 MiB bios (the probe's
/// buffer is `MADV_NOHUGEPAGE`) and an entry up to 872 ms after the spawn
/// measured put it near 1.9 s, so one read at 2 s could miss it (review
/// round 2 of PR 53). At 10 s at most 10 MiB plus one 100 ms slice has
/// drained, so at least 29.9 MiB are still queued, more than `KILL_BOUND`
/// (10 s) drains at 1 MiB/s, and the test still proves the lift (ADR-007,
/// "The timing tests"). The same deadline bounds the wait for a late
/// entry into the write (#54): it covers an entry up to 8,900 ms after
/// the spawn, one 1 MiB bio at the rate and one slice before it.
const IO_HOLD_DEADLINE_MS: u64 = 10_000;
/// The pause between two reads while the poll waits: one 100 ms throttle
/// slice, the step in which blk-throttle dispatches.
const IO_HOLD_POLL: Duration = Duration::from_millis(100);
/// `wchar` under this means nothing of the 40 MiB write has returned: an
/// `O_DIRECT` write returns only multiples of the logical block size, at
/// least 512 bytes on every Linux block device, and the probe writes 38
/// bytes before its write (measured on every CI class and the dev host).
const IO_ENTRY_WCHAR: u64 = 512;
/// The latest entry into the write whose first count the deadline still
/// covers: one 1 MiB bio at `IO_KILL_WBPS` (1,000 ms) and one 100 ms
/// slice before [`IO_HOLD_DEADLINE_MS`], 8,900 ms after the spawn. A
/// writer first seen in its write later and not counted by the deadline
/// started too late; it says nothing about the device.
const IO_LATEST_ENTRY_MS: u64 = IO_HOLD_DEADLINE_MS - (1 << 20) * 1000 / IO_KILL_WBPS - 100;

/// Reads the facts until a read is anything but `NotOnDevice` or
/// `NotEntered`, or until a read taken at or past [`IO_HOLD_DEADLINE_MS`]
/// after the spawn; returns the last verdict and its facts, `reads` and
/// `waited` set. Only the device's count and the writer's entry into its
/// write are waited for (#54: under load the writer was still outside it
/// at the first read at 2 s): a read that finds the writer gone, its write
/// returned or left early ends the poll with that verdict, so `Held`
/// always means the writer was inside its write when the count was seen.
fn poll_io_hold(mut read: impl FnMut() -> IoFacts, mut pause: impl FnMut()) -> (IoHold, IoFacts) {
    let mut reads = 0;
    let mut waited: Vec<(IoHold, u32, u64)> = Vec::new();
    loop {
        let mut f = read();
        reads += 1;
        f.reads = reads;
        let v = io_hold_verdict(&f);
        if !io_hold_waits(v) || f.elapsed_ms >= IO_HOLD_DEADLINE_MS {
            f.waited = waited;
            return (v, f);
        }
        match waited.last_mut() {
            Some((w, n, _)) if *w == v => *n += 1,
            _ => waited.push((v, 1, f.elapsed_ms)),
        }
        pause();
    }
}

/// Whether a read with this verdict before the deadline makes the poll
/// read again.
fn io_hold_waits(v: IoHold) -> bool {
    matches!(v, IoHold::NotOnDevice | IoHold::NotEntered)
}

/// The mapping that holds `addr` in a `/proc/<pid>/smaps` text, for the
/// report: its size, whether its `VmFlags` carry `nh` (`MADV_NOHUGEPAGE`)
/// and its `AnonHugePages`.
fn smaps_buffer(text: &str, addr: u64) -> String {
    // A mapping starts with its address range, `<hex>-<hex>`, end exclusive.
    let range = |l: &str| -> Option<(u64, u64)> {
        let (a, b) = l.split_ascii_whitespace().next()?.split_once('-')?;
        Some((hex_field(&format!("0x{a}"))?, hex_field(&format!("0x{b}"))?))
    };
    let kb = |l: &str, key: &str| -> Option<u64> {
        l.strip_prefix(key)?
            .trim()
            .strip_suffix(" kB")?
            .parse()
            .ok()
    };
    let mut lines = text.lines();
    if !lines
        .by_ref()
        .any(|l| range(l).is_some_and(|(a, b)| a <= addr && addr < b))
    {
        return format!("no mapping at {addr:#x}");
    }
    let block: Vec<&str> = lines.take_while(|l| range(l).is_none()).collect();
    let size = block.iter().find_map(|l| kb(l, "Size:")).unwrap_or(0);
    let huge = block
        .iter()
        .find_map(|l| kb(l, "AnonHugePages:"))
        .unwrap_or(0);
    let nh = block.iter().any(|l| {
        l.strip_prefix("VmFlags:")
            .is_some_and(|f| f.split_ascii_whitespace().any(|x| x == "nh"))
    });
    let nh = if nh { "nh" } else { "no nh" };
    format!("{size} kB {nh} AnonHugePages {huge} kB")
}

/// The buffer address of the 40 MiB write, if a task of the hold check
/// is inside it.
fn write_buffer(check: &HoldCheck) -> Option<u64> {
    let HoldCheck::Syscall { tasks, .. } = check else {
        return None;
    };
    tasks.iter().find_map(|t| match t.call {
        TaskSyscall::In { nr, args } if nr == libc::SYS_write && args[2] == IO_KILL_SIZE => {
            Some(args[1])
        }
        _ => None,
    })
}

/// [`smaps_buffer`] of `pid` at the write's buffer, or why not.
fn buffer_mapping(pid: i32, check: &HoldCheck) -> String {
    let Some(addr) = write_buffer(check) else {
        return "unknown (not in the write)".to_string();
    };
    match std::fs::read_to_string(format!("/proc/{pid}/smaps")) {
        Ok(text) => smaps_buffer(&text, addr),
        Err(e) => format!("smaps unread: {e}"),
    }
}

/// Whether io.max held the writer at the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IoHold {
    /// Alive and inside its 40 MiB write (or in `D` in the fallback), with
    /// a write counted on the `io.max` device.
    Held,
    /// The cgroup was empty: the writer had ended.
    Finished,
    /// Alive, but `wchar` counts the whole write: it returned.
    Returned,
    /// Alive, no task seen inside the 40 MiB write, and `wchar` under
    /// [`IO_ENTRY_WCHAR`]: nothing of the write has returned. Most likely
    /// the writer has not entered it yet (#54: futex at 2,014 ms under
    /// load), but the facts also fit a runnable task inside the write
    /// (`syscall` reads `running` for any runnable task) and a write that
    /// failed (an error adds nothing to `wchar`), so the messages state
    /// only what was read. Final only at [`IO_HOLD_DEADLINE_MS`]; before it
    /// the poll reads again.
    NotEntered,
    /// Alive, no task inside the 40 MiB write, and `wchar` from
    /// [`IO_ENTRY_WCHAR`] up to the write's size: the writer was inside
    /// and left early (a partial return).
    NotInWrite,
    /// Fallback only: no task in `D`.
    NotBlocked,
    /// Held otherwise, but the `io.max` device's `io.stat` line counted no
    /// write: the limit may sit on a device the bios do not pass, so a slow
    /// device and not `io.max` could be what holds the writer. Final only
    /// at [`IO_HOLD_DEADLINE_MS`]; before it the poll reads again.
    NotOnDevice,
}

/// `Held` also needs `wbytes` above 0 on the `io.max` device's line, a
/// lower bound only: where `io.stat` counts depends on the write path, and
/// some lines count above the rate (ADR-007, "The timing tests"), so no
/// upper bound.
fn io_hold_verdict(f: &IoFacts) -> IoHold {
    if f.populated == 0 {
        return IoHold::Finished;
    }
    let held = match &f.check {
        HoldCheck::Syscall { tasks, wchar } => {
            if *wchar >= IO_KILL_SIZE {
                IoHold::Returned
            } else if tasks.iter().any(|t| {
                matches!(t.call, TaskSyscall::In { nr, args }
                    if nr == libc::SYS_write && args[2] == IO_KILL_SIZE)
            }) {
                IoHold::Held
            } else if *wchar < IO_ENTRY_WCHAR {
                IoHold::NotEntered
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
    };
    if held == IoHold::Held && f.wbytes == 0 {
        IoHold::NotOnDevice
    } else {
        held
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
    let waited = f
        .waited
        .iter()
        .map(|(w, n, ms)| format!("{w:?} x{n} from {ms} ms"))
        .collect::<Vec<_>>()
        .join(", ");
    let ended = if io_hold_waits(v) && f.elapsed_ms >= IO_HOLD_DEADLINE_MS {
        "the deadline".to_string()
    } else {
        format!("{v:?}")
    };
    format!(
        "at {} ms (read {}) hold-check={} verdict {v:?}, waited [{waited}], ended by {ended}, \
         tasks [{tasks}], wchar {wchar}, states {:?}, device {}:{} wbytes {} file_dirty {} \
         file_writeback {}, buffer {}",
        f.elapsed_ms,
        f.reads,
        hold_check_label(&f.check),
        f.states,
        f.dev.0,
        f.dev.1,
        f.wbytes,
        f.file_dirty,
        f.file_writeback,
        f.buffer
    )
}

fn io_hold_failure(v: IoHold, status: ExitStatus, f: &IoFacts) -> String {
    // No count with the writer in its write points at the device only when
    // its last stretch in the write began early enough for the first bio
    // to be counted by the deadline (review of PR 76).
    let in_write_since = match f.waited.last() {
        Some(&(IoHold::NotOnDevice, _, from)) => from,
        _ => f.elapsed_ms,
    };
    let off_device = if in_write_since > IO_LATEST_ENTRY_MS {
        format!(
            "the writer was seen in its 40 MiB write only from {in_write_since} ms, after the \
             latest entry the {IO_HOLD_DEADLINE_MS} ms deadline covers ({IO_LATEST_ENTRY_MS} \
             ms): it started too late for the io.max device to count a write, which says \
             nothing about the device"
        )
    } else {
        format!(
            "the io.max device counted no write within {IO_HOLD_DEADLINE_MS} ms of the spawn: \
             the writer's bios may not pass the limited device"
        )
    };
    let not_entered = format!(
        "no task of the writer was seen in its 40 MiB write and nothing of the write \
         returned (wchar under {IO_ENTRY_WCHAR}) within {IO_HOLD_DEADLINE_MS} ms of the spawn"
    );
    let why = match v {
        IoHold::Finished if status == ExitStatus::Exited(0) => {
            "io.max did not hold the writer: it finished its 40 MiB write before the check"
        }
        IoHold::Finished => "the writer failed before the kill",
        IoHold::Returned => {
            "io.max did not hold the writer: its 40 MiB write returned before the check"
        }
        IoHold::NotEntered => not_entered.as_str(),
        IoHold::NotInWrite => "the writer was not inside its 40 MiB write",
        IoHold::NotBlocked => "the writer was not blocked in its write",
        IoHold::NotOnDevice => off_device.as_str(),
        IoHold::Held => "the writer was held",
    };
    format!("{why}: {}, status {status:?}", io_hold_text(v, f))
}

/// `wbytes` of the device's line in an `io.stat` text; no line yet means
/// nothing was submitted (0). The kernel prints the six byte and IO
/// counters together and only when one of them is non-zero (CI: a line
/// `259:0 ` after a killed writer), so a line without any of them is 0
/// too. A line with some counters but no parseable `wbytes=` panics with
/// the line quoted.
fn io_stat_wbytes(stat: &str, major: u32, minor: u32) -> u64 {
    const COUNTERS: [&str; 6] = ["rbytes=", "wbytes=", "rios=", "wios=", "dbytes=", "dios="];
    let key = format!("{major}:{minor} ");
    let Some(line) = stat.lines().find(|l| l.starts_with(&key)) else {
        return 0;
    };
    let fields: Vec<&str> = line.split_whitespace().skip(1).collect();
    if !fields
        .iter()
        .any(|f| COUNTERS.iter().any(|c| f.starts_with(c)))
    {
        return 0;
    }
    fields
        .iter()
        .find_map(|f| f.strip_prefix("wbytes="))
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
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
        reads: 1,
        waited: Vec::new(),
        buffer: "40960 kB nh AnonHugePages 0 kB".to_string(),
    }
}

fn syscall_check(tasks: Vec<TaskLine>, wchar: u64) -> HoldCheck {
    HoldCheck::Syscall { tasks, wchar }
}

/// `wchar` after a partial return: the probe's 38 bytes plus 1 MiB of the
/// write.
const PARTIAL_WCHAR: u64 = 38 + 1_048_576;

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
        // wbytes has a lower bound only: some io.stat lines count above
        // the rate (ADR-007), so a large count is still Held.
        for wbytes in [1, IO_KILL_SIZE] {
            f.wbytes = wbytes;
            assert_eq!(io_hold_verdict(&f), IoHold::Held, "wchar {wchar}, {wbytes}");
        }
        // Nothing counted on the io.max device: the limit may sit on a
        // device the bios do not pass (review of PR 53).
        f.wbytes = 0;
        assert_eq!(io_hold_verdict(&f), IoHold::NotOnDevice, "wchar {wchar}");
    }
    // The device check comes last: every other verdict wins over it.
    let zero = |populated, check, states: &[char]| {
        let mut f = io_facts(populated, check, states);
        f.wbytes = 0;
        io_hold_verdict(&f)
    };
    assert_eq!(
        zero(0, syscall_check(vec![w()], 38), &['D']),
        IoHold::Finished
    );
    assert_eq!(
        zero(1, syscall_check(vec![w()], IO_KILL_SIZE), &['D']),
        IoHold::Returned
    );
    assert_eq!(
        zero(1, syscall_check(vec![futex_task()], 38), &['S', 'D']),
        IoHold::NotEntered
    );
    assert_eq!(
        zero(
            1,
            syscall_check(vec![futex_task()], PARTIAL_WCHAR),
            &['S', 'D']
        ),
        IoHold::NotInWrite
    );
    let eperm = || HoldCheck::DState {
        refused: "io: EPERM".to_string(),
    };
    assert_eq!(zero(1, eperm(), &['S']), IoHold::NotBlocked);
    // The fallback's D needs a counted write too.
    assert_eq!(zero(1, eperm(), &['S', 'D']), IoHold::NotOnDevice);
    assert_eq!(zero(0, eperm(), &['D']), IoHold::Finished);
    // The measured layout: the futex main thread plus the writer, in
    // either order; the futex task alone is not in the write.
    for tasks in [vec![futex_task(), w()], vec![w(), futex_task()]] {
        assert_eq!(
            io_hold_verdict(&io_facts(1, syscall_check(tasks, 38), &['S', 'D'])),
            IoHold::Held
        );
    }
    // #54: the futex task alone with the 38 bytes the probe writes before
    // its write has not entered it yet (the QA failure at 2,014 ms).
    assert_eq!(
        io_hold_verdict(&io_facts(1, syscall_check(vec![futex_task()], 38), &['S'])),
        IoHold::NotEntered
    );
    // wchar decides between not yet entered and left early, both bounds
    // inclusive: under IO_ENTRY_WCHAR nothing of the write has returned,
    // from it up to the write's size a part has; the whole size returned.
    for (wchar, want) in [
        (0, IoHold::NotEntered),
        (IO_ENTRY_WCHAR - 1, IoHold::NotEntered),
        (IO_ENTRY_WCHAR, IoHold::NotInWrite),
        (PARTIAL_WCHAR, IoHold::NotInWrite),
        (IO_KILL_SIZE - 1, IoHold::NotInWrite),
        (IO_KILL_SIZE, IoHold::Returned),
    ] {
        let f = io_facts(1, syscall_check(vec![futex_task()], wchar), &['S', 'R']);
        assert_eq!(io_hold_verdict(&f), want, "wchar {wchar}");
    }
    assert_eq!((IO_ENTRY_WCHAR, PARTIAL_WCHAR), (512, 1_048_614));
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
        // check ran. With nothing returned yet (a task in another write
        // included) the writer has not entered: the poll waits and fails
        // at the deadline, it never passes; after a partial return it left.
        assert_eq!(
            io_hold_verdict(&io_facts(1, syscall_check(tasks.clone(), 38), &['S', 'D'])),
            IoHold::NotEntered,
            "{raws:?}"
        );
        assert_eq!(
            io_hold_verdict(&io_facts(
                1,
                syscall_check(tasks, PARTIAL_WCHAR),
                &['S', 'D']
            )),
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
    let not_in = io_facts(1, syscall_check(vec![futex_task()], PARTIAL_WCHAR), &['S']);
    // Both waiting verdicts end a failed run only at the deadline.
    let mut not_entered = io_facts(1, syscall_check(vec![futex_task()], 38), &['S', 'R']);
    not_entered.elapsed_ms = IO_HOLD_DEADLINE_MS + 3;
    not_entered.reads = 81;
    not_entered.waited = vec![(IoHold::NotEntered, 80, 2004)];
    let refused = io_facts(
        1,
        HoldCheck::DState {
            refused: "io: EPERM".to_string(),
        },
        &['S', 'R'],
    );
    let mut off_device = io_facts(
        1,
        syscall_check(vec![futex_task(), w.clone()], 38),
        &['S', 'D'],
    );
    off_device.wbytes = 0;
    off_device.elapsed_ms = IO_HOLD_DEADLINE_MS + 35;
    off_device.reads = 81;
    off_device.waited = vec![
        (IoHold::NotEntered, 3, 2004),
        (IoHold::NotOnDevice, 77, 2304),
    ];
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
            IoHold::NotEntered,
            ExitStatus::Signaled(9),
            &not_entered,
            "no task of the writer was seen in its 40 MiB write and nothing of the write \
             returned (wchar under 512) within 10000 ms of the spawn",
        ),
        (
            IoHold::NotBlocked,
            ExitStatus::Signaled(9),
            &refused,
            "the writer was not blocked in its write",
        ),
        (
            IoHold::NotOnDevice,
            ExitStatus::Signaled(9),
            &off_device,
            "the io.max device counted no write within 10000 ms of the spawn",
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
            &format!("at {} ms (read {})", facts.elapsed_ms, facts.reads),
            &format!("wbytes {}", facts.wbytes),
            "buffer 40960 kB nh AnonHugePages 0 kB",
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
    // The report line names what the wait read and which case ended it:
    // a waiting verdict at or past the deadline ends it by the deadline.
    for (v, facts, want) in [
        (
            IoHold::NotEntered,
            &not_entered,
            "verdict NotEntered, waited [NotEntered x80 from 2004 ms], ended by the deadline,",
        ),
        (
            IoHold::NotOnDevice,
            &off_device,
            "verdict NotOnDevice, waited [NotEntered x3 from 2004 ms, \
             NotOnDevice x77 from 2304 ms], ended by the deadline,",
        ),
        (IoHold::Held, &f, "verdict Held, waited [], ended by Held,"),
    ] {
        let text = io_hold_text(v, facts);
        assert!(text.contains(want), "{want:?} missing in {text}");
    }
    // Any other read ends it by its own verdict (the QA case of #54 and
    // the mixed wait, Held at the third read).
    let mut late = io_facts(
        1,
        syscall_check(vec![futex_task(), w.clone()], 38),
        &['S', 'D'],
    );
    late.elapsed_ms = 2216;
    late.reads = 3;
    for (waited, want) in [
        (
            vec![(IoHold::NotEntered, 2, 2014)],
            "at 2216 ms (read 3) hold-check=syscall verdict Held, \
             waited [NotEntered x2 from 2014 ms], ended by Held, tasks [",
        ),
        (
            vec![
                (IoHold::NotEntered, 1, 2014),
                (IoHold::NotOnDevice, 1, 2115),
            ],
            "verdict Held, waited [NotEntered x1 from 2014 ms, NotOnDevice x1 from 2115 ms], \
             ended by Held,",
        ),
    ] {
        late.waited = waited;
        let text = io_hold_text(IoHold::Held, &late);
        assert!(text.contains(want), "{want:?} missing in {text}");
    }
    let mut left = io_facts(1, syscall_check(vec![futex_task()], PARTIAL_WCHAR), &['S']);
    left.waited = vec![(IoHold::NotEntered, 4, 2004)];
    let m = io_hold_failure(IoHold::NotInWrite, ExitStatus::Signaled(9), &left);
    assert!(
        m.contains("verdict NotInWrite, waited [NotEntered x4 from 2004 ms], ended by NotInWrite,"),
        "{m}"
    );
}

/// The facts of one poll read: `verdict` picks the shape, `ms` the time
/// since the spawn.
fn poll_read(verdict: IoHold, ms: u64) -> IoFacts {
    let w = || write_task(IO_KILL_SIZE, 2);
    let mut f = match verdict {
        IoHold::Held | IoHold::NotOnDevice => {
            io_facts(1, syscall_check(vec![futex_task(), w()], 38), &['S', 'D'])
        }
        IoHold::Finished => io_facts(0, syscall_check(vec![w()], 41_943_130), &['Z']),
        IoHold::Returned => io_facts(1, syscall_check(vec![w()], 41_943_130), &['S']),
        // The measured QA failure: futex plus running, wchar 38.
        IoHold::NotEntered => io_facts(1, syscall_check(vec![futex_task()], 38), &['S', 'R']),
        IoHold::NotInWrite => io_facts(1, syscall_check(vec![futex_task()], PARTIAL_WCHAR), &['S']),
        IoHold::NotBlocked => io_facts(
            1,
            HoldCheck::DState {
                refused: "io: EPERM".to_string(),
            },
            &['S'],
        ),
    };
    if verdict == IoHold::NotOnDevice {
        f.wbytes = 0;
    }
    f.elapsed_ms = ms;
    assert_eq!(io_hold_verdict(&f), verdict, "fixture for {verdict:?}");
    f
}

/// Runs the poll over `reads` and returns its verdict, the time of the
/// read it ended on, the reads it took and the pauses between them.
fn run_poll(reads: Vec<IoFacts>) -> (IoHold, u64, u32, usize) {
    let (v, f, pauses) = poll_facts(reads);
    (v, f.elapsed_ms, f.reads, pauses)
}

/// [`run_poll`] with the facts of the last read and the pauses.
fn poll_facts(reads: Vec<IoFacts>) -> (IoHold, IoFacts, usize) {
    let mut queue = reads.into_iter();
    let mut pauses = 0;
    let (v, f) = poll_io_hold(
        || queue.next().expect("the poll read past the fixture"),
        || pauses += 1,
    );
    (v, f, pauses)
}

/// Reads of `verdict` every 100 ms from 2,004 ms after the spawn up to the
/// deadline: one at `IO_HOLD_DEADLINE_MS - 1` and the last at the deadline.
fn reads_to_deadline(verdict: IoHold) -> Vec<IoFacts> {
    let mut reads: Vec<IoFacts> = (0..80)
        .map(|i| poll_read(verdict, 2004 + i * 100))
        .filter(|f| f.elapsed_ms < IO_HOLD_DEADLINE_MS)
        .collect();
    reads.push(poll_read(verdict, IO_HOLD_DEADLINE_MS - 1));
    reads.push(poll_read(verdict, IO_HOLD_DEADLINE_MS));
    reads
}

#[test]
fn io_hold_polls() {
    use IoHold::*;
    // Held at the first read: no pause, no second read.
    assert_eq!(run_poll(vec![poll_read(Held, 2004)]), (Held, 2004, 1, 0));
    // Review round 2 of PR 53: a writer that entered its write at ~1.2 s
    // read wbytes 0 at 2,007 ms and was first counted at 2,528 ms. The
    // poll waits for the count and the writer still inside its write.
    assert_eq!(
        run_poll(vec![
            poll_read(NotOnDevice, 2007),
            poll_read(NotOnDevice, 2108),
            poll_read(NotOnDevice, 2209),
            poll_read(NotOnDevice, 2310),
            poll_read(NotOnDevice, 2411),
            poll_read(Held, 2528),
        ]),
        (Held, 2528, 6, 5)
    );
    // The count came, but the writer had left its write by then: the
    // other verdicts end the poll as they would end the single read.
    for late in [Finished, Returned, NotInWrite, NotBlocked] {
        assert_eq!(
            run_poll(vec![poll_read(NotOnDevice, 2004), poll_read(late, 2105)]),
            (late, 2105, 2, 1),
            "{late:?}"
        );
        assert_eq!(run_poll(vec![poll_read(late, 2004)]), (late, 2004, 1, 0));
    }
    // No count by the deadline: NotOnDevice, and no read after the one at
    // the deadline (inclusive); one millisecond before it still waits.
    let reads = reads_to_deadline(NotOnDevice);
    let n = reads.len() as u32;
    let (v, f, pauses) = poll_facts(reads);
    assert_eq!(
        (v, f.elapsed_ms, f.reads, pauses),
        (NotOnDevice, IO_HOLD_DEADLINE_MS, n, n as usize - 1)
    );
    assert_eq!(f.waited, vec![(NotOnDevice, n - 1, 2004)]);
    // #54, QA of PR 58: under load the writer had not entered its write at
    // the first read (futex, wchar 38, 2,014 ms). The poll waits for the
    // entry as it waits for the count.
    let (v, f, pauses) = poll_facts(vec![
        poll_read(NotEntered, 2014),
        poll_read(NotEntered, 2115),
        poll_read(Held, 2216),
    ]);
    assert_eq!((v, f.elapsed_ms, f.reads, pauses), (Held, 2216, 3, 2));
    assert_eq!(f.waited, vec![(NotEntered, 2, 2014)]);
    // Entered, then waited for the count: both waits in one poll, in the
    // order they came.
    let (v, f, pauses) = poll_facts(vec![
        poll_read(NotEntered, 2014),
        poll_read(NotOnDevice, 2115),
        poll_read(Held, 2216),
    ]);
    assert_eq!((v, f.elapsed_ms, f.reads, pauses), (Held, 2216, 3, 2));
    assert_eq!(
        f.waited,
        vec![(NotEntered, 1, 2014), (NotOnDevice, 1, 2115)]
    );
    // Runs of reads in order: a writer seen in its write and then not
    // (a runnable task reads `running`) shows each change.
    let (v, f, _) = poll_facts(vec![
        poll_read(NotOnDevice, 2014),
        poll_read(NotEntered, 2115),
        poll_read(NotOnDevice, 2216),
        poll_read(Held, 2317),
    ]);
    assert_eq!((v, f.reads), (Held, 4));
    assert_eq!(
        f.waited,
        vec![
            (NotOnDevice, 1, 2014),
            (NotEntered, 1, 2115),
            (NotOnDevice, 1, 2216)
        ]
    );
    // Any final verdict after a wait for the entry ends the poll with it:
    // a writer that failed before its write is Finished, one that entered
    // and left is NotInWrite.
    for late in [Finished, Returned, NotInWrite, NotBlocked] {
        let (v, f, pauses) = poll_facts(vec![
            poll_read(NotEntered, 2004),
            poll_read(NotEntered, 2105),
            poll_read(late, 2206),
        ]);
        assert_eq!((v, f.elapsed_ms, f.reads, pauses), (late, 2206, 3, 2));
        assert_eq!(f.waited, vec![(NotEntered, 2, 2004)], "{late:?}");
    }
    // Never entered by the deadline: NotEntered, final at the deadline
    // (inclusive), still waiting one millisecond before it.
    let reads = reads_to_deadline(NotEntered);
    let n = reads.len() as u32;
    let (v, f, pauses) = poll_facts(reads);
    assert_eq!(
        (v, f.elapsed_ms, f.reads, pauses),
        (NotEntered, IO_HOLD_DEADLINE_MS, n, n as usize - 1)
    );
    assert_eq!(f.waited, vec![(NotEntered, n - 1, 2004)]);
    // A task in another write (a 1 MiB count) with nothing returned reads
    // as not entered: it waits and fails at the deadline, it never passes.
    let other = |ms| {
        let mut f = io_facts(
            1,
            syscall_check(vec![futex_task(), write_task(1_048_576, 2)], 38),
            &['S', 'D'],
        );
        f.elapsed_ms = ms;
        f
    };
    let (v, f, _) = poll_facts(vec![
        other(2004),
        other(IO_HOLD_DEADLINE_MS - 1),
        other(IO_HOLD_DEADLINE_MS),
    ]);
    assert_eq!(
        (v, f.elapsed_ms, f.reads),
        (NotEntered, IO_HOLD_DEADLINE_MS, 3)
    );
    // A first read past the deadline that has not entered is final too.
    assert_eq!(
        run_poll(vec![poll_read(NotEntered, IO_HOLD_DEADLINE_MS + 50)]),
        (NotEntered, IO_HOLD_DEADLINE_MS + 50, 1, 0)
    );
    // The D-state fallback cannot tell not yet from left: NotBlocked at
    // the first read stays final.
    let (v, f, pauses) = poll_facts(vec![poll_read(NotBlocked, 2004)]);
    assert_eq!((v, f.reads, pauses), (NotBlocked, 1, 0));
    assert!(f.waited.is_empty());
    // A first read already past the deadline still decides by its facts.
    assert_eq!(
        run_poll(vec![poll_read(NotOnDevice, IO_HOLD_DEADLINE_MS + 50)]),
        (NotOnDevice, IO_HOLD_DEADLINE_MS + 50, 1, 0)
    );
    assert_eq!(
        run_poll(vec![poll_read(Held, IO_HOLD_DEADLINE_MS + 50)]),
        (Held, IO_HOLD_DEADLINE_MS + 50, 1, 0)
    );
}

/// Poll reads of a writer first seen in its write at `ms`: `NotEntered`
/// every 100 ms from 2,004 ms before it, then `NotOnDevice` (no count)
/// from `ms` every 100 ms and once at the deadline.
fn seen_in_write_at(ms: u64) -> Vec<IoFacts> {
    let mut reads: Vec<IoFacts> = (2004..ms)
        .step_by(100)
        .map(|t| poll_read(IoHold::NotEntered, t))
        .collect();
    reads.extend(
        (ms..IO_HOLD_DEADLINE_MS)
            .step_by(100)
            .map(|t| poll_read(IoHold::NotOnDevice, t)),
    );
    reads.push(poll_read(IoHold::NotOnDevice, IO_HOLD_DEADLINE_MS));
    reads
}

#[test]
fn io_hold_late_entry_headline() {
    // Review of PR 76: a writer seen in its write only after the latest
    // entry the deadline covers fails as NotOnDevice at the deadline. The
    // verdict stays (fail closed); the headline names the late start, not
    // a device the bios may not pass.
    let device = "the io.max device counted no write within 10000 ms of the spawn: \
                  the writer's bios may not pass the limited device";
    let late = |since: u64| {
        format!(
            "the writer was seen in its 40 MiB write only from {since} ms, after the latest \
             entry the 10000 ms deadline covers (8900 ms): it started too late for the io.max \
             device to count a write, which says nothing about the device"
        )
    };
    let fail = |reads: Vec<IoFacts>| {
        let (v, f, _) = poll_facts(reads);
        assert_eq!(
            (v, f.elapsed_ms),
            (IoHold::NotOnDevice, IO_HOLD_DEADLINE_MS)
        );
        (io_hold_failure(v, ExitStatus::Signaled(9), &f), f)
    };
    // The reviewer's case: not entered at every read, in the write without
    // a count only at the deadline read.
    let (m, f) = fail(seen_in_write_at(IO_HOLD_DEADLINE_MS));
    assert_eq!(f.waited, vec![(IoHold::NotEntered, 80, 2004)]);
    assert!(m.starts_with(&late(IO_HOLD_DEADLINE_MS)), "{m}");
    assert!(!m.contains("may not pass"), "{m}");
    assert!(
        m.contains("waited [NotEntered x80 from 2004 ms], ended by the deadline,"),
        "{m}"
    );
    // The bound is inclusive: an entry at 8,900 ms is covered, so no count
    // by the deadline still points at the device; one millisecond later
    // it does not.
    let (m, _) = fail(seen_in_write_at(IO_LATEST_ENTRY_MS));
    assert!(m.starts_with(device), "{m}");
    let (m, _) = fail(seen_in_write_at(IO_LATEST_ENTRY_MS + 1));
    assert!(m.starts_with(&late(8_901)), "{m}");
    // An early entry with no count is the device case.
    let (m, _) = fail(seen_in_write_at(2_304));
    assert!(m.starts_with(device), "{m}");
    // Only the last stretch in the write counts: seen in it early, then
    // not (a runnable task inside the write reads `running`), then in it
    // again from 9,500 ms.
    let mut reads = vec![
        poll_read(IoHold::NotOnDevice, 2004),
        poll_read(IoHold::NotEntered, 2105),
    ];
    reads.extend(seen_in_write_at(9_500).into_iter().skip(1));
    let (m, f) = fail(reads);
    assert_eq!(f.waited.first(), Some(&(IoHold::NotOnDevice, 1, 2004)));
    assert_eq!(
        f.waited.last().map(|w| (w.0, w.2)),
        Some((IoHold::NotOnDevice, 9_500))
    );
    assert!(m.starts_with(&late(9_500)), "{m}");
    // The fallback never reads NotEntered: D without a count all along is
    // the device case.
    let mut reads = reads_to_deadline(IoHold::NotOnDevice);
    for r in &mut reads {
        r.check = HoldCheck::DState {
            refused: "io: EPERM".to_string(),
        };
    }
    let (m, _) = fail(reads);
    assert!(m.starts_with(device), "{m}");
}

#[test]
fn io_hold_deadline_keeps_the_lift_proven() {
    // ADR-007, "The timing tests": by the deadline at most one slice more
    // than the rate allows has drained, and what is still queued must
    // take longer than KILL_BOUND (10 s) to drain at the rate, or a
    // destroy without the lift would pass too (mutant MA).
    let slice = IO_KILL_WBPS / 10;
    let drained = IO_KILL_WBPS * IO_HOLD_DEADLINE_MS / 1000 + slice;
    let queued = IO_KILL_SIZE - drained;
    assert_eq!(queued, 31_352_423);
    assert!(queued >= 10 * IO_KILL_WBPS, "{queued}");
    // And the deadline covers the measured case: the latest entry into the
    // write (872 ms after the spawn) plus a first 1 MiB bio at the rate.
    let first_count_ms = 872 + 1_048_576 * 1000 / IO_KILL_WBPS;
    assert_eq!(first_count_ms, 1_872);
    assert!(first_count_ms < IO_HOLD_DEADLINE_MS, "{first_count_ms} ms");
    // #54: the poll also waits for a late entry. The latest entry it
    // covers leaves one 1 MiB bio at the rate and one slice before the
    // deadline; the QA failure's writer was still outside at 2,014 ms.
    // A later entry only leaves more queued at the deadline, so the lift
    // proof above holds for every entry the wait covers.
    let latest_entry_ms = IO_HOLD_DEADLINE_MS - 1_048_576 * 1000 / IO_KILL_WBPS - 100;
    assert_eq!((latest_entry_ms, IO_LATEST_ENTRY_MS), (8_900, 8_900));
    assert!(2_014 < latest_entry_ms, "{latest_entry_ms} ms");
    assert_eq!(10 * IO_KILL_WBPS, 10_485_760);
    assert!(queued > 10 * IO_KILL_WBPS, "{queued}");
}

/// One `/proc/<pid>/smaps` mapping for the pure tests.
fn smaps_block(range: &str, size_kb: u64, anon_huge_kb: u64, flags: &str) -> String {
    format!(
        "{range} rw-p 00000000 00:00 0 \n\
         Size:           {size_kb:>8} kB\n\
         KernelPageSize:        4 kB\n\
         Rss:            {size_kb:>8} kB\n\
         AnonHugePages:  {anon_huge_kb:>8} kB\n\
         VmFlags: {flags}\n"
    )
}

#[test]
fn smaps_buffer_parses() {
    // Measured layout: a 64 MiB malloc arena (65404 kB) before the buffer,
    // so the buffer is found by the write's address, not by its size.
    let heap = smaps_block("55d0c000-55d2d000", 132, 0, "rd wr mr mw me ac");
    let arena = smaps_block("7f3a04000000-7f3a07fdf000", 65_404, 0, "rd wr mr mw me ac");
    let buffer = smaps_block(
        "7f3a0d800000-7f3a10000000",
        40_960,
        0,
        "rd wr mr mw me ac nh",
    );
    let thp = smaps_block(
        "7f3a0d800000-7f3a10000000",
        40_960,
        34_816,
        "rd wr mr mw me ac hg",
    );
    let text = format!("{heap}{arena}{buffer}");
    for addr in [0x7f3a_0d80_0000, 0x7f3a_0fff_ffff] {
        assert_eq!(
            smaps_buffer(&text, addr),
            "40960 kB nh AnonHugePages 0 kB",
            "{addr:#x}"
        );
    }
    assert_eq!(
        smaps_buffer(&format!("{heap}{thp}{arena}"), 0x7f3a_0e00_0000),
        "40960 kB no nh AnonHugePages 34816 kB"
    );
    assert_eq!(
        smaps_buffer(&text, 0x7f3a_0400_1000),
        "65404 kB no nh AnonHugePages 0 kB"
    );
    // The end is exclusive; an address in no mapping, or no text.
    assert_eq!(
        smaps_buffer(&text, 0x7f3a_1000_0000),
        "no mapping at 0x7f3a10000000"
    );
    assert_eq!(smaps_buffer("", 0x1000), "no mapping at 0x1000");
    // The write's address comes from the task inside the 40 MiB write.
    let w = write_task(IO_KILL_SIZE, 2);
    assert_eq!(
        write_buffer(&syscall_check(vec![futex_task(), w], 38)),
        Some(0x7f3a_0d7f_f000)
    );
    for check in [
        syscall_check(vec![futex_task()], 38),
        syscall_check(vec![futex_task(), write_task(1_048_576, 2)], 38),
        HoldCheck::DState {
            refused: "io: EPERM".to_string(),
        },
    ] {
        assert_eq!(write_buffer(&check), None, "{check:?}");
    }
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
    // A line without counters (all zero, measured on CI) reads 0, also
    // with another policy's keys on it.
    assert_eq!(io_stat_wbytes("259:0 \n", 259, 0), 0);
    assert_eq!(
        io_stat_wbytes("259:0", 259, 0),
        0,
        "no key without the space"
    );
    assert_eq!(io_stat_wbytes("259:0 cost.usage=5\n", 259, 0), 0);
    for bad in [
        "8:1 rbytes=0 wios=1",
        "8:1 wbytes=x rbytes=0",
        "8:1 wbytes= rios=0",
        "8:1 wbytes=+5",
    ] {
        let b = bad.to_string();
        let m = panic_message(move || {
            let _ = io_stat_wbytes(&b, 8, 1);
        });
        assert!(m.contains(&format!("{bad:?}")), "{bad:?}: {m}");
    }
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
    // Review of PR 3: a sub-cgroup would make destroy fail with EBUSY.
    // cgroup.max.descendants and cgroup.max.depth are 0, and they hold for
    // the cgroup's owner too: the test process, which owns it and sits
    // outside its namespace, gets EAGAIN from mkdir. Nothing in the
    // sandbox can mount a cgroup2 to try it from inside (no capabilities,
    // ADR-007 D9; cgroup_view_stays_read_only).
    let cg = cgroup::sandbox("no-sub");
    assert_eq!(read(&cg, "cgroup.max.descendants").trim(), "0");
    assert_eq!(read(&cg, "cgroup.max.depth").trim(), "0");
    let fixture = Fixture::new("no-sub");
    // A sleeper inside, so the cgroup is populated while the owner tries.
    let s = spec(fixture.root(), &cg, "/usr/bin/sleep", &["30"]);
    let mut child = spawn(&s).expect("spawn a sleeper");
    drop(s);
    let sub = cg.path().join("sub");
    let made = std::fs::create_dir(&sub);
    if made.is_ok() {
        let _ = std::fs::remove_dir(&sub);
    }
    assert_eq!(
        made.as_ref().map_err(|e| e.raw_os_error()),
        Err(Some(libc::EAGAIN)),
        "the owner created a sub-cgroup: {made:?}"
    );
    assert_eq!(read(&cg, "cgroup.max.descendants").trim(), "0");
    let path = cg.path().to_path_buf();
    cg.destroy().expect("destroy");
    assert_eq!(
        wait_bounded(&mut child, Duration::from_secs(10)),
        ExitStatus::Signaled(libc::SIGKILL)
    );
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
fn kill_survives_chmod() {
    // Review round 3 of PR 3: cgroup.kill made read-only after create must
    // not stop destroy. The sandbox cannot mount a cgroup2 to do it
    // (ADR-007 D9, cgroup_view_stays_read_only), so the test process,
    // which owns the file, sets mode 0444 itself while the workload
    // sleeps; the kill goes through the
    // descriptor create held open, so destroy still kills the workload and
    // removes the cgroup.
    let cg = cgroup::sandbox("chmod-kill");
    let fixture = Fixture::new("chmod-kill");
    let s = spec(fixture.root(), &cg, "/usr/bin/sleep", &["30"]);
    let mut child = spawn(&s).expect("spawn a sleeper");
    drop(s);
    let path = cg.path().to_path_buf();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        path.join("cgroup.kill"),
        std::fs::Permissions::from_mode(0o444),
    )
    .expect("chmod 0444 cgroup.kill as its owner");
    let mode = std::fs::metadata(path.join("cgroup.kill"))
        .expect("stat cgroup.kill")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o444, "cgroup.kill is read-only now");
    // A write by name fails now, so only the held descriptor can kill.
    let by_name = std::fs::write(path.join("cgroup.kill"), "1");
    assert_eq!(
        by_name.as_ref().map_err(|e| e.raw_os_error()),
        Err(Some(libc::EACCES)),
        "{by_name:?}"
    );
    let result = cg.destroy();
    let left = path.exists();
    if left {
        // Clean up before waiting, so a failure here leaves nothing running.
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

#[test]
#[ignore = "host: cgroup v2 delegation, user namespaces"]
fn cgroup_view_stays_read_only() {
    // The inside attempts that the PR 3 tests made with inside id 0's
    // capabilities (sandbox_cannot_create_sub_cgroups,
    // kill_survives_chmod): since the privilege drop (ADR-007, D9) every
    // way to get a writable cgroup2 is refused by the missing
    // CAP_SYS_ADMIN alone. Seccomp has no mount row and Landlock is not
    // applied here. The functions are Linux 7.2's:
    // - mount(2), both remounts and the new cgroup2: path_mount() returns
    //   EPERM when may_mount() fails (fs/namespace.c);
    // - mount_setattr: wants_mount_setattr() checks may_mount() before it
    //   reads the attribute (fs/namespace.c);
    // - fsopen: its syscall checks may_mount() first (fs/fsopen.c);
    // - fchmodat of cgroup.kill: chmod_common() takes mnt_want_write()
    //   before any owner check, so the read-only view gives EROFS
    //   (fs/open.c). That case is an `Own` call, not a capability one.
    // A different errno fails the case instead of widening it.
    use std::os::unix::fs::PermissionsExt;
    let mode = |cg: &Cgroup| {
        std::fs::metadata(cg.path().join("cgroup.kill"))
            .expect("stat cgroup.kill")
            .permissions()
            .mode()
            & 0o7777
    };
    for id in [0, 999] {
        let cg = cgroup::sandbox("view");
        let fixture = Fixture::new("view");
        let before = mode(&cg);
        let p = run_probe_in(
            "cgroup-view",
            ids(id, id),
            &[],
            root_with_cgroup(&fixture),
            &cg,
        );
        p.assert_ok();
        for key in [
            "remount_bind",
            "remount_sb",
            "mount_setattr",
            "mount_cgroup2",
            "fsopen",
        ] {
            assert_eq!(
                p.get(key),
                libc::EPERM.to_string(),
                "inside id {id}, {key}: {}",
                p.raw
            );
        }
        assert_eq!(
            p.get("chmod_kill"),
            libc::EROFS.to_string(),
            "inside id {id}: {}",
            p.raw
        );
        assert_eq!(
            mode(&cg),
            before,
            "inside id {id} changed cgroup.kill's mode"
        );
        cg.destroy().expect("destroy");
    }
}
