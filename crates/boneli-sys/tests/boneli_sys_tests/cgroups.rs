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
    // it before they drain at the throttled rate (40 MiB: about 40 s, past
    // the 10 s bound). destroy lifts io.max after the kill, so the bios
    // drain at once (the reviewer measured 97 ms with the lift).
    let _alone = support::exclusive();
    let fixture = Fixture::new("io-kill");
    let dev = block_device_of(&fixture.workspace).expect("a block device behind /workspace");
    let io = IoLimits::new(vec![IoMax {
        dev,
        rbps: None,
        wbps: Some(1 << 20),
        riops: None,
        wiops: None,
    }])
    .expect("one device");
    let cg = cgroup::create("io-kill", &limits(256 << 20, 16, (100_000, 100_000), io));
    let mut child = spawn(&spec(
        fixture.root(),
        &cg,
        "/usr/bin/dd",
        &[
            "if=/dev/urandom",
            "of=/workspace/big",
            "bs=40M",
            "count=1",
            "iflag=fullblock",
            "oflag=direct",
        ],
    ))
    .expect("spawn dd");
    // Let dd fill its buffer and block in the throttled write.
    std::thread::sleep(Duration::from_secs(2));
    let path = cg.path().to_path_buf();
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
