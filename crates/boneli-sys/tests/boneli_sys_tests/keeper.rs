//! The memory statistics keeper of a sandbox cgroup (ADR-007, D8, #54):
//! one thread per sandbox, from the end of `Cgroup::create` until the
//! sandbox is killed, reading the sandbox's own `memory.stat`; none for a
//! parent.
//!
//! Every test takes `support::exclusive()` and follows its own cgroups'
//! keepers through the descriptor each holds on its sandbox's
//! `memory.stat` for exactly its thread's life: other tests create
//! cgroups, and with them keepers, at any time, so threads are counted
//! only in the unit tests, which run alone. What a keeper reads is
//! followed through inotify `IN_ACCESS` events on the files themselves,
//! which every successful read raises, whoever holds the descriptor.

use std::ffi::{CString, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use boneli_sys::{
    Cgroup, ExitStatus, KeeperReport, Mount, Parent, Root, STATS_KEEPER_PERIOD, Spec, Stdio, spawn,
};

use crate::support::cgroup;
use crate::support::rootfs::{Fixture, inside};
use crate::support::{self, dev_null, ids, report, wait_bounded};

/// How long a test waits for something the keeper does every period or
/// once at its stop: 1 s, 200 periods of 5 ms.
const KEEPER_WAIT: Duration = Duration::from_secs(1);

/// Waits up to [`KEEPER_WAIT`] for `done`.
fn within(mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + KEEPER_WAIT;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The descriptors of this process that point at `path`, also once the
/// file is gone (`<path> (deleted)`).
fn descriptors_of(path: &Path) -> usize {
    let deleted = PathBuf::from(format!("{} (deleted)", path.display()));
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .flatten()
        .filter_map(|e| std::fs::read_link(e.path()).ok())
        .filter(|target| *target == path || *target == deleted)
        .count()
}

/// An inotify instance that watches files for reads (`IN_ACCESS`), read
/// without blocking.
struct ReadWatch {
    fd: OwnedFd,
    /// The watch descriptor of each file, in the order given.
    watches: Vec<i32>,
}

impl ReadWatch {
    fn new(files: &[&Path]) -> ReadWatch {
        // SAFETY: inotify_init1 takes flags only.
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(
            raw >= 0,
            "inotify_init1: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: raw is a new descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let watches = files
            .iter()
            .map(|f| {
                let c = CString::new(f.as_os_str().as_bytes()).expect("a path without NUL");
                // SAFETY: fd is an inotify descriptor, c a NUL-terminated path.
                let wd =
                    unsafe { libc::inotify_add_watch(fd.as_raw_fd(), c.as_ptr(), libc::IN_ACCESS) };
                assert!(
                    wd >= 0,
                    "inotify_add_watch {}: {}",
                    f.display(),
                    std::io::Error::last_os_error()
                );
                wd
            })
            .collect();
        ReadWatch { fd, watches }
    }

    /// Drains the queue: for each file, whether it was read since the
    /// last drain. inotify merges an event with an identical one still
    /// queued, so this tells whether, not how often.
    fn drain(&self) -> Vec<bool> {
        let mut seen = vec![false; self.watches.len()];
        // inotify_event is a 16-byte header plus a name, empty for a file
        // watch; u64 elements keep the buffer aligned for it.
        let mut buf = [0u64; 512];
        loop {
            // SAFETY: buf is valid writable memory of the length passed.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    std::mem::size_of_val(&buf),
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                assert_eq!(e.raw_os_error(), Some(libc::EAGAIN), "read inotify: {e}");
                return seen;
            }
            let n = usize::try_from(n).expect("a byte count");
            let bytes: Vec<u8> = buf.iter().flat_map(|w| w.to_ne_bytes()).take(n).collect();
            let mut at = 0;
            while at + 16 <= n {
                let field = |i: usize| {
                    u32::from_ne_bytes(bytes[at + i..at + i + 4].try_into().expect("4 bytes"))
                };
                let wd = field(0) as i32;
                if let Some(i) = self.watches.iter().position(|w| *w == wd) {
                    seen[i] = true;
                }
                at += 16 + field(12) as usize;
            }
        }
    }
}

/// How many slots of 10 keeper periods a read pin watches: 1 s at 5 ms.
const READ_SLOTS: usize = 20;

/// Watches `files` for [`READ_SLOTS`] slots of 10 keeper periods each and
/// returns, per file, in how many slots it was read.
fn read_slots(files: &[&Path]) -> Vec<usize> {
    let w = ReadWatch::new(files);
    let mut slots = vec![0; files.len()];
    for _ in 0..READ_SLOTS {
        std::thread::sleep(10 * STATS_KEEPER_PERIOD);
        for (n, read) in slots.iter_mut().zip(w.drain()) {
            *n += usize::from(read);
        }
    }
    slots
}

#[test]
#[ignore = "host: cgroup v2 delegation (cpu, io, memory, pids)"]
fn keeper_reads_its_own_sandbox() {
    // H4 (ADR-007 D8): a read of the parent's memory.stat stops flushing
    // once a sandbox below it is flushable, so each keeper must read its
    // own sandbox's file, every period, and never the parent's. The
    // descriptors show what a keeper holds; the inotify reads show what it
    // reads: a keeper that holds its own file but opens, reads and closes
    // the parent's every period passed the descriptor checks alone (#54
    // review, finding 2).
    let _alone = support::exclusive();
    let parent_stat = cgroup::parent().path().join("memory.stat");
    let parent_before = descriptors_of(&parent_stat);
    let a = cgroup::sandbox("keeper-own");
    let b = cgroup::sandbox("keeper-own");
    let a_stat = a.path().join("memory.stat");
    let b_stat = b.path().join("memory.stat");
    assert_eq!(descriptors_of(&a_stat), 1, "{}", a_stat.display());
    assert_eq!(descriptors_of(&b_stat), 1, "{}", b_stat.display());
    assert_eq!(
        descriptors_of(&parent_stat),
        parent_before,
        "a keeper holds the parent's memory.stat"
    );
    // Each keeper reads its own file in at least 3 of 4 slots of 10
    // periods (one read in ten is late at worst; a keeper that reads every
    // period fills every slot), and the parent's file is read in at most
    // a quarter of them (nothing in this test reads it; a host's monitor
    // may, about once a second; a keeper that reads it every period fills
    // every slot).
    let slots = read_slots(&[&a_stat, &b_stat, &parent_stat]);
    report(&format!(
        "keeper_reads_its_own_sandbox: slots of {:?} with a read, of {READ_SLOTS}: \
         sandbox a {}, sandbox b {}, parent {}; {:?} {:?}",
        10 * STATS_KEEPER_PERIOD,
        slots[0],
        slots[1],
        slots[2],
        a.stats_keeper(),
        b.stats_keeper()
    ));
    for (i, name) in ["a", "b"].iter().enumerate() {
        assert!(
            slots[i] * 4 >= READ_SLOTS * 3,
            "the keeper of sandbox {name} read its memory.stat in {} of {READ_SLOTS} slots of \
             10 periods: {:?}",
            slots[i],
            slots
        );
    }
    assert!(
        slots[2] * 4 <= READ_SLOTS,
        "the parent's memory.stat was read in {} of {READ_SLOTS} slots of 10 periods: {:?}",
        slots[2],
        slots
    );
    a.destroy().expect("destroy");
    assert_eq!(descriptors_of(&a_stat), 0, "left after destroy");
    assert_eq!(descriptors_of(&b_stat), 1);
    drop(b);
    assert_eq!(descriptors_of(&b_stat), 0, "left after a drop");
}

#[test]
#[ignore = "host: cgroup v2 delegation (cpu, io, memory, pids)"]
fn keeper_runs_while_cgroup_lives() {
    // Other tests create cgroups (and with them keepers) at any time, so
    // threads are not counted here (the unit tests count them, alone).
    // A keeper holds its sandbox's memory.stat from its start to the end
    // of its thread, and its reads grow only while it runs, so those are
    // followed per cgroup.
    let _alone = support::exclusive();
    let parent_stat = cgroup::parent().path().join("memory.stat");
    let parent_before = descriptors_of(&parent_stat);
    let parent = Parent::open(cgroup::parent().path()).expect("open the harness's parent");
    assert_eq!(
        descriptors_of(&parent_stat),
        parent_before,
        "Parent::open started a keeper"
    );
    let a = cgroup::sandbox("keeper-life");
    let b = Cgroup::create(
        &parent,
        &cgroup::unique_name("keeper-life"),
        &cgroup::default_limits(),
    )
    .expect("create");
    let a_stat = a.path().join("memory.stat");
    let b_stat = b.path().join("memory.stat");
    assert_eq!(descriptors_of(&a_stat), 1, "create starts one keeper");
    assert_eq!(descriptors_of(&b_stat), 1, "one keeper per cgroup");
    let first = a.stats_keeper();
    assert!(first.reads >= 1, "the first read is synchronous: {first:?}");
    let b_first = b.stats_keeper();
    assert!(
        within(|| a.stats_keeper().reads >= first.reads + 2
            && b.stats_keeper().reads >= b_first.reads + 2),
        "a keeper did not read twice within {KEEPER_WAIT:?}: {:?} {:?}",
        a.stats_keeper(),
        b.stats_keeper()
    );
    let r = a.stats_keeper();
    assert_eq!(r.failed, None, "{r:?}");
    report(&format!(
        "keeper_runs_while_cgroup_lives: period {STATS_KEEPER_PERIOD:?}, {r:?}"
    ));
    a.destroy().expect("destroy");
    // Joined in destroy: its descriptor is closed when destroy returns.
    assert_eq!(descriptors_of(&a_stat), 0, "the keeper outlived destroy");
    assert_eq!(descriptors_of(&b_stat), 1, "destroy stopped another keeper");
    drop(b);
    assert_eq!(descriptors_of(&b_stat), 0, "the keeper outlived a drop");
    drop(parent);
}

fn root_with_cgroup(fixture: &Fixture) -> Root {
    let mut mounts = fixture.mounts();
    mounts.push(Mount::Cgroup2 {
        target: inside("/sys/fs/cgroup"),
    });
    fixture.root_with(vec![fixture.layer.clone()], mounts)
}

/// The buffered writers of the cost report: 16 MiB each, `never` mode.
const COST_WRITE: &str = "16777216";

/// How long the cost report watches the keepers per count.
const COST_WINDOW: Duration = Duration::from_secs(3);

/// Runs `n` buffered writers, each in its own cgroup, for [`COST_WINDOW`]
/// and returns each keeper's report at its end and how many writers
/// exited 0.
fn cost_window(n: usize) -> (Vec<KeeperReport>, usize) {
    let fixtures: Vec<Fixture> = (0..n).map(|_| Fixture::new("keeper-cost")).collect();
    let cgs: Vec<Cgroup> = (0..n).map(|_| cgroup::sandbox("keeper-cost")).collect();
    let start = Instant::now();
    let mut children = Vec::new();
    for (f, cg) in fixtures.iter().zip(&cgs) {
        let s = Spec {
            program: crate::support::rootfs::PROBE.into(),
            args: ["--exact", "probe", "--nocapture", "--quiet"]
                .iter()
                .map(OsString::from)
                .collect(),
            env: [
                (support::probe::ACTION_VAR, "io-write"),
                ("BONELI_PROBE_FILE", "/workspace/cost"),
                ("BONELI_PROBE_SIZE", COST_WRITE),
                ("BONELI_PROBE_DIRECT", "never"),
            ]
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect(),
            stdio: Stdio {
                stdin: dev_null(),
                stdout: dev_null(),
                stderr: dev_null(),
            },
            ids: ids(0, 0),
            setup_timeout: support::SETUP_TIMEOUT,
            // The probe reads its own cgroup after its loop, through a
            // cgroup2 mount of its own.
            root: root_with_cgroup(f),
            cgroup: cg,
        };
        children.push(spawn(&s).expect("spawn a writer"));
    }
    let ok = children
        .iter_mut()
        .map(|c| wait_bounded(c, support::PROBE_HANG_BOUND))
        .filter(|s| *s == ExitStatus::Exited(0))
        .count();
    std::thread::sleep(COST_WINDOW.saturating_sub(start.elapsed()));
    let reports = cgs.iter().map(Cgroup::stats_keeper).collect();
    for cg in cgs {
        cg.destroy().expect("destroy");
    }
    drop(fixtures);
    (reports, ok)
}

#[test]
#[ignore = "host: cgroup v2 delegation (cpu, io, memory, pids); cost report"]
fn keeper_cost_report() {
    // Each keeper's CPU per read with 1 and 8 sandboxes writing. The CPU
    // is the keeper thread's whole CPU time, so its wake-ups count; CPU
    // time, not wall time, because a busy runner stretches wall time by
    // preemption, not the CPU a read takes. The bound is a tenth of the
    // period (R-S5's ratio, ADR-007 D8). The rest is reported, for #8.
    let _alone = support::exclusive();
    let bound = STATS_KEEPER_PERIOD / 10;
    for n in [1, 8] {
        let (reports, ok) = cost_window(n);
        assert_eq!(ok, n, "a writer failed");
        let mut per_read_max = Duration::ZERO;
        let mut cpu_total = Duration::ZERO;
        let mut late = 0;
        let mut max_gap = Duration::ZERO;
        let mut max_read = Duration::ZERO;
        for r in &reports {
            assert_eq!(r.failed, None, "{r:?}");
            assert!(r.reads >= 2, "a keeper did not read: {r:?}");
            let per_read = r.cpu / u32::try_from(r.reads).unwrap_or(u32::MAX);
            per_read_max = per_read_max.max(per_read);
            cpu_total += r.cpu;
            late += r.late;
            max_gap = max_gap.max(r.max_gap);
            max_read = max_read.max(r.max_read);
        }
        let reads: u64 = reports.iter().map(|r| r.reads).sum();
        report(&format!(
            "keeper_cost_report: {n} sandboxes, {reads} reads in {COST_WINDOW:?}, cpu {cpu_total:?} \
             ({:.2} ms per second per sandbox, {:.2} in total), up to {per_read_max:?} per read \
             (bound {bound:?}), max_read {max_read:?}, max_gap {max_gap:?}, late {late}",
            cpu_total.as_secs_f64() * 1000.0 / COST_WINDOW.as_secs_f64() / n as f64,
            cpu_total.as_secs_f64() * 1000.0 / COST_WINDOW.as_secs_f64(),
        ));
        assert!(
            per_read_max <= bound,
            "a keeper's CPU per read {per_read_max:?} is over {bound:?} with {n} sandboxes"
        );
    }
}
