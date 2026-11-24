//! The memory statistics keeper of a sandbox cgroup (ADR-007, D8,
//! "Buffered writes and the statistics keeper", #54).
//!
//! Dirty throttling (`balance_dirty_pages`) judges a cgroup by its memcg
//! dirty count, which the kernel refreshes about every 2 s, while a
//! buffered writer fills `memory.max` within milliseconds; with a stale
//! count it is never throttled and the cgroup is OOM-killed instead. A
//! read of a cgroup's `memory.stat` flushes its statistics when enough
//! updates are pending (kernel source, not documented API), so one thread
//! per [`crate::Cgroup`] reads that sandbox's own `memory.stat` every
//! [`STATS_KEEPER_PERIOD`].
//!
//! Per sandbox, not per parent (H4 in ADR-007 D8): once a sandbox's own
//! pending-update counter is over the flush threshold, its updates stop
//! counting towards the parent, so a read of the parent stops flushing
//! while the sandbox's own read still flushes. A sandbox has no cgroup
//! below it (`cgroup.max.descendants` 0), so nothing can block its own
//! read the same way.
//!
//! The keeper starts as the last step of [`crate::Cgroup::create`], reads
//! once before `create` returns, and stops once the sandbox is killed. A
//! read error after the start is sticky in the report, and the sandbox is
//! not killed for it. It allocates nothing per tick.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::raw::c_int;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::{Error, Result, errno};

/// How often the keeper reads its sandbox's `memory.stat`. Measured, not
/// chosen (ADR-007, D8): the longest of 50, 25, 10 and 5 ms at which no
/// buffered writer of 64, 128 or 256 MiB was OOM-killed on any CI class or
/// the dev host when the sandbox's reads came twice as far apart (#54, M3,
/// rule R-S1). Reads every 10 ms held all three sizes in 1,260 runs; every
/// 20 ms lost 64 MiB on most classes, so 10 ms is not the period.
pub const STATS_KEEPER_PERIOD: Duration = Duration::from_millis(5);

/// The size of the read buffer: `memory.stat` is about 1.2 KiB on the 7.0
/// and 7.2 kernels (measured), so one `pread` reads it and a second
/// returns 0.
const READ_BUF: usize = 4096;

/// What a keeper did so far, from [`crate::Cgroup::stats_keeper`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeeperReport {
    /// Reads of `memory.stat` that succeeded, the synchronous first one
    /// included.
    pub reads: u64,
    /// Reads that came a whole period or more after their deadline; the
    /// schedule then starts again from that read, without catching up.
    pub late: u64,
    /// The longest time between the starts of two reads in a row.
    pub max_gap: Duration,
    /// The longest single read.
    pub max_read: Duration,
    /// The keeper thread's whole CPU time (`CLOCK_THREAD_CPUTIME_ID`), its
    /// wake-ups included, as of its last read; the synchronous first read
    /// runs on the caller's thread and is not in it.
    pub cpu: Duration,
    /// The `errno` of the read that stopped the keeper, if one did.
    pub failed: Option<c_int>,
}

/// What the keeper does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tick {
    /// Sleep this long (or until stopped).
    Wait(Duration),
    /// Read now; the next deadline is `next`. `late` when a whole period
    /// was missed.
    Read { next: Instant, late: bool },
}

/// The schedule: wait until `deadline`; at a deadline read and keep the
/// rhythm (next = deadline + period); once a whole period was missed,
/// read once and start again from now, so a stalled keeper never bursts.
pub(crate) fn next_tick(deadline: Instant, now: Instant, period: Duration) -> Tick {
    if now < deadline {
        Tick::Wait(deadline - now)
    } else if now < deadline + period {
        Tick::Read {
            next: deadline + period,
            late: false,
        }
    } else {
        Tick::Read {
            next: now + period,
            late: true,
        }
    }
}

/// Adds one successful read that started at `at` to the report.
pub(crate) fn note_read(
    report: &mut KeeperReport,
    last: &mut Option<Instant>,
    at: Instant,
    took: Duration,
    late: bool,
) {
    report.reads = report.reads.saturating_add(1);
    if late {
        report.late = report.late.saturating_add(1);
    }
    if let Some(prev) = *last {
        report.max_gap = report.max_gap.max(at.saturating_duration_since(prev));
    }
    *last = Some(at);
    report.max_read = report.max_read.max(took);
}

/// A whole read of `total` bytes: a cgroup file that reads as empty is not
/// `memory.stat`, so 0 bytes is `EIO`.
pub(crate) fn read_outcome(total: usize) -> std::result::Result<usize, c_int> {
    if total == 0 {
        Err(libc::EIO)
    } else {
        Ok(total)
    }
}

/// Reads `fd` from offset 0 to its end into `buf` and discards it; the
/// read runs `memory.stat`'s show function, which flushes the statistics.
/// Retries EINTR.
pub(crate) fn read_stat(fd: &OwnedFd, buf: &mut [u8]) -> std::result::Result<usize, c_int> {
    let mut total: usize = 0;
    loop {
        // SAFETY: buf is valid writable memory of the length passed; fd is
        // an open descriptor.
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                total as libc::off_t,
            )
        };
        if n < 0 {
            let e = errno();
            if e == libc::EINTR {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return read_outcome(total);
        }
        total = total.saturating_add(n as usize);
    }
}

/// The calling thread's CPU time; zero if the clock cannot be read.
fn thread_cpu() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is valid storage for one timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) } < 0 {
        return Duration::ZERO;
    }
    Duration::new(
        u64::try_from(ts.tv_sec).unwrap_or(0),
        u32::try_from(ts.tv_nsec).unwrap_or(0),
    )
}

#[derive(Debug, Default)]
struct State {
    stop: bool,
    report: KeeperReport,
    last: Option<Instant>,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    wake: Condvar,
}

impl Shared {
    fn guard(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The keeper thread of one sandbox cgroup; stopped and joined by
/// [`StatsKeeper::stop`] or on drop.
#[derive(Debug)]
pub(crate) struct StatsKeeper {
    shared: Arc<Shared>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl StatsKeeper {
    /// Opens `memory.stat` of the cgroup directory `dir` (relative to it,
    /// `O_NOFOLLOW`, `O_CLOEXEC`), reads it once and starts the thread
    /// `memcg-keeper`. A file that cannot be opened or read fails with
    /// [`Error::CgroupFile`], one that reads as empty with
    /// [`Error::StatsKeeper`] (`EIO`); then no thread runs. A failed spawn
    /// is [`Error::Sys`].
    pub(crate) fn start(dir: &OwnedFd) -> Result<StatsKeeper> {
        let fd = crate::cgroup::open_file(dir, "memory.stat", libc::O_RDONLY)?;
        let shared = Arc::new(Shared::default());
        let mut buf = [0u8; READ_BUF];
        let at = Instant::now();
        match read_stat(&fd, &mut buf) {
            Ok(_) => {}
            Err(libc::EIO) => return Err(Error::StatsKeeper { errno: libc::EIO }),
            Err(errno) => {
                return Err(Error::CgroupFile {
                    file: "memory.stat",
                    errno,
                });
            }
        }
        {
            let mut s = shared.guard();
            let State { report, last, .. } = &mut *s;
            note_read(report, last, at, at.elapsed(), false);
        }
        let first_deadline = at + STATS_KEEPER_PERIOD;
        let theirs = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("memcg-keeper".to_string())
            .spawn(move || run(&theirs, &fd, first_deadline, STATS_KEEPER_PERIOD))
            .map_err(|e| Error::Sys {
                call: "spawn(memcg-keeper)",
                errno: e.raw_os_error().unwrap_or(libc::EAGAIN),
            })?;
        Ok(StatsKeeper {
            shared,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// A keeper without a thread, for values that never were cgroups.
    #[cfg(test)]
    pub(crate) fn inert() -> StatsKeeper {
        StatsKeeper {
            shared: Arc::new(Shared::default()),
            thread: Mutex::new(None),
        }
    }

    /// `Err(Error::StatsKeeper)` once a read failed.
    #[cfg(test)]
    pub(crate) fn check(&self) -> Result<()> {
        match self.shared.guard().report.failed {
            Some(errno) => Err(Error::StatsKeeper { errno }),
            None => Ok(()),
        }
    }

    /// The report so far.
    pub(crate) fn report(&self) -> KeeperReport {
        self.shared.guard().report
    }

    /// Stops the thread and joins it; a second call does nothing. The
    /// thread holds only `Arc<Shared>` and its descriptor, never the
    /// keeper, so the join never waits on itself.
    pub(crate) fn stop(&self) {
        self.shared.guard().stop = true;
        self.shared.wake.notify_all();
        let thread = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(t) = thread {
            // A panic in the thread already ended it; nothing to report.
            let _ = t.join();
        }
    }
}

impl Drop for StatsKeeper {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The keeper thread: reads on [`next_tick`]'s schedule until stopped or
/// until a read fails, which it records and ends on. After every read and
/// at its end it records its own CPU time.
fn run(shared: &Shared, fd: &OwnedFd, first: Instant, period: Duration) {
    let mut buf = [0u8; READ_BUF];
    let mut deadline = first;
    let mut s = shared.guard();
    loop {
        if s.stop {
            s.report.cpu = thread_cpu();
            drop(s);
            // Unit tests slow the thread's end, so that a `stop` that
            // returned before the join is seen (mutant MK4).
            #[cfg(test)]
            std::thread::sleep(tests::EXIT_DELAY);
            return;
        }
        match next_tick(deadline, Instant::now(), period) {
            Tick::Wait(d) => {
                s = shared
                    .wake
                    .wait_timeout(s, d)
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
            }
            Tick::Read { next, late } => {
                drop(s);
                let at = Instant::now();
                let r = read_stat(fd, &mut buf);
                let took = at.elapsed();
                let cpu = thread_cpu();
                s = shared.guard();
                s.report.cpu = cpu;
                match r {
                    Ok(_) => {
                        let State { report, last, .. } = &mut *s;
                        note_read(report, last, at, took, late);
                    }
                    Err(e) => {
                        s.report.failed = Some(e);
                        return;
                    }
                }
                deadline = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: Duration = Duration::from_millis(10);

    /// How long the keeper thread lingers after a stop in unit tests.
    pub(super) const EXIT_DELAY: Duration = Duration::from_millis(50);

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// The tests that start keeper threads count them, so they run one at
    /// a time.
    static THREADS: Mutex<()> = Mutex::new(());

    /// The `memcg-keeper` threads of this process.
    fn keepers() -> usize {
        std::fs::read_dir("/proc/self/task")
            .expect("read /proc/self/task")
            .flatten()
            .filter(|t| {
                std::fs::read_to_string(t.path().join("comm"))
                    .is_ok_and(|c| c.trim() == "memcg-keeper")
            })
            .count()
    }

    /// The descriptors of this process that point at `path`.
    fn descriptors_of(path: &std::path::Path) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("read /proc/self/fd")
            .flatten()
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .filter(|t| t == path)
            .count()
    }

    /// Waits up to 1 s for `done`.
    fn within(mut done: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            if done() {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(ms(2));
        }
    }

    /// A fresh directory under the temp dir, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir()
                .join(format!("boneli-keeper-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir(&p).expect("create a temp dir");
            // Canonical, so that it compares with /proc/self/fd links.
            TempDir(p.canonicalize().expect("canonicalize the temp dir"))
        }

        fn fd(&self) -> OwnedFd {
            std::fs::File::open(&self.0)
                .expect("open the temp dir")
                .into()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn keeper_schedule() {
        let d = Instant::now() + ms(1000);
        assert_eq!(next_tick(d, d - ms(1), P), Tick::Wait(ms(1)));
        assert_eq!(
            next_tick(d, d, P),
            Tick::Read {
                next: d + P,
                late: false
            }
        );
        assert_eq!(
            next_tick(d, d + Duration::from_nanos(9_999_999), P),
            Tick::Read {
                next: d + P,
                late: false
            }
        );
        // A whole period missed (inclusive): one late read, re-anchored.
        assert_eq!(
            next_tick(d, d + P, P),
            Tick::Read {
                next: d + ms(20),
                late: true
            }
        );
        // Ten seconds stalled: one late read, then the rhythm from there,
        // not a burst of 1,000 catch-up reads.
        let now = d + ms(10_000);
        let Tick::Read { next, late } = next_tick(d, now, P) else {
            panic!("a read is due");
        };
        assert!(late);
        assert_eq!(next, d + ms(10_010));
        assert_eq!(next_tick(next, now, P), Tick::Wait(P));
    }

    /// Plays reads at the given offsets in ms from a synchronous first
    /// read at 0 through the schedule and the report.
    fn play(offsets: &[u64]) -> KeeperReport {
        let t0 = Instant::now();
        let mut report = KeeperReport::default();
        let mut last = None;
        note_read(&mut report, &mut last, t0, ms(1), false);
        let mut deadline = t0 + P;
        for &o in offsets {
            let at = t0 + ms(o);
            let Tick::Read { next, late } = next_tick(deadline, at, P) else {
                panic!("no read due at {o} ms");
            };
            note_read(&mut report, &mut last, at, ms(1), late);
            deadline = next;
        }
        report
    }

    #[test]
    fn keeper_report_gaps() {
        let r = play(&[10, 26]);
        assert_eq!((r.reads, r.late, r.max_gap), (3, 0, ms(16)));
        let r = play(&[10, 30]);
        assert_eq!((r.reads, r.late, r.max_gap), (3, 1, ms(20)));
        // The gap is measured from the synchronous first read.
        let r = play(&[24]);
        assert_eq!((r.reads, r.late, r.max_gap), (2, 1, ms(24)));
        assert_eq!(r.max_read, ms(1));
        // CPU is the thread's own clock, not a sum over reads.
        assert_eq!(r.cpu, Duration::ZERO);
        let r = play(&[]);
        assert_eq!((r.reads, r.late, r.max_gap), (1, 0, Duration::ZERO));
    }

    #[test]
    fn keeper_empty_read_is_an_error() {
        assert_eq!(read_outcome(0), Err(libc::EIO));
        assert_eq!(read_outcome(1), Ok(1));
        // A real descriptor that reads as empty.
        let null: OwnedFd = std::fs::File::open("/dev/null").expect("/dev/null").into();
        let mut buf = [0u8; READ_BUF];
        assert_eq!(read_stat(&null, &mut buf), Err(libc::EIO));
        // A file larger than the buffer is read to its end, from offset 0
        // every time.
        let dir = TempDir::new("large");
        let path = dir.0.join("f");
        std::fs::write(&path, [7u8; 1000]).expect("write a temp file");
        let file: OwnedFd = std::fs::File::open(&path).expect("open it").into();
        let mut small = [0u8; 64];
        assert_eq!(read_stat(&file, &mut small), Ok(1000));
        assert_eq!(read_stat(&file, &mut small), Ok(1000));
        // A descriptor that cannot be read gives its errno.
        let root: OwnedFd = std::fs::File::open("/").expect("/").into();
        assert_eq!(read_stat(&root, &mut buf), Err(libc::EISDIR));
    }

    #[test]
    fn inert_keeper_reports_nothing_and_checks_ok() {
        let k = StatsKeeper::inert();
        assert!(k.check().is_ok());
        assert_eq!(k.report(), KeeperReport::default());
        k.shared.guard().report.failed = Some(libc::ENODEV);
        assert!(matches!(
            k.check(),
            Err(Error::StatsKeeper {
                errno: libc::ENODEV
            })
        ));
        assert_eq!(k.report().failed, Some(libc::ENODEV));
        // Stopping a keeper without a thread, twice, does nothing.
        k.stop();
        k.stop();
    }

    #[test]
    fn keeper_start_refuses_missing_or_empty_stat() {
        let _one = THREADS.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new("refuse");
        let before = keepers();
        let missing = StatsKeeper::start(&dir.fd());
        assert!(
            matches!(
                missing,
                Err(Error::CgroupFile {
                    file: "memory.stat",
                    errno: libc::ENOENT
                })
            ),
            "{missing:?}"
        );
        std::fs::write(dir.0.join("memory.stat"), b"").expect("an empty memory.stat");
        let empty = StatsKeeper::start(&dir.fd());
        assert!(
            matches!(empty, Err(Error::StatsKeeper { errno: libc::EIO })),
            "{empty:?}"
        );
        assert_eq!(keepers(), before, "a thread started for a refused keeper");
        // A symlink is not followed (O_NOFOLLOW).
        let target = dir.0.join("real");
        std::fs::write(&target, b"file 1\n").expect("a target");
        std::fs::remove_file(dir.0.join("memory.stat")).expect("remove");
        std::os::unix::fs::symlink(&target, dir.0.join("memory.stat")).expect("a symlink");
        let link = StatsKeeper::start(&dir.fd());
        assert!(
            matches!(
                link,
                Err(Error::CgroupFile {
                    file: "memory.stat",
                    errno: libc::ELOOP
                })
            ),
            "{link:?}"
        );
        assert_eq!(keepers(), before);
    }

    #[test]
    fn keeper_read_failure_is_sticky() {
        let _one = THREADS.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new("sticky");
        let stat = dir.0.join("memory.stat");
        std::fs::write(&stat, b"anon 0\nfile 0\n").expect("a memory.stat");
        let before = keepers();
        let k = StatsKeeper::start(&dir.fd()).expect("start");
        // A new thread takes its name a moment after the spawn returns.
        assert!(
            within(|| keepers() == before + 1),
            "one memcg-keeper thread"
        );
        assert!(within(|| k.report().reads >= 3), "{:?}", k.report());
        // Truncated under the keeper: its next read returns 0 bytes.
        std::fs::write(&stat, b"").expect("truncate");
        assert!(
            within(|| k.report().failed.is_some()),
            "no failure within 1 s: {:?}",
            k.report()
        );
        assert_eq!(k.report().failed, Some(libc::EIO));
        // The thread ended on the failure; the failure stays, also after
        // the file is readable again.
        assert!(within(|| keepers() == before), "the thread still runs");
        std::fs::write(&stat, b"anon 0\n").expect("refill");
        let reads = k.report().reads;
        std::thread::sleep(5 * P);
        assert_eq!(k.report().failed, Some(libc::EIO));
        assert_eq!(k.report().reads, reads);
        assert!(matches!(
            k.check(),
            Err(Error::StatsKeeper { errno: libc::EIO })
        ));
        assert!(k.report().cpu > Duration::ZERO, "{:?}", k.report());
        k.stop();
        k.stop();
    }

    #[test]
    fn keeper_stop_joins_and_is_idempotent() {
        let _one = THREADS.lock().unwrap_or_else(|p| p.into_inner());
        let dir = TempDir::new("stop");
        let stat = dir.0.join("memory.stat");
        std::fs::write(&stat, b"anon 0\n").expect("a memory.stat");
        let before = keepers();
        let k = StatsKeeper::start(&dir.fd()).expect("start");
        assert!(within(|| keepers() == before + 1));
        assert_eq!(descriptors_of(&stat), 1, "the keeper holds memory.stat");
        k.stop();
        // Joined: the thread has ended, and closed its descriptor, when
        // stop returns (its /proc entry may take a moment longer to go).
        assert_eq!(descriptors_of(&stat), 0, "stop returned before the join");
        assert!(within(|| keepers() == before), "the thread still runs");
        let reads = k.report().reads;
        std::thread::sleep(3 * P);
        assert_eq!(k.report().reads, reads, "a stopped keeper read");
        assert_eq!(k.report().failed, None);
        k.stop();
        drop(k);
        assert!(within(|| keepers() == before));
    }
}
