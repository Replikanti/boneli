//! The harness's cgroups (ADR-007, D5 and D8): the delegated parent of the
//! test run and a cgroup with small limits for every sandbox a test starts.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

use boneli_sys::{Cgroup, CpuMax, IoLimits, Limits, Parent};

/// Set to `self` when the test run has a delegated scope of its own, which
/// the harness may reorganize (CLAUDE.md, "Host tests").
pub const TEST_CGROUP_VAR: &str = "BONELI_SYS_TEST_CGROUP";

/// The name `Parent::vacate_and_delegate` moves the scope's processes to.
const LEAF: &str = "leaf";

/// The memory limit of a test sandbox: the probe is this test binary, a
/// few MiB, plus libtest; 256 MiB leaves room and still stops a runaway
/// probe long before it hurts the host.
pub const MEMORY_MAX: u64 = 256 << 20;

/// The task limit of a test sandbox: the probe, libtest's threads and the
/// few children some probes fork.
pub const PIDS_MAX: u64 = 64;

/// The run's own cgroup, from `/proc/self/cgroup`.
pub fn own_cgroup() -> PathBuf {
    let text = std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup");
    let own = text
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .expect("a cgroup v2 line in /proc/self/cgroup");
    Path::new("/sys/fs/cgroup").join(own.trim_start_matches('/'))
}

/// The delegated parent of every test sandbox's cgroup. On first use it
/// vacates the run's own cgroup into `leaf/` and enables the four
/// controllers there; only with `BONELI_SYS_TEST_CGROUP=self`, so a
/// terminal's cgroup is never reorganized. A later test binary of the same
/// run starts in that `leaf/` and uses its parent.
pub fn parent() -> &'static Parent {
    static PARENT: OnceLock<Parent> = OnceLock::new();
    PARENT.get_or_init(|| {
        let mode = std::env::var(TEST_CGROUP_VAR).unwrap_or_default();
        assert_eq!(
            mode, "self",
            "host tests need {TEST_CGROUP_VAR}=self in a delegated scope of their own \
             (systemd-run --user --scope -p Delegate=yes, CLAUDE.md \"Host tests\")"
        );
        let own = own_cgroup();
        if own.file_name().is_some_and(|n| n == LEAF) {
            let up = own.parent().expect("leaf/ has a parent");
            if let Ok(parent) = Parent::open(up) {
                return parent;
            }
        }
        Parent::vacate_and_delegate(&own)
            .unwrap_or_else(|e| panic!("delegate {}: {e}", own.display()))
    })
}

/// Limits for a test sandbox: [`MEMORY_MAX`] without swap, [`PIDS_MAX`],
/// one CPU (`100000 100000`) and no IO limit.
pub fn default_limits() -> Limits {
    Limits {
        memory_max: MEMORY_MAX,
        memory_swap_max: 0,
        pids_max: PIDS_MAX,
        cpu: CpuMax {
            quota_us: 100_000,
            period_us: 100_000,
        },
        io: IoLimits::none(),
    }
}

/// A unique cgroup name for `tag`.
pub fn unique_name(tag: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{tag}-{}-{n}", std::process::id())
}

/// A cgroup with `limits` under [`parent`].
pub fn create(tag: &str, limits: &Limits) -> Cgroup {
    let name = unique_name(tag);
    Cgroup::create(parent(), &name, limits).unwrap_or_else(|e| panic!("create cgroup {name}: {e}"))
}

/// A cgroup with [`default_limits`].
pub fn sandbox(tag: &str) -> Cgroup {
    create(tag, &default_limits())
}

/// A file of `cgroup`, read through its host path.
pub fn read(cgroup: &Cgroup, file: &str) -> String {
    let path = cgroup.path().join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The value of `key` in a flat-keyed file such as `cpu.stat` or
/// `memory.events`.
pub fn keyed(text: &str, key: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no {key} in {text:?}"))
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{key} in {text:?}: {e}"))
}
