//! What the host must provide (ADR-007, D3 and D5; the floor is Linux 6.1,
//! ADR-044), checked by trying each feature instead of reading the kernel
//! version: distributions backport.

use std::fmt;
use std::os::fd::AsRawFd;
use std::time::Duration;

use crate::child::{Action, ChildPlan, Fault, Step};
use crate::error::{Error, Result, errno};
use crate::ffi;
use crate::spawn::{ExitStatus, await_report, launch, report_pipe};

/// The oldest Landlock ABI the runtime accepts: under ABI 1 every rename or
/// link into another directory is denied, which git and npm do (ADR-007, D3).
pub const LANDLOCK_ABI_REQUIRED: u32 = 2;

/// Hang bound of the probe's user-namespace child, which only writes three
/// `/proc` files and exits: it takes milliseconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

use crate::cgroup::CONTROLLERS;

/// The stable id of a [`Missing`] feature, as `BONELI_SYS_EXPECT_MISSING`
/// and CI name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MissingId {
    /// `userns-apparmor`
    UsernsApparmor,
    /// `userns-disabled`
    UsernsDisabled,
    /// `userns-other`
    UsernsOther,
    /// `cgroup-not-delegated`
    CgroupNotDelegated,
    /// `cgroup-controller-missing`
    CgroupControllerMissing,
    /// `cgroup2-missing`
    Cgroup2Missing,
    /// `cgroup-nsdelegate`
    CgroupNsdelegate,
    /// `clone3`
    Clone3,
    /// `close-range`
    CloseRange,
    /// `seccomp-kill-process`
    SeccompKillProcess,
    /// `seccomp-filter`
    SeccompFilter,
    /// `seccomp-notify`
    SeccompNotify,
    /// `landlock-unavailable`
    LandlockUnavailable,
    /// `landlock-abi`
    LandlockAbi,
    /// `keyrings`
    Keyrings,
    /// `kernel-floor`
    KernelFloor,
    /// `probe-failed`
    ProbeFailed,
}

impl MissingId {
    /// Every id.
    pub const ALL: [MissingId; 17] = [
        MissingId::UsernsApparmor,
        MissingId::UsernsDisabled,
        MissingId::UsernsOther,
        MissingId::CgroupNotDelegated,
        MissingId::CgroupControllerMissing,
        MissingId::Cgroup2Missing,
        MissingId::CgroupNsdelegate,
        MissingId::Clone3,
        MissingId::CloseRange,
        MissingId::SeccompKillProcess,
        MissingId::SeccompFilter,
        MissingId::SeccompNotify,
        MissingId::LandlockUnavailable,
        MissingId::LandlockAbi,
        MissingId::Keyrings,
        MissingId::KernelFloor,
        MissingId::ProbeFailed,
    ];

    /// The id's stable name.
    pub fn as_str(self) -> &'static str {
        match self {
            MissingId::UsernsApparmor => "userns-apparmor",
            MissingId::UsernsDisabled => "userns-disabled",
            MissingId::UsernsOther => "userns-other",
            MissingId::CgroupNotDelegated => "cgroup-not-delegated",
            MissingId::CgroupControllerMissing => "cgroup-controller-missing",
            MissingId::Cgroup2Missing => "cgroup2-missing",
            MissingId::CgroupNsdelegate => "cgroup-nsdelegate",
            MissingId::Clone3 => "clone3",
            MissingId::CloseRange => "close-range",
            MissingId::SeccompKillProcess => "seccomp-kill-process",
            MissingId::SeccompFilter => "seccomp-filter",
            MissingId::SeccompNotify => "seccomp-notify",
            MissingId::LandlockUnavailable => "landlock-unavailable",
            MissingId::LandlockAbi => "landlock-abi",
            MissingId::Keyrings => "keyrings",
            MissingId::KernelFloor => "kernel-floor",
            MissingId::ProbeFailed => "probe-failed",
        }
    }

    /// The id with this name.
    pub fn from_name(name: &str) -> Option<MissingId> {
        MissingId::ALL.into_iter().find(|id| id.as_str() == name)
    }
}

/// A host feature the runtime needs and did not find, with its cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Missing {
    /// AppArmor restricts unprivileged user namespaces
    /// (`kernel.apparmor_restrict_unprivileged_userns` = 1, Ubuntu 23.10+).
    UsernsApparmor,
    /// A sysctl disables unprivileged user namespaces.
    UsernsDisabled {
        /// The sysctl that is 0.
        sysctl: &'static str,
    },
    /// Creating a user namespace failed for another reason.
    UsernsOther {
        /// Where it failed: `clone3` or a setup step name.
        stage: &'static str,
        /// The error.
        detail: String,
    },
    /// The caller's cgroup is not delegated to it.
    CgroupNotDelegated {
        /// The cgroup directory.
        path: String,
        /// The first file (or the directory) the caller cannot write.
        file: String,
        /// The caller's effective uid.
        uid: u32,
    },
    /// The caller's cgroup lacks a controller.
    CgroupControllerMissing {
        /// The cgroup directory.
        path: String,
        /// The controller.
        controller: &'static str,
    },
    /// No cgroup v2 hierarchy at `/sys/fs/cgroup`.
    Cgroup2Missing,
    /// The cgroup v2 hierarchy at `/sys/fs/cgroup` is mounted without
    /// `nsdelegate`, the only kernel check that refuses a sandbox's write to
    /// its own limit files through a cgroup2 mount of its own: the files
    /// belong to the host user the inside id maps to (ADR-007, D8).
    CgroupNsdelegate {
        /// The super options of the mount, or why they are unknown.
        options: String,
    },
    /// `clone3` (Linux 5.3) is not available.
    Clone3 {
        /// The errno of the attempt.
        errno: i32,
    },
    /// `close_range` with `CLOSE_RANGE_CLOEXEC` (Linux 5.11) is not available.
    CloseRange {
        /// The errno of the attempt.
        errno: i32,
    },
    /// seccomp cannot kill a whole process (`SECCOMP_RET_KILL_PROCESS`,
    /// Linux 4.14).
    SeccompKillProcess {
        /// The errno of the attempt.
        errno: i32,
    },
    /// The kernel refuses to install a seccomp filter (no
    /// `CONFIG_SECCOMP_FILTER`), tried in the probe's child.
    SeccompFilter {
        /// The errno of the attempt.
        errno: i32,
    },
    /// seccomp user notification as the sandbox uses it (ADR-043, D7) is
    /// not available.
    SeccompNotify(NotifyGap),
    /// Landlock is not built in or not enabled.
    LandlockUnavailable {
        /// The errno of the attempt.
        errno: i32,
    },
    /// Landlock is older than ABI 2 (Linux 5.19).
    LandlockAbi {
        /// The ABI the kernel reports.
        found: u32,
        /// The ABI the runtime needs.
        required: u32,
    },
    /// The kernel keyrings are not usable: built without `CONFIG_KEYS`
    /// (`keyctl` gives ENOSYS, `/proc/keys` is absent), or `keyctl` is
    /// filtered by the runner's own seccomp profile. Every spawn joins a
    /// new session keyring and covers both proc files (ADR-007, D2 and
    /// D3), so such a host could start no sandbox.
    Keyrings {
        /// What failed: `keyctl`, `/proc/keys` or `/proc/key-users`.
        item: &'static str,
        /// The errno.
        errno: i32,
    },
    /// The kernel is older than Linux 6.1, the floor (ADR-044): the
    /// caller's cgroup has the pids controller's `pids.max` but not its
    /// `pids.peak`, which Linux 6.1 added. No interface the runtime calls
    /// changed from 5.19 to 6.1, so this marker is what tells them apart;
    /// a vendor kernel that backports `pids.peak` passes, as D3's backport
    /// rule intends.
    KernelFloor {
        /// The cgroup directory.
        path: String,
    },
    /// A probe could not run its test, for a reason that says nothing
    /// about the feature (a resource limit, a failed pipe, a killed or
    /// mis-reporting probe child), so the feature is neither present nor
    /// missing; the probe fails closed with the real cause instead of
    /// naming a feature the host may have (ADR-007, D3; review of PR 1 and
    /// PR 2 of #6).
    ProbeFailed {
        /// The feature the probe tests.
        probe: &'static str,
        /// Where it failed: a syscall, a setup stage, or how the child ended.
        stage: &'static str,
        /// The cause: an errno, or a description of how the child ended.
        detail: String,
    },
}

impl Missing {
    /// The stable id.
    pub fn id(&self) -> MissingId {
        match self {
            Missing::UsernsApparmor => MissingId::UsernsApparmor,
            Missing::UsernsDisabled { .. } => MissingId::UsernsDisabled,
            Missing::UsernsOther { .. } => MissingId::UsernsOther,
            Missing::CgroupNotDelegated { .. } => MissingId::CgroupNotDelegated,
            Missing::CgroupControllerMissing { .. } => MissingId::CgroupControllerMissing,
            Missing::Cgroup2Missing => MissingId::Cgroup2Missing,
            Missing::CgroupNsdelegate { .. } => MissingId::CgroupNsdelegate,
            Missing::Clone3 { .. } => MissingId::Clone3,
            Missing::CloseRange { .. } => MissingId::CloseRange,
            Missing::SeccompKillProcess { .. } => MissingId::SeccompKillProcess,
            Missing::SeccompFilter { .. } => MissingId::SeccompFilter,
            Missing::SeccompNotify(_) => MissingId::SeccompNotify,
            Missing::LandlockUnavailable { .. } => MissingId::LandlockUnavailable,
            Missing::LandlockAbi { .. } => MissingId::LandlockAbi,
            Missing::Keyrings { .. } => MissingId::Keyrings,
            Missing::KernelFloor { .. } => MissingId::KernelFloor,
            Missing::ProbeFailed { .. } => MissingId::ProbeFailed,
        }
    }
}

fn os(errno: i32) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno)
}

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Missing::UsernsApparmor => write!(
                f,
                "user namespaces are restricted by AppArmor (kernel.apparmor_restrict_unprivileged_userns = 1); \
                 this binary needs a profile that allows userns"
            ),
            Missing::UsernsDisabled { sysctl } => write!(
                f,
                "unprivileged user namespaces are disabled ({sysctl} = 0)"
            ),
            Missing::UsernsOther { stage, detail } => {
                write!(f, "creating a user namespace failed at {stage}: {detail}")
            }
            Missing::CgroupNotDelegated { path, file, uid } => {
                write!(
                    f,
                    "the cgroup {path} is not delegated to uid {uid}: {file} is not writable"
                )
            }
            Missing::CgroupControllerMissing { path, controller } => {
                write!(
                    f,
                    "the cgroup {path} lacks the {controller} controller (not in cgroup.controllers)"
                )
            }
            Missing::Cgroup2Missing => {
                write!(f, "no cgroup v2 hierarchy is mounted at /sys/fs/cgroup")
            }
            Missing::CgroupNsdelegate { options } => write!(
                f,
                "the cgroup v2 hierarchy at /sys/fs/cgroup is mounted without nsdelegate ({options}); \
                 a sandbox could raise its own limits (remount with nsdelegate as root)"
            ),
            Missing::Clone3 { errno } => write!(
                f,
                "clone3 is not available: {} (boneli needs Linux 6.1 or newer)",
                os(*errno)
            ),
            Missing::CloseRange { errno } => {
                write!(
                    f,
                    "close_range with CLOSE_RANGE_CLOEXEC is not available: {} (boneli needs Linux 6.1 or newer)",
                    os(*errno)
                )
            }
            Missing::SeccompKillProcess { errno } => write!(
                f,
                "seccomp cannot kill a whole process (SECCOMP_RET_KILL_PROCESS): {} (boneli needs Linux 6.1 or newer)",
                os(*errno)
            ),
            Missing::SeccompFilter { errno } => write!(
                f,
                "seccomp filters cannot be installed: {} (the kernel needs CONFIG_SECCOMP_FILTER)",
                os(*errno)
            ),
            Missing::SeccompNotify(gap) => write!(f, "{gap}"),
            Missing::LandlockUnavailable { errno } => write!(
                f,
                "Landlock is not available: {} (it must be built in and listed in the lsm= boot parameter)",
                os(*errno)
            ),
            Missing::LandlockAbi { found, required } => {
                write!(
                    f,
                    "Landlock ABI {found} found, {required} or newer required (ABI 2 came with Linux 5.19; \
                     boneli needs Linux 6.1 or newer)"
                )
            }
            Missing::Keyrings { item, errno } => write!(
                f,
                "the kernel keyrings are not usable: {item}: {} (every sandbox joins a new session keyring \
                 and hides /proc/keys; the kernel needs CONFIG_KEYS, and keyctl must not be filtered)",
                os(*errno)
            ),
            Missing::KernelFloor { path } => write!(
                f,
                "this kernel is older than Linux 6.1, the oldest boneli supports: {path}/pids.max exists \
                 but pids.peak (added in Linux 6.1) does not"
            ),
            Missing::ProbeFailed {
                probe,
                stage,
                detail,
            } => write!(
                f,
                "the {probe} probe could not run: {stage}: {detail} (says nothing about {probe}; retry once the cause is gone)"
            ),
        }
    }
}

/// Why seccomp user notification, as the sandbox's supervisor uses it, is
/// not available (ADR-043, D7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyGap {
    /// Installing a filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER |
    /// SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` failed in the probe's
    /// filter child: EINVAL on a kernel below 5.19, which lacks the second
    /// flag; EBUSY when this process already runs under a filter with a
    /// listener (`has_duplicate_listener`, 5.19 `kernel/seccomp.c:1807`),
    /// as under the syscall interception of LXD, Incus or sysbox.
    Install {
        /// The errno of the install.
        errno: i32,
    },
    /// `SECCOMP_GET_ACTION_AVAIL` refuses `SECCOMP_RET_USER_NOTIF`.
    Action {
        /// The errno.
        errno: i32,
    },
    /// `SECCOMP_GET_NOTIF_SIZES` failed.
    SizesUnreadable {
        /// The errno.
        errno: i32,
    },
    /// The kernel's notification structs are smaller than this crate's
    /// (80, 24 and 64 bytes).
    SizesTooSmall {
        /// `struct seccomp_notif`.
        notif: u16,
        /// The reply struct.
        resp: u16,
        /// `struct seccomp_data`.
        data: u16,
    },
}

impl fmt::Display for NotifyGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const WHY: &str =
            "every sandbox's denied calls are answered by a supervisor in this process";
        match self {
            NotifyGap::Install { errno } if *errno == libc::EINVAL => write!(
                f,
                "a seccomp filter with a listener and the wait-killable receive cannot be installed: {} \
                 (SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV came with Linux 5.19, and boneli needs Linux 6.1 \
                 or newer; {WHY})",
                os(*errno)
            ),
            NotifyGap::Install { errno } if *errno == libc::EBUSY => write!(
                f,
                "a seccomp filter with a listener cannot be installed: {} (this process already runs \
                 under a seccomp filter with a listener, such as a container runtime's syscall \
                 interception, and a task can have only one; {WHY})",
                os(*errno)
            ),
            NotifyGap::Install { errno } => write!(
                f,
                "a seccomp filter with a listener cannot be installed: {} ({WHY})",
                os(*errno)
            ),
            NotifyGap::Action { errno } => write!(
                f,
                "seccomp cannot notify a supervisor (SECCOMP_RET_USER_NOTIF): {} (boneli needs Linux 6.1 or newer)",
                os(*errno)
            ),
            NotifyGap::SizesUnreadable { errno } => write!(
                f,
                "the kernel's seccomp notification sizes cannot be read (SECCOMP_GET_NOTIF_SIZES): {}",
                os(*errno)
            ),
            NotifyGap::SizesTooSmall { notif, resp, data } => write!(
                f,
                "the kernel's seccomp notification sizes {notif}/{resp}/{data} are below 80/24/64"
            ),
        }
    }
}

/// The sysctls that explain a failed user namespace; `None` when absent.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct UsernsSysctls {
    /// `kernel.apparmor_restrict_unprivileged_userns`
    pub apparmor_restrict: Option<u64>,
    /// `user.max_user_namespaces`
    pub max_user_namespaces: Option<u64>,
    /// `kernel.unprivileged_userns_clone` (Debian's patch)
    pub unprivileged_userns_clone: Option<u64>,
}

impl UsernsSysctls {
    fn read() -> UsernsSysctls {
        UsernsSysctls {
            apparmor_restrict: read_number(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            ),
            max_user_namespaces: read_number("/proc/sys/user/max_user_namespaces"),
            unprivileged_userns_clone: read_number("/proc/sys/kernel/unprivileged_userns_clone"),
        }
    }
}

fn read_number(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Names the cause of a failed user namespace from the errno and the
/// sysctls (pure, so every branch has a unit test). Under AppArmor's
/// restriction the namespace is created, but it holds no capability, so
/// opening `/proc/self/setgroups` fails with EACCES (measured on the
/// Ubuntu CI runners); a confined profile without `userns` fails the clone
/// with EPERM.
pub(crate) fn classify_userns(stage: &'static str, errno: i32, sysctls: &UsernsSysctls) -> Missing {
    if errno == libc::EPERM && sysctls.unprivileged_userns_clone == Some(0) {
        Missing::UsernsDisabled {
            sysctl: "kernel.unprivileged_userns_clone",
        }
    } else if errno == libc::ENOSPC && sysctls.max_user_namespaces == Some(0) {
        Missing::UsernsDisabled {
            sysctl: "user.max_user_namespaces",
        }
    } else if (errno == libc::EPERM || errno == libc::EACCES)
        && sysctls.apparmor_restrict == Some(1)
    {
        Missing::UsernsApparmor
    } else {
        Missing::UsernsOther {
            stage,
            detail: os(errno).to_string(),
        }
    }
}

/// The host check.
#[derive(Debug, Clone, Copy)]
pub struct Features;

impl Features {
    /// Tries every feature the runtime needs: a user namespace with the
    /// single id map writes (through `clone3`), `close_range` with
    /// `CLOSE_RANGE_CLOEXEC`, `SECCOMP_RET_KILL_PROCESS`, seccomp user
    /// notification with a listener and the wait-killable receive
    /// (ADR-043, D7), Landlock ABI 2 or
    /// newer, cgroup v2 at `/sys/fs/cgroup`, and delegation of the caller's
    /// own cgroup with the cpu, io, memory and pids controllers, the
    /// kernel keyrings (`keyctl`, `/proc/keys`, `/proc/key-users`), and the
    /// floor Linux 6.1 through the pids controller's `pids.peak` (ADR-044).
    /// Returns every missing feature with its cause. Without `clone3` the
    /// user namespace is not tried.
    pub fn probe() -> std::result::Result<(), Vec<Missing>> {
        let mut missing = Vec::new();
        missing.extend(probe_children(Fault::None, Fault::None, PROBE_TIMEOUT));
        missing.extend(probe_close_range());
        missing.extend(probe_seccomp());
        missing.extend(probe_seccomp_notify());
        missing.extend(probe_landlock());
        missing.extend(probe_keyrings());
        missing.extend(probe_cgroup());
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }

    /// [`Features::probe`] as an [`Error::HostUnsupported`].
    pub fn require() -> Result<()> {
        Features::probe().map_err(Error::HostUnsupported)
    }
}

/// Both probe children, each on its own so that one missing feature does
/// not hide another: the user namespace with the id maps, and the seccomp
/// filter (which needs no user namespace).
pub(crate) fn probe_children(
    ids_fault: Fault,
    filter_fault: Fault,
    timeout: std::time::Duration,
) -> Vec<Missing> {
    let mut missing = Vec::new();
    missing.extend(probe_ids_child(ids_fault, timeout));
    missing.extend(probe_filter_child(filter_fault, timeout));
    missing
}

/// How a probe child failed.
enum ProbeFailure {
    /// A step of the parent or a report from the child, with where.
    Error { stage: &'static str, error: Error },
    /// It ran to its end but did not exit 0.
    Exit(ExitStatus),
}

/// Runs one probe child to its end: `Ok` when it exited 0.
fn run_probe_child(
    action: Action<'_>,
    fault: Fault,
    timeout: std::time::Duration,
) -> std::result::Result<(), ProbeFailure> {
    // SAFETY: geteuid and getegid have no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    // SAFETY: as above.
    let egid = unsafe { libc::getegid() };
    let uid_line = format!("0 {euid} 1\n").into_bytes();
    let gid_line = format!("0 {egid} 1\n").into_bytes();
    let failed = |stage: &'static str| move |error: Error| ProbeFailure::Error { stage, error };
    let (read, write) = report_pipe().map_err(failed("pipe2"))?;
    let plan = ChildPlan {
        gid_line: &gid_line,
        uid_line: &uid_line,
        action,
        report_fd: write.as_raw_fd(),
        fault,
    };
    let launched = launch(&plan).map_err(failed("clone3"))?;
    drop(write);
    await_report(&read, &launched, timeout).map_err(failed("report"))?;
    let mut child = crate::spawn::Child::from_launched(launched);
    match child.wait().map_err(failed("waitid"))? {
        ExitStatus::Exited(0) => Ok(()),
        status => Err(ProbeFailure::Exit(status)),
    }
}

/// A `probe-failed`: the probe's own machinery broke, so it names neither
/// present nor missing (review of PR 1 and PR 2 of #6).
fn probe_failed(probe: &'static str, stage: &'static str, detail: String) -> Missing {
    Missing::ProbeFailed {
        probe,
        stage,
        detail,
    }
}

/// How a probe child that ran to its end but did not exit 0 is described:
/// the allocation guard's 97, another exit code, or a signal (an outside
/// kill, OOM, `pids.max`). None of these say anything about the feature.
fn exit_detail(status: ExitStatus) -> String {
    match status {
        ExitStatus::Exited(code) => format!("the probe child exited with code {code}"),
        ExitStatus::Signaled(sig) => format!("the probe child was killed by signal {sig}"),
    }
}

/// The user-namespace child: the single id map writes. Only a failed
/// `clone3` or a failed id-map step is a user-namespace signal; the probe's
/// own machinery breaking (a failed pipe, poll, read or wait, or a child
/// killed before it could report) is `probe-failed`, so a host near
/// `RLIMIT_NOFILE` is not told its user namespaces are broken (review of
/// PR 2 of #6).
pub(crate) fn probe_ids_child(fault: Fault, timeout: std::time::Duration) -> Option<Missing> {
    const PROBE: &str = "user-namespace";
    match run_probe_child(Action::ProbeIds, fault, timeout).err()? {
        ProbeFailure::Exit(status) => Some(probe_failed(PROBE, "exit", exit_detail(status))),
        ProbeFailure::Error { stage, error } => {
            Some(classify_ids_failure(stage, &error, &UsernsSysctls::read()))
        }
    }
}

/// Names what a failed user-namespace child says (pure, so every branch has
/// a unit test). `clone3` or an id-map step failing is a real signal about
/// user namespaces, classified from the errno and the sysctls; anything
/// else (a failed pipe, poll, read or wait, a malformed report) is the
/// probe's own machinery, which says nothing about the feature, so it is
/// `probe-failed` with its stage and cause (review of PR 2 of #6).
pub(crate) fn classify_ids_failure(
    stage: &'static str,
    error: &Error,
    sysctls: &UsernsSysctls,
) -> Missing {
    const PROBE: &str = "user-namespace";
    match error {
        Error::Sys { errno, .. } if stage == "clone3" && *errno == libc::ENOSYS => {
            Missing::Clone3 { errno: *errno }
        }
        // Only an errno that says something about user namespaces is a
        // user-namespace gap. A resource errno (EAGAIN from RLIMIT_NPROC or
        // the scope's pids.max, ENOMEM) is the probe's own machinery, like
        // the filter child's clone3 EAGAIN, so both children agree: it is
        // probe-failed, not a false host gap (review 3b).
        Error::Sys { errno, .. } if stage == "clone3" && is_userns_errno(*errno) => {
            classify_userns("clone3", *errno, sysctls)
        }
        Error::Sys { errno, .. } if stage == "clone3" => {
            probe_failed(PROBE, "clone3", os(*errno).to_string())
        }
        Error::Setup { step, errno, .. } => classify_userns(step.name(), *errno, sysctls),
        Error::Sys { call, errno } => probe_failed(PROBE, call, os(*errno).to_string()),
        other => probe_failed(PROBE, stage, other.to_string()),
    }
}

/// Whether a `clone3` errno says something about user namespaces rather
/// than about resources or the call itself: `EPERM` and `EACCES` (a
/// policy, AppArmor or a sysctl), `ENOSPC` (`user.max_user_namespaces`),
/// `EINVAL` (a rejected flag or map). `EAGAIN`, `ENOMEM` and the rest are
/// resource limits and are reported as `probe-failed` (review 3b).
fn is_userns_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::EPERM | libc::EACCES | libc::ENOSPC | libc::EINVAL
    )
}

/// The filter child: `PR_SET_NO_NEW_PRIVS` and an allow-all filter, without
/// a new user namespace. `SECCOMP_GET_ACTION_AVAIL` alone also succeeds on a
/// kernel with `CONFIG_SECCOMP` but without `CONFIG_SECCOMP_FILTER`.
pub(crate) fn probe_filter_child(fault: Fault, timeout: std::time::Duration) -> Option<Missing> {
    const PROBE: &str = "seccomp-filter";
    match run_probe_child(Action::ProbeFilter, fault, timeout).err()? {
        // A filter child that reached its end but did not exit 0 (the
        // allocation guard's 97, or a signal) proves nothing about filters.
        ProbeFailure::Exit(status) => Some(probe_failed(PROBE, "exit", exit_detail(status))),
        ProbeFailure::Error { stage, error } => classify_filter_failure(stage, &error),
    }
}

/// Names what a failed filter child says (pure, so every branch has a unit
/// test). Only a failure of the child's own filter step (`Step::Seccomp`)
/// is a missing filter; the hung-install timeout is still read as a missing
/// filter, because the install is what hung. Every other failure is the
/// probe's own machinery (a failed `clone3`, pipe, poll, read or wait, a
/// malformed report), which says nothing about seccomp, so it is
/// `probe-failed` with its stage and cause (review of PR 1 and PR 2 of #6).
pub(crate) fn classify_filter_failure(stage: &'static str, error: &Error) -> Option<Missing> {
    const PROBE: &str = "seccomp-filter";
    Some(match error {
        // Without clone3 the user-namespace child already says so.
        Error::Sys { errno, .. } if stage == "clone3" && *errno == libc::ENOSYS => return None,
        // Item 2, the filter with the notifying program's flags.
        Error::Setup {
            step: Step::Seccomp,
            index: 2,
            errno,
        } => Missing::SeccompNotify(NotifyGap::Install { errno: *errno }),
        Error::Setup {
            step: Step::Seccomp,
            errno,
            ..
        } => Missing::SeccompFilter { errno: *errno },
        // The install step hung: the filter itself is what did not finish.
        Error::SetupTimeout(_) => Missing::SeccompFilter {
            errno: libc::ETIMEDOUT,
        },
        Error::Sys { call, errno } => probe_failed(PROBE, call, os(*errno).to_string()),
        other => probe_failed(PROBE, stage, other.to_string()),
    })
}

fn probe_close_range() -> Option<Missing> {
    // An empty range far above any open descriptor: changes nothing, and
    // fails with EINVAL where the flag is unknown, ENOSYS without the call.
    // SAFETY: close_range takes plain integers.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            u32::MAX,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    (rc < 0).then(|| Missing::CloseRange { errno: errno() })
}

fn probe_seccomp() -> Option<Missing> {
    let action: u32 = libc::SECCOMP_RET_KILL_PROCESS;
    // SAFETY: SECCOMP_GET_ACTION_AVAIL reads one u32 through the pointer,
    // which is valid for the call's duration.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_ACTION_AVAIL,
            0u32,
            &action as *const u32,
        )
    };
    (rc < 0).then(|| Missing::SeccompKillProcess { errno: errno() })
}

/// `SECCOMP_RET_USER_NOTIF` and the kernel's notification sizes (ADR-043,
/// D7); the install with the notifying program's flags is item 2 of the
/// filter child.
fn probe_seccomp_notify() -> Option<Missing> {
    let action: u32 = libc::SECCOMP_RET_USER_NOTIF;
    // SAFETY: SECCOMP_GET_ACTION_AVAIL reads one u32 through the pointer,
    // which is valid for the call's duration.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_ACTION_AVAIL,
            0u32,
            &action as *const u32,
        )
    };
    let action = if rc < 0 { Err(errno()) } else { Ok(()) };
    classify_notify(action, crate::seccomp::notify::kernel_sizes())
}

/// Names what the notification probe found (pure, so every branch has a
/// unit test): the action's availability and the sizes the kernel reports.
pub(crate) fn classify_notify(
    action: std::result::Result<(), i32>,
    sizes: std::result::Result<libc::seccomp_notif_sizes, i32>,
) -> Option<Missing> {
    if let Err(errno) = action {
        return Some(Missing::SeccompNotify(NotifyGap::Action { errno }));
    }
    match sizes {
        Err(errno) => Some(Missing::SeccompNotify(NotifyGap::SizesUnreadable { errno })),
        Ok(s) => match crate::seccomp::Buffers::for_sizes(s) {
            Ok(_) => None,
            Err(Error::NotifySizes { notif, resp, data }) => {
                Some(Missing::SeccompNotify(NotifyGap::SizesTooSmall {
                    notif,
                    resp,
                    data,
                }))
            }
            Err(_) => Some(Missing::SeccompNotify(NotifyGap::SizesUnreadable {
                errno: libc::EINVAL,
            })),
        },
    }
}

fn probe_landlock() -> Option<Missing> {
    // SAFETY: with LANDLOCK_CREATE_RULESET_VERSION the attribute pointer
    // must be null and the size 0; the call returns the ABI version.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            ffi::LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        return Some(Missing::LandlockUnavailable { errno: errno() });
    }
    let found = rc as u32;
    (found < LANDLOCK_ABI_REQUIRED).then_some(Missing::LandlockAbi {
        found,
        required: LANDLOCK_ABI_REQUIRED,
    })
}

/// The keyrings the spawn needs (ADR-007, D3): `keyctl` with an operation
/// no kernel defines, which changes nothing and fails with EOPNOTSUPP where
/// keyrings exist (ENOSYS without `CONFIG_KEYS`, EPERM under a seccomp
/// profile that filters it, as the spawn's join would), and the two proc
/// files the sandbox covers.
fn probe_keyrings() -> Option<Missing> {
    const UNKNOWN_OPERATION: libc::c_long = i32::MAX as libc::c_long;
    // SAFETY: keyctl with an unknown operation reads no argument.
    let rc = unsafe { libc::syscall(libc::SYS_keyctl, UNKNOWN_OPERATION, 0, 0, 0, 0) };
    let keyctl = if rc < 0 { errno() } else { 0 };
    let stat = |path: &str| {
        std::fs::metadata(path)
            .err()
            .map(|e| e.raw_os_error().unwrap_or(libc::EIO))
    };
    classify_keyrings(keyctl, stat("/proc/keys"), stat("/proc/key-users"))
}

/// Names what the keyring probe found (pure, so every branch has a unit
/// test): the errno of the unknown `keyctl` operation (EOPNOTSUPP where
/// keyrings work) and of each proc file's `stat`, `None` when it exists.
pub(crate) fn classify_keyrings(
    keyctl: i32,
    keys: Option<i32>,
    key_users: Option<i32>,
) -> Option<Missing> {
    if keyctl != libc::EOPNOTSUPP {
        // A success would mean the kernel knows the operation: not the
        // kernel this probe was written for, so fail closed too.
        let errno = if keyctl == 0 { libc::EINVAL } else { keyctl };
        return Some(Missing::Keyrings {
            item: "keyctl",
            errno,
        });
    }
    if let Some(errno) = keys {
        return Some(Missing::Keyrings {
            item: "/proc/keys",
            errno,
        });
    }
    key_users.map(|errno| Missing::Keyrings {
        item: "/proc/key-users",
        errno,
    })
}

fn probe_cgroup() -> Vec<Missing> {
    // SAFETY: an all-zero statfs is valid storage for statfs to fill.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: the path is NUL-terminated and st is valid storage.
    let rc = unsafe { libc::statfs(c"/sys/fs/cgroup".as_ptr(), &mut st) };
    if rc < 0 || st.f_type as u64 != libc::CGROUP2_SUPER_MAGIC as u64 {
        return vec![Missing::Cgroup2Missing];
    }
    let mut missing = Vec::new();
    let nsdelegate = match std::fs::read("/proc/self/mountinfo") {
        Ok(text) => crate::cgroup::cgroup2_nsdelegate(&text),
        Err(e) => Err(format!("/proc/self/mountinfo unreadable: {e}")),
    };
    if let Err(options) = nsdelegate {
        missing.push(Missing::CgroupNsdelegate { options });
    }
    let dir = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| own_cgroup_dir(&text));
    let Some(dir) = dir else {
        missing.push(Missing::Cgroup2Missing);
        return missing;
    };
    missing.extend(probe_cgroup_dir(dir));
    missing
}

/// The checks on the caller's cgroup directory, in order: the kernel
/// floor, delegation, the controllers, and the floor's last word (a
/// function of the directory alone, so a test can run it on a temp dir).
fn probe_cgroup_dir(dir: String) -> Vec<Missing> {
    let mut missing = Vec::new();
    // Before the delegation check, so that a host that is not delegated
    // and also below 6.1 is told both (ADR-044, D3).
    let floor = kernel_floor(&dir);
    if let Floor::Gap(gap) = &floor {
        missing.push(gap.clone());
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    for file in [
        "",
        "/cgroup.procs",
        "/cgroup.threads",
        "/cgroup.subtree_control",
    ] {
        let path = format!("{dir}{file}");
        let writable = std::ffi::CString::new(path.clone()).is_ok_and(|c| {
            // SAFETY: c is NUL-terminated; access only checks permissions.
            unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
        });
        if !writable {
            // Not delegated: its controllers cannot be used either way.
            missing.push(Missing::CgroupNotDelegated {
                path: dir,
                file: path,
                uid,
            });
            return missing;
        }
    }
    let available =
        std::fs::read_to_string(format!("{dir}/cgroup.controllers")).unwrap_or_default();
    let available: Vec<&str> = available.split_whitespace().collect();
    missing.extend(
        CONTROLLERS
            .into_iter()
            .filter(|c| !available.contains(c))
            .map(|controller| Missing::CgroupControllerMissing {
                path: dir.clone(),
                controller,
            }),
    );
    missing.extend(floor_after_controllers(&floor, &available));
    missing
}

/// The caller's cgroup v2 directory from `/proc/self/cgroup` (pure, so
/// every form has a unit test): the `0::` line's path under
/// `/sys/fs/cgroup`, without a trailing `/`; `None` without that line.
pub(crate) fn own_cgroup_dir(text: &str) -> Option<String> {
    let own = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(format!("/sys/fs/cgroup{}", own.trim_end_matches('/')))
}

/// What the floor check found in the caller's cgroup (ADR-044, D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Floor {
    /// `pids.peak` holds what Linux 6.1 and newer write.
    Met,
    /// Neither file exists: the pids controller is not visible in this
    /// cgroup, so the controllers check decides
    /// ([`floor_after_controllers`]).
    Unseen,
    /// Below the floor, or the check could not run.
    Gap(Missing),
}

/// The floor check on a cgroup directory: `pids.max`'s `stat` and
/// `pids.peak`'s content. `pids.peak` is not read when the `stat` fails
/// with an errno other than ENOENT, which is reported as it is.
pub(crate) fn kernel_floor(dir: &str) -> Floor {
    let max = std::fs::metadata(format!("{dir}/pids.max")).map(|_| ());
    let peak = match &max {
        Err(e) if e.raw_os_error() != Some(libc::ENOENT) => Ok(Vec::new()),
        _ => std::fs::read(format!("{dir}/pids.peak")),
    };
    classify_kernel_floor(dir, max, peak)
}

/// How much of an unexpected `pids.peak` a message echoes.
const PEAK_ECHO: usize = 32;

/// Names what the floor check found (pure, so every branch has a unit
/// test), from `pids.max`'s `stat` and `pids.peak`'s content. Both files
/// are the pids controller's and `CFTYPE_NOT_ON_ROOT`, so they exist
/// together or not at all, from 6.1 on (`kernel/cgroup/pids.c:363` in 6.1,
/// commit 5251c6c436ed); before 6.1 only `pids.max` does. `Met` needs the
/// content the kernel writes, one s64 at or above 0 and a newline
/// (`read_s64`); anything else, and any errno but ENOENT, is
/// `probe-failed` naming the file, never `kernel-floor` and never `Met`.
pub(crate) fn classify_kernel_floor(
    path: &str,
    max: std::io::Result<()>,
    peak: std::io::Result<Vec<u8>>,
) -> Floor {
    const PROBE: &str = "kernel-floor";
    let absent = |e: &std::io::Error| e.raw_os_error() == Some(libc::ENOENT);
    match (max, peak) {
        (Err(e), _) if !absent(&e) => Floor::Gap(probe_failed(PROBE, "pids.max", e.to_string())),
        (Err(_), Err(e)) if absent(&e) => Floor::Unseen,
        (Err(_), Ok(_)) => Floor::Gap(probe_failed(
            PROBE,
            "pids.max",
            format!("{path}/pids.max is absent but {path}/pids.peak exists"),
        )),
        (Ok(()), Err(e)) if absent(&e) => Floor::Gap(Missing::KernelFloor { path: path.into() }),
        (_, Err(e)) => Floor::Gap(probe_failed(PROBE, "pids.peak", e.to_string())),
        (Ok(()), Ok(content)) if is_peak(&content) => Floor::Met,
        (Ok(()), Ok(content)) => {
            let head = content.get(..PEAK_ECHO).unwrap_or(&content);
            let mut detail = format!("unexpected content \"{}\"", head.escape_ascii());
            if content.len() > PEAK_ECHO {
                detail.push_str(&format!(" (first {PEAK_ECHO} of {} bytes)", content.len()));
            }
            Floor::Gap(probe_failed(PROBE, "pids.peak", detail))
        }
    }
}

/// Whether `content` is what `read_s64` writes for a value at or above 0:
/// 1 to 19 ASCII digits that fit an `i64`, then exactly one newline.
fn is_peak(content: &[u8]) -> bool {
    let Some(digits) = content.strip_suffix(b"\n") else {
        return false;
    };
    (1..=19).contains(&digits.len())
        && digits.iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(digits).is_ok_and(|d| d.parse::<i64>().is_ok())
}

/// The floor check's last word, after the controllers check: a cgroup
/// that lists `pids` in `cgroup.controllers` but had no `pids.max` fails
/// closed, so `Features::probe` returns `Ok` only after [`Floor::Met`].
/// Without `pids` listed, `cgroup-controller-missing` already reports it;
/// a [`Floor::Gap`] was pushed before the delegation check.
pub(crate) fn floor_after_controllers(floor: &Floor, available: &[&str]) -> Option<Missing> {
    (*floor == Floor::Unseen && available.contains(&"pids")).then(|| {
        probe_failed(
            "kernel-floor",
            "pids.max",
            "pids is in cgroup.controllers, pids.max is absent".into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: MissingId) -> Missing {
        match id {
            MissingId::UsernsApparmor => Missing::UsernsApparmor,
            MissingId::UsernsDisabled => Missing::UsernsDisabled {
                sysctl: "user.max_user_namespaces",
            },
            MissingId::UsernsOther => Missing::UsernsOther {
                stage: "uid-map",
                detail: "boom".into(),
            },
            MissingId::CgroupNotDelegated => Missing::CgroupNotDelegated {
                path: "/sys/fs/cgroup/a".into(),
                file: "/sys/fs/cgroup/a/cgroup.procs".into(),
                uid: 1001,
            },
            MissingId::CgroupControllerMissing => Missing::CgroupControllerMissing {
                path: "/sys/fs/cgroup/a".into(),
                controller: "io",
            },
            MissingId::Cgroup2Missing => Missing::Cgroup2Missing,
            MissingId::CgroupNsdelegate => Missing::CgroupNsdelegate {
                options: "rw,seclabel".into(),
            },
            MissingId::Clone3 => Missing::Clone3 {
                errno: libc::ENOSYS,
            },
            MissingId::CloseRange => Missing::CloseRange {
                errno: libc::EINVAL,
            },
            MissingId::SeccompKillProcess => Missing::SeccompKillProcess {
                errno: libc::EOPNOTSUPP,
            },
            MissingId::SeccompFilter => Missing::SeccompFilter {
                errno: libc::EINVAL,
            },
            MissingId::SeccompNotify => Missing::SeccompNotify(NotifyGap::Install {
                errno: libc::EINVAL,
            }),
            MissingId::LandlockUnavailable => Missing::LandlockUnavailable {
                errno: libc::EOPNOTSUPP,
            },
            MissingId::LandlockAbi => Missing::LandlockAbi {
                found: 1,
                required: 2,
            },
            MissingId::Keyrings => Missing::Keyrings {
                item: "keyctl",
                errno: libc::ENOSYS,
            },
            MissingId::KernelFloor => Missing::KernelFloor {
                path: "/sys/fs/cgroup/a".into(),
            },
            MissingId::ProbeFailed => Missing::ProbeFailed {
                probe: "seccomp-filter",
                stage: "clone3",
                detail: std::io::Error::from_raw_os_error(libc::EAGAIN).to_string(),
            },
        }
    }

    #[test]
    fn missing_feature_messages() {
        let e = |n| std::io::Error::from_raw_os_error(n).to_string();
        let want = [
            "user namespaces are restricted by AppArmor (kernel.apparmor_restrict_unprivileged_userns = 1); \
             this binary needs a profile that allows userns"
                .to_string(),
            "unprivileged user namespaces are disabled (user.max_user_namespaces = 0)".to_string(),
            "creating a user namespace failed at uid-map: boom".to_string(),
            "the cgroup /sys/fs/cgroup/a is not delegated to uid 1001: /sys/fs/cgroup/a/cgroup.procs is not writable".to_string(),
            "the cgroup /sys/fs/cgroup/a lacks the io controller (not in cgroup.controllers)".to_string(),
            "no cgroup v2 hierarchy is mounted at /sys/fs/cgroup".to_string(),
            "the cgroup v2 hierarchy at /sys/fs/cgroup is mounted without nsdelegate (rw,seclabel); \
             a sandbox could raise its own limits (remount with nsdelegate as root)"
                .to_string(),
            format!("clone3 is not available: {} (boneli needs Linux 6.1 or newer)", e(libc::ENOSYS)),
            format!("close_range with CLOSE_RANGE_CLOEXEC is not available: {} (boneli needs Linux 6.1 or newer)", e(libc::EINVAL)),
            format!(
                "seccomp cannot kill a whole process (SECCOMP_RET_KILL_PROCESS): {} (boneli needs Linux 6.1 or newer)",
                e(libc::EOPNOTSUPP)
            ),
            format!(
                "seccomp filters cannot be installed: {} (the kernel needs CONFIG_SECCOMP_FILTER)",
                e(libc::EINVAL)
            ),
            format!(
                "a seccomp filter with a listener and the wait-killable receive cannot be installed: {} \
                 (SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV came with Linux 5.19, and boneli needs Linux 6.1 \
                 or newer; every sandbox's denied calls are answered by a supervisor in this process)",
                e(libc::EINVAL)
            ),
            format!("Landlock is not available: {} (it must be built in and listed in the lsm= boot parameter)", e(libc::EOPNOTSUPP)),
            "Landlock ABI 1 found, 2 or newer required (ABI 2 came with Linux 5.19; boneli needs Linux 6.1 or newer)".to_string(),
            format!(
                "the kernel keyrings are not usable: keyctl: {} (every sandbox joins a new session keyring \
                 and hides /proc/keys; the kernel needs CONFIG_KEYS, and keyctl must not be filtered)",
                e(libc::ENOSYS)
            ),
            "this kernel is older than Linux 6.1, the oldest boneli supports: /sys/fs/cgroup/a/pids.max exists \
             but pids.peak (added in Linux 6.1) does not"
                .to_string(),
            format!(
                "the seccomp-filter probe could not run: clone3: {} (says nothing about seccomp-filter; retry once the cause is gone)",
                e(libc::EAGAIN)
            ),
        ];
        let names = [
            "userns-apparmor",
            "userns-disabled",
            "userns-other",
            "cgroup-not-delegated",
            "cgroup-controller-missing",
            "cgroup2-missing",
            "cgroup-nsdelegate",
            "clone3",
            "close-range",
            "seccomp-kill-process",
            "seccomp-filter",
            "seccomp-notify",
            "landlock-unavailable",
            "landlock-abi",
            "keyrings",
            "kernel-floor",
            "probe-failed",
        ];
        for (i, id) in MissingId::ALL.into_iter().enumerate() {
            let m = sample(id);
            assert_eq!(m.id(), id);
            assert_eq!(m.to_string(), want[i], "{id:?}");
            assert_eq!(id.as_str(), names[i]);
            assert_eq!(
                MissingId::from_name(id.as_str()),
                Some(id),
                "id -> name -> id"
            );
        }
        assert_eq!(MissingId::from_name("userns"), None);
        assert_eq!(MissingId::from_name(""), None);
        assert_eq!(
            MissingId::from_name("kernel-floor"),
            Some(MissingId::KernelFloor)
        );
        assert_eq!(MissingId::from_name("kernel_floor"), None);
        assert_eq!(MissingId::from_name("Kernel-Floor"), None);
        assert_eq!(MissingId::ALL.len(), 17);
    }

    #[test]
    fn userns_failure_classification() {
        let apparmor = UsernsSysctls {
            apparmor_restrict: Some(1),
            ..Default::default()
        };
        assert_eq!(
            classify_userns("setgroups", libc::EPERM, &apparmor),
            Missing::UsernsApparmor
        );
        assert_eq!(
            classify_userns("clone3", libc::EPERM, &apparmor),
            Missing::UsernsApparmor
        );
        // What the Ubuntu CI runners give: the setgroups open fails.
        assert_eq!(
            classify_userns("setgroups", libc::EACCES, &apparmor),
            Missing::UsernsApparmor
        );
        let no_apparmor = UsernsSysctls::default();
        assert_eq!(
            classify_userns("setgroups", libc::EACCES, &no_apparmor).id(),
            MissingId::UsernsOther
        );
        let none = UsernsSysctls::default();
        assert_eq!(
            classify_userns("setgroups", libc::EPERM, &none).id(),
            MissingId::UsernsOther
        );
        let off = UsernsSysctls {
            apparmor_restrict: Some(0),
            ..Default::default()
        };
        assert_eq!(
            classify_userns("setgroups", libc::EPERM, &off).id(),
            MissingId::UsernsOther
        );
        let zero = UsernsSysctls {
            max_user_namespaces: Some(0),
            ..Default::default()
        };
        assert_eq!(
            classify_userns("clone3", libc::ENOSPC, &zero),
            Missing::UsernsDisabled {
                sysctl: "user.max_user_namespaces"
            }
        );
        let some = UsernsSysctls {
            max_user_namespaces: Some(100),
            ..Default::default()
        };
        assert_eq!(
            classify_userns("clone3", libc::ENOSPC, &some).id(),
            MissingId::UsernsOther
        );
        let debian = UsernsSysctls {
            unprivileged_userns_clone: Some(0),
            apparmor_restrict: Some(1),
            ..Default::default()
        };
        assert_eq!(
            classify_userns("clone3", libc::EPERM, &debian),
            Missing::UsernsDisabled {
                sysctl: "kernel.unprivileged_userns_clone"
            }
        );
        // An errno no rule names stays "other", with the errno rendered.
        match classify_userns("uid-map", libc::EINVAL, &apparmor) {
            Missing::UsernsOther {
                stage: "uid-map",
                detail,
            } => {
                assert_eq!(
                    detail,
                    std::io::Error::from_raw_os_error(libc::EINVAL).to_string()
                )
            }
            other => panic!("{other:?}"),
        }
    }

    fn errno_detail(errno: i32) -> String {
        std::io::Error::from_raw_os_error(errno).to_string()
    }

    use crate::seccomp::notify::sizes as notif_sizes;

    #[test]
    fn probe_notify_classification() {
        let e = |n| std::io::Error::from_raw_os_error(n).to_string();
        // Item 2 of the filter child: the install with both flags.
        let install = |errno| {
            classify_filter_failure(
                "report",
                &Error::Setup {
                    step: Step::Seccomp,
                    index: 2,
                    errno,
                },
            )
        };
        let einval = install(libc::EINVAL).expect("a gap");
        assert_eq!(einval.id(), MissingId::SeccompNotify);
        assert!(
            einval.to_string().contains("came with Linux 5.19")
                && einval.to_string().contains("needs Linux 6.1 or newer"),
            "{einval}"
        );
        let ebusy = install(libc::EBUSY).expect("a gap");
        assert_eq!(
            ebusy,
            Missing::SeccompNotify(NotifyGap::Install { errno: libc::EBUSY })
        );
        assert!(
            ebusy
                .to_string()
                .contains("already runs under a seccomp filter with a listener"),
            "{ebusy}"
        );
        // Items 0 and 1 stay the filter itself.
        for index in [0, 1] {
            assert_eq!(
                classify_filter_failure(
                    "report",
                    &Error::Setup {
                        step: Step::Seccomp,
                        index,
                        errno: libc::EINVAL,
                    },
                ),
                Some(Missing::SeccompFilter {
                    errno: libc::EINVAL
                })
            );
        }
        // The action and the sizes.
        let ours = notif_sizes(80, 24, 64);
        assert_eq!(classify_notify(Ok(()), Ok(ours)), None);
        assert_eq!(
            classify_notify(Ok(()), Ok(notif_sizes(96, 32, 72))),
            None,
            "a newer kernel's larger structs"
        );
        assert_eq!(
            classify_notify(Err(libc::EOPNOTSUPP), Ok(ours)),
            Some(Missing::SeccompNotify(NotifyGap::Action {
                errno: libc::EOPNOTSUPP
            }))
        );
        assert_eq!(
            classify_notify(Ok(()), Err(libc::EINVAL)),
            Some(Missing::SeccompNotify(NotifyGap::SizesUnreadable {
                errno: libc::EINVAL
            }))
        );
        for (n, r, d) in [(79, 24, 64), (80, 23, 64), (80, 24, 63)] {
            let m = classify_notify(Ok(()), Ok(notif_sizes(n, r, d)));
            assert_eq!(
                m,
                Some(Missing::SeccompNotify(NotifyGap::SizesTooSmall {
                    notif: n,
                    resp: r,
                    data: d
                }))
            );
            assert_eq!(m.expect("a gap").id().as_str(), "seccomp-notify");
        }
        assert_eq!(
            NotifyGap::SizesTooSmall {
                notif: 79,
                resp: 24,
                data: 64
            }
            .to_string(),
            "the kernel's seccomp notification sizes 79/24/64 are below 80/24/64"
        );
        assert!(
            NotifyGap::Action {
                errno: libc::EOPNOTSUPP
            }
            .to_string()
            .contains(&e(libc::EOPNOTSUPP))
        );
        assert!(
            NotifyGap::Action {
                errno: libc::EOPNOTSUPP
            }
            .to_string()
            .ends_with("(boneli needs Linux 6.1 or newer)")
        );
    }

    #[test]
    fn filter_failure_classification() {
        // A clone3 that fails for a resource limit is not a missing filter:
        // the real call and cause are reported.
        for errno in [libc::EAGAIN, libc::ENOMEM, libc::EPERM] {
            assert_eq!(
                classify_filter_failure(
                    "clone3",
                    &Error::Sys {
                        call: "clone3",
                        errno
                    }
                ),
                Some(Missing::ProbeFailed {
                    probe: "seccomp-filter",
                    stage: "clone3",
                    detail: errno_detail(errno),
                }),
                "clone3 errno {errno}"
            );
        }
        assert_eq!(
            classify_filter_failure(
                "pipe2",
                &Error::Sys {
                    call: "pipe2",
                    errno: libc::EMFILE
                }
            ),
            Some(Missing::ProbeFailed {
                probe: "seccomp-filter",
                stage: "pipe2",
                detail: errno_detail(libc::EMFILE),
            })
        );
        // A malformed report (Protocol) is the probe's machinery, not a
        // missing filter.
        let proto = Error::Protocol(crate::error::ProtocolError::Length(3));
        assert_eq!(
            classify_filter_failure("report", &proto),
            Some(Missing::ProbeFailed {
                probe: "seccomp-filter",
                stage: "report",
                detail: proto.to_string(),
            })
        );
        // Without clone3 the id child reports it; the filter child adds
        // nothing.
        assert_eq!(
            classify_filter_failure(
                "clone3",
                &Error::Sys {
                    call: "clone3",
                    errno: libc::ENOSYS
                }
            ),
            None
        );
        // The child's own filter step is what a missing filter looks like.
        assert_eq!(
            classify_filter_failure(
                "report",
                &Error::Setup {
                    step: Step::Seccomp,
                    index: 1,
                    errno: libc::EINVAL
                }
            ),
            Some(Missing::SeccompFilter {
                errno: libc::EINVAL
            })
        );
        // The install hung: still a missing filter, because the install is
        // what did not finish.
        assert_eq!(
            classify_filter_failure("report", &Error::SetupTimeout(Duration::from_secs(1))),
            Some(Missing::SeccompFilter {
                errno: libc::ETIMEDOUT
            })
        );
    }

    #[test]
    fn exit_status_is_probe_failed_not_a_feature() {
        // A probe child killed by a signal or ending with the allocation
        // guard's 97 says nothing about its feature; both children report
        // probe-failed, never a host gap (review of PR 2 of #6).
        assert_eq!(
            exit_detail(ExitStatus::Signaled(libc::SIGKILL)),
            "the probe child was killed by signal 9"
        );
        assert_eq!(
            exit_detail(ExitStatus::Exited(crate::test_guard::EXIT_ALLOCATED)),
            "the probe child exited with code 97"
        );
    }

    #[test]
    fn keyrings_classification() {
        let none = |k, a, b| classify_keyrings(k, a, b);
        assert_eq!(none(libc::EOPNOTSUPP, None, None), None);
        // No CONFIG_KEYS: the call is not there, and neither are the files.
        let no_keys = Some(Missing::Keyrings {
            item: "keyctl",
            errno: libc::ENOSYS,
        });
        assert_eq!(
            none(libc::ENOSYS, Some(libc::ENOENT), Some(libc::ENOENT)),
            no_keys
        );
        // keyctl filtered by the runner's own seccomp profile.
        assert_eq!(
            none(libc::EPERM, None, None),
            Some(Missing::Keyrings {
                item: "keyctl",
                errno: libc::EPERM
            })
        );
        // An operation the kernel knows after all: fail closed.
        assert_eq!(
            none(0, None, None),
            Some(Missing::Keyrings {
                item: "keyctl",
                errno: libc::EINVAL
            })
        );
        // Each file on its own.
        assert_eq!(
            none(libc::EOPNOTSUPP, Some(libc::ENOENT), None),
            Some(Missing::Keyrings {
                item: "/proc/keys",
                errno: libc::ENOENT
            })
        );
        assert_eq!(
            none(libc::EOPNOTSUPP, None, Some(libc::EACCES)),
            Some(Missing::Keyrings {
                item: "/proc/key-users",
                errno: libc::EACCES
            })
        );
        // This host has keyrings (the host tests need them anyway).
        assert_eq!(probe_keyrings(), None);
    }

    #[test]
    fn ids_failure_classification() {
        let none = UsernsSysctls::default();
        // clone3 ENOSYS is "no clone3"; another clone3 errno is a real
        // user-namespace signal classified from the sysctls.
        assert_eq!(
            classify_ids_failure(
                "clone3",
                &Error::Sys {
                    call: "clone3",
                    errno: libc::ENOSYS
                },
                &none
            ),
            Missing::Clone3 {
                errno: libc::ENOSYS
            }
        );
        let apparmor = UsernsSysctls {
            apparmor_restrict: Some(1),
            ..Default::default()
        };
        assert_eq!(
            classify_ids_failure(
                "clone3",
                &Error::Sys {
                    call: "clone3",
                    errno: libc::EPERM
                },
                &apparmor
            ),
            Missing::UsernsApparmor
        );
        // A failed id-map step is a real signal too.
        assert_eq!(
            classify_ids_failure(
                "report",
                &Error::Setup {
                    step: Step::SetGroups,
                    index: 0,
                    errno: libc::EACCES
                },
                &apparmor
            ),
            Missing::UsernsApparmor
        );
        // The probe's own machinery (a Sys error at pipe2/waitid, or a
        // malformed report) is probe-failed, not a user-namespace gap: a
        // host near RLIMIT_NOFILE is not told its user namespaces fail.
        assert_eq!(
            classify_ids_failure(
                "pipe2",
                &Error::Sys {
                    call: "pipe2",
                    errno: libc::EMFILE
                },
                &none
            ),
            Missing::ProbeFailed {
                probe: "user-namespace",
                stage: "pipe2",
                detail: errno_detail(libc::EMFILE),
            }
        );
        let proto = Error::Protocol(crate::error::ProtocolError::Length(7));
        assert_eq!(
            classify_ids_failure("report", &proto, &none),
            Missing::ProbeFailed {
                probe: "user-namespace",
                stage: "report",
                detail: proto.to_string(),
            }
        );
        // A clone3 resource errno (RLIMIT_NPROC, pids.max) is probe-failed,
        // not a user-namespace gap, so it matches the filter child, which
        // reports the same errno as probe-failed (review 3b).
        for errno in [libc::EAGAIN, libc::ENOMEM] {
            assert_eq!(
                classify_ids_failure(
                    "clone3",
                    &Error::Sys {
                        call: "clone3",
                        errno
                    },
                    &apparmor
                ),
                Missing::ProbeFailed {
                    probe: "user-namespace",
                    stage: "clone3",
                    detail: errno_detail(errno),
                },
                "clone3 resource errno {errno} must be probe-failed even under AppArmor"
            );
        }
        // An errno that does say something about user namespaces stays a
        // user-namespace gap, never probe-failed. EPERM/EACCES under the
        // AppArmor sysctl are specifically that cause.
        for errno in [libc::EPERM, libc::EACCES] {
            assert_eq!(
                classify_ids_failure(
                    "clone3",
                    &Error::Sys {
                        call: "clone3",
                        errno
                    },
                    &apparmor
                ),
                Missing::UsernsApparmor,
                "clone3 errno {errno} under AppArmor"
            );
        }
        for errno in [libc::ENOSPC, libc::EINVAL] {
            assert_ne!(
                classify_ids_failure(
                    "clone3",
                    &Error::Sys {
                        call: "clone3",
                        errno
                    },
                    &none
                )
                .id(),
                MissingId::ProbeFailed,
                "clone3 errno {errno} is a user-namespace gap, not probe-failed"
            );
        }
    }

    fn io(errno: i32) -> std::io::Error {
        std::io::Error::from_raw_os_error(errno)
    }

    fn floor_failed(stage: &'static str, detail: String) -> Floor {
        Floor::Gap(Missing::ProbeFailed {
            probe: "kernel-floor",
            stage,
            detail,
        })
    }

    #[test]
    fn kernel_floor_classification() {
        const DIR: &str = "/sys/fs/cgroup/a";
        let peak = |content: &[u8]| classify_kernel_floor(DIR, Ok(()), Ok(content.to_vec()));
        // Linux 6.1 and newer: pids.peak is one s64 at or above 0 and a
        // newline (`read_s64`, `kernel/cgroup/pids.c:363` in 6.1).
        for ok in [&b"0\n"[..], b"7\n", b"9223372036854775807\n"] {
            assert_eq!(peak(ok), Floor::Met, "{:?}", ok.escape_ascii().to_string());
        }
        // 5.19.x and 6.0.x: the controller's files are there, pids.peak is not.
        assert_eq!(
            classify_kernel_floor(DIR, Ok(()), Err(io(libc::ENOENT))),
            Floor::Gap(Missing::KernelFloor { path: DIR.into() })
        );
        // The pids controller is not visible in this cgroup: nothing to say
        // about the kernel yet (the controllers check decides).
        assert_eq!(
            classify_kernel_floor(DIR, Err(io(libc::ENOENT)), Err(io(libc::ENOENT))),
            Floor::Unseen
        );
        // pids.peak without pids.max: no kernel has that, so fail closed.
        assert_eq!(
            classify_kernel_floor(DIR, Err(io(libc::ENOENT)), Ok(b"7\n".to_vec())),
            floor_failed(
                "pids.max",
                format!("{DIR}/pids.max is absent but {DIR}/pids.peak exists")
            )
        );
        // Any other errno names the file it came from, never kernel-floor.
        for errno in [libc::EACCES, libc::ENOTDIR, libc::EIO] {
            assert_eq!(
                classify_kernel_floor(DIR, Err(io(errno)), Err(io(libc::ENOENT))),
                floor_failed("pids.max", io(errno).to_string()),
                "pids.max errno {errno}"
            );
            assert_eq!(
                classify_kernel_floor(DIR, Err(io(errno)), Ok(b"7\n".to_vec())),
                floor_failed("pids.max", io(errno).to_string()),
                "pids.max errno {errno}, pids.peak not read"
            );
            assert_eq!(
                classify_kernel_floor(DIR, Ok(()), Err(io(errno))),
                floor_failed("pids.peak", io(errno).to_string()),
                "pids.peak errno {errno}"
            );
            assert_eq!(
                classify_kernel_floor(DIR, Err(io(libc::ENOENT)), Err(io(errno))),
                floor_failed("pids.peak", io(errno).to_string()),
                "pids.max absent, pids.peak errno {errno}"
            );
        }
        // Content that is not what the kernel writes is probe-failed: not
        // Met, and not kernel-floor either.
        let twenty = b"12345678901234567890\n";
        let over = b"9223372036854775808\n";
        for bad in [
            &b""[..],
            b"7",
            b"7\n\n",
            b" 7\n",
            b"+7\n",
            b"-1\n",
            b"max\n",
            "\u{0663}\n".as_bytes(),
            "7\u{200b}\n".as_bytes(),
            twenty,
            over,
        ] {
            assert_eq!(
                peak(bad),
                floor_failed(
                    "pids.peak",
                    format!("unexpected content \"{}\"", bad.escape_ascii())
                ),
                "{:?}",
                bad.escape_ascii().to_string()
            );
        }
        // The echo is capped at 32 bytes.
        let long = [b'x'; 100];
        match peak(&long) {
            Floor::Gap(Missing::ProbeFailed { detail, .. }) => assert_eq!(
                detail,
                format!(
                    "unexpected content \"{}\" (first 32 of 100 bytes)",
                    "x".repeat(32)
                )
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn kernel_floor_after_controllers() {
        let pids = ["cpu", "io", "memory", "pids"];
        let no_pids = ["cpu", "io", "memory"];
        // pids is listed but pids.max was absent: fail closed, never Ok.
        assert_eq!(
            floor_after_controllers(&Floor::Unseen, &pids),
            Some(Missing::ProbeFailed {
                probe: "kernel-floor",
                stage: "pids.max",
                detail: "pids is in cgroup.controllers, pids.max is absent".into(),
            })
        );
        // pids is not listed: cgroup-controller-missing (pids) says it.
        assert_eq!(floor_after_controllers(&Floor::Unseen, &no_pids), None);
        assert_eq!(floor_after_controllers(&Floor::Unseen, &[]), None);
        // Met adds nothing; a gap was pushed before the delegation check.
        assert_eq!(floor_after_controllers(&Floor::Met, &pids), None);
        let gap = Floor::Gap(Missing::KernelFloor {
            path: "/sys/fs/cgroup/a".into(),
        });
        assert_eq!(floor_after_controllers(&gap, &pids), None);
        assert_eq!(floor_after_controllers(&gap, &no_pids), None);
    }

    #[test]
    fn own_cgroup_dir_forms() {
        assert_eq!(own_cgroup_dir("0::/\n").as_deref(), Some("/sys/fs/cgroup"));
        assert_eq!(
            own_cgroup_dir("0::/user.slice/a\n").as_deref(),
            Some("/sys/fs/cgroup/user.slice/a")
        );
        assert_eq!(
            own_cgroup_dir("0::/a/\n").as_deref(),
            Some("/sys/fs/cgroup/a")
        );
        assert_eq!(
            own_cgroup_dir("1:name=systemd:/\n0::/b\n").as_deref(),
            Some("/sys/fs/cgroup/b")
        );
        assert_eq!(own_cgroup_dir("1:name=systemd:/\n"), None);
        assert_eq!(own_cgroup_dir(""), None);
    }

    /// A directory removed on drop, standing in for a cgroup directory.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> TempDir {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("boneli-host-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir(&p).expect("create a temp dir");
            TempDir(p)
        }

        fn path(&self) -> &str {
            self.0.to_str().expect("a UTF-8 temp dir")
        }

        fn write(&self, name: &str, content: &[u8]) {
            std::fs::write(self.0.join(name), content).expect("write a file");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn kernel_floor_reads_a_cgroup_directory() {
        // Regular files stand in for cgroupfs: what matters is which of the
        // two exists and what pids.peak holds.
        let met = TempDir::new("met");
        met.write("pids.max", b"max\n");
        met.write("pids.peak", b"3\n");
        assert_eq!(kernel_floor(met.path()), Floor::Met);

        let old = TempDir::new("old");
        old.write("pids.max", b"max\n");
        assert_eq!(
            kernel_floor(old.path()),
            Floor::Gap(Missing::KernelFloor {
                path: old.path().into()
            })
        );
        assert!(
            Missing::KernelFloor {
                path: old.path().into()
            }
            .to_string()
            .ends_with(&format!(
                "{}/pids.max exists but pids.peak (added in Linux 6.1) does not",
                old.path()
            ))
        );

        let unseen = TempDir::new("unseen");
        assert_eq!(kernel_floor(unseen.path()), Floor::Unseen);

        // pids.peak unreadable (a directory here): probe-failed naming it.
        let unreadable = TempDir::new("unreadable");
        unreadable.write("pids.max", b"max\n");
        std::fs::create_dir(unreadable.0.join("pids.peak")).expect("mkdir");
        assert_eq!(
            kernel_floor(unreadable.path()),
            floor_failed("pids.peak", io(libc::EISDIR).to_string())
        );

        // The cgroup path is not a directory: pids.max gives ENOTDIR.
        let file = TempDir::new("file");
        file.write("cg", b"");
        let not_dir = format!("{}/cg", file.path());
        assert_eq!(
            kernel_floor(&not_dir),
            floor_failed("pids.max", io(libc::ENOTDIR).to_string())
        );
    }

    /// A temp dir laid out as a delegated cgroup: the three files the
    /// delegation check needs, writable, and `cgroup.controllers`.
    fn delegated(tag: &str, controllers: &str) -> TempDir {
        let dir = TempDir::new(tag);
        for file in ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"] {
            dir.write(file, b"");
        }
        dir.write("cgroup.controllers", controllers.as_bytes());
        dir
    }

    #[test]
    fn probe_cgroup_dir_wires_the_floor_check() {
        use std::os::unix::fs::PermissionsExt;
        let all = "cpu io memory pids\n";
        let floor = |dir: &TempDir| Missing::KernelFloor {
            path: dir.path().into(),
        };

        // Below 6.1 and not delegated: both, the floor first (ADR-044 D3).
        // Mode 0444 makes access(W_OK) fail for the non-root test user.
        let old = delegated("dir-old-undelegated", all);
        old.write("pids.max", b"max\n");
        let procs = old.0.join("cgroup.procs");
        std::fs::set_permissions(&procs, std::fs::Permissions::from_mode(0o444))
            .expect("chmod cgroup.procs");
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            probe_cgroup_dir(old.path().into()),
            vec![
                floor(&old),
                Missing::CgroupNotDelegated {
                    path: old.path().into(),
                    file: format!("{}/cgroup.procs", old.path()),
                    uid,
                },
            ]
        );

        // Below 6.1 and delegated with every controller: the floor alone.
        let old = delegated("dir-old", all);
        old.write("pids.max", b"max\n");
        assert_eq!(probe_cgroup_dir(old.path().into()), vec![floor(&old)]);

        // Neither pids file, but pids listed: fail closed, never Ok.
        let unseen = delegated("dir-unseen", all);
        assert_eq!(
            probe_cgroup_dir(unseen.path().into()),
            vec![Missing::ProbeFailed {
                probe: "kernel-floor",
                stage: "pids.max",
                detail: "pids is in cgroup.controllers, pids.max is absent".into(),
            }]
        );

        // Neither pids file and pids not listed: the controllers check says it.
        let unlisted = delegated("dir-unlisted", "cpu io memory\n");
        assert_eq!(
            probe_cgroup_dir(unlisted.path().into()),
            vec![Missing::CgroupControllerMissing {
                path: unlisted.path().into(),
                controller: "pids",
            }]
        );

        // Met, delegated, every controller: nothing missing.
        let met = delegated("dir-met", all);
        met.write("pids.max", b"max\n");
        met.write("pids.peak", b"3\n");
        assert_eq!(probe_cgroup_dir(met.path().into()), Vec::new());
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces, seccomp filters"]
    fn probe_child_killed_is_probe_failed() {
        let _host = crate::test_guard::host_lock();
        // A probe child that allocates is ended by the allocation guard
        // (exit 97) before it can report. Neither child may then name its
        // feature; both report probe-failed at the exit stage.
        for missing in [
            probe_ids_child(
                Fault::Allocate(Step::UidMap),
                std::time::Duration::from_secs(10),
            ),
            probe_filter_child(
                Fault::Allocate(Step::Seccomp),
                std::time::Duration::from_secs(10),
            ),
        ] {
            match missing {
                Some(Missing::ProbeFailed { stage, detail, .. }) => {
                    assert_eq!(stage, "exit");
                    assert!(detail.contains("97"), "detail: {detail}");
                }
                other => panic!("expected probe-failed, got {other:?}"),
            }
        }
    }

    #[test]
    #[ignore = "host: seccomp filters"]
    fn probe_filter_child_installs_a_filter() {
        let _host = crate::test_guard::host_lock();
        // The filter child hangs right after its install; its status must
        // then show filter mode (2), not only that the kernel knows the
        // action values (SECCOMP_GET_ACTION_AVAIL).
        let worker = std::thread::spawn(|| {
            probe_filter_child(
                Fault::Hang(Step::Seccomp),
                std::time::Duration::from_millis(1500),
            )
        });
        let child = crate::test_guard::wait_for_child(std::time::Duration::from_secs(5));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut mode = String::new();
        while std::time::Instant::now() < deadline {
            let status =
                std::fs::read_to_string(format!("/proc/{child}/status")).unwrap_or_default();
            mode = status
                .lines()
                .find_map(|l| l.strip_prefix("Seccomp:"))
                .map(|v| v.trim().to_string())
                .unwrap_or_default();
            if mode == "2" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let result = worker.join().expect("probe thread");
        assert_eq!(mode, "2", "the filter child's seccomp mode");
        assert_eq!(
            result,
            Some(Missing::SeccompFilter {
                errno: libc::ETIMEDOUT
            }),
            "the hung child timed out"
        );
    }

    #[test]
    #[ignore = "host: seccomp filters"]
    fn probe_filter_child_reports_failure() {
        let _host = crate::test_guard::host_lock();
        let result = probe_filter_child(
            Fault::Fail(Step::Seccomp),
            std::time::Duration::from_secs(10),
        );
        assert_eq!(result, Some(Missing::SeccompFilter { errno: libc::EIO }));
    }

    #[test]
    #[ignore = "host: unprivileged user namespaces, seccomp filters"]
    fn filter_failure_does_not_hide_userns_failure() {
        let _host = crate::test_guard::host_lock();
        // A host lacking both reports both (the exact missing set).
        let missing = probe_children(
            Fault::Fail(Step::SetGroups),
            Fault::Fail(Step::Seccomp),
            std::time::Duration::from_secs(10),
        );
        let ids: Vec<MissingId> = missing.iter().map(Missing::id).collect();
        assert_eq!(
            ids,
            [MissingId::UsernsOther, MissingId::SeccompFilter],
            "{missing:?}"
        );
        assert!(
            matches!(
                missing[0],
                Missing::UsernsOther {
                    stage: "setgroups",
                    ..
                }
            ),
            "{missing:?}"
        );
        assert_eq!(missing[1], Missing::SeccompFilter { errno: libc::EIO });
        // And neither probe reports anything when nothing fails.
        assert_eq!(
            probe_children(Fault::None, Fault::None, std::time::Duration::from_secs(10)),
            []
        );
    }
}
