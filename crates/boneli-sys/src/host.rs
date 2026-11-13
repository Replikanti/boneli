//! What the host must provide (ADR-007, D3 and D5), checked by trying each
//! feature instead of reading the kernel version: distributions backport.

use std::fmt;
use std::os::fd::AsRawFd;
use std::time::Duration;

use crate::child::{ChildPlan, Fault};
use crate::error::{Error, Result, errno};
use crate::ffi;
use crate::spawn::{ExitStatus, await_report, launch, report_pipe};

/// The oldest Landlock ABI the runtime accepts: under ABI 1 every rename or
/// link into another directory is denied, which git and npm do (ADR-007, D3).
pub const LANDLOCK_ABI_REQUIRED: u32 = 2;

/// Hang bound of the probe's user-namespace child, which only writes three
/// `/proc` files and exits: it takes milliseconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The controllers every sandbox cgroup is limited by (ADR-007).
const CONTROLLERS: [&str; 4] = ["cpu", "io", "memory", "pids"];

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
    /// `clone3`
    Clone3,
    /// `close-range`
    CloseRange,
    /// `seccomp-kill-process`
    SeccompKillProcess,
    /// `landlock-unavailable`
    LandlockUnavailable,
    /// `landlock-abi`
    LandlockAbi,
}

impl MissingId {
    /// Every id.
    pub const ALL: [MissingId; 11] = [
        MissingId::UsernsApparmor,
        MissingId::UsernsDisabled,
        MissingId::UsernsOther,
        MissingId::CgroupNotDelegated,
        MissingId::CgroupControllerMissing,
        MissingId::Cgroup2Missing,
        MissingId::Clone3,
        MissingId::CloseRange,
        MissingId::SeccompKillProcess,
        MissingId::LandlockUnavailable,
        MissingId::LandlockAbi,
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
            MissingId::Clone3 => "clone3",
            MissingId::CloseRange => "close-range",
            MissingId::SeccompKillProcess => "seccomp-kill-process",
            MissingId::LandlockUnavailable => "landlock-unavailable",
            MissingId::LandlockAbi => "landlock-abi",
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
            Missing::Clone3 { .. } => MissingId::Clone3,
            Missing::CloseRange { .. } => MissingId::CloseRange,
            Missing::SeccompKillProcess { .. } => MissingId::SeccompKillProcess,
            Missing::LandlockUnavailable { .. } => MissingId::LandlockUnavailable,
            Missing::LandlockAbi { .. } => MissingId::LandlockAbi,
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
            Missing::Clone3 { errno } => write!(
                f,
                "clone3 is not available: {} (boneli needs Linux 5.19 or newer)",
                os(*errno)
            ),
            Missing::CloseRange { errno } => {
                write!(
                    f,
                    "close_range with CLOSE_RANGE_CLOEXEC is not available: {} (boneli needs Linux 5.19 or newer)",
                    os(*errno)
                )
            }
            Missing::SeccompKillProcess { errno } => write!(
                f,
                "seccomp cannot kill a whole process (SECCOMP_RET_KILL_PROCESS): {} (boneli needs Linux 5.19 or newer)",
                os(*errno)
            ),
            Missing::LandlockUnavailable { errno } => write!(
                f,
                "Landlock is not available: {} (it must be built in and listed in the lsm= boot parameter)",
                os(*errno)
            ),
            Missing::LandlockAbi { found, required } => {
                write!(
                    f,
                    "Landlock ABI {found} found, {required} or newer required (Linux 5.19)"
                )
            }
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
    /// `CLOSE_RANGE_CLOEXEC`, `SECCOMP_RET_KILL_PROCESS`, Landlock ABI 2 or
    /// newer, cgroup v2 at `/sys/fs/cgroup`, and delegation of the caller's
    /// own cgroup with the cpu, io, memory and pids controllers. Returns
    /// every missing feature with its cause. Without `clone3` the user
    /// namespace is not tried.
    pub fn probe() -> std::result::Result<(), Vec<Missing>> {
        let mut missing = Vec::new();
        if let Some(m) = probe_userns() {
            missing.push(m);
        }
        missing.extend(probe_close_range());
        missing.extend(probe_seccomp());
        missing.extend(probe_landlock());
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

fn probe_userns() -> Option<Missing> {
    // SAFETY: geteuid and getegid have no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    // SAFETY: as above.
    let egid = unsafe { libc::getegid() };
    let uid_line = format!("0 {euid} 1\n").into_bytes();
    let gid_line = format!("0 {egid} 1\n").into_bytes();
    let other = |stage: &'static str, e: &Error| Missing::UsernsOther {
        stage,
        detail: e.to_string(),
    };
    let (read, write) = match report_pipe() {
        Ok(p) => p,
        Err(e) => return Some(other("pipe2", &e)),
    };
    let plan = ChildPlan {
        gid_line: &gid_line,
        uid_line: &uid_line,
        exec: None,
        report_fd: write.as_raw_fd(),
        fault: Fault::None,
    };
    let launched = match launch(&plan) {
        Ok(l) => l,
        Err(Error::Sys { errno, .. }) if errno == libc::ENOSYS => {
            return Some(Missing::Clone3 { errno });
        }
        Err(Error::Sys { errno, .. }) => {
            return Some(classify_userns("clone3", errno, &UsernsSysctls::read()));
        }
        Err(e) => return Some(other("clone3", &e)),
    };
    drop(write);
    match await_report(&read, &launched, PROBE_TIMEOUT) {
        Ok(()) => {
            let mut child = crate::spawn::Child::from_launched(launched);
            match child.wait() {
                Ok(ExitStatus::Exited(0)) => None,
                Ok(status) => Some(Missing::UsernsOther {
                    stage: "exit",
                    detail: format!("the probe child ended with {status:?}"),
                }),
                Err(e) => Some(other("waitid", &e)),
            }
        }
        Err(Error::Setup { step, errno, .. }) => {
            Some(classify_userns(step.name(), errno, &UsernsSysctls::read()))
        }
        Err(e) => Some(other("report", &e)),
    }
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

fn probe_cgroup() -> Vec<Missing> {
    // SAFETY: an all-zero statfs is valid storage for statfs to fill.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: the path is NUL-terminated and st is valid storage.
    let rc = unsafe { libc::statfs(c"/sys/fs/cgroup".as_ptr(), &mut st) };
    if rc < 0 || st.f_type as u64 != libc::CGROUP2_SUPER_MAGIC as u64 {
        return vec![Missing::Cgroup2Missing];
    }
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|l| l.strip_prefix("0::").map(str::to_string))
        });
    let Some(own) = own else {
        return vec![Missing::Cgroup2Missing];
    };
    let dir = format!("/sys/fs/cgroup{}", own.trim_end_matches('/'));
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
            return vec![Missing::CgroupNotDelegated {
                path: dir,
                file: path,
                uid,
            }];
        }
    }
    let available =
        std::fs::read_to_string(format!("{dir}/cgroup.controllers")).unwrap_or_default();
    let available: Vec<&str> = available.split_whitespace().collect();
    CONTROLLERS
        .into_iter()
        .filter(|c| !available.contains(c))
        .map(|controller| Missing::CgroupControllerMissing {
            path: dir.clone(),
            controller,
        })
        .collect()
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
            MissingId::Clone3 => Missing::Clone3 {
                errno: libc::ENOSYS,
            },
            MissingId::CloseRange => Missing::CloseRange {
                errno: libc::EINVAL,
            },
            MissingId::SeccompKillProcess => Missing::SeccompKillProcess {
                errno: libc::EOPNOTSUPP,
            },
            MissingId::LandlockUnavailable => Missing::LandlockUnavailable {
                errno: libc::EOPNOTSUPP,
            },
            MissingId::LandlockAbi => Missing::LandlockAbi {
                found: 1,
                required: 2,
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
            format!("clone3 is not available: {} (boneli needs Linux 5.19 or newer)", e(libc::ENOSYS)),
            format!("close_range with CLOSE_RANGE_CLOEXEC is not available: {} (boneli needs Linux 5.19 or newer)", e(libc::EINVAL)),
            format!(
                "seccomp cannot kill a whole process (SECCOMP_RET_KILL_PROCESS): {} (boneli needs Linux 5.19 or newer)",
                e(libc::EOPNOTSUPP)
            ),
            format!("Landlock is not available: {} (it must be built in and listed in the lsm= boot parameter)", e(libc::EOPNOTSUPP)),
            "Landlock ABI 1 found, 2 or newer required (Linux 5.19)".to_string(),
        ];
        let names = [
            "userns-apparmor",
            "userns-disabled",
            "userns-other",
            "cgroup-not-delegated",
            "cgroup-controller-missing",
            "cgroup2-missing",
            "clone3",
            "close-range",
            "seccomp-kill-process",
            "landlock-unavailable",
            "landlock-abi",
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
}
