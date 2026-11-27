//! The census on a host (ADR-007, D2 and D9): every capability-gated form
//! fails inside the sandbox (`capability_gated_calls_fail`), and every
//! `NotImplemented` entry answers ENOSYS with and without the filter
//! (`not_implemented_entries_return_enosys`).

use crate::census::{CENSUS, Form, Probe, Verdict, entry, gated_forms};
use crate::support::gated::{HOST_MNTNS_VAR, has};
use crate::support::{self, ids, report, run_probe, run_probe_host};

/// What one gated form showed.
#[derive(Debug, PartialEq, Eq)]
pub enum CapOutcome {
    /// The kernel refused it: EPERM or the errno the census names.
    Refused,
    /// The host kernel lacks the syscall, listed as `nosys-<name>`.
    Absent,
    /// The syscall was removed after the floor and answers ENOSYS.
    Removed,
    /// The host lacks what the call needs before its check (an RTC alarm
    /// device), listed as a host gap.
    Unreachable,
}

/// The gap id of a host without an RTC alarm device: the alarm clocks
/// answer EOPNOTSUPP from `alarmtimer_get_rtcdev` before the capability
/// check (`alarm_timer_create` and `alarm_timer_nsleep` in 7.2; the
/// arm64 CI runners have no such device). `timerfd_create` checks the
/// capability first, so it stays a full probe everywhere.
pub const ALARM_RTC_GAP: &str = "alarm-rtc";

/// The forms behind the RTC check.
pub const ALARM_RTC_FORMS: [(&str, &str); 2] = [
    ("timer_create", "CLOCK_REALTIME_ALARM"),
    ("clock_nanosleep", "CLOCK_REALTIME_ALARM"),
];

/// Classifies a form that sits behind the RTC check, exact both ways:
/// EOPNOTSUPP must be listed as [`ALARM_RTC_GAP`], and a listed gap must
/// give EOPNOTSUPP. `None` for every other form.
pub fn classify_rtc(
    name: &str,
    form: &Form,
    got: i32,
    listed: bool,
) -> Option<Result<CapOutcome, String>> {
    if !ALARM_RTC_FORMS.contains(&(name, form.form)) {
        return None;
    }
    let at = format!("{name}:{}", form.form);
    Some(match (got == libc::EOPNOTSUPP, listed) {
        (true, true) => Ok(CapOutcome::Unreachable),
        (true, false) => Err(format!(
            "{at}: EOPNOTSUPP, so the host has no RTC alarm device and the check is not reached; \
             list {ALARM_RTC_GAP} in BONELI_SYS_HOST_GAPS"
        )),
        (false, true) => Err(format!(
            "{at}: {ALARM_RTC_GAP} is listed, but the call gave {got}, so the host has the device"
        )),
        (false, false) => return None,
    })
}

/// Classifies the errno `got` of `form` of the census entry `name`.
/// `listed` is whether `BONELI_SYS_HOST_GAPS` names `nosys-<name>`. Exact
/// both ways: ENOSYS must be listed (or the entry removed), and a listed
/// syscall must answer ENOSYS.
pub fn classify_cap(
    name: &str,
    form: &Form,
    removed_in: Option<(u32, u32)>,
    got: i32,
    listed: bool,
) -> Result<CapOutcome, String> {
    let at = format!("{name}:{}", form.form);
    if got == libc::ENOSYS {
        return match (removed_in, listed) {
            (Some(_), false) => Ok(CapOutcome::Removed),
            (Some((major, minor)), true) => Err(format!(
                "{at}: removed in {major}.{minor}, so nosys-{name} needs no listing"
            )),
            (None, true) => Ok(CapOutcome::Absent),
            (None, false) => Err(format!(
                "{at}: ENOSYS, so the host kernel lacks {name}; list nosys-{name} in \
                 BONELI_SYS_HOST_GAPS"
            )),
        };
    }
    if listed {
        return Err(format!(
            "{at}: nosys-{name} is listed in BONELI_SYS_HOST_GAPS, but the call gave {got}, \
             so the kernel has it"
        ));
    }
    if got == 0 {
        return Err(format!(
            "{at}: the call succeeded, so the check passed and the form acted"
        ));
    }
    if got == libc::EPERM || got == form.errno {
        Ok(CapOutcome::Refused)
    } else {
        Err(format!(
            "{at}: errno {got}, the census expects {} from {}",
            form.errno, form.returned_by
        ))
    }
}

#[test]
fn alarm_rtc_classification() {
    let form = Form {
        form: "CLOCK_REALTIME_ALARM",
        errno: libc::EPERM,
        returned_by: "alarm_timer_create",
    };
    let eopnotsupp = libc::EOPNOTSUPP;
    assert_eq!(
        classify_rtc("timer_create", &form, eopnotsupp, true),
        Some(Ok(CapOutcome::Unreachable))
    );
    assert!(matches!(
        classify_rtc("timer_create", &form, eopnotsupp, false),
        Some(Err(_))
    ));
    assert!(matches!(
        classify_rtc("clock_nanosleep", &form, libc::EPERM, true),
        Some(Err(_))
    ));
    // Unlisted and refused: the normal classification decides.
    assert_eq!(
        classify_rtc("timer_create", &form, libc::EPERM, false),
        None
    );
    // Only the two forms behind the RTC check: timerfd_create checks the
    // capability first.
    assert_eq!(
        classify_rtc("timerfd_create", &form, eopnotsupp, true),
        None
    );
    for (name, f) in ALARM_RTC_FORMS {
        assert!(
            crate::census::gated_forms()
                .iter()
                .any(|(n, g)| *n == name && g.form == f),
            "{name}:{f} is not a census form"
        );
    }
    assert!(crate::support::KNOWN_GAPS.contains(&ALARM_RTC_GAP));
}

#[test]
fn needs_cap_outcome_classification() {
    let form = Form {
        form: "f",
        errno: libc::EACCES,
        returned_by: "check",
    };
    let eperm = Form {
        form: "g",
        errno: libc::EPERM,
        returned_by: "check",
    };
    assert_eq!(
        classify_cap("n", &eperm, None, libc::EPERM, false),
        Ok(CapOutcome::Refused)
    );
    assert_eq!(
        classify_cap("n", &form, None, libc::EACCES, false),
        Ok(CapOutcome::Refused)
    );
    assert_eq!(
        classify_cap("n", &form, None, libc::EPERM, false),
        Ok(CapOutcome::Refused)
    );
    assert_eq!(
        classify_cap("n", &form, None, libc::ENOSYS, true),
        Ok(CapOutcome::Absent)
    );
    assert_eq!(
        classify_cap("n", &form, Some((6, 7)), libc::ENOSYS, false),
        Ok(CapOutcome::Removed)
    );
    // ENOSYS unlisted, listed but present, success, another errno, and a
    // removed entry that is listed.
    assert!(classify_cap("n", &form, None, libc::ENOSYS, false).is_err());
    assert!(classify_cap("n", &eperm, None, libc::EPERM, true).is_err());
    assert!(classify_cap("n", &form, None, 0, false).is_err());
    assert!(classify_cap("n", &form, None, libc::EINVAL, false).is_err());
    assert!(classify_cap("n", &form, Some((6, 7)), libc::ENOSYS, true).is_err());
    assert!(classify_cap("n", &form, Some((6, 7)), 0, false).is_err());
}

/// The host's mount namespace id (`NS_GET_MNTNS_ID` on
/// `/proc/self/ns/mnt`), which the `statmount` and `listmount` forms name.
fn host_mntns_id() -> u64 {
    use std::os::fd::AsRawFd;
    let ns = std::fs::File::open("/proc/self/ns/mnt").expect("open /proc/self/ns/mnt");
    let mut id: u64 = 0;
    // SAFETY: NS_GET_MNTNS_ID writes one u64 through the pointer, valid
    // for the call's duration.
    let rc = unsafe { libc::ioctl(ns.as_raw_fd(), libc::NS_GET_MNTNS_ID as _, &mut id) };
    assert_eq!(
        rc,
        0,
        "NS_GET_MNTNS_ID: {}",
        std::io::Error::last_os_error()
    );
    id
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp filters"]
fn capability_gated_calls_fail() {
    let gaps = support::host_gaps();
    for e in CENSUS {
        if let Verdict::NeedsCap {
            probe: Probe::Unproven(why),
            check,
            cap,
            ..
        } = &e.verdict
            && has(e.name)
        {
            report(&format!(
                "capability_gated_calls_fail: {} unproven ({cap} in {check}): {why}",
                e.name
            ));
        }
    }
    let mntns = host_mntns_id().to_string();
    let env = [(HOST_MNTNS_VAR, mntns.as_str())];
    let mut failures = Vec::new();
    let mut absent = std::collections::BTreeSet::new();
    for inside in [0, 999] {
        let p = run_probe("caps-gated", ids(inside, inside), &env);
        if p.status != boneli_sys::ExitStatus::Exited(0) {
            failures.push(format!("inside id {inside}: the probe failed:\n{}", p.raw));
            continue;
        }
        for (name, form) in gated_forms() {
            if !has(name) {
                continue;
            }
            let key = format!("cap:{name}:{}", form.form);
            let Some(value) = p.values.get(&key) else {
                failures.push(format!(
                    "inside id {inside}: {key} missing (the form killed the probe?)"
                ));
                continue;
            };
            let Ok(got) = value.parse::<i32>() else {
                failures.push(format!("inside id {inside}: {key}={value}"));
                continue;
            };
            let removed_in = match entry(name).map(|e| &e.verdict) {
                Some(Verdict::NeedsCap { removed_in, .. }) => *removed_in,
                _ => None,
            };
            let listed = gaps.contains(&format!("nosys-{name}"));
            let outcome = classify_rtc(name, form, got, gaps.contains(ALARM_RTC_GAP))
                .unwrap_or_else(|| classify_cap(name, form, removed_in, got, listed));
            match outcome {
                Ok(CapOutcome::Unreachable) => report(&format!(
                    "capability_gated_calls_fail: {name}:{} not reached (no RTC alarm device), \
                     listed as {ALARM_RTC_GAP}",
                    form.form
                )),
                Ok(CapOutcome::Absent) => {
                    absent.insert(name);
                }
                Ok(_) => {}
                Err(e) => failures.push(format!("inside id {inside}: {e}")),
            }
        }
    }
    for name in absent {
        report(&format!(
            "capability_gated_calls_fail: {name} absent from the host kernel, listed as nosys-{name}"
        ));
    }
    // A listed nosys- id must name a gated entry this architecture has.
    for gap in &gaps {
        if let Some(name) = gap.strip_prefix("nosys-")
            && !gated_forms().iter().any(|(n, _)| *n == name && has(n))
        {
            failures.push(format!(
                "{gap}: no gated form of {name} runs on this architecture"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore = "host: user namespaces, cgroup v2 delegation, seccomp filters"]
fn not_implemented_entries_return_enosys() {
    let enosys = libc::ENOSYS.to_string();
    let baseline = run_probe_host("nosys", &[]);
    baseline.assert_ok();
    let names: Vec<&str> = CENSUS
        .iter()
        .filter(|e| matches!(e.verdict, Verdict::NotImplemented) && has(e.name))
        .map(|e| e.name)
        .collect();
    assert!(!names.is_empty());
    let mut failures = Vec::new();
    for inside in [0, 999] {
        let p = run_probe("nosys", ids(inside, inside), &[]);
        p.assert_ok();
        for name in &names {
            let key = format!("nosys:{name}");
            for (run, probe) in [("host", &baseline), ("sandbox", &p)] {
                if probe.get(&key) != enosys {
                    failures.push(format!(
                        "inside id {inside}, {run}: {name} gave {}",
                        probe.get(&key)
                    ));
                }
            }
        }
    }
    report(&format!(
        "not_implemented_entries_return_enosys: {} entries on this architecture",
        names.len()
    ));
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
