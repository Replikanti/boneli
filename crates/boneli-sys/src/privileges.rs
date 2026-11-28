//! The privilege drop of the cloned child (ADR-007, D9): locked
//! securebits, an empty bounding set, no ambient, permitted, effective or
//! inheritable capabilities, `no_new_privs`, and the seccomp filter last,
//! so that only the listener hand-off (ADR-043, D3) and `execve` run under
//! it before the program does.
//!
//! The child side ([`drop_all`]) allocates nothing; the parent reads
//! `cap_last_cap` and assembles the filter before the clone.

use crate::child::{Failure, Fault, Step, fail, inject};
use crate::error::{Error, Result, errno};
use crate::ffi;
use crate::seccomp::Insn;
use crate::seccomp::notify::LISTENER_FLAGS;

/// The securebits the child sets, 0xEF (`include/uapi/linux/securebits.h`):
/// `NOROOT` (1) and its lock (2), so uid 0 gains no capabilities at
/// `execve`; `NO_SETUID_FIXUP` (4) and its lock (8); the lock of
/// `KEEP_CAPS` (32) with `KEEP_CAPS` itself off; `NO_CAP_AMBIENT_RAISE`
/// (64) and its lock (128).
pub const SECUREBITS: u32 = (libc::SECBIT_NOROOT
    | libc::SECBIT_NOROOT_LOCKED
    | libc::SECBIT_NO_SETUID_FIXUP
    | libc::SECBIT_NO_SETUID_FIXUP_LOCKED
    | libc::SECBIT_KEEP_CAPS_LOCKED
    | libc::SECBIT_NO_CAP_AMBIENT_RAISE
    | libc::SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED) as u32;

const _: () = assert!(SECUREBITS == 0xEF);

/// The highest capability number this kernel knows, read at run time so
/// that a newer kernel's capabilities are dropped too.
pub(crate) fn cap_last_cap() -> Result<u32> {
    const PATH: &str = "/proc/sys/kernel/cap_last_cap";
    let text = std::fs::read_to_string(PATH).map_err(|e| Error::CapLastCap(e.to_string()))?;
    parse_cap_last_cap(&text).ok_or_else(|| Error::CapLastCap(format!("unparsable {text:?}")))
}

/// Parses `cap_last_cap`: decimal, an optional newline, at most 63 (the
/// bounding set is 64 bits wide).
pub(crate) fn parse_cap_last_cap(text: &str) -> Option<u32> {
    let digits = text.strip_suffix('\n').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok().filter(|&n| n <= 63)
}

/// Everything the child's privilege steps need, prepared before the clone.
pub(crate) struct PrivilegeDrop<'a> {
    pub cap_last_cap: u32,
    /// The assembled program; the child points `sock_fprog` at it. The
    /// notifying one (ADR-043, D2) where `listener` is set, the plain one
    /// for an anchor, which runs no workload (ADR-042, D3).
    pub filter: &'a [Insn],
    /// Whether the filter is installed with [`LISTENER_FLAGS`].
    pub listener: bool,
}

/// The steps from [`Step::Securebits`] to [`Step::Seccomp`], in order.
/// With `listener` set, the filter is installed with [`LISTENER_FLAGS`]
/// (ADR-043, D3) and its listener is returned; without, with no flag, and
/// the result is -1.
pub(crate) fn drop_all(
    plan: &PrivilegeDrop<'_>,
    fault: Fault,
) -> std::result::Result<libc::c_int, Failure> {
    inject(fault, Step::Securebits)?;
    // SAFETY: PR_SET_SECUREBITS takes plain integers.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECUREBITS,
            SECUREBITS as libc::c_ulong,
            0,
            0,
            0,
        )
    } < 0
    {
        return Err(fail(Step::Securebits, 0, errno()));
    }

    inject(fault, Step::CapBoundingSet)?;
    for cap in 0..=plan.cap_last_cap {
        // SAFETY: PR_CAPBSET_DROP takes plain integers.
        if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) } < 0 {
            return Err(fail(Step::CapBoundingSet, cap, errno()));
        }
    }

    inject(fault, Step::CapAmbient)?;
    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL takes plain integers.
    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc < 0 {
        return Err(fail(Step::CapAmbient, 0, errno()));
    }

    inject(fault, Step::Capset)?;
    let header = ffi::CapHeader {
        version: ffi::LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [ffi::CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: header and data are valid for the call's duration; version 3
    // reads two data elements.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const ffi::CapHeader,
            data.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(fail(Step::Capset, 0, errno()));
    }

    inject(fault, Step::NoNewPrivs)?;
    // SAFETY: PR_SET_NO_NEW_PRIVS takes plain integers.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
        return Err(fail(Step::NoNewPrivs, 0, errno()));
    }

    inject(fault, Step::Seccomp)?;
    let prog = libc::sock_fprog {
        // The assembler caps programs at 4096 instructions.
        len: plan.filter.len() as u16,
        filter: plan.filter.as_ptr().cast::<libc::sock_filter>().cast_mut(),
    };
    // SAFETY: prog points at the prepared program, whose instructions have
    // sock_filter's layout (asserted in seccomp::bpf), for the call's
    // duration; the kernel copies it.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            if plan.listener { LISTENER_FLAGS } else { 0 },
            &prog as *const libc::sock_fprog,
        )
    };
    if rc < 0 {
        return Err(fail(Step::Seccomp, 0, errno()));
    }
    // With NEW_LISTENER the install returns the listener.
    Ok(if plan.listener { rc as libc::c_int } else { -1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_last_cap_parsing() {
        assert_eq!(parse_cap_last_cap("40\n"), Some(40));
        assert_eq!(parse_cap_last_cap("0"), Some(0));
        assert_eq!(parse_cap_last_cap("63\n"), Some(63));
        for bad in ["", "\n", "64", "-1", "4 0", "+4", "40\n\n", "x"] {
            assert_eq!(parse_cap_last_cap(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn securebits_value() {
        assert_eq!(SECUREBITS, 239);
        // KEEP_CAPS itself (bit 4) stays off; only its lock is set.
        assert_eq!(SECUREBITS & (1 << 4), 0);
    }
}
