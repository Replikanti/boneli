//! An anchor's memory release and hold (ADR-042, D3).
//!
//! An anchor is a clone of the runner that never execs, so without this it
//! would keep a copy-on-write image of the runner's anonymous memory as it
//! was at the clone (its heap, other threads' stacks, buffers the runner has
//! freed since) for the pod's life. Last in its setup, after the privilege
//! drop and the filter, it unmaps every anonymous mapping but three kinds:
//! the one that holds its stack pointer, the ones that hold a thread-local
//! (its thread's TLS block, where libc keeps `errno`), and each unnamed
//! mapping that starts where a file mapping ends, which is that ELF
//! object's `.bss`. Then it blocks every signal and waits forever.
//!
//! The `.bss` stays because code the compiler emits on its own needs it:
//! a stack buffer is zeroed by a call of libc's `memset`, which reads its
//! size thresholds from libc's `.bss` (measured: with that mapping gone,
//! the first release crashed there with SIGSEGV). Otherwise the code below
//! uses only its arguments, stack memory and raw `syscall`s, whose only
//! state is `errno`; it zeroes its buffers before the first `munmap`,
//! compares and resets byte by byte, and cannot panic: a panic would format
//! and allocate. A libc that keeps a thread's TLS where no thread-local of
//! this crate lives would make it crash here, which fails the anchor's
//! setup: fail closed.

use std::os::raw::c_int;

use crate::child::Step;
use crate::report;

/// Bytes read from the maps file per `read`.
const CHUNK: usize = 4096;

/// Ranges collected per pass. A pass reads the whole file, then unmaps
/// what it collected, so the file is never read while it changes; a
/// process with more anonymous mappings takes more passes.
const RANGES: usize = 128;

/// Passes before the release gives up: `vm.max_map_count` is 65,530 by
/// default and every pass but the last removes [`RANGES`], so 1,024 passes
/// (131,072 ranges) cover twice the default; a host that raised it past
/// that fails the setup instead of looping.
const PASSES: usize = 1024;

/// The bytes of a mapping's name the classification needs: `[anon:` is
/// the longest prefix it compares.
const NAME: usize = 8;

std::thread_local! {
    /// A thread-local of this crate: the mapping holding it holds this
    /// thread's TLS block, which is kept.
    static MARK: u8 = const { 0 };
}

/// A failure of the release: the item of [`Step::Release`] and the errno.
type Failure = (u32, i32);

/// The calling thread's errno, read from libc's TLS slot.
fn errno() -> i32 {
    // SAFETY: __errno_location has no preconditions; it returns this
    // thread's errno slot, which lives in the TLS block the release keeps.
    let slot = unsafe { libc::__errno_location() };
    // SAFETY: the slot is valid for reads for the thread's life.
    unsafe { *slot }
}

/// Writes all of `bytes` with raw `write`s; false if one failed.
fn write_raw(fd: c_int, bytes: &[u8]) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        let Some(rest) = bytes.get(at..) else {
            return false;
        };
        // SAFETY: rest is valid for its length; fd is the report pipe.
        let n = unsafe { libc::syscall(libc::SYS_write, fd, rest.as_ptr(), rest.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        at = at.saturating_add(n as usize);
    }
    true
}

/// Reports the failure and ends the process with 127, as a failed setup
/// step does, with raw syscalls only.
fn die(report_fd: c_int, (index, errno): Failure) -> ! {
    let errno = if errno == 0 { libc::EIO } else { errno };
    let bytes = report::encode(Step::Release, index, errno);
    write_raw(report_fd, &bytes);
    loop {
        // SAFETY: exit_group takes a plain code and does not return.
        unsafe { libc::syscall(libc::SYS_exit_group, 127) };
    }
}

/// One line of the maps file, parsed byte by byte.
struct Line {
    start: usize,
    end: usize,
    /// 0 in the start address, 1 in the end address, 2 after it.
    phase: u8,
    /// The field after the address: 1 permissions, 2 offset, 3 device,
    /// 4 inode, 5 the name.
    field: u8,
    in_space: bool,
    name: [u8; NAME],
    name_len: usize,
    /// Any byte seen on this line.
    any: bool,
}

impl Line {
    fn new() -> Line {
        Line {
            start: 0,
            end: 0,
            phase: 0,
            field: 0,
            in_space: false,
            name: [0; NAME],
            name_len: 0,
            any: false,
        }
    }

    /// Adds one byte (not the newline).
    fn push(&mut self, b: u8) -> Result<(), i32> {
        self.any = true;
        match self.phase {
            0 | 1 => {
                if b == b'-' && self.phase == 0 {
                    self.phase = 1;
                    return Ok(());
                }
                if b == b' ' && self.phase == 1 {
                    self.phase = 2;
                    self.in_space = true;
                    return Ok(());
                }
                let digit = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => return Err(libc::EINVAL),
                };
                let n = if self.phase == 0 {
                    &mut self.start
                } else {
                    &mut self.end
                };
                *n = n
                    .checked_mul(16)
                    .and_then(|v| v.checked_add(usize::from(digit)))
                    .ok_or(libc::EINVAL)?;
                Ok(())
            }
            _ => {
                if b == b' ' {
                    self.in_space = true;
                    return Ok(());
                }
                if self.in_space {
                    self.in_space = false;
                    self.field = self.field.saturating_add(1);
                }
                if self.field == 5
                    && let Some(slot) = self.name.get_mut(self.name_len)
                {
                    *slot = b;
                    self.name_len += 1;
                }
                Ok(())
            }
        }
    }

    /// Whether the mapping is anonymous: no name, or the heap, a stack or
    /// a named anonymous mapping. Files, `[vdso]`, `[vvar]` and
    /// `[vsyscall]` are not.
    fn anonymous(&self) -> bool {
        self.name_len == 0
            || self.named(b"[heap]")
            || self.named(b"[stack")
            || self.named(b"[anon:")
    }

    /// Whether the mapping is a file's: its name is a path.
    fn file(&self) -> bool {
        self.named(b"/")
    }

    /// Whether the name starts with `prefix`, compared byte by byte: a
    /// slice comparison could call libc's `memcmp`.
    fn named(&self, prefix: &[u8]) -> bool {
        if prefix.len() > self.name_len {
            return false;
        }
        let mut i = 0;
        while i < prefix.len() {
            if self.name.get(i) != prefix.get(i) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Back to the start of a line, field by field: assigning a new
    /// `Line` could compile to a call of libc's `memcpy`.
    fn reset(&mut self) {
        self.start = 0;
        self.end = 0;
        self.phase = 0;
        self.field = 0;
        self.in_space = false;
        self.name_len = 0;
        self.any = false;
    }

    /// Whether the mapping holds one of `keep`.
    fn holds_any(&self, keep: &[usize]) -> bool {
        keep.iter().any(|&a| self.start <= a && a < self.end)
    }
}

/// Reads the maps file once from its start and collects up to [`RANGES`]
/// anonymous mappings that hold none of `keep`; returns how many.
fn scan(
    maps: c_int,
    keep: &[usize],
    buf: &mut [u8; CHUNK],
    out: &mut [(usize, usize); RANGES],
) -> Result<usize, Failure> {
    // SAFETY: lseek takes plain integers.
    if unsafe { libc::syscall(libc::SYS_lseek, maps, 0 as libc::off_t, libc::SEEK_SET) } < 0 {
        return Err((1, errno()));
    }
    let mut line = Line::new();
    let mut count = 0;
    // The end of the line before, if it was a file mapping: an unnamed
    // mapping that starts there is that ELF object's `.bss`.
    let mut file_end: Option<usize> = None;
    let mut collect = |line: &Line, count: &mut usize| -> Result<(), Failure> {
        if line.phase != 2 || line.field < 4 || line.start >= line.end {
            return Err((2, libc::EINVAL));
        }
        let bss = line.name_len == 0 && file_end == Some(line.start);
        if line.anonymous()
            && !bss
            && !line.holds_any(keep)
            && let Some(slot) = out.get_mut(*count)
        {
            *slot = (line.start, line.end);
            *count += 1;
        }
        file_end = if line.file() { Some(line.end) } else { None };
        Ok(())
    };
    loop {
        // SAFETY: buf is valid writable memory of the length passed.
        let n = unsafe { libc::syscall(libc::SYS_read, maps, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err((1, errno()));
        }
        if n == 0 {
            break;
        }
        for &b in buf.get(..n as usize).unwrap_or(&[]) {
            if b == b'\n' {
                collect(&line, &mut count)?;
                line.reset();
            } else {
                line.push(b).map_err(|e| (2, e))?;
            }
        }
    }
    if line.any {
        collect(&line, &mut count)?;
    }
    Ok(count)
}

/// Unmaps every anonymous mapping but the ones holding the stack pointer,
/// a thread-local or an ELF object's `.bss`, then holds: every signal
/// blocked, the release's progress record written, the report pipe and
/// the maps file closed, and `rt_sigsuspend` with every signal blocked
/// forever, so only SIGKILL
/// (`cgroup.kill` of the pod, or the runner through the pidfd) ends it. A
/// failure is reported as [`Step::Release`] and ends the process.
#[inline(never)]
pub(crate) fn release_and_hold(maps: c_int, report_fd: c_int) -> ! {
    // Every address that must stay mapped, taken before anything is gone.
    let marker = 0u8;
    let stack = std::hint::black_box(&marker) as *const u8 as usize;
    let tls = MARK.with(|m| m as *const u8 as usize);
    // SAFETY: __errno_location returns this thread's errno slot.
    let errno_at = unsafe { libc::__errno_location() } as usize;
    let keep = [stack, tls, errno_at];

    // Both buffers are zeroed here, before anything is gone.
    let mut buf = [0u8; CHUNK];
    let mut ranges = [(0usize, 0usize); RANGES];
    let mut done = false;
    for _ in 0..PASSES {
        let n = match scan(maps, &keep, &mut buf, &mut ranges) {
            Ok(n) => n,
            Err(f) => die(report_fd, f),
        };
        if n == 0 {
            done = true;
            break;
        }
        for &(start, end) in ranges.get(..n).unwrap_or(&[]) {
            // SAFETY: the range is a whole mapping of this process that
            // holds neither this stack, nor this thread's TLS, nor
            // anything the code below reads.
            if unsafe { libc::syscall(libc::SYS_munmap, start, end - start) } < 0 {
                die(report_fd, (3, errno()));
            }
        }
    }
    if !done {
        die(report_fd, (4, libc::E2BIG));
    }

    let all: u64 = !0;
    // SAFETY: all is a valid kernel signal set of the size passed.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_SETMASK,
            &all as *const u64,
            0usize,
            crate::ffi::SIGSET_SIZE,
        )
    };
    if rc < 0 {
        die(report_fd, (5, errno()));
    }
    let bytes = report::encode(Step::Release, 0, 0);
    if !write_raw(report_fd, &bytes) {
        loop {
            // SAFETY: exit_group takes a plain code and does not return.
            unsafe { libc::syscall(libc::SYS_exit_group, 127) };
        }
    }
    // SAFETY: both descriptors are this process's and closed once.
    unsafe { libc::syscall(libc::SYS_close, maps) };
    // SAFETY: as above.
    unsafe { libc::syscall(libc::SYS_close, report_fd) };
    loop {
        // SAFETY: all is a valid kernel signal set of the size passed; with
        // every signal in it nothing wakes the call but SIGKILL.
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigsuspend,
                &all as *const u64,
                crate::ffi::SIGSET_SIZE,
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &[u8]) -> Result<Vec<(usize, usize, bool)>, i32> {
        let mut out = Vec::new();
        let mut line = Line::new();
        for &b in text {
            if b == b'\n' {
                out.push((line.start, line.end, line.anonymous()));
                line = Line::new();
            } else {
                line.push(b)?;
            }
        }
        Ok(out)
    }

    #[test]
    fn maps_lines_classified() {
        let text = b"55d0c0000000-55d0c0001000 r--p 00000000 00:1f 12345 /usr/bin/x\n\
55d0c0200000-55d0c0300000 rw-p 00000000 00:00 0 \n\
55d0c1000000-55d0c2000000 rw-p 00000000 00:00 0                          [heap]\n\
7f0000000000-7f0000100000 rw-p 00000000 00:00 0\n\
7f0000200000-7f0000201000 rw-p 00000000 00:00 0  [anon: glibc: malloc]\n\
7f0000300000-7f0000301000 rw-s 00000000 00:01 77 /memfd:x (deleted)\n\
7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0                          [stack]\n\
7ffc00100000-7ffc00104000 r--p 00000000 00:00 0                          [vvar]\n\
7ffc00104000-7ffc00106000 r-xp 00000000 00:00 0                          [vdso]\n\
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]\n";
        let lines = parse(text).expect("parse");
        let anon: Vec<bool> = lines.iter().map(|l| l.2).collect();
        assert_eq!(
            anon,
            [
                false, true, true, true, true, false, true, false, false, false
            ]
        );
        assert_eq!(lines[2].0, 0x55d0_c100_0000);
        assert_eq!(lines[2].1, 0x55d0_c200_0000);
        assert_eq!(lines[9].1, 0xffff_ffff_ff60_1000);
    }

    #[test]
    fn malformed_maps_lines_refused() {
        for bad in [
            &b"xyz-1 rw-p\n"[..],
            b"1-2-3 rw-p\n",
            b"10000000000000000-1 r\n",
        ] {
            assert_eq!(parse(bad), Err(libc::EINVAL), "{bad:?}");
        }
    }

    #[test]
    fn scan_keeps_bss_stack_and_files() {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // A file mapping, its .bss right after it, a gap, an unnamed
        // mapping, the heap, a stack-holding mapping, a vdso.
        let text = b"1000-2000 r-xp 00000000 00:1f 1 /lib/x.so\n\
2000-3000 rw-p 00001000 00:1f 1 /lib/x.so\n\
3000-5000 rw-p 00000000 00:00 0 \n\
6000-7000 rw-p 00000000 00:00 0 \n\
7000-9000 rw-p 00000000 00:00 0 [heap]\n\
a000-b000 rw-p 00000000 00:00 0 \n\
b000-c000 r-xp 00000000 00:00 0 [vdso]\n\
c000-d000 rw-p 00000000 00:00 0 \n";
        // SAFETY: the name is NUL-terminated; memfd_create takes flags.
        let fd = unsafe { libc::memfd_create(c"maps".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create");
        // SAFETY: memfd_create returned a new descriptor nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        std::fs::File::from(fd.try_clone().expect("dup"))
            .write_all(text)
            .expect("write");
        let mut buf = [0u8; CHUNK];
        let mut out = [(0usize, 0usize); RANGES];
        let n = scan(fd.as_raw_fd(), &[0xa800], &mut buf, &mut out).expect("scan");
        // 0x3000 is the .bss of x.so; 0xa000 holds a kept address; 0xc000
        // follows the vdso, which is no file.
        assert_eq!(
            out[..n],
            [(0x6000, 0x7000), (0x7000, 0x9000), (0xc000, 0xd000)]
        );
        // A second pass reads from the start again.
        assert_eq!(scan(fd.as_raw_fd(), &[0xa800], &mut buf, &mut out), Ok(n));
    }

    #[test]
    fn kept_addresses_by_range() {
        let mut line = Line::new();
        for &b in b"1000-2000 rw-p 0 00:00 0" {
            line.push(b).expect("push");
        }
        assert!(line.holds_any(&[0x1000]));
        assert!(line.holds_any(&[0x1fff]));
        assert!(!line.holds_any(&[0x2000, 0xfff]));
    }
}
