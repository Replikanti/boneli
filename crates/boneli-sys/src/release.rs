//! An anchor's memory release and hold (ADR-042, D3).
//!
//! An anchor is a clone of the runner that never execs, so without this it
//! would keep a copy-on-write image of the runner's memory as it was at
//! the clone (its heap, other threads' stacks, shared pages, buffers the
//! runner has freed since) for the pod's life. It is cloned from a thread
//! of its own on a freshly mapped stack (`anchor::launch_on_fresh_stack`),
//! so its own stack and TLS hold nothing of the runner's. Last in its
//! setup, after the privilege drop and the filter, it unmaps every shared
//! and every anonymous mapping but three kinds of ranges: each ELF
//! object's `.bss`, as its `PT_LOAD` headers place it (read by the parent
//! before the clone), the stack from [`STACK_BELOW`] under the release's
//! frame up to its caller's frame, and [`TLS_AROUND`] around its thread's
//! TLS (a thread-local of this crate and libc's `errno`). Each window ends
//! at the mapping that holds its address, and a mapping that holds part of
//! a kept range loses the rest. The kept stack under the release's frame
//! is zeroed. Then it blocks every signal and waits forever.
//!
//! The `.bss` stays because code the compiler emits on its own needs it:
//! a stack buffer is zeroed by a call of libc's `memset`, which reads its
//! size thresholds from libc's `.bss` (measured: with that mapping gone,
//! the first release crashed there with SIGSEGV). Only the `PT_LOAD`
//! ranges count: an unnamed mapping that merely starts where a named one
//! ends is runner memory (review of part 3, run 1: a 32 MiB buffer above a
//! shared page was kept). Otherwise the code below uses only its
//! arguments, stack memory and raw `syscall`s, whose only state is
//! `errno`; it zeroes its buffers before the first `munmap`, compares and
//! resets byte by byte, and cannot panic: a panic would format and
//! allocate. A libc that kept a thread's TLS farther than [`TLS_AROUND`]
//! from both of its addresses would make it crash here, which fails the
//! anchor's setup: fail closed.

use std::os::raw::c_int;

use crate::child::Step;
use crate::report;

/// Bytes read from the maps file per `read`.
const CHUNK: usize = 4096;

/// Ranges collected per pass. A pass reads the whole file, then unmaps
/// what it collected, so the file is never read while it changes; a
/// process with more mappings to release takes more passes.
const RANGES: usize = 128;

/// Passes before the release gives up: `vm.max_map_count` is 65,530 by
/// default and every pass but the last removes [`RANGES`], so 1,024 passes
/// (131,072 ranges) cover twice the default; a host that raised it past
/// that fails the setup instead of looping.
const PASSES: usize = 1024;

/// The bytes of a mapping's name the classification needs: `[anon:` is
/// the longest prefix it compares.
const NAME: usize = 8;

/// The most `.bss` ranges the parent passes: one per ELF object with a
/// `PT_LOAD` whose memory size exceeds its file size. The runner links a
/// handful of objects (the binary, libc, libgcc_s, the dynamic loader on
/// the dev host); more than 64 fails `create` before the clone.
pub(crate) const BSS_MAX: usize = 64;

/// The kept ranges: the `.bss` ranges, the stack window, two TLS windows.
const KEPT: usize = BSS_MAX + 3;

/// How far under the release's frame the stack stays: the frames it calls
/// after the first `munmap` (the scan, libc's `syscall`) are a few KiB
/// deep even unoptimized; 64 KiB leaves a margin of more than ten. The
/// window ends at the bottom of the stack's mapping, and all of it but
/// [`ZERO_MARGIN`] under the release's frame is zeroed before the first
/// `munmap` (review of part 3, run 2).
pub(crate) const STACK_BELOW: usize = 64 << 10;

/// How far around each of its two addresses the TLS stays: glibc's static
/// TLS block with its surplus and the thread control block, which holds
/// the stack protector's canary on x86_64, are a few KiB; musl's are
/// smaller. 64 KiB on each side covers them with a margin of more than
/// ten. Each window ends at the mapping that holds its address, which for
/// an anchor is the stack it was cloned on, where the C library put the
/// thread's TLS (review of part 3, run 2: unclipped, it reached into the
/// mapping next to the TLS, another runner thread's stack).
pub(crate) const TLS_AROUND: usize = 64 << 10;

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
    /// The bytes of the permissions seen so far.
    perm: u8,
    /// The fourth permission is `s`: a shared mapping.
    shared: bool,
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
            perm: 0,
            shared: false,
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
                if self.field == 1 {
                    if self.perm == 3 && b == b's' {
                        self.shared = true;
                    }
                    self.perm = self.perm.saturating_add(1);
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

    /// Whether the mapping is released: every shared mapping (an anonymous
    /// shared page reads as `/dev/zero (deleted)`, a memfd and SysV memory
    /// have names too), and every anonymous one: no name, the heap, a
    /// stack or a named anonymous mapping. Private file mappings (code,
    /// read-only data, the relocated and written data of each object),
    /// `[vdso]`, `[vvar]` and `[vsyscall]` stay.
    fn released(&self) -> bool {
        self.shared
            || self.name_len == 0
            || self.named(b"[heap]")
            || self.named(b"[stack")
            || self.named(b"[anon:")
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
        self.perm = 0;
        self.shared = false;
        self.name_len = 0;
        self.any = false;
    }
}

/// Adds the parts of `[start, end)` outside every range of `kept`
/// (ascending by start, possibly overlapping) to `out`, as long as it has
/// room.
fn outside(
    start: usize,
    end: usize,
    kept: &[(usize, usize)],
    out: &mut [(usize, usize); RANGES],
    count: &mut usize,
) {
    let mut push = |s: usize, e: usize, count: &mut usize| {
        if let Some(slot) = out.get_mut(*count) {
            *slot = (s, e);
            *count += 1;
        }
    };
    let mut cursor = start;
    for &(ks, ke) in kept {
        if ke <= cursor {
            continue;
        }
        if ks >= end {
            break;
        }
        if ks > cursor {
            push(cursor, ks, count);
        }
        cursor = ke;
        if cursor >= end {
            return;
        }
    }
    if cursor < end {
        push(cursor, end, count);
    }
}

/// Reads the maps file once from its start and calls `each` for every
/// line; a line it cannot parse is item 2, a failed read item 1.
fn each_line(
    maps: c_int,
    buf: &mut [u8; CHUNK],
    each: &mut dyn FnMut(&Line) -> Result<(), Failure>,
) -> Result<(), Failure> {
    // SAFETY: lseek takes plain integers.
    if unsafe { libc::syscall(libc::SYS_lseek, maps, 0 as libc::off_t, libc::SEEK_SET) } < 0 {
        return Err((1, errno()));
    }
    let mut line = Line::new();
    let mut check = |line: &Line| -> Result<(), Failure> {
        if line.phase != 2 || line.field < 4 || line.start >= line.end {
            return Err((2, libc::EINVAL));
        }
        each(line)
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
                check(&line)?;
                line.reset();
            } else {
                line.push(b).map_err(|e| (2, e))?;
            }
        }
    }
    if line.any {
        check(&line)?;
    }
    Ok(())
}

/// Reads the maps file once and collects up to [`RANGES`] ranges to
/// unmap: the parts of each released mapping outside `kept`; returns how
/// many.
fn scan(
    maps: c_int,
    kept: &[(usize, usize)],
    buf: &mut [u8; CHUNK],
    out: &mut [(usize, usize); RANGES],
) -> Result<usize, Failure> {
    let mut count = 0;
    each_line(maps, buf, &mut |line| {
        if line.released() {
            outside(line.start, line.end, kept, out, &mut count);
        }
        Ok(())
    })?;
    Ok(count)
}

/// The mapping that holds each of `addrs`; one that none holds is item 6,
/// EFAULT.
fn holding(
    maps: c_int,
    buf: &mut [u8; CHUNK],
    addrs: [usize; 3],
) -> Result<[(usize, usize); 3], Failure> {
    let mut found = [(0usize, 0usize); 3];
    each_line(maps, buf, &mut |line| {
        for (i, &a) in addrs.iter().enumerate() {
            if line.start <= a
                && a < line.end
                && let Some(slot) = found.get_mut(i)
            {
                *slot = (line.start, line.end);
            }
        }
        Ok(())
    })?;
    if found.iter().any(|&(s, e)| s >= e) {
        return Err((6, libc::EFAULT));
    }
    Ok(found)
}

/// The kept ranges in ascending order of their start: `.bss` ranges from
/// the parent, the stack window and the two TLS windows (ADR-042, D3),
/// each window clipped to `held_in`, the mapping that holds its address
/// (stack, then the two TLS addresses): a window never reaches into a
/// neighbouring mapping (review of part 3, run 2).
/// Fails with E2BIG when there are more `.bss` ranges than [`BSS_MAX`],
/// EINVAL for a page size that is no power of two or a caller frame not
/// above this one.
fn kept_ranges(
    bss: &[(usize, usize)],
    page: usize,
    stack: usize,
    caller: usize,
    tls: [usize; 2],
    held_in: [(usize, usize); 3],
    kept: &mut [(usize, usize); KEPT],
) -> Result<usize, Failure> {
    if page == 0 || !page.is_power_of_two() || caller <= stack {
        return Err((6, libc::EINVAL));
    }
    if bss.len() > BSS_MAX {
        return Err((6, libc::E2BIG));
    }
    let down = |a: usize| a & !(page - 1);
    let up = |a: usize| a.saturating_add(page - 1) & !(page - 1);
    let mut n = 0;
    let clip = |w: (usize, usize), m: (usize, usize)| (w.0.max(m.0), w.1.min(m.1));
    let mut add = |r: (usize, usize), n: &mut usize| {
        if r.0 >= r.1 {
            return;
        }
        if let Some(slot) = kept.get_mut(*n) {
            *slot = r;
            *n += 1;
        }
    };
    for &r in bss {
        add(r, &mut n);
    }
    // From below the deepest frame the code after the first munmap needs
    // up to the caller's frame: nothing above it is ever returned to.
    let [stack_in, tls_in @ ..] = held_in;
    add(
        clip(
            (
                down(stack.saturating_sub(STACK_BELOW)),
                up(caller.saturating_add(1)),
            ),
            stack_in,
        ),
        &mut n,
    );
    for (a, m) in tls.into_iter().zip(tls_in) {
        add(
            clip(
                (
                    down(a.saturating_sub(TLS_AROUND)),
                    up(a.saturating_add(TLS_AROUND)),
                ),
                m,
            ),
            &mut n,
        );
    }
    // Insertion sort by start, element by element.
    let mut i = 1;
    while i < n {
        let mut j = i;
        while j > 0 {
            let (Some(&a), Some(&b)) = (kept.get(j - 1), kept.get(j)) else {
                break;
            };
            if a.0 <= b.0 {
                break;
            }
            if let Some(slot) = kept.get_mut(j - 1) {
                *slot = b;
            }
            if let Some(slot) = kept.get_mut(j) {
                *slot = a;
            }
            j -= 1;
        }
        i += 1;
    }
    Ok(n)
}

/// How far under a frame one call deeper than the release's the zeroing
/// of the kept stack stops: the calls the release makes while it zeroes
/// and afterwards (the volatile write, the scan, libc's `syscall`) use a
/// few hundred bytes there; 4 KiB keeps them clear of it with a margin of
/// more than ten. What lies in that margin was written by the anchor's own
/// setup, on a stack that held nothing of the runner's.
const ZERO_MARGIN: usize = 4 << 10;

/// The address of a local one call deeper than the caller's frame.
#[inline(never)]
fn frame_below() -> usize {
    let local = 0u8;
    std::hint::black_box(&local) as *const u8 as usize
}

/// Unmaps every shared and every anonymous mapping of the process, but
/// the `.bss` of each ELF object (`bss`, page-aligned, from the parent),
/// the stack from [`STACK_BELOW`] under this frame up to `caller`, the
/// address of a local in the caller's frame, and [`TLS_AROUND`] around this
/// thread's TLS. Then it holds: every signal blocked, the release's
/// progress record written, the report pipe and the maps file closed, and
/// `rt_sigsuspend` with every signal blocked forever, so only SIGKILL
/// (`cgroup.kill` of the pod, or the runner through the pidfd) ends it. A
/// failure is reported as [`Step::Release`] and ends the process.
#[inline(never)]
pub(crate) fn release_and_hold(
    maps: c_int,
    report_fd: c_int,
    bss: &[(usize, usize)],
    page: usize,
    caller: usize,
) -> ! {
    // Every range that must stay mapped, taken before anything is gone:
    // `bss` is in the runner's heap and is copied here first.
    let marker = 0u8;
    let stack = std::hint::black_box(&marker) as *const u8 as usize;
    let tls = MARK.with(|m| m as *const u8 as usize);
    // SAFETY: __errno_location returns this thread's errno slot.
    let errno_at = unsafe { libc::__errno_location() } as usize;
    // Both buffers are zeroed here, before anything is gone.
    let mut buf = [0u8; CHUNK];
    let mut ranges = [(0usize, 0usize); RANGES];
    let held_in = match holding(maps, &mut buf, [stack, tls, errno_at]) {
        Ok(h) => h,
        Err(f) => die(report_fd, f),
    };
    let mut kept = [(0usize, 0usize); KEPT];
    let n = match kept_ranges(
        bss,
        page,
        stack,
        caller,
        [tls, errno_at],
        held_in,
        &mut kept,
    ) {
        Ok(n) => n,
        Err(f) => die(report_fd, f),
    };
    let kept = kept.get(..n).unwrap_or(&[]);

    // The kept stack under this frame holds whatever deeper calls left
    // there before (review of part 3, run 2): zeroed, from the bottom of
    // the window up to ZERO_MARGIN under a frame one call deeper than this
    // one, which no live frame reaches. The writes are volatile, so the
    // compiler neither drops them nor makes them a call of `memset`.
    let deeper = frame_below();
    let top = deeper.saturating_sub(ZERO_MARGIN) & !7;
    let mut at = (stack.saturating_sub(STACK_BELOW) & !(page.wrapping_sub(1)))
        .max(held_in[0].0)
        .saturating_add(7)
        & !7;
    while at < top {
        // SAFETY: `at` lies in the mapping that holds this stack, under
        // every live frame and above the window's bottom, aligned to 8.
        unsafe { std::ptr::write_volatile(at as *mut u64, 0) };
        at = at.saturating_add(8);
    }
    let mut done = false;
    for _ in 0..PASSES {
        let n = match scan(maps, kept, &mut buf, &mut ranges) {
            Ok(n) => n,
            Err(f) => die(report_fd, f),
        };
        if n == 0 {
            done = true;
            break;
        }
        for &(start, end) in ranges.get(..n).unwrap_or(&[]) {
            // SAFETY: the range is part of a mapping of this process that
            // lies outside every kept range: neither this stack, nor this
            // thread's TLS, nor a `.bss`, nor anything the code below reads.
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
                out.push((line.start, line.end, line.released()));
                line.reset();
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
7f0000400000-7f0000401000 rw-s 00000000 00:01 78 /dev/zero (deleted)\n\
7f0000500000-7f0000501000 r--s 00000000 00:1f 79 /usr/share/x.cache\n\
7f0000600000-7f0000601000 rw-p 00001000 00:1f 79 /usr/lib64/libx.so\n\
7ffc00000000-7ffc00021000 rw-p 00000000 00:00 0                          [stack]\n\
7ffc00100000-7ffc00104000 r--p 00000000 00:00 0                          [vvar]\n\
7ffc00104000-7ffc00106000 r-xp 00000000 00:00 0                          [vdso]\n\
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]\n";
        let lines = parse(text).expect("parse");
        let released: Vec<bool> = lines.iter().map(|l| l.2).collect();
        // Shared mappings go whatever their name; private file mappings and
        // the kernel's own stay.
        assert_eq!(
            released,
            [
                false, true, true, true, true, true, true, true, false, true, false, false, false
            ]
        );
        assert_eq!(lines[2].0, 0x55d0_c100_0000);
        assert_eq!(lines[2].1, 0x55d0_c200_0000);
        assert_eq!(lines[12].1, 0xffff_ffff_ff60_1000);
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
    fn scan_releases_all_but_kept_ranges() {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // x.so's code and data, its .bss, a shared page with a runner
        // buffer right above it (review of part 3, run 1), the heap, a
        // stack of which a window is kept, the vdso, a buffer after it.
        let text = b"1000-2000 r-xp 00000000 00:1f 1 /lib/x.so\n\
2000-3000 rw-p 00001000 00:1f 1 /lib/x.so\n\
3000-5000 rw-p 00000000 00:00 0 \n\
6000-7000 rw-s 00000000 00:01 9 /dev/zero (deleted)\n\
7000-9000 rw-p 00000000 00:00 0 \n\
9000-a000 rw-p 00000000 00:00 0 [heap]\n\
c000-14000 rw-p 00000000 00:00 0 [stack]\n\
14000-15000 r-xp 00000000 00:00 0 [vdso]\n\
15000-16000 rw-p 00000000 00:00 0 \n";
        // SAFETY: the name is NUL-terminated; memfd_create takes flags.
        let fd = unsafe { libc::memfd_create(c"maps".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create");
        // SAFETY: memfd_create returned a new descriptor nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        std::fs::File::from(fd.try_clone().expect("dup"))
            .write_all(text)
            .expect("write");
        let kept = [(0x3000, 0x5000), (0xe000, 0x10000), (0xf000, 0x11000)];
        let mut buf = [0u8; CHUNK];
        let mut out = [(0usize, 0usize); RANGES];
        let n = scan(fd.as_raw_fd(), &kept, &mut buf, &mut out).expect("scan");
        assert_eq!(
            out[..n],
            [
                (0x6000, 0x7000),
                (0x7000, 0x9000),
                (0x9000, 0xa000),
                (0xc000, 0xe000),
                (0x11000, 0x14000),
                (0x15000, 0x16000),
            ]
        );
        // A second pass reads from the start again.
        assert_eq!(scan(fd.as_raw_fd(), &kept, &mut buf, &mut out), Ok(n));
    }

    #[test]
    fn outside_kept_ranges() {
        let mut out = [(0usize, 0usize); RANGES];
        let mut n = 0;
        // Kept inside, at both edges, covering all, overlapping.
        outside(
            0x1000,
            0x9000,
            &[(0x2000, 0x3000), (0x5000, 0x6000)],
            &mut out,
            &mut n,
        );
        outside(0x10000, 0x12000, &[(0x10000, 0x11000)], &mut out, &mut n);
        outside(0x20000, 0x22000, &[(0x21000, 0x23000)], &mut out, &mut n);
        outside(0x30000, 0x31000, &[(0x2f000, 0x32000)], &mut out, &mut n);
        outside(
            0x40000,
            0x48000,
            &[(0x41000, 0x44000), (0x42000, 0x45000)],
            &mut out,
            &mut n,
        );
        assert_eq!(
            out[..n],
            [
                (0x1000, 0x2000),
                (0x3000, 0x5000),
                (0x6000, 0x9000),
                (0x11000, 0x12000),
                (0x20000, 0x21000),
                (0x40000, 0x41000),
                (0x45000, 0x48000),
            ]
        );
    }

    #[test]
    fn kept_ranges_are_windows_in_order() {
        let mut kept = [(0usize, 0usize); KEPT];
        let bss = [
            (0x7f00_0000_0000, 0x7f00_0000_8000),
            (0x5000_0000, 0x5000_2000),
        ];
        let stack = 0x7ffc_0010_0123;
        let caller = 0x7ffc_0010_4567;
        let tls = [0x7f10_0000_0800, 0x7f10_0000_0f00];
        // Mappings wide enough that no window is clipped.
        let wide = [
            (0x7ffc_0000_0000, 0x7ffc_0100_0000),
            (0x7f0f_0000_0000, 0x7f11_0000_0000),
            (0x7f0f_0000_0000, 0x7f11_0000_0000),
        ];
        let n = kept_ranges(&bss, 4096, stack, caller, tls, wide, &mut kept).expect("kept");
        assert_eq!(
            kept[..n],
            [
                (0x5000_0000, 0x5000_2000),
                (0x7f00_0000_0000, 0x7f00_0000_8000),
                // 64 KiB around each TLS address, page-aligned.
                (0x7f0f_ffff_0000, 0x7f10_0001_1000),
                (0x7f0f_ffff_0000, 0x7f10_0001_1000),
                // From 64 KiB under this frame up to the caller's page.
                (0x7ffc_000f_0000, 0x7ffc_0010_5000),
            ]
        );
        // Review of part 3, run 2: each window ends at the mapping that
        // holds its address, and a TLS window at the top of a stack does
        // not reach the mapping above or below.
        let tight = [
            (0x7ffc_000f_8000, 0x7ffc_0010_3000),
            (0x7f10_0000_0000, 0x7f10_0000_2000),
            (0x7f10_0000_0000, 0x7f10_0000_1000),
        ];
        let n = kept_ranges(&bss, 4096, stack, caller, tls, tight, &mut kept).expect("kept");
        assert_eq!(
            kept[..n],
            [
                (0x5000_0000, 0x5000_2000),
                (0x7f00_0000_0000, 0x7f00_0000_8000),
                (0x7f10_0000_0000, 0x7f10_0000_2000),
                (0x7f10_0000_0000, 0x7f10_0000_1000),
                (0x7ffc_000f_8000, 0x7ffc_0010_3000),
            ]
        );
        let many = [(0usize, 0usize); BSS_MAX + 1];
        assert_eq!(
            kept_ranges(&many, 4096, stack, caller, tls, wide, &mut kept),
            Err((6, libc::E2BIG))
        );
        assert_eq!(
            kept_ranges(&bss, 4096, caller, stack, tls, wide, &mut kept),
            Err((6, libc::EINVAL)),
            "a caller frame below this one"
        );
        assert_eq!(
            kept_ranges(&bss, 4095, stack, caller, tls, wide, &mut kept),
            Err((6, libc::EINVAL))
        );
    }

    #[test]
    fn mappings_holding_addresses() {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let text = b"1000-3000 rw-p 00000000 00:00 0 \n\
3000-4000 rw-p 00000000 00:00 0 [stack]\n\
8000-9000 r--p 00000000 00:1f 1 /lib/x.so\n";
        // SAFETY: the name is NUL-terminated; memfd_create takes flags.
        let fd = unsafe { libc::memfd_create(c"maps".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create");
        // SAFETY: memfd_create returned a new descriptor nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        std::fs::File::from(fd.try_clone().expect("dup"))
            .write_all(text)
            .expect("write");
        let mut buf = [0u8; CHUNK];
        assert_eq!(
            holding(fd.as_raw_fd(), &mut buf, [0x3800, 0x1000, 0x2fff]),
            Ok([(0x3000, 0x4000), (0x1000, 0x3000), (0x1000, 0x3000)])
        );
        assert_eq!(
            holding(fd.as_raw_fd(), &mut buf, [0x3800, 0x5000, 0x1000]),
            Err((6, libc::EFAULT)),
            "an address no mapping holds"
        );
    }
}
