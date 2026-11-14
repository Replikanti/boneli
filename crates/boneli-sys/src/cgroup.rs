//! cgroups v2 (ADR-007, D8).
//!
//! A sandbox runs in a cgroup of its own under a delegated parent, with a
//! memory, swap, task, CPU and IO limit that are all written and read back
//! before any process enters; `spawn` then places the child there at the
//! clone (`CLONE_INTO_CGROUP`). The parent and every sandbox cgroup are
//! opened once, and every file is reached relative to those descriptors
//! (`openat`, `mkdirat`, `unlinkat`), so no path is checked and then used
//! by name (ADR-007, D8).

use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::{Error, Result, errno};

/// The controllers every sandbox cgroup is limited by, in the order a
/// missing one is reported.
pub(crate) const CONTROLLERS: [&str; 4] = ["cpu", "io", "memory", "pids"];

/// The child cgroup `Parent::vacate_and_delegate` moves processes into.
const LEAF: &CStr = c"leaf";

/// How often `vacate_and_delegate` retries enabling the controllers after
/// a process forked into the cgroup between the moves and the write
/// (EBUSY, the no-internal-process rule).
const VACATE_RETRIES: usize = 3;

/// Hang bound of `destroy`'s wait for an empty cgroup after `cgroup.kill`:
/// the kill is synchronous in the kernel and exits take milliseconds.
const KILL_BOUND: Duration = Duration::from_secs(10);

/// The kernel's bounds of `cpu.max` in microseconds (`tg_set_cfs_bandwidth`:
/// quota and period at least 1 ms, period at most 1 s; measured).
const CPU_MIN_US: u64 = 1000;
const CPU_PERIOD_MAX_US: u64 = 1_000_000;

/// The page size of this host; the kernel rounds memory limits down to it,
/// and arm64 pages may be 4, 16 or 64 KiB.
pub(crate) fn page_size() -> u64 {
    // SAFETY: sysconf takes a plain name and has no memory arguments.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 { n as u64 } else { 4096 }
}

/// A device number, `major:minor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceNumber {
    /// The major number.
    pub major: u32,
    /// The minor number.
    pub minor: u32,
}

/// `cpu.max`: `quota_us` of CPU time per `period_us`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMax {
    /// At least 1000 µs.
    pub quota_us: u64,
    /// 1000 to 1,000,000 µs.
    pub period_us: u64,
}

/// One line of `io.max`: the limits of one whole disk. `None` is `max`
/// (unlimited); at least one field is set, and none is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoMax {
    /// The disk (not a partition: the kernel throttles per disk and gives
    /// ENODEV for a partition, measured); see [`block_device_of`].
    pub dev: DeviceNumber,
    /// Read bytes per second.
    pub rbps: Option<u64>,
    /// Written bytes per second.
    pub wbps: Option<u64>,
    /// Read operations per second.
    pub riops: Option<u64>,
    /// Write operations per second.
    pub wiops: Option<u64>,
}

/// The IO limits of a sandbox: at most one [`IoMax`] per device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoLimits(Vec<IoMax>);

impl IoLimits {
    /// No IO limit, said explicitly: a sandbox whose files live on tmpfs has
    /// no block device to limit (#8 decides when a limit is required).
    pub fn none() -> IoLimits {
        IoLimits(Vec::new())
    }

    /// Limits for these devices: no device twice, every entry sets a field,
    /// and no field is zero (the kernel answers ERANGE, measured).
    pub fn new(entries: Vec<IoMax>) -> Result<IoLimits> {
        for (i, e) in entries.iter().enumerate() {
            let fields = [e.rbps, e.wbps, e.riops, e.wiops];
            if fields.iter().all(Option::is_none) {
                return Err(Error::InvalidLimits(
                    "an io.max entry sets no field; leave the device out instead",
                ));
            }
            if fields.contains(&Some(0)) {
                return Err(Error::InvalidLimits(
                    "an io.max field is 0, which the kernel refuses (ERANGE)",
                ));
            }
            if entries[..i].iter().any(|o| o.dev == e.dev) {
                return Err(Error::InvalidLimits("an io.max device appears twice"));
            }
        }
        Ok(IoLimits(entries))
    }

    /// The entries.
    pub fn entries(&self) -> &[IoMax] {
        &self.0
    }
}

/// The limits of a sandbox's cgroup. No `Default`: the caller (#8) sizes
/// every one, and a sandbox never runs without all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// `memory.max` in bytes, at least one page; the kernel rounds it down
    /// to a page.
    pub memory_max: u64,
    /// `memory.swap.max` in bytes (0: no swap), rounded down to a page.
    pub memory_swap_max: u64,
    /// `pids.max`, the tasks (threads included), at least 1.
    pub pids_max: u64,
    /// `cpu.max`.
    pub cpu: CpuMax,
    /// `io.max`.
    pub io: IoLimits,
}

impl Limits {
    /// Checks the bounds: memory at least one page of this host, at least
    /// one task (0 is accepted by the kernel but leaves the sandbox unable
    /// to start), the CPU quota at least 1000 µs and the period 1000 to
    /// 1,000,000 µs (the kernel's bounds, measured).
    pub fn validate(&self) -> Result<()> {
        if self.memory_max < page_size() {
            return Err(Error::InvalidLimits("memory_max is below one page"));
        }
        if self.pids_max == 0 {
            return Err(Error::InvalidLimits("pids_max 0 admits no process"));
        }
        if self.cpu.quota_us < CPU_MIN_US {
            return Err(Error::InvalidLimits(
                "the cpu quota is below the kernel's 1000 us",
            ));
        }
        if !(CPU_MIN_US..=CPU_PERIOD_MAX_US).contains(&self.cpu.period_us) {
            return Err(Error::InvalidLimits(
                "the cpu period is outside the kernel's 1000-1000000 us",
            ));
        }
        Ok(())
    }
}

pub(crate) fn render_number(n: u64) -> String {
    n.to_string()
}

pub(crate) fn render_cpu(cpu: &CpuMax) -> String {
    format!("{} {}", cpu.quota_us, cpu.period_us)
}

/// One `io.max` line with every field, unset ones as `max`, in the order
/// the kernel prints them; a write sets all four, so no earlier value of
/// the device survives (the kernel merges a partial line with the old one,
/// measured).
pub(crate) fn render_io(io: &IoMax) -> String {
    let f = |v: Option<u64>| v.map_or_else(|| "max".to_string(), |n| n.to_string());
    format!(
        "{}:{} rbps={} wbps={} riops={} wiops={}",
        io.dev.major,
        io.dev.minor,
        f(io.rbps),
        f(io.wbps),
        f(io.riops),
        f(io.wiops)
    )
}

/// What a memory limit of `bytes` reads back as: rounded down to a page.
pub(crate) fn memory_read_back(bytes: u64, page: u64) -> u64 {
    bytes / page * page
}

/// A cgroup name: 1-255 bytes (`NAME_MAX`) of `[A-Za-z0-9_-]`. Every
/// interface file of cgroupfs has a `.` in its name, so such a name can
/// never collide with one, nor be `.` or `..`.
pub(crate) fn check_name(name: &str) -> Result<()> {
    let ok = (1..=255).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidCgroupName(name.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Descriptor-relative file access.

fn c_name(name: &str) -> CString {
    // Names here are this module's constants or checked names, without NUL.
    CString::new(name).unwrap_or_default()
}

/// Opens a cgroup directory by path once, without following any symlink.
fn open_dir_path(path: &Path) -> Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Nul("the cgroup path"))?;
    let how = crate::ffi::OpenHow {
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: c is NUL-terminated and how is a valid open_how of the size
    // passed, both for the call's duration.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c.as_ptr(),
            &how as *const crate::ffi::OpenHow,
            std::mem::size_of::<crate::ffi::OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(Error::last("openat2(cgroup directory)"));
    }
    // SAFETY: openat2 returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Opens the directory `name` beneath `dir`, not following a symlink.
fn open_dir_at(dir: &OwnedFd, name: &CStr) -> Result<OwnedFd> {
    // SAFETY: name is NUL-terminated; dir is an open directory.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::last("openat(cgroup directory)"));
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Fails unless `dir` is on a cgroup v2 file system.
fn check_cgroup2(dir: &OwnedFd, path: &Path) -> Result<()> {
    // SAFETY: an all-zero statfs is valid storage for fstatfs to fill.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: st is valid storage; dir is an open descriptor.
    if unsafe { libc::fstatfs(dir.as_raw_fd(), &mut st) } < 0 {
        return Err(Error::last("fstatfs"));
    }
    if st.f_type as u64 != libc::CGROUP2_SUPER_MAGIC as u64 {
        return Err(Error::NotCgroup2(path.to_path_buf()));
    }
    Ok(())
}

fn open_file(dir: &OwnedFd, file: &'static str, flags: c_int) -> Result<OwnedFd> {
    let name = c_name(file);
    // SAFETY: name is NUL-terminated; dir is an open directory.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::CgroupFile {
            file,
            errno: errno(),
        });
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Writes `data` to a file of `dir` in one `write`, as cgroupfs expects.
fn write_file(dir: &OwnedFd, file: &'static str, data: &[u8]) -> Result<()> {
    let fd = open_file(dir, file, libc::O_WRONLY)?;
    // SAFETY: data is valid for its length; fd was just opened.
    let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };
    if n < 0 {
        return Err(Error::CgroupFile {
            file,
            errno: errno(),
        });
    }
    if n as usize != data.len() {
        return Err(Error::CgroupFile {
            file,
            errno: libc::EIO,
        });
    }
    Ok(())
}

/// Reads a whole file from offset 0 of an open descriptor.
fn read_fd(fd: &OwnedFd, file: &'static str) -> Result<String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: buf is valid writable memory of the length passed.
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                out.len() as libc::off_t,
            )
        };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(Error::CgroupFile {
                file,
                errno: errno(),
            });
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    String::from_utf8(out).map_err(|_| Error::CgroupFile {
        file,
        errno: libc::EILSEQ,
    })
}

fn read_file(dir: &OwnedFd, file: &'static str) -> Result<String> {
    let fd = open_file(dir, file, libc::O_RDONLY)?;
    read_fd(&fd, file)
}

/// Fails with `ControllerMissing` for the first of the four controllers
/// that `file` (`cgroup.subtree_control` or `cgroup.controllers`) lacks.
fn check_controllers(dir: &OwnedFd, file: &'static str) -> Result<()> {
    let text = read_file(dir, file)?;
    let have: Vec<&str> = text.split_whitespace().collect();
    match CONTROLLERS.into_iter().find(|c| !have.contains(c)) {
        Some(missing) => Err(Error::ControllerMissing(missing)),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// The parent.

/// A delegated cgroup v2 directory that has the cpu, io, memory and pids
/// controllers enabled for its children; sandbox cgroups are created in
/// it. Held open: everything below goes through this descriptor.
#[derive(Debug)]
pub struct Parent {
    dir: OwnedFd,
    path: PathBuf,
}

impl Parent {
    /// Opens `path` (resolved without following any symlink, so callers
    /// pass a canonical path) and checks that it is on cgroup v2 and that
    /// its `cgroup.subtree_control` holds cpu, io, memory and pids, else
    /// [`Error::ControllerMissing`]: no sandbox runs without a limit.
    pub fn open(path: &Path) -> Result<Parent> {
        let dir = open_dir_path(path)?;
        check_cgroup2(&dir, path)?;
        check_controllers(&dir, "cgroup.subtree_control")?;
        Ok(Parent {
            dir,
            path: path.to_path_buf(),
        })
    }

    /// Makes the delegated cgroup `path` a parent: moves every process of
    /// its `cgroup.procs` into `path/leaf` (created if missing), then
    /// enables the four controllers for its children, which the kernel
    /// allows only in a cgroup without processes (the no-internal-process
    /// rule). A process forked into `path` between the moves and the write
    /// makes the write fail with EBUSY; the moves are retried up to 3 times.
    ///
    /// A production runner calls this once, in its own `Delegate=yes`
    /// service; the test harness only with `BONELI_SYS_TEST_CGROUP=self`,
    /// so a terminal's cgroup is never reorganized.
    pub fn vacate_and_delegate(path: &Path) -> Result<Parent> {
        let dir = open_dir_path(path)?;
        check_cgroup2(&dir, path)?;
        check_controllers(&dir, "cgroup.controllers")?;
        // SAFETY: LEAF is NUL-terminated; dir is an open directory.
        if unsafe { libc::mkdirat(dir.as_raw_fd(), LEAF.as_ptr(), 0o755) } < 0
            && errno() != libc::EEXIST
        {
            return Err(Error::last("mkdirat(leaf)"));
        }
        let leaf = open_dir_at(&dir, LEAF)?;
        check_cgroup2(&leaf, &path.join("leaf"))?;
        let control = CONTROLLERS.map(|c| format!("+{c}")).join(" ");
        let mut attempt = 0;
        loop {
            for pid in read_file(&dir, "cgroup.procs")?.split_whitespace() {
                match write_file(&leaf, "cgroup.procs", pid.as_bytes()) {
                    Ok(()) => {}
                    // The process exited since the read.
                    Err(Error::CgroupFile {
                        errno: libc::ESRCH, ..
                    }) => {}
                    Err(e) => return Err(e),
                }
            }
            match write_file(&dir, "cgroup.subtree_control", control.as_bytes()) {
                Ok(()) => break,
                Err(Error::CgroupFile {
                    errno: libc::EBUSY, ..
                }) if attempt < VACATE_RETRIES => attempt += 1,
                Err(e) => return Err(e),
            }
        }
        check_controllers(&dir, "cgroup.subtree_control")?;
        Ok(Parent {
            dir,
            path: path.to_path_buf(),
        })
    }

    /// The path it was opened at (for messages; nothing is opened by it
    /// again).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ---------------------------------------------------------------------------
// A sandbox's cgroup.

/// A sandbox's cgroup, with every limit in place. `spawn` places its child
/// here at the clone. Dropping it without [`Cgroup::destroy`] kills what
/// runs in it and removes it, ignoring errors.
#[derive(Debug)]
pub struct Cgroup {
    dir: OwnedFd,
    parent: OwnedFd,
    name: CString,
    path: PathBuf,
    live: bool,
}

impl Cgroup {
    /// Creates the cgroup `name` under `parent` and writes every limit,
    /// then reads each back (memory rounded down to a page) before any
    /// process can enter: `memory.oom.group` 1, `memory.swap.max`,
    /// `memory.max`, `pids.max`, `cpu.max` and one `io.max` line per
    /// device. `memory.oom.group` is always 1, because a partial OOM kill
    /// leaves a half-dead pod whose test results mislead (ADR-007, D8).
    /// On any error the directory is removed again.
    pub fn create(parent: &Parent, name: &str, limits: &Limits) -> Result<Cgroup> {
        limits.validate()?;
        check_name(name)?;
        let cname = c_name(name);
        // SAFETY: cname is NUL-terminated; the parent is an open directory.
        if unsafe { libc::mkdirat(parent.dir.as_raw_fd(), cname.as_ptr(), 0o755) } < 0 {
            return Err(Error::last("mkdirat(cgroup)"));
        }
        let parent_fd = match parent.dir.try_clone() {
            Ok(fd) => fd,
            Err(e) => {
                // SAFETY: cname is NUL-terminated; removes what was just made.
                unsafe {
                    libc::unlinkat(parent.dir.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR)
                };
                return Err(Error::Sys {
                    call: "fcntl(F_DUPFD_CLOEXEC)",
                    errno: e.raw_os_error().unwrap_or(libc::EIO),
                });
            }
        };
        let dir = match open_dir_at(&parent.dir, &cname) {
            Ok(fd) => fd,
            Err(e) => {
                // SAFETY: as above.
                unsafe {
                    libc::unlinkat(parent.dir.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR)
                };
                return Err(e);
            }
        };
        // From here on, dropping `cg` removes the directory.
        let cg = Cgroup {
            dir,
            parent: parent_fd,
            name: cname,
            path: parent.path.join(name),
            live: true,
        };
        check_cgroup2(&cg.dir, &cg.path)?;
        cg.write_limits(limits)?;
        cg.check_limits(limits)?;
        Ok(cg)
    }

    fn write_limits(&self, l: &Limits) -> Result<()> {
        write_file(&self.dir, "memory.oom.group", b"1")?;
        write_file(
            &self.dir,
            "memory.swap.max",
            render_number(l.memory_swap_max).as_bytes(),
        )?;
        write_file(
            &self.dir,
            "memory.max",
            render_number(l.memory_max).as_bytes(),
        )?;
        write_file(&self.dir, "pids.max", render_number(l.pids_max).as_bytes())?;
        write_file(&self.dir, "cpu.max", render_cpu(&l.cpu).as_bytes())?;
        for io in l.io.entries() {
            write_file(&self.dir, "io.max", render_io(io).as_bytes())?;
        }
        Ok(())
    }

    fn check_limits(&self, l: &Limits) -> Result<()> {
        let page = page_size();
        let expect = |file: &'static str, want: String| -> Result<()> {
            let found = read_file(&self.dir, file)?;
            if found.trim_end() == want {
                Ok(())
            } else {
                Err(Error::CgroupReadBack {
                    file,
                    expected: want,
                    found: found.trim_end().to_string(),
                })
            }
        };
        expect("memory.oom.group", "1".to_string())?;
        expect(
            "memory.swap.max",
            render_number(memory_read_back(l.memory_swap_max, page)),
        )?;
        expect(
            "memory.max",
            render_number(memory_read_back(l.memory_max, page)),
        )?;
        expect("pids.max", render_number(l.pids_max))?;
        expect("cpu.max", render_cpu(&l.cpu))?;
        let mut want: Vec<String> = l.io.entries().iter().map(render_io).collect();
        want.sort();
        let text = read_file(&self.dir, "io.max")?;
        let mut found: Vec<&str> = text.lines().collect();
        found.sort_unstable();
        if found != want {
            return Err(Error::CgroupReadBack {
                file: "io.max",
                expected: want.join("; "),
                found: found.join("; "),
            });
        }
        Ok(())
    }

    /// The cgroup's directory descriptor, which `clone3` takes.
    pub(crate) fn dir_fd(&self) -> RawFd {
        self.dir.as_raw_fd()
    }

    /// The path it was created at (for messages and reading statistics).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Kills every process in the cgroup (`cgroup.kill`), waits until it is
    /// empty (`populated 0` in `cgroup.events`, at most 10 s), and removes
    /// it. A killed child that was not reaped yet does not keep it
    /// populated (measured); its [`crate::Child`] still reaps it.
    pub fn destroy(mut self) -> Result<()> {
        self.live = false;
        self.kill_and_remove()
    }

    fn kill_and_remove(&self) -> Result<()> {
        write_file(&self.dir, "cgroup.kill", b"1")?;
        let events = open_file(&self.dir, "cgroup.events", libc::O_RDONLY)?;
        let deadline = Instant::now() + KILL_BOUND;
        loop {
            let text = read_fd(&events, "cgroup.events")?;
            if text.lines().any(|l| l.trim() == "populated 0") {
                break;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::CgroupKillTimeout(KILL_BOUND));
            }
            // cgroup.events signals a change with POLLPRI; the 100 ms cap
            // re-reads it even if a notification was missed.
            let mut pfd = libc::pollfd {
                fd: events.as_raw_fd(),
                events: libc::POLLPRI,
                revents: 0,
            };
            let ms = left.as_millis().clamp(1, 100) as c_int;
            // SAFETY: pfd is one valid pollfd for the call's duration.
            unsafe { libc::poll(&mut pfd, 1, ms) };
        }
        // SAFETY: the name is NUL-terminated; the parent is an open directory.
        let rc = unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        };
        if rc < 0 {
            return Err(Error::last("unlinkat(cgroup)"));
        }
        Ok(())
    }

    /// A value that never was a cgroup, for the unit tests that fail before
    /// the clone; nothing is removed on drop.
    #[cfg(test)]
    pub(crate) fn unplaced() -> Cgroup {
        let dir = open_dir_path(Path::new("/")).expect("open /");
        let parent = dir.try_clone().expect("dup");
        Cgroup {
            dir,
            parent,
            name: c"unplaced".to_owned(),
            path: PathBuf::from("/"),
            live: false,
        }
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if self.live {
            let _ = self.kill_and_remove();
        }
    }
}

// ---------------------------------------------------------------------------
// Which disk a path lives on.

/// One line of `/proc/self/mountinfo`, the fields used here.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MountEntry {
    pub mount_id: u64,
    pub fstype: Vec<u8>,
    pub source: Vec<u8>,
}

/// Decodes the kernel's `\ooo` escapes of mountinfo (space `\040`, tab
/// `\011`, newline `\012`, backslash `\134`); anything else stays as it is.
pub(crate) fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\' && i + 3 < field.len() {
            let d = &field[i + 1..i + 4];
            // At most \377: three octal digits, the first 0-3.
            if d[0] <= b'3' && d.iter().all(|c| (b'0'..=b'7').contains(c)) {
                out.push((d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0'));
                i += 4;
                continue;
            }
        }
        out.push(field[i]);
        i += 1;
    }
    out
}

/// The lines of a mountinfo text, as bytes: mount paths may hold any byte
/// but NUL, so the text need not be UTF-8. Malformed lines are skipped.
pub(crate) fn parse_mountinfo(text: &[u8]) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.split(|&b| b == b'\n') {
        let fields: Vec<&[u8]> = line.split(|&b| b == b' ').collect();
        // The optional fields end with "-", after the six fixed ones.
        let Some(dash) = fields
            .iter()
            .skip(6)
            .position(|f| *f == b"-")
            .map(|p| p + 6)
        else {
            continue;
        };
        let id = fields
            .first()
            .and_then(|f| std::str::from_utf8(f).ok())
            .and_then(|f| f.parse().ok());
        let (Some(id), Some(fstype), Some(source)) =
            (id, fields.get(dash + 1), fields.get(dash + 2))
        else {
            continue;
        };
        out.push(MountEntry {
            mount_id: id,
            fstype: unescape(fstype),
            source: unescape(source),
        });
    }
    out
}

/// What [`resolve_device`] asks the host, so the mapping is testable on
/// fixture text.
pub(crate) trait BlockLookup {
    /// Whether `/sys/dev/block/<d>` exists.
    fn is_block(&self, d: DeviceNumber) -> bool;
    /// The whole disk of a block device: itself, or for a partition its
    /// parent's number.
    fn disk_of(&self, d: DeviceNumber) -> Option<DeviceNumber>;
    /// The device number of a block device node at an absolute path.
    fn node(&self, source: &[u8]) -> Option<DeviceNumber>;
}

/// The disk behind a file with `st_dev` on the mount `mount_id`: `st_dev`
/// itself if it is a block device, else (an anonymous device, as btrfs
/// gives) the mount's source node from mountinfo; either mapped from a
/// partition to its disk. `None` when there is none (tmpfs, overlay).
pub(crate) fn resolve_device(
    st_dev: DeviceNumber,
    mount_id: u64,
    mountinfo: &[u8],
    sys: &dyn BlockLookup,
) -> Option<DeviceNumber> {
    if sys.is_block(st_dev) {
        return sys.disk_of(st_dev);
    }
    let entries = parse_mountinfo(mountinfo);
    let entry = entries.iter().find(|e| e.mount_id == mount_id)?;
    if entry.source.first() != Some(&b'/') {
        return None;
    }
    let node = sys.node(&entry.source)?;
    if !sys.is_block(node) {
        return None;
    }
    sys.disk_of(node)
}

/// The host's sysfs and `/dev`.
struct HostBlocks;

fn sys_path(d: DeviceNumber) -> PathBuf {
    PathBuf::from(format!("/sys/dev/block/{}:{}", d.major, d.minor))
}

fn parse_dev(text: &str) -> Option<DeviceNumber> {
    let (major, minor) = text.trim().split_once(':')?;
    Some(DeviceNumber {
        major: major.parse().ok()?,
        minor: minor.parse().ok()?,
    })
}

impl BlockLookup for HostBlocks {
    fn is_block(&self, d: DeviceNumber) -> bool {
        sys_path(d).exists()
    }

    fn disk_of(&self, d: DeviceNumber) -> Option<DeviceNumber> {
        let at = sys_path(d);
        if !at.join("partition").exists() {
            return Some(d);
        }
        // /sys/dev/block/M:m is a link into the disk's directory; `..`
        // from there is the disk (the kernel resolves `..` after the link).
        parse_dev(&std::fs::read_to_string(at.join("../dev")).ok()?)
    }

    fn node(&self, source: &[u8]) -> Option<DeviceNumber> {
        let c = CString::new(source).ok()?;
        // SAFETY: an all-zero stat is valid storage for stat to fill.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: c is NUL-terminated and st is valid storage.
        if unsafe { libc::stat(c.as_ptr(), &mut st) } < 0 {
            return None;
        }
        if st.st_mode & libc::S_IFMT != libc::S_IFBLK {
            return None;
        }
        Some(DeviceNumber {
            major: libc::major(st.st_rdev),
            minor: libc::minor(st.st_rdev),
        })
    }
}

/// The disk a path lives on, for [`IoMax::dev`]: the file system's device
/// if it is a block device, else the mount's source device (btrfs and
/// other file systems with anonymous device numbers), a partition mapped
/// to its disk; [`Error::NoBlockDevice`] for tmpfs and anything else
/// without one. The mount is found by its id (`statx` `STATX_MNT_ID`), not
/// by `st_dev`, which a nested btrfs subvolume does not share with any
/// mountinfo line. A lookup only: nothing found here is mounted.
pub fn block_device_of(path: &Path) -> Result<DeviceNumber> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Nul("the path"))?;
    // SAFETY: an all-zero statx is valid storage for statx to fill.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: c is NUL-terminated and stx is valid storage.
    let rc = unsafe { libc::statx(libc::AT_FDCWD, c.as_ptr(), 0, libc::STATX_MNT_ID, &mut stx) };
    if rc < 0 {
        return Err(Error::last("statx"));
    }
    if stx.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(Error::Sys {
            call: "statx(STATX_MNT_ID)",
            errno: libc::ENOSYS,
        });
    }
    let mountinfo = std::fs::read("/proc/self/mountinfo").map_err(|e| Error::Sys {
        call: "read /proc/self/mountinfo",
        errno: e.raw_os_error().unwrap_or(libc::EIO),
    })?;
    let st_dev = DeviceNumber {
        major: stx.stx_dev_major,
        minor: stx.stx_dev_minor,
    };
    resolve_device(st_dev, stx.stx_mnt_id, &mountinfo, &HostBlocks)
        .ok_or_else(|| Error::NoBlockDevice(path.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(quota_us: u64, period_us: u64) -> CpuMax {
        CpuMax {
            quota_us,
            period_us,
        }
    }

    fn base() -> Limits {
        Limits {
            memory_max: 64 << 20,
            memory_swap_max: 0,
            pids_max: 16,
            cpu: cpu(100_000, 100_000),
            io: IoLimits::none(),
        }
    }

    fn dev(major: u32, minor: u32) -> DeviceNumber {
        DeviceNumber { major, minor }
    }

    fn io(dev: DeviceNumber, wbps: Option<u64>) -> IoMax {
        IoMax {
            dev,
            rbps: None,
            wbps,
            riops: None,
            wiops: None,
        }
    }

    #[test]
    fn limits_validation() {
        let page = page_size();
        let with = |f: &dyn Fn(&mut Limits)| {
            let mut l = base();
            f(&mut l);
            l.validate()
        };
        assert!(base().validate().is_ok());
        assert!(matches!(
            with(&|l| l.memory_max = page - 1),
            Err(Error::InvalidLimits(_))
        ));
        assert!(with(&|l| l.memory_max = page).is_ok());
        assert!(matches!(
            with(&|l| l.pids_max = 0),
            Err(Error::InvalidLimits(_))
        ));
        assert!(with(&|l| l.pids_max = 1).is_ok());
        assert!(matches!(
            with(&|l| l.cpu = cpu(999, 100_000)),
            Err(Error::InvalidLimits(_))
        ));
        assert!(with(&|l| l.cpu = cpu(1000, 100_000)).is_ok());
        assert!(matches!(
            with(&|l| l.cpu = cpu(1000, 999)),
            Err(Error::InvalidLimits(_))
        ));
        assert!(with(&|l| l.cpu = cpu(1000, 1000)).is_ok());
        assert!(with(&|l| l.cpu = cpu(1000, 1_000_000)).is_ok());
        assert!(matches!(
            with(&|l| l.cpu = cpu(1000, 1_000_001)),
            Err(Error::InvalidLimits(_))
        ));
        assert!(with(&|l| l.memory_swap_max = 0).is_ok());

        // IO: one entry per device, at least one field, no zero rate (the
        // kernel answers ERANGE, measured).
        assert!(IoLimits::new(vec![io(dev(8, 0), Some(1))]).is_ok());
        assert!(matches!(
            IoLimits::new(vec![io(dev(8, 0), Some(1)), io(dev(8, 0), Some(2))]),
            Err(Error::InvalidLimits(_))
        ));
        assert!(
            IoLimits::new(vec![io(dev(8, 0), Some(1)), io(dev(8, 16), Some(2))]).is_ok(),
            "two devices"
        );
        assert!(matches!(
            IoLimits::new(vec![io(dev(8, 0), None)]),
            Err(Error::InvalidLimits(_))
        ));
        assert!(matches!(
            IoLimits::new(vec![io(dev(8, 0), Some(0))]),
            Err(Error::InvalidLimits(_))
        ));
        let mut zero_riops = io(dev(8, 0), None);
        zero_riops.riops = Some(0);
        assert!(matches!(
            IoLimits::new(vec![zero_riops]),
            Err(Error::InvalidLimits(_))
        ));
        assert!(IoLimits::none().entries().is_empty());
    }

    #[test]
    fn limit_files_render() {
        assert_eq!(render_number(33_554_432), "33554432");
        assert_eq!(render_cpu(&cpu(50_000, 100_000)), "50000 100000");
        assert_eq!(
            render_io(&io(dev(8, 0), Some(4_194_304))),
            "8:0 rbps=max wbps=4194304 riops=max wiops=max"
        );
        let all = IoMax {
            dev: dev(252, 3),
            rbps: Some(1),
            wbps: Some(2),
            riops: Some(3),
            wiops: Some(4),
        };
        assert_eq!(render_io(&all), "252:3 rbps=1 wbps=2 riops=3 wiops=4");
        // The kernel rounds memory limits down to a page.
        let page = page_size();
        assert_eq!(memory_read_back(page + 1, page), page);
        assert_eq!(memory_read_back(33_554_433, 4096), 33_554_432);
        assert_eq!(memory_read_back(0, 4096), 0);
    }

    #[test]
    fn cgroup_name_forms() {
        for ok in ["a", "sandbox-1", "A_b-9", &"x".repeat(255)] {
            assert!(check_name(ok).is_ok(), "{ok:?}");
        }
        // Every interface file of cgroupfs has a '.', so a name without
        // one can never collide with a file or be '.' or '..'.
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "memory.max",
            "a\0b",
            "a b",
            "a\nb",
            "ä",
            &"x".repeat(256),
        ] {
            assert!(
                matches!(check_name(bad), Err(Error::InvalidCgroupName(_))),
                "{bad:?}"
            );
        }
    }

    /// The kernel's `mangle` for mountinfo: space, tab, newline and
    /// backslash as `\ooo`.
    fn mangle(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for &b in bytes {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\\') {
                out.extend_from_slice(format!("\\{b:03o}").as_bytes());
            } else {
                out.push(b);
            }
        }
        out
    }

    struct FakeSys {
        block: Vec<DeviceNumber>,
        partitions: Vec<(DeviceNumber, DeviceNumber)>,
        nodes: Vec<(Vec<u8>, DeviceNumber)>,
    }

    impl BlockLookup for FakeSys {
        fn is_block(&self, d: DeviceNumber) -> bool {
            self.block.contains(&d)
        }
        fn disk_of(&self, d: DeviceNumber) -> Option<DeviceNumber> {
            Some(
                self.partitions
                    .iter()
                    .find(|(p, _)| *p == d)
                    .map_or(d, |(_, disk)| *disk),
            )
        }
        fn node(&self, source: &[u8]) -> Option<DeviceNumber> {
            self.nodes
                .iter()
                .find(|(s, _)| s == source)
                .map(|(_, d)| *d)
        }
    }

    const MOUNTINFO: &[u8] = b"\
22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw
25 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 25 0:43 /home /home rw,relatime shared:2 - btrfs /dev/mapper/luks\\040disk\\134x rw,seclabel
41 25 0:44 / /tmp rw,nosuid,nodev shared:3 master:1 - tmpfs tmpfs rw,size=1g
42 25 0:45 / /weird\\040mount rw - btrfs /dev/vdb rw
43 25 0:46 / /not-utf8-\xff rw - tmpfs tmpfs rw
";

    #[test]
    fn mountinfo_and_device_mapping() {
        // Decoding: exact for the escapes the kernel writes.
        assert_eq!(
            unescape(b"/dev/mapper/luks\\040disk\\134x"),
            b"/dev/mapper/luks disk\\x"
        );
        assert_eq!(unescape(b"a\\011b\\012c"), b"a\tb\nc");
        // Anything that is not a three-digit octal escape stays as it is.
        assert_eq!(unescape(b"a\\9b\\04"), b"a\\9b\\04");
        // decode(encode(x)) = x for every byte 0x01-0xff, alone and in a run.
        let all: Vec<u8> = (1..=255u8).collect();
        assert_eq!(unescape(&mangle(&all)), all);
        for b in 1..=255u8 {
            assert_eq!(unescape(&mangle(&[b])), [b], "byte {b:#x}");
        }

        let entries = parse_mountinfo(MOUNTINFO);
        assert_eq!(entries.len(), 6, "a mount path need not be UTF-8");
        let home = entries.iter().find(|e| e.mount_id == 40).expect("40");
        assert_eq!(home.fstype, b"btrfs");
        assert_eq!(home.source, b"/dev/mapper/luks disk\\x");
        let tmp = entries.iter().find(|e| e.mount_id == 41).expect("41");
        assert_eq!(tmp.fstype, b"tmpfs", "optional fields skipped");

        let sys = FakeSys {
            block: vec![dev(8, 0), dev(8, 1), dev(252, 0)],
            partitions: vec![(dev(8, 1), dev(8, 0))],
            nodes: vec![
                (b"/dev/mapper/luks disk\\x".to_vec(), dev(252, 0)),
                (b"/dev/sda1".to_vec(), dev(8, 1)),
            ],
        };
        // ext4 on a partition: st_dev is the partition, mapped to its disk.
        assert_eq!(
            resolve_device(dev(8, 1), 25, MOUNTINFO, &sys),
            Some(dev(8, 0))
        );
        // btrfs: an anonymous st_dev; the mount's source node is the device.
        assert_eq!(
            resolve_device(dev(0, 43), 40, MOUNTINFO, &sys),
            Some(dev(252, 0))
        );
        // A nested btrfs subvolume has an st_dev no line carries; the mount
        // id still finds the mount.
        assert_eq!(
            resolve_device(dev(0, 77), 40, MOUNTINFO, &sys),
            Some(dev(252, 0))
        );
        // tmpfs: no block device.
        assert_eq!(resolve_device(dev(0, 44), 41, MOUNTINFO, &sys), None);
        // A source without a device node, and an unknown mount.
        assert_eq!(resolve_device(dev(0, 45), 42, MOUNTINFO, &sys), None);
        assert_eq!(resolve_device(dev(0, 99), 99, MOUNTINFO, &sys), None);
    }
}
