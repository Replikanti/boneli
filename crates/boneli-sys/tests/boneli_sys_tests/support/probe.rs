//! The probe side: what this test binary does when it is re-executed
//! inside a sandbox. Every action prints `BONELI_PROBE key=value` lines and
//! exits 0; an unknown action exits 1, a broken input 2, a failed
//! measurement 3. (97 is the allocation guard's.)

use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

/// The variable naming the probe's action.
pub const ACTION_VAR: &str = "BONELI_SYS_PROBE";
/// The prefix of every probe line.
pub const PREFIX: &str = "BONELI_PROBE ";

fn put(key: &str, value: &str) {
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{PREFIX}{key}={value}");
    let _ = out.flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn fail(code: i32, why: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "probe: {why}");
    exit(code)
}

/// Ends the probe with `code` through `_exit`, after flushing stdout.
///
/// Not `std::process::exit`: its runtime cleanup unmaps the main thread's
/// alternate signal stack from the calling thread, and the probe runs in
/// libtest's test thread. A probe that calls glibc's `setuid` or
/// `setgroups` makes every thread run the `SIGSETXID` handler, on that
/// stack (glibc installs it with `SA_ONSTACK`), and the handler wakes the
/// caller before it has returned. If the probe thread then unmapped the
/// stack first, the main thread died with SIGSEGV in the handler's
/// epilogue (seen once in a host run and forced under gdb).
fn exit(code: i32) -> ! {
    let _ = std::io::stdout().flush();
    // SAFETY: _exit ends the process at once; nothing is left to run.
    unsafe { libc::_exit(code) }
}

fn input(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fail(2, &format!("{name} is not set")))
}

fn input_id(name: &str) -> u32 {
    input(name)
        .parse()
        .unwrap_or_else(|_| fail(2, &format!("{name} is not a number")))
}

fn c_path(path: &str) -> CString {
    CString::new(path).unwrap_or_else(|_| fail(2, "path with NUL"))
}

/// A map file as `inside host count` triples joined by `;`, whitespace
/// normalized (the kernel pads the columns).
fn map_lines(path: &str) -> String {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| fail(3, &format!("read {path}: {e}")));
    text.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(";")
}

/// Runs `action` and exits.
pub fn main(action: &str) -> ! {
    match action {
        "ids" => ids(),
        "setuid" => setuid(),
        "chown" => chown(),
        "create-file" => create_file(),
        "groups" => groups(),
        "fds-env" => fds_env(),
        "session" => session(),
        "features" => features(),
        "closed-stdio-spawn" => closed_stdio_spawn(),
        "pid" => pid(),
        "net" => net(),
        "shm" => shm(),
        "uname" => uname(),
        "cgroup" => cgroup(),
        "mounts" => mounts(),
        "writes" => writes(),
        "read" => read(),
        "fill" => fill(),
        "connect" => connect(),
        "connect-abstract" => connect_abstract(),
        "dev" => dev(),
        "write" => write(),
        "oom" => oom(),
        "pids" => pids(),
        "spin" => spin(),
        "io-write" => io_write(),
        "oom-adj-spawn" => oom_adj_spawn(),
        "seccomp-rows" => seccomp_rows(),
        "int80" => int80(),
        "caps" => caps(),
        "securebits" => securebits(),
        "filter-reach" => filter_reach(),
        "clone3-fallback" => clone3_fallback(),
        "cgroup-view" => cgroup_view(),
        "landlock" => landlock(),
        _ => fail(1, &format!("unknown action {action}")),
    }
    exit(0)
}

fn ids() {
    // SAFETY: getuid and getgid have no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    // SAFETY: as above.
    let gid = unsafe { libc::getgid() };
    put("uid", &uid.to_string());
    put("gid", &gid.to_string());
    put("uid_map", &map_lines("/proc/self/uid_map"));
    put("gid_map", &map_lines("/proc/self/gid_map"));
    let setgroups = std::fs::read_to_string("/proc/self/setgroups")
        .unwrap_or_else(|e| fail(3, &format!("read setgroups: {e}")));
    put("setgroups", setgroups.trim());
}

fn setuid() {
    let id = input_id("BONELI_PROBE_ID");
    // SAFETY: setuid takes a plain integer; failure is reported via errno.
    let rc = unsafe { libc::setuid(id) };
    put("errno", &if rc == 0 { 0 } else { errno() }.to_string());
}

fn chown() {
    let file = c_path(&input("BONELI_PROBE_FILE"));
    let id = input_id("BONELI_PROBE_ID");
    // SAFETY: file is a valid NUL-terminated path; gid -1 leaves the group.
    let rc = unsafe { libc::chown(file.as_ptr(), id, u32::MAX) };
    put("errno", &if rc == 0 { 0 } else { errno() }.to_string());
}

fn create_file() {
    let file = input("BONELI_PROBE_FILE");
    std::fs::write(&file, b"probe").unwrap_or_else(|e| fail(3, &format!("create {file}: {e}")));
    let stat = input("BONELI_PROBE_STAT");
    let root = std::fs::metadata(&stat).unwrap_or_else(|e| fail(3, &format!("stat {stat}: {e}")));
    use std::os::unix::fs::MetadataExt;
    put("root_uid", &root.uid().to_string());
    put("root_gid", &root.gid().to_string());
}

fn groups() {
    let mut list = [0 as libc::gid_t; 1024];
    // SAFETY: list holds 1024 entries and the size passed says so.
    let n = unsafe { libc::getgroups(list.len() as i32, list.as_mut_ptr()) };
    if n < 0 {
        fail(3, &format!("getgroups: errno {}", errno()));
    }
    let shown: Vec<String> = list[..n as usize].iter().map(|g| g.to_string()).collect();
    put("groups", &shown.join(","));
    // SAFETY: an empty list with a null pointer is valid for setgroups.
    let rc = unsafe { libc::setgroups(0, std::ptr::null()) };
    put(
        "setgroups_errno",
        &if rc == 0 { 0 } else { errno() }.to_string(),
    );
}

fn fds_env() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit is a valid rlimit for getrlimit to fill.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    if rc != 0 {
        fail(3, "getrlimit");
    }
    let top = limit.rlim_cur.min(1 << 20) as i32;
    let mut open = Vec::new();
    for fd in 0..top {
        // SAFETY: F_GETFD only reads the descriptor flags; an fd that is
        // not open gives EBADF.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0 {
            open.push(fd.to_string());
        }
    }
    put("fds", &open.join(","));
    for (k, v) in std::env::vars_os() {
        put(
            "env",
            &format!(
                "{}={}",
                String::from_utf8_lossy(k.as_bytes()),
                String::from_utf8_lossy(v.as_bytes())
            ),
        );
    }
}

fn session() {
    // SAFETY: getpid and getsid(0) have no preconditions.
    let pid = unsafe { libc::getpid() };
    // SAFETY: as above.
    let sid = unsafe { libc::getsid(0) };
    put("pid", &pid.to_string());
    put("sid", &sid.to_string());
    // SAFETY: the path is a valid C string; the fd, if any, is closed below.
    let fd = unsafe {
        libc::open(
            c"/dev/tty".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY,
        )
    };
    if fd >= 0 {
        // SAFETY: fd was just opened by this function.
        unsafe { libc::close(fd) };
        put("tty_errno", "0");
    } else {
        put("tty_errno", &errno().to_string());
    }
}

/// This process's AppArmor label, or `none` where AppArmor is absent.
pub fn apparmor_label() -> String {
    [
        "/proc/self/attr/apparmor/current",
        "/proc/self/attr/current",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok())
    .map(|l| {
        l.trim_matches(|c: char| c.is_whitespace() || c == '\0')
            .to_string()
    })
    .unwrap_or_else(|| "none".to_string())
}

fn features() {
    put("label", &apparmor_label());
    let ids = match boneli_sys::Features::probe() {
        Ok(()) => String::new(),
        Err(missing) => missing
            .iter()
            .map(|m| m.id().as_str())
            .collect::<Vec<_>>()
            .join(","),
    };
    put("missing", &ids);
}

/// Spawns a missing program with descriptors 0-2 closed in this process
/// (a daemonized runner): the report pipe must not land on 0-2, where the
/// child's stdio `dup2` would replace it. Exits 0 when spawn returns
/// `Setup { Exec, ENOENT }`, else writes what it got to `BONELI_PROBE_FILE`
/// and exits 3. This process is not sandboxed: the host test runs it
/// directly, so closing its stdio cannot disturb other tests.
fn closed_stdio_spawn() {
    let out = input("BONELI_PROBE_FILE");
    let null = || -> std::os::fd::OwnedFd {
        std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap_or_else(|e| fail(3, &format!("open /dev/null: {e}")))
            .into()
    };
    // Opened while 0-2 are still open, so they sit at 3 and above.
    let stdio = boneli_sys::Stdio {
        stdin: null(),
        stdout: null(),
        stderr: null(),
    };
    for fd in 0..3 {
        // SAFETY: closing this process's own stdio descriptors; nothing
        // else in this process uses them from here on.
        unsafe { libc::close(fd) };
    }
    let cg = crate::support::cgroup::sandbox("closed-stdio");
    let spec = boneli_sys::Spec {
        program: "/nonexistent/boneli-sys-probe".into(),
        args: Vec::new(),
        env: Vec::new(),
        stdio,
        ids: boneli_sys::Ids::new(0, 0).unwrap_or_else(|e| fail(3, &e.to_string())),
        setup_timeout: std::time::Duration::from_secs(10),
        root: boneli_sys::Root {
            layers: vec![input("BONELI_PROBE_LAYER").into()],
            staging: input("BONELI_PROBE_STAGING").into(),
            mounts: Vec::new(),
            hostname: boneli_sys::Hostname::new("closed-stdio")
                .unwrap_or_else(|e| fail(3, &e.to_string())),
            cwd: boneli_sys::InsidePath::root(),
        },
        cgroup: &cg,
    };
    let result = boneli_sys::spawn(&spec);
    let ok = matches!(
        result,
        Err(boneli_sys::Error::Setup {
            step: boneli_sys::Step::Exec,
            errno: libc::ENOENT,
            ..
        })
    );
    if !ok {
        let got = match result {
            Ok(mut child) => format!("Ok(child), which ended with {:?}", child.wait()),
            Err(e) => format!("Err({e:?})"),
        };
        let _ = std::fs::write(&out, got);
        exit(3);
    }
}

/// The errno of an I/O result: 0 on success.
fn code<T>(r: &std::io::Result<T>) -> String {
    match r {
        Ok(_) => "0".to_string(),
        Err(e) => e.raw_os_error().unwrap_or(-1).to_string(),
    }
}

fn pid() {
    put("pid", &std::process::id().to_string());
    let mut pids: Vec<u32> = std::fs::read_dir("/proc")
        .unwrap_or_else(|e| fail(3, &format!("list /proc: {e}")))
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
        .collect();
    pids.sort_unstable();
    let shown: Vec<String> = pids.iter().map(u32::to_string).collect();
    put("proc_pids", &shown.join(","));
}

fn net() {
    // /proc/net/dev lists the interfaces of the reader's network namespace.
    let dev = std::fs::read_to_string("/proc/net/dev")
        .unwrap_or_else(|e| fail(3, &format!("read /proc/net/dev: {e}")));
    let names: Vec<&str> = dev
        .lines()
        .skip(2)
        .filter_map(|l| l.split(':').next())
        .map(str::trim)
        .collect();
    put("interfaces", &names.join(","));
    // SAFETY: socket takes plain integers.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        fail(3, "socket");
    }
    // SAFETY: an all-zero ifreq is valid storage.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name[0] = b'l' as libc::c_char;
    ifr.ifr_name[1] = b'o' as libc::c_char;
    // SAFETY: ifr is a valid ifreq naming "lo".
    if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifr) } < 0 {
        fail(3, "SIOCGIFFLAGS");
    }
    // SAFETY: SIOCGIFFLAGS filled the flags member.
    let flags = unsafe { ifr.ifr_ifru.ifru_flags } as i32;
    put("lo_up", &((flags & libc::IFF_UP) != 0).to_string());
    // SAFETY: fd was opened above.
    unsafe { libc::close(fd) };
    let tcp = (|| -> std::io::Result<u8> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let mut client = std::net::TcpStream::connect(addr)?;
        let (mut server, _) = listener.accept()?;
        use std::io::Read;
        server.write_all(b"k")?;
        let mut b = [0u8; 1];
        client.read_exact(&mut b)?;
        Ok(b[0])
    })();
    put("tcp_loopback", &code(&tcp));
    let out = std::net::TcpStream::connect_timeout(
        &"192.0.2.1:80"
            .parse()
            .unwrap_or_else(|_| fail(2, "address")),
        std::time::Duration::from_secs(5),
    );
    put("test_net_errno", &code(&out));
}

fn shm() {
    let key: i32 = input("BONELI_PROBE_KEY")
        .parse()
        .unwrap_or_else(|_| fail(2, "BONELI_PROBE_KEY is not a number"));
    // SAFETY: shmget takes plain integers; size 0 and no flags only look up.
    let rc = unsafe { libc::shmget(key, 0, 0) };
    put("errno", &if rc >= 0 { 0 } else { errno() }.to_string());
}

fn uname() {
    // SAFETY: an all-zero utsname is valid storage for uname.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: u is valid storage.
    if unsafe { libc::uname(&mut u) } < 0 {
        fail(3, "uname");
    }
    let name: Vec<u8> = u
        .nodename
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    put("nodename", &String::from_utf8_lossy(&name));
}

fn cgroup() {
    let text = std::fs::read_to_string("/proc/self/cgroup")
        .unwrap_or_else(|e| fail(3, &format!("read /proc/self/cgroup: {e}")));
    put("cgroup", &text.trim().replace('\n', ";"));
}

/// Mount point, per-mount options and file system type of every line of
/// `/proc/self/mountinfo`, as `mount=<point> <options> <fstype>`.
fn mounts() {
    let text = std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_else(|e| fail(3, &format!("read mountinfo: {e}")));
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(dash) = fields.iter().position(|f| *f == "-") else {
            fail(3, &format!("mountinfo line without separator: {line}"));
        };
        if fields.len() < 6 || dash + 1 >= fields.len() {
            fail(3, &format!("short mountinfo line: {line}"));
        }
        put(
            "mount",
            &format!("{} {} {}", fields[4], fields[5], fields[dash + 1]),
        );
    }
    let root = std::fs::read_link("/proc/1/root")
        .map(|p| p.display().to_string())
        .unwrap_or_else(|e| format!("error {e}"));
    put("proc1_root", &root);
    if let Ok(marker) = std::env::var("BONELI_PROBE_MARKER") {
        put("marker_errno", &code(&std::fs::metadata(&marker)));
        let up = format!("/..{marker}");
        put("marker_up_errno", &code(&std::fs::metadata(up)));
    }
}

fn writes() {
    put("etc_errno", &code(&std::fs::write("/etc/x", b"x")));
    put("mkdir_errno", &code(&std::fs::create_dir("/new")));
    put(
        "workspace_errno",
        &code(&std::fs::write("/workspace/w", b"x")),
    );
    put("tmp_errno", &code(&std::fs::write("/tmp/w", b"x")));
}

fn read() {
    for path in input("BONELI_PROBE_FILES").split(',') {
        let value = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) => format!("errno={}", e.raw_os_error().unwrap_or(-1)),
        };
        put(&format!("file:{path}"), &value);
    }
}

fn fill() {
    let path = input("BONELI_PROBE_FILE");
    let size: usize = input("BONELI_PROBE_SIZE")
        .parse()
        .unwrap_or_else(|_| fail(2, "BONELI_PROBE_SIZE is not a number"));
    let first = std::fs::write(&path, vec![b'x'; size]);
    put("fill_errno", &code(&first));
    let more = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .and_then(|mut f| {
            f.write_all(b"y")?;
            f.sync_all()
        });
    put("more_errno", &code(&more));
}

fn connect() {
    use std::io::Read;
    let path = input("BONELI_PROBE_SOCKET");
    match std::os::unix::net::UnixStream::connect(&path) {
        Ok(mut s) => {
            put("connect_errno", "0");
            let mut b = [0u8; 1];
            put("read_errno", &code(&s.read_exact(&mut b)));
            put("byte", &(b[0] as char).to_string());
        }
        Err(e) => put("connect_errno", &e.raw_os_error().unwrap_or(-1).to_string()),
    }
}

fn connect_abstract() {
    use std::os::linux::net::SocketAddrExt;
    let name = input("BONELI_PROBE_NAME");
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
        .unwrap_or_else(|e| fail(2, &format!("abstract name: {e}")));
    let r = std::os::unix::net::UnixStream::connect_addr(&addr);
    put("connect_errno", &code(&r));
}

fn dev() {
    let mut names: Vec<String> = std::fs::read_dir("/dev")
        .unwrap_or_else(|e| fail(3, &format!("list /dev: {e}")))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    put("entries", &names.join(","));
    // SAFETY: an all-zero statvfs is valid storage for statvfs to fill.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: the path is NUL-terminated and st is valid storage.
    if unsafe { libc::statvfs(c"/dev".as_ptr(), &mut st) } == 0 {
        let used = (st.f_blocks - st.f_bfree) as u64 * st.f_frsize as u64;
        put("used_bytes", &used.to_string());
    }
    let null = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .and_then(|mut f| f.write_all(b"discarded"));
    put("null_errno", &code(&null));
    put("create_errno", &code(&std::fs::write("/dev/x", b"x")));
    // SAFETY: posix_openpt takes flags; the descriptor is closed below.
    let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if fd >= 0 {
        // SAFETY: fd was just opened.
        unsafe { libc::close(fd) };
        put("openpt_errno", "0");
    } else {
        put("openpt_errno", &errno().to_string());
    }
}

/// Writes each `path=content` of `BONELI_PROBE_WRITES` (comma-separated)
/// and prints `errno:<path>`.
fn write() {
    for item in input("BONELI_PROBE_WRITES").split(',') {
        let (path, content) = item
            .split_once('=')
            .unwrap_or_else(|| fail(2, "BONELI_PROBE_WRITES item without '='"));
        put(
            &format!("errno:{path}"),
            &code(&std::fs::write(path, content)),
        );
    }
}

/// PID 1 forks a child that touches `BONELI_PROBE_SIZE` bytes of anonymous
/// memory one byte per page, then waits for it. Under `memory.oom.group`
/// the OOM kill takes this process too; otherwise it prints how the child
/// ended and exits 0.
fn oom() {
    let size: usize = input("BONELI_PROBE_SIZE")
        .parse()
        .unwrap_or_else(|_| fail(2, "BONELI_PROBE_SIZE is not a number"));
    // SAFETY: sysconf takes a plain name.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    // SAFETY: fork has no memory arguments; the child below only maps,
    // writes and exits, which needs no lock another thread could hold.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        fail(3, &format!("fork: errno {}", errno()));
    }
    if pid == 0 {
        // SAFETY: an anonymous private mapping with no address hint.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            // SAFETY: _exit ends the forked child without running anything.
            unsafe { libc::_exit(4) };
        }
        let base = p.cast::<u8>();
        let mut at = 0;
        while at < size {
            // SAFETY: at < size, so the pointer is inside the mapping.
            let byte = unsafe { base.add(at) };
            // SAFETY: byte points into the writable mapping created above.
            unsafe { byte.write_volatile(1) };
            at += page;
        }
        // SAFETY: as above.
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    // SAFETY: status is valid storage; pid is this process's child.
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        fail(3, &format!("waitpid: errno {}", errno()));
    }
    put("child_status", &status.to_string());
}

/// The thread count T of this process (from `/proc/self/status`), then
/// forks sleepers until `fork` fails, prints how many it got and the
/// errno, and kills and reaps them.
fn pids() {
    let status = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_else(|e| fail(3, &format!("read status: {e}")));
    let threads = status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .map(str::trim)
        .unwrap_or_else(|| fail(3, "no Threads line"))
        .to_string();
    let mut children = Vec::new();
    let fork_errno = loop {
        // SAFETY: the child only waits for a signal, which takes no lock.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            break errno();
        }
        if pid == 0 {
            loop {
                // SAFETY: pause only waits for a signal.
                unsafe { libc::pause() };
            }
        }
        children.push(pid);
        if children.len() > 1000 {
            break 0;
        }
    };
    put("threads", &threads);
    put("children", &children.len().to_string());
    put("fork_errno", &fork_errno.to_string());
    for &pid in &children {
        // SAFETY: kill and waitpid take plain integers and valid storage;
        // each pid is this process's child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut st = 0;
        // SAFETY: as above.
        unsafe { libc::waitpid(pid, &mut st, 0) };
    }
}

/// `usage_usec` and `nr_throttled` of the sandbox's own `cpu.stat`.
fn cpu_stat() -> (u64, u64) {
    let text = std::fs::read_to_string("/sys/fs/cgroup/cpu.stat")
        .unwrap_or_else(|e| fail(3, &format!("read cpu.stat: {e}")));
    let get = |key: &str| -> u64 {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(' '))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| fail(3, &format!("no {key} in cpu.stat")))
    };
    (get("usage_usec"), get("nr_throttled"))
}

/// Spins on `BONELI_PROBE_THREADS` threads for `BONELI_PROBE_MS` of wall
/// time and prints the cpu.stat deltas over the spin.
fn spin() {
    let ms: u64 = input("BONELI_PROBE_MS")
        .parse()
        .unwrap_or_else(|_| fail(2, "BONELI_PROBE_MS is not a number"));
    let threads: usize = input("BONELI_PROBE_THREADS")
        .parse()
        .unwrap_or_else(|_| fail(2, "BONELI_PROBE_THREADS is not a number"));
    let (usage0, throttled0) = cpu_stat();
    let start = std::time::Instant::now();
    let until = std::time::Duration::from_millis(ms);
    let spinners: Vec<_> = (0..threads)
        .map(|_| {
            std::thread::spawn(move || {
                let mut n = 0u64;
                while start.elapsed() < until {
                    n = std::hint::black_box(n.wrapping_add(1));
                }
                n
            })
        })
        .collect();
    for s in spinners {
        let _ = s.join();
    }
    let (usage1, throttled1) = cpu_stat();
    put("usage_usec", &(usage1 - usage0).to_string());
    put("nr_throttled", &(throttled1 - throttled0).to_string());
}

/// How `io-write` opens its file (`BONELI_PROBE_DIRECT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDirect {
    /// Unset: `O_DIRECT`, and where the file system refuses it (EINVAL)
    /// buffered with `fdatasync` after every write.
    Auto,
    /// `require`: `O_DIRECT`, no fallback.
    Require,
    /// `never`: no `O_DIRECT` and no `fdatasync` in the loop, so only the
    /// kernel writes the data back while the loop runs.
    Never,
}

/// What `io-write` writes: `size` bytes as writes of `chunk` bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct IoWritePlan {
    /// `BONELI_PROBE_SIZE`.
    pub size: usize,
    /// `BONELI_PROBE_CHUNK`, 1 MiB when unset.
    pub chunk: usize,
    /// `BONELI_PROBE_DIRECT`.
    pub direct: IoDirect,
}

/// The plan from the values of `BONELI_PROBE_SIZE`, `BONELI_PROBE_CHUNK`
/// and `BONELI_PROBE_DIRECT` (`None`: unset). A set chunk is ASCII digits,
/// more than 0, a multiple of 4096 (the `O_DIRECT` alignment) and divides
/// the size; the direct mode is exactly `require` or `never`.
pub fn io_write_plan(
    size: &str,
    chunk: Option<&str>,
    direct: Option<&str>,
) -> Result<IoWritePlan, String> {
    let size: usize = size
        .parse()
        .map_err(|_| "BONELI_PROBE_SIZE is not a number".to_string())?;
    let chunk = match chunk {
        None => 1 << 20,
        Some(c) => {
            let n: usize = if !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()) {
                c.parse()
                    .map_err(|_| format!("BONELI_PROBE_CHUNK {c:?} is out of range"))?
            } else {
                return Err(format!("BONELI_PROBE_CHUNK {c:?} is not a number"));
            };
            if n == 0 || !n.is_multiple_of(4096) || !size.is_multiple_of(n) {
                return Err(format!(
                    "BONELI_PROBE_CHUNK {n} must be a non-zero multiple of 4096 that divides {size}"
                ));
            }
            n
        }
    };
    let direct = match direct {
        None => IoDirect::Auto,
        Some("require") => IoDirect::Require,
        Some("never") => IoDirect::Never,
        Some(d) => return Err(format!("BONELI_PROBE_DIRECT {d:?} is not require or never")),
    };
    Ok(IoWritePlan {
        size,
        chunk,
        direct,
    })
}

/// A cgroup file's lines, whitespace normalized, joined by `;` (as
/// [`map_lines`] does), so the file fits one probe line.
pub fn joined_lines(text: &str) -> String {
    text.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(";")
}

/// How often the `never` loop prints a `progress` key: every 16 MiB.
pub const PROGRESS_EVERY: usize = 16 << 20;

/// Writes `BONELI_PROBE_SIZE` bytes to `BONELI_PROBE_FILE` as writes of
/// `BONELI_PROBE_CHUNK` bytes (1 MiB when unset), opened as
/// `BONELI_PROBE_DIRECT` says ([`IoDirect`]: by default with `O_DIRECT`
/// where the file system takes it, else `fdatasync` after every write),
/// then `fdatasync`s and prints the elapsed time. Before that final
/// `fdatasync` it prints `loop_ms`. With `never` it prints `loop_start=1`
/// right before the loop (only there, so the other modes' writers keep
/// their 38 bytes of output before the write, ADR-007 D8), and the loop
/// prints a `progress` key every [`PROGRESS_EVERY`] bytes (`<MiB written>:<ms since
/// the start>:<slowest write of the span in µs>`), so a writer killed in
/// the loop leaves its timeline, and after the loop it reads its own
/// cgroup once: `file_dirty` and `file_writeback` (`loop_file_dirty`,
/// `loop_file_writeback`) and `io.stat` (`loop_io_stat`, lines joined by
/// `;`). That read comes after the loop, whose outcome depends on the
/// kernel's memory statistics; a read flushes them (#54).
fn io_write() {
    use std::os::unix::fs::OpenOptionsExt;
    let path = input("BONELI_PROBE_FILE");
    let plan = io_write_plan(
        &input("BONELI_PROBE_SIZE"),
        std::env::var("BONELI_PROBE_CHUNK").ok().as_deref(),
        std::env::var("BONELI_PROBE_DIRECT").ok().as_deref(),
    )
    .unwrap_or_else(|e| fail(2, &e));
    let size = plan.size;
    let open = |extra: i32| {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(extra)
            .open(&path)
    };
    let (mut file, direct) = match plan.direct {
        IoDirect::Auto => match open(libc::O_DIRECT) {
            Ok(f) => (f, true),
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => (
                open(0).unwrap_or_else(|e| fail(3, &format!("open {path}: {e}"))),
                false,
            ),
            Err(e) => fail(3, &format!("open {path} with O_DIRECT: {e}")),
        },
        IoDirect::Require => (
            open(libc::O_DIRECT)
                .unwrap_or_else(|e| fail(3, &format!("open {path} with O_DIRECT: {e}"))),
            true,
        ),
        IoDirect::Never => (
            open(0).unwrap_or_else(|e| fail(3, &format!("open {path}: {e}"))),
            false,
        ),
    };
    let sync_each = !direct && plan.direct == IoDirect::Auto;
    let chunk_len = plan.chunk;
    // O_DIRECT needs an aligned buffer: a fresh anonymous mapping is page
    // aligned, which covers the logical block size of every device the
    // tests run on. It is advised MADV_NOHUGEPAGE before any byte is
    // touched (review round 2 of PR 53): transparent huge pages would make
    // its pages physically contiguous, the O_DIRECT bios as large as the
    // huge pages (blk-throttle charges a bio whole, so the first one was
    // counted only after 15.6 s at 1 MiB/s, measured), and the timing of
    // destroy_lifts_io_throttle would depend on the host's THP setting.
    // The allocator cannot give that order: it writes its header next to
    // the buffer, which faults a huge page in under THP `always`.
    // SAFETY: a new private anonymous mapping, no address hint, no file.
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            chunk_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if map == libc::MAP_FAILED {
        fail(
            3,
            &format!("mmap the write buffer: {}", std::io::Error::last_os_error()),
        );
    }
    // SAFETY: map is the start of the chunk_len-byte mapping made above.
    let rc = unsafe { libc::madvise(map, chunk_len, libc::MADV_NOHUGEPAGE) };
    // EINVAL for valid arguments means a kernel without transparent huge
    // pages, so there is nothing to opt out of.
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINVAL) {
            fail(3, &format!("madvise MADV_NOHUGEPAGE: {e}"));
        }
    }
    let buf = map.cast::<u8>();
    // SAFETY: buf is the chunk_len-byte mapping, zero-filled by the kernel,
    // owned by this function, and nothing else refers to it.
    let chunk = unsafe { std::slice::from_raw_parts_mut(buf, chunk_len) };
    // Incompressible bytes (xorshift64): a compressing file system (btrfs
    // with compress=zstd, the dev host's) would write zeros as a few
    // hundred KiB and never reach the limit (measured).
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for word in chunk.as_chunks_mut::<8>().0 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *word = x.to_ne_bytes();
    }
    let progress = plan.direct == IoDirect::Never;
    if progress {
        put("loop_start", "1");
    }
    let start = std::time::Instant::now();
    let mut written = 0;
    let mut slowest = std::time::Duration::ZERO;
    while written < size {
        let one = std::time::Instant::now();
        file.write_all(chunk)
            .unwrap_or_else(|e| fail(3, &format!("write {path}: {e}")));
        if sync_each {
            file.sync_data()
                .unwrap_or_else(|e| fail(3, &format!("fdatasync {path}: {e}")));
        }
        slowest = slowest.max(one.elapsed());
        let before = written;
        written += chunk_len;
        if progress && written / PROGRESS_EVERY > before / PROGRESS_EVERY {
            put(
                "progress",
                &format!(
                    "{}:{}:{}",
                    written >> 20,
                    start.elapsed().as_millis(),
                    slowest.as_micros()
                ),
            );
            slowest = std::time::Duration::ZERO;
        }
    }
    put("loop_ms", &start.elapsed().as_millis().to_string());
    if plan.direct == IoDirect::Never {
        let cg_file = |name: &str| {
            std::fs::read_to_string(format!("/sys/fs/cgroup/{name}"))
                .unwrap_or_else(|e| fail(3, &format!("read {name}: {e}")))
        };
        let memory = cg_file("memory.stat");
        let keyed = crate::support::cgroup::keyed;
        put("loop_file_dirty", &keyed(&memory, "file_dirty").to_string());
        put(
            "loop_file_writeback",
            &keyed(&memory, "file_writeback").to_string(),
        );
        put("loop_io_stat", &joined_lines(&cg_file("io.stat")));
    }
    file.sync_data()
        .unwrap_or_else(|e| fail(3, &format!("fdatasync {path}: {e}")));
    put("elapsed_ms", &start.elapsed().as_millis().to_string());
    put("direct", &direct.to_string());
    // SAFETY: map is the chunk_len-byte mapping made above, and chunk, the
    // only reference into it, is not used after this.
    let rc = unsafe { libc::munmap(map, chunk_len) };
    if rc != 0 {
        fail(
            3,
            &format!(
                "munmap the write buffer: {}",
                std::io::Error::last_os_error()
            ),
        );
    }
}

/// Not sandboxed: raises this process's own `oom_score_adj` to
/// `BONELI_PROBE_VALUE`, then starts a probe sandbox that reads its own
/// value, and prints it as `inside`.
fn oom_adj_spawn() {
    let value = input("BONELI_PROBE_VALUE");
    if let Err(e) = std::fs::write("/proc/self/oom_score_adj", &value) {
        fail(3, &format!("raise oom_score_adj to {value}: {e}"));
    }
    let p = crate::support::run_probe(
        "read",
        boneli_sys::Ids::new(0, 0).unwrap_or_else(|e| fail(3, &e.to_string())),
        &[("BONELI_PROBE_FILES", "/proc/self/oom_score_adj")],
    );
    if p.status != boneli_sys::ExitStatus::Exited(0) {
        fail(3, &format!("inner probe failed: {}", p.raw));
    }
    put(
        "inside",
        p.values
            .get("file:/proc/self/oom_score_adj")
            .map_or("missing", |v| v.trim()),
    );
}

/// The errno of a raw syscall result: 0 when it succeeded.
fn rc_errno(rc: libc::c_long) -> i32 {
    if rc < 0 { errno() } else { 0 }
}

/// Forks a child that runs `call`, which must not allocate (the child is a
/// copy of one thread, see `alloc_guard`), and exits with its result;
/// returns that exit code, or 255 when the child did not exit normally.
fn in_fork(call: fn() -> i32) -> i32 {
    // SAFETY: fork has no memory arguments; the child runs only `call`,
    // which makes raw syscalls on prepared memory, and _exit.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        fail(3, &format!("fork: errno {}", errno()));
    }
    if pid == 0 {
        let code = call();
        // SAFETY: _exit ends the forked child without running anything.
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    // SAFETY: status is valid storage; pid is this process's child.
    if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
        fail(3, &format!("waitpid: errno {}", errno()));
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        255
    }
}

/// `keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0)`: its errno,
/// 0 when it succeeded.
fn keyctl_get_keyring_id() -> i32 {
    const KEYCTL_GET_KEYRING_ID: libc::c_long = 0;
    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    // SAFETY: keyctl with this operation takes plain integers.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_GET_KEYRING_ID,
            KEY_SPEC_SESSION_KEYRING,
            0,
        )
    };
    rc_errno(rc)
}

/// Closes `fd` if a call returned one.
fn close_if(rc: libc::c_long) {
    if rc >= 0 {
        // SAFETY: the call returned a new descriptor that nothing else owns.
        unsafe { libc::close(rc as i32) };
    }
}

/// The kernel rows of the seccomp policy (ADR-007, D2): makes each call
/// the rows name and prints `row:<id>=<errno>`, 0 for success. The host
/// test runs this action twice, once on the host without a filter (the
/// baseline) and once in a sandbox. Every call is harmless if it
/// succeeds: what it creates is closed, unmapped, removed or dies with
/// the process (the key in the process keyring), and the namespaces are
/// made by forked children that exit at once.
fn seccomp_rows() {
    let row = |id: &str, e: i32| put(&format!("row:{id}"), &e.to_string());

    let mut params = [0u8; 120];
    // SAFETY: params is zeroed io_uring_params storage of its full size
    // (120 bytes); one entry.
    let rc = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, params.as_mut_ptr()) };
    row("io-uring-setup", rc_errno(rc));
    close_if(rc);

    // A zeroed BPF_MAP_CREATE attribute: rejected by the kernel's own
    // checks if the call gets that far.
    let attr = [0u8; 128];
    // SAFETY: attr is valid for its size for the call's duration.
    let rc = unsafe { libc::syscall(libc::SYS_bpf, 0, attr.as_ptr(), attr.len()) };
    row("bpf", rc_errno(rc));
    close_if(rc);

    const UFFD_USER_MODE_ONLY: libc::c_long = 1;
    // SAFETY: userfaultfd takes plain flags.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_userfaultfd,
            UFFD_USER_MODE_ONLY | libc::O_CLOEXEC as libc::c_long,
        )
    };
    row("userfaultfd", rc_errno(rc));
    close_if(rc);

    // perf_event_attr, PERF_ATTR_SIZE_VER7 (128 bytes): a software CPU
    // clock of this process, disabled, user space only.
    let mut pattr = [0u64; 16];
    pattr[0] = 1 | (128 << 32); // type PERF_TYPE_SOFTWARE, size 128
    pattr[1] = 0; // config PERF_COUNT_SW_CPU_CLOCK
    pattr[5] = 1 | (1 << 5) | (1 << 6); // disabled, exclude_kernel, exclude_hv
    // SAFETY: pattr is a perf_event_attr of the size it names; pid 0, cpu
    // -1, no group, no flags.
    let rc = unsafe { libc::syscall(libc::SYS_perf_event_open, pattr.as_ptr(), 0, -1, -1, 0) };
    row("perf-event-open", rc_errno(rc));
    close_if(rc);

    row("keyctl", keyctl_get_keyring_id());

    const KEY_SPEC_PROCESS_KEYRING: libc::c_long = -2;
    // SAFETY: every string is NUL-terminated and the payload is one byte.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            c"user".as_ptr(),
            c"boneli-probe".as_ptr(),
            c"x".as_ptr(),
            1usize,
            KEY_SPEC_PROCESS_KEYRING,
        )
    };
    row("add-key", rc_errno(rc));

    // SAFETY: the strings are NUL-terminated; no callout, no keyring.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_request_key,
            c"user".as_ptr(),
            c"boneli-probe-absent".as_ptr(),
            std::ptr::null::<libc::c_char>(),
            0,
        )
    };
    row("request-key", rc_errno(rc));

    const SYSLOG_ACTION_SIZE_BUFFER: libc::c_long = 10;
    // SAFETY: SIZE_BUFFER reads no buffer.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_syslog,
            SYSLOG_ACTION_SIZE_BUFFER,
            std::ptr::null_mut::<libc::c_char>(),
            0,
        )
    };
    row("syslog", rc_errno(rc));

    // unshare in a forked child: a multithreaded process cannot unshare
    // its user namespace (EINVAL), and the probe runs in libtest's thread.
    row(
        "unshare-newuser",
        in_fork(|| {
            // SAFETY: unshare takes plain flags.
            rc_errno(unsafe {
                libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER as libc::c_long)
            })
        }),
    );
    row(
        "unshare-newuser-high",
        in_fork(|| {
            let flags: u64 = (1 << 32) | libc::CLONE_NEWUSER as u64;
            // SAFETY: unshare takes plain flags.
            rc_errno(unsafe { libc::syscall(libc::SYS_unshare, flags) })
        }),
    );

    // clone with CLONE_NEWUSER and no stack, like fork; the child exits at
    // once. The other arguments (tids, tls) are null on both arches.
    // SAFETY: without CLONE_VM the child runs on a copy of this stack and
    // only calls _exit.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_long,
            0,
            0,
            0,
            0,
        )
    };
    if pid == 0 {
        // SAFETY: _exit ends the cloned child without running anything.
        unsafe { libc::_exit(0) };
    }
    if pid > 0 {
        let mut st = 0;
        // SAFETY: st is valid storage; pid is this process's child.
        unsafe { libc::waitpid(pid as i32, &mut st, 0) };
    }
    row("clone-newuser", rc_errno(pid));

    // clone3 with a null argument: EINVAL from the kernel's own checks,
    // ENOSYS from the filter.
    // SAFETY: a null pointer and size 0 make clone3 fail before it reads.
    let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) };
    row("clone3", rc_errno(rc));

    let socket = |id: &str, family: i32, ty: i32, protocol: i32| {
        // SAFETY: socket takes plain integers.
        let fd = unsafe { libc::socket(family, ty | libc::SOCK_CLOEXEC, protocol) };
        row(id, if fd < 0 { errno() } else { 0 });
        close_if(fd as libc::c_long);
    };
    socket("socket-vsock", libc::AF_VSOCK, libc::SOCK_STREAM, 0);
    socket("socket-unix", libc::AF_UNIX, libc::SOCK_STREAM, 0);
    socket(
        "netlink-netfilter",
        libc::AF_NETLINK,
        libc::SOCK_RAW,
        libc::NETLINK_NETFILTER,
    );
    socket(
        "netlink-route",
        libc::AF_NETLINK,
        libc::SOCK_RAW,
        libc::NETLINK_ROUTE,
    );

    let mut pair = [-1; 2];
    // SAFETY: pair is storage for two descriptors.
    let rc = unsafe { libc::socketpair(libc::AF_INET, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    row("socketpair-inet", if rc < 0 { errno() } else { 0 });
    if rc == 0 {
        close_if(pair[0] as libc::c_long);
        close_if(pair[1] as libc::c_long);
    }

    const TWO_MIB: usize = 2 << 20;
    // SAFETY: an anonymous mapping with no address hint; unmapped below.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            TWO_MIB,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
            -1,
            0,
        )
    };
    row(
        "mmap-hugetlb",
        if p == libc::MAP_FAILED { errno() } else { 0 },
    );
    if p != libc::MAP_FAILED {
        // SAFETY: p is the mapping created above, of that size.
        unsafe { libc::munmap(p, TWO_MIB) };
    }

    // SAFETY: the name is NUL-terminated.
    let fd = unsafe { libc::memfd_create(c"b".as_ptr(), libc::MFD_HUGETLB | libc::MFD_CLOEXEC) };
    row("memfd-hugetlb", if fd < 0 { errno() } else { 0 });
    close_if(fd as libc::c_long);

    // SAFETY: shmget takes plain integers.
    let id = unsafe {
        libc::shmget(
            libc::IPC_PRIVATE,
            TWO_MIB,
            libc::IPC_CREAT | libc::SHM_HUGETLB | 0o600,
        )
    };
    row("shmget-hugetlb", if id < 0 { errno() } else { 0 });
    if id >= 0 {
        // SAFETY: id is the segment created above; IPC_RMID takes no buffer.
        unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
    }
}

/// An i386 `getpid` through `int 0x80` (x86_64 only). Without a filter it
/// prints the result; under the policy the arch row kills the process
/// with SIGSYS. Core dumps are switched off first.
fn int80() {
    // SAFETY: PR_SET_DUMPABLE takes plain integers.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    #[cfg(target_arch = "x86_64")]
    {
        let mut eax: i64 = 20; // __NR_getpid of the i386 table
        // SAFETY: int 0x80 with eax 20 runs the i386 getpid, which reads
        // and writes no memory; it clobbers r8-r11 at most, declared here.
        unsafe {
            std::arch::asm!(
                "int 0x80",
                inout("rax") eax,
                lateout("r8") _, lateout("r9") _, lateout("r10") _, lateout("r11") _,
                options(nostack)
            );
        }
        put("int80", &eax.to_string());
    }
    #[cfg(not(target_arch = "x86_64"))]
    fail(2, "int80 exists on x86_64 only");
}

/// The capability, `no_new_privs` and seccomp lines of
/// `/proc/self/status`. With `BONELI_PROBE_EXEC=1` it first re-executes
/// this binary as the same action and prints the new image's lines with
/// the prefix `exec_`.
fn caps() {
    let status = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_else(|e| fail(3, &format!("read status: {e}")));
    for key in [
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
        "Seccomp_filters",
    ] {
        let v = status
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}:")))
            .map_or("missing", str::trim);
        put(key, v);
    }
    if std::env::var("BONELI_PROBE_EXEC").as_deref() == Ok("1") {
        let exe = std::env::current_exe().unwrap_or_else(|e| fail(3, &format!("current_exe: {e}")));
        let out = std::process::Command::new(exe)
            .args(["--exact", "probe", "--nocapture", "--quiet"])
            .env_clear()
            .env(ACTION_VAR, "caps")
            .output()
            .unwrap_or_else(|e| fail(3, &format!("re-exec: {e}")));
        put("exec_status", &format!("{:?}", out.status.code()));
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(rest) = line.find(PREFIX).map(|p| &line[p + PREFIX.len()..])
                && let Some((k, v)) = rest.split_once('=')
            {
                put(&format!("exec_{k}"), v);
            }
        }
    }
}

/// `PR_GET_SECUREBITS`, then the errno of `PR_SET_SECUREBITS(0)`.
fn securebits() {
    // SAFETY: PR_GET_SECUREBITS takes no pointer.
    let bits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
    put("securebits", &bits.to_string());
    // SAFETY: PR_SET_SECUREBITS takes plain integers.
    let rc = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0, 0, 0, 0) };
    put("set_errno", &if rc == 0 { 0 } else { errno() }.to_string());
}

/// `keyctl` from a new thread and from a forked child, then again after
/// this process installed an allow-all filter of its own on top.
fn filter_reach() {
    let thread = std::thread::spawn(keyctl_get_keyring_id)
        .join()
        .unwrap_or_else(|_| fail(3, "the thread panicked"));
    put("thread", &thread.to_string());
    put("fork", &in_fork(keyctl_get_keyring_id).to_string());
    let allow = [libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let prog = libc::sock_fprog {
        len: 1,
        filter: allow.as_ptr().cast_mut(),
    };
    // SAFETY: prog points at one valid instruction for the call's duration;
    // no_new_privs is already set by the sandbox.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            &prog as *const libc::sock_fprog,
        )
    };
    put("stack_errno", &rc_errno(rc).to_string());
    put("stacked", &keyctl_get_keyring_id().to_string());
}

/// A raw `clone3`, then a thread started through glibc, which tries
/// `clone3` first and falls back to `clone` on ENOSYS.
fn clone3_fallback() {
    // SAFETY: a null pointer and size 0 make clone3 fail before it reads.
    let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize) };
    put("clone3_errno", &rc_errno(rc).to_string());
    let started = std::thread::Builder::new()
        .spawn(|| 7)
        .map(|h| h.join().unwrap_or(0));
    put("thread", &code(&started.map(|v| assert_eq!(v, 7))));
}

/// `struct mount_attr`, `include/uapi/linux/mount.h`.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Tries to make the read-only cgroup2 view at `/sys/fs/cgroup` writable,
/// or to mount a cgroup2 of its own, each way the kernel offers, and to
/// chmod `cgroup.kill` through the view. Prints each errno.
fn cgroup_view() {
    let target = c"/sys/fs/cgroup";
    let mount = |key: &str, flags: libc::c_ulong| {
        // SAFETY: target is NUL-terminated; no source, type or data.
        let rc = unsafe {
            libc::mount(
                std::ptr::null(),
                target.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        };
        put(key, &if rc == 0 { 0 } else { errno() }.to_string());
    };
    mount(
        "remount_bind",
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
    );
    mount("remount_sb", libc::MS_REMOUNT);
    let attr = MountAttr {
        attr_set: 0,
        attr_clr: libc::MOUNT_ATTR_RDONLY,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: target is NUL-terminated and attr is valid for its size.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            target.as_ptr(),
            0u32,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    put("mount_setattr", &rc_errno(rc).to_string());
    if let Err(e) = std::fs::create_dir_all("/tmp/cg") {
        fail(3, &format!("mkdir /tmp/cg: {e}"));
    }
    // SAFETY: every string is NUL-terminated; no data is passed.
    let rc = unsafe {
        libc::mount(
            c"cgroup2".as_ptr(),
            c"/tmp/cg".as_ptr(),
            c"cgroup2".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    put(
        "mount_cgroup2",
        &if rc == 0 { 0 } else { errno() }.to_string(),
    );
    // SAFETY: the name is NUL-terminated; no flags.
    let rc = unsafe { libc::syscall(libc::SYS_fsopen, c"cgroup2".as_ptr(), 0u32) };
    put("fsopen", &rc_errno(rc).to_string());
    close_if(rc);
    // SAFETY: the path is NUL-terminated; no flags.
    let rc = unsafe {
        libc::fchmodat(
            libc::AT_FDCWD,
            c"/sys/fs/cgroup/cgroup.kill".as_ptr(),
            0o444,
            0,
        )
    };
    put("chmod_kill", &if rc == 0 { 0 } else { errno() }.to_string());
}

/// Not sandboxed: applies a Landlock ruleset to this process and prints
/// what each access gives (ADR-007, D10). `BONELI_PROBE_DIR` holds `r/f`,
/// `r/g`, `w/a/x`, `w/b/`, `outside/f`, `u1/` and `u2/`; the probe makes
/// the listeners before it restricts itself, so they are created outside
/// the domain. A case above the kernel's ABI prints `n/a`.
fn landlock() {
    use boneli_sys::{Abi, AccessFs, AccessNet, Ruleset, Scope};
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};

    let dir = input("BONELI_PROBE_DIR");
    if let Err(e) = std::env::set_current_dir(&dir) {
        fail(2, &format!("chdir {dir}: {e}"));
    }
    let abi = Abi::current().unwrap_or_else(|e| fail(3, &format!("Landlock: {e}")));
    let v = abi.version();
    put("abi", &v.to_string());

    // Listeners, all outside the domain.
    let tcp_ok = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| fail(3, &format!("bind tcp: {e}")));
    let tcp_no = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| fail(3, &format!("bind tcp: {e}")));
    let port = |l: &std::net::TcpListener| {
        l.local_addr()
            .unwrap_or_else(|e| fail(3, &format!("local_addr: {e}")))
            .port()
    };
    let (p_ok, p_no) = (port(&tcp_ok), port(&tcp_no));
    use std::os::linux::net::SocketAddrExt;
    let name = format!("boneli-landlock-{}", std::process::id());
    let abstract_addr = SocketAddr::from_abstract_name(name.as_bytes())
        .unwrap_or_else(|e| fail(3, &format!("abstract name: {e}")));
    let _abstract = UnixListener::bind_addr(&abstract_addr)
        .unwrap_or_else(|e| fail(3, &format!("bind abstract: {e}")));
    let _u1 = UnixListener::bind("u1/s").unwrap_or_else(|e| fail(3, &format!("bind u1/s: {e}")));
    let _u2 = UnixListener::bind("u2/s").unwrap_or_else(|e| fail(3, &format!("bind u2/s: {e}")));
    // execve of a program outside R, prepared before the fork.
    let true_path = c"/usr/bin/true";

    let fs = AccessFs::all_for(abi);
    let net = AccessNet::all_for(abi);
    let mut rules = Ruleset::new(abi, fs, net, Scope::all_for(abi))
        .unwrap_or_else(|e| fail(3, &format!("ruleset: {e}")));
    let read = AccessFs::READ_FILE
        .union(AccessFs::READ_DIR)
        .union(AccessFs::EXECUTE);
    let allow = |rules: &mut Ruleset, path: &str, rights: AccessFs| {
        rules
            .allow_path(std::path::Path::new(path), rights)
            .unwrap_or_else(|e| fail(3, &format!("rule {path}: {e}")));
    };
    allow(&mut rules, "r", read);
    allow(&mut rules, "w", fs);
    allow(&mut rules, "u1", AccessFs::READ_DIR);
    if v >= 9 {
        allow(
            &mut rules,
            "u2",
            AccessFs::READ_DIR.union(AccessFs::RESOLVE_UNIX),
        );
    } else {
        allow(&mut rules, "u2", AccessFs::READ_DIR);
    }
    if v >= 4 {
        rules
            .allow_port(p_ok, AccessNet::CONNECT_TCP)
            .unwrap_or_else(|e| fail(3, &format!("rule port: {e}")));
    }
    rules
        .restrict_self()
        .unwrap_or_else(|e| fail(3, &format!("restrict_self: {e}")));

    let case = |key: &str, since: u32, run: &dyn Fn() -> i32| {
        if v < since {
            put(key, "n/a");
        } else {
            put(key, &run().to_string());
        }
    };
    let open = |path: &str, flags: i32| -> i32 {
        let c = c_path(path);
        // SAFETY: c is NUL-terminated; mode 0600 for O_CREAT.
        let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
        if fd < 0 {
            return errno();
        }
        close_if(fd as libc::c_long);
        0
    };
    let rename = |from: &str, to: &str| -> i32 { code_of(&std::fs::rename(from, to)) };
    case("read_r", 1, &|| open("r/f", libc::O_RDONLY));
    case("write_r", 1, &|| open("r/f", libc::O_WRONLY));
    case("read_outside", 1, &|| open("outside/f", libc::O_RDONLY));
    case("create_w", 1, &|| {
        open("w/new", libc::O_CREAT | libc::O_WRONLY)
    });
    case("rename_w", 2, &|| rename("w/a/x", "w/b/x"));
    case("rename_r_to_w", 2, &|| rename("r/g", "w/g"));
    case("truncate_r", 3, &|| {
        // SAFETY: the path is NUL-terminated.
        let rc = unsafe { libc::truncate(c"r/f".as_ptr(), 0) };
        if rc == 0 { 0 } else { errno() }
    });
    case("exec_outside", 1, &|| {
        // SAFETY: the child only calls execve and _exit on prepared memory.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let argv = [true_path.as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null::<libc::c_char>()];
            // SAFETY: both arrays are NULL-terminated and point at
            // NUL-terminated strings.
            unsafe { libc::execve(true_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            // SAFETY: _exit ends the forked child; its code is the errno.
            unsafe { libc::_exit(errno()) };
        }
        let mut st = 0;
        // SAFETY: st is valid storage; pid is this process's child.
        unsafe { libc::waitpid(pid, &mut st, 0) };
        if libc::WIFEXITED(st) {
            libc::WEXITSTATUS(st)
        } else {
            255
        }
    });
    let tcp = |p: u16| code_of(&std::net::TcpStream::connect(("127.0.0.1", p)));
    case("tcp_allowed", 4, &|| tcp(p_ok));
    case("tcp_denied", 4, &|| tcp(p_no));
    case("kill_outside", 6, &|| {
        // SAFETY: getppid has no preconditions.
        let parent = unsafe { libc::getppid() };
        // SAFETY: signal 0 only checks permission.
        let rc = unsafe { libc::kill(parent, 0) };
        if rc == 0 { 0 } else { errno() }
    });
    case("abstract_outside", 6, &|| {
        code_of(&UnixStream::connect_addr(&abstract_addr))
    });
    case("unix_outside", 9, &|| code_of(&UnixStream::connect("u1/s")));
    case("unix_allowed", 9, &|| code_of(&UnixStream::connect("u2/s")));
    // SAFETY: PR_GET_NO_NEW_PRIVS takes no pointer.
    let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    put("no_new_privs", &nnp.to_string());
    drop((tcp_ok, tcp_no));
}

/// The errno of an I/O result as a number: 0 on success, -1 without one.
fn code_of<T>(r: &std::io::Result<T>) -> i32 {
    match r {
        Ok(_) => 0,
        Err(e) => e.raw_os_error().unwrap_or(-1),
    }
}
