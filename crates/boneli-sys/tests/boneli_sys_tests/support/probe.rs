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
    std::process::exit(code)
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
        _ => fail(1, &format!("unknown action {action}")),
    }
    std::process::exit(0)
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
        std::process::exit(3);
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
