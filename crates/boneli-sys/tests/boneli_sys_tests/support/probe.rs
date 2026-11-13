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
    let root = std::fs::metadata("/").unwrap_or_else(|e| fail(3, &format!("stat /: {e}")));
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
