//! The root, the mounts and the broker socket (ADR-007, D7), observed from
//! inside.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use boneli_sys::{DEV_ENTRIES, Error, Mount, Root, Spec, Stdio, Step, spawn};

use crate::support::rootfs::{Fixture, inside};
use crate::support::{self, Probe, TempDir, dev_null, ids, report, run_probe_on};

/// `(mount point, per-mount options, fs type)` of every `mount` line.
fn mounts_of(p: &Probe) -> Vec<(String, BTreeSet<String>, String)> {
    p.lines
        .iter()
        .filter(|(k, _)| k == "mount")
        .map(|(_, v)| {
            let mut it = v.split(' ');
            let point = it.next().expect("point").to_string();
            let opts = it
                .next()
                .expect("options")
                .split(',')
                .map(str::to_string)
                .collect();
            let fstype = it.next().expect("fstype").to_string();
            (point, opts, fstype)
        })
        .collect()
}

fn mount_at<'a>(
    all: &'a [(String, BTreeSet<String>, String)],
    point: &str,
) -> &'a (String, BTreeSet<String>, String) {
    all.iter()
        .find(|(p, _, _)| p == point)
        .unwrap_or_else(|| panic!("no mount at {point}: {all:?}"))
}

fn has(opts: &BTreeSet<String>, want: &[&str]) -> bool {
    want.iter().all(|w| opts.contains(*w))
}

fn host_mountinfo() -> String {
    std::fs::read_to_string("/proc/self/mountinfo").expect("read the host's mountinfo")
}

/// Spawns `/bin/true` on `root` and returns the spawn error, failing the
/// test when it succeeds.
fn spawn_error(root: Root) -> Error {
    let spec = Spec {
        program: PathBuf::from("/bin/true"),
        args: Vec::new(),
        env: Vec::new(),
        stdio: Stdio {
            stdin: dev_null(),
            stdout: dev_null(),
            stderr: dev_null(),
        },
        ids: ids(0, 0),
        setup_timeout: support::SETUP_TIMEOUT,
        root,
    };
    match spawn(&spec) {
        Ok(mut child) => panic!("spawn succeeded; the child ended with {:?}", child.wait()),
        Err(e) => e,
    }
}

fn index_of(mounts: &[Mount], target: &str) -> u32 {
    mounts
        .iter()
        .position(|m| m.target().as_str() == target)
        .unwrap_or_else(|| panic!("no mount at {target}")) as u32
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn pivot_root_hides_host() {
    let fixture = Fixture::new("pivot");
    // A host file outside every layer and bind.
    let outside = TempDir::new("outside");
    let marker = outside.path().join("marker");
    std::fs::write(&marker, b"host").expect("write the marker");
    let marker = marker.canonicalize().expect("canonical marker");
    let before = host_mountinfo();
    let p = run_probe_on(
        "mounts",
        ids(0, 0),
        &[(
            "BONELI_PROBE_MARKER",
            marker.to_str().expect("UTF-8 marker path"),
        )],
        fixture.root(),
    );
    let after = host_mountinfo();
    p.assert_ok();
    let mut want: Vec<String> = vec!["/".to_string()];
    for m in fixture.mounts() {
        want.push(m.target().as_str().to_string());
        if let Mount::Dev { target, .. } = &m {
            for sub in [
                "null", "zero", "full", "random", "urandom", "tty", "pts", "shm",
            ] {
                want.push(format!("{}/{sub}", target.as_str()));
            }
        }
    }
    want.sort();
    let mut got: Vec<String> = mounts_of(&p).into_iter().map(|(p, _, _)| p).collect();
    got.sort();
    assert_eq!(
        got, want,
        "exactly the root and the spec's mounts: {}",
        p.raw
    );
    assert_eq!(p.get("marker_errno"), libc::ENOENT.to_string(), "{}", p.raw);
    assert_eq!(
        p.get("marker_up_errno"),
        libc::ENOENT.to_string(),
        "{}",
        p.raw
    );
    assert_eq!(p.get("proc1_root"), "/", "{}", p.raw);
    assert_eq!(before, after, "the host's mount table changed");
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn root_is_read_only() {
    let fixture = Fixture::new("ro-root");
    let p = run_probe_on("writes", ids(0, 0), &[], fixture.root());
    p.assert_ok();
    let erofs = libc::EROFS.to_string();
    assert_eq!(p.get("etc_errno"), erofs, "/etc/x: {}", p.raw);
    assert_eq!(p.get("mkdir_errno"), erofs, "mkdir /new: {}", p.raw);
    assert_eq!(p.get("workspace_errno"), "0", "/workspace: {}", p.raw);
    assert_eq!(p.get("tmp_errno"), "0", "/tmp: {}", p.raw);
    assert_eq!(
        std::fs::read(fixture.workspace.join("w")).expect("the write reached the host"),
        b"x"
    );
    assert!(
        !fixture.layer.join("etc/x").exists() && !fixture.layer.join("new").exists(),
        "the layer was written"
    );
}

fn set_xattr(path: &Path, name: &std::ffi::CStr, value: &[u8]) {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path");
    // SAFETY: both strings are NUL-terminated and value is valid for its
    // length.
    let rc = unsafe {
        libc::setxattr(
            c.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    assert_eq!(
        rc,
        0,
        "setxattr {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn overlay_layers_whiteout_and_opaque() {
    let fixture = Fixture::new("layers");
    let bottom = &fixture.layer;
    std::fs::write(bottom.join("both"), b"bottom").expect("write");
    std::fs::write(bottom.join("gone"), b"bottom").expect("write");
    std::fs::write(bottom.join("bottom-only"), b"bottom").expect("write");
    std::fs::create_dir(bottom.join("opq")).expect("mkdir");
    std::fs::write(bottom.join("opq/inner"), b"bottom").expect("write");

    let top = fixture.tree().dir("layers/top");
    std::fs::write(top.join("both"), b"top").expect("write");
    // A whiteout: a 0:0 character device, which an unprivileged user may
    // create since Linux 5.8 (the format #7 unpacks into).
    let gone = std::ffi::CString::new(top.join("gone").as_os_str().as_bytes()).expect("path");
    // SAFETY: gone is NUL-terminated; mode and device are plain integers.
    let rc = unsafe { libc::mknod(gone.as_ptr(), libc::S_IFCHR, libc::makedev(0, 0)) };
    let mknod = std::io::Error::last_os_error();
    report(&format!(
        "overlay_layers_whiteout_and_opaque: unprivileged mknod of a 0:0 whiteout: {}",
        if rc == 0 {
            "allowed".to_string()
        } else {
            mknod.to_string()
        }
    ));
    assert_eq!(rc, 0, "unprivileged whiteout: {mknod}");
    std::fs::create_dir(top.join("opq")).expect("mkdir");
    set_xattr(&top.join("opq"), c"user.overlay.opaque", b"y");

    let root = fixture.root_with(vec![bottom.clone(), top], fixture.mounts());
    let p = run_probe_on(
        "read",
        ids(0, 0),
        &[("BONELI_PROBE_FILES", "/both,/gone,/opq/inner,/bottom-only")],
        root.clone(),
    );
    p.assert_ok();
    let enoent = format!("errno={}", libc::ENOENT);
    assert_eq!(p.get("file:/both"), "top", "{}", p.raw);
    assert_eq!(p.get("file:/gone"), enoent, "whiteout: {}", p.raw);
    assert_eq!(p.get("file:/opq/inner"), enoent, "opaque dir: {}", p.raw);
    assert_eq!(p.get("file:/bottom-only"), "bottom", "{}", p.raw);

    let p = run_probe_on("mounts", ids(0, 0), &[], root);
    p.assert_ok();
    let all = mounts_of(&p);
    let (_, opts, fstype) = mount_at(&all, "/");
    assert_eq!(fstype, "overlay", "{}", p.raw);
    assert!(has(opts, &["ro", "nosuid", "nodev"]), "{opts:?}");
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn single_layer_root_is_bind() {
    let fixture = Fixture::new("one-layer");
    let p = run_probe_on("mounts", ids(0, 0), &[], fixture.root());
    p.assert_ok();
    let all = mounts_of(&p);
    let (_, opts, fstype) = mount_at(&all, "/");
    assert_ne!(
        fstype, "overlay",
        "one layer is bound, not overlaid: {}",
        p.raw
    );
    assert!(has(opts, &["ro", "nosuid", "nodev"]), "{opts:?}");
}

// The root overlay option-length gate is now count-based (fd-path options,
// ADR-007 D7 / review 1b) and lives in `plan()`; it is covered by the pure
// unit test `mount::tests::overlay_option_page_limit`, so there is no host
// test for it here.

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn writable_overlay_mount() {
    let fixture = Fixture::new("rw-overlay");
    let lower = fixture.tree().dir("ov/lower");
    let upper = fixture.tree().dir("ov/upper");
    let work = fixture.tree().dir("ov/work");
    std::fs::write(lower.join("existing"), b"lower").expect("write");
    let mut mounts = fixture.mounts();
    mounts.push(Mount::Overlay {
        lower: lower.clone(),
        upper: upper.clone(),
        work,
        target: inside("/work2"),
    });
    let p = run_probe_on(
        "write",
        ids(0, 0),
        &[(
            "BONELI_PROBE_WRITES",
            "/work2/new=n,/work2/existing=changed",
        )],
        fixture.root_with(vec![fixture.layer.clone()], mounts),
    );
    p.assert_ok();
    assert_eq!(p.get("errno:/work2/new"), "0", "{}", p.raw);
    assert_eq!(p.get("errno:/work2/existing"), "0", "{}", p.raw);
    assert_eq!(std::fs::read(upper.join("new")).expect("upper/new"), b"n");
    assert_eq!(
        std::fs::read(upper.join("existing")).expect("upper/existing"),
        b"changed"
    );
    assert_eq!(
        std::fs::read(lower.join("existing")).expect("lower/existing"),
        b"lower",
        "the lower directory is unchanged"
    );
    assert!(!lower.join("new").exists());
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn tmpfs_size_inclusive() {
    const SIZE: u64 = 1_048_576;
    let fixture = Fixture::new("tmpfs-size");
    let mounts: Vec<Mount> = fixture
        .mounts()
        .into_iter()
        .map(|m| match m {
            Mount::Tmpfs { target, mode, .. } => Mount::Tmpfs {
                target,
                size_bytes: SIZE,
                mode,
            },
            other => other,
        })
        .collect();
    let p = run_probe_on(
        "fill",
        ids(0, 0),
        &[
            ("BONELI_PROBE_FILE", "/tmp/fill"),
            ("BONELI_PROBE_SIZE", &SIZE.to_string()),
        ],
        fixture.root_with(vec![fixture.layer.clone()], mounts),
    );
    p.assert_ok();
    assert_eq!(p.get("fill_errno"), "0", "{SIZE} bytes fit: {}", p.raw);
    assert_eq!(
        p.get("more_errno"),
        libc::ENOSPC.to_string(),
        "one byte more does not: {}",
        p.raw
    );
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn mount_flags() {
    let fixture = Fixture::new("flags");
    let p = run_probe_on("mounts", ids(0, 0), &[], fixture.root());
    p.assert_ok();
    let all = mounts_of(&p);
    let (_, root, _) = mount_at(&all, "/");
    assert!(has(root, &["ro", "nosuid", "nodev"]), "/: {root:?}");
    for point in ["/tmp", "/workspace"] {
        let (_, opts, _) = mount_at(&all, point);
        assert!(has(opts, &["rw", "nosuid", "nodev"]), "{point}: {opts:?}");
        assert!(!opts.contains("noexec"), "{point} allows exec: {opts:?}");
    }
    let (_, proc, fstype) = mount_at(&all, "/proc");
    assert_eq!(fstype, "proc");
    assert!(has(proc, &["nosuid", "nodev", "noexec"]), "/proc: {proc:?}");
    let (_, dev, _) = mount_at(&all, "/dev");
    assert!(has(dev, &["ro", "nosuid", "noexec"]), "/dev: {dev:?}");
    let (_, usr, _) = mount_at(&all, "/usr");
    assert!(has(usr, &["ro", "nosuid", "nodev"]), "/usr: {usr:?}");
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn ro_bind_keeps_locked_flags() {
    let host = host_mountinfo();
    let shm_opts: BTreeSet<String> = host
        .lines()
        .map(|l| l.split(' ').collect::<Vec<_>>())
        .find(|f| f.len() > 5 && f[4] == "/dev/shm")
        .map(|f| f[5].split(',').map(str::to_string).collect())
        .expect("the host has /dev/shm");
    assert!(
        has(&shm_opts, &["nosuid", "nodev"]),
        "the host's /dev/shm is not nosuid,nodev, so this test proves nothing: {shm_opts:?}"
    );
    let fixture = Fixture::new("locked");
    let mut mounts = fixture.mounts();
    mounts.push(Mount::Bind {
        source: PathBuf::from("/dev/shm"),
        target: inside("/shm-ro"),
        writable: false,
    });
    let p = run_probe_on(
        "mounts",
        ids(0, 0),
        &[],
        fixture.root_with(vec![fixture.layer.clone()], mounts),
    );
    p.assert_ok();
    let all = mounts_of(&p);
    let (_, opts, _) = mount_at(&all, "/shm-ro");
    assert!(has(opts, &["ro", "nosuid", "nodev"]), "{opts:?}");
    for flag in ["noexec", "relatime", "noatime"] {
        if shm_opts.contains(flag) {
            assert!(
                opts.contains(flag),
                "the source's {flag} was dropped: {opts:?}"
            );
        }
    }
}

fn replace_with_symlink(path: &Path, to: &str) {
    std::fs::remove_dir(path).expect("remove the mount point");
    std::os::unix::fs::symlink(to, path).expect("symlink");
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn mount_target_symlink_rejected() {
    let before = host_mountinfo();
    // A trailing symlink to a host path, a trailing symlink out of the
    // root, and a symlink in the middle of a target.
    for (link, to, target) in [
        ("workspace", "/etc", "/workspace"),
        ("tmp", "../../..", "/tmp"),
    ] {
        let fixture = Fixture::new("symlink-target");
        replace_with_symlink(&fixture.layer.join(link), to);
        let mounts = fixture.mounts();
        let index = index_of(&mounts, target);
        match spawn_error(fixture.root_with(vec![fixture.layer.clone()], mounts)) {
            Error::Setup {
                step: Step::MountTarget,
                index: got,
                errno,
            } => {
                assert_eq!((got, errno), (index, libc::ELOOP), "{link} -> {to}");
            }
            other => panic!("{link} -> {to}: {other:?}"),
        }
    }
    let fixture = Fixture::new("symlink-middle");
    std::fs::create_dir_all(fixture.layer.join("real/sub")).expect("mkdir");
    std::os::unix::fs::symlink("real", fixture.layer.join("lnk")).expect("symlink");
    let mut mounts = fixture.mounts();
    mounts.push(Mount::Tmpfs {
        target: inside("/lnk/sub"),
        size_bytes: 4096,
        mode: 0o755,
    });
    let index = index_of(&mounts, "/lnk/sub");
    match spawn_error(fixture.root_with(vec![fixture.layer.clone()], mounts)) {
        Error::Setup {
            step: Step::MountTarget,
            index: got,
            errno,
        } => assert_eq!((got, errno), (index, libc::ELOOP), "lnk/sub"),
        other => panic!("lnk/sub: {other:?}"),
    }
    assert_eq!(before, host_mountinfo(), "the host's mount table changed");
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn mount_target_missing() {
    let fixture = Fixture::new("missing-target");
    let mut mounts = fixture.mounts();
    mounts.push(Mount::Tmpfs {
        target: inside("/nonexistent"),
        size_bytes: 4096,
        mode: 0o755,
    });
    let index = index_of(&mounts, "/nonexistent");
    match spawn_error(fixture.root_with(vec![fixture.layer.clone()], mounts)) {
        Error::Setup {
            step: Step::MountTarget,
            index: got,
            errno,
        } => assert_eq!((got, errno), (index, libc::ENOENT)),
        other => panic!("{other:?}"),
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn bind_kind_mismatch() {
    let fixture = Fixture::new("kind");
    let file = fixture.tree().path().join("a-file");
    std::fs::write(&file, b"f").expect("write");
    for (source, target, want) in [
        (
            fixture.workspace.clone(),
            "/run/boneli/egress.sock",
            libc::ENOTDIR,
        ),
        (file, "/empty", libc::EISDIR),
    ] {
        let mut mounts = fixture.mounts();
        mounts.push(Mount::Bind {
            source,
            target: inside(target),
            writable: false,
        });
        let index = index_of(&mounts, target);
        match spawn_error(fixture.root_with(vec![fixture.layer.clone()], mounts)) {
            Error::Setup {
                step: Step::Bind,
                index: got,
                errno,
            } => assert_eq!((got, errno), (index, want), "{target}"),
            other => panic!("{target}: {other:?}"),
        }
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn bind_source_symlink_rejected() {
    // Bind sources are host paths resolved without following symlinks, so
    // a swapped component cannot redirect a bind.
    let fixture = Fixture::new("source-symlink");
    let link = fixture.tree().path().join("link");
    std::os::unix::fs::symlink(&fixture.workspace, &link).expect("symlink");
    let mut mounts = fixture.mounts();
    mounts.push(Mount::Bind {
        source: link,
        target: inside("/empty"),
        writable: false,
    });
    let index = index_of(&mounts, "/empty");
    match spawn_error(fixture.root_with(vec![fixture.layer.clone()], mounts)) {
        Error::Setup {
            step: Step::Bind,
            index: got,
            errno,
        } => assert_eq!((got, errno), (index, libc::ELOOP)),
        other => panic!("{other:?}"),
    }
}

/// A host listener on a pathname socket in its own directory; bound
/// through `/proc/self/fd/<dir>/s`, because the temp path can be longer than
/// `sun_path` (108 bytes). Serves one byte to the first connection within
/// the hang bound.
struct Listener {
    socket: PathBuf,
    thread: std::thread::JoinHandle<bool>,
}

fn listen(tree: &crate::support::rootfs::Tree) -> Listener {
    let dir = tree.dir("sock");
    let dir_fd = std::fs::File::open(&dir).expect("open the socket dir");
    let short = format!("/proc/self/fd/{}/s", dir_fd.as_raw_fd());
    let listener = std::os::unix::net::UnixListener::bind(&short).expect("bind the listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let thread = std::thread::spawn(move || {
        use std::io::Write;
        let deadline = Instant::now() + support::PROBE_HANG_BOUND;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let _ = s.set_nonblocking(false);
                    return s.write_all(b"b").is_ok();
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        false
    });
    Listener {
        socket: dir.join("s"),
        thread,
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn broker_socket_reachable_through_ro_bind() {
    for inside_id in [0, 999] {
        let fixture = Fixture::new("broker");
        let listener = listen(fixture.tree());
        let mut mounts = fixture.mounts();
        mounts.push(Mount::Bind {
            source: listener.socket.clone(),
            target: inside("/run/boneli/egress.sock"),
            writable: false,
        });
        let p = run_probe_on(
            "connect",
            ids(inside_id, inside_id),
            &[("BONELI_PROBE_SOCKET", "/run/boneli/egress.sock")],
            fixture.root_with(vec![fixture.layer.clone()], mounts),
        );
        p.assert_ok();
        assert_eq!(p.get("connect_errno"), "0", "inside {inside_id}: {}", p.raw);
        assert_eq!(p.get("byte"), "b", "inside {inside_id}: {}", p.raw);
        assert!(
            listener.thread.join().expect("listener"),
            "the host listener served"
        );
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn host_abstract_sockets_unreachable() {
    use std::os::linux::net::SocketAddrExt;
    let name = format!("boneli-sys-test-{}", std::process::id());
    let addr =
        std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract name");
    let _listener =
        std::os::unix::net::UnixListener::bind_addr(&addr).expect("bind the abstract listener");
    // Reachable from the host's network namespace.
    std::os::unix::net::UnixStream::connect_addr(&addr).expect("connect on the host");
    let fixture = Fixture::new("abstract");
    let p = run_probe_on(
        "connect-abstract",
        ids(0, 0),
        &[("BONELI_PROBE_NAME", &name)],
        fixture.root(),
    );
    p.assert_ok();
    assert_eq!(
        p.get("connect_errno"),
        libc::ECONNREFUSED.to_string(),
        "{}",
        p.raw
    );
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn dev_minimal() {
    let fixture = Fixture::new("dev");
    let p = run_probe_on("dev", ids(0, 0), &[], fixture.root());
    p.assert_ok();
    assert_eq!(p.get("entries"), DEV_ENTRIES.join(","), "{}", p.raw);
    assert_eq!(p.get("null_errno"), "0", "{}", p.raw);
    assert_eq!(p.get("create_errno"), libc::EROFS.to_string(), "{}", p.raw);
    assert_eq!(p.get("openpt_errno"), "0", "{}", p.raw);
    report(&format!(
        "dev_minimal: the /dev tmpfs holds {} bytes of its 65536",
        p.get("used_bytes")
    ));
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn program_resolves_inside_the_root() {
    // The program path is resolved after pivot_root: a host path that is
    // not in the root does not exist inside.
    let fixture = Fixture::new("program-path");
    let exe: OsString = std::env::current_exe()
        .expect("current_exe")
        .into_os_string();
    let spec = Spec {
        program: PathBuf::from(exe),
        args: Vec::new(),
        env: Vec::new(),
        stdio: Stdio {
            stdin: dev_null(),
            stdout: dev_null(),
            stderr: dev_null(),
        },
        ids: ids(0, 0),
        setup_timeout: support::SETUP_TIMEOUT,
        root: fixture.root(),
    };
    match spawn(&spec) {
        Err(Error::Setup {
            step: Step::Exec,
            errno,
            ..
        }) => assert_eq!(errno, libc::ENOENT),
        other => panic!("{other:?}"),
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn overlay_dir_symlink_rejected() {
    // A writable overlay whose upper (then lower, then work) is a symlink
    // to another host directory. A bind source fails ELOOP; the overlay
    // directory must fail closed the same way, not follow the symlink into
    // the target. Without the fix the write landed in the symlink target.
    for which in ["upper", "lower", "work"] {
        let fixture = Fixture::new("ovl-symlink");
        let lower = fixture.tree().dir("ov/lower");
        let upper = fixture.tree().dir("ov/upper");
        let work = fixture.tree().dir("ov/work");
        let elsewhere = fixture.tree().dir("ov/elsewhere");
        let link = fixture.tree().path().join(format!("ov/{which}-link"));
        std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");
        let (lower, upper, work) = match which {
            "upper" => (lower, link.clone(), work),
            "lower" => (link.clone(), upper, work),
            _ => (lower, upper, link.clone()),
        };
        let mut mounts = fixture.mounts();
        mounts.push(Mount::Overlay {
            lower,
            upper,
            work,
            target: inside("/work2"),
        });
        let index = index_of(&mounts, "/work2");
        match spawn_error(fixture.root_with(vec![fixture.layer.clone()], mounts)) {
            Error::Setup {
                step: Step::Overlay,
                index: got,
                errno,
            } => assert_eq!(
                (got, errno),
                (index, libc::ELOOP),
                "overlay {which} symlink"
            ),
            other => panic!("overlay {which} symlink: {other:?}"),
        }
        assert!(
            !elsewhere.join("new").exists(),
            "the overlay followed the {which} symlink into its target"
        );
    }
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn root_layer_symlink_rejected() {
    // A root layer that is a symlink to a host directory outside the layer
    // store (holding a secret). The overlay must not follow it and expose
    // the host directory as the top of the sandbox root; it fails closed
    // (ELOOP) at the root step, as a symlinked bind source does.
    let fixture = Fixture::new("layer-symlink");
    let host = fixture.tree().dir("hostdir");
    std::fs::write(host.join("secret"), b"HOSTSECRET").expect("write the secret");
    let link = fixture.tree().path().join("top-link");
    std::os::unix::fs::symlink(&host, &link).expect("symlink");
    match spawn_error(fixture.root_with(vec![fixture.layer.clone(), link], fixture.mounts())) {
        Error::Setup {
            step: Step::Root,
            errno,
            ..
        } => assert_eq!(errno, libc::ELOOP, "a symlinked layer must be rejected"),
        other => panic!("{other:?}"),
    }
}

/// A host thread that exchanges `a` and `b` with `renameat2(RENAME_EXCHANGE)`
/// in a tight loop until stopped; returns the stop flag and the handle.
fn swap_loop(
    a: &Path,
    b: &Path,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<u64>,
) {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let a = std::ffi::CString::new(a.as_os_str().as_bytes()).expect("a");
    let b = std::ffi::CString::new(b.as_os_str().as_bytes()).expect("b");
    let handle = std::thread::spawn(move || {
        let mut n = 0u64;
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            // SAFETY: both paths are NUL-terminated for the call's duration.
            unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    a.as_ptr(),
                    libc::AT_FDCWD,
                    b.as_ptr(),
                    libc::RENAME_EXCHANGE,
                );
            }
            n += 1;
        }
        n
    });
    (stop, handle)
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn overlay_upper_swap_race_never_escapes() {
    // `upper` is a real directory; a host thread exchanges it with a
    // symlink to `elsewhere` while sandboxes start. Because the child opens
    // upper without symlinks and mounts the descriptor, a write must land
    // in the real upper (or the spawn fails closed), never in `elsewhere`.
    let fixture = Fixture::new("upper-swap");
    let lower = fixture.tree().dir("rv/lower");
    let work = fixture.tree().dir("rv/work");
    let elsewhere = fixture.tree().dir("rv/elsewhere");
    let upper = fixture.tree().dir("rv/upper");
    let alt = fixture.tree().path().join("rv/upper-alt");
    std::os::unix::fs::symlink(&elsewhere, &alt).expect("symlink");
    let (stop, swapper) = swap_loop(&upper, &alt);
    let mut spawned = 0;
    for i in 0..120 {
        let mut mounts = fixture.mounts();
        mounts.push(Mount::Overlay {
            lower: lower.clone(),
            upper: upper.clone(),
            work: work.clone(),
            target: inside("/work2"),
        });
        let name = format!("esc-{i}");
        // The spawn may fail closed when upper is the symlink at open time;
        // only a leak into `elsewhere` is a failure.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_probe_on(
                "write",
                ids(0, 0),
                &[("BONELI_PROBE_WRITES", &format!("/work2/{name}=x"))],
                fixture.root_with(vec![fixture.layer.clone()], mounts),
            )
        }));
        if r.is_ok() {
            spawned += 1;
        }
        assert!(
            !elsewhere.join(&name).exists(),
            "a write escaped into the swapped symlink target on try {i}"
        );
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let swaps = swapper.join().expect("swapper");
    report(&format!(
        "overlay_upper_swap_race_never_escapes: {spawned}/120 spawned, {swaps} swaps, no escape"
    ));
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn root_layer_swap_race_never_escapes() {
    // The top root layer is exchanged with a symlink to a host directory
    // holding a secret. The child opens each layer without symlinks and
    // mounts the descriptors, so the secret is never exposed; a swapped
    // layer at open time fails the spawn closed.
    let fixture = Fixture::new("layer-swap");
    let host = fixture.tree().dir("rv/hostdir");
    std::fs::write(host.join("secret"), b"HOSTSECRET").expect("secret");
    let top = fixture.tree().dir("rv/top");
    std::fs::write(top.join("marker"), b"TOP").expect("marker");
    let alt = fixture.tree().path().join("rv/top-alt");
    std::os::unix::fs::symlink(&host, &alt).expect("symlink");
    let (stop, swapper) = swap_loop(&top, &alt);
    let mut spawned = 0;
    for _ in 0..120 {
        let root = fixture.root_with(vec![fixture.layer.clone(), top.clone()], fixture.mounts());
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_probe_on(
                "read",
                ids(0, 0),
                &[("BONELI_PROBE_FILES", "/secret")],
                root,
            )
        }));
        if let Ok(p) = r {
            spawned += 1;
            assert_eq!(
                p.get("file:/secret"),
                &format!("errno={}", libc::ENOENT),
                "the host secret became readable: {}",
                p.raw
            );
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let swaps = swapper.join().expect("swapper");
    report(&format!(
        "root_layer_swap_race_never_escapes: {spawned}/120 spawned, {swaps} swaps, no secret read"
    ));
}

#[test]
#[ignore = "host: unprivileged user namespaces, overlayfs, Linux 5.19"]
fn fd_based_multi_layer_root_mounts() {
    // Three fd-named lower layers stack correctly: the top file wins and a
    // bottom-only file is still visible. Proves the fd-path option form
    // mounts a real multi-layer overlay.
    let fixture = Fixture::new("multi-layer");
    let bottom = &fixture.layer;
    std::fs::write(bottom.join("shared"), b"bottom").expect("w");
    std::fs::write(bottom.join("bottom-only"), b"b").expect("w");
    let mid = fixture.tree().dir("layers/mid");
    std::fs::write(mid.join("shared"), b"mid").expect("w");
    let top = fixture.tree().dir("layers/top");
    std::fs::write(top.join("shared"), b"top").expect("w");
    let root = fixture.root_with(vec![bottom.clone(), mid, top], fixture.mounts());
    let p = run_probe_on(
        "read",
        ids(0, 0),
        &[("BONELI_PROBE_FILES", "/shared,/bottom-only")],
        root,
    );
    p.assert_ok();
    assert_eq!(p.get("file:/shared"), "top", "{}", p.raw);
    assert_eq!(p.get("file:/bottom-only"), "b", "{}", p.raw);
}
