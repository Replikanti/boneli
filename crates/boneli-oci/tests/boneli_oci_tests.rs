//! Host and network tests of `boneli-oci` (#7, ADR-009).
//!
//! One test target, `boneli_oci_tests-<hash>`, so the AppArmor profile of
//! the host-setup block in `CLAUDE.md` names it next to the `boneli-sys`
//! test binaries. Every test here is `#[ignore]`:
//!
//! - `host::` needs unprivileged user namespaces, overlayfs and a
//!   delegated cgroup, like the `boneli-sys` host tests, and no network.
//!   CI runs it in the `sandbox` job:
//!   `cargo test -p boneli-oci --test boneli_oci_tests -- --ignored host::`
//!   in a scope started with `-p Delegate=yes` and
//!   `BONELI_SYS_TEST_CGROUP=self`.
//! - `network::` pulls `node:22` and `postgres:17` from Docker Hub and runs
//!   them; the `oci-acceptance` workflow runs it weekly and on demand.
//!
//! The test `probe` is this binary's probe mode: a host test re-executes
//! the binary inside the sandbox with `BONELI_OCI_PROBE=<action>`; without
//! that variable it does nothing.

mod support;

use support::sandbox;

/// The probe mode (see the crate docs); a no-op in a normal test run.
#[test]
fn probe() {
    if let Ok(action) = std::env::var(sandbox::ACTION_VAR) {
        sandbox::probe_main(&action);
    }
}

mod host {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use boneli_app::{ImageRef, ImageStore};
    use boneli_https::Sha256;
    use boneli_oci::{
        Budget, Compression, Error, LayerCache, Limits, OciImageStore, StoreConfig, unpack,
    };

    use crate::support::TempDir;
    use crate::support::images::{Layer, open, push};
    use crate::support::registry::{Fake, Hub};
    use crate::support::sandbox::{self, base_layer, ids, root};
    use crate::support::tarball::Tar;

    /// Lists a gap a kernel lacks, by name, so a test can skip it there.
    const GAPS: &str = "BONELI_OCI_HOST_GAPS";

    fn gap_listed(gap: &str) -> bool {
        std::env::var(GAPS).is_ok_and(|g| g.split(',').any(|x| x == gap))
    }

    /// A synthetic image pulled through the fake registry is mounted by
    /// `boneli_sys::spawn` on top of a base layer. The probe sees what the
    /// layers wrote: a whiteout hides a lower file, an opaque directory
    /// hides the lower one's contents, modes, a hard link (one inode, two
    /// links), a FIFO and a symlink.
    #[test]
    #[ignore = "host: unprivileged user namespaces, overlayfs, a delegated cgroup"]
    fn pulled_image_runs_in_sandbox() {
        let lower = Tar::new()
            .dir("etc", 0o755)
            .file("etc/gone", 0o644, b"lower\n")
            .file("etc/stays", 0o644, b"lower\n")
            .dir("opq", 0o755)
            .file("opq/old", 0o644, b"old\n")
            .file("keep", 0o640, b"keep\n")
            .finish();
        let upper = Tar::new()
            .file("etc/.wh.gone", 0o644, b"")
            .dir("opq", 0o755)
            .file("opq/.wh..wh..opq", 0o644, b"")
            .file("opq/new", 0o644, b"new\n")
            .dir("private", 0o711)
            .file("private/a", 0o600, b"a\n")
            .hardlink("private/b", "private/a")
            .fifo("pipe", 0o644)
            .symlink("link", "keep")
            .finish();
        let mut hub = Hub::default();
        let pushed = push(
            &mut hub,
            "library/synthetic",
            &[Layer::gzip(lower), Layer::tar(upper)],
            "",
        );
        let fake = Fake::new(move |s| hub.handle(s));
        let tmp = TempDir::new("host-pull");
        let store = open(&tmp.path().join("store"), &fake);
        let rootfs = store
            .pull(&ImageRef {
                name: "library/synthetic".to_owned(),
                digest: pushed.index.clone(),
                platform: "linux/amd64".to_owned(),
            })
            .expect("pull");

        let base = tmp.path().join("base");
        let staging = tmp.path().join("staging");
        std::fs::create_dir_all(&staging).expect("staging");
        let mounts = base_layer(&base);
        // The lease pins the layers from before the mount until the sandbox
        // is gone (ADR-025, D2).
        let lease = store.lease(&rootfs).expect("lease");
        let mut layers = vec![base];
        layers.extend_from_slice(lease.layers());
        let paths = "/etc/gone,/etc/stays,/opq/old,/opq/new,/keep,/private,/private/a,\
                     /private/b,/pipe,/link";
        let seen = sandbox::probe(
            "stat",
            &[(sandbox::PATHS_VAR, paths)],
            ids(0, 0),
            root(layers, &staging, mounts),
        );
        let get = |p: &str| {
            seen.get(p)
                .unwrap_or_else(|| panic!("no {p} in {seen:?}"))
                .as_str()
        };
        assert!(get("/etc/gone").starts_with("missing errno=2"), "{seen:?}");
        assert!(get("/etc/stays").starts_with("file:lower"), "{seen:?}");
        assert!(get("/opq/old").starts_with("missing errno=2"), "{seen:?}");
        assert!(get("/opq/new").starts_with("file:new"), "{seen:?}");
        assert!(
            get("/keep").starts_with("file:keep\\n mode=640 "),
            "{seen:?}"
        );
        assert!(get("/private").starts_with("dir mode=711 "), "{seen:?}");
        assert!(get("/pipe").starts_with("fifo mode=644 "), "{seen:?}");
        assert!(get("/link").starts_with("symlink->keep "), "{seen:?}");
        let ino = |p: &str| {
            get(p)
                .split(' ')
                .find_map(|f| f.strip_prefix("ino="))
                .map(str::to_owned)
        };
        assert!(
            get("/private/a").starts_with("file:a\\n mode=600 "),
            "{seen:?}"
        );
        assert!(get("/private/a").ends_with(" nlink=2"), "{seen:?}");
        assert_eq!(ino("/private/a"), ino("/private/b"), "{seen:?}");
    }

    fn budget() -> Budget {
        Budget::new(Limits::new(1 << 32, 1 << 34, 1 << 20, 1 << 20, 128).expect("limits"))
    }

    /// Re-executes this binary as `test` inside `unshare -Urm` after
    /// `setup` (a shell snippet over `$1`, a fresh directory) and passes
    /// `child_value` (a shell word, which may use `$1`) to the child in
    /// `child_var`.
    fn in_mount_namespace(test: &str, setup: &str, child_var: &str, child_value: &str) {
        in_namespaces("-Urm", test, setup, child_var, child_value);
    }

    /// [`in_mount_namespace`] with other `unshare` flags.
    fn in_namespaces(flags: &str, test: &str, setup: &str, child_var: &str, child_value: &str) {
        // The harness moves the run's processes into `leaf/` and enables
        // the controllers on the scope once, on first use. A child forked
        // into the scope before that, while another test does it, keeps
        // the scope from enabling them (EBUSY, seen on CI). So every test
        // that forks takes the parent first.
        sandbox::parent();
        let mount_point = TempDir::new(test.rsplit("::").next().unwrap_or("ns"));
        let exe = std::env::current_exe().expect("test binary");
        let script = format!(
            "{setup} && {child_var}={child_value} exec \"$0\" --exact {test} --ignored \
             --test-threads=1 --nocapture"
        );
        let out = Command::new("unshare")
            .args([flags, "sh", "-c", &script])
            .arg(&exe)
            .arg(mount_point.path())
            .output()
            .expect("spawn unshare");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "the child of {test} failed:\n{text}");
        assert!(text.contains("1 passed"), "the child ran the check: {text}");
    }

    /// The reviewer's sequence of #58: a directory `a`, a symlink `A`
    /// pointing out of the tree, then a file under `a`.
    fn alias_layer(outside: &Path) -> Vec<u8> {
        Tar::new()
            .dir("a", 0o755)
            .symlink("A", outside.to_str().expect("utf-8"))
            .file("a/pwned", 0o644, b"written through a symlink\n")
            .finish()
    }

    const CASEFOLD_CHILD: &str = "BONELI_OCI_CASEFOLD_CHILD";
    const CASEFOLD_GAP: &str = "tmpfs-casefold";

    fn casefold_child(cf: &Path) {
        // The store refuses a case-insensitive root at open.
        let store = cf.join("store");
        std::fs::create_dir(&store).expect("store");
        match LayerCache::new(&store) {
            Err(Error::CaseInsensitive(path)) => assert!(path.starts_with(&store), "{path:?}"),
            other => panic!("a casefold store was opened: {other:?}"),
        }

        // The unpacker refuses the alias even without the store's check.
        let outside = cf.join("outside");
        std::fs::create_dir(&outside).expect("outside");
        let layer = cf.join("layer");
        std::fs::create_dir(&layer).expect("layer");
        assert!(
            layer.join("A").exists() == layer.join("a").exists(),
            "casefold applies"
        );
        let bytes = alias_layer(&outside);
        let e = unpack(&bytes[..], Compression::None, &layer, &mut budget()).expect_err("alias");
        assert!(matches!(e, Error::Entry { .. }), "{e}");
        assert!(
            !outside.join("pwned").exists(),
            "a layer wrote outside its tree"
        );
        let _ = Sha256::digest(&bytes);
    }

    /// A case-insensitive store (ADR-009, D2 and D8). On a casefold
    /// directory a symlink named `A` can replace the directory `a`; the
    /// store refuses such a root, and the unpacker refuses the alias on its
    /// own. Needs tmpfs with `casefold` (Linux 6.13); where the kernel
    /// lacks it, list `tmpfs-casefold` in `BONELI_OCI_HOST_GAPS`. Moved
    /// here from `tests/casefold.rs`, so CI runs it (#58 review).
    #[test]
    #[ignore = "host: needs an unprivileged user namespace and tmpfs casefold"]
    fn casefold_store_and_alias_refused() {
        if let Some(cf) = std::env::var_os(CASEFOLD_CHILD) {
            casefold_child(&PathBuf::from(cf));
            return;
        }
        if gap_listed(CASEFOLD_GAP) {
            println!("skipped: {CASEFOLD_GAP} listed in {GAPS}");
            return;
        }
        in_mount_namespace(
            "host::casefold_store_and_alias_refused",
            "mount -t tmpfs -o casefold boneli-oci-casefold \"$1\" && mkdir \"$1/cf\" \
             && chattr +F \"$1/cf\"",
            CASEFOLD_CHILD,
            "\"$1/cf\"",
        );
    }

    const RAMFS_CHILD: &str = "BONELI_OCI_RAMFS_CHILD";

    /// A store on a filesystem without `user.*` extended attributes
    /// (ramfs) fails at `open` with `Unsupported`, not later in a pull
    /// (ADR-009, D1 and D8). The ramfs is mounted on `/mnt`, in the
    /// child's own mount namespace: in a user namespace every ancestor
    /// that the host's root owns shows the overflow uid, which the root's
    /// ancestor check refuses, so the root's ancestors must be the
    /// namespace's own mounts (`/`, whose owner is not checked, aside).
    #[test]
    #[ignore = "host: needs an unprivileged user namespace and ramfs"]
    fn unsupported_filesystem_refused() {
        if let Some(dir) = std::env::var_os(RAMFS_CHILD) {
            let fake = Fake::new(|_| unreachable!("open makes no request"));
            let config = StoreConfig::new(Box::new(fake)).expect("config");
            match OciImageStore::open(&PathBuf::from(dir).join("store"), config) {
                Err(Error::Unsupported { detail, .. }) => {
                    assert!(detail.contains("extended attributes"), "{detail}")
                }
                other => panic!("a store on ramfs was opened: {other:?}"),
            }
            return;
        }
        in_mount_namespace(
            "host::unsupported_filesystem_refused",
            "mount -t ramfs boneli-oci-ramfs /mnt && mkdir /mnt/r",
            RAMFS_CHILD,
            "/mnt/r",
        );
    }

    const PIDNS_CHILD: &str = "BONELI_OCI_PIDNS_CHILD";

    /// The review of #60: in a PID namespace whose `/proc` is not its own
    /// (`unshare -pf` without `--mount-proc`, bwrap `--unshare-pid`
    /// without `--proc`), `getpid()` is 1 while `/proc/1` is the host's
    /// init. Judged by that `/proc`, this process's own staging name looks
    /// dead and a second `open` used to delete it mid-pull. Now `open`
    /// judges no owner there by `/proc`, so every owned name without an
    /// owner lock file stays (ADR-009, D8); an owner whose lock file is
    /// free is removed there too, since the lock does not read `/proc`
    /// (ADR-025, D1).
    #[test]
    #[ignore = "host: needs an unprivileged user and PID namespace"]
    fn foreign_proc_judges_no_owner() {
        if let Some(dir) = std::env::var_os(PIDNS_CHILD) {
            pidns_child(&PathBuf::from(dir));
            return;
        }
        in_namespaces(
            "-Urpfm",
            "host::foreign_proc_judges_no_owner",
            "mount -t tmpfs -o mode=0700 boneli-oci-pidns /mnt",
            PIDNS_CHILD,
            "/mnt",
        );
    }

    fn pidns_child(dir: &Path) {
        let pid = std::process::id();
        let proc_self = std::fs::read_link("/proc/self").expect("/proc/self");
        assert_eq!(pid, 1, "the child is its PID namespace's init");
        assert_ne!(
            proc_self.to_str(),
            Some("1"),
            "/proc is the host's, not the namespace's"
        );
        let fake = Fake::new(|_| unreachable!("open makes no request"));
        let root = dir.join("store");
        let first = open(&root, &fake);
        let boot = crate::support::boot_hex();
        let ns = crate::support::own_pidns();
        let start = crate::support::start_of("self");
        let layers = root.join("layers/sha256");
        let blobs = root.join("blobs/sha256");
        let named = |prefix: &str, pid: u32, start: u64, n: u64| {
            crate::support::owned_name(
                prefix,
                &crate::support::owner_token(&boot, ns, pid, start),
                n,
            )
        };
        let kept = [
            // This live process, as `Owner::current` names it.
            layers.join(named(".tmp-", pid, start, 99)),
            blobs.join(named(".tmp-", pid, start, 98)),
            // A pid that names another process in the host's `/proc`.
            layers.join(named(".tmp-", 2, start, 97)),
            // A pid no process has in either view.
            layers.join(named(".tmp-", 4_194_303, start, 96)),
        ];
        for path in &kept {
            std::fs::create_dir_all(path.join("usr")).expect("staging");
        }
        // An owner with a free lock file is dead whatever `/proc` shows
        // (ADR-025, D1): its names go, then its lock file.
        let token = crate::support::owner_token(&boot, ns, 4_194_302, start);
        let lock = root.join("locks/owners").join(&token);
        std::fs::write(&lock, b"").expect("owner lock");
        let removed = [
            layers.join(crate::support::owned_name(".tmp-", &token, 95)),
            blobs.join(crate::support::owned_name(".tmp-", &token, 94)),
        ];
        for path in &removed {
            std::fs::create_dir_all(path.join("usr")).expect("staging");
        }
        drop(open(&root, &fake));
        for path in &kept {
            assert!(path.is_dir(), "{} was swept", path.display());
        }
        for path in removed.iter().chain([&lock]) {
            assert!(!path.exists(), "{} was kept", path.display());
        }
        drop(first);
    }

    const PIDPROC_CHILD: &str = "BONELI_OCI_PIDPROC_CHILD";

    /// The second review of #60: under a `/proc` that shows only process
    /// directories (procfs `subset=pid`, systemd's `ProcSubset=pid`), the
    /// boot id cannot be read, and `open` failed. Now such a process names
    /// its owner with a random id that no boot id equals, so the store
    /// opens and pulls, and no other process ever judges its names
    /// (ADR-009, D8).
    #[test]
    #[ignore = "host: needs an unprivileged user and PID namespace"]
    fn pid_only_proc_opens() {
        if let Some(dir) = std::env::var_os(PIDPROC_CHILD) {
            pidproc_child(&PathBuf::from(dir));
            return;
        }
        in_namespaces(
            "-Urpfm",
            "host::pid_only_proc_opens",
            "mount -t proc -o subset=pid proc /proc \
             && mount -t tmpfs -o mode=0700 boneli-oci-pidproc /mnt",
            PIDPROC_CHILD,
            "/mnt",
        );
    }

    fn pidproc_child(dir: &Path) {
        assert!(
            !Path::new("/proc/sys/kernel/random/boot_id").exists(),
            "the boot id is hidden"
        );
        let mut tar = Tar::new();
        tar.file("etc/hostname", 0o644, b"pid-only\n");
        let mut hub = Hub::default();
        let pushed = push(&mut hub, "library/app", &[Layer::tar(tar.finish())], "");
        let fake = Fake::new(move |s| hub.handle(s));
        let root = dir.join("store");
        let store = open(&root, &fake);
        store
            .pull(&ImageRef {
                name: "library/app".to_owned(),
                digest: pushed.index.clone(),
                platform: "linux/amd64".to_owned(),
            })
            .expect("pull");
        drop(open(&root, &fake));
    }

    const TIMENS_CHILD: &str = "BONELI_OCI_TIMENS_CHILD";
    const TIMENS_JUDGE: &str = "BONELI_OCI_TIMENS_JUDGE";
    const TIMENS_OWNER: &str = "BONELI_OCI_TIMENS_OWNER";
    const TIMENS_GAP: &str = "timens";

    /// The second review of #60: `/proc/<pid>/stat` reports start times
    /// shifted by the reader's time-namespace boottime offset, so a store
    /// opened under `unshare -T --boottime N`, with the same boot id, PID
    /// namespace and `/proc`, read a live owner's start time as another
    /// one and deleted its staging tree mid-pull. Now an owner in another
    /// time namespace is not judged (ADR-009, D8). The child (the owner)
    /// runs in `unshare -Urm` on a tmpfs root; the judge it starts runs in
    /// a new time namespace of that user namespace. Where the kernel has
    /// no time namespaces, list `timens` in `BONELI_OCI_HOST_GAPS`.
    #[test]
    #[ignore = "host: needs an unprivileged user namespace and a time namespace"]
    fn other_time_namespace_judges_no_owner() {
        if let Some(dir) = std::env::var_os(TIMENS_JUDGE) {
            timens_judge(&PathBuf::from(dir));
            return;
        }
        if let Some(dir) = std::env::var_os(TIMENS_CHILD) {
            timens_owner(&PathBuf::from(dir));
            return;
        }
        if gap_listed(TIMENS_GAP) {
            println!("skipped: {TIMENS_GAP} listed in {GAPS}");
            return;
        }
        in_mount_namespace(
            "host::other_time_namespace_judges_no_owner",
            "mount -t tmpfs -o mode=0700 boneli-oci-timens /mnt",
            TIMENS_CHILD,
            "/mnt",
        );
    }

    fn timens_owner(dir: &Path) {
        let fake = Fake::new(|_| unreachable!("open makes no request"));
        let root = dir.join("store");
        let first = open(&root, &fake);
        let pid = std::process::id();
        let start = crate::support::start_of("self");
        let token = crate::support::owner_token(
            &crate::support::boot_hex(),
            crate::support::own_pidns(),
            pid,
            start,
        );
        // This live process's names, as `Owner::current` makes them.
        let kept = [
            root.join("layers/sha256")
                .join(crate::support::owned_name(".tmp-", &token, 99)),
            root.join("blobs/sha256")
                .join(crate::support::owned_name(".tmp-", &token, 98)),
        ];
        for path in &kept {
            std::fs::create_dir_all(path.join("usr")).expect("staging");
        }
        let exe = std::env::current_exe().expect("test binary");
        let out = Command::new("unshare")
            .args(["-T", "--boottime", "100000", "-f"])
            .arg(&exe)
            .args([
                "--exact",
                "host::other_time_namespace_judges_no_owner",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(TIMENS_JUDGE, dir)
            .env(TIMENS_OWNER, format!("{pid}:{start}"))
            .output()
            .expect("spawn unshare -T");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "the judge failed:\n{text}");
        assert!(text.contains("1 passed"), "the judge ran: {text}");
        for path in &kept {
            assert!(path.is_dir(), "{} was swept", path.display());
        }
        drop(first);
    }

    /// Runs in the new time namespace: checks that it reads the owner's
    /// start time shifted, then opens the store.
    fn timens_judge(dir: &Path) {
        let owner = std::env::var(TIMENS_OWNER).expect("owner");
        let (pid, start) = owner.split_once(':').expect("pid:start");
        let start: u64 = start.parse().expect("start");
        assert!(
            crate::support::start_of(pid) > start,
            "the judge reads the owner's start time shifted"
        );
        let fake = Fake::new(|_| unreachable!("open makes no request"));
        drop(open(&dir.join("store"), &fake));
    }
}

mod network {
    use std::io::{self, Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use boneli_app::{ImageRef, ImageStore};
    use boneli_http::{IdleCheck, Transport};
    use boneli_https::{ConnectOptions, Roots, TlsConfig};
    use boneli_oci::{
        CONNECT_TIMEOUT, Dial, HANDSHAKE_TIMEOUT, IO_TIMEOUT, OciImageStore, StoreConfig, Stream,
        TlsDial,
    };
    use boneli_sys::ExitStatus;

    use crate::support::TempDir;
    use crate::support::sandbox::{self, ids, image_mounts, root};

    /// `library/node:22`, the index measured on 2026-11-16 (ADR-009).
    const NODE: &str = "sha256:e13726ca604184d7a91fcacab1fc09eefd642dc28e79ac34e85540dd93b78cfb";
    /// `library/postgres:17`, the index measured on 2026-11-16 (ADR-009).
    const POSTGRES: &str =
        "sha256:0d938e975177bef9f1f61f3f9dbcf2e0aa0a139568f66d3415ed8892eb97f6ac";

    /// What the measuring dial saw: bytes read, the longest gap between
    /// two reads of one connection, and per connection its bytes and the
    /// time from the dial to its last read.
    #[derive(Default)]
    struct Stats {
        bytes: u64,
        longest_gap: Duration,
        connections: Vec<(u64, Duration)>,
    }

    impl Stats {
        /// Bytes over the summed connection times: the download rate,
        /// without the unpacking between fetches.
        fn rate(&self) -> f64 {
            let busy: f64 = self.connections.iter().map(|c| c.1.as_secs_f64()).sum();
            self.bytes as f64 / 1_048_576.0 / busy.max(0.001)
        }

        /// The slowest connection that read at most 1 MiB, in seconds from
        /// the dial (name resolution, TCP, TLS, request) to its last read:
        /// what the fixed part of a deadline must cover (D12).
        fn slowest_small(&self) -> f64 {
            self.connections
                .iter()
                .filter(|c| c.0 <= 1 << 20)
                .map(|c| c.1.as_secs_f64())
                .fold(0.0, f64::max)
        }

        /// The connection that read the most bytes: its bytes, its time
        /// and its rate, the fetch closest to its deadline (D12).
        fn largest(&self) -> (u64, f64, f64) {
            let (bytes, took) = self
                .connections
                .iter()
                .copied()
                .max_by_key(|c| c.0)
                .unwrap_or_default();
            let secs = took.as_secs_f64();
            (bytes, secs, bytes as f64 / 1_048_576.0 / secs.max(0.001))
        }
    }

    /// A dial that measures every read of the connections it makes.
    #[derive(Clone)]
    struct Measured {
        inner: Arc<TlsDial>,
        stats: Arc<Mutex<Stats>>,
    }

    struct MeasuredStream {
        inner: Box<dyn Stream>,
        stats: Arc<Mutex<Stats>>,
        /// This connection's index in `Stats::connections`.
        index: usize,
        dialed: Instant,
        last: Instant,
    }

    impl Read for MeasuredStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            let now = Instant::now();
            let mut stats = self.stats.lock().expect("stats");
            stats.bytes += n as u64;
            stats.longest_gap = stats.longest_gap.max(now - self.last);
            if let Some(c) = stats.connections.get_mut(self.index) {
                c.0 += n as u64;
                c.1 = now - self.dialed;
            }
            self.last = now;
            Ok(n)
        }
    }

    impl Write for MeasuredStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.last = Instant::now();
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    impl Transport for MeasuredStream {
        fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.inner.set_read_timeout(timeout)
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.inner.set_write_timeout(timeout)
        }
    }

    impl IdleCheck for MeasuredStream {
        fn is_idle(&mut self) -> io::Result<Option<bool>> {
            self.inner.is_idle()
        }
    }

    impl Dial for Measured {
        fn dial(&self, host: &str, port: u16, deadline: Instant) -> io::Result<Box<dyn Stream>> {
            let dialed = Instant::now();
            let inner = self.inner.dial(host, port, deadline)?;
            let index = {
                let mut stats = self.stats.lock().expect("stats");
                stats.connections.push((0, Duration::ZERO));
                stats.connections.len() - 1
            };
            Ok(Box::new(MeasuredStream {
                inner,
                stats: Arc::clone(&self.stats),
                index,
                dialed,
                last: Instant::now(),
            }))
        }
    }

    /// One image of the acceptance and the program it runs.
    struct Case {
        name: &'static str,
        digest: &'static str,
        program: &'static str,
        args: &'static [&'static str],
        id: u32,
        expect: &'static str,
    }

    fn platform() -> &'static str {
        match std::env::consts::ARCH {
            "x86_64" => "linux/amd64",
            "aarch64" => "linux/arm64",
            other => panic!("no first-stack platform for {other}"),
        }
    }

    /// Pulls the two pinned indexes for this host's platform through the
    /// production dial and runs `node --version` (as inside id 0) and
    /// `postgres --version` (as 999, the image's postgres user, ADR-007
    /// D1) in the sandbox, on the image's layers alone. Logs pull time,
    /// throughput, the longest gap between reads and the layer media types
    /// (ADR-009, D5 and D12).
    #[test]
    #[ignore = "network: pulls node:22 and postgres:17 from Docker Hub; host: user namespaces"]
    fn node_and_postgres_run_in_sandbox() {
        let tls = TlsConfig::new(Roots::mozilla()).expect("tls");
        let options =
            ConnectOptions::new(CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT, IO_TIMEOUT).expect("options");
        let measured = Measured {
            inner: Arc::new(TlsDial::new(tls, options)),
            stats: Arc::default(),
        };
        let config = StoreConfig::new(Box::new(measured.clone())).expect("config");
        let tmp = TempDir::new("network");
        let store = OciImageStore::open(&tmp.path().join("store"), config).expect("open");
        let cases = [
            Case {
                name: "library/node",
                digest: NODE,
                program: "/usr/local/bin/node",
                args: &["--version"],
                id: 0,
                expect: "v22.",
            },
            Case {
                name: "library/postgres",
                digest: POSTGRES,
                program: "/bin/sh",
                args: &["-c", "exec postgres --version"],
                id: 999,
                expect: "postgres (PostgreSQL) 17.",
            },
        ];
        for Case {
            name,
            digest,
            program,
            args,
            id,
            expect,
        } in cases
        {
            *measured.stats.lock().expect("stats") = Stats::default();
            let started = Instant::now();
            let rootfs = store
                .pull(&ImageRef {
                    name: name.to_owned(),
                    digest: digest.to_owned(),
                    platform: platform().to_owned(),
                })
                .unwrap_or_else(|e| panic!("pull {name}: {e}"));
            let took = started.elapsed();
            let manifest = std::fs::read_to_string(
                store
                    .root()
                    .join("blobs/sha256")
                    .join(rootfs.as_str().trim_start_matches("sha256:")),
            )
            .expect("the manifest is kept");
            let media: Vec<&str> = manifest
                .split('"')
                .filter(|t| {
                    t.starts_with("application/vnd.")
                        && (t.contains(".layer.") || t.contains(".rootfs."))
                })
                .collect();
            {
                let stats = measured.stats.lock().expect("stats");
                let (big, big_secs, big_rate) = stats.largest();
                println!(
                    "oci-acceptance {name} {}: pull {:.1} s with unpacking, {} B read over {} \
                     connections at {:.1} MiB/s, largest fetch {big} B in {big_secs:.1} s \
                     ({big_rate:.1} MiB/s), slowest fetch of at most 1 MiB {:.2} s, longest gap \
                     between reads {:.3} s, layers {:?}",
                    platform(),
                    took.as_secs_f64(),
                    stats.bytes,
                    stats.connections.len(),
                    stats.rate(),
                    stats.slowest_small(),
                    stats.longest_gap.as_secs_f64(),
                    media
                );
            }
            let lease = store.lease(&rootfs).expect("lease");
            let layers = lease.layers().to_vec();
            let config = lease.config().clone();
            let env: Vec<(&str, &str)> = config
                .env
                .iter()
                .filter_map(|e| e.split_once('='))
                .collect();
            let staging = tmp.path().join(format!("staging-{id}"));
            std::fs::create_dir_all(&staging).expect("staging");
            let out = sandbox::run(
                program,
                args,
                &env,
                ids(id, id),
                root(layers, &staging, image_mounts()),
            );
            println!(
                "oci-acceptance {name}: {program} {args:?} as {id} -> {:?} {:?}",
                out.status,
                out.stdout.trim()
            );
            assert_eq!(out.status, ExitStatus::Exited(0), "{out:?}");
            assert!(out.stdout.starts_with(expect), "{out:?}");
        }
    }
}
