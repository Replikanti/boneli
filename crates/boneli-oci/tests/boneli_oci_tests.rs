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
//!   them, and checks image signatures on real registries (ADR-029); the
//!   `oci-acceptance` workflow runs it weekly and on demand.
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

    use boneli_app::{ImageOrigin, ImageRef, ImageStore};
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
                origin: ImageOrigin::Operator,
            })
            .expect("pull")
            .rootfs;

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

    /// The acceptance of #56: a layer mounted by a running sandbox is never
    /// removed. The probe runs on a leased image and waits on its stdin;
    /// meanwhile a second store on the root with a budget of 1 opens (and
    /// trims) and trims again: every layer stays, and the probe then reads
    /// a file of the lowest layer intact. Once the sandbox has exited and
    /// the lease is dropped, the next trim removes the layers.
    #[test]
    #[ignore = "host: unprivileged user namespaces, overlayfs, a delegated cgroup"]
    fn mounted_layers_survive_trim() {
        let lowest = Tar::new()
            .dir("data", 0o755)
            .file("data/lowest", 0o644, b"bottom\n")
            .finish();
        let upper = Tar::new().file("data/upper", 0o644, b"top\n").finish();
        let mut hub = Hub::default();
        let pushed = push(
            &mut hub,
            "library/mounted",
            &[Layer::gzip(lowest), Layer::tar(upper)],
            "",
        );
        let fake = Fake::new(move |s| hub.handle(s));
        let tmp = TempDir::new("host-trim");
        let store_root = tmp.path().join("store");
        let store = open(&store_root, &fake);
        let lease = store
            .pull_leased(&ImageRef {
                name: "library/mounted".to_owned(),
                digest: pushed.index.clone(),
                platform: "linux/amd64".to_owned(),
                origin: ImageOrigin::Operator,
            })
            .expect("pull");
        let layer_dirs = lease.layers().to_vec();
        assert_eq!(layer_dirs.len(), 2);

        let base = tmp.path().join("base");
        let staging = tmp.path().join("staging");
        let ready = tmp.path().join("ready");
        std::fs::create_dir_all(&staging).expect("staging");
        std::fs::create_dir_all(&ready).expect("ready");
        let mut mounts = base_layer(&base);
        std::fs::create_dir_all(base.join("ready")).expect("the ready mount point");
        mounts.push(boneli_sys::Mount::Bind {
            source: ready.clone(),
            target: sandbox::inside("/ready"),
            writable: true,
        });
        let mut layers = vec![base];
        layers.extend_from_slice(lease.layers());
        let running = sandbox::start_probe(
            "wait-stat",
            &[
                (sandbox::PATHS_VAR, "/data/lowest,/data/upper"),
                (sandbox::READY_VAR, "/ready/up"),
            ],
            ids(0, 0),
            root(layers, &staging, mounts),
        );
        let deadline = std::time::Instant::now() + sandbox::HANG_BOUND;
        while !ready.join("up").exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the probe never started"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        let mut config = crate::support::images::config(&fake);
        config.cache_budget = 1;
        let other = OciImageStore::open(&store_root, config).expect("a second store");
        let report = other.trim().expect("trim");
        let kept: Vec<bool> = layer_dirs.iter().map(|d| d.is_dir()).collect();
        let seen = sandbox::probe_values(&running.finish());
        assert_eq!(kept, [true, true], "a mounted layer went: {report:?}");
        assert_eq!(report.skipped_in_use, 2, "{report:?}");
        assert!(
            seen.get("/data/lowest")
                .is_some_and(|v| v.starts_with("file:bottom\\n ")),
            "{seen:?}"
        );
        assert!(
            seen.get("/data/upper")
                .is_some_and(|v| v.starts_with("file:top\\n ")),
            "{seen:?}"
        );

        drop(lease);
        let report = other.trim().expect("trim");
        assert_eq!(report.removed_layers, 2, "{report:?}");
        assert!(layer_dirs.iter().all(|d| !d.exists()));
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
                origin: ImageOrigin::Operator,
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

    use boneli_app::{ImageError, ImageExemption, ImageOrigin, ImageRef, ImageStore};
    use boneli_http::{IdleCheck, Transport};
    use boneli_https::{ConnectOptions, PublicKey, Roots, TlsConfig};
    use boneli_oci::{
        AgentExemption, CONNECT_TIMEOUT, Dial, HANDSHAKE_TIMEOUT, IO_TIMEOUT, OciImageStore,
        PolicyRule, Registry, RepoScope, Repository, Requirement, SignaturePolicy, StoreConfig,
        Stream, TlsDial,
    };
    use boneli_sigstore::{
        COSIGN_SIGN_PREDICATE, CertificateClaims, ClaimMatch, Claims, Identity, Material,
        SLSA_PROVENANCE_V1_PREDICATE, SanRule, Trust, TrustedRoot,
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
    /// (ADR-009, D5 and D12). Both references are the agent's, pulled
    /// under the documented first-stack exemption `docker.io` + `library/`
    /// (ADR-032, S4), and each pull reports it.
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
        let mut config = StoreConfig::new(Box::new(measured.clone())).expect("config");
        config.signatures = SignaturePolicy::off()
            .with_agent_exemptions(vec![AgentExemption::docker_official_images()])
            .expect("policy");
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
            let pulled = store
                .pull(&ImageRef {
                    name: name.to_owned(),
                    digest: digest.to_owned(),
                    platform: platform().to_owned(),
                    origin: ImageOrigin::Agent,
                })
                .unwrap_or_else(|e| panic!("pull {name}: {e}"));
            let took = started.elapsed();
            println!(
                "oci-acceptance {name}: chosen by the agent, admitted by {:?}",
                pulled.exemption
            );
            assert_eq!(
                pulled.exemption,
                Some(ImageExemption {
                    registry: "docker.io".to_owned(),
                    scope: "library/".to_owned(),
                })
            );
            let rootfs = pulled.rootfs;
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

    /// A dial that records the host of every connection it makes.
    #[derive(Clone)]
    struct Recording {
        inner: Arc<TlsDial>,
        hosts: Arc<Mutex<Vec<String>>>,
    }

    impl Dial for Recording {
        fn dial(&self, host: &str, port: u16, deadline: Instant) -> io::Result<Box<dyn Stream>> {
            self.hosts.lock().expect("hosts").push(host.to_owned());
            self.inner.dial(host, port, deadline)
        }
    }

    fn recording() -> Recording {
        let tls = TlsConfig::new(Roots::mozilla()).expect("tls");
        let options =
            ConnectOptions::new(CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT, IO_TIMEOUT).expect("options");
        Recording {
            inner: Arc::new(TlsDial::new(tls, options)),
            hosts: Arc::default(),
        }
    }

    /// The public-good `trusted_root.json` of 2026-11-20 (ADR-029).
    const TRUSTED_ROOT: &[u8] = include_bytes!("data/sigstore-trusted-root.json");
    /// cosign's release key, `release/release-cosign.pub` of
    /// `sigstore/cosign`.
    const COSIGN_RELEASE_KEY: &[u8] = include_bytes!("data/release-cosign.pub");
    /// `chainguard/node`, the index measured on 2026-11-20 (ADR-029), on
    /// Docker Hub and on `cgr.dev` with one digest.
    const CHAINGUARD_NODE: &str =
        "sha256:3fb5318a58807dec0f2ece547efbe8d62c67b7b2fd91a16795b98651d6385dbe";
    /// `ghcr.io/sigstore/cosign/cosign:v3.1.4` (`latest` on 2026-11-24).
    const COSIGN: &str = "sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d";
    /// `registry.k8s.io/pause:3.10` through Artifact Registry.
    const PAUSE: &str = "sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a";

    fn keyless(issuer: &str, san: SanRule) -> Requirement {
        let root = Arc::new(TrustedRoot::from_json(TRUSTED_ROOT).expect("root"));
        let identity = Identity::new(issuer, san).expect("identity");
        Requirement::Required(Arc::new(
            Trust::new(
                Vec::new(),
                Some((root, vec![identity])),
                vec![COSIGN_SIGN_PREDICATE.to_owned()],
            )
            .expect("trust"),
        ))
    }

    fn chainguard() -> Requirement {
        keyless(
            "https://token.actions.githubusercontent.com",
            SanRule::Uri(
                "https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main"
                    .to_owned(),
            ),
        )
    }

    /// The names in the store's layer directory, temporary ones aside.
    fn layer_entries(root: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(root.join("layers/sha256"))
            .expect("layers")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    fn rule(registry: &str, scope: RepoScope, requirement: Requirement) -> PolicyRule {
        PolicyRule {
            registry: registry.to_owned(),
            scope,
            requirement,
        }
    }

    /// Pulls `name@digest` for this host's platform and checks that every
    /// layer of the image is committed; prints the hosts dialed.
    fn pull_signed(store: &OciImageStore, dial: &Recording, name: &str, digest: &str) {
        dial.hosts.lock().expect("hosts").clear();
        let started = Instant::now();
        let rootfs = store
            .pull(&ImageRef {
                name: name.to_owned(),
                digest: digest.to_owned(),
                platform: platform().to_owned(),
                origin: ImageOrigin::Operator,
            })
            .unwrap_or_else(|e| panic!("pull {name}: {e}"))
            .rootfs;
        let lease = store.lease(&rootfs).expect("lease");
        assert!(!lease.layers().is_empty());
        for layer in lease.layers() {
            assert!(layer.is_dir(), "{}", layer.display());
        }
        let hosts = dial.hosts.lock().expect("hosts").clone();
        println!(
            "oci-acceptance signatures {name}@{digest} {}: pulled in {:.1} s, {} layers, {} connections",
            platform(),
            started.elapsed().as_secs_f64(),
            lease.layers().len(),
            hosts.len()
        );
        let pointers = std::fs::read_dir(store.root().join("signatures/sha256"))
            .expect("pointers")
            .count();
        assert!(pointers >= 1, "no pointer kept");
    }

    /// The acceptance of ADR-029 on Docker Hub: under a `Required` rule for
    /// `chainguard/` with Chainguard's workflow identity and the committed
    /// public-good root, `chainguard/node` pulls with every layer
    /// committed, and again from the kept evidence with no signature
    /// request; under one for `library/`, the unsigned `library/node`
    /// index of the weekly acceptance is refused with no layer request
    /// (the only CDN connection is the config's). Chosen by the agent, with
    /// no rule and no exemption, it is refused with no connection at all
    /// (ADR-032).
    #[test]
    #[ignore = "network: pulls chainguard/node and resolves node:22 on Docker Hub"]
    fn signatures_on_docker_hub() {
        let dial = recording();
        let mut config = StoreConfig::new(Box::new(dial.clone())).expect("config");
        config.signatures = SignaturePolicy::new(
            Requirement::Off,
            vec![
                rule(
                    "docker.io",
                    RepoScope::Prefix("chainguard/".to_owned()),
                    chainguard(),
                ),
                rule(
                    "docker.io",
                    RepoScope::Prefix("library/".to_owned()),
                    chainguard(),
                ),
            ],
        )
        .expect("policy");
        let tmp = TempDir::new("network-signatures");
        let root = tmp.path().join("store");
        let store = OciImageStore::open(&root, config).expect("open");
        pull_signed(&store, &dial, "chainguard/node", CHAINGUARD_NODE);
        let committed = layer_entries(&root);
        dial.hosts.lock().expect("hosts").clear();
        store
            .pull(&ImageRef {
                name: "chainguard/node".to_owned(),
                digest: CHAINGUARD_NODE.to_owned(),
                platform: platform().to_owned(),
                origin: ImageOrigin::Operator,
            })
            .expect("warm pull");
        assert!(
            dial.hosts.lock().expect("hosts").is_empty(),
            "the warm pull made requests"
        );

        dial.hosts.lock().expect("hosts").clear();
        let refused = store.pull(&ImageRef {
            name: "library/node".to_owned(),
            digest: NODE.to_owned(),
            platform: platform().to_owned(),
            origin: ImageOrigin::Operator,
        });
        let hosts = dial.hosts.lock().expect("hosts").clone();
        println!("oci-acceptance signatures library/node: {refused:?}, hosts {hosts:?}");
        match refused {
            Err(ImageError::Failed { detail }) => {
                assert!(detail.starts_with("signature policy: "), "{detail}");
                assert!(detail.contains(".sig: none"), "{detail}");
            }
            other => panic!("node:22 must be refused: {other:?}"),
        }
        let cdn = hosts.iter().filter(|h| h.ends_with(".docker.com")).count();
        assert_eq!(cdn, 1, "only the config comes from the CDN: {hosts:?}");
        assert_eq!(layer_entries(&root), committed, "node:22 committed a layer");

        let dial = recording();
        let config = StoreConfig::new(Box::new(dial.clone())).expect("config");
        let tmp = TempDir::new("network-agent");
        let store = OciImageStore::open(&tmp.path().join("store"), config).expect("open");
        let refused = store.pull(&ImageRef {
            name: "library/node".to_owned(),
            digest: NODE.to_owned(),
            platform: platform().to_owned(),
            origin: ImageOrigin::Agent,
        });
        let hosts = dial.hosts.lock().expect("hosts").clone();
        println!("oci-acceptance agent library/node, no exemption: {refused:?}, hosts {hosts:?}");
        match refused {
            Err(ImageError::Failed { detail }) => {
                assert!(detail.contains("was chosen by the agent"), "{detail}")
            }
            other => panic!("the agent's node:22 must be refused: {other:?}"),
        }
        assert!(hosts.is_empty(), "the refusal made a connection: {hosts:?}");
    }

    /// Real signatures on the other registries ADR-029 measured: cosign's
    /// keyed bundle on GHCR (no `.sig`, referrers API `404`, the tag
    /// schema's listing), Chainguard's keyless `.sig` on `cgr.dev`, and the
    /// Kubernetes release key's keyless `.sig` on `pause:3.10` through
    /// Artifact Registry (referrers `null`). Each pulls under a `Required`
    /// rule with its signer's identity, and is refused under another one.
    #[test]
    #[ignore = "network: pulls from ghcr.io, cgr.dev and europe-west3-docker.pkg.dev"]
    fn signatures_elsewhere() {
        let ghcr = Registry::new(
            "ghcr.io",
            "ghcr.io",
            &["ghcr.io"],
            &[".githubusercontent.com"],
        )
        .expect("ghcr");
        let cgr = Registry::new(
            "cgr.dev",
            "cgr.dev",
            &["cgr.dev"],
            &[".r2.cloudflarestorage.com"],
        )
        .expect("cgr");
        let ar = Registry::new(
            "europe-west3-docker.pkg.dev",
            "europe-west3-docker.pkg.dev",
            &[],
            &[],
        )
        .expect("artifact registry");
        let cosign_key = Requirement::Required(Arc::new(
            Trust::new(
                vec![PublicKey::from_pem(COSIGN_RELEASE_KEY).expect("key")],
                None,
                vec![COSIGN_SIGN_PREDICATE.to_owned()],
            )
            .expect("trust"),
        ));
        let kubernetes = keyless(
            "https://accounts.google.com",
            SanRule::Email("krel-trust@k8s-releng-prod.iam.gserviceaccount.com".to_owned()),
        );
        let wrong = keyless(
            "https://accounts.google.com",
            SanRule::Email("someone-else@example.com".to_owned()),
        );
        let cases = [
            (
                "ghcr.io/sigstore/cosign/cosign",
                COSIGN,
                "ghcr.io",
                "sigstore/cosign/cosign",
                cosign_key,
            ),
            (
                "cgr.dev/chainguard/node",
                CHAINGUARD_NODE,
                "cgr.dev",
                "chainguard/node",
                chainguard(),
            ),
            (
                "europe-west3-docker.pkg.dev/k8s-artifacts-prod/images/pause",
                PAUSE,
                "europe-west3-docker.pkg.dev",
                "k8s-artifacts-prod/images/pause",
                kubernetes,
            ),
        ];
        for (name, digest, registry, repository, requirement) in cases {
            for trusted in [false, true] {
                let dial = recording();
                let mut config = StoreConfig::new(Box::new(dial.clone())).expect("config");
                config.registries = vec![
                    Registry::docker_hub(),
                    ghcr.clone(),
                    cgr.clone(),
                    ar.clone(),
                ];
                let exact = RepoScope::Exact(Repository::parse(repository).expect("repository"));
                let requirement = if trusted {
                    requirement.clone()
                } else {
                    wrong.clone()
                };
                config.signatures = SignaturePolicy::new(
                    Requirement::Off,
                    vec![rule(registry, exact, requirement)],
                )
                .expect("policy");
                let tmp = TempDir::new("network-elsewhere");
                let store = OciImageStore::open(&tmp.path().join("store"), config).expect("open");
                if trusted {
                    pull_signed(&store, &dial, name, digest);
                    continue;
                }
                let refused = store.pull(&ImageRef {
                    name: name.to_owned(),
                    digest: digest.to_owned(),
                    platform: platform().to_owned(),
                    origin: ImageOrigin::Operator,
                });
                println!("oci-acceptance signatures {name} under another identity: {refused:?}");
                match refused {
                    Err(ImageError::Failed { detail }) => {
                        assert!(detail.starts_with("signature policy: "), "{detail}")
                    }
                    other => panic!("{name} must be refused: {other:?}"),
                }
            }
        }
    }

    /// `ghcr.io/jqlang/jq:1.8.2`, the index whose SLSA provenance ADR-031
    /// measured and whose bundle the offline tests hold.
    const JQ: &str = "sha256:b9c68867e5766576263a222e91db3de422d802069c7af70440e667a95344e486";

    /// jq's keyless SLSA trust: its tag-release workflow by SAN prefix,
    /// with the source repository `repository`, a tag ref and the release
    /// commit as claims (ADR-031).
    fn jq_provenance(repository: &str) -> Requirement {
        let root = Arc::new(TrustedRoot::from_json(TRUSTED_ROOT).expect("root"));
        let identity = Identity::new(
            "https://token.actions.githubusercontent.com",
            SanRule::UriPrefix(
                "https://github.com/jqlang/jq/.github/workflows/ci.yml@refs/tags/".to_owned(),
            ),
        )
        .expect("identity");
        let claims = Claims::new(
            None,
            Some(ClaimMatch::Exact(repository.to_owned())),
            Some(ClaimMatch::Prefix("refs/tags/".to_owned())),
            vec![
                Material::new(
                    "git+https://github.com/jqlang/jq@refs/tags/jq-1.8.2",
                    "gitCommit",
                    "34f7186b86743a083a589741b6cea95293524108",
                )
                .expect("material"),
            ],
        )
        .expect("claims");
        Requirement::Required(Arc::new(
            Trust::new(
                Vec::new(),
                Some((root, vec![identity])),
                vec![SLSA_PROVENANCE_V1_PREDICATE.to_owned()],
            )
            .expect("trust")
            .with_claims(claims)
            .expect("with claims"),
        ))
    }

    /// The acceptance of ADR-031 on GHCR: under a `Required` rule whose
    /// trust has SLSA provenance claims, jq 1.8.2 pulls with every layer
    /// committed (its GitHub artifact attestation, found through the tag
    /// schema); under the same rule with another source repository it is
    /// refused before any layer is committed, and the detail names the
    /// claim.
    #[test]
    #[ignore = "network: pulls jqlang/jq from ghcr.io"]
    fn provenance_claims_on_ghcr() {
        let ghcr = Registry::new(
            "ghcr.io",
            "ghcr.io",
            &["ghcr.io"],
            &[".githubusercontent.com"],
        )
        .expect("ghcr");
        for repository in [
            "https://github.com/jqlang/jq",
            "https://github.com/jqlang/other",
        ] {
            let dial = recording();
            let mut config = StoreConfig::new(Box::new(dial.clone())).expect("config");
            config.registries = vec![Registry::docker_hub(), ghcr.clone()];
            config.signatures = SignaturePolicy::new(
                Requirement::Off,
                vec![rule(
                    "ghcr.io",
                    RepoScope::Exact(Repository::parse("jqlang/jq").expect("repository")),
                    jq_provenance(repository),
                )],
            )
            .expect("policy");
            let tmp = TempDir::new("network-provenance");
            let root = tmp.path().join("store");
            let store = OciImageStore::open(&root, config).expect("open");
            if repository.ends_with("/jq") {
                pull_signed(&store, &dial, "ghcr.io/jqlang/jq", JQ);
                continue;
            }
            let refused = store.pull(&ImageRef {
                name: "ghcr.io/jqlang/jq".to_owned(),
                digest: JQ.to_owned(),
                platform: platform().to_owned(),
                origin: ImageOrigin::Operator,
            });
            println!(
                "oci-acceptance provenance ghcr.io/jqlang/jq under another repository: {refused:?}"
            );
            match refused {
                Err(ImageError::Failed { detail }) => {
                    assert!(detail.starts_with("signature policy: "), "{detail}");
                    assert!(
                        detail
                            .contains("the provenance's source repository does not meet the rule"),
                        "{detail}"
                    );
                    assert!(detail.contains(".sig: not examined"), "{detail}");
                }
                other => panic!("jq must be refused: {other:?}"),
            }
            let committed = std::fs::read_dir(root.join("layers/sha256"))
                .map(|dir| {
                    dir.filter_map(Result::ok)
                        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                        .count()
                })
                .unwrap_or(0);
            assert_eq!(committed, 0, "a layer was committed");
        }
    }

    /// jq's SLSA trust of `jq_provenance` with Fulcio certificate claims
    /// (ADR-033): the source repository exactly, a tag ref, the repository
    /// ID and the trigger list `triggers`, with the statement agreement.
    fn jq_certificate(triggers: &str) -> Requirement {
        let Requirement::Required(trust) = jq_provenance("https://github.com/jqlang/jq") else {
            panic!("jq's provenance rule is Required");
        };
        let claims = CertificateClaims::new(
            Some(ClaimMatch::Exact("https://github.com/jqlang/jq".to_owned())),
            Some(ClaimMatch::Prefix("refs/tags/".to_owned())),
            vec![triggers.to_owned()],
        )
        .expect("certificate claims")
        .with_repository_id("5101141")
        .expect("repository id")
        .with_statement_agreement();
        Requirement::Required(Arc::new(
            Trust::clone(&trust)
                .with_certificate_claims(claims)
                .expect("with certificate claims"),
        ))
    }

    /// The acceptance of ADR-033 on GHCR: under a `Required` rule whose
    /// trust has SLSA provenance claims, Fulcio certificate claims and the
    /// statement agreement, jq 1.8.2 pulls with every layer committed;
    /// under the trigger list `[release]` it is refused before any layer is
    /// committed, and the detail names the build trigger.
    #[test]
    #[ignore = "network: pulls jqlang/jq from ghcr.io"]
    fn certificate_claims_on_ghcr() {
        let ghcr = Registry::new(
            "ghcr.io",
            "ghcr.io",
            &["ghcr.io"],
            &[".githubusercontent.com"],
        )
        .expect("ghcr");
        for triggers in ["push", "release"] {
            let dial = recording();
            let mut config = StoreConfig::new(Box::new(dial.clone())).expect("config");
            config.registries = vec![Registry::docker_hub(), ghcr.clone()];
            config.signatures = SignaturePolicy::new(
                Requirement::Off,
                vec![rule(
                    "ghcr.io",
                    RepoScope::Exact(Repository::parse("jqlang/jq").expect("repository")),
                    jq_certificate(triggers),
                )],
            )
            .expect("policy");
            let tmp = TempDir::new("network-certificate");
            let root = tmp.path().join("store");
            let store = OciImageStore::open(&root, config).expect("open");
            if triggers == "push" {
                pull_signed(&store, &dial, "ghcr.io/jqlang/jq", JQ);
                continue;
            }
            let refused = store.pull(&ImageRef {
                name: "ghcr.io/jqlang/jq".to_owned(),
                digest: JQ.to_owned(),
                platform: platform().to_owned(),
                origin: ImageOrigin::Operator,
            });
            println!(
                "oci-acceptance certificate claims ghcr.io/jqlang/jq under [release]: {refused:?}"
            );
            match refused {
                Err(ImageError::Failed { detail }) => {
                    assert!(detail.starts_with("signature policy: "), "{detail}");
                    assert!(
                        detail.contains(
                            "the certificate's Fulcio Build Trigger (1.3.6.1.4.1.57264.1.20) does not meet the rule"
                        ),
                        "{detail}"
                    );
                }
                other => panic!("jq must be refused: {other:?}"),
            }
            let committed = std::fs::read_dir(root.join("layers/sha256"))
                .map(|dir| {
                    dir.filter_map(Result::ok)
                        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                        .count()
                })
                .unwrap_or(0);
            assert_eq!(committed, 0, "a layer was committed");
        }
    }
}
