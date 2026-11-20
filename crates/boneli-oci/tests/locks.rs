//! Owner locks, layer pins and leases (ADR-025, D1 to D3): one test per
//! edge case of the #56 plan, PR 1. Tests that need a second process
//! re-execute this binary with a variable that names their child mode.

mod support;

use std::fs::{File, TryLockError};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use boneli_app::{ImageError, ImageRef, ImageStore, RootfsRef};
use boneli_oci::OciImageStore;

use support::TempDir;
use support::images::{Layer, config, open, push};
use support::registry::{Fake, Hub};
use support::tarball::Tar;

fn image_ref(name: &str, digest: &str) -> ImageRef {
    ImageRef {
        name: name.to_owned(),
        digest: digest.to_owned(),
        platform: "linux/amd64".to_owned(),
    }
}

fn hex(digest: &str) -> String {
    digest.trim_start_matches("sha256:").to_owned()
}

/// A hub with `library/app`: three layers, the middle one gzip.
fn app_hub() -> (Hub, support::images::Pushed, Vec<Layer>) {
    let mut hub = Hub::default();
    let layers = vec![
        Layer::file("etc/base", b"base\n"),
        Layer::gzip(Tar::new().file("usr/bin/tool", 0o755, b"#!\n").finish()),
        Layer::file("etc/top", b"top\n"),
    ];
    let pushed = push(&mut hub, "library/app", &layers, "");
    (hub, pushed, layers)
}

/// The lock file of the layer `diff_id` (`sha256:<hex>`) under `root`.
fn layer_lock(root: &Path, diff_id: &str) -> PathBuf {
    root.join("locks/sha256").join(hex(diff_id))
}

/// The owner lock file of `token` under `root`.
fn owner_lock(root: &Path, token: &str) -> PathBuf {
    root.join("locks/owners").join(token)
}

/// Whether an exclusive `try_lock` through a new open file description of
/// `path` would block: someone holds a lock on the file.
fn is_held(path: &Path) -> bool {
    let file = File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    match file.try_lock() {
        Ok(()) => false,
        Err(TryLockError::WouldBlock) => true,
        Err(TryLockError::Error(e)) => panic!("{}: {e}", path.display()),
    }
}

/// A pid no process has: a child that has exited and been reaped.
fn dead_pid() -> u32 {
    let mut child = Command::new("true").spawn().expect("spawn true");
    let pid = child.id();
    child.wait().expect("wait");
    pid
}

/// Creates an owner lock file for `token`, free.
fn plant_owner_lock(root: &Path, token: &str) -> PathBuf {
    let path = owner_lock(root, token);
    std::fs::write(&path, b"").expect("owner lock");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    path
}

/// The names an owner leaves: a staging tree with a mode-0 directory and a
/// staged sidecar in `layers/sha256/`, and a staged blob in
/// `blobs/sha256/`.
fn plant_names(root: &Path, token: &str, n: u64) -> Vec<PathBuf> {
    let tree = root
        .join("layers/sha256")
        .join(support::owned_name(".tmp-", token, n));
    std::fs::create_dir_all(tree.join("a/b")).expect("tree");
    std::fs::write(tree.join("a/b/f"), b"x").expect("file");
    std::fs::set_permissions(tree.join("a"), std::fs::Permissions::from_mode(0o000))
        .expect("chmod");
    let sidecar = root.join("layers/sha256").join(format!(
        "{}.stats",
        support::owned_name(".tmp-", token, n + 1)
    ));
    std::fs::write(&sidecar, b"x").expect("sidecar");
    let blob = root
        .join("blobs/sha256")
        .join(support::owned_name(".tmp-", token, n + 2));
    std::fs::write(&blob, b"x").expect("blob");
    vec![tree, sidecar, blob]
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// A boot id that is not this host's.
fn other_boot(boot: &str) -> String {
    if boot.starts_with('0') {
        boot.replacen('0', "1", 1)
    } else {
        format!("0{}", &boot[1..])
    }
}

/// Owners in another PID namespace, another time namespace, with another
/// boot id (an earlier boot, or another host) and with a random id (an
/// owner that could not read its boot id): the `/proc` rule of ADR-009 D8
/// judges none of them. With a free owner lock file each is dead, and
/// `open` removes its names in both directories, then its lock file. An
/// owner whose lock is held, through another open file description in
/// this process, keeps everything, until the lock is released.
#[test]
fn owner_lock_decides_in_every_namespace() {
    let fake = Fake::new(|_| unreachable!("open makes no request"));
    let tmp = TempDir::new("owner-ns");
    let root = tmp.path().join("store");
    drop(open(&root, &fake));
    let boot = support::boot_hex();
    let ns = support::own_pidns();
    let timens = support::own_timens();
    let dead = dead_pid();
    let me = std::process::id();
    let my_start = support::start_of("self");
    // The UUID version digit cleared, as an owner without a boot id makes
    // its random one.
    let random = format!("{}0{}", &boot[..12], &boot[13..]);
    let dead_tokens = [
        support::owner_token_in(&boot, ns + 1, timens, dead, 7),
        support::owner_token_in(&boot, ns, timens + 1, me, my_start),
        support::owner_token_in(&other_boot(&boot), ns, timens, me, my_start),
        support::owner_token_in(&random, ns, timens, dead, 7),
    ];
    let mut removed = Vec::new();
    for (i, token) in dead_tokens.iter().enumerate() {
        removed.push(plant_owner_lock(&root, token));
        removed.extend(plant_names(&root, token, 10 * i as u64));
    }
    let held_token = support::owner_token_in(&boot, ns + 2, timens, dead, 7);
    let held_lock = plant_owner_lock(&root, &held_token);
    let held_names = plant_names(&root, &held_token, 100);
    let holder = File::open(&held_lock).expect("open the held lock");
    holder.lock_shared().expect("lock_shared");

    drop(open(&root, &fake));
    for path in &removed {
        assert!(!exists(path), "{} was kept", path.display());
    }
    for path in held_names.iter().chain([&held_lock]) {
        assert!(exists(path), "{} was removed", path.display());
    }

    drop(holder);
    drop(open(&root, &fake));
    for path in held_names.iter().chain([&held_lock]) {
        assert!(!exists(path), "{} was kept once free", path.display());
    }
}

/// A dead owner (free lock file) one of whose names cannot be removed: a
/// staging tree deeper than `PATH_MAX`, as a root reached through a
/// shorter path can leave. Its other names go, the deep one and the lock
/// file stay, and once the tree can be removed the next `open` removes it
/// and then the lock file.
#[test]
fn owner_lock_kept_while_names_remain() {
    let fake = Fake::new(|_| unreachable!("open makes no request"));
    let tmp = TempDir::new("owner-remain");
    let root = tmp.path().join("store");
    drop(open(&root, &fake));
    let token = support::owner_token(&support::boot_hex(), support::own_pidns() + 1, 42, 7);
    let lock = plant_owner_lock(&root, &token);
    let names = plant_names(&root, &token, 1);
    let deep = root
        .join("layers/sha256")
        .join(support::owned_name(".tmp-", &token, 9));
    let short = tmp.path().join("t");
    let mut bottom = short.clone();
    let mut left = 4097 - deep.as_os_str().len();
    while left > 0 {
        let len = left.saturating_sub(1).clamp(1, 200);
        bottom.push("d".repeat(len));
        left = left.saturating_sub(len + 1);
    }
    std::fs::create_dir_all(&bottom).expect("the deep tree");
    std::fs::rename(&short, &deep).expect("rename");

    drop(open(&root, &fake));
    for path in &names {
        assert!(!exists(path), "{} was kept", path.display());
    }
    assert!(
        deep.is_dir(),
        "the deep name is gone, so the test proves nothing"
    );
    assert!(exists(&lock), "the lock file went while a name remained");

    // Made removable: its first level moved out to a short path.
    let first = std::fs::read_dir(&deep)
        .expect("list")
        .next()
        .expect("a child")
        .expect("entry")
        .path();
    std::fs::rename(&first, tmp.path().join("moved")).expect("move out");
    drop(open(&root, &fake));
    assert!(!exists(&deep), "the next judge did not try again");
    assert!(
        !exists(&lock),
        "the lock file stayed once its names were gone"
    );
}

const IDLE_CHILD: &str = "BONELI_OCI_IDLE_OWNER_CHILD";

/// A process that opened the store and exited without leaving a name
/// leaves its owner lock file; the next `open` removes it. Held lock files
/// stay, this process's own included, and so does every name in
/// `locks/owners/` that is not an owner token.
#[test]
fn idle_owner_lock_removed() {
    if let Some(root) = std::env::var_os(IDLE_CHILD) {
        let fake = Fake::new(|_| unreachable!("open makes no request"));
        drop(open(Path::new(&root), &fake));
        return;
    }
    let fake = Fake::new(|_| unreachable!("open makes no request"));
    let tmp = TempDir::new("owner-idle");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let owners = root.join("locks/owners");
    let mine: Vec<String> = names_in(&owners);
    assert_eq!(mine.len(), 1, "{mine:?}");

    let out = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "idle_owner_lock_removed", "--test-threads=1"])
        .env(IDLE_CHILD, &root)
        .output()
        .expect("spawn the child");
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
    let after_child = names_in(&owners);
    assert_eq!(after_child.len(), 2, "the child left its lock file");

    let held_token = support::owner_token(&support::boot_hex(), support::own_pidns() + 1, 42, 7);
    let held = plant_owner_lock(&root, &held_token);
    let holder = File::open(&held).expect("open");
    holder.lock_shared().expect("lock_shared");
    // Not owner tokens: no token field may hold `X`, and a token has no
    // suffix.
    let unrelated = [
        "README".to_owned(),
        format!("X{}", &held_token[1..]),
        format!("{held_token}.x"),
    ];
    for name in &unrelated {
        std::fs::write(owners.join(name), b"").expect("plant");
    }

    drop(open(&root, &fake));
    let mut want: Vec<String> = mine
        .iter()
        .cloned()
        .chain([held_token.clone()])
        .chain(unrelated.iter().cloned())
        .collect();
    want.sort();
    assert_eq!(names_in(&owners), want);
    drop(store);
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// A gate in the fake registry: the first request for `blob` waits until
/// the test opens it, and the test learns when it got there.
struct Gate {
    open: Mutex<bool>,
    opened: Condvar,
}

impl Gate {
    fn new() -> Arc<Gate> {
        Arc::new(Gate {
            open: Mutex::new(false),
            opened: Condvar::new(),
        })
    }

    fn wait(&self) {
        let mut open = self.open.lock().expect("gate");
        while !*open {
            open = self.opened.wait(open).expect("gate");
        }
    }

    fn release(&self) {
        *self.open.lock().expect("gate") = true;
        self.opened.notify_all();
    }
}

/// A fake over `hub` whose first request for `blob` signals `reached` and
/// waits for `gate`. The wait stays well inside the client's 5 s I/O
/// deadline in every test that uses it.
fn gated(hub: Hub, blob: String, gate: Arc<Gate>, reached: mpsc::Sender<()>) -> Fake {
    let armed = AtomicBool::new(true);
    let reached = Mutex::new(reached);
    Fake::new(move |s| {
        if s.target.ends_with(&blob) && armed.swap(false, Ordering::SeqCst) {
            let _ = reached.lock().expect("reached").send(());
            gate.wait();
        }
        hub.handle(s)
    })
}

/// A pull pins every layer of the image before its first layer blob
/// request: while the fake holds the request for the bottom layer's blob,
/// every layer's lock file is held. Once `pull` returns, none is.
#[test]
fn pull_pins_every_layer_before_fetching() {
    let (hub, pushed, layers) = app_hub();
    let gate = Gate::new();
    let (tx, rx) = mpsc::channel();
    let fake = gated(hub, pushed.blobs[0].clone(), Arc::clone(&gate), tx);
    let tmp = TempDir::new("pins-first");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let image = image_ref("library/app", &pushed.index);
    std::thread::scope(|s| {
        let pull = s.spawn(|| store.pull(&image));
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the pull reached the first layer blob");
        let held: Vec<bool> = layers
            .iter()
            .map(|l| is_held(&layer_lock(&root, &l.diff_id)))
            .collect();
        gate.release();
        pull.join().expect("thread").expect("pull");
        assert_eq!(held, [true, true, true], "pins before the first blob");
    });
    for layer in &layers {
        assert!(
            !is_held(&layer_lock(&root, &layer.diff_id)),
            "a pin outlived pull"
        );
    }
}

/// Two stores in one process hold their locks through their own open file
/// descriptions, so each excludes an exclusive lock taken elsewhere in the
/// process, as a store in another process would. A pin lasts as long as
/// any lease holds it; both stores share this process's owner lock file,
/// held until the last of them is dropped.
#[test]
fn two_stores_one_process_exclude() {
    let (hub, pushed, layers) = app_hub();
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("two-stores");
    let root = tmp.path().join("store");
    let a = open(&root, &fake);
    let b = open(&root, &fake);
    let lease_a = a
        .pull_leased(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let lease_b = b.lease(lease_a.rootfs()).expect("lease");
    assert_eq!(lease_a.layers(), lease_b.layers());
    let locks: Vec<PathBuf> = layers
        .iter()
        .map(|l| layer_lock(&root, &l.diff_id))
        .collect();
    assert!(locks.iter().all(|p| is_held(p)));
    drop(lease_a);
    assert!(locks.iter().all(|p| is_held(p)), "b's lease still pins");
    drop(lease_b);
    assert!(locks.iter().all(|p| !is_held(p)));

    let owners = names_in(&root.join("locks/owners"));
    assert_eq!(owners.len(), 1, "one process, one owner: {owners:?}");
    let own = owner_lock(&root, &owners[0]);
    drop(a);
    assert!(is_held(&own), "b holds the owner lock");
    drop(b);
    assert!(!is_held(&own));
}

const LEASE_CHILD: &str = "BONELI_OCI_LEASE_CHILD";
const LEASE_ROOTFS: &str = "BONELI_OCI_LEASE_ROOTFS";
const LEASE_HOLDER: &str = "BONELI_OCI_LEASE_HOLDER";

/// The child of the two lease tests: opens the store, leases the rootfs,
/// says so on stdout and holds the lease until stdin closes.
fn lease_child(root: &Path) {
    let fake = Fake::new(|_| unreachable!("a lease makes no request"));
    let store = open(root, &fake);
    let rootfs = RootfsRef::new(std::env::var(LEASE_ROOTFS).expect("rootfs"));
    let lease = store.lease(&rootfs).expect("lease");
    let mut holder = None;
    if std::env::var_os(LEASE_HOLDER).is_some() {
        // The holder process's stand-in (ADR-025 D2: in the sandbox's
        // cgroup, never the workload): a process that holds one more pin
        // per layer, inherited as its stdin, stdout and stderr, and that
        // outlives this runner.
        let mut fds = lease.pin_descriptors().expect("descriptors").into_iter();
        let mut next = || Stdio::from(fds.next().expect("one descriptor per layer"));
        let child = Command::new("sleep")
            .arg("120")
            .stdin(next())
            .stdout(next())
            .stderr(next())
            .spawn()
            .expect("spawn the holder");
        println!("holder {}", child.id());
        holder = Some(child);
    }
    println!("leased {}", lease.layers().len());
    let mut rest = String::new();
    let _ = std::io::stdin().read_line(&mut rest);
    drop(lease);
    // Reached only when the runner is not killed: the holder goes too.
    if let Some(mut holder) = holder {
        let _ = holder.kill();
        let _ = holder.wait();
    }
}

/// Pulls `library/app` into a new store and starts `test`'s child holding
/// a lease on it; returns the child once it says it holds the lease.
fn leasing_child(test: &str, tmp: &TempDir) -> (std::process::Child, PathBuf, Vec<PathBuf>) {
    let (child, root, locks, _) = leasing_child_with(test, tmp, false);
    (child, root, locks)
}

/// [`leasing_child`], whose child also starts a holder process with
/// `pin_descriptors` when `holder` is set; returns the holder's pid too.
fn leasing_child_with(
    test: &str,
    tmp: &TempDir,
    holder: bool,
) -> (std::process::Child, PathBuf, Vec<PathBuf>, Option<u32>) {
    let (hub, pushed, layers) = app_hub();
    let fake = Fake::new(move |s| hub.handle(s));
    let root = tmp.path().join("store");
    let rootfs = open(&root, &fake)
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let mut child = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(LEASE_CHILD, &root)
        .env(LEASE_ROOTFS, rootfs.as_str())
        .envs(holder.then_some((LEASE_HOLDER, "1")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the child");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let mut holder_pid = None;
    loop {
        let line = lines
            .next()
            .expect("the child said it leased")
            .expect("line");
        // libtest prints `test <name> ... ` on the same line under
        // `--nocapture`.
        if let Some((_, pid)) = line.rsplit_once("holder ") {
            holder_pid = Some(pid.parse().expect("holder pid"));
        }
        if line.ends_with("leased 3") {
            break;
        }
    }
    // Keep reading in the background, so the child never blocks on a full
    // pipe.
    std::thread::spawn(move || lines.for_each(drop));
    let locks = layers
        .iter()
        .map(|l| layer_lock(&root, &l.diff_id))
        .collect();
    (child, root, locks, holder_pid)
}

/// A lease held in another process pins every layer: an exclusive
/// `try_lock` here gives `WouldBlock`. Once the child drops it and exits,
/// the locks are free.
#[test]
fn lease_in_other_process_pins_layers() {
    if let Some(root) = std::env::var_os(LEASE_CHILD) {
        lease_child(Path::new(&root));
        return;
    }
    let tmp = TempDir::new("lease-child");
    let (mut child, _root, locks) = leasing_child("lease_in_other_process_pins_layers", &tmp);
    assert!(locks.iter().all(|p| is_held(p)), "the child's lease pins");
    drop(child.stdin.take());
    assert!(child.wait().expect("wait").success());
    assert!(locks.iter().all(|p| !is_held(p)));
}

/// A holder killed with `SIGKILL` runs no destructor; the kernel releases
/// its locks with its descriptors.
#[test]
fn killed_holder_releases_its_lease() {
    if let Some(root) = std::env::var_os(LEASE_CHILD) {
        lease_child(Path::new(&root));
        return;
    }
    let tmp = TempDir::new("lease-killed");
    let (mut child, root, locks) = leasing_child("killed_holder_releases_its_lease", &tmp);
    assert!(locks.iter().all(|p| is_held(p)));
    child.kill().expect("SIGKILL");
    let _ = child.wait();
    assert!(locks.iter().all(|p| !is_held(p)));
    // The killed child's owner lock is free too, and the next open removes
    // it.
    let fake = Fake::new(|_| unreachable!("open makes no request"));
    let store = open(&root, &fake);
    assert_eq!(names_in(&root.join("locks/owners")).len(), 1);
    drop(store);
}

/// The review of #92: a sandbox outlives a runner that is killed, so the
/// pins of its mounted layers must not die with the runner. The child (the
/// runner) leases the image and hands `pin_descriptors` to a holder process
/// (the stand-in for #8's holder), then is killed with `SIGKILL`: every layer
/// stays pinned while the holder lives, and is free once it is gone.
#[test]
fn pin_descriptors_outlive_the_runner() {
    if let Some(root) = std::env::var_os(LEASE_CHILD) {
        lease_child(Path::new(&root));
        return;
    }
    let tmp = TempDir::new("lease-holder");
    let (mut runner, _root, locks, holder) =
        leasing_child_with("pin_descriptors_outlive_the_runner", &tmp, true);
    let holder = holder.expect("the child started a holder");
    let kill_holder = || {
        let _ = Command::new("kill")
            .args(["-KILL", &holder.to_string()])
            .status();
    };
    runner.kill().expect("SIGKILL the runner");
    let _ = runner.wait();
    let held: Vec<bool> = locks.iter().map(|p| is_held(p)).collect();
    kill_holder();
    assert_eq!(held, [true, true, true], "pins died with the runner");
    // The holder was reparented away from this process; its descriptors
    // close when it exits.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while locks.iter().any(|p| is_held(p)) {
        assert!(
            std::time::Instant::now() < deadline,
            "pins outlived the holder"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `pin_descriptors` are pins of their own: they keep every layer pinned
/// after the lease is dropped, and a holder's release (`LOCK_UN`) drops
/// only its own pin, never the lease's.
#[test]
fn pin_descriptors_hold_their_own_pins() {
    let (hub, pushed, layers) = app_hub();
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("pin-descriptors");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let lease = store
        .pull_leased(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let locks: Vec<PathBuf> = layers
        .iter()
        .map(|l| layer_lock(&root, &l.diff_id))
        .collect();
    let copies: Vec<File> = lease
        .pin_descriptors()
        .expect("descriptors")
        .into_iter()
        .map(File::from)
        .collect();
    assert_eq!(copies.len(), 3);
    for copy in &copies {
        copy.unlock().expect("a holder's LOCK_UN");
    }
    assert!(
        locks.iter().all(|p| is_held(p)),
        "the lease's pins went too"
    );
    for copy in &copies {
        copy.lock_shared().expect("lock again");
    }
    drop(lease);
    assert!(
        locks.iter().all(|p| is_held(p)),
        "the copies pin on their own"
    );
    drop(copies);
    assert!(locks.iter().all(|p| !is_held(p)));
}

/// A lease of a rootfs one of whose layers is not in the store is
/// `Failed`, names the layer and tells the caller to pull again; it keeps
/// no pin. Pulled again, the rootfs leases.
#[test]
fn lease_of_missing_layer_fails() {
    let (hub, pushed, layers) = app_hub();
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("lease-missing");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let rootfs = store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let middle = root.join("layers/sha256").join(hex(&layers[1].diff_id));
    support::make_writable(&middle);
    std::fs::remove_dir_all(&middle).expect("remove the layer");
    std::fs::remove_file(middle.with_extension("stats")).expect("remove its sidecar");
    match store.lease(&rootfs) {
        Err(ImageError::Failed { detail }) => {
            assert!(detail.contains(&hex(&layers[1].diff_id)), "{detail}");
            assert!(detail.contains("pull the image again"), "{detail}");
        }
        other => panic!("a lease without its layer: {other:?}"),
    }
    for layer in &layers {
        assert!(
            !is_held(&layer_lock(&root, &layer.diff_id)),
            "a failed lease kept a pin"
        );
    }
    // Pulled again, it leases.
    let lease = store
        .pull_leased(&image_ref("library/app", &pushed.index))
        .expect("pull");
    assert_eq!(lease.layers().len(), 3);
}

const NOFILE_CHILD: &str = "BONELI_OCI_LEASE_NOFILE_CHILD";
const NOFILE_ROOTFS: &str = "BONELI_OCI_LEASE_NOFILE_ROOTFS";
/// Below the 64 descriptors a lease of the 64-layer image needs.
const NOFILE: u32 = 48;
const MANY_LAYERS: usize = 64;

fn open_descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd").expect("fds").count()
}

/// A lease of a 64-layer image under `ulimit -n 48` fails as `Failed`,
/// does not panic and leaves no descriptor and no pin behind. The child
/// (this binary again) runs under the low limit, so nothing else does.
#[test]
fn lease_beyond_fd_limit_fails_cleanly() {
    if let Some(root) = std::env::var_os(NOFILE_CHILD) {
        let root = PathBuf::from(root);
        let fake = Fake::new(|_| unreachable!("a lease makes no request"));
        let store = open(&root, &fake);
        let rootfs = RootfsRef::new(std::env::var(NOFILE_ROOTFS).expect("rootfs"));
        let before = open_descriptors();
        match store.lease(&rootfs) {
            Err(ImageError::Failed { detail }) => assert!(!detail.trim().is_empty()),
            other => panic!("a lease beyond the descriptor limit: {other:?}"),
        }
        assert_eq!(open_descriptors(), before, "a descriptor leaked");
        for entry in std::fs::read_dir(root.join("locks/sha256")).expect("locks") {
            let path = entry.expect("entry").path();
            assert!(!is_held(&path), "{} stays pinned", path.display());
        }
        return;
    }
    let mut hub = Hub::default();
    let layers: Vec<Layer> = (0..MANY_LAYERS)
        .map(|i| Layer::file(&format!("f{i}"), format!("layer {i}").as_bytes()))
        .collect();
    let pushed = push(&mut hub, "library/many", &layers, "");
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("lease-nofile");
    let root = tmp.path().join("store");
    let rootfs = open(&root, &fake)
        .pull(&image_ref("library/many", &pushed.index))
        .expect("pull");
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ulimit -n {NOFILE} && exec \"$0\" --exact lease_beyond_fd_limit_fails_cleanly \
             --test-threads=1 --nocapture"
        ))
        .arg(std::env::current_exe().expect("test binary"))
        .env(NOFILE_CHILD, &root)
        .env(NOFILE_ROOTFS, rootfs.as_str())
        .output()
        .expect("spawn the child");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "child failed:\n{text}");
    assert!(text.contains("1 passed"), "the child ran the check: {text}");
}

/// A lease does not take the store's pull mutex: while another thread's
/// pull waits in the fake registry, a lease of an image already pulled
/// returns at once.
#[test]
fn lease_does_not_wait_for_a_pull() {
    let (mut hub, pushed, _) = app_hub();
    let other = push(
        &mut hub,
        "library/other",
        &[Layer::file("other", b"other\n")],
        "",
    );
    let gate = Gate::new();
    let (tx, rx) = mpsc::channel();
    let fake = gated(hub, other.blobs[0].clone(), Arc::clone(&gate), tx);
    let tmp = TempDir::new("lease-no-wait");
    let store = open(&tmp.path().join("store"), &fake);
    let rootfs = store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    std::thread::scope(|s| {
        let pull = s.spawn(|| store.pull(&image_ref("library/other", &other.index)));
        rx.recv_timeout(Duration::from_secs(10))
            .expect("the other pull reached its blob");
        let (done_tx, done_rx) = mpsc::channel();
        let store = &store;
        let rootfs = &rootfs;
        s.spawn(move || {
            let _ = done_tx.send(store.lease(rootfs).map(|l| l.layers().len()));
        });
        let leased = done_rx.recv_timeout(Duration::from_secs(3));
        gate.release();
        assert_eq!(leased.expect("the lease waited for the pull"), Ok(3));
        pull.join().expect("thread").expect("the other pull");
    });
}

/// `pull_leased` and `lease` give the same layers as the reopened store,
/// and the lease's config is the image's.
#[test]
fn pull_leased_matches_lease() {
    let (hub, pushed, _) = app_hub();
    let fake = Fake::new(move |s| hub.handle(s));
    let tmp = TempDir::new("leased-matches");
    let root = tmp.path().join("store");
    let store = OciImageStore::open(&root, config(&fake)).expect("open");
    let pulled = store
        .pull_leased(&image_ref("library/app", &pushed.index))
        .expect("pull");
    drop(store);
    let store = open(&root, &fake);
    let leased = store.lease(pulled.rootfs()).expect("lease");
    assert_eq!(leased.rootfs(), pulled.rootfs());
    assert_eq!(leased.layers(), pulled.layers());
    assert_eq!(leased.config(), pulled.config());
    assert_eq!(
        store.config(pulled.rootfs()).expect("config"),
        *pulled.config()
    );
}
