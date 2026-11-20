//! The store (ADR-009, D8) against the fake registry: one test per store
//! edge case of the #7 plan, part 3.

mod support;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use boneli_app::{ImageError, ImageRef, ImageStore, RootfsRef};
use boneli_oci::{Error, Limits, OciImageStore};

use support::TempDir;
use support::images::{Layer, blob_requests, config, manifest_requests, open, push};
use support::registry::{Fake, Hub, Reply};
use support::tarball::Tar;

fn image_ref(name: &str, digest: &str) -> ImageRef {
    ImageRef {
        name: name.to_owned(),
        digest: digest.to_owned(),
        platform: "linux/amd64".to_owned(),
    }
}

fn hub_fake(hub: Hub) -> Fake {
    Fake::new(move |s| hub.handle(s))
}

/// A hub with `library/app`: three layers, the middle one gzip.
fn app_hub() -> (Hub, support::images::Pushed) {
    let mut hub = Hub::default();
    let pushed = push(
        &mut hub,
        "library/app",
        &[
            Layer::file("etc/base", b"base\n"),
            Layer::gzip(Tar::new().file("usr/bin/tool", 0o755, b"#!\n").finish()),
            Layer::file("etc/top", b"top\n"),
        ],
        r#"{"User":"999","Env":["PATH=/usr/bin:/bin","LANG=C"],"Entrypoint":null,"Cmd":["tool","--version"],"WorkingDir":"/srv"}"#,
    );
    (hub, pushed)
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn assert_root_refused(root: &Path, fake: &Fake, why: &str) {
    match OciImageStore::open(root, config(fake)) {
        Err(Error::Root { .. }) => {}
        other => panic!("{why}: {root:?} gave {other:?}"),
    }
}

/// A relative root, `~/x` (relative, never expanded), `file:///x`, a root
/// with `,`, `:` or `\`, or one that is not UTF-8 is refused. A symlinked
/// root is resolved, then checked: a link to a name with `:` is refused,
/// a link to a clean directory is accepted and the store reports the
/// resolved root.
#[test]
fn root_path_forms() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("root-forms");
    for relative in ["store", "~/store", "file:///store", "./store"] {
        assert_root_refused(Path::new(relative), &fake, "relative");
    }
    for bad in ["a,b", "a:b", "a\\b"] {
        assert_root_refused(&tmp.path().join(bad), &fake, "overlay separator");
        assert!(!tmp.path().join(bad).exists(), "{bad} was created");
    }
    let not_utf8 = {
        use std::os::unix::ffi::OsStrExt;
        tmp.path().join(std::ffi::OsStr::from_bytes(b"caf\xe9"))
    };
    assert_root_refused(&not_utf8, &fake, "not UTF-8");

    let colon = tmp.path().join("real:dir");
    std::fs::create_dir(&colon).expect("dir");
    std::fs::set_permissions(&colon, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let link = tmp.path().join("link-to-colon");
    std::os::unix::fs::symlink(&colon, &link).expect("symlink");
    assert_root_refused(&link, &fake, "a link resolving to ':'");

    let clean = tmp.path().join("clean");
    std::fs::create_dir(&clean).expect("dir");
    std::fs::set_permissions(&clean, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let link = tmp.path().join("link-to-clean");
    std::os::unix::fs::symlink(&clean, &link).expect("symlink");
    let store = OciImageStore::open(&link, config(&fake)).expect("a clean link");
    assert_eq!(store.root(), clean.canonicalize().expect("resolve"));
}

/// A missing root is created `0o700`; an existing one with a group or
/// other bit is refused, `0o700` is accepted.
#[test]
fn root_mode_rules() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("root-mode");
    let fresh = tmp.path().join("fresh");
    open(&fresh, &fake);
    let mode = std::fs::metadata(&fresh)
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o700);
    for refused in [0o750, 0o701, 0o710, 0o707] {
        let root = tmp.path().join(format!("m{refused:o}"));
        std::fs::create_dir(&root).expect("dir");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(refused)).expect("chmod");
        assert_root_refused(&root, &fake, "group or other bits");
    }
    let file = tmp.path().join("file");
    std::fs::write(&file, b"").expect("file");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    assert_root_refused(&file, &fake, "not a directory");
    let ok = tmp.path().join("ok");
    std::fs::create_dir(&ok).expect("dir");
    std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    open(&ok, &fake);
}

/// The ancestors of the root follow sshd's `StrictModes`: a parent or
/// grandparent writable by its group or by others, and not sticky, is
/// refused, whether the root exists or `open` would create it, and nothing
/// is created under it; a sticky `1777` parent (like `/tmp`) is accepted.
/// The reviewer's swap (rename the root away after `open`, plant a layer)
/// needs such a parent, so it cannot start.
#[test]
fn root_ancestor_rules() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("root-ancestors");
    let chmod = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod")
    };
    for (i, mode) in [0o777, 0o775, 0o757, 0o770, 0o707].into_iter().enumerate() {
        let shared = tmp.path().join(format!("shared{i}"));
        std::fs::create_dir(&shared).expect("dir");
        chmod(&shared, mode);
        // Missing: refused before it is created.
        let missing = shared.join("store");
        assert_root_refused(&missing, &fake, "a writable parent, missing root");
        assert!(!missing.exists(), "{mode:o}: the root was created");
        // Existing and private: refused, nothing written into it.
        std::fs::create_dir(&missing).expect("dir");
        chmod(&missing, 0o700);
        assert_root_refused(&missing, &fake, "a writable parent");
        assert!(
            names_in(&missing).is_empty(),
            "{mode:o}: wrote into the root"
        );
        // A writable grandparent.
        let deep = shared.join("mid");
        std::fs::create_dir(&deep).expect("dir");
        chmod(&deep, 0o755);
        assert_root_refused(&deep.join("store"), &fake, "a writable grandparent");
        assert!(
            !deep.join("store").exists(),
            "{mode:o}: the deep root was created"
        );
    }
    match OciImageStore::open(&tmp.path().join("shared0").join("store"), config(&fake)) {
        Err(Error::Root { path, reason }) => {
            assert_eq!(
                path,
                tmp.path().join("shared0").canonicalize().expect("resolve")
            );
            assert!(reason.contains("ancestor"), "{reason}");
        }
        other => panic!("a 0o777 parent gave {other:?}"),
    }
    for (i, mode) in [0o1777, 0o1775, 0o755, 0o700].into_iter().enumerate() {
        let parent = tmp.path().join(format!("ok{i}"));
        std::fs::create_dir(&parent).expect("dir");
        chmod(&parent, mode);
        open(&parent.join("store"), &fake);
    }
}

/// A root with a `.` or `..` component is refused on its text, before
/// `open` checks or creates anything, whether the directory it names would
/// pass or not. Without the rule, `<d>/missing/../gw/store` checks `<d>`,
/// the existing ancestor of the text, and creating it makes `<d>/missing`
/// and `<d>/gw/store` under a group-writable `gw` before the check of the
/// resolved root refuses it (found in `boneli-store-fs`'s copy of these
/// rules, ADR-012 D1).
#[test]
fn root_dot_components_refused() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("root-dots");
    let chmod = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod")
    };
    let gw = tmp.path().join("gw");
    std::fs::create_dir(&gw).expect("dir");
    chmod(&gw, 0o777);
    let ok = tmp.path().join("ok");
    std::fs::create_dir(&ok).expect("dir");
    chmod(&ok, 0o700);
    for dotted in [
        "missing/../gw/store",
        "missing/./../gw/store",
        "ok/../ok/store",
        "ok/./store",
        "ok/store/.",
        "ok/store/..",
        "ok/store/../store",
        "./ok/store",
    ] {
        let root = tmp.path().join(dotted);
        match OciImageStore::open(&root, config(&fake)) {
            Err(Error::Root { path, reason }) => {
                assert_eq!(path, root, "{dotted}");
                assert!(reason.contains("`..`"), "{dotted}: {reason}");
            }
            other => panic!("{dotted}: {root:?} gave {other:?}"),
        }
        assert_eq!(names_in(tmp.path()), vec!["gw", "ok"], "{dotted}");
        assert!(names_in(&gw).is_empty(), "{dotted}: created under gw");
        assert!(names_in(&ok).is_empty(), "{dotted}: created under ok");
    }
    // The same root without the dots opens.
    open(&ok.join("store"), &fake);
}

/// A root owned by someone else is refused for its owner, before anything
/// is written: `/usr`, which is root's on every Linux host and CI runner.
/// A run as root would own it, so the check does not apply there.
#[test]
fn root_owned_by_another_user_refused() {
    let usr = Path::new("/usr");
    let me = std::fs::metadata("/proc/self").expect("self").uid();
    let owner = std::fs::metadata(usr).expect("/usr").uid();
    if me == 0 || owner == me {
        println!("skipped: this process owns /usr");
        return;
    }
    let before = names_in(usr);
    match OciImageStore::open(usr, config(&hub_fake(Hub::default()))) {
        Err(Error::Root { path, reason }) => {
            assert_eq!(path, usr.canonicalize().expect("resolve"));
            assert_eq!(reason, "must be owned by the caller");
        }
        other => panic!("/usr gave {other:?}"),
    }
    assert_eq!(names_in(usr), before, "open wrote into /usr");
}

/// The root rules live in `boneli-private-dir` (ADR-021), and its errors
/// map back to this crate's: a rule to `Error::Root` with the same text, a
/// filesystem failure (here a NUL byte in the root) to `Error::Cache`.
#[test]
fn root_errors_keep_their_variants_and_text() {
    let fake = hub_fake(Hub::default());
    match OciImageStore::open(Path::new("store"), config(&fake)) {
        Err(e @ Error::Root { .. }) => {
            assert_eq!(e.to_string(), "store root store: must be an absolute path")
        }
        other => panic!("a relative root gave {other:?}"),
    }
    let tmp = TempDir::new("root-errors");
    let nul = {
        use std::os::unix::ffi::OsStrExt;
        tmp.path().join(std::ffi::OsStr::from_bytes(b"a\0b"))
    };
    match OciImageStore::open(&nul, config(&fake)) {
        Err(Error::Cache { source, .. }) => {
            assert_eq!(source.kind(), std::io::ErrorKind::InvalidInput, "{source}")
        }
        other => panic!("a NUL byte gave {other:?}"),
    }
    assert!(names_in(tmp.path()).is_empty(), "created something");
}

/// Fullwidth `：`, `，` and `＼` are not the bytes overlay splits on: every
/// byte of a multibyte UTF-8 sequence is at least 0x80, so none is 0x2C,
/// 0x3A or 0x5C, and such a root opens.
#[test]
fn root_overlay_lookalikes_accepted() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("root-lookalikes");
    for name in ["a\u{FF1A}b", "a\u{FF0C}b", "a\u{FF3C}b"] {
        let root = tmp.path().join(name);
        let store = OciImageStore::open(&root, config(&fake)).expect(name);
        assert_eq!(store.root(), root);
    }
}

/// A root whose ancestor link points to a name the overlay rule refuses
/// (`<d>/link -> <d>/real:dir`) is refused at the path it would be created
/// at, before it is created: `real:dir` stays empty (ADR-021, D3).
#[test]
fn root_refused_after_resolution_creates_nothing() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("root-after-resolution");
    let colon = tmp.path().join("real:dir");
    std::fs::create_dir(&colon).expect("dir");
    std::fs::set_permissions(&colon, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&colon, &link).expect("symlink");
    match OciImageStore::open(&link.join("store"), config(&fake)) {
        Err(Error::Root { path, reason }) => {
            assert_eq!(path, colon.join("store"));
            assert_eq!(reason, "must not contain ',', ':' or '\\'");
        }
        other => panic!("a link to real:dir gave {other:?}"),
    }
    assert!(names_in(&colon).is_empty(), "created under real:dir");
}

/// A leftover of a dead owner that cannot be removed does not make the
/// store unopenable: here a staging tree deeper than `PATH_MAX`, as a root
/// reached through a shorter path (a bind mount) can leave, whose
/// path-based removal fails with `ENAMETOOLONG`. `open` skips it, removes
/// the other dead leftovers, and the store pulls; the leftover is a dot
/// name, never read as a layer.
#[test]
fn unremovable_leftover_skipped() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("unremovable");
    let root = tmp.path().join("store");
    drop(open(&root, &fake));
    let layers = root.join("layers/sha256");
    let blobs = root.join("blobs/sha256");
    let boot = support::boot_hex();
    let ns = support::own_pidns();
    let dead = {
        let mut child = Command::new("true").spawn().expect("spawn true");
        let pid = child.id();
        child.wait().expect("wait");
        pid
    };
    let deep = layers.join(owned(".tmp-", &boot, ns, dead, 7, 1));
    // Built where it fits `PATH_MAX`, then renamed under the longer
    // staging name, where its deepest path no longer does.
    let short = tmp.path().join("t");
    let mut bottom = short.clone();
    let mut left = 4097 - deep.as_os_str().len();
    while left > 0 {
        let len = left.saturating_sub(1).clamp(1, 200);
        bottom.push("d".repeat(len));
        left = left.saturating_sub(len + 1);
    }
    assert!(bottom.as_os_str().len() < 4096, "{}", bottom.display());
    std::fs::create_dir_all(&bottom).expect("the deep tree");
    std::fs::rename(&short, &deep).expect("rename");
    let removable = [
        layers.join(owned(".tmp-", &boot, ns, dead, 7, 2)),
        blobs.join(owned(".tmp-", &boot, ns, dead, 7, 3)),
    ];
    for path in &removable {
        std::fs::create_dir_all(path.join("a")).expect("leftover");
    }

    let store = OciImageStore::open(&root, config(&fake)).expect("an unremovable leftover");
    for path in &removable {
        assert!(!path.exists(), "{} was kept", path.display());
    }
    assert!(
        deep.is_dir(),
        "the deep leftover is gone, so the test proves nothing"
    );
    let rootfs = store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    assert_eq!(store.lease(&rootfs).expect("lease").layers().len(), 3);
    drop(store);
    drop(open(&root, &fake));
}

/// The same image pulled again after the store is reopened: the same
/// `RootfsRef`, and not one request.
#[test]
fn pull_idempotent_across_reopen() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("reopen");
    let root = tmp.path().join("store");
    let image = image_ref("library/app", &pushed.index);
    let first = open(&root, &fake).pull(&image).expect("first pull");
    assert_eq!(first.as_str(), pushed.manifest);
    let requests = fake.seen().len();
    let again = open(&root, &fake).pull(&image).expect("second pull");
    assert_eq!(again, first);
    assert_eq!(fake.seen().len(), requests, "the second pull made requests");
}

/// A pull that fails at the 5th of 8 layers, then a second pull: only the
/// blobs of the layers not yet committed are requested.
#[test]
fn resume_fetches_only_missing() {
    let mut hub = Hub::default();
    let layers: Vec<Layer> = (0..8)
        .map(|i| Layer::file(&format!("f{i}"), format!("layer {i}").as_bytes()))
        .collect();
    let pushed = push(&mut hub, "library/eight", &layers, "");
    let fifth = pushed.blobs[4].clone();
    let fail = Arc::new(AtomicBool::new(true));
    let fake = {
        let fail = Arc::clone(&fail);
        Fake::new(move |s| {
            if s.target.ends_with(&fifth) && fail.load(Ordering::SeqCst) {
                Reply::status(503)
            } else {
                hub.handle(s)
            }
        })
    };
    let tmp = TempDir::new("resume");
    let store = open(&tmp.path().join("store"), &fake);
    let image = image_ref("library/eight", &pushed.index);
    match store.pull(&image) {
        Err(ImageError::Failed { detail }) => assert!(detail.contains("503"), "{detail}"),
        other => panic!("the 5th layer must fail the pull: {other:?}"),
    }
    let before = fake.seen().len();
    fail.store(false, Ordering::SeqCst);
    store.pull(&image).expect("the second pull");
    let seen = fake.seen();
    let second = seen.get(before..).expect("requests of the second pull");
    assert_eq!(blob_requests(second), pushed.blobs[4..].to_vec());
    assert!(manifest_requests(second).is_empty(), "{second:?}");
}

/// Two stores on one root pull the same image from two threads: both
/// succeed with the same `RootfsRef`, the layer directories are intact,
/// and no temporary name is left behind.
#[test]
fn concurrent_pulls_two_stores() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("two-stores");
    let root = tmp.path().join("store");
    let image = image_ref("library/app", &pushed.index);
    for round in 0..8 {
        let root = root.join(format!("r{round}"));
        std::fs::create_dir_all(root.parent().expect("parent")).expect("dirs");
        let a = open(&root, &fake);
        let b = open(&root, &fake);
        let (ra, rb) = std::thread::scope(|s| {
            let ta = s.spawn(|| a.pull(&image));
            let tb = s.spawn(|| b.pull(&image));
            (ta.join().expect("a"), tb.join().expect("b"))
        });
        let ra = ra.expect("store a");
        assert_eq!(Ok(ra.clone()), rb);
        let layers = a.lease(&ra).expect("lease").layers().to_vec();
        assert_eq!(b.lease(&ra).expect("lease").layers().to_vec(), layers);
        for (layer, want) in layers.iter().zip(["etc/base", "usr/bin/tool", "etc/top"]) {
            assert!(
                layer.join(want).is_file(),
                "{} lacks {want}",
                layer.display()
            );
        }
        for dir in ["layers/sha256", "blobs/sha256"] {
            let dots: Vec<String> = names_in(&a.root().join(dir))
                .into_iter()
                .filter(|n| n.starts_with('.'))
                .collect();
            assert!(dots.is_empty(), "round {round}: {dir} keeps {dots:?}");
        }
    }
}

/// The name format of ADR-009 D8,
/// `<prefix><boot>.<pidns>.<timens>.<pid>.<start>.<n>`, in this process's
/// time namespace.
fn owned(prefix: &str, boot: &str, pidns: u64, pid: u32, start: u64, n: u64) -> String {
    support::owned_name(prefix, &support::owner_token(boot, pidns, pid, start), n)
}

/// At `open`, a temporary name whose owner is gone (no such pid, or the pid
/// reused with another start time) is removed, a tree as well as a file,
/// in `layers/sha256/` and `blobs/sha256/`. A live owner's names stay, and
/// so do the names of an owner in another PID namespace, whose processes
/// this one cannot see, the names of an owner with another boot id (another
/// host sharing the root, or an earlier boot), the names of an owner in
/// another time namespace, whose start times read differently here, and
/// dot names that carry no owner.
#[test]
fn stale_tmp_rules() {
    let fake = hub_fake(Hub::default());
    let tmp = TempDir::new("stale");
    let root = tmp.path().join("store");
    drop(open(&root, &fake));
    let layers = root.join("layers/sha256");
    let blobs = root.join("blobs/sha256");

    let boot = support::boot_hex();
    let other_boot = if boot.starts_with('0') {
        boot.replacen('0', "1", 1)
    } else {
        format!("0{}", &boot[1..])
    };
    let ns = support::own_pidns();
    let timens = support::own_timens();
    let me = std::process::id();
    let my_start = support::start_of("self");
    let dead = {
        let mut child = Command::new("true").spawn().expect("spawn true");
        let pid = child.id();
        child.wait().expect("wait");
        pid
    };
    let mut sleeper = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn sleep");
    let live = sleeper.id();
    let live_start = support::start_of(&live.to_string());

    let removed = [
        (
            layers.join(owned(".tmp-", &boot, ns, dead, my_start, 1)),
            true,
        ),
        (
            layers.join(owned(".tmp-", &boot, ns, me, my_start - 1, 2)),
            true,
        ),
        (
            layers.join(format!("{}.stats", owned(".tmp-", &boot, ns, dead, 7, 3))),
            false,
        ),
        (
            layers.join(owned(".probe-case-", &boot, ns, dead, 7, 4)),
            false,
        ),
        (
            layers.join(owned(".probe-\u{e9}-", &boot, ns, dead, 7, 5)),
            false,
        ),
        (blobs.join(owned(".tmp-", &boot, ns, dead, 7, 6)), false),
    ];
    let kept = [
        layers.join(owned(".tmp-", &boot, ns, me, my_start, 1)),
        layers.join(owned(".tmp-", &boot, ns, live, live_start, 2)),
        layers.join(owned(".tmp-", &boot, ns + 1, dead, 7, 3)),
        blobs.join(owned(".tmp-", &boot, ns + 1, dead, 7, 4)),
        layers.join(owned(".tmp-", &other_boot, ns, dead, 7, 5)),
        blobs.join(owned(".tmp-", &other_boot, ns, dead, 7, 6)),
        layers.join(owned(".tmp-", &other_boot, ns, me, my_start - 1, 7)),
        layers.join(support::owned_name(
            ".tmp-",
            &support::owner_token_in(&boot, ns, timens + 1, dead, 7),
            9,
        )),
        blobs.join(support::owned_name(
            ".tmp-",
            &support::owner_token_in(&boot, ns, timens + 1, me, my_start - 1),
            10,
        )),
        // The format before the time namespace: no owner, so it stays.
        layers.join(format!(
            ".tmp-{boot}.{ns:020}.{dead:010}.{:020}.{:020}",
            7, 11
        )),
        // The format before the boot id: no owner, so it stays.
        layers.join(format!(".tmp-{ns:020}.{dead:010}.{:020}.{:020}", 7, 8)),
        layers.join(".tmp-1234.5678.0"),
        layers.join(".unrelated"),
    ];
    for (path, tree) in &removed {
        if *tree {
            std::fs::create_dir_all(path.join("a/b")).expect("tree");
            std::fs::write(path.join("a/b/f"), b"x").expect("file");
            std::fs::set_permissions(path.join("a"), std::fs::Permissions::from_mode(0o000))
                .expect("chmod");
        } else {
            std::fs::write(path, b"x").expect("file");
        }
    }
    for path in &kept {
        std::fs::create_dir(path).expect("kept");
    }

    drop(open(&root, &fake));
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    for (path, _) in &removed {
        assert!(
            std::fs::symlink_metadata(path).is_err(),
            "{} was kept",
            path.display()
        );
    }
    for path in &kept {
        assert!(path.is_dir(), "{} was removed", path.display());
    }
}

/// A manifest that lists one `diff_id` twice: a lease, from `pull_leased`
/// or from `lease`, lists it once, at its topmost position, and holds its
/// lock file once (one descriptor per distinct layer, ADR-025 D2).
#[test]
fn duplicate_diff_id_keeps_topmost() {
    let mut hub = Hub::default();
    let a = Layer::file("a", b"a");
    let b = Layer::file("b", b"b");
    let pushed = push(
        &mut hub,
        "library/dup",
        &[a.clone(), b.clone(), a.clone()],
        "",
    );
    let fake = hub_fake(hub);
    let tmp = TempDir::new("dup");
    let store = open(&tmp.path().join("store"), &fake);
    let pulled = store
        .pull_leased(&image_ref("library/dup", &pushed.index))
        .expect("pull");
    let lease = store.lease(pulled.rootfs()).expect("lease");
    assert_eq!(lease.layers(), pulled.layers());
    let layers = lease.layers().to_vec();
    let names: Vec<String> = layers
        .iter()
        .map(|p| p.file_name().expect("name").to_string_lossy().into_owned())
        .collect();
    let hex = |d: &str| d.trim_start_matches("sha256:").to_owned();
    assert_eq!(names, vec![hex(&b.diff_id), hex(&a.diff_id)]);
    let locks: Vec<String> = std::fs::read_dir(store.root().join("locks/sha256"))
        .expect("locks")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(locks.len(), 2, "{locks:?}");
    let fds: Vec<PathBuf> = std::fs::read_dir("/proc/self/fd")
        .expect("fds")
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter(|p| p.starts_with(store.root().join("locks/sha256")))
        .collect();
    // One descriptor per distinct layer for each of the two leases.
    assert_eq!(fds.len(), 4, "{fds:?}");
}

/// `pull`, then `lease` and `config`; the store reopened, then `lease`
/// and `config` again: equal. The config carries the runtime fields. An
/// unknown or malformed `RootfsRef` is `Failed`.
#[test]
fn rootfs_ref_round_trip() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("round-trip");
    let root = tmp.path().join("store");
    let store = open(&root, &fake);
    let rootfs = store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let layers = store.lease(&rootfs).expect("lease").layers().to_vec();
    let config = store.config(&rootfs).expect("config");
    assert_eq!(layers.len(), 3);
    assert_eq!(config.user.as_deref(), Some("999"));
    assert_eq!(config.env, ["PATH=/usr/bin:/bin", "LANG=C"]);
    assert!(config.entrypoint.is_empty());
    assert_eq!(config.cmd, ["tool", "--version"]);
    assert_eq!(config.working_dir.as_deref(), Some("/srv"));
    drop(store);
    let store = open(&root, &fake);
    let reopened = RootfsRef::new(rootfs.as_str().to_owned());
    assert_eq!(
        store.lease(&reopened).expect("lease").layers().to_vec(),
        layers
    );
    assert_eq!(store.config(&reopened).expect("config"), config);
}

#[test]
fn unknown_rootfs_refused() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("unknown-rootfs");
    let store = open(&tmp.path().join("store"), &fake);
    store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let zeros = format!("sha256:{}", "0".repeat(64));
    for bad in [
        zeros.as_str(),
        "rootfs-1",
        "sha256:XYZ",
        "",
        // The index is in the store, but it is not a manifest.
        pushed.index.as_str(),
        // So is the config, which is not a manifest either.
        pushed.config.as_str(),
    ] {
        let rootfs = RootfsRef::new(bad.to_owned());
        for got in [
            store.lease(&rootfs).map(|_| ()),
            store.config(&rootfs).map(|_| ()),
        ] {
            match got {
                Err(ImageError::Failed { detail }) => assert!(!detail.trim().is_empty()),
                other => panic!("{bad:?} gave {other:?}"),
            }
        }
    }
}

/// After a pull the compressed layer blobs are gone and the index,
/// manifest and config are kept, each with its `.type`.
#[test]
fn blob_retention() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("retention");
    let store = open(&tmp.path().join("store"), &fake);
    store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let hex = |d: &str| d.trim_start_matches("sha256:").to_owned();
    let mut want: Vec<String> = [&pushed.index, &pushed.manifest, &pushed.config]
        .iter()
        .flat_map(|d| [hex(d), format!("{}.type", hex(d))])
        .collect();
    want.sort();
    assert_eq!(names_in(&store.root().join("blobs/sha256")), want);
}

/// A cached document that no longer hashes to its digest is fetched again;
/// the pull still succeeds and gives the same `RootfsRef`.
#[test]
fn corrupt_cached_json_refetched() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("corrupt");
    let store = open(&tmp.path().join("store"), &fake);
    let image = image_ref("library/app", &pushed.index);
    let first = store.pull(&image).expect("pull");
    let blobs = store.root().join("blobs/sha256");
    for digest in [&pushed.index, &pushed.manifest, &pushed.config] {
        let path = blobs.join(digest.trim_start_matches("sha256:"));
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[0] ^= 0x20;
        std::fs::write(&path, &bytes).expect("corrupt");
    }
    let before = fake.seen().len();
    assert_eq!(store.pull(&image).expect("second pull"), first);
    let seen = fake.seen();
    let second = seen.get(before..).expect("requests");
    assert_eq!(
        manifest_requests(second),
        vec![pushed.index.clone(), pushed.manifest.clone()]
    );
    assert_eq!(blob_requests(second), vec![pushed.config.clone()]);
}

/// The image caps count layers already in the cache (D7): an image whose
/// second layer is cached and whose total is over the cap is refused, warm
/// as well as cold.
#[test]
fn image_caps_count_cached_layers() {
    let mut hub = Hub::default();
    let shared = Layer::file("shared", &[b's'; 3000]);
    let small = push(&mut hub, "library/small", std::slice::from_ref(&shared), "");
    let big = push(
        &mut hub,
        "library/big",
        &[Layer::file("own", &[b'o'; 3000]), shared],
        "",
    );
    let fake = hub_fake(hub);
    let tmp = TempDir::new("caps");
    let capped = |root: &Path| {
        let mut config = config(&fake);
        // Each layer is 4,608 B of tar: a 512 B header, 3,000 B padded to
        // 3,072 and two 512 B zero blocks. 6,000 admits one, not two.
        config.limits = Limits::new(1 << 20, 6_000, 1 << 20, 1 << 20, 128).expect("limits");
        OciImageStore::open(root, config).expect("open")
    };
    let warm = capped(&tmp.path().join("warm"));
    warm.pull(&image_ref("library/small", &small.index))
        .expect("one layer fits");
    let cold = capped(&tmp.path().join("cold"));
    for (what, store) in [("warm", &warm), ("cold", &cold)] {
        match store.pull(&image_ref("library/big", &big.index)) {
            Err(ImageError::Failed { detail }) => {
                assert!(
                    detail.contains("uncompressed image size"),
                    "{what}: {detail}"
                )
            }
            other => panic!("{what}: {other:?}"),
        }
    }
}

/// The store's own root is reported resolved, so a caller can build the
/// sandbox's layer paths from it.
#[test]
fn layers_live_under_the_root() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("under-root");
    let store = open(&tmp.path().join("store"), &fake);
    let rootfs = store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    let base: PathBuf = store.root().join("layers/sha256");
    for layer in store.lease(&rootfs).expect("lease").layers().to_vec() {
        assert_eq!(layer.parent(), Some(base.as_path()));
    }
}

/// A dial that panics once, then dials `fake`.
struct PanicOnce {
    fake: Fake,
    armed: AtomicBool,
}

impl boneli_oci::Dial for PanicOnce {
    fn dial(
        &self,
        host: &str,
        port: u16,
        deadline: std::time::Instant,
    ) -> std::io::Result<Box<dyn boneli_oci::Stream>> {
        if self.armed.swap(false, Ordering::SeqCst) {
            panic!("a dial that panics inside the store's lock");
        }
        self.fake.dial(host, port, deadline)
    }
}

/// A pull that panics while it holds the store's lock poisons it; disk
/// state commits only by rename, so the next pull recovers the lock
/// (ADR-004, D8) and succeeds.
#[test]
fn poisoned_lock_recovered() {
    let (hub, pushed) = app_hub();
    let fake = hub_fake(hub);
    let mut config = config(&fake);
    config.dial = Box::new(PanicOnce {
        fake: fake.clone(),
        armed: AtomicBool::new(true),
    });
    let tmp = TempDir::new("poison");
    let store = OciImageStore::open(&tmp.path().join("store"), config).expect("open");
    let image = image_ref("library/app", &pushed.index);
    let panicked = std::thread::scope(|s| s.spawn(|| store.pull(&image)).join().is_err());
    assert!(panicked, "the first pull panics");
    store.pull(&image).expect("the lock is recovered");
}

/// A layer blob already on disk is used when it hashes to its digest and
/// is fetched again when it does not.
#[test]
fn kept_layer_blob_used_only_if_it_hashes() {
    let (hub, pushed) = app_hub();
    let blobs: Vec<Vec<u8>> = pushed
        .blobs
        .iter()
        .map(|d| hub.blobs.get(d).expect("blob").clone())
        .collect();
    let fake = hub_fake(hub);
    let tmp = TempDir::new("kept-blob");
    let store = open(&tmp.path().join("store"), &fake);
    let dir = store.root().join("blobs/sha256");
    let path = |d: &str| dir.join(d.trim_start_matches("sha256:"));
    std::fs::write(path(&pushed.blobs[0]), &blobs[0]).expect("an intact copy");
    let mut bad = blobs[2].clone();
    bad[0] ^= 1;
    std::fs::write(path(&pushed.blobs[2]), &bad).expect("a corrupt copy");
    store
        .pull(&image_ref("library/app", &pushed.index))
        .expect("pull");
    assert_eq!(
        blob_requests(&fake.seen())
            .into_iter()
            .filter(|d| pushed.blobs.contains(d))
            .collect::<Vec<_>>(),
        pushed.blobs[1..].to_vec()
    );
}
