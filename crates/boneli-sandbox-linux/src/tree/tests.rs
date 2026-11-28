//! The edge cases of ADR-042 D5 and D6 on plain host directories, so they
//! run in every `cargo test`; the one that needs a mount point re-runs
//! this binary in a user and mount namespace of its own (`unshare -Urm`).

use super::*;
use boneli_workspace::{Metadata, materialize};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// A fresh directory of mode 0700 next to the test binary, on the target
/// directory's file system, removed on drop with every mode opened up.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let exe = std::env::current_exe().expect("current_exe");
        let dir = exe
            .parent()
            .expect("the test binary's directory")
            .join(format!("bsl-{tag}-{}-{n}", std::process::id()));
        if dir.exists() {
            remove_tree(&dir);
        }
        fs::create_dir(&dir).expect("create the scratch directory");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
        Scratch(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }

    fn fd(&self) -> OwnedFd {
        File::open(&self.0).expect("open the scratch").into()
    }

    fn write(&self, rel: &str, data: &[u8]) {
        let p = self.path(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).expect("create the parents");
        }
        fs::write(p, data).expect("write");
    }

    fn mkdir(&self, rel: &str) {
        fs::create_dir_all(self.path(rel)).expect("mkdir");
    }

    fn chmod(&self, rel: &str, mode: u32) {
        fs::set_permissions(self.path(rel), fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// A Unix socket at `rel`, bound through a short symlink in the temp
    /// directory: `sun_path` holds 108 bytes, less than the scratch path.
    fn socket(&self, rel: &str) -> std::os::unix::net::UnixListener {
        let short = std::env::temp_dir().join(format!(
            "bsl-{}-{}",
            std::process::id(),
            COUNTER_SOCK.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_file(&short);
        symlink(&self.0, &short).expect("short symlink");
        let listener = std::os::unix::net::UnixListener::bind(short.join(rel)).expect("bind");
        fs::remove_file(&short).expect("remove the short symlink");
        listener
    }
}

static COUNTER_SOCK: AtomicU32 = AtomicU32::new(0);

impl Drop for Scratch {
    fn drop(&mut self) {
        remove_tree(&self.0);
    }
}

/// Removes a tree after making every directory in it readable, writable
/// and searchable (the unreadable cases leave modes of 0).
fn remove_tree(dir: &Path) {
    fn open_up(dir: &Path) {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                open_up(&entry.path());
            }
        }
    }
    open_up(dir);
    let _ = fs::remove_dir_all(dir);
}

/// Makes `<dir>/<name>/<name>/…/<leaf>`, `depth` directories deep, with
/// path-based calls of short paths only: each step moves the chain built
/// so far into a new directory and renames that into its place, so a chain
/// longer than the path-based calls of std take is made without a
/// `chdir`, which would change every test thread's directory.
fn chain(dir: &Path, name: &str, depth: usize, leaf: &str) {
    let built = dir.join("chain-built");
    let next = dir.join("chain-next");
    fs::create_dir(&built).expect("mkdir");
    fs::write(built.join(leaf), b"x").expect("write the leaf");
    for _ in 1..depth {
        fs::create_dir(&next).expect("mkdir");
        fs::rename(&built, next.join(name)).expect("move the chain down");
        fs::rename(&next, &built).expect("move it back up");
    }
    fs::rename(&built, dir.join(name)).expect("name the top");
}

fn rel(path: &str) -> RelativePath {
    RelativePath::parse(path).expect("a relative path")
}

fn caps() -> Caps {
    Caps::for_workspace(1 << 30).expect("caps")
}

fn tp(bytes: &[u8]) -> TreePath {
    TreePath::parse(bytes).expect("a tree path")
}

/// The workspace of these entries, in the order given.
fn workspace(entries: &[(&[u8], Kind, &[u8])]) -> Workspace {
    Workspace::from_sorted(
        entries.iter().map(|(p, k, d)| (tp(p), *k, d.to_vec())),
        DEFAULT_MAX_NODES,
    )
    .expect("a workspace")
}

fn decode(bytes: &[u8]) -> Workspace {
    Workspace::decode(bytes, DEFAULT_MAX_NODES).expect("the export decodes")
}

fn paths(w: &Workspace) -> Vec<Vec<u8>> {
    w.iter().map(|(p, _, _)| p.as_bytes().to_vec()).collect()
}

fn refused(r: Result<impl fmt::Debug, TreeError>) -> (Vec<u8>, Problem) {
    match r {
        Err(TreeError::Refused { path, problem }) => (path, problem),
        other => panic!("{other:?}"),
    }
}

/// Runs `f` on a thread of its own and fails if it does not return within
/// 10 s: a read that blocked on a FIFO would hang the test otherwise.
fn promptly<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("returned within 10 s, without blocking")
}

/// The rule is `TreePath`'s, byte string by byte string (ADR-042, D1): the
/// git adapter's pin test (`git_cli_rule_is_tree_path`) for this adapter.
#[test]
fn sandbox_rule_is_tree_path() {
    let cases: [&[u8]; 30] = [
        b"",
        b"/",
        b"/abs",
        b"a",
        b"a/b",
        b"a//b",
        b"a/",
        b"./a",
        b"a/./b",
        b"../a",
        b"a/..",
        b"a\0b",
        b"a\\b",
        b"..\\x",
        b" ",
        b"\t",
        b"x\xff",
        b"\xc0\xae\xc0\xae",
        b".git",
        b".git/config",
        b"sub/.git",
        b"sub/.git/HEAD",
        b".gitignore",
        b".github/workflows/ci.yml",
        b".GIT",
        b".git\\x",
        b"a.git",
        b"git",
        "\u{17E}/\u{200B}".as_bytes(),
        b"~/x",
    ];
    for bytes in cases {
        let ours = TreeRule::check(bytes);
        assert_eq!(ours, TreePath::parse(bytes), "{bytes:?}");
        if let Ok(path) = ours {
            assert_eq!(TreeRule::bytes(&path), bytes, "{bytes:?}");
            assert_eq!(
                TreeRule::is_metadata(bytes),
                path.is_repository_metadata(),
                "{bytes:?}"
            );
        } else {
            assert!(TreeRule::is_metadata(bytes), "{bytes:?} fails closed");
        }
    }
    assert!(TreeRule::is_metadata(b"sub/.git/HEAD"));
    assert!(!TreeRule::is_metadata(b".gitignore"));
}

#[test]
fn copy_out_empty_file() {
    let s = Scratch::new("empty-file");
    s.write("e", b"");
    assert_eq!(read_file(s.fd().as_fd(), &rel("e"), 10), Ok(Vec::new()));
}

#[test]
fn copy_out_reads_files_only() {
    let s = Scratch::new("copy-out");
    s.write("d/f", b"content");
    s.write("sentinel", b"inside");
    symlink("/etc/hostname", s.path("abs")).expect("symlink");
    symlink("sentinel", s.path("rel")).expect("symlink");
    symlink("d", s.path("dirlink")).expect("symlink");
    let fd = s.fd();
    let root = fd.as_fd();
    assert_eq!(read_file(root, &rel("d/f"), 7), Ok(b"content".to_vec()));
    assert_eq!(
        refused(read_file(root, &rel("d/f"), 6)),
        (b"d/f".to_vec(), Problem::TooManyBytes { max: 6 }),
        "one byte over the cap"
    );
    for missing in ["none", "d/none", "d/f/below", "d"] {
        assert_eq!(
            read_file(root, &rel(missing), 10),
            Err(TreeError::NotFound),
            "{missing}"
        );
    }
    for (link, at) in [("abs", "abs"), ("rel", "rel"), ("dirlink/f", "dirlink/f")] {
        assert_eq!(
            refused(read_file(root, &rel(link), 100)),
            (at.as_bytes().to_vec(), Problem::Symlink),
            "{link}"
        );
    }
    s.chmod("d/f", 0o000);
    assert_eq!(
        refused(read_file(root, &rel("d/f"), 100)),
        (b"d/f".to_vec(), Problem::Unreadable)
    );
}

#[test]
fn copy_out_fifo_does_not_block() {
    let s = Scratch::new("fifo");
    boneli_sys::make_fifo(&s.path("p"), 0o644).expect("mkfifo");
    let _listener = s.socket("sock");
    let fd = s.fd();
    let result = promptly(move || {
        (
            read_file(fd.as_fd(), &rel("p"), 100),
            read_file(fd.as_fd(), &rel("sock"), 100),
        )
    });
    assert_eq!(refused(result.0), (b"p".to_vec(), Problem::Special));
    assert_eq!(refused(result.1), (b"sock".to_vec(), Problem::Special));
}

#[test]
fn export_of_emptied_workspace() {
    let s = Scratch::new("emptied");
    s.write("a/b/c", b"x");
    fs::remove_dir_all(s.path("a")).expect("delete everything");
    assert_eq!(export(s.fd().as_fd(), &caps()), Ok(MAGIC.to_vec()));
}

/// Copies `w` into a new directory with `materialize`, as the copy-in will
/// (`Metadata::Carry`, ADR-042 D1), and exports it again.
fn round_trip(tag: &str, w: &Workspace) -> Vec<u8> {
    let s = Scratch::new(tag);
    materialize(w, &s.0, &[], DEFAULT_MAX_NODES, Metadata::Carry).expect("materialize");
    export(s.fd().as_fd(), &caps()).expect("export")
}

#[test]
fn empty_workspace_round_trips() {
    let w = Workspace::decode(MAGIC, DEFAULT_MAX_NODES).expect("magic only");
    assert_eq!(round_trip("magic-only", &w), MAGIC);
}

#[test]
fn hostile_names_round_trip() {
    // ADR-018: a backslash, a blank, a tab, a newline and bytes that are
    // not UTF-8 are name bytes, carried both ways.
    let w = workspace(&[
        (b"\t", Kind::File, b"tab"),
        (b"\n", Kind::File, b"newline"),
        (b" ", Kind::Executable, b"blank"),
        (b"..\\x", Kind::File, b"dots"),
        (b"a\\b", Kind::Symlink, b"..\\.."),
        (b"d/\xc0\xae\xc0\xae", Kind::File, b"overlong"),
        (b"d/\xff\xfe", Kind::File, b"latin"),
    ]);
    assert_eq!(round_trip("hostile", &w), w.encode());
}

#[test]
fn workspace_metadata_carried() {
    let w = workspace(&[
        (b".git/HEAD", Kind::File, b"ref: refs/heads/main\n"),
        (b".git/objects/ab/cdef", Kind::File, b"object"),
        (b".gitignore", Kind::File, b"target\n"),
        (b"sub/.git", Kind::File, b"gitdir: ../.git/modules/sub\n"),
    ]);
    assert_eq!(round_trip("metadata", &w), w.encode());
}

#[test]
fn export_orders_like_git() {
    let s = Scratch::new("order");
    for name in ["a-b", "a.txt", "a/b", "a0"] {
        s.write(name, name.as_bytes());
    }
    let got = decode(&export(s.fd().as_fd(), &caps()).expect("export"));
    assert_eq!(
        paths(&got),
        [&b"a-b"[..], b"a.txt", b"a/b", b"a0"].map(<[u8]>::to_vec)
    );
}

#[test]
fn export_reads_hardlinks_as_content() {
    let s = Scratch::new("hardlink");
    s.write("f", b"shared");
    fs::hard_link(s.path("f"), s.path("g")).expect("hard link");
    let got = decode(&export(s.fd().as_fd(), &caps()).expect("export"));
    assert_eq!(
        got,
        workspace(&[(b"f", Kind::File, b"shared"), (b"g", Kind::File, b"shared")])
    );
}

#[test]
fn export_keeps_symlinks_raw() {
    let s = Scratch::new("links");
    s.write("d/f", b"x");
    s.write("sentinel", b"inside");
    symlink("/etc/passwd", s.path("abs")).expect("symlink");
    symlink("../../outside", s.path("d/up")).expect("symlink");
    symlink("dangling", s.path("dangle")).expect("symlink");
    symlink("d", s.path("dirlink")).expect("symlink");
    symlink("sentinel", s.path("rel")).expect("symlink");
    let got = decode(&export(s.fd().as_fd(), &caps()).expect("export"));
    assert_eq!(
        got,
        workspace(&[
            (b"abs", Kind::Symlink, b"/etc/passwd"),
            (b"d/f", Kind::File, b"x"),
            (b"d/up", Kind::Symlink, b"../../outside"),
            (b"dangle", Kind::Symlink, b"dangling"),
            (b"dirlink", Kind::Symlink, b"d"),
            (b"rel", Kind::Symlink, b"sentinel"),
            (b"sentinel", Kind::File, b"inside"),
        ]),
        "every link raw, none followed, the linked directory not walked"
    );
}

#[test]
fn export_skips_specials() {
    let s = Scratch::new("specials");
    s.write("kept", b"x");
    boneli_sys::make_fifo(&s.path("fifo"), 0o644).expect("mkfifo");
    s.mkdir("d");
    boneli_sys::make_fifo(&s.path("d/fifo"), 0o644).expect("mkfifo");
    let _listener = s.socket("sock");
    // An unprivileged process may create the 0:0 whiteout (Linux 5.8).
    boneli_sys::make_whiteout(&s.path("whiteout")).expect("mknod 0:0");
    s.mkdir("empty/deeper/still");
    let fd = s.fd();
    let exported = promptly(move || export(fd.as_fd(), &caps()));
    assert_eq!(
        decode(&exported.expect("export")),
        workspace(&[(b"kept", Kind::File, b"x")]),
        "FIFOs, a socket, a whiteout and empty directories are skipped"
    );
}

#[test]
fn export_maps_modes_to_git() {
    let s = Scratch::new("modes");
    let modes = [
        ("plain", 0o644, Kind::File),
        ("exec", 0o755, Kind::Executable),
        ("owner-only", 0o700, Kind::Executable),
        ("others-only", 0o611, Kind::File),
        ("read-exec", 0o500, Kind::Executable),
        ("setuid", 0o4755, Kind::Executable),
        ("setgid", 0o2644, Kind::File),
        ("sticky", 0o1755, Kind::Executable),
    ];
    for (name, mode, _) in modes {
        s.write(name, name.as_bytes());
        s.chmod(name, mode);
    }
    let got = decode(&export(s.fd().as_fd(), &caps()).expect("export"));
    for (name, mode, kind) in modes {
        assert_eq!(
            got.get(&tp(name.as_bytes())),
            Some((kind, name.as_bytes())),
            "{name} {mode:o}"
        );
    }
}

#[test]
fn export_unreadable_fails_closed() {
    for (what, mode, at) in [
        ("file 000", 0o000, &b"d/f"[..]),
        ("directory 000", 0o000, b"d"),
        ("directory without read", 0o300, b"d"),
        ("directory without search", 0o400, b"d/f"),
    ] {
        let s = Scratch::new("unreadable");
        s.write("d/f", b"x");
        let target = if what.starts_with("file") { "d/f" } else { "d" };
        s.chmod(target, mode);
        assert_eq!(
            refused(export(s.fd().as_fd(), &caps())),
            (at.to_vec(), Problem::Unreadable),
            "{what}: the path is named"
        );
    }
}

fn small(nodes: usize, names: usize, bytes: u64) -> Caps {
    Caps {
        nodes,
        names,
        bytes,
    }
}

#[test]
fn export_node_cap_inclusive() {
    // `d/f1`, `d/f2`, `g`: four nodes, the directory included.
    let s = Scratch::new("nodes");
    s.write("d/f1", b"1");
    s.write("d/f2", b"2");
    s.write("g", b"3");
    let fd = s.fd();
    assert!(
        export(fd.as_fd(), &small(4, 100, 1 << 20)).is_ok(),
        "exactly 4"
    );
    assert_eq!(
        refused(export(fd.as_fd(), &small(3, 100, 1 << 20))),
        (b"g".to_vec(), Problem::TooManyNodes { max: 3 })
    );
    // Empty directories and skipped names are no nodes.
    s.mkdir("empty/deeper");
    boneli_sys::make_fifo(&s.path("p"), 0o644).expect("mkfifo");
    assert!(
        export(fd.as_fd(), &small(4, 100, 1 << 20)).is_ok(),
        "still 4"
    );
}

/// The real cap, 200,000 nodes (ADR-010, D2): one directory and 199,999
/// empty files pass, one file more fails.
#[test]
fn export_default_node_cap_inclusive() {
    let s = Scratch::new("cap");
    s.mkdir("d");
    // Mostly hard links of a few empty files: one call each, and each is
    // a file of its own to the walk. A new file every 60,000 names, under
    // the link limits of btrfs (65,535) and ext4 (65,000).
    for i in 0..(DEFAULT_MAX_NODES - 1) {
        let at = s.path(&format!("d/{i}"));
        if i % 60_000 == 0 {
            File::create(&at).expect("create");
        } else {
            fs::hard_link(s.path(&format!("d/{}", i - i % 60_000)), at).expect("link");
        }
    }
    let fd = s.fd();
    let encoded = export(fd.as_fd(), &caps()).expect("exactly the node cap");
    assert_eq!(decode(&encoded).nodes(), DEFAULT_MAX_NODES);
    File::create(s.path("one-more")).expect("create");
    assert_eq!(
        refused(export(fd.as_fd(), &caps())),
        (
            b"one-more".to_vec(),
            Problem::TooManyNodes {
                max: DEFAULT_MAX_NODES
            }
        )
    );
}

#[test]
fn export_byte_cap_inclusive() {
    let s = Scratch::new("bytes");
    s.write("d/file", b"0123456789");
    symlink("target", s.path("link")).expect("symlink");
    let fd = s.fd();
    let whole = export(fd.as_fd(), &caps()).expect("export");
    // MAGIC + (17 + 6 + 10) + (17 + 4 + 6).
    assert_eq!(whole.len(), MAGIC.len() + 33 + 27);
    let exact = whole.len() as u64;
    assert_eq!(export(fd.as_fd(), &small(100, 100, exact)), Ok(whole));
    assert_eq!(
        refused(export(fd.as_fd(), &small(100, 100, exact - 1))),
        (b"link".to_vec(), Problem::TooManyBytes { max: exact - 1 }),
        "one byte short, in the last link's target"
    );
    // Short in the file's data, and short before it.
    let file_end = (MAGIC.len() + 33) as u64;
    assert_eq!(
        refused(export(fd.as_fd(), &small(100, 100, file_end - 1))),
        (
            b"d/file".to_vec(),
            Problem::TooManyBytes { max: file_end - 1 }
        )
    );
    assert_eq!(
        refused(export(fd.as_fd(), &small(100, 100, MAGIC.len() as u64 + 3))),
        (
            b"d/file".to_vec(),
            Problem::TooManyBytes {
                max: MAGIC.len() as u64 + 3
            }
        )
    );
}

#[test]
fn export_caps_of_a_pod() {
    assert_eq!(METADATA_BUDGET, 51_800_000);
    assert_eq!(
        Caps::for_workspace(536_870_912),
        Some(Caps {
            nodes: 200_000,
            names: 400_000,
            bytes: 536_870_912 + 51_800_000,
        })
    );
    assert_eq!(
        Caps::for_workspace(u64::MAX - 51_800_000).map(|c| c.bytes),
        Some(u64::MAX)
    );
    assert_eq!(Caps::for_workspace(u64::MAX - 51_799_999), None);
}

#[test]
fn export_name_cap_inclusive() {
    // Five names: `d`, `d/f`, an empty directory, a FIFO and `g`.
    let s = Scratch::new("names");
    s.write("d/f", b"1");
    s.write("g", b"2");
    s.mkdir("empty");
    boneli_sys::make_fifo(&s.path("p"), 0o644).expect("mkfifo");
    let fd = s.fd();
    assert!(
        export(fd.as_fd(), &small(100, 5, 1 << 20)).is_ok(),
        "exactly 5"
    );
    assert_eq!(
        refused(export(fd.as_fd(), &small(100, 4, 1 << 20))).1,
        Problem::TooManyNames { max: 4 }
    );
}

#[test]
fn export_path_cap_inclusive() {
    // 16 directories of 250 bytes and a file: 16 × 251 + 79 = 4,095 bytes,
    // then one byte more.
    let dir = "d".repeat(250);
    let s = Scratch::new("path");
    chain(&s.0, &dir, 16, &"f".repeat(79));
    let got = decode(&export(s.fd().as_fd(), &caps()).expect("4,095 bytes"));
    assert_eq!(paths(&got)[0].len(), PATH_MAX);
    let s = Scratch::new("path");
    chain(&s.0, &dir, 16, &"f".repeat(80));
    let (at, problem) = refused(export(s.fd().as_fd(), &caps()));
    assert_eq!(
        (at.len(), problem),
        (4096, Problem::PathTooLong { max: PATH_MAX })
    );
}

/// ADR-042 D5, as #128: the work of a walk down a chain of 1,900
/// directories (`d/d/…/f`, 3,801 bytes) is linear in the chain, counted,
/// not timed: twice the chain is about twice the work.
#[test]
fn export_deep_chain_is_linear() {
    let chain = |depth: usize| {
        let s = Scratch::new("chain");
        chain(&s.0, "d", depth, "f");
        let (encoded, work) = export_counted(s.fd().as_fd(), &caps()).expect("export");
        assert_eq!(paths(&decode(&encoded))[0].len(), 2 * depth + 1);
        work
    };
    let half = chain(950);
    let full = chain(1900);
    // Linear: 2.0 (measured 2.0). Quadratic in the depth: 4.
    assert!(
        full * 10 <= half * 22,
        "work {full} for 1,900 directories, {half} for 950"
    );
    // A few operations per directory and byte, not per directory squared.
    assert!(full <= 20 * 3_801, "work {full}");
}

/// The inode check behind `Changed`: another file, or the same one of
/// another kind, is refused.
#[test]
fn inode_check_refuses_another_file() {
    let s = Scratch::new("inode");
    s.write("a", b"1");
    s.write("b", b"2");
    let open = |p: &str| -> OwnedFd { File::open(s.path(p)).expect("open").into() };
    let a = stat(&open("a"), b"a").expect("stat");
    assert_eq!(same(&open("a"), &a, b"a"), Ok(()));
    assert_eq!(
        refused(same(&open("b"), &a, b"a")),
        (b"a".to_vec(), Problem::Changed)
    );
}

/// The walk's own inode check: a name that is now another inode than the
/// listing saw is refused.
#[test]
fn reopen_refuses_another_inode() {
    let s = Scratch::new("reopen");
    s.write("a", b"1");
    let fd = s.fd();
    let meta = fs::metadata(s.path("a")).expect("stat");
    let caps = caps();
    let mut walk = Walk::new(&caps, 0);
    assert!(
        walk.reopen(&fd, b"a", b"a", Open::Read, meta.dev(), meta.ino())
            .is_ok()
    );
    assert_eq!(
        refused(walk.reopen(&fd, b"a", b"a", Open::Read, meta.dev(), meta.ino() + 1)),
        (b"a".to_vec(), Problem::Changed)
    );
    assert_eq!(
        refused(walk.reopen(&fd, b"a", b"a", Open::Read, meta.dev() + 1, meta.ino())),
        (b"a".to_vec(), Problem::Changed)
    );
}

#[test]
fn failure_details_are_never_blank() {
    let problems = [
        Problem::Symlink,
        Problem::MountPoint,
        Problem::Special,
        Problem::NotADirectory,
        Problem::Unreadable,
        Problem::Changed,
        Problem::NoEntries,
        Problem::NoPaths,
        Problem::Overlap {
            other: b"x".to_vec(),
        },
        Problem::TooManyNodes { max: 1 },
        Problem::TooManyNames { max: 1 },
        Problem::TooManyBytes { max: 1 },
        Problem::PathTooLong { max: 1 },
        Problem::Target,
        Problem::Format(String::from("why")),
        Problem::Io {
            call: "read",
            detail: String::from("why"),
        },
    ];
    for problem in problems {
        for path in [&b""[..], b"a/\xff"] {
            let e = TreeError::at(path, problem.clone());
            let text = e.to_string();
            assert!(!text.trim().is_empty(), "{e:?}");
            match SandboxError::from(e) {
                SandboxError::Failed { detail } => assert_eq!(detail, text),
                other => panic!("{other:?}"),
            }
        }
    }
    assert_eq!(
        TreeError::at(b"a/\xff", Problem::Symlink).to_string(),
        "\"a/\\xff\" is or passes a symlink, which is never followed"
    );
    assert_eq!(
        SandboxError::from(TreeError::NotFound),
        SandboxError::NotFound
    );
    assert!(!TreeError::NotFound.to_string().trim().is_empty());
}

/// A new, empty layer directory of mode 0700 next to the test binary.
fn layer(tag: &str) -> Scratch {
    Scratch::new(tag)
}

#[test]
fn seal_needs_paths() {
    let s = Scratch::new("seal-none");
    let target = layer("layer-none");
    assert_eq!(
        refused(copy_tree(s.fd().as_fd(), &[], &target.0, &caps())),
        (Vec::new(), Problem::NoPaths)
    );
}

#[test]
fn dependency_paths_overlap_refused() {
    let s = Scratch::new("seal-overlap");
    s.write("node_modules/x/f", b"1");
    for (a, b) in [
        ("node_modules", "node_modules"),
        ("node_modules", "node_modules/x"),
        ("node_modules/x", "node_modules"),
    ] {
        let target = layer("layer-overlap");
        assert_eq!(
            refused(copy_tree(
                s.fd().as_fd(),
                &[rel(a), rel(b)],
                &target.0,
                &caps()
            )),
            (
                a.as_bytes().to_vec(),
                Problem::Overlap {
                    other: b.as_bytes().to_vec()
                }
            ),
            "{a} with {b}"
        );
        assert_eq!(
            fs::read_dir(&target.0).expect("list").count(),
            0,
            "nothing copied"
        );
    }
}

#[test]
fn seal_refuses_what_is_no_directory() {
    let s = Scratch::new("seal-refused");
    s.write("dir/f", b"1");
    s.write("file", b"2");
    s.mkdir("empty/deeper");
    boneli_sys::make_fifo(&s.path("dir/p"), 0o644).expect("mkfifo");
    symlink("dir", s.path("link")).expect("symlink");
    s.mkdir("only-specials");
    boneli_sys::make_fifo(&s.path("only-specials/p"), 0o644).expect("mkfifo");
    for (path, at, problem) in [
        ("link", "link", Problem::Symlink),
        ("link/f", "link/f", Problem::Symlink),
        ("file", "file", Problem::NotADirectory),
        ("none", "none", Problem::NotADirectory),
        ("empty", "empty", Problem::NoEntries),
        ("only-specials", "only-specials", Problem::NoEntries),
    ] {
        let target = layer("layer-refused");
        assert_eq!(
            refused(copy_tree(s.fd().as_fd(), &[rel(path)], &target.0, &caps())),
            (at.as_bytes().to_vec(), problem),
            "{path}"
        );
    }
}

#[test]
fn seal_target_must_be_new_and_private() {
    let s = Scratch::new("seal-target");
    s.write("dir/f", b"1");
    let open = layer("layer-open");
    open.chmod("", 0o755);
    let full = layer("layer-full");
    full.write("x", b"");
    let inner = layer("layer-inner");
    let linked = layer("layer-link");
    let link = linked.path("to-inner");
    symlink(&inner.0, &link).expect("symlink");
    for target in [&open.0, &full.0, &link, &linked.path("none")] {
        assert_eq!(
            refused(copy_tree(s.fd().as_fd(), &[rel("dir")], target, &caps())),
            (Vec::new(), Problem::Target),
            "{}",
            target.display()
        );
    }
}

#[test]
fn seal_round_trips() {
    let s = Scratch::new("seal");
    s.write("node_modules/a/index.js", b"module.exports = 1;\n");
    s.write("node_modules/.bin/tool", b"#!/bin/sh\n");
    s.chmod("node_modules/.bin/tool", 0o755);
    symlink("../a/index.js", s.path("node_modules/.bin/a")).expect("symlink");
    boneli_sys::make_fifo(&s.path("node_modules/p"), 0o644).expect("mkfifo");
    s.mkdir("node_modules/empty");
    s.write("vendor/lib/x.rb", b"x");
    s.write("src/main.js", b"not sealed");
    let target = layer("layer");
    copy_tree(
        s.fd().as_fd(),
        &[rel("node_modules"), rel("vendor/lib")],
        &target.0,
        &caps(),
    )
    .expect("seal");
    let sealed = decode(&export(target.fd().as_fd(), &caps()).expect("export the layer"));
    let workspace = decode(&export(s.fd().as_fd(), &caps()).expect("export"));
    let expected: Vec<_> = workspace
        .iter()
        .filter(|(p, _, _)| !p.as_bytes().starts_with(b"src/"))
        .map(|(p, k, d)| (p.clone(), k, d.to_vec()))
        .collect();
    assert_eq!(
        sealed,
        Workspace::from_sorted(expected, DEFAULT_MAX_NODES).expect("expected"),
        "the sealed directories, as they are, at their paths"
    );
    let mode = |p: &str| {
        fs::symlink_metadata(target.path(p))
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode("node_modules/a/index.js"), 0o644);
    assert_eq!(mode("node_modules/.bin/tool"), 0o755);
    assert_eq!(mode("node_modules/.bin"), 0o755);
    assert_eq!(mode("vendor"), 0o755);
    assert!(
        !target.path("node_modules/empty").exists(),
        "no empty directory"
    );
    assert!(!target.path("node_modules/p").exists(), "no FIFO");
}

#[test]
fn seal_caps_hold_across_paths() {
    let s = Scratch::new("seal-caps");
    s.write("a/f", b"1");
    s.write("b/f", b"2");
    // a, a/f, b, b/f: 4 nodes; one fewer fails in the second path.
    let fits = layer("layer-fits");
    assert!(
        copy_tree(
            s.fd().as_fd(),
            &[rel("a"), rel("b")],
            &fits.0,
            &small(4, 100, 1 << 20)
        )
        .is_ok()
    );
    let short = layer("layer-short");
    assert_eq!(
        refused(copy_tree(
            s.fd().as_fd(),
            &[rel("a"), rel("b")],
            &short.0,
            &small(3, 100, 1 << 20)
        )),
        (b"b/f".to_vec(), Problem::TooManyNodes { max: 3 })
    );
    // Bytes: (17 + 3 + 1) per file, 42 for both.
    let exact = layer("layer-exact");
    assert!(
        copy_tree(
            s.fd().as_fd(),
            &[rel("a"), rel("b")],
            &exact.0,
            &small(100, 100, 42)
        )
        .is_ok()
    );
    let over = layer("layer-over");
    assert_eq!(
        refused(copy_tree(
            s.fd().as_fd(),
            &[rel("a"), rel("b")],
            &over.0,
            &small(100, 100, 41)
        )),
        (b"b/f".to_vec(), Problem::TooManyBytes { max: 41 })
    );
}

/// The variable that tells a re-run of this binary that it runs inside
/// `unshare -Urm`.
const IN_USERNS: &str = "BONELI_SANDBOX_LINUX_TEST_IN_USERNS";

/// ADR-042 D5: a mount point (a dependency bind) is not part of the
/// workspace. The export skips it, at a directory and at a file, and
/// `copy_out` and a seal beneath it are refused. Needs a mount, so the
/// test runs itself again in a user and mount namespace of its own.
#[test]
#[ignore = "host: unprivileged user namespaces (unshare -Urm)"]
fn export_skips_dependency_mounts() {
    if std::env::var_os(IN_USERNS).is_none() {
        let status = std::process::Command::new("unshare")
            .args(["-Urm", "--"])
            .arg(std::env::current_exe().expect("current_exe"))
            .args([
                "--exact",
                "tree::tests::export_skips_dependency_mounts",
                "--ignored",
                "--nocapture",
            ])
            .env(IN_USERNS, "1")
            .status()
            .expect("run unshare");
        assert!(
            status.success(),
            "the run in the namespace failed: {status}"
        );
        return;
    }
    let s = Scratch::new("mounts");
    s.write("a", b"tracked");
    s.mkdir("node_modules");
    s.write("covered", b"under the bind");
    let mount = |args: &[&str]| {
        let status = std::process::Command::new("mount")
            .args(args)
            .status()
            .expect("run mount");
        assert!(status.success(), "mount {args:?}");
    };
    let dir = s.path("node_modules");
    let dir = dir.to_str().expect("UTF-8 scratch path");
    mount(&["-t", "tmpfs", "none", dir]);
    fs::write(s.path("node_modules/dep.js"), b"dependency").expect("write in the mount");
    let covered = s.path("covered");
    mount(&["--bind", "/etc/hostname", covered.to_str().expect("UTF-8")]);
    let fd = s.fd();
    let got = decode(&export(fd.as_fd(), &caps()).expect("export"));
    assert_eq!(
        got,
        workspace(&[(b"a", Kind::File, b"tracked")]),
        "both mount points skipped"
    );
    assert_eq!(
        refused(read_file(fd.as_fd(), &rel("node_modules/dep.js"), 100)),
        (b"node_modules/dep.js".to_vec(), Problem::MountPoint)
    );
    assert_eq!(
        refused(read_file(fd.as_fd(), &rel("covered"), 100)),
        (b"covered".to_vec(), Problem::MountPoint)
    );
    let target = layer("layer-mount");
    assert_eq!(
        refused(copy_tree(
            fd.as_fd(),
            &[rel("node_modules")],
            &target.0,
            &caps()
        )),
        (b"node_modules".to_vec(), Problem::MountPoint)
    );
    for d in [dir, covered.to_str().expect("UTF-8")] {
        let _ = std::process::Command::new("umount").arg(d).status();
    }
}
