//! Layer unpacking (ADR-009, D1-D5, D7, D8): the edge cases of the #7 plan,
//! one test per case, against real files in a temporary directory.

mod support;

use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use boneli_https::Sha256;
use boneli_oci::{Budget, Compression, Error, LayerCache, LayerStats, Limits, unpack};
use boneli_sys::user_xattr;

use support::tarball::{self, BLOCK, Checksum, Header, MTIME, Magic, Tar};
use support::{TempDir, make_writable};

const MIB: u64 = 1 << 20;
/// The path depth the store uses (ADR-009, D7).
const DEPTH: u64 = 128;
const OPAQUE: &str = "user.overlay.opaque";

/// Generous limits, so only the case under test can trip one.
fn limits() -> Limits {
    Limits::new(1 << 32, 1 << 34, 1 << 20, MIB, DEPTH).expect("valid limits")
}

fn budget() -> Budget {
    Budget::new(limits())
}

/// Unpacks `bytes` into a fresh directory.
fn try_unpack(bytes: &[u8], compression: Compression) -> (TempDir, Result<LayerStats, Error>) {
    let dir = TempDir::new("layer");
    let result = unpack(bytes, compression, dir.path(), &mut budget());
    (dir, result)
}

/// Unpacks a plain tar that must be accepted.
fn ok(bytes: &[u8]) -> (TempDir, LayerStats) {
    let (dir, result) = try_unpack(bytes, Compression::None);
    match result {
        Ok(stats) => (dir, stats),
        Err(e) => panic!("expected the layer to unpack, got {e}"),
    }
}

/// Unpacks a plain tar that must be refused.
fn refused(bytes: &[u8]) -> (TempDir, Error) {
    let (dir, result) = try_unpack(bytes, Compression::None);
    match result {
        Ok(stats) => panic!("expected a refusal, got {stats:?}"),
        Err(e) => (dir, e),
    }
}

fn meta(path: &Path) -> std::fs::Metadata {
    std::fs::symlink_metadata(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

fn mode(path: &Path) -> u32 {
    meta(path).mode() & 0o7777
}

fn is_whiteout(path: &Path) -> bool {
    let m = meta(path);
    m.file_type().is_char_device() && m.rdev() == 0
}

/// The names in a directory, sorted.
fn names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

// ---- Paths ---------------------------------------------------------------

#[test]
fn paths_normalized() {
    let bytes = Tar::new()
        .file("./a", 0o644, b"1")
        .file("/b", 0o644, b"2")
        .dir("c//", 0o755)
        .file("c//d", 0o644, b"3")
        .file("c/./e", 0o644, b"4")
        .file("/./c/.//f", 0o644, b"5")
        .finish();
    let (dir, stats) = ok(&bytes);
    let root = dir.path();
    assert_eq!(names(root), ["a", "b", "c"]);
    assert_eq!(names(&root.join("c")), ["d", "e", "f"]);
    assert_eq!(std::fs::read(root.join("c/f")).expect("read"), b"5");
    assert_eq!(stats.entries, 6);
}

#[test]
fn dotdot_component_refused() {
    for name in [
        "..",
        "../x",
        "a/../b",
        "a/..",
        "./..",
        "/../etc/x",
        "a/b/../../..",
    ] {
        let bytes = Tar::new().dir("a", 0o755).file(name, 0o644, b"x").finish();
        let (dir, e) = refused(&bytes);
        assert!(matches!(e, Error::Entry { .. }), "{name}: {e}");
        assert!(!exists(&dir.path().join("b")), "{name}");
    }
    // A hard link or symlink target is checked with the same rule for hard
    // links (archive paths); symlink targets are data, read inside the
    // sandbox (D2).
    let bytes = Tar::new()
        .file("f", 0o644, b"x")
        .hardlink("h", "a/../f")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Entry { .. }));
}

#[test]
fn root_entry_sets_root_mode() {
    for name in [".", "./", "/"] {
        let mut h = Header::new(name.as_bytes(), b'5');
        h.mode = 0o751;
        h.mtime = 1_000;
        let bytes = Tar::new().entry(&h, &[]).file("x", 0o644, b"x").finish();
        let (dir, _) = ok(&bytes);
        assert_eq!(mode(dir.path()), 0o751, "{name}");
        // Mode only: the root keeps the unpack time.
        assert_ne!(meta(dir.path()).mtime(), 1_000, "{name}");
    }
    // A root entry that is not a directory is refused.
    let bytes = Tar::new().file("./", 0o644, b"x").finish();
    assert!(matches!(refused(&bytes).1, Error::Entry { .. }));
}

#[test]
fn nul_in_pax_path_refused() {
    let bytes = Tar::new()
        .pax(&[("path", b"a\0b")])
        .file("ignored", 0o644, b"x")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Tar(_)));
    let bytes = Tar::new()
        .pax(&[("linkpath", b"t\0u")])
        .symlink("l", "ignored")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Tar(_)));
}

#[test]
fn name_255_ok_256_refused() {
    let long255 = "n".repeat(255);
    let bytes = Tar::new()
        .pax(&[("path", long255.as_bytes())])
        .file("short", 0o644, b"x")
        .finish();
    let (dir, _) = ok(&bytes);
    assert!(exists(&dir.path().join(&long255)));

    let long256 = "n".repeat(256);
    let bytes = Tar::new()
        .pax(&[("path", long256.as_bytes())])
        .file("short", 0o644, b"x")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Write { .. }));
    // The same as a parent component.
    let bytes = Tar::new()
        .gnu_long(b'L', format!("{long256}/f").as_bytes())
        .file("short", 0o644, b"x")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Write { .. }));
}

#[test]
fn symlink_parent_traversal_refused() {
    let outside = TempDir::new("outside");
    let target = outside.path().to_str().expect("utf-8").to_string();
    for entry in ["etc/passwd", "etc/sub/passwd", "./etc//passwd"] {
        let bytes = Tar::new()
            .symlink("etc", &target)
            .file(entry, 0o644, b"root::0:0")
            .finish();
        let (_dir, e) = refused(&bytes);
        assert!(matches!(e, Error::Entry { .. }), "{entry}: {e}");
        assert!(names(outside.path()).is_empty(), "{entry}: wrote outside");
    }
    // Every kind of entry under a symlinked parent, including a relative
    // link that stays inside the layer.
    let bytes = Tar::new()
        .dir("real", 0o755)
        .symlink("rel", "real")
        .dir("rel/x", 0o755)
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Entry { .. }));
    let bytes = Tar::new()
        .symlink("etc", &target)
        .file(".wh.x", 0o644, b"")
        .finish();
    // A whiteout at the root is fine; under the link it is not.
    ok(&bytes);
    let bytes = Tar::new()
        .symlink("etc", &target)
        .file("etc/.wh.x", 0o644, b"")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Entry { .. }));
    let bytes = Tar::new()
        .symlink("etc", &target)
        .file("etc/.wh..wh..opq", 0o644, b"")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Entry { .. }));
    assert!(names(outside.path()).is_empty());
    // A regular file as a parent.
    let bytes = Tar::new()
        .file("f", 0o644, b"x")
        .file("f/g", 0o644, b"y")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Entry { .. }));
}

#[test]
fn hardlink_target_rules() {
    // Valid: the same inode.
    let bytes = Tar::new()
        .file("f", 0o644, b"data")
        .hardlink("h", "f")
        .finish();
    let (dir, _) = ok(&bytes);
    assert_eq!(
        meta(&dir.path().join("f")).ino(),
        meta(&dir.path().join("h")).ino()
    );

    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "crosses a symlink",
            Tar::new()
                .dir("d", 0o755)
                .file("d/f", 0o644, b"x")
                .symlink("s", "d")
                .hardlink("h", "s/f")
                .finish(),
        ),
        (
            "dotdot",
            Tar::new()
                .dir("a", 0o755)
                .file("f", 0o644, b"x")
                .hardlink("h", "a/../f")
                .finish(),
        ),
        ("missing", Tar::new().hardlink("h", "nope").finish()),
        (
            "a directory",
            Tar::new().dir("d", 0o755).hardlink("h", "d").finish(),
        ),
        (
            "a whiteout",
            Tar::new()
                .file(".wh.x", 0o644, b"")
                .hardlink("h", "x")
                .finish(),
        ),
        (
            "a whiteout by its tar name",
            Tar::new()
                .file(".wh.x", 0o644, b"")
                .hardlink("h", ".wh.x")
                .finish(),
        ),
        (
            "itself",
            Tar::new()
                .file("f", 0o644, b"x")
                .hardlink("f", "f")
                .finish(),
        ),
        ("the root", Tar::new().hardlink("h", "./").finish()),
    ];
    for (what, bytes) in cases {
        let (_dir, e) = refused(&bytes);
        assert!(matches!(e, Error::Entry { .. }), "{what}: {e}");
    }
}

#[test]
fn file_over_symlink_not_followed() {
    let outside = TempDir::new("victim");
    let victim = outside.path().join("victim");
    std::fs::write(&victim, b"original").expect("victim");
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    let bytes = Tar::new()
        .symlink("x", victim.to_str().expect("utf-8"))
        .file("x", 0o644, b"new")
        .hardlink("y", "x")
        .symlink("z", victim.to_str().expect("utf-8"))
        .fifo("z", 0o644)
        .finish();
    let (dir, _) = ok(&bytes);
    assert!(meta(&dir.path().join("x")).is_file());
    assert_eq!(std::fs::read(dir.path().join("x")).expect("read"), b"new");
    assert!(meta(&dir.path().join("z")).file_type().is_fifo());
    assert_eq!(std::fs::read(&victim).expect("read"), b"original");
    assert_eq!(
        mode(&victim),
        0o640,
        "the FIFO's mode did not reach the target"
    );
}

#[test]
fn duplicate_entry_later_wins() {
    let bytes = Tar::new()
        .file("a", 0o644, b"one")
        .file("a", 0o600, b"two")
        .symlink("b", "x")
        .file("b", 0o644, b"file")
        .file("c", 0o644, b"file")
        .symlink("c", "target")
        .file("d", 0o644, b"file")
        .dir("d", 0o750)
        .finish();
    let (dir, _) = ok(&bytes);
    let root = dir.path();
    assert_eq!(std::fs::read(root.join("a")).expect("a"), b"two");
    assert_eq!(mode(&root.join("a")), 0o600);
    assert_eq!(std::fs::read(root.join("b")).expect("b"), b"file");
    assert_eq!(
        std::fs::read_link(root.join("c")).expect("c"),
        Path::new("target")
    );
    assert!(meta(&root.join("d")).is_dir());
    assert_eq!(mode(&root.join("d")), 0o750);
}

#[test]
fn file_replaces_dir_recursively() {
    let bytes = Tar::new()
        .dir("d", 0o555)
        .file("d/f", 0o644, b"x")
        .dir("d/sub", 0o000)
        .file("d/sub/g", 0o000, b"y")
        .file("d", 0o640, b"now a file")
        .finish();
    let (dir, _) = ok(&bytes);
    let d = dir.path().join("d");
    assert!(meta(&d).is_file());
    assert_eq!(std::fs::read(&d).expect("read"), b"now a file");
    assert_eq!(mode(&d), 0o640);
    // And a directory again over that file, then the old children are gone.
    let bytes = Tar::new()
        .dir("d", 0o755)
        .file("d/f", 0o644, b"x")
        .symlink("d", "elsewhere")
        .dir("d", 0o700)
        .finish();
    let (dir, _) = ok(&bytes);
    assert!(names(&dir.path().join("d")).is_empty());
}

#[test]
fn dir_over_dir_merges() {
    let bytes = Tar::new()
        .dir_at("d", 0o755, 1_000_000)
        .file("d/f", 0o644, b"x")
        .dir_at("d", 0o700, 2_000_000)
        .file("d/g", 0o644, b"y")
        .finish();
    let (dir, _) = ok(&bytes);
    let d = dir.path().join("d");
    assert_eq!(names(&d), ["f", "g"]);
    assert_eq!(mode(&d), 0o700);
    assert_eq!(meta(&d).mtime(), 2_000_000);
}

#[test]
fn missing_parents_are_created() {
    let bytes = Tar::new().file("a/b/c", 0o644, b"x").finish();
    let (dir, _) = ok(&bytes);
    assert!(meta(&dir.path().join("a/b")).is_dir());
    assert_eq!(mode(&dir.path().join("a")), 0o755);
}

// ---- Whiteouts -----------------------------------------------------------

#[test]
fn whiteout_becomes_char_device_0_0() {
    let bytes = Tar::new()
        .file(".wh.gone", 0o644, b"")
        .dir("sub", 0o755)
        .file("sub/.wh.x", 0o644, b"")
        .file("deep/er/.wh.y", 0o644, b"")
        .finish();
    let (dir, stats) = ok(&bytes);
    let root = dir.path();
    assert!(is_whiteout(&root.join("gone")));
    assert!(is_whiteout(&root.join("sub/x")));
    assert!(is_whiteout(&root.join("deep/er/y")));
    assert!(!exists(&root.join(".wh.gone")));
    assert_eq!(names(root), ["deep", "gone", "sub"]);
    assert_eq!(stats.skipped_devices, 0);
}

#[test]
fn opaque_marker_sets_user_xattr() {
    let bytes = Tar::new()
        .dir("d", 0o755)
        .file("d/.wh..wh..opq", 0o644, b"")
        .file("d/kept", 0o644, b"x")
        // Marker before its directory entry; the entry merges.
        .file("e/.wh..wh..opq", 0o644, b"")
        .dir("e", 0o700)
        .finish();
    let (dir, _) = ok(&bytes);
    for d in ["d", "e"] {
        let p = dir.path().join(d);
        assert_eq!(
            user_xattr(&p, OPAQUE).expect("xattr"),
            Some(b"y".to_vec()),
            "{d}"
        );
        assert!(!exists(&p.join(".wh..wh..opq")), "{d}");
    }
    assert_eq!(names(&dir.path().join("d")), ["kept"]);
    assert_eq!(mode(&dir.path().join("e")), 0o700);
}

#[test]
fn root_level_opaque_refused() {
    for name in [".wh..wh..opq", "./.wh..wh..opq", "/.wh..wh..opq"] {
        let bytes = Tar::new().file(name, 0o644, b"").finish();
        let (dir, e) = refused(&bytes);
        assert!(matches!(e, Error::Entry { .. }), "{name}: {e}");
        assert_eq!(user_xattr(dir.path(), OPAQUE).expect("xattr"), None);
    }
}

#[test]
fn invalid_whiteout_names_refused() {
    for name in [
        ".wh.",
        ".wh..",
        ".wh...",
        "sub/.wh.",
        "sub/.wh..",
        "sub/.wh...",
    ] {
        let bytes = Tar::new().dir("sub", 0o755).file(name, 0o644, b"").finish();
        let (_dir, e) = refused(&bytes);
        assert!(matches!(e, Error::Entry { .. }), "{name}: {e}");
    }
}

#[test]
fn aufs_metadata_skipped() {
    let bytes = Tar::new()
        .dir(".wh..wh.plnk", 0o700)
        .file(".wh..wh.plnk/123.4", 0o644, b"x")
        .file(".wh..wh.aufs", 0o644, b"")
        .dir(".wh..wh.orph", 0o700)
        .file("kept", 0o644, b"x")
        .finish();
    let (dir, stats) = ok(&bytes);
    assert_eq!(names(dir.path()), ["kept"]);
    assert_eq!(stats.entries, 5, "skipped entries still count");

    let bytes = Tar::new()
        .file(".wh..wh.plnk/123.4", 0o644, b"x")
        .hardlink("h", ".wh..wh.plnk/123.4")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Entry { .. }));
}

#[test]
fn whiteout_component_in_parent_refused() {
    for name in [
        ".wh.foo/bar",
        "a/.wh.foo/bar",
        ".wh..wh..opq/x",
        "a/.wh..wh..opq/x",
    ] {
        let bytes = Tar::new().dir("a", 0o755).file(name, 0o644, b"x").finish();
        let (_dir, e) = refused(&bytes);
        assert!(matches!(e, Error::Entry { .. }), "{name}: {e}");
    }
}

#[test]
fn whiteout_by_name_regardless_of_type() {
    let bytes = Tar::new()
        .file("f", 0o644, b"x")
        .hardlink(".wh.a", "f")
        .symlink(".wh.b", "/etc/passwd")
        .dir(".wh.c", 0o755)
        .fifo(".wh.d", 0o644)
        .device(".wh.e", b'4', 8, 0)
        .finish();
    let (dir, _) = ok(&bytes);
    for name in ["a", "b", "c", "d", "e"] {
        assert!(is_whiteout(&dir.path().join(name)), "{name}");
    }
    assert_eq!(names(dir.path()), ["a", "b", "c", "d", "e", "f"]);
}

#[test]
fn whiteout_lookalikes_are_regular_files() {
    let lookalikes = [
        "\u{ff0e}wh\u{ff0e}foo",
        ".wh\u{200b}.foo",
        ".WH.foo",
        ".wh .foo",
        "wh.foo",
        "..wh.foo",
        " .wh.foo",
    ];
    let mut tar = Tar::new();
    for name in lookalikes {
        tar.pax(&[("path", name.as_bytes())])
            .file("x", 0o644, b"data");
    }
    let (dir, _) = ok(&tar.finish());
    for name in lookalikes {
        let p = dir.path().join(name);
        assert!(meta(&p).is_file(), "{name:?}");
        assert_eq!(std::fs::read(&p).expect("read"), b"data");
    }
    assert_eq!(names(dir.path()).len(), lookalikes.len());
}

#[test]
fn whiteout_and_entry_same_layer_real_wins() {
    let entry_first = Tar::new()
        .file("foo", 0o644, b"real")
        .file(".wh.foo", 0o644, b"")
        .finish();
    let whiteout_first = Tar::new()
        .file(".wh.foo", 0o644, b"")
        .file("foo", 0o644, b"real")
        .finish();
    for bytes in [entry_first, whiteout_first] {
        let (dir, _) = ok(&bytes);
        let foo = dir.path().join("foo");
        assert!(meta(&foo).is_file());
        assert_eq!(std::fs::read(&foo).expect("read"), b"real");
    }
    let bytes = Tar::new()
        .dir("d", 0o755)
        .file("d/x", 0o644, b"x")
        .file(".wh.d", 0o644, b"")
        .finish();
    let (dir, _) = ok(&bytes);
    assert_eq!(names(&dir.path().join("d")), ["x"]);
    // An entry under a path this layer whited out replaces the whiteout
    // with a directory.
    let bytes = Tar::new()
        .file(".wh.p", 0o644, b"")
        .file("p/q", 0o644, b"q")
        .finish();
    let (dir, _) = ok(&bytes);
    assert_eq!(names(&dir.path().join("p")), ["q"]);
    // A real directory after its whiteout keeps nothing of the whiteout.
    let bytes = Tar::new()
        .file(".wh.d", 0o644, b"")
        .dir("d", 0o755)
        .file("d/y", 0o644, b"y")
        .finish();
    let (dir, _) = ok(&bytes);
    assert_eq!(names(&dir.path().join("d")), ["y"]);
}

#[test]
fn device_entries() {
    let bytes = Tar::new()
        .device("w", b'3', 0, 0)
        .device("null", b'3', 1, 3)
        .device("sda", b'4', 8, 0)
        .device("blk0", b'4', 0, 0)
        .fifo("pipe", 0o640)
        .finish();
    let (dir, stats) = ok(&bytes);
    let root = dir.path();
    assert!(is_whiteout(&root.join("w")));
    assert!(!exists(&root.join("null")));
    assert!(!exists(&root.join("sda")));
    assert!(
        !exists(&root.join("blk0")),
        "a 0:0 block device is not a whiteout"
    );
    assert!(meta(&root.join("pipe")).file_type().is_fifo());
    assert_eq!(mode(&root.join("pipe")), 0o640);
    assert_eq!(stats.skipped_devices, 3);
    assert_eq!(stats.entries, 5);
}

// ---- Metadata ------------------------------------------------------------

#[test]
fn setuid_setgid_bits_dropped() {
    let bytes = Tar::new()
        .file("suid", 0o4755, b"x")
        .file("sgid", 0o2755, b"x")
        .file("both", 0o6711, b"x")
        .dir("gdir", 0o2775)
        .fifo("pipe", 0o4644)
        .finish();
    let (dir, _) = ok(&bytes);
    let root = dir.path();
    assert_eq!(mode(&root.join("suid")), 0o755);
    assert_eq!(mode(&root.join("sgid")), 0o755);
    assert_eq!(mode(&root.join("both")), 0o711);
    assert_eq!(mode(&root.join("gdir")), 0o775);
    assert_eq!(mode(&root.join("pipe")), 0o644);
}

#[test]
fn sticky_bit_kept() {
    let bytes = Tar::new().dir("tmp", 0o1777).dir("t2", 0o3777).finish();
    let (dir, _) = ok(&bytes);
    assert_eq!(mode(&dir.path().join("tmp")), 0o1777);
    assert_eq!(mode(&dir.path().join("t2")), 0o1777);
}

#[test]
fn readonly_dir_filled_then_moded() {
    let bytes = Tar::new()
        .dir("ro", 0o555)
        .file("ro/f", 0o644, b"x")
        .dir("ro/inner", 0o500)
        .file("ro/inner/g", 0o400, b"y")
        .dir("z", 0o000)
        .dir("z/sub", 0o555)
        .file("z/sub/f", 0o644, b"z")
        .finish();
    let (dir, _) = ok(&bytes);
    let root = dir.path();
    assert_eq!(mode(&root.join("ro")), 0o555);
    assert_eq!(mode(&root.join("ro/inner")), 0o500);
    assert_eq!(std::fs::read(root.join("ro/inner/g")).expect("read"), b"y");
    assert_eq!(mode(&root.join("z")), 0o000);
    make_writable(root);
    assert_eq!(std::fs::read(root.join("z/sub/f")).expect("read"), b"z");
}

#[test]
fn mode_000_file_written() {
    let bytes = Tar::new().file("secret", 0o000, b"contents").finish();
    let (dir, _) = ok(&bytes);
    let p = dir.path().join("secret");
    assert_eq!(mode(&p), 0o000);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    assert_eq!(std::fs::read(&p).expect("read"), b"contents");
}

#[test]
fn mtimes_preserved() {
    let bytes = Tar::new()
        .dir_at("d", 0o755, 1_100_000_000)
        .dir_at("d/e", 0o555, 1_200_000_000)
        .file_at("d/e/f", 0o644, b"x", 1_000_000_000)
        .file_at("d/g", 0o644, b"x", 0)
        .pax(&[("mtime", b"-100")])
        .file("neg", 0o644, b"x")
        .symlink("link", "d")
        .finish();
    let (dir, _) = ok(&bytes);
    let root = dir.path();
    assert_eq!(
        meta(&root.join("d")).mtime(),
        1_100_000_000,
        "a parent keeps its time"
    );
    assert_eq!(meta(&root.join("d/e")).mtime(), 1_200_000_000);
    assert_eq!(meta(&root.join("d/e/f")).mtime(), 1_000_000_000);
    assert_eq!(meta(&root.join("d/g")).mtime(), 0);
    assert_eq!(meta(&root.join("neg")).mtime(), -100);
    assert_ne!(
        meta(&root.join("link")).mtime(),
        MTIME,
        "symlinks get the unpack time"
    );
}

#[test]
fn pax_mtime_fraction() {
    let bytes = Tar::new()
        .pax(&[("mtime", b"1234567890.123456789")])
        .file("a", 0o644, b"x")
        .pax(&[("mtime", b"-1.5")])
        .file("b", 0o644, b"x")
        .pax(&[("mtime", b"10.1234567891")])
        .file("c", 0o644, b"x")
        .pax(&[("mtime", b"7.5")])
        .dir("d", 0o755)
        .finish();
    let (dir, _) = ok(&bytes);
    let root = dir.path();
    let a = meta(&root.join("a"));
    assert_eq!((a.mtime(), a.mtime_nsec()), (1_234_567_890, 123_456_789));
    let b = meta(&root.join("b"));
    assert_eq!((b.mtime(), b.mtime_nsec()), (-2, 500_000_000));
    let c = meta(&root.join("c"));
    assert_eq!(
        (c.mtime(), c.mtime_nsec()),
        (10, 123_456_789),
        "digits past 9 are dropped"
    );
    let d = meta(&root.join("d"));
    assert_eq!((d.mtime(), d.mtime_nsec()), (7, 500_000_000));

    // Go's parsePAXTime also takes "1." and a leading '+'; so does this.
    let bytes = Tar::new()
        .pax(&[("mtime", b"1.")])
        .file("e", 0o644, b"x")
        .pax(&[("mtime", b"+5")])
        .file("f", 0o644, b"x")
        .pax(&[("mtime", b"-0.25")])
        .file("g", 0o644, b"x")
        .finish();
    let (dir, _) = ok(&bytes);
    assert_eq!(meta(&dir.path().join("e")).mtime(), 1);
    assert_eq!(meta(&dir.path().join("f")).mtime(), 5);
    let g = meta(&dir.path().join("g"));
    assert_eq!((g.mtime(), g.mtime_nsec()), (-1, 750_000_000));

    for bad in [
        &b"1.2.3"[..],
        b"abc",
        b"1e5",
        b"",
        b"- 1",
        b"1.-5",
        b"9223372036854775808",
    ] {
        let bytes = Tar::new()
            .pax(&[("mtime", bad)])
            .file("x", 0o644, b"x")
            .finish();
        assert!(matches!(refused(&bytes).1, Error::Tar(_)), "{bad:?}");
    }
}

#[test]
fn pax_xattrs_never_applied() {
    let bytes = Tar::new()
        .pax(&[
            ("SCHILY.xattr.user.overlay.redirect", b"/etc"),
            ("SCHILY.xattr.user.overlay.opaque", b"y"),
            ("SCHILY.xattr.security.capability", b"\x01\x00\x00\x02"),
            ("SCHILY.xattr.user.other", b"v"),
        ])
        .dir("d", 0o755)
        .pax(&[("SCHILY.xattr.user.overlay.opaque", b"y")])
        .file("f", 0o644, b"x")
        .finish();
    let (dir, _) = ok(&bytes);
    for p in [dir.path().join("d"), dir.path().join("f")] {
        for name in ["user.overlay.redirect", OPAQUE, "user.other"] {
            assert_eq!(user_xattr(&p, name).expect("xattr"), None, "{name}");
        }
    }
}

#[test]
fn ownership_ignored() {
    let mut root_owned = Header::new(b"root-file", b'0');
    root_owned.uid = 0;
    root_owned.gid = 0;
    let mut other = Header::new(b"other-file", b'0');
    other.uid = 4242;
    other.gid = 4243;
    let bytes = Tar::new()
        .entry(&root_owned, b"x")
        .entry(&other, b"y")
        .pax(&[("uid", b"0"), ("gid", b"0"), ("uname", b"root")])
        .dir("d", 0o755)
        .finish();
    let (dir, _) = ok(&bytes);
    let me = meta(dir.path());
    for name in ["root-file", "other-file", "d"] {
        let m = meta(&dir.path().join(name));
        assert_eq!((m.uid(), m.gid()), (me.uid(), me.gid()), "{name}");
    }
}

// ---- Tar framing -----------------------------------------------------------

fn three_entries() -> Tar {
    let mut t = Tar::new();
    t.dir("d", 0o755)
        .file("d/f", 0o644, b"hello")
        .symlink("l", "d/f");
    t
}

#[test]
fn end_of_archive_forms() {
    for zeros in 0..=2 {
        let mut t = three_entries();
        t.zero_blocks(zeros);
        let bytes = t.unterminated();
        let (dir, stats) = ok(&bytes);
        assert_eq!(
            std::fs::read(dir.path().join("d/f")).expect("read"),
            b"hello",
            "{zeros}"
        );
        assert_eq!(stats.entries, 3);
    }
    // One zero block, then a non-zero block: refused.
    let mut t = three_entries();
    t.zero_blocks(1).file("late", 0o644, b"x");
    assert!(matches!(refused(&t.unterminated()).1, Error::Tar(_)));
    // One zero block, then part of a block.
    let mut t = three_entries();
    t.zero_blocks(1);
    let mut bytes = t.unterminated();
    bytes.extend_from_slice(&[0u8; 100]);
    assert!(matches!(refused(&bytes).1, Error::Tar(_) | Error::Read(_)));
    // Part of a header.
    let mut bytes = three_entries().unterminated();
    bytes.extend_from_slice(&[b'x'; 100]);
    assert!(refused(&bytes).1.to_string().contains("truncated"));
}

#[test]
fn trailing_bytes_after_end_hashed_not_extracted() {
    let mut t = three_entries();
    t.zero_blocks(2)
        .file("late", 0o644, b"x")
        .bytes
        .extend_from_slice(b"garbage");
    let bytes = t.unterminated();
    let (dir, stats) = ok(&bytes);
    assert!(!exists(&dir.path().join("late")));
    assert_eq!(stats.diff_id, Sha256::digest(&bytes));
    assert_eq!(stats.bytes, u64::try_from(bytes.len()).expect("fits"));
    assert_eq!(stats.entries, 3);
}

#[test]
fn archive_head_and_tail() {
    let block = vec![7u8; BLOCK];
    let mut t = Tar::new();
    t.pax(&[("path", b"first")])
        .file("ignored", 0o644, b"1")
        .file("empty", 0o644, b"")
        .file("one", 0o644, b"z")
        .file("exact", 0o644, &block);
    // The last file ends on a block boundary and the archive ends there.
    let bytes = t.unterminated();
    let (dir, stats) = ok(&bytes);
    let root = dir.path();
    assert_eq!(names(root), ["empty", "exact", "first", "one"]);
    assert_eq!(std::fs::read(root.join("empty")).expect("read"), b"");
    assert_eq!(std::fs::read(root.join("one")).expect("read"), b"z");
    assert_eq!(std::fs::read(root.join("exact")).expect("read"), block);
    assert_eq!(stats.diff_id, Sha256::digest(&bytes));
}

fn encodings(plain: &[u8]) -> [(Compression, Vec<u8>); 3] {
    [
        (Compression::None, plain.to_vec()),
        (Compression::Gzip, tarball::gzip(plain)),
        (Compression::Zstd, tarball::zstd(plain)),
    ]
}

#[test]
fn truncation_every_offset() {
    let plain = three_entries().finish();
    for (compression, bytes) in encodings(&plain) {
        let (_dir, full) = try_unpack(&bytes, compression);
        assert_eq!(
            full.expect("the whole stream unpacks").diff_id,
            Sha256::digest(&plain)
        );
        for cut in 0..bytes.len() {
            let (_dir, result) = try_unpack(&bytes[..cut], compression);
            // A plain tar cut at the end of an entry or after the first
            // zero block is a complete archive (end of archive by EOF, Go's
            // rules): nothing, the directory, the file with its data, all
            // three, all three plus one zero block. Every other cut is an
            // error, and every cut of a compressed stream is.
            let complete_plain = compression == Compression::None
                && [0, BLOCK, 3 * BLOCK, 4 * BLOCK, 5 * BLOCK].contains(&cut);
            match result {
                Ok(stats) => assert!(
                    complete_plain,
                    "{compression:?}: cut at {cut} accepted ({stats:?})"
                ),
                Err(_) => assert!(
                    !complete_plain,
                    "{compression:?}: complete archive cut at {cut} refused"
                ),
            }
        }
    }
}

#[test]
fn byte_flip_never_panics() {
    let plain = three_entries().finish();
    let expected = Sha256::digest(&plain);
    for (compression, bytes) in encodings(&plain) {
        // Bytes that do not reach the decoded stream: gzip's MTIME, XFL and
        // OS header fields and its CRC-32, which the reader does not check
        // because the diff_id covers every decoded byte (D5), and fields
        // that ruzstd does not read (measured: one byte in this fixture's
        // sequences section). The blob digest (PR 2) covers them on the
        // compressed side.
        let inert = |at: usize| match compression {
            Compression::None => false,
            Compression::Gzip => {
                (4..10).contains(&at) || (bytes.len() - 8..bytes.len() - 4).contains(&at)
            }
            Compression::Zstd => true,
        };
        for at in 0..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[at] ^= 0xff;
            let (dir, result) = try_unpack(&flipped, compression);
            if let Ok(stats) = result {
                // Everything else that is accepted hashes differently, so
                // the diff_id check refuses it.
                assert!(
                    stats.diff_id != expected || inert(at),
                    "{compression:?}: flip at {at} decoded to the original"
                );
                // The same diff_id means the same bytes, so the same tree.
                if stats.diff_id == expected {
                    let f = dir.path().join("d/f");
                    assert_eq!(
                        std::fs::read(f).expect("read"),
                        b"hello",
                        "{compression:?} {at}"
                    );
                }
            }
        }
    }
}

#[test]
fn checksum_forms() {
    // A name with bytes above 0x7f, so the signed and unsigned sums differ.
    for checksum in [Checksum::Unsigned, Checksum::Signed] {
        let mut h = Header::new("caf\u{e9}".as_bytes(), b'0');
        h.checksum = checksum;
        let bytes = Tar::new().entry(&h, b"x").finish();
        let (dir, _) = ok(&bytes);
        assert!(exists(&dir.path().join("caf\u{e9}")), "{checksum:?}");
    }
    let mut h = Header::new(b"x", b'0');
    h.checksum = Checksum::Wrong;
    let bytes = Tar::new().entry(&h, b"x").finish();
    assert!(matches!(refused(&bytes).1, Error::Tar(_)));
}

#[test]
fn magic_forms() {
    let mut gnu = Header::new(b"gnu", b'0');
    gnu.magic = Magic::Gnu;
    let bytes = Tar::new().entry(&gnu, b"x").finish();
    let (dir, _) = ok(&bytes);
    assert!(exists(&dir.path().join("gnu")));
    let mut v7 = Header::new(b"v7", b'0');
    v7.magic = Magic::V7;
    let bytes = Tar::new().entry(&v7, b"x").finish();
    assert!(matches!(refused(&bytes).1, Error::Tar(_)));
}

#[test]
fn base256_numbers() {
    let mut h = Header::new(b"big", b'0');
    h.size_base256 = true;
    let bytes = Tar::new().entry(&h, b"base-256 size").finish();
    let (dir, _) = ok(&bytes);
    assert_eq!(
        std::fs::read(dir.path().join("big")).expect("read"),
        b"base-256 size"
    );

    // A negative base-256 size or mtime: refused.
    let mut h = Header::new(b"neg", b'0');
    let mut raw = [0xffu8; 12];
    raw[11] = 0xfe;
    h.raw_size = Some(raw);
    let bytes = Tar::new().raw(&h, &[]).finish();
    assert!(matches!(refused(&bytes).1, Error::Tar(_)));
    let mut h = Header::new(b"neg-mtime", b'0');
    h.mtime = -5;
    let bytes = Tar::new().entry(&h, b"x").finish();
    assert!(matches!(refused(&bytes).1, Error::Tar(_)));
    // A negative base-256 number that fits the field's 64 bits once its
    // sign bit is ignored: refused for being negative, not for its range.
    let mut h = Header::new(b"dev", b'3');
    h.patches = vec![(329, vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb])];
    let bytes = Tar::new().entry(&h, &[]).finish();
    let (_dir, e) = refused(&bytes);
    assert!(e.to_string().contains("negative"), "{e}");
    // A base-256 size above u64.
    let mut h = Header::new(b"huge", b'0');
    let mut raw = [0u8; 12];
    raw[0] = 0x80;
    raw[2] = 1;
    h.raw_size = Some(raw);
    let bytes = Tar::new().raw(&h, &[]).finish();
    assert!(matches!(refused(&bytes).1, Error::Tar(_)));
}

#[test]
fn typeflag_rules() {
    for typeflag in *b"SZVMNAD89" {
        let h = Header::new(b"x", typeflag);
        let bytes = Tar::new().entry(&h, b"").finish();
        let (_dir, e) = refused(&bytes);
        assert!(matches!(e, Error::Tar(_)), "{}: {e}", char::from(typeflag));
    }
    let bytes = Tar::new()
        .pax(&[("GNU.sparse.major", b"1"), ("GNU.sparse.minor", b"0")])
        .file("x", 0o644, b"x")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Tar(_)));

    // `7` (contiguous) and NUL are regular files; NUL with a trailing slash
    // is a directory (Go's reader).
    let bytes = Tar::new()
        .entry(&Header::new(b"seven", b'7'), b"7")
        .entry(&Header::new(b"nul", 0), b"0")
        .entry(&Header::new(b"nuldir/", 0), b"")
        .finish();
    let (dir, _) = ok(&bytes);
    assert_eq!(std::fs::read(dir.path().join("seven")).expect("read"), b"7");
    assert_eq!(std::fs::read(dir.path().join("nul")).expect("read"), b"0");
    assert!(meta(&dir.path().join("nuldir")).is_dir());

    // Header-only types carry no data even when the size field says so.
    let mut h = Header::new(b"d", b'5');
    h.size = 600;
    let bytes = Tar::new().raw(&h, &[]).file("after", 0o644, b"x").finish();
    let (dir, _) = ok(&bytes);
    assert!(exists(&dir.path().join("after")));
}

#[test]
fn pax_global_header_ignored() {
    let bytes = Tar::new()
        .pax_global(&[
            ("path", b"evil"),
            ("mtime", b"1"),
            ("GNU.sparse.major", b"1"),
        ])
        .file("name", 0o644, b"x")
        .finish();
    let (dir, stats) = ok(&bytes);
    assert_eq!(names(dir.path()), ["name"]);
    assert_eq!(meta(&dir.path().join("name")).mtime(), MTIME);
    assert_eq!(stats.entries, 1);
}

#[test]
fn long_name_forms() {
    let long = format!("{}/{}", "a".repeat(120), "b".repeat(120));
    let link = "t".repeat(150);
    let mut prefixed = Header::new(b"c", b'0');
    prefixed.prefix = b"p/q".to_vec();
    let bytes = Tar::new()
        .pax(&[("path", long.as_bytes())])
        .file("short", 0o644, b"pax")
        .gnu_long(b'L', b"gnu/long/name")
        .file("short2", 0o644, b"gnu")
        .gnu_long(b'K', link.as_bytes())
        .symlink("gnulink", "ignored")
        .pax(&[("linkpath", b"paxtarget")])
        .symlink("paxlink", "ignored")
        // PAX wins over GNU when both are present (Go's order).
        .gnu_long(b'L', b"from-gnu")
        .pax(&[("path", b"from-pax")])
        .file("short3", 0o644, b"both")
        .entry(&prefixed, b"prefix")
        .finish();
    let (dir, _) = ok(&bytes);
    let root = dir.path();
    assert_eq!(std::fs::read(root.join(&long)).expect("pax"), b"pax");
    assert_eq!(
        std::fs::read(root.join("gnu/long/name")).expect("gnu"),
        b"gnu"
    );
    assert_eq!(
        std::fs::read_link(root.join("gnulink")).expect("K"),
        Path::new(&link)
    );
    assert_eq!(
        std::fs::read_link(root.join("paxlink")).expect("linkpath"),
        Path::new("paxtarget")
    );
    assert_eq!(std::fs::read(root.join("from-pax")).expect("both"), b"both");
    assert!(!exists(&root.join("from-gnu")));
    assert_eq!(
        std::fs::read(root.join("p/q/c")).expect("prefix"),
        b"prefix"
    );
    assert!(!exists(&root.join("short")));
}

fn pax_of_size(total: usize) -> Vec<u8> {
    // One comment record padded to make the body exactly `total` bytes.
    let mut value_len = total - 20;
    loop {
        let rec = tarball::pax_record("comment", &vec![b'c'; value_len]);
        match rec.len().cmp(&total) {
            std::cmp::Ordering::Equal => return rec,
            std::cmp::Ordering::Greater => value_len -= 1,
            std::cmp::Ordering::Less => value_len += 1,
        }
    }
}

#[test]
fn special_file_cap_inclusive() {
    let cap = usize::try_from(MIB).expect("fits");
    let h = Header::new(b"././@PaxHeader", b'x');
    let bytes = Tar::new()
        .entry(&h, &pax_of_size(cap))
        .file("f", 0o644, b"x")
        .finish();
    let (dir, _) = ok(&bytes);
    assert!(exists(&dir.path().join("f")));

    let bytes = Tar::new()
        .entry(&h, &pax_of_size(cap + 1))
        .file("f", 0o644, b"x")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Limit { .. }));

    let mut gnu = Header::new(b"././@LongLink", b'L');
    gnu.magic = Magic::Gnu;
    let bytes = Tar::new()
        .entry(&gnu, &vec![b'n'; cap + 1])
        .file("f", 0o644, b"x")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Limit { .. }));
    let g = Header::new(b"././@PaxHeader", b'g');
    let bytes = Tar::new()
        .entry(&g, &pax_of_size(cap + 1))
        .file("f", 0o644, b"x")
        .finish();
    assert!(matches!(refused(&bytes).1, Error::Limit { .. }));
}

#[test]
fn pax_record_framing() {
    for body in [
        &b"4 =\n"[..],   // empty key
        b"11 path=x\n",  // length does not match
        b"8 pathx\n",    // no '='
        b"x path=y\n",   // not a number
        b"3 a\n",        // shorter than the shortest record
        b"7 a=b\r",      // no newline
        b"7 a=b\n7 c=d", // the second record is cut
    ] {
        let h = Header::new(b"././@PaxHeader", b'x');
        let bytes = Tar::new().entry(&h, body).file("f", 0o644, b"x").finish();
        assert!(matches!(refused(&bytes).1, Error::Tar(_)), "{body:?}");
    }
    // PAX `size` overrides the header size.
    let mut h = Header::new(b"sized", b'0');
    h.raw_size = Some(*b"00000000000\0");
    let bytes = Tar::new().pax(&[("size", b"3")]).raw(&h, b"abc").finish();
    let (dir, _) = ok(&bytes);
    assert_eq!(
        std::fs::read(dir.path().join("sized")).expect("read"),
        b"abc"
    );
}

// ---- Decompression ---------------------------------------------------------

/// A reader that hands out at most `chunk` bytes per call and counts them.
struct Trickle<'a> {
    data: &'a [u8],
    chunk: usize,
    read: usize,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.chunk).min(self.data.len() - self.read);
        buf[..n].copy_from_slice(&self.data[self.read..self.read + n]);
        self.read += n;
        Ok(n)
    }
}

#[test]
fn gzip_bomb_stops_at_cap() {
    let cap = MIB;
    let layer_limits = Limits::new(cap, 1 << 34, 1 << 20, MIB, DEPTH).expect("limits");

    // Exactly the cap of zeros (an empty archive followed by zeros): passes.
    let exact = tarball::gzip(&vec![0u8; usize::try_from(cap).expect("fits")]);
    assert!(exact.len() < 5000, "about 1,000:1");
    let dir = TempDir::new("bomb-exact");
    let stats = unpack(
        &exact[..],
        Compression::Gzip,
        dir.path(),
        &mut Budget::new(layer_limits.clone()),
    )
    .expect("exactly the cap");
    assert_eq!(stats.bytes, cap);

    // 16 MiB of zeros, as 16 members of 1 MiB: refused at byte cap + 1,
    // long before the end of the compressed input.
    let bomb = exact.repeat(16);
    let mut source = Trickle {
        data: &bomb,
        chunk: 512,
        read: 0,
    };
    let dir = TempDir::new("bomb");
    let e = unpack(
        &mut source,
        Compression::Gzip,
        dir.path(),
        &mut Budget::new(layer_limits),
    )
    .expect_err("over the cap");
    assert!(matches!(e, Error::Limit { max, .. } if max == cap), "{e}");
    assert!(
        source.read < bomb.len() / 4,
        "decoding went on: {} of {} compressed bytes read",
        source.read,
        bomb.len()
    );
}

#[test]
fn gzip_and_zstd_layers_unpack() {
    let plain = three_entries().finish();
    for (compression, bytes) in encodings(&plain) {
        let mut source = Trickle {
            data: &bytes,
            chunk: 7,
            read: 0,
        };
        let dir = TempDir::new("codec");
        let stats = unpack(&mut source, compression, dir.path(), &mut budget()).expect("unpacks");
        assert_eq!(stats.diff_id, Sha256::digest(&plain), "{compression:?}");
        assert_eq!(stats.bytes, u64::try_from(plain.len()).expect("fits"));
        assert_eq!(
            std::fs::read(dir.path().join("d/f")).expect("read"),
            b"hello"
        );
    }
}

// ---- Limits ----------------------------------------------------------------

#[test]
fn limits_zero_refused() {
    assert!(Limits::new(0, 1, 1, 1, 1).is_err());
    assert!(Limits::new(1, 0, 1, 1, 1).is_err());
    assert!(Limits::new(1, 1, 0, 1, 1).is_err());
    assert!(Limits::new(1, 1, 1, 0, 1).is_err());
    assert!(Limits::new(1, 1, 1, 1, 0).is_err());
    assert!(Limits::new(1, 1, 1, 1, 1).is_ok());
}

#[test]
fn layer_bytes_cap_inclusive() {
    let plain = three_entries().finish();
    let len = u64::try_from(plain.len()).expect("fits");
    for (compression, bytes) in encodings(&plain) {
        let at_cap = Limits::new(len, 1 << 34, 1 << 20, MIB, DEPTH).expect("limits");
        let dir = TempDir::new("cap");
        unpack(
            &bytes[..],
            compression,
            dir.path(),
            &mut Budget::new(at_cap),
        )
        .expect("exactly the cap");
        let below = Limits::new(len - 1, 1 << 34, 1 << 20, MIB, DEPTH).expect("limits");
        let dir = TempDir::new("cap");
        let e = unpack(&bytes[..], compression, dir.path(), &mut Budget::new(below))
            .expect_err("one byte over");
        assert!(matches!(e, Error::Limit { .. }), "{compression:?}: {e}");
    }
}

#[test]
fn image_caps_inclusive() {
    let a = three_entries().finish();
    let b = Tar::new()
        .file("x", 0o644, b"x")
        .file("y", 0o644, b"y")
        .finish();
    let (a_len, b_len) = (a.len() as u64, b.len() as u64);

    let run = |limits: Limits| -> Result<(), Error> {
        let mut budget = Budget::new(limits);
        let d1 = TempDir::new("img");
        unpack(&a[..], Compression::None, d1.path(), &mut budget)?;
        let d2 = TempDir::new("img");
        unpack(&b[..], Compression::None, d2.path(), &mut budget)?;
        Ok(())
    };
    run(Limits::new(1 << 32, a_len + b_len, 5, MIB, DEPTH).expect("limits"))
        .expect("bytes at the cap");
    assert!(matches!(
        run(Limits::new(1 << 32, a_len + b_len - 1, 5, MIB, DEPTH).expect("limits")),
        Err(Error::Limit { .. })
    ));
    assert!(matches!(
        run(Limits::new(1 << 32, 1 << 34, 4, MIB, DEPTH).expect("limits")),
        Err(Error::Limit { .. })
    ));

    // The image limit stops a bomb in the stream, like the layer limit.
    let one = tarball::gzip(&vec![0u8; usize::try_from(MIB).expect("fits")]);
    let bomb = one.repeat(16);
    let mut budget = Budget::new(Limits::new(1 << 32, a_len + MIB, 5, MIB, DEPTH).expect("limits"));
    let d1 = TempDir::new("img");
    unpack(&a[..], Compression::None, d1.path(), &mut budget).expect("first layer");
    let mut source = Trickle {
        data: &bomb,
        chunk: 512,
        read: 0,
    };
    let d2 = TempDir::new("img");
    let e = unpack(&mut source, Compression::Gzip, d2.path(), &mut budget).expect_err("over");
    assert!(
        matches!(e, Error::Limit { max, .. } if max == a_len + MIB),
        "{e}"
    );
    assert!(
        source.read < bomb.len() / 4,
        "decoding went on: {}",
        source.read
    );
}

fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn image_caps_count_cached_layers() {
    let a = three_entries().finish();
    let b = Tar::new()
        .file("x", 0o644, b"x")
        .file("y", 0o644, b"y")
        .finish();
    let (a_id, b_id) = (Sha256::digest(&a), Sha256::digest(&b));
    let (a_len, b_len) = (a.len() as u64, b.len() as u64);
    let store = TempDir::new("cache");
    let cache = LayerCache::new(store.path()).expect("cache");
    cache
        .unpack(&a_id, Compression::None, &a[..], &mut budget())
        .expect("layer a");

    // A warm cache reaches the same verdict as a cold one: the cached layer
    // is charged from its sidecar.
    for (max_bytes, max_entries, accept) in [
        (a_len + b_len, 5, true),
        (a_len + b_len - 1, 5, false),
        (a_len + b_len, 4, false),
    ] {
        let mut warm =
            Budget::new(Limits::new(1 << 32, max_bytes, max_entries, MIB, DEPTH).expect("limits"));
        let cached = cache.cached(&a_id).expect("read").expect("a is cached");
        assert_eq!((cached.bytes, cached.entries), (a_len, 3));
        let warm_result = warm.charge(&cached).and_then(|()| {
            cache
                .unpack(&b_id, Compression::None, &b[..], &mut warm)
                .map(|_| ())
        });
        assert_eq!(
            warm_result.is_ok(),
            accept,
            "{max_bytes} {max_entries}: {warm_result:?}"
        );
        if !accept {
            assert!(matches!(warm_result, Err(Error::Limit { .. })));
            assert!(cache.cached(&b_id).expect("read").is_none());
        }
        // Remove b again so the next case starts from the same cache.
        let b_path = cache.layer_path(&b_id);
        if exists(&b_path) {
            make_writable(&b_path);
            std::fs::remove_dir_all(&b_path).expect("remove b");
            std::fs::remove_file(b_path.with_extension("stats")).expect("remove b's sidecar");
        }
    }
}

// ---- Layer cache (D8) -------------------------------------------------------

fn tmp_entries(store: &Path) -> Vec<String> {
    names(&store.join("tmp"))
}

#[test]
fn layer_commit_writes_sidecar() {
    let plain = Tar::new()
        .dir("ro", 0o555)
        .file("ro/f", 0o444, b"x")
        .device("dev", b'3', 1, 3)
        .finish();
    let id = Sha256::digest(&plain);
    let store = TempDir::new("commit");
    let cache = LayerCache::new(store.path()).expect("cache");
    assert!(cache.cached(&id).expect("read").is_none());
    let gz = tarball::gzip(&plain);
    let stats = cache
        .unpack(&id, Compression::Gzip, &gz[..], &mut budget())
        .expect("commit");
    let path = cache.layer_path(&id);
    assert_eq!(path, store.path().join("layers/sha256").join(hex(&id)));
    assert_eq!(mode(&path.join("ro")), 0o555);
    assert_eq!(stats.diff_id, id);
    assert_eq!(cache.cached(&id).expect("read"), Some(stats.clone()));
    let sidecar = std::fs::read_to_string(path.with_extension("stats")).expect("sidecar");
    assert_eq!(
        sidecar,
        format!("bytes {}\nentries 3\nskipped-devices 1\n", plain.len())
    );
    assert!(tmp_entries(store.path()).is_empty());

    // A second commit of the same layer (another store won the race) keeps
    // the first and discards its own tree.
    let again = cache
        .unpack(&id, Compression::None, &plain[..], &mut budget())
        .expect("again");
    assert_eq!(again, stats);
    assert!(tmp_entries(store.path()).is_empty());
}

#[test]
fn diff_id_mismatch_removes_tree() {
    let plain = Tar::new()
        .dir("z", 0o000)
        .dir("z/y", 0o000)
        .file("f", 0o000, b"x")
        .finish();
    let wrong = Sha256::digest(b"something else");
    let store = TempDir::new("mismatch");
    let cache = LayerCache::new(store.path()).expect("cache");
    let e = cache
        .unpack(&wrong, Compression::None, &plain[..], &mut budget())
        .expect_err("mismatch");
    assert!(matches!(e, Error::DiffId { .. }), "{e}");
    assert!(!exists(&cache.layer_path(&wrong)));
    assert!(!exists(&cache.layer_path(&wrong).with_extension("stats")));
    assert!(tmp_entries(store.path()).is_empty());

    // A failure in the middle of the stream cleans up too.
    let mut bad = Tar::new();
    bad.dir("z", 0o000).file("../x", 0o644, b"x");
    let bad = bad.finish();
    let e = cache
        .unpack(
            &Sha256::digest(&bad),
            Compression::None,
            &bad[..],
            &mut budget(),
        )
        .expect_err("refused");
    assert!(matches!(e, Error::Entry { .. }), "{e}");
    assert!(tmp_entries(store.path()).is_empty());
}

#[test]
fn corrupt_sidecar_is_an_error() {
    let plain = three_entries().finish();
    let id = Sha256::digest(&plain);
    let store = TempDir::new("sidecar");
    let cache = LayerCache::new(store.path()).expect("cache");
    cache
        .unpack(&id, Compression::None, &plain[..], &mut budget())
        .expect("commit");
    let sidecar: PathBuf = cache.layer_path(&id).with_extension("stats");
    for text in [
        "",
        "bytes 1\n",
        "bytes x\nentries 3\nskipped-devices 0\n",
        "bytes 1\nentries 3\nskipped-devices 0\nextra 1\n",
    ] {
        std::fs::write(&sidecar, text).expect("write");
        assert!(cache.cached(&id).is_err(), "{text:?}");
    }
}

/// Per-entry cost does not grow with the square of the depth: parents a
/// layer already verified are not walked again (the review measured
/// 407 ms per entry at depth 1,932 before). Relative to a shallow layer, so
/// the bound does not depend on the machine: quadratic cost makes the
/// deep entries about 90 times dearer, linear path resolution a few times.
#[test]
fn deep_entries_cost_is_not_quadratic() {
    fn per_entry(depth: usize) -> f64 {
        let prefix = vec!["a"; depth - 1].join("/");
        let entries = 60;
        let mut t = Tar::new();
        for i in 0..entries {
            t.pax(&[("path", format!("{prefix}/f{i}").as_bytes())])
                .file("x", 0o644, b"");
        }
        let bytes = t.finish();
        let dir = TempDir::new("depth");
        let start = std::time::Instant::now();
        // Its own depth limit: the test pins the walk, not the cap.
        let mut deep_budget = with_depth(1024);
        unpack(&bytes[..], Compression::None, dir.path(), &mut deep_budget).expect("unpacks");
        start.elapsed().as_secs_f64() / f64::from(entries)
    }
    // Warm up, then compare the median of three runs each.
    per_entry(8);
    let median = |depth: usize| {
        let mut v = [per_entry(depth), per_entry(depth), per_entry(depth)];
        v.sort_by(f64::total_cmp);
        v[1]
    };
    let (shallow, deep) = (median(8), median(512));
    assert!(
        deep < 15.0 * shallow,
        "depth 512 costs {:.3} ms per entry, depth 8 {:.3} ms",
        deep * 1e3,
        shallow * 1e3
    );
}

fn with_depth(max_depth: u64) -> Budget {
    Budget::new(Limits::new(1 << 32, 1 << 34, 1 << 20, MIB, max_depth).expect("limits"))
}

/// The path depth is capped, inclusive: the number of components after
/// normalization, whatever the entry's type (D7).
#[test]
fn depth_cap_inclusive() {
    let ok_cases = [
        Tar::new().file("a/b/c/d", 0o644, b"x").finish(),
        Tar::new().file("./a//b/./c/d/", 0o644, b"x").finish(),
        Tar::new().file("a/b/c/.wh.d", 0o644, b"").finish(),
        Tar::new()
            .dir("a/b/c/d", 0o755)
            .file("a/b/c/.wh..wh..opq", 0o644, b"")
            .finish(),
    ];
    for bytes in ok_cases {
        let dir = TempDir::new("depth-ok");
        unpack(
            &bytes[..],
            Compression::None,
            dir.path(),
            &mut with_depth(4),
        )
        .expect("depth 4");
    }
    let refused_cases = [
        Tar::new().file("a/b/c/d/e", 0o644, b"x").finish(),
        Tar::new().dir("a/b/c/d/e/", 0o755).finish(),
        Tar::new().file("a/b/c/d/.wh.e", 0o644, b"").finish(),
        Tar::new().symlink("a/b/c/d/e", "x").finish(),
        Tar::new()
            .file(".wh..wh.plnk/b/c/d/e", 0o644, b"x")
            .finish(),
    ];
    for bytes in refused_cases {
        let dir = TempDir::new("depth-refused");
        let e = unpack(
            &bytes[..],
            Compression::None,
            dir.path(),
            &mut with_depth(4),
        )
        .expect_err("depth 5");
        assert!(
            matches!(
                e,
                Error::Limit {
                    what: "path depth",
                    max: 4
                }
            ),
            "{e}"
        );
    }
}

/// Directories created for missing parents are inodes like any entry, so
/// they count toward the entry limits: one tar entry cannot create an
/// unbounded number of directories (D7).
#[test]
fn implicit_parents_count_as_entries() {
    let bytes = Tar::new()
        .file("a/b/c", 0o644, b"x")
        .dir("a", 0o755)
        .finish();
    let (_dir, stats) = ok(&bytes);
    assert_eq!(stats.entries, 4, "two tar entries and two created parents");

    let deep = Tar::new().file("1/2/3/4/5/6/7/8/9/f", 0o644, b"x").finish();
    let dir = TempDir::new("implicit");
    let tight = Limits::new(1 << 32, 1 << 34, 9, MIB, DEPTH).expect("limits");
    let e = unpack(
        &deep[..],
        Compression::None,
        dir.path(),
        &mut Budget::new(tight),
    )
    .expect_err("ten inodes");
    assert!(matches!(e, Error::Limit { .. }), "{e}");
    let dir = TempDir::new("implicit");
    let exact = Limits::new(1 << 32, 1 << 34, 10, MIB, DEPTH).expect("limits");
    unpack(
        &deep[..],
        Compression::None,
        dir.path(),
        &mut Budget::new(exact),
    )
    .expect("ten inodes");
}
