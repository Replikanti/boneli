//! One layer stream into an empty directory (ADR-009, D1-D3).
//!
//! The layer keeps the overlay format that `boneli_sys::Root.layers`
//! mounts: a whiteout is a 0:0 character device and an opaque directory
//! carries `user.overlay.opaque=y`.
//!
//! The tar stream is the only adversary: the directory is private to the
//! store and only this process writes it while it unpacks. Nothing is ever
//! followed. Every path is checked lexically (no `..`, no NUL), and every
//! parent is checked component by component with `symlink_metadata` before
//! anything is created under it. Files are created with `O_EXCL` after the
//! old entry is removed, devices with `mknod`, xattrs with `lsetxattr`, and
//! hard links with `linkat` without `AT_SYMLINK_FOLLOW`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, FileTimes, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use boneli_https::Sha256;

use crate::error::{Error, carry, from_io};
use crate::gzip::GzipReader;
use crate::limits::Budget;
use crate::tar::{Entry, Kind, Mtime, Reader};
use crate::zstd::ZstdReader;

/// The compression of a layer blob, from its media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// A plain tar (`application/vnd.oci.image.layer.v1.tar`).
    None,
    /// gzip (`+gzip`, and Docker's `rootfs.diff.tar.gzip`).
    Gzip,
    /// zstd (`+zstd`).
    Zstd,
}

/// What unpacking a layer found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerStats {
    /// SHA-256 of the uncompressed stream, every byte included: the
    /// layer's `diff_id` if the bytes are the right ones.
    pub diff_id: [u8; 32],
    /// Uncompressed bytes.
    pub bytes: u64,
    /// Tar entries, skipped ones included; PAX and GNU extension headers
    /// are not entries.
    pub entries: u64,
    /// Character and block devices that were not written (D3): the sandbox
    /// mounts its own `/dev`, and unprivileged `mknod` refuses them.
    pub skipped_devices: u64,
}

/// The mode bits a layer keeps: permissions and sticky. Setuid and setgid
/// are dropped, because a setuid file owned by the runner user would let
/// other local users run it as that user (D3).
const MODE_MASK: u32 = 0o1777;

/// The mode of a directory this unpacker creates without an entry for it
/// (a missing parent, or the layer root), as Docker does.
const IMPLICIT_DIR_MODE: u32 = 0o755;

/// Directories are `0o700` while the layer is written, so that a read-only
/// directory can be filled; their final modes are set at the end.
const WORKING_DIR_MODE: u32 = 0o700;

const OPAQUE_MARKER: &[u8] = b".wh..wh..opq";
const WHITEOUT_PREFIX: &[u8] = b".wh.";
const AUFS_META_PREFIX: &[u8] = b".wh..wh.";

/// Unpacks the layer `source`, compressed as `compression`, into the empty
/// directory `dest`, charging `budget`. On error `dest` is left as it is;
/// the caller removes it.
pub fn unpack(
    source: impl Read,
    compression: Compression,
    dest: &Path,
    budget: &mut Budget,
) -> Result<LayerStats, Error> {
    let decoded: Box<dyn Read + '_> = match compression {
        Compression::None => Box::new(source),
        Compression::Gzip => Box::new(GzipReader::new(source)),
        Compression::Zstd => Box::new(ZstdReader::new(source)),
    };
    let image_room = budget.limits().max_image_bytes() - budget.bytes();
    let counted = Counted {
        inner: decoded,
        hash: Sha256::new(),
        bytes: 0,
        max_layer: budget.limits().max_layer_bytes(),
        max_image: budget.limits().max_image_bytes(),
        image_room,
    };
    let mut reader = Reader::new(counted, budget.limits().max_special_bytes());
    let mut layer = Layer::new(dest);
    while let Some(entry) = reader.next_entry()? {
        layer.entries += 1;
        budget.check_entries(layer.entries)?;
        layer.entry(entry, &mut reader)?;
    }
    // Bytes after the end of the archive are hashed and counted, never
    // extracted (Go's reader stops at the end marker too).
    let mut counted = reader.into_inner();
    io::copy(&mut counted, &mut io::sink()).map_err(from_io)?;
    layer.finish()?;

    let bytes = budget.check_bytes(counted.bytes)?;
    let entries = budget.check_entries(layer.entries)?;
    let stats = LayerStats {
        diff_id: counted.hash.finish(),
        bytes: counted.bytes,
        entries: layer.entries,
        skipped_devices: layer.skipped_devices,
    };
    budget.charge_totals(bytes, entries);
    Ok(stats)
}

/// The decoded stream: hashed, counted and capped while it is read, so a
/// decompression bomb stops at the first byte over a limit.
struct Counted<R> {
    inner: R,
    hash: Sha256,
    bytes: u64,
    max_layer: u64,
    max_image: u64,
    /// What the image limit leaves for this layer.
    image_room: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let chunk = buf.get(..n).unwrap_or(&[]);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if self.bytes > self.max_layer {
            return Err(carry(Error::Limit {
                what: "uncompressed layer size",
                max: self.max_layer,
            }));
        }
        if self.bytes > self.image_room {
            return Err(carry(Error::Limit {
                what: "uncompressed image size",
                max: self.max_image,
            }));
        }
        self.hash.update(chunk);
        Ok(n)
    }
}

/// The final metadata of a directory, applied deepest first at the end.
struct DirMeta {
    mode: u32,
    mtime: Option<Mtime>,
}

struct Layer<'a> {
    root: &'a Path,
    /// Directories by their path relative to the root (`""` is the root).
    dirs: BTreeMap<Vec<u8>, DirMeta>,
    entries: u64,
    skipped_devices: u64,
}

fn show(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

fn refuse(path: &[u8], reason: &'static str) -> Error {
    Error::Entry {
        path: show(path),
        reason,
    }
}

/// The components of an archive path: a leading `/` and `.` components are
/// dropped and `//` collapses. A `..` component anywhere is refused, and so
/// is a NUL byte. An empty result is the layer root.
fn components(path: &[u8]) -> Result<Vec<&[u8]>, Error> {
    if path.contains(&0) {
        return Err(refuse(path, "NUL in the path"));
    }
    let mut out = Vec::new();
    for c in path.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => return Err(refuse(path, "`..` in the path")),
            c => out.push(c),
        }
    }
    Ok(out)
}

fn join(components: &[&[u8]]) -> Vec<u8> {
    components.join(&b'/')
}

fn system_time(t: Mtime) -> Option<SystemTime> {
    let nanos = Duration::from_nanos(u64::from(t.nanos));
    let base = if t.secs >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(t.secs.unsigned_abs()))?
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(t.secs.unsigned_abs()))?
    };
    base.checked_add(nanos)
}

impl<'a> Layer<'a> {
    fn new(root: &'a Path) -> Layer<'a> {
        let mut dirs = BTreeMap::new();
        dirs.insert(
            Vec::new(),
            DirMeta {
                mode: IMPLICIT_DIR_MODE,
                mtime: None,
            },
        );
        Layer {
            root,
            dirs,
            entries: 0,
            skipped_devices: 0,
        }
    }

    fn host(&self, rel: &[u8]) -> PathBuf {
        self.root.join(OsStr::from_bytes(rel))
    }

    fn write_err(rel: &[u8], source: io::Error) -> Error {
        Error::Write {
            path: show(rel),
            source,
        }
    }

    fn sys_err(rel: &[u8], source: boneli_sys::Error) -> Error {
        Error::Sys {
            path: show(rel),
            source,
        }
    }

    /// The entry at `rel`, not following a symlink; `None` if there is
    /// none. Any other error (`ENAMETOOLONG`) is an error.
    fn lstat(&self, rel: &[u8]) -> Result<Option<fs::Metadata>, Error> {
        match fs::symlink_metadata(self.host(rel)) {
            Ok(m) => Ok(Some(m)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Self::write_err(rel, e)),
        }
    }

    /// Makes every parent of `comps` a real directory, component by
    /// component: a missing one is created, a whiteout of this layer is
    /// replaced (the real entry wins), and a symlink or any other entry is
    /// refused, so nothing is ever written through a link.
    fn parents(&mut self, entry: &[u8], comps: &[&[u8]]) -> Result<(), Error> {
        for i in 1..comps.len() {
            let rel = join(&comps[..i]);
            match self.lstat(&rel)? {
                Some(m) if m.file_type().is_dir() => {}
                Some(m) if m.file_type().is_symlink() => {
                    return Err(refuse(entry, "a parent directory is a symlink"));
                }
                Some(m) if m.file_type().is_char_device() && m.rdev() == 0 => {
                    fs::remove_file(self.host(&rel)).map_err(|e| Self::write_err(&rel, e))?;
                    self.mkdir(&rel)?;
                }
                Some(_) => return Err(refuse(entry, "a parent is not a directory")),
                None => self.mkdir(&rel)?,
            }
        }
        Ok(())
    }

    /// Creates the directory `rel` with the working mode and records the
    /// implicit final mode, which a later entry for it replaces.
    fn mkdir(&mut self, rel: &[u8]) -> Result<(), Error> {
        fs::DirBuilder::new()
            .mode(WORKING_DIR_MODE)
            .create(self.host(rel))
            .map_err(|e| Self::write_err(rel, e))?;
        self.dirs.insert(
            rel.to_vec(),
            DirMeta {
                mode: IMPLICIT_DIR_MODE,
                mtime: None,
            },
        );
        Ok(())
    }

    /// Removes whatever is at `rel`, a whole directory tree included (the
    /// later entry wins). Directories are still in their working mode, so
    /// the removal cannot fail on permissions.
    fn remove(&mut self, rel: &[u8]) -> Result<(), Error> {
        let Some(m) = self.lstat(rel)? else {
            return Ok(());
        };
        let host = self.host(rel);
        if m.file_type().is_dir() {
            fs::remove_dir_all(&host).map_err(|e| Self::write_err(rel, e))?;
            let mut prefix = rel.to_vec();
            prefix.push(b'/');
            self.dirs
                .retain(|k, _| k.as_slice() != rel && !k.starts_with(&prefix));
        } else {
            fs::remove_file(&host).map_err(|e| Self::write_err(rel, e))?;
        }
        Ok(())
    }

    fn entry<R: Read>(&mut self, e: Entry, reader: &mut Reader<R>) -> Result<(), Error> {
        let comps = components(&e.path)?;
        let Some((&name, parent)) = comps.split_last() else {
            // The layer root: mode only.
            if e.kind != Kind::Dir {
                return Err(refuse(&e.path, "the layer root must be a directory"));
            }
            self.dirs.insert(
                Vec::new(),
                DirMeta {
                    mode: e.mode & MODE_MASK,
                    mtime: None,
                },
            );
            return Ok(());
        };
        // aufs metadata at the root (`.wh..wh.plnk`, ...) is skipped with
        // everything under it, as moby does; only the opaque marker counts.
        if let Some(first) = comps.first() {
            if first.starts_with(AUFS_META_PREFIX) && *first != OPAQUE_MARKER {
                return Ok(());
            }
        }
        if parent.iter().any(|c| c.starts_with(WHITEOUT_PREFIX)) {
            return Err(refuse(&e.path, "a whiteout name as a parent directory"));
        }
        // A whiteout is decided by its name, whatever its type.
        if name.starts_with(WHITEOUT_PREFIX) {
            return self.whiteout(&e.path, parent, name);
        }
        self.parents(&e.path, &comps)?;
        let rel = join(&comps);
        match e.kind {
            Kind::Dir => self.dir(&rel, &e),
            Kind::File => self.file(&rel, &e, reader),
            Kind::Symlink => {
                self.remove(&rel)?;
                std::os::unix::fs::symlink(OsStr::from_bytes(&e.link), self.host(&rel))
                    .map_err(|err| Self::write_err(&rel, err))
            }
            Kind::HardLink => self.hard_link(&rel, &e),
            Kind::Char if e.devmajor == 0 && e.devminor == 0 => {
                // The file Docker's overlay2 driver writes for a whiteout.
                self.remove(&rel)?;
                boneli_sys::make_whiteout(&self.host(&rel)).map_err(|err| Self::sys_err(&rel, err))
            }
            Kind::Char | Kind::Block => {
                self.skipped_devices += 1;
                Ok(())
            }
            Kind::Fifo => {
                self.remove(&rel)?;
                let host = self.host(&rel);
                boneli_sys::make_fifo(&host, e.mode).map_err(|err| Self::sys_err(&rel, err))?;
                // The umask applied to mknod; set the exact mode. The FIFO
                // was just created by this process in a private directory.
                fs::set_permissions(&host, Permissions::from_mode(e.mode & MODE_MASK))
                    .map_err(|err| Self::write_err(&rel, err))
            }
        }
    }

    fn whiteout(&mut self, path: &[u8], parent: &[&[u8]], name: &[u8]) -> Result<(), Error> {
        if name == OPAQUE_MARKER {
            if parent.is_empty() {
                // What overlayfs does with an opaque lower root is not
                // pinned by any test, so it is not written.
                return Err(refuse(path, "an opaque marker at the layer root"));
            }
            let mut comps = parent.to_vec();
            comps.push(name);
            self.parents(path, &comps)?;
            let dir = join(parent);
            return boneli_sys::mark_opaque(&self.host(&dir)).map_err(|e| Self::sys_err(&dir, e));
        }
        let target = &name[WHITEOUT_PREFIX.len()..];
        if matches!(target, b"" | b"." | b"..") {
            return Err(refuse(path, "an invalid whiteout name"));
        }
        let mut comps = parent.to_vec();
        comps.push(target);
        self.parents(path, &comps)?;
        let rel = join(&comps);
        // A whiteout hides lower layers only; a real entry of this layer
        // wins in either order (OCI image spec).
        if self.lstat(&rel)?.is_some() {
            return Ok(());
        }
        boneli_sys::make_whiteout(&self.host(&rel)).map_err(|e| Self::sys_err(&rel, e))
    }

    fn dir(&mut self, rel: &[u8], e: &Entry) -> Result<(), Error> {
        match self.lstat(rel)? {
            // A directory over a directory merges; the later entry's
            // metadata wins (moby).
            Some(m) if m.file_type().is_dir() => {}
            _ => {
                self.remove(rel)?;
                self.mkdir(rel)?;
            }
        }
        self.dirs.insert(
            rel.to_vec(),
            DirMeta {
                mode: e.mode & MODE_MASK,
                mtime: Some(e.mtime),
            },
        );
        Ok(())
    }

    fn file<R: Read>(
        &mut self,
        rel: &[u8],
        e: &Entry,
        reader: &mut Reader<R>,
    ) -> Result<(), Error> {
        self.remove(rel)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.host(rel))
            .map_err(|err| Self::write_err(rel, err))?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut left = e.size;
        while left > 0 {
            let n = reader.read_body(&mut buf)?;
            if n == 0 {
                return Err(Error::Tar("truncated archive"));
            }
            file.write_all(buf.get(..n).unwrap_or(&[]))
                .map_err(|err| Self::write_err(rel, err))?;
            left -= u64::try_from(n).unwrap_or(left);
        }
        // Mode and time through the open descriptor, so a mode of 0 does
        // not lock the writer out.
        set_times(&file, e.mtime).map_err(|err| Self::write_err(rel, err))?;
        file.set_permissions(Permissions::from_mode(e.mode & MODE_MASK))
            .map_err(|err| Self::write_err(rel, err))
    }

    fn hard_link(&mut self, rel: &[u8], e: &Entry) -> Result<(), Error> {
        let target = components(&e.link)?;
        if target.is_empty() {
            return Err(refuse(&e.path, "a hard link to the layer root"));
        }
        let target_rel = join(&target);
        if target_rel == rel {
            return Err(refuse(&e.path, "a hard link to itself"));
        }
        for i in 1..target.len() {
            match self.lstat(&join(&target[..i]))? {
                Some(m) if m.file_type().is_dir() => {}
                Some(m) if m.file_type().is_symlink() => {
                    return Err(refuse(&e.path, "a hard link target crosses a symlink"));
                }
                _ => return Err(refuse(&e.path, "a hard link target is missing")),
            }
        }
        match self.lstat(&target_rel)? {
            None => return Err(refuse(&e.path, "a hard link target is missing")),
            Some(m) if m.file_type().is_dir() => {
                return Err(refuse(&e.path, "a hard link target is a directory"));
            }
            Some(m) if m.file_type().is_char_device() => {
                return Err(refuse(&e.path, "a hard link target is a whiteout"));
            }
            Some(_) => {}
        }
        self.remove(rel)?;
        // linkat without AT_SYMLINK_FOLLOW: a symlink target is linked
        // itself, never followed.
        fs::hard_link(self.host(&target_rel), self.host(rel))
            .map_err(|err| Self::write_err(rel, err))
    }

    /// Sets every directory's final mode and time, deepest first: in
    /// reverse path order every directory comes after everything under it.
    fn finish(&mut self) -> Result<(), Error> {
        for (rel, meta) in self.dirs.iter().rev() {
            let host = self.host(rel);
            // Every recorded directory is one this unpacker created or
            // merged; the lstat makes sure no symlink took its place.
            match self.lstat(rel)? {
                Some(m) if m.file_type().is_dir() => {}
                _ => return Err(Self::write_err(rel, io::Error::other("not a directory"))),
            }
            let dir = File::open(&host).map_err(|e| Self::write_err(rel, e))?;
            let is_dir = dir
                .metadata()
                .map_err(|e| Self::write_err(rel, e))?
                .is_dir();
            if !is_dir {
                return Err(Self::write_err(rel, io::Error::other("not a directory")));
            }
            if let Some(t) = meta.mtime {
                set_times(&dir, t).map_err(|e| Self::write_err(rel, e))?;
            }
            dir.set_permissions(Permissions::from_mode(meta.mode))
                .map_err(|e| Self::write_err(rel, e))?;
        }
        Ok(())
    }
}

fn set_times(file: &File, t: Mtime) -> io::Result<()> {
    let t = system_time(t).ok_or_else(|| io::Error::other("mtime out of range"))?;
    file.set_times(FileTimes::new().set_modified(t))
}
