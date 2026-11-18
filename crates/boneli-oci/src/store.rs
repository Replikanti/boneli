//! The store (ADR-009, D8): the `ImageStore` adapter over the registry
//! client and the layer cache.
//!
//! Layout under the root, every directory `0o700`:
//!
//! - `blobs/sha256/<hex>`: the indexes, manifests and configs a pull read,
//!   each with `<hex>.type`, the `Content-Type` it was served with (empty
//!   for none), and the compressed layer blobs of layers not yet
//!   committed. A document is re-hashed on every read; a mismatch removes
//!   it and it is fetched again. A layer blob is removed once its layer is
//!   committed.
//! - `layers/sha256/<hex>` and `<hex>.stats`: the layer cache.
//!
//! Temporary names in both directories carry their owner (boot id, PID
//! and time namespaces, pid, start time); `open` removes those whose owner
//! is gone and leaves the rest.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use boneli_app::{ImageError, ImageRef, ImageStore, RootfsRef};
use boneli_https::{ConnectOptions, Roots, Sha256, TlsConfig};

use crate::dial::{Dial, TlsDial};
use crate::error::{Error, PullError, failed};
use crate::layers::{self, Judge, LayerCache, Liveness, Owner};
use crate::limits::{Budget, Limits};
use crate::manifest::{self, Descriptor, Document, ImageConfig};
use crate::reference::{Digest, Reference};
use crate::registry::{Client, Documents, FetchLimits, Fetched, Registry, Timeouts, select};

/// Uncompressed bytes of one layer: 4 GiB (D7).
pub const MAX_LAYER_BYTES: u64 = 4_294_967_296;
/// Uncompressed bytes of an image: 16 GiB (D7).
pub const MAX_IMAGE_BYTES: u64 = 17_179_869_184;
/// Tar entries of an image: 16 GiB / 16 KiB per inode (D7).
pub const MAX_IMAGE_ENTRIES: u64 = 1_048_576;
/// One PAX or GNU extension body: Go's `maxSpecialFileSize` (D7).
pub const MAX_SPECIAL_BYTES: u64 = 1_048_576;
/// Path components of an entry (D7).
pub const MAX_DEPTH: u64 = 128;
/// An index, manifest or config: the OCI distribution spec's 4 MB (D12).
pub const MAX_DOCUMENT_BYTES: usize = 4_194_304;
/// Nesting depth of a document (D12).
pub const MAX_DOCUMENT_DEPTH: usize = 16;
/// Values of a document (D12).
pub const MAX_DOCUMENT_VALUES: usize = 65_536;
/// A token response body (D12).
pub const MAX_TOKEN_BYTES: usize = 65_536;
/// A response head (D12).
pub const MAX_HEAD_BYTES: usize = 16_384;
/// Fields of a response head (D12).
pub const MAX_HEADERS: usize = 64;
/// Layers of a manifest: moby overlay2's `maxDepth` (D12).
pub const MAX_LAYERS: usize = 128;
/// A blob's descriptor size: the per-layer cap (D12).
pub const MAX_BLOB_BYTES: u64 = 4_294_967_296;
/// The descriptor sizes of a manifest's config and layers, summed: 16 GiB
/// plus 16 MiB (D12).
pub const MAX_PULL_BYTES: u64 = 17_196_646_400;
/// Each TCP connection attempt (D12).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The whole TLS handshake (D12).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Each read and write (D12).
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// The fixed part of a fetch's deadline (D12).
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(30);
/// The slowest transfer a fetch's deadline admits, in bytes per second
/// (D12).
pub const MIN_RATE: u64 = 1_048_576;

/// The longest `Content-Type` a kept document's `.type` file may hold: a
/// response head's limit.
const MAX_TYPE_BYTES: u64 = MAX_HEAD_BYTES as u64;

/// What a store pulls from and how: the registries, the limits and where
/// connections go.
pub struct StoreConfig {
    /// The allowlisted registries; an image name's host must be one of
    /// them (D10).
    pub registries: Vec<Registry>,
    /// The registry of an image name without a host.
    pub default_registry: Registry,
    /// The unpacking limits (D7).
    pub limits: Limits,
    /// The registry client's limits (D12).
    pub fetch: FetchLimits,
    /// The registry client's deadlines (D12).
    pub timeouts: Timeouts,
    /// Where connections go: [`TlsDial`] in production, built from the
    /// TLS config and the connect timeouts.
    pub dial: Box<dyn Dial + Send + Sync>,
}

impl StoreConfig {
    /// Docker Hub as the one and default registry, the limits and
    /// deadlines of ADR-009 (D7, D12), and connections through `dial`.
    pub fn new(dial: Box<dyn Dial + Send + Sync>) -> Result<StoreConfig, Error> {
        let document =
            boneli_json::Limits::new(MAX_DOCUMENT_BYTES, MAX_DOCUMENT_DEPTH, MAX_DOCUMENT_VALUES)
                .map_err(|_| Error::InvalidLimits("document"))?;
        Ok(StoreConfig {
            registries: vec![Registry::docker_hub()],
            default_registry: Registry::docker_hub(),
            limits: Limits::new(
                MAX_LAYER_BYTES,
                MAX_IMAGE_BYTES,
                MAX_IMAGE_ENTRIES,
                MAX_SPECIAL_BYTES,
                MAX_DEPTH,
            )?,
            fetch: FetchLimits::new(
                document,
                MAX_TOKEN_BYTES,
                MAX_HEAD_BYTES,
                MAX_HEADERS,
                MAX_LAYERS,
                MAX_BLOB_BYTES,
                MAX_PULL_BYTES,
            )?,
            timeouts: Timeouts::new(IO_TIMEOUT, SETUP_TIMEOUT, MIN_RATE)?,
            dial,
        })
    }

    /// [`StoreConfig::new`] over a [`TlsDial`] with `tls` and the connect
    /// timeouts of D12.
    pub fn production(tls: TlsConfig) -> Result<StoreConfig, Error> {
        let options = ConnectOptions::new(CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT, IO_TIMEOUT)
            .map_err(|_| Error::InvalidLimits("connect options"))?;
        StoreConfig::new(Box::new(TlsDial::new(tls, options)))
    }

    /// [`StoreConfig::production`] with the Mozilla roots of
    /// `webpki-roots` (ADR-005).
    pub fn mozilla() -> Result<StoreConfig, Error> {
        let tls = TlsConfig::new(Roots::mozilla())
            .map_err(|e| Error::InvalidRegistry(format!("TLS config: {e}")))?;
        StoreConfig::production(tls)
    }
}

impl std::fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreConfig")
            .field("registries", &self.registries)
            .field("default_registry", &self.default_registry)
            .field("limits", &self.limits)
            .field("fetch", &self.fetch)
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

/// The OCI image store: images pulled by digest from allowlisted
/// registries, unpacked one directory per layer (ADR-009).
///
/// Pulls are serialized by one mutex per store. Several stores, in one
/// process or several, may share a root: every write commits by a rename,
/// and two stores committing the same layer keep one tree (D8).
pub struct OciImageStore {
    root: PathBuf,
    cache: LayerCache,
    config: StoreConfig,
    lock: Mutex<()>,
}

impl std::fmt::Debug for OciImageStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciImageStore")
            .field("root", &self.root)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

// `own_uid`, `private_dir` and `check_ancestors` are copied into
// `boneli-store-fs` (`src/root.rs`, ADR-012 D1); a fix to one copy goes
// into the other until #66 extracts them.

/// The owner of the root and of this process: the uid of `/proc/self`,
/// which is this process's effective uid.
fn own_uid(at: &Path) -> Result<u32, Error> {
    let me = Path::new("/proc/self");
    fs::metadata(me).map(|m| m.uid()).map_err(|e| Error::Cache {
        path: at.to_path_buf(),
        source: e,
    })
}

/// The text rules of a root, before and after it is resolved: absolute,
/// no `.` or `..` component, UTF-8, and none of `,`, `:` and `\`, which
/// overlay mount options use as separators and escapes (ADR-007, D7).
/// `open` checks the existing ancestors of a missing root on its text
/// before it creates it, and `..` would make that text name an ancestor
/// other than the one creation resolves to (ADR-012, D1). The components
/// are split on the bytes: `Path::components` drops every `.` but a
/// leading one.
fn check_root_text(path: &Path) -> Result<(), Error> {
    let refuse = |reason| {
        Err(Error::Root {
            path: path.to_path_buf(),
            reason,
        })
    };
    if !path.is_absolute() {
        return refuse("must be an absolute path");
    }
    if path
        .as_os_str()
        .as_encoded_bytes()
        .split(|&b| b == b'/')
        .any(|c| c == b"." || c == b"..")
    {
        return refuse("must not have a `.` or `..` component");
    }
    let Some(text) = path.to_str() else {
        return refuse("must be UTF-8");
    };
    if text.contains([',', ':', '\\']) {
        return refuse("must not contain ',', ':' or '\\'");
    }
    Ok(())
}

fn cache_err(path: &Path, source: io::Error) -> Error {
    Error::Cache {
        path: path.to_path_buf(),
        source,
    }
}

/// Creates `dir` with mode `0o700` where it is missing.
fn private_dir(dir: &Path) -> Result<(), Error> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| cache_err(dir, e))
}

/// Checks `dir` and each of its ancestors the way sshd's `StrictModes`
/// checks a path: a directory, owned by root or by `uid`, and not writable
/// by its group or by others unless it is sticky. Anyone who can rename an
/// entry of an ancestor can swap the root after `open` and plant layers
/// that the store then hands out; in a sticky directory only an entry's
/// owner can rename it, and the next entry down is root's or the caller's.
/// The filesystem root is checked for its mode only: whoever owns it owns
/// every path on the host, and in a user namespace it shows the overflow
/// uid. `dir` must be resolved, so the walk sees no symlink.
fn check_ancestors(dir: &Path, uid: u32) -> Result<(), Error> {
    for at in dir.ancestors() {
        let refuse = |reason| {
            Err(Error::Root {
                path: at.to_path_buf(),
                reason,
            })
        };
        let meta = fs::symlink_metadata(at).map_err(|e| cache_err(at, e))?;
        if !meta.is_dir() {
            return refuse("an ancestor of the root must be a directory");
        }
        if at.parent().is_some() && meta.uid() != 0 && meta.uid() != uid {
            return refuse("an ancestor of the root must be owned by root or the caller");
        }
        if meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0 {
            return refuse(
                "an ancestor of the root must not be writable by its group or others unless it is sticky",
            );
        }
    }
    Ok(())
}

/// Removes every name in `dir` that carries an owner (D8) whose owner is
/// gone, as `judge` sees it, and returns how many it removed. Names of
/// live owners and of owners it cannot judge stay, and so does every name
/// that carries no owner. A name whose removal fails stays too, whatever
/// the error: it is a dot name, never read as a layer or a blob, so it
/// costs disk, while failing `open` for it would leave the store
/// unopenable until someone removed it by hand.
fn sweep(dir: &Path, judge: &Judge) -> Result<u64, Error> {
    let mut removed = 0;
    for entry in fs::read_dir(dir).map_err(|e| cache_err(dir, e))? {
        let entry = entry.map_err(|e| cache_err(dir, e))?;
        let name = entry.file_name();
        let Some(owner) = name.to_str().and_then(Owner::of_name) else {
            continue;
        };
        if owner.liveness(judge) != Liveness::Dead {
            continue;
        }
        // An error is another store's sweep that removed it first, or a
        // tree that cannot be removed by path (one deeper than `PATH_MAX`
        // under this root's path, left by a process that reached the root
        // through a shorter one).
        if layers::remove_tree_bounded(&entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Checks that the filesystem under `dir` holds the overlay format of D1:
/// a 0:0 character device made by `make_whiteout`, and the opaque marker
/// read back through `user_xattr`. Both probes are removed again.
fn probe_overlay_format(dir: &Path) -> Result<(), Error> {
    let unsupported = |detail: String| Error::Unsupported {
        path: dir.to_path_buf(),
        detail,
    };
    let whiteout = dir.join(layers::owned_name(".probe-wh-")?);
    let made = boneli_sys::make_whiteout(&whiteout);
    let seen = fs::symlink_metadata(&whiteout);
    let _ = fs::remove_file(&whiteout);
    made.map_err(|e| unsupported(format!("a 0:0 whiteout cannot be made: {e}")))?;
    match seen {
        Ok(m) if m.file_type().is_char_device() && m.rdev() == 0 => {}
        Ok(_) => {
            return Err(unsupported(
                "a whiteout is not a 0:0 character device".into(),
            ));
        }
        Err(e) => return Err(unsupported(format!("a whiteout cannot be read back: {e}"))),
    }

    let opaque = dir.join(layers::owned_name(".probe-opq-")?);
    DirBuilder::new()
        .mode(0o700)
        .create(&opaque)
        .map_err(|e| cache_err(&opaque, e))?;
    let marked = boneli_sys::mark_opaque(&opaque)
        .and_then(|()| boneli_sys::user_xattr(&opaque, "user.overlay.opaque"));
    let _ = fs::remove_dir(&opaque);
    match marked {
        Ok(Some(value)) if value == b"y" => Ok(()),
        Ok(other) => Err(unsupported(format!(
            "the opaque marker reads back as {other:?}"
        ))),
        Err(e) => Err(unsupported(format!(
            "user.* extended attributes cannot be set: {e}"
        ))),
    }
}

impl OciImageStore {
    /// Opens the store at `root`:
    ///
    /// - `root` must be absolute, without a `.` or `..` component, UTF-8
    ///   and free of `,`, `:` and `\`; it is created with mode `0o700`
    ///   where it is missing, once its existing ancestors pass the check
    ///   below, resolved, and checked again;
    /// - it must be a directory owned by the caller with no group or other
    ///   permission bits;
    /// - each of its ancestors must be owned by root or the caller and not
    ///   writable by its group or others unless it is sticky (sshd's
    ///   `StrictModes`), so no one else can swap the root after `open`;
    /// - temporary names whose owner is gone are removed (D8);
    /// - its filesystem must keep exact names (D8) and hold the overlay
    ///   format (0:0 whiteouts, `user.*` xattrs, D1), or `open` fails
    ///   here rather than in a pull.
    pub fn open(root: &Path, config: StoreConfig) -> Result<OciImageStore, Error> {
        check_root_text(root)?;
        let uid = own_uid(root)?;
        if fs::symlink_metadata(root).is_err() {
            // Nothing is created under an ancestor that fails the check.
            if let Some(existing) = root
                .ancestors()
                .skip(1)
                .find(|a| fs::symlink_metadata(a).is_ok())
            {
                let existing = existing
                    .canonicalize()
                    .map_err(|e| cache_err(existing, e))?;
                check_ancestors(&existing, uid)?;
            }
            private_dir(root)?;
        }
        let resolved = root.canonicalize().map_err(|e| cache_err(root, e))?;
        check_root_text(&resolved)?;
        let refuse = |reason| Error::Root {
            path: resolved.clone(),
            reason,
        };
        let meta = fs::metadata(&resolved).map_err(|e| cache_err(&resolved, e))?;
        if !meta.is_dir() {
            return Err(refuse("must be a directory"));
        }
        if meta.uid() != uid {
            return Err(refuse("must be owned by the caller"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(refuse("must have no group or other permission bits"));
        }
        if let Some(parent) = resolved.parent() {
            check_ancestors(parent, uid)?;
        }

        let blobs = resolved.join("blobs").join("sha256");
        let layer_dir = resolved.join("layers").join("sha256");
        private_dir(&blobs)?;
        private_dir(&layer_dir)?;
        let judge = Judge::current()?;
        sweep(&blobs, &judge)?;
        sweep(&layer_dir, &judge)?;
        let cache = LayerCache::new(&resolved)?;
        probe_overlay_format(&layer_dir)?;
        Ok(OciImageStore {
            root: resolved,
            cache,
            config,
            lock: Mutex::new(()),
        })
    }

    /// The resolved root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("blobs").join("sha256").join(digest.hex())
    }

    /// The layer directories of `rootfs`, bottom first, the order
    /// `boneli_sys::Root.layers` takes. A `diff_id` that appears more than
    /// once keeps only its topmost position, which leaves the merged view
    /// unchanged. Every layer must be in the cache.
    pub fn layers(&self, rootfs: &RootfsRef) -> Result<Vec<PathBuf>, ImageError> {
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let config = self.image_config(rootfs)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut top_down = Vec::with_capacity(config.diff_ids.len());
        for diff_id in config.diff_ids.iter().rev() {
            if !seen.insert(*diff_id) {
                continue;
            }
            match self.cache.cached(diff_id.bytes()) {
                Ok(Some(_)) => top_down.push(self.cache.layer_path(diff_id.bytes())),
                Ok(None) => {
                    return Err(failed_image(format!(
                        "{} needs layer {diff_id}, which is not in the store",
                        rootfs.as_str()
                    )));
                }
                Err(e) => return Err(failed_image(e.to_string())),
            }
        }
        top_down.reverse();
        Ok(top_down)
    }

    /// The image config of `rootfs`: platform, `diff_ids` and the runtime
    /// fields the sandbox starts the image with.
    pub fn config(&self, rootfs: &RootfsRef) -> Result<ImageConfig, ImageError> {
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.image_config(rootfs)
    }

    fn image_config(&self, rootfs: &RootfsRef) -> Result<ImageConfig, ImageError> {
        let unknown = || failed_image(format!("unknown rootfs {:?}", rootfs.as_str()));
        let digest = Digest::parse(rootfs.as_str()).map_err(|_| unknown())?;
        let mut kept = Kept { store: self };
        let fetched = kept.get(&digest).map_err(to_image)?.ok_or_else(unknown)?;
        let document = manifest::parse_document(
            &fetched.bytes,
            fetched.content_type.as_deref(),
            self.config.fetch.document_limits(),
            self.config.fetch.max_layers(),
        )
        .map_err(|e| failed_image(format!("manifest {digest}: {e}")))?;
        let Document::Manifest(m) = document else {
            return Err(unknown());
        };
        let config = kept
            .get(&m.config.digest)
            .map_err(to_image)?
            .ok_or_else(|| {
                failed_image(format!(
                    "{} has no config {} in the store",
                    rootfs.as_str(),
                    m.config.digest
                ))
            })?;
        manifest::parse_config(&config.bytes, self.config.fetch.document_limits())
            .map_err(|e| failed_image(format!("config {}: {e}", m.config.digest)))
    }

    fn pull_locked(&self, image: &ImageRef) -> Result<RootfsRef, PullError> {
        let reference = Reference::parse(&image.name, &image.digest, &image.platform)?;
        let registry = select(
            &self.config.registries,
            &self.config.default_registry,
            &reference,
        )?;
        let mut client = Client::new(
            registry,
            &*self.config.dial,
            &self.config.fetch,
            &self.config.timeouts,
        );
        let resolved = client.resolve_with(&reference, &mut Kept { store: self })?;
        let mut budget = Budget::new(self.config.limits.clone());
        let repo = reference.repository();
        for (layer, diff_id) in resolved
            .manifest
            .layers
            .iter()
            .zip(&resolved.config.diff_ids)
        {
            self.layer(
                &mut client,
                repo,
                &layer.descriptor,
                layer.compression,
                diff_id,
                &mut budget,
            )?;
        }
        Ok(RootfsRef::new(format!(
            "sha256:{}",
            resolved.manifest_digest.hex()
        )))
    }

    /// Makes sure the layer `diff_id` is committed and charges it to
    /// `budget`: from the cache, or unpacked from its blob, which is
    /// fetched unless a copy that hashes to its digest is on disk. The blob
    /// is read through the descriptor that checked it, so another store
    /// that commits the same layer and removes the blob meanwhile changes
    /// nothing here. The blob is removed once the layer is committed.
    fn layer(
        &self,
        client: &mut Client<'_>,
        repo: &crate::reference::Repository,
        descriptor: &Descriptor,
        compression: crate::unpack::Compression,
        diff_id: &Digest,
        budget: &mut Budget,
    ) -> Result<(), PullError> {
        if let Some(stats) = self.cache.cached(diff_id.bytes()).map_err(pull_err)? {
            return budget.charge(&stats).map_err(pull_err);
        }
        let blob = self.blob_path(&descriptor.digest);
        let file = match kept_blob(&blob, descriptor)? {
            Some(file) => file,
            None => client.get_blob(repo, descriptor, &blob)?,
        };
        self.cache
            .unpack(
                diff_id.bytes(),
                compression,
                BufReader::with_capacity(1 << 16, file),
                budget,
            )
            .map_err(|e| failed(format!("layer {diff_id} (blob {}): {e}", descriptor.digest)))?;
        match fs::remove_file(&blob) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(pull_err(cache_err(&blob, e))),
        }
    }
}

/// The blob on disk at `path`, open at its start, if it is exactly
/// `descriptor`: its size and digest. A copy that is not is removed.
fn kept_blob(path: &Path, descriptor: &Descriptor) -> Result<Option<File>, PullError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(pull_err(cache_err(path, e))),
    };
    let ok = hash_file(&mut file, descriptor.size)
        .map_err(|e| pull_err(cache_err(path, e)))?
        .is_some_and(|d| d == descriptor.digest);
    if !ok {
        let _ = fs::remove_file(path);
        return Ok(None);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| pull_err(cache_err(path, e)))?;
    Ok(Some(file))
}

/// The digest of `file` if it has exactly `size` bytes.
fn hash_file(file: &mut File, size: u64) -> io::Result<Option<Digest>> {
    let mut hash = Sha256::new();
    let mut reader = file.take(size.saturating_add(1));
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if let Some(chunk) = buf.get(..n) {
            hash.update(chunk);
        }
    }
    Ok((total == size).then(|| Digest::from_bytes(hash.finish())))
}

/// The documents a pull reads, kept under `blobs/sha256/` (D8).
struct Kept<'s> {
    store: &'s OciImageStore,
}

impl Documents for Kept<'_> {
    fn get(&mut self, digest: &Digest) -> Result<Option<Fetched>, PullError> {
        let path = self.store.blob_path(digest);
        let type_path = type_path(&path);
        let bytes = match read_capped(
            &path,
            self.store.config.fetch.document_limits().max_bytes() as u64,
        ) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(e) => return Err(pull_err(cache_err(&path, e))),
        };
        let content_type = match read_capped(&type_path, MAX_TYPE_BYTES) {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(None),
            Err(e) => return Err(pull_err(cache_err(&type_path, e))),
        };
        if Digest::of(&bytes) != *digest {
            // A corrupted copy: removed, and fetched again.
            let _ = fs::remove_file(&path);
            return Ok(None);
        }
        let content_type = match String::from_utf8(content_type) {
            Ok(t) if t.is_empty() => None,
            Ok(t) => Some(t),
            Err(_) => {
                let _ = fs::remove_file(&path);
                return Ok(None);
            }
        };
        Ok(Some(Fetched {
            bytes,
            content_type,
        }))
    }

    fn put(&mut self, digest: &Digest, fetched: &Fetched) -> Result<(), PullError> {
        let path = self.store.blob_path(digest);
        let dir = path
            .parent()
            .ok_or_else(|| failed(format!("{} has no parent", path.display())))?;
        let content_type = fetched.content_type.as_deref().unwrap_or_default();
        // The type first: a document on disk always has its type.
        write_durably(dir, &type_path(&path), content_type.as_bytes()).map_err(pull_err)?;
        write_durably(dir, &path, &fetched.bytes).map_err(pull_err)
    }
}

/// `<blob>.type`.
fn type_path(blob: &Path) -> PathBuf {
    let mut name = blob.as_os_str().to_owned();
    name.push(".type");
    PathBuf::from(name)
}

/// The bytes of `path`, `None` if it is missing or longer than `max`.
fn read_capped(path: &Path, max: u64) -> io::Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= max).then_some(bytes))
}

/// Writes `bytes` to a temporary name in `dir`, syncs it, renames it to
/// `dest` and syncs `dir`.
fn write_durably(dir: &Path, dest: &Path, bytes: &[u8]) -> Result<(), Error> {
    let temp = dir.join(layers::temporary_name()?);
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            f.sync_all()
        })
        .and_then(|()| fs::rename(&temp, dest))
        .and_then(|()| File::open(dir).and_then(|d| d.sync_all()));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|e| cache_err(dest, e))
}

fn pull_err(e: Error) -> PullError {
    failed(e.to_string())
}

fn failed_image(detail: String) -> ImageError {
    ImageError::Failed { detail }
}

fn to_image(e: PullError) -> ImageError {
    match e {
        PullError::NotFound(_) => ImageError::NotFound,
        PullError::Failed(detail) => ImageError::Failed { detail },
    }
}

impl ImageStore for OciImageStore {
    /// Pulls `image` (ADR-009): documents from the store when it has them,
    /// re-hashed, and from the registry otherwise; only missing layers are
    /// fetched and unpacked. The handle is `sha256:<hex>` of the
    /// platform's manifest, the same across processes and restarts.
    fn pull(&self, image: &ImageRef) -> Result<RootfsRef, ImageError> {
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.pull_locked(image).map_err(to_image)
    }
}
