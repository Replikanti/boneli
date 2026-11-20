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
//! - `locks/owners/<token>`: one owner lock file per process that wrote
//!   into the root, held shared while its store lives (ADR-025, D1).
//! - `locks/sha256/<hex>`: the lock file of the layer `<hex>`, held shared
//!   by every pull and lease that uses the layer (ADR-025, D2).
//!
//! Temporary names in both directories carry their owner (boot id, PID
//! and time namespaces, pid, start time); `open` removes those whose owner
//! is gone, by its owner lock or, without one, by `/proc`, and leaves the
//! rest.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use boneli_app::{ImageError, ImageRef, ImageStore, RootfsRef};
use boneli_https::{ConnectOptions, Dial, Roots, Sha256, TlsConfig, TlsDial};

use crate::error::{Error, PullError, failed, root_err};
use crate::layers::{self, Judge, LayerCache, LayerPin, Liveness, Owner};
use crate::lease::Lease;
use crate::limits::{Budget, Limits};
use crate::lock::{self, Exclusive};
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

/// This store's rule on the text of its root, as given, as it would be
/// created and as resolved; `boneli-private-dir` applies the shared rules
/// around it (ADR-021). UTF-8, and none of `,`, `:` and `\`, which overlay
/// mount options use as separators and escapes (ADR-007, D7).
fn overlay_text_rule(path: &Path) -> Result<(), &'static str> {
    let Some(text) = path.to_str() else {
        return Err("must be UTF-8");
    };
    if text.contains([',', ':', '\\']) {
        return Err("must not contain ',', ':' or '\\'");
    }
    Ok(())
}

fn cache_err(path: &Path, source: io::Error) -> Error {
    Error::Cache {
        path: path.to_path_buf(),
        source,
    }
}

/// Removes the names in `dirs` that carry an owner (ADR-009, D8) whose
/// owner is gone, then the owner lock files no name needs any more
/// (ADR-025, D1). The names are grouped by owner, and each owner is judged
/// once:
///
/// - Its lock file `owners/<token>` exists and an exclusive `try_lock`
///   gets it: the owner is gone, in whatever namespace or boot it ran.
///   Its names are removed, and the lock file is unlinked, still locked,
///   once every one of them is gone; otherwise it stays, and the next
///   judge tries again.
/// - The lock is held: the owner is alive, and its names stay.
/// - There is no lock file: the names come from a build before ADR-025,
///   and the `/proc` rule of ADR-009 D8 decides through `judge`, as it did.
/// - The lock path is not a regular file, or cannot be read: nothing is
///   concluded, and the names stay (fail closed).
///
/// Then every lock file in `owners/` named by a token that no name carries
/// is removed when its exclusive lock can be taken: an owner that left no
/// name and is gone. Names that carry no owner stay, in both places.
///
/// A name whose removal fails stays too, whatever the error: it is a dot
/// name, never read as a layer or a blob, so it costs disk, while failing
/// `open` for it would leave the store unopenable until someone removed it
/// by hand. An error is another store's sweep that removed it first, or a
/// tree that cannot be removed by path (one deeper than `PATH_MAX` under
/// this root's path, left by a process that reached the root through a
/// shorter one).
fn sweep(dirs: &[&Path], owners: &Path, judge: &Judge) -> Result<(), Error> {
    let mut by_owner: BTreeMap<String, (Owner, Vec<PathBuf>)> = BTreeMap::new();
    for dir in dirs {
        for entry in fs::read_dir(dir).map_err(|e| cache_err(dir, e))? {
            let entry = entry.map_err(|e| cache_err(dir, e))?;
            let name = entry.file_name();
            let Some(owner) = name.to_str().and_then(Owner::of_name) else {
                continue;
            };
            by_owner
                .entry(owner.token())
                .or_insert_with(|| (owner, Vec::new()))
                .1
                .push(entry.path());
        }
    }
    for (token, (owner, names)) in &by_owner {
        match lock::try_exclusive_existing(&owners.join(token)) {
            Ok(Exclusive::Held(held)) => {
                if remove_all(names) {
                    let _ = held.remove();
                }
            }
            Ok(Exclusive::Missing) if owner.liveness(judge) == Liveness::Dead => {
                remove_all(names);
            }
            Ok(Exclusive::Missing | Exclusive::Busy) | Err(_) => {}
        }
    }
    for entry in fs::read_dir(owners).map_err(|e| cache_err(owners, e))? {
        let entry = entry.map_err(|e| cache_err(owners, e))?;
        let name = entry.file_name();
        let Some(token) = name.to_str().filter(|t| Owner::of_token(t).is_some()) else {
            continue;
        };
        if by_owner.contains_key(token) {
            continue;
        }
        if let Ok(Exclusive::Held(held)) = lock::try_exclusive_existing(&entry.path()) {
            let _ = held.remove();
        }
    }
    Ok(())
}

/// Removes every path in `names`, each one tried even after a failure,
/// and tells whether all of them are gone.
fn remove_all(names: &[PathBuf]) -> bool {
    let mut all = true;
    for name in names {
        if layers::remove_tree_bounded(name).is_err() {
            all = false;
        }
    }
    all
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
    ///   below, at the path that check saw, which must pass these text
    ///   rules too; then it is resolved and checked again (ADR-021);
    /// - it must be a directory owned by the caller with no group or other
    ///   permission bits;
    /// - each of its ancestors must be owned by root or the caller and not
    ///   writable by its group or others unless it is sticky (sshd's
    ///   `StrictModes`), so no one else can swap the root after `open`;
    /// - this process's owner lock is taken (ADR-025, D1), then temporary
    ///   names whose owner is gone are removed, and so are the owner lock
    ///   files no name needs any more (D8; ADR-025, D1);
    /// - its filesystem must keep exact names (D8) and hold the overlay
    ///   format (0:0 whiteouts, `user.*` xattrs, D1), or `open` fails
    ///   here rather than in a pull.
    pub fn open(root: &Path, config: StoreConfig) -> Result<OciImageStore, Error> {
        let resolved =
            boneli_private_dir::prepare_root(root, &overlay_text_rule).map_err(root_err)?;

        let blobs = resolved.join("blobs").join("sha256");
        let layer_dir = resolved.join("layers").join("sha256");
        let owners = layers::owners_dir(&resolved);
        for dir in [
            &blobs,
            &layer_dir,
            &owners,
            &layers::layer_locks_dir(&resolved),
        ] {
            boneli_private_dir::create(dir).map_err(root_err)?;
        }
        // The owner lock first, so this store's own names, the case probes
        // included, are never judged dead by another store's sweep
        // (ADR-025, D1).
        let cache = LayerCache::new(&resolved)?;
        let judge = Judge::current()?;
        sweep(&[&blobs, &layer_dir], &owners, &judge)?;
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

    /// Pins the layers of `rootfs` and returns them as a [`Lease`]: the
    /// layer directories bottom first, the order `boneli_sys::Root.layers`
    /// takes, with a `diff_id` that appears more than once only at its
    /// topmost position, which leaves the merged view unchanged, and the
    /// image config. Every layer is locked first and then checked to be
    /// committed (ADR-025, D2); a missing one is `Failed`, names the layer
    /// and keeps no lock. A lease does not take the store's pull mutex, so
    /// it never waits for a pull. The caller holds it from before the
    /// layers are mounted until the sandbox is gone.
    pub fn lease(&self, rootfs: &RootfsRef) -> Result<Lease, ImageError> {
        let config = self.image_config(rootfs)?;
        let pins = self
            .pin_all(&config.diff_ids)
            .map_err(|e| failed_image(format!("{}: {e}", rootfs.as_str())))?;
        for diff_id in pins.keys() {
            match self.cache.cached(diff_id.bytes()) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(failed_image(format!(
                        "{} needs layer {diff_id}, which is not in the store; pull the image again",
                        rootfs.as_str()
                    )));
                }
                Err(e) => return Err(failed_image(e.to_string())),
            }
        }
        Ok(self.leased(rootfs.clone(), config, pins))
    }

    /// Pulls `image` like [`ImageStore::pull`] and hands the pins the pull
    /// took to a [`Lease`], so no other store can remove a layer between
    /// the pull and the sandbox (ADR-025, D2). The lease is built from the
    /// manifest and config the pull holds in memory.
    pub fn pull_leased(&self, image: &ImageRef) -> Result<Lease, ImageError> {
        let _held = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.pull_locked(image).map_err(to_image)
    }

    /// One pin for each distinct layer of `diff_ids`, all taken within one
    /// `LOCK_WAIT` (ADR-025, D3): a removal that holds a layer longer fails
    /// the pull or lease with `LockBusy` instead of stalling it, and every
    /// pull queued behind it on the store's mutex, without end.
    fn pin_all(&self, diff_ids: &[Digest]) -> Result<BTreeMap<Digest, LayerPin>, Error> {
        let deadline = Instant::now() + lock::LOCK_WAIT;
        let mut pins = BTreeMap::new();
        for diff_id in diff_ids {
            if !pins.contains_key(diff_id) {
                pins.insert(*diff_id, self.cache.pin_until(diff_id.bytes(), deadline)?);
            }
        }
        Ok(pins)
    }

    /// The lease of `rootfs` with `config` over `pins`, which hold every
    /// layer of `config`.
    fn leased(
        &self,
        rootfs: RootfsRef,
        config: ImageConfig,
        pins: BTreeMap<Digest, LayerPin>,
    ) -> Lease {
        let mut seen = BTreeSet::new();
        let mut layers: Vec<PathBuf> = config
            .diff_ids
            .iter()
            .rev()
            .filter(|diff_id| seen.insert(**diff_id))
            .map(|diff_id| self.cache.layer_path(diff_id.bytes()))
            .collect();
        layers.reverse();
        Lease::new(rootfs, layers, config, pins.into_values().collect())
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

    fn pull_locked(&self, image: &ImageRef) -> Result<Lease, PullError> {
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
        // Every layer is pinned before the cache is checked and before any
        // layer blob is requested, so no other store removes a layer this
        // pull is about to use (ADR-025, D2).
        let pins = self.pin_all(&resolved.config.diff_ids).map_err(pull_err)?;
        let mut budget = Budget::new(self.config.limits.clone());
        let repo = reference.repository();
        for (layer, diff_id) in resolved
            .manifest
            .layers
            .iter()
            .zip(&resolved.config.diff_ids)
        {
            let pin = pins
                .get(diff_id)
                .ok_or_else(|| failed(format!("layer {diff_id} is not pinned")))?;
            self.layer(
                &mut client,
                repo,
                &layer.descriptor,
                layer.compression,
                pin,
                &mut budget,
            )?;
        }
        let rootfs = RootfsRef::new(format!("sha256:{}", resolved.manifest_digest.hex()));
        Ok(self.leased(rootfs, resolved.config, pins))
    }

    /// Makes sure the layer `pin` pins is committed and charges it to
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
        pin: &LayerPin,
        budget: &mut Budget,
    ) -> Result<(), PullError> {
        let diff_id = Digest::from_bytes(*pin.diff_id());
        if let Some(stats) = self.cache.cached(pin.diff_id()).map_err(pull_err)? {
            return budget.charge(&stats).map_err(pull_err);
        }
        let blob = self.blob_path(&descriptor.digest);
        let file = match kept_blob(&blob, descriptor)? {
            Some(file) => file,
            None => client.get_blob(repo, descriptor, &blob)?,
        };
        self.cache
            .unpack(
                pin,
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
    ///
    /// The pins the pull took are released when it returns; a caller that
    /// starts a sandbox from the image takes [`OciImageStore::pull_leased`]
    /// or [`OciImageStore::lease`] instead (ADR-025, D2).
    fn pull(&self, image: &ImageRef) -> Result<RootfsRef, ImageError> {
        self.pull_leased(image).map(|lease| lease.rootfs().clone())
    }
}
