//! Images with real tar layers on the fake Docker Hub, for the store, the
//! contract and the host tests.

use std::time::Duration;

use boneli_oci::{OciImageStore, StoreConfig, Timeouts};

use super::registry::{Fake, Hub, descriptor, digest_of, entry, index, manifest, media};
use super::tarball::{Tar, gzip};

/// A layer: its blob as served, its media type and its diff_id.
#[derive(Clone, Debug)]
pub struct Layer {
    /// The blob.
    pub blob: Vec<u8>,
    /// The media type.
    pub media_type: &'static str,
    /// `sha256:<hex>` of the uncompressed tar.
    pub diff_id: String,
}

impl Layer {
    /// A plain tar layer.
    pub fn tar(bytes: Vec<u8>) -> Layer {
        Layer {
            diff_id: digest_of(&bytes),
            blob: bytes,
            media_type: media::TAR,
        }
    }

    /// A gzip layer.
    pub fn gzip(bytes: Vec<u8>) -> Layer {
        Layer {
            diff_id: digest_of(&bytes),
            blob: gzip(&bytes),
            media_type: media::GZIP,
        }
    }

    /// A layer with one file `name` holding `data`.
    pub fn file(name: &str, data: &[u8]) -> Layer {
        Layer::tar(Tar::new().file(name, 0o644, data).finish())
    }
}

/// What [`push`] put on the hub.
#[derive(Clone, Debug)]
pub struct Pushed {
    /// The index digest, the one an `ImageRef` names.
    pub index: String,
    /// The platform manifest's digest, which the store's `RootfsRef` names.
    pub manifest: String,
    /// The config's digest.
    pub config: String,
    /// The layer blobs' digests, bottom first.
    pub blobs: Vec<String>,
}

/// Pushes an image for `linux/amd64` with these layers and the config's
/// runtime object `runtime` (JSON, or empty for none) to `repo`, under an
/// index that lists only that platform.
pub fn push(hub: &mut Hub, repo: &str, layers: &[Layer], runtime: &str) -> Pushed {
    let mut descriptors = Vec::new();
    let mut blobs = Vec::new();
    let mut ids = Vec::new();
    for layer in layers {
        let digest = hub.blob(repo, &layer.blob);
        descriptors.push(descriptor(layer.media_type, &digest, layer.blob.len()));
        blobs.push(digest);
        ids.push(format!("\"{}\"", layer.diff_id));
    }
    let runtime = if runtime.is_empty() {
        String::new()
    } else {
        format!(r#","config":{runtime}"#)
    };
    let config = format!(
        r#"{{"architecture":"amd64","os":"linux"{runtime},"rootfs":{{"type":"layers","diff_ids":[{}]}}}}"#,
        ids.join(",")
    )
    .into_bytes();
    let config_digest = hub.blob(repo, &config);
    let manifest_bytes = manifest(
        &descriptor(media::CONFIG, &config_digest, config.len()),
        &descriptors,
    );
    let manifest_digest = hub.document(repo, media::MANIFEST, &manifest_bytes);
    let index_bytes = index(&[entry(
        media::MANIFEST,
        &manifest_digest,
        manifest_bytes.len(),
        Some(("linux", "amd64", None)),
    )]);
    let index_digest = hub.document(repo, media::INDEX, &index_bytes);
    Pushed {
        index: index_digest,
        manifest: manifest_digest,
        config: config_digest,
        blobs,
    }
}

/// The store configuration of ADR-009 over `fake`, with short deadlines
/// for tests.
pub fn config(fake: &Fake) -> StoreConfig {
    let mut config = StoreConfig::new(Box::new(fake.clone())).expect("config");
    config.timeouts =
        Timeouts::new(Duration::from_secs(5), Duration::from_secs(10), 1 << 20).expect("timeouts");
    config
}

/// Opens a store at `root` over `fake`.
pub fn open(root: &std::path::Path, fake: &Fake) -> OciImageStore {
    OciImageStore::open(root, config(fake)).expect("open the store")
}

/// The blob requests among `seen` that carried a token, by digest (each
/// fetch first gets a `401` without one).
pub fn blob_requests(seen: &[super::registry::Seen]) -> Vec<String> {
    seen.iter()
        .filter(|s| s.header("authorization").is_some())
        .filter_map(|s| s.target.rsplit_once("/blobs/").map(|(_, d)| d.to_owned()))
        .collect()
}

/// The manifest requests among `seen` that carried a token, by digest.
pub fn manifest_requests(seen: &[super::registry::Seen]) -> Vec<String> {
    seen.iter()
        .filter(|s| s.header("authorization").is_some())
        .filter_map(|s| {
            s.target
                .rsplit_once("/manifests/")
                .map(|(_, d)| d.to_owned())
        })
        .collect()
}
