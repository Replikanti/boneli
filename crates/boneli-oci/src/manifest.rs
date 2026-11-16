//! Image indexes, manifests and configs, parsed with `boneli_json::parse`
//! (ADR-009, D9, D12).
//!
//! The document kind comes from its `mediaType` field, or from the
//! `Content-Type` of the response when the field is absent; both present
//! and different refuses the document, and so does a document with both
//! `manifests` and `layers`. Refused outright: schema 1, a nested index,
//! unknown media types, foreign and nondistributable layers, layers with
//! `urls`, and `size` values that are not unsigned integers.

use crate::error::{PullError, failed};
use crate::reference::{Digest, Platform};
use crate::unpack::Compression;

/// The OCI image index.
pub(crate) const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// The OCI image manifest.
pub(crate) const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// Docker's manifest list, the index of the Docker formats.
pub(crate) const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
/// Docker's image manifest, schema 2.
pub(crate) const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// The `Accept` field of a manifest request: the four kinds above.
pub(crate) const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

/// Docker's schema 1 manifests, refused by name.
const SCHEMA1: [&str; 2] = [
    "application/vnd.docker.distribution.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v1+prettyjws",
];

/// The config media types.
const CONFIGS: [&str; 2] = [
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
];

/// The layer media types that are read, and how each is compressed.
const LAYERS: [(&str, Compression); 4] = [
    ("application/vnd.oci.image.layer.v1.tar", Compression::None),
    (
        "application/vnd.oci.image.layer.v1.tar+gzip",
        Compression::Gzip,
    ),
    (
        "application/vnd.oci.image.layer.v1.tar+zstd",
        Compression::Zstd,
    ),
    (
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        Compression::Gzip,
    ),
];

/// A content descriptor: what to fetch and how many bytes it has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// The media type, as written.
    pub media_type: String,
    /// The digest of the content.
    pub digest: Digest,
    /// The exact size of the content in bytes.
    pub size: u64,
}

/// An entry of an index: a descriptor and the platform it is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The manifest.
    pub descriptor: Descriptor,
    /// `(os, architecture, variant)`, if the entry has a platform.
    pub platform: Option<(String, String, Option<String>)>,
}

/// An image index (or a Docker manifest list).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    /// The media type that decided the kind.
    pub media_type: String,
    /// The entries, in order.
    pub manifests: Vec<Entry>,
}

/// A layer of a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    /// The compressed blob.
    pub descriptor: Descriptor,
    /// How the blob is compressed, from its media type.
    pub compression: Compression,
}

/// An image manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// The media type that decided the kind.
    pub media_type: String,
    /// The config blob.
    pub config: Descriptor,
    /// The layers, bottom first.
    pub layers: Vec<Layer>,
}

/// An index or a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Document {
    /// An image index.
    Index(Index),
    /// An image manifest.
    Manifest(Manifest),
}

/// What the store reads of an image config: its platform, the `diff_id`
/// of each layer and the runtime fields of its `config` object, which the
/// sandbox (#8) and the environment builder (#32) start the image with.
/// Absent runtime fields are empty; `null` is absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImageConfig {
    /// The operating system.
    pub os: String,
    /// The architecture.
    pub architecture: String,
    /// The variant, if any.
    pub variant: Option<String>,
    /// The digest of each uncompressed layer, bottom first.
    pub diff_ids: Vec<Digest>,
    /// `config.User`: `user`, `uid`, `user:group` or `uid:gid`, as written.
    pub user: Option<String>,
    /// `config.Env`: `NAME=value` entries, in order.
    pub env: Vec<String>,
    /// `config.Entrypoint`.
    pub entrypoint: Vec<String>,
    /// `config.Cmd`.
    pub cmd: Vec<String>,
    /// `config.WorkingDir`.
    pub working_dir: Option<String>,
}

type Object = boneli_json::Object;

/// Parses an index or a manifest. `content_type` is the response's
/// `Content-Type`; its parameters are dropped and it is compared in
/// lowercase.
pub(crate) fn parse_document(
    bytes: &[u8],
    content_type: Option<&str>,
    limits: &boneli_json::Limits,
    max_layers: usize,
) -> Result<Document, String> {
    let value = boneli_json::parse(bytes, limits).map_err(|e| e.to_string())?;
    let object = value.as_object().ok_or("not a JSON object")?;
    let schema = object
        .get("schemaVersion")
        .and_then(|v| v.as_number())
        .and_then(|n| n.as_u64());
    if schema != Some(2) {
        return Err("schemaVersion is not 2 (schema 1 is refused)".into());
    }
    let field = match object.get("mediaType") {
        None => None,
        Some(v) => Some(v.as_str().ok_or("mediaType is not a string")?),
    };
    let header = content_type.map(|ct| {
        ct.split(';')
            .next()
            .unwrap_or_default()
            .trim_matches([' ', '\t'])
            .to_ascii_lowercase()
    });
    let media_type = match (field, header.as_deref()) {
        (Some(f), Some(h)) if f != h => {
            return Err(format!(
                "mediaType {f:?} differs from the Content-Type {h:?}"
            ));
        }
        (Some(f), _) => f,
        (None, Some(h)) => h,
        (None, None) => return Err("no mediaType and no Content-Type".into()),
    };
    if object.contains_key("manifests") && object.contains_key("layers") {
        return Err("a document with both manifests and layers".into());
    }
    match media_type {
        OCI_INDEX | DOCKER_LIST => Ok(Document::Index(Index {
            media_type: media_type.to_owned(),
            manifests: entries(object)?,
        })),
        OCI_MANIFEST | DOCKER_MANIFEST => Ok(Document::Manifest(manifest(
            object, media_type, max_layers,
        )?)),
        t if SCHEMA1.contains(&t) => Err("schema 1 manifests are refused".into()),
        t => Err(format!("unknown media type {t:?}")),
    }
}

fn entries(object: &Object) -> Result<Vec<Entry>, String> {
    let list = object
        .get("manifests")
        .and_then(|v| v.as_array())
        .ok_or("an index without a manifests array")?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        let entry = item.as_object().ok_or("an index entry is not an object")?;
        let platform = match entry.get("platform") {
            None => None,
            Some(p) => {
                let p = p.as_object().ok_or("an entry platform is not an object")?;
                let os = string(p, "os")?.ok_or("an entry platform without os")?;
                let arch =
                    string(p, "architecture")?.ok_or("an entry platform without architecture")?;
                Some((os, arch, string(p, "variant")?))
            }
        };
        out.push(Entry {
            descriptor: descriptor(entry)?,
            platform,
        });
    }
    Ok(out)
}

fn manifest(object: &Object, media_type: &str, max_layers: usize) -> Result<Manifest, String> {
    let config = descriptor(
        object
            .get("config")
            .and_then(|v| v.as_object())
            .ok_or("a manifest without a config object")?,
    )?;
    if !CONFIGS.contains(&config.media_type.as_str()) {
        return Err(format!("unknown config media type {:?}", config.media_type));
    }
    let list = object
        .get("layers")
        .and_then(|v| v.as_array())
        .ok_or("a manifest without a layers array")?;
    if list.len() > max_layers {
        return Err(format!(
            "{} layers, more than the limit of {max_layers}",
            list.len()
        ));
    }
    let mut layers = Vec::with_capacity(list.len());
    for item in list {
        let layer = item.as_object().ok_or("a layer is not an object")?;
        let descriptor = descriptor(layer)?;
        let t = descriptor.media_type.as_str();
        let compression = LAYERS
            .iter()
            .find(|(name, _)| *name == t)
            .map(|(_, c)| *c)
            .ok_or_else(|| {
                if t.contains("foreign") || t.contains("nondistributable") {
                    format!("foreign or nondistributable layer {t:?}")
                } else {
                    format!("unknown layer media type {t:?}")
                }
            })?;
        if layer.contains_key("urls") {
            return Err("a layer with urls (fetched from elsewhere) is refused".into());
        }
        layers.push(Layer {
            descriptor,
            compression,
        });
    }
    Ok(Manifest {
        media_type: media_type.to_owned(),
        config,
        layers,
    })
}

fn descriptor(object: &Object) -> Result<Descriptor, String> {
    let media_type = string(object, "mediaType")?.ok_or("a descriptor without mediaType")?;
    let digest = string(object, "digest")?.ok_or("a descriptor without digest")?;
    let digest = Digest::parse(&digest).map_err(|e| e.detail().to_owned())?;
    let size = object
        .get("size")
        .ok_or("a descriptor without size")?
        .as_number()
        .filter(|n| n.is_integer())
        .and_then(|n| n.as_u64())
        .ok_or("a descriptor size that is not an unsigned 64-bit integer")?;
    Ok(Descriptor {
        media_type,
        digest,
        size,
    })
}

/// The string field `key`, `None` if absent, an error if not a string.
fn string(object: &Object, key: &str) -> Result<Option<String>, String> {
    match object.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| format!("{key} is not a string")),
    }
}

/// Parses an image config.
pub(crate) fn parse_config(
    bytes: &[u8],
    limits: &boneli_json::Limits,
) -> Result<ImageConfig, String> {
    let value = boneli_json::parse(bytes, limits).map_err(|e| e.to_string())?;
    let object = value.as_object().ok_or("not a JSON object")?;
    let os = string(object, "os")?.ok_or("a config without os")?;
    let architecture = string(object, "architecture")?.ok_or("a config without architecture")?;
    let variant = string(object, "variant")?;
    let rootfs = object
        .get("rootfs")
        .and_then(|v| v.as_object())
        .ok_or("a config without a rootfs object")?;
    if string(rootfs, "type")?.as_deref() != Some("layers") {
        return Err("rootfs.type is not layers".into());
    }
    let ids = rootfs
        .get("diff_ids")
        .and_then(|v| v.as_array())
        .ok_or("a config without rootfs.diff_ids")?;
    let mut diff_ids = Vec::with_capacity(ids.len());
    for id in ids {
        let id = id.as_str().ok_or("a diff_id is not a string")?;
        diff_ids.push(Digest::parse(id).map_err(|e| e.detail().to_owned())?);
    }
    let runtime = match object.get("config") {
        None => None,
        Some(v) if v.is_null() => None,
        Some(v) => Some(v.as_object().ok_or("config is not an object")?),
    };
    let text = |key: &str| -> Result<Option<String>, String> {
        match runtime.and_then(|r| r.get(key)) {
            None => Ok(None),
            Some(v) if v.is_null() => Ok(None),
            Some(v) => v
                .as_str()
                .map(|s| Some(s.to_owned()))
                .ok_or_else(|| format!("config.{key} is not a string")),
        }
    };
    let list = |key: &str| -> Result<Vec<String>, String> {
        match runtime.and_then(|r| r.get(key)) {
            None => Ok(Vec::new()),
            Some(v) if v.is_null() => Ok(Vec::new()),
            Some(v) => v
                .as_array()
                .ok_or_else(|| format!("config.{key} is not an array"))?
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("config.{key} has an item that is not a string"))
                })
                .collect(),
        }
    };
    Ok(ImageConfig {
        os,
        architecture,
        variant,
        diff_ids,
        user: text("User")?,
        env: list("Env")?,
        entrypoint: list("Entrypoint")?,
        cmd: list("Cmd")?,
        working_dir: text("WorkingDir")?,
    })
}

/// The one index entry for `platform` (ADR-009, D9): none is `NotFound`,
/// more than one is `Failed`. The entry must name a manifest; an index is
/// refused (no nested indexes).
pub(crate) fn select<'i>(index: &'i Index, platform: &Platform) -> Result<&'i Entry, PullError> {
    let mut matches = index.manifests.iter().filter(|entry| {
        entry
            .platform
            .as_ref()
            .is_some_and(|(os, arch, variant)| platform.matches(os, arch, variant.as_deref()))
    });
    let entry = matches.next().ok_or_else(|| {
        PullError::NotFound(format!("the index lists no manifest for {platform}"))
    })?;
    if matches.next().is_some() {
        return Err(failed(format!(
            "the index lists more than one manifest for {platform}"
        )));
    }
    match entry.descriptor.media_type.as_str() {
        OCI_MANIFEST | DOCKER_MANIFEST => Ok(entry),
        OCI_INDEX | DOCKER_LIST => Err(failed(format!(
            "the entry for {platform} is a nested index, which is refused"
        ))),
        t => Err(failed(format!(
            "the entry for {platform} has the unknown media type {t:?}"
        ))),
    }
}
