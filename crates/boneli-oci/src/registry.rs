//! The registry client (ADR-009, D9 to D12): manifests and blobs by
//! digest over the OCI distribution API, the anonymous token flow, the
//! host allowlist and redirects, error classification and limits.
//!
//! - Every request goes to an allowlisted host: the registry's API host,
//!   one of its token hosts, or (for blob redirects only) a host under one
//!   of its redirect suffixes, matched on a dot boundary. `https` only,
//!   certificates verified by the `Dial` (D10).
//! - `Authorization` goes to the API host and port only, never to a token
//!   or redirect host.
//! - Every byte used is checked against its digest: a document before it
//!   is parsed, a blob before it is renamed into place. A blob must be
//!   exactly its descriptor's size.
//! - One connection per request, no reuse, and a deadline per fetch:
//!   `setup + size / min_rate`, its token request and redirects included.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use boneli_http::{Connection, Method, RequestBody, RequestHead, ResponseHead, Target};
use boneli_https::{Dial, Sha256, Timed};

use crate::auth::{self, Challenge};
use crate::error::{Error, PullError, failed};
use crate::manifest::{self, Descriptor, Document, ImageConfig, Manifest};
use crate::reference::{Digest, Reference, RegistryHost, Repository};
use crate::url::{self, Url};

/// The most redirects a blob fetch follows, Go `net/http`'s limit (D10).
pub const MAX_REDIRECTS: usize = 10;

/// The port of a registry, token or redirect host without one.
const HTTPS_PORT: u16 = 443;

/// An allowlisted registry (D10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registry {
    name: String,
    api: (String, u16),
    auth_hosts: Vec<(String, u16)>,
    redirect_suffixes: Vec<String>,
}

impl Registry {
    /// A registry:
    ///
    /// - `name`: the host an image name uses for it (`docker.io`);
    /// - `api_host`: the host, with an optional port, that serves `/v2/`
    ///   (`registry-1.docker.io`); an image name may use it too;
    /// - `auth_hosts`: the hosts a token realm may name;
    /// - `redirect_suffixes`: `.`-prefixed suffixes of the hosts a blob
    ///   request may be redirected to (`.docker.com`), matched on a dot
    ///   boundary, port 443 only.
    ///
    /// Every host must pass the grammar of ADR-003.
    pub fn new(
        name: &str,
        api_host: &str,
        auth_hosts: &[&str],
        redirect_suffixes: &[&str],
    ) -> Result<Registry, Error> {
        let host = |text: &str| {
            url::host_port(text)
                .map(|(h, p)| (h, p.unwrap_or(HTTPS_PORT)))
                .map_err(|e| Error::InvalidRegistry(format!("{text:?}: {e}")))
        };
        let (name, name_port) = host(name)?;
        if name_port != HTTPS_PORT || name.contains(':') {
            return Err(Error::InvalidRegistry(format!(
                "the name {name:?} must be a host without a port"
            )));
        }
        let mut suffixes = Vec::with_capacity(redirect_suffixes.len());
        for suffix in redirect_suffixes {
            let rest = suffix.strip_prefix('.').ok_or_else(|| {
                Error::InvalidRegistry(format!("redirect suffix {suffix:?} must start with ."))
            })?;
            let (rest, port) = host(rest)?;
            if port != HTTPS_PORT || suffix.contains(':') {
                return Err(Error::InvalidRegistry(format!(
                    "redirect suffix {suffix:?} must be a host without a port"
                )));
            }
            suffixes.push(format!(".{rest}"));
        }
        Ok(Registry {
            name,
            api: host(api_host)?,
            auth_hosts: auth_hosts
                .iter()
                .map(|h| host(h))
                .collect::<Result<_, _>>()?,
            redirect_suffixes: suffixes,
        })
    }

    /// Docker Hub, as measured on 2026-11-16: images under `docker.io`,
    /// the API at `registry-1.docker.io`, tokens from `auth.docker.io`,
    /// blobs redirected to `production.cloudfront.docker.com`.
    pub fn docker_hub() -> Registry {
        Registry {
            name: "docker.io".to_owned(),
            api: ("registry-1.docker.io".to_owned(), HTTPS_PORT),
            auth_hosts: vec![("auth.docker.io".to_owned(), HTTPS_PORT)],
            redirect_suffixes: vec![".docker.com".to_owned()],
        }
    }

    /// The name images use for this registry.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the registry host of an image name is this registry: its
    /// name without a port, or its API host with no port or the API port.
    fn serves(&self, host: &RegistryHost) -> bool {
        match host.port() {
            None => host.host() == self.name || host.host() == self.api.0,
            Some(port) => host.host() == self.api.0 && port == self.api.1,
        }
    }

    fn is_api(&self, url: &Url) -> bool {
        url.host == self.api.0 && url.port == self.api.1
    }

    /// Whether a blob request may go to `url`: the API host, or a host
    /// strictly under a redirect suffix on port 443. A suffix starts with
    /// `.` and a host never does (ADR-003 grammar), so `ends_with` alone
    /// means strictly under, on a label boundary.
    fn redirect_allowed(&self, url: &Url) -> bool {
        self.is_api(url)
            || (url.port == HTTPS_PORT
                && self
                    .redirect_suffixes
                    .iter()
                    .any(|s| url.host.ends_with(s.as_str())))
    }

    fn api_url(&self, target: String) -> Url {
        Url {
            host: self.api.0.clone(),
            port: self.api.1,
            target,
        }
    }
}

/// The registry for `reference`: the one its host names, or `default`
/// when the name has no host. A host that no registry serves is refused.
pub fn select<'r>(
    registries: &'r [Registry],
    default: &'r Registry,
    reference: &Reference,
) -> Result<&'r Registry, PullError> {
    match reference.registry() {
        None => Ok(default),
        Some(host) => registries.iter().find(|r| r.serves(host)).ok_or_else(|| {
            failed(format!(
                "the registry {:?} is not on the allowlist",
                match host.port() {
                    Some(port) => format!("{}:{port}", host.host()),
                    None => host.host().to_owned(),
                }
            ))
        }),
    }
}

/// The limits of the registry client (D12). No defaults; a zero is
/// refused, and every limit is inclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchLimits {
    document: boneli_json::Limits,
    max_token_bytes: usize,
    max_head_bytes: usize,
    max_headers: usize,
    max_layers: usize,
    max_blob_bytes: u64,
    max_pull_bytes: u64,
}

impl FetchLimits {
    /// - `document`: an index, manifest or config: bytes, depth, values;
    /// - `max_token_bytes`: a token response body;
    /// - `max_head_bytes`, `max_headers`: a response head;
    /// - `max_layers`: layers of a manifest;
    /// - `max_blob_bytes`: a blob's descriptor size, checked before the
    ///   request;
    /// - `max_pull_bytes`: the descriptor sizes of a manifest's config and
    ///   layers, summed: what one pull downloads, checked when the
    ///   manifest is read.
    pub fn new(
        document: boneli_json::Limits,
        max_token_bytes: usize,
        max_head_bytes: usize,
        max_headers: usize,
        max_layers: usize,
        max_blob_bytes: u64,
        max_pull_bytes: u64,
    ) -> Result<FetchLimits, Error> {
        for (value, what) in [
            (max_token_bytes as u64, "max_token_bytes"),
            (max_head_bytes as u64, "max_head_bytes"),
            (max_headers as u64, "max_headers"),
            (max_layers as u64, "max_layers"),
            (max_blob_bytes, "max_blob_bytes"),
            (max_pull_bytes, "max_pull_bytes"),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimits(what));
            }
        }
        Ok(FetchLimits {
            document,
            max_token_bytes,
            max_head_bytes,
            max_headers,
            max_layers,
            max_blob_bytes,
            max_pull_bytes,
        })
    }

    /// The limits of an index, manifest or config.
    pub(crate) fn document_limits(&self) -> &boneli_json::Limits {
        &self.document
    }

    /// Layers of a manifest.
    pub(crate) fn max_layers(&self) -> usize {
        self.max_layers
    }

    fn token(&self) -> Result<boneli_json::Limits, PullError> {
        boneli_json::Limits::new(
            self.max_token_bytes,
            self.document.max_depth(),
            self.document.max_values(),
        )
        .map_err(|e| failed(format!("token limits: {e}")))
    }

    fn http(&self) -> Result<boneli_http::Limits, PullError> {
        // Body sizes are checked by the client against what it expects.
        boneli_http::Limits::new(self.max_head_bytes, self.max_headers, u64::MAX)
            .map_err(|e| failed(format!("HTTP limits: {e}")))
    }
}

/// The time limits of the registry client (D12). No defaults; a zero is
/// refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    io: Duration,
    setup: Duration,
    min_rate: u64,
}

impl Timeouts {
    /// - `io`: each read and write;
    /// - `setup` and `min_rate` (bytes per second): the deadline of a
    ///   fetch of `size` bytes is `setup + size / min_rate`.
    pub fn new(io: Duration, setup: Duration, min_rate: u64) -> Result<Timeouts, Error> {
        if io.is_zero() {
            return Err(Error::InvalidLimits("io"));
        }
        if setup.is_zero() {
            return Err(Error::InvalidLimits("setup"));
        }
        if min_rate == 0 {
            return Err(Error::InvalidLimits("min_rate"));
        }
        Ok(Timeouts {
            io,
            setup,
            min_rate,
        })
    }

    fn deadline(&self, size: u64) -> Result<Instant, PullError> {
        let nanos = u128::from(size) * 1_000_000_000 / u128::from(self.min_rate);
        u64::try_from(nanos)
            .ok()
            .map(Duration::from_nanos)
            .and_then(|transfer| self.setup.checked_add(transfer))
            .and_then(|total| Instant::now().checked_add(total))
            .ok_or_else(|| failed(format!("no deadline for a fetch of {size} bytes")))
    }
}

/// A fetched document: its bytes, checked against its digest, and the
/// response's `Content-Type`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// The body.
    pub bytes: Vec<u8>,
    /// The `Content-Type`, if the response had a readable one.
    pub content_type: Option<String>,
}

/// An image resolved to the manifest for its platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The index the reference named, if it named one.
    pub index: Option<Digest>,
    /// The digest of the platform's manifest.
    pub manifest_digest: Digest,
    /// The platform's manifest.
    pub manifest: Manifest,
    /// Its config.
    pub config: ImageConfig,
}

/// Where [`Client::resolve_with`] keeps the documents it fetched: indexes,
/// manifests and configs, by digest. The store keeps them on disk and
/// re-hashes them on every read (ADR-009, D8).
pub(crate) trait Documents {
    /// The document `digest`, if it is kept and its bytes still hash to it.
    fn get(&mut self, digest: &Digest) -> Result<Option<Fetched>, PullError>;
    /// Keeps the document `digest`, whose bytes were checked against it.
    fn put(&mut self, digest: &Digest, fetched: &Fetched) -> Result<(), PullError>;
}

/// Keeps nothing: every document is fetched.
struct NoDocuments;

impl Documents for NoDocuments {
    fn get(&mut self, _: &Digest) -> Result<Option<Fetched>, PullError> {
        Ok(None)
    }

    fn put(&mut self, _: &Digest, _: &Fetched) -> Result<(), PullError> {
        Ok(())
    }
}

/// What one exchange ended in.
enum Step<T> {
    Done(T),
    Unauthorized(Result<Challenge, String>),
    Redirect(Url),
}

/// What is being fetched, for error classification (D11).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Manifest,
    Blob,
}

/// A client for one pull from one registry: it holds the token, which is
/// reused within the pull and fetched again once on a `401` (D9).
pub struct Client<'a> {
    registry: &'a Registry,
    dial: &'a dyn Dial,
    limits: &'a FetchLimits,
    timeouts: &'a Timeouts,
    token: Option<String>,
    /// The API host answered a request with a document, a blob or a
    /// redirect to one: the repository exists.
    authorized: bool,
}

impl<'a> Client<'a> {
    /// A client without a token.
    pub fn new(
        registry: &'a Registry,
        dial: &'a dyn Dial,
        limits: &'a FetchLimits,
        timeouts: &'a Timeouts,
    ) -> Client<'a> {
        Client {
            registry,
            dial,
            limits,
            timeouts,
            token: None,
            authorized: false,
        }
    }

    /// Resolves `reference` to its platform's manifest and config: the
    /// document it names; if that is an index, the one entry for the
    /// platform and its manifest; then the config, once every layer is
    /// within `max_blob_bytes` and the config and layers together within
    /// `max_pull_bytes`. The config must list one `diff_id` per layer, and
    /// its platform must be the requested one: for a manifest named
    /// directly a mismatch is `NotFound`, for one selected from an index
    /// it is `Failed`, because the index said otherwise.
    pub fn resolve(&mut self, reference: &Reference) -> Result<Resolved, PullError> {
        self.resolve_with(reference, &mut NoDocuments)
    }

    /// [`Client::resolve`], taking each document from `documents` when it
    /// is kept there and keeping every one it fetches.
    pub(crate) fn resolve_with(
        &mut self,
        reference: &Reference,
        documents: &mut dyn Documents,
    ) -> Result<Resolved, PullError> {
        let repo = reference.repository();
        let digest = reference.digest();
        let platform = reference.platform();
        let top = self.kept_manifest(documents, repo, digest, None)?;
        let (index, manifest_digest, manifest) = match self.document(&top, digest)? {
            Document::Manifest(m) => (None, *digest, m),
            Document::Index(index) => {
                let entry = manifest::select(&index, platform)?;
                let d = entry.descriptor.clone();
                let fetched = self.kept_manifest(documents, repo, &d.digest, Some(d.size))?;
                match self.document(&fetched, &d.digest)? {
                    Document::Manifest(m) if m.media_type == d.media_type => {
                        (Some(*digest), d.digest, m)
                    }
                    Document::Manifest(m) => {
                        return Err(failed(format!(
                            "manifest {} is {:?}, but the index says {:?}",
                            d.digest, m.media_type, d.media_type
                        )));
                    }
                    Document::Index(_) => {
                        return Err(failed(format!(
                            "manifest {} is a nested index, which is refused",
                            d.digest
                        )));
                    }
                }
            }
        };
        for layer in &manifest.layers {
            self.check_blob_size(&layer.descriptor)?;
        }
        self.check_pull_size(&manifest)?;
        let config = self.get_config(documents, repo, &manifest.config)?;
        if config.diff_ids.len() != manifest.layers.len() {
            return Err(failed(format!(
                "config {} lists {} diff_ids for {} layers",
                manifest.config.digest,
                config.diff_ids.len(),
                manifest.layers.len()
            )));
        }
        if !platform.matches(&config.os, &config.architecture, config.variant.as_deref()) {
            let detail = format!(
                "config {} is for {}/{}{}, not {platform}",
                manifest.config.digest,
                config.os,
                config.architecture,
                config
                    .variant
                    .as_deref()
                    .map(|v| format!("/{v}"))
                    .unwrap_or_default()
            );
            return Err(match index {
                None => PullError::NotFound(detail),
                Some(_) => failed(detail),
            });
        }
        Ok(Resolved {
            index,
            manifest_digest,
            manifest,
            config,
        })
    }

    /// The manifest `digest` from `documents`, or fetched and kept there.
    fn kept_manifest(
        &mut self,
        documents: &mut dyn Documents,
        repo: &Repository,
        digest: &Digest,
        size: Option<u64>,
    ) -> Result<Fetched, PullError> {
        if let Some(kept) = documents.get(digest)? {
            return Ok(kept);
        }
        let fetched = self.get_manifest(repo, digest, size)?;
        documents.put(digest, &fetched)?;
        Ok(fetched)
    }

    fn document(&self, fetched: &Fetched, digest: &Digest) -> Result<Document, PullError> {
        manifest::parse_document(
            &fetched.bytes,
            fetched.content_type.as_deref(),
            &self.limits.document,
            self.limits.max_layers,
        )
        .map_err(|e| failed(format!("manifest {digest}: {e}")))
    }

    /// Fetches the index or manifest `digest`; `size` is its exact size
    /// when a descriptor gave it. The body is at most the document limit
    /// and must hash to `digest`. A `404` on the manifest the reference
    /// named (`size` is `None`), or a `401` with a fresh token before
    /// anything was authorized, is `NotFound`; a `404` on a manifest an
    /// index named (`size` is its descriptor's) is `Failed`, because the
    /// index says it exists (D11).
    pub fn get_manifest(
        &mut self,
        repo: &Repository,
        digest: &Digest,
        size: Option<u64>,
    ) -> Result<Fetched, PullError> {
        let max = self.limits.document.max_bytes() as u64;
        if let Some(size) = size
            && size > max
        {
            return Err(failed(format!(
                "manifest {digest} has {size} bytes, more than the limit of {max}"
            )));
        }
        let deadline = self.timeouts.deadline(size.unwrap_or(max))?;
        let url = self
            .registry
            .api_url(format!("/v2/{repo}/manifests/{digest}"));
        let what = format!("manifest {digest}");
        let mut fresh = false;
        loop {
            let step = self.send(
                &url,
                Some(manifest::ACCEPT),
                deadline,
                |head, body| match head.status {
                    200 => {
                        let bytes = read_document(body, size, max, &what)?;
                        if Digest::of(&bytes) != *digest {
                            return Err(failed(format!(
                                "{what} does not match its digest; got {}",
                                Digest::of(&bytes)
                            )));
                        }
                        let content_type = head
                            .headers
                            .get("content-type")
                            .and_then(|v| std::str::from_utf8(v).ok())
                            .map(str::to_owned);
                        Ok(Step::Done(Fetched {
                            bytes,
                            content_type,
                        }))
                    }
                    401 => Ok(Step::Unauthorized(challenge(head))),
                    404 => {
                        let detail = format!("{} has no {what} in {repo} (404)", url.host);
                        Err(match size {
                            None => PullError::NotFound(detail),
                            Some(_) => failed(format!("{detail}, but the index names it")),
                        })
                    }
                    status => Err(status_error(&url, status, &what)),
                },
            )?;
            match step {
                Step::Done(fetched) => {
                    self.authorized = true;
                    return Ok(fetched);
                }
                Step::Unauthorized(c) => {
                    self.reauthenticate(c, repo, deadline, &mut fresh, Kind::Manifest, &what)?
                }
                Step::Redirect(_) => {
                    return Err(failed(format!("{what}: an unexpected redirect")));
                }
            }
        }
    }

    /// Fetches the blob `descriptor` into a temporary file next to `dest`
    /// and renames it to `dest` only when it is exactly `size` bytes that
    /// hash to its digest; on any error the temporary file is removed and
    /// `dest` is untouched. A size above `max_blob_bytes` is refused before
    /// any request. Returns the file, open for reading at its start, so a
    /// caller reads the bytes it checked even if another process replaces
    /// or removes `dest` meanwhile.
    pub fn get_blob(
        &mut self,
        repo: &Repository,
        descriptor: &Descriptor,
        dest: &Path,
    ) -> Result<File, PullError> {
        self.check_blob_size(descriptor)?;
        let io_err = |what: &str, path: &Path, e: io::Error| {
            failed(format!("{what} {} failed: {e}", path.display()))
        };
        let dir = dest
            .parent()
            .ok_or_else(|| failed(format!("{} has no parent", dest.display())))?;
        let name = crate::layers::temporary_name().map_err(|e| failed(e.to_string()))?;
        let temp = dir.join(name);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| io_err("creating", &temp, e))?;
        let result = self
            .fetch_blob(repo, descriptor, &mut file)
            .and_then(|()| file.sync_all().map_err(|e| io_err("syncing", &temp, e)))
            .and_then(|()| fs::rename(&temp, dest).map_err(|e| io_err("renaming", dest, e)))
            .and_then(|()| {
                File::open(dir)
                    .and_then(|d| d.sync_all())
                    .map_err(|e| io_err("syncing", dir, e))
            })
            .and_then(|()| {
                file.seek(SeekFrom::Start(0))
                    .map(|_| ())
                    .map_err(|e| io_err("rewinding", dest, e))
            });
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map(|()| file)
    }

    fn check_blob_size(&self, descriptor: &Descriptor) -> Result<(), PullError> {
        if descriptor.size > self.limits.max_blob_bytes {
            return Err(failed(format!(
                "blob {} has {} bytes, more than the limit of {}",
                descriptor.digest, descriptor.size, self.limits.max_blob_bytes
            )));
        }
        Ok(())
    }

    /// The config and layer descriptor sizes of `manifest`, summed, must be
    /// at most `max_pull_bytes`; a sum that does not fit in a `u64` is
    /// over it. Checked before the config or any layer is requested, so
    /// compressed-side padding that decodes to nothing (D7 charges only
    /// decoded bytes) cannot make a pull download more (D12).
    fn check_pull_size(&self, manifest: &Manifest) -> Result<(), PullError> {
        let max = self.limits.max_pull_bytes;
        let total = manifest
            .layers
            .iter()
            .try_fold(manifest.config.size, |sum, layer| {
                sum.checked_add(layer.descriptor.size)
            });
        match total {
            Some(total) if total <= max => Ok(()),
            Some(total) => Err(failed(format!(
                "the image's config and {} layers have {total} bytes, more than the limit of {max}",
                manifest.layers.len()
            ))),
            None => Err(failed(format!(
                "the image's config and {} layers have more bytes than a u64 holds, more than the limit of {max}",
                manifest.layers.len()
            ))),
        }
    }

    /// Fetches and parses a config, or takes it from `documents`; its size
    /// is held to the document limit before the request.
    fn get_config(
        &mut self,
        documents: &mut dyn Documents,
        repo: &Repository,
        descriptor: &Descriptor,
    ) -> Result<ImageConfig, PullError> {
        let max = self.limits.document.max_bytes() as u64;
        if descriptor.size > max {
            return Err(failed(format!(
                "config {} has {} bytes, more than the limit of {max}",
                descriptor.digest, descriptor.size
            )));
        }
        let bytes = match documents.get(&descriptor.digest)? {
            Some(kept) => kept.bytes,
            None => {
                let mut bytes = Vec::new();
                self.fetch_blob(repo, descriptor, &mut bytes)?;
                let fetched = Fetched {
                    bytes,
                    content_type: None,
                };
                documents.put(&descriptor.digest, &fetched)?;
                fetched.bytes
            }
        };
        manifest::parse_config(&bytes, &self.limits.document)
            .map_err(|e| failed(format!("config {}: {e}", descriptor.digest)))
    }

    /// Streams the blob into `sink` while it hashes it, following up to
    /// `MAX_REDIRECTS` redirects to allowed hosts. The body must be exactly
    /// the descriptor's size and hash to its digest.
    fn fetch_blob(
        &mut self,
        repo: &Repository,
        descriptor: &Descriptor,
        sink: &mut dyn Write,
    ) -> Result<(), PullError> {
        self.check_blob_size(descriptor)?;
        let digest = descriptor.digest;
        let deadline = self.timeouts.deadline(descriptor.size)?;
        let what = format!("blob {digest}");
        let mut url = self.registry.api_url(format!("/v2/{repo}/blobs/{digest}"));
        let mut redirects = 0;
        let mut fresh = false;
        loop {
            let to_api = self.registry.is_api(&url);
            let step = self.send(&url, None, deadline, |head, body| match head.status {
                200 => {
                    copy_exact(body, sink, descriptor, &what)?;
                    Ok(Step::Done(()))
                }
                301 | 302 | 303 | 307 | 308 => {
                    let location = single(head, "location").ok_or_else(|| {
                        failed(format!("{what}: a redirect without one Location"))
                    })?;
                    let next = url.join(location).map_err(|e| {
                        failed(format!("{what}: redirect to {location:?} refused: {e}"))
                    })?;
                    Ok(Step::Redirect(next))
                }
                401 if to_api => Ok(Step::Unauthorized(challenge(head))),
                status => Err(status_error(&url, status, &what)),
            })?;
            match step {
                Step::Done(()) => {
                    if to_api {
                        self.authorized = true;
                    }
                    return Ok(());
                }
                Step::Redirect(next) => {
                    if to_api {
                        self.authorized = true;
                    }
                    redirects += 1;
                    if redirects > MAX_REDIRECTS {
                        return Err(failed(format!(
                            "{what}: more than {MAX_REDIRECTS} redirects"
                        )));
                    }
                    if !self.registry.redirect_allowed(&next) {
                        return Err(failed(format!(
                            "{what}: redirect to {}:{} is not on the allowlist",
                            next.host, next.port
                        )));
                    }
                    url = next;
                }
                Step::Unauthorized(c) => {
                    self.reauthenticate(c, repo, deadline, &mut fresh, Kind::Blob, &what)?;
                    url = self.registry.api_url(format!("/v2/{repo}/blobs/{digest}"));
                }
            }
        }
    }

    /// After a `401`: fetches a token once per fetch (`fresh`). A second
    /// `401` is `NotFound` for a manifest before anything was authorized
    /// (Docker Hub's answer for an unknown repository, D11), `Failed`
    /// otherwise.
    fn reauthenticate(
        &mut self,
        challenge: Result<Challenge, String>,
        repo: &Repository,
        deadline: Instant,
        fresh: &mut bool,
        kind: Kind,
        what: &str,
    ) -> Result<(), PullError> {
        if *fresh {
            let detail = format!(
                "{what}: {} refused a fresh token for {repo} (401)",
                self.registry.api.0
            );
            return Err(if kind == Kind::Manifest && !self.authorized {
                PullError::NotFound(detail)
            } else {
                failed(detail)
            });
        }
        *fresh = true;
        self.token = None;
        let challenge = challenge.map_err(|e| {
            failed(format!(
                "{what}: {} sent an unusable challenge: {e}",
                self.registry.api.0
            ))
        })?;
        let realm = &challenge.realm;
        if !self
            .registry
            .auth_hosts
            .iter()
            .any(|(h, p)| *h == realm.host && *p == realm.port)
        {
            return Err(failed(format!(
                "{what}: the token realm {}:{} is not on the allowlist",
                realm.host, realm.port
            )));
        }
        let url = auth::token_url(&challenge, &format!("repository:{repo}:pull"));
        let max = self.limits.max_token_bytes;
        let limits = self.limits.token()?;
        let token = self.send(&url, None, deadline, |head, body| match head.status {
            200 => {
                let bytes = read_document(body, None, max as u64, "the token response")?;
                auth::token(&bytes, &limits)
                    .map(Step::Done)
                    .map_err(|e| failed(format!("the token response of {}: {e}", url.host)))
            }
            status => Err(status_error(&url, status, "the token")),
        })?;
        match token {
            Step::Done(token) => {
                self.token = Some(token);
                Ok(())
            }
            _ => Err(failed("the token request ended without a token")),
        }
    }

    /// One request on a new connection: `GET url`, with `Accept` if given
    /// and the token if the URL is the API host. `read` sees the response
    /// head and its body.
    fn send<T>(
        &self,
        url: &Url,
        accept: Option<&str>,
        deadline: Instant,
        read: impl FnOnce(&ResponseHead, &mut dyn Read) -> Result<Step<T>, PullError>,
    ) -> Result<Step<T>, PullError> {
        let at = |e: &dyn std::fmt::Display| failed(format!("{}:{}: {e}", url.host, url.port));
        // Past the deadline nothing is dialed, not even a name resolved.
        if deadline.saturating_duration_since(Instant::now()).is_zero() {
            return Err(at(&"the deadline passed"));
        }
        let stream = self
            .dial
            .dial(&url.host, url.port, deadline)
            .map_err(|e| at(&e))?;
        let timed = Timed::new(stream, deadline, self.timeouts.io);
        let mut conn =
            Connection::new(timed, &url.host_field(), self.limits.http()?).map_err(|e| at(&e))?;
        let method = Method::new("GET").map_err(|e| at(&e))?;
        let mut head = RequestHead::new(method, Target::Origin(url.target.clone()));
        if let Some(accept) = accept {
            head.headers.append("Accept", accept);
        }
        if let Some(token) = self.token.as_ref().filter(|_| self.registry.is_api(url)) {
            head.headers
                .append("Authorization", format!("Bearer {token}"));
        }
        let mut response = conn.request(&head, RequestBody::None).map_err(|e| at(&e))?;
        let head = response.head.clone();
        read(&head, &mut response)
    }
}

/// The challenge of a `401`.
fn challenge(head: &ResponseHead) -> Result<Challenge, String> {
    auth::bearer(head.headers.get_all("www-authenticate"))
}

/// The value of a field that must appear exactly once, as visible ASCII.
fn single<'h>(head: &'h ResponseHead, name: &'h str) -> Option<&'h str> {
    let mut values = head.headers.get_all(name);
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    std::str::from_utf8(value).ok()
}

/// A status the fetch cannot continue from (D11).
fn status_error(url: &Url, status: u16, what: &str) -> PullError {
    failed(format!(
        "{}:{} answered {status} for {what}",
        url.host, url.port
    ))
}

/// Reads a JSON body of at most `max` bytes, or exactly `size` bytes when
/// a descriptor gave the size.
fn read_document(
    body: &mut dyn Read,
    size: Option<u64>,
    max: u64,
    what: &str,
) -> Result<Vec<u8>, PullError> {
    let cap = size.unwrap_or(max);
    let mut bytes = Vec::new();
    body.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| {
            failed(format!(
                "reading {what} failed: {}",
                boneli_http::Error::from(e)
            ))
        })?;
    let len = bytes.len() as u64;
    if len > cap {
        return Err(failed(match size {
            Some(size) => format!("{what} is longer than its descriptor's {size} bytes"),
            None => format!("{what} is longer than the limit of {max} bytes"),
        }));
    }
    if size.is_some_and(|size| len != size) {
        return Err(failed(format!(
            "{what} has {len} bytes, not its descriptor's {}",
            size.unwrap_or_default()
        )));
    }
    Ok(bytes)
}

/// Copies exactly `descriptor.size` bytes into `sink` while it hashes
/// them, then checks that the body ends there and that the digest
/// matches.
fn copy_exact(
    body: &mut dyn Read,
    sink: &mut dyn Write,
    descriptor: &Descriptor,
    what: &str,
) -> Result<(), PullError> {
    let read_err = |e: io::Error| {
        failed(format!(
            "reading {what} failed: {}",
            boneli_http::Error::from(e)
        ))
    };
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut left = descriptor.size;
    while left > 0 {
        let want = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        let n = body.read(&mut buf[..want]).map_err(read_err)?;
        if n == 0 {
            return Err(failed(format!(
                "{what} ended {left} bytes before its descriptor's {} bytes",
                descriptor.size
            )));
        }
        hash.update(&buf[..n]);
        sink.write_all(&buf[..n])
            .map_err(|e| failed(format!("writing {what} failed: {e}")))?;
        left -= n as u64;
    }
    let mut extra = [0u8; 1];
    if body.read(&mut extra).map_err(read_err)? != 0 {
        return Err(failed(format!(
            "{what} is longer than its descriptor's {} bytes",
            descriptor.size
        )));
    }
    let actual = Digest::from_bytes(hash.finish());
    if actual != descriptor.digest {
        return Err(failed(format!(
            "{what} does not match its digest; got {actual}"
        )));
    }
    Ok(())
}
