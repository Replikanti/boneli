//! A fake registry for the client tests: a `Dial` that answers each
//! connection on its own thread over `UnixStream::pair`, so the client's
//! HTTP framing and its deadline wrapper are the real code. The fake reads
//! each request head itself and parses it with `boneli_http`, so a test
//! can also answer with exact raw bytes (oversized heads, lying lengths,
//! stalls). Every request is recorded: the dialed host and port, the
//! target and the header fields.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use boneli_http::{Headers, RequestHead, ResponseHead, Target};
use boneli_oci::{Dial, Digest, Stream};

/// One request as the fake saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    /// The host the client dialed.
    pub host: String,
    /// The port the client dialed.
    pub port: u16,
    /// The origin-form target.
    pub target: String,
    /// The header fields, in order.
    pub headers: Vec<(String, String)>,
}

impl Seen {
    /// The first value of `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// How the fake answers.
pub enum Reply {
    /// A response encoded by `boneli_http`, with `Content-Length`.
    Http {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// These bytes, as they are.
    Raw(Vec<u8>),
    /// `head` at once, then each chunk after `delay`.
    Trickle {
        head: Vec<u8>,
        chunks: Vec<Vec<u8>>,
        delay: Duration,
    },
}

impl Reply {
    /// `status` with `body` and these fields.
    pub fn http(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        Reply::Http {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.to_vec(),
        }
    }

    /// `status` with no body.
    pub fn status(status: u16) -> Reply {
        Reply::http(status, &[], b"")
    }
}

type Handler = dyn Fn(&Seen) -> Reply + Send + Sync;

/// The fake: a handler and the log of what it saw.
#[derive(Clone)]
pub struct Fake {
    handler: Arc<Handler>,
    log: Arc<Mutex<Vec<Seen>>>,
    dials: Arc<Mutex<Vec<(String, u16)>>>,
}

impl Fake {
    /// A fake that answers with `handler`.
    pub fn new(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Fake {
        Fake {
            handler: Arc::new(handler),
            log: Arc::default(),
            dials: Arc::default(),
        }
    }

    /// Every request seen so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.log.lock().expect("log").clone()
    }

    /// Every dial so far, a request or not.
    pub fn dials(&self) -> Vec<(String, u16)> {
        self.dials.lock().expect("dials").clone()
    }
}

impl Dial for Fake {
    fn dial(&self, host: &str, port: u16, _deadline: Instant) -> io::Result<Box<dyn Stream>> {
        self.dials
            .lock()
            .expect("dials")
            .push((host.to_owned(), port));
        let (client, server) = UnixStream::pair()?;
        let handler = Arc::clone(&self.handler);
        let log = Arc::clone(&self.log);
        let host = host.to_owned();
        thread::spawn(move || serve(server, host, port, &*handler, &log));
        Ok(Box::new(client))
    }
}

fn serve(
    mut stream: UnixStream,
    host: String,
    port: u16,
    handler: &Handler,
    log: &Mutex<Vec<Seen>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) if bytes.len() < 1 << 16 => bytes.push(byte[0]),
            _ => return,
        }
    }
    let limits = boneli_http::Limits::new(1 << 16, 256, 1).expect("limits");
    let head = RequestHead::parse(&bytes, &limits).expect("the client sent a valid head");
    let Target::Origin(target) = head.target else {
        panic!("the client sent a non-origin target");
    };
    let seen = Seen {
        host,
        port,
        target,
        headers: head
            .headers
            .iter()
            .map(|(n, v)| (n.to_owned(), String::from_utf8_lossy(v).into_owned()))
            .collect(),
    };
    log.lock().expect("log").push(seen.clone());
    match handler(&seen) {
        Reply::Http {
            status,
            headers,
            body,
        } => {
            let mut response = ResponseHead::new(status);
            let mut fields = Headers::new();
            for (n, v) in headers {
                fields.append(n, v);
            }
            fields.append("Content-Length", body.len().to_string());
            response.headers = fields;
            let mut out = response.encode().expect("encode");
            out.extend_from_slice(&body);
            let _ = stream.write_all(&out);
        }
        Reply::Raw(bytes) => {
            let _ = stream.write_all(&bytes);
        }
        Reply::Trickle {
            head,
            chunks,
            delay,
        } => {
            let _ = stream.write_all(&head);
            for chunk in chunks {
                thread::sleep(delay);
                if stream.write_all(&chunk).is_err() {
                    return;
                }
            }
        }
    }
}

/// `sha256:<hex>` of `bytes`.
pub fn digest_of(bytes: &[u8]) -> String {
    Digest::of(bytes).to_string()
}

/// The token the hub issues.
pub const TOKEN: &str = "tok-1";

/// The Docker Hub challenge for `repo`.
pub fn challenge_for(repo: &str) -> String {
    format!(
        r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:{repo}:pull""#
    )
}

/// A small Docker Hub: tokens from `auth.docker.io`, an API at
/// `registry-1.docker.io` that wants `Bearer tok-1` and answers an unknown
/// repository with `401` even then (measured), and blobs redirected to
/// `production.cloudfront.docker.com` when `cdn` is set.
#[derive(Clone, Default)]
pub struct Hub {
    /// Repository → (digest → (content type, bytes)) of its documents.
    pub manifests: BTreeMap<String, BTreeMap<String, (String, Vec<u8>)>>,
    /// Digest → bytes of every blob, any repository.
    pub blobs: BTreeMap<String, Vec<u8>>,
    /// Redirect blob requests to the CDN.
    pub cdn: bool,
    /// Repository → (tag → (content type, bytes)): the signature tags.
    pub tags: BTreeMap<String, BTreeMap<String, (String, Vec<u8>)>>,
    /// Repository → (digest → answer) of the referrers API; a digest
    /// without one is answered `404`, a registry without the API.
    pub referrers: BTreeMap<String, BTreeMap<String, Referrers>>,
}

/// How the hub's referrers API answers for one digest.
#[derive(Clone, Debug)]
pub enum Referrers {
    /// `200` with this listing.
    Listing(Vec<u8>),
    /// This status with no body.
    Status(u16),
}

impl Hub {
    /// Adds a document to `repo` and returns its digest.
    pub fn document(&mut self, repo: &str, content_type: &str, bytes: &[u8]) -> String {
        let digest = digest_of(bytes);
        self.manifests
            .entry(repo.to_owned())
            .or_default()
            .insert(digest.clone(), (content_type.to_owned(), bytes.to_vec()));
        digest
    }

    /// Adds a blob to `repo` and returns its digest.
    pub fn blob(&mut self, repo: &str, bytes: &[u8]) -> String {
        self.manifests.entry(repo.to_owned()).or_default();
        let digest = digest_of(bytes);
        self.blobs.insert(digest.clone(), bytes.to_vec());
        digest
    }

    /// Tags `bytes` as `tag` in `repo`, served as a manifest with
    /// `content_type`; returns their digest.
    pub fn tag(&mut self, repo: &str, tag: &str, content_type: &str, bytes: &[u8]) -> String {
        self.tags
            .entry(repo.to_owned())
            .or_default()
            .insert(tag.to_owned(), (content_type.to_owned(), bytes.to_vec()));
        digest_of(bytes)
    }

    /// Sets the referrers API's answer for `digest` in `repo`.
    pub fn referrers(&mut self, repo: &str, digest: &str, reply: Referrers) {
        self.referrers
            .entry(repo.to_owned())
            .or_default()
            .insert(digest.to_owned(), reply);
    }

    /// The hub's answer to `seen`.
    pub fn handle(&self, seen: &Seen) -> Reply {
        match seen.host.as_str() {
            "auth.docker.io" if seen.target.starts_with("/token?") => Reply::http(
                200,
                &[("Content-Type", "application/json")],
                format!(r#"{{"token":"{TOKEN}","access_token":"{TOKEN}","expires_in":300}}"#)
                    .as_bytes(),
            ),
            "registry-1.docker.io" => self.api(seen),
            "production.cloudfront.docker.com" => {
                let digest = seen.target.trim_start_matches("/blobs/");
                match self.blobs.get(digest) {
                    Some(bytes) => Reply::http(200, &[], bytes),
                    None => Reply::status(404),
                }
            }
            _ => Reply::status(421),
        }
    }

    fn api(&self, seen: &Seen) -> Reply {
        let Some(rest) = seen.target.strip_prefix("/v2/") else {
            return Reply::status(404);
        };
        let (repo, kind, digest) = if let Some((repo, digest)) = rest.rsplit_once("/referrers/") {
            (repo, "referrers", digest)
        } else if let Some((repo, digest)) = rest.rsplit_once("/manifests/") {
            (repo, "manifests", digest)
        } else if let Some((repo, digest)) = rest.rsplit_once("/blobs/") {
            (repo, "blobs", digest)
        } else {
            return Reply::status(404);
        };
        let challenge = challenge_for(repo);
        let authorized = seen.header("authorization") == Some(&format!("Bearer {TOKEN}"));
        let Some(documents) = self.manifests.get(repo).filter(|_| authorized) else {
            return Reply::http(401, &[("WWW-Authenticate", &challenge)], b"{}");
        };
        if kind == "referrers" {
            return match self.referrers.get(repo).and_then(|r| r.get(digest)) {
                Some(Referrers::Listing(bytes)) => Reply::http(
                    200,
                    &[("Content-Type", "application/vnd.oci.image.index.v1+json")],
                    bytes,
                ),
                Some(Referrers::Status(status)) => Reply::status(*status),
                None => Reply::status(404),
            };
        }
        if kind == "manifests" {
            let tagged = self.tags.get(repo).and_then(|t| t.get(digest));
            return match documents.get(digest).or(tagged) {
                Some((ct, bytes)) => Reply::http(200, &[("Content-Type", ct)], bytes),
                None => Reply::status(404),
            };
        }
        match self.blobs.get(digest) {
            Some(_) if self.cdn => Reply::http(
                307,
                &[(
                    "Location",
                    &format!("https://production.cloudfront.docker.com/blobs/{digest}"),
                )],
                b"",
            ),
            Some(bytes) => Reply::http(200, &[], bytes),
            None => Reply::status(404),
        }
    }
}

/// The OCI media types the tests use.
pub mod media {
    pub const INDEX: &str = "application/vnd.oci.image.index.v1+json";
    pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
    pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
    pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
    pub const CONFIG: &str = "application/vnd.oci.image.config.v1+json";
    pub const TAR: &str = "application/vnd.oci.image.layer.v1.tar";
    pub const GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
}

/// `{"mediaType":..,"digest":..,"size":..}`.
pub fn descriptor(media_type: &str, digest: &str, size: usize) -> String {
    format!(r#"{{"mediaType":"{media_type}","digest":"{digest}","size":{size}}}"#)
}

/// An image config for `os/arch[/variant]` with these diff_ids.
pub fn config(os: &str, arch: &str, variant: Option<&str>, diff_ids: &[String]) -> Vec<u8> {
    let variant = variant.map_or(String::new(), |v| format!(r#","variant":"{v}""#));
    let ids: Vec<String> = diff_ids.iter().map(|d| format!("\"{d}\"")).collect();
    format!(
        r#"{{"architecture":"{arch}","os":"{os}"{variant},"rootfs":{{"type":"layers","diff_ids":[{}]}}}}"#,
        ids.join(",")
    )
    .into_bytes()
}

/// An OCI manifest with a `mediaType` field over these descriptors.
pub fn manifest(config: &str, layers: &[String]) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion":2,"mediaType":"{}","config":{config},"layers":[{}]}}"#,
        media::MANIFEST,
        layers.join(",")
    )
    .into_bytes()
}

/// An OCI index over these entries.
pub fn index(entries: &[String]) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion":2,"mediaType":"{}","manifests":[{}]}}"#,
        media::INDEX,
        entries.join(",")
    )
    .into_bytes()
}

/// An index entry for a manifest on `os/arch[/variant]`.
pub fn entry(
    media_type: &str,
    digest: &str,
    size: usize,
    platform: Option<(&str, &str, Option<&str>)>,
) -> String {
    let platform = match platform {
        None => String::new(),
        Some((os, arch, variant)) => {
            let variant = variant.map_or(String::new(), |v| format!(r#","variant":"{v}""#));
            format!(r#","platform":{{"architecture":"{arch}","os":"{os}"{variant}}}"#)
        }
    };
    format!(r#"{{"mediaType":"{media_type}","digest":"{digest}","size":{size}{platform}}}"#)
}

/// An image in `hub`: `layers` plain tar layers (their bytes are the
/// layer index, the diff_id is their digest) and a config for the
/// platform; returns the manifest's digest and size.
pub fn image(
    hub: &mut Hub,
    repo: &str,
    platform: (&str, &str, Option<&str>),
    layers: usize,
) -> (String, usize) {
    let mut descriptors = Vec::new();
    let mut diff_ids = Vec::new();
    for i in 0..layers {
        let bytes = format!("layer {i} of {}/{}", platform.0, platform.1).into_bytes();
        let digest = hub.blob(repo, &bytes);
        descriptors.push(descriptor(media::TAR, &digest, bytes.len()));
        diff_ids.push(digest);
    }
    let config_bytes = config(platform.0, platform.1, platform.2, &diff_ids);
    let config_digest = hub.blob(repo, &config_bytes);
    let manifest = manifest(
        &descriptor(media::CONFIG, &config_digest, config_bytes.len()),
        &descriptors,
    );
    (
        hub.document(repo, media::MANIFEST, &manifest),
        manifest.len(),
    )
}
