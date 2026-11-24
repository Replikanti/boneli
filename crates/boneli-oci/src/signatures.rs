//! Signature discovery and the check of a `Required` rule (ADR-029, S1,
//! S6 and item 9).
//!
//! The subjects are the digest the reference names and, when it names an
//! index, the platform manifest the pull selected; nothing else counts.
//! The check passes as soon as one candidate verifies for one subject
//! under the rule's [`Trust`] (`boneli_sigstore::verify`); otherwise the
//! pull is `Failed` before any layer blob is requested.
//!
//! 1. **Kept evidence, offline.** For every subject, the pointer file
//!    `signatures/sha256/<subject hex>` names the evidence a former pull
//!    verified, kept under `blobs/sha256/` and re-hashed on every read;
//!    it is verified again under the current trust. A missing, malformed
//!    or dangling pointer is absent. A pull of an image already in the
//!    store whose evidence still verifies makes no request (S6).
//! 2. **Discovery,** subject by subject, two carriers in order:
//!    - cosign's tag `sha256-<hex>.sig`: each layer of media type
//!      [`SIMPLE_SIGNING_MEDIA_TYPE`] of at most [`MAX_PAYLOAD_BYTES`] is
//!      a candidate, its payload fetched by digest;
//!    - the referrers API, and on `404` (only) the tag `sha256-<hex>`:
//!      each entry whose `artifactType` is [`BUNDLE_V03_MEDIA_TYPE`] and
//!      whose predicate-type annotation is on the trust's list is a
//!      candidate; its manifest must name the subject and that artifact
//!      type, and its one layer is the bundle. A tag that answers with the
//!      subject itself (GHCR answers `sha256-<hex>` with the image's own
//!      index where no referrer exists, measured) lists nothing.
//!
//!    [`MAX_SIGNATURES`] is checked on each carrier's raw listing before
//!    anything listed is fetched. Every artifact fetched is kept, and a
//!    pass rewrites the subject's pointer.
//!
//! Every failure of a carrier (a status, a deadline, a malformed listing)
//! ends that carrier and the next one is tried; nothing but a verified
//! candidate passes. The failure detail holds the subjects, the carriers
//! tried, the counts and at most one fixed reason per candidate; every
//! character outside printable ASCII is escaped, so no SAN, payload or
//! header text a registry chose reaches a log line as it is.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use boneli_json::{Object, Value};
use boneli_sigstore::{
    BUNDLE_V03_MEDIA_TYPE, Evidence, MAX_BUNDLE_BYTES, MAX_PAYLOAD_BYTES,
    SIMPLE_SIGNING_MEDIA_TYPE, Trust, verify,
};

use crate::error::{PullError, failed};
use crate::manifest::{self, Descriptor};
use crate::reference::{Digest, Repository};
use crate::registry::{Client, Documents, Fetched, SignatureTag};

/// The most entries one carrier's listing may have per subject: the layers
/// of a `.sig` manifest, the entries of a referrers listing. Inclusive: 16
/// are all examined, 17 make that carrier yield no candidate and fetch
/// none of them. Measured: 1 to 2 per digest (Kubernetes 1, Chainguard 1,
/// cosign 2.4.1 and 3.0.2 2 each, `latest` 2 referrers); 16 is 8 times
/// that, for images signed again after a key rotation or by a second
/// signer. Lower than about 4 refuses images re-signed a few times; higher
/// adds requests a hostile listing can force (ADR-029, limits).
pub const MAX_SIGNATURES: usize = 16;

/// The annotation of a referrers entry that names the bundle's predicate
/// type, as cosign writes it.
pub(crate) const PREDICATE_ANNOTATION: &str = "dev.sigstore.bundle.predicateType";

/// The `Accept` field of a `.sig` request: the two manifest kinds.
const SIG_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

/// The longest pointer file read: `bundle`, two digests, two spaces and a
/// newline are 150 bytes.
pub(crate) const MAX_POINTER_BYTES: u64 = 256;

/// The evidence a pull verified for one subject, as its pointer file names
/// it (module doc, step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pointer {
    /// A `.sig` manifest and the payload of the layer that verified.
    Legacy { manifest: Digest, payload: Digest },
    /// A referrer manifest and its bundle.
    Bundle { manifest: Digest, bundle: Digest },
}

impl Pointer {
    /// The file's one line.
    pub(crate) fn render(&self) -> String {
        match self {
            Pointer::Legacy { manifest, payload } => format!("legacy {manifest} {payload}\n"),
            Pointer::Bundle { manifest, bundle } => format!("bundle {manifest} {bundle}\n"),
        }
    }

    /// The pointer `bytes` hold, if they are exactly one rendered line;
    /// anything else is absent. Every part is strict (one trailing
    /// newline, single spaces, the kind's exact word, `Digest::parse`), so
    /// what parses renders back to the same bytes
    /// (`pointer_round_trip_and_exact`).
    pub(crate) fn parse(bytes: &[u8]) -> Option<Pointer> {
        let text = std::str::from_utf8(bytes).ok()?;
        let line = text.strip_suffix('\n')?;
        let mut parts = line.split(' ');
        let (kind, first, second) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let first = Digest::parse(first).ok()?;
        let second = Digest::parse(second).ok()?;
        match kind {
            "legacy" => Some(Pointer::Legacy {
                manifest: first,
                payload: second,
            }),
            "bundle" => Some(Pointer::Bundle {
                manifest: first,
                bundle: second,
            }),
            _ => None,
        }
    }

    /// The two kept blobs it names.
    pub(crate) fn blobs(&self) -> [Digest; 2] {
        match *self {
            Pointer::Legacy { manifest, payload } => [manifest, payload],
            Pointer::Bundle { manifest, bundle } => [manifest, bundle],
        }
    }
}

/// The pointer file of `subject` under the store root.
pub(crate) fn pointer_path(root: &Path, subject: &Digest) -> PathBuf {
    pointers_dir(root).join(subject.hex())
}

/// `signatures/sha256/`.
pub(crate) fn pointers_dir(root: &Path) -> PathBuf {
    root.join("signatures").join("sha256")
}

/// A layer of an artifact manifest with its annotations.
struct ArtifactLayer {
    descriptor: Descriptor,
    annotations: Vec<(String, String)>,
}

/// What the check reads of a `.sig` or referrer manifest: an OCI (or
/// Docker schema 2) manifest with a config of any media type, layers with
/// string annotations, and optional `artifactType` and `subject`. Image
/// manifests are never parsed this way: `manifest::parse_document` keeps
/// refusing these layer media types.
struct Artifact {
    artifact_type: Option<String>,
    subject: Option<Digest>,
    layers: Vec<ArtifactLayer>,
}

/// The `annotations` member of `object`: absent is empty, otherwise an
/// object of strings.
fn annotations(object: &Object) -> Result<Vec<(String, String)>, &'static str> {
    match object.get("annotations") {
        None => Ok(Vec::new()),
        Some(value) => value
            .as_object()
            .ok_or("annotations are not an object")?
            .iter()
            .map(|(k, v)| {
                v.as_str()
                    .map(|v| (k.to_owned(), v.to_owned()))
                    .ok_or("an annotation is not a string")
            })
            .collect(),
    }
}

/// An optional string member.
fn optional_string<'a>(object: &'a Object, key: &str) -> Result<Option<&'a str>, &'static str> {
    match object.get(key) {
        None => Ok(None),
        Some(value) => value.as_str().map(Some).ok_or("a member is not a string"),
    }
}

/// A descriptor object, with a fixed reason when it is malformed.
fn descriptor(value: &Value) -> Result<Descriptor, &'static str> {
    let object = value.as_object().ok_or("a descriptor is not an object")?;
    manifest::descriptor(object).map_err(|_| "a descriptor is malformed")
}

/// Parses an artifact manifest (see [`Artifact`]).
fn parse_artifact(
    fetched: &Fetched,
    limits: &boneli_json::Limits,
) -> Result<Artifact, &'static str> {
    let value = boneli_json::parse(&fetched.bytes, limits).map_err(|_| "not JSON")?;
    let object = value.as_object().ok_or("not a JSON object")?;
    if object
        .get("schemaVersion")
        .and_then(Value::as_number)
        .and_then(|n| n.as_u64())
        != Some(2)
    {
        return Err("schemaVersion is not 2");
    }
    let field = optional_string(object, "mediaType")?;
    // As `manifest::parse_document` reads it: the field, else the
    // Content-Type without parameters, in lower case; both must agree.
    let header = fetched.content_type.as_deref().map(|ct| {
        ct.split(';')
            .next()
            .unwrap_or_default()
            .trim_matches([' ', '\t'])
            .to_ascii_lowercase()
    });
    let media_type = match (field, header.as_deref()) {
        (Some(f), Some(h)) if f != h => {
            return Err("mediaType differs from the Content-Type");
        }
        (Some(f), _) => f,
        (None, Some(h)) => h,
        (None, None) => return Err("no mediaType and no Content-Type"),
    };
    if media_type != manifest::OCI_MANIFEST && media_type != manifest::DOCKER_MANIFEST {
        return Err("not an image manifest");
    }
    if object.contains_key("manifests") {
        return Err("a manifest with manifests");
    }
    descriptor(object.get("config").ok_or("no config")?)?;
    let list = object
        .get("layers")
        .and_then(Value::as_array)
        .ok_or("no layers array")?;
    let mut layers = Vec::with_capacity(list.len().min(MAX_SIGNATURES + 1));
    for item in list {
        let layer = item.as_object().ok_or("a layer is not an object")?;
        layers.push(ArtifactLayer {
            descriptor: descriptor(item)?,
            annotations: annotations(layer)?,
        });
    }
    let subject = match object.get("subject") {
        None => None,
        Some(value) => Some(descriptor(value)?.digest),
    };
    Ok(Artifact {
        artifact_type: optional_string(object, "artifactType")?.map(str::to_owned),
        subject,
        layers,
    })
}

/// One entry of a referrers listing.
struct Referrer {
    descriptor: Descriptor,
    artifact_type: Option<String>,
    annotations: Vec<(String, String)>,
}

/// Parses a referrers listing: an OCI index (schema 2, `mediaType` the
/// index's if present) whose `manifests` is an array or `null` (Artifact
/// Registry answers `null`, measured), each entry a descriptor with
/// optional `artifactType` and string annotations; `platform` and other
/// members are not read.
fn parse_listing(
    bytes: &[u8],
    limits: &boneli_json::Limits,
) -> Result<Vec<Referrer>, &'static str> {
    let value = boneli_json::parse(bytes, limits).map_err(|_| "not JSON")?;
    let object = value.as_object().ok_or("not a JSON object")?;
    if object
        .get("schemaVersion")
        .and_then(Value::as_number)
        .and_then(|n| n.as_u64())
        != Some(2)
    {
        return Err("schemaVersion is not 2");
    }
    if optional_string(object, "mediaType")?.is_some_and(|t| t != manifest::OCI_INDEX) {
        return Err("not an OCI index");
    }
    let list = match object.get("manifests") {
        Some(v) if v.is_null() => return Ok(Vec::new()),
        Some(v) => v.as_array().ok_or("manifests is not an array")?,
        None => return Err("no manifests"),
    };
    let mut out = Vec::with_capacity(list.len().min(MAX_SIGNATURES + 1));
    for item in list {
        let entry = item.as_object().ok_or("an entry is not an object")?;
        out.push(Referrer {
            descriptor: descriptor(item)?,
            artifact_type: optional_string(entry, "artifactType")?.map(str::to_owned),
            annotations: annotations(entry)?,
        });
    }
    Ok(out)
}

/// The value of `key` among `annotations`. They come from one JSON
/// object, and `boneli-json` refuses a key that occurs twice (ADR-008),
/// so there is at most one.
fn annotation<'a>(annotations: &'a [(String, String)], key: &str) -> Option<&'a str> {
    annotations
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// What the kept evidence of one subject gave.
enum KeptOutcome {
    /// It verifies under the current trust.
    Pass,
    /// There is none, or it is no longer complete on disk.
    Absent,
    /// It is there and does not verify: the reason.
    Refused(String),
}

/// One `Required` check (module doc).
pub(crate) struct Check<'a, 'c> {
    /// The pull's registry client.
    pub(crate) client: &'a mut Client<'c>,
    /// The store's kept documents, where evidence is kept too.
    pub(crate) documents: &'a mut dyn Documents,
    /// The store root, for the pointer files.
    pub(crate) root: &'a Path,
    /// The image's repository.
    pub(crate) repo: &'a Repository,
    /// The rule's trust.
    pub(crate) trust: &'a Trust,
    /// The document limits of ADR-009 D12, for manifests and listings.
    pub(crate) limits: &'a boneli_json::Limits,
}

impl Check<'_, '_> {
    /// Passes when one candidate verifies for one of `subjects` (module
    /// doc); `Failed` otherwise. An error of the store itself (a kept
    /// artifact or a pointer that cannot be written) fails the pull too.
    pub(crate) fn run(&mut self, subjects: &[Digest]) -> Result<(), PullError> {
        let mut notes = Vec::new();
        for subject in subjects {
            match self.kept(subject)? {
                KeptOutcome::Pass => return Ok(()),
                KeptOutcome::Absent => {}
                KeptOutcome::Refused(why) => notes.push(format!("{subject}: kept evidence: {why}")),
            }
        }
        for subject in subjects {
            let mut found = self.legacy(subject, &mut notes)?;
            if found.is_none() {
                found = self.referrers(subject, &mut notes)?;
            }
            if let Some(pointer) = found {
                let dir = pointers_dir(self.root);
                crate::store::write_durably(
                    &dir,
                    &pointer_path(self.root, subject),
                    pointer.render().as_bytes(),
                )
                .map_err(|e| failed(e.to_string()))?;
                return Ok(());
            }
        }
        let names: Vec<String> = subjects.iter().map(Digest::to_string).collect();
        Err(failed(escape(&format!(
            "signature policy: no trusted signature for {} in {}: {}",
            names.join(" or "),
            self.repo,
            notes.join("; ")
        ))))
    }

    /// The kept evidence of `subject` (module doc, step 1).
    fn kept(&mut self, subject: &Digest) -> Result<KeptOutcome, PullError> {
        let path = pointer_path(self.root, subject);
        let pointer = match crate::store::read_capped(&path, MAX_POINTER_BYTES) {
            Ok(Some(bytes)) => match Pointer::parse(&bytes) {
                Some(pointer) => pointer,
                None => return Ok(KeptOutcome::Absent),
            },
            Ok(None) => return Ok(KeptOutcome::Absent),
            Err(e) => return Err(failed(format!("{}: {e}", path.display()))),
        };
        let Some(manifest) = self.documents.get(&pointer.blobs()[0])? else {
            return Ok(KeptOutcome::Absent);
        };
        let Some(blob) = self.documents.get(&pointer.blobs()[1])? else {
            return Ok(KeptOutcome::Absent);
        };
        let artifact = match parse_artifact(&manifest, self.limits) {
            Ok(artifact) => artifact,
            Err(why) => return Ok(KeptOutcome::Refused(why.to_owned())),
        };
        let mut last = None;
        match pointer {
            Pointer::Legacy { payload, .. } => {
                if artifact.layers.len() > MAX_SIGNATURES {
                    return Ok(KeptOutcome::Refused("too many layers".to_owned()));
                }
                for layer in artifact.layers.iter().filter(|l| {
                    l.descriptor.digest == payload
                        && l.descriptor.media_type == SIMPLE_SIGNING_MEDIA_TYPE
                }) {
                    let pairs = pairs(&layer.annotations);
                    match Evidence::from_cosign_layer(&pairs, &blob.bytes)
                        .and_then(|e| verify(&e, subject.bytes(), self.trust))
                    {
                        Ok(_) => return Ok(KeptOutcome::Pass),
                        Err(refusal) => last = Some(refusal.to_string()),
                    }
                }
            }
            Pointer::Bundle { bundle, .. } => {
                if let Err(why) = bundle_layer(&artifact, subject).and_then(|layer| {
                    (layer.digest == bundle)
                        .then_some(())
                        .ok_or("the bundle is not the manifest's layer")
                }) {
                    return Ok(KeptOutcome::Refused(why.to_owned()));
                }
                match Evidence::from_bundle(&blob.bytes)
                    .and_then(|e| verify(&e, subject.bytes(), self.trust))
                {
                    Ok(_) => return Ok(KeptOutcome::Pass),
                    Err(refusal) => last = Some(refusal.to_string()),
                }
            }
        }
        Ok(KeptOutcome::Refused(last.unwrap_or_else(|| {
            "the manifest has no such layer".to_owned()
        })))
    }

    /// The blob `descriptor`, kept or fetched (at most `max` bytes) and
    /// kept.
    /// The size cap is `get_small_blob`'s, before any request; a kept copy
    /// was fetched under it.
    fn blob(&mut self, descriptor: &Descriptor, max: usize) -> Result<Fetched, Fault> {
        if let Some(kept) = self
            .documents
            .get(&descriptor.digest)
            .map_err(Fault::Store)?
        {
            return Ok(kept);
        }
        let fetched = self
            .client
            .get_small_blob(self.repo, descriptor, max as u64)
            .map_err(Fault::Registry)?;
        self.documents
            .put(&descriptor.digest, &fetched)
            .map_err(Fault::Store)?;
        Ok(fetched)
    }

    /// The `.sig` carrier of `subject` (module doc, step 2).
    fn legacy(
        &mut self,
        subject: &Digest,
        notes: &mut Vec<String>,
    ) -> Result<Option<Pointer>, PullError> {
        let tag = SignatureTag::Sig(*subject);
        let fetched = match self.client.get_tag_document(self.repo, tag, SIG_ACCEPT) {
            Ok(Some(fetched)) => fetched,
            Ok(None) => {
                notes.push(format!("{subject}: .sig: none"));
                return Ok(None);
            }
            Err(e) => {
                notes.push(format!("{subject}: .sig: {}", e.detail()));
                return Ok(None);
            }
        };
        let manifest = Digest::of(&fetched.bytes);
        self.documents.put(&manifest, &fetched)?;
        let artifact = match parse_artifact(&fetched, self.limits) {
            Ok(artifact) => artifact,
            Err(why) => {
                notes.push(format!("{subject}: .sig {manifest}: {why}"));
                return Ok(None);
            }
        };
        let listed = artifact.layers.len();
        if listed > MAX_SIGNATURES {
            notes.push(format!(
                "{subject}: .sig {manifest}: {listed} layers, more than {MAX_SIGNATURES}"
            ));
            return Ok(None);
        }
        let mut reasons = Vec::new();
        for (i, layer) in artifact.layers.iter().enumerate() {
            if layer.descriptor.media_type != SIMPLE_SIGNING_MEDIA_TYPE {
                reasons.push(format!("layer {i}: not a simple-signing layer"));
                continue;
            }
            let payload = match self.blob(&layer.descriptor, MAX_PAYLOAD_BYTES) {
                Ok(payload) => payload,
                Err(Fault::Store(e)) => return Err(e),
                Err(Fault::Registry(e)) => {
                    reasons.push(format!("layer {i}: {}", e.detail()));
                    continue;
                }
            };
            let pairs = pairs(&layer.annotations);
            match Evidence::from_cosign_layer(&pairs, &payload.bytes)
                .and_then(|e| verify(&e, subject.bytes(), self.trust))
            {
                Ok(_) => {
                    return Ok(Some(Pointer::Legacy {
                        manifest,
                        payload: layer.descriptor.digest,
                    }));
                }
                Err(refusal) => reasons.push(format!("layer {i}: {refusal}")),
            }
        }
        notes.push(format!(
            "{subject}: .sig {manifest}: {listed} listed{}",
            parenthesized(&reasons)
        ));
        Ok(None)
    }

    /// The referrers carrier of `subject` (module doc, step 2).
    fn referrers(
        &mut self,
        subject: &Digest,
        notes: &mut Vec<String>,
    ) -> Result<Option<Pointer>, PullError> {
        let (carrier, listing) = match self.client.get_referrers(self.repo, subject) {
            Ok(Some(listing)) => ("referrers", listing),
            Ok(None) => {
                let tag = SignatureTag::Referrers(*subject);
                match self
                    .client
                    .get_tag_document(self.repo, tag, manifest::OCI_INDEX)
                {
                    Ok(Some(listing)) if Digest::of(&listing.bytes) == *subject => {
                        notes.push(format!(
                            "{subject}: referrers: unsupported, tag answers with the subject"
                        ));
                        return Ok(None);
                    }
                    Ok(Some(listing)) => ("referrers tag", listing),
                    Ok(None) => {
                        notes.push(format!("{subject}: referrers: unsupported, tag: none"));
                        return Ok(None);
                    }
                    Err(e) => {
                        notes.push(format!("{subject}: referrers tag: {}", e.detail()));
                        return Ok(None);
                    }
                }
            }
            Err(e) => {
                notes.push(format!("{subject}: referrers: {}", e.detail()));
                return Ok(None);
            }
        };
        let entries = match parse_listing(&listing.bytes, self.limits) {
            Ok(entries) => entries,
            Err(why) => {
                notes.push(format!("{subject}: {carrier}: {why}"));
                return Ok(None);
            }
        };
        let listed = entries.len();
        if listed > MAX_SIGNATURES {
            notes.push(format!(
                "{subject}: {carrier}: {listed} listed, more than {MAX_SIGNATURES}"
            ));
            return Ok(None);
        }
        let mut reasons = Vec::new();
        let mut seen = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            let candidate = entry.artifact_type.as_deref() == Some(BUNDLE_V03_MEDIA_TYPE)
                && annotation(&entry.annotations, PREDICATE_ANNOTATION)
                    .is_some_and(|p| self.trust.predicate_types().iter().any(|t| t == p));
            if !candidate || seen.contains(&entry.descriptor.digest) {
                continue;
            }
            seen.push(entry.descriptor.digest);
            match self.referrer(subject, &entry.descriptor) {
                Ok(pointer) => return Ok(Some(pointer)),
                Err(Fault::Store(e)) => return Err(e),
                Err(Fault::Registry(e)) => reasons.push(format!("entry {i}: {}", e.detail())),
            }
        }
        notes.push(format!(
            "{subject}: {carrier}: {listed} listed, {} candidates{}",
            seen.len(),
            parenthesized(&reasons)
        ));
        Ok(None)
    }

    /// One referrer candidate: its manifest, its bundle and the verdict. A
    /// refusal comes back as `Fault::Registry` with a fixed reason.
    fn referrer(&mut self, subject: &Digest, entry: &Descriptor) -> Result<Pointer, Fault> {
        let fetched = match self.documents.get(&entry.digest).map_err(Fault::Store)? {
            Some(kept) => kept,
            None => {
                let fetched = self
                    .client
                    .get_manifest(self.repo, &entry.digest, Some(entry.size))
                    .map_err(|e| Fault::Registry(failed(e.detail().to_owned())))?;
                self.documents
                    .put(&entry.digest, &fetched)
                    .map_err(Fault::Store)?;
                fetched
            }
        };
        let refused = |why: &str| Fault::Registry(failed(why.to_owned()));
        let artifact = parse_artifact(&fetched, self.limits).map_err(refused)?;
        let layer = bundle_layer(&artifact, subject).map_err(refused)?;
        let bundle = self.blob(layer, MAX_BUNDLE_BYTES)?;
        match Evidence::from_bundle(&bundle.bytes)
            .and_then(|e| verify(&e, subject.bytes(), self.trust))
        {
            Ok(_) => Ok(Pointer::Bundle {
                manifest: entry.digest,
                bundle: layer.digest,
            }),
            Err(refusal) => Err(refused(&refusal.to_string())),
        }
    }
}

/// The bundle layer of a referrer manifest: the manifest must name
/// `subject` and the bundle artifact type, and hold exactly one layer of
/// the bundle media type.
fn bundle_layer<'a>(
    artifact: &'a Artifact,
    subject: &Digest,
) -> Result<&'a Descriptor, &'static str> {
    if artifact.subject.as_ref() != Some(subject) {
        return Err("the referrer does not name this subject");
    }
    if artifact.artifact_type.as_deref() != Some(BUNDLE_V03_MEDIA_TYPE) {
        return Err("the referrer is not a bundle v0.3");
    }
    match artifact.layers.as_slice() {
        [layer] if layer.descriptor.media_type == BUNDLE_V03_MEDIA_TYPE => Ok(&layer.descriptor),
        _ => Err("the referrer does not hold exactly one bundle layer"),
    }
}

/// A failure inside one candidate: the store's own (which fails the pull)
/// or the registry's and the verdict's (which only refuse the candidate).
enum Fault {
    Store(PullError),
    Registry(PullError),
}

/// ` (a, b)` for reasons `a` and `b`, nothing for none.
fn parenthesized(reasons: &[String]) -> String {
    if reasons.is_empty() {
        String::new()
    } else {
        format!(" ({})", reasons.join(", "))
    }
}

/// The annotations as the pairs `Evidence::from_cosign_layer` takes.
fn pairs(annotations: &[(String, String)]) -> Vec<(&str, &str)> {
    annotations
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// `text` with every character outside printable ASCII escaped
/// (`\n`, `\u{202e}`, ...), so the failure detail carries no control,
/// bidi or look-alike character a registry chose (module doc).
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if (' '..='~').contains(&c) {
            out.push(c);
        } else {
            let _ = write!(out, "{}", c.escape_unicode());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Pointer, escape, parse_artifact, parse_listing};
    use crate::reference::Digest;
    use crate::registry::Fetched;

    fn limits() -> boneli_json::Limits {
        boneli_json::Limits::new(4_194_304, 16, 65_536).expect("limits")
    }

    /// Every prefix of the real `.sig` and referrer manifests and of the
    /// real referrers listing is refused with an error, never a panic;
    /// the whole documents parse.
    #[test]
    fn truncated_inputs_never_panic() {
        let manifests: [&[u8]; 2] = [
            include_bytes!("../tests/data/chainguard-node.sig.json"),
            include_bytes!("../tests/data/cosign.referrer.json"),
        ];
        let listing: &[u8] = include_bytes!("../tests/data/cosign.referrers-tag.json");
        for doc in manifests {
            let fetched = |bytes: &[u8]| Fetched {
                bytes: bytes.to_vec(),
                content_type: Some(crate::manifest::OCI_MANIFEST.to_owned()),
            };
            assert!(parse_artifact(&fetched(doc), &limits()).is_ok());
            for end in 0..doc.len() {
                assert!(
                    parse_artifact(&fetched(&doc[..end]), &limits()).is_err(),
                    "{end}"
                );
            }
        }
        assert_eq!(parse_listing(listing, &limits()).map(|l| l.len()), Ok(2));
        assert!(parse_listing(&listing[..0], &limits()).is_err());
        for end in 0..listing.len() {
            assert!(parse_listing(&listing[..end], &limits()).is_err(), "{end}");
        }
    }

    fn digest(n: u8) -> Digest {
        Digest::from_bytes([n; 32])
    }

    /// Rendering, parsing and comparing agree for both kinds, and any other
    /// byte makes the file absent.
    #[test]
    fn pointer_round_trip_and_exact() {
        for pointer in [
            Pointer::Legacy {
                manifest: digest(1),
                payload: digest(2),
            },
            Pointer::Bundle {
                manifest: digest(3),
                bundle: digest(4),
            },
        ] {
            let text = pointer.render();
            assert_eq!(Pointer::parse(text.as_bytes()), Some(pointer));
            // What parses renders back to the same bytes, for every
            // one-byte change of a valid line.
            for i in 0..text.len() {
                for b in [b' ', b'\n', b'\r', b'0', b'A', b'a', b':', 0xff] {
                    let mut bytes = text.clone().into_bytes();
                    bytes[i] = b;
                    if let Some(p) = Pointer::parse(&bytes) {
                        assert_eq!(p.render().as_bytes(), &bytes[..]);
                    }
                }
            }
            let line = text.trim_end();
            let upper = text.replacen("sha256:01", "sha256:0A", 1);
            for bad in [
                line.to_owned(),
                format!("{text}\n"),
                format!("{line}\r\n"),
                format!(" {text}"),
                format!("{line} \n"),
                text.replacen(' ', "  ", 1),
                text.replacen("legacy", "Legacy", 1)
                    .replacen("bundle", "Bundle", 1),
                text.replacen("sha256:", "sha512:", 1),
                upper,
                format!("{line} {}\n", digest(5)),
                text.replacen(' ', "\t", 1),
                String::new(),
            ] {
                if bad != text {
                    assert_eq!(Pointer::parse(bad.as_bytes()), None, "{bad:?}");
                }
            }
            assert_eq!(Pointer::parse(b"\xffxx"), None);
        }
        assert_eq!(
            Pointer::Legacy {
                manifest: digest(1),
                payload: digest(2)
            }
            .render(),
            format!("legacy {} {}\n", digest(1), digest(2))
        );
    }

    fn artifact(json: &str, content_type: Option<&str>) -> Result<(), &'static str> {
        let fetched = Fetched {
            bytes: json.as_bytes().to_vec(),
            content_type: content_type.map(str::to_owned),
        };
        parse_artifact(&fetched, &limits()).map(|_| ())
    }

    /// The shapes an artifact manifest and a listing must have: schema 2,
    /// a manifest media type (by the field, else the `Content-Type`,
    /// which must agree), a config, layers with string annotations, an
    /// OCI index listing whose `manifests` is an array or `null`.
    #[test]
    fn artifact_and_listing_shapes() {
        let config = r#""config":{"mediaType":"x","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1}"#;
        let oci = crate::manifest::OCI_MANIFEST;
        let docker = crate::manifest::DOCKER_MANIFEST;
        let ok = format!(r#"{{"schemaVersion":2,"mediaType":"{oci}",{config},"layers":[]}}"#);
        assert_eq!(artifact(&ok, None), Ok(()));
        assert_eq!(
            artifact(&ok, Some(&format!("{oci}; charset=utf-8"))),
            Ok(())
        );
        let docker_doc = format!(r#"{{"schemaVersion":2,{config},"layers":[]}}"#);
        assert_eq!(artifact(&docker_doc, Some(docker)), Ok(()));
        for (doc, ct) in [
            (ok.replace("\"schemaVersion\":2", "\"schemaVersion\":1"), None),
            (ok.clone(), Some(docker)),
            (docker_doc.clone(), None),
            (docker_doc.clone(), Some(crate::manifest::OCI_INDEX)),
            (ok.replace(oci, crate::manifest::OCI_INDEX), None),
            (ok.replace("\"layers\":[]", "\"layers\":[],\"manifests\":[]"), None),
            (ok.replace(&format!("{config},"), ""), None),
            (ok.replace("\"layers\":[]", "\"layers\":{}"), None),
            (ok.replace("\"layers\":[]", "\"layers\":[{\"mediaType\":\"x\",\"digest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\",\"size\":1,\"annotations\":{\"k\":1}}]"), None),
            (ok.replace("\"layers\":[]", "\"layers\":[],\"artifactType\":7"), None),
            (ok.replace("\"layers\":[]", "\"layers\":[],\"subject\":{}"), None),
        ] {
            assert!(artifact(&doc, ct).is_err(), "{doc} {ct:?}");
        }
        let index = crate::manifest::OCI_INDEX;
        for good in [
            format!(r#"{{"schemaVersion":2,"mediaType":"{index}","manifests":[]}}"#),
            format!(r#"{{"schemaVersion":2,"mediaType":"{index}","manifests":null}}"#),
            r#"{"schemaVersion":2,"manifests":[]}"#.to_owned(),
        ] {
            assert!(parse_listing(good.as_bytes(), &limits()).is_ok(), "{good}");
        }
        for bad in [
            format!(r#"{{"schemaVersion":1,"mediaType":"{index}","manifests":[]}}"#),
            format!(r#"{{"schemaVersion":2,"mediaType":"{oci}","manifests":[]}}"#),
            format!(
                r#"{{"schemaVersion":2,"mediaType":"{}","manifests":[]}}"#,
                crate::manifest::DOCKER_LIST
            ),
            format!(r#"{{"schemaVersion":2,"mediaType":"{index}"}}"#),
            format!(r#"{{"schemaVersion":2,"mediaType":"{index}","manifests":{{}}}}"#),
            format!(r#"{{"schemaVersion":2,"mediaType":"{index}","manifests":[7]}}"#),
            format!(
                r#"{{"schemaVersion":2,"mediaType":"{index}","manifests":[{{"mediaType":"x","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":1,"artifactType":[]}}]}}"#
            ),
        ] {
            assert!(parse_listing(bad.as_bytes(), &limits()).is_err(), "{bad}");
        }
    }

    #[test]
    fn escape_keeps_printable_ascii_only() {
        assert_eq!(escape("a b~"), "a b~");
        assert_eq!(
            escape("a\nb\u{1b}[31m\u{202e}x"),
            "a\\u{a}b\\u{1b}[31m\\u{202e}x"
        );
        assert_eq!(escape("\u{430}"), "\\u{430}");
    }
}
