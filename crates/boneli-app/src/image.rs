//! The `ImageStore` port: container images as a root filesystem for the
//! sandbox (ADR-004, D1).
//!
//! Minimal on purpose: the real adapter (#7) pulls and unpacks OCI images
//! and may add operations and clauses under the extension rule of ADR-004.
//!
//! Every reference says who chose it ([`ImageOrigin`], ADR-032): the
//! store checks a reference an agent chose more strictly than one the
//! operator configured, and a pull reports the operator exemption that
//! let an agent's image through ([`Pulled::exemption`]), so the caller can
//! write it to its run log.

use alloc::string::String;
use core::fmt;

/// Who chose an image reference (ADR-032). Set where the reference enters
/// the runner and never changed after: there is no default and no third
/// value, so every place that builds an [`ImageRef`] has to say it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImageOrigin {
    /// The runner's operator configured it: a hand-written replica
    /// config, a CLI argument, a job config.
    Operator,
    /// An agent job produced it or could have changed it, a reference
    /// copied from the repository under work included.
    Agent,
}

/// An image to pull. The field is called `platform`, not by the usual
/// short name, which the core token scan bans (ADR-001).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImageRef {
    /// The repository name, for example `library/postgres`. It may start
    /// with a registry host (`registry.example:5000/team/app`); without
    /// one, the store's default registry applies.
    pub name: String,
    /// The content digest of an image index or of a manifest, for example
    /// `sha256:...`; for an index the store picks the manifest of
    /// [`ImageRef::platform`].
    pub digest: String,
    /// The platform to pull, for example `linux/amd64`.
    pub platform: String,
    /// Who chose the reference (ADR-032).
    pub origin: ImageOrigin,
}

/// The operator exemption that let an image an agent chose through
/// without a signature check (ADR-032): what the caller writes to its run
/// log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageExemption {
    /// The registry's name, for example `docker.io`.
    pub registry: String,
    /// One repository exactly, which never ends in `/`, or a prefix of
    /// repositories, which always does (`library/`).
    pub scope: String,
}

/// What a pull gives: the root filesystem and, for an image an agent
/// chose, the exemption that admitted it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pulled {
    /// The root filesystem.
    pub rootfs: RootfsRef,
    /// The exemption that admitted the image; `None` when it was checked
    /// under a rule that requires a signature, and always for a
    /// reference the operator chose.
    pub exemption: Option<ImageExemption>,
}

/// The store's handle to an unpacked root filesystem, which a sandbox is
/// created from. Opaque; the store issues it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RootfsRef(String);

impl RootfsRef {
    /// Wraps a handle the store issued.
    pub fn new(reference: String) -> RootfsRef {
        RootfsRef(reference)
    }

    /// The handle as issued.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why the image store did not do what was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// The registry has no image under this reference.
    NotFound,
    /// The pull or the unpacking failed.
    Failed {
        /// What went wrong, as the store reports it.
        detail: String,
    },
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImageError::NotFound => f.write_str("no image under this reference"),
            ImageError::Failed { detail } => write!(f, "the image pull failed: {detail}"),
        }
    }
}

impl core::error::Error for ImageError {}

/// Images as root filesystems.
pub trait ImageStore {
    /// Pulls the image and returns its root filesystem. Pulling the same
    /// reference again returns the same root filesystem.
    ///
    /// A reference an agent chose that the adapter's policy does not
    /// admit is `Failed` with a detail, never `NotFound`, whether the
    /// registry has the image or not (ADR-032). A pull of a reference the
    /// operator chose never reports an exemption.
    fn pull(&self, image: &ImageRef) -> Result<Pulled, ImageError>;
}
