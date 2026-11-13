//! The `ImageStore` port: container images as a root filesystem for the
//! sandbox (ADR-004, D1).
//!
//! Minimal on purpose: the real adapter (#7) pulls and unpacks OCI images
//! and may add operations and clauses under the extension rule of ADR-004.

use alloc::string::String;
use core::fmt;

/// An image to pull. The field is called `platform`, not by the usual
/// short name, which the core token scan bans (ADR-001).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImageRef {
    /// The repository name, for example `library/postgres`.
    pub name: String,
    /// The content digest of the manifest, for example `sha256:...`.
    pub digest: String,
    /// The platform to pull, for example `linux/amd64`.
    pub platform: String,
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
    fn pull(&self, image: &ImageRef) -> Result<RootfsRef, ImageError>;
}
