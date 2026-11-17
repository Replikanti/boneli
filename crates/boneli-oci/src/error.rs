//! Errors of the OCI image store.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Everything that can go wrong while unpacking or caching a layer.
#[derive(Debug)]
pub enum Error {
    /// The `Limits`, `FetchLimits` or `Timeouts` are unusable: a zero.
    InvalidLimits(&'static str),
    /// A `Registry` host is not a host the client could dial (ADR-009,
    /// D10).
    InvalidRegistry(String),
    /// Reading the layer stream failed.
    Read(io::Error),
    /// The gzip framing is invalid (ADR-009, D5).
    Gzip(&'static str),
    /// The zstd stream is invalid, or its window is above 128 MiB
    /// (ADR-009, D5).
    Zstd(String),
    /// The tar framing is invalid, truncated or uses a refused feature
    /// (ADR-009, D4).
    Tar(&'static str),
    /// An entry breaks the path, type or whiteout rules (ADR-009, D2, D3).
    Entry {
        /// The entry's path in the archive, lossily rendered.
        path: String,
        /// The rule it breaks.
        reason: &'static str,
    },
    /// Writing the layer tree failed, for example with `ENAMETOOLONG`.
    Write {
        /// The path, relative to the layer, lossily rendered.
        path: String,
        /// The error.
        source: io::Error,
    },
    /// A `boneli-sys` layer primitive failed.
    Sys {
        /// The path, relative to the layer, lossily rendered.
        path: String,
        /// The error.
        source: boneli_sys::Error,
    },
    /// A limit was exceeded (ADR-009, D7).
    Limit {
        /// Which limit.
        what: &'static str,
        /// Its value, inclusive.
        max: u64,
    },
    /// The uncompressed layer does not hash to its `diff_id`.
    DiffId {
        /// The expected digest, `sha256:<hex>`.
        expected: String,
        /// The digest of the bytes read.
        actual: String,
    },
    /// A file of the layer cache could not be read or written.
    Cache {
        /// The file.
        path: PathBuf,
        /// The error.
        source: io::Error,
    },
    /// A layer's sidecar is malformed (ADR-009, D8).
    Sidecar(PathBuf),
    /// The store's layer directory treats names that differ in case or in
    /// Unicode normalization as one (ADR-009, D8).
    CaseInsensitive(PathBuf),
    /// The store root is unusable (ADR-009, D8): not absolute, not UTF-8,
    /// a name the overlay mount options cannot carry, not a directory, not
    /// private or not the caller's.
    Root {
        /// The root as given, or as resolved.
        path: PathBuf,
        /// The rule it breaks.
        reason: &'static str,
    },
    /// The store's filesystem cannot hold the overlay format of D1: no 0:0
    /// whiteouts or no `user.*` extended attributes.
    Unsupported {
        /// Where the probe ran.
        path: PathBuf,
        /// What is missing, and why, as the probe saw it.
        detail: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLimits(what) => write!(f, "invalid limits: {what} must not be zero"),
            Error::InvalidRegistry(what) => write!(f, "invalid registry: {what}"),
            Error::Read(e) => write!(f, "reading the layer failed: {e}"),
            Error::Gzip(what) => write!(f, "invalid gzip stream: {what}"),
            Error::Zstd(what) => write!(f, "invalid zstd stream: {what}"),
            Error::Tar(what) => write!(f, "invalid tar archive: {what}"),
            Error::Entry { path, reason } => write!(f, "layer entry {path:?}: {reason}"),
            Error::Write { path, source } => write!(f, "writing {path:?} failed: {source}"),
            Error::Sys { path, source } => write!(f, "creating {path:?} failed: {source}"),
            Error::Limit { what, max } => write!(f, "{what} exceeds the limit of {max}"),
            Error::DiffId { expected, actual } => {
                write!(
                    f,
                    "layer digest {actual} does not match its diff_id {expected}"
                )
            }
            Error::Cache { path, source } => {
                write!(f, "layer cache file {} failed: {source}", path.display())
            }
            Error::Sidecar(path) => write!(f, "malformed layer sidecar {}", path.display()),
            Error::CaseInsensitive(path) => write!(
                f,
                "{} is case-insensitive or normalizes names; a layer store needs exact names",
                path.display()
            ),
            Error::Root { path, reason } => {
                write!(f, "store root {}: {reason}", path.display())
            }
            Error::Unsupported { path, detail } => write!(
                f,
                "the filesystem of {} cannot hold overlay layers: {detail}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Read(e) => Some(e),
            Error::Write { source, .. } => Some(source),
            Error::Sys { source, .. } => Some(source),
            Error::Cache { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// An error raised inside a `Read` adapter of the pipeline (a decoder or
/// the counting reader), carried through `io::Error` and turned back into
/// an [`Error`] by [`from_io`].
#[derive(Debug)]
pub(crate) struct Carried(pub(crate) Error);

impl fmt::Display for Carried {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Carried {}

/// Wraps `e` for a `Read` implementation.
pub(crate) fn carry(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, Carried(e))
}

/// The pipeline error inside `e`, or `e` as a read error. An unexpected end
/// of the stream is a truncated archive.
pub(crate) fn from_io(e: io::Error) -> Error {
    if e.get_ref().is_some_and(|inner| inner.is::<Carried>()) {
        if let Some(inner) = e.into_inner()
            && let Ok(carried) = inner.downcast::<Carried>()
        {
            return carried.0;
        }
        return Error::Tar("unreadable stream");
    }
    if e.kind() == io::ErrorKind::UnexpectedEof {
        return Error::Tar("truncated archive");
    }
    Error::Read(e)
}

/// Why fetching an image from a registry failed, classified the way the
/// `ImageStore` port reports it (ADR-009, D11). The detail is never blank
/// (ADR-004, D4); it names hosts, digests and statuses, never a token or a
/// response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullError {
    /// The registry has no image under this reference: a `404` on a
    /// manifest, a `401` on a manifest with a fresh token before anything
    /// was authorized (Docker Hub's answer for an unknown repository), or
    /// no manifest for the platform.
    NotFound(String),
    /// Anything else: an invalid reference, a refused host, a network,
    /// TLS or HTTP error, a status other than the ones above, a document
    /// outside the accepted subset or a digest mismatch.
    Failed(String),
}

impl PullError {
    /// The detail, never blank.
    pub fn detail(&self) -> &str {
        match self {
            PullError::NotFound(detail) | PullError::Failed(detail) => detail,
        }
    }
}

impl fmt::Display for PullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PullError::NotFound(detail) => write!(f, "image not found: {detail}"),
            PullError::Failed(detail) => write!(f, "image pull failed: {detail}"),
        }
    }
}

impl std::error::Error for PullError {}

/// A `PullError::Failed` with `detail`.
pub(crate) fn failed(detail: impl Into<String>) -> PullError {
    PullError::Failed(detail.into())
}
