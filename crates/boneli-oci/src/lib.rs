//! Boneli adapter: the OCI image store (#7, ADR-009).
//!
//! This part unpacks image layers. Each layer is unpacked into its own
//! directory keyed by its `diff_id`, in the overlay format that
//! `boneli_sys::Root.layers` mounts as it is: a whiteout is a 0:0
//! character device, an opaque directory carries `user.overlay.opaque=y`
//! (ADR-009, D1; ADR-007, D7).
//!
//! - [`unpack`] reads one layer stream (plain, gzip or zstd) into an empty
//!   directory under the path, type and metadata rules of ADR-009 (D2,
//!   D3), and returns its [`LayerStats`]: the SHA-256 of the uncompressed
//!   stream, its size and entry count.
//! - [`LayerCache`] keeps committed layers by `diff_id` and commits a new
//!   one only when its bytes hash to it (D8).
//! - [`Limits`] and [`Budget`] bound every pull (D7); every violation is an
//!   [`Error`], never a panic or an unbounded allocation.
//!
//! Part 2 adds the registry client (D9 to D12):
//!
//! - [`Reference`] parses an image's registry host, repository, digest and
//!   platform before any request is made.
//! - [`Client`] fetches manifests and blobs from an allowlisted
//!   [`Registry`] through a [`Dial`] ([`TlsDial`] in production), with the
//!   anonymous token flow, checks every byte against its digest, and
//!   classifies failures as a [`PullError`].
//!
//! Part 3 adds the store:
//!
//! - [`OciImageStore`] is the `ImageStore` adapter: it opens a private
//!   root, pulls through the client, keeps documents and layers by digest
//!   and hands out the layer directories and the image config of a pulled
//!   root filesystem as a [`Lease`]; [`StoreConfig`] holds the values
//!   ADR-009 states.
//!
//! Locks (ADR-025): every store holds an owner lock under the root while
//! it lives, which tells other stores, in any namespace and after a
//! reboot, whether the owner of a temporary name is gone. Every user of a
//! layer holds a [`LayerPin`] on it: a pull pins all layers of its image
//! before it fetches one, and a [`Lease`] keeps them pinned while a
//! sandbox uses them.
//!
//! Eviction (ADR-025, D4 to D8): a trim at `open`, at the end of every
//! pull and in [`OciImageStore::trim`] evicts the least recently used
//! layers, documents and kept layer blobs that nobody pins, until the
//! store's accounted bytes are at or under [`StoreConfig::cache_budget`]
//! ([`CACHE_BUDGET_BYTES`] by default), and reports it as a
//! [`TrimReport`].
//!
//! Signatures (ADR-029): a [`SignaturePolicy`] in
//! [`StoreConfig::signatures`] names the registries and repositories whose
//! images must carry a signature that `boneli-sigstore` verifies under a
//! `boneli_sigstore::Trust`: a cosign `.sig` layer or a Sigstore bundle
//! v0.3 found through the referrers API or its tag schema, and, only under
//! a trust with provenance claims, a cosign `.att` attestation (ADR-036),
//! over the digest the reference names or the platform manifest it
//! selects. Under a
//! [`Requirement::Required`] rule the pull is `Failed` before any layer
//! blob is requested unless one candidate verifies; the evidence that
//! verified is kept and verified again, offline, on every later pull. The
//! default, [`SignaturePolicy::off`], checks nothing and sends exactly the
//! requests of ADR-009.
//!
//! Origin (ADR-032): a reference an agent chose
//! (`boneli_app::ImageOrigin::Agent`) passes only under a `Required` rule
//! or an operator [`AgentExemption`] for its repository or a prefix of it
//! ([`AgentExemption::docker_official_images`] is the documented
//! first-stack one), and is `Failed` before any request otherwise. The
//! pull reports the exemption that admitted it ([`Lease::exemption`],
//! `boneli_app::Pulled::exemption`).
#![doc(test(attr(forbid(unsafe_code))))]

mod auth;
mod error;
mod evict;
mod gzip;
mod layers;
mod lease;
mod limits;
mod lock;
mod manifest;
mod policy;
mod reference;
mod registry;
#[cfg(test)]
mod scratch;
mod signatures;
mod store;
mod tar;
mod unpack;
mod url;
mod zstd;

// The `Dial` seam lives in boneli-https since ADR-014 (D4); re-exported so
// the registry client's callers keep their paths.
pub use boneli_https::{Dial, Stream, TlsDial};
pub use error::{Error, PullError};
pub use evict::TrimReport;
pub use layers::{LayerCache, LayerPin};
pub use lease::Lease;
pub use limits::{Budget, Limits};
pub use manifest::{Descriptor, Document, Entry, ImageConfig, Index, Layer, Manifest};
pub use policy::{
    AgentExemption, Decision, ExemptScope, PolicyRule, RepoScope, Requirement, SignaturePolicy,
};
pub use reference::{Digest, Platform, Reference, RegistryHost, Repository};
pub use registry::{
    Client, FetchLimits, Fetched, MAX_REDIRECTS, Registry, Resolved, Timeouts, select,
};
pub use signatures::MAX_SIGNATURES;
pub use store::{
    BLOCK_ALLOWANCE, CACHE_BUDGET_BYTES, CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT, IO_TIMEOUT,
    MAX_BLOB_BYTES, MAX_DEPTH, MAX_DOCUMENT_BYTES, MAX_DOCUMENT_DEPTH, MAX_DOCUMENT_VALUES,
    MAX_HEAD_BYTES, MAX_HEADERS, MAX_IMAGE_BYTES, MAX_IMAGE_ENTRIES, MAX_LAYER_BYTES, MAX_LAYERS,
    MAX_PULL_BYTES, MAX_SPECIAL_BYTES, MAX_TOKEN_BYTES, MIN_RATE, OciImageStore, SETUP_TIMEOUT,
    StoreConfig,
};
pub use unpack::{Compression, LayerStats, unpack};
