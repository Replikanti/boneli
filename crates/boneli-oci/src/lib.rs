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
#![doc(test(attr(forbid(unsafe_code))))]

mod error;
mod gzip;
mod layers;
mod limits;
#[cfg(test)]
mod scratch;
mod tar;
mod unpack;
mod zstd;

pub use error::Error;
pub use layers::LayerCache;
pub use limits::{Budget, Limits};
pub use unpack::{Compression, LayerStats, unpack};
