//! The lease of a pulled root filesystem (ADR-025, D2): its layer
//! directories, its image config and a pin on each of its layers.

use std::path::PathBuf;

use boneli_app::RootfsRef;

use crate::layers::LayerPin;
use crate::manifest::ImageConfig;

/// A pulled root filesystem with its layers pinned: while the lease lives,
/// no store removes one of its layers. One descriptor per distinct layer;
/// dropping the lease releases them. The Sandbox adapter (#8) holds it
/// from before the layers are mounted until the sandbox is destroyed.
///
/// Built by [`crate::OciImageStore::pull_leased`] and
/// [`crate::OciImageStore::lease`].
#[derive(Debug)]
pub struct Lease {
    rootfs: RootfsRef,
    layers: Vec<PathBuf>,
    config: ImageConfig,
    _pins: Vec<LayerPin>,
}

impl Lease {
    /// A lease of `rootfs` whose `layers` are pinned by `pins`.
    pub(crate) fn new(
        rootfs: RootfsRef,
        layers: Vec<PathBuf>,
        config: ImageConfig,
        pins: Vec<LayerPin>,
    ) -> Lease {
        Lease {
            rootfs,
            layers,
            config,
            _pins: pins,
        }
    }

    /// The handle the store issued for the root filesystem.
    pub fn rootfs(&self) -> &RootfsRef {
        &self.rootfs
    }

    /// The layer directories, bottom first, the order
    /// `boneli_sys::Root.layers` takes. A `diff_id` that appears more than
    /// once in the image keeps only its topmost position, which leaves the
    /// merged view unchanged.
    pub fn layers(&self) -> &[PathBuf] {
        &self.layers
    }

    /// The image config: platform, `diff_ids` and the runtime fields the
    /// sandbox starts the image with.
    pub fn config(&self) -> &ImageConfig {
        &self.config
    }
}
