//! The lease of a pulled root filesystem (ADR-025, D2): its layer
//! directories, its image config and a pin on each of its layers.

use std::os::fd::OwnedFd;
use std::path::PathBuf;

use boneli_app::RootfsRef;

use crate::error::Error;
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
    pins: Vec<LayerPin>,
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
            pins,
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

    /// One more pin per distinct layer, each a descriptor of its own: a
    /// new read-only open file description of the layer's lock file with
    /// its own shared lock (ADR-025, D2). They exist for the Sandbox
    /// adapter (#8), whose pins must live exactly as long as the mounts,
    /// not as long as the runner: it hands them to a holder process in
    /// the sandbox's cgroup, outside the workload's PID namespace, which
    /// dies with the sandbox. Never to the workload itself, which could
    /// upgrade a pin to `LOCK_EX` or reopen the host file (ADR-025, D2). A
    /// descriptor pins its layer while any process holds it, after this
    /// lease is dropped and after the runner is gone; whoever holds it can
    /// release only its own pin (`close`, `LOCK_UN`), never this lease's.
    /// Each carries `O_CLOEXEC` until the caller hands it on.
    pub fn pin_descriptors(&self) -> Result<Vec<OwnedFd>, Error> {
        self.pins.iter().map(LayerPin::descriptor).collect()
    }
}
