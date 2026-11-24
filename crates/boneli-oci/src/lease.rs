//! The lease of a pulled root filesystem (ADR-025, D2): its layer
//! directories, its image config and a pin on each of its layers.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

use boneli_app::RootfsRef;
use boneli_private_dir::lock::HandOff;

use crate::error::Error;
use crate::evict;
use crate::layers::LayerPin;
use crate::manifest::ImageConfig;

/// A pulled root filesystem with its layers pinned: while the lease lives,
/// no store removes one of its layers. One descriptor per distinct layer;
/// dropping the lease stamps each layer and each of the image's documents
/// as used now, so a sandbox that ran for hours does not look hours old to
/// the next trim, and then releases them (ADR-025, D5). The Sandbox adapter (#8) holds it
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
    /// The image's documents on disk (index, manifest, config), stamped
    /// with the layers when the lease is dropped.
    documents: Vec<PathBuf>,
}

impl Lease {
    /// A lease of `rootfs` whose `layers` are pinned by `pins`.
    pub(crate) fn new(
        rootfs: RootfsRef,
        layers: Vec<PathBuf>,
        config: ImageConfig,
        pins: Vec<LayerPin>,
        documents: Vec<PathBuf>,
    ) -> Lease {
        Lease {
            rootfs,
            layers,
            config,
            pins,
            documents,
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
    /// Each carries `O_CLOEXEC` until the caller hands it on. When one
    /// fails, the pins already taken are released by an explicit unlock,
    /// not the close alone (#98; the rule of ADR-030, D1).
    pub fn pin_descriptors(&self) -> Result<Vec<OwnedFd>, Error> {
        descriptors(&self.pins, &mut |_| {})
    }
}

/// [`Lease::pin_descriptors`] over `pins`, with `reopened(file)` run right
/// after each new pin is taken: a no-op in production, the seam a test
/// hands a copy of a pin to a child through.
fn descriptors(pins: &[LayerPin], reopened: &mut dyn FnMut(&File)) -> Result<Vec<OwnedFd>, Error> {
    // An error drops `taken`, which unlocks the pins already made (#98,
    // ADR-030).
    let mut taken = HandOff::new();
    for pin in pins {
        pin.descriptor(&mut taken)?;
        if let Some(file) = taken.last() {
            reopened(file);
        }
    }
    Ok(taken.hand_on())
}

impl Drop for Lease {
    /// Stamps every layer's sidecar and every document while the pins are
    /// still held (the fields drop after this), best effort: a failure
    /// only changes the eviction order (ADR-025, D5). Without the
    /// documents, the image used last would be the first that can no
    /// longer be leased (review of #99).
    fn drop(&mut self) {
        for layer in &self.layers {
            let mut sidecar = layer.as_os_str().to_owned();
            sidecar.push(".stats");
            evict::stamp(std::path::Path::new(&sidecar));
        }
        for document in &self.documents {
            evict::stamp(document);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::layers::{LayerCache, hex, layer_locks_dir};
    use crate::lock::tests::{Holder, is_held};
    use crate::scratch::ScratchDir;

    /// A pin `pin_descriptors` took before a later one failed is released
    /// by an explicit unlock, not by the close alone, so a child that a
    /// thread spawned, holding a copy of it until its exec, does not keep
    /// the layer from a trim (#98). The second layer's lock file is
    /// replaced, so its reopen fails with `LockChanged`.
    #[test]
    fn abandoned_pin_descriptors_are_released_with_a_child_copy() {
        let scratch = ScratchDir::new("lease-abandoned");
        let root = scratch.path();
        let cache = LayerCache::new(root).expect("cache");
        let (first, second) = ([1; 32], [2; 32]);
        let pins = [
            cache.pin(&first).expect("pin the first layer"),
            cache.pin(&second).expect("pin the second layer"),
        ];
        let first_lock = layer_locks_dir(root).join(hex(&first));
        let second_lock = layer_locks_dir(root).join(hex(&second));
        std::fs::remove_file(&second_lock).expect("unlink");
        std::fs::write(&second_lock, b"").expect("re-create");
        let mut holders = Vec::new();
        match super::descriptors(&pins, &mut |file| holders.push(Holder::spawn(file))) {
            Err(Error::LockChanged(p)) => assert_eq!(p, second_lock),
            other => panic!("the second reopen must fail: {other:?}"),
        }
        assert_eq!(holders.len(), 1, "one pin taken before the failure");
        let [first_pin, second_pin] = pins;
        drop(first_pin);
        assert!(
            !is_held(&first_lock),
            "the child's copy of the abandoned pin kept the layer locked"
        );
        drop(second_pin);
        drop(holders);
    }
}
