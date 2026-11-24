//! [`MemoryImageStore`]: the `ImageStore` port in memory.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use boneli_app::{
    ImageError, ImageExemption, ImageOrigin, ImageRef, ImageStore, Pulled, RootfsRef,
};

use crate::lock;

/// An image without its origin: what the store keys images by, so the
/// origin never changes the root filesystem (ADR-032).
type Key = (String, String, String);

fn key(image: &ImageRef) -> Key {
    (
        image.name.clone(),
        image.digest.clone(),
        image.platform.clone(),
    )
}

/// An `ImageStore` with a fixed set of images. The first pull of an image
/// issues `rootfs-<n>` from a counter starting at 1, and every later pull
/// of the same reference returns it again; an image outside the set is
/// `NotFound`, and a tampered one (its bytes do not match its digest)
/// fails on every pull. A reference the agent chose fails unless an
/// exemption names its image name (ADR-032); the check comes first, as
/// in the real adapter, so it is `Failed` even for an image outside the
/// set.
#[derive(Debug, Default)]
pub struct MemoryImageStore {
    images: BTreeSet<Key>,
    tampered: BTreeSet<Key>,
    exemptions: BTreeMap<String, ImageExemption>,
    pulled: Mutex<BTreeMap<Key, RootfsRef>>,
}

impl MemoryImageStore {
    /// A store that has these images.
    pub fn new(images: Vec<ImageRef>) -> MemoryImageStore {
        MemoryImageStore {
            images: images.iter().map(key).collect(),
            tampered: BTreeSet::new(),
            exemptions: BTreeMap::new(),
            pulled: Mutex::new(BTreeMap::new()),
        }
    }

    /// The same store, whose registry also serves these images with bytes
    /// that do not match their digest (the `tampered-refused` clause).
    pub fn with_tampered(mut self, tampered: Vec<ImageRef>) -> MemoryImageStore {
        self.tampered = tampered.iter().map(key).collect();
        self
    }

    /// The same store, which admits a reference the agent chose when its
    /// image name is one of these and reports the exemption paired with
    /// it (the `exemption-reported` clause).
    pub fn with_agent_exemptions(
        mut self,
        exemptions: Vec<(String, ImageExemption)>,
    ) -> MemoryImageStore {
        self.exemptions = exemptions.into_iter().collect();
        self
    }
}

impl ImageStore for MemoryImageStore {
    fn pull(&self, image: &ImageRef) -> Result<Pulled, ImageError> {
        let exemption = match image.origin {
            ImageOrigin::Operator => None,
            ImageOrigin::Agent => match self.exemptions.get(&image.name) {
                Some(exemption) => Some(exemption.clone()),
                None => {
                    return Err(ImageError::Failed {
                        detail: format!("{} was chosen by the agent and not exempted", image.name),
                    });
                }
            },
        };
        let image_key = key(image);
        if self.tampered.contains(&image_key) {
            return Err(ImageError::Failed {
                detail: format!("{} does not match its digest {}", image.name, image.digest),
            });
        }
        if !self.images.contains(&image_key) {
            return Err(ImageError::NotFound);
        }
        let mut pulled = lock(&self.pulled);
        let n = pulled.len() + 1;
        let rootfs = pulled
            .entry(image_key)
            .or_insert_with(|| RootfsRef::new(format!("rootfs-{n}")));
        Ok(Pulled {
            rootfs: rootfs.clone(),
            exemption,
        })
    }
}
