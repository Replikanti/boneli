//! [`MemoryImageStore`]: the `ImageStore` port in memory.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use boneli_app::{ImageError, ImageRef, ImageStore, RootfsRef};

use crate::lock;

/// An `ImageStore` with a fixed set of images. The first pull of an image
/// issues `rootfs-<n>` from a counter starting at 1, and every later pull
/// of the same reference returns it again; an image outside the set is
/// `NotFound`.
#[derive(Debug, Default)]
pub struct MemoryImageStore {
    images: BTreeSet<ImageRef>,
    pulled: Mutex<BTreeMap<ImageRef, RootfsRef>>,
}

impl MemoryImageStore {
    /// A store that has these images.
    pub fn new(images: Vec<ImageRef>) -> MemoryImageStore {
        MemoryImageStore {
            images: images.into_iter().collect(),
            pulled: Mutex::new(BTreeMap::new()),
        }
    }
}

impl ImageStore for MemoryImageStore {
    fn pull(&self, image: &ImageRef) -> Result<RootfsRef, ImageError> {
        if !self.images.contains(image) {
            return Err(ImageError::NotFound);
        }
        let mut pulled = lock(&self.pulled);
        let n = pulled.len() + 1;
        let rootfs = pulled
            .entry(image.clone())
            .or_insert_with(|| RootfsRef::new(format!("rootfs-{n}")));
        Ok(rootfs.clone())
    }
}
