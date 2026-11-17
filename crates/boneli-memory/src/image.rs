//! [`MemoryImageStore`]: the `ImageStore` port in memory.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use boneli_app::{ImageError, ImageRef, ImageStore, RootfsRef};

use crate::lock;

/// An `ImageStore` with a fixed set of images. The first pull of an image
/// issues `rootfs-<n>` from a counter starting at 1, and every later pull
/// of the same reference returns it again; an image outside the set is
/// `NotFound`, and a tampered one (its bytes do not match its digest)
/// fails on every pull.
#[derive(Debug, Default)]
pub struct MemoryImageStore {
    images: BTreeSet<ImageRef>,
    tampered: BTreeSet<ImageRef>,
    pulled: Mutex<BTreeMap<ImageRef, RootfsRef>>,
}

impl MemoryImageStore {
    /// A store that has these images.
    pub fn new(images: Vec<ImageRef>) -> MemoryImageStore {
        MemoryImageStore {
            images: images.into_iter().collect(),
            tampered: BTreeSet::new(),
            pulled: Mutex::new(BTreeMap::new()),
        }
    }

    /// The same store, whose registry also serves these images with bytes
    /// that do not match their digest (the `tampered-refused` clause).
    pub fn with_tampered(mut self, tampered: Vec<ImageRef>) -> MemoryImageStore {
        self.tampered = tampered.into_iter().collect();
        self
    }
}

impl ImageStore for MemoryImageStore {
    fn pull(&self, image: &ImageRef) -> Result<RootfsRef, ImageError> {
        if self.tampered.contains(image) {
            return Err(ImageError::Failed {
                detail: format!("{} does not match its digest {}", image.name, image.digest),
            });
        }
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
