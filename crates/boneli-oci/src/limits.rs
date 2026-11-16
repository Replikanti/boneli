//! Resource limits of layer unpacking (ADR-009, D7). There are no defaults:
//! the store states its values in one place, and a zero is refused.

use crate::error::Error;

/// The limits of one image pull. Every limit is inclusive: exactly the
/// limit passes, one more is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    max_layer_bytes: u64,
    max_image_bytes: u64,
    max_image_entries: u64,
    max_special_bytes: u64,
    max_depth: u64,
}

impl Limits {
    /// - `max_layer_bytes`: uncompressed bytes of one layer, everything the
    ///   diff_id covers, bytes after the end of the archive included.
    /// - `max_image_bytes`: the same, summed over the image's layers,
    ///   cached ones included.
    /// - `max_image_entries`: tar entries summed over the image's layers,
    ///   plus the directories created for missing parents (PAX and GNU
    ///   headers are not entries).
    /// - `max_special_bytes`: the body of one PAX or GNU long-name header.
    /// - `max_depth`: path components of an entry after normalization.
    pub fn new(
        max_layer_bytes: u64,
        max_image_bytes: u64,
        max_image_entries: u64,
        max_special_bytes: u64,
        max_depth: u64,
    ) -> Result<Limits, Error> {
        for (value, what) in [
            (max_layer_bytes, "max_layer_bytes"),
            (max_image_bytes, "max_image_bytes"),
            (max_image_entries, "max_image_entries"),
            (max_special_bytes, "max_special_bytes"),
            (max_depth, "max_depth"),
        ] {
            if value == 0 {
                return Err(Error::InvalidLimits(what));
            }
        }
        Ok(Limits {
            max_layer_bytes,
            max_image_bytes,
            max_image_entries,
            max_special_bytes,
            max_depth,
        })
    }

    /// Uncompressed bytes of one layer.
    pub fn max_layer_bytes(&self) -> u64 {
        self.max_layer_bytes
    }

    /// Uncompressed bytes of an image.
    pub fn max_image_bytes(&self) -> u64 {
        self.max_image_bytes
    }

    /// Tar entries of an image.
    pub fn max_image_entries(&self) -> u64 {
        self.max_image_entries
    }

    /// The body of one PAX or GNU long-name header.
    pub fn max_special_bytes(&self) -> u64 {
        self.max_special_bytes
    }

    /// Path components of an entry.
    pub fn max_depth(&self) -> u64 {
        self.max_depth
    }
}

/// What one image pull has used of its [`Limits`] so far. Every layer of
/// the image is charged, the ones already in the cache from their sidecar,
/// so a warm cache and a cold one reach the same verdict.
#[derive(Debug, Clone)]
pub struct Budget {
    limits: Limits,
    bytes: u64,
    entries: u64,
}

impl Budget {
    /// A budget with nothing used.
    pub fn new(limits: Limits) -> Budget {
        Budget {
            limits,
            bytes: 0,
            entries: 0,
        }
    }

    /// The limits.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Uncompressed bytes charged so far.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Entries charged so far.
    pub fn entries(&self) -> u64 {
        self.entries
    }

    /// Charges a cached layer's totals; refused, and nothing charged, if
    /// either image limit would be exceeded.
    pub fn charge(&mut self, stats: &crate::LayerStats) -> Result<(), Error> {
        let bytes = self.check_bytes(stats.bytes)?;
        let entries = self.check_entries(stats.entries)?;
        self.bytes = bytes;
        self.entries = entries;
        Ok(())
    }

    /// Sets the totals that [`Budget::check_bytes`] and
    /// [`Budget::check_entries`] returned for a layer.
    pub(crate) fn charge_totals(&mut self, bytes: u64, entries: u64) {
        self.bytes = bytes;
        self.entries = entries;
    }

    /// The image byte total with `layer_bytes` more, if within the limit.
    pub(crate) fn check_bytes(&self, layer_bytes: u64) -> Result<u64, Error> {
        match self.bytes.checked_add(layer_bytes) {
            Some(total) if total <= self.limits.max_image_bytes => Ok(total),
            _ => Err(Error::Limit {
                what: "uncompressed image size",
                max: self.limits.max_image_bytes,
            }),
        }
    }

    /// The image entry total with `layer_entries` more, if within the
    /// limit.
    pub(crate) fn check_entries(&self, layer_entries: u64) -> Result<u64, Error> {
        match self.entries.checked_add(layer_entries) {
            Some(total) if total <= self.limits.max_image_entries => Ok(total),
            _ => Err(Error::Limit {
                what: "image entry count",
                max: self.limits.max_image_entries,
            }),
        }
    }
}
