//! Fixture crate.
#![doc(test(attr(forbid(unsafe_code))))]

use std::io::{self, Write as _};
use std::sync::{Mutex, PoisonError};

/// A cache behind a Mutex.
pub struct Cache {
    cache: Mutex<Option<String>>,
    count: Mutex<u64>,
}

impl Cache {
    /// The cached value, if the cache is free.
    pub fn peek(&self) -> Option<String> {
        let value = &match self.cache.try_lock().as_deref() {
            Ok(Some(v)) => Some(v.clone()),
            _ => None,
        };
        *self.count.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        *self
            .count
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        let _ = Mutex::lock(&self.count).map(|mut c| *c += 1);
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "peek");
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "peek");
        value.clone()
    }
}
