//! The OCSP cache of one `TlsConfig` (ADR-019, item 6; D2): keyed by the
//! SHA-1 CertID, so the responder URLs of one leaf share one entry, in
//! memory for the life of the process, at most `OCSP_CACHE_MAX_ENTRIES`
//! entries. The staleness rules are the CRL cache's (`cache::window`): an
//! answer is fresh for `OCSP_MAX_AGE_SECS` after a fetch last returned it,
//! stale from then until its `nextUpdate` (one check claims the refresh,
//! the others use the answer for `OCSP_REFRESH_RETRY_SECS`), and never
//! used from its `nextUpdate` on.
//!
//! A revocation is final until its `nextUpdate`: no good answer replaces
//! it, whichever responder sent it and whatever its `thisUpdate`, and a
//! revoked answer replaces any good one. Among good answers a later
//! `thisUpdate` replaces the entry, an equal one confirms it and an
//! earlier one changes nothing.

use std::collections::BTreeMap;

use super::super::cache::{Window, window};
use super::response::Status;
use super::{OCSP_CACHE_MAX_ENTRIES, OCSP_MAX_AGE_SECS, OCSP_REFRESH_RETRY_SECS};

/// One cached answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) status: Status,
    pub(crate) this_update: u64,
    pub(crate) next_update: u64,
    /// The canonical URL of the responder that sent it.
    pub(crate) url: String,
    /// The last time a fetch returned this answer or one with the same
    /// `thisUpdate`.
    pub(crate) confirmed_at: u64,
    /// The last refresh attempt since then.
    pub(crate) claimed_at: Option<u64>,
    /// A use counter for least-recently-used eviction; not a time.
    last_used: u64,
}

impl Entry {
    /// An answer from `url`, confirmed at `now`.
    pub(crate) fn new(
        status: Status,
        this_update: u64,
        next_update: u64,
        url: &str,
        now: u64,
    ) -> Entry {
        Entry {
            status,
            this_update,
            next_update,
            url: url.to_owned(),
            confirmed_at: now,
            claimed_at: None,
            last_used: 0,
        }
    }
}

/// What the cache says about a CertID at a time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// No usable answer.
    Missing,
    /// Within the maximum age, or a revocation before its `nextUpdate`:
    /// use it without a fetch.
    Fresh(Entry),
    /// A good answer past the maximum age whose refresh another check
    /// claimed less than `OCSP_REFRESH_RETRY_SECS` ago.
    Stale(Entry),
    /// A good answer past the maximum age, claimed now by this caller, who
    /// fetches; the answer decides if the refresh fails.
    Refresh(Entry),
}

#[derive(Debug, Default)]
pub(crate) struct OcspCache {
    entries: BTreeMap<Vec<u8>, Entry>,
    clock: u64,
}

impl OcspCache {
    pub(crate) fn new() -> OcspCache {
        OcspCache::default()
    }

    /// Forgets every entry (a poisoned mutex: the cache only saves
    /// fetches).
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    #[cfg(test)]
    pub(crate) fn get(&self, key: &[u8]) -> Option<&Entry> {
        self.entries.get(key)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    pub(crate) fn lookup(&mut self, key: &[u8], now: u64) -> Lookup {
        let tick = self.tick();
        let Some(entry) = self.entries.get_mut(key) else {
            return Lookup::Missing;
        };
        let place = window(
            now,
            entry.confirmed_at,
            entry.claimed_at,
            entry.next_update,
            OCSP_MAX_AGE_SECS,
            OCSP_REFRESH_RETRY_SECS,
        );
        if place == Window::Expired {
            self.entries.remove(key);
            return Lookup::Missing;
        }
        entry.last_used = tick;
        // A refresh cannot undo a revocation, so it is never fetched again
        // before its `nextUpdate`.
        if entry.status == Status::Revoked {
            return Lookup::Fresh(entry.clone());
        }
        match place {
            Window::Fresh => Lookup::Fresh(entry.clone()),
            Window::Waiting => Lookup::Stale(entry.clone()),
            Window::Claim | Window::Expired => {
                entry.claimed_at = Some(now);
                Lookup::Refresh(entry.clone())
            }
        }
    }

    /// Stores an answer that settled the leaf, by the rules of the module
    /// doc, and returns the entry that now decides for `key`: the stored
    /// answer, or the cached revocation it could not replace. An answer
    /// already at its `nextUpdate` is not stored.
    pub(crate) fn insert(&mut self, key: &[u8], entry: Entry, now: u64) -> Entry {
        let tick = self.tick();
        if let Some(existing) = self.entries.get(key)
            && existing.next_update <= now
        {
            self.entries.remove(key);
        }
        if entry.next_update <= now {
            return entry;
        }
        let mut entry = entry;
        entry.confirmed_at = now;
        entry.claimed_at = None;
        entry.last_used = tick;
        if let Some(existing) = self.entries.get_mut(key) {
            let keep = match (existing.status, entry.status) {
                // No good answer undoes a revocation.
                (Status::Revoked, Status::Good) => true,
                // A revocation replaces any good answer.
                (Status::Good, Status::Revoked) => false,
                // Same status: the later `thisUpdate` wins.
                _ => entry.this_update < existing.this_update,
            };
            let confirms =
                existing.status == entry.status && entry.this_update == existing.this_update;
            if confirms {
                existing.confirmed_at = now;
                existing.claimed_at = None;
            }
            if keep || confirms {
                existing.last_used = tick;
                return existing.clone();
            }
            *existing = entry.clone();
            return entry;
        }
        while self.entries.len() >= OCSP_CACHE_MAX_ENTRIES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.entries.insert(key.to_vec(), entry.clone());
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_767_225_600;
    const WEEK: u64 = 7 * 86_400;
    const URL: &str = "http://ocsp.boneli.test/";

    fn good(this_update: u64) -> Entry {
        Entry::new(Status::Good, this_update, this_update + WEEK, URL, 0)
    }

    fn revoked(this_update: u64) -> Entry {
        Entry::new(Status::Revoked, this_update, this_update + WEEK, URL, 0)
    }

    fn kind(lookup: &Lookup) -> &'static str {
        match lookup {
            Lookup::Missing => "missing",
            Lookup::Fresh(_) => "fresh",
            Lookup::Stale(_) => "stale",
            Lookup::Refresh(_) => "refresh",
        }
    }

    fn at(cache: &mut OcspCache, now: u64) -> &'static str {
        kind(&cache.lookup(b"k", now))
    }

    #[test]
    fn max_age_and_retry_bounds() {
        let mut cache = OcspCache::new();
        cache.insert(b"k", good(T0), T0);
        assert_eq!(at(&mut cache, T0 + 86_399), "fresh");
        assert_eq!(at(&mut cache, T0 + 86_400), "refresh");
        assert_eq!(at(&mut cache, T0 + 86_400), "stale");
        assert_eq!(at(&mut cache, T0 + 89_999), "stale");
        assert_eq!(at(&mut cache, T0 + 90_000), "refresh");
        assert_eq!(at(&mut cache, T0 + WEEK - 1), "refresh");
        assert_eq!(at(&mut cache, T0 + WEEK), "missing");
        assert_eq!(cache.len(), 0, "the expired entry is dropped");
    }

    #[test]
    fn revocation_is_used_until_next_update_without_refresh() {
        let mut cache = OcspCache::new();
        cache.insert(b"k", revoked(T0), T0);
        assert_eq!(at(&mut cache, T0 + 86_400), "fresh");
        assert_eq!(at(&mut cache, T0 + WEEK - 1), "fresh");
        assert_eq!(at(&mut cache, T0 + WEEK), "missing");
    }

    #[test]
    fn ocsp_cached_revocation_is_not_undone() {
        let mut cache = OcspCache::new();
        cache.insert(b"k", revoked(T0), T0);
        let decided = cache.insert(b"k", good(T0 + 86_400), T0 + 86_400);
        assert_eq!(decided.status, Status::Revoked);
        assert_eq!(cache.get(b"k").expect("entry").this_update, T0);
        // A later revocation replaces the earlier one.
        let decided = cache.insert(b"k", revoked(T0 + 3_600), T0 + 3_600);
        assert_eq!(
            (decided.status, decided.this_update),
            (Status::Revoked, T0 + 3_600)
        );
    }

    #[test]
    fn ocsp_older_revocation_still_wins() {
        let mut cache = OcspCache::new();
        cache.insert(b"k", good(T0 + 86_400), T0 + 86_400);
        let decided = cache.insert(b"k", revoked(T0), T0 + 86_401);
        assert_eq!((decided.status, decided.this_update), (Status::Revoked, T0));
        assert_eq!(cache.get(b"k").expect("entry").status, Status::Revoked);
    }

    #[test]
    fn older_good_changes_nothing_and_equal_confirms() {
        let mut cache = OcspCache::new();
        cache.insert(b"k", good(T0 + 10), T0 + 10);
        assert_eq!(at(&mut cache, T0 + 10 + 86_400), "refresh");
        let decided = cache.insert(b"k", good(T0), T0 + 86_420);
        assert_eq!(decided.this_update, T0 + 10);
        let e = cache.get(b"k").expect("entry");
        assert_eq!((e.confirmed_at, e.claimed_at), (T0 + 10, Some(T0 + 86_410)));
        // Equal: confirmed, the claim cleared.
        cache.insert(b"k", good(T0 + 10), T0 + 86_430);
        let e = cache.get(b"k").expect("entry");
        assert_eq!((e.confirmed_at, e.claimed_at), (T0 + 86_430, None));
        // Later: replaced.
        let decided = cache.insert(b"k", good(T0 + 20), T0 + 86_440);
        assert_eq!(decided.this_update, T0 + 20);
    }

    #[test]
    fn answer_at_next_update_is_not_stored() {
        let mut cache = OcspCache::new();
        cache.insert(b"k", good(T0), T0 + WEEK);
        assert_eq!(cache.len(), 0);
        // An expired entry is replaced even by an older good answer.
        cache.insert(b"k", good(T0 + 86_400), T0 + 86_400);
        cache.insert(
            b"k",
            Entry::new(Status::Good, T0, T0 + 2 * WEEK, URL, 0),
            T0 + 86_400 + WEEK,
        );
        assert_eq!(cache.get(b"k").expect("entry").this_update, T0);
    }

    #[test]
    fn ocsp_cache_evicts_lru_past_1024() {
        let mut cache = OcspCache::new();
        for i in 0..OCSP_CACHE_MAX_ENTRIES as u32 {
            cache.insert(&i.to_be_bytes(), good(T0), T0);
        }
        assert_eq!(cache.len(), 1_024);
        // Key 0 is used, so key 1 is the least recently used.
        assert_eq!(kind(&cache.lookup(&0u32.to_be_bytes(), T0)), "fresh");
        cache.insert(&5_000u32.to_be_bytes(), good(T0), T0);
        assert_eq!(cache.len(), 1_024);
        assert!(cache.get(&0u32.to_be_bytes()).is_some());
        assert!(cache.get(&1u32.to_be_bytes()).is_none());
        assert!(cache.get(&5_000u32.to_be_bytes()).is_some());
    }

    #[test]
    fn ocsp_window_sums_saturate() {
        let mut cache = OcspCache::new();
        let far = Entry::new(Status::Good, 0, u64::MAX, URL, 0);
        cache.insert(b"k", far.clone(), u64::MAX - 1);
        assert_eq!(at(&mut cache, u64::MAX - 1), "fresh");
        let mut cache = OcspCache::new();
        cache.insert(b"k", far, 0);
        assert_eq!(at(&mut cache, u64::MAX - 1), "refresh");
        assert_eq!(at(&mut cache, u64::MAX - 1), "stale");
    }

    #[test]
    fn ocsp_clock_moved_back_refreshes() {
        let mut cache = OcspCache::new();
        cache.insert(b"k", good(T0), T0 + 86_400);
        assert_eq!(
            at(&mut cache, T0),
            "refresh",
            "not fresh before confirmed_at"
        );
        assert_eq!(
            at(&mut cache, T0 - 1),
            "refresh",
            "not waiting before claimed_at"
        );
    }
}
