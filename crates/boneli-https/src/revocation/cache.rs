//! The CRL cache of one `TlsConfig` (ADR-017, item 8): keyed by the
//! canonical URL, in memory for the life of the process, at most
//! `CRL_CACHE_MAX_BYTES` of DER. An entry is fresh for `CRL_MAX_AGE_SECS`
//! after a fetch last returned its list, stale from then until its
//! `nextUpdate` (one check claims the refresh, the others use the list
//! for `CRL_REFRESH_RETRY_SECS`), and never used from `nextUpdate` on.
//!
//! All times are Unix seconds and every sum saturates. A clock moved back
//! before `confirmed_at` or `claimed_at` is inside neither window, so the
//! entry refreshes instead of staying fresh longer. The caller holds the
//! cache's mutex only around these calls, never across a fetch.

use std::collections::BTreeMap;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;

use super::{CRL_CACHE_MAX_BYTES, CRL_MAX_AGE_SECS, CRL_REFRESH_RETRY_SECS};

/// One cached list.
#[derive(Clone, Debug)]
pub(crate) struct Entry {
    /// The verifier built with this list, the handshake's roots and
    /// provider.
    pub(crate) verifier: Arc<WebPkiServerVerifier>,
    pub(crate) this_update: u64,
    pub(crate) next_update: u64,
    /// The size of the list's DER, what the byte cap counts.
    pub(crate) der_len: usize,
    /// The last time a fetch returned this list or one with the same
    /// `thisUpdate`.
    pub(crate) confirmed_at: u64,
    /// The last refresh attempt since then.
    pub(crate) claimed_at: Option<u64>,
    /// A use counter for least-recently-used eviction; not a time, so a
    /// clock moved back cannot reorder it.
    last_used: u64,
}

impl Entry {
    /// A new entry, confirmed at `now`.
    pub(crate) fn new(
        verifier: Arc<WebPkiServerVerifier>,
        this_update: u64,
        next_update: u64,
        der_len: usize,
        now: u64,
    ) -> Entry {
        Entry {
            verifier,
            this_update,
            next_update,
            der_len,
            confirmed_at: now,
            claimed_at: None,
            last_used: 0,
        }
    }
}

/// What the cache says about a URL at a time.
#[derive(Clone, Debug)]
pub(crate) enum Lookup {
    /// No usable entry: none, or `now` is at or past its `nextUpdate`.
    Missing,
    /// Within the maximum age: use it without a fetch.
    Fresh(Arc<WebPkiServerVerifier>),
    /// Past the maximum age, and another check claimed the refresh less
    /// than `CRL_REFRESH_RETRY_SECS` ago: use it without a fetch.
    Stale(Arc<WebPkiServerVerifier>),
    /// Past the maximum age and claimed now by this caller, who fetches;
    /// the list and its `thisUpdate` decide if the refresh fails.
    Refresh(Arc<WebPkiServerVerifier>, u64),
}

#[derive(Debug, Default)]
pub(crate) struct CrlCache {
    entries: BTreeMap<String, Entry>,
    total: usize,
    clock: u64,
}

impl CrlCache {
    pub(crate) fn new() -> CrlCache {
        CrlCache::default()
    }

    /// Forgets every entry (a poisoned mutex: the cache only saves
    /// fetches).
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.total = 0;
    }

    /// The DER bytes the entries hold.
    #[cfg(test)]
    pub(crate) fn total(&self) -> usize {
        self.total
    }

    #[cfg(test)]
    pub(crate) fn get(&self, url: &str) -> Option<&Entry> {
        self.entries.get(url)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    pub(crate) fn lookup(&mut self, url: &str, now: u64) -> Lookup {
        let tick = self.tick();
        let Some(entry) = self.entries.get_mut(url) else {
            return Lookup::Missing;
        };
        if now >= entry.next_update {
            // Expired: never used again, so its bytes go now.
            self.total = self.total.saturating_sub(entry.der_len);
            self.entries.remove(url);
            return Lookup::Missing;
        }
        entry.last_used = tick;
        let fresh =
            entry.confirmed_at <= now && now < entry.confirmed_at.saturating_add(CRL_MAX_AGE_SECS);
        if fresh {
            return Lookup::Fresh(Arc::clone(&entry.verifier));
        }
        let waiting = entry
            .claimed_at
            .is_some_and(|at| at <= now && now < at.saturating_add(CRL_REFRESH_RETRY_SECS));
        if waiting {
            return Lookup::Stale(Arc::clone(&entry.verifier));
        }
        entry.claimed_at = Some(now);
        Lookup::Refresh(Arc::clone(&entry.verifier), entry.this_update)
    }

    /// Stores a list that settled a leaf, by the insert rules of ADR-017,
    /// item 8: entries at or past their `nextUpdate` go first; against an
    /// entry still before its `nextUpdate` a later `thisUpdate` replaces
    /// it, an equal one keeps its verifier and restarts its maximum age,
    /// an earlier one changes nothing. Least recently used entries go
    /// until the new one fits under `CRL_CACHE_MAX_BYTES`.
    pub(crate) fn insert(&mut self, url: &str, mut entry: Entry, now: u64) {
        let tick = self.tick();
        let mut freed = 0;
        self.entries.retain(|_, e| {
            let keep = e.next_update > now;
            if !keep {
                freed += e.der_len;
            }
            keep
        });
        self.total = self.total.saturating_sub(freed);
        if entry.next_update <= now {
            return;
        }
        if let Some(existing) = self.entries.get_mut(url) {
            if entry.this_update < existing.this_update {
                return;
            }
            if entry.this_update == existing.this_update {
                existing.confirmed_at = now;
                existing.claimed_at = None;
                existing.last_used = tick;
                return;
            }
            self.total = self.total.saturating_sub(existing.der_len);
            self.entries.remove(url);
        }
        while self.total.saturating_add(entry.der_len) > CRL_CACHE_MAX_BYTES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(gone) = self.entries.remove(&oldest) {
                self.total = self.total.saturating_sub(gone.der_len);
            }
        }
        if self.total.saturating_add(entry.der_len) > CRL_CACHE_MAX_BYTES {
            // Larger than the whole cache; `MAX_CRL_BYTES` keeps this from
            // happening.
            return;
        }
        entry.confirmed_at = now;
        entry.claimed_at = None;
        entry.last_used = tick;
        self.total += entry.der_len;
        self.entries.insert(url.to_owned(), entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::OnceLock;

    use crate::revocation::MAX_CRL_BYTES;
    use crate::revocation::tests::verifier_for;

    const T0: u64 = 1_767_225_600;
    const WEEK1_END: u64 = 1_767_830_400;
    const MIB: usize = 1_048_576;

    fn verifier() -> Arc<WebPkiServerVerifier> {
        static V: OnceLock<Arc<WebPkiServerVerifier>> = OnceLock::new();
        Arc::clone(
            V.get_or_init(|| verifier_for(include_bytes!("../../tests/data/crl-ca-empty.crl"))),
        )
    }

    fn entry(this_update: u64, next_update: u64, der_len: usize) -> Entry {
        Entry::new(verifier(), this_update, next_update, der_len, 0)
    }

    fn kind(lookup: &Lookup) -> &'static str {
        match lookup {
            Lookup::Missing => "missing",
            Lookup::Fresh(_) => "fresh",
            Lookup::Stale(_) => "stale",
            Lookup::Refresh(..) => "refresh",
        }
    }

    fn at(cache: &mut CrlCache, now: u64) -> &'static str {
        kind(&cache.lookup("u", now))
    }

    #[test]
    fn fresh_until_next_update_exclusive() {
        let mut cache = CrlCache::new();
        cache.insert("u", entry(T0, WEEK1_END, 10), 1_767_787_200);
        assert_eq!(at(&mut cache, WEEK1_END - 1), "fresh");
        assert_eq!(at(&mut cache, WEEK1_END), "missing");
        assert_eq!(cache.total(), 0, "the expired entry is dropped");
    }

    #[test]
    fn max_age_and_retry_bounds_exclusive() {
        let mut cache = CrlCache::new();
        cache.insert("u", entry(T0, WEEK1_END, 10), T0);
        assert_eq!(at(&mut cache, T0 + 86_399), "fresh");
        assert_eq!(at(&mut cache, T0 + 86_400), "refresh");
        assert_eq!(at(&mut cache, T0 + 86_400), "stale", "claimed");
        assert_eq!(at(&mut cache, T0 + 89_999), "stale");
        assert_eq!(at(&mut cache, T0 + 90_000), "refresh");
        assert_eq!(at(&mut cache, T0 + 90_000), "stale");
    }

    #[test]
    fn time_arithmetic_saturates() {
        let mut cache = CrlCache::new();
        cache.insert("u", entry(T0, u64::MAX, 10), u64::MAX - 1);
        assert_eq!(at(&mut cache, u64::MAX - 1), "fresh");
        let mut cache = CrlCache::new();
        cache.insert("u", entry(0, u64::MAX, 10), 0);
        assert_eq!(at(&mut cache, u64::MAX - 1), "refresh");
        assert_eq!(at(&mut cache, u64::MAX - 1), "stale");
    }

    #[test]
    fn clock_moved_back_refreshes() {
        let mut cache = CrlCache::new();
        cache.insert("u", entry(T0, WEEK1_END, 10), T0 + 86_400);
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

    #[test]
    fn tie_keeps_existing_and_restarts_max_age() {
        let mut cache = CrlCache::new();
        let first = entry(T0, WEEK1_END, 10);
        let kept = Arc::clone(&first.verifier);
        cache.insert("u", first, T0);
        assert_eq!(at(&mut cache, T0 + 86_400), "refresh");
        let other = verifier_for(include_bytes!("../../tests/data/crl-ca-week1.crl"));
        cache.insert("u", Entry::new(other, T0, WEEK1_END, 10, 0), T0 + 86_400);
        let e = cache.get("u").expect("entry");
        assert!(Arc::ptr_eq(&e.verifier, &kept));
        assert_eq!((e.confirmed_at, e.claimed_at), (T0 + 86_400, None));
        assert_eq!(at(&mut cache, T0 + 86_400 + 86_399), "fresh");
        assert_eq!(cache.total(), 10);
    }

    #[test]
    fn overlapping_newer_list_replaces() {
        let mut cache = CrlCache::new();
        cache.insert("u", entry(T0, WEEK1_END, 10), T0);
        cache.insert("u", entry(T0 + 86_400, WEEK1_END + 86_400, 20), T0 + 3);
        let e = cache.get("u").expect("entry");
        assert_eq!((e.this_update, e.confirmed_at), (T0 + 86_400, T0 + 3));
        assert_eq!(cache.total(), 20);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn older_list_does_not_replace_fresh() {
        let mut cache = CrlCache::new();
        cache.insert("u", entry(T0 + 86_400, WEEK1_END + 86_400, 20), T0 + 86_400);
        assert_eq!(at(&mut cache, T0 + 172_800), "refresh");
        cache.insert("u", entry(T0, WEEK1_END, 10), T0 + 172_801);
        let e = cache.get("u").expect("entry");
        assert_eq!(e.this_update, T0 + 86_400);
        assert_eq!(
            (e.confirmed_at, e.claimed_at),
            (T0 + 86_400, Some(T0 + 172_800))
        );
        assert_eq!(cache.total(), 20);
    }

    #[test]
    fn expired_entry_is_replaced_even_by_older_list() {
        let mut cache = CrlCache::new();
        cache.insert("u", entry(T0 + 86_400, WEEK1_END, 20), T0 + 86_400);
        // At WEEK1_END the cached entry has expired; an older list that is
        // still valid then replaces it.
        cache.insert("u", entry(T0, WEEK1_END + 1, 10), WEEK1_END);
        let e = cache.get("u").expect("entry");
        assert_eq!(e.this_update, T0);
        assert_eq!(cache.total(), 10);
        // A list already expired is never stored.
        cache.insert("v", entry(T0, WEEK1_END, 10), WEEK1_END);
        assert!(cache.get("v").is_none());
    }

    #[test]
    fn lru_eviction_over_64_mib() {
        let mut cache = CrlCache::new();
        cache.insert("first", entry(T0, WEEK1_END, 30 * MIB), T0);
        cache.insert("second", entry(T0, WEEK1_END, 30 * MIB), T0);
        assert_eq!(kind(&cache.lookup("first", T0)), "fresh");
        cache.insert("third", entry(T0, WEEK1_END, 5 * MIB), T0);
        assert!(cache.get("first").is_some());
        assert!(cache.get("second").is_none());
        assert!(cache.get("third").is_some());
        assert_eq!(cache.total(), 35 * MIB);
    }

    #[test]
    fn single_entry_at_cap_fits() {
        let mut cache = CrlCache::new();
        cache.insert("a", entry(T0, WEEK1_END, MAX_CRL_BYTES), T0);
        cache.insert("b", entry(T0, WEEK1_END, MAX_CRL_BYTES), T0);
        assert_eq!(cache.total(), CRL_CACHE_MAX_BYTES);
        cache.insert("c", entry(T0, WEEK1_END, MAX_CRL_BYTES), T0);
        assert!(cache.get("a").is_none());
        assert!(cache.get("c").is_some());
        assert_eq!(cache.total(), CRL_CACHE_MAX_BYTES);
    }
}
