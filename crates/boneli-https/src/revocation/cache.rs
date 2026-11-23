//! A CRL cache of one `TlsConfig` (ADR-017, item 8): keyed by the
//! canonical URL, in memory for the life of the process, at most the byte
//! cap it was made with (`CRL_CACHE_MAX_BYTES` for the leaves' lists,
//! `CA_CRL_CACHE_MAX_BYTES` for the intermediates' lists, ADR-027) of
//! DER. Each instance stores one kind of list: the leaf's a webpki
//! verifier built with it, the intermediates' the DER that `ca_list`
//! decides again for every certificate. An entry is fresh for `CRL_MAX_AGE_SECS`
//! after a fetch last returned its lists, stale from then until their
//! `nextUpdate` (one check claims the refresh, the others use the lists
//! for `CRL_REFRESH_RETRY_SECS`), and a list is never used from its
//! `nextUpdate` on.
//!
//! An entry holds every distinct list (by SHA-256 of its DER) accepted for
//! its URL at the newest `thisUpdate` seen there. A CA can sign two
//! different lists in the same second, and the cache is shared by every
//! leaf that names the URL, so keeping only one of them could drop a
//! revocation of another leaf; the caller checks a leaf against all of
//! them, and any revocation wins.
//!
//! All times are Unix seconds and every sum saturates. A clock moved back
//! before `confirmed_at` or `claimed_at` is inside neither window, so the
//! entry refreshes instead of staying fresh longer. The caller holds the
//! cache's mutex only around these calls, never across a fetch.

use std::collections::BTreeMap;

use super::{CRL_MAX_AGE_SECS, CRL_REFRESH_RETRY_SECS};

/// One accepted list.
#[derive(Clone, Debug)]
pub(crate) struct List<V> {
    /// The list as its check uses it: for a leaf the verifier built with
    /// it, the handshake's roots and provider; for an intermediate its DER.
    pub(crate) value: V,
    /// SHA-256 of the list's DER: two fetches of the same list are one.
    pub(crate) digest: [u8; 32],
    pub(crate) next_update: u64,
    /// The size of the list's DER, what the byte cap counts.
    pub(crate) der_len: usize,
}

/// The lists of one URL.
#[derive(Clone, Debug)]
pub(crate) struct Entry<V> {
    /// Every distinct list accepted at `this_update`, in arrival order;
    /// never empty in the cache.
    pub(crate) lists: Vec<List<V>>,
    pub(crate) this_update: u64,
    /// The last time a fetch returned one of these lists or another with
    /// the same `thisUpdate`.
    pub(crate) confirmed_at: u64,
    /// The last refresh attempt since then.
    pub(crate) claimed_at: Option<u64>,
    /// A use counter for least-recently-used eviction; not a time, so a
    /// clock moved back cannot reorder it.
    last_used: u64,
}

impl<V: Clone> Entry<V> {
    /// An entry of one list, confirmed at `now`.
    pub(crate) fn new(
        value: V,
        digest: [u8; 32],
        this_update: u64,
        next_update: u64,
        der_len: usize,
        now: u64,
    ) -> Entry<V> {
        Entry {
            lists: vec![List {
                value,
                digest,
                next_update,
                der_len,
            }],
            this_update,
            confirmed_at: now,
            claimed_at: None,
            last_used: 0,
        }
    }

    /// The DER bytes of all its lists.
    pub(crate) fn der_len(&self) -> usize {
        self.lists.iter().map(|l| l.der_len).sum()
    }

    fn values(&self) -> Vec<V> {
        self.lists.iter().map(|l| l.value.clone()).collect()
    }

    /// Drops the lists at or past their `nextUpdate`; the bytes freed.
    fn expire(&mut self, now: u64) -> usize {
        let before = self.der_len();
        self.lists.retain(|l| now < l.next_update);
        before - self.der_len()
    }
}

/// Where a cached answer stands at `now` (ADR-017, item 8; ADR-020):
/// the one rule both caches use. All times are Unix seconds and every sum
/// saturates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Window {
    /// At or past `nextUpdate`: never used again.
    Expired,
    /// `confirmed_at <= now < confirmed_at + max_age`: used without a
    /// fetch.
    Fresh,
    /// Past its maximum age, and a refresh was claimed less than `retry`
    /// ago (`claimed_at <= now`): used without a fetch.
    Waiting,
    /// Past its maximum age with no claim waiting: the caller claims the
    /// refresh and fetches. A clock moved back before `confirmed_at` or
    /// `claimed_at` lands here too, never in a longer `Fresh`.
    Claim,
}

/// The window of an answer confirmed at `confirmed_at`, valid until
/// `next_update` (exclusive), whose last refresh was claimed at
/// `claimed_at`.
pub(crate) fn window(
    now: u64,
    confirmed_at: u64,
    claimed_at: Option<u64>,
    next_update: u64,
    max_age: u64,
    retry: u64,
) -> Window {
    if next_update <= now {
        return Window::Expired;
    }
    if confirmed_at <= now && now < confirmed_at.saturating_add(max_age) {
        return Window::Fresh;
    }
    if claimed_at.is_some_and(|at| at <= now && now < at.saturating_add(retry)) {
        return Window::Waiting;
    }
    Window::Claim
}

/// What the cache says about a URL at a time. The values are all lists
/// the entry holds; a certificate is checked against each.
#[derive(Clone, Debug)]
pub(crate) enum Lookup<V> {
    /// No usable list: none, or `now` is at or past the `nextUpdate` of
    /// every list.
    Missing,
    /// Within the maximum age: use them without a fetch.
    Fresh(Vec<V>),
    /// Past the maximum age, and another check claimed the refresh less
    /// than `CRL_REFRESH_RETRY_SECS` ago: use them without a fetch.
    Stale(Vec<V>),
    /// Past the maximum age and claimed now by this caller, who fetches;
    /// the lists and their `thisUpdate` decide if the refresh fails.
    Refresh(Vec<V>, u64),
}

#[derive(Debug)]
pub(crate) struct CrlCache<V> {
    entries: BTreeMap<String, Entry<V>>,
    total: usize,
    clock: u64,
    /// The DER bytes the entries may hold at most.
    max_bytes: usize,
}

impl<V: Clone> CrlCache<V> {
    /// An empty cache that holds at most `max_bytes` of DER.
    pub(crate) fn new(max_bytes: usize) -> CrlCache<V> {
        CrlCache {
            entries: BTreeMap::new(),
            total: 0,
            clock: 0,
            max_bytes,
        }
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
    pub(crate) fn get(&self, url: &str) -> Option<&Entry<V>> {
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

    /// The lists cached for `url` while `now` is before their
    /// `nextUpdate`, fresh or stale, without claiming a refresh or
    /// counting a use.
    pub(crate) fn peek(&self, url: &str, now: u64) -> Vec<V> {
        self.entries.get(url).map_or_else(Vec::new, |e| {
            e.lists
                .iter()
                .filter(|l| now < l.next_update)
                .map(|l| l.value.clone())
                .collect()
        })
    }

    pub(crate) fn lookup(&mut self, url: &str, now: u64) -> Lookup<V> {
        let tick = self.tick();
        let Some(entry) = self.entries.get_mut(url) else {
            return Lookup::Missing;
        };
        // Expired lists are never used again, so their bytes go now.
        let freed = entry.expire(now);
        self.total = self.total.saturating_sub(freed);
        if entry.lists.is_empty() {
            self.entries.remove(url);
            return Lookup::Missing;
        }
        entry.last_used = tick;
        // Every list left is before its `nextUpdate`, so the window is
        // never `Expired` here.
        let next_update = entry.lists.iter().map(|l| l.next_update).max().unwrap_or(0);
        match window(
            now,
            entry.confirmed_at,
            entry.claimed_at,
            next_update,
            CRL_MAX_AGE_SECS,
            CRL_REFRESH_RETRY_SECS,
        ) {
            Window::Fresh => Lookup::Fresh(entry.values()),
            Window::Waiting => Lookup::Stale(entry.values()),
            Window::Claim | Window::Expired => {
                entry.claimed_at = Some(now);
                Lookup::Refresh(entry.values(), entry.this_update)
            }
        }
    }

    /// Stores the list of `entry`, which settled a leaf, by the insert
    /// rules of ADR-017, item 8: lists at or past their `nextUpdate` go
    /// first; against an entry with a list still before its `nextUpdate`,
    /// a later `thisUpdate` replaces the entry and an earlier one changes
    /// nothing. An equal `thisUpdate` restarts the entry's maximum age and
    /// adds the list unless the entry holds the same bytes already, so
    /// every distinct list at the newest `thisUpdate` stays, whichever
    /// leaf it was fetched for. Least recently used entries of other URLs
    /// go until the list fits under the cache's byte cap.
    pub(crate) fn insert(&mut self, url: &str, entry: Entry<V>, now: u64) {
        let tick = self.tick();
        let mut freed = 0;
        self.entries.retain(|_, e| {
            freed += e.expire(now);
            !e.lists.is_empty()
        });
        self.total = self.total.saturating_sub(freed);
        let mut entry = entry;
        entry.lists.retain(|l| now < l.next_update);
        if entry.lists.is_empty() {
            return;
        }
        if let Some(existing) = self.entries.get(url) {
            if entry.this_update < existing.this_update {
                return;
            }
            if entry.this_update == existing.this_update {
                for list in entry.lists {
                    let known = self
                        .entries
                        .get(url)
                        .is_some_and(|e| e.lists.iter().any(|l| l.digest == list.digest));
                    if !known && self.make_room(url, list.der_len) {
                        self.total += list.der_len;
                        if let Some(e) = self.entries.get_mut(url) {
                            e.lists.push(list);
                        }
                    }
                }
                if let Some(e) = self.entries.get_mut(url) {
                    e.confirmed_at = now;
                    e.claimed_at = None;
                    e.last_used = tick;
                }
                return;
            }
            if let Some(gone) = self.entries.remove(url) {
                self.total = self.total.saturating_sub(gone.der_len());
            }
        }
        let len = entry.der_len();
        if !self.make_room(url, len) {
            // Larger than the whole cache; `MAX_CRL_BYTES` and
            // `MAX_CA_CRL_BYTES` keep this from happening.
            return;
        }
        entry.confirmed_at = now;
        entry.claimed_at = None;
        entry.last_used = tick;
        self.total += len;
        self.entries.insert(url.to_owned(), entry);
    }

    /// Evicts least recently used entries other than `keep` until `need`
    /// more bytes fit; whether they do.
    fn make_room(&mut self, keep: &str, need: usize) -> bool {
        while self.total.saturating_add(need) > self.max_bytes {
            let Some(oldest) = self
                .entries
                .iter()
                .filter(|(k, _)| k.as_str() != keep)
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone())
            else {
                return false;
            };
            if let Some(gone) = self.entries.remove(&oldest) {
                self.total = self.total.saturating_sub(gone.der_len());
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, OnceLock};

    use rustls::client::WebPkiServerVerifier;

    use crate::revocation::tests::verifier_for;
    use crate::revocation::{CRL_CACHE_MAX_BYTES, MAX_CRL_BYTES};

    type Cache = CrlCache<Arc<WebPkiServerVerifier>>;

    const T0: u64 = 1_767_225_600;
    const WEEK1_END: u64 = 1_767_830_400;
    const MIB: usize = 1_048_576;

    fn verifier() -> Arc<WebPkiServerVerifier> {
        static V: OnceLock<Arc<WebPkiServerVerifier>> = OnceLock::new();
        Arc::clone(
            V.get_or_init(|| verifier_for(include_bytes!("../../tests/data/crl-ca-empty.crl"))),
        )
    }

    fn entry(
        this_update: u64,
        next_update: u64,
        der_len: usize,
    ) -> Entry<Arc<WebPkiServerVerifier>> {
        Entry::new(verifier(), [0; 32], this_update, next_update, der_len, 0)
    }

    fn first(entry: &Entry<Arc<WebPkiServerVerifier>>) -> &Arc<WebPkiServerVerifier> {
        &entry.lists.first().expect("a list").value
    }

    fn kind<V>(lookup: &Lookup<V>) -> &'static str {
        match lookup {
            Lookup::Missing => "missing",
            Lookup::Fresh(_) => "fresh",
            Lookup::Stale(_) => "stale",
            Lookup::Refresh(..) => "refresh",
        }
    }

    fn at(cache: &mut Cache, now: u64) -> &'static str {
        kind(&cache.lookup("u", now))
    }

    #[test]
    fn fresh_until_next_update_exclusive() {
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
        cache.insert("u", entry(T0, WEEK1_END, 10), 1_767_787_200);
        assert_eq!(at(&mut cache, WEEK1_END - 1), "fresh");
        assert_eq!(at(&mut cache, WEEK1_END), "missing");
        assert_eq!(cache.total(), 0, "the expired entry is dropped");
    }

    #[test]
    fn max_age_and_retry_bounds_exclusive() {
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
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
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
        cache.insert("u", entry(T0, u64::MAX, 10), u64::MAX - 1);
        assert_eq!(at(&mut cache, u64::MAX - 1), "fresh");
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
        cache.insert("u", entry(0, u64::MAX, 10), 0);
        assert_eq!(at(&mut cache, u64::MAX - 1), "refresh");
        assert_eq!(at(&mut cache, u64::MAX - 1), "stale");
    }

    #[test]
    fn clock_moved_back_refreshes() {
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
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
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
        let original = entry(T0, WEEK1_END, 10);
        let kept = Arc::clone(first(&original));
        cache.insert("u", original, T0);
        assert_eq!(at(&mut cache, T0 + 86_400), "refresh");
        // The same bytes again (same digest), parsed into a new verifier.
        let again = verifier_for(include_bytes!("../../tests/data/crl-ca-empty.crl"));
        cache.insert(
            "u",
            Entry::new(again, [0; 32], T0, WEEK1_END, 10, 0),
            T0 + 86_400,
        );
        let e = cache.get("u").expect("entry");
        assert_eq!(e.lists.len(), 1);
        assert!(Arc::ptr_eq(first(e), &kept));
        assert_eq!((e.confirmed_at, e.claimed_at), (T0 + 86_400, None));
        assert_eq!(at(&mut cache, T0 + 86_400 + 86_399), "fresh");
        assert_eq!(cache.total(), 10);
    }

    #[test]
    fn overlapping_newer_list_replaces() {
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
        cache.insert("u", entry(T0, WEEK1_END, 10), T0);
        cache.insert("u", entry(T0 + 86_400, WEEK1_END + 86_400, 20), T0 + 3);
        let e = cache.get("u").expect("entry");
        assert_eq!((e.this_update, e.confirmed_at), (T0 + 86_400, T0 + 3));
        assert_eq!(cache.total(), 20);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn older_list_does_not_replace_fresh() {
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
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
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
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
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
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
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
        cache.insert("a", entry(T0, WEEK1_END, MAX_CRL_BYTES), T0);
        cache.insert("b", entry(T0, WEEK1_END, MAX_CRL_BYTES), T0);
        assert_eq!(cache.total(), CRL_CACHE_MAX_BYTES);
        cache.insert("c", entry(T0, WEEK1_END, MAX_CRL_BYTES), T0);
        assert!(cache.get("a").is_none());
        assert!(cache.get("c").is_some());
        assert_eq!(cache.total(), CRL_CACHE_MAX_BYTES);
    }

    #[test]
    fn ca_cache_cap_is_inclusive() {
        // The intermediates' cache (ADR-027): 16 lists at
        // `MAX_CA_CRL_BYTES` fit exactly, a 17th evicts the least
        // recently used.
        use crate::revocation::{CA_CRL_CACHE_MAX_BYTES, MAX_CA_CRL_BYTES};
        let mut cache: Cache = CrlCache::new(CA_CRL_CACHE_MAX_BYTES);
        for i in 0..16 {
            cache.insert(&format!("u{i}"), entry(T0, WEEK1_END, MAX_CA_CRL_BYTES), T0);
        }
        assert_eq!(cache.total(), CA_CRL_CACHE_MAX_BYTES);
        assert_eq!(cache.len(), 16);
        // u0 used last, so u1 is the least recently used.
        assert_eq!(kind(&cache.lookup("u0", T0)), "fresh");
        cache.insert("u16", entry(T0, WEEK1_END, MAX_CA_CRL_BYTES), T0);
        assert_eq!(cache.len(), 16);
        assert!(cache.get("u0").is_some());
        assert!(cache.get("u1").is_none());
        assert!(cache.get("u16").is_some());
        assert_eq!(cache.total(), CA_CRL_CACHE_MAX_BYTES);
        assert_eq!(CA_CRL_CACHE_MAX_BYTES, 16 * MAX_CA_CRL_BYTES);
    }

    #[test]
    fn tie_keeps_every_distinct_list() {
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
        cache.insert("u", entry(T0, WEEK1_END, 10), T0);
        let other = verifier_for(include_bytes!("../../tests/data/crl-ca-fresh.crl"));
        cache.insert(
            "u",
            Entry::new(Arc::clone(&other), [1; 32], T0, WEEK1_END, 30, 0),
            T0 + 5,
        );
        let e = cache.get("u").expect("entry");
        assert_eq!(e.lists.len(), 2);
        assert!(Arc::ptr_eq(&e.lists[1].value, &other));
        assert_eq!((e.der_len(), e.confirmed_at), (40, T0 + 5));
        assert_eq!(cache.total(), 40);
        // Known bytes again: no third list, the age restarts.
        cache.insert("u", entry(T0, WEEK1_END, 10), T0 + 9);
        let e = cache.get("u").expect("entry");
        assert_eq!((e.lists.len(), e.confirmed_at), (2, T0 + 9));
        assert_eq!(cache.total(), 40);
        assert_eq!(cache.peek("u", T0 + 9).len(), 2);
        // An older list changes nothing; a newer one replaces both.
        cache.insert(
            "u",
            Entry::new(verifier(), [2; 32], T0 - 1, WEEK1_END, 5, 0),
            T0 + 10,
        );
        assert_eq!(cache.get("u").expect("entry").lists.len(), 2);
        cache.insert(
            "u",
            Entry::new(verifier(), [3; 32], T0 + 1, WEEK1_END, 7, 0),
            T0 + 11,
        );
        assert_eq!(cache.get("u").expect("entry").lists.len(), 1);
        assert_eq!(cache.total(), 7);
    }

    #[test]
    fn lists_of_one_entry_expire_one_by_one() {
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
        cache.insert("u", entry(T0, WEEK1_END, 10), T0);
        cache.insert(
            "u",
            Entry::new(verifier(), [1; 32], T0, WEEK1_END + 100, 20, 0),
            T0,
        );
        assert_eq!(cache.peek("u", WEEK1_END - 1).len(), 2);
        assert_eq!(cache.peek("u", WEEK1_END).len(), 1);
        match cache.lookup("u", WEEK1_END) {
            Lookup::Stale(v) | Lookup::Refresh(v, _) | Lookup::Fresh(v) => assert_eq!(v.len(), 1),
            Lookup::Missing => panic!("one list is still valid"),
        }
        assert_eq!(cache.total(), 20);
        assert_eq!(at(&mut cache, WEEK1_END + 100), "missing");
        assert_eq!(cache.total(), 0);
    }

    #[test]
    fn peek_neither_claims_nor_outlives_next_update() {
        let mut cache = Cache::new(CRL_CACHE_MAX_BYTES);
        cache.insert("u", entry(T0, WEEK1_END, 10), T0);
        assert_eq!(cache.peek("u", T0 + 86_400).len(), 1, "stale entries count");
        assert_eq!(cache.get("u").expect("entry").claimed_at, None);
        assert_eq!(cache.peek("u", WEEK1_END - 1).len(), 1);
        assert!(cache.peek("u", WEEK1_END).is_empty());
        assert!(cache.peek("v", T0).is_empty());
    }
}
