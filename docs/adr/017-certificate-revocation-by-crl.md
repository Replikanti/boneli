# ADR-017: Certificate revocation by CRL

- Status: accepted
- Date: 2026-11-20

## Context

`boneli-https` (ADR-005) is the TLS client of every connection the runner
makes: forge tokens, registry pulls, prompts and code sent to LLM APIs.
It verifies the server's chain against the roots and the clock, but never
asks whether a certificate was revoked. ADR-005 lists this as a known
limit and points to issue #38. A certificate is revoked when its key
leaks or it was misissued; someone who holds such a key and sits on the
network path can impersonate the server until the certificate expires,
which for the measured leaves is up to 13 months away.

What rustls 0.23.46 and rustls-webpki 0.103.17 offer: `WebPkiServerVerifier`
checks a chain against CRLs the caller hands it (`with_crls`), for the
leaf only or the whole chain, with unknown status allowed or an error,
and with `nextUpdate` enforced or not. Nothing fetches the lists. webpki
parses the leaf's CRL distribution points, but keeps them `pub(crate)`
(`Cert::crl_distribution_points`), and it keeps a list's `nextUpdate`
private. rustls does not run the certificate verifier when it resumes a
session (`src/client/tls13.rs`: "We *don't* reverify the certificate
chain here"; `tls12.rs` asserts `ServerCertVerified` on resumption), but
it restores the peer's chain from the session, so `peer_certificates()`
holds it on a resumed connection too.

Measured on 2026-11-20 while planning #38: `openssl s_client
-showcerts` against 47 hosts (forges, registries, package indexes, LLM
APIs, CA and large company sites), `openssl x509 -ext
crlDistributionPoints` on every certificate, every CRL fetched with curl
from a residential link in Europe and read with `openssl crl`; the cost
in rustls measured with rustls 0.23.46 and ring in a release build with
`boneli-https`'s features.

- **Leaves.** 41 of 47 name a CRL distribution point: 33 one URL, 8 two
  (DigiCert's crl3/crl4 and Microsoft's www/crl2 mirrors). 6 name none
  and carry only an OCSP URL, all Sectigo DV: `github.com`,
  `api.github.com`, `codeload.github.com`, `ghcr.io`, `gitlab.com`,
  `registry.gitlab.com`. Every intermediate names one; the three chain
  certificates without one are self-signed roots.
- **URLs and responses.** All 65 distinct URLs (42 leaf CRLs, 23 CA CRLs)
  are `http://`; none is `https`, none redirected, 65 of 65 answered 200.
  The 9 probed for headers answered without `User-Agent` and `Accept`,
  with `Content-Length`. Every body is DER, version 2, no delta CRL.
  Content types vary: `application/pkix-crl`, `application/octet-stream`,
  `binary/octet-stream`.
- **Sizes.** Leaf CRLs from 308 B, median 55,959 B, p90 1,562,480 B, max
  11,005,110 B (289,071 entries, DigiCert Global G2 TLS RSA SHA256 2020
  CA1). The 34 distinct leaf CRLs (mirrors once) sum to 19,043,748 B. CA
  CRLs 284 to 2,199 B.
- **Validity** (`nextUpdate` minus `thisUpdate`): leaf CRLs 25 h (Amazon S
  shards), 95 h (GoDaddy), 167 to 168 h (DigiCert, GlobalSign, Apple,
  Amazon M), 192 h (Microsoft), 215 h (Let's Encrypt), 238 h (Google Trust
  Services). CA CRLs 504 to 8,736 h.
- **Age at fetch** (fetch time minus `thisUpdate`, the 42 leaf CRL URLs,
  all fetched within 10 s): min 0.1 h, median 3.6 h, p90 7.0 h, max 9.6 h,
  although the same lists were valid for 25 to 238 h. The CAs publish new
  lists far more often than `nextUpdate` says; the exact cadence was not
  measured (one fetch per list). Validity left at fetch: under 24 h for 2
  of the 42 (Amazon's S shards, 20.8 and 21.8 h), at least 90.1 h for the
  other 40. Mirrors disagree: for 2 of the 4 Microsoft partitions,
  `crl2.microsoft.com` served a list with a `thisUpdate` 4 h older than the
  one `www.microsoft.com` served in the same 10 s.
- **Timing.** TCP connect at most 0.120 s, first byte at most 0.211 s, the
  11,005,110 B list in 0.587 s in total. Response heads at most 1,036 B
  (all 65) and 23 fields (the 9 probed).
- **The runner's hosts.** `registry-1.docker.io` (Amazon RSA 2048 M01, CRL
  1,889,589 B), its blob CDN and `auth.docker.io` (Let's Encrypt shards,
  about 105 KB each), `api.anthropic.com` and `api.openai.com` (Google
  Trust Services WE1 shards, 308 B); GitHub names no point.
- **Cost in rustls.** `WebPkiServerVerifier` built with the 11,005,110 B
  list: 299 to 351 ms and +51.5 MiB RSS (4.9 B of memory per CRL byte),
  then 10.6 to 11.5 ms per `verify_server_cert` (webpki checks the list's
  signature over the whole list on every call). The 1,889,589 B list: 33
  to 38 ms, +8.0 to 8.1 MiB, about 2 ms per verify. Without a list: 0.075
  ms.
- **Baseline Requirements v2.3.1.** 7.1.2.11.2: the distribution point
  MUST be present in subordinate CA certificates and in subscriber
  certificates that are not short-lived and have no OCSP URL; it MUST be
  a `fullName`, `reasons` and `cRLIssuer` MUST NOT be present, every
  URI's scheme MUST be `http`, more than one point is NOT RECOMMENDED.
  4.9.7: a CA publishes a new subscriber CRL at least every 7 days (4
  without OCSP) and within 24 hours after it records a revocation. 7.2: a
  subscriber CRL's `nextUpdate` is at most 10 days after `thisUpdate`,
  other CRLs' at most 12 months.
- **Live revocation.** `revoked-isrgrootx1.letsencrypt.org` serves a leaf
  listed in its point's CRL; `valid-isrgrootx1.letsencrypt.org` is not
  listed.
- **Fixtures against rustls 0.23.46.** An openssl 3.5 CRL with
  `issuingDistributionPoint` that lists the leaf's serial gives
  `InvalidCertificate(Revoked)`; an empty CRL with `nextUpdate`
  1,767,830,400 passes at 1,767,830,399 and gives
  `ExpiredRevocationListContext { next_update: 1767830400 }` at
  1,767,830,400 (the boundary is exclusive); a truncated CRL fails at
  `build()` with `InvalidCrl`.

Decided at #38 STOP 1 (2026-11-20), each with its basis in the Decision:

- **D1, decided at STOP 1:** fail closed when the leaf names a CRL that
  cannot settle it, with no opt-out (item 4).
- **D2, decided at STOP 1:** a leaf without a fetchable point passes
  unchecked; OCSP for such leaves is a follow-up (item 5).
- **D3, decided at STOP 1:** the leaf only; intermediates are a follow-up
  (item 2).
- **D4, decided at STOP 1:** 32 MiB per CRL and 64 MiB per cache (item
  7).
- **D5, decided at STOP 1:** a cached list is used for at most 24 h after
  a fetch last returned it, with a soft refresh (item 8). Changed at STOP
  1 from the recommendation, which cached a list until its `nextUpdate`.
- **D6, decided at STOP 1:** every change to `boneli-https` gets an
  adversarial review next to QA, as the other crates on the security
  boundary do.

## Decision

1. **Where the check runs.** In `handshake()`, after rustls has verified
   the chain and before `connect`, `connect_over` or `TlsDial::dial`
   return, on `peer_certificates()`; no application byte is sent before
   it passes. Resumed sessions are checked again, because rustls restores
   the peer chain from the session but skips its verifier. A revocation
   failure is a TLS failure, so `connect` does not try the next address
   (ADR-005, item 8). Rejected: a verifier inside the handshake. It is
   skipped on resumption, so a revoked certificate would stay usable
   through every ticket issued before, and it would fetch while the
   server waits inside the handshake.

2. **What is checked (D3, decided at STOP 1).** The leaf only:
   `WebPkiServerVerifier::builder_with_provider(roots, provider)
   .with_crls([crl]).only_check_end_entity_revocation()
   .enforce_revocation_expiration().build()`, with the handshake's own
   roots and ring provider. Unknown status stays an error (rustls'
   default `Deny`), so a list that does not cover the leaf settles
   nothing: another issuer, another shard's `issuingDistributionPoint`, a
   bad signature, an issuer without `cRLSign`. Intermediates are not
   checked: rustls does not expose the verified path, and webpki's
   unknown-status policy is one setting for the whole chain. Their lists
   are small (284 to 2,199 B measured), so checking them later costs
   code, not bytes. Basis of D3: the leaf check needs no new edge; the
   chain needs webpki's verified path (a new direct edge `boneli-https ->
   rustls-webpki`) and a per-certificate unknown policy webpki lacks.

3. **Which distribution points.** Only from the leaf of the verified
   chain, never from another certificate the server sent. Only points
   with a `fullName` and neither `reasons` nor `cRLIssuer` (BR 7.1.2.11.2
   forbids both; webpki would not take a list from them as
   authoritative). URIs in certificate order. `http` and `https` are
   fetched; other well-formed schemes (`ldap`, `ftp`, `file`) are skipped,
   so no local file is ever read; a URI without a well-formed scheme, or
   an `http(s)` URL outside the grammar below, counts as a failed
   attempt, so garbage cannot turn into "unchecked". At most 4 URLs per
   leaf (`MAX_CRL_URLS`): twice the measured maximum of 2. Fewer than 2
   would lose DigiCert's and Microsoft's mirrors; more only adds attempts
   inside the same deadline for a certificate with dead URLs. The URL
   grammar: at most 1,024 bytes (9.4 times the longest measured, 109 B),
   bytes 0x21 to 0x7E only; the scheme compared case-insensitively
   (RFC 3986, 3.1), then `//`; the authority, with the default port
   appended when none is given, goes through `boneli-http`'s
   `Target::parse_authority` (ADR-003), so userinfo, percent-encoded or
   trailing-dot hosts, numeric forms like `127.1` and port 0 are refused
   and the host comes back in lowercase; no fragment; percent escapes in
   the path are passed through.

4. **The algorithm, and fail closed (D1, decided at STOP 1).**
   - A leaf without an `http` or `https` point (after skipping other
     schemes) gives `RevocationStatus::NoDistributionPoint`, and the
     connection proceeds (D2).
   - Each candidate in order, under one shared deadline and one `now`;
     the cache answers as item 8 says. A fresh entry, or a stale one
     inside its retry wait, is verified without a fetch. Otherwise:
     fetch, check the size, `build()` (webpki parses), read the dates,
     refuse when `nextUpdate < thisUpdate` (`Malformed`) or `nextUpdate <=
     now` (`Expired`), verify, and cache only a list that settled the leaf
     (passed or revoked). On a refresh, a failure of any of these steps, a
     list that does not settle the leaf and a list older than the cached
     one all leave the decision to the cached list. `Revoked` returns
     `Error::Revoked { url }` at once; no mirror is asked to overrule it.
     Any other outcome is recorded and the next candidate is tried. The
     first success is checked against the cache before it is returned:
     every list cached for any of the leaf's points and still before its
     `nextUpdate`, fresh or stale, verifies the leaf too, and a revocation
     there returns `Error::Revoked` with that list's URL (item 8). Only
     then does the check return `RevocationStatus::Checked { url }`, or
     `CheckedStale { url }` when a list past its maximum age decided it.
   - No candidate settled the leaf: `Error::RevocationUnknown(failures)`,
     each failure with its URL and kind: unreachable, timeout, non-200,
     too large, malformed (not DER, PEM, HTML, truncated, trailing bytes,
     version 1, delta), expired, not settled and bad distribution point.
     A failed refresh alone never fails a connection while the cached
     list is before its `nextUpdate` (D5); from `nextUpdate` on it does.
   - Why fail closed (basis of D1): revocation exists against someone who
     holds a revoked certificate's key and sits on the network path. The
     list travels over plain HTTP on that same path, so with fail-open
     that attacker drops the fetch and the check is gone; fail-open would
     catch only an honest server that still serves a revoked
     certificate. The runner's CRL hosts are few and CDN-backed (65 of 65
     answered 200). Invariant 6 and ADR-005 item 8 make the TLS client
     fail closed everywhere else, and no switch turns it off, as ADR-005
     item 8 has none for certificate verification. Weak spot:
     availability on networks that block outbound HTTP, and during a CRL
     CDN outage at `nextUpdate` or on a cold cache, with no escape until a
     source of the operator's own exists (item 10).

5. **No distribution point (D2, decided at STOP 1).** A leaf that names
   no fetchable point is not refused. The point sits in a signed
   extension, so an attacker cannot remove it; BR 7.1.2.11.2 lets leaves
   with an OCSP URL and short-lived leaves omit it; refusing would refuse
   6 of the 47 measured hosts, GitHub and GitLab among them. Known limit:
   GitHub, GHCR and GitLab forge traffic, which carries the `contents:
   write` token, gets no revocation check from this ADR; webpki has no
   OCSP, so checking such leaves needs a request and response codec of
   its own. The follow-up issue for OCSP on such leaves is filed at #38
   STOP 2: Replikanti/boneli#79.

6. **Fetching and bootstrapping.** HTTP/1.1 `GET` through `boneli-http`,
   `Host` only (served without `User-Agent` in every probe), no
   credentials or cookies, 200 only, no redirects (0 of 65 measured), no
   `Content-Encoding` other than `identity`, DER only (RFC 5280,
   4.2.1.13), content type not checked (three types measured). The fetch
   goes directly from the process that holds the TLS connection, like the
   connection itself, never through `boneli-egress`: that proxy serves the
   sandbox and tunnels without MITM, so the sandbox's own TLS clients are
   unaffected. `https` points (none of 65 measured, so in practice a
   customer CA) are fetched over `boneli-https` with the same roots and
   without a revocation check for that one connection: the list's
   integrity comes from its signature, not from the transport, and this
   is what keeps the fetch from recursing. The CRL host is not on any
   allowlist: the CA fixes the URL in the verified leaf, and the request
   carries nothing of the runner's.

7. **Limits and deadlines** (inclusive, public constants of
   `boneli_https`; the two byte caps are D4, decided at STOP 1 as the flow
   recommended; the two times of the cache are D5, item 8):
   - `MAX_CRL_BYTES` 33,554,432 B (32 MiB), 3.05 times the largest
     measured list (11,005,110 B), so that list can triple before hosts
     behind that CA fail. Lower refuses real lists; higher costs memory at
     4.9 B per byte and lets a broken server send more before it fails. A
     `Content-Length` above it fails before the body is read; a source
     other than HTTP is held to it too.
   - `CRL_CACHE_MAX_BYTES` 67,108,864 B (64 MiB): two lists at the cap,
     and 3.5 times the 19,043,748 B of all 34 distinct leaf lists of the
     47 measured hosts. Worst-case memory is about 4.9 times 64 MiB, 314
     MiB; the measured runner set (Docker Hub with its CDN and auth host,
     one LLM API) is about 2.1 MB of DER and about 10 MiB of memory. Lower
     thrashes once two large lists alternate; higher only raises the worst
     case.
   - `CRL_CONNECT_TIMEOUT` 10 s per address: Linux sends a SYN and
     retransmits it after 1, 3 and 7 s, so 10 s lets three retransmissions
     through (measured connect at most 0.120 s). Lower fails on a lossy
     first round trip; higher only delays the next address.
   - `CRL_HANDSHAKE_TIMEOUT` 10 s, for `https` points only (none
     measured): a handshake is one or two round trips, each far below one
     SYN timeout.
   - `CRL_IO_TIMEOUT` 10 s for each read and write: three lost segments in
     a row (retransmission timeouts 1 + 2 + 4 = 7 s) still pass; the
     measured first byte took at most 0.211 s. Lower fails healthy fetches
     on lossy links; higher only delays the failure of a dead server.
   - `CRL_SETUP_TIME` 30 s: it holds the connect bound (10 s), the
     handshake bound (10 s) and a round trip with the server's time
     (measured at most 0.211 s), about 20.2 s; lower cuts an `https` fetch
     off inside its own bounds.
   - `CRL_MIN_RATE` 1,048,576 B/s: the measured 11,005,110 B arrived at
     about 21 MB/s, so a link 20 times slower still fetches it in 10.5 s.
     Higher refuses slow customer links; lower lets a trickling server
     hold a connect longer.
   - `CRL_CHECK_DEADLINE`, one deadline per check shared by all its URLs:
     30 s + 33,554,432 / 1,048,576 s = 62 s, and never past `TlsDial`'s
     request deadline, except the CRL host's name resolution (Known
     limits). The honest worst case at the minimum rate is 30 +
     10.5 = 40.5 s; measured 0.59 s.
   - `CRL_MAX_HEAD_BYTES` 16,384 B and `CRL_MAX_HEADERS` 64 fields: 15.8
     and 2.8 times the measured 1,036 B and 23 fields. Lower refuses a CDN
     that adds tracing fields; higher lets a CRL server make the client
     buffer more.
   - `MAX_CRL_URL_BYTES` 1,024 B: 9.4 times the longest measured, 109 B.
   - `CRL_MAX_AGE_SECS` 86,400 s and `CRL_REFRESH_RETRY_SECS` 3,600 s:
     derived in item 8.

8. **The cache: maximum age and soft refresh (D5, decided at STOP 1,
   changed from the recommendation to cache until `nextUpdate`).** One
   cache per `TlsConfig` (clones share it), in memory for the life of the
   process, keyed by the canonical URL. Each entry keeps its lists (each
   with its verifier, the SHA-256 of its DER, its `nextUpdate` and its DER
   length; see the insert rules for why more than one), their common
   `thisUpdate`, `confirmed_at` (the last time a fetch returned one of
   these lists or another with the same `thisUpdate`), `claimed_at` (the
   last refresh attempt) and a use counter for eviction. A leaf is checked
   against every list of the entry; any revocation wins.
   All times are Unix seconds and every sum saturates.
   - **Fresh** while `now < nextUpdate` and `confirmed_at <= now <
     confirmed_at + 86,400`: used without a fetch. A clock moved back
     before `confirmed_at` makes the entry stale, never fresh for longer.
   - **Stale** from `confirmed_at + 86,400` until `nextUpdate`: the first
     check to see it claims the refresh (records `claimed_at = now` under
     the lock) and fetches; other checks while `claimed_at <= now <
     claimed_at + 3,600` use the stale list without a fetch. A refresh
     succeeds when the fetched list passes the size, parse and date
     checks, settles the leaf and has a `thisUpdate` not earlier than the
     cached one: a later list replaces the entry, an equal one confirms it
     (`confirmed_at = now`) and joins it when its bytes are new. Anything else is a failed
     refresh: the cached list decides, and the next attempt waits until
     `claimed_at + 3,600`. A connection decided by a stale list reports
     `RevocationStatus::CheckedStale { url }`.
   - **Expired** from `nextUpdate` on: never used, and its bytes are freed.
     The list is fetched as on a cold cache, the retry wait does not
     apply, and a failure fails the connection closed (item 4).
   - **Why a maximum age at all:** every measured leaf list was 0.1 to 9.6
     h old when fetched (median 3.6 h) but valid for 25 to 238 h, so a
     list kept until `nextUpdate` can trail the CA's current one by almost
     10 days (238 h), while a fetch returns one a few hours old.
   - **Why 24 h (`CRL_MAX_AGE_SECS` = 86,400).** BR 4.9.7 gives the CA 24
     h to publish a revocation, so on a network that lets the refresh
     through, a revocation reaches the check at most 24 h (CA) + 24 h
     (maximum age) = 48 h after the CA records it, instead of up to 24 +
     238 = 262 h (about 11 days) without it. The maximum age matches the
     CA's own bound: 12 h would cut the worst case only from 48 to 36 h at
     twice the fetches, 48 h would raise it to 72 h. Cost per URL per
     process per day: one more fetch and build, 1,889,589 B and 33 to 38
     ms for Docker Hub's list, 11,005,110 B and 299 to 351 ms for the
     largest. The maximum age matters for 40 of the 42 measured leaf URLs
     (at least 90.1 h of validity left at fetch); Amazon's S shards (20.8
     and 21.8 h left) reach `nextUpdate` first and are fetched there. The
     age counts from the last fetch, not from `thisUpdate`: counted from
     `thisUpdate`, a CA that publishes less often than daily, which BR
     4.9.7 allows (every 7 days, 4 without OCSP), would turn every check
     after 24 h into a refresh that returns the same list.
   - **Why 1 h between failed refreshes (`CRL_REFRESH_RETRY_SECS` =
     3,600, set by the flow with D5).** It bounds what a transient failure
     adds to the 48 h: at most 1 h per failed attempt in a row, 1/24 of
     the maximum age. It bounds what an outage costs: one connection per
     URL per hour runs the failing refresh, which waits at most the check
     deadline (62 s, item 7) or its request deadline, and every other
     connection uses the cached list at no cost (measured: 65 of 65
     fetches answered 200, the largest in 0.587 s). 5 min would make 12
     connections an hour per URL wait during an outage; 6 h would keep the
     old list 6 h longer after a short failure.
   - **What D5 does not change:** an attacker on the path who holds the
     revoked key can drop every refresh and so keep the cached list in use
     until its `nextUpdate`, which is what caching until `nextUpdate` gave
     anyway; D5 shortens the window on networks that let refreshes
     through, and never fails a connection that caching until
     `nextUpdate` would pass. Rejected: a hard maximum age that fails
     closed when the refresh fails, which turns a CRL outage at any daily
     refresh into failed connections while the cached list is still
     CA-valid.
   - **Insert rules.** A list already expired when fetched is not cached,
     nor one that does not settle the leaf. Entries at or past their
     `nextUpdate` are dropped first. Among entries before their
     `nextUpdate` the later `thisUpdate` wins and an earlier one changes
     nothing (Microsoft's mirrors served lists 4 h apart in the same 10 s,
     so an older list on a refresh happens without an attacker). An equal
     `thisUpdate` restarts the entry's maximum age and adds the list to
     the entry unless it holds the same bytes already (by SHA-256), so the
     entry keeps every distinct list accepted at the newest `thisUpdate`
     until each reaches its own `nextUpdate`. Why every one: a CA may sign
     two different lists in the same second, and the entry is shared by
     every leaf that names the URL, so any rule that keeps one of them
     (the first, or the one that revokes the leaf being checked) can drop
     a revocation of another leaf; the review of the first two
     implementations found exactly that. Rejected: a tie-break by CRL
     number, which does not settle two lists with equal numbers and
     different bytes. The extra lists count against the 64 MiB cap like
     any other; an entry is never evicted to make room for its own list,
     so a list that does not fit beside its entry's other lists (more than
     64 MiB at one `thisUpdate` for one URL) is not cached, and its
     revocations hold only for the connection that fetched it. An entry
     whose lists all reached their `nextUpdate` is gone; one whose lists
     expire one by one keeps the rest.
   - **A revocation the cache holds is never undone** by an equal or older
     list, from the same point or from a mirror. Besides the insert rules,
     before any list's pass is returned the leaf is verified against
     every cached list of its other points still before its `nextUpdate`
     (item 4), so a mirror that was unreachable when another point's list
     revoked the leaf cannot later pass it with an older list. Cost: one
     more verify per cached mirror list (up to 11.5 ms for the largest
     measured list), only for leaves with more than one point. Revocation
     is final for this purpose: a certificate on hold that its CA releases
     stays refused until the list that held it reaches its `nextUpdate`,
     unless a newer list from the same point replaces it. Least recently
     used entries go past
     64 MiB. The mutex is never held while fetching or parsing; a poisoned
     one is recovered and the cache cleared, because the cache only saves
     fetches.

9. **The DER reader.** Why our own: webpki parses the distribution points
   but keeps them `pub(crate)` and keeps `nextUpdate` private;
   `x509-parser` brings `nom`, `asn1-rs`, `der-parser`, `oid-registry`,
   `thiserror` (a proc macro) and more; RustCrypto's `x509-cert` brings
   `der` with a derive macro, `spki` and `const-oid`; a direct edge to
   `untrusted` (already in the graph) would save only the bounds checks.
   The reader takes definite lengths in their minimal encoding only, at
   most four length bytes, low tag numbers only, and cannot panic on an
   index. It reads only bytes webpki has accepted: the leaf after the
   handshake, and the dates of a list read before `build()` (which takes
   the bytes) but looked at only once `build()` has accepted them. So a
   misparse can refuse a valid certificate (availability) or miss a
   point (the leaf then passes unchecked), but never accept a certificate
   a list revokes: webpki makes that decision. Its selection rules mirror
   webpki's `authoritative_for`, and its time rules webpki's
   `src/time.rs`. Rust was weighed against the alternatives above; the
   reader is about 300 lines of Rust in the crate, comments included.

10. **The seam `CrlSource`.** Public, so that tests and, later, an
    operator's source (through a proxy, from files) can supply bytes
    (`TlsConfig::with_crl_source`). It is not a verifier hook: whatever it
    returns is verified by webpki against the roots, the leaf's issuer and
    point and the system clock. A source can make a connection fail, hand
    over an older CA-signed list that is still before its `nextUpdate` on
    a cold cache, or keep a cached list in use until its `nextUpdate` by
    failing every refresh, and nothing else; on a refresh, a list older
    than the cached one is ignored. No clock and no switch are public.

11. **Errors and observability.** `Error::Revoked { url }`,
    `Error::RevocationUnknown(Vec<CrlFailure>)` whose `Display` lists each
    URL with its kind, and `TlsStream::revocation()`, which says whether
    the connection was checked, against which URL and whether a stale list
    decided it (`CheckedStale`: refreshes are failing, which an operator
    can see in logs before `nextUpdate` turns it into failed connections).
    `TlsDial` keeps the error inside the `io::Error` it returns, so a
    caller can tell a revoked certificate from a network failure.

12. **Proof, and what each test does not prove.**
    - Unit tests in `src/revocation/`: the reader (every truncation and
      byte flip of the fixtures, the length, tag and time rules), the URL
      grammar, the HTTP source against loopback servers with millisecond
      timeouts, the cache arithmetic at every bound, and the check with
      explicit times and a scripted source (items 2 to 9, D5 included).
    - `tests/revocation.rs`: real handshakes on loopback through the
      public API with a fake source: revoked and good leaves, every way a
      list fails to settle a leaf, the order and number of points, leaves
      without one, resumed TLS 1.2 and 1.3 sessions, CONNECT tunnels,
      `TlsDial`'s deadline and the default source (items 1 to 6).
    - `tests/network.rs`, by hand: Let's Encrypt's revoked test site is
      refused with `Error::Revoked`, its valid one is `Checked`, and the
      status of the runner's hosts is printed. Loopback tests do not prove
      interoperability with real CAs; these do.
    - The reader's unit tests do not prove agreement with webpki beyond the
      fixtures. A differential of `distribution_point_uris` against
      `openssl x509 -ext crlDistributionPoints` over the certificates of
      the 47 measured hosts, and of `crl_validity` against `openssl crl`
      over the 65 measured lists, ran once while implementing on the
      chains and lists saved on 2026-11-20 while planning: 140
      certificate files (80 distinct certificates; 131 name points with
      145 URIs in all, 9 name none) gave the same URIs in the same order
      as openssl, and the 65 lists the same `thisUpdate` and `nextUpdate`
      in Unix seconds; the reader refused none of them. The harness was a
      temporary test, not committed.

## Consequences

- Every connection whose leaf names a point now fetches its list once per
  process and URL, and again 24 h later or at its `nextUpdate`. OCI pulls
  fetch Docker Hub's 1,889,589 B list (measured 0.25 s); the forge is
  unchanged, because GitHub's leaf names no point. A fetch on a cold cache
  counts against `TlsDial`'s request deadline.
- The runner, and the gateway of #20, need outbound HTTP to the CRL hosts
  of their endpoints; a host that blocks outbound port 80, or allows only
  443 to listed hosts, fails closed for every endpoint whose leaf names a
  point (`docs/ARCHITECTURE.md`).
- Memory: 4.9 B per CRL byte, at most about 314 MiB for a full cache;
  CPU: up to 11.5 ms per connection for the largest measured list.
- The `oci-acceptance` workflow fetches Docker Hub's lists for real every
  week.
- **Known limits**, each with where it closes:
  - Leaves without a point, GitHub's, GHCR's and GitLab's among them, get
    no check (D2): Replikanti/boneli#79, filed at #38 STOP 2. Closed for leaves
    that name an OCSP responder by ADR-020 (Replikanti/boneli#79); a leaf
    with neither still passes unchecked.
  - Intermediates are not checked (D3):
    Replikanti/boneli#80, filed at #38 STOP 2.
  - No CRL fetch through a proxy. `boneli-https` has no proxy support
    for its own connections either, so a host that needs a proxy cannot
    use the client at all today; this ADR adds no new case. When proxy
    support lands, the `CrlSource` seam takes a proxy source.
  - Staleness: at most about 48 h after the CA records a revocation while
    refreshes get through, plus 1 h per failed refresh in a row, and up to
    the cached list's `nextUpdate` (238 h measured, 240 h by the BR) while
    they fail, including when an attacker on the path drops them (item 8).
  - During an outage that stalls instead of refusing, one connection per
    URL per hour waits for its refresh up to the check or request
    deadline; if the request deadline passes, that one request fails.
  - Clock skew larger than a list's remaining validity fails closed, as an
    expired certificate already does.
  - The name resolution of a CRL host is not bounded by the check's or
    `TlsDial`'s request deadline: std's resolver takes no timeout, so a
    resolver whose answers are dropped holds the check for its own
    timeout per URL. It is the same gap `TlsDial` has for its own target,
    and everything after the lookup is bounded. Both close in
    Replikanti/boneli#81. Closed by ADR-022 (Replikanti/boneli#81).
  - A cold cache adds one fetch per URL per process; a slow fetch could
    outlast a server's idle timeout on the open TLS connection
    (assumption, not measured: servers wait well over the measured 0.59
    s), and the caller then reconnects with a warm cache.

## Alternatives considered

- **Fail-open.** Rejected in item 4: the attacker revocation is for can
  drop the plain-HTTP fetch.
- **Fail closed with a per-config soft-fail opt-out,** like
  `TlsConfig::classical`. Rejected at STOP 1 (D1): the opt-out would give
  back exactly what fail-open gives an attacker on the path, and ADR-005
  item 8 has no switch for certificate verification either.
- **A verifier inside the handshake.** Rejected in item 1.
- **The whole chain.** Deferred (D3, item 2).
- **`x509-parser` or `x509-cert`** for the extension. Rejected in item 9.
- **OCSP.** Out of scope of #38; the follow-up of D2.
- **CRLs disclosed in CCADB** for leaves without a point. Out of scope
  of #38; the leaves without a point are the OCSP follow-up's (D2).
- **Caching until `nextUpdate` with no maximum age.** The recommendation,
  changed at STOP 1 (D5, item 8).
- **A hard maximum age that fails closed when the refresh fails.**
  Rejected in item 8.
- **A maximum age counted from `thisUpdate`.** Rejected in item 8.
- **A refresh in a background thread.** No thread outlives a check; the
  connection that claims the refresh pays for it.
- **A disk cache,** or any cache that outlives the process. Out of scope
  of #38: the cache only saves fetches.
- **One fetch per URL at a time across threads.** Two cold checks may
  both fetch; the insert rules keep the later list, and the claim already
  keeps refreshes to one per URL.
