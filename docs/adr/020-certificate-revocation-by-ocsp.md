# ADR-020: Certificate revocation by OCSP

- Status: accepted
- Date: 2026-11-20

## Context

ADR-017 checks a server's leaf for revocation through its CRL
distribution points. A leaf without one passes unchecked (ADR-017, D2),
and the six forge hosts whose traffic carries the installation token with
`contents: write` are such leaves: `github.com`, `api.github.com`,
`codeload.github.com`, `ghcr.io`, `gitlab.com` and `registry.gitlab.com`.
ADR-017's first known limit points to issue #79, which this ADR closes for
leaves that name an OCSP responder. It refines ADR-017 D2 and does not
supersede ADR-017: a leaf with a CRL point stays on ADR-017's path.

What rustls 0.23.46 and rustls-webpki 0.103.17 offer: webpki has no OCSP.
rustls sends `status_request` in every ClientHello
(`src/client/hs.rs`, line 233) and hands a stapled response only to
`ServerCertVerifier::verify_server_cert`, which it skips on resumption
(ADR-017, item 1); after the handshake it exposes nothing.
`EndEntityCert::verify_for_usage` returns the `VerifiedPath` with the
leaf's issuer (its first intermediate, or its anchor), and checks any
certificate for any extended key usage against anchors the caller gives.

Measured on 2026-11-20, 13:24 to 13:40 UTC, from one host in Europe, with
`openssl s_client -showcerts`, `openssl ocsp` and curl (commands in
`crates/boneli-https/tests/data/README.md`):

- **The six hosts.** None names a CRL point; each names one AIA OCSP URL,
  `http://ocsp.sectigo.com`. They have 5 distinct leaves (`api.` and
  `codeload.github.com` share `*.github.com`). `github.com`, `api.` and
  `codeload.github.com` come from Sectigo DV E36 (ECDSA), `ghcr.io`,
  `gitlab.com` and `registry.gitlab.com` from DV R36 (RSA 2048). Leaf
  validity is 90 to 199 days.
- **Stapling.** 1 of the 6 staples (`gitlab.com`).
- **Sectigo's answers.** 279 B (E36, ecdsa-with-SHA256) and 599 to 600 B
  (R36, sha256WithRSAEncryption), all signed directly by the issuing CA
  (responder ID by key, equal to the issuer's key hash), no certificates.
  The CertID comes back SHA-1 even when the request used SHA-256 (5 of 5
  leaves). The nonce is ignored (10 of 10 requests with a nonce came back
  without one). Validity 604,799 s on all 5. Age at fetch 35.78 to 82.23 h
  (median 62.81 h), validity left 85.76 to 132.21 h. Requests are 83 to
  84 B of DER, the GET path 117 to 119 B.
- **HTTP.** 12 of 12 GETs without `User-Agent` and `Accept` answered 200
  from 8 responder URLs (Sectigo, DigiCert, Amazon, GlobalSign three
  times, Microsoft, SSL.com). That run measured connect at most 0.087 s
  and first byte at most 0.152 s; across all runs a whole fetch took at
  most 0.347 s. Heads at most 826 B and 16 fields. Every response was
  `application/ocsp-response`, no content coding, no redirect. POST also
  answered 200 at Sectigo. Sectigo sits behind Cloudflare
  (`CF-Cache-Status: HIT`, `s-maxage=1800`); edge lifetimes across
  responders range from 300 to 86,400 s.
- **All 13 answers** (the 5 Sectigo ones, and DigiCert, Amazon, GlobalSign
  three times, Microsoft and SSL.com twice for generality; those leaves
  also name a CRL point): 279 to 2,341 B. Delegated responders at
  GlobalSign (3) and Microsoft (1), one certificate each; every responder
  certificate has EKU `OCSPSigning` only and `ocsp-nocheck`, a 2048- to
  4096-bit RSA key and a validity of 7 days to 6 months. Responder ID by
  name at SSL.com (2 of 2), by key elsewhere. CertID SHA-1 in 13 of 13.
  Validity 12 h (GlobalSign Atlas) to 168 h. GeneralizedTime without
  fractions, no explicit version, no response extensions.
- **Revoked, live.** SSL.com's `revoked-rsa-dv` and `revoked-ecc-dv`
  test sites answer `revoked` (by name, signed by the CA). Both leaves
  also name a CRL point, so the public API checks them by CRL. No public
  test site with a revoked leaf that names only an OCSP responder was
  found.
- **The CCADB alternative.** Sectigo DV R36's full CRL is 26,563,231 B
  with 725,150 entries and a 7-day validity, fetched in 0.92 s; DV E36's
  is 118,310 B. 26.6 MB is 79 % of `MAX_CRL_BYTES`. At ADR-017's 4.9 B of
  memory per CRL byte that is about 124 MiB, and about 26 to 28 ms per
  verify (both extrapolated from ADR-017's measurements, not measured).
  The mapping from an issuer to its full CRL is not in the certificate.
- **Baseline Requirements v2.3.1.** 4.9.9: GET support SHALL, a nonce MAY;
  subscriber answers valid 8 h to 10 days; a new answer at least 8 h
  before `nextUpdate` and no later than 4 days after `thisUpdate`; the
  24 h bound after a revocation applies only to CA certificates. 4.10.2:
  a response time of 10 s or less. 4.10.1: revocation entries stay until
  the certificate expires. 7.1.2.8: a delegated responder is issued by
  the same CA, with EKU `OCSPSigning` and `ocsp-nocheck`. SC-053: no SHA-1
  signatures.

Decided at #79 STOP 1 (2026-11-20), all three as the plan recommended:

- **D1, decided at STOP 1:** fail closed on every OCSP outcome that does
  not settle the leaf, with no opt-out (item 5).
- **D2, decided at STOP 1:** cache an answer until `min(nextUpdate, last
  fetch + 24 h)` with a soft refresh and a 1 h retry, ADR-017 D5's
  staleness policy (item 6).
- **D3, decided at STOP 1:** OCSP rather than the issuing CA's full CRL
  from CCADB (Alternatives).

## Decision

1. **Routing.** The check runs where ADR-017's does, after the handshake
   on `peer_certificates()`, resumed sessions included. A leaf that names
   an `http` or `https` CRL point after skipping other schemes takes the
   CRL path only, and its OCSP URLs are never read. Only a leaf without
   one reads its authorityInfoAccess extension: the
   `uniformResourceIdentifier` locations of its `id-ad-ocsp` descriptions,
   in certificate order; `caIssuers`, other location types and a second
   AIA extension are skipped or refused as for CRL points, and an AIA
   extension that cannot be read is `RevocationUnknown([BadUrl])`. URLs
   follow ADR-017's grammar (item 3), and a URL with a query is refused as
   `BadUrl`, because the request is appended to the path. Other schemes
   (`ldap`) are skipped. A leaf with neither source still passes
   unchecked (`RevocationStatus::NoRevocationSource`, ADR-017 D2).

2. **The issuer.** rustls does not expose the path it verified, so the
   check verifies the chain again with webpki
   (`EndEntityCert::verify_for_usage` with the handshake's roots and
   algorithms, `serverAuth`, at the check's `now`) and takes the leaf's
   issuer from that `VerifiedPath`: its first intermediate, or its anchor
   when a root issued the leaf. The issuer is never one of the
   certificates the server sent beside the leaf unless the path goes
   through it. webpki picks the path by the same rules rustls used; a
   different path could only change the issuer's key, which no answer
   then matches, so the check fails closed. This is the new direct edge
   `boneli-https -> rustls-webpki` that ADR-017 item 2 names for #80.

3. **The request.** One `CertID` with SHA-1 hashes (the hash every
   measured responder answers with): the issuer name hash over the whole
   DER Name, the key hash over the issuer's subjectPublicKey bits, the
   leaf's serial as encoded. No version, no requestor name, no extensions
   (so no nonce: no measured responder echoes one, and BR 4.9.9 makes it
   optional), no signature; byte for byte what `openssl ocsp -no_nonce
   -reqout` writes. Sent as a GET (RFC 6960, A.1; BR 4.9.9 requires GET):
   the responder's path without one trailing `/`, then `/`, then the
   request in standard base64 with `+`, `/` and `=` percent-encoded. A GET
   is cacheable at the CDN, which Sectigo's Cloudflare front uses.

4. **Accepting an answer.** The parser is strict: definite minimal
   lengths, no trailing bytes at any level. `responseStatus` 0 only;
   1, 2, 3, 5 and 6 are `ResponderError`, any other value `Malformed`.
   `responseType` must be `id-pkix-ocsp-basic`; the signature a BIT
   STRING with 0 unused bits; the version absent or `[0] INTEGER 0`. The
   responder ID must be a well-formed `[1]` Name or `[2]` key hash but is
   never used to pick the signer. At most `MAX_OCSP_RESPONSE_CERTS`
   certificates and at least one `SingleResponse`. An extension marked
   critical, in the response or a single response, is `Malformed`: the
   client understands none; a non-critical one, a nonce for example, is
   ignored. The signer is tried in this order: the issuer's key, then each
   certificate of the answer that webpki verifies with the issuer as the
   only anchor, no intermediates, for `id-kp-OCSPSigning` (required, not
   only if present) at `now` (RFC 6960 4.2.2.2, BR 7.1.2.8); a CA
   certificate fails as an end entity. The signature is checked over the
   raw `tbsResponseData` bytes with every algorithm of the handshake
   whose signature id equals the answer's `signatureAlgorithm` and whose
   key id equals the signer's: webpki's own matching rule, so SHA-1
   signatures (SC-053) and an algorithm claimed over the wrong key type
   never verify (`BadSignature`). A `SingleResponse` counts when its
   CertID hash is SHA-1 or SHA-256 with NULL or absent parameters and its
   name hash, key hash and serial content bytes equal the leaf's exactly;
   a different encoding of the same serial does not count. Every match
   needs a `nextUpdate` (missing is `Malformed`), `thisUpdate <=
   nextUpdate` (otherwise `Malformed`) and `now < nextUpdate` (otherwise
   `Expired`, exclusive as webpki's bound for a CRL). A `thisUpdate` in
   the future is accepted, as webpki accepts one for a CRL. Any revoked
   match decides `Revoked`; otherwise any `unknown` decides
   `UnknownCertificate`; otherwise `Good`. No match is `NotSettled`.

5. **The algorithm, and fail closed (D1, decided at STOP 1).** Under one
   deadline, `min(OCSP_CHECK_DEADLINE, TlsDial's request deadline)`, and
   one `now`: issuer and CertID, then the cache (item 6), then each URL in
   order: fetch, size check, verify. A revoked answer is cached and
   returns `Error::Revoked { url }` at once; no second responder is asked
   to overrule it. A good one is cached and returns
   `RevocationStatus::OcspChecked { url }`, unless the cache already holds
   a revocation for the leaf, which then decides. Any other outcome is
   recorded and the next URL is tried; when none settles the leaf the
   connection fails with `Error::RevocationUnknown(failures)`: unreachable,
   timeout, non-200, too large, malformed, responder error, unknown
   certificate, bad signature, expired, not settled and bad URL. Basis of
   D1, ADR-017 D1's: the answer travels over plain HTTP on the attacker's
   path, so soft-fail means no check against the attacker revocation is
   for. Weak spot: forge traffic that had no revocation check until now
   stops for a runner that starts with a cold cache during an outage of
   Sectigo's responder; a warm cache rides out at least 72 h (item 6).

6. **The cache (D2, decided at STOP 1).** One per `TlsConfig` (clones
   share it), in memory, keyed by the SHA-1 CertID, so the responder URLs
   of one leaf share one entry. Each entry holds the status (good or
   revoked), `thisUpdate`, `nextUpdate`, the responder URL, `confirmed_at`,
   `claimed_at` and a use counter. The staleness arithmetic is ADR-017
   item 8's, now one pure function both caches call: fresh while
   `confirmed_at <= now < confirmed_at + OCSP_MAX_AGE_SECS`; then stale
   until `nextUpdate`, where the first check claims the refresh and the
   others use the answer (`OcspCheckedStale`) for
   `OCSP_REFRESH_RETRY_SECS`; never used from `nextUpdate` on, where a
   failure fails closed. A clock moved back refreshes. A refresh succeeds
   with an answer that verifies and is not older than the cached one; a
   revoked answer always counts. Insert rules: a good answer replaces
   only an older good one, an equal `thisUpdate` confirms the entry, an
   older one changes nothing; a revoked answer replaces any good one, and
   no good answer replaces a revocation before its `nextUpdate` (so a
   cached revocation is not refreshed at all). Answers that settle
   nothing are not cached. At most `OCSP_CACHE_MAX_ENTRIES`; eviction
   keeps revocations final: the least recently used good answer goes
   first, a good answer is not stored when only revocations are left
   (it still decides its check), and a revocation leaves before its
   `nextUpdate` only when the cache holds 1,024 of them and a newer one
   displaces the least recently used. A poisoned mutex clears the cache.
   - Why 24 h and 1 h: one staleness policy for both mechanisms. The
     measured answers were 35.78 to 82.23 h old at fetch with 85.76 to
     132.21 h left, so caching until `nextUpdate` alone would trail the
     responder by up to 132.21 h; the daily refresh bounds what the runner
     adds to the CA's own lag to 24 h, plus 1 h per failed refresh in a
     row. Weak spot: BR 4.9.9 lets a CA keep a subscriber answer for 4 days
     after `thisUpdate` even after it revokes, so the daily refresh only
     helps when the CA re-signs at revocation. 1 h would cut the runner's
     share from 24 h to 1 h for about 24 times 600 B a day per leaf;
     D2 kept 24 h.
   - Outage: a warm cache rides out a responder outage of at least 72 h
     (7-day validity minus BR 4.9.9's 4-day refresh lag; 85.76 h
     measured).

7. **Limits and deadlines** (public constants of `boneli_https`):
   - `MAX_OCSP_URLS` 2: twice the measured maximum of 1 (every measured
     leaf that names a responder names one). Fewer would mean no check;
     more only adds attempts inside the same deadline.
   - `MAX_OCSP_RESPONSE_BYTES` 65,536 B: 28 times the largest measured
     answer (2,341 B, Microsoft, one 4096-bit responder certificate),
     room for a responder chain. A `Content-Length` above it fails before
     the body; a source other than HTTP is held to it too. Lower refuses
     responders that send a chain; higher only lets a broken server send
     more.
   - `MAX_OCSP_RESPONSE_CERTS` 4: 1 measured, and delegation is one level
     deep (RFC 6960, 4.2.2.2). It caps the work at 4 webpki path
     verifications per answer.
   - `OCSP_CHECK_DEADLINE` 31 s = 10 s connect (SYN retransmissions at
     1, 3 and 7 s) + 10 s TLS (`https` responders only, none measured) +
     10 s for the response (BR 4.10.2) + 65,536 B at `CRL_MIN_RATE`
     1,048,576 B/s (0.0625 s, rounded up to 1 s). Measured: at most
     0.347 s.
   - Reused fetch limits, re-justified for OCSP: `CRL_CONNECT_TIMEOUT`,
     `CRL_HANDSHAKE_TIMEOUT` and `CRL_IO_TIMEOUT` of 10 s by the same TCP
     arithmetic and BR 4.10.2's 10 s; `CRL_MAX_HEAD_BYTES` 16,384 B and
     `CRL_MAX_HEADERS` 64, 19.8 and 4 times the measured 826 B and 16
     fields; `MAX_CRL_URL_BYTES` 1,024 B, 19.7 times the longest measured
     responder URL (52 B).
   - `OCSP_CACHE_MAX_ENTRIES` 1,024: 204 times the 5 measured OCSP-path
     leaves of the runner. Worst case about 1.2 KiB per entry with a
     1,024 B URL, about 1.2 MiB in all. Lower makes a gateway refetch (at
     most 0.152 s each); higher only raises the worst case.
   - `OCSP_MAX_AGE_SECS` 86,400 s and `OCSP_REFRESH_RETRY_SECS` 3,600 s:
     item 6.

8. **Transport and disclosure.** The fetch is ADR-017 item 6's: HTTP/1.1
   GET through `boneli-http`, `Host` only (12 of 12 measured GETs
   answered without `User-Agent` and `Accept`), no cookies (Sectigo's CDN
   sets one; it is never sent back), 200 only, no redirects, no
   `Content-Encoding`, the body to its end under
   `MAX_OCSP_RESPONSE_BYTES`; directly from the process, never through
   `boneli-egress`. An `https` responder is fetched over `boneli-https`
   without a revocation check of its own, which keeps the fetch from
   recursing. The responder's `http://` transport is on the attacker's
   path: the signature is the only integrity check, which is why item 4
   is strict and D1 fails closed. The request discloses the leaf's serial
   and issuer to the responder and, in plaintext, to the network and the
   responder's CDN (Cloudflare for Sectigo): which host the runner talks
   to, at most once a day per leaf while the cache is warm. The runner
   reaches the same hosts in the open by DNS and SNI anyway.

9. **Stapling is ignored.** rustls asks for a staple in every ClientHello, but
   hands it only to the verifier, which it skips on resumption, and exposes nothing
   after the handshake. Reading it would need a verifier hook that
   misses resumed sessions, to save one fetch for 1 of the 6 hosts. The
   check never reads a staple; a garbage or misleading staple changes
   nothing.

10. **Code and crates.** The request encoder, the response parser, the
    AIA reader, the check and its cache are about 1,200 lines of Rust in
    the crate, comments included, on ADR-017's DER reader (now
    crate-visible, with an encoder and a whole-element read). Unlike
    ADR-017 item 9, this parser's result decides: nothing behind it
    re-checks an answer it accepts. Hence the strictness of item 4, the
    signature over the raw bytes, every certificate decision in webpki,
    the real captures and the differential below. Why our own: RustCrypto's
    `x509-ocsp` brings `der` and `x509-cert`, which ADR-017 item 9
    rejected, and no crate removes the security decisions (signer
    authorization, CertID matching, time), which stay ours in every
    option. Rust was the only language weighed for code inside this Rust
    crate. Two direct edges to crates already in the graph, no new crate:
    `boneli-https -> rustls-webpki` (the verified path and the responder
    check; `default-features = false`, `alloc`) and `boneli-https -> ring`
    (`digest::SHA1_FOR_LEGACY_USE_ONLY`, for CertIDs only; a CertID names a
    certificate the chain already verified, so SHA-1's collisions buy an
    attacker nothing there). Both resolve to the versions already in the
    lock file, and `cargo tree -d` shows no second copy. Their records in
    `tools/architecture.toml` cite this ADR.

11. **The seam `OcspSource`.** Public, like `CrlSource`, through
    `TlsConfig::with_ocsp_source`; `with_crl_source` and
    `with_ocsp_source` keep the other source and start both caches empty.
    It is not a verifier hook: whatever it returns is verified against
    the leaf's issuer on the verified path, the leaf's CertID and the
    system clock. A source can make a connection fail, hand over an older
    answer the issuer signed that is still before its `nextUpdate` on a
    cold cache, or keep a cached good answer in use until its `nextUpdate`
    by failing every refresh, and nothing else. The transport types
    (`CrlUrl`, `CrlScheme`, `CrlFetchError`) and the `CRL_*` fetch limits
    keep their names and are shared; the failure and status names that
    were CRL-only are renamed (`RevocationFailure`,
    `RevocationFailureKind::BadUrl`,
    `RevocationStatus::NoRevocationSource`), and the new kinds
    `ResponderError`, `UnknownCertificate` and `BadSignature` and the
    statuses `OcspChecked` and `OcspCheckedStale` are added.
    `Error::Revoked { url }` names the list or the responder.

12. **Proof, and what each test does not prove.**
    - Unit tests in `src/revocation/ocsp/` and `der.rs`, with explicit
      times and answers built and signed at test time with the kept test
      keys: the parser (every truncation and byte flip, each malformed
      form), the signer rules (delegated, without the EKU, from another
      CA, expired, `CA:TRUE`, a forger, flipped signature and data, an
      algorithm over the wrong key, SHA-1), CertID matching (serial
      encodings, hashes, SHA-256, parameters, MD5), the time window at
      each bound, the cache arithmetic and insert rules, the routing, the
      URL rules, and the request against openssl's bytes. They do not
      prove interoperability; the captures and the live tests do.
    - Real captures, at their capture time and at their `nextUpdate`:
      Sectigo E36 and R36 good, GlobalSign's delegated good, SSL.com's
      revoked by name. They pin the encodings of three CAs, not every CA.
    - `tests/ocsp.rs`: real handshakes on loopback through the public API
      with openssl's responder answers and a fake source: good (by name
      and by key), revoked, unknown, delegated, expired, malformed,
      unreachable, routing, resumed TLS 1.2 and 1.3, CONNECT tunnels,
      `TlsDial`'s deadline, clones, stapling and the default source.
    - By hand before merge (#79): `tests/network.rs`
      `forge_hosts_checked_by_ocsp` gave `OcspChecked { url:
      "http://ocsp.sectigo.com/" }` for 6 of 6 hosts, next to ADR-017's
      Let's Encrypt tests (revoked refused, valid checked); `ocsp::live`
      gave `Revoked` for both SSL.com test leaves through the OCSP path and
      `OcspChecked` for `pypi.org` and `www.microsoft.com` (delegated
      responders); the live forge test (`boneli-acceptance`, ADR-014 D12)
      opened its pull request with the forge's own traffic checked by
      OCSP. No public site with a revoked leaf that names only an OCSP
      responder exists to test the refusal end to end; the revoked path is
      proven by SSL.com through the check and by the loopback tests.
    - A one-time differential, run while implementing and not committed:
      the parser over all 13 measured answers against `openssl ocsp
      -resp_text` agreed on 13 of 13 (hash algorithm, status,
      `thisUpdate`, `nextUpdate`, name hash, key hash, serial; 4 carry a
      responder certificate), and the whole check over each answer with
      its chain and Mozilla's roots at its fetch time gave 11
      `OcspChecked` and 2 `Revoked` (SSL.com), as openssl reports.

## Consequences

- GitHub, GHCR and GitLab connections, which carry the forge token, are
  now checked for revocation: one GET of about 600 B to
  `ocsp.sectigo.com` per leaf per process, then one a day, measured at
  most 0.347 s.
- The runner, and the gateway of #20, need outbound HTTP to the OCSP
  responders of their endpoints (`docs/ARCHITECTURE.md`); for the forges
  that is `ocsp.sectigo.com`. A host that blocks outbound port 80 now
  fails closed for the forges too.
- Forge availability depends on Sectigo's responder on a cold cache and
  at each answer's `nextUpdate` (D1).
- Memory: at most about 1.2 MiB for a full OCSP cache; CPU: one webpki
  path verification and one signature check per fetched answer, none on
  a warm cache.
- **Known limits**, each with where it closes:
  - The CA side: BR 4.9.9 sets no deadline after a revocation for a
    subscriber answer, so a new answer may come up to 96 h after
    `thisUpdate`. Not closable on the client.
  - Replay: an attacker on the path can replay an older answer the issuer
    signed until its `nextUpdate` (7 days measured, 10 days by the BR),
    on a cold cache or by dropping every refresh. No nonce is honored by
    the measured responders, so a nonce would not close it.
  - Disclosure of the serial to the responder and the network (item 8).
  - A delegated responder's own certificate is not checked for
    revocation (`ocsp-nocheck`, RFC 6960 4.2.2.2.1).
  - The name resolution of a responder is not bounded by the deadline:
    Replikanti/boneli#81, as for CRL hosts.
  - Intermediates are not checked: Replikanti/boneli#80.
  - A leaf with neither a CRL point nor an OCSP responder still passes
    unchecked (ADR-017, D2).
  - A cold cache during a responder outage fails closed (D1).
  - No fetch through a proxy, as ADR-017's known limit says for CRLs.

## Alternatives considered

- **The issuing CA's full CRL disclosed in CCADB (D3).** Rejected at STOP
  1: Sectigo DV R36's list is 26,563,231 B against 599 B for one answer,
  about 124 MiB of memory (extrapolated), and the mapping from an issuer
  to its list is not in the certificate, so it would need a table of our
  own. Its strength, that webpki decides, does not outweigh the cost.
- **Soft-fail or an opt-out (D1).** Rejected at STOP 1, ADR-017 D1's
  reason.
- **Caching until `nextUpdate` (D2).** Rejected at STOP 1: it trails the
  responder by up to 132.21 h measured; one policy for both mechanisms.
- **Reading the stapled response.** Rejected in item 9.
- **OCSP as a fallback for leaves that name a CRL point.** Out of scope:
  ADR-017 settles them, and a second source would only add a way for a
  failure to be retried.
- **A nonce.** No measured responder echoes it; it would add bytes and
  close nothing (Known limits).
- **POST.** BR 4.9.9 requires GET support, and a GET is cacheable at the
  responder's CDN.
- **`x509-ocsp` or another crate for the codec.** Rejected in item 10.
- **A disk cache.** Out of scope, as for ADR-017.
