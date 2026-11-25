# ADR-027: Revocation of intermediate certificates

- Status: accepted
- Date: 2026-11-23

## Context

ADR-017 checks a server's leaf for revocation by CRL and decides in D3 to
check the leaf only; ADR-020 adds OCSP for leaves without a CRL point. A
certificate whose intermediate CA has been revoked, for example after
that CA's key leaked, is therefore accepted as long as its own leaf is not
listed. ADR-017's known limit "Intermediates are not checked" points to
issue #80, which this ADR closes. It refines ADR-017 D3 and does not
supersede ADR-017 or ADR-020: the leaf's rules and limits stay as they
are.

What rustls 0.23.46 and rustls-webpki 0.103.17 offer: rustls'
`WebPkiServerVerifier` checks the whole chain against CRLs when
`only_check_end_entity_revocation()` is left out, and webpki's
`RevocationOptions` with `RevocationCheckDepth::Chain` does the same for
`verify_for_usage`. Both need a list that covers every certificate of the
chain, the leaf included (the unknown-status policy is one setting for the
whole chain), and both parse lists with
`BorrowedCertRevocationList::from_der`, which refuses an
issuingDistributionPoint that asserts `onlyContainsCACerts` and names no
`distributionPoint` (`UnsupportedCrlIssuingDistributionPoint`,
`src/crl/types.rs`, the test `test_issuing_distribution_no_name`). RFC 5280
5.2.5 and BR 7.2.2.1 allow that form for a full list; the source of
0.104.0-alpha.8 has the same refusal.

Measured on 2026-11-20, 23:16 to 23:18 UTC, from one host in Europe
(commands in `crates/boneli-https/tests/data/README.md`): the chains of 46
hosts (forges, the runner's hosts, package indexes, LLM APIs, CA and large
company sites) with `openssl s_client -showcerts`, the path of each
computed by webpki itself (`verify_for_usage` with `webpki-roots` 1.0.12,
`serverAuth`, no revocation), every CRL point of the path's intermediates
read with `openssl x509 -ext crlDistributionPoints`, every list fetched
with `curl -w`, read with `openssl crl -text` and given to
`webpki::OwnedCertRevocationList::from_der`:

- **Paths.** 30 hosts have 1 intermediate on the path and 16 have 2;
  none has more. 26 distinct intermediates. 31 of the 46 servers send
  certificates that are not on the path (a cross-signed root such as
  GitHub's `Sectigo Public Server Authentication Root E46`, or
  `auth.docker.io`'s `ISRG Root X2` cross-sign).
- **Roots as intermediates.** Let's Encrypt's `Root YR` and `Root YE`
  (cross-signed by ISRG Root X1 and X2), `GoDaddy TLS Root CA - R1` and
  `Microsoft TLS RSA Root G2` are intermediates on webpki's path, because
  their self-signed versions are not in `webpki-roots`.
- **CRL points.** 26 of 26 intermediates name an `http` point, as BR
  7.1.2.11.2 requires: 23 one URL, 3 two (DigiCert EV RSA CA G2 on `crl3`
  and `crl4`, Microsoft TLS G2 RSA CA OCSP 04 and 10 on `www` and `crl2`).
  15 of 26 also name an OCSP responder.
- **Lists.** 18 distinct URLs, 16 distinct lists (two pairs of mirrors
  serve the same bytes), 284 to 2,157 B, 17,025 B over the 18 URLs, 0 to
  36 entries. All answered 200 without a redirect; connect took at most
  0.081 s, the first byte at most 0.119 s, a whole fetch at most 0.119 s;
  heads were at most 819 B. The longest URL is 74 B.
- **Validity.** 168 h (Sectigo) to 8,736 h (GoDaddy). Age at fetch 5 to
  6,419 h, validity left 162 to 8,280 h.
- **webpki refuses 6 of the 18 URLs**: every Let's Encrypt list (`x1`,
  `x2`, `yr`, `ye`) and both GoDaddy lists, all for the nameless
  `onlyContainsCACerts` IDP. With webpki's chain check 13 of the 46 hosts
  would fail closed, among them `auth.docker.io`,
  `production.cloudflare.docker.com` (Docker Hub's blob CDN),
  `objects.githubusercontent.com`, `pkg-containers.githubusercontent.com`,
  `deb.debian.org` and `repo.maven.apache.org`.
- **A real revoked intermediate.** `x1.c.lencr.org` (thisUpdate
  2026-11-05) lists two ISRG Root X1 cross-signs as superseded on
  2026-05-13: `Root YR` serial `FAA6275DC258431D9766EC3045EF24AC` (crt.sh
  20947047101) and `ISRG Root X2` serial
  `7F2AB707B5BDD93C9FD48B7C6029DB33`. The servers send the current
  cross-signs (`Root YR` `F24B6D17...`), which are not listed.
- **Baseline Requirements v2.3.1.** A CA that issues CA certificates
  publishes a new CRL at least every 12 months and within 24 h after it
  records a revocation (4.9.7); such a list's `nextUpdate` is at most 12
  months after `thisUpdate` (7.2). The point MUST be present in a
  subordinate CA certificate (7.1.2.11.2). A `distributionPoint` in the
  IDP is required only for a partitioned list, and a CA must not assert
  both `onlyContains*` flags (7.2.2.1).

Decided at #80 STOP 1 (2026-11-21), all three as the plan recommended:

- **D1, decided at STOP 1:** an own strict parser for the intermediates'
  lists, webpki only for the path and the signatures (items 3 and 4).
- **D2, decided at STOP 1:** an intermediate without an `http` or `https`
  CRL point passes unchecked, a named known limit (item 2).
- **D3, decided at STOP 1:** the limits of item 6.

## Decision

1. **Where and in which order.** In the hook of ADR-017 item 1, after the
   handshake, on `peer_certificates()`, so resumed sessions are checked
   again. When the server sent more than its leaf, webpki rebuilds the
   verified path (`EndEntityCert::verify_for_usage` with the handshake's
   roots and algorithms, `serverAuth`, at the check's `now`, no
   revocation: ADR-020 item 2's call). Every intermediate on that path is
   checked from the anchor side down, the last intermediate first; then
   the leaf exactly as before. Checking the anchor side first means a URL
   is fetched only from a certificate whose issuers have passed, so a CA
   whose key leaked and whose certificate is revoked cannot steer fetches
   through the leaves it signs. A chain of the leaf alone has no
   intermediate: rustls verified it, so a root issued it, and no path is
   rebuilt. A path that does not verify again fails closed
   (`RevocationUnknown`), as for OCSP.

2. **The path, the anchor and the points (D2, decided at STOP 1).** Only
   certificates on the path are read: the anchor and every certificate
   the server sent beside the path are never fetched for. The anchor is
   configured trust and is not checked. Each intermediate's points follow
   ADR-017 item 3: the URIs of points whose name is a `fullName` without
   `reasons` or `cRLIssuer`, ADR-017's grammar, other schemes skipped, at
   most `MAX_CRL_URLS`, a refused URL counted as `BadUrl`. An intermediate
   with no `http` or `https` point passes as `NoRevocationSource`. Basis
   of D2, ADR-017 D2's: the point sits in a signed extension, 26 of 26
   measured intermediates have one, and BR 7.1.2.11.2 requires it. Weak
   spot: an intermediate of a private PKI without a point is never
   checked. An intermediate that names only an OCSP responder passes the
   same way; none was measured.

3. **The parser (D1, decided at STOP 1).** `ca_list` reads the
   CertificateList with ADR-017's DER reader, strictly, because its result
   decides and nothing behind it checks again (as ADR-020 item 4's OCSP
   parser): definite minimal lengths and no trailing bytes at any level;
   version 2; the inner `signature` equal to the outer algorithm byte for
   byte (RFC 5280 5.1.1.2); `nextUpdate` required; `revokedCertificates`
   absent or an empty SEQUENCE; every entry serial a minimal DER INTEGER
   (BR 7.2 compares serials byte for byte); the signature a BIT STRING
   with no unused bits. A list extension seen twice, `deltaCRLIndicator`,
   and any other critical extension than authorityKeyIdentifier,
   cRLNumber and issuingDistributionPoint are `Malformed`; unknown
   non-critical ones are ignored. In an entry, a critical extension other
   than `reasonCode`, a duplicate, and a malformed `reasonCode` are
   `Malformed`. The issuingDistributionPoint is read whether or not it is
   marked critical, so a scope is never ignored; `nameRelativeToCRLIssuer`,
   an empty `fullName`, `onlySomeReasons`, `indirectCRL`,
   `onlyContainsAttributeCerts` and both `onlyContains*` flags are
   `Malformed`. Rust was the only language weighed for code inside this
   Rust crate.

4. **The decision.** In this order, for one intermediate and its issuer
   on the path:
   - Dates: `nextUpdate < thisUpdate` is `Malformed`; `now >= nextUpdate`
     is `Expired` (exclusive, as webpki's bound and ADR-017's); a
     `thisUpdate` in the future is accepted, as webpki and ADR-020 accept
     one.
   - Authority: the list's issuer Name must equal the intermediate's
     issuer Name byte for byte (the content webpki's `Cert::issuer()`
     returns). Without an IDP the list is authoritative. With one,
     `onlyContainsUserCerts` is not authoritative for a CA; a `fullName`
     must have a URI equal, byte for byte, to a URI of the intermediate's
     points (webpki's rule); an IDP without a `distributionPoint` is
     authoritative within its scope (RFC 5280 5.2.5). This last rule is
     the one difference from webpki, and the reason for D1.
   - Right to sign: an issuer that is an intermediate whose keyUsage lacks
     `cRLSign` does not settle (webpki's `IssuerNotCrlSigner`). An anchor's
     key usage is not checked, as webpki does not.
   - Signature: over the raw `tbsCertList` bytes with the issuer's SPKI
     (the next intermediate's, or the anchor's for the top one) and every
     algorithm of the handshake whose signature id equals the list's and
     whose key id equals the key's: webpki's matching rule, now one helper
     (`signature::verified`) shared with ADR-020's response check. SHA-1
     lists (SC-053) never verify.
   - Status: any entry whose serial content equals the intermediate's is
     `Revoked`, whatever its `reasonCode` (`removeFromCRL` belongs to delta
     lists, which are refused; a hold is a revocation while listed).
     Otherwise `Good`.

5. **The algorithm per intermediate.** ADR-017 item 4's, with the CA
   cache (item 7), each URL in order: fresh and stale cached lists decide
   without a fetch; a due refresh is soft (a failed refresh leaves the
   cached list deciding until its `nextUpdate`); a revoking list is cached
   and returns `Error::Revoked { url }` at once, and no mirror is asked to
   overrule it; before a pass is returned, every cached list of the
   intermediate's other points still before its `nextUpdate` is decided
   too, so a revocation seen at one point wins over a later pass at
   another; only a list that settled a certificate is cached; when no URL
   settles it, `Error::RevocationUnknown(failures)` with each detail
   prefixed `intermediate k of n` (k = 1 is the leaf's issuer). A cached
   list is decided again for every certificate it is used for, against
   that certificate's issuer key, so a list cached for one issuer never
   settles a certificate of another. Statuses come back in path order,
   the leaf's issuer first (`TlsStream::intermediate_revocation`).
   Fail closed with no opt-out, ADR-017 D1's reason: the list travels
   over plain HTTP on the attacker's path.

6. **Fetch and limits (D3, decided at STOP 1).** The fetch is ADR-017
   item 6's, through the same `CrlSource`, which gains the provided method
   `fetch_limited(url, cap, deadline)`; the HTTP source fails a
   `Content-Length` above the cap before the body, and every source is
   held to the cap after the fetch. Per connection:
   - `MAX_CA_CRL_BYTES` 1,048,576 B per list: 486 times the largest
     measured CA list (2,157 B; ADR-017 saw 2,199 B). At ADR-017's 38 B
     per entry (11,005,110 B for 289,071 entries) it holds about 27,500
     entries; the most measured on a CA list is 36. Lower values would
     still pass every measured list but refuse more private PKIs whose CA
     list also carries leaves; higher values raise the per-connection
     bytes (8 times the cap) and the fetch time, 1 s per MiB at
     `CRL_MIN_RATE`. A list above it fails closed (`TooLarge`).
   - `MAX_CA_CRL_FETCHES` 8 per connection, refreshes included, apart from
     the leaf's own limits. The measured cold-cache worst case is 2
     intermediates times 2 URLs, 4 fetches, when every first URL fails and
     the mirrors answer; 8 is twice that. A chain at webpki's maximum of 6
     intermediates (`MAX_SUB_CA_COUNT`) with one working URL each needs 6,
     which fits. 4 would refuse 5- and 6-deep private chains on a cold
     cache; more only lets dead URLs cost more inside the deadline. At the
     limit a missing list is `RevocationFailureKind::LimitReached` without
     a fetch, and a due refresh is left to the cached list and counts as a
     failed refresh (the next waits `CRL_REFRESH_RETRY_SECS`). At most
     8 x 1,048,576 = 8,388,608 B of lists per connection, plus 8 heads of
     at most 16,384 B.
   - `CA_CRL_CHECK_DEADLINE` 38 s, one deadline for all intermediates of a
     connection: `CRL_SETUP_TIME` 30 s (a 10 s connect, a 10 s handshake
     for `https` points, a round trip) plus 8 lists at the cap at
     `CRL_MIN_RATE` 1,048,576 B/s, 8 s. `TlsDial`'s request deadline cuts
     it shorter. A whole measured fetch took at most 0.119 s. Lower would
     cut a healthy `https` fetch; higher only delays failure behind a dead
     CDN. With the leaf's 62 s, a connection's worst case is 100 s, cut by
     the request deadline.
   - Reused, each for its own reason: `MAX_CRL_URLS` 4, twice the measured
     maximum of 2 URLs per intermediate; `MAX_CRL_URL_BYTES` 1,024, 13.8
     times the longest measured URL (74 B); `CRL_MAX_HEAD_BYTES` 16,384 and
     `CRL_MAX_HEADERS` 64, 20 times the measured 819 B; the 10 s timeouts by
     ADR-017's TCP arithmetic (SYN retransmissions at 1, 3 and 7 s).

7. **Cache.** A second instance of ADR-017 item 8's cache, now generic
   over what it stores, with its own byte cap: one per `TlsConfig`
   (clones share it), keyed by the canonical URL, holding the DER of each
   list that settled an intermediate. A URL that is both a leaf's point
   and an intermediate's keeps both lists, one in each cache.
   - `CA_CRL_CACHE_MAX_BYTES` 16,777,216 B: 16 lists at the cap, and 985
     times all 18 measured lists (17,025 B). It stores DER only, decided
     again per use, so memory equals bytes. Lower thrashes once many
     near-cap private lists alternate; higher only raises the worst case.
   - `CRL_MAX_AGE_SECS` 86,400 and `CRL_REFRESH_RETRY_SECS` 3,600, for this
     cache's own reason: BR 4.9.7 gives a CA that issues CA certificates 24
     h to publish a revocation, so the runner sees it within 24 + 24 = 48 h
     while refreshes get through. Without a maximum age, a cached CA list
     could trail by up to its validity, 8,280 h left measured. The cost is
     one fetch of at most 2,157 B per URL per day.
   - The insert, staleness and eviction rules are ADR-017 item 8's, and
     the leaf's cache keeps them unchanged.

8. **Errors and what the API reports.** A revoked intermediate is
   `Error::Revoked { url }` with its issuer's list; one that no list
   settles is `Error::RevocationUnknown` (`intermediate k of n` in each
   detail); the new failure kind is `LimitReached`. The docs of
   `Error::Revoked`, `Error::RevocationUnknown`, `RevocationStatus` and
   `RevocationFailureKind` now speak of a certificate of the server's
   chain. `TlsStream::intermediate_revocation()` returns one status per
   intermediate, empty when a root issued the leaf. The connection of an
   `https` fetch still checks nothing, so a fetch cannot recurse.

9. **Code and crates.** About 950 lines of Rust in `boneli-https`
   (`ca_list`, `chain`, `signature`, a keyUsage reader in `der`, the
   generic cache), comments included, plus tests. No new crate and no new
   edge: `boneli-https -> rustls-webpki` was approved by ADR-020 for the
   path; its record in `tools/architecture.toml` now also names the
   issuers of intermediates and keeps `decision = "ADR-020"`, the ADR that
   approved the edge.

10. **The seam.** `CrlSource` serves both caches. Whatever it returns for
    an intermediate is decided by `ca_list` against the issuer on the
    verified path and the system clock: a source can make a connection
    fail, hand over an older list the issuer signed that is still before
    its `nextUpdate` on a cold cache, or keep a cached list in use until
    its `nextUpdate` by failing every refresh, and nothing else.

11. **Measured cost.** On a warm cache, the check of the two
    intermediates of `www.microsoft.com`'s captured chain (RSA, lists of
    1,032 and 2,102 B) took 0.186 ms per connection in a release build
    (2,000 runs, the parse and two RSA signature checks), and the path
    rebuild 0.30 ms. A cold cache adds one fetch per intermediate.

12. **Proof, and what each test does not prove.**
    - Unit tests in `src/revocation/ca_list.rs`, with lists built and
      signed at test time with the kept test keys and two lists from
      openssl as an independent encoder: issuer, scope, IDP names, the
      unsupported IDP forms, the signature, `cRLSign`, entry serials,
      reason codes, critical extensions, structure, SHA-1, the dates at
      each bound, every truncation and every flip of a byte with three
      masks over the fixture and capture lists (refused or the same
      verdict, never `Good` after a flip inside `tbsCertList`). Ten hand
      mutants of the decision and the order, each killed by a named test
      (the PR lists them).
    - Differentials against webpki, committed: the issuer bytes and serial
      set of every capture webpki parses (10 lists from the 12 URLs) and
      of fixture lists; the revoked or good verdict of a two-intermediate
      fixture chain under nine list pairs against `verify_for_usage` with
      `RevocationOptions` (depth `Chain`, unknown status `Allow`,
      expiration `Enforce`). And a test that webpki still refuses the six
      nameless-IDP captures: if it passes after a webpki update, D1 is to
      be revisited.
    - Real captures at their capture time and at each list's
      `nextUpdate`: Let's Encrypt's `yr` and `x1` lists settle
      `valid-isrgrootx1`'s two intermediates, Sectigo's E46 and R46 lists
      settle E36 (`github.com`) and R36 (`gitlab.com`), Microsoft's and
      DigiCert's lists settle `www.microsoft.com`'s two, and `x1` revokes
      the superseded `Root YR` cross-sign from crt.sh. They pin the
      encodings of six CAs, not every CA.
    - A one-time differential while implementing, not committed: the
      parser over the 16 distinct measured lists against `openssl crl
      -text` agreed on 16 of 16 (`thisUpdate`, `nextUpdate`, every serial,
      openssl printing them without the DER sign byte, and the IDP's name
      and user-only flag).
    - `tests/intermediates.rs`: real handshakes on loopback through the
      public API with a fake source: revoked and good intermediates,
      unreachable, malformed, expired, foreign and forged lists, the size
      cap at each bound, the URL limit, the budget (a ninth fetch fails
      closed, the leaf's fetches do not count), the cache (per URL, a
      cached revocation at another point, a URL shared with a leaf),
      OCSP-route and sourceless leaves under a revoked CA, the root and a
      stray CA sent by the server, resumed TLS 1.2 and 1.3, a CONNECT
      tunnel and `TlsDial`'s deadline. Every test of `tests/revocation.rs`
      and `tests/ocsp.rs` passes unchanged, and so do the unit suites of
      the leaf's check and cache, whose only edits are the cache's type
      parameter and its field `verifier` renamed `value`.
    - By hand before merge (#80): `tests/network.rs`
      `intermediates_checked_live` gave, on 2026-11-23,
      `valid-isrgrootx1.letsencrypt.org` both intermediates `Checked` by
      `http://yr.c.lencr.org/` and `http://x1.c.lencr.org/` and its leaf
      `Checked`; `revoked-isrgrootx1` refused by its leaf's list after its
      intermediates passed; `github.com` E36 `Checked` by
      `crl.sectigo.com` and its leaf `OcspChecked`; and every intermediate
      of `api.github.com`, `ghcr.io`, `gitlab.com`, `registry-1.docker.io`,
      `auth.docker.io`, `production.cloudflare.docker.com`,
      `pkg-containers.githubusercontent.com` and `api.anthropic.com`
      `Checked`. ADR-017's and ADR-020's live tests, `ocsp::live`, the
      OpenSSL interop test and the forge's live acceptance test
      (`boneli-acceptance`, ADR-014 D12) passed with the check on.

## Consequences

- A certificate under a revoked intermediate is refused, the broad event
  revocation exists for, including the forge connections that carry the
  installation token.
- The runner, and the gateway of #20, need outbound HTTP to the CA list
  hosts of their endpoints too: `crl.sectigo.com` for GitHub, GHCR and
  GitLab beside `ocsp.sectigo.com`, and `x2.c.lencr.org` and
  `ye.c.lencr.org` for Docker Hub's auth host and blob CDN
  (`docs/ARCHITECTURE.md`).
- Availability: every endpoint now also depends on its CA list hosts on a
  cold cache and at each list's `nextUpdate`. A warm cache rides out an
  outage until `nextUpdate`: Sectigo's root lists had 162 h left at fetch.
- Cost per connection: on a cold cache up to 8 fetches of CA lists (2
  measured, at most 2,157 B each), on a warm cache about 0.5 ms of CPU
  (item 11). CA fetches also happen when the leaf turns out revoked.
- Memory: at most 16 MiB for a full CA cache.
- **Known limits**, each with where it closes:
  - An intermediate without an `http` or `https` CRL point passes
    unchecked (D2), an intermediate that names only an OCSP responder
    among them. Not closable without failing such private PKIs closed;
    0 of 26 measured intermediates lack a point.
  - The anchor is configured trust and never checked. Removing a root is
    the root program's job (`webpki-roots` releases), not this check's.
  - Replay: an attacker on the path can replay an older list the issuer
    signed on a cold cache until its `nextUpdate`, up to 12 months under
    BR 7.2 (8,280 h left measured on Let's Encrypt's lists), far longer
    than the leaf's 10 days. A warm cache keeps the newest list and a
    cached revocation is final. Inherent to CRLs.
  - Staleness: at most about 48 h after the CA records a revocation while
    refreshes get through (item 7), plus 1 h per failed refresh in a row,
    and up to the cached list's `nextUpdate` while they fail.
  - A private CA whose list for an intermediate exceeds 1 MiB fails closed
    (D3), with no opt-out (ADR-017 D1).
  - Delta and indirect lists, `onlySomeReasons` partitions and names
    relative to the issuer are refused (`Malformed`), so a CA that uses
    them fails closed. None was measured.
  - No fetch through a proxy, as ADR-017's known limit says. Closed by
    ADR-039 (Replikanti/boneli#55).

## Alternatives considered

- **webpki's chain-depth check** (rustls' verifier without
  `only_check_end_entity_revocation()`, or `RevocationOptions` with
  `RevocationCheckDepth::Chain`). Rejected by D1: it refuses 6 of the 18
  measured URLs, so 13 of 46 hosts would fail closed, Docker Hub's among
  them; and it needs a list covering the leaf too, which OCSP-route
  leaves (GitHub, GHCR, GitLab) never have.
- **webpki where it parses, our parser elsewhere.** Rejected: two decision
  paths for one question, and the weaker one decides when they differ.
- **Soft-fail on webpki's refusal.** Rejected: fail-open, because an
  unsigned forged list with a nameless IDP is refused before its
  signature is checked, so an attacker could turn every check off.
- **An upstream webpki change for nameless IDPs.** Out of scope for this
  issue; the test of item 12 tells when a release accepts them.
- **OCSP for intermediates.** Rejected: every measured intermediate names
  a CRL point, and 11 of 26 name no responder.
- **A pushed list such as Mozilla's OneCRL.** Rejected: its staleness is
  tied to releases of a list we would have to ship, and it covers the
  public PKI only.
- **`x509-cert` or `x509-parser` for the codec.** Rejected: new crates,
  and the decisions (authority, scope, signer, time) stay ours in every
  option; ADR-017 item 9 rejected the first for the same reason.
- **The leaf first.** Rejected: a leaf of a revoked CA could steer a fetch
  before the CA is refused (item 1).
- **Failing closed on an intermediate without a point (D2).** Rejected at
  STOP 1: it refuses private PKIs whose CAs publish no list, for a case
  that no measured public intermediate has.
- **A per-connection byte budget at the leaf's 32 MiB.** Rejected: 15,500
  times the largest measured CA list, so it bounds nothing that the
  fetch count and the per-list cap do not.
