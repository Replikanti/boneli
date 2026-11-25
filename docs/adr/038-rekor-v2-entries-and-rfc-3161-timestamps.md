# ADR-038: Rekor v2 entries and RFC 3161 timestamps

- Status: proposed
- Date: 2026-11-25

## Context

ADR-029 verifies a keyless signature only through a Rekor v1 entry with
an inclusion promise (SET): the SET's integrated time is the one time
the Fulcio leaf is checked at, and the entry is the one transparency
evidence. Its known limit: "A signer that moves to Rekor v2 or to TSA
time is refused". Issue #102 asks for both.

Measured on 2026-11-25 through the anonymous registry API, the release
assets and OpenSSL:

- **A Rekor v2 entry carries no time.** Three real public-good bundles
  logged in `log2025-1.rekor.sigstore.dev` (the cosign signature of
  `ghcr.io/bex-co/bex-cnb-run`, index `sha256:b02a639b…1732df9`, and the
  release bundles of `NVIDIA/aicr` v1.3.0's recipe catalog and SBOM) hold
  a `hashedrekord` 0.0.2 entry with an inclusion proof and a checkpoint,
  no `integratedTime` and no `inclusionPromise`, and exactly one RFC 3161
  timestamp each. Sigstore's conformance suite has
  `rekor2-no-timestamp_fail` ("rekor 2 entries do not come with a
  integrated time making TSA timestamps required"), and sigstore-go never
  takes a time from a v2 entry. A v2 entry is transparency evidence; its
  time has to come from a timestamp authority (TSA). So the TSA comes
  first: this ADR lands in two pull requests, RFC 3161 timestamps first,
  Rekor v2 entries second (#102 STOP 1, decision 1).
- **The v2 entries verify by hand.** For 3 of 3 v2 bundles the canonical
  body rebuilt from the bundle (sorted keys, compact JSON) equals
  `canonicalizedBody` byte for byte, and its digest is the SHA-256 of the
  DSSE PAE. The RFC 9162 inclusion proof (13, 14 and 20 hashes) reaches
  `rootHash`. The checkpoint's first signature verifies with the root's
  Ed25519 key over `origin\nsize\nroot\n`. The root's `logId.keyId` for
  `log2025-1` equals SHA-256(`log2025-1.rekor.sigstore.dev` ‖ `0x0A` ‖
  `0x01` ‖ raw key), the signed-note key ID, so the origin line is bound
  by the key ID and `baseUrl` is never needed. Each checkpoint also has 4
  witness cosignatures; the root holds no witness keys.
- **Seven TSA tokens, all from Sigstore's public-good TSA, verify** with
  OpenSSL against the trusted root's TSA chain (leaf `sigstore-tsa`,
  P-384, EKU timeStamping critical, keyUsage digitalSignature critical;
  anchor `sigstore-tsa-selfsigned`, `CA:TRUE pathlen:0`; both valid
  2025-04-08 to 2035-04-06; the root's window from 2025-07-04, no end):
  the three v2 bundles above, two aicr OpenVEX bundles (v1 SET and a
  token), cosign `latest` (keyed, v1 SET and a token) and the keyless
  `cosign sign` bundle of `ghcr.io/sigstore/scaffolding/trillian_log_server`
  v0.7.42 (v1 SET and a token). `signedTimestamp` is the whole
  `TimeStampResp` (status 0), 717 to 719 bytes. In every token:
  `certificates [0]` is present and empty; one SignerInfo by issuer and
  serial number, digest SHA-256 (parameters absent), signature
  `ecdsa-with-SHA256` under the P-384 key; the signed attributes are
  contentType, signingTime, messageDigest and signingCertificateV2
  (ESSCertIDv2, hash algorithm left out, so SHA-256, certHash = SHA-256 of
  the TSA leaf's DER); the TSTInfo has policy 1.3.6.1.4.1.57264.2, a
  SHA-256 imprint (NULL parameters) of the DSSE signature bytes, genTime
  in whole seconds, accuracy 1 s, no nonce and no extension. **In 4 of
  the 6 keyless tokens genTime equals the leaf's notBefore exactly**
  (aicr recipe catalog, aicr SBOM, aicr OpenVEX 1.3.0 and
  trillian_log_server; bex and the older aicr OpenVEX are notBefore + 1).
  The aicr OpenVEX (and CycloneDX) bundles carry an in-toto
  `Statement/v0.1`, which a bundle may not (ADR-029 S1), so they are
  refused before any timestamp is read; their tokens are known answers of
  the token reader, and trillian_log_server is the known answer of a
  bundle with a SET and a token.
- **Who signs this way.** Sigstore's default signing configuration
  (`signing_config.v0.2.json`, TUF targets v14) still sends signers to
  Rekor v1 plus the TSA, so new keyless `cosign sign` bundles carry a SET
  and a token (trillian_log_server, 2026-11-22). Rekor v2 is opt-in
  (`signing_config_rekor_v2.v0.2.json`), yet `log2025-1`'s checkpoint
  already reads 215,560,469 entries. bex-cnb-run is the one public image
  found on Rekor v2. 12 of 12 measured Fulcio leaves are P-256.
- **GitHub's private-repository instance** (`gh attestation
  trusted-root`, its second root) lists 0 Rekor logs, 0 CT logs, 6 Fulcio
  CAs and 6 TSAs with 3-certificate chains. Its bundles have no log entry
  and no SCT.

## Decision

1. **D1, time.** The verified times of a keyless bundle are the integrated
   time of a Rekor v1 entry with its SET (ADR-029, unchanged) and the
   genTime of every RFC 3161 token that a TSA of the trusted root
   verifies over the bundle's DSSE signature bytes. At least one is
   needed: none is `NoTimeSource`, or the first token's refusal when a
   token failed. The Fulcio leaf and its CA window must hold at **every**
   verified time, and the first time gives the leaf. Why: it is
   sigstore-go's `verifyLeafCertificate` loop, and a bundle whose times
   contradict each other is refused rather than read by the source that
   passes. `Accepted::Keyless` reports the integrated time (`Option`) and
   how many tokens verified.
2. **D2, transparency.** Exactly one log entry: Rekor v1 with its SET
   (ADR-029), or Rekor v2 `hashedrekord` 0.0.2 with its inclusion proof and
   checkpoint (D6, D7; second pull request). A keyless bundle with no
   entry is still refused (#102 STOP 1, decision 2): accepting GitHub's
   private-repository bundles would also mean dropping the SCT rule for
   that root, and those images sit in private repositories, which boneli
   cannot pull before #55 (follow-up #129). Until the second pull request
   an entry without a SET is `TlogEntries` once a time was found.
3. **D3, the token rules** (`boneli_https::TimestampToken`). Strict DER;
   the whole `TimeStampResp` with status 0 or 1 and nothing after it;
   ContentInfo `id-signedData`; eContentType `id-ct-TSTInfo` with the
   eContent present as a primitive OCTET STRING; `certificates [0]` and
   `crls [1]` skipped unread (the signer's chain comes only from the
   trusted root, so an attacker's certificate there is never parsed);
   exactly one SignerInfo, `sid` read for form only (ESSCertIDv2 binds the
   signer); digest SHA-256, parameters absent or NULL; signed attributes
   required, with contentType (naming a TSTInfo), messageDigest and
   signingCertificateV2 each exactly once, other attributes not read;
   signature `ecdsa-with-SHA256` without parameters. TSTInfo version 1, a
   SHA-256 imprint of exactly 32 bytes, genTime `YYYYMMDDHHMMSSZ` from
   1970 on, a critical extension refused (`CriticalExtension`), policy,
   serial number, accuracy, ordering, nonce and TSA name read for form
   only. `verify` then checks, cheapest first: the imprint against
   SHA-256 of the message; certHash against SHA-256 of the TSA leaf
   (hash algorithm absent or SHA-256); the leaf's EKU present, critical
   and exactly `id-kp-timeStamping` (RFC 3161 2.3) and its keyUsage, if
   present, allowing digitalSignature or nonRepudiation; webpki's
   `verify_for_usage` for `id-kp-timeStamping` at genTime with the root's
   intermediates and anchor only, and the anchor itself valid at genTime
   (inclusive at both ends, as webpki's check of the other certificates);
   messageDigest against SHA-256 of the
   TSTInfo; and the leaf's signature over the signed attributes re-tagged
   as a SET, through the algorithms ECDSA P-256 and P-384 with SHA-256
   only. Every refusal is a fixed `TimestampError`.
   The anchor check is in the shared `verify_chain` (D9), so it also
   tightens the Fulcio chains of ADR-029: before, an anchor was never
   checked against the time, because webpki's `TrustAnchor` carries no
   validity and webpki checks only the certificates on the path. Why:
   Go's `x509.Verify`, which sigstore-go and timestamp-authority use,
   refuses an expired or not yet valid root, and without the check a
   token whose genTime lies outside its anchor's lifetime but inside an
   open-ended `validFor` (the public-good TSA has no `end`) would count
   as a time (review of this pull request, run 1). It runs as webpki's
   path callback, so a path to an anchor outside its validity is not
   taken and path building goes on to the other roots. Cost: none
   measured; in the public-good root the TSA anchor is valid from
   2025-04-08 to 2035-04-06 and the two Fulcio anchors from 2021-03-07
   to 2031-02-23 and from 2021-10-07 to 2031-10-05, which holds every
   measured time, and every real known answer still verifies. The
   current Fulcio anchor's `validFor` has no `end`, so from 2031-10-06 a
   time is refused by the certificate, not by the window, as sigstore-go
   refuses it.
4. **D4, TSAs in the trusted root.** `timestampAuthorities` is read
   (absent is empty): `certChain.certificates` with the leaf first, the
   anchor last, the rest intermediates, every certificate non-empty
   (`RootCertificate` otherwise, also for an empty chain), and `validFor`
   with `start` required, as for CAs. `subject` and `uri` are not read. A
   token counts only through a TSA whose window holds its genTime, in
   milliseconds as every window here. An entry that cannot serve as a TSA
   chain does not refuse the file: one of a single certificate is read
   as strictly and then skipped (it is not counted by `tsa_count`), and
   one whose first certificate is a CA (CAs only, the leaf left to the
   token's own `certificates`) stays listed, but no token verifies
   through it, because its first certificate is not the token's signer
   (`SigningCertificate`) or is a CA (`IsCa`). Fail closed at the token,
   not at the root. Why: sigstore-go's `ParseTimestampingAuthority` loads
   both shapes (it takes the leaf from the token when the first
   certificate is a CA), and refusing the file would also refuse every
   Rekor v1 bundle that verifies under it, a regression against the root
   before this ADR, which did not read the member. No measured root has
   either shape (public-good: 1 TSA of 2 certificates; GitHub: 6 TSAs of
   3, all leaf first), so the skip costs nothing measured, and a TSA of
   that shape gives no time until a successor ADR reads the leaf from the
   token (review of this pull request, run 1).
5. **D5, failing tokens do not count.** A token that does not parse or
   that no TSA verifies is skipped, and is no refusal by itself. Why:
   sigstore-go's `VerifySignedTimestamp` skips such tokens and counts
   toward a threshold of 1. A rule that every token must verify would
   refuse a bundle cosign accepts, for example one with an extra token
   from a TSA the operator's root does not list.
6. **D6, the v2 log identity** (second pull request) comes from the
   signed-note key ID, SHA-256(origin ‖ `0x0A` ‖ `0x01` ‖ raw Ed25519
   key), compared with the root's `logId.keyId`; `baseUrl` is not read.
7. **D7, the v2 entry check** (second pull request): the body rebuilt from
   the bundle must equal `canonicalizedBody` byte for byte; the RFC 9162
   inclusion proof from SHA-256(`0x00` ‖ body) must reach the
   checkpoint's root; the checkpoint must carry exactly one signature of
   the log key over its body; and the log's window must hold every
   verified time.
8. **D8, what is trusted.** The SET rests on the Rekor v1 key, a v2
   inclusion proof on the v2 log key through the checkpoint, exactly as
   strongly, and a token on the TSA key. Not checked: witness
   cosignatures (the root lists no witness keys), consistency proofs (an
   offline verifier holds no earlier checkpoint), v1 inclusion proofs
   (ADR-029), and the TSA's nonce, policy, accuracy and revocation
   (sigstore-go checks none of them offline, and the root lists no CRL).
9. **D9, the code split.** The CMS and RFC 3161 primitive is in
   `boneli-https`, next to webpki, the strict DER reader and the OCSP and
   SCT code (ADR-029 S3): `TimestampToken`, `TimestampError`, and one
   private webpki call shared with code-signing chains (`verify_chain`).
   The Sigstore rules (which tokens, which TSA, the time rules) are in
   `boneli-sigstore`. No new crate and no new dependency edge.

### Limits, and where each number comes from

- **`MAX_TIMESTAMPS` = 32** tokens per bundle (`TooManyTimestamps`).
  Measured: 1 token per bundle in 7 of 7. 32 is sigstore-go's
  `limits.MaxAllowedTimestamps`, so no bundle cosign verifies is refused
  by count alone. The cost is at most 32 × (one parse of about 718 bytes
  and, per TSA of the root whose window holds the time, one webpki check
  and one ECDSA verification; the public-good root has 1 TSA). A lower
  cap refuses bundles cosign accepts; a higher one only lets a hostile
  bundle force more checks: without a cap the 4,194,304-byte bundle limit
  allows 4,194,304 ÷ about 985 bytes per base64 token entry ≈ 4,258
  tokens.
- **A TSA chain of at least 2 certificates to count.** webpki cannot
  verify a certificate that is itself the anchor, so a chain of one is
  skipped (D4). Measured chains: 2 certificates (public-good) and 3
  (GitHub).
- **genTime in whole seconds only.** 7 of 7 tokens have no fraction. A
  fraction would need every validity window checked at both ends of the
  second (two webpki calls per time), for no measured token. A TSA that
  writes fractions fails closed (`Timestamp(Time)`).
- **Accuracy is ignored.** In 4 of 6 real keyless tokens genTime equals
  the leaf's notBefore and the accuracy is 1 s, so honoring ±1 s at the
  leaf's lower bound would refuse them.
- **Inclusion proof: no count cap** (second pull request). A path for n
  leaves has at most ⌈log₂ n⌉ hashes: 28 for 215,560,469 (2²⁷ =
  134,217,728 < n ≤ 2²⁸ = 268,435,456) and 63 for `i64::MAX`. Measured
  13, 14 and 20. The RFC 9162 loop refuses at the first hash past the
  path.
- **Checkpoint lines: no cap** (second pull request). Measured 5 lines
  (1 log, 4 witnesses), and only the log's line is verified. The bundle's
  4 MiB bounds the parse.

## Consequences

- A keyless bundle with a SET and a token has its token checked too, and
  must hold at both times: the trillian_log_server bundle (integrated
  time = genTime = notBefore = 1795367610) passes with one verified
  token. Only bundles whose verified times contradict each other change
  their verdict.
- A bundle entry without a SET and without a token is now `NoTimeSource`
  instead of `TlogEntries` (the time is missing before the transparency
  is). With a token that verifies it stays `TlogEntries` until the second
  pull request.
- Kept evidence is re-verified under the same rules, so a warm pull
  gives the cold pull's verdict.
- `NoCaAtTime` now names a verified time, not only the integrated time.
- The anchor of a Fulcio chain must now be valid at every verified time
  too (D3). No measured bundle changes its verdict: the public-good
  Fulcio anchors are valid from 2021 to 2031, around every measured time.
- A `trusted_root.json` whose TSA entry has a single certificate or CAs
  only still reads (D4); that TSA gives no time.
- `Accepted::Keyless` changed shape (`integrated_time: Option<u64>`,
  `signed_timestamps`), a breaking change of a public enum whose only
  users are this crate's tests.
- CMS is new parsing on the security boundary (`boneli-https` is on the
  always-review list). Mitigations: strict DER, embedded certificates
  never parsed, a fixed algorithm table, 7 real known answers, a mutant
  per check, a reviewer on both pull requests.

**Known limits, each with its closure:**

- A TSA listed with CAs only, its leaf only in the token, gives no time
  (D4). Closure: a measured root with that shape, and a successor ADR
  that reads the leaf from the token's `certificates`.

- Rekor v2 entries are still refused (`MalformedTlogEntry`: they have no
  `integratedTime`). Closure: the second pull request of #102.
- Keyless bundles with no log entry (GitHub's private-repository
  instance) are refused. Closure: #129, after #55.
- RFC 3161 tokens in cosign `.sig` and `.att` annotations are not read
  (no measured layer has one), and keyed signatures read no token.
  Closure: a captured layer with one, and a successor ADR.
- TSA certificates are not checked for revocation (the root lists no
  CRL; sigstore-go does not either). Closure: a TSA whose root names a
  revocation source, and a successor ADR.
- A TSA that writes fractional genTimes fails closed. Closure: a
  captured token with a fraction, and a successor ADR that decides the
  rounding.

## Alternatives considered

- **RustCrypto `cms` 0.2.3** for the token. Rejected: at least 7 new
  crate names (`cms`, `x509-cert`, `der`, `der_derive`, `spki`,
  `const-oid`, `pem-rfc7468`), `der_derive` a proc macro, which ADR-029
  already refused for `sigstore-verify`, while `boneli-https` already has
  a strict DER reader.
- **Every token must verify.** Rejected (D5): refuses bundles cosign
  accepts.
- **Reading a v2 body field by field**, as ADR-029 does for v1. Rejected:
  rebuilding and requiring byte equality is what sigstore-go does
  (`reconstructV2EntryHash`), and the proof then commits to exactly the
  bytes we derived.
- **Parsing the token's embedded certificates** to find the signer.
  Rejected: the chain must come from the operator's root, and a parse of
  attacker-chosen certificates is attack surface for no gain;
  ESSCertIDv2 names the signer.
- **The first verified time only** (instead of every time). Rejected
  (D1): a bundle could then pick the source that passes.
- **Rust is the language of every option above;** the code goes into
  existing Rust crates.

## Accept when

The second pull request's `oci-acceptance` run passes
`signatures_on_rekor_v2` (bex-cnb-run pulled under a `Required` rule, its
Rekor v2 bundle kept and re-verified offline) on x86_64 and arm64, every
edge case of both pull requests refuses with its named refusal, and every
hand-applied mutant of the new checks is killed.

**Result of the first pull request (RFC 3161).** The seven real tokens
parse with their measured genTimes and verify (`real_tokens_verify`);
trillian_log_server passes with `integrated_time: Some(1795367610)` and
one verified token, and with the token not counted against a root
without TSAs (`real_set_and_timestamp_verify`). Every edge case of the
first part refuses with its named refusal (`src/timestamp.rs` unit tests,
`crates/boneli-sigstore/tests/timestamp.rs`, `root_tsa_and_note_logs`).
54 hand-applied mutants, 54 killed: 35 in `boneli-https` (the status,
content types, signer count, digest, signature and imprint algorithms,
unknown algorithm parameters, the signed-attribute rules, the
ESSCertIDv2 algorithm, genTime's tag, the TSTInfo version and critical
extensions, the explicit FALSE, the skipped `certificates`, each of the
six checks of `verify`, the time webpki is asked at, the re-tag of the
signed attributes, the criticality the strict leaf reader reports, and
after review the anchor's validity: the check not called, either bound
dropped, either bound made exclusive)
and 19 in `boneli-sigstore` (the token cap at both ends, unknown members,
empty tokens, tokens not passed, the imprint over the PAE, the TSA window,
the TSA check itself, which failure is kept, `NoTsaAtTime` over a token
error, `NoTimeSource` over a token error, the transparency check, the
chain at every time, the leaf from the first time, the reported
`integrated_time` and `signed_timestamps`, and the one-certificate
rule of D4 as changed after review: the entry refusing the file again,
its window read only after the skip, and every TSA dropped).
The anchor and skip rules are tested by `anchor_validity_at_gen_time`,
`codesign::tests::anchor_validity_at_time`,
`unusable_tsa_entry_anchors_no_token` and `root_tsa_and_note_logs`. The
second part adds its own.
