# ADR-040: Keyless bundles without a transparency log

- Status: accepted
- Date: 2026-11-26

## Context

ADR-029 and ADR-038 verify a keyless signature only through exactly one
transparency log entry, a Rekor v1 entry with its inclusion promise or a
Rekor v2 entry with its inclusion proof, and an embedded SCT from a CT log
of the operator's `trusted_root.json`. ADR-038 lists the gap as a known
limit: "Keyless bundles with no log entry (GitHub's private-repository
instance) are refused. Closure: #129". GitHub signs the artifact
attestations of private repositories with its own Sigstore instance,
whose root lists no log at all, so a `Required` rule can never be met
for an image built in a private GitHub repository.

Measured on 2026-11-25 (planning) and re-checked on 2026-11-26 with
`gh`, `jq` and OpenSSL 3.5:

- **GitHub's root.** `gh attestation trusted-root` prints two roots, one
  per line; the second, the one whose first certificate authority has
  `uri` `fulcio.githubapp.com`, is 28,886 bytes with SHA-256
  `26b3382d…245ce485`. It has no `tlogs` and no `ctlogs` member, 6
  `certificateAuthorities` and 6 `timestampAuthorities`, each a chain of
  3 certificates. Every CA chain is `Fulcio Intermediate l2` (EKU
  codeSigning, `pathlen:0`, its own key per window) → `Fulcio
  Intermediate l1` (no EKU, `pathlen:1`, 2023-09-11 to 2028-09-09, the
  same certificate in all 6) → `Internal Services Root` (2023-08-07 to
  2033-08-04, the same in all 12 chains). Every TSA chain is a leaf (EKU
  timeStamping, critical) → `TSA intermediate` (EKU timeStamping, the
  same in all 6) → that root. Every certificate is P-384 and signed with
  `ecdsa-with-SHA384` (planning). The windows start 2023-10-27,
  2024-05-13, 2024-10-07, 2025-05-27, 2025-11-13 and 2026-06-12; the
  last has no end. A new window comes every 199, 147, 232, 170 and 211
  days and overlaps the one before by 12, 18, 23, 26 and 31 days; on
  2026-11-25 the current one was 166 days old.
- **The reader takes it already.** `TrustedRoot::from_json` reads it with
  0 Rekor v1 logs, 0 Rekor v2 logs, 6 authorities, 0 CT logs and 6 TSAs.
- **Six GitHub-instance bundles** (planning), 2024-04-22 to 2026-05-16,
  in CA windows 0, 2 and 4: each a v0.3 DSSE bundle over SLSA v1
  provenance with 0 `tlogEntries` and exactly 1 RFC 3161 token of 723 to
  726 bytes. Each token has a whole-second genTime, a SHA-256 imprint of
  the DSSE signature, a SignerInfo digest **SHA-384** and signature
  **`ecdsa-with-SHA384`**, and an ESSCertIDv2 without a hash algorithm
  (SHA-256) with issuerSerial. Each leaf is P-256, signed
  `ecdsa-with-SHA384` by l2, has **no SCT list**, and carries the issuer
  extensions 1.1 and 1.8 `https://token.actions.githubusercontent.com`
  and the claims 1.12, 1.15 and 1.20. All 6 verify with OpenSSL against
  the CA and TSA of their window (`openssl ts -verify`, `openssl verify
  -purpose codesign`, and the DSSE signature with `openssl dgst
  -sha256`).
- **Two of them are redistributable** and committed as known answers:
  K1, `pkg/cmd/attestation/test/data/github_provenance_demo-0.0.12-py3-none-any-bundle.jsonl`
  of `cli/cli` (MIT) at `574e1310720e`, from the private
  `actions/attest-demo` (genTime 1713807206, window 0); K2, the bundle of
  GitHub's prober of its own instance in the MIT
  `actions/attest-build-provenance` (genTime 1763712806, windows 3 and 4,
  only 4 verifies). In both, genTime equals the leaf's notBefore. The
  other four come from public repositories without a license and are
  measurements only.
- **Three blockers on main**, each confirmed on K1 and K2: `verify` gives
  `TlogEntries` (no entry); their tokens give `TimestampError::Algorithm`
  (ADR-038 D3 takes SHA-256 with `ecdsa-with-SHA256` only); their leaves
  through l2 and l1 give `CertError::NotCodeSigning`, because webpki's
  `KeyUsage::required` demands the EKU of every intermediate and l1 has
  none (ADR-029 item 7 and its known limit). With l1 as the anchor the
  chain verifies, so l1's missing EKU is the chain's only defect.
- **How GitHub verifies it** (planning, `gh` source): `gh attestation
  verify` asks its private instance for `WithSignedTimestamps(1)` only;
  public-good gets SCT, transparency log and observer time. Its
  custom-root verifier turns the transparency log on only when the root
  lists Rekor logs. Go's `x509.Verify`, which sigstore-go and
  timestamp-authority use, treats an intermediate without an EKU as
  unrestricted and still requires the leaf's purpose.
- **Who signs there** (planning, `actions/attest` `src/main.ts`): GitHub's
  instance when the repository is not public, or when the undocumented
  `private-signing` input is set.
- **No own capture.** The organization is on the Team plan, and GitHub's
  documentation (not run) says attestations in private repositories need
  Enterprise Cloud. The one public GHCR image found with a GitHub-instance
  bundle lists it under its `sha256-<hex>` tag, but the referrer manifest
  answers 404. No image-subject capture can be fetched, so there is no
  live acceptance test (#129 STOP 1, decision 2).

## Decision

The decisions of STOP 1, all as recommended: (1) accept no-log bundles
only under an explicit per-trust opt-in, with the two `boneli-https`
changes below; (2) this ADR rests on the committed offline known answers
K1 and K2, with no live test and no new `boneli-oci` test; (3) the TUF
refresh of GitHub's root is follow-up #137.

1. **D1, the opt-in and its configuration rules.**
   `Trust::with_no_log()` in `boneli-sigstore`, refused when the trust is
   built, never at pull time:
   - no keyless part: `NoLogWithoutKeyless`;
   - the root lists any log: `NoLogRootHasLogs`. "Lists" counts every
     `tlogs` entry, kept as Rekor v1, kept as Rekor v2, or left out (a
     non-Ed25519 log whose `keyId` is not its key's hash), and every
     `ctlogs` entry (`TrustedRoot::lists_logs`, the number of log IDs
     before the duplicate check). Why every entry, not only those the
     reader keeps: the opt-in must never weaken a logged instance, so an
     operator who points the trust at the public-good root, or at a
     GitHub root to which GitHub one day adds a log, gets a refusal and
     not a silent loss of transparency;
   - the root has no usable TSA (`tsa_count() == 0`, skipped one-
     certificate entries not counted): `NoLogRootWithoutTsa`, because a
     token is the only time source left;
   - an identity whose SAN rule is a `UriPrefix` that does not name an
     owner (`<scheme>://<host>/<owner>/` at least, no empty, `.` or `..`
     segment, the rule of ADR-036 item 4): `NoLogIdentityWithoutOwner`.
     Exact `Email` and `Uri` rules pass. Every identity must pass, not
     any. Why: the root is shared by every private repository on GitHub,
     so the identity rule is all that separates the operator's workflows
     from everyone else's.

   Keys stay allowed and keyed signatures are unaffected. The opt-in
   composes with `with_claims` and `with_certificate_claims` in either
   order; `Debug` names `no_log: true` only when set, so a trust without
   it reads byte for byte as before.
2. **D2, verification under the opt-in** (`keyless_without_log`):
   - a keyless cosign `.sig` or `.att` layer is `NoTimeSource` before its
     entry is read: its tokens are not read (ADR-038 limit), and the root
     has no log whose SET could time it;
   - a bundle must carry no `tlogEntries` (`TlogEntries` otherwise, also
     for one Rekor v1 entry with its SET or one v2 entry), and no SET or
     v1/v2 check runs;
   - the times are the verified tokens alone (ADR-038 D1 and D5: a token
     that fails does not count); none is `NoTimeSource`, or the first
     token's refusal;
   - the chain is checked at every verified time, as under ADR-038;
   - the SCT list is not read (the root has no CT log to check one
     against);
   - signature, exactly one SAN, issuer and identity are checked as now,
     and certificate claims (ADR-034) and provenance claims (ADR-031)
     after them, as now;
   - the result is `Accepted::KeylessWithoutLog { signed_timestamps,
     identity }`, so a caller can tell that no transparency backs it.

   Without the opt-in nothing changes: a bundle with no entry is
   `TlogEntries` under every root.
3. **D3, what a no-log bundle proves (AC 1).**
   - It proves that a CA of the operator's root, here GitHub's Fulcio,
     issued the 10-minute leaf to the workflow identity in the SAN and the
     1.x extensions; that a TSA of the root, here GitHub's, saw the
     signature at a time inside the leaf's and the CA's validity, which
     keeps a leaked ephemeral key from signing later; and that the
     leaf's key signed the statement over this digest.
   - It does not prove that anyone outside GitHub can see the
     certificate or the signature: there is no CT log and no Rekor entry.
     A mis-issued or misused GitHub CA or TSA key (one operator, one
     root) signs for any workflow identity, and nobody can detect it then
     or later. It proves nothing independent about the time, since the
     TSA and the CA belong to the same operator, and nothing about
     revocation: there is none.
   - Why it is acceptable: GitHub already hosts the source of these
     images and runs their build, so it can already make any image it
     likes pass under that repository's identity. The logs would add
     detection after the fact, not prevention.
4. **D4, intermediates without an EKU (amends ADR-029 item 7).**
   `verify_chain` in `boneli-https` passes webpki
   `KeyUsage::required_if_present(eku)` instead of `required(eku)`, and
   before webpki requires that the leaf (strict reader) carries an EKU
   extension, else `NotCodeSigning`. The rule then reads: the leaf must
   have an EKU, and webpki checks that it lists the purpose; an
   intermediate with an EKU must list the purpose; an intermediate
   without one is unrestricted. This is Go's `x509.Verify` rule.
   Intermediates still come only from the operator's root, and
   `anyExtendedKeyUsage` never stands in for the purpose (webpki matches
   the OID exactly; stricter than Go, and no measured CA uses it). It
   applies to Fulcio and TSA chains alike, since both go through the one
   shared call (ADR-038 D9); a TSA leaf still needs its critical, exact
   timeStamping EKU (ADR-038 D3). Why globally and not per root: the
   rule is a property of X.509 path validation, not of an instance, and a
   per-root switch would be a second code path with nothing to gain;
   every public-good known answer keeps its verdict.
5. **D5, the SHA-384 token triple (amends ADR-038 D3).** A token is
   accepted with exactly one of two (digest, signature, key) triples:
   SHA-256, `ecdsa-with-SHA256`, a P-256 or P-384 leaf (as before), or
   SHA-384, `ecdsa-with-SHA384`, a P-384 leaf only. Any other pairing is
   `Algorithm`; messageDigest must be 32 or 48 bytes to match the pair
   (`SignedAttributes`), and is compared with the pair's digest of the
   TSTInfo (`MessageDigest`). SHA-384 is ring's `digest::SHA384`; ring is
   a direct dependency of `boneli-https` already (OCSP's SHA-1), so there
   is no new edge. The imprint and the ESSCertIDv2 hash stay SHA-256: 6
   of 6 measured GitHub tokens and 7 of 7 public-good tokens use it. Why
   P-384 only under SHA-384: every measured TSA leaf that signs with it
   is P-384, and a P-256 key under SHA-384 truncates the digest to 256
   bits, a pairing nobody has been seen to use. Why not every webpki
   ECDSA algorithm: a fixed table of two rows is what the reviewer and
   the mutants can pin.
6. **D6, the code split.** No crate and no dependency edge: D1 and D2 in
   `boneli-sigstore` (`verify.rs`, `root.rs`, `error.rs`;
   `names_owner` moved from `provenance.rs` to `identity.rs` so both
   rules share it), D4 and D5 in `boneli-https` (`codesign.rs`,
   `timestamp.rs`). `boneli-oci` does not change: the opt-in rides in the
   `Trust` its `PolicyRule` already holds, and a warm pull runs `verify`
   again under the current trust (`warm_pull_reverifies_under_current_policy`).
   The opt-in's key in the runner's policy file is #32 and #33. The
   language is not in question: the change goes into existing Rust
   crates.

### Limits, and where each number comes from

- **No new number.** The opt-in reuses `MAX_TIMESTAMPS` (32, ADR-038):
  each measured no-log bundle carries 1 token, so the cap refuses none of
  them, and under the opt-in a token is the only time source, so a
  bundle with 33 is refused as before (`TooManyTimestamps`).
- **At least 1 verified token.** The opt-in leaves no other time source;
  1 is what GitHub's own verifier asks for (`WithSignedTimestamps(1)`)
  and what all 6 measured bundles carry. Requiring 2 would refuse all of
  them.
- **The owner rule's minimum, `<scheme>://<host>/<owner>/`,** is the
  smallest unit a forge gives one party control of (ADR-036 item 4);
  anything shorter covers every private repository on the host.
- **The refresh interval of the root by hand.** GitHub adds a CA and a
  TSA every 147 to 232 days (5 measured gaps) with 12 to 31 days of
  overlap, so a file refreshed at least every 147 days, the shortest gap,
  never misses a whole window; a stale file fails closed (below).

## Consequences

- K1 and K2 verify under GitHub's root with the opt-in and their exact
  SAN, and K2 also under `UriPrefix("https://github.com/actions/")`, as
  `KeylessWithoutLog { signed_timestamps: 1, identity: 0 }`. Without the
  opt-in they stay `TlogEntries` (AC 2).
- An intermediate without an EKU no longer refuses a chain, for Fulcio
  and TSA chains alike (D4). The synthetic `CA_NO_EKU` case of
  `codesign::tests::intermediates_only_those_passed` flips to `Ok`, the
  one test that pinned the old rule. No public-good known answer changes
  its verdict: the public-good Fulcio intermediate carries the EKU.
- A leaf with no EKU extension is still refused, now by our own check
  before webpki (`leaf_needs_its_eku`), not by webpki.
- GitHub's SHA-384 tokens verify (D5); public-good tokens are unchanged.
- **A stale root fails closed.** A bundle from a CA and TSA window newer
  than the file gets `Timestamp(SigningCertificate)`: the last window of
  a stale file is open-ended, so it holds the new time, but its TSA leaf
  did not sign the token (`no_log_stale_root`). The operator guide says
  so.
- **Breaking public enums:** `Accepted::KeylessWithoutLog` and four
  `ConfigError` variants. Only tests read `Accepted`'s fields;
  `boneli-oci` matches none of them.
- `TrustedRoot` counts the logs it lists (`listed_logs`), a private
  field; its `Debug` does not change.
- **Weak spots of the opt-in**, each by design: GitHub alone vouches
  (D3); the root is shared by every private repository on GitHub, so a
  renamed or re-registered repository is visible in no log, which is why
  the operator guide recommends certificate claims with the repository
  ID (1.15, ADR-034); and a stale root fails closed (above).

**Known limits, each with its closure:**

- GitHub's root is captured by hand (`gh attestation trusted-root`); the
  TUF refresh of ADR-033 covers Sigstore's public-good repository only.
  Closure: #137, the TUF refresh of GitHub's root from
  `tuf-repo.github.com` (gh embeds its root v3 with 9 ECDSA P-256 keys
  and consistent snapshots, the shape `boneli-tuf` reads).
- No live acceptance test of a GitHub-instance image: no image-subject
  capture can be fetched on this plan (Context). Closure: an image with a
  fetchable GitHub-instance referrer (an Enterprise Cloud repository, or
  a public repository signing with `private-signing`), and a live test
  in `oci-acceptance` that pulls it under the opt-in.
- RFC 3161 tokens in cosign `.sig` and `.att` layers are not read
  (ADR-038), so the opt-in covers bundles only; such a layer is
  `NoTimeSource` under it. Closure: ADR-038's, a captured layer with a
  token.
- GitHub release attestations (leaves issued by l1 under `Attester`,
  with no OIDC issuer extension) are refused with `NoIssuer`. Closure: a
  release-attestation use case and a successor ADR that decides their
  identity.
- `anyExtendedKeyUsage` on an intermediate stays refused, stricter than
  Go. Closure: a measured CA that uses it.
- TSA certificates are not checked for revocation (ADR-038), and GitHub's
  root names no revocation source. Closure: ADR-038's.

## Alternatives considered

- **Infer the mode from the root's contents**, as `gh`'s custom-root
  verifier does (transparency only when the root lists Rekor logs).
  Rejected: an operator who points a trust at the wrong file would lose
  transparency without noticing, and the issue asks for an explicit
  opt-in.
- **An opt-in that also accepts a logged root** (a log entry optional
  when present). Rejected: a public-good bundle stripped of its entry
  would then pass (`stripped_public_good_bundle_refused`), a downgrade
  for every rule that sets the opt-in by mistake.
- **A per-root EKU switch** instead of D4. Rejected (D4): the same
  validation rule twice, for no measured chain that the global rule gets
  wrong.
- **Pin GitHub's l1 as an extra anchor** to skip it on the path.
  Rejected: the operator's root names `Internal Services Root` as the
  anchor, and reshaping the operator's chain in code is the kind of
  silent trust change the strict reader exists to prevent.
- **Accept every webpki ECDSA algorithm** for tokens. Rejected (D5): a
  fixed table is what the tests and mutants pin, and no measured token
  needs more.
- **Rust is the language of every option above;** the change goes into
  existing Rust crates.

## Accept when

Every edge case of the plan refuses with its named refusal, K1 and K2
pass only under the opt-in, every hand-applied mutant is killed, every
public-good known answer keeps its verdict, and the `oci-acceptance` run
dispatched on the pull request's branch (the EKU rule touches every
keyless chain the live tests verify) is green on x86_64 and arm64.

**Result.** K1 and K2 verify only under the opt-in
(`real_github_bundles_verify_under_no_log`,
`real_github_bundles_refused_without_opt_in`); their chains
(`github_fulcio_chains_verify`) and tokens (`real_github_tokens_verify`)
verify in `boneli-https`. Every edge case refuses with its named refusal
(`crates/boneli-sigstore/tests/no_log.rs`, 18 tests; `leaf_needs_its_eku`,
`sha384_triple_rules` and `p256_leaf_under_sha384_refused` in
`boneli-https`). The public-good known answers keep their verdicts
(`tests/verify.rs`, `rekor.rs`, `rekor_v2.rs` and `timestamp.rs` of
`boneli-sigstore` and the 7 tokens of `real_tokens_verify` unchanged).
29 hand-applied mutants, 29 killed, each by an assertion of the named
test:

- `boneli-https` (9): `required_if_present` back to `required`
  (`github_fulcio_chains_verify`); the leaf-EKU presence check dropped
  (`leaf_needs_its_eku`); SHA-384 accepted with `ecdsa-with-SHA256` and
  the messageDigest length not tied to the pair (`sha384_triple_rules`);
  the P-384-only key filter dropped (`p256_leaf_under_sha384_refused`:
  a real P-256 `ecdsa-with-SHA384` token OpenSSL made, since ring signs
  P-256 with SHA-256 only, so the synthetic tokens could not tell the
  filter's absence apart); messageDigest compared as SHA-256, the
  SHA-256 filter and the SHA-256 signature algorithm used for SHA-384
  tokens (`real_github_tokens_verify`); the SHA-256 triple dropped
  (`real_tokens_verify`).
- `boneli-sigstore` (20): the root-has-logs check dropped, and
  `listed_logs` counting without CT, without left-out or without v2
  logs (4, `no_log_config_rules`, one variant each); the TSA check
  dropped, or counting a skipped one-certificate entry (2); the identity
  check dropped, or `all` turned into `any` (2); the keyless-part check
  dropped; zero entries allowed without the opt-in
  (`stripped_public_good_bundle_refused`); entries ignored under the
  opt-in (`no_log_refuses_log_entries`); the SCT checked under the opt-in
  and `Keyless` returned instead of `KeylessWithoutLog`
  (`real_github_bundles_verify_under_no_log`); the SCT skipped without
  it (`tests/verify.rs`, `sct_cases`); no time read as the leaf's
  notBefore (`no_log_needs_a_timestamp`); the cosign-layer refusal
  dropped (`no_log_refuses_cosign_layers`); only the first time checked,
  and the reported token count fixed at 1 (`no_log_token_rules`); and
  `no_log: true` left out of `Debug` and `no_log()` always false
  (`no_log_debug`).

**Accepted.** The `oci-acceptance` run dispatched on the pull request's
branch, https://github.com/Replikanti/boneli/actions/runs/45723922807,
passed on x86_64 and arm64: the 7 signature and pull tests of
`network::` (`signatures_on_docker_hub`, `signatures_elsewhere`,
`provenance_claims_on_ghcr`, `certificate_claims_on_ghcr`,
`provenance_v02_on_ghcr`, `signatures_on_rekor_v2`,
`node_and_postgres_run_in_sandbox`), the proxy pull and the TUF refresh,
so every live keyless chain still verifies under the EKU rule of D4.
