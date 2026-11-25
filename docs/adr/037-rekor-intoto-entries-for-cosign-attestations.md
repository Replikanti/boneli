# ADR-037: Rekor `intoto` entries for cosign attestations

- Status: accepted
- Date: 2026-11-25

## Context

ADR-036 admits SLSA v0.2 provenance in cosign `.att` layers, but item 2
of its decision requires the keyless layer's log entry to be exactly one
Rekor `dsse` 0.0.1 entry. Its first known limit records what that
refuses: `.att` layers that slsa-github-generator before v2.0.0 logged
as Rekor `intoto` 0.0.1, refused with `EntryKind`. Issue #118 asks for an
`intoto` body check bound through `content.hash`.

Measured on 2026-11-24 through the anonymous registry API and the
captured Rekor bodies:

- **2 of ADR-036's 13 `.att` releases are logged as `intoto` 0.0.1,**
  both from generator v1.9.0: `quay.io/argoproj/argocd` v2.10.0 (log
  index 69,491,963, integrated time 1707230840) and
  `ghcr.io/kyverno/kyverno` v1.11.0 (log index 48,852,930, integrated
  time 1699611421). Both entries are in the public-good Rekor log
  `c0d23d6a…9591801d`.
- **Body shape, 2 of 2:** exactly `kind`, `apiVersion`, `spec.content.hash`,
  `spec.content.payloadHash` and `spec.publicKey`, 3,615 and 3,583 bytes.
  There is no signature member and no `content.envelope`.
- **What the members hold, 2 of 2:** `content.hash` is the SHA-256 of the
  envelope bytes, which is the layer digest; `payloadHash` is the SHA-256
  of the base64-decoded payload, not of its base64 text; `publicKey` is
  the base64 of the PEM in the layer's certificate annotation, byte for
  byte (`real_intoto_entries_as_measured` asserts each of these).
- **kyverno v1.11.0 has no other evidence:** its `.sig`, the referrers
  API and the referrers tag answer 404, so `.att` is the only thing a
  `Required` rule can check for it.
- **The leaves:** both carry Fulcio's Source Repository URI (1.12), Ref
  (1.14), Build Config URI (1.18) and Build Trigger (1.20, `push`), so
  ADR-034's certificate claims apply to them. In both the leaf's
  notBefore equals the integrated time to the second (argocd
  2024-02-06T14:47:20Z, kyverno 2023-11-10T10:17:01Z, notAfter = notBefore
  + 600 s), so both pass only on webpki's inclusive lower bound.
- **Rekor's `intoto` v0.0.1 type** (`pkg/types/intoto/v0.0.1/entry.go`,
  main) computes `payloadHash` from the decoded payload and `hash` over
  the envelope as submitted; its comment says "PayloadHash is not present
  for old entries". The change "compute payload and envelope hashes upon
  validating intoto proposed entries" was merged on 2022-08-12 and first
  released in v0.11.0 on 2022-08-19. The generator's container workflow
  shipped in v1.2.0 on 2022-07-19.
- **cosign's legacy `VerifyBundle`** (`pkg/cosign/verify.go`, main)
  compares `content.hash` with the SHA-256 of the layer bytes and
  `publicKey` with the certificate. It skips the signature comparison for
  attestations and never reads `payloadHash`.
- **sigstore-go** (`pkg/tlog/entry.go`) has no `intoto` 0.0.1 case for
  Rekor v1; it handles `dsse` 0.0.1, `hashedrekord` 0.0.1 and `intoto`
  0.0.2.
- **flux-cli's two `dsse` `.att` entries** (ADR-036's known answers) also
  carry an `envelopeHash` equal to the layer digest. Recorded, not used
  (item 1).

## Decision

1. **Scope: `.att` only.** A cosign `.att` layer's keyless entry may be
   Rekor `dsse` 0.0.1, checked exactly as ADR-036 checks it, or Rekor
   `intoto` 0.0.1, checked as below. Bundles and `.sig` layers stay as in
   ADR-029 S2 and refuse an `intoto` entry with `EntryKind`: a bundle
   does not carry the bytes Rekor hashed (cosign writes the envelope
   again), so no `content.hash` could be checked, and sigstore-go refuses
   that kind for bundles too; a `.sig` layer is a `hashedrekord`.
   `envelopeHash` on `dsse` `.att` entries stays unchecked, as ADR-036
   item 2 decided.
2. **The binding chain.** The SET covers the body. The body's
   `content.hash` must be the SHA-256 of the exact envelope bytes the
   reader received (`Evidence::from_cosign_attestation` hashes its input
   before any parse, never a re-serialization; `boneli-oci` passes the
   layer blob, digest-checked on fetch and re-hashed on every read, so it
   is the layer digest). Those bytes fix the signature and the payload.
   `publicKey` must decode to the leaf's DER, which the chain then
   verifies at the integrated time and matches against the identity. So
   the body needs no signature member: every byte the verdict reads is
   bound by the SET through one of the two hashes or the key. The check
   runs before the chain, the SCT and the signature, as for every kind.
3. **`payloadHash` is checked on top of cosign's two checks, and is
   required (STOP 1, D2).** It must be the SHA-256 of the decoded payload.
   Rekor indexes attestations by `payloadHash`, so the check ties the
   statement log monitors see to the one we read. Our parsers are
   stricter than Go's (duplicate keys refused, canonical base64 only), so
   where they could diverge the result is a refusal, never a pass. A
   missing `payloadHash` refuses; 2 of 2 measured entries carry it.
4. **No new refusal and no new text.** A body that does not say what the
   layer says (any of the three members missing, of the wrong type or
   different, a `spec` or `content` that is not an object, a body that is
   not JSON) is `BodyMismatch`; another kind or version on an `.att` is
   `EntryKind`. Hash values compare as lower-case hex strings with the
   algorithm exactly `sha256`, as for `hashedrekord` and `dsse`.
5. **No new limit, crate or dependency edge.** The body is at most 3,615
   bytes measured, against the 4,194,304-byte parse cap
   (`MAX_BUNDLE_BYTES`), 1,160 times that; its nesting is 4 against
   `MAX_JSON_DEPTH` 16, and 12 values against `MAX_JSON_VALUES` 65,536.
   The added work is one SHA-256 over an envelope of at most 4,194,304
   bytes per candidate, and at most 16 candidates per `.att`
   (`MAX_SIGNATURES`), so at most 67,108,864 bytes hashed per subject,
   bytes the carrier has already fetched and hashed once. Requests and
   the worst case per subject are unchanged: ADR-036's 17 `.att`
   requests and 578 s. A lower parse cap would not change these bodies;
   a separate cap for `intoto` bodies would add a number with no
   measured reason.

### Partial supersession

For `.att` layers, ADR-036 item 2's "exactly one Rekor `dsse` 0.0.1
entry" becomes "exactly one Rekor `dsse` 0.0.1 or `intoto` 0.0.1 entry".
The rest of ADR-036 stands.

## Consequences

- argocd v2.10.0 and kyverno v1.11.0 pass a claims rule that names
  their builder, repository, ref and material, and are refused, naming
  `.att` and the claim, under a rule they do not meet. kyverno v1.11.0,
  whose `.att` is its only evidence, can now pass a `Required` rule at
  all.
- Rules without claims, bundles, `.sig` layers and `dsse` `.att`
  layers give the same verdicts and send the same requests as before.
- `Form::Attestation` carries the envelope digest next to the envelope,
  so an attestation without its digest cannot be built, and a bundle has
  no digest field to forget.

**Known limits, each with its closure:**

- Rekor `intoto` 0.0.2 entries are refused with `EntryKind`. No
  candidate `.att` layer with one was measured; external-secrets' layers
  carry no predicate-type annotation, so `boneli-oci` never fetches
  them, and their entry kind is unknown. Closure: a captured producer
  that logs `.att` as `intoto` 0.0.2, and a successor ADR with it as a
  known answer.
- An `intoto` 0.0.1 entry without `payloadHash` refuses with
  `BodyMismatch` (item 3), where cosign accepts it. Such an entry could
  exist for an `.att` logged between generator v1.2.0 (2022-07-19) and
  the production rollout of Rekor v0.11.0 (released 2022-08-19, rollout
  date unknown); this is inferred from release dates, no such entry was
  measured. Closure: a captured `.att` that lacks it, and a successor ADR
  that decides whether `content.hash` and `publicKey` alone suffice.

## Alternatives considered

- **An `Option<[u8; 32]>` envelope digest on the shared `Dsse` struct.**
  Rejected: it makes a bundle with an envelope digest representable,
  which is the state item 1 forbids; the tuple variant
  `Form::Attestation(Dsse, [u8; 32])` makes it impossible to build.
- **`payloadHash` checked only when present (STOP 1, D2 (b)).**
  Rejected: fail-closed is the house pattern (ADR-031 and ADR-036 admit
  only measured forms), and both measured entries carry it. It would be
  as strong a binding, because `content.hash` fixes the bytes, so the
  only gain would be the unmeasured pre-v0.11.0 entries, which stay a
  known limit with a closure.
- **cosign's two checks only** (`content.hash` and `publicKey`).
  Rejected: it leaves the statement Rekor indexed unchecked against the
  one we read, for one more hash over bytes already in memory.
- **`intoto` entries for bundles too.** Rejected: a bundle carries no
  copy of the envelope bytes Rekor hashed, so `content.hash` could not be
  checked, and sigstore-go refuses the kind.
- **Checking `envelopeHash` on `dsse` `.att` entries** (equal to the
  layer digest on both flux captures). Rejected here: ADR-036 item 2
  decided it adds no binding the PAE signature, the payload hash and
  the verifier lack, and nothing measured since changes that.
- **A live `oci-acceptance` test with kyverno v1.11.0 (STOP 1, D1 (b)).**
  Rejected: `boneli-oci` does not change, the verdict depends only on the
  captured bytes, which the offline fake-registry test replays, and
  `provenance_v02_on_ghcr` already runs the same carrier live every week;
  a kyverno amd64 pull would add 35,584,021 bytes per architecture per
  run. A GHCR change that affects only kyverno's `.att` would go
  unnoticed, but it would not change a verdict on the captured files.

## Accept when

Both known answers pass (argocd v2.10.0 and kyverno v1.11.0 verify
against the committed public-good root under the generator's exact
v1.9.0 SAN and under its tag prefix, with exact builder, repository, ref
and material claims), every edge case of the body check refuses with its
named refusal, the kyverno files pass and fail through the offline fake
registry in `boneli-oci`, and every hand-applied mutant of the new checks
is killed.

**Result (2026-11-25).** Both known answers pass: argocd v2.10.0
(index `sha256:13cdc24e…87440baa`, log index 69,491,963) and kyverno
v1.11.0 (`sha256:4c30afa8…8ab39e3a`, 48,852,930) verify against the
committed public-good root under the exact v1.9.0 SAN and under its tag
prefix and meet exact builder, repository, ref and material claims;
argocd's leaf also meets ADR-034 certificate claims (`push`, its
`release.yaml`). Every edge case of the body check refuses with its named
refusal (`tests/intoto.rs`), and kyverno's files pass and fail through
the offline fake registry (`real_intoto_attestation_through_att_tag`),
the warm pull sending no signature request. The hand-applied mutation
pass over `rekor.rs`, `attestation.rs` and `verify.rs` kills 15 of 15
mutants: the 14 of the plan, the last split in two (a missing `content`
and a missing `publicKey` each treated as a match). None survived the
first pass.
