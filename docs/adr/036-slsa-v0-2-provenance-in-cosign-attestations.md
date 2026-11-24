# ADR-036: SLSA v0.2 provenance in cosign attestations

- Status: proposed
- Date: 2026-11-24

## Context

ADR-031 checks provenance claims only on SLSA v1 statements in Sigstore
bundles, and a rule with claims skips the cosign `.sig` carrier.
`slsa-github-generator`, the isolated builder (SLSA Build L3) where
provenance claims mean the most, publishes SLSA v0.2 provenance as a
cosign `.att` attestation, so a rule with claims refuses those images.
ADR-031's 20-repository GHCR sample found 1 such repository
(`fluxcd/flux-cli`). Issue #114 asks to discover `.att`, verify its DSSE
envelope under the trust of ADR-029, and map the v0.2 predicate onto
ADR-031's claims.

Measured on 2026-11-24 through the anonymous registry API:

- **A targeted sample of known users of the generator's container
  workflow** (not a prevalence figure): 13 releases in 6 repositories,
  all with SLSA v0.2 in `.att` on the **index** digest:
  `ghcr.io/fluxcd/flux-cli` v2.3.0, v2.4.0, v2.7.0, v2.7.3;
  `ghcr.io/fluxcd/{source,helm,kustomize}-controller` v1.4.1, v1.1.0,
  v1.7.0; `quay.io/argoproj/argocd` v2.10.0, v2.13.0, v3.2.0;
  `ghcr.io/kyverno/kyverno` v1.11.0, v1.13.0, v1.16.0. The `.att` tag of
  flux-cli v2.4.0's amd64 manifest answers 404. Kyverno's index has no
  `.sig`, so `.att` is its only signature. flux-cli v2.0.0,
  `stefanprodan/podinfo` 6.7.0 and `kubewarden/policy-server` v1.17.0
  have no `.att`.
- **Carrier shape, 13 of 13:** an OCI manifest with exactly one layer of
  media type `application/vnd.dsse.envelope.v1+json` and the annotations
  `predicateType` (`https://slsa.dev/provenance/v0.2`),
  `dev.cosignproject.cosign/signature` (empty: the signature is in the
  envelope), `dev.sigstore.cosign/certificate` (Fulcio leaf, PEM),
  `dev.sigstore.cosign/chain` and `dev.sigstore.cosign/bundle` (the legacy
  Rekor entry, the `.sig` layer's form). The envelope holds exactly
  `payload`, `payloadType` (`application/vnd.in-toto+json`) and
  `signatures` (one entry, `keyid` empty), 12,624 to 13,644 bytes.
- **Rekor kinds:** `dsse` 0.0.1 in 11 of 13 (generator v2.0.0 ×6, v2.1.0
  ×5); `intoto` 0.0.1 in 2 (generator v1.9.0: kyverno v1.11.0 from
  2023-11, argocd v2.10.0 from 2024-02). The generator moved to the DSSE
  type in v2.0.0. An `intoto` 0.0.1 body holds `content.hash` (the
  SHA-256 of the exact envelope bytes, equal to the layer digest in both),
  `content.payloadHash` and `publicKey`, and no signature.
- **They verify under ADR-029.** All 11 `dsse` ones verify against the
  committed public-good root under the generator's exact SAN, flux-cli
  v2.4.0 among them (index `sha256:a9cb966c…3471fd1f`, integrated time
  1727714974, log index 135502222) and v2.7.3 (`sha256:334f7363…d418f14e`,
  1761669969, 649299369). The 2 `intoto` ones are refused with
  `EntryKind`. Under another SAN (flux's own `release.yaml`) flux-cli
  v2.4.0's `.att` gives `IdentityMismatch`.
- **Statement:** `_type` `https://in-toto.io/Statement/v0.1` in 13 of 13
  (ADR-029's reader admitted only v1), one subject `{name, digest:
  {sha256: <index hex>}}`. The predicate holds exactly `builder`,
  `buildType`, `invocation`, `materials` and `metadata`; `invocation`
  exactly `configSource`, `parameters` and `environment`; `configSource`
  exactly `uri`, `digest` and `entryPoint`. `builder.id` is the
  generator's workflow `…/generator_container_slsa3.yml@refs/tags/v2.x.0`
  (v1.9.0 for the two older ones) and equals the certificate's SAN in 13
  of 13. `configSource.uri` is `git+https://github.com/<owner>/<repo>@refs/tags/<version>`
  with `digest.sha1`, and `materials` is exactly one entry with the same
  URI and `sha1`. Statements are 9,323 to 10,087 bytes, nesting 7, 227 to
  250 JSON values.
- **`invocation.parameters`:** `{}` in 8 (generator v1.9.0 and v2.0.0),
  `{"vars": {}}` in 2, and a non-empty `vars` object of strings in 3
  (flux-cli v2.7.0 and v2.7.3, `TF_VAR_*`; argocd v3.2.0). `event_inputs`
  appears in none. All 13 runs were triggered by `push` of a tag.
- **The generator's source** (`slsa/buildtype.go` and
  `github/workflow.go` of `slsa-framework/slsa-github-generator`, main):
  `configSource.uri` and the one material are
  `git+<server>/<repository>` plus `@<ref>` when the ref is non-empty,
  `digest.sha1` is `GITHUB_SHA`, and `parameters` is
  `WorkflowParameters{event_inputs (omitted when empty), vars}`, the
  workflow-dispatch inputs and the `vars` context (CHANGELOG v2.1.0).
  `entryPoint` is the caller's workflow path. GitHub owner and repository
  names cannot contain `@`, so the first `@` after `git+` ends the
  repository.
- **Fulcio extensions of the `.att` certificates** (flux-cli v2.4.0 and
  v2.7.3, argocd v3.2.0, kyverno v1.16.0): 1.9 is the generator workflow;
  1.12 the caller's repository and 1.14 the caller's ref, equal to the
  two parts of `configSource.uri`; 1.18 the caller's workflow
  `<repository>/.github/workflows/release.yaml@<ref>`; 1.20 `push`.
- **Other `.att` content:** `chainguard/node` on Docker Hub has 3 layers
  (SLSA v1 in Statement v0.1, an apko image configuration, SPDX), 2,008
  to 5,128 bytes; its SLSA v1 layer verifies but has no
  `externalParameters`, which ADR-031 item 5 requires. `external-secrets`
  v0.10.4 has 2 layers with no `predicateType` annotation and `intoto`
  entries.

## Decision

Decided at STOP 1 of #114, all as recommended: D1 (b), D2 (b) and D3 (a
follow-up, #118). The choices below the STOP decisions are the plan's.

1. **Discovery only under claims, after referrers.** `boneli-oci` asks
   for the tag `sha256-<hex>.att` of a subject only when the rule's trust
   has claims, and only after the referrers carrier found nothing for
   that subject: per subject `.sig` (skipped under claims, ADR-031 item
   2), referrers, `.att`. So every rule without claims, and every image
   that passes under ADR-031, sends exactly the requests it sent before.
   The tag is built from the digest only, as `.sig` is. A candidate is a
   layer whose media type is exactly `application/vnd.dsse.envelope.v1+json`
   and whose `predicateType` annotation is exactly on the trust's list;
   other layers are never fetched. The annotation only saves requests:
   the verdict reads the signed statement's predicate type.

2. **The `.att` evidence and its readers** (`boneli-sigstore`,
   `Evidence::from_cosign_attestation`). The annotations are read as on a
   `.sig` layer: a key the reader uses twice refuses, the certificate is
   optional (absent or empty means keyed), the Rekor entry is the legacy
   form. The signature annotation, the chain and `predicateType` are never
   read: intermediates come from the trusted root (ADR-029 item 8). The
   envelope must be a JSON object with in-toto's `payloadType`, a
   canonical base64 `payload` and exactly one signature with a canonical
   base64 `sig`; `keyid` is not read. The statement may be Statement v0.1
   or v1 here (13 of 13 measured `.att` are v0.1); a bundle still admits
   v1 only, since no v0.1 bundle was measured. The evidence is then
   checked as a bundle: predicate type, subject, the keyed or keyless
   signature over PAE with exactly one Rekor `dsse` 0.0.1 entry (ADR-029
   S2), then the claims. The entry's `envelopeHash` is not checked, as in
   ADR-029 item 8: the signature over PAE, the payload hash and the
   verifier already bind everything the verdict reads.

3. **`AttestationNeedsClaims`.** Under a trust without claims an
   attestation is refused before any other check. A cold pull under such
   a rule never asks for `.att` (item 1); without this rule, an `attest`
   line kept by a claims rule would let a warm pull under a rule without
   claims pass where a cold pull refuses. With it, the warm verdict
   always equals the cold one.

4. **The predicate list under claims.** ADR-031 item 1 asked for exactly
   `[https://slsa.dev/provenance/v1]`. A trust with claims now admits a
   non-empty list of SLSA v1 and v0.2, each at most once, in any order
   (`ClaimsPredicateTypes` otherwise); v0.2 is opt-in through the list,
   as ADR-029 S5 made v1 opt-in. A list with v0.2 also needs a source
   repository claim or at least one material claim
   (`ClaimsWithoutSource`): the v0.2 producer's identity is the
   generator's workflow, the same SAN for flux, argocd and kyverno
   (measured), so a rule with v0.2 and only a builder or ref claim would
   accept any project's image built by the generator.

5. **The v0.2 reader and the claim mapping.** Read strictly, whichever
   claims are set, so a statement has one reading under every rule:
   `predicate`, `builder` (object), `builder.id` and `buildType` (strings)
   are required; `invocation` is an object where present; `materials` is
   an array where present (absent is empty) whose entries follow ADR-031
   item 5's dependency rule. `metadata`, `buildConfig` and other members
   are not read. Builder ID is `builder.id`; materials are `materials`.
   One build type is known,
   `https://github.com/slsa-framework/slsa-github-generator/container@v1`
   (13 of 13), and always checked when named: `invocation` is required
   and holds no member but `configSource`, `parameters` and
   `environment` (an object, not read); `configSource` is required and
   holds no member but `uri` (required string), `digest` (object of
   strings) and `entryPoint` (string, not read). `uri` must be
   `git+<repository>[@<ref>]`, split at the first `@`, with a non-empty
   repository and, when `@` is there, a non-empty ref; otherwise
   `MalformedProvenance`. The repository claim matches the part before
   `@`, the ref claim the part after it; a ref claim against a URI
   without a ref is not met (`Claim(SourceRef)`). An undefined member
   anywhere in `invocation` is `UnknownParameters`. Any other build type
   refuses a repository or ref claim (`UnknownBuildType`), as ADR-031
   item 6 does; builder and material claims still apply. A new build type
   needs a captured statement and a new ADR, ADR-031's rule.

6. **`parameters` (D1).** `parameters` is absent or an object with no
   member but the two of the generator's `WorkflowParameters`. `vars`
   (`null` or an object of strings) is accepted and not read: 5 of the
   13 measured statements carry it, 3 non-empty, including the current
   releases of flux and argocd, and only repository admins set
   repository variables, who can change the release workflow anyway.
   `event_inputs` absent, `null` or `{}` passes; a non-empty
   `event_inputs` is `WorkflowInputs`: a dispatch input is input the
   caller chose for this run, and it can change what was built while the
   repository and ref claims still match (ADR-031 item 6's reason for
   refusing undefined external parameters). Measured in none of 13.

7. **Matching, order and texts.** Matching is ADR-031 item 7's: exact
   bytes after JSON unescaping, or a `/`-bounded prefix followed by a
   plain path. The shape is read before any claim, then builder,
   repository, ref and materials in rule order, as ADR-031 item 8. New
   fixed texts, none echoing the input:
   - `EnvelopeTooLarge`: "the DSSE envelope is too large"
   - `MalformedEnvelope`: "the DSSE envelope is malformed"
   - `AttestationNeedsClaims`: "a cosign attestation counts only under a
     rule with provenance claims"
   - `WorkflowInputs`: "the provenance records workflow inputs, which
     can change what was built"
   - `StatementType` now reads "the payload is not an in-toto statement
     of an accepted type"; `ClaimsPredicateTypes` "a trust with claims
     must list SLSA provenance v1 or v0.2, each at most once, and nothing
     else"; `ClaimsWithoutSource` "a trust that lists SLSA provenance v0.2
     needs a source repository or material claim".

   The failure detail gains `{subject}: .att: none`, `.att: <fetch
   detail>`, `.att {manifest}: <parser reason>`, `.att {manifest}: {n}
   layers, more than 16` and `.att {manifest}: {n} listed, {m} candidates
   (layer i: <refusal>, …)`.

8. **Limits,** each derived below. No new crate and no new dependency
   edge: the readers are in `boneli-sigstore` over `boneli-json`, the
   carrier in `boneli-oci`.

### Limits

- **Envelope: at most `MAX_BUNDLE_BYTES` = 4,194,304 bytes.** The largest
  measured envelope is 13,644 bytes, so the cap is 307 times that. An
  envelope is a bundle without its verification material, so anything a
  bundle may carry fits. Its payload decodes to at most 3,145,728 bytes
  (3/4 of the cap), inside the statement's own 4,194,304-byte parse
  limit. A lower cap would refuse statements that a bundle carrying the
  same statement passes; a higher one admits nothing more until about
  5,592,405 bytes, where the decoded payload reaches the statement limit
  and is refused anyway, so it only costs memory. `boneli-oci` checks the
  descriptor's size against it before the request.
- **`MAX_SIGNATURES` = 16 on the `.att` layers,** inclusive: 16 layers
  are all examined, 17 make the carrier yield nothing and fetch nothing.
  Measured layers: 1 (13 of 13 SLSA v0.2), 2 (external-secrets), 3
  (Chainguard). Each `cosign attest` run adds a layer unless it is run
  with `--replace`, so a re-run or another predicate type grows the
  manifest; 16 is 5.3 times the maximum seen. Below about 4, an image
  with Chainguard's three predicate types would be refused after one
  re-attestation; above 16, a hostile listing could force more fetches,
  although only layers whose annotation is on the list are fetched.
- **`MAX_KEPT` = 48 = 3 × `MAX_SIGNATURES` lines per pointer file.**
  ADR-029 derived 32 as every candidate the carriers can list for one
  subject at once, with two carriers; three carriers give 48. A line is
  at most 151 bytes (`attest`, like `legacy` and `bundle`, is 6
  letters), so 48 lines are 7,248 bytes, within `MAX_POINTER_BYTES`
  8,192, which stays. With a lower value, enough rules over one digest
  could push each other's evidence out and send warm pulls to the
  network; a higher one only keeps lines no listing can produce.
- **Worst case per subject under a claims rule** (ADR-029's deadline
  formula: a document or envelope at the 4 MiB cap gets 30 + 4 = 34 s):
  referrers 34 + 34 (404, then the fallback tag) + 16 × (34 + 34) =
  1,156 s; `.att` 34 + 16 × 34 = 578 s; together 1,734 s per subject and
  3,468 s (57.8 min) for two subjects. A rule without claims stays at
  ADR-029's 3,342 s, and one 4 GiB blob may take about 69 min (ADR-009
  D12). Requests: referrers 2 + 32 = 34, `.att` 1 + 16 = 17, so 51 per
  subject, the same as a rule without claims (`.sig` 17 + referrers 34).
- **An honest flux-cli cold pull under claims** makes 4 signature
  requests: referrers 404, the referrers tag 404, the `.att` manifest and
  the envelope. Without claims it makes 2, the `.sig` and its payload, as
  before. A warm pull makes none (ADR-029 S6).
- **JSON limits** stay ADR-029's depth 16 and 65,536 values. Measured
  v0.2 statements reach nesting 7 and 250 values. The deepest member a
  GitHub event payload adds (`release.assets[i].uploader.*`) gives
  nesting 10, derived from the generator's `github_event_payload` field,
  not measured; 16 leaves room for 6 more levels.

### Partial supersession

ADR-031 item 1's "exactly `[https://slsa.dev/provenance/v1]`" is
superseded by item 4 here. The rest of ADR-031 stands.

## Consequences

- An operator can write claims for images that `slsa-github-generator`'s
  container workflow builds (flux, argocd, kyverno), the isolated-builder
  provenance ADR-031 could not read, and a statement that says otherwise
  refuses the pull before any layer request, naming `.att` and the claim.
- Rules without claims, and images that pass under ADR-031, send the same
  requests as before; a claims rule whose referrers find nothing sends 1
  more manifest request per subject (the `.att` tag), and up to 16 more
  envelope fetches when it lists candidates.
- A pointer file with an `attest` line or more than 32 lines is absent
  for a binary before this change, which then discovers again
  (pre-1.0, no data loss).
- A generator release that adds a member to `invocation`, `configSource`
  or `parameters` fails closed with `UnknownParameters` until a successor
  ADR admits it; the known answers pin generator v2.0.0's and v2.1.0's
  shape.
- `Refusal` and `ConfigError` gain variants and two texts change; their
  consumers are in this repository (pre-1.0).

**Known limits, each with its closure:**

- `.att` attestations logged as Rekor `intoto` 0.0.1 entries (generator
  before v2.0.0, 2 of 13 measured) are refused with `EntryKind` (D3).
  Closure: #118, an `intoto` body check bound through `content.hash`.
- The caller's workflow file is not bound (D2). For v0.2 the SAN is the
  generator's, so any workflow of the source repository at a matching
  ref that calls the generator passes; for v1 the SAN names the
  workflow. Whoever can create a matching ref can also edit the release
  workflow at that ref, so the gap adds little against them. Closure:
  #113 adds Fulcio's Build Config URI (1.3.6.1.4.1.57264.1.18), which
  Fulcio writes from the OIDC token (measured on 4 `.att` certificates).
- The trigger: as for v1 (ADR-031, known limits), the ref and the source
  commit name the built code only for some triggers. Closure: #113's
  Build Trigger extension (1.20), measured `push` on the `.att`
  certificates.
- Workflow inputs and `vars` (D1): a non-empty `event_inputs` refuses, so
  a project that releases through `workflow_dispatch` with inputs cannot
  pass a claims rule; `vars` is not read. Closure: a successor ADR when a
  measured producer needs dispatch inputs; `vars` stays unread by design
  (only repository admins set it).
- The generator's SAN prefix (`…@refs/tags/`) trusts whoever may push
  tags to `slsa-framework/slsa-github-generator`: open by design,
  ADR-029 S2.

## Alternatives considered

- **Asking for `.att` under every `Required` rule.** Rejected: a rule
  without claims would send one more request per subject on every cold
  pull and gain nothing, because the measured producers' identity is the
  shared generator workflow (item 4); it would also change #104's request
  logs, against the issue's fourth acceptance criterion.
- **`.att` before referrers.** Rejected: every image that passes under
  ADR-031 would send one request more; the order costs a flux pull 2
  requests (referrers and its tag, both 404).
- **D1 (a), admitting only `{}` or empty `vars`.** Rejected: it refuses 3
  of the 11 verifiable statements, the current flux and argocd releases.
  **D1 (c), admitting `event_inputs` unread.** Rejected: dispatch inputs
  would stay a known limit with no closure.
- **D2 (a), an exact `entryPoint` claim here** (v0.2
  `configSource.entryPoint`, v1 `workflow.path`). Rejected at STOP 1: it
  grows the claim set beyond the issue, and the statement, not Fulcio,
  writes the value.
- **D3, an `Expected::Intoto` body check here** (about 40 lines and 2
  known answers). Deferred to #118 at STOP 1.
- **Checking `envelopeHash`.** Rejected, as in ADR-029 item 8: it adds no
  binding the PAE signature, payload hash and verifier lack.
- **Statement v0.1 in bundles too.** Rejected: no v0.1 bundle was
  measured, and it would change #57's verdicts.
- **Other v0.2 build types** (`generic@v1`, `go@v1`, BYOB). Rejected for
  now: none was captured in an image `.att`, and ADR-031's rule is one
  captured statement per build type.

## Accept when

The known answers pass (flux-cli v2.4.0 and v2.7.3 verify and meet their
claims, argocd v2.10.0's `intoto` entry is refused, and the five negative
fixtures refuse with the claim named), and the `oci-acceptance` run on
the PR for #114 passes `network::provenance_v02_on_ghcr` and
`network::provenance_claims_on_ghcr` on x86_64 and arm64.

**Result (2026-11-24, before the `oci-acceptance` run).** The known
answers pass: flux-cli v2.4.0 (index `sha256:a9cb966c…3471fd1f`) and
v2.7.3 (`sha256:334f7363…d418f14e`, non-empty `vars`) verify against the
committed public-good root and meet their claims, argocd v2.10.0 is
refused with `EntryKind`, and the five negative fixtures refuse with the
claim named. The hand-applied mutation pass over every new check in
`attestation.rs`, `provenance/v02.rs`, `verify.rs`, the predicate-list
rule, the `.att` carrier, the `attest` pointer and the tag kills 61 of 61
mutants; one survived the first pass (`configSource` read from
`invocation` when missing, refused either way but as another refusal)
and is killed by a test added for it. Live on x86_64 (local run):
`provenance_v02_on_ghcr` pulls flux-cli with its 4 layers in 26.1 s over
19 connections and refuses it under another source repository with
`.att sha256:467ee9c3…5b9f7ac5: 1 listed, 1 candidates (layer 0: the
provenance's source repository does not meet the rule)`, the `.sig` not
examined and no layer committed; `provenance_claims_on_ghcr` still
passes, its refused pull now noting `.att: none` for both subjects.
