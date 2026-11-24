# ADR-031: SLSA provenance claims

- Status: accepted
- Date: 2026-11-24

## Context

ADR-029 S5 counts a signed in-toto statement by its predicate type only.
A `Required` rule that lists `https://slsa.dev/provenance/v1` accepts any
SLSA statement the trusted signer signed for the digest, whatever
builder, source repository, ref or source commit it names. An operator
who wants "built by this workflow from this repository at a release tag"
cannot write that rule. Issue #104 asks for an optional claim list on a
`Required` rule: the SLSA v1 `builderId`, the source repository and ref,
and materials by URI and digest, matched exactly, with an ADR deciding
the claim set and what each claim is trusted to mean.

Measured on 2026-11-24 through the anonymous GHCR API over 20
repositories (the index and its Linux platform manifests, the
`sha256-<hex>` tag, `.sig` and `.att`):

- **Who publishes SLSA v1.** 5 of 20 carry SLSA v1 Sigstore bundle v0.3
  referrers, 10 bundles in all, each listed with the
  `dev.sigstore.bundle.predicateType` annotation:
  `actions/actions-runner` (1), `coder/coder` (2), `jqlang/jq` (1),
  `dependabot/dependabot-updater-core` (5) and `sigstore/timestamp-server`
  (1). All 10 are GitHub's artifact attestations: build type
  `https://actions.github.io/buildtypes/workflow/v1`, keyless, issuer
  `https://token.actions.githubusercontent.com`, one Rekor v1 `dsse` 0.0.1
  entry with an inclusion promise.
- **One shape.** In all 10, `externalParameters` is exactly
  `{"workflow": {path, ref, repository}}` and `resolvedDependencies` is
  exactly one entry, the source commit `git+<repository>@<ref>` with a
  `gitCommit` digest.
- **They verify under ADR-029 as it is.** Three were checked against the
  committed public-good root with the exact SAN: `actions/actions-runner`
  index `sha256:6d0b2d80…b8c31300` (integrated time 1794424176, log
  index 3816483043), `coder/coder` `sha256:2ce6b2ab…2c15631a`
  (1794808393, 3918564748) and `jqlang/jq:1.8.2` `sha256:b9c68867…5344e486`
  (1781962736, 1884124456). The runner and jq bundles are the known
  answers of this ADR (`crates/boneli-sigstore/tests/data`).
- **`builder.id`** is `<server>/<job_workflow_ref>`, and in the three
  checked it equals the certificate's SAN. It carries the ref: 2 of 5
  producers release from tags (jq `…/ci.yml@refs/tags/jq-1.8.2`;
  timestamp-server `…/build_container.yml@refs/tags/v2.2.2`, a reusable
  workflow whose `workflow.path` is `release.yaml`), 1 from a release
  branch (`coder …@refs/heads/release/2.39`), 2 from `main`. In 2 of 5 the
  source repository is not the image's name (`dependabot-core`,
  `timestamp-authority`). Coder builds on a `self-hosted` runner, the
  others on `github-hosted` ones.
- **Fulcio's extensions agree.** In the runner capture, the certificate's
  extensions 1.3.6.1.4.1.57264.1.12 (Source Repository URI)
  `https://github.com/actions/runner` and 1.14 (Source Repository Ref)
  `refs/heads/main` equal `workflow.repository` and `workflow.ref`.
- **Sizes.** The statements are 1,026 bytes (runner), 1,013 (coder) and
  964 (jq), with nesting 6 and 32 JSON values each; the bundles are 10,794
  bytes (runner) and 10,151 (jq).
- **The rest.** `fluxcd/flux-cli:v2.4.0` carries SLSA **v0.2** only, in a
  cosign `.att`. `github/github-mcp-server`'s one referrer has no
  predicate annotation and is a `cosign/sign/v1` bundle, and so are the
  referrers of `sigstore/cosign/cosign`, `goreleaser/goreleaser` and
  `stacklok/toolhive`. `home-assistant` and `trivy` list only non-bundle
  referrers; uv, ruff, kyverno, immich, zitadel, open-webui, oras and
  syft list none.
- **The build type's specification** (`actions/buildtypes`,
  `workflow/v1/README.md`, last commit 2024-06-11) defines exactly
  `workflow.ref`, `workflow.repository` (`https://`, no `.git`) and
  `workflow.path`, says "Consumers SHOULD reject unrecognized external
  parameters", sets `builder.id` to `server_url + "/" + job_workflow_ref`,
  and requires `resolvedDependencies` to contain
  `git+<server>/<repo>@<ref>`.

## Decision

Decided at STOP 1 of #104, both as recommended: the claims are checked
against the statement as filed (Fulcio's certificate extensions follow in
#113), and cosign `.att` with SLSA v0.2 follows in #114.

1. **Claims live in the trust.** `boneli_sigstore::Trust` gets an
   optional `Claims` (`Trust::with_claims`), so a `Required` rule keeps
   holding one `Arc<Trust>` and `boneli-oci` gets no new policy type. The
   kept evidence of ADR-029 S6 is verified again through the same
   `verify` call, so a warm pull checks the current rule's claims
   offline. `with_claims` is refused unless the predicate list is exactly
   `[https://slsa.dev/provenance/v1]`: another type's statements carry no
   SLSA predicate, so a claim list next to it could only be bypassed.
   `Trust::new` is unchanged, and a trust without claims never reads the
   predicate: #57's verdicts stay as they were.

2. **A rule with claims admits provenance only.** A cosign simple-signing
   layer carries no claims, so under claims it is refused
   (`NotProvenance`) before any other check; a `cosign/sign/v1` bundle is
   refused by the predicate list. Otherwise a `.sig` by the trusted signer
   would pass a rule whose claims it never made. `boneli-oci` does not
   ask for the `.sig` tag of such a rule at all: none of its candidates
   could pass, and skipping it saves 1 manifest request plus up to 16
   payload fetches (`MAX_SIGNATURES`) per subject. The failure detail
   says `.sig: not examined, the rule has provenance claims`.

3. **Claims are checked after the signature.** The predicate type, the
   subject and the signature (keyed or keyless) are checked first, as in
   ADR-029; only a statement that passed is read for its claims. So an
   attacker's unsigned predicate is never parsed for meaning, and a
   failing claim never hides a bad signature.

4. **The claim set and what each claim means.**
   - **Builder ID**, exact: `runDetails.builder.id`, the entity the
     signer says generated the provenance. For GitHub's producer it is
     `job_workflow_ref`, the same text as the SAN, so a prefix here would
     add nothing to ADR-029 S2's identity prefix. A tag-released workflow
     gets a new builder ID with every release (jq, timestamp-server), so
     for GitHub builds the S2 identity prefix is the tool, and the builder
     claim is for builders that pin a version on purpose. Exact, as the
     issue asks.
   - **Source repository**, exact or a prefix ending in `/`:
     `externalParameters.workflow.repository`, the repository whose
     workflow run produced the build (the caller of a reusable workflow).
   - **Source ref**, exact or a prefix ending in `/`:
     `externalParameters.workflow.ref`, the run's `GITHUB_REF` as the OIDC
     token carries it (a branch, a tag or `refs/pull/N/merge`). It names
     the code the run built only when the trigger's ref is the code
     built: `push` (branch or tag), `release`, `pull_request`,
     `workflow_dispatch` and `schedule`, and then only when the steps
     build the commit the run started on. Every other trigger counts as
     unknown: some, among them `pull_request_target`, `workflow_run`,
     `issue_comment`, `issues` and `discussion`, get the base or default
     branch as their ref and that branch's commit as `gitCommit`,
     whatever code their steps check out (see Known limits). A prefix is allowed because
     3 of the 5 measured producers have a ref that moves with every
     release, the reason S2 allows a URI prefix.
   - **Materials**, by URI and one digest: an entry of
     `buildDefinition.resolvedDependencies`. For GitHub's producer the
     only entry is the source commit. Any algorithm name is allowed,
     because the source commit is `gitCommit` (SHA-1 for most
     repositories); the digest is lower-case hex at configuration.
     `byproducts` and `builderDependencies` are never read.
   - **How far they can be trusted:** they are the signer's assertions,
     no stronger than the identity or key that signed them. GitHub's
     producer runs inside the build job (SLSA Build L2), so any step of
     that job that holds `id-token: write` can sign another statement
     under the same identity. Claims narrow which of a trusted signer's
     statements count; they do not prove the build. SLSA level
     assessment stays out of scope, as filed.

5. **A strict reader, one reading.** Every field the reader models is
   type-checked whichever claims are set, so a statement has one reading
   under every rule: `predicate`, `buildDefinition`, `buildType`,
   `externalParameters`, `runDetails`, `builder` and `builder.id` are
   required and of their type (`null` is a wrong type);
   `resolvedDependencies` is optional (absent is empty), otherwise an
   array of objects whose `uri`, where present, is a string and whose
   `digest`, where present, is an object of strings. A missing or
   mistyped field is `MalformedProvenance`. Members the reader does not
   model are ignored, the in-toto and SLSA parsing rule: a producer may
   add `metadata`, `byproducts` or `internalParameters` without
   breaking rules that never read them. A member twice never reaches the
   reader: `boneli-json` refuses the statement (ADR-008), so it has one
   reading.

6. **One known build type.** When `buildType` is
   `https://actions.github.io/buildtypes/workflow/v1` (10 of 10
   measured), its fields are always checked: `externalParameters` is
   exactly `{"workflow": …}`, and `workflow` holds only `ref`,
   `repository` and `path`, strings, the first two required. Another
   member is `UnknownParameters`, as the specification asks: an external
   parameter is input the build was run with, and one the type does not
   define (a workflow input, say) could change what was built while the
   repository and ref claims still match. Any other build type refuses a
   repository or ref claim (`UnknownBuildType`), because where the source
   sits is defined per build type; builder and material claims are
   generic SLSA v1 fields and still work. Matching is exact: a trailing
   `/`, `http://`, `/v2` or `V1` is another type. A new build type gets a
   new ADR with a captured statement.

7. **Matching.** Exact means equal bytes after JSON unescaping: no
   normalization, so `.git`, `http://`, `git+https://`, other case,
   trailing whitespace and a look-alike letter never match, as identities
   in S2. A prefix must end in `/` (the boundary rule of S2), and what
   follows it must be a plain path: non-empty, only bytes `!` to `~`
   other than `%`, `?`, `#` and `\`, every `/`-segment non-empty and
   neither `.` nor `..`. Unlike Fulcio's SAN, this text is written by the
   signer, so a remainder that a URL or ref reader would resolve outside
   the prefix (`…/acme/../evil`, `…/acme/%2e%2e/evil`, `…/acme/a\b`, a
   query, a fragment, `…/acme//x`) is refused. A material matches when at
   least one entry has the rule's URI and every entry with that URI has
   the rule's digest under the rule's algorithm; none with the URI is
   `MaterialMissing(i)`, one that lacks the algorithm or differs is
   `MaterialDigest(i)`, with `i` the material's 0-based position in the
   rule, as `rule {i}` counts in `SignaturePolicy::new`. "Every" and not
   "any": two entries for one URI with different digests leave the
   source commit undecided, and that refuses.

8. **Order and texts.** The shape (5, 6) is read before any claim; then
   builder, repository, ref and the materials in rule order, and the first
   that fails is the refusal. Each refusal is a fixed text that names its
   claim and echoes nothing of the statement (ADR-029 item 8):
   - `NotProvenance`: "the rule requires SLSA provenance claims, which a
     simple-signing signature does not carry"
   - `MalformedProvenance`: "the SLSA provenance predicate is malformed"
   - `UnknownParameters`: "the provenance has external parameters its
     build type does not define"
   - `UnknownBuildType`: "the provenance's build type is not one whose
     source the rule can read"
   - `Claim(…)`: "the provenance's builder ID / source repository /
     source ref does not meet the rule", "the provenance lists no
     resolved dependency for material {i} of the rule", "the
     provenance's resolved dependency for material {i} of the rule has
     another digest"

   Configuration refuses a claim list with no claim (`ClaimsEmpty`), a
   text that is empty or not printable ASCII without spaces, the rule of
   S2 (`ClaimNotAscii`), a prefix without the `/` boundary
   (`ClaimPrefixWithoutBoundary`) and a digest that is not lower-case hex
   (`MaterialDigestNotHex`).

9. **No new limit.** The payload is parsed again under the limits it
   already passed in `dsse::statement`, ADR-029's 4,194,304 bytes, depth
   16 and 65,536 values, against measured statements of at most 1,026
   bytes, nesting 6 and 32 values (4,088, 2.7 and 2,048 times smaller). An
   entry `{uri, digest: {alg: v}}` is 4 values, so at most 16,384 entries
   fit, and a rule with M materials makes at most M × 16,384 string
   comparisons, linear in a payload the signature check has already
   hashed in full, so no separate cap is needed
   (`many_dependencies_last_matches` checks 16,000 entries with the match
   last).
   A tighter limit would only refuse statements ADR-029 already accepts
   as signed; a looser one is not possible without loosening ADR-029.
   No crate and no dependency edge is added: the reader is in
   `boneli-sigstore` over `boneli-json`.

## Consequences

- An operator can write "built by this workflow, from this repository,
  at a release tag, from this commit" for GitHub's artifact attestations,
  and a statement that says otherwise refuses the pull before any layer
  request, naming the claim.
- A rule with claims refuses images signed only through `.sig`
  (Chainguard, Kubernetes) and images whose only SLSA provenance is v0.2
  in `.att`: claims and those carriers do not meet until #113 and #114.
- Other forms of a repository (`.git`, case, `http://`) are refused, not
  normalized; the rule is written in the producer's form, which for
  GitHub's build type is fixed by its specification.
- A producer that adds an external parameter to GitHub's build type
  fails closed with `UnknownParameters` until this ADR or a successor
  admits it; the known answers pin the shape measured on 10 of 10
  statements.
- `Refusal` and `ConfigError` gain variants; their consumers are in this
  repository (pre-1.0).
- `Debug` of a trust names `claims: true` when claims are set and shows
  no claim text; a trust without claims prints as before.

**Known limits, each with its closure:**

- Any step of the signing job can sign other claims: the statement is
  written inside the build job (L2), so its claims are as strong as the
  job's identity and no stronger. Closure: #113 matches Fulcio's
  certificate extensions (1.9 Build Signer URI, 1.12 Source Repository
  URI, 1.14 Source Repository Ref), which Fulcio writes from the OIDC
  token rather than the job, and which also cover `.sig` signatures such
  as Chainguard's. ADR-033 adds these certificate claims and an opt-in
  agreement of the statement with the certificate.
- cosign `.att` and SLSA v0.2, where the isolated-builder (L3) provenance
  of `slsa-github-generator` lives, are not read, so claims cannot be
  checked where they would mean the most (1 of the 20 measured
  repositories). Closure: #114.
- The ref and the source commit say which code a run built only for the
  triggers listed in item 4 (`push`, `release`, `pull_request`,
  `workflow_dispatch`, `schedule`), and only when the steps build the
  commit the run started on; a step that checks out other code is the
  first known limit above. Any other trigger is treated as unknown, and
  some, such as `pull_request_target`, `workflow_run`, `issue_comment`
  or `issues`, carry the base or default branch as their ref and that
  branch's commit as `gitCommit`, so a rule with ref `refs/heads/main` and that
  commit as a material accepts an image such a run built from a fork's
  code. Only the trigger tells these runs apart. The gap is open when
  the signing workflow, or any workflow that calls it as a reusable
  workflow, lists such a trigger: the SAN names the called workflow,
  while the trigger is the caller's (the measured timestamp-server
  build is a reusable workflow called by its release workflow).
  Closure: #113 adds Fulcio's Build Trigger extension (1.20), which
  Fulcio writes from the token's `event_name`, the caller's event.
  ADR-033 makes a trigger list part of every set of certificate claims.

## Alternatives considered

- **Fulcio's certificate extensions instead of the statement.** Stronger
  (written by Fulcio, not the job) and they cover `.sig` too; but the
  issue asks for the statement's claims, materials exist only there, and
  the extensions are a separate reader of certificate content. Follow-up
  #113 (STOP 1).
- **Claims that apply only to SLSA evidence,** letting a `.sig` pass a
  rule with claims. Rejected: the trusted signer's `.sig` would bypass
  every claim (item 2).
- **A builder ID prefix.** Rejected: for GitHub the builder ID is the
  SAN, which S2's identity prefix already covers, and the issue asks for
  exact.
- **Regex or glob.** Rejected as in ADR-029 S2: one look-alike class
  more per operator mistake, and no measured need beyond a `/`-bounded
  prefix.
- **Parsing the predicate in `Evidence::from_bundle`.** Rejected: it would
  change #57's verdict for rules without claims (a malformed predicate
  would start refusing) and read untrusted predicate data before the
  signature is checked.
- **Ignoring unknown external parameters.** Rejected: the specification
  says consumers should reject them, and an unknown input can change the
  build while the repository and ref still match (item 6).
- **URI normalization** (strip `.git`, lower-case the host). Rejected:
  every normalization adds a form an attacker can choose; the producer's
  form is fixed by its build type.
- **Checking `event_name`** (`internalParameters.github`). Rejected: out
  of the claim set as filed. The ref names the built code only for the
  triggers listed in item 4; every other trigger is a known limit,
  closed by #113 through the certificate's Build Trigger extension,
  which Fulcio writes rather than the job.

## Accept when

The known answers pass (the runner and jq attestations verify and meet
their claims, and the issue's five negative fixtures refuse), and the
`oci-acceptance` run on the PR for #104 passes
`network::provenance_claims_on_ghcr` on x86_64 and arm64.

**Result (2026-11-24).** The known answers pass: GitHub's attestations
of `actions/actions-runner` (index `sha256:6d0b2d80…b8c31300`) and
`jqlang/jq:1.8.2` (`sha256:b9c68867…5344e486`) verify against the
committed public-good root and meet their claims, and the five negative
fixtures refuse with the claim named. The hand-applied mutation pass of
the PR kills 42 of 43 mutants; the one left was equivalent (a non-empty
check the segment rule already makes) and its clause was removed. Live
on x86_64 (local run): `provenance_claims_on_ghcr` pulls jq with both
layers in 5.2 s over 15 connections and refuses it under another source
repository with `referrers tag: 1 listed, 1 candidates (entry 0: the
provenance's source repository does not meet the rule)`, the `.sig`
not examined, and no layer committed. The `oci-acceptance` run on the PR (run
45360452215) passes `provenance_claims_on_ghcr` on x86_64 (jq in 5.1 s)
and arm64 (6.2 s), next to `signatures_on_docker_hub`,
`signatures_elsewhere` and `node_and_postgres_run_in_sandbox`.
