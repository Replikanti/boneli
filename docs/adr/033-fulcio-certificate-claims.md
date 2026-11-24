# ADR-033: Fulcio certificate claims

- Status: accepted
- Date: 2026-11-24

## Context

ADR-031 checks an SLSA statement's builder, source repository, ref and
source commit as the statement states them. The statement is written
inside the build job, so any step of a trusted workflow's job that holds
`id-token: write` can sign another statement under the same identity
(ADR-031, first known limit). And the ref and commit name the code that
was built only for some triggers: a run started by `pull_request_target`,
`workflow_run`, `issue_comment`, `issues` or `discussion` carries the base
repository, the default branch and that branch's commit, while its steps
may build a fork's code (ADR-031, third known limit). Issue #113 asks for
rules on the extensions Fulcio writes into a keyless leaf from the OIDC
token, which no step of the job can change, and for a cross-check of the
statement against them.

Measured on 2026-11-24:

- **The committed leaves.** The three GitHub keyless leaves in
  `crates/boneli-sigstore/tests/data` (the actions-runner bundle, the jq
  1.8.2 bundle and Chainguard node's `.sig`) each carry Fulcio's
  extensions 1.3.6.1.4.1.57264.1.8 through 1.22 and 1.24, each a DER
  UTF8String with a short-form length; the longest value is 90 bytes
  (Chainguard's 1.9 and 1.18). They also carry the deprecated raw 1.1 to
  1.6. The Kubernetes leaf (Google issuer) carries only 1.1 and 1.8.
- **Their values** of 1.12 / 1.14 / 1.20 / 1.15:
  - runner: `https://github.com/actions/runner` / `refs/heads/main` /
    `workflow_dispatch` / `184286875`
  - jq: `https://github.com/jqlang/jq` / `refs/tags/jq-1.8.2` / `push` /
    `5101141`
  - Chainguard: `https://github.com/chainguard-images/images` /
    `refs/heads/main` / `push` / `563510952`

  1.9 equals the SAN in all three, and the deprecated 1.2 equals 1.20.
- **Why the statement and the certificate agree.** GitHub's producer
  (`actions/toolkit`, `packages/attest/src/provenance.ts`) fills
  `workflow.ref`, `workflow.repository`, the source dependency
  `git+<repository>@<ref>` with its `gitCommit`, and `builder.id` from the
  OIDC token's `ref`, `repository`, `sha` and `job_workflow_ref`. Fulcio's
  GitHub template (`config/identity/config.yaml`) writes 1.14, 1.12, 1.13,
  1.9 and the SAN from the same claims, and 1.20 from `event_name`.
- **Every current SLSA v1 bundle of ADR-031's five producers agrees.**
  Through GHCR's tag schema (the index of `actions/actions-runner:latest`,
  `coder/coder:latest`, `jqlang/jq:1.8.2`,
  `dependabot/dependabot-updater-core:latest` and
  `sigstore/timestamp-server:latest` and their Linux platform manifests)
  there are now 12 SLSA v1 bundles, 2 more than ADR-031 counted
  (dependabot lists 6 instead of 5). Decoded, not verified, all 12 have
  issuer `https://token.actions.githubusercontent.com` and GitHub's build
  type, and in all 12 `builder.id` = 1.9, `workflow.repository` = 1.12,
  `workflow.ref` = 1.14, every dependency `git+<1.12>@<1.14>` has the
  `gitCommit` 1.13, and 1.20 = `internalParameters.github.event_name`.
  Triggers: `workflow_dispatch` (runner, coder ×2), `push` (jq,
  dependabot ×6, timestamp-server). The runner and jq bundles are also
  verified, as the known answers of ADR-031.
- **Formats.** Fulcio's `docs/oid-info.md`: 1.8 to 1.24 are DER
  UTF8String; 1.1 to 1.6 are raw bytes. Under other issuers the same OIDs
  mean other things: GitLab's 1.20 is `pipeline_source`, and its 1.14 is
  built as `refs/heads|tags/<ref>`.

## Decision

Decided at STOP 1 of #113, all three as recommended: rules on 1.12, 1.14
and 1.20, the agreement over 1.9, 1.12, 1.14 and 1.13 (D1); a trigger
list in every set of certificate claims (D2); an optional repository ID
(D3).

1. **Certificate claims live in the trust.** `boneli_sigstore::Trust`
   gets optional `CertificateClaims` (`Trust::with_certificate_claims`),
   built like ADR-031's claims, so a `Required` rule still holds one
   `Arc<Trust>` and `boneli-oci` gets no new policy type; the kept
   evidence of ADR-029 S6 is verified again through the same `verify`, so
   a warm pull checks the current rule offline. They apply to every
   keyless carrier: cosign `.sig` layers and bundles of any listed
   predicate type. `boneli-oci` keeps asking for `.sig` under certificate
   claims alone (only ADR-031's claims skip it). The extensions are read
   only from the leaf webpki verified (ADR-029 item 7,
   `CodeSigningCert::extension`), after the signature and the identity.

2. **Which extensions count (D1).**
   - **Rules:** Source Repository URI (1.12), exact or a prefix ending in
     `/`; Source Repository Ref (1.14), the same; Build Trigger (1.20), a
     list of exact names. These are what the issue asks for, and what
     tells a run's code apart: the repository and ref, and the trigger
     for which they name the built code.
   - **Statement agreement** (opt-in,
     `CertificateClaims::with_statement_agreement`): `builder.id` = 1.9,
     `workflow.repository` = 1.12, `workflow.ref` = 1.14, and at least
     one resolved dependency with the URI `git+<1.12>@<1.14>`, every one
     of them with the `gitCommit` 1.13 ("every, not any", as ADR-031 item
     7). 1.9 and 1.13 go beyond the repository and ref the issue names:
     1.9 ties ADR-031's builder claim to the certificate, and 1.13 ties its
     material claim, the source commit, which ADR-031's first known limit
     leaves written by the signer. 12 of 12 measured bundles agree in all
     four.
   - **Never read:** 1.10, 1.11, 1.16 to 1.19, 1.21 to 1.24 and the
     deprecated raw 1.2 to 1.6. A 1.9 rule would repeat ADR-029 S2 (1.9
     equals the SAN in 3 of 3 leaves).

3. **A trigger list in every set of certificate claims (D2).**
   `CertificateClaims::new` refuses an empty list (`TriggersEmpty`). The
   certificate's repository, ref and commit name the code that was built
   only for the triggers of ADR-031 item 4, so a rule that trusts them has
   to say for which triggers; a rule without a list would keep the gap of
   ADR-031's third known limit open by default. Measured triggers:
   `workflow_dispatch` and `push`. Stricter than the issue's "can": a
   producer that changes its trigger fails closed until the rule is
   edited. Identity-only rules (ADR-029) and statement-only rules
   (ADR-031) keep the gap, as the issue's last criterion requires.

4. **An optional repository ID (D3).**
   `CertificateClaims::with_repository_id` takes the exact Source
   Repository Identifier (1.15), ASCII digits without a leading zero (no
   GitHub ID is 0, and `01` could never equal Fulcio's text). 1.15 is in 3
   of 3 leaves. 1.12 and the SAN are names: a repository deleted or
   renamed can be registered again by someone else under the same name,
   which then meets every name rule, while the new repository gets a new
   ID. The operator looks it up once (`GET /repos/{owner}/{repo}`, field
   `id`); an owner who deletes and recreates the repository has to edit
   the rule.

5. **GitHub Actions only, keyless only.** `with_certificate_claims` is
   refused unless every identity's issuer is exactly
   `https://token.actions.githubusercontent.com`
   (`CertificateClaimsIssuer`): other issuers fill these OIDs with other
   meanings (GitLab above), and the issue puts them out of scope. A trust
   with keys is refused (`CertificateClaimsWithKeys`): a keyed signature
   has no certificate that could meet the claims, so a key next to them
   would bypass them. The agreement needs ADR-031's claims
   (`AgreementWithoutClaims`, call `with_claims` first), because only a
   trust with claims reads the statement, and GitHub's build type
   (`UnknownBuildType` otherwise), the only one whose fields Fulcio's
   correspond to.

6. **One reading.** Under any certificate claims, every modeled extension
   that is present (1.9, 1.12, 1.13, 1.14, 1.15, 1.20) must be one whole
   DER UTF8String with a minimal length, non-empty and valid UTF-8;
   otherwise the refusal is `Malformed(ext)`, naming the first in OID
   order, whichever rules are set, so a leaf has one reading under every
   rule. A missing extension refuses only where a rule needs it
   (`Missing(ext)`): 1.12, 1.14 or 1.15 under their rules, 1.20 always,
   1.9, 1.12, 1.13 and 1.14 under the agreement. An extension twice is
   refused by `boneli-https`'s certificate reader before any of this
   (`Certificate(Malformed)`), and so is a critical Fulcio extension, by
   webpki. Without certificate claims nothing beyond the issuer is read,
   so ADR-029 and ADR-031 verdicts do not change: the issuer reader keeps
   its own path (`utf8_string`, moved into the new `fulcio` module byte
   for byte, with no UTF-8 check added there).

7. **The deprecated extensions are never read.** Under certificate claims
   a leaf without the newer extension a rule needs is refused, so nothing
   needs a fallback; a raw 1.2 or 1.6 never decides, whatever it says.
   The issuer pair 1.1/1.8 differs: there, old leaves need the fallback
   (ADR-029).

8. **Matching.** Byte for byte with no normalization: `.git`, `http://`,
   other case, trailing whitespace or a zero-width space and look-alike
   letters never match. A prefix ends in `/` and what follows must be a
   plain path, ADR-031's `under` rule. Fulcio writes these values, but it
   copies them from claims a repository owner can shape (a ref is any
   branch or tag name), so the remainder rule applies here too. Triggers
   are a set of exact names; a name listed twice counts once. The
   agreement compares after JSON unescaping.

9. **Order and texts.** The checks run:
   1. what is signed, then the signature and identity (ADR-029);
   2. the facts read from the leaf (item 6);
   3. the rules: repository, ref, ID, trigger, then the presence of what
      the agreement needs;
   4. the statement's shape (ADR-031 items 5 and 6);
   5. the agreement: builder, repository, ref, commit;
   6. ADR-031's claims.

   Fulcio's facts come first, so no statement is parsed for a leaf that
   fails, and a statement that disagrees with its certificate is refused
   before its claims are read. Each refusal is a fixed text that names
   the extension by name and OID and echoes nothing of the leaf or the
   statement (`Refusal::CertificateClaim`): "the certificate has no
   Fulcio Build Trigger (1.3.6.1.4.1.57264.1.20)", "the certificate's
   Fulcio … is malformed", "… does not meet the rule", "the provenance
   disagrees with the certificate's Fulcio …".

10. **No new limit.** The values sit in a leaf that `MAX_BUNDLE_BYTES`
    (a bundle) or the manifest document limit of ADR-009 D12 (a `.sig`
    layer's annotation) already bound. The DER reader takes
    lengths up to 65,535 (the `0x82` form), 728 times the longest
    measured value, and refuses `0x83` and longer forms: a value that
    long is no repository, ref, ID or event name. No crate and no
    dependency edge is added; `boneli-https` is unchanged.

## Consequences

- An operator can require "built from this repository, at a tag, for a
  push" from what Fulcio wrote, for GitHub's attestations and for
  cosign `.sig` signatures such as Chainguard's, and can tie an SLSA
  statement's builder, repository, ref and source commit to the
  certificate.
- Every set of certificate claims names its triggers; a producer that
  starts releasing from another trigger fails closed until the rule is
  edited.
- A rule with a repository ID refuses a repository recreated under the
  same name.
- `Refusal` and `ConfigError` gain variants; their consumers are in this
  repository (pre-1.0). `Debug` of a trust names `certificate_claims:
  true` when they are set and shows no claim text.

**Known limits, each with its closure:**

- Certificate claims are as strong as Fulcio's issuance and GitHub's
  token: a step of the job that holds `id-token: write` still gets a leaf
  with the same extensions, so it can sign another artifact as the same
  run, now only for that run's repository, ref, commit and trigger. What
  the steps did with the code stays outside what a signature can say;
  SLSA Build L3 provenance (`slsa-github-generator`, cosign `.att`) is
  #114.
- Only GitHub Actions' issuer. Other issuers' meanings of these OIDs are
  not modeled; a trust with another issuer cannot have certificate
  claims. Closure: an ADR per issuer with a captured leaf, when a user
  needs one; until then such trusts keep ADR-029 and ADR-031 rules.
- The configuration that builds these claims (the policy file) is #32 and
  #33.

## Alternatives considered

- **A 1.9 (Build Signer URI) rule.** Rejected: it equals the SAN in 3 of
  3 leaves, so ADR-029 S2's identity already is that rule.
- **A 1.18 (Build Config URI) rule.** Rejected: within one repository and
  ref, whoever can add a calling workflow can also edit the one it names,
  and it equals 1.9 in 3 of 3 leaves.
- **A 1.11 (runner environment) rule.** Rejected: whether a build ran on
  a GitHub-hosted runner is a question of SLSA levels, out of scope.
- **Reading the deprecated 1.2 to 1.6 as a fallback.** Rejected: raw
  bytes with no type, and every measured leaf carries the newer ones; a
  fallback would give an old leaf two readings.
- **An implicit agreement** whenever a trust has ADR-031 claims.
  Rejected: it would change ADR-031 verdicts for rules that configure
  nothing new (the issue's last criterion), and it cannot apply to keyed
  SLSA statements.
- **An implicit trigger allowlist** (ADR-031 item 4's list). Rejected: it
  goes stale as GitHub adds events, and it would accept triggers a
  producer never uses.
- **A trigger denylist** (`pull_request_target`, …). Rejected: incomplete
  by construction; a new event would pass.
- **Accepting any issuer.** Rejected: under GitLab 1.20 is
  `pipeline_source` and 1.14 another form, so a GitHub-shaped rule would
  match by accident or not at all.
- **Rules outside the trust** (a new policy type in `boneli-oci`).
  Rejected for the reason of ADR-031 item 1: one `Arc<Trust>` per rule,
  and the warm path verifies kept evidence through the same `verify`.

## Accept when

The known answers pass (the runner, jq and Chainguard leaves meet their
certificate claims, and one field off on each refuses, naming it), every
negative fixture kills a mutant in the hand-applied mutation pass, and
the `oci-acceptance` run on the PR for #113 passes
`network::certificate_claims_on_ghcr` on x86_64 and arm64.

**Result (2026-11-24).** The known answers pass: the runner and jq
attestations and Chainguard's `.sig` meet their certificate claims with
the same `Accepted` as without them, the two attestations also with
ADR-031's claims and the agreement, and one field off on each (repository,
ref, ref prefix, trigger, repository ID) refuses naming it. The
hand-applied mutation pass over `fulcio.rs`, the agreement step, the
order in `verify` and the configuration checks kills 45 of 46 mutants.
The one left is equivalent: certificate claims on an accepted signature
without a certificate (the `NoCertificate` arm) cannot be reached,
because configuration refuses a trust with keys. Live on x86_64 (local
run): `certificate_claims_on_ghcr` pulls jq with both layers in 5.9 s
over 15 connections and refuses it under `[release]` with `referrers tag:
1 listed, 1 candidates (entry 0: the certificate's Fulcio Build Trigger
(1.3.6.1.4.1.57264.1.20) does not meet the rule)`, and no layer
committed. The `oci-acceptance` run on the PR (run 45444216792) passes
`certificate_claims_on_ghcr` on x86_64 and arm64 (jq pulled in 5.8 to
6.3 s over 15 connections on both), next to `provenance_claims_on_ghcr`,
`signatures_on_docker_hub`, `signatures_elsewhere` and
`node_and_postgres_run_in_sandbox`.
