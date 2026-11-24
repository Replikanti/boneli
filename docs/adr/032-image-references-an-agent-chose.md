# ADR-032: Image references an agent chose

- Status: accepted
- Date: 2026-11-24

## Context

ADR-029 added a signature policy to `boneli-oci`: rules keyed by registry
and repository, each `Off` or `Required` with a trust, and a default.
The default is `Off`, because Docker Official Images are unsigned and a
`Required` default would refuse the first-stack images. Protection
therefore exists only where the operator writes a `Required` rule, and an
`Off` rule under a `Required` prefix is the operator's own exemption by
design (ADR-029, first known limit).

That is the right default for references the operator wrote: they are as
trusted as the rest of the operator's configuration. It is the wrong one
for references an agent chose. The environment builder (plan step 3 of
`docs/ARCHITECTURE.md`) proposes the images of a replica, and a playbook
may name images too. The agent is the party least trusted to pick an
image, and under ADR-029 it can pick any repository the operator wrote no
rule for: digest pinning (ADR-009) then pins whatever the agent chose.
Issue #105 asks that the origin of a reference travel with the pull, that
agent references resolve under `Required` unless an operator exemption
names them, and that the exemption be recorded.

Measured on 2026-11-24 through the anonymous Docker Hub API:

- **No first-stack image carries a signature.** ADR-029 measured
  `library/node` (`sha256:e13726ca…`): `.sig` 404, referrers `[]`. The
  same holds for the other images the first stack uses: the current
  indexes of `library/postgres:17` (`sha256:cdbfb3de…`),
  `library/redis:7` (`sha256:314425e4…`), `mailhog/mailhog:latest`
  (`sha256:8d76a3d4…`) and `inbucket/inbucket:latest`
  (`sha256:48063d73…`) answer the `.sig` tag of the index digest with 404
  and the referrers API with 200 and `"manifests":[]`. So 0 of these 5
  repositories would pass any trust today.
- **What the first stack pulls.** The compose files on the default
  branches of the three candidate repositories that `docs/ARCHITECTURE.md`
  names for the first stack (10 files, counted for the plan of #105) use
  these service images besides the applications' own: `postgres` in 3 of
  3 repositories, `redis` in 3 of 3, and a mail catcher in 2 of 3
  (`mailhog/mailhog`, `inbucket/inbucket`). The M0 demo runs `node` and
  `postgres` (the weekly `oci-acceptance` run).
- **The size of `library/`.** The Docker Official Images namespace holds
  181 repositories (`hub.docker.com/v2/repositories/library/`, field
  `count`).
- **Who builds references today.** Nothing in the runner calls
  `ImageStore::pull` yet: its callers are the contract suites, the
  mutants and the tests (16 `ImageRef` struct literals in 8 files, all in tests
  or test support). The first use case that pulls is `BuildEnvironment`
  (#14), where the agent's proposal becomes references.

## Decision

The decisions S1 to S5 were taken at STOP 1 of #105 as recommended.

### S1. The origin is a required field of `ImageRef`

`boneli_app::ImageRef` gets `origin: ImageOrigin`, with exactly two
values:

- `Operator`: the runner's operator configured the reference (a
  hand-written replica config, a CLI argument, a job config).
- `Agent`: an agent job produced it or could have changed it. A reference
  copied from the repository under work counts as `Agent`, because the
  agent works in that repository and the repository's author is no more
  trusted than the agent.

The origin is set where the reference enters the runner, in the parser of
an agent proposal or of operator configuration, and never changed after.
There is no default (`ImageRef` has no `Default`, so every struct literal
must name the origin; the compiler refuses one that does not) and no third
value: "unknown" would have to be treated as `Agent` anyway, so it adds a
name for the same thing.

Why a field and not a parameter of `pull`: with a parameter, every call
site decides again, and every call site is a chance to downgrade. With a
field, the reference carries its taint from the place that knows it.

`MemoryImageStore` keys its images by name, digest and platform without
the origin, so two references that differ only in their origin give the
same root filesystem; the real adapter's handle is the manifest digest
and never depended on the reference.

### S2. An agent reference no `Required` rule covers is refused before any request

For an `Agent` reference, `SignaturePolicy::decide` returns:

1. `Required(trust)` when a `Required` rule of its registry covers it,
   the most specific such rule, or else when the default is `Required`:
   the reference is checked exactly as ADR-029 checks the operator's, with
   that trust, SLSA provenance claims (ADR-031) included. `Off` rules play
   no part for the agent: they neither admit its reference nor shadow a
   `Required` rule that covers it (S3);
2. otherwise `Exempted(exemption)` when an operator agent exemption (S3)
   covers it;
3. otherwise `Refused`: the pull is `Failed` with
   `signature policy: <registry>/<repository> was chosen by the agent, and
   no Required rule or agent exemption covers it`.

There is no separate trust for agent images: a trust for them is written
as a `Required` rule. A request without a trust could verify nothing, so
it would only tell the registry what the agent wanted. The decision is
made after the reference is parsed and its registry selected, and before
the registry client is built or the cache is asked, so a refused reference
makes 0 requests and reads nothing from the store. An agent reference to a
repository the registry does not have is therefore `Failed`, not
`NotFound` (ADR-029: a policy refusal is `Failed`); the port's doc and the
contract say so.

The operator's reference is decided as before, by the most specific rule
of any kind: `Required` under a `Required` rule, otherwise `Unchecked`.

### S3. Agent exemptions are a separate list, by repository or prefix

`SignaturePolicy::with_agent_exemptions(Vec<AgentExemption>)` sets the
list. An `AgentExemption` is a registry name plus an `ExemptScope`:
`Exact(Repository)` or `Prefix(String)`, where the prefix ends in `/` and
its components follow the repository grammar of ADR-009 D9, as a rule's
prefix does (one shared check). A registry-wide exemption cannot be
written: the agent can choose any namespace of a registry, so a whole
registry is the hole of #105 again. Two exemptions with the same registry
and scope are refused, as two rules are.

- **An exemption never lifts a `Required` rule.** It only replaces the
  refusal of S2. So an agent reference never gets a weaker check than the
  operator's reference to the same image: where the operator's is checked,
  the agent's is checked with the same trust, and where a `Required` rule
  covers the repository the agent's is checked even if an operator `Off`
  rule unchecks the operator's.
- **An `Off` rule does not apply to the agent.** ADR-029 uses an `Off` rule
  under a `Required` prefix as the operator's exemption for their own
  references. If it also opened the repository to the agent, an operator
  who opened a repository for their own hand-written configuration would
  open it to the agent without noticing. That holds two ways: an `Off`
  rule is not an exemption, and it does not shadow a `Required` rule for
  the agent, because then a broader exemption (the preset `library/`
  under a `Required` rule for `library/`, say) would start to admit the
  repository the `Off` rule names, unchecked. Found at the review of
  PR #116; `operator_off_rule_never_shadows_required_for_agent`.
- **The most specific exemption is the one reported:** an exact one over
  any prefix, a longer prefix over a shorter one, the ranking the rules
  use.
- **Who may exempt:** only the operator, through `StoreConfig::signatures`
  before `OciImageStore::open`. No port operation adds or widens an
  exemption, and a run cannot change the config of a store that is open.
  `open` refuses an exemption for a registry the store does not pull from,
  as it refuses such a rule.

### S4. The documented first-stack configuration

`AgentExemption::docker_official_images()` is the exemption `docker.io` +
`library/`, the namespace of the Docker Official Images program. It is the
documented configuration under which the first-stack demo images pull as
agent references (#105 acceptance criterion 5). With it:

- `library/node`, `library/postgres` and `library/redis` pass (3 of the 5
  repositories measured), each pull reporting `docker.io` / `library/`;
- the mail catchers are user namespaces and are refused until the operator
  exempts them exactly (`mailhog/mailhog`, `inbucket/inbucket`), which an
  operator who wants them does in one line each;
- an image an arbitrary Docker Hub account pushed is refused.

The exact pair `library/node` + `library/postgres` would cover only 2 of
the 5 (the M0 demo) and refuse `redis`, which all 3 candidate
repositories use; that is why the preset is the prefix. Which namespace
is official is Docker's documentation and is not verified by boneli.

### S5. The pull reports the exemption; the run log write lands in #14

`ImageStore::pull` returns `Pulled { rootfs, exemption }`, where
`exemption: Option<ImageExemption>` holds the registry name and the scope
as text (a repository never ends in `/`, a prefix always does, so the
text says which). It is `Some` only for an agent reference admitted by an
exemption: `None` for every operator reference and for an agent reference
checked under `Required`. `Lease::exemption()` carries it for
`pull_leased`; a lease from `OciImageStore::lease(&RootfsRef)` is not a
pull and reports `None`.

The first use case that pulls an agent reference writes it to its run
log: `BuildEnvironment` in #14, whose issue body carries this
requirement. A domain `RunEvent` is not added now: no run step pulls an
image, the domain has no image event among its 12 `RunEvent` variants,
and `BuildEnvironment` is not a `Run`, so an event added now would guess
#14's shape. Until #14 exists, no code builds an `Agent` reference, so no
exemption goes unrecorded.

### S6. An agent reference is served only a digest its repository holds

The store keeps documents by digest, not by repository (ADR-009 D8), so
a warm cache would hand an agent reference `library/node@D` the image
`D` that the operator pulled from `evil/miner`: the decision (`Exempted`
under `library/`) is taken on the name the agent wrote, and the image
would come from a repository it never named. On a cold store the same
reference is `NotFound`, because the registry has no `library/node@D`.
Found at the review of PR #116.

So every agent pull that is not refused, exempted or under `Required`
alike, fetches the document the reference names (the index or manifest
`D`) from the named repository of the named registry, warm or cold. A
registry serves a manifest by digest only in a repository that holds it
(OCI distribution spec, "Pulling manifests"), so the answer is the
registry's own statement that `D` belongs there; a `404` is `NotFound`,
as on a cold store. What `D` names in turn (the platform manifest, the
config) is bound by its digest and comes from the store as before, and
so do the layers and, under `Required`, the kept signature evidence.
Under `Required` the hand-over would not have let an untrusted image
through, since the trust is checked against `D` whichever repository it
came from; the rule applies there too so that both agent lanes mean the
same thing by "the repository the agent named" and the requests do not
depend on what the operator pulled before.

**Cost and the warm-pull rule.** ADR-009 D8 and ADR-029 S6 promise that a
pull of an image already in the store makes no request. That stays true
for the operator's references. A warm agent pull now makes the requests
of fetching one manifest: on Docker Hub the unauthorized `GET`, the token
and the authorized `GET`, 3 requests of which 1 is a manifest request
(`exempted_agent_requests_unchanged`, which pins the lines;
`agent_ref_never_served_another_repositorys_digest`). A cold agent pull
makes exactly the requests it made before. Against Docker Hub's
anonymous limit of 100 manifest requests per hour (ADR-009), a warm agent
pull costs 1, the same as the first request of a cold pull. A warm agent
pull also needs the registry to answer: during a registry outage the
operator's cached images still pull and the agent's do not, which fails
closed.

**Rejected: provenance kept next to each document.** A record of the
(registry, repository) pairs each kept document was fetched from would
keep warm agent pulls at 0 requests. It would add a new on-disk record
in a store whose every file is under the sweep, eviction and lock rules
of ADR-009 D8, ADR-025 and ADR-030, written by concurrent stores, with
a cap needed because a popular digest lives in many repositories, and a
record would keep saying "yes" after the registry unlinked the digest
from the repository (a takedown). The one manifest request asks the
authority each time and adds no state.

### What the PR builds

- `boneli-app`: `ImageOrigin`, `ImageRef::origin`, `ImageExemption`,
  `Pulled`; `ImageStore::pull` returns `Result<Pulled, ImageError>`
  (breaking, pre-1.0, CHANGELOG).
- The contract (ADR-004) gains two clauses: `agent-origin-refused` (the
  operator's pull of the fixture's image passes, a fixture check, and the
  agent's pull of the same image is `Failed` with a detail) and
  `exemption-reported`, with the sub-checks `agent-pull` (the exemption
  comes back with both fields filled) and `operator-pull` (the operator's
  pull of the same image right after reports none). The origin is now a
  port promise, so a future adapter (#49) must keep it; ADR-029 added no
  clause because its policy was adapter configuration only.
  `digest-pinned` and `platform-pinned` also require the fixture's
  variants to share the present image's origin. Each clause case has a
  mutant in `boneli-replay-check`: the origin dropped, the exemption
  dropped, an exemption reported for an operator pull. The counts go from
  60 clauses and 76 mutant cases (ADR-023) to 62 and 79
  (`mutant_table_covers_every_clause`).
- `boneli-memory`: an agent pull fails unless an exemption names its image
  name, checked before the tamper check as the real adapter checks before
  any request.
- `boneli-oci`: `ExemptScope`, `AgentExemption` and its preset,
  `SignaturePolicy::with_agent_exemptions` and `decide`, `Decision`, the
  decision in `pull_pinned` before the client is built, the named
  document fetched from the named repository on every agent pull (S6), and
  `Lease::exemption`.

### Numbers

This ADR adds no limit. The counts below are derived from the code paths
and checked by the tests named:

- **A refused agent reference makes 0 requests** and 0 dials, whatever the
  registry has, because the decision comes before the client exists
  (`agent_unsigned_refused_without_any_request`, live in
  `signatures_on_docker_hub`: no connection).
- **A cold exempted agent pull makes exactly the requests of #7**, byte
  for byte, because `Exempted` takes the `Off` path of ADR-029; **a warm
  one makes 3** (S6), the first 3 lines of the cold pull's log
  (`exempted_agent_requests_unchanged` against the log recorded before
  ADR-029).
- **An unsigned agent reference under `Required` makes 4 signature
  requests and 0 layer requests on a registry that answers like Docker
  Hub**: per subject a `.sig` tag (404) and the referrers API (`[]`), and
  2 subjects for an index (the index and the platform manifest, ADR-029).
  The agent's request log equals the operator's
  (`agent_ref_under_required_rule_checked`).
- **No cap on the number of exemptions.** They are operator configuration,
  as the rules are, and a pull scans the list once.
- **The weekly `oci-acceptance` run keeps its 13 Docker Hub manifest, tag
  and referrers requests per architecture** (ADR-029's count): the agent
  pulls of `node` and `postgres` under the preset are cold, so they send
  exactly the operator pulls' requests, and the added agent refusal sends
  none.

### Why the global default stays `Off`

For operator references, `Off` remains the default. A `Required` default
refuses all 5 first-stack repositories measured above, so every operator
would start by writing `Off` rules to get the demo running, which would
then also be the habit for everything else. The operator's own references
are as trusted as the operator's configuration, and the agent's no longer
depend on the default (S2).

## Consequences

- The port changes: every `ImageRef` names its origin and every pull
  returns `Pulled`. Today this touches only tests; the first production
  caller (#14) is written against the new shape.
- An agent can no longer get an unsigned image from a repository the
  operator did not exempt. The cost: an operator who wants agent images
  from outside `library/` writes an exemption or a `Required` rule for
  them, in one line each.
- A warm agent pull makes one manifest request (S6) and needs the
  registry to answer; the operator's warm pulls stay at 0 requests.
- An operator who wants the same repository open on both lanes writes it
  twice, an `Off` rule (or nothing) for themselves and an exemption for
  the agent. This is the price of S3's separation.
- **Known limits**, each with where it closes:
  - Under the preset, all 181 repositories of `library/` and every digest
    ever pushed to them pass unsigned, old releases with known
    vulnerabilities included. Digest pinning still pins, but it pins
    whatever the agent chose. Narrowing it is the operator's choice (exact
    exemptions); which images the agent may use (a digest allowlist) is
    outside #105 by its scope, recorded here only.
  - Nothing in the type system stops a future use case from marking agent
    data `Operator`. The rule "set where the reference enters" is fixed
    here and in #14's body, and the reviewer runs on every `boneli-oci`
    change (always-review list).
  - `OciImageStore::lease(&RootfsRef)` is not checked against an origin: a
    handle names only a manifest digest, with no registry or repository to
    decide on. #14's body binds a sandbox to the `rootfs` of the `Pulled`
    it got for that reference.
  - The run-log record of an exemption is written by #14, not here (S5).
  - The policy's configuration file format, presets for other registries
    and private registries stay with #32, #33 and #55 (recorded here only).

## Alternatives considered

- **A global `Required` default.** Rejected: 0 of the 5 first-stack
  repositories carry a signature (measured above; `library/node` also in
  ADR-029), so it refuses the demo, and operators would answer with `Off`
  rules. It also protects the wrong lane: the risk #105 names is the
  agent's choice, which S2 closes without touching the operator's.
- **The origin as a parameter, `pull(&ImageRef, ImageOrigin)`.** Rejected:
  no taint at the source, each call site decides again (S1).
- **The origin inside `boneli-oci` only** (for example
  `pull_leased(&ImageRef, Origin)`). Rejected: the code that knows the
  origin is the use case that parsed the agent's proposal, and it talks to
  the port, not to the adapter.
- **A default agent trust**
  (`SignaturePolicy::agent_default(Requirement)`, a third lookup lane).
  Rejected: with today's measured signatures it admits none of the 5
  first-stack repositories, and a trust for agent images is already
  expressible as a `Required` rule, which also binds the operator's
  references there, only making them stricter.
- **`Off` rules as agent exemptions.** Rejected: an operator opening a
  repository for their own configuration would open it to the agent too
  (S3).
- **Registry-wide exemptions.** Rejected: the agent picks the namespace,
  so a registry-wide exemption is the hole #105 closes.
- **Exact `library/node` + `library/postgres` as the preset.** Rejected:
  covers 2 of 5 and refuses `redis`, used by all 3 candidate repositories
  (S4).
- **A `RunEvent::ImageExempted` now.** Rejected: domain, state machine and
  replay corpus changes for a step that does not exist (S5).

## Accept when

This PR's fake-registry tests pass (the origin section of
`crates/boneli-oci/tests/signatures.rs`, the contract on both adapters and
every mutant killed), and the `oci-acceptance` run on this PR passes
`network::node_and_postgres_run_in_sandbox`, which now pulls `node:22`
and `postgres:17` as agent references under the preset and checks the
reported exemption, and `network::signatures_on_docker_hub`, which now
also refuses the agent's `node:22` with no connection, on x86_64 and
arm64.

**Result (PR #116, 2026-11-24).** The fake-registry tests pass: 22 origin
tests in `crates/boneli-oci/tests/signatures.rs`, the contract with the
two new clauses on both adapters, and every mutant killed (the 3 contract
mutants and 17 hand mutants over `decide`, `with_agent_exemptions`,
`ExemptScope::parse`, `open`, the store wiring, the named document's
fetch and the memory adapter). Live on x86_64 (local run, before the
review fixes) and in the `oci-acceptance` run on the rebased head of
PR #116 (run 45366860253) on x86_64 and arm64: `node:22` and
`postgres:17` pull as agent references under the preset, each reporting
`docker.io` / `library/`, and run; with no exemption the agent's
`node:22` is refused with no connection; the checks of ADR-029 and
ADR-031 pass unchanged. The review of PR #116 found S3's `Off` shadowing
and the warm-cache hand-over that S6 closes, both fixed before this
result. An earlier run on the PR (45361409402) failed once on x86_64
before any check of this ADR, because Docker Hub redirected layer blobs
to `docker-images-prod.s3.dualstack.us-east-1.amazonaws.com`, a host
outside the redirect allowlist of ADR-009 D10, for the ADR-029
`chainguard/node` pull as for `node:22`; the rerun of that job passed.
