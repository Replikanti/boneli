# ADR-035: Docker Hub's blob redirect hosts

- Status: accepted
- Date: 2026-11-24

Amends ADR-009 D10: the redirect rule gains a list of exact hosts, and
Docker Hub's list holds the S3 host it was measured to redirect blobs to.
Everything else in D10 holds.

## Context

ADR-009 D10 lets a blob request follow a redirect only to the registry's
API host or to a host strictly under one of its redirect suffixes, on port
443. Docker Hub's only suffix is `.docker.com`, measured on 2026-11-16:
every blob redirect went to `production.cloudfront.docker.com`.

Issue #117: Docker Hub sometimes redirects a blob request to
`docker-images-prod.s3.dualstack.us-east-1.amazonaws.com` instead, and the
pull fails closed with `redirect to
docker-images-prod.s3.dualstack.us-east-1.amazonaws.com:443 is not on the
allowlist`. Logged twice, both on the x86_64 job of `oci-acceptance` on
GitHub-hosted runners:

- run 45210635062 (2026-11-23 15:55 UTC), the `library/node` blob
  `sha256:cb7c8430…36dd456`;
- attempt 1 of run 45361409402 (2026-11-24 09:03 UTC, on PR #116), the
  same blob and the `chainguard/node` blob `sha256:a4e4a9b8…`; the rerun
  passed.

The 13 other finished `oci-acceptance` runs since 2026-11-24 02:55 UTC and
the dispatch of 2026-11-20 passed, and any S3 redirect fails a run, so
they saw none: 2 of 16 x86_64 attempts, 0 of the arm64 ones.

Measured from outside CI on 2026-11-24, 16:12 to 16:30 UTC, from a
residential connection in the EU: an anonymous token from
`auth.docker.io`, the `latest` index of 22 repositories (the 20 `library/`
repositories with the most pulls: nginx, memcached, busybox, postgres,
alpine, redis, ubuntu, python, node, mysql, mongo, httpd, rabbitmq,
traefik, hello-world, mariadb, golang, debian, ruby, php; plus
`chainguard/node` and `grafana/grafana`), their linux/amd64 and
linux/arm64 manifests (24 images), the config and every layer: 191
distinct blobs, each requested 3 times at
`registry-1.docker.io/v2/<repo>/blobs/<digest>` without following the
redirect. 573 requests, 573 `307` to `production.cloudfront.docker.com`,
none to an `amazonaws.com` host. The blob that failed in CI went to
CloudFront 3 times of 3. Docker's firewall allowlist page names
`registry-1.docker.io` and `production.cloudfront.docker.com` and no S3
bucket: the S3 host is undocumented behavior that depends on where (or
when) the client asks.

**From the runners** (the measurement this ADR rests on): a temporary
workflow on PR #119 ran the same method with `curl` and `jq` on both
GitHub-hosted runner architectures, `ubuntu-latest` (x86_64) and
`ubuntu-24.04-arm` (arm64): the 22 repositories, both platforms, every
config and layer blob, the first hop only, 3 rounds 10 minutes apart per
job, and the first run again 6 hours later (its attempt 2). Each job made 66
manifest requests (22 indexes, 44 manifests) and found 327 distinct
blobs, counted per repository and digest (the local measurement above
counted 191 on the same day; how it deduplicated is not recorded), so a
round is 327 requests and a run 981 per architecture.

| Run | Time (UTC) | x86_64 | arm64 |
|-----|------------|--------|-------|
| 45440408062 | 2026-11-24 16:44-17:06 | 981 to CloudFront, 0 to S3 | 981 to CloudFront, 0 to S3 |
| 45448071309 | 2026-11-24 17:24-17:46 | 981 to CloudFront, 0 to S3 | 981 to CloudFront, 0 to S3 |
| 45448490888 | 2026-11-24 17:26-17:48 | 981 to CloudFront, 0 to S3 | 981 to CloudFront, 0 to S3 |
| 45473258310 | 2026-11-24 19:44-20:07 | 981 to CloudFront, 0 to S3 | 981 to CloudFront, 0 to S3 |
| 45440408062, attempt 2 | 2026-11-24 22:45-23:09 | 981 to CloudFront, 0 to S3 | 981 to CloudFront, 0 to S3 |

Every first-hop answer was `307`. The first CloudFront hit of each of the
10 jobs answered `Range: bytes=0-0` with `206` and no further redirect. In
all, 4,905 requests per architecture over 5 runs between 16:44 and 23:09
UTC, 9,810 in total, and none went to an S3 host.

**Reading.** If the S3 redirect were a steady per-request rate of about
0.9 % (D4), a single run of 981 requests would have shown none with
probability `0.991^981` = 0.00014. Five runs showed none on either
architecture, so the redirect is not a steady rate: it comes in episodes
(a time window, a CloudFront failover) or depends on something about the
request that neither measurement reproduced. One such difference is
known: `curl` sends a `User-Agent` and the client sends none; the blob
that failed in CI, requested from the residential connection without a
`User-Agent`, still went to CloudFront 3 times of 3 (2026-11-24). Its
only evidence remains the two logged failures, and the admitted set is
the one host they name.

The S3 host's certificate is `CN=s3.amazonaws.com`, issued by
`Amazon RSA 2048 M01`, with `*.s3.dualstack.us-east-1.amazonaws.com` among
its names: every bucket in the region shares it, so TLS proves "an S3
endpoint in us-east-1", never "Docker's bucket". Only the host name tells
Docker's bucket from anyone else's.

## Decision

### D1. Docker Hub's redirect set

`Registry::docker_hub()` admits blob redirects to hosts under the suffix
`.docker.com` (ADR-009 D10, unchanged) and to exactly these hosts:

| Host | Seen | Where |
|------|------|-------|
| `docker-images-prod.s3.dualstack.us-east-1.amazonaws.com` | 3 blob requests in 2 of 16 `oci-acceptance` attempts (runs 45210635062 and 45361409402); 0 of 9,810 measured requests | GitHub-hosted x86_64 runners |

The admitted set is exactly the set Docker Hub was seen to use: the one
S3 host both logged failures name, and no other. A host no run showed is
not added by guess, not even another region or endpoint form of the same
bucket.

### D2. Matching

An exact host matches when the redirect URL's host equals it and the port
is 443, after the URL parser of ADR-009 D10 has lowercased the host and
refused userinfo, IP literals and names outside the grammar of ADR-003.
Equality, not `ends_with`: `x.<host>`, `evil<host>` and
`<host>.evil.example` are refused, and so are another port, a trailing
dot and `http`. A path-style URL (`s3.dualstack.us-east-1.amazonaws.com/
docker-images-prod/...`) is refused too: the bucket sits in the path
there, and the host admits every bucket.

The exact list is set by `Registry::with_redirect_hosts`, which takes each
entry in the canonical form only: lowercase, no port, no IP address, no
leading `.` (that is a suffix, the other list). A non-canonical entry is
`Error::InvalidRegistry` rather than silently normalized, so the list in
the code reads as the hosts it admits. `Registry::new` keeps its signature
and builds a registry with no exact hosts.

Unchanged from D10: `Authorization` goes to the API host and port only, so
the S3 host never sees the token; the blob is checked against its
descriptor's size and digest before it is renamed into place; the 10
redirect limit counts every hop over every host.

### D3. Why exact hosts, not a suffix

The integrity of a blob never depends on the allowlist: the digest check
holds whatever host serves it. The allowlist bounds where the runner
connects, and that matters on its own:

- **`.amazonaws.com`** admits every S3 bucket and every AWS service
  endpoint. Anyone with an AWS account can create a bucket whose host is
  under it, so a redirect from a compromised or spoofed registry response
  path would send the runner to an endpoint an attacker controls: a beacon
  of the runner's address and pull timing, up to `max_blob_bytes` (4 GiB,
  ADR-009 D12) of wasted transfer per blob, and a way to make the runner
  probe AWS hosts.
- **`.s3.dualstack.us-east-1.amazonaws.com`** narrows the region but not
  the bucket: any bucket in us-east-1 matches, and the certificate cannot
  tell them apart (Context).
- **The bucket's exact host** is the one name only Docker controls.

### D4. Numbers

- **Sample size.** 2 failures in 16 x86_64 attempts, about 16 blob
  requests each, is about 0.9 % of requests if they are independent
  (`1 - 0.875^(1/16)`). 500 requests see at least one S3 redirect with
  probability `1 - 0.991^500` = 99 %, so the measurement was sized for at
  least 500 per architecture and run. A run made 981 (3 rounds of 327): at
  0.9 % it sees one with probability 99.99 %, and two runs (1,962
  requests) still see a rate 3 times lower (0.3 %) with 99.7 %; five runs
  made 4,905. Fewer would risk a clean
  sample that proves nothing; more costs only runner time, which is free
  for a public repository. The clean runs refute the independence
  assumption itself (Context, Reading), which is the finding: the rate is
  not steady.
- **Docker Hub's anonymous limit.** 100 manifest requests per hour per
  address (ADR-029). The measurement makes at most 66 per job (22 indexes,
  44 manifests); blob requests do not count. Each job runs on its own
  runner and address.
- **Revocation.** `TlsDial` runs the revocation checks of ADR-017, 020 and
  027 on every host, so an admitted host that fails closed there would be
  a dead entry. The leaf names
  `http://crl.r2m01.amazontrust.com/r2m01.crl`: 1,835,073 bytes, 42,056
  entries, nextUpdate 2026-12-01, under the 32 MiB cap per CRL of ADR-017
  (a list 18 times larger would fail every connection to the host closed).
  The intermediate's list `http://crl.rootca1.amazontrust.com/rootca1.crl`
  is 969 bytes, under the 1 MiB cap per CA list of ADR-027. Measured
  2026-11-24; `registry-1.docker.io` already uses the same Amazon chain
  and lists. `intermediates_checked_live` in
  `crates/boneli-https/tests/network.rs` now connects to the S3 host and
  passed: leaf `Checked` by the r2m01 list, intermediate `Checked` by the
  rootca1 list.

## Consequences

- Docker Hub pulls from GitHub-hosted runners no longer fail when a blob
  is redirected to the S3 host.
- A second S3 host, region or endpoint form fails closed, with the host
  named in the error. Admitting it is a new ADR (accepted ADRs are not
  edited), with its own measurement.
- Docker documents none of this, so a change on its side shows up first as
  a failed weekly `oci-acceptance` run. There is no standing measurement:
  the temporary workflow is removed before this PR merges, and the weekly
  acceptance fails closed and names the host.
- Each further registry with an undocumented redirect target needs the
  same kind of measurement; the exact list is per registry
  (`redirect_s3_host_only_for_docker_hub`).

## Alternatives considered

- **The suffix `.amazonaws.com`.** Rejected: any bucket or AWS service host
  (D3).
- **A regional suffix (`.s3.dualstack.us-east-1.amazonaws.com`).**
  Rejected: any bucket in the region, and the shared wildcard certificate
  cannot narrow it (D3).
- **A pattern such as `docker-images-prod.s3.*.amazonaws.com`.** Rejected:
  a new matching type for regions nobody has measured.
- **Retry the blob until Docker Hub answers with CloudFront.**
  Rejected: nondeterministic; at about 1 % per request it compounds over
  16 blobs per pull, and it hides the host instead of deciding on it.
- **No allowlist for blob redirects.** Rejected: it drops ADR-009 D10.
- **A 5th parameter of `Registry::new`.** Rejected: it touches every call
  site for one registry's list. **An entry without a leading `.` in the
  suffix list means exact.** Rejected: one list with two meanings is easy
  to misread in review.

## Accept when

The runner measurement is recorded in Context and D1, the fake-registry
tests in `crates/boneli-oci/tests/registry.rs` pass
(`redirect_to_the_s3_host_succeeds`, `redirect_exact_host_refusals`,
`redirect_s3_host_only_for_docker_hub`, `redirect_hosts_grammar`,
`s3_tampered_blob_never_cached`, `redirect_chain_cloudfront_then_s3`), and
`intermediates_checked_live` passes with the S3 host.

**Result (PR #119, 2026-11-24).** The runner measurement is recorded: 5
runs, 9,810 first-hop requests, all to CloudFront (Context). The 6
fake-registry tests pass, with the existing
`redirect_suffix_dot_boundary`, `redirect_limit_10_ok_11_refused` and
`authorization_only_to_registry_host` unchanged, and 6 hand mutants of
`redirect_allowed` and `with_redirect_hosts` are killed: equality turned
into `ends_with`, and each of the leading `.`, port, IPv6, IPv4 and
lowercase checks removed (`redirect_hosts_grammar` checks the reason each
refusal names). `intermediates_checked_live` passes with the S3 host.
`oci-acceptance` passed on x86_64 and arm64 on this PR (runs 45448071359
and 45473258117); no S3 redirect occurred in them, so criterion 3 of #117
rests on the fake-registry tests.
