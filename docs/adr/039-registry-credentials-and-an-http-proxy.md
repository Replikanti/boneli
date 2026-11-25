# ADR-039: Registry credentials and an HTTP proxy

- Status: proposed
- Date: 2026-11-25

Issue #55, in two PRs. Part 1 (PR #135) added the proxy route in
`boneli-http` and `boneli-https`: `TlsConfig::with_proxy`, the tunnel in
`TlsDial`, revocation fetches through the proxy, and `BasicCredentials`.
Part 2 adds registry credentials to `boneli-oci` (`Registry::with_credentials`),
wires the proxy into `StoreConfig::production`, runs the acceptance
through Squid and accepts this ADR. The decisions for both parts are
recorded here.

## Context

ADR-009 pulls public images anonymously, straight from the runner over
`boneli-https`, from an explicit registry allowlist. It leaves two cases
open (ADR-009 D10 weak spot, Replikanti/boneli#55):

- A registry that needs credentials: a private repository on a public
  registry, a self-hosted registry (Harbor, GitLab, Nexus, Artifactory), a
  cloud provider's registry (ECR, Artifact Registry, ACR). Customer images
  live there.
- A customer network where outbound HTTPS must go through an HTTP proxy.
  `boneli-https` has no proxy support for any of its connections, so a
  runner in such a network can reach neither a registry nor the forge.

Planning found a third case hidden in the second. Every connection is
checked for revocation and fails closed (ADR-017, ADR-020, ADR-027). The
CRL, CA list and OCSP fetches connect on their own, directly. In a
network whose only way out is the proxy they fail, and so does every
connection to a registry with a public-CA certificate (Docker Hub, GHCR,
ECR) with `RevocationUnknown`. A proxy for registry requests alone would
not let one image through. ADR-017 noted it as a known limit ("When proxy
support lands, the `CrlSource` seam takes a proxy source"). The operator
decided at #55 STOP 1 that revocation fetches go through the proxy in
this issue (decision 1).

## Decision

### D1. Credentials

`boneli_https::BasicCredentials::new(username, password)` follows RFC
7617:

- the username is not empty and has no `:` (the first `:` of the decoded
  pair ends the username, so a `:` in it would move the split);
- the password is not empty; a `:` in it is allowed;
- neither holds a control character, U+0000 to U+001F, U+007F or U+0080
  to U+009F (`char::is_control`, the Unicode `Cc` category); other UTF-8
  is allowed and encoded as UTF-8 (RFC 7617, 2.1). A control character
  has no place in a password a person or a cloud API produces, and CR and
  LF would split a field line if a lower layer ever stopped checking;
- `username:password` is at most `MAX_BASIC_CREDENTIAL_BYTES` = 6,120
  bytes (D9).

An error names the rule, never the value. `header_value()` returns
`Basic <base64(username:password)>`; it is public because part 2 sends it
to a registry as `Authorization`, and documented as the secret itself.
`Debug` prints `BasicCredentials([redacted])`; there is no `Display`. The
base64 encoder is the one the OCSP GET path already uses, moved to its
own module (`base64.rs`); no crate is added.

Why `Basic` only, for registries and proxies alike: every registry the
runner targets accepts a username and a password, either at the API
(`Basic` challenge) or at its token endpoint (the Docker token flow), and
cloud tokens (ECR's `GetAuthorizationToken`, a GCP access token or
`_json_key_base64`, an ACR token) enter as a password.

### D2. Where credentials and tokens go

Part 2's rule, the one ADR-009 D10 applies to the anonymous token,
extended to credentials:

| host | may receive |
| --- | --- |
| the registry's API host and port | `Basic` after a `Basic` challenge, or the `Bearer` token |
| a configured token host and port | `Basic`, on the token request only |
| a redirect host (CDN, S3), another registry, the proxy | nothing |

When a server offers both `Bearer` and `Basic`, `Bearer` wins, so the
password goes to the token host and never to the API host. Credentials
belong to one `Registry` allowlist entry and follow it; registry A's
never go to registry B or to the default registry.

How part 2 holds the table, in `boneli-oci`'s registry client:

- **Nothing before the host's own challenge.** A client starts without
  an `Authorization` value. Only a `401` from the API host and port, on
  the connection to it, makes it authenticate; a `401` from a redirect
  host is that host's status and fails the fetch (`answered 401`), so a
  CDN or a party behind it cannot draw credentials to anyone.
- **`Basic` challenge:** with credentials, they are set for the API host
  and the request is retried once; a second `401` is `Failed`, "refused
  the configured credentials", never `NotFound` (the D11 rule of ADR-009
  that turns Docker Hub's second `401` into `NotFound` is for tokens).
  Without credentials it fails at once, naming the registry.
- **`Bearer` challenge:** the realm must be one of the registry's
  allowlisted token hosts and ports before anything is sent to it, as
  ADR-009 D10 has it; then the token request carries the credentials
  if and only if the registry has some. A `401` or `403` from the token
  host to a request with credentials is `Failed`, "refused the configured
  credentials", naming host, port and status. The token goes to the API
  host only; it expires mid-pull as before, one new token request per
  fetch, with the credentials again.
- **One writer.** The client's `send` writes `Authorization` from the
  value its caller passes and from nothing else; manifests, blobs,
  configs and the signature lookups (the `.sig` and `.att` tags, the
  referrers API and its tag fallback, signature blobs) pass the API
  value only when the URL is the API host and port, the token request
  passes the credentials, redirects pass nothing. So a fetch added later
  inherits the rule. The TUF refresh of ADR-033 does not use the
  registry client and carries no registry credentials; with a proxied
  `TlsConfig` its `TlsDial` goes through the proxy like any other.

### D3. The credential source (STOP 1 decision 2)

The API takes credential values. A composition root reads them from a
file under ADR-014 D6's file rules (absolute path, regular file, not a
symlink, owned by the runner's uid, no group or other permission bit,
`lstat` and `fstat` agree), never from an environment variable (every
child process inherits it), the command line (`/proc/<pid>/cmdline` is
world-readable) or the image reference (it ends up in events and logs).
The file format and its reader land with the runner (#33). Why not now:
no composition root or runner configuration exists yet, and a reader
written here would be a third copy of the D6 file rules, the duplication
ADR-021 removed for the store root. Weak spot: no binary can pull a
private image until #33 lands; no binary pulls any image today.

### D4. Keeping secrets out of logs, events, details, the run store and patches

- `boneli-http`, `boneli-https` and `boneli-oci` write no log lines.
- A pull's text reaches the app only as the `Failed` detail of
  `ImageError`; it is the only way it reaches events and the run store.
  Part 2 makes it carry hosts, ports, digests and statuses only, and a
  test drives every failure path through `OciImageStore::pull` against a
  hostile server that echoes `Authorization` into its headers, reason
  phrase and body, and scans every detail for every 16-byte window of the
  password, the username and `base64(user:pass)`, and for the token, as
  ADR-014's `failure_details_never_carry_secrets` does.
- `Error::Proxy` (part 1) names the proxy, the target and the status;
  `boneli-http`'s errors are fixed strings, so no field value reaches a
  message.
- `Debug` of `BasicCredentials`, `Proxy`, `TlsConfig`, `TlsDial`, and in
  part 2 `Registry` and `StoreConfig`, is redacted; a test scans each.
- An image name's userinfo (`user:pw@ghcr.io/x/y`) is refused as today,
  and part 2 stops echoing it in the detail: a name with `@` anywhere is
  refused before it is parsed further, everything up to its last `@`
  shown as `[userinfo]`. The same mask covers the hosts of
  `Registry::new` and `with_redirect_hosts` in their errors.
- Part 2 removes the places where a detail quoted the server's own text:
  a redirect's `Location` (only the fact that it was refused, and why,
  is named), a response's `Content-Type` (named, not quoted), and the
  name of a duplicated auth-parameter in `WWW-Authenticate`. What is
  left of server-chosen text are hosts: the realm host refused by the
  allowlist, a redirect host refused by it, and the names in a TLS
  error. A server that holds the credentials or a token can put them
  there, lowercase, into a host label (63 bytes, enough for most
  passwords and tokens).
- So every detail the registry client returns passes a redaction as the
  last step: `BasicCredentials::redact` replaces every run of
  `REDACT_WINDOW` = 16 bytes of the username, the password, the pair and
  its base64, and `boneli_https::redact` every such run of every token
  the client received, each stretch by `[redacted]` (a secret shorter
  than 16 bytes where it appears whole). The store applies it once more
  to the whole pull, the signature check included. Why 16: 16 bytes of
  base64 are 96 bits, so a run that long in a detail is the secret and
  not a host, digest or word by chance; a shorter window starts to hit
  ordinary text (a username like `AWS` already does, where it appears
  whole), a longer one lets a 16-byte piece through. It is the window of
  ADR-014's secret scans. A piece shorter than the window stays: a
  hostile registry that splits its own credentials into 15-byte pieces
  gets them into its detail, which leaks nothing it did not hold.
- Credentials never enter the sandbox or the workspace: the store hands
  out layer directories and configs only (invariant 5).

### D5. Why the proxy lives on `TlsConfig`

`TlsConfig::with_proxy(Proxy)` routes every connection the configuration
makes: `TlsDial`'s, and the CRL, CA list and OCSP fetches of its
revocation check. One setting gives one route, so a runner cannot be
configured to reach a registry through the proxy and its revocation
servers directly, which in a proxy-only network fails every connection
(Context). `TlsDial` with a proxy resolves the proxy's name only (the
configuration's resolver, ADR-022), connects to each of its addresses in
turn, sends `CONNECT host:port` (with `Proxy-Authorization` when
credentials are set) and runs `connect_over_until` over the tunnel: the
target's certificate and its revocation are checked exactly as on a
direct connection, and the target's name is never resolved locally, so a
split-horizon name that only the proxy can resolve works. A non-2xx
answer is `Error::Proxy` inside the `io::Error`; a proxy that answered,
whatever it answered, ends the dial, and only a failed TCP connect moves
to the next address. The tunnel runs under the request's deadline below
TLS (the `DeadlineSocket` of ADR-009 D10), each read and write also
bounded by `io_timeout`, so a proxy that accepts and never answers fails
at the deadline.

`boneli_https::connect` refuses a configuration with a proxy with
`InvalidInput`, before anything is resolved: connecting directly could
break the customer's egress policy, and a silent bypass is worse than an
error. No caller outside the crate uses `connect` today; `TlsDial` is the
route.

`with_proxy` and `with_resolver` both install `HttpSource`s over the
current resolver and proxy, so their order does not matter; a second
`with_proxy` replaces the first. Both replace a source set earlier with
`with_crl_source` or `with_ocsp_source` (call those after), as ADR-022
documents for `with_resolver`.

### D6. Revocation through the proxy

- `http` points and responders (all 65 CRL URLs measured for ADR-017,
  42 leaf lists and 23 CA lists, and every OCSP responder measured for
  ADR-020 are `http`) go as an
  absolute-form `GET http://host/path HTTP/1.1` to the proxy, with `Host`
  the point's (RFC 9112, 3.2.2) and no `Proxy-Authorization` until the
  proxy asks for it (D8).
  `boneli_http::Connection::new_via_proxy` is the only writer of the
  absolute form. This is a client-only exception to ADR-003 item 3: the
  server still refuses absolute and asterisk forms (its test
  `absolute_and_asterisk_form_rejected` is unchanged), and `request()`
  still takes origin-form targets only; the connection builds
  `http://<Host><target>` from them.
- `CONNECT` to port 80 is not used for `http` points: Squid's default
  configuration refuses it (`http_access deny CONNECT !SSL_ports`).
- `https` points use `CONNECT` and then TLS with the fetch configuration
  (no revocation check of its own, ADR-017 item 6); the request inside
  the tunnel carries `Host` only.
- A refused `CONNECT` is `CrlFetchError::Unreachable` whose text is
  `Error::Proxy`'s: the proxy, the target and the status. A `407` to a
  proxied `GET` is `Unreachable` too, naming the proxy: without a `Basic`
  challenge it says the `407` is not the proxy's own and was not retried,
  without credentials it says none are configured, and after the one
  retry with them it says the proxy refused them (D8). Any other non-200 answer to a
  proxied `GET` is `CrlFetchError::Status`, as on a direct fetch: the
  client cannot tell whether the proxy or the server behind it
  answered. Either way the check fails closed with `RevocationUnknown`
  naming the URL, so the operator knows which host to allow.
- A caching proxy is an on-path party, which ADR-017 already assumes for
  plain-HTTP fetches: it can withhold or replay a list, never forge one;
  the signature and `nextUpdate` checks hold, and a replayed old list is
  ADR-017's documented staleness.

### D7. Why this stays out of `boneli-egress`

- `boneli-egress` is the sandbox's broker: a server whose allowlist and
  connection log are the sandbox's evidence (ADR-006, ADR-009 D10,
  ADR-014 D11). This route is the runner's, a client of the customer's
  proxy; mixing the two would put runner traffic into the sandbox's
  evidence.
- An adapter cannot depend on a composition root (invariant 1).
- Chaining `boneli-egress`'s upstream through the customer's proxy is a
  separate follow-up; until then the sandbox has no network in such a
  customer network beyond what its brokers carry.

### D8. Configuration (STOP 1 decision 3)

- The proxy is set only explicitly, `Proxy::new(host, port)` and
  `TlsConfig::with_proxy`; `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` and
  `ALL_PROXY` are never read, because the sandbox's `HTTPS_PROXY` points
  at `boneli-egress`, and a runner process that inherited it would route
  itself through the sandbox's broker. The host is in ADR-003's grammar
  (lowercase LDH, canonical IPv4, IPv6 without brackets, no userinfo,
  port not 0); an error does not echo the host, which may hold userinfo.
- One proxy for every connection of a `TlsConfig`; no per-host routes.
- An HTTP proxy, reached in plain HTTP, with optional `Basic`
  credentials.
  - **`CONNECT`: sent up front** (`boneli_http::connect_tunnel_with`
    writes them after `Host`). The proxy consumes a `CONNECT` head and
    relays only the tunnel's bytes, so the field cannot reach the target,
    and sending it before a `407` saves a round trip per connection; the
    runner opens one connection per request (ADR-009 D10).
  - **Proxied `GET` (the `http` revocation fetches, D6): sent only after
    a `407`.** A forward proxy that did not authenticate the request
    itself may forward `Proxy-Authorization` to the server with the rest
    of the head: Apache httpd's `mod_proxy` unsets it only when it
    authenticated the user (`proxy_util.c`), so behind an IP access rule
    or as a parent proxy it passes the field on. The #55 part 1 review
    reproduced this with Apache 2.4.69: the CRL server received the
    runner's proxy credentials in cleartext. Squid drops the field toward
    servers. So the first `GET` carries no credentials; on the proxy's
    own `407` the fetch retries once, on a new connection under the same
    deadline, with `Proxy-Authorization`; a second such `407` fails
    closed with `Unreachable` ("refused the configured credentials"), and
    a `407` without configured credentials is not retried.
  - **Only the proxy's own `407` triggers the retry: one with a `Basic`
    challenge in `Proxy-Authenticate`.** A proxy that does not
    authenticate passes on whatever status the server answers, `407`
    included, and anyone on the plaintext leg between the proxy and the
    server can forge one. Retrying on such a `407` would send the
    credentials through the same proxy that forwards the field, to the
    server (the #55 part 1 review, run 2, reproduced it with Apache
    2.4.69 behind an open proxy and behind an IP-or-user rule). A proxy
    sends `Proxy-Authenticate` for its own challenge and does not pass a
    server's on (RFC 9110, 11.7.1: the field applies to the next
    inbound proxy only; Apache httpd strips it from a passed-on `407`,
    verified in the same review). So the retry needs a `Basic` challenge:
    the auth-scheme token compared case-insensitively, one of several
    challenges in one field or in several fields counts, commas in quoted
    strings do not split (`proxy::offers_basic`). A `407` without one
    fails closed with `Unreachable` ("without a Basic Proxy-Authenticate
    challenge … not retried with credentials"), so a server that answers
    `407` behind the proxy makes the fetch fail and gets no credentials.
    What "the proxy has consumed them" rests on is therefore the proxy's
    own challenge, not the status. Known limit: a non-conforming proxy
    that forwards a server's `Proxy-Authenticate` with its `407` and also
    forwards `Proxy-Authorization` to the server would still let a server
    or the plaintext leg behind it obtain the credentials; the client
    cannot tell that `407` from the proxy's own. The cure is a proxy that
    follows RFC 9110 or one that authenticates every request.
  - Cost: one more connection and round trip per revocation fetch through
    an authenticating proxy, at most once per list or answer per cache
    period (24 h, ADR-017 and ADR-020); D9 counts it in the setup time.
  - Weak spots: a proxy that requires NTLM or Kerberos is not supported,
    and a registry reachable only directly next to one reachable only
    through the proxy needs two stores until a `NO_PROXY` follow-up.

### D9. Limits and deadlines

- **`MAX_BASIC_CREDENTIAL_BYTES` 6,120.** nginx, the reverse proxy in
  front of Harbor and many self-hosted registries, reads request lines and
  field lines into `large_client_header_buffers`, default `4 8k`, and
  refuses a line longer than one buffer, 8,192 B. The longer of the two
  lines a credential produces is `Proxy-Authorization: Basic ` (27 B) +
  base64 + CRLF (2 B). Base64 of n bytes is 4 * ceil(n / 3) bytes, so
  27 + 4 * ceil(n / 3) + 2 <= 8,192 gives ceil(n / 3) <= 2,040 and
  n <= 6,120 (`basic_credential_cap_inclusive` checks the line at the cap
  fits). The largest common credential, Artifact Registry's
  `_json_key_base64` with a base64 service-account key as the password,
  is about 3.3 KB: worked out, not measured, from the documented key
  format with a fresh RSA-2048 key (1,704 B PEM) and 30-character project
  and account names, the longest Google allows, the JSON is 2,444 B, its
  base64 3,260 B and the pair 3,277 B, a 4,401-byte field line. Lower
  refuses that credential; higher admits credentials that nginx answers
  with `400`, a confusing registry error instead of a configuration
  error.
- **`PROXY_MAX_HEAD_BYTES` 16,384 and `PROXY_MAX_HEADERS` 64** for the
  answer to `CONNECT`: the same client code and the same values as the
  registry's response heads (ADR-009 D12) and the CRL heads (ADR-017),
  with this reason of their own: the answer is buffered whole before the
  tunnel's first byte, and a proxy is a single hop whose success answer
  is a status line, so the limit only has to leave room for a refusal's
  fields (`Proxy-Authenticate`, an error page's metadata, policy and
  tracing fields corporate proxies add). Not measured yet: part 2's CI
  step prints Squid's head for an accepted and a refused `CONNECT`, and
  the measurement goes here before this ADR is accepted. Lower risks
  refusing a proxy's refusal (the operator then sees a limit error
  instead of the status); higher only lets a proxy make the runner buffer
  more per connection.
- **Setup time through a proxy, `PROXIED_SETUP_TIMEOUT` 40 s** (part 2,
  `boneli-oci`). ADR-009 D12 derives a direct fetch's setup as connect
  (10 s) + handshake (10 s) + one round trip, about 21 s, and keeps 30 s,
  a 9 s margin. A proxy adds the wait for the `CONNECT` answer; in
  practice the proxy's own connect to the registry bounds it, and that
  connect goes through the same SYN retransmission schedule (1, 3 and
  7 s, 10 s). That makes about 31 s, plus the same 9 s margin: 40 s.
  Lower cuts a proxied connection off inside its own bounds; higher only
  lets a small fetch through a proxy hang longer. `StoreConfig::production`
  uses it when the `TlsConfig` has a proxy, 30 s otherwise.
- **Revocation constants stay as they are.** The bounds are ADR-017's:
  `CRL_CONNECT_TIMEOUT` 10 s per TCP connect, `CRL_IO_TIMEOUT` 10 s per
  read (the proxy's own connect to the server is seen as one read, so it
  is bounded by it), `CRL_HANDSHAKE_TIMEOUT` 10 s, and a round trip with
  the server's time, at most 0.211 s measured (rounded to 0.25 s here).
  Through a proxy:
  - `http` point, proxy without authentication: TCP to the proxy (10 s)
    + the proxy's upstream connect (10 s) + one round trip, about 20.3 s,
    inside `CRL_SETUP_TIME` (30 s).
  - `http` point, authenticating proxy (D8): the first attempt is TCP to
    the proxy (10 s) + the `407`, which the proxy answers itself (one
    round trip, 0.25 s); the retry is TCP again (10 s) + the upstream
    connect (10 s) + one round trip (0.25 s): about 30.5 s, 0.5 s over.
  - `https` point: TCP to the proxy (10 s) + the `CONNECT` answer, which
    waits for the upstream connect (10 s) + the handshake (10 s) + one
    round trip, about 30.3 s, 0.3 s over; credentials go up front, so no
    `407` round.
  What "over" means: `CRL_SETUP_TIME` is not a timeout of its own but the
  setup share of the check's deadline (`CRL_CHECK_DEADLINE` = 30 s +
  `MAX_CRL_BYTES` at `CRL_MIN_RATE`, 62 s; `CA_CRL_CHECK_DEADLINE` 38 s).
  A fetch that hits every bound leaves its body less than the 32 s
  budgeted, at most 0.5 s less: a list at the 32 MiB cap at exactly
  1 MiB/s would then miss the deadline, the largest measured list
  (11,005,110 B, 10.5 s at that rate) would not, and a fetch that hits
  none of the bounds is unaffected. Weak spot, accepted: raising
  `CRL_SETUP_TIME` to 31 s would lengthen every check's deadline, proxied
  or not, for a worst case that needs three 10 s bounds to be hit in one
  fetch. None of the measured points is `https` (ADR-017: 65 of 65 CRL
  URLs, CA lists included, `http`; ADR-020: every responder), so the
  `https` case is a customer CA's point.
- **OCSP through a proxy.** `OCSP_CHECK_DEADLINE` (31 s, ADR-020) is the
  sum of the bounds of a direct fetch: connect (10 s), TLS for an `https`
  responder (10 s), the response (10 s) and 1 s of body. A direct `http`
  responder uses 21 s of it. Through a proxy the response read also
  covers the proxy's upstream connect (one read, still bounded by 10 s):
  an `http` responder needs about 21 s without proxy authentication and
  about 31.3 s with it (TCP 10 s + the `407` 0.25 s + TCP 10 s + the
  response 10 s + 1 s), 0.3 s over; an `https` responder needs TCP
  (10 s) + the `CONNECT` answer (10 s) + TLS (10 s) + the response
  (10 s) + 1 s, about 41 s, 10 s over. Weak spot, accepted for the same
  reason: it takes every bound to be hit in one fetch, no measured
  responder is `https`, and a longer deadline would delay every failing
  OCSP check, proxied or not. A check cut short fails closed with
  `RevocationUnknown`, it never passes a certificate.

### D10. Tests and the live check

Part 1, local: `boneli-http` pins the exact bytes of
`connect_tunnel_with` and of the absolute form, and that owned fields,
control characters, CONNECT and non-origin targets are refused with
nothing written. `boneli-https`'s `tests/proxy.rs` runs `TlsDial` and
`connect_over` through a fake proxy on 127.0.0.1 that records every head
and tunnels to local rustls servers that record what they receive: the
trusted leaf passes, an untrusted one is refused behind a tunnel and
behind a proxy that terminates TLS itself, an invalid target and a past
deadline dial nothing, the target is never resolved, the proxy's
addresses are tried in turn, credentials appear on `CONNECT` and, only
after a `407`, on a proxied `GET` (against a fake proxy that asks for
them), refusals are `Error::Proxy` without secrets, the head limits
hold at their edge, a silent proxy fails at the deadline, the leaf's CRL,
an intermediate's CA list and an OCSP responder are fetched through the
proxy and a refused fetch fails closed, and the configuration order and
`connect`'s refusal hold. Unit tests cover the credential and host rules,
the RFC 7617 vector, the `https` point through a tunnel, redaction, and
the `407` rule of D8: no credentials on the first `GET`, the retry
carries them, a second `407` fails closed with no third try, a `407`
without credentials is not retried, a `407` with no challenge or only
non-`Basic` ones (`Negotiate`, `NTLM`) is not retried and sends no
credential, a `Basic` challenge among others in one or several fields is
retried once, a challenge-less `407` passed on after the retry is final,
and a `CONNECT` carries them up front and is not retried; the challenge
parser has its own cases (quoted commas, case, RFC 9110's example).
The live revocation tests (`tests/network.rs`, `ocsp::live`) still run
direct.

Part 2: `boneli-oci`'s `tests/credentials.rs` runs the store and the
client against a fake private registry in front of the fake Docker Hub
and checks every recorded request: the Basic flow (no credentials before
the challenge, one retry, a second `401` `Failed`, none configured
`Failed`), the token flow (credentials on the token request only, a
refusing token host, the realm on the API host as on GHCR, `Bearer`
over `Basic`, a token expiring on the last blob), host scoping over a
3-hop redirect chain in every flow, a redirect suffix that covers the
token host, a realm off the allowlist, registry A's credentials never at
the default registry, the redirect limit, a `401` from a redirect host;
the secret scans of D4 against a hostile registry that echoes the
secrets into reason phrases, fields, bodies, `Location`,
`WWW-Authenticate` and `Content-Type` in 46 hostile answers, through
`OciImageStore::pull` in both flows and through the client, lowercase secrets in realm and
redirect hosts, userinfo in image names, `Debug`; and the proxied setup
time. `tests/signatures.rs` pulls under `Required` rules with and
without claims in both flows and checks that every signature lookup
carries the API value and nothing goes elsewhere. `tests/proxy.rs` runs
the production `TlsDial` through a fake proxy to a local rustls registry
(the `localhost` leaf of `boneli-https`'s test data): a pull with proxy
and registry credentials each only where they belong, an untrusted
registry refused behind the proxy with nothing committed, and the proxy
refusing the CDN. That server is the one new dependency edge: `rustls`
as a dev-dependency of `boneli-oci`
(`[external.rustls.pulled-by.boneli-oci]`, approved here), with
`boneli-https`'s features, so no new crate; it is the edge ADR-009 had
for the `TlsDial` tests until ADR-014 D4 moved them to `boneli-https`
(#72).
And one live pull of `node:22` through Squid in `oci-acceptance`
(`proxy::node_pulls_through_the_proxy`, `BONELI_OCI_TEST_PROXY`), with
direct outbound 80 and 443 rejected for the runner user, and Squid's
access log checked for the `CONNECT` and an absolute-form CRL `GET`.

## Consequences

- A runner in a proxy-only network reaches registries, CRL, CA list and
  OCSP servers once a composition root passes a proxied `TlsConfig`
  (part 2 for the image store, #32/#33 for the binaries).
- A failure detail may show `[redacted]` where a host it names held a
  run of the credentials or of a token (D4), and a username shorter than
  16 bytes is taken out wherever it appears whole, also inside an
  unrelated word, so the operator sees less of the detail.
- `boneli_https` gains `redact` and `REDACT_WINDOW`, and
  `BasicCredentials::redact`, for any crate that builds text from what a
  server holding its secrets sent.
- A TLS-inspecting proxy works only once its CA is in the runner's
  `Roots`, and then it sees registry credentials and tokens: the end to
  end check is exactly what keeps an unconfigured inspecting proxy out.
- Proxy `Basic` credentials travel to the proxy in clear, as HTTP proxy
  authentication does; TLS to the proxy is not supported.
- The forge's REST calls go through the proxy once a composition root
  passes it a proxied `TlsConfig`, but `git push` (the host git binary,
  ADR-010) does not; GitHub Enterprise Server stays a follow-up
  (ADR-014 D11).
- `boneli-egress` does not use the proxy (D7).
- `boneli_https::connect` is unusable with a proxied configuration (D5).
- Kubernetes secret mounts (symlinked, root-owned files) do not pass
  ADR-014 D6's file rules, which matters for #33's reader.
- `boneli-http` writes the absolute form for one constructor; the server
  is unchanged (D6).

## Alternatives considered

- **A separate `ProxyDial` next to an unchanged `TlsConfig`.** Rejected:
  the fail-closed revocation check would still fetch CRLs and OCSP
  directly, and in a proxy-only network every registry with a public-CA
  certificate would fail with `RevocationUnknown` (Context).
- **The proxy in `boneli-egress`.** Rejected by D7: it is the sandbox's
  broker, and an adapter cannot depend on a composition root.
- **Proxy settings from the environment.** Rejected by D8: the sandbox's
  `HTTPS_PROXY` points at `boneli-egress`.
- **`CONNECT` to port 80 for `http` points.** Rejected: Squid's default
  configuration refuses it (D6).
- **Waiting for `407` before sending proxy credentials on `CONNECT`.**
  Rejected: one more round trip per connection for no gain, because a
  proxy consumes the `CONNECT` head and the field cannot reach the target.
- **Sending proxy credentials up front on a proxied `GET` too.**
  Rejected after review (D8): a proxy that does not authenticate the
  request may pass the field on to the server in cleartext, as Apache
  httpd's forward proxy does; the saved round trip is not worth the
  credentials.
- **NTLM, Negotiate, Digest, SOCKS, TLS to the proxy.** Out of scope:
  each needs a protocol implementation (NTLM and Negotiate need a GSSAPI
  or an NTLM crate, which ADR-001 would have to admit) and #55 asks for
  none of them.
- **A base64 crate.** Rejected: the crate already has a 20-line encoder
  for OCSP, now shared.
- **Reading credentials from a file now.** Rejected at STOP 1 (D3): it
  would duplicate the D6 file rules before a runner configuration
  exists.
- **Redacting only the whole secrets, or nothing beyond the fixed
  texts.** Rejected (D4): a server that holds the credentials chooses
  how much of them it echoes, so an exact match misses a part; and the
  hosts the detail must name for the operator (a refused realm or
  redirect host, the names of a TLS error) stay server text.

## Accept when

Part 2's tests are green and the Squid step of `oci-acceptance` has
passed once on the PR branch, with Squid's `CONNECT` heads recorded in
D9.
