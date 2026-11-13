# ADR-006: The egress proxy: exact allowlist, global addresses and a write-ahead connection log

- Status: accepted
- Date: 2026-11-13

## Context

`docs/ARCHITECTURE.md` ("LLM access and egress") gives the sandbox one way
out in the prepare phase and, in the MVP, in the agent phase: an HTTP
CONNECT proxy behind a Unix socket, without MITM, with an allowlist and a
log of every connection. In the prepare phase the list holds package
registries (npm, PyPI). In the MVP agent phase it holds only
`api.anthropic.com`, because Claude Code runs on a subscription token
inside the sandbox. ARCHITECTURE ("Code architecture") gives the proxy its
own small hexagon: a pure policy and ports to the outside. Issue #10 builds
it as the composition root `boneli-egress`.

The proxy is the process that parses bytes from the sandbox and opens
connections for it. A bug in it is a security bug: a bypass of the list
reaches the internet, the host's loopback services or a cloud metadata
endpoint, and a gap in the log hides what the sandbox did.

What already exists:

- `boneli-http` (ADR-003) parses a CONNECT head before any handler runs. It
  rejects absolute-form targets, non-ASCII targets, hosts that `inet_aton`
  would read as IPv4 (`127.1`, `0x7f.1`), names with an empty label (a
  trailing dot), a `Host` that names another host or port than the target,
  and CONNECT with `Content-Length` or `Transfer-Encoding`. It lowercases
  names. A `Host` without a port is accepted, because undici sends one.
- `serve` drops each connection's result, and a handler never sees a head
  the server rejected. So `serve` alone cannot log every connection.
- ADR-003 (item 9) makes the socket path the run's identity: one server
  per run.

Resolving the MVP hosts from one resolver while planning (2026-11-13):
`registry.npmjs.org` gave 12 A and 12 AAAA records (104.16.0.0/16,
2606:4700::/32), `pypi.org` and `files.pythonhosted.org` 4 and 4 each
(151.101.0.0/16, 2a04:4e42::/32), and `api.anthropic.com` 1 and 1
(160.79.104.10, 2607:6bc0::10). All of them are global under D4.

Issue #10 is delivered in two pull requests. This ADR covers both. Part 1
adds the pure policy (the allowlist, the address classes, the connect order
and budget, and the log codec), `boneli_http::Target::parse_authority`,
and this ADR. Part 2 adds the I/O: `boneli_http::accept_loop`, the relay,
the server and the binary. The decision tables, where Unicode and boundary
bypasses hide, get their own review round, apart from the concurrency code,
where hangs and leaks hide.

## Decision

### D1. One process per run phase

- Invocation: `boneli-egress --socket <path> --allow <host:port>
  [--allow <host:port> ...]`. Only the `--flag value` form is accepted:
  `--flag=value`, an unknown flag, a repeated `--socket`, a missing value
  and a `--allow` value that is not UTF-8 are usage errors. The socket path
  is used as given, with no `~` expansion.
- Exit codes: 2 for a usage error, including an allowlist that does not
  parse (D2); 1 when binding or accepting fails (message on stderr); 3
  when the log cannot be written (D8).
- Startup order: bind, write the `start` record, accept. The egress never
  unlinks or replaces an existing path: binding fails on an existing file
  and on a symlink (`EADDRINUSE`), and that is exit 1. A proxy that
  removed what it found at its path could be pointed at any file the
  runner can delete.
- The binary has no built-in lists; the runner passes the list of each
  phase. The MVP lists, as guidance for the runner (#32):
  - prepare: `registry.npmjs.org:443`, `pypi.org:443`,
    `files.pythonhosted.org:443`;
  - MVP agent phase: `api.anthropic.com:443`.
- **Why one process per phase:** a crash or fd exhaustion hits one run, and
  `serve` has no shutdown API (ADR-003, Consequences), so the runner ends a
  phase by ending the process. Rejected: one process for many runs, which
  needs a shutdown API and shares the fd table and thread budget across
  runs.

### D2. The allowlist is exact canonical `host:port` pairs

- Entries are parsed by `boneli_http::Target::parse_authority`, the same
  function that parses a CONNECT target (ADR-003, item 3). An entry and a
  target therefore canonicalize identically: lowercase host, numeric port,
  so `REGISTRY.NPMJS.ORG:0443` is `registry.npmjs.org:443`. A test renders
  every accepted entry into a CONNECT head, parses it with the server's
  parser and compares the targets.
- Startup errors (exit 2): an empty list, an entry outside the grammar, an
  IP literal (IPv4 or IPv6), and an entry equal to an earlier one after
  canonicalization. Errors name the entry by index and never repeat its
  bytes.
- Matching is equality of `(host, port)`. There are no wildcards and no
  suffix match.
- Rejected:
  - `*.example` patterns and suffix matching, the classic bypass surface
    (`registry.npmjs.org.evil.example`, `evil.registry.npmjs.org`).
  - IP entries. No MVP host needs one, and an IP entry skips the address
    check by name that D4 does.
  - Trimming or repairing entries. ADR-003 never repairs input, and an
    entry with a stray space or newline is a bug in whatever built it.

### D3. A refused name is never resolved

The allowlist decides before any DNS query. Otherwise `CONNECT
<data>.attacker.example:443` would carry data out through the resolver
even though the CONNECT is refused.

### D4. Only global addresses

- The egress resolves an allowed name once (`ToSocketAddrs`, which is
  `getaddrinfo` in std) and checks every address in the answer.
- If **any** address is forbidden, the request is refused with 403 and
  `failed reason=forbidden-address`. A public registry name that resolves
  to loopback or metadata space signals a hostile or broken resolver, and
  the rest of the same answer is not trusted either. Rejected: skipping
  the forbidden addresses and connecting to the others.
- The egress connects only to the checked addresses. There is no second
  resolution, so there is no DNS rebinding window between check and use.
- Sources, retrieved 2026-11-13: the IANA IPv4 Special-Purpose Address
  Registry and the IANA IPv6 Special-Purpose Address Registry (both last
  updated 2025-10-09), and the IANA IPv4 Address Space Registry (last
  updated 2025-10-10) for multicast and reserved space. Both tables below
  were checked row by row against them.
- **IPv4, forbidden:** every block of the special-purpose registry that is
  not globally reachable, plus multicast and the reserved space above it:

  | Block | Registry entry |
  |---|---|
  | `0.0.0.0/8` | "This network" (RFC 791), with "this host" `0.0.0.0/32` |
  | `10.0.0.0/8` | Private-Use (RFC 1918) |
  | `100.64.0.0/10` | Shared Address Space (RFC 6598) |
  | `127.0.0.0/8` | Loopback (RFC 1122) |
  | `169.254.0.0/16` | Link Local (RFC 3927), with the metadata address `169.254.169.254` |
  | `172.16.0.0/12` | Private-Use (RFC 1918) |
  | `192.0.0.0/24` | IETF Protocol Assignments (RFC 6890) and all its sub-entries |
  | `192.0.2.0/24` | Documentation, TEST-NET-1 (RFC 5737) |
  | `192.88.99.0/24` | Deprecated 6to4 Relay Anycast (RFC 7526), with `192.88.99.2/32` |
  | `192.168.0.0/16` | Private-Use (RFC 1918) |
  | `198.18.0.0/15` | Benchmarking (RFC 2544) |
  | `198.51.100.0/24` | Documentation, TEST-NET-2 (RFC 5737) |
  | `203.0.113.0/24` | Documentation, TEST-NET-3 (RFC 5737) |
  | `224.0.0.0/4` | Multicast (RFC 5771), from the address space registry |
  | `240.0.0.0/4` | Reserved (RFC 1112), with Limited Broadcast `255.255.255.255/32` |

  `192.0.0.0/24` holds two globally reachable anycast addresses
  (`192.0.0.9` and `192.0.0.10`, PCP and TURN). Forbidding the whole /24
  costs nothing, because no registry is served from them, and keeps the
  table to whole registry rows. The three globally reachable blocks of the
  registry (`192.31.196.0/24` and `192.175.48.0/24` for AS112,
  `192.52.193.0/24` for AMT) stay allowed.
- **IPv6:** an address is allowed only inside global unicast `2000::/3`
  (RFC 4291) and outside these blocks of the special-purpose registry:

  | Block | Registry entry |
  |---|---|
  | `2001::/23` | IETF Protocol Assignments (RFC 2928), with Teredo `2001::/32` |
  | `2001:db8::/32` | Documentation (RFC 3849) |
  | `2002::/16` | 6to4 (RFC 3056) |
  | `3fff::/20` | Documentation (RFC 9637) |

  - Everything outside `2000::/3` is forbidden. That covers every
    remaining entry of the registry: `::/128`, `::1/128`, IPv4-mapped
    `::ffff:0:0/96`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`,
    discard-only `100::/64` and the dummy prefix `100:0:0:1::/64`, SRv6
    `5f00::/16`, unique local `fc00::/7` and link-local `fe80::/10`, plus
    multicast `ff00::/8`.
  - `2001::/23` is forbidden whole, although some of its sub-entries are
    globally reachable (anycast addresses, AMT, AS112, ORCHIDv2, DETs).
    No registry is served from them, and Teredo and the benchmarking block
    inside it are not global. `2620:4f:8000::/48` (AS112, globally
    reachable) stays allowed.
  - 6to4 (`2002::/16`) is forbidden because the IPv4 address it embeds
    would need its own check; no MVP host publishes one.
  - IPv4-mapped addresses are refused outright instead of classifying the
    embedded IPv4 address. No registry publishes them, and they are the
    usual AAAA bypass of an IPv4 check.
- Consequences: private and shared ranges have no override, so a private
  or customer-network registry cannot be reached (an opt-in needs a later
  ADR; decided at STOP 1 of #10). IPv6-only hosts behind NAT64 cannot
  connect.

### D5. Connect order and budget

- **Order:** families alternate, starting with the family of the
  resolver's first address, and each family keeps the resolver's order
  (RFC 8305, section 4, with a "First Address Family Count" of 1). When one
  family runs out, the rest of the other follows. The attempts are
  sequential, not raced: a Happy Eyeballs race needs a thread or
  non-blocking connects per attempt, and the order alone already bounds
  what a dead family costs (one attempt per switch).
- **Per attempt: `min(10 s, remaining)`. Total: 30 s.** No further
  attempt is made once the remaining budget is zero (std rejects a zero
  connect timeout).
  - Why 10 s: before its first RTT sample a sender sets its retransmission
    timeout to 1 s (RFC 6298, section 2.1) and doubles it on every
    retransmission (section 5.5), so Linux sends SYNs at 0, 1, 3 and 7 s.
    A 10 s attempt survives three lost SYNs when the fourth gets through
    with an RTT under 3 s. Below about 3 s, two lost SYNs fail an
    attempt; above 10 s, a blackholed address holds the connection longer
    without a fifth SYN (due at 15 s) to show for it. Without any
    timeout, Linux gives up after `tcp_syn_retries` = 6 retransmissions,
    about 127 s (tcp(7)).
  - Why 30 s: three fully blackholed attempts. With alternating families,
    a dead family costs one attempt before the other is tried, so 30 s
    covers a dead family plus one more failure. Without a total, npm's 24
    addresses at 10 s each would hold the connection for 240 s.
- Outcome: 504 (`failed reason=connect-timeout`) when the budget ran out
  on a timeout, otherwise 502 (`failed reason=connect`).
- `TCP_NODELAY` is set on the upstream socket. The relay forwards whole
  reads already, and Nagle together with delayed ACKs can add tens of ms
  to every small server-sent event.

### D6. Answers

- 403 for a name not on the list and for a forbidden address. The status is
  the same on purpose: the sandbox cannot tell them apart and so cannot use
  the egress to probe the DNS answers of allowed names.
- 502 for a resolution error, an empty resolution or a refused connect; 504
  when the connect budget runs out.
- 405 with `Allow: CONNECT` for any other method.
- Every refusal has an empty body and ends the connection
  (`Exchange::close_after`; a refused CONNECT closes anyway, ADR-003 item
  11), so a pipelined second request is never served.
- `200` is sent, through `accept_tunnel`, only after the upstream connect
  succeeded and the `open` record was written.

### D7. Relay

- Bytes that arrived with the CONNECT head (`Tunnel::into_parts`) go
  upstream first and count as upload.
- Two directions, one extra thread (`thread::Builder::spawn_scoped`). A
  failed spawn ends the tunnel with `end=error`, without a panic.
- Half-close: the end of one side's stream becomes `shutdown(Write)` on the
  other, and the tunnel ends when both directions are done.
- **Buffer: 16 KiB**, the largest TLS plaintext fragment, 2^14 bytes (RFC
  8446, section 5.1). On the wire a protected record carries up to 2^14 +
  256 bytes, so a full record takes two reads and a typical one takes one;
  correctness does not depend on the size. Memory: 2 directions × 16 KiB ×
  64 connections (D9) = 2 MiB. A smaller buffer costs more system calls
  per MB of a registry download; a larger one costs memory per connection
  without fewer reads, since a read returns at most what the peer has sent.
- **Idle timeout: 660 s, shared by both directions.** Each read waits for
  the rest of the idle window. A direction whose read times out while the
  other direction moved bytes within the window waits again, so a long
  download with a silent upload stays open. The write timeouts on both
  sockets are 660 s too.
  - Where 660 s comes from: the Anthropic SDKs time out a request after 10
    minutes by default (TypeScript SDK `DEFAULT_TIMEOUT = 600000` ms in
    `src/client.ts`, Python SDK `DEFAULT_TIMEOUT` of `10 * 60` s in
    `src/anthropic/_constants.py`, both on their `main` branches), and
    Claude Code documents `API_TIMEOUT_MS` with a default of 600000 ms for
    each request attempt to receive its response headers (Claude Code
    environment variable reference). Retrieved 2026-11-13. 600 s plus 60 s
    lets the client's own timeout fire first, so a slow request ends with
    the client's error, not a cut tunnel.
  - Shorter would cut a request the client still waits for. Longer only
    keeps a dead tunnel's slot longer, inside its own run's cap, and the
    process ends with the phase anyway.
  - Claude Code's timeout does not cover a streaming response once its
    headers have arrived. A stream that is silent for 660 s is cut with
    `end=idle`; how often the API sends keep-alive events in a stream is
    not documented, so this is a residual, not a verified bound.
- No byte cap. An npm install moves hundreds of MB. Both directions'
  byte counts are logged (`up`, `down`).

### D8. Connection log: stdout, line records, write-ahead

- One record per line, `<kind> key=value ...`, with a fixed field order
  per kind:

  | kind | fields, in this order |
  |---|---|
  | `start` | `t=<u64> v=1 unix_ms=<u64> allow=<host:port>(,<host:port>)*` (canonical, sorted) |
  | `allowed` | `t=<u64> id=<u64> host=<host> port=<1..65535>` |
  | `refused` | `t=<u64> id=<u64> host=<host> port=<1..65535>` (403) |
  | `open` | `t=<u64> id=<u64> addr=<socket-addr>` |
  | `failed` | `t=<u64> id=<u64> reason=<forbidden-address\|resolve\|connect\|connect-timeout> addr=<socket-addr\|->` |
  | `close` | `t=<u64> id=<u64> up=<u64> down=<u64> end=<eof\|idle\|error>` |
  | `method` | `t=<u64> id=<u64>` (405) |
  | `rejected` | `t=<u64> id=<u64> status=<400\|408\|413\|417\|431\|501\|505>` |
  | `aborted` | `t=<u64> id=<u64>` (the stream ended or failed before a complete head) |
  | `no-request` | `t=<u64> id=<u64>` (closed or idle before the first byte) |

  - `addr` of `failed` is the first forbidden address, or the last address
    tried, or `-` after a failed resolution.
  - `t` is milliseconds from the `Clock` port, a monotonic origin at
    egress start; `start` anchors it to `unix_ms`. Records with the same
    `t` keep their line order; a reader never sorts by `t`.
  - `id` is a per-process counter from 1.
  - Numbers are decimal, with no sign and no leading zero. `host` is the
    target's host as the CONNECT grammar canonicalizes it, IPv6 without
    brackets. The grammar lowercases an IPv6 host but keeps its spelling,
    so a refused `[2606:4700:0::1]` is logged as `2606:4700:0::1`.
  - `rejected` statuses are exactly those `boneli_http::Error::status`
    gives a request the server rejects (ADR-003).
- **A closed alphabet, no escaping.** Every value is a host that passed the
  CONNECT grammar, a decimal number, a `SocketAddr` in its `Display` form
  or a fixed word, so no value can contain a space, `=`, a comma or a line
  break. The parser is strict: exact field order, no unknown, missing or
  repeated keys, single spaces, canonical numbers, `v=1` only, and hosts
  re-checked through `Target::parse_authority`. A line parses only if
  rendering the record gives the same bytes back, so every record has one
  spelling. A log whose last line has no newline was cut off mid-write,
  and the parser reports that line.
- **Ordering (write-ahead):** a decision record is written before its
  effect. `allowed` comes before any DNS query, `open` before the `200`,
  `refused` and `method` before the answer. Every connection ends with
  exactly one terminal record (`refused`, `failed`, `close`, `method`,
  `rejected`, `aborted` or `no-request`), and every `open` gets a `close`,
  also when `accept_tunnel` fails (`up=0 down=0 end=error`). An `open`
  without a `close` in a stored log means the process was killed.
- **No log, no egress.** When appending a record fails:
  - the current connection gets no answer and no effect: no resolution,
    no upstream, no `200`;
  - an upstream that is already connected is dropped;
  - the egress calls `on_log_failure`, which in the binary exits with 3.
- The stdout sink writes each line with one `write_all` and a `flush`
  under the stdout lock, so lines of concurrent connections never
  interleave. Diagnostics go to stderr.
- **Why stdout and not the `Evidence` port inside the egress** (decided at
  STOP 1 of #10):
  - Least privilege: the egress parses hostile bytes from the sandbox, and
    a compromised egress with a handle to the evidence store could rewrite
    the run's evidence.
  - A content-addressed `put` cannot append. A blob per record would need a
    chain of references that the runner then has to collect anyway.
  - The runner owns the run and stores the log blob through `Evidence`
    (#32).
- **Why an own line format and not JSON lines:** `boneli-json` (#29) does
  not exist yet, and a closed-alphabet format needs no escaping, so there
  is no escaping code to get wrong. Rust is the language either way.

### D9. Server limits

ADR-003 (item 7) makes each consumer justify its own limits.

- `max_head_bytes = 8192`. A legitimate CONNECT head is under 1 KiB: the
  request line is at most 278 bytes (`CONNECT ` 8, host 253, `:` 1, port
  5, ` HTTP/1.1` 9, CRLF 2), `Host` at most 267, and a `User-Agent` and
  `Proxy-Connection` add about 200. 8 KiB is about 8× headroom; the worst
  case buffered is 64 × 8 KiB = 512 KiB. Smaller would reject a client
  with a long `User-Agent`; larger only lets a hostile client make the
  egress buffer more.
- `max_headers = 32`. Proxy clients send 2 to 4 fields. httparse gets
  `min(32, 8192 / 4 + 1) = 32` slots (ADR-003, item 15).
- `max_body_bytes = 1`. The egress never reads a body, and 1 is the
  smallest value the constructor accepts. A declared body over 1 byte is
  `413` at head time; a CONNECT with any framing field is already `400`.
- `max_connections = 64`.
  - npm opens at most `maxsockets` connections per origin, 15 by default
    (npm CLI v11 config reference, retrieved 2026-11-13). Two npm origins
    at once take 30, and 34 remain for pip and other tools. The share of
    pip and other tools is an estimate, not a measurement.
  - Each tunnel costs 2 threads and 4 fds (both sockets and a clone of
    each). 64 × 4 = 256 fds, a quarter of the default soft
    `RLIMIT_NOFILE` of 1024 (the kernel's `INR_OPEN_CUR`, and systemd's
    `DefaultLimitNOFILE` soft value).
  - Fewer connections make npm wait in the listen backlog: slower, not
    failing. More press against the fd limit.
- `idle_timeout = 10 s`, `request_timeout = 10 s`. A proxy client writes
  its whole head right after connecting, in one segment under 1 KiB. 10 s
  tolerates a CPU-capped sandbox in the middle of a build. A client that
  connects and stays silent frees its slot within 10 s, and it only ever
  blocks its own run.
- `write_timeout = 10 s`. It covers only the egress's own answer heads, at
  most about 120 bytes; the relay sets its own timeouts (D7).

### D10. Two additive `boneli-http` APIs

`serve`'s behaviour does not change, and its existing tests pin that.

- `Target::parse_authority(value: &str) -> Result<Target>` (part 1)
  delegates to the private function that parses CONNECT targets, so
  targets and allowlist entries share one grammar. A test runs the same
  table of values through it and through a CONNECT head.
- `accept_loop(listener, limits, per_connection)` (part 2) is the current
  accept loop and connection cap with the slot and thread logic unchanged;
  `serve` becomes `accept_loop` plus `serve_connection`. The egress calls
  `serve_connection` itself and logs its result, as ADR-003 expects ("the
  composition root logs what `serve_connection` returns"). Rejected:
  copying the cap logic into the egress, which would leave two reviewed
  copies of the same concurrency code.

### D11. Seams and ports

- `Upstream` (resolve a name and port to addresses; connect to one address
  with a timeout) and `LogSink` (append one line) are traits local to
  `boneli-egress`, not ports of `boneli-app`. The egress is a composition
  root with its own small hexagon (ARCHITECTURE, "Gateway, egress and
  shim"), and no use case of the application drives it, so invariant 7
  (an in-memory adapter in `boneli-memory` and a contract suite in
  `boneli_app::contract`) does not apply. Its tests replace both seams
  with fakes.
- The relay's streams are `Read + Write + Send` with clone, shutdown and
  timeout operations, implemented for `TcpStream` and `UnixStream`; a fake
  upstream hands out one end of `UnixStream::pair()`.
- The clock is the `boneli_app::Clock` port, with an adapter in the egress
  (an `Instant` origin, saturating milliseconds) that passes
  `boneli_app::contract::clock::run`. The relay's idle logic uses
  `Instant` directly, because it is tied to socket timeouts.
- **TLS:** ADR-005 lists the egress among the users of `boneli-https`.
  That does not apply: without MITM the egress never terminates TLS, so it
  has no edge to `boneli-https` and pulls in no external crate. ADR-005 is
  accepted and is not edited.

## Consequences

- **Upload is not inspected.** Without MITM, an allowed tunnel can carry
  any bytes to an allowed host, for example data written into a package
  publish request. Upload bytes are logged per tunnel. A read-only
  registry mirror is the later fix, required before hosted runners run
  untrusted code against private repositories (decided at STOP 1 of #10).
- No private or customer-network registries (D4), and no IPv6-only hosts
  behind NAT64.
- The egress enforces only the list it is given. The rule that github.com
  is never on a list is enforced where the per-phase lists are built
  (#32), with a test there.
- Resolution is a blocking `getaddrinfo` without a timeout of our own. With
  glibc's defaults (`timeout:5`, `attempts:2`, up to 3 name servers,
  resolv.conf(5)) a dead resolver can hold a connection's slot for about
  30 s; this is an estimate from the defaults, not a measurement, and the
  man page says one call may take longer than one timeout. It only blocks
  the run that asked.
- An `open` without a `close` in a stored log means the process was
  killed mid-tunnel; the log cannot say more.
- The log lives on stdout until the runner stores it (#32). A runner that
  does not drain stdout fills the pipe, every write then blocks, and the
  egress stops serving: it fails closed, not open.
- The codec is part of the evidence format: a change to a record needs a
  new `v` and a reader for both.

## Alternatives considered

- **MITM** with a local CA, to inspect uploads. It needs TLS termination,
  a CA inside the sandbox and certificate handling per client, and it
  would put the subscription token's traffic through our code in
  plaintext. Rejected for the MVP; the mirror in Consequences is the
  planned answer.
- **Suffix wildcards, IP allowlists, trimming entries** (D2).
- **Skipping forbidden addresses** and connecting to the rest (D4).
- **`Evidence` inside the egress** (D8).
- **JSON lines** (D8).
- **An own accept loop in the egress** (D10).
- **Built-in presets in the binary** (D1): the runner owns the phases, and
  a preset would be a second place to change a list.
- **SOCKS5.** The clients in the sandbox (npm, pip, Claude Code) are
  given an HTTP proxy URL in `HTTPS_PROXY` and tunnel through it with
  CONNECT, which `boneli-http` already parses. SOCKS5 would be
  a second protocol to parse on the security boundary, with its own
  address types (including raw IPs) to police.
