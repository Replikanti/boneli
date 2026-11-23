# ADR-022: Name resolution under the request deadline

- Status: accepted (2026-11-20, after the live tests of part 2)
- Date: 2026-11-20

## Context

Every network call of `boneli-https` has a deadline: `TlsDial` bounds
TCP, TLS and every read and write by the request's deadline (ADR-009,
D10), and the CRL and OCSP checks run under the check's deadline and the
request's (ADR-017, ADR-020). The one step outside every bound is name
resolution. `TlsDial`, `connect` and the CRL and OCSP fetches resolve
with std's `to_socket_addrs`, which calls `getaddrinfo`, and
`getaddrinfo` takes no timeout. ADR-017 lists this as a known limit
(item 7 and Consequences), and so do ADR-020 and ADR-009 D12; all point
to Replikanti/boneli#81.

How long the gap is was measured for ADR-006: on the development host
(glibc 2.43, Linux 7.2), `getent ahosts` against name servers that
receive every query and never answer took 10.0 s with one server and
28.0 s with three, the most glibc uses. A request with a 30 s deadline
can thus spend all of it, or more, before its deadline is first looked
at.

#81 sets two criteria for a fix:

1. a resolver that stalls makes `TlsDial` and the CRL fetch fail at the
   request deadline, not at the resolver's own timeout;
2. no resolver work outlives the call. ADR-017 adds the same rule for
   its own work: no thread outlives a check (Alternatives, "a refresh in
   a background thread").

The work ships in two pull requests. Part 1 adds the resolver, its tests
and this ADR as proposed, and wires nothing. Part 2 moves the three call
sites onto it, adds the end-to-end deadline tests and accepts this ADR.

## Decision

### D1. An own stub resolver, std only, on the caller's thread

`boneli-https` gets its own stub resolver (`src/resolve/`): `/etc/hosts`
first, then A and AAAA queries over UDP (TCP when an answer is
truncated) to the name servers of `/etc/resolv.conf`. Every wait is
`min(try timeout, time left before the deadline)`, so a lookup ends by
the deadline, and nothing is spawned, so nothing outlives the call.

These are the semantics of musl's `getaddrinfo`, which has no NSS:
Rust's self-contained musl `libc.a` defines `getaddrinfo`,
`__lookup_name`, `__get_resolv_conf` and `__res_msend` and no
`getaddrinfo_a` (checked when this was planned). A runner built for musl
resolves this way today. One exception: musl uses a name server with an
IPv6 zone (`fe80::1%eth0`), this resolver does not (D3).

Why this mechanism:

- It is the only option weighed that meets both criteria without a host
  binary, a new crate, a new `libc` edge or `unsafe` code (Alternatives).
- Language: Rust, in the crate that already owns the deadline socket
  (`DeadlineSocket`, `time_left`) the TCP fallback reuses. Every option
  weighed was Rust code; the C options (c-ares, `getaddrinfo_a`) lost on
  the build script, the FFI and the helper thread, not on the language.
- Measured when this was planned, without EDNS through the development
  host's stub resolver: the largest of the 28 A and AAAA answers for the
  14 hosts of the live test was 262 bytes (registry-1.docker.io AAAA, 8
  records), none was truncated. 512 bytes over UDP hold 1.95 times the
  largest, so the TCP fallback is for outliers.
- DNS is not the trust anchor. The TLS name check and the signatures on
  CRLs and OCSP answers carry trust, so a spoofed answer costs
  availability only, as with glibc's stub resolver.

Weak spots, recorded here and under Known limits: names that only other
NSS sources know fail closed (mDNS `.local`, LDAP or sssd host maps,
`myhostname`, and systemd-resolved's split DNS when resolv.conf lists the
uplink servers instead of the 127.0.0.53 stub), and a new parser of
hostile input joins an always-review crate.

### D2. Sources, in order

1. **The input grammar.** The host is ASCII-lowercased, then must be an
   ADR-003 host (`Target::parse_authority` through the same `check_host`
   as `TlsDial`: an LDH name whose last label is not a number, at most
   63 bytes per label and 253 in all, or a canonical IPv4 address) or an
   IPv6 address without brackets; port 0 is refused. Anything else is
   `InvalidInput` before any file is read or query sent. Numeric forms
   that `inet_aton` reads (`127.1`, `0x7f000001`, `2130706433`) never
   reach a name server as names.
2. **An IP literal** is returned as it is.
3. **`localhost`** and names under `.localhost` return `::1` and
   `127.0.0.1`, with no file or query (RFC 6761, 6.3).
4. **`/etc/hosts`**, with no search list, as nss_files reads it: every
   matching line, canonical name or alias, ASCII case-insensitively, in
   file order. A line whose address `IpAddr::from_str` does not read
   (`127.1`, a zone) is skipped.
5. **DNS**, for each candidate name (D5).

### D3. The resolv.conf subset

- Read: `nameserver` (port 53, at most 3), `search` and `domain` (the
  last such line wins; `.` is the root and adds nothing, and is what
  systemd-resolved writes), `options ndots: timeout: attempts: use-vc`.
- Ignored: every other keyword and option (`rotate`, `edns0`,
  `trust-ad`, `single-request`, `sortlist`, ...), the environment
  variables `LOCALDOMAIN`, `RES_OPTIONS` and `HOSTALIASES`, and the
  default domain glibc derives from the hostname.
- No `nameserver` line at all means `127.0.0.1:53`, as in libc.
- A server with a zone (`fe80::1%eth0`) or one that does not parse is
  skipped and does not count toward the 3. When `nameserver` lines list
  servers and every one is skipped, the resolver asks no server: a lookup
  that needs DNS fails with `Unsupported`, naming the first listed value.
  It never falls back to `127.0.0.1:53` then, because that asks a server
  nobody configured: the error would name it (`connection refused`), or
  whatever listens on loopback port 53 would answer.

  Why not use the zone, as glibc and musl do: a zone is an interface
  name, and a socket needs its index. `if_nametoindex` is a `libc` call
  (hand-written FFI in `boneli-sys` and a new `libc` edge, each needing
  an ADR); `/sys/class/net/<name>/ifindex` builds a path from file text
  in an always-review crate and is absent where `/sys` is not mounted.
  Link-local name servers come from IPv6 router advertisements (RDNSS)
  on IPv6-only links, and NetworkManager writes them into resolv.conf
  only when systemd-resolved is off; with systemd-resolved, resolv.conf
  lists the 127.0.0.53 stub. A runner host like that is rare enough that
  failing with the cause named beats either mechanism; when one shows up,
  supporting zones is a decision of its own (Known limits).
- An option value that is not a number keeps the default (glibc reads
  `ndots:x` as 0 through `atoi`; a typo should not turn the search list
  off). A value out of range is clamped (Numbers).
- A missing or unreadable file counts as empty, as in libc.

`ResolverConfig::new` builds a configuration without a file, with name
servers at any port, for a runner with its own name servers and for the
tests; it refuses values outside the bounds instead of clamping them,
because a caller's value is a bug, not a file to tolerate.

### D4. The protocol subset

- RD=1, one question, a 16-bit id per query from `fill_random`. When the
  random source fails, the lookup fails; there is no predictable-id
  fallback.
- One UDP socket per server and try, bound to the unspecified address of
  the server's family and connected, carries the A and AAAA queries, so
  only datagrams from that server's address reach it and the kernel
  picks a random source port.
- No EDNS, so an answer over UDP is at most 512 bytes (RFC 1035, 4.2.1).
  TC=1 asks that type again over TCP (RFC 7766, 5), one connection per
  query with a two-byte length prefix; a length of 0 is malformed. A
  datagram longer than 512 bytes is read as truncated. TC=1 over TCP is
  malformed.
- A message is ignored unless QR=1, opcode 0, QDCOUNT 1 and its id and
  question (name case-insensitively, type, class IN) match an
  outstanding query; matching is by (id, type), so an A and an AAAA
  query with the same id are told apart. A message shorter than the
  header or whose question does not parse is ignored too, as glibc's
  `send_dg` drops it (`goto wait`): only a message that matches an
  outstanding query can fail it, so a sender must know the 16-bit id as
  well as the port. A second answer to a settled or failed query is
  ignored.
- The CNAME chain is followed inside the answer section only, from the
  question name, at most ANCOUNT steps; a name met twice is malformed.
  Only the records of the query's type owned by the chain's last name
  count. The authority and additional sections are never read.
- Names: labels of at most 63 octets, 255 octets on the wire; the label
  types 0x40 and 0x80 are malformed; a compression pointer must point
  strictly before the labels it ends, and each later pointer before the
  previous target, so reading always ends; more than 127 pointers in one
  name are malformed, which bounds the work (Numbers).
- An A record of class IN must have 4 bytes of RDATA and an AAAA record
  16, a CNAME's name must fill its RDATA exactly; records of another
  class or type are skipped. Every index is checked, so no input panics:
  a message is ignored, an answer, or a malformed answer to the query it
  matched.
- rcode 0 is an answer or NODATA, 3 is NXDOMAIN, and every other rcode
  (SERVFAIL 2, NOTIMP 4, REFUSED 5 and the rest) fails that query.

### D5. The schedule

- Candidates (glibc's `res_search`): a name with at least `ndots` dots is
  asked as it is first, then under each search domain; one with fewer
  dots under the search domains first and as it is last. A candidate
  over 253 bytes is skipped.
- For each candidate, `for attempt in 0..attempts { for server in
  servers { try } }`. Each try waits at most `min(timeout, left)`;
  `use-vc` sends every query over TCP.
- A try ends when both types are answered (settled or failed) or its
  wait ends. A failed query (an rcode or a malformed answer to it) does
  not end the try: the other type is still waited for, as glibc's
  `send_dg` does on SERVFAIL, NOTIMP and REFUSED (`recvresp1`,
  `recvresp2`), and over TCP the other query is still asked. A socket
  error (ECONNREFUSED) ends the try at once. Addresses for either type
  mean Found, whichever arrives first, even when the other type stays
  silent or fails (a partial answer). Otherwise a failed query fails the
  server and the next one is asked. NODATA or NXDOMAIN for both means the
  candidate has no address.
- A candidate whose tries all time out ends the lookup with `TimedOut`,
  as glibc's `res_search` stops on a timeout. NXDOMAIN, NODATA and
  failures go on to the next candidate.
- The lookup ends with `NotFound` when no candidate had an address and
  no server failed, otherwise with `Other` naming the last failure. A
  passed deadline is `TimedOut` wherever it is noticed; a deadline equal
  to now counts as passed, as `time_left` has it, and sends nothing.

### D6. Order

Duplicates go, the first occurrence stays; then a stable sort by the
precedence of glibc's default table, RFC 3484 as gai.conf(5) prints it:
`::1/128` 50, `::/0` 40, `2002::/16` 30, `::/96` 20, `::ffff:0:0/96`
(and IPv4) 10. The other rules of RFC 3484 (unusable destinations,
scope, labels) are not applied, so an IPv6 address comes first even on
a host without an IPv6 route; its connect then fails at once with
`ENETUNREACH` and the next address is tried.

### D7. The API

- Part 1: `Resolver::system()` (reads `/etc/resolv.conf` and
  `/etc/hosts`), `Resolver::fixed(ResolverConfig)`,
  `Resolver::lookup(host, port, deadline)`, `ResolverConfig::parse`,
  `ResolverConfig::new` and its builders (`with_search`, `with_ndots`,
  `with_use_vc`, `with_hosts`), and the `DNS_*` constants.
- Part 2: `TlsConfig::with_resolver`, and `TlsDial`, `connect` and the
  CRL and OCSP fetches resolve through the `TlsConfig`'s resolver
  (`Resolver::system()` by default). `TlsDial` and the fetches resolve
  under the request's or the check's deadline; a fetch whose lookup runs
  out of it fails as `TimedOut`, like every later step, and any other
  lookup error is `Unreachable`.
- `with_resolver` installs fetch sources over the new resolver for both
  CRLs and OCSP, so it replaces a source set earlier by
  `with_crl_source` or `with_ocsp_source`, and both caches start empty;
  a caller who wants both sets the source after the resolver. Why not
  keep a custom source: a source reaches lists its own way, so whether a
  resolver applies to it is the source's business, and a configuration
  where the CRL fetches silently kept the old resolver would be worse
  than one rebuilt in a documented order.
- `connect`'s lookup is bounded by its `connect_timeout`, the only bound
  `connect` has before the handshake: it already bounds each TCP attempt,
  and a caller who set it expects `connect` not to wait longer for an
  address. A `connect_timeout` too large to add to the clock
  (`Duration::MAX`, "no bound of mine") saturates, so only the
  resolver's own tries bound that lookup, as before. `connect` refuses
  names outside the ADR-003 grammar before any query: after
  `server_name` (`Error::InvalidServerName`), a name rustls accepts and
  the grammar does not (an underscore, a trailing dot) is `Error::Io` of
  kind `InvalidInput`. This narrows a public API; every lookup of the
  crate then has one grammar and a bound. Upper case still passes,
  because the resolver lowercases first.
- This changes `connect` as ADR-005, item 8, describes it: it no longer
  resolves with std (no NSS sources such as mDNS or `myhostname`), and
  a trailing-dot name is refused.

### D8. No thread, no process, no cache

The lookup runs on the caller's thread and starts no thread or process.
The files are read at every lookup, as musl does, so a changed
resolv.conf applies to the next lookup. Nothing is cached; the name
servers cache.

## Numbers

Each value's source, and what breaks at another. The resolver values
come from glibc 2.43's `resolv.h` on the development host, the same as
in resolv.conf(5).

- **Port 53** (`DNS_PORT`): RFC 1035, 4.2.
- **At most 3 name servers** (`DNS_MAX_NAME_SERVERS`, glibc's `MAXNS`):
  the set libc uses for the same file. More would mean more tries before
  a failure; fewer would drop a server the host configured.
- **Try timeout 5 s, capped at 30 s** (`DNS_DEFAULT_TRY_TIMEOUT`,
  `DNS_MAX_TRY_TIMEOUT`; glibc's `RES_TIMEOUT` and `RES_MAXRETRANS`).
  Lower would skip and re-ask a slow but alive server on a cold
  recursive lookup; higher lets a dead first server take more of the
  deadline before the next is asked.
- **Attempts 2, capped at 5** (`DNS_DEFAULT_ATTEMPTS`,
  `DNS_MAX_ATTEMPTS`; glibc's `RES_DFLRETRY` and `RES_MAXRETRY`): the
  rounds a host's administrator expects from the same file.
- **ndots 1, capped at 15** (`DNS_DEFAULT_NDOTS`, `DNS_MAX_NDOTS`;
  glibc's default and `RES_MAXNDOTS`).
- **Zero clamps to 1** for `timeout:` and `attempts:`, so a lookup always
  asks once; a lookup that never asks is not reproduced.
- **512 bytes over UDP** (`DNS_UDP_MESSAGE_BYTES`): RFC 1035 without
  EDNS; it holds the measured 262-byte maximum 1.95 times over. A larger
  answer costs one TCP round trip.
- **65,535 bytes over TCP**: the two-byte length prefix allows no more.
- **127 compression pointers per name** (`MAX_POINTER_JUMPS`): a name of
  255 octets has at most 127 labels (each takes at least 2 octets), and a
  pointer that saves space leads to at least one label, because a pointer
  to a bare root octet or to another pointer is 2 octets for at most 2.
  So no space-saving encoding of a legal name needs more jumps; a lower
  cap could refuse one that shares every suffix. Without a cap a TCP
  answer of 65,532 bytes whose 4,096 owner names follow one chain of
  8,169 pointers took about 145 ms to parse (release build, development
  host), all of it possibly after the deadline; at the cap the heaviest
  such answer, 5,436 owner names of 127 jumps, takes 3 to 5 ms. A higher
  cap moves that time up linearly.
- **The precedence table** (D6): gai.conf(5)'s default.
- **No cap on search domains**: glibc dropped its cap of 6 in 2.26, and
  the deadline bounds the candidates.

## Consequences

- With part 2, the lookup counts inside every deadline. Dead name servers
  ahead of a live one cost `C x D x T`: `T` the try timeout, `D` the dead
  servers before the live one, `C` the candidates asked up to the one
  with the address, because every candidate starts again at the first
  server (D5, as glibc's `res_search`). A name with at least `ndots` dots
  is asked as it is first, so `C` is 1; a name with fewer dots goes
  through the `S` search domains first, so `C` is `S + 1`. With
  resolv.conf's defaults (`T` 5 s, `ndots` 1) and no search list, one
  dead server (`D` 1) costs 5 s before the second answers:
  - a CRL fetch over `https`: 5 + 10 connect + 10 handshake + 0.211
    (measured first byte, ADR-017) = 25.2 s, under `CRL_SETUP_TIME` 30 s.
    With two dead servers, 10 + 20.2 = 30.2 s: a fetch is cut off only if
    connect and handshake also take their full bounds;
  - an OCSP check over `http`: 5 + 10 + 10 + 1 = 26 s, within
    `OCSP_CHECK_DEADLINE` 31 s. An `https` responder would need 5 + 10 +
    10 + 10 + 1 = 36 s; none was measured;
  - `boneli-oci`'s `SETUP_TIMEOUT` 30 s and the forge's 30 s: 5 + 10 +
    10 + a round trip, under 30 s.

  The budgets do not hold with a search list and a high `ndots`. A
  Kubernetes pod's resolv.conf has at least 3 search domains (the
  cluster's, then the node's) and `ndots:5`, so a
  CRL host such as `crl3.digicert.com` (2 dots) is asked under the 3
  domains first: `C` 4, and one dead first server costs 4 x 5 = 20 s.
  The CRL fetch then needs 20 + 10 + 10 + 0.211 = 40.2 s against 30 s,
  the OCSP check 20 + 10 + 10 + 1 = 41 s against 31 s, and the oci and
  forge setups 20 + 10 + 10 s and a round trip against 30 s.
  glibc spends the same 20 s there (same schedule), so this is not a
  regression; with `getaddrinfo` those 20 s sat outside every deadline.
  No constant changes. From part 2 the lookup runs under each
  call's deadline, so on such a host the call ends at its deadline with
  `TimedOut` instead of running past it, and a revocation check that ends
  so fails closed (ADR-017, ADR-020); the request fails instead of
  overrunning. A host that needs these calls to fit lists a live server
  first or lowers `ndots`. Before, the lookup sat outside these budgets
  and was unbounded: 10.0 to 28.0 s for glibc in ADR-006.
- Behavior differs from today's glibc path: NSS sources other than files
  and DNS, the environment variables, gai.conf and the hostname-derived
  search domain are not used, and IPv6 addresses with no route are tried
  first and fail at once. Every failure is an error, never a wrong peer,
  because TLS verifies the name.
- Live test, part 1 (`own_resolver_agrees_with_the_system`,
  2026-11-20, development host, resolv.conf pointing at
  systemd-resolved's stub 127.0.0.53): for all 14 hosts, the own
  resolver found a non-empty set of addresses equal to the one
  `getaddrinfo` found (1 to 16 addresses per host). Lookup times, own
  resolver first, then the system's:
  - first run, the stub's cache cold for the own resolver: own 0.7 to
    57.7 ms (median about 21 ms), system after it 0.6 to 2.0 ms;
  - second run, both warm: own 0.25 to 1.2 ms, system 0.23 to 1.6 ms.
- Live tests, part 2 (2026-11-20, development host, the same
  resolv.conf), with `TlsDial`, `connect` and the CRL and OCSP fetches
  on this resolver: `own_resolver_agrees_with_the_system` again found
  equal address sets for all 14 hosts (own 0.6 to 40.3 ms, system 0.5 to
  2.0 ms; the slow own lookups are the ones the stub had not cached for
  it). Let's Encrypt's revoked test site failed with `Error::Revoked`
  and its valid one was checked against its CRL; the six forge hosts
  were `OcspChecked` by Sectigo's responder; the runner hosts' status
  printed (`Checked` by CRL for Docker Hub and the LLM provider,
  `OcspChecked` for GitHub); the crate's `ocsp::live` tests (SSL.com's
  revoked leaves, two delegated responders) and the 32 `openssl
  s_server` handshakes of `tests/interop.rs` passed.
- In CI, through the call sites, against a name server that receives
  every query and never answers (deadline 300 ms; 250 ms tries, 3.75 s
  of them, so a lookup left running would send its next query at 500
  ms): `TlsDial`, `connect` (at a 300 ms `connect_timeout`), the CRL
  and the OCSP fetch end within 1 s with `TimedOut` (the fetches
  inside a revocation failure), and no query arrives in the 600 ms
  after they returned (`dial_fails_at_the_deadline_on_a_stalled_resolver`,
  `connect_lookup_stops_at_the_connect_timeout`,
  `crl_lookup_stops_at_the_request_deadline`,
  `ocsp_lookup_stops_at_the_request_deadline`; each fails against a
  lookup moved to a detached thread, run 2026-11-20), nor after a
  direct lookup returned (`no_query_after_the_lookup_returns`); and
  no source file of the crate outside comments names `to_socket_addrs`
  or `ToSocketAddrs`, or names a std function that takes them
  (`TcpStream::connect`, `TcpListener::bind`, `UdpSocket::bind`,
  `UdpSocket::connect`, `UdpSocket::send_to`, as a call, a UFCS call
  or the function as a value; and the methods `connect` and `send_to`)
  except in a call whose argument is a socket address
  (`crate_has_no_std_lookup`). The scan is a text match: it does not see
  a method turbofish (`socket.connect::<&str>(host)`), a qualified path
  (`<TcpStream>::connect(host)`), an alias or a macro. Since #93 the
  scan reads tokens and keys on the names `connect`, `bind` and
  `send_to` whatever path or alias comes before them, so it catches the
  turbofish, the qualified path and the alias, and it refuses
  `macro_rules!`, `include!`, a `#[path]` module, a first line that
  rustc drops as a shebang (`#!` not followed by `[`) and a non-ASCII
  character outside comments and literals.
- `boneli-https` has a DNS message parser now, hostile input in an
  always-review crate; its tests sweep every truncation and every byte
  flip of a valid answer.

### Known limits

- Names known only to other NSS sources (mDNS `.local`, LDAP or sssd
  host maps, `myhostname`, split DNS behind systemd-resolved when
  resolv.conf lists the uplink servers) do not resolve.
- Reading `/etc/resolv.conf` and `/etc/hosts` from a hung network file
  system is not bounded by the deadline. A huge hosts file is: the
  deadline is checked before every line.
- An on-path attacker can still answer first, as against glibc. An
  off-path sender who hits the ephemeral port and the 16-bit id of a
  query can fail that query (SERVFAIL, a malformed answer), and when the
  other type yields no address the try moves on to the next server; a
  datagram that matches no query is ignored, as glibc's `send_dg` does.
  Both cost availability only.
- Name servers with an IPv6 zone are not used (D3); when resolv.conf
  lists only such servers, lookups that need DNS fail with
  `Unsupported`, where glibc and musl would ask them.
- Dead name servers ahead of a live one cost `C x D x T` per lookup
  (Consequences); with a Kubernetes-style search list the CRL, OCSP, oci
  and forge budgets do not hold, and part 2's deadlines end those calls
  instead.
- `boneli-egress` resolves with its own `getaddrinfo` (ADR-006); its known
  limit stays open. This resolver could move into a support crate of its
  own when the egress wants it.

## Alternatives considered

- **A resolver thread with a timeout.** The call returns at the deadline,
  but the thread runs on inside `getaddrinfo` until glibc gives up: it
  outlives the call (#81's second criterion, ADR-017's rule).
- **`getaddrinfo_a`.** Its helper thread runs on too (getaddrinfo_a(3):
  a request "cannot be canceled if it is currently being processed");
  musl does not have it; `libc` 0.2.191 binds neither it nor `gaicb`, so
  the FFI would be hand-written `unsafe` in `boneli-sys`, and a new
  `boneli-sys -> libc` use would need its own ADR.
- **A `getent ahosts` child**, polled with `try_wait` and killed and
  reaped at the deadline. It keeps NSS exactly and took at most 0.02 s
  per call on the development host. It lost because it needs a host
  binary (absent from distroless and static images; whether Alpine's
  `getent` supports `ahosts` is unverified), costs a process per
  request, and parses an informal output format.
- **A helper binary of our own** under the same kill-at-deadline rule:
  the costs of the `getent` child plus shipping and locating it.
- **`RES_OPTIONS=timeout:1 attempts:1`** for the process: still not the
  request's deadline, still unbounded under other NSS modules, and it
  changes every lookup of the process.
- **Crates.** `hickory-resolver` needs tokio, which `deny.toml` bans;
  `dns-lookup` is the same blocking `getaddrinfo`; c-ares needs a C
  build script (ADR-001).
- **DNS over HTTPS to a public resolver.** It sends every name the runner
  resolves to a third party and ignores the customer's DNS, which may be
  the only one that knows their internal forge.
- **A separate `boneli-dns` crate.** Deferred until the egress wants it;
  until then the resolver needs `DeadlineSocket` and `fill_random`, which
  live in `boneli-https`.

## Accept when

Part 2's end-to-end tests with a stalled resolver are green in CI
(`TlsDial`, the CRL and OCSP fetches and `connect` fail at their
deadline, and no query is sent after a lookup returns), and on the
development host `own_resolver_agrees_with_the_system` and the
revocation live tests pass through the wired resolver.
