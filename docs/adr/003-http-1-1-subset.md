# ADR-003: A strict HTTP/1.1 subset for boneli-http

- Status: accepted
- Date: 2026-11-13

## Context

`docs/ARCHITECTURE.md` ("Pure Rust and dependencies") puts an HTTP/1.1
server over a Unix socket and an HTTP client on the "we write ourselves"
list, on top of `httparse`. Issue #5 builds them as the support crate
`boneli-http`. A second crate, `boneli-https`, adds TLS later under its own
ADR.

The parser is the surface that the gateway (#20) and the egress proxy (#10)
expose to the sandbox. Every byte a sandboxed agent sends to a broker
arrives through it, so a parsing difference between this crate and an
upstream server (request smuggling) or a slow or endless input (resource
exhaustion) is a security bug. Its other consumers are the forge adapter
(#19) and the OCI image store (#7). The OCI store streams image layers of
hundreds of MB from a registry. The gateway relays server-sent events
(SSE) from LLM providers, and those streams live for minutes.

The planned peers are Claude Code's Node.js client, npm and pip (through
CONNECT), and the GitHub, registry and Anthropic APIs. All of them speak
HTTP/1.1.

`httparse` 1.10.1, measured during planning of #5 (2026-11-12, cargo
1.98.0):

| Input | httparse | This crate |
|---|---|---|
| Bare LF line endings in a head | accepted | rejects them |
| Non-ASCII bytes in the request target (`CONNECT` with a Cyrillic `а` in the host) | accepted | rejects them |
| Absolute-form targets | accepted | rejects them |
| `HTTP/1.0` | accepted | rejects it |
| A zero-width space inside a header value | accepted | compares framing values exactly |
| Trailing SP/HTAB in a header value | trimmed | relies on the trim |
| obs-fold, a space before the colon, NUL or VT in a value | rejected | maps to 400 |
| Status `1000` | rejected | maps to an error |
| `parse_chunk_size` with a bare LF after an extension (`a;x\n`) | **accepted** | uses its own chunk-line parser |

## Decision

`boneli-http` accepts a strict subset of HTTP/1.1 and rejects everything
else. It never repairs a message.

1. **HTTP/1.1 only.** A request in `HTTP/1.0` gets `505`, and any other
   version gets `400`. A response in any other version is an error. RFC
   9112 suggests that servers accept 1.0, but no planned peer speaks it,
   and 1.0 brings its own framing rules (keep-alive by opt-in, no chunked
   coding). Each of them is code that only an attacker would exercise.
   Rejected: 1.0 support.
2. **CRLF only.** A bare LF or a bare CR anywhere in a head, chunk line or
   trailer section is rejected (`400`). httparse accepts a bare LF, and a
   peer that splits lines differently from us can hide a header from one of
   the two parsers. The end of a head is found in one pass over the bytes,
   and httparse runs once on the complete head. Running httparse again
   after every read would make a head trickled one byte per read cost time
   quadratic in its length: with a 64 KiB limit that is about 2^31 byte
   comparisons for one request.
3. **Targets and hosts.** Origin form (`/` followed by visible ASCII) for
   every method except `CONNECT`, which takes exactly the authority form
   `host:port` or `[ipv6]:port`. The method compares case-sensitively
   (RFC 9110 §9.1), so `connect` is not CONNECT. The port is 1 to 65535 in
   at most five decimal digits. Absolute and asterisk forms are rejected.
   No planned client sends them to an origin server or a CONNECT proxy, and
   an absolute form makes the target's host disagree with `Host`. Rejected:
   accepting the absolute form as RFC 9112 requires of servers.

   A host is one of three forms, and nothing else (`400`):
   - a canonical dotted-decimal IPv4 address, as `Ipv4Addr::from_str`
     reads it (four decimal octets, no leading zeros);
   - an IPv6 address in brackets (`Ipv6Addr::from_str`, so no zone);
   - a name of LDH labels (letters, digits and `-`, not at either end of a
     label, RFC 5890), each 1 to 63 bytes and 253 bytes in total, whose
     last label does not "end in a number" in the sense of the WHATWG URL
     standard: decimal digits only, or `0x`/`0X` followed by hex digits
     only.

   Names are lowercased (RFC 4343). The rule exists because `getaddrinfo`
   resolves `0xa9fea9fe`, `2130706433`, `127.1`, `0177.0.0.1` and `10.1`
   to IPv4 addresses (`inet_aton`), while `Ipv4Addr::from_str` rejects
   them. Accepted as names, they would reach `169.254.169.254`,
   `127.0.0.1` or `10.0.0.1` past any check that classifies the parsed
   host, and the egress proxy (#10) decides on the parsed form: it must be
   canonical, so that "an IP literal" and "a name" cannot be confused. The
   same grammar applies wherever the crate parses or builds an authority:
   the CONNECT target, the `Host` field, the client's `Host` and the
   client's CONNECT destination. Rejected: returning such forms as names
   and leaving the check to consumers, and `_` in names (not LDH; no
   planned peer needs it).
4. **Framing without the lenient options.** Exactly one `Host`, whose
   value is `host [":" port]` with the grammar of item 3 (an empty value is
   rejected; RFC 9112 §3.2 allows it only for a target without a host, and
   our clients always send one). For CONNECT, `Host` must name the same
   host (case-insensitively) and port as the target, or the answer is
   `400`, so that a consumer that routes or logs by `Host` sees the
   destination the tunnel uses. At most one
   `Content-Length`, at most one `Transfer-Encoding`, and never both (`400`).
   The transfer coding must be exactly `chunked`, ASCII case-insensitive
   with optional whitespace around it, or the answer is `501`.
   `Content-Length` is one or more ASCII digits with optional whitespace
   around them: no sign, no list, and no overflow. RFC 9112 lets a
   recipient accept identical duplicate `Content-Length` fields and lets
   `Transfer-Encoding` override `Content-Length`. Both options are
   behaviours an upstream may not share, which is the precondition for
   request smuggling. Rejected: the RFC's lenient options.
5. **Our own chunk-line parser.** It accepts 1 to 16 hex digits, optional
   SP or HTAB before `;` extensions (which are ignored), CRLF only, and no
   other control character. 16 digits are 64 bits, the largest size a `u64`
   holds. Fewer digits would reject legal chunk sizes. More digits would
   need overflow handling and would allow zero padding of any length. Each
   chunk-size line is bounded by `max_head_bytes`. Rejected: httparse's
   `parse_chunk_size`, which accepts a bare LF after an extension (table
   above).
6. **Trailers** are read and discarded. They are held to the head limits
   (bytes and field count) and to the same CRLF and field syntax.
7. **Limits have no defaults.** `Limits { max_head_bytes, max_headers,
   max_body_bytes }` and `ServerLimits { http, max_connections,
   idle_timeout, request_timeout, write_timeout }` are built by
   constructors that reject zero values: std rejects a zero socket
   timeout, and a zero size limit rejects every message. The right values
   depend on the peer. The gateway faces the sandbox, while the OCI store
   reads multi-hundred-MB layers from a registry, so each consumer (#7,
   #10, #19, #20) states and justifies its own numbers in its PR. Rejected:
   default limits, because a default chosen for one peer is silently wrong
   for the other. Interim `1xx` responses count together with the final
   head against `max_head_bytes`, so an endless 1xx stream fails.
8. **Deadlines.** The wait for the first byte of a request is bounded by
   `idle_timeout`. From that byte, the head and the body must arrive
   within `request_timeout`, or the answer is `408`. Before every read the
   server sets the socket's read timeout to what is left of the deadline,
   so a total deadline holds without polling and without a timer thread. A
   client that trickles one byte at a time cannot extend it. Responses have
   no total deadline: an SSE stream lives for minutes, so `write_timeout`
   applies to each write instead. Rejected: a total response deadline.
9. **The connection cap stops accepting.** At `max_connections`, `serve`
   stops calling `accept`, and the kernel's listen backlog holds new
   clients until a slot frees. A slot frees when its connection ends, also
   when the handler panics. Rejected: accept-and-close at the cap. A
   client that is closed at once retries at once, and the server keeps
   paying for the accepts.

   One constraint follows for consumers: **one server per run.** The
   socket path is the run's identity (ARCHITECTURE, "Isolation"), so a slow
   client of one run holds only that run's slots and cannot starve another
   run.
10. **Who owns which header.** The server writes `Content-Length`,
    `Transfer-Encoding` and `Connection`. The client writes `Host`,
    `Content-Length` and `Transfer-Encoding`, and refuses `Connection`. A
    caller or handler that sets one of these gets an error, and nothing is
    written. So the gateway cannot forward the sandbox's framing upstream.
    Every name must be a token, and a value may not contain any control
    character except HTAB. Both are checked before the first byte is
    written.
11. **Server behaviour.**
    - A rejected request is answered with its status and
      `Connection: close`, and the connection closes.
    - `Expect: 100-continue` on a request with a body gets `100 Continue`
      before the handler runs. Any other expectation gets `417`.
    - A request body the handler leaves unread is never drained. The
      response says `Connection: close` and the connection closes.
    - `HEAD` responses omit the body bytes. `204` and `304` cannot carry
      a body, and handlers cannot send `1xx` at all.
    - A `2xx` to CONNECT is sent only through `accept_tunnel`, which hands
      over the stream with the bytes already read first. A CONNECT that is
      not tunnelled closes the connection, because the bytes after it are
      not a request.
    - Before any byte of a response is written, a handler error is
      answered only when it is `Error::Status(code)` with a code from 400
      to 599; a gateway that wants `502` or `504` for an upstream failure
      returns it. The one other answered case is a failure of the server's
      own reading of the request body (`Exchange::body`): its status
      (`400`, `408`, `413` or `431`) is sent even if the handler
      returns a different error. Every other handler error closes the
      connection without an answer. The mapping from error kinds to
      statuses belongs to reading the request only: an upstream timeout or
      malformed upstream answer that a handler passes on with `?` must not
      tell the client that its own request was late or bad. A client error
      that a handler passes on with `?` is `Error::Status` too, so a
      refused upstream CONNECT answers with the upstream's status; a
      handler that does not want this maps the error itself.
    - A handler that returns `Ok` while no byte of a response has been
      written gets `500` and the connection closes. This includes a
      `respond` that was refused for an invalid status or field: nothing
      was written, so the client gets an answer instead of a silent close,
      which a client would retry. Once bytes of a response were written,
      an incomplete one (a failed write, a stream without its last chunk)
      closes the connection without any further byte, and so does a
      returned tunnel.
12. **Client behaviour.** One request at a time. Responses are framed per
    RFC 9112 §6.3: `HEAD`, `1xx`, `204` and `304` have no body, and a body
    with neither framing field is read until close. `101` is an error,
    because this client never asks for an upgrade. The client follows no
    redirects, sends no `Accept-Encoding` and decodes nothing, keeps no
    cookies and reads no proxy environment variables. The caller decides
    each of these, for example whether credentials may follow a redirect
    to another host. A connection is reusable only after the body was
    read to its end, no byte beyond the response has been read, and
    neither side asked to close. Bytes that arrive while a connection is
    idle answered no request; read as the next response, a peer could
    answer a request it has not seen yet. So before a request on a
    connection used before, the client asks the stream whether it is
    still idle (`IdleCheck`): `UnixStream` and `TcpStream` read one byte in
    non-blocking mode, and any byte or the end of the stream ends the
    connection with nothing written. A stream that cannot tell (an
    in-memory stream, a wrapper without a hook) returns "not idle", and a
    connection over it serves one request. `Tunnel` counts its unread early
    bytes as input. Rejected: no reuse at all, which costs a connection per
    request for the forge and registry clients; and the check for Unix
    sockets only, which would leave other streams reusing without it.
13. **Truncation stays visible.** The end of the stream inside a
    `Content-Length` body or before the last chunk is an error, never a
    short complete body. `pass_through` writes and flushes after every
    read, so events are not buffered. On an upstream error it returns
    without writing the last chunk, so the downstream peer sees a
    truncated body too.
14. **Read size: 8 KiB.** This is `std::io::BufReader`'s default. It only
    trades system calls for memory: a smaller chunk costs more reads per
    100 MiB layer (about 12,800 at 8 KiB), and a larger one costs more
    memory per connection, multiplied by `max_connections`. Correctness
    does not depend on it: tests split every head at every offset and
    feed bodies one byte per read.
15. **httparse field slots.** httparse needs a preallocated field array.
    It gets `min(max_headers, max_head_bytes / 4 + 1)` slots, because the
    shortest field line (`a:` and CRLF) is four bytes. A huge `max_headers`
    therefore costs no memory beyond what the byte limit allows.
16. **No fuzzer in the build.** `cargo-fuzz` needs `libfuzzer-sys`, whose
    build script compiles and links libFuzzer's C++ sources, native code
    that no check of ADR-001 sees, and it needs a nightly toolchain for
    `-Zsanitizer`, while CI builds with stable. httparse's build script
    (item 17) does neither. Deterministic sweeps replace the fuzzer, and
    they run in every `cargo test`:
    - every byte of a 150-byte chunked request replaced by each of seven
      framing-relevant bytes (`00 0a 0d 20 3a 3b ff`), 1,050 inputs;
    - every prefix of that request;
    - every split offset of a head.

    Rejected: cargo-fuzz.
17. **httparse's build script is approved.** `httparse` 1.10.1 has a
    `build.rs` (cargo metadata lists a `custom-build` target), the first
    build script in the resolved graph. It runs `$RUSTC --version` and,
    from the version, the `std` feature and `CARGO_CFG_TARGET_FEATURE`,
    prints `rustc-cfg` lines that switch on its SIMD code paths
    (`httparse_simd`, `httparse_simd_neon_intrinsics` and the SSE4.2 and
    AVX2 compile-time variants), unless one of its two opt-out cfgs is
    set. Apart from spawning `$RUSTC` and reading cargo's environment
    variables it does nothing: it compiles no native code, links nothing,
    and touches no file or network. This ADR approves it.

    The approval is per crate, not per version: a new httparse version
    with a changed build script is caught only by reviewing `Cargo.lock`
    and the crate's diff. The rule of ADR-001 (`roles.build-script`)
    covers workspace members only, so today no check notices a build
    script in a dependency. Part 2 of #5 (the `boneli-https` PR) adds
    the check, as decided at STOP 1 of #5: a `build-script = "ADR-NNN"`
    key on `[external.<crate>]` in `tools/architecture.toml` and a
    `dep-build-script` rule that fails on any reachable external crate
    with a build script and without the key. httparse's record then
    cites this ADR. Until then, `tools/architecture.toml` notes the
    approval in a comment on `[external.httparse]`, because the current
    checker rejects unknown keys. Rejected: changing the checker in this
    PR, which would put a second security surface into the parser's
    review.

`boneli-http` depends on `httparse` only, with its default `std` feature.
That feature enables runtime SIMD detection and adds no crate; the build
script of item 17 comes with the crate itself. The edge
`boneli-http -> httparse` already has its record in
`tools/architecture.toml`.

## Consequences

- Peers that send HTTP/1.0, bare LF line endings, absolute-form targets,
  duplicate `Content-Length` fields or a transfer coding other than
  `chunked` are refused. None of the planned peers does any of this; a new
  peer that does needs a new ADR, not a quiet relaxation.
- Every consumer has to choose and justify its limits. That is deliberate
  work in #7, #10, #19 and #20.
- `serve` has no shutdown API. It runs until accepting fails. The
  composition roots of #10 and #20 add one if they host more than one run
  per process.
- Setting the read timeout before every read costs one extra system call
  per read on the server. With 8 KiB reads that is noise next to the reads.
- `serve` returns when `accept` or a thread spawn fails, for example with
  too many open files, instead of retrying in a loop. The composition
  root decides whether to restart.
- Handler errors other than `Error::Status` close the connection without
  an answer. The crate does no logging; the composition root logs what
  `serve_connection` returns.
- A pooled client connection costs one non-blocking read and two `fcntl`
  calls per reused request. Non-blocking mode belongs to the open socket,
  so a clone of the stream used on another thread at that moment sees it
  too; the client does not clone its stream.
- Hosts with `_` and numeric names such as `example.123` are refused. A
  peer that needs them needs a new ADR.

## Alternatives considered

- **hyper.** Needs tokio, which is on the "do not use" list
  (ARCHITECTURE), and brings its own dependency tree.
- **A head parser without httparse.** httparse is approved in ARCHITECTURE,
  needs no further crate and has wide production use. We add the checks it
  leaves out (table above) instead of writing a second parser.
- **HTTP/1.0 support, the RFC's lenient framing options, httparse's
  `parse_chunk_size`, default limits, accept-and-close at the cap, a total
  response deadline, cargo-fuzz.** Each one is rejected in the decision
  item above that names it.
