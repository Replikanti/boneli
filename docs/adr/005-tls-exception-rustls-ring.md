# ADR-005: TLS with rustls and ring, the exception to pure Rust

- Status: accepted
- Date: 2026-11-13

## Context

`docs/ARCHITECTURE.md` ("Pure Rust and dependencies") approves `rustls`,
`webpki-roots` and `ring` for one support crate, `boneli-https`, and
names TLS as an exception to pure Rust: no production-ready cryptographic
backend exists in pure Rust, and `ring` contains C and assembly. Issue #5
builds the crate, the HTTPS client that the forge adapter (#19), the OCI
image store (#7), the egress proxy (#10) and the gateway (#20) use for
LLM providers, forges and registries. `boneli-http` (ADR-003) is the HTTP
layer on top of it.

ADR-001 holds every edge into an external crate to a record in
`tools/architecture.toml`, a new crate name to an ADR or an ARCHITECTURE
row, and every edge into `libc` to an accepted ADR that names it. The rows
in ARCHITECTURE cover the three crates above and nothing they pull in.

Measured on 2026-11-13 with cargo 1.98.0 and cargo-deny 0.20.2, after
adding `rustls = "0.23.46"` (`default-features = false`, features `ring`,
`std`, `tls12`) and `webpki-roots = "1.0.12"` to `boneli-https`:

- `tools/check-architecture.sh` reports 20 `dep-edge` failures. The graph
  of external crates has 16 crates and 23 edges; 3 edges were recorded
  already (`boneli-http -> httparse`, `boneli-https -> rustls`,
  `boneli-https -> webpki-roots`).
- `cargo deny check licenses` rejects five crates: `ring`
  (`Apache-2.0 AND ISC`), `untrusted` (`ISC`), `rustls-webpki` (`ISC`),
  `subtle` (`BSD-3-Clause`) and `webpki-roots` (`CDLA-Permissive-2.0`).
  Advisories, bans and sources pass.
- Every crate declares `rust-version` 1.85 or lower, or none (the highest
  is `zeroize` with 1.85), so the workspace MSRV of 1.85 stays.
- Four reachable external crates have a build script (cargo metadata lists
  a `custom-build` target): `httparse`, `libc`, `ring` and `rustls`. The
  eight `windows_*` crates have one too, but no edge to them is reachable
  on a checked Linux target. ADR-001's `build-script` rule covers
  workspace members only, so no check saw these.
- The rustls `ring` provider offers the key exchange groups X25519, P-256
  and P-384. Its post-quantum hybrid needs the `aws_lc_rs` provider.
- `tls12` is an empty feature in rustls 0.23 (`tls12 = []`).

## Decision

1. **Provider and features.** `boneli-https` depends on `rustls` with
   `default-features = false` and the features `ring`, `std` and `tls12`,
   and on `webpki-roots`. It takes no direct dependency on `ring`:
   `rustls::crypto::ring` is enough.
   - `ring`, not `aws_lc_rs`: `aws-lc-sys` is banned in `deny.toml`. It
     builds a large C library with CMake, and its prebuilt NASM objects are
     binaries no review sees.
   - `std`: blocking `Read` and `Write` streams over std sockets, because
     ports are synchronous (ARCHITECTURE).
   - `tls12`: runners inside customer networks reach self-hosted forges
     and registries, and some of them do not speak TLS 1.3. The feature
     adds no crate. Rejected: TLS 1.3 only, which would refuse those hosts
     with nothing gained in the graph.
   - No `logging`: it pulls `log`, and Boneli writes its own structured
     logs (ARCHITECTURE).
   - The minimum versions are the ones measured (`0.23.46`, `1.0.12`), so
     that a lockfile regenerated later cannot resolve to an older release
     than the one this ADR reviewed.
2. **Trust.** Mozilla's root program as compiled into `webpki-roots`
   (`Roots::mozilla`), plus roots the caller adds as PEM or DER, for
   example a customer's internal CA. Adding PEM is all or nothing, and
   input without a certificate is an error, because an empty bundle is a
   configuration mistake; an empty trust store is refused for the same
   reason. Rejected:
   - the host's CA bundle: it differs from host to host, and anything
     installed there widens trust without a change in this repository;
   - `rustls-native-certs`: a further crate that reads the same bundle.
3. **The approved crates.** These are the crates of the TLS stack, with the
   versions locked when this ADR was accepted. A version update needs no
   new ADR (see item 6 for build scripts); a new crate or a new edge does.

   | Crate | Version | License | Role | Pulled by |
   | --- | --- | --- | --- | --- |
   | `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS protocol | `boneli-https` |
   | `webpki-roots` | 1.0.12 | CDLA-Permissive-2.0 | Mozilla's roots as data | `boneli-https` |
   | `ring` | 0.17.14 | Apache-2.0 AND ISC | crypto provider: key exchange, AEAD, signatures | `rustls`, `rustls-webpki` |
   | `rustls-webpki` | 0.103.17 | ISC | certificate path validation | `rustls` |
   | `rustls-pki-types` | 1.16.0 | MIT OR Apache-2.0 | certificate, key and name types | `rustls`, `rustls-webpki`, `webpki-roots` |
   | `untrusted` | 0.9.0 | ISC | panic-free parsing of untrusted input | `ring`, `rustls-webpki` |
   | `subtle` | 2.6.1 | BSD-3-Clause | constant-time comparisons | `rustls` |
   | `zeroize` | 1.9.1 | Apache-2.0 OR MIT | wiping secrets from memory | `rustls`, `rustls-pki-types` |
   | `once_cell` | 1.21.4 | MIT OR Apache-2.0 | lazy initialization | `rustls` |
   | `getrandom` | 0.2.17 | MIT OR Apache-2.0 | OS random numbers | `ring` |
   | `cfg-if` | 1.0.5 | MIT OR Apache-2.0 | cfg branching macro | `getrandom`, `ring` |
   | `libc` | 0.2.191 | MIT OR Apache-2.0 | system call declarations | `getrandom`, `ring` (item 4) |
   | `cc` | 1.11.1 | MIT OR Apache-2.0 | C compiler driver, build-dependency of `ring` | `ring` (build) |
   | `shlex` | 2.0.1 | MIT OR Apache-2.0 | splitting compiler flags | `cc` |
   | `find-msvc-tools` | 0.1.15 | MIT OR Apache-2.0 | MSVC lookup, unused for Linux targets | `cc` |

   Together with `httparse` (ADR-003) these are the 16 external crates and
   23 edges of the workspace. `tools/architecture.toml` records each edge
   with its reason and this ADR.
4. **Two new edges into `libc`.** `libc` is strict (ADR-001), so each edge
   is named here:
   - `` `getrandom -> libc` `` (`cfg(unix)`): `getrandom` fills buffers
     with `syscall(SYS_getrandom)`. When the kernel answers `ENOSYS` or
     `EPERM` (a seccomp filter), it falls back to `/dev/urandom`: `poll`
     on `/dev/random` once, then `open`, `read` and `close`, behind a
     `pthread_mutex`, with `errno` read through `__errno_location`. ring's
     `SystemRandom` draws its key shares and nonces from it.
   - `` `ring -> libc` `` (aarch64 and arm Linux only): `getauxval(AT_HWCAP)`
     to detect the AES, PMULL and SHA instructions, so that ring picks its
     assembly for them.

   Both run in the process that holds the TLS connection: the runner, the
   gateway or the egress proxy. None of them runs in the sandbox, which has
   no network (ARCHITECTURE, "Isolation"). Rejected: routing these calls
   through `boneli-sys`, which would mean patching third-party crates.
5. **ring's C and assembly are the one exception to pure Rust.** ring's
   build script compiles C and assembly from BoringSSL with `cc` and links
   them as a static library (`links = "ring_core_0_17_14_"`). This is the
   native code that ARCHITECTURE accepts for TLS, and it stays inside one
   support crate.
6. **Build scripts of external crates need an ADR.** A build script runs
   on every machine that builds the workspace, CI included, and can
   compile and link native code that no scan of ours reads. ADR-001 limits
   build scripts of members; this decision extends the rule to
   dependencies. `[external.<crate>]` in `tools/architecture.toml` takes
   an optional key `build-script = "ADR-NNN"`. As for an edge into a
   strict crate, the ADR must resolve to exactly one file, be accepted,
   and name the crate, here in the sentence `<crate>'s build script is
   approved` (outside HTML comments, the crate name not part of a longer
   name, line breaks read as spaces). ADR-003 item 17 already says it for
   httparse, in that form. Anything else is a `policy-format` failure and
   approves nothing, so an ADR about another crate, or one that was
   proposed or rejected, approves no build script. The rule
   `dep-build-script` of `tools/check-architecture.sh` fails on every
   reachable external crate with a build script and without a key that
   approves it. It reads the `custom-build` target from cargo metadata,
   not file names, so a script renamed with `build = "gen.rs"` counts and
   `build = false` does not, and it covers crates reached only through a
   build-dependency. Rejected: a list of approved build scripts in
   ARCHITECTURE, which no check reads. The approved scripts:
   - `httparse` (ADR-003, item 17): runs `$RUSTC --version` and prints
     SIMD cfgs.
   - libc's build script is approved. It runs `$RUSTC --version` and
     prints cfgs for the target and the compiler version; it compiles
     and links nothing.
   - rustls's build script is approved. It prints the `read_buf` cfg on a
     nightly compiler with the `read_buf` feature, which we do not enable;
     otherwise it is empty.
   - ring's build script is approved. It compiles and links C and
     assembly (item 5).

   The weak spot: the approval is per crate, not per version. A version
   update that changes what a build script does passes the check, and only
   the review of `Cargo.lock` and of the crate's diff catches it. A
   per-version or per-hash approval would make every patch release of
   these four crates a policy change; the lockfile review already sees the
   update.

   A second weak spot: the check matches the sentence, not what it means.
   A sentence that denies the approval ("we do not think libc's build
   script is approved") or quotes it in a code block still approves the
   crate. The check of a strict edge (ADR-001) has the same property: it
   looks for the edge's name in the ADR's text. Both checks catch an
   approval that was forgotten, not an ADR written to sneak one in. Such an
   ADR has to pass review before it is accepted, and a change that passes
   review could just as well edit the check. Refusing negations or code
   blocks would cover two wordings and leave every other one, so the check
   stays a plain match and the review of an accepted ADR is the gate.
7. **License exceptions.** `deny.toml` allows per crate: ISC for `ring`,
   `untrusted` and `rustls-webpki`, BSD-3-Clause for `subtle`, and
   CDLA-Permissive-2.0 for `webpki-roots`. All three licenses are
   permissive and compatible with Apache-2.0; they require their notices
   in binary distributions. The exceptions name crates, not versions: a
   license that changes in an update still fails unless it is listed, so
   a version pin would only add churn.
8. **Fail closed.**
   - Certificates are always verified against the roots, and the API has
     no switch to turn verification off and no way to install a custom
     verifier.
   - `connect` and `connect_over` finish the handshake before they return,
     so a certificate error surfaces there, not on the first read. `connect`
     resolves with std, tries each address with the connect timeout, sets
     the read and write timeouts on the socket and does not try another
     address after a TLS failure.
   - The server name is checked before any I/O. rustls refuses names whose
     last label is a number (`127.1`, `0x7f000001`), the same rule ADR-003
     item 3 applies to hosts, so such a form never reaches `getaddrinfo`.
   - A TCP close without `close_notify` is an `UnexpectedEof` error, never
     the clean end of a body read until close. `TlsStream::close` sends
     `close_notify`.
   - No 0-RTT data: a replayed request to a paid API would be charged
     twice. The key log stays rustls' `NoKeyLog`, so `SSLKEYLOGFILE` is
     never read.
   - `ConnectOptions` has no defaults, for the reason of ADR-003 item 7:
     the right timeouts depend on the peer.
   - The handshake has a total deadline, `handshake_timeout`, on top of
     `io_timeout` for each read and write. Before every read and write
     during the handshake the stream's timeout is set to what is left of
     the deadline, at most `io_timeout`; when it runs out, the handshake
     fails with `TimedOut`. Afterwards both timeouts are `io_timeout`. It
     is the client's side of ADR-003 item 8: without it a peer that sends
     one byte just inside `io_timeout` holds `connect` for as long as it
     likes (759 bytes at 150 ms each take about two minutes, and with a
     30 s `io_timeout` hours). `connect_over` takes the same options and
     sets the same timeouts, so a tunnel through a proxy is bounded too;
     there `connect_timeout` does not apply, because the caller
     connected. A separate field and not the connect timeout for both:
     a TCP connection attempt and a handshake that crosses the network
     several times are different budgets, and the connect timeout applies
     to each address in turn.
9. **The idle check over TLS.** ADR-003 item 12 lets a client connection be
   reused only while nothing arrives between responses, asked through
   `IdleCheck` before every request. Over TLS the answer cannot come from
   the socket under it, for two reasons. rustls may already hold decrypted
   plaintext past a response, which the socket does not see. And a TLS 1.3
   server sends session tickets after the handshake: records without
   application data that a byte read on the socket would count as input,
   failing the first request on every TLS 1.3 connection. So `TlsStream`
   checks what rustls holds (plaintext not read, or `close_notify`), then
   switches the socket to non-blocking mode and feeds every record that
   has arrived into rustls, until the socket would block. Plaintext,
   `close_notify` or the end of the stream is input that has arrived;
   records without application data leave the connection idle. Nothing
   read is dropped. Part of a record is input too: rustls keeps it
   without a sign until the rest arrives, and the rest may be a response.
   If the head of an unsolicited response's record counted as idle, the
   next request would get that response as its answer. A 16 KiB record
   spans many TCP segments, and rustls can take the head of the next
   record in the same read as the end of a response, so this happens
   without a crafted peer. The stream under rustls therefore follows the
   record framing (a five-byte header whose last two bytes are the body
   length) of every byte it reads, from the first byte of the handshake
   on, and the connection is idle only when those bytes end at a record
   boundary. A session ticket that has partly arrived then ends the
   connection too; that fails closed and costs one reconnect. The socket
   must be able to switch modes (`Nonblocking`, implemented for
   `TcpStream`, `UnixStream` and a `Tunnel` over either).
   Rejected: answering "cannot tell", which would allow one request per
   TLS connection.

## Consequences

- Every crate that depends on `boneli-https` needs a C compiler to build.
  CI's `ubuntu-latest` has gcc. Release builds for aarch64 and musl need a
  cross C toolchain; that is part of the release work in #22. The C
  compiler's version is part of the build's input.
- Binary distributions must carry the ISC, BSD-3-Clause and
  CDLA-Permissive-2.0 notices of these crates (#22).
- Every new external crate with a build script now needs an ADR. A version
  update of an approved one does not; see item 6 for what that leaves to
  review.
- The idle check costs two `fcntl` calls and at least one non-blocking read
  per request, as on a plain socket (ADR-003).
- **Known limits**, each with the issue that closes it. Neither is part of
  #5:
  - No post-quantum hybrid key exchange: the ring provider has none.
    Replikanti/boneli#37 adds X25519MLKEM768 over the pure-Rust `ml-kem`
    crate.
  - No certificate revocation checking: rustls checks CRLs only when it is
    given them, and nothing fetches them yet. Replikanti/boneli#38 adds
    fetching and caching of CRLs.

## Alternatives considered

- **aws-lc-rs as the provider.** It has the post-quantum hybrid and FIPS
  builds, but `aws-lc-sys` is banned: a CMake build of a large C library
  and prebuilt objects.
- **native-tls or OpenSSL.** C TLS linked from the host; `openssl-sys` is
  banned in `deny.toml`.
- **The host's trust store,** directly or through `rustls-native-certs`:
  rejected in item 2.
- **rcgen for the test certificates.** A further crate for files that are
  generated once; the fixtures are made with `openssl`, and
  `crates/boneli-https/tests/data/README.md` records the commands.
