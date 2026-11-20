# ADR-016: Hybrid post-quantum key exchange X25519MLKEM768 over ml-kem

- Status: accepted
- Date: 2026-11-20

## Context

`boneli-https` (ADR-005) is the TLS client of every connection the runner
makes: customer code and prompts sent to LLM APIs, forge tokens, registry
pulls. Its ring provider offers X25519, P-256 and P-384 and no
post-quantum group, so every session it opens can be recorded today and
decrypted once a cryptographically relevant quantum computer exists
("harvest now, decrypt later"). ADR-005 lists this as a known limit and
points to issue #37. rustls' own post-quantum groups need the `aws-lc-rs`
provider, and `aws-lc-sys` is banned in `deny.toml` (ADR-005).

RFC 10024 (Standards Track, August 2026; it was the draft
draft-ietf-tls-ecdhe-mlkem) defines the hybrid group X25519MLKEM768 for
TLS 1.3, codepoint 4588 (0x11EC, section 7.1):

- the client's key share is the ML-KEM-768 encapsulation key (1184
  bytes) followed by the X25519 share (32), 1216 bytes (section 4.1);
- the server's share is the ML-KEM-768 ciphertext (1088) followed by the
  X25519 share (32), 1120 bytes (section 4.2);
- the shared secret is the ML-KEM secret (32) followed by the X25519
  secret (32), 64 bytes (section 4.3).

The RFC has no test vectors.

Who benefits, measured on 2026-11-20 while planning #37 with an OpenSSL
3.5.9 client that offered `X25519MLKEM768:X25519`: api.anthropic.com,
api.openai.com, generativelanguage.googleapis.com, gitlab.com and
pq.cloudflareresearch.com negotiated X25519MLKEM768; github.com,
api.github.com, ghcr.io and registry-1.docker.io negotiated X25519. All
nine completed a handshake with the 1216-byte share in the ClientHello.
So the traffic to LLM APIs gets the protection; GitHub forge tokens and
registry pulls stay classical until those hosts deploy the group, and
nothing on the client changes that.

Decided at #37 STOP 1 (2026-11-20): ADR-005 gets one sentence on its
post-quantum known limit pointing here, and `docs/adr/README.md` one
lifecycle sentence that allows such a pointer (D1); the opt-out
`TlsConfig::classical` lands with this ADR (D2, item 8); the crate is
`ml-kem` 0.3.4, whose never-independently-audited status the operator
accepted on the grounds of item 4 (D3, item 3).

## Decision

### 1. The construction: RFC 10024, client only

`boneli-https` gets a private module `pq` with one rustls key exchange
group, X25519MLKEM768: ML-KEM-768 (FIPS 203) from the RustCrypto
`ml-kem` crate, and X25519 from rustls' ring provider
(`rustls::crypto::ring::kx_group::X25519`), so the crate still takes no
direct `ring` dependency (ADR-005, item 1). The layout and lengths are
those of the Context; each constant in the code cites its section.

- **Server share length.** The client checks that the server's share is
  exactly 1120 bytes; anything else is `InvalidKeyShare`, which rustls
  answers with `illegal_parameter`, as section 4.2 requires.
- **X25519 checks.** ring checks the length of the X25519 part and
  refuses an all-zero result (section 4.3); the error is propagated, so
  the alert is the same.
- **Decapsulation.** ML-KEM decapsulation does not fail: a ciphertext of
  the right length that was tampered with yields a key the server does
  not have (FIPS 203 implicit rejection), and the handshake fails when
  the server's encrypted flight does not decrypt. The `internal_error`
  case of section 4.2 ("decapsulation fails for any other reason")
  therefore cannot occur with `ml-kem`.
- **TLS 1.3 only.** `usable_for_version` is true for TLS 1.3 alone; the
  RFC defines the group for TLS 1.3, whose transcript its security
  analysis relies on (section 6).
- **Client only.** `boneli-https` is a client (ADR-005). The trait's
  default server path (`start_and_complete`) is shaped for
  Diffie-Hellman and would be wrong for a KEM, so it returns an error.
- **Seed.** Each `start` draws a 64-byte seed (d followed by z) from
  `fill_random`, ring's source and the one rustls draws its handshake
  randomness from (RFC 10024 section 6 on the random generator), and
  makes the key with `DecapsulationKey::from_seed`, the FIPS 203
  `ML-KEM.KeyGen_internal` that the crate's random key generation calls
  too. A failing random source starts nothing; there is no fallback. The
  known-answer tests pass a fixed seed through the same function.
- **Wiping.** The seed buffer and the ML-KEM shared secret are wiped
  (`zeroize`); the decapsulation key is wiped on drop by `ml-kem`'s
  `zeroize` feature; rustls wipes the combined secret (`SharedSecret`).
  That feature wipes only the copy that is dropped, so the key is never
  moved out of the heap block rustls holds it in: `complete` uses it
  through the box and moves only the X25519 half out, and the key sits in
  a wrapper with a `Drop` impl (`PinnedKey`), which Rust does not let a
  field be moved out of. A unit test checks that the key is dropped at
  its address in the box after `complete` (success, wrong length,
  all-zero X25519), `complete_hybrid_component` and an unused drop.
  Review of #37 found the first version moving the whole state out of
  the box in `complete`, which left d and z in freed heap memory on every
  hybrid handshake.
  Nothing implements a `Debug` that prints key material: the group
  prints its name, the key exchange in progress has no `Debug`.

**Why a hybrid, and why this one:**

- **Pure ML-KEM-768** (`MLKEM768`) loses all security if ML-KEM turns
  out to be broken.
- **The concatenation** fed into TLS 1.3's HKDF keeps X25519's classical
  security whatever happens to ML-KEM, and ML-KEM's whatever happens to
  X25519 (RFC 10024 section 6 refers to the analysis of RFC 9954). A
  broken ML-KEM leaves the session exactly as strong as today's X25519.
- **SecP256r1MLKEM768** orders its parts for FIPS certification of the
  ECDHE half (RFC 10024 section 5), which Boneli does not need, and the
  runner's first classical group is already X25519.
- **X-Wing and other hashed combiners** have no TLS 1.3 codepoint, so no
  server would pick them.

### 2. The offer

`TlsConfig::new` offers, in this order, X25519MLKEM768, X25519,
secp256r1 and secp384r1, as an explicit list, so a rustls update that
changes ring's default groups cannot change the offer without a failing
test. The ClientHello carries two key shares, the hybrid and X25519.

- **Why the hybrid first.** rustls sends the key share of the first
  group, and adds the classical half of a hybrid as a second share only
  when the hybrid comes first and the classical group is in the list
  (`ActiveKeyExchange::hybrid_component`, rustls 0.23.46). With X25519
  first there would be no hybrid share, so a server that supports both
  would either pick X25519 or ask for a retry.
- **Why the second share.** A server without the hybrid picks X25519 from
  the same ClientHello, with no HelloRetryRequest, and the X25519 key
  pair is made once for both shares.
- **The key share hint.** rustls remembers per server name which group
  the server picked, in an in-memory store of 256 entries. A host that
  picked X25519 then gets a ClientHello with only an X25519 share, so it
  pays the larger ClientHello once per `TlsConfig`. A host that deploys
  the group later gets it once the entry is gone: on a restart, by
  eviction, or when it asks for a retry, which rustls answers by
  starting the hybrid (tested).

### 3. The crate: `ml-kem` 0.3.4

Verified while planning #37 on 2026-11-20, except where a check of this
PR is named:

- **Version and maintenance.** 0.3.4, published 2026-10-31; the
  downloaded `.crate` matched its crates.io SHA-256 (`84ca78b6…`). The
  RustCrypto/KEMs repository was active (last push 2026-11-18).
- **Use.** 16.9 million downloads on crates.io.
- **Tests.** Wycheproof and NIST ACVP vectors (its `tests/README.md` and
  `tests/wycheproof.rs`).
- **Audit status.** Its README says: "The implementation contained in
  this crate has never been independently audited!" (checked again in
  the 0.3.4 sources for this PR). The operator accepted this status at
  #37 STOP 1, on the grounds of item 4.
- **Advisories.** None: no RUSTSEC entry (advisory DB `074ea9a` of
  2026-11-19, equal to its upstream head then), no GitHub advisory, no
  published security advisory in RustCrypto/KEMs. `cargo deny check`
  on this PR reports `advisories ok`.

**What that evidence does not show:**

- **Tests and side channels.** `ml-kem`'s Wycheproof and ACVP runs, our
  known-answer tests and the OpenSSL interop prove functional
  correctness, not the absence of side channels. Nothing here measures
  timing.
- **"No advisory" proves less than it seems.** `ml-kem`'s own CHANGELOG
  lists timing hardening under "Security" in two releases, and neither
  has an advisory against `ml-kem`:
  - 0.3.3 (2026-10-17): "Eliminate secret-dependent CBD table lookups"
    (#386 of RustCrypto/KEMs). No RUSTSEC entry and no GitHub advisory
    references it.
  - 0.3.4 (2026-10-31): "Harden reduction using newly-hardened
    `ctutils`" (#409) and the bump of `ctutils` (#405). The underlying
    `ctutils` fix has its own advisory, RUSTSEC-2026-0385, filed
    against `ctutils` only.

  So an empty advisory list does not mean that no timing weakness was
  ever fixed; the project fixes such things in releases without always
  filing an advisory. What protects the runner is the minimum version
  below and the bound of item 4, not the empty list.

**Why at least 0.3.4,** not 0.3.0 or 0.2.x: 0.3.0 added encapsulation key
validation, 0.3.3 removed the secret-dependent table lookups in CBD
sampling, and 0.3.4 hardened reduction, equality and zeroization,
redacted secret key material from `Debug` output, bumped `ctutils` and
moved its MSRV to 1.87. 0.2.x has none of these. Through its
requirements 0.3.4 pins `module-lattice >= 0.2.4`, which pins
`ctutils >= 0.4.7`, which pins `cmov >= 0.5.4`. That puts every new
crate past the patched versions of all known advisories: `ctutils`
RUSTSEC-2026-0385 (below 0.4.4), `cmov` RUSTSEC-2026-0003 (below 0.4.4)
and GHSA-3rjw-m598-pq24 (below 0.5.4; not in RustSec, so `cargo deny`
would not catch a downgrade, which is why the floor comes from the
requirements and not from the advisory gate), and `keccak`
RUSTSEC-2026-0012 (below 0.1.6).

**Features:**

- `zeroize`: wipes the decapsulation key on drop. It adds no crate and
  three edges (`ml-kem`, `module-lattice` and `hybrid-array` into
  `zeroize`).
- No `alloc` (a default feature): it enables `pkcs8?/alloc`, and
  `cargo metadata`, which the architecture check reads, then lists
  `pkcs8`, `der`, `spki`, `const-oid` and `base64ct` as dependencies
  although `cargo tree` shows that none of them is built (measured while
  planning). Five records for crates that never compile would be noise
  in the policy.
- No `getrandom`: it would pull `getrandom` 0.4, a second getrandom
  with its own edge into `libc`. The seed comes from `fill_random`
  (item 1).

**MSRV.** The highest among the new crates is 1.87 (`ml-kem`,
`module-lattice`, `ctutils`), below the workspace's 1.89, which stays.

### 4. Why the ML-KEM risk is bounded

- **A broken `ml-kem`** leaves the session as strong as X25519 is today
  (item 1). The worst case of the unaudited code is the status quo.
- **Side channels.** The decapsulation key is ephemeral and used for one
  handshake, and the only party that supplies the ciphertext is the
  server, which knows the shared secret already. A timing leak in
  decapsulation tells no one anything they lack. What remains is a
  co-tenant on the same host timing the key generation.
- **A panic** ends the handshake: a denial of service, not a disclosure.
- **Memory safety** depends on the crates that contain `unsafe`. Lines
  that contain the keyword in `src`, as a pointer for review:
  `hybrid-array` 43, `cmov` 28 (inline assembly in three files),
  `cpufeatures` 11 (assembly in one file), `keccak` 10, `sponge-cursor`
  5, `ctutils` 1, `num-traits` 1. `ml-kem`, `module-lattice`,
  `rand_core` and `autocfg` have none; `sha3`, `shake`, `kem`,
  `crypto-common`, `digest` and `typenum` are `#![forbid(unsafe_code)]`.
- **The glue is our risk.** What review must cover: the split offsets and
  the concatenation order in share and secret; that the error of the
  X25519 half is propagated; the refusal of the server role; TLS 1.3
  only; the seed source (`fill_random`, no fallback); the wiping of the
  seed and of the ML-KEM secret; that the decapsulation key is never
  moved out of its box; that no `Debug` prints key material; the
  explicit group lists; the 49 policy records against the measured
  graph; that neither CI step can pass without running.

### 5. The approved crates

The graph `ml-kem` 0.3.4 adds without default features and with
`zeroize`, resolved with cargo 1.98.0 on 2026-11-20. All are
MIT OR Apache-2.0 and come from crates.io; `cfg-if`, `libc` and
`zeroize` are ADR-005 crates and only get new edges.

| Crate | Version | MSRV | Role | Pulled by |
| --- | --- | --- | --- | --- |
| `ml-kem` | 0.3.4 | 1.87 | ML-KEM-768 (FIPS 203) | `boneli-https` |
| `module-lattice` | 0.2.4 | 1.87 | ring and NTT arithmetic | `ml-kem` |
| `hybrid-array` | 0.4.15 | 1.85 | typed fixed-size arrays | `ml-kem`, `module-lattice`, `crypto-common` |
| `typenum` | 1.20.1 | 1.41 | type-level lengths | `hybrid-array` |
| `ctutils` | 0.4.8 | 1.87 | constant-time select and compare | `module-lattice`, `hybrid-array` |
| `cmov` | 0.5.4 | 1.85 | constant-time move | `ctutils` |
| `kem` | 0.3.0 | 1.85 | KEM traits | `ml-kem` |
| `crypto-common` | 0.2.2 | 1.85 | shared traits | `kem`, `digest` |
| `rand_core` | 0.10.1 | 1.85 | RNG traits in `ml-kem`'s API (we pass no RNG) | `ml-kem`, `kem`, `crypto-common` |
| `sha3` | 0.12.0 | 1.85 | SHA3-256 and SHA3-512 | `ml-kem` |
| `shake` | 0.1.0 | 1.85 | SHAKE128 and SHAKE256 | `ml-kem` |
| `digest` | 0.11.3 | 1.85 | hash traits | `sha3`, `shake` |
| `keccak` | 0.2.2 | 1.85 | Keccak permutation | `sha3`, `shake` |
| `sponge-cursor` | 0.1.0 | 1.85 | sponge buffering | `sha3`, `shake` |
| `cpufeatures` | 0.3.1 | 1.85 | CPU detection on aarch64 | `keccak` (aarch64 only) |
| `num-traits` | 0.2.19 | 1.60 | numeric traits | `module-lattice` |
| `autocfg` | 1.5.1 | 1.0 | build-dependency of `num-traits` | `num-traits` (build) |

`tools/architecture.toml` records each crate and each of the 32 edges
(`boneli-https -> ml-kem` and `boneli-https -> zeroize` included) with
`decision = "ADR-016"`: 49 records. Measured before they existed:
`tools/check-architecture.sh` reported 32 `dep-edge` failures and one
`dep-build-script` failure (`num-traits`); with them it is clean.

### 6. The edge `cpufeatures -> libc`

`cpufeatures -> libc` is a new edge into the strict crate `libc`
(ADR-001), on aarch64 Linux only: `getauxval(AT_HWCAP)`, so that
`keccak` can use the SHA3 instructions of the CPU. It is the same call as
ADR-005's ring edge into `libc`, and it runs in the process that holds the
TLS connection, never in the sandbox. `keccak` 0.2.2 has no feature
that turns the probe off: its one feature is `parallel`, and its
dependency on `cpufeatures` is unconditional on aarch64.

### 7. num-traits's build script is approved

`num-traits` 0.2.19 has a build script. It runs `autocfg`'s probe of
`1f64.total_cmp(&2f64)` with `$RUSTC` and prints one cfg; it compiles and
links nothing into the crate. The approval is per crate, not per
version, with the same weak spot ADR-005 item 6 describes: a later
version's script is reviewed only when its update is.

### 8. The opt-out `TlsConfig::classical`

`TlsConfig::classical(roots)` is the same configuration without the
hybrid: it offers X25519, secp256r1 and secp384r1 and sends one X25519
key share. Both constructors go through one private builder that takes
the group list, so they cannot drift in anything else (roots check,
versions, ALPN, SNI, no early data, no key log). Certificates are
verified as with `new`.

- **Why it exists although the nine-host probe passed:** the probe ran
  from one network, so it shows that those servers accept the larger
  ClientHello, not that a customer's network path does. A middlebox that
  drops a ClientHello spanning two TCP segments would otherwise block
  every connection to the host behind it.
- **Why it is not automatic:** retrying without the hybrid after a failed
  handshake would hand an active attacker a downgrade (drop the first
  ClientHello, get a classical session). It is an explicit choice per
  host.
- **Who chooses it:** the setting that selects it for a host belongs to
  the composition root and is part of #32.

### 9. Observability

`TlsStream::key_exchange_group()` returns the negotiated group, for the
tests, the interop check and runner logs.

### 10. Proof, and what each test does not prove

- **Known-answer tests with a fake X25519 half** (`src/pq.rs`, values in
  `tests/data/x25519mlkem768-kat.txt`): Wycheproof
  `testvectors_v1/mlkem_768_test.json` at commit
  `3fa63dd0344abb611f1fb1d77e119938603ea230`, tcId 2 (FIPS 203, round 3
  seeds 0) and tcId 194 (implicit rejection, `MalleableCiphertext`), and
  the RFC 7748 section 6.1 X25519 values. They prove our byte layout,
  offsets and order against literal values from two independent
  sources. They do not prove that our reading of RFC 10024 is right: the
  expected value is assembled from the same reading.
- **Known-answer test with ring's X25519:** the real classical half sits
  at bytes 1184..1216 of the client share and 1088..1120 of the server
  share, and its secret lands at 32..64. X25519's own correctness is
  ring's.
- **Local rustls handshakes** (`tests/pq.rs`): the codepoint, both key
  shares and the ClientHello on the wire (parsed from the first record),
  no retry on fallback, the retry path, the TLS 1.2 exclusion,
  resumption, `TlsConfig::classical` (no hybrid group and no hybrid share,
  1222 bytes shorter), a CONNECT tunnel, and servers with a short, long,
  zero, reversed or tampered share (the error, the `illegal_parameter`
  alert, and one connection, no retry). They do not prove
  interoperability: the test server half is written from the same
  reading, so a mirrored layout error passes them.
- **OpenSSL interop** (`tests/interop.rs`, CI on every PR): the only test
  that checks the reading. OpenSSL's independent ML-KEM and hybrid code
  must derive the same 64-byte secret in each of 32 full handshakes with
  a fresh configuration, or the server's Finished would not verify and
  no response would come back; it also shows that OpenSSL's FIPS 203
  section 7.2 check accepts our encapsulation keys. Why 32: one
  handshake samples one key pair, and 32 catch a fault that hits 10% of
  key pairs with probability 1 - 0.9^32, about 0.97; 100 would raise
  that to 0.99997 at three times the cost, for a class of fault the
  known-answer tests and `ml-kem`'s own vectors already cover. It
  fails, not skips, without OpenSSL 3.5 or the group. It does not cover
  aarch64 or hostile servers.
- **The arm64 known-answer step** (CI, `sandbox (arm64)`): the
  known-answer tests on aarch64, where `keccak` 0.2.2 picks a backend
  with the SHA3 instructions at run time; no other CI job runs
  `boneli-https` code on arm64.
- **The live test** (`tests/network.rs`, by hand before a change to
  `src/pq.rs` or to the group lists merges): pq.cloudflareresearch.com,
  a second independent production stack, answers `kex=X25519MLKEM768`
  from the server side, and the larger ClientHello crosses a real
  network. Not in CI, because it depends on a third party.
- **Not proven by any of them:** resistance to an active attacker who
  rewrites the ClientHello. TLS 1.3 binds the ClientHello into the
  transcript the server signs (RFC 8446, section 4.4); that is rustls'
  job.

## Consequences

- **Bytes per connection:** the first ClientHello to a host grows by
  1222 bytes (1216 of share, 4 of entry header, 2 for the group in
  `supported_groups`); the ServerHello grows by 1088 bytes when the
  hybrid is picked (1120 - 32). The ClientHello no longer fits one TCP
  segment of about 1460 bytes.
- **Time per connection:** one ML-KEM key generation per connection,
  also to hosts that then pick X25519, plus a decapsulation when the
  hybrid is picked. Measured on 2026-11-20 on the development machine
  (Intel i7-1355U, release build, 1000 runs, two runs): the median of
  `start` plus `complete` was 340 µs (the two runs gave 345 µs and
  340 µs), against 86 µs for an X25519 key pair and agreement alone, so
  the hybrid adds about a quarter of a millisecond per full handshake,
  small next to one network round trip.
- **Every TLS user changes at once** (the OCI store, the GitHub forge,
  the future gateway). The fallback and retry tests, the host probe and
  the `oci-acceptance` workflow on both architectures cover the paths
  that matter.
- **A defect in `ml-kem` or `keccak` on one platform** would fail every
  handshake with hosts that pick the hybrid, which today includes the
  LLM APIs: an availability risk, not a confidentiality one. The
  known-answer tests on x86_64 and arm64 and the interop on every PR
  guard it.
- **Forge and registry traffic stays classical** until those hosts
  deploy the group.
- **The policy grows by 49 records,** one new edge into `libc` and one
  approved build script.
- **`ml-kem` may raise its MSRV in a patch release** (its README). The
  workspace resolver is `"3"`, so `cargo update` keeps versions that fit
  `rust-version = "1.89"`.
- **Known limits, each closed:**
  - `ml-kem` is not independently audited: closed by evidence (item 4)
    and accepted by the operator at STOP 1; item 3 states what the
    evidence does not show.
  - A host behind a middlebox that drops a two-segment ClientHello:
    closed by `TlsConfig::classical` (item 8); its setting is part of
    #32.
  - Copies of key material on the stack are not wiped (Rust cannot
    promise it): closed by evidence. The key is ephemeral and used for
    one handshake, and an attacker who can read process memory reads the
    live traffic keys anyway; the seed buffer, the ML-KEM secret, the
    decapsulation key and rustls' combined secret are wiped.
  - The aarch64 code paths (`keccak`'s SHA3 backend, `cpufeatures`):
    closed by the arm64 known-answer step and the `oci-acceptance`
    workflow, which runs on both architectures.
  - An active downgrade, stripping the hybrid: closed by evidence. It
    needs a forged transcript signature during the handshake, which the
    classical part prevents today; a passive harvest-now attacker cannot
    downgrade.
  - The key share hint keeps X25519 for a host that deploys the group
    later: closed by evidence. The hint is set only after a verified
    handshake, lives in memory per process, and clears on restart, by
    eviction from the 256-entry store, or when the server asks for a
    retry.
  - ADR-005 still listed the limit as open: closed by its forward
    pointer to this ADR and the lifecycle sentence in
    `docs/adr/README.md`.

## Alternatives considered

Checked on crates.io and in the advisory DB on 2026-11-20.

- **`aws-lc-rs` as the provider,** which has the group built in:
  `aws-lc-sys` is banned (ADR-005).
- **`libcrux-ml-kem` 0.0.12.** For: Cryspen states formal verification
  (taken from Cryspen, not verified here). Against: a 0.0.x crate with
  exact `=` pins on five libcrux crates; `libcrux-platform` adds a
  further edge into `libc`; four advisories on its `libcrux-sha3` and
  `libcrux-intrinsics` between 2025-12 and 2026-05 (wrong output,
  panic); 4.9 million downloads.
- **`fips203` 0.5.0:** 0.8 million downloads and a smaller maintainer
  base than RustCrypto.
- **`pqcrypto-mlkem`:** C from PQClean, unmaintained (RUSTSEC-2026-0161);
  a C build is what ADR-005 allows only for ring.
- **`pqc_kyber`:** unmaintained, and vulnerable to KyberSlash
  (RUSTSEC-2023-0079).
- **Copying rustls' generic `Hybrid` with a configurable layout:** the
  runner needs exactly one layout, and a fixed one leaves less glue to
  review.
- **Waiting for a post-quantum group in rustls' ring provider:** rustls
  0.23.46 ships the group only for `aws-lc-rs`.
