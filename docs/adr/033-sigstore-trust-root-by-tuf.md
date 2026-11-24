# ADR-033: Keeping Sigstore's trusted root current through TUF

- Status: accepted
- Date: 2026-11-24

## Context

ADR-029 verifies keyless image signatures against the operator's
`trusted_root.json`, read once and never updated by Boneli. Its known
limit: "Rotation depends on the operator replacing `trusted_root.json`; a
stale file refuses signatures from new logs or CAs." Sigstore publishes
that file as a target of a TUF repository (The Update Framework,
specification 1.0), whose metadata chain says which file is current and
protects the client against rollback, freeze and mix-and-match attacks.
Issue #103 asks for a client that keeps the file current, with an ADR
that decides own code or a crate, the bootstrap of trust, and when the
refresh runs.

Measured on 2026-11-24, anonymously, over HTTP/1.1 from a developer host:

- **The repository** `tuf-repo-cdn.sigstore.dev` (Google Cloud Storage
  behind Google's CDN) answers HTTP/1.1 with `Content-Length` and no
  content coding. A missing object is `404` with a 127-byte body. The
  response head of `timestamp.json` is 735 bytes with 20 fields. No
  redirects.
- **The root chain** has versions 1 to 16; `17.root.json` is 404. The
  files are 4,809 to 6,911 bytes (largest: v10). The root role is 3 of 5
  keys in every version, and so is targets. Timestamp and snapshot are 1
  of 1 and share one online key since v10. The timestamp key changed at
  v2, v5, v9, v10 and v12. `consistent_snapshot` is true from v5 on.
  - Every key is ECDSA P-256 under scheme `ecdsa-sha2-nistp256`. The key
    type is `ecdsa-sha2-nistp256` up to v8 and `ecdsa` from v9. v1 to v4
    carry hex points, v5 to v16 PEM SPKI.
  - `expires` is `YYYY-MM-DDTHH:MM:SSZ` from v4 on. v1 has an offset with
    a fraction (`…12.99008-06:00`), v2 and v3 have nanoseconds.
  - No root lists one key under two key IDs. In v11 one key ID is not the
    SHA-256 of its key entry's canonical form, so key IDs are opaque
    labels, not hashes a client can check.
  - Roots v12 to v14 carry signatures with an empty `sig` (1 or 2 each),
    and v9 carries 10 signatures, old and new keys, for 5 role keys.
  - Expiry dates run from 2021-12-18 (v1) to 2027-04-22 (v16): 15
    rotations in about 5.3 years, about 2.8 a year. That rate is inferred
    from expiry dates, not signing dates. Root v16 declares an expiry
    period of 197 days and a signing period of 46.
- **Current metadata:** `timestamp.json` v842 is 447 bytes, expires
  2026-11-30T01:20:52Z, expiry period 7 days, signing period 6, and names
  snapshot v166 by version only. `166.snapshot.json` is 1,760 bytes, 6
  entries of at most 304 bytes, and lists `targets.json` v14 by version
  only; four entries are stale ones of an old layout. `14.targets.json`
  is 4,942 bytes, 11 targets of at most 287 bytes and one delegation
  (`registry.npmjs.org/*`, terminating).
- **`trusted_root.json` is a top-level target:** 6,787 bytes, SHA-256
  only, served at `targets/6494e21e….trusted_root.json`, byte for byte
  the file ADR-029 verifies against
  (`crates/boneli-sigstore/tests/data/sigstore-trusted-root.json`).
- **Largest JSON depth and value counts:** root 6 / 124, timestamp 5 /
  13, snapshot 6 / 39, targets 7 / 120.
- **The canonical form** that the repository signs: sorted keys, no
  whitespace, only `\` and `"` escaped, control characters raw (the PEM
  keys hold line feeds), integers only. With that rule every signature
  verifies under the measured thresholds: each root v2 to v16 against its
  predecessor's keys and its own, and timestamp, snapshot and targets
  against v16's keys.
- **Fetch times** (25 fetches with curl, so without a revocation check):
  each at most 0.47 s; one honest refresh of 5 requests took 1.06 s. The
  CDN's leaf (Google Trust Services WR3) names one CRL of 335,587 bytes,
  fetched in at most 0.17 s (3 runs).
- **TUF crates**, with no default features, normal and build edges:
  `tough` 0.24.0 has 106 crate names, among them tokio, serde,
  serde_json and aws-lc-sys; `tuf` 0.3.0-beta9 75, with serde,
  serde_json, thiserror and a second `ring` (0.16.20); `sigstore-tuf`
  0.17.0 52, with serde, serde_json, thiserror and tracing; `tuffet`
  0.1.0 39, with serde, serde_json, thiserror and tracing. The
  workspace's whole external graph is 36 crate names.

## Decision

The client was built in three PRs under #103: PR 1 the canonical form,
signatures, thresholds and the root chain; PR 2 timestamp, snapshot,
targets and the target; PR 3 the refresh with its fetches and trust
directory, the live run, and the acceptance of this ADR.

1. **Own code**, in the support crate `boneli-tuf`, on `boneli-https`
   (`PublicKey`, `Sha256`, and later `Dial`), `boneli-json` and
   `boneli-sigstore` (the RFC 3339 reader, and `TrustedRoot::from_json`
   as the last gate before a file is installed). No external crate and no
   new external edge. The crate joins `roles.support` and the list of
   crates the adversarial reviewer always reads (S1).
2. **The workflow** is the TUF specification's 5.1 to 5.7, top-level
   roles only (S3):
   - **Start time.** One start time for every expiry check, passed in by
     the caller (5.1). The pure core reads no clock.
   - **Root chain** (5.3). Fetch `N+1.root.json` until a 404. Each new
     root must be signed by a threshold of N's root keys and by a
     threshold of its own; have version exactly N+1 (a checked add, so
     `i64::MAX` has no successor and nothing is fetched); have `_type`
     `root`; and be persisted before the next one is fetched. The
     expiry of intermediate roots is not checked; the newest root must
     not be expired (5.3.10). When a new root changes the key material or
     the threshold of timestamp or snapshot against its predecessor, the
     stored timestamp and snapshot are dropped (5.3.11, fast-forward
     recovery); the signal is sticky over one update. The refresh deletes
     them before it stores the root that changed the keys: a run that
     stops after storing that root would otherwise leave them to the next
     run, whose set starts from that root and sees no change. Sigstore changed
     the timestamp key 5 times. The pure core enforces the drop as well:
     after such a root it refuses to load a stored timestamp or snapshot
     (`OnlineKeysChanged`), so a copy that still verifies (only the
     snapshot key moved, or a threshold changed) cannot hold back the
     recovered repository's versions.
   - **Order.** The core takes the steps in one order and refuses a
     call out of it (`OutOfOrder`): roots, the stored timestamp, the
     timestamp, the stored snapshot, the snapshot, targets, the target.
     No root is accepted once a timestamp is held; the stored snapshot
     and the snapshot both need a timestamp verified in this update (a
     stored copy is not enough), so a stored snapshot is never read under
     a root the chain later replaces; and targets need a verified
     snapshot. Each step runs once, except that
     a timestamp may be updated again before the snapshot, against the
     one it replaces. A step that fails leaves the set as it was.
   - **Timestamp** (5.4). No timestamp is trusted while the trusted
     root has expired (5.3.10 again, so the core does not depend on the
     caller's order of checks). Its version must not be below the stored
     one, and its snapshot version must not be below the stored
     timestamp's. An equal version is allowed and passes every check
     again. Threshold, `_type`, and expired when `start >= expires`.
     `meta` must hold `snapshot.json`; other entries are not read.
   - **Snapshot** (5.5), fetched as `V.snapshot.json`. Length and SHA-256
     are checked when the timestamp lists them, on the bytes before they
     are parsed. Threshold, `_type`, version equal to the timestamp's
     entry, expiry. Every entry of the stored snapshot must still be
     there with a version at least as high; the errors name no entry,
     because entry names are metadata text. Every entry of `meta` must be
     an object with a version of at least 1, and `meta` must hold
     `targets.json`; lengths and hashes are read only for `targets.json`,
     the one file fetched from it, so a stale entry with another hash
     algorithm refuses nothing.
   - **Targets** (5.6), fetched as `V.targets.json`. Length and SHA-256
     when listed, before parsing; threshold, `_type`, version equal to
     the snapshot's entry, expiry. `targets` must be an object; only the
     looked-up entry is read.
   - **Target** (5.7). `trusted_root.json` is looked up byte-exact
     in top-level `targets` and fetched as
     `targets/<sha256>.trusted_root.json`. Its length is exact and its
     SHA-256 must match. The entry's `length` is a non-negative integer
     and its `hashes` is required.
   - **The hash rule** (snapshot and targets entries, and the target): a
     hash map is an object holding `sha256` as 64 lower-case hex
     characters, the form Sigstore and securesystemslib write; other
     algorithms are not read. A map without `sha256` is refused
     (`NoSha256`), not skipped: the repository asked for a check this
     client cannot make. A listed length is a non-negative integer.
   - **Refused outright:** delegations are never followed (a target
     found only in a delegation is "not listed"), and a repository
     without consistent snapshots is refused.
3. **Signatures and thresholds.**
   - One key kind counts: key type `ecdsa` or `ecdsa-sha2-nistp256`,
     scheme `ecdsa-sha2-nistp256`, and a `PUBLIC KEY` PEM that
     `PublicKey::from_pem` reads as P-256 (S3). Every other key, and every
     signature that does not decode (hex of either case) or verify,
     counts zero. The document is not refused, so a root can add a key of
     another kind and still pass on the threshold of the others.
   - A threshold counts **distinct SPKI DER**, not key IDs: two key IDs of
     one key, or one key ID listed twice, count once. Measured: no
     Sigstore root lists a key twice, so this rule costs nothing there.
   - Only signatures whose key ID is in the role's list are checked, and
     only the first entry for each key ID. Key IDs compare byte for byte;
     a look-alike (another script, a zero-width character, another case)
     is another key ID.
   - In a role, duplicate key IDs, a key ID missing from `keys` and a
     threshold below 1 refuse the document. A threshold above the number
     of keys refuses only by never being met. The root must list all four
     top-level roles.
   - **Test-time signing** (S4): `boneli_https::EcdsaP256Key`, ECDSA P-256
     with SHA-256 through ring's key provider, the one scheme production
     accepts. Fixture repositories are signed with it at test time, so no
     second scheme (such as `rsa-pkcs1v15-sha256`, which Sigstore never
     uses) exists only for tests.
4. **Parsing is strict where it decides.**
   - `boneli-json` under per-role limits, duplicate keys refused.
   - The envelope is an object with a `signed` object and a `signatures`
     array of objects with string `keyid` and `sig`. Other top-level
     members and other members of a signature object are unsigned and
     not read.
   - `_type` and `spec_version` compare byte-exact; `spec_version` must
     be `1.<n>` or `1.<n>.<m>` without leading zeros.
   - `expires` is exactly 20 bytes and read with
     `boneli_sigstore::time::parse`, so no fraction, no offset and no leap
     second.
   - Integers are canonical lexemes (`0` or `-?[1-9][0-9]*`, within
     `i64`, `-0` refused). Versions are at least 1. A fraction or an
     exponent anywhere in `signed` refuses the document, because the
     canonical form has no floats.
   - The bytes that are verified are the canonical form of the parsed
     `signed` value, and every field read comes from that same value.
5. **The initial root** is an operator input,
   `InitialRoot::new(bytes, sha256_hex)`. The bytes must hash to the pin
   and pass their own root threshold.
   - It is used only when the trust directory has no stored root yet, and
     its SHA-256 is recorded there (`tuf/pin`).
   - A later refresh with another pin fails at `InitialRoot` until the
     operator removes `tuf/`, so a changed pin is never ignored silently
     (S5).
   - **Not embedded**: an embedded root makes every Boneli upgrade a
     change of whom the operator trusts; ADR-029 S2 left trust to the
     operator ("no embedded copy"); and a root from our release has a date
     the operator cannot see and did not verify.
   - The earliest Sigstore root the rules accept as a pin is v5: v1 to v4
     carry hex keys, which count zero, and v1 to v3 a non-TUF `expires`.
6. **Trust directory** (S5). One private directory under the rules
   of ADR-021 (`boneli_private_dir::prepare_root`) holds
   `trusted_root.json`, which the verifier's configuration (#32) reads;
   `tuf/root.json`, `tuf/timestamp.json` and `tuf/snapshot.json`, the
   fetched bytes unchanged; `tuf/pin`; and `tuf/lock`.
   - The whole refresh holds `FileLock::try_take(Kind::Exclusive)` on
     `tuf/lock` (ADR-030); a second refresh fails at `Lock` with "busy".
     `tuf/` must be a directory, not a symlink.
   - Writes go to a temporary name in the same directory with
     `create_new` and mode 0600, then `sync_all`, rename, and a sync of
     the directory. The temporary name is `.tmp-<name>`, one per file,
     because under the lock no other refresh writes; every `.tmp-` name
     in the two directories is a crashed run's and is removed under the
     lock.
   - The pin is recorded before the initial root is stored, so a stored
     root always has one. A recorded pin other than the initial root's,
     and a stored root without a pin, fail at `InitialRoot` and name the
     remedy (remove `tuf/`).
   - A stored root that does not parse or verify against itself fails the
     refresh at `Root` and names the remedy (remove `tuf/`); it never
     falls back to the pin. A stored timestamp or snapshot that fails to
     parse or verify under the current root, or is above its role's cap,
     is ignored, and its expiry is never checked, so it serves only for
     rollback checks. Only verdicts on the copy are ignored: the core's
     `OutOfOrder` from such a load fails the refresh, because it means
     the refresh called the core out of its order, and ignoring it would
     drop the rollback checks without a trace.
   - `trusted_root.json` is replaced only after every TUF step passed, the
     target's length and SHA-256 matched, and `TrustedRoot::from_json`
     read it. When the file on disk is a regular file with the target's
     length and SHA-256, nothing is fetched or written
     (`Outcome::Unchanged`); a symlink there is never followed, and the
     rename replaces it. TUF
     state advances as the specification persists it, and the output file
     stays untouched on every failure.
7. **Fetches** go through `boneli_https::Dial` (`TlsDial` in
   production, so revocation by ADR-017, ADR-020 and ADR-027 and name
   resolution by ADR-022 apply under each request's deadline), as the
   clients of `boneli-oci` and `boneli-forge-github` do: one `GET` per
   file with `Host` only; `200` only, except `404` for `N+1.root.json`,
   which ends the chain (the fetch reports a `404`, and the caller decides
   that it ends only the root chain); every other status and every redirect is an
   error naming the file; a content coding other than `identity` is
   refused; a `Content-Length` above the cap or other than the listed
   length fails before the body is read; the body has a cap per role and
   is read exactly when its length is known. A length the referring
   metadata lists above the role's cap is refused before the request. The repository is
   `Repository::parse("https://<host>[:port][/<prefix>]")`: https only,
   no userinfo, query, fragment or percent sign, prefix segments
   `[A-Za-z0-9._~-]+` and not `.` or `..`, host in ADR-003's grammar.
   Only that host is ever dialed.
8. **Operator action** (S6). `refresh_trusted_root` is a library call
   that spawns no thread; nothing in the workspace calls it but its
   tests. The operator's command is a `trust refresh` subcommand of
   `boneli-cli` (#32's scope); a background or periodic refresh in the
   runner stays out (#33). Run it weekly: the timestamp expires 7 days
   after signing, so a weekly run refuses a frozen repository at most 14
   days after the freeze. Run it also whenever a signature is refused for
   an unknown log or CA.
9. **Errors.** The pure core's `Error` and the refresh's
   `RefreshError { step, detail }` (`step` one of `Lock`,
   `InitialRoot`, `Root(version)` (`Root(None)` for the stored root, whose
   version is unknown when it does not parse), `Timestamp`, `Snapshot(version)`,
   `Targets(version)`, `Target`, `TrustedRoot`, `Write`) carry fixed
   reasons that echo file names, role names, versions, statuses, sizes
   and hosts, never metadata text.

### Limits and how each number was derived

All limits are inclusive, and each has an at-limit and an over-limit
test.

| Limit | Value | Derivation |
| --- | --- | --- |
| `MAX_ROOT_BYTES` | 65,536 | The largest root is 6,911 bytes, so the cap is 9.5 times that. A signing key costs about 854 bytes (key entry 550, signature 234, key ID in a role about 70), so the cap holds about 76 signing keys against today's 6. Below about 7 KB today's v10 is refused; higher only costs memory. |
| `MAX_TIMESTAMP_BYTES` | 16,384 | Measured 447 bytes, 36.7 times that. One entry of at most 304 bytes (two hashes) plus 234 bytes per signature: about 68 signatures. |
| `MAX_SNAPSHOT_BYTES` | 1,048,576 | Measured 1,760 bytes (595 times). At 304 bytes per entry about 3,449 roles; entries grow with delegated roles (Sigstore: 1 live, 4 stale). |
| `MAX_TARGETS_BYTES` | 1,048,576 | Measured 4,942 bytes (212 times). At 287 bytes per target about 3,650 targets. |
| Target length | at most `boneli_sigstore::MAX_TRUSTED_ROOT_BYTES` (1,048,576) | ADR-029's own cap on the file this target becomes; checked against the targets entry before the request, so a larger file is never fetched. |
| `MAX_JSON_DEPTH` / `MAX_JSON_VALUES` | 16 / 65,536 | ADR-009 D12's document limits, also ADR-029's: the same parser over documents of the same scale. Measured at most 7 / 124, so 2.3 and 528 times that. A depth below 7 refuses today's targets. Under the root and timestamp caps the value limit is never reached (two bytes per value at least); it bounds snapshot and targets. |
| Response head | 16,384 bytes / 64 fields | D12. Measured 735 bytes / 20, so 22 and 3.2 times that. |
| `MAX_ROOT_ROTATIONS` | 32 per run | 15 rotations measured in about 5.3 years (inferred about 2.8 a year), so 32 is about 11 years of lag. A run verifies and persists at most 32 new roots; a 33rd `200` stops it with an error (the 32 roots stay) and the next run continues. The cap bounds one run (at most 33 root requests), not how far behind a directory may be. |
| Timeouts | connect 10 s, handshake 10 s, io 30 s, setup 30 s, `min_rate` 1,048,576 B/s | D12's values and reasons. `setup` is 63 times the slowest measured TUF fetch (0.47 s). With the measured connect and TLS of about 0.1 s it leaves about 29.9 s for the leaf's CRL inside the first request: about 29.9 MiB at `min_rate`, 93 times the measured 335,587 bytes. The CRL is cached per `TlsConfig` for 24 h, so one run fetches it once. |
| Deadline per fetch | `setup + size / min_rate`, `size` the cap, or the exact length when listed | Root 30 + 65,536 / 1,048,576 = 30.0625 s. Timestamp 30.015625 s. Snapshot and targets 31 s. Target at most 31 s. |
| Worst-case run | 37 requests, 1,115 s | A server that trickles every answer to its deadline: 33 × 30.0625 (roots) + 30.015625 + 31 + 31 + 31 = 1,115.08 s, about 18.6 min. An honest run is 5 requests (root 404, timestamp, snapshot, targets, target), 1.06 s measured; a run that finds `trusted_root.json` current makes 4. |

`EcdsaP256Key::MAX_PEM_LEN` is 16,384 bytes: a P-256 key is 241 bytes of
PKCS#8 PEM and 643 bytes with OpenSSL's text dump in front, so the cap is
25 times that, and it equals `RsaSha256Key::MAX_PEM_LEN` so that the one
fixed sentence of `KeyError::TooLarge` stays true for both key types.

## Consequences

- A second security-critical verifier is ours to keep correct. Every
  check has a negative test and a killed mutant (the mutation table of
  each PR); thresholds count distinct keys; the canonical form is pinned
  by known answers on 12 real roots (11 rotations) and on 3 online files
  (timestamp v842, snapshot v166, targets v14), whose `trusted_root.json`
  target is byte for byte ADR-029's fixture; the reviewer reads every PR
  of the crate.
- A canonical-form or format mismatch can only refuse: the known answers
  prove that today's repository passes, and the weekly live run
  catches upstream drift within a week, for example a new key type in a
  threshold position, `trusted_root.json` moved into a delegation, or a
  changed `expires` form. Failure is closed: the old file stays.
- `boneli-https` exports a signing type, `EcdsaP256Key`, whose only
  callers are tests. It adds no crate and no edge (ring is already a
  direct dependency), and it lives in a crate the reviewer always reads.
- If the trust directory is lost, the next run bootstraps from the pin
  again, and rollback protection restarts from the served versions, as
  for any new TUF client. If the stored root is corrupt, the run fails
  closed and names the remedy.
- ADR-029 S6 re-verifies kept evidence under the current root, so after a
  refresh that drops a log or CA, evidence that only the old root
  verified goes back to discovery. That is the intended effect.
- **Known limits**, each with where it closes:
  - Until #32 lands an operator has no command, only the API and the live
    test (S6).
  - If Sigstore moves `trusted_root.json` into a delegation or adds a key
    kind that a threshold needs, the refresh fails closed until a
    follow-up adds it (S3).
  - An operator who keeps `trusted_root.json` elsewhere (a root-owned
    configuration directory) must point #32's configuration at the trust
    directory, and hand edits there are overwritten by the next refresh
    (S5).
  - Rekor v2 and TSA time (#102), `signing_config*.json` targets, mirrors
    and private TUF repositories beyond the pinned initial root, and a
    refresh inside the runner (#33) are out of scope.

## Alternatives considered

- **`tough`, `tuf`, `sigstore-tuf` or `tuffet`.** Every dependency tree
  holds crates that `deny.toml` bans (serde, tokio, tracing, aws-lc-sys,
  a second ring), at 39 to 106 crate names against the workspace's 36.
  Rejected.
- **The client inside `boneli-sigstore`.** Its documented property is "no
  clock, file, network or thread" (ADR-029, Consequences), which the
  refresh breaks. Rejected; `boneli-tuf` depends on it instead.
- **Counting distinct key IDs.** One key listed under two key IDs would
  count twice, and key IDs are opaque labels here (v11). Distinct SPKI
  costs nothing on Sigstore's roots. Rejected.
- **Accepting `rsa-pkcs1v15-sha256` to sign fixtures with `RsaSha256Key`**
  (as ADR-029 did for its test PKI). It adds a scheme Sigstore never uses
  to production only for tests. Rejected for `EcdsaP256Key` (S4).
- **An embedded initial root.** Rejected for the three reasons in item 5.
- **Following delegations.** The only delegation is npm's, and
  `trusted_root.json` is a top-level target; a delegation walk is code
  that only adds ways to accept. Rejected until a target moves (S3).
- **A background refresh in the runner.** Rejected by #103's acceptance
  criteria; the runner's own scheduling is #33.

## Accept when

PR 3 lands: a refresh from the pinned Sigstore v16 against
`tuf-repo-cdn.sigstore.dev` installs a `trusted_root.json` whose SHA-256
equals the target's, by hand and in the weekly `oci-acceptance` workflow
on both architectures, and every mutant of the three PRs is killed.

Met on 2026-11-24 with PR 3:

- **By hand** (`cargo test -p boneli-tuf --test network -- --ignored`,
  developer host, `TlsDial` with the Mozilla roots): from the pinned v16
  into an empty trust directory in 1.9 s with 5 requests (`17.root.json`
  404, timestamp v843, snapshot v166, targets v14, the target). The
  installed `trusted_root.json` is 6,787 bytes with SHA-256 `6494e21e…`,
  the target's, and byte for byte ADR-029's fixture. A second run found it
  current (`Outcome::Unchanged`) in 1.0 s with 4 requests.
- **In `oci-acceptance`** on x86_64 and arm64, the step "Refresh
  Sigstore's trusted root through TUF" of PR 3's own run (the workflow
  runs on a PR that edits it): the same versions and the same SHA-256 on
  both, the first run in 0.81 s (x86_64) and 0.72 s (arm64), the second
  `Outcome::Unchanged`.
- **Mutants:** 38 in PR 1, 44 in PR 2 and 51 in PR 3, each run against
  the crate's whole suite; all killed (the tables are in the PR bodies).
