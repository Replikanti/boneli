# ADR-041: GitHub's trusted root through TUF

- Status: proposed
- Date: 2026-11-26

## Context

ADR-040 verifies GitHub private-repository attestations against GitHub's
own trusted root (0 Rekor logs, 0 CT logs, 6 Fulcio CA chains, 6
timestamp authorities). Its known limit: "GitHub's root is captured by
hand (`gh attestation trusted-root`); the TUF refresh of ADR-033 covers
Sigstore's public-good repository only. Closure: #137". GitHub has added
a CA and TSA window every 147 to 232 days since 2023-10-27, and a stale
copy makes every new private-repository image fail closed with
`Timestamp(SigningCertificate)`. ADR-033 left "mirrors and private TUF
repositories beyond the pinned initial root" out of scope, so nothing
refreshes this root today. Issue #137 asks for an ADR that decides the
pin, the trust directory, and the rule that a refresh of one root never
touches the other root's directory.

Measured on 2026-11-26, anonymously over HTTP/1.1 from a developer host.
The probe ran the unchanged `refresh_trusted_root` of main; the files are
committed as captured (`crates/boneli-tuf/tests/data/README.md`):

- **The repository** `https://tuf-repo.github.com` is GitHub Pages behind
  Fastly. The head of `timestamp.json` is 686 to 708 bytes with 22 to 23
  fields (two measurements), with `Content-Length` and no content coding.
  A missing file is `404` with a 9,379-byte body. Only the current
  snapshot and targets are served (`83.snapshot.json` and
  `9.targets.json` are 404). The index page names `github/prod-tuf-root`
  as its source, which is not public.
- **The root chain** has versions 1 to 9; `10.root.json` is 404. The
  files are 6,537 to 7,660 bytes, at most depth 6 and 127 JSON values.
  - Every root has `spec_version` `1.0.31` and `consistent_snapshot`
    true, and every key is `ecdsa` / `ecdsa-sha2-nistp256` as a PEM SPKI,
    8 or 9 keys per root, none under two key IDs. There are no
    delegations.
  - Root and targets are 3 of 7 or 8, the same keys; timestamp and
    snapshot are 1 of 1, one shared online key unchanged from v1 to v9,
    so the 5.3.11 drop never fires.
  - Each root carries 4 to 8 non-empty signatures against its threshold
    of 3 (v4 has the smallest margin, 4 non-empty of 8).
  - Every `expires` is the 20-byte `YYYY-MM-DDTHH:MM:SSZ` form, so the
    rules of ADR-033 accept every version v1 to v9 as a pin (unlike
    Sigstore's v1 to v4).
  - The roots declare an expiry period of 240 days and a signing period
    of 60. v1 expired on 2024-06-23 and was so signed about 2023-10-27;
    v9 expires on 2027-01-28T20:18:53Z, so v10 is due from about
    2026-11-29. That is 8 rotations in about 3.1 years, about 2.6 a year,
    inferred from expiry dates, not signing dates.
- **Online metadata:** `timestamp.json` v1027 is 450 bytes, expires
  2026-12-03T07:22:31Z (expiry period 7 days, signing period 6) and names
  snapshot v84 by version only. `84.snapshot.json` is 446 bytes, expires
  after 21 days (signing period 7) and names targets v10 by version only.
  `10.targets.json` is 2,974 bytes with 7 top-level targets and no
  delegations: `trusted_root.json` and six `prod-*.trusted_root.json`
  roots of GHE.com data-residency tenants.
- **The target** `trusted_root.json` is 31,645 bytes, SHA-256 only
  (`484cdfe1…`), at most depth 7 and 194 values, with 0 tlogs, 0 ctlogs,
  6 CAs and 6 TSAs. It is the same JSON as the compact line `gh
  attestation trusted-root` prints (`jq -S -c` equal, the file ADR-040
  verifies against) but not the same bytes: the TUF file is
  pretty-printed, the `gh` line is 28,886 bytes. K1 and K2 of ADR-040
  verify under both as `KeylessWithoutLog { signed_timestamps: 1,
  identity: 0 }`.
- **A second channel for a pin:** `cli/cli` embeds
  `pkg/cmd/attestation/verification/embed/tuf-repo.github.com/root.json`,
  byte for byte the served `3.root.json` (7,480 bytes, SHA-256
  `98cba97be9075bc98b2322de3de85fbd1b70ec7392991dfd2f53d215bede1a8d`),
  unchanged since 2024-08-15. `gh attestation verify` starts its TUF
  client from it. No other root has a second public copy: the source
  repository is not public, and `cli/cli`'s earlier embedded v1 (9,350
  bytes) is not the served `1.root.json` (7,660 bytes).
- **TLS:** the leaf is `*.github.io` (its SAN also covers
  `*.github.com`), issued by Let's Encrypt YR1 under ISRG Root YR. The
  leaf's CRL is `http://yr1.c.lencr.org/57.crl` (291,120 bytes, 0.14 to
  0.16 s in 3 runs) and the intermediate's `http://yr.c.lencr.org/`. The
  revocation checks of ADR-017 and ADR-027 pass.
- **Live runs** of the unchanged client, each with a fresh trust
  directory and a new `TlsDial` (so each first run includes the CRL
  fetches):

  | Pin | First run | Second run |
  | --- | --- | --- |
  | v1 | 2.08 s, 13 requests | 0.56 s, 4 requests |
  | v3 | 3.33 s, 11 requests | 0.67 s, 4 requests |
  | v9 | 0.89 s, 5 requests | 0.65 s, 4 requests |

So the client of ADR-033 refreshes GitHub's root without a change to its
TUF steps. What is left to decide is the pin, where the state lives, and
how two roots stay apart.

## Decision

1. **The pin (D1)** is GitHub's root **v3**, in ADR-033's format
   unchanged: the root's bytes plus their SHA-256,
   `InitialRoot::new(bytes, "98cba97be9075bc98b2322de3de85fbd1b70ec7392991dfd2f53d215bede1a8d")`.
   One code path and one operator procedure for both roots. v3 is the
   only GitHub root that a second public channel carries byte for byte
   (`cli/cli`'s embedded copy), and the anchor every `gh attestation
   verify` starts from, so an operator can check the pin against two
   sources that do not share a publishing path. The cost is 6 more
   verified rotations on a bootstrap only (11 requests instead of 5, 3.3 s
   measured). ADR-033 item 5's reasons against an embedded root apply
   unchanged: the operator chooses and keeps the bytes and the pin.
2. **Two trust directories (D2).** Each root has its own ADR-033 trust
   directory, each with its own `lock`, `tuf/` and `tuf/pin`, as
   siblings under one base the operator chooses:

   ```text
   <trust base>/
     sigstore/   ADR-033's trust directory for tuf-repo-cdn.sigstore.dev
     github/     the same layout for tuf-repo.github.com
   ```

   The verifier's configuration (#32) points each trust at its own
   `trusted_root.json`. `Refresh` keeps its API: `dir` names one trust
   directory per call. A refresh of one root takes only its own lock, so
   the two refresh independently, and the remedy of ADR-033 (remove
   `tuf/`) resets one root only.
3. **The isolation rule (D3)**, in code, so that "a refresh of one root
   never touches the other root's directory" holds whatever paths an
   operator configures:
   - **R1, one directory per pin.** A trust directory belongs to the pin
     recorded in its `tuf/pin`. A refresh with another pin fails at
     `InitialRoot` before any request and before anything in the
     directory changes. For that the removal of a crashed run's `.tmp-`
     files moves from opening the directory to after the pin check
     (and before the first write, whose `create_new` a leftover would
     fail), so even another root's crash leftovers stay.
   - **R2, no trust directory at or under a `tuf` entry.** No component
     of a trust directory's path may be a `tuf` entry, in each of the
     three forms `prepare_root` checks (as given, as it would be created,
     and resolved). A component is a `tuf` entry when its name equals
     `tuf` ignoring ASCII case, or when its `(st_dev, st_ino)` equals
     that of its parent's `tuf` entry; the second test catches whatever a
     case-folding filesystem folds to `tuf`. A violation fails at
     `Step::Lock` before anything is created; a failure to read a
     component other than "missing" refuses too (fail closed).
   - **Why R1 and R2 suffice.** A refresh of directory D writes, renames,
     removes or sweeps only names directly in D and in D/tuf. Two
     directories A and B share one of those names only if A = B (R1
     refuses the second root), A = B/tuf, or A/tuf = B (R2 refuses the
     inner one either way). R2 also keeps every trust directory out from
     under another's `tuf/`, so the remedy cannot reach it. A trust
     directory beside another's `tuf/` (B/x) shares nothing: the sweep is
     not recursive, and `remove_file` fails on a directory.
4. **The command and its cadence (D4).** `boneli trust refresh` (#32's
   scope) refreshes every configured root, one after another, each under
   its own lock; `--root sigstore|github` refreshes one. A failure of
   one root does not skip the other, and the exit status is non-zero
   when any root failed. Run it weekly for both: GitHub's timestamp
   expires 7 days after it is signed (signing period 6), as Sigstore's
   does, so a weekly run refuses a frozen repository at most 14 days
   after the freeze. Run it also at once when GitHub bundles fail with
   `Timestamp(SigningCertificate)`, the stale-root signal of ADR-040.
   This replaces ADR-040's "capture by hand at least every 147 days":
   the weekly run is 21 times more frequent than the shortest measured
   window gap.
5. **No limit changes (D5).** Every limit of ADR-033 holds for GitHub's
   repository, each derived from GitHub's own numbers:

### Limits on GitHub's numbers

| Limit | Value | Derivation on GitHub's repository |
| --- | --- | --- |
| `MAX_ROOT_BYTES` | 65,536 | The largest root is 7,660 bytes (v1, 9 keys), so the cap is 8.6 times that. At ADR-033's 854 bytes per signing key the cap holds about 67 keys more than v1's 9. |
| `MAX_TIMESTAMP_BYTES` | 16,384 | Measured 450 bytes, 36.4 times that: one entry by version only and one signature. |
| `MAX_SNAPSHOT_BYTES` | 1,048,576 | Measured 446 bytes, 2,351 times that. GitHub has no delegated roles, so the snapshot has one entry. |
| `MAX_TARGETS_BYTES` | 1,048,576 | Measured 2,974 bytes for 7 targets and 3 signatures, 352 times that. At about 300 bytes per target entry that is about 3,400 targets, against 7 today (one per tenant root). |
| Target length | `boneli_sigstore::MAX_TRUSTED_ROOT_BYTES` (1,048,576) | Measured 31,645 bytes for 6 CA and 6 TSA windows, so about 5.3 KB per window: the cap holds about 190 windows, which at the shortest measured gap of 147 days is about 76 years of windows kept in one file. |
| `MAX_JSON_DEPTH` / `MAX_JSON_VALUES` | 16 / 65,536 | Measured at most depth 7 (the target) and 194 values (the target; roots at most 127), so 2.3 and 338 times that. |
| Response head | 16,384 bytes / 64 fields | Measured 686 to 708 bytes and 22 to 23 fields, so 23 and 2.8 times that. |
| `MAX_ROOT_ROTATIONS` | 32 per run | 8 rotations in about 3.1 years, about 2.6 a year (inferred from expiry dates), so one run catches up about 12 years of lag. From the pin v3 a bootstrap verifies 6 today. |
| Timeouts | connect 10 s, handshake 10 s, io 30 s, setup 30 s, `min_rate` 1,048,576 B/s | ADR-033's. The leaf's CRL is 291,120 bytes, 0.14 to 0.16 s measured; `setup` leaves about 29.9 MiB at `min_rate` for it inside the first request, 107 times its size. |
| Requests per run | first run from v3: 11; current file: 4 | One per root newer than the trusted one, the `404` of the next root, timestamp, snapshot, targets, and the target when it changed. Each later GitHub root adds one request to a bootstrap from v3. |

## Consequences

- GitHub's root is refreshed by the same verified client as Sigstore's,
  with no change to a TUF step, so ADR-033's tests, mutants and review
  cover it. Known answers on GitHub's real roots v1 to v9 and its online
  metadata pin that today's repository passes; fixture tests show that a
  rollback, an expired timestamp, a snapshot version mismatch and a
  changed pin each refuse a refresh of the second root, with the
  installed file and the other root's directory unchanged.
- The weekly live refresh in `oci-acceptance` (`github_refresh_live`)
  catches upstream drift within a week: a new key type or scheme in a
  threshold position, the target moved or renamed, and a retired CA or
  TSA window that K1 or K2 needs. It adds 15 requests per architecture
  per run to `tuf-repo.github.com` while v9 is current, one more per
  later root.
- **R2 refuses a path an operator might pick:** any trust directory whose
  path has a component named `tuf` in any ASCII case (`/srv/TUF/github`).
  There are no deployments yet (#32 has not landed), and the error names
  the rule; the sibling layout of D2 never meets it.
- A refresh with the wrong pin is now side-effect free in that
  directory: a crashed run's temporary files stay until a refresh with
  the right pin removes them. They are never read.
- `docs/sigstore-trust.md` replaces the capture by hand with the TUF
  refresh; the `gh` capture stays as a cross-check, since it yields the
  same JSON in other bytes.
- **Known limits**, each with its closure:
  - The six `prod-*.trusted_root.json` GHE.com tenant roots are listed
    but never fetched. Closure: a GHE.com data-residency use case, which
    would name its target per trust.
  - A reset of GitHub's TUF repository (a new root v1 under new keys)
    fails closed at `Root` or `Timestamp` until the operator changes the
    pin; the procedure is in `docs/sigstore-trust.md`.
  - Roots after v3 have one public channel only (the repository itself),
    because GitHub's source repository is not public. A pin newer than v3
    can be checked only against the repository. Closure: a second public
    copy of a newer root, for example a new `cli/cli` embed.
  - The repository's certificate chain (Let's Encrypt YR1 today) can
    move, which changes the CRL hosts the refresh reaches; the weekly run
    shows it, and the revocation rules of ADR-017 and ADR-027 apply to
    any chain.
  - If GitHub retires CA and TSA window 0 from its root, K1 fails the
    live test. That is drift detection, not a defect of the refresh.
    Closure: a newer private-repository capture as the known answer.

## Alternatives considered

- **One trust directory holding both roots' state.** A refresh of either
  root would write into the directory that holds the other's file, one
  lock would serialize both, and one remedy (remove `tuf/`) would reset
  both. Rejected for D2.
- **Library-managed subdirectories** (`dir` becomes a base plus a root
  name). It rewrites ADR-033's accepted layout and every refresh test,
  and adds no protection beyond R2. Rejected.
- **R1 plus documentation only.** A GitHub directory configured as
  Sigstore's `tuf/` would let Sigstore's sweep delete GitHub's in-flight
  temporary files (fail closed, but it touches them), and Sigstore's
  remedy would wipe GitHub's whole state. Rejected for R2.
- **An ancestor walk for any directory that holds `lock` and `tuf/`.** It
  catches nesting only after the outer directory exists, and the result
  depends on which root was set up first. Rejected for R2's name and
  identity test, which needs no state.
- **Pin v9, the current root.** The shortest chain (5 requests), but only
  one public channel, because `github/prod-tuf-root` is not public.
  Rejected for D1.
- **Pin v1.** No byte-equal second copy exists. Rejected.
- **An embedded GitHub root.** Rejected by ADR-033 item 5's three
  reasons, which apply unchanged.
- **A pin by hash only, with the bytes fetched by version.** A new
  bootstrap code path in a crate on the always-review list, for the
  convenience of not keeping 7,480 bytes. Rejected.
- **A separate `trust refresh-github` command.** A second command for one
  action and one more cron entry per root. Rejected for D4's `--root`.
- The language is not in question: the change is in the existing Rust
  crate `boneli-tuf`, with no new crate or dependency edge.

## Accept when

The pull request's own `oci-acceptance` run (it edits the workflow file,
so `pull_request` runs it) is green on x86_64 and arm64 with
`github_refresh_live`, and every hand-applied mutant of the pull request
is killed.

**Result before the run.** By hand on 2026-11-26
(`cargo test -p boneli-tuf --test network -- --ignored --nocapture`,
developer host, `TlsDial` with the Mozilla roots): from the pin v3 into
an empty trust directory in 3.7 s to root v9, timestamp v1027, snapshot
v84 and targets v10; the installed file is 31,645 bytes with SHA-256
`484cdfe1…`, the target's, and byte for byte the captured fixture; K1
and K2 verify under it as `KeylessWithoutLog { signed_timestamps: 1,
identity: 0 }`; a second run found it current in 0.58 s. 13 hand-applied
mutants, 13 killed, each by an assertion of the named test:

- the timestamp version rollback check dropped
  (`github_timestamp_rollback_refused`); `start >= expires` turned into
  `>` (`github_expired_timestamp_refused`, at the boundary); the
  snapshot version equality dropped
  (`github_snapshot_mismatch_refused`);
- the pin comparison dropped (`github_changed_pin_refused`,
  `one_directory_per_pin`); the sweep moved back before the pin check
  (`one_directory_per_pin`, a planted `.tmp-root.json` survives);
- R2 removed (`trust_dir_is_tuf_refused`); R2 on the last component only
  and R2 applied only to the resolved path after `prepare_root`
  (`trust_dir_below_tuf_refused`, the "not created" assertion); the name
  compared case-sensitively (`trust_dir_case_variant_refused`); the
  identity comparison dropped and a read failure passing instead of
  refusing (`tuf_rule_by_identity`);
- `check_held` dropped (`github_tuf_removed_during_refresh`); the lock
  file at the trust directory's parent, shared by siblings
  (`github_lock_is_its_own`).
