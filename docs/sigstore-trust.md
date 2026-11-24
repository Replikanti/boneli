# Sigstore trusted root: operator guide

Keyless image signatures are verified against the operator's
`trusted_root.json` (ADR-029): the Fulcio CAs, Rekor logs and CT logs that
Sigstore's public-good instance uses. Sigstore rotates them, and publishes
the current file as a target of its TUF repository
`https://tuf-repo-cdn.sigstore.dev`. `boneli-tuf` keeps the file current
from that repository (ADR-033). This guide covers the initial root and its
pin, the trust directory, when to refresh, and what each failure means.
The design and the reasons for every rule are in
`docs/adr/033-sigstore-trust-root-by-tuf.md`.

Until the `trust refresh` command of `boneli-cli` exists (#32), the
refresh is the library call `boneli_tuf::refresh_trusted_root`, and the
live test below runs it.

## The initial root and its pin

TUF starts from one root the operator trusts: every later root must be
signed by a threshold of the keys of the one before. Boneli does not embed
it; you choose it and pin it by its SHA-256.

1. Fetch a root, for example the current one, from two places that do not
   share an operator: the repository itself
   (`https://tuf-repo-cdn.sigstore.dev/<N>.root.json`) and Sigstore's
   root-signing repository on GitHub (`sigstore/root-signing`, the file
   `metadata/root_history/<N>.root.json`). On 2026-11-24 the two copies
   of `16.root.json` were byte for byte the same.
2. Compare them byte for byte and take their SHA-256 (`sha256sum`). The
   pin is those 64 lower-case hex characters.
3. Keep the file and the pin with the rest of the runner's configuration.

The earliest root the client accepts is version 5: versions 1 to 4 carry
keys in a hex form that counts zero, and 1 to 3 an `expires` with an
offset or a fraction. Any later version works; a newer pin only shortens
the chain the first refresh walks. The root's expiry does not matter for
the pin: an expired root still starts the chain, and only the newest root
of a refresh must not have expired.

`InitialRoot::new(bytes, pin)` refuses bytes that do not hash to the pin,
a pin that is not 64 lower-case hex characters, a file over 65,536 bytes
and a root that does not reach its own root threshold.

## The trust directory

One private directory, under the same rules as the image store (ADR-021):
an absolute path without `.` or `..`, a directory of the runner's user
with mode `0700`, and no ancestor writable by its group or by others
unless it is sticky. It is created where it is missing. A symlinked path
is resolved and checked where it points.

```text
<trust dir>/
  trusted_root.json   the file the verifier reads (#32 points it here)
  tuf/
    root.json         the newest verified root, as fetched
    timestamp.json    the last verified timestamp, as fetched
    snapshot.json     the last verified snapshot, as fetched
    pin               the initial root's SHA-256, written on the first run
  lock                held by a refresh for its whole run
```

Files are written `0600`, to a temporary `.tmp-<name>` first, synced and
renamed into place, so a reader sees the old file or the new one, never a
part. A refresh removes the `.tmp-` files a crashed run left.

The first refresh records the pin and stores the initial root. Every later
refresh starts from `tuf/root.json` and does not read the initial root
again, but it does compare the pin: another pin fails, so a changed pin
is never ignored silently.

`trusted_root.json` is replaced only after every TUF step passed, the
file's length and SHA-256 matched the signed target, and the verifier's
own reader (`TrustedRoot::from_json`) read it. On every failure before
the file is renamed into place it stays as it was. After the rename only
the sync of the directory can fail: the refresh then reports `Write` with
the new, fully verified file already in place, and the next run finds it
current (`Unchanged`) while the repository still lists it, or installs
it again if a crash lost the rename. Do not edit it by hand: the next
refresh replaces it.

## When to refresh

- **Weekly.** Sigstore's timestamp expires 7 days after it is signed, so a
  weekly refresh notices a frozen repository at most 14 days after the
  freeze.
- **When a signature is refused for an unknown log or CA.** Sigstore may
  have rotated one since the last refresh.

A refresh makes 5 requests when the file changes (the probe for the next
root, timestamp, snapshot, targets, the file) and 4 when it is current, to
`tuf-repo-cdn.sigstore.dev` only, plus the revocation checks of its TLS
certificate chain (ADR-017, ADR-027), which fetch from its CA's CRL host.
It takes about 1 to
2 seconds; a server that answers as slowly as the deadlines allow can hold
it for about 18.6 minutes (ADR-033, limits).

## Failures

A failed refresh returns `RefreshError { step, detail }`. The detail names
the file, status, size or path, never text from the metadata.

| Step | Meaning | What to do |
| --- | --- | --- |
| `Lock` | The trust directory breaks a rule (path, owner, mode, an ancestor writable by others), or another refresh holds `lock` ("busy"); or the trust directory, `tuf/` or `lock` was removed or replaced while this refresh ran. | Fix the directory, or wait for the other refresh and run again. |
| `InitialRoot` | The pin does not match the initial root, the root does not verify, the directory was set up from another pin, or `tuf/root.json` has no `tuf/pin`. | Check the pin. To change the initial root on purpose, remove `tuf/`. |
| `Root(Some(N))` | `N.root.json` was refused: a status other than `200` or `404`, a signature or version check, more than 32 new roots in one run, the newest root expired, or a repository without consistent snapshots. | Retry. More than 32 roots: run again, the next run goes on. An expired newest root or a bad signature means the repository is stale or not Sigstore's: do not remove anything. |
| `Root(None)` | The stored `tuf/root.json` does not parse or verify. | Remove `tuf/`; the next refresh bootstraps from the pin. |
| `Timestamp` | `timestamp.json` was refused: missing, expired (a frozen repository), rolled back, or not signed by the timestamp key. | Retry later; a lasting failure means the repository is frozen or under attack. |
| `Snapshot(N)`, `Targets(N)` | `N.snapshot.json` or `N.targets.json` was refused: hash, length, version, signature, expiry, or a role the stored snapshot listed is gone or lower. | As for `Timestamp`. |
| `Target` | `trusted_root.json` is not a top-level target (for example, moved into a delegation), is listed above 1 MiB, or the fetched file does not match its length and SHA-256. | Retry; a lasting "not listed" needs a Boneli update (ADR-033, known limits). |
| `TrustedRoot` | The signed file passed TUF but the verifier cannot read it. | Keep the old file and report it: Sigstore changed the file's format. |
| `Write` | The trust directory could not be read or written. When only the sync after the rename of `trusted_root.json` failed, the new, verified file is already in place. | Check disk space and permissions, then run again. |

After a rollback or freeze refusal, the stored metadata keep protecting
the next run: a repository that serves older versions keeps failing.
Remove `tuf/` only for `Root(None)` or to change the pin; it resets that
protection to whatever the repository serves next. Remove only `tuf/`,
never `lock`. A refresh that is running holds `lock`, so one started
after the removal fails as "busy" until it ends, and the running one
stops at `Lock` instead of writing into the new `tuf/`: run the refresh
again once it has ended. Do not remove the whole trust directory while a
refresh may run: a refresh that recreates it at that moment can race the
running one's last write (ADR-033, item 6).

## Live test

```sh
cargo test -p boneli-tuf --test network -- --ignored --nocapture
```

It refreshes from the pinned root v16 into an empty trust directory under
the temporary directory and once more, which must find the file current,
and prints the versions and the file's SHA-256. CI runs it weekly in the
`oci-acceptance` workflow on x86_64 and arm64.
