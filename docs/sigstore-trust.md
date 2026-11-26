# Sigstore trusted root: operator guide

Keyless image signatures are verified against the operator's
`trusted_root.json` (ADR-029): the Fulcio CAs, Rekor logs and CT logs that
Sigstore's public-good instance uses. Sigstore rotates them, and publishes
the current file as a target of its TUF repository
`https://tuf-repo-cdn.sigstore.dev`. `boneli-tuf` keeps the file current
from that repository (ADR-033). This guide covers the initial root and its
pin, the trust directory, when to refresh, what each failure means, and
GitHub's private-repository root, which the same client keeps current
from GitHub's TUF repository in a trust directory of its own (ADR-041).
The design and the reasons for every rule are in
`docs/adr/033-sigstore-trust-root-by-tuf.md` and
`docs/adr/041-github-trusted-root-by-tuf.md`.

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
| `Lock` | The trust directory breaks a rule (path, owner, mode, an ancestor writable by others; a path component named `tuf` in any case, or the parent's `tuf` itself, "directory named tuf"), or another refresh holds `lock` ("busy"); or the trust directory, `tuf/` or `lock` was removed or replaced while this refresh ran. | Fix the directory (for two roots use the sibling layout below), or wait for the other refresh and run again. |
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

## GitHub's private-repository root

GitHub signs the artifact attestations of private repositories with its
own Sigstore instance, not with the public-good one. Its trusted root
lists no Rekor log and no CT log, only Fulcio CAs and timestamp
authorities, so its bundles carry an RFC 3161 timestamp and no log entry.
They verify only under a trust with the no-log opt-in (ADR-040,
`docs/adr/040-keyless-bundles-without-a-transparency-log.md`), which says
what such a signature proves and what it does not: GitHub alone vouches
for it, and nobody outside GitHub can see it.

**Cross-check the root** with a logged-in `gh` and `jq`. The TUF refresh
below keeps the file current; `gh attestation trusted-root` prints the
same root, which serves as a second look. It prints two roots, one per
line; GitHub's is the one whose first CA is `fulcio.githubapp.com`:

```sh
gh attestation trusted-root |
  jq -c 'select(.certificateAuthorities[0].uri == "fulcio.githubapp.com")' \
  > github-trusted-root.json
jq '{tlogs: (.tlogs // [] | length), ctlogs: (.ctlogs // [] | length),
     cas: (.certificateAuthorities | length),
     tsas: (.timestampAuthorities | length)}' github-trusted-root.json
```

The second command must show 0 `tlogs` and 0 `ctlogs`; on 2026-11-26 it
showed 6 CAs and 6 TSAs. The TUF file and this line are the same content
in different bytes: the TUF file is pretty-printed (31,645 bytes on
2026-11-26), the `gh` line compact (28,886), and `jq -S -c .` gives the
same output for both. Keep the file apart from the public-good
`trusted_root.json`: each trust names its own root.

**The opt-in.** Until the runner's policy file has a key for it (#32,
#33), the opt-in is the library call `Trust::with_no_log()` on a trust
over this root, after certificate claims (`with_certificate_claims`,
ADR-034) that bind the source repository. It is refused when the root
lists any log, when the root has no timestamp authority, when an
identity's SAN prefix does not name at least an owner
(`https://github.com/<owner>/`), and when the certificate claims do not
bind the repository the run belongs to (`NoLogWithoutRepository`). A
verified signature reports `KeylessWithoutLog`.

**Bind the repository, not only the workflow.** The SAN names the
workflow that signed, and that can be a public reusable workflow which
any repository on GitHub may call: a private repository of another owner
calling your `release.yml` gets a leaf with your workflow in the SAN and
its own repository in the Source Repository URI (1.12) and ID (1.15).
The root is shared by every private repository on GitHub, and with no
log nobody would ever see such a signature, so the opt-in needs one of:
an exact 1.12 rule (`ClaimMatch::Exact("https://github.com/<owner>/<repo>")`),
a 1.12 prefix that names at least an owner
(`https://github.com/<owner>/`), or the repository ID
(`with_repository_id`, 1.15). Prefer the ID: a repository name can be
renamed or registered again by someone else, and the numeric ID never
moves to another repository. Since certificate claims refuse keys, a
no-log trust holds no keys.

### GitHub's root through TUF

GitHub publishes this root as the target `trusted_root.json` of its own
TUF repository, `https://tuf-repo.github.com`, and `boneli-tuf` refreshes
it with the same client and the same rules as Sigstore's (ADR-041). Only
the repository, the pin and the trust directory differ.

**The pin** is GitHub's root v3: `3.root.json`, 7,480 bytes, SHA-256
`98cba97be9075bc98b2322de3de85fbd1b70ec7392991dfd2f53d215bede1a8d`. It is
the only GitHub root a second public channel carries byte for byte:
`cli/cli` embeds it, and `gh attestation verify` starts from it. Fetch
it from both and compare:

```sh
curl -sSf -o github-3.root.json https://tuf-repo.github.com/3.root.json
gh api repos/cli/cli/contents/pkg/cmd/attestation/verification/embed/tuf-repo.github.com/root.json \
  -H 'Accept: application/vnd.github.raw' | cmp - github-3.root.json
sha256sum github-3.root.json
```

Every later GitHub root is also a pin the client accepts (v1 to v9 on
2026-11-26), but only the repository itself serves them, because GitHub's
source repository is not public. From v3 the first refresh verifies each
later root: 11 requests with v9 current.

**Two trust directories, side by side.** Each root has its own trust
directory with its own `lock`, `tuf/` and `tuf/pin`:

```text
<trust base>/
  sigstore/   trust directory for tuf-repo-cdn.sigstore.dev (pin: a Sigstore root)
  github/     trust directory for tuf-repo.github.com (pin: GitHub's v3)
```

Each trust in the verifier's configuration (#32) names its own
`trusted_root.json`. Two rules keep a refresh of one root out of the
other's directory:

- **One directory per pin.** A directory belongs to the pin in its
  `tuf/pin`. A refresh with another pin, for example GitHub's pointed at
  Sigstore's directory, fails at `InitialRoot` before any request and
  changes nothing there, not even a crashed run's temporary files.
- **No trust directory at or under a `tuf` entry.** A trust directory
  whose path has a component named `tuf` in any ASCII case, or a
  component that is its parent's `tuf` entry (what a case-insensitive
  filesystem folds to `tuf`), fails at `Lock` with "directory named tuf"
  before anything is created. So no root's directory can sit inside the
  other's `tuf/`, where that root's sweep or its remedy (remove `tuf/`)
  would reach it. Do not name a directory on the path `tuf`.

**Refresh** with `boneli trust refresh` (#32): it refreshes every
configured root, one after another, each under its own lock, and
`--root sigstore` or `--root github` refreshes one. A failure of one root
does not skip the other, and the exit status is non-zero when any root
failed. Until the command exists, the refresh is the library call with
`Repository::parse("https://tuf-repo.github.com")`, the pin above and
`<trust base>/github` as `dir`.

**When.** Weekly, as for Sigstore: GitHub's timestamp expires 7 days
after it is signed, so a weekly run refuses a frozen repository at most
14 days after the freeze. GitHub adds a CA and TSA window every 147 to
232 days, so a weekly run never comes close to missing one. Refresh at
once when GitHub bundles start failing with
`Timestamp(SigningCertificate)`: that is the refusal a stale file gives,
because its last window has no end and so holds the new time, but its
TSA leaf did not sign the new token.

A refresh of GitHub's root makes, while v9 is current, 4 requests when
the file is current and 5 when it changed (the probe for the next root,
timestamp, snapshot, targets, the file), to `tuf-repo.github.com` only,
plus the CRL fetches of its certificate chain (`yr1.c.lencr.org`,
`yr.c.lencr.org` on 2026-11-26). It never fetches the six
`prod-*.trusted_root.json` roots of GHE.com tenants the repository also
lists.

**Changing the pin.** A rotation of GitHub's root never changes the pin:
every new root is verified against the one before it and stored in
`tuf/root.json`. To change the pin on purpose (for example after GitHub
reset its repository, which fails every refresh at `Root` or
`Timestamp`):

1. Make sure no refresh runs.
2. Remove only `<trust base>/github/tuf/`: never `lock`, and never the
   Sigstore directory.
3. Set the new root and pin in the configuration.
4. Run the refresh; it bootstraps from the new pin.

Until then every run fails at `InitialRoot` ("set up from another initial
root") and the old `trusted_root.json` stays in place.

## Live test

```sh
cargo test -p boneli-tuf --test network -- --ignored --nocapture
```

It refreshes Sigstore's root from the pinned v16 and GitHub's from the
pinned v3, each into an empty trust directory under the temporary
directory and once more, which must find the file current, and prints
the versions and the file's SHA-256. GitHub's installed file must verify
two captured private-repository attestations under the no-log opt-in. CI
runs it weekly in the `oci-acceptance` workflow on x86_64 and arm64.
