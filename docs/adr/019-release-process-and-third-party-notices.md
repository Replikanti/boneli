# ADR-019: Release process and third-party notices

- Status: accepted
- Date: 2026-11-20

## Context

Boneli has no release yet (#22). The runner and the CLI do not exist (#33,
#32); the one binary that could ship today is `boneli-egress`. Users will
install binaries, not build from source, so the repository needs a release
path before the first of them is useful: a version scheme, a tag that
publishes, and archives a user can verify.

Two things make this more than a copy of `Replikanti/mie`'s release
workflow. First, `boneli-https` pulls a TLS stack whose licenses ask for
their texts to travel with the binary (ADR-005, item 7 and Consequences):
ISC (`ring`, `untrusted`, `rustls-webpki`) and BSD-3-Clause (`subtle`)
require the copyright and permission notice in copies of the software,
CDLA-Permissive-2.0 (`webpki-roots`) requires that the agreement's text be
made available with the shared data, and Apache-2.0 requires a copy of the
license and the contents of a `NOTICE` file. `deny.toml` records the
exceptions with a pointer to this ADR. Second, the
runner is security software that runs at the customer: a release workflow
holds a write token and decides what users install, so it is on the
always-review list (`.github/workflows/`), and its guards must be tested
like code.

Measured while planning (2026-11-20): `cargo build --release -p
boneli-https --target x86_64-unknown-linux-musl` fails in `ring`'s build
script (`failed to find tool "x86_64-linux-musl-gcc"`). The registry
source of every crate in ADR-005's table ships at least one `LICENSE*`
file; `ring` ships three (`LICENSE`, `LICENSE-BoringSSL`,
`LICENSE-other-bits`). CI's `check` job took 3 min 27 s on `main`.

## Decision

### D1. Version and tag

Semantic Versioning; below 1.0 a breaking change bumps the minor. The
source of truth is `[workspace.package] version`, which every member
inherits; it stays `0.0.0` until the first release PR bumps it. A release
is a `vX.Y.Z` tag on a commit of `main`, pushed right after the release PR
merges; a tag with a prerelease part (`v0.2.0-rc.1`) publishes a GitHub
prerelease. The changelog section of the version is the release notes;
`tools/release-notes.sh` is mie's script unchanged.

### D2. Guards as tested scripts

The checks live in POSIX sh scripts under `tools/`, not inline in YAML, so
`tools/test-release.sh` can run every failure mode against fixtures (a
throwaway git repository with a cargo workspace, a fake registry, a
changelog) on every PR in `check`. `tools/release-check.sh <tag> [<sha>]`
fails unless the tag is exactly `v` + the workspace version, the commit is
an ancestor of `origin/main`, and the changelog section is non-empty. Every
mode of the script, `--packages` and `--bins` included, first checks the
package list (D5). Branch protection does not cover tags, so anyone with
write access can push one; the ancestry and version guards are what a tag
must pass before anything is built. A tag ruleset for `v*` is a repository
setting outside this ADR.

### D3. Native glibc builds on Ubuntu 22.04

One build per architecture, natively on GitHub's `ubuntu-22.04` (x86_64)
and `ubuntu-22.04-arm` (aarch64) runners, for the `-unknown-linux-gnu`
targets. A dynamically linked binary needs at least the glibc of its
builder, and Ubuntu 22.04 has 2.35. That floor costs nothing in practice:
the sandbox needs Linux 5.19 (ADR-007, D3), and the distributions that ship
such a kernel ship glibc 2.35 or newer (Ubuntu 22.04: 2.35, Debian 12:
2.36). `ubuntu-latest` (24.04, glibc 2.39) would shut out Debian 12 and
Ubuntu 22.04 for nothing. The build logs the highest glibc symbol version
each binary references, so the floor is visible per release.

Rejected: **musl** (static binaries without a glibc floor). `ring`'s build
script needs a musl C cross compiler that the runners do not have (measured
above). The shim (#9) will need a static musl build anyway and brings its
own recipe; the runner and CLI can follow it then. **Cross builds from one
x86_64 runner**: they need an aarch64 C toolchain for `ring` and cannot run
the tests for the target; GitHub's arm runners are free for public
repositories and `ci.yml` already uses them.

### D4. Third-party notices from the dependency graph

`tools/third-party-notices.sh <target> <package>...` writes
`THIRD-PARTY-NOTICES.txt`. The crate set is what `cargo tree --locked -e
normal --target <target>` resolves for the packages: what is compiled into
the binaries. Build and dev dependencies are not linked and stay out (no
`cc`), and so do workspace members, which the repository's own `LICENSE`
covers. For each crate, sorted by name and version in the C locale: its
name, version, license expression and repository from `cargo metadata`,
then every top-level regular file of its published source whose name
starts with `LICENSE`, `LICENCE`, `COPYING`, `NOTICE` or `UNLICENSE` (any
case), verbatim under its file name. The script fails closed: a crate
without such a file with content, a crate that `cargo metadata` does not
know, or a symlinked license file (it could point anywhere on the build
host) is named on stderr, the script exits 1 and writes nothing, and the
workflow packages only on success. Copying every file instead of choosing
the one that matches the license expression keeps the script free of SPDX
parsing and over-complies where a crate offers a choice.

A crate that keeps its license text only in the manifest's `license-file`
in a subdirectory, or nowhere, turns the release red rather than shipping
without it. That is the intended direction; a per-crate override would need
a note in this ADR.

Rejected:

- **`cargo-about`.** A Rust tool, but it needs an `accepted` license list
  that duplicates `deny.toml`, a clarification entry with file checksums for
  `ring` (three license files), and a template, and it does not copy Apache
  `NOTICE` files. It would also be a new third-party binary in the release
  path.
- **A Rust member crate** that reads `cargo metadata` through
  `boneli-json`: about 300 lines, a `roles` entry and a new always-review
  surface, for a job with no parsing that `cargo`, `jq` and the shell
  cannot do.

### D5. What ships: `tools/release-packages`

The packages a release builds are listed in `tools/release-packages`, one
per line; today only `boneli-egress`. `release-check.sh` refuses an empty
list, a name that is not a crate name, a package that is not a member or
has no binary target, and the test and tool roots of `roles.roots`
(`boneli-replay-check`, ADR-002; `boneli-acceptance`, ADR-014 D12;
`boneli-arch-check`, ADR-015), which must never ship. The runner (#33) and
the CLI (#32) join the list in the PRs that make them shippable. Every
archive holds one directory `boneli-<tag>-linux-<arch>/` with the binaries
(mode 0755), `LICENSE` and `THIRD-PARTY-NOTICES.txt` (0644), and is
reproducible from the same inputs (`tools/release-package.sh`: entries
sorted by name, owner 0, every mtime the commit time, `gzip -n`). The
`.sha256` sidecar names the bare archive file, so `sha256sum -c` works in
the download directory.

### D6. Permissions and the publish path

The workflow's token is `contents: read`. Only `publish` (tag pushes, after
both builds) and `rehearsal` (dispatch on `main`) get `contents: write`;
they run GitHub's own actions (`checkout`, `download-artifact`) and `gh`,
nothing third-party. `publish` verifies the four expected files and their
checksums before it creates the release, and uses `--verify-tag`, so `gh`
never creates a tag. Ref names reach the shell through `env:` only;
`tools/test-release.sh` fails on any `${{` inside a `run:` value of
`release.yml`. The build uses no cache: a cache restored into a tag run
could carry build output from another run, and a release is built from the
tagged tree and the registry alone. Checkouts do not persist the token.

A pull request cannot run `publish`, and a dispatch only runs on the
default branch, so the publish path would first run on a real tag. The
`rehearsal` job closes that gap: a dispatch on `main` creates a draft
release from the real archives with the real token, checks its asset list
and downloads the assets back through `sha256sum -c`, then deletes it in a
step that runs also when one before failed, and fails if the draft or a tag
of its name is left. GitHub creates a draft's tag only when it is
published.

### D7. Timeouts

`build` has a provisional timeout of 60 minutes until the dry run of the
PR that adds this ADR is measured.
`publish` and `rehearsal` have 10 minutes: a few API calls and uploads of
a few MiB, so this is a hang bound, not a measurement; neither job can run
before merge.

## Consequences

- A tag push publishes for both architectures or not at all: `publish`
  needs both builds.
- Hosts with glibc older than 2.35 (Debian 11, RHEL 9 and its rebuilds at
  2.34) cannot run the release binaries. Debian 11's kernel is below the
  sandbox's floor anyway; a RHEL 9 host whose backports pass the feature
  probe builds from source until a static build exists.
- The notices tool reads license files by name. A crate update that drops
  its license file, or a new crate without one, fails the release and, for
  crates under `boneli-https` or `boneli-egress`, `check` on the PR that
  brings it.
- The `ubuntu-22.04` labels will be retired by GitHub. Moving the label is
  a one-line change plus an update of the floor in D3 and in
  `docs/release.md`; every PR that touches the release files runs the dry
  run, which catches a dead label.
- No provenance attestation or signature yet: the SHA-256 sidecar proves
  integrity of a download against the release page, not who built it.
  Attestations need `id-token: write` and `attestations: write` and a new
  action in the release path; a follow-up decides them.
- Over-inclusion: a crate pulled only under a `cfg` that is true for the
  build target appears in the notices even if the code path is dead. That
  is harmless.

## Alternatives considered

- **mie's single raw binary per release** (no archive): no place for the
  license and notices files next to the binary, which D4 requires.
- **One archive for both architectures**: a user would download twice the
  bytes, and the notices differ per target where `cfg`s differ.
- **The tag checks inline in YAML**, as in mie: untestable except by
  pushing tags. D2 moves them into scripts with fixtures.
- **`cargo-about` or a Rust crate for the notices**: D4.
- **musl, cross builds, `ubuntu-latest`**: D3.
