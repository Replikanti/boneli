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
file at its top level. `ring` 0.17.14 ships six license files: three at the
top (`LICENSE`, `LICENSE-BoringSSL`, `LICENSE-other-bits`) and three below
it, which its `LICENSE` points to (`src/polyfill/once_cell/LICENSE-APACHE`,
`src/polyfill/once_cell/LICENSE-MIT`, `third_party/fiat/LICENSE`; counted in
the review of the PR that adds this ADR). `rand_core` ships a `COPYRIGHT`
file next to its licenses. CI's `check` job took 3 min 27 s on `main`.

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
must pass before anything is built. They run from the tagged tree, so they
cannot stop a tag on a tree whose workflow drops them: that is what a tag
ruleset for `v*` does (creation, update and deletion restricted). The
ruleset is a repository setting, made after the PR that adds this ADR
merges (decision 3 at STOP 1 of #22).

### D3. Native glibc builds on Ubuntu 22.04

One build per architecture, natively on GitHub's `ubuntu-22.04` (x86_64)
and `ubuntu-22.04-arm` (aarch64) runners, for the `-unknown-linux-gnu`
targets. A dynamically linked binary needs at least the glibc of its
builder, and Ubuntu 22.04 has 2.35. That floor costs nothing in practice:
the sandbox needs Linux 5.19 (ADR-007, D3), and the distributions that ship
such a kernel ship glibc 2.35 or newer (Ubuntu 22.04: 2.35, Debian 12:
2.36). `ubuntu-latest` (24.04, glibc 2.39) would shut out Debian 12 and
Ubuntu 22.04 for nothing. The build logs the highest glibc symbol version
each binary references, so the floor is visible per release: the dry run
on the PR that adds this ADR built a `boneli-egress` that references
`GLIBC_2.34` at most on both architectures. The promise stays 2.35, the
builder's, so a later binary may use anything the builder has.

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
then every regular file of its published source, at any depth except
`target/` and `.git/`, whose name starts with `LICENSE`, `LICENCE`,
`COPYING`, `COPYRIGHT`, `NOTICE` or `UNLICENSE` (any case), verbatim under
its path in the crate. Nested files matter: vendored code keeps its license
next to it, and `ring`'s top-level `LICENSE` points to three of them
(Context). Symlinks are never read (they could point anywhere on the build
host). The script fails closed: a crate without such a file with content at
its top level, or a crate that `cargo metadata` does not know, is named on
stderr, the script exits 1 and writes nothing, and the workflow packages
only on success.

The standard library is linked into every binary too: `std`, `core`,
`alloc` and the crates they are built from (`addr2line`, `gimli`,
`hashbrown`, `miniz_oxide`, `rustc-demangle`, `compiler_builtins` and more),
which `cargo tree` does not show. Their notices come from the toolchain that
built the archive: `share/doc/rust/COPYRIGHT-library.html` under `rustc
--print sysroot`, which lists the in-tree licenses and, for each
out-of-tree crate of the standard library, its license files, goes in
verbatim as the first section (`rust-std <version>`), followed by every
license text in `share/doc/rust/licenses/` whose SPDX id it names
(Apache-2.0 and MIT at least). It comes with the `rustc` component, so the
minimal profile installs it. A toolchain without the document or without
those two texts fails the run like a crate without a license. That covers
the standard library's graph with its maintainers' own record of it; the
script does not rebuild that record. Copying every file instead of choosing
the one that matches the license expression keeps the script free of SPDX
parsing and over-complies where a crate offers a choice.

A crate that keeps its license text only in the manifest's `license-file`
in a subdirectory, or nowhere, turns the release red rather than shipping
without it. That is the intended direction; a per-crate override would need
a note in this ADR.

Rejected:

- **`cargo-about`.** A Rust tool, but it needs an `accepted` license list
  that duplicates `deny.toml`, a clarification entry with file checksums for
  `ring` (six license files), and a template, and it does not copy Apache
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
nothing third-party. `publish` runs only for a tag push
(`github.event_name == 'push'`): a dispatch never publishes, also on a tag
ref; a failed release run is re-run with `gh run rerun`, which keeps its
event. It fetches the tag fresh and requires that it still points at the
commit the run built (`GITHUB_SHA`), verifies the four expected files and
their checksums, creates the release with `--verify-tag` (so `gh` never
creates a tag) on that commit, and checks the tag once more afterwards,
deleting the release if it moved. The `build` job runs one third-party
action, `dtolnay/rust-toolchain`, which installs the toolchain that builds
what users run; it is pinned to a full commit of its `stable` branch, so a
push to that branch cannot change the build, and the pin is bumped by hand.
`tools/test-release.sh` fails on an action outside `actions/` that is not
pinned to a commit, and on a `publish` without the tag-push condition or
the two tag checks. Ref names reach the shell through `env:` only;
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

`build` has a timeout of 7 minutes: three times the slower leg of the dry
run on the PR that adds this ADR, rounded up. Measured 2026-11-20 without a
build cache: x86_64 1 min 59 s, aarch64 2 min 17 s, each from checkout to
upload, `cargo test --workspace --locked` (1,137 tests) included. The
factor covers a slower runner or registry; a timeout fails the release
before `publish`, so the cost of a too-tight bound is a re-run. The bound
grows with the binaries: the PR that adds a package to
`tools/release-packages` runs the dry run, which gives the new measurement.
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
  brings it. A file named otherwise (`MIT.txt` in a `LICENSES/` directory)
  is not found; when that leaves a crate without a top-level match it fails
  closed, otherwise the file is missing from the notices unnoticed.
- The standard library's notices are an HTML document in a text file,
  about 1.5 MB uncompressed; the archive's gzip keeps the cost small. Its
  content changes with the toolchain, so two releases built with
  different toolchains differ there.
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
