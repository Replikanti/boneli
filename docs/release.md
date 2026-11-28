# Releasing

A release is a `vX.Y.Z` git tag on a commit in `main`. Pushing the tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which
tests the workspace, builds the packages listed in
[`tools/release-packages`](../tools/release-packages) for Linux x86_64 and
aarch64, and publishes one archive per architecture with a SHA-256 sidecar
as a GitHub Release, with the matching [`CHANGELOG.md`](../CHANGELOG.md)
section as release notes. Nothing is published to crates.io
(`publish = false`). Decisions and their reasons:
[ADR-019](adr/019-release-process-and-third-party-notices.md).

## Versioning

[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version
is below 1.0, a breaking change (CLI flags, config, file or log formats,
anything a stored run depends on) bumps the **minor** version and is marked
**Breaking:** under `Changed` in the changelog; everything else bumps the
patch. The single source of truth is `[workspace.package] version` in
`Cargo.toml`, which every member inherits. A version with a prerelease part
(`0.2.0-rc.1`) is published as a GitHub prerelease.

## Recipe

1. **Release PR.**
   - Bump `[workspace.package] version` in `Cargo.toml` and refresh the
     lockfile with `cargo check --workspace`.
   - In `CHANGELOG.md` rename `## [Unreleased]` to
     `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` above
     it. Headings are Keep a Changelog: `Added`, `Changed`, `Fixed`,
     `Removed`.
   - Preview the notes: `tools/release-notes.sh X.Y.Z`. It fails when the
     section is missing or empty.
   - The PR body carries the usual `Closes #N` or `No-Issue: <reason>` line.
2. **Tag after the merge.** Tag the squash-merge commit and push the tag
   immediately: `git tag vX.Y.Z <merge-sha> && git push origin vX.Y.Z`. A
   merge without the tag is not a release.
3. **Verify.** The release holds, for `<arch>` in `x86_64` and `aarch64`,
   `boneli-vX.Y.Z-linux-<arch>.tar.gz` and its `.sha256`. Download them and
   run `sha256sum -c boneli-vX.Y.Z-linux-<arch>.tar.gz.sha256`; then
   `tar -tzf` lists exactly the directory `boneli-vX.Y.Z-linux-<arch>/` with
   the binaries, `LICENSE` and `THIRD-PARTY-NOTICES.txt`.

## What the workflow checks

Before building anything, on tag pushes, `tools/release-check.sh`: the tag
is exactly `v` + the workspace version, the tagged commit is an ancestor of
`origin/main`, `CHANGELOG.md` has a non-empty section for it (no release with
an empty body), and every package in `tools/release-packages` is a member
with a binary target and not one of the test or tool roots
(`boneli-replay-check`, `boneli-acceptance`, `boneli-arch-check`). Then, on
each architecture, `cargo test --workspace --locked`, a `--locked` release
build of the listed packages (a drifting `Cargo.lock` fails the release),
`tools/third-party-notices.sh` and `tools/release-package.sh`. The notices
hold the Rust standard library's notices from the toolchain, then every
license, copyright, copying and notice file of every bundled crate,
nested ones included; the step fails when the toolchain lacks its notices
or a bundled crate ships no license file at its top level, and nothing is
packaged then. `publish` runs only for a tag push and only when both
architectures built, and it is the one job with a write token. It requires
that the tag still points at the commit the run built, before and after
creating the release.

The archive is reproducible from the same inputs: entries sorted, owner 0,
every mtime the commit time, gzip without a time stamp. `sh
tools/test-release.sh` tests all of the tooling; CI runs it in `check`.

## Platform floor

Linux on x86_64 or aarch64 with glibc 2.35 or newer: the binaries are built
natively on Ubuntu 22.04, and a binary needs at least the glibc of its
builder. The sandbox runtime needs Linux 6.1 (ADR-044), so the hosts that
can run it mostly have this glibc (Ubuntu 22.04 has 2.35, Debian 12
has 2.36). Hosts on an older glibc build from source; Amazon Linux 2023
is one of them: its kernel is 6.1 or newer, its glibc 2.34 (ADR-044).

## Dry run

A pull request that changes the release files, and
`Actions > Release > Run workflow` (or `gh workflow run release.yml`), build
and test exactly like a tag push and upload the archives as the artifacts
`dist-x86_64` and `dist-aarch64` (named `boneli-dev-<sha>-linux-<arch>`),
but never publish, also when dispatched on a tag ref (the tag guard runs
then). A dispatch on `main` also rehearses the publish path: it creates a
draft release with the archives, checks its asset list and checksums, and
deletes it again, also when a step before failed. GitHub creates a draft's
tag only on publishing, so no tag appears. Use it after changing the
workflow or the toolchain, before cutting a tag.

## A failed release run

When a leg of a tag push run fails for a reason outside the tree (a runner
or registry hiccup), re-run it with `gh run rerun <run-id> --failed`: the
re-run keeps the tag push event and publishes. A new dispatch does not.

## A bad release

Never move a published tag silently. Delete the GitHub Release and the tag
(`gh release delete vX.Y.Z --cleanup-tag`), fix forward on `main` and tag
again; if users may already have the archive, publish the fix as the next
patch version instead.

## A new binary

Add its package to `tools/release-packages` in the PR that makes it
shippable (the runner, #33, and the CLI, #32). `tools/release-check.sh
--packages` refuses a package that is not a member, has no binary target or
is a test or tool root. The notices follow from the dependency graph. A
crate without a license file turns `check` red on every PR when it sits
under `boneli-https` or `boneli-egress` (`tools/test-release.sh` runs the
notices over both), and the release dry run red for any listed package: the
PR that edits `tools/release-packages` runs it.
