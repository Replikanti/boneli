#!/bin/sh
# Architecture and dependency rules of the workspace. The checker, its rules
# and the fixture runner are the Rust crate crates/boneli-arch-check, which
# replaced the earlier script checker (ADR-015); why each rule exists is
# recorded in docs/adr/001-core-purity-and-dependency-allowlist.md, and why
# the checker is built this way in docs/adr/015-architecture-checker-in-rust.md.
#
# The checker is built from `/` with an explicit manifest path, so that no
# cargo config or toolchain file in the checkout applies to its build (the
# check reports such files), into its own target directory, and from the
# committed lockfile. It then runs from the caller's working directory, so a
# relative --root resolves as the caller means it.
root=$(CDPATH='' cd -P -- "$(dirname -- "$0")/.." && pwd -P) || exit 2
if ! (cd / && cargo build --quiet --locked --manifest-path "$root/Cargo.toml" \
    -p boneli-arch-check --target-dir "$root/target/arch-check"); then
  echo "FAIL [tool-error] Cargo.toml: cannot build the architecture checker (cargo output on stderr)"
  echo "1 violation(s)"
  exit 2
fi
exec "$root/target/arch-check/debug/boneli-arch-check" "$@"
