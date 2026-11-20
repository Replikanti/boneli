#!/bin/sh
# Architecture and dependency rules of the workspace. The checker, its rules
# and the fixture runner are the Rust crate crates/boneli-arch-check, which
# replaced the earlier script checker (ADR-015); why each rule exists is
# recorded in docs/adr/001-core-purity-and-dependency-allowlist.md, and why
# the checker is built this way in docs/adr/015-architecture-checker-in-rust.md.
#
# Every cargo call here runs from `/` with an explicit manifest path, so that
# no cargo config or toolchain file in the checkout applies (the check
# reports such files). Before anything is compiled, two reads that run no
# code from the checkout make sure the build of the checker runs none either
# (ADR-015, D2):
#   - its build closure is exactly boneli-arch-check, boneli-json and
#     boneli-toml, each a directory of this checkout without symlinks and a
#     workspace member: no other crate, so no external build script and no
#     proc macro;
#   - no workspace member has a build script or is a proc macro
#     (roles.build-script is empty), so neither do those three.
# The checker is then built from the committed lockfile for the host triple,
# into its own target directory, after its old binary is deleted, so a stale
# binary can never run. It runs from the caller's working directory, so a
# relative --root resolves as the caller means it.
fail() {
  echo "FAIL [$1] Cargo.toml: $2"
  echo "1 violation(s)"
  exit "$3"
}
root=$(CDPATH='' cd -P -- "$(dirname -- "$0")/.." && pwd -P) || exit 2
manifest=$root/Cargo.toml
crates=$root/crates
checker_crates="boneli-arch-check boneli-json boneli-toml"
host=$(cd / && rustc -vV | sed -n 's/^host: //p') && [ -n "$host" ] ||
  fail tool-error "cannot read the host triple from rustc -vV" 2
# Each of the three is a real directory of this checkout: no symlink in its
# path, so the sources the closure names are the ones under crates/.
for name in $checker_crates; do
  [ "$(CDPATH='' cd -P -- "$crates/$name" 2>/dev/null && pwd -P)" = "$crates/$name" ] ||
    fail tool-error "crates/$name is not a directory of this checkout without symlinks" 2
done
closure=$(cd / && cargo tree --locked --manifest-path "$manifest" -p boneli-arch-check \
    -e normal,build --target "$host" --prefix none --format '{p}') ||
  fail tool-error "cannot list the build closure of the architecture checker (cargo output on stderr)" 2
[ -n "$closure" ] || fail tool-error "the build closure of the architecture checker is empty" 2
printf '%s\n' "$closure" | while IFS= read -r line; do
  case $line in
    "boneli-arch-check v"*" ($crates/boneli-arch-check)"* | \
    "boneli-json v"*" ($crates/boneli-json)"* | \
    "boneli-toml v"*" ($crates/boneli-toml)"*) ;;
    *) exit 1 ;;
  esac
done || fail tool-error "the architecture checker's build would compile a crate other than boneli-arch-check, boneli-json and boneli-toml of this checkout, which could run code before the check" 2
members=$(cd / && cargo metadata --no-deps --offline --format-version 1 --manifest-path "$manifest") ||
  fail tool-error "cargo metadata --no-deps failed (cargo output on stderr)" 2
case $members in
  *'"targets":'*) ;;
  *) fail tool-error "cargo metadata --no-deps printed no targets" 2 ;;
esac
# Each of the three is a workspace member, so the two checks below cover
# it: a crate excluded from the workspace, or the root of a workspace of
# its own, would build with its build script unseen.
for name in $checker_crates; do
  case $members in
    *"\"manifest_path\":\"$crates/$name/Cargo.toml\""*) ;;
    *) fail tool-error "$name, which the architecture checker's build compiles, is not a member of this workspace" 2 ;;
  esac
done
case $members in
  *'"kind":['*'"custom-build"'*) fail build-script "a workspace member has a build script, which would run before the check could report it (roles.build-script is empty)" 1 ;;
esac
case $members in
  *'"kind":['*'"proc-macro"'*) fail proc-macro "a workspace member is a proc macro, which could run before the check could report it" 1 ;;
esac
bin=$root/target/arch-check/$host/debug/boneli-arch-check
rm -f "$bin" || fail tool-error "cannot remove the old architecture checker binary" 2
(cd / && cargo build --quiet --locked --manifest-path "$manifest" -p boneli-arch-check \
    --target "$host" --target-dir "$root/target/arch-check") ||
  fail tool-error "cannot build the architecture checker (cargo output on stderr)" 2
[ -x "$bin" ] || fail tool-error "the build left no architecture checker binary at target/arch-check/$host/debug" 2
exec "$bin" "$@"
