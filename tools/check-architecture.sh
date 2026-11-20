#!/bin/sh
# Architecture and dependency rules of the workspace. The checker, its rules
# and the fixture runner are the Rust crate crates/boneli-arch-check, which
# replaced the earlier script checker (ADR-015); why each rule exists is
# recorded in docs/adr/001-core-purity-and-dependency-allowlist.md, and why
# the checker is built this way in docs/adr/015-architecture-checker-in-rust.md.
#
# Every cargo call here runs from `/` with an explicit manifest path, so that
# no cargo config or toolchain file in the checkout applies (the check
# reports such files). Before anything is compiled, reads that run no code
# from the checkout make sure the build of the checker runs none either
# (ADR-015, D2). Each decision reads only output that the checkout cannot
# fill with free text, matched whole, or tests for something cargo prints
# that added text cannot take away:
#   - its build closure is exactly boneli-arch-check, boneli-json and
#     boneli-toml, each a directory of this checkout without symlinks and,
#     by cargo's own workspace resolution, a member of this workspace: no
#     other crate, so no external build script and no proc macro;
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
# rustc's own output; the triple is used in paths, so only its characters.
host=$(cd / && rustc -vV | sed -n 's/^host: //p') ||
  fail tool-error "cannot read the host triple from rustc -vV" 2
case $host in
  '' | *[!A-Za-z0-9_.-]*) fail tool-error "rustc -vV printed no usable host triple" 2 ;;
esac
# Each of the three is a real directory of this checkout: no symlink in its
# path, so the sources the closure names are the ones under crates/.
for name in $checker_crates; do
  [ "$(CDPATH='' cd -P -- "$crates/$name" 2>/dev/null && pwd -P)" = "$crates/$name" ] ||
    fail tool-error "crates/$name is not a directory of this checkout without symlinks" 2
done
# Each of the three is a member of this workspace, as cargo resolves it:
# the workspace root cargo finds for its manifest is this one, the whole
# output (one path cargo computes) compared exactly. An excluded crate
# gives its own manifest or an error, never this root.
for name in $checker_crates; do
  ws=$(cd / && cargo locate-project --workspace --message-format plain \
      --manifest-path "$crates/$name/Cargo.toml") && [ "$ws" = "$manifest" ] ||
    fail tool-error "$name, which the architecture checker's build compiles, is not a member of this workspace" 2
done
# The build closure: one line per package in both forms, so that a path
# with a line break cannot add a line to one form only, and each line
# exactly `<name> v<version> (<checkout>/crates/<name>)` with a version of
# semver characters, so a path cannot carry a second package name either.
tree() {
  cd / && cargo tree --locked --manifest-path "$manifest" -p boneli-arch-check \
    -e normal,build --target "$host" --prefix none --format "$1"
}
dots=$(tree .) && closure=$(tree '{p}') ||
  fail tool-error "cannot list the build closure of the architecture checker (cargo output on stderr)" 2
foreign="the architecture checker's build would compile a crate other than boneli-arch-check, boneli-json and boneli-toml of this checkout, which could run code before the check"
[ "$dots" = "$(printf '.\n.\n.')" ] || fail tool-error "$foreign" 2
seen=
while IFS= read -r line; do
  matched=
  for name in $checker_crates; do
    rest=${line#"$name v"}
    [ "$rest" != "$line" ] || continue
    version=${rest%" ($crates/$name)"}
    [ "$version" != "$rest" ] || continue
    case $version in
      '' | *[!0-9A-Za-z.+-]*) continue ;;
    esac
    case " $seen " in
      *" $name "*) ;;
      *) seen="$seen $name" matched=1 ;;
    esac
  done
  [ -n "$matched" ] || fail tool-error "$foreign" 2
done <<EOF_CLOSURE
$closure
EOF_CLOSURE
[ "$(printf '%s\n' "$closure" | wc -l)" -eq 3 ] || fail tool-error "$foreign" 2
# Build scripts and proc macros of the members: `cargo metadata --no-deps`
# also echoes [workspace.metadata] and [package.metadata] verbatim, but a
# target cargo reports as `custom-build` or `proc-macro` always prints its
# kind array, and text the checkout adds can only add matches, never
# remove one (a false positive fails closed). Attack 1 of the CI
# regression step proves on every run that this cargo prints the kind.
members=$(cd / && cargo metadata --no-deps --offline --format-version 1 --manifest-path "$manifest") ||
  fail tool-error "cargo metadata --no-deps failed (cargo output on stderr)" 2
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
