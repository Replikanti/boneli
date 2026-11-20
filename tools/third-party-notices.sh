#!/bin/sh
# Writes the third-party notices of a release archive to stdout (#22,
# ADR-019). Usage:
#
#   tools/third-party-notices.sh <target-triple> <package>...
#
# The crates are those `cargo tree -e normal` resolves for the packages on
# that target: what is compiled into the binaries. Build and dev
# dependencies are not linked into them and are left out, and so are
# workspace members (the repository's own LICENSE covers them). For every
# crate the output carries its name and version, the license expression and
# repository from its manifest, and then every regular file of its published
# source, at any depth except target/ and .git/, whose name starts with
# LICENSE, LICENCE, COPYING, COPYRIGHT, NOTICE or UNLICENSE (any case),
# verbatim under its path in the crate. A crate without such a file with
# content at its top level fails the run: exit 1, every such crate named on
# stderr, nothing on stdout. Output is sorted by name and version in the C
# locale, so it does not depend on tree order or locale. A section for the
# Rust standard library comes first (see below); it fails the same way when
# the toolchain does not ship its notices.
#
# NOTICES_CRATES (a file of `cargo tree --format '{p}'` output),
# NOTICES_METADATA (a file of `cargo metadata` JSON) and NOTICES_SYSROOT
# (a toolchain root) replace the cargo and rustc calls;
# tools/test-release.sh feeds fixtures through them. POSIX sh, dash-safe;
# needs cargo, rustc and jq.
set -eu
export LC_ALL=C

usage() {
  echo "usage: $0 <target-triple> <package>..." >&2
  exit 2
}

[ "$#" -ge 2 ] || usage
target=$1
shift
for p in "$@"; do
  case $p in
    '' | -* | *[!A-Za-z0-9_-]*) usage ;;
  esac
done
case $target in
  '' | -* | *[!A-Za-z0-9_.-]*) usage ;;
esac

packages=$*
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

if [ -n "${NOTICES_CRATES:-}" ]; then
  cp "$NOTICES_CRATES" "$tmp/tree"
else
  set --
  for p in $packages; do
    set -- "$@" -p "$p"
  done
  (cd "$root" && cargo tree --locked -e normal --target "$target" --prefix none --format '{p}' "$@") > "$tmp/tree"
fi
if [ -n "${NOTICES_METADATA:-}" ]; then
  cp "$NOTICES_METADATA" "$tmp/metadata.json"
else
  (cd "$root" && cargo metadata --locked --format-version 1) > "$tmp/metadata.json"
fi

# "name version" per crate, once each. `cargo tree` prints `name vX.Y.Z`,
# then a path for members, ` (*)` for repeats and ` (proc-macro)`.
awk 'NF >= 2 && substr($2, 1, 1) == "v" { print $1, substr($2, 2) }' "$tmp/tree" \
  | sort -u > "$tmp/crates"

# Fields separated by the unit separator, which no field holds and which,
# unlike a tab, is not whitespace to `read`, so an empty field stays a
# field: name, version, member or registry, license, repository, manifest path.
jq -r '.packages[]
  | [.name, .version, (if .source == null then "member" else "registry" end),
     (.license // ""), (.repository // ""), .manifest_path]
  | map(tostring) | join("\u001f")' "$tmp/metadata.json" > "$tmp/packages.tsv"

sep=$(printf '%080d' 0 | tr 0 =)
us=$(printf '\037')
# Copies the files named on stdin (paths relative to $1) verbatim, each
# under a `==> path <==` line and followed by a blank line.
emit() {
  while IFS= read -r rel; do
    printf '==> %s <==\n' "$rel"
    cat "$1/$rel"
    # A file without a final newline still ends its line.
    [ -z "$(tail -c 1 "$1/$rel")" ] || printf '\n'
    printf '\n'
  done
}

: > "$tmp/missing"
: > "$tmp/body"
count=0
while IFS=' ' read -r name version; do
  awk -F "$us" -v n="$name" -v v="$version" '$1 == n && $2 == v { print; exit }' \
    "$tmp/packages.tsv" > "$tmp/row"
  if [ ! -s "$tmp/row" ]; then
    printf '%s %s: not in cargo metadata\n' "$name" "$version" >> "$tmp/missing"
    continue
  fi
  IFS=$us read -r _ _ kind license repository manifest < "$tmp/row"
  [ "$kind" = registry ] || continue
  dir=${manifest%/*}

  # Every regular file whose name starts with a license-like word, at any
  # depth (vendored code keeps its license next to it), except build
  # output and git data; paths relative to the crate, C order. find does
  # not follow symlinks and -type f skips them: a symlink could point
  # anywhere on the build host. A line without the `./` prefix belongs
  # to a name with a newline and is dropped.
  (cd "$dir" && find . \( -path ./target -o -path ./.git \) -prune -o -type f -print) \
    | awk -F / 'substr($0, 1, 2) == "./" {
        n = toupper($NF)
        if (n ~ /^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE|UNLICENSE)/) print substr($0, 3)
      }' | sort > "$tmp/candidates"
  : > "$tmp/files"
  while IFS= read -r rel; do
    [ -f "$dir/$rel" ] && [ ! -L "$dir/$rel" ] || continue
    grep -q '[^[:space:]]' "$dir/$rel" || continue
    printf '%s\n' "$rel" >> "$tmp/files"
  done < "$tmp/candidates"
  # The crate's own license must be at its top level.
  if ! grep -q -v / "$tmp/files"; then
    printf '%s %s: no license, copying or notice file at the top level of %s\n' "$name" "$version" "$dir" >> "$tmp/missing"
    continue
  fi

  count=$((count + 1))
  {
    printf '%s\n%s %s\nLicense: %s\nRepository: %s\n%s\n\n' "$sep" "$name" "$version" \
      "${license:-(not declared, see the files below)}" "${repository:-(not declared)}" "$sep"
    emit "$dir" < "$tmp/files"
  } >> "$tmp/body"
done < "$tmp/crates"

# The standard library (std, core, alloc) and the crates it is built from
# (addr2line, gimli, hashbrown, miniz_oxide, rustc-demangle,
# compiler_builtins and more) are linked into every binary, but `cargo
# tree` does not show them. The toolchain ships their notices in
# share/doc/rust/COPYRIGHT-library.html: the in-tree licenses and, for each
# out-of-tree crate, its license files. That document goes in verbatim,
# with every license text under share/doc/rust/licenses/ whose SPDX id it
# names (Apache-2.0 and MIT at least). Missing or empty: fail closed.
# NOTICES_SYSROOT replaces `rustc --print sysroot` for the fixtures.
rustc_version=$(cd "$root" && rustc -V)
if [ -n "${NOTICES_SYSROOT:-}" ]; then
  sysroot=$NOTICES_SYSROOT
else
  sysroot=$(cd "$root" && rustc --print sysroot)
fi

std_doc=share/doc/rust/COPYRIGHT-library.html
std_version=$(printf '%s\n' "$rustc_version" | cut -d ' ' -f 2)
: > "$tmp/std-files"
if [ -f "$sysroot/$std_doc" ] && [ ! -L "$sysroot/$std_doc" ] && grep -q '[^[:space:]]' "$sysroot/$std_doc"; then
  printf '%s\n' "$std_doc" >> "$tmp/std-files"
  for f in "$sysroot"/share/doc/rust/licenses/*.txt; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    id=${f##*/}
    id=${id%.txt}
    grep -qF -- "$id" "$sysroot/$std_doc" || continue
    grep -q '[^[:space:]]' "$f" || continue
    printf 'share/doc/rust/licenses/%s.txt\n' "$id" >> "$tmp/std-files"
  done
  for id in Apache-2.0 MIT; do
    grep -qxF "share/doc/rust/licenses/$id.txt" "$tmp/std-files" \
      || printf 'rust-std %s: no %s text in %s/share/doc/rust/licenses\n' "$std_version" "$id" "$sysroot" >> "$tmp/missing"
  done
else
  printf 'rust-std %s: no %s in the toolchain at %s\n' "$std_version" "$std_doc" "$sysroot" >> "$tmp/missing"
fi
{
  printf '%s\nrust-std %s\nLicense: see the files below\nRepository: https://github.com/rust-lang/rust\n%s\n\n' \
    "$sep" "$std_version" "$sep"
  printf 'The Rust standard library and the crates it is built from, as linked by\n%s. Their notices are the toolchain'"'"'s own, reproduced verbatim.\n\n' \
    "$rustc_version"
  emit "$sysroot" < "$tmp/std-files"
} > "$tmp/std"

if [ -s "$tmp/missing" ]; then
  sed 's/^/third-party-notices: /' "$tmp/missing" >&2
  echo "third-party-notices: no notices written; every bundled crate must ship its license text" >&2
  exit 1
fi

cat <<EOF
THIRD-PARTY NOTICES

The binaries in this archive are boneli (https://github.com/Replikanti/boneli),
licensed under the Apache License 2.0 (see LICENSE). They contain the Rust
standard library and the third-party crates listed below. For each crate,
its license, copyright, copying and notice files, at any depth of its
published source, are reproduced verbatim; for the standard library, the
notices its toolchain ships.

Target: ${target}
Packages: ${packages}
Third-party crates: ${count}

EOF
cat "$tmp/std"
cat "$tmp/body"
