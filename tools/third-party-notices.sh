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
# repository from its manifest, and then every top-level regular file of its
# published source whose name starts with LICENSE, LICENCE, COPYING, NOTICE
# or UNLICENSE (any case), verbatim under its file name. A crate without such
# a file with content fails the run: exit 1, every such crate named on
# stderr, nothing on stdout. Output is sorted by name and version in the C
# locale, so it does not depend on tree order or locale.
#
# NOTICES_CRATES (a file of `cargo tree --format '{p}'` output) and
# NOTICES_METADATA (a file of `cargo metadata` JSON) replace the two cargo
# calls; tools/test-release.sh feeds fixtures through them. POSIX sh,
# dash-safe; needs cargo and jq.
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
nl='
'
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

  : > "$tmp/files"
  for f in "$dir"/*; do
    base=${f##*/}
    case $base in
      *"$nl"*) continue ;;
    esac
    # Regular files only: a symlink could point anywhere on the build host.
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    upper=$(printf '%s' "$base" | tr '[:lower:]' '[:upper:]')
    case $upper in
      LICENSE* | LICENCE* | COPYING* | NOTICE* | UNLICENSE*) ;;
      *) continue ;;
    esac
    grep -q '[^[:space:]]' "$f" || continue
    printf '%s\n' "$base" >> "$tmp/files"
  done
  if [ ! -s "$tmp/files" ]; then
    printf '%s %s: no license, copying or notice file in %s\n' "$name" "$version" "$dir" >> "$tmp/missing"
    continue
  fi
  sort "$tmp/files" -o "$tmp/files"

  count=$((count + 1))
  {
    printf '%s\n%s %s\nLicense: %s\nRepository: %s\n%s\n\n' "$sep" "$name" "$version" \
      "${license:-(not declared, see the files below)}" "${repository:-(not declared)}" "$sep"
    while IFS= read -r base; do
      printf '==> %s <==\n' "$base"
      cat "$dir/$base"
      # A file without a final newline still ends its line.
      [ -z "$(tail -c 1 "$dir/$base")" ] || printf '\n'
      printf '\n'
    done < "$tmp/files"
  } >> "$tmp/body"
done < "$tmp/crates"

if [ -s "$tmp/missing" ]; then
  sed 's/^/third-party-notices: /' "$tmp/missing" >&2
  echo "third-party-notices: no notices written; every bundled crate must ship its license text" >&2
  exit 1
fi

cat <<EOF
THIRD-PARTY NOTICES

The binaries in this archive are boneli (https://github.com/Replikanti/boneli),
licensed under the Apache License 2.0 (see LICENSE). They contain the
third-party crates listed below. For each crate, its license, copying and
notice files are reproduced verbatim from its published source.

Target: ${target}
Packages: ${packages}
Third-party crates: ${count}

EOF
cat "$tmp/body"
