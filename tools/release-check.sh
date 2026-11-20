#!/bin/sh
# The guards of a release (#22, ADR-019). Usage:
#
#   tools/release-check.sh <tag> [<sha>]   guard a release tag
#   tools/release-check.sh --packages      print the packages a release ships
#   tools/release-check.sh --bins          print their binary targets
#
# Every mode first checks tools/release-packages: one package per line
# (`#` comments and blank lines aside), at least one, each a member of this
# workspace with a binary target and none of the test or tool roots. With a
# tag it also requires that the tag is exactly `v` + the workspace version,
# that <sha> (default HEAD) is an ancestor of origin/main, and that
# CHANGELOG.md has a non-empty section for the version (no release with an
# empty body). Exits 1 on a failed guard, 2 on a usage error. POSIX sh,
# dash-safe; needs cargo, jq and git. Acts on the workspace this script
# lives in.
set -eu
export LC_ALL=C

usage() {
  echo "usage: $0 <tag> [<sha>] | --packages | --bins" >&2
  exit 2
}

fail() {
  echo "release-check: $*" >&2
  exit 1
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
mode=tag
case $1 in
  --packages | --bins)
    [ "$#" -eq 1 ] || usage
    mode=${1#--}
    ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
list="$root/tools/release-packages"

# Test and tool roots never ship (roles.roots in tools/architecture.toml:
# the replay gate of ADR-002, the live tests of ADR-014 D12 and the
# architecture checker of ADR-015).
not_shipped="boneli-replay-check boneli-arch-check boneli-acceptance"

[ -f "$list" ] || fail "$list not found"
packages=$(grep -v -e '^#' -e '^[[:space:]]*$' "$list" || true)
[ -n "$packages" ] || fail "tools/release-packages lists no package"

meta=$(cd "$root" && cargo metadata --no-deps --format-version 1 --offline) \
  || fail "cargo metadata failed"

# One name per line, nothing else: a crate name, which also keeps option
# look-alikes out of `cargo -p` and leaves nothing for the shell to split
# or expand in the loops below.
bad=$(printf '%s\n' "$packages" | grep -v -E '^[A-Za-z0-9_][A-Za-z0-9_-]*$' || true)
[ -z "$bad" ] || fail "not a package name in tools/release-packages: $bad"
for p in $packages; do
  for root_crate in $not_shipped; do
    [ "$p" != "$root_crate" ] || fail "$p is a test or tool root and never ships"
  done
  found=$(printf '%s' "$meta" | jq -r --arg p "$p" '[.packages[] | select(.name == $p)] | length')
  [ "$found" = 1 ] || fail "$p is not a member of this workspace"
  bins=$(printf '%s' "$meta" | jq -r --arg p "$p" \
    '.packages[] | select(.name == $p) | .targets[] | select(.kind | index("bin")) | .name')
  [ -n "$bins" ] || fail "$p has no binary target"
done

case $mode in
  packages)
    printf '%s\n' "$packages"
    exit 0
    ;;
  bins)
    for p in $packages; do
      printf '%s' "$meta" | jq -r --arg p "$p" \
        '.packages[] | select(.name == $p) | .targets[] | select(.kind | index("bin")) | .name'
    done
    exit 0
    ;;
esac

tag=$1
sha=${2:-HEAD}

# Every member inherits [workspace.package] version; the first listed
# package stands for it, and every other listed package must agree.
first=$(printf '%s\n' "$packages" | head -n 1)
version=$(printf '%s' "$meta" | jq -r --arg p "$first" '.packages[] | select(.name == $p) | .version')
for p in $packages; do
  v=$(printf '%s' "$meta" | jq -r --arg p "$p" '.packages[] | select(.name == $p) | .version')
  [ "$v" = "$version" ] || fail "$p is at $v, $first at $version"
done

# `v` + MAJOR.MINOR.PATCH with an optional prerelease, and equal to the
# workspace version.
case $tag in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "tag '$tag' is not v<MAJOR>.<MINOR>.<PATCH>[-<prerelease>]" ;;
esac
[ "$tag" = "v$version" ] || fail "tag $tag does not match the workspace version v$version"

commit=$(git -C "$root" rev-parse --verify --quiet "$sha^{commit}") \
  || fail "$sha is not a commit"
git -C "$root" merge-base --is-ancestor "$commit" origin/main \
  || fail "commit $commit is not on origin/main"

sh "$root/tools/release-notes.sh" "$version" "$root/CHANGELOG.md" > /dev/null \
  || fail "CHANGELOG.md has no non-empty section [$version]"

echo "OK: $tag is v$version on origin/main ($commit), changelog section present, ships: $(printf '%s' "$packages" | tr '\n' ' ')"
