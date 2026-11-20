#!/bin/sh
# Packs a release archive and its SHA-256 sidecar (#22, ADR-019). Usage:
#
#   SOURCE_DATE_EPOCH=<seconds> \
#     tools/release-package.sh <stem> <dist-dir> <license> <notices> <binary>...
#
# Writes <dist-dir>/<stem>.tar.gz holding the directory <stem>/ with the
# binaries (mode 0755), LICENSE and THIRD-PARTY-NOTICES.txt (mode 0644), and
# <dist-dir>/<stem>.tar.gz.sha256 in `sha256sum` format naming the bare file,
# so `sha256sum -c` works in the download directory. The archive is
# byte-identical for the same inputs: entries sorted by name, owner 0, every
# mtime SOURCE_DATE_EPOCH (required; the workflow passes the commit time),
# gzip without name or time stamp. Needs GNU tar. POSIX sh, dash-safe.
set -eu
export LC_ALL=C

usage() {
  echo "usage: SOURCE_DATE_EPOCH=<seconds> $0 <stem> <dist-dir> <license> <notices> <binary>..." >&2
  exit 2
}

[ "$#" -ge 5 ] || usage
case ${SOURCE_DATE_EPOCH:-} in
  '' | *[!0-9]*) usage ;;
esac
stem=$1
dist=$2
license=$3
notices=$4
shift 4
case $stem in
  '' | -* | *[!A-Za-z0-9._-]*) usage ;;
esac

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
trap 'exit 130' INT TERM

mkdir "$stage/$stem"
cp "$license" "$stage/$stem/LICENSE"
cp "$notices" "$stage/$stem/THIRD-PARTY-NOTICES.txt"
chmod 0644 "$stage/$stem/LICENSE" "$stage/$stem/THIRD-PARTY-NOTICES.txt"
for bin in "$@"; do
  name=${bin##*/}
  case $name in
    LICENSE | THIRD-PARTY-NOTICES.txt) echo "release-package: a binary named $name" >&2; exit 1 ;;
  esac
  [ ! -e "$stage/$stem/$name" ] || { echo "release-package: two binaries named $name" >&2; exit 1; }
  cp "$bin" "$stage/$stem/$name"
  chmod 0755 "$stage/$stem/$name"
done
chmod 0755 "$stage/$stem"

mkdir -p "$dist"
tar --format=ustar --sort=name --mtime="@$SOURCE_DATE_EPOCH" \
  --owner=0 --group=0 --numeric-owner -C "$stage" -cf - "$stem" \
  | gzip -9 -n > "$dist/$stem.tar.gz"
(cd "$dist" && sha256sum "$stem.tar.gz" > "$stem.tar.gz.sha256")
cat "$dist/$stem.tar.gz.sha256"
