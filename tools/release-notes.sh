#!/bin/sh
# Prints the body of the `## [X.Y.Z]` section of CHANGELOG.md (up to the next
# `## [` heading), for use as GitHub release notes. Usage:
#
#   tools/release-notes.sh <X.Y.Z> [CHANGELOG]
#
# Fails when the section is missing or empty, so a release can never be
# published with an empty body. POSIX sh, dash-safe; used by the release
# workflow and runnable locally to preview the notes.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <X.Y.Z> [CHANGELOG]" >&2
  exit 2
fi
version=$1
changelog=${2:-"$(dirname "$0")/../CHANGELOG.md"}

if [ ! -f "$changelog" ]; then
  echo "release-notes: $changelog not found" >&2
  exit 1
fi

notes=$(awk -v want="## [$version]" '
  index($0, "## [") == 1 {
    if (on) exit
    on = (index($0, want) == 1)
    next
  }
  on { print }
' "$changelog")

# Reject a section that holds nothing but whitespace.
if [ -z "$(printf '%s' "$notes" | tr -d ' \t\n\r')" ]; then
  echo "release-notes: no non-empty '## [$version]' section in $changelog" >&2
  exit 1
fi

printf '%s\n' "$notes" | awk '
  NF { started = 1 }
  started { lines[++n] = $0 }
  END {
    while (n > 0 && lines[n] !~ /[^ \t]/) n--
    for (i = 1; i <= n; i++) print lines[i]
  }
'
