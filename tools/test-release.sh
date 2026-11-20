#!/bin/sh
# Tests of the release tooling (#22, ADR-019): tools/release-notes.sh,
# tools/release-check.sh, tools/third-party-notices.sh,
# tools/release-package.sh and the expression rule of
# .github/workflows/release.yml. Fixtures go to a temporary directory that
# is removed on exit. The real-graph cases read the cargo registry, so run
# this after `cargo test --workspace` (CI: step "Release tooling" of the
# `check` job). POSIX sh, dash-safe. Usage:
#
#   sh tools/test-release.sh
#
# Prints one line per case and ends with `OK: test-release: N cases
# passed`; exits 1 when a case fails.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
tools="$root/tools"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM
out="$tmp/out"
err="$tmp/err"
passed=0
failed=0

# --- helpers ---------------------------------------------------------------

fail_msg() {
  printf '    %s\n' "$*" >&2
  return 1
}

# Runs a command with stdout in $out and stderr in $err; its exit status in
# $rc.
run() {
  rc=0
  "$@" > "$out" 2> "$err" || rc=$?
}

want_rc() {
  [ "$rc" = "$1" ] || fail_msg "exit $rc, want $1; stderr: $(cat "$err")"
}

has() {
  grep -qF -- "$2" "$1" || fail_msg "$(basename "$1") lacks: $2"
}

hasnt() {
  if grep -qF -- "$2" "$1"; then
    fail_msg "$(basename "$1") has: $2"
  fi
}

# A line of the file equal to the whole argument.
has_line() {
  grep -qxF -- "$2" "$1" || fail_msg "$(basename "$1") lacks the line: $2"
}

hasnt_line() {
  if grep -qxF -- "$2" "$1"; then
    fail_msg "$(basename "$1") has the line: $2"
  fi
}

check() {
  name=$1
  if ( "$name" ) > "$tmp/case.log" 2>&1; then
    passed=$((passed + 1))
    printf 'ok   %s\n' "$name"
  else
    failed=$((failed + 1))
    printf 'FAIL %s\n' "$name"
    sed 's/^/    /' "$tmp/case.log"
  fi
}

# --- release-notes.sh --------------------------------------------------------

changelog="$tmp/CHANGELOG.md"
{
  printf '# Changelog\n\n## [Unreleased]\n\n### Added\n\n- Pending.\n\n'
  printf '## [0x1x1] - 2026-03-02\n\n- Regex trap.\n\n'
  printf '## [0.1.10] - 2026-03-01\n\n- Ten.\n\n'
  printf '## [0.1.1] - 2026-02-01\n\n- One.\n\n'
  printf '## [0.1.0-rc.1] - 2026-01-15\n\n- Candidate.\n\n'
  printf '## [0.0.9] - 2026-01-10\n'
  printf '## [0.0.8] - 2026-01-05\n   \n\t\n \t \n\n'
  printf '## [0.0.1] - 2026-01-01\n\n### Added\n\n- Last section.\n\n  continued\n'
} > "$changelog"

notes() {
  run sh "$tools/release-notes.sh" "$1" "$changelog"
}

release_notes_missing_section() {
  notes 0.2.0 || true
  want_rc 1 || return 1
  test ! -s "$out" || fail_msg "printed notes for a missing section"
}

release_notes_empty_section() {
  notes 0.0.9 || true
  want_rc 1 || return 1
  test ! -s "$out" || fail_msg "printed notes for an empty section"
}

release_notes_blank_only_section() {
  notes 0.0.8 || true
  want_rc 1 || return 1
  test ! -s "$out" || fail_msg "printed notes for a blank-only section"
}

release_notes_exact_heading_match() {
  notes 0.1.1 || true
  want_rc 0 || return 1
  printf -- '- One.\n' > "$tmp/want"
  cmp -s "$out" "$tmp/want" || fail_msg "0.1.1 notes: $(cat "$out")" || return 1
  notes 0.1.10 || true
  want_rc 0 || return 1
  printf -- '- Ten.\n' > "$tmp/want"
  cmp -s "$out" "$tmp/want" || fail_msg "0.1.10 notes: $(cat "$out")"
}

release_notes_prerelease_heading() {
  notes 0.1.0-rc.1 || true
  want_rc 0 || return 1
  printf -- '- Candidate.\n' > "$tmp/want"
  cmp -s "$out" "$tmp/want" || fail_msg "rc notes: $(cat "$out")"
}

release_notes_last_section() {
  notes 0.0.1 || true
  want_rc 0 || return 1
  printf '### Added\n\n- Last section.\n\n  continued\n' > "$tmp/want"
  cmp -s "$out" "$tmp/want" || fail_msg "last section notes: $(cat "$out")"
}

check release_notes_missing_section
check release_notes_empty_section
check release_notes_blank_only_section
check release_notes_exact_heading_match
check release_notes_prerelease_heading
check release_notes_last_section

# --- release-check.sh ------------------------------------------------------

# A throwaway git repository with a cargo workspace of five members: a
# binary, a library and the three test and tool roots by name, all at
# workspace version $1, and a release list of the remaining arguments (one
# line each). Copies of the release scripts live in its tools/, so they act
# on this workspace. Committed; origin/main points at that commit.
ws="$tmp/ws"
g() {
  git -C "$ws" -c user.name=test -c user.email=test@example.invalid \
    -c commit.gpgsign=false "$@"
}
member() {
  mkdir -p "$ws/crates/$1/src"
  printf '[package]\nname = "%s"\nversion.workspace = true\nedition.workspace = true\npublish.workspace = true\n' \
    "$1" > "$ws/crates/$1/Cargo.toml"
  if [ "$2" = bin ]; then
    printf 'fn main() {}\n' > "$ws/crates/$1/src/main.rs"
  else
    printf '//! A library.\n' > "$ws/crates/$1/src/lib.rs"
  fi
}
mkws() {
  version=$1
  shift
  rm -rf "$ws"
  mkdir -p "$ws/tools"
  printf '[workspace]\nresolver = "2"\nmembers = ["crates/*"]\n\n[workspace.package]\nversion = "%s"\nedition = "2021"\npublish = false\n' \
    "$version" > "$ws/Cargo.toml"
  member app bin
  member lib-only lib
  member boneli-replay-check bin
  member boneli-arch-check bin
  member boneli-acceptance bin
  printf '# Changelog\n\n## [Unreleased]\n\n## [%s] - 2026-01-01\n\n### Added\n\n- First.\n' \
    "$version" > "$ws/CHANGELOG.md"
  printf '# Packages a release ships, one per line.\n' > "$ws/tools/release-packages"
  for p in "$@"; do
    printf '%s\n' "$p" >> "$ws/tools/release-packages"
  done
  cp "$tools/release-check.sh" "$tools/release-notes.sh" "$ws/tools/"
  g init -q -b main
  g add -A
  g commit -q -m fixture
  g update-ref refs/remotes/origin/main HEAD
}

release_check() {
  run sh "$ws/tools/release-check.sh" "$@"
}

release_check_passes() {
  mkws 0.1.0 app
  release_check v0.1.0 || true
  want_rc 0 || return 1
  has "$out" "v0.1.0"
}

release_check_rejects_version_mismatch() {
  mkws 0.1.0 app
  release_check v0.1.1 || true
  want_rc 1 || return 1
  has "$err" "v0.1.1" || return 1
  has "$err" "0.1.0"
}

release_check_rejects_malformed_tag() {
  mkws 0.1.0 app
  for tag in 0.1.0 V0.1.0 v0.1 'v0.1.0 ' v0.1.0.0 ''; do
    release_check "$tag" || true
    want_rc 1 || fail_msg "tag '$tag' passed" || return 1
  done
}

release_check_accepts_prerelease() {
  mkws 0.1.0-rc.1 app
  release_check v0.1.0-rc.1 || true
  want_rc 0
}

release_check_prerelease_not_equal_to_release() {
  mkws 0.1.0-rc.1 app
  release_check v0.1.0 || true
  want_rc 1 || return 1
  mkws 0.1.0 app
  release_check v0.1.0-rc.1 || true
  want_rc 1
}

release_check_rejects_commit_off_main() {
  mkws 0.1.0 app
  g checkout -q -b side
  printf '\n' >> "$ws/CHANGELOG.md"
  g commit -q -am side
  side=$(g rev-parse HEAD)
  release_check v0.1.0 "$side" || true
  want_rc 1 || return 1
  has "$err" "$side" || return 1
  # HEAD defaults to the side commit as well.
  release_check v0.1.0 || true
  want_rc 1 || return 1
  # The commit on main passes when named explicitly.
  release_check v0.1.0 "$(g rev-parse main)" || true
  want_rc 0
}

release_check_rejects_missing_changelog_section() {
  mkws 0.1.0 app
  printf '# Changelog\n\n## [Unreleased]\n\n- Pending.\n' > "$ws/CHANGELOG.md"
  g commit -q -am "no section"
  g update-ref refs/remotes/origin/main HEAD
  release_check v0.1.0 || true
  want_rc 1
}

release_check_package_list_guard() {
  # Empty list (comments only).
  mkws 0.1.0
  release_check v0.1.0 || true
  want_rc 1 || fail_msg "empty list passed" || return 1
  release_check --packages || true
  want_rc 1 || fail_msg "empty list passed --packages" || return 1
  # A package that is not a member, a library, each test or tool root,
  # and a name that is not a crate name.
  for p in boneli-nope lib-only boneli-replay-check boneli-arch-check boneli-acceptance '-p' 'app extra'; do
    mkws 0.1.0 app "$p"
    release_check v0.1.0 || true
    want_rc 1 || fail_msg "package '$p' passed" || return 1
    release_check --packages || true
    want_rc 1 || fail_msg "package '$p' passed --packages" || return 1
  done
  # A valid list prints its packages and their binaries.
  mkws 0.1.0 app
  release_check --packages || true
  want_rc 0 || return 1
  printf 'app\n' > "$tmp/want"
  cmp -s "$out" "$tmp/want" || fail_msg "--packages printed: $(cat "$out")" || return 1
  release_check --bins || true
  want_rc 0 || return 1
  cmp -s "$out" "$tmp/want" || fail_msg "--bins printed: $(cat "$out")"
}

check release_check_passes
check release_check_rejects_version_mismatch
check release_check_rejects_malformed_tag
check release_check_accepts_prerelease
check release_check_prerelease_not_equal_to_release
check release_check_rejects_commit_off_main
check release_check_rejects_missing_changelog_section
check release_check_package_list_guard

# --- third-party-notices.sh --------------------------------------------------

# A fake registry: one directory per crate, a `cargo metadata` document
# for them, and `cargo tree` output that names them.
reg="$tmp/registry"
meta="$tmp/metadata.json"
# crate <name> <version> <license-expression>; then files go to $reg/<name>-<version>.
crate() {
  dir="$reg/$1-$2"
  mkdir -p "$dir"
  printf 'x\n' > "$dir/Cargo.toml"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$dir/Cargo.toml" >> "$tmp/crates.tsv"
}
# Writes the metadata document from crates.tsv, plus one workspace member.
write_meta() {
  {
    printf '{"packages":['
    printf '{"name":"boneli-egress","version":"0.0.0","license":"Apache-2.0","repository":null,"source":null,"manifest_path":"%s"},' \
      "$tmp/ws-member/Cargo.toml"
    awk -F '\t' '{
      if (NR > 1) printf ","
      printf "{\"name\":\"%s\",\"version\":\"%s\",\"license\":\"%s\",\"repository\":\"https://example.invalid/%s\",\"source\":\"registry+https://github.com/rust-lang/crates.io-index\",\"manifest_path\":\"%s\"}", $1, $2, $3, $1, $4
    }' "$tmp/crates.tsv"
    printf '],"workspace_members":[]}\n'
  } > "$meta"
}
notices() {
  # $1: file with `cargo tree` output.
  run env NOTICES_CRATES="$1" NOTICES_METADATA="$meta" NOTICES_SYSROOT="$sysroot" \
    sh "$tools/third-party-notices.sh" x86_64-unknown-linux-gnu boneli-egress
}
# Prints the copy of file $3 in the section of crate "$1 $2" of notices $4.
copy_of() {
  awk -v hdr="$1 $2" -v mark="==> $3 <==" '
    function flush() {
      if (n > 0 && lines[n] == "") n--
      for (i = 1; i <= n; i++) print lines[i]
      found = 1
    }
    BEGIN { for (i = 0; i < 80; i++) sep = sep "=" }
    # Separators come in pairs around a crate header.
    $0 == sep {
      if (on) { flush(); on = 0 }
      inhead = !inhead
      if (inhead) { getline; crate = $0 }
      next
    }
    /^==> .* <==$/ {
      if (on) { flush(); on = 0 }
      if (crate == hdr && $0 == mark) { on = 1; n = 0 }
      next
    }
    on { lines[++n] = $0 }
    END { if (on) flush(); if (!found) exit 1 }
  ' "$4"
}

rm -f "$tmp/crates.tsv"
crate alpha 1.0.0 "MIT OR Apache-2.0"
printf 'Apache text\n\n  indented line, trailing blanks follow\n\n\n' > "$reg/alpha-1.0.0/LICENSE-APACHE"
printf 'MIT text without a final newline' > "$reg/alpha-1.0.0/LICENSE-MIT"
printf 'NOTICE text\n' > "$reg/alpha-1.0.0/NOTICE"
printf 'not a license\n' > "$reg/alpha-1.0.0/README.md"
# Nested license files (vendored code), a COPYRIGHT file, and what is
# never read: build output, git data, a symlink.
mkdir -p "$reg/alpha-1.0.0/src/vendored/once" "$reg/alpha-1.0.0/third_party/x" \
  "$reg/alpha-1.0.0/target" "$reg/alpha-1.0.0/.git" "$reg/alpha-1.0.0/sub"
printf 'vendored MIT\n\n  kept verbatim\n' > "$reg/alpha-1.0.0/src/vendored/once/LICENSE-MIT"
printf 'third party notice\n' > "$reg/alpha-1.0.0/third_party/x/NOTICE"
printf 'alpha copyright\n' > "$reg/alpha-1.0.0/COPYRIGHT"
printf 'build output\n' > "$reg/alpha-1.0.0/target/LICENSE"
printf 'git data\n' > "$reg/alpha-1.0.0/.git/LICENSE"
printf 'a source file\n' > "$reg/alpha-1.0.0/src/vendored/once/lib.rs"
crate alpha 2.0.0 "MIT"
printf 'alpha two MIT\n' > "$reg/alpha-2.0.0/LICENSE"
crate a_b 0.1.0 "MIT"
printf 'a_b MIT\n' > "$reg/a_b-0.1.0/LICENSE"
crate a-b 0.1.0 "MIT"
printf 'a-b MIT\n' > "$reg/a-b-0.1.0/LICENSE"
crate Zeta 1.0.0 "MIT"
printf 'Zeta MIT\n' > "$reg/Zeta-1.0.0/LICENSE"
crate gamma 0.3.0 "MIT"
printf 'gamma MIT\n' > "$reg/gamma-0.3.0/License.md"
printf 'gamma copying\n' > "$reg/gamma-0.3.0/copying"
crate delta 0.4.0 "ISC"
printf 'delta ISC\n' > "$reg/delta-0.4.0/licence"
printf 'delta unlicense\n' > "$reg/delta-0.4.0/UNLICENSE"
mkdir -p "$reg/delta-0.4.0/LICENSES"
printf 'in a directory\n' > "$reg/delta-0.4.0/LICENSES/MIT.txt"
crate nolicense 1.0.0 "MIT"
printf 'readme only\n' > "$reg/nolicense-1.0.0/README.md"
crate nestedonly 1.0.0 "MIT"
mkdir -p "$reg/nestedonly-1.0.0/vendor"
printf 'a vendored license only\n' > "$reg/nestedonly-1.0.0/vendor/LICENSE"
crate emptylicense 1.0.0 "MIT"
: > "$reg/emptylicense-1.0.0/LICENSE"
printf ' \n\t\n' > "$reg/emptylicense-1.0.0/LICENSE-MIT"
crate linked 1.0.0 "MIT"
printf 'secret\n' > "$tmp/outside-file"
ln -s "$tmp/outside-file" "$reg/linked-1.0.0/LICENSE"
mkdir -p "$tmp/ws-member"
write_meta
ln -s "$tmp/outside-file" "$reg/alpha-1.0.0/sub/LICENSE"

# A fake toolchain: the standard library's notices name Apache-2.0 and
# MIT, not GPL-2.0-only.
sysroot="$tmp/sysroot"
rustdoc="$sysroot/share/doc/rust"
mkdir -p "$rustdoc/licenses"
printf '<html>\n<p>License: Apache-2.0 OR MIT</p>\n<p>gimli: notices</p>\n</html>\n' > "$rustdoc/COPYRIGHT-library.html"
printf 'Apache text of the toolchain\n' > "$rustdoc/licenses/Apache-2.0.txt"
printf 'MIT text of the toolchain\n' > "$rustdoc/licenses/MIT.txt"
printf 'GPL text\n' > "$rustdoc/licenses/GPL-2.0-only.txt"
rust_version=$(cd "$root" && rustc -V | cut -d' ' -f2)

# The tree as cargo prints it: members with their path, repeats marked
# (*), a proc macro, a blank line between two roots.
tree_ok="$tmp/tree-ok"
{
  printf 'boneli-egress v0.0.0 (%s)\n' "$tmp/ws-member"
  printf 'alpha v1.0.0\n'
  printf 'gamma v0.3.0 (proc-macro)\n'
  printf 'alpha v2.0.0\n'
  printf 'a_b v0.1.0\n'
  printf 'alpha v1.0.0 (*)\n'
  printf '\n'
  printf 'boneli-egress v0.0.0 (%s) (*)\n' "$tmp/ws-member"
  printf 'delta v0.4.0\n'
  printf 'a-b v0.1.0\n'
  printf 'Zeta v1.0.0\n'
} > "$tree_ok"

notices_copy_every_license_file() {
  notices "$tree_ok" || true
  want_rc 0 || return 1
  cp "$out" "$tmp/notices"
  for f in LICENSE-APACHE NOTICE; do
    copy_of alpha 1.0.0 "$f" "$tmp/notices" > "$tmp/copy" || fail_msg "no copy of $f" || return 1
    cmp -s "$tmp/copy" "$reg/alpha-1.0.0/$f" || fail_msg "$f is not verbatim" || return 1
  done
  copy_of alpha 1.0.0 LICENSE-MIT "$tmp/notices" > "$tmp/copy" || fail_msg "no copy of LICENSE-MIT" || return 1
  { cat "$reg/alpha-1.0.0/LICENSE-MIT"; printf '\n'; } > "$tmp/want"
  cmp -s "$tmp/copy" "$tmp/want" || fail_msg "LICENSE-MIT is not verbatim" || return 1
  hasnt "$tmp/notices" "not a license" || return 1
  has_line "$tmp/notices" "License: MIT OR Apache-2.0" || return 1
  has_line "$tmp/notices" "Repository: https://example.invalid/alpha"
}

notices_filename_case() {
  notices "$tree_ok" || true
  want_rc 0 || return 1
  cp "$out" "$tmp/notices"
  copy_of gamma 0.3.0 License.md "$tmp/notices" > /dev/null || fail_msg "License.md missing" || return 1
  copy_of gamma 0.3.0 copying "$tmp/notices" > /dev/null || fail_msg "copying missing" || return 1
  copy_of delta 0.4.0 licence "$tmp/notices" > /dev/null || fail_msg "licence missing" || return 1
  copy_of delta 0.4.0 UNLICENSE "$tmp/notices" > /dev/null || fail_msg "UNLICENSE missing" || return 1
  hasnt "$tmp/notices" "in a directory"
}

notices_fail_on_missing_license() {
  cp "$tree_ok" "$tmp/tree"
  printf 'nolicense v1.0.0\n' >> "$tmp/tree"
  notices "$tmp/tree" || true
  want_rc 1 || return 1
  has "$err" "nolicense 1.0.0" || return 1
  test ! -s "$out" || fail_msg "wrote notices on failure"
}

notices_fail_on_empty_license() {
  cp "$tree_ok" "$tmp/tree"
  printf 'emptylicense v1.0.0\n' >> "$tmp/tree"
  notices "$tmp/tree" || true
  want_rc 1 || return 1
  has "$err" "emptylicense 1.0.0" || return 1
  test ! -s "$out" || fail_msg "wrote notices on failure"
}

notices_fail_on_symlinked_license() {
  printf 'linked v1.0.0\n' > "$tmp/tree"
  notices "$tmp/tree" || true
  want_rc 1 || return 1
  has "$err" "linked 1.0.0" || return 1
  hasnt "$out" "secret"
}

notices_fail_on_unknown_crate() {
  printf 'ghost v9.9.9\n' > "$tmp/tree"
  notices "$tmp/tree" || true
  want_rc 1 || return 1
  has "$err" "ghost 9.9.9"
}

notices_two_versions() {
  notices "$tree_ok" || true
  want_rc 0 || return 1
  has_line "$out" "alpha 1.0.0" || return 1
  has_line "$out" "alpha 2.0.0" || return 1
  copy_of alpha 2.0.0 LICENSE "$out" > /dev/null || fail_msg "alpha 2.0.0 LICENSE missing"
}

# A locale that collates "alpha" before "Zeta", unlike C; empty if this
# host has none.
collating_locale() {
  for l in en_US.UTF-8 en_US.utf8 $(locale -a 2> /dev/null); do
    case $l in
      C | C.* | POSIX) continue ;;
    esac
    if [ "$(printf 'Zeta\nalpha\n' | LC_ALL=$l sort 2> /dev/null | head -n 1)" = alpha ]; then
      printf '%s\n' "$l"
      return 0
    fi
  done
}

notices_deterministic_order() {
  run env LC_ALL=C NOTICES_CRATES="$tree_ok" NOTICES_METADATA="$meta" NOTICES_SYSROOT="$sysroot" \
    sh "$tools/third-party-notices.sh" x86_64-unknown-linux-gnu boneli-egress || true
  want_rc 0 || return 1
  cp "$out" "$tmp/first"
  loc=$(collating_locale)
  if [ -z "$loc" ]; then
    echo "    note: no collating locale on this host; input order only"
    loc=C
  fi
  # Reversed, with repeats, under a collating locale.
  awk '{ l[NR] = $0 } END { for (i = NR; i > 0; i--) print l[i] }' "$tree_ok" > "$tmp/tree"
  cat "$tree_ok" >> "$tmp/tree"
  run env LC_ALL="$loc" LANG="$loc" NOTICES_CRATES="$tmp/tree" NOTICES_METADATA="$meta" NOTICES_SYSROOT="$sysroot" \
    sh "$tools/third-party-notices.sh" x86_64-unknown-linux-gnu boneli-egress || true
  want_rc 0 || return 1
  cmp -s "$out" "$tmp/first" || fail_msg "output depends on input order or locale ($loc)" || return 1
  # The standard library first, then each crate once, in C order of
  # "name version": Zeta first, a-b before a_b.
  grep -xE '[A-Za-z_-]+ [0-9.]+' "$tmp/first" > "$tmp/headers"
  printf 'rust-std %s\n' "$rust_version" > "$tmp/want"
  printf 'Zeta 1.0.0\na-b 0.1.0\na_b 0.1.0\nalpha 1.0.0\nalpha 2.0.0\ndelta 0.4.0\ngamma 0.3.0\n' >> "$tmp/want"
  cmp -s "$tmp/headers" "$tmp/want" || fail_msg "headers: $(tr '\n' ' ' < "$tmp/headers")"
}

notices_excludes_members_and_dev() {
  notices "$tree_ok" || true
  want_rc 0 || return 1
  hasnt_line "$out" "boneli-egress 0.0.0" || return 1
  has_line "$out" "gamma 0.3.0"
}

notices_copy_nested_license_files() {
  notices "$tree_ok" || true
  want_rc 0 || return 1
  cp "$out" "$tmp/notices"
  for f in src/vendored/once/LICENSE-MIT third_party/x/NOTICE COPYRIGHT; do
    copy_of alpha 1.0.0 "$f" "$tmp/notices" > "$tmp/copy" || fail_msg "no copy of $f" || return 1
    cmp -s "$tmp/copy" "$reg/alpha-1.0.0/$f" || fail_msg "$f is not verbatim" || return 1
  done
  # Build output, git data, a symlink and other files are never read.
  for s in "build output" "git data" "secret" "a source file"; do
    hasnt "$tmp/notices" "$s" || return 1
  done
  # Crate-relative paths in C order: top level first, then by directory.
  awk '$0 == "alpha 1.0.0" { on = 1 } on && /^==> / { print } on && $0 == "alpha 2.0.0" { exit }' \
    "$tmp/notices" > "$tmp/marks"
  printf '==> COPYRIGHT <==\n==> LICENSE-APACHE <==\n==> LICENSE-MIT <==\n==> NOTICE <==\n==> src/vendored/once/LICENSE-MIT <==\n==> third_party/x/NOTICE <==\n' > "$tmp/want"
  cmp -s "$tmp/marks" "$tmp/want" || fail_msg "files of alpha: $(tr '\n' ' ' < "$tmp/marks")"
}

notices_fail_on_nested_only_license() {
  printf 'nestedonly v1.0.0\n' > "$tmp/tree"
  notices "$tmp/tree" || true
  want_rc 1 || return 1
  has "$err" "nestedonly 1.0.0" || return 1
  test ! -s "$out" || fail_msg "wrote notices on failure"
}

notices_rust_toolchain_section() {
  notices "$tree_ok" || true
  want_rc 0 || return 1
  cp "$out" "$tmp/notices"
  has_line "$tmp/notices" "rust-std $rust_version" || return 1
  for f in share/doc/rust/COPYRIGHT-library.html share/doc/rust/licenses/Apache-2.0.txt share/doc/rust/licenses/MIT.txt; do
    copy_of rust-std "$rust_version" "$f" "$tmp/notices" > "$tmp/copy" || fail_msg "no copy of $f" || return 1
    cmp -s "$tmp/copy" "$sysroot/$f" || fail_msg "$f is not verbatim" || return 1
  done
  # A license text the library's notices do not name stays out.
  hasnt "$tmp/notices" "GPL text"
}

notices_fail_without_toolchain_notices() {
  mv "$rustdoc/COPYRIGHT-library.html" "$tmp/library.html"
  notices "$tree_ok" || true
  mv "$tmp/library.html" "$rustdoc/COPYRIGHT-library.html"
  want_rc 1 || return 1
  has "$err" "rust-std" || return 1
  test ! -s "$out" || fail_msg "wrote notices without the toolchain's notices" || return 1
  # An empty document fails too.
  cp "$rustdoc/COPYRIGHT-library.html" "$tmp/library.html"
  printf ' \n' > "$rustdoc/COPYRIGHT-library.html"
  notices "$tree_ok" || true
  mv "$tmp/library.html" "$rustdoc/COPYRIGHT-library.html"
  want_rc 1 || return 1
  # So does a document whose MIT text is missing.
  mv "$rustdoc/licenses/MIT.txt" "$tmp/MIT.txt"
  notices "$tree_ok" || true
  mv "$tmp/MIT.txt" "$rustdoc/licenses/MIT.txt"
  want_rc 1
}

check notices_copy_every_license_file
check notices_copy_nested_license_files
check notices_fail_on_nested_only_license
check notices_rust_toolchain_section
check notices_fail_without_toolchain_notices
check notices_filename_case
check notices_fail_on_missing_license
check notices_fail_on_empty_license
check notices_fail_on_symlinked_license
check notices_fail_on_unknown_crate
check notices_two_versions
check notices_deterministic_order
check notices_excludes_members_and_dev

# The real dependency graph through cargo: the TLS stack of ADR-005 and
# the egress binary. Names only, so a version bump keeps passing; a new
# crate without a license file turns these red.
real_notices() {
  run sh -c 'cd "$1" && shift && sh tools/third-party-notices.sh "$@"' sh "$root" "$@"
}

notices_real_graph_tls() {
  real_notices x86_64-unknown-linux-gnu boneli-https || true
  want_rc 0 || return 1
  cp "$out" "$tmp/tls"
  for c in rustls webpki-roots ring rustls-webpki rustls-pki-types untrusted subtle \
           zeroize once_cell getrandom cfg-if libc; do
    grep -qE "^$c [0-9]" "$tmp/tls" || fail_msg "no header for $c" || return 1
  done
  has_line "$tmp/tls" "# Community Data License Agreement - Permissive - Version 2.0" || return 1
  # ring's three top-level files and the nested ones its LICENSE points
  # to (vendored once_cell code, fiat-crypto).
  v=$(grep -E '^ring [0-9]' "$tmp/tls" | cut -d' ' -f2)
  for f in LICENSE LICENSE-BoringSSL LICENSE-other-bits src/polyfill/once_cell/LICENSE-APACHE \
           src/polyfill/once_cell/LICENSE-MIT third_party/fiat/LICENSE; do
    copy_of ring "$v" "$f" "$tmp/tls" > /dev/null || fail_msg "ring $f missing" || return 1
  done
  # The standard library: the active toolchain's own notices, verbatim.
  sr=$(cd "$root" && rustc --print sysroot)
  copy_of rust-std "$rust_version" share/doc/rust/COPYRIGHT-library.html "$tmp/tls" > "$tmp/copy" \
    || fail_msg "no notices of the standard library" || return 1
  # The notices end every file with a newline; this one ships without.
  lib="$sr/share/doc/rust/COPYRIGHT-library.html"
  { cat "$lib"; [ -z "$(tail -c 1 "$lib")" ] || printf '\n'; } > "$tmp/want"
  cmp -s "$tmp/copy" "$tmp/want" || fail_msg "std notices not verbatim" || return 1
  copy_of rust-std "$rust_version" share/doc/rust/licenses/MIT.txt "$tmp/tls" > /dev/null \
    || fail_msg "no MIT text of the toolchain" || return 1
  # Build-only (cc) and dev-only crates, and workspace members, are not
  # linked into the binary.
  for c in cc shlex find-msvc-tools boneli-https boneli-http; do
    if grep -qE "^$c [0-9]" "$tmp/tls"; then
      fail_msg "header for $c"
      return 1
    fi
  done
}

notices_real_graph_egress() {
  real_notices x86_64-unknown-linux-gnu boneli-egress || true
  want_rc 0 || return 1
  grep -qE '^httparse [0-9]' "$out" || fail_msg "no header for httparse"
}

check notices_real_graph_tls
check notices_real_graph_egress

# --- release-package.sh ------------------------------------------------------

pkg_inputs() {
  mkdir -p "$tmp/in"
  printf '#!/bin/sh\necho dummy\n' > "$tmp/in/boneli-dummy"
  chmod 0755 "$tmp/in/boneli-dummy"
  printf 'license text\n' > "$tmp/in/LICENSE"
  printf 'notices text\n' > "$tmp/in/notices.txt"
}

package() {
  run env SOURCE_DATE_EPOCH=1700000000 sh "$tools/release-package.sh" \
    "boneli-v0.1.0-linux-x86_64" "$1" "$tmp/in/LICENSE" "$tmp/in/notices.txt" "$tmp/in/boneli-dummy"
}

package_contents() {
  pkg_inputs
  rm -rf "$tmp/dist1"
  package "$tmp/dist1" || true
  want_rc 0 || return 1
  ls "$tmp/dist1" > "$tmp/files"
  printf 'boneli-v0.1.0-linux-x86_64.tar.gz\nboneli-v0.1.0-linux-x86_64.tar.gz.sha256\n' > "$tmp/want"
  cmp -s "$tmp/files" "$tmp/want" || fail_msg "dist holds: $(tr '\n' ' ' < "$tmp/files")" || return 1
  tar -tzf "$tmp/dist1/boneli-v0.1.0-linux-x86_64.tar.gz" > "$tmp/list"
  printf 'boneli-v0.1.0-linux-x86_64/\nboneli-v0.1.0-linux-x86_64/LICENSE\nboneli-v0.1.0-linux-x86_64/THIRD-PARTY-NOTICES.txt\nboneli-v0.1.0-linux-x86_64/boneli-dummy\n' > "$tmp/want"
  cmp -s "$tmp/list" "$tmp/want" || fail_msg "archive lists: $(tr '\n' ' ' < "$tmp/list")" || return 1
  tar -tvzf "$tmp/dist1/boneli-v0.1.0-linux-x86_64.tar.gz" > "$tmp/long"
  grep -q '^-rwxr-xr-x 0/0 .* boneli-v0.1.0-linux-x86_64/boneli-dummy$' "$tmp/long" || fail_msg "binary mode or owner: $(cat "$tmp/long")" || return 1
  grep -q '^-rw-r--r-- 0/0 .* boneli-v0.1.0-linux-x86_64/THIRD-PARTY-NOTICES.txt$' "$tmp/long" || fail_msg "notices mode or owner" || return 1
  # Every entry carries SOURCE_DATE_EPOCH (1700000000) as its mtime.
  TZ=UTC tar --full-time -tvzf "$tmp/dist1/boneli-v0.1.0-linux-x86_64.tar.gz" > "$tmp/long"
  n=$(grep -c ' 2023-11-14 22:13:20 ' "$tmp/long")
  [ "$n" = 4 ] || fail_msg "mtimes: $(cat "$tmp/long")" || return 1
  mkdir "$tmp/x"
  tar -xzf "$tmp/dist1/boneli-v0.1.0-linux-x86_64.tar.gz" -C "$tmp/x"
  cmp -s "$tmp/x/boneli-v0.1.0-linux-x86_64/THIRD-PARTY-NOTICES.txt" "$tmp/in/notices.txt" || fail_msg "notices changed" || return 1
  cmp -s "$tmp/x/boneli-v0.1.0-linux-x86_64/LICENSE" "$tmp/in/LICENSE" || fail_msg "LICENSE changed"
}

package_is_reproducible() {
  pkg_inputs
  rm -rf "$tmp/dist1" "$tmp/dist2"
  package "$tmp/dist1" || true
  want_rc 0 || return 1
  # Other input mtimes and another umask give the same bytes.
  touch -d '2001-02-03 04:05:06' "$tmp/in/LICENSE" "$tmp/in/notices.txt" "$tmp/in/boneli-dummy"
  chmod 0700 "$tmp/in/boneli-dummy"
  rc=0
  (umask 077 && env SOURCE_DATE_EPOCH=1700000000 sh "$tools/release-package.sh" \
    "boneli-v0.1.0-linux-x86_64" "$tmp/dist2" "$tmp/in/LICENSE" "$tmp/in/notices.txt" "$tmp/in/boneli-dummy") \
    > "$out" 2> "$err" || rc=$?
  want_rc 0 || return 1
  cmp -s "$tmp/dist1/boneli-v0.1.0-linux-x86_64.tar.gz" "$tmp/dist2/boneli-v0.1.0-linux-x86_64.tar.gz" \
    || fail_msg "two runs differ"
}

package_sidecar_verifies() {
  pkg_inputs
  rm -rf "$tmp/dist1"
  package "$tmp/dist1" || true
  want_rc 0 || return 1
  (cd "$tmp/dist1" && sha256sum -c boneli-v0.1.0-linux-x86_64.tar.gz.sha256) > /dev/null || fail_msg "sha256sum -c failed" || return 1
  grep -qE '^[0-9a-f]{64}  boneli-v0.1.0-linux-x86_64\.tar\.gz$' "$tmp/dist1/boneli-v0.1.0-linux-x86_64.tar.gz.sha256" \
    || fail_msg "sidecar: $(cat "$tmp/dist1/boneli-v0.1.0-linux-x86_64.tar.gz.sha256")"
}

package_requires_source_date_epoch() {
  pkg_inputs
  rm -rf "$tmp/dist1"
  run env -u SOURCE_DATE_EPOCH sh "$tools/release-package.sh" \
    "boneli-v0.1.0-linux-x86_64" "$tmp/dist1" "$tmp/in/LICENSE" "$tmp/in/notices.txt" "$tmp/in/boneli-dummy" || true
  want_rc 2
}

check package_contents
check package_is_reproducible
check package_sidecar_verifies
check package_requires_source_date_epoch

# --- release.yml -------------------------------------------------------------

# Prints every `${{` inside a `run:` value (single line or block) of the
# workflow files given; exits 1 when there is one. Ref names and other
# context values reach the shell through `env:` only.
expr_in_run() {
  awk '
    function indent(s) { match(s, /^ */); return RLENGTH }
    {
      if (inrun) {
        if ($0 ~ /^[ \t]*$/) next
        if (indent($0) > runind) {
          if (index($0, "${{")) { print FILENAME ":" FNR ": " $0; bad = 1 }
          next
        }
        inrun = 0
      }
      if ($0 ~ /^ *(- )?run:/) {
        at = index($0, "run:")
        runind = at - 1
        if (index(substr($0, at), "${{")) { print FILENAME ":" FNR ": " $0; bad = 1 }
        inrun = 1
      }
    }
    END { exit bad }
  ' "$@"
}

# The fixtures hold literal workflow expressions, not shell ones.
# shellcheck disable=SC2016
release_workflow_no_expression_in_run() {
  # The detector finds both forms and ignores env values.
  printf 'jobs:\n  a:\n    steps:\n      - run: echo ${{ github.ref_name }}\n' > "$tmp/bad1.yml"
  printf 'jobs:\n  a:\n    steps:\n      - name: x\n        run: |\n          echo ok\n\n          echo "${{ github.ref_name }}"\n' > "$tmp/bad2.yml"
  printf 'jobs:\n  a:\n    steps:\n      - name: x\n        env:\n          TAG: ${{ github.ref_name }}\n        run: |\n          echo "$TAG"\n      - uses: x/y@v1\n        with:\n          name: ${{ matrix.arch }}\n' > "$tmp/good.yml"
  for f in bad1 bad2; do
    if expr_in_run "$tmp/$f.yml" > /dev/null; then
      fail_msg "detector missed $f"
      return 1
    fi
  done
  expr_in_run "$tmp/good.yml" > /dev/null || fail_msg "detector flagged an env value" || return 1
  expr_in_run "$root/.github/workflows/release.yml"
}

release_workflow_publish_gate_and_pins() {
  wf="$root/.github/workflows/release.yml"
  # Only a tag push publishes; a dispatch on a tag ref does not.
  awk '/^  publish:$/ { on = 1; next } on && /^  [^ ]/ { exit } on' "$wf" > "$tmp/publish"
  has_line "$tmp/publish" "    if: github.event_name == 'push' && github.ref_type == 'tag'" || return 1
  # Publishing checks the tag against the built commit, before and after.
  # shellcheck disable=SC2016 # a literal line of the workflow
  n=$(grep -cF 'tagged=$(tag_commit)' "$tmp/publish")
  [ "$n" = 2 ] || fail_msg "tag_commit checks in publish: $n" || return 1
  # errexit does not reach into $(...): a failed fetch must fail the
  # function, and an unreadable tag after publishing takes the release down.
  # shellcheck disable=SC2016 # a literal regex over the workflow
  grep -qE 'git fetch .*refs/tags/\$TAG.* \|\| return 1$' "$tmp/publish" ||
    fail_msg "tag_commit does not fail on a failed fetch" || return 1
  # shellcheck disable=SC2016 # a literal line of the workflow
  has_line "$tmp/publish" '          tagged=$(tag_commit) || tagged=unreadable' || return 1
  # Every action outside actions/ is pinned to a full commit.
  if grep -nE '^ *(- )?uses: ' "$wf" | grep -v 'uses: actions/' | grep -vE 'uses: [^@ ]+@[0-9a-f]{40}( |$)'; then
    fail_msg "a third-party action is not pinned to a commit"
    return 1
  fi
}

check release_workflow_no_expression_in_run
check release_workflow_publish_gate_and_pins

# -----------------------------------------------------------------------------

total=$((passed + failed))
if [ "$failed" -ne 0 ]; then
  printf 'FAIL: test-release: %d of %d cases failed\n' "$failed" "$total"
  exit 1
fi
printf 'OK: test-release: %d cases passed\n' "$total"
