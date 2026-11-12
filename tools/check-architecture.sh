#!/usr/bin/env bash
# Enforces the hexagonal boundary and the dependency policy of
# docs/ARCHITECTURE.md ("Code architecture", "Pure Rust and dependencies")
# as crate-graph rules:
#
#   boneli-domain     -> nothing
#   boneli-app        -> boneli-domain
#   support crates    -> other support crates (generic plumbing, no domain)
#   adapters          -> boneli-domain, boneli-app, support crates
#   composition roots -> anything but another root; nothing depends on them
#
# plus three checks:
#   - external dependencies only from the per-crate allowlist below,
#   - core purity: boneli-domain and boneli-app never touch the wall clock,
#     the filesystem, the network, the environment, threads, processes,
#     async or hash-ordered collections (deterministic replay),
#   - every crate except boneli-sys inherits the workspace lints, which
#     forbid unsafe code.
#
# The purity scan is a pattern guard over source text, not a proof; review
# still applies. Dev-dependencies are exempt from the graph rules.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
fail() {
  echo "FAIL: $*"
  status=1
}

roots="boneli-runner boneli-gw boneli-egress boneli-shim boneli-cli"
support="boneli-sys boneli-http boneli-https boneli-json boneli-toml"

# External crates each workspace crate may depend on directly. Widening this
# list is a design decision: it needs an ADR and a justification comment in
# the crate's Cargo.toml (docs/ARCHITECTURE.md, "Pure Rust and dependencies").
allowed_external() {
  case "$1" in
    boneli-sys) echo "libc" ;;
    boneli-http) echo "httparse" ;;
    boneli-https) echo "rustls webpki-roots ring" ;;
    boneli-store-fs) echo "sha2" ;;
    boneli-oci) echo "miniz_oxide ruzstd" ;;
    *) echo "" ;;
  esac
}

meta=$(cargo metadata --format-version 1 --no-deps)
members=$(jq -r '.packages[].name' <<<"$meta")

for core in boneli-domain boneli-app; do
  grep -qx "$core" <<<"$members" || fail "core crate $core is missing from the workspace"
done

# Normal and build dependencies of a workspace member, by package name.
deps_of() {
  jq -r --arg name "$1" \
    '.packages[] | select(.name == $name) | .dependencies[] | select(.kind != "dev") | .name' \
    <<<"$meta"
}

is_in() {
  [[ " $2 " == *" $1 "* ]]
}

for name in $members; do
  if [[ "$name" == boneli-domain ]]; then
    role=domain
  elif [[ "$name" == boneli-app ]]; then
    role=app
  elif is_in "$name" "$roots"; then
    role=root
  elif is_in "$name" "$support"; then
    role=support
  elif [[ "$name" == boneli-* ]]; then
    role=adapter
  else
    fail "$name: every workspace crate is named boneli-<name>"
    continue
  fi

  externals=$(allowed_external "$name")
  for dep in $(deps_of "$name"); do
    if [[ "$dep" == boneli-* ]]; then
      if is_in "$dep" "$roots"; then
        fail "$name -> $dep: composition roots must stay leaves"
        continue
      fi
      case "$role" in
        domain) fail "$name -> $dep: the domain depends on nothing" ;;
        app) [[ "$dep" == boneli-domain ]] || fail "$name -> $dep: the application depends only on the domain" ;;
        support) is_in "$dep" "$support" || fail "$name -> $dep: support crates stay generic (support crates only)" ;;
        adapter)
          [[ "$dep" == boneli-domain || "$dep" == boneli-app ]] || is_in "$dep" "$support" \
            || fail "$name -> $dep: adapters depend on the domain, the application and support crates only"
          ;;
        root) ;;
      esac
    else
      is_in "$dep" "$externals" \
        || fail "$name -> $dep: external dependency not on the allowlist in tools/check-architecture.sh"
    fi
  done

  manifest="crates/$name/Cargo.toml"
  if [[ "$name" != boneli-sys ]] && [[ -f "$manifest" ]]; then
    grep -qE '^\[lints\]' "$manifest" && grep -qE '^workspace[[:space:]]*=[[:space:]]*true' "$manifest" \
      || fail "$name: must inherit the workspace lints ([lints] workspace = true)"
  fi
done

# Module paths are matched both as `std::fs` and as a bare `fs::` usage, so
# grouped imports (`use std::{fs, env};`) are caught where the module is used.
io='(fs|net|env|thread|process)'
forbidden="SystemTime::now|Instant::now|UNIX_EPOCH|\.elapsed\(\)|std::${io}\b|std::\{[^}]*\b${io}\b|\b${io}::|\b(HashMap|HashSet|RandomState)\b|\basync\b|\.await\b"
hits=$(grep -rnE "$forbidden" crates/boneli-domain/src crates/boneli-app/src \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true)
if [[ -n "$hits" ]]; then
  fail "core purity violations (docs/ARCHITECTURE.md, Code architecture):"
  echo "$hits"
fi

if [[ $status -eq 0 ]]; then
  echo "OK: crate graph, dependency allowlist, core purity and lints"
fi
exit $status
