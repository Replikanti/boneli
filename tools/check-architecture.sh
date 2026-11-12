#!/bin/sh
# Architecture and dependency rules of the workspace. The checker, its rules
# and the fixture runner live in tools/check_architecture.py; why each rule
# exists is recorded in docs/adr/001-core-purity-and-dependency-allowlist.md.
exec python3 -I "$(dirname "$0")/check_architecture.py" "$@"
