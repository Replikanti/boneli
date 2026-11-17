# toml-test (vendored)

The TOML 1.0.0 files of toml-test by the TOML authors,
<https://github.com/toml-lang/toml-test>, MIT License (`LICENSE` in this
directory, the upstream text verbatim).

- Source: commit `96fd088448ec0f4d9f061c730ed7854399c46faf`
  (2026-10-27), directory `tests/`: exactly the files that upstream's
  `tests/files-toml-1.0.0` lists, and that list itself (`files-toml-1.0.0`
  here, verbatim). The TOML 1.1 files are not vendored.
- Files: 925 listed, 103,336 bytes; `valid/` 208 `.toml` files and their 208
  expected `.json` values, `invalid/` 509 `.toml` files.
- Bytes unchanged, modes 0644 (upstream has no executables), and no file is
  a symlink.
- `tests/conformance.rs` (`corpus_is_pinned`) requires that the files here
  are exactly the list and pins the counts, the byte total and an
  FNV-1a-64 digest over the sorted (name, length, bytes) records. The
  repository's `.gitattributes` marks this directory `-text`, so no
  line-ending conversion can alter a file; seven of them depend on exact
  CR and CRLF bytes.
- `tests/toml_test_outcomes.txt` pins the outcome of every `.toml` file
  (`ok`, `unsupported:<feature>` or `error:<kind>`), and
  `outcomes_are_pinned` compares the value of every accepted valid file
  with its `.json`.

Why vendored rather than fetched in CI: ADR-011, D9.

## Re-vendoring

By hand, with no script in this repository: clone the upstream repository,
check out the new commit, copy the files `tests/files-toml-1.0.0` lists and
the list itself into this directory, set their modes to 0644, and update the
commit, date and counts above and the totals and digest in
`corpus_is_pinned` in the same PR. `outcomes_are_pinned` then fails and
prints the computed outcomes; every changed line of
`tests/toml_test_outcomes.txt` must be reviewed before it is committed: a
valid file may only be `ok` or `unsupported:*`, and no invalid file may be
`ok`.
