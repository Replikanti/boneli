# JSONTestSuite (vendored)

`test_parsing/` is the parsing corpus of JSONTestSuite by Nicolas Seriot,
<https://github.com/nst/JSONTestSuite>, MIT License (`LICENSE` in this
directory, the upstream text verbatim).

- Source: commit `1ef36fa01286573e846ac449e8683f8833c5b26a`
  (2024-11-22), directory `test_parsing/`.
- Files: 318 in total; `y_` 95 files and 1,190 bytes, `n_` 188 files and
  351,272 bytes, `i_` 35 files and 1,562 bytes.
- Bytes unchanged. Modes are normalized to 0644 (122 files are executable
  upstream), and no file is a symlink.
- `tests/conformance.rs` (`corpus_is_pinned`) pins the counts, the byte
  totals and an FNV-1a-64 digest over the sorted (name, length, bytes)
  records, and the repository's `.gitattributes` marks this directory
  `-text`, so no line-ending conversion can alter a file.

Only the parsing corpus is vendored; `test_transform/` and the upstream
harness are not. Why vendored rather than fetched in CI: ADR-008.

## Re-vendoring

By hand, with no script in this repository: clone the upstream repository,
check out the new commit, replace `test_parsing/` with its files, set their
modes to 0644, and update the commit, date and counts above and the totals
and digest in `corpus_is_pinned` in the same PR. The expectations in
`tests/conformance.rs` (the two rejected `y_` files, the `i_` table) must
then be reviewed for every added or changed file: the table test fails on
any `i_` file it does not list.
