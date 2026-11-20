# ADR-013: The patch policy

- Status: accepted
- Date: 2026-11-19

## Context

`docs/ARCHITECTURE.md`, "Debugging line", lists a **patch policy** next to
the gates: it "checks diff size, forbidden paths (CI, Dockerfile,
CODEOWNERS), binaries, symlinks pointing outside and disabled tests". Issue
#18 builds it. Three things make it a security decision rather than a
style rule:

- The fix branch is pushed to the customer's repository (#19), so CI that
  is defined in the repository runs on the pull request, with the
  repository's secrets, before a human reads the diff. A fix that edits a
  workflow is code execution with those secrets.
- Gates are deterministic and fail closed (invariant 6). The policy sees
  agent-written content, so whatever it cannot judge it refuses.
- ADR-010 (D2) keeps every symlink target in a workspace as written, never
  resolves one on the host, and hands the question "which links may a fix
  add" to the patch policy. This ADR answers it (D6).

Wiring the policy into the run (an evaluation point between `FixWritten`
and `VerifyFix`, a `Git` port operation, limits as run input) is #68, by
decision 1 at #18 STOP 1. This ADR fixes the policy itself, its input and
the converter from the `boneli-git-cli` workspace format.

The decisions below were settled at #18 STOP 1: wiring as a follow-up
(#68), the `Dependencies` class in, JS/TS only for disabled tests in v1
(Python and `.vue`/`.svelte` in-source tests are #69), and every
fail-closed widening beyond the issue's literal list kept.

## Decision

### D1. Input model

`boneli_domain::patch_policy(&Patch, &PatchLimits) -> PatchVerdict` is a
pure function. A `Patch` holds the changed paths, each with its full
`before` and `after` entry (`None` where the path is absent), and every
symlink of the base tree (`base_links`). An entry is one of git's four tree
entry kinds, `File`, `Executable`, `Symlink` and `Gitlink` (modes 100644,
100755, 120000 and 160000), with its bytes: the content, the link target or
the gitlink's commit id.

The domain computes everything itself (line edit distance, path classes,
link walks, JS/TS markers), so the verdict never rests on a number an
adapter computed, and the replay gate covers it. `Gitlink` exists so a git
tree change is never lossy, although a workspace diff never produces one
(ADR-010, D3 refuses entries at or under gitlinks).

Violations derive `Debug` and carry only indices, counts and enum values,
never content (the rule of ADR-004, D10), and the policy adds no
hand-written `fmt` impl to the domain. `boneli-git-cli` gets
`patch_between(base, after)`, a lossless converter from two ADR-010
workspaces: a merge join in path order that drops repository metadata on
both sides, as `diff` does (ADR-010, D1), with every symlink of the base as
`base_links`.

Limits (files, lines and bytes) are non-zero by type and inclusive, as the
budget limits are (ADR-002, D3): 25 files pass and 26 fail; 1,000 lines
pass and 1,001 fail; 42,000 bytes pass and 42,001 fail.

### D2. Evaluation order

1. More changes than the file limit: `TooManyFiles`, and nothing else
   runs. This bounds every later step by the file limit.
2. No changes: `Empty`. An empty fix is not a fix.
3. Validation, changes first and then base links, collecting every
   problem; if there is any, the patch is rejected with exactly those and
   nothing else runs, because an inconsistent patch is never judged:
   `OutOfOrder` (a path not strictly greater than the previous one in byte
   order, duplicates included), `Path` (the shared citation path rule,
   `gate::path_problem`), `NoChange` (`before == after`, both absent
   included), `EmptyLinkTarget` and `NulInLinkTarget` (a symlink on either
   side, as ADR-010 D2 rules), `BaseLinkMismatch` (a `before` symlink
   without an equal base link, or a change at a base link's path whose
   `before` is not that symlink; checked only when the base links are well
   formed), and `BaseLinkMalformed` for the base links' own order, path
   and target problems.
4. Size (D3): `TooManyLines` or `TooManyBytes`, whichever budget the
   count crosses first, first in the list.
5. Per change, in index order, each family once: `Forbidden` (the first
   matching class), `Gitlink`, `NotText` (the first of `Nul`, `NotUtf8`,
   `BidiControl`), `Link`, then `DisablesTests` for each marker in marker
   order, `DeletedTestFile`, `TestsRemoved` and `TestConfigChanged`.
6. No violation: `Pass { files, lines }`.

Arithmetic is checked or saturating and indexing goes through `get`: no
input panics (a 10,000-patch pseudo-random run pins it).

### D3. Size

Files are the number of changes; a rename is a delete plus an add, since
the adapter diffs without rename detection. A line is a run of bytes up to
and including `\n`, plus a final run without one if it is not empty: `""`
has 0 lines, `"a"` 1, `"a\n"` 1, `"a\nb"` 2, and `"a"` to `"a\n"` costs 2,
as git's "No newline at end of file" does. A text side gives its lines, a
symlink or gitlink side one line, a binary or absent side none (D5 refuses
a binary after side anyway). A type change (a file to a symlink) shares no
lines, as git shows it as a deletion and an addition; a mode-only change
costs 0.

The cost of a change is the least number of inserted plus deleted lines
and the bytes of those lines, newlines included: Myers' greedy forward
pass, cut off at what is left of the line budget, with the edit script
recovered from the furthest point of every diagonal and step. Before the
search, the line counts and the byte lengths of the two sides cut it off:
a line-count difference above what is left is over the line budget, and a
byte-length difference above what is left of the byte budget is over it
(common lines are equal on both sides, so the difference is a lower bound
of the changed bytes). A multiset count of lines would cost 0 for
reordered lines and so fail open.

**Time is O(total bytes + (N + M) * D) and memory linear with a small
constant.** Common leading and trailing lines are stripped by walking both
sides. Each remaining line is hashed once (FNV-1a, 8 bytes per line), the
search compares hashes, and the recovered edit script is then verified
byte for byte in one pass, which also sums the changed bytes. A hash
collision could only make two different lines look equal; the
verification finds it and the change is refused (`TooManyLines`), so the
hash need not resist collisions. The trace keeps one entry per diagonal
and step, at most (D + 1)(D + 2) / 2 for a distance of D, about 0.5
million at the default budget. Above a line budget of 4,096 the script is
not recovered (its trace would pass 8.4 million entries): the search then
compares the bytes of lines with equal hashes on the spot, keeping each
line's start (8 more bytes per line), and the bytes are bounded by both
middles together, which refuses more, never less. Measured in a debug
build: a 200,000-line file with 499 spread edits takes about 1.6 s (an LCS
table would need 4 * 10^10 cells); 400 distinct 25 KB lines per side, all
different, take about 1.7 s. Reviews of PR #70 found two earlier forms:
the first collected every line before the cut-off (a 100 MB added file
peaked at 1.66 GB, now about 100 MB resident, the file itself), and the
second rescanned whole lines at every search step (500 distinct 100 KB
lines per side took 36 s in a release build, now 0.7 s).

**The byte budget** closes what a line count cannot see: a one-line file of
several megabytes, minified or generated, costs one line.

**Defaults: 1,000 lines, 42,000 bytes and 25 files**, the 97th percentile
of the human fixes measured in D8 (973 lines rounded up to the next
hundred, 41,616 bytes rounded up to the next thousand, and 25 files). Why p97: the
size rule should refuse what is unusual for a fix in these repositories,
not large fixes that are still typical, and at p97 it rejects 3.9% of
human fixes, next to about 5% from the other rules; the byte budget adds 3
fixes that are within 1,000 lines and 25 files. At 500 lines and 20 files
it would reject 9.1%; at 1,500 and 30 files (or p99, 2,483 lines, 106,443
bytes and 49 files) it lets through diffs a human cannot review line by
line before merging (ARCHITECTURE, step 6). All three are run input later
(#32), like the budget.

### D4. Forbidden paths

Each path component is folded before it is matched: cut at the first `:`
(NTFS stream syntax), Unicode default-ignorable code points dropped, the
non-ASCII code points whose case mapping or folding is ASCII letters
replaced by them, ASCII lowercased, trailing `.` and ` ` trimmed. The
code points were derived from UnicodeData.txt and CaseFolding.txt of
Unicode 18.0.0, the version `values.rs` cites, by listing every code point
above U+007F whose simple uppercase, lowercase or titlecase mapping, or
whose case folding of any status, consists of ASCII letters only. The
simple mappings give U+0130 and U+0131 (`i`), U+017F (`s`) and U+212A
(`k`); the full foldings, which casefolding file systems such as ext4
`casefold` apply, add U+00DF, U+1E9E and U+1DF95 (`ss`) and the ligatures
U+FB00 to U+FB06 (`ff`, `fi`, `fl`, `ffi`, `ffl`, `st`, `st`), so
`Docker` + U+FB01 + `le` is a Dockerfile. Folding over-matches on purpose:
it can only refuse names no fix needs, the reasoning of ADR-010 D6.
Cyrillic or fullwidth look-alikes are different names on every file system
and stay content.

Classes, in this order, on every change kind (deleting a workflow turns a
check off as surely as editing it):

- `RepositoryMetadata`: a component `.git` or `git~N` (8.3 short names).
  Defense in depth: `diff` drops metadata and `apply` refuses it
  (ADR-010, D1).
- `Ci`: a component `.github`, `.gitlab`, `.circleci`, `.buildkite`,
  `.azure-pipelines` or `.woodpecker`; or a last component
  `.gitlab-ci.yml`/`.yaml`, `.travis.yml`, `jenkinsfile` or
  `jenkinsfile.*`, `azure-pipelines.yml`/`.yaml`,
  `bitbucket-pipelines.yml`, `.drone.yml`/`.yaml`,
  `.woodpecker.yml`/`.yaml`, `appveyor.yml`, `.appveyor.yml` or
  `.cirrus.yml`. The whole `.github` and `.gitlab` directories, because
  they also hold composite actions, CODEOWNERS, Dependabot configuration
  and templates, none of which a code fix needs.
- `ContainerBuild`: `dockerfile`, `containerfile`, `dockerfile.*`,
  `containerfile.*`, `*.dockerfile`, `*.containerfile`, `.dockerignore`,
  `.containerignore`, and the compose files `compose.*` and
  `docker-compose.*` ending in `.yml` or `.yaml`. They define the image and
  the replica the line verifies in (ARCHITECTURE, "Environment and data"),
  so a fix that edits them changes what verification measures.
- `CodeOwners`: `codeowners` in any directory (GitHub reads the root,
  `.github/` and `docs/`; GitLab the root, `.gitlab/` and `docs/`).
- `GitConfig`: `.gitattributes` and `.gitmodules`. Attributes decide what
  a reviewer sees (`linguist-generated` collapses a file in the pull
  request view, `-diff` hides its lines), and `.gitmodules` decides what a
  checkout fetches.
- `Dependencies`: `package.json`, `package-lock.json`,
  `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`,
  `yarn.lock`, `.yarnrc`, `.yarnrc.yml`, `.npmrc`, `.pnpmfile.cjs`,
  `bun.lock`, `bun.lockb`, or a component `.yarn`. The verify sandbox has
  no network and runs on the base's prepare layer (ARCHITECTURE, "Three
  phases"), so a dependency change in a fix is never verified, and these
  files can redirect registries or run code at install. It costs 36 of
  the 769 measured fixes (D8).

A change with a gitlink side is refused (`Gitlink`): the policy cannot see
a submodule's content. Per-repository forbidden paths and custom CI
locations (GitLab's custom CI path, Jenkins script paths, `include:`
targets) are #21.

### D5. Text

A `File` or `Executable` after side must be UTF-8 with no NUL anywhere and
none of the explicit bidi formatting characters U+202A to U+202E and
U+2066 to U+2069 (Trojan Source, CVE-2021-42574). The whole content is
read: git's own binary check reads only the first 8,000 bytes, so a NUL at
byte 8,000 is binary here. Deleting a binary passes; adding or modifying
one does not. A BOM, LRM and RLM (U+200E, U+200F) and right-to-left text
are text.

### D6. Symlinks

Each symlink on the after side (added, retargeted, or converted from a
file) passes only when its target:

- is UTF-8 (`NotUtf8`);
- is at most **4,095 bytes** (`TooLong`): Linux refuses a 4,096-byte target
  with ENAMETOOLONG (checked with `ln -s` on a Linux host), so no Linux
  checkout holds a longer one, and the bound caps the walk;
- does not start with `/` (`Absolute`);
- holds no `\` or `:`, and no component other than `.` and `..` made only
  of dots and spaces (`WindowsForm`): `..\x`, `C:x`, and `.. ` or `...`,
  which Windows trims to `..` or `.`, resolve differently on a Windows
  checkout;
- walks inside the repository: the walk starts at the link's parent
  directory and applies the target's components; empty and `.` are
  skipped, `..` pops, and popping at the root is `Escapes`;
- never passes through a link (`ThroughLink`): at each parent prefix and
  each pushed component, the path must not alias a symlink of the tree
  after the fix (the base links the patch does not change plus the after
  side's links). A link to itself is a walk through a link;
- resolves into no forbidden class (`Into(class)`): `x -> .git` and
  `docs/wf -> ../.github/workflows` are refused;
- does not resolve to the root, which holds `.git`, or to a directory above
  a forbidden path the patch or the tree's links name
  (`Encloses(class)`): `x -> .`, `docs/x -> ..` and `x -> .github/..` are
  refused, and so is `l -> apps/web` next to a link at
  `apps/web/package.json`. A tool that walks a directory and follows links
  would find the forbidden files again under the link. The policy knows
  the paths of the changes and the links, not the whole tree, so a link to
  a directory that holds an unlisted forbidden file passes; the root
  always holds one.

**Aliases.** Two components alias when their keys are equal. The key of
an ASCII component is its D4 folding, so a case, ignorable-character or
NTFS alias counts. The domain has no Unicode case folding or
normalization tables (a core crate takes no dependencies, ADR-001), so it
cannot decide whether `Ä` and `ä`, or `é` and `e` + U+0301 (NFC and NFD),
are one name on a case-insensitive or normalizing file system. Every
non-ASCII component therefore gets one shared key: any two non-ASCII
components alias. That refuses a file beneath `ü/` next to a link at
`ö`, which no fix needs, and never lets an alias through (review round 1
of PR #70: `Ä -> .github` with `ä/workflows/ci.yml` passed).

**Links at protected paths protect what they point to.** A link of the
tree after the fix whose own path is forbidden (D4), a test runner's
configuration, a JS/TS test file or inside a test directory (D7; the
link's own name counts, so `tests -> shared` is one) is resolved like any
reader would: from its parent directory, in every reading at once. At a
name that aliases a link, both the link (all targets of all aliasing
links, up to 40 links deep, Linux's ELOOP limit) and the real directory a
case-sensitive checkout may hold under that name are followed. A target
holding a `\` is read twice, split at `/` only and split at `/` and `\`,
as a Windows checkout reads it. Every link position the resolutions pass
and every path they end on are protected, and a change at, above or
beneath a protected path takes the link's class: `Forbidden`,
`TestConfigChanged` for a test runner's configuration, and for a test path
the test-file rules of D7 (markers with the key form, `TestsRemoved`,
`DeletedTestFile`), whatever the reached file's name. So editing
`config/npmrc` behind a base link `.npmrc -> config/npmrc` is a
dependency change (review round 1 of PR #70: npm reads the registry
through the link). Outward and absolute targets protect nothing, because
nothing in the patch is there.

**The resolutions are bounded, and every bound fails closed** (review
round 3 of PR #70: an agent's links with 40 KB targets made the walk
grab memory until the process aborted at 8 GB, and 23 guard links over
two legal 4,094-byte targets took 45 s and 1.35 GB in a release build).
Each bound, once crossed, makes the policy protect every path, which
refuses the whole patch:

- A target over 4,095 bytes (`MAX_TARGET`, the Linux limit of this
  section) or not UTF-8 is never walked, whether it is the protected
  link's own or one met on the way.
- One resolution makes at most 256 states (a state is one resolution in
  progress; each alias of a followed link and each reading adds one),
  counted when they are made, so at most 256 wait at any time. A natural
  chain needs one state per link it follows, at most 41, so only trees
  built to branch reach the cap.
- All resolutions of one patch together walk at most 2^20 bytes: each
  component costs its length plus one. That is 256 walks of one longest
  target each (256 x 4,096), the bound the state cap gives one
  resolution, now for the whole patch, however many protected links the
  tree holds.

Memory follows the work: every reached directory is a place in one arena
shared by all resolutions (a path is stored once, however often it is
reached), a place is made only by a step and stores its component, so
the arena holds at most 2^20 places and 2^20 key bytes. A branch copies a
place index and at most 41 frames that point into target components
stored once per followed target, never the components themselves. With
these bounds the two inputs above take under 1 ms and 3 MB, and 74 ms and
9 MB.

The same parent-prefix check applies to every regular file of the after
side: a file beneath a link of the tree after the fix is `ThroughLink`.
Lexically `docs/workflows/ci.yml` is content; through a base link
`docs -> .github` it is a workflow.

Why no chains: following links would need one resolution per file system,
because case-sensitive Linux and case-insensitive macOS and Windows can
follow different links. Refusing every walk through a link makes the
lexical walk exact on all of them; in D8 the only link change was inward
and unchained. Base links the patch does not touch are not judged, except
as protectors of what they point to. The link tree is a flat trie keyed by
node and alias key, so a deep path costs no recursion and each step is one
lookup: 24 links with 4,095-byte targets past 25 base links 2,047
components deep, plus a file 50,000 directories deep, take under 1 s in a
debug build.

### D7. Disabled tests, JS/TS in v1

A JS/TS file has a folded last component ending in `.js`, `.jsx`, `.mjs`,
`.cjs`, `.ts`, `.tsx`, `.mts` or `.cts`. A test file is a JS/TS file with a
folded directory component `__tests__`, `test`, `tests`, `e2e`, `spec`,
`specs`, `playwright` or `cypress`, or whose stem (the name without its
last extension) ends in `.test`, `.spec`, `-spec`, `_spec`, `.e2e`, `.cy`,
`-test` or `_test`. The scanner first decodes `\uXXXX`, `\u{...}` (any
number of digits, at most U+10FFFF, no surrogates) and `\xHH` in one pass,
because JS allows escapes in identifiers.

- **Markers**, counted per marker on both sides of every JS/TS file
  (in-source tests exist); more after than before is
  `DisablesTests(Marker(m))`. A marker refuses as a net increase, so the
  bounds run in mirror image of the declarations': the after side counts
  every occurrence, comments and strings included (an upper bound), and
  the base only occurrences that both readings of the lexer below put in
  code, HTML-like comments read as comments (a lower bound). Deleting a
  marker the base holds in a comment or a string therefore cannot offset
  a new one (review round 1 of PR #70). Member names `skip`, `only`, `todo`,
  `fixme`, `skipIf`, `runIf`, `fails`, `failing`, and `fail` only when the
  receiver is `test` or `it` (`expect.fail` and `assert.fail` are
  assertions). A name counts when it stands as a whole identifier (ASCII
  letters, digits, `_`, `$` and non-ASCII characters that are not
  whitespace are identifier characters) and (a) the previous significant
  character is `.` or `/`, where whitespace includes U+FEFF and a line
  that ends in `.` (whole or cut at a `//`) counts as `.`, while blank and
  `//` lines are skipped, so `it?.skip`, `it . skip`, `it./* c */skip` and
  a line comment between the dot and the name count; or (b) the name is
  quoted between brackets (`it['skip']`); or (c), in test files only,
  `skip`, `only` or `todo` is an object key. The calls `xit`, `xtest`,
  `xdescribe`, `xcontext`, `xspecify`, `fit`, `fdescribe` and `fcontext`
  count when not preceded by `.` and followed by `(`, `.` or a backtick,
  after the separators the member rule accepts: whitespace, comments,
  optional chaining `?.` and a TypeScript non-null `!` (`fit?.(`,
  `fit/**/(`, `fit!(`).
- **`TestsRemoved`**: in a test file that stays a regular file, the after
  side has fewer active declarations (`it`, `test` or `specify`, not after
  `.`, followed by `(`, `.` or a backtick) than the base. A side that is
  not text cannot be counted, so a base or after side that is not text
  counts as a removal. Commenting a test out counts as removing it.

- **`DeletedTestFile`**: a test file whose after side is absent or not a
  regular file. Moving a test file (a delete plus an add) is refused.
- **`TestConfigChanged`**: any change to `jest.config.*`,
  `vitest.config.*`, `vitest.workspace.*`, `playwright.config.*`,
  `cypress.config.*`, `karma.conf.*` or `.mocharc*`, and to
  `vite.config.*` when either side has a `test` key (`test:`, a quoted
  `'test':` or `['test']:`, or the shorthand `{ test }`), where Vitest
  reads its options when there is no `vitest.config`.

**Counting under ambiguity: the base's declaration count is an upper
bound and the after side's a lower bound** (markers run in mirror image,
above). Whatever the scanner cannot decide must make the base count more
and the after side less, so an ambiguity can only refuse. A small lexer
reads the raw text, before any escape is decoded, by the JS rules for
strings, template literals (with `${...}` code), regular expressions and
comments: a `\` escapes the next code point inside a literal, CR LF
included as one line continuation, and U+2028 and U+2029 do not end a
string. Declarations and markers are found in the decoded text and mapped
back to raw offsets. The lexer knows one ambiguity: `/` after any token
that can end an expression (a word, keywords and numbers included, a
closed literal, `)`, `]`, `}`, a postfix `++` or `--`, a TypeScript
non-null `!`) divides (`a / b`, `x++ / 2`, `x! / 2`) or starts a regular
expression (`return /re/`, `if (x) /re/`, `!/re/`); after any other
token, or at the start, it starts one. The lexer runs once with each
reading, so no keyword list is needed. A first line that starts with
`#!` (a hashbang) is a comment on the after side and in the base's
marker count, and code in the base's declaration count, which keeps all
three bounds (review round 3 of PR #70 found the
postfix, non-null and hashbang forms reading a string as code). The base counts every declaration that not both
readings put in a comment, strings included, with the wider call forms
(`it!(`, `it?.(`); the after side counts a declaration only when both
readings put it in code, and reads the HTML-like comments of script code,
`<!--` and `-->`, as comments anywhere in code, which the base ignores.
Reviews of PR #70 found the skews this closes: a `/*` in a base string
(`'/api/*'`) hid every later base test; a test inside an after string
offset a deleted one, also through an escaped quote (`\u0027`, `\x27`,
`\u0060` decoded before lexing), a line continuation over CR LF, U+2028
inside a string, and a regular expression after a keyword missing from
the old list; and a `-->` line comment hid a test without lowering the
count. The first version masked every comment opener, a string's
included, on both sides; the lexer masks only what it reads as a
comment, so an edit next to a glob string such as `'**/*.ts'` passes.

**Layering.** This is a lexical first layer that refuses too much rather
than too little, like the token scan of ADR-001. The authoritative check is
dynamic and belongs to #17: a test that was green on the base and is
skipped, todo or missing after the fix must fail the "previously green"
check. Residuals: computed names (`it['sk' + 'ip']`), destructuring
(`const { skip } = test`), runtime configuration through environment
variables, JSX, which the lexer does not model and reads as code, so a
test written as JSX text in a `.jsx` or `.tsx` file still counts on the
after side (telling JSX from a TypeScript generic or a comparison needs a
parser; #17's dynamic check is the backstop), and every ecosystem other
than JS/TS (Python and the in-source tests of `.vue` and `.svelte` files
are #69). The cost of the bounds is over-refusal of an edit to a test file
whose base holds a declaration in a string or template (the base counts
it, the after side does not) or a marker in a comment or string (the
after side counts it, the base does not); the diffs of D8 hold only
changed lines, so neither was measurable there.

### D8. Measurement

Human bug fixes of the three candidate repositories in ARCHITECTURE
("First stack"), fetched on 2026-11-18: for each, the first 300 results of
the GitHub search `is:merged fix in:title` (`gh pr list --state merged
--search "fix in:title" --limit 300`, with additions, deletions, changed
files and the file list), keeping titles that match `^fix[(:!]`, the
conventional commit type `fix`: Cal.com 292, Twenty 182, Documenso 295,
**769 pull requests**. Patches came from the pulls API
(`application/vnd.github.v3.diff`); 2 of the 769 were refused for having
more than 300 files, and both are over the file limit anyway. Sizes count
lines without lockfiles (`pnpm-lock.yaml`, `yarn.lock`,
`package-lock.json`, `npm-shrinkwrap.json`, `bun.lock[b]`); file counts
are GitHub's, which counts a rename once, so they are a lower bound of
D3's.

- Changed lines: p50 32, p90 380, p95 658, **p97 973**, p99 2,483.
  Changed files: p50 2, p90 12, p95 20, **p97 25**, p99 49. Over 1,000
  lines or 25 files: **30 (3.9%)**; at 500 and 20: 70 (9.1%); at 1,500
  and 30: 22 (2.9%).
- Changed bytes (review round 1 of PR #70): the bytes of every added and
  removed line inside the hunks of the diff, newline included (one byte
  less where git marks "No newline at end of file"), lockfiles excluded as
  above; the 2 diffs the API refused count as over any budget. p50 1,322,
  p90 14,218, p95 27,754, **p97 41,616**, p99 106,443. Over 42,000 bytes:
  23 (3.0%), of which 3 are within 1,000 lines and 25 files.
- Pull requests each family would reject (the families overlap): CI paths
  19; compose files 4; the Dockerfile family 1; CODEOWNERS 1; test-runner
  configuration 8 (2 without `vite.config.*`); added binaries 2; disabled
  tests 14 (net-added markers 5, deleted test files 6, fewer declarations
  in a test file that stays 6); `.gitattributes`, `.gitmodules`,
  gitlinks, bidi controls and non-UTF-8 content 0; outward symlinks 0 (one
  pull request retargeted an inward link, which passes); links to the root
  or above a forbidden path 0 (that one link, `CLAUDE.md -> AGENTS.md`,
  points at a sibling file); dependency files 36. Links at forbidden paths
  that protect their targets could not be counted: the diffs do not hold
  the base trees, and the one link in them is not at a forbidden path.
- The issue's literal list rejects **52 (6.8%)**, D3 to D7 without
  `Dependencies` and the byte budget **71 (9.2%)**, with `Dependencies`
  **102 (13.3%)**, and with the byte budget as well **104 (13.5%)**.
- Marker forms: over the 769 patches, the member, call and bracket forms
  net-added markers only in test files, and each of those pull requests
  adds a real skip (`test.skip(...)`, `describe.skip` aliases, a
  conditional `test.skip(cond, ...)`). The object-key form hit 3 pull
  requests, all in application code (Prisma pagination `skip:`, an `only:`
  option), so it applies to test files only. Counting the bare words
  instead hit 58 pull requests in test files, mostly the English word
  "only" in test titles, so the rule uses forms, not words.

## Consequences

- The policy refuses about 13.5% of human fixes in the first stack's
  repositories, measured, not estimated. Most refused fixes are CI,
  infrastructure, dependency and refactoring changes, which the line is
  not meant to make. Limits are inputs (#32); the classes are fixed here,
  and per-repository additions are #21.
- The JS/TS layer can be bypassed by computed names and aliases. It does
  not claim completeness; #17's dynamic check is the backstop, and #17 is
  told so.
- Moving or deleting a test file, commenting a test out, and touching a
  test runner's configuration are refused even when harmless.
- The replay gate grows by one section: `boneli-replay-check` renders the
  verdict of every case of `boneli_domain::patch_corpus`, which together
  reach every violation and reason variant, in two processes and its own.
  No hand-written `fmt` impl is added, so the formatting tripwire stays as
  it is.
- ADR-010 is accepted and stays unchanged; its D2 sentence that leaves
  link targets to "the patch policy's question (#17)" is answered here
  (D6), under #18.
- Nothing calls the policy yet. #68 wires it into the run with a `Git`
  port operation, its contract clause and mutant (ADR-004), an evaluation
  point between `FixWritten` and `VerifyFix` and a `GateFailure` for it.
  ADR-023 closes this: the run checks every fix with the policy before it
  is verified.

## Alternatives considered

- **Parse git's patch format in the domain.** The diff format belongs to
  the adapter (ADR-004, D11; ARCHITECTURE, "Code architecture"), and a
  parser of agent-written patch text in the core is a second attack
  surface. Rejected for full before and after entries.
- **Take `git diff --numstat` counts from the adapter.** The domain would
  decide on numbers it cannot check, and `MemoryGit` would need its own
  diff. Rejected.
- **A multiset line count.** Cheap, but 0 for reordered lines and below
  the true edit distance, so it fails open. Rejected for Myers with a
  cut-off.
- **Bare words as markers.** 58 of 769 human fixes would be false
  positives (D8). Rejected for forms.
- **One JS lexer as the only reading.** Regular expression literals make
  a lexer desync, and a desync hides code as a string, which fails open.
  Rejected: markers use the identifier-and-context scan, which only
  over-counts, and declarations run the lexer with both readings of its
  ambiguity and take the bound that refuses (D7).
- **Masking every comment opener, a string's included, on both sides**
  (the first version). It undercounts the base, so a `/*` in a base string
  hid base tests. Rejected for the bounds of D7.
- **Following symlink chains for the after side's links.** Needs a
  resolution per file system (case sensitivity differs between
  checkouts), so it is exact on none. Rejected for refusing every walk
  through a link. Links at forbidden paths are followed through chains,
  every alias's target included, because there the policy needs every
  path a reader may reach, not one resolution (D6).
- **Unicode case folding and normalization tables for aliases.** Exact,
  but a core crate takes no dependencies and would carry the tables
  itself. Rejected for one shared key for non-ASCII components (D6),
  which only over-refuses.
- **A byte budget on file sizes instead of changed lines.** Simpler, but it
  refuses any edit to a large file. Rejected for the bytes of the changed
  lines, measured the same way as the line budget (D3, D8).
- **Refusing every symlink.** Simple, but inward links are legitimate and
  occur in human fixes (D8). Rejected.
- **Simple case mappings only for folding.** Misses the full foldings
  casefolding file systems apply (U+FB01 is `fi` there). Rejected for
  both.
- **NFKC folding for Python identifiers.** Python normalizes identifiers
  with NFKC (`pytest.mark.ｓｋｉｐ` is `skip`), and a core crate without
  dependencies has no NFKC tables. Decided with the ecosystem scope: #69.
- **Rust as the language** was the only candidate: the policy is domain
  code (ADR-001), pure, `no_std` and without dependencies.
