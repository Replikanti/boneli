# ADR-011: boneli-toml, a strict parser for a TOML 1.0 subset

- Status: accepted
- Date: 2026-11-17

## Context

`docs/ARCHITECTURE.md` ("Pure Rust and dependencies") puts "a parser for a
TOML subset for configuration" on the list of parts we write ourselves.
The `toml` crate pulls serde, which `deny.toml` bans. Issue #34 builds the
support crate `boneli-toml`, which `tools/architecture.toml` already lists
in `roles.support`. Its consumers are the Rust port of the architecture
checker (#35), which reads every Cargo manifest of the workspace and of
its fixtures, the playbook format (#11), which is specified as parsed by
our own TOML subset parser, and possibly the replica format (#13).

For #35 the input is hostile: the checker runs on pull requests from
outside contributors, whose manifests it reads to decide whether a
dependency edge is allowed. A parser bug there is a gate bug, so the
classes that matter are parser differentials (this crate reading a
different table than cargo does, so an edge slips past the gate),
resource exhaustion (memory, stack, CPU) and leaks of configuration
content, which can hold credentials for a replica, into logs. #35's
acceptance asks the Rust checker to report the same rule set as the
Python checker on every fixture, and the Python checker reads TOML with
`tomllib`.

Two facts shape the design:

- A stack overflow in Rust is not a panic; it aborts the process. A
  recursive parser and recursive operations on its values need a depth
  bound that is a property of the crate.
- TOML's hard part is not its lexical grammar but its table definition
  rules: which header or dotted key may create, define or extend which
  table. Every rule a parser gets wrong is a document it reads differently
  from cargo and tomllib.

The conformance corpus is toml-test (the TOML authors, MIT): its file list
for TOML 1.0.0 holds 208 valid documents with their expected values as
JSON and 509 invalid ones.

## Decision

### D1. The subset

TOML 1.0.0 without three scalar families, decided at STOP 1 of #34:
floats (`inf` and `nan` included), the four date and time types (offset
date-time, local date-time, local date, local time) and hexadecimal,
octal and binary integers. Everything else is in: bare, basic-quoted,
literal-quoted and dotted keys, all four string forms, decimal integers,
booleans, arrays (mixed types allowed), inline tables, `[table]` headers
and `[[array of tables]]` headers.

Why the structure cannot be cut: the architecture checker's fixture
manifests already use `[[bin]]`, literal-string keys in headers
(`[target.'cfg(windows)'.dependencies]`), quoted keys
(`"httparse:1.0.0"`), `\u` and `\n` escapes, negative integers
(`priority = -1`) and inline tables, so #35 could not reach parity
without them; the playbook and replica formats need multi-line text. Why
the three families are out: none of the workspace's 139 TOML files uses
them (138 parse, one fixture is deliberately invalid; measured with
`tomllib`), no consumer needs them, and each would add code that only a
hostile input exercises. Floats would also cost `Value` its `Eq` and the
exact round trip. A consumer that needs one of them brings it with a new
ADR.

A value of an excluded type is `ErrorKind::Unsupported(Feature)` at the
value's first byte, with the feature it would have been, never a silent
misread: the scalar token (the run of ASCII letters, digits, `_`, `+`,
`-`, `.` and `:`) is classified as a whole before any of it is read as an
integer, so `1.5` is `Unsupported(Float)` and never `1`. The
classification is by shape: `0x`, `0o`, `0b`; `inf` or `nan` with an
optional sign; four digits and `-` (a date, with a time after `T`, `t` or
a space, and an offset if the time holds `Z`, `z`, `+` or `-`); two
digits and `:` (a time); a digit followed anywhere by `.`, `e` or `E` (a
float). A malformed token of such a shape is `Unsupported` too, which
fails closed. TOML 1.1-only syntax (`\e`, `\x`, newlines or a trailing
comma in an inline table) is an ordinary syntax error, not
`Unsupported`, because it is not TOML 1.0.

### D2. Encoding

The input is checked once with `core::str::from_utf8` before parsing;
a failure is `InvalidUtf8` at `valid_up_to()`. That is the decoder every
Rust consumer already uses: it rejects overlong forms, encoded
surrogates, code points above U+10FFFF and truncated sequences, and
there is no second UTF-8 decoder to get wrong. A leading BOM is
`UnexpectedByte` at 0, as in tomllib (TOML 1.0 does not mention it, and
accepting it would add a whitespace class the Python checker does not
have). Whitespace is space and tab only; newlines are LF and CRLF, and a
CR without LF is an error everywhere. CRLF inside a multi-line string
reads as LF, as in tomllib, so a value never depends on the line endings
of a checkout. Control characters (U+0000 to U+001F except tab, and
U+007F) are `ControlCharacter` in strings and comments; a newline in a
single-line string is one of them. C1 controls (U+0080 to U+009F) are
ordinary characters, as TOML 1.0's grammar says. Escapes are the TOML
1.0 set, `\b \t \n \f \r \" \\ \uXXXX \UXXXXXXXX`, for Unicode scalar
values only, and a line-ending backslash only in multi-line basic
strings; anything else is `InvalidEscape` at the backslash.

### D3. Keys

Keys compare after unescaping and byte-wise, without Unicode
normalization: `a`, `"a"`, `'a'` and `"a"` are one key, and U+00E9
and `e` + U+0301 are two, as in tomllib and cargo. Normalizing would make
this crate merge keys that the Python checker and cargo keep apart, a
differential at the gate. Bare keys are ASCII only, so a look-alike
(`lınts`, a Cyrillic `е`, fullwidth letters) is `UnexpectedByte`, and a
quoted look-alike is a different key that no rule matches.

### D4. Table definition rules

Every table remembers how it came to exist, and the rules follow from
that; they agree with tomllib on all 717 corpus files (D9):

- `[k1. ... .kn]` walks from the root through tables of any origin and
  through the last element of arrays of tables, creating missing tables
  as *implicit*. A scalar, an inline table or a static array on the way
  is `NotExtensible`. The final table may be missing (it becomes
  *defined by a header*) or implicit (defined once); anything else there
  is `DuplicateTable`.
- `[[k1. ... .kn]]` walks the same way; the final key may be missing (a
  new array of tables with one element) or an array of tables (a new
  element); anything else is `DuplicateTable`.
- `k1. ... .kn = v` in the current table walks through tables that
  dotted keys created and through implicit ones, which become dotted, so
  a later header for them is `DuplicateTable`. A table a header defined,
  an array of tables, or a scalar, inline table or static array on the
  way is `NotExtensible`; an existing final key is `DuplicateKey`.
- An inline table or array is closed when its `}` or `]` is read, and
  nothing extends it after that.
- A table keeps its members in the order they were first created, so
  `[a.b]` then `[a]` with `x = 1` gives `a` = {`b`, `x`}.

Errors point at the key segment or bracket that would create or redefine
the offending table or key. Where toml-test and tomllib are silent, the
tie-break is tomllib, because #35 compares the Rust checker with the
Python one.

### D5. Limits have no defaults

`Limits::new(max_bytes, max_depth)` rejects a zero and a `max_depth`
above `MAX_DEPTH` (`InvalidLimit`); both limits are inclusive. Each
consumer states its own numbers in its own PR, because the inputs
differ: a workspace manifest is a few KiB (the largest TOML file in the
repository is 9,529 bytes), a playbook is operator content, and a file an
agent writes is hostile. Decided at STOP 1 of #34: two limits, and no
value-count limit (unlike ADR-008), because every known input is
KiB-scale and memory can be bounded through `max_bytes` with the factor
measured below.

- `max_bytes` bounds the input and is checked first, before the UTF-8
  check and any allocation (`TooLarge` at offset `max_bytes`).
- `max_depth` bounds nesting: the root table is depth 1 and every table
  or array below it adds 1, whichever route creates it (a header, a
  dotted key, an inline value; `[[a]]` is 3, the array and its element).
  It is checked before a container is created, so the bytes after the
  offending bracket or key segment are never read.

A decoded string never outgrows its encoding (escapes shrink, CRLF reads
as LF, a line-ending backslash drops bytes), and the parser makes that
hold for the allocation too: a string without anything to decode is
copied once at its exact length, and at the first escape or CRLF the
buffer reserves exactly the encoded length up to the closing delimiter
(`string_capacity_within_encoding`). Keys without escapes borrow the
input until the tree is finished. Arrays are shrunk to their length when
they close and tables are built at their exact length, so a parsed value
holds no spare slots (`parsed_containers_have_exact_capacity`).
`size_of::<Value>()` is 32 bytes and a table member 56
(`value_sizes_pinned`).

Peak RSS of the process around `parse` on 16 MiB inputs (release, glibc,
x86_64, rustc 1.98.0, the input held by the caller, about 18 MiB before
the parse; R is peak / input). Keys are the shortest distinct bare keys,
which is the cheapest input per table or member:

| Input | Units | Peak RSS | Per unit | R |
|---|---|---|---|---|
| `K.k.k…k=0` lines, 127 tables each | 8,260,588 tables | 1,029 MiB | 128 B | **64.3** |
| `[K.k.k…k]` lines, 127 tables each | 8,260,588 tables | 1,033 MiB | 129 B | **64.5** |
| `[K]` + 17 `x=0` lines per table | 4,081,932 members and tables | 747 MiB | 187 B | 46.7 |
| `[K]` + 9 `x=0` lines per table | 3,964,550 | 601 MiB | 154 B | 37.5 |
| `[K]` lines | 2,435,391 tables | 567 MiB | 236 B | 35.4 |
| `a=[{a={a=…{}}},…]`, chains 126 deep | 4,202,478 tables | 549 MiB | 133 B | 34.3 |
| `a=[[[…]]],…`, chains 125 deep | 8,355,125 arrays | 400 MiB | 48 B | 25.0 |
| `K=0` lines, one table | 2,435,391 keys | 352 MiB | 144 B | 22.0 |
| `a=[{a=0},…]` | 2,796,201 tables | 360 MiB | 128 B | 22.5 |
| `a=[{a=0,…},…]`, 2, 5 or 9 members | | | 75 to 83 B | 23.0 to 23.5 |
| `a.K=0` lines | 1,894,193 keys | 278 MiB | 144 B | 17.4 |
| `a=[0,0,…]` | 8,388,606 values | 274 MiB | 32 B | 17.1 |
| `[[a]]` lines | 2,796,202 elements | 253 MiB | 88 B | 15.8 |
| `a=[[],[],…]`, `a=[{},…]`, `a=['',…]` | 5,592,404 values | 189 MiB | 32 B | 11.8 |
| `a="\n…"`, one string | 1 | 34 MiB | | 2.1 |
| `a='''a\r\n…'''`, one string | 1 | 29 MiB | | 1.8 |

Per unit is (peak − RSS before the parse) / units. The worst inputs are
chains of tables, because a table costs at least one member in its
parent and the input spends only 2 bytes (`.k`) per table. Where the 129
bytes per chain table come from: while the document is read, a table is
a box of 64 bytes (a glibc chunk for the 56-byte builder) and a member
slot in its parent of another 64 (56 bytes for the key and the node,
allocated for exactly one member, because a chain table holds one); the
finished tree then reuses those freed chunks for its own 64-byte member
buffers. The finished tree alone costs 96 bytes per chain table (the
member buffer and the key's 32-byte chunk), so no change to the builder
gets chains below an R of about 48 without changing `Value`.

The first version of this crate kept a B-tree index for every table and
copied every key: chains cost 622 B per table, R 307.3, and one-table
keys 204 B. Two changes brought R to 64.5: keys borrow the input until
the tree is finished, and a table gets its index only after `SMALL` = 8
members, scanning its keys until then. Why 8: a scan of at most 8 keys
costs at most 8 comparisons, each no longer than the key being looked up,
so the cost stays linear in the input (D11); and 1,422 of the 1,426
tables in the workspace's TOML files have at most 8 members (measured
with `tomllib`; the largest has 19), so real tables never pay for a
B-tree leaf of about 370 bytes (11 slots of a 24-byte key and an 8-byte
slot number). The builder sizes are pinned by `builder_sizes_pinned`.

So the peak memory of one parse is at most about 65 × `max_bytes`, plus
the caller's own state. Consumers size `max_bytes` with that factor: a
checker that accepts 1 MiB per manifest accepts at most about 65 MiB of
peak memory per parse.

### D6. `MAX_DEPTH = 128`

The parser recurses through arrays and inline tables; moving the parsed
tree into `Table`, `Clone` and `PartialEq` (derived), `Debug` (written by
hand, D8) and `Drop` (default) recurse too. Header and dotted-key paths
are walked iteratively.

Where 128 comes from: the deepest known document is 9 levels deep
(`valid/inline-table/key-dotted-02` of toml-test; the workspace's deepest
is 5, `[external.<crate>.pulled-by.<parent>]` in `tools/architecture.toml`).
Ten times that is 90, and 128 is the next power of two. The headroom
matters for configuration nobody has written yet (#11, #13); a consumer
that needs less states its own `max_depth`. At 512, as in ADR-008, the
stack need would grow about four times (it is linear in the depth, below),
to about 600 KB in the test profile, for nesting 57 times deeper than any
known document. The cost of 128: it rejects nesting that full TOML
accepts.

Stack each operation needs, measured as the smallest thread stack size on
which it completes (bisected to 1 KiB in a child process, since an
overflow aborts; rustc 1.98.0, x86_64, glibc; the input's root holds 127
nested containers, depth 128; the smallest thread std starts needs about
5 KiB):

| Operation | Worst route | Test profile, thread size | Test profile, per level | Release, thread size |
|---|---|---|---|---|
| parse | header and dotted chains | 157,658 B | 1,167 B | 69,616 B |
| parse | inline tables | 146,397 B | 1,071 B | 42,998 B |
| parse | inline arrays | 106,471 B | 767 B | 42,998 B |
| clone | tables | 144,349 B | 1,071 B | 30,713 B |
| `==` | tables | 72,687 B | 511 B | about 5 KiB |
| `{:?}` and `{:#?}` | tables | 75,758 B | 527 B | about 5 KiB |
| drop | tables | 39,927 B | | about 5 KiB |

Per level is the difference between depth 128 and depth 64, divided by
64; drop at depth 64 fits the smallest thread, so it has no per-level
figure. Parse of a header or dotted chain recurses only when the tree is
moved into `Table`. The first version of that move went through iterator
adaptors and a key-ordering pass per level, 2,751 B per level and
360,361 bytes at 128; plain loops brought it to 1,167 B. Reading the key
of an inline-table member out of line brought inline tables from 1,775 B
to 1,071 B per level.

The gate thread is the smallest power-of-two size on which the worst
operation at depth 128 uses at most 75%: 256 KiB, where parse of a
header chain uses 157,658 bytes, 60.1% (128 KiB is below the need). Why
75%: it leaves a quarter of the thread for frames that grow with a
compiler upgrade or a later change; at 60.1% today, frames may grow by
24% (to 196,608 bytes) before the gate fails, and it fails in CI, not in
production. `tests/stack.rs` (its own test binary) parses every
route at depth 128 on a 256 KiB thread in the test profile, clones,
compares, formats and drops the values, and requires `TooDeep` one level
deeper. 256 KiB is also what a consumer's thread needs at `MAX_DEPTH`;
std gives a spawned thread 2 MiB by default. If frames grow past the
gate, the remedy order is the one of ADR-008: slim the frames, then lower
`MAX_DEPTH` in a new ADR.

A value built by hand deeper than `MAX_DEPTH` prints `..` inside
`MAX_DEPTH` containers in `Debug` (`debug_stops_at_max_depth`); its
`Clone`, `PartialEq` and `Drop` are not bounded, and parsed values are
never that deep.

### D7. Integers are `i64`

A decimal integer outside `i64` is `IntegerOutOfRange`. tomllib accepts
arbitrary precision, so this is the one place where a valid document
fails here and parses there; it is the safe direction (an error, never a
different value), and TOML 1.0 requires only the 64-bit range. The value
is accumulated negatively, so `-9223372036854775808` fits. Leading zeros,
misplaced underscores and anything that is not a digit are
`InvalidInteger`.

### D8. Errors and `Debug`

`Error` has a kind, a byte offset, a 1-based line (lines end at LF) and
a 1-based byte column, and implements `std::error::Error`. `Display` and
`Debug` show the kind (with the feature's name for `Unsupported`) and the
position only, never input bytes, for the reason of ADR-008, D9:
configuration can hold credentials, and errors get logged.
`errors_never_show_input` feeds inputs with a marker in keys, strings,
comments and scalar tokens and checks that no form of any error shows
it.

`Debug` of `Value` and `Table` does show content. It is written by hand,
compact and the same with and without `#`
(`{"a": Array [Integer(1), String("x")]}`), because the derived `{:#?}`
is cubic in the depth (ADR-008, D9). `pretty_debug_matches_compact_and_is_fast`
requires `{:#?}` to equal `{:?}` for every depth-128 route and to finish
in under 2 s.

### D9. toml-test is vendored

Not fetched or generated: the files of upstream's `tests/files-toml-1.0.0`
at commit `96fd0884` (2026-10-27, the latest; tag v2.2.0 of 2026-04-30
lacks 35 invalid and 3 valid files) and the list itself, 925 files and
103,336 bytes, bytes unchanged and modes 0644, with the MIT `LICENSE`
next to them. MIT is compatible with Apache-2.0, and its one condition,
keeping the notice, is met there. Fetching in CI would add network, a
moving target and a skip path when the network is down (ADR-008, D10).
`.gitattributes` marks the directory `-text`, because seven files depend
on exact CR and CRLF bytes, and `corpus_is_pinned` pins the file set,
counts, byte total and a digest.

Outcomes, pinned per file in `tests/toml_test_outcomes.txt`: 168 of the
208 valid files parse to exactly their expected value (tagged JSON,
objects compared without order, integers as numbers), the other 40 are
`Unsupported` (19 float, 11 offset date-time, 3 local date, 2 local
date-time, 2 local time, 2 hexadecimal, 1 binary). None of the 509
invalid files is accepted: 392 are syntax or rule errors and 117 are
`Unsupported` because they are malformed floats, dates or radix integers
(three of them `control/linetab-number-*`, a vertical tab after such a
value). None is rejected for its size or depth.

`examples/toml_test_decoder.rs` speaks the toml-test decoder protocol
(TOML on stdin, tagged JSON on stdout, exit 1 on error), so the upstream
harness and a differential can run the crate. A differential against
tomllib (Python 3.14) over the corpus and the workspace's TOML files, 856
files, found no file this crate accepts and tomllib rejects, no value
difference, and no file this crate rejects with a syntax or rule error
that tomllib accepts; the 40 files tomllib accepts here fail with
`Unsupported`. The same differential over 50,000 random mutants of those
files (the operators of D10) found no difference either: 6,330 parse in
both with equal values, 38,255 fail in both, 4,763 are `Unsupported` here
and fail in tomllib, 600 are `Unsupported` here and parse there.

### D10. A deterministic mutation sweep instead of a fuzzer

As for ADR-003 and ADR-008. Seeds: the 717 corpus `.toml` files (45,191
bytes) and the workspace's manifests, `deny.toml` and
`tools/architecture.toml` (15 files today). At most 128 offsets per seed,
with a fixed stride for longer seeds; at every offset 27 mutants:
truncation, deletion, replacement and insertion of each of the 12 bytes
`" ' [ ] { } = . , # \n \`, and one bit flip (bit = offset mod 8). That is
32,363 offsets (30,574 in the corpus) and 873,801 mutants, each parsed
under the harness limits and under tight ones (64 bytes, depth 3),
1,747,602 parses in 19.4 s of CPU time in the test profile on the dev
host (22 and 32 s wall clock when the shared CPU quota of its build slice
was quiet, 89 s while another job held most of it). The budget, set
when the work was planned, is 60 s, so that the sweep stays a minor part
of the workspace's `cargo test` (157 s on the same host), and the lever
is the offset cap, never the operators: at 256 offsets per
seed (40,638 offsets, 1,097,226 mutants) the sweep took 31 to 42 s when
the slice was quiet and 63 s when it was not, so the cap went to 128.
The cap cuts the workspace seeds, about 1.6 KB each against 63 bytes for
a corpus file, which at 256 offsets made up about two thirds of the bytes
parsed (3,343 offsets of about 1.6 KB against 37,295 of about 63 bytes).
A first version that also wrote
back every value the tight limits accepted took 46 and 67 s at 256.
No mutant panics, every error offset lies inside the
input, a value the tight limits accept equals the harness value, and
every accepted mutant is written back by the test writer and parses to
an equal value.

The test writer (`tests/common`, test-only; the crate has no public
serializer) writes a table in 15 styles: inline values, dotted keys and
headers with `[[ ]]`, each with every string form (basic with raw or
escaped non-ASCII, literal, multi-line basic with quote runs, multi-line
literal), bare or quoted keys, three integer spellings, multi-line arrays
with comments, and CRLF. 10,000 generated tables round-trip through all
15 styles (8 s in the test profile), with keys that need quoting (empty, dots, spaces, `#`, `=`,
quotes, backslashes, controls, non-ASCII, zero-width and look-alike
characters), strings with every C0 control, DEL, quote runs and CRLF,
`i64::MIN` and `i64::MAX`, and four depth-128 chains (tables, arrays,
alternating, alternating with siblings).

### D11. Lookups are not quadratic

A table being built finds a key by scanning while it has at most 8
members (D5) and through a B-tree index after that, so a lookup costs
O(log m) comparisons for a table of m members, each at most as long as
the key looked up. The current table after a header is a path of member
slots, so a key-value pair costs no lookup per level above it. A
quadratic check would need about 2^35, 3.4 × 10^10, comparisons for
2^18 keys in one table. `many_keys_not_quadratic` parses 2^18 keys in one
table, as dotted keys and in one inline table, and
`many_tables_not_quadratic` parses 2^16 `[[a]]` headers, 2^16 sibling
`[tN]` headers and 2^16 pairs `[s.tN]`, `[s.tN.u]`, each under 30 s in
the test profile, which a quadratic check cannot meet even at 1 ns per
comparison; both tests together took 7.4 s.

## Consequences

- Floats, dates, times and radix integers fail with `Unsupported`.
  A playbook with a sampling temperature needs a new ADR, or an integer
  in thousandths.
- Integers beyond `i64` are rejected where tomllib accepts them (D7).
- Every consumer chooses and justifies `max_bytes` and `max_depth`, using
  R = 65 (D5) and the 256 KiB thread (D6). Without a value-count limit,
  memory is bounded only through `max_bytes`; a consumer that accepts
  MiB-scale hostile TOML (an agent-written file, say) should revisit that
  with a new ADR rather than accept 65 times its input.
- `Table` equality is order-sensitive, and `Table::get` scans; a consumer
  that looks up many keys in a large table collects them into its own
  map.
- `{:#?}` prints the same single line as `{:?}` (D8).
- Building a table with repeated `insert` costs O(m²) key comparisons;
  `collect` costs O(m log m). The parser uses neither.

## Alternatives considered

- **Full TOML 1.0.** Rejected in D1: three scalar families no consumer
  needs, each new code that only hostile input exercises.
- **The subset `tools/architecture.toml`'s header comment describes**
  (headers, bare keys, basic strings, string arrays). It reads the policy
  file but fails `[[bin]]`, `'cfg(...)'` keys and `priority = -1` in the
  fixtures, so #35 could not reach parity.
- **A value-count limit**, as in ADR-008. Rejected at STOP 1 of #34: the
  known inputs are KiB-scale, and with R measured, `max_bytes` bounds
  memory on its own (D5).
- **`MAX_DEPTH` 512**, as for JSON. Rejected in D6.
- **Fetching toml-test in CI.** Rejected in D9.
- **Accepting a BOM, normalizing keys.** Rejected in D2 and D3: both
  disagree with tomllib.
- **A B-tree index for every table, owned keys while parsing.** The first
  version; rejected in D5 for R = 307.
- **A hash index.** A keyed hash would make lookups O(1) on average, but
  `HashMap` with a random key makes runs non-deterministic, and an
  unkeyed hash lets an attacker build colliding keys; the B-tree is
  deterministic and its worst case is the bound.
- **The `toml` crate or `toml_edit`.** `toml` needs serde, which
  `deny.toml` bans. `toml_edit` makes serde optional, but its default
  parser and writer bring further crates (`toml_parser`, `winnow`,
  `toml_writer`, `toml_datetime`), each a new crate name that needs an ADR
  under ADR-001 and a reviewed edge, for a parser that is about 1,500
  lines here with its comments and unit tests.
