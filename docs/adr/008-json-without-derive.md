# ADR-008: boneli-json, a strict JSON parser and serializer without derive

- Status: accepted
- Date: 2026-11-15

## Context

`docs/ARCHITECTURE.md` ("Pure Rust and dependencies") puts "a JSON parser
and serializer without derive" on the list of parts we write ourselves,
and `deny.toml` bans serde. Issue #29 builds it as the support crate
`boneli-json`, which `tools/architecture.toml` already lists in
`roles.support`. Its consumers are the OCI image store (#7, manifests and
image configs from a registry), the agent adapter (#12, Claude Code's
stream-json output, one value per line), the forge adapter (#19, the
GitHub API) and the gateway (#20, Messages API requests that the sandbox
sends and responses it relays).

For the gateway the input is hostile: every byte comes from the sandbox,
where an agent runs code we do not trust. A parser bug there is a gateway
bug, so the classes that matter are resource exhaustion (memory, stack,
CPU), parser differentials (the gateway and the upstream reading
different members from the same bytes) and leaks of request content into
logs. The crate exists to give #7, #12, #19 and #20 one set of limits they
can rely on.

Two facts shape the design:

- A stack overflow in Rust is not a panic. It aborts the process, which
  for the gateway ends every run it serves. A recursive parser therefore
  needs a depth bound that is a property of the crate, not of each
  consumer's care.
- RFC 8259 leaves several behaviours open (duplicate keys, lone
  surrogates, number range, a BOM). Each open choice is a place where two
  parsers can disagree.

The conformance corpus is JSONTestSuite (Nicolas Seriot, MIT): 95 `y_`
files every parser must accept, 188 `n_` files every parser must reject,
and 35 `i_` files where the choice is the implementation's.

## Decision

### D1. Grammar

RFC 8259 exactly. Any value may stand at the top level.
Whitespace is SP, HT, LF and CR only, and only whitespace may follow
the value (`TrailingData` otherwise). No comments, trailing commas,
single quotes, `NaN`, `Infinity`, leading `+` or leading zeros, and no
unescaped U+0000 to U+001F in strings. The parser never repairs input.

### D2. Encoding

The input is checked once with `core::str::from_utf8`
before parsing, and a failure is `InvalidUtf8` at `valid_up_to()`. That
is the decoder every Rust consumer already uses; it rejects overlong
forms, encoded surrogates (`ED A0 80`), code points above U+10FFFF and
truncated sequences, and there is no second UTF-8 decoder to get wrong.
A `\uD800` to `\uDBFF` escape must be followed directly by a `\uDC00`
to `\uDFFF` escape; any other use of a surrogate escape is
`LoneSurrogate` at its backslash. Rejected: replacing lone surrogates
with U+FFFD. A Rust `String` cannot hold a lone surrogate, replacing
would map different inputs to one value, and it would disagree with
parsers that keep UTF-16 code units (JavaScript), a differential at the
gateway. Noncharacters (U+FFFE, U+FFFF, U+FDD0, U+10FFFF) are accepted:
they are `y_` files, and every UTF-8 decoder reads them the same way. A
leading BOM is rejected (`UnexpectedByte` at 0). RFC 8259 §8.1 lets a
parser ignore it, but no consumer's peer sends one, and ignoring it adds
a whitespace class some peers do not have.

### D3. Numbers keep their lexeme

`Number` holds the validated source
text. `as_i64` and `as_u64` return `Some` only for integer lexemes in
range (`-0` gives `as_i64() == Some(0)` and `as_u64() == None`);
`as_f64` only for a finite result (`1e400` gives `None`, `1e-400` gives
`Some(0.0)`). `From<i64>`, `From<u64>`, `Number::from_lexeme` (checked
against the grammar) and `Number::from_f64` (`None` for NaN and the
infinities; the `{:?}` form, checked against the grammar and for a
bitwise round trip) build numbers. Why: pass-through without loss. The
gateway and the transcript store re-serialize what they parse, and
integers above 2^53 (sizes, ids) must survive: as an `f64`,
9007199254740993 reads back as 9007199254740992. The round trip is
exact by construction, and no one pays for float parsing of numbers
nobody reads. Equality compares lexemes, so `1`, `1.0` and `1e0` differ,
and so do `-0` and `0`. A lexeme is bounded only by `max_bytes`: the
integer accessors stop at the first overflow (within 20 digits, since
leading zeros are not in the grammar), and std's float parser is linear
in the length (a 100,000-digit lexeme is a test case).

### D4. Duplicate keys are rejected

Decided at STOP 1 of #29.
`DuplicateKey` is reported at the offset of the earliest key that
repeats an earlier key of the same object. Keys are compared after
unescaping (`"a"` and its `\u` escape are duplicates) and byte-wise,
without Unicode normalization (U+00E9 and `e` + U+0301 are different
keys, as for every other parser). Why: a broker that parses a body and
lets another parser read it (the gateway forwards Messages API requests
upstream) must not see a different member than the upstream does.
RFC 8259 §4 leaves duplicates open (last wins, first wins or an
error), so every choice except rejection disagrees with some peer.

The check runs when an object closes: the member indices are sorted by
(key, position) with `sort_unstable_by`, whose worst case is
O(m log m) comparisons, and adjacent equal keys are duplicates. A
comparison costs at most the length of the shorter key, and each member
takes part in O(log m) comparisons, so the whole check costs
O(K log m) byte comparisons, where K is the total key length of the
object, itself at most `max_bytes`. Its memory is two `usize` per
member (the key offset and the sort index), freed or reused when the
object closes. A quadratic check would need m²/2 comparisons: for
2^18 keys that is about 3.4 × 10^10, against about 4.7 × 10^6 here. The
test `duplicate_check_not_quadratic` parses an object with 2^18
distinct keys in 1 to 3 s in the test profile (measured on a loaded
laptop) and fails above 30 s, which a quadratic check cannot meet even
at 1 ns per comparison.

`Object` keeps the same invariant for built values: `insert` on an
existing key replaces the value in place and returns the old one, and
`FromIterator` keeps the first position and the last value of a
repeated key, in O(m log m). There is no way to add a duplicate, so
everything the serializer writes parses back. Two `y_` files,
`y_object_duplicated_key` and `y_object_duplicated_key_and_value`, are
therefore rejected; the conformance test names both and requires
`DuplicateKey`, so the list cannot grow silently.

### D5. Limits have no defaults

`Limits::new(max_bytes, max_depth, max_values)` rejects a zero and a `max_depth` above `MAX_DEPTH`
(`InvalidLimit`). Each consumer states and justifies its own numbers in
its own PR, because the peers differ by orders of magnitude: an image
config is a few KiB, a Messages API request with images is several MiB,
and a stream-json line carries whole tool results. A default fitted to
one would be silently wrong for another. All three limits are
inclusive.

- `max_bytes` bounds the whole input of `parse`, or one NDJSON line
  without its `\n`. It is checked first, before the UTF-8 check or any
  allocation (`TooLarge` at offset `max_bytes`). A decoded string is
  never longer than its encoding (a `\u` escape is 6 bytes and decodes
  to at most 3, a surrogate pair is 12 and decodes to 4, `\n` is 2 and
  decodes to 1, raw UTF-8 is copied 1:1), so `max_bytes` also bounds
  strings, keys and lexemes, and there is no separate string limit.
  The parser makes this hold for the allocation too, not only for the
  length: a string without escapes is copied once at its exact length,
  and at its first escape the buffer reserves exactly the encoded
  length up to the closing quote, so it never grows. Appending to an
  empty `String` instead would double the buffer at the first push
  after a long run: `"` + 1 MiB of `a` + `\/b"` held 2,097,152 bytes of
  capacity for 1,048,578 decoded bytes. `string_capacity_within_encoding`
  pins capacity ≤ encoded length for that input, for all-escape strings
  and for keys.
- `max_depth` bounds nesting: a scalar has depth 0, `[]` depth 1,
  `[[]]` depth 2. It is checked before the parser descends, so the
  bytes after the offending bracket are never read.
- `max_values` counts every value once (scalars, containers, elements;
  keys do not count), so `[1,2]` is 3 and `{"a":1}` is 2. Why a third
  limit when the issue names only depth and size: memory amplification.
  Every array and object is shrunk to its length when it closes
  (`shrink_to_fit`, which glibc's `realloc` does in place), so a parsed
  value holds no spare slots. Peak RSS of the process around `parse` on
  16 MiB inputs (release, glibc, x86_64, the input held by the caller):

  | Input | Values | Peak RSS | Per value | Peak / input |
  |---|---|---|---|---|
  | `[0,0,…]` | 8,388,608 | 530 MiB | 64 B | 33.1 |
  | `[[],[],…]` | 5,592,406 | 188 MiB | 32 B | 11.8 |
  | `["","",…]` | 5,592,406 | 188 MiB | 32 B | 11.8 |
  | `[{},{},…]` | 5,592,406 | 188 MiB | 32 B | 11.8 |
  | `{"0":0,"1":0,…}` (hex keys) | 1,626,882 | 228 MiB | **136 B** | 14.3 |
  | `[{"a":0},…]` | 4,194,303 | 338 MiB | 80 B | 21.1 |
  | `[{"":0},…]` | 4,793,491 | 310 MiB | 64 B | 19.4 |
  | `[[0],[0],…]` | 8,388,607 | 466 MiB | 56 B | 29.1 |
  | `[{"a":0,"b":0,"c":0},…]` | 3,355,441 | 338 MiB | 100 B | 21.1 |
  | `[[0,0,0],…]` | 8,388,605 | 498 MiB | 60 B | 31.1 |
  | `[{"a":{"a":…0}},…]`, chains 256 deep | 2,803,457 | 274 MiB | 96 B | 17.2 |
  | `[{"":{"":…{}}},…]`, chains 500 deep | 3,358,001 | 223 MiB | 64 B | 13.9 |
  | `[[[…[0]…]],…]`, chains 256 deep | 8,388,353 | 402 MiB | 48 B | 25.2 |
  | `[{k distinct keys},…]`, k = 2 to 65,537 | | | 101 to 121 B | 14.6 to 22.9 |
  | `[[k zeros],…]`, k = 2 to 65,537 | | | 59 to 65 B | 30.5 to 33.7 |
  | `"aaa…a\/b"`, one string | 1 | 34 MiB | | 2.1 |

  Per value is (peak − RSS before the parse) / values; k is 2^j + 1,
  the count just past a `Vec` growth step. Before containers were
  shrunk (the first version of this ADR), a one-element container kept
  std's minimum capacity of 4: `[{"a":0},…]` cost 168 B per value,
  `{"a":{"a":…}}` chains 271 B, `[[0],[0],…]` 104 B and 53 times the
  input, and `[[[…[0]…]],…]` chains 144 B and 73 times the input.

  Where the worst case comes from: a value is 32 bytes in its array
  (`size_of::<Value>()`, pinned by a test) and an object member 56 (the
  key's `String` header and the value). On top of that come the
  allocations: a lexeme, a string or a key takes a glibc chunk of at
  least 32 bytes (up to 24 bytes of content; longer content counts
  against `max_bytes`), a container's chunk adds at most 24 bytes of
  header and rounding, and while an object is open the duplicate check
  holds 16 bytes per member (the key offset and the sort order, D4). The
  most a value can cost is therefore a member with a short key and a
  number or string value in a large object: 56 + 32 + 32 + 16 = 136 B,
  measured 135.9 B. A growing `Vec`'s unused capacity did not show in
  any row: the large ones are mapped by `mmap` and grow with `mremap`,
  and pages that are never written are not resident (measured at
  2^20 + 1 members and 2^22 + 1 elements: 135.8 and 64.0 B).

  Rejected: collecting every container's elements on one shared
  scratch stack and copying them out at the exact length when the
  container closes. It gives exact containers too, but the scratch
  stack's own growth and the copy are resident together, so large
  containers got worse: 192 B per value for the hex-key object and 96 B
  for `[0,0,…]`. The parse times of the two variants and of the first
  version did not differ beyond the run-to-run noise of the loaded
  machine (up to 2 times between runs).

  So a gateway that must accept a 32 MiB request, mostly one base64
  string, would accept about 1 GiB of peak memory from a hostile
  `[0,0,…]` body of the same size if only `max_bytes` bounded it. With
  `max_values` the peak is at most about 2 × `max_bytes` (the input,
  plus the decoded strings, keys and lexemes, whose capacity never
  exceeds their encoding) plus 136 B × `max_values` (the worst
  per-value cost, above). Consumers size `max_values` with that number.

### D6. `MAX_DEPTH = 512`

The parser and the serializer recurse; `Clone` and
`PartialEq` are derived, `Debug` is written by hand (D9) and `Drop` is
the default, and they recurse too. std gives a spawned thread 2 MiB of stack by default, and
`boneli-http` serves each connection on such a thread. Half of it,
1,048,576 bytes, is the budget for JSON; the other half belongs to the
frames below (server, handler) and above (an adapter's own recursive
walk over a `Value`, such as secret redaction in #20).

Stack high-water marks of the real crate, measured by painting a
thread stack before each operation and scanning it after (rustc
1.98.0, x86_64, glibc), for values nested 512 deep; the per-level cost
is the difference between depth 512 and depth 256, divided by 256:

| Operation | Test profile, per level | Test profile, at 512 | Release, per level | Release, at 512 |
|---|---|---|---|---|
| parse, arrays | 832 B | 427,543 B | 176 B | 90,655 B |
| parse, objects | 1,488 B | 764,247 B | 240 B | 123,647 B |
| drop, objects | 256 B | 131,415 B | 64 B | 32,943 B |
| clone, objects | 1,072 B | 549,295 B | 192 B | 98,535 B |
| `==`, objects | 512 B | 262,415 B | 48 B | 24,623 B |
| serialize, either | 832 B | 427,999 B | 112 B | 57,799 B |
| `{:?}` and `{:#?}`, objects | 496 B | 254,831 B | 64 B | 33,079 B |

Arrays cost less than objects in every operation but serialize, where
both are equal. The worst case is parse of objects in the test profile:
764,247 bytes, 73% of the budget, so 27% is left for frame growth
across compiler versions. The derived `Debug` of the first version of
this ADR cost 1,184 B per level for `{:?}` and 1,632 B for `{:#?}` and
was the worst case then (837,599 bytes at 512). The check: in the same build with only
the ceiling raised, a test-profile parse on a 1 MiB thread passes at
depth 1,250 and overflows at 1,253 for arrays, and passes at 697 and
overflows at 701 for objects, which matches the painted marks (1,048,576
bytes / 1,488 bytes per level is 704, less the thread's own overhead).

Where 512 comes from: the worst operation fits the budget up to
(1,048,576 − 2,391) / 1,488 = 703 levels (2,391 bytes is its fixed
part). 512 is the largest power of two below that, and it is kept
rather than about 690 because 690 would leave 2% headroom, which one
compiler upgrade can eat; `tests/stack.rs` would then fail in CI, not in
production, but the ceiling is part of the API. At 1,024 the worst
operation would need 1.53 MB, 73% of a connection thread's whole stack,
for one call. At 128, `i_structure_500_nested_arrays` would be rejected
and the headroom over realistic documents would drop to about 5 times:
OCI manifests nest about 5 deep, GitHub responses about 8, Messages API
requests with tool schemas about 24 (estimates, not measurements; each
consumer measures its deepest real document in its PR).

The gate is `tests/stack.rs` (its own test binary, because an overflow
aborts the binary): on a 1 MiB thread in the test profile it parses
arrays and objects nested 512 deep, serializes, clones, compares,
formats with `{:?}` and `{:#?}`, and drops them, and depth 513 must be
`TooDeep` for both parse and serialize. If frames grow past the budget,
the remedy order is: slim the frames (`#[inline(never)]` paths, a
smaller error type), then lower `MAX_DEPTH` in a new ADR, and below 128
switch to an iterative design.

A value built by hand deeper than `MAX_DEPTH` is refused by the
serializer (`TooDeep`, checked before it descends), and `Debug` prints
`..` for the contents of a non-empty container inside `MAX_DEPTH`
others, so it recurses no deeper than on a parsed value
(`debug_stops_at_max_depth`). Its `Clone`, `PartialEq` and `Drop` are
not bounded; building such a value is the consumer's choice, and parsed
values never are that deep.

### D7. Serializer

Compact and deterministic: the same value gives the
same bytes, members in stored order, numbers as their lexemes. The
transcript store addresses transcripts by content (#20), so this
matters. It escapes exactly `"`, `\` and U+0000 to U+001F, with
`\b \f \n \r \t` where they exist and lowercase `\u00xx` otherwise, and
writes everything else as raw UTF-8, `/`, DEL and U+2028/U+2029
included. There is no pretty printer.

### D8. NDJSON

`ndjson::Reader` yields one `Result<Value, Error>` per line
ended by `\n`, with the 1-based line on every error and offsets counted
from the line's start. It never reads a line without a bound: it scans
`fill_buf` and copies at most `max_bytes` bytes, so it holds at most
`max_bytes` plus the `BufRead` buffer. An over-long line is
`LineTooLong` as soon as its byte `max_bytes + 1` arrives, without
waiting for an end of line that may never come; the rest of the line is
skipped without being buffered. A line that does not parse, an empty
line included, is an error, and the next item is the next line; the
consumer decides whether to stop or skip. `\r\n` works because `\r` is
whitespace, and it counts toward `max_bytes`. A non-empty last line
without `\n` is `UnterminatedLine` even if it parses, because a
truncated `12345` would otherwise read as `123`. `Interrupted` is
retried; any other I/O error is returned once, as `Io`, and then the
reader ends. `ndjson::write_line` writes the compact form and `\n` in
one `write_all`; the compact form never contains a raw line feed
(D7), so a record cannot split. Rejected: skipping blank lines
(D1, never repair) and accepting an unterminated last line.

### D9. Errors

`Error` has a kind, an offset and an optional line, and
implements `std::error::Error` (`source` is the I/O error for `Io`).
`Display` and `Debug` show the kind and the position only, never input
bytes: requests carry secrets, and errors get logged. A test feeds
inputs holding a marker in strings and keys and checks that neither
form of any error contains it.

`Debug` of `Value`, `Object` and `Number` does show content, so
consumers must not `Debug`-log request bodies. It is written by hand,
compact, and the same with and without `#`:
`Object {"a": Array [Number(1), String("x"), Null]}`. Its cost is linear
in its output, and the output is at most 6 times the input (a raw DEL
byte in a string prints as `\u{7f}`). The plan derived `Debug`, and the
first version of this ADR kept the derive. Its `{:#?}` goes through
std's `debug_list` and `debug_struct`, which pass every byte through one
indentation adapter per enclosing level while the indented output grows
with the square of the depth, so the cost is cubic: for values nested
512 deep (a 1,024-byte and a 3,076-byte input) 6.7 s for arrays and
61 s for objects in release, 26 s for arrays in the test profile. A
public `Debug` cannot prove that no caller pretty-prints a hostile
value, so it is fixed in the crate rather than ruled out by
convention. The hand-written form formats the same values in 87 µs and
186 µs in the test profile; `pretty_debug_of_deep_values_is_fast`
fails above 2 s and requires `{:#?}` to equal `{:?}`. Rejected: an
indented form written without the adapters. It is linear in its
output too, but that output is quadratic in the depth (about 1 MB for
the 1,024-byte input), and nothing reads `Debug` output that needs it;
indented JSON is the job of a tool on the serialized form.

### D10. JSONTestSuite is vendored

Not fetched or generated: the
`test_parsing/` corpus at commit `1ef36fa0` (2024-11-22, the latest),
318 files and 354,024 bytes, bytes unchanged and modes normalized,
with the MIT `LICENSE` next to it. MIT is compatible with Apache-2.0,
and its one condition, keeping the notice, is met there; `cargo deny`
checks crate licenses only. Fetching in CI would add network, a moving
target and a skip path when the network is down, which can turn green
without running anything. The corpus runs inside `cargo test` of the
`check` job, with pinned counts, byte totals and a digest, and
`.gitattributes` marks it `-text`. Outcomes: 93 of 95 `y_` files are
accepted (D4), all 188 `n_` files are rejected and none with
`TooLarge`, and all 35 `i_` files are pinned: the 10 `i_number_` files
and `i_structure_500_nested_arrays` are accepted, the 10
surrogate-escape files are `LoneSurrogate`, the 13 invalid-UTF-8 files
(UTF-16 with and without BOM included) are `InvalidUtf8`, and the
UTF-8 BOM file is `UnexpectedByte` at 0.

### D11. A deterministic mutation sweep instead of a fuzzer

As for
`boneli-http` (ADR-003): every suite file, cut to its first 2,048
bytes (only the two deep `n_` files are longer, and both are rejected
before that point), gets every truncation, deletion, replacement and
insertion with 16 bytes chosen for the grammar, and three bit flips
per byte: 305,491 mutants, each parsed under the harness limits and a
tight set (64 bytes, depth 4, 16 values), 610,982 parses in about
17 s in the test profile. No mutant panics, and every one that parses
respects the limits, round-trips and serializes to a fixed point.
10,000 generated values with every C0 control, quotes, backslashes,
line separators, noncharacters, astral and combining characters and
the number edge cases round-trip too.

## Consequences

- Values compare by lexeme: `1` and `1.0` differ. A consumer that needs
  numeric equality converts with the accessors.
- Two `y_` files are rejected, and so is any real peer that sends
  duplicate keys; none is known (an assumption). Such a peer sees
  `DuplicateKey` with an offset, and accepting it needs a new ADR that
  picks a resolution rule and shows the gateway cannot be confused by it.
- Every consumer has to choose and justify `max_bytes`, `max_depth` and
  `max_values`, using the memory table in D5.
- `{:#?}` of a value prints the same single line as `{:?}` (D9). A
  consumer that wants indented output formats the serialized form.
- The depth ceiling is a property of the crate, but it holds for parsed
  values only; a deep value built by hand is the consumer's
  responsibility (D6).
- Building an object with repeated `insert` costs O(m²) key comparisons,
  because lookups scan; `collect` costs O(m log m). The parser never uses
  `insert`.

## Alternatives considered

- **A fully iterative parser, with hand-written iterative `Drop`, `Clone`,
  `PartialEq`, `Debug` and serializer.** It would remove the depth
  ceiling, but it swaps three derives and the recursive `Debug` for four
  hand-written iterative traversals, and
  the adapters' own recursive walks over a `Value` (redaction in #20)
  would still need a bound. Kept as the fallback if the ceiling ever has
  to drop below 128.
- **Numbers as `f64` only, or as an `I64`/`U64`/`F64` enum.** Both lose
  large integers and the lexeme; the enum also makes every number pick a
  variant. Arbitrary-precision decimals are code no consumer needs.
- **Last wins, first wins or keeping every duplicate.** Last wins (the
  JavaScript and Python behaviour) removes the differential when the
  gateway re-serializes, but not when it forwards the original bytes;
  first wins disagrees with those parsers; keeping all of them moves the
  choice to every consumer.
- **U+FFFD for lone surrogates, accepting a BOM.** Rejected in D2.
- **Default limits.** Rejected in D5.
- **Fetching the suite in CI.** Rejected in D10.
- **A separate string-length limit.** `max_bytes` already bounds every
  string (D5).
- **The derived `Debug`**, or a hand-written indented one. Rejected in
  D9: the first is cubic in the depth with `{:#?}`, the second has an
  output quadratic in the depth.
- **Shared scratch stacks for container elements.** Rejected in D5.
