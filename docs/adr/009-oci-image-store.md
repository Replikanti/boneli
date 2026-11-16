# ADR-009: boneli-oci, an OCI image store with a layered rootfs

- Status: proposed
- Date: 2026-11-16

## Context

Issue #7 builds the `ImageStore` adapter, `boneli-oci`. It pulls an image
pinned by digest from a registry and turns it into a root filesystem that
`boneli-sys` mounts for the sandbox (ADR-007, D7). Its input is hostile in
two ways. The registry, or whoever pinned the image, controls every byte
of the archives, and the store unpacks them onto the host as the runner
user, who holds the git token. A path bug here writes outside the store as
that user, so `boneli-oci` is on the always-review list.

The issue is split into three PRs. Part 1 (this ADR as proposed) unpacks
layers and needs no network. Part 2 adds the registry client and part 3
the store, the port contract and the acceptance, which settles this ADR.

What the numbers below come from (Docker Hub, anonymous, 2026-11-16,
`linux/amd64`):

- `library/node:22`: 8 layers, 408,439,522 B compressed and 1,156,002,816 B
  uncompressed. The largest layer is 597,621,760 B uncompressed. 34,097
  tar entries, at most 13,350 in one layer. The longest path is 128 B, the
  longest name 65 B, the deepest path 13 components. One layer carries PAX
  headers (3 entries). No device nodes, FIFOs, opaque markers or PAX
  xattrs. 16 setuid or setgid entries, 6 hard links, up to 194 absolute
  symlinks per layer.
- `library/postgres:17`: 14 layers, 167,333,338 B compressed and
  478,661,120 B uncompressed, 2 whiteouts, up to 456 absolute symlinks per
  layer.
- Upstream constants, read in their sources: moby overlay2
  `maxDepth = 128`; Go's `archive/tar` `maxSpecialFileSize = 1 << 20` and
  its end-of-archive rules; `ruzstd` 0.8.2
  `MAXIMUM_ALLOWED_WINDOW_SIZE = 100 MiB` and 0.9.1
  `DEFAULT_MAX_WINDOW_SIZE = 128 MiB`; mke2fs's default
  `inode_ratio = 16384`.

## Decision

### D1. One directory per layer, in the overlay format

Each layer is unpacked into its own directory, keyed by its `diff_id`. A
whiteout is a 0:0 character device and an opaque directory carries
`user.overlay.opaque=y`, the format overlayfs reads with `userxattr`, so
`boneli_sys::Root.layers` mounts the directories as they are (ADR-007, D7
built and measured it for this issue). Docker's overlay2 driver also
stacks one directory per layer, so the merged view is the one Docker
shows.

Rejected: flattening every image into one directory. It needs no new
`unsafe` in `boneli-sys`, but it needs merge rules of its own (a directory
over a symlink, opaque directories, a whiteout next to an entry of the same
layer), and no runtime test pins them; with layers, overlayfs applies its
own, tested rules. Flattening would also store a shared base layer once per
image instead of once.

`boneli-sys` gains the primitives an unprivileged process needs for this
format and std cannot write without `libc`: `make_whiteout` (`mknod` of a
0:0 character device, allowed without `CAP_MKNOD` since Linux 5.8),
`make_fifo`, `mark_opaque` (`lsetxattr`) and `user_xattr` (`lgetxattr`,
`user.` names only, values up to `XATTR_SIZE_MAX`, 65,536 B). All are path
based and never follow a final symlink.

### D2. Path rules

- A leading `/` and `.` components are dropped and `//` collapses, so
  `./a`, `/a`, `a//b` and `a/./b` mean `a` and `a/b`. An entry for `.`,
  `./` or `/` is the layer root; it must be a directory and sets the
  root's mode only.
- A `..` component anywhere is refused, and so is NUL in a PAX `path` or
  `linkpath`. The layer is refused, not the entry: a hostile layer gets no
  partial result.
- Before anything is created, every parent is checked component by
  component with `symlink_metadata`. A symlink or a non-directory as a
  parent refuses the layer; a missing parent is created with mode 0o755,
  as Docker does. Nothing is ever followed: files are created with
  `O_EXCL` after the old entry is removed, devices with `mknod`, xattrs
  with `lsetxattr`, hard links with `linkat` without `AT_SYMLINK_FOLLOW`.
  Why this is enough: the store directory is private (`0o700`) and only
  this process writes it while it unpacks, so the tar stream, read
  sequentially, is the only adversary, and every link it planted is seen
  by the walk before the next create.
- Symlink targets are data for the sandbox and are written as they are,
  absolute ones included.
- Hard link targets are archive paths under the same rules, must already
  exist in this layer, may not cross a symlink, and may not be a
  directory, a whiteout or the entry itself.
- A later entry for the same path wins. A non-directory over a directory
  removes the tree; a directory over a directory merges, with the later
  entry's metadata (moby).
- Name length is the kernel's: a 256 B component is `ENAMETOOLONG`, an
  error, never a panic.

Whiteouts:

- `.wh.<name>` becomes a 0:0 character device `<name>`, whatever the
  entry's type flag; the byte-exact prefix decides, as in Docker, so
  look-alikes (`.WH.`, fullwidth dots, a zero-width space) are regular
  names.
- `.wh..wh..opq` marks its directory opaque. At the layer root it is
  refused, because what overlayfs does with an opaque lower root is not
  pinned by any test.
- `.wh.`, `.wh..` and `.wh...` are refused (they would name nothing, the
  directory itself or its parent), and so is a `.wh.` prefix in a parent
  component.
- aufs metadata at the root (`.wh..wh.plnk` and the like) is skipped with
  everything under it, as moby does.
- A whiteout hides lower layers only, so a real entry of the same layer
  wins in either order (OCI image spec).

### D3. Entry types and metadata

- Regular files, directories, symlinks, hard links and FIFOs are written.
  A 0:0 character device is a whiteout, the file Docker's overlay2 driver
  writes. Any other character or block device is skipped and counted in
  the layer's sidecar: the sandbox mounts its own `/dev`, and unprivileged
  `mknod` refuses them.
- Modes keep `& 0o1777`: setuid and setgid are dropped, sticky stays.
  node:22 has 16 setuid or setgid entries, and a setuid file owned by the
  runner user would let other local users run it as that user. Inside the
  sandbox the single id mapping (ADR-007, D1) makes setuid meaningless
  anyway.
- uid and gid are ignored: every file belongs to the runner, the one
  mapped id.
- Tar xattrs (`SCHILY.xattr.*`) are never applied. `user.overlay.*` from
  an archive would let a layer redirect or hide paths of other layers, and
  `security.*` cannot be written unprivileged.
- mtimes are kept for files and directories, PAX fractions and negative
  times included. Symlinks get the unpack time, because std cannot set it
  without following the link.
- Directories are created `0o700` and get their final mode and time at
  the end, deepest first, so read-only directories can be filled. A file
  gets its mode and time through its open descriptor, so mode 0 does not
  lock the writer out.

### D4. The tar subset

Go's `archive/tar` is the reader of record: Docker and containerd read
layers with it, and most images are written by it. The reader here accepts
what Go accepts in practice and refuses the rest:

- ustar and GNU magic. V7 and other formats are refused (no current
  writer emits them for images).
- The header checksum as the unsigned or the signed sum.
- Numbers in octal or base-256, up to `i64::MAX`; a negative base-256
  number is refused.
- PAX `x` (`path`, `linkpath`, `size`, `mtime`; every other key is
  ignored), PAX `g` (framing checked, contents ignored, as Docker does),
  GNU `L` and `K`. GNU names come first and PAX overrides them, Go's order.
  A PAX or GNU body may be at most 1,048,576 B, Go's `maxSpecialFileSize`.
- Types `0`, NUL and `7` as regular files (NUL with a trailing `/` is a
  directory), `1`-`6`. Header-only types carry no data whatever their size
  field says. Sparse files (`S`, `GNU.sparse.*`) and every other type are
  refused.
- The end of the archive is Go's: EOF at a header boundary, or a zero
  block followed by EOF or a second zero block. A zero block followed by
  anything else is refused. Bytes after the end are hashed into the
  `diff_id` and counted, never extracted.

Where this is stricter than Go, on purpose: a PAX or GNU header with no
entry after it (Go reports a clean end), a PAX record length with a sign,
V7 headers and sparse files. None of the measured images uses them, and
refusing fails closed.

Rejected: the `tar` crate. docs/ARCHITECTURE.md puts tar reading on the
list of parts we write ourselves, the crate pulls `filetime` and `xattr`
(with `libc` edges), and its unpacker applies its own path and permission
policy that we would have to audit and override.

### D5. Decompression

- gzip: our RFC 1952 framing over `miniz_oxide` 0.9.1's raw deflate
  (`default-features = false`, `with-alloc` for the streaming state).
  Reserved `FLG` bits and `CM != 8` are refused, `FEXTRA`, `FNAME`,
  `FCOMMENT` and `FHCRC` are skipped, `ISIZE` is checked. Several members
  decode as one stream, and any byte after the last member that does not
  start another member is refused, as in Go. CRC-32 is not computed,
  because the `diff_id` covers every decoded byte; a corrupted CRC field
  alone therefore passes, and the blob digest (part 2) covers it on the
  compressed side. `miniz_oxide` forbids `unsafe` in its own code. It
  pulls `adler2` (Adler-32 for the zlib format, `forbid(unsafe_code)`),
  which we do not use, but the edge is unconditional; this ADR approves
  the crate name.
- zstd: `ruzstd` 0.9.1's `FrameDecoder` (`default-features = false`,
  `std`, which pulls no crate): frames in sequence, skippable frames
  skipped, anything after the last frame refused, checksums read but not
  verified (no `hash` feature, which would pull `twox-hash`; the
  `diff_id` covers the bytes). The reserved bit of the frame header
  descriptor must be 0 (RFC 8878 says a decoder must check it; ruzstd does
  not), so the reader checks it before ruzstd reads the header.
- At least 0.9.1, and with it MSRV 1.87 (decided by the operator during
  part 1, 2026-11-16). `cargo deny check` refused 0.8.2 for
  RUSTSEC-2026-0344: a crafted frame under 128 KB makes one block expand
  to gigabytes, because 0.8.2 never bounds a block's decoded size, so the
  counting reader of D7, which sees the output only after a block is
  decoded, cannot stop it. The fix exists only in 0.9.1, which declares
  `rust-version = 1.87`; resolver 3 picks versions by `rust-version`, so
  the workspace's `rust-version` moves from 1.85 to 1.87. The cost is
  only the declared floor: CI and the hosts build with current stable.
  Rejected: an advisory ignore in `deny.toml` (a denial of service on
  hostile input, and widening the deny policy needs an ADR of its own),
  and refusing zstd layers until later (zstd is in the OCI layer media
  types the store must read). ADR-005 records "the workspace MSRV of 1.85
  stays" for the TLS stack; that still holds for those crates (none
  declares more than 1.85), but the workspace floor is now 1.87. ADR-005
  is accepted and keeps its text; this paragraph is the record.
- The zstd window cap is 100 MiB, set with `set_max_window_size`. ruzstd
  0.9.1 checks it when a frame header is read, for the first frame,
  later frames and single-segment frames (whose window is their content
  size) alike, before it allocates the window (read in its source;
  0.8.2 checked only later frames, which part 1 first worked around with
  its own header parse). The decoder's memory is the window plus one
  block of at most 128 KiB, which 0.9.1 now enforces. Why 100 MiB: it is
  the value ruzstd 0.8.2 hard-coded and the plan adopted; 0.9.1's default
  and zstd's own default limit (`ZSTD_WINDOWLOG_LIMIT_DEFAULT = 27`) are
  128 MiB. Consequence: a layer compressed with `zstd --long`, whose
  default window log is 27 (128 MiB), is refused; raising the cap to
  128 MiB admits it at 28 MiB more memory per decoding pull. Part 3
  measures the first-stack images and settles the value.
- `ruzstd` contains `unsafe` in its ring buffer, and RUSTSEC-2024-0400 was
  an out-of-bounds read there (patched in 0.7.3). `cargo deny check` runs
  advisories in CI. Its input is digest-verified before it is decoded
  (part 2), so the adversary is whoever pinned the image, not the network.
  ruzstd also does not read some fields: one flipped byte of the test
  fixture's sequences section (measured with 0.8.2 and again with 0.9.1)
  decodes to the same output, which the `diff_id` then matches, so the
  result is the right bytes.
- Every decompressor's output passes a counting reader that refuses the
  first byte over a limit (D7), so a bomb stops there.

Rejected: `flate2` (pulls `crc32fast` and `cfg-if` for a CRC we do not
need, plus a backend switch), the `zstd` crate (C bindings with a build
script, against "pure Rust" in docs/ARCHITECTURE.md).

### D6. SHA-256: ring's, exported by boneli-https

The one SHA-256 of the repository is `boneli_https::Sha256`: ring's
SHA-256 through rustls' public hash-provider API
(`rustls::crypto::hash`, the `hash_provider` of
`TLS13_AES_128_GCM_SHA256`, read through an exhaustive `match` on
`SupportedCipherSuite` with no panic path). This widens ring's exception
in docs/ARCHITECTURE.md and ADR-005 from "TLS only" to "TLS and content
hashing", still confined to `boneli-https`. Reasons:

- The same BoringSSL-derived code is already linked into the runner and
  already hashes the transcript of every TLS 1.3 connection on a SHA-256
  suite, so no foreign code is added and no crate or edge either.
- It uses the CPU's SHA instructions: ring 0.17.14 dispatches to
  `sha256_block_data_order_hw` on x86_64 with the SHA extensions and on
  aarch64, with AVX and SSSE3 paths on older x86_64.
- ring is audited and widely deployed.

Weak spot: dropping ring later means replacing the hash too. The single
type confines that to one file and its tests. A rustls update that changes
the API fails to compile there; one that swaps the provider fails the
known-answer tests and `hash_provider_is_sha256`.

ADR-004 requires the file store (#4) to use "a cryptographic digest from
a vetted crate" and names `sha2` as the planned crate. The rule still
holds and only the crate changes; ADR-004 stays as it is, because an
accepted ADR changes only its status line. `sha2` leaves the dependency
table and `tools/architecture.toml`, so #4 uses the same type.

Alternatives:

- Our own FIPS 180-4 implementation: rejected, it duplicates code that is
  already linked.
- `sha2` 0.11: rejected, it adds 6 crate names and the strict edge
  `cpufeatures -> libc` on aarch64 for a second SHA-256 next to ring's.
- Our own TLS primitives, or a pure-Rust rustls provider such as
  `rustls-rustcrypto` that would make the hash pure Rust along with the
  rest: rejected. TLS primitives handle secret keys, need constant-time
  code and fail open on a signature-verification bug, whereas a
  deterministic bug in a hash fails closed. ADR-005 is not edited.

### D7. Limits

`Limits::new(max_layer_bytes, max_image_bytes, max_image_entries,
max_special_bytes)` has no defaults and refuses a zero (the house style of
ADR-003 and ADR-008), so the values live in one place, the store (part 3).
Every limit is inclusive: the limit passes, one more is refused. The values
the store will use, and why:

- Per layer: 4,294,967,296 B uncompressed (4 GiB), 7.2 times node:22's
  largest layer of 597,621,760 B. Counted on the decoded stream while it
  is read, trailing bytes included. Lower refuses real first-stack images
  sooner; higher lets one layer fill more disk before it is refused. Known
  casualty: images with layers above 4 GiB (CUDA and ML images) are
  refused until the value is raised.
- Per image: 17,179,869,184 B (16 GiB), 14.9 times node:22's
  1,156,002,816 B, and 1,048,576 entries, 30.8 times node:22's 34,097.
  16 GiB divided by mke2fs's default 16,384 B per inode is exactly
  1,048,576, so the two caps exhaust the same default ext4 at the same
  time; neither is the weaker bound. Layers already in the cache are
  charged from their sidecars, so a warm cache and a cold one reach the
  same verdict.
- A PAX or GNU extension body: 1,048,576 B, Go's `maxSpecialFileSize`, so
  every archive Go reads passes; it is read into memory, so this is the
  memory one header may take.
- The zstd window: 100 MiB (D5).

### D8. The cache layout and concurrency

- `<root>/layers/sha256/<hex>` is the layer directory and
  `<root>/layers/sha256/<hex>.stats` its sidecar: uncompressed bytes,
  entry count and skipped devices, as
  `bytes N\nentries N\nskipped-devices N\n`, parsed exactly.
- A layer is unpacked into `<root>/tmp/<pid>.<starttime>.<n>/` (the start
  time from `/proc/self/stat`, so a reused pid is told from a live owner
  when the store cleans up). The stream is hashed while it is unpacked. On
  a `diff_id` match the sidecar is written to a temporary file and renamed
  into place, then the directory is renamed to `layers/sha256/<hex>`: that
  rename is the commit point. A mismatch or an error removes the
  temporary tree, after giving every directory `u+rwx`, because final
  modes may be 0.
- Moving a directory to another parent rewrites its `..`, which needs
  write permission on it. A layer root without `u+w` gets it for the
  rename only; a crash between the rename and the restore leaves the root
  with `u+w`, which changes nothing inside the read-only sandbox root.
- Two stores committing the same layer: the rename of the second fails
  because the directory exists; it discards its tree and reads the
  winner's sidecar. The same `diff_id` means the same bytes, so the trees
  are equal.
- There is no `fsync`. A power loss after the commit can leave a layer
  with lost data under its name; the store (part 3) and eviction (#56)
  decide whether that needs a check.

## Consequences

- The sandbox mounts registry images without root and without a
  flattening step, with overlayfs's merge rules.
- The runner gains one more C-backed path, ring's SHA-256, inside the
  crate that already holds ring.
- `boneli-sys` grows by four path-based primitives; `unsafe` stays there.
- Images that need devices, setuid bits, xattrs, sparse files, V7 tar,
  or layers above 4 GiB do not pull. None of the first-stack images does.
- `boneli-oci` is on the always-review list (#7 STOP 1).

## Alternatives considered

Flattening (D1), the `tar` crate (D4), `flate2` and the `zstd` crate (D5),
`sha2`, our own SHA-256 and a pure-Rust TLS provider (D6), each with the
reason it lost in its decision.

## Accept when

Part 3 of #7 pulls `node:22` and `postgres:17` on x86_64 and arm64 and runs
both in the sandbox.
